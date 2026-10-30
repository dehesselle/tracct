#!/opt/tracct/bin/python
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Invariants of the soak run, checked against the running unit and its database.

  check.py loop [--interval 60]   check every interval, one line each to checks.jsonl
  check.py once                   one check, printed
  check.py summary [--since T]    the last check, and every WARN/ERR/FAIL since T;
                                  exit 2 on a FAIL or ERR since T

Runs with tracct's own interpreter, for its config, schema and query client. The
database is opened read-only. Levels: PASS, WARN (worth a look), ERR (the check itself
broke), FAIL (tracct did something wrong).
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import re
import sqlite3
import subprocess
import sys
import time
import traceback
from pathlib import Path

from tracct.config import load_config
from tracct.constants import DB_VERSION
from tracct.query import QueryClient, QueryError
from tracct.writer import ORPHAN_DELETES

LOG = Path("/var/log/soak")
CHECKS = LOG / "checks.jsonl"
EVENTS = LOG / "events.jsonl"
LEDGER = LOG / "ledger"
DB = Path("/var/lib/private/tracct/tracct.db")
LEVELS = ("PASS", "WARN", "ERR", "FAIL")
#: Messages that mean tracct failed, and those worth counting.
FAIL_IDS = {
    "thread-died",
    "writer-failed",
    "database-unusable",
    "retention-skipped",
    "drain-failed",
    "drain-entry-failed",
    "monitor-failed",
    "retry-buffer-full",
}
MAINTENANCE = re.compile(
    r"rolled up (\d+) period\(s\), deleted (\d+) row\(s\)"
    r"(?: and (\d+) unreferenced lookup entries)?"
    r"(?:, released (\d+) MiB of free space)? in ([\d.]+) s"
)
#: Every id column and the lookup table it refers to.
REFERENCES = (
    ("connections", ("exe_id", "pexe_id"), "executables"),
    ("connections", ("unit_id",), "units"),
    ("connections", ("laddr_id", "raddr_id"), "addresses"),
    ("connections", ("domain_id",), "domains"),
    ("connections", ("netns_id",), "netns"),
    ("connections", ("iface_id",), "interfaces"),
    ("connections_rollup", ("exe_id", "pexe_id"), "executables"),
    ("connections_rollup", ("unit_id",), "units"),
    ("connections_rollup", ("domain_id",), "domains"),
    ("connections_rollup", ("netns_id",), "netns"),
    ("connections_rollup", ("iface_id",), "interfaces"),
    ("interface_traffic", ("iface_id",), "interfaces"),
    ("interface_traffic_rollup", ("iface_id",), "interfaces"),
    ("forwarded", ("netns_id",), "netns"),
    ("forwarded", ("src_id", "dst_id"), "addresses"),
    ("forwarded", ("domain_id",), "domains"),
    ("forwarded_rollup", ("netns_id",), "netns"),
    ("forwarded_rollup", ("src_id",), "addresses"),
    ("forwarded_rollup", ("domain_id",), "domains"),
    ("interfaces", ("netns_id",), "netns"),
)
#: Raw table, rollup, the sums compared, and whether the rollup counts its rows.
CONSERVED = (
    ("connections", "connections_rollup", ("sent", "received", "events"), True),
    ("interface_traffic", "interface_traffic_rollup", ("sent", "received"), False),
    (
        "forwarded",
        "forwarded_rollup",
        ("orig_bytes", "reply_bytes", "orig_packets", "reply_packets"),
        True,
    ),
)


def sh(cmd: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd, shell=True, text=True, capture_output=True, timeout=timeout
    )


def read_jsonl(path: Path) -> list[dict]:
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


class Checker:
    def __init__(self) -> None:
        self.runs = 0
        self.cursor: str | None = None
        self.since = time.time()
        self.last: dict = {}
        self.counts: dict[str, int] = {}
        self.maintenance = {
            "passes": 0,
            "periods": 0,
            "deleted": 0,
            "orphan_passes": 0,
            "orphans": 0,
            "released_mib": 0,
            "max_s": 0.0,
            "last": "",
        }
        self.rss: list[tuple[float, float]] = []
        self.free_high = 0
        self.max_db = 0
        self.verified: set[int] = set()
        self.periods_seen: set[int] = set()
        self.early_times: set[int] = set()
        self.unreferenced: list[tuple[float, int]] = []

    # --- context ---

    def load_context(self) -> None:
        self.now = time.time()
        config = load_config().database
        self.window = config.write_limit_seconds
        self.period = config.rollup_period_minutes * 60
        self.interval = config.maintenance_interval_minutes * 60
        self.raw_ret = math.ceil(config.raw_retention_days * 86400)
        self.rollup_ret = math.ceil(config.rollup_retention_days * 86400)
        events = read_jsonl(EVENTS)
        resets = [e for e in events if e["action"] == "reset"]
        self.reset_t = resets[-1]["t"] if resets else self.since
        self.events = [e for e in events if e["t"] >= self.reset_t]
        self.windows = {self.window, 2}
        self.periods_seen.add(self.period)
        for e in self.events:
            if e["action"] == "config" and e.get("window"):
                self.windows.add(e["window"])
                self.periods_seen.add(e["period"] * 60)
        self.wmax = max(self.windows)
        # Spans in which gaps, restarts and losses are planned.
        self.disrupted: list[tuple[float, float]] = []
        down = None
        for e in self.events:
            action = e["action"]
            if action == "stop":
                down = e["t"]
            elif action == "start" and down is not None:
                self.disrupted.append((down - 5, e["t"] + 30))
                down = None
            elif action in ("restart", "kill", "config", "v7-start"):
                self.disrupted.append((e["t"] - 5, e["t"] + 40))
            elif action == "v7-done":
                self.disrupted.append((e["t"] - 30, e["t"] + 40))
        if down is not None:
            self.disrupted.append((down - 5, self.now + 1))
        # Without traffic an interface changes in few windows, and only those get rows.
        ends = [e["t"] for e in self.events if e["action"] == "scenario-end"]
        if ends:
            self.disrupted.append((ends[-1] - 5, self.now + 1))

    def is_disrupted(self, start: float, end: float) -> bool:
        return any(a < end and b > start for a, b in self.disrupted)

    def db(self) -> sqlite3.Connection:
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=30)
        con.execute("PRAGMA busy_timeout = 30000")
        return con

    # --- checks; each returns [(level, name, detail)] ---

    def check_daemon(self) -> list:
        out = []
        props = dict(
            line.split("=", 1)
            for line in sh(
                "systemctl show tracct -p ActiveState,SubState,MainPID,NRestarts,CPUUsageNSec,MemoryCurrent"
            ).stdout.splitlines()
            if "=" in line
        )
        active = props.get("ActiveState") == "active"
        pid = int(props.get("MainPID") or 0)
        restarts = int(props.get("NRestarts") or 0)
        cpu_ns = (
            int(props.get("CPUUsageNSec") or 0)
            if props.get("CPUUsageNSec", "").isdigit()
            else 0
        )
        self.metrics["active"] = props.get("ActiveState")
        self.metrics["pid"] = pid
        self.metrics["restarts"] = restarts
        if not active and not self.is_disrupted(self.now - 1, self.now):
            out.append(
                (
                    "FAIL",
                    "daemon-active",
                    f"tracct is {props.get('ActiveState')}/{props.get('SubState')}",
                )
            )
        last = self.last
        if last and (pid != last.get("pid") or restarts != last.get("restarts")):
            if self.is_disrupted(last["t"], self.now):
                out.append(
                    (
                        "PASS",
                        "daemon-restart",
                        f"planned: pid {last.get('pid')} -> {pid}, restarts {last.get('restarts')} -> {restarts}",
                    )
                )
            else:
                out.append(
                    (
                        "FAIL",
                        "daemon-restart",
                        f"unplanned: pid {last.get('pid')} -> {pid}, restarts {last.get('restarts')} -> {restarts}",
                    )
                )
        rss = 0.0
        if pid:
            try:
                for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
                    if line.startswith("Rss:"):
                        rss = int(line.split()[1]) / 1024
            except OSError:
                pass
        self.metrics["rss_mb"] = round(rss)
        if rss:
            if last.get("pid") != pid:
                self.rss = []
            self.rss.append((self.now, rss))
            self.rss = [(t, r) for t, r in self.rss if t > self.now - 900]
            low = min(r for _, r in self.rss)
            if rss > 800:
                out.append(
                    ("FAIL", "daemon-memory", f"RSS {rss:.0f} MiB, MemoryMax is 1 GiB")
                )
            elif rss > 500:
                out.append(("WARN", "daemon-memory", f"RSS {rss:.0f} MiB"))
            elif (
                len(self.rss) >= 12
                and rss - low > 150
                and all(b[1] >= a[1] for a, b in zip(self.rss[-6:], self.rss[-5:]))
            ):
                out.append(
                    (
                        "WARN",
                        "daemon-memory-growth",
                        f"RSS {low:.0f} -> {rss:.0f} MiB in 15 min, still growing",
                    )
                )
        if last.get("cpu_ns") and cpu_ns >= last["cpu_ns"] and pid == last.get("pid"):
            self.metrics["cpu_pct"] = round(
                (cpu_ns - last["cpu_ns"]) / 1e9 / (self.now - last["t"]) * 100, 1
            )
        self.metrics["cpu_ns"] = cpu_ns
        query = sh(
            "systemctl show tracct-query.service -p ActiveState --value"
        ).stdout.strip()
        socket_state = sh(
            "systemctl show tracct-query.socket -p ActiveState --value"
        ).stdout.strip()
        if query == "failed" or socket_state != "active":
            out.append(
                ("FAIL", "query-server", f"service {query}, socket {socket_state}")
            )
        if self.runs % 5 == 0:
            r = sh("/opt/tracct/bin/tracct status")
            if r.returncode != 0:
                out.append(
                    (
                        "WARN",
                        "tracct-status",
                        f"exit {r.returncode}: {(r.stdout + r.stderr).strip()[-300:]}",
                    )
                )
        return out

    def check_journal(self) -> list:
        out = []
        cmd = "journalctl -u tracct -u tracct-query -o json --no-pager"
        cmd += (
            f" --after-cursor '{self.cursor}'"
            if self.cursor
            else f" --since @{int(self.reset_t)}"
        )
        r = sh(cmd, timeout=120)
        new: dict[str, int] = {}
        failures = []
        for line in r.stdout.splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            self.cursor = entry.get("__CURSOR", self.cursor)
            message = entry.get("MESSAGE", "")
            if isinstance(message, list):
                message = bytes(message).decode("utf-8", "replace")
            t = int(entry.get("__REALTIME_TIMESTAMP", "0")) / 1e6
            found = re.search(r"\[([a-z0-9-]+)\] ", message)
            if found:
                msgid = found.group(1)
                new[msgid] = new.get(msgid, 0) + 1
                if msgid in FAIL_IDS:
                    failures.append(message[:300])
                if msgid == "maintenance-done":
                    self.parse_maintenance(message)
            elif "Traceback" in message or "Error" in message.split(":")[0]:
                failures.append(message[:300])
            elif entry.get("_PID") == "1" and (
                "Failed with result" in message or "Main process exited" in message
            ):
                if not self.is_disrupted(t - 1, t + 1):
                    failures.append(message[:300])
        for msgid, n in new.items():
            self.counts[msgid] = self.counts.get(msgid, 0) + n
        for message in failures:
            out.append(("FAIL", "journal", message))
        warn = {
            k: v
            for k, v in new.items()
            if k not in FAIL_IDS and k not in ("maintenance-done",)
        }
        if warn:
            out.append(
                (
                    "WARN",
                    "journal-messages",
                    ", ".join(f"{k} x{v}" for k, v in sorted(warn.items())),
                )
            )
        self.metrics["journal"] = dict(self.counts)
        self.metrics["maintenance"] = dict(self.maintenance)
        return out

    def parse_maintenance(self, message: str) -> None:
        found = MAINTENANCE.search(message)
        if not found:
            return
        periods, deleted, orphans, released, seconds = found.groups()
        m = self.maintenance
        m["passes"] += 1
        m["periods"] += int(periods)
        m["deleted"] += int(deleted)
        if orphans is not None:
            m["orphan_passes"] += 1
            m["orphans"] += int(orphans)
        if released is not None:
            m["released_mib"] += int(released)
        m["max_s"] = max(m["max_s"], float(seconds))
        m["last"] = found.group(0)

    def check_file(self, con: sqlite3.Connection) -> list:
        out = []
        version = con.execute("PRAGMA user_version").fetchone()[0]
        vacuum = con.execute("PRAGMA auto_vacuum").fetchone()[0]
        mode = con.execute("PRAGMA journal_mode").fetchone()[0]
        if (version, vacuum, mode) != (DB_VERSION, 2, "wal"):
            out.append(
                (
                    "FAIL",
                    "db-settings",
                    f"user_version {version}, auto_vacuum {vacuum}, journal_mode {mode}",
                )
            )
        pages = con.execute("PRAGMA page_count").fetchone()[0]
        free = con.execute("PRAGMA freelist_count").fetchone()[0]
        size = DB.stat().st_size
        try:
            wal = Path(f"{DB}-wal").stat().st_size
        except OSError:
            wal = 0
        self.max_db = max(self.max_db, size)
        fraction = free / pages if pages else 0
        self.metrics.update(
            db_mib=round(size / 1048576, 1),
            max_db_mib=round(self.max_db / 1048576, 1),
            wal_mib=round(wal / 1048576, 1),
            free_pct=round(fraction * 100, 1),
        )
        # A pass releases the free pages past a quarter of the file; three checks in a
        # row above it mean passes did not.
        self.free_high = self.free_high + 1 if fraction > 0.26 else 0
        if self.free_high >= 3:
            out.append(
                (
                    "FAIL",
                    "free-pages",
                    f"{fraction:.0%} of the file free for {self.free_high} checks",
                )
            )
        if wal > 512 * 1048576:
            out.append(("WARN", "wal-size", f"WAL {wal / 1048576:.0f} MiB"))
        if self.runs % 10 == 9:
            started = time.monotonic()
            result = con.execute("PRAGMA quick_check").fetchall()
            took = time.monotonic() - started
            if result != [("ok",)]:
                out.append(("FAIL", "quick-check", str(result[:5])))
            else:
                out.append(("PASS", "quick-check", f"ok in {took:.1f} s"))
        return out

    def check_writes(self, con: sqlite3.Connection) -> list:
        out = []
        counts = {}
        for table in (
            "connections",
            "connections_rollup",
            "interface_traffic",
            "interface_traffic_rollup",
            "forwarded",
            "forwarded_rollup",
        ):
            counts[table] = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        self.metrics["rows"] = counts
        newest = con.execute("SELECT MAX(time) FROM interface_traffic").fetchone()[0]
        age = self.now - newest if newest else None
        self.metrics["newest_age"] = None if age is None else round(age, 1)
        if (age is None or age > 3 * self.wmax + 5) and self.now - self.reset_t > 30:
            if not self.is_disrupted(self.now - (age or 60), self.now):
                out.append(
                    ("FAIL", "writes-alive", f"newest interface row {age} s old")
                )
        times = [
            row[0]
            for row in con.execute(
                "SELECT DISTINCT time FROM interface_traffic WHERE time > ? ORDER BY time",
                (self.now - 300,),
            )
        ]
        worst = 0
        for a, b in itertools.pairwise(times):
            if b - a > worst and not self.is_disrupted(a, b):
                worst = b - a
        self.metrics["max_gap_s"] = worst
        # A large window takes seconds to write; a gap past 15 s would be a pass or a
        # write holding the writer up.
        if worst > max(15, 2 * self.wmax + 3):
            out.append(
                (
                    "FAIL",
                    "write-gap",
                    f"{worst} s between two windows in the last 5 min",
                )
            )
        elif worst > 2 * self.wmax + 3:
            out.append(
                (
                    "WARN",
                    "write-gap",
                    f"{worst} s between two windows in the last 5 min",
                )
            )
        # The seconds of a window are measured: the time since the write before, which
        # is longer than the window while writes take long, shorter when written early.
        since = self.now - 300
        writes = con.execute(
            "SELECT time, MAX(seconds), MIN(seconds) FROM interface_traffic WHERE time > ? GROUP BY time ORDER BY time",
            (since,),
        ).fetchall()
        off = []
        for (a, _, _), (b, high, low) in itertools.pairwise(writes):
            if self.is_disrupted(a, b):
                continue
            # Consecutive windows; past a gap an idle interface had no row.
            consecutive = b - a <= self.wmax + 3
            if (
                high != low
                or high > b - a + 2
                or (consecutive and abs(high - (b - a)) > 2)
            ):
                off.append(f"{b}: {low}..{high} s for {b - a} s")
        if off:
            out.append(
                (
                    "FAIL",
                    "raw-seconds",
                    f"{len(off)} windows, e.g. " + ", ".join(off[:3]),
                )
            )
        high = con.execute(
            "SELECT MAX(seconds) FROM connections WHERE time > ?", (since,)
        ).fetchone()[0]
        longest = max(
            (b - a for (a, _, _), (b, _, _) in itertools.pairwise(writes)), default=0
        )
        if high is not None and high > max(longest, self.wmax) + 2:
            out.append(
                (
                    "FAIL",
                    "raw-seconds",
                    f"a connection row covers {high} s, the longest gap was {longest} s",
                )
            )
        self.metrics["max_raw_seconds"] = high
        # A window is written early at 65 536 connections; with a 2 s window its
        # seconds still round to 2, so it shows by its rows.
        for (t,) in con.execute(
            "SELECT time FROM connections WHERE time > ? GROUP BY time HAVING COUNT(*) >= 50000",
            (since,),
        ):
            self.early_times.add(t)
        self.metrics["early_windows"] = len(self.early_times)
        # The seconds of one interface's rows add up to the time they span.
        iface = con.execute(
            "SELECT iface_id FROM interface_traffic WHERE time > ? GROUP BY iface_id ORDER BY COUNT(*) DESC LIMIT 1",
            (since,),
        ).fetchone()
        if iface and not self.is_disrupted(since - 10, self.now):
            rows = con.execute(
                "SELECT time, seconds FROM interface_traffic WHERE iface_id = ? AND time > ? ORDER BY time",
                (iface[0], since),
            ).fetchall()
            if len(rows) > 10:
                spanned = rows[-1][0] - rows[0][0]
                summed = sum(s for _, s in rows[1:])
                ratio = summed / spanned if spanned else 1
                self.metrics["seconds_ratio"] = round(ratio, 3)
                if abs(ratio - 1) > 0.02:
                    level = "FAIL" if abs(ratio - 1) > 0.05 else "WARN"
                    out.append(
                        (
                            level,
                            "seconds-sum",
                            f"rows spanning {spanned} s carry {summed} s ({ratio:.3f})",
                        )
                    )
        return out

    def check_rollups(self, con: sqlite3.Connection) -> list:
        out = []
        watermark = con.execute(
            "SELECT value FROM meta WHERE key = 'rollup_watermark'"
        ).fetchone()
        watermark = watermark[0] if watermark else 0
        self.metrics["watermark_lag"] = (
            round(self.now - watermark) if watermark else None
        )
        if watermark > self.now + 5:
            out.append(
                ("FAIL", "watermark", f"{watermark - self.now:.0f} s in the future")
            )
        elif (
            watermark
            and self.now - watermark
            > max(self.periods_seen) + self.interval + 3 * self.wmax + 60
            and not self.is_disrupted(
                self.now - max(self.periods_seen) - self.interval - 60, self.now
            )
        ):
            out.append(("FAIL", "watermark", f"{self.now - watermark:.0f} s behind"))
        # Rollup spans are boundaries at every multiple of the longest period seen
        # (periods end on multiples of their length), so each such chunk sums the same
        # raw and rolled up, as long as its raw rows are all still there.
        # A chunk is whole while the purge cutoff (now - raw retention at most) is 20 s
        # short of it.
        chunk = math.lcm(*self.periods_seen)
        if not watermark:
            return out
        first = (
            max(
                math.ceil((self.now - self.raw_ret + 20) / chunk),
                int(self.reset_t) // chunk,
            )
            * chunk
        )
        checked = mismatched = 0
        for start in range(first, watermark - chunk + 1, chunk):
            if start in self.verified:
                continue
            end = start + chunk
            problems = []
            for raw, rollup, columns, counts_rows in CONSERVED:
                sums = ", ".join(
                    f"(SELECT TOTAL({c}) FROM {raw} WHERE time >= :s AND time < :e)"
                    for c in columns
                )
                rolled = ", ".join(
                    f"(SELECT TOTAL({c}) FROM {rollup} WHERE period >= :s AND period < :e)"
                    for c in columns
                )
                extra = ""
                if counts_rows:
                    extra = f", (SELECT COUNT(*) FROM {raw} WHERE time >= :s AND time < :e), (SELECT TOTAL(rows) FROM {rollup} WHERE period >= :s AND period < :e)"
                row = con.execute(
                    f"SELECT (SELECT value FROM meta WHERE key = 'rollup_watermark'), {sums}, {rolled}{extra}",
                    {"s": start, "e": end},
                ).fetchone()
                mark, *values = row
                if mark < end:
                    problems = None  # not rolled up yet
                    break
                n = len(columns)
                raw_values, rolled_values = values[:n], values[n : 2 * n]
                if counts_rows:
                    raw_values.append(values[2 * n])
                    rolled_values.append(values[2 * n + 1])
                if [int(v) for v in raw_values] != [int(v) for v in rolled_values]:
                    problems.append(
                        f"{raw}: raw {[int(v) for v in raw_values]} rolled up {[int(v) for v in rolled_values]}"
                    )
            if problems is None:
                continue
            checked += 1
            if problems and not self.is_disrupted(start - 60, end + 60):
                mismatched += 1
                out.append(
                    ("FAIL", "rollup-sums", f"[{start}, {end}): " + "; ".join(problems))
                )
            elif problems:
                out.append(
                    (
                        "WARN",
                        "rollup-sums",
                        f"[{start}, {end}) around a restart: " + "; ".join(problems),
                    )
                )
            self.verified.add(start)
        self.metrics["rollup_chunks_verified"] = len(self.verified)
        # Spans of the interface rollups never overlap.
        spans = con.execute(
            "SELECT period, MAX(seconds), MIN(seconds) FROM interface_traffic_rollup GROUP BY period ORDER BY period"
        ).fetchall()
        for (p, s, s_min), (q, _, _) in itertools.pairwise(spans):
            if s <= 0 or s_min <= 0:
                out.append(("FAIL", "rollup-seconds", f"period {p} has {s_min} s"))
            if p + s > q and s_min == s:
                out.append(
                    (
                        "FAIL",
                        "rollup-seconds",
                        f"period {p} spans {s} s, past the next at {q}",
                    )
                )
        partial = sum(
            1 for p, s, s_min in spans if s not in self.periods_seen or s != s_min
        )
        self.metrics["rollup_partial_periods"] = partial
        return out

    def check_retention(self, con: sqlite3.Connection) -> list:
        out = []
        elapsed = self.now - self.reset_t
        slack = self.interval + self.maintenance["max_s"] + 60
        for table, column, keep in (
            ("interface_traffic", "time", self.raw_ret),
            ("connections", "time", self.raw_ret),
            ("interface_traffic_rollup", "period", self.rollup_ret),
        ):
            oldest = con.execute(f"SELECT MIN({column}) FROM {table}").fetchone()[0]
            if oldest is None:
                continue
            age = self.now - oldest
            self.metrics[f"oldest_{table}"] = round(age)
            limit = keep + slack + (max(self.periods_seen) if "rollup" in table else 0)
            # A daemon that is down (or just back) has not purged yet.
            if age > limit and not self.is_disrupted(self.now - slack - 60, self.now):
                out.append(
                    (
                        "FAIL",
                        "retention",
                        f"{table} keeps a row {age:.0f} s old, retention {keep} s",
                    )
                )
            # Not purged early: once the run is past the retention, the oldest row is
            # about as old as it.
            ago = self.now - keep
            if (
                elapsed > keep + slack + 120
                and age
                < keep - 120 - (max(self.periods_seen) if "rollup" in table else 0)
                and not self.is_disrupted(ago - 300, ago + 300)
                and table != "connections"
            ):
                out.append(
                    (
                        "FAIL",
                        "retention",
                        f"{table}: oldest row only {age:.0f} s old, retention {keep} s",
                    )
                )
        return out

    def check_references(self, con: sqlite3.Connection) -> list:
        out = []
        for table, columns, lookup in REFERENCES:
            for column in columns:
                n = con.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {column} NOT IN (SELECT id FROM {lookup})"
                ).fetchone()[0]
                if n:
                    out.append(
                        (
                            "FAIL",
                            "references",
                            f"{n} {table}.{column} missing in {lookup}",
                        )
                    )
        if self.runs % 3 == 1:
            unreferenced = 0
            for statement in ORPHAN_DELETES:
                unreferenced += con.execute(
                    statement.replace("DELETE FROM", "SELECT COUNT(*) FROM", 1)
                ).fetchone()[0]
            self.unreferenced.append((self.now, unreferenced))
        if self.unreferenced:
            self.metrics["unreferenced"] = self.unreferenced[-1][1]
        return out

    def check_ground_truth(self, con: sqlite3.Connection) -> list:
        out = []
        span = min(480, self.raw_ret - 90)
        t2 = int(self.now - 3 * self.wmax - 5)
        t1 = t2 - span
        if t1 < self.reset_t + 60 or self.is_disrupted(t1 - self.wmax - 2, t2):
            return out
        results = {}
        for path in sorted(LEDGER.glob("*.jsonl")):
            tag = path.stem
            points = [(e["t"], e["sent"]) for e in read_jsonl(path)]
            if len(points) < 2 or points[0][0] > t1 - self.wmax - 2:
                continue

            def at(t: float, points: list = points) -> float:
                prev = points[0]
                for point in points:
                    if point[0] >= t:
                        if point[0] == prev[0]:
                            return point[1]
                        return prev[1] + (point[1] - prev[1]) * (t - prev[0]) / (
                            point[0] - prev[0]
                        )
                    prev = point
                return points[-1][1]

            low = at(t2 - self.wmax - 1) - at(t1)
            high = at(t2) - at(t1 - self.wmax - 1)
            if high <= 0:
                continue
            # tag-0 and tag-1 are separate processes; "--tag tcp" must not match tcpx
            recorded = con.execute(
                "SELECT TOTAL(c.sent) FROM connections c JOIN executables e ON e.id = c.exe_id"
                " WHERE (e.cmdline LIKE ? OR e.cmdline LIKE ?) AND c.time > ? AND c.time <= ?",
                (f"% --tag {tag} %", f"% {tag}", t1, t2),
            ).fetchone()[0]
            if tag in ("exec", "argv"):
                recorded = con.execute(
                    "SELECT TOTAL(c.sent) FROM connections c JOIN executables e ON e.id = c.exe_id"
                    " WHERE e.cmdline LIKE ? AND e.name = 'benchload' AND c.time > ? AND c.time <= ?",
                    (f"% once % {tag}%", t1, t2),
                ).fetchone()[0]
            if recorded < low:
                off = (low - recorded) / low if low else 1
            elif recorded > high:
                off = (recorded - high) / high
            else:
                off = 0.0
            results[tag] = round(off * 100, 2)
            level = "FAIL" if off > 0.10 else "WARN" if off > 0.02 else None
            if level:
                out.append(
                    (
                        level,
                        "ground-truth",
                        f"{tag}: recorded {recorded:.0f} B, generated {low:.0f}..{high:.0f} B ({off:.1%} off)",
                    )
                )
        self.metrics["truth_off_pct"] = results
        return out

    def check_details(self, con: sqlite3.Connection) -> list:
        out = []
        longest = (
            con.execute("SELECT MAX(length(cmdline)) FROM executables").fetchone()[0]
            or 0
        )
        self.metrics["longest_cmdline"] = longest
        if longest > 4200:
            out.append(
                (
                    "FAIL",
                    "cmdline",
                    f"a command line of {longest} characters, past 4 KiB",
                )
            )
        argv = con.execute(
            "SELECT COUNT(*) FROM executables WHERE name = 'benchload' AND cmdline LIKE '% once % argvx%'"
        ).fetchone()[0]
        self.metrics["argv_rows"] = argv
        if argv > 1:
            out.append(
                (
                    "FAIL",
                    "cmdline",
                    f"{argv} executables rows for command lines differing past 4 KiB",
                )
            )
        names = dict(
            con.execute(
                "SELECT name, COUNT(*) FROM netns WHERE name IN ('nsa', 'nsb') GROUP BY name"
            )
        )
        shared = con.execute(
            "SELECT COUNT(*) FROM (SELECT inode FROM netns WHERE id != 0 GROUP BY inode HAVING COUNT(DISTINCT name) > 1)"
        ).fetchone()[0]
        self.metrics["netns"] = {**names, "inodes_reused": shared}
        for name in ("nsa", "nsb"):
            wrong = con.execute(
                "SELECT n.name, COUNT(*) FROM connections c JOIN executables e ON e.id = c.exe_id JOIN netns n ON n.id = c.netns_id"
                " WHERE e.cmdline LIKE ? AND n.name != ? GROUP BY n.name",
                (f"% --tag ns-{name} %", name),
            ).fetchall()
            for other, n in wrong:
                level = "WARN" if other == "" else "FAIL"
                out.append(
                    (
                        level,
                        "netns-names",
                        f"{n} rows of ns-{name} under namespace {other!r}",
                    )
                )
            wrong = con.execute(
                "SELECT n.name, COUNT(*) FROM interfaces i JOIN netns n ON n.id = i.netns_id WHERE i.name = ? AND n.name != ? GROUP BY n.name",
                (f"vin-{name}", name),
            ).fetchall()
            for other, n in wrong:
                out.append(
                    (
                        "FAIL",
                        "netns-names",
                        f"interface vin-{name} under namespace {other!r} ({n})",
                    )
                )
        router = [e["t"] for e in self.events if e["action"] == "router-up"]
        if router and self.now - router[0] > 180:
            recent = con.execute(
                "SELECT COUNT(*) FROM forwarded WHERE time > ?", (self.now - 120,)
            ).fetchone()[0]
            self.metrics["forwarded_recent"] = recent
            if not recent and not self.is_disrupted(self.now - 120, self.now):
                out.append(
                    (
                        "FAIL",
                        "forwarded",
                        "no forwarded rows in 2 min with the router up",
                    )
                )
        return out

    def check_query(self, con: sqlite3.Connection) -> list:
        out = []
        if self.runs % 2:
            return out
        client = QueryClient(timeout=60)
        try:
            for group in ("name", "domain"):
                for attempt in range(3):
                    end = con.execute("SELECT MAX(time) FROM connections").fetchone()[0]
                    if end is None:
                        return out
                    start = int(self.now - 900) // 180 * 180
                    started = time.monotonic()
                    try:
                        answer = client.request(
                            "aggregate",
                            source="connections",
                            group_by=group,
                            start=start,
                            end=end,
                        )
                    except QueryError as e:
                        out.append(
                            (
                                "FAIL" if attempt == 2 else "PASS",
                                "query",
                                f"{type(e).__name__}: {e}",
                            )
                        )
                        continue
                    took = time.monotonic() - started
                    split = answer["split"]
                    expected = con.execute(
                        "SELECT (SELECT TOTAL(sent) FROM connections_rollup WHERE period >= :s AND period < :m),"
                        " (SELECT TOTAL(sent) FROM connections WHERE time >= :n AND time < :e)",
                        {
                            "s": start,
                            "m": min(end, split),
                            "n": max(start, split),
                            "e": end,
                        },
                    ).fetchone()
                    want = int(expected[0] if start < split else 0) + int(
                        expected[1] if end > split else 0
                    )
                    got = answer["totals"][0]
                    self.metrics[f"query_{group}_s"] = round(took, 2)
                    if took > 2:
                        out.append(
                            (
                                "WARN",
                                "query-latency",
                                f"aggregate by {group} over 15 min took {took:.1f} s",
                            )
                        )
                    if got == want:
                        break
                    if attempt == 2:
                        out.append(
                            (
                                "FAIL",
                                "query-totals",
                                f"by {group}: server {got}, database {want} (split {split})",
                            )
                        )
        finally:
            client.close()
        errors = [
            e
            for e in read_jsonl(LOG / "query.jsonl")
            if e["error"] and e["t"] > self.last.get("t", 0)
        ]
        slow = [
            e
            for e in read_jsonl(LOG / "query.jsonl")
            if e["seconds"] > 5 and e["t"] > self.last.get("t", 0)
        ]
        for e in errors[:3]:
            level = "WARN" if self.is_disrupted(e["t"] - 5, e["t"] + 5) else "FAIL"
            out.append(
                (
                    level,
                    "query-load",
                    f"{e['op']} {e.get('group_by', '')}: {e['error']}",
                )
            )
        if slow:
            worst = max(slow, key=lambda e: e["seconds"])
            out.append(
                (
                    "WARN",
                    "query-load",
                    f"{len(slow)} requests over 5 s, worst {worst['op']} {worst.get('group_by', '')} {worst['span']} s span: {worst['seconds']} s",
                )
            )
        return out

    # --- the run ---

    def run_once(self) -> dict:
        self.metrics: dict = {}
        self.load_context()
        results = []
        started = time.monotonic()
        checks = [self.check_daemon, self.check_journal]
        db_checks = [
            self.check_file,
            self.check_writes,
            self.check_rollups,
            self.check_retention,
            self.check_references,
            self.check_ground_truth,
            self.check_details,
            self.check_query,
        ]
        for check in checks:
            results += self.guarded(check)
        if DB.exists():
            try:
                con = self.db()
            except sqlite3.Error as e:
                results.append(("ERR", "db-open", str(e)))
            else:
                try:
                    for check in db_checks:
                        results += self.guarded(check, con)
                finally:
                    con.close()
        self.metrics["check_s"] = round(time.monotonic() - started, 1)
        worst = max((LEVELS.index(r[0]) for r in results), default=0)
        record = {
            "t": round(self.now, 1),
            "elapsed_min": round((self.now - self.reset_t) / 60, 1),
            "level": LEVELS[worst],
            "results": [
                r
                for r in results
                if r[0] != "PASS" or r[1] in ("daemon-restart", "quick-check")
            ],
            "metrics": self.metrics,
        }
        self.last = {
            "t": self.now,
            **{k: self.metrics.get(k) for k in ("pid", "restarts", "cpu_ns")},
        }
        self.runs += 1
        return record

    def guarded(self, check, *args) -> list:
        try:
            return check(*args)
        except sqlite3.OperationalError as e:
            if "locked" in str(e) or "interrupted" in str(e):
                return [("WARN", check.__name__, f"{type(e).__name__}: {e}")]
            return [("ERR", check.__name__, f"{type(e).__name__}: {e}")]
        except Exception as e:  # a broken check must not stop the others
            tb = traceback.extract_tb(e.__traceback__)[-1]
            return [
                ("ERR", check.__name__, f"{type(e).__name__}: {e} (line {tb.lineno})")
            ]


def line(record: dict) -> str:
    """One check as one line of text."""
    m = record["metrics"]
    rows = m.get("rows", {})
    maint = m.get("maintenance", {})
    raw = rows.get("connections", 0)
    rolled = rows.get("connections_rollup", 0)
    return (
        f"+{record['elapsed_min']:>4}m {record['level']:<4} | {m.get('active')} pid {m.get('pid')} rst {m.get('restarts')}"
        f" rss {m.get('rss_mb')}M cpu {m.get('cpu_pct', '-')}% | conn {raw} roll {rolled} fwd {rows.get('forwarded', 0)}"
        f" | db {m.get('db_mib')}M (max {m.get('max_db_mib')}) wal {m.get('wal_mib')}M free {m.get('free_pct')}%"
        f" | maint {maint.get('passes', 0)}x p={maint.get('periods', 0)} del={maint.get('deleted', 0)}"
        f" orph={maint.get('orphans', 0)}/{maint.get('orphan_passes', 0)}x rel={maint.get('released_mib', 0)}M max {maint.get('max_s', 0)}s"
        f" | gap {m.get('max_gap_s')}s early {m.get('early_windows')} chunks {m.get('rollup_chunks_verified')} unref {m.get('unreferenced', '-')}"
        f" | check {m.get('check_s')}s"
    )


def summary(since: float) -> int:
    records = read_jsonl(CHECKS)
    if not records:
        print("no checks yet")
        return 0
    print(line(records[-1]))
    seen: dict[tuple[str, str], list] = {}
    for record in records:
        if record["t"] <= since:
            continue
        for level, name, detail in record["results"]:
            if level == "PASS" and name != "daemon-restart":
                continue
            key = (level, name)
            if key not in seen:
                seen[key] = [0, detail]
            seen[key][0] += 1
            seen[key][1] = detail
    for (level, name), (n, detail) in sorted(
        seen.items(), key=lambda kv: -LEVELS.index(kv[0][0])
    ):
        print(f"    {level} {name} x{n}: {detail}")
    last = records[-1]
    m = last["metrics"]
    if m.get("truth_off_pct"):
        print(
            f"    truth off %: {m['truth_off_pct']}  netns: {m.get('netns')}  seconds ratio: {m.get('seconds_ratio')}"
        )
    return 2 if any(level in ("FAIL", "ERR") for level, _ in seen) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("loop")
    p.add_argument("--interval", type=float, default=60)
    sub.add_parser("once")
    p = sub.add_parser("summary")
    p.add_argument("--since", type=float, default=0)
    args = parser.parse_args()
    if args.cmd == "summary":
        return summary(args.since)
    checker = Checker()
    if args.cmd == "once":
        print(json.dumps(checker.run_once(), indent=1))
        return 0
    while True:
        started = time.monotonic()
        record = checker.run_once()
        with open(CHECKS, "a") as f:
            f.write(json.dumps(record) + "\n")
        print(line(record), flush=True)
        time.sleep(max(1.0, args.interval - (time.monotonic() - started)))


if __name__ == "__main__":
    sys.exit(main())
