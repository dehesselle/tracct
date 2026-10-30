# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import ipaddress
import logging
import math
import shlex
import socket
import sqlite3
import threading
import time
from collections.abc import Callable

from tracct.config import Config
from tracct.conntrack import Flow, Trackers
from tracct.constants import DB_PATH, RETRY_BUFFER_MAX
from tracct.messages import report
from tracct.netinfo import NetInfo
from tracct.reverse_dns import ReverseDns
from tracct.types import BpfEvent
from tracct.utils import (
    DropOldestQueue,
    ephemeral_port_start,
    quarantine_database,
    sqlite_error_means_corrupt,
)

logger = logging.getLogger(__name__)

#: Distinct connections one write window may hold; past it the window is written early.
WINDOW_CONNECTIONS_MAX = 65536
#: Rows the retention purge deletes per transaction; a write that is due goes between
#: two.
PURGE_CHUNK_ROWS = 10000
#: How often unreferenced lookup entries are looked for at most (once per retention when
#: that is shorter): finding them scans every row, while waiting only leaves a few
#: unused entries.
ORPHAN_INTERVAL_SECONDS = 86400
#: A maintenance pass is skipped when the wall clock moved this far from the boot clock
#: since the last.
CLOCK_JUMP_SECONDS = 60
#: Ids the writer keeps per lookup table; past it the cache starts over from the
#: database.
ID_CACHE_MAX = 65536
#: A namespace as the database keeps it: its inode and the name it has now, "" for
#: none; the namespace of a row whose namespace is unknown.
NO_NETNS = (0, "")
#: The interface of a row whose interface is unknown: namespace, name, kind.
NO_INTERFACE = (NO_NETNS, "", "")
#: Free pages past this share of the file are given back to the filesystem; fewer wait
#: to be reused, as the next windows would only grow the file again.
RELEASE_FREE_FRACTION = 0.25
#: Pages given back per transaction (10 MiB at 4 KiB); a write that is due goes between
#: two.
RELEASE_CHUNK_PAGES = 2560

#: Rows of a closed rollup period, summed; the parameters are the period, the first port
#: of the ephemeral range (ports from there on are a peer's or our own random port, kept
#: as 0 so a server's rollup does not grow with its clients), and the period's bounds,
#: which also give its seconds (less than a period after a change of the period length).
#: Columns are named, so no statement depends on the order a table declares them in.
ROLLUPS = (
    # ICMP (1) and ICMPv6 (58) rows carry the echo id as a port, a new one per ping.
    (
        "INSERT INTO connections_rollup(period, exe_id, pexe_id, unit_id, uid, family, protocol, lport, rport, domain_id, netns_id, iface_id, sent, received, events, rows, seconds)"
        " SELECT :period, exe_id, pexe_id, unit_id, uid, family, protocol,"
        " CASE WHEN lport < :ephemeral AND protocol NOT IN (1, 58) THEN lport ELSE 0 END AS lp,"
        " CASE WHEN rport < :ephemeral AND protocol NOT IN (1, 58) THEN rport ELSE 0 END AS rp,"
        " domain_id, netns_id, iface_id, SUM(sent), SUM(received), SUM(events), COUNT(*), :end - :start"
        " FROM connections WHERE time >= :start AND time < :end"
        " GROUP BY exe_id, pexe_id, unit_id, uid, family, protocol, lp, rp, domain_id, netns_id, iface_id"
    ),
    (
        "INSERT INTO interface_traffic_rollup(period, iface_id, sent, received, seconds)"
        " SELECT :period, iface_id, SUM(sent), SUM(received), :end - :start FROM interface_traffic WHERE time >= :start AND time < :end GROUP BY iface_id"
    ),
    (
        "INSERT INTO forwarded_rollup(period, netns_id, protocol, src_id, dport, domain_id, orig_bytes, reply_bytes, orig_packets, reply_packets, rows, seconds)"
        " SELECT :period, netns_id, protocol, src_id, CASE WHEN dport < :ephemeral THEN dport ELSE 0 END AS dp, domain_id,"
        " SUM(orig_bytes), SUM(reply_bytes), SUM(orig_packets), SUM(reply_packets), COUNT(*), :end - :start"
        " FROM forwarded WHERE time >= :start AND time < :end GROUP BY netns_id, protocol, src_id, dp, domain_id"
    ),
)
INSERT_CONNECTIONS = (
    "INSERT INTO connections(time, sent, received, events, exe_id, pexe_id, unit_id, uid, family, protocol, lport, rport, laddr_id, raddr_id, domain_id, netns_id, iface_id, seconds)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
INSERT_INTERFACE_TRAFFIC = "INSERT INTO interface_traffic(time, iface_id, sent, received, seconds) VALUES (?, ?, ?, ?, ?)"
INSERT_FORWARDED = (
    "INSERT INTO forwarded(time, netns_id, protocol, src_id, sport, dst_id, dport, domain_id, orig_bytes, reply_bytes, orig_packets, reply_packets, seconds)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
#: The tables purged past the raw and the rollup retention, with their time column.
RAW_TABLES = (
    ("connections", "time"),
    ("interface_traffic", "time"),
    ("forwarded", "time"),
)
ROLLUP_TABLES = (
    ("connections_rollup", "period"),
    ("interface_traffic_rollup", "period"),
    ("forwarded_rollup", "period"),
)
#: Lookup entries nothing refers to, one transaction each; executables, units and domains
#: read the indexes on their ids, the others scan the tables referring to them.
ORPHAN_DELETES = (
    (
        "DELETE FROM executables WHERE id != 0"
        " AND NOT EXISTS (SELECT 1 FROM connections WHERE exe_id = executables.id) AND NOT EXISTS (SELECT 1 FROM connections WHERE pexe_id = executables.id)"
        " AND NOT EXISTS (SELECT 1 FROM connections_rollup WHERE exe_id = executables.id) AND NOT EXISTS (SELECT 1 FROM connections_rollup WHERE pexe_id = executables.id)"
    ),
    "DELETE FROM units WHERE id != 0 AND id NOT IN (SELECT unit_id FROM connections UNION SELECT unit_id FROM connections_rollup)",
    (
        "DELETE FROM domains WHERE id != 0 AND id NOT IN"
        " (SELECT domain_id FROM connections UNION SELECT domain_id FROM connections_rollup UNION SELECT domain_id FROM forwarded UNION SELECT domain_id FROM forwarded_rollup)"
    ),
    (
        "DELETE FROM addresses WHERE id != 0 AND id NOT IN"
        " (SELECT laddr_id FROM connections UNION SELECT raddr_id FROM connections UNION SELECT src_id FROM forwarded UNION SELECT dst_id FROM forwarded UNION SELECT src_id FROM forwarded_rollup)"
    ),
    (
        "DELETE FROM interfaces WHERE id != 0 AND id NOT IN"
        " (SELECT iface_id FROM connections UNION SELECT iface_id FROM connections_rollup UNION SELECT iface_id FROM interface_traffic UNION SELECT iface_id FROM interface_traffic_rollup)"
    ),
    # After the interfaces, whose deletion frees namespaces.
    (
        "DELETE FROM netns WHERE id != 0 AND id NOT IN"
        " (SELECT netns_id FROM connections UNION SELECT netns_id FROM connections_rollup UNION SELECT netns_id FROM interfaces UNION SELECT netns_id FROM forwarded UNION SELECT netns_id FROM forwarded_rollup)"
    ),
)


class Interned:
    """The ids of one lookup table, cached.

    Ids a rolled-back transaction inserted are dropped again, as sqlite hands their
    rowids out anew.
    """

    def __init__(self, table: str, columns: tuple[str, ...], sentinel: tuple) -> None:
        self.insert = f"INSERT OR IGNORE INTO {table}({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"
        self.select = f"SELECT id FROM {table} WHERE {' AND '.join(f'{column} = ?' for column in columns)}"
        self.sentinel = sentinel
        self.ids: dict[tuple, int] = {sentinel: 0}
        #: Inserted during the current, uncommitted transaction.
        self.pending: list[tuple] = []

    def id(self, con: sqlite3.Connection, key: tuple) -> int:
        found = self.ids.get(key)
        if found is None:
            con.execute(self.insert, key)
            found = con.execute(self.select, key).fetchone()[0]
            self.ids[key] = found
            self.pending.append(key)
        return found

    def committed(self) -> None:
        self.pending.clear()

    def rolled_back(self) -> None:
        for key in self.pending:
            self.ids.pop(key, None)
        self.pending.clear()

    def clear(self) -> None:
        self.ids = {self.sentinel: 0}
        self.pending.clear()


class WriteWindow:
    """The connections and forwarded flows of one write window, summed as their events
    arrive, so memory follows the number of distinct connections rather than events. The
    events are not modified, the live feed may still be sending the same objects.
    """

    def __init__(
        self,
        config: Config,
        reverse_dns: ReverseDns | None = None,
        netinfo: NetInfo | None = None,
    ) -> None:
        self.config = config
        self.reverse_dns = reverse_dns
        self.netinfo = netinfo
        self.ignored_networks = [
            ipaddress.ip_network(ip_subnet, strict=False)
            for ip_subnet in config.record.ignore_ips
        ]
        self.connections: dict[tuple, list[int]] = {}
        self.flows: dict[tuple, list[int]] = {}
        #: Many connections in one window share a cmdline, and this string work
        #: dominated at high cardinality.
        self.cmdlines: dict[str, str] = {}
        #: (exe, name, unit) -> what is recorded of it, from [[record.process]].
        self.details: dict[tuple[str, str, str], tuple[bool, bool, bool]] = {}

    def __len__(self) -> int:
        return len(self.connections) + len(self.flows)

    def clean_cmdline(self, raw: str) -> str:
        cleaned = self.cmdlines.get(raw)
        if cleaned is None:
            cleaned = shlex.join(
                raw.encode("utf-8", "ignore")
                .decode("utf-8", "ignore")
                .strip("\0\t\n ")
                .split("\0")
            )
            self.cmdlines[raw] = cleaned
        return cleaned

    def detail(self, proc: BpfEvent) -> tuple[bool, bool, bool]:
        """Whether a process's addresses, ports and commands are recorded: as the first
        rule matching it says, else as [record] does.
        """
        record = self.config.record
        if not record.process:
            return record.addresses, record.ports, record.commands
        key = (proc["exe"], proc["name"], proc.get("unit", ""))
        detail = self.details.get(key)
        if detail is None:
            rule = next((rule for rule in record.process if rule.matches(*key)), None)
            if rule is None:
                detail = record.addresses, record.ports, record.commands
            else:
                detail = (
                    record.addresses if rule.addresses is None else rule.addresses,
                    record.ports if rule.ports is None else rule.ports,
                    record.commands if rule.commands is None else rule.commands,
                )
            self.details[key] = detail
        return detail

    def ignored(self, *addresses: str) -> bool:
        if self.ignored_networks:
            for address in addresses:
                if address and any(
                    ipaddress.ip_address(address) in network
                    for network in self.ignored_networks
                ):
                    return True
        return False

    def interface(
        self, netns: tuple[int, str], laddr: str, tun: str
    ) -> tuple[tuple[int, str], str, str]:
        """The interface a row was counted on.

        The TUN device of a process's TUN reads and writes, else the interface holding
        the local address.
        """
        if self.netinfo is None:
            return NO_INTERFACE
        name, kind = (tun, "tun") if tun else self.netinfo.interface_of(netns[0], laddr)
        return (netns, name, kind) if name else NO_INTERFACE

    def add(self, events: list[BpfEvent]) -> None:
        record = self.config.record
        for proc in events:
            addresses, ports, commands = self.detail(proc)
            # Join or omit commands from logs.
            if commands:
                cmdline = self.clean_cmdline(proc["cmdline"])
                pcmdline = self.clean_cmdline(proc["pcmdline"])
            else:
                cmdline = pcmdline = ""
            # The domain the program looked up; omitted with the address from logs.
            domain, raddr = proc["domain"], proc["raddr"]
            if not addresses:
                domain = raddr = ""
            lport, rport = proc["lport"], proc["rport"]
            if not ports:
                lport, rport = min(0, lport), min(0, rport)
            # Omit entry from logs (domains are matched in take_rows, once reverse DNS
            # had its chance).
            if rport in record.ignore_ports or lport in record.ignore_ports:
                continue
            if self.ignored_networks and raddr and self.ignored(raddr, proc["laddr"]):
                continue
            family = int(proc.get("family", 0) or 0)
            netns = int(proc.get("netns", 0) or 0)
            # The interface follows from netns and laddr in the key, and is looked up
            # once per row in take_rows; only a TUN row needs its process for it, which
            # is not in the key.
            tun = (
                self.netinfo.tun_of(proc["pid"])
                if family == socket.AF_PACKET and self.netinfo is not None
                else ""
            )
            key = (
                (proc["exe"], proc["name"], cmdline),
                (proc["pexe"], proc["pname"], pcmdline),
                proc.get("unit", ""),
                proc["uid"],
                family,
                int(proc.get("protocol", 0) or 0),
                lport,
                rport,
                proc["laddr"],
                raddr,
                domain,
                netns,
                tun,
            )
            counters = self.connections.get(key)
            if counters is None:
                self.connections[key] = [
                    proc["send"],
                    proc["recv"],
                    proc.get("pkts", 1),
                ]
                if self.netinfo is not None:
                    self.netinfo.note(netns, proc["pid"])
                # Asked for now, so the answer has the rest of the window to arrive.
                if not domain and raddr and self.reverse_dns is not None:
                    self.reverse_dns.lookup(raddr)
            else:
                counters[0] += proc["send"]
                counters[1] += proc["recv"]
                counters[2] += proc.get("pkts", 1)

    def add_flows(self, flows: list[Flow]) -> None:
        record = self.config.record
        for flow in flows:
            src, dst = (flow.src, flow.dst) if record.addresses else ("", "")
            sport, dport = (flow.sport, flow.dport) if record.ports else (0, 0)
            if (
                sport in record.ignore_ports
                or dport in record.ignore_ports
                or self.ignored(src, dst)
            ):
                continue
            key = (flow.netns, flow.protocol, src, sport, dst, dport)
            counters = self.flows.get(key)
            if counters is None:
                self.flows[key] = [
                    flow.orig_bytes,
                    flow.reply_bytes,
                    flow.orig_packets,
                    flow.reply_packets,
                ]
                if dst and self.reverse_dns is not None:
                    self.reverse_dns.lookup(dst)
            else:
                counters[0] += flow.orig_bytes
                counters[1] += flow.reply_bytes
                counters[2] += flow.orig_packets
                counters[3] += flow.reply_packets

    def domain_of(self, address: str) -> str:
        return (
            self.reverse_dns.lookup(address)
            if address and self.reverse_dns is not None
            else ""
        )

    def is_ignored_domain(self, domain: str) -> bool:
        return any(
            domain.startswith(domain_prefix)
            for domain_prefix in self.config.record.ignore_domains
        )

    def take_rows(
        self, names: dict[int, str] | None = None, seconds: int = 0
    ) -> tuple[list[tuple], list[tuple]]:
        """The window as connection and forwarded rows for the database, with domains
        from reverse DNS where the program looked up none, each namespace as (inode,
        name) by names, and the seconds the window lasted last; the next window starts
        empty.
        """
        names = names or {}
        written = int(time.time())
        rows: dict[tuple, list[int]] = {}
        for key, (send, recv, n_events) in self.connections.items():
            *identity, laddr, raddr, domain, inode, tun = key
            if not domain:
                domain = self.domain_of(raddr)
            netns = (inode, names.get(inode, ""))
            key = (
                *identity,
                laddr,
                raddr,
                domain,
                netns,
                self.interface(netns, laddr, tun),
            )
            if self.is_ignored_domain(domain):
                continue
            # A connection with and without the domain the program looked up are one row
            # now.
            counters = rows.get(key)
            if counters is None:
                rows[key] = [send, recv, n_events]
            else:
                counters[0] += send
                counters[1] += recv
                counters[2] += n_events
        flow_rows = []
        for (inode, protocol, src, sport, dst, dport), counters in self.flows.items():
            domain = self.domain_of(dst)
            if not self.is_ignored_domain(domain):
                flow_rows.append(
                    (
                        written,
                        (inode, names.get(inode, "")),
                        protocol,
                        src,
                        sport,
                        dst,
                        dport,
                        domain,
                        *counters,
                        seconds,
                    )
                )
        self.connections = {}
        self.flows = {}
        self.cmdlines = {}
        self.details = {}
        return [
            (written, send, recv, n_events, *key, seconds)
            for key, (send, recv, n_events) in rows.items()
        ], flow_rows


def window_seconds(started: float, ended: float) -> int:
    """The seconds a window lasted, for its rows.

    Its ends are rounded rather than its length: a window runs a fraction past its due
    time, which rounding the length would drop every time, so a stretch of windows would
    add up to less than the stretch.
    """
    return round(ended) - round(started)


def _chunked_delete(
    con: sqlite3.Connection,
    table: str,
    column: str,
    cutoff: int,
    between_chunks: Callable[[], bool],
) -> tuple[int, bool]:
    """Delete the rows of table older than cutoff.

    Returns how many, and whether between_chunks stopped it.
    """
    deleted = 0
    while True:
        with con:
            chunk = con.execute(
                f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {column} < ? LIMIT ?)",
                (cutoff, PURGE_CHUNK_ROWS),
            ).rowcount
        deleted += chunk
        if chunk < PURGE_CHUNK_ROWS:
            return deleted, False
        if between_chunks():
            return deleted, True


def roll_up(
    con: sqlite3.Connection,
    period_minutes: int,
    between_periods: Callable[[], bool],
    ephemeral: int | None = None,
) -> int:
    """Sum the raw rows of every period that has closed since the last one rolled up,
    per period; the watermark in meta marks where the next starts. Returns the number of
    periods summed.
    """
    period = period_minutes * 60
    ephemeral = ephemeral_port_start() if ephemeral is None else ephemeral
    # Periods end on multiples of the period length; the current one is still open, and
    # so is the newest row's, so a clock running ahead cannot carry the watermark past
    # the data.
    now = int(time.time())
    current = closed = now // period * period
    newest_sql = "SELECT MAX(t) FROM (SELECT MAX(time) AS t FROM connections UNION ALL SELECT MAX(time) FROM interface_traffic UNION ALL SELECT MAX(time) FROM forwarded)"
    newest = con.execute(newest_sql).fetchone()[0]
    if newest is not None:
        closed = min(closed, newest // period * period)
    row = con.execute(
        "SELECT value FROM meta WHERE key = 'rollup_watermark'"
    ).fetchone()
    watermark = row[0] if row is not None else 0
    if watermark > now:
        # The clock went back past periods rolled up while it ran ahead: their rollups
        # go, and the periods are rolled up again once they close, with the rows written
        # since.
        with con:
            for table, column in ROLLUP_TABLES:
                con.execute(f"DELETE FROM {table} WHERE {column} >= ?", (current,))
            con.execute(
                "UPDATE meta SET value = ? WHERE key = 'rollup_watermark'", (current,)
            )
        report(
            logger,
            "clock-went-back",
            f"maintenance: the wall clock went back behind the rolled-up periods; rolling up again from {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(current))}",
        )
        watermark = current
    periods = 0
    while watermark < closed:
        # The next row at or past the watermark, so spans without any are skipped (a
        # first start, a long downtime).
        oldest = con.execute(
            "SELECT MIN(t) FROM (SELECT MIN(time) AS t FROM connections WHERE time >= :w UNION ALL SELECT MIN(time) FROM interface_traffic WHERE time >= :w"
            " UNION ALL SELECT MIN(time) FROM forwarded WHERE time >= :w)",
            {"w": watermark},
        ).fetchone()[0]
        if oldest is None or oldest >= closed:
            start = end = closed
        else:
            # After a change of the period length the watermark may sit inside a period.
            start = max(watermark, oldest // period * period)
            end = start // period * period + period
        with con:
            if start < end:
                for statement in ROLLUPS:
                    con.execute(
                        statement,
                        {
                            # The start of what the rollup covers, so a partial period
                            # is not placed over the one before it.
                            "period": start,
                            "ephemeral": ephemeral,
                            "start": start,
                            "end": end,
                        },
                    )
                periods += 1
            con.execute(
                "INSERT INTO meta(key, value) VALUES ('rollup_watermark', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (end,),
            )
        watermark = end
        if watermark < closed and between_periods():
            break
    return periods


def retention_seconds(config: Config) -> tuple[int, int]:
    """The raw and the rollup retention in seconds, 0 for keeping forever.

    Retention may be a fraction of a day, rounded up so a tiny one never becomes 0.
    """
    database = config.database
    return math.ceil(database.raw_retention_days * 86400), math.ceil(
        database.rollup_retention_days * 86400
    )


def purge_database(
    con: sqlite3.Connection, config: Config, between_chunks: Callable[[], bool]
) -> tuple[int, int]:
    """Roll up the closed periods, then delete the rows past their retention in chunks
    (raw rows only once rolled up). between_chunks runs after each committed chunk or
    period and ends the purge by returning True. Returns the numbers of periods rolled
    up and rows deleted.
    """
    periods = roll_up(con, config.database.rollup_period_minutes, between_chunks)
    now = int(time.time())
    # A cutoff past the newest row means a future clock (booted before NTP), which would
    # wipe the db.
    newest = con.execute("SELECT MAX(time) FROM connections").fetchone()[0]
    raw_seconds, rollup_seconds = retention_seconds(config)
    shortest = raw_seconds or rollup_seconds
    if newest is not None and shortest > 0 and now - shortest > newest:
        report(
            logger,
            "retention-skipped",
            "skipping retention purge, wall clock is ahead of the newest logged connection (clock not synced?); no rows deleted",
        )
        return periods, 0
    watermark_row = con.execute(
        "SELECT value FROM meta WHERE key = 'rollup_watermark'"
    ).fetchone()
    watermark = watermark_row[0] if watermark_row is not None else 0
    purges = []
    # Retention 0 is the usual "keep forever"; raw rows go only once they are rolled up.
    if raw_seconds > 0:
        purges += [
            (table, column, min(now - raw_seconds, watermark))
            for table, column in RAW_TABLES
        ]
    if rollup_seconds > 0:
        purges += [
            (table, column, now - rollup_seconds) for table, column in ROLLUP_TABLES
        ]
    deleted = 0
    for table, column, cutoff in purges:
        count, stopped = _chunked_delete(con, table, column, cutoff, between_chunks)
        deleted += count
        if stopped:
            break
    return periods, deleted


def delete_orphans(
    con: sqlite3.Connection, between_statements: Callable[[], bool]
) -> int:
    """Delete the lookup entries nothing refers to any more, one table per transaction.

    between_statements runs after each and ends the cleanup by returning True. Returns
    the number of entries deleted.
    """
    orphans = 0
    for statement in ORPHAN_DELETES:
        with con:
            orphans += con.execute(statement).rowcount
        if between_statements():
            break
    return orphans


def release_free_pages(
    con: sqlite3.Connection, between_chunks: Callable[[], bool]
) -> int:
    """Give the free pages back to the filesystem in chunks, once they are more than
    RELEASE_FREE_FRACTION of the file (after a burst, or a shorter retention).

    between_chunks runs after each chunk and ends the release by returning True. The
    file shrinks at the next WAL checkpoint. Returns the number of bytes released.
    """
    if con.execute("PRAGMA auto_vacuum").fetchone()[0] != 2:
        # Not created with incremental auto_vacuum; only a VACUUM could shrink it.
        return 0
    free = con.execute("PRAGMA freelist_count").fetchone()[0]
    if free <= con.execute("PRAGMA page_count").fetchone()[0] * RELEASE_FREE_FRACTION:
        return 0
    page_size = con.execute("PRAGMA page_size").fetchone()[0]
    released = 0
    while free:
        with con:
            # Each step releases one page, so the statement is run to its end.
            con.execute(f"PRAGMA incremental_vacuum({RELEASE_CHUNK_PAGES})").fetchall()
        left = con.execute("PRAGMA freelist_count").fetchone()[0]
        if left >= free:
            break
        released += free - left
        free = left
        if free and between_chunks():
            break
    return released * page_size


class ClockCheck:
    """How far the wall clock moved apart from the boot clock between two calls.

    A clock set by hand or stepped by NTP. The boot clock keeps counting through a
    suspend.
    """

    def __init__(
        self,
        wall: Callable[[], float] = time.time,
        boot: Callable[[], float] = lambda: time.clock_gettime(time.CLOCK_BOOTTIME),
    ) -> None:
        self.wall = wall
        self.boot = boot
        self.last: tuple[float, float] | None = None

    def jump(self) -> float:
        """Seconds the wall clock jumped since the last call, 0 on the first."""
        now = (self.wall(), self.boot())
        last, self.last = self.last, now
        return 0.0 if last is None else (now[0] - last[0]) - (now[1] - last[1])


def run_writer(
    config: Config, batches: DropOldestQueue[BpfEvent], stop: threading.Event
) -> None:
    """The writer thread.

    Sums the reader's batches per write window, writes them to SQLite with the interface
    counters and forwarded flows of the window, and rolls up and purges past the
    retention windows; once stop is set it writes what is left and returns.
    """
    file_path = DB_PATH
    executables = Interned("executables", ("exe", "name", "cmdline"), ("", "", ""))
    domains = Interned("domains", ("domain",), ("",))
    addresses = Interned("addresses", ("addr",), ("",))
    units = Interned("units", ("unit",), ("",))
    namespaces = Interned("netns", ("inode", "name"), NO_NETNS)
    interfaces = Interned("interfaces", ("netns_id", "name", "kind"), (0, "", ""))
    interned = (executables, domains, addresses, units, namespaces, interfaces)

    def interface_id(
        con: sqlite3.Connection, iface: tuple[tuple[int, str], str, str]
    ) -> int:
        netns, name, kind = iface
        return interfaces.id(con, (namespaces.id(con, netns), name, kind))

    record = config.record
    reverse_dns = (
        ReverseDns()
        if record.reverse_dns
        and (record.addresses or any(rule.addresses for rule in record.process))
        else None
    )
    netinfo = NetInfo() if config.database.enabled else None
    forwarded = (
        Trackers() if netinfo is not None and config.monitoring.conntrack else None
    )

    def collect_forwarded() -> list[Flow]:
        """The forwarded flows of every namespace the last refresh looked at.

        A namespace that cannot be read is reported and skipped, so the rest of the
        window is still written.
        """
        if forwarded is None or netinfo is None:
            return []
        return forwarded.collect(
            {
                inode: (netinfo.label(inode), path, netinfo.local_addresses(inode))
                for inode, path in netinfo.paths.items()
            }
        )

    if netinfo is not None:
        # The baseline the first window's interface counters and forwarded flows start
        # from.
        netinfo.refresh()
        collect_forwarded()
    window = WriteWindow(config, reverse_dns, netinfo)
    # Where the current window started, for the seconds its rows cover: a window may be
    # written early, and the config may change between runs.
    window_start = time.monotonic()

    def clear_id_caches() -> None:
        for table in interned:
            table.clear()

    # Rows waiting for a write that succeeds: connections, interface counters, forwarded
    # flows.
    transaction: list[tuple] = []
    iface_rows: list[tuple] = []
    flow_rows: list[tuple] = []

    def write() -> None:
        nonlocal transaction, iface_rows, flow_rows, window_start
        started, window_start = window_start, time.monotonic()
        seconds = window_seconds(started, window_start)
        names: dict[int, str] = {}
        if netinfo is not None:
            # A namespace removed since the last refresh keeps its name for the rows of
            # its last window.
            names = dict(netinfo.names)
            # First, so the window's rows find the namespaces and addresses as they are
            # now.
            written = int(time.time())
            traffic = netinfo.refresh()
            names.update(netinfo.names)
            iface_rows += [
                (written, ((inode, names.get(inode, "")), name, kind), tx, rx, seconds)
                for inode, name, kind, rx, tx in traffic
            ]
            window.add_flows(collect_forwarded())
        rows, flows = window.take_rows(names, seconds)
        transaction += rows
        flow_rows += flows
        if any(len(table.ids) > ID_CACHE_MAX for table in interned):
            clear_id_caches()
        transaction_success = False
        try:
            if config.database.enabled:
                con = sqlite3.connect(file_path)
                with con:
                    conn_rows = []
                    for (
                        written,
                        sent,
                        received,
                        n_events,
                        exe_key,
                        pexe_key,
                        unit,
                        uid,
                        family,
                        protocol,
                        lport,
                        rport,
                        laddr,
                        raddr,
                        domain,
                        netns,
                        iface,
                        seconds,
                    ) in transaction:
                        conn_rows.append(
                            (
                                written,
                                sent,
                                received,
                                n_events,
                                executables.id(con, exe_key),
                                executables.id(con, pexe_key),
                                units.id(con, (unit,)),
                                uid,
                                family,
                                protocol,
                                lport,
                                rport,
                                addresses.id(con, (laddr,)),
                                addresses.id(con, (raddr,)),
                                domains.id(con, (domain,)),
                                namespaces.id(con, netns),
                                interface_id(con, iface),
                                seconds,
                            )
                        )
                    con.executemany(INSERT_CONNECTIONS, conn_rows)
                    con.executemany(
                        INSERT_INTERFACE_TRAFFIC,
                        [
                            (written, interface_id(con, iface), sent, received, seconds)
                            for written, iface, sent, received, seconds in iface_rows
                        ],
                    )
                    con.executemany(
                        INSERT_FORWARDED,
                        [
                            (
                                written,
                                namespaces.id(con, netns),
                                protocol,
                                addresses.id(con, (src,)),
                                sport,
                                addresses.id(con, (dst,)),
                                dport,
                                domains.id(con, (domain,)),
                                *counters,
                                seconds,
                            )
                            for written, netns, protocol, src, sport, dst, dport, domain, *counters, seconds in flow_rows
                        ],
                    )
                con.close()
                transaction_success = True
                for table in interned:
                    table.committed()  # cached ids are now durable
        except Exception as e:
            # Rolled back: drop this transaction's cache entries so a retry re-inserts.
            for table in interned:
                table.rolled_back()
            if isinstance(e, sqlite3.DatabaseError) and sqlite_error_means_corrupt(e):
                raise
            report(
                logger,
                "sqlite-retry",
                "SQLite execute {}{} on line {}, will retry {} entries".format(
                    type(e).__name__,
                    str(e.args),
                    e.__traceback__.tb_lineno if e.__traceback__ else "?",
                    len(transaction),
                ),
            )
        if transaction_success or not config.database.enabled:
            transaction, iface_rows, flow_rows = [], [], []
            return
        # A persistent write outage would grow the buffers unbounded; keep the newest.
        dropped = [
            len(rows) - RETRY_BUFFER_MAX
            for rows in (transaction, iface_rows, flow_rows)
        ]
        if any(count > 0 for count in dropped):
            transaction, iface_rows, flow_rows = (
                transaction[-RETRY_BUFFER_MAX:],
                iface_rows[-RETRY_BUFFER_MAX:],
                flow_rows[-RETRY_BUFFER_MAX:],
            )
            connections, interface_rows, forwarded_rows = (
                max(0, count) for count in dropped
            )
            report(
                logger,
                "retry-buffer-full",
                f"writer retry buffer full (persistent write outage), dropped the oldest {connections} connection, {interface_rows} interface and {forwarded_rows} forwarded row(s);"
                f" retrying {len(transaction) + len(iface_rows) + len(flow_rows)}",
            )

    last_write = 0.0

    def collect(timeout: float) -> None:
        for batch in batches.get_all(timeout):
            window.add(batch)

    def write_if_due() -> None:
        nonlocal last_write
        # Interface counters and forwarded flows are due every window, with or without
        # connections.
        if (
            time.monotonic() - last_write > config.database.write_limit_seconds
            or len(window) >= WINDOW_CONNECTIONS_MAX
        ):
            last_write = time.monotonic()
            write()

    clock = ClockCheck()
    orphan_interval = min(
        [
            ORPHAN_INTERVAL_SECONDS,
            *(seconds for seconds in retention_seconds(config) if seconds > 0),
        ]
    )
    # Entries become orphans only when rows are deleted; the first cleanup follows the
    # first purge.
    next_orphans = time.monotonic()
    deleted_since_orphans = 0

    def maintain() -> None:
        nonlocal next_orphans, deleted_since_orphans

        def between_chunks() -> bool:
            collect(0)
            write_if_due()
            return stop.is_set()

        def between_orphan_deletes() -> bool:
            # The entries just deleted may be cached, and the write in between must not
            # use them.
            clear_id_caches()
            return between_chunks()

        jump = clock.jump()
        if abs(jump) > CLOCK_JUMP_SECONDS:
            # Rows past their retention by a clock set wrong would be gone for good.
            report(
                logger,
                "maintenance-clock-jump",
                f"maintenance: skipped, the wall clock jumped {jump:+.0f} s since the last pass; the next pass trusts it",
            )
            return
        started = time.monotonic()
        orphans = None
        released = 0
        con = sqlite3.connect(file_path)
        try:
            periods, deleted = purge_database(con, config, between_chunks)
            deleted_since_orphans += deleted
            if (
                deleted_since_orphans
                and time.monotonic() >= next_orphans
                and not stop.is_set()
            ):
                orphans = delete_orphans(con, between_orphan_deletes)
                next_orphans = time.monotonic() + orphan_interval
                deleted_since_orphans = 0
            if not stop.is_set():
                released = release_free_pages(con, between_chunks)
        finally:
            con.close()
            # Orphan cleanup deletes ids the caches may hold.
            clear_id_caches()
        if periods or deleted or orphans is not None or released:
            cleanup = (
                "" if orphans is None else f" and {orphans} unreferenced lookup entries"
            )
            release = (
                f", released {released / 1048576:.0f} MiB of free space"
                if released
                else ""
            )
            report(
                logger,
                "maintenance-done",
                f"maintenance: rolled up {periods} period(s), deleted {deleted} row(s){cleanup}{release} in {time.monotonic() - started:.1f} s",
            )

    # The first pass runs at startup.
    next_maintenance = time.monotonic()
    try:
        while True:
            # Checked before emptying the queue: the reader has stopped by the time stop
            # is set, so the queue then holds all that is left.
            stopping = stop.is_set()
            try:
                collect(0.5)
                if stopping:
                    write()
                    return
                write_if_due()
                if config.database.enabled and time.monotonic() >= next_maintenance:
                    next_maintenance = (
                        time.monotonic()
                        + config.database.maintenance_interval_minutes * 60
                    )
                    maintain()
            except Exception as e:
                if isinstance(e, sqlite3.DatabaseError) and sqlite_error_means_corrupt(
                    e
                ):
                    # The thread ends and the daemon exits, for the service manager to
                    # start it on a new db.
                    report(
                        logger,
                        "database-unusable",
                        f"tracct.db is unusable ({e}); quarantining to {file_path.name}.bad and recreating on restart",
                    )
                    quarantine_database(file_path)
                    raise
                report(
                    logger,
                    "writer-failed",
                    "{}{} on line {}".format(
                        type(e).__name__,
                        str(e.args),
                        e.__traceback__.tb_lineno if e.__traceback__ else "?",
                    ),
                )
    finally:
        if reverse_dns is not None:
            reverse_dns.close()
        if forwarded is not None:
            forwarded.close()
