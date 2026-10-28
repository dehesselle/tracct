# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""the query server: answers the viewer's history requests from the database, opened read-only.
it runs as tracct-query.service, which systemd starts on the first connection to
tracct-query.socket, without capabilities, and exits once no viewer has been connected for a
while. a request names a source, a dimension to group by, filters and a time range; dimensions
map to SQL here and values are bound, so no SQL comes from a client.

each source has a raw table and a rollup. a range is read from the raw rows wherever they still
exist and from the rollups before that (the split), so the detail of the raw rows (addresses,
ephemeral ports) is there for all of the raw retention. a dimension the rollups do not keep clips
the range to the split; ports are coarsened in the raw rows the way the rollups keep them
whenever a range reaches into the rollups, so a port groups the same on both sides"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import socket
import sqlite3
import threading
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path

from tracct.config import load_config
from tracct.constants import DB_PATH, DB_VERSION
from tracct.query import MAX_RESPONSE_BYTES, QUERY_SOCKET_PATH, recv_message, send_message
from tracct.utils import ephemeral_port_start

# viewers connected at once; one more is told so and closed
MAX_CLIENTS = 8
MAX_REQUEST_BYTES = 64 * 1024
MAX_FILTERS = 16
MAX_ROWS = 10000
DEFAULT_ROWS = 1000
MAX_BUCKETS = 4000
# a query running longer is interrupted
QUERY_TIMEOUT_SECONDS = 30
# a viewer that does not take its answer within this is dropped
SEND_TIMEOUT_SECONDS = 60
# under socket activation the server exits once no viewer has been connected this long
IDLE_EXIT_SECONDS = 600
# the first file descriptor systemd passes (sd_listen_fds(3))
SD_LISTEN_FDS_START = 3

# the join a key may need; the raw table and its rollup are both t and share their columns
JOIN_INTERFACE = "JOIN interfaces ti ON ti.id = t.iface_id"


@dataclasses.dataclass(frozen=True)
class Dimension:
    """each part of a request groups its rows by the key; the outer query turns each key k into
    the value shown, so text from the lookup tables is read once per group, not per row"""

    label: str
    # over the raw table t
    key: str
    # the value of key {k}
    value: str = "{k}"
    # true for a row whose value is the one bound to each ?; by default the value of its key is
    match: str = ""
    join: bool = False
    # the key over the rollup; None when the rollup does not keep it
    rollup: str | None = ""
    # the key over the raw table kept the way the rollup keeps it, for a range that reads both
    coarse: str = ""

    def key_sql(self, rollup: bool, coarse: bool, ephemeral: int) -> str:
        if rollup:
            key = self.rollup or self.key
        else:
            key = (self.coarse if coarse else "") or self.key
        return key.replace("{ephemeral}", str(ephemeral))

    def value_sql(self, k: str) -> str:
        return self.value.replace("{k}", k)

    def match_sql(self, rollup: bool, coarse: bool, ephemeral: int) -> str:
        return self.match or f"{self.value_sql(self.key_sql(rollup, coarse, ephemeral))} IS ?"


def _lookup(label: str, column: str, table: str, field: str, raw_only: bool = False) -> Dimension:
    # the id filters use the (exe_id, contime) indexes of the traffic tables
    return Dimension(label, f"t.{column}", f"(SELECT {field} FROM {table} WHERE id = {{k}})", f"t.{column} IN (SELECT id FROM {table} WHERE {field} IS ?)", rollup=None if raw_only else "")


def _port(label: str, column: str, icmp: bool) -> Dimension:
    # the rollups keep a port below the ephemeral range, and none for ICMP, whose rows carry the echo id
    icmp_case = " AND t.protocol NOT IN (1, 58)" if icmp else ""
    return Dimension(label, f"t.{column}", coarse=f"CASE WHEN t.{column} < {{ephemeral}}{icmp_case} THEN t.{column} ELSE 0 END")


# a namespace by name, unnamed ones by inode; an interface qualified by its namespace, as each
# namespace has its own lo and the VPN namespaces may each have a tun0
NETNS = Dimension(
    "namespace",
    "t.netns",
    "COALESCE((SELECT name FROM netns WHERE inode = {k}), CAST({k} AS TEXT))",
    "(t.netns IN (SELECT inode FROM netns WHERE name IS ?) OR CAST(t.netns AS TEXT) IS ?)",
)
_IFACE_FROM = "interfaces i LEFT JOIN netns n ON n.inode = i.netns"
_IFACE_NAME = "CASE WHEN i.id = 0 THEN '' ELSE COALESCE(n.name, CAST(i.netns AS TEXT)) || '/' || i.name END"
_IFACE_NETNS = "COALESCE(n.name, CAST(i.netns AS TEXT))"
IFACE = Dimension("interface", "t.iface_id", f"(SELECT {_IFACE_NAME} FROM {_IFACE_FROM} WHERE i.id = {{k}})", f"t.iface_id IN (SELECT i.id FROM {_IFACE_FROM} WHERE {_IFACE_NAME} IS ?)")
# see "Layers" in docs/DESIGN.md: a socket on a tun is inside the tunnel, a raw row on a tun is the VPN client's
LAYER = Dimension("layer", "CASE WHEN ti.kind = 'tun' AND t.family = 17 THEN 'tunnel' WHEN ti.kind = 'tun' THEN 'inner' ELSE 'outer' END", join=True)
# the same on an interface's counters: a tun device carries what goes through the tunnel
IFACE_LAYER = Dimension("layer", "CASE WHEN ti.kind = 'tun' THEN 'inner' ELSE 'outer' END", join=True)
# the layers as conditions on a row, for the sums per layer every request adds up alongside its
# rows; {tun} is the ids of the tun devices, read once per request rather than joined per row.
# outer is what the others leave, so it needs no sum of its own
LAYER_SUMS = (("inner", "t.iface_id IN ({tun}) AND t.family IS NOT 17"), ("tunnel", "t.iface_id IN ({tun}) AND t.family = 17"))
IFACE_LAYER_SUMS = (("inner", "t.iface_id IN ({tun})"),)
DOMAIN = _lookup("domain", "domain_id", "domains", "domain")
PROTOCOL = Dimension("protocol", "t.protocol")


@dataclasses.dataclass(frozen=True)
class Source:
    label: str
    # what its bytes are; the three kinds are never added together
    kind: str
    raw: str
    rollup: str
    # the two byte columns, as (out, in) where a direction applies
    values: tuple[str, str]
    value_labels: tuple[str, str]
    dimensions: dict[str, Dimension]
    default: str
    # the dimension the sums over all values are given per, so that layers are never added up:
    # its values with the condition a row meets for each, and the value of the rows left over;
    # None for one sum
    totals_by: str | None = None
    totals: tuple[tuple[str, str], ...] = ()
    totals_rest: str | None = None


SOURCES = {
    "connections": Source(
        "Processes",
        "socket bytes",
        "connections",
        "connections_rollup",
        ("send", "recv"),
        ("sent", "received"),
        {
            "exe": _lookup("executable", "exe_id", "executables", "exe"),
            "name": _lookup("name", "exe_id", "executables", "name"),
            "cmdline": _lookup("command", "exe_id", "executables", "cmdline"),
            "pexe": _lookup("parent executable", "pexe_id", "executables", "exe"),
            "pname": _lookup("parent name", "pexe_id", "executables", "name"),
            "pcmdline": _lookup("parent command", "pexe_id", "executables", "cmdline"),
            "unit": _lookup("unit", "unit_id", "units", "unit"),
            "uid": Dimension("user", "t.uid"),
            "netns": NETNS,
            "iface": IFACE,
            "layer": LAYER,
            "protocol": PROTOCOL,
            "lport": _port("local port", "lport", icmp=True),
            "rport": _port("remote port", "rport", icmp=True),
            "laddr": _lookup("local address", "laddr_id", "addresses", "addr", raw_only=True),
            "raddr": _lookup("remote address", "raddr_id", "addresses", "addr", raw_only=True),
            "domain": DOMAIN,
        },
        "exe",
        "layer",
        LAYER_SUMS,
        "outer",
    ),
    "interfaces": Source(
        "Interfaces",
        "interface bytes",
        "interface_traffic",
        "interface_traffic_rollup",
        ("tx", "rx"),
        ("sent", "received"),
        {
            "iface": IFACE,
            "netns": Dimension(
                "namespace", "t.iface_id", f"(SELECT {_IFACE_NETNS} FROM {_IFACE_FROM} WHERE i.id = {{k}})", f"t.iface_id IN (SELECT i.id FROM {_IFACE_FROM} WHERE {_IFACE_NETNS} IS ?)"
            ),
            "kind": _lookup("kind", "iface_id", "interfaces", "kind"),
            "layer": IFACE_LAYER,
        },
        "iface",
        "layer",
        IFACE_LAYER_SUMS,
        "outer",
    ),
    "forwarded": Source(
        "Forwarded",
        "IP bytes",
        "forwarded",
        "forwarded_rollup",
        ("orig_bytes", "reply_bytes"),
        ("src to dst", "dst to src"),
        {
            "src": _lookup("source", "src_id", "addresses", "addr"),
            "dst": _lookup("destination", "dst_id", "addresses", "addr", raw_only=True),
            "domain": DOMAIN,
            "dport": _port("destination port", "dport", icmp=False),
            "sport": Dimension("source port", "t.sport", rollup=None),
            "protocol": PROTOCOL,
            "netns": NETNS,
        },
        "src",
    ),
}


class RequestError(Exception):
    """a request the server refuses; the message goes back to the viewer"""


@dataclasses.dataclass(frozen=True)
class Settings:
    """what the answers depend on besides the database"""

    # the first ephemeral port, below which the rollups keep ports
    ephemeral: int
    # the daemon's write window and rollup period, in seconds, for the peaks of a timeline
    write_window: int
    rollup_period: int


def _source(request: dict) -> Source:
    source = SOURCES.get(request.get("source", ""))
    if source is None:
        raise RequestError(f"unknown source {request.get('source')!r}, expected one of {', '.join(SOURCES)}")
    return source


def _int(request: dict, key: str, default: int | None, low: int, high: int) -> int:
    value = request.get(key, default)
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int):
        raise RequestError(f"{key} must be an integer")
    if value < low or value > high:
        raise RequestError(f"{key} must be in [{low}, {high}]")
    return value


def _range(request: dict) -> tuple[int, int]:
    """[start, end) in unix seconds; an open end is the whole history"""
    start = _int(request, "start", 0, 0, 2**53)
    end = _int(request, "end", int(time.time()) + 1, 0, 2**53)
    if end <= start:
        raise RequestError("end must be after start")
    return start, end


def _filters(request: dict, source: Source) -> list[tuple[Dimension, object, bool]]:
    """[dimension, value, exclude] each; a row matches when every filter does"""
    filters = request.get("filters") or []
    if not isinstance(filters, list) or len(filters) > MAX_FILTERS:
        raise RequestError(f"filters must be a list of at most {MAX_FILTERS}")
    parsed = []
    for item in filters:
        if not isinstance(item, list) or len(item) != 3:
            raise RequestError("a filter is [dimension, value, exclude]")
        name, value, exclude = item
        dimension = source.dimensions.get(name) if isinstance(name, str) else None
        if dimension is None:
            raise RequestError(f"unknown dimension {name!r} for {source.label}")
        if value is not None and (isinstance(value, bool) or not isinstance(value, (str, int))):
            raise RequestError("a filter value is a string, an integer or null")
        if not isinstance(exclude, bool):
            raise RequestError("a filter's exclude is true or false")
        parsed.append((dimension, value, exclude))
    return parsed


def split_point(con: sqlite3.Connection, source: Source) -> int:
    """where a source's raw rows take over from its rollups: the first rolled-up period from the
    oldest raw row on (that row's own period, partly purged, comes from the rollup), else the
    watermark; 0 when nothing is rolled up"""
    row = con.execute(
        f"SELECT COALESCE((SELECT MIN(period) FROM {source.rollup} WHERE period >= (SELECT MIN(contime) FROM {source.raw})), (SELECT value FROM meta WHERE key = 'rollup_watermark'), 0)"
    ).fetchone()
    return row[0]


class _Plan:
    """the tables a request reads, as (rollup, start, end) parts, and how its expressions are built"""

    def __init__(self, con: sqlite3.Connection, source: Source, dimensions: list[Dimension], filters: list[tuple[Dimension, object, bool]], start: int, end: int, ephemeral: int) -> None:
        self.source = source
        self.filters = filters
        self.ephemeral = ephemeral
        self.split = split_point(con, source)
        # what the rollups do not keep is only there in the raw rows
        self.clipped = start < self.split and any(dimension.rollup is None for dimension in [*dimensions, *(f[0] for f in filters)])
        if self.clipped:
            start = max(start, self.split)
        self.start, self.end = start, end
        self.coarse = start < self.split
        self.join = any(dimension.join for dimension in [*dimensions, *(f[0] for f in filters)])
        self.parts = []
        if start < self.split:
            self.parts.append((True, start, min(end, self.split)))
        if end > self.split:
            self.parts.append((False, max(start, self.split), end))

    def key(self, dimension: Dimension, rollup: bool) -> str:
        return dimension.key_sql(rollup, self.coarse, self.ephemeral)

    def from_where(self, rollup: bool, start: int, end: int) -> tuple[str, list]:
        table, time_column = (self.source.rollup, "period") if rollup else (self.source.raw, "contime")
        where = [f"t.{time_column} >= ?", f"t.{time_column} < ?"]
        params: list = [start, end]
        for dimension, value, exclude in self.filters:
            match = dimension.match_sql(rollup, self.coarse, self.ephemeral)
            where.append(f"NOT ({match})" if exclude else f"({match})")
            params += [value] * match.count("?")
        return f"FROM {table} t {JOIN_INTERFACE if self.join else ''} WHERE {' AND '.join(where)}", params

    def union(self, key: Callable[[bool], str], leading: Callable[[], list] = list, sums: tuple[str, ...] = ()) -> tuple[str, list]:
        """the parts as one UNION ALL of (k, a, b), each summed per key(rollup), and a0, b0, ...
        summed over the rows that meet each of sums; grouping by the key alone keeps the order
        of its index"""
        a, b = self.source.values
        extra = "".join(f", SUM(CASE WHEN {condition} THEN t.{a} END) AS a{i}, SUM(CASE WHEN {condition} THEN t.{b} END) AS b{i}" for i, condition in enumerate(sums))
        selects, params = [], []
        for rollup, start, end in self.parts:
            from_where, part_params = self.from_where(rollup, start, end)
            selects.append(f"SELECT {key(rollup)} AS k, SUM(t.{a}) AS a, SUM(t.{b}) AS b{extra} {from_where} GROUP BY k")
            params += leading() + part_params
        return " UNION ALL ".join(selects), params

    def info(self) -> dict:
        return {"start": self.start, "end": self.end, "split": self.split, "clipped": self.clipped}


def aggregate(con: sqlite3.Connection, request: dict, settings: Settings) -> dict:
    """the byte sums per value of one dimension, largest first, and the sums over all values per
    value of the source's totals_by (one sum without), whose sum is only right where it does not
    add up layers"""
    source = _source(request)
    group = source.dimensions.get(request.get("group_by") or source.default)
    if group is None:
        raise RequestError(f"unknown dimension {request.get('group_by')!r} for {source.label}")
    filters = _filters(request, source)
    start, end = _range(request)
    limit = _int(request, "limit", DEFAULT_ROWS, 1, MAX_ROWS)
    plan = _Plan(con, source, [group], filters, start, end, settings.ephemeral)
    result: dict = {**plan.info(), "rows": [], "totals": [0, 0], "totals_by": source.totals_by, "parts": [], "groups": 0, "truncated": False}
    if not plan.parts:
        return result
    # without a tun device every row is left over, and no sum is needed
    tun = ", ".join(str(row[0]) for row in con.execute("SELECT id FROM interfaces WHERE kind = 'tun'"))
    totals = tuple((name, condition.format(tun=tun)) for name, condition in source.totals) if tun else ()
    conditions = tuple(condition for _, condition in totals)
    union, params = plan.union(lambda rollup: plan.key(group, rollup), sums=conditions)
    sums = "".join(f", SUM(SUM(u.a{i})) OVER (), SUM(SUM(u.b{i})) OVER ()" for i in range(len(conditions)))
    # keys with the same value (one name, several executables) become one row
    sql = (
        f"SELECT {group.value_sql('u.k')} AS g, SUM(u.a), SUM(u.b), SUM(SUM(u.a)) OVER (), SUM(SUM(u.b)) OVER (), COUNT(*) OVER (){sums}"
        f" FROM ({union}) u GROUP BY g ORDER BY SUM(u.a) + SUM(u.b) DESC, g LIMIT ?"
    )
    size = 0
    for value, a, b, total_a, total_b, groups, *per_value in con.execute(sql, [*params, limit]):
        if not result["groups"]:
            # the window sums are the same on every row; a value with no bytes is not there
            result["totals"], result["groups"] = [total_a, total_b], groups
            parts = [[name, per_value[2 * i] or 0, per_value[2 * i + 1] or 0] for i, (name, _) in enumerate(totals)]
            parts.append([source.totals_rest, total_a - sum(part[1] for part in parts), total_b - sum(part[2] for part in parts)])
            result["parts"] = sorted((part for part in parts if part[1] or part[2]), key=lambda part: -(part[1] + part[2]))
        size += len(json.dumps(value)) + 48
        if size > MAX_RESPONSE_BYTES // 2:
            result["truncated"] = True
            break
        result["rows"].append([value, a, b])
    result["truncated"] = result["truncated"] or result["groups"] > len(result["rows"])
    return result


def timeline(con: sqlite3.Connection, request: dict, settings: Settings) -> dict:
    """the byte sums per bucket of step seconds from start; buckets without bytes are left out.
    with peak, each bucket also carries the highest rate of a stretch of peak seconds in it, so a
    spike shorter than the bucket keeps its height"""
    source = _source(request)
    filters = _filters(request, source)
    start, end = _range(request)
    step = _int(request, "step", None, 1, 2**53) if request.get("step") is not None else max(1, (end - start) // 100)
    if (end - start + step - 1) // step > MAX_BUCKETS:
        raise RequestError(f"at most {MAX_BUCKETS} buckets, make step larger")
    peak = _int(request, "peak", None, 1, step) if request.get("peak") is not None else None
    plan = _Plan(con, source, [], filters, start, end, settings.ephemeral)
    result: dict = {**plan.info(), "step": step, "buckets": []}
    if peak is not None:
        # a write window's rows share one contime, so a stretch shorter than the window would
        # count the window's bytes as if they came in that stretch
        result["peak"] = max(peak, settings.write_window)
    if not plan.parts:
        return result
    # buckets count from the requested start, so they stay put when a dimension clips the range
    if peak is None:
        union, params = plan.union(lambda rollup: f"(t.{'period' if rollup else 'contime'} - ?) / ?", lambda: [start, step])
        for bucket, a, b in con.execute(f"SELECT k, SUM(a), SUM(b) FROM ({union}) GROUP BY k ORDER BY k", params):
            result["buckets"].append([start + bucket * step, a, b])
        return result
    a_column, b_column = source.values
    selects, params = [], []
    for rollup, part_start, part_end in plan.parts:
        # a rollup holds nothing finer than its period
        column, length = ("period", max(peak, settings.rollup_period)) if rollup else ("contime", result["peak"])
        from_where, part_params = plan.from_where(rollup, part_start, part_end)
        selects.append(
            f"SELECT (t.{column} - ?) / ? AS k, SUM(t.{a_column}) AS a, SUM(t.{b_column}) AS b,"
            f" SUM(t.{a_column}) * 1.0 / {length} AS ra, SUM(t.{b_column}) * 1.0 / {length} AS rb {from_where} GROUP BY k, (t.{column} - ?) / {length}"
        )
        params += [start, step, *part_params, start]
    union = " UNION ALL ".join(selects)
    for bucket, a, b, rate_a, rate_b in con.execute(f"SELECT k, SUM(a), SUM(b), MAX(ra), MAX(rb) FROM ({union}) GROUP BY k ORDER BY k", params):
        result["buckets"].append([start + bucket * step, a, b, rate_a, rate_b])
    return result


def describe(con: sqlite3.Connection, request: dict, settings: Settings) -> dict:
    """the sources, their dimensions and the time each covers"""
    sources = {}
    for name, source in SOURCES.items():
        oldest, newest = con.execute(
            f"SELECT MIN(t), MAX(t) FROM (SELECT MIN(contime) AS t FROM {source.raw} UNION ALL SELECT MAX(contime) FROM {source.raw}"
            f" UNION ALL SELECT MIN(period) FROM {source.rollup} UNION ALL SELECT MAX(period) FROM {source.rollup})"
        ).fetchone()
        sources[name] = {
            "label": source.label,
            "kind": source.kind,
            "values": list(source.value_labels),
            "default": source.default,
            "dimensions": [[key, dimension.label, dimension.rollup is None] for key, dimension in source.dimensions.items()],
            "oldest": oldest,
            "newest": newest,
            "split": split_point(con, source),
            "totals_by": source.totals_by,
        }
    return {"now": int(time.time()), "sources": sources}


OPS: dict[str, Callable[[sqlite3.Connection, dict, Settings], dict]] = {"describe": describe, "aggregate": aggregate, "timeline": timeline}


def open_database(db_path: Path) -> sqlite3.Connection:
    """the database, read-only; the server runs as the daemon's user, so the WAL index is shared"""
    if not db_path.exists():
        raise RequestError(f"no database at {db_path} yet; is the tracct service running?")
    con = sqlite3.connect(f"file:{urllib.parse.quote(os.fspath(db_path), safe='/')}?mode=ro", uri=True, timeout=5)
    try:
        version = con.execute("PRAGMA user_version").fetchone()[0]
    except sqlite3.Error:
        con.close()
        raise
    if version != DB_VERSION:
        con.close()
        raise RequestError(f"the database has schema version {version}, this tracct reads {DB_VERSION}")
    return con


class QueryServer:
    def __init__(self, db_path: Path = DB_PATH, ephemeral: int | None = None, write_window: int | None = None, rollup_period: int | None = None) -> None:
        self.db_path = db_path
        # the daemon's config, which the database was written with; a change of it applies to the
        # history from then on, and the peaks of older history take the current values
        database = load_config().database if write_window is None or rollup_period is None else None
        self.settings = Settings(
            ephemeral_port_start() if ephemeral is None else ephemeral,
            database.write_limit_seconds if write_window is None else write_window,
            database.rollup_period_minutes * 60 if rollup_period is None else rollup_period,
        )
        self._lock = threading.Lock()
        self._clients = 0

    def answer(self, request: dict) -> dict:
        op = OPS.get(request.get("op", ""))
        if op is None:
            return {"ok": False, "error": f"unknown op {request.get('op')!r}, expected one of {', '.join(OPS)}"}
        try:
            con = open_database(self.db_path)
        except RequestError as e:
            return {"ok": False, "error": str(e)}
        except sqlite3.Error as e:
            return {"ok": False, "error": f"cannot open {self.db_path}: {e}"}
        deadline = time.monotonic() + QUERY_TIMEOUT_SECONDS
        con.set_progress_handler(lambda: time.monotonic() > deadline, 10000)
        try:
            return {"ok": True, **op(con, request, self.settings)}
        except RequestError as e:
            return {"ok": False, "error": str(e)}
        except sqlite3.Error as e:
            if time.monotonic() > deadline:
                logging.warning(f"query server: interrupted a {request.get('op')} of {request.get('source')} after {QUERY_TIMEOUT_SECONDS} s")
                return {"ok": False, "error": f"the query took longer than {QUERY_TIMEOUT_SECONDS} s; narrow the time range or filter"}
            logging.warning(f"query server: {type(e).__name__}: {e}")
            return {"ok": False, "error": f"database: {e}"}
        finally:
            con.close()

    def _client(self, conn: socket.socket) -> None:
        try:
            with conn:
                while True:
                    conn.settimeout(None)
                    try:
                        request = recv_message(conn, MAX_REQUEST_BYTES)
                    except ValueError as e:
                        conn.settimeout(SEND_TIMEOUT_SECONDS)
                        send_message(conn, {"ok": False, "error": f"bad request: {e}"})
                        return
                    if request is None:
                        return
                    response = self.answer(request)
                    conn.settimeout(SEND_TIMEOUT_SECONDS)
                    send_message(conn, response)
        except OSError:
            pass
        finally:
            with self._lock:
                self._clients -= 1

    def serve(self, listener: socket.socket, idle_exit: float | None) -> None:
        """answer viewers, each in its own thread; returns once none has been connected for
        idle_exit seconds (never when None)"""
        listener.settimeout(1.0)
        last_active = time.monotonic()
        while True:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                with self._lock:
                    busy = self._clients > 0
                if busy:
                    last_active = time.monotonic()
                elif idle_exit is not None and time.monotonic() - last_active > idle_exit:
                    return
                continue
            except OSError:
                # the listener was closed
                return
            last_active = time.monotonic()
            with self._lock:
                admitted = self._clients < MAX_CLIENTS
                if admitted:
                    self._clients += 1
            if not admitted:
                with conn:
                    try:
                        conn.settimeout(1.0)
                        send_message(conn, {"ok": False, "error": f"the query server already serves {MAX_CLIENTS} viewers"})
                    except OSError:
                        pass
                continue
            threading.Thread(target=self._client, args=(conn,), name="query-client", daemon=True).start()


def listening_socket(path: Path) -> tuple[socket.socket, bool]:
    """the socket systemd passes (sd_listen_fds(3)), else one bound at path; and whether it was passed"""
    if os.getenv("LISTEN_PID") == str(os.getpid()) and int(os.getenv("LISTEN_FDS", "0") or 0) >= 1:
        for variable in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
            os.environ.pop(variable, None)
        sock = socket.socket(fileno=SD_LISTEN_FDS_START)
        sock.set_inheritable(False)
        return sock, True
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    os.chmod(path, 0o660)
    sock.listen(16)
    return sock, False


def run_query_server(path: Path = QUERY_SOCKET_PATH) -> int:
    """`tracct query-server`: under tracct-query.socket until idle, else until stopped"""
    listener, activated = listening_socket(path)
    logging.info(f"query server: reading {DB_PATH}, {'socket from systemd' if activated else f'listening on {path}'}")
    try:
        QueryServer().serve(listener, IDLE_EXIT_SECONDS if activated else None)
    finally:
        listener.close()
        if not activated:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    return 0
