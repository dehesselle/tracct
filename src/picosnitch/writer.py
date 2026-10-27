# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import ipaddress
import logging
import shlex
import socket
import sqlite3
import threading
import time
from collections.abc import Callable

from picosnitch.config import Config
from picosnitch.conntrack import Conntrack, Flow
from picosnitch.constants import DB_PATH, RETRY_BUFFER_MAX
from picosnitch.netinfo import NetInfo
from picosnitch.reverse_dns import ReverseDns
from picosnitch.types import BpfEvent
from picosnitch.utils import DropOldestQueue, ephemeral_port_start, log_error, quarantine_database, sqlite_error_means_corrupt

# distinct connections one write window may hold; past it the window is written early
WINDOW_CONNECTIONS_MAX = 65536
# rows the retention purge deletes per transaction; a write that is due goes between two
PURGE_CHUNK_ROWS = 10000
# ids the writer keeps per lookup table; past it the cache starts over from the database
ID_CACHE_MAX = 65536
# the interface of a row whose interface is unknown
NO_INTERFACE = (0, "", "")

# rows of a closed rollup period, summed; the parameters are the period, the first port of the
# ephemeral range (ports from there on are a peer's or our own random port, kept as 0 so a
# server's rollup does not grow with its clients), and the period's bounds
ROLLUPS = (
    # ICMP (1) and ICMPv6 (58) rows carry the echo id as a port, a new one per ping
    "INSERT INTO connections_rollup SELECT :period, exe_id, pexe_id, unit_id, uid, family, protocol,"
    " CASE WHEN lport < :ephemeral AND protocol NOT IN (1, 58) THEN lport ELSE 0 END AS lp,"
    " CASE WHEN rport < :ephemeral AND protocol NOT IN (1, 58) THEN rport ELSE 0 END AS rp,"
    " domain_id, netns, iface_id, SUM(send), SUM(recv), SUM(events), COUNT(*)"
    " FROM connections WHERE contime >= :start AND contime < :end"
    " GROUP BY exe_id, pexe_id, unit_id, uid, family, protocol, lp, rp, domain_id, netns, iface_id",
    "INSERT INTO interface_traffic_rollup SELECT :period, iface_id, SUM(rx), SUM(tx) FROM interface_traffic WHERE contime >= :start AND contime < :end GROUP BY iface_id",
    "INSERT INTO forwarded_rollup SELECT :period, netns, protocol, src_id, CASE WHEN dport < :ephemeral THEN dport ELSE 0 END AS dp, domain_id,"
    " SUM(orig_bytes), SUM(reply_bytes), SUM(orig_packets), SUM(reply_packets), COUNT(*)"
    " FROM forwarded WHERE contime >= :start AND contime < :end GROUP BY netns, protocol, src_id, dp, domain_id",
)
# the tables purged past the raw and the rollup retention, with their time column
RAW_TABLES = (("connections", "contime"), ("interface_traffic", "contime"), ("forwarded", "contime"))
ROLLUP_TABLES = (("connections_rollup", "period"), ("interface_traffic_rollup", "period"), ("forwarded_rollup", "period"))
# lookup entries nothing refers to; executables uses the exe_id and pexe_id indexes, the
# others scan the tables referring to them (about half a second per million rows)
ORPHAN_DELETES = (
    "DELETE FROM executables WHERE id != 0"
    " AND NOT EXISTS (SELECT 1 FROM connections WHERE exe_id = executables.id) AND NOT EXISTS (SELECT 1 FROM connections WHERE pexe_id = executables.id)"
    " AND NOT EXISTS (SELECT 1 FROM connections_rollup WHERE exe_id = executables.id) AND NOT EXISTS (SELECT 1 FROM connections_rollup WHERE pexe_id = executables.id)",
    "DELETE FROM units WHERE id != 0 AND id NOT IN (SELECT unit_id FROM connections UNION SELECT unit_id FROM connections_rollup)",
    "DELETE FROM domains WHERE id != 0 AND id NOT IN"
    " (SELECT domain_id FROM connections UNION SELECT domain_id FROM connections_rollup UNION SELECT domain_id FROM forwarded UNION SELECT domain_id FROM forwarded_rollup)",
    "DELETE FROM addresses WHERE id != 0 AND id NOT IN"
    " (SELECT laddr_id FROM connections UNION SELECT raddr_id FROM connections UNION SELECT src_id FROM forwarded UNION SELECT dst_id FROM forwarded UNION SELECT src_id FROM forwarded_rollup)",
    "DELETE FROM interfaces WHERE id != 0 AND id NOT IN"
    " (SELECT iface_id FROM connections UNION SELECT iface_id FROM connections_rollup UNION SELECT iface_id FROM interface_traffic UNION SELECT iface_id FROM interface_traffic_rollup)",
    "DELETE FROM netns WHERE inode NOT IN"
    " (SELECT netns FROM connections UNION SELECT netns FROM connections_rollup UNION SELECT netns FROM interfaces UNION SELECT netns FROM forwarded UNION SELECT netns FROM forwarded_rollup)",
)


class Interned:
    """the ids of one lookup table, cached. ids a rolled-back transaction inserted are dropped
    again, as sqlite hands their rowids out anew"""

    def __init__(self, table: str, columns: tuple[str, ...], sentinel: tuple) -> None:
        self.insert = f"INSERT OR IGNORE INTO {table}({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"
        self.select = f"SELECT id FROM {table} WHERE {' AND '.join(f'{column} = ?' for column in columns)}"
        self.sentinel = sentinel
        self.ids: dict[tuple, int] = {sentinel: 0}
        # inserted during the current, uncommitted transaction
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
    """the connections and forwarded flows of one write window, summed as their events arrive,
    so memory follows the number of distinct connections rather than events. the events are not
    modified, the live feed may still be sending the same objects"""

    def __init__(self, config: Config, reverse_dns: ReverseDns | None = None, netinfo: NetInfo | None = None) -> None:
        self.config = config
        self.reverse_dns = reverse_dns
        self.netinfo = netinfo
        self.ignored_networks = [ipaddress.ip_network(ip_subnet, strict=False) for ip_subnet in config.log.ignore_ips]
        self.connections: dict[tuple, list[int]] = {}
        self.flows: dict[tuple, list[int]] = {}
        # many connections in one window share a cmdline, and this string work dominated at high cardinality
        self.cmdlines: dict[str, str] = {}

    def __len__(self) -> int:
        return len(self.connections) + len(self.flows)

    def clean_cmdline(self, raw: str) -> str:
        cleaned = self.cmdlines.get(raw)
        if cleaned is None:
            cleaned = shlex.join(raw.encode("utf-8", "ignore").decode("utf-8", "ignore").strip("\0\t\n ").split("\0"))
            self.cmdlines[raw] = cleaned
        return cleaned

    def ignored(self, *addresses: str) -> bool:
        if self.ignored_networks:
            for address in addresses:
                if address and any(ipaddress.ip_address(address) in network for network in self.ignored_networks):
                    return True
        return False

    def interface(self, netns: int, laddr: str, tun: str) -> tuple[int, str, str]:
        """the interface a row was counted on: the TUN device of a process's TUN reads and
        writes, else the interface holding the local address"""
        if self.netinfo is None:
            return NO_INTERFACE
        name, kind = (tun, "tun") if tun else self.netinfo.interface_of(netns, laddr)
        return (netns, name, kind) if name else NO_INTERFACE

    def add(self, events: list[BpfEvent]) -> None:
        log = self.config.log
        for proc in events:
            # join or omit commands from logs
            if log.commands:
                cmdline = self.clean_cmdline(proc["cmdline"])
                pcmdline = self.clean_cmdline(proc["pcmdline"])
            else:
                cmdline = pcmdline = ""
            # the domain the program looked up; omitted with the address from logs
            domain, raddr = proc["domain"], proc["raddr"]
            if not log.addresses:
                domain = raddr = ""
            lport, rport = proc["lport"], proc["rport"]
            if not log.ports:
                lport, rport = min(0, lport), min(0, rport)
            # omit entry from logs (domains are matched in take_rows, once reverse DNS had its chance)
            if rport in log.ignore_ports or lport in log.ignore_ports:
                continue
            if self.ignored_networks and raddr and self.ignored(raddr, proc["laddr"]):
                continue
            family = int(proc.get("family", 0) or 0)
            netns = int(proc.get("netns", 0) or 0)
            # the interface follows from netns and laddr in the key, and is looked up once per
            # row in take_rows; only a TUN row needs its process for it, which is not in the key
            tun = self.netinfo.tun_of(proc["pid"]) if family == socket.AF_PACKET and self.netinfo is not None else ""
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
                self.connections[key] = [proc["send"], proc["recv"], proc.get("pkts", 1)]
                if self.netinfo is not None:
                    self.netinfo.note(netns, proc["pid"])
                # asked for now, so the answer has the rest of the window to arrive
                if not domain and raddr and self.reverse_dns is not None:
                    self.reverse_dns.lookup(raddr)
            else:
                counters[0] += proc["send"]
                counters[1] += proc["recv"]
                counters[2] += proc.get("pkts", 1)

    def add_flows(self, flows: list[Flow]) -> None:
        log = self.config.log
        for flow in flows:
            src, dst = (flow.src, flow.dst) if log.addresses else ("", "")
            sport, dport = (flow.sport, flow.dport) if log.ports else (0, 0)
            if sport in log.ignore_ports or dport in log.ignore_ports or self.ignored(src, dst):
                continue
            key = (flow.netns, flow.protocol, src, sport, dst, dport)
            counters = self.flows.get(key)
            if counters is None:
                self.flows[key] = [flow.orig_bytes, flow.reply_bytes, flow.orig_packets, flow.reply_packets]
                if dst and self.reverse_dns is not None:
                    self.reverse_dns.lookup(dst)
            else:
                counters[0] += flow.orig_bytes
                counters[1] += flow.reply_bytes
                counters[2] += flow.orig_packets
                counters[3] += flow.reply_packets

    def domain_of(self, address: str) -> str:
        return self.reverse_dns.lookup(address) if address and self.reverse_dns is not None else ""

    def is_ignored_domain(self, domain: str) -> bool:
        return any(domain.startswith(domain_prefix) for domain_prefix in self.config.log.ignore_domains)

    def take_rows(self) -> tuple[list[tuple], list[tuple]]:
        """the window as connection and forwarded rows for the database, with domains from
        reverse DNS where the program looked up none; the next window starts empty"""
        contime = int(time.time())
        rows: dict[tuple, list[int]] = {}
        for key, (send, recv, n_events) in self.connections.items():
            *identity, laddr, raddr, domain, netns, tun = key
            if not domain:
                domain = self.domain_of(raddr)
            key = (*identity, laddr, raddr, domain, netns, self.interface(netns, laddr, tun))
            if self.is_ignored_domain(domain):
                continue
            # a connection with and without the domain the program looked up are one row now
            counters = rows.get(key)
            if counters is None:
                rows[key] = [send, recv, n_events]
            else:
                counters[0] += send
                counters[1] += recv
                counters[2] += n_events
        flow_rows = []
        for (netns, protocol, src, sport, dst, dport), counters in self.flows.items():
            domain = self.domain_of(dst)
            if not self.is_ignored_domain(domain):
                flow_rows.append((contime, netns, protocol, src, sport, dst, dport, domain, *counters))
        self.connections = {}
        self.flows = {}
        self.cmdlines = {}
        return [(contime, send, recv, n_events, *key) for key, (send, recv, n_events) in rows.items()], flow_rows


def _chunked_delete(con: sqlite3.Connection, table: str, column: str, cutoff: int, between_chunks: Callable[[], bool]) -> tuple[int, bool]:
    """delete the rows of table older than cutoff; returns how many, and whether between_chunks stopped it"""
    deleted = 0
    while True:
        with con:
            chunk = con.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {column} < ? LIMIT ?)", (cutoff, PURGE_CHUNK_ROWS)).rowcount
        deleted += chunk
        if chunk < PURGE_CHUNK_ROWS:
            return deleted, False
        if between_chunks():
            return deleted, True


def roll_up(con: sqlite3.Connection, period_minutes: int, between_periods: Callable[[], bool], ephemeral: int | None = None) -> int:
    """sum the raw rows of every period that has closed since the last one rolled up, per period;
    the watermark in meta marks where the next starts. returns the number of periods summed"""
    period = period_minutes * 60
    ephemeral = ephemeral_port_start() if ephemeral is None else ephemeral
    # periods end on multiples of the period length; the current one is still open, and so is
    # the newest row's, so a clock running ahead cannot carry the watermark past the data
    closed = int(time.time()) // period * period
    newest_sql = "SELECT MAX(t) FROM (SELECT MAX(contime) AS t FROM connections UNION ALL SELECT MAX(contime) FROM interface_traffic UNION ALL SELECT MAX(contime) FROM forwarded)"
    newest = con.execute(newest_sql).fetchone()[0]
    if newest is not None:
        closed = min(closed, newest // period * period)
    row = con.execute("SELECT value FROM meta WHERE key = 'rollup_watermark'").fetchone()
    watermark = row[0] if row is not None else 0
    periods = 0
    while watermark < closed:
        # the next row at or past the watermark, so spans without any are skipped (a first
        # start, a long downtime)
        oldest = con.execute(
            "SELECT MIN(t) FROM (SELECT MIN(contime) AS t FROM connections WHERE contime >= :w UNION ALL SELECT MIN(contime) FROM interface_traffic WHERE contime >= :w"
            " UNION ALL SELECT MIN(contime) FROM forwarded WHERE contime >= :w)",
            {"w": watermark},
        ).fetchone()[0]
        if oldest is None or oldest >= closed:
            start = end = closed
        else:
            # after a change of the period length the watermark may sit inside a period
            start = max(watermark, oldest // period * period)
            end = start // period * period + period
        with con:
            if start < end:
                for statement in ROLLUPS:
                    con.execute(statement, {"period": start // period * period, "ephemeral": ephemeral, "start": start, "end": end})
                periods += 1
            con.execute("INSERT INTO meta(key, value) VALUES ('rollup_watermark', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (end,))
        watermark = end
        if watermark < closed and between_periods():
            break
    return periods


def purge_database(con: sqlite3.Connection, config: Config, between_chunks: Callable[[], bool]) -> tuple[int, int, int]:
    """roll up the closed periods, delete the rows past their retention in chunks (raw rows only
    once rolled up), then the lookup entries nothing refers to any more. between_chunks runs
    after each committed chunk or period and ends the purge by returning True. returns the
    numbers of periods rolled up, rows deleted and lookup entries deleted"""
    database = config.database
    periods = roll_up(con, database.rollup_period_minutes, between_chunks)
    now = int(time.time())
    # a cutoff past the newest row means a future clock (booted before NTP), which would wipe the db
    newest = con.execute("SELECT MAX(contime) FROM connections").fetchone()[0]
    shortest = database.raw_retention_days or database.rollup_retention_days
    if newest is not None and shortest > 0 and now - shortest * 86400 > newest:
        logging.error("picosnitch: skipping retention purge, wall clock is ahead of the newest logged connection (clock not synced?); no rows deleted")
        return periods, 0, 0
    watermark_row = con.execute("SELECT value FROM meta WHERE key = 'rollup_watermark'").fetchone()
    watermark = watermark_row[0] if watermark_row is not None else 0
    purges = []
    # retention 0 is the usual "keep forever"; raw rows go only once they are rolled up
    if database.raw_retention_days > 0:
        purges += [(table, column, min(now - database.raw_retention_days * 86400, watermark)) for table, column in RAW_TABLES]
    if database.rollup_retention_days > 0:
        purges += [(table, column, now - database.rollup_retention_days * 86400) for table, column in ROLLUP_TABLES]
    deleted = 0
    for table, column, cutoff in purges:
        count, stopped = _chunked_delete(con, table, column, cutoff, between_chunks)
        deleted += count
        if stopped:
            return periods, deleted, 0
    # entries become orphans only when rows are deleted
    orphans = 0
    if deleted:
        with con:
            for statement in ORPHAN_DELETES:
                orphans += con.execute(statement).rowcount
    return periods, deleted, orphans


def run_writer(config: Config, batches: DropOldestQueue[BpfEvent], stop: threading.Event) -> None:
    """the writer thread: sums the reader's batches per write window, writes them to SQLite with
    the interface counters and forwarded flows of the window, and rolls up and purges past the
    retention windows; once stop is set it writes what is left and returns"""
    file_path = DB_PATH
    executables = Interned("executables", ("exe", "name", "cmdline"), ("", "", ""))
    domains = Interned("domains", ("domain",), ("",))
    addresses = Interned("addresses", ("addr",), ("",))
    units = Interned("units", ("unit",), ("",))
    interfaces = Interned("interfaces", ("netns", "name", "kind"), NO_INTERFACE)
    interned = (executables, domains, addresses, units, interfaces)
    reverse_dns = ReverseDns() if config.log.addresses and config.log.reverse_dns else None
    netinfo = NetInfo(log_error) if config.database.enabled else None
    if netinfo is not None:
        # the baseline the first window's interface counters start from
        netinfo.refresh()
    conntrack = None
    if netinfo is not None and config.monitoring.conntrack:
        try:
            conntrack = Conntrack(log_error, netinfo.local_addresses())
        except OSError as e:
            log_error(f"conntrack: not available ({e}); forwarded traffic goes unrecorded")
    window = WriteWindow(config, reverse_dns, netinfo)

    def clear_id_caches() -> None:
        for table in interned:
            table.clear()

    # rows waiting for a write that succeeds: connections, interface counters, forwarded flows
    transaction: list[tuple] = []
    iface_rows: list[tuple] = []
    flow_rows: list[tuple] = []

    def write() -> None:
        nonlocal transaction, iface_rows, flow_rows
        if conntrack is not None and netinfo is not None:
            window.add_flows(conntrack.collect(netinfo.local_addresses()))
        rows, flows = window.take_rows()
        transaction += rows
        flow_rows += flows
        if netinfo is not None:
            contime = int(time.time())
            iface_rows += [(contime, (netns, name, kind), rx, tx) for netns, name, kind, rx, tx in netinfo.refresh()]
        if any(len(table.ids) > ID_CACHE_MAX for table in interned):
            clear_id_caches()
        transaction_success = False
        try:
            if config.database.enabled:
                con = sqlite3.connect(file_path)
                with con:
                    conn_rows = []
                    for contime, send, recv, n_events, exe_key, pexe_key, unit, uid, family, protocol, lport, rport, laddr, raddr, domain, netns, iface in transaction:
                        conn_rows.append(
                            (
                                contime,
                                send,
                                recv,
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
                                netns,
                                interfaces.id(con, iface),
                            )
                        )
                    con.executemany("INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", conn_rows)
                    con.executemany("INSERT INTO interface_traffic VALUES (?, ?, ?, ?)", [(contime, interfaces.id(con, iface), rx, tx) for contime, iface, rx, tx in iface_rows])
                    con.executemany(
                        "INSERT INTO forwarded VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [
                            (contime, netns, protocol, addresses.id(con, (src,)), sport, addresses.id(con, (dst,)), dport, domains.id(con, (domain,)), *counters)
                            for contime, netns, protocol, src, sport, dst, dport, domain, *counters in flow_rows
                        ],
                    )
                    if netinfo is not None:
                        con.executemany(
                            "INSERT INTO netns(inode, name) VALUES (?, ?) ON CONFLICT(inode) DO UPDATE SET name = excluded.name WHERE name != excluded.name",
                            list(netinfo.names.items()),
                        )
                con.close()
                transaction_success = True
                for table in interned:
                    table.committed()  # cached ids are now durable
        except Exception as e:
            # rolled back: drop this transaction's cache entries so a retry re-inserts
            for table in interned:
                table.rolled_back()
            if isinstance(e, sqlite3.DatabaseError) and sqlite_error_means_corrupt(e):
                raise
            log_error("SQLite execute %s%s on line %s, will retry %s entries" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?", len(transaction)))
        if transaction_success or not config.database.enabled:
            transaction, iface_rows, flow_rows = [], [], []
            return
        # a persistent write outage would grow the buffers unbounded; keep the newest
        if len(transaction) > RETRY_BUFFER_MAX:
            dropped = len(transaction) - RETRY_BUFFER_MAX
            transaction = transaction[-RETRY_BUFFER_MAX:]
            log_error("writer retry buffer full (persistent write outage), dropped %s oldest entries; retrying %s" % (dropped, len(transaction)))
        iface_rows = iface_rows[-RETRY_BUFFER_MAX:]
        flow_rows = flow_rows[-RETRY_BUFFER_MAX:]

    last_write = 0.0

    def collect(timeout: float) -> None:
        for batch in batches.get_all(timeout):
            window.add(batch)

    def write_if_due() -> None:
        nonlocal last_write
        # interface counters and forwarded flows are due every window, with or without connections
        if time.monotonic() - last_write > config.database.write_limit_seconds or len(window) >= WINDOW_CONNECTIONS_MAX:
            last_write = time.monotonic()
            write()

    def maintain() -> None:
        def between_chunks() -> bool:
            collect(0)
            write_if_due()
            return stop.is_set()

        started = time.monotonic()
        con = sqlite3.connect(file_path)
        try:
            periods, deleted, orphans = purge_database(con, config, between_chunks)
        finally:
            con.close()
            # orphan cleanup deletes ids the caches may hold
            clear_id_caches()
        if periods or deleted:
            logging.info(f"maintenance: rolled up {periods} period(s), deleted {deleted} row(s) and {orphans} unreferenced lookup entries in {time.monotonic() - started:.1f} s")

    # the first pass runs at startup
    next_maintenance = time.monotonic()
    try:
        while True:
            # checked before emptying the queue: the reader has stopped by the time stop is set,
            # so the queue then holds all that is left
            stopping = stop.is_set()
            try:
                collect(0.5)
                if stopping:
                    write()
                    return
                write_if_due()
                if config.database.enabled and time.monotonic() >= next_maintenance:
                    next_maintenance = time.monotonic() + config.database.maintenance_interval_minutes * 60
                    maintain()
            except Exception as e:
                if isinstance(e, sqlite3.DatabaseError) and sqlite_error_means_corrupt(e):
                    # the thread ends and the daemon exits, for the service manager to start it on a new db
                    logging.error(f"picosnitch.db is unusable ({e}); quarantining to {file_path.name}.bad and recreating on restart")
                    quarantine_database(file_path)
                    raise
                log_error("writer %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
    finally:
        if reverse_dns is not None:
            reverse_dns.close()
        if conntrack is not None:
            conntrack.close()
