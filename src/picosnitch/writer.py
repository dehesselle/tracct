# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import ipaddress
import logging
import shlex
import sqlite3
import threading
import time
from collections.abc import Callable

from picosnitch.config import Config
from picosnitch.constants import DB_PATH, RETRY_BUFFER_MAX
from picosnitch.reverse_dns import ReverseDns
from picosnitch.types import BpfEvent
from picosnitch.utils import DropOldestQueue, log_error, quarantine_database, sqlite_error_means_corrupt

# distinct connections one write window may hold; past it the window is written early
WINDOW_CONNECTIONS_MAX = 65536
# rows the retention purge deletes per transaction; a write that is due goes between two
PURGE_CHUNK_ROWS = 10000
# ids the writer keeps per lookup table; past it the cache starts over from the database
ID_CACHE_MAX = 65536
# lookup entries no connection refers to; executables uses the exe_id and pexe_id indexes,
# domains and addresses scan the connections (about half a second per million rows)
ORPHAN_DELETES = (
    "DELETE FROM executables WHERE id != 0 AND NOT EXISTS (SELECT 1 FROM connections WHERE exe_id = executables.id) AND NOT EXISTS (SELECT 1 FROM connections WHERE pexe_id = executables.id)",
    "DELETE FROM domains WHERE id != 0 AND id NOT IN (SELECT domain_id FROM connections)",
    "DELETE FROM addresses WHERE id != 0 AND id NOT IN (SELECT laddr_id FROM connections UNION SELECT raddr_id FROM connections)",
)


class WriteWindow:
    """the connections of one write window, summed as their events arrive, so memory follows the
    number of distinct connections rather than events. the events are not modified, the live
    feed may still be sending the same objects"""

    def __init__(self, config: Config, reverse_dns: ReverseDns | None = None) -> None:
        self.config = config
        self.reverse_dns = reverse_dns
        self.ignored_networks = [ipaddress.ip_network(ip_subnet, strict=False) for ip_subnet in config.log.ignore_ips]
        self.connections: dict[tuple, list[int]] = {}
        # many connections in one window share a cmdline, and this string work dominated at high cardinality
        self.cmdlines: dict[str, str] = {}

    def __len__(self) -> int:
        return len(self.connections)

    def clean_cmdline(self, raw: str) -> str:
        cleaned = self.cmdlines.get(raw)
        if cleaned is None:
            cleaned = shlex.join(raw.encode("utf-8", "ignore").decode("utf-8", "ignore").strip("\0\t\n ").split("\0"))
            self.cmdlines[raw] = cleaned
        return cleaned

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
            if self.ignored_networks and raddr:
                if any(ipaddress.ip_address(raddr) in network for network in self.ignored_networks):
                    continue
                if any(ipaddress.ip_address(proc["laddr"]) in network for network in self.ignored_networks):
                    continue
            # exe info as tuples for normalization, connection-specific fields
            exe_key = (proc["exe"], proc["name"], cmdline)
            pexe_key = (proc["pexe"], proc["pname"], pcmdline)
            key = (
                exe_key,
                pexe_key,
                proc["uid"],
                int(proc.get("family", 0) or 0),
                int(proc.get("protocol", 0) or 0),
                lport,
                rport,
                proc["laddr"],
                raddr,
                domain,
                int(proc.get("netns", 0) or 0),
            )
            counters = self.connections.get(key)
            if counters is None:
                self.connections[key] = [proc["send"], proc["recv"], proc.get("pkts", 1)]
                # asked for now, so the answer has the rest of the window to arrive
                if not domain and raddr and self.reverse_dns is not None:
                    self.reverse_dns.lookup(raddr)
            else:
                counters[0] += proc["send"]
                counters[1] += proc["recv"]
                counters[2] += proc.get("pkts", 1)

    def take_rows(self) -> list[tuple]:
        """the window as rows for the database, with domains from reverse DNS where the program
        looked up none; the next window starts empty"""
        contime = int(time.time())
        ignore_domains = self.config.log.ignore_domains
        rows: dict[tuple, list[int]] = {}
        for key, (send, recv, n_events) in self.connections.items():
            domain, raddr = key[9], key[8]
            if not domain and raddr and self.reverse_dns is not None:
                domain = self.reverse_dns.lookup(raddr)
                key = (*key[:9], domain, key[10])
            if any(domain.startswith(domain_prefix) for domain_prefix in ignore_domains):
                continue
            # a connection with and without the domain the program looked up are one row now
            counters = rows.get(key)
            if counters is None:
                rows[key] = [send, recv, n_events]
            else:
                counters[0] += send
                counters[1] += recv
                counters[2] += n_events
        self.connections = {}
        self.cmdlines = {}
        return [(contime, send, recv, n_events, *key) for key, (send, recv, n_events) in rows.items()]


def purge_database(con: sqlite3.Connection, retention_days: int, between_chunks: Callable[[], bool]) -> tuple[int, int]:
    """delete the connections past the retention window in chunks, then the lookup entries no
    connection refers to any more. between_chunks runs after each committed chunk and ends the
    purge by returning True. returns the numbers of connections and lookup entries deleted"""
    # retention_days <= 0 is the usual "keep forever" convention; config clamps only negatives
    if retention_days <= 0:
        return 0, 0
    retention_cutoff = int(time.time()) - retention_days * 86400
    # a cutoff past the newest row means a future clock (booted before NTP), which would wipe the db
    newest_contime = con.execute("SELECT MAX(contime) FROM connections").fetchone()[0]
    if newest_contime is None:
        return 0, 0
    if retention_cutoff > newest_contime:
        logging.error("picosnitch: skipping retention purge, wall clock is ahead of the newest logged connection (clock not synced?); no connections deleted")
        return 0, 0
    deleted = 0
    while True:
        with con:
            chunk = con.execute("DELETE FROM connections WHERE rowid IN (SELECT rowid FROM connections WHERE contime < ? LIMIT ?)", (retention_cutoff, PURGE_CHUNK_ROWS)).rowcount
        deleted += chunk
        if chunk < PURGE_CHUNK_ROWS:
            break
        if between_chunks():
            return deleted, 0
    # entries become orphans only when connections are deleted
    orphans = 0
    if deleted:
        with con:
            for statement in ORPHAN_DELETES:
                orphans += con.execute(statement).rowcount
    return deleted, orphans


def run_writer(config: Config, batches: DropOldestQueue[BpfEvent], stop: threading.Event) -> None:
    """the writer thread: sums the reader's batches per write window, writes them to SQLite and
    purges past the retention window; once stop is set it writes what is left and returns"""
    # init sql
    # connections columns: contime, send, recv, events, exe_id, pexe_id, uid,
    # family, protocol, lport, rport, laddr_id, raddr_id, domain_id, netns  (15 cols).
    # executables: (id, exe, name, cmdline). domains/addresses: (id, value).
    sqlite_insert_exe = "INSERT OR IGNORE INTO executables(exe, name, cmdline) VALUES (?, ?, ?)"
    sqlite_select_exe = "SELECT id FROM executables WHERE exe = ? AND name = ? AND cmdline = ?"
    sqlite_insert_dom = "INSERT OR IGNORE INTO domains(domain) VALUES (?)"
    sqlite_select_dom = "SELECT id FROM domains WHERE domain = ?"
    sqlite_insert_addr = "INSERT OR IGNORE INTO addresses(addr) VALUES (?)"
    sqlite_select_addr = "SELECT id FROM addresses WHERE addr = ?"
    sqlite_insert_conn = "INSERT INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    file_path = DB_PATH
    exe_id_cache: dict[tuple, int] = {}
    domain_id_cache: dict[str, int] = {"": 0}
    addr_id_cache: dict[str, int] = {"": 0}
    # ids inserted into the caches during the current (uncommitted) sqlite transaction;
    # a rolled-back INSERT frees its rowid for reuse, so on failure these must be dropped
    # from the caches or a later cache hit would misattribute rows to a stale/reused id
    pending_cache_keys: list[tuple] = []
    reverse_dns = ReverseDns() if config.log.addresses and config.log.reverse_dns else None
    window = WriteWindow(config, reverse_dns)

    def clear_id_caches() -> None:
        exe_id_cache.clear()
        domain_id_cache.clear()
        addr_id_cache.clear()
        domain_id_cache[""] = 0
        addr_id_cache[""] = 0

    # resolve exe tuples to IDs with caching
    def resolve_exe_id(con: sqlite3.Connection, exe_key: tuple) -> int:
        if exe_key in exe_id_cache:
            return exe_id_cache[exe_key]
        con.execute(sqlite_insert_exe, exe_key)
        row = con.execute(sqlite_select_exe, exe_key).fetchone()
        exe_id_cache[exe_key] = row[0]
        pending_cache_keys.append((exe_id_cache, exe_key))
        return row[0]

    def resolve_domain_id(con: sqlite3.Connection, domain: str) -> int:
        if domain in domain_id_cache:
            return domain_id_cache[domain]
        con.execute(sqlite_insert_dom, (domain,))
        row = con.execute(sqlite_select_dom, (domain,)).fetchone()
        domain_id_cache[domain] = row[0]
        pending_cache_keys.append((domain_id_cache, domain))
        return row[0]

    def resolve_addr_id(con: sqlite3.Connection, addr: str) -> int:
        if addr in addr_id_cache:
            return addr_id_cache[addr]
        con.execute(sqlite_insert_addr, (addr,))
        row = con.execute(sqlite_select_addr, (addr,)).fetchone()
        addr_id_cache[addr] = row[0]
        pending_cache_keys.append((addr_id_cache, addr))
        return row[0]

    transaction: list[tuple] = []

    def write() -> None:
        nonlocal transaction
        transaction += window.take_rows()
        if max(len(exe_id_cache), len(domain_id_cache), len(addr_id_cache)) > ID_CACHE_MAX:
            clear_id_caches()
        transaction_success = False
        try:
            if config.database.enabled:
                con = sqlite3.connect(file_path)
                with con:
                    conn_rows = []
                    for contime, send, recv, n_events, exe_key, pexe_key, uid, family, protocol, lport, rport, laddr, raddr, domain, netns in transaction:
                        exe_id = resolve_exe_id(con, exe_key)
                        pexe_id = resolve_exe_id(con, pexe_key)
                        laddr_id = resolve_addr_id(con, laddr)
                        raddr_id = resolve_addr_id(con, raddr)
                        domain_id = resolve_domain_id(con, domain)
                        conn_rows.append((contime, send, recv, n_events, exe_id, pexe_id, uid, family, protocol, lport, rport, laddr_id, raddr_id, domain_id, netns))
                    con.executemany(sqlite_insert_conn, conn_rows)
                con.close()
                transaction_success = True
                pending_cache_keys.clear()  # committed: cached ids are now durable
        except Exception as e:
            # rolled back: drop this transaction's cache entries so a retry re-inserts
            for cache, cache_key in pending_cache_keys:
                cache.pop(cache_key, None)
            pending_cache_keys.clear()
            if isinstance(e, sqlite3.DatabaseError) and sqlite_error_means_corrupt(e):
                raise
            log_error("SQLite execute %s%s on line %s, will retry %s entries" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?", len(transaction)))
        if transaction_success or not config.database.enabled:
            transaction = []
        elif len(transaction) > RETRY_BUFFER_MAX:
            # a persistent write outage would grow transaction unbounded; keep the newest
            dropped = len(transaction) - RETRY_BUFFER_MAX
            transaction = transaction[-RETRY_BUFFER_MAX:]
            log_error("writer retry buffer full (persistent write outage), dropped %s oldest entries; retrying %s" % (dropped, len(transaction)))

    last_write = 0.0

    def collect(timeout: float) -> None:
        for batch in batches.get_all(timeout):
            window.add(batch)

    def write_if_due() -> None:
        nonlocal last_write
        if not (window or transaction):
            return
        # a backward wall-clock jump must not stall writes; contime still uses time.time()
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
            deleted, orphans = purge_database(con, config.database.retention_days, between_chunks)
        finally:
            con.close()
            # orphan cleanup deletes ids the caches may hold
            clear_id_caches()
        if deleted:
            logging.info(f"retention purge: deleted {deleted} connection(s) and {orphans} unreferenced lookup entries in {time.monotonic() - started:.1f} s")

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
                    if window or transaction:
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
