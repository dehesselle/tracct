# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import ipaddress
import logging
import queue
import shlex
import sqlite3
import sys
import threading
import time
from pathlib import Path

from picosnitch.config import Config
from picosnitch.constants import DB_PATH, DB_VERSION, RETRY_BUFFER_MAX, VERSION
from picosnitch.types import BpfEvent
from picosnitch.utils import log_error, reverse_dns_is_cached, reverse_dns_lookup, sqlite_error_means_corrupt

# new (uncached, blocking) reverse-DNS lookups per write; ~256 * a few ms stays under a second
REVERSE_DNS_LOOKUPS_PER_WRITE = 256


def maintain_database(file_path: Path, retention_days: int) -> None:
    """open picosnitch.db and purge rows past the retention window. exits on a version mismatch;
    on a corrupt/malformed or table-missing db, quarantine it to picosnitch.db.bad and exit so the
    next boot's init recreates a fresh db (crash-loop safety -- this runs before the main loop's
    try/except; the data is kept in .bad). a transient error (e.g. a lock) is re-raised untouched."""
    con = None
    try:
        con = sqlite3.connect(file_path)
        cur = con.cursor()
        cur.execute("PRAGMA user_version")
        db_version = cur.fetchone()[0]
        if db_version != DB_VERSION:
            con.close()
            logging.error(f"Incorrect database version of picosnitch.db for picosnitch v{VERSION}")
            sys.exit(1)
        # retention_days <= 0 is the usual "keep forever" convention; config clamps only negatives
        if int(retention_days) <= 0:
            con.close()
            return
        retention_cutoff = int(time.time()) - int(retention_days) * 86400
        # a cutoff past the newest row means a future clock (booted before NTP), which would wipe the db
        newest_contime = cur.execute("SELECT MAX(contime) FROM connections").fetchone()[0]
        if newest_contime is None or retention_cutoff <= newest_contime:
            cur.execute("DELETE FROM connections WHERE contime < ?", (retention_cutoff,))
        else:
            logging.error("picosnitch: skipping retention purge, wall clock is ahead of the newest logged connection (clock not synced?); no connections deleted")
        cur.execute("DELETE FROM domains WHERE id != 0 AND id NOT IN (SELECT DISTINCT domain_id FROM connections)")
        cur.execute("DELETE FROM addresses WHERE id != 0 AND id NOT IN (SELECT DISTINCT laddr_id FROM connections UNION SELECT DISTINCT raddr_id FROM connections)")
        # executables interns (exe, name, cmdline); a new cmdline is a new row, so a high
        # argv cardinality (per-invocation tokens) grows it unbounded without this. purge orphans
        # like domains/addresses above, keeping it consistent with the connection retention window
        cur.execute("DELETE FROM executables WHERE id != 0 AND id NOT IN (SELECT exe_id FROM connections UNION SELECT pexe_id FROM connections)")
        con.commit()
        con.close()
    except sqlite3.DatabaseError as e:
        # this runs before the main loop's try/except, so re-raising a full disk crash-loops the daemon
        if "disk is full" in str(e).lower():
            logging.error(f"picosnitch: skipping startup db maintenance, disk is full ({e}); starting anyway")
            if con is not None:
                con.close()
            return
        if not sqlite_error_means_corrupt(e):
            raise
        logging.error(f"picosnitch.db is unusable ({e}); quarantining to picosnitch.db.bad and recreating on restart")
        if con is not None:
            con.close()
        try:
            file_path.rename(file_path.with_name("picosnitch.db.bad"))
        except OSError:
            pass
        sys.exit(1)


def build_log_entries(
    config: Config,
    new_processes: list[BpfEvent],
    ignored_networks: list,
) -> list[tuple]:
    """iterate over the list of process/connection data to generate a list of entries for the sql database;
    the events are not modified, the live feed may still be sending the same objects"""
    datetime_now = int(time.time())
    traffic_counter: dict[tuple, list[int]] = {}
    # a burst of distinct addresses is that many serial round-trips before any row is written
    reverse_dns_budget = REVERSE_DNS_LOOKUPS_PER_WRITE
    # many connections in one write share a cmdline, and this string work dominated at high cardinality
    cmdline_cache: dict[str, str] = {}

    def clean_cmdline(raw: str) -> str:
        cleaned = cmdline_cache.get(raw)
        if cleaned is None:
            cleaned = shlex.join(raw.encode("utf-8", "ignore").decode("utf-8", "ignore").strip("\0\t\n ").split("\0"))
            cmdline_cache[raw] = cleaned
        return cleaned

    for proc in new_processes:
        # join or omit commands from logs
        if config.log.commands:
            cmdline = clean_cmdline(proc["cmdline"])
            pcmdline = clean_cmdline(proc["pcmdline"])
        else:
            cmdline = pcmdline = ""
        # reverse dns lookup or omit with IP from logs
        domain, raddr = proc["domain"], proc["raddr"]
        if config.log.addresses:
            if not domain and raddr:
                # a cached lookup is free; a new one has to fit the per-write budget
                if reverse_dns_is_cached(raddr):
                    domain = reverse_dns_lookup(raddr)
                elif reverse_dns_budget > 0:
                    domain = reverse_dns_lookup(raddr)
                    reverse_dns_budget -= 1
        else:
            domain = raddr = ""
        lport, rport = proc["lport"], proc["rport"]
        if not config.log.ports:
            lport, rport = min(0, lport), min(0, rport)
        # omit entry from logs
        ignored = False
        if rport in config.log.ignore_ports or lport in config.log.ignore_ports:
            ignored = True
        if not ignored:
            for domain_prefix in config.log.ignore_domains:
                if domain.startswith(domain_prefix):
                    ignored = True
                    break
        if ignored:
            continue
        if ignored_networks and raddr:
            if any(ipaddress.ip_address(raddr) in network for network in ignored_networks):
                continue
            if any(ipaddress.ip_address(proc["laddr"]) in network for network in ignored_networks):
                continue
        # create sql entry (exe info as tuples for normalization, connection-specific fields)
        exe_key = (proc["exe"], proc["name"], cmdline)
        pexe_key = (proc["pexe"], proc["pname"], pcmdline)
        event = (
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
        if event in traffic_counter:
            traffic_counter[event][0] += proc["send"]
            traffic_counter[event][1] += proc["recv"]
            traffic_counter[event][2] += proc.get("pkts", 1)
        else:
            traffic_counter[event] = [proc["send"], proc["recv"], proc.get("pkts", 1)]
    return [(datetime_now, send, recv, n_events, *event) for event, (send, recv, n_events) in traffic_counter.items()]


def run_writer(config: Config, batches: queue.Queue[list[BpfEvent]], stop: threading.Event) -> None:
    """the writer thread: collects the reader's batches and writes them to SQLite once per write
    window; once stop is set it writes what the queue still holds and returns"""
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
    # get network address and mask for ignored IP subnets
    ignored_networks = [ipaddress.ip_network(ip_subnet, strict=False) for ip_subnet in config.log.ignore_ips]

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
    new_processes: list[BpfEvent] = []

    def write() -> None:
        nonlocal transaction, new_processes
        transaction += build_log_entries(config, new_processes, ignored_networks)
        new_processes = []
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
            log_error("SQLite execute %s%s on line %s, will retry %s entries" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?", len(transaction)))
        if transaction_success or not config.database.enabled:
            transaction = []
        elif len(transaction) > RETRY_BUFFER_MAX:
            # a persistent write outage would grow transaction unbounded; keep the newest
            dropped = len(transaction) - RETRY_BUFFER_MAX
            transaction = transaction[-RETRY_BUFFER_MAX:]
            log_error("writer retry buffer full (persistent write outage), dropped %s oldest entries; retrying %s" % (dropped, len(transaction)))

    last_write = 0.0
    while True:
        # checked before emptying the queue: the reader has stopped by the time stop is set,
        # so the queue then holds all that is left
        stopping = stop.is_set()
        try:
            new_processes.extend(batches.get(timeout=0.5))
            while True:
                new_processes.extend(batches.get_nowait())
        except queue.Empty:
            pass
        try:
            if stopping:
                if transaction or new_processes:
                    write()
                return
            # a backward wall-clock jump must not stall writes; contime still uses time.time()
            if time.monotonic() - last_write > config.database.write_limit_seconds and (transaction or new_processes):
                last_write = time.monotonic()
                write()
        except Exception as e:
            log_error("writer %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
