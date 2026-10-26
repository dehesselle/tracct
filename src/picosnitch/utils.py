# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import collections
import ipaddress
import os
import socket
import sqlite3
import stat
import unicodedata
import urllib.parse
from pathlib import Path


def sd_notify(message: str) -> None:
    """best-effort systemd notification via the raw sd_notify(3) protocol, so the
    privileged daemon needs no python-systemd dependency. no-op unless launched by a
    Type=notify unit (NOTIFY_SOCKET set); errors are swallowed, a readiness signal
    must never take the daemon down."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            # a leading '@' selects the abstract namespace, sent as a leading NUL
            sock.sendto(message.encode(), "\0" + addr[1:] if addr[0] == "@" else addr)
    except OSError:
        pass


def sqlite_error_means_corrupt(e: sqlite3.Error) -> bool:
    """True when a sqlite error means picosnitch.db itself is unusable (quarantine+recreate);
    False for transient errors (locked by the live daemon, busy, disk I/O) where quarantining
    would destroy a healthy database. Shared by the cli boot check and the secondary purge."""
    msg = str(e).lower()
    return any(s in msg for s in ("malformed", "not a database", "no such table", "no such column", "encrypted"))


def connect_db_readonly(db_path: Path | str, timeout: float = 5.0) -> sqlite3.Connection:
    """Open a sqlite3 connection for read-only access.

    Tries `mode=ro`, then `mode=ro&immutable=1`. The immutable fallback is needed
    when the caller cannot write to the -shm / -wal sidecar files of a WAL database (e.g.
    a non-root user opening the picosnitch database written by the root
    daemon). Raises sqlite3.OperationalError if both attempts fail."""
    try:
        db_stat = os.lstat(db_path)
    except OSError as e:
        raise sqlite3.OperationalError(f"could not inspect {db_path}: {e}") from e
    if not stat.S_ISREG(db_stat.st_mode) or db_stat.st_nlink != 1:
        raise sqlite3.OperationalError(f"refusing non-regular or hardlinked database: {db_path}")
    quoted_path = urllib.parse.quote(os.fspath(db_path), safe="/")
    last_err: Exception | None = None
    for uri in (
        f"file:{quoted_path}?mode=ro",
        f"file:{quoted_path}?mode=ro&immutable=1",
    ):
        con = None
        try:
            con = sqlite3.connect(uri, uri=uri.startswith("file:"), timeout=timeout)
            # Force the connection to actually touch the file so we
            # surface "attempt to write a readonly database" here
            # instead of at the first user query.
            con.execute("PRAGMA user_version").fetchone()
            return con
        except sqlite3.OperationalError as e:
            if con is not None:
                con.close()
            last_err = e
            continue
    raise sqlite3.OperationalError(f"could not open {db_path} for reading: {last_err}")


def sanitize_log_line(line: str) -> str:
    """Remove control characters from a log line to prevent terminal-escape / log injection."""
    return "".join(c for c in line if c == "\t" or unicodedata.category(c) not in ("Cc", "Cf", "Cs"))


# reverse-DNS results keyed by ip; getnameinfo blocks, so callers probe reverse_dns_is_cached() first
_reverse_dns_cache: collections.OrderedDict[str, str] = collections.OrderedDict()
_REVERSE_DNS_CACHE_MAX: int = 8192


def reverse_dns_is_cached(ip: str) -> bool:
    """True if `ip` already has a cached reverse-DNS result (so resolving it is free)."""
    return ip in _reverse_dns_cache


def reverse_dns_lookup(ip: str) -> str:
    """Reverse-DNS `ip` to a hostname, cached; return the ip itself on failure. A
    repeated address costs nothing; callers gate a NEW (blocking) getnameinfo with
    reverse_dns_is_cached() plus their own per-write budget so a burst of distinct
    addresses cannot stall byte accounting."""
    cached = _reverse_dns_cache.get(ip)
    if cached is not None:
        _reverse_dns_cache.move_to_end(ip)
        return cached
    try:
        host = socket.getnameinfo((ip, 0), 0)[0]
        try:
            ipaddress.ip_address(host)
            result = ip
        except ValueError:
            result = ".".join(reversed(host.split(".")))
    except Exception:
        result = ip
    _reverse_dns_cache[ip] = result
    _reverse_dns_cache.move_to_end(ip)
    if len(_reverse_dns_cache) > _REVERSE_DNS_CACHE_MAX:
        _reverse_dns_cache.popitem(last=False)
    return result
