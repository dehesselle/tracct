# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import collections
import logging
import os
import socket
import sqlite3
import stat
import threading
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
    would destroy a healthy database. Shared by the cli boot check and the writer."""
    msg = str(e).lower()
    return any(s in msg for s in ("malformed", "not a database", "no such table", "no such column", "encrypted"))


def quarantine_database(db_path: Path) -> None:
    """move an unusable database aside to picosnitch.db.bad, with its WAL files so that none is
    replayed into the new database the next start creates"""
    for suffix in ("", "-wal", "-shm"):
        try:
            db_path.with_name(db_path.name + suffix).rename(db_path.with_name(db_path.name + ".bad" + suffix))
        except OSError:
            pass


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


def log_error(message: str) -> None:
    """log a problem of the capture or write side; messages carry comm, cmdline and domain strings"""
    logging.getLogger("picosnitch.error").warning(sanitize_log_line(message))


class DropOldestQueue[T]:
    """a hand-off between threads, bounded by the items in its batches, that never blocks its
    producer: past the bound the oldest batches are dropped and their items counted in dropped"""

    def __init__(self, max_items: int) -> None:
        self.max_items = max_items
        self.dropped = 0
        self._batches: collections.deque[list[T]] = collections.deque()
        self._items = 0
        self._ready = threading.Condition()

    def put(self, batch: list[T]) -> None:
        with self._ready:
            self._batches.append(batch)
            self._items += len(batch)
            # the newest batch is always kept, even one larger than the bound
            while self._items > self.max_items and len(self._batches) > 1:
                oldest = self._batches.popleft()
                self._items -= len(oldest)
                self.dropped += len(oldest)
            self._ready.notify()

    def get_all(self, timeout: float) -> list[list[T]]:
        """all waiting batches, oldest first, after waiting up to timeout for one; [] if none came"""
        with self._ready:
            if not self._batches:
                self._ready.wait(timeout)
            batches = list(self._batches)
            self._batches.clear()
            self._items = 0
        return batches
