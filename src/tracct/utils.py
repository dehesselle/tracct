# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import collections
import os
import socket
import sqlite3
import stat
import threading
import unicodedata
import urllib.parse
from pathlib import Path

from tracct.constants import ROLE_ACCEPTED, ROLE_BOUND, ROLE_PICKED

__all__ = [
    "DropOldestQueue",
    "connect_db_readonly",
    "quarantine_database",
    "sanitize_log_line",
    "sd_notify",
    "service_port_sql",
    "sqlite_error_means_corrupt",
]

#: The socket module has it only where Python was built against headers that do.
IPPROTO_MPTCP = 262


def sd_notify(message: str) -> None:
    """Best-effort systemd notification via the raw sd_notify(3) protocol, so the
    privileged daemon needs no python-systemd dependency. No-op unless launched by a
    Type=notify unit (NOTIFY_SOCKET set); errors are swallowed, a readiness signal must
    never take the daemon down.
    """
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            # A leading '@' selects the abstract namespace, sent as a leading NUL.
            sock.sendto(message.encode(), "\0" + addr[1:] if addr[0] == "@" else addr)
    except OSError:
        pass


def sqlite_error_means_corrupt(e: sqlite3.Error) -> bool:
    """True when a sqlite error means tracct.db itself is unusable
    (quarantine+recreate); False for transient errors (locked by the live daemon, busy,
    disk I/O) where quarantining would destroy a healthy database. Shared by the cli
    boot check and the writer.
    """
    msg = str(e).lower()
    return any(
        s in msg
        for s in (
            "malformed",
            "not a database",
            "no such table",
            "no such column",
            "encrypted",
        )
    )


def quarantine_database(db_path: Path) -> None:
    """Move an unusable database aside to tracct.db.bad, with its WAL files so that none
    is replayed into the new database the next start creates.
    """
    for suffix in ("", "-wal", "-shm"):
        try:
            db_path.with_name(db_path.name + suffix).rename(
                db_path.with_name(db_path.name + ".bad" + suffix)
            )
        except OSError:
            pass


def connect_db_readonly(
    db_path: Path | str, timeout: float = 5.0
) -> sqlite3.Connection:
    """A read-only connection to a regular, not hardlinked database file.

    Raises sqlite3.OperationalError when it cannot be opened.
    """
    try:
        db_stat = os.lstat(db_path)
    except OSError as e:
        raise sqlite3.OperationalError(f"could not inspect {db_path}: {e}") from e
    if not stat.S_ISREG(db_stat.st_mode) or db_stat.st_nlink != 1:
        raise sqlite3.OperationalError(
            f"refusing non-regular or hardlinked database: {db_path}"
        )
    con = sqlite3.connect(
        f"file:{urllib.parse.quote(os.fspath(db_path), safe='/')}?mode=ro",
        uri=True,
        timeout=timeout,
    )
    try:
        # Touch the file, so an unreadable database fails here and not at the first
        # query.
        con.execute("PRAGMA user_version").fetchone()
    except sqlite3.Error:
        con.close()
        raise
    return con


def service_port_sql(remote: bool, prefix: str = "") -> str:
    """The local or remote port of a connections row as the rollups and folded rows keep
    it, as SQL over its columns (each with prefix): only the port that names the
    service, by the socket's role (see "Storage" in docs/DESIGN.md), else 0.

    The service is ours where we accepted the connection, and where a UDP socket bound
    its port on purpose; it is the peer's where our port was picked, and where a TCP
    client bound a port of its own (MPTCP is TCP here). A role that is unknown keeps
    neither port, as do ICMP rows, whose role always is.
    """
    p = prefix
    stream = f"({socket.IPPROTO_TCP}, {IPPROTO_MPTCP})"
    if remote:
        return (
            f"CASE WHEN {p}role = {ROLE_PICKED}"
            f" OR ({p}role = {ROLE_BOUND} AND {p}protocol IN {stream})"
            f" THEN {p}rport ELSE 0 END"
        )
    return (
        f"CASE WHEN {p}role = {ROLE_ACCEPTED}"
        f" OR ({p}role = {ROLE_BOUND} AND {p}protocol NOT IN {stream})"
        f" THEN {p}lport ELSE 0 END"
    )


def sanitize_log_line(line: str) -> str:
    """Remove control characters from a log line to prevent terminal-escape / log
    injection.
    """
    return "".join(
        c
        for c in line
        if c == "\t" or unicodedata.category(c) not in ("Cc", "Cf", "Cs")
    )


class DropOldestQueue[T]:
    """A hand-off between threads, bounded by the items in its batches, that never
    blocks its producer: past the bound the oldest batches are dropped and their items
    counted in dropped.
    """

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
            # The newest batch is always kept, even one larger than the bound.
            while self._items > self.max_items and len(self._batches) > 1:
                oldest = self._batches.popleft()
                self._items -= len(oldest)
                self.dropped += len(oldest)
            self._ready.notify()

    def get_all(self, timeout: float) -> list[list[T]]:
        """All waiting batches, oldest first, after waiting up to timeout for one.

        [] if none came.
        """
        with self._ready:
            if not self._batches:
                self._ready.wait(timeout)
            batches = list(self._batches)
            self._batches.clear()
            self._items = 0
        return batches
