# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Live event feed published over a UNIX socket so external readers
(the live tab of tracct view, custom tools) can subscribe to network
events in real time without polling the database.
"""

import collections.abc
import grp
import json
import logging
import os
import select
import socket
import threading
from pathlib import Path

from tracct.constants import RUN_DIR

logger = logging.getLogger(__name__)

__all__ = [
    "EVENTS_SOCKET_PATH",
    "MAX_PENDING_BYTES",
    "MAX_SUBSCRIBERS",
    "LiveFeedPublisher",
    "LiveFeedSubscriber",
    "feed_closed_reason",
]

EVENTS_SOCKET_PATH = RUN_DIR / "events.sock"
MAX_SUBSCRIBERS = 32
#: Per-subscriber backlog held in userspace once the kernel send buffer is full; a drain
#: burst (one event per active connection, each carrying three cmdlines) can exceed the
#: default ~208 KB socket buffer by far before a reader gets scheduled.
MAX_PENDING_BYTES = 8 * 1024 * 1024


def feed_closed_reason(path: Path | None = None) -> str:
    """Why a subscriber saw EOF.

    The daemon removes the socket on shutdown, so a socket that is still there means
    this subscriber was dropped (or the daemon restarted).
    """
    if (path or EVENTS_SOCKET_PATH).exists():
        return f"the daemon dropped this viewer after it fell more than {MAX_PENDING_BYTES // (1024 * 1024)} MiB behind (or the daemon restarted)"
    return "the tracct daemon stopped"


class _Subscriber:
    __slots__ = ("conn", "out")

    def __init__(self, conn: socket.socket) -> None:
        self.conn = conn
        self.out = bytearray()


class LiveFeedPublisher:
    """Single-publisher, many-subscribers UNIX socket broadcaster.

    Runs an accept thread and a writer thread. Publishing only queues output per
    subscriber; the writer thread sends it whenever a socket has room, so delivery is
    not limited to one kernel buffer per publish call. A subscriber is dropped only once
    its queue exceeds MAX_PENDING_BYTES.
    """

    def __init__(self, group: str | None = None) -> None:
        self._group = group
        self._sock: socket.socket | None = None
        self._subscribers: list[_Subscriber] = []
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._writer_thread: threading.Thread | None = None
        self._wake_r = self._wake_w = -1
        self.dropped = 0  # subscribers dropped for falling too far behind

    def start(self) -> None:
        try:
            EVENTS_SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
            try:
                EVENTS_SOCKET_PATH.unlink()
            except FileNotFoundError:
                pass
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.bind(str(EVENTS_SOCKET_PATH))
            os.chmod(EVENTS_SOCKET_PATH, 0o660)
            if self._group:
                # Unprivileged, this only works for a group the daemon is a member of
                # (SupplementaryGroups= in the unit).
                try:
                    gid = grp.getgrnam(self._group).gr_gid
                    os.chown(EVENTS_SOCKET_PATH, -1, gid)
                except (KeyError, PermissionError) as e:
                    logger.warning(
                        f"live feed: could not hand {EVENTS_SOCKET_PATH} to group {self._group!r}: {e}"
                    )
            self._sock.listen(8)
            self._wake_r, self._wake_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
            self._accept_thread = threading.Thread(
                target=self._accept_loop, daemon=True
            )
            self._accept_thread.start()
            self._writer_thread = threading.Thread(
                target=self._writer_loop, daemon=True
            )
            self._writer_thread.start()
        except Exception:
            self._sock = None

    def _accept_loop(self) -> None:
        while not self._stopped.is_set():
            if self._sock is None:
                return
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            conn.setblocking(False)
            with self._lock:
                if self._stopped.is_set() or len(self._subscribers) >= MAX_SUBSCRIBERS:
                    conn.close()
                else:
                    self._subscribers.append(_Subscriber(conn))

    def has_subscribers(self) -> bool:
        """True if anyone is listening, so callers can skip serializing an event no one
        will read -- the common case (no live tab of tracct view open).
        """
        return self._sock is not None and bool(self._subscribers)

    def publish(self, event: dict) -> None:
        self.publish_many([event])

    def publish_many(
        self, events: collections.abc.Sequence[collections.abc.Mapping[str, object]]
    ) -> None:
        """Serialize events once and queue them for every subscriber.

        The writer thread sends them.
        """
        if not events or self._sock is None or not self._subscribers:
            return
        payload = "".join(
            json.dumps(event, default=str) + "\n" for event in events
        ).encode("utf-8", "replace")
        with self._lock:
            overflowed = []
            for sub in self._subscribers:
                sub.out += payload
                if len(sub.out) > MAX_PENDING_BYTES:
                    overflowed.append(sub)
            self.dropped += len(overflowed)
            self._remove(overflowed)
        self._wake()

    def _wake(self) -> None:
        try:
            os.write(self._wake_w, b"\0")
        except OSError:
            pass  # pipe full: a wakeup is already pending

    def _writer_loop(self) -> None:
        while not self._stopped.is_set():
            poller = select.poll()
            poller.register(self._wake_r, select.POLLIN)
            with self._lock:
                for sub in self._subscribers:
                    if sub.out:
                        poller.register(sub.conn, select.POLLOUT)
            poller.poll(1000)
            try:
                os.read(self._wake_r, 4096)
            except BlockingIOError:
                pass
            with self._lock:
                self._remove([sub for sub in self._subscribers if not self._flush(sub)])

    def _remove(self, subs: list[_Subscriber]) -> None:
        """Close and forget subscribers; the caller holds the lock."""
        for sub in subs:
            try:
                sub.conn.close()
            except OSError:
                pass
            self._subscribers.remove(sub)

    @staticmethod
    def _flush(sub: _Subscriber) -> bool:
        """Send as much of the backlog as the socket takes; False if the peer is gone.

        Uses send rather than sendall, which can write part of the data and then raise,
        losing track of how much went out and breaking the line framing.
        """
        while sub.out:
            try:
                sent = sub.conn.send(sub.out)
            except BlockingIOError:
                return True
            except OSError:
                return False
            del sub.out[:sent]
        return True

    def stop(self) -> None:
        self._stopped.set()
        if self._writer_thread is not None:
            self._wake()
            self._writer_thread.join(timeout=2)
            self._writer_thread = None
        with self._lock:
            self._remove(list(self._subscribers))
        for fd in (self._wake_r, self._wake_w):
            if fd >= 0:
                os.close(fd)
        self._wake_r = self._wake_w = -1
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        try:
            EVENTS_SOCKET_PATH.unlink()
        except FileNotFoundError:
            pass


class LiveFeedSubscriber:
    """Iterable line-delimited JSON reader for the live event socket."""

    def __init__(self, timeout: float | None = None, path: Path | None = None) -> None:
        self._timeout = timeout
        #: Resolved at connect time, so a test that moves EVENTS_SOCKET_PATH is
        #: followed.
        self._path = path
        self._sock: socket.socket | None = None
        self._buf = b""

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self._timeout is not None:
            sock.settimeout(self._timeout)
        try:
            sock.connect(str(self._path or EVENTS_SOCKET_PATH))
        except OSError:
            sock.close()
            raise
        self._sock = sock

    def settimeout(self, timeout: float | None) -> None:
        if self._sock is not None:
            self._sock.settimeout(timeout)
        self._timeout = timeout

    def __iter__(self) -> "LiveFeedSubscriber":
        return self

    def __next__(self) -> dict:
        if self._sock is None:
            raise StopIteration
        while b"\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise StopIteration
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        try:
            return json.loads(line.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return {}

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
