# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""reverse DNS (PTR) lookups in worker threads, so the writer never waits on a resolver"""

from __future__ import annotations

import collections
import ipaddress
import queue
import socket
import threading
import time
from collections.abc import Callable

# answers kept, the least recently used dropped first
CACHE_MAX = 8192
# addresses waiting for a worker; past it an address is skipped and asked for again when it
# shows up in a later window
PENDING_MAX = 1024
# getnameinfo has no timeout of its own and blocks as long as the system resolver takes
# (resolv.conf timeout and attempts); several workers keep one unresponsive server from
# holding up every other lookup
WORKERS = 4


def resolve(ip: str) -> str:
    """the name of ip in reversed notation (com.example.www), or ip itself when it has none"""
    try:
        host = socket.getnameinfo((ip, 0), 0)[0]
    except Exception:
        return ip
    try:
        ipaddress.ip_address(host)
        return ip
    except ValueError:
        return ".".join(reversed(host.split(".")))


class ReverseDns:
    """answers lookups from its cache and hands unknown addresses to worker threads; an answer
    serves the lookups after it, the ones before it get "" """

    def __init__(
        self, resolver: Callable[[str], str] = resolve, workers: int = WORKERS
    ) -> None:
        self._resolver = resolver
        self._names: collections.OrderedDict[str, str] = collections.OrderedDict()
        # queued or being resolved, so an address is asked for once
        self._pending: set[str] = set()
        self._queue: queue.Queue[str] = queue.Queue(PENDING_MAX)
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._workers = [
            threading.Thread(target=self._work, name=f"reverse-dns-{i}", daemon=True)
            for i in range(workers)
        ]
        for worker in self._workers:
            worker.start()

    def close(self, timeout: float = 0) -> None:
        """let the workers end after their current lookup, waiting up to timeout for them"""
        self._closed.set()
        deadline = time.monotonic() + timeout
        for worker in self._workers:
            worker.join(max(0, deadline - time.monotonic()))

    def lookup(self, ip: str) -> str:
        """the name of ip if it is known, else "" (and ip is queued for a worker)"""
        with self._lock:
            name = self._names.get(ip)
            if name is not None:
                self._names.move_to_end(ip)
                return name
            if ip not in self._pending:
                try:
                    self._queue.put_nowait(ip)
                    self._pending.add(ip)
                except queue.Full:
                    pass
        return ""

    def _work(self) -> None:
        while not self._closed.is_set():
            try:
                ip = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                name = self._resolver(ip)
            except Exception:
                name = ip
            with self._lock:
                self._pending.discard(ip)
                self._names[ip] = name
                self._names.move_to_end(ip)
                if len(self._names) > CACHE_MAX:
                    self._names.popitem(last=False)
