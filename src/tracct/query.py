# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""the protocol between the query server and its clients: one JSON object per message, preceded
by its length as a 4-byte big-endian integer. each request gets one response, which has "ok" set
and either the result or an "error"; requests and their fields are in query_server.py"""

from __future__ import annotations

import json
import os
import socket
import struct
from pathlib import Path

# created by tracct-query.socket; outside the daemon's runtime directory, which goes with the daemon
QUERY_SOCKET_PATH = Path(os.getenv("TRACCT_QUERY_SOCKET") or "/run/tracct-query.sock")
# a response's bound; the server keeps its answers below it
MAX_RESPONSE_BYTES = 16 * 1024 * 1024

_HEADER = struct.Struct(">I")


class QueryError(Exception):
    """the server answered with an error, or the answer could not be read"""


def send_message(sock: socket.socket, message: dict) -> None:
    data = json.dumps(message, separators=(",", ":")).encode("utf-8", "replace")
    sock.sendall(_HEADER.pack(len(data)) + data)


def _recv_exact(sock: socket.socket, size: int) -> bytes | None:
    """size bytes, or None when the peer closed before the first of them"""
    chunks = []
    received = 0
    while received < size:
        chunk = sock.recv(min(size - received, 1024 * 1024))
        if not chunk:
            if received:
                raise ConnectionError("connection closed inside a message")
            return None
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def recv_message(sock: socket.socket, max_bytes: int) -> dict | None:
    """the next message, or None when the peer closed between messages; ValueError for one that
    is too large or not a JSON object"""
    header = _recv_exact(sock, _HEADER.size)
    if header is None:
        return None
    (size,) = _HEADER.unpack(header)
    if size > max_bytes:
        raise ValueError(f"message of {size} bytes exceeds {max_bytes}")
    data = _recv_exact(sock, size) if size else b""
    if data is None:
        raise ConnectionError("connection closed inside a message")
    message = json.loads(data.decode("utf-8", "replace"))
    if not isinstance(message, dict):
        raise ValueError("message is not a JSON object")
    return message


class QueryClient:
    """a connection to the query server; one request at a time"""

    def __init__(self, path: Path = QUERY_SOCKET_PATH, timeout: float = 60.0) -> None:
        self.path = path
        self.timeout = timeout
        self._sock: socket.socket | None = None

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(str(self.path))
        except OSError:
            sock.close()
            raise
        self._sock = sock

    def request(self, op: str, **params: object) -> dict:
        """send a request and return the server's answer; reconnects once if the server went away
        in between (it exits when idle and systemd starts it again)"""
        for attempt in (0, 1):
            if self._sock is None:
                self.connect()
            assert self._sock is not None
            try:
                send_message(self._sock, {"op": op, **params})
                response = recv_message(self._sock, MAX_RESPONSE_BYTES)
            except (ConnectionError, BrokenPipeError) as e:
                self.close()
                if attempt:
                    raise QueryError(f"the query server closed the connection ({e})") from e
                continue
            except (OSError, ValueError) as e:
                self.close()
                raise QueryError(f"{type(e).__name__}: {e}") from e
            if response is None:
                self.close()
                if attempt:
                    raise QueryError("the query server closed the connection")
                continue
            if not response.get("ok"):
                raise QueryError(str(response.get("error", "unknown error")))
            return response
        raise QueryError("unreachable")

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
