# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Which events start a connection.

tracct sees bytes per tuple (namespace, protocol, local address and port, remote address
and port), not connections opening and closing. A connection is the activity of one
tuple with no silence longer than GAP_SECONDS: an event whose tuple is new, or was silent
that long, starts one. The reader marks each event before the writer and the live feed
get it, so both count alike; see "Storage" in docs/DESIGN.md.
"""

from __future__ import annotations

import collections
import socket
import sqlite3
import typing

from tracct.types import BpfEvent

#: The silence after which a tuple's next event starts a new connection.
GAP_SECONDS: typing.Final[int] = 3600
#: Tuples remembered at most (principle 10); past that the longest silent are forgotten
#: early, and their next event counts as a new connection.
MAX_TUPLES: typing.Final[int] = 262144

Tuple = tuple[int, int, str, int, str, int]


def tuple_of(event: BpfEvent) -> Tuple | None:
    """The event's connection, None without one: no IP socket, or an address or port
    missing (as a packet socket's are)."""
    if event.get("family") not in (socket.AF_INET, socket.AF_INET6):
        return None
    raddr, lport, rport = event.get("raddr"), event.get("lport"), event.get("rport")
    if not raddr or not lport or not rport or lport < 0 or rport < 0:
        return None
    return (
        int(event.get("netns", 0) or 0),
        int(event.get("protocol", 0) or 0),
        event.get("laddr", ""),
        lport,
        raddr,
        rport,
    )


class ConnectionTracker:
    """The tuples seen within the last gap, by when they were last seen; the longest
    silent come first, so pruning only ever looks at the front."""

    def __init__(self, gap: int = GAP_SECONDS, limit: int = MAX_TUPLES) -> None:
        self.gap = gap
        self.limit = limit
        self.seen: collections.OrderedDict[Tuple, float] = collections.OrderedDict()
        #: Tuples forgotten for the limit while not yet silent for the gap; their next
        #: event counts again.
        self.evicted = 0

    def __len__(self) -> int:
        return len(self.seen)

    def mark(self, batch: list[BpfEvent], now: float) -> None:
        """Set each event's "new": True where it starts a connection."""
        for event in batch:
            key = tuple_of(event)
            if key is None:
                event["new"] = False
                continue
            last = self.seen.pop(key, None)
            event["new"] = last is None or now - last > self.gap
            self.seen[key] = now
        self._prune(now)

    def remember(self, key: Tuple, last_seen: float) -> None:
        """Take a tuple seen before, as at a start; older ones go first."""
        if key not in self.seen or self.seen[key] < last_seen:
            self.seen.pop(key, None)
            self.seen[key] = last_seen

    def _prune(self, now: float) -> None:
        cutoff = now - self.gap
        while self.seen:
            key, last = next(iter(self.seen.items()))
            if last >= cutoff and len(self.seen) <= self.limit:
                break
            del self.seen[key]
            if last >= cutoff:
                self.evicted += 1

    def load(self, con: sqlite3.Connection, now: float) -> int:
        """Remember the tuples of the rows written within the last gap, so a restart
        shorter than it does not count their connections again. Returns how many."""
        rows = con.execute(
            "SELECT n.inode, c.protocol, la.addr, c.lport, ra.addr, c.rport, MAX(c.time) AS t"
            " FROM connections c JOIN netns n ON n.id = c.netns_id"
            " JOIN addresses la ON la.id = c.laddr_id JOIN addresses ra ON ra.id = c.raddr_id"
            " WHERE c.time > ? AND c.family IN (?, ?) AND c.raddr_id != 0 AND c.lport > 0 AND c.rport > 0"
            " GROUP BY 1, 2, 3, 4, 5, 6 ORDER BY t",
            (now - self.gap, socket.AF_INET, socket.AF_INET6),
        ).fetchall()
        for inode, protocol, laddr, lport, raddr, rport, last_seen in rows:
            self.remember((inode, protocol, laddr, lport, raddr, rport), last_seen)
        self._prune(now)
        return len(rows)
