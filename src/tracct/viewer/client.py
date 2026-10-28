# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The viewer's connections to the daemon, and what it says when one fails.

The history tabs ask the query server through a HistoryClient; the live tab reads
events.sock itself. The messages for both name the group a socket belongs to, read from
the socket, so they stay right when `[viewer] group` names another one.
"""

from __future__ import annotations

import grp
import os
import threading
from pathlib import Path

from tracct.live_feed import feed_closed_reason
from tracct.query import QueryClient, QueryError
from tracct.viewer.model import Aggregate, Filter, SourceInfo, Timeline


def access_hint(path: Path) -> str:
    """Return how to get access to the socket at `path`."""
    try:
        gid = os.stat(path).st_gid
        group = grp.getgrgid(gid).gr_name if gid else ""
    except (OSError, KeyError):
        group = ""
    if group:
        return f"join the viewer group ({group}) or run as root"
    return "run as root, or set [viewer] group in config.toml and join it"


def no_access(path: Path) -> str:
    return f"no access to {path}: {access_hint(path)}"


def feed_unavailable(path: Path, error: OSError) -> str:
    """Return why the live feed at `path` could not be read."""
    if isinstance(error, PermissionError):
        return no_access(path)
    return (
        f"live feed unavailable ({error.strerror or error});"
        " is the tracct service running?"
    )


def feed_closed(path: Path) -> str:
    return f"feed closed: {feed_closed_reason(path)}; reconnecting"


class HistoryClient:
    """The query server, asked by the history tabs from their worker threads."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._client = QueryClient(path)
        #: One request at a time: the tabs share one connection.
        self._lock = threading.Lock()

    def ask(self, op: str, **params: object) -> dict:
        """Send a request and return the answer.

        Raises:
            QueryError: The server could not be reached or refused the request, with
                a message for the user.
        """
        with self._lock:
            try:
                return self._client.request(op, **params)
            except PermissionError as e:
                raise QueryError(no_access(self.path)) from e
            except OSError as e:
                raise QueryError(
                    f"query server unavailable at {self.path} ({e.strerror or e});"
                    " is tracct-query.socket enabled?"
                ) from e

    def describe(self) -> dict[str, SourceInfo]:
        """Return the sources by name."""
        sources = self.ask("describe")["sources"]
        return {name: SourceInfo.parse(raw) for name, raw in sources.items()}

    def aggregate(
        self,
        source: str,
        group_by: str,
        filters: list[Filter],
        start: int,
        end: int,
        limit: int,
    ) -> Aggregate:
        """Return the byte sums per value of `group_by` from `start` to `end`."""
        return Aggregate.parse(
            self.ask(
                "aggregate",
                source=source,
                group_by=group_by,
                filters=[f.to_request() for f in filters],
                start=start,
                end=end,
                limit=limit,
            )
        )

    def timeline(
        self,
        source: str,
        filters: list[Filter],
        start: int,
        end: int,
        origin: int,
        step: int,
        peak: int,
    ) -> Timeline:
        """Return the byte sums from `start` to `end` in buckets laid out from `origin`."""
        raw = self.ask(
            "timeline",
            source=source,
            filters=[f.to_request() for f in filters],
            start=origin,
            end=end,
            step=step,
            peak=peak,
        )
        return Timeline.parse(raw, start, end, origin)

    def close(self) -> None:
        self._client.close()
