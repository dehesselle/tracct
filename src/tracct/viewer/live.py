# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""the live tab: connections as the daemon drains them, from events.sock, with totals per
executable since the tab started (or was reset)"""

from __future__ import annotations

import collections
import dataclasses
import enum
import itertools
import threading
import time
from pathlib import Path

from rich.text import Text
from tcoda.settings import config
from tcoda.widgets import DataTable
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets.data_table import RowKey
from textual.worker import get_current_worker

from tracct.live_feed import LiveFeedSubscriber
from tracct.viewer.banner import Banner
from tracct.viewer.client import feed_closed, feed_unavailable
from tracct.viewer.format import bytes_cell, clean, format_clock
from tracct.viewer.pane import FindablePane
from tracct.viewer.settings import LIVE_EVENTS, LIVE_EXECUTABLES

# events waiting between the feed thread and the next redraw; fills only while the UI stalls
INCOMING_MAX = 10000
REDRAW_SECONDS = 0.5
RECONNECT_SECONDS = 3.0


def _int(value: object) -> int:
    return value if isinstance(value, int) else 0


def remote(event: dict) -> str:
    rport = event.get("rport", -1)
    host = event.get("domain") or event.get("raddr") or ""
    return host + (f":{rport}" if isinstance(rport, int) and rport > 0 else "")


class FeedState(enum.Enum):
    CONNECTING = "connecting"
    CONNECTED = "connected"
    #: Not connected, for the reason in the pane's state message.
    DOWN = "down"


@dataclasses.dataclass(frozen=True)
class LiveEvent:
    """A connection as the daemon drained it, numbered as it arrived."""

    #: Numbers the events in the order they arrived; also their row key.
    seq: int
    arrived: float
    name: str
    exe: str
    parent: str
    unit: str
    #: The local port, or 0 for none.
    lport: int
    remote: str
    sent: int
    received: int
    #: What a find looks in.
    domain: str
    raddr: str

    @classmethod
    def parse(cls, seq: int, arrived: float, event: dict) -> LiveEvent:
        lport = _int(event.get("lport"))
        return cls(
            seq=seq,
            arrived=arrived,
            name=event.get("name") or "",
            exe=event.get("exe") or "",
            parent=event.get("pname") or "",
            unit=event.get("unit") or "",
            lport=max(lport, 0),
            remote=remote(event),
            sent=_int(event.get("send")),
            received=_int(event.get("recv")),
            domain=event.get("domain") or "",
            raddr=event.get("raddr") or "",
        )

    @property
    def key(self) -> str:
        return str(self.seq)


@dataclasses.dataclass
class LiveTotal:
    """The sums of one executable, under one name, since the tab started."""

    name: str
    exe: str
    sent: int = 0
    received: int = 0
    events: int = 0
    #: The systemd unit of its last event that had one.
    unit: str = ""
    last_seen: float = 0.0

    @staticmethod
    def key_of(name: str, exe: str) -> str:
        return f"{name}\0{exe}"

    def add(self, event: LiveEvent) -> None:
        self.sent += event.sent
        self.received += event.received
        self.events += 1
        self.unit = event.unit or self.unit
        self.last_seen = event.arrived


class LivePane(FindablePane):
    BINDINGS = [
        Binding("space", "pause", "pause", key_display="␣"),
        Binding("r", "reset", "reset"),
    ]

    def __init__(self, events_socket: Path, *, id: str | None = None) -> None:
        super().__init__(id=id)
        self.events_socket = events_socket
        self._lock = threading.Lock()
        # (arrival time, event) from the feed thread, for the next redraw
        self._incoming: collections.deque[tuple[float, dict]] = collections.deque(
            maxlen=INCOMING_MAX
        )
        #: The latest events by row key, oldest first; frozen while paused.
        self.events: dict[str, LiveEvent] = {}
        #: The totals per executable by row key.
        self.summary: dict[str, LiveTotal] = {}
        #: Executables dropped from the summary for the limit, since the tab started or
        #: was reset.
        self.dropped = 0
        self.event_count = 0
        self.since = time.time()
        self.paused = False
        self.state = FeedState.CONNECTING
        #: Why the feed is down, while it is.
        self.state_message = ""
        self._dirty = True
        self._seq = 0

    def compose_content(self) -> ComposeResult:
        yield DataTable(id="summary", cursor_type="row", zebra_stripes=True)
        yield DataTable(id="events", cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        # the columns of numbers sort by the number, not by its text; the tables only
        # ever show rows that are in the models, so every key is there to look up
        summary = self.query_one("#summary", DataTable)
        for key, label, sort_key in (
            ("exe", "executable", None),
            ("name", "name", None),
            ("unit", "unit", None),
            ("events", _right("events"), lambda k: self.summary[k.value].events),
            ("sent", _right("sent"), lambda k: self.summary[k.value].sent),
            ("received", _right("received"), lambda k: self.summary[k.value].received),
        ):
            summary.add_column(label, key=key, sortable=True, sort_key=sort_key)
        summary.sort_by("exe")
        events = self.query_one("#events", DataTable)
        for key, label, sort_key in (
            ("time", "time", lambda k: self.events[k.value].seq),
            ("name", "name", None),
            ("parent", "parent", None),
            ("unit", "unit", None),
            ("lport", _right("lport"), lambda k: self.events[k.value].lport),
            ("remote", "remote", None),
            ("sent", _right("sent"), lambda k: self.events[k.value].sent),
            ("received", _right("received"), lambda k: self.events[k.value].received),
        ):
            events.add_column(label, key=key, sortable=True, sort_key=sort_key)
        events.sort_by("time", reverse=True)
        self.subscribe()
        self.set_interval(REDRAW_SECONDS, self.redraw)

    @work(thread=True, group="live-feed")
    def subscribe(self) -> None:
        """reads the feed until the app ends, reconnecting while the daemon is away"""
        worker = get_current_worker()
        while not worker.is_cancelled:
            sub = LiveFeedSubscriber(timeout=1.0, path=self.events_socket)
            try:
                sub.connect()
            except OSError as e:
                self._set_state(FeedState.DOWN, feed_unavailable(self.events_socket, e))
            else:
                self._set_state(FeedState.CONNECTED)
                while not worker.is_cancelled:
                    try:
                        event = next(sub)
                    except TimeoutError:
                        continue
                    except (StopIteration, OSError):
                        self._set_state(FeedState.DOWN, feed_closed(self.events_socket))
                        break
                    if isinstance(event, dict) and event:
                        with self._lock:
                            self._incoming.append((time.time(), event))
            finally:
                sub.close()
            self._dirty = True
            deadline = time.monotonic() + RECONNECT_SECONDS
            while not worker.is_cancelled and time.monotonic() < deadline:
                time.sleep(0.2)

    def _set_state(self, state: FeedState, message: str = "") -> None:
        # the message first: the redraw reads the state, then the message
        self.state_message = message
        self.state = state

    def redraw(self) -> None:
        with self._lock:
            incoming = list(self._incoming)
            self._incoming.clear()
        arrived = []
        for t, raw in incoming:
            self._seq += 1
            event = LiveEvent.parse(self._seq, t, raw)
            arrived.append(event)
            key = LiveTotal.key_of(event.name, event.exe)
            self.summary.setdefault(key, LiveTotal(event.name, event.exe)).add(event)
        self.event_count += len(arrived)
        if not self.paused:
            self.events.update((event.key, event) for event in arrived)
        self.apply_limits()
        if arrived or self._dirty:
            self._dirty = False
            self.render_tables(events=not self.paused)
        self.update_banner()
        self.update_titles()

    def apply_limits(self) -> None:
        """the limits from the settings, read on every redraw so a change applies at once"""
        executables = config.get(LIVE_EXECUTABLES)
        if len(self.summary) > executables:
            # the executables idle the longest make room
            ranked = sorted(
                self.summary.items(), key=lambda item: item[1].last_seen, reverse=True
            )
            self.dropped += len(ranked) - executables
            self.summary = dict(ranked[:executables])
            self._dirty = True
        # paused, the events table keeps what it shows
        excess = len(self.events) - config.get(LIVE_EVENTS)
        if excess > 0 and not self.paused:
            for key in list(itertools.islice(self.events, excess)):
                del self.events[key]
            self._dirty = True

    def matches(self, *fields: object) -> bool:
        needle = self.find.lower()
        return not needle or any(needle in str(field or "").lower() for field in fields)

    def render_tables(self, events: bool = True) -> None:
        rows = [
            (
                key,
                (
                    Text(clean(total.exe)),
                    Text(clean(total.name)),
                    Text(clean(total.unit)),
                    Text(str(total.events), justify="right"),
                    bytes_cell(total.sent),
                    bytes_cell(total.received),
                ),
            )
            for key, total in self.summary.items()
            if self.matches(total.name, total.exe, total.unit)
        ]
        # the cursor stays on its executable as the rows move with the sort
        _replace_rows(self.query_one("#summary", DataTable), rows, follow=True)
        if not events:
            return
        rows = [
            (
                key,
                (
                    format_clock(event.arrived),
                    Text(clean(event.name)),
                    Text(clean(event.parent)),
                    Text(clean(event.unit)),
                    Text(str(event.lport) if event.lport else "", justify="right"),
                    Text(clean(event.remote)),
                    bytes_cell(event.sent),
                    bytes_cell(event.received),
                ),
            )
            for key, event in self.events.items()
            if self.matches(
                event.name, event.exe, event.unit, event.domain, event.raddr
            )
        ]
        # the cursor keeps its place while new events push the rows along
        _replace_rows(self.query_one("#events", DataTable), rows, follow=False)

    def update_banner(self) -> None:
        """Say why the feed is not connected, and a kept find; nothing, no banner."""
        notes = []
        down = self.state is not FeedState.CONNECTED
        if down:
            notes.append(self.state_message or self.state.value)
        # while the find input is open, it says it already
        kept = bool(self.find) and not self.find_open()
        if kept:
            notes.append(f"find: {self.find}")
        self.query_one(Banner).say(
            notes, "press c to clear" if kept else "", error=down
        )

    def update_titles(self) -> None:
        """Count the tables' rows and the time since the tab started in their titles."""
        summary = f"summary ({self.dropped} dropped)" if self.dropped else "summary"
        self.query_one(
            "#summary", DataTable
        ).border_title = f"{summary} · {int(time.time() - self.since)} s"
        events = self.query_one("#events", DataTable)
        events.border_title = (
            f"last {config.get(LIVE_EVENTS)} events · {self.event_count} total"
        )
        events.border_subtitle = "table is frozen" if self.paused else ""

    def action_pause(self) -> None:
        self.paused = not self.paused
        self._dirty = True
        self.redraw()

    def action_reset(self) -> None:
        self.summary.clear()
        self.events.clear()
        self.dropped = 0
        self.event_count = 0
        self.since = time.time()
        # paused too: the frozen events would be gone from the model behind them
        self.query_one("#events", DataTable).clear()
        self._dirty = True
        self.redraw()

    def apply_find(self) -> None:
        # on the next redraw, which comes soon enough for typing
        self._dirty = True


def _right(label: str) -> Text:
    return Text(label, justify="right")


def _replace_rows(
    table: DataTable, rows: list[tuple[str, tuple]], follow: bool
) -> None:
    """new rows, in the table's sort order at once rather than on the next idle; the cursor
    follows its row by key, or keeps its place"""
    cursor = table.cursor_row
    followed: RowKey | None = None
    if follow and 0 <= cursor < table.row_count:
        followed = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
    table.clear()
    for row_key, cells in rows:
        table.add_row(*cells, key=row_key)
    if table.sort_column is not None:
        table.sort_by(table.sort_column, reverse=table.sort_reverse)
    if rows:
        if followed is not None and followed in table.rows:
            cursor = table.get_row_index(followed)
        table.move_cursor(row=min(cursor, len(rows) - 1))
