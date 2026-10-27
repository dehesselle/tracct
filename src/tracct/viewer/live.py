# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""the live tab: connections as the daemon drains them, from events.sock, with totals per
executable since the tab started (or was reset) and the ports each one listens on"""

from __future__ import annotations

import collections
import itertools
import os
import threading
import time
from pathlib import Path

from rich.text import Text
from tcoda.settings import config
from tcoda.widgets import DataTable
from textual import work
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Static
from textual.widgets.data_table import RowKey
from textual.worker import get_current_worker

from tracct.live_feed import LiveFeedSubscriber, feed_closed_reason
from tracct.viewer.format import bytes_cell, clean, clock
from tracct.viewer.settings import LIVE_EVENTS, LIVE_EXECUTABLES

# events waiting between the feed thread and the next redraw; fills only while the UI stalls
INCOMING_MAX = 10000
REDRAW_SECONDS = 0.5
RECONNECT_SECONDS = 3.0
LISTEN_SCAN_SECONDS = 5.0


def scan_listening_ports() -> dict[str, set[int]]:
    """executable path -> its listening TCP and bound UDP ports, from /proc/net and the sockets in
    /proc/<pid>/fd; processes this user cannot inspect are skipped"""
    inode_to_port: dict[int, int] = {}
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        try:
            with open(f"/proc/net/{proto}") as f:
                lines = f.readlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            # tcp: only LISTEN (0A); udp: any bound socket
            if len(parts) < 10 or (proto.startswith("tcp") and parts[3] != "0A"):
                continue
            try:
                port = int(parts[1].rsplit(":", 1)[1], 16)
                inode = int(parts[9])
            except (ValueError, IndexError):
                continue
            if inode and port:
                inode_to_port[inode] = port
    exe_to_ports: dict[str, set[int]] = {}
    if not inode_to_port:
        return exe_to_ports
    try:
        pids = [name for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        return exe_to_ports
    for pid in pids:
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                port = inode_to_port.get(int(target[8:-1]) if target[8:-1].isdigit() else -1)
                if port is not None:
                    exe_to_ports.setdefault(exe, set()).add(port)
    return exe_to_ports


def remote(event: dict) -> str:
    rport = event.get("rport", -1)
    host = event.get("domain") or event.get("raddr") or ""
    return host + (f":{rport}" if isinstance(rport, int) and rport > 0 else "")


class LivePane(Vertical):
    DEFAULT_CSS = """
    LivePane .header { height: 1; padding: 0 1; background: $foreground 8%; }
    LivePane .header.-error { color: $text-error; }
    /* a gray a little dimmer than an inactive tab's, so the titles in the border stay readable */
    LivePane DataTable { border: round $foreground 40%; }
    LivePane DataTable:focus { border: round $accent; }
    LivePane #totals { height: 2fr; }
    LivePane #recent { height: 3fr; }
    """
    BINDINGS = [
        Binding("p,space", "pause", "pause"),
        Binding("r", "reset", "reset"),
    ]

    def __init__(self, events_socket: Path, *, id: str | None = None) -> None:
        super().__init__(id=id)
        self.events_socket = events_socket
        self._lock = threading.Lock()
        self._incoming: collections.deque[dict] = collections.deque(maxlen=INCOMING_MAX)
        # newest first
        self.recent: collections.deque[dict] = collections.deque(maxlen=config.get(LIVE_EVENTS))
        # (name, exe) -> [sent, received, events, unit, last seen]
        self.totals: dict[tuple[str, str], list] = {}
        # executables dropped from totals for the limit, since the tab started or was reset
        self.dropped = 0
        self.listening: dict[str, set[int]] = {}
        self.events = 0
        self.since = time.time()
        self.paused = False
        self.find = ""
        self.state = "connecting"
        self._dirty = True
        # numbers each event, so the events table has a row key and an order by time
        self._seq = 0
        # the rows in the tables by row key, for the columns that sort by the value behind the text
        self._shown_totals: dict[str, tuple[tuple[str, str], list]] = {}
        self._shown_recent: dict[str, dict] = {}

    def compose(self):
        yield Static(classes="header")
        yield DataTable(id="totals", cursor_type="row", zebra_stripes=True)
        yield DataTable(id="recent", cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        totals = self.query_one("#totals", DataTable)
        for key, label, by_value in (
            ("exe", "executable", None),
            ("name", "name", None),
            ("unit", "unit", None),
            ("events", Text("events", justify="right"), lambda entry: entry[1][2]),
            ("sent", Text("sent", justify="right"), lambda entry: entry[1][0]),
            ("received", Text("received", justify="right"), lambda entry: entry[1][1]),
            ("listening", "listening", lambda entry: tuple(sorted(self.listening.get(entry[0][1], ())))),
        ):
            totals.add_column(label, key=key, sortable=True, sort_key=self._by_value(self._shown_totals, by_value))
        totals.sort_by("exe")
        recent = self.query_one("#recent", DataTable)
        for key, label, by_value in (
            ("time", "time", lambda event: event["_seq"]),
            ("name", "name", None),
            ("parent", "parent", None),
            ("unit", "unit", None),
            ("lport", Text("lport", justify="right"), lambda event: _int(event.get("lport"))),
            ("remote", "remote", None),
            ("sent", Text("sent", justify="right"), lambda event: _int(event.get("send"))),
            ("received", Text("received", justify="right"), lambda event: _int(event.get("recv"))),
        ):
            recent.add_column(label, key=key, sortable=True, sort_key=self._by_value(self._shown_recent, by_value))
        recent.sort_by("time", reverse=True)
        self.subscribe()
        self.scan_ports()
        self.set_interval(REDRAW_SECONDS, self.redraw)
        self.set_interval(LISTEN_SCAN_SECONDS, self.scan_ports)

    @work(thread=True, group="live-feed")
    def subscribe(self) -> None:
        """reads the feed until the app ends, reconnecting while the daemon is away"""
        worker = get_current_worker()
        while not worker.is_cancelled:
            sub = LiveFeedSubscriber(timeout=1.0, path=self.events_socket)
            try:
                sub.connect()
            except PermissionError:
                self.state = f"no access to {self.events_socket}: join the viewer group (tracct-viewer) or run as root"
            except OSError as e:
                self.state = f"live feed unavailable ({e.strerror or e}); is the tracct service running?"
            else:
                self.state = "connected"
                while not worker.is_cancelled:
                    try:
                        event = next(sub)
                    except TimeoutError:
                        continue
                    except (StopIteration, OSError):
                        self.state = f"feed closed: {feed_closed_reason(self.events_socket)}; reconnecting"
                        break
                    if isinstance(event, dict) and event:
                        event["_t"] = time.time()
                        with self._lock:
                            self._incoming.append(event)
            finally:
                sub.close()
            self._dirty = True
            deadline = time.monotonic() + RECONNECT_SECONDS
            while not worker.is_cancelled and time.monotonic() < deadline:
                time.sleep(0.2)

    @work(thread=True, exclusive=True, group="live-ports")
    def scan_ports(self) -> None:
        try:
            self.listening = scan_listening_ports()
        except Exception:
            self.listening = {}

    def redraw(self) -> None:
        with self._lock:
            arrived = list(self._incoming)
            self._incoming.clear()
        for event in arrived:
            self.events += 1
            self._seq += 1
            event["_seq"] = self._seq
            key = (event.get("name") or "", event.get("exe") or "")
            row = self.totals.setdefault(key, [0, 0, 0, "", 0.0])
            row[0] += int(event.get("send", 0) or 0)
            row[1] += int(event.get("recv", 0) or 0)
            row[2] += 1
            row[3] = event.get("unit") or row[3]
            row[4] = event["_t"]
        self.apply_limits()
        if not self.paused:
            self.recent.extendleft(arrived)
        if arrived or self._dirty:
            self._dirty = False
            self.render_tables(recent=not self.paused)
        self.update_header()

    def apply_limits(self) -> None:
        """the limits from the settings, read on every redraw so a change applies at once"""
        executables = config.get(LIVE_EXECUTABLES)
        if len(self.totals) > executables:
            # the executables idle the longest make room
            ranked = sorted(self.totals.items(), key=lambda item: item[1][4], reverse=True)
            self.dropped += len(ranked) - executables
            self.totals = dict(ranked[:executables])
            self._dirty = True
        events = config.get(LIVE_EVENTS)
        if self.recent.maxlen != events:
            self.recent = collections.deque(itertools.islice(self.recent, events), maxlen=events)
            self._dirty = True

    def matches(self, *fields: object) -> bool:
        needle = self.find.lower()
        return not needle or any(needle in str(field or "").lower() for field in fields)

    @staticmethod
    def _by_value(shown: dict, by_value):
        """a column's sort key: the value behind its text, from the row shown under that row key;
        None ranks by the text itself"""
        if by_value is None:
            return None
        return lambda row_key: by_value(shown[row_key.value])

    def render_tables(self, recent: bool = True) -> None:
        self._shown_totals.clear()
        rows = []
        for (name, exe), entry in self.totals.items():
            sent, received, count, unit, _ = entry
            if self.matches(name, exe, unit):
                row_key = f"{name}\0{exe}"
                self._shown_totals[row_key] = ((name, exe), entry)
                ports = ",".join(str(port) for port in sorted(self.listening.get(exe, ())))
                rows.append((row_key, (Text(clean(exe)), Text(clean(name)), Text(clean(unit)), Text(str(count), justify="right"), bytes_cell(sent), bytes_cell(received), Text(ports))))
        # the cursor stays on its executable as the rows move with the sort
        _replace_rows(self.query_one("#totals", DataTable), rows, follow=True)
        if recent:
            self._shown_recent.clear()
            rows = []
            for event in self.recent:
                if not self.matches(event.get("name"), event.get("exe"), event.get("unit"), event.get("domain"), event.get("raddr")):
                    continue
                row_key = str(event["_seq"])
                self._shown_recent[row_key] = event
                lport = event.get("lport", -1)
                rows.append(
                    (
                        row_key,
                        (
                            clock(event.get("_t", 0)),
                            Text(clean(event.get("name") or "")),
                            Text(clean(event.get("pname") or "")),
                            Text(clean(event.get("unit") or "")),
                            Text(str(lport) if isinstance(lport, int) and lport > 0 else "", justify="right"),
                            Text(clean(remote(event))),
                            bytes_cell(event.get("send", 0)),
                            bytes_cell(event.get("recv", 0)),
                        ),
                    )
                )
            # the cursor keeps its place while new events push the rows along
            _replace_rows(self.query_one("#recent", DataTable), rows, follow=False)

    def update_header(self) -> None:
        elapsed = max(1.0, time.time() - self.since)
        header = Text()
        header.append("Live ", style="bold")
        header.append(f"(socket bytes)  {self.events} events in {int(elapsed)} s")
        if self.find:
            header.append(f"  find: {self.find}")
        if self.state != "connected":
            header.append(f"  {self.state}", style="bold")
        widget = self.query_one(".header", Static)
        widget.set_class(self.state != "connected", "-error")
        widget.update(header)
        self.query_one("#totals", DataTable).border_title = f"summary ({self.dropped} dropped)" if self.dropped else "summary"
        recent = self.query_one("#recent", DataTable)
        recent.border_title = f"last {config.get(LIVE_EVENTS)} events"
        recent.border_subtitle = "PAUSED" if self.paused else ""

    def action_pause(self) -> None:
        self.paused = not self.paused
        self._dirty = True

    def action_reset(self) -> None:
        self.totals.clear()
        self.recent.clear()
        self.dropped = 0
        self.events = 0
        self.since = time.time()
        self._dirty = True

    def set_find(self, needle: str) -> None:
        self.find = needle
        self._dirty = True


def _int(value: object) -> int:
    return value if isinstance(value, int) else 0


def _replace_rows(table: DataTable, rows: list[tuple[str, tuple]], follow: bool) -> None:
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
