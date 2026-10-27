# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""the live tab: connections as the daemon drains them, from events.sock, with totals per
executable since the tab started (or was reset) and the ports each one listens on"""

from __future__ import annotations

import collections
import os
import threading
import time
from pathlib import Path

from rich.text import Text
from textual import work
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import DataTable, Static
from textual.worker import get_current_worker

from tracct.live_feed import LiveFeedSubscriber, feed_closed_reason
from tracct.viewer.format import bytes_cell, clean, clock

# events kept for the recent table, and how many of them it shows
RECENT_KEPT = 10000
RECENT_SHOWN = 500
# executables shown in the totals table, and kept: past the bound the smaller half is dropped
TOTALS_SHOWN = 500
TOTALS_KEPT = 10000
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
    LivePane #totals { height: 2fr; }
    LivePane #recent { height: 3fr; }
    """
    BINDINGS = [
        Binding("p,space", "pause", "pause"),
        Binding("s", "sort", "sort"),
        Binding("r", "reset", "reset"),
    ]

    def __init__(self, events_socket: Path, *, id: str | None = None) -> None:
        super().__init__(id=id)
        self.events_socket = events_socket
        self._lock = threading.Lock()
        self._incoming: collections.deque[dict] = collections.deque(maxlen=RECENT_KEPT)
        self.recent: collections.deque[dict] = collections.deque(maxlen=RECENT_KEPT)
        # (name, exe) -> [sent, received, events, unit]
        self.totals: dict[tuple[str, str], list] = {}
        self.listening: dict[str, set[int]] = {}
        self.events = 0
        self.since = time.time()
        self.paused = False
        self.sort_received = False
        self.find = ""
        self.state = "connecting"
        self._dirty = True

    def compose(self):
        yield Static(classes="header")
        yield DataTable(id="totals", cursor_type="row", zebra_stripes=True)
        yield DataTable(id="recent", cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        self.query_one("#totals", DataTable).add_columns("executable", "name", "unit", Text("events", justify="right"), Text("sent", justify="right"), Text("received", justify="right"), "listening")
        self.query_one("#recent", DataTable).add_columns("time", "name", "parent", "unit", Text("lport", justify="right"), "remote", Text("sent", justify="right"), Text("received", justify="right"))
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
            key = (event.get("name") or "", event.get("exe") or "")
            row = self.totals.setdefault(key, [0, 0, 0, ""])
            row[0] += int(event.get("send", 0) or 0)
            row[1] += int(event.get("recv", 0) or 0)
            row[2] += 1
            row[3] = event.get("unit") or row[3]
        if len(self.totals) > TOTALS_KEPT:
            ranked = sorted(self.totals.items(), key=lambda item: item[1][0] + item[1][1], reverse=True)
            self.totals = dict(ranked[: TOTALS_KEPT // 2])
        if not self.paused:
            self.recent.extendleft(arrived)
        if arrived or self._dirty:
            self._dirty = False
            self.render_tables(recent=not self.paused)
        self.update_header()

    def matches(self, *fields: object) -> bool:
        needle = self.find.lower()
        return not needle or any(needle in str(field or "").lower() for field in fields)

    def render_tables(self, recent: bool = True) -> None:
        totals = self.query_one("#totals", DataTable)
        ranked = sorted(self.totals.items(), key=lambda item: item[1][1 if self.sort_received else 0], reverse=True)
        rows = []
        for (name, exe), (sent, received, count, unit) in ranked:
            if self.matches(name, exe, unit) and len(rows) < TOTALS_SHOWN:
                ports = ",".join(str(port) for port in sorted(self.listening.get(exe, ())))
                rows.append((Text(clean(exe)), Text(clean(name)), Text(clean(unit)), Text(str(count), justify="right"), bytes_cell(sent), bytes_cell(received), Text(ports)))
        _replace_rows(totals, rows)
        if recent:
            table = self.query_one("#recent", DataTable)
            rows = []
            for event in self.recent:
                if len(rows) >= RECENT_SHOWN:
                    break
                if not self.matches(event.get("name"), event.get("exe"), event.get("unit"), event.get("domain"), event.get("raddr")):
                    continue
                lport = event.get("lport", -1)
                rows.append(
                    (
                        clock(event.get("_t", 0)),
                        Text(clean(event.get("name") or "")),
                        Text(clean(event.get("pname") or "")),
                        Text(clean(event.get("unit") or "")),
                        Text(str(lport) if isinstance(lport, int) and lport > 0 else "", justify="right"),
                        Text(clean(remote(event))),
                        bytes_cell(event.get("send", 0)),
                        bytes_cell(event.get("recv", 0)),
                    )
                )
            _replace_rows(table, rows)

    def update_header(self) -> None:
        elapsed = max(1.0, time.time() - self.since)
        header = Text()
        header.append("Live ", style="bold")
        header.append(f"(socket bytes)  {self.events} events in {int(elapsed)} s, sorted by {'received' if self.sort_received else 'sent'}")
        if self.paused:
            # TODO: restyle; was bold reverse before the default theme
            header.append("  PAUSED", style="bold")
        if self.find:
            header.append(f"  find: {self.find}")
        if self.state != "connected":
            header.append(f"  {self.state}", style="bold")
        widget = self.query_one(".header", Static)
        widget.set_class(self.state != "connected", "-error")
        widget.update(header)

    def action_pause(self) -> None:
        self.paused = not self.paused
        self._dirty = True

    def action_sort(self) -> None:
        self.sort_received = not self.sort_received
        self._dirty = True

    def action_reset(self) -> None:
        self.totals.clear()
        self.recent.clear()
        self.events = 0
        self.since = time.time()
        self._dirty = True

    def set_find(self, needle: str) -> None:
        self.find = needle
        self._dirty = True


def _replace_rows(table: DataTable, rows: list) -> None:
    """new rows with the cursor kept where it was"""
    cursor = table.cursor_row
    table.clear()
    table.add_rows(rows)
    if rows:
        table.move_cursor(row=min(cursor, len(rows) - 1))
