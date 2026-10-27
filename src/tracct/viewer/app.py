# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""the viewer app: a live tab from events.sock and a history tab per source of the query
server, sharing one time range so a spike found in one tab can be taken apart in the next"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from textual import work
from textual.app import App
from textual.binding import Binding
from textual.widgets import DataTable, Footer, Input, TabbedContent, TabPane

from tracct.query import QueryClient, QueryError
from tracct.viewer.format import BYTE_UNITS, SPANS, moment
from tracct.viewer.history import HistoryPane
from tracct.viewer.live import LivePane
from tracct.viewer.timeline import Timeline

# tab id -> (title, query source)
TABS = {"live": ("Live", ""), "processes": ("Processes", "connections"), "interfaces": ("Interfaces", "interfaces"), "forwarded": ("Forwarded", "forwarded")}
# a range that ends now is asked again this often while its tab is shown
REFRESH_SECONDS = 10.0


def _aligned(now: int, seconds: int) -> int:
    """the start of the local-time period of length seconds (up to a day) holding now"""
    offset = time.localtime(now).tm_gmtoff
    return now - (now + offset) % min(seconds, 86400)


class TimeRange:
    """a span that ends now, a span stepped back into the past, or a range zoomed into from the
    timeline; zooms stack, so zooming out returns to the range before"""

    def __init__(self, span: int = 4) -> None:
        self.span = span
        self.back = 0
        self.zooms: list[tuple[int, int]] = []

    def bounds(self, now: int, oldest: int | None) -> tuple[int, int]:
        if self.zooms:
            return self.zooms[-1]
        seconds = SPANS[self.span][1]
        if seconds == 0:
            return (oldest or 0), now + 1
        if self.back == 0:
            return now - seconds, now + 1
        # back 1 is the last whole period, back 2 the one before
        end = _aligned(now, seconds) - (self.back - 1) * seconds
        return end - seconds, end

    def ends_now(self) -> bool:
        return not self.zooms and self.back == 0

    def label(self) -> str:
        if self.zooms:
            return "zoomed"
        name = SPANS[self.span][0]
        if self.back:
            return f"{name}, {self.back} back"
        return "all" if name == "all" else f"last {name}"


class ViewerApp(App):
    TITLE = "tracct"
    CSS = """
    #find { dock: bottom; display: none; }
    #find.shown { display: block; }
    """
    BINDINGS = [
        Binding("q", "quit", "quit"),
        Binding("question_mark", "show_help_panel", "keys"),
        Binding("1", "tab('live')", show=False),
        Binding("2", "tab('processes')", show=False),
        Binding("3", "tab('interfaces')", show=False),
        Binding("4", "tab('forwarded')", show=False),
        Binding("t", "span(1)", "span"),
        Binding("T", "span(-1)", show=False),
        Binding("h", "earlier(1)", "earlier"),
        Binding("H", "earlier(-1)", "later"),
        Binding("z", "zoom_out", "zoom out"),
        Binding("u", "units", "units"),
        Binding("r", "refresh", "refresh"),
        Binding("slash", "find", "find"),
        Binding("escape", "close_find", show=False),
    ]

    def __init__(self, events_socket: Path, query_socket: Path, tab: str = "processes") -> None:
        super().__init__()
        self.events_socket = events_socket
        self.query_socket = query_socket
        self.initial_tab = tab
        self.time_range = TimeRange()
        self.unit = BYTE_UNITS[0]
        self._client = QueryClient(query_socket)
        self._client_lock = threading.Lock()
        self.sources: dict = {}

    def compose(self):
        with TabbedContent(initial=self.initial_tab):
            for tab, (title, source) in TABS.items():
                with TabPane(title, id=tab):
                    yield LivePane(self.events_socket) if not source else HistoryPane(source)
        yield Input(id="find", placeholder="find in the rows shown (Enter keeps it, Escape clears)")
        yield Footer()

    def on_mount(self) -> None:
        self.describe()
        self.set_interval(REFRESH_SECONDS, self.refresh_if_live)

    # ── the query server ────────────────────────────────────────────

    def ask(self, op: str, **params: object) -> dict:
        """a request to the query server, from a worker thread"""
        with self._client_lock:
            try:
                return self._client.request(op, **params)
            except PermissionError as e:
                raise QueryError(f"no access to {self.query_socket}: join the viewer group (tracct-viewer) or run as root") from e
            except OSError as e:
                raise QueryError(f"query server unavailable at {self.query_socket} ({e.strerror or e}); is tracct-query.socket enabled?") from e

    @work(thread=True, exclusive=True, group="describe")
    def describe(self) -> None:
        try:
            sources = self.ask("describe")["sources"]
        except QueryError as e:
            self.call_from_thread(self._describe_failed, str(e))
            return
        self.call_from_thread(self._described, sources)

    def _described(self, sources: dict) -> None:
        self.sources = sources
        for pane in self.query(HistoryPane):
            if pane.source in sources:
                pane.configure(sources[pane.source])
        self.reload_active()

    def _describe_failed(self, message: str) -> None:
        for pane in self.query(HistoryPane):
            pane.show_error(message)

    # ── panes ───────────────────────────────────────────────────────

    def active_pane(self) -> HistoryPane | LivePane | None:
        active = self.query_one(TabbedContent).active
        for pane in [*self.query(HistoryPane), *self.query(LivePane)]:
            if pane.parent is not None and pane.parent.id == active:
                return pane
        return None

    def active_history(self) -> HistoryPane | None:
        pane = self.active_pane()
        return pane if isinstance(pane, HistoryPane) else None

    def reload_active(self) -> None:
        pane = self.active_history()
        if pane is not None:
            if not pane.info:
                self.describe()
            pane.reload()

    def refresh_if_live(self) -> None:
        if self.time_range.ends_now():
            self.reload_active()

    def focus_pane(self) -> None:
        """focus the shown tab's table, so its keys (filter, pause, ...) apply"""
        pane = self.active_pane()
        if pane is not None:
            pane.query(DataTable).first().focus()

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        pane = self.active_pane()
        find = self.query_one("#find", Input)
        if pane is not None:
            find.value = pane.find
        self.focus_pane()
        self.reload_active()

    def zoom(self, start: int, end: int) -> None:
        self.time_range.zooms.append((start, end))
        self.notify(f"zoomed to {moment(start)} to {moment(end)}; z zooms out", timeout=3)
        self.reload_active()

    # ── actions ─────────────────────────────────────────────────────

    def action_tab(self, tab: str) -> None:
        self.query_one(TabbedContent).active = tab

    def action_span(self, delta: int) -> None:
        self.time_range.span = (self.time_range.span + delta) % len(SPANS)
        self.time_range.back = 0
        self.time_range.zooms.clear()
        self.reload_active()

    def action_earlier(self, delta: int) -> None:
        if SPANS[self.time_range.span][1] == 0:
            self.notify("pick a span with t first; all has no earlier or later", timeout=3)
            return
        self.time_range.zooms.clear()
        self.time_range.back = max(0, self.time_range.back + delta)
        self.reload_active()

    def action_zoom_out(self) -> None:
        if self.time_range.zooms:
            self.time_range.zooms.pop()
            self.reload_active()

    def action_units(self) -> None:
        self.unit = BYTE_UNITS[(BYTE_UNITS.index(self.unit) + 1) % len(BYTE_UNITS)]
        for timeline in self.query(Timeline):
            timeline.unit = self.unit
            timeline.refresh()
        for pane in self.query(HistoryPane):
            if pane.result:
                pane.render_rows()
        self.notify(f"bytes in {self.unit}", timeout=2)

    def action_refresh(self) -> None:
        self.reload_active()

    def action_find(self) -> None:
        find = self.query_one("#find", Input)
        find.add_class("shown")
        find.focus()

    def action_close_find(self) -> None:
        find = self.query_one("#find", Input)
        if find.has_class("shown"):
            find.value = ""
            self._set_find("")
            find.remove_class("shown")
            self.focus_pane()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "find":
            self._set_find(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "find":
            event.input.remove_class("shown")
            self.focus_pane()

    def _set_find(self, needle: str) -> None:
        pane = self.active_pane()
        if pane is not None:
            pane.set_find(needle)

    def on_unmount(self) -> None:
        self._client.close()
