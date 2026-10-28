# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""the viewer app: a live tab from events.sock and a history tab per source of the query
server, sharing one time range so a spike found in one tab can be taken apart in the next"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from tcoda.chords import ChordMixin
from tcoda.dialogs import SettingsDialog
from tcoda.widgets import ChordViewer
from textual import work
from textual.app import App
from textual.binding import Binding
from textual.widgets import DataTable, Footer, Input, TabbedContent, TabPane, Tabs

from tracct.query import QueryClient, QueryError
from tracct.viewer import TABS
from tracct.viewer.format import BYTE_UNITS, SPANS
from tracct.viewer.history import HistoryPane
from tracct.viewer.live import LivePane
from tracct.viewer.pickers import TO_SPAN, SpanPicker, UnitPicker
from tracct.viewer.plot import TrafficPlot

# a range that ends now is asked again this often while its tab is shown
REFRESH_SECONDS = 10.0


def _aligned(now: int, seconds: int) -> int:
    """the start of the local-time period of length seconds (up to a day) holding now"""
    offset = time.localtime(now).tm_gmtoff
    return now - (now + offset) % min(seconds, 86400)


class TimeRange:
    """a span that ends now, a span stepped back into the past, or the range a plot was zoomed or
    panned to; zooming out returns to the span"""

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
        return "all history" if name == "all" else f"last {name}"


class ViewerApp(ChordMixin, App):
    TITLE = "tracct"
    # the tab bar takes no focus, so Textual's own would land in the first tab and switch to it;
    # on_mount focuses the tab asked for instead
    AUTO_FOCUS = None
    CSS = """
    /* a gray a little dimmer than an inactive tab's, so the titles in the border stay readable */
    TabPane DataTable, TabPane OptionList { border: round $foreground 40%; }
    TabPane DataTable:focus, TabPane OptionList:focus { border: round $accent; }
    .find { display: none; }
    .find.shown { display: block; }
    """
    BINDINGS = [
        # a tab's first letter, highlighted in its title
        *(
            Binding(title[0].lower(), f"tab('{tab}')", show=False)
            for tab, (title, _) in TABS.items()
        ),
        Binding("slash", "find", "find"),
        # the banner says so while a find is kept
        Binding("c", "clear_find", "clear find", show=False),
        # chords start with a comma; the ChordViewer lists them when the next key is slow to come
        Binding("comma s", "settings", "settings", show=False),
        Binding("escape", "close_find", show=False),
    ]

    def __init__(
        self, events_socket: Path, query_socket: Path, tab: str = "processes"
    ) -> None:
        super().__init__()
        self.events_socket = events_socket
        self.query_socket = query_socket
        self.initial_tab = tab
        self.time_range = TimeRange()
        self.unit = BYTE_UNITS[0]
        # the unit before, which u pressed twice goes back to
        self.last_unit: str | None = None
        self._client = QueryClient(query_socket)
        self._client_lock = threading.Lock()
        self.sources: dict = {}

    def compose(self):
        with TabbedContent(initial=self.initial_tab):
            for tab, (title, source) in TABS.items():
                with TabPane(f"[$accent bold]{title[0]}[/]{title[1:]}", id=tab):
                    yield (
                        LivePane(self.events_socket)
                        if not source
                        else HistoryPane(source)
                    )
        yield Footer(show_command_palette=False)
        yield ChordViewer()

    def on_mount(self) -> None:
        # tabs are switched by their letters or a click; focus stays in the tab's content
        self.query_one(TabbedContent).query_one(Tabs).can_focus = False
        self.focus_pane()
        self.describe()
        self.set_interval(REFRESH_SECONDS, self.refresh_if_live)

    # ── the query server ────────────────────────────────────────────

    def ask(self, op: str, **params: object) -> dict:
        """a request to the query server, from a worker thread"""
        with self._client_lock:
            try:
                return self._client.request(op, **params)
            except PermissionError as e:
                raise QueryError(
                    f"no access to {self.query_socket}: join the viewer group (tracct-viewer) or run as root"
                ) from e
            except OSError as e:
                raise QueryError(
                    f"query server unavailable at {self.query_socket} ({e.strerror or e}); is tracct-query.socket enabled?"
                ) from e

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

    def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated
    ) -> None:
        self.focus_pane()
        self.reload_active()

    def view(self, start: int, end: int) -> None:
        """the range a plot came to rest on, which every history tab then shows"""
        if self.time_range.zooms:
            self.time_range.zooms[-1] = (start, end)
        else:
            self.time_range.zooms.append((start, end))
        self.reload_active()

    # ── actions ─────────────────────────────────────────────────────

    def action_tab(self, tab: str) -> None:
        self.query_one(TabbedContent).active = tab

    def action_span(self) -> None:
        """pick the span from a list: one reload for the choice, none for the spans between"""
        pane = self.active_history()
        oldest = pane.info.get("oldest") if pane is not None else None
        covered = int(time.time()) - oldest if oldest else None
        self.push_screen(
            SpanPicker(self.time_range.span, covered, bool(self.time_range.zooms)),
            self._span_picked,
        )

    def _span_picked(self, span: int | None) -> None:
        if span == TO_SPAN:
            # back from the zoom to the span, stepped back as it was
            self.time_range.zooms.clear()
            self.reload_active()
            return
        # the span picked again still ends a step back or a zoom, as it did when cycled to
        if span is None or (
            span == self.time_range.span and self.time_range.ends_now()
        ):
            return
        self.time_range.span = span
        self.time_range.back = 0
        self.time_range.zooms.clear()
        self.reload_active()

    def action_earlier(self, delta: int) -> None:
        if SPANS[self.time_range.span][1] == 0:
            self.notify(
                "pick a span with s first; all history has no earlier or later",
                timeout=3,
            )
            return
        self.time_range.zooms.clear()
        self.time_range.back = max(0, self.time_range.back + delta)
        self.reload_active()

    def action_units(self) -> None:
        self.push_screen(UnitPicker(self.unit, self.last_unit), self._unit_picked)

    def _unit_picked(self, unit: str | None) -> None:
        if unit is None or unit == self.unit:
            return
        self.last_unit, self.unit = self.unit, unit
        for plot in self.query(TrafficPlot):
            plot.set_unit(self.unit)
        for pane in self.query(HistoryPane):
            if pane.result:
                pane.render_rows()

    def action_refresh(self) -> None:
        self.reload_active()

    def action_settings(self) -> None:
        self.push_screen(SettingsDialog())

    def action_find(self) -> None:
        """each tab has its own find input, on its top line, where a banner shows a kept find"""
        pane = self.active_pane()
        if pane is not None:
            find = pane.query_one(".find", Input)
            find.value = pane.find
            find.add_class("shown")
            find.focus()
            pane.update_banner()

    def action_close_find(self) -> None:
        pane = self.active_pane()
        if pane is not None:
            find = pane.query_one(".find", Input)
            if find.has_class("shown"):
                find.value = ""
                pane.set_find("")
                find.remove_class("shown")
                pane.update_banner()
                self.focus_pane()

    def action_clear_find(self) -> None:
        pane = self.active_pane()
        if pane is not None and pane.find:
            pane.query_one(".find", Input).value = ""
            pane.set_find("")

    def on_input_changed(self, event: Input.Changed) -> None:
        pane = event.input.parent
        if event.input.has_class("find") and isinstance(pane, HistoryPane | LivePane):
            pane.set_find(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        pane = event.input.parent
        if event.input.has_class("find") and isinstance(pane, HistoryPane | LivePane):
            event.input.remove_class("shown")
            # a kept find goes to the banner, on the line the input leaves
            pane.update_banner()
            self.focus_pane()

    def on_unmount(self) -> None:
        self._client.close()
