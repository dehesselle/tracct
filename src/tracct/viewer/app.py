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
from textual.widgets import DataTable, Footer, Input, TabbedContent, TabPane
from textual.widgets.tabbed_content import ContentTabs

from tracct.query import QueryClient, QueryError
from tracct.viewer import TABS
from tracct.viewer.format import BYTE_UNITS
from tracct.viewer.history import HistoryPane
from tracct.viewer.live import LivePane
from tracct.viewer.pickers import UNZOOM, ByteUnitPicker, SpanPicker, Unzoom
from tracct.viewer.plot import TrafficPlot
from tracct.viewer.timerange import TimeRange

# a range that ends now is asked again this often while its tab is shown
REFRESH_SECONDS = 10.0


class TracctApp(ChordMixin, App):
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
        self.byte_unit = BYTE_UNITS[0]
        #: The byte unit before, which `u` pressed twice goes back to.
        self.last_byte_unit: str | None = None
        self._client = QueryClient(query_socket)
        self._client_lock = threading.Lock()

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
        # Tabs are switched by their letters or a click, so focus stays in the tab's
        # content.
        self.query_one(ContentTabs).can_focus = False
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

    def zoom_to(self, start: int, end: int) -> None:
        """Show the range a plot came to rest on, in every history tab."""
        self.time_range.zoom_to(start, end)
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
            SpanPicker(self.time_range.span, covered, self.time_range.zoom is not None),
            self._span_picked,
        )

    def _span_picked(self, span: int | Unzoom | None) -> None:
        if span is UNZOOM:
            self.time_range.unzoom()
            self.reload_active()
        elif isinstance(span, int) and self.time_range.pick(span):
            self.reload_active()

    def action_step_span(self, step: int) -> None:
        """Step the span back (-1) or forward (+1) by a whole span of local time."""
        if not self.time_range.steppable():
            self.notify(
                "pick a span with s first; all history has no earlier or later",
                timeout=3,
            )
            return
        self.time_range.step(step)
        self.reload_active()

    def action_byte_unit(self) -> None:
        self.push_screen(
            ByteUnitPicker(self.byte_unit, self.last_byte_unit),
            self._byte_unit_picked,
        )

    def _byte_unit_picked(self, byte_unit: str | None) -> None:
        if byte_unit is None or byte_unit == self.byte_unit:
            return
        self.last_byte_unit, self.byte_unit = self.byte_unit, byte_unit
        for plot in self.query(TrafficPlot):
            plot.set_byte_unit(self.byte_unit)
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
