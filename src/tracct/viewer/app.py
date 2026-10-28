# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The viewer app.

A live tab from events.sock and a history tab per source of the query server, sharing
one time range so a spike found in one tab can be taken apart in the next.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import ClassVar

from tcoda.chords import ChordMixin
from tcoda.dialogs import SettingsDialog
from tcoda.terminal_title import TerminalTitleMixin
from tcoda.widgets import ChordViewer
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.reactive import reactive
from textual.widgets import Footer, TabbedContent, TabPane
from textual.widgets.tabbed_content import ContentTabs

from tracct.query import QueryError
from tracct.viewer import TABS
from tracct.viewer.client import HistoryClient
from tracct.viewer.format import BYTE_UNITS
from tracct.viewer.history import HistoryPane
from tracct.viewer.live import LivePane
from tracct.viewer.model import SourceInfo
from tracct.viewer.pane import FindablePane
from tracct.viewer.pickers import UNZOOM, ByteUnitPicker, SpanPicker, Unzoom
from tracct.viewer.plot import TrafficPlot
from tracct.viewer.timerange import TimeRange

#: A range that ends now is asked again this often while its tab is shown.
REFRESH_SECONDS = 10.0


class TracctApp(TerminalTitleMixin, ChordMixin, App):
    TITLE = "tracct"
    TERMINAL_TITLE = "tracct"
    #: The tab bar takes no focus, so Textual's own would land in the first tab and
    #: switch to it; on_mount focuses the tab asked for instead.
    AUTO_FOCUS = None
    CSS_PATH = "app.tcss"
    BINDINGS: ClassVar[list[Binding]] = [
        # A tab's first letter, highlighted in its title.
        *(
            Binding(title[0].lower(), f"tab('{tab}')", show=False)
            for tab, (title, _) in TABS.items()
        ),
        # Chords start with a comma; the ChordViewer lists them when the next key is
        # slow to come.
        Binding("comma s", "settings", "settings", show=False),
    ]

    #: The range every history tab shows. It is changed in place, then announced with
    #: range_changed(); only the tab shown reloads, a hidden one when it is shown.
    time_range: reactive[TimeRange] = reactive(
        TimeRange, init=False, always_update=True
    )
    #: The unit the history tabs show bytes in; every tab redraws, no request needed.
    byte_unit: reactive[str] = reactive(BYTE_UNITS[0], init=False)
    #: Whether the history tabs give their whole area to the plot.
    plot_only: reactive[bool] = reactive(False, init=False)

    def __init__(
        self, events_socket: Path, query_socket: Path, tab: str = "processes"
    ) -> None:
        super().__init__()
        self.events_socket = events_socket
        self.initial_tab = tab
        #: The byte unit before, which `u` pressed twice goes back to.
        self.last_byte_unit: str | None = None
        self.client = HistoryClient(query_socket)

    def compose(self) -> ComposeResult:
        with TabbedContent(initial=self.initial_tab):
            for tab, (title, source) in TABS.items():
                with TabPane(f"[$accent bold]{title[0]}[/]{title[1:]}", id=tab):
                    yield (
                        LivePane(self.events_socket)
                        if source is None
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

    # ── the query server ──

    @work(thread=True, exclusive=True, group="describe")
    def describe(self) -> None:
        try:
            sources = self.client.describe()
        except QueryError as e:
            self.call_from_thread(self._describe_failed, str(e))
            return
        self.call_from_thread(self._described, sources)

    def _described(self, sources: dict[str, SourceInfo]) -> None:
        for pane in self.query(HistoryPane):
            if pane.source in sources:
                pane.configure(sources[pane.source])
        self.reload_active()

    def _describe_failed(self, message: str) -> None:
        for pane in self.query(HistoryPane):
            pane.show_error(message)

    # ── panes ──

    def active_pane(self) -> FindablePane | None:
        tab = self.query_one(TabbedContent).active_pane
        return None if tab is None else tab.query_one(FindablePane)

    def active_history(self) -> HistoryPane | None:
        pane = self.active_pane()
        return pane if isinstance(pane, HistoryPane) else None

    def reload_active(self) -> None:
        pane = self.active_history()
        if pane is not None:
            if pane.info is None:
                self.describe()
            pane.reload()

    def refresh_if_live(self) -> None:
        if self.time_range.ends_now():
            self.reload_active()

    def focus_pane(self) -> None:
        """Focus the shown tab's table, so its keys (filter, pause, ...) apply."""
        pane = self.active_pane()
        if pane is not None:
            pane.focus_content()

    def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated
    ) -> None:
        self.focus_pane()
        self.reload_active()

    def range_changed(self) -> None:
        """Announce a change made to time_range in place."""
        self.mutate_reactive(TracctApp.time_range)

    def watch_time_range(self) -> None:
        # Set before the app runs, there is no tab to reload yet.
        if self.is_running:
            self.reload_active()

    def on_plot_range_settled(self, event: TrafficPlot.RangeSettled) -> None:
        # Exactly what the plot shows, empty time included: the plot keeps its own
        # limits.
        start, end = event.x_range
        self.time_range.zoom_to(int(start), int(end))
        self.range_changed()

    # ── actions ──

    def action_tab(self, tab: str) -> None:
        self.query_one(TabbedContent).active = tab

    def action_span(self) -> None:
        """Pick the span from a list.

        One reload for the choice, none for the spans between.
        """
        pane = self.active_history()
        oldest = pane.info.oldest if pane is not None and pane.info else None
        covered = int(time.time()) - oldest if oldest else None
        self.push_screen(
            SpanPicker(self.time_range.span, covered, self.time_range.zoom is not None),
            self._span_picked,
        )

    def _span_picked(self, span: int | Unzoom | None) -> None:
        if span is UNZOOM:
            self.time_range.unzoom()
            self.range_changed()
        elif isinstance(span, int) and self.time_range.pick(span):
            self.range_changed()

    def action_step_span(self, step: int) -> None:
        """Step the span back (-1) or forward (+1) by a whole span of local time."""
        if not self.time_range.steppable():
            self.notify(
                "pick a span with s first; all history has no earlier or later",
                timeout=3,
            )
            return
        self.time_range.step(step)
        self.range_changed()

    def action_byte_unit(self) -> None:
        self.push_screen(
            ByteUnitPicker(self.byte_unit, self.last_byte_unit),
            self._byte_unit_picked,
        )

    def _byte_unit_picked(self, byte_unit: str | None) -> None:
        if byte_unit is None or byte_unit == self.byte_unit:
            return
        self.last_byte_unit, self.byte_unit = self.byte_unit, byte_unit

    def action_plot_only(self) -> None:
        self.plot_only = not self.plot_only

    def action_refresh(self) -> None:
        self.reload_active()

    def action_settings(self) -> None:
        self.push_screen(SettingsDialog())

    def on_unmount(self) -> None:
        self.client.close()
