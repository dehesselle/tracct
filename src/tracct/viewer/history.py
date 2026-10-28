# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""a history tab: one source of the query server, grouped by one dimension, narrowed by a stack
of filters, over the viewer's time range, with the plot of the highlighted row"""

from __future__ import annotations

import dataclasses
import time
from typing import TYPE_CHECKING

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, OptionList
from textual.widgets.option_list import Option
from textual.worker import get_current_worker

from tracct.query import QueryError
from tracct.viewer.banner import Banner
from tracct.viewer.format import (
    bytes_cell,
    format_time,
    format_value,
    value_cell,
)
from tracct.viewer.pane import FindablePane
from tracct.viewer.plot import PEAK_SECONDS, TrafficPlot
from tracct.viewer.timerange import bucket_grid

if TYPE_CHECKING:
    from tracct.viewer.app import TracctApp

# rows asked for per request; the table's title says when there are more
ROWS = 1000
# how long the highlight has to rest on a row before its timeline is asked for
TIMELINE_DELAY_SECONDS = 0.25
# how long a fetch has to take before the plot's title says so; most answer within
# milliseconds, and the glyph would flicker on every refresh
BUSY_DELAY_SECONDS = 0.3


@dataclasses.dataclass(frozen=True)
class Total:
    """The value of a row of sums over all rows.

    There is one per layer where the source has layers, which are never added up, else
    one, whose layer is None.
    """

    layer: str | None

    def label(self) -> str:
        return f"(all · {self.layer})" if self.layer else "(all)"


class HistoryPane(FindablePane):
    DEFAULT_CSS = """
    HistoryPane OptionList { width: 30; height: 1fr; }
    HistoryPane DataTable { height: 1fr; }
    """
    BINDINGS = [
        # the time range and units are the app's, shared by the history tabs
        # the picker's s again returns from a zoom to the span
        Binding("s", "app.span", "span"),
        # by a whole span of local time, next to s that picks its length; the range is the tab's,
        # not only the plot's, whose arrows pan by a few columns
        Binding(
            "shift+left",
            "app.step_span(-1)",
            "previous span",
            key_display="⇧←",
            group=Binding.Group("step span"),
        ),
        Binding(
            "shift+right",
            "app.step_span(1)",
            "next span",
            key_display="⇧→",
            group=Binding.Group("step span"),
        ),
        Binding("u", "app.byte_unit", "unit"),
        Binding("r", "app.refresh", "refresh"),
        # the drill-down: a filter on the highlighted row's value stays when the dimension on the
        # left changes, which breaks that value down
        Binding("comma f i", "filter(False)", "include row", show=False),
        Binding("comma f e", "filter(True)", "exclude row", show=False),
        Binding("comma f p", "pop_filter", "pop last", show=False),
        Binding("comma f c", "clear_filters", "clear", show=False),
    ]
    CHORD_GROUPS = {"comma f": "filter"}

    def __init__(self, source: str, *, id: str | None = None) -> None:
        super().__init__(id=id)
        self.source = source
        self.info: dict = {}
        self.group_by = ""
        # (dimension, value, exclude), applied in order
        self.filters: list[tuple[str, object, bool]] = []
        self.rows: list[list] = []
        # the rows of values shown, and the table's rows: the sums over all of them first
        self.shown: list[list] = []
        self.table_rows: list[list] = []
        self.result: dict = {}
        self.error = ""
        self._timeline_timer = None
        # the row the plot was last asked for, so refilling the table does not ask again
        self._plot_filter: tuple[str, object] | None = None
        # what is being fetched, "rows" and "plot", and the timer that then marks the plot busy
        self._fetching: set[str] = set()
        self._busy_timer = None
        self._configured = False

    @property
    def viewer(self) -> TracctApp:
        return self.app

    def compose_content(self) -> ComposeResult:
        with Horizontal():
            yield OptionList(id="dimensions")
            with Vertical():
                yield TrafficPlot()
                yield DataTable(cursor_type="row", zebra_stripes=True)

    def configure(self, info: dict) -> None:
        """the source's dimensions and covered time, from describe"""
        self.info = info
        if self._configured:
            return
        self._configured = True
        self.group_by = info["default"]
        options = self.query_one(OptionList)
        options.clear_options()
        options.add_options(
            [
                Option(label + (" (raw only)" if raw_only else ""), id=name)
                for name, label, raw_only in info["dimensions"]
            ]
        )
        options.highlighted = next(
            (
                i
                for i, (name, _, _) in enumerate(info["dimensions"])
                if name == self.group_by
            ),
            0,
        )

    def labels(self) -> dict[str, str]:
        return {name: label for name, label, _ in self.info.get("dimensions", [])}

    # ── requests ─────────────────────────────────────────────────────

    def bounds(self) -> tuple[int, int]:
        return self.viewer.time_range.bounds(int(time.time()), self.info.get("oldest"))

    def highlighted(self) -> object:
        """the value of the highlighted row, a Total for a row of sums, or None without rows"""
        table = self.query_one(DataTable)
        return (
            self.table_rows[table.cursor_row][0]
            if 0 <= table.cursor_row < len(self.table_rows)
            else None
        )

    def plot_filter(self) -> tuple[str, object] | None:
        """the filter that narrows the plot to the highlighted row, or None for all rows"""
        value = self.highlighted()
        if isinstance(value, Total):
            return (self.result["totals_by"], value.layer) if value.layer else None
        return None if value is None else (self.group_by, value)

    def reload(self) -> None:
        if not self.info:
            return
        start, end = self.bounds()
        self.fetching("rows", True)
        self._load(start, end, list(self.filters), self.group_by)

    @work(thread=True, exclusive=True, group="history-table")
    def _load(self, start: int, end: int, filters: list, group_by: str) -> None:
        worker = get_current_worker()
        try:
            result = self.viewer.client.ask(
                "aggregate",
                source=self.source,
                group_by=group_by,
                filters=[list(f) for f in filters],
                start=start,
                end=end,
                limit=ROWS,
            )
        except QueryError as e:
            if not worker.is_cancelled:
                self.app.call_from_thread(self.show_error, str(e))
            return
        if not worker.is_cancelled:
            self.app.call_from_thread(self.show_rows, result)

    def load_timeline(self) -> None:
        if not self.info:
            self.fetching("plot", False)
            return
        self.fetching("plot", True)
        start, end = self.bounds()
        origin, step = bucket_grid(start, end, self.query_one(TrafficPlot).points())
        plot_filter = self._plot_filter = self.plot_filter()
        filters = [list(f) for f in self.filters] + (
            [[plot_filter[0], plot_filter[1], False]] if plot_filter else []
        )
        value = self.highlighted()
        if isinstance(value, Total) or plot_filter is None:
            row_label = (
                value.label() if isinstance(value, Total) else Total(None).label()
            )
        else:
            dimension, filtered = plot_filter
            row_label = (
                f"{self.labels().get(dimension, dimension)}"
                f" = {format_value(dimension, filtered)}"
            )
        self._load_timeline(
            start,
            end,
            origin,
            step,
            filters,
            row_label,
            self.viewer.time_range.heading(start, end),
        )

    @work(thread=True, exclusive=True, group="history-timeline")
    def _load_timeline(
        self,
        start: int,
        end: int,
        origin: int,
        step: int,
        filters: list,
        row_label: str,
        heading: str,
    ) -> None:
        worker = get_current_worker()
        try:
            result = self.viewer.client.ask(
                "timeline",
                source=self.source,
                filters=filters,
                start=origin,
                end=end,
                step=step,
                peak=PEAK_SECONDS,
            )
        except QueryError as e:
            if not worker.is_cancelled:
                self.app.call_from_thread(self.show_error, str(e))
            return
        if not worker.is_cancelled:
            value_labels = tuple(self.info.get("values", ["sent", "received"]))
            self.app.call_from_thread(
                self.show_timeline,
                start,
                end,
                origin,
                step,
                result,
                heading,
                row_label,
                value_labels,
            )

    def schedule_timeline(self) -> None:
        if self._timeline_timer is not None:
            self._timeline_timer.stop()
        self._timeline_timer = self.set_timer(
            TIMELINE_DELAY_SECONDS, self.load_timeline
        )

    def fetching(self, what: str, active: bool) -> None:
        """the plot's title says the tab is updating while its rows or its plot are being fetched,
        from BUSY_DELAY_SECONDS on; until the rows are in, the plot waits to be fetched after them"""
        if active:
            self._fetching.add(what)
        else:
            self._fetching.discard(what)
        if self._fetching and self._busy_timer is None:
            self._busy_timer = self.set_timer(BUSY_DELAY_SECONDS, self._show_busy)
        elif not self._fetching:
            if self._busy_timer is not None:
                self._busy_timer.stop()
                self._busy_timer = None
            self.query_one(TrafficPlot).set_busy(False)

    def _show_busy(self) -> None:
        self._busy_timer = None
        if self._fetching:
            self.query_one(TrafficPlot).set_busy(True)

    # ── showing results ─────────────────────────────────────────────

    def show_timeline(
        self,
        start: int,
        end: int,
        origin: int,
        step: int,
        result: dict,
        heading: str,
        row_label: str,
        value_labels: tuple[str, str],
    ) -> None:
        self.fetching("plot", False)
        self.query_one(TrafficPlot).show(
            start,
            end,
            origin,
            step,
            result["peak"],
            result["split"],
            result["buckets"],
            heading,
            row_label,
            value_labels,
        )

    def show_error(self, message: str) -> None:
        self.fetching("rows", False)
        self.fetching("plot", False)
        self.error = message
        self.update_banner()

    def show_rows(self, result: dict) -> None:
        self.error = ""
        self.result = result
        self.rows = result["rows"]
        self.render_rows()
        # at once: the rows that came in are the plot's too, and the highlight has not moved
        self.load_timeline()
        # after the plot is asked for, so the title does not drop the glyph in between
        self.fetching("rows", False)

    def render_rows(self) -> None:
        table = self.query_one(DataTable)
        previous = self.highlighted()
        needle = self.find.lower()
        self.shown = (
            [
                row
                for row in self.rows
                if needle in format_value(self.group_by, row[0]).lower()
            ]
            if needle
            else self.rows
        )
        # the sums come from all rows, so a find, which hides some, hides them too; grouped by
        # the layer, the rows are the sums already
        totals = []
        if not needle and self.result and self.group_by != self.result["totals_by"]:
            totals = [
                [Total(layer), out_bytes, in_bytes]
                for layer, out_bytes, in_bytes in self.result["parts"]
            ]
        self.table_rows = totals + self.shown
        byte_unit = self.viewer.byte_unit
        out_label, in_label = self.info.get("values", ["sent", "received"])
        table.clear(columns=True)
        table.add_column(self.labels().get(self.group_by, self.group_by), key="value")
        table.add_column(Text(out_label, justify="right"), key="out")
        table.add_column(Text(in_label, justify="right"), key="in")
        table.add_rows(
            [
                (
                    _value_cell(self.group_by, value),
                    bytes_cell(out_bytes, byte_unit),
                    bytes_cell(in_bytes, byte_unit),
                )
                for value, out_bytes, in_bytes in self.table_rows
            ]
        )
        # keep the highlight on the same value across refreshes; a sum only if it was on one, as
        # sums add up what is otherwise kept apart
        index = next(
            (i for i, row in enumerate(self.table_rows) if row[0] == previous),
            len(totals) if self.shown else 0,
        )
        if self.table_rows:
            table.move_cursor(row=index)
        self.update_banner()
        self.update_status()

    def update_banner(self) -> None:
        """a problem, the filters and a kept find, as on the live tab; nothing to say, no banner"""
        notes, keys = [], []
        if self.error:
            notes.append(self.error)
        if self.filters:
            labels = self.labels()
            notes.append(
                "filter: "
                + " > ".join(
                    f"{'!' if exclude else ''}{labels.get(dimension, dimension)}={format_value(dimension, value)}"
                    for dimension, value, exclude in self.filters
                )
            )
            keys.append(", f c to clear filters")
        # while the find input is open, it says it already
        if self.find and not self.find_open():
            notes.append(f"find: {self.find}")
            keys.insert(0, "c to clear")
        self.query_one(Banner).say(
            notes, f"press {' · '.join(keys)}" if keys else "", error=bool(self.error)
        )

    def update_status(self) -> None:
        """the table's borders: its title counts the rows only while some are not shown, its
        bottom border says where the range meets the rollups"""
        table = self.query_one(DataTable)
        result = self.result
        title = subtitle = ""
        if result:
            if self.find or result["truncated"]:
                title = f"{len(self.shown)} of {result['groups']} rows"
            if result["clipped"]:
                subtitle = f"raw rows only: from {format_time(result['start'])}"
            elif result["start"] < result["split"]:
                subtitle = f"rollups before {format_time(result['split'])}: no addresses, ephemeral ports as 0"
        table.border_title = title
        table.border_subtitle = subtitle

    # ── events and keys ──────────────────────────────────────────────

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        if event.option.id and event.option.id != self.group_by:
            self.group_by = event.option.id
            self.reload()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        # refilling the table highlights the row again; only another row needs another plot
        if self.plot_filter() != self._plot_filter:
            self.schedule_timeline()

    def on_plot_range_settled(self, event: TrafficPlot.RangeSettled) -> None:
        # exactly what the plot shows, empty time included: the plot keeps its own limits
        start, end = event.x_range
        self.viewer.zoom_to(int(start), int(end))

    def action_filter(self, exclude: bool) -> None:
        # a row of sums has no value of the dimension to keep or exclude
        value = self.highlighted()
        if value is None or isinstance(value, Total):
            return
        self.filters.append((self.group_by, value, exclude))
        self.reload()

    def action_pop_filter(self) -> None:
        if self.filters:
            dimension, _, _ = self.filters.pop()
            self.select_dimension(dimension)
            self.reload()

    def action_clear_filters(self) -> None:
        # back to where the drill-down started
        if self.filters:
            dimension, _, _ = self.filters[0]
            self.filters.clear()
            self.select_dimension(dimension)
            self.reload()

    def select_dimension(self, dimension: str) -> None:
        options = self.query_one(OptionList)
        for i, (name, _, _) in enumerate(self.info.get("dimensions", [])):
            if name == dimension:
                self.group_by = dimension
                options.highlighted = i

    def apply_find(self) -> None:
        if self.result:
            self.render_rows()


def _value_cell(dimension: str, value: object) -> Text:
    """a row of sums dim like a missing value, so it is not taken for a value of the dimension"""
    return (
        Text(value.label(), style="dim")
        if isinstance(value, Total)
        else value_cell(dimension, value)
    )
