# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""A history tab.

One source of the query server, grouped by one dimension, narrowed by a stack of
filters, over the viewer's time range, with the plot of the highlighted row.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, ClassVar

from rich.text import Text
from tcoda.widgets import DataTable
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import OptionList
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
from tracct.viewer.model import ALL, Aggregate, Filter, Row, SourceInfo, Timeline, Total
from tracct.viewer.pane import FindablePane
from tracct.viewer.plot import PEAK_SECONDS, TrafficPlot
from tracct.viewer.timerange import bucket_grid

if TYPE_CHECKING:
    from tracct.viewer.app import TracctApp

#: Rows asked for per request; the table's title says when there are more.
ROWS = 1000
#: How long the highlight has to rest on a row before its timeline is asked for.
TIMELINE_DELAY_SECONDS = 0.25
#: How long a fetch has to take before the plot's title says so; most answer within
#: milliseconds, and the glyph would flicker on every refresh.
BUSY_DELAY_SECONDS = 0.3


def _value_cell(dimension: str, value: object) -> Text:
    """Return a cell of the value column; a row of sums dim like a missing value.

    So a row of sums is not taken for a value of the dimension.
    """
    return (
        Text(value.label(), style="dim")
        if isinstance(value, Total)
        else value_cell(dimension, value)
    )


class HistoryPane(FindablePane):
    BINDINGS: ClassVar[list[Binding]] = [
        # The time range and the byte unit are the app's, shared by the history tabs.
        # In the span picker, s pressed again returns from a zoom to the span.
        Binding("s", "app.span", "Span"),
        # By a whole span of local time, next to s that picks its length; the range is
        # the tab's, not only the plot's, whose arrows pan by a few columns.
        Binding(
            "shift+left",
            "app.step_span(-1)",
            "Previous span",
            key_display="⇧←",
            group=Binding.Group("Step span"),
        ),
        Binding(
            "shift+right",
            "app.step_span(1)",
            "Next span",
            key_display="⇧→",
            group=Binding.Group("Step span"),
        ),
        Binding("u", "app.byte_unit", "Unit"),
        Binding("r", "app.refresh", "Refresh"),
        # The drill-down: a filter on the highlighted row's value stays when the
        # dimension on the left changes, which breaks that value down.
        Binding("comma f i", "filter(False)", "Include row", show=False),
        Binding("comma f e", "filter(True)", "Exclude row", show=False),
        Binding("comma f p", "pop_filter", "Pop last", show=False),
        Binding("comma f c", "clear_filters", "Clear", show=False),
        # Shared by the history tabs, as the range is.
        Binding("comma p", "app.plot_only", "Plot only", show=False),
    ]
    CHORD_GROUPS: ClassVar[dict[str, str]] = {"comma f": "Filter"}

    #: Whether the rows are being fetched, and whether the plot is.
    rows_loading: reactive[bool] = reactive(False, init=False)
    plot_loading: reactive[bool] = reactive(False, init=False)

    def __init__(self, source: str, *, id: str | None = None) -> None:
        super().__init__(id=id)
        self.source = source
        self.info: SourceInfo | None = None
        self.group_by = ""
        #: Applied in order: the drill-down so far.
        self.filters: list[Filter] = []
        self.result: Aggregate | None = None
        #: The rows in the table: the sums over all values first, then the values the
        #: find leaves.
        self.table_rows: list[Row] = []
        self.error = ""
        self._timeline_timer = None
        #: The row the plot was last asked for, so refilling the table does not ask
        #: again.
        self._plot_filter: Filter | None = None
        #: Marks the plot busy once a fetch has taken a moment.
        self._busy_timer = None

    def on_mount(self) -> None:
        self.watch(self.viewer, "byte_unit", self._show_byte_unit, init=False)
        self.watch(self.viewer, "plot_only", self._show_plot_only, init=False)

    def _show_byte_unit(self, byte_unit: str) -> None:
        self.query_one(TrafficPlot).set_byte_unit(byte_unit)
        self.render_rows()

    def _show_plot_only(self, plot_only: bool) -> None:
        """Hide the dimensions and the table, or show them again; app.tcss says how.

        Only the tab shown takes the focus and asks for a plot as wide as it is now; a
        hidden one asks when it is shown.
        """
        self.set_class(plot_only, "-plot-only")
        if self.viewer.active_pane() is self:
            self.focus_content()
            self.schedule_timeline()

    def focus_content(self) -> None:
        # Showing only the plot, focus it, so its keys pan and zoom.
        if self.has_class("-plot-only"):
            self.query_one(TrafficPlot).focus()
        else:
            super().focus_content()

    @property
    def viewer(self) -> TracctApp:
        return self.app

    def compose_content(self) -> ComposeResult:
        with Horizontal():
            dimensions = OptionList(id="dimensions")
            dimensions.border_title = "group by"
            yield dimensions
            with Vertical():
                yield TrafficPlot()
                # tcoda's, for the same look as the live tab's; its columns do not sort,
                # as the query server orders the rows, largest first.
                yield DataTable(cursor_type="row", zebra_stripes=True)

    def configure(self, info: SourceInfo) -> None:
        """Take the source's dimensions and covered time from describe."""
        first = self.info is None
        self.info = info
        if not first:
            return
        self.group_by = info.default
        options = self.query_one(OptionList)
        options.clear_options()
        options.add_options(
            [
                Option(d.label + (" (raw only)" if d.raw_only else ""), id=d.name)
                for d in info.dimensions
            ]
        )
        options.highlighted = info.dimension_index(self.group_by) or 0

    def shown(self) -> list[Row]:
        """The rows of values in the table, without the sums."""
        return [row for row in self.table_rows if not isinstance(row.value, Total)]

    # ── requests ──

    def bounds(self) -> tuple[int, int]:
        oldest = self.info.oldest if self.info is not None else None
        return self.viewer.time_range.bounds(int(time.time()), oldest)

    def highlighted(self) -> object:
        """Return the highlighted row's value: a Total for a row of sums, else None.

        None also when the table has no rows.
        """
        table = self.query_one(DataTable)
        return (
            self.table_rows[table.cursor_row].value
            if 0 <= table.cursor_row < len(self.table_rows)
            else None
        )

    def plot_filter(self) -> Filter | None:
        """Return the filter that narrows the plot to the highlighted row.

        None draws all rows.
        """
        value = self.highlighted()
        if isinstance(value, Total):
            if value.layer is None or self.result is None:
                return None
            return Filter(self.result.layers_by, value.layer)
        return None if value is None else Filter(self.group_by, value)

    def reload(self) -> None:
        if self.info is None:
            return
        start, end = self.bounds()
        self.rows_loading = True
        self._load(start, end, list(self.filters), self.group_by)

    @work(thread=True, exclusive=True, group="history-table")
    def _load(self, start: int, end: int, filters: list[Filter], group_by: str) -> None:
        worker = get_current_worker()
        try:
            result = self.viewer.client.aggregate(
                self.source, group_by, filters, start, end, ROWS
            )
        except QueryError as e:
            if not worker.is_cancelled:
                self.viewer.call_from_thread(self.show_error, str(e))
            return
        if not worker.is_cancelled:
            self.viewer.call_from_thread(self.show_rows, result)

    def load_timeline(self) -> None:
        if self.info is None:
            self.plot_loading = False
            return
        self.plot_loading = True
        start, end = self.bounds()
        origin, step = bucket_grid(start, end, self.query_one(TrafficPlot).points())
        plot_filter = self._plot_filter = self.plot_filter()
        filters = self.filters + ([plot_filter] if plot_filter else [])
        value = self.highlighted()
        if isinstance(value, Total):
            row_label = value.label()
        elif plot_filter is None:
            row_label = ALL
        else:
            row_label = (
                f"{self.info.dimension_label(plot_filter.dimension)}"
                f" = {format_value(plot_filter.dimension, plot_filter.value)}"
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
        filters: list[Filter],
        row_label: str,
        heading: str,
    ) -> None:
        worker = get_current_worker()
        try:
            timeline = self.viewer.client.timeline(
                self.source, filters, start, end, origin, step, PEAK_SECONDS
            )
        except QueryError as e:
            if not worker.is_cancelled:
                self.viewer.call_from_thread(self.show_error, str(e))
            return
        if not worker.is_cancelled:
            self.viewer.call_from_thread(
                self.show_timeline, timeline, heading, row_label
            )

    def schedule_timeline(self) -> None:
        if self._timeline_timer is not None:
            self._timeline_timer.stop()
        self._timeline_timer = self.set_timer(
            TIMELINE_DELAY_SECONDS, self.load_timeline
        )

    # ── whether the tab is updating ──

    def loading(self) -> bool:
        return self.rows_loading or self.plot_loading

    def watch_rows_loading(self) -> None:
        self._loading_changed()

    def watch_plot_loading(self) -> None:
        self._loading_changed()

    def _loading_changed(self) -> None:
        """The plot's title says the tab is updating, from BUSY_DELAY_SECONDS on."""
        if self.loading():
            if self._busy_timer is None:
                self._busy_timer = self.set_timer(BUSY_DELAY_SECONDS, self._show_busy)
        else:
            # Once the current message is handled: rows that just came in ask for their
            # plot right after, and the glyph stays on through both.
            self.call_later(self._settle_busy)

    def _show_busy(self) -> None:
        self._busy_timer = None
        if self.loading():
            self.query_one(TrafficPlot).set_busy(True)

    def _settle_busy(self) -> None:
        if self.loading():
            return
        if self._busy_timer is not None:
            self._busy_timer.stop()
            self._busy_timer = None
        self.query_one(TrafficPlot).set_busy(False)

    # ── showing results ──

    def show_timeline(self, timeline: Timeline, heading: str, row_label: str) -> None:
        self.plot_loading = False
        if self.info is None:
            return
        self.query_one(TrafficPlot).show(
            timeline,
            heading=heading,
            row_label=row_label,
            value_labels=self.info.value_labels,
        )

    def show_error(self, message: str) -> None:
        self.rows_loading = False
        self.plot_loading = False
        self.error = message
        self.update_banner()

    def show_rows(self, result: Aggregate) -> None:
        self.error = ""
        self.result = result
        self.render_rows()
        # At once: the rows that came in are the plot's too, and the highlight has not
        # moved.
        self.load_timeline()
        # After the plot is asked for, so the title does not drop the glyph in between.
        self.rows_loading = False

    def render_rows(self) -> None:
        if self.result is None or self.info is None:
            return
        table = self.query_one(DataTable)
        previous = self.highlighted()
        needle = self.find.lower()
        shown = [
            row
            for row in self.result.rows
            if needle in format_value(self.group_by, row.value).lower()
        ]
        # The sums come from all rows, so a find, which hides some, hides them too;
        # grouped by the layer, the rows are the sums already.
        totals = (
            list(self.result.totals)
            if not needle and self.group_by != self.result.layers_by
            else []
        )
        self.table_rows = totals + shown
        byte_unit = self.viewer.byte_unit
        out_label, in_label = self.info.value_labels
        table.clear(columns=True)
        table.add_column(self.info.dimension_label(self.group_by), key="value")
        table.add_column(Text(out_label, justify="right"), key="out")
        table.add_column(Text(in_label, justify="right"), key="in")
        table.add_rows(
            [
                (
                    _value_cell(self.group_by, row.value),
                    bytes_cell(row.out_bytes, byte_unit),
                    bytes_cell(row.in_bytes, byte_unit),
                )
                for row in self.table_rows
            ]
        )
        # Keep the highlight on the same value across refreshes; a sum only if it was on
        # one, as sums add up what is otherwise kept apart.
        index = next(
            (i for i, row in enumerate(self.table_rows) if row.value == previous),
            len(totals) if shown else 0,
        )
        if self.table_rows:
            table.move_cursor(row=index)
        self.update_banner()
        self.update_status()

    def update_banner(self) -> None:
        """A problem, the filters and a kept find, as on the live tab.

        Nothing to say, no banner.
        """
        notes, keys = [], []
        if self.error:
            notes.append(self.error)
        if self.filters and self.info is not None:
            notes.append(
                "filter: "
                + " > ".join(
                    f"{'!' if f.exclude else ''}{self.info.dimension_label(f.dimension)}"
                    f"={format_value(f.dimension, f.value)}"
                    for f in self.filters
                )
            )
            keys.append(",f c to clear filters")
        # While the find input is open, it says it already.
        if self.find and not self.find_open():
            notes.append(f"find: {self.find}")
            keys.insert(0, "c to clear")
        self.query_one(Banner).say(
            notes, f"press {' · '.join(keys)}" if keys else "", error=bool(self.error)
        )

    def update_status(self) -> None:
        """The table's borders.

        Its title names it summary, as on the live tab, and counts the rows only while
        some are not shown; its bottom border says where the range meets the rollups.
        """
        table = self.query_one(DataTable)
        result = self.result
        title, subtitle = "summary", ""
        if result is not None:
            if self.find or result.truncated:
                title += f" · {len(self.shown())} of {result.groups} rows"
            if result.clipped:
                subtitle = f"raw rows only: from {format_time(result.start)}"
            elif result.start < result.split:
                subtitle = (
                    f"rollups before {format_time(result.split)}:"
                    " no addresses, ephemeral ports as 0"
                )
        table.border_title = title
        table.border_subtitle = subtitle

    # ── events and keys ──

    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        if event.option.id and event.option.id != self.group_by:
            self.group_by = event.option.id
            self.reload()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        # Refilling the table highlights the row again; only another row needs another
        # plot.
        if self.plot_filter() != self._plot_filter:
            self.schedule_timeline()

    def action_filter(self, exclude: bool) -> None:
        # A row of sums has no value of the dimension to keep or exclude.
        value = self.highlighted()
        if value is None or isinstance(value, Total):
            return
        self.filters.append(Filter(self.group_by, value, exclude))
        self.reload()

    def action_pop_filter(self) -> None:
        if self.filters:
            self.select_dimension(self.filters.pop().dimension)
            self.reload()

    def action_clear_filters(self) -> None:
        # Back to where the drill-down started.
        if self.filters:
            dimension = self.filters[0].dimension
            self.filters.clear()
            self.select_dimension(dimension)
            self.reload()

    def select_dimension(self, dimension: str) -> None:
        index = self.info.dimension_index(dimension) if self.info else None
        if index is not None:
            # group_by first: the highlight's handler then finds nothing changed and
            # leaves the reload to the caller, which has the filters to set first.
            self.group_by = dimension
            self.query_one(OptionList).highlighted = index

    def apply_find(self) -> None:
        self.render_rows()
