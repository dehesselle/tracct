# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""a history tab: one source of the query server, grouped by one dimension, narrowed by a stack
of filters, over the viewer's time range, with the timeline of the highlighted row"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.text import Text
from textual import work
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, OptionList, Static
from textual.widgets.option_list import Option
from textual.worker import get_current_worker

from tracct.query import QueryError
from tracct.viewer.format import bytes_cell, display, moment, value_cell
from tracct.viewer.timeline import Timeline

if TYPE_CHECKING:
    from tracct.viewer.app import ViewerApp

# rows asked for per request; the status line says when there are more
ROWS = 1000
# how long the highlight has to rest on a row before its timeline is asked for
TIMELINE_DELAY = 0.25
# timeline bucket lengths; none is shorter than the default write window, whose rows would
# otherwise leave every other bucket empty
BUCKET_STEPS = (10, 30, 60, 120, 300, 600, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 7 * 86400, 30 * 86400, 365 * 86400)


def bucket_step(span: int, columns: int) -> int:
    """the shortest bucket length that fits span into columns"""
    return next((step for step in BUCKET_STEPS if span <= step * columns), BUCKET_STEPS[-1])


class HistoryPane(Vertical):
    DEFAULT_CSS = """
    HistoryPane .header { height: 1; padding: 0 1; background: $foreground 8%; }
    /* TODO: restyle; was $text-muted before the default theme */
    HistoryPane .status { height: 2; padding: 0 1; }
    HistoryPane .status.-error { color: $text-error; }
    HistoryPane OptionList { width: 30; height: 1fr; }
    HistoryPane DataTable { height: 1fr; }
    """
    BINDINGS = [
        # the time range and units are the app's, shared by the history tabs
        Binding("t", "app.span(1)", "span"),
        Binding("T", "app.span(-1)", show=False),
        Binding("h", "app.earlier(1)", "earlier"),
        Binding("H", "app.earlier(-1)", "later"),
        Binding("z", "app.zoom_out", "zoom out"),
        Binding("u", "app.units", "units"),
        Binding("r", "app.refresh", "refresh"),
        Binding("e", "filter(True)", "exclude row"),
        Binding("backspace", "pop_filter", "pop filter"),
        Binding("a", "toggle_subject", "timeline of all rows"),
    ]

    def __init__(self, source: str, *, id: str | None = None) -> None:
        super().__init__(id=id)
        self.source = source
        self.info: dict = {}
        self.group_by = ""
        # (dimension, value, exclude), applied in order
        self.filters: list[tuple[str, object, bool]] = []
        self.rows: list[list] = []
        self.shown: list[list] = []
        self.result: dict = {}
        self.find = ""
        self.all_rows = False
        self.error = ""
        self._timeline_timer = None
        self._configured = False

    @property
    def viewer(self) -> ViewerApp:
        return self.app

    def compose(self):
        yield Static(classes="header")
        with Horizontal():
            yield OptionList(id="dimensions")
            with Vertical():
                yield Timeline()
                yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Static(classes="status")

    def configure(self, info: dict) -> None:
        """the source's dimensions and covered time, from describe"""
        self.info = info
        if self._configured:
            return
        self._configured = True
        self.group_by = info["default"]
        options = self.query_one(OptionList)
        options.clear_options()
        options.add_options([Option(label + (" (raw only)" if raw_only else ""), id=name) for name, label, raw_only in info["dimensions"]])
        options.highlighted = next((i for i, (name, _, _) in enumerate(info["dimensions"]) if name == self.group_by), 0)

    def labels(self) -> dict[str, str]:
        return {name: label for name, label, _ in self.info.get("dimensions", [])}

    # ── requests ─────────────────────────────────────────────────────

    def bounds(self) -> tuple[int, int]:
        return self.viewer.time_range.bounds(int(time.time()), self.info.get("oldest"))

    def subject(self) -> tuple[str, object] | None:
        """the row whose timeline is shown, or None for all rows"""
        table = self.query_one(DataTable)
        if self.all_rows or not self.shown or not 0 <= table.cursor_row < len(self.shown):
            return None
        return self.group_by, self.shown[table.cursor_row][0]

    def reload(self) -> None:
        if not self.info:
            return
        start, end = self.bounds()
        self._load(start, end, list(self.filters), self.group_by)

    @work(thread=True, exclusive=True, group="history-table")
    def _load(self, start: int, end: int, filters: list, group_by: str) -> None:
        worker = get_current_worker()
        try:
            result = self.viewer.ask("aggregate", source=self.source, group_by=group_by, filters=[list(f) for f in filters], start=start, end=end, limit=ROWS)
        except QueryError as e:
            if not worker.is_cancelled:
                self.app.call_from_thread(self.show_error, str(e))
            return
        if not worker.is_cancelled:
            self.app.call_from_thread(self.show_rows, result)

    def load_timeline(self) -> None:
        if not self.info:
            return
        start, end = self.bounds()
        timeline = self.query_one(Timeline)
        step = bucket_step(end - start, max(10, timeline.content_size.width or 80))
        # buckets on whole steps of local time, so their times read well
        if step <= 86400:
            start -= (start + time.localtime(start).tm_gmtoff) % step
        subject = self.subject()
        filters = [list(f) for f in self.filters] + ([[subject[0], subject[1], False]] if subject else [])
        label = f"{self.labels().get(subject[0], subject[0])} = {display(*subject)}" if subject else "all rows"
        self._load_timeline(start, end, step, filters, label)

    @work(thread=True, exclusive=True, group="history-timeline")
    def _load_timeline(self, start: int, end: int, step: int, filters: list, label: str) -> None:
        worker = get_current_worker()
        try:
            result = self.viewer.ask("timeline", source=self.source, filters=filters, start=start, end=end, step=step)
        except QueryError as e:
            if not worker.is_cancelled:
                self.app.call_from_thread(self.show_error, str(e))
            return
        if not worker.is_cancelled:
            self.app.call_from_thread(self.query_one(Timeline).show, start, end, step, result["split"], result["buckets"], label)

    def schedule_timeline(self) -> None:
        if self._timeline_timer is not None:
            self._timeline_timer.stop()
        self._timeline_timer = self.set_timer(TIMELINE_DELAY, self.load_timeline)

    # ── showing results ─────────────────────────────────────────────

    def show_error(self, message: str) -> None:
        self.error = message
        status = self.query_one(".status", Static)
        status.add_class("-error")
        status.update(Text(message))

    def show_rows(self, result: dict) -> None:
        self.result = result
        self.rows = result["rows"]
        self.render_rows()
        self.schedule_timeline()

    def render_rows(self) -> None:
        table = self.query_one(DataTable)
        previous = self.shown[table.cursor_row][0] if self.shown and 0 <= table.cursor_row < len(self.shown) else None
        needle = self.find.lower()
        self.shown = [row for row in self.rows if needle in display(self.group_by, row[0]).lower()] if needle else self.rows
        unit = self.viewer.unit
        out_label, in_label = self.info.get("values", ["sent", "received"])
        table.clear(columns=True)
        table.add_column(self.labels().get(self.group_by, self.group_by), key="value")
        table.add_column(Text(out_label, justify="right"), key="a")
        table.add_column(Text(in_label, justify="right"), key="b")
        table.add_rows([(value_cell(self.group_by, value), bytes_cell(a, unit), bytes_cell(b, unit)) for value, a, b in self.shown])
        # keep the highlight on the same value across refreshes
        index = next((i for i, row in enumerate(self.shown) if row[0] == previous), 0)
        if self.shown:
            table.move_cursor(row=index)
        self.update_header()
        self.update_status()

    def update_header(self) -> None:
        start, end = self.bounds()
        crumbs = " > ".join(f"{'!' if exclude else ''}{self.labels().get(dimension, dimension)}={display(dimension, value)}" for dimension, value, exclude in self.filters)
        header = Text()
        header.append(f"{self.info.get('label', self.source)} ", style="bold")
        header.append(f"({self.info.get('kind', '')})  ")
        header.append(f"{self.viewer.time_range.label()}: {moment(start)} to {moment(min(end, int(time.time())))}")
        if crumbs:
            header.append("   filter: ", style="bold")
            header.append(crumbs)
        self.query_one(".header", Static).update(header)

    def update_status(self) -> None:
        self.error = ""
        status = self.query_one(".status", Static)
        status.remove_class("-error")
        result, unit = self.result, self.viewer.unit
        if not result:
            status.update("")
            return
        out_label, in_label = self.info.get("values", ["sent", "received"])
        line = Text()
        count = f"{len(self.shown)} of {result['groups']} rows" if self.find or result["truncated"] else f"{result['groups']} rows"
        line.append(count)
        a, b = result["totals"]
        if self.source == "connections":
            layer = next((display(d, v) for d, v, exclude in self.filters if d == "layer" and not exclude), "all layers")
            line.append(f"   total {out_label} {_bytes(a, unit)}, {in_label} {_bytes(b, unit)} ({layer})")
        elif self.source == "forwarded":
            line.append(f"   total {out_label} {_bytes(a, unit)}, {in_label} {_bytes(b, unit)}")
        notes = []
        if result["clipped"]:
            notes.append(f"addresses and source ports exist only in raw rows: shown from {moment(result['start'])}")
        elif result["start"] < result["split"]:
            notes.append(f"before {moment(result['split'])} from rollups: whole periods, no addresses, ephemeral ports as 0")
        status.update(line + (Text("\n" + "; ".join(notes)) if notes else Text()))

    # ── events and keys ──────────────────────────────────────────────

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option.id and event.option.id != self.group_by:
            self.group_by = event.option.id
            self.reload()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if not self.all_rows:
            self.schedule_timeline()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_filter(False)

    def on_timeline_zoom(self, event: Timeline.Zoom) -> None:
        self.viewer.zoom(event.start, event.end)

    def action_filter(self, exclude: bool) -> None:
        subject = self.subject() if not self.all_rows else None
        table = self.query_one(DataTable)
        if subject is None and self.shown and 0 <= table.cursor_row < len(self.shown):
            subject = (self.group_by, self.shown[table.cursor_row][0])
        if subject is None:
            return
        self.filters.append((subject[0], subject[1], exclude))
        self.reload()

    def action_pop_filter(self) -> None:
        if self.filters:
            dimension, _, _ = self.filters.pop()
            self.select_dimension(dimension)
            self.reload()

    def action_toggle_subject(self) -> None:
        self.all_rows = not self.all_rows
        self.load_timeline()

    def select_dimension(self, dimension: str) -> None:
        options = self.query_one(OptionList)
        for i, (name, _, _) in enumerate(self.info.get("dimensions", [])):
            if name == dimension:
                self.group_by = dimension
                options.highlighted = i

    def set_find(self, needle: str) -> None:
        self.find = needle
        if self.result:
            self.render_rows()


def _bytes(n: int, unit: str) -> str:
    return bytes_cell(n, unit).plain
