# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""the bars of a history tab: bytes per bucket, one column each, with a cursor to pick a spike"""

from __future__ import annotations

from rich.text import Text
from textual.binding import Binding
from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget

from picosnitch.viewer.format import duration, format_bytes, moment

_EIGHTHS = " ▁▂▃▄▅▆▇█"


class Timeline(Widget, can_focus=True):
    DEFAULT_CSS = """
    Timeline {
        height: 8;
        border: round $panel;
        padding: 0 1;
    }
    Timeline:focus {
        border: round $accent;
    }
    """
    BINDINGS = [
        Binding("left", "move(-1)", "earlier", show=False),
        Binding("right", "move(1)", "later", show=False),
        Binding("home", "jump(0)", show=False),
        Binding("end", "jump(-1)", show=False),
        Binding("enter", "zoom", "zoom in"),
    ]

    cursor = reactive(-1)

    class Zoom(Message):
        """the bucket under the cursor was chosen as the new range"""

        def __init__(self, start: int, end: int) -> None:
            super().__init__()
            self.start = start
            self.end = end

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id)
        self.start = 0
        self.step = 1
        self.count = 0
        self.split = 0
        # bucket index -> (a, b)
        self.values: dict[int, tuple[int, int]] = {}
        self.unit = "auto"
        self.subject = ""

    def show(self, start: int, end: int, step: int, split: int, buckets: list, subject: str) -> None:
        # another range or another row: start again on its largest bucket
        moved = (start, step, subject) != (self.start, self.step, self.subject)
        self.start, self.step, self.split, self.subject = start, step, split, subject
        self.count = max(1, -(-(end - start) // step))
        self.values = {(t - start) // step: (a, b) for t, a, b in buckets}
        if moved or not 0 <= self.cursor < self.count:
            # start on the largest bucket: usually the spike being looked for
            self.cursor = max(self.values, key=lambda i: sum(self.values[i])) if self.values else self.count - 1
        self.refresh()

    def action_move(self, delta: int) -> None:
        if self.count:
            self.cursor = max(0, min(self.count - 1, self.cursor + delta))

    def action_jump(self, index: int) -> None:
        if self.count:
            self.cursor = index % self.count

    def action_zoom(self) -> None:
        # a bucket of the shortest length holds about one write window, nothing to take apart
        if self.count and self.step > 10:
            start = self.start + self.cursor * self.step
            self.post_message(self.Zoom(start, start + self.step))

    def watch_cursor(self) -> None:
        self.refresh()

    def render(self) -> Text:
        width = max(1, self.size.width)
        rows = max(1, self.size.height - 1)
        if not self.count:
            return Text("\n" * rows + "loading", style="dim")
        totals = [sum(self.values.get(i, (0, 0))) for i in range(self.count)]
        peak = max(totals, default=0) or 1
        # more buckets than columns: each column shows the largest of its buckets; fewer: the
        # buckets share the width out
        per_column = max(1, -(-self.count // width))
        columns = [max(totals[i : i + per_column], default=0) for i in range(0, self.count, per_column)]
        if per_column == 1:
            widths = [(i + 1) * width // self.count - i * width // self.count for i in range(self.count)]
        else:
            widths = [1] * len(columns)
        cursor_column = self.cursor // per_column if self.cursor >= 0 else -1
        text = Text(no_wrap=True, overflow="crop")
        for row in range(rows):
            # eighths of this row that a bar must reach to fill it
            floor = (rows - row - 1) * 8
            for column, total in enumerate(columns):
                height = round(total / peak * rows * 8) if total else 0
                if total and height == 0:
                    height = 1
                glyph = _EIGHTHS[max(0, min(8, height - floor))]
                bucket_time = self.start + column * per_column * self.step
                cursor = column == cursor_column
                style = "bold yellow" if cursor else ("dim" if bucket_time < self.split else "")
                if cursor and glyph == " ":
                    # a thin line marks the cursor above its bar
                    glyph = "│"
                # a gap between wide buckets keeps them apart
                repeat = widths[column]
                text.append(glyph * (repeat - 1) + (" " if repeat > 2 and not cursor else glyph), style=style)
            text.append("\n")
        if 0 <= self.cursor < self.count:
            a, b = self.values.get(self.cursor, (0, 0))
            when = moment(self.start + self.cursor * self.step)
            label = f"{when} +{duration(self.step)}  {format_bytes(a, self.unit)} / {format_bytes(b, self.unit)}"
        else:
            label = ""
        if self.subject:
            label = f"{label}  [{self.subject}]"
        text.append(label[:width], style="bold")
        return text
