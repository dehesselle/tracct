# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The plot of a history tab.

A line each for sent and received, as a rate per bucket; what it shows is the viewer's
time range, so zooming or panning it narrows every tab.
"""

from __future__ import annotations

from tcoda.plot import DateTimeFormatter, NumericFormatter, Plot
from textual.content import Content
from textual.events import Leave, MouseMove

from tracct.viewer.format import duration, format_bytes, format_time
from tracct.viewer.model import Timeline

#: The shortest and longest range zooming goes to, in seconds; the longest stays within
#: the query server's bucket limit at the longest bucket.
MIN_SPAN = 60
MAX_SPAN = 10 * 365 * 86400
#: In the title while the tab is updating, as snakecam shows it.
BUSY = "↻"
#: The stretch, in seconds, whose highest rate a point shows; the default write window,
#: which the query server lengthens it to if the daemon writes less often.
PEAK_SECONDS = 10
OUT_STYLE = "$accent"
IN_STYLE = "$primary"
SPLIT_STYLE = "$foreground 60%"


class RateAxis(NumericFormatter):
    """Bytes per second on round values."""

    def __init__(self, byte_unit: str = "auto") -> None:
        self.byte_unit = byte_unit

    def get_labels(self, ticks) -> list[str]:
        return [
            f"{format_bytes(tick, self.byte_unit)}/s" if tick else "0" for tick in ticks
        ]


class TrafficPlot(Plot):
    # Its look is in app.tcss.
    def __init__(self, *, id: str | None = None) -> None:
        # Zooming and panning move the time axis only; the rate axis fits the data in
        # view.
        super().__init__(id=id, pan_and_zoom="x")
        self.x_formatter = DateTimeFormatter()
        self.y_formatter = RateAxis()
        #: Nothing before 1970.
        self.x_bounds = (0, None)
        self.x_span = (MIN_SPAN, MAX_SPAN)
        #: What is drawn, or None before anything is.
        self.timeline: Timeline | None = None
        #: Bucket start -> its (out, in) bytes.
        self.values: dict[int, tuple[int, int]] = {}
        #: Bucket start -> the highest (out, in) rate of a stretch in it.
        self.peaks: dict[int, tuple[float, float]] = {}
        #: What the source calls its out and in bytes.
        self.value_labels = ("sent", "received")
        self.heading = ""
        self.row_label = ""
        #: The tab is fetching rows or this plot's data, and has been for a moment.
        self.busy = False
        self.byte_unit = "auto"

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool:
        # The plot's r resets the zoom behind the viewer's back, where r refreshes
        # everywhere else.
        return action != "reset_range" and super().check_action(action, parameters)

    def points(self) -> int:
        """Return how many buckets fit: braille has two dots across a cell."""
        return 2 * max(10, self.data_size.width)

    def show(
        self,
        timeline: Timeline,
        *,
        heading: str = "",
        row_label: str = "",
        value_labels: tuple[str, str] = ("sent", "received"),
    ) -> None:
        """Draw `timeline`.

        Args:
            timeline: The buckets and the range they cover.
            heading: The range's name, which the title starts with.
            row_label: The name of the row drawn.
            value_labels: What the source calls its out and in bytes.
        """
        self.timeline = timeline
        self.heading, self.row_label, self.value_labels = (
            heading,
            row_label,
            value_labels,
        )
        # The lines show the peaks: averaged over a wide bucket, a short spike would
        # flatten into the traffic around it.
        self.values = {b.start: (b.out_bytes, b.in_bytes) for b in timeline.buckets}
        self.peaks = {b.start: (b.out_rate, b.in_rate) for b in timeline.buckets}
        self.redraw()

    def redraw(self) -> None:
        timeline = self.timeline
        if timeline is None:
            return
        self.update_title()
        self.clear()
        # Every bucket, the empty ones at zero, so a line drops to nothing rather than
        # bridging a gap.
        times = range(timeline.origin, timeline.end, timeline.step)
        xs = [t + timeline.step / 2 for t in times]
        out_rates = [self.peaks.get(t, (0, 0))[0] for t in times]
        in_rates = [self.peaks.get(t, (0, 0))[1] for t in times]
        if len(xs) > 1:
            # In first: it is usually the larger, and the smaller line stays visible on
            # top.
            self.plot(xs, in_rates, style=IN_STYLE, hires_mode="braille")
            self.plot(xs, out_rates, style=OUT_STYLE, hires_mode="braille")
        if timeline.start < timeline.split < timeline.end:
            self.vline(timeline.split, style=SPLIT_STYLE)
        # A refresh arriving while zooming or panning rests does not move the range: the
        # plot keeps new limits for once it settles.
        self.x_limits = (timeline.start, timeline.end)
        self.y_limits = (0, None)

    def set_byte_unit(self, byte_unit: str) -> None:
        self.byte_unit = byte_unit
        self.y_formatter = RateAxis(byte_unit)

    def set_busy(self, busy: bool) -> None:
        if busy != self.busy:
            self.busy = busy
            self.update_title()

    def update_title(self) -> None:
        """Put the range, the colors' key and whether the tab is updating in the title.

        The key sits in the title, where it takes no height from the lines; the busy
        glyph comes and goes at its end, where it moves nothing. The highlighted row, a
        row of sums too, says which row is drawn. The stretch of the peaks is named only
        when the daemon's write window made it longer than asked for, and is the first
        thing to go when the title does not fit.
        """
        out_label, in_label = self.value_labels
        head = Content(f"{self.heading} · " if self.heading else "")
        key = Content.assemble(
            ("━━", OUT_STYLE), f" {out_label} ", ("━━", IN_STYLE), f" {in_label}"
        )
        peak = self.timeline.peak if self.timeline is not None else PEAK_SECONDS
        rate = Content(f" · peak {duration(peak)} rate" if peak != PEAK_SECONDS else "")
        busy = Content(f" · {BUSY}" if self.busy else "")
        # The corners and a border cell either side.
        if (
            head.cell_length + key.cell_length + rate.cell_length + busy.cell_length
            > self.size.width - 4
        ):
            rate = Content("")
        self.border_title = Content.assemble(head, key, rate, busy)

    # ── the bucket under the pointer, in the bottom border ──

    def on_mouse_move(self, event: MouseMove) -> None:
        point = self.data_at(event.screen_offset)
        timeline = self.timeline
        if event.button or point is None or timeline is None:
            self.border_subtitle = ""
            return
        origin, step = timeline.origin, timeline.step
        bucket = origin + (int(point[0]) - origin) // step * step
        out_bytes, in_bytes = self.values.get(bucket, (0, 0))
        out_peak, in_peak = self.peaks.get(bucket, (0, 0))
        out_label, in_label = self.value_labels

        def amount(n: float) -> str:
            return format_bytes(n, self.byte_unit)

        self.border_subtitle = Content(
            f"{format_time(bucket)} +{duration(step)}"
            f" · {out_label} {amount(out_bytes)} (peak {amount(out_peak)}/s)"
            f" · {in_label} {amount(in_bytes)} (peak {amount(in_peak)}/s)"
        )

    def on_leave(self, event: Leave) -> None:
        self.border_subtitle = ""
