# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""the plot of a history tab: a line each for sent and received, as a rate per bucket; what it
shows is the viewer's time range, so zooming or panning it narrows every tab"""

from __future__ import annotations

from tcoda.plot import DateTimeFormatter, NumericFormatter, Plot
from textual.content import Content
from textual.events import Leave, MouseMove

from tracct.viewer.format import duration, format_bytes, moment

# the shortest and longest range zooming goes to, in seconds; the longest stays within the
# query server's bucket limit at the longest bucket
MIN_SPAN = 60
MAX_SPAN = 10 * 365 * 86400
# in the title while the tab is updating, as snakecam shows it
BUSY = "↻"
# the stretch, in seconds, whose highest rate a point shows; the default write window, which
# the query server lengthens it to if the daemon writes less often
PEAK_SECONDS = 10
SENT_STYLE = "$accent"
RECEIVED_STYLE = "$primary"
SPLIT_STYLE = "$foreground 60%"


class RateAxis(NumericFormatter):
    """bytes per second on round values"""

    def __init__(self, unit: str = "auto") -> None:
        self.unit = unit

    def get_labels(self, ticks) -> list[str]:
        return [f"{format_bytes(tick, self.unit)}/s" if tick else "0" for tick in ticks]


class TrafficPlot(Plot):
    # no axis labels: the border title says what is drawn; the tick labels get a fixed width, so
    # the lines do not shift sideways when the rates refit to a zoom
    DEFAULT_CSS = """
    TrafficPlot {
        height: 33vh;
        border: round $foreground 40%;
        grid-columns: 12 1fr;
        & > .plot--axis, &:focus > .plot--axis { color: $foreground 40%; }
        & > .plot--tick { color: $foreground 70%; text-style: none; }
    }
    TrafficPlot:focus {
        border: round $accent;
    }
    """

    def __init__(self, *, id: str | None = None) -> None:
        # zooming and panning move the time axis only; the rate axis fits the data in view
        super().__init__(id=id, pan_and_zoom="x")
        self.x_formatter = DateTimeFormatter()
        self.y_formatter = RateAxis()
        # nothing before 1970
        self.x_bounds = (0, None)
        self.x_span = (MIN_SPAN, MAX_SPAN)
        self.start = 0
        self.end = 0
        self.origin = 0
        self.step = 1
        self.peak = 1
        self.split = 0
        # bucket start -> (a, b) bytes, and -> (a, b) the highest rate of a stretch in it
        self.values: dict[int, tuple[int, int]] = {}
        self.peaks: dict[int, tuple[float, float]] = {}
        self.labels = ("sent", "received")
        self.heading = ""
        self.subject = ""
        # the tab is fetching rows or this plot's data, and has been for a moment
        self.busy = False
        self.unit = "auto"

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool:
        # the plot's r resets the zoom behind the viewer's back, where r refreshes everywhere else
        return action != "reset_range" and super().check_action(action, parameters)

    def points(self) -> int:
        """how many buckets the lines have room for: braille has two dots across a cell"""
        return 2 * max(10, self.data_size.width)

    def show(self, start: int, end: int, origin: int, step: int, peak: int, split: int, buckets: list, heading: str, subject: str, labels: tuple[str, str]) -> None:
        """the range start to end, named heading, of the row named subject, in buckets of step
        seconds counted from origin, each with its sums and the highest rate of a stretch of peak
        seconds in it"""
        self.start, self.end, self.origin, self.step, self.peak, self.split = start, end, origin, step, peak, split
        self.heading, self.subject, self.labels = heading, subject, labels
        # the lines show the peaks: averaged over a wide bucket, a short spike would flatten into
        # the traffic around it
        self.values = {t: (a, b) for t, a, b, _, _ in buckets}
        self.peaks = {t: (rate_a, rate_b) for t, _, _, rate_a, rate_b in buckets}
        self.redraw()

    def redraw(self) -> None:
        if not self.end:
            return
        self.update_title()
        self.clear()
        # every bucket, the empty ones at zero, so a line drops to nothing rather than bridging a gap
        times = range(self.origin, self.end, self.step)
        xs = [t + self.step / 2 for t in times]
        sent = [self.peaks.get(t, (0, 0))[0] for t in times]
        received = [self.peaks.get(t, (0, 0))[1] for t in times]
        if len(xs) > 1:
            # received first: it is usually the larger, and the smaller line stays visible on top
            self.plot(xs, received, style=RECEIVED_STYLE, hires_mode="braille")
            self.plot(xs, sent, style=SENT_STYLE, hires_mode="braille")
        if self.start < self.split < self.end:
            self.vline(self.split, style=SPLIT_STYLE)
        # a refresh arriving while zooming or panning rests does not move the range: the plot
        # keeps new limits for once it settles
        self.x_limits = (self.start, self.end)
        self.y_limits = (0, None)

    def set_unit(self, unit: str) -> None:
        self.unit = unit
        self.y_formatter = RateAxis(unit)

    def set_busy(self, busy: bool) -> None:
        if busy != self.busy:
            self.busy = busy
            self.update_title()

    def update_title(self) -> None:
        """the range drawn, then the colors' key, where it takes no height from the lines, and
        whether the tab is updating, which comes and goes at the end where it moves nothing. the
        highlighted row, a row of sums too, says which row is drawn; the stretch of the peaks only
        when the daemon's write window made it longer than asked for, and that goes first when
        the title does not fit"""
        out_label, in_label = self.labels
        head = Content(f"{self.heading} · " if self.heading else "")
        key = Content.assemble(("━━", SENT_STYLE), f" {out_label} ", ("━━", RECEIVED_STYLE), f" {in_label}")
        rate = Content(f" · peak {duration(self.peak)} rate" if self.end and self.peak != PEAK_SECONDS else "")
        busy = Content(f" · {BUSY}" if self.busy else "")
        # the corners and a border cell either side
        if head.cell_length + key.cell_length + rate.cell_length + busy.cell_length > self.size.width - 4:
            rate = Content("")
        self.border_title = Content.assemble(head, key, rate, busy)

    # ── the bucket under the pointer, in the bottom border ──

    def on_mouse_move(self, event: MouseMove) -> None:
        point = self.data_at(event.screen_offset)
        if event.button or point is None or not self.end:
            self.border_subtitle = ""
            return
        t = int(point[0])
        bucket = self.origin + (t - self.origin) // self.step * self.step
        a, b = self.values.get(bucket, (0, 0))
        peak_a, peak_b = self.peaks.get(bucket, (0, 0))
        out_label, in_label = self.labels
        self.border_subtitle = Content(
            f"{moment(bucket)} +{duration(self.step)} · {out_label} {format_bytes(a, self.unit)} (peak {format_bytes(peak_a, self.unit)}/s)"
            f" · {in_label} {format_bytes(b, self.unit)} (peak {format_bytes(peak_b, self.unit)}/s)"
        )

    def on_leave(self, event: Leave) -> None:
        self.border_subtitle = ""
