# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""the plot of a history tab: a line each for sent and received, as a rate per bucket; what it
shows is the viewer's time range, so zooming or panning it narrows every tab"""

from __future__ import annotations

import time
from math import ceil, floor, log10

from textual import on
from textual.binding import Binding
from textual.content import Content
from textual.events import Leave, MouseMove
from textual.message import Message
from textual_plot import HiResMode, PlotWidget
from textual_plot.axis_formatter import AxisFormatter
from textual_plot.plot_widget import Canvas

from tracct.viewer.format import duration, format_bytes, moment

# how long zooming or panning has to rest before the range is asked for
VIEW_DELAY = 0.15
# the shortest and longest range zooming goes to, in seconds; the longest stays within the
# query server's bucket limit at the longest bucket
MIN_SPAN = 60
MAX_SPAN = 10 * 365 * 86400
# in the title while the tab is updating, as snakecam shows it
BUSY = "↻"
# the stretch, in seconds, whose highest rate a point shows; the default write window, which
# the query server lengthens it to if the daemon writes less often
PEAK_SECONDS = 10
# lengths between the time axis' ticks, in seconds
_TIME_STEPS = (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 2 * 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 2 * 86400, 7 * 86400, 14 * 86400, 30 * 86400, 91 * 86400, 365 * 86400)


def _local(t: float) -> float:
    """the plot's x for a time: its local clock time read as UTC, so ticks land on local hours"""
    return t + time.localtime(t).tm_gmtoff


def _epoch(x: float) -> int:
    return int(x - time.localtime(x).tm_gmtoff)


class TimeAxis(AxisFormatter):
    """ticks on round local times, as many as fit the width"""

    def __init__(self) -> None:
        self.columns = 80

    def get_ticks(self, min_: float, max_: float, max_ticks: int = 8) -> list[float]:
        limit = max(2, min(max_ticks, self.columns // 14))
        step = next((step for step in _TIME_STEPS if (max_ - min_) / step <= limit), _TIME_STEPS[-1])
        return [float(k * step) for k in range(ceil(min_ / step), floor(max_ / step) + 1)]

    def get_labels_for_ticks(self, ticks) -> list[str]:
        step = ticks[1] - ticks[0] if len(ticks) > 1 else 3600
        labels = []
        for tick in ticks:
            clock = time.gmtime(tick)
            if step >= 365 * 86400:
                pattern = "%Y"
            elif step >= 30 * 86400:
                pattern = "%b %Y"
            elif step >= 86400 or clock.tm_hour == clock.tm_min == clock.tm_sec == 0:
                # a midnight among hours says which day starts
                pattern = "%b %d"
            elif step < 60:
                pattern = "%H:%M:%S"
            else:
                pattern = "%H:%M"
            labels.append(time.strftime(pattern, clock))
        return labels


class RateAxis(AxisFormatter):
    """bytes per second on round values, as many as fit the height"""

    def __init__(self) -> None:
        self.rows = 10
        self.unit = "auto"

    def get_ticks(self, min_: float, max_: float, max_ticks: int = 8) -> list[float]:
        if max_ <= min_:
            return []
        rough = (max_ - min_) / max(2, min(max_ticks, self.rows // 2))
        power = 10 ** floor(log10(rough))
        step = next(m * power for m in (1, 2, 5, 10) if m * power >= rough)
        return [float(k * step) for k in range(ceil(min_ / step), floor(max_ / step) + 1)]

    def get_labels_for_ticks(self, ticks) -> list[str]:
        return [f"{format_bytes(tick, self.unit)}/s" if tick else "0" for tick in ticks]


class TrafficPlot(PlotWidget, inherit_bindings=False):
    # PlotWidget's own keys pan and zoom the rate axis too, which this plot fits to the data,
    # and its r resets the zoom behind the viewer's back, where r refreshes everywhere else
    BINDINGS = [
        Binding("+", "zoom_in", "zoom in", group=Binding.Group("zoom")),
        Binding("-", "zoom_out", "zoom out", group=Binding.Group("zoom")),
        Binding("left", "pan_left", "pan earlier", group=Binding.Group("pan")),
        Binding("right", "pan_right", "pan later", group=Binding.Group("pan")),
    ]
    COMPONENT_CLASSES = PlotWidget.COMPONENT_CLASSES | {"trafficplot--sent", "trafficplot--received", "trafficplot--split"}
    DEFAULT_CSS = """
    TrafficPlot {
        height: 33vh;
        border: round $foreground 40%;
        & > .plot--axis, &:focus > .plot--axis { color: $foreground 40%; }
        & > .plot--tick { color: $foreground 70%; text-style: none; }
        & > .trafficplot--sent { color: $accent; }
        & > .trafficplot--received { color: $primary; }
        & > .trafficplot--split { color: $foreground 60%; }
    }
    TrafficPlot:focus {
        border: round $accent;
    }
    """

    class Viewed(Message):
        """zooming or panning came to rest on a new range"""

        def __init__(self, start: int, end: int) -> None:
            super().__init__()
            self.start = start
            self.end = end

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id)
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
        self._time_axis = TimeAxis()
        self._rate_axis = RateAxis()
        self._view_timer = None
        # the range zoomed or panned to, until it is posted
        self._pending: tuple[float, float] | None = None

    def on_mount(self) -> None:
        # no axis labels: the border title says what is drawn
        self.margin_top = 0
        self.margin_bottom = 1
        self.margin_left = 12
        self.set_x_formatter(self._time_axis)
        self.set_y_formatter(self._rate_axis)

    def on_resize(self) -> None:
        # the ticks follow the size
        self.redraw()

    def columns(self) -> int:
        """the width of the plot area, in cells"""
        return max(10, self.content_size.width - self.margin_left - 2)

    def points(self) -> int:
        """how many buckets the lines have room for: braille has two dots across a cell"""
        return 2 * self.columns()

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
        sent_style, received_style = self._style("sent"), self._style("received")
        self.update_title()
        self.clear()
        self._time_axis.columns = self.columns()
        self._rate_axis.rows = max(2, self.content_size.height - self.margin_bottom - 2)
        self._rate_axis.unit = self.unit
        # every bucket, the empty ones at zero, so a line drops to nothing rather than bridging a gap
        times = range(self.origin, self.end, self.step)
        xs = [_local(t) + self.step / 2 for t in times]
        sent = [self.peaks.get(t, (0, 0))[0] for t in times]
        received = [self.peaks.get(t, (0, 0))[1] for t in times]
        if len(xs) > 1:
            # received first: it is usually the larger, and the smaller line stays visible on top
            self.plot(xs, received, line_style=received_style, hires_mode=HiResMode.BRAILLE)
            self.plot(xs, sent, line_style=sent_style, hires_mode=HiResMode.BRAILLE)
        if self.start < self.split < self.end:
            self.add_v_line(_local(self.split), self._style("split"))
        # a refresh arriving while zooming or panning rests does not snap the range back
        if self._pending is None:
            self.set_xlimits(_local(self.start), _local(self.end))
        top = max(max(sent, default=0), max(received, default=0))
        self.set_ylimits(0, top * 1.1 or 1)

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
        key = Content.assemble(("━━", self._style("sent")), f" {out_label} ", ("━━", self._style("received")), f" {in_label}")
        rate = Content(f" · peak {duration(self.peak)} rate" if self.end and self.peak != PEAK_SECONDS else "")
        busy = Content(f" · {BUSY}" if self.busy else "")
        # the corners and a border cell either side
        if head.cell_length + key.cell_length + rate.cell_length + busy.cell_length > self.size.width - 4:
            rate = Content("")
        self.border_title = Content.assemble(head, key, rate, busy)

    def _style(self, part: str) -> str:
        return str(self.get_component_rich_style(f"trafficplot--{part}", partial=True))

    # ── zooming and panning move the time axis only; the rate axis fits the data ──

    def _zoom(self, center_x: float, center_y: float, factor: float, zoom_x: bool, zoom_y: bool) -> None:
        if not zoom_x:
            return
        # PlotWidget's own formula, checked against the limits before it is applied
        x_min = (self._x_min + factor * center_x) / (1 + factor)
        x_max = (self._x_max + factor * center_x) / (1 + factor)
        # each limit stops zooming further past it only: a range "all" may start out wider
        if x_max - x_min < self._x_max - self._x_min:
            allowed = x_max - x_min >= MIN_SPAN
        else:
            allowed = x_max - x_min <= MAX_SPAN and _epoch(x_min) >= 0
        if allowed:
            super()._zoom(center_x, center_y, factor, True, False)
            self._schedule_view()

    def _pan(self, factor_x: float, factor_y: float) -> None:
        if not factor_x:
            return
        x_min, x_max = self._x_min, self._x_max
        super()._pan(factor_x, 0)
        if _epoch(self._x_min) < 0:
            # nothing before 1970: back to where it was
            self.set_xlimits(x_min, x_max)
            self._rerender()
            return
        self._schedule_view()

    def _schedule_view(self) -> None:
        self._pending = (self._x_min, self._x_max)
        if self._view_timer is not None:
            self._view_timer.stop()
        self._view_timer = self.set_timer(VIEW_DELAY, self._viewed)

    def _viewed(self) -> None:
        x_min, x_max = self._pending
        self._pending = None
        self.post_message(self.Viewed(_epoch(x_min), _epoch(x_max)))

    # ── the bucket under the pointer, in the bottom border ──

    @on(MouseMove)
    def hover(self, event: MouseMove) -> None:
        canvas = self.query_one("#plot", Canvas)
        if event.button or not canvas.region.contains_point(event.screen_offset) or not self.end:
            self.border_subtitle = ""
            return
        offset = event.screen_offset - canvas.region.offset
        x, _ = self.get_coordinate_from_pixel(offset.x, offset.y)
        t = _epoch(x)
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
