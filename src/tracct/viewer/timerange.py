# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The time range the history tabs share, and the local-time math behind it.

Spans and buckets fall on whole periods of local time, so their times read well: an hour
starts on the hour, a day at midnight.
"""

from __future__ import annotations

import time

#: The spans `s` picks from, as (name, seconds); 0 is all of the history.
SPANS = (
    ("all", 0),
    ("1 minute", 60),
    ("5 minutes", 300),
    ("15 minutes", 900),
    ("1 hour", 3600),
    ("3 hours", 3 * 3600),
    ("6 hours", 6 * 3600),
    ("12 hours", 12 * 3600),
    ("1 day", 86400),
    ("3 days", 3 * 86400),
    ("7 days", 7 * 86400),
    ("30 days", 30 * 86400),
    ("365 days", 365 * 86400),
)
#: The bucket lengths of a timeline, in seconds. None is shorter than the default
#: write window, whose rows would otherwise leave every other bucket empty.
BUCKET_STEPS = (
    10,
    30,
    60,
    120,
    300,
    600,
    900,
    1800,
    3600,
    3 * 3600,
    6 * 3600,
    12 * 3600,
    86400,
    7 * 86400,
    30 * 86400,
    365 * 86400,
)
DAY = 86400


def align(t: int, seconds: int) -> int:
    """Return the start of the local-time period of `seconds` that holds `t`.

    Args:
        t: A time, in seconds since the epoch.
        seconds: The period's length, at most a day.
    """
    return t - (t + time.localtime(t).tm_gmtoff) % seconds


def bucket_step(span: int, columns: int) -> int:
    """Return the shortest bucket length that fits `span` seconds into `columns`."""
    return next(
        (step for step in BUCKET_STEPS if span <= step * columns), BUCKET_STEPS[-1]
    )


def bucket_grid(start: int, end: int, columns: int) -> tuple[int, int]:
    """Return the (origin, step) of the buckets that show `start` to `end` in `columns`.

    Buckets up to a day long start on whole steps of local time; longer ones start at
    `start`.
    """
    step = bucket_step(end - start, columns)
    return (align(start, step) if step <= DAY else start), step


class TimeRange:
    """A span that ends now, a span stepped back into the past, or a zoom.

    A zoom is the range a plot was zoomed or panned to. Zooming out only widens it; `s`
    `s` returns from it to the span, stepped back as it was.
    """

    def __init__(self, span: int = 4) -> None:
        """
        Args:
            span: An index of SPANS.
        """
        self.span = span
        #: How many whole spans back from now; 0 ends now.
        self.back = 0
        self.zoom: tuple[int, int] | None = None

    def bounds(self, now: int, oldest: int | None) -> tuple[int, int]:
        """Return the range's (start, end) at `now`.

        Args:
            now: The time now.
            oldest: The start of the history, which all of it starts at; None for 0.
        """
        if self.zoom is not None:
            return self.zoom
        seconds = SPANS[self.span][1]
        if seconds == 0:
            return (oldest or 0), now + 1
        if self.back == 0:
            return now - seconds, now + 1
        # Back 1 is the last whole period, back 2 the one before.
        end = align(now, min(seconds, DAY)) - (self.back - 1) * seconds
        return end - seconds, end

    def ends_now(self) -> bool:
        return self.zoom is None and self.back == 0

    def steppable(self) -> bool:
        """Whether the span can step back and forward; all of the history cannot."""
        return SPANS[self.span][1] != 0

    def pick(self, span: int) -> bool:
        """Show the last `span`, ending a step back or a zoom.

        Returns:
            Whether the range changed: picking the span shown, ending now, does not.
        """
        if span == self.span and self.ends_now():
            return False
        self.span = span
        self.back = 0
        self.zoom = None
        return True

    def step(self, step: int) -> None:
        """Step the span back (-1) or forward (+1).

        Forward stops at the span ending now.
        """
        self.zoom = None
        self.back = max(0, self.back - step)

    def zoom_to(self, start: int, end: int) -> None:
        self.zoom = (start, end)

    def unzoom(self) -> None:
        """Return from the zoom to the span, stepped back as it was."""
        self.zoom = None

    def heading(self, start: int, end: int) -> str:
        """Return the range as the plot's title begins.

        A span goes by its name, a zoom by its ends, which name the day once if both
        fall on it.
        """
        if self.zoom is None:
            name = SPANS[self.span][0]
            if self.back:
                return f"{name}, {self.back} back"
            return "all history" if name == "all" else f"last {name}"
        pattern = "%H:%M" if end - start >= 3600 else "%H:%M:%S"
        first, last = time.localtime(start), time.localtime(end)
        tail = time.strftime(
            pattern if first[:3] == last[:3] else f"%b %d {pattern}", last
        )
        return f"{time.strftime(f'%b %d {pattern}', first)} – {tail}"
