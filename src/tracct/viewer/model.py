# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The query server's answers, parsed once where they arrive.

The server speaks JSON: lists for rows and pairs, dicts for everything else. The history
tabs work with these types instead, so a field has one name and one shape wherever it is
read. Every source has two byte values, out and in, which it names itself (`sent` and
`received`, or `src to dst` and `dst to src`).
"""

from __future__ import annotations

import dataclasses

#: The name of the row of sums of a source without layers.
ALL = "(all)"


@dataclasses.dataclass(frozen=True)
class Dimension:
    """A column a source's rows can be grouped and filtered by."""

    name: str
    label: str
    #: Only the raw rows have it; the rollups do not.
    raw_only: bool


@dataclasses.dataclass(frozen=True)
class SourceInfo:
    """What `describe` says about one source."""

    label: str
    #: What the source calls its out and in bytes.
    value_labels: tuple[str, str]
    #: The dimension a tab starts grouped by.
    default: str
    dimensions: tuple[Dimension, ...]
    #: The start of its history, or None while it has none.
    oldest: int | None

    @classmethod
    def parse(cls, raw: dict) -> SourceInfo:
        out_label, in_label = raw["values"]
        return cls(
            label=raw["label"],
            value_labels=(out_label, in_label),
            default=raw["default"],
            dimensions=tuple(
                Dimension(name, label, raw_only)
                for name, label, raw_only in raw["dimensions"]
            ),
            oldest=raw["oldest"],
        )

    def dimension_label(self, name: str) -> str:
        return next((d.label for d in self.dimensions if d.name == name), name)

    def dimension_index(self, name: str) -> int | None:
        return next((i for i, d in enumerate(self.dimensions) if d.name == name), None)


@dataclasses.dataclass(frozen=True)
class Filter:
    """Keep the rows whose `dimension` is `value`; with `exclude`, all others."""

    dimension: str
    value: object
    exclude: bool = False

    def to_request(self) -> list:
        return [self.dimension, self.value, self.exclude]


@dataclasses.dataclass(frozen=True)
class Total:
    """The value of a row of sums over all rows.

    There is one per layer where the source has layers, which are never added up, else
    one, whose layer is None.
    """

    layer: str | None

    def label(self) -> str:
        return f"(all · {self.layer})" if self.layer else ALL


@dataclasses.dataclass(frozen=True)
class Row:
    """A row of a history table: a dimension's value, or a Total, and its bytes."""

    value: object
    out_bytes: int
    in_bytes: int


@dataclasses.dataclass(frozen=True)
class Aggregate:
    """The byte sums per value of one dimension, over a range."""

    #: Largest first, at most as many as were asked for.
    rows: tuple[Row, ...]
    #: The sums over all values, one per layer, largest first; the values are Totals.
    totals: tuple[Row, ...]
    #: The dimension the layers are values of, or None for a source without layers.
    layers_by: str | None
    #: How many values there are, shown or not.
    groups: int
    #: Whether there are more values than rows.
    truncated: bool
    #: The start of the range the answer covers.
    start: int
    #: Where the raw rows take over from the rollups.
    split: int
    #: Whether the dimension exists only in the raw rows, which then cut the range.
    clipped: bool

    @classmethod
    def parse(cls, raw: dict) -> Aggregate:
        return cls(
            rows=tuple(Row(value, a, b) for value, a, b in raw["rows"]),
            totals=tuple(Row(Total(layer), a, b) for layer, a, b in raw["parts"]),
            layers_by=raw["totals_by"],
            groups=raw["groups"],
            truncated=raw["truncated"],
            start=raw["start"],
            split=raw["split"],
            clipped=raw["clipped"],
        )


@dataclasses.dataclass(frozen=True)
class Bucket:
    """A bucket of a timeline: its sums and the highest rate of a stretch in it."""

    start: int
    out_bytes: int
    in_bytes: int
    out_rate: float
    in_rate: float


@dataclasses.dataclass(frozen=True)
class Timeline:
    """The byte sums over a range, in buckets of `step` seconds from `origin`."""

    #: The range shown, which the buckets cover.
    start: int
    end: int
    origin: int
    step: int
    #: The stretch, in seconds, whose highest rate a bucket carries.
    peak: int
    #: Where the raw rows take over from the rollups.
    split: int
    #: Only the buckets with bytes, in order.
    buckets: tuple[Bucket, ...]

    @classmethod
    def parse(cls, raw: dict, start: int, end: int, origin: int) -> Timeline:
        return cls(
            start=start,
            end=end,
            origin=origin,
            step=raw["step"],
            peak=raw["peak"],
            split=raw["split"],
            buckets=tuple(Bucket(*bucket) for bucket in raw["buckets"]),
        )
