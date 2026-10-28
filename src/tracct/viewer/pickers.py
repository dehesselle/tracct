# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The history tabs' span and byte unit, picked from a list.

A list rather than cycling through the values makes a choice one reload, not one per
value passed on the way. The key that opened a picker, pressed again, picks the entry
with the hint, as snakecam's `f` does in its filter dialog.
"""

from __future__ import annotations

from typing import ClassVar, Final

from rich.text import Text
from tcoda.dialogs import Dialog
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Label, OptionList
from textual.widgets.option_list import Option

from tracct.viewer.format import BYTE_UNITS
from tracct.viewer.timerange import SPANS


class Unzoom:
    """The type of UNZOOM."""

    def __repr__(self) -> str:
        return "UNZOOM"


#: What the span picker dismisses with for `s` pressed again: back from the zoom to the
#: span, stepped back as it was.
UNZOOM: Final = Unzoom()


def span_label(index: int) -> str:
    name = SPANS[index][0]
    return "all history" if name == "all" else name


class ListPicker[T](Dialog[T]):
    """Pick a value from a list opened on the current one, or dismiss with None.

    KEY, the key that opened the picker, pressed again dismisses with `again_value`.
    """

    DEFAULT_CSS = """
    ListPicker > #dialog { max-height: 80%; }
    ListPicker #picker-results { height: auto; max-height: 20; margin-top: 1; }
    """
    KEY: ClassVar[str] = ""

    def __init__(
        self,
        title: str,
        entries: list[tuple[T, str, str]],
        current: T,
        *,
        hint_value: T | None = None,
        again_value: T | None = None,
    ) -> None:
        """
        Args:
            title: The picker's title.
            entries: The values as (value, label, note).
            current: The value shown now, which the list opens on.
            hint_value: The entry that says KEY selects it, or None for none.
            again_value: What KEY pressed again dismisses with, or None to leave KEY
                without effect and the picker open.
        """
        super().__init__()
        self._title = title
        self._entries = entries
        self._current = current
        self._hint_value = hint_value
        self._again_value = again_value

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self._title, id="title")
            yield OptionList(
                *[Option(self._text(*entry)) for entry in self._entries],
                id="picker-results",
            )

    def on_mount(self) -> None:
        options = self.query_one("#picker-results", OptionList)
        options.highlighted = next(
            (
                i
                for i, (value, _, _) in enumerate(self._entries)
                if value == self._current
            ),
            0,
        )
        options.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.dismiss(self._entries[event.option_index][0])

    def action_again(self) -> None:
        if self._again_value is not None:
            self.dismiss(self._again_value)

    def _text(self, value: T, label: str, note: str) -> Text:
        # The notes in a column after the longest label.
        column = max(len(entry[1]) for entry in self._entries) + 3
        text = Text(label + " " * (column - len(label)))
        notes = [note] if note else []
        if value == self._current:
            notes.append("(current)")
        text.append("  ".join(notes), style="dim")
        if self._hint_value is not None and value == self._hint_value:
            text.append(f"  (press {self.KEY} to select)", style="italic")
        return text


class SpanPicker(ListPicker[int | Unzoom]):
    """An index of SPANS, or UNZOOM from a zoom."""

    DEFAULT_CSS = """
    SpanPicker > #dialog { width: 64; }
    """
    KEY = "s"
    BINDINGS: ClassVar[list[Binding]] = [Binding("s", "again", "back to span")]

    def __init__(self, current: int, covered: int | None, zoomed: bool) -> None:
        """
        Args:
            current: The span shown now.
            covered: How many seconds of history there are, or None if not known.
            zoomed: Whether a zoom is shown, which `s` pressed again returns from.
        """
        entries: list[tuple[int | Unzoom, str, str]] = []
        # Shortest first, the whole history last.
        for index in sorted(
            range(len(SPANS)), key=lambda i: SPANS[i][1] or float("inf")
        ):
            seconds = SPANS[index][1]
            # A span longer than the history shows all of it, as the whole history does.
            entries.append(
                (
                    index,
                    span_label(index),
                    "all of it"
                    if seconds and covered is not None and seconds >= covered
                    else "",
                )
            )
        # Without a zoom the span is shown already.
        super().__init__(
            "Span",
            entries,
            current,
            hint_value=current if zoomed else None,
            again_value=UNZOOM if zoomed else None,
        )


class ByteUnitPicker(ListPicker[str]):
    """One of BYTE_UNITS; `u` pressed again goes back to the byte unit before."""

    DEFAULT_CSS = """
    ByteUnitPicker > #dialog { width: 52; }
    """
    KEY = "u"
    BINDINGS: ClassVar[list[Binding]] = [Binding("u", "again", "last unit")]

    def __init__(self, current: str, last: str | None) -> None:
        entries = [
            (byte_unit, byte_unit, "a unit per value" if byte_unit == "auto" else "")
            for byte_unit in BYTE_UNITS
        ]
        super().__init__("Unit", entries, current, hint_value=last, again_value=last)
