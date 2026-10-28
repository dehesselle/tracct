# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""the history tabs' span and byte unit, picked from a list rather than cycled through, so a
choice is one reload and not one per entry passed on the way. the key that opened a picker,
pressed again, picks the entry with the hint, as snakecam's f does in its filter dialog"""

from __future__ import annotations

from typing import ClassVar

from rich.text import Text
from tcoda.dialogs import Dialog
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Label, OptionList
from textual.widgets.option_list import Option

from tracct.viewer.format import BYTE_UNITS, SPANS

# what the span picker dismisses with for s: back from the zoom to the span, as it was stepped back
TO_SPAN = -1


def span_label(index: int) -> str:
    name = SPANS[index][0]
    return "all history" if name == "all" else name


class ListPicker[T](Dialog[T]):
    """pick a value from a list opened on the current one, or dismiss with None; KEY, the key
    that opened it, pressed again dismisses with what again names"""

    DEFAULT_CSS = """
    ListPicker > #dialog { max-height: 80%; }
    ListPicker #picker-results { height: auto; max-height: 20; margin-top: 1; }
    """
    KEY: ClassVar[str] = ""

    def __init__(self, title: str, entries: list[tuple[T, str, str]], current: T, again: tuple[T, T] | None) -> None:
        """entries are (value, label, note); again is the entry with the hint and the value KEY
        dismisses with, or None, which leaves KEY without effect and the picker open"""
        super().__init__()
        self._title = title
        self._entries = entries
        self._current = current
        self._again = again

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self._title, id="title")
            yield OptionList(*[Option(self._text(*entry)) for entry in self._entries], id="picker-results")

    def on_mount(self) -> None:
        options = self.query_one("#picker-results", OptionList)
        options.highlighted = next((i for i, (value, _, _) in enumerate(self._entries) if value == self._current), 0)
        options.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.dismiss(self._entries[event.option_index][0])

    def action_again(self) -> None:
        if self._again is not None:
            self.dismiss(self._again[1])

    def _text(self, value: T, label: str, note: str) -> Text:
        # the notes in a column after the longest label
        column = max(len(entry[1]) for entry in self._entries) + 3
        text = Text(label + " " * (column - len(label)))
        notes = [note] if note else []
        if value == self._current:
            notes.append("(current)")
        text.append("  ".join(notes), style="dim")
        if self._again is not None and value == self._again[0]:
            text.append(f"  (press {self.KEY} to select)", style="italic")
        return text


class SpanPicker(ListPicker[int]):
    """an index of SPANS, or TO_SPAN from a zoom"""

    DEFAULT_CSS = """
    SpanPicker > #dialog { width: 64; }
    """
    KEY = "s"
    BINDINGS: ClassVar[list[Binding]] = [Binding("s", "again", "back to span")]

    def __init__(self, current: int, covered: int | None, zoomed: bool) -> None:
        """covered is how many seconds of history there are, None if not known"""
        entries = []
        # shortest first, the whole history last
        for index in sorted(range(len(SPANS)), key=lambda i: SPANS[i][1] or float("inf")):
            seconds = SPANS[index][1]
            # a span longer than the history shows all of it, as the whole history does
            entries.append((index, span_label(index), "all of it" if seconds and covered is not None and seconds >= covered else ""))
        # without a zoom the span is shown already
        super().__init__("Span", entries, current, (current, TO_SPAN) if zoomed else None)


class UnitPicker(ListPicker[str]):
    """one of BYTE_UNITS; u again goes back to the unit before"""

    DEFAULT_CSS = """
    UnitPicker > #dialog { width: 52; }
    """
    KEY = "u"
    BINDINGS: ClassVar[list[Binding]] = [Binding("u", "again", "last unit")]

    def __init__(self, current: str, last: str | None) -> None:
        entries = [(unit, unit, "a unit per value" if unit == "auto" else "") for unit in BYTE_UNITS]
        super().__init__("Unit", entries, current, (last, last) if last else None)
