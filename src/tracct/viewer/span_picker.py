# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""the span of the history tabs, picked from a list rather than cycled through, so a choice is
one reload and not one per span passed on the way; s again returns from a zoom to the span, as
snakecam's f toggles its filter"""

from __future__ import annotations

from typing import ClassVar

from rich.text import Text
from tcoda.dialogs import Dialog
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Label, OptionList
from textual.widgets.option_list import Option

from tracct.viewer.format import SPANS

# what the picker dismisses with for s: back from the zoom to the span, as it was stepped back
TO_SPAN = -1


def span_label(index: int) -> str:
    name = SPANS[index][0]
    return "all history" if name == "all" else name


class SpanPicker(Dialog[int]):
    """pick an index of SPANS, return to the span from a zoom with TO_SPAN, or dismiss with None"""

    DEFAULT_CSS = """
    SpanPicker > #dialog { width: 64; max-height: 80%; }
    SpanPicker #picker-results { height: auto; max-height: 20; margin-top: 1; }
    """
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("s", "to_span", "back to span"),
    ]
    HINT: ClassVar[str] = "(press s to select)"

    def __init__(self, current: int, covered: int | None, zoomed: bool) -> None:
        """covered is how many seconds of history there are, None if not known"""
        super().__init__()
        self._current = current
        self._covered = covered
        self._zoomed = zoomed
        # shortest first, the whole history last
        self._shown = sorted(range(len(SPANS)), key=lambda i: SPANS[i][1] or float("inf"))

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Span", id="title")
            yield OptionList(*[Option(self._text(i)) for i in self._shown], id="picker-results")

    def on_mount(self) -> None:
        options = self.query_one("#picker-results", OptionList)
        options.highlighted = self._shown.index(self._current)
        options.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.dismiss(self._shown[event.option_index])

    def action_to_span(self) -> None:
        # without a zoom the span is shown already; the picker stays open
        if self._zoomed:
            self.dismiss(TO_SPAN)

    def _text(self, index: int) -> Text:
        column = max(len(span_label(i)) for i in self._shown) + 3
        label = span_label(index)
        text = Text(label + " " * (column - len(label)))
        notes = []
        seconds = SPANS[index][1]
        # a span longer than the history shows all of it, as the whole history does
        if seconds and self._covered is not None and seconds >= self._covered:
            notes.append("all of it")
        if index == self._current:
            notes.append("(current)")
        text.append("  ".join(notes), style="dim")
        if index == self._current and self._zoomed:
            text.append(f"  {self.HINT}", style="italic")
        return text
