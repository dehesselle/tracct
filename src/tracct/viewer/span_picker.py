# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""the span of the history tabs, picked from a list rather than cycled through, so a choice is
one reload and not one per span passed on the way; laid out like nivaria's PickerDialog, until
a picker moves to tcoda"""

from __future__ import annotations

from typing import ClassVar

from rich.text import Text
from tcoda.dialogs import Dialog
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Input, Label, OptionList
from textual.widgets.option_list import Option

from tracct.viewer.format import SPANS


def span_label(index: int) -> str:
    name = SPANS[index][0]
    return "all history" if name == "all" else name


class SpanPicker(Dialog[int]):
    """pick an index of SPANS, or dismiss with None"""

    DEFAULT_CSS = """
    SpanPicker > #dialog { width: 40; max-height: 80%; }
    SpanPicker #picker-query { margin: 1 0; }
    SpanPicker #picker-results { height: auto; max-height: 20; }
    """
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("down", "to_list", show=False),
        Binding("enter", "choose", show=False),
    ]

    def __init__(self, current: int, covered: int | None) -> None:
        """covered is how many seconds of history there are, None if not known"""
        super().__init__()
        self._current = current
        self._covered = covered
        # shortest first, the whole history last
        self._order = sorted(range(len(SPANS)), key=lambda i: SPANS[i][1] or float("inf"))
        self._shown: list[int] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Span", id="title")
            yield Input(placeholder="type to filter", id="picker-query")
            yield OptionList(id="picker-results")

    def on_mount(self) -> None:
        self._refresh("")
        self.query_one("#picker-query", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        self._refresh(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.action_choose()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.dismiss(self._shown[event.option_index])

    def action_to_list(self) -> None:
        if self._shown:
            self.query_one("#picker-results", OptionList).focus()

    def action_choose(self) -> None:
        if self._shown:
            self.dismiss(self._shown[self.query_one("#picker-results", OptionList).highlighted or 0])

    def _refresh(self, needle: str) -> None:
        self._shown = [i for i in self._order if needle.lower() in span_label(i)]
        options = self.query_one("#picker-results", OptionList)
        options.clear_options()
        options.add_options([Option(self._text(i)) for i in self._shown])
        if self._shown:
            # on the current span while nothing is typed, else on the first match
            options.highlighted = self._shown.index(self._current) if not needle and self._current in self._shown else 0

    def _text(self, index: int) -> Text:
        text = Text(span_label(index))
        notes = []
        seconds = SPANS[index][1]
        # a span longer than the history shows all of it, as the whole history does
        if seconds and self._covered is not None and seconds >= self._covered:
            notes.append("all of it")
        if index == self._current:
            notes.append("(current)")
        if notes:
            text.append(f"  {'  '.join(notes)}", style="dim")
        return text
