# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The content of a tab, with a find on its top line.

The find narrows the rows shown by text; it is kept apart from the history tabs'
filters, which narrow what the query server is asked for. While the find input is
closed, a banner on the same line says what the tab has to say: a kept find, the
filters, or why it shows nothing.
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import DataTable, Input

from tracct.viewer.banner import Banner

FIND_PLACEHOLDER = "find in the rows shown (Enter keeps it, Escape clears)"


class FindablePane(Vertical):
    """A tab's content, below a find input and a banner that share its top line.

    Subclasses compose the rest in `compose_content`, narrow their rows in `apply_find`,
    and say what they have to say in `update_banner`.
    """

    DEFAULT_CSS = """
    FindablePane > .find { display: none; }
    FindablePane > .find.shown { display: block; }
    """
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("slash", "find", "Find"),
        # The banner says so while a find is kept.
        Binding("c", "clear_find", "Clear find", show=False),
        Binding("escape", "close_find", show=False),
    ]

    def __init__(self, *, id: str | None = None) -> None:
        super().__init__(id=id)
        #: The text the rows shown contain; empty shows all of them.
        self.find = ""

    def compose(self) -> ComposeResult:
        yield Input(classes="find", compact=True, placeholder=FIND_PLACEHOLDER)
        yield Banner()
        yield from self.compose_content()

    def compose_content(self) -> ComposeResult:
        """Compose what goes below the top line."""
        raise NotImplementedError

    def apply_find(self) -> None:
        """Show the rows that contain `find`."""
        raise NotImplementedError

    def update_banner(self) -> None:
        """Say what the tab has to say, or hide the banner when there is nothing."""
        raise NotImplementedError

    @property
    def find_input(self) -> Input:
        return self.query_one(".find", Input)

    def find_open(self) -> bool:
        """Whether the find input is shown, which then says the find itself."""
        return self.find_input.has_class("shown")

    def set_find(self, needle: str) -> None:
        self.find = needle
        self.apply_find()

    def focus_content(self) -> None:
        """Focus the tab's first table, so its keys apply."""
        self.query(DataTable).first().focus()

    def action_find(self) -> None:
        find = self.find_input
        find.value = self.find
        find.add_class("shown")
        find.focus()
        self.update_banner()

    def action_close_find(self) -> None:
        find = self.find_input
        if find.has_class("shown"):
            find.value = ""
            self.set_find("")
            find.remove_class("shown")
            self.update_banner()
            self.focus_content()

    def action_clear_find(self) -> None:
        if self.find:
            self.find_input.value = ""
            self.set_find("")

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input is self.find_input:
            event.stop()
            self.set_find(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input is self.find_input:
            event.stop()
            event.input.remove_class("shown")
            # A kept find goes to the banner, on the line the input leaves.
            self.update_banner()
            self.focus_content()
