# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The line above a tab's tables, shown only while there is something to say.

A problem, a kept find, filters; with a hint on the right for the keys that undo them.
"""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static


class Banner(Horizontal):
    DEFAULT_CLASSES = "banner"
    DEFAULT_CSS = """
    Banner { height: auto; padding: 0 1; background: $foreground 8%; display: none; }
    Banner.-error { color: $text-error; }
    Banner .banner-text { width: 1fr; }
    Banner .banner-hint { width: auto; }
    """

    def compose(self) -> ComposeResult:
        yield Static(classes="banner-text")
        yield Static(classes="banner-hint")

    def say(self, notes: list[str], hint: str = "", error: bool = False) -> None:
        """The notes joined with " · ", and no banner without any.

        The hint dim on the right.
        """
        self.display = bool(notes)
        self.set_class(error, "-error")
        self.query_one(".banner-text", Static).update(Text(" · ".join(notes)))
        hint_static = self.query_one(".banner-hint", Static)
        hint_static.display = bool(hint)
        hint_static.update(Text(hint, style="dim italic"))
