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

    def __init__(self) -> None:
        super().__init__()
        # Kept rather than queried, so say() works before they are mounted: a missing
        # query server is reported before then.
        self.text = Static(classes="banner-text")
        self.hint = Static(classes="banner-hint")

    def compose(self) -> ComposeResult:
        yield self.text
        yield self.hint

    def say(self, notes: list[str], hint: str = "", error: bool = False) -> None:
        """The notes joined with " · ", and no banner without any.

        The hint dim on the right.
        """
        self.display = bool(notes)
        self.set_class(error, "-error")
        self.text.update(Text(" · ".join(notes)))
        self.hint.display = bool(hint)
        self.hint.update(Text(hint, style="dim italic"))
