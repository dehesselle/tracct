# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The manual's viewer sections, inside the viewer (, ? m).

The build cuts them out of docs/MANUAL.md into `manual.md` next to this module (see
hatch_build.py). A link within them scrolls to its heading; any other link is copied to
the clipboard rather than opened, since a browser started from a terminal over SSH may
be a text one that takes over the viewer's terminal.
"""

from __future__ import annotations

import posixpath
import re
from importlib.resources import files
from pathlib import PurePath
from typing import ClassVar

from tcoda.widgets import Footer
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import MarkdownViewer

from tracct.constants import VERSION

REPOSITORY = "https://github.com/dehesselle/tracct"

#: Shown when the build did not write manual.md, as in a checkout never synced.
MISSING = "This installation of tracct has no manual built in."


def read_manual() -> str:
    try:
        return files("tracct.viewer").joinpath("manual.md").read_text(encoding="utf-8")
    except FileNotFoundError:
        return MISSING


def link_url(href: str, version: str = VERSION) -> str:
    """The URL a link in the manual stands for.

    A relative link is to another file of the repository, relative to docs/, at the
    tag of this release, or on master for any other version.
    """
    if "://" in href:
        return href
    path, _, anchor = href.partition("#")
    ref = f"v{version}" if re.fullmatch(r"\d+(\.\d+)*", version) else "master"
    url = f"{REPOSITORY}/blob/{ref}/{posixpath.normpath(f'docs/{path}')}"
    return f"{url}#{anchor}" if anchor else url


class ManualViewer(MarkdownViewer):
    """The manual with its headings in a sidebar; links leave it only as text."""

    def __init__(self, markdown: str) -> None:
        super().__init__(markdown, show_table_of_contents=True, open_links=False)

    async def go(self, location: str | PurePath) -> None:
        href = str(location)
        if href.startswith("#"):
            await super().go(href)
            return
        url = link_url(href)
        self.app.copy_to_clipboard(url)
        self.app.notify(url, title="Link copied")


class ManualScreen(ModalScreen[None]):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        yield ManualViewer(read_manual())
        yield Footer(pinned=("escape",))

    def on_mount(self) -> None:
        # The document rather than the contents, so the arrow keys scroll it at once.
        self.query_one(ManualViewer).document.focus()
