# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""`tracct view`: the live feed and the history in one Textual app (tracct[tui]). it needs
no capabilities, only access to the daemon's events.sock and the query server's socket.
the package imports without Textual, so the command line can be built without it"""

from __future__ import annotations

import argparse
from pathlib import Path

from tracct.live_feed import EVENTS_SOCKET_PATH
from tracct.query import QUERY_SOCKET_PATH

# tab id -> (title, query source); live first, then the history tabs, which share the plot's
# time range, in alphabetical order
TABS = {
    "live": ("Live", ""),
    "forwarded": ("Forwarded", "forwarded"),
    "interfaces": ("Interfaces", "interfaces"),
    "processes": ("Processes", "connections"),
}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tab",
        choices=list(TABS),
        default="processes",
        help="the tab to start on (default: processes)",
    )
    parser.add_argument(
        "--events-socket",
        type=Path,
        default=EVENTS_SOCKET_PATH,
        help=f"the daemon's live feed (default: {EVENTS_SOCKET_PATH})",
    )
    parser.add_argument(
        "--query-socket",
        type=Path,
        default=QUERY_SOCKET_PATH,
        help=f"the query server (default: {QUERY_SOCKET_PATH})",
    )


def run_viewer(args: argparse.Namespace) -> int:
    """raises ImportError without Textual"""
    from tracct.viewer.app import TracctApp

    TracctApp(args.events_socket, args.query_socket, args.tab).run()
    return 0
