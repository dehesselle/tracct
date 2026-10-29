# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The daemon's runtime messages, each with an ID that the line shows and a level."""

import logging
import typing

from tracct.utils import sanitize_log_line

__all__ = ["DEFAULTS", "LEVEL_NAMES", "report", "set_levels"]

#: The levels [log] can give a message; off leaves it out.
LEVEL_NAMES: typing.Final[dict[str, int | None]] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "off": None,
}

#: Every message ID with its default level.
DEFAULTS: typing.Final[dict[str, int]] = {
    "bpf-requirements-failed": logging.ERROR,
    "bpf-init-failed": logging.ERROR,
    "bpf-attach-failed": logging.ERROR,
    "hook-skipped": logging.WARNING,
    "hook-failed": logging.ERROR,
    "dns-uprobe-missing": logging.WARNING,
    "drain-failed": logging.ERROR,
    "drain-entry-failed": logging.ERROR,
    "monitor-failed": logging.ERROR,
    "map-near-capacity": logging.WARNING,
    "exec-ring-full": logging.WARNING,
    "dns-ring-full": logging.WARNING,
    "multi-call-inode": logging.WARNING,
    "writer-queue-full": logging.WARNING,
    "live-feed-queue-full": logging.WARNING,
    "live-feed-subscribers-dropped": logging.WARNING,
    "thread-died": logging.ERROR,
    "resumed-from-suspend": logging.INFO,
    "live-feed-group": logging.WARNING,
    "sqlite-retry": logging.WARNING,
    "retry-buffer-full": logging.WARNING,
    "writer-failed": logging.ERROR,
    "database-unusable": logging.ERROR,
    "retention-skipped": logging.ERROR,
    "maintenance-done": logging.INFO,
    "maintenance-clock-jump": logging.WARNING,
    "clock-went-back": logging.WARNING,
    "conntrack-unreadable": logging.WARNING,
    "conntrack-no-counters": logging.WARNING,
    "conntrack-events-lost": logging.WARNING,
    "conntrack-listener-stopped": logging.WARNING,
    "netns-unreadable": logging.WARNING,
}

#: The level each message is logged at; None leaves it out.
LEVELS: dict[str, int | None] = dict(DEFAULTS)


def set_levels(levels: dict[str, str]) -> None:
    """Give messages the levels named in [log], the others their defaults.

    Called before the threads start.
    """
    LEVELS.clear()
    LEVELS.update(DEFAULTS)
    LEVELS.update((msgid, LEVEL_NAMES[name]) for msgid, name in levels.items())


def report(logger: logging.Logger, msgid: str, message: str) -> None:
    """Log a runtime message under its ID, at its level.

    Messages carry comm, cmdline and domain strings, so they are sanitized.
    """
    level = LEVELS[msgid]
    if level is not None:
        logger.log(level, f"[{msgid}] {sanitize_log_line(message)}")
