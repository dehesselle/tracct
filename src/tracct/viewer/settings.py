# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The viewer's settings, per user in its config directory.

They live in `~/.config/tracct/settings.json`. The chord `,` `s` in the viewer edits
them, and only values changed from their default are stored. Import `config` from here
or from `tcoda.settings`; it is the same object either way.

Read values at the point of use (`config.get(LIVE_EVENTS)`) rather than caching them, so
a change in the settings dialog takes effect without a restart.
"""

from __future__ import annotations

from tcoda.settings import Setting, config, configure

configure("tracct")

__all__ = ["LIVE_EVENTS", "LIVE_SUMMARY_ROWS", "Setting", "config"]

LIMIT_MIN = 10
LIMIT_MAX = 100000


def _limit(text: str) -> int:
    value = int(text)
    if not LIMIT_MIN <= value <= LIMIT_MAX:
        raise ValueError(f"not between {LIMIT_MIN} and {LIMIT_MAX}: {value}")
    return value


LIVE_SUMMARY_ROWS = Setting(
    key="live_summary_rows",
    label="summary rows kept",
    description=(
        "Rows of the summary table, one per executable and unit. Past this, the rows"
        f" idle the longest are dropped. {LIMIT_MIN} to {LIMIT_MAX}."
    ),
    group="Live",
    default=100,
    parse=_limit,
)

LIVE_EVENTS = Setting(
    key="live_events",
    label="events kept",
    description=(
        f"Rows of the events table, the newest ones. {LIMIT_MIN} to {LIMIT_MAX}."
    ),
    group="Live",
    default=500,
    parse=_limit,
)
