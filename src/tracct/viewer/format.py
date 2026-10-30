# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Text for the viewer's cells: byte counts, users, protocols, times and durations, and
long values shortened."""

from __future__ import annotations

import functools
import pwd
import time

from rich.cells import cell_len, get_character_cell_size, set_cell_size
from rich.text import Text

from tracct.utils import sanitize_log_line

#: What `u` picks from; auto picks a unit per value.
BYTE_UNITS = ("auto", "B", "kB", "MB", "GB")
_FACTORS = {"kB": 10**3, "MB": 10**6, "GB": 10**9}
PROTOCOLS = {
    0: "",
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    33: "dccp",
    47: "gre",
    50: "esp",
    58: "icmpv6",
    132: "sctp",
    136: "udplite",
}


def format_bytes(n: float | None, byte_unit: str = "auto") -> str:
    n = n or 0
    if byte_unit == "B":
        return f"{int(n):,}"
    if byte_unit in _FACTORS:
        return f"{n / _FACTORS[byte_unit]:,.1f} {byte_unit}"
    for suffix in ("B", "kB", "MB", "GB", "TB"):
        if abs(n) < 1000 or suffix == "TB":
            return f"{int(n)} B" if suffix == "B" else f"{n:.1f} {suffix}"
        n /= 1000
    return ""


def bytes_cell(n: float | None, byte_unit: str = "auto") -> Text:
    return Text(format_bytes(n, byte_unit), justify="right")


@functools.lru_cache(maxsize=1024)
def user_name(uid: int) -> str:
    try:
        return f"{pwd.getpwuid(uid).pw_name} ({uid})"
    except KeyError:
        return str(uid)


def clean(value: object) -> str:
    """Return `value` on one line, without control characters.

    Command lines carry tabs and newlines.
    """
    text = (
        str(value)
        .replace("\0", " ")
        .replace("\t", " ")
        .replace("\n", " ")
        .replace("\r", " ")
    )
    return sanitize_log_line(text)


def _head(text: str, width: int) -> str:
    """The longest start of `text` that fits in `width` cells."""
    return set_cell_size(text, width).rstrip() if width > 0 else ""


def _tail(text: str, width: int) -> str:
    """The longest end of `text` that fits in `width` cells."""
    start, used = len(text), 0
    while start > 0:
        used += get_character_cell_size(text[start - 1])
        if used > width:
            break
        start -= 1
    return text[start:]


def shorten_path(text: str, width: int) -> str:
    """`text` in `width` cells at most, keeping its end: `…/lib/firefox/firefox`.

    Cut at a slash where one is left, so no directory shows only in part.
    """
    if cell_len(text) <= width:
        return text
    tail = _tail(text, width - 1)
    if "/" in tail:
        tail = tail[tail.index("/") :]
    return "…" + tail


def shorten_end(text: str, width: int) -> str:
    """`text` in `width` cells at most, keeping its start."""
    if cell_len(text) <= width:
        return text
    return _head(text, width - 1) + "…"


def shorten_host(host: str, port: int, width: int) -> str:
    """`host:port` in `width` cells at most, keeping the port and the host's end.

    The end of a domain says more than its start. Without a port (0), the host alone.
    """
    suffix = f":{port}" if port > 0 else ""
    if cell_len(host) + len(suffix) <= width:
        return host + suffix
    return "…" + _tail(host, width - 1 - len(suffix)) + suffix


def format_value(dimension: str, value: object) -> str:
    """Return a dimension's value as shown; a filter on it sends the value itself."""
    if value is None or value == "":
        return "(none)"
    if dimension == "uid" and isinstance(value, int):
        return user_name(value)
    if dimension == "protocol" and isinstance(value, int):
        return PROTOCOLS.get(value, str(value))
    if dimension in ("lport", "rport", "dport") and value == 0:
        return "0 (ephemeral or none)"
    return clean(value)


def value_cell(dimension: str, value: object) -> Text:
    """A cell that shows text as it is.

    A plain str in a DataTable would be read as markup.
    """
    text = format_value(dimension, value)
    return Text(text, style="dim" if value is None or value == "" else "")


def format_clock(t: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(t))


def format_time(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def duration(seconds: int) -> str:
    for size, suffix in ((86400, "d"), (3600, "h"), (60, "min")):
        if seconds >= size and seconds % size == 0:
            return f"{seconds // size} {suffix}"
    return f"{seconds} s"
