# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Text for the viewer's cells: byte counts, users, protocols, times and durations."""

from __future__ import annotations

import functools
import pwd
import time

from rich.text import Text

from tracct.utils import sanitize_log_line

FIND_PLACEHOLDER = "find in the rows shown (Enter keeps it, Escape clears)"
# what `u` picks from; auto picks a unit per value
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


def format_bytes(n: int | float | None, byte_unit: str = "auto") -> str:
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


def bytes_cell(n: int | float | None, byte_unit: str = "auto") -> Text:
    return Text(format_bytes(n, byte_unit), justify="right")


@functools.lru_cache(maxsize=1024)
def user_name(uid: int) -> str:
    try:
        return f"{pwd.getpwuid(uid).pw_name} ({uid})"
    except KeyError:
        return str(uid)


def clean(value: object) -> str:
    """a value on one line, without control characters (command lines carry tabs and newlines)"""
    text = (
        str(value)
        .replace("\0", " ")
        .replace("\t", " ")
        .replace("\n", " ")
        .replace("\r", " ")
    )
    return sanitize_log_line(text)


def format_value(dimension: str, value: object) -> str:
    """a dimension's value as shown; the value itself is what a filter on it sends back"""
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
    """a cell that shows text as it is: a plain str in a DataTable would be read as markup"""
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
