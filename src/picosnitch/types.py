# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import typing


class BpfEvent(typing.TypedDict):
    """Process and connection data for each event captured by the BPF program, handed from the reader to the writer and the live feed"""

    pid: int
    name: str
    dev: int
    ino: int
    exe: str
    cmdline: str
    ppid: int
    pname: str
    pdev: int
    pino: int
    pexe: str
    pcmdline: str
    uid: int
    send: int
    recv: int
    # packets in a drained connection entry; other events count as one
    pkts: typing.NotRequired[int]
    family: int
    protocol: int
    lport: int
    rport: int
    laddr: str
    raddr: str
    domain: str
    netns: int
