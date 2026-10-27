# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""a minimal rtnetlink client: the interfaces of the calling thread's network namespace, with
their kind and byte counters, and their addresses. stdlib only"""

from __future__ import annotations

import dataclasses
import ipaddress
import socket
import struct
from collections.abc import Iterator

NETLINK_ROUTE = 0
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLM_F_REQUEST, NLM_F_DUMP = 0x1, 0x300
RTM_GETLINK, RTM_GETADDR = 18, 22
IFLA_IFNAME, IFLA_LINKINFO, IFLA_STATS64 = 3, 18, 23
IFLA_INFO_KIND = 1
IFA_ADDRESS, IFA_LOCAL = 1, 2
NLA_TYPE_MASK = 0x3FFF

_NLMSGHDR = struct.Struct("=IHHII")
_IFINFOMSG = struct.Struct("=BxHiII")
_IFADDRMSG = struct.Struct("=BBBBI")
_RTATTR = struct.Struct("=HH")
# rtnl_link_stats64 starts with rx_packets, tx_packets, rx_bytes, tx_bytes
_STATS64_HEAD = struct.Struct("=QQQQ")


@dataclasses.dataclass
class Link:
    index: int
    name: str
    # IFLA_INFO_KIND: "tun", "veth", "wireguard", ...; "" for physical devices and lo
    kind: str
    rx_bytes: int
    tx_bytes: int


@dataclasses.dataclass
class Address:
    index: int
    addr: str
    prefixlen: int


def _align(n: int) -> int:
    return (n + 3) & ~3


def _attributes(data: bytes, offset: int) -> Iterator[tuple[int, bytes]]:
    while offset + _RTATTR.size <= len(data):
        length, kind = _RTATTR.unpack_from(data, offset)
        if length < _RTATTR.size:
            return
        yield kind & NLA_TYPE_MASK, data[offset + _RTATTR.size : offset + length]
        offset += _align(length)


def _dump(msg_type: int, body: bytes) -> Iterator[bytes]:
    """the payloads of a dump request's answer, one per object"""
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE) as sock:
        sock.settimeout(2)
        sock.bind((0, 0))
        sock.send(_NLMSGHDR.pack(_NLMSGHDR.size + len(body), msg_type, NLM_F_REQUEST | NLM_F_DUMP, 1, 0) + body)
        while True:
            data = sock.recv(65536)
            offset = 0
            while offset + _NLMSGHDR.size <= len(data):
                length, kind, _flags, _seq, _pid = _NLMSGHDR.unpack_from(data, offset)
                if length < _NLMSGHDR.size:
                    return
                if kind == NLMSG_DONE:
                    return
                if kind == NLMSG_ERROR:
                    errno = -struct.unpack_from("=i", data, offset + _NLMSGHDR.size)[0]
                    raise OSError(errno, f"rtnetlink request {msg_type} failed")
                yield data[offset + _NLMSGHDR.size : offset + length]
                offset += _align(length)


def links() -> list[Link]:
    result = []
    for payload in _dump(RTM_GETLINK, _IFINFOMSG.pack(socket.AF_UNSPEC, 0, 0, 0, 0)):
        _family, _type, index, _flags, _change = _IFINFOMSG.unpack_from(payload)
        name, kind, rx_bytes, tx_bytes = "", "", 0, 0
        for attr, value in _attributes(payload, _IFINFOMSG.size):
            if attr == IFLA_IFNAME:
                name = value.split(b"\0", 1)[0].decode(errors="replace")
            elif attr == IFLA_STATS64 and len(value) >= _STATS64_HEAD.size:
                _rx_packets, _tx_packets, rx_bytes, tx_bytes = _STATS64_HEAD.unpack_from(value)
            elif attr == IFLA_LINKINFO:
                for info, info_value in _attributes(value, 0):
                    if info == IFLA_INFO_KIND:
                        kind = info_value.split(b"\0", 1)[0].decode(errors="replace")
        result.append(Link(index, name, kind, rx_bytes, tx_bytes))
    return result


def addresses() -> list[Address]:
    result = []
    for payload in _dump(RTM_GETADDR, _IFADDRMSG.pack(socket.AF_UNSPEC, 0, 0, 0, 0)):
        family, prefixlen, _flags, _scope, index = _IFADDRMSG.unpack_from(payload)
        attrs = dict(_attributes(payload, _IFADDRMSG.size))
        # on a point-to-point link IFA_ADDRESS is the peer, IFA_LOCAL the address of this end
        raw = attrs.get(IFA_LOCAL) or attrs.get(IFA_ADDRESS)
        if raw is None or family not in (socket.AF_INET, socket.AF_INET6):
            continue
        result.append(Address(index, str(ipaddress.ip_address(raw)), prefixlen))
    return result
