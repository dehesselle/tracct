"""forwarded traffic from the kernel's connection tracking (ctnetlink), for the packets the host
routes without any local socket: an exit node, NAT for containers or VMs. stdlib only.

counters are read, never zeroed, so nothing else that reads them is disturbed: each dump is
compared with the previous one per conntrack id, and a listener on the destroy group catches
the final counters of flows that end in between. the counters need nf_conntrack_acct=1, and
the dump and the group need CAP_NET_ADMIN"""

from __future__ import annotations

import collections
import dataclasses
import errno
import ipaddress
import os
import socket
import struct
import threading
from collections.abc import Callable, Iterator

NETLINK_NETFILTER = 12
NFNL_SUBSYS_CTNETLINK = 1
IPCTNL_MSG_CT_GET, IPCTNL_MSG_CT_DELETE = 1, 2
NFNLGRP_CONNTRACK_DESTROY = 3
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLM_F_REQUEST, NLM_F_DUMP = 0x1, 0x300
CTA_TUPLE_ORIG, CTA_TUPLE_REPLY, CTA_COUNTERS_ORIG, CTA_COUNTERS_REPLY, CTA_ID = 1, 2, 9, 10, 12
CTA_TUPLE_IP, CTA_TUPLE_PROTO = 1, 2
CTA_IP_V4_SRC, CTA_IP_V4_DST, CTA_IP_V6_SRC, CTA_IP_V6_DST = 1, 2, 3, 4
CTA_PROTO_NUM, CTA_PROTO_SRC_PORT, CTA_PROTO_DST_PORT = 1, 2, 3
CTA_COUNTERS_PACKETS, CTA_COUNTERS_BYTES = 1, 2
NLA_TYPE_MASK = 0x3FFF
ACCT_SYSCTL = "/proc/sys/net/netfilter/nf_conntrack_acct"
# ended flows held for the next collect; past it the oldest are dropped and counted
DESTROYED_MAX = 262144
RECEIVE_BUFFER = 8 * 1024 * 1024

_NLMSGHDR = struct.Struct("=IHHII")
_NFGENMSG = struct.Struct("=BBH")
_RTATTR = struct.Struct("=HH")


@dataclasses.dataclass(frozen=True)
class Flow:
    """bytes and packets a forwarded flow moved since the last collect; src is the side that
    opened it, dst the side that answered (after any destination NAT)"""

    netns: int
    protocol: int
    src: str
    sport: int
    dst: str
    dport: int
    orig_bytes: int
    reply_bytes: int
    orig_packets: int
    reply_packets: int


@dataclasses.dataclass
class Entry:
    """one conntrack entry as read: its tuples and cumulative counters"""

    protocol: int
    orig_src: str
    orig_sport: int
    reply_src: str
    reply_sport: int
    counters: tuple[int, int, int, int]  # orig bytes, reply bytes, orig packets, reply packets


def _align(n: int) -> int:
    return (n + 3) & ~3


def _attributes(data: bytes, offset: int = 0, end: int | None = None) -> dict[int, bytes]:
    attrs = {}
    end = len(data) if end is None else end
    while offset + _RTATTR.size <= end:
        length, kind = _RTATTR.unpack_from(data, offset)
        if length < _RTATTR.size:
            break
        attrs[kind & NLA_TYPE_MASK] = data[offset + _RTATTR.size : offset + length]
        offset += _align(length)
    return attrs


def _tuple(data: bytes) -> tuple[str, str, int, int, int]:
    """(src, dst, protocol, sport, dport) of a CTA_TUPLE_* attribute"""
    attrs = _attributes(data)
    ip = _attributes(attrs.get(CTA_TUPLE_IP, b""))
    proto = _attributes(attrs.get(CTA_TUPLE_PROTO, b""))
    src = ip.get(CTA_IP_V4_SRC) or ip.get(CTA_IP_V6_SRC)
    dst = ip.get(CTA_IP_V4_DST) or ip.get(CTA_IP_V6_DST)
    protocol = proto[CTA_PROTO_NUM][0] if CTA_PROTO_NUM in proto else 0
    sport = struct.unpack(">H", proto[CTA_PROTO_SRC_PORT])[0] if CTA_PROTO_SRC_PORT in proto else 0
    dport = struct.unpack(">H", proto[CTA_PROTO_DST_PORT])[0] if CTA_PROTO_DST_PORT in proto else 0
    return (str(ipaddress.ip_address(src)) if src else "", str(ipaddress.ip_address(dst)) if dst else "", protocol, sport, dport)


def _counters(data: bytes | None) -> tuple[int, int] | None:
    """(bytes, packets) of a CTA_COUNTERS_* attribute"""
    if data is None:
        return None
    attrs = _attributes(data)
    if CTA_COUNTERS_BYTES not in attrs or CTA_COUNTERS_PACKETS not in attrs:
        return None
    return struct.unpack(">Q", attrs[CTA_COUNTERS_BYTES])[0], struct.unpack(">Q", attrs[CTA_COUNTERS_PACKETS])[0]


def _first_source(payload: bytes, offset: int) -> bytes:
    """the packed source address of the tuple attribute at offset, where the kernel puts it:
    the first attribute of its first attribute"""
    _ip_length, ip_kind = _RTATTR.unpack_from(payload, offset + _RTATTR.size)
    length, kind = _RTATTR.unpack_from(payload, offset + 2 * _RTATTR.size)
    if ip_kind & NLA_TYPE_MASK != CTA_TUPLE_IP or kind not in (CTA_IP_V4_SRC, CTA_IP_V6_SRC):
        raise ValueError("unexpected tuple layout")
    start = offset + 3 * _RTATTR.size
    return payload[start : start + length - _RTATTR.size]


def quick_sources(payload: bytes) -> tuple[bytes, bytes] | None:
    """the packed source addresses of the original and the reply tuple of a ctnetlink message,
    read without parsing it, which costs too much for every flow a busy host opens; None when
    the message is laid out otherwise"""
    try:
        offset = _NFGENMSG.size
        length, kind = _RTATTR.unpack_from(payload, offset)
        if kind & NLA_TYPE_MASK != CTA_TUPLE_ORIG:
            return None
        reply = offset + _align(length)
        _reply_length, reply_kind = _RTATTR.unpack_from(payload, reply)
        if reply_kind & NLA_TYPE_MASK != CTA_TUPLE_REPLY:
            return None
        return _first_source(payload, offset), _first_source(payload, reply)
    except (struct.error, ValueError):
        return None


def is_local(payload: bytes, local: frozenset[bytes]) -> bool:
    """whether a flow ends on this host: its opening or its answering side is a local address,
    or it was sent to a broadcast or multicast address, which the kernel never forwards (the
    answering side of such a flow is the address it was sent to)"""
    sources = quick_sources(payload)
    if sources is None:
        return False
    answering = sources[1]
    # IPv4 224/4 multicast and everything above (255.255.255.255 among it), IPv6 ff00::/8
    if (len(answering) == 4 and answering[0] >= 224) or (len(answering) == 16 and answering[0] == 0xFF):
        return True
    return sources[0] in local or answering in local


def parse_entry(payload: bytes) -> tuple[int, Entry] | None:
    """(conntrack id, entry) from a ctnetlink message's payload; None without counters"""
    attrs = _attributes(payload, _NFGENMSG.size)
    if CTA_ID not in attrs or CTA_TUPLE_ORIG not in attrs or CTA_TUPLE_REPLY not in attrs:
        return None
    orig = _counters(attrs.get(CTA_COUNTERS_ORIG))
    reply = _counters(attrs.get(CTA_COUNTERS_REPLY))
    if orig is None or reply is None:
        # nf_conntrack_acct was off when the flow started
        return None
    orig_src, _orig_dst, protocol, orig_sport, _orig_dport = _tuple(attrs[CTA_TUPLE_ORIG])
    reply_src, _reply_dst, _protocol, reply_sport, _reply_dport = _tuple(attrs[CTA_TUPLE_REPLY])
    entry = Entry(protocol, orig_src, orig_sport, reply_src, reply_sport, (orig[0], reply[0], orig[1], reply[1]))
    return struct.unpack(">I", attrs[CTA_ID])[0], entry


def _messages(data: bytes) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset + _NLMSGHDR.size <= len(data):
        length, kind, _flags, _seq, _pid = _NLMSGHDR.unpack_from(data, offset)
        if length < _NLMSGHDR.size:
            return
        yield kind, data[offset + _NLMSGHDR.size : offset + length]
        offset += _align(length)


def _socket(groups: int = 0) -> socket.socket:
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC, NETLINK_NETFILTER)
    try:
        # past the default limit, which only CAP_NET_ADMIN may do; the dump of a busy table and
        # a burst of ended flows both need the room
        sock.setsockopt(socket.SOL_SOCKET, 33, RECEIVE_BUFFER)  # SO_RCVBUFFORCE
    except OSError:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECEIVE_BUFFER)
    sock.bind((0, groups))
    return sock


def dump(local: frozenset[bytes]) -> dict[int, Entry]:
    """every conntrack entry with counters in the calling thread's network namespace that does
    not end on this host (see is_local)"""
    entries: dict[int, Entry] = {}
    with _socket() as sock:
        sock.settimeout(10)
        body = _NFGENMSG.pack(socket.AF_UNSPEC, 0, 0)
        msg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET
        sock.send(_NLMSGHDR.pack(_NLMSGHDR.size + len(body), msg_type, NLM_F_REQUEST | NLM_F_DUMP, 1, 0) + body)
        while True:
            for kind, payload in _messages(sock.recv(RECEIVE_BUFFER)):
                if kind == NLMSG_DONE:
                    return entries
                if kind == NLMSG_ERROR:
                    code = -struct.unpack_from("=i", payload)[0]
                    if code:
                        raise OSError(code, f"conntrack dump failed: {os.strerror(code)}")
                    continue
                if is_local(payload, local):
                    continue
                parsed = parse_entry(payload)
                if parsed is not None:
                    entries[parsed[0]] = parsed[1]


def pack_addresses(addresses: set[str]) -> frozenset[bytes]:
    packed = set()
    for address in addresses:
        try:
            packed.add(ipaddress.ip_address(address).packed)
        except ValueError:
            continue
    return frozenset(packed)


class Conntrack:
    """turns the conntrack table of the daemon's own namespace into forwarded flows, as deltas
    per collect. the first dump only sets the baseline, so traffic from before the start is not
    counted"""

    def __init__(self, report: Callable[[str], object], local: set[str], dumper: Callable[[frozenset[bytes]], dict[int, Entry]] = dump, listen: bool = True) -> None:
        self.report = report
        self.dumper = dumper
        self.netns = os.stat("/proc/self/ns/net").st_ino
        # the addresses of this host, packed; read by the listener thread, replaced by collect
        self.local = pack_addresses(local)
        try:
            with open(ACCT_SYSCTL, "r") as f:
                if f.read().strip() == "0":
                    report("conntrack: net.netfilter.nf_conntrack_acct is 0, so flows carry no counters and forwarded traffic goes unrecorded; set it to 1")
        except OSError:
            pass
        # the counters each forwarded flow had at the last collect
        self.seen = self.dumper(self.local)
        self.destroyed: collections.deque[tuple[int, Entry]] = collections.deque()
        self.lock = threading.Lock()
        self.lost = 0
        self.closed = threading.Event()
        self.listener: socket.socket | None = None
        if listen:
            self.listener = _socket(1 << (NFNLGRP_CONNTRACK_DESTROY - 1))
            threading.Thread(target=self._listen, name="conntrack", daemon=True).start()

    def _listen(self) -> None:
        listener = self.listener
        assert listener is not None
        while not self.closed.is_set():
            try:
                data = listener.recv(RECEIVE_BUFFER)
            except OSError as e:
                if self.closed.is_set():
                    return
                if e.errno == errno.ENOBUFS:
                    # the kernel dropped events: those flows' last bytes are missing
                    with self.lock:
                        self.lost += 1
                    continue
                self.report(f"conntrack: listener stopped ({e}); flows that end go uncounted for their last window")
                return
            local = self.local
            for kind, payload in _messages(data):
                if kind & 0xFF != IPCTNL_MSG_CT_DELETE or is_local(payload, local):
                    continue
                parsed = parse_entry(payload)
                if parsed is not None:
                    with self.lock:
                        self.destroyed.append(parsed)
                        if len(self.destroyed) > DESTROYED_MAX:
                            self.destroyed.popleft()
                            self.lost += 1

    def collect(self, local: set[str]) -> list[Flow]:
        """the forwarded flows that moved bytes since the last collect: those whose opening
        side and answering side are both other hosts"""
        self.local = pack_addresses(local)
        current = self.dumper(self.local)
        with self.lock:
            destroyed, self.destroyed = self.destroyed, collections.deque()
            lost, self.lost = self.lost, 0
        flows = []

        def add(entry: Entry, before: Entry | None) -> None:
            delta = entry.counters if before is None else tuple(now - then for now, then in zip(entry.counters, before.counters))
            # a negative delta is an id reused by another flow
            if any(delta) and min(delta) >= 0:
                flows.append(Flow(self.netns, entry.protocol, entry.orig_src, entry.orig_sport, entry.reply_src, entry.reply_sport, *delta))

        for flow_id, entry in current.items():
            add(entry, self.seen.get(flow_id))
        # ended flows: what they moved after the dump that saw them last, this one or the one before
        for flow_id, entry in destroyed:
            add(entry, current.pop(flow_id, None) or self.seen.get(flow_id))
        self.seen = current
        if lost:
            self.report(f"conntrack: {lost} ended flow event(s) lost; the last bytes of those flows are missing")
        return flows

    def close(self) -> None:
        self.closed.set()
        if self.listener is not None:
            try:
                self.listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.listener.close()
