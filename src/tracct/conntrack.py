# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Forwarded traffic from the kernel's connection tracking (ctnetlink), for the packets
the host routes without any local socket: an exit node, NAT for containers or VMs.
Stdlib only.

Counters are read, never zeroed, so nothing else that reads them is disturbed: each dump
is compared with the previous one per conntrack id, and a listener on the destroy group
catches the final counters of flows that end in between. Every network namespace has a
table of its own; another namespace is dumped from inside it, and its listener socket is
opened there. The counters need nf_conntrack_acct=1 in each namespace, and the dump and
the group need CAP_NET_ADMIN.
"""

from __future__ import annotations

import collections
import dataclasses
import errno
import ipaddress
import os
import select
import socket
import struct
import threading
from collections.abc import Callable, Iterator, Mapping

from tracct.netinfo import run_in_netns

NETLINK_NETFILTER = 12
NFNL_SUBSYS_CTNETLINK = 1
IPCTNL_MSG_CT_GET, IPCTNL_MSG_CT_DELETE = 1, 2
NFNLGRP_CONNTRACK_DESTROY = 3
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLM_F_REQUEST, NLM_F_DUMP = 0x1, 0x300
CTA_TUPLE_ORIG, CTA_TUPLE_REPLY, CTA_COUNTERS_ORIG, CTA_COUNTERS_REPLY, CTA_ID = (
    1,
    2,
    9,
    10,
    12,
)
CTA_TUPLE_IP, CTA_TUPLE_PROTO = 1, 2
CTA_IP_V4_SRC, CTA_IP_V4_DST, CTA_IP_V6_SRC, CTA_IP_V6_DST = 1, 2, 3, 4
CTA_PROTO_NUM, CTA_PROTO_SRC_PORT, CTA_PROTO_DST_PORT = 1, 2, 3
CTA_COUNTERS_PACKETS, CTA_COUNTERS_BYTES = 1, 2
NLA_TYPE_MASK = 0x3FFF
ACCT_SYSCTL = "/proc/sys/net/netfilter/nf_conntrack_acct"
#: Ended flows held for the next collect; past it the oldest are dropped and counted.
DESTROYED_MAX = 262144
RECEIVE_BUFFER = 8 * 1024 * 1024
#: A dump inside another namespace that takes longer is given up (the socket's own limit
#: is 10 s).
DUMP_TIMEOUT = 15.0
#: How long the listener waits for events before it looks for closed trackers again.
LISTENER_POLL_MS = 500

_NLMSGHDR = struct.Struct("=IHHII")
_NFGENMSG = struct.Struct("=BBH")
_RTATTR = struct.Struct("=HH")


@dataclasses.dataclass(frozen=True)
class Flow:
    """Bytes and packets a forwarded flow moved since the last collect.

    Src is the side that opened it, dst the side that answered (after any destination
    NAT).
    """

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
    """One conntrack entry as read: its tuples and cumulative counters."""

    protocol: int
    orig_src: str
    orig_sport: int
    reply_src: str
    reply_sport: int
    #: Orig bytes, reply bytes, orig packets, reply packets; None when nf_conntrack_acct
    #: was off as the flow started.
    counters: tuple[int, int, int, int] | None


def _align(n: int) -> int:
    return (n + 3) & ~3


def _attributes(
    data: bytes, offset: int = 0, end: int | None = None
) -> dict[int, bytes]:
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
    """(src, dst, protocol, sport, dport) of a CTA_TUPLE_* attribute."""
    attrs = _attributes(data)
    ip = _attributes(attrs.get(CTA_TUPLE_IP, b""))
    proto = _attributes(attrs.get(CTA_TUPLE_PROTO, b""))
    src = ip.get(CTA_IP_V4_SRC) or ip.get(CTA_IP_V6_SRC)
    dst = ip.get(CTA_IP_V4_DST) or ip.get(CTA_IP_V6_DST)
    protocol = proto[CTA_PROTO_NUM][0] if CTA_PROTO_NUM in proto else 0
    sport = (
        struct.unpack(">H", proto[CTA_PROTO_SRC_PORT])[0]
        if CTA_PROTO_SRC_PORT in proto
        else 0
    )
    dport = (
        struct.unpack(">H", proto[CTA_PROTO_DST_PORT])[0]
        if CTA_PROTO_DST_PORT in proto
        else 0
    )
    return (
        str(ipaddress.ip_address(src)) if src else "",
        str(ipaddress.ip_address(dst)) if dst else "",
        protocol,
        sport,
        dport,
    )


def _counters(data: bytes | None) -> tuple[int, int] | None:
    """(bytes, packets) of a CTA_COUNTERS_* attribute."""
    if data is None:
        return None
    attrs = _attributes(data)
    if CTA_COUNTERS_BYTES not in attrs or CTA_COUNTERS_PACKETS not in attrs:
        return None
    return struct.unpack(">Q", attrs[CTA_COUNTERS_BYTES])[0], struct.unpack(
        ">Q", attrs[CTA_COUNTERS_PACKETS]
    )[0]


def _first_source(payload: bytes, offset: int) -> bytes:
    """The packed source address of the tuple attribute at offset, where the kernel puts
    it: the first attribute of its first attribute.
    """
    _ip_length, ip_kind = _RTATTR.unpack_from(payload, offset + _RTATTR.size)
    length, kind = _RTATTR.unpack_from(payload, offset + 2 * _RTATTR.size)
    if ip_kind & NLA_TYPE_MASK != CTA_TUPLE_IP or kind not in (
        CTA_IP_V4_SRC,
        CTA_IP_V6_SRC,
    ):
        raise ValueError("unexpected tuple layout")
    start = offset + 3 * _RTATTR.size
    return payload[start : start + length - _RTATTR.size]


def quick_sources(payload: bytes) -> tuple[bytes, bytes] | None:
    """The packed source addresses of the original and the reply tuple of a ctnetlink
    message, read without parsing it, which costs too much for every flow a busy host
    opens; None when the message is laid out otherwise.
    """
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
    """Whether a flow ends on this host.

    Its opening or its answering side is a local address, or it was sent to a broadcast
    or multicast address, which the kernel never forwards (the answering side of such a
    flow is the address it was sent to).
    """
    sources = quick_sources(payload)
    if sources is None:
        return False
    answering = sources[1]
    # IPv4 224/4 multicast and everything above (255.255.255.255 among it), IPv6
    # ff00::/8.
    if (len(answering) == 4 and answering[0] >= 224) or (
        len(answering) == 16 and answering[0] == 0xFF
    ):
        return True
    return sources[0] in local or answering in local


def parse_entry(payload: bytes) -> tuple[int, Entry] | None:
    """(conntrack id, entry) from a ctnetlink message's payload."""
    attrs = _attributes(payload, _NFGENMSG.size)
    if (
        CTA_ID not in attrs
        or CTA_TUPLE_ORIG not in attrs
        or CTA_TUPLE_REPLY not in attrs
    ):
        return None
    orig = _counters(attrs.get(CTA_COUNTERS_ORIG))
    reply = _counters(attrs.get(CTA_COUNTERS_REPLY))
    counters = (
        None
        if orig is None or reply is None
        else (orig[0], reply[0], orig[1], reply[1])
    )
    orig_src, _orig_dst, protocol, orig_sport, _orig_dport = _tuple(
        attrs[CTA_TUPLE_ORIG]
    )
    reply_src, _reply_dst, _protocol, reply_sport, _reply_dport = _tuple(
        attrs[CTA_TUPLE_REPLY]
    )
    return struct.unpack(">I", attrs[CTA_ID])[0], Entry(
        protocol, orig_src, orig_sport, reply_src, reply_sport, counters
    )


def _messages(data: bytes) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset + _NLMSGHDR.size <= len(data):
        length, kind, _flags, _seq, _pid = _NLMSGHDR.unpack_from(data, offset)
        if length < _NLMSGHDR.size:
            return
        yield kind, data[offset + _NLMSGHDR.size : offset + length]
        offset += _align(length)


def _socket(groups: int = 0) -> socket.socket:
    sock = socket.socket(
        socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC, NETLINK_NETFILTER
    )
    try:
        # Past the default limit, which only CAP_NET_ADMIN may do; the dump of a busy
        # table and a burst of ended flows both need the room.
        sock.setsockopt(socket.SOL_SOCKET, 33, RECEIVE_BUFFER)  # SO_RCVBUFFORCE
    except OSError:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECEIVE_BUFFER)
    sock.bind((0, groups))
    return sock


def dump(local: frozenset[bytes]) -> dict[int, Entry]:
    """Every conntrack entry in the calling thread's network namespace that does not end
    on this host (see is_local).
    """
    entries: dict[int, Entry] = {}
    with _socket() as sock:
        sock.settimeout(10)
        body = _NFGENMSG.pack(socket.AF_UNSPEC, 0, 0)
        msg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET
        sock.send(
            _NLMSGHDR.pack(
                _NLMSGHDR.size + len(body), msg_type, NLM_F_REQUEST | NLM_F_DUMP, 1, 0
            )
            + body
        )
        while True:
            for kind, payload in _messages(sock.recv(RECEIVE_BUFFER)):
                if kind == NLMSG_DONE:
                    return entries
                if kind == NLMSG_ERROR:
                    code = -struct.unpack_from("=i", payload)[0]
                    if code:
                        raise OSError(
                            code, f"conntrack dump failed: {os.strerror(code)}"
                        )
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


def listener_socket() -> socket.socket:
    """A socket on the destroy group of the calling thread's network namespace."""
    return _socket(1 << (NFNLGRP_CONNTRACK_DESTROY - 1))


class Conntrack:
    """Turns the conntrack table of one network namespace into forwarded flows, as
    deltas per collect. The first dump only sets the baseline, so traffic from before is
    not counted.
    """

    def __init__(
        self,
        report: Callable[[str], object],
        local: set[str],
        netns: int = 0,
        label: str = "host",
        path: str | None = None,
        dumper: Callable[[frozenset[bytes]], dict[int, Entry]] = dump,
        opener: Callable[[], socket.socket] | None = listener_socket,
    ) -> None:
        self.report = report
        self.dumper = dumper
        self.netns = netns or os.stat("/proc/self/ns/net").st_ino
        self.label = label
        #: The nsfs file to join for the dump, None for the daemon's own namespace.
        self.path = path
        #: The addresses of this namespace, packed; read by the listener thread,
        #: replaced by collect.
        self.local = pack_addresses(local)
        self.destroyed: collections.deque[tuple[int, Entry]] = collections.deque()
        self.lock = threading.Lock()
        self.lost = 0
        self.closed = threading.Event()
        self.uncounted_reported = False
        #: Opened before the baseline, so no flow that ends after it is missed; a
        #: Listener reads it and closes it once the tracker is closed.
        self.listener = self._enter(opener) if opener is not None else None
        self.watched = False
        try:
            #: The counters each forwarded flow had at the last collect.
            self.seen = self._enter(lambda: self.dumper(self.local))
        except BaseException:
            if self.listener is not None:
                self.listener.close()
            raise

    def _enter[T](self, function: Callable[[], T]) -> T:
        """Run function in this tracker's namespace."""
        if self.path is None:
            return function()
        return run_in_netns(self.path, function, DUMP_TIMEOUT)

    def receive(self) -> bool:
        """Take the ended flows waiting on the listener socket.

        False once it has failed.
        """
        listener = self.listener
        assert listener is not None
        while True:
            try:
                data = listener.recv(RECEIVE_BUFFER, socket.MSG_DONTWAIT)
            except BlockingIOError:
                return True
            except OSError as e:
                if e.errno == errno.ENOBUFS:
                    # The kernel dropped events: those flows' last bytes are missing.
                    with self.lock:
                        self.lost += 1
                    continue
                if not self.closed.is_set():
                    self.report(
                        f"conntrack: listener stopped in network namespace {self.label} ({e}); flows that end there go uncounted for their last window"
                    )
                return False
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
        """The forwarded flows that moved bytes since the last collect.

        Those whose opening side and answering side are both other hosts.
        """
        self.local = pack_addresses(local)
        current = self._enter(lambda: self.dumper(self.local))
        with self.lock:
            destroyed, self.destroyed = self.destroyed, collections.deque()
            lost, self.lost = self.lost, 0
        flows = []
        uncounted = 0

        def add(entry: Entry, before: Entry | None) -> None:
            nonlocal uncounted
            if entry.counters is None:
                uncounted += 1
                return
            delta = (
                entry.counters
                if before is None or before.counters is None
                else tuple(
                    now - then for now, then in zip(entry.counters, before.counters)
                )
            )
            # A negative delta is an id reused by another flow.
            if any(delta) and min(delta) >= 0:
                flows.append(
                    Flow(
                        self.netns,
                        entry.protocol,
                        entry.orig_src,
                        entry.orig_sport,
                        entry.reply_src,
                        entry.reply_sport,
                        *delta,
                    )
                )

        for flow_id, entry in current.items():
            add(entry, self.seen.get(flow_id))
        # Ended flows: what they moved after the dump that saw them last, this one or
        # the one before.
        for flow_id, entry in destroyed:
            add(entry, current.pop(flow_id, None) or self.seen.get(flow_id))
        self.seen = current
        if lost:
            self.report(
                f"conntrack: {lost} ended flow event(s) lost in network namespace {self.label}; the last bytes of those flows are missing"
            )
        if uncounted and not self.uncounted_reported:
            self.uncounted_reported = True
            self.report(
                f"conntrack: forwarded flows in network namespace {self.label} carry no counters and go unrecorded;"
                " set net.netfilter.nf_conntrack_acct = 1 there, or load nf_conntrack with acct=1 for every namespace"
            )
        return flows

    def close(self) -> None:
        self.closed.set()
        if self.listener is not None and not self.watched:
            self.listener.close()


class Listener:
    """One thread reading the ended flows of every tracker added to it.

    It alone closes their sockets, once a tracker is closed, so no socket is closed
    while it is polled.
    """

    def __init__(self) -> None:
        self.trackers: dict[int, Conntrack] = {}
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        threading.Thread(target=self._run, name="conntrack", daemon=True).start()

    def add(self, tracker: Conntrack) -> None:
        assert tracker.listener is not None
        with self.lock:
            tracker.watched = True
            self.trackers[tracker.listener.fileno()] = tracker

    def _close(self, everything: bool) -> dict[int, Conntrack]:
        """Close the sockets of the closed trackers, or of all.

        Returns the trackers left.
        """
        with self.lock:
            for fd, tracker in list(self.trackers.items()):
                if everything or tracker.closed.is_set():
                    del self.trackers[fd]
                    tracker.closed.set()
                    assert tracker.listener is not None
                    tracker.listener.close()
            return dict(self.trackers)

    def _run(self) -> None:
        try:
            while not self.stopped.is_set():
                watched = self._close(False)
                poll = select.poll()
                for fd in watched:
                    poll.register(fd, select.POLLIN)
                # Also paces the loop while nothing is watched.
                for fd, _event in poll.poll(LISTENER_POLL_MS):
                    tracker = watched[fd]
                    if not tracker.closed.is_set() and not tracker.receive():
                        tracker.closed.set()
        finally:
            self._close(True)

    def stop(self) -> None:
        self.stopped.set()


class Trackers:
    """A Conntrack per network namespace, following the namespaces the writer knows.

    A namespace seen for the first time only sets its baseline; the tracker of one that
    has gone is closed, so its listener socket holds the namespace until the next
    collect at most.
    """

    def __init__(
        self,
        report: Callable[[str], object],
        dumper: Callable[[frozenset[bytes]], dict[int, Entry]] = dump,
        listen: bool = True,
    ) -> None:
        self.report = report
        self.dumper = dumper
        self.listener = Listener() if listen else None
        self.trackers: dict[int, Conntrack] = {}
        #: Namespaces whose table could not be read, reported once until it can.
        self.failed: set[int] = set()

    def collect(
        self, namespaces: Mapping[int, tuple[str, str | None, set[str]]]
    ) -> list[Flow]:
        """The forwarded flows of every namespace since the last collect.

        Namespaces maps an inode to (label, the path to join or None for the daemon's
        own, its local addresses).
        """
        for inode in [inode for inode in self.trackers if inode not in namespaces]:
            self.trackers.pop(inode).close()
        self.failed &= set(namespaces)
        flows = []
        for inode, (label, path, local) in namespaces.items():
            try:
                tracker = self.trackers.get(inode)
                if tracker is None:
                    tracker = Conntrack(
                        self.report,
                        local,
                        inode,
                        label,
                        path,
                        self.dumper,
                        listener_socket if self.listener is not None else None,
                    )
                    self.trackers[inode] = tracker
                    if self.listener is not None:
                        self.listener.add(tracker)
                else:
                    # An unnamed namespace is joined through whichever process was seen
                    # in it last.
                    tracker.label, tracker.path = label, path
                    flows += tracker.collect(local)
                self.failed.discard(inode)
            except Exception as e:
                if inode not in self.failed:
                    self.failed.add(inode)
                    self.report(
                        f"conntrack: cannot read the table of network namespace {label} ({e}); its forwarded traffic goes unrecorded"
                    )
        return flows

    def close(self) -> None:
        for tracker in self.trackers.values():
            tracker.close()
        self.trackers = {}
        if self.listener is not None:
            self.listener.stop()
