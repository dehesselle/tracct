# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Tests for the ctnetlink parser and the forwarded flow deltas.

The last test routes real traffic between two network namespaces through the host and
needs root.
"""

import ipaddress
import os
import shutil
import socket
import struct
import subprocess
import time

import pytest

from tracct import conntrack, netinfo


def _attr(kind: int, payload: bytes, nested: bool = False) -> bytes:
    length = 4 + len(payload)
    return (
        struct.pack("=HH", length, kind | (0x8000 if nested else 0))
        + payload
        + b"\0" * ((-length) % 4)
    )


def _tuple(
    kind: int, src: str, dst: str, protocol: int, sport: int, dport: int
) -> bytes:
    v6 = ipaddress.ip_address(src).version == 6
    ip = _attr(3 if v6 else 1, ipaddress.ip_address(src).packed) + _attr(
        4 if v6 else 2, ipaddress.ip_address(dst).packed
    )
    proto = (
        _attr(1, bytes([protocol]))
        + _attr(2, struct.pack(">H", sport))
        + _attr(3, struct.pack(">H", dport))
    )
    return _attr(kind, _attr(1, ip, True) + _attr(2, proto, True), True)


def _counters(kind: int, packets: int, nbytes: int) -> bytes:
    return _attr(
        kind,
        _attr(1, struct.pack(">Q", packets)) + _attr(2, struct.pack(">Q", nbytes)),
        True,
    )


def _message(
    ct_id: int,
    orig: tuple,
    reply: tuple,
    counters: tuple[int, int, int, int] | None = (100, 2000, 2, 3),
) -> bytes:
    """A ctnetlink payload.

    Nfgenmsg, the two tuples, counters (orig bytes, reply bytes, orig packets, reply
    packets) and the id, in the kernel's order.
    """
    payload = (
        struct.pack("=BBH", socket.AF_INET, 0, 0) + _tuple(1, *orig) + _tuple(2, *reply)
    )
    if counters is not None:
        payload += _counters(9, counters[2], counters[0]) + _counters(
            10, counters[3], counters[1]
        )
    return payload + _attr(12, struct.pack(">I", ct_id))


#: A peer of an exit node opening a connection that the host masquerades.
ORIG = ("100.64.0.2", "198.51.100.7", 6, 40000, 443)
REPLY = ("198.51.100.7", "203.0.113.1", 6, 443, 61000)


def test_parse_entry_reads_tuples_and_counters():
    flow_id, entry = conntrack.parse_entry(_message(7, ORIG, REPLY)) or (0, None)
    assert flow_id == 7
    assert entry == conntrack.Entry(
        6, "100.64.0.2", 40000, "198.51.100.7", 443, (100, 2000, 2, 3)
    )
    # A flow started while nf_conntrack_acct was off has no counters.
    assert conntrack.parse_entry(_message(7, ORIG, REPLY, None)) == (
        7,
        conntrack.Entry(6, "100.64.0.2", 40000, "198.51.100.7", 443, None),
    )


def test_quick_sources_find_both_ends():
    payload = _message(7, ORIG, REPLY)
    assert conntrack.quick_sources(payload) == (
        ipaddress.ip_address("100.64.0.2").packed,
        ipaddress.ip_address("198.51.100.7").packed,
    )
    host = conntrack.pack_addresses({"203.0.113.1"})
    # Masqueraded: the host's address is only the reply's destination, so it is
    # forwarded.
    assert not conntrack.is_local(payload, host)
    # Opened by the host, or answered by it.
    assert conntrack.is_local(
        _message(
            8,
            ("203.0.113.1", "198.51.100.7", 6, 50000, 443),
            ("198.51.100.7", "203.0.113.1", 6, 443, 50000),
        ),
        host,
    )
    assert conntrack.is_local(
        _message(
            9,
            ("198.51.100.7", "203.0.113.1", 6, 50000, 22),
            ("203.0.113.1", "198.51.100.7", 6, 22, 50000),
        ),
        host,
    )
    # Sent to a broadcast or multicast address: delivered here, never forwarded.
    assert conntrack.is_local(
        _message(
            11,
            ("172.31.1.1", "255.255.255.255", 17, 67, 68),
            ("255.255.255.255", "172.31.1.1", 17, 68, 67),
        ),
        frozenset(),
    )
    assert conntrack.is_local(
        _message(
            12, ("fe80::1", "ff02::1", 58, 0, 0), ("ff02::1", "fe80::1", 58, 0, 0)
        ),
        frozenset(),
    )
    v6 = _message(
        10,
        ("2001:db8::2", "2001:db8::7", 17, 5000, 53),
        ("2001:db8::7", "2001:db8::2", 17, 53, 5000),
    )
    assert conntrack.quick_sources(v6) == (
        ipaddress.ip_address("2001:db8::2").packed,
        ipaddress.ip_address("2001:db8::7").packed,
    )
    assert conntrack.quick_sources(b"\0" * 8) is None


def _entry(orig_bytes: int, reply_bytes: int) -> conntrack.Entry:
    return conntrack.Entry(
        6, "100.64.0.2", 40000, "198.51.100.7", 443, (orig_bytes, reply_bytes, 1, 1)
    )


def test_collect_reports_deltas():
    """The first dump is the baseline.

    Then each flow reports what it moved since the dump that saw it last, and an ended
    flow its last bytes from the destroy event.
    """
    dumps = [
        {1: _entry(100, 1000)},
        {1: _entry(150, 1500), 2: _entry(30, 300)},
        {2: _entry(40, 400)},
    ]
    tracker = conntrack.Conntrack(
        lambda msgid, message: None,
        set(),
        dumper=lambda local: dumps.pop(0),
        opener=None,
    )
    flows = tracker.collect(set())
    assert [(flow.orig_bytes, flow.reply_bytes) for flow in flows] == [
        (50, 500),
        (30, 300),
    ]
    # Flow 1 ended at 170/1700 between the dumps; flow 2 goes on.
    tracker.destroyed.append((1, _entry(170, 1700)))
    flows = tracker.collect(set())
    assert sorted((flow.orig_bytes, flow.reply_bytes) for flow in flows) == [
        (10, 100),
        (20, 200),
    ]
    assert set(tracker.seen) == {2}


def test_collect_reports_flows_without_counters_once():
    uncounted = conntrack.Entry(6, "100.64.0.2", 40000, "198.51.100.7", 443, None)
    dumps = [{}, {1: uncounted}, {1: uncounted, 2: _entry(30, 300)}]
    reports: list[tuple[str, ...]] = []
    tracker = conntrack.Conntrack(
        lambda *report: reports.append(report),
        set(),
        label="vpn1",
        dumper=lambda local: dumps.pop(0),
        opener=None,
    )
    assert tracker.collect(set()) == []
    assert [(flow.orig_bytes, flow.reply_bytes) for flow in tracker.collect(set())] == [
        (30, 300)
    ]
    [(msgid, message)] = reports
    assert msgid == "conntrack-no-counters"
    assert "vpn1" in message and "nf_conntrack_acct" in message


def test_trackers_follow_the_namespaces():
    """A namespace's first dump is its baseline.

    One that cannot be read is reported once and the others go on; one that has gone is
    closed.
    """
    # Each namespace's table, told apart by its local address.
    tables: dict[bytes, list] = {
        socket.inet_aton("10.0.0.1"): [
            {1: _entry(100, 1000)},
            {1: _entry(150, 1500)},
            {1: _entry(160, 1600)},
            {1: _entry(170, 1700)},
            {1: _entry(170, 1700)},
        ],
        socket.inet_aton("10.0.0.2"): [
            {},
            OSError("busy"),
            OSError("busy"),
            {1: _entry(5, 50)},
        ],
    }

    def dumper(local: frozenset[bytes]) -> dict[int, conntrack.Entry]:
        (address,) = local
        answer = tables[address].pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    reports: list[tuple[str, ...]] = []
    trackers = conntrack.Trackers(
        lambda *report: reports.append(report), dumper=dumper, listen=False
    )
    namespaces = {1: ("host", None, {"10.0.0.1"}), 2: ("vpn1", None, {"10.0.0.2"})}
    assert trackers.collect(namespaces) == []
    assert [(flow.netns, flow.orig_bytes) for flow in trackers.collect(namespaces)] == [
        (1, 50)
    ]
    assert [(flow.netns, flow.orig_bytes) for flow in trackers.collect(namespaces)] == [
        (1, 10)
    ]
    [(msgid, message)] = reports
    assert msgid == "conntrack-unreadable" and "vpn1" in message and "busy" in message
    # Vpn1 can be read again, counting from its baseline; then it goes away and is
    # closed.
    assert sorted(
        (flow.netns, flow.orig_bytes) for flow in trackers.collect(namespaces)
    ) == [(1, 10), (2, 5)]
    vpn1 = trackers.trackers[2]
    assert trackers.collect({1: namespaces[1]}) == []
    assert vpn1.closed.is_set() and set(trackers.trackers) == {1} and len(reports) == 1


@pytest.mark.skipif(
    os.geteuid() != 0
    or shutil.which("ip") is None
    or shutil.which("nft") is None
    or not os.path.exists(conntrack.ACCT_SYSCTL),
    reason="needs root, iproute2, nft and nf_conntrack",
)
def test_collect_sees_routed_traffic():
    """Two namespaces talk through the host.

    The host forwards, no local socket is involved.
    """
    # Docker sets the FORWARD policy to DROP, and a dropped packet's flow is never
    # committed; an accept in a table of our own would not get past it.
    iptables = shutil.which("iptables")
    rules = ["FORWARD -s 10.97.0.0/16 -j ACCEPT", "FORWARD -d 10.97.0.0/16 -j ACCEPT"]

    def sh(command: str) -> None:
        subprocess.run(command, shell=True, check=True, capture_output=True)

    def sysctl(path: str, value: str) -> str:
        with open(path) as f:
            before = f.read().strip()
        with open(path, "w") as f:
            f.write(value)
        return before

    acct = sysctl(conntrack.ACCT_SYSCTL, "1")
    forward = sysctl("/proc/sys/net/ipv4/ip_forward", "1")
    try:
        if iptables:
            for rule in rules:
                sh(f"{iptables} -I {rule}")
        # The kernel tracks flows in a namespace only once a rule there uses conntrack;
        # loading the module does not.
        sh(
            "nft 'add table inet psct; add chain inet psct forward { type filter hook forward priority 0; }; add rule inet psct forward ct state new,established accept'"
        )
        for i in (1, 2):
            sh(
                f"ip netns add psct{i} && ip link add psct{i}h type veth peer name psct{i}n && ip link set psct{i}n netns psct{i}"
            )
            sh(f"ip addr add 10.97.{i}.1/24 dev psct{i}h && ip link set psct{i}h up")
            sh(
                f"ip -n psct{i} addr add 10.97.{i}.2/24 dev psct{i}n && ip -n psct{i} link set psct{i}n up && ip -n psct{i} route add default via 10.97.{i}.1"
            )
        tracker = conntrack.Conntrack(
            lambda msgid, message: None, {"10.97.1.1", "10.97.2.1"}, opener=None
        )
        server = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                "psct2",
                "python3",
                "-c",
                "import socket; s = socket.create_server(('10.97.2.2', 8099)); c, _ = s.accept(); print(len(c.recv(65536)))",
            ]
        )
        time.sleep(0.5)
        sh(
            "ip netns exec psct1 python3 -c \"import socket; c = socket.create_connection(('10.97.2.2', 8099)); c.sendall(b'x' * 20000); c.close()\""
        )
        server.wait(10)
        flows = [
            flow
            for flow in tracker.collect({"10.97.1.1", "10.97.2.1"})
            if flow.dport == 8099
        ]
        assert [(flow.src, flow.dst, flow.protocol) for flow in flows] == [
            ("10.97.1.2", "10.97.2.2", 6)
        ]
        # Wire bytes: the payload and its headers.
        assert flows[0].orig_bytes >= 20000 and flows[0].orig_packets >= 3
    finally:
        for i in (1, 2):
            subprocess.run(
                f"ip netns del psct{i}; ip link del psct{i}h",
                shell=True,
                capture_output=True,
                check=False,
            )
        subprocess.run(
            "nft delete table inet psct", shell=True, capture_output=True, check=False
        )
        if iptables:
            for rule in rules:
                subprocess.run(
                    f"{iptables} -D {rule}",
                    shell=True,
                    capture_output=True,
                    check=False,
                )
        sysctl(conntrack.ACCT_SYSCTL, acct)
        sysctl("/proc/sys/net/ipv4/ip_forward", forward)


def _flush_conntrack() -> None:
    """Delete every entry of this thread's conntrack table, as conntrack -F does."""
    with conntrack._socket() as sock:
        body = conntrack._NFGENMSG.pack(socket.AF_INET, 0, 0)
        msg_type = (
            conntrack.NFNL_SUBSYS_CTNETLINK << 8
        ) | conntrack.IPCTNL_MSG_CT_DELETE
        sock.send(
            conntrack._NLMSGHDR.pack(
                conntrack._NLMSGHDR.size + len(body),
                msg_type,
                conntrack.NLM_F_REQUEST | 0x4,
                1,
                0,
            )
            + body
        )  # NLM_F_ACK
        sock.recv(65536)


@pytest.mark.skipif(
    os.geteuid() != 0
    or shutil.which("ip") is None
    or shutil.which("nft") is None
    or not os.path.exists(conntrack.ACCT_SYSCTL),
    reason="needs root, iproute2, nft and nf_conntrack",
)
def test_trackers_see_forwarding_inside_a_namespace():
    """A namespace routes between two others, as a VPN namespace that forwards would.

    Its own conntrack table is dumped from inside it, and its listener catches flows
    that end.
    """

    def sh(command: str) -> None:
        subprocess.run(command, shell=True, check=True, capture_output=True)

    trackers = None
    try:
        sh("ip netns add psfr")
        for side, i in (("a", 1), ("b", 2)):
            sh(
                f"ip netns add psf{side} && ip link add psf{side}0 netns psf{side} type veth peer name psfr{i} netns psfr"
            )
            sh(
                f"ip -n psf{side} addr add 10.98.{i}.2/24 dev psf{side}0 && ip -n psf{side} link set psf{side}0 up && ip -n psf{side} route add default via 10.98.{i}.1"
            )
            sh(
                f"ip -n psfr addr add 10.98.{i}.1/24 dev psfr{i} && ip -n psfr link set psfr{i} up"
            )
        # Forwarding with counters in the router only; the ct rule turns conntrack on
        # there.
        sh(
            "ip netns exec psfr sysctl -qw net.ipv4.ip_forward=1 net.netfilter.nf_conntrack_acct=1"
        )
        sh(
            "ip netns exec psfr nft 'add table inet psf; add chain inet psf forward { type filter hook forward priority 0; }; add rule inet psf forward ct state new,established accept'"
        )
        router = os.stat("/run/netns/psfr").st_ino
        namespaces = {router: ("psfr", "/run/netns/psfr", {"10.98.1.1", "10.98.2.1"})}
        reports: list[tuple[str, ...]] = []
        trackers = conntrack.Trackers(lambda *report: reports.append(report))
        assert trackers.collect(namespaces) == []

        def transfer(size: int) -> None:
            server = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    "psfb",
                    "python3",
                    "-c",
                    "import socket; s = socket.create_server(('10.98.2.2', 8098)); c, _ = s.accept()\nwhile c.recv(65536): pass",
                ]
            )
            time.sleep(0.5)
            sh(
                f"ip netns exec psfa python3 -c \"import socket; c = socket.create_connection(('10.98.2.2', 8098)); c.sendall(b'x' * {size}); c.close()\""
            )
            server.wait(10)

        transfer(20000)
        flows = [flow for flow in trackers.collect(namespaces) if flow.dport == 8098]
        assert [(flow.netns, flow.src, flow.dst, flow.protocol) for flow in flows] == [
            (router, "10.98.1.2", "10.98.2.2", 6)
        ]
        assert flows[0].orig_bytes >= 20000
        # A flow that ends between two collects is known from the destroy event alone.
        transfer(30000)
        netinfo.run_in_netns("/run/netns/psfr", _flush_conntrack)
        time.sleep(1)
        flows = [flow for flow in trackers.collect(namespaces) if flow.dport == 8098]
        assert len(flows) == 1 and flows[0].orig_bytes >= 30000
        assert reports == []
        trackers.collect({})
        assert trackers.trackers == {}
    finally:
        if trackers is not None:
            trackers.close()
        subprocess.run(
            "ip netns del psfa; ip netns del psfb; ip netns del psfr",
            shell=True,
            capture_output=True,
            check=False,
        )
