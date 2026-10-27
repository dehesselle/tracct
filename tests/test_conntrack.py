"""Tests for the ctnetlink parser and the forwarded flow deltas; the last test routes real
traffic between two network namespaces through the host and needs root."""

import ipaddress
import os
import shutil
import socket
import struct
import subprocess
import time

import pytest

from picosnitch import conntrack


def _attr(kind: int, payload: bytes, nested: bool = False) -> bytes:
    length = 4 + len(payload)
    return struct.pack("=HH", length, kind | (0x8000 if nested else 0)) + payload + b"\0" * ((-length) % 4)


def _tuple(kind: int, src: str, dst: str, protocol: int, sport: int, dport: int) -> bytes:
    v6 = ipaddress.ip_address(src).version == 6
    ip = _attr(3 if v6 else 1, ipaddress.ip_address(src).packed) + _attr(4 if v6 else 2, ipaddress.ip_address(dst).packed)
    proto = _attr(1, bytes([protocol])) + _attr(2, struct.pack(">H", sport)) + _attr(3, struct.pack(">H", dport))
    return _attr(kind, _attr(1, ip, True) + _attr(2, proto, True), True)


def _counters(kind: int, packets: int, nbytes: int) -> bytes:
    return _attr(kind, _attr(1, struct.pack(">Q", packets)) + _attr(2, struct.pack(">Q", nbytes)), True)


def _message(ct_id: int, orig: tuple, reply: tuple, counters: tuple[int, int, int, int] | None = (100, 2000, 2, 3)) -> bytes:
    """a ctnetlink payload: nfgenmsg, the two tuples, counters (orig bytes, reply bytes, orig
    packets, reply packets) and the id, in the kernel's order"""
    payload = struct.pack("=BBH", socket.AF_INET, 0, 0) + _tuple(1, *orig) + _tuple(2, *reply)
    if counters is not None:
        payload += _counters(9, counters[2], counters[0]) + _counters(10, counters[3], counters[1])
    return payload + _attr(12, struct.pack(">I", ct_id))


# a peer of an exit node opening a connection that the host masquerades
ORIG = ("100.64.0.2", "198.51.100.7", 6, 40000, 443)
REPLY = ("198.51.100.7", "203.0.113.1", 6, 443, 61000)


def test_parse_entry_reads_tuples_and_counters():
    flow_id, entry = conntrack.parse_entry(_message(7, ORIG, REPLY)) or (0, None)
    assert flow_id == 7
    assert entry == conntrack.Entry(6, "100.64.0.2", 40000, "198.51.100.7", 443, (100, 2000, 2, 3))
    # a flow started while nf_conntrack_acct was off has no counters
    assert conntrack.parse_entry(_message(7, ORIG, REPLY, None)) is None


def test_quick_sources_find_both_ends():
    payload = _message(7, ORIG, REPLY)
    assert conntrack.quick_sources(payload) == (ipaddress.ip_address("100.64.0.2").packed, ipaddress.ip_address("198.51.100.7").packed)
    host = conntrack.pack_addresses({"203.0.113.1"})
    # masqueraded: the host's address is only the reply's destination, so it is forwarded
    assert not conntrack.is_local(payload, host)
    # opened by the host, or answered by it
    assert conntrack.is_local(_message(8, ("203.0.113.1", "198.51.100.7", 6, 50000, 443), ("198.51.100.7", "203.0.113.1", 6, 443, 50000)), host)
    assert conntrack.is_local(_message(9, ("198.51.100.7", "203.0.113.1", 6, 50000, 22), ("203.0.113.1", "198.51.100.7", 6, 22, 50000)), host)
    # sent to a broadcast or multicast address: delivered here, never forwarded
    assert conntrack.is_local(_message(11, ("172.31.1.1", "255.255.255.255", 17, 67, 68), ("255.255.255.255", "172.31.1.1", 17, 68, 67)), frozenset())
    assert conntrack.is_local(_message(12, ("fe80::1", "ff02::1", 58, 0, 0), ("ff02::1", "fe80::1", 58, 0, 0)), frozenset())
    v6 = _message(10, ("2001:db8::2", "2001:db8::7", 17, 5000, 53), ("2001:db8::7", "2001:db8::2", 17, 53, 5000))
    assert conntrack.quick_sources(v6) == (ipaddress.ip_address("2001:db8::2").packed, ipaddress.ip_address("2001:db8::7").packed)
    assert conntrack.quick_sources(b"\0" * 8) is None


def _entry(orig_bytes: int, reply_bytes: int) -> conntrack.Entry:
    return conntrack.Entry(6, "100.64.0.2", 40000, "198.51.100.7", 443, (orig_bytes, reply_bytes, 1, 1))


def test_collect_reports_deltas():
    """the first dump is the baseline; then each flow reports what it moved since the dump that
    saw it last, and an ended flow its last bytes from the destroy event"""
    dumps = [{1: _entry(100, 1000)}, {1: _entry(150, 1500), 2: _entry(30, 300)}, {2: _entry(40, 400)}]
    tracker = conntrack.Conntrack(lambda message: None, set(), dumper=lambda local: dumps.pop(0), listen=False)
    flows = tracker.collect(set())
    assert [(flow.orig_bytes, flow.reply_bytes) for flow in flows] == [(50, 500), (30, 300)]
    # flow 1 ended at 170/1700 between the dumps; flow 2 goes on
    tracker.destroyed.append((1, _entry(170, 1700)))
    flows = tracker.collect(set())
    assert sorted((flow.orig_bytes, flow.reply_bytes) for flow in flows) == [(10, 100), (20, 200)]
    assert set(tracker.seen) == {2}


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("ip") is None or not os.path.exists(conntrack.ACCT_SYSCTL), reason="needs root, iproute2 and nf_conntrack")
def test_collect_sees_routed_traffic():
    """two namespaces talk through the host: the host forwards, no local socket is involved"""
    # docker sets the FORWARD policy to DROP, and a dropped packet's flow is never committed
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
        for i in (1, 2):
            sh(f"ip netns add psct{i} && ip link add psct{i}h type veth peer name psct{i}n && ip link set psct{i}n netns psct{i}")
            sh(f"ip addr add 10.97.{i}.1/24 dev psct{i}h && ip link set psct{i}h up")
            sh(f"ip -n psct{i} addr add 10.97.{i}.2/24 dev psct{i}n && ip -n psct{i} link set psct{i}n up && ip -n psct{i} route add default via 10.97.{i}.1")
        tracker = conntrack.Conntrack(lambda message: None, {"10.97.1.1", "10.97.2.1"}, listen=False)
        server = subprocess.Popen(["ip", "netns", "exec", "psct2", "python3", "-c", "import socket; s = socket.create_server(('10.97.2.2', 8099)); c, _ = s.accept(); print(len(c.recv(65536)))"])
        time.sleep(0.5)
        sh("ip netns exec psct1 python3 -c \"import socket; c = socket.create_connection(('10.97.2.2', 8099)); c.sendall(b'x' * 20000); c.close()\"")
        server.wait(10)
        flows = [flow for flow in tracker.collect({"10.97.1.1", "10.97.2.1"}) if flow.dport == 8099]
        assert [(flow.src, flow.dst, flow.protocol) for flow in flows] == [("10.97.1.2", "10.97.2.2", 6)]
        # wire bytes: the payload and its headers
        assert flows[0].orig_bytes >= 20000 and flows[0].orig_packets >= 3
    finally:
        for i in (1, 2):
            subprocess.run(f"ip netns del psct{i}; ip link del psct{i}h", shell=True, capture_output=True)
        if iptables:
            for rule in rules:
                subprocess.run(f"{iptables} -D {rule}", shell=True, capture_output=True)
        sysctl(conntrack.ACCT_SYSCTL, acct)
        sysctl("/proc/sys/net/ipv4/ip_forward", forward)
