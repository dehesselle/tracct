# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Tests for the interface and namespace information the writer records.

The last test creates real namespaces, a veth pair and a TUN device and needs root.
"""

import fcntl
import os
import shutil
import struct
import subprocess

import pytest

from tracct import netinfo
from tracct.rtnetlink import Address, Link


def _snapshot(eth0_rx: int, eth0_tx: int) -> netinfo.Snapshot:
    links = [
        Link(1, "lo", "", 100, 100),
        Link(2, "eth0", "", eth0_rx, eth0_tx),
        Link(3, "tailscale0", "tun", 0, 0),
    ]
    addresses = [
        Address(1, "127.0.0.1", 8),
        Address(1, "::1", 128),
        Address(2, "10.0.0.2", 24),
        Address(3, "100.64.0.1", 32),
    ]
    return netinfo.Snapshot(links, addresses)


def test_refresh_reports_deltas_and_owners(monkeypatch, tmp_path):
    monkeypatch.setattr(netinfo, "NETNS_DIRS", (str(tmp_path),))
    snapshots = [_snapshot(1000, 500), _snapshot(1500, 500), _snapshot(10, 20)]
    reports: list[str] = []
    info = netinfo.NetInfo(reports.append, query=lambda path: snapshots.pop(0))
    host = info.host
    # The first look is the baseline.
    assert info.refresh() == []
    assert info.names == {host: "host"}
    assert info.interface_of(host, "10.0.0.2") == ("eth0", "")
    assert info.interface_of(host, "100.64.0.1") == ("tailscale0", "tun")
    assert info.interface_of(host, "127.0.0.53") == ("lo", "")
    assert info.interface_of(host, "192.0.2.1") == ("", "")
    # With the broadcast addresses of the IPv4 networks.
    assert info.local_addresses() == {
        "127.0.0.1",
        "::1",
        "10.0.0.2",
        "100.64.0.1",
        "127.255.255.255",
        "10.0.0.255",
    }
    assert info.refresh() == [(host, "eth0", "", 500, 0)]
    # eth0 was recreated: its counters start over.
    assert info.refresh() == [(host, "eth0", "", 10, 20)]
    assert reports == []


def test_refresh_survives_a_failed_look(monkeypatch, tmp_path):
    """A namespace that cannot be queried once is reported once and keeps its owners and
    baseline, so the next look counts from where the last one left off.
    """
    monkeypatch.setattr(netinfo, "NETNS_DIRS", (str(tmp_path),))
    answers = [
        _snapshot(1000, 500),
        OSError("busy"),
        OSError("busy"),
        _snapshot(1200, 600),
    ]

    def query(path):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    reports: list[str] = []
    info = netinfo.NetInfo(reports.append, query=query)
    info.refresh()
    assert info.refresh() == [] and info.refresh() == []
    assert len(reports) == 1 and "busy" in reports[0]
    assert info.interface_of(info.host, "10.0.0.2") == ("eth0", "")
    assert info.refresh() == [(info.host, "eth0", "", 200, 100)]


@pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("ip") is None, reason="needs root and iproute2"
)
def test_real_namespaces_and_tun():
    def sh(command: str) -> None:
        subprocess.run(command, shell=True, check=True, capture_output=True)

    tun = None
    try:
        sh(
            "ip netns add psni && ip link add psni0 type veth peer name psni1 && ip link set psni1 netns psni"
        )
        sh("ip addr add 10.96.0.1/24 dev psni0 && ip link set psni0 up")
        sh(
            "ip -n psni addr add 10.96.0.2/24 dev psni1 && ip -n psni link set psni1 up && ip -n psni link set lo up"
        )
        tun = os.open("/dev/net/tun", os.O_RDWR)
        # TUNSETIFF with IFF_TUN | IFF_NO_PI.
        fcntl.ioctl(tun, 0x400454CA, struct.pack("16sH", b"psnitun0", 0x0001 | 0x1000))
        info = netinfo.NetInfo(lambda message: None)
        info.refresh()
        inode = os.stat("/run/netns/psni").st_ino
        assert info.names[inode] == "psni"
        assert info.interface_of(inode, "10.96.0.2") == ("psni1", "veth")
        assert info.interface_of(inode, "127.0.0.1") == ("lo", "")
        assert info.interface_of(info.host, "10.96.0.1") == ("psni0", "veth")
        assert info.tun_of(os.getpid()) == "psnitun0"
        sh("ping -c 5 -i 0.05 -s 1000 -q 10.96.0.2")
        moved = {
            (netns, name): (rx, tx) for netns, name, kind, rx, tx in info.refresh()
        }
        # 5 echo requests and replies of 1028 bytes of ICMP, plus their IP and
        # Ethernet headers.
        assert (
            moved[(inode, "psni1")][0] >= 5 * 1028
            and moved[(info.host, "psni0")][1] >= 5 * 1028
        )
    finally:
        if tun is not None:
            os.close(tun)
        subprocess.run(
            "ip netns del psni; ip link del psni0", shell=True, capture_output=True
        )
