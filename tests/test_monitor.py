# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for monitor exe-resolution helpers."""

import ipaddress
import os
import subprocess
import sys

import pytest

from tracct.constants import ST_DEV_MASK
from tracct.monitor import (
    ExeResolver,
    _classify_inode_fallback,
    _parse_proc_net_addr,
    _read_proc_unit,
    unit_of_cgroup,
    unmap_ipv4,
)


def _dev_ino(path: str) -> tuple[int, int]:
    stat = os.stat(path)
    return stat.st_dev & ST_DEV_MASK, stat.st_ino


def test_plain_binary_returns_its_own_path(tmp_path):
    real = tmp_path / "binary"
    real.write_bytes(b"#!/bin/true\n")
    dev, ino = _dev_ino(str(real))
    assert _classify_inode_fallback(dev, ino, str(real)) == str(real)


def test_symlink_alias_collapses_to_canonical(tmp_path):
    # Busybox-style: many symlink names point at one ELF (nlink == 1).
    real = tmp_path / "busybox"
    real.write_bytes(b"ELF\n")
    sh = tmp_path / "sh"
    nc = tmp_path / "nc"
    sh.symlink_to(real)
    nc.symlink_to(real)
    dev, ino = _dev_ino(str(real))
    assert _classify_inode_fallback(dev, ino, str(sh)) == str(real)
    assert _classify_inode_fallback(dev, ino, str(nc)) == str(real)


def test_hardlink_multicall_returns_sentinel(tmp_path):
    # Uutils-style: many hardlink names share one inode (nlink > 1), no canonical name
    # exists so we must not pick one.
    a = tmp_path / "ls"
    a.write_bytes(b"ELF\n")
    b = tmp_path / "cat"
    os.link(str(a), str(b))
    dev, ino = _dev_ino(str(a))
    label = _classify_inode_fallback(dev, ino, str(a))
    assert label == f"<multi-call:dev={dev},ino={ino}>"
    # Either hardlink name classifies identically.
    assert _classify_inode_fallback(dev, ino, str(b)) == label


def test_inode_mismatch_returns_input_unchanged(tmp_path):
    real = tmp_path / "binary"
    real.write_bytes(b"x")
    dev, ino = _dev_ino(str(real))
    # A path whose inode no longer matches the event must not be attributed.
    assert _classify_inode_fallback(dev, ino + 1, str(real)) == str(real)


def test_empty_and_sentinel_pass_through():
    assert _classify_inode_fallback(1, 2, "") == ""
    assert (
        _classify_inode_fallback(1, 2, "<multi-call:dev=1,ino=2>")
        == "<multi-call:dev=1,ino=2>"
    )


@pytest.fixture
def child():
    """A running process with a plain executable (not multi-call), killed after."""
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    yield p
    p.kill()
    p.wait()


def _resolver() -> ExeResolver:
    return ExeResolver(lambda msgid, message: None)


def test_resolver_returns_live_path(child):
    dev, ino = _dev_ino(f"/proc/{child.pid}/exe")
    assert _resolver().resolve(dev, ino, child.pid, "python") == (
        dev,
        ino,
        os.readlink(f"/proc/{child.pid}/exe"),
    )


def test_resolver_takes_inode_from_live_process(child):
    # An event without an inode gets the live process's (dev, ino).
    dev, ino = _dev_ino(f"/proc/{child.pid}/exe")
    assert _resolver().resolve(0, 0, child.pid, "python") == (
        dev,
        ino,
        os.readlink(f"/proc/{child.pid}/exe"),
    )


def test_resolver_rejects_exec_since_event(child):
    # The pid runs another binary than the event recorded: its live path must not be
    # attributed.
    dev, ino = _dev_ino(f"/proc/{child.pid}/exe")
    assert _resolver().resolve(dev, ino + 1, child.pid, "python")[2] == ""


def test_resolver_remembers_exited_process(child):
    dev, ino = _dev_ino(f"/proc/{child.pid}/exe")
    exe = os.readlink(f"/proc/{child.pid}/exe")
    resolver = _resolver()
    # A worker-thread comm that names no binary on disk.
    assert resolver.resolve(dev, ino, child.pid, "worker-1")[2] == exe
    child.kill()
    child.wait()
    assert resolver.resolve(dev, ino, child.pid, "worker-1")[2] == exe


def test_resolver_keeps_no_fds(child):
    """Identity is by path.

    Resolving must neither open the binary for later nor leak fds.
    """
    resolver = _resolver()
    before = set(os.listdir("/proc/self/fd"))
    for pid in (os.getpid(), os.getppid(), child.pid):
        dev, ino = _dev_ino(f"/proc/{pid}/exe")
        resolver.resolve(dev, ino, pid, "python")
    child.kill()
    child.wait()
    resolver.resolve(dev, ino, child.pid, "python")
    assert set(os.listdir("/proc/self/fd")) == before


def test_unit_of_cgroup_takes_the_innermost_unit():
    assert unit_of_cgroup("/system.slice/nginx.service") == "nginx.service"
    assert (
        unit_of_cgroup(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox@1.service"
        )
        == "app-firefox@1.service"
    )
    assert (
        unit_of_cgroup("/system.slice/docker-0123abcd.scope") == "docker-0123abcd.scope"
    )
    # A delegated subtree below the unit.
    assert (
        unit_of_cgroup("/system.slice/tailscaled.service/sub") == "tailscaled.service"
    )
    assert unit_of_cgroup("/") == ""
    assert unit_of_cgroup("/user.slice") == ""


def test_read_proc_unit_of_self():
    # Whatever runs the tests runs in some unit or none, but never fails while it lives.
    assert isinstance(_read_proc_unit(os.getpid()), str)
    with pytest.raises(OSError):
        _read_proc_unit(2**22 + 1)


def _packed(address: str) -> bytes:
    return ipaddress.ip_address(address).packed


def test_unmap_ipv4_turns_dual_stack_peers_into_ipv4():
    # An IPv4 client of a server listening on [::].
    assert unmap_ipv4(
        _packed("::ffff:203.0.113.1"), _packed("::ffff:198.51.100.7")
    ) == (2, "203.0.113.1", "198.51.100.7")
    # An unbound dual-stack UDP socket sending to an IPv4 peer.
    assert unmap_ipv4(_packed("::"), _packed("::ffff:198.51.100.7")) == (
        2,
        "0.0.0.0",
        "198.51.100.7",
    )
    # IPv6 stays IPv6, ::1 and :: included.
    assert unmap_ipv4(_packed("2001:db8::1"), _packed("2001:db8::7")) == (
        10,
        "2001:db8::1",
        "2001:db8::7",
    )
    assert unmap_ipv4(_packed("::1"), _packed("::1")) == (10, "::1", "::1")
    assert unmap_ipv4(_packed("::"), _packed("::")) == (10, "::", "::")


def test_parse_proc_net_addr_unmaps_ipv4():
    # /proc/net/tcp6 holds four little-endian words
    assert _parse_proc_net_addr("0000000000000000FFFF00000100007F:1F90") == "127.0.0.1"
    assert _parse_proc_net_addr("00000000000000000000000001000000:0016") == "::1"
    assert _parse_proc_net_addr("0100007F:0050") == "127.0.0.1"
