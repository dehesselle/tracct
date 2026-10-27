"""what the writer knows about network namespaces and their interfaces: their names, which
interface owns a local address, the TUN device of a process, and the bytes each interface
moved. a namespace other than the daemon's own is queried from a short-lived thread that
joins it (setns, CAP_SYS_ADMIN), so no other thread changes namespace and no file
descriptor pins a namespace that has gone"""

from __future__ import annotations

import collections
import dataclasses
import ipaddress
import os
import threading
import time
from collections.abc import Callable

from picosnitch import rtnetlink

# where ip netns and docker keep their named namespaces
NETNS_DIRS = ("/run/netns", "/run/docker/netns")
# unnamed namespaces are reached through a process seen in them; they are forgotten after
# this long without a connection, and at most this many are kept
UNNAMED_NETNS_SECONDS = 3600
UNNAMED_NETNS_MAX = 256
# a query in another namespace that takes longer is given up
NETNS_QUERY_TIMEOUT = 5.0
# the name given to the daemon's own namespace unless one of NETNS_DIRS names it
HOST_NETNS_NAME = "host"


@dataclasses.dataclass
class Snapshot:
    links: list[rtnetlink.Link]
    addresses: list[rtnetlink.Address]


def _query() -> Snapshot:
    return Snapshot(rtnetlink.links(), rtnetlink.addresses())


def query_netns(path: str, query: Callable[[], Snapshot] = _query) -> Snapshot:
    """run query inside the network namespace that path (an nsfs file) refers to"""
    result: list[Snapshot] = []
    errors: list[BaseException] = []
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)

    def run() -> None:
        try:
            # changes this thread's namespace only, and the thread ends right after
            os.setns(fd, os.CLONE_NEWNET)
            result.append(query())
        except BaseException as e:
            errors.append(e)

    try:
        thread = threading.Thread(target=run, name="netns-query", daemon=True)
        thread.start()
        thread.join(NETNS_QUERY_TIMEOUT)
    finally:
        os.close(fd)
    if errors:
        raise errors[0]
    if not result:
        raise TimeoutError(f"querying the network namespace of {path} took longer than {NETNS_QUERY_TIMEOUT} s")
    return result[0]


def named_namespaces() -> dict[int, tuple[str, str]]:
    """{inode: (name, path)} for the namespaces in NETNS_DIRS"""
    named: dict[int, tuple[str, str]] = {}
    for directory in NETNS_DIRS:
        try:
            entries = sorted(os.listdir(directory))
        except OSError:
            continue
        for entry in entries:
            path = os.path.join(directory, entry)
            try:
                named.setdefault(os.stat(path).st_ino, (entry, path))
            except OSError:
                continue
    return named


def tun_devices(pid: int) -> list[str]:
    """the names of the TUN/TAP devices pid has attached (fdinfo 'iff:' of /dev/net/tun fds)"""
    names = []
    try:
        fds = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return names
    for fd in fds:
        try:
            if os.readlink(f"/proc/{pid}/fd/{fd}") != "/dev/net/tun":
                continue
            with open(f"/proc/{pid}/fdinfo/{fd}", "r", errors="replace") as f:
                for line in f:
                    if line.startswith("iff:"):
                        names.append(line.split(None, 1)[1].strip())
        except (OSError, IndexError):
            continue
    return names


class NetInfo:
    """refreshed once per write window by the writer; its lookups answer from the last refresh"""

    def __init__(self, report: Callable[[str], object], query: Callable[[str | None], Snapshot] | None = None) -> None:
        self.report = report
        # query(None) answers for the daemon's own namespace, query(path) for another one
        self.query = query or (lambda path: _query() if path is None else query_netns(path))
        self.host = os.stat("/proc/self/ns/net").st_ino
        # inode -> name of every namespace with a name, the daemon's own included
        self.names: dict[int, str] = {self.host: HOST_NETNS_NAME}
        # unnamed namespace inode -> (pid seen in it, when), oldest first
        self.unnamed: collections.OrderedDict[int, tuple[int, float]] = collections.OrderedDict()
        # (netns, address) -> (interface name, kind); exact addresses, then loopback networks
        self.owners: dict[tuple[int, str], tuple[str, str]] = {}
        self.loopback: dict[int, tuple[str, str]] = {}
        # broadcast addresses of the IPv4 networks in the daemon's own namespace
        self.broadcasts: set[str] = set()
        # (netns, ifindex, name) -> (rx, tx) at the last refresh
        self.counters: dict[tuple[int, int, str], tuple[int, int]] = {}
        self.tun_cache: dict[int, str] = {}
        self.failed: set[int] = set()

    def note(self, netns: int, pid: int) -> None:
        """remember that pid lives in netns, as a way into a namespace that has no name"""
        if not netns or netns == self.host or netns in self.names:
            return
        self.unnamed[netns] = (pid, time.monotonic())
        self.unnamed.move_to_end(netns)
        while len(self.unnamed) > UNNAMED_NETNS_MAX:
            self.unnamed.popitem(last=False)

    def interface_of(self, netns: int, laddr: str) -> tuple[str, str]:
        """(name, kind) of the interface that holds laddr in netns, ("", "") if none does"""
        owner = self.owners.get((netns, laddr))
        if owner is not None:
            return owner
        if laddr and netns in self.loopback:
            try:
                if ipaddress.ip_address(laddr).is_loopback:
                    return self.loopback[netns]
            except ValueError:
                pass
        return "", ""

    def local_addresses(self) -> set[str]:
        """the addresses of the daemon's own namespace and the broadcast addresses of its IPv4
        networks, as of the last refresh"""
        return {address for netns, address in self.owners if netns == self.host} | self.broadcasts

    def tun_of(self, pid: int) -> str:
        """the TUN device of pid when it has exactly one, else ''"""
        name = self.tun_cache.get(pid)
        if name is None:
            devices = tun_devices(pid)
            name = devices[0] if len(devices) == 1 else ""
            self.tun_cache[pid] = name
        return name

    def _targets(self) -> dict[int, str | None]:
        """{inode: path to join, None for the daemon's own} of the namespaces to look at"""
        named = named_namespaces()
        self.names = {inode: name for inode, (name, _) in named.items()}
        self.names.setdefault(self.host, HOST_NETNS_NAME)
        targets: dict[int, str | None] = {inode: path for inode, (_, path) in named.items() if inode != self.host}
        targets[self.host] = None
        expired = time.monotonic() - UNNAMED_NETNS_SECONDS
        for inode, (pid, seen) in list(self.unnamed.items()):
            path = f"/proc/{pid}/ns/net"
            try:
                alive = os.stat(path).st_ino == inode
            except OSError:
                alive = False
            if inode in self.names or seen < expired or not alive:
                del self.unnamed[inode]
            else:
                targets[inode] = path
        return targets

    def refresh(self) -> list[tuple[int, str, str, int, int]]:
        """look at every namespace again; returns (netns, interface, kind, rx, tx) with the
        bytes each interface moved since the last refresh, for the interfaces that moved any"""
        owners: dict[tuple[int, str], tuple[str, str]] = {}
        loopback: dict[int, tuple[str, str]] = {}
        counters: dict[tuple[int, int, str], tuple[int, int]] = {}
        broadcasts = set(self.broadcasts)
        traffic = []
        for inode, path in self._targets().items():
            try:
                snapshot = self.query(path)
            except Exception as e:
                if inode not in self.failed:
                    self.failed.add(inode)
                    self.report(f"netinfo: cannot query network namespace {inode} ({e}); its interfaces go unrecorded")
                # keep what the last look found, so the next one that works counts from there
                owners.update({key: value for key, value in self.owners.items() if key[0] == inode})
                counters.update({key: value for key, value in self.counters.items() if key[0] == inode})
                if inode in self.loopback:
                    loopback[inode] = self.loopback[inode]
                continue
            self.failed.discard(inode)
            if inode == self.host:
                broadcasts = {
                    str(network.broadcast_address)
                    for address in snapshot.addresses
                    if (network := ipaddress.ip_network(f"{address.addr}/{address.prefixlen}", strict=False)).version == 4 and network.prefixlen < 31
                }
            by_index = {link.index: link for link in snapshot.links}
            for address in snapshot.addresses:
                link = by_index.get(address.index)
                if link is None:
                    continue
                owners[(inode, address.addr)] = (link.name, link.kind)
                if address.addr in ("127.0.0.1", "::1"):
                    loopback[inode] = (link.name, link.kind)
            for link in snapshot.links:
                key = (inode, link.index, link.name)
                counters[key] = (link.rx_bytes, link.tx_bytes)
                previous = self.counters.get(key)
                if previous is None:
                    # the first look only sets the baseline
                    continue
                # a counter that went back was reset (device recreated): count from zero
                rx = link.rx_bytes - previous[0] if link.rx_bytes >= previous[0] else link.rx_bytes
                tx = link.tx_bytes - previous[1] if link.tx_bytes >= previous[1] else link.tx_bytes
                if rx or tx:
                    traffic.append((inode, link.name, link.kind, rx, tx))
        self.owners, self.loopback, self.counters, self.broadcasts = owners, loopback, counters, broadcasts
        self.tun_cache = {}
        return traffic
