# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""What the writer knows about network namespaces and their interfaces.

Their names, which interface owns a local address, the TUN device of a process, and the
bytes each interface moved. A namespace other than the daemon's own is queried from a
short-lived thread that joins it (setns, CAP_SYS_ADMIN), so no other thread changes
namespace and no file descriptor of this module pins a namespace that has gone.
"""

from __future__ import annotations

import collections
import dataclasses
import ipaddress
import os
import threading
import time
from collections.abc import Callable

from tracct import rtnetlink

#: Where ip netns and docker keep their named namespaces.
NETNS_DIRS = ("/run/netns", "/run/docker/netns")
#: Unnamed namespaces are reached through a process seen in them; they are forgotten
#: after this long without a connection, and at most this many are kept.
UNNAMED_NETNS_SECONDS = 3600
UNNAMED_NETNS_MAX = 256
#: A query in another namespace that takes longer is given up.
NETNS_QUERY_TIMEOUT = 5.0
#: The name given to the daemon's own namespace unless one of NETNS_DIRS names it.
HOST_NETNS_NAME = "host"


@dataclasses.dataclass
class Snapshot:
    links: list[rtnetlink.Link]
    addresses: list[rtnetlink.Address]


def _query() -> Snapshot:
    return Snapshot(rtnetlink.links(), rtnetlink.addresses())


def run_in_netns[T](
    path: str, function: Callable[[], T], timeout: float = NETNS_QUERY_TIMEOUT
) -> T:
    """Run function inside the network namespace that path (an nsfs file) refers to.

    A socket it opens stays in that namespace.
    """
    result: list[T] = []
    errors: list[BaseException] = []
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)

    def run() -> None:
        try:
            # Changes this thread's namespace only, and the thread ends right after.
            os.setns(fd, os.CLONE_NEWNET)
            result.append(function())
        except BaseException as e:  # noqa: BLE001
            # Handed to the calling thread, which raises it there.
            errors.append(e)

    try:
        thread = threading.Thread(target=run, name="netns-query", daemon=True)
        thread.start()
        thread.join(timeout)
    finally:
        os.close(fd)
    if errors:
        raise errors[0]
    if not result:
        raise TimeoutError(
            f"querying the network namespace of {path} took longer than {timeout} s"
        )
    return result[0]


def query_netns(path: str) -> Snapshot:
    """The interfaces and addresses of the network namespace that path refers to."""
    return run_in_netns(path, _query)


def named_namespaces() -> dict[int, tuple[str, str]]:
    """{inode: (name, path)} for the namespaces in NETNS_DIRS."""
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
    """The names of the TUN/TAP devices pid has attached (fdinfo 'iff:' of /dev/net/tun
    fds).
    """
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
    """Refreshed once per write window by the writer.

    Its lookups answer from the last refresh.
    """

    def __init__(
        self,
        report: Callable[[str], object],
        query: Callable[[str | None], Snapshot] | None = None,
    ) -> None:
        self.report = report
        #: query(None) answers for the daemon's own namespace, query(path) for another
        #: one.
        self.query = query or (
            lambda path: _query() if path is None else query_netns(path)
        )
        self.host = os.stat("/proc/self/ns/net").st_ino
        #: Inode -> name of every namespace with a name, the daemon's own included.
        self.names: dict[int, str] = {self.host: HOST_NETNS_NAME}
        #: Unnamed namespace inode -> (pid seen in it, when), oldest first.
        self.unnamed: collections.OrderedDict[int, tuple[int, float]] = (
            collections.OrderedDict()
        )
        #: (netns, address) -> (interface name, kind) for the exact addresses; loopback
        #: holds the loopback networks.
        self.owners: dict[tuple[int, str], tuple[str, str]] = {}
        self.loopback: dict[int, tuple[str, str]] = {}
        #: Netns -> the broadcast addresses of its IPv4 networks.
        self.broadcasts: dict[int, set[str]] = {}
        #: (netns, ifindex, name) -> (rx, tx) at the last refresh.
        self.counters: dict[tuple[int, int, str], tuple[int, int]] = {}
        self.tun_cache: dict[int, str] = {}
        #: Inode -> path to join (None for the daemon's own) of the namespaces the last
        #: refresh looked at.
        self.paths: dict[int, str | None] = {}
        self.failed: set[int] = set()

    def note(self, netns: int, pid: int) -> None:
        """Remember that pid lives in netns, as a way into a namespace that has no name."""
        if not netns or netns == self.host or netns in self.names:
            return
        self.unnamed[netns] = (pid, time.monotonic())
        self.unnamed.move_to_end(netns)
        while len(self.unnamed) > UNNAMED_NETNS_MAX:
            self.unnamed.popitem(last=False)

    def interface_of(self, netns: int, laddr: str) -> tuple[str, str]:
        """(name, kind) of the interface that holds laddr in netns, ("", "") if none
        does.
        """
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

    def local_addresses(self, netns: int | None = None) -> set[str]:
        """The addresses of a namespace (by default the daemon's own) and the broadcast
        addresses of its IPv4 networks, as of the last refresh.
        """
        netns = self.host if netns is None else netns
        return {
            address for inode, address in self.owners if inode == netns
        } | self.broadcasts.get(netns, set())

    def label(self, netns: int) -> str:
        """A namespace's name, or its inode when it has none."""
        return self.names.get(netns, str(netns))

    def tun_of(self, pid: int) -> str:
        """The TUN device of pid when it has exactly one, else ''."""
        name = self.tun_cache.get(pid)
        if name is None:
            devices = tun_devices(pid)
            name = devices[0] if len(devices) == 1 else ""
            self.tun_cache[pid] = name
        return name

    def _targets(self) -> dict[int, str | None]:
        """Return the namespaces to look at, as {inode: the path to join}.

        The path is None for the daemon's own namespace.
        """
        named = named_namespaces()
        self.names = {inode: name for inode, (name, _) in named.items()}
        self.names.setdefault(self.host, HOST_NETNS_NAME)
        targets: dict[int, str | None] = {
            inode: path for inode, (_, path) in named.items() if inode != self.host
        }
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
        """Look at every namespace again.

        Returns (netns, interface, kind, rx, tx) with the bytes each interface moved
        since the last refresh, for the interfaces that moved any.
        """
        owners: dict[tuple[int, str], tuple[str, str]] = {}
        loopback: dict[int, tuple[str, str]] = {}
        counters: dict[tuple[int, int, str], tuple[int, int]] = {}
        broadcasts: dict[int, set[str]] = {}
        traffic = []
        targets = self._targets()
        # A namespace that has gone is no longer reported, nor remembered as failed.
        self.failed &= set(targets)
        for inode, path in targets.items():
            try:
                snapshot = self.query(path)
            except Exception as e:  # noqa: BLE001
                # A namespace that cannot be read is reported and skipped.
                if inode not in self.failed:
                    self.failed.add(inode)
                    self.report(
                        f"netinfo: cannot query network namespace {self.label(inode)} ({e}); its interfaces go unrecorded"
                    )
                # Keep what the last look found, so the next one that works counts from
                # there.
                owners.update(
                    {
                        key: value
                        for key, value in self.owners.items()
                        if key[0] == inode
                    }
                )
                counters.update(
                    {
                        key: value
                        for key, value in self.counters.items()
                        if key[0] == inode
                    }
                )
                if inode in self.loopback:
                    loopback[inode] = self.loopback[inode]
                if inode in self.broadcasts:
                    broadcasts[inode] = self.broadcasts[inode]
                continue
            self.failed.discard(inode)
            broadcasts[inode] = {
                str(network.broadcast_address)
                for address in snapshot.addresses
                if (
                    network := ipaddress.ip_network(
                        f"{address.addr}/{address.prefixlen}", strict=False
                    )
                ).version
                == 4
                and network.prefixlen < 31
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
                    # The first look only sets the baseline.
                    continue
                # A counter that went back was reset (device recreated): count from
                # zero.
                rx = (
                    link.rx_bytes - previous[0]
                    if link.rx_bytes >= previous[0]
                    else link.rx_bytes
                )
                tx = (
                    link.tx_bytes - previous[1]
                    if link.tx_bytes >= previous[1]
                    else link.tx_bytes
                )
                if rx or tx:
                    traffic.append((inode, link.name, link.kind, rx, tx))
        self.owners, self.loopback, self.counters, self.broadcasts = (
            owners,
            loopback,
            counters,
            broadcasts,
        )
        self.paths = targets
        self.tun_cache = {}
        return traffic
