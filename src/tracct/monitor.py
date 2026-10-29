# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import collections
import ipaddress
import logging
import os
import resource
import shutil
import socket
import struct
import threading
import time
import typing

from tracct.bpf_wrapper import (
    BPF,
    ConnKey4,
    ConnKey6,
    ConnKeyPacket,
    ConnVal,
    check_bpf_requirements,
    find_bpf_object,
    kernel_symbol_addrs,
)
from tracct.config import Config
from tracct.constants import ST_DEV_MASK
from tracct.messages import report
from tracct.types import BpfEvent

logger = logging.getLogger(__name__)


def _report(msgid: str, message: str) -> None:
    """report() under this module's logger, as the default report callable."""
    report(logger, msgid, message)


#: Entries per drain handoff: one per event costs a hand-off each, one per drain lands a
#: burst at once.
CONN_DRAIN_CHUNK: typing.Final[int] = 2048
#: Bound of each exe resolution cache and of the dns answer cache.
LOOKUP_CACHE_MAX: typing.Final[int] = 8192
#: Bytes of a command line kept: Linux allows about 2 MB, and the line goes into caches,
#: every event of the live feed, the database and its unique index.
CMDLINE_MAX: typing.Final[int] = 4096
#: Entries of conn_stats_packet, one per process and namespace doing raw packet or TUN
#: I/O.
PACKET_MAP_MAX: typing.Final[int] = 65536


def _read_proc_comm(pid: int) -> str:
    # Comm is kernel-supplied bytes (prctl PR_SET_NAME), not necessarily utf-8.
    try:
        with open(f"/proc/{pid}/comm", "r", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _classify_inode_fallback(st_dev: int, st_ino: int, exe: str) -> str:
    """Classify a resolved path before it is stored in dev_ino_fallback, which is keyed
    by (dev, ino) alone and reused for later events that have no comm.

    Realpath collapses symlink aliases to one canonical file (busybox ->
    /bin/busybox, python -> python3.13) with st_nlink == 1, which is what the
    kernel reports for live procs anyway. Hardlink multi-call binaries (uutils)
    have st_nlink > 1 and no canonical name, so return a '<multi-call:dev,ino>'
    sentinel rather than claim an arbitrary hardlink. Inode re-verified after
    realpath so a name is never attributed unless dev+ino still match.
    """
    if not exe or exe.startswith("<multi-call:"):
        return exe
    try:
        canonical = os.path.realpath(exe)
        stat = os.stat(canonical)
    except OSError:
        return exe
    if (stat.st_dev & ST_DEV_MASK) != st_dev or stat.st_ino != st_ino:
        return exe
    if stat.st_nlink > 1:
        return f"<multi-call:dev={st_dev},ino={st_ino}>"
    return canonical


def _read_proc_status_uid(pid: int) -> int:
    """Return the effective UID for `pid` from /proc/[pid]/status.

    Format: 'Uid:\\treal\\teffective\\tsaved\\tfs'.  We use the effective
    UID (field 2) because BPF's bpf_get_current_uid_gid() also returns
    the effective UID -- keeping the two paths consistent."""
    # errors="replace": the Name: line precedes Uid: and may hold non-utf-8 comm bytes.
    try:
        with open(f"/proc/{pid}/status", "r", errors="replace") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[2])
    except (OSError, ValueError, IndexError):
        pass
    return 0


#: Suffixes of the systemd units processes run in.
UNIT_SUFFIXES: typing.Final[tuple[str, ...]] = (
    ".service",
    ".scope",
    ".socket",
    ".mount",
    ".swap",
)


def unit_of_cgroup(path: str) -> str:
    """The innermost systemd unit in a cgroup path, e.g. 'nginx.service' for
    /system.slice/nginx.service, '' for a process outside any unit.
    """
    for part in reversed(path.split("/")):
        if part.endswith(UNIT_SUFFIXES):
            return part
    return ""


def _read_proc_file(path: str, limit: int | None = None) -> str:
    """A /proc file, whole or its first limit bytes, decoded with errors replaced.

    Plain reads, as a text-mode open costs more than the read itself and this runs per
    exec and per process and drain.
    """
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        chunks = []
        left = limit
        while chunk := os.read(fd, 65536 if left is None else min(65536, left)):
            chunks.append(chunk)
            if left is not None:
                left -= len(chunk)
                if not left:
                    break
    finally:
        os.close(fd)
    return b"".join(chunks).decode(errors="replace")


def _read_proc_unit(pid: int) -> str:
    """The systemd unit of pid from its cgroup v2 path (or the v1 name=systemd
    hierarchy); raises OSError once the process is gone.
    """
    path = ""
    for line in _read_proc_file(f"/proc/{pid}/cgroup").splitlines():
        hierarchy, _, rest = line.partition(":")
        controllers, _, cgroup = rest.partition(":")
        if (hierarchy == "0" and not controllers) or controllers == "name=systemd":
            path = cgroup.strip()
    return unit_of_cgroup(path)


def _cache_get(cache: collections.OrderedDict[str, str], key: str) -> str:
    try:
        cache.move_to_end(key)
        return cache[key]
    except KeyError:
        return ""


def _cache_put(cache: collections.OrderedDict[str, str], key: str, value: str) -> str:
    """Store value and return the key evicted to keep the cache bounded, or ''."""
    cache[key] = value
    cache.move_to_end(key)
    if len(cache) > LOOKUP_CACHE_MAX:
        return cache.popitem(last=False)[0]
    return ""


def _find_exe_by_inode(comm: str, st_dev: int, st_ino: int) -> str:
    """Try to find the executable file on disk by comm name and inode match."""
    if not comm:
        return ""
    # Try shutil.which first (uses PATH).
    candidate = shutil.which(comm)
    if candidate:
        try:
            stat = os.stat(candidate)
            if (stat.st_dev & ST_DEV_MASK) == st_dev and stat.st_ino == st_ino:
                return os.path.realpath(candidate)
        except OSError:
            pass
    # Try common system directories.
    for prefix in (
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/libexec",
    ):
        candidate = os.path.join(prefix, comm)
        try:
            stat = os.stat(candidate)
            if (stat.st_dev & ST_DEV_MASK) == st_dev and stat.st_ino == st_ino:
                return os.path.realpath(candidate)
        except OSError:
            continue
    return ""


class ExeResolver:
    """Resolves the executable path of an event's process, checked against the (dev,
    ino) BPF recorded at event time. Reads /proc and stats paths only: no binary is
    opened and no fd is kept, so the kernel frees a deleted executable's disk space as
    usual.
    """

    def __init__(
        self,
        report: typing.Callable[[str, str], object] = _report,
    ) -> None:
        self.report = report
        #: Cache of resolved (dev, ino, comm) -> exe path, used as a fallback for
        #: when /proc/PID/exe is no longer readable (short-lived processes).
        #: Keyed by comm in addition to (dev, ino) because multi-call binaries
        #: (e.g. uutils-coreutils) hardlink many symlinks (head, sleep, cat, ...)
        #: to a single inode; the kernel distinguishes them per-process via
        #: /proc/PID/exe but the inode alone is ambiguous.
        self.ino_path_cache: collections.OrderedDict[str, str] = (
            collections.OrderedDict()
        )
        #: Last-resort fallback keyed only by (dev, ino), used when the live readlink
        #: and the (dev, ino, comm) lookup both miss (e.g. BPF reports a worker-thread
        #: comm like `tokio-rt-worker` matching no binary). Value is classified once by
        #: _classify_inode_fallback(): a canonical path, or a '<multi-call:dev,ino>'
        #: sentinel for hardlink multi-call binaries.
        self.dev_ino_fallback: collections.OrderedDict[str, str] = (
            collections.OrderedDict()
        )
        #: Last exe resolved per (dev, ino), for when the fallback above holds a
        #: sentinel.
        self.last_exe: collections.OrderedDict[str, str] = collections.OrderedDict()
        self.multi_call_reported: set[str] = set()

    def _record_inode_fallback(
        self, sig: str, st_dev: int, st_ino: int, exe: str
    ) -> None:
        """Classify and memoize the (dev, ino) fallback name the first time an inode is
        resolved (O(1), so multi-call binaries with many names don't trigger rescans).
        Reports once per hardlink multi-call inode when first seen.
        """
        if not exe or exe.startswith("<multi-call:") or sig in self.dev_ino_fallback:
            return
        label = _classify_inode_fallback(st_dev, st_ino, exe)
        evicted = _cache_put(self.dev_ino_fallback, sig, label)
        self.multi_call_reported.discard(evicted)
        if label.startswith("<multi-call:") and sig not in self.multi_call_reported:
            self.multi_call_reported.add(sig)
            self.report(
                "multi-call-inode",
                f"hardlink multi-call inode dev={st_dev} ino={st_ino} (e.g. {exe}), fallback reports {label!r} when /proc is gone",
            )

    def _resolve_when_proc_gone(
        self, sig: str, st_dev: int, st_ino: int, pid: int, comm: str
    ) -> str:
        """Best-effort exe resolution when the /proc/PID/exe readlink failed.

        Comm only locates a candidate; _find_exe_by_inode verifies its (dev, ino)
        against the event inode, so at worst comm names another hardlink of the same
        inode (same bytes). With no comm match, fall back to dev_ino_fallback (sentinel
        for hardlink multi-call inodes).
        """
        candidate = _cache_get(self.ino_path_cache, f"{sig} {comm}")
        if not candidate and comm:
            candidate = _find_exe_by_inode(comm, st_dev, st_ino)
        if not candidate:
            # BPF reports the comm of the current task, which for worker threads is the
            # thread name (prctl PR_SET_NAME, e.g. `tokio-rt-worker`); the thread group
            # leader's comm usually matches the binary's basename.
            leader_comm = _read_proc_comm(pid)
            if leader_comm and leader_comm != comm:
                candidate = _find_exe_by_inode(leader_comm, st_dev, st_ino)
        # An inode-verified candidate names a hardlink of the exact event inode, trust
        # it; otherwise use the comm-less fallback.
        return candidate or _cache_get(self.dev_ino_fallback, sig)

    def resolve(
        self, st_dev: int, st_ino: int, pid: int, comm: str = ""
    ) -> tuple[int, int, str]:
        """Return (dev, ino, exe) for pid.

        Dev and ino come from the live process when the event had none, exe is '' when
        it can't be attributed.
        """
        st_dev = st_dev & ST_DEV_MASK
        # Resolve the exe path for THIS process via /proc/PID/exe whenever possible. The
        # kernel records the specific symlink each process was exec'd from, even when
        # many symlinks share an inode (multi-call binaries like uutils-coreutils),
        # which the (dev, ino) keyed caches below can't tell apart (e.g. report `head`
        # as `sleep`).
        proc_exe = ""
        try:
            proc_exe = os.readlink(f"/proc/{pid}/exe")
            pstat = os.stat(f"/proc/{pid}/exe")
            live = (pstat.st_dev & ST_DEV_MASK, pstat.st_ino)
            if not st_ino:
                # The event had no inode: readlink is the only signal, keep it.
                st_dev, st_ino = live
            elif live != (st_dev, st_ino):
                # Events carry (dev, ino) from event time; if the pid exec'd another
                # binary since (readlink now names it), don't attribute it or poison the
                # caches.
                proc_exe = ""
        except OSError:
            pass
        if not st_ino:
            # Nothing to verify a cached path against.
            return st_dev, st_ino, proc_exe
        sig = f"{st_dev} {st_ino}"
        exe = (
            proc_exe
            or self._resolve_when_proc_gone(sig, st_dev, st_ino, pid, comm)
            or _cache_get(self.last_exe, sig)
        )
        # Only cache non-empty, non-sentinel resolutions; an empty value would poison
        # ino_path_cache for a (dev, ino, comm) tuple whose first event was a dead
        # process, masking later live lookups.
        if exe and not exe.startswith("<multi-call:"):
            _cache_put(self.ino_path_cache, f"{sig} {comm}", exe)
            _cache_put(self.last_exe, sig, exe)
            self._record_inode_fallback(sig, st_dev, st_ino, exe)
        return st_dev, st_ino, exe


#: The first 12 bytes of an IPv4-mapped IPv6 address (::ffff:a.b.c.d).
V4_MAPPED_PREFIX: typing.Final[bytes] = b"\0" * 10 + b"\xff\xff"
V6_UNSPECIFIED: typing.Final[bytes] = b"\0" * 16


def unmap_ipv4(saddr: bytes, daddr: bytes) -> tuple[int, str, str]:
    """(family, laddr, raddr) of an IPv6 socket's addresses.

    An IPv4 peer of a dual-stack socket shows as ::ffff:a.b.c.d, and is IPv4 traffic, on
    an interface's IPv4 address.
    """
    sides = (saddr, daddr)
    if any(side[:12] == V4_MAPPED_PREFIX for side in sides) and all(
        side[:12] == V4_MAPPED_PREFIX or side == V6_UNSPECIFIED for side in sides
    ):
        return (
            int(socket.AF_INET),
            socket.inet_ntop(socket.AF_INET, saddr[12:]),
            socket.inet_ntop(socket.AF_INET, daddr[12:]),
        )
    return (
        int(socket.AF_INET6),
        socket.inet_ntop(socket.AF_INET6, saddr),
        socket.inet_ntop(socket.AF_INET6, daddr),
    )


def _parse_proc_net_addr(hex_addr: str) -> str:
    """Parse 'AABBCCDD:PPPP' or IPv6 hex form into a string IP address."""
    addr_part, _, _port_part = hex_addr.partition(":")
    try:
        if len(addr_part) == 8:
            packed = bytes.fromhex(addr_part)
            return socket.inet_ntop(socket.AF_INET, packed[::-1])
        if len(addr_part) == 32:
            # /proc/net stores IPv6 as 4 little-endian u32 words
            packed = b"".join(
                bytes.fromhex(addr_part[i : i + 8])[::-1] for i in range(0, 32, 8)
            )
            if packed[:12] == V4_MAPPED_PREFIX:
                return socket.inet_ntop(socket.AF_INET, packed[12:])
            return socket.inet_ntop(socket.AF_INET6, packed)
    except (ValueError, OSError):
        pass
    return ""


def _parse_proc_net_port(hex_addr: str) -> int:
    _, _, port_part = hex_addr.partition(":")
    try:
        return int(port_part, 16)
    except ValueError:
        return -1


def _initial_family_for(addr: str) -> int:
    """Best-effort AF_* guess for an initial-poll address.

    Returns 0 when the address is empty/unparseable.
    """
    if not addr:
        return 0
    if ":" in addr:
        return int(socket.AF_INET6)
    return int(socket.AF_INET)


def _read_netns_inode(pid: int) -> int:
    """Return the network namespace inode for a pid, or 0 if unreadable."""
    try:
        return os.stat(f"/proc/{pid}/ns/net").st_ino
    except OSError:
        return 0


def _scan_proc_net_sockets() -> dict[int, tuple[str, int, str, int]]:
    """Return {inode: (laddr, lport, raddr, rport)} from /proc/net/{tcp,tcp6,udp,udp6}."""
    inode_to_endpoint: dict[int, tuple[str, int, str, int]] = {}
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        try:
            with open(f"/proc/net/{proto}", "r") as f:
                next(f, None)  # skip header
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    try:
                        inode = int(parts[9])
                    except ValueError:
                        continue
                    if inode == 0:
                        continue
                    laddr = _parse_proc_net_addr(parts[1])
                    lport = _parse_proc_net_port(parts[1])
                    raddr = _parse_proc_net_addr(parts[2])
                    rport = _parse_proc_net_port(parts[2])
                    # Only keep connections that actually have a remote peer.
                    if not raddr or rport <= 0 or raddr in ("0.0.0.0", "::"):
                        continue
                    inode_to_endpoint[inode] = (laddr, lport, raddr, rport)
        except OSError:
            continue
    return inode_to_endpoint


def _scan_pid_socket_inodes(pid: int) -> list[int]:
    """Return socket inode numbers owned by `pid` by reading /proc/{pid}/fd/*."""
    inodes: list[int] = []
    try:
        entries = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return inodes
    for entry in entries:
        try:
            target = os.readlink(f"/proc/{pid}/fd/{entry}")
        except OSError:
            continue
        if target.startswith("socket:["):
            try:
                inodes.append(int(target[8:-1]))
            except ValueError:
                continue
    return inodes


def _read_proc_ppid(pid: int) -> int:
    """Parse ppid (4th field) from /proc/{pid}/stat, splitting on the last `)` to handle
    comms containing spaces, parens, or non-utf-8 bytes.
    """
    try:
        with open(f"/proc/{pid}/stat", "r", errors="replace") as f:
            return int(f.read().rsplit(")", 1)[1].split()[1])
    except (OSError, ValueError, IndexError):
        return 0


def initial_poll() -> list:
    """Poll initial processes from /proc and seed any pre-existing TCP/UDP connections
    from /proc/net/{tcp,tcp6,udp,udp6} so the daemon catches sockets that were already
    open before BPF attached.

    BPF picks up every new send/recv after attach, so this only matters for long-running
    connections that pre-date the daemon.
    """
    initial_processes = []
    try:
        pids = [int(name) for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        return initial_processes
    inode_to_endpoint = _scan_proc_net_sockets()
    for pid in pids:
        try:
            name = _read_proc_comm(pid)
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                exe = ""
            ppid = _read_proc_ppid(pid)
            uid = _read_proc_status_uid(pid)
            pname = _read_proc_comm(ppid) if ppid else ""
            base = {
                "name": name,
                "exe": exe,
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "pname": pname,
            }
            # Find connections that this pid owns by matching socket inodes.
            seeded_any = False
            if inode_to_endpoint:
                for inode in _scan_pid_socket_inodes(pid):
                    endpoint = inode_to_endpoint.get(inode)
                    if endpoint is None:
                        continue
                    laddr, lport, raddr, rport = endpoint
                    initial_processes.append(
                        {
                            **base,
                            "raddr": raddr,
                            "rport": rport,
                            "laddr": laddr,
                            "lport": lport,
                        }
                    )
                    seeded_any = True
            if not seeded_any:
                initial_processes.append(
                    {
                        **base,
                        "raddr": "",
                        "rport": -1,
                        "laddr": "",
                        "lport": -1,
                    }
                )
        except Exception:  # noqa: BLE001, S110
            # Best effort: a process that is gone or unreadable is left out of the seed.
            pass
    return initial_processes


def run_monitor(
    config: Config,
    publish: typing.Callable[[list[BpfEvent]], object],
    stop: threading.Event,
    reattach: threading.Event,
    ready: threading.Event,
) -> None:
    """Runs a bpf program to monitor the system for new connections and hands each batch
    of attributed events to publish; the reader thread of the daemon, so nothing here
    may block on anything but the kernel.
    """
    # Required for libbpf to lock the BPF maps and ring buffers past the inherited 8 MiB
    # cap.
    try:
        resource.setrlimit(
            resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
        )
    except (ValueError, OSError):
        pass
    EVERY_EXE: typing.Final[bool] = config.monitoring.every_exe
    # The size of each aggregation map, set at load; the packet map is keyed by process,
    # not connection, so it keeps its own size.
    map_sizes = {
        "conn_stats4": config.monitoring.conn_map_max_entries,
        "conn_stats6": config.monitoring.conn_map_max_entries,
        "conn_stats_packet": PACKET_MAP_MAX,
    }
    domain_dict: collections.OrderedDict[str, str] = collections.OrderedDict()
    resolver = ExeResolver()

    # The cmdline and unit last read per pid, for the drains after the process has
    # exited: a connection's last bytes are often drained once their process is gone.
    last_read: collections.OrderedDict[int, tuple[str, str]] = collections.OrderedDict()

    def read_process(pid: int) -> tuple[str, str]:
        """Cmdline and systemd unit of pid, read now.

        Once the process is gone (or a zombie, whose cmdline reads empty), what was read
        last while it ran. The current value wins while it lasts, so an execve or a
        reused pid is never answered from the past.
        """
        try:
            # Errors replaced: a non-utf-8 argv must not blank the whole cmdline.
            cmdline = _read_proc_file(f"/proc/{pid}/cmdline", CMDLINE_MAX)
            unit = _read_proc_unit(pid)
        except OSError:
            cmdline = unit = ""
        if not cmdline:
            # Kernel threads have no cmdline either, and are never in last_read with
            # one.
            return last_read.get(pid, (cmdline, unit))
        last_read[pid] = (cmdline, unit)
        last_read.move_to_end(pid)
        if len(last_read) > LOOKUP_CACHE_MAX:
            last_read.popitem(last=False)
        return cmdline, unit

    def read_process_cached(
        pid: int, cache: dict[int, tuple[str, str]]
    ) -> tuple[str, str]:
        """read_process once per pid per drain rather than once per drained entry, so a
        process with a huge (crafted) cmdline flooding connections cannot stall the
        drain. A pid in one drain snapshot is a single process, and the cache is rebuilt
        each drain.
        """
        if pid not in cache:
            cache[pid] = read_process(pid)
        return cache[pid]

    # Get current connections.
    initial_batch: list[BpfEvent] = []
    for proc in initial_poll():
        try:
            stat = os.stat(f"/proc/{proc['pid']}/exe")
            pstat = os.stat(f"/proc/{proc['ppid']}/exe")
            cmd, unit = read_process(proc["pid"])
            pcmd, _ = read_process(proc["ppid"])
            st_dev, st_ino, exe = resolver.resolve(
                stat.st_dev, stat.st_ino, proc["pid"], proc["name"]
            )
            pst_dev, pst_ino, pexe = resolver.resolve(
                pstat.st_dev, pstat.st_ino, proc["ppid"], proc["pname"]
            )
            if EVERY_EXE or proc["rport"] != -1:
                initial_batch.append(
                    {
                        "pid": proc["pid"],
                        "name": proc["name"],
                        "dev": st_dev,
                        "ino": st_ino,
                        "exe": exe,
                        "cmdline": cmd,
                        "ppid": proc["ppid"],
                        "pname": proc["pname"],
                        "pdev": pst_dev,
                        "pino": pst_ino,
                        "pexe": pexe,
                        "pcmdline": pcmd,
                        "unit": unit,
                        "uid": proc["uid"],
                        "send": 0,
                        "recv": 0,
                        "family": _initial_family_for(proc["raddr"]),
                        "protocol": 0,
                        "lport": proc["lport"],
                        "rport": proc["rport"],
                        "laddr": proc["laddr"],
                        "raddr": proc["raddr"],
                        "domain": _cache_get(domain_dict, proc["raddr"]),
                        "netns": _read_netns_inode(proc["pid"]),
                    }
                )
        except Exception:  # noqa: BLE001, S110
            # Best effort: a process that is gone or unreadable is left out of the seed.
            pass
    if initial_batch:
        publish(initial_batch)

    def attach() -> BPF:
        """Pre-flight checks, load the BPF program and attach its probes and ring
        buffers.
        """
        try:
            check_bpf_requirements()
        except (RuntimeError, FileNotFoundError) as e:
            report(
                logger, "bpf-requirements-failed", f"BPF requirements check failed: {e}"
            )
            raise
        try:
            bpf_obj_path = find_bpf_object()
            optional_trace_targets = {
                "inet6_sendmsg_ret": "inet6_sendmsg",
                "inet6_recvmsg_ret": "inet6_recvmsg",
                "tcp_splice_read_ret": "tcp_splice_read",
                "mptcp_splice_read_ret": "mptcp_splice_read",
                # tcp_read_sock covers io_uring zero-copy recv (IORING_OP_RECV_ZC), but
                # every proto_ops->read_sock reaches it too: kTLS copy-mode, strparser
                # (kcm/espintcp), nvme-tcp etc., double counting or misattributing
                # bytes. So the BPF program counts only calls whose recv_actor is
                # io_zcrx_recv_skb (the actor io_uring passes) and needs its address;
                # without the symbol the program stays disabled.
                "tcp_read_sock_ret": "io_zcrx_recv_skb",
                # af_packet raw send/recv (L2 injection / capture). Optional: absent if
                # CONFIG_PACKET=n.
                "packet_sendmsg_ret": "packet_sendmsg",
                "packet_recvmsg_ret": "packet_recvmsg",
                # tun/tap raw write egress + read ingress. Optional: absent if
                # CONFIG_TUN=n.
                "tun_get_user_ret": "tun_get_user",
                "tun_do_read_ret": "tun_do_read",
                # af_xdp copy-mode tx (per-frame skb build). Optional: absent if
                # CONFIG_XDP_SOCKETS=n.
                "xsk_build_skb_ret": "xsk_build_skb",
                # Mmap-ring RX capture (opt-in mmap_ring_rx). Absent if CONFIG_PACKET=n
                # / CONFIG_XDP_SOCKETS=n.
                "packet_set_ring_ret": "packet_set_ring",
                "tpacket_rcv_ret": "tpacket_rcv",
                "xsk_bind_ret": "xsk_bind",
                "xsk_rcv_ret": "__xsk_rcv",
            }
            syms = kernel_symbol_addrs(set(optional_trace_targets.values()))
            # Gate on symbol PRESENCE (kptr_restrict=2 zeroes addresses but still lists
            # names). With kallsyms unreadable (None), assume present and let the load
            # try; a fexit prog whose target symbol is absent would otherwise fail the
            # whole bpf object load.
            disabled_traces = (
                set()
                if syms is None
                else {
                    prog
                    for prog, target in optional_trace_targets.items()
                    if target not in syms
                }
            )
            # Snapshot before the opt-in gate below, so a disabled hook is not reported
            # as a missing symbol.
            missing_symbol = set(disabled_traces)
            # tcp_read_sock_ret is the exception: its actor filter needs the real
            # address, not just existence -- disable it rather than leave it attached
            # counting nothing.
            io_zcrx_actor = 0 if syms is None else syms.get("io_zcrx_recv_skb", 0)
            if io_zcrx_actor == 0:
                disabled_traces.add("tcp_read_sock_ret")
            # Opt-in: these add a per-frame softirq hook the per-connection aggregation
            # avoids.
            if not config.monitoring.mmap_ring_rx:
                disabled_traces.update(
                    (
                        "packet_set_ring_ret",
                        "tpacket_rcv_ret",
                        "xsk_bind_ret",
                        "xsk_rcv_ret",
                    )
                )
            # A ringbuf's max_entries is its byte size, so the configured page count
            # sizes it.
            exec_ring_bytes = (
                config.monitoring.exec_ring_buffer_pages * resource.getpagesize()
            )
            b = BPF(
                obj_file=bpf_obj_path,
                map_max_entries={**map_sizes, "exec_events": exec_ring_bytes},
                disabled_programs=disabled_traces,
            )
            b.attach_kretprobe(
                event=b.get_syscall_fnname("execve"), fn_name="exec_entry"
            )
        except Exception as e:
            report(
                logger,
                "bpf-init-failed",
                "Init BPF {}{} on line {}".format(
                    type(e).__name__,
                    str(e.args),
                    e.__traceback__.tb_lineno if e.__traceback__ else "?",
                ),
            )
            raise
        use_getaddrinfo_uprobe = False
        try:
            b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="dns_entry")
            b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="dns_return")
            use_getaddrinfo_uprobe = True
        except Exception as e:  # noqa: BLE001
            # Best effort: whatever libbpf raises, the log says what goes uncounted.
            report(
                logger,
                "dns-uprobe-missing",
                f"getaddrinfo uprobe not attached ({e}); falling back to only using reverse DNS lookup",
            )
        # Attach fexit network hooks: inet_sendmsg for send, inet_recvmsg for recv;
        # sock_common_recvmsg covers af_inet6 raw / l2tp / dccp recv (not
        # inet6_recvmsg).
        try:
            b.bpf_obj.attach_trace("inet_sendmsg_ret")
            b.bpf_obj.attach_trace("inet_recvmsg_ret")
            b.bpf_obj.attach_trace("sock_common_recvmsg_ret")
        except Exception as e:
            report(
                logger,
                "bpf-attach-failed",
                f"Failed to attach network monitoring programs: {e}",
            )
            raise
        # inet6_sendmsg and inet6_recvmsg are best-effort: absent on kernels built
        # without IPv6, a missing hook only drops IPv6 send/recv bytes. Attach each
        # independently so one failing does not skip the other.
        # packet_sendmsg/packet_recvmsg are best-effort too (see
        # optional_trace_targets).
        for prog, target, msg in (
            ("inet6_sendmsg_ret", "inet6_sendmsg", "IPv6 send bytes"),
            ("inet6_recvmsg_ret", "inet6_recvmsg", "IPv6 recv bytes"),
            ("packet_sendmsg_ret", "packet_sendmsg", "AF_PACKET raw send bytes"),
            ("packet_recvmsg_ret", "packet_recvmsg", "AF_PACKET raw recv bytes"),
            ("tun_get_user_ret", "tun_get_user", "TUN/TAP raw write bytes"),
            ("tun_do_read_ret", "tun_do_read", "TUN/TAP raw read bytes"),
            ("xsk_build_skb_ret", "xsk_build_skb", "AF_XDP copy-mode tx bytes"),
            (
                "packet_set_ring_ret",
                "packet_set_ring",
                "AF_PACKET RX_RING owner tracking",
            ),
            ("tpacket_rcv_ret", "tpacket_rcv", "AF_PACKET RX_RING capture bytes"),
            ("xsk_bind_ret", "xsk_bind", "AF_XDP RX owner tracking"),
            ("xsk_rcv_ret", "__xsk_rcv", "AF_XDP RX capture bytes"),
        ):
            if prog in disabled_traces:
                if prog in missing_symbol:
                    report(
                        logger,
                        "hook-skipped",
                        f"BPF.attach_trace() skipped for {target}: kernel symbol not found, {msg} will not be recorded",
                    )
                continue
            try:
                b.bpf_obj.attach_trace(prog)
            except Exception as e:  # noqa: BLE001
                # Best effort: whatever libbpf raises, the log says what goes uncounted.
                report(
                    logger,
                    "hook-failed",
                    f"BPF.attach_trace() failed for {target}: {e}, {msg} will not be recorded",
                )
        # tcp/mptcp splice_read: recv via splice()/sendfile() bypasses recvmsg.
        # Best-effort, one hook covers v4+v6; a missing hook only drops spliced recv
        # bytes.
        for prog, target in (
            ("tcp_splice_read_ret", "tcp_splice_read"),
            ("mptcp_splice_read_ret", "mptcp_splice_read"),
        ):
            if prog in disabled_traces:
                report(
                    logger,
                    "hook-skipped",
                    f"BPF.attach_trace() skipped for {target}: kernel symbol not found, spliced recv bytes will not be recorded",
                )
                continue
            try:
                b.bpf_obj.attach_trace(prog)
            except Exception as e:  # noqa: BLE001
                # Best effort: whatever libbpf raises, the log says what goes uncounted.
                report(
                    logger,
                    "hook-failed",
                    f"BPF.attach_trace() failed for {prog}: {e}, spliced recv bytes will not be recorded",
                )
        # tcp_read_sock: recv via io_uring zero-copy (IORING_OP_RECV_ZC). Only enabled
        # when io_zcrx_recv_skb is present (see optional_trace_targets); its address
        # must be written before attach so the actor filter never counts other read_sock
        # users. A missing/disabled hook only drops io_uring zcrx recv.
        if "tcp_read_sock_ret" in disabled_traces:
            report(
                logger,
                "hook-skipped",
                "BPF.attach_trace() skipped for tcp_read_sock: io_zcrx_recv_skb address unavailable (absent, or kallsyms restricted), io_uring zero-copy recv bytes will not be recorded",
            )
        else:
            try:
                b.bpf_obj.set_global(".data.io_zcrx", struct.pack("<Q", io_zcrx_actor))
                b.bpf_obj.attach_trace("tcp_read_sock_ret")
            except Exception as e:  # noqa: BLE001
                # Best effort: whatever libbpf raises, the log says what goes uncounted.
                report(
                    logger,
                    "hook-failed",
                    f"BPF.attach_trace() failed for tcp_read_sock_ret: {e}, io_uring zero-copy recv bytes will not be recorded",
                )
        b["exec_events"].open_ring_buffer(queue_exec_event)
        if use_getaddrinfo_uprobe:
            b["dns_events"].open_ring_buffer(queue_dns_event)
        return b

    # Callbacks for bpf events, read event and hand it to publish. Maps already warned
    # as near-capacity, so the warning fires once per episode, not every drain.
    near_capacity_maps: set[str] = set()

    def drain_conn_maps():
        """Drain the per-connection aggregation maps.

        Bytes and packets are summed in-kernel per connection in the
        conn_stats4/conn_stats6 LRU hash maps, so process-ancestry resolution runs once
        per connection per drain interval rather than per packet. Each entry carries the
        send and recv totals as one event.
        """
        for map_name, key_type, map_family in (
            ("conn_stats4", ConnKey4, socket.AF_INET),
            ("conn_stats6", ConnKey6, socket.AF_INET6),
            ("conn_stats_packet", ConnKeyPacket, socket.AF_PACKET),
        ):
            try:
                entries = b.drain_map(map_name, key_type, ConnVal)
            except Exception as e:  # noqa: BLE001
                # The reader outlives any one drain; the error is logged.
                report(
                    logger,
                    "drain-failed",
                    "BPF drain {} {}{} on line {}".format(
                        map_name,
                        type(e).__name__,
                        str(e.args),
                        e.__traceback__.tb_lineno if e.__traceback__ else "?",
                    ),
                )
                continue
            # An lru map evicts oldest entries silently when full, so a drain at near
            # capacity means connections may have been dropped before drain.
            capacity = map_sizes[map_name]
            if len(entries) >= capacity * 9 // 10:
                if map_name not in near_capacity_maps:
                    near_capacity_maps.add(map_name)
                    hint = (
                        "try increasing [monitoring].conn_map_max_entries"
                        if map_name != "conn_stats_packet"
                        else "too many processes doing raw packet or TUN I/O"
                    )
                    report(
                        logger,
                        "map-near-capacity",
                        f"{map_name} near capacity ({len(entries)}/{capacity}), connections may have been evicted, {hint}",
                    )
            else:
                near_capacity_maps.discard(map_name)
            # drain_map already lookup_and_delete'd every entry from the kernel, so a
            # raise here would drop the rest of this (now unrecoverable) batch -- keep
            # per-entry failures isolated so one bad entry can't lose its siblings.
            outgoing: list[BpfEvent] = []
            process_cache: dict[int, tuple[str, str]] = {}
            # A process's connections share their exe and parent; resolved once per
            # drain.
            exe_cache: dict[tuple[int, int, int, bytes], tuple[int, int, str]] = {}

            def resolve_cached(
                st_dev: int,
                st_ino: int,
                pid: int,
                comm: bytes,
                cache: dict[
                    tuple[int, int, int, bytes], tuple[int, int, str]
                ] = exe_cache,
            ) -> tuple[int, int, str]:
                cache_key = (st_dev, st_ino, pid, comm)
                resolved = cache.get(cache_key)
                if resolved is None:
                    resolved = cache[cache_key] = resolver.resolve(
                        st_dev, st_ino, pid, comm.decode(errors="replace")
                    )
                return resolved

            for key, val in entries:
                try:
                    st_dev, st_ino, exe = resolve_cached(
                        val.dev, val.ino, key.pid, val.comm
                    )
                    pst_dev, pst_ino, pexe = resolve_cached(
                        val.pdev, val.pino, val.ppid, val.pcomm
                    )
                    cmd, unit = read_process_cached(key.pid, process_cache)
                    pcmd, _ = read_process_cached(val.ppid, process_cache)
                    family = int(map_family)
                    if map_family == socket.AF_INET:
                        laddr = socket.inet_ntop(
                            socket.AF_INET, struct.pack("I", key.saddr)
                        )
                        raddr = socket.inet_ntop(
                            socket.AF_INET, struct.pack("I", key.daddr)
                        )
                        lport, rport, protocol = key.lport, key.dport, int(key.protocol)
                    elif map_family == socket.AF_INET6:
                        family, laddr, raddr = unmap_ipv4(
                            bytes(key.saddr)[:16], bytes(key.daddr)[:16]
                        )
                        lport, rport, protocol = key.lport, key.dport, int(key.protocol)
                    else:
                        # The peer, ports and protocol live inside the app-crafted
                        # frame, so record them as unknown.
                        laddr = raddr = ""
                        lport = rport = protocol = 0
                    outgoing.append(
                        {
                            "pid": key.pid,
                            "name": val.comm.decode(errors="replace"),
                            "dev": st_dev,
                            "ino": st_ino,
                            "exe": exe,
                            "cmdline": cmd,
                            "ppid": val.ppid,
                            "pname": val.pcomm.decode(errors="replace"),
                            "pdev": pst_dev,
                            "pino": pst_ino,
                            "pexe": pexe,
                            "pcmdline": pcmd,
                            "unit": unit,
                            "uid": val.uid,
                            "send": int(val.send_bytes),
                            "recv": int(val.recv_bytes),
                            "pkts": int(val.send_pkts) + int(val.recv_pkts),
                            "family": family,
                            "protocol": protocol,
                            "lport": lport,
                            "rport": rport,
                            "laddr": laddr,
                            "raddr": raddr,
                            "domain": _cache_get(domain_dict, raddr),
                            "netns": int(key.netns),
                        }
                    )
                    if len(outgoing) >= CONN_DRAIN_CHUNK:
                        publish(outgoing)
                        outgoing = []
                except Exception as e:  # noqa: BLE001
                    # The reader outlives any one drain; the error is logged.
                    report(
                        logger,
                        "drain-entry-failed",
                        "BPF drain entry {}{} on line {}".format(
                            type(e).__name__,
                            str(e.args),
                            e.__traceback__.tb_lineno if e.__traceback__ else "?",
                        ),
                    )
            if outgoing:
                publish(outgoing)

    def queue_exec_event(ctx, data, size):
        event = b["exec_events"].event(data)
        # Resolve while the process is young even without every_exe: it fills the caches
        # its connections fall back on once a short-lived process has exited.
        st_dev, st_ino, exe = resolver.resolve(
            event.dev, event.ino, event.pid, event.comm.decode(errors="replace")
        )
        pst_dev, pst_ino, pexe = resolver.resolve(
            event.pdev, event.pino, event.ppid, event.pcomm.decode(errors="replace")
        )
        # What was read under this pid before belongs to the program before the exec, or
        # to an earlier process the pid was reused from; it must not answer once this
        # one has exited.
        last_read.pop(event.pid, None)
        cmd, unit = read_process(event.pid)
        if EVERY_EXE:
            publish(
                [
                    {
                        "pid": event.pid,
                        "name": event.comm.decode(errors="replace"),
                        "dev": st_dev,
                        "ino": st_ino,
                        "exe": exe,
                        "cmdline": cmd,
                        "ppid": event.ppid,
                        "pname": event.pcomm.decode(errors="replace"),
                        "pdev": pst_dev,
                        "pino": pst_ino,
                        "pexe": pexe,
                        "pcmdline": read_process(event.ppid)[0],
                        "unit": unit,
                        "uid": event.uid,
                        "send": 0,
                        "recv": 0,
                        "family": 0,
                        "protocol": 0,
                        "lport": -1,
                        "rport": -1,
                        "laddr": "",
                        "raddr": "",
                        "domain": "",
                        "netns": 0,
                    }
                ]
            )

    def queue_dns_event(ctx, data, size):
        event = b["dns_events"].event(data)
        if event.family == socket.AF_INET:
            ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        else:
            ip = socket.inet_ntop(socket.AF_INET6, bytes(event.daddr6))
        domain = event.host.decode("utf-8", "replace")
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            _cache_put(domain_dict, ip, ".".join(reversed(domain.split("."))))

    b = attach()
    # Probes are attached, so the main thread can sd_notify READY.
    ready.set()
    # Main loop: poll the exec/dns ring buffer on a short timeout so DNS/exec context
    # stays fresh, and drain the in-kernel connection aggregation maps on a fixed
    # interval. Bandwidth is accumulated in-kernel between drains, so the userspace cost
    # scales with the number of active connections per interval rather than the packet
    # rate. A full ring drops silently, so read the BPF drop counters each drain and log
    # any increase.
    ring_drop_state = [0, 0]  # last-reported (exec, dns) totals

    def report_ring_drops() -> None:
        try:
            exec_drops = struct.unpack(
                "<Q", b.bpf_obj.get_global(".data.execdrops", 8)
            )[0]
            dns_drops = struct.unpack("<Q", b.bpf_obj.get_global(".data.dnsdrops", 8))[
                0
            ]
        except Exception:  # noqa: BLE001
            # Counters that cannot be read leave nothing to report this drain.
            return
        if exec_drops > ring_drop_state[0]:
            report(
                logger,
                "exec-ring-full",
                f"exec ring buffer full: dropped {exec_drops - ring_drop_state[0]} exec event(s) (total {exec_drops}); their process attribution is lost",
            )
            ring_drop_state[0] = exec_drops
        if dns_drops > ring_drop_state[1]:
            report(
                logger,
                "dns-ring-full",
                f"dns ring buffer full: dropped {dns_drops - ring_drop_state[1]} dns event(s) (total {dns_drops})",
            )
            ring_drop_state[1] = dns_drops

    drain_interval = 1.0
    next_drain = time.monotonic() + drain_interval
    try:
        while not stop.is_set():
            if reattach.is_set():
                # After a suspend: hand over what the maps hold, then load the program
                # afresh; its counters, the ring drop totals among them, start from
                # zero.
                reattach.clear()
                drain_conn_maps()
                b.cleanup()
                b = attach()
                ring_drop_state[:] = [0, 0]
                next_drain = time.monotonic() + drain_interval
                continue
            try:
                b.ring_buffer_poll(timeout=200)
                now = time.monotonic()
                if now >= next_drain:
                    drain_conn_maps()
                    report_ring_drops()
                    next_drain = now + drain_interval
            except Exception as e:  # noqa: BLE001
                # The reader outlives any one drain; the error is logged.
                report(
                    logger,
                    "monitor-failed",
                    "BPF {}{} on line {}".format(
                        type(e).__name__,
                        str(e.args),
                        e.__traceback__.tb_lineno if e.__traceback__ else "?",
                    ),
                )
        # Hand over what the maps still hold before shutting down.
        drain_conn_maps()
    finally:
        b.cleanup()
