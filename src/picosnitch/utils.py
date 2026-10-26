# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import collections
import ctypes
import fcntl
import functools
import hashlib
import ipaddress
import json
import logging
import multiprocessing
import os
import socket
import sqlite3
import stat
import tempfile
import termios
import unicodedata
import urllib.parse
from pathlib import Path

from picosnitch.constants import PID_CACHE, ST_DEV_MASK, STATE_DIR
from picosnitch.types import FanotifyEventMetadata, State


def sd_notify(message: str) -> None:
    """best-effort systemd notification via the raw sd_notify(3) protocol, so the
    privileged daemon needs no python-systemd dependency. no-op unless launched by a
    Type=notify unit (NOTIFY_SOCKET set); errors are swallowed, a readiness signal
    must never take the daemon down."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            # a leading '@' selects the abstract namespace, sent as a leading NUL
            sock.sendto(message.encode(), "\0" + addr[1:] if addr[0] == "@" else addr)
    except OSError:
        pass


def sqlite_error_means_corrupt(e: sqlite3.Error) -> bool:
    """True when a sqlite error means picosnitch.db itself is unusable (quarantine+recreate);
    False for transient errors (locked by the live daemon, busy, disk I/O) where quarantining
    would destroy a healthy database. Shared by the cli boot check and the secondary purge."""
    msg = str(e).lower()
    return any(s in msg for s in ("malformed", "not a database", "no such table", "no such column", "encrypted"))


def connect_db_readonly(db_path: Path | str, timeout: float = 5.0) -> sqlite3.Connection:
    """Open a sqlite3 connection for read-only access.

    Tries `mode=ro`, then `mode=ro&immutable=1`. The immutable fallback is needed
    when the caller cannot write to the -shm / -wal sidecar files of a WAL database (e.g.
    a non-root user opening the picosnitch database written by the root
    daemon). Raises sqlite3.OperationalError if both attempts fail."""
    try:
        db_stat = os.lstat(db_path)
    except OSError as e:
        raise sqlite3.OperationalError(f"could not inspect {db_path}: {e}") from e
    if not stat.S_ISREG(db_stat.st_mode) or db_stat.st_nlink != 1:
        raise sqlite3.OperationalError(f"refusing non-regular or hardlinked database: {db_path}")
    quoted_path = urllib.parse.quote(os.fspath(db_path), safe="/")
    last_err: Exception | None = None
    for uri in (
        f"file:{quoted_path}?mode=ro",
        f"file:{quoted_path}?mode=ro&immutable=1",
    ):
        con = None
        try:
            con = sqlite3.connect(uri, uri=uri.startswith("file:"), timeout=timeout)
            # Force the connection to actually touch the file so we
            # surface "attempt to write a readonly database" here
            # instead of at the first user query.
            con.execute("PRAGMA user_version").fetchone()
            return con
        except sqlite3.OperationalError as e:
            if con is not None:
                con.close()
            last_err = e
            continue
    raise sqlite3.OperationalError(f"could not open {db_path} for reading: {last_err}")


def load_state() -> State:
    """read data for the state dictionary from state.json or init new if not found"""
    data: State = {
        "Error Log": [],
        "Exe Log": [],
        "Executables": {},
        "Names": {},
        "Parent Executables": {},
        "Parent Names": {},
        "Grandparent Executables": {},
        "Grandparent Names": {},
        "SHA256": {},
    }
    state_path = STATE_DIR / "state.json"
    keys = ["Executables", "Names", "Parent Executables", "Parent Names", "Grandparent Executables", "Grandparent Names", "SHA256"]
    if state_path.exists() or state_path.is_symlink():
        try:
            state_fd = os.open(state_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            state_stat = os.fstat(state_fd)
            if not stat.S_ISREG(state_stat.st_mode) or state_stat.st_nlink != 1:
                os.close(state_fd)
                raise OSError("state.json is not a regular, singly linked file")
            if state_stat.st_size > 256 * 1024 * 1024:
                os.close(state_fd)
                raise OSError("state.json exceeds 256 MiB")
            os.set_blocking(state_fd, True)
            with os.fdopen(state_fd, "r", encoding="utf-8", errors="surrogateescape") as json_file:
                state_record = json.load(json_file)
            if not isinstance(state_record, dict):
                raise ValueError("state.json is not a JSON object")
            for key in keys:
                if key in state_record:
                    value = state_record[key]
                    if not isinstance(value, dict):
                        raise ValueError(f"state.json[{key!r}] is not an object")
                    # validate the inner shape too: SHA256 maps exe -> {sha256: result}, the rest
                    # map exe -> [name history]. a wrong-typed entry (e.g. a str/int) breaks the
                    # secondary's hash bookkeeping on every write cycle
                    inner_type = dict if key == "SHA256" else list
                    if not all(isinstance(v, inner_type) for v in value.values()):
                        raise ValueError(f"state.json[{key!r}] has a non-{inner_type.__name__} entry")
                    data[key] = value  # ty: ignore[invalid-key]
        except (OSError, ValueError) as e:
            # corrupt/unreadable state must not crash-loop the daemon (JSONDecodeError is a
            # ValueError): quarantine the bad file and start fresh instead of sys.exit(1)
            logging.error(f"invalid state.json, starting with empty state: {e}")
            try:
                state_path.rename(state_path.with_name("state.json.bad"))
            except OSError:
                pass
            for key in keys:
                data[key] = {}  # ty: ignore[invalid-key]
    return data


def sanitize_log_line(line: str) -> str:
    """Remove control characters from a log line to prevent terminal-escape / log injection."""
    return "".join(c for c in line if c == "\t" or unicodedata.category(c) not in ("Cc", "Cf", "Cs"))


def flush_logs(state: State) -> None:
    """log pending error and new-executable entries to stderr (the journal under systemd), then clear the lists"""
    for line in state["Error Log"]:
        logging.getLogger("picosnitch.error").warning(sanitize_log_line(line))
    state["Error Log"] = []
    for line in state["Exe Log"]:
        logging.getLogger("picosnitch.exe").info(sanitize_log_line(line))
    state["Exe Log"] = []


def save_state(state: State, write_record: bool = True) -> None:
    """flush logs then atomically write state.json via tempfile + os.replace"""
    flush_logs(state)
    try:
        if write_record:
            state_path = STATE_DIR / "state.json"
            state_data = {k: state[k] for k in ("Executables", "Names", "Parent Executables", "Parent Names", "Grandparent Executables", "Grandparent Names", "SHA256")}
            fd = tempfile.NamedTemporaryFile(dir=STATE_DIR, mode="w", prefix=".state.", suffix=".tmp", delete=False, encoding="utf-8", errors="surrogateescape")
            try:
                json.dump(state_data, fd, indent=2, separators=(",", ": "), sort_keys=True, ensure_ascii=False)
                fd.flush()
                os.fsync(fd.fileno())
                fd.close()
                os.replace(fd.name, state_path)
            except BaseException:
                fd.close()
                try:
                    os.unlink(fd.name)
                except OSError:
                    pass
                raise
    except Exception as e:
        logging.error(f"picosnitch write error (state.json): {type(e).__name__}{e.args}")


# reverse-DNS results keyed by ip; getnameinfo blocks, so callers probe reverse_dns_is_cached() first
_reverse_dns_cache: collections.OrderedDict[str, str] = collections.OrderedDict()
_REVERSE_DNS_CACHE_MAX: int = 8192


def reverse_dns_is_cached(ip: str) -> bool:
    """True if `ip` already has a cached reverse-DNS result (so resolving it is free)."""
    return ip in _reverse_dns_cache


def reverse_dns_lookup(ip: str) -> str:
    """Reverse-DNS `ip` to a hostname, cached; return the ip itself on failure. A
    repeated address costs nothing; callers gate a NEW (blocking) getnameinfo with
    reverse_dns_is_cached() plus their own per-write budget so a burst of distinct
    addresses cannot stall byte accounting."""
    cached = _reverse_dns_cache.get(ip)
    if cached is not None:
        _reverse_dns_cache.move_to_end(ip)
        return cached
    try:
        host = socket.getnameinfo((ip, 0), 0)[0]
        try:
            ipaddress.ip_address(host)
            result = ip
        except ValueError:
            result = ".".join(reversed(host.split(".")))
    except Exception:
        result = ip
    _reverse_dns_cache[ip] = result
    _reverse_dns_cache.move_to_end(ip)
    if len(_reverse_dns_cache) > _REVERSE_DNS_CACHE_MAX:
        _reverse_dns_cache.popitem(last=False)
    return result


@functools.lru_cache(maxsize=PID_CACHE)
def get_sha256_fd(path: str, st_dev: int, st_ino: int, _mod_cnt: int) -> str:
    """get sha256 of process executable from /proc/monitor_pid/fd/proc_exe_fd"""
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            if not st_ino:
                return "!!! FD Stat Error"
            if (st_dev, st_ino) != get_fstat(f.fileno()):
                return "!!! FD Cache Error"
            while data := f.read(1048576):
                sha256.update(data)
        return sha256.hexdigest()
    except Exception:
        return "!!! FD Read Error"


@functools.lru_cache(maxsize=PID_CACHE)
def get_sha256_pid(pid: int, st_dev: int, st_ino: int, _mod_cnt: int = 0) -> str:
    """get sha256 of process executable from /proc/pid/exe"""
    try:
        sha256 = hashlib.sha256()
        with open(f"/proc/{pid}/exe", "rb") as f:
            if (st_dev, st_ino) != get_fstat(f.fileno()):
                return "!!! PID Recycled Error"
            while data := f.read(1048576):
                sha256.update(data)
        return sha256.hexdigest()
    except Exception:
        return "!!! PID Read Error"


def get_fstat(fd: int) -> tuple[int, int]:
    """get (st_dev, st_ino) or (0, 0) if fails"""
    try:
        stat = os.fstat(fd)
        return stat.st_dev & ST_DEV_MASK, stat.st_ino
    except Exception:
        return 0, 0


def get_fanotify_events(fan_fd: int, fan_mod_cnt: dict[str, int], q_error: multiprocessing.Queue[str]) -> None:
    """check if any watched executables were modified and increase count to trigger rehash"""
    sizeof_event = ctypes.sizeof(FanotifyEventMetadata)
    bytes_avail = ctypes.c_int()
    fcntl.ioctl(fan_fd, termios.FIONREAD, bytes_avail)
    for _ in range(0, bytes_avail.value, sizeof_event):
        event_fd = -1
        try:
            fanotify_event_metadata = FanotifyEventMetadata()
            buf = os.read(fan_fd, sizeof_event)
            if len(buf) != sizeof_event:
                raise OSError(f"short fanotify event: {len(buf)}/{sizeof_event}")
            ctypes.memmove(ctypes.addressof(fanotify_event_metadata), buf, sizeof_event)
            event_fd = fanotify_event_metadata.fd
            if fanotify_event_metadata.mask & 0x4000:  # FAN_Q_OVERFLOW
                fan_mod_cnt["*"] = fan_mod_cnt.get("*", 0) + 1
                q_error.put("fanotify queue overflowed; invalidating all cached executable hashes")
                continue
            if event_fd < 0:
                raise OSError(f"fanotify event has invalid fd {event_fd}")
            st_dev, st_ino = get_fstat(event_fd)
            fan_mod_cnt[f"{st_dev} {st_ino}"] += 1
        except Exception as e:
            q_error.put("Fanotify Event %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
        finally:
            if event_fd >= 0:
                os.close(event_fd)
