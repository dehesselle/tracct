# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""Regression tests for robustness against corrupt inputs: a malformed config.toml or
state.json must never crash-loop the daemon. All pure-Python, no root/BPF."""

import ctypes
import json
import os
import socket
import struct
import subprocess
import sys
import time

import pytest

import picosnitch.utils as utils
from picosnitch.bpf_wrapper import ConnKey4, ConnKey6, ConnVal, DNSEvent, ExecEvent
from picosnitch.config import Config, load_config
from picosnitch.types import FanotifyEventMetadata


def test_corrupt_config_falls_back_to_defaults(tmp_path):
    (tmp_path / "config.toml").write_text("this is [not valid toml @@@\nx=")
    config = load_config(tmp_path / "config.toml")
    assert isinstance(config, Config)
    assert config.database.enabled is True  # defaults intact, no exception raised


def test_non_utf8_config_falls_back_to_defaults(tmp_path):
    # non-UTF-8 config.toml raises UnicodeDecodeError (not TOMLDecodeError); must still fall back
    (tmp_path / "config.toml").write_bytes(b'owner = "caf\xe9"\n')  # latin-1 e-acute, invalid UTF-8
    config = load_config(tmp_path / "config.toml")
    assert isinstance(config, Config)
    assert config.database.enabled is True  # defaults intact, no exception raised


def test_config_numeric_clamps(tmp_path):
    (tmp_path / "config.toml").write_text(
        "[monitoring]\nexec_ring_buffer_pages = 3\nconn_map_max_entries = 0\nrlimit_nofile = true\nst_dev_mask = 4294967296\n[database]\nretention_days = -1\nwrite_limit_seconds = -1\n"
    )
    config = load_config(tmp_path / "config.toml")
    assert config.monitoring.exec_ring_buffer_pages == 256  # non-power-of-two clamped to default
    assert config.monitoring.conn_map_max_entries == 65536  # < 1 clamped to default
    assert config.monitoring.st_dev_mask is None
    assert config.database.retention_days == 30
    assert config.database.write_limit_seconds == 10


def test_config_valid_values_preserved(tmp_path):
    (tmp_path / "config.toml").write_text("[monitoring]\nexec_ring_buffer_pages = 512\nconn_map_max_entries = 1024\n")
    config = load_config(tmp_path / "config.toml")
    assert config.monitoring.exec_ring_buffer_pages == 512
    assert config.monitoring.conn_map_max_entries == 1024


def test_config_renamed_key_warns_and_is_ignored(tmp_path, caplog):
    (tmp_path / "config.toml").write_text("[monitoring]\nperf_ring_buffer_pages = 512\n")
    config = load_config(tmp_path / "config.toml")
    assert config.monitoring.exec_ring_buffer_pages == 256  # old name no longer applies
    assert "config.monitoring.perf_ring_buffer_pages: unknown option" in caplog.text


def test_config_scalar_for_list_field_skipped(tmp_path):
    """a scalar where a list is expected (e.g. ignore_ports = 443) must keep the default:
    it would TypeError in the secondary's filters every write cycle, halting connection
    logging and growing new_processes unboundedly."""
    (tmp_path / "config.toml").write_text('[log]\nignore_ports = 443\nignore_domains = "example.com"\nignore_ips = "10.0.0.1"\n')
    config = load_config(tmp_path / "config.toml")
    assert config.log.ignore_ports == []
    assert config.log.ignore_domains == []
    assert config.log.ignore_ips == []


def test_config_numeric_upper_clamps(tmp_path):
    """Absurd but positive / power-of-two BPF sizes must be clamped to defaults, not handed to
    the perf mmap or BPF map alloc where they crash-loop the daemon (conn also wraps a c_uint32)."""
    (tmp_path / "config.toml").write_text("[monitoring]\nexec_ring_buffer_pages = 1073741824\nconn_map_max_entries = 8589934592\n")
    config = load_config(tmp_path / "config.toml")
    assert config.monitoring.exec_ring_buffer_pages == 256  # 2^30 is a power of two but over max
    assert config.monitoring.conn_map_max_entries == 65536  # 2^33 over max (and would wrap c_uint32)


def test_config_viewer_group_reset_when_missing(tmp_path):
    """a group that doesn't exist can't be handed the sockets; reset it instead of failing later."""
    (tmp_path / "config.toml").write_text('[viewer]\ngroup = "no_such_group_xyz123"\n')
    assert load_config(tmp_path / "config.toml").viewer.group == ""
    (tmp_path / "config.toml").write_text('[viewer]\ngroup = "root"\n')
    assert load_config(tmp_path / "config.toml").viewer.group == "root"


def test_config_unknown_options_warn(tmp_path, caplog):
    """removed sections and typos must be reported, not silently ignored."""
    (tmp_path / "config.toml").write_text('[virustotal]\napi_key = "x"\n[database]\nretention_dayz = 7\n')
    config = load_config(tmp_path / "config.toml")
    assert config.database.retention_days == 30
    assert "config.virustotal: unknown section" in caplog.text
    assert "config.database.retention_dayz: unknown option" in caplog.text


def test_missing_config_uses_defaults(tmp_path):
    assert load_config(tmp_path / "config.toml") == Config()


def test_paths_follow_systemd_directories(tmp_path):
    """the daemon finds its directories where the unit put them; the first entry wins when a
    unit lists several, and a missing variable falls back to the default."""
    code = "from picosnitch import constants as c; print(c.CONFIG_PATH, c.STATE_DIR, c.RUN_DIR, c.DB_PATH)"
    env = {k: v for k, v in os.environ.items() if k not in ("PICOSNITCH_CONFIG", "CONFIGURATION_DIRECTORY", "STATE_DIRECTORY", "RUNTIME_DIRECTORY")}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout.split()
    assert out == ["/etc/opt/picosnitch/config.toml", "/var/lib/picosnitch", "/run/picosnitch", "/var/lib/picosnitch/picosnitch.db"]
    env.update(CONFIGURATION_DIRECTORY=f"{tmp_path}/etc", STATE_DIRECTORY=f"{tmp_path}/state:{tmp_path}/other", RUNTIME_DIRECTORY=f"{tmp_path}/run")
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout.split()
    assert out == [f"{tmp_path}/etc/config.toml", f"{tmp_path}/state", f"{tmp_path}/run", f"{tmp_path}/state/picosnitch.db"]
    env["PICOSNITCH_CONFIG"] = f"{tmp_path}/custom.toml"
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout.split()
    assert out[0] == f"{tmp_path}/custom.toml"


def test_config_ignore_ips_validated(tmp_path):
    """log.ignore_ips entries that aren't valid networks must be dropped (a host-bit CIDR is kept
    and later normalized with strict=False); else secondary crashes building ignored_networks at
    boot (list[str] skips load_config's type check, so a non-list must also reset to [])."""
    import ipaddress

    (tmp_path / "config.toml").write_text('[log]\nignore_ips = ["not-an-ip", "192.168.1.5/24", "10.0.0.0/8"]\n')
    config = load_config(tmp_path / "config.toml")
    assert config.log.ignore_ips == ["192.168.1.5/24", "10.0.0.0/8"]  # invalid dropped, valid kept
    [ipaddress.ip_network(x, strict=False) for x in config.log.ignore_ips]  # consumer must not raise
    (tmp_path / "config.toml").write_text('[log]\nignore_ips = "1.2.3.4"\n')  # not a list
    assert load_config(tmp_path / "config.toml").log.ignore_ips == []


def test_config_ignore_domains_validated(tmp_path):
    """log.ignore_domains entries that aren't non-empty strings must be dropped: a non-str crashes
    secondary's startswith() filter every write cycle (halting all logging), an empty string matches
    every domain (silently dropping all connections) -- both outside the subprocess try/except."""
    (tmp_path / "config.toml").write_text('[log]\nignore_domains = ["ads.", "", "telemetry."]\n')
    config = load_config(tmp_path / "config.toml")
    assert config.log.ignore_domains == ["ads.", "telemetry."]  # empty string dropped
    for prefix in config.log.ignore_domains:  # consumer must not raise
        "example.com".startswith(prefix)


def test_config_ignore_ports_and_hashes_validated(tmp_path):
    digest = "A" * 64
    (tmp_path / "config.toml").write_text(f'[log]\nignore_ports = [true, -2, -1, 443, 65536]\nignore_sha256 = [5, "bad", "{digest}"]\n')
    config = load_config(tmp_path / "config.toml")
    assert config.log.ignore_ports == [-1, 443]
    assert config.log.ignore_sha256 == [digest.lower()]


def test_maintain_database_quarantines_corrupt(tmp_path):
    """maintain_database must purge a healthy db, but quarantine a corrupt/table-missing db to
    .bad and exit (so the next boot recreates it) rather than crash-loop; a version mismatch must
    exit WITHOUT quarantining (migratable data preserved)."""
    import sqlite3

    import pytest

    from picosnitch.constants import DB_VERSION
    from picosnitch.subprocesses.secondary import maintain_database

    db = tmp_path / "picosnitch.db"
    bad = tmp_path / "picosnitch.db.bad"

    def fresh(version=DB_VERSION):
        db.unlink(missing_ok=True)
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE connections (contime INTEGER, domain_id INTEGER, laddr_id INTEGER, raddr_id INTEGER, exe_id INTEGER, pexe_id INTEGER, gpexe_id INTEGER)")
        con.execute("CREATE TABLE domains (id INTEGER)")
        con.execute("CREATE TABLE addresses (id INTEGER)")
        con.execute("CREATE TABLE executables (id INTEGER)")
        con.execute(f"PRAGMA user_version = {version}")
        con.commit()
        con.close()

    fresh()  # healthy -> purge, no quarantine, no exit
    maintain_database(db, 365)
    assert db.exists() and not bad.exists()

    fresh()  # missing table -> quarantine + exit
    con = sqlite3.connect(db)
    con.execute("DROP TABLE connections")
    con.commit()
    con.close()
    with pytest.raises(SystemExit):
        maintain_database(db, 365)
    assert bad.exists() and not db.exists()

    bad.unlink()  # not-a-database file -> quarantine + exit
    db.write_bytes(b"this is not a sqlite database" * 8)
    with pytest.raises(SystemExit):
        maintain_database(db, 365)
    assert bad.exists() and not db.exists()

    bad.unlink()  # wrong version -> exit but do NOT destroy the db
    fresh(version=DB_VERSION - 1)
    with pytest.raises(SystemExit):
        maintain_database(db, 365)
    assert db.exists() and not bad.exists()

    bad.unlink(missing_ok=True)  # right table name, wrong columns -> "no such column" -> quarantine
    db.unlink(missing_ok=True)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE connections (foo INTEGER)")
    con.execute(f"PRAGMA user_version = {DB_VERSION}")
    con.commit()
    con.close()
    with pytest.raises(SystemExit):
        maintain_database(db, 365)
    assert bad.exists() and not db.exists()


def test_maintain_database_purges_orphans(tmp_path):
    """after connections age out, the reference tables (executables/domains/addresses)
    must shed rows no live connection points at, while referenced rows and the id=0
    sentinel survive -- otherwise executables grows unbounded with argv cardinality."""
    import sqlite3

    from picosnitch.constants import DB_VERSION, SCHEMA_ADDRESSES, SCHEMA_CONNECTIONS, SCHEMA_DOMAINS, SCHEMA_EXECUTABLES
    from picosnitch.subprocesses.secondary import maintain_database

    db = tmp_path / "picosnitch.db"
    con = sqlite3.connect(db)
    con.execute(f"CREATE TABLE executables ({SCHEMA_EXECUTABLES}) STRICT")
    con.execute(f"CREATE TABLE domains ({SCHEMA_DOMAINS}) STRICT")
    con.execute(f"CREATE TABLE addresses ({SCHEMA_ADDRESSES}) STRICT")
    con.execute(f"CREATE TABLE connections ({SCHEMA_CONNECTIONS}) STRICT")
    for t in ("executables", "domains", "addresses"):
        col = "exe, name, cmdline, sha256" if t == "executables" else ("domain" if t == "domains" else "addr")
        vals = "'', '', '', ''" if t == "executables" else "''"
        con.execute(f"INSERT INTO {t}(id, {col}) VALUES (0, {vals})")  # sentinel
    # id 1 = referenced by a live connection; id 2 = orphan (no connection points at it)
    con.execute("INSERT INTO executables(id, exe, name, cmdline, sha256) VALUES (1, '/bin/live', 'live', 'live', 'a')")
    con.execute("INSERT INTO executables(id, exe, name, cmdline, sha256) VALUES (2, '/bin/orphan', 'orphan', 'orphan --token-999', 'b')")
    con.execute("INSERT INTO domains(id, domain) VALUES (1, 'live.example'), (2, 'orphan.example')")
    con.execute("INSERT INTO addresses(id, addr) VALUES (1, '10.0.0.1'), (2, '10.0.0.2')")
    now = int(time.time())
    # one live connection referencing exe 1 / domain 1 / addr 1 (as laddr AND raddr)
    con.execute(f"INSERT INTO connections VALUES ({now}, 0, 0, 1, 1, 1, 1, 0, 2, 6, 0, 443, 1, 1, 1, 0)")
    con.execute(f"PRAGMA user_version = {DB_VERSION}")
    con.commit()
    con.close()

    maintain_database(db, 365)

    con = sqlite3.connect(db)
    assert sorted(r[0] for r in con.execute("SELECT id FROM executables")) == [0, 1]  # orphan 2 purged, sentinel + live kept
    assert sorted(r[0] for r in con.execute("SELECT id FROM domains")) == [0, 1]
    assert sorted(r[0] for r in con.execute("SELECT id FROM addresses")) == [0, 1]
    con.close()


def test_db_is_corrupt(tmp_path):
    """_db_is_corrupt must flag an unopenable / missing-table / wrong-column db (to be
    quarantined) but not a valid or merely wrong-version one."""
    import sqlite3

    from picosnitch.cli import _db_is_corrupt
    from picosnitch.constants import DB_VERSION

    def mkdb(name, connections_cols="contime INTEGER, domain_id INTEGER, laddr_id INTEGER, raddr_id INTEGER", tables=True, version=DB_VERSION):
        p = tmp_path / name
        con = sqlite3.connect(p)
        if tables:
            con.execute(f"CREATE TABLE connections ({connections_cols})")
            con.execute("CREATE TABLE domains (id INTEGER)")
            con.execute("CREATE TABLE addresses (id INTEGER)")
            con.execute("CREATE TABLE executables (id INTEGER, exe TEXT, name TEXT, cmdline TEXT, sha256 TEXT)")
        con.execute(f"PRAGMA user_version = {version}")
        con.commit()
        con.close()
        return p

    assert _db_is_corrupt(mkdb("ok.db")) is False
    assert _db_is_corrupt(mkdb("notables.db", tables=False)) is True  # missing tables -> quarantine
    assert _db_is_corrupt(mkdb("wrongcols.db", connections_cols="foo INTEGER")) is True  # right name, wrong columns
    assert _db_is_corrupt(mkdb("oldver.db", version=DB_VERSION - 1)) is False  # wrong version -> keep for check_database
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"not a sqlite database" * 8)
    assert _db_is_corrupt(garbage) is True
    target = mkdb("target.db")
    symlink = tmp_path / "symlink.db"
    symlink.symlink_to(target)
    assert _db_is_corrupt(symlink) is True
    hardlink = tmp_path / "hardlink.db"
    os.link(target, hardlink)
    assert _db_is_corrupt(hardlink) is True
    with pytest.raises(sqlite3.OperationalError):
        utils.connect_db_readonly(symlink)


def test_db_is_corrupt_ignores_transient_errors(tmp_path, monkeypatch):
    """a healthy db that's merely locked (the live daemon mid-write, or a user's sqlite session)
    must NOT be flagged corrupt -- `start` runs _db_is_corrupt before the already-running check,
    so a lock false-positive would quarantine the live database out from under the daemon."""
    import sqlite3

    from picosnitch.cli import _db_is_corrupt
    from picosnitch.constants import DB_VERSION
    from picosnitch.utils import sqlite_error_means_corrupt

    db = tmp_path / "picosnitch.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE connections (contime INTEGER, domain_id INTEGER, laddr_id INTEGER, raddr_id INTEGER)")
    con.execute("CREATE TABLE domains (id INTEGER)")
    con.execute("CREATE TABLE addresses (id INTEGER)")
    con.execute("CREATE TABLE executables (id INTEGER, exe TEXT, name TEXT, cmdline TEXT, sha256 TEXT)")
    con.execute(f"PRAGMA user_version = {DB_VERSION}")
    con.commit()
    con.execute("BEGIN EXCLUSIVE")  # hold a write lock, as the live secondary would
    orig_connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda p, **kw: orig_connect(p, timeout=0.05, **kw))  # don't wait out the 5s busy timeout
    assert _db_is_corrupt(db) is False
    con.rollback()
    con.close()

    # the shared classifier: only structural errors mean corrupt
    assert sqlite_error_means_corrupt(sqlite3.DatabaseError("database disk image is malformed")) is True
    assert sqlite_error_means_corrupt(sqlite3.OperationalError("no such table: connections")) is True
    assert sqlite_error_means_corrupt(sqlite3.OperationalError("database is locked")) is False
    assert sqlite_error_means_corrupt(sqlite3.OperationalError("disk I/O error")) is False


def test_check_database_handles_corrupt(tmp_path, monkeypatch):
    """check_database must return 1 (not crash with sqlite3.DatabaseError, which is not an
    OperationalError) on a corrupt db, so the boot path doesn't crash-loop before init quarantines it."""
    import picosnitch.cli as cli

    monkeypatch.setattr(cli, "DB_PATH", tmp_path / "picosnitch.db")
    (tmp_path / "picosnitch.db").write_bytes(b"not a sqlite database" * 8)
    assert cli.check_database() == 1


def test_config_scalar_section_falls_back(tmp_path):
    """A valid-TOML-but-wrong-shape section (a scalar where a table is expected) must be
    ignored, not crash the daemon (regression: `field.name in section_data` raised
    TypeError on an int/bool/float section and crash-looped under systemd Restart=always)."""
    (tmp_path / "config.toml").write_text("monitoring = 5\ndatabase = true\n")
    config = load_config(tmp_path / "config.toml")  # must not raise TypeError
    assert isinstance(config, Config)
    assert config.database.enabled is True  # defaults intact
    assert config.monitoring.exec_ring_buffer_pages == 256


def test_resolve_tool_prefers_trusted_dirs(tmp_path, monkeypatch):
    """a build tool must resolve from a standard system dir even when another dir is earlier on
    $PATH (a bare-name lookup would resolve the other one first)."""
    import pytest

    from picosnitch import bpf_wrapper

    other = tmp_path / "other"
    other.mkdir()
    (other / "env").write_text("#!/bin/sh\ntrue\n")  # shadow a tool that exists in /usr/bin
    (other / "env").chmod(0o755)
    monkeypatch.setenv("PATH", str(other) + os.pathsep + os.environ.get("PATH", ""))
    resolved = bpf_wrapper._resolve_tool("env")
    assert os.path.isabs(resolved)
    assert str(other) not in resolved
    with pytest.raises(RuntimeError):
        bpf_wrapper._resolve_tool("picosnitch-no-such-build-tool-xyz")


def test_corrupt_state_json_quarantined(tmp_path, monkeypatch):
    monkeypatch.setattr(utils, "STATE_DIR", tmp_path)
    (tmp_path / "state.json").write_text("{ not valid json ")
    state = utils.load_state()  # must not raise SystemExit
    assert state["Executables"] == {} and state["SHA256"] == {}
    assert (tmp_path / "state.json.bad").exists()
    assert not (tmp_path / "state.json").exists()


def test_state_json_non_dict_value_reset(tmp_path, monkeypatch):
    monkeypatch.setattr(utils, "STATE_DIR", tmp_path)
    (tmp_path / "state.json").write_text('{"Executables": [1, 2, 3]}')
    state = utils.load_state()
    assert state["Executables"] == {}
    assert (tmp_path / "state.json.bad").exists()


def test_state_json_nested_non_dict_value_reset(tmp_path, monkeypatch):
    """A state.json whose top-level keys are dicts but whose INNER values are the wrong shape
    (SHA256 exe -> str, or a name-history exe -> non-list) must be quarantined, not accepted --
    else the secondary's hash bookkeeping breaks on every write cycle."""
    monkeypatch.setattr(utils, "STATE_DIR", tmp_path)
    (tmp_path / "state.json").write_text('{"SHA256": {"/bin/x": "corrupt"}}')  # inner must be a dict
    state = utils.load_state()
    assert state["SHA256"] == {}
    assert (tmp_path / "state.json.bad").exists()
    (tmp_path / "state.json").write_text('{"Executables": {"/bin/x": 5}}')  # inner must be a list
    state = utils.load_state()
    assert state["Executables"] == {}


def test_valid_state_json_loads(tmp_path, monkeypatch):
    monkeypatch.setattr(utils, "STATE_DIR", tmp_path)
    (tmp_path / "state.json").write_text(json.dumps({"Executables": {"/bin/x": ["abc"]}, "SHA256": {}}))
    state = utils.load_state()
    assert state["Executables"] == {"/bin/x": ["abc"]}
    assert not (tmp_path / "state.json.bad").exists()


def test_state_json_rejects_hardlinks_and_oversize(tmp_path, monkeypatch):
    monkeypatch.setattr(utils, "STATE_DIR", tmp_path)
    target = tmp_path / "target"
    target.write_text("{}")
    os.link(target, tmp_path / "state.json")
    assert utils.load_state()["Executables"] == {}
    assert (tmp_path / "state.json.bad").exists()
    (tmp_path / "state.json.bad").unlink()
    oversized = tmp_path / "state.json"
    with open(oversized, "wb") as f:
        f.truncate(256 * 1024 * 1024 + 1)
    assert utils.load_state()["Executables"] == {}
    assert (tmp_path / "state.json.bad").exists()


def test_dns_event_family_demux():
    """dns_event_t <-> DNSEvent must stay byte-synced, and the family field must tell a
    v4 0.0.0.0 answer from a v6 :: answer (regression: 0.0.0.0 was demuxed as IPv6
    because daddr == 0)."""
    assert ctypes.sizeof(DNSEvent) == 102  # host80 + daddr4 + daddr6_16 + family2, packed
    v4 = b"sinkhole.test".ljust(80, b"\x00") + struct.pack("I", 0) + b"\x00" * 16 + struct.pack("H", socket.AF_INET)
    assert DNSEvent.from_buffer_copy(v4).family == socket.AF_INET  # -> "0.0.0.0", not "::"
    v6 = b"ipv6.test".ljust(80, b"\x00") + struct.pack("I", 0) + b"\x00" * 16 + struct.pack("H", socket.AF_INET6)
    assert DNSEvent.from_buffer_copy(v6).family == socket.AF_INET6


def test_exec_event_byte_synced_with_bpf():
    """exec_event_t <-> ExecEvent must stay byte-synced or exec ancestry misparses."""
    assert ctypes.sizeof(ExecEvent) == 100  # 3*comm16 + 3*ino8 + 7*u32, packed
    assert (ExecEvent.ino.offset, ExecEvent.pid.offset, ExecEvent.dev.offset) == (48, 72, 88)


def test_conn_structs_byte_synced_with_bpf():
    """conn_key4_t/conn_key6_t/conn_val_t drive all send/recv/pkt accounting and the connection
    key; the ctypes mirrors must stay byte-exact with picosnitch.bpf.c or counts silently corrupt."""
    # keys are packed (_pack_=1): u32 pid+netns+(saddr,daddr), then u16 lport,dport,protocol,_pad
    assert ctypes.sizeof(ConnKey4) == 24  # 4+4 + 4+4 (v4 addrs) + 2*4
    assert (ConnKey4.saddr.offset, ConnKey4.daddr.offset, ConnKey4.dport.offset) == (8, 12, 18)
    assert ctypes.sizeof(ConnKey6) == 48  # 4+4 + 16+16 (v6 addrs) + 2*4
    assert (ConnKey6.saddr.offset, ConnKey6.daddr.offset, ConnKey6.dport.offset) == (8, 24, 42)
    # value is NOT packed: 3*char[16] then 7*u64 counters (8-byte aligned) then 6*u32
    assert ctypes.sizeof(ConnVal) == 128  # 48 + 56 + 24, no internal or trailing padding
    assert (ConnVal.send_bytes.offset, ConnVal.recv_bytes.offset) == (72, 80)
    assert (ConnVal.send_pkts.offset, ConnVal.recv_pkts.offset) == (88, 96)


def test_fanotify_overflow_invalidates_all_hashes():
    class Errors:
        def __init__(self):
            self.items = []

        def put(self, item):
            self.items.append(item)

    event = FanotifyEventMetadata()
    event.event_len = ctypes.sizeof(event)
    event.metadata_len = ctypes.sizeof(event)
    event.mask = 0x4000  # FAN_Q_OVERFLOW
    event.fd = -1
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, bytes(event))
        counts = {}
        errors = Errors()
        utils.get_fanotify_events(read_fd, counts, errors)  # ty: ignore[invalid-argument-type]
        assert counts == {"*": 1}
        assert errors.items == ["fanotify queue overflowed; invalidating all cached executable hashes"]
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_proc_reads_survive_non_utf8_comm():
    """a process can set a non-UTF-8 comm via prctl(PR_SET_NAME); the monitor's /proc text
    readers must degrade to replacement chars, not raise UnicodeDecodeError (which dropped
    the process's drain entry) or misparse stat/status (ppid 0, uid 0)"""
    from picosnitch.subprocesses.monitor import _read_proc_comm, _read_proc_ppid, _read_proc_status_uid

    code = 'import ctypes, time\nctypes.CDLL(None).prctl(15, b"\\xff\\xfe*bad", 0, 0, 0)\nprint("x", flush=True)\ntime.sleep(30)'
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)
    try:
        assert p.stdout is not None and p.stdout.read(1) == b"x"  # comm is set once the child prints
        comm = _read_proc_comm(p.pid)
        assert "\ufffd" in comm and "*bad" in comm  # replaced, not raised or emptied
        assert _read_proc_ppid(p.pid) == os.getpid()  # stat parse survives the comm bytes
        assert _read_proc_status_uid(p.pid) == os.geteuid()  # status parse reaches the Uid: line
    finally:
        p.kill()
        p.wait()


def test_sanitize_log_line_neutralizes_control_chars():
    """attacker-influenced fields (comm/cmdline/domain) reach error.log/exe.log; every
    C0 (except tab), DEL, and C1 (e.g. U+009B CSI) must be stripped so a viewed log can't be
    driven to emit a terminal escape or overwrite a prior line."""
    dirty = "safe\x1b[2K\x07\x08\r\n\x00mid\x7f\x9bend\ttab\u202eignored\udc9b"
    clean = utils.sanitize_log_line(dirty)
    assert all(c not in clean for c in "\x1b\x07\x08\r\n\x00\x7f\x9b")  # all control chars gone
    assert "safe" in clean and "mid" in clean and "end" in clean  # printable text preserved
    assert "\ttab" in clean  # tab kept (harmless in a log, not cursor movement here)
    assert "\u202e" not in clean
    assert "\udc9b" not in clean
