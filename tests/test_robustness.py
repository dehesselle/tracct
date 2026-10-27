# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Regression tests for robustness against corrupt inputs: a malformed config.toml or
database must never crash-loop the daemon. All pure-Python, no root/BPF."""

import ctypes
import os
import socket
import struct
import subprocess
import sys
import time

import pytest

import tracct.utils as utils
from tracct.bpf_wrapper import ConnKey4, ConnKey6, ConnVal, DNSEvent, ExecEvent
from tracct.config import Config, load_config


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
        "[monitoring]\nexec_ring_buffer_pages = 3\nconn_map_max_entries = 0\nrlimit_nofile = true\nst_dev_mask = 4294967296\n[database]\nraw_retention_days = -1\nrollup_retention_days = -1\nrollup_period_minutes = 0\n"
        "write_limit_seconds = -1\nmaintenance_interval_minutes = 0\n"
    )
    config = load_config(tmp_path / "config.toml")
    assert config.monitoring.exec_ring_buffer_pages == 256  # non-power-of-two clamped to default
    assert config.monitoring.conn_map_max_entries == 65536  # < 1 clamped to default
    assert config.monitoring.st_dev_mask is None
    assert config.database.raw_retention_days == 30
    assert config.database.rollup_retention_days == 365
    assert config.database.rollup_period_minutes == 60
    assert config.database.write_limit_seconds == 10
    assert config.database.maintenance_interval_minutes == 60


def test_config_retention_fractions(tmp_path):
    """retention takes fractions of a day and plain integers; inf and nan are replaced"""
    (tmp_path / "config.toml").write_text("[database]\nraw_retention_days = 0.01\nrollup_retention_days = 2\n")
    config = load_config(tmp_path / "config.toml")
    assert config.database.raw_retention_days == 0.01
    assert config.database.rollup_retention_days == 2.0 and isinstance(config.database.rollup_retention_days, float)
    (tmp_path / "config.toml").write_text("[database]\nraw_retention_days = inf\nrollup_retention_days = nan\n")
    config = load_config(tmp_path / "config.toml")
    assert config.database.raw_retention_days == 30
    assert config.database.rollup_retention_days == 365


def test_config_valid_values_preserved(tmp_path):
    (tmp_path / "config.toml").write_text("[monitoring]\nexec_ring_buffer_pages = 512\nconn_map_max_entries = 1024\n")
    config = load_config(tmp_path / "config.toml")
    assert config.monitoring.exec_ring_buffer_pages == 512
    assert config.monitoring.conn_map_max_entries == 1024


def test_config_scalar_for_list_field_skipped(tmp_path):
    """a scalar where a list is expected (e.g. ignore_ports = 443) must keep the default:
    it would TypeError in the writer's filters on every batch, so no connection would be
    recorded."""
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
    """unknown sections and typos must be reported, not silently ignored."""
    (tmp_path / "config.toml").write_text('[no_such_section]\nkey = "x"\n[database]\nretention_dayz = 7\n')
    config = load_config(tmp_path / "config.toml")
    assert config.database.raw_retention_days == 30
    assert "config.no_such_section: unknown section" in caplog.text
    assert "config.database.retention_dayz: unknown option" in caplog.text


def test_missing_config_uses_defaults(tmp_path):
    assert load_config(tmp_path / "config.toml") == Config()


def test_paths_follow_systemd_directories(tmp_path):
    """the daemon finds its directories where the unit put them; the first entry wins when a
    unit lists several, and a missing variable falls back to the default."""
    code = "from tracct import constants as c; print(c.CONFIG_PATH, c.STATE_DIR, c.RUN_DIR, c.DB_PATH)"
    env = {k: v for k, v in os.environ.items() if k not in ("TRACCT_CONFIG", "CONFIGURATION_DIRECTORY", "STATE_DIRECTORY", "RUNTIME_DIRECTORY")}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout.split()
    assert out == ["/etc/opt/tracct/config.toml", "/var/lib/tracct", "/run/tracct", "/var/lib/tracct/tracct.db"]
    env.update(CONFIGURATION_DIRECTORY=f"{tmp_path}/etc", STATE_DIRECTORY=f"{tmp_path}/state:{tmp_path}/other", RUNTIME_DIRECTORY=f"{tmp_path}/run")
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout.split()
    assert out == [f"{tmp_path}/etc/config.toml", f"{tmp_path}/state", f"{tmp_path}/run", f"{tmp_path}/state/tracct.db"]
    env["TRACCT_CONFIG"] = f"{tmp_path}/custom.toml"
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout.split()
    assert out[0] == f"{tmp_path}/custom.toml"


def test_config_ignore_ips_validated(tmp_path):
    """log.ignore_ips entries that aren't valid networks must be dropped (a host-bit CIDR is kept
    and later normalized with strict=False); else the writer crashes building ignored_networks at
    start (list[str] skips load_config's type check, so a non-list must also reset to [])."""
    import ipaddress

    (tmp_path / "config.toml").write_text('[log]\nignore_ips = ["not-an-ip", "192.168.1.5/24", "10.0.0.0/8"]\n')
    config = load_config(tmp_path / "config.toml")
    assert config.log.ignore_ips == ["192.168.1.5/24", "10.0.0.0/8"]  # invalid dropped, valid kept
    [ipaddress.ip_network(x, strict=False) for x in config.log.ignore_ips]  # consumer must not raise
    (tmp_path / "config.toml").write_text('[log]\nignore_ips = "1.2.3.4"\n')  # not a list
    assert load_config(tmp_path / "config.toml").log.ignore_ips == []


def test_config_ignore_domains_validated(tmp_path):
    """log.ignore_domains entries that aren't non-empty strings must be dropped: a non-str breaks
    the writer's startswith() filter on every write (nothing gets recorded), an empty string
    matches every domain (silently dropping all connections)."""
    (tmp_path / "config.toml").write_text('[log]\nignore_domains = ["ads.", "", "telemetry."]\n')
    config = load_config(tmp_path / "config.toml")
    assert config.log.ignore_domains == ["ads.", "telemetry."]  # empty string dropped
    for prefix in config.log.ignore_domains:  # consumer must not raise
        "example.com".startswith(prefix)


def test_config_ignore_ports_validated(tmp_path):
    (tmp_path / "config.toml").write_text("[log]\nignore_ports = [true, -2, -1, 443, 65536]\n")
    config = load_config(tmp_path / "config.toml")
    assert config.log.ignore_ports == [-1, 443]


def _purge_db(tmp_path):
    """a database with the real schema, its sentinels, and ids 1 (kept) and 2 (to be orphaned)"""
    import sqlite3

    from tracct.constants import DB_VERSION, INDEXES, SENTINELS, TABLES

    con = sqlite3.connect(tmp_path / "tracct.db")
    for table, schema in TABLES:
        con.execute(f"CREATE TABLE {table} ({schema}) STRICT")
    for statement in SENTINELS + INDEXES:
        con.execute(statement)
    con.execute("INSERT INTO executables VALUES (1, '/bin/live', 'live', 'live'), (2, '/bin/old', 'old', 'old --token-999')")
    con.execute("INSERT INTO domains VALUES (1, 'live.example'), (2, 'old.example')")
    con.execute("INSERT INTO addresses VALUES (1, '10.0.0.1'), (2, '10.0.0.2')")
    con.execute(f"PRAGMA user_version = {DB_VERSION}")
    con.commit()
    return con


def _insert_connections(con, *rows):
    # each row (contime, ref[, lport, rport]) refers to ref as exe, parent, both addresses and domain
    con.executemany(
        "INSERT INTO connections VALUES (?, 10, 20, 1, ?, ?, 0, 0, 2, 6, ?, ?, ?, ?, ?, 0, 0)",
        [(row[0], row[1], row[1], *(row[2:] or (50000, 443)), row[1], row[1], row[1]) for row in rows],
    )
    con.commit()


def _config(raw_days=7, rollup_days=365):
    config = Config()
    config.database.raw_retention_days = raw_days
    config.database.rollup_retention_days = rollup_days
    return config


def test_roll_up_sums_closed_periods(tmp_path):
    """each closed period becomes one rollup row per identity, without ephemeral ports; the
    open period and the newest row's period wait, and a second pass finds nothing new"""
    import tracct.writer as writer

    con = _purge_db(tmp_path)
    hour = 3600
    now = int(time.time())
    first = now // hour * hour - 3 * hour
    # a client row (ephemeral local port) twice in one period, a server row (ephemeral peer
    # port), and a row in the current period
    _insert_connections(con, (first + 10, 1), (first + 20, 1, 50001, 443), (first + hour + 5, 1, 443, 50002), (now, 1))
    assert writer.roll_up(con, 60, lambda: False, ephemeral=32768) == 2
    rows = con.execute("SELECT period, lport, rport, send, recv, events, rows FROM connections_rollup ORDER BY period").fetchall()
    assert rows == [(first, 0, 443, 20, 40, 2, 2), (first + hour, 443, 0, 10, 20, 1, 1)]
    assert con.execute("SELECT value FROM meta WHERE key = 'rollup_watermark'").fetchone()[0] == now // hour * hour
    assert writer.roll_up(con, 60, lambda: False, ephemeral=32768) == 0
    con.close()


def test_purge_database_in_chunks(tmp_path, monkeypatch):
    """raw rows past their window go in chunks once rolled up, rollups past theirs too, with a
    hook between chunks; then the lookup entries nothing refers to any more, a table per hook
    call. recent rows, their entries and the sentinels stay"""
    import tracct.writer as writer

    monkeypatch.setattr(writer, "PURGE_CHUNK_ROWS", 2)
    con = _purge_db(tmp_path)
    now = int(time.time())
    _insert_connections(con, *[(now - 10 * 86400, 2)] * 5, (now, 1))
    calls = []
    # one period rolled up, 5 raw rows and that period's rollup row deleted
    assert writer.purge_database(con, _config(7, 8), lambda: calls.append(1) or False) == (1, 6)
    # after the rolled-up period and after the two full chunks of raw rows
    assert len(calls) == 3
    assert con.execute("SELECT count(*) FROM connections").fetchone()[0] == 1
    calls.clear()
    assert writer.delete_orphans(con, lambda: calls.append(1) or False) == 3
    assert len(calls) == len(writer.ORPHAN_DELETES)
    for table in ("executables", "domains", "addresses"):
        assert [r[0] for r in con.execute(f"SELECT id FROM {table} ORDER BY id")] == [0, 1]
    con.close()


def test_delete_orphans_stops_between_tables(tmp_path):
    """a hook returning True ends the cleanup after the table it follows, which is committed"""
    import tracct.writer as writer

    con = _purge_db(tmp_path)
    _insert_connections(con, (int(time.time()), 1))
    # executables come first: its orphan goes, the domain and address stay for the next cleanup
    assert writer.delete_orphans(con, lambda: True) == 1
    assert [r[0] for r in con.execute("SELECT id FROM executables ORDER BY id")] == [0, 1]
    assert [r[0] for r in con.execute("SELECT id FROM domains ORDER BY id")] == [0, 1, 2]
    con.close()


def test_purge_database_keeps_what_is_not_rolled_up(tmp_path):
    """raw rows past their window stay until their period is rolled up, and the rollup keeps
    their entries referenced"""
    import tracct.writer as writer

    con = _purge_db(tmp_path)
    now = int(time.time())
    # two old rows an hour apart, both past the raw window
    _insert_connections(con, (now - 10 * 86400, 2), (now - 10 * 86400 + 3600, 2), (now, 1))
    # the hook stops the rollup after the first period: only that period's raw row may go
    assert writer.purge_database(con, _config(), lambda: True) == (1, 1)
    assert con.execute("SELECT count(*) FROM connections").fetchone()[0] == 2
    assert con.execute("SELECT count(*) FROM connections_rollup").fetchone()[0] == 1
    assert sorted(r[0] for r in con.execute("SELECT id FROM executables")) == [0, 1, 2]
    # the second period follows, and exe 2 lives on in the rollup once its raw rows are gone
    assert writer.purge_database(con, _config(), lambda: False) == (1, 1)
    assert con.execute("SELECT count(*) FROM connections").fetchone()[0] == 1
    # only address 2 goes, rollups keep no addresses
    assert writer.delete_orphans(con, lambda: False) == 1
    assert sorted(r[0] for r in con.execute("SELECT id FROM executables")) == [0, 1, 2]
    assert sorted(r[0] for r in con.execute("SELECT id FROM addresses")) == [0, 1]
    con.close()


def test_purge_database_guards(tmp_path, monkeypatch):
    """a hook returning True ends the purge after a chunk; retention 0 keeps everything; a
    clock ahead of the newest row deletes nothing"""
    import tracct.writer as writer

    monkeypatch.setattr(writer, "PURGE_CHUNK_ROWS", 2)
    con = _purge_db(tmp_path)
    now = int(time.time())
    _insert_connections(con, *[(now - 10 * 86400, 2)] * 4, (now - 3 * 86400, 2))
    assert writer.purge_database(con, _config(0, 0), lambda: False)[1] == 0
    assert writer.purge_database(con, _config(7, 0), lambda: True)[1] == 2
    assert con.execute("SELECT count(*) FROM connections").fetchone()[0] == 3
    # the newest row is 3 days old, so a 1 day window would delete everything: clock ahead
    assert writer.purge_database(con, _config(1, 0), lambda: False)[1] == 0
    assert con.execute("SELECT count(*) FROM connections").fetchone()[0] == 3
    con.close()


def test_roll_up_after_the_clock_went_back(tmp_path, monkeypatch):
    """a watermark ahead of the clock (rolled up while it ran ahead) moves back to the current
    period; rollups from then on go, and the rows written since are rolled up once closed"""
    import tracct.writer as writer

    con = _purge_db(tmp_path)
    hour = 3600
    now = int(time.time())
    current = now // hour * hour
    ahead = current + 2 * 86400
    # a row from the ahead clock, already rolled up, and one written after the clock went back
    _insert_connections(con, (ahead + 10, 1), (now, 2))
    con.execute("INSERT INTO connections_rollup SELECT ?, 1, 1, 0, 0, 2, 6, 0, 443, 1, 0, 0, 10, 20, 1, 1", (ahead,))
    con.execute("INSERT INTO meta(key, value) VALUES ('rollup_watermark', ?)", (ahead + hour,))
    con.commit()
    errors = []
    monkeypatch.setattr(writer, "log_error", errors.append)
    assert writer.roll_up(con, 60, lambda: False, ephemeral=32768) == 0
    assert len(errors) == 1
    assert con.execute("SELECT value FROM meta WHERE key = 'rollup_watermark'").fetchone()[0] == current
    assert con.execute("SELECT count(*) FROM connections_rollup").fetchone()[0] == 0
    # an hour on, the period of the row written since is closed and rolled up
    monkeypatch.setattr(writer.time, "time", lambda: now + hour)
    assert writer.roll_up(con, 60, lambda: False, ephemeral=32768) == 1
    assert con.execute("SELECT period, exe_id FROM connections_rollup").fetchall() == [(current, 2)]
    con.close()


def test_clock_check():
    """the wall clock's jump against the boot clock: 0 at first and while both advance alike"""
    from tracct.writer import ClockCheck

    wall, boot = [1000.0], [50.0]
    clock = ClockCheck(lambda: wall[0], lambda: boot[0])
    assert clock.jump() == 0
    wall[0], boot[0] = 4600.0, 3650.0
    assert clock.jump() == 0
    # set two days ahead within a minute, then back
    wall[0], boot[0] = 4660.0 + 2 * 86400, 3710.0
    assert clock.jump() == 2 * 86400
    wall[0], boot[0] = 4720.0, 3770.0
    assert clock.jump() == -2 * 86400


def test_purge_database_fraction_of_a_day(tmp_path):
    """a retention of minutes, given as a fraction of a day, purges at that many seconds"""
    import tracct.writer as writer

    con = _purge_db(tmp_path)
    now = int(time.time())
    _insert_connections(con, (now - 1800, 2), (now - 300, 1))
    config = _config(15 / 1440, 0)
    config.database.rollup_period_minutes = 1
    assert writer.purge_database(con, config, lambda: False)[1] == 1
    assert [r[0] for r in con.execute("SELECT contime FROM connections")] == [now - 300]
    con.close()


def test_init_database_uses_wal(tmp_path, monkeypatch):
    """a new database is in WAL mode, and one made without it is converted at the next start"""
    import sqlite3

    import tracct.cli as cli

    db = tmp_path / "tracct.db"
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DB_PATH", db)

    def journal_mode() -> str:
        con = sqlite3.connect(db)
        try:
            return con.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            con.close()

    cli.init_database()
    assert journal_mode() == "wal"
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=DELETE")
    con.close()
    assert journal_mode() == "delete"
    cli.init_database()
    assert journal_mode() == "wal"


def test_quarantine_moves_wal_files(tmp_path):
    """the WAL files go along, or one would be replayed into the next database"""
    for name in ("tracct.db", "tracct.db-wal"):
        (tmp_path / name).write_bytes(name.encode())
    utils.quarantine_database(tmp_path / "tracct.db")
    assert sorted(path.name for path in tmp_path.iterdir()) == ["tracct.db.bad", "tracct.db.bad-wal"]
    assert (tmp_path / "tracct.db.bad-wal").read_bytes() == b"tracct.db-wal"


def test_db_is_corrupt(tmp_path):
    """_db_is_corrupt must flag an unopenable / missing-table / wrong-column db (to be
    quarantined) but not a valid or merely wrong-version one."""
    import sqlite3

    from tracct.cli import _db_is_corrupt
    from tracct.constants import DB_VERSION, TABLES

    def mkdb(name, connections_cols=None, tables=True, version=DB_VERSION):
        p = tmp_path / name
        con = sqlite3.connect(p)
        if tables:
            for table, schema in TABLES:
                con.execute(f"CREATE TABLE {table} ({connections_cols if table == 'connections' and connections_cols else schema})")
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

    from tracct.cli import _db_is_corrupt
    from tracct.constants import DB_VERSION
    from tracct.utils import sqlite_error_means_corrupt

    db = tmp_path / "tracct.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE connections (contime INTEGER, domain_id INTEGER, laddr_id INTEGER, raddr_id INTEGER)")
    con.execute("CREATE TABLE domains (id INTEGER)")
    con.execute("CREATE TABLE addresses (id INTEGER)")
    con.execute("CREATE TABLE executables (id INTEGER, exe TEXT, name TEXT, cmdline TEXT)")
    con.execute(f"PRAGMA user_version = {DB_VERSION}")
    con.commit()
    con.execute("BEGIN EXCLUSIVE")  # hold a write lock, as the live writer would
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
    import tracct.cli as cli

    monkeypatch.setattr(cli, "DB_PATH", tmp_path / "tracct.db")
    (tmp_path / "tracct.db").write_bytes(b"not a sqlite database" * 8)
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

    from tracct import bpf_wrapper

    other = tmp_path / "other"
    other.mkdir()
    (other / "env").write_text("#!/bin/sh\ntrue\n")  # shadow a tool that exists in /usr/bin
    (other / "env").chmod(0o755)
    monkeypatch.setenv("PATH", str(other) + os.pathsep + os.environ.get("PATH", ""))
    resolved = bpf_wrapper._resolve_tool("env")
    assert os.path.isabs(resolved)
    assert str(other) not in resolved
    with pytest.raises(RuntimeError):
        bpf_wrapper._resolve_tool("tracct-no-such-build-tool-xyz")


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
    key; the ctypes mirrors must stay byte-exact with tracct.bpf.c or counts silently corrupt."""
    # keys are packed (_pack_=1): u32 pid+netns+(saddr,daddr), then u16 lport,dport,protocol,_pad
    assert ctypes.sizeof(ConnKey4) == 24  # 4+4 + 4+4 (v4 addrs) + 2*4
    assert (ConnKey4.saddr.offset, ConnKey4.daddr.offset, ConnKey4.dport.offset) == (8, 12, 18)
    assert ctypes.sizeof(ConnKey6) == 48  # 4+4 + 16+16 (v6 addrs) + 2*4
    assert (ConnKey6.saddr.offset, ConnKey6.daddr.offset, ConnKey6.dport.offset) == (8, 24, 42)
    # value is NOT packed: 3*char[16] then 7*u64 counters (8-byte aligned) then 6*u32
    assert ctypes.sizeof(ConnVal) == 128  # 48 + 56 + 24, no internal or trailing padding
    assert (ConnVal.send_bytes.offset, ConnVal.recv_bytes.offset) == (72, 80)
    assert (ConnVal.send_pkts.offset, ConnVal.recv_pkts.offset) == (88, 96)


def test_proc_reads_survive_non_utf8_comm():
    """a process can set a non-UTF-8 comm via prctl(PR_SET_NAME); the monitor's /proc text
    readers must degrade to replacement chars, not raise UnicodeDecodeError (which dropped
    the process's drain entry) or misparse stat/status (ppid 0, uid 0)"""
    from tracct.monitor import _read_proc_comm, _read_proc_ppid, _read_proc_status_uid

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
