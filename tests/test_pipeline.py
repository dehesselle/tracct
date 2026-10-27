"""Tests for the hand-off between the reader, writer and live feed threads. No root/BPF."""

import copy
import sqlite3
import threading
import time
import typing

import picosnitch.cli as cli
import picosnitch.writer as writer
from picosnitch.config import Config
from picosnitch.reverse_dns import ReverseDns
from picosnitch.types import BpfEvent
from picosnitch.utils import DropOldestQueue


def _event(**fields) -> BpfEvent:
    event = {
        "pid": 4242,
        "name": "curl",
        "dev": 1,
        "ino": 2,
        "exe": "/usr/bin/curl",
        "cmdline": "curl\0https://example.com\0",
        "ppid": 4241,
        "pname": "bash",
        "pdev": 1,
        "pino": 3,
        "pexe": "/usr/bin/bash",
        "pcmdline": "bash\0",
        "uid": 1000,
        "send": 100,
        "recv": 2000,
        "pkts": 4,
        "family": 2,
        "protocol": 6,
        "lport": 50000,
        "rport": 443,
        "laddr": "10.0.0.2",
        "raddr": "93.184.215.14",
        "domain": "com.example",
        "netns": 4026531840,
    }
    event.update(fields)
    return typing.cast(BpfEvent, event)


def test_drop_oldest_queue_bounds_events():
    hand_off: DropOldestQueue[int] = DropOldestQueue(3)
    for batch in ([1], [2, 3], [4, 5]):
        hand_off.put(batch)
    # five events over a bound of three: the oldest batches made room and were counted
    assert hand_off.dropped == 3
    assert hand_off.get_all(0) == [[4, 5]]
    # a batch larger than the bound is still kept whole
    hand_off.put([6, 7, 8, 9])
    assert hand_off.get_all(0) == [[6, 7, 8, 9]]
    started = time.monotonic()
    assert hand_off.get_all(0.1) == []
    assert time.monotonic() - started < 1


def test_window_leaves_events_alone():
    """the live feed may still be sending the events the writer aggregates"""
    events = [_event(), _event(send=1, recv=1, pkts=1)]
    before = copy.deepcopy(events)
    window = writer.WriteWindow(Config())
    window.add(events)
    assert events == before
    # both events are the same connection: one row with their sums
    assert len(window) == 1
    rows = window.take_rows()
    assert len(rows) == 1 and len(window) == 0
    contime, send, recv, n_events, exe_key, pexe_key, *_ = rows[0]
    assert (send, recv, n_events) == (101, 2001, 5)
    assert exe_key == ("/usr/bin/curl", "curl", "curl https://example.com")


class _FakeDns:
    def __init__(self) -> None:
        self.names: dict[str, str] = {}
        self.asked: list[str] = []

    def lookup(self, ip: str) -> str:
        self.asked.append(ip)
        return self.names.get(ip, "")


def test_window_fills_domains_at_write():
    """reverse DNS is asked once per new connection and its answer used when the window is
    written; a connection with and without the program's own lookup becomes one row, and
    ignore_domains matches the name from reverse DNS"""
    config = Config()
    config.log.ignore_domains = ["org.ignored."]
    dns = _FakeDns()
    window = writer.WriteWindow(config, typing.cast(ReverseDns, dns))
    window.add([_event(domain=""), _event(domain="", send=1, recv=1, pkts=1)])
    window.add([_event(), _event(domain="", raddr="192.0.2.1", rport=80)])
    assert dns.asked == ["93.184.215.14", "192.0.2.1"]
    dns.names = {"93.184.215.14": "com.example", "192.0.2.1": "org.ignored.www"}
    rows = window.take_rows()
    assert [(send, recv, n_events, domain) for _, send, recv, n_events, *_, domain, _ in rows] == [(201, 4001, 9, "com.example")]


def _init_database(tmp_path, monkeypatch):
    db = tmp_path / "picosnitch.db"
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DB_PATH", db)
    monkeypatch.setattr(writer, "DB_PATH", db)
    cli.init_database()
    return db


def test_writer_writes_what_is_left_on_stop(tmp_path, monkeypatch):
    db = _init_database(tmp_path, monkeypatch)
    batches: DropOldestQueue[BpfEvent] = DropOldestQueue(1000)
    batches.put([_event()])
    batches.put([_event(rport=80, domain="org.example")])
    stop = threading.Event()
    # stopped before it starts: the window has not closed, everything goes in the final write
    stop.set()
    thread = threading.Thread(target=writer.run_writer, args=(Config(), batches, stop))
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    con = sqlite3.connect(db)
    rows = con.execute("SELECT c.rport, c.send, c.recv, e.exe, d.domain FROM connections c JOIN executables e ON c.exe_id = e.id JOIN domains d ON c.domain_id = d.id ORDER BY c.rport").fetchall()
    con.close()
    assert rows == [(80, 100, 2000, "/usr/bin/curl", "org.example"), (443, 100, 2000, "/usr/bin/curl", "com.example")]


def test_writer_writes_full_window_early(tmp_path, monkeypatch):
    db = _init_database(tmp_path, monkeypatch)
    monkeypatch.setattr(writer, "WINDOW_CONNECTIONS_MAX", 2)
    config = Config()
    config.database.write_limit_seconds = 3600
    batches: DropOldestQueue[BpfEvent] = DropOldestQueue(1000)
    stop = threading.Event()
    thread = threading.Thread(target=writer.run_writer, args=(config, batches, stop))
    thread.start()

    def count() -> int:
        con = sqlite3.connect(db)
        try:
            return con.execute("SELECT count(*) FROM connections").fetchone()[0]
        finally:
            con.close()

    try:
        batches.put([_event(lport=1), _event(lport=2)])
        deadline = time.monotonic() + 10
        while count() < 2 and time.monotonic() < deadline:
            time.sleep(0.1)
        assert count() == 2
        # one connection is below the bound: it waits for its window
        batches.put([_event(lport=3)])
        time.sleep(1.5)
        assert count() == 2
    finally:
        stop.set()
        thread.join(timeout=10)
    assert count() == 3


def test_writer_quarantines_unusable_db(tmp_path, monkeypatch):
    """a database that turns out unusable while running is moved aside and the writer thread
    ends, so the daemon exits and its next start creates a new one"""
    db = _init_database(tmp_path, monkeypatch)
    db.write_bytes(b"this is not a sqlite database" * 64)
    failures: list[type] = []
    monkeypatch.setattr(threading, "excepthook", lambda args: failures.append(args.exc_type))
    thread = threading.Thread(target=writer.run_writer, args=(Config(), DropOldestQueue(1000), threading.Event()))
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert failures == [sqlite3.DatabaseError]
    assert (tmp_path / "picosnitch.db.bad").exists() and not db.exists()
