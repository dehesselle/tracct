"""Tests for the hand-off between the reader, writer and live feed threads. No root/BPF."""

import copy
import queue
import sqlite3
import threading
import typing

import picosnitch.cli as cli
import picosnitch.writer as writer
from picosnitch.config import Config
from picosnitch.main_loop import DropOldestQueue
from picosnitch.types import BpfEvent


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


def test_drop_oldest_queue_never_blocks():
    hand_off = DropOldestQueue(2)
    batches = [[_event()], [_event(), _event()], [_event()] * 3]
    for batch in batches:
        hand_off.put(batch)
    # the oldest batch made room for the newest, and its events were counted
    assert hand_off.dropped == 1
    assert [hand_off.queue.get_nowait(), hand_off.queue.get_nowait()] == batches[1:]


def test_build_log_entries_leaves_events_alone():
    """the live feed may still be sending the events the writer aggregates"""
    events = [_event(), _event(send=1, recv=1, pkts=1)]
    before = copy.deepcopy(events)
    rows = writer.build_log_entries(Config(), events, [])
    assert events == before
    # both events are the same connection: one row with their sums
    assert len(rows) == 1
    contime, send, recv, n_events, exe_key, pexe_key, *_ = rows[0]
    assert (send, recv, n_events) == (101, 2001, 5)
    assert exe_key == ("/usr/bin/curl", "curl", "curl https://example.com")


def test_writer_writes_what_is_left_on_stop(tmp_path, monkeypatch):
    db = tmp_path / "picosnitch.db"
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "DB_PATH", db)
    monkeypatch.setattr(writer, "DB_PATH", db)
    cli.init_database()
    batches: queue.Queue = queue.Queue()
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
