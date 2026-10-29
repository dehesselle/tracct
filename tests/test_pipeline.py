# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Tests for the hand-off between the reader, writer and live feed threads.

No root or BPF needed.
"""

import copy
import sqlite3
import threading
import time
import typing

from tracct import cli, writer
from tracct.config import Config
from tracct.reverse_dns import ReverseDns
from tracct.types import BpfEvent
from tracct.utils import DropOldestQueue


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
        "unit": "session-1.scope",
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
    # Five events over a bound of three: the oldest batches made room and were counted.
    assert hand_off.dropped == 3
    assert hand_off.get_all(0) == [[4, 5]]
    # A batch larger than the bound is still kept whole.
    hand_off.put([6, 7, 8, 9])
    assert hand_off.get_all(0) == [[6, 7, 8, 9]]
    started = time.monotonic()
    assert hand_off.get_all(0.1) == []
    assert time.monotonic() - started < 1


def test_window_leaves_events_alone():
    """The live feed may still be sending the events the writer aggregates."""
    events = [_event(), _event(send=1, recv=1, pkts=1)]
    before = copy.deepcopy(events)
    window = writer.WriteWindow(Config())
    window.add(events)
    assert events == before
    # Both events are the same connection: one row with their sums.
    assert len(window) == 1
    rows, flows = window.take_rows()
    assert len(rows) == 1 and not flows and len(window) == 0
    _contime, send, recv, n_events, exe_key, _pexe_key, unit, *_ = rows[0]
    assert (send, recv, n_events) == (101, 2001, 5)
    assert exe_key == ("/usr/bin/curl", "curl", "curl https://example.com")
    assert unit == "session-1.scope"


class _FakeDns:
    def __init__(self) -> None:
        self.names: dict[str, str] = {}
        self.asked: list[str] = []

    def lookup(self, ip: str) -> str:
        self.asked.append(ip)
        return self.names.get(ip, "")


def test_window_fills_domains_at_write():
    """Reverse DNS is asked once per new connection and its answer used when the window
    is written; a connection with and without the program's own lookup becomes one row,
    and ignore_domains matches the name from reverse DNS.
    """
    config = Config()
    config.record.ignore_domains = ["org.ignored."]
    dns = _FakeDns()
    window = writer.WriteWindow(config, typing.cast(ReverseDns, dns))
    window.add([_event(domain=""), _event(domain="", send=1, recv=1, pkts=1)])
    window.add([_event(), _event(domain="", raddr="192.0.2.1", rport=80)])
    assert dns.asked == ["93.184.215.14", "192.0.2.1"]
    dns.names = {"93.184.215.14": "com.example", "192.0.2.1": "org.ignored.www"}
    rows, _ = window.take_rows()
    assert [
        (send, recv, n_events, domain)
        for _, send, recv, n_events, *_, domain, _, _ in rows
    ] == [(201, 4001, 9, "com.example")]


class _FakeNetInfo:
    def __init__(self) -> None:
        self.noted: list[tuple[int, int]] = []

    def interface_of(self, netns: int, laddr: str) -> tuple[str, str]:
        return ("eth0", "") if laddr == "10.0.0.2" else ("", "")

    def tun_of(self, pid: int) -> str:
        return "tailscale0" if pid == 77 else ""

    def note(self, netns: int, pid: int) -> None:
        self.noted.append((netns, pid))


def test_window_interfaces_and_flows():
    """A row carries the interface of its local address, a TUN row the device of its
    process; forwarded flows are summed per flow and named by reverse DNS of the
    answering side.
    """
    from tracct.conntrack import Flow
    from tracct.netinfo import NetInfo

    netinfo = _FakeNetInfo()
    dns = _FakeDns()
    dns.names = {"198.51.100.7": "org.example.cdn"}
    window = writer.WriteWindow(
        Config(), typing.cast(ReverseDns, dns), typing.cast(NetInfo, netinfo)
    )
    window.add(
        [
            _event(),
            _event(laddr="10.9.9.9", lport=50001),
            _event(
                pid=77,
                family=17,
                protocol=0,
                laddr="",
                raddr="",
                lport=0,
                rport=0,
                domain="",
            ),
        ]
    )
    flow = Flow(
        4026531840, 6, "100.64.0.2", 40000, "198.51.100.7", 443, 1000, 50000, 10, 40
    )
    window.add_flows([flow, flow])
    rows, flows = window.take_rows()
    assert sorted(row[-1] for row in rows) == [
        (0, "", ""),
        (4026531840, "eth0", ""),
        (4026531840, "tailscale0", "tun"),
    ]
    assert netinfo.noted == [(4026531840, 4242)] * 2 + [(4026531840, 77)]
    assert [flow_row[1:] for flow_row in flows] == [
        (
            4026531840,
            6,
            "100.64.0.2",
            40000,
            "198.51.100.7",
            443,
            "org.example.cdn",
            2000,
            100000,
            20,
            80,
        )
    ]


def _init_database(tmp_path, monkeypatch):
    db = tmp_path / "tracct.db"
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
    # Stopped before it starts: the window has not closed, everything goes in the final
    # write.
    stop.set()
    thread = threading.Thread(target=writer.run_writer, args=(Config(), batches, stop))
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    con = sqlite3.connect(db)
    rows = con.execute(
        "SELECT c.rport, c.send, c.recv, e.exe, d.domain FROM connections c JOIN executables e ON c.exe_id = e.id JOIN domains d ON c.domain_id = d.id ORDER BY c.rport"
    ).fetchall()
    con.close()
    assert rows == [
        (80, 100, 2000, "/usr/bin/curl", "org.example"),
        (443, 100, 2000, "/usr/bin/curl", "com.example"),
    ]


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
        # One connection is below the bound: it waits for its window.
        batches.put([_event(lport=3)])
        time.sleep(1.5)
        assert count() == 2
    finally:
        stop.set()
        thread.join(timeout=10)
    assert count() == 3


def test_writer_quarantines_unusable_db(tmp_path, monkeypatch):
    """A database that turns out unusable while running is moved aside and the writer
    thread ends, so the daemon exits and its next start creates a new one.
    """
    db = _init_database(tmp_path, monkeypatch)
    db.write_bytes(b"this is not a sqlite database" * 64)
    failures: list[type] = []
    monkeypatch.setattr(
        threading, "excepthook", lambda args: failures.append(args.exc_type)
    )
    thread = threading.Thread(
        target=writer.run_writer,
        args=(Config(), DropOldestQueue(1000), threading.Event()),
    )
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert failures == [sqlite3.DatabaseError]
    assert (tmp_path / "tracct.db.bad").exists() and not db.exists()
