# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Tests for the Textual viewer, driven headless against a query server on a temporary socket
and a live feed publisher. No root needed; skipped without textual (picosnitch[tui])."""

import asyncio
import threading
import time

import pytest

pytest.importorskip("textual")

from test_query_server import P0, VPN, H, _db  # noqa: E402
from textual.widgets import DataTable  # noqa: E402

from picosnitch import live_feed, query_server  # noqa: E402
from picosnitch.viewer.app import TimeRange, ViewerApp  # noqa: E402
from picosnitch.viewer.format import SPANS, display, format_bytes  # noqa: E402
from picosnitch.viewer.history import HistoryPane, bucket_step  # noqa: E402
from picosnitch.viewer.live import LivePane, remote  # noqa: E402
from picosnitch.viewer.timeline import Timeline  # noqa: E402


def test_format():
    assert format_bytes(999) == "999 B"
    assert format_bytes(1500) == "1.5 kB"
    assert format_bytes(2_500_000, "kB") == "2,500.0 kB"
    assert format_bytes(1234, "B") == "1,234"
    assert display("protocol", 6) == "tcp"
    assert display("domain", "") == "(none)"
    assert display("cmdline", "a\tb\nc\x1b[31m") == "a b c[31m"
    assert remote({"domain": "com.example", "raddr": "93.184.215.14", "rport": 443}) == "com.example:443"
    assert remote({"raddr": "10.0.0.1", "rport": -1}) == "10.0.0.1"


def test_time_range():
    now = 1_000_000_000
    hour = next(i for i, (name, _) in enumerate(SPANS) if name == "1 hour")
    time_range = TimeRange(hour)
    assert time_range.bounds(now, None) == (now - 3600, now + 1) and time_range.ends_now()
    time_range.back = 1
    start, end = time_range.bounds(now, None)
    # the last whole hour of local time before now
    assert end - start == 3600 and end <= now < end + 3600 and not time_range.ends_now()
    time_range.zooms.append((5, 10))
    assert time_range.bounds(now, None) == (5, 10)
    assert TimeRange(0).bounds(now, 1234) == (1234, now + 1)


def test_bucket_step():
    # round lengths, never below the write window
    assert bucket_step(60, 100) == 10
    assert bucket_step(900, 100) == 10
    assert bucket_step(3600, 100) == 60
    assert bucket_step(86400, 120) == 900
    assert bucket_step(10**12, 100) == 365 * 86400


async def _until(pilot, condition, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        await pilot.pause(0.05)


def _server(tmp_path):
    db = _db(tmp_path)
    listener, _ = query_server.listening_socket(tmp_path / "query.sock")
    threading.Thread(target=query_server.QueryServer(db, ephemeral=32768).serve, args=(listener, None), daemon=True).start()
    return listener


def _values(pane: HistoryPane) -> list:
    return [row[0] for row in pane.shown]


def test_history_drill_down(tmp_path):
    listener = _server(tmp_path)

    async def drive():
        app = ViewerApp(tmp_path / "events.sock", tmp_path / "query.sock", "processes")
        app.time_range = TimeRange(0)
        async with app.run_test(size=(140, 45)) as pilot:
            processes = app.query_one("#processes HistoryPane", HistoryPane)
            await _until(pilot, lambda: bool(processes.result))
            assert _values(processes) == ["/usr/bin/curl", "/usr/sbin/nginx"]
            assert processes.result["totals"] == [1111 + 5300, 11022 + 530]
            # the timeline follows the highlighted row
            timeline = processes.query_one(Timeline)
            await _until(pilot, lambda: "curl" in timeline.subject)
            assert sum(a for a, _ in timeline.values.values()) == 1111
            # Enter keeps the highlighted row, e excludes it, Backspace pops the filter
            processes.query_one(DataTable).focus()
            await pilot.press("down", "enter")
            await _until(pilot, lambda: processes.filters == [("exe", "/usr/sbin/nginx", False)] and _values(processes) == ["/usr/sbin/nginx"])
            await pilot.press("backspace")
            await _until(pilot, lambda: not processes.filters and len(_values(processes)) == 2)
            # the highlight stayed on nginx through the refresh
            await pilot.press("e")
            await _until(pilot, lambda: processes.filters == [("exe", "/usr/sbin/nginx", True)] and _values(processes) == ["/usr/bin/curl"])
            await pilot.press("backspace")
            await _until(pilot, lambda: len(_values(processes)) == 2)
            # another dimension
            processes.select_dimension("netns")
            processes.reload()
            await _until(pilot, lambda: set(_values(processes)) == {"host", str(VPN)})
            # find narrows the rows shown, Escape clears it
            await pilot.press("slash", "h", "o", "s", "t")
            await _until(pilot, lambda: _values(processes) == ["host"])
            await pilot.press("escape")
            await _until(pilot, lambda: len(_values(processes)) == 2)
            # the interfaces tab shares the range
            await pilot.press("3")
            interfaces = app.query_one("#interfaces HistoryPane", HistoryPane)
            await _until(pilot, lambda: bool(interfaces.result))
            assert _values(interfaces) == ["host/eth0", f"{VPN}/tun0"]
            # zooming into the timeline's busiest bucket narrows every tab to it
            timeline = interfaces.query_one(Timeline)
            await _until(pilot, lambda: bool(timeline.values))
            timeline.focus()
            await pilot.press("enter")
            await _until(pilot, lambda: bool(app.time_range.zooms))
            start, end = app.time_range.zooms[-1]
            assert start <= P0 + H < end
            await pilot.press("z")
            await _until(pilot, lambda: not app.time_range.zooms)
            await pilot.press("u")
            assert app.unit == "B"

    try:
        asyncio.run(drive())
    finally:
        listener.close()


def test_history_without_query_server(tmp_path):
    async def drive():
        app = ViewerApp(tmp_path / "events.sock", tmp_path / "missing.sock", "processes")
        async with app.run_test(size=(120, 40)) as pilot:
            pane = app.query_one("#processes HistoryPane", HistoryPane)
            await _until(pilot, lambda: bool(pane.error))
            assert "query server unavailable" in pane.error

    asyncio.run(drive())


def test_live_tab(tmp_path, monkeypatch):
    socket_path = tmp_path / "events.sock"
    monkeypatch.setattr(live_feed, "EVENTS_SOCKET_PATH", socket_path)
    publisher = live_feed.LiveFeedPublisher()
    publisher.start()

    async def drive():
        app = ViewerApp(socket_path, tmp_path / "missing.sock", "live")
        async with app.run_test(size=(140, 45)) as pilot:
            pane = app.query_one(LivePane)
            await _until(pilot, lambda: pane.state == "connected" and publisher.has_subscribers())
            event = {"name": "curl", "exe": "/usr/bin/curl", "pname": "bash", "unit": "session-1.scope", "send": 100, "recv": 2000, "lport": 50000, "rport": 443, "domain": "com.example"}
            publisher.publish_many([event, {**event, "send": 1}, {**event, "name": "wget", "exe": "/usr/bin/wget", "recv": 5}])
            await _until(pilot, lambda: pane.events == 3)
            assert pane.totals[("curl", "/usr/bin/curl")][:3] == [101, 4000, 2]
            await _until(pilot, lambda: pane.query_one("#totals", DataTable).row_count == 2 and pane.query_one("#recent", DataTable).row_count == 3)
            # paused, recent stops; reset clears
            pane.query_one("#totals", DataTable).focus()
            await pilot.press("p")
            publisher.publish(event)
            await _until(pilot, lambda: pane.events == 4)
            assert len(pane.recent) == 3
            await pilot.press("r")
            await _until(pilot, lambda: pane.events == 0 and not pane.totals)

    try:
        asyncio.run(drive())
    finally:
        publisher.stop()
