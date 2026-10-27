# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Tests for the Textual viewer, driven headless against a query server on a temporary socket
and a live feed publisher. No root needed; skipped without textual (tracct[tui])."""

import asyncio
import re
import threading
import time

import pytest

pytest.importorskip("textual")

from tcoda.dialogs import SettingsDialog  # noqa: E402
from tcoda.settings import config, configure  # noqa: E402
from test_query_server import VPN, _db  # noqa: E402
from textual.content import Content  # noqa: E402
from textual.widgets import DataTable, TabbedContent, TabPane, Tabs  # noqa: E402

from tracct import live_feed, query_server  # noqa: E402
from tracct.viewer import settings  # noqa: E402
from tracct.viewer.app import TimeRange, ViewerApp  # noqa: E402
from tracct.viewer.banner import Banner  # noqa: E402
from tracct.viewer.format import SPANS, display, format_bytes  # noqa: E402
from tracct.viewer.history import HistoryPane, bucket_step  # noqa: E402
from tracct.viewer.live import LivePane, remote  # noqa: E402
from tracct.viewer.plot import ALL_ROWS, BUSY, RateAxis, TimeAxis, TrafficPlot  # noqa: E402


@pytest.fixture(autouse=True)
def settings_file(tmp_path):
    """the viewer's settings in a file of the test's own, never the user's"""
    configure(path=tmp_path / "settings.json")


def test_settings():
    assert settings._limit("10") == 10
    for text in ("5", "100001", "x"):
        with pytest.raises(ValueError):
            settings._limit(text)
    config.set(settings.LIVE_EVENTS, 20)
    configure(path=config.path)
    assert config.get(settings.LIVE_EVENTS) == 20 and config.get(settings.LIVE_EXECUTABLES) == 100


def test_settings_chord(tmp_path):
    async def drive():
        app = ViewerApp(tmp_path / "events.sock", tmp_path / "missing.sock", "live")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.press("s")
            assert not isinstance(app.screen, SettingsDialog)
            await pilot.press("comma", "s")
            await _until(pilot, lambda: isinstance(app.screen, SettingsDialog))

    asyncio.run(drive())


def test_tab_keys(tmp_path):
    async def drive():
        app = ViewerApp(tmp_path / "events.sock", tmp_path / "missing.sock", "live")
        async with app.run_test(size=(120, 40)) as pilot:
            tabs = app.query_one(TabbedContent)
            assert [pane.id for pane in tabs.query(TabPane)] == ["forwarded", "interfaces", "live", "processes"]
            assert not tabs.query_one(Tabs).can_focus
            # Textual's own ctrl+q quits; no single key does
            assert "ctrl+q" in app.screen.active_bindings and not {"q", "question_mark"} & set(app.screen.active_bindings)
            # no daemon: the live tab's banner shows why, as an error
            banner = app.query_one(LivePane).query_one(".banner")
            await _until(pilot, lambda: banner.display and banner.has_class("-error"))
            assert "live feed unavailable" in str(banner.query_one(".banner-text").render())
            assert not banner.query_one(".banner-hint").display
            # p means Processes, even with the focus in the live tab
            await pilot.press("p")
            assert tabs.active == "processes"
            # the time range and units belong to the history tabs only
            await _until(pilot, lambda: {"t", "h", "z", "u"} <= set(app.screen.active_bindings))
            for key, tab in (("i", "interfaces"), ("f", "forwarded"), ("l", "live")):
                await pilot.press(key)
                assert tabs.active == tab
            await _until(pilot, lambda: not {"t", "h", "z", "u"} & set(app.screen.active_bindings))
            await pilot.press("u")
            assert app.unit == "auto"

    asyncio.run(drive())


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


def test_plot_axes():
    axis = TimeAxis()
    axis.columns = 100
    # a day in round hours, its midnight named by its date
    ticks = axis.get_ticks(0, 86400)
    assert ticks == [k * 6 * 3600.0 for k in range(5)]
    assert axis.get_labels_for_ticks(ticks) == ["Jan 01", "06:00", "12:00", "18:00", "Jan 02"]
    rates = RateAxis()
    rates.rows = 10
    ticks = rates.get_ticks(0, 7000)
    assert ticks == [0.0, 2000.0, 4000.0, 6000.0]
    assert rates.get_labels_for_ticks(ticks) == ["0", "2.0 kB/s", "4.0 kB/s", "6.0 kB/s"]


async def _until(pilot, condition, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        await pilot.pause(0.05)


def _server(tmp_path):
    db = _db(tmp_path)
    listener, _ = query_server.listening_socket(tmp_path / "query.sock")
    threading.Thread(target=query_server.QueryServer(db, ephemeral=32768, write_window=10, rollup_period=3600).serve, args=(listener, None), daemon=True).start()
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
            # the tab asked for keeps the focus, rather than the first tab taking it
            await pilot.pause(0.3)
            assert app.query_one(TabbedContent).active == "processes"
            assert _values(processes) == ["/usr/bin/curl", "/usr/sbin/nginx"]
            assert processes.result["totals"] == [1111 + 5300, 11022 + 530]
            # the plot follows the highlighted row
            plot = processes.query_one(TrafficPlot)
            await _until(pilot, lambda: "curl" in plot.subject)
            assert sum(a for a, _ in plot.values.values()) == 1111
            # Enter keeps the highlighted row, e excludes it, Backspace pops the filter
            processes.query_one(DataTable).focus()
            # no filter, no find, no problem: no banner
            banner = processes.query_one(Banner)
            assert not banner.display
            await pilot.press("down", "enter")
            await _until(pilot, lambda: processes.filters == [("exe", "/usr/sbin/nginx", False)] and _values(processes) == ["/usr/sbin/nginx"])
            # the filters are in the banner, with the key that pops them
            assert banner.display and _banner(processes) == ("filter: executable=/usr/sbin/nginx", "press ⌫ to pop a filter")
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
            assert not banner.display
            # find narrows the rows shown; kept with Enter, the banner says it, and c clears it
            await pilot.press("slash", "h", "o", "s", "t")
            await _until(pilot, lambda: _values(processes) == ["host"])
            # the input opens on the tab's own top line
            assert processes.children[0].has_class("find", "shown") and not banner.display
            await pilot.press("enter")
            await _until(pilot, lambda: _banner(processes) == ("find: host", "press c to clear"))
            await pilot.press("c")
            await _until(pilot, lambda: len(_values(processes)) == 2 and not banner.display)
            # Escape clears an open one
            await pilot.press("slash", "h")
            await _until(pilot, lambda: _values(processes) == ["host"])
            await pilot.press("escape")
            await _until(pilot, lambda: len(_values(processes)) == 2)
            assert not processes.children[0].has_class("shown") and not banner.display
            # the interfaces tab shares the range
            await pilot.press("i")
            interfaces = app.query_one("#interfaces HistoryPane", HistoryPane)
            await _until(pilot, lambda: bool(interfaces.result))
            assert _values(interfaces) == ["host/eth0", f"{VPN}/tun0"]
            # zooming the plot narrows every tab to what it shows; r and z return to the span
            plot = interfaces.query_one(TrafficPlot)
            await _until(pilot, lambda: bool(plot.values))
            start, end = interfaces.bounds()
            plot.focus()
            for key in ("r", "z"):
                await pilot.press("plus")
                await _until(pilot, lambda: bool(app.time_range.zooms))
                zoomed_start, zoomed_end = app.time_range.zooms[-1]
                assert start <= zoomed_start < zoomed_end <= end and zoomed_end - zoomed_start < end - start
                await _until(pilot, lambda: plot.start == zoomed_start)
                await pilot.press(key)
                await _until(pilot, lambda: not app.time_range.zooms and plot.start == start)
            await pilot.press("u")
            assert app.unit == "B"

    try:
        asyncio.run(drive())
    finally:
        listener.close()


def test_plot_title_and_busy(tmp_path):
    listener = _server(tmp_path)
    slow = threading.Event()

    async def drive():
        app = ViewerApp(tmp_path / "events.sock", tmp_path / "query.sock", "interfaces")
        app.time_range = TimeRange(0)
        ask = app.ask

        def delayed(op, **params):
            if slow.is_set():
                time.sleep(1.0)
            return ask(op, **params)

        app.ask = delayed
        async with app.run_test(size=(140, 45)) as pilot:
            pane = app.query_one("#interfaces HistoryPane", HistoryPane)
            plot = pane.query_one(TrafficPlot)
            shown = []
            set_busy = plot.set_busy
            plot.set_busy = lambda busy: (shown.append(busy), set_busy(busy))
            await _until(pilot, lambda: bool(plot.values) and not pane._fetching)
            # answers within milliseconds never show the glyph
            assert True not in shown and BUSY not in _title(plot)
            # the range, then the key; the highlighted row is in the table, and the peaks' stretch
            # is the usual one
            assert _title(plot) == "all history · ━━ sent ━━ received"
            # a slow answer shows it until the rows and the plot are both in
            slow.set()
            app.action_refresh()
            await _until(pilot, lambda: plot.busy and _title(plot).endswith(f" · {BUSY}"))
            slow.clear()
            await _until(pilot, lambda: not plot.busy and BUSY not in _title(plot))
            # the plot of all rows says so, as no row in the table stands for it
            await pilot.press("a")
            await _until(pilot, lambda: _title(plot).startswith(f"all history · {ALL_ROWS} · "))
            # a zoom is named by its ends
            plot.focus()
            await pilot.press("plus")
            await _until(pilot, lambda: bool(app.time_range.zooms) and " – " in _title(plot))

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
            # in the banner, as on the live tab, and with nothing to undo no hint
            banner = pane.query_one(Banner)
            assert banner.display and banner.has_class("-error") and _banner(pane) == (pane.error, "")

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
            # nothing to say: no banner; the events title carries the counts
            banner = pane.query_one(".banner")
            assert not banner.display
            await _until(pilot, lambda: str(pane.query_one("#recent", DataTable).border_title) == "last 500 events · 3 total")
            # the seconds since the tab started go with the totals they were summed over
            assert re.fullmatch(r"summary · \d+ s", str(pane.query_one("#totals", DataTable).border_title))
            # typing a find (c types, it does not clear): the input says it; kept with Enter, the
            # banner on the same line does, with a hint that c clears it
            await pilot.press("slash", "c", "u", "r", "l")
            await _until(pilot, lambda: pane.find == "curl")
            assert not banner.display
            await pilot.press("enter")
            await _until(pilot, lambda: banner.display and str(banner.query_one(".banner-text").render()) == "find: curl")
            assert banner.query_one(".banner-hint").display
            await pilot.press("c")
            await _until(pilot, lambda: not banner.display)
            assert pane.find == "" and pane.query_one(".find").value == ""
            await _until(pilot, lambda: pane.query_one("#totals", DataTable).row_count == 2 and pane.query_one("#recent", DataTable).row_count == 3)
            # by executable, newest event first
            totals, recent = pane.query_one("#totals", DataTable), pane.query_one("#recent", DataTable)
            assert _keys(totals) == ["curl\0/usr/bin/curl", "wget\0/usr/bin/wget"]
            assert _keys(recent) == ["3", "2", "1"]
            # by the number behind the text: 5 B before 4.0 kB, where the text would rank the other way
            totals.sort_by("received")
            assert _keys(totals) == ["wget\0/usr/bin/wget", "curl\0/usr/bin/curl"]
            # a refill keeps the sort, and the cursor stays on its executable as it moves up
            totals.move_cursor(row=1)
            pane.totals[("curl", "/usr/bin/curl")][1] = 0
            pane.render_tables()
            assert _keys(totals) == ["curl\0/usr/bin/curl", "wget\0/usr/bin/wget"] and totals.cursor_row == 0
            recent.sort_by("sent")
            assert _keys(recent)[0] == "2"
            # paused, recent stops; reset clears
            pane.query_one("#totals", DataTable).focus()
            await pilot.press("space")
            publisher.publish(event)
            await _until(pilot, lambda: pane.events == 4)
            assert len(pane.recent) == 3
            await _until(pilot, lambda: recent.border_subtitle == "table is frozen")
            await pilot.press("r")
            await _until(pilot, lambda: pane.events == 0 and not pane.totals)

    try:
        asyncio.run(drive())
    finally:
        publisher.stop()


def _keys(table: DataTable) -> list[str]:
    return [row.key.value for row in table.ordered_rows]


def _banner(pane) -> tuple[str, str]:
    """the banner's text and its hint, or "" for a hidden hint"""
    banner = pane.query_one(Banner)
    hint = banner.query_one(".banner-hint")
    return str(banner.query_one(".banner-text").render()), str(hint.render()) if hint.display else ""


def _title(plot: TrafficPlot) -> str:
    """the plot's title as shown: Textual keeps it as markup"""
    return Content.from_markup(plot.border_title).plain


def test_live_limits(tmp_path, monkeypatch):
    socket_path = tmp_path / "events.sock"
    monkeypatch.setattr(live_feed, "EVENTS_SOCKET_PATH", socket_path)
    publisher = live_feed.LiveFeedPublisher()
    publisher.start()
    config.set(settings.LIVE_EXECUTABLES, 10)
    config.set(settings.LIVE_EVENTS, 12)

    async def drive():
        app = ViewerApp(socket_path, tmp_path / "missing.sock", "live")
        async with app.run_test(size=(140, 45)) as pilot:
            pane = app.query_one(LivePane)
            await _until(pilot, lambda: pane.state == "connected" and publisher.has_subscribers())
            # two executables go idle, ten more arrive after them: the idle two make room
            publisher.publish_many([{"name": f"old{i}", "exe": f"/bin/old{i}", "send": 1} for i in range(2)])
            await _until(pilot, lambda: pane.events == 2)
            publisher.publish_many([{"name": f"new{i}", "exe": f"/bin/new{i}", "send": 1} for i in range(10)])
            await _until(pilot, lambda: pane.events == 12)
            assert pane.dropped == 2 and len(pane.totals) == 10
            await _until(pilot, lambda: str(pane.query_one("#totals", DataTable).border_title).startswith("summary (2 dropped) · "))
            assert str(pane.query_one("#recent", DataTable).border_title) == "last 12 events · 12 total"
            assert not any(name.startswith("old") for name, _ in pane.totals)
            assert pane.query_one("#totals", DataTable).row_count == 10
            assert len(pane.recent) == 12
            # a lowered limit applies on the next redraw and keeps the newest events
            config.set(settings.LIVE_EVENTS, 10)
            await _until(pilot, lambda: pane.recent.maxlen == 10)
            await _until(pilot, lambda: str(pane.query_one("#recent", DataTable).border_title).startswith("last 10 events · "))
            assert [event["name"] for event in pane.recent] == [f"new{i}" for i in range(9, -1, -1)]
            await _until(pilot, lambda: pane.query_one("#recent", DataTable).row_count == 10)
            pane.query_one("#totals", DataTable).focus()
            await pilot.press("r")
            await _until(pilot, lambda: pane.dropped == 0)
            await _until(pilot, lambda: str(pane.query_one("#totals", DataTable).border_title).startswith("summary · "))

    try:
        asyncio.run(drive())
    finally:
        publisher.stop()
