# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Tests for the Textual viewer, driven headless against a query server on a temporary
socket and a live feed publisher. No root needed; skipped without Textual
(tracct[viewer]).
"""

import grp
import os
import re
import threading
import time

import pytest

pytest.importorskip("textual")

from tcoda.dialogs import AboutDialog, SettingsDialog
from tcoda.settings import config, configure
from test_query_server import P0, VPN, H, _db
from textual.app import App, ComposeResult
from textual.content import Content
from textual.widgets import DataTable, OptionList, TabbedContent, TabPane
from textual.widgets.tabbed_content import ContentTabs

from tracct import live_feed, query_server
from tracct.viewer import settings
from tracct.viewer.app import TracctApp
from tracct.viewer.banner import Banner
from tracct.viewer.client import access_hint
from tracct.viewer.format import (
    format_bytes,
    format_time,
    format_value,
    shorten_end,
    shorten_host,
    shorten_path,
)
from tracct.viewer.history import HistoryPane
from tracct.viewer.live import FeedState, LivePane, remote
from tracct.viewer.model import Filter, Timeline
from tracct.viewer.pickers import ByteUnitPicker, SpanPicker
from tracct.viewer.plot import (
    BUSY,
    MAX_SPAN,
    MIN_SPAN,
    PEAK_SECONDS,
    RateAxis,
    TrafficPlot,
)
from tracct.viewer.timerange import (
    SPANS,
    TimeRange,
    bucket_grid,
    bucket_step,
)


@pytest.fixture(autouse=True)
def settings_file(tmp_path):
    """The viewer's settings in a file of the test's own, never the user's."""
    configure(path=tmp_path / "settings.json")


def test_settings():
    assert settings._limit("10") == 10
    for text in ("5", "100001", "x"):
        with pytest.raises(ValueError):
            settings._limit(text)
    assert settings._width("10") == 10
    for text in ("9", "201", "x"):
        with pytest.raises(ValueError):
            settings._width(text)
    config.set(settings.LIVE_EVENTS, 20)
    configure(path=config.path)
    assert (
        config.get(settings.LIVE_EVENTS) == 20
        and config.get(settings.LIVE_SUMMARY_ROWS) == 100
    )


async def test_settings_chord(tmp_path):
    app = TracctApp(tmp_path / "events.sock", tmp_path / "missing.sock", "live")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        assert not isinstance(app.screen, SettingsDialog)
        await pilot.press("comma", "s")
        await _until(pilot, lambda: isinstance(app.screen, SettingsDialog))


async def test_about_chord(tmp_path):
    app = TracctApp(tmp_path / "events.sock", tmp_path / "missing.sock", "live")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("comma", "a")
        await _until(pilot, lambda: isinstance(app.screen, AboutDialog))
        await pilot.press("escape")
        await _until(pilot, lambda: not isinstance(app.screen, AboutDialog))


async def test_tab_keys(tmp_path):
    app = TracctApp(tmp_path / "events.sock", tmp_path / "missing.sock", "live")
    async with app.run_test(size=(120, 40)) as pilot:
        tabs = app.query_one(TabbedContent)
        assert [pane.id for pane in tabs.query(TabPane)] == [
            "live",
            "forwarded",
            "interfaces",
            "processes",
        ]
        assert not tabs.query_one(ContentTabs).can_focus
        # Textual's own ctrl+q quits; no single key does.
        assert "ctrl+q" in app.screen.active_bindings and not {
            "q",
            "question_mark",
        } & set(app.screen.active_bindings)
        # No daemon: the live tab's banner shows why, as an error.
        banner = app.query_one(LivePane).query_one(".banner")
        await _until(pilot, lambda: banner.display and banner.has_class("-error"))
        assert "live feed unavailable" in str(banner.query_one(".banner-text").render())
        assert not banner.query_one(".banner-hint").display
        assert app.focused is app.query_one("#live #summary", DataTable)
        # P means Processes, even with the focus in the live tab, and the focus goes
        # along to its table, not the dimensions.
        await pilot.press("p")
        assert tabs.active == "processes"
        assert app.focused is app.query_one("#processes DataTable", DataTable)
        # The time range and units belong to the history tabs only.
        await _until(
            pilot,
            lambda: (
                {"s", "shift+left", "shift+right", "comma b"}
                <= set(app.screen.active_bindings)
            ),
        )
        for key, tab in (("i", "interfaces"), ("f", "forwarded"), ("l", "live")):
            await pilot.press(key)
            assert tabs.active == tab
            assert app.focused is app.query(f"#{tab} DataTable").first()
        await _until(
            pilot,
            lambda: (
                not {"s", "shift+left", "shift+right", "comma b"}
                & set(app.screen.active_bindings)
            ),
        )
        await pilot.press("comma", "b")
        assert app.byte_unit == "auto"


async def test_span_picker(tmp_path):
    app = TracctApp(tmp_path / "events.sock", tmp_path / "missing.sock", "processes")
    app.time_range.zoom_to(5, 10)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        await _until(pilot, lambda: isinstance(app.screen, SpanPicker))
        picker = app.screen
        options = picker.query_one("#picker-results")
        # Shortest first, the whole history last, opened on the current span, which s
        # returns to while zoomed.
        labels = [label for _, label, _ in picker._entries]
        assert labels[:2] == ["1 minute", "5 minutes"] and labels[-1] == "all history"
        assert picker._entries[options.highlighted][0] == app.time_range.span
        assert (
            str(options.get_option_at_index(options.highlighted).prompt)
            .rstrip()
            .endswith("(current)  (press s to select)")
        )
        # Escape changes nothing.
        await pilot.press("escape")
        await _until(pilot, lambda: not isinstance(app.screen, SpanPicker))
        assert app.time_range.zoom == (5, 10)
        # Enter takes the highlighted span, which ends the zoom.
        span = app.time_range.span
        await pilot.press("s", "down", "enter")
        await _until(
            pilot, lambda: app.time_range.span != span and app.time_range.zoom is None
        )
        # Without a zoom, s in the picker has nothing to return to: no hint, and it
        # stays open.
        await pilot.press("s")
        await _until(pilot, lambda: isinstance(app.screen, SpanPicker))
        options = app.screen.query_one("#picker-results")
        assert "press s" not in str(
            options.get_option_at_index(options.highlighted).prompt
        )
        await pilot.press("s")
        await pilot.pause(0.2)
        assert isinstance(app.screen, SpanPicker)


async def test_unit_picker(tmp_path):
    app = TracctApp(tmp_path / "events.sock", tmp_path / "missing.sock", "processes")
    async with app.run_test(size=(120, 40)) as pilot:
        # Before any change there is no unit to go back to: no hint, and b leaves it
        # open.
        await pilot.press("comma", "b")
        await _until(pilot, lambda: isinstance(app.screen, ByteUnitPicker))
        options = app.screen.query_one("#picker-results")
        assert app.screen._entries[options.highlighted][0] == "auto"
        assert not any(
            "press b" in str(options.get_option_at_index(i).prompt)
            for i in range(options.option_count)
        )
        await pilot.press("b")
        await pilot.pause(0.2)
        assert isinstance(app.screen, ByteUnitPicker)
        # Enter takes the highlighted unit.
        await pilot.press("down", "down", "down", "enter")
        await _until(
            pilot,
            lambda: (
                app.byte_unit == "MB" and not isinstance(app.screen, ByteUnitPicker)
            ),
        )
        # The unit before has the hint, and , b b goes back and forth.
        await pilot.press("comma", "b")
        await _until(pilot, lambda: isinstance(app.screen, ByteUnitPicker))
        options = app.screen.query_one("#picker-results")
        assert (
            str(options.get_option_at_index(0).prompt)
            .rstrip()
            .endswith("(press b to select)")
        )
        await pilot.press("b")
        await _until(
            pilot, lambda: app.byte_unit == "auto" and app.last_byte_unit == "MB"
        )
        await pilot.press("comma", "b", "b")
        await _until(
            pilot, lambda: app.byte_unit == "MB" and app.last_byte_unit == "auto"
        )


def test_access_hint(tmp_path):
    """The group named is the socket's own, whatever [viewer] group calls it."""
    path = tmp_path / "query.sock"
    path.touch()
    if os.geteuid() == 0:
        os.chown(path, -1, next(g.gr_gid for g in grp.getgrall() if g.gr_gid))
    group = grp.getgrgid(os.stat(path).st_gid).gr_name
    assert access_hint(path) == f"join the viewer group ({group}) or run as root"
    assert "[viewer] group" in access_hint(tmp_path / "missing.sock")


def test_format():
    assert format_bytes(999) == "999 B"
    assert format_bytes(1500) == "1.5 kB"
    assert format_bytes(2_500_000, "kB") == "2,500.0 kB"
    assert format_bytes(1234, "B") == "1,234"
    assert format_value("protocol", 6) == "tcp"
    assert format_value("domain", "") == "(none)"
    assert format_value("cmdline", "a\tb\nc\x1b[31m") == "a b c[31m"
    assert (
        remote({"domain": "com.example", "raddr": "93.184.215.14", "rport": 443})
        == "com.example:443"
    )
    assert remote({"raddr": "10.0.0.1", "rport": -1}) == "10.0.0.1"


def test_time_range():
    now = 1_000_000_000
    hour = next(i for i, (name, _) in enumerate(SPANS) if name == "1 hour")
    time_range = TimeRange(hour)
    assert (
        time_range.bounds(now, None) == (now - 3600, now + 1) and time_range.ends_now()
    )
    assert time_range.heading(*time_range.bounds(now, None)) == "last 1 hour"
    time_range.step(-1)
    start, end = time_range.bounds(now, None)
    # The last whole hour of local time before now.
    assert end - start == 3600 and end <= now < end + 3600 and not time_range.ends_now()
    assert time_range.heading(start, end) == "1 hour, 1 back"
    # A zoom keeps the step back for s s to return to.
    time_range.zoom_to(5, 10)
    assert time_range.bounds(now, None) == (5, 10)
    time_range.unzoom()
    assert time_range.bounds(now, None) == (start, end)
    # Forward stops at the span that ends now.
    time_range.step(1)
    time_range.step(1)
    assert time_range.ends_now()
    # Picking the span shown, ending now, changes nothing; after a step back it does.
    assert not time_range.pick(hour)
    time_range.step(-1)
    assert time_range.pick(hour) and time_range.ends_now()
    everything = TimeRange(0)
    assert everything.bounds(now, 1234) == (1234, now + 1)
    assert not everything.steppable() and everything.heading(0, 1) == "all history"


def test_bucket_step():
    # Round lengths, never below the write window.
    assert bucket_step(60, 100) == 10
    assert bucket_step(900, 100) == 10
    assert bucket_step(3600, 100) == 60
    assert bucket_step(86400, 120) == 900
    assert bucket_step(10**12, 100) == 365 * 86400
    # A daemon writing every 45 s gets no bucket shorter, which would be empty between
    # its rows.
    assert bucket_step(60, 100, 45) == 60
    assert bucket_step(3600, 100, 45) == 60
    # Buckets up to a day long start on whole steps of local time, longer ones at the
    # start.
    start = 1_000_000_007
    origin, step = bucket_grid(start, start + 3600, 100)
    assert step == 60 and origin <= start < origin + step
    assert (origin + time.localtime(origin).tm_gmtoff) % step == 0
    assert bucket_grid(start, start + 10**12, 100) == (start, 365 * 86400)


def test_plot_axes():
    # The time axis is tcoda's; the rate axis labels round values in bytes per second.
    rates = RateAxis()
    ticks = rates.get_ticks(0, 7000, 5)
    assert ticks == [0.0, 2000.0, 4000.0, 6000.0]
    assert rates.get_labels(ticks) == ["0", "2.0 kB/s", "4.0 kB/s", "6.0 kB/s"]


async def test_plot_limits():
    """Zooming out stops at ten years, zooming in at a minute, and nothing reaches back
    before 1970.
    """
    settled = []

    class PlotApp(App):
        def compose(self) -> ComposeResult:
            yield TrafficPlot()

        def on_plot_range_settled(self, event: TrafficPlot.RangeSettled) -> None:
            settled.append(event.x_range)

    def width_is(span):
        return lambda: bool(settled) and abs(settled[-1][1] - settled[-1][0] - span) < 1

    app = PlotApp()
    async with app.run_test(size=(100, 30)) as pilot:
        plot = app.query_one(TrafficPlot)
        # The first hour after the epoch, so zooming out runs into 1970.
        plot.show(Timeline(0, 3600, 0, 60, PEAK_SECONDS, 0, ()))
        plot.focus()
        await pilot.press(*["minus"] * 100)
        await _until(pilot, width_is(MAX_SPAN))
        assert settled[-1][0] >= 0
        await pilot.press(*["plus"] * 200)
        await _until(pilot, width_is(MIN_SPAN))


async def _until(pilot, condition, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        await pilot.pause(0.05)


def _server(tmp_path):
    db = _db(tmp_path)
    listener, _ = query_server.listening_socket(tmp_path / "query.sock")
    threading.Thread(
        target=query_server.QueryServer(
            db, ephemeral=32768, write_window=10, rollup_period=3600
        ).serve,
        args=(listener, None),
        daemon=True,
    ).start()
    return listener


def _values(pane: HistoryPane) -> list:
    return [row.value for row in pane.shown()]


async def test_history_drill_down(tmp_path):
    listener = _server(tmp_path)

    try:
        app = TracctApp(tmp_path / "events.sock", tmp_path / "query.sock", "processes")
        app.time_range = TimeRange(0)
        async with app.run_test(size=(140, 45)) as pilot:
            processes = app.query_one("#processes HistoryPane", HistoryPane)
            await _until(pilot, lambda: bool(processes.result))
            # The tab asked for keeps the focus, rather than the first tab taking it.
            await pilot.pause(0.3)
            assert app.query_one(TabbedContent).active == "processes"
            assert _values(processes) == ["/usr/bin/curl", "/usr/sbin/nginx"]
            # Above them the sums over all rows, per layer and peer, which are never
            # added up.
            table = processes.query_one(DataTable)
            assert [str(table.get_row_at(i)[0]) for i in range(table.row_count)] == [
                "(all · outer · remote)",
                "(all · inner)",
                "/usr/bin/curl",
                "/usr/sbin/nginx",
            ]
            assert (
                processes.table_rows[0].out_bytes,
                processes.table_rows[0].in_bytes,
            ) == (6111, 11522)
            # The plot follows the highlighted row, which starts on the largest value,
            # not a sum.
            plot = processes.query_one(TrafficPlot)
            await _until(pilot, lambda: "curl" in plot.row_label)
            assert sum(a for a, _ in plot.values.values()) == 1111
            # A sum is a row like any other: its layer's plot.
            table.focus()
            await pilot.press("up")
            await _until(
                pilot,
                lambda: (
                    plot.row_label == "(all · inner)"
                    and sum(a for a, _ in plot.values.values()) == 300
                ),
            )
            # One of a layer and a peer plots the rows of both.
            await pilot.press("up")
            await _until(
                pilot,
                lambda: (
                    plot.row_label == "(all · outer · remote)"
                    and sum(a for a, _ in plot.values.values()) == 6111
                ),
            )
            assert processes.plot_filters() == [
                Filter("layer", "outer"),
                Filter("peer", "remote"),
            ]
            # It has no value to filter on.
            await pilot.press("comma", "f", "i")
            await pilot.pause(0.3)
            assert not processes.filters
            await pilot.press("down", "down")
            # ,f i keeps the highlighted row, ,f e excludes it, ,f p pops the last
            # filter.
            processes.query_one(DataTable).focus()
            # No filter, no find, no problem: no banner.
            banner = processes.query_one(Banner)
            assert not banner.display
            # Enter on a row no longer filters.
            await pilot.press("down", "enter")
            await pilot.pause(0.3)
            assert not processes.filters
            await pilot.press("comma", "f", "i")
            await _until(
                pilot,
                lambda: (
                    processes.filters == [Filter("exe", "/usr/sbin/nginx", False)]
                    and _values(processes) == ["/usr/sbin/nginx"]
                ),
            )
            # The filters are in the banner, with the chord that clears them.
            assert banner.display and _banner(processes) == (
                "filter: executable=/usr/sbin/nginx",
                "press ,f c to clear filters",
            )
            await pilot.press("comma", "f", "p")
            await _until(
                pilot, lambda: not processes.filters and len(_values(processes)) == 2
            )
            # The highlight stayed on nginx through the refresh.
            await pilot.press("comma", "f", "e")
            await _until(
                pilot,
                lambda: (
                    processes.filters == [Filter("exe", "/usr/sbin/nginx", True)]
                    and _values(processes) == ["/usr/bin/curl"]
                ),
            )
            # A drill-down: keep curl, break it down by namespace, keep that; , f c
            # clears both and returns to the dimension it started from.
            await pilot.press("comma", "f", "p")
            await _until(pilot, lambda: len(_values(processes)) == 2)
            # Excluding nginx moved the highlight to curl, and it stayed there.
            await pilot.press("comma", "f", "i")
            await _until(
                pilot,
                lambda: processes.filters == [Filter("exe", "/usr/bin/curl", False)],
            )
            processes.select_dimension("netns")
            processes.reload()
            await _until(pilot, lambda: _values(processes) == ["host"])
            await pilot.press("comma", "f", "i")
            await _until(pilot, lambda: len(processes.filters) == 2)
            await pilot.press("comma", "f", "c")
            await _until(
                pilot,
                lambda: (
                    not processes.filters
                    and processes.group_by == "exe"
                    and len(_values(processes)) == 2
                ),
            )
            # Grouped by a dimension the sums are made of, the rows are the sums
            # already.
            processes.select_dimension("peer")
            processes.reload()
            await _until(pilot, lambda: _values(processes) == ["remote"])
            assert len(processes.table_rows) == 1
            # Another dimension.
            processes.select_dimension("netns")
            processes.reload()
            await _until(pilot, lambda: set(_values(processes)) == {"host", str(VPN)})
            assert not banner.display
            assert processes.query_one("#dimensions").border_title == "group by"
            # The table's title counts the rows only while some are hidden.
            assert table.border_title == "summary"
            # Find narrows the rows shown; kept with Enter, the banner says it, and c
            # clears it.
            await pilot.press("slash", "h", "o", "s", "t")
            await _until(pilot, lambda: _values(processes) == ["host"])
            assert table.border_title == "summary · 1 of 2 rows"
            # The input opens on the tab's own top line.
            assert (
                processes.children[0].has_class("find", "shown") and not banner.display
            )
            await pilot.press("enter")
            await _until(
                pilot, lambda: _banner(processes) == ("find: host", "press c to clear")
            )
            await pilot.press("c")
            await _until(
                pilot, lambda: len(_values(processes)) == 2 and not banner.display
            )
            assert table.border_title == "summary"
            # Escape clears an open one.
            await pilot.press("slash", "h")
            await _until(pilot, lambda: _values(processes) == ["host"])
            await pilot.press("escape")
            await _until(pilot, lambda: len(_values(processes)) == 2)
            assert not processes.children[0].has_class("shown") and not banner.display
            # The interfaces tab shares the range.
            await pilot.press("i")
            interfaces = app.query_one("#interfaces HistoryPane", HistoryPane)
            await _until(pilot, lambda: bool(interfaces.result))
            assert _values(interfaces) == ["host/eth0", f"{VPN}/tun0"]
            # Its sums: the tunnels' and the network cards'.
            assert [row.value.label() for row in interfaces.table_rows[:2]] == [
                "(all · physical)",
                "(all · inner)",
            ]
            # Zooming the plot narrows every tab to what it shows; z returns to the
            # span.
            plot = interfaces.query_one(TrafficPlot)
            await _until(pilot, lambda: bool(plot.values))
            start, end = interfaces.bounds()
            plot.focus()
            # The plot keeps only its time keys; up and down do not move it, r refreshes
            # as anywhere.
            await _until(
                pilot,
                lambda: (
                    {"plus", "minus", "left", "right", "r", "s"}
                    <= set(app.screen.active_bindings)
                ),
            )
            assert app.screen.active_bindings["r"][1].action == "app.refresh"
            assert not {
                "up",
                "down",
                "ctrl+shift+equals_sign",
                "ctrl+shift+minus",
            } & set(app.screen.active_bindings)
            await pilot.press("plus")
            await _until(pilot, lambda: app.time_range.zoom is not None)
            zoomed_start, zoomed_end = app.time_range.zoom
            assert (
                start <= zoomed_start < zoomed_end <= end
                and zoomed_end - zoomed_start < end - start
            )
            await _until(pilot, lambda: plot.timeline.start == zoomed_start)
            await pilot.press("r")
            await pilot.pause(0.3)
            assert app.time_range.zoom == (zoomed_start, zoomed_end)
            # S twice: the picker, then back from the zoom to the span.
            await pilot.press("s", "s")
            await _until(
                pilot,
                lambda: app.time_range.zoom is None and plot.timeline.start == start,
            )
            await pilot.press("comma", "b", "down", "enter")
            await _until(pilot, lambda: app.byte_unit == "B")
            # Every history tab shows it, the hidden ones too, without asking again.
            for pane in (interfaces, processes):
                cell = str(pane.query_one(DataTable).get_cell_at((0, 1)))
                assert pane.query_one(TrafficPlot).byte_unit == "B"
                assert cell and not any(c.isalpha() for c in cell)
    finally:
        listener.close()


async def test_history_reads_rollup_periods_whole(tmp_path):
    """A range inside the rollups takes the periods it reaches into whole and says so,
    and the plot shows a period longer than a bucket as one span at its average.
    """
    listener = _server(tmp_path)

    try:
        app = TracctApp(tmp_path / "events.sock", tmp_path / "query.sock", "processes")
        app.time_range = TimeRange(0)
        # Twenty minutes inside the second rolled-up hour.
        app.time_range.zoom_to(P0 + H + 600, P0 + H + 1800)
        async with app.run_test(size=(140, 45)) as pilot:
            processes = app.query_one("#processes HistoryPane", HistoryPane)
            await _until(pilot, lambda: bool(processes.result))
            # Not nothing: the hour, as the table's bottom border says.
            assert _values(processes) == ["/usr/sbin/nginx", "/usr/bin/curl"]
            table = processes.query_one(DataTable)
            assert table.border_subtitle == (
                f"rollups before {format_time(P0 + 2 * H)}:"
                f" whole periods {format_time(P0 + H)} – {format_time(P0 + 2 * H)},"
                " no addresses, ephemeral ports as 0"
            )
            plot = processes.query_one(TrafficPlot)
            await _until(
                pilot, lambda: plot.timeline is not None and plot.timeline.spans
            )
            (span,) = plot.timeline.spans
            assert (span.start, span.seconds, span.out_bytes) == (P0 + H, H, 5000)
            # Anywhere in it the pointer finds the period, with its average.
            assert plot.describe(P0 + H + 900) == (
                f"{format_time(P0 + H)} +1 h"
                f" · sent {format_bytes(5000)} (avg {format_bytes(5000 / H)}/s)"
                f" · received {format_bytes(500)} (avg {format_bytes(500 / H)}/s)"
            )
    finally:
        listener.close()


async def test_plot_title_and_busy(tmp_path):
    listener = _server(tmp_path)
    slow = threading.Event()

    try:
        app = TracctApp(tmp_path / "events.sock", tmp_path / "query.sock", "interfaces")
        app.time_range = TimeRange(0)
        ask = app.client.ask

        def delayed(op, **params):
            if slow.is_set():
                time.sleep(1.0)
            return ask(op, **params)

        app.client.ask = delayed
        async with app.run_test(size=(140, 45)) as pilot:
            pane = app.query_one("#interfaces HistoryPane", HistoryPane)
            plot = pane.query_one(TrafficPlot)
            shown = []
            set_busy = plot.set_busy
            plot.set_busy = lambda busy: (shown.append(busy), set_busy(busy))
            await _until(pilot, lambda: bool(plot.values) and not pane.loading())
            # Answers within milliseconds never show the glyph.
            assert True not in shown and BUSY not in _title(plot)
            # The range, then the key; the highlighted row is in the table, and the
            # peaks' stretch is the usual one. Left of the line the points are the
            # rollups' averages.
            assert _title(plot) == (
                "all history · ━━ sent ━━ received · averages before the line"
            )
            # A slow answer shows it until the rows and the plot are both in.
            slow.set()
            app.action_refresh()
            await _until(
                pilot, lambda: plot.busy and _title(plot).endswith(f" · {BUSY}")
            )
            slow.clear()
            await _until(pilot, lambda: not plot.busy and BUSY not in _title(plot))
            # A zoom is named by its ends.
            plot.focus()
            await pilot.press("plus")
            await _until(
                pilot, lambda: app.time_range.zoom is not None and " – " in _title(plot)
            )
    finally:
        listener.close()


async def test_history_plot_only(tmp_path):
    listener = _server(tmp_path)

    try:
        app = TracctApp(tmp_path / "events.sock", tmp_path / "query.sock", "processes")
        app.time_range = TimeRange(0)
        timeline = app.client.timeline
        asked = []
        app.client.timeline = lambda *args, **kwargs: (
            asked.append(args),
            timeline(*args, **kwargs),
        )[1]
        async with app.run_test(size=(140, 45)) as pilot:
            processes = app.query_one("#processes HistoryPane", HistoryPane)
            plot = processes.query_one(TrafficPlot)
            table = processes.query_one(DataTable)
            await _until(pilot, lambda: bool(plot.values) and not processes.loading())
            await pilot.pause(0.3)
            size, points, requests = plot.size, plot.points(), len(asked)
            assert app.focused is table
            # The plot takes the whole tab, with the focus, and asks again for its new
            # width.
            await pilot.press("comma", "p")
            await _until(
                pilot,
                lambda: (
                    not table.display
                    and not processes.query_one("#dimensions").display
                    and app.focused is plot
                ),
            )
            assert plot.size.width > size.width and plot.size.height > size.height
            assert plot.points() > points
            await _until(pilot, lambda: len(asked) > requests)
            # Shared by the history tabs, as the range is.
            await pilot.press("i")
            interfaces = app.query_one("#interfaces HistoryPane", HistoryPane)
            await _until(
                pilot,
                lambda: (
                    app.focused is interfaces.query_one(TrafficPlot)
                    and not interfaces.query_one(DataTable).display
                ),
            )
            # Pressed again, the dimensions and the table come back.
            await pilot.press("p", "comma", "p")
            await _until(
                pilot,
                lambda: table.display and app.focused is table and plot.size == size,
            )
    finally:
        listener.close()


async def test_history_dimension_headings(tmp_path):
    listener = _server(tmp_path)

    try:
        app = TracctApp(tmp_path / "events.sock", tmp_path / "query.sock", "processes")
        app.time_range = TimeRange(0)
        async with app.run_test(size=(140, 45)) as pilot:
            processes = app.query_one("#processes HistoryPane", HistoryPane)
            interfaces = app.query_one("#interfaces HistoryPane", HistoryPane)
            await _until(
                pilot, lambda: bool(processes.result) and interfaces.info is not None
            )
            options = processes.query_one("#dimensions", OptionList)
            # Each a rule as wide as the list.
            headings = [
                option.prompt.title for option in options.options if option.disabled
            ]
            assert headings == [
                f"─── {heading}"
                for heading in ("process", "parent", "network", "connection")
            ]
            # The first heading comes before the dimension the tab starts on.
            assert options.highlighted == 1
            assert options.highlighted_option.id == "exe"
            # The highlight skips a heading, both ways.
            options.focus()
            processes.select_dimension("uid")
            await pilot.press("down")
            assert options.highlighted_option.id == "pexe"
            # Under its heading it drops the prefix, but the table's header keeps it.
            assert str(options.highlighted_option.prompt) == "executable"
            table = processes.query_one(DataTable)
            await _until(
                pilot,
                lambda: str(table.columns["value"].label) == "parent executable",
            )
            await pilot.press("up")
            assert options.highlighted_option.id == "uid"
            # Interfaces' short list has none.
            assert not any(
                option.disabled
                for option in interfaces.query_one("#dimensions", OptionList).options
            )
    finally:
        listener.close()


async def test_history_without_query_server(tmp_path):
    app = TracctApp(tmp_path / "events.sock", tmp_path / "missing.sock", "processes")
    async with app.run_test(size=(120, 40)) as pilot:
        pane = app.query_one("#processes HistoryPane", HistoryPane)
        await _until(pilot, lambda: bool(pane.error))
        assert "query server unavailable" in pane.error
        # In the banner, as on the live tab, and with nothing to undo no hint.
        banner = pane.query_one(Banner)
        assert (
            banner.display
            and banner.has_class("-error")
            and _banner(pane) == (pane.error, "")
        )


async def test_error_before_mount(tmp_path):
    # A missing query server is reported as soon as the app is mounted, which can be
    # before a pane has composed its banner, or the banner its own children.
    app = TracctApp(tmp_path / "events.sock", tmp_path / "missing.sock", "processes")
    async with app.run_test(size=(120, 40)) as pilot:
        shown = app.query_one("#processes HistoryPane", HistoryPane)
        await _until(pilot, lambda: bool(shown.error))
        pane = HistoryPane("processes")
        pane.show_error("unavailable")
        await app.screen.mount(pane)
        await pilot.pause()
        # The app keeps asking the query server, whose error may have replaced this one.
        banner = pane.query_one(Banner)
        assert (
            banner.display
            and banner.has_class("-error")
            and _banner(pane) == (pane.error, "")
        )


async def test_live_tab(tmp_path, monkeypatch):
    socket_path = tmp_path / "events.sock"
    monkeypatch.setattr(live_feed, "EVENTS_SOCKET_PATH", socket_path)
    publisher = live_feed.LiveFeedPublisher()
    publisher.start()

    try:
        app = TracctApp(socket_path, tmp_path / "missing.sock", "live")
        async with app.run_test(size=(140, 45)) as pilot:
            pane = app.query_one(LivePane)
            await _until(
                pilot,
                lambda: (
                    pane.state is FeedState.CONNECTED and publisher.has_subscribers()
                ),
            )
            event = {
                "name": "curl",
                "exe": "/usr/bin/curl",
                "pname": "bash",
                "unit": "session-1.scope",
                "send": 100,
                "recv": 2000,
                "lport": 50000,
                "rport": 443,
                "domain": "com.example",
            }
            publisher.publish_many(
                [
                    event,
                    {**event, "send": 1},
                    {**event, "name": "wget", "exe": "/usr/bin/wget", "recv": 5},
                    {**event, "unit": "vpn@b.service", "recv": 1000},
                ]
            )
            await _until(pilot, lambda: pane.event_count == 4)
            curl_key = "curl\0/usr/bin/curl\0session-1.scope"
            vpn_key = "curl\0/usr/bin/curl\0vpn@b.service"
            wget_key = "wget\0/usr/bin/wget\0session-1.scope"
            curl = pane.summary[curl_key]
            assert (curl.sent, curl.received, curl.events) == (101, 4000, 2)
            # The same executable in another unit, an instance here, sums on a row of
            # its own.
            vpn = pane.summary[vpn_key]
            assert (vpn.sent, vpn.received, vpn.events) == (100, 1000, 1)
            assert (curl.unit, vpn.unit) == ("session-1.scope", "vpn@b.service")
            # Nothing to say: no banner; the events title carries the counts.
            banner = pane.query_one(".banner")
            assert not banner.display
            await _until(
                pilot,
                lambda: (
                    str(pane.query_one("#events", DataTable).border_title)
                    == "last 500 events · 4 total"
                ),
            )
            # The seconds since the tab started go with the totals they were summed
            # over.
            assert re.fullmatch(
                r"summary · \d+ s",
                str(pane.query_one("#summary", DataTable).border_title),
            )
            # Typing a find (c types, it does not clear): the input says it; kept with
            # Enter, the banner on the same line does, with a hint that c clears it.
            await pilot.press("slash", "c", "u", "r", "l")
            await _until(pilot, lambda: pane.find == "curl")
            assert not banner.display
            await pilot.press("enter")
            await _until(
                pilot,
                lambda: (
                    banner.display
                    and str(banner.query_one(".banner-text").render()) == "find: curl"
                ),
            )
            assert banner.query_one(".banner-hint").display
            await pilot.press("c")
            await _until(pilot, lambda: not banner.display)
            assert pane.find == "" and pane.query_one(".find").value == ""
            await _until(
                pilot,
                lambda: (
                    pane.query_one("#summary", DataTable).row_count == 3
                    and pane.query_one("#events", DataTable).row_count == 4
                ),
            )
            # By executable, newest event first.
            summary, events = (
                pane.query_one("#summary", DataTable),
                pane.query_one("#events", DataTable),
            )
            assert _keys(summary) == [curl_key, vpn_key, wget_key]
            assert _keys(events) == ["4", "3", "2", "1"]
            # By the number behind the text: 5 B before 1.0 kB before 4.0 kB, where the
            # text would rank them the other way.
            summary.sort_by("received")
            assert _keys(summary) == [wget_key, vpn_key, curl_key]
            # A refill keeps the sort, and the cursor stays on its row as it moves up.
            summary.move_cursor(row=2)
            pane.summary[curl_key].received = 0
            pane.render_tables()
            assert (
                _keys(summary) == [curl_key, wget_key, vpn_key]
                and summary.cursor_row == 0
            )
            events.sort_by("sent")
            assert _keys(events)[0] == "2"
            # Paused, the events table stops; reset clears.
            pane.query_one("#summary", DataTable).focus()
            await pilot.press("space")
            publisher.publish(event)
            await _until(pilot, lambda: pane.event_count == 5)
            assert len(pane.events) == 4
            await _until(pilot, lambda: events.border_subtitle == "updates are paused")
            await pilot.press("r")
            await _until(pilot, lambda: pane.event_count == 0 and not pane.summary)
            # Reset empties the frozen table too, so nothing in it outlives its event.
            assert events.row_count == 0 and summary.row_count == 0
            events.sort_by("received")
    finally:
        publisher.stop()


async def test_live_summary_keeps_raw_bytes_apart(tmp_path, monkeypatch):
    """A process's raw bytes, a VPN client's TUN packets, sum on a row of their own,
    never with its socket bytes; events lost while the UI stalled are counted.
    """
    monkeypatch.setattr("tracct.viewer.live.INCOMING_MAX", 3)
    app = TracctApp(tmp_path / "events.sock", tmp_path / "query.sock", "live")
    async with app.run_test(size=(140, 45)) as pilot:
        pane = app.query_one(LivePane)
        event = {
            "name": "tailscaled",
            "exe": "/usr/sbin/tailscaled",
            "unit": "tailscaled.service",
            "send": 1000,
            "recv": 2000,
            "family": 2,
        }
        # Taken between two redraws: the fourth pushes the first out.
        for received in (
            event,
            {**event, "family": 17, "send": 900, "recv": 1900},
            event,
            event,
        ):
            pane.receive(received)
        assert pane.lost == 1
        await _until(pilot, lambda: pane.event_count == 3)
        key = "tailscaled\0/usr/sbin/tailscaled\0tailscaled.service"
        assert (pane.summary[key].sent, pane.summary[key].received) == (2000, 4000)
        raw = pane.summary[key + "\0raw"]
        assert (raw.sent, raw.received, raw.raw) == (900, 1900, True)
        summary = pane.query_one("#summary", DataTable)
        await _until(pilot, lambda: summary.row_count == 2)
        assert {str(summary.get_cell(row, "kind")) for row in summary.rows} == {
            "socket",
            "raw",
        }
        await _until(
            pilot,
            lambda: str(summary.border_title).startswith("summary (1 events lost) · "),
        )


def test_shorten():
    path = "/opt/very/long/lib/firefox/firefox"
    assert shorten_path(path, len(path)) == path
    # Cut at a slash, so no directory shows in part.
    assert shorten_path(path, len(path) - 1) == "…/very/long/lib/firefox/firefox"
    assert shorten_path(path, 22) == "…/lib/firefox/firefox"
    # A name longer than the width keeps its end.
    assert shorten_path("/bin/" + "x" * 30 + "end", 10) == "…xxxxxxend"
    assert shorten_path("x" * 30 + "end", 10) == "…xxxxxxend"
    # Wide characters count twice.
    assert shorten_path("/ü/日本語", 7) == "…日本語"
    assert shorten_end("snap.firefox.firefox-0d8f.scope", 31) == (
        "snap.firefox.firefox-0d8f.scope"
    )
    assert shorten_end("snap.firefox.firefox-0d8f.scope", 12) == "snap.firefo…"
    assert shorten_end("日本語日本語", 6) == "日本…"
    host = "lhr48s27-in-f14.1e100.net"
    assert shorten_host(host, 443, 40) == host + ":443"
    assert shorten_host(host, 443, 14) == "…1e100.net:443"
    assert shorten_host(host, 0, 10) == "…1e100.net"
    # An IPv6 address keeps its own colons.
    assert shorten_host("2001:db8:85a3::8a2e:370:7334", 443, 16) == "…2e:370:7334:443"


async def test_live_shortened(tmp_path):
    """Long executables, units and remotes are shortened to the width setting; the
    selected row's show in full in the bottom border, and sorting follows them.
    """
    config.set(settings.LIVE_COLUMN_WIDTH, 20)
    app = TracctApp(tmp_path / "events.sock", tmp_path / "query.sock", "live")
    async with app.run_test(size=(140, 45)) as pilot:
        pane = app.query_one(LivePane)
        summary = pane.query_one("#summary", DataTable)
        events = pane.query_one("#events", DataTable)
        deep = "/opt/zz/very/deep/directory/bin/app"
        unit = "app-gnome-org.example.App-12345.scope"
        pane.receive(
            {
                "name": "app",
                "exe": deep,
                "unit": unit,
                "send": 1,
                "rport": 443,
                "domain": "lhr48s27-in-f14.1e100.net",
            }
        )
        pane.receive({"name": "curl", "exe": "/usr/bin/curl", "send": 1})
        await _until(pilot, lambda: summary.row_count == 2 and events.row_count == 2)
        deep_key = f"app\0{deep}\0{unit}"
        assert summary.get_cell(deep_key, "exe").plain == "…/directory/bin/app"
        assert summary.get_cell(deep_key, "unit").plain == "app-gnome-org.examp…"
        assert events.get_cell("1", "remote").plain == "…n-f14.1e100.net:443"
        # By the full path: /opt/zz before /usr, where "…" would rank after "/".
        assert _keys(summary) == [deep_key, "curl\0/usr/bin/curl\0"]
        summary.move_cursor(row=0)
        await _until(pilot, lambda: summary.border_subtitle == f"{deep} · {unit}")
        # A row shown in full has nothing to add.
        summary.move_cursor(row=1)
        await _until(pilot, lambda: summary.border_subtitle == "")
        # The events table, newest first: the long one is second.
        events.move_cursor(row=1)
        await _until(
            pilot,
            lambda: events.border_subtitle == f"lhr48s27-in-f14.1e100.net:443 · {unit}",
        )
        # A wider setting applies without new traffic.
        config.set(settings.LIVE_COLUMN_WIDTH, 60)
        await _until(pilot, lambda: summary.get_cell(deep_key, "exe").plain == deep)
        await _until(pilot, lambda: events.border_subtitle == "")


async def test_live_summary_scroll(tmp_path, monkeypatch):
    socket_path = tmp_path / "events.sock"
    monkeypatch.setattr(live_feed, "EVENTS_SOCKET_PATH", socket_path)
    publisher = live_feed.LiveFeedPublisher()
    publisher.start()

    try:
        app = TracctApp(socket_path, tmp_path / "missing.sock", "live")
        async with app.run_test(size=(140, 45)) as pilot:
            pane = app.query_one(LivePane)
            summary = pane.query_one("#summary", DataTable)
            await _until(
                pilot,
                lambda: (
                    pane.state is FeedState.CONNECTED and publisher.has_subscribers()
                ),
            )
            publisher.publish_many(
                [
                    {"name": f"x{i:02}", "exe": f"/bin/x{i:02}", "send": 1}
                    for i in range(60)
                ]
            )
            await _until(pilot, lambda: summary.row_count == 60)
            await _until(pilot, lambda: summary.max_scroll_y > 10)
            summary.scroll_to(y=10, animate=False)
            await pilot.pause()
            assert summary.scroll_y == 10
            # More traffic for a row shown updates it in place: the summary stays
            # scrolled where it was, the cursor out of view included.
            publisher.publish({"name": "x30", "exe": "/bin/x30", "send": 1})
            await _until(
                pilot,
                lambda: summary.get_cell("x30\0/bin/x30\0", "events").plain == "2",
            )
            await pilot.pause()
            assert summary.scroll_y == 10 and summary.row_count == 60
    finally:
        publisher.stop()


def _keys(table: DataTable) -> list[str]:
    return [row.key.value for row in table.ordered_rows]


def _banner(pane) -> tuple[str, str]:
    """The banner's text and its hint, or "" for a hidden hint."""
    banner = pane.query_one(Banner)
    hint = banner.query_one(".banner-hint")
    return str(banner.query_one(".banner-text").render()), str(
        hint.render()
    ) if hint.display else ""


def _title(plot: TrafficPlot) -> str:
    """The plot's title as shown: Textual keeps it as markup."""
    return Content.from_markup(plot.border_title).plain


async def test_live_limits(tmp_path, monkeypatch):
    socket_path = tmp_path / "events.sock"
    monkeypatch.setattr(live_feed, "EVENTS_SOCKET_PATH", socket_path)
    publisher = live_feed.LiveFeedPublisher()
    publisher.start()
    config.set(settings.LIVE_SUMMARY_ROWS, 10)
    config.set(settings.LIVE_EVENTS, 12)

    try:
        app = TracctApp(socket_path, tmp_path / "missing.sock", "live")
        async with app.run_test(size=(140, 45)) as pilot:
            pane = app.query_one(LivePane)
            await _until(
                pilot,
                lambda: (
                    pane.state is FeedState.CONNECTED and publisher.has_subscribers()
                ),
            )
            # Two rows go idle, ten more arrive after them: the idle two make room.
            publisher.publish_many(
                [
                    {"name": f"old{i}", "exe": f"/bin/old{i}", "send": 1}
                    for i in range(2)
                ]
            )
            await _until(pilot, lambda: pane.event_count == 2)
            publisher.publish_many(
                [
                    {"name": f"new{i}", "exe": f"/bin/new{i}", "send": 1}
                    for i in range(10)
                ]
            )
            await _until(pilot, lambda: pane.event_count == 12)
            assert pane.dropped == 2 and len(pane.summary) == 10
            await _until(
                pilot,
                lambda: str(
                    pane.query_one("#summary", DataTable).border_title
                ).startswith("summary (2 dropped) · "),
            )
            assert (
                str(pane.query_one("#events", DataTable).border_title)
                == "last 12 events · 12 total"
            )
            assert not any(t.name.startswith("old") for t in pane.summary.values())
            assert pane.query_one("#summary", DataTable).row_count == 10
            assert len(pane.events) == 12
            # A lowered limit applies on the next redraw and keeps the newest events.
            config.set(settings.LIVE_EVENTS, 10)
            await _until(pilot, lambda: len(pane.events) == 10)
            await _until(
                pilot,
                lambda: str(
                    pane.query_one("#events", DataTable).border_title
                ).startswith("last 10 events · "),
            )
            assert [event.name for event in reversed(pane.events.values())] == [
                f"new{i}" for i in range(9, -1, -1)
            ]
            await _until(
                pilot, lambda: pane.query_one("#events", DataTable).row_count == 10
            )
            pane.query_one("#summary", DataTable).focus()
            await pilot.press("r")
            await _until(pilot, lambda: pane.dropped == 0)
            await _until(
                pilot,
                lambda: str(
                    pane.query_one("#summary", DataTable).border_title
                ).startswith("summary · "),
            )
    finally:
        publisher.stop()
