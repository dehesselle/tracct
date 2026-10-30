# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Tests for the query server.

Routing between raw rows and rollups, dimensions, filters, request validation and the
socket. No root needed.
"""

import socket
import sqlite3
import struct
import threading
import time

import pytest

from tracct import query_server
from tracct.constants import DB_VERSION, INDEXES, SENTINELS, TABLES
from tracct.query import QueryClient, QueryError, recv_message

H = 3600
P0 = 100 * H
HOST, VPN = 4026531840, 4026532500
#: Their ids in the netns table.
HOST_ID, VPN_ID = 1, 2
EPHEMERAL = 32768


def _db(tmp_path):
    """Four hours of history.

    The first two only as rollups (the second one's raw rows partly purged), the third
    rolled up and still raw, the fourth raw only. Rows that must not be read (the purged
    period's raw remainder, the third period's rollup) carry large sums.
    """
    db = tmp_path / "tracct.db"
    con = sqlite3.connect(db)
    for table, schema in TABLES:
        con.execute(f"CREATE TABLE {table} ({schema}) STRICT")
    for statement in SENTINELS + INDEXES:
        con.execute(statement)
    con.execute(
        "INSERT INTO executables VALUES (1, '/usr/bin/curl', 'curl', 'curl example.com'), (2, '/usr/bin/bash', 'bash', 'bash'), (3, '/usr/sbin/nginx', 'nginx', 'nginx')"
    )
    con.execute("INSERT INTO units VALUES (1, 'nginx.service')")
    con.execute(
        "INSERT INTO addresses VALUES (1, '10.0.0.2'), (2, '93.184.215.14'), (3, '100.64.0.2'), (4, '198.51.100.7')"
    )
    con.execute("INSERT INTO domains VALUES (1, 'com.example')")
    con.execute(
        f"INSERT INTO interfaces VALUES (1, {HOST_ID}, 'eth0', ''), (2, {HOST_ID}, 'tailscale0', 'tun'), (3, {VPN_ID}, 'tun0', 'tun')"
    )
    con.execute(
        f"INSERT INTO netns VALUES ({HOST_ID}, {HOST}, 'host'), ({VPN_ID}, {VPN}, '')"
    )
    # Time, sent, received, events, exe, pexe, unit, uid, family, protocol, lport, rport,
    # laddr, raddr, domain, netns_id, iface, seconds.
    con.executemany(
        "INSERT INTO connections VALUES (?, ?, ?, 1, ?, 2, ?, 1000, 2, 6, ?, ?, 1, ?, ?, ?, ?, 10)",
        [
            (
                P0 + H + 100,
                100000,
                100000,
                1,
                0,
                50000,
                443,
                2,
                1,
                HOST_ID,
                1,
            ),  # purged period: from the rollup
            (P0 + 2 * H + 10, 1, 2, 1, 0, 50001, 443, 2, 1, HOST_ID, 1),
            (P0 + 3 * H + 10, 10, 20, 1, 0, 50002, 443, 2, 1, HOST_ID, 1),
            (P0 + 3 * H + 20, 300, 30, 3, 1, 80, 50003, 3, 0, VPN_ID, 3),
        ],
    )
    # Period, exe, pexe, unit, uid, family, protocol, lport, rport, domain, netns_id,
    # iface, sent, received, events, rows, seconds.
    con.executemany(
        "INSERT INTO connections_rollup VALUES (?, ?, 2, ?, 1000, 2, 6, ?, ?, ?, ?, 1, ?, ?, 1, 1, 3600)",
        [
            (P0, 1, 0, 0, 443, 1, HOST_ID, 1000, 10000),
            (P0 + H, 1, 0, 0, 443, 1, HOST_ID, 100, 1000),
            (P0 + H, 3, 1, 80, 0, 0, HOST_ID, 5000, 500),
            (
                P0 + 2 * H,
                1,
                0,
                0,
                443,
                1,
                HOST_ID,
                999999,
                999999,
            ),  # still raw: from the raw rows
        ],
    )
    con.executemany(
        "INSERT INTO interface_traffic VALUES (?, ?, ?, ?, 10)",
        [
            (P0 + H + 100, 1, 100000, 100000),
            (P0 + 2 * H + 10, 1, 70, 700),
            (P0 + 3 * H + 10, 3, 4, 40),
        ],
    )
    con.executemany(
        "INSERT INTO interface_traffic_rollup VALUES (?, ?, ?, ?, 3600)",
        [(P0 + H, 1, 600, 6000), (P0 + 2 * H, 1, 999999, 999999)],
    )
    con.execute(
        f"INSERT INTO forwarded VALUES ({P0 + 3 * H + 10}, {HOST_ID}, 6, 3, 40000, 4, 443, 0, 2000, 100000, 20, 80, 10)"
    )
    con.execute(
        f"INSERT INTO forwarded_rollup VALUES ({P0 + H}, {HOST_ID}, 6, 3, 443, 0, 50, 5000, 1, 4, 1, 3600)"
    )
    con.execute(f"INSERT INTO meta VALUES ('rollup_watermark', {P0 + 3 * H})")
    con.execute(f"PRAGMA user_version = {DB_VERSION}")
    con.commit()
    con.close()
    return db


def _ask(db, op, write_window=10, rollup_period=H, **request):
    response = query_server.QueryServer(
        db,
        ephemeral=EPHEMERAL,
        write_window=write_window,
        rollup_period=rollup_period,
    ).answer({"op": op, **request})
    assert response["ok"], response.get("error")
    return response


def _aggregate(db, group_by, start=P0, end=P0 + 4 * H, **request):
    response = _ask(
        db,
        "aggregate",
        source=request.pop("source", "connections"),
        group_by=group_by,
        start=start,
        end=end,
        **request,
    )
    return response, {value: (a, b) for value, a, b in response["rows"]}


def test_raw_rows_take_over_from_rollups(tmp_path):
    db = _db(tmp_path)
    response, rows = _aggregate(db, "exe")
    # The purged period's remainder and the rolled-up period that is still raw are not
    # read twice.
    assert response["split"] == P0 + 2 * H
    assert rows == {
        "/usr/bin/curl": (1000 + 100 + 1 + 10, 10000 + 1000 + 2 + 20),
        "/usr/sbin/nginx": (5000 + 300, 500 + 30),
    }
    assert [row[0] for row in response["rows"]] == ["/usr/bin/curl", "/usr/sbin/nginx"]
    assert response["totals"] == [1111 + 5300, 11022 + 530]
    assert (
        response["groups"] == 2
        and not response["truncated"]
        and not response["clipped"]
    )


def test_raw_rows_older_than_the_rollups_are_read(tmp_path):
    # Rollups kept shorter than the raw rows, raw rows kept forever, or both as long, which
    # purges the oldest raw rows' own period from the rollups: the rollups begin after
    # the raw rows.
    db = _db(tmp_path)
    con = sqlite3.connect(db)
    for table in ("connections_rollup", "interface_traffic_rollup", "forwarded_rollup"):
        con.execute(f"DELETE FROM {table} WHERE period <= ?", (P0 + H,))
    con.commit()
    con.close()
    response, rows = _aggregate(db, "exe")
    # The raw rows are all there is before the oldest rollup, and from it on hold more
    # than the rollups do.
    assert response["split"] == 0
    assert rows == {
        "/usr/bin/curl": (100000 + 1 + 10, 100000 + 2 + 20),
        "/usr/sbin/nginx": (300, 30),
    }
    # Nor do they clip a dimension the rollups do not keep.
    response, rows = _aggregate(db, "raddr")
    assert not response["clipped"] and rows["93.184.215.14"] == (100011, 100022)
    assert _ask(db, "describe")["sources"]["connections"]["split"] == 0


def test_without_rollups_the_raw_rows_are_read(tmp_path):
    db = _db(tmp_path)
    con = sqlite3.connect(db)
    con.execute("DELETE FROM connections_rollup")
    con.commit()
    con.close()
    response, rows = _aggregate(db, "exe")
    assert response["split"] == 0
    assert rows["/usr/bin/curl"] == (100011, 100022)


def test_a_request_reads_one_snapshot(tmp_path, monkeypatch):
    db = _db(tmp_path)
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode = WAL")
    con.close()
    split_point = query_server.split_point

    def purged_meanwhile(con, source):
        split = split_point(con, source)
        # The writer purges raw rows past the split while the request runs.
        writer = sqlite3.connect(db)
        with writer:
            writer.execute("DELETE FROM connections WHERE time < ?", (P0 + 3 * H,))
        writer.close()
        return split

    monkeypatch.setattr(query_server, "split_point", purged_meanwhile)
    response, rows = _aggregate(db, "exe")
    assert response["split"] == P0 + 2 * H
    assert rows["/usr/bin/curl"] == (1111, 11022)


def test_ports_group_like_the_rollups_keep_them(tmp_path):
    db = _db(tmp_path)
    # Reaching into the rollups, ephemeral ports in raw rows become 0 as they are there.
    _, rows = _aggregate(db, "rport")
    assert rows == {443: (1111, 11022), 0: (5300, 530)}
    # Inside the raw rows they stay exact.
    _, rows = _aggregate(db, "rport", start=P0 + 2 * H)
    assert rows == {443: (11, 22), 50003: (300, 30)}


def test_raw_only_dimension_clips_to_the_raw_rows(tmp_path):
    db = _db(tmp_path)
    response, rows = _aggregate(db, "raddr")
    assert response["clipped"] and response["start"] == P0 + 2 * H
    assert rows == {"93.184.215.14": (11, 22), "100.64.0.2": (300, 30)}
    # A filter on one clips too.
    response, rows = _aggregate(db, "exe", filters=[["raddr", "100.64.0.2", False]])
    assert response["clipped"] and rows == {"/usr/sbin/nginx": (300, 30)}


def test_filters_include_and_exclude(tmp_path):
    db = _db(tmp_path)
    _, rows = _aggregate(db, "exe", filters=[["exe", "/usr/sbin/nginx", True]])
    assert list(rows) == ["/usr/bin/curl"]
    _, rows = _aggregate(db, "unit", filters=[["name", "nginx", False]])
    assert rows == {"nginx.service": (5300, 530)}
    # Unnamed namespaces go by inode, and a filter takes the value as it came back.
    _, rows = _aggregate(db, "netns", start=P0 + 2 * H)
    assert rows == {"host": (11, 22), str(VPN): (300, 30)}
    _, rows = _aggregate(
        db, "exe", start=P0 + 2 * H, filters=[["netns", str(VPN), False]]
    )
    assert list(rows) == ["/usr/sbin/nginx"]


def test_interfaces_and_layers(tmp_path):
    db = _db(tmp_path)
    _, rows = _aggregate(db, "iface", start=P0 + 2 * H)
    assert rows == {"host/eth0": (11, 22), f"{VPN}/tun0": (300, 30)}
    _, rows = _aggregate(db, "layer", start=P0 + 2 * H)
    assert rows == {"outer": (11, 22), "inner": (300, 30)}
    # Interface counters, sent and received like the rest.
    _, rows = _aggregate(db, "iface", source="interfaces")
    assert rows == {"host/eth0": (600 + 70, 6000 + 700), f"{VPN}/tun0": (4, 40)}
    _, rows = _aggregate(db, "kind", source="interfaces")
    assert rows == {"": (670, 6700), "tun": (4, 40)}
    # A tun device's counters are what went through the tunnel.
    _, rows = _aggregate(db, "layer", source="interfaces")
    assert rows == {"outer": (670, 6700), "inner": (4, 40)}


def test_namespaces_keep_the_name_of_their_rows(tmp_path):
    """A reused inode named anew leaves the older rows their name, and one name over
    several inodes (a namespace made again after a reboot) is one value.
    """
    db = _db(tmp_path)
    other = VPN + 100
    con = sqlite3.connect(db)
    con.execute(f"INSERT INTO netns VALUES (3, {VPN}, 'vpn'), (4, {other}, 'vpn')")
    con.execute(
        "INSERT INTO interfaces VALUES (4, 3, 'tun0', 'tun'), (5, 4, 'tun0', 'tun')"
    )
    con.executemany(
        "INSERT INTO connections VALUES (?, ?, ?, 1, 3, 2, 1, 1000, 2, 6, 80, 0, 1, 3, 0, ?, ?, 10)",
        [(P0 + 3 * H + 30, 5, 6, 3, 4), (P0 + 3 * H + 40, 7, 8, 4, 5)],
    )
    con.commit()
    con.close()
    _, rows = _aggregate(db, "netns", start=P0 + 2 * H)
    assert rows == {"host": (11, 22), str(VPN): (300, 30), "vpn": (12, 14)}
    _, rows = _aggregate(db, "iface", start=P0 + 2 * H)
    assert rows == {
        "host/eth0": (11, 22),
        f"{VPN}/tun0": (300, 30),
        "vpn/tun0": (12, 14),
    }
    _, rows = _aggregate(db, "exe", start=P0 + 2 * H, filters=[["netns", "vpn", False]])
    assert rows == {"/usr/sbin/nginx": (12, 14)}


def test_totals_per_layer(tmp_path):
    db = _db(tmp_path)
    # The sums over all rows never add up layers: one per layer, largest first.
    response, _ = _aggregate(db, "exe")
    assert response["totals_by"] == "layer" and response["parts"] == [
        ["outer", 6111, 11522],
        ["inner", 300, 30],
    ]
    response, _ = _aggregate(db, "iface", source="interfaces")
    assert response["parts"] == [["outer", 670, 6700], ["inner", 4, 40]]
    # Forwarded bytes have no layers: one sum.
    response, _ = _aggregate(db, "src", source="forwarded")
    assert response["totals_by"] is None and response["parts"] == [[None, 2050, 105000]]
    # A filter narrows them as it does the rows.
    response, rows = _aggregate(db, "exe", filters=[["layer", "inner", False]])
    assert response["parts"] == [["inner", 300, 30]] and rows == {
        "/usr/sbin/nginx": (300, 30)
    }


def test_forwarded(tmp_path):
    db = _db(tmp_path)
    _, rows = _aggregate(db, "src", source="forwarded")
    assert rows == {"100.64.0.2": (2050, 105000)}
    response, rows = _aggregate(db, "dst", source="forwarded")
    assert response["clipped"] and rows == {"198.51.100.7": (2000, 100000)}


def test_timeline(tmp_path):
    db = _db(tmp_path)
    response = _ask(
        db, "timeline", source="connections", start=P0, end=P0 + 4 * H, step=H
    )
    assert response["buckets"] == [
        [P0, 1000, 10000],
        [P0 + H, 5100, 1500],
        [P0 + 2 * H, 1, 2],
        [P0 + 3 * H, 310, 50],
    ]
    # A filter on one row's value gives that row's timeline.
    response = _ask(
        db,
        "timeline",
        source="connections",
        start=P0,
        end=P0 + 4 * H,
        step=H,
        filters=[["exe", "/usr/sbin/nginx", False]],
    )
    assert response["buckets"] == [[P0 + H, 5000, 500], [P0 + 3 * H, 300, 30]]
    with pytest.raises(AssertionError, match="buckets"):
        _ask(db, "timeline", source="connections", start=P0, end=P0 + 4 * H, step=1)


def test_timeline_peaks(tmp_path):
    db = _db(tmp_path)
    response = _ask(
        db, "timeline", source="connections", start=P0, end=P0 + 4 * H, step=H, peak=10
    )
    assert response["peak"] == 10
    # A rollup is one stretch as long as its period; raw rows are per stretch of 10 s,
    # so the last hour's two windows, 10 s apart, peak at the larger one.
    assert response["buckets"] == [
        [P0, 1000, 10000, pytest.approx(1000 / H), pytest.approx(10000 / H)],
        [P0 + H, 5100, 1500, pytest.approx(5100 / H), pytest.approx(1500 / H)],
        [P0 + 2 * H, 1, 2, pytest.approx(0.1), pytest.approx(0.2)],
        [P0 + 3 * H, 310, 50, pytest.approx(30.0), pytest.approx(3.0)],
    ]
    # A stretch is never shorter than a write window: one of 30 s holds both windows.
    response = _ask(
        db,
        "timeline",
        write_window=30,
        source="connections",
        start=P0 + 3 * H,
        end=P0 + 4 * H,
        step=H,
        peak=10,
    )
    assert response["peak"] == 30 and response["buckets"] == [
        [P0 + 3 * H, 310, 50, pytest.approx(310 / 30), pytest.approx(50 / 30)]
    ]
    # A stretch longer than the bucket says nothing about it.
    with pytest.raises(AssertionError, match="peak"):
        _ask(
            db,
            "timeline",
            source="connections",
            start=P0,
            end=P0 + 4 * H,
            step=H,
            peak=2 * H,
        )


def test_timeline_peaks_of_history_written_with_longer_windows(tmp_path):
    """Rows keep the seconds they cover, so history written with a longer window or
    period than today's does not peak higher than it was.
    """
    db = _db(tmp_path)
    con = sqlite3.connect(db)
    con.execute("UPDATE connections SET seconds = 60")
    con.commit()
    con.close()
    response = _ask(
        db,
        "timeline",
        rollup_period=H // 4,
        source="connections",
        start=P0,
        end=P0 + 4 * H,
        step=H,
        peak=10,
    )
    assert response["buckets"] == [
        [P0, 1000, 10000, pytest.approx(1000 / H), pytest.approx(10000 / H)],
        [P0 + H, 5100, 1500, pytest.approx(5100 / H), pytest.approx(1500 / H)],
        [P0 + 2 * H, 1, 2, pytest.approx(1 / 60), pytest.approx(2 / 60)],
        [P0 + 3 * H, 310, 50, pytest.approx(300 / 60), pytest.approx(30 / 60)],
    ]


def test_describe(tmp_path):
    db = _db(tmp_path)
    sources = _ask(db, "describe")["sources"]
    assert set(sources) == {"connections", "interfaces", "forwarded"}
    connections = sources["connections"]
    assert connections["kind"] == "socket bytes" and connections["split"] == P0 + 2 * H
    assert connections["oldest"] == P0 and connections["newest"] == P0 + 3 * H + 20
    assert ["raddr", "remote address", True] in connections["dimensions"]
    assert ["exe", "executable", False] in connections["dimensions"]
    # The viewer's headings, by the dimension each comes before; a short list has none.
    assert connections["headings"]["pexe"] == "parent"
    assert sources["interfaces"]["headings"] == {}


@pytest.mark.parametrize(
    "request_, error",
    [
        ({"op": "drop"}, "unknown op"),
        ({"op": "aggregate", "source": "executables"}, "unknown source"),
        (
            {
                "op": "aggregate",
                "source": "connections",
                "group_by": "exe; DROP TABLE connections",
            },
            "unknown dimension",
        ),
        (
            {
                "op": "aggregate",
                "source": "connections",
                "filters": [["e.exe", "x", False]],
            },
            "unknown dimension",
        ),
        (
            {
                "op": "aggregate",
                "source": "connections",
                "filters": [["exe", ["x"], False]],
            },
            "filter value",
        ),
        (
            {
                "op": "aggregate",
                "source": "connections",
                "filters": [["exe", "x", "yes"]],
            },
            "exclude",
        ),
        (
            {
                "op": "aggregate",
                "source": "connections",
                "filters": [["exe", "x", False]] * 17,
            },
            "at most",
        ),
        (
            {"op": "aggregate", "source": "connections", "start": 10, "end": 5},
            "after start",
        ),
        ({"op": "aggregate", "source": "connections", "limit": 0}, "limit"),
        ({"op": "aggregate", "source": "connections", "start": "yesterday"}, "integer"),
    ],
)
def test_bad_requests(tmp_path, request_, error):
    db = _db(tmp_path)
    response = query_server.QueryServer(db).answer(request_)
    assert not response["ok"] and error in response["error"]
    con = sqlite3.connect(db)
    assert con.execute("SELECT count(*) FROM connections").fetchone()[0] == 4
    con.close()


def test_database_missing_or_other_version(tmp_path):
    response = query_server.QueryServer(tmp_path / "tracct.db").answer(
        {"op": "describe"}
    )
    assert not response["ok"] and "no database" in response["error"]
    db = _db(tmp_path)
    con = sqlite3.connect(db)
    con.execute("PRAGMA user_version = 5")
    con.commit()
    con.close()
    response = query_server.QueryServer(db).answer({"op": "describe"})
    assert not response["ok"] and "schema version 5" in response["error"]


def test_slow_query_is_interrupted(tmp_path, monkeypatch):
    db = _db(tmp_path)
    con = sqlite3.connect(db)
    con.executemany(
        "INSERT INTO connections VALUES (?, 1, 1, 1, 1, 2, 0, 1000, 2, 6, 50000, 443, 1, 2, 1, ?, 1, 10)",
        [(P0 + 3 * H + i % 3000, HOST_ID) for i in range(20000)],
    )
    con.commit()
    con.close()
    monkeypatch.setattr(query_server, "QUERY_TIMEOUT_SECONDS", 0)
    response = query_server.QueryServer(db).answer(
        {"op": "aggregate", "source": "connections", "group_by": "raddr"}
    )
    assert not response["ok"] and "longer than" in response["error"]


def _serve(tmp_path, db, idle_exit=None):
    listener, activated = query_server.listening_socket(tmp_path / "query.sock")
    assert not activated
    thread = threading.Thread(
        target=query_server.QueryServer(db).serve,
        args=(listener, idle_exit),
        daemon=True,
    )
    thread.start()
    return listener, thread


def test_socket_round_trip_and_idle_exit(tmp_path):
    db = _db(tmp_path)
    listener, thread = _serve(tmp_path, db, idle_exit=1)
    try:
        client = QueryClient(tmp_path / "query.sock", timeout=5)
        assert (
            client.request("describe")["sources"]["connections"]["split"] == P0 + 2 * H
        )
        rows = client.request(
            "aggregate",
            source="connections",
            group_by="exe",
            start=P0,
            end=P0 + 4 * H,
            limit=1,
        )
        assert len(rows["rows"]) == 1 and rows["truncated"] and rows["groups"] == 2
        with pytest.raises(QueryError, match="unknown source"):
            client.request("aggregate", source="nope")
        # An error leaves the connection usable.
        assert client.request("describe")["ok"]
        # Still busy while a viewer is connected.
        time.sleep(2.5)
        assert thread.is_alive()
        client.close()
        thread.join(timeout=5)
        assert not thread.is_alive()
    finally:
        listener.close()


def test_client_cap_and_bad_messages(tmp_path, monkeypatch):
    db = _db(tmp_path)
    monkeypatch.setattr(query_server, "MAX_CLIENTS", 1)
    listener, _ = _serve(tmp_path, db)
    try:
        first = QueryClient(tmp_path / "query.sock", timeout=5)
        assert first.request("describe")["ok"]
        second = QueryClient(tmp_path / "query.sock", timeout=5)
        with pytest.raises(QueryError, match="already serves"):
            second.request("describe")
        second.close()
        first.close()
        time.sleep(0.2)
        # A slot is free again; a message over the request bound is answered and closed.
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        raw.settimeout(5)
        raw.connect(str(tmp_path / "query.sock"))
        raw.sendall(struct.pack(">I", query_server.MAX_REQUEST_BYTES + 1))
        response = recv_message(raw, 1 << 20)
        assert (
            response is not None
            and not response["ok"]
            and "exceeds" in response["error"]
        )
        raw.close()
    finally:
        listener.close()
