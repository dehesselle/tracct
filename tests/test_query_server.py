"""Tests for the query server: routing between raw rows and rollups, dimensions, filters,
request validation and the socket. No root needed."""

import socket
import sqlite3
import struct
import threading
import time

import pytest

from picosnitch import query_server
from picosnitch.constants import DB_VERSION, INDEXES, SENTINELS, TABLES
from picosnitch.query import QueryClient, QueryError, recv_message

H = 3600
P0 = 100 * H
HOST, VPN = 4026531840, 4026532500
EPHEMERAL = 32768


def _db(tmp_path):
    """four hours of history: the first two only as rollups (the second one's raw rows partly
    purged), the third rolled up and still raw, the fourth raw only. rows that must not be read
    (the purged period's raw remainder, the third period's rollup) carry large sums"""
    db = tmp_path / "picosnitch.db"
    con = sqlite3.connect(db)
    for table, schema in TABLES:
        con.execute(f"CREATE TABLE {table} ({schema}) STRICT")
    for statement in SENTINELS + INDEXES:
        con.execute(statement)
    con.execute("INSERT INTO executables VALUES (1, '/usr/bin/curl', 'curl', 'curl example.com'), (2, '/usr/bin/bash', 'bash', 'bash'), (3, '/usr/sbin/nginx', 'nginx', 'nginx')")
    con.execute("INSERT INTO units VALUES (1, 'nginx.service')")
    con.execute("INSERT INTO addresses VALUES (1, '10.0.0.2'), (2, '93.184.215.14'), (3, '100.64.0.2'), (4, '198.51.100.7')")
    con.execute("INSERT INTO domains VALUES (1, 'com.example')")
    con.execute(f"INSERT INTO interfaces VALUES (1, {HOST}, 'eth0', ''), (2, {HOST}, 'tailscale0', 'tun'), (3, {VPN}, 'tun0', 'tun')")
    con.execute(f"INSERT INTO netns VALUES ({HOST}, 'host')")
    # contime, send, recv, events, exe, pexe, unit, uid, family, protocol, lport, rport, laddr, raddr, domain, netns, iface
    con.executemany(
        "INSERT INTO connections VALUES (?, ?, ?, 1, ?, 2, ?, 1000, 2, 6, ?, ?, 1, ?, ?, ?, ?)",
        [
            (P0 + H + 100, 100000, 100000, 1, 0, 50000, 443, 2, 1, HOST, 1),  # purged period: from the rollup
            (P0 + 2 * H + 10, 1, 2, 1, 0, 50001, 443, 2, 1, HOST, 1),
            (P0 + 3 * H + 10, 10, 20, 1, 0, 50002, 443, 2, 1, HOST, 1),
            (P0 + 3 * H + 20, 300, 30, 3, 1, 80, 50003, 3, 0, VPN, 3),
        ],
    )
    # period, exe, pexe, unit, uid, family, protocol, lport, rport, domain, netns, iface, send, recv, events, rows
    con.executemany(
        "INSERT INTO connections_rollup VALUES (?, ?, 2, ?, 1000, 2, 6, ?, ?, ?, ?, 1, ?, ?, 1, 1)",
        [
            (P0, 1, 0, 0, 443, 1, HOST, 1000, 10000),
            (P0 + H, 1, 0, 0, 443, 1, HOST, 100, 1000),
            (P0 + H, 3, 1, 80, 0, 0, HOST, 5000, 500),
            (P0 + 2 * H, 1, 0, 0, 443, 1, HOST, 999999, 999999),  # still raw: from the raw rows
        ],
    )
    con.executemany("INSERT INTO interface_traffic VALUES (?, ?, ?, ?)", [(P0 + H + 100, 1, 100000, 100000), (P0 + 2 * H + 10, 1, 700, 70), (P0 + 3 * H + 10, 3, 40, 4)])
    con.executemany("INSERT INTO interface_traffic_rollup VALUES (?, ?, ?, ?)", [(P0 + H, 1, 6000, 600), (P0 + 2 * H, 1, 999999, 999999)])
    con.execute(f"INSERT INTO forwarded VALUES ({P0 + 3 * H + 10}, {HOST}, 6, 3, 40000, 4, 443, 0, 2000, 100000, 20, 80)")
    con.execute(f"INSERT INTO forwarded_rollup VALUES ({P0 + H}, {HOST}, 6, 3, 443, 0, 50, 5000, 1, 4, 1)")
    con.execute(f"INSERT INTO meta VALUES ('rollup_watermark', {P0 + 3 * H})")
    con.execute(f"PRAGMA user_version = {DB_VERSION}")
    con.commit()
    con.close()
    return db


def _ask(db, op, **request):
    response = query_server.QueryServer(db, ephemeral=EPHEMERAL).answer({"op": op, **request})
    assert response["ok"], response.get("error")
    return response


def _aggregate(db, group_by, start=P0, end=P0 + 4 * H, **request):
    response = _ask(db, "aggregate", source=request.pop("source", "connections"), group_by=group_by, start=start, end=end, **request)
    return response, {value: (a, b) for value, a, b in response["rows"]}


def test_raw_rows_take_over_from_rollups(tmp_path):
    db = _db(tmp_path)
    response, rows = _aggregate(db, "exe")
    # the purged period's remainder and the rolled-up period that is still raw are not read twice
    assert response["split"] == P0 + 2 * H
    assert rows == {"/usr/bin/curl": (1000 + 100 + 1 + 10, 10000 + 1000 + 2 + 20), "/usr/sbin/nginx": (5000 + 300, 500 + 30)}
    assert [row[0] for row in response["rows"]] == ["/usr/bin/curl", "/usr/sbin/nginx"]
    assert response["totals"] == [1111 + 5300, 11022 + 530]
    assert response["groups"] == 2 and not response["truncated"] and not response["clipped"]


def test_ports_group_like_the_rollups_keep_them(tmp_path):
    db = _db(tmp_path)
    # reaching into the rollups, ephemeral ports in raw rows become 0 as they are there
    _, rows = _aggregate(db, "rport")
    assert rows == {443: (1111, 11022), 0: (5300, 530)}
    # inside the raw rows they stay exact
    _, rows = _aggregate(db, "rport", start=P0 + 2 * H)
    assert rows == {443: (11, 22), 50003: (300, 30)}


def test_raw_only_dimension_clips_to_the_raw_rows(tmp_path):
    db = _db(tmp_path)
    response, rows = _aggregate(db, "raddr")
    assert response["clipped"] and response["start"] == P0 + 2 * H
    assert rows == {"93.184.215.14": (11, 22), "100.64.0.2": (300, 30)}
    # a filter on one clips too
    response, rows = _aggregate(db, "exe", filters=[["raddr", "100.64.0.2", False]])
    assert response["clipped"] and rows == {"/usr/sbin/nginx": (300, 30)}


def test_filters_include_and_exclude(tmp_path):
    db = _db(tmp_path)
    _, rows = _aggregate(db, "exe", filters=[["exe", "/usr/sbin/nginx", True]])
    assert list(rows) == ["/usr/bin/curl"]
    _, rows = _aggregate(db, "unit", filters=[["name", "nginx", False]])
    assert rows == {"nginx.service": (5300, 530)}
    # unnamed namespaces go by inode, and a filter takes the value as it came back
    _, rows = _aggregate(db, "netns", start=P0 + 2 * H)
    assert rows == {"host": (11, 22), str(VPN): (300, 30)}
    _, rows = _aggregate(db, "exe", start=P0 + 2 * H, filters=[["netns", str(VPN), False]])
    assert list(rows) == ["/usr/sbin/nginx"]


def test_interfaces_and_layers(tmp_path):
    db = _db(tmp_path)
    _, rows = _aggregate(db, "iface", start=P0 + 2 * H)
    assert rows == {"host/eth0": (11, 22), f"{VPN}/tun0": (300, 30)}
    _, rows = _aggregate(db, "layer", start=P0 + 2 * H)
    assert rows == {"outer/direct": (11, 22), "inner": (300, 30)}
    # interface counters: values are (tx, rx)
    _, rows = _aggregate(db, "iface", source="interfaces")
    assert rows == {"host/eth0": (600 + 70, 6000 + 700), f"{VPN}/tun0": (4, 40)}
    _, rows = _aggregate(db, "kind", source="interfaces")
    assert rows == {"": (670, 6700), "tun": (4, 40)}


def test_forwarded(tmp_path):
    db = _db(tmp_path)
    _, rows = _aggregate(db, "src", source="forwarded")
    assert rows == {"100.64.0.2": (2050, 105000)}
    response, rows = _aggregate(db, "dst", source="forwarded")
    assert response["clipped"] and rows == {"198.51.100.7": (2000, 100000)}


def test_timeline(tmp_path):
    db = _db(tmp_path)
    response = _ask(db, "timeline", source="connections", start=P0, end=P0 + 4 * H, step=H)
    assert response["buckets"] == [[P0, 1000, 10000], [P0 + H, 5100, 1500], [P0 + 2 * H, 1, 2], [P0 + 3 * H, 310, 50]]
    # a filter on one row's value gives that row's timeline
    response = _ask(db, "timeline", source="connections", start=P0, end=P0 + 4 * H, step=H, filters=[["exe", "/usr/sbin/nginx", False]])
    assert response["buckets"] == [[P0 + H, 5000, 500], [P0 + 3 * H, 300, 30]]
    with pytest.raises(AssertionError, match="buckets"):
        _ask(db, "timeline", source="connections", start=P0, end=P0 + 4 * H, step=1)


def test_describe(tmp_path):
    db = _db(tmp_path)
    sources = _ask(db, "describe")["sources"]
    assert set(sources) == {"connections", "interfaces", "forwarded"}
    connections = sources["connections"]
    assert connections["kind"] == "socket bytes" and connections["split"] == P0 + 2 * H
    assert connections["oldest"] == P0 and connections["newest"] == P0 + 3 * H + 20
    assert ["raddr", "remote address", True] in connections["dimensions"]
    assert ["exe", "executable", False] in connections["dimensions"]


@pytest.mark.parametrize(
    "request_, error",
    [
        ({"op": "drop"}, "unknown op"),
        ({"op": "aggregate", "source": "executables"}, "unknown source"),
        ({"op": "aggregate", "source": "connections", "group_by": "exe; DROP TABLE connections"}, "unknown dimension"),
        ({"op": "aggregate", "source": "connections", "filters": [["e.exe", "x", False]]}, "unknown dimension"),
        ({"op": "aggregate", "source": "connections", "filters": [["exe", ["x"], False]]}, "filter value"),
        ({"op": "aggregate", "source": "connections", "filters": [["exe", "x", "yes"]]}, "exclude"),
        ({"op": "aggregate", "source": "connections", "filters": [["exe", "x", False]] * 17}, "at most"),
        ({"op": "aggregate", "source": "connections", "start": 10, "end": 5}, "after start"),
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
    response = query_server.QueryServer(tmp_path / "picosnitch.db").answer({"op": "describe"})
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
    con.executemany("INSERT INTO connections VALUES (?, 1, 1, 1, 1, 2, 0, 1000, 2, 6, 50000, 443, 1, 2, 1, ?, 1)", [(P0 + 3 * H + i % 3000, HOST) for i in range(20000)])
    con.commit()
    con.close()
    monkeypatch.setattr(query_server, "QUERY_TIMEOUT_SECONDS", 0)
    response = query_server.QueryServer(db).answer({"op": "aggregate", "source": "connections", "group_by": "raddr"})
    assert not response["ok"] and "longer than" in response["error"]


def _serve(tmp_path, db, idle_exit=None):
    listener, activated = query_server.listening_socket(tmp_path / "query.sock")
    assert not activated
    thread = threading.Thread(target=query_server.QueryServer(db).serve, args=(listener, idle_exit), daemon=True)
    thread.start()
    return listener, thread


def test_socket_round_trip_and_idle_exit(tmp_path):
    db = _db(tmp_path)
    listener, thread = _serve(tmp_path, db, idle_exit=1)
    try:
        client = QueryClient(tmp_path / "query.sock", timeout=5)
        assert client.request("describe")["sources"]["connections"]["split"] == P0 + 2 * H
        rows = client.request("aggregate", source="connections", group_by="exe", start=P0, end=P0 + 4 * H, limit=1)
        assert len(rows["rows"]) == 1 and rows["truncated"] and rows["groups"] == 2
        with pytest.raises(QueryError, match="unknown source"):
            client.request("aggregate", source="nope")
        # an error leaves the connection usable
        assert client.request("describe")["ok"]
        # still busy while a viewer is connected
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
        # a slot is free again; a message over the request bound is answered and closed
        raw = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        raw.settimeout(5)
        raw.connect(str(tmp_path / "query.sock"))
        raw.sendall(struct.pack(">I", query_server.MAX_REQUEST_BYTES + 1))
        response = recv_message(raw, 1 << 20)
        assert response is not None and not response["ok"] and "exceeds" in response["error"]
        raw.close()
    finally:
        listener.close()
