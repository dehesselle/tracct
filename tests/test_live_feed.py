# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for tracct.live_feed (no root needed)."""

import os
import socket
import tempfile
import time

import pytest

# Force RUN_DIR to a tempdir before importing live_feed so the socket lands somewhere we can write.
_TMP_RUN = tempfile.mkdtemp(prefix="tracct-test-")
os.environ["RUNTIME_DIRECTORY"] = _TMP_RUN

from tracct import live_feed  # noqa: E402

# Patch the socket path to live under our temp dir
live_feed.EVENTS_SOCKET_PATH = type(live_feed.EVENTS_SOCKET_PATH)(os.path.join(_TMP_RUN, "events.sock"))


def test_publish_and_subscribe():
    pub = live_feed.LiveFeedPublisher(group=None)
    pub.start()
    assert pub._sock is not None, "publisher should have started"
    try:
        sub = live_feed.LiveFeedSubscriber(timeout=2.0)
        sub.connect()
        try:
            # give accept thread a tick to register the subscriber
            time.sleep(0.05)
            pub.publish({"name": "curl", "exe": "/usr/bin/curl", "send": 42, "recv": 0})
            event = next(sub)
            assert event["name"] == "curl"
            assert event["exe"] == "/usr/bin/curl"
            assert event["send"] == 42
        finally:
            sub.close()
    finally:
        pub.stop()


def test_slow_subscriber_dropped(monkeypatch):
    monkeypatch.setattr(live_feed, "MAX_PENDING_BYTES", 64 * 1024)
    pub = live_feed.LiveFeedPublisher(group=None)
    pub.start()
    try:
        # Connect but never read
        sub_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sub_sock.connect(str(live_feed.EVENTS_SOCKET_PATH))
        time.sleep(0.05)
        # Flood past the kernel buffer and the backlog limit; the subscriber gets dropped.
        started = time.monotonic()
        for i in range(2000):
            pub.publish({"i": i, "blob": "x" * 1024})
        assert time.monotonic() - started < 2
        assert not pub._subscribers
        assert pub.dropped == 1
        # Publisher should still be functional
        pub.publish({"final": True})
        sub_sock.close()
    finally:
        pub.stop()


def test_burst_survives_slow_reader():
    pub = live_feed.LiveFeedPublisher(group=None)
    pub.start()
    try:
        sub = live_feed.LiveFeedSubscriber(timeout=2.0)
        sub.connect()
        try:
            time.sleep(0.05)
            # ~5 MB in one burst, far beyond the kernel socket buffer, while the reader is idle
            pub.publish_many([{"i": i, "blob": "x" * 1024} for i in range(5000)])
            time.sleep(0.2)
            assert len(pub._subscribers) == 1
            assert pub._subscribers[0].out, "burst should leave a backlog in userspace"
            # the writer thread delivers the whole backlog without further publish calls
            received = [next(sub) for _ in range(5000)]
            assert [e["i"] for e in received] == list(range(5000))
            assert all(e["blob"] == "x" * 1024 for e in received)
            assert pub.dropped == 0
        finally:
            sub.close()
    finally:
        pub.stop()


def test_closed_subscriber_removed():
    pub = live_feed.LiveFeedPublisher(group=None)
    pub.start()
    try:
        sub_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sub_sock.connect(str(live_feed.EVENTS_SOCKET_PATH))
        time.sleep(0.05)
        sub_sock.close()
        pub.publish({"name": "curl"})
        deadline = time.monotonic() + 2
        while pub._subscribers and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not pub._subscribers
        # a reader that went away is not counted as one that fell behind
        assert pub.dropped == 0
    finally:
        pub.stop()


def test_subscriber_count_is_bounded(monkeypatch):
    monkeypatch.setattr(live_feed, "MAX_SUBSCRIBERS", 2)
    pub = live_feed.LiveFeedPublisher(group=None)
    pub.start()
    clients = []
    try:
        for _ in range(3):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(live_feed.EVENTS_SOCKET_PATH))
            clients.append(client)
        time.sleep(0.05)
        assert len(pub._subscribers) == 2
    finally:
        for client in clients:
            client.close()
        pub.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
