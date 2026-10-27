# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Tests for the reverse DNS workers, with a fake resolver. No root/BPF, no network."""

import threading
import time

import tracct.reverse_dns as reverse_dns


def _wait_for(lookup, ip: str) -> str:
    deadline = time.monotonic() + 5
    while (name := lookup(ip)) == "" and time.monotonic() < deadline:
        time.sleep(0.01)
    return name


def test_lookup_never_waits_for_the_resolver():
    release = threading.Event()
    asked: list[str] = []

    def slow_resolver(ip: str) -> str:
        asked.append(ip)
        release.wait(5)
        return "com.example"

    dns = reverse_dns.ReverseDns(slow_resolver, workers=1)
    started = time.monotonic()
    # unknown, then pending: neither waits, and the address is asked for once
    assert dns.lookup("192.0.2.1") == ""
    assert dns.lookup("192.0.2.1") == ""
    assert time.monotonic() - started < 1
    release.set()
    assert _wait_for(dns.lookup, "192.0.2.1") == "com.example"
    assert asked == ["192.0.2.1"]
    dns.close(5)


def test_failed_lookup_answers_with_the_address():
    def broken_resolver(ip: str) -> str:
        raise OSError("resolver down")

    dns = reverse_dns.ReverseDns(broken_resolver, workers=1)
    dns.lookup("192.0.2.2")
    assert _wait_for(dns.lookup, "192.0.2.2") == "192.0.2.2"
    dns.close(5)


def test_full_queue_skips_and_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(reverse_dns, "PENDING_MAX", 2)
    monkeypatch.setattr(reverse_dns, "CACHE_MAX", 2)
    release = threading.Event()

    def held_resolver(ip: str) -> str:
        release.wait(5)
        return f"name.{ip}"

    dns = reverse_dns.ReverseDns(held_resolver, workers=1)
    dns.lookup("192.0.2.1")
    # wait for the worker to take the first address, so the queue holds the next two
    deadline = time.monotonic() + 5
    while dns._queue.qsize() and time.monotonic() < deadline:
        time.sleep(0.01)
    for ip in ("192.0.2.2", "192.0.2.3", "192.0.2.4"):
        dns.lookup(ip)
    # the fourth did not fit and is not pending, so a later lookup can queue it again
    assert dns._pending == {"192.0.2.1", "192.0.2.2", "192.0.2.3"}
    release.set()
    assert _wait_for(dns.lookup, "192.0.2.3") == "name.192.0.2.3"
    deadline = time.monotonic() + 5
    while dns._pending and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(dns._names) == 2
    dns.close(5)


def test_resolve_reverses_names(monkeypatch):
    monkeypatch.setattr(reverse_dns.socket, "getnameinfo", lambda addr, flags: ("www.example.com", "0"))
    assert reverse_dns.resolve("192.0.2.1") == "com.example.www"
    # getnameinfo answers with the address itself when there is no PTR record
    monkeypatch.setattr(reverse_dns.socket, "getnameinfo", lambda addr, flags: (addr[0], "0"))
    assert reverse_dns.resolve("192.0.2.1") == "192.0.2.1"
