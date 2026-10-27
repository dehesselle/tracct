# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import logging
import signal
import threading
import time

from picosnitch.config import Config
from picosnitch.live_feed import MAX_PENDING_BYTES, LiveFeedPublisher
from picosnitch.monitor import run_monitor
from picosnitch.types import BpfEvent
from picosnitch.utils import DropOldestQueue, log_error, sd_notify
from picosnitch.writer import run_writer

# hand-off bounds, in events; the writer sums what it takes off its queue right away, so its
# queue only fills while it writes or purges
WRITER_QUEUE_EVENTS = 262144
FEED_QUEUE_EVENTS = 131072


def run_feed(live_feed: LiveFeedPublisher, batches: DropOldestQueue[BpfEvent], stop: threading.Event) -> None:
    """the live feed thread: serializes batches for the viewers, off the reader's path"""
    reported = 0
    while not stop.is_set():
        for batch in batches.get_all(timeout=0.5):
            try:
                live_feed.publish_many(batch)
            except Exception:
                pass
        if live_feed.dropped > reported:
            log_error(f"live feed: dropped {live_feed.dropped - reported} subscriber(s) that fell more than {MAX_PENDING_BYTES // (1024 * 1024)} MiB behind")
            reported = live_feed.dropped


def run_main_loop(config: Config) -> int:
    """runs the daemon: a reader thread for the BPF program, a writer thread for the database and
    a thread for the live feed, supervised from the main thread"""
    live_feed = LiveFeedPublisher(group=config.viewer.group)
    live_feed.start()
    to_writer: DropOldestQueue[BpfEvent] = DropOldestQueue(WRITER_QUEUE_EVENTS)
    to_feed: DropOldestQueue[BpfEvent] = DropOldestQueue(FEED_QUEUE_EVENTS)

    def publish(batch: list[BpfEvent]) -> None:
        to_writer.put(batch)
        # serializing with no subscriber backs the reader up at high connection cardinality
        if live_feed.has_subscribers():
            to_feed.put(batch)

    reader_stop, writer_stop, feed_stop = threading.Event(), threading.Event(), threading.Event()
    reattach, ready = threading.Event(), threading.Event()
    reader = threading.Thread(target=run_monitor, args=(config, publish, reader_stop, reattach, ready), name="reader", daemon=True)
    writer = threading.Thread(target=run_writer, args=(config, to_writer, writer_stop), name="writer", daemon=True)
    feed = threading.Thread(target=run_feed, args=(live_feed, to_feed, feed_stop), name="feed", daemon=True)
    threads = [reader, writer, feed]
    for thread in threads:
        thread.start()
    shutdown_event = threading.Event()
    resume_event = threading.Event()

    def _request_shutdown(signum, frame):
        # also wake the resume_event.wait() below so stop/restart tears down promptly
        # instead of after the 5s poll timeout (the loop breaks on shutdown before resuming)
        shutdown_event.set()
        resume_event.set()

    signal.signal(signal.SIGINT, _request_shutdown)
    signal.signal(signal.SIGTERM, _request_shutdown)
    signal.signal(signal.SIGUSR1, lambda signum, frame: resume_event.set())
    # the reader sets ready once its probes are attached; bounded so a stall cannot hang startup
    deadline = time.monotonic() + 30
    while not ready.wait(timeout=0.5) and reader.is_alive() and time.monotonic() < deadline and not shutdown_event.is_set():
        pass
    if reader.is_alive():
        sd_notify("READY=1")
    # watch the threads; detect a real suspend/resume by the gap between CLOCK_BOOTTIME (counts
    # time asleep) and CLOCK_MONOTONIC (does not). a plain wall-clock gap can also come from cpu
    # starvation or SIGSTOP, and re-attaching then would only lose the traffic in between
    mono_last = time.monotonic()
    boot_last = time.clock_gettime(time.CLOCK_BOOTTIME)
    dropped_reported = {"writer": 0, "live feed": 0}
    while not shutdown_event.is_set():
        if not all(thread.is_alive() for thread in threads):
            dead = " ".join(thread.name for thread in threads if not thread.is_alive())
            logging.error(f"picosnitch thread died, exiting for the service manager to restart ({dead})")
            break
        resume_event.wait(timeout=5)
        if shutdown_event.is_set():
            break
        for name, hand_off in (("writer", to_writer), ("live feed", to_feed)):
            if hand_off.dropped > dropped_reported[name]:
                log_error(f"{name} queue full: dropped {hand_off.dropped - dropped_reported[name]} event(s) (total {hand_off.dropped}), it is not keeping up with the reader")
                dropped_reported[name] = hand_off.dropped
        mono_now = time.monotonic()
        boot_now = time.clock_gettime(time.CLOCK_BOOTTIME)
        suspended_for = (boot_now - boot_last) - (mono_now - mono_last)
        if resume_event.is_set() or suspended_for > 5:
            resume_event.clear()
            logging.info("re-attaching the BPF program after resuming from suspend")
            reattach.set()
        mono_last, boot_last = mono_now, boot_now
    # stop in pipeline order: the reader hands over what the kernel still holds, the writer
    # writes everything it was handed
    reader_stop.set()
    reader.join(timeout=10)
    writer_stop.set()
    writer.join(timeout=60)
    feed_stop.set()
    feed.join(timeout=5)
    live_feed.stop()
    # a clean exit only on signal; otherwise a non-zero exit lets the service manager restart us
    return 0 if shutdown_event.is_set() else 1
