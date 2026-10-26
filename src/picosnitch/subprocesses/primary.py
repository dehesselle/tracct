# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import logging
import multiprocessing
import multiprocessing.connection
import os
import pickle
import signal
import sys
import threading

from picosnitch.config import Config
from picosnitch.live_feed import MAX_PENDING_BYTES, LiveFeedPublisher
from picosnitch.utils import sanitize_log_line


def run_primary(
    config: Config,
    event_pipes: tuple,
    secondary_pipe: multiprocessing.connection.Connection,
    q_error: multiprocessing.Queue[str],
    q_in: multiprocessing.Queue[bytes],
    _q_out: multiprocessing.Queue,
) -> None:
    """first to receive connection data from monitor, more responsive than secondary, publishes the live feed and logs errors"""
    try:
        os.nice(-20)
    except Exception:
        pass
    # init variables for loop
    parent_process = multiprocessing.parent_process()
    assert parent_process is not None
    live_feed = LiveFeedPublisher(group=config.viewer.group)
    live_feed.start()
    live_feed_dropped = 0
    processes_to_send = []

    # init signal handlers
    shutdown_event = threading.Event()

    def _drain_errors(q_error: multiprocessing.Queue) -> None:
        # to stderr (the journal under systemd); the messages carry comm, cmdline and domain strings
        while not q_error.empty():
            logging.getLogger("picosnitch.error").warning(sanitize_log_line(q_error.get()))

    def _exit(q_error: multiprocessing.Queue, event_pipes: tuple) -> None:
        _drain_errors(q_error)
        live_feed.stop()
        for event_pipe in event_pipes:
            event_pipe.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, lambda *args: shutdown_event.set())
    signal.signal(signal.SIGINT, lambda *args: shutdown_event.set())

    # init thread to receive new connection data over pipe
    def event_pipe_thread(event_pipes: tuple, pipe_data: list, listen: threading.Event, ready: threading.Event) -> None:
        while True:
            listen.wait()
            new_processes = pipe_data[0]
            while listen.is_set():
                # block on poll's own timeout; sleeping between polls capped the pipeline at one chunk per sleep
                if any(event_pipe.poll(0.05) for event_pipe in event_pipes):
                    for event_pipe in event_pipes:
                        while event_pipe.poll():
                            # each message is a pickled batch, so extend rather than append
                            new_processes.extend(pickle.loads(event_pipe.recv_bytes()))
            ready.set()

    listen, ready = threading.Event(), threading.Event()
    pipe_data = [[]]
    thread = threading.Thread(
        target=event_pipe_thread,
        args=(
            event_pipes,
            pipe_data,
            listen,
            ready,
        ),
        daemon=True,
    )
    thread.start()
    listen.set()
    # main loop
    while not shutdown_event.is_set():
        if not parent_process.is_alive():
            q_error.put("picosnitch has stopped")
            _exit(q_error, event_pipes)
        try:
            # check for errors
            _drain_errors(q_error)
            # get list of new processes and connections since last update
            listen.clear()
            if not ready.wait(timeout=300):
                q_error.put("thread timeout error for primary subprocess")
                _exit(q_error, event_pipes)
            new_processes = pipe_data[0]
            pipe_data[0] = []
            ready.clear()
            listen.set()
            # serializing with no subscriber backs the pipeline up at high connection cardinality;
            # with one, the batch is serialized once and the publisher's writer thread delivers it
            if live_feed.has_subscribers():
                try:
                    live_feed.publish_many(new_processes)
                except Exception:
                    pass
            if live_feed.dropped > live_feed_dropped:
                q_error.put(f"live feed: dropped {live_feed.dropped - live_feed_dropped} subscriber(s) that fell more than {MAX_PENDING_BYTES // (1024 * 1024)} MiB behind")
                live_feed_dropped = live_feed.dropped
            processes_to_send += new_processes
            while not q_in.empty():
                msg: dict = pickle.loads(q_in.get())
                if msg["type"] == "ready":
                    # one message for the whole batch: a send per event blocks until the secondary receives each
                    secondary_pipe.send_bytes(pickle.dumps(processes_to_send))
                    processes_to_send = []
                    break
        except Exception as e:
            q_error.put("primary subprocess %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
    # clean exit after shutdown_event was set (by signal handler)
    _exit(q_error, event_pipes)
