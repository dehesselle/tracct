# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import multiprocessing
import multiprocessing.connection
import os
import pickle
import signal
import sys
import threading
import time

from picosnitch.config import Config
from picosnitch.live_feed import MAX_PENDING_BYTES, LiveFeedPublisher
from picosnitch.types import BpfEvent, State
from picosnitch.utils import flush_logs, save_state


def handle_new_processes(state: State, new_processes: list[BpfEvent]) -> None:
    """iterate over the list of process/connection data to update the state dictionary and log new entries to exe.log"""
    datetime_now = time.strftime("%Y-%m-%d %H:%M:%S")
    for proc in new_processes:
        levels = (
            (proc["name"], proc["exe"], state["Names"], state["Executables"], ""),
            (proc["pname"], proc["pexe"], state["Parent Names"], state["Parent Executables"], " (parent)"),
            (proc["gpname"], proc["gpexe"], state["Grandparent Names"], state["Grandparent Executables"], " (grandparent)"),
        )
        for proc_name, proc_exe, state_names, state_executables, parent in levels:
            # skip levels with no real process (e.g. grandparent of an init child
            # is the kernel/swapper, daemons whose parent walk hits PID 0, or
            # short-lived processes where /proc was already gone). these would
            # otherwise pollute state with empty entries and log blank lines.
            if not proc_name and not proc_exe:
                continue
            notification = []
            if proc_name in state_names:
                if proc_exe not in state_names[proc_name]:
                    state_names[proc_name].append(proc_exe)
            else:
                state_names[proc_name] = [proc_exe]
                notification.append("name")
            if proc_exe in state_executables:
                if proc_name not in state_executables[proc_exe]:
                    state_executables[proc_exe].append(proc_name)
            else:
                state_executables[proc_exe] = [proc_name]
                notification.append("exe")
                if proc_exe not in state["SHA256"]:
                    state["SHA256"][proc_exe] = {}
            if notification:
                state["Exe Log"].append(f"{datetime_now} {proc_name:<16.16} {proc_exe} (new {', '.join(notification)}){parent}")


def run_primary(
    config: Config,
    state: State,
    event_pipes: tuple,
    secondary_pipe: multiprocessing.connection.Connection,
    q_error: multiprocessing.Queue[str],
    q_in: multiprocessing.Queue[bytes],
    _q_out: multiprocessing.Queue,
) -> None:
    """first to receive connection data from monitor, more responsive than secondary, publishes the live feed and writes exe.log, error.log, and state.json"""
    try:
        os.nice(-20)
    except Exception:
        pass
    # init variables for loop
    parent_process = multiprocessing.parent_process()
    assert parent_process is not None
    live_feed = LiveFeedPublisher(group=config.data.group)
    live_feed.start()
    live_feed_dropped = 0
    state_record = pickle.dumps(
        [state["Executables"], state["Names"], state["Parent Executables"], state["Parent Names"], state["Grandparent Executables"], state["Grandparent Names"], state["SHA256"]]
    )
    last_write = 0
    write_record = False
    processes_to_send = []

    # init signal handlers
    shutdown_event = threading.Event()

    def _drain_errors(state: State, q_error: multiprocessing.Queue) -> None:
        while not q_error.empty():
            state["Error Log"].append(time.strftime("%Y-%m-%d %H:%M:%S") + " " + q_error.get())

    def save_state_and_exit(state: State, q_error: multiprocessing.Queue, event_pipes: tuple) -> None:
        _drain_errors(state, q_error)
        save_state(state, config=config)
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
            save_state_and_exit(state, q_error, event_pipes)
        try:
            # check for errors
            _drain_errors(state, q_error)
            # get list of new processes and connections since last update
            listen.clear()
            if not ready.wait(timeout=300):
                q_error.put("thread timeout error for primary subprocess")
                save_state_and_exit(state, q_error, event_pipes)
            new_processes = pipe_data[0]
            pipe_data[0] = []
            ready.clear()
            listen.set()
            # process the list and update state, send new process/connection data to secondary subprocess if ready
            handle_new_processes(state, new_processes)
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
                elif msg["type"] == "sha256":
                    # value is the first-seen time of this hash for this executable
                    first_seen = time.strftime("%Y-%m-%d %H:%M:%S")
                    if msg["exe"] in state["SHA256"]:
                        if msg["sha256"] not in state["SHA256"][msg["exe"]]:
                            state["SHA256"][msg["exe"]][msg["sha256"]] = first_seen
                            state["Exe Log"].append(f"{first_seen} {msg['sha256']:<16.16} {msg['exe']} (new hash)")
                    else:
                        state["SHA256"][msg["exe"]] = {msg["sha256"]: first_seen}
            # flush logs every iteration (cheap appends), write state.json only when changed or every 30s
            flush_logs(state, config)
            # monotonic interval: a wall-clock jump must not stall state.json persistence
            if time.monotonic() - last_write > 30:
                new_record = pickle.dumps(
                    [state["Executables"], state["Names"], state["Parent Executables"], state["Parent Names"], state["Grandparent Executables"], state["Grandparent Names"], state["SHA256"]]
                )
                if new_record != state_record:
                    state_record = new_record
                    write_record = True
                if write_record:
                    save_state(state, write_record=True, config=config)
                    write_record = False
                last_write = time.monotonic()
        except Exception as e:
            q_error.put("primary subprocess %s%s on line %s" % (type(e).__name__, str(e.args), e.__traceback__.tb_lineno if e.__traceback__ else "?"))
    # clean exit after shutdown_event was set (by signal handler)
    save_state_and_exit(state, q_error, event_pipes)
