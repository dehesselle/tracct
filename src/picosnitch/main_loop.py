# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
from __future__ import annotations

import logging
import multiprocessing
import queue
import signal
import sys
import threading
import time

from picosnitch.config import Config
from picosnitch.process_manager import ProcessManager
from picosnitch.subprocesses.monitor import run_monitor
from picosnitch.subprocesses.primary import run_primary
from picosnitch.subprocesses.secondary import run_secondary
from picosnitch.utils import sd_notify


def run_main_loop(config: Config) -> int:
    """coordinates all picosnitch subprocesses"""
    # start subprocesses
    event_pipes = [multiprocessing.Pipe(duplex=False) for _ in range(5)]
    event_recv_pipes, event_send_pipes = zip(*event_pipes)
    secondary_recv_pipe, secondary_send_pipe = multiprocessing.Pipe(duplex=False)
    q_error: multiprocessing.Queue[str] = multiprocessing.Queue()
    p_monitor = ProcessManager(
        name="snitchmonitor",
        target=run_monitor,
        init_args=(
            config,
            event_send_pipes,
            q_error,
        ),
    )
    p_primary = ProcessManager(
        name="snitchprimary",
        target=run_primary,
        init_args=(
            config,
            event_recv_pipes,
            secondary_send_pipe,
            q_error,
        ),
    )
    p_secondary = ProcessManager(
        name="snitchsecondary",
        target=run_secondary,
        init_args=(
            config,
            secondary_recv_pipe,
            p_primary.q_in,
            q_error,
        ),
    )
    # set signals
    subprocesses = [p_monitor, p_primary, p_secondary]
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
    # the monitor puts "ready" on q_out once its probes are attached; bounded so a stall cannot hang startup
    try:
        p_monitor.q_out.get(timeout=30)
    except queue.Empty:
        pass
    sd_notify("READY=1")
    # watch subprocesses; detect a real suspend/resume by the gap between CLOCK_BOOTTIME
    # (counts time asleep) and CLOCK_MONOTONIC (does not). a plain wall-clock gap can be
    # forged by cpu starvation or SIGSTOP, which must not trigger a monitor restart -- that
    # would open a bpf re-attach window an attacker could slip traffic through.
    mono_last = time.monotonic()
    boot_last = time.clock_gettime(time.CLOCK_BOOTTIME)
    try:
        while not shutdown_event.is_set():
            resume_event.wait(timeout=5)
            if shutdown_event.is_set():
                break
            # log here, not via q_error: the primary that drains it may be the one that died
            if not all(p.is_alive() for p in subprocesses):
                dead = " ".join([p.name for p in subprocesses if not p.is_alive()])
                logging.error(f"picosnitch subprocess died, exiting for the service manager to restart ({dead})")
                break
            if any(p.is_zombie() for p in subprocesses):
                zombies = " ".join([p.name for p in subprocesses if p.is_zombie()])
                logging.error(f"picosnitch subprocess became a zombie, exiting for the service manager to restart ({zombies})")
                break
            mono_now = time.monotonic()
            boot_now = time.clock_gettime(time.CLOCK_BOOTTIME)
            suspended_for = (boot_now - boot_last) - (mono_now - mono_last)
            # skip the resume/suspend restart once shutdown is requested: the shutdown handler
            # also sets resume_event (to break the wait() above), and a spurious monitor re-attach
            # here would only add teardown latency before the clean exit below
            if not shutdown_event.is_set() and (resume_event.is_set() or suspended_for > 5):
                resume_event.clear()
                logging.info("restarting picosnitch monitor after resuming from suspend")
                p_monitor.q_in.put("terminate")
                # let the monitor drain the conn maps and exit before SIGTERM aborts it
                p_monitor.join(timeout=10)
                p_monitor.terminate()
                p_monitor.q_in.get()
                p_monitor.start()
            mono_last, boot_last = mono_now, boot_now
    except Exception as e:
        tb = sys.exc_info()[2]
        logging.error("picosnitch subprocess exception: %s%s on line %s" % (type(e).__name__, str(e.args), tb.tb_lineno if tb else "?"))
    for p in subprocesses:
        p.terminate()
    # a clean exit only on signal; otherwise a non-zero exit lets the service manager restart us
    return 0 if shutdown_event.is_set() else 1
