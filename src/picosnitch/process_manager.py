# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import collections.abc
import multiprocessing


def _read_proc_stat_state(pid: int | None) -> str:
    """Read the single-character state field (3rd field) from /proc/{pid}/stat.

    The stat format is: pid (comm) state ppid ... where comm may itself
    contain spaces and parentheses. Splitting on the last `)` works around
    that since state is always the next token.
    """
    if pid is None:
        return ""
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            return f.read().rsplit(")", 1)[1].split()[0]
    except OSError:
        return ""


class ProcessManager:
    """A class for managing a subprocess"""

    def __init__(self, name: str, target: collections.abc.Callable, init_args: tuple = ()) -> None:
        self.name, self.target, self.init_args = name, target, init_args
        self.q_in, self.q_out = multiprocessing.Queue(), multiprocessing.Queue()
        self.start()

    def start(self) -> None:
        self.p = multiprocessing.Process(name=self.name, target=self.target, daemon=True, args=(*self.init_args, self.q_in, self.q_out))
        self.p.start()

    def join(self, timeout: float | None = None) -> None:
        self.p.join(timeout)

    def terminate(self) -> None:
        if self.p.is_alive():
            self.p.terminate()
        self.p.join(timeout=5)
        if self.p.is_alive():
            self.p.kill()
        self.p.join(timeout=5)
        self.p.close()

    def is_alive(self) -> bool:
        return self.p.is_alive()

    def is_zombie(self) -> bool:
        return self.p.is_alive() and _read_proc_stat_state(self.p.pid) == "Z"
