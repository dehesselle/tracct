# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""The runtime messages: their IDs, levels and the loggers they go to."""

import ast
import logging
from pathlib import Path

import tracct
from tracct import messages


def test_every_id_in_the_code_is_known_and_every_known_id_used():
    """An unknown ID would raise in the thread that reports it."""
    used = set()
    for path in Path(tracct.__file__).parent.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            # report(logger, "id", ...) or an injected self.report("id", ...).
            if isinstance(node.func, ast.Name) and node.func.id == "report":
                args = node.args[1:]
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "report":
                args = node.args
            else:
                continue
            used.update(
                arg.value
                for arg in args[:1]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            )
    # main_loop picks its queue's ID from a tuple.
    used |= {"writer-queue-full", "live-feed-queue-full"}
    assert used == set(messages.DEFAULTS)


def test_report_logs_at_the_default_level_with_its_id(caplog):
    caplog.set_level(logging.DEBUG)
    messages.report(logging.getLogger("tracct.monitor"), "multi-call-inode", "seen")
    [record] = caplog.records
    assert record.name == "tracct.monitor"
    assert record.levelno == logging.WARNING
    assert record.getMessage() == "[multi-call-inode] seen"


def test_report_follows_the_level_set_and_off(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger("tracct.writer")
    monkeypatch.setitem(messages.LEVELS, "maintenance-done", logging.ERROR)
    monkeypatch.setitem(messages.LEVELS, "sqlite-retry", None)
    messages.report(logger, "maintenance-done", "rolled up")
    messages.report(logger, "sqlite-retry", "will retry")
    assert [(r.levelno, r.getMessage()) for r in caplog.records] == [
        (logging.ERROR, "[maintenance-done] rolled up")
    ]


def test_report_strips_control_characters(caplog):
    messages.report(logging.getLogger("tracct"), "exec-ring-full", "a\x1b[2Kb\nc")
    assert caplog.records[0].getMessage() == "[exec-ring-full] a[2Kbc"
