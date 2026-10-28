# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""`tracct install`: put the units, the sysusers file and the base config in place.

An existing file is replaced only with --force, and the drop-ins in config.d are never
touched. When any target cannot be written, nothing goes to the system: every file goes
into a new temporary tree instead, and the commands that copy them over are printed.
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import os
import sys
import tempfile
from importlib import resources
from pathlib import Path

logger = logging.getLogger(__name__)

#: The command the packaged units start, replaced by the tracct that installs them.
PACKAGED_COMMAND = "/opt/tracct/bin/tracct"
#: Packaged file -> target, relative to the root.
FILES: dict[str, str] = {
    "tracct.service": "etc/systemd/system/tracct.service",
    "tracct-query.socket": "etc/systemd/system/tracct-query.socket",
    "tracct-query.service": "etc/systemd/system/tracct-query.service",
    "tracct.sysusers": "etc/sysusers.d/tracct.conf",
    "config.toml": "etc/opt/tracct/config.toml",
}
#: Byte counters for forwarded flows (--conntrack); they change the module system-wide.
CONNTRACK_FILES: dict[str, str] = {
    "modules-load.conf": "etc/modules-load.d/tracct.conf",
    "modprobe.conf": "etc/modprobe.d/tracct.conf",
}
#: Where local settings go: created empty, never written into.
DROP_INS = "etc/opt/tracct/config.d"
FORWARDED_TRAFFIC_DOCS = "https://github.com/dehesselle/tracct/blob/master/docs/OPERATIONS.md#forwarded-traffic"


@dataclasses.dataclass
class Target:
    #: Relative to the root.
    path: str
    #: None for a directory.
    content: bytes | None
    #: "write", "same" or "kept".
    state: str = "write"


def tracct_command() -> str:
    """Return how a unit starts this tracct: its script, else its Python with -m."""
    script = Path(sys.executable).parent / "tracct"
    if script.is_file():
        return str(script)
    return f"{sys.executable} -m tracct"


def targets(conntrack: bool) -> list[Target]:
    """Return what an install writes, with the units starting this tracct."""
    packaged = resources.files("tracct") / "files"
    found = []
    for name, path in {**FILES, **(CONNTRACK_FILES if conntrack else {})}.items():
        text = (packaged / name).read_text(encoding="utf-8")
        text = text.replace(PACKAGED_COMMAND, tracct_command())
        found.append(Target(path, text.encode()))
    found.sort(key=lambda target: target.path)
    found.append(Target(DROP_INS, None))
    return found


def compare(target: Target, root: Path, force: bool) -> None:
    """Set whether `target` is written, already in place, or kept as it differs."""
    path = root / target.path
    if target.content is None:
        target.state = "same" if path.is_dir() else "write"
        return
    if not (path.exists() or path.is_symlink()):
        target.state = "write"
        return
    try:
        same = path.read_bytes() == target.content
    except OSError:
        same = False
    target.state = "same" if same else "write" if force else "kept"


def writable(path: Path) -> bool:
    """Whether `path` can be written: itself and its directory, or its nearest existing
    ancestor when it is missing.
    """
    if path.exists() or path.is_symlink():
        return os.access(path, os.W_OK) and os.access(path.parent, os.W_OK)
    for parent in path.parents:
        if parent.exists():
            return os.access(parent, os.W_OK | os.X_OK)
    return False


def write(path: Path, content: bytes | None) -> None:
    """Create `path`, a file through a temporary one beside it, or a directory."""
    if content is None:
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
        return
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def install(
    root: Path | None, force: bool, conntrack: bool, system: Path = Path("/")
) -> int:
    """Write the files under `root`, or the system when None; return the exit code.

    `system` is the system's root, which a test moves.
    """
    base = system if root is None else root
    planned = targets(conntrack)
    for target in planned:
        compare(target, base, force)
    pending = [target for target in planned if target.state == "write"]
    refused = [t.path for t in pending if not writable(base / t.path)]
    staged = None
    if refused and root is not None:
        logger.error(f"cannot write {root / refused[0]}")
        return 1
    if refused:
        staged = Path(tempfile.mkdtemp(prefix="tracct-install-"))
        print(
            f"Cannot write /{refused[0]}"
            + (f" and {len(refused) - 1} more" if len(refused) > 1 else "")
            + f", so nothing went to the system; the files are in {staged} instead."
        )
    destination = staged or base
    try:
        for target in pending:
            write(destination / target.path, target.content)
    except OSError as e:
        logger.error(f"cannot write {e.filename}: {e.strerror}")
        return 1
    for target in planned:
        shown = (
            destination / target.path if target.state == "write" else base / target.path
        )
        suffix = "/" if target.content is None else ""
        note = " (differs; -f replaces it)" if target.state == "kept" else ""
        verb = {"write": "wrote", "same": "same", "kept": "kept"}[target.state]
        print(f"{verb:6} {shown}{suffix}{note}")
    if staged is not None:
        print("\nTo put them in place, as root:")
        for target in pending:
            if target.content is None:
                print(f"  install -d -m 755 /{target.path}")
            else:
                print(f"  install -D -m 644 {staged / target.path} /{target.path}")
    if root is None:
        print_next_steps(conntrack)
    return 0


def print_next_steps(conntrack: bool) -> None:
    print(
        "\nThen, as root:\n"
        "  systemd-sysusers\n"
        "  systemctl daemon-reload\n"
        "  systemctl enable --now tracct tracct-query.socket\n"
        "  systemctl restart tracct   # instead, if it runs already\n"
        "  usermod -aG tracct-viewer <user>   # for each user of tracct view\n"
        "Local settings go in /etc/opt/tracct/config.d/*.toml."
    )
    if conntrack:
        print(
            "The conntrack options apply from the next boot; to apply them now, see "
            + FORWARDED_TRAFFIC_DOCS
        )
    else:
        print(
            "Forwarded traffic needs nf_conntrack with acct=1: run again with "
            "--conntrack, or see " + FORWARDED_TRAFFIC_DOCS
        )


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="replace files that differ (never the drop-ins in config.d)",
    )
    parser.add_argument(
        "--conntrack",
        action="store_true",
        help="also load nf_conntrack with acct=1 at boot, for forwarded traffic",
    )
    parser.add_argument(
        "--root",
        type=Path,
        help="write under this directory instead of the system, e.g. for a package",
    )


def run_install(args: argparse.Namespace) -> int:
    return install(args.root, args.force, args.conntrack)
