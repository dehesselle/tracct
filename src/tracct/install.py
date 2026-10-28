# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""`tracct install`: put the units, the sysusers file and the base config in place, and
`tracct uninstall`: stop the units and take them away again.

Both say what they will do and ask first, and change nothing when any target cannot be
written. An existing file is replaced only with --force, and the drop-ins in config.d
are never touched. Uninstall keeps the drop-ins and the database unless --purge is given.
"""

from __future__ import annotations

import argparse
import dataclasses
import grp
import logging
import os
import shutil
import subprocess
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
#: The units in FILES; tracct-query.service is started by its socket and not enabled.
UNITS = ("tracct.service", "tracct-query.socket", "tracct-query.service")
UNIT_PROPERTIES = (
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "FragmentPath",
    "DropInPaths",
    "ActiveEnterTimestamp",
)
#: The group from tracct.sysusers.
VIEWER_GROUP = "tracct-viewer"
#: Where DynamicUser= keeps the state directory, which holds the database.
STATE = "var/lib/private/tracct"
#: What --purge removes besides the drop-ins: the state directory and the query
#: service's cache, each with the symlink systemd reaches it by.
PURGED = (
    "var/lib/tracct",
    STATE,
    "var/cache/tracct-query",
    "var/cache/private/tracct-query",
)


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
    root: Path | None,
    force: bool,
    conntrack: bool,
    yes: bool,
    system: Path = Path("/"),
) -> int:
    """Write the files under `root`, or the system when None, once confirmed; return
    the exit code.

    `system` is the system's root, which a test moves.
    """
    base = system if root is None else root
    planned = targets(conntrack)
    for target in planned:
        compare(target, base, force)
    pending = [target for target in planned if target.state == "write"]

    if pending:
        print("This will:")
    for target in pending:
        path = base / target.path
        if target.content is None:
            print(f"  create {path}/")
        else:
            print(f"  {'replace' if present(path) else 'write'} {path}")
    kept = [target for target in planned if target.state != "write"]
    if kept:
        print("It keeps:")
    for target in kept:
        suffix = "/" if target.content is None else ""
        note = (
            "differs; -f replaces it" if target.state == "kept" else "already in place"
        )
        print(f"  {base / target.path}{suffix} ({note})")
    refused = [target.path for target in pending if not writable(base / target.path)]
    if refused:
        hint = ": run as root" if root is None else ""
        logger.error(f"cannot write {base / refused[0]}{hint}")
        return 1
    if not pending:
        print("Nothing to write.")
    elif not yes and not confirm("Continue?"):
        print("Nothing changed.")
        return 1

    try:
        for target in pending:
            write(base / target.path, target.content)
    except OSError as e:
        logger.error(f"cannot write {e.filename}: {e.strerror}")
        return 1
    for target in pending:
        suffix = "/" if target.content is None else ""
        print(f"wrote {base / target.path}{suffix}")
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
        print("The conntrack options apply from the next boot.")
    else:
        print(
            "Forwarded traffic needs nf_conntrack with acct=1: run again with --conntrack"
        )


def systemctl(*args: str) -> subprocess.CompletedProcess[str] | None:
    """Run systemctl with `args`; None when there is no systemctl."""
    try:
        return subprocess.run(
            ["systemctl", *args], capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        return None


def run_systemctl(*args: str) -> int:
    """Run systemctl with `args`, reporting a failure; return the exit code."""
    result = systemctl(*args)
    if result is None or result.returncode != 0:
        reason = "not found" if result is None else result.stderr.strip()
        logger.error(f"systemctl {' '.join(args)}: {reason}")
        return 1
    return 0


def unit_states() -> dict[str, dict[str, str]] | str:
    """Return the UNIT_PROPERTIES of each of UNITS, or why systemd cannot tell them.

    This needs no privileges; a unit that isn't there has LoadState not-found.
    """
    result = systemctl("show", f"--property={','.join(UNIT_PROPERTIES)}", *UNITS)
    if result is None:
        return "systemctl not found"
    if result.returncode != 0:
        lines = result.stderr.strip().splitlines()
        return lines[0] if lines else f"systemctl show exited with {result.returncode}"
    blocks = result.stdout.strip().split("\n\n")
    return {
        unit: dict(line.partition("=")[::2] for line in block.splitlines())
        for unit, block in zip(UNITS, blocks)
    }


def present(path: Path) -> bool:
    """Whether `path` is there, a dangling symlink too; True when it cannot be told."""
    try:
        path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    return True


def directory(path: Path) -> bool:
    """Whether `path` is a directory and no symlink; False when it cannot be told."""
    return os.path.isdir(path) and not os.path.islink(path)


def removable(path: Path) -> bool:
    """Whether `path` can be removed: its directory can be written."""
    return os.access(path.parent, os.W_OK | os.X_OK)


def remove(path: Path, tree: bool) -> None:
    """Remove a file or symlink, an empty directory, or with `tree` a directory and
    what it holds.
    """
    if not directory(path):
        path.unlink()
    elif tree:
        shutil.rmtree(path)
    else:
        path.rmdir()


def confirm(question: str) -> bool:
    """Ask `question`, which defaults to no; without a terminal the answer is no."""
    if not sys.stdin.isatty():
        print(f"{question} [y/N] no terminal to ask on, so no; -y answers yes")
        return False
    try:
        answer = input(f"{question} [y/N] ")
    except EOFError:
        print()
        return False
    return answer.strip().lower() in ("y", "yes")


def uninstall(purge: bool, yes: bool, system: Path = Path("/")) -> int:
    """Stop the units and remove what install wrote, once confirmed; return the exit
    code.

    `system` is the system's root, which a test moves.
    """
    states = unit_states()
    loaded = []
    if isinstance(states, dict):
        loaded = [
            unit
            for unit in UNITS
            if states.get(unit, {}).get("LoadState", "not-found") != "not-found"
        ]
    # The socket's service is static: it is stopped, there is nothing to disable.
    disable = [unit for unit in loaded if unit != "tracct-query.service"]
    stop = [unit for unit in loaded if unit == "tracct-query.service"]
    reload = isinstance(states, dict) and any(
        present(system / FILES[unit]) for unit in UNITS
    )
    # (path, with what it holds)
    removals = [
        (system / path, False)
        for path in sorted([*FILES.values(), *CONNTRACK_FILES.values()])
        if present(system / path)
    ]
    drop_ins = system / DROP_INS
    held = sorted(drop_ins.iterdir()) if directory(drop_ins) else []
    if directory(drop_ins) and (purge or not held):
        removals.append((drop_ins, purge))
    base = drop_ins.parent
    removed = [path for path, _ in removals]
    if directory(base) and all(path in removed for path in base.iterdir()):
        removals.append((base, False))
    if purge:
        removals += [(system / path, True) for path in PURGED if present(system / path)]
    if not loaded and not removals:
        print("Nothing to uninstall.")
        return 0

    print("This will:")
    if disable:
        print(f"  stop and disable {' '.join(disable)}")
    if stop:
        print(f"  stop {' '.join(stop)}")
    if isinstance(states, str):
        print(f"  leave the units alone ({states})")
    for path, tree in removals:
        line = f"  remove {path}{'/' if directory(path) else ''}"
        if path == drop_ins and held:
            line += f" with {', '.join(p.name for p in held)}"
        elif tree and directory(path):
            line += " and everything in it"
        print(line)
    if reload:
        print("  reload systemd")
    print("It keeps:")
    if held and not purge:
        names = ", ".join(p.name for p in held)
        print(f"  {drop_ins}/ with {names} (--purge removes them)")
    if not purge and present(system / STATE):
        print(f"  the database in {system / STATE}/ (--purge removes it)")
    try:
        grp.getgrnam(VIEWER_GROUP)
        print(f"  the group {VIEWER_GROUP} (groupdel {VIEWER_GROUP} removes it)")
    except KeyError:
        pass
    print(f"  itself in {sys.prefix} (cannot uninstall myself)")
    refused = [path for path, _ in removals if not removable(path)]
    if refused:
        logger.error(f"cannot remove {refused[0]}: run as root")
        return 1
    if not yes and not confirm("Continue?"):
        print("Nothing changed.")
        return 1

    if disable:
        if err := run_systemctl("disable", "--now", *disable):
            return err
        print(f"stopped and disabled {' '.join(disable)}")
    if stop:
        if err := run_systemctl("stop", *stop):
            return err
        print(f"stopped {' '.join(stop)}")
    for path, tree in removals:
        suffix = "/" if directory(path) else ""
        try:
            remove(path, tree)
        except OSError as e:
            logger.error(f"cannot remove {path}: {e.strerror}")
            return 1
        print(f"removed {path}{suffix}")
    if reload:
        if err := run_systemctl("daemon-reload"):
            return err
        print("reloaded systemd")
    return 0


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
    parser.add_argument(
        "-y", "--yes", action="store_true", help="go ahead without asking"
    )


def run_install(args: argparse.Namespace) -> int:
    return install(args.root, args.force, args.conntrack, args.yes)


def add_uninstall_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--purge",
        action="store_true",
        help="also remove the drop-ins in config.d, the database and the query cache",
    )
    parser.add_argument(
        "-y", "--yes", action="store_true", help="go ahead without asking"
    )


def run_uninstall(args: argparse.Namespace) -> int:
    return uninstall(args.purge, args.yes)
