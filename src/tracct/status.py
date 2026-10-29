# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""`tracct status`: what is installed, how the units run, whether conntrack tracks and
counts forwarded traffic, who may view, and the database.

All of it but the database can be read without privileges.
"""

from __future__ import annotations

import grp
import os
import pwd
from pathlib import Path

from tracct.config import Config, config_files, load_config
from tracct.conntrack import ACCT_SYSCTL
from tracct.install import (
    DROP_INS,
    FILES,
    STATE,
    UNITS,
    VIEWER_GROUP,
    compare,
    targets,
    unit_states,
)

#: The module's option, which a network namespace created later starts from.
MODULE_ACCT = "sys/module/nf_conntrack/parameters/acct"
#: The flows in this namespace's table, 0 while nothing here uses conntrack.
COUNT_SYSCTL = "proc/sys/net/netfilter/nf_conntrack_count"
#: A file's state as compare() sets it, as status shows it.
LABELS = {"same": "same", "kept": "modified", "write": "missing"}


def status(system: Path = Path("/")) -> int:
    """Print the overview; return the exit code.

    `system` is the system's root, which a test moves.
    """
    config = load_config(system / FILES["config.toml"])
    print_files(system)
    print_drop_ins(system)
    print_services(system)
    print_conntrack(system, config)
    print_viewer(config)
    print_database(system)
    return 0


def print_files(system: Path) -> None:
    print("Files")
    modified = False
    for target in targets(conntrack=True):
        if target.content is None:
            continue
        compare(target, system, force=False)
        modified |= target.state == "kept"
        print(f"  {LABELS[target.state]:8}  {system / target.path}")
    if modified:
        print(
            "  (modified: not what this tracct's install writes; install -f replaces it)"
        )


def print_drop_ins(system: Path) -> None:
    drop_ins = system / DROP_INS
    print(f"\nDrop-ins in {drop_ins}/")
    if not drop_ins.is_dir():
        print("  no such directory")
        return
    read = [
        path
        for path in config_files(system / FILES["config.toml"])
        if path.parent == drop_ins
    ]
    ignored = sorted(path for path in drop_ins.iterdir() if path not in read)
    for path in read:
        print(f"  {path.name}")
    for path in ignored:
        print(f"  {path.name} (ignored, not a *.toml file)")
    if not read and not ignored:
        print("  none")


def print_services(system: Path) -> None:
    print("\nServices")
    states = unit_states()
    if isinstance(states, str):
        print(f"  unknown: {states}")
        return
    for unit in UNITS:
        properties = states.get(unit, {})
        if properties.get("LoadState", "not-found") == "not-found":
            print(f"  {unit:20}  not found")
            continue
        active = properties.get("ActiveState", "?")
        line = f"{properties.get('UnitFileState', '?')}, {active}"
        line += f" ({properties.get('SubState', '?')})"
        if active == "active" and properties.get("ActiveEnterTimestamp"):
            line += f" since {properties['ActiveEnterTimestamp']}"
        print(f"  {unit:20}  {line}")
        fragment = properties.get("FragmentPath")
        if fragment and Path(fragment) != system / FILES[unit]:
            print(f"  {'':20}  from {fragment}")
        for drop_in in properties.get("DropInPaths", "").split():
            print(f"  {'':20}  drop-in {drop_in}")


def read_value(path: Path) -> str | None:
    """The first line of a sysfs or procfs file, None when it is not there."""
    try:
        return path.read_text().strip()
    except OSError:
        return None


def print_conntrack(system: Path, config: Config) -> None:
    """The option, the kernel's two settings and the table's size, with the values as
    the kernel shows them.
    """
    print("\nConntrack")
    print(f"  [monitoring] conntrack = {str(config.monitoring.conntrack).lower()}")
    module_acct = read_value(system / MODULE_ACCT)
    if module_acct is None:
        print("  nf_conntrack module: not loaded")
        return
    acct = read_value(system / ACCT_SYSCTL.lstrip("/"))
    if acct is not None:
        print(f"  net.netfilter.nf_conntrack_acct (sysctl): {acct}")
    count = read_value(system / COUNT_SYSCTL)
    if count is not None:
        print(f"  net.netfilter.nf_conntrack_count (sysctl): {count}")
    print(f"  acct (nf_conntrack module parameter): {module_acct}")


def print_viewer(config: Config) -> None:
    print("\nViewer")
    if config.viewer.group != VIEWER_GROUP:
        print(
            f"  [viewer] group = {config.viewer.group!r}:"
            f" events.sock does not go to {VIEWER_GROUP}"
        )
    try:
        group = grp.getgrnam(VIEWER_GROUP)
    except KeyError:
        print(f"  the group {VIEWER_GROUP} is missing (systemd-sysusers creates it)")
        return
    if os.geteuid() == 0:
        access = "you are root"
    elif group.gr_gid in os.getgroups():
        access = "you are a member"
    elif pwd.getpwuid(os.getuid()).pw_name in group.gr_mem:
        access = "you are a member from your next login on"
    else:
        access = f"you are not a member (usermod -aG {VIEWER_GROUP} <user>)"
    print(f"  the group {VIEWER_GROUP} exists, {access}")


def print_database(system: Path) -> None:
    print("\nDatabase")
    path = system / STATE / "tracct.db"
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        print(f"  {path}: not found")
        return
    except PermissionError:
        print(f"  {path}: not readable without root")
        return
    except OSError as e:
        print(f"  {path}: {e.strerror}")
        return
    try:
        size += path.with_name(path.name + "-wal").stat().st_size
    except OSError:
        pass
    print(f"  {path}: {size / 10**6:,.1f} MB")
