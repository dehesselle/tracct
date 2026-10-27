# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import os
import tomllib
import typing
from pathlib import Path

from picosnitch import __version__

# picosnitch version
VERSION: typing.Final[str] = __version__


def _systemd_directory(variable: str, default: str) -> Path:
    """the directory systemd passes for a *Directory= setting (first entry when the unit lists
    several, colon-separated), else the default for running outside a unit"""
    value = os.getenv(variable, "").split(":")[0]
    return Path(value) if value else Path(default)


# paths come from the environment so a unit (or a test) can place them; the variables are the
# ones systemd sets for ConfigurationDirectory=, StateDirectory= and RuntimeDirectory=
CONFIG_PATH: typing.Final[Path] = Path(os.getenv("PICOSNITCH_CONFIG") or _systemd_directory("CONFIGURATION_DIRECTORY", "/etc/opt/picosnitch") / "config.toml")
STATE_DIR: typing.Final[Path] = _systemd_directory("STATE_DIRECTORY", "/var/lib/picosnitch")
RUN_DIR: typing.Final[Path] = _systemd_directory("RUNTIME_DIRECTORY", "/run/picosnitch")
DB_PATH: typing.Final[Path] = STATE_DIR / "picosnitch.db"

# bounds the writer's retry buffer near 200 MB (~2 KB/entry) on a persistent outage
RETRY_BUFFER_MAX: typing.Final[int] = 100000
# btrfs device numbers differ per subvolume and its inodes aren't unique across subvolumes,
# so (dev, ino) checks are disabled there unless [monitoring].st_dev_mask overrides it
st_dev_mask = 0xFFFFFFFF
try:
    # parse /proc/mounts to detect btrfs filesystems (replaces psutil.disk_partitions)
    with open("/proc/mounts", "r") as _mounts_file:
        for _line in _mounts_file:
            _parts = _line.split()
            if len(_parts) >= 3 and _parts[2] == "btrfs":
                st_dev_mask = 0
                break
    with open(CONFIG_PATH, "rb") as toml_file:
        set_mask = tomllib.load(toml_file).get("monitoring", {}).get("st_dev_mask")
    if isinstance(set_mask, int) and not isinstance(set_mask, bool) and 0 <= set_mask <= 0xFFFFFFFF:
        st_dev_mask = set_mask
except Exception:
    pass
ST_DEV_MASK: typing.Final[int] = st_dev_mask

# database schema version and table definitions, see docs/schema.md
# id 0 in each lookup table is the "empty/unknown" sentinel.
# `family` is AF_INET (2), AF_INET6 (10), AF_PACKET (17) for raw L2 sends, or 0 when unknown.
# `protocol` is an IPPROTO_* value (TCP=6, UDP=17, ...) or 0 when unknown.
# `netns` is the inode of a network namespace.
DB_VERSION: typing.Final[int] = 6
SCHEMA_EXECUTABLES: typing.Final[str] = """
    id INTEGER PRIMARY KEY,
    exe TEXT NOT NULL,
    name TEXT NOT NULL,
    cmdline TEXT NOT NULL,
    UNIQUE(exe, name, cmdline)"""
SCHEMA_DOMAINS: typing.Final[str] = """
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE"""
SCHEMA_ADDRESSES: typing.Final[str] = """
    id INTEGER PRIMARY KEY,
    addr TEXT NOT NULL UNIQUE"""
SCHEMA_UNITS: typing.Final[str] = """
    id INTEGER PRIMARY KEY,
    unit TEXT NOT NULL UNIQUE"""
SCHEMA_INTERFACES: typing.Final[str] = """
    id INTEGER PRIMARY KEY,
    netns INTEGER NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    UNIQUE(netns, name, kind)"""
SCHEMA_NETNS: typing.Final[str] = """
    inode INTEGER PRIMARY KEY,
    name TEXT NOT NULL"""
SCHEMA_CONNECTIONS: typing.Final[str] = """
    contime INTEGER NOT NULL,
    send INTEGER NOT NULL,
    recv INTEGER NOT NULL,
    events INTEGER NOT NULL,
    exe_id INTEGER NOT NULL REFERENCES executables(id),
    pexe_id INTEGER NOT NULL REFERENCES executables(id),
    unit_id INTEGER NOT NULL REFERENCES units(id),
    uid INTEGER NOT NULL,
    family INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    lport INTEGER NOT NULL,
    rport INTEGER NOT NULL,
    laddr_id INTEGER NOT NULL REFERENCES addresses(id),
    raddr_id INTEGER NOT NULL REFERENCES addresses(id),
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    netns INTEGER NOT NULL,
    iface_id INTEGER NOT NULL REFERENCES interfaces(id)"""
SCHEMA_CONNECTIONS_ROLLUP: typing.Final[str] = """
    period INTEGER NOT NULL,
    exe_id INTEGER NOT NULL REFERENCES executables(id),
    pexe_id INTEGER NOT NULL REFERENCES executables(id),
    unit_id INTEGER NOT NULL REFERENCES units(id),
    uid INTEGER NOT NULL,
    family INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    lport INTEGER NOT NULL,
    rport INTEGER NOT NULL,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    netns INTEGER NOT NULL,
    iface_id INTEGER NOT NULL REFERENCES interfaces(id),
    send INTEGER NOT NULL,
    recv INTEGER NOT NULL,
    events INTEGER NOT NULL,
    rows INTEGER NOT NULL"""
SCHEMA_INTERFACE_TRAFFIC: typing.Final[str] = """
    contime INTEGER NOT NULL,
    iface_id INTEGER NOT NULL REFERENCES interfaces(id),
    rx INTEGER NOT NULL,
    tx INTEGER NOT NULL"""
SCHEMA_INTERFACE_TRAFFIC_ROLLUP: typing.Final[str] = """
    period INTEGER NOT NULL,
    iface_id INTEGER NOT NULL REFERENCES interfaces(id),
    rx INTEGER NOT NULL,
    tx INTEGER NOT NULL"""
SCHEMA_FORWARDED: typing.Final[str] = """
    contime INTEGER NOT NULL,
    netns INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    src_id INTEGER NOT NULL REFERENCES addresses(id),
    sport INTEGER NOT NULL,
    dst_id INTEGER NOT NULL REFERENCES addresses(id),
    dport INTEGER NOT NULL,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    orig_bytes INTEGER NOT NULL,
    reply_bytes INTEGER NOT NULL,
    orig_packets INTEGER NOT NULL,
    reply_packets INTEGER NOT NULL"""
SCHEMA_FORWARDED_ROLLUP: typing.Final[str] = """
    period INTEGER NOT NULL,
    netns INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    src_id INTEGER NOT NULL REFERENCES addresses(id),
    dport INTEGER NOT NULL,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    orig_bytes INTEGER NOT NULL,
    reply_bytes INTEGER NOT NULL,
    orig_packets INTEGER NOT NULL,
    reply_packets INTEGER NOT NULL,
    rows INTEGER NOT NULL"""
SCHEMA_META: typing.Final[str] = """
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL"""
# every table with its schema, in creation order, and the sentinel row of each lookup table
TABLES: typing.Final[tuple[tuple[str, str], ...]] = (
    ("executables", SCHEMA_EXECUTABLES),
    ("domains", SCHEMA_DOMAINS),
    ("addresses", SCHEMA_ADDRESSES),
    ("units", SCHEMA_UNITS),
    ("interfaces", SCHEMA_INTERFACES),
    ("netns", SCHEMA_NETNS),
    ("connections", SCHEMA_CONNECTIONS),
    ("connections_rollup", SCHEMA_CONNECTIONS_ROLLUP),
    ("interface_traffic", SCHEMA_INTERFACE_TRAFFIC),
    ("interface_traffic_rollup", SCHEMA_INTERFACE_TRAFFIC_ROLLUP),
    ("forwarded", SCHEMA_FORWARDED),
    ("forwarded_rollup", SCHEMA_FORWARDED_ROLLUP),
    ("meta", SCHEMA_META),
)
SENTINELS: typing.Final[tuple[str, ...]] = (
    "INSERT INTO executables(id, exe, name, cmdline) VALUES (0, '', '', '')",
    "INSERT INTO domains(id, domain) VALUES (0, '')",
    "INSERT INTO addresses(id, addr) VALUES (0, '')",
    "INSERT INTO units(id, unit) VALUES (0, '')",
    "INSERT INTO interfaces(id, netns, name, kind) VALUES (0, 0, '', '')",
)
INDEXES: typing.Final[tuple[str, ...]] = (
    "CREATE INDEX idx_contime ON connections(contime)",
    "CREATE INDEX idx_exe_id_contime ON connections(exe_id, contime)",
    "CREATE INDEX idx_pexe_id_contime ON connections(pexe_id, contime)",
    "CREATE INDEX idx_rollup_period ON connections_rollup(period)",
    "CREATE INDEX idx_rollup_exe_id_period ON connections_rollup(exe_id, period)",
    "CREATE INDEX idx_rollup_pexe_id_period ON connections_rollup(pexe_id, period)",
    "CREATE INDEX idx_interface_traffic_contime ON interface_traffic(contime)",
    "CREATE INDEX idx_interface_traffic_rollup_period ON interface_traffic_rollup(period)",
    "CREATE INDEX idx_forwarded_contime ON forwarded(contime)",
    "CREATE INDEX idx_forwarded_rollup_period ON forwarded_rollup(period)",
)
