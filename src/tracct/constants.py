# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import tomllib
import typing
from pathlib import Path

from tracct.version import __version__

#: tracct version, from the git tag at build time (hatch-vcs writes version.py).
VERSION: typing.Final[str] = __version__


def _systemd_directory(variable: str, default: str) -> Path:
    """The directory systemd passes for a *Directory= setting (first entry when the unit
    lists several, colon-separated), else the default for running outside a unit.
    """
    value = os.getenv(variable, "").split(":")[0]
    return Path(value) if value else Path(default)


# Paths come from the environment, so a unit (or a test) can place them; the variables
# are the ones systemd sets for ConfigurationDirectory=, StateDirectory= and
# RuntimeDirectory=.
CONFIG_PATH: typing.Final[Path] = Path(
    os.getenv("TRACCT_CONFIG")
    or _systemd_directory("CONFIGURATION_DIRECTORY", "/etc/opt/tracct") / "config.toml"
)
STATE_DIR: typing.Final[Path] = _systemd_directory("STATE_DIRECTORY", "/var/lib/tracct")
RUN_DIR: typing.Final[Path] = _systemd_directory("RUNTIME_DIRECTORY", "/run/tracct")
DB_PATH: typing.Final[Path] = STATE_DIR / "tracct.db"

#: Bounds the writer's retry buffer near 200 MB (~2 KB/entry) on a persistent outage.
RETRY_BUFFER_MAX: typing.Final[int] = 100000
#: Btrfs device numbers differ per subvolume and its inodes aren't unique across
#: subvolumes, so (dev, ino) checks are disabled there unless [monitoring].st_dev_mask
#: overrides it.
st_dev_mask = 0xFFFFFFFF
try:
    # Parse /proc/mounts to detect btrfs filesystems (replaces psutil.disk_partitions).
    with open("/proc/mounts", "r") as _mounts_file:
        for _line in _mounts_file:
            _parts = _line.split()
            if len(_parts) >= 3 and _parts[2] == "btrfs":
                st_dev_mask = 0
                break
    with open(CONFIG_PATH, "rb") as toml_file:
        set_mask = tomllib.load(toml_file).get("monitoring", {}).get("st_dev_mask")
    if (
        isinstance(set_mask, int)
        and not isinstance(set_mask, bool)
        and 0 <= set_mask <= 0xFFFFFFFF
    ):
        st_dev_mask = set_mask
except Exception:  # noqa: BLE001, S110
    # A config this cannot read keeps the default; load_config reports it.
    pass
ST_DEV_MASK: typing.Final[int] = st_dev_mask

#: Database schema version and table definitions, see "Storage" in docs/DESIGN.md. Id 0
#: in each lookup table is the "empty/unknown" sentinel. `family` is AF_INET (2),
#: AF_INET6 (10), AF_PACKET (17) for raw L2 sends, or 0 when unknown. `protocol` is an
#: IPPROTO_* value (TCP=6, UDP=17, ...) or 0 when unknown. A network namespace is
#: interned with the name it had when the row was written, as the kernel reuses its
#: inode. A raw row's `time` is the end of its write window, a rollup's `period` the
#: start of its period, and `seconds` how long either is.
DB_VERSION: typing.Final[int] = 8
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
SCHEMA_NETNS: typing.Final[str] = """
    id INTEGER PRIMARY KEY,
    inode INTEGER NOT NULL,
    name TEXT NOT NULL,
    UNIQUE(inode, name)"""
SCHEMA_INTERFACES: typing.Final[str] = """
    id INTEGER PRIMARY KEY,
    netns_id INTEGER NOT NULL REFERENCES netns(id),
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    UNIQUE(netns_id, name, kind)"""
SCHEMA_CONNECTIONS: typing.Final[str] = """
    time INTEGER NOT NULL,
    sent INTEGER NOT NULL,
    received INTEGER NOT NULL,
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
    netns_id INTEGER NOT NULL REFERENCES netns(id),
    iface_id INTEGER NOT NULL REFERENCES interfaces(id),
    seconds INTEGER NOT NULL"""
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
    netns_id INTEGER NOT NULL REFERENCES netns(id),
    iface_id INTEGER NOT NULL REFERENCES interfaces(id),
    sent INTEGER NOT NULL,
    received INTEGER NOT NULL,
    events INTEGER NOT NULL,
    rows INTEGER NOT NULL,
    seconds INTEGER NOT NULL"""
SCHEMA_INTERFACE_TRAFFIC: typing.Final[str] = """
    time INTEGER NOT NULL,
    iface_id INTEGER NOT NULL REFERENCES interfaces(id),
    sent INTEGER NOT NULL,
    received INTEGER NOT NULL,
    seconds INTEGER NOT NULL"""
SCHEMA_INTERFACE_TRAFFIC_ROLLUP: typing.Final[str] = """
    period INTEGER NOT NULL,
    iface_id INTEGER NOT NULL REFERENCES interfaces(id),
    sent INTEGER NOT NULL,
    received INTEGER NOT NULL,
    seconds INTEGER NOT NULL"""
SCHEMA_FORWARDED: typing.Final[str] = """
    time INTEGER NOT NULL,
    netns_id INTEGER NOT NULL REFERENCES netns(id),
    protocol INTEGER NOT NULL,
    src_id INTEGER NOT NULL REFERENCES addresses(id),
    sport INTEGER NOT NULL,
    dst_id INTEGER NOT NULL REFERENCES addresses(id),
    dport INTEGER NOT NULL,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    orig_bytes INTEGER NOT NULL,
    reply_bytes INTEGER NOT NULL,
    orig_packets INTEGER NOT NULL,
    reply_packets INTEGER NOT NULL,
    seconds INTEGER NOT NULL"""
SCHEMA_FORWARDED_ROLLUP: typing.Final[str] = """
    period INTEGER NOT NULL,
    netns_id INTEGER NOT NULL REFERENCES netns(id),
    protocol INTEGER NOT NULL,
    src_id INTEGER NOT NULL REFERENCES addresses(id),
    dport INTEGER NOT NULL,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    orig_bytes INTEGER NOT NULL,
    reply_bytes INTEGER NOT NULL,
    orig_packets INTEGER NOT NULL,
    reply_packets INTEGER NOT NULL,
    rows INTEGER NOT NULL,
    seconds INTEGER NOT NULL"""
SCHEMA_META: typing.Final[str] = """
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL"""
#: Every table with its schema, in creation order, and the sentinel row of each lookup
#: table.
TABLES: typing.Final[tuple[tuple[str, str], ...]] = (
    ("executables", SCHEMA_EXECUTABLES),
    ("domains", SCHEMA_DOMAINS),
    ("addresses", SCHEMA_ADDRESSES),
    ("units", SCHEMA_UNITS),
    ("netns", SCHEMA_NETNS),
    ("interfaces", SCHEMA_INTERFACES),
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
    "INSERT INTO netns(id, inode, name) VALUES (0, 0, '')",
    "INSERT INTO interfaces(id, netns_id, name, kind) VALUES (0, 0, '', '')",
)
#: Time, and the lookups a drill-down filters by most: executable, parent, unit and
#: domain (see "Indexes" in docs/performance.md). There is no ANALYZE: with its
#: statistics SQLite answers unfiltered queries through an executable index, twice as
#: slow.
INDEXES: typing.Final[tuple[str, ...]] = (
    "CREATE INDEX idx_connections_time ON connections(time)",
    "CREATE INDEX idx_connections_exe_id_time ON connections(exe_id, time)",
    "CREATE INDEX idx_connections_pexe_id_time ON connections(pexe_id, time)",
    "CREATE INDEX idx_connections_unit_id_time ON connections(unit_id, time)",
    "CREATE INDEX idx_connections_domain_id_time ON connections(domain_id, time)",
    "CREATE INDEX idx_connections_rollup_period ON connections_rollup(period)",
    "CREATE INDEX idx_connections_rollup_exe_id_period ON connections_rollup(exe_id, period)",
    "CREATE INDEX idx_connections_rollup_pexe_id_period ON connections_rollup(pexe_id, period)",
    "CREATE INDEX idx_connections_rollup_unit_id_period ON connections_rollup(unit_id, period)",
    "CREATE INDEX idx_connections_rollup_domain_id_period ON connections_rollup(domain_id, period)",
    "CREATE INDEX idx_interface_traffic_time ON interface_traffic(time)",
    "CREATE INDEX idx_interface_traffic_rollup_period ON interface_traffic_rollup(period)",
    "CREATE INDEX idx_forwarded_time ON forwarded(time)",
    "CREATE INDEX idx_forwarded_rollup_period ON forwarded_rollup(period)",
)
