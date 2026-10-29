# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import dataclasses
import fnmatch
import grp
import ipaddress
import logging
import math
import tomllib
from pathlib import Path

from tracct.constants import CONFIG_PATH
from tracct.messages import DEFAULTS, LEVEL_NAMES

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class DatabaseConfig:
    enabled: bool = True
    #: Rows per write window; rollups per period, which outlive them. Fractions of a day
    #: are allowed, so a test can run through retention in minutes.
    raw_retention_days: float = 30.0
    rollup_retention_days: float = 365.0
    rollup_period_minutes: int = 60
    write_limit_seconds: int = 10
    maintenance_interval_minutes: int = 60


#: The keys of a [[record.process]] rule that pick its processes, and those that set
#: what is recorded of them.
RULE_PATTERNS = ("exe", "name", "unit")
RULE_SETTINGS = ("addresses", "ports", "commands")


@dataclasses.dataclass(frozen=True)
class ProcessRule:
    """What is recorded of the processes matching every pattern given; a setting left
    out (None) stays as [record] has it.
    """

    exe: str | None = None
    name: str | None = None
    unit: str | None = None
    addresses: bool | None = None
    ports: bool | None = None
    commands: bool | None = None

    def matches(self, exe: str, name: str, unit: str) -> bool:
        patterns = (self.exe, self.name, self.unit)
        return all(
            pattern is None or fnmatch.fnmatchcase(value, pattern)
            for pattern, value in zip(patterns, (exe, name, unit))
        )


@dataclasses.dataclass
class RecordConfig:
    addresses: bool = True
    #: PTR queries for remote addresses the program looked up no name for.
    reverse_dns: bool = True
    commands: bool = True
    ports: bool = True
    ignore_ports: list[int] = dataclasses.field(default_factory=list)
    ignore_domains: list[str] = dataclasses.field(default_factory=list)
    ignore_ips: list[str] = dataclasses.field(default_factory=list)
    #: Tables as read, ProcessRules once load_config() has checked them.
    process: list[ProcessRule] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class MonitoringConfig:
    every_exe: bool = False
    #: Attribute receives that never issue a recvmsg; off by default, adds a per-frame
    #: softirq hook.
    mmap_ring_rx: bool = False
    exec_ring_buffer_pages: int = 256
    conn_map_max_entries: int = 65536
    st_dev_mask: int | None = None
    #: Forwarded traffic from the kernel's connection tracking (needs CAP_NET_ADMIN,
    #: nf_conntrack_acct).
    conntrack: bool = True


@dataclasses.dataclass
class ViewerConfig:
    #: Group whose members may connect to events.sock (the live tab of view); empty
    #: keeps the daemon's own group.
    group: str = ""


@dataclasses.dataclass
class Config:
    database: DatabaseConfig = dataclasses.field(default_factory=DatabaseConfig)
    record: RecordConfig = dataclasses.field(default_factory=RecordConfig)
    #: Message ID -> level name, for the messages not logged at their default level.
    log: dict[str, str] = dataclasses.field(default_factory=dict)
    monitoring: MonitoringConfig = dataclasses.field(default_factory=MonitoringConfig)
    viewer: ViewerConfig = dataclasses.field(default_factory=ViewerConfig)


def config_files(config_path: Path = CONFIG_PATH) -> list[Path]:
    """Return the files a config is read from, in the order they apply.

    config.toml comes first, then the drop-ins in config.d beside it in name order, so
    local settings outlive a config.toml that `tracct install -f` replaces.
    """
    files = [config_path] if config_path.exists() else []
    drop_ins = config_path.parent / "config.d"
    if drop_ins.is_dir():
        files += sorted(path for path in drop_ins.glob("*.toml") if path.is_file())
    return files


def _apply(config: Config, raw: dict, path: Path) -> None:
    """Set the options of one file on `config`, warning about what doesn't fit."""
    section_names = {section_field.name for section_field in dataclasses.fields(config)}
    for section_name in raw:
        if section_name not in section_names:
            logger.warning(f"{path}: {section_name}: unknown section, ignoring")
    for section_field in dataclasses.fields(config):
        section_name = section_field.name
        if section_name not in raw:
            continue
        section_data = raw[section_name]
        if not isinstance(section_data, dict):
            # Valid TOML but wrong shape (e.g. `monitoring = 5` instead of
            # `[monitoring]`); skip so `field.name in section_data` can't raise and
            # crash-loop the daemon.
            logger.warning(
                f"{path}: {section_name}: expected a table, got {type(section_data).__name__}, ignoring"
            )
            continue
        section_obj = getattr(config, section_name)
        if isinstance(section_obj, dict):
            # A table section adds to the earlier files' rather than replacing it, so a
            # drop-in can set one key; load_config() checks its keys.
            setattr(config, section_name, {**section_obj, **section_data})
            continue
        field_names = {field.name for field in dataclasses.fields(section_obj)}
        for key in section_data:
            if key not in field_names:
                logger.warning(
                    f"{path}: {section_name}.{key}: unknown option, ignoring"
                )
        for field in dataclasses.fields(section_obj):
            if field.name in section_data:
                value = section_data[field.name]
                expected_type = field.type
                if hasattr(expected_type, "__origin__"):
                    # Parameterized generics (list[int]): enforce the container type, a
                    # scalar here would break the writer's filters on every batch.
                    if expected_type.__origin__ is list and not isinstance(value, list):
                        logger.warning(
                            f"{path}: {section_name}.{field.name}: expected a list, got {type(value).__name__}, skipping"
                        )
                        continue
                elif not isinstance(expected_type, type):
                    # field.type may be a forward-ref string under `from __future__
                    # import annotations`.
                    pass
                elif (
                    expected_type is float
                    and isinstance(value, int)
                    and not isinstance(value, bool)
                ):
                    # TOML reads 30 as an integer.
                    value = float(value)
                elif not isinstance(value, expected_type) or (
                    isinstance(value, bool) and expected_type is not bool
                ):
                    type_name = getattr(expected_type, "__name__", str(expected_type))
                    logger.warning(
                        f"{path}: {section_name}.{field.name}: expected {type_name}, got {type(value).__name__}, skipping"
                    )
                    continue
                setattr(section_obj, field.name, value)


def _rule_problem(rule: object) -> str | None:
    """Why a [[record.process]] entry can't be used, or None. A rule without patterns
    would match every process, one without settings would change nothing.
    """
    if not isinstance(rule, dict):
        return f"expected a table, got {type(rule).__name__}"
    unknown = set(rule) - set(RULE_PATTERNS) - set(RULE_SETTINGS)
    if unknown:
        return f"unknown option {', '.join(sorted(unknown))}"
    for key in RULE_PATTERNS:
        if key in rule and not isinstance(rule[key], str):
            return f"{key}: expected a pattern, got {rule[key]!r}"
    for key in RULE_SETTINGS:
        if key in rule and not isinstance(rule[key], bool):
            return f"{key}: expected true or false, got {rule[key]!r}"
    if not any(key in rule for key in RULE_PATTERNS):
        return f"names none of {', '.join(RULE_PATTERNS)}"
    if not any(key in rule for key in RULE_SETTINGS):
        return f"sets none of {', '.join(RULE_SETTINGS)}"
    return None


def load_config(config_path: Path = CONFIG_PATH) -> Config:
    """Load config.toml and its drop-ins over the defaults.

    A later file wins per option, a list replaces the one before and a table adds to it.
    Missing files mean all defaults.
    """
    config = Config()
    for path in config_files(config_path):
        try:
            with open(path, "rb") as f:
                raw = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
            # Never crash-loop the daemon on a malformed config; the other files still
            # apply.
            logger.error(f"failed to read {path}, ignoring it: {e}")
            continue
        _apply(config, raw, path)
    # Clamp values that would otherwise fail the BPF load and restart-loop the daemon.
    pages = config.monitoring.exec_ring_buffer_pages
    if pages < 1 or pages > 16384 or (pages & (pages - 1)) != 0:
        logger.warning(
            f"monitoring.exec_ring_buffer_pages must be a power of two in [1, 16384], got {pages}, using 256"
        )
        config.monitoring.exec_ring_buffer_pages = 256
    entries = config.monitoring.conn_map_max_entries
    if entries < 1 or entries > 1048576:
        logger.warning(
            f"monitoring.conn_map_max_entries must be in [1, 1048576], got {entries}, using 65536"
        )
        config.monitoring.conn_map_max_entries = 65536
    dev_mask = config.monitoring.st_dev_mask
    if dev_mask is not None and (
        isinstance(dev_mask, bool)
        or not isinstance(dev_mask, int)
        or not 0 <= dev_mask <= 0xFFFFFFFF
    ):
        logger.warning(
            f"monitoring.st_dev_mask must be in [0, 4294967295], got {dev_mask!r}, ignoring"
        )
        config.monitoring.st_dev_mask = None
    # Reject negatives (a negative retention makes the cutoff a future time, which
    # wipes the db) and TOML's inf and nan, which would make the cutoff meaningless.
    for key, default in (
        ("raw_retention_days", 30.0),
        ("rollup_retention_days", 365.0),
    ):
        retention = getattr(config.database, key)
        if not math.isfinite(retention) or retention < 0:
            logger.warning(
                f"database.{key} must not be negative, got {retention}, using {default}"
            )
            setattr(config.database, key, default)
    period = config.database.rollup_period_minutes
    if not 1 <= period <= 1440:
        logger.warning(
            f"database.rollup_period_minutes must be in [1, 1440], got {period}, using 60"
        )
        config.database.rollup_period_minutes = 60
    write_limit = config.database.write_limit_seconds
    if write_limit < 0:
        logger.warning(
            f"database.write_limit_seconds must not be negative, got {write_limit}, using 10"
        )
        config.database.write_limit_seconds = 10
    interval = config.database.maintenance_interval_minutes
    if interval < 1:
        logger.warning(
            f"database.maintenance_interval_minutes must be at least 1, got {interval}, using 60"
        )
        config.database.maintenance_interval_minutes = 60
    # Reset a group that doesn't resolve, else the daemon can't hand the sockets to it.
    if config.viewer.group:
        try:
            grp.getgrnam(config.viewer.group)
        except KeyError:
            logger.warning(
                f"config.viewer.group: {config.viewer.group!r} does not exist, ignoring"
            )
            config.viewer.group = ""
    # Drop record.ignore_ips entries that aren't valid networks (strict=False accepts a
    # host-bit CIDR); otherwise the writer crashes building ignored_networks at start,
    # outside its try/except.
    valid_ignore_ips = []
    for ip_subnet in config.record.ignore_ips:
        try:
            ipaddress.ip_network(ip_subnet, strict=False)
        except (ValueError, TypeError):
            logger.warning(
                f"config.record.ignore_ips: {ip_subnet!r} is not a valid network, ignoring"
            )
            continue
        valid_ignore_ips.append(ip_subnet)
    config.record.ignore_ips = valid_ignore_ips
    # Drop ignore_domains entries that aren't non-empty strings: a non-str breaks the
    # writer's startswith() filter on every write (nothing gets recorded), an empty
    # string prefixes every domain (silently dropping all connections).
    valid_ignore_domains = []
    for domain_prefix in config.record.ignore_domains:
        if not isinstance(domain_prefix, str) or not domain_prefix:
            logger.warning(
                f"config.record.ignore_domains: {domain_prefix!r} is not a non-empty string, ignoring"
            )
            continue
        valid_ignore_domains.append(domain_prefix)
    config.record.ignore_domains = valid_ignore_domains
    config.record.ignore_ports = [
        port
        for port in config.record.ignore_ports
        if isinstance(port, int) and not isinstance(port, bool) and -1 <= port <= 65535
    ]
    rules = []
    for number, rule in enumerate(config.record.process, 1):
        problem = _rule_problem(rule)
        if problem:
            logger.warning(f"config.record.process #{number}: {problem}, ignoring")
        else:
            rules.append(ProcessRule(**rule))
    config.record.process = rules
    # Drop unknown messages and levels; set_levels() takes the rest as they are.
    valid_messages = {}
    for msgid, level in config.log.items():
        if msgid not in DEFAULTS:
            logger.warning(f"config.log: unknown message {msgid!r}, ignoring")
        elif not isinstance(level, str) or level not in LEVEL_NAMES:
            logger.warning(
                f"config.log.{msgid}: expected one of {', '.join(LEVEL_NAMES)}, got {level!r}, ignoring"
            )
        else:
            valid_messages[msgid] = level
    config.log = valid_messages
    return config
