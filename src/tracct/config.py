# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import dataclasses
import grp
import ipaddress
import logging
import math
import tomllib
from pathlib import Path

from tracct.constants import CONFIG_PATH


@dataclasses.dataclass
class DatabaseConfig:
    enabled: bool = True
    # rows per write window; rollups per period, which outlive them. fractions of a day are
    # allowed, so a test can run through retention in minutes
    raw_retention_days: float = 30.0
    rollup_retention_days: float = 365.0
    rollup_period_minutes: int = 60
    write_limit_seconds: int = 10
    maintenance_interval_minutes: int = 60


@dataclasses.dataclass
class LogConfig:
    addresses: bool = True
    # PTR queries for remote addresses the program looked up no name for
    reverse_dns: bool = True
    commands: bool = True
    ports: bool = True
    ignore_ports: list[int] = dataclasses.field(default_factory=list)
    ignore_domains: list[str] = dataclasses.field(default_factory=list)
    ignore_ips: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class MonitoringConfig:
    every_exe: bool = False
    # attribute receives that never issue a recvmsg; off by default, adds a per-frame softirq hook
    mmap_ring_rx: bool = False
    exec_ring_buffer_pages: int = 256
    conn_map_max_entries: int = 65536
    st_dev_mask: int | None = None
    # forwarded traffic from the kernel's connection tracking (needs CAP_NET_ADMIN, nf_conntrack_acct)
    conntrack: bool = True


@dataclasses.dataclass
class ViewerConfig:
    # group whose members may connect to events.sock (the live tab of view); empty keeps the daemon's own group
    group: str = ""


@dataclasses.dataclass
class Config:
    database: DatabaseConfig = dataclasses.field(default_factory=DatabaseConfig)
    log: LogConfig = dataclasses.field(default_factory=LogConfig)
    monitoring: MonitoringConfig = dataclasses.field(default_factory=MonitoringConfig)
    viewer: ViewerConfig = dataclasses.field(default_factory=ViewerConfig)


def load_config(config_path: Path = CONFIG_PATH) -> Config:
    """Load config.toml, merging with defaults. A missing file means all defaults."""
    config = Config()
    if config_path.exists():
        try:
            with open(config_path, "rb") as f:
                raw = tomllib.load(f)
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
            # never crash-loop the daemon on a malformed config; fall back to defaults
            logging.error(f"failed to read {config_path}, using defaults: {e}")
            raw = {}
        section_names = {section_field.name for section_field in dataclasses.fields(config)}
        for section_name in raw:
            if section_name not in section_names:
                logging.warning(f"config.{section_name}: unknown section, ignoring")
        for section_field in dataclasses.fields(config):
            section_name = section_field.name
            if section_name not in raw:
                continue
            section_data = raw[section_name]
            if not isinstance(section_data, dict):
                # valid TOML but wrong shape (e.g. `monitoring = 5` instead of `[monitoring]`);
                # skip so `field.name in section_data` can't raise and crash-loop the daemon
                logging.warning(f"config.{section_name}: expected a table, got {type(section_data).__name__}, ignoring")
                continue
            section_obj = getattr(config, section_name)
            field_names = {field.name for field in dataclasses.fields(section_obj)}
            for key in section_data:
                if key not in field_names:
                    logging.warning(f"config.{section_name}.{key}: unknown option, ignoring")
            for field in dataclasses.fields(section_obj):
                if field.name in section_data:
                    value = section_data[field.name]
                    expected_type = field.type
                    if hasattr(expected_type, "__origin__"):
                        # parameterized generics (list[int]): enforce the container type, a
                        # scalar here would break the writer's filters on every batch
                        if expected_type.__origin__ is list and not isinstance(value, list):
                            logging.warning(f"config.{section_name}.{field.name}: expected a list, got {type(value).__name__}, skipping")
                            continue
                    elif not isinstance(expected_type, type):
                        # field.type may be a forward-ref string under `from __future__ import annotations`
                        pass
                    elif expected_type is float and isinstance(value, int) and not isinstance(value, bool):
                        # TOML reads 30 as an integer
                        value = float(value)
                    elif not isinstance(value, expected_type) or (isinstance(value, bool) and expected_type is not bool):
                        type_name = getattr(expected_type, "__name__", str(expected_type))
                        logging.warning(f"config.{section_name}.{field.name}: expected {type_name}, got {type(value).__name__}, skipping")
                        continue
                    setattr(section_obj, field.name, value)
    # clamp values that would otherwise fail the BPF load and restart-loop the daemon
    pages = config.monitoring.exec_ring_buffer_pages
    if pages < 1 or pages > 16384 or (pages & (pages - 1)) != 0:
        logging.warning(f"monitoring.exec_ring_buffer_pages must be a power of two in [1, 16384], got {pages}, using 256")
        config.monitoring.exec_ring_buffer_pages = 256
    entries = config.monitoring.conn_map_max_entries
    if entries < 1 or entries > 1048576:
        logging.warning(f"monitoring.conn_map_max_entries must be in [1, 1048576], got {entries}, using 65536")
        config.monitoring.conn_map_max_entries = 65536
    dev_mask = config.monitoring.st_dev_mask
    if dev_mask is not None and (isinstance(dev_mask, bool) or not isinstance(dev_mask, int) or not 0 <= dev_mask <= 0xFFFFFFFF):
        logging.warning(f"monitoring.st_dev_mask must be in [0, 4294967295], got {dev_mask!r}, ignoring")
        config.monitoring.st_dev_mask = None
    # reject negatives (a negative retention makes the cutoff a future time -> wipes the db) and
    # TOML's inf and nan, which would make the cutoff meaningless
    for key, default in (("raw_retention_days", 30.0), ("rollup_retention_days", 365.0)):
        retention = getattr(config.database, key)
        if not math.isfinite(retention) or retention < 0:
            logging.warning(f"database.{key} must not be negative, got {retention}, using {default}")
            setattr(config.database, key, default)
    period = config.database.rollup_period_minutes
    if not 1 <= period <= 1440:
        logging.warning(f"database.rollup_period_minutes must be in [1, 1440], got {period}, using 60")
        config.database.rollup_period_minutes = 60
    write_limit = config.database.write_limit_seconds
    if write_limit < 0:
        logging.warning(f"database.write_limit_seconds must not be negative, got {write_limit}, using 10")
        config.database.write_limit_seconds = 10
    interval = config.database.maintenance_interval_minutes
    if interval < 1:
        logging.warning(f"database.maintenance_interval_minutes must be at least 1, got {interval}, using 60")
        config.database.maintenance_interval_minutes = 60
    # reset a group that doesn't resolve, else the daemon can't hand the sockets to it
    if config.viewer.group:
        try:
            grp.getgrnam(config.viewer.group)
        except KeyError:
            logging.warning(f"config.viewer.group: {config.viewer.group!r} does not exist, ignoring")
            config.viewer.group = ""
    # drop log.ignore_ips entries that aren't valid networks (strict=False accepts a host-bit CIDR);
    # otherwise the writer crashes building ignored_networks at start, outside its try/except
    valid_ignore_ips = []
    for ip_subnet in config.log.ignore_ips:
        try:
            ipaddress.ip_network(ip_subnet, strict=False)
        except (ValueError, TypeError):
            logging.warning(f"config.log.ignore_ips: {ip_subnet!r} is not a valid network, ignoring")
            continue
        valid_ignore_ips.append(ip_subnet)
    config.log.ignore_ips = valid_ignore_ips
    # drop ignore_domains entries that aren't non-empty strings: a non-str breaks the writer's
    # startswith() filter on every write (nothing gets recorded), an empty string prefixes every
    # domain (silently dropping all connections)
    valid_ignore_domains = []
    for domain_prefix in config.log.ignore_domains:
        if not isinstance(domain_prefix, str) or not domain_prefix:
            logging.warning(f"config.log.ignore_domains: {domain_prefix!r} is not a non-empty string, ignoring")
            continue
        valid_ignore_domains.append(domain_prefix)
    config.log.ignore_domains = valid_ignore_domains
    config.log.ignore_ports = [port for port in config.log.ignore_ports if isinstance(port, int) and not isinstance(port, bool) and -1 <= port <= 65535]
    return config
