# Manual

This document covers the `picosnitch` commands, the configuration file and the paths the
daemon and viewers use. Installing and running the unit is in [OPERATIONS.md](OPERATIONS.md).

## Commands

```text
picosnitch run|top|tui|version|help
```

| Command | What it does | Needs |
| --- | --- | --- |
| `run` | the daemon, in the foreground; this is what the unit starts | the capabilities in [OPERATIONS.md](OPERATIONS.md#capabilities) |
| `top` | live feed: connections as the daemon sees them, with per-executable totals | access to `events.sock` |
| `tui` | browse the history by executable, parent, user, port, address, domain or time; also has a live tab | read access to the database |
| `version` | print the version | |
| `help` | print usage and the resolved paths | |

`top` and the live tab of `tui` work for root and for members of the viewer group
(`[viewer] group`). The history in `tui` reads the database directly, which lies in the
dynamic user's private state directory, so it currently works only as root.

Press `?` in `top` or `tui` for their keys.

## Configuration

The daemon reads `config.toml` once at startup; restart the unit after a change. A missing
file means all defaults. Unknown sections and keys are reported in the journal and ignored;
a value of the wrong type is skipped with a warning; an unreadable file falls back to all
defaults.

```toml
[database]
enabled = true              # write connections to SQLite
raw_retention_days = 30     # keep the rows of every write window this long; 0 keeps them forever
rollup_retention_days = 365 # keep the rollups this long; 0 keeps them forever
rollup_period_minutes = 60  # the rows of each period are summed into rollups once it has closed
write_limit_seconds = 10    # length of a write window: traffic is summed per connection and window
maintenance_interval_minutes = 60  # how often rollups and purges run, besides at startup

[log]
addresses = true            # store remote addresses and domains
reverse_dns = true          # name addresses no program looked up by a PTR query (needs addresses)
commands = true             # store command lines of the process and its parent
ports = true                # store local and remote ports
ignore_ports = []           # connections with a matching local or remote port are not stored
ignore_domains = []         # domain prefixes in reversed notation, e.g. "com.example." matches all subdomains
ignore_ips = []             # addresses or networks, e.g. "10.0.0.0/8", matched against both ends

[monitoring]
every_exe = false           # also store every executed program as a row without traffic (ports -1)
mmap_ring_rx = false        # count AF_PACKET/AF_XDP mmap-ring receives; adds a per-frame softirq hook
exec_ring_buffer_pages = 256  # size of the exec event ring buffer, a power of two up to 16384
conn_map_max_entries = 65536  # connections the kernel can hold between drains, up to 1048576
# st_dev_mask = 0           # mask for device numbers in inode checks; auto-detected (0 on btrfs)
conntrack = true            # record forwarded traffic from connection tracking (needs nf_conntrack_acct = 1)

[viewer]
group = ""                  # group that gets the daemon's sockets; empty keeps the daemon's own
```

Out-of-range values for `exec_ring_buffer_pages`, `conn_map_max_entries`,
`raw_retention_days`, `rollup_retention_days`, `rollup_period_minutes` (1 to 1440),
`write_limit_seconds`, `maintenance_interval_minutes` and `st_dev_mask` are replaced by
their defaults with a warning.

Raw rows past `raw_retention_days` are only deleted once their period is rolled up. A change
of `rollup_period_minutes` applies to the periods from then on. Invalid `ignore_*` entries are dropped. A `[viewer] group` that does not
exist is ignored.

Domains in the database are stored in reversed notation (`com.example.www`), which is what
`ignore_domains` prefixes match. A domain is the name the program looked up, else the
reverse DNS name; a connection whose reverse DNS answer was still outstanding when its
window was written has none, and `ignore_domains` cannot match it.

## Paths

The daemon takes its directories from the variables systemd sets for the unit's
`*Directory=` settings, so the unit decides where they are. Outside a unit the defaults
apply. Viewers use the same rules, so they find the defaults unless the variables are set.

| What | Variable | Default |
| --- | --- | --- |
| configuration file | `PICOSNITCH_CONFIG` (a file), else `$CONFIGURATION_DIRECTORY/config.toml` | `/etc/opt/picosnitch/config.toml` |
| state directory with `picosnitch.db` | `STATE_DIRECTORY` | `/var/lib/picosnitch` |
| runtime directory with `events.sock`, `picosnitch.lock` | `RUNTIME_DIRECTORY` | `/run/picosnitch` |

When a variable lists several directories separated by colons, the first one is used.

## Querying the database

The database is plain SQLite; see [schema.md](schema.md) for the tables and example queries.
Open it read-only (`file:…?mode=ro`) while the daemon runs.
