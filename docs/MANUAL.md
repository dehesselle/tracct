# Manual

This document covers the `tracct` commands, the configuration file and the paths the
daemon and viewers use. Installing and running the unit is in [OPERATIONS.md](OPERATIONS.md).

## Commands

```text
tracct [-h] [--version] {run,view,query-server}
```

| Command | What it does | Needs |
| --- | --- | --- |
| `run` | the daemon, in the foreground; this is what the unit starts | the capabilities in [OPERATIONS.md](OPERATIONS.md#capabilities) |
| `view` | the viewer: live traffic and the history of processes, interfaces and forwarded flows | `tracct[tui]`, access to `events.sock` and the query socket |
| `query-server` | answer the viewer's history queries; this is what `tracct-query.service` starts | read access to the database |

`--version` prints the version. `-h` prints the usage, and on its own also the resolved
paths; after a command it prints that command's options.

`view` works for root and for members of the viewer group (`[viewer] group`, and the group
of `tracct-query.socket`). Press `?` in it for its keys.

### The viewer

`tracct view` needs the `tui` extra (`uv pip install 'tracct[tui]'`). It has four
tabs, switched with `1` to `4`:

- **Live**: connections as the daemon drains them, with totals per executable since the tab
  started and the ports each listens on (for processes the viewer's user may inspect, all of
  them as root). It keeps the newest 500 events and 100 executables; past that, the
  executables idle the longest are dropped. `p` pauses the list, `r` resets.
- **Processes** (socket bytes), **Interfaces** (interface bytes) and **Forwarded** (IP bytes
  of routed flows): the history, grouped by the dimension chosen on the left, over the time
  range in the header. The three kinds of bytes are never added together.

In a history tab, `Enter` keeps only the highlighted row's value and `e` excludes it; the
filters stack up in the header, and `Backspace` takes the last one off. The timeline above
the table shows the highlighted row, or all rows after `a`, in buckets of a round length
from 10 seconds up; dimmed buckets come from rollups. In the timeline, `←` and `→` pick a
bucket and `Enter` narrows the range to it, `z` goes back. `t` cycles the span (last
hour, last day, ...), `h` and `H` step back and forward by a whole span, `u` cycles the byte
units, `/` finds text in the rows shown, `r` refreshes. A range that ends now refreshes
every 10 seconds.

Commands of two keys start with `,`, and a pause after it lists what can follow. `,` `s`
opens the viewer's settings, such as the live tab's limits. They are kept per user in
`~/.config/tracct/settings.json` (under `$XDG_CONFIG_HOME` if set), which holds only the
values changed from their defaults.

Ranges older than the raw rows come from the rollups: whole periods, no addresses except a
forwarded flow's source, ephemeral ports as 0. Dimensions marked "raw only" narrow the range
to the raw rows, and the status line says from when.

```text
tracct view [--tab live|processes|interfaces|forwarded] [--events-socket PATH] [--query-socket PATH]
```

## Configuration

The daemon reads `config.toml` once at startup; restart the unit after a change. A missing
file means all defaults. Unknown sections and keys are reported in the journal and ignored;
a value of the wrong type is skipped with a warning; an unreadable file falls back to all
defaults.

```toml
[database]
enabled = true              # record to SQLite; false leaves only the live feed
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
conntrack = true            # record forwarded traffic of every namespace from connection tracking (needs nf_conntrack_acct = 1)

[viewer]
group = ""                  # group that gets events.sock; empty keeps the daemon's own
```

Out-of-range values for `exec_ring_buffer_pages`, `conn_map_max_entries`,
`raw_retention_days`, `rollup_retention_days` (negative, `inf` or `nan`), `rollup_period_minutes` (1 to 1440),
`write_limit_seconds`, `maintenance_interval_minutes` and `st_dev_mask` are replaced by
their defaults with a warning.

Both retentions take fractions of a day, down to seconds: `raw_retention_days = 0.0069`
keeps about ten minutes, which lets a test run through retention without waiting a day.
Raw rows past `raw_retention_days` are only deleted once their period is rolled up. A change
of `rollup_period_minutes` applies to the periods from then on. Invalid `ignore_*` entries
are dropped. A `[viewer] group` that does not exist is ignored. The `[log]` settings apply to
forwarded flows too.

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
| configuration file | `TRACCT_CONFIG` (a file), else `$CONFIGURATION_DIRECTORY/config.toml` | `/etc/opt/tracct/config.toml` |
| state directory with `tracct.db` | `STATE_DIRECTORY` | `/var/lib/tracct` |
| runtime directory with `events.sock`, `tracct.lock` | `RUNTIME_DIRECTORY` | `/run/tracct` |
| query socket, from `tracct-query.socket` | `TRACCT_QUERY_SOCKET` | `/run/tracct-query.sock` |

When a variable lists several directories separated by colons, the first one is used. The
options of `view` override both sockets. Outside socket activation, `query-server` creates its
socket itself and runs until stopped.

The database is read through `view`. Its tables are internal and change between versions
without migration (see [DESIGN.md](DESIGN.md#storage)).
