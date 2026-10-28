# Manual

This document covers the `tracct` commands, the configuration file and the paths the
daemon and viewers use. Installing and running the unit is in [OPERATIONS.md](OPERATIONS.md).

## Commands

```text
tracct [-h] [--version] {run,view,query-server,install}
```

| Command | What it does | Needs |
| --- | --- | --- |
| `run` | the daemon, in the foreground; this is what the unit starts | the capabilities in [OPERATIONS.md](OPERATIONS.md#capabilities) |
| `view` | the viewer: live traffic and the history of processes, interfaces and forwarded flows | `tracct[viewer]`, access to `events.sock` and the query socket |
| `query-server` | answer the viewer's history queries; this is what `tracct-query.service` starts | read access to the database |
| `install` | write the systemd units, the sysusers file and the base configuration | root, else it writes into a temporary directory |

`--version` prints the version. `-h` prints the usage, and on its own also the resolved
paths; after a command it prints that command's options.

`view` works for root and for members of the viewer group (`[viewer] group`, and the group
of `tracct-query.socket`). Its footer shows the keys of the tab in view; `Ctrl+Q` quits.

### The viewer

`tracct view` needs the `viewer` extra (`uv pip install 'tracct[viewer]'`). It has four
tabs, Live first and then the history tabs in alphabetical order, switched with the letter
highlighted in their title (`l`, `f`, `i`, `p`). It opens on Live unless `--tab` names
another:

- **Live**: connections as the daemon drains them, with totals per executable since the tab
  started. It keeps the newest 500 events and 100 executables; past that, the executables
  idle the longest are dropped, and the summary's title counts them along with the seconds
  since the tab started. The events table's title counts all events; a line above the tables
  appears only for a problem with the feed or an active find. Clicking a column's header
  sorts by it, clicking it again reverses; the executables start sorted by path, the events
  newest first. `Space` pauses the events table, `r` resets both.
- **Forwarded** (IP bytes of routed flows), **Interfaces** (interface bytes) and
  **Processes** (socket bytes): the history, grouped by the dimension chosen on the left, over the time
  range named at the start of the plot's title. The three kinds of bytes are never added
  together.

A history table starts with the sums over all its rows. On Processes and Interfaces there is
one per layer, `(all · inner)`, `(all · tunnel)` and `(all · outer)`, as a VPN's traffic shows
once per layer and adding them up would count it two or three times: inner is what goes
through a VPN, seen at the program's socket or the `tun` device; tunnel the same at the VPN
client; outer everything else, which is what leaves the network card (the VPN's own
encrypted traffic too) and localhost. On Forwarded there is one `(all)`. The highlight starts
on the largest row below them; a find hides them, as they sum up the rows it hides too. The
table's title counts the rows while a find hides some or there are more than it shows (up to
1000).

In a history tab, the chords under `,` `f` filter: `i` keeps only the highlighted row's value
and `e` excludes it, `p` takes the last filter off and `c` all of them. A filter stays when
another dimension is chosen on the left, which breaks the kept value down: keep an
executable, then choose domain to see whom it talked to, with the sums above as its total.
The filters stack up in a line above the tab. As on the live tab, that line also holds a
kept find and any problem with the query server, and it appears only while there is one of
them. The plot above the table draws the highlighted row, a sum too, as a line each for sent
and received. A point is the highest rate of
any 10 seconds within its bucket (a whole period in the rollups), so a short spike keeps its
height at any zoom; if the daemon writes less often than every 10 seconds, the stretch is its
write window and the title says so. A vertical line marks where the rollups end. Hovering
shows a bucket's bytes and peaks in the bottom border.

The plot's time axis is the range of every history tab: the mouse wheel or `+` and `-` zoom,
dragging or `←` and `→` pan, and a moment after the plot comes to rest the tables follow.
`s` picks the span (last hour, last day, ...) from a list, where spans past the oldest data
say so; after a zoom, `s` pressed again in the list returns to the span; `Shift+←` and
`Shift+→` step back and forward by a whole span of local time (with "1 day", yesterday from
midnight to midnight), `u` picks the byte unit from a list, where `u` pressed again goes
back to the unit before, `/` finds text in the rows shown (on every
tab; `c` clears it), `r` refreshes. A range that ends now refreshes every 10 seconds. While a
tab waits more than a moment for the query server, `↻` ends the plot's title.

Commands of two keys start with `,`, and a pause after it lists what can follow. `,` `s`
opens the viewer's settings, such as the live tab's limits. They are kept per user in
`~/.config/tracct/settings.json` (under `$XDG_CONFIG_HOME` if set), which holds only the
values changed from their defaults.

Ranges older than the raw rows come from the rollups: whole periods, no addresses except a
forwarded flow's source, ephemeral ports as 0. Dimensions marked "raw only" narrow the range
to the raw rows. The table's bottom border says from when, or where the rollups begin.

```text
tracct view [--tab live|forwarded|interfaces|processes] [--events-socket PATH] [--query-socket PATH]
```

### Install

```text
tracct install [-f] [--conntrack] [--root DIR]
```

`install` writes these files and prints each one's path with what happened to it: `wrote`,
`same` when it already had this content, or `kept` when it differs:

| File | Written to |
| --- | --- |
| `tracct.service`, `tracct-query.socket`, `tracct-query.service` | `/etc/systemd/system/` |
| the sysusers file, which creates the group `tracct-viewer` | `/etc/sysusers.d/tracct.conf` |
| the base configuration, every option at its default and `[viewer] group = "tracct-viewer"` | `/etc/opt/tracct/config.toml` |
| an empty directory for your own settings | `/etc/opt/tracct/config.d/` |
| with `--conntrack`: load `nf_conntrack` at boot, with `acct=1` | `/etc/modules-load.d/tracct.conf`, `/etc/modprobe.d/tracct.conf` |

The units start the tracct that ran `install`, wherever its venv is. A file that differs is
kept unless `-f` is given; nothing in `config.d/` is ever written, so settings there outlive
`install -f` after an upgrade. Then it prints the commands that create the group and start
the units.

Before writing anything, `install` checks that it may write every file. If one is refused,
nothing goes to the system: every file it would write goes into a new directory such as
`/tmp/tracct-install-k3x9q2`, under the same paths, and it prints the `install` commands
that copy each one in place as root. `--root DIR` writes under `DIR` instead of `/`, for
packaging or to look at the files; there a refused file is an error.

## Configuration

The daemon reads `config.toml` and then every `config.d/*.toml` beside it, in name order,
once at startup; restart the unit after a change. A later file wins per option, and a list
in it replaces the earlier list rather than adding to it. Missing files mean all defaults.
Unknown sections and keys are reported in the journal with their file and ignored; a value
of the wrong type is skipped with a warning; a file that cannot be read is skipped, and the
others still apply.

Keep your own settings in a drop-in such as `config.d/50-local.toml`, since `config.toml` is
the base file that `tracct install -f` replaces (see [Install](#install)):

```toml
[database]
raw_retention_days = 14

[log]
ignore_ports = [22]
```

The options and their defaults:

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
| configuration drop-ins | `config.d/*.toml` beside the configuration file | `/etc/opt/tracct/config.d/` |
| state directory with `tracct.db` | `STATE_DIRECTORY` | `/var/lib/tracct` |
| runtime directory with `events.sock`, `tracct.lock` | `RUNTIME_DIRECTORY` | `/run/tracct` |
| query socket, from `tracct-query.socket` | `TRACCT_QUERY_SOCKET` | `/run/tracct-query.sock` |

When a variable lists several directories separated by colons, the first one is used. The
options of `view` override both sockets. Outside socket activation, `query-server` creates its
socket itself and runs until stopped.

The database is read through `view`. Its tables are internal and change between versions
without migration (see [DESIGN.md](DESIGN.md#storage)).
