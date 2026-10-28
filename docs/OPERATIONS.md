# Operations

This document covers running tracct as a systemd unit: its privileges, what it logs,
how it behaves under load and on failure, upgrades and troubleshooting. The install steps
are in the [README](../README.md).

## The unit

`src/tracct/files/tracct.service` runs `/opt/tracct/bin/tracct run` with:

- `Type=notify`: the unit is started once the BPF probes are attached, so units ordered
  after it are measured.
- `DynamicUser=yes`: an unprivileged user created per start, holding only the capabilities
  below. Its state lives in `/var/lib/private/tracct` (reached through the symlink
  `/var/lib/tracct`), readable by root only.
- `SupplementaryGroups=tracct-viewer`: lets the daemon hand `events.sock` to that
  group (the query socket gets it from its socket unit). The group comes from
  `src/tracct/files/tracct.sysusers`; it cannot be called `tracct`, which `DynamicUser=`
  takes for itself. Set `[viewer] group` to match and add
  viewers with `usermod -aG tracct-viewer <user>`.
- `Restart=always`, `RestartSec=5`: the daemon exits non-zero whenever one of its threads
  dies and is restarted.
- `LimitMEMLOCK=infinity` for the BPF maps and ring buffers.
- `MemoryMax=1G`: a safety net against a leak, above the daemon's bounded memory (see
  [Resource use](#resource-use)); past it systemd kills the daemon and `Restart=` starts it
  again, losing the events still queued. `MemoryCurrent` also counts the page cache of the
  database and sits at the cap once a large database has been read; the kernel then drops
  cache rather than killing the daemon. The daemon's own memory is its PSS
  (`grep Pss /proc/$(systemctl show -p MainPID --value tracct)/smaps_rollup`).

Day to day:

```sh
tracct status                # files, drop-ins, units, conntrack, database
systemctl status tracct
journalctl -u tracct -f
systemctl restart tracct     # after a config change
```

## The query service

The history tabs of `tracct view` ask `tracct-query.service`, which systemd starts
from `src/tracct/files/tracct-query.socket` on the first connection:

- The socket is `/run/tracct-query.sock`, mode 0660, group `tracct-viewer`, set by
  systemd. It is not in `/run/tracct`, which systemd removes whenever `tracct.service`
  stops.
- The service runs `tracct query-server` as the daemon's dynamic user (`User=tracct`)
  with the same `StateDirectory=`, so it can read the database and share its WAL index. It
  opens the database read-only and has no capabilities and no network. It reads the
  daemon's configuration (`config.toml` and its drop-ins) for the write window and rollup
  period, which a plot's peaks are reckoned with.
- It exits after ten minutes without a connected viewer; the next one starts it again.
- `MemoryMax=512M`, `Nice=10` and `IOSchedulingClass=idle`: a heavy query slows or kills the
  query service, not the daemon.
- `CacheDirectory=tracct-query` with `SQLITE_TMPDIR` pointing there: SQLite's temp files
  for sorting a long range go to disk. The private `/var/tmp` that `DynamicUser=` brings is a
  tmpfs on newer systemd (390 MB on a 4 GB host with systemd 259), counted against
  `MemoryMax=`; a 30-day range of 30 million rows filled it.

`tracct install` writes both units; only the socket is enabled, the service needs no
enabling:

```sh
systemctl daemon-reload && systemctl enable --now tracct-query.socket
```

`systemctl stop tracct-query.service` ends a running server; the socket stays and starts
a new one when needed.

## Forwarded traffic

Flows the host or one of its namespaces only routes (an exit node, NAT for containers, a VPN
namespace routing for others) are read from connection tracking, whose entries carry byte
counters only with `nf_conntrack_acct` on. Each network namespace has its own
`nf_conntrack_acct`, and a new one starts from the `nf_conntrack` module's `acct` option, not
from the host's setting. Setting the option when the module loads at boot covers the host and
every namespace created later; `tracct install --conntrack` writes the two files that do so:

```text
/etc/modules-load.d/tracct.conf    nf_conntrack
/etc/modprobe.d/tracct.conf        options nf_conntrack acct=1
```

On a running system, set it for the namespaces still to come and in each existing one, then
restart the unit; flows that started before keep having no counters:

```sh
echo 1 > /sys/module/nf_conntrack/parameters/acct
sysctl -w net.netfilter.nf_conntrack_acct=1
for ns in $(ip netns list | cut -d' ' -f1); do ip netns exec "$ns" sysctl -qw net.netfilter.nf_conntrack_acct=1; done
```

The tables of the daemon's namespace, the named ones (`/run/netns`, `/run/docker/netns`) and
those a recorded process lives in are read. Where flows carry no counters, or the table cannot
be read, the journal says so once per namespace. `[monitoring] conntrack = false` turns the
reading off.

## Capabilities

`tracct run` checks these at startup and exits if one is missing; the unit grants
exactly these.

| Capability | Why |
| --- | --- |
| `CAP_BPF` | load the BPF program and maps |
| `CAP_DAC_READ_SEARCH` | list `/proc/<pid>/fd` of other users' processes, a plain permission check `CAP_SYS_PTRACE` does not override: matching connections open before the start to their processes, finding a process's TUN device |
| `CAP_NET_ADMIN` | read the conntrack table and its events (forwarded traffic), and size netlink receive buffers |
| `CAP_PERFMON` | attach kprobes, uprobes and fexit programs |
| `CAP_SYS_ADMIN` | attach the `getaddrinfo` uprobe, whose perf event the kernel refuses without it at any `perf_event_paranoid` (seen on Ubuntu's 7.0 kernel; without it, domains come from reverse DNS only); join other network namespaces (`setns`) to read their interfaces and conntrack tables |
| `CAP_SYS_PTRACE` | read `/proc/<pid>/exe` and open `/proc/<pid>/ns/net` of other users' processes |
| `CAP_SYSLOG` | not checked; reads kernel symbol addresses, without which io_uring zero-copy receives go uncounted |

## Logs

Everything goes to stderr, which is the journal under the unit; lines carry their syslog
priority, and the name of the module that logged them, such as `tracct.cli` or
`tracct.writer`. Startup logs the resolved config, state and runtime paths. What the
running daemon reports starts with the message's ID in brackets:

```text
tracct.monitor: [exec-ring-full] exec ring buffer full: dropped 12 exec event(s) (total 12); …
```

`[log.messages]` in the configuration sets each message's level, or leaves it out with
`"off"`; the base `config.toml` lists them all at their default levels. For instance, a
host with uutils coreutils that does not need to hear about it once per start:

```toml
# config.d/50-local.toml
[log.messages]
multi-call-inode = "info"
```

The messages, warnings unless marked:

- `hook-skipped`, `hook-failed` (error): a BPF hook that was not attached, and which
  traffic it leaves uncounted
- `exec-ring-full`: exec events were dropped; raise `[monitoring] exec_ring_buffer_pages`
- `dns-ring-full`: those connections get their domain from reverse DNS instead
- `map-near-capacity` for `conn_stats4` or `conn_stats6`: connections may have been
  evicted before a drain; raise `[monitoring] conn_map_max_entries`. For
  `conn_stats_packet`: more than about 59 000 processes did raw packet or TUN I/O within
  a second; its size is fixed
- `drain-failed`, `drain-entry-failed`, `monitor-failed`, `writer-failed` (error): an
  unexpected exception, with its line; the thread carries on
- `writer-queue-full`: the writer fell behind the reader (slow disk, locked database) and
  the oldest batches were discarded
- `live-feed-queue-full`: the same for viewers, which costs no data
- `live-feed-subscribers-dropped`: a viewer fell more than 8 MiB behind
- `live-feed-group`: `[viewer] group` is not among the unit's `SupplementaryGroups=`
- `multi-call-inode`: once per hardlinked multi-call binary, such as uutils coreutils; its
  processes that are gone before they are resolved are recorded as `<multi-call:dev,ino>`
- `sqlite-retry`: a failed write, retried on the next window
- `retry-buffer-full`: writes have failed for so long that the oldest rows were given up
- `maintenance-done` (info): a maintenance pass that did something, with how long it
  took and how many unreferenced lookup entries it cleaned
- `maintenance-clock-jump`: the clock was set or stepped since the last pass; see
  [Failure and recovery](#failure-and-recovery)
- `clock-went-back`: the clock had run ahead while periods were rolled up; they are rolled
  up again
- `retention-skipped` (error): the clock is ahead of the newest row, so nothing is purged
- `conntrack-unreadable`: no `nf_conntrack` module, no `CAP_NET_ADMIN`, or the namespace
  cannot be joined; its forwarded traffic goes unrecorded until the table can be read,
  while the rest of each window is written
- `conntrack-no-counters`: once per namespace; see [Forwarded traffic](#forwarded-traffic)
- `conntrack-events-lost`: the kernel dropped destroy events under load; those flows miss
  their last window's bytes
- `conntrack-listener-stopped`: from then on, flows that end there miss their last
  window's bytes until the daemon restarts
- `netns-unreadable`: once per namespace that cannot be joined; its interfaces go
  unrecorded until it can

The query service logs to its own unit (`journalctl -u tracct-query`): where it reads
from at start, and `query server: interrupted …` for a query stopped after 30 seconds.

## Resource use

Bytes are summed in the kernel, so CPU use follows the number of active connections per
second, not the packet rate. The benchmark in `bench/` measures overhead and accuracy; see
[bench/reports/findings.md](../bench/reports/findings.md). `bench/lib/loadtest.py`
measures the daemon's CPU, memory and losses under sustained load (many idle clients,
tens of thousands of connections per second, hundreds of short-lived processes per
second); see [bench/README.md](../bench/README.md#load-test). Measured results are in
[performance.md](performance.md).

Memory is bounded: the writer's queue holds at most 262 144 events, a write window 65 536
connections (a fuller one is written early), the retry buffer 100 000 rows, and each cache
a fixed number of entries. After a burst the process gives part of its memory back and
keeps the rest allocated; see [performance.md](performance.md) for measured peaks. A full
writer queue measured 717 MB PSS on a database of 30 million rows, the highest seen; the
unit's `MemoryMax=1G` leaves room above it.

The database grows with the number of distinct connections per write window (process,
addresses, ports), not with bytes. Longer `write_limit_seconds` makes fewer, larger rows.
Retention keeps it at roughly `raw_retention_days` worth of raw rows plus
`rollup_retention_days` worth of rollups, which hold one row per program, peer domain and
service port per period; deleted pages are reused, so the file stays at its largest size
without shrinking. Once a day after deleting rows, maintenance also scans all of them for
unreferenced lookup entries, one lookup table at a time with due writes in between; while a
table is scanned, writes wait and the queue fills.

Every write window the writer also reads the interfaces and dumps the conntrack table of
each namespace it knows, another namespace's from a short-lived thread that joins it. A dump
walks every tracked flow, local ones included, but skips local ones without parsing them;
with a full table of 65 536 flows under load it made no measurable difference (see
[performance.md](performance.md)). One thread waits on the ended-flow events of all
namespaces.

Reverse DNS sends a PTR query through the system resolver for every remote address no
program looked up by name, port scanners included. Four workers handle the queries, with
up to 1024 addresses waiting and 8192 answers cached; addresses beyond that are asked for
again in a later window. `[log] reverse_dns = false` turns it off.

## Failure and recovery

- **Database write fails** (locked, disk full): rows are kept and retried each window; past
  100 000 pending rows the oldest are dropped and the drop is logged.
- **Corrupt database**: moved to `tracct.db.bad` (with its `-wal` and `-shm` files) in
  the state directory and recreated on the next start. When the writer finds it while
  running, the daemon exits so that the unit restarts it on a new database; the window
  being written is lost.
- **Database of another schema version**: the daemon refuses to start, leaving the file
  untouched (see [Upgrades](#upgrades)).
- **Malformed config**: defaults are used and the problem is logged.
- **Second instance**: refused while `tracct.lock` in the runtime directory is held.
- **Stop**: the reader drains the kernel maps once more and the writer writes everything
  it holds before the process exits, so a restart loses no counted traffic.
- **Suspend and resume**: detected from the clocks; the reader drains the maps, unloads
  the BPF program and loads it again.
  `systemctl kill -s SIGUSR1 --kill-whom=main tracct` forces the same.
- **Clock ahead of the data** (booted before NTP): the retention purge is skipped rather
  than wiping the database, and tried again on the next pass; the rollup does not pass the
  newest row's period.
- **Clock set or stepped while running**: a maintenance pass that finds the wall clock moved
  more than a minute apart from the boot clock since the last pass is skipped, and the next
  one trusts the clock. A clock that stays wrong past the next pass purges by it: running
  ahead deletes that much of the oldest history early. When it goes back behind periods
  already rolled up, those are rolled up again, so the rows written since are kept. Rows
  carry the time the clock showed when they were written.
- **Maintenance fails** (locked, disk full): logged, and retried on the next pass.
- **Conntrack table unreadable** (module unloaded, namespace gone mid-dump): logged once per
  namespace; its forwarded flows are skipped for that window, everything else is written.
- **Restart**: interface counters and conntrack start from a new baseline, so the traffic
  of the minutes the daemon was down is not attributed to the first window.
- **Slow history query**: interrupted after 30 seconds; the viewer says so and suggests a
  shorter range or a filter. A query past `MemoryMax=` kills the query service, the viewer
  reports the closed connection, and the next request starts a new one.
- **Daemon down**: the history stays readable through the query service; the live tab says
  the feed is unavailable and reconnects when the daemon is back.

Maintenance runs at daemon start and then every `maintenance_interval_minutes`: closed
periods are rolled up, raw rows older than `raw_retention_days` (once rolled up) and
rollups older than `rollup_retention_days` are deleted, and once a day lookup entries nothing
refers to any more.

## Upgrades

Install the new version into `/opt/tracct`, run `/opt/tracct/bin/tracct install -f` to
bring the units and the base `config.toml` up to it, then `systemctl daemon-reload` and
restart the unit. `-f` replaces `config.toml`, so keep your own settings in `config.d/`
(see [MANUAL.md](MANUAL.md#configuration)); move them there before the first `install -f`
if they are still in `config.toml`. When a release changes
the schema version, the daemon refuses the old database: stop the unit, move
`/var/lib/private/tracct/tracct.db` aside (with its `-wal` and `-shm` files), and
start it again to get a new one.

### Uninstalling

`tracct uninstall` stops the units and removes the files `install` wrote, after listing
them and asking; the drop-ins and the database stay unless `--purge` is given (see
[MANUAL.md](MANUAL.md#uninstall)). tracct cannot uninstall itself. If no one needs it any
more, remove the group too (`groupdel tracct-viewer`).

### Moving from a picosnitch install

Installs from before the rename used the name picosnitch for the unit, user, group and
paths. The database format is the same, so its history carries over:

```sh
systemctl disable --now picosnitch picosnitch-query.socket
rm /etc/systemd/system/picosnitch.service /etc/systemd/system/picosnitch-query.*
rm /etc/sysusers.d/picosnitch.conf
```

Then install tracct as in the [README](../README.md#install), but move the old
configuration and database in place before the final `systemctl enable --now`:

```sh
sed 's/picosnitch-viewer/tracct-viewer/' /etc/opt/picosnitch/config.toml > /etc/opt/tracct/config.d/50-local.toml
install -d -m 700 /var/lib/private/tracct
mv /var/lib/private/picosnitch/picosnitch.db /var/lib/private/tracct/tracct.db
mv /var/lib/private/picosnitch/picosnitch.db-wal /var/lib/private/tracct/tracct.db-wal 2>/dev/null
mv /var/lib/private/picosnitch/picosnitch.db-shm /var/lib/private/tracct/tracct.db-shm 2>/dev/null
```

systemd hands the state directory to the new dynamic user on start. Add viewers to
`tracct-viewer` again (`usermod -aG tracct-viewer <user>`); the old group can be removed
with `groupdel picosnitch-viewer`, and `/opt/picosnitch` deleted.

## Troubleshooting

- **`Missing capabilities: …`**: the unit file in `/etc/systemd/system` is older than the
  installed version (`tracct status` shows it `modified`); run `tracct install -f` and
  `systemctl daemon-reload`.
- **`getaddrinfo uprobe not attached`**: `CAP_SYS_ADMIN` is missing, or libc is not where
  libbpf looks; domains then come from reverse DNS only.
- **No forwarded rows on an exit node or VPN namespace**: check `nf_conntrack_acct` in that
  namespace and the journal for `conntrack:` lines; flows that started while it was 0 never
  get counters.
- **`BPF requirements not met`**: the kernel lacks BTF (`CONFIG_DEBUG_INFO_BTF=y`), the bpf
  filesystem is not mounted at `/sys/fs/bpf`, or `libbpf.so.1` is not installed.
- **`view`: no access to `events.sock`**: the user is not in the viewer group (log in again
  after `usermod`), or `[viewer] group` is not set.
- **`view`: query server unavailable**: `tracct-query.socket` is not installed or not
  enabled (`systemctl status tracct-query.socket`); with "no access", the user is not in
  `tracct-viewer`. Errors of the server itself are in `journalctl -u tracct-query`.
- **`view` over SSH: the connection closes at once**: the remote login user has no access to
  the sockets; see [Remote viewing](MANUAL.md#remote-viewing).
- **`Unsupported database version N, expected M`**: see [Upgrades](#upgrades).
