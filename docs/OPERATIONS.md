# Operations

This document covers running picosnitch as a systemd unit: its privileges, what it logs,
how it behaves under load and on failure, upgrades and troubleshooting. The install steps
are in the [README](../README.md).

## The unit

`systemd/picosnitch.service` runs `/opt/picosnitch/bin/picosnitch run` with:

- `Type=notify`: the unit is started once the BPF probes are attached, so units ordered
  after it are measured.
- `DynamicUser=yes`: an unprivileged user created per start, holding only the capabilities
  below. Its state lives in `/var/lib/private/picosnitch` (reached through the symlink
  `/var/lib/picosnitch`), readable by root only.
- `SupplementaryGroups=picosnitch-viewer`: lets the daemon hand `events.sock` to that
  group. The group comes from `systemd/picosnitch.sysusers`; it cannot be called
  `picosnitch`, which `DynamicUser=` takes for itself. Set `[viewer] group` to match and add
  viewers with `usermod -aG picosnitch-viewer <user>`.
- `Restart=always`, `RestartSec=5`: the daemon exits non-zero whenever one of its threads
  dies and is restarted.
- `LimitMEMLOCK=infinity` for the BPF maps and ring buffers, and a commented
  `MemoryMax=` to cap memory if wanted.

Day to day:

```sh
systemctl status picosnitch
journalctl -u picosnitch -f
systemctl restart picosnitch     # after a config change
```

## Capabilities

`picosnitch run` checks these at startup and exits if one is missing; the unit grants
exactly these.

| Capability | Why |
| --- | --- |
| `CAP_BPF` | load the BPF program and maps |
| `CAP_PERFMON` | attach kprobes, uprobes and fexit programs |
| `CAP_SYS_ADMIN` | attach the `getaddrinfo` uprobe; the kernel refuses its perf event without it, at any `perf_event_paranoid` (seen on Ubuntu's 7.0 kernel). Without it, domains come from reverse DNS only |
| `CAP_SYS_PTRACE` | read `/proc/<pid>/exe`, `/proc/<pid>/fd` and `/proc/<pid>/ns/net` of other users' processes |
| `CAP_SYSLOG` | not checked; reads kernel symbol addresses, without which io_uring zero-copy receives go uncounted |

## Logs

Everything goes to stderr, which is the journal under the unit; lines carry their syslog
priority. Startup logs the resolved config, state and runtime paths. Problems from the
capture side are logged under `picosnitch.error`, among them:

- a skipped or failed BPF hook and which traffic it leaves uncounted
- `exec ring buffer full: dropped N exec event(s)`: raise
  `[monitoring] exec_ring_buffer_pages`
- `conn_stats4 near capacity`: connections may have been evicted before a drain; raise
  `[monitoring] conn_map_max_entries`
- `writer queue full: dropped N event(s)`: the writer fell behind the reader (slow disk,
  locked database) and the oldest batches were discarded
- `live feed queue full: dropped N event(s)`: the same for viewers, which costs no data
- `live feed: dropped N subscriber(s)`: a viewer fell more than 8 MiB behind
- `hardlink multi-call inode …`: informational, once per multi-call binary
- `SQLite execute … will retry N entries`: a failed write, retried on the next window
- `retention purge: deleted N connection(s) …` (info): a maintenance pass that deleted
  rows, with how long it took

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
keeps the rest allocated; see [performance.md](performance.md) for measured peaks.

The database grows with the number of distinct connections per write window (process,
addresses, ports), not with bytes. Longer `write_limit_seconds` makes fewer, larger rows.
Retention keeps it at roughly `retention_days` worth of rows; deleted pages are reused, so
the file stays at its largest size without shrinking. Each maintenance pass that deletes
rows also scans all of them for unreferenced lookup entries, about half a second per
million rows, during which writes wait and the queue fills; raise
`maintenance_interval_minutes` for a very large database.

Reverse DNS sends a PTR query through the system resolver for every remote address no
program looked up by name, port scanners included. Four workers handle the queries, with
up to 1024 addresses waiting and 8192 answers cached; addresses beyond that are asked for
again in a later window. `[log] reverse_dns = false` turns it off.

## Failure and recovery

- **Database write fails** (locked, disk full): rows are kept and retried each window; past
  100 000 pending rows the oldest are dropped and the drop is logged.
- **Corrupt database**: moved to `picosnitch.db.bad` (with its `-wal` and `-shm` files) in
  the state directory and recreated on the next start. When the writer finds it while running, the daemon exits so that the unit
  restarts it on a new database; the window being written is lost.
- **Database of another schema version**: the daemon refuses to start, leaving the file
  untouched (see [Upgrades](#upgrades)).
- **Malformed config**: defaults are used and the problem is logged.
- **Second instance**: refused while `picosnitch.lock` in the runtime directory is held.
- **Stop**: the reader drains the kernel maps once more and the writer writes everything
  it holds before the process exits, so a restart loses no counted traffic.
- **Suspend and resume**: detected from the clocks; the reader drains the maps, unloads
  the BPF program and loads it again.
  `systemctl kill -s SIGUSR1 --kill-whom=main picosnitch` forces the same.
- **Clock ahead of the data** (booted before NTP): the retention purge is skipped rather
  than wiping the database, and tried again on the next pass.
- **Maintenance fails** (locked, disk full): logged, and retried on the next pass.

Retention runs at daemon start and then every `maintenance_interval_minutes`: rows older
than `retention_days` and lookup entries nothing refers to any more are deleted.

## Upgrades

Install the new version into `/opt/picosnitch` and restart the unit. When a release changes
the schema version, the daemon refuses the old database: stop the unit, move
`/var/lib/private/picosnitch/picosnitch.db` aside (with its `-wal` and `-shm` files), and
start it again to get a new one.

## Troubleshooting

- **`Missing capabilities: …`**: the unit file in `/etc/systemd/system` is older than the
  installed version; copy `systemd/picosnitch.service` again and `systemctl daemon-reload`.
- **`getaddrinfo uprobe not attached`**: `CAP_SYS_ADMIN` is missing, or libc is not where
  libbpf looks; domains then come from reverse DNS only.
- **`BPF requirements not met`**: the kernel lacks BTF (`CONFIG_DEBUG_INFO_BTF=y`), the bpf
  filesystem is not mounted at `/sys/fs/bpf`, or `libbpf.so.1` is not installed.
- **`top`: socket not accessible**: the user is not in the viewer group (log in again after
  `usermod`), or `[viewer] group` is not set.
- **`tui`: `Database not found`** as a viewer: the database is readable by root only; run
  `tui` as root.
- **`Unsupported database version N, expected M`**: see [Upgrades](#upgrades).
