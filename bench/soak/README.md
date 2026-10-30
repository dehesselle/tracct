<!--
SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>

SPDX-License-Identifier: 0BSD
-->

# Soak run

A run of 30 to 60 minutes that drives the database through everything it does in
months: inserts, early writes, rollups, retention purges, the cleanup of unreferenced
lookup entries and giving free pages back. It runs the real build and unit on a
disposable box; only a drop-in shortens the intervals (2 s windows, 1 min periods and
maintenance, 10 min raw and 25 min rollup retention). A checker looks at the unit and
the database every minute, so a fault shows within minutes, not at the end.

| Scenario | What it provokes |
| --- | --- |
| `steady` | 200 long-lived TCP clients, 30 execs/s, command lines past 4 KiB, curl and wget to real hosts, viewer queries |
| `burst` | two UDP bursts across 120 000 addresses, past 65 536 connections per window: early writes, purges of many chunks, address orphans, free pages given back |
| `netns` | namespaces nsa and nsb made and removed in turn, reusing inodes; a router namespace forwarding with a `ct` rule |
| `ops` | a schema 7 database refused, restart, `kill -9`, period and window changed and back, 3 min down, queries throughout |
| `all` | steady at half, smaller bursts, namespaces and router, queries |
| `smoke` | a few minutes of all of it, with every disturbance once, to try the scripts |

## Running

On each box, as root, from a checkout with `.git` (the version comes from git) at
`/root/tracct`:

```sh
bash bench/soak/setup.sh                    # packages, helpers, tracct into /opt/tracct
bench/soak/traffic.py reset                 # new database, drop-in, check loop started
systemd-run --unit soak-traffic --collect /usr/bin/python3 \
    /root/tracct/bench/soak/traffic.py run --scenario burst --minutes 40
```

`reset --raw-min 2 --rollup-min 4` shortens the retention for a smoke run. From the
machine the boxes are reached from, `fleet.sh watch 300` looks at every box each 30 s
and returns early on a FAIL or ERR, else prints each box's last check after 5 minutes;
`fleet.sh tick` prints it at once. `SOAK_HOSTS` names the ssh hosts.

Everything lands in `/var/log/soak/`: `checks.jsonl` (one check a minute),
`events.jsonl` (the planned disturbances), `ledger/` (the bytes each generator sent) and
`query.jsonl` (the viewer-like requests). `check.py summary --since <unix time>` prints
the last check and every finding since.

## The checks

Each finding is PASS, WARN (worth a look), ERR (the check itself broke) or FAIL (tracct
did something wrong). Restarts, gaps and losses inside a planned disturbance are not
failures.

- The unit: active, no unplanned restart, memory below 80 % of `MemoryMax=`, its CPU,
  `tracct status`; the query socket.
- The journal: the messages that mean a failure, the warnings counted by ID, each
  maintenance pass with its periods, rows, orphans and space released.
- Writes: the newest row a few windows old at most, no gap past 15 s, each window's
  `seconds` the time since the write before, and the seconds of a stretch adding up to
  it.
- Rollups: every stretch of the longest period seen sums to the same, raw and rolled
  up, while its raw rows are all there; the watermark keeps up.
- Retention: nothing older than it, nothing purged early.
- References: every id in every table found in its lookup table.
- The file: schema version, incremental auto_vacuum, WAL; free pages given back once past
  a quarter; `PRAGMA quick_check` every ten checks.
- Ground truth: per generator, the bytes recorded in the last 8 minutes against its
  ledger, give or take a window at each end.
- Details: command lines cut at 4 KiB into one row, the rows of each namespace under its
  own name, forwarded rows while the router runs, the query server's totals against the
  database's.
