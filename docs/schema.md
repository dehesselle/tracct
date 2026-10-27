# Database schema

This document describes the tables of the traffic database and how to query them.

The database is SQLite at `$STATE_DIRECTORY/picosnitch.db` (`/var/lib/picosnitch/picosnitch.db`
under the unit), in WAL mode. All tables are [`STRICT`](https://sqlite.org/stricttables.html).
`PRAGMA user_version` holds the schema version (6); the daemon refuses a database with
another version, and there are no migrations.

The tables come in three kinds:

- **lookup tables** intern strings so the traffic rows stay small: `executables`, `domains`,
  `addresses`, `units`, `interfaces`, and `netns` for namespace names. Id 0 in each is the
  empty/unknown sentinel.
- **raw tables**, one row per write window (`write_limit_seconds`): `connections` (socket
  bytes per process and peer), `interface_traffic` (bytes per interface) and `forwarded`
  (bytes of flows the host routes). They are kept for `raw_retention_days`.
- **rollups**, one row per period (`rollup_period_minutes`) with the raw rows of a closed
  period summed: `connections_rollup`, `interface_traffic_rollup`, `forwarded_rollup`. They
  are kept for `rollup_retention_days`. `meta` holds the rollup watermark.

Three kinds of bytes are recorded, and they must not be added together:

- `connections`: **socket bytes**, what programs sent and received, without headers.
- `interface_traffic`: **interface bytes**, everything a device moved, headers included.
- `forwarded`: **IP bytes** of routed flows, from connection tracking, headers included.

On a host with tunnels the same transfer appears at several layers (see
[DESIGN.md](DESIGN.md#what-is-and-isnt-counted)); `interfaces.kind` tells them apart.

## Lookup tables

### `executables`

One row per (path, name, command line). Re-executing the same binary with the same arguments
reuses the row; different arguments make a new one.

```sql
id      INTEGER PRIMARY KEY
exe     TEXT NOT NULL    -- absolute path, e.g. /usr/bin/curl
name    TEXT NOT NULL    -- /proc/<pid>/comm, e.g. curl
cmdline TEXT NOT NULL    -- argv, shell-quoted and joined with spaces
UNIQUE(exe, name, cmdline)
```

### `domains`, `addresses`, `units`

```sql
domains(id INTEGER PRIMARY KEY, domain TEXT NOT NULL UNIQUE)   -- reversed: com.example.www
addresses(id INTEGER PRIMARY KEY, addr TEXT NOT NULL UNIQUE)   -- IPv4 or IPv6, canonical text
units(id INTEGER PRIMARY KEY, unit TEXT NOT NULL UNIQUE)       -- systemd unit, e.g. nginx.service
```

A domain is the name the program looked up (`getaddrinfo`), else the reverse DNS name of the
address, else the address itself when it has no name. A unit is the innermost systemd unit
of the process's cgroup (`.service`, `.scope`, …); empty outside any unit or when the process
was gone before it could be read.

### `interfaces`

```sql
id    INTEGER PRIMARY KEY
netns INTEGER NOT NULL  -- namespace inode
name  TEXT NOT NULL     -- e.g. eth0, tailscale0
kind  TEXT NOT NULL     -- link kind: tun, veth, wireguard, bridge, ...; '' for physical and lo
UNIQUE(netns, name, kind)
```

### `netns`

```sql
inode INTEGER PRIMARY KEY  -- as in the netns columns elsewhere
name  TEXT NOT NULL        -- from /run/netns or /run/docker/netns; 'host' for the daemon's own
```

Namespaces without a name have no row; their rows keep the bare inode. Inodes can be reused
once a namespace is gone, so a name is only reliable for the time it was seen.

## Raw tables

### `connections`

One row per connection and write window. `events` is the number of drained kernel entries
summed into it (packets for drained connections).

```sql
contime   INTEGER NOT NULL  -- unix time of the write, seconds
send      INTEGER NOT NULL  -- socket bytes sent in this window
recv      INTEGER NOT NULL  -- socket bytes received in this window
events    INTEGER NOT NULL
exe_id    INTEGER NOT NULL REFERENCES executables(id)
pexe_id   INTEGER NOT NULL REFERENCES executables(id)   -- parent
unit_id   INTEGER NOT NULL REFERENCES units(id)
uid       INTEGER NOT NULL
family    INTEGER NOT NULL  -- AF_INET=2, AF_INET6=10, AF_PACKET=17 (raw and TUN), 0=unknown
protocol  INTEGER NOT NULL  -- IPPROTO_* (TCP=6, UDP=17), 0=unknown
lport     INTEGER NOT NULL
rport     INTEGER NOT NULL
laddr_id  INTEGER NOT NULL REFERENCES addresses(id)
raddr_id  INTEGER NOT NULL REFERENCES addresses(id)
domain_id INTEGER NOT NULL REFERENCES domains(id)
netns     INTEGER NOT NULL  -- the socket's namespace inode
iface_id  INTEGER NOT NULL REFERENCES interfaces(id)
```

`iface_id` is the interface that holds the local address in the socket's namespace, or for
`AF_PACKET` rows of a process with one TUN device, that device. A row whose interface is a
`tun` is inside a tunnel (inner layer); an `AF_PACKET` row on a `tun` is the VPN client's own
reads and writes (tunnel layer); the VPN client's encrypted socket is a plain row on the
physical interface (outer layer).

### `interface_traffic`

Bytes each interface received and sent during a write window, from the kernel's counters
(`IFLA_STATS64`), for the daemon's namespace, the named ones and those a recorded process
lives in. Windows without traffic have no row. The first window after a start only sets the
baseline.

```sql
contime  INTEGER NOT NULL
iface_id INTEGER NOT NULL REFERENCES interfaces(id)
rx       INTEGER NOT NULL
tx       INTEGER NOT NULL
```

### `forwarded`

Flows the host routes without a local socket at either end, from connection tracking in the
daemon's namespace: an exit node's or NAT's traffic. `src` opened the flow, `dst` answered it
(after any destination NAT). `orig` counts the direction src → dst, `reply` the other.

```sql
contime       INTEGER NOT NULL
netns         INTEGER NOT NULL
protocol      INTEGER NOT NULL
src_id        INTEGER NOT NULL REFERENCES addresses(id)
sport         INTEGER NOT NULL
dst_id        INTEGER NOT NULL REFERENCES addresses(id)
dport         INTEGER NOT NULL
domain_id     INTEGER NOT NULL REFERENCES domains(id)   -- reverse DNS of dst
orig_bytes    INTEGER NOT NULL
reply_bytes   INTEGER NOT NULL
orig_packets  INTEGER NOT NULL
reply_packets INTEGER NOT NULL
```

## Rollups

Each rollup row sums the raw rows of one period (`period` is its start, unix time) that share
the columns it keeps; `rows` is how many raw rows went into it. The rollups drop what makes
raw rows numerous: process ids were never stored, and addresses and ephemeral ports are
dropped. A port at or above the start of the kernel's ephemeral range
(`net.ipv4.ip_local_port_range`, 32768 by default) is stored as 0, so a server keeps its
service port as `lport`, a client the server's port as `rport`.

```sql
connections_rollup(period, exe_id, pexe_id, unit_id, uid, family, protocol, lport, rport,
                   domain_id, netns, iface_id, send, recv, events, rows)
interface_traffic_rollup(period, iface_id, rx, tx)
forwarded_rollup(period, netns, protocol, src_id, dport, domain_id,
                 orig_bytes, reply_bytes, orig_packets, reply_packets, rows)
meta(key TEXT PRIMARY KEY, value INTEGER)   -- rollup_watermark: raw rows before it are rolled up
```

A period is rolled up once it has closed; raw rows are deleted past `raw_retention_days`
only once their period is rolled up. To cover a range that reaches past the raw window, read
the rollups before the watermark and the raw rows from it on. The query server keeps more
detail: it reads the raw rows from the first rolled-up period at or after the oldest raw row
on (the oldest row's own period is partly purged), the rollups before that, and the raw rows
from the watermark on when nothing at or after the oldest raw row is rolled up yet.

## Indexes

```sql
CREATE INDEX idx_contime         ON connections(contime);
CREATE INDEX idx_exe_id_contime  ON connections(exe_id,  contime);
CREATE INDEX idx_pexe_id_contime ON connections(pexe_id, contime);
CREATE INDEX idx_rollup_period          ON connections_rollup(period);
CREATE INDEX idx_rollup_exe_id_period   ON connections_rollup(exe_id,  period);
CREATE INDEX idx_rollup_pexe_id_period  ON connections_rollup(pexe_id, period);
CREATE INDEX idx_interface_traffic_contime        ON interface_traffic(contime);
CREATE INDEX idx_interface_traffic_rollup_period  ON interface_traffic_rollup(period);
CREATE INDEX idx_forwarded_contime        ON forwarded(contime);
CREATE INDEX idx_forwarded_rollup_period  ON forwarded_rollup(period);
```

## Example queries

Open the database read-only (`sqlite3 'file:/var/lib/picosnitch/picosnitch.db?mode=ro'`)
while the daemon runs.

Traffic per interface and hour over the last day, as `vnstat` would show it:

```sql
SELECT datetime(t.contime / 3600 * 3600, 'unixepoch') AS hour,
       n.name AS netns, i.name AS iface, SUM(t.rx) AS rx, SUM(t.tx) AS tx
FROM interface_traffic t
JOIN interfaces i ON i.id = t.iface_id
LEFT JOIN netns n ON n.inode = i.netns
WHERE t.contime >= unixepoch('now', '-1 day')
GROUP BY hour, i.id
ORDER BY hour, rx + tx DESC;
```

Which units moved the most socket bytes in the last hour:

```sql
SELECT u.unit, SUM(c.send) AS sent, SUM(c.recv) AS received
FROM connections c
JOIN units u ON u.id = c.unit_id
WHERE c.contime >= unixepoch('now', '-1 hour')
GROUP BY c.unit_id
ORDER BY sent + received DESC
LIMIT 10;
```

Top 10 executables by bytes received in the last 24 hours:

```sql
SELECT e.name, e.exe, SUM(c.recv) AS bytes_in
FROM connections c
JOIN executables e ON e.id = c.exe_id
WHERE c.contime >= unixepoch('now', '-1 day')
GROUP BY c.exe_id
ORDER BY bytes_in DESC
LIMIT 10;
```

Where the hosts behind an exit node went today:

```sql
SELECT s.addr AS peer, d.domain, f.dport, SUM(f.orig_bytes) AS up, SUM(f.reply_bytes) AS down
FROM forwarded f
JOIN addresses s ON s.id = f.src_id
JOIN domains   d ON d.id = f.domain_id
WHERE f.contime >= unixepoch('now', 'start of day')
GROUP BY f.src_id, f.domain_id, f.dport
ORDER BY down DESC
LIMIT 20;
```

Socket bytes per month and executable, beyond the raw window, from the rollups:

```sql
SELECT strftime('%Y-%m', r.period, 'unixepoch') AS month, e.name,
       SUM(r.send) AS sent, SUM(r.recv) AS received
FROM connections_rollup r
JOIN executables e ON e.id = r.exe_id
GROUP BY month, e.name
ORDER BY month, sent + received DESC;
```
