# tracct

tracct ("traffic accounting") is a Linux daemon that keeps a history of who used the
network: which program, under which user and systemd unit, exchanged how many bytes with
which remote address, domain and port, and when. It also records the counters of every
interface in every network namespace and the flows the host forwards for others. The bytes
are counted in the kernel with [BPF](https://ebpf.io/) and netlink and stored in SQLite, so
a spike in traffic can be traced to its cause long after it happened.

tracct also comes with a [Textual](https://textual.textualize.io/)-based TUI to watch traffic live and browse the collectd history.

## Install

You need a kernel with BTF (`/sys/kernel/btf/vmlinux`), Python 3.12 or newer with its
`venv` module (`python3-venv` on Debian and Ubuntu) and `libbpf1`; wheels exist for x86_64
and aarch64. As root:

```sh
python3 -m venv /opt/tracct
/opt/tracct/bin/pip install 'tracct[viewer]'
/opt/tracct/bin/tracct install
systemd-sysusers
systemctl daemon-reload && systemctl enable --now tracct tracct-query.socket
```

`tracct install` writes the systemd units, the sysusers file and the base configuration,
after saying what it will write and asking; it replaces nothing without `-f` (see
[MANUAL.md](https://github.com/dehesselle/tracct/blob/master/docs/MANUAL.md#install)).
The `viewer` extra installs `tracct view`; the daemon itself needs only the standard
library.
Forwarded traffic is recorded once `nf_conntrack` is loaded with `acct=1`, which
`tracct install --conntrack` sets up, see
[OPERATIONS.md](https://github.com/dehesselle/tracct/blob/master/docs/OPERATIONS.md#forwarded-traffic).

As root or as a member of `tracct-viewer`:

```sh
/opt/tracct/bin/tracct view
```

## Caveats

- Accounting, not security: programs are identified by their path, and anything running as
  root can evade or alter the record.
- Bytes are counted at the socket, without headers or retransmits, and traffic through a
  tunnel appears once per layer; see
  [DESIGN.md](https://github.com/dehesselle/tracct/blob/master/docs/DESIGN.md).

## Documentation

- [docs/DESIGN.md](https://github.com/dehesselle/tracct/blob/master/docs/DESIGN.md):
  architecture, what is and isn't counted, core principles
- [docs/MANUAL.md](https://github.com/dehesselle/tracct/blob/master/docs/MANUAL.md):
  commands, configuration reference, paths
- [docs/OPERATIONS.md](https://github.com/dehesselle/tracct/blob/master/docs/OPERATIONS.md):
  running the unit, capabilities, logs, failure behavior, upgrades, troubleshooting
- [docs/DEVELOPMENT.md](https://github.com/dehesselle/tracct/blob/master/docs/DEVELOPMENT.md):
  building, checks, licensing, tests, benchmark
- [docs/performance.md](https://github.com/dehesselle/tracct/blob/master/docs/performance.md):
  measured CPU, memory and losses under load

## AI disclosure

Substantial parts of this code were generated with Opus 5.x. Generated code was tested, but not every line was reviewed in detail.

## License

tracct is based on [picosnitch](https://github.com/elesiuta/picosnitch) by Eric Lesiuta, licensed under GPL-3.0-or-later. Its BPF program is GPL-2.0-only. Everything written for tracct alone is licensed under 0BSD.
