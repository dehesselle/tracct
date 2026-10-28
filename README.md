# tracct

tracct ("traffic accounting") is a Linux daemon that keeps a history of who used the
network: which program, under which user and systemd unit, exchanged how many bytes with
which remote address, domain and port, and when. It also records the counters of every
interface in every network namespace and the flows the host forwards for others. The bytes
are counted in the kernel with [BPF](https://ebpf.io/) and netlink and stored in SQLite, so
a spike in traffic can be traced to its cause long after it happened.

It is meant for servers: it runs headless as a systemd unit with a dynamic user, and a
terminal viewer shows live and recorded traffic.

## Install

You need a kernel with BTF (`/sys/kernel/btf/vmlinux`), Python 3.12 or newer,
[uv](https://docs.astral.sh/uv/) and `libbpf1`. As root, with the wheel for your
architecture (x86_64 or aarch64) from a [release](https://github.com/dehesselle/tracct/releases):

```sh
uv venv /opt/tracct
VIRTUAL_ENV=/opt/tracct uv pip install 'tracct[viewer] @ https://github.com/dehesselle/tracct/releases/download/v<version>/<wheel>'
/opt/tracct/bin/tracct install
systemd-sysusers
systemctl daemon-reload && systemctl enable --now tracct tracct-query.socket
```

To build from a git checkout instead, which also needs `clang` and `libbpf-dev`, install
`'.[viewer]'` in its place.

`tracct install` writes the systemd units, the sysusers file and the base configuration,
after saying what it will write and asking; it replaces nothing without `-f` (see
[MANUAL.md](docs/MANUAL.md#install)). The `viewer` extra installs `tracct view`; the
daemon itself needs only the standard library.
Forwarded traffic is recorded once `nf_conntrack` is loaded with `acct=1`, which
`tracct install --conntrack` sets up, see
[OPERATIONS.md](docs/OPERATIONS.md#forwarded-traffic).

As root or as a member of `tracct-viewer`:

```sh
/opt/tracct/bin/tracct view
```

## Caveats

- Accounting, not security: programs are identified by their path, and anything running as
  root can evade or alter the record.
- Bytes are counted at the socket, without headers or retransmits, and traffic through a
  VPN tunnel appears once per layer; see [DESIGN.md](docs/DESIGN.md).

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md): architecture, what is and isn't counted, core principles
- [docs/MANUAL.md](docs/MANUAL.md): commands, configuration reference, paths
- [docs/OPERATIONS.md](docs/OPERATIONS.md): running the unit, capabilities, logs, failure
  behavior, upgrades, troubleshooting
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): building, checks, licensing, tests, benchmark
- [docs/performance.md](docs/performance.md): measured CPU, memory and losses under load

## License

tracct is based on [picosnitch](https://github.com/elesiuta/picosnitch) by Eric Lesiuta and
is distributed under the GPL-3.0-or-later. Its BPF program is GPL-2.0-only, and files
written for tracct alone are 0BSD; each file states its own terms.
