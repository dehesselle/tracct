# picosnitch (traffic accounting fork)

A Linux daemon that records network traffic per process: which program (and its parent and
user) exchanged how many bytes with which remote address, domain and port, and when. It counts
bytes in the kernel with [BPF](https://ebpf.io/) and keeps the history in SQLite, so a traffic
spike seen in `vnstat` can be traced back to who caused it, after the fact.

This is a fork of [elesiuta/picosnitch](https://github.com/elesiuta/picosnitch) for headless
servers. It drops upstream's desktop and security features (notifications, executable hashes,
VirusTotal, web UI) and runs as a systemd unit with a dynamic user.

## Install

Needs a kernel with BTF (`/sys/kernel/btf/vmlinux`), `libbpf1` at runtime, and `clang` plus
`libbpf-dev` to build the BPF object. As root, from a checkout:

```sh
uv venv /opt/picosnitch
VIRTUAL_ENV=/opt/picosnitch uv pip install .
install -m 644 systemd/picosnitch.service /etc/systemd/system/
install -m 644 systemd/picosnitch.sysusers /etc/sysusers.d/picosnitch.conf
systemd-sysusers
install -d /etc/opt/picosnitch
printf '[viewer]\ngroup = "picosnitch-viewer"\n' > /etc/opt/picosnitch/config.toml
systemctl daemon-reload && systemctl enable --now picosnitch
```

Then watch live traffic as root or as a member of `picosnitch-viewer`:

```sh
/opt/picosnitch/bin/picosnitch top
```

## Caveats

- Not a security tool: programs are identified by path, and anything with root can evade or
  alter the record.
- Bytes are counted at the socket, so headers and retransmits are missing; on hosts with VPN
  tunnels the same download shows up once per layer (see [DESIGN.md](docs/DESIGN.md)).

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md): architecture, what is and isn't counted, core principles
- [docs/MANUAL.md](docs/MANUAL.md): commands, configuration reference, paths
- [docs/OPERATIONS.md](docs/OPERATIONS.md): running the unit, capabilities, logs, failure
  behavior, upgrades, troubleshooting
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): building, checks, tests, benchmark
- [docs/schema.md](docs/schema.md): database tables and example queries
- [docs/alternatives.md](docs/alternatives.md): how other per-process traffic tools compare
