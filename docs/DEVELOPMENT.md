# Development

This document covers the code layout, building, the checks, licensing, the tests and the
benchmark.

## Layout

| Path | Contents |
| --- | --- |
| `src/picosnitch/bpf/picosnitch.bpf.c` | the BPF program (tracked against upstream) |
| `src/picosnitch/bpf_wrapper.py` | ctypes libbpf wrapper and struct mirrors (tracked against upstream) |
| `src/picosnitch/cli.py` | commands, capability and database checks, schema creation |
| `src/picosnitch/main_loop.py` | starts and supervises the threads, the live feed thread |
| `src/picosnitch/monitor.py` | the reader thread: BPF attach, drain, attribution |
| `src/picosnitch/writer.py` | the writer thread: aggregation, filters, SQLite, rollups, retention |
| `src/picosnitch/reverse_dns.py` | the reverse DNS workers |
| `src/picosnitch/netinfo.py`, `rtnetlink.py` | namespaces, interfaces and their counters, via rtnetlink |
| `src/picosnitch/conntrack.py` | forwarded flows from connection tracking, via ctnetlink |
| `src/picosnitch/utils.py`, `types.py` | the hand-off queue between threads and the event passed through it, logging and SQLite helpers |
| `src/picosnitch/config.py`, `constants.py` | configuration, paths, schema |
| `src/picosnitch/live_feed.py` | `events.sock` publisher and subscriber |
| `src/picosnitch/query.py` | the query socket's message framing and client |
| `src/picosnitch/query_server.py` | the query server: sources, dimensions, raw and rollup routing, socket activation |
| `src/picosnitch/viewer/` | `view` (Textual): app, live tab, history tabs, timeline |
| `systemd/` | daemon unit, query socket and service, sysusers file |
| `hatch_build.py` | build hook compiling the BPF object into the wheel |
| `bench/` | accuracy and overhead benchmark against other tools |

How the parts fit together is in [DESIGN.md](DESIGN.md).

## Requirements

Everything runs on Linux only: Python 3.12 or newer, [uv](https://docs.astral.sh/uv/),
`clang` and `libbpf-dev` to compile the BPF object, `libbpf1` at runtime. Vendored
`vmlinux_*.h` headers cover x86_64 and aarch64; elsewhere the build dumps one from the
running kernel with `bpftool`. The viewer needs Textual (the `tui` extra); the dev group
pins it for the tests.

## Building

```sh
uv sync                                         # dev tools; an editable install, without the BPF object
uv pip install --reinstall-package picosnitch .  # a real build, compiling picosnitch.bpf.o
```

Editable installs skip the BPF build, as does `PICOSNITCH_SKIP_BPF_BUILD=1`. The build
reuses `src/picosnitch/bpf/picosnitch.bpf.o` while it is newer than the source.

## Checks

```sh
uv run ruff check
uv run ruff format --check
uv run reuse lint
```

## Licensing

Every file states its copyright and license in the [REUSE](https://reuse.software) format:
a header where the format allows comments, otherwise an entry in `REUSE.toml`. The license
texts are in `LICENSES/`.

```python
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD
```

- A new file names its author only and is `0BSD`.
- A file holding code from upstream keeps Eric Lesiuta's line, with the year his header
  had, and is `GPL-3.0-or-later`; the BPF program is `GPL-2.0-only`. Moving upstream code
  into a file adds his line and changes its license to match.
- Write each header for its file; never copy one from another file.

The project as a whole is distributed under GPL-3.0-or-later.

## Tests

```sh
sudo .venv/bin/python -m pytest tests
```

Call the venv's Python directly: `uv run` would re-sync the editable install, which has no
BPF object.

- `test_functional.py` starts a real daemon under `/tmp/picosnitch` and checks what it
  records for `curl`, `wget` and generated traffic. It needs root and the built BPF object,
  and is skipped otherwise.
- `test_netinfo.py` and `test_conntrack.py` test their parsers and deltas with fakes; their
  root tests create network namespaces and route traffic between them, through the host and
  through a router namespace (which needs `nft`), and are skipped without root and iproute2.
- `test_monitor.py` covers executable and unit resolution, `test_pipeline.py` the hand-off
  between the threads and the writer, `test_reverse_dns.py` the reverse DNS workers with a
  fake resolver, `test_robustness.py` config, rollups, retention, database and
  struct-layout robustness, `test_live_feed.py` the socket, `test_query_server.py` the
  routing between raw rows and rollups, the dimensions, request bounds and the socket,
  `test_viewer.py` the Textual viewer headless against both sockets (skipped without
  Textual). These run unprivileged.

CI (`.github/workflows/ci.yml`) runs the checks, builds the sdist and x86_64 and aarch64
wheels, and runs the tests as root from the wheels on Python 3.12 to 3.14.

## Comparing with upstream

The remote `upstream` points at elesiuta/picosnitch. Changes to the tracked files show
with:

```sh
git fetch upstream
git diff upstream/master -- src/picosnitch/bpf/picosnitch.bpf.c src/picosnitch/bpf_wrapper.py
```

## Benchmark

`bench/` generates known traffic in many hard-to-attribute ways and scores each tool's
detection and byte counts; see [bench/README.md](../bench/README.md). Its picosnitch
adapter builds the checked-out tree into `/opt/picosnitch` and runs the unit, replacing
any existing install and its database, so run it on a disposable machine. Running only
picosnitch (`--tools picosnitch`) regenerates `bench/reports/` with that tool alone; keep
those files out of commits unless the full matrix ran.
