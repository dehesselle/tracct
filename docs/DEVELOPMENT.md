# Development

This document covers the code layout, building, the checks and tests, and the benchmark.

## Layout

| Path | Contents |
| --- | --- |
| `src/picosnitch/bpf/picosnitch.bpf.c` | the BPF program (tracked against upstream) |
| `src/picosnitch/bpf_wrapper.py` | ctypes libbpf wrapper and struct mirrors (tracked against upstream) |
| `src/picosnitch/cli.py` | commands, capability and database checks, schema creation |
| `src/picosnitch/main_loop.py` | starts and supervises the threads, the live feed thread |
| `src/picosnitch/monitor.py` | the reader thread: BPF attach, drain, attribution |
| `src/picosnitch/writer.py` | the writer thread: aggregation, filters, SQLite, retention |
| `src/picosnitch/reverse_dns.py` | the reverse DNS workers |
| `src/picosnitch/utils.py` | the hand-off queue between threads, logging and SQLite helpers |
| `src/picosnitch/config.py`, `constants.py` | configuration, paths, schema |
| `src/picosnitch/live_feed.py` | `events.sock` publisher and subscriber |
| `src/picosnitch/ui/` | `top` and `tui` (curses) |
| `systemd/` | unit and sysusers file |
| `hatch_build.py` | build hook compiling the BPF object into the wheel |
| `bench/` | accuracy and overhead benchmark against other tools |

How the parts fit together is in [DESIGN.md](DESIGN.md).

## Requirements

Everything runs on Linux only: Python 3.12 or newer, [uv](https://docs.astral.sh/uv/),
`clang` and `libbpf-dev` to compile the BPF object, `libbpf1` at runtime. Vendored
`vmlinux_*.h` headers cover x86_64 and aarch64; elsewhere the build dumps one from the
running kernel with `bpftool`.

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
uv run tach check
uv run ty check
```

`tach.toml` declares which module may import which; update it when imports between
modules change.

## Tests

```sh
sudo .venv/bin/python -m pytest tests
```

Call the venv's Python directly: `uv run` would re-sync the editable install, which has no
BPF object.

- `test_functional.py` starts a real daemon under `/tmp/picosnitch` and checks what it
  records for `curl`, `wget` and generated traffic. It needs root and the built BPF object,
  and is skipped otherwise.
- `test_monitor.py` covers executable resolution, `test_pipeline.py` the hand-off between
  the threads and the writer, `test_reverse_dns.py` the reverse DNS workers with a fake
  resolver, `test_robustness.py` config, retention, database and
  struct-layout robustness, `test_live_feed.py` the socket, `test_ui_*.py` the viewers
  in a pty. These run unprivileged.

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
