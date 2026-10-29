# Development

This document covers the code layout, building, the checks, licensing, the tests,
releasing and the benchmark.

## Layout

| Path | Contents |
| --- | --- |
| `src/tracct/bpf/tracct.bpf.c` | the BPF program (kept close to picosnitch's) |
| `src/tracct/bpf_wrapper.py` | ctypes libbpf wrapper and struct mirrors (kept close to picosnitch's) |
| `src/tracct/cli.py` | commands, capability and database checks, schema creation |
| `src/tracct/install.py` | `install`: writes `src/tracct/files/` to the system or under a root; `uninstall` |
| `src/tracct/status.py` | `status`: the installed files, drop-ins, units, conntrack accounting, viewer group, database |
| `src/tracct/main_loop.py` | starts and supervises the threads, the live feed thread |
| `src/tracct/monitor.py` | the reader thread: BPF attach, drain, attribution |
| `src/tracct/writer.py` | the writer thread: aggregation, filters, SQLite, rollups, retention |
| `src/tracct/reverse_dns.py` | the reverse DNS workers |
| `src/tracct/netinfo.py`, `rtnetlink.py` | namespaces, interfaces and their counters, via rtnetlink |
| `src/tracct/conntrack.py` | forwarded flows from connection tracking, via ctnetlink |
| `src/tracct/utils.py`, `types.py` | the hand-off queue between threads and the event passed through it, logging and SQLite helpers |
| `src/tracct/messages.py` | the running daemon's messages: their IDs, default levels and `report` |
| `src/tracct/config.py`, `constants.py` | configuration, paths, schema |
| `src/tracct/live_feed.py` | `events.sock` publisher and subscriber |
| `src/tracct/query.py` | the query socket's message framing and client |
| `src/tracct/query_server.py` | the query server: sources, dimensions, raw and rollup routing, socket activation |
| `src/tracct/viewer/` | `view` (Textual): app and its CSS (`app.tcss`), the tabs' base with its find, live tab, history tabs, plot, the shared time range, pickers, the query client and connection messages, the query results as types, settings, the about box's text (`about.txt`) |
| `src/tracct/files/` | what `tracct install` writes: daemon unit, query socket and service, sysusers file, base `config.toml`, conntrack module options |
| `hatch_build.py` | build hook compiling the BPF object into the wheel |
| `bench/` | accuracy and overhead benchmark against other tools |

How the parts fit together is in [DESIGN.md](DESIGN.md).

## Requirements

Everything runs on Linux only: Python 3.12 or newer, [uv](https://docs.astral.sh/uv/),
`clang` and `libbpf-dev` to compile the BPF object, `libbpf1` at runtime. Vendored
`vmlinux_*.h` headers cover x86_64 and aarch64; elsewhere the build dumps one from the
running kernel with `bpftool`. The viewer needs Textual and tcoda, whose `tcoda.plot`
draws the history plot (the `viewer` extra); the dev group asks for both within the
extra's bounds, plus textual-dev. `uv.lock` holds the versions development and CI use; `uv lock
--upgrade` moves them on. `.python-version` pins development to 3.12, the minimum, so
`uv sync` builds the venv with it.

## Building

```sh
uv sync                                      # dev tools; an editable install, without the BPF object
uv pip install --reinstall-package tracct .  # a real build, compiling tracct.bpf.o
```

Editable installs skip the BPF build, as does `TRACCT_SKIP_BPF_BUILD=1`. The build
reuses `src/tracct/bpf/tracct.bpf.o` while it is newer than the source.

The version comes from git: hatch-vcs runs `git describe` against the `v*` tags and writes
`src/tracct/version.py` (ignored by git), so a build needs a git checkout or an sdist. After
a commit or tag, `uv sync --reinstall-package tracct` refreshes it. picosnitch's release tags
are kept as `picosnitch-<version>` and do not count.

## Checks

```sh
uvx --from 'ruff~=0.16.0' ruff check
uvx --from 'ruff~=0.16.0' ruff format --check
uv run reuse lint
```

Ruff comes from outside the project: `required-version` in `pyproject.toml` and the CI
lint job name the same minor, and are bumped together once its new findings are reviewed.
Formatting is ruff's default, at 88 columns, and the lint rules are its defaults plus
import sorting. `bpf_wrapper.py` is left out of formatting and ignores the two rules its
picosnitch code breaks, so it stays close to picosnitch's; `bench/`, picosnitch's
benchmark, ignores the rules its harness breaks on purpose. Commits
that only reformat go into `.git-blame-ignore-revs`.

Files are UTF-8 with LF line endings: `.gitattributes` makes git store and check out LF
on every platform, and `.editorconfig` tells editors to write UTF-8, LF and a final
newline and to trim trailing whitespace outside Markdown.

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
- A file holding code from picosnitch keeps Eric Lesiuta's line, with the year his header
  had, and is `GPL-3.0-or-later`; the BPF program is `GPL-2.0-only`. Moving picosnitch's
  code into a file adds his line and changes its license to match.
- Write each header for its file; never copy one from another file.

The project as a whole is distributed under GPL-3.0-or-later.

## Tests

```sh
sudo .venv/bin/python -m pytest tests
```

Call the venv's Python directly: `uv run` would re-sync the editable install, which has no
BPF object. The viewer tests are `async`; pytest-asyncio runs them (`asyncio_mode = "auto"`
in `pyproject.toml`).

- `test_functional.py` starts a real daemon under `/tmp/tracct` and checks what it
  records for `curl`, `wget` and generated traffic. It needs root and the built BPF object,
  and is skipped otherwise.
- `test_netinfo.py` and `test_conntrack.py` test their parsers and deltas with fakes; their
  root tests create network namespaces and route traffic between them, through the host and
  through a router namespace, and are skipped without root and iproute2; the conntrack ones
  also need `nft`, whose rule makes the kernel track the routed flows.
- `test_monitor.py` covers executable and unit resolution, `test_pipeline.py` the hand-off
  between the threads and the writer, `test_reverse_dns.py` the reverse DNS workers with a
  fake resolver, `test_robustness.py` config, rollups, retention, database and
  struct-layout robustness, `test_messages.py` the message IDs and their levels,
  `test_live_feed.py` the socket, `test_query_server.py` the
  routing between raw rows and rollups, the dimensions, request bounds and the socket,
  `test_viewer.py` the Textual viewer headless against both sockets (skipped without
  Textual), `test_install.py` `install` and `uninstall` in a scratch root,
  `test_status.py` `status` of one, both with a fake `systemctl`. These run unprivileged.

CI (`.github/workflows/build.yml`) runs the checks, builds the sdist and, with the BPF
object, the x86_64 and aarch64 wheels, and runs the tests as root from the wheels on Python
3.12 to 3.14. The `Programming Language :: Python :: 3.x` classifiers in `pyproject.toml`
name the same versions; change both together.

## Releasing

Pushing a tag `v<version>` runs the same workflow, which checks that the wheels carry that
version, creates a draft GitHub release with the sdist and both wheels attached, and
publishes them to PyPI through trusted publishing (GitHub environment `pypi`). Look the
draft release over and publish it.

## Comparing with picosnitch

The remote `upstream` points at elesiuta/picosnitch and fetches no tags. The files kept
close to it (see [DESIGN.md](DESIGN.md#relationship-to-picosnitch)) compare with:

```sh
git fetch upstream
git diff upstream/master:src/picosnitch/bpf/picosnitch.bpf.c HEAD:src/tracct/bpf/tracct.bpf.c
git diff upstream/master:src/picosnitch/bpf_wrapper.py HEAD:src/tracct/bpf_wrapper.py
```

## Benchmark

`bench/` generates known traffic in many hard-to-attribute ways and scores each tool's
detection and byte counts; see [bench/README.md](../bench/README.md). Its tracct
adapter builds the checked-out tree into `/opt/tracct` and runs the unit, replacing
any existing install and its database, so run it on a disposable machine. Running only
tracct (`--tools tracct`) regenerates `bench/reports/` with that tool alone; keep
those files out of commits unless the full matrix ran.
