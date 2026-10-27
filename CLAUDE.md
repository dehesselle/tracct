# CLAUDE.md

picosnitch (this fork) is a Linux daemon that records network traffic per process with BPF
and keeps the history in SQLite, for traffic accounting on servers, not security.

## Where to look

- Read [docs/DESIGN.md](docs/DESIGN.md) before architectural changes and respect its core
  principles; it also says which files are tracked against upstream.
- Commands, configuration and paths: [docs/MANUAL.md](docs/MANUAL.md).
- The unit, capabilities, logs and failure behavior: [docs/OPERATIONS.md](docs/OPERATIONS.md).
- Database tables: [docs/schema.md](docs/schema.md).

@docs/DEVELOPMENT.md

## Documentation rules

- The README stays short: what it is, install, one example, caveats, the doc list.
- A change that affects design, usage or behavior updates the matching document in the
  same change.
- DESIGN.md is kept current, rewritten where the design changes, and carries no project
  history.
