# CLAUDE.md

tracct is a Linux daemon that records network traffic per process with BPF and keeps the
history in SQLite, for traffic accounting on servers, not security.

## Where to look

- Read [docs/DESIGN.md](docs/DESIGN.md) before architectural changes and respect its core
  principles; it also explains the database tables and says which files are kept close to
  picosnitch.
- Copyright and licenses follow authorship; see Licensing in
  [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md#licensing) before adding or moving code.
- Commands, configuration and paths: [docs/MANUAL.md](docs/MANUAL.md).
- The unit, capabilities, logs and failure behavior: [docs/OPERATIONS.md](docs/OPERATIONS.md).
- Measured cost under load: [docs/performance.md](docs/performance.md).

@docs/DEVELOPMENT.md

## Documentation rules

- The README stays short: what it is, install, one example, caveats, the doc list.
- A change that affects design, usage or behavior updates the matching document in the
  same change.
- DESIGN.md is kept current, rewritten where the design changes, and carries no project
  history.
