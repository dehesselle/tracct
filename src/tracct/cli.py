# SPDX-FileCopyrightText: 2020 Eric Lesiuta
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import fcntl
import logging
import os
import sqlite3
import stat
import sys
from pathlib import Path

from tracct.config import config_files, load_config
from tracct.constants import (
    CONFIG_PATH,
    DB_PATH,
    DB_VERSION,
    INDEXES,
    RUN_DIR,
    SENTINELS,
    STATE_DIR,
    TABLES,
    VERSION,
)
from tracct.install import add_arguments as add_install_arguments
from tracct.install import add_uninstall_arguments, run_install, run_uninstall
from tracct.main_loop import run_main_loop
from tracct.messages import set_levels
from tracct.query_server import run_query_server
from tracct.status import status
from tracct.utils import (
    connect_db_readonly,
    quarantine_database,
    sqlite_error_means_corrupt,
)
from tracct.viewer import add_arguments as add_viewer_arguments
from tracct.viewer import run_viewer

logger = logging.getLogger(__name__)

#: What the daemon needs, as root or as an unprivileged user with ambient capabilities.
REQUIRED_CAPABILITIES: dict[str, int] = {
    # List /proc/<pid>/fd of other users' processes (mode 0500, a plain permission check
    # that CAP_SYS_PTRACE does not override): the startup seed and the TUN devices of a
    # process.
    "CAP_DAC_READ_SEARCH": 2,
    "CAP_NET_ADMIN": 12,  # read the conntrack table and its events for forwarded traffic
    "CAP_SYS_PTRACE": 19,  # resolve /proc/<pid>/exe and open /proc/<pid>/ns/net of other users' processes
    # Attach the getaddrinfo uprobe: its perf event is refused without, at any
    # perf_event_paranoid (checked on Ubuntu's kernel 7.0); without the uprobe, domains
    # come from reverse DNS only. Also joins other network namespaces (setns) to read
    # their interfaces.
    "CAP_SYS_ADMIN": 21,
    "CAP_PERFMON": 38,  # attach kprobes, uprobes and fexit programs
    "CAP_BPF": 39,  # load BPF programs and maps
}


class _JournalFormatter(logging.Formatter):
    """Prefix each record with its sd-daemon(3) priority so journald keeps the level."""

    def format(self, record: logging.LogRecord) -> str:
        if record.levelno >= logging.ERROR:
            priority = 3
        elif record.levelno >= logging.WARNING:
            priority = 4
        elif record.levelno >= logging.INFO:
            priority = 6
        else:
            priority = 7
        return f"<{priority}>{super().format(record)}"


def configure_logging() -> None:
    """Journald adds its own timestamps; anywhere else they come with the message."""
    if os.getenv("JOURNAL_STREAM"):
        formatter: logging.Formatter = _JournalFormatter("%(name)s: %(message)s")
    else:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    for handler in logging.getLogger().handlers:
        handler.setFormatter(formatter)


def check_capabilities() -> int:
    """Check the effective capabilities and BPF requirements, return exit code on
    failure.
    """
    with open("/proc/self/status", "r") as f:
        proc_status = f.read()
    capeff = int(
        proc_status[proc_status.find("CapEff:") + 8 :].splitlines()[0].strip(), base=16
    )
    missing = [
        name for name, bit in REQUIRED_CAPABILITIES.items() if not capeff & (1 << bit)
    ]
    if missing:
        logger.error(
            f"Missing capabilities: {' '.join(missing)} (run as root or grant them with AmbientCapabilities=)"
        )
        return 1
    from .bpf_wrapper import check_bpf_requirements

    try:
        check_bpf_requirements()
    except (RuntimeError, FileNotFoundError) as e:
        logger.error(f"{e}")
        return 1
    return 0


def check_database() -> int:
    """Check database exists and has correct version, return exit code on failure."""
    if not DB_PATH.exists():
        logger.error(f"Database not found: {DB_PATH}")
        logger.error("Start the tracct service to create it (systemctl start tracct)")
        return 1
    con = None
    try:
        con = connect_db_readonly(DB_PATH)
        cur = con.cursor()
        cur.execute("PRAGMA user_version")
        user_version = cur.fetchone()[0]
    except sqlite3.Error as e:
        # sqlite3.Error, not just OperationalError, so a corrupt db (DatabaseError)
        # returns 1 instead of crashing the boot path; init_database quarantines it
        # beforehand.
        logger.error(f"Could not open database {DB_PATH}: {e}")
        return 1
    finally:
        if con is not None:
            con.close()
    if user_version != DB_VERSION:
        logger.error(
            f"Unsupported database version {user_version}, expected {DB_VERSION}"
        )
        return 1
    return 0


def _db_is_corrupt(db_path: Path) -> bool:
    """True if the db can't be opened, its version read, or its expected tables are
    present -- such a db must be quarantined+recreated, else check_database or the
    writer's first maintenance pass crash-loops the daemon. A populated db with the
    wrong version is NOT corrupt (returns False) so check_database can reject it without
    destroying its data; an empty or schema-less file with a wrong version holds nothing
    and IS treated as recreatable.
    """
    try:
        db_stat = db_path.lstat()
        if not stat.S_ISREG(db_stat.st_mode) or db_stat.st_nlink != 1:
            return True
        con = sqlite3.connect(db_path)
        try:
            cur = con.cursor()
            if cur.execute("PRAGMA user_version").fetchone()[0] != DB_VERSION:
                # Recreate a 0-byte db a killed writer left behind instead of preserving
                # it.
                has_schema = cur.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'connections'"
                ).fetchone()
                return has_schema is None
            # Validate the tables AND the columns the boot purge / inserts need: a db
            # with the right table names but wrong columns (a foreign db sharing the
            # version) passes a name-only check yet crashes the writer. LIMIT 0
            # validates the columns without reading any rows; a missing table or column
            # raises here.
            cur.execute(
                "SELECT time, domain_id, laddr_id, raddr_id, unit_id, iface_id FROM connections LIMIT 0"
            )
            cur.execute("SELECT id, exe, name, cmdline FROM executables LIMIT 0")
            for table, _ in TABLES:
                cur.execute(f"SELECT * FROM {table} LIMIT 0")
            return False
        finally:
            con.close()
    except sqlite3.DatabaseError as e:
        # Not a database, a malformed header, a missing table or column: corrupt. A
        # transient error (locked by the live daemon or a user's sqlite session, busy,
        # disk I/O) must NOT quarantine a healthy db, e.g. one the query server or a
        # sqlite session has open.
        return sqlite_error_means_corrupt(e)


def init_database() -> None:
    """Create the state directory and database if missing (systemd creates the directory
    for a unit).
    """
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    db_path = DB_PATH
    if (db_path.exists() or db_path.is_symlink()) and _db_is_corrupt(db_path):
        # Quarantine a corrupt db and recreate it below, so check_database / the
        # writer's first maintenance pass don't crash-loop the daemon (data is kept in
        # tracct.db.bad).
        logger.error(
            f"tracct.db is unusable, quarantining to {db_path.name}.bad and recreating"
        )
        quarantine_database(db_path)
    if not db_path.exists():
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        # Only possible before the first table: lets maintenance give free pages back to
        # the filesystem, which otherwise takes a VACUUM rewriting the whole file.
        cur.execute("PRAGMA auto_vacuum = INCREMENTAL")
        for table, schema in TABLES:
            cur.execute(f"CREATE TABLE {table} ({schema}) STRICT")
        for statement in SENTINELS + INDEXES:
            cur.execute(statement)
        cur.execute(f"PRAGMA user_version = {DB_VERSION}")
        con.commit()
        con.close()
    # Readers must not block the writer; sqlite ignores this inside a transaction, so it
    # runs on its own, and as the mode is kept in the file this also converts a database
    # made without it.
    con = sqlite3.connect(db_path)
    try:
        mode = con.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if mode != "wal":
            logger.warning(
                f"tracct.db stays in journal mode {mode}; readers will block writes"
            )
    except sqlite3.OperationalError as e:
        # Another connection holds the database; the next start tries again.
        logger.warning(
            f"could not switch tracct.db to WAL mode ({e}); readers will block writes"
        )
    finally:
        con.close()


def main() -> int:
    """Run the tracct daemon in the foreground (under a service manager)."""
    # Hold an exclusive lock for the daemon's lifetime: a second instance would unlink
    # and rebind the live feed socket and write the same database. The kernel drops the
    # lock when the process exits, so a crash never leaves a stale lock behind.
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(
        RUN_DIR / "tracct.lock",
        os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o644,
    )
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logger.error(
            f"tracct is already running (lock held on {RUN_DIR / 'tracct.lock'})"
        )
        return 1
    init_database()
    if err := check_database():
        return err
    # Read once: a change takes a restart.
    config = load_config()
    set_levels(config.log)
    files = config_files()
    logger.info(
        f"config: {', '.join(map(str, files)) if files else f'{CONFIG_PATH} (not found, using defaults)'}"
    )
    logger.info(f"state: {STATE_DIR}")
    logger.info(f"run: {RUN_DIR}")
    return run_main_loop(config)


def start_tracct() -> int:
    """Command line interface, pre-startup checks, and run."""
    if not sys.platform.startswith("linux"):
        logger.error("Did not detect a supported operating system")
        return 1
    configure_logging()
    parser = argparse.ArgumentParser(
        prog="tracct",
        description="Traffic accounting per process, unit and interface, recorded with BPF and kept in SQLite.",
        epilog=(
            f"config: {CONFIG_PATH}, state: {STATE_DIR}, run: {RUN_DIR}. "
            "These follow $TRACCT_CONFIG (a file), else $CONFIGURATION_DIRECTORY, $STATE_DIRECTORY and $RUNTIME_DIRECTORY "
            "as set by systemd; the query socket follows $TRACCT_QUERY_SOCKET."
        ),
    )
    parser.add_argument("--version", action="version", version=f"tracct {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "run", help="run the daemon in the foreground (used by tracct.service)"
    )
    view = commands.add_parser(
        "view",
        help="live and history viewer (needs tracct[viewer])",
        description="Browse live and recorded traffic.",
    )
    add_viewer_arguments(view)
    commands.add_parser(
        "query-server", help="answer history queries (used by tracct-query.service)"
    )
    install = commands.add_parser(
        "install",
        help="write the units, the sysusers file and the base config",
        description=(
            "Write tracct's systemd units, sysusers file and base config.toml, with the "
            "units starting this tracct, after saying what will be written and asking. "
            "Files that differ are kept unless --force is given. If any target cannot "
            "be written, nothing is written."
        ),
    )
    add_install_arguments(install)
    uninstall = commands.add_parser(
        "uninstall",
        help="stop the units and remove what install wrote",
        description=(
            "Stop and disable tracct's units and remove the files install wrote, after "
            "saying what will go and asking. The drop-ins in config.d and the database "
            "stay unless --purge is given."
        ),
    )
    add_uninstall_arguments(uninstall)
    commands.add_parser(
        "status",
        help="show what is installed and running",
        description=(
            "Show the installed files and whether they were modified, the drop-ins, the "
            "units, conntrack accounting, the viewer group and the database. Only the "
            "database needs root."
        ),
    )
    args = parser.parse_args()
    if args.command == "run":
        if err := check_capabilities():
            return err
        return main()
    elif args.command == "view":
        try:
            return run_viewer(args)
        except ImportError as e:
            logger.error(
                f"the viewer needs Textual and tcoda, installed with tracct[viewer] "
                f"({e})"
            )
            return 1
    elif args.command == "install":
        return run_install(args)
    elif args.command == "uninstall":
        return run_uninstall(args)
    elif args.command == "status":
        return status()
    else:
        return run_query_server()


if __name__ == "__main__":
    sys.exit(start_tracct())
