# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import fcntl
import logging
import os
import sqlite3
import stat
import sys
import textwrap
from pathlib import Path

from picosnitch.config import load_config
from picosnitch.constants import CONFIG_PATH, DB_PATH, DB_VERSION, INDEXES, RUN_DIR, SENTINELS, STATE_DIR, TABLES, VERSION
from picosnitch.main_loop import run_main_loop
from picosnitch.query_server import run_query_server
from picosnitch.utils import connect_db_readonly, quarantine_database, sqlite_error_means_corrupt

# what the daemon needs, as root or as an unprivileged user with ambient capabilities
REQUIRED_CAPABILITIES: dict[str, int] = {
    # list /proc/<pid>/fd of other users' processes (mode 0500, a plain permission check that
    # CAP_SYS_PTRACE does not override): the startup seed and the TUN devices of a process
    "CAP_DAC_READ_SEARCH": 2,
    "CAP_NET_ADMIN": 12,  # read the conntrack table and its events for forwarded traffic
    "CAP_SYS_PTRACE": 19,  # resolve /proc/<pid>/exe and open /proc/<pid>/ns/net of other users' processes
    # attach the getaddrinfo uprobe: its perf event is refused without, at any perf_event_paranoid
    # (checked on Ubuntu's kernel 7.0); without the uprobe, domains come from reverse DNS only.
    # also joins other network namespaces (setns) to read their interfaces
    "CAP_SYS_ADMIN": 21,
    "CAP_PERFMON": 38,  # attach kprobes, uprobes and fexit programs
    "CAP_BPF": 39,  # load BPF programs and maps
}


class _JournalFormatter(logging.Formatter):
    """prefix each record with its sd-daemon(3) priority so journald keeps the level"""

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
    """journald adds its own timestamps; anywhere else they come with the message"""
    if os.getenv("JOURNAL_STREAM"):
        formatter: logging.Formatter = _JournalFormatter("%(name)s: %(message)s")
    else:
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    for handler in logging.getLogger().handlers:
        handler.setFormatter(formatter)


def check_capabilities() -> int:
    """check the effective capabilities and BPF requirements, return exit code on failure"""
    with open("/proc/self/status", "r") as f:
        proc_status = f.read()
    capeff = int(proc_status[proc_status.find("CapEff:") + 8 :].splitlines()[0].strip(), base=16)
    missing = [name for name, bit in REQUIRED_CAPABILITIES.items() if not capeff & (1 << bit)]
    if missing:
        logging.error(f"Missing capabilities: {' '.join(missing)} (run as root or grant them with AmbientCapabilities=)")
        return 1
    from .bpf_wrapper import check_bpf_requirements

    try:
        check_bpf_requirements()
    except (RuntimeError, FileNotFoundError) as e:
        logging.error(f"{e}")
        return 1
    return 0


def check_database() -> int:
    """check database exists and has correct version, return exit code on failure"""
    if not DB_PATH.exists():
        logging.error(f"Database not found: {DB_PATH}")
        logging.error("Start the picosnitch service to create it (systemctl start picosnitch)")
        return 1
    con = None
    try:
        con = connect_db_readonly(DB_PATH)
        cur = con.cursor()
        cur.execute("PRAGMA user_version")
        user_version = cur.fetchone()[0]
    except sqlite3.Error as e:
        # sqlite3.Error (not just OperationalError) so a corrupt db -> DatabaseError returns 1
        # instead of crashing the boot path (init_database quarantines it beforehand)
        logging.error(f"Could not open database {DB_PATH}: {e}")
        return 1
    finally:
        if con is not None:
            con.close()
    if user_version != DB_VERSION:
        logging.error(f"Unsupported database version {user_version}, expected {DB_VERSION}")
        return 1
    return 0


def _db_is_corrupt(db_path: Path) -> bool:
    """True if the db can't be opened, its version read, or its expected tables are present -- such
    a db must be quarantined+recreated, else check_database or the writer's first maintenance pass
    crash-loops the daemon. A populated db with the wrong version is NOT corrupt (returns False) so
    check_database can reject it without destroying its data; an empty or schema-less file with a
    wrong version holds nothing and IS treated as recreatable."""
    try:
        db_stat = db_path.lstat()
        if not stat.S_ISREG(db_stat.st_mode) or db_stat.st_nlink != 1:
            return True
        con = sqlite3.connect(db_path)
        try:
            cur = con.cursor()
            if cur.execute("PRAGMA user_version").fetchone()[0] != DB_VERSION:
                # recreate a 0-byte db a killed writer left behind instead of preserving it
                has_schema = cur.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'connections'").fetchone()
                return has_schema is None
            # validate the tables AND the columns the boot purge / inserts need: a db with the
            # right table names but wrong columns (a foreign db sharing the version) passes a
            # name-only check yet crashes the writer. LIMIT 0 validates the
            # columns without reading any rows; a missing table or column raises here.
            cur.execute("SELECT contime, domain_id, laddr_id, raddr_id, unit_id, iface_id FROM connections LIMIT 0")
            cur.execute("SELECT id, exe, name, cmdline FROM executables LIMIT 0")
            for table, _ in TABLES:
                cur.execute(f"SELECT * FROM {table} LIMIT 0")
            return False
        finally:
            con.close()
    except sqlite3.DatabaseError as e:
        # not a database / malformed header / missing table or column -> corrupt; a transient
        # error (locked by the live daemon or a user's sqlite session, busy, disk I/O) must
        # NOT quarantine a healthy db (e.g. one the query server or a sqlite session has open)
        return sqlite_error_means_corrupt(e)


def init_database() -> None:
    """create the state directory and database if missing (systemd creates the directory for a unit)"""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    db_path = DB_PATH
    if (db_path.exists() or db_path.is_symlink()) and _db_is_corrupt(db_path):
        # quarantine a corrupt db and recreate it below, so check_database / the writer's first
        # maintenance pass don't crash-loop the daemon (data is kept in picosnitch.db.bad)
        logging.error(f"picosnitch.db is unusable, quarantining to {db_path.name}.bad and recreating")
        quarantine_database(db_path)
    if not db_path.exists():
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        for table, schema in TABLES:
            cur.execute(f"CREATE TABLE {table} ({schema}) STRICT")
        for statement in SENTINELS + INDEXES:
            cur.execute(statement)
        cur.execute(f"PRAGMA user_version = {DB_VERSION}")
        con.commit()
        con.close()
    # readers must not block the writer; sqlite ignores this inside a transaction, so it runs on
    # its own, and as the mode is kept in the file this also converts a database made without it
    con = sqlite3.connect(db_path)
    try:
        mode = con.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if mode != "wal":
            logging.warning(f"picosnitch.db stays in journal mode {mode}; readers will block writes")
    except sqlite3.OperationalError as e:
        # another connection holds the database; the next start tries again
        logging.warning(f"could not switch picosnitch.db to WAL mode ({e}); readers will block writes")
    finally:
        con.close()


def main() -> int:
    """run the picosnitch daemon in the foreground (under a service manager)"""
    # hold an exclusive lock for the daemon's lifetime: a second instance would unlink and
    # rebind the live feed socket and write the same database. the kernel drops the lock
    # when the process exits, so a crash never leaves a stale lock behind
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(RUN_DIR / "picosnitch.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logging.error(f"picosnitch is already running (lock held on {RUN_DIR / 'picosnitch.lock'})")
        return 1
    init_database()
    if err := check_database():
        return err
    # read once: a change takes a restart
    config = load_config()
    logging.info(f"config: {CONFIG_PATH}{'' if CONFIG_PATH.exists() else ' (not found, using defaults)'}")
    logging.info(f"state: {STATE_DIR}")
    logging.info(f"run: {RUN_DIR}")
    return run_main_loop(config)


def start_picosnitch() -> int:
    """command line interface, pre-startup checks, and run"""
    if sys.version_info < (3, 12):
        logging.error("Python version >= 3.12 is required")
        return 1
    if not sys.platform.startswith("linux"):
        logging.error("Did not detect a supported operating system")
        return 1
    configure_logging()
    readme = textwrap.dedent(
        f"""
        Monitor your system for applications that make network connections and track
        their bandwidth.

        Picosnitch comes with ABSOLUTELY NO WARRANTY. This is free software, and you
        are welcome to redistribute it under certain conditions. See version 3 of the
        GNU General Public License for details.

        version: {VERSION}
        entrypoint: {Path(sys.argv[0]).resolve()}
        config: {CONFIG_PATH}
        state: {STATE_DIR}
        run: {RUN_DIR}

        usage:
            picosnitch run|view|query-server|version|help
                        |   |    |            |       |--> this text
                        |   |    |            |--> version number
                        |   |    |--> answer history queries (used by picosnitch-query.service)
                        |   |--> live and history viewer (needs picosnitch[tui]; view --help)
                        |--> run the daemon in the foreground (used by picosnitch.service)

            systemctl enable|disable|start|stop|restart|status picosnitch

        paths follow $PICOSNITCH_CONFIG (a file), else $CONFIGURATION_DIRECTORY,
        $STATE_DIRECTORY and $RUNTIME_DIRECTORY as set by systemd; the query socket
        follows $PICOSNITCH_QUERY_SOCKET
        """.lstrip("\n")
    )
    if len(sys.argv) >= 2 and sys.argv[1] == "view":
        try:
            from picosnitch.viewer import run_viewer
        except ImportError as e:
            logging.error(f"the viewer needs Textual, installed with picosnitch[tui] ({e})")
            return 1
        return run_viewer(sys.argv[2:])
    if len(sys.argv) != 2:
        print(readme)
        return 2
    cmd = sys.argv[1]
    if cmd == "help":
        print(readme)
        return 0
    elif cmd == "version":
        print(f"version: {VERSION}")
        return 0
    elif cmd == "run":
        if err := check_capabilities():
            return err
        return main()
    elif cmd == "query-server":
        return run_query_server()
    else:
        print(readme)
        return 2


if __name__ == "__main__":
    sys.exit(start_picosnitch())
