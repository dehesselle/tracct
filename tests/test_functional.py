# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

"""
Functional end-to-end tests for picosnitch BPF CO-RE implementation.

These tests verify:
1. Picosnitch daemon starts and stops correctly
2. Network traffic is captured with correct byte counts
3. Short-lived processes are detected with exe paths resolved
4. Database and log files are populated correctly
"""

import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from picosnitch.constants import DB_VERSION

# Constants
PICOSNITCH_DIR = Path(__file__).parent.parent
PYTHON_EXE = sys.executable

# Use a test prefix so tests don't touch the real picosnitch directories
TEST_ROOT = "/tmp/picosnitch"
# point the daemon at the test root through the variables systemd would set
CONFIG_PATH = Path(f"{TEST_ROOT}/etc/config.toml")
STATE_DIR = Path(f"{TEST_ROOT}/state")
RUN_DIR = Path(f"{TEST_ROOT}/run")
# the daemon logs to stderr; a file, not an unread pipe that would block it once full
DAEMON_LOG = Path(f"{TEST_ROOT}/daemon.log")
os.environ["PICOSNITCH_CONFIG"] = str(CONFIG_PATH)
os.environ["STATE_DIRECTORY"] = str(STATE_DIR)
os.environ["RUNTIME_DIRECTORY"] = str(RUN_DIR)

# Test configuration
DB_WRITE_LIMIT = 5  # seconds - we set this in config
STARTUP_WAIT = 8  # seconds to wait for picosnitch to fully start
TRAFFIC_WAIT = 3  # seconds to wait after network activity


def find_executable(name: str) -> str | None:
    """Find the full path to an executable."""
    result = subprocess.run(["which", name], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def clean_test_dirs():
    """Remove and recreate test directories for a fresh test."""
    test_root = Path(TEST_ROOT)
    if test_root.exists():
        shutil.rmtree(test_root)
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)


def start_picosnitch(extra_config_toml: str = "") -> subprocess.Popen:
    """Start the picosnitch daemon in the foreground (`run`) and return the process.

    Waits for the daemon to be fully ready (events socket present) and then
    issues a warmup HTTP request that is polled-for in the database so we
    know the BPF monitor is actually producing events before the test
    starts exercising it. Without this, the first test in a run frequently
    races the BPF attachment and sees no events."""
    config_toml = f"""\
[database]
enabled = true
raw_retention_days = 1
write_limit_seconds = {DB_WRITE_LIMIT}

[log]
addresses = true
commands = true
ports = true

[monitoring]
every_exe = false
exec_ring_buffer_pages = 256
"""
    if extra_config_toml:
        config_toml += "\n" + extra_config_toml

    config_file = CONFIG_PATH
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(config_file, "w") as f:
        f.write(config_toml)

    with open(DAEMON_LOG, "wb") as daemon_log:
        proc = subprocess.Popen([PYTHON_EXE, "-m", "picosnitch", "run"], stdout=daemon_log, stderr=subprocess.STDOUT)

    # wait for the events socket to appear -- means primary subprocess is listening
    events_sock = RUN_DIR / "events.sock"
    deadline = time.time() + STARTUP_WAIT + 10
    while time.time() < deadline:
        if proc.poll() is not None:
            output = DAEMON_LOG.read_text()
            raise RuntimeError(f"picosnitch exited early: {output}")
        if events_sock.exists():
            break
        time.sleep(0.2)

    # additional settle time for BPF program load
    time.sleep(STARTUP_WAIT)

    # warmup: hit a known endpoint and poll for it to appear in the DB so we
    # know the BPF monitor is producing events end-to-end. Retry the warmup
    # up to a few times because the first event after BPF attach can be
    # missed on slower systems.
    warmup_deadline = time.time() + 60
    warmup_seen = False
    while time.time() < warmup_deadline and not warmup_seen:
        subprocess.run(["curl", "-s", "-o", "/dev/null", "https://example.com"], timeout=15)
        # give the writer time to flush
        for _ in range(int((DB_WRITE_LIMIT + 4) * 2)):
            time.sleep(0.5)
            if proc.poll() is not None:
                output = DAEMON_LOG.read_text()
                raise RuntimeError(f"picosnitch exited during warmup: {output}")
            rows = get_connections_for_process("curl")
            if rows:
                warmup_seen = True
                break

    if proc.poll() is not None:
        output = DAEMON_LOG.read_text()
        raise RuntimeError(f"picosnitch exited early: {output}")

    return proc


def stop_picosnitch(proc: subprocess.Popen):
    """Stop picosnitch process and wait for DB flush."""
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    time.sleep(DB_WRITE_LIMIT + 2)


def query_db(query: str, params: tuple = ()) -> list:
    """Execute a query on the picosnitch database."""
    db_path = STATE_DIR / "picosnitch.db"
    if not db_path.exists():
        return []
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    try:
        cur.execute(query, params)
        results = cur.fetchall()
    finally:
        con.close()
    return results


def get_connections_for_process(process_name: str) -> list:
    """Get all connections for a process name."""
    return query_db(
        "SELECT e.name, e.exe, a.addr, c.rport, c.send, c.recv, d.domain "
        "FROM connections c "
        "JOIN executables e ON c.exe_id = e.id "
        "JOIN addresses a ON c.raddr_id = a.id "
        "JOIN domains d ON c.domain_id = d.id "
        "WHERE e.name LIKE ?",
        (f"%{process_name}%",),
    )


@pytest.fixture(scope="module")
def picosnitch_session():
    """Module-scoped fixture that manages picosnitch lifecycle for all tests."""
    if os.geteuid() != 0:
        pytest.skip("Tests require root privileges. Run with: sudo uv run pytest tests/test_functional.py -v")

    clean_test_dirs()

    proc = start_picosnitch()

    yield proc

    stop_picosnitch(proc)
    # Clean up test root
    test_root = Path(TEST_ROOT)
    if test_root.exists():
        shutil.rmtree(test_root)


class TestShortLivedProcesses:
    """Tests for capturing short-lived processes with correct exe paths."""

    def test_curl_exe_resolved(self, picosnitch_session):
        """Test that curl's executable path is resolved even though it exits quickly."""
        curl_exe = find_executable("curl")
        if not curl_exe:
            pytest.skip("curl not available")

        subprocess.run(["curl", "-s", "http://example.com", "-o", "/dev/null"], capture_output=True, timeout=30)

        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        connections = get_connections_for_process("curl")
        assert len(connections) > 0, "Should have captured curl connections"

        for conn in connections:
            name, exe, raddr, rport, send, recv, domain = conn
            assert exe != "", f"curl exe should be resolved, got empty for raddr={raddr} rport={rport}"
            assert "curl" in exe, f"curl exe should contain 'curl', got: {exe}"

    def test_wget_exe_resolved(self, picosnitch_session):
        """Test that wget's executable path is resolved."""
        wget_exe = find_executable("wget")
        if not wget_exe:
            pytest.skip("wget not available")

        # Retry to absorb transient network failures (DNS/connect to example.com)
        # and rare BPF event drops on a busy CI runner. The test is asserting
        # that *when* wget makes a connection, picosnitch resolves its exe -- so
        # any single attempt that produces captured connections is sufficient.
        last_wget_err = ""
        connections: list = []
        for attempt in range(5):
            result = subprocess.run(["wget", "-q", "http://example.com", "-O", "/dev/null"], capture_output=True, timeout=30)
            if result.returncode != 0:
                last_wget_err = result.stderr.decode(errors="replace").strip()
                time.sleep(1)
                continue
            time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)
            connections = get_connections_for_process("wget")
            if connections:
                break
            time.sleep(1)

        assert connections, f"Should have captured wget connections after retries (last wget stderr: {last_wget_err!r})"

        for conn in connections:
            name, exe, raddr, rport, send, recv, domain = conn
            assert exe != "", "wget exe should be resolved, got empty"
            assert "wget" in exe, f"wget exe should contain 'wget', got: {exe}"

    def test_multiple_rapid_curl(self, picosnitch_session):
        """Test that multiple rapid curl invocations all get exe resolved."""
        curl_exe = find_executable("curl")
        if not curl_exe:
            pytest.skip("curl not available")

        for i in range(3):
            subprocess.run(["curl", "-s", "http://example.com", "-o", "/dev/null"], capture_output=True, timeout=30)
            time.sleep(0.5)

        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        connections = get_connections_for_process("curl")
        assert len(connections) >= 1, "Should have captured at least one curl connection"

        # All curl connections should have exe resolved
        for conn in connections:
            name, exe, raddr, rport, send, recv, domain = conn
            assert exe != "", "All curl connections should have exe resolved"


class TestDatabaseIntegrity:
    """Tests for database integrity."""

    def test_database_schema(self, picosnitch_session):
        """Test that database has correct schema."""
        subprocess.run(["curl", "-s", "http://example.com", "-o", "/dev/null"], capture_output=True, timeout=30)
        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        db_path = STATE_DIR / "picosnitch.db"
        assert db_path.exists(), "Database should exist"

        con = sqlite3.connect(str(db_path))
        cur = con.cursor()
        cur.execute("PRAGMA user_version")
        version = cur.fetchone()[0]
        assert version == DB_VERSION, f"Database version should be {DB_VERSION}, got {version}"

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='connections'")
        tables = cur.fetchall()
        assert len(tables) == 1, "connections table should exist"
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='executables'")
        tables = cur.fetchall()
        assert len(tables) == 1, "executables table should exist"
        # identity is by path: no hash column, and process ancestry stops at the parent
        cur.execute("PRAGMA table_info(executables)")
        assert [row[1] for row in cur.fetchall()] == ["id", "exe", "name", "cmdline"]
        cur.execute("PRAGMA table_info(connections)")
        assert "gpexe_id" not in [row[1] for row in cur.fetchall()]
        con.close()

    def test_no_device_mismatch_errors(self, picosnitch_session):
        """Test no 'Exe inode changed' errors (device encoding bug)."""
        subprocess.run(["curl", "-s", "http://example.com", "-o", "/dev/null"], capture_output=True, timeout=30)
        time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

        error_log = DAEMON_LOG
        if error_log.exists():
            content = error_log.read_text()
            assert content.count("Exe inode changed") == 0, "Should not have inode changed errors"


class TestSpliceRecvAccounting:
    """recv via splice() bypasses recvmsg, so only the tcp_splice_read hook sees it; the
    recorded bytes must match what was spliced exactly once (0 means the hook is missing,
    ~2x means another hook double counted the same bytes)."""

    def test_splice_recv_bytes_exact(self, picosnitch_session):
        total = 4 * 1024 * 1024
        port = 42813  # fixed server port so the receiver's connection row is queryable by rport
        script = f"""
import os, socket, threading
total, port = {total}, {port}
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
def send():
    c, _ = srv.accept()
    sent = 0
    while sent < total:
        sent += c.send(b"A" * min(65536, total - sent))
    c.shutdown(socket.SHUT_WR)
    c.close()
t = threading.Thread(target=send)
t.start()
s = socket.create_connection(("127.0.0.1", port))
r, w = os.pipe()
devnull = os.open(os.devnull, os.O_WRONLY)
got = 0
while n := os.splice(s.fileno(), w, 65536):
    left = n
    while left:
        left -= os.splice(r, devnull, left)
    got += n
s.close()
t.join()
assert got == total, got
"""
        subprocess.run([PYTHON_EXE, "-c", script], check=True, timeout=60)

        def spliced_recv_rows() -> list:
            return query_db(
                "SELECT c.send, c.recv FROM connections c JOIN addresses a ON c.raddr_id = a.id WHERE c.rport = ? AND a.addr = '127.0.0.1'",
                (port,),
            )

        deadline = time.time() + (DB_WRITE_LIMIT + TRAFFIC_WAIT) * 3
        rows = []
        while time.time() < deadline:
            time.sleep(2)
            rows = spliced_recv_rows()
            if sum(recv for _, recv in rows) >= total:
                break
        assert rows, "spliced recv connection was not recorded at all (tcp_splice_read hook missing?)"
        # wait out one more write cycle so a straddled flush (or double-counted rows still in
        # flight) can't hide bytes from the final tally
        time.sleep(DB_WRITE_LIMIT + 2)
        rows = spliced_recv_rows()
        recv_total = sum(recv for _, recv in rows)
        assert recv_total == total, f"spliced recv bytes {recv_total} != {total} transferred (2x means double counting), rows: {rows}"


class TestParentTracking:
    """Tests for parent process tracking."""

    def test_shell_curl_parent(self, picosnitch_session):
        """Test that the parent is captured when a shell invokes curl."""
        curl_exe = find_executable("curl")
        if not curl_exe:
            pytest.skip("curl not available")
        bash_exe = find_executable("bash")
        if not bash_exe:
            pytest.skip("bash not available")

        # Spin up a private localhost HTTP server on an ephemeral port so we
        # can later filter `connections` by that exact rport, isolating this
        # test's curl from prior tests' curls, the startup warmup, and any
        # sudo-launched daemon health checks that might also hit example.com.
        import http.server
        import socketserver
        import threading

        class _Quiet(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), _Quiet)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # Bash exec's the last command in place to avoid an extra process;
            # the trailing no-op (`:`) makes it fork curl, so curl's parent is bash.
            #
            # Retry the whole invocation a few times to absorb rare event drops
            # on slow/emulated CI runners.
            results: list = []
            for _ in range(5):
                start_time = int(time.time())
                subprocess.run(
                    [bash_exe, "-c", f"curl -s http://127.0.0.1:{port}/ -o /dev/null; :"],
                    capture_output=True,
                    timeout=30,
                )
                time.sleep(DB_WRITE_LIMIT + TRAFFIC_WAIT)

                # Filter strictly to this test's curl: same rport (unique to this
                # server) and contime within the invocation window. This isolates
                # us from any other curl traffic happening on the box.
                results = query_db(
                    "SELECT p.exe, p.name FROM connections c "
                    "JOIN executables e ON c.exe_id = e.id "
                    "JOIN executables p ON c.pexe_id = p.id "
                    "WHERE e.name LIKE '%curl%' AND c.rport = ? AND c.contime >= ?",
                    (port, start_time),
                )
                if results:
                    break
        finally:
            server.shutdown()
            server.server_close()

        assert len(results) > 0, f"Should have at least one curl connection with a parent (rport={port})"
        pexes = [row[0] for row in results]
        assert any("bash" in pexe for pexe in pexes), f"Parent should be bash, got: {pexes}"


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("WARNING: These tests require root privileges.")
        print("Run with: sudo uv run pytest tests/test_functional.py -v")
        sys.exit(1)
    pytest.main([__file__, "-v"])
