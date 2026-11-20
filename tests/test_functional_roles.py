# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""End-to-end tests of the role a connection's socket is recorded with: how its local
port came to be (see "Storage" in docs/DESIGN.md).

Their own module, so the daemon can start after a connection is already open. They need
root and the built BPF object, like test_functional.py, whose helpers they use.
"""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from test_functional import (
    DB_WRITE_LIMIT,
    PYTHON_EXE,
    TEST_ROOT,
    TRAFFIC_WAIT,
    clean_test_dirs,
    query_db,
    start_tracct,
    stop_tracct,
)

from tracct.constants import ROLE_ACCEPTED, ROLE_BOUND, ROLE_PICKED

IPPROTO_MPTCP = 262
#: Ports below the ephemeral range, so no client gets one as its source port.
PORT_TCP, PORT_BOUND_CLIENT, PORT_BOUND_SERVER, PORT_UDP, PORT_MPTCP, PORT_EARLY = (
    24821,
    24822,
    24823,
    24824,
    24825,
    24826,
)
#: Outside TEST_ROOT, which start-up wipes.
EARLY_GO = Path("/tmp/tracct-roles-go")

#: A TCP pair opened before the daemon starts; it exchanges bytes once EARLY_GO exists.
EARLY_SCRIPT = f"""
import os, socket, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", {PORT_EARLY}))
srv.listen(1)
c = socket.create_connection(("127.0.0.1", {PORT_EARLY}))
a, _ = srv.accept()
while not os.path.exists("{EARLY_GO}"):
    time.sleep(0.1)
c.sendall(b"E" * 5000)
a.recv(5000, socket.MSG_WAITALL)
a.sendall(b"F" * 5000)
c.recv(5000, socket.MSG_WAITALL)
"""

#: One exchange per case, both ends in this process.
CASES_SCRIPT = f"""
import socket

def tcp_pair(port, bind=None, proto=0):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto)
    if bind:
        c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        c.bind(("127.0.0.1", bind))
    c.connect(("127.0.0.1", port))
    a, _ = srv.accept()
    c.sendall(b"x" * 3000)
    a.recv(3000, socket.MSG_WAITALL)
    a.sendall(b"y" * 3000)
    c.recv(3000, socket.MSG_WAITALL)
    for s in (c, a, srv):
        s.close()

tcp_pair({PORT_TCP})
tcp_pair({PORT_BOUND_SERVER}, bind={PORT_BOUND_CLIENT})
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", {PORT_UDP}))
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.sendto(b"u" * 300, ("127.0.0.1", {PORT_UDP}))
data, peer = srv.recvfrom(300)
srv.sendto(b"v" * 300, peer)
c.recv(300)
try:
    tcp_pair({PORT_MPTCP}, proto={IPPROTO_MPTCP})
except OSError as e:
    print("no MPTCP:", e)
"""


@pytest.fixture(scope="module")
def roles_session():
    if os.geteuid() != 0:
        pytest.skip("Tests require root privileges.")
    clean_test_dirs()
    EARLY_GO.unlink(missing_ok=True)
    early = subprocess.Popen([PYTHON_EXE, "-c", EARLY_SCRIPT])
    proc = None
    try:
        time.sleep(1)
        proc = start_tracct()
        yield proc
    finally:
        early.kill()
        early.wait()
        EARLY_GO.unlink(missing_ok=True)
        if proc is not None:
            stop_tracct(proc)
        shutil.rmtree(TEST_ROOT, ignore_errors=True)


def _roles(where: str, params: tuple) -> set[tuple[int, int]]:
    """(protocol, role) of the rows with bytes that match where."""
    return set(
        query_db(
            f"SELECT protocol, role FROM connections WHERE sent + received > 0 AND {where}",
            params,
        )
    )


def test_roles_of_servers_clients_and_bound_ports(roles_session):
    out = subprocess.run(
        [PYTHON_EXE, "-c", CASES_SCRIPT],
        check=True,
        timeout=60,
        capture_output=True,
        text=True,
    ).stdout
    mptcp = "no MPTCP" not in out
    EARLY_GO.touch()
    expected = {
        # A plain server and its client.
        ("lport = ?", (PORT_TCP,)): {(6, ROLE_ACCEPTED)},
        ("rport = ? AND lport != ?", (PORT_TCP, PORT_TCP)): {(6, ROLE_PICKED)},
        # A TCP client bound to a fixed port is still the client.
        ("lport = ?", (PORT_BOUND_CLIENT,)): {(6, ROLE_BOUND)},
        ("lport = ?", (PORT_BOUND_SERVER,)): {(6, ROLE_ACCEPTED)},
        # UDP has no accept: the server's port is bound, the client's picked.
        ("lport = ?", (PORT_UDP,)): {(17, ROLE_BOUND)},
        ("rport = ? AND lport != ?", (PORT_UDP, PORT_UDP)): {(17, ROLE_PICKED)},
        # Read from the socket, so a connection open before the start has it too.
        ("lport = ?", (PORT_EARLY,)): {(6, ROLE_ACCEPTED)},
        ("rport = ? AND lport != ?", (PORT_EARLY, PORT_EARLY)): {(6, ROLE_PICKED)},
    }
    if mptcp:
        # Read from the first subflow.
        expected[("lport = ?", (PORT_MPTCP,))] = {(IPPROTO_MPTCP, ROLE_ACCEPTED)}
        expected[("rport = ? AND lport != ?", (PORT_MPTCP, PORT_MPTCP))] = {
            (IPPROTO_MPTCP, ROLE_PICKED)
        }
    deadline = time.time() + (DB_WRITE_LIMIT + TRAFFIC_WAIT) * 3
    found: dict = {}
    while time.time() < deadline:
        time.sleep(2)
        found = {case: _roles(*case) for case in expected}
        if found == expected:
            break
    assert found == expected
