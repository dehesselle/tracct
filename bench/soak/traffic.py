#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Traffic for the soak run: a scenario on a timeline against the installed unit.

  traffic.py reset [--raw-min 10] [--rollup-min 25]   fresh database, soak drop-in,
                                                      check loop started
  traffic.py run --scenario NAME [--minutes 40]       the scenario, until its end

Generators are child processes of `run`, each with --tag in its command line, so the
checker finds their rows; each writes its bytes sent, cumulative, to
/var/log/soak/ledger/<tag>.jsonl. Restarts, kills, config changes and downtime go to
/var/log/soak/events.jsonl, so the checker can tell them from failures.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import random
import selectors
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

SOAK = Path(__file__).resolve().parent
BENCHLOAD = SOAK.parent / "bin" / "benchload"
TRACCT_PYTHON = "/opt/tracct/bin/python"
LOG = Path("/var/log/soak")
LEDGER = LOG / "ledger"
EVENTS = LOG / "events.jsonl"
CONFIG_D = Path("/etc/opt/tracct/config.d")
DROP_IN = CONFIG_D / "99-soak.toml"
#: Sorts after DROP_IN, so its options win.
OPS_DROP_IN = CONFIG_D / "99-zz-ops.toml"
STATE = Path("/var/lib/private/tracct")
DB = STATE / "tracct.db"
SINK_PORT = 9300
ROUTED_PORT = 9400
EXEC_PORT = 10000
ARGV_PORT = 10001
CHURN_PORT = 20000
#: Past the 4 KiB the reader keeps of a command line.
PAD = "x" * 4200
WEB_HOSTS = (
    "https://example.com/",
    "https://www.debian.org/",
    "https://www.kernel.org/",
    "https://www.wikipedia.org/",
    "https://github.com/",
)


def sh(cmd: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    r = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd}: {r.stderr.strip()}")
    return r


def event(action: str, **detail: object) -> None:
    with open(EVENTS, "a") as f:
        f.write(json.dumps({"t": round(time.time(), 3), "action": action, **detail}))
        f.write("\n")
    print(f"{time.strftime('%H:%M:%S')} {action} {detail or ''}", flush=True)


class Ledger:
    """The bytes a generator sent, cumulative, at most once a second; a generator
    taking up a tag again (one per namespace made) goes on from the last count.
    """

    def __init__(self, tag: str) -> None:
        LEDGER.mkdir(parents=True, exist_ok=True)
        path = LEDGER / f"{tag}.jsonl"
        self.sent = 0
        if path.exists():
            lines = path.read_text().splitlines()
            if lines:
                self.sent = json.loads(lines[-1])["sent"]
        self.base = self.sent
        self.file = open(path, "a", buffering=1)
        self.last = 0.0
        self.flush()
        # The last second too when the generator is stopped (SIGTERM exits, see main).
        atexit.register(self.flush)

    def add(self, n: int) -> None:
        self.sent += n
        if time.time() - self.last >= 1:
            self.flush()

    def flush(self) -> None:
        self.last = time.time()
        self.file.write(json.dumps({"t": round(self.last, 3), "sent": self.sent}))
        self.file.write("\n")


# --- generators, each its own process ---


def gen_tcp(args) -> None:
    """Long-lived TCP clients, each sending --bytes every --interval seconds."""
    ledger = Ledger(args.tag)
    payload = b"p" * args.bytes
    socks: list[socket.socket | None] = [None] * args.clients
    end = time.monotonic() + args.seconds
    tick = time.monotonic()
    while time.monotonic() < end:
        for i, sock in enumerate(socks):
            try:
                if sock is None:
                    sock = socket.create_connection((args.host, args.port), timeout=5)
                    socks[i] = sock
                sock.sendall(payload)
                ledger.add(len(payload))
            except OSError:
                if sock is not None:
                    sock.close()
                socks[i] = None
        tick += args.interval
        time.sleep(max(0.0, tick - time.monotonic()))
    ledger.flush()


def gen_udp(args) -> None:
    """32-byte datagrams from benchload spray, --rate a second, across --addrs addresses
    from --net and --ports ports from --port: every datagram a connection of its own
    until the combinations wrap. In C, as Python resolves every address it sends to,
    and tracct's getaddrinfo probe would see each.
    """
    ledger = Ledger(args.tag)
    proc = subprocess.Popen(
        [
            str(BENCHLOAD),
            "spray",
            args.net,
            str(args.addrs),
            str(args.port),
            str(args.ports),
            str(int(args.rate)),
            str(args.seconds),
            args.tag,
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        for out in proc.stdout:
            if out.startswith(("PROGRESS sent=", "RESULT sent=")):
                ledger.add(int(out.split("=")[1]) - ledger.sent + ledger.base)
    finally:
        proc.terminate()
        ledger.flush()


def gen_exec(args) -> None:
    """--rate short-lived benchload processes a second, one datagram each; with --argv
    their command lines run past 4 KiB and differ only there.
    """
    ledger = Ledger(args.tag)
    running: list[subprocess.Popen] = []
    end = time.monotonic() + args.seconds
    tick = time.monotonic()
    n = 0
    while time.monotonic() < end:
        # benchload takes no further arguments, so the tag carries the padding.
        tag = f"{args.tag}{PAD}{n}" if args.argv else args.tag
        argv = [str(BENCHLOAD), "once", str(args.port), tag]
        n += 1
        running.append(subprocess.Popen(argv, stdout=subprocess.DEVNULL))
        still = []
        for proc in running:
            if proc.poll() is None:
                still.append(proc)
            elif proc.returncode == 0:
                ledger.add(32)
        running = still
        tick += 1 / args.rate
        time.sleep(max(0.0, tick - time.monotonic()))
    for proc in running:
        if proc.wait() == 0:
            ledger.add(32)
    ledger.flush()


def gen_web(args) -> None:
    """curl and wget against a few real hosts: domains and reverse DNS."""
    end = time.monotonic() + args.seconds
    while time.monotonic() < end:
        for url in WEB_HOSTS:
            sh(f"curl -s -m 10 -o /dev/null -H 'X-Soak: {args.tag}' {url}")
        sh(f"wget -q -T 10 -O /dev/null --header='X-Soak: {args.tag}' {WEB_HOSTS[0]}")
        time.sleep(args.interval)


def gen_query(args) -> None:
    """Viewer-like requests to the query server, their latency and errors logged."""
    from tracct.query import QueryClient, QueryError

    client = QueryClient()
    requests = (
        ("aggregate", {"source": "connections", "group_by": "name"}),
        ("aggregate", {"source": "connections", "group_by": "domain"}),
        ("aggregate", {"source": "connections", "group_by": "unit"}),
        ("aggregate", {"source": "connections", "group_by": "raddr"}),
        ("aggregate", {"source": "interfaces", "group_by": "iface"}),
        ("aggregate", {"source": "forwarded"}),
        ("timeline", {"source": "connections", "step": 60, "peak": 10}),
        ("timeline", {"source": "interfaces", "step": 120, "peak": 60}),
    )
    end = time.monotonic() + args.seconds
    n = 0
    with open(LOG / "query.jsonl", "a", buffering=1) as log:
        while time.monotonic() < end:
            op, params = requests[n % len(requests)]
            n += 1
            span = random.choice((600, 1800, 3600))
            now = int(time.time())
            started = time.monotonic()
            error = None
            try:
                client.request(op, start=now - span, end=now + 1, **params)
            except (QueryError, OSError) as e:
                error = f"{type(e).__name__}: {e}"
            entry = {
                "t": round(time.time(), 3),
                "op": op,
                **params,
                "span": span,
                "seconds": round(time.monotonic() - started, 3),
                "error": error,
            }
            log.write(json.dumps(entry) + "\n")
            time.sleep(args.interval)


def sink(args) -> None:
    """Accept TCP connections on --port and read what comes."""
    serve_sink(args.port)
    threading.Event().wait()


def serve_sink(port: int) -> None:
    def run() -> None:
        selector = selectors.DefaultSelector()
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(1024)
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ)
        while True:
            for key, _ in selector.select():
                if key.fileobj is listener:
                    try:
                        conn, _ = listener.accept()
                    except OSError:
                        continue
                    conn.setblocking(False)
                    selector.register(conn, selectors.EVENT_READ)
                    continue
                conn = key.fileobj
                try:
                    data = conn.recv(65536)
                except BlockingIOError:
                    continue
                except OSError:
                    data = b""
                if not data:
                    selector.unregister(conn)
                    conn.close()

    threading.Thread(target=run, daemon=True).start()


# --- the scenario runner ---


class Runner:
    def __init__(self, scenario: str, minutes: float) -> None:
        self.scenario = scenario
        self.seconds = minutes * 60
        self.started = time.time()
        self.children: list[subprocess.Popen] = []
        self.stopping = threading.Event()
        self.netns_cycle = False
        self.router = False

    def spawn(self, kind: str, *argv: str, netns: str | None = None, python=None):
        cmd = [python or sys.executable, str(Path(__file__)), kind, *argv]
        if netns:
            cmd = ["ip", "netns", "exec", netns, *cmd]
        self.children.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL))

    def gen(self, kind: str, tag: str, seconds: float, *argv: str, **kw) -> None:
        self.spawn(kind, "--tag", tag, "--seconds", str(int(seconds)), *argv, **kw)

    def at(self, minute: float, action, *args) -> None:
        self.schedule.append((minute, action, args))

    # --- disturbances ---

    def restart(self) -> None:
        event("restart")
        sh("systemctl restart tracct")

    def kill(self) -> None:
        event("kill")
        sh("systemctl kill -s KILL tracct")

    def config(self, window: int | None, period: int | None) -> None:
        if window is None:
            event("config", window=None, period=None)
            OPS_DROP_IN.unlink(missing_ok=True)
        else:
            event("config", window=window, period=period)
            OPS_DROP_IN.write_text(
                f"[database]\nwrite_limit_seconds = {window}\nrollup_period_minutes = {period}\n"
            )
        sh("systemctl restart tracct")
        # Its window and period are those of the daemon.
        sh("systemctl stop tracct-query.service")

    def stop(self) -> None:
        event("stop")
        sh("systemctl stop tracct")

    def start(self) -> None:
        event("start")
        sh("systemctl start tracct")

    def old_database(self) -> None:
        """A database of schema version 7 is refused; moved aside, a new one starts."""
        event("v7-start")
        sh("systemctl stop tracct")
        for suffix in ("", "-wal", "-shm"):
            Path(f"{DB}{suffix}").unlink(missing_ok=True)
        con = sqlite3.connect(DB)
        con.execute("CREATE TABLE connections (time INTEGER)")
        con.execute("PRAGMA user_version = 7")
        con.commit()
        con.close()
        sh(f"chown --reference={STATE} {DB}")
        since = time.strftime("%Y-%m-%d %H:%M:%S")
        sh("systemctl start tracct")
        time.sleep(12)
        state = sh("systemctl show tracct -p ActiveState,SubState,NRestarts").stdout
        refused = sh(
            f"journalctl -u tracct --since '{since}' --no-pager -o cat | grep -c 'Unsupported database version'"
        ).stdout.strip()
        sh("systemctl stop tracct")
        os.replace(DB, f"{DB}.v7")
        sh("systemctl reset-failed tracct")
        sh("systemctl start tracct")
        event("v7-done", refusals=refused, state=" ".join(state.split()))

    # --- namespaces ---

    def netns_loop(self, life: float = 20.0, period: float = 30.0) -> None:
        """nsa and nsb in turn, each made, used for --life seconds and removed, so the
        next takes the inode the last one left.
        """
        n = 0
        while not self.stopping.is_set():
            name = ("nsa", "nsb")[n % 2]
            subnet = 1 + n % 2
            n += 1
            host, inner = f"vh-{name}", f"vin-{name}"
            sh(f"ip netns del {name}")
            sh(f"ip netns add {name}", check=True)
            sh(f"ip link add {host} type veth peer name {inner} netns {name}")
            sh(f"ip addr add 10.201.{subnet}.1/30 dev {host}")
            sh(f"ip link set {host} up")
            sh(f"ip -n {name} addr add 10.201.{subnet}.2/30 dev {inner}")
            sh(f"ip -n {name} link set {inner} up")
            sh(f"ip -n {name} link set lo up")
            event("netns-up", name=name)
            self.gen(
                "gen-tcp",
                f"ns-{name}",
                life,
                "--host",
                f"10.201.{subnet}.1",
                "--port",
                str(SINK_PORT),
                "--clients",
                "3",
                "--bytes",
                "2048",
                "--interval",
                "0.2",
                netns=name,
            )
            self.stopping.wait(life + 1)
            sh(f"ip netns pids {name} | xargs -r kill")
            sh(f"ip netns del {name}")
            event("netns-down", name=name)
            self.stopping.wait(max(0.0, period - life - 1))

    def router_up(self) -> None:
        """cl1 -- rtr -- cl2, rtr forwarding with a ct rule, so conntrack tracks there."""
        self.router_down()
        for ns in ("rtr", "cl1", "cl2"):
            sh(f"ip netns add {ns}", check=True)
            sh(f"ip -n {ns} link set lo up")
        for i in (1, 2):
            sh(f"ip -n rtr link add r{i} type veth peer name c{i} netns cl{i}")
            sh(f"ip -n rtr addr add 10.210.{i}.1/24 dev r{i}")
            sh(f"ip -n rtr link set r{i} up")
            sh(f"ip -n cl{i} addr add 10.210.{i}.2/24 dev c{i}")
            sh(f"ip -n cl{i} link set c{i} up")
            sh(f"ip -n cl{i} route add default via 10.210.{i}.1")
        sh("ip netns exec rtr sysctl -qw net.ipv4.ip_forward=1")
        sh("ip netns exec rtr sysctl -qw net.netfilter.nf_conntrack_acct=1")
        subprocess.run(
            ["ip", "netns", "exec", "rtr", "nft", "-f", "-"],
            input="table inet soak {\n chain pass {\n  type filter hook forward priority 0;\n"
            "  ct state new,established,related counter accept\n }\n}\n",
            text=True,
            check=True,
        )
        self.spawn("sink", "--port", str(ROUTED_PORT), netns="cl2")
        time.sleep(1)
        rest = self.seconds - (time.time() - self.started)
        self.gen(
            "gen-tcp",
            "routed",
            rest,
            "--host",
            "10.210.2.2",
            "--port",
            str(ROUTED_PORT),
            "--clients",
            "10",
            "--bytes",
            "4096",
            "--interval",
            "0.1",
            netns="cl1",
        )
        self.gen(
            "gen-udp",
            "routed-udp",
            rest,
            "--rate",
            "200",
            "--net",
            "10.210.2.2",
            "--addrs",
            "1",
            "--ports",
            "300",
            "--port",
            str(CHURN_PORT),
            netns="cl1",
        )
        event("router-up")

    def router_down(self) -> None:
        for ns in ("cl1", "cl2", "rtr"):
            sh(f"ip netns pids {ns} | xargs -r kill")
            sh(f"ip netns del {ns}")

    # --- the scenarios ---

    def steady(self, scale: float = 1.0) -> None:
        s = self.seconds
        self.gen(
            "gen-tcp",
            "tcp",
            s,
            "--host",
            "127.0.0.1",
            "--port",
            str(SINK_PORT),
            "--clients",
            str(int(200 * scale)),
            "--bytes",
            "512",
            "--interval",
            "0.5",
        )
        self.gen(
            "gen-exec", "exec", s, "--rate", str(30 * scale), "--port", str(EXEC_PORT)
        )
        self.gen(
            "gen-exec", "argv", s, "--rate", "0.5", "--argv", "--port", str(ARGV_PORT)
        )
        self.gen("gen-web", "web", s, "--interval", "20")

    def background(self) -> None:
        s = self.seconds
        self.gen(
            "gen-tcp",
            "tcp",
            s,
            "--host",
            "127.0.0.1",
            "--port",
            str(SINK_PORT),
            "--clients",
            "20",
            "--bytes",
            "512",
            "--interval",
            "0.5",
        )
        self.gen("gen-exec", "exec", s, "--rate", "5", "--port", str(EXEC_PORT))

    def burst(self, minute: float, seconds: float, tag: str, procs: int = 2) -> None:
        """Datagrams across 60 000 addresses and 40 ports, procs x 17 000 a second: past
        the 65 536 connections a 2 s window holds, so windows are written early, and
        short of the 65 536 the kernel's map holds per 1 s drain.
        """
        for i in range(procs):
            self.at(
                minute,
                self.gen,
                "gen-udp",
                f"{tag}-{i}",
                seconds,
                "--rate",
                "17000",
                "--net",
                f"127.{1 + i}.0.0",
                "--addrs",
                "60000",
                "--ports",
                "40",
                "--port",
                str(CHURN_PORT),
            )

    def query_load(self, interval: float) -> None:
        self.gen(
            "gen-query",
            "query",
            self.seconds,
            "--interval",
            str(interval),
            python=TRACCT_PYTHON,
        )

    def plan(self) -> None:
        self.schedule: list = []
        name = self.scenario
        if name == "steady":
            self.steady()
            self.query_load(15)
        elif name == "burst":
            self.background()
            self.burst(6, 45, "burst1")
            self.burst(24, 20, "burst2")
        elif name == "netns":
            self.background()
            self.netns_cycle = self.router = True
        elif name == "ops":
            self.at(0, self.old_database)
            self.at(0.5, self.steady, 0.5)
            self.at(0.5, self.query_load, 10)
            self.at(6, self.restart)
            self.at(12, self.kill)
            self.at(16, self.config, 5, 3)
            self.at(24, self.config, None, None)
            self.at(30, self.stop)
            self.at(33, self.start)
        elif name == "all":
            self.steady(0.5)
            self.query_load(10)
            self.burst(6, 25, "burst1")
            self.burst(24, 15, "burst2")
            self.netns_cycle = self.router = True
        elif name == "smoke":
            self.background()
            self.gen(
                "gen-exec",
                "argv",
                self.seconds,
                "--rate",
                "0.5",
                "--argv",
                "--port",
                str(ARGV_PORT),
            )
            self.gen("gen-web", "web", self.seconds, "--interval", "20")
            self.query_load(10)
            self.at(0, self.old_database)
            self.burst(0.5, 15, "burst1")
            self.at(2.5, self.restart)
            self.at(3.5, self.kill)
            self.at(4.5, self.config, 5, 3)
            self.at(6.5, self.config, None, None)
            self.netns_cycle = self.router = True
        else:
            raise SystemExit(f"unknown scenario {name!r}")

    def run(self) -> None:
        serve_sink(SINK_PORT)
        self.plan()
        event("scenario-start", scenario=self.scenario, minutes=self.seconds / 60)
        threads = []
        if self.router:
            self.router_up()
        if self.netns_cycle:
            threads.append(threading.Thread(target=self.netns_loop, daemon=True))
        for thread in threads:
            thread.start()
        try:
            for minute, action, args in sorted(self.schedule, key=lambda s: s[0]):
                delay = self.started + minute * 60 - time.time()
                if self.stopping.wait(max(0.0, delay)):
                    break
                action(*args)
            self.stopping.wait(max(0.0, self.started + self.seconds - time.time()))
        finally:
            self.stopping.set()
            for thread in threads:
                thread.join(timeout=30)
            for child in self.children:
                child.terminate()
            for child in self.children:
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
            if self.router:
                self.router_down()
            event("scenario-end", scenario=self.scenario)


def reset(args) -> None:
    """Stop the run and the checks, start the unit on a new database with the soak
    settings, and start the check loop.
    """
    sh("systemctl stop soak-traffic soak-check")
    sh("systemctl reset-failed soak-traffic soak-check")
    sh("systemctl stop tracct tracct-query.service")
    for ns in ("nsa", "nsb", "cl1", "cl2", "rtr"):
        sh(f"ip netns del {ns}")
    for path in STATE.glob("tracct.db*"):
        path.unlink()
    CONFIG_D.mkdir(parents=True, exist_ok=True)
    OPS_DROP_IN.unlink(missing_ok=True)
    DROP_IN.write_text(
        "[database]\n"
        "write_limit_seconds = 2\n"
        "rollup_period_minutes = 1\n"
        "maintenance_interval_minutes = 1\n"
        f"raw_retention_days = {args.raw_min / 1440:.6f}\n"
        f"rollup_retention_days = {args.rollup_min / 1440:.6f}\n"
    )
    shutil.rmtree(LOG, ignore_errors=True)
    LEDGER.mkdir(parents=True)
    sh("systemctl reset-failed tracct")
    sh("systemctl start tracct tracct-query.socket", check=True)
    for _ in range(40):
        if DB.exists():
            break
        time.sleep(0.5)
    event("reset", raw_min=args.raw_min, rollup_min=args.rollup_min)
    sh(
        f"systemd-run --unit soak-check --collect {TRACCT_PYTHON} {SOAK / 'check.py'} loop",
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("reset")
    p.add_argument("--raw-min", type=float, default=10)
    p.add_argument("--rollup-min", type=float, default=25)
    p = sub.add_parser("run")
    p.add_argument("--scenario", required=True)
    p.add_argument("--minutes", type=float, default=40)
    p = sub.add_parser("sink")
    p.add_argument("--port", type=int, required=True)
    for kind in ("gen-tcp", "gen-udp", "gen-exec", "gen-web", "gen-query"):
        p = sub.add_parser(kind)
        p.add_argument("--tag", required=True)
        p.add_argument("--seconds", type=float, required=True)
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", type=int, default=SINK_PORT)
        p.add_argument("--clients", type=int, default=1)
        p.add_argument("--bytes", type=int, default=512)
        p.add_argument("--interval", type=float, default=0.5)
        p.add_argument("--rate", type=float, default=1)
        p.add_argument("--net", default="127.1.0.0")
        p.add_argument("--addrs", type=int, default=1)
        p.add_argument("--ports", type=int, default=1)
        p.add_argument("--argv", action="store_true")
    args = parser.parse_args()
    if args.cmd == "reset":
        reset(args)
    elif args.cmd == "run":
        Runner(args.scenario, args.minutes).run()
    elif args.cmd == "sink":
        sink(args)
    else:
        # Stopped with the run or its namespace: exit, so the ledger gets its last
        # count.
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        {
            "gen-tcp": gen_tcp,
            "gen-udp": gen_udp,
            "gen-exec": gen_exec,
            "gen-web": gen_web,
            "gen-query": gen_query,
        }[args.cmd](args)


if __name__ == "__main__":
    main()
