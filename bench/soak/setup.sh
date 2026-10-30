#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

# Prepare a disposable box for the soak run, as root, from a checkout with .git: the
# packages, the bench helpers, tracct built from the tree into /opt/tracct with its
# units and the conntrack options, and conntrack accounting on now rather than from
# the next boot. Replaces an installed tracct; `traffic.py reset` starts it.
set -euo pipefail
cd "$(dirname "$0")/../.."
export DEBIAN_FRONTEND=noninteractive
# The apt timers would compete with the run.
systemctl stop apt-daily.timer apt-daily-upgrade.timer unattended-upgrades 2>/dev/null || true
apt-get update -qq
apt-get install -y -qq clang libbpf-dev libbpf1 nftables iproute2 curl wget sqlite3 \
    build-essential liburing-dev >/dev/null
command -v uv >/dev/null || [ -x ~/.local/bin/uv ] ||
    curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
export PATH="$HOME/.local/bin:$PATH"
bash bench/lib/build.sh >/dev/null
# The system interpreter: the unit runs as a dynamic user, which cannot reach one that
# uv installed under /root (the checkout pins 3.12).
[ -x /opt/tracct/bin/python ] || uv venv -q --python /usr/bin/python3 /opt/tracct
VIRTUAL_ENV=/opt/tracct uv pip install -q --reinstall-package tracct .
/opt/tracct/bin/tracct install -f -y --conntrack >/dev/null
systemd-sysusers
systemctl daemon-reload
systemctl enable tracct tracct-query.socket
modprobe nf_conntrack
echo 1 > /sys/module/nf_conntrack/parameters/acct
sysctl -qw net.netfilter.nf_conntrack_acct=1
/opt/tracct/bin/tracct --version
