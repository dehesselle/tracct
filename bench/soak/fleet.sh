#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

# The soak boxes from where the run is watched.
#
#   fleet.sh tick [since]       each box's last check, and its WARN/ERR/FAIL since
#   fleet.sh watch <seconds>    look every 30 s; return early with 2 on a FAIL or ERR,
#                               else print a tick after <seconds>
#
# SOAK_HOSTS names the ssh hosts (default hetzner-soak1 to 5), SOAK_SSH_CONFIG their
# ssh config (default .devbox/ssh_config), SOAK_DIR the checkout on them.
set -uo pipefail
hosts=${SOAK_HOSTS:-hetzner-soak1 hetzner-soak2 hetzner-soak3 hetzner-soak4 hetzner-soak5}
config=${SOAK_SSH_CONFIG:-.devbox/ssh_config}
dir=${SOAK_DIR:-/root/tracct}

summary() {  # host since
    ssh -F "$config" -o ConnectTimeout=10 -o BatchMode=yes "$1" \
        "$dir/bench/soak/check.py summary --since $2"
}

tick() {  # since
    status=0
    for host in $hosts; do
        echo "== $host"
        summary "$host" "$1" || status=2
    done
    return $status
}

case ${1:-} in
tick)
    tick "${2:-0}"
    ;;
watch)
    since=$(date +%s)
    end=$((since + $2))
    while [ "$(date +%s)" -lt "$end" ]; do
        sleep 30
        for host in $hosts; do
            if ! summary "$host" "$since" >/dev/null 2>&1; then
                echo "!! $host reports a FAIL or ERR"
                tick "$since"
                exit 2
            fi
        done
    done
    tick "$since"
    ;;
*)
    echo "usage: $0 tick [since] | watch <seconds>" >&2
    exit 1
    ;;
esac
