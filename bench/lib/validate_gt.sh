#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Eric Lesiuta
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Validate that the nft wire counter matches what a pcap tap on the interface
# sees (i.e. what nethogs/bandwhich/sniffnet capture), and that peer-side
# offloads are disabled. Also sums the captured frame (L2) bytes.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN=./bin
srv_pid=""; td_pid=""
cleanup() { [ -n "$td_pid" ] && kill "$td_pid" 2>/dev/null; [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null; bash lib/netlab.sh down 2>/dev/null; }
trap cleanup EXIT
bash lib/netlab.sh down 2>/dev/null; bash lib/netlab.sh up
echo "=== peer-side (vbench1) offloads ==="
ip netns exec benchpeer ethtool -k vbench1 2>/dev/null | grep -E "^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload):"
ip netns exec benchpeer "$BIN"/benchserver >/tmp/srv.log 2>&1 &
srv_pid=$!; sleep 1

for spec in "tcp down 10485760 10.99.0.2" "tcp up 10485760 10.99.0.2" "udp down 10485760 10.99.0.2" \
            "sctp down 5242880 10.99.0.2" "tcp down 5242880 fd00:be0c::2"; do
  set -- $spec; proto=$1; dir=$2; bytes=$3; peer=$4
  fam=""; case $peer in *:*) fam="-6" ;; esac
  bash lib/netlab.sh reset
  # tcpdump on the host side of the veth = exactly where pcap monitors tap. A fresh
  # file each time: tcpdump writes as its own user, and in sticky /tmp root cannot
  # reopen that user's file (fs.protected_regular), so it would read a stale one.
  # -U and a large buffer, so the capture itself drops nothing; the transfer
  # starts once tcpdump says it is listening, not after a guessed delay.
  pcap=/tmp/gt_${proto}_${dir}.pcap
  rm -f "$pcap" /tmp/gt_tcpdump.log
  tcpdump -U -B 16384 -i vbench0 -w "$pcap" -s0 "host $peer" >/tmp/gt_tcpdump.log 2>&1 &
  td_pid=$!
  for _ in $(seq 50); do grep -q "listening on" /tmp/gt_tcpdump.log && break; sleep 0.1; done
  out=$(timeout 40 "$BIN"/benchgen $fam -H "$peer" -t "$proto" -d "$dir" -b "$bytes" 2>&1)
  sleep 1; kill "$td_pid" 2>/dev/null; wait "$td_pid" 2>/dev/null; td_pid=""
  dropped=$(grep -oE "[0-9]+ packets dropped by kernel" /tmp/gt_tcpdump.log)
  read -r eb ep ib ipk < <(bash lib/netlab.sh read)
  # sum captured frame bytes with tcpdump's own reader (-e prints the frame
  # length first; take only that one -- later "length" tokens are L4 payload)
  capframes=$(tcpdump -r "$pcap" -q -n 2>/dev/null | wc -l)
  capsum=$(tcpdump -nr "$pcap" -e 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="length"){s+=$(i+1); break}} END{print s+0}')
  # the frame-layer reference: the L3 counts plus one Ethernet header per packet
  ref=$((eb + ib + 14 * (ep + ipk)))
  printf "[%s %s %s]\n  gen: %s\n  nft wire: egress=%s/%spkt ingress=%s/%spkt\n  pcap(vbench0): frames=%s  frame_len_sum=%s  nft+14/pkt=%s  diff=%s  (%s)\n" \
    "$proto" "$dir" "$peer" "$out" "$eb" "$ep" "$ib" "$ipk" "$capframes" "$capsum" "$ref" "$((capsum - ref))" "$dropped"
done
