#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Eric Lesiuta
#
# SPDX-License-Identifier: GPL-3.0-or-later

# netlab.sh — isolated, reproducible network lab for the tracct benchmark.
#
# Builds a dedicated "remote peer" inside its own network namespace connected to
# the host over a veth pair, so benchmark traffic crosses a real interface
# (vbench0) with exact wire accounting via dedicated nftables counters: no
# external network, no CDN variance, fully reproducible.
#
#   host (default netns)                     peer netns (BENCH_NS)
#     vbench0  10.99.0.1/24  <============>  vbench1 10.99.0.2/24
#              fd00:be0c::1/64                       fd00:be0c::2/64
#
# Loopback scenarios use `lo` in the host netns directly (peer not involved).
#
# Ground truth is captured at TWO layers so the comparison is fair to tools that
# measure at different points in the stack:
#   * application bytes  — counted by the traffic generators themselves (exact)
#   * wire bytes (L3+L4): dedicated nftables counters where each packet arrives,
#     the peer's veth ingress and the host's prerouting from vbench0, so a packet
#     is counted as it crossed the pair
# pcap tools additionally see the 14-byte Ethernet header per packet; the packet
# count is recorded so that delta is computable.
set -euo pipefail

BENCH_NS="benchpeer"
VETH_HOST="vbench0"       # host side of the pair (kept <= 15 chars)
VETH_PEER="vbench1"       # peer side (moved into the namespace)
HOST_V4="10.99.0.1"
PEER_V4="10.99.0.2"
V4_CIDR="24"
HOST_V6="fd00:be0c::1"
PEER_V6="fd00:be0c::2"
V6_CIDR="64"
NFT_TABLE="benchgt"       # nftables table (netdev, one per end) holding the ground-truth counters

# --- lifecycle ---------------------------------------------------------------

netlab_up() {
    netlab_down >/dev/null 2>&1 || true
    ip netns add "$BENCH_NS"
    ip link add "$VETH_HOST" type veth peer name "$VETH_PEER"
    ip link set "$VETH_PEER" netns "$BENCH_NS"

    # host side
    ip addr add "$HOST_V4/$V4_CIDR" dev "$VETH_HOST"
    ip -6 addr add "$HOST_V6/$V6_CIDR" dev "$VETH_HOST" nodad
    ip link set "$VETH_HOST" up

    # peer side (inside the namespace)
    ip -n "$BENCH_NS" addr add "$PEER_V4/$V4_CIDR" dev "$VETH_PEER"
    ip -n "$BENCH_NS" -6 addr add "$PEER_V6/$V6_CIDR" dev "$VETH_PEER" nodad
    ip -n "$BENCH_NS" link set "$VETH_PEER" up
    ip -n "$BENCH_NS" link set lo up

    # Disable offloads on BOTH ends so the generator's byte counts match what
    # crosses the wire (GSO/GRO would otherwise coalesce segments and skew the
    # per-packet accounting that pcap tools rely on). Checksum offloads
    # (rx/tx/tx-checksum-sctp) are disabled too: with them ON, attaching a
    # libpcap capture to the veth (bandwhich captures every interface) leaves
    # SCTP's mandatory CRC32c uncomputed on the transmit path, so the peer drops
    # every packet and the SCTP transfer stalls -- unmeasurable for the capturing
    # tool. Software checksums are correct on the wire and don't change byte counts.
    for f in tso gso gro lro rx-gro-list rx tx tx-checksum-sctp; do
        ethtool -K "$VETH_HOST" "$f" off 2>/dev/null || true
        ip netns exec "$BENCH_NS" ethtool -K "$VETH_PEER" "$f" off 2>/dev/null || true
    done

    # Ground-truth counters sit on the ingress hook of the veth end a packet
    # arrives at, so each counts packets as they crossed the pair: TCP and SCTP
    # hand the stack GSO superpackets even with the offloads above off, and split
    # them only at the device, so a hook on the sending side (inet output) would
    # see one packet, with one set of headers, per superpacket. The pair carries
    # ONLY benchmark traffic; ARP and other non-IP frames are not counted.
    #   vbench1 ingress (peer netns)       = host egress / upload   = gt_in_c
    #   prerouting from vbench0 (host netns) = host ingress / download = gt_out_c
    ip netns exec "$BENCH_NS" nft -f - <<EOF
table netdev ${NFT_TABLE} {
	counter gt_in_c { }
	chain gt_in {
		type filter hook ingress device "${VETH_PEER}" priority -500; policy accept;
		meta protocol { ip, ip6 } counter name gt_in_c
	}
}
table inet ${NFT_TABLE} {
	chain gt_in {
		type filter hook input priority -300; policy accept;
		# s10 sends IP proto 253, which the peer has no handler for; without this
		# it would reply ICMP proto-unreachable, polluting gt_out_c (ingress) on an
		# egress-only test. Dropped after the ingress hook counted it.
		meta l4proto 253 drop
	}
}
EOF
    # The host end counts at prerouting rather than on a netdev ingress hook: an
    # ingress hook on vbench0 blinds bandwhich's capture of the packets leaving it.
    # With GRO off on vbench0, prerouting sees the packets as they crossed the pair.
    nft -f - <<EOF
table inet ${NFT_TABLE} {
	counter gt_out_c { }
	chain gt_out {
		type filter hook prerouting priority -500; policy accept;
		iifname "${VETH_HOST}" counter name gt_out_c
	}
}
EOF
    # settle (v6 DAD/ND); a couple of pings prime neighbour tables
    ping -c1 -W1 "$PEER_V4" >/dev/null 2>&1 || true
    ping -c1 -W1 -6 "$PEER_V6" >/dev/null 2>&1 || true
}

netlab_down() {
    ip netns del "$BENCH_NS" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
    nft delete table inet "$NFT_TABLE" 2>/dev/null || true
}

# --- ground truth ------------------------------------------------------------
# Reset both ends' counters to zero (call immediately before a trial).
netlab_gt_reset() {
    ip netns exec "$BENCH_NS" nft reset counters table netdev "$NFT_TABLE" >/dev/null
    nft reset counters table inet "$NFT_TABLE" >/dev/null
}

# Emit "egress_bytes egress_pkts ingress_bytes ingress_pkts" (host perspective).
# egress  = host -> peer (arrives at vbench1 = gt_in_c).
# ingress = peer -> host (arrives at vbench0 = gt_out_c).
netlab_gt_read() {
    { ip netns exec "$BENCH_NS" nft -j list counters table netdev "$NFT_TABLE"
      nft -j list counters table inet "$NFT_TABLE"; } \
        | python3 -c '
import json,sys
c={}
for line in sys.stdin:
    for o in json.loads(line)["nftables"]:
        co=o.get("counter")
        if co: c[co["name"]]=[co["bytes"],co["packets"]]
gi=c.get("gt_in_c",[0,0]); go=c.get("gt_out_c",[0,0])
print(gi[0],gi[1],go[0],go[1])
'
}

# run a command inside the peer namespace (used to host the controlled server)
netlab_peer() { ip netns exec "$BENCH_NS" "$@"; }

case "${1:-}" in
    up) netlab_up ;;
    down) netlab_down ;;
    reset) netlab_gt_reset ;;
    read) netlab_gt_read ;;
    peer) shift; netlab_peer "$@" ;;
    *) echo "usage: $0 {up|down|reset|read|peer <cmd...>}" >&2; exit 2 ;;
esac
