# Per-process network & bandwidth monitors on Linux

<!-- --8<-- [start:overview] -->
24 scenarios × 5 trials on Ubuntu 26.04.1 LTS (kernel 7.0.0-30-generic) on a Hetzner vServer with 4 vCPUs (AMD EPYC-Genoa Processor) and 8 GB, run 2026-10-27. Detection = *seen and attributed to the right process*; Bandwidth = *bytes within ±10% (PASS) / ±25% (PARTIAL)* of the reference for the tool's layer. Method, harness, versions, and how to reproduce: [the `bench/` directory](..).

## Results summary

Each cell counts scenarios (of 24), unweighted; the scenarios are not equally important and the totals are not an overall ranking. N/A marks a missing capability or reference: OpenSnitch does no bandwidth accounting; the BCC utilities and the bpftrace script used here hook TCP only; Sniffnet reports one combined per-program total, so full-duplex scenarios it cannot split by direction are N/A; the loopback scenario has no wire measurement, so tools counting at a packet layer are N/A on its bandwidth.

| Tool | Detection: PASS / PART / FAIL / N/A | Bandwidth: PASS / PART / FAIL / N/A | Trial disagreement |
|---|---|---|---|
| tracct | **24** / 0 / 0 / 0 | **24** / 0 / 0 / 0 | 0 |
| Sysdig | **24** / 0 / 0 / 0 | **19** / 0 / 5 / 0 | 0 |
| Little Snitch | **19** / 3 / 2 / 0 | **16** / 0 / 8 / 0 | 2 |
| OpenSnitch | **19** / 0 / 5 / 0 | **0** / 0 / 0 / 24 | 3 |
| bandwhich | **15** / 6 / 3 / 0 | **18** / 1 / 4 / 1 | 4 |
| BCC tcplife/tcpconnect | **14** / 0 / 0 / 10 | **14** / 0 / 0 / 10 | 0 |
| bpftrace script | **14** / 0 / 0 / 10 | **14** / 0 / 0 / 10 | 0 |
| BCC tcptop | **14** / 0 / 0 / 10 | **13** / 0 / 1 / 10 | 0 |
| Sniffnet | **13** / 7 / 4 / 0 | **18** / 0 / 3 / 3 | 0 |
| NetHogs | **11** / 10 / 3 / 0 | **18** / 0 / 5 / 1 | 1 |

## Run health

Recorded by the harness during this run. A tool that was never measured has no results in the tables above.

- **OpenSnitch**: ran, with notes
    - control passed on the second attempt (first attempt missed; probe warm-up)

## Versions

Read from each installed tool during the run. Pinned entries are built or downloaded at a fixed version by the harness; distro packages are whatever the Ubuntu archive shipped on the run date and are recorded, not pinned.

| Tool | Version observed | Source |
|---|---|---|
| tracct | 0.1.1.dev2+g9553864.d20261027 | source tree |
| Sysdig | 0.40.0 | distro package (recorded, not pinned) |
| Little Snitch | 1.1.1 | current release (recorded, not pinned) |
| OpenSnitch | 1.8.0-1 | pinned (release .deb) |
| bandwhich | 0.23.1 | pinned (release binary) |
| BCC tcplife/tcpconnect | 0.37.0 | pinned (built from source tag) |
| bpftrace script | 0.25.0 | distro package (recorded, not pinned) |
| BCC tcptop | 0.37.0 | pinned (built from source tag) |
| Sniffnet | 1.5.1-1 | pinned (release .deb) |
| NetHogs | 0.9.0 | pinned (built from source tag) |

## Observed footprint

Each tool's whole process tree, sampled at 1 Hz across its session under its own capture scope; not a controlled performance comparison. CPU is % of one core (can exceed 100% across cores). PSS (proportional set size) charges each shared page once, split across its sharers.

| Tool | CPU mean % | CPU 95th pct % | PSS mean MB | PSS peak MB |
|---|---|---|---|---|
| tracct | 3.8 | 5.9 | 19.5 | 20.5 |
| Sysdig | 1.3 | 5.0 | 27.0 | 28.4 |
| Little Snitch | 0.3 | 1.0 | 42.7 | 42.9 |
| OpenSnitch | 8.2 | 64.4 | 68.3 | 71.1 |
| bandwhich | 1.8 | 4.0 | 3.1 | 3.5 |
| BCC tcplife/tcpconnect | 0.0 | 0.0 | 284.0 | 284.0 |
| bpftrace script | 0.1 | 1.0 | 175.1 | 175.5 |
| BCC tcptop | 0.1 | 1.0 | 177.4 | 177.4 |
| Sniffnet | 2.4 | 10.0 | 69.7 | 80.1 |
| NetHogs | 0.4 | 1.0 | 7.6 | 8.2 |

<!-- --8<-- [end:overview] -->

## Per-scenario notes

- **s05 ICMP echo flood w/ payload**: ICMP is neither TCP nor UDP; monitors that only parse TCP/UDP miss it entirely.
- **s08 SCTP transfer**: SCTP is neither TCP nor UDP; TCP/UDP-only parsers miss it.
- **s10 Raw IP socket (proto 253) egress**: raw sockets with a custom IP protocol carry no TCP/UDP header; TCP/UDP-only attribution misses them.
- **s11 Short-lived processes**: /proc-scan attribution loses processes that exit before the next scan; their traffic lands in an unknown bucket.
- **s12 AF_PACKET raw-frame injection**: AF_PACKET hands complete L2 frames to the driver, bypassing the INET socket path, so monitors hooking the INET socket functions record nothing; the writes are ordinary syscalls, so syscall tracing still sees them; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to attribute them to a process.
- **s16 Loopback-only transfer**: traffic never leaves lo, which many monitors skip by default.

## Reference bytes per scenario

App bytes are the generators' own counts. Wire bytes include per-run variance (handshakes, retransmits); this table shows one session's capture, and each tool page records its own run's values.

| # | Scenario | app bytes s/r | wire bytes s/r |
|---|---|---|---|
| s01 | TCP bulk download (control) | 24/33554432 | 248852/34779356 |
| s02 | TCP bulk upload | 33554456/0 | 34779484/107596 |
| s03 | TCP full-duplex up+down | 25165872/25165824 | 26288464/26162420 |
| s04 | UDP bulk up+down | 25166448/25165824 | 25669832/25669152 |
| s05 | ICMP echo flood w/ payload | 6342336/6468176 | 6468176/6468176 |
| s06 | UDP/443 bulk | 25166424/0 | 25669780/0 |
| s07 | IPv6 TCP transfer | 24/25165824 | 114944/26437856 |
| s08 | SCTP transfer | 24/25165824 | 424472/26014140 |
| s09 | Small-packet UDP/53 flood | 4194328/0 | 6029364/0 |
| s10 | Raw IP socket (proto 253) egress | 4194304/0 | 4254224/0 |
| s11 | Short-lived processes | 10486240/0 | 10874112/115808 |
| s12 | AF_PACKET raw-frame injection | 4320136/0 | 4278192/0 |
| s13 | io_uring data path | 25165848/0 | 26084404/113088 |
| s14 | sendfile() zero-copy upload | 33554456/0 | 34779480/80920 |
| s15 | sendmmsg batched UDP | 25177624/0 | 25681204/0 |
| s16 | Loopback-only transfer | 24/25165824 | 0/0 |
| s17 | In-container (docker) egress | 25165848/0 | 26084644/72340 |
| s18 | Low-and-slow drip upload | 2097176/0 | 2174044/35576 |
| s19 | Many small TCP connections | 3933600/0 | 4093200/77492 |
| s20 | High-rate parallel burst | 7865040/0 | 8157624/77460 |
| s21 | io_uring download (recv) | 24/25165824 | 110948/26080148 |
| s22 | splice() zero-copy download | 24/33554432 | 318532/34779300 |
| s23 | recvmmsg batched UDP (recv) | 24/25165824 | 52/25669152 |
| s24 | IPv6 UDP download | 24/25165824 | 72/26028672 |
