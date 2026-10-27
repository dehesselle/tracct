# Sniffnet: detailed results

- scored against: **wire bytes (L3 + Ethernet header per packet)**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=36000000)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/35109004 | -/36000000 | ingress 1.0254 | per-program total from the GUI |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 35109296/- | 35000000/- | egress 0.9969 | per-program total from the GUI |
| s03 | TCP full-duplex up+down | ✅ PASS | ⬜ N/A | -/- | -/- |  | per-program total from the GUI; one combined figure, cannot split direction |
| s04 | UDP bulk up+down | ✅ PASS | ⬜ N/A | -/- | -/- |  | per-program total from the GUI; one combined figure, cannot split direction |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6556264/6556264 | 0/0 | egress 0.0 ingress 0.0 | no Program row |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25921458/- | 26000000/- | egress 1.003 | per-program total from the GUI |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/26685108 | -/27000000 | ingress 1.0118 | per-program total from the GUI |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | -/26261492 | 0/0 | ingress 0.0 | no Program row |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ✅ PASS | 6946882/- | 6900000/- | egress 0.9933 | per-program total from the GUI |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4296168/- | 0/0 | egress 0.0 | no Program row |
| s11 | Short-lived processes | 🟡 PART | ✅ PASS | 10978298/- | 11000000/- | egress 1.002 | listed unattributed (?) by Sniffnet |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS | 4320136/- | 4300000/- | egress 0.9953 | listed unattributed (?) by Sniffnet |
| s13 | io_uring data path | 🟡 PART | ✅ PASS | 26331152/- | 26000000/- | egress 0.9874 | listed unattributed (?) by Sniffnet |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 35109226/- | 35000000/- | egress 0.9969 | per-program total from the GUI |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25932994/- | 26000000/- | egress 1.0026 | per-program total from the GUI |
| s16 | Loopback-only transfer | ❌ FAIL | ⬜ N/A | -/- | 0/0 |  | no Program row |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 26332010/- | 26000000/- | egress 0.9874 | listed unattributed (?) by Sniffnet |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2194666/- | 2200000/- | egress 1.0024 | per-program total from the GUI |
| s19 | Many small TCP connections | 🟡 PART | ✅ PASS | 4136040/- | 4200000/- | egress 1.0155 | listed unattributed (?) by Sniffnet |
| s20 | High-rate parallel burst | 🟡 PART | ✅ PASS | 8236332/- | 8300000.000000001/- | egress 1.0077 | listed unattributed (?) by Sniffnet |
| s21 | io_uring download (recv) | 🟡 PART | ✅ PASS | -/26331722 | -/27000000 | ingress 1.0254 | listed unattributed (?) by Sniffnet |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/35109004 | -/36000000 | ingress 1.0254 | per-program total from the GUI |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS | -/25920816 | -/26000000 | ingress 1.0031 | per-program total from the GUI |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | -/26280336 | -/26000000 | ingress 0.9893 | per-program total from the GUI |
