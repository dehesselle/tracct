# NetHogs: detailed results

- scored against: **wire bytes (L3 + Ethernet header per packet)**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=35109100)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/35109004 | 318680/35109100 | ingress 1.0 |  |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 35109226/- | 35109200/93266 | egress 1.0 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 26685868/26394760 | 26685858/26394806 | egress 1.0 ingress 1.0 |  |
| s04 | UDP bulk up+down | 🟡 PART | ✅ PASS | 25921524/25920816 | 25921500/25920800 | egress 1.0 ingress 1.0 | named 0/0, unknown 25921500/25920800 |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6556264/6556264 | 0/0 | egress 0.0 ingress 0.0 |  |
| s06 | UDP/443 bulk | 🟡 PART | ✅ PASS | 25921458/- | 25921000/0 | egress 1.0 | named 0/0, unknown 25921000/0 |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/26685194 | 197402/26685200 | ingress 1.0 |  |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | -/26261492 | 0/0 | ingress 0.0 |  |
| s09 | Small-packet UDP/53 flood | 🟡 PART | ✅ PASS | 6946882/- | 6947000/0 | egress 1.0 | named 0/0, unknown 6947000/0 |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4296168/- | 0/0 | egress 0.0 |  |
| s11 | Short-lived processes | 🟡 PART | ❌ FAIL | 10978760/- | 5205310/65676 | egress 0.4741 | named 0/0, unknown 5205310/65676 |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS | 4320136/- | 4320000/0 | egress 1.0 | named 0/0, unknown 4320000/0 |
| s13 | io_uring data path | ✅ PASS | ✅ PASS | 26331944/- | 25123400/156296 | egress 0.9541 |  |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 35109226/- | 35109200/87326 | egress 1.0 |  |
| s15 | sendmmsg batched UDP | 🟡 PART | ✅ PASS | 25932994/- | 25933000/0 | egress 1.0 | named 0/0, unknown 25933000/0 |
| s16 | Loopback-only transfer | ✅ PASS | ⬜ N/A | -/- | 27752/0 |  |  |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 26332010/- | 26332000/60266 | egress 1.0 | named 0/0, unknown 26332000/60266 |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2194666/- | 2194670/34922 | egress 1.0 |  |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 4136040/- | 4135550/94596 | egress 0.9999 | named 1516550/34166, unknown 2619000/60430 |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 8235738/- | 1942000/14596 | egress 0.2358 | named 0/0, unknown 1942000/14596 |
| s21 | io_uring download (recv) | ✅ PASS* | ✅ PASS* | -/26331920 | 381908/26331900 | ingress 1.0 |  |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/35109004 | 456950/35109100 | ingress 1.0 |  |
| s23 | recvmmsg batched UDP (recv) | 🟡 PART | ✅ PASS | -/25920816 | 0/25921000 | ingress 1.0 | named 0/0, unknown 0/25921000 |
| s24 | IPv6 UDP download | 🟡 PART | ✅ PASS | -/26280336 | 0/26281000 | ingress 1.0 | named 0/0, unknown 0/26281000 |
