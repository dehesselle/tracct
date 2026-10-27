# bandwhich: detailed results

- scored against: **IP payload bytes (L3 minus the IP header per packet)**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=33896204)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/34308204 | 103336/33812354 | ingress 0.9855 | named 97436/31828870, <UNKNOWN> 5900/1983484 |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 34308288/- | 33329996/37162 | egress 0.9715 | named 29416640/32484, <UNKNOWN> 3913356/4678 |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25859872/25761616 | 25859891/25761645 | egress 1.0 ingress 1.0 | named 21416443/21334795, <UNKNOWN> 4443448/4426850 |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25310272/25309632 | 24931815/24930751 | egress 0.985 ingress 0.985 | named 23417915/23415039, <UNKNOWN> 1513900/1515712 |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6342336/6342336 | 0/0 | egress 0.0 ingress 0.0 |  |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25310240/- | 25021312/0 | egress 0.9886 | named 23865628/0, <UNKNOWN> 1155684/0 |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/25731144 | 49057/25516800 | ingress 0.9917 | named 47357/24659015, <UNKNOWN> 1700/857785 |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | -/25660780 | 0/0 | ingress 0.0 |  |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ✅ PASS | 4718624/- | 4718620/0 | egress 1.0 | named 3385040/0, <UNKNOWN> 1333580/0 |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/- | 0/0 | egress 0.0 |  |
| s11 | Short-lived processes | 🟡 PART | ✅ PASS | 10724896/- | 10717511/64717 | egress 0.9993 | named 0/0, <UNKNOWN> 10717511/64717 |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS | 4218272/- | 4218282/21 | egress 1.0 | named 0/0, <UNKNOWN> 4218282/21 |
| s13 | io_uring data path | 🟡 PART | ✅ PASS* | 25731264/- | 21666465/43515 | egress 0.842 | named 0/0, <UNKNOWN> 21666465/43515 |
| s14 | sendfile() zero-copy upload | ✅ PASS | 🟡 PART* | 34308288/- | 28630540/39011 | egress 0.8345 | named 26457853/36130, <UNKNOWN> 2172687/2881 |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25321504/- | 24925120/187 | egress 0.9843 | named 23339036/0, <UNKNOWN> 1586084/187 |
| s16 | Loopback-only transfer | ✅ PASS | ⬜ N/A | -/- | 27290/449 |  | named 24639/0, <UNKNOWN> 2651/449 |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25731264/- | 25342685/53469 | egress 0.9849 | named 0/0, <UNKNOWN> 25342685/53469 |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2144448/- | 2117603/21856 | egress 0.9875 |  |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 4032000/- | 3978364/46710 | egress 0.9867 | named 134334/1454, <UNKNOWN> 3844030/45256 |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL* | 8045536/- | 4554103/27475 | egress 0.566 | named 0/0, <UNKNOWN> 4554103/27475 |
| s21 | io_uring download (recv) | 🟡 PART* | ✅ PASS | -/25731208 | 165490/25439276 | ingress 0.9887 | named 0/0, <UNKNOWN> 165490/25439276 |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/34308168 | 130824/33396925 | ingress 0.9734 | named 116220/29751620, <UNKNOWN> 14604/3645305 |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS | -/25309632 | 70/25309697 | ingress 1.0 | named 30/20610300, <UNKNOWN> 40/4699397 |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | -/25309632 | 50/25309658 | ingress 1.0 | named 30/20276605, <UNKNOWN> 20/5033053 |
