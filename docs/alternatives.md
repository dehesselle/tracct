# Alternatives

This document compares picosnitch with other tools that measure traffic per process or per
flow on Linux, from the angle this fork cares about: keeping a history of who exchanged how
much with whom.

| Tool | History | Who | With whom |
| --- | --- | --- | --- |
| vnstat | yes | – | – |
| nethogs, bandwhich | live only | process | partly |
| Netdata eBPF | yes | application group, service | not historically |
| ntopng, pmacct, conntrack + ulogd2 | yes | – | per flow, wire bytes, including forwarded traffic |
| systemd `IPAccounting=` | counters only | unit | – |
| picosnitch | yes | process, parent, unit | address, domain, port; forwarded flows per peer |

The flow-based tools see forwarded traffic but attribute none of it to a process. picosnitch
records forwarded flows from connection tracking too, apart from its per-process socket
bytes (see [DESIGN.md](DESIGN.md#what-is-and-isnt-counted)).

How accurately the per-process monitors detect and count traffic, across many
hard-to-attribute cases, is measured by the benchmark in `bench/`:
[findings](../bench/reports/findings.md),
[detection scorecard](../bench/reports/scorecard-detection.md),
[bandwidth scorecard](../bench/reports/scorecard-bandwidth.md), and
[method](../bench/README.md). Those runs measured upstream's PyPI release, not this fork.
