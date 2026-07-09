# yip-bench Results

Generated: 2026-06-30 19:51:19 UTC

## yip vs kernel WireGuard — netem loss sweep
ping -c 100 -i 0.05 -W 1 across each tunnel; netem: loss X% delay 5ms (symmetric)

| injected% | yip_loss% | wg_loss%  | yip_rtt_ms | wg_rtt_ms |
|-----------|-----------|-----------|------------|-----------|
| 0%        | 0%         | 0%         | 10.541      | 10.322     |
| 1%        | 0%         | 2%         | 10.567      | 10.332     |
| 3%        | 0%         | 4%         | 10.544      | 10.360     |
| 5%        | 0%         | 8%         | 10.550      | 10.388     |
| 10%        | 1%         | 17%         | 10.544      | 10.337     |

## QUIC-vs-raw benchmark (3c.1 Task 7)

Generated: 2026-07-09 14:20:16 UTC

`transport=quic` (real QUIC/TLS1.3 handshake + DATAGRAM-frame pump,
wrapping the inner yip Noise-IK session — see bin/yipd/src/quic.rs) vs
yip's default raw-UDP path. Same netns/veth harness as the driver A/B
RTT test and the iperf3 throughput matrix; `ping -c 100 -i 0.02` for
RTT, `iperf3 -t 8` for TCP throughput. This is NOT the obf_psk
cover-traffic premium (3a/3b, a separate cost) — this isolates the QUIC
mimicry premium alone.

| transport | rtt_avg_ms | tcp_Mbit/s |
|-----------|------------|------------|
| raw       | 0.394      | 355        |
| quic      | 0.438      | 266        |

Honest framing: `transport=quic` is an **opt-in premium** for DPI
resistance (see `bin/yipd/tests/run-quic-mimicry-oracle.sh` / the
`quic_classified_as_quic` test for the payoff — a real nDPI
classification flip to QUIC with no Susp Entropy risk). Raw UDP remains
yip's low-latency default; the double-encryption/two-layer-handshake
cost above is what QUIC mimicry spends to buy that payoff (the 3c.1
Task 1 spike estimated ~1.68x CPU/packet for the QUIC path; the table
above is the measured RTT/throughput consequence of that cost).
