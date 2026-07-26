# Testing & benchmarking yip

How to run yip's test suites and measure its performance. Two layers:

- **Tests** prove correctness — unit tests, root-gated network-namespace
  integration tests (across both I/O drivers), and an nDPI undetectability
  oracle.
- **Benchmarks** measure performance — hot-path micro-benchmarks and
  `tc netem` comparisons against kernel WireGuard, OpenVPN, and n2n.

Most integration tests and all benchmarks need **root** (they create network
namespaces and TUN/TAP devices) and a **release** `yipd` (a debug build of the
FEC path is ~75× slower and misrepresents results).

---

## Unit tests

Fast, no root needed:

```sh
cargo test --workspace                 # everything
cargo test -p yip-transport            # a single crate (FEC, classifier, ARQ …)
cargo test -p yip-obf                  # the obfuscation envelope
cargo test -p yip-ca                   # CA cert/root-set round-trips
cargo test -p yip-rendezvous-bin       # rendezvous server smoke test
```

Quality gates CI also runs:

```sh
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

---

## Network-namespace integration tests

These live in `bin/yipd/tests/tunnel_netns.rs`. Each one shells out to a script
in `bin/yipd/tests/` that builds a topology of network namespaces + veth pairs,
runs real `yipd` daemons, and asserts a real ping (or a specific path) works.
They are **root-gated**: without root they print `SKIP <name>: needs root` and
pass vacuously (CI fails the job if it sees an unexpected SKIP).

| Test | Proves |
|---|---|
| `ping_across_yipd_tunnel` | Baseline two-peer direct tunnel. |
| `ping_across_yipd_tunnel_under_loss` | Tunnel survives 10 % injected loss (FEC/ARQ). |
| `l2_tap_ping_or_arp_across_tunnel` | L2 (TAP) mode works. |
| `triangle_full_mesh_ping` | Three-peer full mesh. |
| `arq_recovers_bulk_loss` | FEC + ARQ recover 5 % bulk loss (needs **release** yipd). |
| `relay_path_ping` | Connectivity via the **blind relay** (rendezvous). |
| `hole_punch_ping` | Connectivity via **direct hole-punch** (relay counter stays 0). |
| `discovery_dynamic_ping` | A discovers + pings B purely via gossip, with no static knowledge of B. |
| `admission_rejects_uncertified` | An uncertified peer's handshake is rejected. |
| `discovery_survives_root_outage` | Connectivity survives the seed root dying. |
| `obfuscated_ping` | Direct tunnel still works with `obf_psk` set. |
| `obf_psk_mismatch_no_connection` | Mismatched `obf_psk` ⇒ ping **must fail** (load-bearing inverse). |
| `relay_path_ping_obfuscated` | Relay path works with obfuscation on. |
| `hole_punch_ping_obfuscated` | Hole-punch works with obfuscation on. |
| `discovery_dynamic_ping_obfuscated` | Mesh discovery works with obfuscation on. |

### Running them

The simplest way — build the helpers, then run under `sudo` via cargo:

```sh
cargo build --release -p yipd
cargo build -p yip-rendezvous-bin -p yip-ca
sudo -E $(command -v cargo) test -p yipd --test tunnel_netns -- --test-threads=1
```

To run **both I/O drivers** the way CI does, run the compiled test binary
directly and toggle `YIP_USE_URING`:

```sh
BIN=$(cargo test -p yipd --test tunnel_netns --no-run --message-format=json \
      | jq -r 'select(.executable != null) | .executable' | grep tunnel_netns | tail -1)

# default (epoll) driver:
sudo -E "$BIN" ping_across_yipd_tunnel --exact --nocapture --test-threads=1
# io_uring driver:
sudo -E env YIP_USE_URING=1 "$BIN" ping_across_yipd_tunnel --exact --nocapture --test-threads=1
```

`--exact` matters so `ping_across_yipd_tunnel` doesn't also match
`ping_across_yipd_tunnel_under_loss`.

---

## The nDPI undetectability oracle

The concrete proof that obfuscated yip is unrecognizable to deep packet
inspection. It captures a real obfuscated exchange and asserts the nDPI
classifier can't identify it.

**Build nDPI** (the test adversary) once:

```sh
cd refrences/nDPI && ./autogen.sh && ./configure && make   # -> example/ndpiReader
```

**Run the oracle:**

```sh
cargo build --release -p yipd
sudo bash bin/yipd/tests/run-ndpi-oracle.sh \
    "$(pwd)/target/release/yipd" \
    "$(pwd)/refrences/nDPI/example/ndpiReader"
```

Or via the Rust harness (root-gated; skips if `ndpiReader` isn't built):

```sh
sudo -E "$BIN" dpi_undetectability --exact --nocapture --test-threads=1
```

It captures traffic on a **neutral port** (34567 — *not* 51820, which nDPI
port-matches to WireGuard regardless of payload) and enforces:

- **(a)** no flow classified as WireGuard / OpenVPN / Tor / any VPN-category
  protocol — the flow must be `Unknown`;
- **(b)** no `NDPI_OBFUSCATED_TRAFFIC` risk flag;
- **(c)** `NDPI_SUSPICIOUS_ENTROPY` is *reported but not gated* — high-entropy
  payloads inherently trip it (WireGuard does too) for the plain `obf_psk`
  wire format exercised by this oracle. Suppressing it means dressing the
  flow as a real protocol: yip ships `transport=quic`, `transport=tls`, and
  an Xray-REALITY relay-dial transport for exactly this (see
  [`docs/configuration.md`](configuration.md#transport-mode-optional)); those
  transports have their own dedicated classification tests
  (`quic_classified_as_quic`, the REALITY netns suite) rather than this oracle.

CI runs this as the `dpi-undetectability` job against a pinned nDPI commit.

---

## Benchmarks

### Hot-path micro-benchmarks

Criterion benchmarks of the per-packet crypto/wire/FEC costs (no root):

```sh
cargo bench -p yip-bench
```

| Bench | Typical median | Measures |
|---|---|---|
| `aead_seal_1300` | ~0.63 µs | ChaCha20-Poly1305 seal (`ring` backend), 1300-byte payload |
| `aead_open_1300` | ~1.28 µs | seal **+** open together (open alone ≈ 0.65 µs) |
| `wire_frame_1300` | ~0.5 µs | header + auth tag + keyed header-protection |
| `wire_deframe_1300` | ~0.55 µs | the inverse |
| `transport_encode_1300` | ~0.32 µs | Reed–Solomon FEC encode over GF(256), Default class R=1 (P+Q XOR scheme, the common steady-state path); ARQ-eligible/Bulk classes and R=2 use the general Cauchy scheme, ~1.3 µs |

Numbers above are the current ones as of the throughput-optimization passes
(RS-codec swap, P+Q fast path, `ring` AEAD); see
[`crates/yip-bench/RESULTS.md`](../crates/yip-bench/RESULTS.md) for the full
before/after history and methodology. `transport_encode_1300` in particular
went through several rounds: ~26 µs (original RaptorQ) → ~1.3 µs (RS,
general Cauchy scheme, #50) → ~0.32 µs (P+Q XOR fast path for the common
R=1 case, #51).

### MAC-candidate spike (#58)

A Criterion micro-bench comparing keyed-MAC candidates for the `yip-wire`
coverage-auth tag over the real covered region (header‖symbol, 8-byte tag):

```sh
cargo bench -p yip-bench --bench mac_candidates
```

SipHash-1-3 is ~45 % cheaper than today's SipHash-2-4 at packet size; keyed
BLAKE3 is ~2.5× **slower** at a 1.4 KB symbol (its SIMD advantage needs
KB–MB inputs). Measured on the EPYC target box and a dev box. The saving is
real but third-tier behind TUN-write and AEAD, and only helps in the
CPU-bound regime below — so #58 stays parked. Full write-up:
[`crates/yip-bench/mac-candidates-58.md`](../crates/yip-bench/mac-candidates-58.md).

### CPU-bound-regime spike (#4 go/no-go)

Determines whether the yip receiver can become CPU-bound or is always
RTT/window-bound. Pins the receiving `yipd` to one core (models the 1-core
target), sweeps netem RTT, and records throughput + the pinned core's
utilization (needs root):

```sh
sudo bash crates/yip-bench/tests/run-cpu-regime.sh target/release/yipd
```

A CPU-bound regime **exists**: under a UDP blast the single core saturates and
caps at ~1.2 Gbps at every RTT; TCP is CPU-bound at low RTT and window-bound at
high RTT. So the "CPU wins don't move throughput" observation was specific to
the 24 ms single-flow WAN path — the #4 CPU work pays off for short-RTT /
aggregate-parallel traffic. Full write-up:
[`crates/yip-bench/cpu-bound-regime.md`](../crates/yip-bench/cpu-bound-regime.md).

### yip vs WireGuard/OpenVPN/n2n under loss (`tc netem`)

The comparison tests in `crates/yip-bench/tests/netem_bench.rs` set up tunnels
in network namespaces, inject loss/latency with `tc netem`, and measure
effective loss, RTT, and throughput. Root + release yipd required. Contenders
that aren't installed (wireguard-tools, openvpn, n2n, iperf3, UDPspeeder) are
skipped cleanly.

```sh
cargo build --release -p yipd
BIN=$(cargo test -p yip-bench --test netem_bench --no-run --message-format=json \
      | jq -r 'select(.executable!=null)|.executable' | tail -1)

sudo -E "$BIN" yip_tunnel_under_netem_loss   --nocapture --test-threads=1  # yip-only loss sweep
sudo -E "$BIN" comparison_under_netem_loss   --nocapture --test-threads=1  # yip vs WireGuard; writes RESULTS.md
sudo -E "$BIN" iperf_throughput_comparison   --nocapture --test-threads=1  # yip vs WG/OpenVPN/n2n TCP throughput
sudo -E "$BIN" scp_throughput_comparison     --nocapture --test-threads=1  # scp (TCP) throughput under loss
sudo -E "$BIN" udp_loss_recovery_comparison  --nocapture --test-threads=1  # delivered-loss: bare vs UDPspeeder vs yip
```

`comparison_under_netem_loss` writes a Markdown table to
`crates/yip-bench/RESULTS.md`.

**What to expect** (the headline yip result): at 10 % injected loss yip's FEC
delivers ~1–2 % effective loss where WireGuard passes through ~13–17 %, for a
~0.2 ms RTT premium; and under loss yip's TCP throughput holds (~7× WireGuard at
10 %) because FEC keeps TCP from collapsing. On a clean link yip trades a little
raw throughput (userspace + FEC overhead) for that loss resilience.

### Driver A/B RTT

Compare the three I/O-driver modes head-to-head:

```sh
sudo bash crates/yip-bench/tests/run-driver-ab-rtt.sh "$(pwd)/target/release/yipd"
# poll ~0.37 ms · io_uring ~0.41 ms · io_uring+busypoll ~0.30 ms
```

See [`crates/yip-bench/README.md`](../crates/yip-bench/README.md) for the full
harness details and recorded results.
