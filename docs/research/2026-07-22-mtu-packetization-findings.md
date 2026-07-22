# #59 MTU-aware packetization — measurement findings (throughput lever 4c)

**Date:** 2026-07-22
**Status:** investigation complete; feeds the mechanism design (deferred pending these findings).
**Method:** real code path (`yip_transport::Transport::encode`) via
`crates/yip-bench/examples/mtu_symbol_sweep.rs`; source reading of the
send-path layering; the 4a/4b profiling in `crates/yip-bench/RESULTS.md`.

## The send-path layering (confirmed from source)

```
inner IP packet (≤ TUN MTU)
  → Session::seal_into          +16  (ChaCha20-Poly1305 tag)          [per inner packet]
  → Transport::encode           split into K = ceil((inner+16)/symbol_size) SOURCE symbols
                                 + R repair symbols (adaptive)          [per symbol]
      each symbol is EXACTLY symbol_size on the wire (last zero-padded)
  → Codec::frame                +23  (yip-wire HEADER_LEN 15 + TAG_LEN 8) [per symbol]
  → obf envelope                +11  (yip-obf MIN_ENVELOPE) + random pad   [per symbol]
  → UDP/IP                      +28 v4 / +48 v6                            [per datagram]
```

Two cost tiers matter:
- **per-inner-packet:** AEAD seal/open (now the dominant per-packet cost per
  RESULTS.md), TUN write (~20%). One each per inner packet, independent of
  `symbol_size`.
- **per-symbol / per-datagram:** UDP `sendmsg` (~23%), yip-wire SipHash
  header-auth (~9%, #58), FEC encode (~1.3µs), framing. One each per symbol.

`yipd` does **not** currently set the TUN MTU (no `SIOCSIFMTU` in `yip-device`,
nothing in the netns scripts) — the interface takes the kernel default (1500).
The QUIC `MtuDiscoveryConfig` (1200→1452) is only the QUIC-*mimicry* transport,
a separate path; the real data plane has no PMTUD.

## The measurement (`mtu_symbol_sweep`, real `Transport::encode`)

Symbols emitted per inner packet, and lower-bound outer wire bytes
(symbols × (symbol_size + 23 + 11 + 28)), fresh Transport (default-class
repair ratio, clean-link baseline):

| inner | symbol_size | source | total | repair | outer_bytes | overhead |
|------:|------------:|-------:|------:|-------:|------------:|---------:|
|  1184 |        1200 |      1 |     2 |      1 |        2524 |     113% |
|  1400 |        1200 |      2 |     3 |      1 |        3786 |     170% |
|  1400 |        1500 |      1 |     2 |      1 |        3124 |     123% |
|  1448 |        1200 |      2 |     3 |      1 |        3786 |     161% |
|  1448 |        1452 |      2 |     3 |      1 |        4542 |     214% |
|  1448 |        1500 |      1 |     2 |      1 |        3124 |     116% |
|  8972 |        1200 |      8 |     9 |      1 |       11358 |      27% |
|  8972 |        1500 |      6 |     7 |      1 |       10934 |      22% |
|  8972 |        9000 |      1 |     2 |      1 |       18124 |     102% |
|   576 |        9000 |      1 |     2 |      1 |       18124 |    3047% |

## Findings

### 1. Every symbol is zero-padded to full `symbol_size` on the wire — so a blind `symbol_size` increase is a bandwidth REGRESSION for small packets.

`fec.rs` (“last zero-padded”), the reassembler rejects `data.len() != symbol_size`
(fec.rs:206), and `wire_glue::symbol_to_frame` frames the full `sym.data`
untrimmed. A 576-byte packet at `symbol_size` 9000 emits two 9000-byte symbols
(3047% overhead). `symbol_size` therefore cannot simply be cranked up: it is a
per-datagram floor that every packet, however small, pays in full.

### 2. Two independent MTU levers with very different reach.

- **Lever 1 — raise `symbol_size` to ~1500.** Collapses a standard 1400–1500 B
  inner packet from 2 source symbols to 1 (1448 B: 3→2 datagrams, −33%).
  Reduces only the **per-symbol** costs (sendmsg, SipHash, FEC, framing) — NOT
  AEAD or TUN-write. Internet-safe (path MTU ~1500). Caveat: `symbol_size` must
  be ≥ inner+16, so 1452 does NOT fit a 1448 B packet — need 1500. And it pays
  Finding 1's padding penalty on sub-`symbol_size` traffic.
- **Lever 2 — raise the inner TUN MTU to jumbo (~9000) with a matching
  `symbol_size`.** Fewer, bigger inner packets → reduces **all** costs including
  AEAD + TUN-write (the two largest): moving 8972 B as one jumbo inner packet
  (2 datagrams, 1 seal, 1 TUN write) vs ~6× 1448 B packets (~12 datagrams,
  6 seals, 6 TUN writes) is ~6× fewer of everything. But it needs the **whole
  path** to carry jumbo, and only helps when traffic is actually jumbo-sized
  (Finding 1 punishes small packets hard at `symbol_size` 9000).

The issue’s framing — raising MTU “reduces every per-packet cost proportionally”
— is fully true only for **Lever 2**. Lever 1’s ceiling is the per-symbol share
(~sendmsg 23% + SipHash 9% ≈ 32%), and only for packets that currently split.

### 3. The FEC repair floor (+1 per object, min-1) doubles single-symbol objects — but it is loss-adaptive.

Every case above shows `repair = 1`: `repair_count = max(1, ceil(K × ratio))`,
so a 1-source-symbol object is 1 source + 1 repair = **100% packet overhead**,
while an 8-source jumbo object amortizes the same +1 over 8 (12.5%). This is a
large packet-count multiplier for MTU-sized single-packet flows — BUT
`repair_count` returns **0** once the adaptive ratio decays to zero on a clean
link (ARQ-eligible classes), so steady-state clean traffic would not pay it. The
sweep shows the fresh/default-ratio baseline, not steady state. This is an
**FEC-rate** lever (which classes FEC-protect single-symbol objects on clean
links), adjacent to but distinct from #59’s MTU scope — flag for separate
investigation; it may be a bigger single-core win than the MTU change.

### 4. The structural fix that removes Finding 1’s tradeoff: variable-length last symbol (wire-trim).

Zero-pad only for the GF math on encode/decode; carry the true byte length and
trim the partial final source symbol on the wire (`object_size` is already
transmitted, so the receiver can reconstruct). This decouples FEC granularity
from wire bytes: `symbol_size` can rise to collapse source-symbol counts
**without** padding small packets. It is more invasive (touches the RS codec
wire representation of the last symbol) but removes the Lever-1 tradeoff
entirely and is the enabler for a safe, always-on MTU increase.

## Recommendation (feeds the mechanism design)

Ranked, given the padding constraint:

1. **Wire-trim the last symbol (Finding 4) + static configurable inner MTU with
   a derived `symbol_size`.** The wire-trim makes Lever 1 safe on the internet
   (no small-packet penalty); the configurable MTU ships Lever 2 for
   controlled/jumbo paths (the biggest win, which the issue itself calls
   “largest on controlled/LAN paths”). `yipd` gains a `SIOCSIFMTU` on the TUN
   device and the derivation `path_MTU → symbol_size → inner MTU`, with the safe
   default = today’s behavior.
2. **If wire-trim is out of scope for v1:** static configurable MTU only,
   `symbol_size` capped at 1500, operator opt-in, documented as bulk-optimized
   (accepts Finding 1’s small-packet padding). Ships Lever 1+2 without a codec
   change but is a bandwidth regression on mixed traffic if raised blindly.
3. **Active PLPMTUD (RFC 8899)** remains a later automation layer over either.

Separately: open an FEC-rate investigation for Finding 3 (suppress the +1 repair
on clean single-symbol objects) — plausibly a larger single-core win than the
MTU change, and independent of it.

## Finding 3 resolved (2026-07-22): the +1 repair is PERMANENT for the common traffic class.

Followed the pivot into the FEC-rate lever. The adaptive controller
(`control.rs`) sets `min_ratio = 0.0` for ARQ classes but
`min_ratio = initial_repair_ratio` for non-ARQ classes — so non-ARQ classes
**floor above zero and can never decay to repair = 0**. The class taxonomy
(`lib.rs::params`):

| Class | DSCP | `initial_repair_ratio` | `arq` | Clean-link repair (K=1) |
|-------|------|-----------------------:|:-----:|------------------------:|
| Realtime | EF/CS5-7 | 0.15 | false | **1 (permanent)** |
| Bulk | CS1/AF1x | 0.05 | **true** | 0 (decays) |
| Default | 0 (**~all traffic**) | 0.10 | false | **1 (permanent)** |

The feedback loop is live (`dataplane.rs:440-443` drives `observe_loss` per
class from each peer `LossReport`; `FEEDBACK_INTERVAL_MS = 30`, so clean-link
reports fire and decay works). So Bulk genuinely reaches 0 on clean links, but
**Default and Realtime are stuck at their floor forever** —
`repair_count(1) = max(1, ceil(1 × 0.10)) = 1`. Since Default is the class for
essentially all traffic that doesn't set DSCP, the common case permanently emits
1 source + 1 repair = **2 datagrams per single-symbol packet, on a pristine
link**. The bench's “2.00 symbols/packet” is this steady state, not an artifact.

This is a large, internet-universal, single-core packet-count tax that is
independent of MTU and the wire-padding constraint. It is the recommended focus
(user pivot, 2026-07-22). The design is a **policy tradeoff** — proactive
protection (instant recovery, permanent cost) vs efficiency (zero clean-link
cost, ARQ/slower recovery on loss onset) — for the non-ARQ classes that floor
above zero. Options: (A) let Default decay to 0 on a proven-clean link and
re-arm on the first observed loss (keep Realtime’s floor); (B) make Default
ARQ-eligible so it decays like Bulk (biggest reach, changes recovery to
reactive); (C) suppress repair only for K=1 objects on clean links. The MTU work
(Findings 1–2, 4) is parked behind this.

## Finding 3 — the cheap experiment (2026-07-22): the floor is load-bearing, NOT waste.

Ran the experiment (set non-ARQ `min_ratio` to 0 so Default decays to 0 on a
clean link; `crates/yip-bench/examples/fec_rate_experiment.rs` for the mechanism,
netns for recovery). Results:

**Clean-link win (measured, deterministic).** Baseline: Default holds **2.000
symbols/packet** permanently, even after 1000 clean LossReports (the 0.10 floor
never decays). Experiment: decays to **1.000** after ~200 clean reports (~6 s at
the 30 ms feedback interval). So on a *sustained-clean* link the change is a real
**2× reduction in send-path datagrams** for Default traffic.

**Lossy low-rate REGRESSION (measured, netns 10% netem, low-rate ping).**
Baseline delivers **10/10** (RESULTS.md: “RS FEC recovers the injected loss”).
Experiment: **7/10, 9/10, 8/10** across three runs — ~20% delivered loss, i.e.
the netem loss passing through *unrecovered*. Sparse traffic cannot sustain the
feedback loop, so the ratio decays to ~0 between packets and each loss is
unprotected (Default is non-ARQ — no retransmit to catch it).

**High-rate is orthogonal.** `run-arq-integrity.sh` (20000×1400 B, 5% loss)
still passes at 99.3% — but that path recovers via **ARQ** (132 retransmits,
Bulk class), which the change never touched. It does not validate the Default
proactive-FEC path.

**The floor is a deliberate, tested invariant.** The change breaks
`control::tests::non_arq_class_keeps_floor`, which explicitly asserts non-ARQ
classes keep their floor. The permanent +1 repair exists precisely to protect
the **low-rate, latency-sensitive** traffic (SSH, DNS, VoIP, gaming) that
non-ARQ classes serve — exactly the traffic that cannot keep the controller
armed and cannot wait for ARQ. It is buying real loss protection, not wasting
bandwidth.

### Conclusion

The apparent FEC-rate inefficiency is **load-bearing**. Decaying Default to 0
(Option A) trades a clean-link throughput win for a lossy-link recovery
regression on exactly the low-rate traffic the class exists to protect — a bad
trade for a VPN. Option C (suppress K=1 repair on “clean” links) has the same
flaw: “clean” is unknowable for sparse traffic, which is when it matters. Option
B (Default→ARQ) likely regresses low-rate recovery differently (gap-detection
latency). **Recommendation: do not pursue the FEC-rate change; the current
tuning is right.**

Net for #59: the MTU levers are real but constrained (wire-padding; jumbo only
on controlled paths — Findings 1, 2, 4), and the FEC-rate lever is a mirage. The
defensible remaining work is **static configurable MTU + last-symbol wire-trim**
(Finding 4) for operators on controlled/jumbo paths, or closing #59 with these
findings until a controlled-path deployment makes the MTU work worth it.


**9b knock-on:** wire-trim + a raised `symbol_size` ceiling gives the PQ
handshake more headroom on controlled paths, but the handshake must still fit
the safe floor (ML-KEM-512 under `OBF_MTU_BUDGET`), so 9b’s sizing decision is
unchanged by this.
