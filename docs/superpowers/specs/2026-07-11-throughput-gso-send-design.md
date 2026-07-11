# Throughput — Send-side UDP GSO on the poll path (lever 4a) — Design Spec

**Status:** draft (under review)
**Sub-project:** #4 (Throughput & Scalability). Lever 4, stage **a** of a measure-gated
campaign: **4a send-side GSO** → 4b recv GRO → 4c MTU raise. On main after batched I/O
(#54, `e030a39`).

---

## 1. Goal

Cut the per-datagram kernel UDP-stack traversal on the poll send path by coalescing
same-destination, same-length datagrams into one `UDP_SEGMENT` ("GSO") send, so the kernel
UDP stack is traversed **once per batch instead of once per packet** — while preserving FEC
per-symbol loss-independence. Target: raise the single-core throughput ceiling above the
measured ~200–350 Mbit/s, without a cipher/handshake/wire change.

## 2. Why (grounded in real-hardware measurement, 2026-07-11)

Profiling on two target-profile VPSes (1-core AMD EPYC, 967 MB, virtio, AES+AVX2;
`45.61.149.155` ↔ `144.172.98.216`, 24 ms apart) established:

- **yip is CPU-bound at ~200 Mbit/s per core.** In the isolated 4-box test (yip gateways
  own their cores, traffic generated off-box ny→lv through the tunnel), the ingress yipd
  **pegs at 98% CPU while delivering ~180–200 Mbit/s UDP.** Direct box-to-box over the
  tunnel (iperf sharing the core) delivered ~266 Mbit/s with yipd at ~55–70% (core split
  with iperf). True single-core ceiling ≈ 300–400 Mbit/s — ~20–30× under the earlier
  7 Gbit projection.
- **The CPU goes to the kernel UDP *send* path.** With no `perf` on the box, kernel-stack
  sampling of yipd under load showed `__sys_sendmmsg` as the single largest slice
  (~40% of samples), plus `irqentry_exit_to_user_mode` / softirq. Userspace crypto/FEC
  (the parts levers 1–2 optimized, and the basis of the 7 Gbit projection) **did not
  appear.** The dominant cost is ~40 µs/packet of kernel syscall + interrupt work, not
  yip's arithmetic (<1 µs/packet).

Batched I/O (#54) cut the syscall *count* (one `sendmmsg` per burst) but each datagram still
traverses the full kernel UDP stack (route lookup, checksum, netfilter, copy) individually.
GSO attacks exactly that: `UDP_SEGMENT` lets one `sendmsg` carry N same-size datagrams that
the kernel/NIC segments low in the stack, so the expensive per-packet stack work amortizes
across the batch.

**Bandwidth is free and the box is 1-core**, so single-core CPU is the ceiling and this is
the highest-value remaining lever. CLAUDE.md-conformant: no cipher, handshake, or wire-format
change — only how the same wire datagrams reach the socket.

## 3. The unknown, and why Task 0 is a spike

`UDP_SEGMENT` benefit depends on the NIC/driver: with hardware GSO offload the win is large;
on a **virtio** guest without offload the kernel software-segments, which still saves the
per-packet *syscall* and part of the stack traversal but less than hardware. Whether it pays
off **on these specific virtio boxes** is unproven. So the first task is a throwaway
measurement spike, not production code — mirroring the fast-AEAD spec's spike-first approach.
If the spike shows GSO gives little on virtio, we report that and reconsider the campaign
rather than building three stages on a false premise.

## 4. Architecture

### 4.1 What already exists (do not rebuild)
- The dataplane tags every egress datagram with its FEC object id:
  `EgressDatagram.fate = sym.object_id` (`bin/yipd/src/dataplane.rs:282`; retransmits set
  `fate: oid`). Non-FEC egress (control replies, tick) uses `fate: 0`.
- The **uring** backend already implements correct fate-safe GSO
  (`crates/yip-io/src/uring.rs`): `can_coalesce_gso_tagged` coalesces only datagrams that
  share one `dst`, share one payload length, and carry **distinct** `fate` values; and it
  GSO-sends via a `UDP_SEGMENT` cmsg. This is the reference for the grouping rule.

### 4.2 The gap
The **poll** send path (`crates/yip-io/src/poll.rs`, `flush_tx` → `send_mmsg`) sends one
independent UDP packet per datagram — it ignores `fate` and does no GSO. Poll is the default
data-plane driver (also under QUIC-less operation).

### 4.3 The change
1. **Extract the fate-safe grouping rule into a shared `yip-io` helper** (new
   `crates/yip-io/src/gso.rs`) so poll and uring share one definition instead of duplicating
   the correctness-critical rule. The helper answers: "given a slice of `EgressDatagram`,
   partition it into GSO-safe runs" where a run is a maximal set of datagrams that share one
   `dst`, share one payload length, and have pairwise-distinct `fate`. uring is refactored to
   call the shared helper (behavior-preserving), so both drivers enforce the identical rule.
2. **Teach the poll send path to GSO.** `flush_tx` groups its `tx` batch into fate-safe GSO
   runs; each run of ≥2 datagrams is sent as one `sendmsg` with a `UDP_SEGMENT` cmsg carrying
   the run's common segment size (per-datagram `dst` via `msg_name`); runs of 1 (and any
   trailing odd datagram) fall back to the existing plain `send_mmsg`. `unsafe` for the cmsg
   construction lives in `yip-io` (already exempt from `forbid(unsafe_code)`), every block
   `// SAFETY:`-commented.

### 4.4 Where the batching comes from (subtle — read this)
All symbols of **one** FEC object share one `fate`, so the distinct-`fate` rule means GSO
**never** coalesces symbols *within* an object — it coalesces one symbol each from
**different** objects (all typically the same fixed symbol length). So GSO engages only when a
`flush_tx` burst spans multiple FEC objects — i.e. when `drain_tun` accumulated several TUN
packets' egress into one batch, which is exactly the high-throughput case this lever targets.
A lone TUN packet's symbols (one object) send plain, with no GSO — correct and latency-neutral
under light load. The partial last symbol of an object (shorter) simply forms its own
length-keyed run.

### 4.5 Segment-size rule
`UDP_SEGMENT` requires every segment in a send to be the same size except the last. The
grouping already keys on equal payload length, so all datagrams in a run are equal-size and
the constraint holds trivially; the common length is the segment size passed in the cmsg.

## 5. Invariants (load-bearing — FEC correctness)

1. **≤1 symbol of any FEC object per GSO skb.** The distinct-`fate` rule guarantees no GSO
   send coalesces two datagrams of the same FEC object. So even in the pessimistic case where
   a whole super-skb is dropped/delayed as a unit, each object loses **at most one symbol per
   skb** — identical to losing one independent wire packet, which the FEC is designed to
   recover. This is the entire reason `fate` exists.
2. **Byte-identical wire datagrams.** GSO changes only how datagrams reach the socket, not
   their bytes, size, destination, or count on the wire. A receiver sees the same UDP packets
   as with plain `send_mmsg`.
3. **Latency-neutral / opportunistic.** GSO only coalesces datagrams already queued in one
   `flush_tx` burst; nothing waits to fill a batch. A single queued datagram is one plain
   send.
4. **`fate: 0` never coalesces with itself.** Control/tick datagrams all carry `fate: 0`;
   the distinct-`fate` rule forbids putting two `fate: 0` datagrams in one skb, so they each
   send individually (correct — they are not FEC-protected and must not be grouped under the
   FEC-safety rule). This is a safe, if conservative, default.
5. **Correctness-preserving fallback.** If a `UDP_SEGMENT` send returns EIO/EINVAL
   (unsupported), fall back to plain `send_mmsg` for that batch and latch a process-wide
   "GSO unavailable" flag so subsequent sends skip GSO (no per-send retry cost). Partial
   sends loop the remainder, as today.
6. **`unsafe` contained in `yip-io`.** yipd and other crates stay `#![forbid(unsafe_code)]`.
7. **Scope: poll send path only.** `uring.rs` GSO is refactored to the shared helper but
   otherwise unchanged; recv path unchanged (GRO is 4b); the QUIC `run_quic` loop is out of
   scope.

## 6. Testing

- **Task 0 spike report:** measured CPU-per-Gbit (or delivered Gbit at fixed CPU) for plain
  `sendmmsg` vs `sendmsg`+`UDP_SEGMENT`, box→box on Y1→Y2. **Decision gate recorded:** if
  GSO < ~1.3× on these virtio boxes, stop and reassess before building §4.3.
- **Unit (yip-io, the shared helper):** two same-`fate` datagrams never land in one run; a
  run is split when `dst` differs, when length differs, or when a `fate` repeats; an
  all-distinct-`fate`, same-`dst`, same-length batch forms one run; singletons/`fate: 0`
  fall back. uring's existing GSO tests still pass against the refactored shared helper.
- **netns loss (the critical end-to-end gate):** `run-netns-tunnel.sh`,
  `run-netns-tunnel-loss.sh` (10% netem — **FEC must still recover with GSO sends**), and
  `run-arq-integrity.sh` green.
- **No-regression:** full `cargo test --workspace`; the `YIP_USE_URING=1` driver still starts
  and passes traffic.
- **Benchmark gate (headline):** re-run the real-hardware tests on Y1/Y2 — the isolated
  4-box test (ingress yipd CPU + delivered UDP at saturation) and the direct box-to-box test
  — recording **before (#54 baseline) vs after (4a)** in `crates/yip-bench/RESULTS.md`.
  Expect the ingress core to deliver more Mbit/s at the same 98%-pegged CPU if GSO amortizes
  the send-stack cost.

## 7. Scope & files

- **Create:** `crates/yip-io/src/gso.rs` (shared fate-safe grouping helper + its unit tests).
- **Modify:** `crates/yip-io/src/poll.rs` (fate-safe `UDP_SEGMENT` send in `flush_tx`, plain
  fallback), `crates/yip-io/src/uring.rs` (call the shared helper; behavior-preserving),
  `crates/yip-io/src/lib.rs` (module wiring), `crates/yip-bench/RESULTS.md`.
- **Untouched:** the QUIC path, `Dispatch`/`EgressDatagram` types (already carry `fate`),
  crypto/FEC pipeline, `yip-wire`, `wire_glue`, the recv path.

**Out of scope (later campaign stages / levers):** recv-side `UDP_GRO` (4b); tunnel MTU raise
(4c); AF_XDP zero-copy; TUN-side batching.
