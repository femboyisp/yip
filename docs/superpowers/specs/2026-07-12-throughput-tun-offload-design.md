# Throughput — TUN vnet-header GSO/GRO offload (lever 4b) — Design Spec

**Status:** draft (under review)
**Sub-project:** #4 (Throughput & Scalability). Lever **4b** of the single-core campaign
(4a send GSO ✓ merged #55 → **4b TUN offload** → 4c MTU). On main after 4a (`ec3ae21`).

---

## 1. Goal

Cut the per-packet **TUN device** I/O cost — the dominant single-core cost after 4a — by
batching yipd's reads/writes of its own TUN via a `virtio_net_hdr` (GSO/GRO offload):

- **RX (receiver, the big win ~20%):** coalesce consecutive decrypted same-flow inner packets
  into one GSO super-frame and `write()` it once; the kernel segments on delivery.
- **TX (sender, ~7%):** let the kernel GRO the outgoing flow so one `read()` returns a
  coalesced super-frame; yipd splits it back into MTU packets for its existing per-packet
  encrypt/FEC/send.

Target: reduce the combined ~27% TUN cost, raising the single-core throughput ceiling — with
**no wire-format, FEC, or AEAD change**.

## 2. Why (post-4a re-profile, 2026-07-12)

`perf` on the target boxes (1-core AMD EPYC, virtio, kernel 6.12; Y1 `45.61.149.155` ↔ Y2
`144.172.98.216`) under an 800 Mbit/s in-tunnel flood, after 4a merged:

- **Receiver:** `tun_chr_write_iter`/`tun_get_user` (the per-packet TUN `write()` re-injecting
  each decrypted packet through `netif_receive_skb` → `ip_local_deliver`) = **~20%** of yipd
  CPU — the single largest cost. `recvmmsg` = **0.03%** (recv is already batched and free —
  which is why the originally-planned recv-GRO was dropped: measurement showed ~0 benefit).
  A surprising `yip_wire` SipHash header-auth cost (~9%) and cheap AEAD (4.4%) / FEC (1.6%)
  round out the profile.
- **Sender:** `sendmsg`/`udp_send_skb` ~23% (already GSO-reduced from ~40% by 4a), TUN
  `read()` (`tun_chr_read_iter`) ~7%.

So the biggest untapped single-core lever is the TUN boundary (~27% RX+TX combined). Bulk
TCP-in-tunnel — the dominant real VPN workload — is exactly what GSO/GRO coalesces.

## 3. The unknown, and why Task 0 is a spike (with a hard gate)

Two real unknowns gate the whole milestone:

1. **Does vnet-hdr GSO/GRO fire and pay off on the target kernel?** `TUNSETOFFLOAD` support
   and whether the kernel actually GROs TUN reads / accepts GSO TUN writes at a CPU saving is
   kernel- and virtio-dependent. Unproven on these boxes.
2. **The benchmark must use bulk TCP, not UDP.** GSO/GRO coalesces **same-flow** traffic; the
   synthetic iperf-**UDP** flood used for 4a will *not* coalesce (independent datagrams). 4b
   must be measured with **iperf-TCP-in-tunnel** (or `iperf -P` bulk streams), which is also
   the realistic workload.

**Task 0 (throwaway spike):** on Y1/Y2, open a TUN with `IFF_VNET_HDR` + `TUNSETOFFLOAD`, run
bulk TCP-in-tunnel, and measure (a) whether TUN reads return super-frames > MTU (GRO firing),
and (b) whether a coalesced GSO `write()` reduces receiver TUN CPU vs per-packet writes.
**Hard gate: if vnet-hdr GSO/GRO does not meaningfully reduce TUN CPU on the target kernel
with bulk TCP, STOP and report** — do not build §4. (Same spike-first discipline as 4a's
`UDP_SEGMENT` gate and 4b's re-profile.)

## 4. Architecture

**The coalescing is entirely local to each box's yipd↔kernel-TUN boundary.** Each wire
datagram remains one encrypted MTU packet; the wire format, FEC symbol sizing, AEAD, replay,
and the whole UDP send/recv path are **unchanged**. Only how yipd frames its own TUN I/O
changes.

### 4.1 Device setup (`yip-device`) — gated on the poll driver
**The TUN fd's framing must match whichever driver consumes it.** `IFF_VNET_HDR` prepends a
header to *every* read/write on that fd, so it can only be enabled when the vnet-hdr-aware poll
path owns the fd. The `uring` driver's TUN handling is out of scope here and stays plain — so
vnet-hdr is **opt-in at open time, gated on the poll driver being selected**: `yipd` passes a
`want_vnet_hdr` intent to `yip-device` (true only when the default `PollDriver` will run; false
under `YIP_USE_URING=1`). When true, open with `IFF_VNET_HDR` added to `IFF_TUN | IFF_NO_PI`,
then `ioctl(TUNSETOFFLOAD, TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6)`,
falling back through a smaller feature set and finally to **no-vnet-hdr** on `EINVAL`. The
device exposes whether vnet-hdr ended up active and its header length (10 or 12 bytes). When
vnet-hdr is off (uring selected, unsupported, or fallback), the poll path uses today's plain
per-packet TUN I/O unchanged — so the fd framing and its consumer always agree.

### 4.2 The `virtio_net_hdr`
A fixed struct prefixed to every TUN read/write when vnet-hdr is active: `flags`,
`gso_type` (NONE / TCPV4 / TCPV6 / UDP_L4), `hdr_len`, `gso_size`, `csum_start`,
`csum_offset` (plus `num_buffers` for the 12-byte mrg-rxbuf form). yipd reads it on RX-split
and writes it on TX-coalesce.

### 4.3 TX read GRO — the easy half (~7%)
`drain_tun` reads into a buffer whose first bytes are the `virtio_net_hdr`. When
`gso_type != NONE`, the read returned a kernel-GRO'd super-frame of N segments; yipd **splits**
it into N MTU-sized inner packets using `gso_size` (re-deriving each segment's IP/TCP headers
and per-segment checksums, or relying on the offloaded csum fields), then feeds each to the
existing `on_tun` → encrypt/FEC/send. `gso_type == NONE` is a lone packet (today's path). No
userspace coalescing — the kernel already did it.

### 4.4 RX write GSO — the hard half (~20%)
`drain_udp` decrypts inner packets one at a time (unchanged). Instead of `send_to_tun` per
packet, it feeds each into a **userspace GRO coalescer** that:
- groups by flow (src/dst IP, protocol, TCP/UDP ports);
- for TCP: appends a segment when it is the flow's next expected sequence, equal-window, no
  disqualifying flags — building one payload buffer + a `virtio_net_hdr` (`gso_type=TCPV4/6`,
  `gso_size`=segment MSS); flushes the accumulated super-frame on a flow change, a
  non-contiguous segment, a `PSH`/`FIN`/`RST`/`URG`, a differing option set, the segment cap,
  or end-of-burst;
- for UDP / non-coalescible / IP-fragmented / unknown: flushes immediately as a singleton
  (`gso_type=NONE`).
Each flushed super-frame is one `write()` with its `virtio_net_hdr`; the kernel GSO-segments
it on delivery. This is the intricate, from-scratch part (no local reference clone) — its
correctness is the milestone's main risk and gets the most tests.

### 4.5 Buffers
`run_poll` owns the reusable TUN read buffer (grown to 64 KiB + header for super-frames), the
coalescer's per-flow accumulation buffer(s), and the vnet-hdr scratch — all allocated once.

## 5. Invariants

1. **Byte-exact packet preservation.** Splitting a super-frame yields exactly the MTU packets
   the kernel would have delivered un-GRO'd; coalescing then GSO-segmenting yields exactly the
   inner packets that were decrypted. A packet's bytes reaching the peer's applications are
   identical to the per-packet path. (Verified by round-trip tests and netns end-to-end.)
2. **No wire / FEC / AEAD change.** Each wire datagram stays one encrypted MTU packet. The
   coalescer/splitter never spans the wire — a decrypted packet is coalesced only with other
   *already-decrypted* packets from the same RX burst; a read super-frame is split *before*
   encryption. FEC symbol sizing, replay, nonce, and `yip-wire` framing are untouched.
3. **Correctness-preserving fallback.** No `TUNSETOFFLOAD` (or `IFF_VNET_HDR`) → plain
   per-packet TUN I/O, exactly today's behavior. A malformed/oversized super-frame on read, or
   any coalescer uncertainty, falls back to singleton handling rather than corrupting packets.
4. **Latency-neutral.** RX coalescing flushes at end-of-burst (no cross-burst buffering / added
   delay); a lone or PSH-marked packet writes immediately. TX split is immediate.
5. **`unsafe` contained.** New `unsafe` (the `virtio_net_hdr` byte framing, the TUN
   `ioctl`s) lives in `yip-io` / `yip-device` only; `yipd` stays `#![forbid(unsafe_code)]`.
   No `as` numeric casts except libc-ABI/discriminants; no bare `#[allow]`.
6. **Scope: poll path only.** The `uring` driver's TUN I/O and the QUIC loop are out of scope
   this milestone (the poll driver is the default and where the profile was taken).

## 6. Testing

- **Task 0 spike report:** measured TUN read super-frame sizes (GRO firing?) and receiver TUN
  CPU per-packet vs coalesced, bulk-TCP-in-tunnel on Y1/Y2. **Decision gate recorded.**
- **Split unit tests:** a synthetic GRO super-frame (known `gso_size`, N TCP segments) splits
  into exactly N correct MTU packets with valid per-segment IP/TCP headers + checksums;
  `gso_type==NONE` passes through unchanged; a truncated/over-long super-frame is rejected to
  the fallback path.
- **Coalescer unit tests:** N contiguous same-flow TCP segments coalesce into one super-frame
  with the right `gso_size`/`hdr_len`/csum fields; a flow change, a sequence gap, a `PSH`/`FIN`,
  a UDP packet, and an IP fragment each force a flush; a lone packet is a singleton; the
  round-trip (coalesce → split) reproduces the inputs byte-for-byte.
- **netns end-to-end (both correctness gates):** `ping_across_yipd_tunnel`,
  `ping_across_yipd_tunnel_under_loss` (10% — FEC still recovers), `arq_recovers_bulk_loss`
  green with offload active; plus a **bulk-TCP** netns transfer (the case offload targets) —
  data arrives intact.
- **No-regression:** full `cargo test --workspace`; the `YIP_USE_URING=1` driver (unchanged
  TUN path) still passes; offload-unsupported fallback path exercised (force vnet-hdr off).
- **Benchmark gate (headline):** on Y1/Y2, bulk **TCP**-in-tunnel throughput + receiver TUN
  CPU, **before (main `ec3ae21`) vs after (4b)**, recorded in `crates/yip-bench/RESULTS.md`.
  Use a separate device/port so the user's pre-existing Y1↔Y2 tunnel stays undisturbed.

## 7. Scope & files

- **Modify:** `crates/yip-device/src/lib.rs` (accept a `want_vnet_hdr` intent; when set, open
  with `IFF_VNET_HDR` + `TUNSETOFFLOAD` with feature-fallback; expose the resulting vnet-hdr
  state + header length), and `bin/yipd` (pass `want_vnet_hdr = true` only when the `PollDriver`
  will run — `false` under `YIP_USE_URING=1` — and thread the device's vnet-hdr state into
  `run_poll`). `yipd` stays `#![forbid(unsafe_code)]`.
- **Create:** `crates/yip-io/src/tun_offload.rs` (the `virtio_net_hdr` framing, the TX
  super-frame splitter, the RX userspace-GRO coalescer + their unit tests).
- **Modify:** `crates/yip-io/src/poll.rs` (`drain_tun` split on read; `drain_udp` feed the
  coalescer instead of per-packet `send_to_tun`; reusable buffers in `run_poll`; plain
  fallback when vnet-hdr is off), `crates/yip-io/src/lib.rs` (module wiring),
  `crates/yip-bench/RESULTS.md`.
- **Untouched:** the wire format, FEC/AEAD/replay pipeline, `yip-wire`, the UDP send/recv path
  (incl. 4a's GSO), the QUIC path, the `uring` driver's TUN handling.

**Out of scope (later):** `uring`-path TUN offload; the ~9% `yip-wire` SipHash header-auth cost
(a separate investigation); AF_XDP; 4c MTU raise (next lever).
