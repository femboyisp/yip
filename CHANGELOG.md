# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- REALITY-style Trojan relay front (anti-DPI milestone 3c.3): `yip-rendezvous`
  gains an opt-in TCP/TLS listener (`--listen-tcp`/`--tls-cert`/`--tls-key`/
  `--decoy`) that terminates **real-cert** TLS and routes a fresh, obfuscated
  `Register` (now carrying a monotonic `counter` for replay rejection) to the
  relay tunnel, while transparently reverse-proxying every other connection —
  active probes, scanners, plain browsers — to a real decoy site, so the relay
  is indistinguishable from an ordinary HTTPS server to anyone without
  `obf_psk`. `--obf-psk` is now **required** with `--listen-tcp` (it is the
  tunnel discriminator). `tokio` is added to `yip-rendezvous` — the control/
  relay tier only; the `yipd` data plane stays 100% async-free. **New build
  dependency: `cmake` + a BoringSSL compile, now also required to build
  `yip-rendezvous`** (already required for `yipd` since 3c.2). The `yipd`
  client that dials this front (`rendezvous = "tls://host:443"`) is milestone
  3c.4, not shipped here.
- TLS-over-TCP mimicry transport (`transport=tls`, anti-DPI milestone 3c.2):
  carries the **unchanged** inner yip protocol (Noise-IK, FEC, AEAD) inside a
  real TLS 1.3 connection over TCP/443 with a **browser-parrot ClientHello**
  (BoringSSL via the `boring` crate, GREASE-enabled — a Chrome-shaped JA3/JA4,
  not a Rust-TLS fingerprint), so yip survives UDP-blocked networks and
  classifies as ordinary browser HTTPS. Datagrams are framed length-prefixed
  over the TLS byte-stream; the client/server role is a deterministic
  static-key tiebreak; teardown reconnects with backoff. Opt-in **last-resort**
  path (TCP head-of-line blocking, no FEC benefit — trades yip's latency
  identity for reachability); **mutually exclusive with `obf_psk`**; the
  default raw-UDP path and the `quic` costume are unchanged. New config keys
  `transport=tls` and `tls_sni` (default `www.apple.com`). **New build
  dependency: `cmake` + a BoringSSL compile** (required whenever `yipd` is
  built).
- L2 TAP tunnel mode in `yipd`: config now supports `device_kind=tap` for
  Ethernet (L2) tunnel interfaces; `device_kind=tun` remains the default for
  IP (L3) mode.
- io_uring Phase B driver (`UringDriver`): a single-ring (UDP+TUN) io_uring data
  loop, available **opt-in** via `YIP_USE_URING=1` (the **default is the epoll
  `PollDriver`**). netns CI runs all tunnel tests under **both** drivers. The
  opt-in path was hardened to match `PollDriver`'s robustness contract: `EINTR`
  on the blocking ring wait is retried (a signal no longer tears down the tunnel),
  and non-GSO send-completion errors drop on transient buffer pressure but
  propagate genuinely fatal errors (TUN writes always drop) instead of being
  swallowed forever. (Latency tuning — where io_uring goes from regressing to
  *beating* epoll via adaptive busy-poll — is in the "io_uring driver RTT work"
  entry under Changed; GSO throughput batching is the "io_uring GSO batching"
  entry under Changed.)
- `docs/configuration.md`: a single reference for everything `yipd` reads at
  startup — config-file keys (`device_kind`, keys, endpoints…), the
  `YIP_USE_URING` / `YIP_URING_BUSYPOLL` env knobs, and CLI flags — linked from
  the README.
- Single-threaded data loop (Phase A): replaced the two-thread `Arc<Mutex>`
  data plane with a mutex-free `DataPlane` driven by an `epoll` `PollDriver`
  (io_uring driver to follow). Removes per-packet lock/handoff overhead — tunnel
  RTT ~0.51 ms -> ~0.36 ms; throughput holds. No wire change.
- Adaptive loss-feedback loop + reactive ARQ. The receiver detects post-FEC
  residual loss as gaps in the object counter and reports it (with NACKs) in an
  authenticated `Control` packet; the sender attributes loss per class and drives
  the repair controller. ARQ-eligible (`Bulk`) flows on a clean link now decay
  their repair ratio to **zero**, activating the FEC-encode bypass — clean-link
  single-stream TCP rises from ~273–285 to ~457 Mbit/s. On loss the controller
  re-arms FEC instantly and NACKed `Bulk` objects are retransmitted with fresh
  RaptorQ repair symbols (reusing the original object id); `Realtime`/`Default`
  flows keep a proactive floor and are not retransmitted. New `yip-transport`
  modules: `feedback` (`LossReport`), `lossdetect` (`LossDetector`), `retxbuf`
  (`RetxBuffer`), plus `Transport::repair_object`.

### Changed
- **Relicensed from MPL-2.0 to AGPL-3.0-or-later**, copyright FEMBOY CYBER NETWORKS
  LLC. The AGPL network-use clause (§13) means anyone running a modified `yip` as a
  network service must offer their users the corresponding source — privacy
  infrastructure stays open. (Closes #53.)
- README rewritten with the project identity ("🦊 what does the fox say? — nothing a
  DPI firewall can hear") and a "Silicon Slopes Paradox" section on Utah SB 73 and
  the EFF's coverage; corrected the lingering "RaptorQ" references to Reed–Solomon
  across README, `CLAUDE.md`, and `yip-transport`/`yip-wire` doc comments (the codec
  was swapped in #50). Repo description + topics added.
- TUN vnet-header GSO/GRO offload on the **poll** hot path (throughput lever 4b):
  the TUN device is opened with `IFF_VNET_HDR` + `TUNSETOFFLOAD` (gated on the poll
  driver — `uring` and QUIC keep a plain TUN), so yipd batches its own TUN I/O.
  On **read**, a kernel-GRO'd super-frame is software-segmented back into MTU
  packets (`split_gro`); on **write**, consecutive same-flow TCP segments are
  merged by a userspace-GRO **coalescer** into one GSO super-frame the kernel
  re-segments — collapsing many per-packet `tun_chr_write_iter` traversals into
  one. The coalescing is **entirely local to the yipd↔kernel-TUN boundary: no
  wire-format, FEC, AEAD, or replay change** (each wire datagram stays one
  encrypted MTU packet); non-coalescible traffic (UDP, pings, flow changes) passes
  through as singletons at zero cost, and an unsupported kernel falls back to plain
  per-packet TUN I/O. A new `crates/yip-io/src/tun_offload.rs` holds the
  `virtio_net_hdr` codec, the coalescer, the splitter, and the partial-checksum
  completion for `F_NEEDS_CSUM` reads (the kernel offloads L4 checksums on large
  reads — completing them before encrypt is load-bearing, or the far end drops the
  packets). `unsafe` stays confined to `yip-io`/`yip-device`. **Real-hardware A/B
  (two 1-core AMD EPYC virtio VPSes, bulk TCP): receiver `tun_chr_write_iter`
  19.0% → 14.6%** — the mechanism cuts the targeted TUN-write cost, though
  end-to-end throughput on that 24 ms-RTT / same-core-`iperf` path is RTT/window-
  capped rather than TUN-CPU-bound, so the full win lands on low-RTT / high-
  throughput single flows. netns ping / 10%-loss / ARQ pass under both drivers;
  TCP-in-tunnel data verified intact. See `crates/yip-bench/RESULTS.md`.
- Send-side UDP GSO on the **poll** hot path (throughput lever 4a): `run_poll`'s
  `flush_tx` now partitions its egress batch into fate-safe runs (same
  destination, same length, pairwise-distinct FEC `fate`) and sends each run as
  one `sendmsg` with a `UDP_SEGMENT` control message, instead of one `sendmmsg`
  datagram-per-packet. The fate-safe grouping rule is factored into a shared
  `yip-io::gso` module (`can_coalesce` / `partition_fate_safe` /
  `max_gso_run_len`); the `UringDriver` GSO path now delegates to it, so both
  drivers enforce **at most one datagram per FEC object per skb** from one
  definition — a dropped GSO super-skb costs each object at most one symbol, so
  FEC per-symbol loss-independence is preserved. Opportunistic and
  latency-neutral (coalesces only what a burst already queued; a lone datagram
  still sends plain). Falls back to plain `send_mmsg` for singletons and, after
  latching a per-`run_poll` "GSO unavailable" flag, whenever the kernel reports
  `UDP_SEGMENT` unsupported (`EIO`/`EINVAL`). Wire-identical; no cipher/handshake/
  wire-format change. **Real-hardware A/B (two 1-core AMD EPYC virtio VPSes):
  +25–31 % end-to-end UDP throughput at equal single-core CPU** (a decision-gate
  spike measured a 2.6× send-path CPU reduction; the end-to-end gain is smaller
  because recv/TUN/conntrack/IRQ costs do not benefit from send-side GSO). netns
  10 %-loss + ARQ recovery verified under both drivers. `unsafe` stays confined to
  `yip-io`. See `crates/yip-bench/RESULTS.md` ("4a send-side GSO").
- Batched UDP I/O on the poll hot path (throughput lever): `run_poll` drains the
  UDP socket with one `recvmmsg` per burst and sends each TUN burst's egress with
  one addressed `sendmmsg` (per-datagram `dst`/`src`), collapsing ~2–3 `sendto`s
  per packet into one syscall per burst. Opportunistic and latency-neutral (batches
  only what epoll already queued). (PR #54.)
- Fast data-plane AEAD (throughput lever): `yip-crypto::Session` seal/open moved
  from snow's RustCrypto ChaCha20-Poly1305 to **`ring`** ChaCha20-Poly1305, keyed by
  snow's secret `Split()` transport keys and Noise's nonce so the output is
  **byte-identical to the previous wire** — **~2.1 µs → 0.6 µs** per packet. Same
  256-bit ChaCha20-Poly1305 cipher; snow is now handshake-only. A durable
  byte-identity KAT guards the equivalence. (PR #52.)
- **FEC codec swapped from RaptorQ to a small-K systematic Reed–Solomon codec**
  (throughput lever): a hand-rolled GF(256) Cauchy RS-v1 codec replaces the
  `raptorq` crate — **encode ~26 µs → ~1.33 µs**. RaptorQ's K′=10 minimum-block
  padding taxed every small packet with ~10 symbols of work, the price of a
  ratelessness yip never uses (`observe_loss` clamps the repair ratio ≤ 1.0). New
  `yip-transport` modules `gf256` + `rs` (exhaustive MDS proof); `raptorq` dropped
  from the dependency tree. Wire `payload_id` now carries a codec tag; `yip-wire`
  framing unchanged. (PR #50.)
- io_uring graceful fallback (issue #25): `run_uring` now falls back to the
  `PollDriver` on any `UringDriver` failure (init or runtime) instead of killing
  the tunnel. Found on a clean Debian 13 (kernel 6.12) box: io_uring's multishot
  UDP recv is rejected there with `EINVAL` and was fatal ~4/6 runs; it works on
  6.18+. Opting into io_uring (`YIP_USE_URING=1`) is now safe on any kernel — it
  degrades to epoll where io_uring is buggy/unsupported. (The re-default question
  is settled: **epoll `PollDriver` stays the default** — io_uring's busy-poll RTT
  win needs bare metal + a dedicated core + a recent kernel, so it remains a
  bare-metal opt-in. See the README "I/O driver" section.)
- io_uring GSO batching (issue #17): the `UringDriver` egress path coalesces
  TUN-egress datagrams into `UDP_SEGMENT` sends again (`MAX_GSO_SEGMENTS_PER_SEND`
  1 → 32), made **FEC-safe** by tagging each egress datagram with its RaptorQ
  object id ("fate") across the `Dispatch::on_tun` boundary (new `EgressDatagram`)
  and coalescing **at most one datagram per fate per skb** — so a dropped GSO
  super-skb never costs an object both its source symbol and its own repair
  (which previously pinned the cap to 1). The invariant is enforced at a single
  unit-tested choke point (`can_coalesce_gso_tagged`); `arq_recovers_bulk_loss`
  stays ≥ 98% delivery under uring with GSO active. No wire-format or
  `yip-transport` API change. (Single-stream throughput is unchanged on
  measurement — that path is FEC/CPU-bound, not syscall-bound; GSO's win is on
  syscall-bound bursts. The ARQ-retransmit egress path is left non-GSO for now.)
- io_uring driver RTT work: the `UringDriver` hot path no longer allocates per
  packet — received datagrams dispatch from a reused scratch buffer, send buffers
  are recycled through a pool, and `poll_once` drains completions into a reused
  vec (matching `PollDriver`, which was already alloc-free). Adds an opt-in
  **busy-poll** mode (`YIP_URING_BUSYPOLL=1`): `poll_once` spins the completion
  queue before blocking, cutting tunnel RTT from ~0.47 ms to ~0.31 ms and
  **beating the epoll `PollDriver` (~0.37 ms)** — a "burn CPU for latency" knob,
  off by default so idle tunnels don't spin. The spin is **adaptive**: it only
  runs while an exchange is active (recent completions) and backs off to a plain
  blocking wait the moment a wait times out, so an idle tunnel burns no CPU while
  an active one still catches imminent completions. (Making it the default /
  tuning the spin budget wants clean-hardware measurement; io_uring stays opt-in.)
  The `UringDriver` blocking wait is now bounded by a 10 ms timeout (via io_uring
  `EXT_ARG`, kernel 5.11+), so `Dispatch::tick` fires on cadence even on a fully
  idle tunnel — parity with poll.rs's `epoll_wait` timeout, fixing a latent gap
  where an idle uring tunnel could starve rekey/feedback timers.
- io_uring cleanup: the `UringDriver` now exposes a `dropped_sends` counter (folded
  into the send-drop logs) so slot-exhaustion drops are observable in aggregate,
  and drops the dead `udp_armed`/`tun_armed` fields. The two provided-buffer/send-
  slot reuse unit tests were made robust to bounded, load-dependent datagram loss
  (they assert pool *reuse* — round-tripping more than the fixed pool holds — plus
  the leak checks, rather than 100% round-trip), so the local suite is fast and
  reliable again.
- Coverage CI: exclude `yip-io/src/uring.rs` from the llvm-cov denominator (honest
  exclusion — the `UringDriver` syscall loop is netns/integration-gated, same
  pattern as `yip-device` privileged paths).
- Data-plane throughput pass: yipd now batches egress sends (`sendmmsg`) and
  ingress reads (`recvmmsg`) through yip-io's `PlainIo`, reuses framing buffers
  (no per-symbol allocation), and sizes `SO_SNDBUF`/`SO_RCVBUF` to 4 MiB via a
  yip-io `set_socket_buffers` helper. `yip-transport` gained a byte-identical
  RaptorQ encode bypass for the zero-repair case (dormant until the controller
  can request zero repair — see `crates/yip-bench/README.md`). yipd is now
  `#![forbid(unsafe_code)]`; `yip-io` pins `libc` exactly.

### Added
- Workspace scaffold with `yip-io`, `yip-wire`, `yip-crypto`, `yip-transport`,
  `yip-device`, and `yipd` crate stubs.
- CI quality gates: build, test, clippy, rustfmt, cargo-shear, cargo-deny,
  coverage, and mutation testing.
- Pre-commit hooks (file hygiene, cargo fmt, clippy, and test).
- Public `README.md` and `docs/architecture.md`.
- `yip-wire` frame codec: header serialization, SipHash coverage-auth tag, and
  keyed header protection, with fuzzing of the deframe path.
- `yip-crypto` Noise-IK handshake (via `snow`) and AEAD `Session` with explicit
  per-frame nonces and a sliding anti-replay window.
- `yip-device` TUN (L3) and TAP (L2) tunnel devices, and `yip-io` io_uring
  DataPlaneIo backend with a portable plain-socket fallback.
- `yip-transport` adaptive RaptorQ FEC: per-flow classifier, object encoder,
  pipelined erasure-tolerant reassembler, and a repair-ratio controller.
- `yip-transport` stateful flow-table heuristic: classifies unmarked flows by
  observed packet size/rate, completing the policy -> DSCP -> heuristic -> default
  precedence chain.
- `yipd` end-to-end tunnel: Noise handshake over UDP, session-derived wire keys,
  and L3 (TUN) traffic tunneled through the encrypted adaptive-FEC transport
  between two static peers (ping-tested across network namespaces).
- `yip-bench`: hot-path micro-benchmarks (AEAD, wire framing, RaptorQ FEC encode)
  via Criterion, and a `tc netem` latency/loss harness comparing the yip tunnel
  against kernel WireGuard (results in `crates/yip-bench/README.md`).
