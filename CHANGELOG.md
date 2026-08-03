# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

No release has been cut yet — everything below is tracked under `[Unreleased]`
until 0.1.0.

### Security
- **Handshake anti-replay + authenticated endpoint (#34, PR #99).** The
  Noise-IK `msg1` now frames a TAI64N timestamp alongside the existing cert
  inside the encrypted handshake payload; a freshness-gate check replaces the
  old age gate, and a peer's endpoint is learned **only from a fresh `Init`**.
  This closes an endpoint-hijack-via-replay vector: a captured `Init` replayed
  later could previously rebuild session state and redirect a peer's outbound
  traffic. The earlier #36 cold-start relay-rebuild path is retired in favor
  of this freshness gate (a stale/replayed `Init` is rejected outright rather
  than triggering a rebuild).
- **Signed rendezvous registration + authenticated endpoint roaming (#37 +
  M2, PR #100).** A `yip-rendezvous` server started with `--roots
  <path> --network-id <hex32>` now enters mesh mode and rejects any
  registration that doesn't carry a `RegisterSigned` record verified against
  the root set's CA keys — closing registration-squatting/overwrite, where an
  unauthenticated actor could previously claim another node's rendezvous slot
  and redirect its traffic. Endpoint roaming (M2) is now itself
  authenticated: a peer's stored endpoint updates only after an inbound
  datagram passes AEAD authentication and the anti-replay window (WireGuard's
  roaming model), including the in-flight-rekey and relay-adoption edge
  cases. Exercised end-to-end by netns tests asserting a forged registration
  is refused and the legitimate node stays reachable.
- **Punch→relay escalation always draws a fresh ephemeral (#116, PR #117).**
  The `#34` freshness gate requires a Punch→Relay path re-target to draw a
  **fresh** Noise ephemeral; a preserved (retransmitted) ephemeral is a bare
  replay a captured `Init` could ride to force a relay downgrade. The
  escalation only redrew when it fired *before* the peer was flagged
  relay-reached — but an inbound relayed packet (`on_relayed`) can set that
  flag first, and the old guard then skipped the escalation and retransmitted
  the **same** punch ephemeral over the relay. This was intermittent and
  race-dependent (the path-switch money test failed on `main` whenever the
  relayed packet won the race). The escalation now keys on the in-flight
  `Init`'s own relay origin rather than the peer's relay flag, so a fresh
  ephemeral is drawn regardless of when the flag flipped, while a relay `Init`
  already in flight is still merely retransmitted (no ephemeral churn).
  Covered by a deterministic regression test.

### Added
- Classical session rekey + epoch handling (milestone 9a, #9, PR #90):
  established sessions now rotate keys roughly every **~120 s** via a
  winner-initiates, one-in-flight rekey exchange (`EpochSet`:
  current/next/previous epochs, WireGuard-style confirmed-switch), with the
  losing side falling back cleanly on a race. Visible on the wire as a
  connection-tag rotation; verified with a loss-free netns rotation test.
- Relay-path rekey completion (#91, PR #92): the 9a rekey exchange, until now
  gated off for relayed peers, completes over the blind relay too
  (`relayed_handshake_init`/`relayed_handshake_resp` cores), preserving FEC
  fate tagging through the relay wrap/unwrap. Previously a relayed session
  simply never rekeyed.
- **REALITY.3–5d** (PR #83, PR #88 — PR #88's branch is named "follow-up
  cleanups" but actually carries REALITY.5b–5d): the Xray-REALITY relay
  transport's authenticated-serving path is now feature-complete. REALITY.3
  finished the server's stolen-cert forging (AIA extension copying, a
  per-SNI anti-replay guard on the auth seal, `--reality-cert-refresh-secs`/
  `--reality-cert-max-stale-secs` staleness bounds). REALITY.4a/4b wired up
  the `yipd` client side: `rendezvous=reality://host:port?pbk=&sid=&sni=`
  dials the relay with a Chrome-faithful crafted ClientHello, and `verify=`
  (default `on`) adds explicit client-side relay verification (pinned leaf
  key + `CertificateVerify` check derived from the shared seal secret) so a
  wrong `pbk`/relay key fails closed with a long jittered backoff instead of
  hammering the wrong host. REALITY.5a–5d then replaced the relay's
  authed-connection TLS serving with a hand-rolled, byte-matching TLS 1.3
  server flight (`yip-utls`'s `RealityStream`) built from a captured template
  of the real destination's own handshake shape — **dropping BoringSSL
  forged acceptors from the authed-serve path** (BoringSSL/`cmake` remain a
  build dependency overall, for the unauthenticated-splice path and
  `transport=tls`). Exercised end-to-end by `run-netns-reality-relay.sh` and
  `run-netns-reality-5d.sh`, including wrong-`pbk` and wrong-relay-key
  negative tests. See `docs/configuration.md` for the full `reality://` /
  `--reality-*` flag reference.
- `#59` MTU-aware packetization investigation findings + measurement tooling
  (PR #94) — **documentation/investigation only**, no code or wire change.
- REALITY.2 (anti-DPI): new pure-Rust `yip-utls` crate — a uTLS-equivalent
  REALITY client that crafts a **byte-faithful latest-Chrome (150) ClientHello**
  (with our own X25519 `key_share` and a REALITY auth seal in `legacy_session_id`)
  and completes a **TLS 1.3 handshake to an application-data stream**, entirely in
  safe Rust (`ring` + `x25519-dalek` + `chacha20poly1305` + `ml-kem`; no Go, no
  BoringSSL, `#![forbid(unsafe_code)]`). The crafted hello is locked to the real
  Chrome JA4 (`t13d1516h2_8daaf6152771_806a8c22fdea`) by a CI diff test, permutes
  its extension order per connection like real Chrome (so JA3 varies), and includes
  a genuine **X25519MLKEM768 post-quantum hybrid** key — the client completes the
  real ML-KEM-768 + X25519 hybrid handshake (verified live against Cloudflare, which
  selects it). The REALITY auth seal/open is now a shared codec used by both this
  client and the `yip-rendezvous` relay (REALITY.1). Standalone library — wired into
  yipd in REALITY.4.
- REALITY-style TLS front for the relay, server side (anti-DPI milestone
  REALITY.1): `yip-rendezvous`'s `--listen-tcp` TLS front gains an opt-in
  full Xray-style REALITY mode — `--reality-dest <host:port>`,
  `--reality-private-key <hex64>`, `--reality-short-id <hex16>` (repeatable),
  `--reality-server-name <name>` (repeatable). The relay reads the raw TLS
  `ClientHello` off the socket *before* terminating TLS and checks for a
  REALITY auth seal — an X25519-ECDH-keyed ChaCha20-Poly1305 seal carried in
  `legacy_session_id`, validated against the relay's REALITY private key, the
  configured `short_id`s, and a ±10-minute timestamp freshness window.
  Authenticated connections are served the relay tunnel (TLS terminated with
  the configured cert, same as the 3c.3 front below); everything else — an
  active prober, a scanner, a plain browser, or any connection without valid
  auth, including malformed/oversized TLS records — is **transparently
  spliced to a real upstream site** (`--reality-dest`, e.g.
  `www.apple.com:443`), replaying the bytes already read, so the prober
  completes a genuine handshake with the real site and sees *its* real cert.
  `--reality-dest` **supersedes `--decoy`** (the 3c.3 self-hosted-backend
  Trojan model) when both are given. **Server side only:** the yip client
  that embeds REALITY auth into its ClientHello is milestone REALITY.2, not
  yet shipped — until it lands, no production client authenticates and the
  relay forwards every live connection to `dest`.
- Port plausibility (anti-DPI 3d, R8/#45): `listen` is now optional and
  auto-defaults every transport to 443 (443/TCP for `tls`, 443/UDP for
  `quic`/`raw`) — the single least-suspicious port — falling back to 8443
  with a warning when binding 443 is denied (grant `CAP_NET_BIND_SERVICE`).
  yipd (and `yip-rendezvous`) warn at config load when a port is a known
  DPI-fingerprinted VPN default (51820/1194/500/4500/1701/1723/655);
  `example.config` no longer ships WireGuard's 51820. Fixes the port-match
  tell (#45).
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
- TLS relay-dial client (`rendezvous = tls://host:443`, anti-DPI 3c.4): a
  `yipd` node reaches the 3c.3 relay over a persistent browser-parrot TLS
  connection (a dedicated thread; the data plane stays tokio-free) and relays
  the unchanged inner protocol through it — so two UDP-blocked peers can
  tunnel to each other. Requires `obf_psk`; poll-driver-only; straight-to-relay
  (no Direct/UDP-punch).
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

### Fixed
- **Privileged CI jobs declared none of the tooling they drive (PR #156).**
  `catthehacker/ubuntu:act-22.04` — the image every Forgejo Actions job runs
  in — ships no `ip`, `tc`, `ping`, `tcpdump`, `iperf3` or `wg`, and its
  `PATH` already includes `/usr/sbin` and `/sbin`, so these were missing
  packages and never a PATH problem. `netns-tunnel-test` and
  `dpi-undetectability` died at `run-netns-tunnel.sh:86` and
  `run-ndpi-oracle.sh:129` with `ip: command not found`; every retry failed
  identically because the fault was deterministic. `netem-comparison` had
  `ip` only as a transitive *Recommends* of `wireguard-tools` — not a
  dependency — and broke the day that resolution changed. Each job now
  installs what its harness scripts actually run, sized from every script the
  job drives rather than the one that happened to fail first. Also: the scp
  harness creates `/run/sshd` before starting `sshd` (the package postinst
  normally does, but the image ships `sshd` without having run it and `/run`
  is a fresh tmpfs per container), and `start_sshd` now prints sshd's log and
  exit status on failure instead of leaving `-E "$logfile"` output in a file
  the cleanup trap deletes — which is why that failure had surfaced only as
  `harness failed`. A stale comment claiming `tcpdump` was "preinstalled on
  the runner image" is corrected; that belief is why it was never declared.
- **`hardening.41` cert-revocation gave discovery less time than it needs
  (PR #158, #157).** `CERT_A_SECS` was 60 and the establish loop stops 5s
  before expiry to keep the "still valid" invariant honest, leaving a 55s
  convergence window — while `run-netns-discovery.sh:287` documents gossip
  warm-up as needing "up to a 60s budget". The test allocated less time than
  its own sibling says the thing it waits for can take, so a green run was
  one that happened to converge early. Raised to 150s (~2.5x the documented
  worst case); the assertion is unchanged, since the cert still expires
  mid-test.
- Session-lifecycle hardening (#36 path-switch re-handshake + #41 cert
  revocation, PR #95): a path-switch (roaming) no longer discards the
  in-flight handshake ephemeral, both initiator- and responder-side relay
  adoption are covered for a relayed cold-start retransmit, and mesh peers
  now get a periodic cert-liveness sweep plus a re-verify-on-rekey-`Init`
  gate (both exempting root nodes) — so a revoked member's session no longer
  silently keeps working until its next full handshake.
- Root-exempt responder-cert checks (PR #97): responder-side cert checks now
  exempt root nodes symmetrically with the initiator-side gates — a root
  could previously fail a check the initiator side already exempted it from.
- Gossip digest chunking (#44, PR #98): the mesh gossip digest is now
  chunked, and its obfuscation degrades fail-soft, instead of panicking once
  a mesh grows past a single-datagram digest size.
- io_uring loopback recycle tests hardened against default socket buffers
  (PR #113): the recv-buffer and send-slot recycle tests now interleave
  send+drain (bounded in-flight window) instead of blasting all datagrams
  first, so they no longer fail on a box with a default
  `net.core.rmem_default`. The old pattern asserted `>256` datagrams
  round-trip but relied on the kernel buffering that many at once; the default
  ~208 KB receive buffer holds only ~230 small datagrams, so the assert
  failed deterministically on stock-configured machines.

### Changed
- Rendezvous relay-forward counter moved off the server's mutex onto a
  shared `AtomicU64` (#68, PR #93) — a pure perf fix (removes lock
  contention on the hot forwarding path under load); no behavior change to
  the `relay-forwarded=<N>` log line.
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
