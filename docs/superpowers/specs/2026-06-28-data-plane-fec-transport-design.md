# Sub-project #1 — Core Data Plane + FEC Transport (Design)

**Date:** 2026-06-28
**Status:** Approved design, pre-implementation
**Scope:** The first of five sub-projects for the low-latency P2P mesh VPN (working name **yip**).

---

## 0. Context & decomposition

The overall project (see root `README.md` and `docs/research/00-overview.md`) is a low-latency,
high-performance P2P mesh-network VPN tunnel in Rust. That is a *platform*, not one project. It is
decomposed into five sub-projects, each with its own spec → plan → build cycle:

1. **Core data plane + FEC transport (THIS SPEC)** — two manually-configured peers, encrypted L2+L3
   tunnel over an adaptive RaptorQ-FEC UDP transport, with a kernel-bypass-ready I/O layer.
2. **Control plane** — discovery (DHT/gossip), self-certifying key-derived addresses, UDP
   hole-punching, zero-knowledge relay fallback.
3. **Anti-DPI / obfuscation layer** — implements the pluggable link trait; AmneziaWG recipe,
   optional REALITY-style TLS mimicry; nDPI/nDPId wired into CI as the adversary.
4. **Traffic-analysis defense (DAITA) + per-flow anonymity dial** — optional onion routing via Arti.
5. **Hardening / multi-platform / management UX** — macOS/Windows, optional kernel-module or
   Hermit-on-Firecracker relay appliance, config tooling.

Build #1 first: it is the latency-critical core and the only piece fully testable in isolation.

### Primary goals (from brainstorming)

- **Insane low latency** for direct P2P: gaming/streaming + L2 IXP-style offloading with FEC
  autocorrection. This is the north star.
- **General-purpose VPN** as the broad use case (L2 + L3).
- Censorship-resistance, DAITA, and anonymity are **secondary dials** layered on in later
  sub-projects, not part of #1.

### Locked decisions

- **Data-plane foundation:** custom protocol — our own I/O + lean wire framing (norp-inspired
  ideas), reusing **gotatun's audited Noise-IK + AEAD** as a crypto library only. Not a gotatun
  fork; not building out norp; not hand-rolling crypto.
- **Layering:** encrypt-then-FEC. AEAD-encrypt each inner frame end-to-end, then RaptorQ-encode the
  ciphertext for the wire. FEC never sees plaintext.
- **FEC strategy:** adaptive per-flow dial (not fixed, not lane-based).
- **Crypto:** classical Noise-IK first, handshake structured so a Rosenpass-style hybrid PQ KEM
  (Classic McEliece + ML-KEM) drops in later. ~120 s rekey.
- **Platform:** Linux-first. **License:** MPL-2.0 (keeps gotatun compatibility).
- **L2 (TAP) and L3 (TUN) both at launch.**

### Research basis (see `docs/research/`)

- Crypto is **latency-irrelevant** (~0.5–2 µs/packet). The ~300 µs gap between userspace WireGuard
  (~0.73 ms RTT) and kernel WireGuard (~0.42 ms) is **syscalls + copies + tokio scheduling**, not
  crypto. → The I/O model is the latency lever, so we replace gotatun's tokio-UDP path.
- **norp** (MirOS-licensed): solid wire-format/coverage-auth/identity *ideas*, but core is `todo!()`
  stubs, bespoke unproven crypto, no PQ path, naive `recvfrom` I/O. Borrow ideas, not code.
- **nyxpsi** (MPL-2.0, the author's earlier failed attempt): tried this exact idea; its four fatal
  bugs become four non-negotiable rules (see §4). Validates adaptive-FEC direction; cautionary on
  framing/measurement/benchmarks.
- **Unikernels:** no latency win over tuned AF_XDP/io_uring; architecturally broken for a client
  (a VM behind a host TUN). Deferred to sub-project #5 for the relay tier on security grounds only.

---

## 1. Component architecture

A Cargo workspace (MPL-2.0), bootstrapping scaffolding/conventions from the sibling `blackwall`
project (workspace lints, rustfmt, pre-commit, CI, coverage script, crate-splitting discipline).

| Crate | Responsibility |
|---|---|
| **`yip-io`** ⭐ | The latency core. `DataPlaneIo` trait. Backend A: a single `io_uring` ring servicing both the UDP socket and the TUN/TAP fd (DEFER_TASKRUN, NAPI busy-poll, registered files, multishot recv, opportunistic non-blocking batching; skip `SEND_ZC`). Backend B: AF_XDP zero-copy with graceful fallback (zerocopy → copy → io_uring → `recvmmsg`/`sendmmsg`). |
| **`yip-wire`** | Lean custom framing: keyed header-protection (no fixed magic from byte 0), coverage-style selective authentication (NAT-survivable), epoch-rotating keyed conn tag, explicit FEC block header, 8-byte alignment, one symbol per datagram, no cross-packet fragmentation. |
| **`yip-crypto`** | Reuse gotatun's audited Noise-IK + AEAD session (Curve25519 / ChaCha20-Poly1305 / BLAKE2s), anti-replay window, ~120 s rekey with an overlap window. Handshake structured for later PQ KEM drop-in. |
| **`yip-transport`** | RaptorQ encode/decode · per-flow classifier (precedence: policy → DSCP/ToS → heuristic → default) · adaptive controller (piggyback + periodic feedback) · thin ARQ for residual loss on reliable classes · per-flow coalescing/GRO dial unified with FEC class. The algorithmic heart. |
| **`yip-device`** | `Tun` (L3) and `Tap` (L2 + MAC-learning table + broadcast) behind one `Device` trait, fed by `yip-io`'s ring. |
| **`yipd`** | Daemon: static 2-peer config, wires device ↔ transport ↔ crypto ↔ wire ↔ io, runs the busy-poll loop, exposes tuning knobs (core pinning off the IRQ core, `rx-usecs 0–2`, C-state cap, `performance` governor, optional `SO_PREFER_BUSY_POLL` IRQ-suspension). |

Every layer is one trait — independently testable; the I/O backend is swappable without touching
the protocol.

---

## 2. Data flow

**Egress** (device → wire):

```
1. device.read()          inner L2/L3 frame (plaintext, local)
2. classifier.classify()  reads DSCP/5-tuple → FlowClass   (policy → DSCP → heuristic → default)
3. session.seal()         AEAD-encrypt inner frame → ciphertext            [yip-crypto]
4. fec.encode()           RaptorQ-encode the CIPHERTEXT → symbols          [yip-transport]
5. wire.frame()           per-symbol header + coverage-auth + header-protect [yip-wire]
6. io.send()              io_uring / AF_XDP                                 [yip-io]
```

**Ingress** reverses: `io.recv → wire.deframe (auth + deprotect) → fec.decode (object complete?)
→ session.open → device.write`.

The classifier reads the plaintext inner packet (local, pre-encryption). FEC operates only on
ciphertext.

### Wire frame layout (per UDP datagram = one symbol)

Whole header is **keyed header-protected** (QUIC/AmneziaWG-style XOR keystream sampled from a header
field), so every wire byte looks random — no constant offsets for nDPI.

Logical fields (pre-protection):

| Field | Size | Purpose |
|---|---|---|
| conn tag | 4–8 B | Selects session/decoder. Epoch-rotating keyed token (not a static peer ID) — avoids linkability + DPI fingerprint; also carries rekey epoch. |
| object_id | 2 B | Which pipelined FEC object this symbol belongs to. |
| RaptorQ payload ID | 4 B | SBN + ESI — emitted by the `raptorq` crate's `EncodingPacket::serialize()`. |
| flags | 1 B | symbol kind (source/repair), object-descriptor-present, is-feedback, is-ARQ. |
| object descriptor (first/periodic symbols only) | ~3 B | `object_size` (the OTI piece RaptorQ does not self-signal). `symbol_size` is fixed per FlowClass, negotiated in the handshake — 0 bytes/packet. |
| payload | ≤ MTU | ciphertext symbol. |
| coverage-auth tag | 8 B | SipHash-style tag over header + a coverage-selected slice of transport context. |

Steady-state per-packet overhead ≈ **17–21 B** (vs norp ~105–120 B, vs WireGuard's fixed
fingerprintable header), none of it constant on the wire.

### Inner frame → RaptorQ object mapping

- **Realtime classes:** one sealed inner frame = one RaptorQ object (tiny K, zero wait-to-fill).
  Rateless property → emit source symbols immediately, mint repair symbols on demand.
- **Bulk/L2 classes:** coalesce several frames into a larger object (bigger K, better coding
  efficiency) — same per-flow dial as the GSO/GRO coalescing knob, unified.

### Feedback packet (adaptive loop)

Small control symbol (`is-feedback` flag), **piggybacked on return data when available, else on a
50–100 ms timer**. Carries per active object/flow: symbols-received vs needed, echoed client
send-timestamps (→ true RTT/jitter), observed erasure rate. Sender's controller sets the repair
ratio for subsequent objects.

### Controller ↔ ARQ interaction

- **Controller (proactive):** targets a post-FEC residual loss (e.g. < 0.1%). AIMD on repair-symbol
  count per FlowClass, driven by real feedback. Clean link → ~0 % overhead; lossy link → more repair
  symbols, no retransmit RTT.
- **Thin ARQ (reactive, reliable classes only):** undecodable-after-budget → receiver NACKs
  `object_id`; sender mints additional repair symbols (cheap, rateless), drops after a retry cap.
  **Realtime classes skip ARQ entirely** — a late repair is useless to a game/voice frame.

---

## 3. Flow classification

Precedence chain (each layer overrides the one below); the resulting class still auto-tunes
redundancy to live conditions:

1. **Explicit policy rule** (user-pinned CIDR/port/proto → class) — highest.
2. **DSCP/ToS** from the inner packet — honor what the app marked.
3. **Automatic heuristic** (per-5-tuple size/rate/burstiness) — fills unmarked, unruled flows.
4. **Adaptive default** — baseline.

Per FlowClass parameters: RaptorQ `symbol_size`, object granularity (single-frame vs coalesced),
target residual-loss, ARQ on/off, coalescing/GRO flush behavior (flush-now for realtime — dodges
the 50 µs GRO timeout trap; batch for bulk).

---

## 4. Error handling & failure modes

| Failure | Handling |
|---|---|
| Object never decodes | Per-object deadline tied to FlowClass. Realtime → drop silently, advance. Reliable → ARQ for more repair symbols, drop after retry cap. Never block the pipeline. |
| Decoder memory growth | Hard cap on in-flight objects per flow; LRU eviction by `object_id` age + metric. No unbounded buffering. |
| Late/duplicate symbols | Dropped on `object_id` lookup miss. |
| Auth-fail / malformed | Coverage-auth checked before any FEC/crypto work; silent rate-limited drop (no error reply — replying is a DPI/amplification oracle); constant-time compare. |
| Replay | AEAD nonce/counter monotonicity (gotatun anti-replay window); FEC idempotent per object_id+ESI. |
| Rekey mid-flight | Epoch in conn tag; previous epoch's session + decoders kept alive for a short overlap so in-flight objects finish under the old key. No flush/stall. |
| Path MTU | `symbol_size` negotiated below path MTU per FlowClass (probe + conservative ~1200 B default). No IP fragmentation, no cross-packet symbol splitting. PMTU drop → renegotiate, don't fragment. |
| I/O backend unavailable | `DataPlaneIo` probes at startup, falls back zerocopy → copy → io_uring → recvmmsg; always boots, logs chosen backend. |
| Device errors | Backpressure to the ring (no spin-drop); interface-down → pause, re-open, surface state. |
| Classifier mis-class | Self-correcting via real feedback; misclass costs efficiency, never correctness. Policy always overrides. |

**Principle:** every attacker-influenced path fails silent + rate-limited + metered; never an error
reply; never unbounded state.

### The four nyxpsi rules (non-negotiable)

1. **OTI explicit in the frame header — never inferred from packet length** (nyxpsi's fatal bug).
2. **Pipelined FEC groups — never stop-and-wait** (N objects in flight, each its own coder).
3. **Real RTT via echoed client timestamps — never syscall duration.**
4. **Plain UDP, not UDP-Lite** (middlebox-dropped + a DPI signature; AEAD already rejects
   corruption, FEC handles erasures).

---

## 5. Test & benchmark strategy

**Unit (per crate):**
- `yip-wire` — frame round-trip; header-protect inverse; coverage-auth accept/reject + NAT-rewrite
  survival; `cargo-fuzz` on the deframe path.
- `yip-transport` — RaptorQ round-trips under programmatic erasure; explicit-OTI test (vary packet
  sizes, confirm decode — the nyxpsi anti-test); pipelined multi-object concurrency; eviction/
  deadline; controller AIMD convergence from synthetic feedback.
- `yip-crypto` — gotatun vectors; rekey-overlap correctness.

**Integration (two `yipd` in Linux netns over veth):** L3 (TUN) and L2 (TAP incl. MAC learning +
broadcast) end-to-end; each backend-fallback path forced and verified; rekey under load with no
stall/drop spike.

**Benchmark harness (headline deliverable, nyxpsi-proofed) — `yip-bench` crate:**
- Real impairment via `tc netem` (loss, latency, jitter, reorder, dup) on veth — never loopback +
  sleep.
- Apples-to-apples: identical transfer patterns and netem profiles across every contender; pinned
  versions and documented configs for each, automated so runs are reproducible.
- **Comparison matrix — compared like-for-like by layer** (a tool is only benched on the data plane
  it actually provides):

  | Contender | Layer | Role in comparison |
  |---|---|---|
  | **yip** (io_uring + AF_XDP backends) | L2 + L3 | subject |
  | **WireGuard (kernel)** | L3 | the latency floor to approach |
  | **WireGuard-go / boringtun** | L3 | userspace baseline we must beat |
  | **AmneziaWG** | L3 | obfuscated-WG latency cost reference |
  | **OpenVPN** | L3 | legacy baseline |
  | **n2n** | L2 | primary L2 mesh comparison |
  | **ZeroTier** | L2 | L2 overlay comparison |
  | **plain UDP / plain kernel routing** | — | absolute floor (no tunnel) |

- Metrics across a netem sweep: added one-way latency + p99 (target within ~50–80 µs of kernel WG on
  io_uring); **p99-under-loss** (the thesis: yip stays ~flat through 1–10 % loss while the others
  spike); repair-overhead % vs measured loss; throughput single/multi-core per backend; CPU per Gbps.
- Latency-floor validation on real hardware: confirm ~0.42–0.5 ms io_uring and ~6.5–13 µs AF_XDP
  wire path; record as project baseline.
- In-process micro-benches (Criterion) for the hot logic (AEAD seal/open, RaptorQ encode/decode,
  classify, header-protect) kept separate from the network benches.
- CI: unit + netns integration every commit; netem comparison bench nightly/on-demand (needs
  `CAP_NET_ADMIN` and the contenders installed), tracked over time for regressions.

### Coverage & correctness bar

- **≥ 90 % line coverage on every crate**, measured with `cargo-llvm-cov`, enforced in CI.
- Coverage alone is gameable, so it is backed by: **`cargo-mutants`** (mutation testing) on the
  protocol/logic crates (`yip-wire`, `yip-transport`, `yip-crypto`) so the 90 % is *meaningful*, and
  **`cargo-fuzz`** on every parser (`yip-wire` deframe, RaptorQ packet deserialize, feedback parse).
- **Honest exclusion:** the AF_XDP **zero-copy** path and io_uring SQPOLL paths cannot be covered
  hermetically (need specific NICs / kernel caps not present in CI runners). These are covered by the
  netns integration suite in *copy/fallback* mode and a separately-documented, hardware-gated suite;
  the un-CI-able lines are explicitly annotated and excluded from the 90 % denominator with a
  rationale comment, **not** silently. No other exclusions.

---

## 6. Definition of done

Two peers, manual config, L2+L3 tunnel up; `DataPlaneIo` auto-selects backend with fallback; the
bench harness produces latency + p99-under-loss + repair-overhead plots showing **yip at
WireGuard-class latency and materially flatter under loss**.

### Expected results (targets to validate, not promises)

- Added one-way latency ~0.1–0.3 ms (io_uring), toward ~0.05 ms with AF_XDP on bare metal —
  WireGuard-class.
- Flat p99 under 1–5 % loss where plain tunnels spike +50–150 ms per lost packet.
- Recovers ~5–10 % random loss for realtime flows at ~10–30 % auto-tuned repair overhead (~0 % on
  clean links); bulk classes tolerate ~15–20 %+.
- Throughput ~1–5 Gbps/core (io_uring) → 10 Gbps+/core (AF_XDP).

### Explicitly NOT in #1

No discovery / NAT traversal / relay (#2); no anti-DPI obfuscation (#3, though `yip-wire` is built
DPI-friendly); classical crypto only, PQ-ready (PQ in a later sub-project).

---

## 7. Coding standards & guidelines compliance

Follows `~/projects/femboy/coding-guidelines` (the Mullvad guidelines) — same lint set already used
by `blackwall`, so the two repos stay consistent.

- **Lints:** adopt the guideline `[workspace.lints]` set verbatim; CI builds with `--deny warnings`.
  rustfmt with the Mullvad reference config. `cargo clippy` clean.
- **Integer conversions — `as` is banned for numeric casts.** Use `From` / `TryFrom`. This is
  load-bearing here: the packet/symbol code is full of width conversions (`symbol_size: u16`, ESI,
  lengths, counters) and **nyxpsi's fatal bug was literally `let packet_symbol_size = size as u16`**.
  The guideline that forbids `as` would have caught it at compile time — so this rule is a primary
  defense, not a style nicety.
- **Unsafe:** `yip-io` (io_uring/AF_XDP) is the only crate with significant `unsafe`. Every `unsafe`
  block gets a `// SAFETY:` comment; every `unsafe fn` a `# Safety` doc section; blocks kept minimal.
  `undocumented_unsafe_blocks` lint enforces it. Goal: confine `unsafe` to `yip-io`; the protocol
  crates stay `#![forbid(unsafe_code)]`.
- **Borrowed types:** `&[u8]` / `&str` / `&Path`, never `&Vec` / `&String` / `&PathBuf` in signatures.
- **Dependencies:** pin full versions (`x.y.z`, not `x`); prefer crates.io; any git dep is forked to
  our org and pinned by `rev`. `cargo-shear` (unused deps) and `cargo-deny` (licenses + RUSTSEC
  advisories) in CI; verify against `-Z minimal-versions`.
- **API design:** follow the Rust API guidelines; avoid premature generality (a concrete
  `Tap`/`Tun` over an over-abstracted device factory) per the "don't over-genericize" rule.
- **Docs:** document what the signature does *not* already say (invariants, drop behavior, units),
  not restatements. Public items documented; keep the documentation ratio up.
- **Changelog:** keep-a-changelog `CHANGELOG.md` from the first commit (Added/Changed/Fixed/…).
- **Git:** imperative, capitalized, ≤72-char subjects; kebab-case branches; clean history (no
  intra-branch "fix typo" commits).
- **Files:** UTF-8, LF, final newline, no trailing whitespace, space indent.

## 8. Future-reuse earmark

A fast-path AF_XDP/eBPF packet-I/O layer is wanted by both this project (`yip-io`'s AF_XDP backend)
and `blackwall` (DDoS fast-drop). Earmark a shared `xdp-io` crate, factored out once #1's AF_XDP
backend is proven.
