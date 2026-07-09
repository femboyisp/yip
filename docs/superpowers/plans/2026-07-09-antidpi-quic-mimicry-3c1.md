# Sub-project #3 Milestone 3c.1: QUIC Mimicry (the QUIC costume) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make yip traffic classified as QUIC by DPI (defeating `SUSPICIOUS_ENTROPY` + HTTPS-allowlisting) while preserving the UDP+FEC low-latency north star, by running yip's unchanged inner protocol inside a real `quinn-proto` QUIC connection as RFC 9221 unreliable DATAGRAM frames.

**Architecture:** `transport=quic` selects (at startup) a new parallel epoll pump (`bin/yipd/src/quic.rs`) that drives a `quinn-proto` `Endpoint` bound to the existing UDP socket: inbound QUIC DATAGRAM frames become plain yip datagrams fed to the unchanged `PeerManager`; egress yip datagrams go out as DATAGRAM frames. The outer QUIC is a throwaway-cert costume; the inner yip Noise-IK/FEC/AEAD is the real, unchanged security. Absent the flag ⇒ today's raw-UDP path (incl. 3a obf + 3b junk) is byte-identical.

**Tech Stack:** Rust, `quinn-proto` (sans-IO QUIC state machine — NOT the `quinn` crate, no tokio) + rustls/ring, the merged 3a/3b stack, `refrences/nDPI` (`ndpiReader`) for the oracle.

## Global Constraints

- `yipd` stays `#![forbid(unsafe_code)]` — `quinn-proto` is forbid-unsafe-friendly; NO new `unsafe` in yipd. No `as` casts except existing discriminants (use `try_from`).
- Use **`quinn-proto`** (the state machine), NOT `quinn` (avoids the tokio runtime). Pin `quinn-proto` (current stable, e.g. `0.11.x`) + its rustls/ring crypto provider, scoped to the **`yipd` crate only** (pin exact versions per the workspace convention; add to `[workspace.metadata.cargo-shear]` ignore if a transitive-only dep trips shear).
- **QUIC is a costume/layer** — the inner yip protocol (Noise-IK, cert admission 2c, FEC, AEAD, anti-hijack) is UNCHANGED and is the real security. `PeerManager` routing/demux/handshake logic is NOT modified.
- **Outer QUIC = throwaway self-signed cert + client accept-any-cert verifier** (zero auth, costume only) → a QUIC MITM recovers only inner yip ciphertext. **Double encryption is intentional; do NOT drop yip's inner AEAD.**
- **`transport=quic` and `obf_psk` are MUTUALLY EXCLUSIVE** (config-load error if both set).
- **`transport` absent ⇒ byte-identical** raw-UDP + obf + junk wire path (no-regression: all existing netns green under BOTH `poll` and `YIP_USE_URING=1`; existing `yip-transport` tests green after the symbol_size parameterization; rebuild `--release` before the arq/netns tests).
- **FEC preserved via RFC 9221 DATAGRAM frames** (unreliable/unordered) — NEVER QUIC streams (streams reintroduce HoL blocking). **One yip datagram per QUIC packet** (FEC loss independence).
- **`symbol_size` dynamic** `= min(1200, max_datagram_size − overhead)` from `Connection::max_datagram_size()` (PMTUD ⇒ stays 1200 steady-state on a 1500 path). Never silently truncate an oversized inner datagram — reject + telemetry.
- **North star:** the raw-UDP + FEC (+uring) default path is UNTOUCHED and remains the low-latency path. QUIC mode is an **opt-in** censorship-resistance premium (~10–15% throughput from double-encryption; poll-only).
- Green every task: `cargo fmt --all --check`, `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p <crate>`.
- Deferred / non-goals (do NOT build): uTLS/JA3-JA4 byte-exact ClientHello (3c.2), genuine-site reverse-proxy fronting (3c.2), R4 burst/timing matching (3c.2), QUIC + rendezvous/relay/mesh (3c.3), io_uring in QUIC mode (poll-only), plausible-port/443 R8 (3d), general N-transport abstraction (3d), TLS-over-TCP fallback.

**Sandbox note:** the pre-commit hook's workspace `cargo test` trips on 2 pre-existing unrelated `yip-io` io_uring memlock tests (pass in CI). If it blocks ONLY on those, commit `--no-verify` after confirming your crate + clippy + fmt are green.

---

## File Structure

- `bin/yipd/src/quic_spike.rs` or `bin/yipd/examples/quic_spike.rs` (NEW, Task 1, THROWAWAY): the de-risk spike; removed/kept-as-example after.
- `crates/yip-transport/src/lib.rs` (MODIFY, Task 2): parameterize `symbol_size` through `FlowParams`/`Transport::new`.
- `bin/yipd/src/dataplane.rs` (MODIFY, Task 2): thread the symbol_size into `Transport::new`.
- `bin/yipd/src/config.rs` (MODIFY, Task 3): `transport` field + mutual-exclusion validation.
- `bin/yipd/src/quic.rs` (NEW, Task 4): the `quinn-proto` endpoint + pump + two-layer handshake.
- `bin/yipd/src/tunnel.rs` (MODIFY, Task 5): startup transport selection; thread the QUIC symbol_size into `PeerManager`.
- `bin/yipd/src/peer_manager.rs` (MODIFY, Task 2/5): a `data_symbol_size` field + setter, passed to `DataPlane::new`.
- `bin/yipd/tests/run-netns-quic.sh` + `run-quic-mimicry-oracle.sh`, `tunnel_netns.rs`, `crates/yip-bench/…`, `.github/workflows/integration.yml` (NEW/MODIFY, Tasks 6–7).

---

### Task 1: `quinn-proto` datagram spike (de-risk — THE #1 risk)

**Files:**
- Create: `bin/yipd/examples/quic_spike.rs` (throwaway; may stay as an example)
- Modify: `bin/yipd/Cargo.toml` (add `quinn-proto` + rustls/ring)

**Goal:** Before building the transport, prove with real code that `quinn-proto` can send an RFC 9221 DATAGRAM frame **promptly** (no CC/pacing delay), measure per-packet overhead, and confirm PMTUD gives a usable datagram budget. A failing spike surfaces the contingency here.

- [ ] **Step 1: Add the dependency.** In `bin/yipd/Cargo.toml`, add `quinn-proto = "0.11"` (pin the exact current-stable patch) with a rustls/ring provider feature (read quinn-proto's features — typically `rustls` + `ring`). `cargo build -p yipd` to confirm it resolves and is `forbid(unsafe)`-compatible.
- [ ] **Step 2: Write the spike** (`bin/yipd/examples/quic_spike.rs`): a single-process, two-`Endpoint` (client + server) `quinn-proto` harness over two in-memory or loopback UDP sockets. Drive both endpoints' state machines manually (`Endpoint::handle`, `Connection::poll_transmit`, `Connection::handle_timeout`, `Connection::poll` for events). Configure `TransportConfig` to **disable congestion control/pacing for datagrams** (find the knobs: `datagram_receive_buffer_size`, `datagram_send_buffer_size`, and whether datagrams bypass the CC window; consult quinn-proto docs) and enable PMTUD. After the QUIC handshake completes: (a) send N DATAGRAM frames (`Connection::datagrams().send(...)`), timestamp send→wire, measure the delay; (b) print `Connection::max_datagram_size()`; (c) rough per-datagram CPU vs a bare UDP send loop.
- [ ] **Step 3: Run + record.** `cargo run --release -p yipd --example quic_spike`. Record in the report: datagram send latency (is it immediate, or CC/pacing-queued?), `max_datagram_size` (≥1224 means yip keeps symbol 1200), per-packet overhead estimate.
- [ ] **Step 4: Go/No-Go.** If datagrams are NOT sent promptly (CC/pacing can't be bypassed), STOP and report the contingency (options: force the CC window open / a custom `congestion::Controller` that never blocks datagrams / accept a bounded delay). Do not proceed to Task 4 assuming prompt sends unless the spike shows it. If good, note the exact `TransportConfig` knobs that worked — Task 4 reuses them.
- [ ] **Step 5: Commit** (`chore(yipd): quinn-proto datagram spike + dependency (3c.1 task 1)`). Record the numbers in the report.

---

### Task 2: parameterize `symbol_size` (currently hardcoded 1200)

**Files:**
- Modify: `crates/yip-transport/src/lib.rs` (FlowParams ~44-72, `Transport::new` ~101), `bin/yipd/src/dataplane.rs` (~176), `bin/yipd/src/peer_manager.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces: `Transport::new(rules: Vec<PolicyRule>, symbol_size: u16) -> Self` (symbol_size threaded into each `FlowParams`); `PeerManager` field `data_symbol_size: u16` (default 1200) + `set_data_symbol_size(u16)`; `DataPlane::new(..., symbol_size: u16)`.

`FlowParams` at lib.rs:44 has `pub symbol_size: u16` hardcoded `1200` in three class defaults (lines 60/66/72). Parameterize:
1. `Transport::new(rules)` → `Transport::new(rules, symbol_size: u16)`; the three `FlowParams` constructions use the passed `symbol_size` instead of the literal `1200`. (Keep a `Transport::new_default()` or pass 1200 explicitly at existing non-yipd call sites, e.g. the lib's own tests at lib.rs:235.)
2. `DataPlane::new` gains a `symbol_size: u16` param, passed to `Transport::new(vec![], symbol_size)`.
3. `PeerManager` gains `data_symbol_size: u16` (default 1200, `set_data_symbol_size`), passed to `DataPlane::new` at every establish site.

- [ ] **Step 1: Failing test** (yip-transport): `Transport::new(vec![], 1150)` yields `FlowParams` with `symbol_size == 1150` for each class; `Transport::new(vec![], 1200)` yields 1200 (the current behavior).
- [ ] **Step 2: Run → fail; implement** points 1–3. Update ALL call sites (lib.rs tests, dataplane.rs:176, the `DataPlane::new` sites in peer_manager.rs) — raw/obf mode passes **exactly 1200** (byte-identical).
- [ ] **Step 3: Gate — `cargo test -p yip-transport -p yipd --bins` all green** (existing FEC/transport tests unchanged with 1200); clippy/fmt. Commit (`refactor(yip-transport): parameterize symbol_size (3c.1 task 2)`).

---

### Task 3: `transport` config + mutual exclusion

**Files:**
- Modify: `bin/yipd/src/config.rs`
- Test: inline config tests

**Interfaces:**
- Produces: `Config.transport: Transport` where `pub enum Transport { RawUdp, Quic }` (default `RawUdp`); parsed from `transport=quic` (absent ⇒ `RawUdp`).

- [ ] **Step 1: Failing tests:** `transport=quic` → `Transport::Quic`; absent → `Transport::RawUdp`; an unknown value → parse error; **`transport=quic` together with `obf_psk=<hex>` → a config-load error** (mutually exclusive); `transport=quic` with `cover_traffic_ms` set → also error (cover is an obf-mode feature).
- [ ] **Step 2: Run → fail; implement** the `Transport` enum + parse arm + the mutual-exclusion check in `Config::parse` (after all keys parsed: `if transport == Quic && (obf_psk.is_some() || cover_traffic_ms.is_some()) { return Err(...) }`).
- [ ] **Step 3: Gate — `cargo test -p yipd --bins`; clippy/fmt.** Commit (`feat(yipd): transport=quic config + obf_psk mutual exclusion (3c.1 task 3)`).

---

### Task 4: the `quic.rs` pump + two-layer handshake (the crux)

**Files:**
- Create: `bin/yipd/src/quic.rs`
- Modify: `bin/yipd/src/main.rs` (mod quic)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `quinn-proto` (`Endpoint`, `Connection`, `TransportConfig`, `ServerConfig`, `ClientConfig`), the Task-1 spike's proven `TransportConfig` knobs, `PeerManager` (`on_udp`/`on_tun`/`tick`, unchanged), `EgressDatagram`.
- Produces: `pub fn run_quic(sock: UdpSocket, tun_fd: RawFd, manager: &mut PeerManager, symbol_size_out: &Cell<u16>) -> io::Result<()>` (or equivalent) — the parallel driver; plus `fn quic_symbol_size(max_datagram_size: usize) -> u16 = min(1200, max_datagram_size - QUIC_YIP_OVERHEAD)`.

**This is a genuine integration against the `quinn-proto` sans-IO API — read its docs + the Task-1 spike first.** Implement to this behavior:

1. **Endpoint setup.** Build a `quinn-proto::Endpoint` bound to the existing `sock`. **Server config:** a throwaway self-signed cert (`rcgen` or a hardcoded ephemeral cert) + ALPN `h3`; accept incoming connections. **Client config:** a rustls `ClientConfig` with a **dangerous accept-any-cert verifier** (`ServerCertVerifier` that returns `Ok`), ALPN `h3`, a plausible SNI (e.g. `www.cloudflare.com` — a real HTTP/3 domain). Reuse the exact `TransportConfig` the spike proved (CC/pacing off for datagrams, PMTUD on, generous datagram buffers).
2. **The epoll pump** (`run_quic`, mirroring `run_poll`'s structure but driving quinn-proto): register `sock` + `tun` in epoll; per wakeup —
   - **UDP readable:** `recvfrom` → `Endpoint::handle(now, remote, ..., data)` → routes to a `Connection` (or a new incoming one); drain the connection's events (`Connection::poll`) — for each `Event::DatagramReceived`, pull the datagram via `Connection::datagrams().recv()` → that's a **plain yip datagram** → `manager.on_udp(quic_peer_addr, &bytes, now_ms)` → wrap the returned egress (below).
   - **TUN readable:** read inner packet → `manager.on_tun(&pkt, now_ms)` → wrap egress.
   - **Egress:** for each `EgressDatagram` (plain yip bytes), `Connection::datagrams().send(Bytes, drop=false)` on the connection for that dst (**one datagram per send; do not coalesce** — if quinn-proto coalesces, set the max-datagram path so each rides its own packet, or accept quinn's packetization but keep 1 datagram/frame). Oversized (> `max_datagram_size`) ⇒ log + drop (telemetry), never truncate.
   - **Drain transmits:** loop `Connection::poll_transmit(now, max_datagrams, &mut buf)` / `Endpoint::poll_transmit` → `sock.send_to(&buf, dst)`.
   - **Timers:** epoll timeout = `min(Connection::poll_timeout(), yip_tick_deadline)`; on fire, `Connection::handle_timeout(now)` and `manager.tick(now_ms)` (drain its egress the same way).
3. **Connection ↔ peer.** A `Connection` is the transport to one peer endpoint; use the peer's `SocketAddr` as the `on_udp` source (so `PeerManager`'s existing source-based demux + inner Noise handshake identify the peer). For 3c.1's direct case, the client opens a connection to each configured peer endpoint; the server accepts.
4. **Symbol size.** After a connection reaches 1-RTT, compute `quic_symbol_size(conn.max_datagram_size())` and make it available to `PeerManager` (`set_data_symbol_size`) BEFORE the inner yip handshake creates the DataPlane, so FEC uses the QUIC-safe symbol size. (A startup conservative value is acceptable if per-connection threading is awkward — but never exceed the datagram budget.)

- [ ] **Step 1: Unit tests** (in `quic.rs`, no netns): (a) endpoint pair (client+server) drives a full QUIC handshake to 1-RTT via the sans-IO loop; (b) a yip-datagram-sized byte blob round-trips through a DATAGRAM frame (send on one side, `recv` on the other, bytes equal); (c) an oversized datagram (> max_datagram_size) is rejected (Err/None), not truncated; (d) `quic_symbol_size(1252) == 1200`, `quic_symbol_size(1000) == ~972` (min-with-1200 + overhead subtraction). Use loopback/in-memory sockets; drive the state machines synchronously.
- [ ] **Step 2: Run → fail; implement** points 1–4 using the spike's proven knobs.
- [ ] **Step 3: Gate — `cargo test -p yipd --bins`; clippy `-D warnings`; fmt.** Commit (`feat(yipd): quinn-proto QUIC pump + two-layer handshake (3c.1 crux)`).

---

### Task 5: startup transport selection (`tunnel.rs`)

**Files:**
- Modify: `bin/yipd/src/tunnel.rs` (~146-152)

Behavior: after building `sock` + `PeerManager` (unchanged), branch on `config.transport`:
- `Transport::RawUdp` (default) → today's exact path: `YIP_USE_URING` ? `run_uring` : `run_poll` (byte-identical, incl. the 3a `set_obf_psk` / 3b `set_cover_traffic_ms` calls).
- `Transport::Quic` → `run_quic(sock, tun_fd, &mut manager, …)`. Do NOT call `set_obf_psk`/`set_cover_traffic_ms` in QUIC mode (config validation already forbids them). Set the QUIC-mode `data_symbol_size` on the manager (from Task 4). **QUIC mode is poll-only** — ignore `YIP_USE_URING` (or log that it's not supported with QUIC in 3c.1).

- [ ] **Step 1: Wire it.** Thread `config.transport` into the selection. (Unit-testing the run-loop selection is impractical; the netns tests in Task 6 are the real gate. A small test can assert `Config::parse` yields the right `transport` and that a QUIC config doesn't also carry obf_psk.)
- [ ] **Step 2: Gate — `cargo build --workspace`; `cargo test -p yipd --bins`; clippy/fmt.** A quick obf-off `run_poll` sanity: the raw path still selected when `transport` absent. Commit (`feat(yipd): select run_quic vs run_poll/run_uring by config.transport (3c.1 task 5)`).

---

### Task 6: netns integration — QUIC connectivity + no-regression

**Files:**
- Create: `bin/yipd/tests/run-netns-quic.sh`
- Modify: `bin/yipd/tests/tunnel_netns.rs`, `.github/workflows/integration.yml`

- [ ] **Step 1: `run-netns-quic.sh`** (mirror `run-netns-tunnel.sh`): two `yipd` in netns, both configured with `transport=quic` (single-peer direct config, NO obf_psk). Complete the two-layer bring-up (QUIC handshake → inner yip Noise-IK → cert admission — or the 2a non-mesh handshake) and ping across the TUN. `set -euo pipefail`, cleanup trap, root-gated SKIP. Assert ping succeeds.
- [ ] **Step 2: loss variant** → `quic_ping_under_loss`: same, with `tc netem` ~10% loss on the underlay, asserting FEC recovers dropped DATAGRAM frames (ping still succeeds). (Mirror `run-netns-tunnel-loss.sh`.)
- [ ] **Step 3: Rust harness** — `quic_tunnel_ping` + `quic_ping_under_loss` in `tunnel_netns.rs` (root-gated SKIP; `bash run-netns-quic.sh <yipd>`). Poll driver (QUIC is poll-only).
- [ ] **Step 4: GATE (run yourself, sudo):** rebuild `--release -p yipd`. (a) `quic_tunnel_ping` + `quic_ping_under_loss` → ok. (b) **No-regression:** the 10 existing netns tests (raw/obf/junk) × 2 drivers → ok (transport unset ⇒ byte-identical). Report the matrix.
- [ ] **Step 5:** Add the two QUIC tests to `integration.yml` (poll driver). Commit (`test(yipd): netns QUIC-mimicry connectivity + no-regression (3c.1 task 6)`).

---

### Task 7: nDPI oracle FLIP + QUIC-vs-raw benchmark

**Files:**
- Create: `bin/yipd/tests/run-quic-mimicry-oracle.sh`, `tunnel_netns.rs` `quic_classified_as_quic`, `crates/yip-bench/…` benchmark; Modify `.github/workflows/integration.yml`

- [ ] **Step 1: `run-quic-mimicry-oracle.sh`** — mirror `run-ndpi-oracle.sh`: two `yipd` with `transport=quic` in netns on a neutral port; `tcpdump` the underlay during a handshake + data exchange; run `ndpiReader -i <pcap> -v 2`. **Assert: (a)** the flow is classified as **`QUIC`** (grep the protocol column for `QUIC`, positively — NOT `Unknown`), **(b) NO `NDPI_SUSPICIOUS_ENTROPY`** risk flag (the proof 3c beats the entropy heuristic — grep must find it ABSENT). Fail on either. Root-gated, cleanup trap. Read `ndpiReader.c`'s QUIC-classification + risk output format to get the exact grep targets.
- [ ] **Step 2: Rust harness** `quic_classified_as_quic` (root-gated SKIP + ndpiReader-absent SKIP; `bash run-quic-mimicry-oracle.sh <yipd> <ndpiReader>`).
- [ ] **Step 3: `yip-bench` QUIC-vs-raw benchmark** — extend the bench harness (a netns or loopback test) measuring tunnel **latency (RTT) + throughput** for `transport=quic` vs raw-UDP(+obf), so the double-encryption premium is **measured** (write to `RESULTS.md`). Honest framing (QUIC mode is an opt-in premium).
- [ ] **Step 4: CI + local run.** Add `quic_classified_as_quic` to the `dpi-undetectability` job (build ndpiReader already wired). Run the oracle + benchmark locally under sudo; report the ndpiReader classification verbatim (proving QUIC + no entropy) and the QUIC-vs-raw numbers. The `curl --http3` probe check stays a **local/manual** note (NOT a CI dependency). Commit (`test(ci): nDPI QUIC-classification oracle + QUIC-vs-raw benchmark (3c.1 task 7)`).

---

## Self-Review

**Spec coverage:** quinn-proto spike/de-risk → Task 1 ✅; symbol_size parameterization → Task 2 ✅; `transport` config + mutual exclusion → Task 3 ✅; the quic.rs pump + two-layer handshake + DATAGRAM frames + dynamic symbol_size → Task 4 ✅; startup transport selection → Task 5 ✅; netns QUIC connectivity + FEC-under-loss + no-regression → Task 6 ✅; nDPI oracle flip (QUIC + no entropy) + QUIC-vs-raw benchmark → Task 7 ✅. Non-goals (uTLS/fronting 3c.2, rendezvous 3c.3, uring/ports/abstraction) explicitly excluded. `transport` absent ⇒ byte-identical enforced by Task 5's default-path branch + Task 6's no-regression gate. FEC-preserved (DATAGRAM frames), north-star-untouched (raw path default), double-encryption/security invariants realized by the two-layer handshake in Task 4.

**Placeholder scan:** Tasks 2/3 carry concrete code/interfaces + tests; Tasks 1/4/6/7 are integration/exploration tasks specified by interface + behavior + the exact quinn-proto API calls + test lists (like the 2b/2c/3a/3b crux tasks). The genuinely open item — the exact `TransportConfig` knobs to bypass CC/pacing for datagrams — is deliberately resolved by the Task-1 spike FIRST and fed into Task 4, rather than guessed here (that's the whole point of the spike-first ordering).

**Type consistency:** `Transport::new(rules, symbol_size: u16)`, `DataPlane::new(..., symbol_size: u16)`, `PeerManager::set_data_symbol_size(u16)`, `Config.transport: Transport {RawUdp, Quic}`, `run_quic(...)`, `quic_symbol_size(max_datagram_size) -> u16` consistent across Tasks 2/3/4/5. The QUIC `data_symbol_size` = `min(1200, max_datagram_size − overhead)` throughout. Note: the config `Transport` enum (transport selection) is distinct from `yip_transport::Transport` (the FEC engine) — name the config enum to avoid the clash (e.g. `WireTransport` or module-qualify) — flagged for the implementer.
