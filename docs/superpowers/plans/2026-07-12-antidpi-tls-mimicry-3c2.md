# TLS Mimicry (3c.2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give yip a TLS-over-TCP-443 costume (`transport=tls`) that carries its unchanged inner protocol inside a real rustls TLS 1.3 connection with a browser-parrot ClientHello, so it survives UDP-blocked networks and classifies as ordinary browser HTTPS.

**Architecture:** Mirror 3c.1 (`bin/yipd/src/quic.rs`) with TLS-over-TCP instead of QUIC-over-UDP: a dedicated `run_tls` pump, a zero-auth outer TLS costume (browser-parrot ClientHello, configurable SNI, accept-any-cert), the unchanged inner yip protocol (Noise/FEC/AEAD via `PeerManager`) framed as `[u16 len][datagram]` over the TLS byte-stream, static-key role tiebreak, driven by the safe `yip_io::epoll::Epoll` primitive.

**Tech Stack:** Rust, `rustls` (already in-tree via quinn), `std::net::{TcpStream,TcpListener}`, `yip_io::epoll`. Possibly `boring` (BoringSSL) if Task 0 finds rustls can't parrot — a Task-0 decision.

## Global Constraints

- **Opt-in, default byte-identical:** `transport` absent (or `raw`/`udp`) ⇒ no TLS, no TCP listener, no new bytes; merged raw/3a/3b/3c.1 behavior untouched.
- **Inner protocol UNCHANGED:** Noise-IK, cert admission, FEC, AEAD, anti-hijack, rekey are the raw-path logic verbatim. 3c.2 is transport only.
- **`transport=tls` is mutually exclusive with `obf_psk`/`cover_traffic_ms`** (enforced at config load with a clear error, mirroring `quic`).
- **`#![forbid(unsafe_code)]` holds in `yipd`;** all `unsafe` stays in `yip-io`/deps (rustls, TCP sockets, epoll primitive). No `as` numeric casts except discriminants/libc-ABI. No bare `#[allow]` — `#[expect(reason = "...")]` only.
- **Fail-closed:** malformed/oversized frame or TLS error tears the connection down without touching session/admission state or panicking; the inner Noise session re-handshakes on reconnect.
- **A real handshake:** a real rustls TLS 1.3 handshake with a browser-parrot ClientHello — never a hand-rolled fake TLS record layer.
- **Spike gate (Task 0) is binding:** if no JA3/JA4-clean browser parrot is achievable within these constraints, STOP — do not implement Tasks 1–7.
- **`refrences/` is read-only.**

---

### Task 0: Feasibility spike — a JA3/JA4-clean browser ClientHello in Rust (throwaway, hard gate)

**Purpose:** The one genuinely risky piece. rustls does not parrot browsers — its default ClientHello has a distinctive JA3/JA4. Prove we can emit a **current Chrome/Firefox** JA3/JA4 within yip's constraints, or stop. This also decides the dependency (rustls-coaxed vs `boring`).

**Files:** throwaway, in the scratchpad (NOT under `bin/`/`crates/`).

- [ ] **Step 1: Stand up a minimal TLS-over-TCP client + capture its ClientHello**

A throwaway program (or a `#[test]` behind a scratch feature) that opens a rustls TLS 1.3 client connection to a local TLS server (or a real `www.apple.com:443`) and captures the raw ClientHello bytes (tcpdump/pcap, or a local server that dumps the first record). Compute its JA3/JA4 (use the nDPI oracle machinery in `bin/yipd/tests/run-ndpi-oracle.sh`, which already builds JA3/JA4).

- [ ] **Step 2: Attempt a browser parrot with rustls**

Try to coax rustls toward a Chrome/Firefox JA3/JA4: cipher-suite order, the ALPN set (`h2`,`http/1.1`), signature-algorithm list, supported-groups/key-share order, extension presence/order, GREASE values. Record how close the JA3/JA4 gets to a current Chrome/Firefox reference (pull a reference JA3 from a public browser-fingerprint list or a real Chrome capture).

- [ ] **Step 3: If rustls can't reach a clean parrot, evaluate `boring`**

`boring` (Cloudflare's BoringSSL bindings) supports explicit cipher/extension configuration used by uTLS-style impersonation. Spike a minimal `boring` client ClientHello and compare its JA3/JA4 to Chrome. Note the dependency cost (compiles BoringSSL C; its `unsafe` is inside the crate, acceptable like `ring`/quinn — but it is a heavy pinned dep).

- [ ] **Step 4: Record the decision + the parrot recipe**

Append a "3c.2 TLS-parrot spike" section to `crates/yip-bench/RESULTS.md` (committed; the spike code is not): the chosen mechanism (rustls-coaxed **or** `boring`), the exact parrot target (e.g. Chrome N stable), the achieved JA3/JA4 vs the reference, and the resulting `Cargo.toml` dependency decision. State the verdict:
- a JA3/JA4 that matches (or is within a browser's natural variance of) a current browser → **proceed to Task 1** with the recorded mechanism.
- neither rustls nor boring yields a clean browser parrot within constraints → **STOP and report**; do not build Tasks 1–7.

- [ ] **Step 5: Commit the recorded decision**

```bash
git add crates/yip-bench/RESULTS.md
git commit -m "spike(antidpi-3c2): TLS browser-parrot ClientHello feasibility — gate + rustls-vs-boring decision"
```

---

### Task 1: Config — `transport=tls`, `tls_sni`, obf_psk mutual-exclusion

**Files:**
- Modify: `bin/yipd/src/config.rs` (`TransportMode` enum, the `transport=` parse, a `tls_sni` field + parse, the `obf_psk` mutual-exclusion validation)

**Interfaces:**
- Produces: `TransportMode::Tls` variant; `Config.tls_sni: String` (a sane default when absent); a load-time `Err` when `transport=tls` is combined with `obf_psk` or `cover_traffic_ms`.

- [ ] **Step 1: Write the failing config tests**

Add to `config.rs`'s test module. `parse_config` (or the crate's existing parse entry — match the actual name) is the unit under test:

```rust
    #[test]
    fn transport_tls_parses_with_sni() {
        let cfg = parse_config_str(
            "local_private=<64hex>\nlocal_public=<64hex>\ntransport=tls\ntls_sni=www.apple.com\n"
        ).expect("parse");
        assert_eq!(cfg.transport, TransportMode::Tls);
        assert_eq!(cfg.tls_sni, "www.apple.com");
    }

    #[test]
    fn transport_tls_default_sni_when_absent() {
        let cfg = parse_config_str(
            "local_private=<64hex>\nlocal_public=<64hex>\ntransport=tls\n"
        ).expect("parse");
        assert_eq!(cfg.transport, TransportMode::Tls);
        assert_eq!(cfg.tls_sni, DEFAULT_TLS_SNI);
    }

    #[test]
    fn transport_tls_rejects_obf_psk() {
        let err = parse_config_str(
            "local_private=<64hex>\nlocal_public=<64hex>\ntransport=tls\nobf_psk=<64hex>\n"
        ).unwrap_err();
        assert!(err.to_string().contains("transport=tls") && err.to_string().contains("obf_psk"));
    }
```

*(Use the exact test-helper name the file already uses to build a `Config` from a string; replace `<64hex>` with the valid keys the existing tests use.)*

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --lib config::` (or the module path the tests live in)
Expected: FAIL — `TransportMode::Tls` / `tls_sni` / `DEFAULT_TLS_SNI` not found.

- [ ] **Step 3: Implement the config additions**

- Add `Tls` to the enum:

```rust
pub enum TransportMode {
    RawUdp,
    Quic,
    Tls,
}
```

- Add near the `TransportMode` docs: `pub const DEFAULT_TLS_SNI: &str = "www.apple.com";`
- Add to `Config`: `pub tls_sni: String,`
- In the transport parse, accept `"tls"` → `TransportMode::Tls`; keep `quic`/`raw`/`udp`.
- Parse `tls_sni=<domain>` into `Config.tls_sni`, defaulting to `DEFAULT_TLS_SNI.to_owned()` when absent.
- Extend the existing `obf_psk`-vs-`quic` mutual-exclusion check so `transport == Tls` with `obf_psk.is_some()` (or `cover_traffic_ms.is_some()`) returns `Err(io::Error::new(io::ErrorKind::InvalidData, "transport=tls is mutually exclusive with obf_psk/cover_traffic_ms"))`. (Mirror the exact existing `quic` check — find it and add the `Tls` arm.)

- [ ] **Step 4: Run tests + clippy**

Run: `cargo test -p yipd --lib config:: && cargo clippy -p yipd --all-targets -- -D warnings`
Expected: PASS, clean.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/config.rs
git commit -m "feat(yipd): transport=tls config + tls_sni + obf_psk mutual-exclusion (3c.2)"
```

---

### Task 2: TLS-stream datagram framing

**Files:**
- Create: `bin/yipd/src/tls.rs` (start it with just the framing + tests; the pump is Task 3)
- Modify: `bin/yipd/src/main.rs` (add `mod tls;`)

**Interfaces:**
- Produces:
  - `pub(crate) const TLS_FRAME_MAX: usize` = `yip_io::MAX_WIRE_DATAGRAM` (the max datagram body).
  - `pub(crate) fn frame_datagram(dg: &[u8], out: &mut Vec<u8>) -> io::Result<()>` — append `[u16 BE len][dg]` to `out`; `Err` if `dg.len() > TLS_FRAME_MAX`.
  - `pub(crate) struct FrameReader { buf: Vec<u8> }` with `push(&mut self, bytes: &[u8])` (append decrypted TLS plaintext) and `next(&mut self) -> Result<Option<Vec<u8>>, io::Error>` — pop one complete datagram, `Ok(None)` if incomplete, `Err` (fail-closed) on a zero or `> TLS_FRAME_MAX` length prefix.

- [ ] **Step 1: Write the failing framing tests**

Create `bin/yipd/src/tls.rs`:

```rust
//! TLS-mimicry transport (3c.2): a rustls TLS-over-TCP costume carrying yip's
//! UNCHANGED inner protocol (Noise-IK / FEC / AEAD via `PeerManager`), framed as
//! length-prefixed datagrams over the TLS byte-stream. Mirrors `quic.rs` (3c.1).

use std::io;

pub(crate) const TLS_FRAME_MAX: usize = yip_io::MAX_WIRE_DATAGRAM;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_single() {
        let dg = b"hello yip";
        let mut wire = Vec::new();
        frame_datagram(dg, &mut wire).unwrap();
        let mut r = FrameReader::default();
        r.push(&wire);
        assert_eq!(r.next().unwrap().unwrap(), dg);
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn frame_reassembles_across_partial_reads() {
        let dg = vec![0xABu8; 1200];
        let mut wire = Vec::new();
        frame_datagram(&dg, &mut wire).unwrap();
        let mut r = FrameReader::default();
        // deliver the wire in three arbitrary chunks
        r.push(&wire[..1]);
        assert!(r.next().unwrap().is_none());
        r.push(&wire[1..700]);
        assert!(r.next().unwrap().is_none());
        r.push(&wire[700..]);
        assert_eq!(r.next().unwrap().unwrap(), dg);
    }

    #[test]
    fn frame_two_back_to_back() {
        let (a, b) = (b"aaa".as_slice(), b"bbbb".as_slice());
        let mut wire = Vec::new();
        frame_datagram(a, &mut wire).unwrap();
        frame_datagram(b, &mut wire).unwrap();
        let mut r = FrameReader::default();
        r.push(&wire);
        assert_eq!(r.next().unwrap().unwrap(), a);
        assert_eq!(r.next().unwrap().unwrap(), b);
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn frame_oversize_body_errs_on_write() {
        let big = vec![0u8; TLS_FRAME_MAX + 1];
        assert!(frame_datagram(&big, &mut Vec::new()).is_err());
    }

    #[test]
    fn reader_rejects_zero_and_oversize_len() {
        let mut r = FrameReader::default();
        r.push(&[0u8, 0]); // len 0
        assert!(r.next().is_err());
        let mut r2 = FrameReader::default();
        let bad = u16::try_from(TLS_FRAME_MAX).unwrap().wrapping_add(1);
        // only valid if TLS_FRAME_MAX < u16::MAX; if TLS_FRAME_MAX >= 65535 this
        // arm is unreachable — assert the max instead. Guard accordingly.
        if usize::from(bad) > TLS_FRAME_MAX && bad != 0 {
            r2.push(&bad.to_be_bytes());
            assert!(r2.next().is_err());
        }
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --lib tls::`
Expected: FAIL — `frame_datagram`/`FrameReader` not found.

- [ ] **Step 3: Implement the framing**

Add to `tls.rs` (above the tests):

```rust
/// Append `[u16 BE length][dg]` to `out`. Errors if `dg` exceeds `TLS_FRAME_MAX`.
pub(crate) fn frame_datagram(dg: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    let len = u16::try_from(dg.len())
        .ok()
        .filter(|_| dg.len() <= TLS_FRAME_MAX)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "datagram too large for TLS frame"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(dg);
    Ok(())
}

/// Reassembles length-prefixed datagrams from a TLS plaintext byte-stream.
#[derive(Default)]
pub(crate) struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// Append freshly-decrypted TLS plaintext.
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Pop one complete datagram; `Ok(None)` if incomplete. Fail-closed on a zero
    /// or `> TLS_FRAME_MAX` length prefix (a hostile/corrupt peer).
    pub(crate) fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.buf.len() < 2 {
            return Ok(None);
        }
        let len = usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]]));
        if len == 0 || len > TLS_FRAME_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad TLS frame length"));
        }
        if self.buf.len() < 2 + len {
            return Ok(None);
        }
        let dg = self.buf[2..2 + len].to_vec();
        self.buf.drain(..2 + len);
        Ok(Some(dg))
    }
}
```

*(Note: if `MAX_WIRE_DATAGRAM ≥ 65535` the `frame_datagram` `u16` cap and the reader's `> TLS_FRAME_MAX` check still hold; the oversize-len test guards for that case.)*

- [ ] **Step 4: Run tests + clippy**

Run: `cargo test -p yipd --lib tls:: && cargo clippy -p yipd --all-targets -- -D warnings`
Expected: PASS, clean. (`frame_datagram`/`FrameReader` are unused by non-test code until Task 3 — add `#[cfg_attr(not(test), expect(dead_code, reason = "used by run_tls in Task 3"))]` if clippy flags them; verify both `--lib` and `--all-targets` clean.)

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/tls.rs bin/yipd/src/main.rs
git commit -m "feat(yipd): length-prefix datagram framing for the TLS transport (3c.2)"
```

---

### Task 3: The `run_tls` pump

**Files:**
- Modify: `bin/yipd/src/tls.rs` (add the rustls costume config + the `run_tls` pump), `bin/yipd/Cargo.toml` (ensure `rustls` is a direct dep — or add `boring` per Task 0)

**Interfaces:**
- Consumes: `frame_datagram`/`FrameReader` (Task 2); `PeerManager` (`on_udp`/`on_tun`/`tick` — the same `Dispatch`-shaped methods `run_quic` calls); `yip_io::epoll::Epoll`; the Task-0 ClientHello mechanism.
- Produces: `pub(crate) fn run_tls(tun_fd: RawFd, manager: &mut PeerManager, local_public: [u8; 32], peers: &[([u8; 32], SocketAddr)], tls_sni: &str) -> io::Result<()>`.

**This task mirrors `bin/yipd/src/quic.rs` (`run_quic`) closely** — read it first. The differences are: TCP sockets instead of a UDP `Endpoint`; rustls TLS streams instead of quinn connections; the Task-2 length framing instead of QUIC DATAGRAM frames; a browser-parrot ClientHello (Task 0) instead of quinn's default. The exact rustls-vs-boring client config comes from **Task 0's recorded decision** — use that mechanism here; the structure below is dependency-agnostic.

- [ ] **Step 1: Add the zero-auth costume config**

Mirror `quic.rs`'s `SkipServerVerification` (accept-any-cert) — it already exists in `quic.rs`; either reuse it (make it `pub(crate)` there) or add an equivalent in `tls.rs`. Add:
- a rustls (or boring) **client config** producing the Task-0 browser-parrot ClientHello, with `ServerName = tls_sni`, the accept-any-cert verifier, and ALPN matching a browser (`h2`, `http/1.1`);
- a rustls **server config** with a throwaway self-signed cert for `tls_sni` (generate at startup, like `run_quic` does its self-signed cert — reuse that helper if present).

Show the full config constructors. If Task 0 chose `boring`, use `boring`'s client builder for the parrot and keep rustls only if still needed; document which in the module header.

- [ ] **Step 2: Implement the role tiebreak + connect/accept**

Mirror `run_quic`'s static-key role decision: for each `(peer_public, endpoint)` in `peers`, `local_public.cmp(&peer_public)`:
- `Ordering::Less` → **client**: `TcpStream::connect(endpoint)`, set non-blocking, run the TLS client handshake (parrot ClientHello).
- `Ordering::Greater` → **server**: bind a `TcpListener` on the local TLS port, `accept()` connections, run the TLS server handshake.
- `Ordering::Equal` → impossible (distinct keys); return an error.

- [ ] **Step 3: Implement the pump loop**

Drive the TCP fd(s) + TUN fd with `yip_io::epoll::Epoll` (the same safe primitive `run_quic` uses — all `unsafe` stays in `yip-io`). Per iteration (mirror `run_quic`'s pump ordering):
1. `epoll_wait` (timeout `min(next tick, 10 ms)`).
2. TCP readable → read into a scratch buf → feed rustls (`read_tls`/`process_new_packets`) → drain decrypted plaintext into the peer's `FrameReader` → for each `reader.next()?` datagram → `manager.on_udp(peer_src, &dg, now_ms)` → frame each returned egress datagram with `frame_datagram` into the TLS writer → `write_tls` → flush TCP.
3. TUN readable → read inner packet → `manager.on_tun(inner, now_ms)` → frame + write to the TLS stream the same way.
4. On cadence, `manager.tick(now_ms)` → frame + write its egress.
5. TLS/TCP error or `reader.next()` `Err` → drop the connection (fail-closed); the **client** re-dials with backoff (100 ms → cap ~5 s); the **server** goes back to `accept()`. The inner Noise session re-handshakes naturally on reconnect.

Show the complete `run_tls` body. Keep it structured like `run_quic`; where `run_quic` calls quinn APIs, call the TCP+rustls equivalents. `yipd` stays `#![forbid(unsafe_code)]` — all `unsafe` is inside `yip-io`/rustls/boring.

- [ ] **Step 4: Build + clippy**

Run: `cargo build -p yipd && cargo clippy -p yipd --all-targets -- -D warnings`
Expected: builds, clean.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/tls.rs bin/yipd/Cargo.toml
git commit -m "feat(yipd): run_tls pump — rustls TLS-over-TCP costume carrying inner yip (3c.2)"
```

---

### Task 4: Wire `transport=tls` into the run-loop

**Files:**
- Modify: `bin/yipd/src/tunnel.rs` (dispatch `TransportMode::Tls` → `run_tls`, next to the `Quic` branch)

- [ ] **Step 1: Add the dispatch branch**

Immediately after the existing `if config.transport == TransportMode::Quic { … return run_quic(…); }` block (tunnel.rs:160), add:

```rust
    if config.transport == crate::config::TransportMode::Tls {
        let tls_peers: Vec<([u8; 32], std::net::SocketAddr)> = config
            .peers
            .iter()
            .filter_map(|p| p.endpoint.map(|ep| (p.public_key, ep)))
            .collect();
        return crate::tls::run_tls(
            tun_fd,
            &mut manager,
            config.local_public,
            &tls_peers,
            &config.tls_sni,
        );
    }
```

*(The TLS path does not use the UDP `sock`; it opens its own TCP sockets. If `sock` is bound earlier and now unused on this path, that is fine — the raw/quic paths still use it. Match the surrounding code's variable names.)*

- [ ] **Step 2: Build + a smoke run**

Run: `cargo build --release -p yipd`
Expected: builds. (Behavioral verification is the netns test in Task 6.)

- [ ] **Step 3: Commit**

```bash
git add bin/yipd/src/tunnel.rs
git commit -m "feat(yipd): dispatch transport=tls to run_tls (3c.2)"
```

---

### Task 5: Docs — config reference + example

**Files:**
- Modify: `docs/configuration.md`, `example.config`, `CHANGELOG.md`

- [ ] **Step 1: Document `transport=tls` + `tls_sni`**

In `docs/configuration.md`, alongside the existing `transport=quic` entry, document `transport=tls` (the TLS-over-TCP-443 costume: opt-in last-resort for UDP-blocked networks, mutually exclusive with `obf_psk`, connects to configured `peer_endpoint`/relay, slower than raw/QUIC — TCP HoL, no FEC benefit) and `tls_sni=<domain>` (default `www.apple.com`). In `example.config`, add a commented `# transport=tls` / `# tls_sni=www.apple.com` stanza next to the QUIC one.

- [ ] **Step 2: CHANGELOG entry**

Add an `### Added` (or `### Changed`) entry: "TLS-over-TCP mimicry transport (`transport=tls`, anti-DPI 3c.2): carries the unchanged inner yip protocol inside a real rustls TLS 1.3 connection with a browser-parrot ClientHello, so yip survives UDP-blocked networks and classifies as browser HTTPS. Opt-in last-resort path (TCP; no FEC benefit); mutually exclusive with `obf_psk`; default raw-UDP unchanged."

- [ ] **Step 3: Commit**

```bash
git add docs/configuration.md example.config CHANGELOG.md
git commit -m "docs(yipd): document transport=tls / tls_sni (3c.2)"
```

---

### Task 6: netns money-test + nDPI oracle arm

**Files:**
- Create: `bin/yipd/tests/run-netns-tls.sh` (or add a `transport=tls` case to the existing netns tunnel harness, matching how the QUIC netns test is structured — find it first)
- Modify: `bin/yipd/tests/run-ndpi-oracle.sh` (add a `transport=tls` arm), and the `tunnel_netns.rs` harness if the shell scripts are driven from it

- [ ] **Step 1: netns connectivity money-test**

Following the existing QUIC netns test's structure (search for the 3c.1 QUIC netns test — e.g. a `transport=quic` case in `tunnel_netns.rs` / a `run-netns-*quic*.sh`), add a `transport=tls` case: two `yipd` in separate netns with `transport=tls` and configured `peer_endpoint`s (direct-reachable, no NAT), complete the Noise handshake, **ping across the TLS-TCP tunnel**, push a bulk transfer and diff a known payload (data-intact), and verify a forced TCP teardown reconnects. Run under both drivers if the harness parameterizes the driver (the inner path is driver-agnostic; the TLS pump is its own loop, so one run may suffice — match the QUIC test's driver coverage).

- [ ] **Step 2: nDPI oracle arm (hard gate)**

Add a `transport=tls` arm to `run-ndpi-oracle.sh` alongside raw/obf/quic: capture the TLS handshake, run it through `ndpiReader`, assert it classifies as **TLS/HTTPS** with the browser JA3/JA4 (from Task 0) and the configured SNI — **not** VPN, **not** `NDPI_OBFUSCATED_TRAFFIC`. This is the milestone's success criterion.

- [ ] **Step 3: Run both**

Run (root/netns): the new netns TLS test and `run-ndpi-oracle.sh` (TLS arm).
Expected: handshake+ping+bulk PASS; nDPI classifies TLS with browser JA3/JA4 + SNI.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/tests/
git commit -m "test(yipd): netns TLS connectivity + nDPI TLS-classification oracle (3c.2)"
```

---

### Task 7: No-regression

**Files:** none expected (verification; fix in place if a regression appears).

- [ ] **Step 1: Full workspace tests** — `cargo test --workspace` → 0 failures.
- [ ] **Step 2: clippy** — `cargo clippy --workspace --all-targets -- -D warnings` → clean.
- [ ] **Step 3: `transport` absent = byte-identical** — the existing netns suite (raw + obf + QUIC, both drivers) stays green: `transport=tls` is purely additive. Build the `tunnel_netns` binary and run the core cases (`ping_across_yipd_tunnel`, `..._under_loss`, `arq_recovers_bulk_loss`) under both drivers.
- [ ] **Step 4: Commit** any regression fix (else skip).

---

## Notes for the executor

- **Task 0 is a hard gate.** If no JA3/JA4-clean browser parrot is achievable, STOP after Task 0 and report — the whole milestone rests on the costume being convincing.
- **Mirror `quic.rs`.** `run_tls` is the TCP/TLS sibling of `run_quic`; read that module first and follow its structure (role tiebreak, epoll pump, self-signed cert, accept-any-cert verifier, tick cadence). The novel pieces are only: TCP sockets, the length-prefix framing (Task 2), reconnect-with-backoff, and the browser-parrot ClientHello (Task 0).
- **Inner protocol is untouched.** Do not modify `PeerManager`, Noise, FEC, AEAD, or `yip-wire`. 3c.2 is transport only.
- **`unsafe` stays out of `yipd`.** rustls/boring/TCP/epoll keep it in dependencies / `yip-io`. No `as` casts (use `try_from`); no bare `#[allow]`.
- **The dependency (rustls-coaxed vs `boring`) is Task 0's call** — Task 3's config code uses whatever Task 0 recorded; keep the pump structure the same either way.
