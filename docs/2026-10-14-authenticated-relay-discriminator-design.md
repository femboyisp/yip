# Design Specification: Authenticated Discriminator for Relay Trojan Front (#64)

**Date:** 2026-10-14
**Status:** Approved
**Issue:** #64
**Scope:** Eliminating probabilistic false-upgrade vulnerabilities on the rendezvous TLS Trojan front by requiring cryptographically authenticated symmetric MACs (`Message::RegisterAuth`) in rootless mode and preserving signed registration verification in rooted mode.

---

## 1. Problem Statement & Threat Model

### 1.1 The Vulnerability
The 3c.3 relay's TLS Trojan front (`bin/yip-rendezvous/src/conn.rs`) inspects the first framed message received on a TLS connection to determine whether to upgrade the stream to a relay tunnel (`Classify::Upgrade`) or proxy it to the decoy web backend (`Classify::Decoy`).

When mesh membership roots are configured (`server.roots_cfg().is_some()`), the relay requires a signed registration record (`Message::RegisterSigned`), which verifies an Ed25519 signature and certificate chain against CA roots ($2^{-256}$ forgery resistance).

However, in rootless mode (`server.roots_cfg().is_none()`), clients and the relay share only `obf_psk`. Because `yip_obf` is an unauthenticated keystream XOR (SipHash-CTR), the classification of `Message::Register { node, counter }` currently reduces to structural heuristics:
- `ptype == RDV_TYPE` (8 bits: 1 in 256)
- `tag == Tag::Register` (8 bits: 1 in 256)
- `body_len >= 25` and bounded within the frame (~5 bits)

This leaves only $\approx 21$ effective bits of entropy. A blind prober (without `obf_psk`) sending random bytes over a completed TLS handshake lands a false upgrade with probability $p \approx 2^{-21}$. Upon a false upgrade, the relay writes an obfuscated rendezvous-shaped reply and enters tunnel mode instead of serving the decoy website, violating the core probe-resistance guarantee of the 3c.3 Trojan front.

### 1.2 Invariants & Goals
1. **Cryptographic Authentication ($2^{-144}$)**: A blind prober without `obf_psk` must face cryptographically negligible forgery odds ($< 2^{-128}$) on the Trojan front.
2. **Rejection of Unauthenticated Registrations**: Bare `Message::Register` frames without cryptographic proof of `obf_psk` must be rejected as `Classify::Decoy` on the TLS Trojan front.
3. **Zero Wire Regression on UDP**: UDP rendezvous registration on port 51821 must continue to function without breaking backward compatibility.
4. **Constant-Time Verification**: MAC checks must be constant-time to avoid timing side-channels.
5. **Memory & Concurrency Safety**: Strictly maintain `#![forbid(unsafe_code)]`.

---

## 2. Architecture & Detailed Design

### 2.1 Protocol Extension: `Message::RegisterAuth`
In `crates/yip-rendezvous/src/proto.rs`:

1. **Tag Definition**:
   ```rust
   #[repr(u8)]
   enum Tag {
       Register = 0,
       Lookup = 1,
       PeerInfo = 2,
       NotFound = 3,
       PunchHint = 4,
       RelaySend = 5,
       RelayDeliver = 6,
       RegisterSigned = 7,
       RegisterAuth = 8,
   }
   ```

2. **Message Variant**:
   ```rust
   pub enum Message {
       // ... existing variants ...
       RegisterAuth {
           node: NodeId,
           counter: u64,
           mac: [u8; 16],
       },
   }
   ```

3. **Wire Encoding (41 bytes)**:
   - `tag`: 1 byte (`0x08`)
   - `node`: 16 bytes (`NodeId`)
   - `counter`: 8 bytes (`u64` big-endian)
   - `mac`: 16 bytes (`[u8; 16]`)

4. **MAC Computation**:
   Using `blake2::Blake2sVar`:
   ```rust
   const DOMAIN_REG_AUTH: &[u8] = b"yip-rendezvous-v1-reg-auth";

   pub fn compute_register_mac(obf_key: &[u8; 16], node: &NodeId, counter: u64) -> [u8; 16] {
       let mut h = Blake2sVar::new(16).expect("16 is valid blake2s len");
       h.update(DOMAIN_REG_AUTH);
       h.update(obf_key);
       h.update(node);
       h.update(&counter.to_be_bytes());
       let mut out = [0u8; 16];
       h.finalize_variable(&mut out).expect("len matches");
       out
   }

   pub fn verify_register_mac(obf_key: &[u8; 16], node: &NodeId, counter: u64, mac: &[u8; 16]) -> bool {
       let expected = compute_register_mac(obf_key, node, counter);
       let mut diff = 0u8;
       for (a, b) in mac.iter().zip(expected.iter()) {
           diff |= a ^ b;
       }
       diff == 0
   }
   ```

### 2.2 Trojan-Front Discrimination (`bin/yip-rendezvous/src/conn.rs`)
In `classify_first_frame_at`:
1. Parse length prefix and deobfuscate `env` under `obf_key`.
2. Check `ptype == RDV_TYPE` and decode `Message`.
3. If `server.roots_cfg().is_some()` (rooted mode):
   - Require `Message::RegisterSigned { record }`.
   - Verify `server.verify_signed_record(&record, now_secs)`.
   - Verify `server.register_if_fresh_tls(record.node_id, record.seq, now_ms)`.
   - Upgrade with obfuscated `RegisterSigned` echo reply.
4. If `server.roots_cfg().is_none()` (rootless mode):
   - Require `Message::RegisterAuth { node, counter, mac }`.
   - Verify `verify_register_mac(obf_key, &node, counter, &mac)`. If MAC check fails: return `Classify::Decoy`.
   - Verify `server.register_if_fresh_tls(node, counter, now_ms)`. If stale: return `Classify::Decoy`.
   - Upgrade with obfuscated `RegisterAuth` echo reply.
5. Any other message (including bare `Message::Register`, bad MACs, or malformed bytes) returns `Classify::Decoy`.

### 2.3 Relay Client Generation (`bin/yipd/src/relay_client.rs`)
In `build_register(obf_key: &[u8; 16], node: NodeId, counter: u64) -> Vec<u8>`:
- Compute `mac = compute_register_mac(obf_key, &node, counter)`.
- Encode `Message::RegisterAuth { node, counter, mac }`.
- Wrap in `yip_obf::obfuscate(obf_key, yip_obf::RDV_TYPE, &plain, 0)`.
- Frame with length prefix via `frame_datagram`.

In `build_registration_frame`:
- If `signer.is_some()`: calls `build_register_signed` (rooted mode).
- If `signer.is_none()`: calls `build_register` with `RegisterAuth` (rootless mode).

### 2.4 Server Message Handling (`crates/yip-rendezvous/src/server.rs`)
In `RendezvousServer::handle`:
- Add handler for `Message::RegisterAuth { node, counter, mac }`:
  - Registers `(node, counter)` into `self.regs` with `REG_TTL_MS`.
  - Emits reply `vec![(src, Message::RegisterAuth { node, counter, mac })]`.
- Bare `Message::Register` continues to be handled for UDP backward compatibility.

---

## 3. Testing & Verification

1. **Unit Tests (`crates/yip-rendezvous`)**:
   - `test_compute_register_mac_kat`: Fixed vector deterministic test.
   - `test_verify_register_mac`: Validates acceptance on matching key/node/counter and rejection on any bit tampering or key mismatch.
   - `test_register_auth_roundtrip`: `encode` and `decode` roundtrip of `Message::RegisterAuth` (41 bytes).
   - `test_server_handle_register_auth`: `RendezvousServer::handle` populates registrations and generates proper reply.

2. **Trojan Front Tests (`bin/yip-rendezvous/src/conn.rs`)**:
   - `test_classify_rootless_register_auth_upgrades`: Valid `RegisterAuth` upgrades.
   - `test_classify_rootless_bare_register_is_decoy`: Bare `Register` without MAC classifies as `Decoy`.
   - `test_classify_rootless_bad_mac_is_decoy`: `RegisterAuth` with invalid MAC classifies as `Decoy`.
   - `test_classify_random_probe_resistance`: 10,000 random payload probes all classify as `Decoy`.
   - `test_classify_rootless_replay_is_decoy`: Stale/replayed counter classifies as `Decoy`.

3. **Relay Client Tests (`bin/yipd/src/relay_client.rs`)**:
   - `test_build_register_generates_valid_auth`: Verifies `build_register` output unmasks and validates as `RegisterAuth`.

4. **Integration & Regression Tests**:
   - `bin/yipd/tests/run-netns-relay-tls.sh`
   - `bin/yipd/tests/run-netns-reality-relay.sh`
   - Workspace verification: `cargo test --all`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, `cargo deny check`.
