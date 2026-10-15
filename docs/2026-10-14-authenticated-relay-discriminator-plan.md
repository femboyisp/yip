# Authenticated Discriminator for Relay Trojan Front Implementation Plan (#64)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate probabilistic false-upgrade vulnerabilities on the rendezvous TLS Trojan front by requiring cryptographically authenticated symmetric MACs (`Message::RegisterAuth`) in rootless mode and preserving signed registration verification in rooted mode.

**Architecture:** Extend `yip-rendezvous` wire protocol with `Message::RegisterAuth` containing a 128-bit constant-time BLAKE2s-MAC. The relay Trojan discriminator enforces verified `RegisterAuth` in rootless mode, rejecting unauthenticated bare `Register` frames as decoy traffic. `yipd` relay clients emit `RegisterAuth` in rootless mode.

**Tech Stack:** Rust (edition 2021), `blake2`, `yip-obf`, `yip-rendezvous`, `yipd`, tokio.

## Global Constraints
- Zero wire format regressions on direct UDP rendezvous (`Message::Register` continues to be handled for UDP).
- Strictly `#![forbid(unsafe_code)]` preserved across all crates.
- Constant-time verification for `verify_register_mac` to prevent timing side channels.
- Codebase standards: `cargo test --all` passes, `cargo clippy --all-targets -- -D warnings` clean, `cargo fmt --check` clean, `cargo deny check` clean.

---

### Task 1: Protocol & MAC Primitives in `crates/yip-rendezvous`

**Files:**
- Modify: `crates/yip-rendezvous/src/proto.rs`
- Modify: `crates/yip-rendezvous/src/server.rs`
- Modify: `crates/yip-rendezvous/src/lib.rs`

**Interfaces:**
- Produces:
  - `yip_rendezvous::compute_register_mac(obf_key: &[u8; 16], node: &NodeId, counter: u64) -> [u8; 16]`
  - `yip_rendezvous::verify_register_mac(obf_key: &[u8; 16], node: &NodeId, counter: u64, mac: &[u8; 16]) -> bool`
  - `yip_rendezvous::Message::RegisterAuth { node: NodeId, counter: u64, mac: [u8; 16] }`
  - `encode(&Message::RegisterAuth, &mut out)` (tag `8`, 41 bytes total)
  - `decode(buf)` parses `Tag::RegisterAuth` (tag `8`) into `Message::RegisterAuth`

- [ ] **Step 1: Write unit tests in `crates/yip-rendezvous/src/proto.rs`**

Add tests for `compute_register_mac`, `verify_register_mac`, and `Message::RegisterAuth` encoding/decoding:
```rust
#[test]
fn test_compute_register_mac_kat_and_verify() {
    let key = [0x42u8; 16];
    let node = node_id(&[0x11u8; 32]);
    let counter = 12345u64;
    let mac = compute_register_mac(&key, &node, counter);
    assert_ne!(mac, [0u8; 16]);
    assert!(verify_register_mac(&key, &node, counter, &mac));

    // Tampered key
    let bad_key = [0x43u8; 16];
    assert!(!verify_register_mac(&bad_key, &node, counter, &mac));

    // Tampered node
    let bad_node = node_id(&[0x22u8; 32]);
    assert!(!verify_register_mac(&key, &bad_node, counter, &mac));

    // Tampered counter
    assert!(!verify_register_mac(&key, &node, counter + 1, &mac));

    // Tampered mac byte
    let mut bad_mac = mac;
    bad_mac[0] ^= 1;
    assert!(!verify_register_mac(&key, &node, counter, &bad_mac));
}

#[test]
fn test_register_auth_encode_decode_roundtrip() {
    let node = node_id(&[0x55u8; 32]);
    let counter = 9999u64;
    let mac = [0x77u8; 16];
    let msg = Message::RegisterAuth { node, counter, mac };
    let mut buf = Vec::new();
    encode(&msg, &mut buf);
    assert_eq!(buf.len(), 1 + 16 + 8 + 16);
    assert_eq!(buf[0], 8);
    let decoded = decode(&buf).expect("decodes RegisterAuth");
    assert_eq!(decoded, msg);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-rendezvous test_compute_register_mac_kat`
Expected: FAIL (types / functions not defined).

- [ ] **Step 3: Implement `RegisterAuth` and MAC functions in `crates/yip-rendezvous`**

In `crates/yip-rendezvous/src/proto.rs`:
```rust
const DOMAIN_REG_AUTH: &[u8] = b"yip-rendezvous-v1-reg-auth";

pub fn compute_register_mac(obf_key: &[u8; 16], node: &NodeId, counter: u64) -> [u8; 16] {
    let mut h = Blake2sVar::new(16).expect("16 is a valid blake2s output len");
    h.update(DOMAIN_REG_AUTH);
    h.update(obf_key);
    h.update(node);
    h.update(&counter.to_be_bytes());
    let mut out = [0u8; 16];
    h.finalize_variable(&mut out).expect("len matches");
    out
}

pub fn verify_register_mac(
    obf_key: &[u8; 16],
    node: &NodeId,
    counter: u64,
    mac: &[u8; 16],
) -> bool {
    let expected = compute_register_mac(obf_key, node, counter);
    let mut diff = 0u8;
    for (a, b) in mac.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
```

Update `Tag` enum:
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

Update `Message` enum:
```rust
pub enum Message {
    // ...
    RegisterAuth {
        node: NodeId,
        counter: u64,
        mac: [u8; 16],
    },
}
```

Update `encode`:
```rust
        Message::RegisterAuth { node, counter, mac } => {
            out.push(Tag::RegisterAuth as u8);
            out.extend_from_slice(node);
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(mac);
        }
```

Update `decode`:
```rust
        t if t == Tag::RegisterAuth as u8 => {
            let node = node16(rest)?;
            let counter = u64::from_be_bytes(rest.get(16..24)?.try_into().ok()?);
            let mac: [u8; 16] = rest.get(24..40)?.try_into().ok()?;
            Some(Message::RegisterAuth { node, counter, mac })
        }
```

In `crates/yip-rendezvous/src/server.rs`:
In `handle`:
```rust
        Message::RegisterAuth { node, counter, mac } => {
            self.regs.insert(
                node,
                Registration {
                    addr: src,
                    counter,
                    record: None,
                    expiry_ms: now_ms.saturating_add(REG_TTL_MS),
                },
            );
            vec![(src, Message::RegisterAuth { node, counter, mac })]
        }
```

In `crates/yip-rendezvous/src/lib.rs`:
Export `compute_register_mac` and `verify_register_mac`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yip-rendezvous`
Expected: PASS (all tests pass).

- [ ] **Step 5: Commit**

```bash
git add crates/yip-rendezvous/src/
git commit -m "feat(rendezvous): add Message::RegisterAuth and constant-time BLAKE2s MAC (#64)"
```

---

### Task 2: Enforce Authenticated Discrimination in `bin/yip-rendezvous/src/conn.rs`

**Files:**
- Modify: `bin/yip-rendezvous/src/conn.rs`

**Interfaces:**
- Consumes:
  - `yip_rendezvous::{compute_register_mac, verify_register_mac, Message::RegisterAuth}`
- Produces:
  - `classify_first_frame_at`: strictly requires `RegisterAuth` in rootless mode, rejecting bare `Register` and invalid MACs as `Classify::Decoy`.

- [ ] **Step 1: Write failing tests in `bin/yip-rendezvous/src/conn.rs`**

Add tests asserting:
1. Valid `RegisterAuth` produces `Classify::Upgrade`.
2. Bare `Message::Register` in rootless mode produces `Classify::Decoy`.
3. `RegisterAuth` with an invalid/tampered MAC produces `Classify::Decoy`.
4. Stale/replayed counter produces `Classify::Decoy`.
5. 10,000 random probe frames produce `Classify::Decoy`.

```rust
#[test]
fn rootless_valid_register_auth_upgrades() {
    let key = yip_obf::derive_key(b"test-obf-psk");
    let node = node_id(&[1u8; 32]);
    let counter = 100u64;
    let mac = yip_rendezvous::compute_register_mac(&key, &node, counter);
    let mut s = RendezvousServer::new(0);

    let frame = crate::frame_obf(&key, &Message::RegisterAuth { node, counter, mac });
    let class = classify_first_frame_at(&frame, &key, &mut s, 1000, 1000);
    assert!(matches!(class, Classify::Upgrade { node: n, .. } if n == node));
}

#[test]
fn rootless_bare_register_is_decoy() {
    let key = yip_obf::derive_key(b"test-obf-psk");
    let node = node_id(&[1u8; 32]);
    let mut s = RendezvousServer::new(0);

    // An unauthenticated bare Register must be rejected as Decoy in rootless mode (#64)
    let frame = crate::frame_obf(&key, &Message::Register { node, counter: 1 });
    let class = classify_first_frame_at(&frame, &key, &mut s, 1000, 1000);
    assert!(matches!(class, Classify::Decoy));
}

#[test]
fn rootless_bad_mac_register_auth_is_decoy() {
    let key = yip_obf::derive_key(b"test-obf-psk");
    let node = node_id(&[1u8; 32]);
    let counter = 100u64;
    let bad_mac = [0xffu8; 16];
    let mut s = RendezvousServer::new(0);

    let frame = crate::frame_obf(&key, &Message::RegisterAuth { node, counter, mac: bad_mac });
    let class = classify_first_frame_at(&frame, &key, &mut s, 1000, 1000);
    assert!(matches!(class, Classify::Decoy));
}

#[test]
fn rootless_random_probe_resistance() {
    let key = yip_obf::derive_key(b"test-obf-psk");
    let mut s = RendezvousServer::new(0);
    let mut rng = yip_obf::XorShift64::from_getrandom();

    for _ in 0..10_000 {
        let len = (rng.next_u64() % 200 + 10) as usize;
        let mut probe = vec![0u8; len];
        for b in &mut probe {
            *b = rng.next_u64() as u8;
        }
        let class = classify_first_frame_at(&probe, &key, &mut s, 1000, 1000);
        assert!(matches!(class, Classify::Decoy));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-rendezvous-bin rootless_bare_register_is_decoy`
Expected: FAIL (`bare_register` currently returns `Upgrade`).

- [ ] **Step 3: Update `classify_first_frame_at` in `bin/yip-rendezvous/src/conn.rs`**

Replace lines 94-105 with:
```rust
    } else {
        // Rootless mode: require verified RegisterAuth with valid MAC.
        // Bare Register is intentionally rejected as Decoy (#64).
        let Message::RegisterAuth { node, counter, mac } = msg else {
            return Classify::Decoy;
        };
        if !yip_rendezvous::verify_register_mac(obf_key, &node, counter, &mac) {
            return Classify::Decoy;
        }
        if !server.register_if_fresh_tls(node, counter, now_ms) {
            return Classify::Decoy;
        }
        let reply = crate::frame_obf(obf_key, &Message::RegisterAuth { node, counter, mac });
        Classify::Upgrade { node, reply }
    }
```

Also update any existing tests in `conn.rs` that constructed bare `framed_register` to use `RegisterAuth`:
```rust
fn framed_register_auth(obf_key: &[u8; 16], node: NodeId, counter: u64) -> Vec<u8> {
    let mac = yip_rendezvous::compute_register_mac(obf_key, &node, counter);
    crate::frame_obf(obf_key, &Message::RegisterAuth { node, counter, mac })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yip-rendezvous-bin`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bin/yip-rendezvous/src/conn.rs
git commit -m "feat(rendezvous): enforce verified RegisterAuth on Trojan front discriminator (#64)"
```

---

### Task 3: Relay Client Integration & Workspace Verification

**Files:**
- Modify: `bin/yipd/src/relay_client.rs`

**Interfaces:**
- Consumes:
  - `yip_rendezvous::{compute_register_mac, Message::RegisterAuth}`
- Produces:
  - `build_register` emits framed obfuscated `RegisterAuth` message.

- [ ] **Step 1: Update `build_register` and its unit tests in `bin/yipd/src/relay_client.rs`**

In `bin/yipd/src/relay_client.rs`:
```rust
pub(crate) fn build_register(obf_key: &[u8; 16], node: NodeId, counter: u64) -> Vec<u8> {
    let mac = yip_rendezvous::compute_register_mac(obf_key, &node, counter);
    let mut plain = Vec::new();
    encode(&Message::RegisterAuth { node, counter, mac }, &mut plain);
    let env = yip_obf::obfuscate(obf_key, yip_obf::RDV_TYPE, &plain, 0)
        .expect("RegisterAuth body fits u16");
    let mut out = Vec::new();
    crate::tls::frame_datagram(&env, &mut out).expect("register envelope within frame cap");
    out
}
```

Update unit tests in `relay_client.rs`:
```rust
    #[test]
    fn register_frame_deobfuscates_to_fresh_register_auth() {
        let key = yip_obf::derive_key(&[7u8; 32]);
        let node = node_id(&[1u8; 32]);
        let framed = build_register(&key, node, 1);
        let len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
        let env = &framed[2..2 + len];
        let (pt, body) = yip_obf::deobfuscate(&key, env).expect("deobfuscates");
        assert_eq!(pt, yip_obf::RDV_TYPE);
        let msg = decode(&body);
        let mac = yip_rendezvous::compute_register_mac(&key, &node, 1);
        assert_eq!(msg, Some(yip_rendezvous::Message::RegisterAuth { node, counter: 1, mac }));
    }
```

- [ ] **Step 2: Run tests in `yipd`**

Run: `cargo test -p yipd relay_client`
Expected: PASS.

- [ ] **Step 3: Run full workspace verification**

Run:
```bash
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check
```
Expected: All pass with 0 errors and 0 warnings.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/relay_client.rs
git commit -m "feat(relay): emit authenticated RegisterAuth in relay client registration (#64)"
```
