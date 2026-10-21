# Post-Quantum Hybrid Handshake (Noise-IKpsk2 + ML-KEM-512) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade `yip`'s transport handshake from classical Noise-IK to a single-RTT post-quantum hybrid key exchange (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` + ML-KEM-512 / FIPS 203) that fits comfortably under `OBF_MTU_BUDGET = 1200` bytes with zero allocation in the data plane.

**Architecture:** The handshake incorporates ephemeral ML-KEM-512 (Kyber) key exchange into Noise-IK: Message 1 embeds the 800-byte encapsulation key ($ek_A$) inside the authenticated Noise payload, while Message 2 places the 768-byte ciphertext ($ct$) in the outer framing envelope before the Noise Message 2 token sequence (`e, ee, se, psk`). This allows the Initiator to decapsulate the post-quantum shared secret ($ss$) and inject it via `handshake_state.set_psk(2, &ss)` *before* decrypting Message 2's payload, eliminating `snow` evaluation deadlock while guaranteeing IND-CCA2 security against quantum harvesting.

**Tech Stack:** Rust 2021, `snow` 0.10, `ml-kem` 0.3 (or 0.2 API compatible), `rand` 0.8, `zeroize` 1.8, `ring` 0.17 (ChaCha20-Poly1305 data plane).

## Global Constraints

- Language & Edition: Rust 2021 edition (rustc 1.85+ compatible).
- Security Profile: NIST Security Category 1 post-quantum resistance ($\ge 2^{140}$ quantum operations) dual-layered with classical X25519 Diffie-Hellman.
- Noise Parameter Set: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`.
- Wire Budget: Both handshake datagrams must strictly remain under `OBF_MTU_BUDGET = 1200` bytes (Message 1 = 1,025 bytes, Message 2 = 945 bytes).
- Memory Hygiene: Ephemeral private decapsulation keys ($dk_A$) and all shared secret ($ss$) intermediate buffers must be wrapped in `zeroize::Zeroizing` and wiped from memory on drop across both success and timeout paths.
- Quality Gates: Code coverage must remain $\ge 90.00\%$ across `yip-crypto` and `bin/yipd`, with zero clippy warnings (`-D warnings -D clippy::allow_attributes`) and zero allocations in the data-plane hot path.

---

### Task 1: Post-Quantum Primitives in `crates/yip-crypto`

**Files:**
- Modify: `crates/yip-crypto/Cargo.toml`
- Modify: `crates/yip-crypto/src/lib.rs:1-80`
- Test: `crates/yip-crypto/src/lib.rs` (unit tests module)

**Interfaces:**
- Consumes: `ml_kem = { version = "0.3", features = ["zeroize", "getrandom"] }`, `rand = "0.8"`, `zeroize::Zeroizing`
- Produces:
  - `pub const PQ_ENCAPS_KEY_LEN: usize = 800;`
  - `pub const PQ_CIPHERTEXT_LEN: usize = 768;`
  - `pub const PQ_SHARED_SECRET_LEN: usize = 32;`
  - `pub struct PqEncapsKey(pub [u8; PQ_ENCAPS_KEY_LEN]);`
  - `pub struct PqDecapsKey(pub Box<zeroize::Zeroizing<ml_kem::ml_kem_512::DecapsulationKey>>);`
  - `pub struct PqCiphertext(pub [u8; PQ_CIPHERTEXT_LEN]);`
  - `pub fn generate_pq_keypair() -> (PqEncapsKey, PqDecapsKey);`
  - `pub fn pq_encapsulate(ek: &PqEncapsKey) -> Result<(PqCiphertext, zeroize::Zeroizing<[u8; PQ_SHARED_SECRET_LEN]>), CryptoError>;`
  - `pub fn pq_decapsulate(dk: &PqDecapsKey, ct: &PqCiphertext) -> Result<zeroize::Zeroizing<[u8; PQ_SHARED_SECRET_LEN]>, CryptoError>;`

- [ ] **Step 1: Write failing tests for ML-KEM-512 primitives**

Add the unit tests to `crates/yip-crypto/src/lib.rs`:

```rust
#[test]
fn pq_keypair_encapsulate_decapsulate_roundtrip() {
    let (ek, dk) = generate_pq_keypair();
    assert_eq!(ek.0.len(), PQ_ENCAPS_KEY_LEN);

    let (ct, ss_sender) = pq_encapsulate(&ek).expect("encapsulation succeeds");
    assert_eq!(ct.0.len(), PQ_CIPHERTEXT_LEN);
    assert_eq!(ss_sender.len(), PQ_SHARED_SECRET_LEN);

    let ss_recipient = pq_decapsulate(&dk, &ct).expect("decapsulation succeeds");
    assert_eq!(*ss_sender, *ss_recipient, "both sides agree on 32-byte shared secret");
}

#[test]
fn pq_encapsulate_rejects_fips203_invalid_modulus() {
    let (mut ek, _dk) = generate_pq_keypair();
    // FIPS 203 Section 7.2 ByteDecode_12 requires all 12-bit coefficients < q (3329).
    // Inject 0x0FFF (4095 >= 3329) into the first coefficient pair.
    ek.0[0] = 0xFF;
    ek.0[1] = 0x0F;
    let res = pq_encapsulate(&ek);
    assert!(res.is_err(), "encapsulation must reject coefficient >= 3329");
}

#[test]
fn pq_decapsulate_implicit_rejection_on_tampered_ciphertext() {
    let (ek, dk) = generate_pq_keypair();
    let (mut ct, ss_sender) = pq_encapsulate(&ek).expect("encapsulation succeeds");

    // Tamper with the ciphertext: flip one bit in ct
    ct.0[0] ^= 0x01;
    let ss_recipient = pq_decapsulate(&dk, &ct).expect("decapsulation succeeds via implicit rejection");
    assert_ne!(
        *ss_sender, *ss_recipient,
        "FIPS 203 implicit rejection must yield a distinct pseudorandom secret on tampered ciphertext"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-crypto --lib pq_keypair_encapsulate_decapsulate_roundtrip`
Expected: FAIL with "cannot find function `generate_pq_keypair` in this scope"

- [ ] **Step 3: Update `crates/yip-crypto/Cargo.toml` and implement primitives**

In `crates/yip-crypto/Cargo.toml`, add `ml-kem`, `rand`, and `zeroize`:

```toml
[dependencies]
thiserror = { workspace = true }
snow = { version = "0.10.0", features = ["risky-raw-split"] }
ring = "0.17"
ml-kem = { version = "0.3", features = ["zeroize", "getrandom"] }
rand = "0.8"
zeroize = { version = "1.8", features = ["zeroize_derive"] }
```

In `crates/yip-crypto/src/lib.rs`, add the imports, types, and explicit FIPS 203 Section 7.2 ByteDecode_12 coefficient modulus check:

```rust
use ml_kem::{
    array::Array,
    kem::{Decapsulate, Encapsulate, Kem},
    ml_kem_512::{self, MlKem512},
};
use zeroize::Zeroizing;

/// ML-KEM-512 encapsulation key length in bytes (FIPS 203).
pub const PQ_ENCAPS_KEY_LEN: usize = 800;

/// ML-KEM-512 ciphertext length in bytes (FIPS 203).
pub const PQ_CIPHERTEXT_LEN: usize = 768;

/// ML-KEM-512 shared secret length in bytes (FIPS 203).
pub const PQ_SHARED_SECRET_LEN: usize = 32;

/// An ML-KEM-512 public encapsulation key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqEncapsKey(pub [u8; PQ_ENCAPS_KEY_LEN]);

/// An ML-KEM-512 private decapsulation key wrapped in zeroizing memory.
pub struct PqDecapsKey(pub Box<Zeroizing<ml_kem_512::DecapsulationKey>>);

impl std::fmt::Debug for PqDecapsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PqDecapsKey([REDACTED])")
    }
}

/// An ML-KEM-512 encapsulated ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqCiphertext(pub [u8; PQ_CIPHERTEXT_LEN]);

/// Generate a fresh ML-KEM-512 keypair.
pub fn generate_pq_keypair() -> (PqEncapsKey, PqDecapsKey) {
    let (dk, ek) = MlKem512::generate_keypair();
    let ek_bytes = ek.to_bytes();
    let mut ek_arr = [0u8; PQ_ENCAPS_KEY_LEN];
    ek_arr.copy_from_slice(ek_bytes.as_slice());
    (
        PqEncapsKey(ek_arr),
        PqDecapsKey(Box::new(Zeroizing::new(dk))),
    )
}

/// Encapsulate a shared secret toward `ek`, producing `(ciphertext, shared_secret)`.
///
/// Explicitly validates FIPS 203 Section 7.2 ByteDecode_12 (all 12-bit coefficients < 3329)
/// across the first 768 bytes before invoking key encapsulation.
pub fn pq_encapsulate(
    ek: &PqEncapsKey,
) -> Result<(PqCiphertext, Zeroizing<[u8; PQ_SHARED_SECRET_LEN]>), CryptoError> {
    // FIPS 203 Section 7.2: ByteDecode_12 modulus check (all 12-bit coeffs < 3329)
    for chunk in ek.0[..768].chunks_exact(3) {
        let d0 = u16::from(chunk[0]) | ((u16::from(chunk[1]) & 0x0F) << 8);
        let d1 = (u16::from(chunk[1]) >> 4) | (u16::from(chunk[2]) << 4);
        if d0 >= 3329 || d1 >= 3329 {
            return Err(CryptoError::Handshake);
        }
    }

    let ek_arr = Array::clone_from_slice(&ek.0);
    let key = ml_kem_512::EncapsulationKey::new(&ek_arr).map_err(|_| CryptoError::Handshake)?;
    let (ct, ss) = key.encapsulate();
    let mut ct_arr = [0u8; PQ_CIPHERTEXT_LEN];
    ct_arr.copy_from_slice(ct.as_slice());
    let mut ss_arr = Zeroizing::new([0u8; PQ_SHARED_SECRET_LEN]);
    ss_arr.copy_from_slice(ss.as_slice());
    Ok((PqCiphertext(ct_arr), ss_arr))
}

/// Decapsulate `ct` using `dk`, recovering the 32-byte shared secret wrapped in zeroizing memory.
pub fn pq_decapsulate(
    dk: &PqDecapsKey,
    ct: &PqCiphertext,
) -> Result<Zeroizing<[u8; PQ_SHARED_SECRET_LEN]>, CryptoError> {
    let ct_arr = Array::clone_from_slice(&ct.0);
    let ss = dk.0.decapsulate(&ct_arr);
    let mut ss_arr = Zeroizing::new([0u8; PQ_SHARED_SECRET_LEN]);
    ss_arr.copy_from_slice(ss.as_slice());
    Ok(ss_arr)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yip-crypto --lib pq_`
Expected: PASS (3 tests passed)

- [ ] **Step 5: Commit**

```bash
git add crates/yip-crypto/Cargo.toml crates/yip-crypto/src/lib.rs
git commit -m "feat(crypto): implement ML-KEM-512 post-quantum primitives"
```

---

### Task 2: Noise-IKpsk2 Hybrid State Machine in `crates/yip-crypto`

**Files:**
- Modify: `crates/yip-crypto/src/lib.rs:16-360`
- Test: `crates/yip-crypto/src/lib.rs` (unit tests module)

**Interfaces:**
- Consumes: `PqEncapsKey`, `PqDecapsKey`, `PqCiphertext`, `generate_pq_keypair`, `pq_encapsulate`, `pq_decapsulate`
- Produces:
  - Updated `NOISE_PARAMS`: `"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"`
  - Updated `Handshake`:
    - `Handshake::initiator(local_private: &[u8; 32], peer_public: &[u8; 32]) -> Result<Handshake, CryptoError>`
    - `Handshake::responder(local_private: &[u8; 32]) -> Result<Handshake, CryptoError>`
    - `Handshake::write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError>`
    - `Handshake::read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>`
    - `Handshake::channel_binding(&self) -> [u8; 32]`
    - `Handshake::raw_split_keys(&self) -> ([u8; 32], [u8; 32])`
    - `Handshake::into_session(self) -> Result<Session, CryptoError>`

- [ ] **Step 1: Write failing tests for Noise-IKpsk2 hybrid handshake**

Add to `crates/yip-crypto/src/lib.rs`:

```rust
#[test]
fn pq_hybrid_handshake_roundtrip_with_payload() {
    let init_kp = generate_keypair();
    let resp_kp = generate_keypair();

    let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
    let mut res = Handshake::responder(&resp_kp.private).unwrap();

    let cert_a = b"initiator-test-certificate-128b";
    let cert_b = b"responder-test-certificate-128b";

    // Msg 1: Initiator -> Responder
    let msg1 = ini.write_message(cert_a).unwrap();
    // Msg 1 wire size = 32(e) + 48(s) + 800(ek) + cert_a.len() + 16(tag)
    assert_eq!(msg1.len(), 32 + 48 + PQ_ENCAPS_KEY_LEN + cert_a.len() + 16);

    let p1 = res.read_message(&msg1).unwrap();
    assert_eq!(p1, cert_a);
    assert_eq!(res.remote_static(), Some(init_kp.public));

    // Msg 2: Responder -> Initiator
    let msg2 = res.write_message(cert_b).unwrap();
    // Msg 2 wire size = 768(ct) + 32(e) + cert_b.len() + 16(tag)
    assert_eq!(msg2.len(), PQ_CIPHERTEXT_LEN + 32 + cert_b.len() + 16);

    let p2 = ini.read_message(&msg2).unwrap();
    assert_eq!(p2, cert_b);
    assert_eq!(ini.remote_static(), Some(resp_kp.public));

    assert!(ini.is_finished());
    assert!(res.is_finished());
    assert_eq!(ini.channel_binding(), res.channel_binding());

    let (ini_send, ini_recv) = ini.raw_split_keys();
    let (res_send, res_recv) = res.raw_split_keys();
    assert_eq!(ini_send, res_recv);
    assert_eq!(ini_recv, res_send);

    let mut ini_session = ini.into_session().unwrap();
    let mut res_session = res.into_session().unwrap();
    let sealed = ini_session.seal(b"quantum safe transport payload").unwrap();
    let opened = res_session.open(sealed.counter, &sealed.ciphertext).unwrap();
    assert_eq!(opened, b"quantum safe transport payload");
}

#[test]
fn pq_hybrid_handshake_rejects_tampered_ciphertext() {
    let init_kp = generate_keypair();
    let resp_kp = generate_keypair();

    let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
    let mut res = Handshake::responder(&resp_kp.private).unwrap();

    let msg1 = ini.write_message(b"certA").unwrap();
    let _ = res.read_message(&msg1).unwrap();
    let mut msg2 = res.write_message(b"certB").unwrap();

    // Tamper with the cleartext ct prefix of msg2
    msg2[10] ^= 0x01;

    // Initiator decapsulates to a mismatched ss, causing snow Poly1305 MAC to fail
    let err = ini.read_message(&msg2);
    assert!(err.is_err(), "tampered ct must fail handshake verification");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-crypto --lib pq_hybrid_handshake_roundtrip_with_payload`
Expected: FAIL with message size assertions or handshake errors

- [ ] **Step 3: Update `Handshake` state machine in `crates/yip-crypto/src/lib.rs`**

Update `NOISE_PARAMS` and `Handshake`:

```rust
/// The Noise parameter set: IKpsk2 pattern, X25519, ChaCha20-Poly1305, BLAKE2s.
pub(crate) const NOISE_PARAMS: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// Internal role-specific state for post-quantum hybrid key exchange.
enum HandshakePqRole {
    Initiator {
        dk: Option<PqDecapsKey>,
        ek: PqEncapsKey,
    },
    Responder {
        pending_ct: Option<PqCiphertext>,
    },
}

/// An in-progress Noise-IKpsk2 post-quantum hybrid handshake.
pub struct Handshake {
    inner: std::sync::Mutex<snow::HandshakeState>,
    role: HandshakePqRole,
}

impl Handshake {
    /// Begin as the initiator, which must already know the responder's static public key.
    pub fn initiator(
        local_private: &[u8; 32],
        peer_public: &[u8; 32],
    ) -> Result<Handshake, CryptoError> {
        let inner = snow::Builder::new(NOISE_PARAMS.parse().map_err(|_| CryptoError::Handshake)?)
            .local_private_key(local_private)
            .map_err(|_| CryptoError::Handshake)?
            .remote_public_key(peer_public)
            .map_err(|_| CryptoError::Handshake)?
            .build_initiator()
            .map_err(|_| CryptoError::Handshake)?;

        let (ek, dk) = generate_pq_keypair();
        Ok(Handshake {
            inner: std::sync::Mutex::new(inner),
            role: HandshakePqRole::Initiator {
                dk: Some(dk),
                ek,
            },
        })
    }

    /// Begin as the responder; learns the initiator's static key during the handshake.
    pub fn responder(local_private: &[u8; 32]) -> Result<Handshake, CryptoError> {
        let inner = snow::Builder::new(NOISE_PARAMS.parse().map_err(|_| CryptoError::Handshake)?)
            .local_private_key(local_private)
            .map_err(|_| CryptoError::Handshake)?
            .build_responder()
            .map_err(|_| CryptoError::Handshake)?;

        Ok(Handshake {
            inner: std::sync::Mutex::new(inner),
            role: HandshakePqRole::Responder { pending_ct: None },
        })
    }

    /// Produce the next handshake message to send to the peer.
    ///
    /// - For Initiator (Msg 1): Encrypts `[ek_A (800B) || payload]` inside Noise Msg 1.
    /// - For Responder (Msg 2): Encrypts `payload` inside Noise Msg 2, framed as `[ct (768B) || Noise Msg 2]`.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = [0u8; 4096];
        match &mut self.role {
            HandshakePqRole::Initiator { ek, .. } => {
                let mut full_payload = Vec::with_capacity(PQ_ENCAPS_KEY_LEN + payload.len());
                full_payload.extend_from_slice(&ek.0);
                full_payload.extend_from_slice(payload);
                let n = self
                    .inner
                    .get_mut()
                    .expect("handshake lock")
                    .write_message(&full_payload, &mut buf)
                    .map_err(|_| CryptoError::Handshake)?;
                Ok(buf[..n].to_vec())
            }
            HandshakePqRole::Responder { pending_ct } => {
                let ct = pending_ct.take().ok_or(CryptoError::Handshake)?;
                let n = self
                    .inner
                    .get_mut()
                    .expect("handshake lock")
                    .write_message(payload, &mut buf)
                    .map_err(|_| CryptoError::Handshake)?;
                let mut out = Vec::with_capacity(PQ_CIPHERTEXT_LEN + n);
                out.extend_from_slice(&ct.0);
                out.extend_from_slice(&buf[..n]);
                Ok(out)
            }
        }
    }

    /// Consume a handshake message received from the peer, returning the decrypted app payload.
    ///
    /// - For Responder (Msg 1): Decrypts Noise Msg 1, extracts `ek_A`, encapsulates `(ct, ss)`,
    ///   calls `set_psk(2, &ss)`, and returns `payload`.
    /// - For Initiator (Msg 2): Slices `ct` from Msg 2 prefix, decapsulates `ss`,
    ///   calls `set_psk(2, &ss)`, decrypts Noise Msg 2, scrubs `dk`, and returns `payload`.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = [0u8; 4096];
        match &mut self.role {
            HandshakePqRole::Responder { pending_ct } => {
                let n = self
                    .inner
                    .get_mut()
                    .expect("handshake lock")
                    .read_message(msg, &mut buf)
                    .map_err(|_| CryptoError::Handshake)?;
                if n < PQ_ENCAPS_KEY_LEN {
                    return Err(CryptoError::Handshake);
                }
                let mut ek_bytes = [0u8; PQ_ENCAPS_KEY_LEN];
                ek_bytes.copy_from_slice(&buf[..PQ_ENCAPS_KEY_LEN]);
                let ek = PqEncapsKey(ek_bytes);
                let (ct, ss) = pq_encapsulate(&ek)?;
                self.inner
                    .get_mut()
                    .expect("handshake lock")
                    .set_psk(2, &ss)
                    .map_err(|_| CryptoError::Handshake)?;
                *pending_ct = Some(ct);
                Ok(buf[PQ_ENCAPS_KEY_LEN..n].to_vec())
            }
            HandshakePqRole::Initiator { dk, .. } => {
                if msg.len() < PQ_CIPHERTEXT_LEN {
                    return Err(CryptoError::Handshake);
                }
                let mut ct_bytes = [0u8; PQ_CIPHERTEXT_LEN];
                ct_bytes.copy_from_slice(&msg[..PQ_CIPHERTEXT_LEN]);
                let ct = PqCiphertext(ct_bytes);
                let decaps_key = dk.take().ok_or(CryptoError::Handshake)?;
                let ss = pq_decapsulate(&decaps_key, &ct)?;
                drop(decaps_key); // Explicit scrub of dk_A

                let inner = self.inner.get_mut().expect("handshake lock");
                inner.set_psk(2, &ss).map_err(|_| CryptoError::Handshake)?;
                let n = inner
                    .read_message(&msg[PQ_CIPHERTEXT_LEN..], &mut buf)
                    .map_err(|_| CryptoError::Handshake)?;
                Ok(buf[..n].to_vec())
            }
        }
    }
```

Update `session_seal_is_byte_identical_to_snow_write_message_both_directions` to perform a completed handshake through `Handshake::initiator` and `Handshake::responder`, verify symmetric `raw_split_keys()`, and confirm that `Session::seal` and `Session::open` are roundtrip byte-equivalent across both peers.

- [ ] **Step 4: Run all yip-crypto tests to verify they pass**

Run: `cargo test -p yip-crypto`
Expected: PASS (all tests passed)

- [ ] **Step 5: Commit**

```bash
git add crates/yip-crypto/src/lib.rs
git commit -m "feat(crypto): implement Noise-IKpsk2 post-quantum hybrid handshake"
```

---

### Task 3: Framing, Ephemeral Extraction, and Rekey Witness Updates in `bin/yipd`

**Files:**
- Modify: `bin/yipd/src/handshake.rs:240-285,435-500`
- Modify: `bin/yipd/examples/rekey_epoch_witness.rs:210-285`
- Test: `bin/yipd/src/handshake.rs` (unit tests)

**Interfaces:**
- Consumes: `yip_crypto::PQ_CIPHERTEXT_LEN`
- Produces:
  - `pub fn resp_ephemeral(resp_pkt: &[u8]) -> Option<[u8; 32]>`
  - Updated `rekey_epoch_witness` parsing `inner[769..801]` for `TYPE_HANDSHAKE_RESP`

- [ ] **Step 1: Write failing test for `resp_ephemeral` extraction**

In `bin/yipd/src/handshake.rs`, add unit tests with properly matched keypairs:

```rust
#[test]
fn resp_ephemeral_matches_across_identical_retransmits_and_differs_for_new_attempts() {
    let local_kp = yip_crypto::generate_keypair();
    let peer_kp = yip_crypto::generate_keypair();

    let (_hs, init_pkt) = HandshakeState::start_initiator(&local_kp.private, &peer_kp.public, &[]).unwrap();
    let (_, resp_pkt1, _, _) = HandshakeState::start_responder(&peer_kp.private, &init_pkt, &[]).unwrap();
    let (_, resp_pkt2, _, _) = HandshakeState::start_responder(&peer_kp.private, &init_pkt, &[]).unwrap();

    let eph1 = resp_ephemeral(&resp_pkt1).expect("valid resp has ephemeral");
    let eph2 = resp_ephemeral(&resp_pkt2).expect("valid resp has ephemeral");
    assert_ne!(eph1, [0u8; 32]);
    assert_ne!(eph2, [0u8; 32]);
    assert_ne!(eph1, eph2, "distinct responder attempts draw distinct ephemerals");
    assert_eq!(resp_ephemeral(&[0u8; 10]), None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd --lib resp_ephemeral_matches_across_identical_retransmits`
Expected: FAIL with "cannot find function `resp_ephemeral` in this scope"

- [ ] **Step 3: Implement `resp_ephemeral` and update `rekey_epoch_witness.rs`**

In `bin/yipd/src/handshake.rs`, add `resp_ephemeral`:

```rust
/// The responder's Noise ephemeral public key: the raw, unencrypted 32 bytes
/// that lead Noise Msg 2 (`<- e, ee, se, psk`), located immediately after the
/// 1-byte [`PacketType::HandshakeResp`] prefix and the 768-byte ML-KEM ciphertext.
///
/// Offset: `1 + 768 .. 1 + 768 + 32` = `769..801`.
pub const RESP_EPHEMERAL_OFFSET: usize = 1 + yip_crypto::PQ_CIPHERTEXT_LEN;

pub fn resp_ephemeral(resp_pkt: &[u8]) -> Option<[u8; 32]> {
    resp_pkt
        .get(RESP_EPHEMERAL_OFFSET..RESP_EPHEMERAL_OFFSET + 32)?
        .try_into()
        .ok()
}
```

In `bin/yipd/examples/rekey_epoch_witness.rs`, update the handshake parsing loop:

```rust
const MIN_INIT_LEN: usize = 33;
const MIN_RESP_LEN: usize = 801;

// In main():
for p in &pkts {
    let inner: &[u8] = if unwrap_relay {
        unwrap_relay_envelope(&p.payload)
    } else {
        &p.payload
    };
    if inner.is_empty() {
        continue;
    }
    match inner[0] {
        TYPE_HANDSHAKE_INIT => {
            if inner.len() < MIN_INIT_LEN {
                continue;
            }
            let ephemeral: [u8; 32] = inner[1..33].try_into().expect("32 bytes");
            init_pkt_count += 1;
            if !init_ephemerals.contains(&ephemeral) {
                init_ephemerals.push(ephemeral);
            }
        }
        TYPE_HANDSHAKE_RESP => {
            if inner.len() < MIN_RESP_LEN {
                continue;
            }
            let ephemeral: [u8; 32] = inner[769..801].try_into().expect("32 bytes");
            resp_pkt_count += 1;
            if !resp_ephemerals.contains(&ephemeral) {
                resp_ephemerals.push(ephemeral);
            }
        }
        _ => continue,
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yipd --lib handshake::tests`
Expected: PASS (all tests in handshake.rs pass)

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/handshake.rs bin/yipd/examples/rekey_epoch_witness.rs
git commit -m "feat(handshake): support PQ hybrid ephemeral extraction and witness parsing"
```

---

### Task 4: Session Rekey & PeerManager Integration Tests

**Files:**
- Modify: `bin/yipd/src/peer_manager/tests.rs`
- Test: `bin/yipd/src/peer_manager/tests.rs`

**Interfaces:**
- Consumes: `established_pm_pair()`, `established_pm_pair_with_obf()` from `super::testutil::*`
- Produces: Passing unit and rekey lifecycle tests verifying PQ hybrid exchange under `PeerManager` within `OBF_MTU_BUDGET = 1200`

- [ ] **Step 1: Write integration tests in `bin/yipd/src/peer_manager/tests.rs`**

Using `testutil` helpers `established_pm_pair` and `established_pm_pair_with_obf`:

```rust
#[test]
fn test_peer_manager_pq_hybrid_handshake_datagrams_fit_mtu_budget() {
    let (mut pm_a, mut pm_b) = established_pm_pair();

    // Verify existing established pair operates across cold start and rekey
    let now = 10_000u64;
    let b_addr = peer_src(&pm_a, 0);

    // Verify rekey payload construction
    let rekey_pkt = rekey_init_with_payload(&pm_a, 0, &valid_cert_bytes(&pm_a, 0));
    assert!(
        rekey_pkt.len() <= OBF_MTU_BUDGET,
        "rekey Init with cert must stay within OBF_MTU_BUDGET, got {}",
        rekey_pkt.len()
    );
    assert_eq!(rekey_pkt[0], PacketType::HandshakeInit as u8);

    // Verify with obfuscation
    let (mut pm_obf_a, _) = established_pm_pair_with_obf();
    let rekey_obf = rekey_init_with_payload(&pm_obf_a, 0, &valid_cert_bytes(&pm_obf_a, 0));
    let wrapped = pm_obf_a.obf_envelope(rekey_obf, now);
    assert!(
        wrapped.len() <= OBF_MTU_BUDGET,
        "obfuscated rekey datagram must stay within OBF_MTU_BUDGET, got {}",
        wrapped.len()
    );
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cargo test -p yipd --lib peer_manager::tests::test_peer_manager_pq_hybrid_handshake_datagrams_fit_mtu_budget`
Expected: PASS

- [ ] **Step 3: Run full peer_manager test suite**

Run: `cargo test -p yipd --lib peer_manager`
Expected: PASS (all tests pass, 0 failures)

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/peer_manager/tests.rs
git commit -m "test(peer_manager): verify post-quantum hybrid cold-start and rekey round"
```

---

### Task 5: End-to-End System Verification (Netns Rekey & Multi-Round Witness)

**Files:**
- Test: `bin/yipd/tests/run-netns-rekey.sh`
- Test: `bin/yipd/tests/run-netns-rekey-relay.sh`
- Test: `bin/yipd/tests/run-netns-replay-hijack.sh`

**Interfaces:**
- Consumes: Complete workspace builds of `yipd` and `rekey_epoch_witness`
- Produces: Successful multi-round continuous rekey validation across network namespaces

- [ ] **Step 1: Build yipd and rekey_epoch_witness release binaries**

Run: `cargo build --release -p yipd --bin yipd --example rekey_epoch_witness`
Expected: Build succeeds with 0 errors and 0 warnings.

- [ ] **Step 2: Run netns direct rekey test**

Run: `sudo bin/yipd/tests/run-netns-rekey.sh`
Expected: PASS with output verifying multiple distinct post-quantum initiator and responder ephemerals (`COMPLETED_ROUNDS >= 3`).

- [ ] **Step 3: Run netns replay hijack protection test**

Run: `sudo bin/yipd/tests/run-netns-replay-hijack.sh`
Expected: PASS with output showing replay refusal and zero packet loss.

- [ ] **Step 4: Run full workspace test suite and linter checks**

Run:
```bash
cargo clippy --all-targets -- -D warnings -D clippy::allow_attributes
cargo test --workspace
```
Expected: All linter checks clean, all workspace tests passing.

- [ ] **Step 5: Commit any test harness or documentation cleanups**

```bash
git add docs/ bin/ crates/
git commit -m "chore(pqc): complete end-to-end post-quantum hybrid handshake verification"
```
