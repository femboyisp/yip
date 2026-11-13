# Design Document: Zero-Allocation PQNoise State Machine and BLAKE3 Migration

- **Date**: 2026-11-11
- **Status**: Approved
- **Target Repository**: `femboyisp/yip`
- **Scope**: `crates/yip-crypto`, `bin/yipd`, `crates/yip-rendezvous`, `crates/yip-obf`, `crates/yip-wire`

---

## 1. Executive Summary

This specification establishes the architectural design for migrating `yip` from its status quo handshake and utility hashing stack (`snow`, `blake2` v0.10.6, `hkdf`, `hmac`) to a bespoke, zero-allocation **Post-Quantum Extended Noise** state machine (`PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3`) implemented natively in `crates/yip-crypto`.

By eliminating `snow` and utilizing BLAKE3's native keyed PRF and Extendable Output Function (XOF), key derivation rounds drop from 87 compression invocations (870 permutation rounds) to 8 compression invocations (56 permutation rounds)—a 10.9x reduction in compression calls and a 15.5x reduction in permutation work during the handshake. All dynamic heap allocations (`Box<dyn Hash>`, `Box<dyn CipherState>`, `Vec<u8>`) are replaced with stack-allocated fixed arrays, while preserving `SipHash-1-3` on the per-packet wire and obfuscation data plane.

---

## 2. Goals & Non-Goals

### Goals
- **Zero Heap Allocations**: Ensure handshake state initialization, flight transitions, and key ratchets operate 100% on the stack with zero dynamic allocations.
- **Single-Pass Key Derivation**: Leverage BLAKE3 keyed hashing and XOF to replace nested HMAC/HKDF loops with 1-pass root compressions.
- **First-Class Post-Quantum Integration**: Represent NIST FIPS 203 `ML-KEM-512` as a native state-machine token (`skem`), rather than an out-of-band payload attachment.
- **Dependency Purge**: Completely remove `snow`, `blake2`, `hkdf`, and `hmac` from `Cargo.lock`.
- **Domain-Separated XOF Ratchets**: Enforce 1-byte domain tags to guarantee dual-PRF security across prefix-compatible BLAKE3 XOF outputs.
- **Context-Separated Addressing & Rendezvous**: Standardize overlay IPv6 address (`fd00::/8`) and rendezvous `node_id` derivation on `blake3::derive_key`.

### Non-Goals
- **No BLAKE3 on Data Plane Per-Packet Framing**: Do not replace `SipHash-1-3` in `crates/yip-wire` or `crates/yip-obf`. Prior benchmarking demonstrated that SipHash-1-3 is ~45% cheaper than 7-round BLAKE3 for 16–32 byte wire headers.
- **No Multi-Threading in Control Plane**: Disable `rayon` features in `blake3` to prevent background thread pool initialization in embedded or resource-constrained environments.

---

## 3. Architecture & State Machine (`crates/yip-crypto`)

### 3.1 State Representation

The state machine is implemented without dynamic dispatch or trait objects. To preserve stack efficiency across concurrent tasks, the 1,632-byte ML-KEM-512 decapsulation key (`dk`) is passed directly into `read_message_1` as a reference (`&[u8; 1632]`) rather than stored inside `HandshakeState`:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricState {
    pub ck: [u8; 32],
    pub h: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HandshakeState {
    pub symmetric: SymmetricState,
    pub s_secret: [u8; 32],
    pub s_public: [u8; 32],
    pub e_secret: [u8; 32],
    pub e_public: [u8; 32],
    pub rs_x25519: [u8; 32],
    pub rs_mlkem512: [u8; 800],
    pub re_x25519: Option<[u8; 32]>,
}
```

### 3.2 BLAKE3 Keyed XOF Ratchet with Domain Separation

Because BLAKE3 XOF outputs are prefix-compatible, shorter outputs are exact prefixes of longer outputs. To maintain dual-PRF security and prevent key reuse across 64-byte, 96-byte, and 32-byte derivations, the state machine prepends an explicit 1-byte operational domain tag to the input key material before hashing:
- `0x01`: `MixKey` (emits 64 bytes: 32 B chaining key `ck'`, 32 B AEAD cipher key `k`)
- `0x02`: `MixKeyAndHash` (emits 96 bytes: 32 B chaining key `ck'`, 32 B transcript update `temp_h`, 32 B AEAD cipher key `k`)
- `0x03`: `Split` (emits 64 bytes: 32 B initiator-to-responder transport key, 32 B responder-to-initiator transport key)
- `0x04`: `Rekey` (emits 32 bytes: 32 B next transport AEAD key for 120s forward-secrecy epoch rotation)

All stack-allocated intermediate key output buffers are explicitly zeroized prior to returning from the call:

```rust
impl SymmetricState {
    pub fn new(protocol_name: &[u8]) -> Self {
        let h = blake3::hash(protocol_name);
        Self {
            ck: *h.as_bytes(),
            h: *h.as_bytes(),
        }
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h.copy_from_slice(hasher.finalize().as_bytes());
    }

    pub fn mix_key(&mut self, ikm: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.ck);
        hasher.update(&[0x01]);
        hasher.update(ikm);
        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);

        self.ck.copy_from_slice(&out[0..32]);
        let mut k = [0u8; 32];
        k.copy_from_slice(&out[32..64]);
        out.zeroize();
        k
    }

    pub fn mix_key_and_hash(&mut self, psk: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.ck);
        hasher.update(&[0x02]);
        hasher.update(psk);
        let mut out = [0u8; 96];
        hasher.finalize_xof().fill(&mut out);

        self.ck.copy_from_slice(&out[0..32]);
        let mut temp_h = [0u8; 32];
        temp_h.copy_from_slice(&out[32..64]);
        self.mix_hash(&temp_h);
        temp_h.zeroize();

        let mut k = [0u8; 32];
        k.copy_from_slice(&out[64..96]);
        out.zeroize();
        k
    }

    pub fn split(&self) -> ([u8; 32], [u8; 32]) {
        let mut hasher = blake3::Hasher::new_keyed(&self.ck);
        hasher.update(&[0x03]);
        let mut out = [0u8; 64];
        hasher.finalize_xof().fill(&mut out);

        let mut k_send = [0u8; 32];
        let mut k_recv = [0u8; 32];
        k_send.copy_from_slice(&out[0..32]);
        k_recv.copy_from_slice(&out[32..64]);
        out.zeroize();
        (k_send, k_recv)
    }

    pub fn rekey(current_key: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(current_key);
        hasher.update(&[0x04]);
        let mut next_key = [0u8; 32];
        hasher.finalize_xof().fill(&mut next_key);
        next_key
    }
}
```

---

## 4. Handshake Protocol & Wire Layout

### 4.1 Protocol Pattern
The formal protocol string is:
```
PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3
```

- **Prologue**: Mixes application context and static responder keys into $h$:
  - `MixHash(prologue)`
  - `MixHash(rs_x25519)` (32 bytes)
  - `MixHash(rs_mlkem512_ek)` (800 bytes)

### 4.2 Message Flight 1 (Initiator $\rightarrow$ Responder)
Pattern: `-> e, es, s, ss, skem, payload`
1. `e`: Initiator generates ephemeral X25519 keypair $e_i$. Writes $e_i.\text{public}$ (32 B). `MixHash(&e_i.public)`.
2. `es`: Computes $\text{X25519}(e_i.\text{secret}, rs_{\text{X25519}})$. Enforces constant-time non-zero check via `subtle::ConstantTimeEq` (rejects all-zeros). `k_1 = MixKey(&dh_es)`. Zeroizes `dh_es`.
3. `s`: Encrypts $s_i.\text{public}$ with $k_1$ using `ChaCha20Poly1305` (`ad = h`). Writes 48 bytes (32 B ciphertext + 16 B MAC). `MixHash(enc_s)`.
4. `ss`: Computes $\text{X25519}(s_i.\text{secret}, rs_{\text{X25519}})$. Enforces constant-time non-zero check. `k_2 = MixKey(&dh_ss)`. Zeroizes `dh_ss`.
5. `skem`: Encapsulates against $rs_{\text{MLKEM512\_EK}}$, producing $(ct_{\text{KEM}}\,[768\text{ B}], ss_{\text{KEM}}\,[32\text{ B}])$. Writes $ct_{\text{KEM}}$ in plaintext (768 B). `MixHash(&ct_KEM)`. `k_3 = MixKey(&ss_KEM)`. Zeroizes `ss_KEM`.
6. `payload`: Mandatory authenticated AEAD envelope under $k_3$ with `ad = h`. Even when application payload is 0 bytes, this step writes at least a 16-byte Poly1305 MAC, ensuring `ct_KEM` and `ss_KEM` are cryptographically authenticated before the Responder commits state.

*Flight 1 Framing Overhead*: $32\text{ B } (e) + 48\text{ B } (s) + 768\text{ B } (ct) + 16\text{ B } (\text{MAC}) = 864$ bytes base cryptographic overhead.

### 4.3 Message Flight 2 (Responder $\rightarrow$ Initiator & Split)
Pattern: `<- e, ee, se, psk, payload`
1. `e`: Responder generates ephemeral X25519 keypair $e_r$. Writes $e_r.\text{public}$ (32 B). `MixHash(&e_r.public)`.
2. `ee`: Computes $\text{X25519}(e_r.\text{secret}, e_i.\text{public})$. Enforces constant-time non-zero check. `k_4 = MixKey(&dh_ee)`. Zeroizes `dh_ee`.
3. `se`: Computes X25519(s_i.public, e_r.secret) on responder / X25519(s_i.secret, e_r.public) on initiator. Enforces constant-time non-zero check. `k_5 = MixKey(&dh_se)`. Zeroizes `dh_se`.
4. `psk`: `k_6 = MixKeyAndHash(&psk)`.
5. `payload`: Encrypts handshake payload with $k_6$ (`ad = h`). Writes ciphertext + 16 B Poly1305 MAC.
6. `Split()`: Invokes `symmetric.split()` to emit directional 32-byte transport AEAD keys.

*Flight 2 Framing Overhead*: $32\text{ B } (e) + 16\text{ B } (\text{MAC}) = 48$ bytes base cryptographic overhead.

---

## 5. Overlay Addressing, Rendezvous Identity, & Subsystem Boundaries

### 5.1 Self-Certifying IPv6 Overlay Addressing (`bin/yipd/src/addr.rs`)
Derives immutable node addresses in the `fd00::/8` ULA space using `blake3::derive_key`:

```rust
pub const OVERLAY_ADDR_CONTEXT_V2: &str = "yip-v2-overlay-ipv6-addr";

pub fn derive_overlay_ipv6(public_key: &[u8; 32]) -> std::net::Ipv6Addr {
    let digest = blake3::derive_key(OVERLAY_ADDR_CONTEXT_V2, public_key);
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..16].copy_from_slice(&digest[0..15]);
    std::net::Ipv6Addr::from(octets)
}
```

### 5.2 Rendezvous Protocol (`crates/yip-rendezvous/src/proto.rs`)
- **Peer Identity**:
  ```rust
  pub const RENDEZVOUS_NODE_ID_CONTEXT_V2: &str = "yip-v2-rendezvous-node-id";

  pub fn derive_node_id(public_key: &[u8; 32]) -> [u8; 16] {
      let digest = blake3::derive_key(RENDEZVOUS_NODE_ID_CONTEXT_V2, public_key);
      let mut node_id = [0u8; 16];
      node_id.copy_from_slice(&digest[0..16]);
      node_id
  }
  ```
- **Registration MAC**: Computed via `blake3::keyed_hash(&shared_secret, payload)` and truncated to 16 bytes. Verified in constant time.

### 5.3 Data-Plane Hotpath Boundary
- `crates/yip-wire` (header protection, sequence counters, and coverage MACs) and `crates/yip-obf` (anti-DPI masking envelope) **retain `SipHash-1-3`**.
- Data-plane packet payload confidentiality and authenticity are handled by `ChaCha20Poly1305` (with hardware AES-GCM offload). BLAKE3 is not invoked per data packet.

---

## 6. Dependency & Workspace Changes

### Cargo.toml Workspace Root
- **Remove**:
  - `snow = "0.10.0"`
  - `blake2 = "=0.10.6"`
  - `hkdf` (if explicitly present)
  - `hmac` (if explicitly present)
- **Add**:
  ```toml
  blake3 = { version = "1.8", default-features = false, features = ["zeroize"] }
  ```

---

## 7. Testing, Verification, & Migration Plan

1. **Deterministic Test Vectors**:
   - Create `crates/yip-crypto/tests/pqnoise_vectors.rs` testing known static keys, ephemeral keys, and PSKs against recorded hex dumps of `ck`, `h`, and split keys.
2. **Replay & Corruption Tests**:
   - Ensure corrupted ML-KEM-512 ciphertexts or modified Flight 1 payloads trigger Poly1305 MAC failure and abort the handshake with zero state leakage.
   - Enforce atomic Responder verification: `read_message_1` verifies static key authorization and payload MAC before committing any state to long-lived session stores. On failure, all intermediate state is wiped via `zeroize`.
   - Validate constant-time rejection of all-zero Diffie-Hellman outputs (`ct_eq(&[0u8; 32])`) on low-order point attacks.
3. **Address Derivation Compatibility**:
   - Update address derivation unit tests and shell integration scripts (`run-netns-registration-hijack.sh`) to the v2 context strings and expected hashes.
4. **CI Gates**:
   - Enforce `-D warnings`, `cargo clippy --workspace --all-targets`, `cargo test --workspace`, and `cargo deny check`.
