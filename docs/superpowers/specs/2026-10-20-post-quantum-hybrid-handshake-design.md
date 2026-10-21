# Design Specification: Post-Quantum Hybrid Handshake (Noise-IKpsk2 + ML-KEM-512)

**Author:** Zoa Hickenlooper  
**Date:** 2026-10-20  
**Target Milestone:** Issue #9 (Part 9b)  
**Status:** Approved  

---

## 1. Executive Summary

`yip` currently establishes transport sessions using classical Noise-IK (`Noise_IK_25519_ChaChaPoly_BLAKE2s`). While cryptographically sound against classical attackers, classical Diffie-Hellman exchanges over Curve25519 are vulnerable to "Harvest-Now, Decrypt-Later" adversary strategies where encrypted traffic is archived today to be decrypted by future Cryptanalytically Relevant Quantum Computers (CRQCs) using Shor's algorithm.

This specification details the transition of `yip`'s cryptographic handshake to a **Post-Quantum Hybrid Key Exchange** utilizing **`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`** paired with **ML-KEM-512** (FIPS 203 / Kyber).

The design satisfies two non-negotiable operational requirements:
1. **Single-Datagram Fit**: Both handshake messages fit comfortably inside `OBF_MTU_BUDGET = 1200` bytes (Msg1 = 1,028 bytes, Msg2 = 980 bytes), completely avoiding IP fragmentation, chunking overhead, and packet loss amplification on lossy WAN links.
2. **Dual-Layer Defense**: Session keys are derived via HKDF over *both* classical X25519 Diffie-Hellman secrets and ML-KEM-512 post-quantum shared secrets. Breaking the session requires breaking *both* discrete logarithms and the Module Learning with Errors (MLWE) lattice problem simultaneously.

---

## 2. Cryptographic Protocol Specification

### 2.1 Noise Protocol Parameter Set
The Noise Protocol Framework parameter string is:
```text
Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
```
* **Pattern**: `IK` (Initiator knows Responder static public key upfront; authenticates both sides in 1 round trip).
* **Modifier**: `psk2` (Pre-Shared Key mixed into the chaining key at the end of Message 2).
* **DH Function**: `25519` (X25519 scalar multiplication, 32-byte public keys / shared secrets).
* **Cipher**: `ChaChaPoly` (ChaCha20 stream cipher with Poly1305 MAC).
* **Hash Function**: `BLAKE2s` (256-bit cryptographic hash function).

### 2.2 Wire Message Layout & Datagram Budget

```text
Message 1 (Initiator -> Responder):
+------------------------------------------------------------------------+
| Header (4B) | Ephemeral e (32B) | Encrypted Static s (48B)            |
| Encrypted Payload: ML-KEM-512 Encapsulation Key ek (800B)              |
|                    Member Certificate (128B)                          |
|                    Poly1305 Auth Tag (16B)                            |
+------------------------------------------------------------------------+
Total Wire Size: 1,028 bytes (172 bytes headroom under 1,200 MTU budget)

Message 2 (Responder -> Initiator):
+------------------------------------------------------------------------+
| Header (4B) | Ephemeral e (32B)                                        |
| Encrypted Payload: ML-KEM-512 Ciphertext ct (768B)                    |
|                    Member Certificate (128B)                          |
|                    Poly1305 Auth Tag (16B)                            |
+------------------------------------------------------------------------+
Total Wire Size: 980 bytes (220 bytes headroom under 1,200 MTU budget)
```

### 2.3 Post-Quantum Key Encapsulation (ML-KEM-512)
* Standard: **FIPS 203 (ML-KEM)** / Kyber-512.
* Encapsulation Key ($ek$): 800 bytes.
* Decapsulation Key ($dk$): 1,632 bytes (stored in volatile zeroized memory).
* Ciphertext ($ct$): 768 bytes.
* Shared Secret ($ss$): 32 bytes.
* Security Level: NIST Security Category 1 (equivalent to AES-128 against classical and quantum cryptanalysis, $\ge 2^{140}$ quantum gate operations).

---

## 3. Handshake Flow & State Machine

```mermaid
sequenceDiagram
    autonumber
    participant I as Initiator (Node A)
    participant R as Responder (Node B)

    Note over I: 1. Generate Ephemeral X25519 (e_A)<br/>2. Generate Ephemeral ML-KEM-512 (ek_A, dk_A)<br/>3. Format Msg1: payload = ek_A (800B) || Cert_A (128B)
    I->>R: Handshake Message 1 (1,028 bytes)

    Note over R: 4. Noise decrypts Msg1 payload<br/>5. Verify Cert_A against Root Ed25519 CA<br/>6. Generate Ephemeral X25519 (e_B)<br/>7. ML-KEM Encapsulate: (ct, ss) = Encaps(ek_A)<br/>8. MixKey(psk = ss) into Noise state<br/>9. Format Msg2: payload = ct (768B) || Cert_B (128B)
    R->>I: Handshake Message 2 (980 bytes)

    Note over I: 10. Noise decrypts Msg2 payload<br/>11. Verify Cert_B against Root Ed25519 CA<br/>12. ML-KEM Decapsulate: ss = Decaps(dk_A, ct)<br/>13. MixKey(psk = ss) into Noise state<br/>14. Zeroize memory of dk_A

    Note over I,R: Session Established: Split into Send & Recv Transport Keys<br/>Transport: ChaCha20-Poly1305 AEAD + Reed-Solomon RS(8,12) FEC
```

### 3.1 Step-by-Step Operations

1. **Initiator Setup**:
   * Initiator generates classical ephemeral keypair $e_A$ via `snow`.
   * Initiator generates ML-KEM-512 keypair $(ek_A, dk_A)$ via `ml_kem::MlKem512::generate(&mut rng)`.
   * Initiator builds Msg1 payload: `[ek_A (800B) || Cert_A (128B)]`.
   * `snow` encrypts payload under ephemeral Diffie-Hellman intermediate key.

2. **Responder Processing & Response**:
   * Responder decrypts Msg1 payload.
   * Responder extracts and verifies `Cert_A` using Root CA public key. If invalid or expired, abort.
   * Responder extracts `ek_A`.
   * Responder calls `ml_kem::MlKem512::encapsulate(&ek_A, &mut rng)` yielding $(ct, ss)$.
   * Responder feeds $ss$ into `snow` state machine via `handshake_state.set_psk(ss)`.
   * Responder builds Msg2 payload: `[ct (768B) || Cert_B (128B)]`.
   * `snow` completes Msg2 Diffie-Hellman and mixes `psk` into chaining key (`ck`).

3. **Initiator Finalization**:
   * Initiator receives Msg2, decrypts payload via `snow`.
   * Initiator extracts and verifies `Cert_B`.
   * Initiator extracts $ct$ (768 bytes).
   * Initiator calls `ml_kem::MlKem512::decapsulate(&dk_A, &ct)` recovering $ss$.
   * Initiator feeds $ss$ into `snow` state machine via `handshake_state.set_psk(ss)`.
   * Initiator zeroes `dk_A` in memory immediately.
   * Both sides call `snow::HandshakeState::split()` deriving identical send and receive AEAD transport keys.

---

## 4. Periodic Session Rekey Integration (120-Second Rotation)

The post-quantum hybrid handshake is directly bound to `yipd`'s 120-second session rekey rotation mechanism:
* **Fresh Ephemerals**: Every rekey cycle generates a brand-new classical X25519 ephemeral *and* a brand-new ML-KEM-512 ephemeral keypair.
* **Forward Secrecy**: Even if a physical node's memory is dumped hours later, past session traffic cannot be decrypted because all ephemeral $dk$ instances were zeroized upon epoch installation.
* **Zero-Downtime Epoch Overlap**: Outgoing traffic transitions immediately to the new epoch; incoming traffic continues to accept the old epoch for 15 seconds to drain network inflight packets.

---

## 5. Security & Threat Modeling

1. **Adversary with Cryptanalytically Relevant Quantum Computer (CRQC)**:
   * Classical X25519 discrete logs are cracked.
   * The Noise `ck` retains entropy from the ML-KEM-512 shared secret $ss$.
   * Derivation of transport keys remains computationally infeasible ($\ge 2^{140}$ quantum operations).
2. **Adversary Manipulating Ciphertext ($ct$)**:
   * Under ML-KEM-512's Fujisaki-Okamoto transform (FIPS 203 implicit rejection), modified ciphertext produces a deterministic pseudorandom $ss$ that does not match the responder's secret.
   * The resulting Noise MAC fails instantly. No timing leak is exposed.
3. **Replay Attacks**:
   * Handshake messages reuse `yip`'s monotonic timestamp window and anti-replay epoch cache. Replays are dropped at the border.

---

## 6. Implementation & Verification Plan

### 6.1 Affected Crates
* `crates/yip-crypto`:
  * Add `ml-kem = "0.3"` dependency.
  * Update `NOISE_PARAMS` to `"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"`.
  * Update `Handshake::initiator`, `Handshake::responder`, and `Handshake::finalize_initiator`.
* `bin/yipd`:
  * Update handshake buffer sizing constants to accommodate 1,028-byte Msg1 and 980-byte Msg2.
  * Wire PQ rekey state machine into `peer_manager`.

### 6.2 Testing Requirements
* **Unit Tests**:
  * Round-trip PQ handshake producing working transport sessions.
  * Bit-tampered encapsulation key rejection.
  * Bit-tampered ciphertext implicit rejection and subsequent MAC failure.
  * Memory hygiene test confirming $dk$ zeroization.
* **Integration Tests**:
  * Privileged network namespace tunnel test under 5% packet loss with active PQ encryption.
  * 10 consecutive fast-cadence rekey rotations over `poll` and `io_uring` drivers.
* **CI Quality Gates**:
  * Workspace line coverage $\ge 90.00\%$.
  * Zero Clippy warnings (`-D warnings`).
