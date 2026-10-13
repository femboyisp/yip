# Design Specification: Data-Plane Obfuscation Key Rotation Per Epoch (#105)

## 1. Problem Statement & Motivation
In `yip`'s anti-DPI subsystem, data-plane datagrams between established peers are wrapped in an obfuscation envelope using a SipHash-CTR keystream keyed by a 16-byte key and an 8-byte random nonce (`crates/yip-obf`).

Prior to this fix, `session_obf_key` was derived once at cold start from the initial session's `hp_key` and was deliberately left unrotated across rekeys (`bin/yipd/src/peer_manager/rekey.rs:414-425`). Over the lifetime of a long-running tunnel session, drawing random 8-byte nonces under a static key incurs the birthday bound at approximately $2^{32}$ datagrams (~1 hour at $10^6$ pps). A nonce collision leaks the XOR of the two datagrams' plaintext type/length headers and inner AEAD ciphertexts, degrading the statistical indistinguishability guarantees of the anti-DPI layer.

The blocker to rotating `session_obf_key` during rekey was the confirmed-switch timing gap:
- The responder installs a staged `next` epoch upon answering `HandshakeInit` with `HandshakeResp`.
- The initiator promotes `next -> current` upon receiving `HandshakeResp` and begins transmitting on the new epoch immediately.
- The responder promotes `next -> current` only when it receives its first validated inbound datagram on the new epoch (`EpochSet::inbound_open`).
- Because ingress deobfuscation (`deobf_ingress`) occurs *before* datagram dispatch to `EpochSet`, an ingress trial with a single static `session_obf_key` would reject the initiator's new-epoch datagram, preventing confirmed-switch promotion.

## 2. Proposed Architecture: Epoch-Aware Multi-Key Trial Deobfuscation

### 2.1 Key Lifecycle & Ownership
Instead of maintaining a single static `session_obf_key` on `Peer`:
1. **`DataPlane` Key Ownership:**
   - Each `DataPlane` epoch stores its own derived obfuscation key:
     $$\text{obf\_key} = \begin{cases} \text{Some}(\text{yip\_obf::derive\_key}(\&established.hp\_key)) & \text{if } obf\_on \\ \text{None} & \text{otherwise} \end{cases}$$
   - When obfuscation is disabled (`obf_on = false`), `obf_key` is `None` (preserving zero-allocation and byte-identical behavior).

2. **`EpochSet` Candidate Key Extraction:**
   - `EpochSet` exposes:
     - `current_obf_key(&self) -> Option<[u8; 16]>`: Returns `self.current.obf_key()`.
     - `candidate_obf_keys(&self) -> impl Iterator<Item = [u8; 16]>`: Yields all live candidate keys for ingress deobfuscation:
       1. `self.current.obf_key()`
       2. `self.next.as_ref().and_then(|n| n.dp.obf_key())`
       3. `self.previous.as_ref().and_then(|p| p.obf_key())`

### 2.2 Egress Framing
When transmitting outbound datagrams (`PacketType::Data`, `PacketType::Control`, `PacketType::Gossip`):
- `PeerManager::obf_key_for_egress` queries the destination peer's active `current` epoch obf key via `epochs.current_obf_key()`.
- The active transmitting key always corresponds to the currently confirmed transmitting epoch.

### 2.3 Ingress Trial Deobfuscation & Promotion Sequence
When an obfuscated datagram arrives at `PeerManager::deobf_ingress(src, dg)`:

1. **Known Endpoint Fast-Path (Case a):**
   - For an `Established(epochs)` peer matching `endpoint == Some(src)`:
   - Trial `deobfuscate` with candidate keys from `epochs.candidate_obf_keys()` in order:
     1. `current` key
     2. `next` key (staged epoch, if present)
     3. `previous` key (grace-period epoch, if present)
   - Accept the first candidate that decodes to a valid `PacketType::Data`, `PacketType::Control`, or `PacketType::Gossip` (or drops inert `Junk`).

2. **Roaming Fallback (Case a'):**
   - If `src` is unknown, trial candidate keys across all established peers.

3. **Confirmed Promotion:**
   - When initiator promotes upon receiving `HandshakeResp`, it immediately masks outbound data with the new epoch's key.
   - When responder receives this packet, trial deobfuscation against `next.dp.obf_key()` succeeds.
   - The unmasked packet is passed to `epochs.inbound_open`:
     - Inner AEAD decryption confirms the packet.
     - `next` is promoted to `current`.
     - The old `current` becomes `previous` with a 15-second grace window (`PREVIOUS_EPOCH_GRACE_MS`).
   - Responder is now fully confirmed on the new key, and all its subsequent transmissions use the new key.

4. **In-Flight Grace Window:**
   - Any packets in flight from the responder under the previous epoch's key that arrive after the initiator has promoted will match `previous.dp.obf_key()` and decrypt without loss.

## 3. Wire Format Compatibility & Security Guarantees
- **Zero Wire Changes:** The outer `yip-obf` envelope remains strictly identical (`[len: 2][nonce: 8][masked region]`).
- **Cryptographic Independence:** Keystream unmasking is unauthenticated by design; all security and admission gates are enforced downstream by the inner Noise/AEAD session (`Codec::open`).
- **Birthday-Bound Elimination:** Periodic rekeying rotates the key material before datagram volume approaches $2^{32}$, preventing keystream reuse and header XOR leakage.

## 4. Verification & Testing Strategy
1. **Unit Tests:**
   - `DataPlane::new` derives and exposes `obf_key` from `hp_key` when `obf_on` is true.
   - `EpochSet::candidate_obf_keys` yields active keys across `current`, `next`, and `previous`.
   - `rekey_resp_core` / `install_next` properly rotate and stage keys across simulated rekeys.
   - Ingress deobfuscation accepts packets under `next` and `previous` keys.
2. **Netns & Regression Testing:**
   - Existing netns test suite (`tunnel_netns.rs`) verifying obfuscated tunnels.
   - Clipy with 0 warnings and formatting clean.
