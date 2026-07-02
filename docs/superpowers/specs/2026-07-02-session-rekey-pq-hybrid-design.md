# Session rekey (~120s) + PQ-hybrid handshake path - design

**Status:** approved (design, 2026-07-02)
**Issue:** #9
**Scope:** daemon/session lifecycle + crypto interfaces for periodic rekey and PQ-hybrid follow-up

## Goal

Add periodic session rotation (~120 s) with a bounded overlap window, epoch-aware packet routing, and per-epoch `conn_tag` rotation, while preserving current wire compatibility. Define the interface seam for a later Rosenpass-style PQ PSK injection path without forcing a wire break now.

## Non-goals

- No control-plane discovery/NAT changes.
- No anti-DPI format redesign in this issue.
- No mandatory wire-format change in phase 1.

## Current baseline

- One startup Noise-IK handshake creates one `Session` for process lifetime.
- `conn_tag` is derived once from handshake-derived wire keys and remains static.
- `PacketType::Data` carries an authenticated wire header with `conn_tag`; `PacketType::Control` currently carries only `[type][counter][ciphertext]`.
- `Session` replay/counter state is per session and resets when a new session is created.

This baseline causes forward-secrecy drift and a static linkability surface (`conn_tag`).

## Design summary

Implement rekey in two explicit phases:

1. **Phase A (this issue implementation target): classical rekey**
   - Periodic Noise-IK re-handshake every ~120 s (with jitter).
   - Epoch state with overlap: `current` + at most `previous`.
   - Per-epoch `conn_tag` rotation.
   - Epoch-aware routing for data/control traffic without changing wire format.
2. **Phase B (follow-up under this spec): PQ-hybrid rekey**
   - Add external PSK injection to the Noise handshake path (`NOISE_PARAMS` PSK variant).
   - Keep the same daemon epoch/rekey machinery from phase A.

## Epoch model

### Epoch identity and lifecycle

Each successful handshake creates a new epoch:

- `epoch_id: u64` (local monotonic identifier, never on wire in phase A).
- `established_at_ms: u64`.
- `session: yip_crypto::Session`.
- `wire_codec` keys and derived `conn_tag`.
- `state`: `Active` or `Draining`.

At any time, daemon keeps:

- `current_epoch` (Active, used for all new egress sealing/encoding).
- optional `previous_epoch` (Draining, decode-only until overlap expiry).

Bound: max two epochs in memory.

### Rekey timer and jitter

Constants:

- `REKEY_BASE_MS = 120_000` (120 s).
- `REKEY_JITTER_MS = 12_000` (uniform +/-10% jitter).
- `REKEY_RETRY_BASE_MS = 1_000`.
- `REKEY_RETRY_MAX_MS = 8_000`.

Scheduling:

- On epoch establish, sample jitter `j in [-REKEY_JITTER_MS, +REKEY_JITTER_MS]`.
- Next rekey attempt deadline = `established_at_ms + REKEY_BASE_MS + j`.
- Jitter is independent per epoch (prevents lock-step fingerprints between peers).

### Overlap window

Constant:

- `EPOCH_OVERLAP_MS = 15_000`.

Behavior:

- After new epoch is installed, old epoch transitions to `Draining`.
- Old epoch remains decode-only for `EPOCH_OVERLAP_MS`.
- On expiry, old epoch is dropped completely (session/replay state and buffers freed).

15 s is long enough for in-flight packet/FEC completion and short enough to cap replay surface.

## Packet/session routing by epoch

### Data packets

Data already carries `conn_tag` in authenticated header.

Routing algorithm:

1. Try `deframe` with `current` epoch codec.
2. If auth/parse fails, try `deframe` with `previous` epoch codec (if present).
3. On successful deframe, require `frame.conn_tag == epoch.conn_tag` for the codec that succeeded.
4. Parse symbol/counter/class and open with that same epoch's `session`.

Maintain a two-entry active epoch table:

- `{epoch_id, conn_tag, wire_codec, session_ref}` for `current` and optional `previous`.

Unknown `conn_tag` is dropped silently.

### Control packets

Phase A keeps control wire layout unchanged (`[type][counter][ciphertext]`), so no explicit epoch tag exists.

Routing algorithm:

1. Parse counter + ciphertext.
2. Attempt `session.open(counter, ciphertext)` on `current` first.
3. If decrypt/replay fails, attempt once on `previous` if present.
4. First successful open wins; packet is bound to that epoch.
5. If both fail, drop.

Because max epochs is 2, this is bounded and deterministic.

## conn_tag rotation per epoch

`conn_tag` rotates automatically by deriving it from per-epoch wire keys (which are derived from each epoch handshake channel binding).

Rules:

- New epoch MUST derive a new `auth_key/hp_key` and new `conn_tag`.
- Egress uses only current epoch `conn_tag`.
- Ingress accepts current + previous `conn_tag` during overlap.
- No static `conn_tag` persists beyond one epoch.

No wire-format change is needed because `conn_tag` is already an existing field.

## Replay and counter implications

### Counter namespace

- Each epoch's `Session` starts send counter at `0` (existing behavior).
- Counter collisions across epochs are valid and expected.
- Epoch routing disambiguates collisions:
  - data: via `conn_tag`;
  - control: via successful decrypt against epoch session.

### Replay windows

- Replay window remains per epoch/session.
- During overlap, each epoch tracks replay independently.
- Dropping old epoch deletes its replay state, closing acceptance for old packets after overlap deadline.

### Side-effect note

Current `Session::open` marks replay before AEAD verification. With two-epoch control probing, one forged control can consume one slot per active epoch. This remains bounded by the two-epoch cap and overlap duration. A stricter mark-on-success replay variant is a valid follow-up hardening item, not required to ship phase A.

## Rekey failure and retry semantics

### Attempt ownership

Role follows existing tunnel mode:

- node started as initiator: initiates rekey handshakes.
- node started as responder: responds whenever it receives a rekey init; does not proactively originate unless explicitly enabled later.

### Retries

If rekey attempt fails:

- Keep old/current epoch active (no traffic stall).
- Schedule retry with exponential backoff:
  - `delay = min(REKEY_RETRY_BASE_MS * 2^n, REKEY_RETRY_MAX_MS)`.
- Retry counter resets after successful rekey.

### Timeout/fallback safety

- Never tear down current epoch before successor is established.
- If peer is unreachable, tunnel continues on current epoch; logs escalate at rate-limited intervals.
- Optional safety valve: force full tunnel reconnect only if no successful rekey for a long horizon (`>= 10 * REKEY_BASE_MS`), guarded by config flag default-off in phase A.

## Interfaces for future PQ PSK injection

Phase A introduces crypto interfaces now, even if PSK source is initially `None`:

### `yip-crypto` interface additions

- Add handshake builder/options surface:
  - `HandshakeMode::ClassicalIk`
  - `HandshakeMode::IkPsk2`
- Add optional PSK input:
  - `psk: Option<[u8; 32]>`

Parameter behavior:

- Classical: `NOISE_PARAMS = "Noise_IK_25519_ChaChaPoly_BLAKE2s"`.
- PSK path: `NOISE_PARAMS_PSK = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"`.

Only select PSK params when `psk.is_some()`. This keeps classical peers interoperable by default.

### Daemon seam

Define a provider trait used by tunnel rekey path:

- `trait RekeyPskProvider { fn current_psk(&self) -> Option<[u8; 32]>; }`

Phase A implementation returns `None`.
Phase B PQ implementation feeds a 32-byte PSK derived from Classic McEliece + ML-KEM result material (Rosenpass model), then hands it to `HandshakeMode::IkPsk2`.

This isolates PQ complexity from dataplane epoch machinery.

## Wire compatibility and migration story

### Phase A compatibility promise

- No mandatory wire-format change.
- Existing `Data` framing is reused (`conn_tag` already present).
- Existing `Control` framing is reused (trial-decrypt routing during overlap).

### Mixed-version behavior

During migration, a new node can talk to an old node only if rekey behavior is gated:

- Config flag `rekey_enabled` default `false` for first release containing phase A code.
- Rollout sequence:
  1. deploy binaries everywhere with code present but disabled;
  2. enable `rekey_enabled=true` fleet-wide (or by compatibility domain);
  3. monitor metrics/logs; then make enabled-by-default in a later release.

If an enabled node detects repeated rekey incompatibility signatures (timeouts/parse failures across many cycles), it should auto-suppress rekey for that peer for a cooldown window and continue forwarding on current epoch.

This avoids a wire break and provides an explicit migration path.

## Observability

Add structured counters/gauges/log fields:

- `rekey_attempt_total{result=success|timeout|error}`
- `rekey_retry_total`
- `rekey_duration_ms`
- `epoch_current_id`
- `epoch_overlap_active` (bool gauge)
- `epoch_old_drop_total`
- `packet_drop_total{reason=unknown_conn_tag|decrypt_fail|replay|epoch_expired}`
- `control_route_total{epoch=current|previous|none}`

Periodic logs (rate-limited) include:

- next rekey deadline and jitter;
- current+previous conn_tag hashes (never raw keys);
- overlap start/expiry timestamps;
- last successful rekey age.

## Tests

### Unit tests

`yip-crypto`:

- classical and `IKpsk2` handshake constructors select correct Noise params.
- `psk=None` path is wire-compatible with current behavior.

`yipd` epoch manager:

- timer+jitter bounds (`[108s, 132s]`).
- successful rekey installs new current and preserves previous for overlap.
- overlap expiry drops previous exactly at deadline.
- data routing by conn_tag chooses correct epoch.
- control routing picks current first, then previous fallback.
- counter collision across epochs still decrypts correctly via routing.

### Integration tests (netns)

- tunnel stays up across multiple rekeys under ping and bulk traffic.
- induced loss/reordering around rekey boundary does not cause prolonged outage.
- old-epoch packets accepted inside overlap and rejected after overlap.
- conn_tag changes every epoch (no reuse across successive rekeys).

### Regression checks

- with `rekey_enabled=false`, behavior and packet formats match current baseline.
- forced `YIP_FORCE_POLL=1` and default driver both pass rekey tests.

## Rollout plan

1. Land phase A code behind `rekey_enabled=false`.
2. Land epoch/rekey observability.
3. Run soak tests in netns and constrained staging.
4. Enable `rekey_enabled` in controlled cohorts.
5. Promote to default-on after stability window.
6. Implement phase B PQ provider + PSK mode on same epoch manager.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Control packet lacks explicit epoch tag in phase A | bounded two-epoch trial decrypt, current-first deterministic routing |
| Replay-slot consumption by forged controls across two epochs | overlap bounded to 15 s, max two epochs, rate-limited logging, optional hardening follow-up |
| Mixed-version rekey incompatibility | feature-gated rollout (`rekey_enabled`), peer cooldown suppression, no mandatory wire change |
| Rekey storms creating timing fingerprint | per-epoch jitter (+/-10%), bounded retries with backoff |

## Definition of done for issue #9

- Approved and implemented classical rekey with epoch overlap and conn_tag rotation.
- No mandatory wire-format break; migration path documented and executable.
- PQ-hybrid seam (`IKpsk2` + PSK provider interface) is present and ready for follow-up implementation.
