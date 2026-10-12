# Time-Based Anti-Replay Hardening Design (Issues #103 & #104)

**Status:** Approved design spec
**Date:** 2026-10-12
**Target Issues:**
- [#103: security(rendezvous): registration is replayable after TTL lapse + reg_seq resets on restart](https://github.com/femboyisp/yip/issues/103)
- [#104: security(handshake): #34 anti-replay baseline is in-memory only](https://github.com/femboyisp/yip/issues/104)

---

## 1. Overview & Context

`yip` uses Noise-IK handshakes and authenticated rendezvous/mesh registration to establish secure peer tunnels and discovery paths. While cryptographic confidentiality and forward secrecy are provided by Noise and ChaCha20-Poly1305, both the handshake and rendezvous subsystems currently possess transient replay/desync vulnerabilities across daemon restarts and cache expirations:

1. **Issue #104 (Responder Boot-Time Anti-Replay Window):**
   In `PeerManager::accept_fresh_init`, if `last_accepted_init_ts` is `None` (uninitialized on cold start/restart), any incoming `HandshakeInit` is accepted as fresh. An attacker who previously captured a valid Init packet from a past session can replay it against a restarted responder. While Noise-IK prevents unauthorized completion of the session, the responder temporarily learns the attacker's source address as the peer's endpoint, causing transient traffic blackholing and disruption.

2. **Issue #103 (Rendezvous Post-TTL Replay & Restart Counter Reset):**
   In `PeerManager`, `reg_seq: u64` is an in-memory counter initialized to 0 that increments by 1 per registration. On daemon restart, `reg_seq` resets to 0. If the rendezvous server holds a previous counter (e.g. 50), the restarted daemon cannot register until the 60s TTL lapses. Furthermore, on `yip-rendezvous`, `register_if_fresh` only enforces monotonic counters while an unexpired entry exists; once the 60s `REG_TTL_MS` expires and sweep evicts the entry, any old, captured (but still signature-valid) `RegisterSigned` packet can be replayed to re-register the victim node pointing to the attacker's reflexive address.

This design closes both vulnerabilities by anchoring sequences and baselines to monotonic wall-clock time across process restarts.

---

## 2. Architecture & Components

### 2.1 Handshake Boot-Time Floor (#104)

#### Component: `bin/yipd/src/handshake.rs`
- Add helper `tai64n_sub_duration(ts: [u8; 12], duration: std::time::Duration) -> [u8; 12]`:
  Safely subtracts `duration` from a big-endian TAI64N timestamp (accounting for nanosecond borrows and second decrements), clamping at UNIX epoch baseline (`1u64 << 62` seconds).

#### Component: `bin/yipd/src/peer_manager`
- In `PeerManager` (struct definition in `bin/yipd/src/peer_manager/mod.rs`):
  Add `boot_floor_ts: [u8; 12]`.
  In `PeerManager::new(...)`:
  ```rust
  let boot_floor_ts = tai64n_sub_duration(now_tai64n(), Duration::from_secs(5));
  ```
  A 5-second grace window accommodates small NTP skew and genuine in-flight packets in transit at daemon restart, while rejecting historical packets from previous sessions.
- In `PeerManager::accept_fresh_init` (`bin/yipd/src/peer_manager/handshake.rs`):
  ```rust
  pub(super) fn accept_fresh_init(&self, idx: usize, ts: &[u8; 12]) -> bool {
      match self.peers[idx].last_accepted_init_ts {
          None => {
              let fresh = *ts > self.boot_floor_ts;
              if !fresh {
                  eprintln!("peer_manager: stale/replayed Init refused (boot floor gate)");
              }
              fresh
          }
          Some(last) => {
              let fresh = *ts > last;
              if !fresh {
                  eprintln!("peer_manager: stale/replayed Init refused (freshness gate)");
              }
              fresh
          }
      }
  }
  ```
- **Session teardown:** `drop_session` continues to preserve `last_accepted_init_ts` in memory.

---

### 2.2 Rendezvous Registration Monotonic Wall-Clock Sequence (#103)

#### Component: `bin/yipd/src/peer_manager`
- Replace in-memory counter increment with wall-clock epoch milliseconds in `bin/yipd/src/peer_manager/mod.rs`:
  - `reg_seq: u64` initialized in `PeerManager::new`:
    ```rust
    reg_seq: now_wall_clock_ms(),
    ```
  - In `tick_dispatch` when refreshing registration:
    ```rust
    let wall_ms = now_wall_clock_ms();
    self.reg_seq = self.reg_seq.max(wall_ms).saturating_add(1);
    let signed = self.membership.as_ref().map(|m| m.sign_registration(self.reg_seq));
    ```
  - Guarantee:
    - Daemon restarts initialize `reg_seq` to a strictly larger timestamp than prior executions.
    - Local monotonicity is guaranteed by `.max(wall_ms).saturating_add(1)` even during negative clock drift or rapid ticks.

#### Component: `crates/yip-rendezvous/src/server.rs`
- In `RendezvousServer::handle`:
  Plumb wall-clock milliseconds `now_wall_ms: u64` (in addition to monotonic loop milliseconds `now_ms: u64` and wall seconds `now_secs: u64`).
- For `Message::RegisterSigned { record }`:
  1. Verify certificate and record signature against trusted roots.
  2. Enforce wall-clock acceptance window:
     - `min_seq = now_wall_ms.saturating_sub(REG_TTL_MS + (REGISTRATION_SKEW_SECS * 1000))`
     - `max_seq = now_wall_ms.saturating_add(REGISTRATION_SKEW_SECS * 1000)`
     - If `record.seq < min_seq || record.seq > max_seq`, drop the packet without registration.
  3. Enforce active entry monotonicity:
     - If an unexpired entry for `record.node_id` exists in `self.regs`, `record.seq > existing.last_counter` must hold.
- In `bin/yip-rendezvous/src/main.rs`:
  Compute `now_wall_ms` via `SystemTime::now()` and pass to `server.handle`.

---

## 3. Data Flow & State Transitions

### Handshake Ingress
```
Incoming HandshakeInit
         │
         ▼
Noise-IK decrypt payload -> extract init_ts [u8; 12]
         │
         ▼
accept_fresh_init(idx, &init_ts)
   ├── last_accepted_init_ts == None
   │        └── init_ts > boot_floor_ts ?
   │                 ├── YES: accept, set last_accepted_init_ts = init_ts
   │                 └── NO:  reject with "boot floor gate" warning
   └── last_accepted_init_ts == Some(last)
            └── init_ts > last ?
                     ├── YES: accept, set last_accepted_init_ts = init_ts
                     └── NO:  reject with "freshness gate" warning
```

### Rendezvous Registration Ingress
```
Incoming RegisterSigned
         │
         ▼
Verify signature against roots (now_secs ± SKEW)
         │
         ▼
Check wall-clock bounds:
   now_wall_ms - (REG_TTL_MS + SKEW) <= record.seq <= now_wall_ms + SKEW
         │
         ├── NO: drop (reject replay or future forgery)
         └── YES:
              │
              ▼
   Check existing active registration in self.regs:
      ├── None / expired: accept and insert into self.regs
      └── Some(unexpired): record.seq > existing.last_counter ?
              ├── YES: accept and update self.regs
              └── NO:  drop (stale sequence)
```

---

## 4. Error Handling & Invariants

- **Clock Drift & Skew:**
  - `REGISTRATION_SKEW_SECS = 300` (5 minutes) matches the existing cert-validity skew across `yipd` and `yip-rendezvous`.
  - Initiator/responder handshake skew is tolerated up to 5 seconds across restarts via `boot_floor_ts`.
- **Wire Compatibility:**
  - `Record.seq` and `Register.counter` remain `u64`.
  - Wire codecs are unchanged.
- **Fail-Closed Security:**
  - Replays of captured Init packets or Register packets are silently dropped or logged to stderr without disrupting active state.

---

## 5. Testing & Verification

1. **Unit Tests:**
   - `bin/yipd/src/peer_manager/handshake.rs`:
     - `accept_fresh_init_rejects_pre_boot_ts`: Cold-start Init with timestamp $\le$ `boot_floor_ts` is rejected.
     - `accept_fresh_init_accepts_fresh_ts`: Cold-start Init with timestamp $>$ `boot_floor_ts` is accepted and advances baseline.
     - `tai64n_sub_duration_correctness`: Correct arithmetic on TAI64N seconds and nanoseconds.
   - `crates/yip-rendezvous/src/server.rs`:
     - `register_signed_rejects_stale_wall_clock`: Old sequence before `min_seq` rejected.
     - `register_signed_rejects_post_expiry_replay`: Capturing a valid registration, sweeping cache, and replaying is rejected.
     - `register_signed_accepts_valid_seq_and_advances`: Valid timestamp within window registered, subsequent monotonically higher sequence accepted.
   - `bin/yipd/src/peer_manager/mod.rs`:
     - `reg_seq_monotonic_across_simulated_restart`: Verification that re-instantiating `PeerManager` produces higher `reg_seq`.
2. **Netns Integration Tests:**
   - `bin/yipd/tests/run-netns-replay-hijack.sh`: Passes cleanly, with extended witness verifying responder restart rejection.
   - `bin/yipd/tests/run-netns-registration-hijack.sh`: Passes cleanly.
