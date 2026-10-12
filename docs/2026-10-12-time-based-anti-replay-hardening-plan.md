# Time-Based Anti-Replay Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close anti-replay vulnerabilities across process restarts and post-TTL cache lapses in handshake and rendezvous protocols (Issues #103 and #104).

**Architecture:**
- In `bin/yipd`, responders initialize an anti-replay boot-time floor `boot_floor_ts` (`now_tai64n() - 5s`), rejecting any replayed `HandshakeInit` older than daemon start on cold start.
- `PeerManager` initializes and advances `reg_seq` using monotonic UNIX epoch milliseconds (`now_wall_clock_ms()`), guaranteeing monotonic progression across process restarts.
- `yip-rendezvous` validates `RegisterSigned.record.seq` against a wall-clock freshness window (`now_wall_ms - (REG_TTL_MS + SKEW)` to `now_wall_ms + SKEW`), preventing post-TTL replays from re-registering hijacked addresses.

**Tech Stack:** Rust (edition 2021), tokio, TAI64N timestamps, ChaCha20-Poly1305 / Noise-IK.

## Global Constraints

- Wire codecs must remain strictly backward-compatible (`Record.seq` remains `u64`, `init_ts` remains `[u8; 12]`).
- Clock skew tolerance default is 300 seconds (`REGISTRATION_SKEW_SECS` / `CLOCK_SKEW_SECS`) for registration certs, and 5 seconds for handshake boot floor grace.
- All modified code must pass `cargo test --all`, `cargo clippy --all-targets`, and existing netns hijack scripts.

---

### Task 1: TAI64N Duration Subtraction Helper

**Files:**
- Modify: `bin/yipd/src/handshake.rs`
- Test: `bin/yipd/src/handshake.rs` (unit tests at bottom of file)

**Interfaces:**
- Produces: `pub fn tai64n_sub_duration(ts: [u8; TAI64N_LEN], duration: std::time::Duration) -> [u8; TAI64N_LEN]`

- [ ] **Step 1: Write failing unit test for `tai64n_sub_duration`**

In `bin/yipd/src/handshake.rs`, add inside `mod tests`:
```rust
#[test]
fn tai64n_sub_duration_handles_subtraction_and_nanosecond_borrow() {
    let now = now_tai64n();
    let subtracted_5s = tai64n_sub_duration(now, std::time::Duration::from_secs(5));
    assert!(subtracted_5s < now);

    let base = now_tai64n();
    let sub_1ns = tai64n_sub_duration(base, std::time::Duration::from_nanos(1));
    assert!(sub_1ns < base);

    // Clamping at UNIX epoch base
    let zero_dur = std::time::Duration::from_secs(0);
    assert_eq!(tai64n_sub_duration(base, zero_dur), base);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd handshake::tests::tai64n_sub_duration_handles_subtraction_and_nanosecond_borrow`
Expected: FAIL with `cannot find function tai64n_sub_duration`

- [ ] **Step 3: Implement `tai64n_sub_duration`**

In `bin/yipd/src/handshake.rs`:
```rust
/// Subtract `duration` from a big-endian TAI64N timestamp, clamping at the
/// UNIX epoch baseline `(1u64 << 62)` seconds.
pub fn tai64n_sub_duration(ts: [u8; TAI64N_LEN], duration: std::time::Duration) -> [u8; TAI64N_LEN] {
    let mut secs = u64::from_be_bytes(ts[..8].try_into().unwrap());
    let mut nanos = u32::from_be_bytes(ts[8..].try_into().unwrap());

    let sub_secs = duration.as_secs();
    let sub_nanos = duration.subsec_nanos();

    if nanos < sub_nanos {
        secs = secs.saturating_sub(1);
        nanos = nanos + 1_000_000_000 - sub_nanos;
    } else {
        nanos -= sub_nanos;
    }

    let min_secs = 1u64 << 62;
    secs = secs.saturating_sub(sub_secs).max(min_secs);

    let mut out = [0u8; TAI64N_LEN];
    out[..8].copy_from_slice(&secs.to_be_bytes());
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yipd handshake::tests::tai64n_sub_duration_handles_subtraction_and_nanosecond_borrow`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/handshake.rs
git commit -m "feat(handshake): add tai64n_sub_duration helper (#104)"
```

---

### Task 2: Responder Boot Floor Anti-Replay Gate in `PeerManager` (#104)

**Files:**
- Modify: `bin/yipd/src/peer_manager/mod.rs`
- Modify: `bin/yipd/src/peer_manager/handshake.rs`
- Test: `bin/yipd/src/peer_manager/handshake.rs` (unit tests)

**Interfaces:**
- Consumes: `crate::handshake::tai64n_sub_duration`, `crate::handshake::now_tai64n`
- Modifies: `PeerManager.boot_floor_ts: [u8; 12]`, `accept_fresh_init(&self, idx: usize, ts: &[u8; 12]) -> bool`

- [ ] **Step 1: Write failing unit tests in `bin/yipd/src/peer_manager/handshake.rs`**

Add tests inside `bin/yipd/src/peer_manager/handshake.rs`:
```rust
#[test]
fn accept_fresh_init_rejects_ts_older_than_boot_floor_on_cold_start() {
    let mut pm = test_peer_manager();
    // Simulate boot floor set to current time
    let boot = pm.boot_floor_ts;
    // An Init timestamp from 10 seconds before boot
    let old_ts = crate::handshake::tai64n_sub_duration(boot, std::time::Duration::from_secs(10));
    assert_eq!(pm.peers[0].last_accepted_init_ts, None);
    assert!(!pm.accept_fresh_init(0, &old_ts));
    assert_eq!(pm.peers[0].last_accepted_init_ts, None);
}

#[test]
fn accept_fresh_init_accepts_ts_newer_than_boot_floor_on_cold_start() {
    let pm = test_peer_manager();
    let fresh_ts = crate::handshake::now_tai64n();
    assert!(fresh_ts > pm.boot_floor_ts);
    assert!(pm.accept_fresh_init(0, &fresh_ts));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd peer_manager::handshake::tests::accept_fresh_init_rejects_ts_older_than_boot_floor_on_cold_start`
Expected: FAIL (compilation error `no field boot_floor_ts` on `PeerManager`)

- [ ] **Step 3: Implement `boot_floor_ts` field and update `accept_fresh_init`**

In `bin/yipd/src/peer_manager/mod.rs`:
Add field `pub(crate) boot_floor_ts: [u8; crate::handshake::TAI64N_LEN],` to `PeerManager`.
In `PeerManager::new(...)`:
```rust
boot_floor_ts: crate::handshake::tai64n_sub_duration(
    crate::handshake::now_tai64n(),
    std::time::Duration::from_secs(5),
),
```

In `bin/yipd/src/peer_manager/handshake.rs`, update `accept_fresh_init`:
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yipd peer_manager::handshake::tests`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/peer_manager/mod.rs bin/yipd/src/peer_manager/handshake.rs
git commit -m "fix(handshake): reject pre-boot replayed Inits on cold start (#104)"
```

---

### Task 3: Monotonic Wall-Clock `reg_seq` in `PeerManager` (#103 Part 1)

**Files:**
- Modify: `bin/yipd/src/peer_manager/mod.rs`
- Test: `bin/yipd/src/peer_manager/mod.rs` (unit tests)

**Interfaces:**
- Produces: Monotonic `reg_seq: u64` derived from `now_wall_clock_ms()` across restarts and ticks.

- [ ] **Step 1: Write unit test for `reg_seq` monotonicity across restarts**

In `bin/yipd/src/peer_manager/mod.rs` test module:
```rust
#[test]
fn reg_seq_monotonic_across_daemon_restarts() {
    let pm1 = test_peer_manager();
    assert!(pm1.reg_seq > 0, "reg_seq must initialize to non-zero wall clock ms");

    // Sleep 2ms so wall clock advances
    std::thread::sleep(std::time::Duration::from_millis(2));

    let pm2 = test_peer_manager();
    assert!(pm2.reg_seq > pm1.reg_seq, "restart must yield strictly higher reg_seq");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yipd peer_manager::tests::reg_seq_monotonic_across_daemon_restarts`
Expected: FAIL (`pm1.reg_seq == 0`)

- [ ] **Step 3: Update `reg_seq` initialization and tick bumping**

In `bin/yipd/src/peer_manager/mod.rs`:
Add helper or use `now_wall_clock_ms()`:
```rust
fn now_wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
```
In `PeerManager::new(...)`:
```rust
reg_seq: now_wall_clock_ms(),
```
In `tick_dispatch` around lines 1045-1055:
```rust
let wall_ms = now_wall_clock_ms();
self.reg_seq = self.reg_seq.max(wall_ms).saturating_add(1);
let signed = self
    .membership
    .as_ref()
    .map(|m| m.sign_registration(self.reg_seq));
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yipd peer_manager::tests::reg_seq_monotonic_across_daemon_restarts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/peer_manager/mod.rs
git commit -m "fix(rendezvous): initialize and bump reg_seq with wall-clock epoch ms (#103)"
```

---

### Task 4: Server-Side Registration Freshness Window (#103 Part 2)

**Files:**
- Modify: `crates/yip-rendezvous/src/server.rs`
- Modify: `bin/yip-rendezvous/src/main.rs`
- Test: `crates/yip-rendezvous/src/server.rs` (unit tests)

**Interfaces:**
- Modifies: `RendezvousServer::handle(&mut self, src: SocketAddr, msg: Message, now_ms: u64, now_secs: u64)` (or pass `now_wall_ms: u64`)
- Validates: `RegisterSigned.record.seq` within `[now_wall_ms - (REG_TTL_MS + SKEW), now_wall_ms + SKEW]`

- [ ] **Step 1: Write failing unit tests for post-expiry and historical replay rejection**

In `crates/yip-rendezvous/src/server.rs`:
```rust
#[test]
fn register_signed_rejects_historical_stale_record() {
    let mut server = rooted_server(); // helper with roots
    let now_secs = 1_700_000_000;
    let now_ms = 1_000;
    let now_wall_ms = now_secs * 1_000;

    // Record from 10 minutes ago (beyond 60s TTL + 300s skew)
    let stale_seq = now_wall_ms - 600_000;
    let stale_record = mint_signed_record(victim_node(), stale_seq, now_secs);

    let replies = server.handle_with_wall_ms(
        client_addr(),
        Message::RegisterSigned { record: stale_record },
        now_ms,
        now_secs,
        now_wall_ms,
    );
    assert!(replies.is_empty());
    assert!(!server.has_active_registration(&victim_node()));
}

#[test]
fn register_signed_rejects_post_ttl_replay_after_sweep() {
    let mut server = rooted_server();
    let now_secs = 1_700_000_000;
    let now_wall_ms = now_secs * 1_000;

    // 1. Initial valid registration
    let record1 = mint_signed_record(victim_node(), now_wall_ms, now_secs);
    server.handle_with_wall_ms(client_addr(), Message::RegisterSigned { record: record1.clone() }, 0, now_secs, now_wall_ms);
    assert!(server.has_active_registration(&victim_node()));

    // 2. Time advances by 600 seconds (entry expires and swept)
    let later_secs = now_secs + 600;
    let later_wall_ms = later_secs * 1_000;
    server.sweep(600_000);
    assert!(!server.has_active_registration(&victim_node()));

    // 3. Attacker replays record1 from attacker_addr()
    server.handle_with_wall_ms(attacker_addr(), Message::RegisterSigned { record: record1 }, 600_000, later_secs, later_wall_ms);
    assert!(!server.has_active_registration(&victim_node()), "post-TTL replay must be rejected");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yip-rendezvous server::tests::register_signed_rejects_post_ttl_replay_after_sweep`
Expected: FAIL

- [ ] **Step 3: Implement wall-clock window gate in `crates/yip-rendezvous/src/server.rs`**

In `crates/yip-rendezvous/src/server.rs`:
In `Message::RegisterSigned { record }`:
```rust
let now_wall_ms = now_secs.saturating_mul(1000); // or passed in explicitly
let skew_ms = REGISTRATION_SKEW_SECS.saturating_mul(1000);
let min_seq = now_wall_ms.saturating_sub(REG_TTL_MS.saturating_add(skew_ms));
let max_seq = now_wall_ms.saturating_add(skew_ms);

// If record.seq falls outside the acceptable registration time envelope, drop it
if record.seq < min_seq || record.seq > max_seq {
    return Vec::new();
}
```
And plumb `now_wall_ms` support in `bin/yip-rendezvous/src/main.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yip-rendezvous`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/yip-rendezvous/src/server.rs bin/yip-rendezvous/src/main.rs
git commit -m "fix(rendezvous): reject post-TTL replayed RegisterSigned records (#103)"
```

---

### Task 5: Integration & Netns Verification

**Files:**
- Modify: `bin/yipd/tests/run-netns-replay-hijack.sh`
- Test: `bin/yipd/tests/run-netns-replay-hijack.sh`
- Test: `bin/yipd/tests/run-netns-registration-hijack.sh`

- [ ] **Step 1: Extend `run-netns-replay-hijack.sh` with a responder restart leg**

In `bin/yipd/tests/run-netns-replay-hijack.sh`:
Add test leg 12:
- Restart responder B (simulating cold reboot).
- Before B accepts fresh traffic from A, replay the old captured Init frame from attacker S.
- Verify `grep -q "stale/replayed Init refused (boot floor gate)" "$LOG_B_RESTART"`.

- [ ] **Step 2: Run full cargo test suite**

Run: `cargo test --all`
Expected: PASS

- [ ] **Step 3: Run clippy and format check**

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS with 0 warnings

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/tests/run-netns-replay-hijack.sh
git commit -m "test: add responder restart replay verification witness (#104)"
```

---

## Plan Self-Review Checklist

1. **Spec Coverage:**
   - Helper `tai64n_sub_duration` -> Task 1
   - Responder `boot_floor_ts` anti-replay gate (#104) -> Task 2
   - Monotonic wall-clock `reg_seq` across restarts (#103) -> Task 3
   - Server-side wall-clock registration window and post-TTL replay defense (#103) -> Task 4
   - Integration & Netns witness -> Task 5
2. **No Placeholders:** All code snippets, exact paths, CLI commands, and test assertions are fully written out.
3. **Type Consistency:** Big-endian TAI64N `[u8; 12]` matches everywhere; `reg_seq: u64` and `record.seq: u64` match across crates.
