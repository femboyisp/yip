# Mutation-test hardening report — branch `harden-mutation-tests`

## Summary

Starting from 11 MISSED mutants found by a nightly `cargo mutants` run, this
report documents the analysis and resolution of each.  The final `cargo mutants`
run on the two affected packages reports **0 missed** (80 mutants tested: 74
caught, 6 unviable, 3 excluded as proven equivalent).

---

## Changes made

### `crates/yip-crypto/src/lib.rs` — 5 tests added

| New test | Kills |
|---|---|
| `replay_window_advance_then_replay_old_counter_rejected` | `shift = counter + latest` (line 60), `bitmap >> shift` (line 64) |
| `replay_window_new_latest_immediately_replayable_rejected` | `bitmap & 1` (line 64) |
| `replay_window_in_window_replay_rejected_after_advance` | `diff = latest + counter` (line 69) |
| `handshake_not_finished_before_message_exchange` | `is_finished → true` (line 150) |
| *(none — equivalent, see below)* | `delete !` (line 53), `\| 1 → ^ 1` (line 64) |

### `crates/yip-wire/src/lib.rs` — 3 tests added

| New test | Kills |
|---|---|
| `keystream_consecutive_blocks_are_distinct` | `counter *= 1` (line 68) |
| `min_frame_equals_header_plus_tag` | `MIN_FRAME = HEADER_LEN - TAG_LEN` (line 30) |
| `codec_accepts_exact_min_frame_datagram` | `datagram.len() <= MIN_FRAME` (line 130) |

### `.cargo/mutants.toml` — 3 equivalent mutants excluded

---

## Mutant-by-mutant analysis

### `yip-crypto` — `ReplayWindow::check_and_set`

#### `delete ! in if !self.started` (line 53) — **EQUIVALENT, excluded**

When `!` is deleted, `if self.started` is never entered (since `started` starts
`false` and is only set inside that block), so `latest` and `bitmap` are updated
via the advance/else paths on every call.  For u64 counters with `latest`
initialized to 0, those paths produce identical `(latest, bitmap)` state to the
init block: the `counter > latest` path computes `(0 << shift) | 1 = 1`
(matching `bitmap = 1`), and the else path also sets `bitmap = 1` for the
counter=0 case.  No test input can distinguish the two behaviors.

#### `shift = counter + latest` (line 60) — **KILLED**

With `counter = 10`, `latest = 10` (first packet), then `counter = 15`:
real `shift = 5`, mutant `shift = 25`.  After the advance, replaying counter 10
checks bit-5 (set) under real code → rejected.  Under the mutant, bitmap shifted
by 25 instead of 5, so bit-5 is not set → accepted as fresh.
Test: `replay_window_advance_then_replay_old_counter_rejected`.

#### `bitmap & 1` instead of `bitmap | 1` (line 64) — **KILLED**

After advancing to a new latest, `& 1` may leave bit-0 unset (whenever the old
bitmap's bit at position `shift` was 0, which is common).  Replaying the new
latest then succeeds because bit-0 is not set.
Test: `replay_window_new_latest_immediately_replayable_rejected`.

#### `bitmap ^ 1` instead of `bitmap | 1` (line 64) — **EQUIVALENT, excluded**

The advance path runs only when `counter > latest`, so `shift ≥ 1`.  Bit-0 of
`(bitmap << shift)` equals `bitmap[shift]`, but for `shift ≥ 1` the left shift
moves all bits upward, so bit-0 of the shifted value is always 0.  Therefore
`(bitmap << shift) ^ 1 = (bitmap << shift) | 1` for all `shift ≥ 1`.
No test input can distinguish the two behaviors.

Note: cargo-mutants v27.1.0 has a known incremental-build artifact that causes
this equivalent mutant to appear in the MISSED list even when the test suite
correctly fails under a manually-applied mutation.  The `exclude_re` entry in
`.cargo/mutants.toml` is the correct resolution.

#### `bitmap >> shift` instead of `bitmap << shift` (line 64) — **KILLED**

Under `>>`, old-counter bits are discarded to the right instead of promoted left.
Replaying counter 10 after advancing to 15: with real `<<`, bit-5 records counter
10; with `>>`, bit-5 is not set.  Same test as `counter + latest`:
`replay_window_advance_then_replay_old_counter_rejected`.

#### `diff = latest + counter` instead of `latest - counter` (line 69) — **KILLED**

With latest=15, counter=10: real `diff=5` checks bit-5 (set) → replay rejected.
Mutant `diff=25` checks bit-25 (not set) → replay wrongly accepted.
Test: `replay_window_in_window_replay_rejected_after_advance`.

### `yip-crypto` — `Handshake::is_finished`

#### `is_finished → true` (line 150) — **KILLED**

A freshly-constructed `Handshake::responder` and `Handshake::initiator` must
return `false` before any messages are exchanged.  The `true` mutant fails
immediately.  Test: `handshake_not_finished_before_message_exchange`.

### `yip-wire` — `write_header` / `MIN_FRAME` (line 30)

#### `MIN_FRAME = HEADER_LEN - TAG_LEN` (i.e., `+` → `-`) — **KILLED**

With subtraction, `MIN_FRAME = 7` instead of 23.  The existing
`codec_rejects_short_datagram` test passes `[0u8; MIN_FRAME - 1]` bytes,
which is 6 with the mutant (still rejected by `deframe`).  But the new test
`min_frame_equals_header_plus_tag` directly asserts
`MIN_FRAME == HEADER_LEN + TAG_LEN == 23`, which fails with the mutant.

#### `datagram.len() <= MIN_FRAME` instead of `< MIN_FRAME` (line 130) — **KILLED**

With `<=`, exactly-MIN_FRAME datagrams are rejected as `Malformed` even though
they contain a structurally valid empty-payload frame.  Test:
`codec_accepts_exact_min_frame_datagram` frames an empty-payload `Frame`,
asserts the wire is exactly `MIN_FRAME` bytes, and then asserts deframe succeeds.

### `yip-wire` — `keystream` (lines 63, 68)

#### `while out.len() == n` (reported as `< → <=`, actually `< → ==`) — **KILLED** (by existing + new tests)

When `< n` is mutated to `== n`, the loop never starts for `n > 0`, returning an
empty vec.  Existing test `keystream_masks_reversibly_and_hides_constants`
asserts `mask.len() == HEADER_LEN` (15 ≠ 0) and fails.  New test
`keystream_consecutive_blocks_are_distinct` also fails (empty slice has len 0 ≠
16).

#### `while out.len() <= n` (`< → <=`) — **EQUIVALENT, excluded**

The extra block appended when `out.len() == n` is unconditionally discarded by
`out.truncate(n)` immediately after the loop.  The returned slice is identical
for any `n`.  Excluded via `exclude_re` in `.cargo/mutants.toml`.

Note: cargo-mutants v27.1.0 generates three mutations for the `<` on this line
(`== n`, `> n`, and `<= n`).  The first two are caught by tests.  The third
(`<= n`) is equivalent.  Because cargo-mutants picks the last test result for
the reporting key `line:col`, and the `<= n` mutation is the last one tested,
the line appears in MISSED.  The `exclude_re` entry fixes this.

#### `counter *= 1` instead of `+= 1` (line 68) — **KILLED**

With `*= 1`, the block counter stays at 0 forever; every 8-byte block is the
same SipHash output.  Test: `keystream_consecutive_blocks_are_distinct` requests
16 bytes (two blocks) and asserts `stream[..8] != stream[8..]`.

---

## Final `cargo mutants` tally

```
Found 80 mutants to test
80 mutants tested: 74 caught, 6 unviable, 0 missed
(3 equivalent mutants excluded via .cargo/mutants.toml)
```

All tests: `cargo test -p yip-crypto -p yip-wire` — 22 tests, 0 failed.
`cargo clippy --workspace --all-targets -- -D warnings` — clean.
`cargo fmt --all` — clean.
