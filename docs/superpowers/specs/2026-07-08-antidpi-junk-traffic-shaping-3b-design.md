# Sub-project #3 Milestone 3b: Junk / Decoy Packets + Traffic-Shaping — Design

**Status:** approved (brainstorming complete), ready for implementation planning.
**Sub-project:** #3 (anti-DPI / censorship resistance), milestone 3b. 3a (kill
fixed bytes) is complete/merged.

## Goal

Blur yip's residual **flow-shape** fingerprint — the statistical silhouette a
DPI adversary can see *without* reading packet contents — using junk/decoy
traffic and one more timing-cadence jitter, **without adding any latency to the
data path**. All opt-in behind the existing `obf_psk`, all reusing the 3a
`yip-obf` envelope (no new crate, no wire-format change).

## What 3a already did (and what's left)

3a made every byte on the wire indistinguishable from random (masked type +
random padding, no fixed value/offset/size), and jittered three control
cadences (handshake retry, registration refresh, gossip digest). A
content-reading DPI engine (nDPI) now classifies yip as `Unknown`.

What 3a deliberately left — the residual **flow-shape** signature a statistical
classifier keys on (research R2/R3/R6):

- The handshake is still **exactly 2 packets in a strict A→B→data order** — a
  countable, contentless "connection-opening" fingerprint (nDPI's WireGuard
  dissector tracks exactly this stage sequence).
- The loss-feedback `Control` timer fires at a **dead-constant 30 ms**
  (`FEEDBACK_INTERVAL_MS`, `dataplane.rs`) — a clean ~33 Hz periodic pulse for
  every session's lifetime. (3a's jitter covered only the other three cadences.)

3b targets exactly these two, plus optional idle cover.

## Scope decisions (locked during brainstorming)

1. **Latency-free only.** Junk/padding cost *bandwidth*, never latency. The
   data-plane hot path is NEVER delayed, batched, or rate-shaped. Data-path
   timing manipulation (inter-packet delay injection à la obfs4 `iat-mode`) is
   explicitly **out of scope** — a deferred, explicitly-opt-in "paranoid mode"
   that overlaps sub-project #4 (traffic-analysis defense), not 3b.
2. **Reuse the 3a envelope.** Junk is a new `ptype` in the *same* `yip_obf`
   envelope — same key, same keystream mask, same nonce, same padding — so a
   censor without `obf_psk` cannot distinguish junk from real traffic.
3. **`obf_psk`-gated.** All of 3b is active only when `obf_psk` is set; absent
   it, byte-identical to the merged 3a wire format (and to 2a/2b/2c).
4. **Fast PRNG for junk, `getrandom` for the nonce.** The junk *body content is
   irrelevant to indistinguishability* (the keystream XOR masks it — even zeros
   mask to random on the wire), so junk bodies/lengths/counts/pads come from a
   fast userspace PRNG; only the 8-byte per-packet nonce uses `getrandom`.
5. **Only one new config key** — `cover_traffic_ms` (idle cover, default off).
   Handshake junk and control-jitter are automatic when `obf_psk` is set.

## Non-goals (out of scope for 3b)

- Data-path timing shaping / inter-packet delay / batching → deferred opt-in
  "paranoid mode" / sub-project #4.
- Entropy shaping (`NDPI_SUSPICIOUS_ENTROPY`) → milestone **3c** (TLS/QUIC
  mimicry). Junk is high-entropy too; it cannot help here.
- Port plausibility (R8) → milestone **3d**.
- Any new AEAD / session-key material. Junk is a keystream-XOR envelope only; it
  never touches Noise/session crypto.
- The heavyweight `nDPId -A` ML-statistical CI harness — flaky + CPU-heavy;
  replaced by a lightweight deterministic structural check.

## Architecture

### The junk envelope

Add `JUNK_TYPE = 6` (the next `ptype` after `RDV_TYPE = 5`; the tunnel
`PacketType` discriminants are 0..=4). A junk datagram is built exactly like any
obfuscated datagram:

```
yip_obf::obfuscate(key, JUNK_TYPE, <throwaway body of random length>, random_pad)
```

Because it reuses the same key, keystream mask, random nonce, and padding as
real traffic, a censor without `obf_psk` cannot distinguish a junk packet from a
real one — both are uniform-random bytes of random length from the same
distribution. This indistinguishability falls out of reuse; there is no separate
junk format.

**Two keying regimes** (matching 3a): handshake junk (pre-session) is keyed by
the network `obf_psk`; idle cover (post-session) is keyed by the peer's session
key.

### Receive path

`deobf_ingress` (`peer_manager.rs`) gains one arm: `JUNK_TYPE => drop silently`
— no reply (zero reflection/amplification), no session state touched, no payload
parsed, no panic. Fail-closed and inert.

### The fast PRNG

A tiny handwritten xorshift/PCG (a few lines, no new dependency, lives in the
`#![forbid(unsafe_code)]` crates), seeded once from `getrandom`. Used for junk
body content, junk lengths, `Jc` counts, and pad lengths. (`rand::rngs::SmallRng`
is a valid alternative if a dependency is preferred; the handwritten generator
avoids a new pinned dep and is trivially auditable.) `getrandom` is still used
for the per-packet 8-byte nonce (uniqueness).

## The three techniques

### ① Handshake junk burst (Jc / Jmin / Jmax) — automatic with `obf_psk`

At `begin_handshake` (`peer_manager.rs`), *before* emitting the real
`HandshakeInit`, emit **Jc** junk datagrams (Jc drawn per attempt from a small
range, e.g. `3..=12`) each of random length (`Jmin..=Jmax`, e.g. `64..=1024`,
capped under the existing `OBF_MTU_BUDGET`), `JUNK_TYPE`-wrapped with the network
key, sent to the handshake target. The flow no longer opens with a countable
"2 packets then data" — packet 0 is noise, and a stage-tracking detector never
finds its A→B→data sequence. Latency-free: the handshake path runs on a
1 s-retry / 90 s-total scale, so a few extra ms is invisible. Parameters are
sensible hardcoded defaults, re-randomized each attempt — no config knob.

### ② Idle cover traffic — opt-in (`cover_traffic_ms`, default off)

In the `tick` loop, for each `Established` peer idle for a short window (no real
data in/out), emit an occasional session-keyed `JUNK_TYPE` datagram so the flow
never goes tellingly silent. This is the only 3b feature with a *continuous*
bandwidth cost, so it's opt-in: one optional config key
`cover_traffic_ms=<interval>` (emit ~one cover packet per interval while idle;
**absent ⇒ off**). Latency-free — fires only when there's no real data to delay.

### ③ Jitter the 30 ms Control-feedback cadence — automatic with `obf_psk`

Extend 3a's `jitter_ms` to reshuffle the emission schedule of the loss-feedback
`Control` timer (`FEEDBACK_INTERVAL_MS = 30`, `dataplane.rs`) by ±25%
(~22–38 ms) when `obf_psk` is set, smearing the ~33 Hz periodic pulse. Latency-
free: it moves only *when the report is sent*, never a data packet, and the
bound keeps ARQ feedback timely. Small integration point: `dataplane.rs` must
learn that obf is on — a bool threaded in, mirroring how `peer_manager` already
gates jitter.

## Config surface

One new optional key:

| Key | Value | Default | Notes |
|---|---|---|---|
| `cover_traffic_ms` | positive integer (ms) | absent = off | While a session is Established and idle, emit ~one session-keyed junk datagram per this interval. Bandwidth cost; opt-in. |

Handshake junk and control-jitter are automatic when `obf_psk` is set; with
`obf_psk` unset, none of 3b exists.

## Security & correctness invariants

1. **Junk never touches Noise/AEAD/session crypto** — keystream envelope over a
   throwaway body; carries no real data, mutates no session state.
2. **Silent-drop, inert on receive** — `JUNK_TYPE → drop`: no reply (zero
   reflection/amplification), no state change, no payload parsed, no panic.
3. **`obf_psk` absent ⇒ byte-identical** — no junk, no `JUNK_TYPE`, no timing
   change. The 3a / 2a-2b-2c no-regression guarantee holds.
4. **Bounded cost** — `Jc ≤ 12`, junk sizes capped under `OBF_MTU_BUDGET`,
   `cover_traffic_ms` rate-bounded; handshake junk is one burst per attempt.
5. **Never breaks connectivity or latency** — the real handshake completes amid
   the junk (peer processes the real Init, drops junk); idle cover fires only
   when idle; control-jitter keeps ARQ feedback timely and touches no data
   packet. The data hot path is never delayed.
6. **Anti-hijack / admission (2a/2b/2c) + Noise unchanged** — junk is inert
   decoy traffic; it changes no admission, session, or routing decision.

## Testing

- **Unit** (`yip-obf` + `peer_manager`): `JUNK_TYPE` obfuscate/deobfuscate
  round-trip; a junk datagram through the demux is dropped with no reply / no
  state change / no panic; the xorshift PRNG yields varied lengths/counts within
  `[Jmin,Jmax]` / `Jc ≤ 12`; `begin_handshake` emits *Jc junk + exactly one real
  Init*.
- **Structural** (binary generalization of 3a's no-constant-byte test): across
  many handshake attempts the **count of pre-handshake datagrams varies** (Jc
  actually randomizes the opener). Control-jitter: feedback interval ∈ [22,38] ms
  with obf on, exactly 30 ms off (mirrors 3a's `jitter_ms` test).
- **netns integration** (both drivers): two `yipd` with `obf_psk` + junk (and
  `cover_traffic_ms` set) still complete handshake + ping — junk doesn't break
  connectivity; obf-off stays byte-identical (existing suite green).
- **nDPI oracle no-regression** (hard gate): re-run `run-ndpi-oracle.sh` with
  junk enabled → still `Unknown`, still no `NDPI_OBFUSCATED_TRAFFIC`. Junk must
  not become a new signature.
- **Flow-shape structural check** (lightweight, deterministic — NOT an ML
  harness): a capture-based assertion that, over N sessions, the first-N-packet
  count is non-constant and there is no clean fixed-period pulse. Framed
  honestly as *"no obviously-constant shape,"* not "provably unclassifiable."

## Integration surface reused

- `yip_obf::{obfuscate, deobfuscate}` + the `ptype` scheme (add `JUNK_TYPE = 6`).
- `PeerManager`'s `obf_egress` / `deobf_ingress` trial-unmask-and-dispatch
  pattern (add the `JUNK_TYPE` drop arm + the junk-emission calls).
- 3a's `jitter_ms` helper (extend to the Control cadence) and `obf_psk` gating.
- `bin/yipd/tests/run-ndpi-oracle.sh` (re-run with junk enabled for the
  no-regression gate).
