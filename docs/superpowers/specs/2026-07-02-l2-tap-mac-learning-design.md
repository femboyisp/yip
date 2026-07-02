# L2 (TAP) path + MAC learning - design

**Status:** approved (brainstorming, 2026-07-02)
**Scope:** issue #8 milestone for sub-project #1 follow-up
**Predecessor:** issue #7 (`UringDriver` / single-loop dataplane) merged on `main`
**Related issues:** #9 (rekey + PQ-hybrid), #11b (correctness follow-ups)

## Goal

Land a practical first L2 milestone that makes yipd run over TAP as well as TUN while preserving the existing encrypted FEC transport and wire format. The milestone must ship usable two-peer TAP operation now and establish the MAC-learning bridge structure needed for multi-peer overlay forwarding later.

## Why now / sequencing

Issue #8 intentionally follows #7 in the orchestration spec:

- #7 changed tunnel runtime structure (`DataPlane` + driver dispatch in `tunnel.rs`), so #8 should build on that merged shape rather than racing it.
- #8 and #9 both touch `tunnel.rs` / `DataPlane`; #8 goes first so #9 can layer epoch/rekey behavior onto both L3 and L2 paths instead of rewriting device-mode plumbing.
- #11b may touch packet-accounting/correctness internals; #8 keeps these changes minimal and explicit so #11b can reason over a stable L2/L3 dispatch surface.

## Non-goals

- Multi-peer control-plane discovery, membership, or path selection.
- Cross-node STP, loop prevention, VLAN policy, or full bridge feature parity.
- Wire-format redesign (inner payload remains opaque bytes to wire framing).
- Rekey semantics themselves (#9 owns session epoch rotation and conn_tag changes).
- Deep anti-DPI work (#11c); this milestone does not add any static signature.

## Success criteria

- Config selects `device_kind=tun|tap`, defaulting to `tun` for backward compatibility.
- `tunnel.rs` creates `DeviceKind::Tun` or `DeviceKind::Tap` from config and runs unchanged transport/wire/session machinery.
- `DataPlane` passes `l2=true` to `Transport::encode(.., l2, ..)` in TAP mode so classifier behavior is L2-aware.
- Two-peer TAP netns test passes with an Ethernet bridge-like flow over yipd.
- A bounded MAC table implementation exists in yipd with deterministic learning/aging behavior and explicit 2-peer simplifications.

## Architecture

### 1) Device mode is a runtime dataplane parameter

Introduce explicit daemon runtime mode:

- `TunnelMode::L3Tun`
- `TunnelMode::L2Tap`

Mode derives from parsed config (`device_kind`), then feeds:

- tunnel device creation (`Tun` vs `Tap`)
- dataplane encode classifier hint (`l2`)
- forwarding logic (single-peer direct forward now, MAC-directed forward shape for future)

This keeps transport/wire/session crates layer-agnostic and localizes L2 policy to yipd.

### 2) L2 forwarding split: now vs future

#### Current milestone (2 static peers)

- There is exactly one remote peer endpoint after handshake.
- For every valid frame read from TAP, dataplane encodes/sends to that one peer.
- Destination-MAC lookup is not used for egress decision in this mode (egress always targets the only peer), but source-MAC learning still runs so behavior and tests are consistent with future multi-peer mode.

#### Future-ready shape (multi-peer)

Define forwarding contract now (implementation mostly deferred):

- Learn mapping `src_mac -> peer_id` on authenticated ingress from peer.
- For local TAP egress:
  - if `dst_mac` known in table: unicast to owning peer
  - if unknown, broadcast, or multicast: flood to eligible peers except the ingress/origin peer
- Apply split-horizon style rule on peer ingress flood (do not reflect a frame back to its ingress peer).

This design lets control-plane issue(s) later provide `peer_id` set changes without altering core L2 forwarding semantics.

### 3) MAC learning table design

Table lives in yipd dataplane runtime (not in `yip-device`):

- Key: 6-byte source MAC.
- Value:
  - `peer_id` (stable dataplane peer handle; for 2-peer this is the single remote)
  - `last_seen_ms`
  - `origin` enum: `Peer` or `LocalTap` (for diagnostics/policy)
- Capacity: fixed upper bound (default 4096 entries).
- Update rule: on each accepted Ethernet frame with unicast source MAC, update/insert entry for `src_mac` with latest `peer_id`/timestamp.

#### Aging and eviction

- Aging TTL (default 300_000 ms / 5 min): stale entries treated as unknown.
- Sweep cadence (default 1_000 ms): incremental cleanup in dataplane tick path.
- Eviction policy on capacity pressure: evict the entry with the oldest `last_seen_ms` (deterministic oldest-first scan at current small table size).
- Unknown destination after expiry falls back to flood behavior (future) or single-peer send (current 2-peer).

Rationale: predictable memory bound, robust against MAC churn/abuse, no unbounded hash growth.

## Security checks

L2 introduces new trust and abuse surfaces; enforce these checks:

- Learn only from authenticated/decrypted packets (post-session-open path), never raw ciphertext.
- Ignore non-Ethernet payloads in TAP mode if frame length < 14.
- Reject source MAC that is broadcast/multicast/all-zero for learning.
- Rate-limit MAC move logging (same MAC rapidly switching peer_id) to avoid log spam amplification.
- Bound all flood fan-out by configured peer set size; no dynamic untrusted fan-out.
- Keep table strictly local process memory; no persistence across restarts.

Note on #11b interaction:

- #11b wire-auth/object binding strengthens packet identity checks; this spec assumes authenticated peer context is available and should be consumed when updating learning entries.

## Error handling and behavior

- Invalid `device_kind` config value: fail startup with clear parse error.
- TAP creation failure (`CAP_NET_ADMIN`, missing device path, ioctl failure): fail startup with contextual error.
- Malformed short frame in TAP mode: drop and increment counter; continue loop.
- MAC table insertion under full capacity: evict per policy and continue.
- Unexpected mode/frame mismatch (for example, L3 parse helper called in TAP mode): covered by explicit tests and handled as drop/error path, not panic.

## Component/file changes

Planned file-level scope for this milestone:

- `bin/yipd/src/config.rs`
  - add `device_kind` parse (`tun|tap`)
  - preserve backward compatibility by defaulting to `tun` when key absent
- `bin/yipd/src/tunnel.rs`
  - select `DeviceKind` from config
  - pass mode/l2 hint into dataplane constructor
- `bin/yipd/src/dataplane.rs`
  - store tunnel mode flag
  - route `Transport::encode(..., l2, ...)` using mode
  - add MAC table struct + bounded learning/aging helpers
  - keep 2-peer forwarding path simple while structuring for multi-peer extension
- `crates/yip-device/src/lib.rs`
  - no behavior change required (already supports `DeviceKind::Tap`); touch only if API glue is required
- test targets under existing yipd/yip-bench netns harness
  - add L2 TAP flow case

No changes required in wire/crypto framing for this milestone.

## Data flow

### A) Two-peer now (implemented in this milestone)

1. Local host writes Ethernet frame to TAP.
2. yipd reads frame, marks path as `l2=true`.
3. Dataplane seals + FEC-encodes + frames exactly as today.
4. Packet sent to single remote peer endpoint.
5. Remote yipd decodes and injects recovered Ethernet frame into its TAP.
6. MAC learning updates:
   - on remote ingress from peer: learn source MAC belongs to peer
   - on local TAP egress: learn local source MAC as `origin=LocalTap` for diagnostics and future policy hooks (not used for egress peer selection in 2-peer mode)

### B) Multi-peer future (defined contract, deferred implementation)

1. Frame arrives from local TAP or remote peer.
2. Learn source MAC against ingress origin peer/local.
3. Resolve destination:
   - known unicast destination -> unicast to mapped peer
   - unknown/broadcast/multicast -> flood set selection
4. Apply split-horizon and peer eligibility checks.
5. Encode/send selected copies; remote peer injects into TAP.

## Testing strategy

### Unit tests (new/expanded)

- Config parser:
  - accepts `device_kind=tun|tap`
  - rejects unknown values with deterministic error text
  - defaults to `tun` when absent
- Dataplane L2 hint threading:
  - in TAP mode, encode path calls transport with `l2=true`
  - in TUN mode, existing `l2=false` behavior preserved
- MAC table:
  - learns valid unicast source MAC
  - ignores invalid source MACs
  - age-out behavior after TTL
  - bounded eviction order under pressure
  - move update semantics when same MAC appears from different peer

### Netns / integration tests

- Existing L3 tests remain green (`tun` default path).
- New L2 TAP netns scenario:
  - create TAP devices in two namespaces
  - bridge-compatible addressing
  - verify L2 payload crosses tunnel (for example, ARP + ICMP over bridged path)
- Bench extension:
  - add n2n comparison row for TAP/L2 flow as issue requests.

## Rollout plan

1. Land config and mode plumbing with no behavior change for default configs (`tun`).
2. Land dataplane `l2` hint threading and TAP device path.
3. Land MAC table core + tests (learning/aging/eviction) with 2-peer forwarding behavior unchanged (single peer send).
4. Land L2 netns test and bench note/update.
5. Document operational usage (`device_kind=tap`) in README/changelog if needed.

This sequencing keeps each step testable and minimizes blast radius.

## Interactions with #9 and #11b

### #9 (session rekey + PQ-hybrid)

- #8 introduces no key schedule changes.
- MAC table entries are keyed by peer identity handle, not by session epoch; rekey should not flush learned state by default.
- If #9 rotates `conn_tag`/epoch context, L2/TAP path should remain transparent because inner frame bytes are unchanged opaque payload from wire perspective.

### #11b (correctness follow-ups)

- Object/auth binding improvements in #11b should be consumed before MAC learn updates when possible.
- Bidirectional accounting in #11b can reuse L2 ingress/egress counters introduced here.
- Any deadline/FEC eviction changes in #11b stay orthogonal to MAC table eviction (separate stores, separate policies).

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| L2 path regresses existing L3 behavior | Keep `tun` default; preserve existing L3 tests and run both modes in CI where practical |
| MAC-table growth or churn under noisy L2 segments | Hard capacity + TTL aging + deterministic eviction |
| Incorrect learning from unauthenticated or malformed frames | Learn only after successful decrypt/auth and frame validation |
| Future multi-peer assumptions drift from current implementation | Encode future forwarding contract explicitly in this spec and shape current APIs around `peer_id` |
| Cross-issue merge conflicts with #9/#11b | Sequence after merged #7 and before #9 implementation; keep #8 edits localized to config/tunnel/dataplane |

## Deferred items (explicitly out of this milestone)

- Full multi-peer flood/unicast forwarding implementation.
- Control-plane-discovered dynamic peer set updates.
- VLAN-aware learning/segmentation.
- Loop prevention and bridge protocol features.
- Persisted FDB snapshots across restart.

## Milestone accept checklist

- [ ] `device_kind=tap` starts successfully and drives tunnel over TAP
- [ ] `device_kind` absent still yields current TUN behavior
- [ ] `Transport::encode` receives correct `l2` flag by mode
- [ ] MAC learning table unit tests pass (learn/age/evict/move)
- [ ] L2 netns test passes in CI/local harness
- [ ] No wire-format changes introduced
