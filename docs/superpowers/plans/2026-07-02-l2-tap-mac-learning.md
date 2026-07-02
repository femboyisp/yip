# L2 (TAP) path + MAC learning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach yipd to run over TAP (L2) as well as TUN (L3), wire `l2=true` into the FEC classifier, and add a bounded MAC learning table for future multi-peer bridging — with a 2-peer netns test proving Ethernet frames cross the tunnel.

**Architecture:** Add `device_kind=tun|tap` to config (default `tun`). `tunnel.rs` creates `DeviceKind::Tap` when requested and passes `TunnelMode` into `DataPlane`. Dataplane threads `l2` into `Transport::encode`; a new `MacTable` learns source MACs on ingress/local TAP egress but does not change 2-peer forwarding (always send to the single remote peer). No wire-format change.

**Tech Stack:** Rust, existing `yip-device` TAP support, `yip-transport` classifier, netns harness under `bin/yipd/tests/`.

## Global Constraints

- **No wire-format change.** Existing L3 netns tests must stay green.
- **`yipd` stays `#![forbid(unsafe_code)]`.**
- **Default `device_kind=tun`** when key absent — backward compatible configs.
- **Learn MACs only from authenticated/decrypted frames** (post `session.open`).
- **MAC table:** capacity 4096, TTL 300_000 ms, sweep every 1_000 ms in `tick`.
- **2-peer egress:** always forward to single remote peer; MAC table is learn-only for now.
- Mullvad lints, `-D warnings`; `CHANGELOG.md` entry on completion.

---

### Task 1: Config `device_kind` + `TunnelMode`

**Files:**
- Modify: `bin/yipd/src/config.rs`
- Create: `bin/yipd/src/mode.rs` (or add to `config.rs` if tiny)

**Interfaces:**
- Produces: `pub enum DeviceKindConfig { Tun, Tap }` (or `TunnelMode { L3Tun, L2Tap }`)
- `Config` gains `pub device_kind: DeviceKindConfig` defaulting to `Tun`
- Parse `device_kind=tun|tap`; reject unknown values

- [ ] **Step 1: Write failing tests** for parse accept/reject/default
- [ ] **Step 2: Run** `cargo test -p yipd config::tests` → fail
- [ ] **Step 3: Implement** parse + enum
- [ ] **Step 4: Run tests** → pass
- [ ] **Step 5: Commit** `Add device_kind config for TUN vs TAP mode`

### Task 2: Tunnel device selection + dataplane mode plumbing

**Files:**
- Modify: `bin/yipd/src/tunnel.rs`, `bin/yipd/src/dataplane.rs`, `bin/yipd/src/main.rs`

**Interfaces:**
- `DataPlane::new(established, conn_tag, mode: TunnelMode)` stores `l2: bool` (`true` for L2Tap)
- `tunnel.rs`: `TunTap::create(&config.device, Tun|Tap)` from `device_kind`
- `on_tun_packet`: pass `self.l2` to `transport.encode(..., self.l2, now_ms)`

- [ ] **Step 1: Unit test** dataplane encode uses `l2=true` in TAP mode (mock/spy via transport test hook or inspect classifier path)
- [ ] **Step 2-4: Implement** tunnel + dataplane plumbing; existing tests still pass with default tun
- [ ] **Step 5: Commit** `Wire TAP device creation and l2 encode hint`

### Task 3: MAC learning table

**Files:**
- Create: `bin/yipd/src/mac_table.rs`
- Modify: `bin/yipd/src/dataplane.rs`, `bin/yipd/src/main.rs`

**Interfaces:**
- `MacTable::learn(src_mac: [u8;6], peer_id: u64, origin, now_ms)`
- `MacTable::sweep(now_ms)` in `tick`
- Ignore broadcast/multicast/zero MAC; evict oldest on capacity

- [ ] **Step 1: Unit tests** learn/ignore/age/evict/move
- [ ] **Step 2-4: Implement** + hook learn on ingress TAP write path and local TAP egress
- [ ] **Step 5: Commit** `Add bounded MAC learning table`

### Task 4: L2 TAP netns integration test

**Files:**
- Create: `bin/yipd/tests/run-netns-tunnel-l2.sh`
- Modify: `bin/yipd/tests/tunnel_netns.rs`

**Interfaces:**
- Two namespaces, TAP devices, `device_kind=tap` in configs
- Verify L2 payload (ARP or raw Ethernet + ping) crosses tunnel

- [ ] **Step 1: Script** + rust test wrapper (sudo-gated skip)
- [ ] **Step 2: Run** under sudo locally
- [ ] **Step 3: Commit** `Netns test: L2 TAP Ethernet flow across tunnel`

### Task 5: Docs + changelog + gate

**Files:**
- Modify: `CHANGELOG.md`, `README.md` (brief `device_kind=tap` note)

- [ ] **Step 1:** `cargo test --workspace`, clippy, existing 3 netns tests
- [ ] **Step 2:** Update CHANGELOG + README
- [ ] **Step 3: Commit** `Document L2 TAP mode (device_kind=tap)`

---

## Self-review

- Spec rollout steps 1–5 map to tasks 1–5.
- Multi-peer flood forwarding explicitly deferred.
- #9 rekey: MAC table keyed by peer_id, not epoch — no flush on rekey in this milestone.
