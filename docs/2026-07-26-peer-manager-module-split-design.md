# peer_manager.rs module split — design

**Date:** 2026-07-26
**Issue:** #11 (architecture / god-struct). Prerequisite for multi-core sharding (#10, Way A).
**Status:** approved, pre-implementation.

## Purpose

`bin/yipd/src/peer_manager.rs` is a single ~9,400-line file (~3,300 production +
~6,000 test) holding the entire control plane: cold-start handshake, epoch
rekey, relay/rendezvous, path/routing, obfuscation, and mesh gossip. It is the
hottest file in the project to edit and the highest-risk (the #116 escalation
bug lived here). Splitting it into concern-focused files makes it tractable to
work in and — critically — lets the coming multi-core sharding work (Way A,
per-peer engine sharding, #10) touch only the steering/dispatch layer instead of
the whole god-struct.

This is **sub-project 1** of the multi-core effort. Sub-project 2 (the sharding
itself) gets its own spec + plan after this lands.

## Non-goals

- **No behavior change.** This is a pure code-movement refactor. Same struct,
  same methods, same logic, byte-identical runtime behavior.
- **No struct split.** The `PeerManager` struct (26 fields) stays a single
  struct in `mod.rs`. Splitting its fields into sub-structs fights the borrow
  checker (methods borrow across field clusters) and is explicitly out of scope
  (a possible, separate Phase-2 per the roadmap).
- **No sharding.** That is sub-project 2.

## Approach

Rust allows a type's **inherent `impl` blocks to be split across multiple files**
within the same module tree. So we keep the struct definition and its fields in
`mod.rs`, and move method *groups* into sibling files, each as an additional
`impl PeerManager { … }` block. Private helpers stay private (same crate/module
tree); nothing about visibility or call sites changes.

### Target layout: `bin/yipd/src/peer_manager/`

| File | Methods (current line refs) | ~prod lines |
|---|---|---|
| `mod.rs` | struct + fields + `PeerState`/`HandshakingState` types, `new`, `admit_member`, setters (`set_obf_psk`/`set_cover_traffic_ms`/`set_data_symbol_size`), `local_addr`, public `on_udp`/`on_tun`/`tick` + `on_udp_dispatch`/`on_tun_dispatch`/`tick_dispatch`, `is_root`, `finish_wrapped`, `server_addr`, `push_pending` | ~600 |
| `handshake.rs` | `begin_handshake`, `handle_handshake_init`, `handle_handshake_resp`, `accept_fresh_init`, `responder_cert_ok`, `drop_session` | ~700 |
| `rekey.rs` | `drive_rekey_schedule`, `handle_rekey_init`, `rekey_init_core`, `handle_rekey_resp`, `rekey_resp_core`, `push_rekey_egress` | ~550 |
| `relay.rs` | `relay_wrap`, `on_rdv`, `on_relayed`, `relayed_handshake_init`, `relayed_handshake_resp`, `relayed_data`, `maybe_lookup` | ~550 |
| `routing.rs` | `drive_path_idle`, `route_tun_index`, `route_data`, `relearn_endpoint`, `dispatch_established`, `handle_data_or_control`, `kind_for_stage` | ~450 |
| `obf.rs` | `deobf_ingress`, `build_junk`, `obf_key_for_egress`, `obf_egress`, `session_obf_key_for` | ~250 |
| `gossip.rs` | `on_gossip`, `gossip_targets`, `tick_gossip` | ~200 |

`tick_dispatch` stays in `mod.rs` because it is the central per-tick driver that
touches handshake, rekey, and routing concerns; the punch→relay escalation arm
(the #116 fix) lives here and is the seam the sharding work will read.

### Tests

The ~6,000 lines of `#[cfg(test)]` code move to sit beside the code they
exercise: each module file gets its own `#[cfg(test)] mod tests`. Shared test
helpers (`pm_with_mock_rdv`, `mock_server`, `generate_keypair`, `node_id`,
`fake_established_dataplane`, the `MockRendezvous`, etc.) move to a
`peer_manager/testutil.rs` (a `#[cfg(test)] pub(super)` module) so every module's
tests can use them. Test-to-module assignment follows the method each test
targets; ambiguous integration-style tests (that drive `on_udp`/`tick`
end-to-end) stay in `mod.rs`'s test module.

## Boundaries / interfaces

Each module is one `impl PeerManager` block over the shared struct, so the
"interface" between them is just the struct's methods — unchanged. The value of
the split is **readability and edit-locality**, not new abstraction boundaries.
A reader can now answer "where is the rekey logic" by opening `rekey.rs` instead
of scrolling a 9k-line file, and the sharding work can reason about `routing.rs`
+ `mod.rs` (steering/dispatch) in isolation.

## Risks

- **Accidental logic change during the move.** Mitigation: move code verbatim
  (cut/paste, no edits), and rely on the full test suite (262 tests) plus the
  mutation-tested crates staying green. The diff must read as pure movement.
- **Private-item visibility.** A helper used across two new modules must be
  visible to both. Since all modules are children of `peer_manager`, `fn` on the
  struct stays reachable; free-function helpers (e.g. `push_pending`,
  `kind_for_stage`) that cross modules move to `mod.rs` or become
  `pub(super)`/`pub(in crate::peer_manager)`. No item becomes more public than
  the crate.
- **Constants / type imports.** Module-level `const`s (`HANDSHAKE_RETRY_MS`,
  `HANDSHAKE_TOTAL_MS`, `PUNCH_MS` import, etc.) and type aliases stay in
  `mod.rs` and are `use super::*`-imported by the submodules.

## Verification (proves no behavior change)

1. `cargo test -p yipd --bins` — all 262 tests pass, unchanged in name/count.
2. `cargo fmt -p yipd -- --check` clean; `cargo clippy -p yipd --bins` clean
   (no new warnings).
3. The integration netns money-tests (incl. `run-netns-pathswitch-rehandshake.sh`)
   still pass — the #116 fix survives the move.
4. Human diff review: every moved block is identical to its origin (a
   `git diff` that is pure relocation, no logic hunks).

## Sequencing

Land this as one PR (or a small series if the diff is too large to review in
one). Then sub-project 2 (multi-core Way A / #10) is specced against the clean
`routing.rs` + `mod.rs` steering layer.
