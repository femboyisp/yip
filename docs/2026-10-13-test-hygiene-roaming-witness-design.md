# Design Specification: Test Hygiene and Roaming Positive Witness (#110)

- **Date:** 2026-10-13
- **Author:** Antigravity / Pair Programming
- **Target Issue:** [#110](https://github.com/femboyisp/yip/issues/110) — "test-hygiene: run-netns-roaming.sh lacks a positive witness; 7 tunnel_netns.rs wrappers are structurally dead"
- **Target Branch:** `fix/test-hygiene-roaming-witness`

---

## 1. Context & Motivation

1. **Lack of Direct Positive Witness in `run-netns-roaming.sh`:**
   `run-netns-roaming.sh` verifies that ping traffic continues across an on-wire source-address rebind with $\le 1\%$ packet loss and `relay-forwarded == 0`. While this demonstrates that traffic did not black-hole and did not escalate to the relay, it proves endpoint relearning and egress redirect only transitively. Unlike `run-netns-registration-hijack.sh` which carries a direct reflexive witness, roaming lacks an explicit positive witness confirming that peer B actually updated its recorded peer endpoint to A's new IP address.

2. **Structurally Dead Wrappers in `tunnel_netns.rs`:**
   In `bin/yipd/tests/tunnel_netns.rs`, 7 test wrappers:
   - `dpi_undetectability`
   - `quic_classified_as_quic`
   - `tls_classified_as_tls`
   - `port_plausibility_oracle`
   - `reality_probe_serves_decoy`
   - `relay_tls_tunnel_ping`
   - `relay_reality_tunnel_ping`
   and the helper `ndpi_reader_bin()` are never invoked by `--exact` in privileged CI (`.github/workflows/integration.yml`), where the underlying scripts are invoked directly. In unprivileged CI (`ci.yml`), they skip-pass forever. These 7 wrappers present a silent drift risk and should be deleted.

---

## 2. Invariants & Scope

1. **Zero Wire Format Changes:**
   No protocol headers, codecs, or network wire bytes are altered.
2. **Explicit Positive Witness:**
   `PeerManager::relearn_endpoint` will log endpoint migrations to stderr:
   `peer_manager: relearn_endpoint: peer {idx} roamed to {new_endpoint}`.
   `run-netns-roaming.sh` will assert that peer B's daemon log contains this positive witness matching `${IP_A2}`.
3. **Clean Harness Pruning:**
   Deleting the 7 dead wrappers in `tunnel_netns.rs` reduces dead code by ~360 lines without removing any test coverage (the underlying bash scripts remain fully executed in `integration.yml`).

---

## 3. Implementation Details

### `bin/yipd/src/peer_manager/routing.rs`
In `relearn_endpoint`:
```rust
if let Some(ref mut ep) = self.peers[idx].endpoint {
    if ep.ip() != src.ip() {
        ep.set_ip(src.ip());
        let new_endpoint = *ep;
        if let PeerState::Established(epochs) = &mut self.peers[idx].state {
            epochs.set_peer_addr(new_endpoint);
        }
        eprintln!("peer_manager: relearn_endpoint: peer {idx} roamed to {new_endpoint}");
    }
}
```

### `bin/yipd/tests/run-netns-roaming.sh`
Add assertion after the rebind ping:
```bash
# ── assertion: positive witness — B logged that it relearned A's new IP ─────
if grep -qE "relearn_endpoint: peer [0-9]+ roamed to ${IP_A2}:" "$LOG_B"; then
    echo "[PASS] positive witness: yipRoamB logged endpoint relearn for roamed source ${IP_A2}"
else
    echo "[FAIL] positive witness: yipRoamB did not log endpoint relearn for ${IP_A2}"
    dump_logs
    exit 1
fi
```

### `bin/yipd/tests/tunnel_netns.rs`
Remove `ndpi_reader_bin()` and the 7 dead wrapper functions:
- `dpi_undetectability`
- `quic_classified_as_quic`
- `tls_classified_as_tls`
- `port_plausibility_oracle`
- `reality_probe_serves_decoy`
- `relay_tls_tunnel_ping`
- `relay_reality_tunnel_ping`

---

## 4. Verification Plan

- `cargo test -p yipd --test tunnel_netns`: verifies remaining 20 active wrappers pass cleanly.
- Full workspace test pass: `cargo test --all`.
- Full clippy & fmt check: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`.
