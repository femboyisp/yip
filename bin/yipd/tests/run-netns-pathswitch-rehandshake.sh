#!/usr/bin/env bash
# The hardening.36 money test: proves the #36 INVERSION (anti-replay.34 Task
# 4) end-to-end — a Punch->Relay path re-target now legitimately draws a
# FRESH Noise ephemeral (state -> Idle -> begin_handshake) instead of
# preserving the in-flight one, and the session still CONVERGES because the
# responder rebuilds on the fresh Init (freshness-gated, #34 Task 3) rather
# than relying on ephemeral preservation to avoid a black hole.
#
# Usage: run-netns-pathswitch-rehandshake.sh <path-to-yipd-binary> <path-to-yip-rendezvous-binary>
#
# ── which #36 variant this implements ──
# The brief's headline scenario is: A and B rendezvous-only; B adopts the
# responder role and goes Established over a DIRECT punch reply, but that
# reply is lost through A's punch window, so A escalates to the relay while
# B is already direct-established. Pre-#34, this needed ephemeral
# PRESERVATION across the retarget (the original #36 fix) so the responder's
# `cached_resp` dedup would recognize the relayed retry. Post-#34, the
# responder instead REBUILDS on a fresh-ephemeral, fresh-ts Init (Task 3's
# freshness gate + Task 4's fresh-Init inversion), so preservation is no
# longer needed for convergence — and no longer happens.
#
# Deterministically dropping "only B->A's first resp, through exactly the
# punch window" is impractical to construct in netns (it requires
# millisecond-precision, one-shot loss on a specific reply, not a topology
# property). This script instead implements the brief's documented
# acceptable equivalent: fork run-netns-relay.sh's RELAY-FORCED topology
# (three netns A/B/R; R does not forward IPv4, so A and B are mutually
# unreachable and can only ever converge via R's blind relay) — this forces
# EVERY session, including the very first one, through the punch->escalate
# ->relay path, and asserts A converges over the relay. It does not exercise
# Task 4's responder-side relay adoption in isolation (B never gets far
# enough into a direct punch to adopt anything in this topology — punch
# delivery is unconditionally dropped by R's lack of forwarding), but that
# half is covered by the freshness-gated-rebuild unit tests in
# bin/yipd/src/peer_manager.rs.
#
# ── proving "a FRESH ephemeral" on the wire, not just from source ──
# `bin/yipd/examples/rekey_epoch_witness` (built alongside yipd; see step 0
# below) counts DISTINCT cleartext Noise-IK ephemeral public keys across
# captured [HandshakeInit] datagrams — cleartext because Noise_IK's leading
# token on message 1 is `e`, unencrypted (see the tool's own module doc and
# run-netns-rekey.sh's header for the full argument). Post-#34/#36-inversion,
# a Punch->Relay retarget goes `state = Idle; begin_handshake(..)`, drawing a
# NEW ephemeral for the relayed resend instead of resending the punch
# attempt's `init_pkt` byte-for-byte. So: capture every datagram A itself
# SENDS (both its raw, silently-dropped punch attempt AND its later
# RelaySend-wrapped escalation retry — `YIP_WITNESS_UNWRAP_RELAY=1`, the same
# opt-in run-netns-rekey-relay.sh uses, strips the RelaySend/RelayDeliver
# envelope before applying the witness's cleartext-ephemeral logic; a
# non-relay-tagged datagram, like A's raw punch attempt, passes through
# unchanged and is still counted) and assert AT LEAST TWO distinct INIT
# ephemerals appear. Exactly one would mean the retarget reused the punch
# attempt's ephemeral — the OLD #36 behavior, now itself the regression this
# inverted test exists to catch (a preserved ephemeral means the escalation
# is a bare retransmit the freshness gate would refuse as stale on a replay,
# reopening the downgrade #34 Task 4 closes).
#
# ── why the capture is restricted to A's own outbound traffic ──
# Neither peer has a static `endpoint=`/`initiate=` field (config.rs's
# `initiate` key is a documented no-op), so on a cold start BOTH A and B
# independently attempt to become the initiator ("startup-glare").
# `handle_handshake_init`'s tie-break (`self.local_pub <
# self.peers[idx].pubkey`) makes the SMALLER public key the persistent
# initiator; the larger-pubkey side sends at most one abortive attempt of its
# own before deferring and completing as responder instead. An UNFILTERED
# capture on A's veth would therefore also see B's relayed loser-attempt
# arrive as a `RelayDeliver` addressed to A (R forwards it), which the
# witness tool would count as an extra, unrelated INIT ephemeral — a false
# positive with nothing to do with #36. Two countermeasures close this: (1)
# keys are generated in a retry loop until `PUB_A < PUB_B`, so A is
# deterministically the persistent initiator (the one that actually performs
# the punch->escalate dance this test is about); (2) the tcpdump capture
# filters `src host $IP_A`, so only datagrams A itself transmits (its own raw
# punch Init, its own relay-wrapped retry) are captured — B's inbound
# `RelayDeliver` traffic to A is excluded. Losing the Resp side of the
# capture this way means `COMPLETED_ROUNDS` isn't meaningful here (no
# [HandshakeResp] ever originates at A); this script instead gates on
# DISTINCT_INIT_EPHEMERALS>=2 (the #36-inversion proof) plus
# HANDSHAKE_INIT_PKTS>=2 (non-vacuity: proves both a punch attempt AND a
# relay retransmit were actually observed, not just one lucky send) and
# leans on the ping convergence + relay-forwarded assertions below for "it
# actually completed".
#
# Assertions (any failure is non-zero exit, [PASS]/[FAIL] markers):
#   1. convergence: ping -6 -c 50 -W 2 A->B over the relay succeeds with
#      >=98% delivery (tolerating the same ~PUNCH_MS warm-up loss
#      run-netns-relay.sh documents) — the headline #36-inversion claim: A
#      still converges, now via rebuild rather than preservation.
#   2. relay_forwarded: R's stderr shows `relay-forwarded=<N>`, N>0 — the
#      blind relay, not a direct/punched path, carried the traffic.
#   3. fresh-ephemeral escalation: rekey_epoch_witness
#      (YIP_WITNESS_UNWRAP_RELAY=1) on a src-host-$IP_A-filtered capture
#      reports >=2 distinct INIT ephemerals across >=2 captured
#      HandshakeInit datagrams — proving the retarget drew a fresh ephemeral
#      instead of preserving the punch attempt's.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
RDV="${2:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
WITNESS_BIN="$(dirname "$YIPD")/examples/rekey_epoch_witness"

# ── 0. root + tool preflight (invoked directly by CI, not through the
# tunnel_netns.rs Rust harness, so it does its own SKIP-gating per the
# run-netns-rekey.sh / run-netns-rekey-relay.sh convention) ──
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-netns-pathswitch-rehandshake: needs root (netns + TUN + tcpdump)"
    exit 0
fi
for tool in tcpdump ping; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP run-netns-pathswitch-rehandshake: required tool '$tool' not found"
        exit 0
    fi
done
if [ ! -x "$WITNESS_BIN" ]; then
    echo "SKIP run-netns-pathswitch-rehandshake: rekey_epoch_witness not built at $WITNESS_BIN"
    echo "  build it with: cargo build --release -p yipd --example rekey_epoch_witness"
    exit 0
fi

TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-pathswitch-test.XXXXXX)"

NS_A="yipPswA"
NS_B="yipPswB"
NS_R="yipPswR"

VETH_A_N="vPswA1"; VETH_A_R="vPswA0"   # A<->R pair: A-side, R-side
VETH_B_N="vPswB1"; VETH_B_R="vPswB0"   # B<->R pair: B-side, R-side

IP_A="10.74.0.2"
IP_R_A="10.74.0.1"   # R's address on A's subnet
IP_B="10.75.0.2"
IP_R_B="10.75.0.1"   # R's address on B's subnet
PREFIX="24"

PORT_A="51820"
PORT_B="51820"
RDV_PORT="51821"
TUN_DEV="yip0"

PID_A=""
PID_B=""
PID_RDV=""
TCPDUMP_PID=""

cleanup() {
    echo "[cleanup] killing daemons/tcpdump, removing namespaces"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill "$PID_RDV" 2>/dev/null || true
    [ -n "$TCPDUMP_PID" ] && kill "$TCPDUMP_PID" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill -9 "$PID_RDV" 2>/dev/null || true
    [ -n "$TCPDUMP_PID" ] && kill -9 "$TCPDUMP_PID" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip netns del "$NS_R" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. generate keypairs, retrying until PUB_A < PUB_B ────────────────────
# `handle_handshake_init`'s glare tie-break (`self.local_pub <
# self.peers[idx].pubkey`) makes the SMALLER public key the deterministic,
# persistent initiator (see the header comment above). hex_encode is
# byte-order-preserving, so a plain bash string `<` comparison of the two
# hex pubkeys is equivalent to Rust's `[u8; 32]` lexicographic `<`. ~50%
# chance per attempt; capped well above what randomness could plausibly need.
echo "[setup] generating keypairs (retrying until PUB_A < PUB_B, for a deterministic initiator)"
PUB_A=""
PUB_B=""
for _attempt in $(seq 1 50); do
    GENKEY_A="$("$YIPD" --genkey)"
    GENKEY_B="$("$YIPD" --genkey)"
    CAND_PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
    CAND_PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"
    if [[ "$CAND_PUB_A" < "$CAND_PUB_B" ]]; then
        PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
        PUB_A="$CAND_PUB_A"
        PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
        PUB_B="$CAND_PUB_B"
        break
    fi
done
if [ -z "$PUB_A" ]; then
    echo "[error] could not generate PUB_A < PUB_B after 50 attempts (something is very wrong)"
    exit 1
fi

ADDR_A="$("$YIPD" --addr "$PUB_A")"
ADDR_B="$("$YIPD" --addr "$PUB_B")"
echo "[setup] node_addr A=$ADDR_A B=$ADDR_B (A is the deterministic glare-winner/initiator)"

# ── 2. write config files (rendezvous-only peers: public_key, no endpoint) ────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipPswA
local_private=${PRIV_A}
local_public=${PUB_A}
listen=${IP_A}:${PORT_A}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_R_A}:${RDV_PORT}
[peer]
public_key=${PUB_B}
EOF

cat > "$CFG_B" <<EOF
# yipPswB
local_private=${PRIV_B}
local_public=${PUB_B}
listen=${IP_B}:${PORT_B}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_R_B}:${RDV_PORT}
[peer]
public_key=${PUB_A}
EOF

# ── 3. create namespaces + point-to-point veths into R ────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"
ip netns add "$NS_R"

echo "[setup] wiring A<->R"
ip link add "$VETH_A_R" type veth peer name "$VETH_A_N"
ip link set "$VETH_A_N" netns "$NS_A"
ip link set "$VETH_A_R" netns "$NS_R"
ip netns exec "$NS_A" ip addr add "${IP_A}/${PREFIX}" dev "$VETH_A_N"
ip netns exec "$NS_A" ip link set "$VETH_A_N" up
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_R" ip addr add "${IP_R_A}/${PREFIX}" dev "$VETH_A_R"
ip netns exec "$NS_R" ip link set "$VETH_A_R" up

echo "[setup] wiring B<->R"
ip link add "$VETH_B_R" type veth peer name "$VETH_B_N"
ip link set "$VETH_B_N" netns "$NS_B"
ip link set "$VETH_B_R" netns "$NS_R"
ip netns exec "$NS_B" ip addr add "${IP_B}/${PREFIX}" dev "$VETH_B_N"
ip netns exec "$NS_B" ip link set "$VETH_B_N" up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_R" ip addr add "${IP_R_B}/${PREFIX}" dev "$VETH_B_R"
ip netns exec "$NS_R" ip link set "$VETH_B_R" up
ip netns exec "$NS_R" ip link set lo up

# A's and B's only route beyond their own /24 is via R -- and R does NOT
# forward, so a cross-subnet packet dies silently at R (see
# run-netns-relay.sh's header comment for the full reasoning: this keeps the
# punch attempt a normal, silently-dropped packet rather than a synchronous
# socket error that would kill yipd's event loop).
ip netns exec "$NS_A" ip route add default via "$IP_R_A" dev "$VETH_A_N"
ip netns exec "$NS_B" ip route add default via "$IP_R_B" dev "$VETH_B_N"

# Explicitly disable IPv4 forwarding in R (belt-and-suspenders: a fresh netns
# already defaults to this, but the isolation invariant this whole test
# rests on deserves to be asserted, not assumed).
ip netns exec "$NS_R" sysctl -q -w net.ipv4.ip_forward=0
ip netns exec "$NS_R" sysctl -q -w net.ipv4.conf.all.forwarding=0

# ── 4. start yip-rendezvous in R, bound on both subnets ───────────────────────
LOG_RDV="$TMPDIR_TEST/rdv.log"
echo "[start] starting yip-rendezvous in R on 0.0.0.0:${RDV_PORT}"
ip netns exec "$NS_R" "$RDV" "0.0.0.0:${RDV_PORT}" >"$LOG_RDV" 2>&1 &
PID_RDV=$!
sleep 0.3

LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

dump_logs() {
    echo "=== rendezvous log ==="
    cat "$LOG_RDV" || true
    echo "=== yipPswA log ==="
    cat "$LOG_A" || true
    echo "=== yipPswB log ==="
    cat "$LOG_B" || true
}

# ── 5. start the capture BEFORE either daemon starts ──────────────────────────
# Must be attached before A's very first punch attempt (t=0, well before
# ~PUNCH_MS) or the proof below is incomplete. `src host $IP_A` restricts the
# capture to A's own outbound datagrams -- see the header comment for why
# (excludes B's unrelated loser-glare traffic, which would otherwise be
# double-counted as a spurious second INIT ephemeral).
PCAP="$TMPDIR_TEST/pathswitch.pcap"
echo "[capture] starting tcpdump on $VETH_A_N (udp, src host $IP_A) -> $PCAP"
ip netns exec "$NS_A" tcpdump -i "$VETH_A_N" -w "$PCAP" -U udp and src host "$IP_A" \
    >"$TMPDIR_TEST/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 0.3

# ── 6. start yipd in A and B ───────────────────────────────────────────────────
echo "[start] starting yipPswA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipPswB"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 7. wait for TUN devices to appear in A and B ──────────────────────────────
TUN_WAIT=20
INTERVAL=0.25

echo "[wait] waiting for TUN devices to appear (up to ${TUN_WAIT}s)"
elapsed=0
while true; do
    A_UP=0; B_UP=0
    ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true

    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ]; then
        echo "[wait] both TUN devices are up"
        break
    fi

    if ! kill -0 "$PID_A" 2>/dev/null; then
        echo "[error] yipPswA daemon died unexpectedly"; dump_logs; exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipPswB daemon died unexpectedly"; dump_logs; exit 1
    fi
    if ! kill -0 "$PID_RDV" 2>/dev/null; then
        echo "[error] yip-rendezvous died unexpectedly"; dump_logs; exit 1
    fi

    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for TUN devices"; dump_logs; exit 1
    fi
    sleep "$INTERVAL"
done

# ── 8. assign each TUN its node_addr/128 + the mesh-prefix route ─────────────
echo "[setup] assigning node_addr/128 + fd00::/8 route on each TUN"
assign_mesh() {
    local ns="$1" addr="$2"
    ip netns exec "$ns" ip -6 addr add "${addr}/128" dev "$TUN_DEV" 2>/dev/null || true
    ip netns exec "$ns" ip -6 route add fd00::/8 dev "$TUN_DEV" 2>/dev/null || true
    ip netns exec "$ns" ip link show "$TUN_DEV" | grep -q "UP" || \
        ip netns exec "$ns" ip link set "$TUN_DEV" up
}
assign_mesh "$NS_A" "$ADDR_A"
assign_mesh "$NS_B" "$ADDR_B"

# ── 9. ping A->B, tolerating warm-up loss while the path escalates to relay ──
# Same tolerance run-netns-relay.sh documents: ~PUNCH_MS (5s) of unavoidable
# warm-up while the path state machine escalates from a silently-dropped
# direct punch to the blind relay. This proves initial convergence (with the
# #36 inversion, A still converges instead of black-holing, now via rebuild
# rather than ephemeral preservation) without the fixed warm-up window
# skewing a delivery percentage.
echo "[test] pinging ${ADDR_B} from yipPswA (expect escalate-to-relay warm-up loss, then success)"
set +e
ip netns exec "$NS_A" ping -6 -c 20 -W 2 "$ADDR_B"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -ne 0 ]; then
    echo "[FAIL] ping A->B did not converge (exit $PING_STATUS) — #36-inversion regression: A black-holed"
    dump_logs
    exit 1
fi
echo "[PASS] ping A->B converged over the relay"

# ── 9b. steady-state continuity, now that warm-up is over ──────────────────
# A fresh, stricter ping burst AFTER the path has already converged (step 9
# above): with the escalation's one-time warm-up loss out of the way, this
# is the ">=98% delivery" convergence bar the anti-replay.34 plan calls for
# — proving the rebuilt (fresh-ephemeral) relay session is fully stable, not
# just "received at least one reply".
STEADY_PING_LOG="$TMPDIR_TEST/steady_ping.log"
echo "[test] steady-state ping ${ADDR_B} from yipPswA (post-convergence, >=98% delivery required)"
set +e
ip netns exec "$NS_A" ping -6 -i 0.2 -c 50 -W 1 "$ADDR_B" >"$STEADY_PING_LOG" 2>&1
set -e
cat "$STEADY_PING_LOG"
LOSS_PCT="$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' "$STEADY_PING_LOG" | grep -oE '^[0-9]+(\.[0-9]+)?' || true)"
if [ -z "$LOSS_PCT" ]; then
    echo "[FAIL] convergence: could not parse packet loss from the steady-state ping output"
    dump_logs
    exit 1
fi
echo "[metric] convergence: steady-state packet loss = ${LOSS_PCT}%"
if awk "BEGIN {exit ($LOSS_PCT <= 2.0) ? 0 : 1}"; then
    echo "[PASS] convergence: ${LOSS_PCT}% loss (<=2%, i.e. >=98% delivery) in steady state over the relay"
else
    echo "[FAIL] convergence: ${LOSS_PCT}% loss (>2%, i.e. <98% delivery) — #36-inversion regression"
    dump_logs
    exit 1
fi

# ── 10. stop the capture ──────────────────────────────────────────────────────
sleep 0.3
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""

if ! kill -0 "$PID_A" 2>/dev/null; then
    echo "[error] yipPswA daemon died during the test"; dump_logs; exit 1
fi
if ! kill -0 "$PID_B" 2>/dev/null; then
    echo "[error] yipPswB daemon died during the test"; dump_logs; exit 1
fi

# ── assertion: relay actually carried it — relay-forwarded=<N>, N>0 ─────────
# One more sweep interval so R's final line reflects the traffic that just
# flowed (same convention as run-netns-relay.sh's money test).
sleep 5.5
FINAL_COUNT="$(grep -oE 'relay-forwarded=[0-9]+' "$LOG_RDV" | tail -1 | cut -d= -f2)"
echo "[check] server's final relay-forwarded count: ${FINAL_COUNT:-<none>}"
if [ -z "${FINAL_COUNT:-}" ] || [ "$FINAL_COUNT" -eq 0 ]; then
    echo "[FAIL] relay-forwarded count is 0 (or missing) — traffic did not go through the relay"
    dump_logs
    exit 1
fi
echo "[PASS] relay-forwarded=${FINAL_COUNT} (>0): the blind relay carried the traffic"

# ── assertion: fresh-ephemeral escalation — the #36-inversion headline proof ──
if [ ! -s "$PCAP" ]; then
    echo "[FAIL] fresh-ephemeral escalation: capture is empty or missing at $PCAP"
    dump_logs
    exit 1
fi

WITNESS_LOG="$TMPDIR_TEST/witness.log"
YIP_WITNESS_UNWRAP_RELAY=1 "$WITNESS_BIN" "$PCAP" >"$WITNESS_LOG"
cat "$WITNESS_LOG"

INIT_PKTS="$(grep -oE '^HANDSHAKE_INIT_PKTS=[0-9]+' "$WITNESS_LOG" | cut -d= -f2)"
DISTINCT_INIT="$(grep -oE '^DISTINCT_INIT_EPHEMERALS=[0-9]+' "$WITNESS_LOG" | cut -d= -f2)"

if [ -z "$INIT_PKTS" ] || [ -z "$DISTINCT_INIT" ]; then
    echo "[FAIL] fresh-ephemeral escalation: could not parse rekey_epoch_witness output"
    dump_logs
    exit 1
fi

# Non-vacuity: must have actually observed both the raw punch attempt and at
# least one relay-wrapped escalation retry -- else ">=2 distinct ephemerals"
# couldn't even be structurally possible with fewer than 2 Inits observed.
if [ "$INIT_PKTS" -lt 2 ]; then
    echo "[FAIL] fresh-ephemeral escalation: only $INIT_PKTS Init packet(s) captured from A (need >=2: punch attempt + relay retry) — test is vacuous, not proof"
    dump_logs
    exit 1
fi

# The money assertion (INVERTED from the pre-#34 test): at least two distinct
# cleartext ephemerals across every Init A itself sent (punch attempt +
# relay-wrapped retry/retries) -- proving the punch->relay retarget drew a
# FRESH ephemeral (Task 4's `state = Idle; begin_handshake(..)`) rather than
# reusing the punch attempt's. Exactly one would mean the OLD #36 behavior
# (ephemeral preservation) is still happening, which is now itself the
# regression: a preserved ephemeral is a bare retransmit the freshness gate
# would refuse as stale on a genuine replay, reopening the downgrade #34
# Task 4 closed.
if [ "$DISTINCT_INIT" -ge 2 ]; then
    echo "[PASS] fresh-ephemeral escalation: $INIT_PKTS Init packets from A, $DISTINCT_INIT distinct ephemerals (punch attempt + a freshly-drawn relay retry, no #36-preservation regression)"
else
    echo "[FAIL] fresh-ephemeral escalation: only $DISTINCT_INIT distinct Init ephemeral(s) from A (need >=2) — the punch->relay retarget reused the punch attempt's ephemeral, reproducing the OLD #36 behavior"
    dump_logs
    exit 1
fi

echo "[PASS] run-netns-pathswitch-rehandshake: A converged over the relay (>=98% steady-state delivery) via a freshly-drawn escalation ephemeral"
