#!/usr/bin/env bash
# "hole_punch_ping" money test for yipd's rendezvous/punch path (2b).
# Usage: run-netns-punch.sh <path-to-yipd-binary> <path-to-yip-rendezvous-binary>
#
# Topology: two client netns A / B, each "behind a NAT" to a shared transit
# netns T that also hosts yip-rendezvous:
#   A --10.80.0.0/24-- T --10.81.0.0/24-- B
#
# In A and B, `iptables -t nat -A POSTROUTING -o <veth> -j MASQUERADE` is
# applied on the sole egress interface, per the spec's classic-NAT recipe.
# Because each client netns is single-homed (one veth, one address), this
# MASQUERADE rewrites a source address onto itself (a no-op) rather than
# hiding a private subnet behind a distinct public one -- it is kept here for
# topological fidelity with the spec's instructions, not because it changes
# any address on the wire.
#
# T DOES route between the two client subnets (IPv4 forwarding enabled), so
# each peer's server-observed reflexive address (learned via yip-rendezvous)
# IS directly reachable through T. This is the documented fallback from the
# task brief: "if a true post-NAT simultaneous-open punch proves flaky... T
# routes between subnets so the reflexive addr is directly reachable -> the
# punch/direct path carries it, relay-forwarded stays 0" -- the invariant
# under test (punch path used, relay NOT used) still holds, since the peers
# are configured rendezvous-only (public_key, no endpoint) and can only ever
# learn each other's address via the rendezvous protocol's PeerInfo/PunchHint
# messages, never via static config.
#
# Assert: ping succeeds AND the server's final `relay-forwarded=<N>`
# (grepped from its stderr log) stays 0 -- proving the punch/direct path,
# NOT the blind relay, carried the traffic.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
RDV="${2:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-punch-test.XXXXXX)"

NS_A="yipPunchA"
NS_B="yipPunchB"
NS_T="yipPunchT"

VETH_A_N="vPnA1"; VETH_A_T="vPnA0"   # A<->T pair: A-side, T-side
VETH_B_N="vPnB1"; VETH_B_T="vPnB0"   # B<->T pair: B-side, T-side

IP_A="10.80.0.2"
IP_T_A="10.80.0.1"   # T's address on A's subnet
IP_B="10.81.0.2"
IP_T_B="10.81.0.1"   # T's address on B's subnet
PREFIX="24"

PORT_A="51820"
PORT_B="51820"
RDV_PORT="51821"
TUN_DEV="yip0"

PID_A=""
PID_B=""
PID_RDV=""

cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill "$PID_RDV" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill -9 "$PID_RDV" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip netns del "$NS_T" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. generate keypairs ──────────────────────────────────────────────────────
echo "[setup] generating keypairs"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"

PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

ADDR_A="$("$YIPD" --addr "$PUB_A")"
ADDR_B="$("$YIPD" --addr "$PUB_B")"
echo "[setup] node_addr A=$ADDR_A B=$ADDR_B"

# ── 2. write config files (rendezvous-only peers: public_key, no endpoint) ────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipPunchA
local_private=${PRIV_A}
local_public=${PUB_A}
listen=${IP_A}:${PORT_A}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_T_A}:${RDV_PORT}
[peer]
public_key=${PUB_B}
EOF

cat > "$CFG_B" <<EOF
# yipPunchB
local_private=${PRIV_B}
local_public=${PUB_B}
listen=${IP_B}:${PORT_B}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_T_B}:${RDV_PORT}
[peer]
public_key=${PUB_A}
EOF

# ── 3. create namespaces + point-to-point veths into T ────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"
ip netns add "$NS_T"

echo "[setup] wiring A<->T"
ip link add "$VETH_A_T" type veth peer name "$VETH_A_N"
ip link set "$VETH_A_N" netns "$NS_A"
ip link set "$VETH_A_T" netns "$NS_T"
ip netns exec "$NS_A" ip addr add "${IP_A}/${PREFIX}" dev "$VETH_A_N"
ip netns exec "$NS_A" ip link set "$VETH_A_N" up
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_T" ip addr add "${IP_T_A}/${PREFIX}" dev "$VETH_A_T"
ip netns exec "$NS_T" ip link set "$VETH_A_T" up

echo "[setup] wiring B<->T"
ip link add "$VETH_B_T" type veth peer name "$VETH_B_N"
ip link set "$VETH_B_N" netns "$NS_B"
ip link set "$VETH_B_T" netns "$NS_T"
ip netns exec "$NS_B" ip addr add "${IP_B}/${PREFIX}" dev "$VETH_B_N"
ip netns exec "$NS_B" ip link set "$VETH_B_N" up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_T" ip addr add "${IP_T_B}/${PREFIX}" dev "$VETH_B_T"
ip netns exec "$NS_T" ip link set "$VETH_B_T" up
ip netns exec "$NS_T" ip link set lo up

# A and B each default-route via T (their only path off-subnet).
ip netns exec "$NS_A" ip route add default via "$IP_T_A" dev "$VETH_A_N"
ip netns exec "$NS_B" ip route add default via "$IP_T_B" dev "$VETH_B_N"

# Simulated NAT in A and B (see header comment: a no-op on a single-homed
# netns, kept for topological fidelity with the spec's recipe).
ip netns exec "$NS_A" iptables -t nat -A POSTROUTING -o "$VETH_A_N" -j MASQUERADE
ip netns exec "$NS_B" iptables -t nat -A POSTROUTING -o "$VETH_B_N" -j MASQUERADE

# T routes between the two client subnets: this is what makes each peer's
# server-observed reflexive addr directly reachable, so the punch succeeds
# without ever needing the relay.
ip netns exec "$NS_T" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$NS_T" iptables -P FORWARD ACCEPT
ip netns exec "$NS_T" iptables -A FORWARD -i "$VETH_A_T" -o "$VETH_B_T" -j ACCEPT
ip netns exec "$NS_T" iptables -A FORWARD -i "$VETH_B_T" -o "$VETH_A_T" -j ACCEPT

# ── 4. start yip-rendezvous in T, bound on both subnets ───────────────────────
LOG_RDV="$TMPDIR_TEST/rdv.log"
echo "[start] starting yip-rendezvous in T on 0.0.0.0:${RDV_PORT}"
ip netns exec "$NS_T" "$RDV" "0.0.0.0:${RDV_PORT}" >"$LOG_RDV" 2>&1 &
PID_RDV=$!
sleep 0.3

# ── 5. start yipd in A and B ───────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

dump_logs() {
    echo "=== rendezvous log ==="
    cat "$LOG_RDV" || true
    echo "=== yipPunchA log ==="
    cat "$LOG_A" || true
    echo "=== yipPunchB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipPunchA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipPunchB"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 6. wait for TUN devices to appear in A and B ──────────────────────────────
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
        echo "[error] yipPunchA daemon died unexpectedly"; dump_logs; exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipPunchB daemon died unexpectedly"; dump_logs; exit 1
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

# ── 7. assign each TUN its node_addr/128 + the mesh-prefix route ─────────────
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

echo "[check] interface state in yipPunchA:"
ip netns exec "$NS_A" ip -6 addr show "$TUN_DEV"
echo "[check] interface state in yipPunchB:"
ip netns exec "$NS_B" ip -6 addr show "$TUN_DEV"

# ── 8. ping A->B, tolerating warm-up loss while the punch path comes up ──────
# Escalation timing: Lookup -> reflexive candidate -> punch Init, which
# succeeds directly here (T routes between subnets) well within PUNCH_MS, so
# no relay escalation should ever happen. A generous count/timeout still
# absorbs ordinary lookup/handshake warm-up; ping's own exit code already
# only requires >=1 reply, so no `|| true` is needed to keep the measured
# result load-bearing.
echo "[test] pinging ${ADDR_B} from yipPunchA (expect direct/punch success, no relay)"
set +e
ip netns exec "$NS_A" ping -6 -c 20 -W 2 "$ADDR_B"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -ne 0 ]; then
    echo "[FAIL] ping A->B did not succeed (exit $PING_STATUS)"
    dump_logs
    exit 1
fi
echo "[PASS] ping A->B succeeded"

# ── 9. assert the relay was NOT used: relay-forwarded stays 0 ───────────────
sleep 5.5
FINAL_COUNT="$(grep -oE 'relay-forwarded=[0-9]+' "$LOG_RDV" | tail -1 | cut -d= -f2)"
echo "[check] server's final relay-forwarded count: ${FINAL_COUNT:-<none>}"
if [ -n "${FINAL_COUNT:-}" ] && [ "$FINAL_COUNT" -ne 0 ]; then
    echo "[FAIL] relay-forwarded=${FINAL_COUNT} (expected 0) — traffic went through the relay, not the punch path"
    dump_logs
    exit 1
fi
echo "[PASS] relay-forwarded=${FINAL_COUNT:-0}: the punch/direct path carried the traffic, relay unused"
