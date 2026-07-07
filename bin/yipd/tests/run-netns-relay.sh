#!/usr/bin/env bash
# "relay_path_ping" money test for yipd's rendezvous/relay path (2b).
# Usage: run-netns-relay.sh <path-to-yipd-binary> <path-to-yip-rendezvous-binary>
#
# Topology: three netns, A / B / R (rendezvous+relay server).
#   A --10.70.0.0/24-- R --10.71.0.0/24-- B
# Two point-to-point veth pairs (A<->R, B<->R); no shared bridge. A's only
# route beyond its own /24 is a DEFAULT route via R (10.70.0.1); B's only
# route beyond its own /24 is a DEFAULT route via R (10.71.0.1). R does NOT
# have IPv4 forwarding enabled, so a packet A sends toward B's subnet reaches
# R (the default gateway) and is silently dropped there instead of being
# forwarded on to B — A and B have NO reachability to each other, only to
# R's yip-rendezvous socket (bound on both subnets via 0.0.0.0).
#
# yipd A and B each list the OTHER by public_key only (no endpoint) and set
# rendezvous=<R's address on their own subnet>. On startup each peer's path
# state machine: registers with R, looks up the other, learns the other's
# server-observed reflexive addr (on the UNREACHABLE far subnet), attempts a
# punch Init toward it (silently dropped by R), and after ~PUNCH_MS (5s)
# escalates to the blind relay through R — which DOES reach the peer, since
# R's relay forwards by rewriting to the registered reflexive addr rather
# than routing the original packet.
#
# Assert: ping succeeds (tolerating warm-up loss during
# lookup->punch-attempt->escalate->relay-handshake) AND the server's final
# `relay-forwarded=<N>` (grepped from its stderr log) has N>0 — proving the
# BLIND RELAY, not a direct/punched path, carried the traffic.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
RDV="${2:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-relay-test.XXXXXX)"

NS_A="yipRelA"
NS_B="yipRelB"
NS_R="yipRelR"

VETH_A_N="vRelA1"; VETH_A_R="vRelA0"   # A<->R pair: A-side, R-side
VETH_B_N="vRelB1"; VETH_B_R="vRelB0"   # B<->R pair: B-side, R-side

IP_A="10.70.0.2"
IP_R_A="10.70.0.1"   # R's address on A's subnet
IP_B="10.71.0.2"
IP_R_B="10.71.0.1"   # R's address on B's subnet
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
    ip netns del "$NS_R" 2>/dev/null || true
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
# yipRelA
local_private=${PRIV_A}
local_public=${PUB_A}
listen=${IP_A}:${PORT_A}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_R_A}:${RDV_PORT}
[peer]
public_key=${PUB_B}
EOF
[ -n "${OBF_PSK:-}" ] && echo "obf_psk=${OBF_PSK}" >> "$CFG_A"

cat > "$CFG_B" <<EOF
# yipRelB
local_private=${PRIV_B}
local_public=${PUB_B}
listen=${IP_B}:${PORT_B}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_R_B}:${RDV_PORT}
[peer]
public_key=${PUB_A}
EOF
[ -n "${OBF_PSK:-}" ] && echo "obf_psk=${OBF_PSK}" >> "$CFG_B"

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
# forward, so this is a route to nowhere for cross-subnet traffic (the kernel
# accepts the sendto() instead of failing it with ENETUNREACH, but the
# packet dies silently at R). This is what makes A and B mutually
# unreachable while keeping the punch attempt a normal (silently-dropped)
# packet rather than a synchronous socket error that would kill yipd's event
# loop.
ip netns exec "$NS_A" ip route add default via "$IP_R_A" dev "$VETH_A_N"
ip netns exec "$NS_B" ip route add default via "$IP_R_B" dev "$VETH_B_N"

# Explicitly disable IPv4 forwarding in R (belt-and-suspenders: a fresh netns
# already defaults to this, but the isolation invariant this whole test rests
# on deserves to be asserted, not assumed).
ip netns exec "$NS_R" sysctl -q -w net.ipv4.ip_forward=0
ip netns exec "$NS_R" sysctl -q -w net.ipv4.conf.all.forwarding=0

# ── 4. start yip-rendezvous in R, bound on both subnets ───────────────────────
LOG_RDV="$TMPDIR_TEST/rdv.log"
RDV_ARGS=("0.0.0.0:${RDV_PORT}")
[ -n "${OBF_PSK:-}" ] && RDV_ARGS+=(--obf-psk "${OBF_PSK}")
echo "[start] starting yip-rendezvous in R on 0.0.0.0:${RDV_PORT}"
ip netns exec "$NS_R" "$RDV" "${RDV_ARGS[@]}" >"$LOG_RDV" 2>&1 &
PID_RDV=$!
sleep 0.3

# ── 5. start yipd in A and B ───────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

dump_logs() {
    echo "=== rendezvous log ==="
    cat "$LOG_RDV" || true
    echo "=== yipRelA log ==="
    cat "$LOG_A" || true
    echo "=== yipRelB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipRelA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipRelB"
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
        echo "[error] yipRelA daemon died unexpectedly"; dump_logs; exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipRelB daemon died unexpectedly"; dump_logs; exit 1
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

echo "[check] interface state in yipRelA:"
ip netns exec "$NS_A" ip -6 addr show "$TUN_DEV"
echo "[check] interface state in yipRelB:"
ip netns exec "$NS_B" ip -6 addr show "$TUN_DEV"

# ── 8. ping A->B, tolerating warm-up loss while the path escalates to relay ──
# Escalation timing (PUNCH_MS = 5s): Lookup -> reflexive candidate -> punch
# Init (silently dropped by R) -> ~5s later, escalate to relay -> relay
# handshake completes in ~1 RTT. A generous count/timeout absorbs that
# warm-up; ping's own exit code already only requires >=1 reply (see
# `ping_across_yipd_tunnel_under_loss` for the same tolerance pattern), so no
# `|| true` is needed to keep the measured result load-bearing.
echo "[test] pinging ${ADDR_B} from yipRelA (expect escalate-to-relay warm-up loss, then success)"
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

# ── 9. assert the relay actually carried it: relay-forwarded=<N>, N>0 ────────
# Give the server one more sweep interval to emit a final relay-forwarded
# line reflecting the traffic that just flowed.
sleep 5.5
FINAL_COUNT="$(grep -oE 'relay-forwarded=[0-9]+' "$LOG_RDV" | tail -1 | cut -d= -f2)"
echo "[check] server's final relay-forwarded count: ${FINAL_COUNT:-<none>}"
if [ -z "${FINAL_COUNT:-}" ] || [ "$FINAL_COUNT" -eq 0 ]; then
    echo "[FAIL] relay-forwarded count is 0 (or missing) — traffic did not go through the relay"
    dump_logs
    exit 1
fi
echo "[PASS] relay-forwarded=${FINAL_COUNT} (>0): the blind relay carried the traffic"
