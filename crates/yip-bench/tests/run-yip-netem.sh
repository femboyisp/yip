#!/usr/bin/env bash
# netem latency-and-loss harness for the yip tunnel.
# Usage: run-yip-netem.sh <path-to-yipd-binary>
#
# Sets up two network namespaces (yipA, yipB) joined by a veth pair,
# starts a yipd daemon in each, brings up the yip0 TUN tunnel, then
# sweeps across a set of packet-loss rates using tc netem on the veth
# pair.  For each rate it runs ping -c 100 across the TUNNEL and prints
# the effective (post-FEC) loss and RTT.
#
# The thesis: yip wraps each packet in RaptorQ FEC with proactive repair
# symbols, so the measured ping loss through the tunnel should be at or
# below the injected netem loss.
set -euo pipefail

# If a binary path is provided use it; otherwise build yipd and use target/debug/yipd.
if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    YIPD="$1"
else
    # Locate workspace root (parent of crates/yip-bench) and build yipd.
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
    echo "[build] running cargo build -p yipd --quiet in $WORKSPACE_ROOT"
    cargo build -p yipd --quiet --manifest-path "$WORKSPACE_ROOT/Cargo.toml"
    YIPD="$WORKSPACE_ROOT/target/debug/yipd"
fi

TMPDIR_TEST="$(mktemp -d /tmp/yipd-netem-test.XXXXXX)"

NS_A="yipA"
NS_B="yipB"
VETH_A="vethA"
VETH_B="vethB"
VETH_A_IP="10.0.0.1"
VETH_B_IP="10.0.0.2"
TUN_A_IP="10.9.0.1"
TUN_B_IP="10.9.0.2"
TUN_PREFIX="24"
VETH_PREFIX="24"
PORT_A="51820"
PORT_B="51821"
TUN_DEV="yip0"

PID_A=""
PID_B=""

cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. generate keypairs ──────────────────────────────────────────────────────
echo "[setup] generating keypairs"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"

PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A"  | grep '^public='  | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B"  | grep '^public='  | cut -d= -f2)"

# ── 2. write config files ─────────────────────────────────────────────────────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipA — responder
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT_A}
peer_endpoint=${VETH_B_IP}:${PORT_B}
device=${TUN_DEV}
initiate=false
EOF

cat > "$CFG_B" <<EOF
# yipB — initiator
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT_B}
peer_endpoint=${VETH_A_IP}:${PORT_A}
device=${TUN_DEV}
initiate=true
EOF

# ── 3. create namespaces and veth pair ────────────────────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"

echo "[setup] creating veth pair"
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

ip netns exec "$NS_A" ip addr add "${VETH_A_IP}/${VETH_PREFIX}" dev "$VETH_A"
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_A" ip link set lo up

ip netns exec "$NS_B" ip addr add "${VETH_B_IP}/${VETH_PREFIX}" dev "$VETH_B"
ip netns exec "$NS_B" ip link set "$VETH_B" up
ip netns exec "$NS_B" ip link set lo up

# ── 4. start daemons ─────────────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

echo "[start] starting yipA (responder)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB (initiator)"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 5. wait for handshake and TUN device creation ────────────────────────────
TUN_WAIT=20
INTERVAL=0.25

echo "[wait] waiting for TUN devices to appear (up to ${TUN_WAIT}s)"
elapsed=0
while true; do
    A_UP=0
    B_UP=0
    ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true

    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ]; then
        echo "[wait] both TUN devices are up"
        break
    fi

    if ! kill -0 "$PID_A" 2>/dev/null; then
        echo "[error] yipA daemon died unexpectedly"
        echo "=== yipA log ===" && cat "$LOG_A" || true
        exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipB daemon died unexpectedly"
        echo "=== yipB log ===" && cat "$LOG_B" || true
        exit 1
    fi

    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for TUN devices"
        echo "=== yipA log ===" && cat "$LOG_A" || true
        echo "=== yipB log ===" && cat "$LOG_B" || true
        exit 1
    fi
    sleep "$INTERVAL"
done

# ── 6. assign tunnel IPs ──────────────────────────────────────────────────────
echo "[setup] assigning tunnel IPs"
ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/${TUN_PREFIX}" dev "$TUN_DEV"

ip netns exec "$NS_A" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_A" ip link set "$TUN_DEV" up
ip netns exec "$NS_B" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_B" ip link set "$TUN_DEV" up

# Brief settle before the sweep
sleep 0.5

# ── 7. baseline connectivity check ───────────────────────────────────────────
echo "[check] baseline connectivity (3 pings, no netem)"
ip netns exec "$NS_B" ping -c 3 -W 5 "$TUN_A_IP" || {
    echo "[error] baseline ping failed — aborting sweep"
    echo "=== yipA log ===" && cat "$LOG_A" || true
    echo "=== yipB log ===" && cat "$LOG_B" || true
    exit 1
}

# ── 8. netem loss sweep ───────────────────────────────────────────────────────
LOSS_RATES="0 1 3 5 10"

echo ""
echo "=========================================================="
echo "  yip netem loss sweep"
echo "  ping -c 100 -i 0.05 -W 1 across TUN (${TUN_B_IP} -> ${TUN_A_IP})"
echo "  netem applied symmetrically on both veth ends + 5ms delay"
echo "=========================================================="
printf "%-16s  %-22s  %-12s  %-12s\n" \
       "injected_loss" "yip_effective_loss" "rtt_avg_ms" "rtt_max_ms"
echo "----------------------------------------------------------"

for LOSS in $LOSS_RATES; do
    # Apply netem on both veth ends for symmetrical impairment.
    # The yipd UDP control/data traffic traverses the veth pair, so
    # applying loss here degrades both the data symbols AND the
    # repair symbols — a realistic lossy-link scenario.
    ip netns exec "$NS_A" tc qdisc replace dev "$VETH_A" root netem \
        loss "${LOSS}%" delay 5ms
    ip netns exec "$NS_B" tc qdisc replace dev "$VETH_B" root netem \
        loss "${LOSS}%" delay 5ms

    # Run ping across the TUNNEL (not the veth directly).
    PING_OUT="$(ip netns exec "$NS_B" ping -c 100 -i 0.05 -W 1 "$TUN_A_IP" 2>&1)" || true

    # Parse: "100 packets transmitted, 97 received, 3% packet loss"
    EFFECTIVE_LOSS="$(echo "$PING_OUT" \
        | grep -oP '\d+% packet loss' | grep -oP '^\d+' || echo "100")"

    # Parse: "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms"
    RTT_LINE="$(echo "$PING_OUT" | grep -oP 'rtt min/avg/max/mdev = [0-9./]+ ms' || echo "")"
    if [ -n "$RTT_LINE" ]; then
        RTT_AVG="$(echo "$RTT_LINE" | cut -d= -f2 | tr '/' ' ' | awk '{print $2}')"
        RTT_MAX="$(echo "$RTT_LINE" | cut -d= -f2 | tr '/' ' ' | awk '{print $3}')"
    else
        RTT_AVG="N/A"
        RTT_MAX="N/A"
    fi

    printf "%-16s  %-22s  %-12s  %-12s\n" \
           "${LOSS}%" "${EFFECTIVE_LOSS}%" "${RTT_AVG}" "${RTT_MAX}"
done

echo "=========================================================="
echo ""
echo "[done] sweep complete"
