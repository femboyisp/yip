#!/usr/bin/env bash
# End-to-end netns QUIC-mimicry tunnel test for yipd (3c.1 Task 6).
# Usage: run-netns-quic.sh <path-to-yipd-binary>
#
# Creates two network namespaces (yipA, yipB) joined by a veth pair,
# starts a `transport=quic` yipd daemon in each (NO obf_psk — mutually
# exclusive with transport=quic, see config.rs), brings up TUN devices with
# tunnel IPs, then pings across the tunnel.
#
# Unlike run-netns-tunnel.sh, this is a TWO-layer bring-up: a real QUIC
# handshake (connection role decided by static-key order — see
# quic.rs::connection_role, NOT the legacy `initiate=` key, which is parsed
# but ignored) must complete before the inner yip Noise-IK handshake even
# starts, since the inner handshake rides QUIC DATAGRAM frames. That's two
# sequential handshakes before any tunnel traffic can flow, so the ping step
# below is deliberately as generous as the discovery money test
# (run-netns-discovery.sh: `ping -c 30 -W 2`, not the bare tunnel test's
# `ping -c 3 -W 5`) to absorb that extra warm-up without being flaky.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-quic-test.XXXXXX)"

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
    # Give them a moment to die
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
PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

# ── 2. write config files (transport=quic, NO obf_psk/cover_traffic_ms) ──────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipA — QUIC transport
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT_A}
peer_endpoint=${VETH_B_IP}:${PORT_B}
device=${TUN_DEV}
initiate=false
transport=quic
EOF

cat > "$CFG_B" <<EOF
# yipB — QUIC transport
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT_B}
peer_endpoint=${VETH_A_IP}:${PORT_A}
device=${TUN_DEV}
initiate=true
transport=quic
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

echo "[start] starting yipA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 5. wait for TUN device creation ──────────────────────────────────────────
# TunTap::create runs unconditionally before the transport dispatch in
# tunnel.rs::run, so the TUN device appears as soon as the daemon starts —
# this wait is NOT gated on the (two-layer) handshake completing. Same
# budget as the raw tunnel test is therefore fine here.
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

    # Check if either daemon died unexpectedly
    if ! kill -0 "$PID_A" 2>/dev/null; then
        echo "[error] yipA daemon died unexpectedly"
        echo "=== yipA log ==="
        cat "$LOG_A" || true
        exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipB daemon died unexpectedly"
        echo "=== yipB log ==="
        cat "$LOG_B" || true
        exit 1
    fi

    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for TUN devices"
        echo "=== yipA log ==="
        cat "$LOG_A" || true
        echo "=== yipB log ==="
        cat "$LOG_B" || true
        exit 1
    fi
    sleep "$INTERVAL"
done

# ── 6. assign tunnel IPs ──────────────────────────────────────────────────────
echo "[setup] assigning tunnel IPs"
ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/${TUN_PREFIX}" dev "$TUN_DEV"

# The TUN device is already brought up by the daemon (bring_up in TunTap::create).
# Verify the link is up; if not, bring it up explicitly.
ip netns exec "$NS_A" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_A" ip link set "$TUN_DEV" up
ip netns exec "$NS_B" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_B" ip link set "$TUN_DEV" up

echo "[check] interface state in yipA:"
ip netns exec "$NS_A" ip addr show "$TUN_DEV"
echo "[check] interface state in yipB:"
ip netns exec "$NS_B" ip addr show "$TUN_DEV"

# Brief additional settle time to ensure the data loops are ready
sleep 0.5

# ── 7. ping across the tunnel — generous warm-up (two sequential handshakes:
#      outer QUIC, then inner yip Noise-IK) ───────────────────────────────────
echo "[test] pinging ${TUN_A_IP} from yipB across the QUIC tunnel"
set +e
ip netns exec "$NS_B" ping -c 30 -W 2 "$TUN_A_IP"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -eq 0 ]; then
    echo "[PASS] ping succeeded over QUIC transport"
else
    echo "[FAIL] ping failed over QUIC transport (exit $PING_STATUS)"
    echo "=== yipA log ==="
    cat "$LOG_A" || true
    echo "=== yipB log ==="
    cat "$LOG_B" || true
    exit "$PING_STATUS"
fi
