#!/usr/bin/env bash
# End-to-end L2 TAP netns tunnel test for yipd.
# Usage: run-netns-tunnel-l2.sh <path-to-yipd-binary>
#
# Creates two network namespaces (yipA, yipB) joined by a veth pair,
# starts a yipd daemon in each with device_kind=tap, assigns IPv4 addrs
# on the TAP devices, then verifies L2 traffic crosses the tunnel by
# accepting either:
#   1) successful ICMP ping over TAP, or
#   2) successful ARP neighbor learning over TAP.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-l2-test.XXXXXX)"

NS_A="yipA"
NS_B="yipB"
VETH_A="vethA"
VETH_B="vethB"
VETH_A_IP="10.0.0.1"
VETH_B_IP="10.0.0.2"
VETH_PREFIX="24"
PORT_A="51820"
PORT_B="51821"
TAP_DEV="yip0"
TAP_A_IP="10.9.0.1"
TAP_B_IP="10.9.0.2"
TAP_PREFIX="24"

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

echo "[setup] generating keypairs"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"

PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat >"$CFG_A" <<EOF
# yipA — responder
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT_A}
peer_endpoint=${VETH_B_IP}:${PORT_B}
device=${TAP_DEV}
device_kind=tap
initiate=false
EOF

cat >"$CFG_B" <<EOF
# yipB — initiator
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT_B}
peer_endpoint=${VETH_A_IP}:${PORT_A}
device=${TAP_DEV}
device_kind=tap
initiate=true
EOF

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

LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

echo "[start] starting yipA (responder)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB (initiator)"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

DEV_WAIT=20
INTERVAL=0.25

echo "[wait] waiting for TAP devices to appear (up to ${DEV_WAIT}s)"
elapsed=0
while true; do
    A_UP=0
    B_UP=0
    ip netns exec "$NS_A" ip link show "$TAP_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$TAP_DEV" >/dev/null 2>&1 && B_UP=1 || true

    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ]; then
        echo "[wait] both TAP devices are up"
        break
    fi

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
    if awk "BEGIN {exit ($elapsed >= $DEV_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for TAP devices"
        echo "=== yipA log ==="
        cat "$LOG_A" || true
        echo "=== yipB log ==="
        cat "$LOG_B" || true
        exit 1
    fi
    sleep "$INTERVAL"
done

echo "[setup] assigning TAP IPv4 addresses for ARP+ICMP validation"
ip netns exec "$NS_A" ip addr add "${TAP_A_IP}/${TAP_PREFIX}" dev "$TAP_DEV"
ip netns exec "$NS_B" ip addr add "${TAP_B_IP}/${TAP_PREFIX}" dev "$TAP_DEV"

ip netns exec "$NS_A" ip link show "$TAP_DEV" | grep -q "UP" || \
    ip netns exec "$NS_A" ip link set "$TAP_DEV" up
ip netns exec "$NS_B" ip link show "$TAP_DEV" | grep -q "UP" || \
    ip netns exec "$NS_B" ip link set "$TAP_DEV" up

echo "[check] interface state in yipA:"
ip netns exec "$NS_A" ip addr show "$TAP_DEV"
echo "[check] interface state in yipB:"
ip netns exec "$NS_B" ip addr show "$TAP_DEV"

sleep 0.5

echo "[test] try ICMP ping over TAP first"
if ip netns exec "$NS_B" ping -c 3 -W 5 "$TAP_A_IP"; then
    echo "[PASS] L2 TAP flow validated by ping"
    exit 0
fi

echo "[warn] ping failed, checking ARP neighbor learning as fallback"
ip netns exec "$NS_B" ip neigh flush dev "$TAP_DEV" || true
ip netns exec "$NS_B" ping -c 1 -W 2 "$TAP_A_IP" >/dev/null 2>&1 || true

NEIGH_LINE="$(ip netns exec "$NS_B" ip neigh show "$TAP_A_IP" dev "$TAP_DEV" || true)"
echo "[check] neighbor entry on yipB: ${NEIGH_LINE:-<none>}"
if echo "$NEIGH_LINE" | grep -Eq 'lladdr [0-9a-f:]{17}'; then
    echo "[PASS] L2 TAP flow validated by ARP neighbor learning"
    exit 0
fi

echo "[FAIL] neither ping nor ARP neighbor learning succeeded across TAP tunnel"
echo "=== yipA neighbors ==="
ip netns exec "$NS_A" ip neigh show || true
echo "=== yipB neighbors ==="
ip netns exec "$NS_B" ip neigh show || true
echo "=== yipA log ==="
cat "$LOG_A" || true
echo "=== yipB log ==="
cat "$LOG_B" || true
exit 1
