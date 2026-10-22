#!/usr/bin/env bash
# End-to-end netns tunnel test for yipd.
# Usage: run-netns-tunnel.sh <path-to-yipd-binary>
#
# Creates two network namespaces (yipA, yipB) joined by a veth pair,
# starts a yipd daemon in each, brings up TUN devices with tunnel IPs,
# then pings across the encrypted FEC tunnel.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-test.XXXXXX)"

NS_A="${NS_A:-yipA}"
NS_B="${NS_B:-yipB}"
VETH_A="${VETH_A:-vethA}"
VETH_B="${VETH_B:-vethB}"
VETH_A_IP="10.0.0.1"
VETH_B_IP="10.0.0.2"
TUN_A_IP="10.9.0.1"
TUN_B_IP="10.9.0.2"
TUN_PREFIX="24"
VETH_PREFIX="24"
PORT_A="${PORT_A:-51820}"
PORT_B="${PORT_B:-51821}"
TUN_DEV="yip0"

PID_A=""
PID_B=""
TCPDUMP_PID=""
IPERF_PID=""

cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2>/dev/null || true
    [ -n "$TCPDUMP_PID" ] && kill "$TCPDUMP_PID" 2>/dev/null || true
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    # Give them a moment to die
    sleep 0.2
    [ -n "$IPERF_PID" ] && kill -9 "$IPERF_PID" 2>/dev/null || true
    [ -n "$TCPDUMP_PID" ] && kill -9 "$TCPDUMP_PID" 2>/dev/null || true
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
[ -n "${OBF_PSK:-}" ] && echo "obf_psk=${OBF_PSK}" >> "$CFG_A"
[ -n "${COVER_MS:-}" ] && echo "cover_traffic_ms=${COVER_MS}" >> "$CFG_A"
[ -n "${TRAFFIC_DEFENSE:-}" ] && echo "traffic_defense=${TRAFFIC_DEFENSE}" >> "$CFG_A"

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
[ -n "${OBF_PSK:-}" ] && echo "obf_psk=${OBF_PSK}" >> "$CFG_B"
[ -n "${COVER_MS:-}" ] && echo "cover_traffic_ms=${COVER_MS}" >> "$CFG_B"
[ -n "${TRAFFIC_DEFENSE:-}" ] && echo "traffic_defense=${TRAFFIC_DEFENSE}" >> "$CFG_B"

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
ip netns exec "$NS_A" ethtool -K "$VETH_A" rx off tx off gso off gro off tso off tx-udp-segmentation off 2>/dev/null || true

ip netns exec "$NS_B" ip addr add "${VETH_B_IP}/${VETH_PREFIX}" dev "$VETH_B"
ip netns exec "$NS_B" ip link set "$VETH_B" up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_B" ethtool -K "$VETH_B" rx off tx off gso off gro off tso off tx-udp-segmentation off 2>/dev/null || true

# ── 4. start tcpdump if requested ──────────────────────────────────────────
if [ -n "${CAPTURE_PCAP:-}" ]; then
    echo "[capture] starting tcpdump inside $NS_B on $VETH_B"
    mkdir -p "$(dirname "$CAPTURE_PCAP")"
    ip netns exec "$NS_B" tcpdump -nn -i "$VETH_B" -w "$CAPTURE_PCAP" -U "udp and (port $PORT_A or port $PORT_B)" >"$TMPDIR_TEST/tcpdump.log" 2>&1 &
    TCPDUMP_PID=$!
    sleep 0.2
fi

# ── 5. start daemons ─────────────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

echo "[start] starting yipA (responder)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB (initiator)"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 5. wait for handshake and TUN device creation ────────────────────────────
# The daemons create the TUN device after a successful handshake.
# Poll for the TUN device to appear in each namespace (up to 10s).
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

# ── 7. ping across the tunnel ─────────────────────────────────────────────────
PING_COUNT="${PING_COUNT:-3}"
PING_ARGS=(-c "$PING_COUNT" -W 5)
if [ "$PING_COUNT" -gt 5 ]; then
    # When sending many pings (e.g. 50), use interval 0.05s to finish fast (~2.5s)
    PING_ARGS=(-c "$PING_COUNT" -i 0.05 -W 5)
fi

echo "[test] pinging ${TUN_A_IP} from yipB across the tunnel (${PING_COUNT} pings)"
if ip netns exec "$NS_B" ping "${PING_ARGS[@]}" "$TUN_A_IP"; then
    echo "[PASS] ping B -> A succeeded"
else
    PING_EXIT=$?
    echo "[FAIL] ping B -> A failed (exit $PING_EXIT)"
    echo "=== yipA log ==="
    cat "$LOG_A" || true
    echo "=== yipB log ==="
    cat "$LOG_B" || true
    exit "$PING_EXIT"
fi

if [ "${BIDI_PING:-0}" = "1" ]; then
    echo "[test] pinging ${TUN_B_IP} from yipA across the tunnel (${PING_COUNT} pings)"
    if ip netns exec "$NS_A" ping "${PING_ARGS[@]}" "$TUN_B_IP"; then
        echo "[PASS] ping A -> B succeeded"
    else
        PING_EXIT=$?
        echo "[FAIL] ping A -> B failed (exit $PING_EXIT)"
        echo "=== yipA log ==="
        cat "$LOG_A" || true
        echo "=== yipB log ==="
        cat "$LOG_B" || true
        exit "$PING_EXIT"
    fi
fi

# ── 8. TCP iperf3 throughput test ───────────────────────────────────────────
if [ "${RUN_IPERF:-0}" = "1" ]; then
    echo "[test] starting 3-second TCP iperf3 across the tunnel"
    IPERF_SERVER_LOG="$TMPDIR_TEST/iperf_server.log"
    IPERF_CLIENT_LOG="$TMPDIR_TEST/iperf_client.log"
    ip netns exec "$NS_A" iperf3 -s -1 -p 5201 >"$IPERF_SERVER_LOG" 2>&1 &
    IPERF_PID=$!
    sleep 0.3
    if ip netns exec "$NS_B" iperf3 -c "$TUN_A_IP" -p 5201 -t 3 >"$IPERF_CLIENT_LOG" 2>&1; then
        echo "[PASS] iperf3 succeeded"
        cat "$IPERF_CLIENT_LOG"
        wait "$IPERF_PID" 2>/dev/null || true
        IPERF_PID=""
    else
        IPERF_EXIT=$?
        echo "[FAIL] iperf3 failed (exit $IPERF_EXIT)"
        cat "$IPERF_CLIENT_LOG" || true
        cat "$IPERF_SERVER_LOG" || true
        echo "=== yipA log ==="
        cat "$LOG_A" || true
        echo "=== yipB log ==="
        cat "$LOG_B" || true
        exit "$IPERF_EXIT"
    fi
fi

# ── 9. stop tcpdump if running ───────────────────────────────────────────────
if [ -n "$TCPDUMP_PID" ]; then
    echo "[capture] stopping tcpdump"
    sleep 0.5
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    TCPDUMP_PID=""
    chmod 666 "$CAPTURE_PCAP" 2>/dev/null || true
fi
