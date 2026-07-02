#!/usr/bin/env bash
# Measure tunnel RTT for default driver vs YIP_FORCE_POLL=1 (clean link, no netem).
# Usage: run-driver-ab-rtt.sh <path-to-release-yipd>
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yip-driver-ab-rtt.XXXXXX)"

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

measure_mode() {
    local mode="$1"
  shift
    local -a env_args=("$@")

    cleanup
    trap cleanup EXIT

    TMPDIR_TEST="$(mktemp -d /tmp/yip-driver-ab-rtt.XXXXXX)"
    PID_A=""
    PID_B=""

    GENKEY_A="$("$YIPD" --genkey)"
    GENKEY_B="$("$YIPD" --genkey)"
    PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
    PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
    PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
    PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

    CFG_A="$TMPDIR_TEST/yipA.conf"
    CFG_B="$TMPDIR_TEST/yipB.conf"
    cat > "$CFG_A" <<EOF
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT_A}
peer_endpoint=${VETH_B_IP}:${PORT_B}
device=${TUN_DEV}
initiate=false
EOF
    cat > "$CFG_B" <<EOF
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT_B}
peer_endpoint=${VETH_A_IP}:${PORT_A}
device=${TUN_DEV}
initiate=true
EOF

    ip netns add "$NS_A"
    ip netns add "$NS_B"
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
    env "${env_args[@]}" ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
    PID_A=$!
    env "${env_args[@]}" ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
    PID_B=$!

    local elapsed=0
    while true; do
        local a_up=0 b_up=0
        ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && a_up=1 || true
        ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && b_up=1 || true
        if [ "$a_up" -eq 1 ] && [ "$b_up" -eq 1 ]; then
            break
        fi
        if ! kill -0 "$PID_A" 2>/dev/null || ! kill -0 "$PID_B" 2>/dev/null; then
            echo "[error] daemon died in mode=$mode" >&2
            cat "$LOG_A" "$LOG_B" >&2 || true
            exit 1
        fi
        elapsed=$(awk "BEGIN {print $elapsed + 0.25}")
        if awk "BEGIN {exit ($elapsed >= 20) ? 0 : 1}"; then
            echo "[error] TUN timeout mode=$mode" >&2
            exit 1
        fi
        sleep 0.25
    done

    ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
    ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
    sleep 0.5

    local ping_out
    ping_out="$(ip netns exec "$NS_B" ping -c 100 -i 0.02 -W 1 "$TUN_A_IP" 2>&1)" || true
    local rtt_avg
    rtt_avg="$(echo "$ping_out" | grep -oP 'rtt min/avg/max/mdev = [0-9./]+ ms' \
        | cut -d= -f2 | tr '/' ' ' | awk '{print $2}' || echo "N/A")"
    echo "RTT mode=${mode} avg_ms=${rtt_avg}"
}

measure_mode "uring"
measure_mode "poll" YIP_FORCE_POLL=1
