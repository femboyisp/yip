#!/usr/bin/env bash
# 3-peer full-mesh netns "triangle" test for yipd.
# Usage: run-netns-triangle.sh <path-to-yipd-binary>
#
# Creates three network namespaces (A/B/C), each with a veth attached to a
# shared Linux bridge in the root namespace (one L2 underlay segment), starts
# a yipd daemon in each with a 2-peer static config (the *other* two nodes),
# assigns each TUN device its own self-certifying mesh address (node_addr,
# derived from the node's public key via `yipd --addr`), and pings across
# every leg of the mesh: A->B, A->C, B->C.
#
# Unlike the single-peer netns tests (which assign plain IPv4 addresses to
# the TUN device and rely on PeerManager's single-peer fallback routing),
# this test exercises the REAL multi-peer routing path: each ping targets a
# peer's node_addr, so PeerManager's `by_addr` lookup must pick the right
# peer's DataPlane out of two configured peers.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-triangle-test.XXXXXX)"

BR="brTri0"

NS_A="yipTriA"
NS_B="yipTriB"
NS_C="yipTriC"

# Host-side veth ends (attached to the bridge) and their netns-side peers.
VETH_A_H="vTriA0"; VETH_A_N="vTriA1"
VETH_B_H="vTriB0"; VETH_B_N="vTriB1"
VETH_C_H="vTriC0"; VETH_C_N="vTriC1"

IP_A="10.9.0.1"
IP_B="10.9.0.2"
IP_C="10.9.0.3"
VETH_PREFIX="24"
PORT="51820"
TUN_DEV="yip0"

PID_A=""
PID_B=""
PID_C=""

cleanup() {
    echo "[cleanup] killing daemons and removing namespaces/bridge"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_C" ] && kill "$PID_C" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    [ -n "$PID_C" ] && kill -9 "$PID_C" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip netns del "$NS_C" 2>/dev/null || true
    ip link del "$BR" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. generate keypairs ──────────────────────────────────────────────────────
echo "[setup] generating keypairs"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"
GENKEY_C="$("$YIPD" --genkey)"

PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"
PRIV_C="$(echo "$GENKEY_C" | grep '^private=' | cut -d= -f2)"
PUB_C="$(echo "$GENKEY_C" | grep '^public=' | cut -d= -f2)"

# ── 2. compute each node's self-certifying mesh address ───────────────────────
ADDR_A="$("$YIPD" --addr "$PUB_A")"
ADDR_B="$("$YIPD" --addr "$PUB_B")"
ADDR_C="$("$YIPD" --addr "$PUB_C")"
echo "[setup] node_addr A=$ADDR_A B=$ADDR_B C=$ADDR_C"

# ── 3. write config files (2-peer block syntax — each node lists the OTHER two) ─
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"
CFG_C="$TMPDIR_TEST/yipC.conf"

cat > "$CFG_A" <<EOF
# yipTriA
local_private=${PRIV_A}
local_public=${PUB_A}
listen=${IP_A}:${PORT}
device=${TUN_DEV}
device_kind=tun
[peer]
public_key=${PUB_B}
endpoint=${IP_B}:${PORT}
[peer]
public_key=${PUB_C}
endpoint=${IP_C}:${PORT}
EOF

cat > "$CFG_B" <<EOF
# yipTriB
local_private=${PRIV_B}
local_public=${PUB_B}
listen=${IP_B}:${PORT}
device=${TUN_DEV}
device_kind=tun
[peer]
public_key=${PUB_A}
endpoint=${IP_A}:${PORT}
[peer]
public_key=${PUB_C}
endpoint=${IP_C}:${PORT}
EOF

cat > "$CFG_C" <<EOF
# yipTriC
local_private=${PRIV_C}
local_public=${PUB_C}
listen=${IP_C}:${PORT}
device=${TUN_DEV}
device_kind=tun
[peer]
public_key=${PUB_A}
endpoint=${IP_A}:${PORT}
[peer]
public_key=${PUB_B}
endpoint=${IP_B}:${PORT}
EOF

# ── 4. create namespaces + shared bridge underlay ─────────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"
ip netns add "$NS_C"

echo "[setup] creating bridge $BR in the root namespace"
ip link add "$BR" type bridge
ip link set "$BR" up

setup_leg() {
    local ns="$1" veth_h="$2" veth_n="$3" ip_addr="$4"
    ip link add "$veth_h" type veth peer name "$veth_n"
    ip link set "$veth_n" netns "$ns"
    ip link set "$veth_h" master "$BR"
    ip link set "$veth_h" up
    ip netns exec "$ns" ip addr add "${ip_addr}/${VETH_PREFIX}" dev "$veth_n"
    ip netns exec "$ns" ip link set "$veth_n" up
    ip netns exec "$ns" ip link set lo up
}

echo "[setup] wiring veths to the bridge"
setup_leg "$NS_A" "$VETH_A_H" "$VETH_A_N" "$IP_A"
setup_leg "$NS_B" "$VETH_B_H" "$VETH_B_N" "$IP_B"
setup_leg "$NS_C" "$VETH_C_H" "$VETH_C_N" "$IP_C"

# ── 5. start daemons ───────────────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"
LOG_C="$TMPDIR_TEST/yipC.log"

dump_logs() {
    echo "=== yipTriA log ==="
    cat "$LOG_A" || true
    echo "=== yipTriB log ==="
    cat "$LOG_B" || true
    echo "=== yipTriC log ==="
    cat "$LOG_C" || true
}

echo "[start] starting yipTriA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipTriB"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

echo "[start] starting yipTriC"
ip netns exec "$NS_C" "$YIPD" "$CFG_C" >"$LOG_C" 2>&1 &
PID_C=$!

# ── 6. wait for TUN devices to appear in all three namespaces ─────────────────
TUN_WAIT=20
INTERVAL=0.25

echo "[wait] waiting for TUN devices to appear (up to ${TUN_WAIT}s)"
elapsed=0
while true; do
    A_UP=0; B_UP=0; C_UP=0
    ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true
    ip netns exec "$NS_C" ip link show "$TUN_DEV" >/dev/null 2>&1 && C_UP=1 || true

    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ] && [ "$C_UP" -eq 1 ]; then
        echo "[wait] all three TUN devices are up"
        break
    fi

    for pid_var_name in PID_A:yipTriA PID_B:yipTriB PID_C:yipTriC; do
        pid_var="${pid_var_name%%:*}"
        node_name="${pid_var_name##*:}"
        pid="${!pid_var}"
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[error] $node_name daemon died unexpectedly"
            dump_logs
            exit 1
        fi
    done

    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for TUN devices"
        dump_logs
        exit 1
    fi
    sleep "$INTERVAL"
done

# ── 7. assign each TUN its own node_addr/128 + the mesh-prefix route ──────────
# yipd's own `assign_mesh_address` already does this best-effort (and swallows
# failures), so this is belt-and-suspenders: guard every command so a
# pre-existing address/route (already assigned by the daemon) does not trip
# `set -e`.
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
assign_mesh "$NS_C" "$ADDR_C"

echo "[check] interface state in yipTriA:"
ip netns exec "$NS_A" ip -6 addr show "$TUN_DEV"
echo "[check] interface state in yipTriB:"
ip netns exec "$NS_B" ip -6 addr show "$TUN_DEV"
echo "[check] interface state in yipTriC:"
ip netns exec "$NS_C" ip -6 addr show "$TUN_DEV"

# Brief additional settle time to ensure the data loops are ready.
sleep 0.5

# ── 8. full-mesh ping across every leg ────────────────────────────────────────
# Lazy handshake: the first ping on a leg triggers HandshakeInit/Resp before
# the ICMP echo can flow. A short best-effort warm-up ping (result ignored)
# absorbs that one-time cost so the measured run below can assert 0% loss
# without a flaky first packet.
ping_leg() {
    local from_ns="$1" target="$2" leg_name="$3"
    echo "[warmup] $leg_name: triggering lazy handshake"
    ip netns exec "$from_ns" ping -6 -c 1 -W 5 "$target" >/dev/null 2>&1 || true

    echo "[test] $leg_name: pinging $target from $from_ns"
    local out status
    set +e
    out="$(ip netns exec "$from_ns" ping -6 -c 5 -W 5 "$target" 2>&1)"
    status=$?
    set -e
    echo "$out"
    if [ "$status" -ne 0 ] || ! echo "$out" | grep -q '0% packet loss'; then
        echo "[FAIL] $leg_name: ping did not achieve 0% loss (exit $status)"
        dump_logs
        exit 1
    fi
    echo "[PASS] $leg_name: 0% loss"
}

ping_leg "$NS_A" "$ADDR_B" "A->B"
ping_leg "$NS_A" "$ADDR_C" "A->C"
ping_leg "$NS_B" "$ADDR_C" "B->C"

echo "[PASS] full mesh triangle: all three legs reached 0% loss"
