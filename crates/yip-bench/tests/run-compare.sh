#!/usr/bin/env bash
# run-compare.sh — yip vs kernel WireGuard under tc netem loss.
#
# Sets up two independent tunnel pairs in separate netns:
#   yip:  yipA ↔ yipB  over vethA/vethB (10.0.0.x underlay, 10.9.0.x tunnel)
#   wg:   wgA  ↔ wgB   over vethC/vethD (10.1.0.x underlay, 10.99.0.x tunnel)
#
# Sweeps loss rates 0 1 3 5 10%; applies tc netem symmetrically to BOTH veth
# pairs at each step; measures effective loss + RTT via ping -c 100 across each
# tunnel; emits a combined table and saves to crates/yip-bench/RESULTS.md.
#
# Usage: run-compare.sh [<path-to-yipd>]
set -euo pipefail

# ── binary ────────────────────────────────────────────────────────────────────
if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    YIPD="$1"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
    echo "[build] running cargo build -p yipd --quiet in $WORKSPACE_ROOT"
    cargo build -p yipd --quiet --manifest-path "$WORKSPACE_ROOT/Cargo.toml"
    YIPD="$WORKSPACE_ROOT/target/debug/yipd"
fi

# Also locate workspace root for RESULTS.md output
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BENCH_DIR="$WORKSPACE_ROOT/crates/yip-bench"

# ── tmpdir ────────────────────────────────────────────────────────────────────
TMPDIR_TEST="$(mktemp -d /tmp/yip-compare.XXXXXX)"

# ── yip netns/veth ───────────────────────────────────────────────────────────
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

# ── WireGuard netns/veth ──────────────────────────────────────────────────────
NS_WGA="wgA"
NS_WGB="wgB"
VETH_C="vethC"
VETH_D="vethD"
VETH_C_IP="10.1.0.1"
VETH_D_IP="10.1.0.2"
WG_A_TUN_IP="10.99.0.1"
WG_B_TUN_IP="10.99.0.2"
WG_PREFIX="24"
WG_VETH_PREFIX="24"
WG_PORT_A="51830"
WG_PORT_B="51831"

WG_AVAILABLE=true

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    # Remove WG interfaces inside namespaces before deleting namespaces
    ip netns exec "$NS_WGA" ip link del wg0 2>/dev/null || true
    ip netns exec "$NS_WGB" ip link del wg0 2>/dev/null || true
    ip netns del "$NS_A"   2>/dev/null || true
    ip netns del "$NS_B"   2>/dev/null || true
    ip netns del "$NS_WGA" 2>/dev/null || true
    ip netns del "$NS_WGB" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════════════════
# PART 1: yip tunnel setup
# ══════════════════════════════════════════════════════════════════════════════

echo "[yip] generating keypairs"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"

PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A"  | grep '^public='  | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B"  | grep '^public='  | cut -d= -f2)"

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

echo "[yip] creating namespaces and veth pair"
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

echo "[yip] starting daemons"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

echo "[yip] waiting for TUN devices (up to 20s)"
TUN_WAIT=20
INTERVAL=0.25
elapsed=0
while true; do
    A_UP=0
    B_UP=0
    ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true

    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ]; then
        echo "[yip] both TUN devices are up"
        break
    fi

    if ! kill -0 "$PID_A" 2>/dev/null; then
        echo "[error] yipA daemon died unexpectedly"
        cat "$LOG_A" || true
        exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipB daemon died unexpectedly"
        cat "$LOG_B" || true
        exit 1
    fi

    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for yip TUN devices"
        cat "$LOG_A" || true
        cat "$LOG_B" || true
        exit 1
    fi
    sleep "$INTERVAL"
done

echo "[yip] assigning tunnel IPs"
ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/${TUN_PREFIX}" dev "$TUN_DEV"

ip netns exec "$NS_A" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_A" ip link set "$TUN_DEV" up
ip netns exec "$NS_B" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_B" ip link set "$TUN_DEV" up

sleep 0.5

echo "[yip] baseline connectivity check"
ip netns exec "$NS_B" ping -c 3 -W 5 "$TUN_A_IP" || {
    echo "[error] yip baseline ping failed"
    cat "$LOG_A" || true
    cat "$LOG_B" || true
    exit 1
}

# ══════════════════════════════════════════════════════════════════════════════
# PART 2: kernel WireGuard tunnel setup
# ══════════════════════════════════════════════════════════════════════════════

setup_wg() {
    # Check prerequisites
    if ! command -v wg >/dev/null 2>&1; then
        echo "[wg] SKIP: 'wg' command not found"
        WG_AVAILABLE=false
        return
    fi

    # Ensure kernel module is loaded
    if ! modprobe wireguard 2>/dev/null; then
        echo "[wg] SKIP: modprobe wireguard failed"
        WG_AVAILABLE=false
        return
    fi

    echo "[wg] generating keypairs"
    WG_PRIV_A="$(wg genkey)"
    WG_PUB_A="$(echo "$WG_PRIV_A" | wg pubkey)"
    WG_PRIV_B="$(wg genkey)"
    WG_PUB_B="$(echo "$WG_PRIV_B" | wg pubkey)"

    echo "[wg] creating namespaces and veth pair"
    ip netns add "$NS_WGA"
    ip netns add "$NS_WGB"

    ip link add "$VETH_C" type veth peer name "$VETH_D"
    ip link set "$VETH_C" netns "$NS_WGA"
    ip link set "$VETH_D" netns "$NS_WGB"

    ip netns exec "$NS_WGA" ip addr add "${VETH_C_IP}/${WG_VETH_PREFIX}" dev "$VETH_C"
    ip netns exec "$NS_WGA" ip link set "$VETH_C" up
    ip netns exec "$NS_WGA" ip link set lo up

    ip netns exec "$NS_WGB" ip addr add "${VETH_D_IP}/${WG_VETH_PREFIX}" dev "$VETH_D"
    ip netns exec "$NS_WGB" ip link set "$VETH_D" up
    ip netns exec "$NS_WGB" ip link set lo up

    echo "[wg] creating WireGuard interfaces inside namespaces"
    # Create wg0 in wgA namespace
    ip netns exec "$NS_WGA" ip link add wg0 type wireguard
    ip netns exec "$NS_WGB" ip link add wg0 type wireguard

    # Write private keys to tmpfiles (wg set reads from file path)
    WG_PRIV_A_FILE="$TMPDIR_TEST/wg_priv_a"
    WG_PRIV_B_FILE="$TMPDIR_TEST/wg_priv_b"
    printf '%s' "$WG_PRIV_A" > "$WG_PRIV_A_FILE"
    printf '%s' "$WG_PRIV_B" > "$WG_PRIV_B_FILE"
    chmod 600 "$WG_PRIV_A_FILE" "$WG_PRIV_B_FILE"

    echo "[wg] configuring wgA (listen-port ${WG_PORT_A}, peer = wgB)"
    ip netns exec "$NS_WGA" wg set wg0 \
        private-key "$WG_PRIV_A_FILE" \
        listen-port "$WG_PORT_A" \
        peer "$WG_PUB_B" \
            allowed-ips "10.99.0.0/24" \
            endpoint "${VETH_D_IP}:${WG_PORT_B}"

    echo "[wg] configuring wgB (listen-port ${WG_PORT_B}, peer = wgA)"
    ip netns exec "$NS_WGB" wg set wg0 \
        private-key "$WG_PRIV_B_FILE" \
        listen-port "$WG_PORT_B" \
        peer "$WG_PUB_A" \
            allowed-ips "10.99.0.0/24" \
            endpoint "${VETH_C_IP}:${WG_PORT_A}"

    echo "[wg] assigning tunnel IPs and bringing up wg0"
    ip netns exec "$NS_WGA" ip addr add "${WG_A_TUN_IP}/${WG_PREFIX}" dev wg0
    ip netns exec "$NS_WGA" ip link set wg0 up

    ip netns exec "$NS_WGB" ip addr add "${WG_B_TUN_IP}/${WG_PREFIX}" dev wg0
    ip netns exec "$NS_WGB" ip link set wg0 up

    sleep 0.5

    echo "[wg] baseline connectivity check"
    if ! ip netns exec "$NS_WGB" ping -c 3 -W 5 "$WG_A_TUN_IP"; then
        echo "[wg] SKIP: baseline WG ping failed — WG column will be omitted"
        WG_AVAILABLE=false
        return
    fi

    echo "[wg] WireGuard tunnel is up and reachable"
}

setup_wg

# ══════════════════════════════════════════════════════════════════════════════
# PART 3: sweep and emit combined table
# ══════════════════════════════════════════════════════════════════════════════

LOSS_RATES="0 1 3 5 10"

HEADER="yip vs kernel WireGuard — netem loss sweep"
SUBHEADER="ping -c 100 -i 0.05 -W 1 across each tunnel; netem: loss X% delay 5ms (symmetric)"

if [ "$WG_AVAILABLE" = true ]; then
    COL_HDR="| injected% | yip_loss% | wg_loss%  | yip_rtt_ms | wg_rtt_ms |"
    COL_SEP="|-----------|-----------|-----------|------------|-----------|"
else
    COL_HDR="| injected% | yip_loss% | yip_rtt_ms | yip_rtt_max_ms |"
    COL_SEP="|-----------|-----------|------------|----------------|"
fi

TABLE=""
TABLE+="## $HEADER"$'\n'
TABLE+="$SUBHEADER"$'\n'
TABLE+=""$'\n'
TABLE+="$COL_HDR"$'\n'
TABLE+="$COL_SEP"$'\n'

echo ""
echo "=========================================================="
echo "  $HEADER"
echo "  $SUBHEADER"
echo "=========================================================="
echo "$COL_HDR"
echo "$COL_SEP"

for LOSS in $LOSS_RATES; do
    # Apply netem on yip veth pair
    ip netns exec "$NS_A" tc qdisc replace dev "$VETH_A" root netem \
        loss "${LOSS}%" delay 5ms
    ip netns exec "$NS_B" tc qdisc replace dev "$VETH_B" root netem \
        loss "${LOSS}%" delay 5ms

    # Apply netem on wg veth pair (same impairment)
    if [ "$WG_AVAILABLE" = true ]; then
        ip netns exec "$NS_WGA" tc qdisc replace dev "$VETH_C" root netem \
            loss "${LOSS}%" delay 5ms
        ip netns exec "$NS_WGB" tc qdisc replace dev "$VETH_D" root netem \
            loss "${LOSS}%" delay 5ms
    fi

    # ── ping yip tunnel ───────────────────────────────────────────────────────
    YIP_PING="$(ip netns exec "$NS_B" ping -c 100 -i 0.05 -W 1 "$TUN_A_IP" 2>&1)" || true

    YIP_LOSS="$(echo "$YIP_PING" \
        | grep -oP '\d+% packet loss' | grep -oP '^\d+' || echo "100")"
    YIP_RTT_LINE="$(echo "$YIP_PING" | grep -oP 'rtt min/avg/max/mdev = [0-9./]+ ms' || echo "")"
    if [ -n "$YIP_RTT_LINE" ]; then
        YIP_RTT_AVG="$(echo "$YIP_RTT_LINE" | cut -d= -f2 | tr '/' ' ' | awk '{print $2}')"
    else
        YIP_RTT_AVG="N/A"
    fi

    # ── ping WireGuard tunnel ─────────────────────────────────────────────────
    if [ "$WG_AVAILABLE" = true ]; then
        WG_PING="$(ip netns exec "$NS_WGB" ping -c 100 -i 0.05 -W 1 "$WG_A_TUN_IP" 2>&1)" || true

        WG_LOSS="$(echo "$WG_PING" \
            | grep -oP '\d+% packet loss' | grep -oP '^\d+' || echo "100")"
        WG_RTT_LINE="$(echo "$WG_PING" | grep -oP 'rtt min/avg/max/mdev = [0-9./]+ ms' || echo "")"
        if [ -n "$WG_RTT_LINE" ]; then
            WG_RTT_AVG="$(echo "$WG_RTT_LINE" | cut -d= -f2 | tr '/' ' ' | awk '{print $2}')"
        else
            WG_RTT_AVG="N/A"
        fi

        ROW="| ${LOSS}%        | ${YIP_LOSS}%         | ${WG_LOSS}%         | ${YIP_RTT_AVG}      | ${WG_RTT_AVG}     |"
        echo "$ROW"
        TABLE+="$ROW"$'\n'
    else
        # yip-only row
        YIP_RTT_MAX="N/A"
        if [ -n "$YIP_RTT_LINE" ]; then
            YIP_RTT_MAX="$(echo "$YIP_RTT_LINE" | cut -d= -f2 | tr '/' ' ' | awk '{print $3}')"
        fi
        ROW="| ${LOSS}%        | ${YIP_LOSS}%         | ${YIP_RTT_AVG}      | ${YIP_RTT_MAX}      |"
        echo "$ROW"
        TABLE+="$ROW"$'\n'
    fi
done

echo "=========================================================="
echo ""
echo "[done] sweep complete"

if [ "$WG_AVAILABLE" = false ]; then
    NOTE="WireGuard column skipped (module or baseline ping unavailable in this environment)"
    echo "[note] $NOTE"
    TABLE+=""$'\n'
    TABLE+="Note: $NOTE"$'\n'
fi

# ── Save to RESULTS.md ────────────────────────────────────────────────────────
RESULTS_FILE="$BENCH_DIR/RESULTS.md"
{
    echo "# yip-bench Results"
    echo ""
    echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    echo "$TABLE"
} > "$RESULTS_FILE"
echo "[done] results saved to $RESULTS_FILE"
