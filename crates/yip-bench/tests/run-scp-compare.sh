#!/usr/bin/env bash
# run-scp-compare.sh — yip vs kernel WireGuard TCP throughput under tc netem loss.
#
# Sets up two independent tunnel pairs in separate netns (identical to
# run-compare.sh):
#   yip:  yipA ↔ yipB  over vethA/vethB (10.0.0.x underlay, 10.9.0.x tunnel)
#   wg:   wgA  ↔ wgB   over vethC/vethD (10.1.0.x underlay, 10.99.0.x tunnel)
#
# Sweeps loss rates 0 5 10%; applies tc netem symmetrically to BOTH veth pairs
# at each step; transfers a 20 MB file via scp across each tunnel; measures
# throughput (MB/s) and emits a comparison table.
#
# Thesis: yip's RaptorQ FEC hides packet loss from TCP so throughput holds,
# while WireGuard's TCP sees real retransmits and collapses under loss.
#
# Usage: run-scp-compare.sh [<path-to-yipd>]
set -euo pipefail

# ── availability checks ───────────────────────────────────────────────────────
if ! command -v scp >/dev/null 2>&1; then
    echo "[SKIP] scp not found — skipping scp throughput comparison"
    exit 0
fi
if [ ! -x /usr/sbin/sshd ]; then
    echo "[SKIP] /usr/sbin/sshd not found — skipping scp throughput comparison"
    exit 0
fi

# ── binary ────────────────────────────────────────────────────────────────────
if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    YIPD="$1"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
    # --release: yipd's RaptorQ path is ~75x slower unoptimized; a debug build
    # measured against in-kernel WireGuard is apples-to-oranges.
    echo "[build] running cargo build --release -p yipd --quiet in $WORKSPACE_ROOT"
    cargo build --release -p yipd --quiet --manifest-path "$WORKSPACE_ROOT/Cargo.toml"
    YIPD="$WORKSPACE_ROOT/target/release/yipd"
fi

# Also locate workspace root for output
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BENCH_DIR="$WORKSPACE_ROOT/crates/yip-bench"

# ── tmpdir ────────────────────────────────────────────────────────────────────
TMPDIR_TEST="$(mktemp -d /tmp/yip-scp-compare.XXXXXX)"

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
    # Kill sshd by pidfile (may already be gone — suppress errors)
    for _pidfile in "$TMPDIR_TEST/sshd-yip.pid" "$TMPDIR_TEST/sshd-wg.pid"; do
        [ -f "$_pidfile" ] || continue
        _pid="$(cat "$_pidfile" 2>/dev/null)" || continue
        [ -n "$_pid" ] || continue
        kill "$_pid" 2>/dev/null || true
    done
    sleep 0.2
    for _pidfile in "$TMPDIR_TEST/sshd-yip.pid" "$TMPDIR_TEST/sshd-wg.pid"; do
        [ -f "$_pidfile" ] || continue
        _pid="$(cat "$_pidfile" 2>/dev/null)" || continue
        [ -n "$_pid" ] || continue
        kill -9 "$_pid" 2>/dev/null || true
    done
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

# ── SSH key generation ────────────────────────────────────────────────────────
echo "[ssh] generating host and client keys"
ssh-keygen -t ed25519 -f "$TMPDIR_TEST/host" -N '' -q
ssh-keygen -t ed25519 -f "$TMPDIR_TEST/client" -N '' -q
cat "$TMPDIR_TEST/client.pub" > "$TMPDIR_TEST/authkeys"
chmod 600 "$TMPDIR_TEST/authkeys" "$TMPDIR_TEST/host"

# ── payload ───────────────────────────────────────────────────────────────────
echo "[payload] generating 20 MB test file"
dd if=/dev/zero of="$TMPDIR_TEST/payload" bs=1M count=20 status=none

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

# ── set the yip0 tunnel MTU ────────────────────────────────────────────────────
# The default 1500 TUN MTU is wrong for yip's data path.  Each inner packet is
# AEAD-sealed (+16-byte tag) and then FEC-encoded into fixed 1200-byte symbols
# (yip-transport symbol_size = 1200).  A full 1500-byte inner segment seals to
# 1516 bytes, which exceeds one symbol and is split into TWO source symbols (plus
# proactive repair) — i.e. every full-size TCP segment fans out into 2+ UDP
# datagrams through the single mutex-locked data path, collapsing throughput even
# at 0% loss.  Capping the inner MTU so the sealed packet fits one symbol
# (inner + 16 <= 1200  =>  inner <= 1184) keeps each TCP segment to one source
# symbol.  This is yip's analogue of WireGuard auto-setting wg0 to MTU 1420.
YIP_MTU=1184
echo "[yip] setting ${TUN_DEV} MTU to ${YIP_MTU} (fit sealed inner packet in one FEC symbol)"
ip netns exec "$NS_A" ip link set "$TUN_DEV" mtu "$YIP_MTU"
ip netns exec "$NS_B" ip link set "$TUN_DEV" mtu "$YIP_MTU"

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
    ip netns exec "$NS_WGA" ip link add wg0 type wireguard
    ip netns exec "$NS_WGB" ip link add wg0 type wireguard

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
# PART 3: scp throughput sweep
# ══════════════════════════════════════════════════════════════════════════════

LOSS_RATES="0 5 10"

# Helper: start sshd in a namespace on port 2222
# Usage: start_sshd <netns> <pidfile> <logfile>
start_sshd() {
    local ns="$1"
    local pidfile="$2"
    local logfile="$3"
    # Remove stale pidfile
    rm -f "$pidfile"
    ip netns exec "$ns" /usr/sbin/sshd -p 2222 -h "$TMPDIR_TEST/host" \
        -o "PidFile=$pidfile" \
        -o "AuthorizedKeysFile=$TMPDIR_TEST/authkeys" \
        -o "UsePAM=no" \
        -o "PasswordAuthentication=no" \
        -o "StrictModes=no" \
        -o "PermitRootLogin=yes" \
        -E "$logfile"
    # Brief wait for sshd to write its pidfile
    local wait=0
    while [ ! -f "$pidfile" ] && [ "$wait" -lt 50 ]; do
        sleep 0.1
        wait=$((wait + 1))
    done
}

# Helper: stop sshd by pidfile
# Usage: stop_sshd <pidfile>
stop_sshd() {
    local pidfile="$1"
    if [ -f "$pidfile" ]; then
        local pid
        pid="$(cat "$pidfile" 2>/dev/null)" || return 0
        [ -n "$pid" ] || return 0
        kill "$pid" 2>/dev/null || true
        sleep 0.3
        kill -9 "$pid" 2>/dev/null || true
        rm -f "$pidfile"
    fi
}

YIP_RESULTS=""
WG_RESULTS=""

echo ""
echo "=========================================================="
echo "  yip vs WireGuard — scp throughput under netem loss"
echo "  20 MB file via scp; netem: loss X% delay 5ms (symmetric)"
echo "  sshd on port 2222; scp timeout 120 s per transfer"
echo "=========================================================="

for LOSS in $LOSS_RATES; do
    echo ""
    echo "[netem] applying loss=${LOSS}% delay=5ms to all veth pairs"

    # Apply netem on yip veth pair
    ip netns exec "$NS_A" tc qdisc replace dev "$VETH_A" root netem \
        loss "${LOSS}%" delay 5ms
    ip netns exec "$NS_B" tc qdisc replace dev "$VETH_B" root netem \
        loss "${LOSS}%" delay 5ms

    # Apply netem on wg veth pair
    if [ "$WG_AVAILABLE" = true ]; then
        ip netns exec "$NS_WGA" tc qdisc replace dev "$VETH_C" root netem \
            loss "${LOSS}%" delay 5ms
        ip netns exec "$NS_WGB" tc qdisc replace dev "$VETH_D" root netem \
            loss "${LOSS}%" delay 5ms
    fi

    # ── yip scp measurement ───────────────────────────────────────────────────
    echo "[yip] starting sshd in $NS_A"
    start_sshd "$NS_A" "$TMPDIR_TEST/sshd-yip.pid" "$TMPDIR_TEST/sshd-yip.log"

    echo "[yip] transferring 20 MB via scp at loss=${LOSS}%"
    t_start=$(date +%s.%N)
    ip netns exec "$NS_B" timeout 120 scp -q -P 2222 \
        -i "$TMPDIR_TEST/client" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "$TMPDIR_TEST/payload" \
        "root@${TUN_A_IP}:/tmp/payload-yip.copy" || true
    t_end=$(date +%s.%N)

    yip_elapsed=$(awk "BEGIN {print $t_end - $t_start}")
    yip_mbps=$(awk "BEGIN { if ($yip_elapsed > 0) printf \"%.2f\", 20.0/$yip_elapsed; else print \"0.00\" }")
    echo "[yip] loss=${LOSS}%: elapsed=${yip_elapsed}s throughput=${yip_mbps} MB/s"

    # Integrity check at 0% loss
    if [ "$LOSS" -eq 0 ]; then
        echo "[yip] integrity check at 0% loss"
        if ip netns exec "$NS_A" cmp "$TMPDIR_TEST/payload" /tmp/payload-yip.copy 2>/dev/null; then
            echo "[yip] integrity OK: files match"
        else
            echo "[yip] WARNING: integrity check failed at 0% loss"
        fi
    fi

    stop_sshd "$TMPDIR_TEST/sshd-yip.pid"

    # ── WireGuard scp measurement ─────────────────────────────────────────────
    wg_mbps="N/A"
    if [ "$WG_AVAILABLE" = true ]; then
        echo "[wg] starting sshd in $NS_WGA"
        start_sshd "$NS_WGA" "$TMPDIR_TEST/sshd-wg.pid" "$TMPDIR_TEST/sshd-wg.log"

        echo "[wg] transferring 20 MB via scp at loss=${LOSS}%"
        t_start=$(date +%s.%N)
        ip netns exec "$NS_WGB" timeout 120 scp -q -P 2222 \
            -i "$TMPDIR_TEST/client" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            "$TMPDIR_TEST/payload" \
            "root@${WG_A_TUN_IP}:/tmp/payload-wg.copy" || true
        t_end=$(date +%s.%N)

        wg_elapsed=$(awk "BEGIN {print $t_end - $t_start}")
        wg_mbps=$(awk "BEGIN { if ($wg_elapsed > 0) printf \"%.2f\", 20.0/$wg_elapsed; else print \"0.00\" }")
        echo "[wg] loss=${LOSS}%: elapsed=${wg_elapsed}s throughput=${wg_mbps} MB/s"

        stop_sshd "$TMPDIR_TEST/sshd-wg.pid"
    fi

    YIP_RESULTS="${YIP_RESULTS}${LOSS} ${yip_mbps}"$'\n'
    WG_RESULTS="${WG_RESULTS}${LOSS} ${wg_mbps}"$'\n'
done

# ── emit final table ──────────────────────────────────────────────────────────
echo ""
echo "=========================================================="
echo "  Results"
echo "=========================================================="
echo ""
echo "| loss% | yip_MBps | wg_MBps |"
echo "|-------|----------|---------|"

# Parse results into table rows
while IFS= read -r yip_line; do
    [ -z "$yip_line" ] && continue
    loss_pct="${yip_line%% *}"
    y_mbps="${yip_line##* }"
    # Find matching WG result
    w_mbps="N/A"
    if [ "$WG_AVAILABLE" = true ]; then
        w_mbps=$(echo "$WG_RESULTS" | awk -v loss="$loss_pct" '$1 == loss { print $2 }')
    fi
    printf "| %-5s | %-8s | %-7s |\n" "$loss_pct" "$y_mbps" "$w_mbps"
done <<< "$YIP_RESULTS"

echo ""
echo "[done] scp throughput sweep complete"

if [ "$WG_AVAILABLE" = false ]; then
    echo "[note] WireGuard column skipped (module or baseline ping unavailable in this environment)"
fi
