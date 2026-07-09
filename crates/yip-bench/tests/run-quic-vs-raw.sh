#!/usr/bin/env bash
# QUIC-vs-raw benchmark (3c.1 Task 7, Deliverable 3): measures tunnel RTT and
# TCP throughput for `transport=quic` against yip's default raw-UDP path, on
# the same netns/veth harness used by run-driver-ab-rtt.sh (RTT) and
# run-iperf-compare.sh (throughput).
#
# This is NOT a comparison against obf_psk (3a/3b's cover-traffic/junk
# premium) — that's a separate, orthogonal cost. This measures specifically
# the QUIC-mimicry double-encryption premium (real QUIC/TLS1.3 handshake +
# DATAGRAM-frame pump wrapping the inner yip Noise-IK session) against yip's
# plain raw-UDP fast path, which is the comparison 3c.1's spike (Task 1)
# estimated at ~1.68x CPU/packet.
#
# Honest framing: `transport=quic` is an OPT-IN premium for DPI resistance
# (Task 7's nDPI oracle proves the payoff); raw UDP remains yip's low-latency
# default. This benchmark quantifies what that premium costs in RTT and
# throughput, not just CPU.
#
# Usage: run-quic-vs-raw.sh [<path-to-release-yipd>]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BENCH_DIR="$WORKSPACE_ROOT/crates/yip-bench"

if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    YIPD="$1"
else
    echo "[build] running cargo build --release -p yipd --quiet in $WORKSPACE_ROOT"
    cargo build --release -p yipd --quiet --manifest-path "$WORKSPACE_ROOT/Cargo.toml"
    YIPD="$WORKSPACE_ROOT/target/release/yipd"
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-quic-vs-raw: needs root (netns + TUN)"
    exit 0
fi

HAVE_IPERF3=1
if ! command -v iperf3 >/dev/null 2>&1; then
    echo "[note] iperf3 not found — throughput column will be N/A (RTT still measured)"
    HAVE_IPERF3=0
fi

NS_A="yipQvrA"
NS_B="yipQvrB"
VETH_A="vQvrA"
VETH_B="vQvrB"
VETH_A_IP="10.20.0.1"
VETH_B_IP="10.20.0.2"
TUN_A_IP="10.21.0.1"
TUN_B_IP="10.21.0.2"
TUN_PREFIX="24"
VETH_PREFIX="24"
PORT_A="51920"
PORT_B="51921"
TUN_DEV="yip0"

PID_A=""
PID_B=""
TMPDIR_TEST=""

cleanup() {
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    [ -n "$TMPDIR_TEST" ] && rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# measure_mode <mode: raw|quic> -> prints "RTT_MS TCP_MBPS" on stdout (last line)
measure_mode() {
    local mode="$1"

    cleanup
    trap cleanup EXIT

    TMPDIR_TEST="$(mktemp -d /tmp/yip-quic-vs-raw.XXXXXX)"
    PID_A=""
    PID_B=""

    GENKEY_A="$("$YIPD" --genkey)"
    GENKEY_B="$("$YIPD" --genkey)"
    PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
    PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
    PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
    PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

    local transport_line=""
    if [ "$mode" = "quic" ]; then
        transport_line="transport=quic"
    fi

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
${transport_line}
EOF
    cat > "$CFG_B" <<EOF
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT_B}
peer_endpoint=${VETH_A_IP}:${PORT_A}
device=${TUN_DEV}
initiate=true
${transport_line}
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
    ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
    PID_A=$!
    ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
    PID_B=$!

    # transport=quic needs a two-layer bring-up (outer QUIC handshake, then the
    # inner yip Noise-IK handshake over DATAGRAM frames) — give it the same
    # generous budget run-netns-quic.sh uses, not the raw path's tighter one.
    local tun_wait=40
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
        if awk "BEGIN {exit ($elapsed >= $tun_wait) ? 0 : 1}"; then
            echo "[error] TUN timeout mode=$mode" >&2
            exit 1
        fi
        sleep 0.25
    done

    ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
    ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
    sleep 1

    # Baseline connectivity + handshake warm-up before the timed measurement
    # (mirrors run-netns-quic.sh's generous ping budget for the two-layer
    # QUIC bring-up; harmless extra warm-up for the raw path).
    if ! ip netns exec "$NS_B" ping -c 10 -W 2 "$TUN_A_IP" >/dev/null 2>&1; then
        echo "[error] baseline ping failed in mode=$mode" >&2
        cat "$LOG_A" "$LOG_B" >&2 || true
        exit 1
    fi

    # ── RTT: ping -c 100 -i 0.02 (matches run-driver-ab-rtt.sh) ──────────────
    local ping_out rtt_avg
    ping_out="$(ip netns exec "$NS_B" ping -c 100 -i 0.02 -W 1 "$TUN_A_IP" 2>&1)" || true
    rtt_avg="$(echo "$ping_out" | grep -oP 'rtt min/avg/max/mdev = [0-9./]+ ms' \
        | cut -d= -f2 | tr '/' ' ' | awk '{print $2}' || echo "N/A")"
    [ -z "$rtt_avg" ] && rtt_avg="N/A"

    # ── throughput: iperf3 TCP -t 8 (matches run-iperf-compare.sh) ───────────
    local mbps="N/A"
    if [ "$HAVE_IPERF3" -eq 1 ]; then
        ip netns exec "$NS_A" iperf3 -s -1 -B "$TUN_A_IP" >/dev/null 2>&1 &
        sleep 0.5
        mbps="$(ip netns exec "$NS_B" iperf3 -c "$TUN_A_IP" -t 8 2>/dev/null \
            | grep -i receiver | grep -oP '[0-9.]+ (Mbits|Gbits)/sec' | tail -1 || echo "")"
        if echo "$mbps" | grep -qi 'Gbits'; then
            mbps="$(echo "$mbps" | grep -oP '[0-9.]+' | awk '{printf "%.1f", $1*1000}')"
        else
            mbps="$(echo "$mbps" | grep -oP '[0-9.]+' | head -1)"
        fi
        [ -z "$mbps" ] && mbps="N/A"
    fi

    echo "[result] mode=${mode} rtt_avg_ms=${rtt_avg} tcp_mbps=${mbps}" >&2
    echo "${rtt_avg} ${mbps}"
}

echo "=========================================================="
echo "  QUIC-vs-raw benchmark (3c.1 Task 7)"
echo "  RTT: ping -c 100 -i 0.02 -W 1; throughput: iperf3 -t 8"
echo "=========================================================="

read -r RAW_RTT RAW_MBPS <<< "$(measure_mode raw)"
read -r QUIC_RTT QUIC_MBPS <<< "$(measure_mode quic)"

echo ""
echo "| transport | rtt_avg_ms | tcp_Mbit/s |"
echo "|-----------|------------|------------|"
printf "| %-9s | %-10s | %-10s |\n" "raw"  "$RAW_RTT"  "$RAW_MBPS"
printf "| %-9s | %-10s | %-10s |\n" "quic" "$QUIC_RTT" "$QUIC_MBPS"

# ── append (not overwrite — run-compare.sh owns the top-level netem sweep
# table in RESULTS.md) a QUIC-vs-raw section ──────────────────────────────
RESULTS_FILE="$BENCH_DIR/RESULTS.md"
{
    echo ""
    echo "## QUIC-vs-raw benchmark (3c.1 Task 7)"
    echo ""
    echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    echo "\`transport=quic\` (real QUIC/TLS1.3 handshake + DATAGRAM-frame pump,"
    echo "wrapping the inner yip Noise-IK session — see bin/yipd/src/quic.rs) vs"
    echo "yip's default raw-UDP path. Same netns/veth harness as the driver A/B"
    echo "RTT test and the iperf3 throughput matrix; \`ping -c 100 -i 0.02\` for"
    echo "RTT, \`iperf3 -t 8\` for TCP throughput. This is NOT the obf_psk"
    echo "cover-traffic premium (3a/3b, a separate cost) — this isolates the QUIC"
    echo "mimicry premium alone."
    echo ""
    echo "| transport | rtt_avg_ms | tcp_Mbit/s |"
    echo "|-----------|------------|------------|"
    printf "| %-9s | %-10s | %-10s |\n" "raw"  "$RAW_RTT"  "$RAW_MBPS"
    printf "| %-9s | %-10s | %-10s |\n" "quic" "$QUIC_RTT" "$QUIC_MBPS"
    echo ""
    echo "Honest framing: \`transport=quic\` is an **opt-in premium** for DPI"
    echo "resistance (see \`bin/yipd/tests/run-quic-mimicry-oracle.sh\` / the"
    echo "\`quic_classified_as_quic\` test for the payoff — a real nDPI"
    echo "classification flip to QUIC with no Susp Entropy risk). Raw UDP remains"
    echo "yip's low-latency default; the double-encryption/two-layer-handshake"
    echo "cost above is what QUIC mimicry spends to buy that payoff (the 3c.1"
    echo "Task 1 spike estimated ~1.68x CPU/packet for the QUIC path; the table"
    echo "above is the measured RTT/throughput consequence of that cost)."
} >> "$RESULTS_FILE"
echo ""
echo "[done] QUIC-vs-raw results appended to $RESULTS_FILE"
