#!/usr/bin/env bash
# run-fec-compare.sh — the FEC-vs-FEC headline.
#
# Under a tc netem loss sweep (0 5 10 %, symmetric delay 5ms), measure UDP
# delivered-loss with a pure-UDP sequenced blaster across three transports:
#
#   bare       — straight veth, no FEC (the loss floor)
#   udpspeeder — UDPspeeder RS-FEC forwarder (f20:10)        [SKIP if absent]
#   yip        — yip RaptorQ-FEC tunnel (release yipd)
#
# The blaster (udp_tx.py / udp_rx.py) sends N seq-numbered datagrams at PPS
# packets/sec; the receiver counts UNIQUE sequence numbers => delivered fraction.
# It is pure UDP (no TCP control channel), so it traverses UDPspeeder — which
# iperf3 cannot do.
#
# Thesis: bare drops ~loss%; UDPspeeder and yip both recover via FEC and deliver
# ~100% where bare drops packets.
#
# Emits:  | loss% | bare_recv% | udpspeeder_recv% | yip_recv% |
#
# Usage: run-fec-compare.sh [<path-to-yipd>]
set -euo pipefail

# ── binary ────────────────────────────────────────────────────────────────────
if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    YIPD="$1"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
    # --release: yipd's RaptorQ path is ~75x slower unoptimized.
    echo "[build] running cargo build --release -p yipd --quiet in $WORKSPACE_ROOT"
    cargo build --release -p yipd --quiet --manifest-path "$WORKSPACE_ROOT/Cargo.toml"
    YIPD="$WORKSPACE_ROOT/target/release/yipd"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$SCRIPT_DIR"

# ── UDPspeeder binary: env override, then .bench-tools, then PATH ──────────────
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SPEEDER_AVAILABLE=true
if [ -n "${SPEEDERV2:-}" ] && [ -x "${SPEEDERV2}" ]; then
    SPEEDER="$SPEEDERV2"
elif [ -x "$WORKSPACE_ROOT/.bench-tools/speederv2" ]; then
    SPEEDER="$WORKSPACE_ROOT/.bench-tools/speederv2"
elif command -v speederv2 >/dev/null 2>&1; then
    SPEEDER="$(command -v speederv2)"
else
    SPEEDER=""
    SPEEDER_AVAILABLE=false
    echo "[udpspeeder] SKIP: speederv2 binary not found (SPEEDERV2 / .bench-tools/speederv2 / PATH)"
fi

# ── blaster parameters ────────────────────────────────────────────────────────
N="${N:-20000}"
PPS="${PPS:-4000}"

# ── tmpdir ────────────────────────────────────────────────────────────────────
TMPDIR_TEST="$(mktemp -d /tmp/yip-fec-compare.XXXXXX)"

# ── bare-link netns/veth (unique names: 'fec' prefix) ─────────────────────────
NS_BR="fecBR"
NS_BS="fecBS"
VBR="fecvBR"
VBS="fecvBS"
IP_BR="10.40.0.1"
IP_BS="10.40.0.2"

# ── UDPspeeder netns/veth ─────────────────────────────────────────────────────
NS_SR="fecSR"
NS_SS="fecSS"
VSR="fecvSR"
VSS="fecvSS"
IP_SR="10.41.0.1"
IP_SS="10.41.0.2"

# ── yip netns/veth (own names, not the shared 'yipA/B' so no collision) ───────
NS_YA="fecYA"
NS_YB="fecYB"
VYA="fecvYA"
VYB="fecvYB"
VYA_IP="10.42.0.1"
VYB_IP="10.42.0.2"
TUN_YA_IP="10.43.0.1"
TUN_YB_IP="10.43.0.2"
YPORT_A="51840"
YPORT_B="51841"
TUN_DEV="yip0"
PID_YA=""
PID_YB=""

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_YA" ] && kill "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill "$PID_YB" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_YA" ] && kill -9 "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill -9 "$PID_YB" 2>/dev/null || true
    for ns in "$NS_BR" "$NS_BS" "$NS_SR" "$NS_SS" "$NS_YA" "$NS_YB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── helper: make a two-netns veth pair with addresses ─────────────────────────
# make_pair <nsR> <nsS> <vethR> <vethS> <ipR> <ipS>
make_pair() {
    local nsR="$1" nsS="$2" vR="$3" vS="$4" ipR="$5" ipS="$6"
    ip netns add "$nsR"
    ip netns add "$nsS"
    ip link add "$vR" type veth peer name "$vS"
    ip link set "$vR" netns "$nsR"
    ip link set "$vS" netns "$nsS"
    ip netns exec "$nsR" ip addr add "$ipR/24" dev "$vR"
    ip netns exec "$nsR" ip link set "$vR" up
    ip netns exec "$nsR" ip link set lo up
    ip netns exec "$nsS" ip addr add "$ipS/24" dev "$vS"
    ip netns exec "$nsS" ip link set "$vS" up
    ip netns exec "$nsS" ip link set lo up
}

# ── helper: apply netem to both ends of a pair ────────────────────────────────
apply_netem() {
    local nsR="$1" nsS="$2" vR="$3" vS="$4" loss="$5"
    ip netns exec "$nsR" tc qdisc replace dev "$vR" root netem loss "${loss}%" delay 5ms
    ip netns exec "$nsS" tc qdisc replace dev "$vS" root netem loss "${loss}%" delay 5ms
}

# ── helper: extract received count from "received=K of N" ─────────────────────
recv_pct() {
    # args: <received_line> <N>
    local line="$1" n="$2" k
    k="$(echo "$line" | grep -oP 'received=\K[0-9]+' || echo 0)"
    awk "BEGIN { if ($n > 0) printf \"%.1f\", 100.0*$k/$n; else print \"0.0\" }"
}

# ══════════════════════════════════════════════════════════════════════════════
# Set up the bare-link and UDPspeeder pairs (cheap, always up)
# ══════════════════════════════════════════════════════════════════════════════
echo "[bare] creating veth pair"
make_pair "$NS_BR" "$NS_BS" "$VBR" "$VBS" "$IP_BR" "$IP_BS"

if [ "$SPEEDER_AVAILABLE" = true ]; then
    echo "[udpspeeder] creating veth pair"
    make_pair "$NS_SR" "$NS_SS" "$VSR" "$VSS" "$IP_SR" "$IP_SS"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Set up the yip tunnel (own netns pair)
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
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VYA_IP}:${YPORT_A}
peer_endpoint=${VYB_IP}:${YPORT_B}
device=${TUN_DEV}
initiate=false
EOF
cat > "$CFG_B" <<EOF
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VYB_IP}:${YPORT_B}
peer_endpoint=${VYA_IP}:${YPORT_A}
device=${TUN_DEV}
initiate=true
EOF

echo "[yip] creating namespaces and veth pair"
make_pair "$NS_YA" "$NS_YB" "$VYA" "$VYB" "$VYA_IP" "$VYB_IP"

LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"
echo "[yip] starting daemons"
ip netns exec "$NS_YA" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_YA=$!
ip netns exec "$NS_YB" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_YB=$!

echo "[yip] waiting for TUN devices (up to 20s)"
TUN_WAIT=20
INTERVAL=0.25
elapsed=0
while true; do
    A_UP=0; B_UP=0
    ip netns exec "$NS_YA" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_YB" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true
    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ]; then
        echo "[yip] both TUN devices are up"; break
    fi
    if ! kill -0 "$PID_YA" 2>/dev/null; then echo "[error] yipA died"; cat "$LOG_A" || true; exit 1; fi
    if ! kill -0 "$PID_YB" 2>/dev/null; then echo "[error] yipB died"; cat "$LOG_B" || true; exit 1; fi
    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for yip TUN"; cat "$LOG_A" "$LOG_B" || true; exit 1
    fi
    sleep "$INTERVAL"
done

echo "[yip] assigning tunnel IPs"
ip netns exec "$NS_YA" ip addr add "${TUN_YA_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_YB" ip addr add "${TUN_YB_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_YA" ip link set "$TUN_DEV" up
ip netns exec "$NS_YB" ip link set "$TUN_DEV" up
sleep 0.5

echo "[yip] baseline connectivity check"
ip netns exec "$NS_YB" ping -c 3 -W 5 "$TUN_YA_IP" >/dev/null || {
    echo "[error] yip baseline ping failed"; cat "$LOG_A" "$LOG_B" || true; exit 1
}

# ══════════════════════════════════════════════════════════════════════════════
# Sweep
# ══════════════════════════════════════════════════════════════════════════════
LOSS_RATES="0 5 10"

echo ""
echo "=========================================================="
echo "  FEC-vs-FEC — UDP delivered-loss under netem"
echo "  blaster: N=${N} pps=${PPS}; netem: loss X% delay 5ms (symmetric)"
echo "=========================================================="

ROWS=""
for LOSS in $LOSS_RATES; do
    echo ""
    echo "[netem] loss=${LOSS}% delay=5ms on all pairs"
    apply_netem "$NS_BR" "$NS_BS" "$VBR" "$VBS" "$LOSS"
    [ "$SPEEDER_AVAILABLE" = true ] && apply_netem "$NS_SR" "$NS_SS" "$VSR" "$VSS" "$LOSS"
    apply_netem "$NS_YA" "$NS_YB" "$VYA" "$VYB" "$LOSS"

    # ── bare-link blast ──────────────────────────────────────────────────────
    echo "[bare] blasting N=${N} over lossy veth"
    ip netns exec "$NS_BR" python3 "$PY/udp_rx.py" "$IP_BR" 7777 "$N" 3 >"$TMPDIR_TEST/bare.out" 2>&1 &
    RX=$!; sleep 0.4
    ip netns exec "$NS_BS" python3 "$PY/udp_tx.py" "$IP_BR" 7777 "$N" "$PPS" >/dev/null 2>&1
    wait "$RX"
    BARE_LINE="$(cat "$TMPDIR_TEST/bare.out")"
    BARE_PCT="$(recv_pct "$BARE_LINE" "$N")"
    echo "[bare] $BARE_LINE -> ${BARE_PCT}%"

    # ── UDPspeeder blast (RS-FEC f20:10) ─────────────────────────────────────
    SP_PCT="N/A"
    if [ "$SPEEDER_AVAILABLE" = true ]; then
        echo "[udpspeeder] blasting N=${N} through f20:10 forwarder"
        ip netns exec "$NS_SR" python3 "$PY/udp_rx.py" 127.0.0.1 7777 "$N" 4 >"$TMPDIR_TEST/sp.out" 2>&1 &
        RX=$!; sleep 0.3
        ip netns exec "$NS_SR" "$SPEEDER" -s -l"$IP_SR":4096 -r 127.0.0.1:7777 -f20:10 -k benchpw --mode 0 \
            >"$TMPDIR_TEST/sp-srv.log" 2>&1 &
        ip netns exec "$NS_SS" "$SPEEDER" -c -l127.0.0.1:3333 -r"$IP_SR":4096 -f20:10 -k benchpw --mode 0 \
            >"$TMPDIR_TEST/sp-cli.log" 2>&1 &
        sleep 1.2
        ip netns exec "$NS_SS" python3 "$PY/udp_tx.py" 127.0.0.1 3333 "$N" "$PPS" >/dev/null 2>&1
        wait "$RX"
        # Stop the speeder daemons before the next sweep iteration.
        ip netns exec "$NS_SR" pkill -f speederv2 2>/dev/null || true
        ip netns exec "$NS_SS" pkill -f speederv2 2>/dev/null || true
        SP_LINE="$(cat "$TMPDIR_TEST/sp.out")"
        SP_PCT="$(recv_pct "$SP_LINE" "$N")"
        echo "[udpspeeder] $SP_LINE -> ${SP_PCT}%"
    fi

    # ── yip blast (RaptorQ-FEC; send from B-netns to A tunnel IP) ─────────────
    echo "[yip] blasting N=${N} across yip tunnel"
    ip netns exec "$NS_YA" python3 "$PY/udp_rx.py" "$TUN_YA_IP" 7777 "$N" 5 >"$TMPDIR_TEST/yip.out" 2>&1 &
    RX=$!; sleep 0.4
    ip netns exec "$NS_YB" python3 "$PY/udp_tx.py" "$TUN_YA_IP" 7777 "$N" "$PPS" >/dev/null 2>&1
    wait "$RX"
    YIP_LINE="$(cat "$TMPDIR_TEST/yip.out")"
    YIP_PCT="$(recv_pct "$YIP_LINE" "$N")"
    echo "[yip] $YIP_LINE -> ${YIP_PCT}%"

    ROWS="${ROWS}${LOSS}|${BARE_PCT}|${SP_PCT}|${YIP_PCT}"$'\n'
done

# ── emit table ────────────────────────────────────────────────────────────────
echo ""
echo "=========================================================="
echo "  Results — UDP delivered (% of ${N} packets)"
echo "=========================================================="
echo ""
echo "| loss% | bare_recv% | udpspeeder_recv% | yip_recv% |"
echo "|-------|------------|------------------|-----------|"
while IFS='|' read -r loss bare sp yip; do
    [ -z "$loss" ] && continue
    printf "| %-5s | %-10s | %-16s | %-9s |\n" "$loss" "$bare" "$sp" "$yip"
done <<< "$ROWS"
echo ""

if [ "$SPEEDER_AVAILABLE" = false ]; then
    echo "[note] UDPspeeder column skipped (speederv2 binary absent)"
fi
echo "[done] FEC compare sweep complete"
