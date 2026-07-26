#!/usr/bin/env bash
# CPU-bound-regime spike for the #4 throughput campaign.
#
# Question: can the yip RECEIVER ever become CPU-bound (its packet-processing
# core pegged at ~100%), or is throughput always RTT/window-bound? If the
# receiver core never saturates even under a UDP blast at ~0 RTT, then CPU
# optimizations (codec/MAC swaps) can NEVER move end-to-end throughput and the
# rest of #4 should yield to feature work.
#
# Method: two netns joined by a veth, a yip tunnel between them. The RECEIVING
# yipd (yipd_A) is taskset-pinned to a SINGLE core to model the 1-core EPYC
# target; everything else (sender yipd_B, iperf) gets other cores so they are
# never the bottleneck. We push data B->A with iperf3 (UDP blast, then TCP -P N)
# while sweeping netem RTT, and at each point record tunnel throughput plus the
# pinned RX core's utilization (cores busy: 1.0 == one core saturated).
#
# Caveat: veth has no real NIC, so absolute Gbps is optimistic — which only
# makes CPU-bound HARDER to reach. A negative result here is a strong negative.
#
# Usage: sudo run-cpu-regime.sh [path-to-yipd-binary]
set -euo pipefail

if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    YIPD="$1"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
    echo "[build] cargo build --release -p yipd"
    cargo build --release -p yipd --quiet --manifest-path "$WORKSPACE_ROOT/Cargo.toml"
    YIPD="$WORKSPACE_ROOT/target/release/yipd"
fi

# ── core assignment (models a 1-core receiver) ───────────────────────────────
NCORES="$(nproc)"
if [ "$NCORES" -lt 6 ]; then
    echo "[error] need >= 6 cores to isolate a 1-core receiver cleanly; have $NCORES"
    exit 1
fi
RX_CORE=2                 # yipd_A (receiver under test) — pinned here, alone
IPERF_SRV_CORE=3          # iperf3 server in NS_A (decrypted-side sink)
TX_CORES="6,7,8"          # yipd_A's peer (sender encrypt path)
IPERF_CLI_CORES="9,10,11" # iperf3 client (traffic source)

TMPDIR_TEST="$(mktemp -d /tmp/yipd-cpuregime.XXXXXX)"
NS_A="yipA"; NS_B="yipB"
VETH_A="vethA"; VETH_B="vethB"
VETH_A_IP="10.0.0.1"; VETH_B_IP="10.0.0.2"
TUN_A_IP="10.9.0.1"; TUN_B_IP="10.9.0.2"
PORT_A="51820"; PORT_B="51821"
TUN_DEV="yip0"
TUN_MTU=1380
DUR=8                     # seconds per iperf run
UDP_RATE="6G"            # UDP blast target (well above any plausible plateau)
TCP_STREAMS=8

PID_A=""; PID_B=""; IPERF_SRV_PID=""

cleanup() {
    echo "[cleanup] tearing down"
    [ -n "$IPERF_SRV_PID" ] && kill "$IPERF_SRV_PID" 2>/dev/null || true
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

# ── keys + configs ───────────────────────────────────────────────────────────
GENKEY_A="$("$YIPD" --genkey)"; GENKEY_B="$("$YIPD" --genkey)"
PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A"  | grep '^public='  | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B"  | grep '^public='  | cut -d= -f2)"

CFG_A="$TMPDIR_TEST/yipA.conf"; CFG_B="$TMPDIR_TEST/yipB.conf"
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

# ── netns + veth ─────────────────────────────────────────────────────────────
echo "[setup] netns + veth"
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"; ip link set "$VETH_B" netns "$NS_B"
ip netns exec "$NS_A" ip addr add "${VETH_A_IP}/24" dev "$VETH_A"
ip netns exec "$NS_A" ip link set "$VETH_A" up; ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip addr add "${VETH_B_IP}/24" dev "$VETH_B"
ip netns exec "$NS_B" ip link set "$VETH_B" up; ip netns exec "$NS_B" ip link set lo up

# ── daemons (RX pinned to one core) ──────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"; LOG_B="$TMPDIR_TEST/yipB.log"
echo "[start] yipd_A (receiver) pinned to core ${RX_CORE}; yipd_B on cores ${TX_CORES}"
ip netns exec "$NS_A" taskset -c "$RX_CORE" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!
ip netns exec "$NS_B" taskset -c "$TX_CORES" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── wait for TUN devices ─────────────────────────────────────────────────────
echo "[wait] TUN devices"
elapsed=0
while true; do
    A_UP=0; B_UP=0
    ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true
    [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ] && break
    kill -0 "$PID_A" 2>/dev/null || { echo "[error] yipd_A died"; cat "$LOG_A"; exit 1; }
    kill -0 "$PID_B" 2>/dev/null || { echo "[error] yipd_B died"; cat "$LOG_B"; exit 1; }
    elapsed=$(awk "BEGIN {print $elapsed + 0.25}")
    awk "BEGIN {exit ($elapsed >= 20) ? 0 : 1}" && { echo "[error] TUN timeout"; cat "$LOG_A" "$LOG_B"; exit 1; }
    sleep 0.25
done

# ── tunnel IPs + MTU ─────────────────────────────────────────────────────────
ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_A" ip link set "$TUN_DEV" mtu "$TUN_MTU" up
ip netns exec "$NS_B" ip link set "$TUN_DEV" mtu "$TUN_MTU" up
sleep 0.5
ip netns exec "$NS_B" ping -c 3 -W 5 "$TUN_A_IP" >/dev/null || { echo "[error] baseline ping failed"; cat "$LOG_A" "$LOG_B"; exit 1; }

# read total CPU ticks (utime+stime) for a pid
cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

run_iperf() {  # $1=label  $2..=iperf client args
    local label="$1"; shift
    # fresh server for this run
    ip netns exec "$NS_A" taskset -c "$IPERF_SRV_CORE" iperf3 -s -1 -p 5201 >/dev/null 2>&1 &
    local srv=$!
    sleep 0.3
    local t0 c0 out c1 t1 cores gbps loss
    t0="$(date +%s.%N)"; c0="$(cpu_ticks "$PID_A")"
    out="$(ip netns exec "$NS_B" taskset -c "$IPERF_CLI_CORES" iperf3 -c "$TUN_A_IP" -p 5201 -J "$@" 2>/dev/null || true)"
    c1="$(cpu_ticks "$PID_A")"; t1="$(date +%s.%N)"
    kill "$srv" 2>/dev/null || true
    cores="$(awk "BEGIN {w=$t1-$t0; if (w<=0) w=1; printf \"%.2f\", ($c1-$c0)/100.0/w}")"
    gbps="$(echo "$out" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin); e=d['end']
    r=e.get('sum_received') or e.get('sum')
    print('%.3f' % (r['bits_per_second']/1e9))
except Exception: print('ERR')
" 2>/dev/null || echo ERR)"
    loss="$(echo "$out" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin); s=d['end'].get('sum',{})
    print('%.1f%%' % s['lost_percent']) if 'lost_percent' in s else print('-')
except Exception: print('-')
" 2>/dev/null || echo -)"
    printf "%-6s  %-8s  %-10s  %-10s  %-8s\n" "$RTT_LABEL" "$label" "$gbps" "$cores" "$loss"
}

# ── RTT sweep ────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  yip receiver CPU-bound-regime sweep"
echo "  data flows NS_B -> NS_A;  yipd_A RX pinned to core ${RX_CORE}"
echo "  rx_cores = cores busy on the pinned RX process (1.0 = saturated)"
echo "================================================================"
printf "%-6s  %-8s  %-10s  %-10s  %-8s\n" "RTT" "flow" "Gbps" "rx_cores" "udp_loss"
echo "----------------------------------------------------------------"

for RTT in 0 1 5 12 24; do
    RTT_LABEL="${RTT}ms"
    if [ "$RTT" -eq 0 ]; then
        ip netns exec "$NS_A" tc qdisc del dev "$VETH_A" root 2>/dev/null || true
        ip netns exec "$NS_B" tc qdisc del dev "$VETH_B" root 2>/dev/null || true
    else
        HALF="$(awk "BEGIN {printf \"%.3f\", $RTT/2.0}")"
        ip netns exec "$NS_A" tc qdisc replace dev "$VETH_A" root netem delay "${HALF}ms"
        ip netns exec "$NS_B" tc qdisc replace dev "$VETH_B" root netem delay "${HALF}ms"
    fi
    run_iperf "udp" -u -b "$UDP_RATE" -t "$DUR" -O 1
    run_iperf "tcp" -P "$TCP_STREAMS" -t "$DUR" -O 1
done

echo "================================================================"
echo "[verdict] If rx_cores approaches ~1.0 at low RTT (<=5ms) while Gbps"
echo "          plateaus, a CPU-bound regime EXISTS -> #4 is justified."
echo "          If rx_cores stays well below 1.0 everywhere Gbps plateaus,"
echo "          the receiver is window/other-bound -> #4 CPU levers are dead."
echo "[done]"
