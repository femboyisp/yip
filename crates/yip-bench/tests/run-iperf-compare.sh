#!/usr/bin/env bash
# run-iperf-compare.sh — iperf3 TCP & UDP throughput + ping latency/loss under netem,
# across contemporary tunnels and mesh overlays in dual-stack IPv4 and IPv6:
#   yip, WireGuard, AmneziaWG, OpenVPN, n2n, ZeroTier, Tailscale, NetBird.
#
# Each contender is set up in its OWN dedicated netns pair; at each loss rate
# (0 5 10 %, symmetric delay 5ms) we run:
#   ping      -c 50 -i 0.1             -> effective loss % + avg RTT (ms)
#   iperf3    -c <tun> -t 8             -> TCP goodput (Mbit/s)
#   iperf3 -u -c <tun> -b <rate> -t 8   -> UDP throughput (Mbit/s) + UDP loss % + CPU telemetry
#
# yip MUST always run; every other contender SKIPs cleanly (logging why) if its
# tool/module is absent.
#
# Usage: run-iperf-compare.sh [<path-to-yipd>]
set -euo pipefail

if ! command -v iperf3 >/dev/null 2>&1; then
    echo "[SKIP] iperf3 not found — skipping iperf throughput comparison"
    exit 0
fi

# Disable IPv6 DAD in current namespace
sysctl -qw net.ipv6.conf.all.accept_dad=0 \
    net.ipv6.conf.default.accept_dad=0 \
    net.ipv6.conf.lo.accept_dad=0 2>/dev/null || true

# ── binary ────────────────────────────────────────────────────────────────────
if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    YIPD="$1"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
    echo "[build] running cargo build --release -p yipd --quiet in $WORKSPACE_ROOT"
    cargo build --release -p yipd --quiet --manifest-path "$WORKSPACE_ROOT/Cargo.toml"
    YIPD="$WORKSPACE_ROOT/target/release/yipd"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

TMPDIR_TEST="$(mktemp -d /dev/shm/yip-iperf-compare.XXXXXX 2>/dev/null || mktemp -d /tmp/yip-iperf-compare.XXXXXX)"
chmod 777 "$TMPDIR_TEST"

# ── yip ───────────────────────────────────────────────────────────────────────
NS_YA="ipfYA"; NS_YB="ipfYB"; VYA="ipfvYA"; VYB="ipfvYB"
VYA_IP="10.10.0.1"; VYB_IP="10.10.0.2"
TUN_YA_IP="10.11.0.1"; TUN_YB_IP="10.11.0.2"
TUN_YA_IP6="fd00:11::1"; TUN_YB_IP6="fd00:11::2"
YPORT_A="443"; YPORT_B="443"; TUN_DEV="yip0"; YIP_MTU="${YIP_MTU:-1420}"; YIP_SHARDS="${YIP_SHARDS:-1}"
PID_YA=""; PID_YB=""

# ── WireGuard ─────────────────────────────────────────────────────────────────
NS_WA="ipfWA"; NS_WB="ipfWB"; VWA="ipfvWA"; VWB="ipfvWB"
VWA_IP="10.12.0.1"; VWB_IP="10.12.0.2"
TUN_WA_IP="10.13.0.1"; TUN_WB_IP="10.13.0.2"
TUN_WA_IP6="fd00:13::1"; TUN_WB_IP6="fd00:13::2"
WPORT_A="51860"; WPORT_B="51861"
WG_AVAILABLE=true

# ── OpenVPN ───────────────────────────────────────────────────────────────────
NS_OA="ipfOA"; NS_OB="ipfOB"; VOA="ipfvOA"; VOB="ipfvOB"
VOA_IP="10.14.0.1"; VOB_IP="10.14.0.2"
TUN_OA_IP="10.15.0.1"; TUN_OB_IP="10.15.0.2"
TUN_OA_IP6="fd00:15::1"; TUN_OB_IP6="fd00:15::2"
OVPN_AVAILABLE=true

# ── n2n ───────────────────────────────────────────────────────────────────────
NS_NA="ipfNA"; NS_NB="ipfNB"; VNA="ipfvNA"; VNB="ipfvNB"
VNA_IP="10.16.0.1"; VNB_IP="10.16.0.2"
OVL_NA_IP="10.17.0.1"; OVL_NB_IP="10.17.0.2"
OVL_NA_IP6="fd00:17::1"; OVL_NB_IP6="fd00:17::2"
N2N_PORT="7654"
N2N_AVAILABLE=true

# ── AmneziaWG ─────────────────────────────────────────────────────────────────
NS_AA="ipfAA"; NS_AB="ipfAB"; VAA="ipfvAA"; VAB="ipfvAB"
VAA_IP="10.18.0.1"; VAB_IP="10.18.0.2"
TUN_AA_IP="10.19.0.1"; TUN_AB_IP="10.19.0.2"
TUN_AA_IP6="fd00:19::1"; TUN_AB_IP6="fd00:19::2"
APORT_A="51870"; APORT_B="51871"
AWG_AVAILABLE=true

# ── ZeroTier ──────────────────────────────────────────────────────────────────
NS_ZA="ipfZA"; NS_ZB="ipfZB"; VZA="ipfvZA"; VZB="ipfvZB"
VZA_IP="10.20.0.1"; VZB_IP="10.20.0.2"
TUN_ZA_IP="10.21.0.1"; TUN_ZB_IP="10.21.0.2"
TUN_ZA_IP6="fd00:21::1"; TUN_ZB_IP6="fd00:21::2"
ZT_AVAILABLE=true

# ── Tailscale ─────────────────────────────────────────────────────────────────
NS_TA="ipfTA"; NS_TB="ipfTB"; VTA="ipfvTA"; VTB="ipfvTB"
VTA_IP="10.22.0.1"; VTB_IP="10.22.0.2"
TUN_TA_IP="10.23.0.1"; TUN_TB_IP="10.23.0.2"
TUN_TA_IP6="fd00:23::1"; TUN_TB_IP6="fd00:23::2"
TS_AVAILABLE=true

# ── NetBird ───────────────────────────────────────────────────────────────────
NS_BA="ipfBA"; NS_BB="ipfBB"; VBA="ipfvBA"; VBB="ipfvBB"
VBA_IP="10.24.0.1"; VBB_IP="10.24.0.2"
TUN_BA_IP="10.25.0.1"; TUN_BB_IP="10.25.0.2"
TUN_BA_IP6="fd00:25::1"; TUN_BB_IP6="fd00:25::2"
NB_AVAILABLE=true

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    if [ -f "${LOG_A:-}" ] && [ -s "${LOG_A:-}" ]; then
        echo "=== yipA log ==="
        tail -n 50 "$LOG_A" || true
    fi
    if [ -f "${LOG_B:-}" ] && [ -s "${LOG_B:-}" ]; then
        echo "=== yipB log ==="
        tail -n 50 "$LOG_B" || true
    fi
    [ -n "$PID_YA" ] && kill "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill "$PID_YB" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_YA" ] && kill -9 "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill -9 "$PID_YB" 2>/dev/null || true
    # Remove virtual interfaces before deleting namespaces
    ip netns exec "$NS_WA" ip link del wg0 2>/dev/null || true
    ip netns exec "$NS_WB" ip link del wg0 2>/dev/null || true
    rm -f /etc/wireguard/wg_a /etc/wireguard/wg_b 2>/dev/null || true
    ip netns exec "$NS_AA" ip link del awg0 2>/dev/null || true
    ip netns exec "$NS_AB" ip link del awg0 2>/dev/null || true
    for ns in "$NS_YA" "$NS_YB" "$NS_WA" "$NS_WB" "$NS_OA" "$NS_OB" "$NS_NA" "$NS_NB" \
              "$NS_AA" "$NS_AB" "$NS_ZA" "$NS_ZB" "$NS_TA" "$NS_TB" "$NS_BA" "$NS_BB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── helper: two-netns veth pair ───────────────────────────────────────────────
make_pair() {
    local nsR="$1" nsS="$2" vR="$3" vS="$4" ipR="$5" ipS="$6"
    ip netns add "$nsR"; ip netns add "$nsS"
    for ns in "$nsR" "$nsS"; do
        ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_dad=0 \
            net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.lo.accept_dad=0 2>/dev/null || true
    done
    ip link add "$vR" type veth peer name "$vS"
    ip link set "$vR" netns "$nsR"; ip link set "$vS" netns "$nsS"
    ip netns exec "$nsR" ip addr add "$ipR/24" dev "$vR"
    ip netns exec "$nsR" ip link set "$vR" up; ip netns exec "$nsR" ip link set lo up
    ip netns exec "$nsS" ip addr add "$ipS/24" dev "$vS"
    ip netns exec "$nsS" ip link set "$vS" up; ip netns exec "$nsS" ip link set lo up
}

# ── helper: symmetric netem loss + 5ms delay ──────────────────────────────────
apply_netem() {
    local nsR="$1" nsS="$2" vR="$3" vS="$4" loss="$5"
    if [ "$loss" -eq 0 ]; then
        ip netns exec "$nsR" tc qdisc del dev "$vR" root 2>/dev/null || true
        ip netns exec "$nsS" tc qdisc del dev "$vS" root 2>/dev/null || true
        return
    fi
    ip netns exec "$nsR" tc qdisc replace dev "$vR" root netem loss "${loss}%" delay 5ms
    ip netns exec "$nsS" tc qdisc replace dev "$vS" root netem loss "${loss}%" delay 5ms
}

# ── helper: ping a tunnel IP from a netns; echo "<loss%> <avg_rtt_ms>" ─────────
PING_COUNT="${PING_COUNT:-50}"
if [ -n "${PING_INTERVAL:-}" ]; then
    PING_INTERVAL="$PING_INTERVAL"
elif [ "$PING_COUNT" -ge 1000 ] 2>/dev/null; then
    PING_INTERVAL="0.005"
else
    PING_INTERVAL="0.1"
fi

measure_ping() {
    local ns="$1" dst="$2" ping_cmd out loss rttline rtt
    if [[ "$dst" == *:* ]]; then
        ping_cmd="ping -6"
    else
        ping_cmd="ping"
    fi
    out="$(ip netns exec "$ns" $ping_cmd -c "$PING_COUNT" -i "$PING_INTERVAL" -W 1 "$dst" 2>&1 || true)"
    loss="$(echo "$out" | sed -nE 's/.* ([0-9.]+)% packet loss.*/\1/p' | head -1 || true)"
    [ -z "$loss" ] && loss="100"
    rttline="$(echo "$out" | grep -oP '(rtt|round-trip) min/avg/max/(mdev|stddev) = [0-9./]+ ms' || true)"
    if [ -n "$rttline" ]; then
        rtt="$(echo "$rttline" | cut -d= -f2 | tr '/' ' ' | awk '{print $2}' || true)"
    else
        rtt="N/A"
    fi
    echo "$loss $rtt"
}
measure_ping_v6() { measure_ping "$@"; }

# ── CPU telemetry helpers ─────────────────────────────────────────────────────
CPU_START_USER=0
CPU_START_NICE=0
CPU_START_SYS=0
CPU_START_IDLE=0
CPU_START_IOW=0
CPU_START_IRQ=0
CPU_START_SIRQ=0
CPU_START_STEAL=0

sample_cpu_start() {
    local cpu u n s id io irq sirq st rest
    read -r cpu u n s id io irq sirq st rest < /proc/stat
    CPU_START_USER="${u:-0}"
    CPU_START_NICE="${n:-0}"
    CPU_START_SYS="${s:-0}"
    CPU_START_IDLE="${id:-0}"
    CPU_START_IOW="${io:-0}"
    CPU_START_IRQ="${irq:-0}"
    CPU_START_SIRQ="${sirq:-0}"
    CPU_START_STEAL="${st:-0}"
}

sample_cpu_end() {
    local mbps="${1:-}"
    local cpu u n s id io irq sirq st rest
    read -r cpu u n s id io irq sirq st rest < /proc/stat
    awk -v u1="$CPU_START_USER" -v n1="$CPU_START_NICE" -v s1="$CPU_START_SYS" \
        -v id1="$CPU_START_IDLE" -v io1="$CPU_START_IOW" -v irq1="$CPU_START_IRQ" \
        -v sirq1="$CPU_START_SIRQ" -v st1="$CPU_START_STEAL" \
        -v u2="${u:-0}" -v n2="${n:-0}" -v s2="${s:-0}" \
        -v id2="${id:-0}" -v io2="${io:-0}" -v irq2="${irq:-0}" \
        -v sirq2="${sirq:-0}" -v st2="${st:-0}" \
        -v mbps="$mbps" '
    BEGIN {
        idle1 = id1 + io1
        busy1 = u1 + n1 + s1 + irq1 + sirq1 + st1
        total1 = idle1 + busy1

        idle2 = id2 + io2
        busy2 = u2 + n2 + s2 + irq2 + sirq2 + st2
        total2 = idle2 + busy2

        d_total = total2 - total1
        d_busy = busy2 - busy1

        if (d_total > 0 && d_busy >= 0) {
            pct = (d_busy / d_total) * 100.0
            cpu_pct = sprintf("%.1f", pct)
        } else {
            cpu_pct = "0.0"
        }

        if (mbps != "" && mbps != "N/A" && (mbps + 0) > 0) {
            gbps = (mbps + 0) / 1000.0
            eff = sprintf("%.1f", (cpu_pct + 0) / gbps)
        } else {
            eff = "N/A"
        }

        if (mbps != "") {
            printf "%s %s\n", cpu_pct, eff
        } else {
            printf "%s\n", cpu_pct
        }
    }'
}

calc_cpu_efficiency() {
    local cpu_pct="$1" mbps="$2"
    awk -v pct="$cpu_pct" -v m="$mbps" '
    BEGIN {
        if (pct == "N/A" || m == "N/A" || (m + 0) <= 0) {
            printf "N/A\n"
        } else {
            gbps = (m + 0) / 1000.0
            eff = (pct + 0) / gbps
            printf "%.1f\n", eff
        }
    }'
}

# ── RAM telemetry helper ──────────────────────────────────────────────────────
# Returns peak resident memory (MB) for processes inside namespace $1, excluding test harnesses
get_ns_ram_mb() {
    local ns="$1"
    local pids max_kb=0
    pids="$(ip netns pids "$ns" 2>/dev/null || true)"
    for pid in $pids; do
        local comm
        comm="$(cat /proc/$pid/comm 2>/dev/null || true)"
        if [ "$comm" = "iperf3" ] || [ "$comm" = "ping" ] || [ "$comm" = "bash" ]; then
            continue
        fi
        local hwm_kb
        hwm_kb="$(grep -i VmHWM /proc/$pid/status 2>/dev/null | awk '{print $2}' || true)"
        if [ -z "$hwm_kb" ]; then
            hwm_kb="$(grep -i VmRSS /proc/$pid/status 2>/dev/null | awk '{print $2}' || true)"
        fi
        if [ -n "$hwm_kb" ] && [ "$hwm_kb" -gt "$max_kb" ] 2>/dev/null; then
            max_kb="$hwm_kb"
        fi
    done
    if [ "$max_kb" -gt 0 ]; then
        awk -v kb="$max_kb" 'BEGIN {printf "%.1f", kb / 1024.0}'
    else
        echo "N/A"
    fi
}

calc_ram_efficiency() {
    local ram_mb="$1" mbps="$2"
    awk -v ram="$ram_mb" -v m="$mbps" '
    BEGIN {
        if (ram == "N/A" || m == "N/A" || (m + 0) <= 0) {
            printf "N/A\n"
        } else {
            gbps = (m + 0) / 1000.0
            eff = (ram + 0) / gbps
            printf "%.1f\n", eff
        }
    }'
}

# ── helper: iperf3 TCP Mbit/s; server in <ns_srv> bound to <srv_ip>, client in
#    <ns_cli> -> <srv_ip>.  echo "<mbps>" ───────────────────────────────────────
measure_iperf() {
    local ns_srv="$1" srv_ip="$2" ns_cli="$3" v6_flag="" srv_pid mbps
    if [[ "$srv_ip" == *:* ]]; then
        v6_flag="-6"
    fi
    ip netns exec "$ns_srv" iperf3 -s -1 -B "$srv_ip" $v6_flag >/dev/null 2>&1 &
    srv_pid=$!
    sleep 0.5
    mbps="$(ip netns exec "$ns_cli" iperf3 -c "$srv_ip" $v6_flag --connect-timeout 3000 -t 8 2>/dev/null \
        | grep -i receiver | grep -oP '[0-9.]+ (Mbits|Gbits)/sec' | tail -1 || echo "")"
    kill "$srv_pid" 2>/dev/null || true
    if echo "$mbps" | grep -qi 'Gbits'; then
        mbps="$(echo "$mbps" | grep -oP '[0-9.]+' | awk '{printf "%.1f", $1*1000}' || true)"
    else
        mbps="$(echo "$mbps" | grep -oP '[0-9.]+' | head -1 || true)"
    fi
    [ -z "$mbps" ] && mbps="N/A"
    echo "$mbps"
}
measure_iperf_v6() { measure_iperf "$@"; }

# ── helper: iperf3 UDP Mbit/s, loss %, CPU % and CPU efficiency; server in <ns_srv> bound to <srv_ip>,
#    client in <ns_cli> -> <srv_ip>. echo "<mbps> <loss_pct> <cpu_pct> <cpu_eff>" ───────────
measure_iperf_udp() {
    local ns_srv="$1" srv_ip="$2" ns_cli="$3" v6_flag="" srv_pid out mbps loss cpu_pct cpu_eff
    if [[ "$srv_ip" == *:* ]]; then
        v6_flag="-6"
    fi
    ip netns exec "$ns_srv" iperf3 -s -1 -B "$srv_ip" $v6_flag >/dev/null 2>&1 &
    srv_pid=$!
    sleep 0.5
    sample_cpu_start
    out="$(ip netns exec "$ns_cli" iperf3 -c "$srv_ip" $v6_flag -u \
        -b "${UDP_RATE:-10G}" -l "${UDP_LEN:-1400}" --connect-timeout 3000 -t 8 -J 2>/dev/null || true)"
    read -r cpu_pct _ <<< "$(sample_cpu_end)"
    kill "$srv_pid" 2>/dev/null || true

    if [ -n "$out" ]; then
        if command -v jq >/dev/null 2>&1; then
            mbps="$(echo "$out" | jq -r '.end.sum.bits_per_second // empty' 2>/dev/null || true)"
            loss="$(echo "$out" | jq -r '.end.sum.lost_percent // empty' 2>/dev/null || true)"
        else
            mbps="$(echo "$out" | grep -oP '"bits_per_second":\s*[0-9.]+' | tail -1 | grep -oP '[0-9.]+' || true)"
            loss="$(echo "$out" | grep -oP '"lost_percent":\s*[0-9.]+' | tail -1 | grep -oP '[0-9.]+' || true)"
        fi
        if [ -n "$mbps" ] && [ "$mbps" != "null" ]; then
            mbps="$(awk "BEGIN {printf \"%.1f\", $mbps / 1000000}")"
        else
            mbps="N/A"
        fi
        if [ -n "$loss" ] && [ "$loss" != "null" ]; then
            loss="$(awk "BEGIN {printf \"%.1f\", $loss}")"
        else
            loss="N/A"
        fi
    else
        mbps="N/A"
        loss="N/A"
    fi

    if [ "$mbps" != "N/A" ]; then
        cpu_eff="$(calc_cpu_efficiency "$cpu_pct" "$mbps")"
    else
        cpu_eff="N/A"
        cpu_pct="N/A"
    fi

    echo "$mbps $loss $cpu_pct $cpu_eff"
}
measure_iperf_udp_v6() { measure_iperf_udp "$@"; }

# ══════════════════════════════════════════════════════════════════════════════
# yip setup (always)
# ══════════════════════════════════════════════════════════════════════════════
echo "[yip] generating keypairs"
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
listen=${VYA_IP}:${YPORT_A}
peer_endpoint=${VYB_IP}:${YPORT_B}
device=${TUN_DEV}
initiate=false
shards=${YIP_SHARDS}
EOF
cat > "$CFG_B" <<EOF
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VYB_IP}:${YPORT_B}
peer_endpoint=${VYA_IP}:${YPORT_A}
device=${TUN_DEV}
initiate=true
shards=${YIP_SHARDS}
EOF

echo "[yip] creating namespaces and veth pair"
make_pair "$NS_YA" "$NS_YB" "$VYA" "$VYB" "$VYA_IP" "$VYB_IP"
LOG_A="$TMPDIR_TEST/yipA.log"; LOG_B="$TMPDIR_TEST/yipB.log"
echo "[yip] starting daemons"
ip netns exec "$NS_YA" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_YA=$!
ip netns exec "$NS_YB" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_YB=$!

echo "[yip] waiting for TUN devices (up to 20s)"
elapsed=0
while true; do
    A_UP=0; B_UP=0
    ip netns exec "$NS_YA" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_YB" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true
    [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ] && { echo "[yip] both TUN up"; break; }
    if ! kill -0 "$PID_YA" 2>/dev/null; then echo "[error] yipA died"; cat "$LOG_A" || true; exit 1; fi
    if ! kill -0 "$PID_YB" 2>/dev/null; then echo "[error] yipB died"; cat "$LOG_B" || true; exit 1; fi
    elapsed=$(awk "BEGIN {print $elapsed + 0.25}")
    if awk "BEGIN {exit ($elapsed >= 20) ? 0 : 1}"; then
        echo "[error] timed out waiting for yip TUN"; cat "$LOG_A" "$LOG_B" || true; exit 1
    fi
    sleep 0.25
done
ip netns exec "$NS_YA" ip link set "$TUN_DEV" mtu "$YIP_MTU"
ip netns exec "$NS_YB" ip link set "$TUN_DEV" mtu "$YIP_MTU"
ip netns exec "$NS_YA" ip link set dev "$TUN_DEV" txqueuelen 10000
ip netns exec "$NS_YB" ip link set dev "$TUN_DEV" txqueuelen 10000
ip netns exec "$NS_YA" ip link set "$TUN_DEV" up
ip netns exec "$NS_YB" ip link set "$TUN_DEV" up
ip netns exec "$NS_YA" ip addr add "${TUN_YA_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_YB" ip addr add "${TUN_YB_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_YA" ip -6 addr add "${TUN_YA_IP6}/64" dev "$TUN_DEV" nodad
ip netns exec "$NS_YB" ip -6 addr add "${TUN_YB_IP6}/64" dev "$TUN_DEV" nodad
sleep 0.5
echo "[yip] baseline connectivity check"
ip netns exec "$NS_YB" ping -c 3 -W 5 "$TUN_YA_IP" >/dev/null || {
    echo "[error] yip baseline IPv4 ping failed"; cat "$LOG_A" "$LOG_B" || true; exit 1
}
ip netns exec "$NS_YB" ping -6 -c 3 -W 5 "$TUN_YA_IP6" >/dev/null || {
    echo "[error] yip baseline IPv6 ping failed"; cat "$LOG_A" "$LOG_B" || true; exit 1
}

# ══════════════════════════════════════════════════════════════════════════════
# WireGuard setup
# ══════════════════════════════════════════════════════════════════════════════
setup_wg() {
    if ! command -v wg >/dev/null 2>&1; then
        echo "[wg] SKIP: 'wg' command not found"; WG_AVAILABLE=false; return
    fi
    if ! modprobe wireguard 2>/dev/null; then
        echo "[wg] SKIP: modprobe wireguard failed"; WG_AVAILABLE=false; return
    fi
    # If Ubuntu AppArmor confines /usr/bin/wg, unload or complain so it can read keys
    apparmor_parser -R /etc/apparmor.d/wg 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.bin.wg 2>/dev/null || true
    echo "[wg] generating keypairs"
    local privA pubA privB pubB
    privA="$(wg genkey 2>/dev/null || true)"; pubA="$(echo "$privA" | wg pubkey 2>/dev/null || true)"
    privB="$(wg genkey 2>/dev/null || true)"; pubB="$(echo "$privB" | wg pubkey 2>/dev/null || true)"
    if [ -z "$privA" ] || [ -z "$privB" ]; then
        echo "[wg] SKIP: key generation failed"; WG_AVAILABLE=false; return
    fi
    echo "[wg] creating namespaces and veth pair"
    make_pair "$NS_WA" "$NS_WB" "$VWA" "$VWB" "$VWA_IP" "$VWB_IP"
    if ! ip netns exec "$NS_WA" ip link add wg0 type wireguard 2>/dev/null || \
       ! ip netns exec "$NS_WB" ip link add wg0 type wireguard 2>/dev/null; then
        echo "[wg] SKIP: wireguard interface creation failed"; WG_AVAILABLE=false; return
    fi
    local wg_dir="/etc/wireguard"
    if [ ! -d "$wg_dir" ]; then
        mkdir -p "$wg_dir" 2>/dev/null || wg_dir="$TMPDIR_TEST"
    fi
    local keyA="$wg_dir/wg_a"
    local keyB="$wg_dir/wg_b"
    printf '%s' "$privA" > "$keyA"
    printf '%s' "$privB" > "$keyB"
    chmod 600 "$keyA" "$keyB"
    local wg_err=""
    if ! wg_err="$(ip netns exec "$NS_WA" wg set wg0 private-key "$keyA" listen-port "$WPORT_A" \
            peer "$pubB" endpoint "${VWB_IP}:${WPORT_B}" allowed-ips "${TUN_WB_IP}/32,fd00:13::/64" 2>&1)" || \
       ! wg_err="$(ip netns exec "$NS_WB" wg set wg0 private-key "$keyB" listen-port "$WPORT_B" \
            peer "$pubA" endpoint "${VWA_IP}:${WPORT_A}" allowed-ips "${TUN_WA_IP}/32,fd00:13::/64" 2>&1)"; then
        echo "[wg] SKIP: wg set configuration failed: $wg_err"; WG_AVAILABLE=false; return
    fi
    if ! ip netns exec "$NS_WA" ip addr add "${TUN_WA_IP}/24" dev wg0 2>/dev/null || \
       ! ip netns exec "$NS_WB" ip addr add "${TUN_WB_IP}/24" dev wg0 2>/dev/null || \
       ! ip netns exec "$NS_WA" ip -6 addr add "${TUN_WA_IP6}/64" dev wg0 nodad 2>/dev/null || \
       ! ip netns exec "$NS_WB" ip -6 addr add "${TUN_WB_IP6}/64" dev wg0 nodad 2>/dev/null || \
       ! ip netns exec "$NS_WA" ip link set wg0 up 2>/dev/null || \
       ! ip netns exec "$NS_WB" ip link set wg0 up 2>/dev/null; then
        echo "[wg] SKIP: interface setup failed"; WG_AVAILABLE=false; return
    fi
    sleep 0.5
    if ! ip netns exec "$NS_WB" ping -c 3 -W 5 "$TUN_WA_IP" >/dev/null 2>&1; then
        echo "[wg] SKIP: baseline IPv4 ping failed"; WG_AVAILABLE=false; return
    fi
    if ! ip netns exec "$NS_WB" ping -6 -c 3 -W 5 "$TUN_WA_IP6" >/dev/null 2>&1; then
        echo "[wg] SKIP: baseline IPv6 ping failed"; WG_AVAILABLE=false; return
    fi
    echo "[wg] tunnel up"
}
setup_wg

# ══════════════════════════════════════════════════════════════════════════════
# AmneziaWG setup (kernel module or amneziawg-go)
# ══════════════════════════════════════════════════════════════════════════════
setup_awg() {
    if ! command -v awg >/dev/null 2>&1; then
        echo "[awg] SKIP: 'awg' command not found"; AWG_AVAILABLE=false; return
    fi
    local use_go=false
    if ! modprobe amneziawg 2>/dev/null; then
        if command -v amneziawg-go >/dev/null 2>&1; then
            use_go=true
        else
            echo "[awg] SKIP: neither amneziawg kernel module nor amneziawg-go found"
            AWG_AVAILABLE=false; return
        fi
    fi
    echo "[awg] generating keypairs"
    local privA pubA privB pubB
    privA="$(awg genkey 2>/dev/null || true)"; pubA="$(echo "$privA" | awg pubkey 2>/dev/null || true)"
    privB="$(awg genkey 2>/dev/null || true)"; pubB="$(echo "$privB" | awg pubkey 2>/dev/null || true)"
    if [ -z "$privA" ] || [ -z "$privB" ]; then
        echo "[awg] SKIP: key generation failed"; AWG_AVAILABLE=false; return
    fi
    echo "[awg] creating namespaces and veth pair"
    make_pair "$NS_AA" "$NS_AB" "$VAA" "$VAB" "$VAA_IP" "$VAB_IP"
    if [ "$use_go" = true ]; then
        ip netns exec "$NS_AA" amneziawg-go awg0 >"$TMPDIR_TEST/awg-go-a.log" 2>&1 &
        ip netns exec "$NS_AB" amneziawg-go awg0 >"$TMPDIR_TEST/awg-go-b.log" 2>&1 &
        sleep 0.5
    else
        if ! ip netns exec "$NS_AA" ip link add awg0 type amneziawg 2>/dev/null || \
           ! ip netns exec "$NS_AB" ip link add awg0 type amneziawg 2>/dev/null; then
            echo "[awg] SKIP: amneziawg link add failed"; AWG_AVAILABLE=false; return
        fi
    fi

    local awg_up=false
    for i in $(seq 1 20); do
        if ip netns exec "$NS_AA" ip link show awg0 >/dev/null 2>&1 && \
           ip netns exec "$NS_AB" ip link show awg0 >/dev/null 2>&1; then
            awg_up=true
            break
        fi
        sleep 0.25
    done
    if [ "$awg_up" = false ]; then
        echo "[awg] SKIP: awg0 interface creation failed or timed out"
        tail -5 "$TMPDIR_TEST/awg-go-a.log" "$TMPDIR_TEST/awg-go-b.log" 2>/dev/null || true
        AWG_AVAILABLE=false; return
    fi

    if ! ip netns exec "$NS_AA" ip addr add "${TUN_AA_IP}/24" dev awg0 2>/dev/null || \
       ! ip netns exec "$NS_AB" ip addr add "${TUN_AB_IP}/24" dev awg0 2>/dev/null || \
       ! ip netns exec "$NS_AA" ip -6 addr add "${TUN_AA_IP6}/64" dev awg0 nodad 2>/dev/null || \
       ! ip netns exec "$NS_AB" ip -6 addr add "${TUN_AB_IP6}/64" dev awg0 nodad 2>/dev/null; then
        echo "[awg] SKIP: ip addr add failed"; AWG_AVAILABLE=false; return
    fi

    local CFG_AA="$TMPDIR_TEST/awgA.conf"; local CFG_AB="$TMPDIR_TEST/awgB.conf"
    cat > "$CFG_AA" <<EOF
[Interface]
PrivateKey = $privA
ListenPort = $APORT_A
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 20
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = $pubB
Endpoint = ${VAB_IP}:${APORT_B}
AllowedIPs = ${TUN_AB_IP}/32, fd00:19::/64
EOF

    cat > "$CFG_AB" <<EOF
[Interface]
PrivateKey = $privB
ListenPort = $APORT_B
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 20
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = $pubA
Endpoint = ${VAA_IP}:${APORT_A}
AllowedIPs = ${TUN_AA_IP}/32, fd00:19::/64
EOF
    chmod 600 "$CFG_AA" "$CFG_AB"

    if ! ip netns exec "$NS_AA" awg setconf awg0 "$CFG_AA" 2>/dev/null || \
       ! ip netns exec "$NS_AB" awg setconf awg0 "$CFG_AB" 2>/dev/null; then
        echo "[awg] SKIP: awg setconf failed"; AWG_AVAILABLE=false; return
    fi
    if ! ip netns exec "$NS_AA" ip link set awg0 up 2>/dev/null || \
       ! ip netns exec "$NS_AB" ip link set awg0 up 2>/dev/null; then
        echo "[awg] SKIP: ip link set up failed"; AWG_AVAILABLE=false; return
    fi
    sleep 0.5
    if ! ip netns exec "$NS_AB" ping -c 3 -W 5 "$TUN_AA_IP" >/dev/null 2>&1; then
        echo "[awg] SKIP: baseline IPv4 ping failed"; AWG_AVAILABLE=false; return
    fi
    if ! ip netns exec "$NS_AB" ping -6 -c 3 -W 5 "$TUN_AA_IP6" >/dev/null 2>&1; then
        echo "[awg] SKIP: baseline IPv6 ping failed"; AWG_AVAILABLE=false; return
    fi
    echo "[awg] tunnel up"
}
setup_awg

# ══════════════════════════════════════════════════════════════════════════════
# OpenVPN setup (peer-fingerprint, UDP, AES-256-GCM)
# ══════════════════════════════════════════════════════════════════════════════
setup_ovpn() {
    if ! command -v openvpn >/dev/null 2>&1; then
        echo "[ovpn] SKIP: 'openvpn' not found"; OVPN_AVAILABLE=false; return
    fi
    echo "[ovpn] generating self-signed certificates"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$TMPDIR_TEST/ovpn-a.key" -out "$TMPDIR_TEST/ovpn-a.crt" \
        -days 1 -nodes -subj "/CN=ovpn-a" >/dev/null 2>&1
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$TMPDIR_TEST/ovpn-b.key" -out "$TMPDIR_TEST/ovpn-b.crt" \
        -days 1 -nodes -subj "/CN=ovpn-b" >/dev/null 2>&1
    chmod 600 "$TMPDIR_TEST/ovpn-a.key" "$TMPDIR_TEST/ovpn-b.key"
    local FA FB
    FA="$(openssl x509 -in "$TMPDIR_TEST/ovpn-a.crt" -noout -fingerprint -sha256 \
        | cut -d= -f2)"
    FB="$(openssl x509 -in "$TMPDIR_TEST/ovpn-b.crt" -noout -fingerprint -sha256 \
        | cut -d= -f2)"

    echo "[ovpn] creating namespaces and veth pair"
    make_pair "$NS_OA" "$NS_OB" "$VOA" "$VOB" "$VOA_IP" "$VOB_IP"
    ip netns exec "$NS_OA" openvpn \
        --dev tun0 --dev-type tun \
        --local "$VOA_IP" --port 1194 --ifconfig "$TUN_OA_IP" "$TUN_OB_IP" \
        --ifconfig-ipv6 "$TUN_OA_IP6" "$TUN_OB_IP6" \
        --tls-server --cert "$TMPDIR_TEST/ovpn-a.crt" --key "$TMPDIR_TEST/ovpn-a.key" \
        --peer-fingerprint "$FB" --data-ciphers AES-256-GCM \
        --proto udp --verb 1 --ping 10 --ping-restart 0 \
        >"$TMPDIR_TEST/ovpn-a.log" 2>&1 &
    ip netns exec "$NS_OB" openvpn \
        --dev tun0 --dev-type tun \
        --remote "$VOA_IP" --rport 1194 --ifconfig "$TUN_OB_IP" "$TUN_OA_IP" \
        --ifconfig-ipv6 "$TUN_OB_IP6" "$TUN_OA_IP6" \
        --tls-client --cert "$TMPDIR_TEST/ovpn-b.crt" --key "$TMPDIR_TEST/ovpn-b.key" \
        --peer-fingerprint "$FA" --data-ciphers AES-256-GCM \
        --proto udp --verb 1 --ping 10 --ping-restart 0 \
        >"$TMPDIR_TEST/ovpn-b.log" 2>&1 &
    local i
    for i in $(seq 1 60); do
        ip netns exec "$NS_OA" ip link show tun0 >/dev/null 2>&1 \
            && ip netns exec "$NS_OB" ip link show tun0 >/dev/null 2>&1 && break
        sleep 0.25
    done
    ip netns exec "$NS_OA" ip -6 addr add "${TUN_OA_IP6}/64" dev tun0 nodad 2>/dev/null || true
    ip netns exec "$NS_OB" ip -6 addr add "${TUN_OB_IP6}/64" dev tun0 nodad 2>/dev/null || true
    sleep 1
    if ! ip netns exec "$NS_OB" ping -c 3 -W 5 "$TUN_OA_IP" >/dev/null 2>&1; then
        echo "[ovpn] SKIP: baseline IPv4 ping failed"
        tail -5 "$TMPDIR_TEST/ovpn-a.log" "$TMPDIR_TEST/ovpn-b.log" 2>/dev/null || true
        OVPN_AVAILABLE=false; return
    fi
    if ! ip netns exec "$NS_OB" ping -6 -c 3 -W 5 "$TUN_OA_IP6" >/dev/null 2>&1; then
        echo "[ovpn] SKIP: baseline IPv6 ping failed"
        tail -5 "$TMPDIR_TEST/ovpn-a.log" "$TMPDIR_TEST/ovpn-b.log" 2>/dev/null || true
        OVPN_AVAILABLE=false; return
    fi
    echo "[ovpn] tunnel up"
}
setup_ovpn

# ══════════════════════════════════════════════════════════════════════════════
# n2n setup (supernode + 2 edges; TAP L2 overlay, also carries L3)
# ══════════════════════════════════════════════════════════════════════════════
setup_n2n() {
    if ! command -v supernode >/dev/null 2>&1 || ! command -v edge >/dev/null 2>&1; then
        echo "[n2n] SKIP: 'supernode'/'edge' not found"; N2N_AVAILABLE=false; return
    fi
    echo "[n2n] creating namespaces and veth pair"
    make_pair "$NS_NA" "$NS_NB" "$VNA" "$VNB" "$VNA_IP" "$VNB_IP"
    ip netns exec "$NS_NA" supernode -p "$N2N_PORT" -f >"$TMPDIR_TEST/n2-sn.log" 2>&1 &
    sleep 0.5
    ip netns exec "$NS_NA" edge -c bench -k benchkey -a "$OVL_NA_IP" -l "$VNA_IP":"$N2N_PORT" \
        -d n2n0 -f >"$TMPDIR_TEST/n2-eA.log" 2>&1 &
    ip netns exec "$NS_NB" edge -c bench -k benchkey -a "$OVL_NB_IP" -l "$VNA_IP":"$N2N_PORT" \
        -d n2n0 -f >"$TMPDIR_TEST/n2-eB.log" 2>&1 &
    local i
    for i in $(seq 1 60); do
        ip netns exec "$NS_NA" ip link show n2n0 >/dev/null 2>&1 \
            && ip netns exec "$NS_NB" ip link show n2n0 >/dev/null 2>&1 && break
        sleep 0.25
    done
    ip netns exec "$NS_NA" ip -6 addr add "${OVL_NA_IP6}/64" dev n2n0 nodad 2>/dev/null || true
    ip netns exec "$NS_NB" ip -6 addr add "${OVL_NB_IP6}/64" dev n2n0 nodad 2>/dev/null || true
    sleep 2
    if ! ip netns exec "$NS_NB" ping -c 3 -W 5 "$OVL_NA_IP" >/dev/null 2>&1; then
        echo "[n2n] SKIP: baseline overlay IPv4 ping failed"
        tail -5 "$TMPDIR_TEST/n2-sn.log" "$TMPDIR_TEST/n2-eA.log" "$TMPDIR_TEST/n2-eB.log" 2>/dev/null || true
        N2N_AVAILABLE=false; return
    fi
    echo "[n2n] overlay up"
}
setup_n2n

# ══════════════════════════════════════════════════════════════════════════════
# ZeroTier setup (local netns controller)
# ══════════════════════════════════════════════════════════════════════════════
setup_zerotier() {
    if ! command -v zerotier-one >/dev/null 2>&1; then
        echo "[zerotier] SKIP: 'zerotier-one' not found"; ZT_AVAILABLE=false; return
    fi
    echo "[zerotier] creating namespaces and veth pair"
    make_pair "$NS_ZA" "$NS_ZB" "$VZA" "$VZB" "$VZA_IP" "$VZB_IP"
    local zt_dir_a="$TMPDIR_TEST/zt_a"; local zt_dir_b="$TMPDIR_TEST/zt_b"
    mkdir -p "$zt_dir_a" "$zt_dir_b"
    ip netns exec "$NS_ZA" zerotier-one "$zt_dir_a" >"$TMPDIR_TEST/zt-a.log" 2>&1 &
    ip netns exec "$NS_ZB" zerotier-one "$zt_dir_b" >"$TMPDIR_TEST/zt-b.log" 2>&1 &
    local i token_a="" node_a=""
    for i in $(seq 1 30); do
        if [ -f "$zt_dir_a/authtoken.secret" ] && [ -f "$zt_dir_b/authtoken.secret" ]; then
            token_a="$(cat "$zt_dir_a/authtoken.secret")"
            break
        fi
        sleep 0.2
    done
    if [ -z "$token_a" ]; then
        echo "[zerotier] SKIP: daemon failed to initialize"; ZT_AVAILABLE=false; return
    fi
    node_a="$(ip netns exec "$NS_ZA" zerotier-cli -D"$zt_dir_a" info 2>/dev/null | awk '{print $3}' || true)"
    if [ -z "$node_a" ]; then
        echo "[zerotier] SKIP: failed to get node identity"; ZT_AVAILABLE=false; return
    fi
    local net_id="${node_a}ffffff"
    ip netns exec "$NS_ZA" curl -s -H "X-ZT1-Auth: $token_a" -X POST \
        -d '{"name": "bench", "private": false, "v4AssignMode": {"zt": true}, "routes": [{"target": "10.21.0.0/24"}], "ipAssignmentPools": [{"ipRangeStart": "10.21.0.1", "ipRangeEnd": "10.21.0.254"}]}' \
        "http://127.0.0.1:9993/controller/network/${net_id}" >/dev/null 2>&1 || true
    ip netns exec "$NS_ZA" zerotier-cli -D"$zt_dir_a" join "$net_id" >/dev/null 2>&1 || true
    ip netns exec "$NS_ZB" zerotier-cli -D"$zt_dir_b" join "$net_id" >/dev/null 2>&1 || true
    local found=false
    for i in $(seq 1 40); do
        if ip netns exec "$NS_ZA" ip -o -4 addr show 2>/dev/null | grep -q "10.21." && \
           ip netns exec "$NS_ZB" ip -o -4 addr show 2>/dev/null | grep -q "10.21."; then
            found=true; break
        fi
        sleep 0.5
    done
    if [ "$found" = false ]; then
        echo "[zerotier] SKIP: overlay assignment timed out"; ZT_AVAILABLE=false; return
    fi
    local zt_a_if zt_b_if
    zt_a_if="$(ip netns exec "$NS_ZA" ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^zt' | head -1 || true)"
    zt_b_if="$(ip netns exec "$NS_ZB" ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^zt' | head -1 || true)"
    [ -n "$zt_a_if" ] && ip netns exec "$NS_ZA" ip -6 addr add "${TUN_ZA_IP6}/64" dev "$zt_a_if" nodad 2>/dev/null || true
    [ -n "$zt_b_if" ] && ip netns exec "$NS_ZB" ip -6 addr add "${TUN_ZB_IP6}/64" dev "$zt_b_if" nodad 2>/dev/null || true
    echo "[zerotier] network up"
}
setup_zerotier

# ══════════════════════════════════════════════════════════════════════════════
# Tailscale setup (local headscale coordinator)
# ══════════════════════════════════════════════════════════════════════════════
setup_tailscale() {
    if ! command -v tailscaled >/dev/null 2>&1 || ! command -v headscale >/dev/null 2>&1; then
        echo "[tailscale] SKIP: 'tailscaled' or 'headscale' not found"; TS_AVAILABLE=false; return
    fi
    echo "[tailscale] creating namespaces and veth pair"
    make_pair "$NS_TA" "$NS_TB" "$VTA" "$VTB" "$VTA_IP" "$VTB_IP"
    local hs_dir="$TMPDIR_TEST/headscale"
    mkdir -p "$hs_dir"
    cat > "$hs_dir/config.yaml" <<EOF
server_url: http://${VTA_IP}:8080
listen_addr: ${VTA_IP}:8080
ip_prefixes:
  - 10.23.0.0/24
derp:
  server:
    enabled: false
database:
  type: sqlite
  sqlite:
    path: $hs_dir/db.sqlite
dns:
  magic_dns: false
EOF
    ip netns exec "$NS_TA" headscale serve -c "$hs_dir/config.yaml" >"$TMPDIR_TEST/headscale.log" 2>&1 &
    sleep 1
    ip netns exec "$NS_TA" headscale users create bench -c "$hs_dir/config.yaml" >/dev/null 2>&1 || true
    local auth_key
    auth_key="$(ip netns exec "$NS_TA" headscale preauthkeys create -u bench --reusable --expiration 1h -c "$hs_dir/config.yaml" 2>/dev/null || true)"
    if [ -z "$auth_key" ]; then
        echo "[tailscale] SKIP: headscale preauthkey creation failed"; TS_AVAILABLE=false; return
    fi
    local ts_dir_a="$TMPDIR_TEST/ts_a"; local ts_dir_b="$TMPDIR_TEST/ts_b"
    mkdir -p "$ts_dir_a" "$ts_dir_b"
    ip netns exec "$NS_TA" tailscaled --state="$ts_dir_a/tailscaled.state" --socket="$ts_dir_a/tailscaled.sock" --tun=tailscale0 >"$TMPDIR_TEST/ts-a.log" 2>&1 &
    ip netns exec "$NS_TB" tailscaled --state="$ts_dir_b/tailscaled.state" --socket="$ts_dir_b/tailscaled.sock" --tun=tailscale0 >"$TMPDIR_TEST/ts-b.log" 2>&1 &
    sleep 1
    ip netns exec "$NS_TA" tailscale --socket="$ts_dir_a/tailscaled.sock" up --login-server="http://${VTA_IP}:8080" --auth-key="$auth_key" >/dev/null 2>&1 || true
    ip netns exec "$NS_TB" tailscale --socket="$ts_dir_b/tailscaled.sock" up --login-server="http://${VTA_IP}:8080" --auth-key="$auth_key" >/dev/null 2>&1 || true
    local found=false
    for i in $(seq 1 40); do
        if ip netns exec "$NS_TA" ip -o -4 addr show tailscale0 >/dev/null 2>&1 && \
           ip netns exec "$NS_TB" ip -o -4 addr show tailscale0 >/dev/null 2>&1; then
            found=true; break
        fi
        sleep 0.5
    done
    if [ "$found" = false ]; then
        echo "[tailscale] SKIP: tailscale tunnel activation timed out"; TS_AVAILABLE=false; return
    fi
    ip netns exec "$NS_TA" ip -6 addr add "${TUN_TA_IP6}/64" dev tailscale0 nodad 2>/dev/null || true
    ip netns exec "$NS_TB" ip -6 addr add "${TUN_TB_IP6}/64" dev tailscale0 nodad 2>/dev/null || true
    echo "[tailscale] tunnel up"
}
setup_tailscale

# ══════════════════════════════════════════════════════════════════════════════
# NetBird setup (management coordinator)
# ══════════════════════════════════════════════════════════════════════════════
setup_netbird() {
    if ! command -v netbird >/dev/null 2>&1; then
        echo "[netbird] SKIP: 'netbird' not found"; NB_AVAILABLE=false; return
    fi
    echo "[netbird] creating namespaces and veth pair"
    make_pair "$NS_BA" "$NS_BB" "$VBA" "$VBB" "$VBA_IP" "$VBB_IP"
    echo "[netbird] SKIP: local management service not running"; NB_AVAILABLE=false
}
setup_netbird

# ══════════════════════════════════════════════════════════════════════════════
# Sweep
# ══════════════════════════════════════════════════════════════════════════════
LOSS_RATES="${LOSS_RATES:-0 5 10}"

echo ""
echo "=========================================================="
echo "  iperf3 TCP & UDP throughput + ping latency/loss under netem"
echo "  dual-stack IPv4 & IPv6 with CPU telemetry from /proc/stat"
echo "  ping -c ${PING_COUNT} -i ${PING_INTERVAL}; iperf3 -t 8; netem: loss X% delay 5ms (symmetric)"
echo "  UDP rate: ${UDP_RATE:-10G}, len: ${UDP_LEN:-1400}"
echo "=========================================================="

for LOSS in $LOSS_RATES; do
    echo ""
    echo "[netem] loss=${LOSS}% delay=5ms on all active pairs"
    apply_netem "$NS_YA" "$NS_YB" "$VYA" "$VYB" "$LOSS"
    [ "$WG_AVAILABLE"   = true ] && apply_netem "$NS_WA" "$NS_WB" "$VWA" "$VWB" "$LOSS"
    [ "$AWG_AVAILABLE"  = true ] && apply_netem "$NS_AA" "$NS_AB" "$VAA" "$VAB" "$LOSS"
    [ "$OVPN_AVAILABLE" = true ] && apply_netem "$NS_OA" "$NS_OB" "$VOA" "$VOB" "$LOSS"
    [ "$N2N_AVAILABLE"  = true ] && apply_netem "$NS_NA" "$NS_NB" "$VNA" "$VNB" "$LOSS"
    [ "$ZT_AVAILABLE"   = true ] && apply_netem "$NS_ZA" "$NS_ZB" "$VZA" "$VZB" "$LOSS"
    [ "$TS_AVAILABLE"   = true ] && apply_netem "$NS_TA" "$NS_TB" "$VTA" "$VTB" "$LOSS"
    [ "$NB_AVAILABLE"   = true ] && apply_netem "$NS_BA" "$NS_BB" "$VBA" "$VBB" "$LOSS"

    # yip (IPv4 & IPv6)
    read -r Y_LOSS Y_RTT <<< "$(measure_ping "$NS_YB" "$TUN_YA_IP")"
    Y_TCP="$(measure_iperf "$NS_YA" "$TUN_YA_IP" "$NS_YB")"
    read -r Y_UDP_MBPS Y_UDP_LOSS Y_CPU Y_EFF <<< "$(measure_iperf_udp "$NS_YA" "$TUN_YA_IP" "$NS_YB")"
    Y_RAM="$(get_ns_ram_mb "$NS_YA")"
    Y_RAM_EFF="$(calc_ram_efficiency "$Y_RAM" "$Y_UDP_MBPS")"
    echo "[yip] [ipv4] ping_loss=${Y_LOSS}% rtt=${Y_RTT}ms tcp=${Y_TCP}Mbit/s udp=${Y_UDP_MBPS}Mbit/s udp_loss=${Y_UDP_LOSS}% cpu=${Y_CPU}% eff=${Y_EFF} ram=${Y_RAM}MB ram_eff=${Y_RAM_EFF}"

    read -r Y6_LOSS Y6_RTT <<< "$(measure_ping "$NS_YB" "$TUN_YA_IP6")"
    Y6_TCP="$(measure_iperf "$NS_YA" "$TUN_YA_IP6" "$NS_YB")"
    read -r Y6_UDP_MBPS Y6_UDP_LOSS Y6_CPU Y6_EFF <<< "$(measure_iperf_udp "$NS_YA" "$TUN_YA_IP6" "$NS_YB")"
    Y6_RAM="$(get_ns_ram_mb "$NS_YA")"
    Y6_RAM_EFF="$(calc_ram_efficiency "$Y6_RAM" "$Y6_UDP_MBPS")"
    echo "[yip] [ipv6] ping_loss=${Y6_LOSS}% rtt=${Y6_RTT}ms tcp=${Y6_TCP}Mbit/s udp=${Y6_UDP_MBPS}Mbit/s udp_loss=${Y6_UDP_LOSS}% cpu=${Y6_CPU}% eff=${Y6_EFF} ram=${Y6_RAM}MB ram_eff=${Y6_RAM_EFF}"

    # WireGuard (IPv4 & IPv6)
    W_LOSS="N/A"; W_RTT="N/A"; W_TCP="N/A"; W_UDP_MBPS="N/A"; W_UDP_LOSS="N/A"; W_CPU="N/A"; W_EFF="N/A"; W_RAM="N/A"; W_RAM_EFF="N/A"
    W6_LOSS="N/A"; W6_RTT="N/A"; W6_TCP="N/A"; W6_UDP_MBPS="N/A"; W6_UDP_LOSS="N/A"; W6_CPU="N/A"; W6_EFF="N/A"; W6_RAM="N/A"; W6_RAM_EFF="N/A"
    if [ "$WG_AVAILABLE" = true ]; then
        read -r W_LOSS W_RTT <<< "$(measure_ping "$NS_WB" "$TUN_WA_IP")"
        W_TCP="$(measure_iperf "$NS_WA" "$TUN_WA_IP" "$NS_WB")"
        read -r W_UDP_MBPS W_UDP_LOSS W_CPU W_EFF <<< "$(measure_iperf_udp "$NS_WA" "$TUN_WA_IP" "$NS_WB")"
        W_RAM="$(get_ns_ram_mb "$NS_WA")"
        W_RAM_EFF="$(calc_ram_efficiency "$W_RAM" "$W_UDP_MBPS")"
        echo "[wg] [ipv4] ping_loss=${W_LOSS}% rtt=${W_RTT}ms tcp=${W_TCP}Mbit/s udp=${W_UDP_MBPS}Mbit/s udp_loss=${W_UDP_LOSS}% cpu=${W_CPU}% eff=${W_EFF} ram=${W_RAM}MB ram_eff=${W_RAM_EFF}"

        read -r W6_LOSS W6_RTT <<< "$(measure_ping "$NS_WB" "$TUN_WA_IP6")"
        W6_TCP="$(measure_iperf "$NS_WA" "$TUN_WA_IP6" "$NS_WB")"
        read -r W6_UDP_MBPS W6_UDP_LOSS W6_CPU W6_EFF <<< "$(measure_iperf_udp "$NS_WA" "$TUN_WA_IP6" "$NS_WB")"
        W6_RAM="$(get_ns_ram_mb "$NS_WA")"
        W6_RAM_EFF="$(calc_ram_efficiency "$W6_RAM" "$W6_UDP_MBPS")"
        echo "[wg] [ipv6] ping_loss=${W6_LOSS}% rtt=${W6_RTT}ms tcp=${W6_TCP}Mbit/s udp=${W6_UDP_MBPS}Mbit/s udp_loss=${W6_UDP_LOSS}% cpu=${W6_CPU}% eff=${W6_EFF} ram=${W6_RAM}MB ram_eff=${W6_RAM_EFF}"
    fi

    # AmneziaWG (IPv4 & IPv6)
    A_LOSS="N/A"; A_RTT="N/A"; A_TCP="N/A"; A_UDP_MBPS="N/A"; A_UDP_LOSS="N/A"; A_CPU="N/A"; A_EFF="N/A"; A_RAM="N/A"; A_RAM_EFF="N/A"
    A6_LOSS="N/A"; A6_RTT="N/A"; A6_TCP="N/A"; A6_UDP_MBPS="N/A"; A6_UDP_LOSS="N/A"; A6_CPU="N/A"; A6_EFF="N/A"; A6_RAM="N/A"; A6_RAM_EFF="N/A"
    if [ "$AWG_AVAILABLE" = true ]; then
        read -r A_LOSS A_RTT <<< "$(measure_ping "$NS_AB" "$TUN_AA_IP")"
        A_TCP="$(measure_iperf "$NS_AA" "$TUN_AA_IP" "$NS_AB")"
        read -r A_UDP_MBPS A_UDP_LOSS A_CPU A_EFF <<< "$(measure_iperf_udp "$NS_AA" "$TUN_AA_IP" "$NS_AB")"
        A_RAM="$(get_ns_ram_mb "$NS_AA")"
        A_RAM_EFF="$(calc_ram_efficiency "$A_RAM" "$A_UDP_MBPS")"
        echo "[awg] [ipv4] ping_loss=${A_LOSS}% rtt=${A_RTT}ms tcp=${A_TCP}Mbit/s udp=${A_UDP_MBPS}Mbit/s udp_loss=${A_UDP_LOSS}% cpu=${A_CPU}% eff=${A_EFF} ram=${A_RAM}MB ram_eff=${A_RAM_EFF}"

        read -r A6_LOSS A6_RTT <<< "$(measure_ping "$NS_AB" "$TUN_AA_IP6")"
        A6_TCP="$(measure_iperf "$NS_AA" "$TUN_AA_IP6" "$NS_AB")"
        read -r A6_UDP_MBPS A6_UDP_LOSS A6_CPU A6_EFF <<< "$(measure_iperf_udp "$NS_AA" "$TUN_AA_IP6" "$NS_AB")"
        A6_RAM="$(get_ns_ram_mb "$NS_AA")"
        A6_RAM_EFF="$(calc_ram_efficiency "$A6_RAM" "$A6_UDP_MBPS")"
        echo "[awg] [ipv6] ping_loss=${A6_LOSS}% rtt=${A6_RTT}ms tcp=${A6_TCP}Mbit/s udp=${A6_UDP_MBPS}Mbit/s udp_loss=${A6_UDP_LOSS}% cpu=${A6_CPU}% eff=${A6_EFF} ram=${A6_RAM}MB ram_eff=${A6_RAM_EFF}"
    fi

    # OpenVPN (IPv4 & IPv6)
    O_LOSS="N/A"; O_RTT="N/A"; O_TCP="N/A"; O_UDP_MBPS="N/A"; O_UDP_LOSS="N/A"; O_CPU="N/A"; O_EFF="N/A"; O_RAM="N/A"; O_RAM_EFF="N/A"
    O6_LOSS="N/A"; O6_RTT="N/A"; O6_TCP="N/A"; O6_UDP_MBPS="N/A"; O6_UDP_LOSS="N/A"; O6_CPU="N/A"; O6_EFF="N/A"; O6_RAM="N/A"; O6_RAM_EFF="N/A"
    if [ "$OVPN_AVAILABLE" = true ]; then
        read -r O_LOSS O_RTT <<< "$(measure_ping "$NS_OB" "$TUN_OA_IP")"
        O_TCP="$(measure_iperf "$NS_OA" "$TUN_OA_IP" "$NS_OB")"
        read -r O_UDP_MBPS O_UDP_LOSS O_CPU O_EFF <<< "$(measure_iperf_udp "$NS_OA" "$TUN_OA_IP" "$NS_OB")"
        O_RAM="$(get_ns_ram_mb "$NS_OA")"
        O_RAM_EFF="$(calc_ram_efficiency "$O_RAM" "$O_UDP_MBPS")"
        echo "[ovpn] [ipv4] ping_loss=${O_LOSS}% rtt=${O_RTT}ms tcp=${O_TCP}Mbit/s udp=${O_UDP_MBPS}Mbit/s udp_loss=${O_UDP_LOSS}% cpu=${O_CPU}% eff=${O_EFF} ram=${O_RAM}MB ram_eff=${O_RAM_EFF}"

        read -r O6_LOSS O6_RTT <<< "$(measure_ping "$NS_OB" "$TUN_OA_IP6")"
        O6_TCP="$(measure_iperf "$NS_OA" "$TUN_OA_IP6" "$NS_OB")"
        read -r O6_UDP_MBPS O6_UDP_LOSS O6_CPU O6_EFF <<< "$(measure_iperf_udp "$NS_OA" "$TUN_OA_IP6" "$NS_OB")"
        O6_RAM="$(get_ns_ram_mb "$NS_OA")"
        O6_RAM_EFF="$(calc_ram_efficiency "$O6_RAM" "$O6_UDP_MBPS")"
        echo "[ovpn] [ipv6] ping_loss=${O6_LOSS}% rtt=${O6_RTT}ms tcp=${O6_TCP}Mbit/s udp=${O6_UDP_MBPS}Mbit/s udp_loss=${O6_UDP_LOSS}% cpu=${O6_CPU}% eff=${O6_EFF} ram=${O6_RAM}MB ram_eff=${O6_RAM_EFF}"
    fi

    # n2n (IPv4 & IPv6)
    N_LOSS="N/A"; N_RTT="N/A"; N_TCP="N/A"; N_UDP_MBPS="N/A"; N_UDP_LOSS="N/A"; N_CPU="N/A"; N_EFF="N/A"; N_RAM="N/A"; N_RAM_EFF="N/A"
    N6_LOSS="N/A"; N6_RTT="N/A"; N6_TCP="N/A"; N6_UDP_MBPS="N/A"; N6_UDP_LOSS="N/A"; N6_CPU="N/A"; N6_EFF="N/A"; N6_RAM="N/A"; N6_RAM_EFF="N/A"
    if [ "$N2N_AVAILABLE" = true ]; then
        read -r N_LOSS N_RTT <<< "$(measure_ping "$NS_NB" "$OVL_NA_IP")"
        N_TCP="$(measure_iperf "$NS_NA" "$OVL_NA_IP" "$NS_NB")"
        read -r N_UDP_MBPS N_UDP_LOSS N_CPU N_EFF <<< "$(measure_iperf_udp "$NS_NA" "$OVL_NA_IP" "$NS_NB")"
        N_RAM="$(get_ns_ram_mb "$NS_NA")"
        N_RAM_EFF="$(calc_ram_efficiency "$N_RAM" "$N_UDP_MBPS")"
        echo "[n2n] [ipv4] ping_loss=${N_LOSS}% rtt=${N_RTT}ms tcp=${N_TCP}Mbit/s udp=${N_UDP_MBPS}Mbit/s udp_loss=${N_UDP_LOSS}% cpu=${N_CPU}% eff=${N_EFF} ram=${N_RAM}MB ram_eff=${N_RAM_EFF}"

        read -r N6_LOSS N6_RTT <<< "$(measure_ping "$NS_NB" "$OVL_NA_IP6")"
        N6_TCP="$(measure_iperf "$NS_NA" "$OVL_NA_IP6" "$NS_NB")"
        read -r N6_UDP_MBPS N6_UDP_LOSS N6_CPU N6_EFF <<< "$(measure_iperf_udp "$NS_NA" "$OVL_NA_IP6" "$NS_NB")"
        N6_RAM="$(get_ns_ram_mb "$NS_NA")"
        N6_RAM_EFF="$(calc_ram_efficiency "$N6_RAM" "$N6_UDP_MBPS")"
        echo "[n2n] [ipv6] ping_loss=${N6_LOSS}% rtt=${N6_RTT}ms tcp=${N6_TCP}Mbit/s udp=${N6_UDP_MBPS}Mbit/s udp_loss=${N6_UDP_LOSS}% cpu=${N6_CPU}% eff=${N6_EFF} ram=${N6_RAM}MB ram_eff=${N6_RAM_EFF}"
    fi

    # ZeroTier (IPv4 & IPv6)
    Z_LOSS="N/A"; Z_RTT="N/A"; Z_TCP="N/A"; Z_UDP_MBPS="N/A"; Z_UDP_LOSS="N/A"; Z_CPU="N/A"; Z_EFF="N/A"; Z_RAM="N/A"; Z_RAM_EFF="N/A"
    Z6_LOSS="N/A"; Z6_RTT="N/A"; Z6_TCP="N/A"; Z6_UDP_MBPS="N/A"; Z6_UDP_LOSS="N/A"; Z6_CPU="N/A"; Z6_EFF="N/A"; Z6_RAM="N/A"; Z6_RAM_EFF="N/A"
    if [ "$ZT_AVAILABLE" = true ]; then
        read -r Z_LOSS Z_RTT <<< "$(measure_ping "$NS_ZB" "$TUN_ZA_IP")"
        Z_TCP="$(measure_iperf "$NS_ZA" "$TUN_ZA_IP" "$NS_ZB")"
        read -r Z_UDP_MBPS Z_UDP_LOSS Z_CPU Z_EFF <<< "$(measure_iperf_udp "$NS_ZA" "$TUN_ZA_IP" "$NS_ZB")"
        Z_RAM="$(get_ns_ram_mb "$NS_ZA")"
        Z_RAM_EFF="$(calc_ram_efficiency "$Z_RAM" "$Z_UDP_MBPS")"
        echo "[zerotier] [ipv4] ping_loss=${Z_LOSS}% rtt=${Z_RTT}ms tcp=${Z_TCP}Mbit/s udp=${Z_UDP_MBPS}Mbit/s udp_loss=${Z_UDP_LOSS}% cpu=${Z_CPU}% eff=${Z_EFF} ram=${Z_RAM}MB ram_eff=${Z_RAM_EFF}"

        read -r Z6_LOSS Z6_RTT <<< "$(measure_ping "$NS_ZB" "$TUN_ZA_IP6")"
        Z6_TCP="$(measure_iperf "$NS_ZA" "$TUN_ZA_IP6" "$NS_ZB")"
        read -r Z6_UDP_MBPS Z6_UDP_LOSS Z6_CPU Z6_EFF <<< "$(measure_iperf_udp "$NS_ZA" "$TUN_ZA_IP6" "$NS_ZB")"
        Z6_RAM="$(get_ns_ram_mb "$NS_ZA")"
        Z6_RAM_EFF="$(calc_ram_efficiency "$Z6_RAM" "$Z6_UDP_MBPS")"
        echo "[zerotier] [ipv6] ping_loss=${Z6_LOSS}% rtt=${Z6_RTT}ms tcp=${Z6_TCP}Mbit/s udp=${Z6_UDP_MBPS}Mbit/s udp_loss=${Z6_UDP_LOSS}% cpu=${Z6_CPU}% eff=${Z6_EFF} ram=${Z6_RAM}MB ram_eff=${Z6_RAM_EFF}"
    fi

    # Tailscale (IPv4 & IPv6)
    T_LOSS="N/A"; T_RTT="N/A"; T_TCP="N/A"; T_UDP_MBPS="N/A"; T_UDP_LOSS="N/A"; T_CPU="N/A"; T_EFF="N/A"; T_RAM="N/A"; T_RAM_EFF="N/A"
    T6_LOSS="N/A"; T6_RTT="N/A"; T6_TCP="N/A"; T6_UDP_MBPS="N/A"; T6_UDP_LOSS="N/A"; T6_CPU="N/A"; T6_EFF="N/A"; T6_RAM="N/A"; T6_RAM_EFF="N/A"
    if [ "$TS_AVAILABLE" = true ]; then
        read -r T_LOSS T_RTT <<< "$(measure_ping "$NS_TB" "$TUN_TA_IP")"
        T_TCP="$(measure_iperf "$NS_TA" "$TUN_TA_IP" "$NS_TB")"
        read -r T_UDP_MBPS T_UDP_LOSS T_CPU T_EFF <<< "$(measure_iperf_udp "$NS_TA" "$TUN_TA_IP" "$NS_TB")"
        T_RAM="$(get_ns_ram_mb "$NS_TA")"
        T_RAM_EFF="$(calc_ram_efficiency "$T_RAM" "$T_UDP_MBPS")"
        echo "[tailscale] [ipv4] ping_loss=${T_LOSS}% rtt=${T_RTT}ms tcp=${T_TCP}Mbit/s udp=${T_UDP_MBPS}Mbit/s udp_loss=${T_UDP_LOSS}% cpu=${T_CPU}% eff=${T_EFF} ram=${T_RAM}MB ram_eff=${T_RAM_EFF}"

        read -r T6_LOSS T6_RTT <<< "$(measure_ping "$NS_TB" "$TUN_TA_IP6")"
        T6_TCP="$(measure_iperf "$NS_TA" "$TUN_TA_IP6" "$NS_TB")"
        read -r T6_UDP_MBPS T6_UDP_LOSS T6_CPU T6_EFF <<< "$(measure_iperf_udp "$NS_TA" "$TUN_TA_IP6" "$NS_TB")"
        T6_RAM="$(get_ns_ram_mb "$NS_TA")"
        T6_RAM_EFF="$(calc_ram_efficiency "$T6_RAM" "$T6_UDP_MBPS")"
        echo "[tailscale] [ipv6] ping_loss=${T6_LOSS}% rtt=${T6_RTT}ms tcp=${T6_TCP}Mbit/s udp=${T6_UDP_MBPS}Mbit/s udp_loss=${T6_UDP_LOSS}% cpu=${T6_CPU}% eff=${T6_EFF} ram=${T6_RAM}MB ram_eff=${T6_RAM_EFF}"
    fi

    # NetBird (IPv4 & IPv6)
    B_LOSS="N/A"; B_RTT="N/A"; B_TCP="N/A"; B_UDP_MBPS="N/A"; B_UDP_LOSS="N/A"; B_CPU="N/A"; B_EFF="N/A"; B_RAM="N/A"; B_RAM_EFF="N/A"
    B6_LOSS="N/A"; B6_RTT="N/A"; B6_TCP="N/A"; B6_UDP_MBPS="N/A"; B6_UDP_LOSS="N/A"; B6_CPU="N/A"; B6_EFF="N/A"; B6_RAM="N/A"; B6_RAM_EFF="N/A"
    if [ "$NB_AVAILABLE" = true ]; then
        read -r B_LOSS B_RTT <<< "$(measure_ping "$NS_BB" "$TUN_BA_IP")"
        B_TCP="$(measure_iperf "$NS_BA" "$TUN_BA_IP" "$NS_BB")"
        read -r B_UDP_MBPS B_UDP_LOSS B_CPU B_EFF <<< "$(measure_iperf_udp "$NS_BA" "$TUN_BA_IP" "$NS_BB")"
        B_RAM="$(get_ns_ram_mb "$NS_BA")"
        B_RAM_EFF="$(calc_ram_efficiency "$B_RAM" "$B_UDP_MBPS")"
        echo "[netbird] [ipv4] ping_loss=${B_LOSS}% rtt=${B_RTT}ms tcp=${B_TCP}Mbit/s udp=${B_UDP_MBPS}Mbit/s udp_loss=${B_UDP_LOSS}% cpu=${B_CPU}% eff=${B_EFF} ram=${B_RAM}MB ram_eff=${B_RAM_EFF}"

        read -r B6_LOSS B6_RTT <<< "$(measure_ping "$NS_BB" "$TUN_BA_IP6")"
        B6_TCP="$(measure_iperf "$NS_BA" "$TUN_BA_IP6" "$NS_BB")"
        read -r B6_UDP_MBPS B6_UDP_LOSS B6_CPU B6_EFF <<< "$(measure_iperf_udp "$NS_BA" "$TUN_BA_IP6" "$NS_BB")"
        B6_RAM="$(get_ns_ram_mb "$NS_BA")"
        B6_RAM_EFF="$(calc_ram_efficiency "$B6_RAM" "$B6_UDP_MBPS")"
        echo "[netbird] [ipv6] ping_loss=${B6_LOSS}% rtt=${B6_RTT}ms tcp=${B6_TCP}Mbit/s udp=${B6_UDP_MBPS}Mbit/s udp_loss=${B6_UDP_LOSS}% cpu=${B6_CPU}% eff=${B6_EFF} ram=${B6_RAM}MB ram_eff=${B6_RAM_EFF}"
    fi

    # ── emit per-loss-rate tables ─────────────────────────────────────────────
    YIP_LABEL="yip"
    if [ "$YIP_SHARDS" -gt 1 ] 2>/dev/null; then
        YIP_LABEL="yip(s=$YIP_SHARDS)"
    fi

    echo ""
    echo "  --- IPv4 loss=${LOSS}% ---"
    echo "  | contender | eff_loss% | rtt_ms | tcp_Mbit/s | udp_Mbit/s | udp_loss% | cpu% | cpu_eff(%/Gbps) | ram_MB | ram_eff(MB/Gbps) |"
    echo "  |-----------|-----------|--------|------------|------------|-----------|------|-----------------|--------|------------------|"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "$YIP_LABEL" "$Y_LOSS" "$Y_RTT" "$Y_TCP" "$Y_UDP_MBPS" "$Y_UDP_LOSS" "$Y_CPU" "$Y_EFF" "$Y_RAM" "$Y_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "wireguard" "$W_LOSS" "$W_RTT" "$W_TCP" "$W_UDP_MBPS" "$W_UDP_LOSS" "$W_CPU" "$W_EFF" "$W_RAM" "$W_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "amneziawg" "$A_LOSS" "$A_RTT" "$A_TCP" "$A_UDP_MBPS" "$A_UDP_LOSS" "$A_CPU" "$A_EFF" "$A_RAM" "$A_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "openvpn"   "$O_LOSS" "$O_RTT" "$O_TCP" "$O_UDP_MBPS" "$O_UDP_LOSS" "$O_CPU" "$O_EFF" "$O_RAM" "$O_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "n2n"       "$N_LOSS" "$N_RTT" "$N_TCP" "$N_UDP_MBPS" "$N_UDP_LOSS" "$N_CPU" "$N_EFF" "$N_RAM" "$N_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "zerotier"  "$Z_LOSS" "$Z_RTT" "$Z_TCP" "$Z_UDP_MBPS" "$Z_UDP_LOSS" "$Z_CPU" "$Z_EFF" "$Z_RAM" "$Z_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "tailscale" "$T_LOSS" "$T_RTT" "$T_TCP" "$T_UDP_MBPS" "$T_UDP_LOSS" "$T_CPU" "$T_EFF" "$T_RAM" "$T_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "netbird"   "$B_LOSS" "$B_RTT" "$B_TCP" "$B_UDP_MBPS" "$B_UDP_LOSS" "$B_CPU" "$B_EFF" "$B_RAM" "$B_RAM_EFF"

    echo ""
    echo "  --- IPv6 loss=${LOSS}% ---"
    echo "  | contender | eff_loss% | rtt_ms | tcp_Mbit/s | udp_Mbit/s | udp_loss% | cpu% | cpu_eff(%/Gbps) | ram_MB | ram_eff(MB/Gbps) |"
    echo "  |-----------|-----------|--------|------------|------------|-----------|------|-----------------|--------|------------------|"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "$YIP_LABEL" "$Y6_LOSS" "$Y6_RTT" "$Y6_TCP" "$Y6_UDP_MBPS" "$Y6_UDP_LOSS" "$Y6_CPU" "$Y6_EFF" "$Y6_RAM" "$Y6_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "wireguard" "$W6_LOSS" "$W6_RTT" "$W6_TCP" "$W6_UDP_MBPS" "$W6_UDP_LOSS" "$W6_CPU" "$W6_EFF" "$W6_RAM" "$W6_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "amneziawg" "$A6_LOSS" "$A6_RTT" "$A6_TCP" "$A6_UDP_MBPS" "$A6_UDP_LOSS" "$A6_CPU" "$A6_EFF" "$A6_RAM" "$A6_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "openvpn"   "$O6_LOSS" "$O6_RTT" "$O6_TCP" "$O6_UDP_MBPS" "$O6_UDP_LOSS" "$O6_CPU" "$O6_EFF" "$O6_RAM" "$O6_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "n2n"       "$N6_LOSS" "$N6_RTT" "$N6_TCP" "$N6_UDP_MBPS" "$N6_UDP_LOSS" "$N6_CPU" "$N6_EFF" "$N6_RAM" "$N6_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "zerotier"  "$Z6_LOSS" "$Z6_RTT" "$Z6_TCP" "$Z6_UDP_MBPS" "$Z6_UDP_LOSS" "$Z6_CPU" "$Z6_EFF" "$Z6_RAM" "$Z6_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "tailscale" "$T6_LOSS" "$T6_RTT" "$T6_TCP" "$T6_UDP_MBPS" "$T6_UDP_LOSS" "$T6_CPU" "$T6_EFF" "$T6_RAM" "$T6_RAM_EFF"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "netbird"   "$B6_LOSS" "$B6_RTT" "$B6_TCP" "$B6_UDP_MBPS" "$B6_UDP_LOSS" "$B6_CPU" "$B6_EFF" "$B6_RAM" "$B6_RAM_EFF"
done

echo ""
echo "[done] iperf compare sweep complete"
[ "$WG_AVAILABLE"   = false ] && echo "[note] WireGuard skipped (module/CLI absent)"
[ "$AWG_AVAILABLE"  = false ] && echo "[note] AmneziaWG skipped (module/CLI absent)"
[ "$OVPN_AVAILABLE" = false ] && echo "[note] OpenVPN skipped (binary absent or setup failed)"
[ "$N2N_AVAILABLE"  = false ] && echo "[note] n2n skipped (binary absent or setup failed)"
[ "$ZT_AVAILABLE"   = false ] && echo "[note] ZeroTier skipped (binary absent or setup failed)"
[ "$TS_AVAILABLE"   = false ] && echo "[note] Tailscale skipped (binary absent or setup failed)"
[ "$NB_AVAILABLE"   = false ] && echo "[note] NetBird skipped (binary absent or setup failed)"
true
