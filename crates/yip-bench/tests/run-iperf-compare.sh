#!/usr/bin/env bash
# run-iperf-compare.sh — iperf3 TCP & UDP throughput + ping latency/loss under netem,
# across contemporary tunnels and mesh overlays in dual-stack IPv4 and IPv6:
#   yip, WireGuard, WireGuard-Go, AmneziaWG, OpenVPN, n2n, ZeroTier, Tailscale, NetBird.
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

# Disable IPv6 DAD and configure high-BDP socket buffers in current namespace
sysctl -qw net.ipv6.conf.all.accept_dad=0 \
    net.ipv6.conf.default.accept_dad=0 \
    net.ipv6.conf.lo.accept_dad=0 \
    net.core.rmem_max=67108864 \
    net.core.wmem_max=67108864 \
    net.ipv4.tcp_rmem="4096 87380 67108864" \
    net.ipv4.tcp_wmem="4096 65536 67108864" \
    net.ipv4.tcp_reordering=20 2>/dev/null || true

# Pre-sweep: kill any orphaned contender daemons from previous runs
killall -9 netbird netbird-mgmt netbird-signal edge supernode 2>/dev/null || true

# ── binary ────────────────────────────────────────────────────────────────────
if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    YIPD="$1"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
    if [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" bash -lc "cargo build --release -p yipd --quiet --manifest-path '$WORKSPACE_ROOT/Cargo.toml'" 2>/dev/null || true
    elif command -v cargo >/dev/null 2>&1; then
        cargo build --release -p yipd --quiet --manifest-path "$WORKSPACE_ROOT/Cargo.toml" 2>/dev/null || true
    fi
    if [ ! -x "$WORKSPACE_ROOT/target/release/yipd" ]; then
        echo "[error] target/release/yipd does not exist and cargo build failed" >&2
        exit 1
    fi
    YIPD="$WORKSPACE_ROOT/target/release/yipd"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

TMPDIR_TEST="$(mktemp -d /dev/shm/yip-iperf-compare.XXXXXX 2>/dev/null || mktemp -d /tmp/yip-iperf-compare.XXXXXX)"
chmod 777 "$TMPDIR_TEST"

contender_wanted() {
    local name="$1"
    if [ -z "${CONTENDERS:-}" ]; then
        return 0
    fi
    for c in $CONTENDERS; do
        if [ "$c" = "$name" ] || [ "$c" = "all" ]; then
            return 0
        fi
    done
    return 1
}

# ── yip ───────────────────────────────────────────────────────────────────────
NS_YA="ipfYA"; NS_YB="ipfYB"; VYA="ipfvYA"; VYB="ipfvYB"
VYA_IP="10.10.0.1"; VYB_IP="10.10.0.2"
TUN_YA_IP="10.11.0.1"; TUN_YB_IP="10.11.0.2"
TUN_YA_IP6="fd00:11::1"; TUN_YB_IP6="fd00:11::2"
YPORT_A="443"; YPORT_B="443"; TUN_DEV="yip0"; YIP_MTU="${YIP_MTU:-1420}"; YIP_SHARDS="${YIP_SHARDS:-1}"
DEFAULT_UDP_LEN=$((YIP_MTU - 48))
[ "$DEFAULT_UDP_LEN" -gt 1350 ] && DEFAULT_UDP_LEN=1350
UDP_LEN="${UDP_LEN:-$DEFAULT_UDP_LEN}"
UDP_RATE="${UDP_RATE:-2G}"
PID_YA=""; PID_YB=""

# ── WireGuard ─────────────────────────────────────────────────────────────────
NS_WA="ipfWA"; NS_WB="ipfWB"; VWA="ipfvWA"; VWB="ipfvWB"
VWA_IP="10.12.0.1"; VWB_IP="10.12.0.2"
TUN_WA_IP="10.13.0.1"; TUN_WB_IP="10.13.0.2"
TUN_WA_IP6="fd00:13::1"; TUN_WB_IP6="fd00:13::2"
WPORT_A="51860"; WPORT_B="51861"
WG_AVAILABLE=""

# ── WireGuard-Go ──────────────────────────────────────────────────────────────
NS_GGA="ipfGGA"; NS_GGB="ipfGGB"; VGGA="ipfvGGA"; VGGB="ipfvGGB"
VGGA_IP="10.26.0.1"; VGGB_IP="10.26.0.2"
TUN_GGA_IP="10.27.0.1"; TUN_GGB_IP="10.27.0.2"
TUN_GGA_IP6="fd00:27::1"; TUN_GGB_IP6="fd00:27::2"
GGPORT_A="51880"; GGPORT_B="51881"
WGGO_AVAILABLE=""
PID_GGA=""; PID_GGB=""

# ── OpenVPN ───────────────────────────────────────────────────────────────────
NS_OA="ipfOA"; NS_OB="ipfOB"; VOA="ipfvOA"; VOB="ipfvOB"
VOA_IP="10.14.0.1"; VOB_IP="10.14.0.2"
TUN_OA_IP="10.15.0.1"; TUN_OB_IP="10.15.0.2"
TUN_OA_IP6="fd00:15::1"; TUN_OB_IP6="fd00:15::2"
OVPN_AVAILABLE=""
PID_OA=""; PID_OB=""

# ── n2n ───────────────────────────────────────────────────────────────────────
NS_NA="ipfNA"; NS_NB="ipfNB"; VNA="ipfvNA"; VNB="ipfvNB"
VNA_IP="10.16.0.1"; VNB_IP="10.16.0.2"
OVL_NA_IP="10.17.0.1"; OVL_NB_IP="10.17.0.2"
OVL_NA_IP6="fd00:17::1"; OVL_NB_IP6="fd00:17::2"
N2N_PORT="7654"
N2N_AVAILABLE=""
PID_N2N_SN=""; PID_N2N_EA=""; PID_N2N_EB=""

# ── AmneziaWG ─────────────────────────────────────────────────────────────────
NS_AA="ipfAA"; NS_AB="ipfAB"; VAA="ipfvAA"; VAB="ipfvAB"
VAA_IP="10.18.0.1"; VAB_IP="10.18.0.2"
TUN_AA_IP="10.19.0.1"; TUN_AB_IP="10.19.0.2"
TUN_AA_IP6="fd00:19::1"; TUN_AB_IP6="fd00:19::2"
APORT_A="51870"; APORT_B="51871"
AWG_AVAILABLE=""
PID_AA=""; PID_AB=""

# ── ZeroTier ──────────────────────────────────────────────────────────────────
NS_ZA="ipfZA"; NS_ZB="ipfZB"; VZA="ipfvZA"; VZB="ipfvZB"
VZA_IP="10.20.0.1"; VZB_IP="10.20.0.2"
TUN_ZA_IP="10.21.0.1"; TUN_ZB_IP="10.21.0.2"
TUN_ZA_IP6="fd00:21::1"; TUN_ZB_IP6="fd00:21::2"
ZT_AVAILABLE=""
PID_ZT_A=""; PID_ZT_B=""

# ── Tailscale ─────────────────────────────────────────────────────────────────
NS_TA="ipfTA"; NS_TB="ipfTB"; VTA="ipfvTA"; VTB="ipfvTB"
VTA_IP="10.22.0.1"; VTB_IP="10.22.0.2"
TUN_TA_IP="10.23.0.1"; TUN_TB_IP="10.23.0.2"
TUN_TA_IP6="fd00:23::1"; TUN_TB_IP6="fd00:23::2"
TS_AVAILABLE=""
PID_TS_HS=""; PID_TS_DA=""; PID_TS_DB=""

# ── NetBird ───────────────────────────────────────────────────────────────────
NS_BA="ipfBA"; NS_BB="ipfBB"; VBA="ipfvBA"; VBB="ipfvBB"
VBA_IP="10.24.0.1"; VBB_IP="10.24.0.2"
TUN_BA_IP="10.25.0.1"; TUN_BB_IP="10.25.0.2"
TUN_BA_IP6="fd00:25::1"; TUN_BB_IP6="fd00:25::2"
NB_AVAILABLE=""
PID_NB_SIG=""; PID_NB_MGMT=""; PID_NB_SA=""; PID_NB_SB=""

# ── lifecycle and performance thresholds ──────────────────────────────────────
CONTENDER_ISOLATION="${CONTENDER_ISOLATION:-true}"
ASSERT_THRESHOLDS="${ASSERT_THRESHOLDS:-false}"

THRESH_YIP_TCP_MIN_MBPS_0="${THRESH_YIP_TCP_MIN_MBPS_0:-1000}"
THRESH_YIP_UDP_MIN_MBPS_0="${THRESH_YIP_UDP_MIN_MBPS_0:-1000}"
THRESH_YIP_PING_MAX_LOSS_0="${THRESH_YIP_PING_MAX_LOSS_0:-1.0}"

THRESH_YIP_TCP_MIN_MBPS_5="${THRESH_YIP_TCP_MIN_MBPS_5:-500}"
THRESH_YIP_UDP_MIN_MBPS_5="${THRESH_YIP_UDP_MIN_MBPS_5:-800}"
THRESH_YIP_PING_MAX_LOSS_5="${THRESH_YIP_PING_MAX_LOSS_5:-8.0}"

THRESH_YIP_TCP_MIN_MBPS_10="${THRESH_YIP_TCP_MIN_MBPS_10:-100}"
THRESH_YIP_UDP_MIN_MBPS_10="${THRESH_YIP_UDP_MIN_MBPS_10:-500}"
THRESH_YIP_PING_MAX_LOSS_10="${THRESH_YIP_PING_MAX_LOSS_10:-15.0}"

THRESHOLD_FAILED=false
ISOLATION_FAILED=false
LAST_CHECK_PIDS=()

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
    if type stop_all_contenders >/dev/null 2>&1; then
        stop_all_contenders
    fi
    for ns in "$NS_YA" "$NS_YB" "$NS_WA" "$NS_WB" "$NS_GGA" "$NS_GGB" "$NS_OA" "$NS_OB" "$NS_NA" "$NS_NB" \
              "$NS_AA" "$NS_AB" "$NS_ZA" "$NS_ZB" "$NS_TA" "$NS_TB" "$NS_BA" "$NS_BB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT INT TERM HUP
# ── helper: two-netns veth pair ───────────────────────────────────────────────
make_pair() {
    local nsR="$1" nsS="$2" vR="$3" vS="$4" ipR="$5" ipS="$6"
    ip netns add "$nsR"; ip netns add "$nsS"
    for ns in "$nsR" "$nsS"; do
        ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_dad=0 \
            net.ipv6.conf.default.accept_dad=0 \
            net.ipv6.conf.lo.accept_dad=0 \
            net.core.rmem_max=67108864 \
            net.core.wmem_max=67108864 \
            net.ipv4.tcp_rmem="4096 87380 67108864" \
            net.ipv4.tcp_wmem="4096 65536 67108864" \
            net.ipv4.tcp_reordering=20 2>/dev/null || true
    done
    ip link add "$vR" type veth peer name "$vS"
    ip link set "$vR" netns "$nsR"; ip link set "$vS" netns "$nsS"
    ip netns exec "$nsR" ip addr add "$ipR/24" dev "$vR"
    ip netns exec "$nsR" ip link set dev "$vR" txqueuelen 10000 2>/dev/null || true
    ip netns exec "$nsR" ip link set "$vR" up; ip netns exec "$nsR" ip link set lo up
    ip netns exec "$nsS" ip addr add "$ipS/24" dev "$vS"
    ip netns exec "$nsS" ip link set dev "$vS" txqueuelen 10000 2>/dev/null || true
    ip netns exec "$nsS" ip link set "$vS" up; ip netns exec "$nsS" ip link set lo up
}

# ── helper: symmetric netem loss + 5ms delay ──────────────────────────────────
NETEM_DELAY="${NETEM_DELAY:-5ms}"
NETEM_LIMIT="${NETEM_LIMIT:-50000}"

apply_netem() {
    local nsR="$1" nsS="$2" vR="$3" vS="$4" loss="$5"
    if [ "$loss" -eq 0 ]; then
        if [ "$NETEM_DELAY" = "0" ] || [ "$NETEM_DELAY" = "0ms" ]; then
            ip netns exec "$nsR" tc qdisc del dev "$vR" root 2>/dev/null || true
            ip netns exec "$nsS" tc qdisc del dev "$vS" root 2>/dev/null || true
        else
            ip netns exec "$nsR" tc qdisc replace dev "$vR" root netem delay "$NETEM_DELAY" limit "$NETEM_LIMIT"
            ip netns exec "$nsS" tc qdisc replace dev "$vS" root netem delay "$NETEM_DELAY" limit "$NETEM_LIMIT"
        fi
        return
    fi
    ip netns exec "$nsR" tc qdisc replace dev "$vR" root netem loss "${loss}%" delay "$NETEM_DELAY" limit "$NETEM_LIMIT"
    ip netns exec "$nsS" tc qdisc replace dev "$vS" root netem loss "${loss}%" delay "$NETEM_DELAY" limit "$NETEM_LIMIT"
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
    if [ -z "$dst" ]; then
        echo "N/A N/A"
        return
    fi
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

TCP_CC="${TCP_CC:-cubic}"
IPERF_STREAMS="${IPERF_STREAMS:-1}"
YIP_FAILED=false

# ── helper: iperf3 TCP Mbit/s; server in <ns_srv> bound to <srv_ip>, client in
#    <ns_cli> -> <srv_ip>.  echo "<mbps> <loss>" ───────────────────────────────
measure_iperf() {
    local ns_srv="$1" srv_ip="$2" ns_cli="$3" streams="${4:-$IPERF_STREAMS}" v6_flag="" srv_pid out mbps loss retransmits bytes
    local TCP_CC="${TCP_CC:-cubic}"
    if [ -z "$srv_ip" ]; then
        echo "N/A N/A"
        return
    fi
    if [[ "$srv_ip" == *:* ]]; then
        v6_flag="-6"
    fi

    for attempt in 1 2 3; do
        ip netns exec "$ns_srv" killall -9 iperf3 2>/dev/null || true
        ip netns exec "$ns_cli" killall -9 iperf3 2>/dev/null || true
        for _ in $(seq 1 20); do
            if ! ip netns exec "$ns_srv" ss -tlpn 2>/dev/null | grep -q ":5201 "; then
                break
            fi
            sleep 0.05
        done
        ip netns exec "$ns_srv" iperf3 -s -B "$srv_ip" $v6_flag >/dev/null 2>&1 &
        srv_pid=$!
        for _ in $(seq 1 40); do
            if ip netns exec "$ns_srv" ss -tlpn 2>/dev/null | grep -q ":5201 " && kill -0 "$srv_pid" 2>/dev/null; then
                break
            fi
            sleep 0.05
        done
        out="$(timeout 45 ip netns exec "$ns_cli" iperf3 -c "$srv_ip" $v6_flag -C "$TCP_CC" -P "$streams" --connect-timeout 20000 -t "${IPERF_DURATION:-8}" -J 2>/dev/null || true)"
        kill -9 "$srv_pid" 2>/dev/null || true
        wait "$srv_pid" 2>/dev/null || true
        ip netns exec "$ns_srv" killall -9 iperf3 2>/dev/null || true
        ip netns exec "$ns_cli" killall -9 iperf3 2>/dev/null || true

        if [ -n "$out" ]; then
            if command -v jq >/dev/null 2>&1; then
                mbps="$(echo "$out" | jq -r '.end.sum_received.bits_per_second // .end.sum_sent.bits_per_second // empty' 2>/dev/null || true)"
                retransmits="$(echo "$out" | jq -r '.end.sum_sent.retransmits // 0' 2>/dev/null || true)"
                bytes="$(echo "$out" | jq -r '.end.sum_sent.bytes // 0' 2>/dev/null || true)"
            else
                mbps="$(echo "$out" | grep -oP '"bits_per_second":\s*[0-9.]+' | tail -1 | grep -oP '[0-9.]+' || true)"
                retransmits="$(echo "$out" | grep -oP '"retransmits":\s*[0-9]+' | head -1 | grep -oP '[0-9]+' || true)"
                bytes="$(echo "$out" | grep -oP '"bytes":\s*[0-9]+' | head -1 | grep -oP '[0-9]+' || true)"
            fi
            if [ -n "$mbps" ] && [ "$mbps" != "null" ] && [ "$(awk "BEGIN {print ($mbps > 0)}")" = "1" ]; then
                mbps="$(awk "BEGIN {printf \"%.1f\", $mbps / 1000000}")"
                if [ -n "$retransmits" ] && [ "$retransmits" != "null" ] && [ -n "$bytes" ] && [ "$bytes" != "null" ]; then
                    loss="$(awk -v r="${retransmits:-0}" -v b="${bytes:-0}" 'BEGIN { segs = b / 1400.0; if (segs + r > 0) printf "%.1f", (r / (segs + r)) * 100.0; else printf "0.0" }')"
                else
                    loss="0.0"
                fi
                echo "$mbps $loss"
                return
            fi
        fi
        sleep 0.5
    done

    echo "0.0 100.0"
}
measure_iperf_v6() { measure_iperf "$@"; }

# ── helper: iperf3 UDP Mbit/s, loss %, CPU % and CPU efficiency; server in <ns_srv> bound to <srv_ip>,
#    client in <ns_cli> -> <srv_ip>. echo "<mbps> <loss_pct> <cpu_pct> <cpu_eff>" ───────────
measure_iperf_udp() {
    local ns_srv="$1" srv_ip="$2" ns_cli="$3" v6_flag="" srv_pid out mbps loss cpu_pct cpu_eff
    if [ -z "$srv_ip" ]; then
        echo "N/A N/A N/A N/A"
        return
    fi
    if [[ "$srv_ip" == *:* ]]; then
        v6_flag="-6"
    fi

    for attempt in 1 2 3; do
        ip netns exec "$ns_srv" killall -9 iperf3 2>/dev/null || true
        ip netns exec "$ns_cli" killall -9 iperf3 2>/dev/null || true
        for _ in $(seq 1 20); do
            if ! ip netns exec "$ns_srv" ss -tlpn 2>/dev/null | grep -q ":5201 "; then
                break
            fi
            sleep 0.05
        done
        ip netns exec "$ns_srv" iperf3 -s -B "$srv_ip" $v6_flag >/dev/null 2>&1 &
        srv_pid=$!
        for _ in $(seq 1 40); do
            if ip netns exec "$ns_srv" ss -tlpn 2>/dev/null | grep -q ":5201 " && kill -0 "$srv_pid" 2>/dev/null; then
                break
            fi
            sleep 0.05
        done
        sample_cpu_start
        out="$(timeout 45 ip netns exec "$ns_cli" iperf3 -c "$srv_ip" $v6_flag -u \
            -b "$UDP_RATE" -l "$UDP_LEN" --connect-timeout 20000 -t "${IPERF_DURATION:-8}" -J 2>/dev/null || true)"
        read -r cpu_pct _ <<< "$(sample_cpu_end)"
        kill -9 "$srv_pid" 2>/dev/null || true
        wait "$srv_pid" 2>/dev/null || true
        ip netns exec "$ns_srv" killall -9 iperf3 2>/dev/null || true
        ip netns exec "$ns_cli" killall -9 iperf3 2>/dev/null || true

        if [ -n "$out" ]; then
            if command -v jq >/dev/null 2>&1; then
                mbps="$(echo "$out" | jq -r '.end.sum_received.bits_per_second // .end.sum.bits_per_second // empty' 2>/dev/null || true)"
                loss="$(echo "$out" | jq -r '.end.sum_received.lost_percent // .end.sum.lost_percent // empty' 2>/dev/null || true)"
            else
                mbps="$(echo "$out" | grep -oP '"bits_per_second":\s*[0-9.]+' | tail -1 | grep -oP '[0-9.]+' || true)"
                loss="$(echo "$out" | grep -oP '"lost_percent":\s*[0-9.]+' | tail -1 | grep -oP '[0-9.]+' || true)"
            fi
            if [ -n "$mbps" ] && [ "$mbps" != "null" ] && [ "$(awk "BEGIN {print ($mbps > 0)}")" = "1" ]; then
                mbps="$(awk "BEGIN {printf \"%.1f\", $mbps / 1000000}")"
                if [ -n "$loss" ] && [ "$loss" != "null" ]; then
                    loss="$(awk "BEGIN {printf \"%.1f\", $loss}")"
                else
                    loss="0.0"
                fi
                cpu_eff="$(calc_cpu_efficiency "$cpu_pct" "$mbps")"
                echo "$mbps $loss $cpu_pct $cpu_eff"
                return
            fi
        fi
        sleep 0.5
    done

    echo "N/A N/A N/A N/A"
}
measure_iperf_udp_v6() { measure_iperf_udp "$@"; }
# ── helper: threshold evaluation ──────────────────────────────────────────────
check_threshold() {
    local contender="$1" ip_ver="$2" metric="$3" val="$4" loss="$5"
    if [ "${ASSERT_THRESHOLDS:-false}" != "true" ]; then
        return 0
    fi
    if [ "$val" = "N/A" ] || [ -z "$val" ]; then
        return 0
    fi

    local c_upper; c_upper="$(echo "$contender" | tr '[:lower:]-' '[:upper:]_')"
    local m_upper; m_upper="$(echo "$metric" | tr '[:lower:]-' '[:upper:]_')"
    local v_upper; v_upper="$(echo "$ip_ver" | tr '[:lower:]' '[:upper:]')"

    local var_specific="THRESH_${c_upper}_${v_upper}_${m_upper}_${loss}"
    local var_general="THRESH_${c_upper}_${m_upper}_${loss}"

    local thresh=""
    if [ -n "${!var_specific:-}" ]; then
        thresh="${!var_specific}"
    elif [ -n "${!var_general:-}" ]; then
        thresh="${!var_general}"
    fi

    if [ -z "$thresh" ]; then
        return 0
    fi

    local failed=false
    if [[ "$metric" == *"max"* ]]; then
        if [ "$(awk "BEGIN {print ($val > $thresh)}")" = "1" ]; then
            failed=true
            echo "[fail] threshold violation: $contender [$ip_ver] $metric at loss=${loss}% was ${val}, expected <= ${thresh}"
        fi
    else
        if [ "$(awk "BEGIN {print ($val < $thresh)}")" = "1" ]; then
            failed=true
            echo "[fail] threshold violation: $contender [$ip_ver] $metric at loss=${loss}% was ${val}, expected >= ${thresh}"
        fi
    fi

    if [ "$failed" = true ]; then
        THRESHOLD_FAILED=true
    fi
}

# ── helper: single-contender dual-stack measurement ───────────────────────────
measure_contender() {
    local tag="$1" ns_srv="$2" ns_cli="$3" tun_ip4="$4" tun_ip6="$5" loss="$6"

    M_LOSS="N/A"; M_RTT="N/A"; M_TCP="N/A"; M_TCP_LOSS="N/A"; M_UDP_MBPS="N/A"; M_UDP_LOSS="N/A"; M_CPU="N/A"; M_EFF="N/A"; M_RAM="N/A"; M_RAM_EFF="N/A"
    M6_LOSS="N/A"; M6_RTT="N/A"; M6_TCP="N/A"; M6_TCP_LOSS="N/A"; M6_UDP_MBPS="N/A"; M6_UDP_LOSS="N/A"; M6_CPU="N/A"; M6_EFF="N/A"; M6_RAM="N/A"; M6_RAM_EFF="N/A"

    if [ -n "$tun_ip4" ] && [ "$tun_ip4" != "N/A" ]; then
        read -r M_LOSS M_RTT <<< "$(measure_ping "$ns_cli" "$tun_ip4")"
        read -r M_TCP M_TCP_LOSS <<< "$(measure_iperf "$ns_srv" "$tun_ip4" "$ns_cli")"
        read -r M_UDP_MBPS M_UDP_LOSS M_CPU M_EFF <<< "$(measure_iperf_udp "$ns_srv" "$tun_ip4" "$ns_cli")"
        M_RAM="$(get_ns_ram_mb "$ns_srv")"
        M_RAM_EFF="$(calc_ram_efficiency "$M_RAM" "$M_UDP_MBPS")"
        echo "[$tag] [ipv4] ping_loss=${M_LOSS}% rtt=${M_RTT}ms tcp=${M_TCP}Mbit/s tcp_loss=${M_TCP_LOSS}% udp=${M_UDP_MBPS}Mbit/s udp_loss=${M_UDP_LOSS}% cpu=${M_CPU}% eff=${M_EFF} ram=${M_RAM}MB ram_eff=${M_RAM_EFF}"
        check_threshold "$tag" "ipv4" "ping_max_loss" "$M_LOSS" "$loss"
        check_threshold "$tag" "ipv4" "tcp_min_mbps" "$M_TCP" "$loss"
        check_threshold "$tag" "ipv4" "udp_min_mbps" "$M_UDP_MBPS" "$loss"
        sleep 0.5
    fi

    if [ -n "$tun_ip6" ] && [ "$tun_ip6" != "N/A" ]; then
        read -r M6_LOSS M6_RTT <<< "$(measure_ping "$ns_cli" "$tun_ip6")"
        read -r M6_TCP M6_TCP_LOSS <<< "$(measure_iperf "$ns_srv" "$tun_ip6" "$ns_cli")"
        read -r M6_UDP_MBPS M6_UDP_LOSS M6_CPU M6_EFF <<< "$(measure_iperf_udp "$ns_srv" "$tun_ip6" "$ns_cli")"
        M6_RAM="$(get_ns_ram_mb "$ns_srv")"
        M6_RAM_EFF="$(calc_ram_efficiency "$M6_RAM" "$M6_UDP_MBPS")"
        echo "[$tag] [ipv6] ping_loss=${M6_LOSS}% rtt=${M6_RTT}ms tcp=${M6_TCP}Mbit/s tcp_loss=${M6_TCP_LOSS}% udp=${M6_UDP_MBPS}Mbit/s udp_loss=${M6_UDP_LOSS}% cpu=${M6_CPU}% eff=${M6_EFF} ram=${M6_RAM}MB ram_eff=${M6_RAM_EFF}"
        check_threshold "$tag" "ipv6" "ping_max_loss" "$M6_LOSS" "$loss"
        check_threshold "$tag" "ipv6" "tcp_min_mbps" "$M6_TCP" "$loss"
        check_threshold "$tag" "ipv6" "udp_min_mbps" "$M6_UDP_MBPS" "$loss"
        sleep 0.5
    fi
}

# ── helper: resource cleanup verification ─────────────────────────────────────
is_pid_alive() {
    local pid="$1"
    [ -z "$pid" ] && return 1
    [ "$pid" = "$$" ] && return 1
    wait "$pid" 2>/dev/null || true
    if [ ! -d "/proc/$pid" ]; then
        return 1
    fi
    local state
    state="$(awk '/^State:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true)"
    if [ -z "$state" ] || [ "$state" = "Z" ] || [ "$state" = "X" ]; then
        return 1
    fi
    return 0
}

is_test_pid() {
    local pid="$1"
    [ -z "$pid" ] && return 1
    [ "$pid" = "$$" ] && return 1
    if ! is_pid_alive "$pid"; then
        return 1
    fi
    if grep -Fq "$TMPDIR_TEST" "/proc/$pid/cmdline" 2>/dev/null; then
        return 0
    fi
    if ls -l "/proc/$pid/fd" 2>/dev/null | grep -Fq "$TMPDIR_TEST"; then
        return 0
    fi
    return 1
}

verify_isolation() {
    local name="$1"
    local ns_list
    ns_list="$(ip netns list 2>/dev/null | awk '{print $1}')"
    local leaked_ns=()
    local leaked_pids=()

    # Check direct PIDs tracked prior to teardown
    for entry in "${LAST_CHECK_PIDS[@]}"; do
        local p="${entry%%:*}"
        local desc="${entry#*:}"
        if [ -n "$p" ] && is_pid_alive "$p"; then
            local alive=false
            for _ in 1 2 3 4 5; do
                sleep 0.1
                if ! is_pid_alive "$p"; then
                    alive=false
                    break
                fi
                alive=true
            done
            if [ "$alive" = true ]; then
                leaked_pids+=("$p($desc)")
            fi
        fi
    done

    case "$name" in
        yip)
            for ns in "$NS_YA" "$NS_YB"; do
                if echo "$ns_list" | grep -qx "$ns"; then leaked_ns+=("$ns"); fi
            done
            for p in $(pgrep -f "yipd.*$TMPDIR_TEST" 2>/dev/null || pgrep -x yipd 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(yipd)"); fi
            done
            ;;
        wireguard|wg)
            for ns in "$NS_WA" "$NS_WB"; do
                if echo "$ns_list" | grep -qx "$ns"; then leaked_ns+=("$ns"); fi
            done
            ;;
        wireguard-go|wggo)
            for ns in "$NS_GGA" "$NS_GGB"; do
                if echo "$ns_list" | grep -qx "$ns"; then leaked_ns+=("$ns"); fi
            done
            for p in $(pgrep -x wireguard-go 2>/dev/null || pgrep -x wireguard 2>/dev/null || true); do
                if is_pid_alive "$p" && { is_test_pid "$p" || grep -q "wggo0" "/proc/$p/cmdline" 2>/dev/null; }; then
                    [ "$p" != "$$" ] && leaked_pids+=("$p(wireguard-go)")
                fi
            done
            ;;
        amneziawg|awg)
            for ns in "$NS_AA" "$NS_AB"; do
                if echo "$ns_list" | grep -qx "$ns"; then leaked_ns+=("$ns"); fi
            done
            for p in $(pgrep -x amneziawg-go 2>/dev/null || true); do
                if is_pid_alive "$p" && { is_test_pid "$p" || grep -q "awg0" "/proc/$p/cmdline" 2>/dev/null; }; then
                    [ "$p" != "$$" ] && leaked_pids+=("$p(amneziawg-go)")
                fi
            done
            ;;
        openvpn|ovpn)
            for ns in "$NS_OA" "$NS_OB"; do
                if echo "$ns_list" | grep -qx "$ns"; then leaked_ns+=("$ns"); fi
            done
            for p in $(pgrep -x openvpn 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(openvpn)"); fi
            done
            ;;
        n2n)
            for ns in "$NS_NA" "$NS_NB"; do
                if echo "$ns_list" | grep -qx "$ns"; then leaked_ns+=("$ns"); fi
            done
            for p in $(pgrep -x edge 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(edge)"); fi
            done
            for p in $(pgrep -x supernode 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(supernode)"); fi
            done
            ;;
        zerotier|zt)
            for ns in "$NS_ZA" "$NS_ZB"; do
                if echo "$ns_list" | grep -qx "$ns"; then leaked_ns+=("$ns"); fi
            done
            for p in $(pgrep -x zerotier-one 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(zerotier-one)"); fi
            done
            ;;
        tailscale|ts)
            for ns in "$NS_TA" "$NS_TB"; do
                if echo "$ns_list" | grep -qx "$ns"; then leaked_ns+=("$ns"); fi
            done
            for p in $(pgrep -x tailscaled 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(tailscaled)"); fi
            done
            for p in $(pgrep -x headscale 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(headscale)"); fi
            done
            ;;
        netbird|nb)
            for ns in "$NS_BA" "$NS_BB"; do
                if echo "$ns_list" | grep -qx "$ns"; then leaked_ns+=("$ns"); fi
            done
            for p in $(pgrep -x netbird 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(netbird)"); fi
            done
            for p in $(pgrep -x netbird-mgmt 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(netbird-mgmt)"); fi
            done
            for p in $(pgrep -x netbird-signal 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(netbird-signal)"); fi
            done
            ;;
    esac

    # Deduplicate leaked_pids
    if [ ${#leaked_pids[@]} -gt 1 ]; then
        mapfile -t leaked_pids < <(printf "%s\n" "${leaked_pids[@]}" | sort -u)
    fi

    if [ ${#leaked_ns[@]} -gt 0 ] || [ ${#leaked_pids[@]} -gt 0 ]; then
        echo "[warn] isolation leak detected after stopping $name:"
        [ ${#leaked_ns[@]} -gt 0 ] && echo "  leaked namespaces: ${leaked_ns[*]}"
        [ ${#leaked_pids[@]} -gt 0 ] && echo "  leaked pids: ${leaked_pids[*]}"
        for ns in "${leaked_ns[@]}"; do
            ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
            ip netns del "$ns" 2>/dev/null || true
        done
        for p in "${leaked_pids[@]}"; do
            local pid="${p%%(*}"
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        done
        ISOLATION_FAILED=true
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle: yip
# ══════════════════════════════════════════════════════════════════════════════
start_yip() {
    echo "[yip] generating keypairs"
    local GENKEY_A GENKEY_B PRIV_A PUB_A PRIV_B PUB_B
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
mtu=${YIP_MTU}
${YIP_XDP:+xdp=$YIP_XDP}
${YIP_XDP:+xdp_ifname=${YIP_XDP_IFNAME:-$VYA}}
${YIP_XDP_MODE:+xdp_mode=$YIP_XDP_MODE}
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
mtu=${YIP_MTU}
${YIP_XDP:+xdp=$YIP_XDP}
${YIP_XDP:+xdp_ifname=${YIP_XDP_IFNAME:-$VYB}}
${YIP_XDP_MODE:+xdp_mode=$YIP_XDP_MODE}
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
    local elapsed=0
    while true; do
        local A_UP=0 B_UP=0
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
    ip netns exec "$NS_YA" ip link set dev "$TUN_DEV" txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_YB" ip link set dev "$TUN_DEV" txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_YA" ip link set "$TUN_DEV" up 2>/dev/null || true
    ip netns exec "$NS_YB" ip link set "$TUN_DEV" up 2>/dev/null || true
    ip netns exec "$NS_YA" sysctl -qw net.ipv6.conf."$TUN_DEV".disable_ipv6=0 net.ipv6.conf."$TUN_DEV".accept_dad=0 2>/dev/null || true
    ip netns exec "$NS_YB" sysctl -qw net.ipv6.conf."$TUN_DEV".disable_ipv6=0 net.ipv6.conf."$TUN_DEV".accept_dad=0 2>/dev/null || true
    ip netns exec "$NS_YA" ip addr add "${TUN_YA_IP}/24" dev "$TUN_DEV" 2>/dev/null || true
    ip netns exec "$NS_YB" ip addr add "${TUN_YB_IP}/24" dev "$TUN_DEV" 2>/dev/null || true
    ip netns exec "$NS_YA" ip -6 addr add "${TUN_YA_IP6}/64" dev "$TUN_DEV" nodad 2>/dev/null || true
    ip netns exec "$NS_YB" ip -6 addr add "${TUN_YB_IP6}/64" dev "$TUN_DEV" nodad 2>/dev/null || true
    sleep 0.5
    echo "[yip] baseline connectivity check"
    ip netns exec "$NS_YB" ping -c 3 -W 5 "$TUN_YA_IP" >/dev/null || {
        echo "[error] yip baseline IPv4 ping failed"; cat "$LOG_A" "$LOG_B" || true; stop_yip; return 1
    }
    ip netns exec "$NS_YB" ping -6 -c 3 -W 5 "$TUN_YA_IP6" >/dev/null || {
        echo "[error] yip baseline IPv6 ping failed"; cat "$LOG_A" "$LOG_B" || true; stop_yip; return 1
    }
    return 0
}

stop_yip() {
    LAST_CHECK_PIDS=("$PID_YA:yipA" "$PID_YB:yipB")
    [ -n "$PID_YA" ] && kill "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill "$PID_YB" 2>/dev/null || true
    sleep 0.1
    [ -n "$PID_YA" ] && kill -9 "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill -9 "$PID_YB" 2>/dev/null || true
    [ -n "$PID_YA" ] && wait "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && wait "$PID_YB" 2>/dev/null || true
    PID_YA=""; PID_YB=""
    for ns in "$NS_YA" "$NS_YB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -f "$CFG_A" "$CFG_B" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle: WireGuard
# ══════════════════════════════════════════════════════════════════════════════
start_wg() {
    if ! contender_wanted "wireguard" && ! contender_wanted "wg"; then WG_AVAILABLE=false; return 1; fi
    if [ "${WG_AVAILABLE:-}" = false ]; then return 1; fi
    if ! command -v wg >/dev/null 2>&1; then
        echo "[wg] SKIP: 'wg' command not found"; WG_AVAILABLE=false; return 1
    fi
    if ! modprobe wireguard 2>/dev/null; then
        echo "[wg] SKIP: modprobe wireguard failed"; WG_AVAILABLE=false; return 1
    fi
    apparmor_parser -R /etc/apparmor.d/wg 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.bin.wg 2>/dev/null || true
    echo "[wg] generating keypairs"
    local privA pubA privB pubB
    privA="$(wg genkey 2>/dev/null || true)"; pubA="$(echo "$privA" | wg pubkey 2>/dev/null || true)"
    privB="$(wg genkey 2>/dev/null || true)"; pubB="$(echo "$privB" | wg pubkey 2>/dev/null || true)"
    if [ -z "$privA" ] || [ -z "$privB" ]; then
        echo "[wg] SKIP: key generation failed"; WG_AVAILABLE=false; return 1
    fi
    echo "[wg] creating namespaces and veth pair"
    make_pair "$NS_WA" "$NS_WB" "$VWA" "$VWB" "$VWA_IP" "$VWB_IP"
    if ! ip netns exec "$NS_WA" ip link add wg0 type wireguard 2>/dev/null || \
       ! ip netns exec "$NS_WB" ip link add wg0 type wireguard 2>/dev/null; then
        echo "[wg] SKIP: wireguard interface creation failed"; stop_wg; WG_AVAILABLE=false; return 1
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
        echo "[wg] SKIP: wg set configuration failed: $wg_err"; stop_wg; WG_AVAILABLE=false; return 1
    fi
    if ! ip netns exec "$NS_WA" ip addr add "${TUN_WA_IP}/24" dev wg0 2>/dev/null || \
       ! ip netns exec "$NS_WB" ip addr add "${TUN_WB_IP}/24" dev wg0 2>/dev/null || \
       ! ip netns exec "$NS_WA" ip -6 addr add "${TUN_WA_IP6}/64" dev wg0 nodad 2>/dev/null || \
       ! ip netns exec "$NS_WB" ip -6 addr add "${TUN_WB_IP6}/64" dev wg0 nodad 2>/dev/null; then
        echo "[wg] SKIP: interface setup failed"; stop_wg; WG_AVAILABLE=false; return 1
    fi
    ip netns exec "$NS_WA" ip link set dev wg0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_WB" ip link set dev wg0 txqueuelen 10000 2>/dev/null || true
    if ! ip netns exec "$NS_WA" ip link set wg0 up 2>/dev/null || \
       ! ip netns exec "$NS_WB" ip link set wg0 up 2>/dev/null; then
        echo "[wg] SKIP: interface setup failed"; stop_wg; WG_AVAILABLE=false; return 1
    fi
    sleep 0.5
    if ! ip netns exec "$NS_WB" ping -c 3 -W 5 "$TUN_WA_IP" >/dev/null 2>&1; then
        echo "[wg] SKIP: baseline IPv4 ping failed"; stop_wg; WG_AVAILABLE=false; return 1
    fi
    if ! ip netns exec "$NS_WB" ping -6 -c 3 -W 5 "$TUN_WA_IP6" >/dev/null 2>&1; then
        echo "[wg] SKIP: baseline IPv6 ping failed"; stop_wg; WG_AVAILABLE=false; return 1
    fi
    echo "[wg] tunnel up"
    WG_AVAILABLE=true
    return 0
}

stop_wg() {
    LAST_CHECK_PIDS=()
    ip netns exec "$NS_WA" ip link del wg0 2>/dev/null || true
    ip netns exec "$NS_WB" ip link del wg0 2>/dev/null || true
    rm -f /etc/wireguard/wg_a /etc/wireguard/wg_b "$TMPDIR_TEST/wg_a" "$TMPDIR_TEST/wg_b" 2>/dev/null || true
    for ns in "$NS_WA" "$NS_WB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle: WireGuard-Go
# ══════════════════════════════════════════════════════════════════════════════
start_wireguard_go() {
    if ! contender_wanted "wireguard-go" && ! contender_wanted "wggo"; then WGGO_AVAILABLE=false; return 1; fi
    if [ "${WGGO_AVAILABLE:-}" = false ]; then return 1; fi
    local wggo_bin="wireguard-go"
    if ! command -v "$wggo_bin" >/dev/null 2>&1; then
        if command -v wireguard >/dev/null 2>&1; then
            wggo_bin="wireguard"
        else
            echo "[wggo] SKIP: 'wireguard-go' command not found"; WGGO_AVAILABLE=false; return 1
        fi
    fi
    if ! command -v wg >/dev/null 2>&1; then
        echo "[wggo] SKIP: 'wg' command not found"; WGGO_AVAILABLE=false; return 1
    fi
    apparmor_parser -R /etc/apparmor.d/wg 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.bin.wg 2>/dev/null || true
    echo "[wggo] generating keypairs"
    local privA pubA privB pubB
    privA="$(wg genkey 2>/dev/null || true)"; pubA="$(echo "$privA" | wg pubkey 2>/dev/null || true)"
    privB="$(wg genkey 2>/dev/null || true)"; pubB="$(echo "$privB" | wg pubkey 2>/dev/null || true)"
    if [ -z "$privA" ] || [ -z "$privB" ]; then
        echo "[wggo] SKIP: key generation failed"; WGGO_AVAILABLE=false; return 1
    fi

    mkdir -p /etc/wireguard-run
    mkdir -p "/etc/netns/$NS_GGA/wireguard-run" "/etc/netns/$NS_GGB/wireguard-run"
    if [ ! -L /run/wireguard ]; then
        rm -rf /run/wireguard 2>/dev/null || true
        ln -sf /etc/wireguard-run /run/wireguard
    fi

    echo "[wggo] creating namespaces and veth pair"
    make_pair "$NS_GGA" "$NS_GGB" "$VGGA" "$VGGB" "$VGGA_IP" "$VGGB_IP"

    echo "[wggo] launching wireguard-go daemons"
    ip netns exec "$NS_GGA" "$wggo_bin" wggo0 >"$TMPDIR_TEST/wggo-a.log" 2>&1 &
    PID_GGA=$!
    ip netns exec "$NS_GGB" "$wggo_bin" wggo0 >"$TMPDIR_TEST/wggo-b.log" 2>&1 &
    PID_GGB=$!

    local wggo_up=false
    for i in $(seq 1 20); do
        if ip netns exec "$NS_GGA" ip link show wggo0 >/dev/null 2>&1 && \
           ip netns exec "$NS_GGB" ip link show wggo0 >/dev/null 2>&1; then
            wggo_up=true
            break
        fi
        sleep 0.25
    done
    if [ "$wggo_up" = false ]; then
        echo "[wggo] SKIP: wggo0 interface creation failed or timed out"
        tail -5 "$TMPDIR_TEST/wggo-a.log" "$TMPDIR_TEST/wggo-b.log" 2>/dev/null || true
        stop_wireguard_go; WGGO_AVAILABLE=false; return 1
    fi

    local keyA="$TMPDIR_TEST/wggo_a"
    local keyB="$TMPDIR_TEST/wggo_b"
    printf '%s' "$privA" > "$keyA"
    printf '%s' "$privB" > "$keyB"
    chmod 600 "$keyA" "$keyB"

    local wg_err=""
    if ! wg_err="$(ip netns exec "$NS_GGA" wg set wggo0 private-key "$keyA" listen-port "$GGPORT_A" \
            peer "$pubB" endpoint "${VGGB_IP}:${GGPORT_B}" allowed-ips "${TUN_GGB_IP}/32,fd00:27::/64" 2>&1)" || \
       ! wg_err="$(ip netns exec "$NS_GGB" wg set wggo0 private-key "$keyB" listen-port "$GGPORT_B" \
            peer "$pubA" endpoint "${VGGA_IP}:${GGPORT_A}" allowed-ips "${TUN_GGA_IP}/32,fd00:27::/64" 2>&1)"; then
        echo "[wggo] SKIP: wg set configuration failed: $wg_err"; stop_wireguard_go; WGGO_AVAILABLE=false; return 1
    fi

    if ! ip netns exec "$NS_GGA" ip addr add "${TUN_GGA_IP}/24" dev wggo0 2>/dev/null || \
       ! ip netns exec "$NS_GGB" ip addr add "${TUN_GGB_IP}/24" dev wggo0 2>/dev/null || \
       ! ip netns exec "$NS_GGA" ip -6 addr add "${TUN_GGA_IP6}/64" dev wggo0 nodad 2>/dev/null || \
       ! ip netns exec "$NS_GGB" ip -6 addr add "${TUN_GGB_IP6}/64" dev wggo0 nodad 2>/dev/null; then
        echo "[wggo] SKIP: interface setup failed"; stop_wireguard_go; WGGO_AVAILABLE=false; return 1
    fi

    ip netns exec "$NS_GGA" ip link set dev wggo0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_GGB" ip link set dev wggo0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_GGA" ip link set dev wggo0 mtu 1420 2>/dev/null || true
    ip netns exec "$NS_GGB" ip link set dev wggo0 mtu 1420 2>/dev/null || true

    if ! ip netns exec "$NS_GGA" ip link set wggo0 up 2>/dev/null || \
       ! ip netns exec "$NS_GGB" ip link set wggo0 up 2>/dev/null; then
        echo "[wggo] SKIP: interface set up failed"; stop_wireguard_go; WGGO_AVAILABLE=false; return 1
    fi

    sleep 0.5
    if ! ip netns exec "$NS_GGB" ping -c 3 -W 5 "$TUN_GGA_IP" >/dev/null 2>&1; then
        echo "[wggo] SKIP: baseline IPv4 ping failed"; stop_wireguard_go; WGGO_AVAILABLE=false; return 1
    fi
    if ! ip netns exec "$NS_GGB" ping -6 -c 3 -W 5 "$TUN_GGA_IP6" >/dev/null 2>&1; then
        echo "[wggo] SKIP: baseline IPv6 ping failed"; stop_wireguard_go; WGGO_AVAILABLE=false; return 1
    fi
    echo "[wggo] tunnel up"
    WGGO_AVAILABLE=true
    return 0
}

stop_wireguard_go() {
    LAST_CHECK_PIDS=("$PID_GGA:wggoA" "$PID_GGB:wggoB")
    [ -n "$PID_GGA" ] && kill "$PID_GGA" 2>/dev/null || true
    [ -n "$PID_GGB" ] && kill "$PID_GGB" 2>/dev/null || true
    sleep 0.1
    [ -n "$PID_GGA" ] && kill -9 "$PID_GGA" 2>/dev/null || true
    [ -n "$PID_GGB" ] && kill -9 "$PID_GGB" 2>/dev/null || true
    [ -n "$PID_GGA" ] && wait "$PID_GGA" 2>/dev/null || true
    [ -n "$PID_GGB" ] && wait "$PID_GGB" 2>/dev/null || true
    PID_GGA=""; PID_GGB=""
    ip netns exec "$NS_GGA" ip link del wggo0 2>/dev/null || true
    ip netns exec "$NS_GGB" ip link del wggo0 2>/dev/null || true
    rm -rf "/etc/netns/$NS_GGA" "/etc/netns/$NS_GGB" /etc/wireguard-run 2>/dev/null || true
    if [ -L /run/wireguard ]; then
        rm -f /run/wireguard 2>/dev/null || true
    fi
    rm -f "$TMPDIR_TEST/wggo_a" "$TMPDIR_TEST/wggo_b" 2>/dev/null || true
    for ns in "$NS_GGA" "$NS_GGB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle: AmneziaWG
# ══════════════════════════════════════════════════════════════════════════════
start_awg() {
    if ! contender_wanted "amneziawg" && ! contender_wanted "awg"; then AWG_AVAILABLE=false; return 1; fi
    if [ "${AWG_AVAILABLE:-}" = false ]; then return 1; fi
    if ! command -v awg >/dev/null 2>&1; then
        echo "[awg] SKIP: 'awg' command not found"; AWG_AVAILABLE=false; return 1
    fi
    local use_go=false
    if ! modprobe amneziawg 2>/dev/null; then
        if command -v amneziawg-go >/dev/null 2>&1; then
            use_go=true
        else
            echo "[awg] SKIP: neither amneziawg kernel module nor amneziawg-go found"
            AWG_AVAILABLE=false; return 1
        fi
    fi
    echo "[awg] generating keypairs"
    local privA pubA privB pubB
    privA="$(awg genkey 2>/dev/null || true)"; pubA="$(echo "$privA" | awg pubkey 2>/dev/null || true)"
    privB="$(awg genkey 2>/dev/null || true)"; pubB="$(echo "$privB" | awg pubkey 2>/dev/null || true)"
    if [ -z "$privA" ] || [ -z "$privB" ]; then
        echo "[awg] SKIP: key generation failed"; AWG_AVAILABLE=false; return 1
    fi
    echo "[awg] creating namespaces and veth pair"
    make_pair "$NS_AA" "$NS_AB" "$VAA" "$VAB" "$VAA_IP" "$VAB_IP"
    if [ "$use_go" = true ]; then
        mkdir -p /etc/amneziawg-run
        mkdir -p "/etc/netns/$NS_AA/amneziawg-run" "/etc/netns/$NS_AB/amneziawg-run"
        if [ ! -L /run/amneziawg ]; then
            rm -rf /run/amneziawg 2>/dev/null || true
            ln -sf /etc/amneziawg-run /run/amneziawg
        fi
        if [ ! -L /var/run/amneziawg ]; then
            rm -rf /var/run/amneziawg 2>/dev/null || true
            ln -sf /etc/amneziawg-run /var/run/amneziawg
        fi
        ip netns exec "$NS_AA" amneziawg-go -f awg0 >"$TMPDIR_TEST/awg-go-a.log" 2>&1 &
        PID_AA=$!
        ip netns exec "$NS_AB" amneziawg-go -f awg0 >"$TMPDIR_TEST/awg-go-b.log" 2>&1 &
        PID_AB=$!
        sleep 0.5
    else
        if ! ip netns exec "$NS_AA" ip link add awg0 type amneziawg 2>/dev/null || \
           ! ip netns exec "$NS_AB" ip link add awg0 type amneziawg 2>/dev/null; then
            echo "[awg] SKIP: amneziawg link add failed"; stop_awg; AWG_AVAILABLE=false; return 1
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
        stop_awg; AWG_AVAILABLE=false; return 1
    fi

    if ! ip netns exec "$NS_AA" ip addr add "${TUN_AA_IP}/24" dev awg0 2>/dev/null || \
       ! ip netns exec "$NS_AB" ip addr add "${TUN_AB_IP}/24" dev awg0 2>/dev/null || \
       ! ip netns exec "$NS_AA" ip -6 addr add "${TUN_AA_IP6}/64" dev awg0 nodad 2>/dev/null || \
       ! ip netns exec "$NS_AB" ip -6 addr add "${TUN_AB_IP6}/64" dev awg0 nodad 2>/dev/null; then
        echo "[awg] SKIP: ip addr add failed"; stop_awg; AWG_AVAILABLE=false; return 1
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
        echo "[awg] SKIP: awg setconf failed"; stop_awg; AWG_AVAILABLE=false; return 1
    fi
    ip netns exec "$NS_AA" ip link set dev awg0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_AB" ip link set dev awg0 txqueuelen 10000 2>/dev/null || true
    if ! ip netns exec "$NS_AA" ip link set awg0 up 2>/dev/null || \
       ! ip netns exec "$NS_AB" ip link set awg0 up 2>/dev/null; then
        echo "[awg] SKIP: ip link set up failed"; stop_awg; AWG_AVAILABLE=false; return 1
    fi
    sleep 0.5
    if ! ip netns exec "$NS_AB" ping -c 3 -W 5 "$TUN_AA_IP" >/dev/null 2>&1; then
        echo "[awg] SKIP: baseline IPv4 ping failed"; stop_awg; AWG_AVAILABLE=false; return 1
    fi
    if ! ip netns exec "$NS_AB" ping -6 -c 3 -W 5 "$TUN_AA_IP6" >/dev/null 2>&1; then
        echo "[awg] SKIP: baseline IPv6 ping failed"; stop_awg; AWG_AVAILABLE=false; return 1
    fi
    echo "[awg] tunnel up"
    AWG_AVAILABLE=true
    return 0
}

stop_awg() {
    LAST_CHECK_PIDS=("$PID_AA:awgA" "$PID_AB:awgB")
    [ -n "$PID_AA" ] && kill "$PID_AA" 2>/dev/null || true
    [ -n "$PID_AB" ] && kill "$PID_AB" 2>/dev/null || true
    sleep 0.1
    [ -n "$PID_AA" ] && kill -9 "$PID_AA" 2>/dev/null || true
    [ -n "$PID_AB" ] && kill -9 "$PID_AB" 2>/dev/null || true
    [ -n "$PID_AA" ] && wait "$PID_AA" 2>/dev/null || true
    [ -n "$PID_AB" ] && wait "$PID_AB" 2>/dev/null || true
    PID_AA=""; PID_AB=""
    ip netns exec "$NS_AA" ip link del awg0 2>/dev/null || true
    ip netns exec "$NS_AB" ip link del awg0 2>/dev/null || true
    rm -rf "/etc/netns/$NS_AA" "/etc/netns/$NS_AB" /etc/amneziawg-run 2>/dev/null || true
    if [ -L /run/amneziawg ]; then rm -f /run/amneziawg 2>/dev/null || true; fi
    if [ -L /var/run/amneziawg ]; then rm -f /var/run/amneziawg 2>/dev/null || true; fi
    rm -f "$TMPDIR_TEST/awgA.conf" "$TMPDIR_TEST/awgB.conf" 2>/dev/null || true
    for ns in "$NS_AA" "$NS_AB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle: OpenVPN
# ══════════════════════════════════════════════════════════════════════════════
start_ovpn() {
    if ! contender_wanted "openvpn" && ! contender_wanted "ovpn"; then OVPN_AVAILABLE=false; return 1; fi
    if [ "${OVPN_AVAILABLE:-}" = false ]; then return 1; fi
    if ! command -v openvpn >/dev/null 2>&1; then
        echo "[ovpn] SKIP: 'openvpn' not found"; OVPN_AVAILABLE=false; return 1
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
    PID_OA=$!
    ip netns exec "$NS_OB" openvpn \
        --dev tun0 --dev-type tun \
        --remote "$VOA_IP" --rport 1194 --ifconfig "$TUN_OB_IP" "$TUN_OA_IP" \
        --ifconfig-ipv6 "$TUN_OB_IP6" "$TUN_OA_IP6" \
        --tls-client --cert "$TMPDIR_TEST/ovpn-b.crt" --key "$TMPDIR_TEST/ovpn-b.key" \
        --peer-fingerprint "$FA" --data-ciphers AES-256-GCM \
        --proto udp --verb 1 --ping 10 --ping-restart 0 \
        >"$TMPDIR_TEST/ovpn-b.log" 2>&1 &
    PID_OB=$!
    local i
    for i in $(seq 1 60); do
        ip netns exec "$NS_OA" ip link show tun0 >/dev/null 2>&1 \
            && ip netns exec "$NS_OB" ip link show tun0 >/dev/null 2>&1 && break
        sleep 0.25
    done
    ip netns exec "$NS_OA" ip link set dev tun0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_OB" ip link set dev tun0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_OA" ip -6 addr add "${TUN_OA_IP6}/64" dev tun0 nodad 2>/dev/null || true
    ip netns exec "$NS_OB" ip -6 addr add "${TUN_OB_IP6}/64" dev tun0 nodad 2>/dev/null || true
    local ovpn_up=false
    for i in $(seq 1 20); do
        if ip netns exec "$NS_OB" ping -c 1 -W 1 "$TUN_OA_IP" >/dev/null 2>&1; then
            ovpn_up=true
            break
        fi
        sleep 0.5
    done
    if [ "$ovpn_up" = false ]; then
        echo "[ovpn] SKIP: baseline IPv4 ping failed"
        tail -5 "$TMPDIR_TEST/ovpn-a.log" "$TMPDIR_TEST/ovpn-b.log" 2>/dev/null || true
        stop_ovpn; OVPN_AVAILABLE=false; return 1
    fi
    if ! ip netns exec "$NS_OB" ping -6 -c 3 -W 5 "$TUN_OA_IP6" >/dev/null 2>&1; then
        echo "[ovpn] SKIP: baseline IPv6 ping failed"
        tail -5 "$TMPDIR_TEST/ovpn-a.log" "$TMPDIR_TEST/ovpn-b.log" 2>/dev/null || true
        stop_ovpn; OVPN_AVAILABLE=false; return 1
    fi
    echo "[ovpn] tunnel up"
    OVPN_AVAILABLE=true
    return 0
}

stop_ovpn() {
    LAST_CHECK_PIDS=("$PID_OA:ovpnA" "$PID_OB:ovpnB")
    [ -n "$PID_OA" ] && kill "$PID_OA" 2>/dev/null || true
    [ -n "$PID_OB" ] && kill "$PID_OB" 2>/dev/null || true
    sleep 0.1
    [ -n "$PID_OA" ] && kill -9 "$PID_OA" 2>/dev/null || true
    [ -n "$PID_OB" ] && kill -9 "$PID_OB" 2>/dev/null || true
    [ -n "$PID_OA" ] && wait "$PID_OA" 2>/dev/null || true
    [ -n "$PID_OB" ] && wait "$PID_OB" 2>/dev/null || true
    PID_OA=""; PID_OB=""
    ip netns exec "$NS_OA" ip link del tun0 2>/dev/null || true
    ip netns exec "$NS_OB" ip link del tun0 2>/dev/null || true
    for ns in "$NS_OA" "$NS_OB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -f "$TMPDIR_TEST/ovpn-a."* "$TMPDIR_TEST/ovpn-b."* 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle: n2n
# ══════════════════════════════════════════════════════════════════════════════
start_n2n() {
    if ! contender_wanted "n2n"; then N2N_AVAILABLE=false; return 1; fi
    if [ "${N2N_AVAILABLE:-}" = false ]; then return 1; fi
    if ! command -v supernode >/dev/null 2>&1 || ! command -v edge >/dev/null 2>&1; then
        echo "[n2n] SKIP: 'supernode'/'edge' not found"; N2N_AVAILABLE=false; return 1
    fi
    killall -9 edge supernode 2>/dev/null || true
    echo "[n2n] creating namespaces and veth pair"
    make_pair "$NS_NA" "$NS_NB" "$VNA" "$VNB" "$VNA_IP" "$VNB_IP"
    ip netns exec "$NS_NA" supernode -p "$N2N_PORT" -f -M >"$TMPDIR_TEST/n2-sn.log" 2>&1 &
    PID_N2N_SN=$!
    sleep 0.5
    ip netns exec "$NS_NA" edge -c bench -k benchkey -a "${OVL_NA_IP}/24" -l "$VNA_IP":"$N2N_PORT" \
        -d n2n0 -f -r -E >"$TMPDIR_TEST/n2-eA.log" 2>&1 &
    PID_N2N_EA=$!
    ip netns exec "$NS_NB" edge -c bench -k benchkey -a "${OVL_NB_IP}/24" -l "$VNA_IP":"$N2N_PORT" \
        -d n2n0 -f -r -E >"$TMPDIR_TEST/n2-eB.log" 2>&1 &
    PID_N2N_EB=$!
    local i
    for i in $(seq 1 60); do
        ip netns exec "$NS_NA" ip link show n2n0 >/dev/null 2>&1 \
            && ip netns exec "$NS_NB" ip link show n2n0 >/dev/null 2>&1 && break
        sleep 0.25
    done
    ip netns exec "$NS_NA" sysctl -w net.ipv6.conf.n2n0.disable_ipv6=0 >/dev/null 2>&1 || true
    ip netns exec "$NS_NB" sysctl -w net.ipv6.conf.n2n0.disable_ipv6=0 >/dev/null 2>&1 || true
    ip netns exec "$NS_NA" ip link set dev n2n0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_NB" ip link set dev n2n0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_NA" ip link set dev n2n0 up 2>/dev/null || true
    ip netns exec "$NS_NB" ip link set dev n2n0 up 2>/dev/null || true
    ip netns exec "$NS_NA" ip -6 addr add "${OVL_NA_IP6}/64" dev n2n0 nodad 2>/dev/null || true
    ip netns exec "$NS_NB" ip -6 addr add "${OVL_NB_IP6}/64" dev n2n0 nodad 2>/dev/null || true
    local n2n_up=false
    for i in $(seq 1 40); do
        if ip netns exec "$NS_NB" ping -c 1 -W 1 "$OVL_NA_IP" >/dev/null 2>&1; then
            n2n_up=true
            break
        fi
        sleep 0.5
    done
    if [ "$n2n_up" = false ]; then
        echo "[n2n] SKIP: baseline overlay IPv4 ping failed"
        tail -5 "$TMPDIR_TEST/n2-sn.log" "$TMPDIR_TEST/n2-eA.log" "$TMPDIR_TEST/n2-eB.log" 2>/dev/null || true
        stop_n2n; N2N_AVAILABLE=false; return 1
    fi
    local n2n_v6_up=false
    for i in $(seq 1 10); do
        if ip netns exec "$NS_NB" ping -6 -c 1 -W 1 "$OVL_NA_IP6" >/dev/null 2>&1; then
            n2n_v6_up=true
            break
        fi
        sleep 0.5
    done
    if [ "$n2n_v6_up" = false ]; then
        OVL_NA_IP6=""
        OVL_NB_IP6=""
    fi
    echo "[n2n] overlay up"
    N2N_AVAILABLE=true
    return 0
}

stop_n2n() {
    LAST_CHECK_PIDS=("$PID_N2N_SN:n2n_sn" "$PID_N2N_EA:n2n_ea" "$PID_N2N_EB:n2n_eb")
    [ -n "$PID_N2N_SN" ] && kill "$PID_N2N_SN" 2>/dev/null || true
    [ -n "$PID_N2N_EA" ] && kill "$PID_N2N_EA" 2>/dev/null || true
    [ -n "$PID_N2N_EB" ] && kill "$PID_N2N_EB" 2>/dev/null || true
    sleep 0.1
    [ -n "$PID_N2N_SN" ] && kill -9 "$PID_N2N_SN" 2>/dev/null || true
    [ -n "$PID_N2N_EA" ] && kill -9 "$PID_N2N_EA" 2>/dev/null || true
    [ -n "$PID_N2N_EB" ] && kill -9 "$PID_N2N_EB" 2>/dev/null || true
    [ -n "$PID_N2N_SN" ] && wait "$PID_N2N_SN" 2>/dev/null || true
    [ -n "$PID_N2N_EA" ] && wait "$PID_N2N_EA" 2>/dev/null || true
    [ -n "$PID_N2N_EB" ] && wait "$PID_N2N_EB" 2>/dev/null || true
    PID_N2N_SN=""; PID_N2N_EA=""; PID_N2N_EB=""
    killall -9 edge supernode 2>/dev/null || true
    ip netns exec "$NS_NA" ip link del n2n0 2>/dev/null || true
    ip netns exec "$NS_NB" ip link del n2n0 2>/dev/null || true
    for ns in "$NS_NA" "$NS_NB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle: ZeroTier
# ══════════════════════════════════════════════════════════════════════════════
start_zerotier() {
    if ! contender_wanted "zerotier" && ! contender_wanted "zt"; then ZT_AVAILABLE=false; return 1; fi
    if [ "${ZT_AVAILABLE:-}" = false ]; then return 1; fi
    if ! command -v zerotier-one >/dev/null 2>&1; then
        echo "[zerotier] SKIP: 'zerotier-one' not found"; ZT_AVAILABLE=false; return 1
    fi
    echo "[zerotier] creating namespaces and veth pair"
    make_pair "$NS_ZA" "$NS_ZB" "$VZA" "$VZB" "$VZA_IP" "$VZB_IP"
    local zt_dir_a="$TMPDIR_TEST/zt_a"; local zt_dir_b="$TMPDIR_TEST/zt_b"
    mkdir -p "$zt_dir_a" "$zt_dir_b"

    if command -v zerotier-idtool >/dev/null 2>&1; then
        zerotier-idtool generate "$zt_dir_a/identity.secret" "$zt_dir_a/identity.public" >/dev/null 2>&1 || true
        zerotier-idtool generate "$zt_dir_b/identity.secret" "$zt_dir_b/identity.public" >/dev/null 2>&1 || true
        local node_a node_b
        node_a="$(zerotier-idtool getpublic "$zt_dir_a/identity.secret" 2>/dev/null | cut -d: -f1 || true)"
        node_b="$(zerotier-idtool getpublic "$zt_dir_b/identity.secret" 2>/dev/null | cut -d: -f1 || true)"
        if [ -n "$node_a" ] && [ -n "$node_b" ]; then
            (cd "$zt_dir_a" && zerotier-idtool initmoon identity.public > moon.json 2>/dev/null || true)
            if [ -f "$zt_dir_a/moon.json" ]; then
                python3 -c "
import json
with open('$zt_dir_a/moon.json', 'r') as f:
    d = json.load(f)
d['roots'][0]['stableEndpoints'] = ['$VZA_IP/9993']
with open('$zt_dir_a/moon.json', 'w') as f:
    json.dump(d, f)
" 2>/dev/null || true
                (cd "$zt_dir_a" && zerotier-idtool genmoon moon.json >/dev/null 2>&1 || true)
                mkdir -p "$zt_dir_a/moons.d" "$zt_dir_b/moons.d"
                cp "$zt_dir_a"/*.moon "$zt_dir_a/moons.d/" 2>/dev/null || true
                cp "$zt_dir_a"/*.moon "$zt_dir_b/moons.d/" 2>/dev/null || true
            fi
        fi
    fi

    ip netns exec "$NS_ZA" zerotier-one "$zt_dir_a" >"$TMPDIR_TEST/zt-a.log" 2>&1 &
    PID_ZT_A=$!
    ip netns exec "$NS_ZB" zerotier-one "$zt_dir_b" >"$TMPDIR_TEST/zt-b.log" 2>&1 &
    PID_ZT_B=$!
    local i token_a="" node_a="" node_b=""
    for i in $(seq 1 40); do
        if [ -f "$zt_dir_a/authtoken.secret" ] && [ -f "$zt_dir_b/authtoken.secret" ]; then
            token_a="$(cat "$zt_dir_a/authtoken.secret")"
            break
        fi
        sleep 0.25
    done
    if [ -z "$token_a" ]; then
        echo "[zerotier] SKIP: daemon failed to initialize"; ZT_AVAILABLE=false; return 1
    fi
    for i in $(seq 1 40); do
        node_a="$(ip netns exec "$NS_ZA" zerotier-cli -D"$zt_dir_a" info 2>/dev/null | awk '$1=="200" && $3!="OFFLINE" && length($3)>=10 {print $3}' || true)"
        if [ -n "$node_a" ]; then
            break
        fi
        sleep 0.25
    done
    for i in $(seq 1 40); do
        node_b="$(ip netns exec "$NS_ZB" zerotier-cli -D"$zt_dir_b" info 2>/dev/null | awk '$1=="200" && $3!="OFFLINE" && length($3)>=10 {print $3}' || true)"
        if [ -n "$node_b" ]; then
            break
        fi
        sleep 0.25
    done
    if [ -z "$node_a" ] || [ -z "$node_b" ]; then
        echo "[zerotier] SKIP: failed to get node identity"; stop_zerotier; ZT_AVAILABLE=false; return 1
    fi
    local net_id="${node_a}ffffff"
    ip netns exec "$NS_ZA" curl -s -H "X-ZT1-Auth: $token_a" -X POST \
        -d '{"name": "bench", "private": false, "v4AssignMode": {"zt": true}, "routes": [{"target": "10.21.0.0/24"}], "ipAssignmentPools": [{"ipRangeStart": "10.21.0.1", "ipRangeEnd": "10.21.0.254"}]}' \
        "http://127.0.0.1:9993/controller/network/${net_id}" >/dev/null 2>&1 || true
    ip netns exec "$NS_ZA" zerotier-cli -D"$zt_dir_a" join "$net_id" >/dev/null 2>&1 || true
    ip netns exec "$NS_ZB" zerotier-cli -D"$zt_dir_b" join "$net_id" >/dev/null 2>&1 || true
    sleep 0.5
    ip netns exec "$NS_ZA" curl -s -H "X-ZT1-Auth: $token_a" -X POST -d '{"authorized": true}' "http://127.0.0.1:9993/controller/network/${net_id}/member/${node_a}" >/dev/null 2>&1 || true
    ip netns exec "$NS_ZA" curl -s -H "X-ZT1-Auth: $token_a" -X POST -d '{"authorized": true}' "http://127.0.0.1:9993/controller/network/${net_id}/member/${node_b}" >/dev/null 2>&1 || true
    local found=false
    for i in $(seq 1 40); do
        if ip netns exec "$NS_ZA" ip -o -4 addr show 2>/dev/null | grep -q "10.21." && \
           ip netns exec "$NS_ZB" ip -o -4 addr show 2>/dev/null | grep -q "10.21."; then
            found=true; break
        fi
        sleep 0.5
    done
    if [ "$found" = false ]; then
        echo "[zerotier] SKIP: overlay assignment timed out"; stop_zerotier; ZT_AVAILABLE=false; return 1
    fi
    local zt_a_if zt_b_if
    zt_a_if="$(ip netns exec "$NS_ZA" ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^zt' | head -1 || true)"
    zt_b_if="$(ip netns exec "$NS_ZB" ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^zt' | head -1 || true)"
    [ -n "$zt_a_if" ] && ip netns exec "$NS_ZA" ip link set dev "$zt_a_if" txqueuelen 10000 2>/dev/null || true
    [ -n "$zt_b_if" ] && ip netns exec "$NS_ZB" ip link set dev "$zt_b_if" txqueuelen 10000 2>/dev/null || true
    [ -n "$zt_a_if" ] && ip netns exec "$NS_ZA" ip -6 addr add "${TUN_ZA_IP6}/64" dev "$zt_a_if" nodad 2>/dev/null || true
    [ -n "$zt_b_if" ] && ip netns exec "$NS_ZB" ip -6 addr add "${TUN_ZB_IP6}/64" dev "$zt_b_if" nodad 2>/dev/null || true
    local zt_dyn_a zt_dyn_b
    zt_dyn_a="$(ip netns exec "$NS_ZA" ip -o -4 addr show dev "$zt_a_if" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
    zt_dyn_b="$(ip netns exec "$NS_ZB" ip -o -4 addr show dev "$zt_b_if" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
    [ -n "$zt_dyn_a" ] && TUN_ZA_IP="$zt_dyn_a"
    [ -n "$zt_dyn_b" ] && TUN_ZB_IP="$zt_dyn_b"
    local zt_up=false
    for i in $(seq 1 20); do
        if ip netns exec "$NS_ZB" ping -c 1 -W 1 "$TUN_ZA_IP" >/dev/null 2>&1; then
            zt_up=true
            break
        fi
        sleep 0.5
    done
    if [ "$zt_up" = false ]; then
        echo "[zerotier] SKIP: overlay ping failed"; stop_zerotier; ZT_AVAILABLE=false; return 1
    fi
    echo "[zerotier] network up"
    ZT_AVAILABLE=true
    return 0
}

stop_zerotier() {
    LAST_CHECK_PIDS=("$PID_ZT_A:ztA" "$PID_ZT_B:ztB")
    [ -n "$PID_ZT_A" ] && kill "$PID_ZT_A" 2>/dev/null || true
    [ -n "$PID_ZT_B" ] && kill "$PID_ZT_B" 2>/dev/null || true
    sleep 0.1
    [ -n "$PID_ZT_A" ] && kill -9 "$PID_ZT_A" 2>/dev/null || true
    [ -n "$PID_ZT_B" ] && kill -9 "$PID_ZT_B" 2>/dev/null || true
    [ -n "$PID_ZT_A" ] && wait "$PID_ZT_A" 2>/dev/null || true
    [ -n "$PID_ZT_B" ] && wait "$PID_ZT_B" 2>/dev/null || true
    PID_ZT_A=""; PID_ZT_B=""
    for ns in "$NS_ZA" "$NS_ZB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMPDIR_TEST/zt_a" "$TMPDIR_TEST/zt_b" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle: Tailscale
# ══════════════════════════════════════════════════════════════════════════════
start_tailscale() {
    if ! contender_wanted "tailscale" && ! contender_wanted "ts"; then TS_AVAILABLE=false; return 1; fi
    if [ "${TS_AVAILABLE:-}" = false ]; then return 1; fi
    if ! command -v tailscaled >/dev/null 2>&1 || ! command -v headscale >/dev/null 2>&1; then
        echo "[tailscale] SKIP: 'tailscaled' or 'headscale' not found"; TS_AVAILABLE=false; return 1
    fi
    echo "[tailscale] creating namespaces and veth pair"
    make_pair "$NS_TA" "$NS_TB" "$VTA" "$VTB" "$VTA_IP" "$VTB_IP"
    local hs_dir="$TMPDIR_TEST/headscale"
    mkdir -p "$hs_dir"
    cat > "$hs_dir/derp.yaml" <<EOF
regions:
  900:
    regionid: 900
    regioncode: bench
    regionname: LocalBench
    nodes:
      - name: 900a
        regionid: 900
        hostname: 127.0.0.1
        stunonly: true
        stunport: 3478
EOF
    cat > "$hs_dir/config.yaml" <<EOF
server_url: http://${VTA_IP}:8080
listen_addr: ${VTA_IP}:8080
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
derp:
  server:
    enabled: false
  paths:
    - $hs_dir/derp.yaml
database:
  type: sqlite
  sqlite:
    path: $hs_dir/db.sqlite
dns:
  magic_dns: false
  nameservers:
    global:
      - 1.1.1.1
noise:
  private_key_path: $hs_dir/noise_private.key
unix_socket: $hs_dir/headscale.sock
EOF
    ip netns exec "$NS_TA" headscale serve -c "$hs_dir/config.yaml" >"$TMPDIR_TEST/headscale.log" 2>&1 &
    PID_TS_HS=$!
    local i
    for i in $(seq 1 30); do
        if [ -S "$hs_dir/headscale.sock" ]; then
            break
        fi
        sleep 0.2
    done
    ip netns exec "$NS_TA" headscale users create bench -c "$hs_dir/config.yaml" >/dev/null 2>&1 || true
    local auth_key
    auth_key="$(ip netns exec "$NS_TA" headscale preauthkeys create -u 1 --reusable --expiration 1h -c "$hs_dir/config.yaml" 2>/dev/null | grep -oE '[a-f0-9]{48,}|hskey-[a-zA-Z0-9_-]+' | head -1 || true)"
    if [ -z "$auth_key" ]; then
        auth_key="$(ip netns exec "$NS_TA" headscale preauthkeys create --user bench --reusable --expiration 1h -c "$hs_dir/config.yaml" 2>/dev/null | grep -oE '[a-f0-9]{48,}|hskey-[a-zA-Z0-9_-]+' | head -1 || true)"
    fi
    if [ -z "$auth_key" ]; then
        echo "[tailscale] SKIP: headscale preauthkey creation failed"
        tail -5 "$TMPDIR_TEST/headscale.log" 2>/dev/null || true
        stop_tailscale; TS_AVAILABLE=false; return 1
    fi
    local ts_dir_a="$TMPDIR_TEST/ts_a"; local ts_dir_b="$TMPDIR_TEST/ts_b"
    mkdir -p "$ts_dir_a" "$ts_dir_b"
    ip netns exec "$NS_TA" tailscaled --state="$ts_dir_a/tailscaled.state" --socket="$ts_dir_a/tailscaled.sock" --tun=tailscale0 >"$TMPDIR_TEST/ts-a.log" 2>&1 &
    PID_TS_DA=$!
    ip netns exec "$NS_TB" tailscaled --state="$ts_dir_b/tailscaled.state" --socket="$ts_dir_b/tailscaled.sock" --tun=tailscale0 >"$TMPDIR_TEST/ts-b.log" 2>&1 &
    PID_TS_DB=$!
    sleep 1
    ip netns exec "$NS_TA" tailscale --socket="$ts_dir_a/tailscaled.sock" up --login-server="http://${VTA_IP}:8080" --auth-key="$auth_key" --accept-dns=false --accept-routes=false >/dev/null 2>&1 || true
    ip netns exec "$NS_TB" tailscale --socket="$ts_dir_b/tailscaled.sock" up --login-server="http://${VTA_IP}:8080" --auth-key="$auth_key" --accept-dns=false --accept-routes=false >/dev/null 2>&1 || true
    local found=false
    local ts_dyn_a="" ts_dyn_b="" ts_dyn6_a="" ts_dyn6_b=""
    for i in $(seq 1 40); do
        ts_dyn_a="$(ip netns exec "$NS_TA" tailscale --socket="$ts_dir_a/tailscaled.sock" ip -4 2>/dev/null | head -1 || true)"
        ts_dyn_b="$(ip netns exec "$NS_TB" tailscale --socket="$ts_dir_b/tailscaled.sock" ip -4 2>/dev/null | head -1 || true)"
        ts_dyn6_a="$(ip netns exec "$NS_TA" tailscale --socket="$ts_dir_a/tailscaled.sock" ip -6 2>/dev/null | grep -v '^fe80' | head -1 || true)"
        ts_dyn6_b="$(ip netns exec "$NS_TB" tailscale --socket="$ts_dir_b/tailscaled.sock" ip -6 2>/dev/null | grep -v '^fe80' | head -1 || true)"
        if [ -n "$ts_dyn_a" ] && [ -n "$ts_dyn_b" ] && [ -n "$ts_dyn6_a" ] && [ -n "$ts_dyn6_b" ]; then
            found=true; break
        fi
        sleep 0.5
    done
    if [ "$found" = false ]; then
        echo "[tailscale] SKIP: tailscale tunnel activation timed out"; stop_tailscale; TS_AVAILABLE=false; return 1
    fi
    TUN_TA_IP="$ts_dyn_a"
    TUN_TB_IP="$ts_dyn_b"
    TUN_TA_IP6="$ts_dyn6_a"
    TUN_TB_IP6="$ts_dyn6_b"
    ip netns exec "$NS_TA" ip link set dev tailscale0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_TB" ip link set dev tailscale0 txqueuelen 10000 2>/dev/null || true
    local ts_up=false
    for i in $(seq 1 20); do
        if ip netns exec "$NS_TB" ping -c 1 -W 1 "$TUN_TA_IP" >/dev/null 2>&1 && \
           ip netns exec "$NS_TB" ping -6 -c 1 -W 1 "$TUN_TA_IP6" >/dev/null 2>&1; then
            ts_up=true
            break
        fi
        sleep 0.5
    done
    if [ "$ts_up" = false ]; then
        echo "[tailscale] SKIP: baseline ping failed"; stop_tailscale; TS_AVAILABLE=false; return 1
    fi
    echo "[tailscale] tunnel up"
    TS_AVAILABLE=true
    return 0
}

stop_tailscale() {
    LAST_CHECK_PIDS=("$PID_TS_DA:tailscaledA" "$PID_TS_DB:tailscaledB" "$PID_TS_HS:headscale")
    [ -n "$PID_TS_DA" ] && kill "$PID_TS_DA" 2>/dev/null || true
    [ -n "$PID_TS_DB" ] && kill "$PID_TS_DB" 2>/dev/null || true
    [ -n "$PID_TS_HS" ] && kill "$PID_TS_HS" 2>/dev/null || true
    sleep 0.1
    [ -n "$PID_TS_DA" ] && kill -9 "$PID_TS_DA" 2>/dev/null || true
    [ -n "$PID_TS_DB" ] && kill -9 "$PID_TS_DB" 2>/dev/null || true
    [ -n "$PID_TS_HS" ] && kill -9 "$PID_TS_HS" 2>/dev/null || true
    [ -n "$PID_TS_DA" ] && wait "$PID_TS_DA" 2>/dev/null || true
    [ -n "$PID_TS_DB" ] && wait "$PID_TS_DB" 2>/dev/null || true
    [ -n "$PID_TS_HS" ] && wait "$PID_TS_HS" 2>/dev/null || true
    PID_TS_DA=""; PID_TS_DB=""; PID_TS_HS=""
    for ns in "$NS_TA" "$NS_TB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMPDIR_TEST/headscale" "$TMPDIR_TEST/ts_a" "$TMPDIR_TEST/ts_b" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle: NetBird
# ══════════════════════════════════════════════════════════════════════════════
start_netbird() {
    if ! contender_wanted "netbird" && ! contender_wanted "nb"; then NB_AVAILABLE=false; return 1; fi
    if [ "${NB_AVAILABLE:-}" = false ]; then return 1; fi
    if ! command -v netbird >/dev/null 2>&1; then
        echo "[netbird] SKIP: 'netbird' not found"; NB_AVAILABLE=false; return 1
    fi
    killall -9 netbird netbird-mgmt netbird-signal 2>/dev/null || true
    local mgmt_url="${NETBIRD_MGMT_URL:-}"
    local setup_key="${NETBIRD_SETUP_KEY:-}"

    echo "[netbird] creating namespaces and veth pair"
    make_pair "$NS_BA" "$NS_BB" "$VBA" "$VBB" "$VBA_IP" "$VBB_IP"

    if [ -z "$mgmt_url" ] || [ -z "$setup_key" ]; then
        if ! command -v netbird-mgmt >/dev/null 2>&1 || ! command -v netbird-signal >/dev/null 2>&1; then
            echo "[netbird] SKIP: 'netbird-mgmt' or 'netbird-signal' not found (run setup-contenders.sh --netbird)"; NB_AVAILABLE=false; return 1
        fi
        local geo_dir="/usr/local/share/netbird-geo"
        mkdir -p "$geo_dir" 2>/dev/null || true
        if [ ! -f "$geo_dir"/GeoLite2-City_*.mmdb ] || [ ! -f "$geo_dir"/geonames_*.db ]; then
            local tmp_geo; tmp_geo="$(mktemp -d /tmp/nb-geo.XXXXXX)"
            cat > "$tmp_geo/config.json" <<EOF
{
  "Signal": { "Proto": "http", "URI": "127.0.0.1:10000" },
  "EmbeddedIdP": { "Enabled": true, "Issuer": "http://127.0.0.1:18999" },
  "Datadir": "$geo_dir"
}
EOF
            netbird-mgmt management --config "$tmp_geo/config.json" --datadir "$geo_dir" --port 18999 --metrics-port 19098 >/dev/null 2>&1 &
            local pid_geo=$!
            for i in $(seq 1 30); do
                if ls "$geo_dir"/GeoLite2-City_*.mmdb >/dev/null 2>&1 && ls "$geo_dir"/geonames_*.db >/dev/null 2>&1; then
                    break
                fi
                sleep 0.5
            done
            kill -9 $pid_geo 2>/dev/null || true
            wait $pid_geo 2>/dev/null || true
            rm -rf "$tmp_geo" "$geo_dir"/store.db "$geo_dir"/events.db "$geo_dir"/access_logs.db "$geo_dir"/idp 2>/dev/null || true
        fi

        local nb_dir="$TMPDIR_TEST/nb_coord"
        mkdir -p "$nb_dir/data"
        if [ -d "$geo_dir" ]; then
            cp -f "$geo_dir"/* "$nb_dir/data/" 2>/dev/null || true
        fi
        cat > "$nb_dir/management.json" <<EOF
{
  "Signal": {
    "Proto": "http",
    "URI": "${VBA_IP}:10000"
  },
  "EmbeddedIdP": {
    "Enabled": true,
    "Issuer": "http://${VBA_IP}:8080"
  },
  "Datadir": "$nb_dir/data"
}
EOF
        ip netns exec "$NS_BA" netbird-signal run --port 10000 --log-file "$TMPDIR_TEST/nb-signal.log" >/dev/null 2>&1 &
        PID_NB_SIG=$!
        ip netns exec "$NS_BA" netbird-mgmt management --config "$nb_dir/management.json" --datadir "$nb_dir/data" --port 8080 --metrics-port 9099 --log-file "$TMPDIR_TEST/nb-mgmt.log" >/dev/null 2>&1 &
        local pid_mgmt=$!
        for i in $(seq 1 40); do
            if [ -f "$nb_dir/data/store.db" ]; then
                break
            fi
            sleep 0.2
        done
        if [ ! -f "$nb_dir/data/store.db" ]; then
            echo "[netbird] SKIP: store.db initialization timed out"; NB_AVAILABLE=false; return 1
        fi
        kill $pid_mgmt 2>/dev/null || true
        wait $pid_mgmt 2>/dev/null || true
        sqlite3 "$nb_dir/data/store.db" <<'SQL'
INSERT INTO accounts (id, created_by, created_at, domain, domain_category, is_domain_primary_account, network_identifier, network_net, network_net_v6, settings_peer_login_expiration_enabled, settings_groups_propagation_enabled, settings_lazy_connection_enabled, settings_ipv6_enabled_groups)
VALUES ('acc_bench', 'usr_bench', datetime('now'), 'netbird.selfhosted', 'private', 1, 'net_bench', '{"IP":"100.64.0.0","Mask":"//8AAA=="}', '{"IP":"fd00:4e42::","Mask":"//////////8AAAAAAAAAAA=="}', 0, 1, 0, '["grp_all"]');

INSERT INTO users (id, account_id, role, is_service_user, non_deletable, created_at, issued)
VALUES ('usr_bench', 'acc_bench', 'owner', 0, 1, datetime('now'), 'api');

INSERT INTO "groups" (id, account_id, public_id, name, issued)
VALUES ('grp_all', 'acc_bench', 'grp_all_pub', 'All', 'api');

INSERT INTO policies (id, public_id, account_id, name, description, enabled)
VALUES ('pol_bench', 'pol_bench_pub', 'acc_bench', 'Default mesh', 'Full connectivity for All group', 1);

INSERT INTO policy_rules (id, policy_id, name, description, enabled, action, destinations, sources, bidirectional, protocol)
VALUES ('rule_bench', 'pol_bench', 'Rule 1', 'Allow all between All', 1, 'accept', '["grp_all"]', '["grp_all"]', 1, 'all');

INSERT INTO setup_keys (id, account_id, key, key_secret, name, type, created_at, expires_at, revoked, usage_limit, ephemeral, auto_groups)
VALUES ('key_bench', 'acc_bench', 'mewqgKYulb4neyT85tvUyw1QzCAhxDjA9+5h7WeAysw=', 'A1B2C****', 'Bench Key', 'reusable', datetime('now'), datetime('now', '+10 years'), 0, 0, 0, '["grp_all"]');
SQL
        ip netns exec "$NS_BA" netbird-mgmt management --config "$nb_dir/management.json" --datadir "$nb_dir/data" --port 8080 --metrics-port 9099 --log-file "$TMPDIR_TEST/nb-mgmt.log" >/dev/null 2>&1 &
        PID_NB_MGMT=$!
        local mgmt_ok=false
        for i in $(seq 1 60); do
            if ip netns exec "$NS_BA" ss -tlpn 2>/dev/null | grep -q ":8080"; then
                mgmt_ok=true
                break
            fi
            sleep 0.25
        done
        if [ "$mgmt_ok" = false ]; then
            echo "[netbird] SKIP: netbird-mgmt port 8080 not listening"
            tail -15 "$TMPDIR_TEST/nb-mgmt.log" 2>/dev/null || true
            NB_AVAILABLE=false; return 1
        fi
        mgmt_url="http://${VBA_IP}:8080"
        setup_key="A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
    fi

    local nb_dir_a="$TMPDIR_TEST/nb_a"; local nb_dir_b="$TMPDIR_TEST/nb_b"
    mkdir -p "$nb_dir_a" "$nb_dir_b"
    ip netns exec "$NS_BA" netbird service run --config "$nb_dir_a/config.json" --daemon-addr "unix://$nb_dir_a/daemon.sock" --log-file "$TMPDIR_TEST/nb-a.log" >/dev/null 2>&1 &
    PID_NB_SA=$!
    ip netns exec "$NS_BB" netbird service run --config "$nb_dir_b/config.json" --daemon-addr "unix://$nb_dir_b/daemon.sock" --log-file "$TMPDIR_TEST/nb-b.log" >/dev/null 2>&1 &
    PID_NB_SB=$!
    for i in $(seq 1 40); do
        if [ -S "$nb_dir_a/daemon.sock" ] && [ -S "$nb_dir_b/daemon.sock" ]; then
            break
        fi
        sleep 0.25
    done
    for i in $(seq 1 10); do
        timeout 6 ip netns exec "$NS_BA" netbird up --daemon-addr "unix://$nb_dir_a/daemon.sock" --management-url "$mgmt_url" --setup-key "$setup_key" --disable-dns --disable-firewall >/dev/null 2>&1 && break || sleep 0.5
    done
    for i in $(seq 1 10); do
        timeout 6 ip netns exec "$NS_BB" netbird up --daemon-addr "unix://$nb_dir_b/daemon.sock" --management-url "$mgmt_url" --setup-key "$setup_key" --disable-dns --disable-firewall >/dev/null 2>&1 && break || sleep 0.5
    done
    local found=false
    for i in $(seq 1 40); do
        if ip netns exec "$NS_BA" ip link show wt0 >/dev/null 2>&1 && \
           ip netns exec "$NS_BB" ip link show wt0 >/dev/null 2>&1; then
            found=true; break
        fi
        sleep 0.5
    done
    if [ "$found" = false ]; then
        echo "[netbird] SKIP: wt0 interface creation timed out"
        tail -15 "$TMPDIR_TEST/nb-mgmt.log" "$TMPDIR_TEST/nb-a.log" "$TMPDIR_TEST/nb-b.log" 2>/dev/null || true
        stop_netbird; NB_AVAILABLE=false; return 1
    fi
    local nb_dyn_a="" nb_dyn_b="" nb_dyn6_a="" nb_dyn6_b=""
    for i in $(seq 1 40); do
        nb_dyn_a="$(ip netns exec "$NS_BA" ip -o -4 addr show wt0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
        nb_dyn_b="$(ip netns exec "$NS_BB" ip -o -4 addr show wt0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
        nb_dyn6_a="$(ip netns exec "$NS_BA" ip -o -6 addr show wt0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^fe80' | head -1 || true)"
        nb_dyn6_b="$(ip netns exec "$NS_BB" ip -o -6 addr show wt0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^fe80' | head -1 || true)"
        if [ -n "$nb_dyn_a" ] && [ -n "$nb_dyn_b" ]; then
            TUN_BA_IP="$nb_dyn_a"
            TUN_BB_IP="$nb_dyn_b"
            if [ -n "$nb_dyn6_a" ] && [ -n "$nb_dyn6_b" ]; then
                TUN_BA_IP6="$nb_dyn6_a"
                TUN_BB_IP6="$nb_dyn6_b"
                break
            fi
        fi
        sleep 0.5
    done
    if [ -n "$nb_dyn6_a" ] && [ -n "$nb_dyn6_b" ]; then
        TUN_BA_IP6="$nb_dyn6_a"
        TUN_BB_IP6="$nb_dyn6_b"
    else
        TUN_BA_IP6=""
        TUN_BB_IP6=""
    fi
    ip netns exec "$NS_BA" ip link set dev wt0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_BB" ip link set dev wt0 txqueuelen 10000 2>/dev/null || true
    local nb_up=false
    for i in $(seq 1 30); do
        if ip netns exec "$NS_BB" ping -c 1 -W 1 "$TUN_BA_IP" >/dev/null 2>&1; then
            nb_up=true
            break
        fi
        sleep 0.5
    done
    if [ "$nb_up" = false ]; then
        echo "[netbird] SKIP: baseline ping failed"; stop_netbird; NB_AVAILABLE=false; return 1
    fi
    if [ -n "$TUN_BA_IP6" ]; then
        for i in $(seq 1 30); do
            if ip netns exec "$NS_BB" ping -c 1 -W 1 "$TUN_BA_IP6" >/dev/null 2>&1; then
                break
            fi
            sleep 0.5
        done
    fi
    echo "[netbird] tunnel up"
    NB_AVAILABLE=true
    return 0
}

stop_netbird() {
    LAST_CHECK_PIDS=("$PID_NB_SA:nb_svcA" "$PID_NB_SB:nb_svcB" "$PID_NB_MGMT:nb_mgmt" "$PID_NB_SIG:nb_sig")
    [ -n "$PID_NB_SA" ] && kill "$PID_NB_SA" 2>/dev/null || true
    [ -n "$PID_NB_SB" ] && kill "$PID_NB_SB" 2>/dev/null || true
    [ -n "$PID_NB_MGMT" ] && kill "$PID_NB_MGMT" 2>/dev/null || true
    [ -n "$PID_NB_SIG" ] && kill "$PID_NB_SIG" 2>/dev/null || true
    sleep 0.1
    [ -n "$PID_NB_SA" ] && kill -9 "$PID_NB_SA" 2>/dev/null || true
    [ -n "$PID_NB_SB" ] && kill -9 "$PID_NB_SB" 2>/dev/null || true
    [ -n "$PID_NB_MGMT" ] && kill -9 "$PID_NB_MGMT" 2>/dev/null || true
    [ -n "$PID_NB_SIG" ] && kill -9 "$PID_NB_SIG" 2>/dev/null || true
    [ -n "$PID_NB_SA" ] && wait "$PID_NB_SA" 2>/dev/null || true
    [ -n "$PID_NB_SB" ] && wait "$PID_NB_SB" 2>/dev/null || true
    [ -n "$PID_NB_MGMT" ] && wait "$PID_NB_MGMT" 2>/dev/null || true
    [ -n "$PID_NB_SIG" ] && wait "$PID_NB_SIG" 2>/dev/null || true
    PID_NB_SA=""; PID_NB_SB=""; PID_NB_MGMT=""; PID_NB_SIG=""
    killall -9 netbird netbird-mgmt netbird-signal 2>/dev/null || true
    for ns in "$NS_BA" "$NS_BB"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMPDIR_TEST/nb_coord" "$TMPDIR_TEST/nb_a" "$TMPDIR_TEST/nb_b" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════════════
# Lifecycle Dispatchers
# ══════════════════════════════════════════════════════════════════════════════
start_contender() {
    local name="$1"
    local rc=0
    case "$name" in
        yip) start_yip || rc=$? ;;
        wireguard|wg) start_wg || rc=$? ;;
        wireguard-go|wggo) start_wireguard_go || rc=$? ;;
        amneziawg|awg) start_awg || rc=$? ;;
        openvpn|ovpn) start_ovpn || rc=$? ;;
        n2n) start_n2n || rc=$? ;;
        zerotier|zt) start_zerotier || rc=$? ;;
        tailscale|ts) start_tailscale || rc=$? ;;
        netbird|nb) start_netbird || rc=$? ;;
        *) echo "[error] unknown contender: $name" >&2; return 1 ;;
    esac
    if [ $rc -ne 0 ]; then
        stop_contender "$name"
        return $rc
    fi
    return 0
}

stop_contender() {
    local name="$1"
    case "$name" in
        yip) stop_yip ;;
        wireguard|wg) stop_wg ;;
        wireguard-go|wggo) stop_wireguard_go ;;
        amneziawg|awg) stop_awg ;;
        openvpn|ovpn) stop_ovpn ;;
        n2n) stop_n2n ;;
        zerotier|zt) stop_zerotier ;;
        tailscale|ts) stop_tailscale ;;
        netbird|nb) stop_netbird ;;
        *) echo "[error] unknown contender: $name" >&2; return 1 ;;
    esac
}

start_all_contenders() {
    contender_wanted "yip" && start_contender "yip" || true
    (contender_wanted "wireguard" || contender_wanted "wg") && start_contender "wireguard" || true
    (contender_wanted "wireguard-go" || contender_wanted "wggo") && start_contender "wireguard-go" || true
    (contender_wanted "amneziawg" || contender_wanted "awg") && start_contender "amneziawg" || true
    (contender_wanted "openvpn" || contender_wanted "ovpn") && start_contender "openvpn" || true
    contender_wanted "n2n" && start_contender "n2n" || true
    (contender_wanted "zerotier" || contender_wanted "zt") && start_contender "zerotier" || true
    (contender_wanted "tailscale" || contender_wanted "ts") && start_contender "tailscale" || true
    (contender_wanted "netbird" || contender_wanted "nb") && start_contender "netbird" || true
}

stop_all_contenders() {
    for c in yip wireguard wireguard-go amneziawg openvpn n2n zerotier tailscale netbird; do
        stop_contender "$c"
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# Sweep
# ══════════════════════════════════════════════════════════════════════════════
LOSS_RATES="${LOSS_RATES:-0 5 10}"

echo ""
echo "=========================================================="
echo "  iperf3 TCP & UDP throughput + ping latency/loss under netem"
echo "  dual-stack IPv4 & IPv6 with CPU telemetry from /proc/stat"
echo "  ping -c ${PING_COUNT} -i ${PING_INTERVAL}; iperf3 -t 8; netem: loss X% delay 5ms (symmetric) limit 50000"
echo "  TCP cc: ${TCP_CC}, streams: ${IPERF_STREAMS}"
echo "  UDP rate: ${UDP_RATE}, len: ${UDP_LEN}"
echo "  contender isolation: ${CONTENDER_ISOLATION}"
echo "=========================================================="

if [ "$CONTENDER_ISOLATION" = false ]; then
    echo "[info] starting all wanted contenders concurrently (CONTENDER_ISOLATION=false)"
    start_all_contenders
fi

for LOSS in $LOSS_RATES; do
    echo ""
    echo "[netem] loss=${LOSS}% delay=5ms on all active pairs"

    if [ "$CONTENDER_ISOLATION" = false ]; then
        apply_netem "$NS_YA" "$NS_YB" "$VYA" "$VYB" "$LOSS"
        [ "$WG_AVAILABLE"   = true ] && apply_netem "$NS_WA" "$NS_WB" "$VWA" "$VWB" "$LOSS"
        [ "$WGGO_AVAILABLE" = true ] && apply_netem "$NS_GGA" "$NS_GGB" "$VGGA" "$VGGB" "$LOSS"
        [ "$AWG_AVAILABLE"  = true ] && apply_netem "$NS_AA" "$NS_AB" "$VAA" "$VAB" "$LOSS"
        [ "$OVPN_AVAILABLE" = true ] && apply_netem "$NS_OA" "$NS_OB" "$VOA" "$VOB" "$LOSS"
        [ "$N2N_AVAILABLE"  = true ] && apply_netem "$NS_NA" "$NS_NB" "$VNA" "$VNB" "$LOSS"
        [ "$ZT_AVAILABLE"   = true ] && apply_netem "$NS_ZA" "$NS_ZB" "$VZA" "$VZB" "$LOSS"
        [ "$TS_AVAILABLE"   = true ] && apply_netem "$NS_TA" "$NS_TB" "$VTA" "$VTB" "$LOSS"
        [ "$NB_AVAILABLE"   = true ] && apply_netem "$NS_BA" "$NS_BB" "$VBA" "$VBB" "$LOSS"
    fi

    # ── yip ───────────────────────────────────────────────────────────────────
    Y_LOSS="N/A"; Y_RTT="N/A"; Y_TCP="N/A"; Y_TCP_LOSS="N/A"; Y_UDP_MBPS="N/A"; Y_UDP_LOSS="N/A"; Y_CPU="N/A"; Y_EFF="N/A"; Y_RAM="N/A"; Y_RAM_EFF="N/A"
    Y6_LOSS="N/A"; Y6_RTT="N/A"; Y6_TCP="N/A"; Y6_TCP_LOSS="N/A"; Y6_UDP_MBPS="N/A"; Y6_UDP_LOSS="N/A"; Y6_CPU="N/A"; Y6_EFF="N/A"; Y6_RAM="N/A"; Y6_RAM_EFF="N/A"
    if contender_wanted "yip"; then
        if [ "$CONTENDER_ISOLATION" = true ]; then
            start_contender "yip"
            apply_netem "$NS_YA" "$NS_YB" "$VYA" "$VYB" "$LOSS"
        fi
        measure_contender "yip" "$NS_YA" "$NS_YB" "$TUN_YA_IP" "$TUN_YA_IP6" "$LOSS"
        Y_LOSS="$M_LOSS"; Y_RTT="$M_RTT"; Y_TCP="$M_TCP"; Y_TCP_LOSS="$M_TCP_LOSS"; Y_UDP_MBPS="$M_UDP_MBPS"; Y_UDP_LOSS="$M_UDP_LOSS"; Y_CPU="$M_CPU"; Y_EFF="$M_EFF"; Y_RAM="$M_RAM"; Y_RAM_EFF="$M_RAM_EFF"
        Y6_LOSS="$M6_LOSS"; Y6_RTT="$M6_RTT"; Y6_TCP="$M6_TCP"; Y6_TCP_LOSS="$M6_TCP_LOSS"; Y6_UDP_MBPS="$M6_UDP_MBPS"; Y6_UDP_LOSS="$M6_UDP_LOSS"; Y6_CPU="$M6_CPU"; Y6_EFF="$M6_EFF"; Y6_RAM="$M6_RAM"; Y6_RAM_EFF="$M6_RAM_EFF"

        if [ "$Y_TCP" = "0.0" ] || [ "$Y_TCP" = "N/A" ] || \
           [ "$Y6_TCP" = "0.0" ] || [ "$Y6_TCP" = "N/A" ] || \
           [ "$Y_UDP_MBPS" = "0.0" ] || [ "$Y_UDP_MBPS" = "N/A" ] || \
           [ "$Y6_UDP_MBPS" = "0.0" ] || [ "$Y6_UDP_MBPS" = "N/A" ]; then
            echo "[error] yip throughput failure detected at loss=${LOSS}% (v4_tcp=$Y_TCP v6_tcp=$Y6_TCP v4_udp=$Y_UDP_MBPS v6_udp=$Y6_UDP_MBPS)"
            YIP_FAILED=true
        fi
        if [ "$CONTENDER_ISOLATION" = true ]; then
            stop_contender "yip"
            verify_isolation "yip"
        fi
    fi

    # ── WireGuard ─────────────────────────────────────────────────────────────
    W_LOSS="N/A"; W_RTT="N/A"; W_TCP="N/A"; W_TCP_LOSS="N/A"; W_UDP_MBPS="N/A"; W_UDP_LOSS="N/A"; W_CPU="N/A"; W_EFF="N/A"; W_RAM="N/A"; W_RAM_EFF="N/A"
    W6_LOSS="N/A"; W6_RTT="N/A"; W6_TCP="N/A"; W6_TCP_LOSS="N/A"; W6_UDP_MBPS="N/A"; W6_UDP_LOSS="N/A"; W6_CPU="N/A"; W6_EFF="N/A"; W6_RAM="N/A"; W6_RAM_EFF="N/A"
    if (contender_wanted "wireguard" || contender_wanted "wg") && [ "${WG_AVAILABLE:-true}" != false ]; then
        if [ "$CONTENDER_ISOLATION" = true ]; then
            if start_contender "wireguard"; then
                apply_netem "$NS_WA" "$NS_WB" "$VWA" "$VWB" "$LOSS"
                measure_contender "wg" "$NS_WA" "$NS_WB" "$TUN_WA_IP" "$TUN_WA_IP6" "$LOSS"
                W_LOSS="$M_LOSS"; W_RTT="$M_RTT"; W_TCP="$M_TCP"; W_TCP_LOSS="$M_TCP_LOSS"; W_UDP_MBPS="$M_UDP_MBPS"; W_UDP_LOSS="$M_UDP_LOSS"; W_CPU="$M_CPU"; W_EFF="$M_EFF"; W_RAM="$M_RAM"; W_RAM_EFF="$M_RAM_EFF"
                W6_LOSS="$M6_LOSS"; W6_RTT="$M6_RTT"; W6_TCP="$M6_TCP"; W6_TCP_LOSS="$M6_TCP_LOSS"; W6_UDP_MBPS="$M6_UDP_MBPS"; W6_UDP_LOSS="$M6_UDP_LOSS"; W6_CPU="$M6_CPU"; W6_EFF="$M6_EFF"; W6_RAM="$M6_RAM"; W6_RAM_EFF="$M6_RAM_EFF"
                stop_contender "wireguard"
                verify_isolation "wireguard"
            fi
        elif [ "$WG_AVAILABLE" = true ]; then
            measure_contender "wg" "$NS_WA" "$NS_WB" "$TUN_WA_IP" "$TUN_WA_IP6" "$LOSS"
            W_LOSS="$M_LOSS"; W_RTT="$M_RTT"; W_TCP="$M_TCP"; W_TCP_LOSS="$M_TCP_LOSS"; W_UDP_MBPS="$M_UDP_MBPS"; W_UDP_LOSS="$M_UDP_LOSS"; W_CPU="$M_CPU"; W_EFF="$M_EFF"; W_RAM="$M_RAM"; W_RAM_EFF="$M_RAM_EFF"
            W6_LOSS="$M6_LOSS"; W6_RTT="$M6_RTT"; W6_TCP="$M6_TCP"; W6_TCP_LOSS="$M6_TCP_LOSS"; W6_UDP_MBPS="$M6_UDP_MBPS"; W6_UDP_LOSS="$M6_UDP_LOSS"; W6_CPU="$M6_CPU"; W6_EFF="$M6_EFF"; W6_RAM="$M6_RAM"; W6_RAM_EFF="$M6_RAM_EFF"
        fi
    fi

    # ── WireGuard-Go ──────────────────────────────────────────────────────────
    GG_LOSS="N/A"; GG_RTT="N/A"; GG_TCP="N/A"; GG_TCP_LOSS="N/A"; GG_UDP_MBPS="N/A"; GG_UDP_LOSS="N/A"; GG_CPU="N/A"; GG_EFF="N/A"; GG_RAM="N/A"; GG_RAM_EFF="N/A"
    GG6_LOSS="N/A"; GG6_RTT="N/A"; GG6_TCP="N/A"; GG6_TCP_LOSS="N/A"; GG6_UDP_MBPS="N/A"; GG6_UDP_LOSS="N/A"; GG6_CPU="N/A"; GG6_EFF="N/A"; GG6_RAM="N/A"; GG6_RAM_EFF="N/A"
    if (contender_wanted "wireguard-go" || contender_wanted "wggo") && [ "${WGGO_AVAILABLE:-true}" != false ]; then
        if [ "$CONTENDER_ISOLATION" = true ]; then
            if start_contender "wireguard-go"; then
                apply_netem "$NS_GGA" "$NS_GGB" "$VGGA" "$VGGB" "$LOSS"
                measure_contender "wggo" "$NS_GGA" "$NS_GGB" "$TUN_GGA_IP" "$TUN_GGA_IP6" "$LOSS"
                GG_LOSS="$M_LOSS"; GG_RTT="$M_RTT"; GG_TCP="$M_TCP"; GG_TCP_LOSS="$M_TCP_LOSS"; GG_UDP_MBPS="$M_UDP_MBPS"; GG_UDP_LOSS="$M_UDP_LOSS"; GG_CPU="$M_CPU"; GG_EFF="$M_EFF"; GG_RAM="$M_RAM"; GG_RAM_EFF="$M_RAM_EFF"
                GG6_LOSS="$M6_LOSS"; GG6_RTT="$M6_RTT"; GG6_TCP="$M6_TCP"; GG6_TCP_LOSS="$M6_TCP_LOSS"; GG6_UDP_MBPS="$M6_UDP_MBPS"; GG6_UDP_LOSS="$M6_UDP_LOSS"; GG6_CPU="$M6_CPU"; GG6_EFF="$M6_EFF"; GG6_RAM="$M6_RAM"; GG6_RAM_EFF="$M6_RAM_EFF"
                stop_contender "wireguard-go"
                verify_isolation "wireguard-go"
            fi
        elif [ "$WGGO_AVAILABLE" = true ]; then
            measure_contender "wggo" "$NS_GGA" "$NS_GGB" "$TUN_GGA_IP" "$TUN_GGA_IP6" "$LOSS"
            GG_LOSS="$M_LOSS"; GG_RTT="$M_RTT"; GG_TCP="$M_TCP"; GG_TCP_LOSS="$M_TCP_LOSS"; GG_UDP_MBPS="$M_UDP_MBPS"; GG_UDP_LOSS="$M_UDP_LOSS"; GG_CPU="$M_CPU"; GG_EFF="$M_EFF"; GG_RAM="$M_RAM"; GG_RAM_EFF="$M_RAM_EFF"
            GG6_LOSS="$M6_LOSS"; GG6_RTT="$M6_RTT"; GG6_TCP="$M6_TCP"; GG6_TCP_LOSS="$M6_TCP_LOSS"; GG6_UDP_MBPS="$M6_UDP_MBPS"; GG6_UDP_LOSS="$M6_UDP_LOSS"; GG6_CPU="$M6_CPU"; GG6_EFF="$M6_EFF"; GG6_RAM="$M6_RAM"; GG6_RAM_EFF="$M6_RAM_EFF"
        fi
    fi

    # ── AmneziaWG ─────────────────────────────────────────────────────────────
    A_LOSS="N/A"; A_RTT="N/A"; A_TCP="N/A"; A_TCP_LOSS="N/A"; A_UDP_MBPS="N/A"; A_UDP_LOSS="N/A"; A_CPU="N/A"; A_EFF="N/A"; A_RAM="N/A"; A_RAM_EFF="N/A"
    A6_LOSS="N/A"; A6_RTT="N/A"; A6_TCP="N/A"; A6_TCP_LOSS="N/A"; A6_UDP_MBPS="N/A"; A6_UDP_LOSS="N/A"; A6_CPU="N/A"; A6_EFF="N/A"; A6_RAM="N/A"; A6_RAM_EFF="N/A"
    if (contender_wanted "amneziawg" || contender_wanted "awg") && [ "${AWG_AVAILABLE:-true}" != false ]; then
        if [ "$CONTENDER_ISOLATION" = true ]; then
            if start_contender "amneziawg"; then
                apply_netem "$NS_AA" "$NS_AB" "$VAA" "$VAB" "$LOSS"
                measure_contender "awg" "$NS_AA" "$NS_AB" "$TUN_AA_IP" "$TUN_AA_IP6" "$LOSS"
                A_LOSS="$M_LOSS"; A_RTT="$M_RTT"; A_TCP="$M_TCP"; A_TCP_LOSS="$M_TCP_LOSS"; A_UDP_MBPS="$M_UDP_MBPS"; A_UDP_LOSS="$M_UDP_LOSS"; A_CPU="$M_CPU"; A_EFF="$M_EFF"; A_RAM="$M_RAM"; A_RAM_EFF="$M_RAM_EFF"
                A6_LOSS="$M6_LOSS"; A6_RTT="$M6_RTT"; A6_TCP="$M6_TCP"; A6_TCP_LOSS="$M6_TCP_LOSS"; A6_UDP_MBPS="$M6_UDP_MBPS"; A6_UDP_LOSS="$M6_UDP_LOSS"; A6_CPU="$M6_CPU"; A6_EFF="$M6_EFF"; A6_RAM="$M6_RAM"; A6_RAM_EFF="$M6_RAM_EFF"
                stop_contender "amneziawg"
                verify_isolation "amneziawg"
            fi
        elif [ "$AWG_AVAILABLE" = true ]; then
            measure_contender "awg" "$NS_AA" "$NS_AB" "$TUN_AA_IP" "$TUN_AA_IP6" "$LOSS"
            A_LOSS="$M_LOSS"; A_RTT="$M_RTT"; A_TCP="$M_TCP"; A_TCP_LOSS="$M_TCP_LOSS"; A_UDP_MBPS="$M_UDP_MBPS"; A_UDP_LOSS="$M_UDP_LOSS"; A_CPU="$M_CPU"; A_EFF="$M_EFF"; A_RAM="$M_RAM"; A_RAM_EFF="$M_RAM_EFF"
            A6_LOSS="$M6_LOSS"; A6_RTT="$M6_RTT"; A6_TCP="$M6_TCP"; A6_TCP_LOSS="$M6_TCP_LOSS"; A6_UDP_MBPS="$M6_UDP_MBPS"; A6_UDP_LOSS="$M6_UDP_LOSS"; A6_CPU="$M6_CPU"; A6_EFF="$M6_EFF"; A6_RAM="$M6_RAM"; A6_RAM_EFF="$M6_RAM_EFF"
        fi
    fi

    # ── OpenVPN ───────────────────────────────────────────────────────────────
    O_LOSS="N/A"; O_RTT="N/A"; O_TCP="N/A"; O_TCP_LOSS="N/A"; O_UDP_MBPS="N/A"; O_UDP_LOSS="N/A"; O_CPU="N/A"; O_EFF="N/A"; O_RAM="N/A"; O_RAM_EFF="N/A"
    O6_LOSS="N/A"; O6_RTT="N/A"; O6_TCP="N/A"; O6_TCP_LOSS="N/A"; O6_UDP_MBPS="N/A"; O6_UDP_LOSS="N/A"; O6_CPU="N/A"; O6_EFF="N/A"; O6_RAM="N/A"; O6_RAM_EFF="N/A"
    if (contender_wanted "openvpn" || contender_wanted "ovpn") && [ "${OVPN_AVAILABLE:-true}" != false ]; then
        if [ "$CONTENDER_ISOLATION" = true ]; then
            if start_contender "openvpn"; then
                apply_netem "$NS_OA" "$NS_OB" "$VOA" "$VOB" "$LOSS"
                measure_contender "ovpn" "$NS_OA" "$NS_OB" "$TUN_OA_IP" "$TUN_OA_IP6" "$LOSS"
                O_LOSS="$M_LOSS"; O_RTT="$M_RTT"; O_TCP="$M_TCP"; O_TCP_LOSS="$M_TCP_LOSS"; O_UDP_MBPS="$M_UDP_MBPS"; O_UDP_LOSS="$M_UDP_LOSS"; O_CPU="$M_CPU"; O_EFF="$M_EFF"; O_RAM="$M_RAM"; O_RAM_EFF="$M_RAM_EFF"
                O6_LOSS="$M6_LOSS"; O6_RTT="$M6_RTT"; O6_TCP="$M6_TCP"; O6_TCP_LOSS="$M6_TCP_LOSS"; O6_UDP_MBPS="$M6_UDP_MBPS"; O6_UDP_LOSS="$M6_UDP_LOSS"; O6_CPU="$M6_CPU"; O6_EFF="$M6_EFF"; O6_RAM="$M6_RAM"; O6_RAM_EFF="$M6_RAM_EFF"
                stop_contender "openvpn"
                verify_isolation "openvpn"
            fi
        elif [ "$OVPN_AVAILABLE" = true ]; then
            measure_contender "ovpn" "$NS_OA" "$NS_OB" "$TUN_OA_IP" "$TUN_OA_IP6" "$LOSS"
            O_LOSS="$M_LOSS"; O_RTT="$M_RTT"; O_TCP="$M_TCP"; O_TCP_LOSS="$M_TCP_LOSS"; O_UDP_MBPS="$M_UDP_MBPS"; O_UDP_LOSS="$M_UDP_LOSS"; O_CPU="$M_CPU"; O_EFF="$M_EFF"; O_RAM="$M_RAM"; O_RAM_EFF="$M_RAM_EFF"
            O6_LOSS="$M6_LOSS"; O6_RTT="$M6_RTT"; O6_TCP="$M6_TCP"; O6_TCP_LOSS="$M6_TCP_LOSS"; O6_UDP_MBPS="$M6_UDP_MBPS"; O6_UDP_LOSS="$M6_UDP_LOSS"; O6_CPU="$M6_CPU"; O6_EFF="$M6_EFF"; O6_RAM="$M6_RAM"; O6_RAM_EFF="$M6_RAM_EFF"
        fi
    fi

    # ── n2n ───────────────────────────────────────────────────────────────────
    N_LOSS="N/A"; N_RTT="N/A"; N_TCP="N/A"; N_TCP_LOSS="N/A"; N_UDP_MBPS="N/A"; N_UDP_LOSS="N/A"; N_CPU="N/A"; N_EFF="N/A"; N_RAM="N/A"; N_RAM_EFF="N/A"
    N6_LOSS="N/A"; N6_RTT="N/A"; N6_TCP="N/A"; N6_TCP_LOSS="N/A"; N6_UDP_MBPS="N/A"; N6_UDP_LOSS="N/A"; N6_CPU="N/A"; N6_EFF="N/A"; N6_RAM="N/A"; N6_RAM_EFF="N/A"
    if contender_wanted "n2n" && [ "${N2N_AVAILABLE:-true}" != false ]; then
        if [ "$CONTENDER_ISOLATION" = true ]; then
            if start_contender "n2n"; then
                apply_netem "$NS_NA" "$NS_NB" "$VNA" "$VNB" "$LOSS"
                measure_contender "n2n" "$NS_NA" "$NS_NB" "$OVL_NA_IP" "$OVL_NA_IP6" "$LOSS"
                N_LOSS="$M_LOSS"; N_RTT="$M_RTT"; N_TCP="$M_TCP"; N_TCP_LOSS="$M_TCP_LOSS"; N_UDP_MBPS="$M_UDP_MBPS"; N_UDP_LOSS="$M_UDP_LOSS"; N_CPU="$M_CPU"; N_EFF="$M_EFF"; N_RAM="$M_RAM"; N_RAM_EFF="$M_RAM_EFF"
                N6_LOSS="$M6_LOSS"; N6_RTT="$M6_RTT"; N6_TCP="$M6_TCP"; N6_TCP_LOSS="$M6_TCP_LOSS"; N6_UDP_MBPS="$M6_UDP_MBPS"; N6_UDP_LOSS="$M6_UDP_LOSS"; N6_CPU="$M6_CPU"; N6_EFF="$M6_EFF"; N6_RAM="$M6_RAM"; N6_RAM_EFF="$M6_RAM_EFF"
                stop_contender "n2n"
                verify_isolation "n2n"
            fi
        elif [ "$N2N_AVAILABLE" = true ]; then
            measure_contender "n2n" "$NS_NA" "$NS_NB" "$OVL_NA_IP" "$OVL_NA_IP6" "$LOSS"
            N_LOSS="$M_LOSS"; N_RTT="$M_RTT"; N_TCP="$M_TCP"; N_TCP_LOSS="$M_TCP_LOSS"; N_UDP_MBPS="$M_UDP_MBPS"; N_UDP_LOSS="$M_UDP_LOSS"; N_CPU="$M_CPU"; N_EFF="$M_EFF"; N_RAM="$M_RAM"; N_RAM_EFF="$M_RAM_EFF"
            N6_LOSS="$M6_LOSS"; N6_RTT="$M6_RTT"; N6_TCP="$M6_TCP"; N6_TCP_LOSS="$M6_TCP_LOSS"; N6_UDP_MBPS="$M6_UDP_MBPS"; N6_UDP_LOSS="$M6_UDP_LOSS"; N6_CPU="$M6_CPU"; N6_EFF="$M6_EFF"; N6_RAM="$M6_RAM"; N6_RAM_EFF="$M6_RAM_EFF"
        fi
    fi

    # ── ZeroTier ──────────────────────────────────────────────────────────────
    Z_LOSS="N/A"; Z_RTT="N/A"; Z_TCP="N/A"; Z_TCP_LOSS="N/A"; Z_UDP_MBPS="N/A"; Z_UDP_LOSS="N/A"; Z_CPU="N/A"; Z_EFF="N/A"; Z_RAM="N/A"; Z_RAM_EFF="N/A"
    Z6_LOSS="N/A"; Z6_RTT="N/A"; Z6_TCP="N/A"; Z6_TCP_LOSS="N/A"; Z6_UDP_MBPS="N/A"; Z6_UDP_LOSS="N/A"; Z6_CPU="N/A"; Z6_EFF="N/A"; Z6_RAM="N/A"; Z6_RAM_EFF="N/A"
    if (contender_wanted "zerotier" || contender_wanted "zt") && [ "${ZT_AVAILABLE:-true}" != false ]; then
        if [ "$CONTENDER_ISOLATION" = true ]; then
            if start_contender "zerotier"; then
                apply_netem "$NS_ZA" "$NS_ZB" "$VZA" "$VZB" "$LOSS"
                measure_contender "zerotier" "$NS_ZA" "$NS_ZB" "$TUN_ZA_IP" "$TUN_ZA_IP6" "$LOSS"
                Z_LOSS="$M_LOSS"; Z_RTT="$M_RTT"; Z_TCP="$M_TCP"; Z_TCP_LOSS="$M_TCP_LOSS"; Z_UDP_MBPS="$M_UDP_MBPS"; Z_UDP_LOSS="$M_UDP_LOSS"; Z_CPU="$M_CPU"; Z_EFF="$M_EFF"; Z_RAM="$M_RAM"; Z_RAM_EFF="$M_RAM_EFF"
                Z6_LOSS="$M6_LOSS"; Z6_RTT="$M6_RTT"; Z6_TCP="$M6_TCP"; Z6_TCP_LOSS="$M6_TCP_LOSS"; Z6_UDP_MBPS="$M6_UDP_MBPS"; Z6_UDP_LOSS="$M6_UDP_LOSS"; Z6_CPU="$M6_CPU"; Z6_EFF="$M6_EFF"; Z6_RAM="$M6_RAM"; Z6_RAM_EFF="$M6_RAM_EFF"
                stop_contender "zerotier"
                verify_isolation "zerotier"
            fi
        elif [ "$ZT_AVAILABLE" = true ]; then
            measure_contender "zerotier" "$NS_ZA" "$NS_ZB" "$TUN_ZA_IP" "$TUN_ZA_IP6" "$LOSS"
            Z_LOSS="$M_LOSS"; Z_RTT="$M_RTT"; Z_TCP="$M_TCP"; Z_TCP_LOSS="$M_TCP_LOSS"; Z_UDP_MBPS="$M_UDP_MBPS"; Z_UDP_LOSS="$M_UDP_LOSS"; Z_CPU="$M_CPU"; Z_EFF="$M_EFF"; Z_RAM="$M_RAM"; Z_RAM_EFF="$M_RAM_EFF"
            Z6_LOSS="$M6_LOSS"; Z6_RTT="$M6_RTT"; Z6_TCP="$M6_TCP"; Z6_TCP_LOSS="$M6_TCP_LOSS"; Z6_UDP_MBPS="$M6_UDP_MBPS"; Z6_UDP_LOSS="$M6_UDP_LOSS"; Z6_CPU="$M6_CPU"; Z6_EFF="$M6_EFF"; Z6_RAM="$M6_RAM"; Z6_RAM_EFF="$M6_RAM_EFF"
        fi
    fi

    # ── Tailscale ─────────────────────────────────────────────────────────────
    T_LOSS="N/A"; T_RTT="N/A"; T_TCP="N/A"; T_TCP_LOSS="N/A"; T_UDP_MBPS="N/A"; T_UDP_LOSS="N/A"; T_CPU="N/A"; T_EFF="N/A"; T_RAM="N/A"; T_RAM_EFF="N/A"
    T6_LOSS="N/A"; T6_RTT="N/A"; T6_TCP="N/A"; T6_TCP_LOSS="N/A"; T6_UDP_MBPS="N/A"; T6_UDP_LOSS="N/A"; T6_CPU="N/A"; T6_EFF="N/A"; T6_RAM="N/A"; T6_RAM_EFF="N/A"
    if (contender_wanted "tailscale" || contender_wanted "ts") && [ "${TS_AVAILABLE:-true}" != false ]; then
        if [ "$CONTENDER_ISOLATION" = true ]; then
            if start_contender "tailscale"; then
                apply_netem "$NS_TA" "$NS_TB" "$VTA" "$VTB" "$LOSS"
                measure_contender "tailscale" "$NS_TA" "$NS_TB" "$TUN_TA_IP" "$TUN_TA_IP6" "$LOSS"
                T_LOSS="$M_LOSS"; T_RTT="$M_RTT"; T_TCP="$M_TCP"; T_TCP_LOSS="$M_TCP_LOSS"; T_UDP_MBPS="$M_UDP_MBPS"; T_UDP_LOSS="$M_UDP_LOSS"; T_CPU="$M_CPU"; T_EFF="$M_EFF"; T_RAM="$M_RAM"; T_RAM_EFF="$M_RAM_EFF"
                T6_LOSS="$M6_LOSS"; T6_RTT="$M6_RTT"; T6_TCP="$M6_TCP"; T6_TCP_LOSS="$M6_TCP_LOSS"; T6_UDP_MBPS="$M6_UDP_MBPS"; T6_UDP_LOSS="$M6_UDP_LOSS"; T6_CPU="$M6_CPU"; T6_EFF="$M6_EFF"; T6_RAM="$M6_RAM"; T6_RAM_EFF="$M6_RAM_EFF"
                stop_contender "tailscale"
                verify_isolation "tailscale"
            fi
        elif [ "$TS_AVAILABLE" = true ]; then
            measure_contender "tailscale" "$NS_TA" "$NS_TB" "$TUN_TA_IP" "$TUN_TA_IP6" "$LOSS"
            T_LOSS="$M_LOSS"; T_RTT="$M_RTT"; T_TCP="$M_TCP"; T_TCP_LOSS="$M_TCP_LOSS"; T_UDP_MBPS="$M_UDP_MBPS"; T_UDP_LOSS="$M_UDP_LOSS"; T_CPU="$M_CPU"; T_EFF="$M_EFF"; T_RAM="$M_RAM"; T_RAM_EFF="$M_RAM_EFF"
            T6_LOSS="$M6_LOSS"; T6_RTT="$M6_RTT"; T6_TCP="$M6_TCP"; T6_TCP_LOSS="$M6_TCP_LOSS"; T6_UDP_MBPS="$M6_UDP_MBPS"; T6_UDP_LOSS="$M6_UDP_LOSS"; T6_CPU="$M6_CPU"; T6_EFF="$M6_EFF"; T6_RAM="$M6_RAM"; T6_RAM_EFF="$M6_RAM_EFF"
        fi
    fi

    # ── NetBird ───────────────────────────────────────────────────────────────
    B_LOSS="N/A"; B_RTT="N/A"; B_TCP="N/A"; B_TCP_LOSS="N/A"; B_UDP_MBPS="N/A"; B_UDP_LOSS="N/A"; B_CPU="N/A"; B_EFF="N/A"; B_RAM="N/A"; B_RAM_EFF="N/A"
    B6_LOSS="N/A"; B6_RTT="N/A"; B6_TCP="N/A"; B6_TCP_LOSS="N/A"; B6_UDP_MBPS="N/A"; B6_UDP_LOSS="N/A"; B6_CPU="N/A"; B6_EFF="N/A"; B6_RAM="N/A"; B6_RAM_EFF="N/A"
    if (contender_wanted "netbird" || contender_wanted "nb") && [ "${NB_AVAILABLE:-true}" != false ]; then
        if [ "$CONTENDER_ISOLATION" = true ]; then
            if start_contender "netbird"; then
                apply_netem "$NS_BA" "$NS_BB" "$VBA" "$VBB" "$LOSS"
                measure_contender "netbird" "$NS_BA" "$NS_BB" "$TUN_BA_IP" "$TUN_BA_IP6" "$LOSS"
                B_LOSS="$M_LOSS"; B_RTT="$M_RTT"; B_TCP="$M_TCP"; B_TCP_LOSS="$M_TCP_LOSS"; B_UDP_MBPS="$M_UDP_MBPS"; B_UDP_LOSS="$M_UDP_LOSS"; B_CPU="$M_CPU"; B_EFF="$M_EFF"; B_RAM="$M_RAM"; B_RAM_EFF="$M_RAM_EFF"
                B6_LOSS="$M6_LOSS"; B6_RTT="$M6_RTT"; B6_TCP="$M6_TCP"; B6_TCP_LOSS="$M6_TCP_LOSS"; B6_UDP_MBPS="$M6_UDP_MBPS"; B6_UDP_LOSS="$M6_UDP_LOSS"; B6_CPU="$M6_CPU"; B6_EFF="$M6_EFF"; B6_RAM="$M6_RAM"; B6_RAM_EFF="$M6_RAM_EFF"
                stop_contender "netbird"
                verify_isolation "netbird"
            fi
        elif [ "$NB_AVAILABLE" = true ]; then
            measure_contender "netbird" "$NS_BA" "$NS_BB" "$TUN_BA_IP" "$TUN_BA_IP6" "$LOSS"
            B_LOSS="$M_LOSS"; B_RTT="$M_RTT"; B_TCP="$M_TCP"; B_TCP_LOSS="$M_TCP_LOSS"; B_UDP_MBPS="$M_UDP_MBPS"; B_UDP_LOSS="$M_UDP_LOSS"; B_CPU="$M_CPU"; B_EFF="$M_EFF"; B_RAM="$M_RAM"; B_RAM_EFF="$M_RAM_EFF"
            B6_LOSS="$M6_LOSS"; B6_RTT="$M6_RTT"; B6_TCP="$M6_TCP"; B6_TCP_LOSS="$M6_TCP_LOSS"; B6_UDP_MBPS="$M6_UDP_MBPS"; B6_UDP_LOSS="$M6_UDP_LOSS"; B6_CPU="$M6_CPU"; B6_EFF="$M6_EFF"; B6_RAM="$M6_RAM"; B6_RAM_EFF="$M6_RAM_EFF"
        fi
    fi

    # ── emit per-loss-rate tables ─────────────────────────────────────────────
    YIP_LABEL="yip"
    if [ "$YIP_SHARDS" = "auto" ]; then
        YIP_LABEL="yip(auto)"
    elif [ "$YIP_SHARDS" -gt 1 ] 2>/dev/null; then
        YIP_LABEL="yip(s=$YIP_SHARDS)"
    fi

    echo ""
    echo "  --- IPv4 loss=${LOSS}% ---"
    echo "  | contender    | eff_loss% | rtt_ms | tcp_Mbit/s | tcp_loss% | udp_Mbit/s | udp_loss% | cpu% | cpu_eff(%/Gbps) | ram_MB | ram_eff(MB/Gbps) |"
    echo "  |--------------|-----------|--------|------------|-----------|------------|-----------|------|-----------------|--------|------------------|"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "$YIP_LABEL" "$Y_LOSS" "$Y_RTT" "$Y_TCP" "$Y_TCP_LOSS" "$Y_UDP_MBPS" "$Y_UDP_LOSS" "$Y_CPU" "$Y_EFF" "$Y_RAM" "$Y_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "wireguard" "$W_LOSS" "$W_RTT" "$W_TCP" "$W_TCP_LOSS" "$W_UDP_MBPS" "$W_UDP_LOSS" "$W_CPU" "$W_EFF" "$W_RAM" "$W_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "wireguard-go" "$GG_LOSS" "$GG_RTT" "$GG_TCP" "$GG_TCP_LOSS" "$GG_UDP_MBPS" "$GG_UDP_LOSS" "$GG_CPU" "$GG_EFF" "$GG_RAM" "$GG_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "amneziawg" "$A_LOSS" "$A_RTT" "$A_TCP" "$A_TCP_LOSS" "$A_UDP_MBPS" "$A_UDP_LOSS" "$A_CPU" "$A_EFF" "$A_RAM" "$A_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "openvpn"   "$O_LOSS" "$O_RTT" "$O_TCP" "$O_TCP_LOSS" "$O_UDP_MBPS" "$O_UDP_LOSS" "$O_CPU" "$O_EFF" "$O_RAM" "$O_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "n2n"       "$N_LOSS" "$N_RTT" "$N_TCP" "$N_TCP_LOSS" "$N_UDP_MBPS" "$N_UDP_LOSS" "$N_CPU" "$N_EFF" "$N_RAM" "$N_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "zerotier"  "$Z_LOSS" "$Z_RTT" "$Z_TCP" "$Z_TCP_LOSS" "$Z_UDP_MBPS" "$Z_UDP_LOSS" "$Z_CPU" "$Z_EFF" "$Z_RAM" "$Z_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "tailscale" "$T_LOSS" "$T_RTT" "$T_TCP" "$T_TCP_LOSS" "$T_UDP_MBPS" "$T_UDP_LOSS" "$T_CPU" "$T_EFF" "$T_RAM" "$T_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "netbird"   "$B_LOSS" "$B_RTT" "$B_TCP" "$B_TCP_LOSS" "$B_UDP_MBPS" "$B_UDP_LOSS" "$B_CPU" "$B_EFF" "$B_RAM" "$B_RAM_EFF"

    echo ""
    echo "  --- IPv6 loss=${LOSS}% ---"
    echo "  | contender    | eff_loss% | rtt_ms | tcp_Mbit/s | tcp_loss% | udp_Mbit/s | udp_loss% | cpu% | cpu_eff(%/Gbps) | ram_MB | ram_eff(MB/Gbps) |"
    echo "  |--------------|-----------|--------|------------|-----------|------------|-----------|------|-----------------|--------|------------------|"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "$YIP_LABEL" "$Y6_LOSS" "$Y6_RTT" "$Y6_TCP" "$Y6_TCP_LOSS" "$Y6_UDP_MBPS" "$Y6_UDP_LOSS" "$Y6_CPU" "$Y6_EFF" "$Y6_RAM" "$Y6_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "wireguard" "$W6_LOSS" "$W6_RTT" "$W6_TCP" "$W6_TCP_LOSS" "$W6_UDP_MBPS" "$W6_UDP_LOSS" "$W6_CPU" "$W6_EFF" "$W6_RAM" "$W6_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "wireguard-go" "$GG6_LOSS" "$GG6_RTT" "$GG6_TCP" "$GG6_TCP_LOSS" "$GG6_UDP_MBPS" "$GG6_UDP_LOSS" "$GG6_CPU" "$GG6_EFF" "$GG6_RAM" "$GG6_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "amneziawg" "$A6_LOSS" "$A6_RTT" "$A6_TCP" "$A6_TCP_LOSS" "$A6_UDP_MBPS" "$A6_UDP_LOSS" "$A6_CPU" "$A6_EFF" "$A6_RAM" "$A6_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "openvpn"   "$O6_LOSS" "$O6_RTT" "$O6_TCP" "$O6_TCP_LOSS" "$O6_UDP_MBPS" "$O6_UDP_LOSS" "$O6_CPU" "$O6_EFF" "$O6_RAM" "$O6_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "n2n"       "$N6_LOSS" "$N6_RTT" "$N6_TCP" "$N6_TCP_LOSS" "$N6_UDP_MBPS" "$N6_UDP_LOSS" "$N6_CPU" "$N6_EFF" "$N6_RAM" "$N6_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "zerotier"  "$Z6_LOSS" "$Z6_RTT" "$Z6_TCP" "$Z6_TCP_LOSS" "$Z6_UDP_MBPS" "$Z6_UDP_LOSS" "$Z6_CPU" "$Z6_EFF" "$Z6_RAM" "$Z6_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "tailscale" "$T6_LOSS" "$T6_RTT" "$T6_TCP" "$T6_TCP_LOSS" "$T6_UDP_MBPS" "$T6_UDP_LOSS" "$T6_CPU" "$T6_EFF" "$T6_RAM" "$T6_RAM_EFF"
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "netbird"   "$B6_LOSS" "$B6_RTT" "$B6_TCP" "$B6_TCP_LOSS" "$B6_UDP_MBPS" "$B6_UDP_LOSS" "$B6_CPU" "$B6_EFF" "$B6_RAM" "$B6_RAM_EFF"
done

if [ "$CONTENDER_ISOLATION" = false ]; then
    echo "[info] stopping all contenders (CONTENDER_ISOLATION=false)"
    stop_all_contenders
fi

echo ""
echo "[done] iperf compare sweep complete"
[ "$WG_AVAILABLE"   = false ] && echo "[note] WireGuard skipped (module/CLI absent)"
[ "$WGGO_AVAILABLE" = false ] && echo "[note] WireGuard-Go skipped (binary absent or setup failed)"
[ "$AWG_AVAILABLE"  = false ] && echo "[note] AmneziaWG skipped (module/CLI absent)"
[ "$OVPN_AVAILABLE" = false ] && echo "[note] OpenVPN skipped (binary absent or setup failed)"
[ "$N2N_AVAILABLE"  = false ] && echo "[note] n2n skipped (binary absent or setup failed)"
[ "$ZT_AVAILABLE"   = false ] && echo "[note] ZeroTier skipped (binary absent or setup failed)"
[ "$TS_AVAILABLE"   = false ] && echo "[note] Tailscale skipped (binary absent or setup failed)"
[ "$NB_AVAILABLE"   = false ] && echo "[note] NetBird skipped (binary absent or setup failed)"

if [ "$YIP_FAILED" = true ]; then
    echo "[fail] benchmark sweep failed: yip did not maintain healthy throughput across all loss conditions"
    exit 1
fi

if [ "$THRESHOLD_FAILED" = true ]; then
    echo "[fail] benchmark sweep failed: one or more performance thresholds were violated"
    exit 1
fi

if [ "$ISOLATION_FAILED" = true ]; then
    echo "[fail] benchmark sweep failed: resource leak detected during isolation verification"
    exit 1
fi
true
