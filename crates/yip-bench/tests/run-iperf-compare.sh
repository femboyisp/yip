#!/usr/bin/env bash
# run-iperf-compare.sh — iperf3 TCP & UDP throughput + ping latency/loss under netem,
# across contemporary tunnels and mesh overlays in dual-stack IPv4 and IPv6:
#   yip, WireGuard, WireGuard-Go, AmneziaWG, OpenVPN, n2n, ZeroTier, Tailscale, NetBird, Nebula.
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

# Pre-sweep: clean any orphaned contender namespaces from previous test runs
for _pre_ns in ipfYA ipfYB ipfWA ipfWB ipfGGA ipfGGB ipfOA ipfOB ipfNA ipfNB ipfAA ipfAB ipfZA ipfZB ipfTA ipfTB ipfBA ipfBB ipfEA ipfEB; do
    ip netns pids "$_pre_ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$_pre_ns" 2>/dev/null || true
done

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
OUTPUT_JSON="${OUTPUT_JSON:-}"
TELEMETRY_RECORDS_FILE="$TMPDIR_TEST/telemetry_records.jsonl"

record_telemetry() {
    local contender="$1" loss="$2" ip_ver="$3" eff_loss="$4" rtt="$5" tcp="$6" tcp_loss="$7" udp="$8" udp_loss="$9" cpu="${10}" cpu_eff="${11}" ram="${12}" ram_eff="${13}"
    [ -n "$OUTPUT_JSON" ] || return 0
    cat >> "$TELEMETRY_RECORDS_FILE" <<EOF
{"contender":"$contender","loss_rate":$loss,"ip_version":$ip_ver,"eff_loss_pct":"$eff_loss","rtt_ms":"$rtt","tcp_mbps":"$tcp","tcp_loss_pct":"$tcp_loss","udp_mbps":"$udp","udp_loss_pct":"$udp_loss","cpu_pct":"$cpu","cpu_eff":"$cpu_eff","ram_mb":"$ram","ram_eff":"$ram_eff"}
EOF
}

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

# Source unified contender definitions, topology, and lifecycles
# shellcheck source=./contenders-lib.sh
source "$SCRIPT_DIR/contenders-lib.sh"

DEFAULT_UDP_LEN=$((YIP_MTU - 48))
[ "$DEFAULT_UDP_LEN" -gt 1350 ] && DEFAULT_UDP_LEN=1350
UDP_LEN="${UDP_LEN:-$DEFAULT_UDP_LEN}"
UDP_RATE="${UDP_RATE:-2G}"

# ── lifecycle and performance thresholds ──────────────────────────────────────
CONTENDER_ISOLATION="${CONTENDER_ISOLATION:-true}"
ASSERT_THRESHOLDS="${ASSERT_THRESHOLDS:-false}"

THRESH_YIP_TCP_MIN_MBPS_0="${THRESH_YIP_TCP_MIN_MBPS_0:-1000}"
THRESH_YIP_UDP_MIN_MBPS_0="${THRESH_YIP_UDP_MIN_MBPS_0:-1000}"
THRESH_YIP_PING_MAX_LOSS_0="${THRESH_YIP_PING_MAX_LOSS_0:-1.0}"
THRESH_YIP_TCP_MAX_LOSS_0="${THRESH_YIP_TCP_MAX_LOSS_0:-1.0}"
THRESH_YIP_UDP_MAX_LOSS_0="${THRESH_YIP_UDP_MAX_LOSS_0:-}"

THRESH_YIP_TCP_MIN_MBPS_5="${THRESH_YIP_TCP_MIN_MBPS_5:-500}"
THRESH_YIP_UDP_MIN_MBPS_5="${THRESH_YIP_UDP_MIN_MBPS_5:-800}"
THRESH_YIP_PING_MAX_LOSS_5="${THRESH_YIP_PING_MAX_LOSS_5:-8.0}"
THRESH_YIP_TCP_MAX_LOSS_5="${THRESH_YIP_TCP_MAX_LOSS_5:-2.0}"
THRESH_YIP_UDP_MAX_LOSS_5="${THRESH_YIP_UDP_MAX_LOSS_5:-}"

THRESH_YIP_TCP_MIN_MBPS_10="${THRESH_YIP_TCP_MIN_MBPS_10:-100}"
THRESH_YIP_UDP_MIN_MBPS_10="${THRESH_YIP_UDP_MIN_MBPS_10:-500}"
THRESH_YIP_PING_MAX_LOSS_10="${THRESH_YIP_PING_MAX_LOSS_10:-15.0}"
THRESH_YIP_TCP_MAX_LOSS_10="${THRESH_YIP_TCP_MAX_LOSS_10:-5.0}"
THRESH_YIP_UDP_MAX_LOSS_10="${THRESH_YIP_UDP_MAX_LOSS_10:-}"

THRESHOLD_FAILED=false

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
    for ns in "${ALL_NETNS_LIST[@]}"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT INT TERM HUP

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

    if [ "$val" = "N/A" ]; then
        if [[ "$metric" == *"min"* ]]; then
            echo "[fail] threshold violation: $contender [$ip_ver] $metric at loss=${loss}% was N/A, expected >= ${thresh}"
            THRESHOLD_FAILED=true
        fi
        return 0
    fi

    local failed=false
    if [[ "$metric" == *"max"* ]]; then
        if [ "$(awk -v v="$val" -v t="$thresh" 'BEGIN {print (v > t)}')" = "1" ]; then
            failed=true
            echo "[fail] threshold violation: $contender [$ip_ver] $metric at loss=${loss}% was ${val}, expected <= ${thresh}"
        fi
    else
        if [ "$(awk -v v="$val" -v t="$thresh" 'BEGIN {print (v < t)}')" = "1" ]; then
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
        check_threshold "$tag" "ipv4" "tcp_max_loss" "$M_TCP_LOSS" "$loss"
        check_threshold "$tag" "ipv4" "udp_min_mbps" "$M_UDP_MBPS" "$loss"
        check_threshold "$tag" "ipv4" "udp_max_loss" "$M_UDP_LOSS" "$loss"
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
        check_threshold "$tag" "ipv6" "tcp_max_loss" "$M6_TCP_LOSS" "$loss"
        check_threshold "$tag" "ipv6" "udp_min_mbps" "$M6_UDP_MBPS" "$loss"
        check_threshold "$tag" "ipv6" "udp_max_loss" "$M6_UDP_LOSS" "$loss"
        sleep 0.5
    fi
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
        [ "$NEB_AVAILABLE"  = true ] && apply_netem "$NS_EA" "$NS_EB" "$VEA" "$VEB" "$LOSS"
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
        if [ "${ASSERT_THRESHOLDS:-false}" = true ] && [ "$LOSS" -eq 0 ]; then
            if { [ "$Y_TCP_LOSS" != "N/A" ] && [ "$(awk -v l="$Y_TCP_LOSS" 'BEGIN {print (l > 5.0)}')" = "1" ]; } || \
               { [ "$Y6_TCP_LOSS" != "N/A" ] && [ "$(awk -v l="$Y6_TCP_LOSS" 'BEGIN {print (l > 5.0)}')" = "1" ]; }; then
                echo "[fail] yip clean-link (0% netem) TCP retransmission loss failure detected (v4_tcp_loss=$Y_TCP_LOSS% v6_tcp_loss=$Y6_TCP_LOSS%)"
                THRESHOLD_FAILED=true
            fi
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

    # ── Nebula ────────────────────────────────────────────────────────────────
    E_LOSS="N/A"; E_RTT="N/A"; E_TCP="N/A"; E_TCP_LOSS="N/A"; E_UDP_MBPS="N/A"; E_UDP_LOSS="N/A"; E_CPU="N/A"; E_EFF="N/A"; E_RAM="N/A"; E_RAM_EFF="N/A"
    E6_LOSS="N/A"; E6_RTT="N/A"; E6_TCP="N/A"; E6_TCP_LOSS="N/A"; E6_UDP_MBPS="N/A"; E6_UDP_LOSS="N/A"; E6_CPU="N/A"; E6_EFF="N/A"; E6_RAM="N/A"; E6_RAM_EFF="N/A"
    if (contender_wanted "nebula" || contender_wanted "neb") && [ "${NEB_AVAILABLE:-true}" != false ]; then
        if [ "$CONTENDER_ISOLATION" = true ]; then
            if start_contender "nebula"; then
                apply_netem "$NS_EA" "$NS_EB" "$VEA" "$VEB" "$LOSS"
                measure_contender "nebula" "$NS_EA" "$NS_EB" "$TUN_EA_IP" "$TUN_EA_IP6" "$LOSS"
                E_LOSS="$M_LOSS"; E_RTT="$M_RTT"; E_TCP="$M_TCP"; E_TCP_LOSS="$M_TCP_LOSS"; E_UDP_MBPS="$M_UDP_MBPS"; E_UDP_LOSS="$M_UDP_LOSS"; E_CPU="$M_CPU"; E_EFF="$M_EFF"; E_RAM="$M_RAM"; E_RAM_EFF="$M_RAM_EFF"
                E6_LOSS="$M6_LOSS"; E6_RTT="$M6_RTT"; E6_TCP="$M6_TCP"; E6_TCP_LOSS="$M6_TCP_LOSS"; E6_UDP_MBPS="$M6_UDP_MBPS"; E6_UDP_LOSS="$M6_UDP_LOSS"; E6_CPU="$M6_CPU"; E6_EFF="$M6_EFF"; E6_RAM="$M6_RAM"; E6_RAM_EFF="$M6_RAM_EFF"
                stop_contender "nebula"
                verify_isolation "nebula"
            fi
        elif [ "$NEB_AVAILABLE" = true ]; then
            measure_contender "nebula" "$NS_EA" "$NS_EB" "$TUN_EA_IP" "$TUN_EA_IP6" "$LOSS"
            E_LOSS="$M_LOSS"; E_RTT="$M_RTT"; E_TCP="$M_TCP"; E_TCP_LOSS="$M_TCP_LOSS"; E_UDP_MBPS="$M_UDP_MBPS"; E_UDP_LOSS="$M_UDP_LOSS"; E_CPU="$M_CPU"; E_EFF="$M_EFF"; E_RAM="$M_RAM"; E_RAM_EFF="$M_RAM_EFF"
            E6_LOSS="$M6_LOSS"; E6_RTT="$M6_RTT"; E6_TCP="$M6_TCP"; E6_TCP_LOSS="$M6_TCP_LOSS"; E6_UDP_MBPS="$M6_UDP_MBPS"; E6_UDP_LOSS="$M6_UDP_LOSS"; E6_CPU="$M6_CPU"; E6_EFF="$M6_EFF"; E6_RAM="$M6_RAM"; E6_RAM_EFF="$M6_RAM_EFF"
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
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "nebula"    "$E_LOSS" "$E_RTT" "$E_TCP" "$E_TCP_LOSS" "$E_UDP_MBPS" "$E_UDP_LOSS" "$E_CPU" "$E_EFF" "$E_RAM" "$E_RAM_EFF"

    record_telemetry "$YIP_LABEL" "$LOSS" 4 "$Y_LOSS" "$Y_RTT" "$Y_TCP" "$Y_TCP_LOSS" "$Y_UDP_MBPS" "$Y_UDP_LOSS" "$Y_CPU" "$Y_EFF" "$Y_RAM" "$Y_RAM_EFF"
    record_telemetry "wireguard" "$LOSS" 4 "$W_LOSS" "$W_RTT" "$W_TCP" "$W_TCP_LOSS" "$W_UDP_MBPS" "$W_UDP_LOSS" "$W_CPU" "$W_EFF" "$W_RAM" "$W_RAM_EFF"
    record_telemetry "wireguard-go" "$LOSS" 4 "$GG_LOSS" "$GG_RTT" "$GG_TCP" "$GG_TCP_LOSS" "$GG_UDP_MBPS" "$GG_UDP_LOSS" "$GG_CPU" "$GG_EFF" "$GG_RAM" "$GG_RAM_EFF"
    record_telemetry "amneziawg" "$LOSS" 4 "$A_LOSS" "$A_RTT" "$A_TCP" "$A_TCP_LOSS" "$A_UDP_MBPS" "$A_UDP_LOSS" "$A_CPU" "$A_EFF" "$A_RAM" "$A_RAM_EFF"
    record_telemetry "openvpn" "$LOSS" 4 "$O_LOSS" "$O_RTT" "$O_TCP" "$O_TCP_LOSS" "$O_UDP_MBPS" "$O_UDP_LOSS" "$O_CPU" "$O_EFF" "$O_RAM" "$O_RAM_EFF"
    record_telemetry "n2n" "$LOSS" 4 "$N_LOSS" "$N_RTT" "$N_TCP" "$N_TCP_LOSS" "$N_UDP_MBPS" "$N_UDP_LOSS" "$N_CPU" "$N_EFF" "$N_RAM" "$N_RAM_EFF"
    record_telemetry "zerotier" "$LOSS" 4 "$Z_LOSS" "$Z_RTT" "$Z_TCP" "$Z_TCP_LOSS" "$Z_UDP_MBPS" "$Z_UDP_LOSS" "$Z_CPU" "$Z_EFF" "$Z_RAM" "$Z_RAM_EFF"
    record_telemetry "tailscale" "$LOSS" 4 "$T_LOSS" "$T_RTT" "$T_TCP" "$T_TCP_LOSS" "$T_UDP_MBPS" "$T_UDP_LOSS" "$T_CPU" "$T_EFF" "$T_RAM" "$T_RAM_EFF"
    record_telemetry "netbird" "$LOSS" 4 "$B_LOSS" "$B_RTT" "$B_TCP" "$B_TCP_LOSS" "$B_UDP_MBPS" "$B_UDP_LOSS" "$B_CPU" "$B_EFF" "$B_RAM" "$B_RAM_EFF"
    record_telemetry "nebula" "$LOSS" 4 "$E_LOSS" "$E_RTT" "$E_TCP" "$E_TCP_LOSS" "$E_UDP_MBPS" "$E_UDP_LOSS" "$E_CPU" "$E_EFF" "$E_RAM" "$E_RAM_EFF"

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
    printf "  | %-12s | %-9s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" "nebula"    "$E6_LOSS" "$E6_RTT" "$E6_TCP" "$E6_TCP_LOSS" "$E6_UDP_MBPS" "$E6_UDP_LOSS" "$E6_CPU" "$E6_EFF" "$E6_RAM" "$E6_RAM_EFF"

    record_telemetry "$YIP_LABEL" "$LOSS" 6 "$Y6_LOSS" "$Y6_RTT" "$Y6_TCP" "$Y6_TCP_LOSS" "$Y6_UDP_MBPS" "$Y6_UDP_LOSS" "$Y6_CPU" "$Y6_EFF" "$Y6_RAM" "$Y6_RAM_EFF"
    record_telemetry "wireguard" "$LOSS" 6 "$W6_LOSS" "$W6_RTT" "$W6_TCP" "$W6_TCP_LOSS" "$W6_UDP_MBPS" "$W6_UDP_LOSS" "$W6_CPU" "$W6_EFF" "$W6_RAM" "$W6_RAM_EFF"
    record_telemetry "wireguard-go" "$LOSS" 6 "$GG6_LOSS" "$GG6_RTT" "$GG6_TCP" "$GG6_TCP_LOSS" "$GG6_UDP_MBPS" "$GG6_UDP_LOSS" "$GG6_CPU" "$GG6_EFF" "$GG6_RAM" "$GG6_RAM_EFF"
    record_telemetry "amneziawg" "$LOSS" 6 "$A6_LOSS" "$A6_RTT" "$A6_TCP" "$A6_TCP_LOSS" "$A6_UDP_MBPS" "$A6_UDP_LOSS" "$A6_CPU" "$A6_EFF" "$A6_RAM" "$A6_RAM_EFF"
    record_telemetry "openvpn" "$LOSS" 6 "$O6_LOSS" "$O6_RTT" "$O6_TCP" "$O6_TCP_LOSS" "$O6_UDP_MBPS" "$O6_UDP_LOSS" "$O6_CPU" "$O6_EFF" "$O6_RAM" "$O6_RAM_EFF"
    record_telemetry "n2n" "$LOSS" 6 "$N6_LOSS" "$N6_RTT" "$N6_TCP" "$N6_TCP_LOSS" "$N6_UDP_MBPS" "$N6_UDP_LOSS" "$N6_CPU" "$N6_EFF" "$N6_RAM" "$N6_RAM_EFF"
    record_telemetry "zerotier" "$LOSS" 6 "$Z6_LOSS" "$Z6_RTT" "$Z6_TCP" "$Z6_TCP_LOSS" "$Z6_UDP_MBPS" "$Z6_UDP_LOSS" "$Z6_CPU" "$Z6_EFF" "$Z6_RAM" "$Z6_RAM_EFF"
    record_telemetry "tailscale" "$LOSS" 6 "$T6_LOSS" "$T6_RTT" "$T6_TCP" "$T6_TCP_LOSS" "$T6_UDP_MBPS" "$T6_UDP_LOSS" "$T6_CPU" "$T6_EFF" "$T6_RAM" "$T6_RAM_EFF"
    record_telemetry "netbird" "$LOSS" 6 "$B6_LOSS" "$B6_RTT" "$B6_TCP" "$B6_TCP_LOSS" "$B6_UDP_MBPS" "$B6_UDP_LOSS" "$B6_CPU" "$B6_EFF" "$B6_RAM" "$B6_RAM_EFF"
    record_telemetry "nebula" "$LOSS" 6 "$E6_LOSS" "$E6_RTT" "$E6_TCP" "$E6_TCP_LOSS" "$E6_UDP_MBPS" "$E6_UDP_LOSS" "$E6_CPU" "$E6_EFF" "$E6_RAM" "$E6_RAM_EFF"
done

if [ "$CONTENDER_ISOLATION" = false ]; then
    echo "[info] stopping all contenders (CONTENDER_ISOLATION=false)"
    stop_all_contenders
fi

echo ""
echo "[done] iperf compare sweep complete"

if [ -n "$OUTPUT_JSON" ]; then
    echo "[telemetry] exporting JSON telemetry to $OUTPUT_JSON"
    mkdir -p "$(dirname "$OUTPUT_JSON")" 2>/dev/null || true
    cat > "$OUTPUT_JSON" <<EOF
{
  "benchmark": "iperf-netem",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "streams": $IPERF_STREAMS,
  "shards": "$YIP_SHARDS",
  "loss_rates": [$(echo "$LOSS_RATES" | sed 's/  */, /g')],
  "results": [
$(if [ -f "$TELEMETRY_RECORDS_FILE" ]; then paste -sd, "$TELEMETRY_RECORDS_FILE"; fi)
  ]
}
EOF
    echo "[telemetry] export complete"
fi
[ "$WG_AVAILABLE"   = false ] && echo "[note] WireGuard skipped (module/CLI absent)"
[ "$WGGO_AVAILABLE" = false ] && echo "[note] WireGuard-Go skipped (binary absent or setup failed)"
[ "$AWG_AVAILABLE"  = false ] && echo "[note] AmneziaWG skipped (module/CLI absent)"
[ "$OVPN_AVAILABLE" = false ] && echo "[note] OpenVPN skipped (binary absent or setup failed)"
[ "$N2N_AVAILABLE"  = false ] && echo "[note] n2n skipped (binary absent or setup failed)"
[ "$ZT_AVAILABLE"   = false ] && echo "[note] ZeroTier skipped (binary absent or setup failed)"
[ "$TS_AVAILABLE"   = false ] && echo "[note] Tailscale skipped (binary absent or setup failed)"
[ "$NB_AVAILABLE"   = false ] && echo "[note] NetBird skipped (binary absent or setup failed)"
[ "$NEB_AVAILABLE"  = false ] && echo "[note] Nebula skipped (binary absent or setup failed)"

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
