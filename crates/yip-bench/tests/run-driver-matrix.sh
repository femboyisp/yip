#!/usr/bin/env bash
# run-driver-matrix.sh — Systematic comparative benchmark of epoll, io_uring, and AF_XDP
# drivers under multi-shard workloads across 1, 2, 4, and auto shards.
#
# Measures:
#   1. TCP throughput (Mbit/s) & retransmit loss (%) via iperf3
#   2. UDP throughput (Mbit/s) & packet loss (%) via iperf3
#   3. Round-trip baseline latency (ms) via ICMP ping
#   4. CPU utilization (%) & efficiency (%/Gbps) via /proc/stat
#   5. Peak resident memory (MB) & RAM efficiency (MB/Gbps)
#
# Usage:
#   run-driver-matrix.sh [<path-to-yipd>]
set -euo pipefail

# ── root requirement ──────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "[error] run-driver-matrix.sh requires root privileges (network namespaces and netem)" >&2
    exit 1
fi

# ── locate yipd binary ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    YIPD="$1"
else
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

# Source unified contender library for namespaces, veth, netem, and cleanup
# shellcheck source=./contenders-lib.sh
source "$SCRIPT_DIR/contenders-lib.sh"

# ── configuration ─────────────────────────────────────────────────────────────
DRIVERS="${DRIVERS:-epoll uring xdp}"
SHARD_COUNTS="${SHARD_COUNTS:-1 2 4 auto}"
LOSS_RATES="${LOSS_RATES:-0 5}"
IPERF_STREAMS="${IPERF_STREAMS:-1}"
IPERF_DURATION="${IPERF_DURATION:-6}"
OUTPUT_JSON="${OUTPUT_JSON:-}"
ASSERT_THRESHOLDS="${ASSERT_THRESHOLDS:-false}"

# Dedicated namespace and interface definitions for driver matrix
NS_DA="drvA"
NS_DB="drvB"
VDA="vethDA"
VDB="vethDB"
VDA_IP="10.40.0.1"
VDB_IP="10.40.0.2"
TUN_DA_IP="10.41.0.1"
TUN_DB_IP="10.41.0.2"
TUN_DA_IP6="fd00:41::1"
TUN_DB_IP6="fd00:41::2"
TUN_DEV="yip0"
PORT_A="4430"
PORT_B="4430"

PID_DA=""
PID_DB=""
BENCH_FAILED=false

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup_driver_matrix() {
    echo "[cleanup] cleaning up active driver matrix processes and namespaces"
    reap_pids "$PID_DA" "$PID_DB"
    PID_DA=""
    PID_DB=""
    clean_netns "$NS_DA" "$NS_DB"
    rm -rf "$TMPDIR_TEST" 2>/dev/null || true
}
trap cleanup_driver_matrix EXIT INT TERM HUP

# Pre-sweep cleanup
clean_netns "$NS_DA" "$NS_DB"

# ── CPU telemetry helpers ─────────────────────────────────────────────────────
CPU_START_USER=0; CPU_START_NICE=0; CPU_START_SYS=0; CPU_START_IDLE=0
CPU_START_IOW=0; CPU_START_IRQ=0; CPU_START_SIRQ=0; CPU_START_STEAL=0

sample_cpu_start() {
    local cpu u n s id io irq sirq st rest
    read -r cpu u n s id io irq sirq st rest < /proc/stat
    CPU_START_USER="${u:-0}"; CPU_START_NICE="${n:-0}"; CPU_START_SYS="${s:-0}"
    CPU_START_IDLE="${id:-0}"; CPU_START_IOW="${io:-0}"; CPU_START_IRQ="${irq:-0}"
    CPU_START_SIRQ="${sirq:-0}"; CPU_START_STEAL="${st:-0}"
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

# ── Ping measurement helper ───────────────────────────────────────────────────
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
    out="$(ip netns exec "$ns" $ping_cmd -c 20 -i 0.05 -W 1 "$dst" 2>&1 || true)"
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

# ── iperf3 TCP measurement helper ─────────────────────────────────────────────
measure_iperf_tcp() {
    local ns_srv="$1" srv_ip="$2" ns_cli="$3" streams="${4:-$IPERF_STREAMS}" v6_flag="" srv_pid out mbps loss retransmits bytes
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
        out="$(timeout 30 ip netns exec "$ns_cli" iperf3 -c "$srv_ip" $v6_flag -P "$streams" --connect-timeout 10000 -t "$IPERF_DURATION" -J 2>/dev/null || true)"
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
        sleep 0.3
    done
    echo "0.0 100.0"
}

# ── iperf3 UDP measurement helper ─────────────────────────────────────────────
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
        out="$(timeout 30 ip netns exec "$ns_cli" iperf3 -c "$srv_ip" $v6_flag -u \
            -b 2000M -l 1184 --connect-timeout 10000 -t "$IPERF_DURATION" -J 2>/dev/null || true)"
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
        sleep 0.3
    done
    echo "0.0 100.0 N/A N/A"
}

# ── Launch yipd with driver & shard parameters ────────────────────────────────
start_yip_driver() {
    local driver="$1" shards="$2"
    echo "[start] yipd driver=${driver} shards=${shards}"

    make_pair "$NS_DA" "$NS_DB" "$VDA" "$VDB" "$VDA_IP" "$VDB_IP"

    local genkey_a genkey_b priv_a pub_a priv_b pub_b cfg_a cfg_b
    genkey_a="$("$YIPD" --genkey)"
    genkey_b="$("$YIPD" --genkey)"
    priv_a="$(echo "$genkey_a" | grep '^private=' | cut -d= -f2)"
    pub_a="$(echo "$genkey_a" | grep '^public=' | cut -d= -f2)"
pq_pub_a="$(echo "$genkey_a" | grep '^pq_public=' | cut -d= -f2)"
    priv_b="$(echo "$genkey_b" | grep '^private=' | cut -d= -f2)"
    pub_b="$(echo "$genkey_b" | grep '^public=' | cut -d= -f2)"
pq_pub_b="$(echo "$genkey_b" | grep '^pq_public=' | cut -d= -f2)"

    cfg_a="$TMPDIR_TEST/yipA.conf"
    cfg_b="$TMPDIR_TEST/yipB.conf"

    local driver_cfg=""
    case "$driver" in
        epoll)
            driver_cfg="driver=epoll"
            ;;
        uring)
            driver_cfg="driver=uring"
            ;;
        xdp)
            driver_cfg="driver=xdp
xdp=true
xdp_ifname=${VDA}
xdp_mode=generic"
            ;;
    esac

    cat > "$cfg_a" <<EOF
local_private=${priv_a}
local_public=${pub_a}
peer_public=${pub_b}
pq_public_key=${pq_pub_b}
listen=${VDA_IP}:${PORT_A}
peer_endpoint=${VDB_IP}:${PORT_B}
device=${TUN_DEV}
shards=${shards}
${driver_cfg}
EOF

    local driver_cfg_b=""
    case "$driver" in
        epoll)
            driver_cfg_b="driver=epoll"
            ;;
        uring)
            driver_cfg_b="driver=uring"
            ;;
        xdp)
            driver_cfg_b="driver=xdp
xdp=true
xdp_ifname=${VDB}
xdp_mode=generic"
            ;;
    esac

    cat > "$cfg_b" <<EOF
local_private=${priv_b}
local_public=${pub_b}
peer_public=${pub_a}
pq_public_key=${pq_pub_a}
listen=${VDB_IP}:${PORT_B}
peer_endpoint=${VDA_IP}:${PORT_A}
device=${TUN_DEV}
shards=${shards}
${driver_cfg_b}
EOF

    local log_a="$TMPDIR_TEST/yipA-${driver}-${shards}.log"
    local log_b="$TMPDIR_TEST/yipB-${driver}-${shards}.log"

    local -a env_args=()
    if [ "$driver" = "uring" ]; then
        env_args+=("YIP_USE_URING=1" "YIP_URING_BUSYPOLL=1" "YIP_URING_SQPOLL=${YIP_URING_SQPOLL:-1}")
    fi

    env "${env_args[@]}" ip netns exec "$NS_DA" "$YIPD" "$cfg_a" >"$log_a" 2>&1 &
    PID_DA=$!
    env "${env_args[@]}" ip netns exec "$NS_DB" "$YIPD" "$cfg_b" >"$log_b" 2>&1 &
    PID_DB=$!

    local elapsed=0 interval=0.25 max_wait=20
    while true; do
        local a_up=0 b_up=0
        ip netns exec "$NS_DA" ip link show "$TUN_DEV" >/dev/null 2>&1 && a_up=1 || true
        ip netns exec "$NS_DB" ip link show "$TUN_DEV" >/dev/null 2>&1 && b_up=1 || true
        if [ "$a_up" -eq 1 ] && [ "$b_up" -eq 1 ]; then break; fi
        if ! kill -0 "$PID_DA" 2>/dev/null || ! kill -0 "$PID_DB" 2>/dev/null; then
            echo "[error] yipd died during startup for driver=${driver} shards=${shards}" >&2
            cat "$log_a" "$log_b" || true
            return 1
        fi
        elapsed=$(awk "BEGIN {print $elapsed + $interval}")
        if awk "BEGIN {exit ($elapsed >= $max_wait) ? 0 : 1}"; then
            echo "[error] timed out waiting for TUN device for driver=${driver} shards=${shards}" >&2
            cat "$log_a" "$log_b" || true
            return 1
        fi
        sleep "$interval"
    done

    ip netns exec "$NS_DA" ip addr add "${TUN_DA_IP}/24" dev "$TUN_DEV"
    ip netns exec "$NS_DB" ip addr add "${TUN_DB_IP}/24" dev "$TUN_DEV"
    ip netns exec "$NS_DA" ip -6 addr add "${TUN_DA_IP6}/64" dev "$TUN_DEV" nodad 2>/dev/null || true
    ip netns exec "$NS_DB" ip -6 addr add "${TUN_DB_IP6}/64" dev "$TUN_DEV" nodad 2>/dev/null || true
    ip netns exec "$NS_DA" ip link set dev "$TUN_DEV" txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_DB" ip link set dev "$TUN_DEV" txqueuelen 10000 2>/dev/null || true

    sleep 0.5
    if ! ip netns exec "$NS_DB" ping -c 3 -W 1 "$TUN_DA_IP" >/dev/null 2>&1; then
        echo "[error] initial overlay ping failed for driver=${driver} shards=${shards}" >&2
        cat "$log_a" "$log_b" || true
        return 1
    fi
    echo "[start] yipd tunnel active"
    return 0
}

stop_yip_driver() {
    LAST_CHECK_PIDS=("$PID_DA:yipd-A" "$PID_DB:yipd-B")
    reap_pids "$PID_DA" "$PID_DB"
    PID_DA=""
    PID_DB=""
    clean_netns "$NS_DA" "$NS_DB"
    verify_isolation "yip-driver"
}

# ── Data plane driver matrix execution ────────────────────────────────────────
declare -A RESULT_RTT
declare -A RESULT_TCP
declare -A RESULT_TCP_LOSS
declare -A RESULT_UDP
declare -A RESULT_UDP_LOSS
declare -A RESULT_CPU
declare -A RESULT_EFF
declare -A RESULT_RAM
declare -A RESULT_RAM_EFF

echo "=========================================================="
echo "  Yip Data Plane Driver Benchmark Matrix (Issue #279)"
echo "  Drivers: $DRIVERS"
echo "  Shards:  $SHARD_COUNTS"
echo "  Loss:    $LOSS_RATES"
echo "=========================================================="

for DRIVER in $DRIVERS; do
    for SHARDS in $SHARD_COUNTS; do
        if ! start_yip_driver "$DRIVER" "$SHARDS"; then
            echo "[skip] driver=${DRIVER} shards=${SHARDS} failed to start"
            BENCH_FAILED=true
            continue
        fi

        for LOSS in $LOSS_RATES; do
            echo ""
            echo "--- driver=${DRIVER} shards=${SHARDS} loss=${LOSS}% ---"
            apply_netem "$NS_DA" "$NS_DB" "$VDA" "$VDB" "$LOSS"

            # Ping latency and loss
            read -r p_loss p_rtt <<< "$(measure_ping "$NS_DB" "$TUN_DA_IP")"

            # TCP throughput and retransmit loss
            read -r tcp_mbps tcp_loss <<< "$(measure_iperf_tcp "$NS_DA" "$TUN_DA_IP" "$NS_DB" "$IPERF_STREAMS")"

            # UDP throughput, loss, and CPU utilization
            read -r udp_mbps udp_loss cpu_pct cpu_eff <<< "$(measure_iperf_udp "$NS_DA" "$TUN_DA_IP" "$NS_DB")"

            # Peak RAM footprint and efficiency
            ram_mb="$(get_ns_ram_mb "$NS_DA")"
            ram_eff="$(calc_ram_efficiency "$ram_mb" "$udp_mbps")"

            KEY="${DRIVER}:${SHARDS}:${LOSS}"
            RESULT_RTT["$KEY"]="$p_rtt"
            RESULT_TCP["$KEY"]="$tcp_mbps"
            RESULT_TCP_LOSS["$KEY"]="$tcp_loss"
            RESULT_UDP["$KEY"]="$udp_mbps"
            RESULT_UDP_LOSS["$KEY"]="$udp_loss"
            RESULT_CPU["$KEY"]="$cpu_pct"
            RESULT_EFF["$KEY"]="$cpu_eff"
            RESULT_RAM["$KEY"]="$ram_mb"
            RESULT_RAM_EFF["$KEY"]="$ram_eff"

            echo "[result] rtt=${p_rtt}ms tcp=${tcp_mbps}Mbit/s (loss ${tcp_loss}%) udp=${udp_mbps}Mbit/s (loss ${udp_loss}%) cpu=${cpu_pct}% (${cpu_eff}/Gbps) ram=${ram_mb}MB"

            if [ "$ASSERT_THRESHOLDS" = true ]; then
                if [ "$tcp_mbps" = "0.0" ] || [ "$udp_mbps" = "0.0" ]; then
                    echo "[fail] throughput violation: driver=${DRIVER} shards=${SHARDS} loss=${LOSS}% produced 0 throughput" >&2
                    BENCH_FAILED=true
                fi
                if [ "$LOSS" -eq 0 ] && [ "$tcp_loss" != "N/A" ]; then
                    if [ "$(awk -v t="$tcp_loss" 'BEGIN {print (t > 5.0)}')" = "1" ]; then
                        echo "[fail] clean link loss violation: driver=${DRIVER} shards=${SHARDS} loss=${LOSS}% exceeded 5% TCP retransmit loss" >&2
                        BENCH_FAILED=true
                    fi
                fi
            fi
        done

        stop_yip_driver
    done
done

# ── Summary Markdown Table ────────────────────────────────────────────────────
echo ""
echo "=========================================================="
echo "  Data Plane Driver Matrix Summary"
echo "=========================================================="
echo ""
echo "| driver | shards | loss% | rtt_ms | tcp_Mbit/s | tcp_loss% | udp_Mbit/s | udp_loss% | cpu% | cpu_eff(%/Gbps) | ram_MB | ram_eff(MB/Gbps) |"
echo "|:-------|:------:|:-----:|:------:|:----------:|:---------:|:----------:|:---------:|:----:|:---------------:|:------:|:----------------:|"

for DRIVER in $DRIVERS; do
    for SHARDS in $SHARD_COUNTS; do
        for LOSS in $LOSS_RATES; do
            KEY="${DRIVER}:${SHARDS}:${LOSS}"
            rtt="${RESULT_RTT["$KEY"]:-N/A}"
            tcp="${RESULT_TCP["$KEY"]:-N/A}"
            tcp_l="${RESULT_TCP_LOSS["$KEY"]:-N/A}"
            udp="${RESULT_UDP["$KEY"]:-N/A}"
            udp_l="${RESULT_UDP_LOSS["$KEY"]:-N/A}"
            cpu="${RESULT_CPU["$KEY"]:-N/A}"
            eff="${RESULT_EFF["$KEY"]:-N/A}"
            ram="${RESULT_RAM["$KEY"]:-N/A}"
            ram_eff="${RESULT_RAM_EFF["$KEY"]:-N/A}"
            printf "| %-6s | %-6s | %-5s | %-6s | %-10s | %-9s | %-10s | %-9s | %-4s | %-15s | %-6s | %-16s |\n" \
                "$DRIVER" "$SHARDS" "$LOSS" "$rtt" "$tcp" "$tcp_l" "$udp" "$udp_l" "$cpu" "$eff" "$ram" "$ram_eff"
        done
    done
done
echo ""

# ── JSON Telemetry Export ─────────────────────────────────────────────────────
if [ -n "$OUTPUT_JSON" ]; then
    echo "[telemetry] exporting JSON to $OUTPUT_JSON"
    mkdir -p "$(dirname "$OUTPUT_JSON")" 2>/dev/null || true
    cat > "$OUTPUT_JSON" <<EOF
{
  "benchmark": "driver-matrix",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "drivers": [$(echo "$DRIVERS" | sed 's/  */", "/g; s/^/"/; s/$/"/')],
  "shard_counts": [$(echo "$SHARD_COUNTS" | sed 's/  */", "/g; s/^/"/; s/$/"/')],
  "loss_rates": [$(echo "$LOSS_RATES" | sed 's/  */, /g')],
  "results": [
EOF
    first=1
    for DRIVER in $DRIVERS; do
        for SHARDS in $SHARD_COUNTS; do
            for LOSS in $LOSS_RATES; do
                KEY="${DRIVER}:${SHARDS}:${LOSS}"
                [ -n "${RESULT_TCP["$KEY"]:-}" ] || continue
                rtt="${RESULT_RTT["$KEY"]}"
                tcp="${RESULT_TCP["$KEY"]}"
                tcp_l="${RESULT_TCP_LOSS["$KEY"]}"
                udp="${RESULT_UDP["$KEY"]}"
                udp_l="${RESULT_UDP_LOSS["$KEY"]}"
                cpu="${RESULT_CPU["$KEY"]}"
                eff="${RESULT_EFF["$KEY"]}"
                ram="${RESULT_RAM["$KEY"]}"
                ram_eff="${RESULT_RAM_EFF["$KEY"]}"

                if [ "$first" -eq 0 ]; then
                    echo "    ," >> "$OUTPUT_JSON"
                fi
                first=0
                cat >> "$OUTPUT_JSON" <<EOF
    {
      "driver": "$DRIVER",
      "shards": "$SHARDS",
      "loss_percent": $LOSS,
      "rtt_ms": $([ "$rtt" = "N/A" ] && echo "null" || echo "$rtt"),
      "tcp_mbps": $([ "$tcp" = "N/A" ] && echo "null" || echo "$tcp"),
      "tcp_loss_percent": $([ "$tcp_l" = "N/A" ] && echo "null" || echo "$tcp_l"),
      "udp_mbps": $([ "$udp" = "N/A" ] && echo "null" || echo "$udp"),
      "udp_loss_percent": $([ "$udp_l" = "N/A" ] && echo "null" || echo "$udp_l"),
      "cpu_percent": $([ "$cpu" = "N/A" ] && echo "null" || echo "$cpu"),
      "cpu_efficiency": $([ "$eff" = "N/A" ] && echo "null" || echo "$eff"),
      "ram_mb": $([ "$ram" = "N/A" ] && echo "null" || echo "$ram"),
      "ram_efficiency": $([ "$ram_eff" = "N/A" ] && echo "null" || echo "$ram_eff")
    }
EOF
            done
        done
    done
    cat >> "$OUTPUT_JSON" <<EOF
  ]
}
EOF
    echo "[telemetry] export complete"
fi

if [ "$BENCH_FAILED" = true ]; then
    echo "[fail] driver matrix benchmark failed: throughput violation or driver startup failure" >&2
    exit 1
fi

if [ "$ISOLATION_FAILED" = true ]; then
    echo "[fail] driver matrix benchmark failed: resource leak detected during isolation verification" >&2
    exit 1
fi

echo "[done] driver matrix benchmark sweep complete"
