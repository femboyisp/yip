#!/usr/bin/env bash
# Run the WAN benchmark matrix across {baseline, yip, wireguard, openvpn}:
# TCP/UDP throughput, latency-under-load, CPU headroom, a netem loss sweep, and
# an MGEN real-time-media flow. Writes one CSV under results/<ts>/. Assumes
# provision.sh has brought the three tunnels up. Safe: all netem is scoped to
# A->B egress (never the control SSH) and always torn down.
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SUITE_DIR/lib.sh"

DUR="${DUR:-12}"          # seconds per throughput run
UDP_DUR="${UDP_DUR:-10}"
PING_COUNT="${PING_COUNT:-100}"
if [ -n "${PING_INTERVAL:-}" ]; then
    PING_INTERVAL="$PING_INTERVAL"
elif [ "$PING_COUNT" -ge 1000 ] 2>/dev/null; then
    PING_INTERVAL="0.005"
else
    PING_INTERVAL="0.05"
fi
LOSS_STEPS=(0 1 3 5 10)   # injected % on the A->B outer path
IPERF_PORT=5201
EGRESS="$(A "ip route get $HOST_B | grep -oE 'dev [a-z0-9]+' | awk '{print \$2}' | head -1")"
[[ -n "$EGRESS" ]] || die "could not detect egress iface on host A"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="$SUITE_DIR/results/$TS"; mkdir -p "$RESULTS_DIR"
CSV_FILE="$RESULTS_DIR/wan.csv"; echo "$CSV_HEADER" > "$CSV_FILE"
log "results -> $CSV_FILE (egress=$EGRESS, dur=${DUR}s)"

# tunnel -> B-side overlay IP the client on A dials ("" = baseline public IP)
declare -A DST=( [baseline]="$HOST_B" [yip]="$YIP_B" [wireguard]="$WG_B" [openvpn]="$OVPN_B" )
TUNNELS=(baseline yip wireguard openvpn)

# ── iperf3 server on B (whole-suite) ────────────────────────────────────────
iperf_up()   { B "systemctl reset-failed yipbench-iperf 2>/dev/null; systemctl stop yipbench-iperf 2>/dev/null; \
                  systemd-run --unit=yipbench-iperf --collect iperf3 -s -p $IPERF_PORT >/dev/null 2>&1"; sleep 1; }
iperf_down() { Bq "systemctl stop yipbench-iperf 2>/dev/null"; }

# ── netem (A->B only, via all-zero-priomap prio so control SSH is never hit) ─
netem_on()  { # <loss%>
    netem_off
    [[ "$1" == "0" ]] && return 0
    A "tc qdisc add dev $EGRESS root handle 1: prio bands 4 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 && \
       tc qdisc add dev $EGRESS parent 1:4 handle 40: netem loss ${1}% && \
       tc filter add dev $EGRESS parent 1:0 protocol ip prio 1 u32 match ip dst $HOST_B/32 flowid 1:4"
}
netem_off() { Aq "tc qdisc del dev $EGRESS root 2>/dev/null"; }

cleanup() { netem_off; iperf_down; }
trap cleanup EXIT

# ── JSON parse (local python3) ──────────────────────────────────────────────
# Safe dotted key-path navigator (no eval): jget end.sum_received.bits_per_second
# walks the parsed dict/list by literal keys only. Arithmetic is done in awk by
# the callers, so no code is ever executed from the JSON or the path string.
jget() {
    python3 -c '
import sys, json
d = json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[int(k)] if k.lstrip("-").isdigit() else d[k]
print(d)
' "$1"
}
# round a raw number: rnd <value> <scale> <divisor>
rnd() { awk -v v="$1" -v s="$2" -v dv="${3:-1}" 'BEGIN{printf "%.*f", s, v/dv}'; }

# ── profiles ────────────────────────────────────────────────────────────────
tcp_tput() { # <tunnel> <dst> <streams>
    local j; j="$(A "iperf3 -c $2 -p $IPERF_PORT -t $DUR -P $3 -J 2>/dev/null")"
    [[ -z "$j" ]] && { warn "$1 tcp P$3: no data"; return; }
    local mbps; mbps="$(rnd "$(jget end.sum_received.bits_per_second <<<"$j" 2>/dev/null || echo 0)" 1 1e6)"
    csv_row "$1" tcp_throughput "streams=$3" mbit_s "$mbps" "clean"
    log "  $1 TCP x$3: ${mbps} Mbit/s"
}
udp_tput() { # <tunnel> <dst>
    # push UDP hard (200M offered) and read delivered rate, jitter, loss
    local j; j="$(A "iperf3 -c $2 -p $IPERF_PORT -u -b 200M -t $UDP_DUR -J 2>/dev/null")"
    [[ -z "$j" ]] && { warn "$1 udp: no data"; return; }
    local mbps jit loss
    mbps="$(rnd "$(jget end.sum.bits_per_second <<<"$j" 2>/dev/null || echo 0)" 1 1e6)"
    jit="$(rnd  "$(jget end.sum.jitter_ms <<<"$j" 2>/dev/null || echo 0)" 3)"
    loss="$(rnd "$(jget end.sum.lost_percent <<<"$j" 2>/dev/null || echo 0)" 2)"
    csv_row "$1" udp_throughput offered=200M mbit_s "$mbps" "clean"
    csv_row "$1" udp_jitter     offered=200M ms     "$jit"  "clean"
    csv_row "$1" udp_loss       offered=200M pct    "$loss" "clean"
    log "  $1 UDP: ${mbps} Mbit/s, jitter ${jit} ms, loss ${loss}%"
}
latency_load() { # <tunnel> <dst>
    local idle loaded
    idle="$(Aq "ping -c 15 -i 0.2 -W 2 $2 | tail -1 | sed -E 's#.*= [0-9.]+/([0-9.]+)/.*#\1#'")"
    # saturate with iperf in the background, ping concurrently, then reap
    loaded="$(A "iperf3 -c $2 -p $IPERF_PORT -t 12 >/dev/null 2>&1 & sleep 1; \
                 ping -c 25 -i 0.2 -W 2 $2 | tail -1 | sed -E 's#.*= [0-9.]+/([0-9.]+)/.*#\1#'; wait" 2>/dev/null)"
    csv_row "$1" latency idle    rtt_ms "$idle"   "clean"
    csv_row "$1" latency loaded  rtt_ms "$loaded" "saturated"
    log "  $1 RTT: idle ${idle} ms -> under load ${loaded} ms"
}
cpu_headroom() { # <tunnel> <dst>  — %CPU used on A (sender) during a TCP run
    local used
    used="$(A "read _ a b c d0 e0 f0 g0 h0 rest < /proc/stat; i0=\$d0; t0=\$((a+b+c+d0+e0+f0+g0+h0)); \
               iperf3 -c $2 -p $IPERF_PORT -t 6 >/dev/null 2>&1; \
               read _ a b c d1 e1 f1 g1 h1 rest < /proc/stat; i1=\$d1; t1=\$((a+b+c+d1+e1+f1+g1+h1)); \
               awk -v i0=\$i0 -v i1=\$i1 -v t0=\$t0 -v t1=\$t1 'BEGIN{printf \"%.1f\", 100-100*(i1-i0)/(t1-t0)}'")"
    csv_row "$1" cpu_used tcp_saturate pct "$used" "sender_host_A_1vcpu"
    log "  $1 CPU used (A, 1 vCPU) during TCP: ${used}%"
}
loss_sweep() { # <tunnel> <dst>
    for L in "${LOSS_STEPS[@]}"; do
        netem_on "$L"
        local eff good
        eff="$(Aq "ping -c "${PING_COUNT:-100}" -i "${PING_INTERVAL:-0.05}" -W 2 $2 | sed -nE 's/.* ([0-9.]+)% packet loss.*/\1/p' | head -1")"
        local j; j="$(A "iperf3 -c $2 -p $IPERF_PORT -t 12 -J 2>/dev/null")"
        good="$(rnd "$(jget end.sum_received.bits_per_second <<<"$j" 2>/dev/null || echo 0)" 1 1e6)"
        [[ "$good" == "0.0" ]] && good=NA
        csv_row "$1" loss_effective "injected=${L}pct" pct    "${eff:-NA}"  "netem_${L}pct"
        csv_row "$1" loss_goodput   "injected=${L}pct" mbit_s "${good:-NA}" "netem_${L}pct"
        log "  $1 @${L}% inject: effective loss ${eff:-NA}%, TCP goodput ${good:-NA} Mbit/s"
        netem_off
    done
}
mgen_media() { # <tunnel> <dst> — periodic ~8Mbit/s media flow at 3% injected loss
    local rate_pps=800 size=1250  # 800*1250*8 ~= 8 Mbit/s
    netem_on 3
    B "systemctl reset-failed yipbench-mgen 2>/dev/null; systemctl stop yipbench-mgen 2>/dev/null; \
       rm -f /tmp/mgen_recv.log; \
       systemd-run --unit=yipbench-mgen --collect mgen output /tmp/mgen_recv.log event '0.0 LISTEN UDP 5000' >/dev/null 2>&1"
    sleep 0.5
    # ship the sender script over stdin (no fragile heredoc-in-ssh), then run it
    printf '0.0 ON 1 UDP DST %s/5000 PERIODIC [%s %s]\n25.0 OFF 1\n' "$2" "$rate_pps" "$size" \
        | A "cat > /tmp/mgen.mgn"
    A "rm -f /tmp/mgen_send.log; mgen input /tmp/mgen.mgn output /tmp/mgen_send.log 2>/dev/null; true"
    local recv sent
    recv="$(B "grep -c RECV /tmp/mgen_recv.log 2>/dev/null || echo 0")"
    sent="$(A "grep -c SEND /tmp/mgen_send.log 2>/dev/null || echo 0")"
    Bq "systemctl stop yipbench-mgen 2>/dev/null"
    netem_off
    local delivered="NA"
    [[ "$sent" =~ ^[0-9]+$ && "$sent" -gt 0 && "$recv" =~ ^[0-9]+$ ]] && \
        delivered="$(awk -v r="$recv" -v s="$sent" 'BEGIN{printf "%.1f",100*r/s}')"
    csv_row "$1" media_delivered "8Mbit_3pctloss" pct "$delivered" "mgen_periodic"
    log "  $1 MGEN media (8 Mbit/s @3% loss): delivered ${delivered}% ($recv/$sent)"
}

# ── run the matrix ──────────────────────────────────────────────────────────
# Benchmarking makes many network calls that can transiently fail; a single
# hiccup must log NA and continue, not abort the suite. Drop errexit here (the
# cleanup trap still runs on real exit).
set +e
iperf_up
for t in "${TUNNELS[@]}"; do
    log "── tunnel: $t (dst ${DST[$t]}) ──────────────────────────────"
    tcp_tput "$t" "${DST[$t]}" 1
    tcp_tput "$t" "${DST[$t]}" 4
    udp_tput "$t" "${DST[$t]}"
    latency_load "$t" "${DST[$t]}"
    cpu_headroom "$t" "${DST[$t]}"
    loss_sweep "$t" "${DST[$t]}"
    [[ "${RUN_MGEN:-0}" == "1" ]] && mgen_media "$t" "${DST[$t]}"
done
log "matrix complete -> $CSV_FILE"
