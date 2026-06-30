#!/usr/bin/env bash
# run-iperf-compare.sh — iperf3 TCP throughput + ping latency/loss under netem,
# across the full-IP tunnels: yip, WireGuard, OpenVPN, n2n.
#
# Each contender is set up in its OWN netns pair (mirroring the verified spikes);
# at each loss rate (0 5 10 %, symmetric delay 5ms) we run:
#   ping  -c 50 -i 0.1   -> effective loss % + avg RTT (ms)
#   iperf3 -c <tun> -t 8 -> TCP throughput (Mbit/s)
#
# yip MUST always run; every other contender SKIPs cleanly (logging why) if its
# tool/module is absent.
#
# n2n note: one TAP data plane serves both L2 and L3 — measured once.
#
# Usage: run-iperf-compare.sh [<path-to-yipd>]
set -euo pipefail

if ! command -v iperf3 >/dev/null 2>&1; then
    echo "[SKIP] iperf3 not found — skipping iperf throughput comparison"
    exit 0
fi

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

TMPDIR_TEST="$(mktemp -d /tmp/yip-iperf-compare.XXXXXX)"

# ── yip ───────────────────────────────────────────────────────────────────────
NS_YA="ipfYA"; NS_YB="ipfYB"; VYA="ipfvYA"; VYB="ipfvYB"
VYA_IP="10.10.0.1"; VYB_IP="10.10.0.2"
TUN_YA_IP="10.11.0.1"; TUN_YB_IP="10.11.0.2"
YPORT_A="51850"; YPORT_B="51851"; TUN_DEV="yip0"; YIP_MTU=1184
PID_YA=""; PID_YB=""

# ── WireGuard ─────────────────────────────────────────────────────────────────
NS_WA="ipfWA"; NS_WB="ipfWB"; VWA="ipfvWA"; VWB="ipfvWB"
VWA_IP="10.12.0.1"; VWB_IP="10.12.0.2"
TUN_WA_IP="10.13.0.1"; TUN_WB_IP="10.13.0.2"
WPORT_A="51860"; WPORT_B="51861"
WG_AVAILABLE=true

# ── OpenVPN ───────────────────────────────────────────────────────────────────
NS_OA="ipfOA"; NS_OB="ipfOB"; VOA="ipfvOA"; VOB="ipfvOB"
VOA_IP="10.14.0.1"; VOB_IP="10.14.0.2"
TUN_OA_IP="10.15.0.1"; TUN_OB_IP="10.15.0.2"
OVPN_AVAILABLE=true

# ── n2n ───────────────────────────────────────────────────────────────────────
NS_NA="ipfNA"; NS_NB="ipfNB"; VNA="ipfvNA"; VNB="ipfvNB"
VNA_IP="10.16.0.1"; VNB_IP="10.16.0.2"
OVL_NA_IP="10.17.0.1"; OVL_NB_IP="10.17.0.2"
N2N_PORT="7654"
N2N_AVAILABLE=true

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_YA" ] && kill "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill "$PID_YB" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_YA" ] && kill -9 "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill -9 "$PID_YB" 2>/dev/null || true
    # Remove WG interfaces before deleting namespaces.
    ip netns exec "$NS_WA" ip link del wg0 2>/dev/null || true
    ip netns exec "$NS_WB" ip link del wg0 2>/dev/null || true
    for ns in "$NS_YA" "$NS_YB" "$NS_WA" "$NS_WB" "$NS_OA" "$NS_OB" "$NS_NA" "$NS_NB"; do
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
    ip link add "$vR" type veth peer name "$vS"
    ip link set "$vR" netns "$nsR"; ip link set "$vS" netns "$nsS"
    ip netns exec "$nsR" ip addr add "$ipR/24" dev "$vR"
    ip netns exec "$nsR" ip link set "$vR" up; ip netns exec "$nsR" ip link set lo up
    ip netns exec "$nsS" ip addr add "$ipS/24" dev "$vS"
    ip netns exec "$nsS" ip link set "$vS" up; ip netns exec "$nsS" ip link set lo up
}

apply_netem() {
    local nsR="$1" nsS="$2" vR="$3" vS="$4" loss="$5"
    ip netns exec "$nsR" tc qdisc replace dev "$vR" root netem loss "${loss}%" delay 5ms
    ip netns exec "$nsS" tc qdisc replace dev "$vS" root netem loss "${loss}%" delay 5ms
}

# ── helper: ping a tunnel IP from a netns; echo "<loss%> <avg_rtt_ms>" ─────────
measure_ping() {
    local ns="$1" dst="$2" out loss rttline rtt
    out="$(ip netns exec "$ns" ping -c 50 -i 0.1 -W 1 "$dst" 2>&1)" || true
    loss="$(echo "$out" | grep -oP '\d+(\.\d+)?% packet loss' | grep -oP '^[0-9.]+' || echo 100)"
    rttline="$(echo "$out" | grep -oP 'rtt min/avg/max/mdev = [0-9./]+ ms' || echo "")"
    if [ -n "$rttline" ]; then
        rtt="$(echo "$rttline" | cut -d= -f2 | tr '/' ' ' | awk '{print $2}')"
    else
        rtt="N/A"
    fi
    echo "$loss $rtt"
}

# ── helper: iperf3 TCP Mbit/s; server in <ns_srv> bound to <srv_ip>, client in
#    <ns_cli> -> <srv_ip>.  echo "<mbps>" ───────────────────────────────────────
measure_iperf() {
    local ns_srv="$1" srv_ip="$2" ns_cli="$3" mbps
    ip netns exec "$ns_srv" iperf3 -s -1 -B "$srv_ip" >/dev/null 2>&1 &
    sleep 0.5
    mbps="$(ip netns exec "$ns_cli" iperf3 -c "$srv_ip" -t 8 2>/dev/null \
        | grep -i receiver | grep -oP '[0-9.]+ (Mbits|Gbits)/sec' | tail -1 || echo "")"
    # Normalize Gbits -> Mbits.
    if echo "$mbps" | grep -qi 'Gbits'; then
        mbps="$(echo "$mbps" | grep -oP '[0-9.]+' | awk '{printf "%.1f", $1*1000}')"
    else
        mbps="$(echo "$mbps" | grep -oP '[0-9.]+' | head -1)"
    fi
    [ -z "$mbps" ] && mbps="N/A"
    echo "$mbps"
}

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
ip netns exec "$NS_YA" ip addr add "${TUN_YA_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_YB" ip addr add "${TUN_YB_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_YA" ip link set "$TUN_DEV" mtu "$YIP_MTU"
ip netns exec "$NS_YB" ip link set "$TUN_DEV" mtu "$YIP_MTU"
ip netns exec "$NS_YA" ip link set "$TUN_DEV" up
ip netns exec "$NS_YB" ip link set "$TUN_DEV" up
sleep 0.5
echo "[yip] baseline connectivity check"
ip netns exec "$NS_YB" ping -c 3 -W 5 "$TUN_YA_IP" >/dev/null || {
    echo "[error] yip baseline ping failed"; cat "$LOG_A" "$LOG_B" || true; exit 1
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
    echo "[wg] generating keypairs"
    local pa pb ka kb
    pa="$(wg genkey)"; ka="$(echo "$pa" | wg pubkey)"
    pb="$(wg genkey)"; kb="$(echo "$pb" | wg pubkey)"
    echo "[wg] creating namespaces and veth pair"
    make_pair "$NS_WA" "$NS_WB" "$VWA" "$VWB" "$VWA_IP" "$VWB_IP"
    ip netns exec "$NS_WA" ip link add wg0 type wireguard
    ip netns exec "$NS_WB" ip link add wg0 type wireguard
    printf '%s' "$pa" > "$TMPDIR_TEST/wg_a"; printf '%s' "$pb" > "$TMPDIR_TEST/wg_b"
    chmod 600 "$TMPDIR_TEST/wg_a" "$TMPDIR_TEST/wg_b"
    ip netns exec "$NS_WA" wg set wg0 private-key "$TMPDIR_TEST/wg_a" listen-port "$WPORT_A" \
        peer "$kb" allowed-ips "${TUN_WB_IP}/32" endpoint "${VWB_IP}:${WPORT_B}"
    ip netns exec "$NS_WB" wg set wg0 private-key "$TMPDIR_TEST/wg_b" listen-port "$WPORT_B" \
        peer "$ka" allowed-ips "${TUN_WA_IP}/32" endpoint "${VWA_IP}:${WPORT_A}"
    ip netns exec "$NS_WA" ip addr add "${TUN_WA_IP}/24" dev wg0
    ip netns exec "$NS_WA" ip link set wg0 up
    ip netns exec "$NS_WB" ip addr add "${TUN_WB_IP}/24" dev wg0
    ip netns exec "$NS_WB" ip link set wg0 up
    sleep 0.5
    if ! ip netns exec "$NS_WB" ping -c 3 -W 5 "$TUN_WA_IP" >/dev/null; then
        echo "[wg] SKIP: baseline WG ping failed"; WG_AVAILABLE=false; return
    fi
    echo "[wg] tunnel up"
}
setup_wg

# ══════════════════════════════════════════════════════════════════════════════
# OpenVPN setup (static-key p2p TUN; AES-256-CBC since static key has no AEAD)
# ══════════════════════════════════════════════════════════════════════════════
setup_ovpn() {
    if ! command -v openvpn >/dev/null 2>&1; then
        echo "[ovpn] SKIP: 'openvpn' not found"; OVPN_AVAILABLE=false; return
    fi
    echo "[ovpn] creating namespaces and veth pair"
    make_pair "$NS_OA" "$NS_OB" "$VOA" "$VOB" "$VOA_IP" "$VOB_IP"
    echo "[ovpn] genkey"
    if ! openvpn --genkey secret "$TMPDIR_TEST/static.key" >/dev/null 2>&1; then
        echo "[ovpn] SKIP: openvpn --genkey failed"; OVPN_AVAILABLE=false; return
    fi
    ip netns exec "$NS_OA" openvpn --dev tun --dev-type tun --local "$VOA_IP" --lport 1194 \
        --remote "$VOB_IP" --rport 1194 --ifconfig "$TUN_OA_IP" "$TUN_OB_IP" \
        --secret "$TMPDIR_TEST/static.key" --allow-deprecated-insecure-static-crypto \
        --proto udp --auth SHA256 --cipher AES-256-CBC --verb 1 --ping 10 --ping-restart 0 \
        >"$TMPDIR_TEST/ovpn-a.log" 2>&1 &
    ip netns exec "$NS_OB" openvpn --dev tun --dev-type tun --local "$VOB_IP" --lport 1194 \
        --remote "$VOA_IP" --rport 1194 --ifconfig "$TUN_OB_IP" "$TUN_OA_IP" \
        --secret "$TMPDIR_TEST/static.key" --allow-deprecated-insecure-static-crypto \
        --proto udp --auth SHA256 --cipher AES-256-CBC --verb 1 --ping 10 --ping-restart 0 \
        >"$TMPDIR_TEST/ovpn-b.log" 2>&1 &
    local i
    for i in $(seq 1 60); do
        ip netns exec "$NS_OA" ip link show tun0 >/dev/null 2>&1 \
            && ip netns exec "$NS_OB" ip link show tun0 >/dev/null 2>&1 && break
        sleep 0.25
    done
    sleep 1
    if ! ip netns exec "$NS_OB" ping -c 3 -W 5 "$TUN_OA_IP" >/dev/null 2>&1; then
        echo "[ovpn] SKIP: baseline ping failed"
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
    sleep 2
    if ! ip netns exec "$NS_NB" ping -c 3 -W 5 "$OVL_NA_IP" >/dev/null 2>&1; then
        echo "[n2n] SKIP: baseline overlay ping failed"
        tail -5 "$TMPDIR_TEST/n2-sn.log" "$TMPDIR_TEST/n2-eA.log" "$TMPDIR_TEST/n2-eB.log" 2>/dev/null || true
        N2N_AVAILABLE=false; return
    fi
    echo "[n2n] overlay up"
}
setup_n2n

# ══════════════════════════════════════════════════════════════════════════════
# Sweep
# ══════════════════════════════════════════════════════════════════════════════
LOSS_RATES="0 5 10"

echo ""
echo "=========================================================="
echo "  iperf3 TCP throughput + ping latency/loss under netem"
echo "  ping -c 50 -i 0.1; iperf3 -t 8; netem: loss X% delay 5ms (symmetric)"
echo "=========================================================="

for LOSS in $LOSS_RATES; do
    echo ""
    echo "[netem] loss=${LOSS}% delay=5ms on all active pairs"
    apply_netem "$NS_YA" "$NS_YB" "$VYA" "$VYB" "$LOSS"
    [ "$WG_AVAILABLE" = true ]   && apply_netem "$NS_WA" "$NS_WB" "$VWA" "$VWB" "$LOSS"
    [ "$OVPN_AVAILABLE" = true ] && apply_netem "$NS_OA" "$NS_OB" "$VOA" "$VOB" "$LOSS"
    [ "$N2N_AVAILABLE" = true ]  && apply_netem "$NS_NA" "$NS_NB" "$VNA" "$VNB" "$LOSS"

    # yip
    read -r Y_LOSS Y_RTT <<< "$(measure_ping "$NS_YB" "$TUN_YA_IP")"
    Y_MBPS="$(measure_iperf "$NS_YA" "$TUN_YA_IP" "$NS_YB")"
    echo "[yip] loss=${Y_LOSS}% rtt=${Y_RTT}ms tcp=${Y_MBPS}Mbit/s"

    # WireGuard
    W_LOSS="N/A"; W_RTT="N/A"; W_MBPS="N/A"
    if [ "$WG_AVAILABLE" = true ]; then
        read -r W_LOSS W_RTT <<< "$(measure_ping "$NS_WB" "$TUN_WA_IP")"
        W_MBPS="$(measure_iperf "$NS_WA" "$TUN_WA_IP" "$NS_WB")"
        echo "[wg] loss=${W_LOSS}% rtt=${W_RTT}ms tcp=${W_MBPS}Mbit/s"
    fi

    # OpenVPN
    O_LOSS="N/A"; O_RTT="N/A"; O_MBPS="N/A"
    if [ "$OVPN_AVAILABLE" = true ]; then
        read -r O_LOSS O_RTT <<< "$(measure_ping "$NS_OB" "$TUN_OA_IP")"
        O_MBPS="$(measure_iperf "$NS_OA" "$TUN_OA_IP" "$NS_OB")"
        echo "[ovpn] loss=${O_LOSS}% rtt=${O_RTT}ms tcp=${O_MBPS}Mbit/s"
    fi

    # n2n
    N_LOSS="N/A"; N_RTT="N/A"; N_MBPS="N/A"
    if [ "$N2N_AVAILABLE" = true ]; then
        read -r N_LOSS N_RTT <<< "$(measure_ping "$NS_NB" "$OVL_NA_IP")"
        N_MBPS="$(measure_iperf "$NS_NA" "$OVL_NA_IP" "$NS_NB")"
        echo "[n2n] loss=${N_LOSS}% rtt=${N_RTT}ms tcp=${N_MBPS}Mbit/s"
    fi

    # ── emit per-loss-rate table ──────────────────────────────────────────────
    echo ""
    echo "  --- loss=${LOSS}% ---"
    echo "  | contender | eff_loss% | rtt_ms | tcp_Mbit/s |"
    echo "  |-----------|-----------|--------|------------|"
    printf "  | %-9s | %-9s | %-6s | %-10s |\n" "yip"       "$Y_LOSS" "$Y_RTT" "$Y_MBPS"
    printf "  | %-9s | %-9s | %-6s | %-10s |\n" "wireguard" "$W_LOSS" "$W_RTT" "$W_MBPS"
    printf "  | %-9s | %-9s | %-6s | %-10s |\n" "openvpn"   "$O_LOSS" "$O_RTT" "$O_MBPS"
    printf "  | %-9s | %-9s | %-6s | %-10s |\n" "n2n"       "$N_LOSS" "$N_RTT" "$N_MBPS"
done

echo ""
echo "[done] iperf compare sweep complete"
[ "$WG_AVAILABLE"   = false ] && echo "[note] WireGuard skipped (module/CLI absent)"
[ "$OVPN_AVAILABLE" = false ] && echo "[note] OpenVPN skipped (binary absent or setup failed)"
[ "$N2N_AVAILABLE"  = false ] && echo "[note] n2n skipped (binary absent or setup failed)"
true
