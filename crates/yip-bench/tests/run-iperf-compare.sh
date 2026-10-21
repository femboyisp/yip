#!/usr/bin/env bash
# run-iperf-compare.sh — iperf3 TCP & UDP throughput + ping latency/loss under netem,
# across contemporary tunnels and mesh overlays:
#   yip, WireGuard, AmneziaWG, OpenVPN, n2n, ZeroTier, Tailscale, NetBird.
#
# Each contender is set up in its OWN dedicated netns pair; at each loss rate
# (0 5 10 %, symmetric delay 5ms) we run:
#   ping      -c 50 -i 0.1             -> effective loss % + avg RTT (ms)
#   iperf3    -c <tun> -t 8             -> TCP goodput (Mbit/s)
#   iperf3 -u -c <tun> -b <rate> -t 8   -> UDP throughput (Mbit/s) + UDP loss %
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

# ── AmneziaWG ─────────────────────────────────────────────────────────────────
NS_AA="ipfAA"; NS_AB="ipfAB"; VAA="ipfvAA"; VAB="ipfvAB"
VAA_IP="10.18.0.1"; VAB_IP="10.18.0.2"
TUN_AA_IP="10.19.0.1"; TUN_AB_IP="10.19.0.2"
APORT_A="51870"; APORT_B="51871"
AWG_AVAILABLE=true

# ── ZeroTier ──────────────────────────────────────────────────────────────────
NS_ZA="ipfZA"; NS_ZB="ipfZB"; VZA="ipfvZA"; VZB="ipfvZB"
VZA_IP="10.20.0.1"; VZB_IP="10.20.0.2"
TUN_ZA_IP="10.21.0.1"; TUN_ZB_IP="10.21.0.2"
ZT_AVAILABLE=true

# ── Tailscale ─────────────────────────────────────────────────────────────────
NS_TA="ipfTA"; NS_TB="ipfTB"; VTA="ipfvTA"; VTB="ipfvTB"
VTA_IP="10.22.0.1"; VTB_IP="10.22.0.2"
TUN_TA_IP="10.23.0.1"; TUN_TB_IP="10.23.0.2"
TS_AVAILABLE=true

# ── NetBird ───────────────────────────────────────────────────────────────────
NS_BA="ipfBA"; NS_BB="ipfBB"; VBA="ipfvBA"; VBB="ipfvBB"
VBA_IP="10.24.0.1"; VBB_IP="10.24.0.2"
TUN_BA_IP="10.25.0.1"; TUN_BB_IP="10.25.0.2"
NB_AVAILABLE=true

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_YA" ] && kill "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill "$PID_YB" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_YA" ] && kill -9 "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill -9 "$PID_YB" 2>/dev/null || true
    # Remove virtual interfaces before deleting namespaces
    ip netns exec "$NS_WA" ip link del wg0 2>/dev/null || true
    ip netns exec "$NS_WB" ip link del wg0 2>/dev/null || true
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
    local ns="$1" dst="$2" out loss rttline rtt
    out="$(ip netns exec "$ns" ping -c "$PING_COUNT" -i "$PING_INTERVAL" -W 1 "$dst" 2>&1)" || true
    loss="$(echo "$out" | sed -nE 's/.* ([0-9.]+)% packet loss.*/\1/p' | head -1)"
    [ -z "$loss" ] && loss="100"
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
    if echo "$mbps" | grep -qi 'Gbits'; then
        mbps="$(echo "$mbps" | grep -oP '[0-9.]+' | awk '{printf "%.1f", $1*1000}')"
    else
        mbps="$(echo "$mbps" | grep -oP '[0-9.]+' | head -1)"
    fi
    [ -z "$mbps" ] && mbps="N/A"
    echo "$mbps"
}

# ── helper: iperf3 UDP Mbit/s and loss %; server in <ns_srv> bound to <srv_ip>,
#    client in <ns_cli> -> <srv_ip>. echo "<mbps> <loss_pct>" ───────────────────
measure_iperf_udp() {
    local ns_srv="$1" srv_ip="$2" ns_cli="$3" out mbps loss
    ip netns exec "$ns_srv" iperf3 -s -1 -B "$srv_ip" >/dev/null 2>&1 &
    sleep 0.5
    out="$(ip netns exec "$ns_cli" iperf3 -c "$srv_ip" -u -b "${UDP_RATE:-50M}" -t 8 -J 2>/dev/null || true)"
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
    echo "$mbps $loss"
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
    local privA pubA privB pubB
    privA="$(wg genkey)"; pubA="$(echo "$privA" | wg pubkey)"
    privB="$(wg genkey)"; pubB="$(echo "$privB" | wg pubkey)"
    echo "[wg] creating namespaces and veth pair"
    make_pair "$NS_WA" "$NS_WB" "$VWA" "$VWB" "$VWA_IP" "$VWB_IP"
    ip netns exec "$NS_WA" ip link add wg0 type wireguard
    ip netns exec "$NS_WB" ip link add wg0 type wireguard
    ip netns exec "$NS_WA" ip addr add "${TUN_WA_IP}/24" dev wg0
    ip netns exec "$NS_WB" ip addr add "${TUN_WB_IP}/24" dev wg0
    echo "$privA" > "$TMPDIR_TEST/wgA.key"
    echo "$privB" > "$TMPDIR_TEST/wgB.key"
    ip netns exec "$NS_WA" wg set wg0 listen-port "$WPORT_A" private-key "$TMPDIR_TEST/wgA.key" \
        peer "$pubB" endpoint "${VWB_IP}:${WPORT_B}" allowed-ips "${TUN_WB_IP}/32"
    ip netns exec "$NS_WB" wg set wg0 listen-port "$WPORT_B" private-key "$TMPDIR_TEST/wgB.key" \
        peer "$pubA" endpoint "${VWA_IP}:${WPORT_A}" allowed-ips "${TUN_WA_IP}/32"
    ip netns exec "$NS_WA" ip link set wg0 up
    ip netns exec "$NS_WB" ip link set wg0 up
    sleep 0.5
    if ! ip netns exec "$NS_WB" ping -c 3 -W 5 "$TUN_WA_IP" >/dev/null 2>&1; then
        echo "[wg] SKIP: baseline ping failed"; WG_AVAILABLE=false; return
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
    privA="$(awg genkey)"; pubA="$(echo "$privA" | awg pubkey)"
    privB="$(awg genkey)"; pubB="$(echo "$privB" | awg pubkey)"
    echo "[awg] creating namespaces and veth pair"
    make_pair "$NS_AA" "$NS_AB" "$VAA" "$VAB" "$VAA_IP" "$VAB_IP"
    if [ "$use_go" = true ]; then
        ip netns exec "$NS_AA" amneziawg-go awg0 >"$TMPDIR_TEST/awg-go-a.log" 2>&1 &
        ip netns exec "$NS_AB" amneziawg-go awg0 >"$TMPDIR_TEST/awg-go-b.log" 2>&1 &
        sleep 0.5
    else
        ip netns exec "$NS_AA" ip link add awg0 type amneziawg
        ip netns exec "$NS_AB" ip link add awg0 type amneziawg
    fi
    ip netns exec "$NS_AA" ip addr add "${TUN_AA_IP}/24" dev awg0
    ip netns exec "$NS_AB" ip addr add "${TUN_AB_IP}/24" dev awg0

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
AllowedIPs = ${TUN_AB_IP}/32
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
AllowedIPs = ${TUN_AA_IP}/32
EOF

    ip netns exec "$NS_AA" awg setconf awg0 "$CFG_AA"
    ip netns exec "$NS_AB" awg setconf awg0 "$CFG_AB"
    ip netns exec "$NS_AA" ip link set awg0 up
    ip netns exec "$NS_AB" ip link set awg0 up
    sleep 0.5
    if ! ip netns exec "$NS_AB" ping -c 3 -W 5 "$TUN_AA_IP" >/dev/null 2>&1; then
        echo "[awg] SKIP: baseline ping failed"; AWG_AVAILABLE=false; return
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
        --tls-server --cert "$TMPDIR_TEST/ovpn-a.crt" --key "$TMPDIR_TEST/ovpn-a.key" \
        --peer-fingerprint "$FB" --data-ciphers AES-256-GCM \
        --proto udp --verb 1 --ping 10 --ping-restart 0 \
        >"$TMPDIR_TEST/ovpn-a.log" 2>&1 &
    ip netns exec "$NS_OB" openvpn \
        --dev tun0 --dev-type tun \
        --remote "$VOA_IP" --rport 1194 --ifconfig "$TUN_OB_IP" "$TUN_OA_IP" \
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
LOSS_RATES="0 5 10"

echo ""
echo "=========================================================="
echo "  iperf3 TCP & UDP throughput + ping latency/loss under netem"
echo "  ping -c ${PING_COUNT} -i ${PING_INTERVAL}; iperf3 -t 8; netem: loss X% delay 5ms (symmetric)"
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

    # yip
    read -r Y_LOSS Y_RTT <<< "$(measure_ping "$NS_YB" "$TUN_YA_IP")"
    Y_TCP="$(measure_iperf "$NS_YA" "$TUN_YA_IP" "$NS_YB")"
    read -r Y_UDP_MBPS Y_UDP_LOSS <<< "$(measure_iperf_udp "$NS_YA" "$TUN_YA_IP" "$NS_YB")"
    echo "[yip] ping_loss=${Y_LOSS}% rtt=${Y_RTT}ms tcp=${Y_TCP}Mbit/s udp=${Y_UDP_MBPS}Mbit/s udp_loss=${Y_UDP_LOSS}%"

    # WireGuard
    W_LOSS="N/A"; W_RTT="N/A"; W_TCP="N/A"; W_UDP_MBPS="N/A"; W_UDP_LOSS="N/A"
    if [ "$WG_AVAILABLE" = true ]; then
        read -r W_LOSS W_RTT <<< "$(measure_ping "$NS_WB" "$TUN_WA_IP")"
        W_TCP="$(measure_iperf "$NS_WA" "$TUN_WA_IP" "$NS_WB")"
        read -r W_UDP_MBPS W_UDP_LOSS <<< "$(measure_iperf_udp "$NS_WA" "$TUN_WA_IP" "$NS_WB")"
        echo "[wg] ping_loss=${W_LOSS}% rtt=${W_RTT}ms tcp=${W_TCP}Mbit/s udp=${W_UDP_MBPS}Mbit/s udp_loss=${W_UDP_LOSS}%"
    fi

    # AmneziaWG
    A_LOSS="N/A"; A_RTT="N/A"; A_TCP="N/A"; A_UDP_MBPS="N/A"; A_UDP_LOSS="N/A"
    if [ "$AWG_AVAILABLE" = true ]; then
        read -r A_LOSS A_RTT <<< "$(measure_ping "$NS_AB" "$TUN_AA_IP")"
        A_TCP="$(measure_iperf "$NS_AA" "$TUN_AA_IP" "$NS_AB")"
        read -r A_UDP_MBPS A_UDP_LOSS <<< "$(measure_iperf_udp "$NS_AA" "$TUN_AA_IP" "$NS_AB")"
        echo "[awg] ping_loss=${A_LOSS}% rtt=${A_RTT}ms tcp=${A_TCP}Mbit/s udp=${A_UDP_MBPS}Mbit/s udp_loss=${A_UDP_LOSS}%"
    fi

    # OpenVPN
    O_LOSS="N/A"; O_RTT="N/A"; O_TCP="N/A"; O_UDP_MBPS="N/A"; O_UDP_LOSS="N/A"
    if [ "$OVPN_AVAILABLE" = true ]; then
        read -r O_LOSS O_RTT <<< "$(measure_ping "$NS_OB" "$TUN_OA_IP")"
        O_TCP="$(measure_iperf "$NS_OA" "$TUN_OA_IP" "$NS_OB")"
        read -r O_UDP_MBPS O_UDP_LOSS <<< "$(measure_iperf_udp "$NS_OA" "$TUN_OA_IP" "$NS_OB")"
        echo "[ovpn] ping_loss=${O_LOSS}% rtt=${O_RTT}ms tcp=${O_TCP}Mbit/s udp=${O_UDP_MBPS}Mbit/s udp_loss=${O_UDP_LOSS}%"
    fi

    # n2n
    N_LOSS="N/A"; N_RTT="N/A"; N_TCP="N/A"; N_UDP_MBPS="N/A"; N_UDP_LOSS="N/A"
    if [ "$N2N_AVAILABLE" = true ]; then
        read -r N_LOSS N_RTT <<< "$(measure_ping "$NS_NB" "$OVL_NA_IP")"
        N_TCP="$(measure_iperf "$NS_NA" "$OVL_NA_IP" "$NS_NB")"
        read -r N_UDP_MBPS N_UDP_LOSS <<< "$(measure_iperf_udp "$NS_NA" "$OVL_NA_IP" "$NS_NB")"
        echo "[n2n] ping_loss=${N_LOSS}% rtt=${N_RTT}ms tcp=${N_TCP}Mbit/s udp=${N_UDP_MBPS}Mbit/s udp_loss=${N_UDP_LOSS}%"
    fi

    # ZeroTier
    Z_LOSS="N/A"; Z_RTT="N/A"; Z_TCP="N/A"; Z_UDP_MBPS="N/A"; Z_UDP_LOSS="N/A"
    if [ "$ZT_AVAILABLE" = true ]; then
        read -r Z_LOSS Z_RTT <<< "$(measure_ping "$NS_ZB" "$TUN_ZA_IP")"
        Z_TCP="$(measure_iperf "$NS_ZA" "$TUN_ZA_IP" "$NS_ZB")"
        read -r Z_UDP_MBPS Z_UDP_LOSS <<< "$(measure_iperf_udp "$NS_ZA" "$TUN_ZA_IP" "$NS_ZB")"
        echo "[zerotier] ping_loss=${Z_LOSS}% rtt=${Z_RTT}ms tcp=${Z_TCP}Mbit/s udp=${Z_UDP_MBPS}Mbit/s udp_loss=${Z_UDP_LOSS}%"
    fi

    # Tailscale
    T_LOSS="N/A"; T_RTT="N/A"; T_TCP="N/A"; T_UDP_MBPS="N/A"; T_UDP_LOSS="N/A"
    if [ "$TS_AVAILABLE" = true ]; then
        read -r T_LOSS T_RTT <<< "$(measure_ping "$NS_TB" "$TUN_TA_IP")"
        T_TCP="$(measure_iperf "$NS_TA" "$TUN_TA_IP" "$NS_TB")"
        read -r T_UDP_MBPS T_UDP_LOSS <<< "$(measure_iperf_udp "$NS_TA" "$TUN_TA_IP" "$NS_TB")"
        echo "[tailscale] ping_loss=${T_LOSS}% rtt=${T_RTT}ms tcp=${T_TCP}Mbit/s udp=${T_UDP_MBPS}Mbit/s udp_loss=${T_UDP_LOSS}%"
    fi

    # NetBird
    B_LOSS="N/A"; B_RTT="N/A"; B_TCP="N/A"; B_UDP_MBPS="N/A"; B_UDP_LOSS="N/A"
    if [ "$NB_AVAILABLE" = true ]; then
        read -r B_LOSS B_RTT <<< "$(measure_ping "$NS_BB" "$TUN_BA_IP")"
        B_TCP="$(measure_iperf "$NS_BA" "$TUN_BA_IP" "$NS_BB")"
        read -r B_UDP_MBPS B_UDP_LOSS <<< "$(measure_iperf_udp "$NS_BA" "$TUN_BA_IP" "$NS_BB")"
        echo "[netbird] ping_loss=${B_LOSS}% rtt=${B_RTT}ms tcp=${B_TCP}Mbit/s udp=${B_UDP_MBPS}Mbit/s udp_loss=${B_UDP_LOSS}%"
    fi

    # ── emit per-loss-rate table ──────────────────────────────────────────────
    echo ""
    echo "  --- loss=${LOSS}% ---"
    echo "  | contender | eff_loss% | rtt_ms | tcp_Mbit/s | udp_Mbit/s | udp_loss% |"
    echo "  |-----------|-----------|--------|------------|------------|-----------|"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s |\n" "yip"       "$Y_LOSS" "$Y_RTT" "$Y_TCP" "$Y_UDP_MBPS" "$Y_UDP_LOSS"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s |\n" "wireguard" "$W_LOSS" "$W_RTT" "$W_TCP" "$W_UDP_MBPS" "$W_UDP_LOSS"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s |\n" "amneziawg" "$A_LOSS" "$A_RTT" "$A_TCP" "$A_UDP_MBPS" "$A_UDP_LOSS"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s |\n" "openvpn"   "$O_LOSS" "$O_RTT" "$O_TCP" "$O_UDP_MBPS" "$O_UDP_LOSS"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s |\n" "n2n"       "$N_LOSS" "$N_RTT" "$N_TCP" "$N_UDP_MBPS" "$N_UDP_LOSS"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s |\n" "zerotier"  "$Z_LOSS" "$Z_RTT" "$Z_TCP" "$Z_UDP_MBPS" "$Z_UDP_LOSS"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s |\n" "tailscale" "$T_LOSS" "$T_RTT" "$T_TCP" "$T_UDP_MBPS" "$T_UDP_LOSS"
    printf "  | %-9s | %-9s | %-6s | %-10s | %-10s | %-9s |\n" "netbird"   "$B_LOSS" "$B_RTT" "$B_TCP" "$B_UDP_MBPS" "$B_UDP_LOSS"
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
