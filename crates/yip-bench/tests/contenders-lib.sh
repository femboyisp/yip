#!/usr/bin/env bash
# contenders-lib.sh — Shared contender definitions, topology, and lifecycles
# for the YIP benchmark suite (run-iperf-compare.sh and run-scp-compare.sh).
#
# Supported Contenders (10):
#   1. yip          — Multi-queue TUN, post-quantum ML-KEM-768/X25519, ChaCha20-Poly1305, zero-copy sharding
#   2. wireguard    — Linux kernel in-tree WireGuard (L3, Noise_IK_25519_ChaChaPoly)
#   3. wireguard-go — Userspace Go WireGuard implementation (golang.zx2c4.com/wireguard)
#   4. amneziawg    — DPI-obfuscated WireGuard variant (advanced junk packet headers & padding)
#   5. openvpn      — Classic userspace SSL/TLS tunnel (AES-256-GCM, TLS 1.3, TCP/UDP)
#   6. n2n          — Peer-to-peer overlay network with supernode relaying & twofish/AES encryption
#   7. zerotier     — ZeroTier One virtual ethernet network hypervisor (L2 TAP overlay)
#   8. tailscale    — Mesh VPN based on WireGuard with Headscale self-hosted coordination server
#   9. netbird      — WireGuard-based overlay mesh with local management & WebRTC signaling
#  10. nebula       — Mutually authenticated peer-to-peer overlay network (Slack / Defined Networking)
#
# Sourced by run-iperf-compare.sh and run-scp-compare.sh.
set -euo pipefail

TMPDIR_TEST="${TMPDIR_TEST:-$(mktemp -d /dev/shm/yip-bench.XXXXXX 2>/dev/null || mktemp -d /tmp/yip-bench.XXXXXX)}"
mkdir -p "$TMPDIR_TEST"
YIPD="${YIPD:-yipd}"
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"
LAST_CHECK_PIDS=()
ISOLATION_FAILED="${ISOLATION_FAILED:-false}"

# ══════════════════════════════════════════════════════════════════════════════
# Contender Network Topology & Namespace Configuration
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. Yip ────────────────────────────────────────────────────────────────────
NS_YA="${NS_YA:-ipfYA}"; NS_YB="${NS_YB:-ipfYB}"; VYA="${VYA:-ipfvYA}"; VYB="${VYB:-ipfvYB}"
VYA_IP="${VYA_IP:-10.10.0.1}"; VYB_IP="${VYB_IP:-10.10.0.2}"
TUN_YA_IP="${TUN_YA_IP:-10.11.0.1}"; TUN_YB_IP="${TUN_YB_IP:-10.11.0.2}"
TUN_YA_IP6="${TUN_YA_IP6:-fd00:11::1}"; TUN_YB_IP6="${TUN_YB_IP6:-fd00:11::2}"
YPORT_A="443"; YPORT_B="443"; YIP_TUN_DEV="yip0"; YIP_MTU="${YIP_MTU:-1420}"; YIP_SHARDS="${YIP_SHARDS:-1}"
PID_YA=""; PID_YB=""

# ── 2. WireGuard (Kernel) ─────────────────────────────────────────────────────
NS_WA="${NS_WA:-ipfWA}"; NS_WB="${NS_WB:-ipfWB}"; VWA="${VWA:-ipfvWA}"; VWB="${VWB:-ipfvWB}"
VWA_IP="${VWA_IP:-10.12.0.1}"; VWB_IP="${VWB_IP:-10.12.0.2}"
TUN_WA_IP="${TUN_WA_IP:-10.13.0.1}"; TUN_WB_IP="${TUN_WB_IP:-10.13.0.2}"
TUN_WA_IP6="${TUN_WA_IP6:-fd00:13::1}"; TUN_WB_IP6="${TUN_WB_IP6:-fd00:13::2}"
WPORT_A="51860"; WPORT_B="51861"
WG_AVAILABLE=""

# ── 3. WireGuard-Go ───────────────────────────────────────────────────────────
NS_GGA="${NS_GGA:-ipfGGA}"; NS_GGB="${NS_GGB:-ipfGGB}"; VGGA="${VGGA:-ipfvGGA}"; VGGB="${VGGB:-ipfvGGB}"
VGGA_IP="${VGGA_IP:-10.26.0.1}"; VGGB_IP="${VGGB_IP:-10.26.0.2}"
TUN_GGA_IP="${TUN_GGA_IP:-10.27.0.1}"; TUN_GGB_IP="${TUN_GGB_IP:-10.27.0.2}"
TUN_GGA_IP6="${TUN_GGA_IP6:-fd00:27::1}"; TUN_GGB_IP6="${TUN_GGB_IP6:-fd00:27::2}"
GGPORT_A="51880"; GGPORT_B="51881"
WGGO_AVAILABLE=""
PID_GGA=""; PID_GGB=""

# ── 4. OpenVPN ────────────────────────────────────────────────────────────────
NS_OA="${NS_OA:-ipfOA}"; NS_OB="${NS_OB:-ipfOB}"; VOA="${VOA:-ipfvOA}"; VOB="${VOB:-ipfvOB}"
VOA_IP="${VOA_IP:-10.14.0.1}"; VOB_IP="${VOB_IP:-10.14.0.2}"
TUN_OA_IP="${TUN_OA_IP:-10.15.0.1}"; TUN_OB_IP="${TUN_OB_IP:-10.15.0.2}"
TUN_OA_IP6="${TUN_OA_IP6:-fd00:15::1}"; TUN_OB_IP6="${TUN_OB_IP6:-fd00:15::2}"
OVPN_AVAILABLE=""
PID_OA=""; PID_OB=""

# ── 5. n2n ────────────────────────────────────────────────────────────────────
NS_NA="${NS_NA:-ipfNA}"; NS_NB="${NS_NB:-ipfNB}"; VNA="${VNA:-ipfvNA}"; VNB="${VNB:-ipfvNB}"
VNA_IP="${VNA_IP:-10.16.0.1}"; VNB_IP="${VNB_IP:-10.16.0.2}"
OVL_NA_IP="${OVL_NA_IP:-10.17.0.1}"; OVL_NB_IP="${OVL_NB_IP:-10.17.0.2}"
OVL_NA_IP6="${OVL_NA_IP6:-fd00:17::1}"; OVL_NB_IP6="${OVL_NB_IP6:-fd00:17::2}"
N2N_PORT="7654"
N2N_AVAILABLE=""
PID_N2N_SN=""; PID_N2N_EA=""; PID_N2N_EB=""

# ── 6. AmneziaWG ──────────────────────────────────────────────────────────────
NS_AA="${NS_AA:-ipfAA}"; NS_AB="${NS_AB:-ipfAB}"; VAA="${VAA:-ipfvAA}"; VAB="${VAB:-ipfvAB}"
VAA_IP="${VAA_IP:-10.18.0.1}"; VAB_IP="${VAB_IP:-10.18.0.2}"
TUN_AA_IP="${TUN_AA_IP:-10.19.0.1}"; TUN_AB_IP="${TUN_AB_IP:-10.19.0.2}"
TUN_AA_IP6="${TUN_AA_IP6:-fd00:19::1}"; TUN_AB_IP6="${TUN_AB_IP6:-fd00:19::2}"
APORT_A="51870"; APORT_B="51871"
AWG_AVAILABLE=""
PID_AA=""; PID_AB=""

# ── 7. ZeroTier ───────────────────────────────────────────────────────────────
NS_ZA="${NS_ZA:-ipfZA}"; NS_ZB="${NS_ZB:-ipfZB}"; VZA="${VZA:-ipfvZA}"; VZB="${VZB:-ipfvZB}"
VZA_IP="${VZA_IP:-10.20.0.1}"; VZB_IP="${VZB_IP:-10.20.0.2}"
TUN_ZA_IP="${TUN_ZA_IP:-10.21.0.1}"; TUN_ZB_IP="${TUN_ZB_IP:-10.21.0.2}"
TUN_ZA_IP6="${TUN_ZA_IP6:-fd00:21::1}"; TUN_ZB_IP6="${TUN_ZB_IP6:-fd00:21::2}"
ZT_AVAILABLE=""
PID_ZT_A=""; PID_ZT_B=""

# ── 8. Tailscale ──────────────────────────────────────────────────────────────
NS_TA="${NS_TA:-ipfTA}"; NS_TB="${NS_TB:-ipfTB}"; VTA="${VTA:-ipfvTA}"; VTB="${VTB:-ipfvTB}"
VTA_IP="${VTA_IP:-10.22.0.1}"; VTB_IP="${VTB_IP:-10.22.0.2}"
TUN_TA_IP="${TUN_TA_IP:-10.23.0.1}"; TUN_TB_IP="${TUN_TB_IP:-10.23.0.2}"
TUN_TA_IP6="${TUN_TA_IP6:-fd00:23::1}"; TUN_TB_IP6="${TUN_TB_IP6:-fd00:23::2}"
TS_AVAILABLE=""
PID_TS_HS=""; PID_TS_DA=""; PID_TS_DB=""

# ── 9. NetBird ────────────────────────────────────────────────────────────────
NS_BA="${NS_BA:-ipfBA}"; NS_BB="${NS_BB:-ipfBB}"; VBA="${VBA:-ipfvBA}"; VBB="${VBB:-ipfvBB}"
VBA_IP="${VBA_IP:-10.24.0.1}"; VBB_IP="${VBB_IP:-10.24.0.2}"
TUN_BA_IP="${TUN_BA_IP:-10.25.0.1}"; TUN_BB_IP="${TUN_BB_IP:-10.25.0.2}"
TUN_BA_IP6="${TUN_BA_IP6:-fd00:25::1}"; TUN_BB_IP6="${TUN_BB_IP6:-fd00:25::2}"
NB_AVAILABLE=""
PID_NB_SIG=""; PID_NB_MGMT=""; PID_NB_SA=""; PID_NB_SB=""

# ── 10. Nebula ────────────────────────────────────────────────────────────────
NS_EA="${NS_EA:-ipfEA}"; NS_EB="${NS_EB:-ipfEB}"; VEA="${VEA:-ipfvEA}"; VEB="${VEB:-ipfvEB}"
VEA_IP="${VEA_IP:-10.28.0.1}"; VEB_IP="${VEB_IP:-10.28.0.2}"
TUN_EA_IP="${TUN_EA_IP:-10.29.0.1}"; TUN_EB_IP="${TUN_EB_IP:-10.29.0.2}"
TUN_EA_IP6="${TUN_EA_IP6:-fd00:29::1}"; TUN_EB_IP6="${TUN_EB_IP6:-fd00:29::2}"
NEB_PORT="4242"
NEB_AVAILABLE=""
PID_NEB_A=""; PID_NEB_B=""

ALL_NETNS_LIST=(
    "$NS_YA" "$NS_YB"
    "$NS_WA" "$NS_WB"
    "$NS_GGA" "$NS_GGB"
    "$NS_OA" "$NS_OB"
    "$NS_NA" "$NS_NB"
    "$NS_AA" "$NS_AB"
    "$NS_ZA" "$NS_ZB"
    "$NS_TA" "$NS_TB"
    "$NS_BA" "$NS_BB"
    "$NS_EA" "$NS_EB"
)

# ══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ══════════════════════════════════════════════════════════════════════════════

is_pid_alive() {
    local pid="$1"
    [ -z "$pid" ] && return 1
    [ "$pid" = "$$" ] && return 1
    if [ ! -d "/proc/$pid" ]; then
        return 1
    fi
    local state
    state="$(awk '/^State:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true)"
    if [ -z "$state" ] || [ "$state" = "Z" ] || [ "$state" = "X" ]; then
        wait "$pid" 2>/dev/null || true
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

make_pair() {
    local nsR="$1" nsS="$2" vR="$3" vS="$4" ipR="$5" ipS="$6"
    ip netns add "$nsR" 2>/dev/null || true
    ip netns add "$nsS" 2>/dev/null || true
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
    ip link add "$vR" type veth peer name "$vS" 2>/dev/null || true
    ip link set "$vR" netns "$nsR" 2>/dev/null || true
    ip link set "$vS" netns "$nsS" 2>/dev/null || true
    ip netns exec "$nsR" ip addr add "$ipR/24" dev "$vR" 2>/dev/null || true
    ip netns exec "$nsR" ip link set dev "$vR" txqueuelen 10000 2>/dev/null || true
    ip netns exec "$nsR" ip link set "$vR" up
    ip netns exec "$nsR" ip link set lo up
    ip netns exec "$nsS" ip addr add "$ipS/24" dev "$vS" 2>/dev/null || true
    ip netns exec "$nsS" ip link set dev "$vS" txqueuelen 10000 2>/dev/null || true
    ip netns exec "$nsS" ip link set "$vS" up
    ip netns exec "$nsS" ip link set lo up
}

NETEM_DELAY="${NETEM_DELAY:-5ms}"
NETEM_LIMIT="${NETEM_LIMIT:-50000}"

apply_netem() {
    local nsR="$1" nsS="$2" vR="$3" vS="$4" loss="$5"
    if [ "$loss" -eq 0 ]; then
        if [ "$NETEM_DELAY" = "0" ] || [ "$NETEM_DELAY" = "0ms" ]; then
            ip netns exec "$nsR" tc qdisc del dev "$vR" root 2>/dev/null || true
            ip netns exec "$nsS" tc qdisc del dev "$vS" root 2>/dev/null || true
        else
            ip netns exec "$nsR" tc qdisc replace dev "$vR" root netem delay "$NETEM_DELAY" limit "$NETEM_LIMIT" 2>/dev/null || true
            ip netns exec "$nsS" tc qdisc replace dev "$vS" root netem delay "$NETEM_DELAY" limit "$NETEM_LIMIT" 2>/dev/null || true
        fi
        return
    fi
    ip netns exec "$nsR" tc qdisc replace dev "$vR" root netem loss "${loss}%" delay "$NETEM_DELAY" limit "$NETEM_LIMIT" 2>/dev/null || true
    ip netns exec "$nsS" tc qdisc replace dev "$vS" root netem loss "${loss}%" delay "$NETEM_DELAY" limit "$NETEM_LIMIT" 2>/dev/null || true
}

reap_pids() {
    local pids=("$@")
    for pid in "${pids[@]}"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            for _ in $(seq 1 10); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.05
            done
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}

clean_netns() {
    local namespaces=("$@")
    for ns in "${namespaces[@]}"; do
        if [ -n "$ns" ]; then
            ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
            ip netns del "$ns" 2>/dev/null || true
        fi
    done
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
        nebula|neb)
            for ns in "$NS_EA" "$NS_EB"; do
                if echo "$ns_list" | grep -qx "$ns"; then leaked_ns+=("$ns"); fi
            done
            for p in $(pgrep -x nebula 2>/dev/null || true); do
                if is_test_pid "$p"; then leaked_pids+=("$p(nebula)"); fi
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
    LAST_CHECK_PIDS=()
    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Contender Implementations
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. Yip ────────────────────────────────────────────────────────────────────
start_yip() {
    echo "[yip] setting up yip tunnel"
    local GENKEY_A GENKEY_B PRIV_A PUB_A PRIV_B PUB_B CFG_A CFG_B
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
device=${YIP_TUN_DEV}
initiate=false
shards=${YIP_SHARDS}
EOF

    cat > "$CFG_B" <<EOF
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VYB_IP}:${YPORT_B}
peer_endpoint=${VYA_IP}:${YPORT_A}
device=${YIP_TUN_DEV}
initiate=true
shards=${YIP_SHARDS}
EOF

    make_pair "$NS_YA" "$NS_YB" "$VYA" "$VYB" "$VYA_IP" "$VYB_IP"

    LOG_A="$TMPDIR_TEST/yipA.log"
    LOG_B="$TMPDIR_TEST/yipB.log"
    ip netns exec "$NS_YA" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
    PID_YA=$!
    ip netns exec "$NS_YB" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
    PID_YB=$!

    local elapsed=0 interval=0.25 max_wait=20
    while true; do
        local a_up=0 b_up=0
        ip netns exec "$NS_YA" ip link show "$YIP_TUN_DEV" >/dev/null 2>&1 && a_up=1 || true
        ip netns exec "$NS_YB" ip link show "$YIP_TUN_DEV" >/dev/null 2>&1 && b_up=1 || true
        if [ "$a_up" -eq 1 ] && [ "$b_up" -eq 1 ]; then break; fi
        if ! kill -0 "$PID_YA" 2>/dev/null || ! kill -0 "$PID_YB" 2>/dev/null; then
            echo "[error] yip daemon died during startup" >&2
            cat "$LOG_A" "$LOG_B" || true
            return 1
        fi
        elapsed=$(awk "BEGIN {print $elapsed + $interval}")
        if awk "BEGIN {exit ($elapsed >= $max_wait) ? 0 : 1}"; then
            echo "[error] timed out waiting for yip TUN devices" >&2
            cat "$LOG_A" "$LOG_B" || true
            return 1
        fi
        sleep "$interval"
    done

    ip netns exec "$NS_YA" ip addr add "${TUN_YA_IP}/24" dev "$YIP_TUN_DEV"
    ip netns exec "$NS_YB" ip addr add "${TUN_YB_IP}/24" dev "$YIP_TUN_DEV"
    ip netns exec "$NS_YA" ip -6 addr add "${TUN_YA_IP6}/64" dev "$YIP_TUN_DEV" nodad 2>/dev/null || true
    ip netns exec "$NS_YB" ip -6 addr add "${TUN_YB_IP6}/64" dev "$YIP_TUN_DEV" nodad 2>/dev/null || true

    ip netns exec "$NS_YA" ip link set dev "$YIP_TUN_DEV" txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_YB" ip link set dev "$YIP_TUN_DEV" txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_YA" ip link set dev "$YIP_TUN_DEV" mtu "$YIP_MTU" 2>/dev/null || true
    ip netns exec "$NS_YB" ip link set dev "$YIP_TUN_DEV" mtu "$YIP_MTU" 2>/dev/null || true
    ip netns exec "$NS_YA" ip link set "$YIP_TUN_DEV" up
    ip netns exec "$NS_YB" ip link set "$YIP_TUN_DEV" up

    sleep 0.5
    ip netns exec "$NS_YB" ping -c 3 -W 5 "$TUN_YA_IP" >/dev/null 2>&1
    ip netns exec "$NS_YB" ping -6 -c 3 -W 5 "$TUN_YA_IP6" >/dev/null 2>&1
    return 0
}

stop_yip() {
    LAST_CHECK_PIDS=("$PID_YA:yipA" "$PID_YB:yipB")
    reap_pids "$PID_YA" "$PID_YB"
    PID_YA=""; PID_YB=""
    clean_netns "$NS_YA" "$NS_YB"
    rm -f "$TMPDIR_TEST/yipA.conf" "$TMPDIR_TEST/yipB.conf" "$TMPDIR_TEST/yipA.log" "$TMPDIR_TEST/yipB.log" 2>/dev/null || true
}

# ── 2. WireGuard ──────────────────────────────────────────────────────────────
start_wg() {
    if ! command -v wg >/dev/null 2>&1 || ! modprobe wireguard 2>/dev/null; then
        echo "[wg] SKIP: wg or wireguard kernel module not available"
        WG_AVAILABLE=false
        return 1
    fi
    echo "[wg] setting up WireGuard tunnel"
    make_pair "$NS_WA" "$NS_WB" "$VWA" "$VWB" "$VWA_IP" "$VWB_IP"

    local PRIV_A PUB_A PRIV_B PUB_B
    PRIV_A="$(wg genkey)"; PUB_A="$(echo "$PRIV_A" | wg pubkey)"
    PRIV_B="$(wg genkey)"; PUB_B="$(echo "$PRIV_B" | wg pubkey)"
    printf '%s' "$PRIV_A" > "$TMPDIR_TEST/wg_priv_a"
    printf '%s' "$PRIV_B" > "$TMPDIR_TEST/wg_priv_b"

    ip netns exec "$NS_WA" ip link add wg0 type wireguard
    ip netns exec "$NS_WB" ip link add wg0 type wireguard

    ip netns exec "$NS_WA" wg set wg0 private-key "$TMPDIR_TEST/wg_priv_a" listen-port "$WPORT_A" \
        peer "$PUB_B" allowed-ips "0.0.0.0/0,::/0" endpoint "${VWB_IP}:${WPORT_B}"
    ip netns exec "$NS_WB" wg set wg0 private-key "$TMPDIR_TEST/wg_priv_b" listen-port "$WPORT_B" \
        peer "$PUB_A" allowed-ips "0.0.0.0/0,::/0" endpoint "${VWA_IP}:${WPORT_A}"

    ip netns exec "$NS_WA" ip addr add "${TUN_WA_IP}/24" dev wg0
    ip netns exec "$NS_WB" ip addr add "${TUN_WB_IP}/24" dev wg0
    ip netns exec "$NS_WA" ip -6 addr add "${TUN_WA_IP6}/64" dev wg0 nodad 2>/dev/null || true
    ip netns exec "$NS_WB" ip -6 addr add "${TUN_WB_IP6}/64" dev wg0 nodad 2>/dev/null || true

    ip netns exec "$NS_WA" ip link set dev wg0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_WB" ip link set dev wg0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_WA" ip link set dev wg0 mtu 1420 2>/dev/null || true
    ip netns exec "$NS_WB" ip link set dev wg0 mtu 1420 2>/dev/null || true
    ip netns exec "$NS_WA" ip link set wg0 up
    ip netns exec "$NS_WB" ip link set wg0 up

    WG_AVAILABLE=true
    sleep 0.5
    ip netns exec "$NS_WB" ping -c 3 -W 5 "$TUN_WA_IP" >/dev/null 2>&1
    ip netns exec "$NS_WB" ping -6 -c 3 -W 5 "$TUN_WA_IP6" >/dev/null 2>&1
    return 0
}

stop_wg() {
    LAST_CHECK_PIDS=()
    ip netns exec "$NS_WA" ip link del dev wg0 2>/dev/null || true
    ip netns exec "$NS_WB" ip link del dev wg0 2>/dev/null || true
    clean_netns "$NS_WA" "$NS_WB"
    rm -f "$TMPDIR_TEST/wg_priv_a" "$TMPDIR_TEST/wg_priv_b" 2>/dev/null || true
}

# ── 3. WireGuard-Go ───────────────────────────────────────────────────────────
start_wireguard_go() {
    local wggo_bin="wireguard-go"
    if ! command -v "$wggo_bin" >/dev/null 2>&1; then
        if command -v wireguard >/dev/null 2>&1; then
            wggo_bin="wireguard"
        else
            echo "[wggo] SKIP: 'wireguard-go' command not found"
            WGGO_AVAILABLE=false
            return 1
        fi
    fi
    if ! command -v wg >/dev/null 2>&1; then
        echo "[wggo] SKIP: 'wg' command not found"
        WGGO_AVAILABLE=false
        return 1
    fi
    apparmor_parser -R /etc/apparmor.d/wg 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.bin.wg 2>/dev/null || true
    echo "[wggo] generating keypairs"
    local privA pubA privB pubB
    privA="$(wg genkey 2>/dev/null || true)"; pubA="$(echo "$privA" | wg pubkey 2>/dev/null || true)"
    privB="$(wg genkey 2>/dev/null || true)"; pubB="$(echo "$privB" | wg pubkey 2>/dev/null || true)"
    if [ -z "$privA" ] || [ -z "$privB" ]; then
        echo "[wggo] SKIP: key generation failed"
        WGGO_AVAILABLE=false
        return 1
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
    ip netns exec "$NS_GGA" "$wggo_bin" -f wggo0 >"$TMPDIR_TEST/wggo-a.log" 2>&1 &
    PID_GGA=$!
    ip netns exec "$NS_GGB" "$wggo_bin" -f wggo0 >"$TMPDIR_TEST/wggo-b.log" 2>&1 &
    PID_GGB=$!

    local wggo_up=false
    for _ in $(seq 1 20); do
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
        stop_wireguard_go
        WGGO_AVAILABLE=false
        return 1
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
        echo "[wggo] SKIP: wg set configuration failed: $wg_err"
        stop_wireguard_go
        WGGO_AVAILABLE=false
        return 1
    fi

    if ! ip netns exec "$NS_GGA" ip addr add "${TUN_GGA_IP}/24" dev wggo0 2>/dev/null || \
       ! ip netns exec "$NS_GGB" ip addr add "${TUN_GGB_IP}/24" dev wggo0 2>/dev/null || \
       ! ip netns exec "$NS_GGA" ip -6 addr add "${TUN_GGA_IP6}/64" dev wggo0 nodad 2>/dev/null || \
       ! ip netns exec "$NS_GGB" ip -6 addr add "${TUN_GGB_IP6}/64" dev wggo0 nodad 2>/dev/null; then
        echo "[wggo] SKIP: interface setup failed"
        stop_wireguard_go
        WGGO_AVAILABLE=false
        return 1
    fi

    ip netns exec "$NS_GGA" ip link set dev wggo0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_GGB" ip link set dev wggo0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_GGA" ip link set dev wggo0 mtu 1420 2>/dev/null || true
    ip netns exec "$NS_GGB" ip link set dev wggo0 mtu 1420 2>/dev/null || true

    if ! ip netns exec "$NS_GGA" ip link set wggo0 up 2>/dev/null || \
       ! ip netns exec "$NS_GGB" ip link set wggo0 up 2>/dev/null; then
        echo "[wggo] SKIP: interface set up failed"
        stop_wireguard_go
        WGGO_AVAILABLE=false
        return 1
    fi

    sleep 0.5
    if ! ip netns exec "$NS_GGB" ping -c 3 -W 5 "$TUN_GGA_IP" >/dev/null 2>&1; then
        echo "[wggo] SKIP: baseline IPv4 ping failed"
        stop_wireguard_go
        WGGO_AVAILABLE=false
        return 1
    fi
    if ! ip netns exec "$NS_GGB" ping -6 -c 3 -W 5 "$TUN_GGA_IP6" >/dev/null 2>&1; then
        echo "[wggo] SKIP: baseline IPv6 ping failed"
        stop_wireguard_go
        WGGO_AVAILABLE=false
        return 1
    fi
    echo "[wggo] tunnel up"
    WGGO_AVAILABLE=true
    return 0
}

stop_wireguard_go() {
    LAST_CHECK_PIDS=("$PID_GGA:wggoA" "$PID_GGB:wggoB")
    reap_pids "$PID_GGA" "$PID_GGB"
    PID_GGA=""; PID_GGB=""
    ip netns exec "$NS_GGA" ip link del wggo0 2>/dev/null || true
    ip netns exec "$NS_GGB" ip link del wggo0 2>/dev/null || true
    rm -rf "/etc/netns/$NS_GGA" "/etc/netns/$NS_GGB" /etc/wireguard-run 2>/dev/null || true
    if [ -L /run/wireguard ]; then
        rm -f /run/wireguard 2>/dev/null || true
    fi
    rm -f "$TMPDIR_TEST/wggo_a" "$TMPDIR_TEST/wggo_b" 2>/dev/null || true
    clean_netns "$NS_GGA" "$NS_GGB"
}

# ── 4. OpenVPN ────────────────────────────────────────────────────────────────
start_ovpn() {
    if ! command -v openvpn >/dev/null 2>&1; then
        echo "[ovpn] SKIP: openvpn command not found"
        OVPN_AVAILABLE=false
        return 1
    fi
    echo "[ovpn] generating certificates"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$TMPDIR_TEST/ovpn-a.key" -out "$TMPDIR_TEST/ovpn-a.crt" \
        -days 1 -nodes -subj "/CN=ovpn-a" >/dev/null 2>&1
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$TMPDIR_TEST/ovpn-b.key" -out "$TMPDIR_TEST/ovpn-b.crt" \
        -days 1 -nodes -subj "/CN=ovpn-b" >/dev/null 2>&1
    chmod 600 "$TMPDIR_TEST/ovpn-a.key" "$TMPDIR_TEST/ovpn-b.key"

    local FA FB
    FA="$(openssl x509 -in "$TMPDIR_TEST/ovpn-a.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
    FB="$(openssl x509 -in "$TMPDIR_TEST/ovpn-b.crt" -noout -fingerprint -sha256 | cut -d= -f2)"

    echo "[ovpn] creating namespaces and veth pair"
    make_pair "$NS_OA" "$NS_OB" "$VOA" "$VOB" "$VOA_IP" "$VOB_IP"

    echo "[ovpn] launching openvpn server & client"
    ip netns exec "$NS_OA" openvpn \
        --dev tun0 --dev-type tun \
        --local "$VOA_IP" --port 1194 --ifconfig "$TUN_OA_IP" "$TUN_OB_IP" \
        --tls-server --cert "$TMPDIR_TEST/ovpn-a.crt" --key "$TMPDIR_TEST/ovpn-a.key" \
        --peer-fingerprint "$FB" --data-ciphers AES-256-GCM \
        --proto udp --verb 1 --ping 10 --ping-restart 0 \
        >"$TMPDIR_TEST/ovpn-a.log" 2>&1 &
    PID_OA=$!

    ip netns exec "$NS_OB" openvpn \
        --dev tun0 --dev-type tun \
        --remote "$VOA_IP" --rport 1194 --ifconfig "$TUN_OB_IP" "$TUN_OA_IP" \
        --tls-client --cert "$TMPDIR_TEST/ovpn-b.crt" --key "$TMPDIR_TEST/ovpn-b.key" \
        --peer-fingerprint "$FA" --data-ciphers AES-256-GCM \
        --proto udp --verb 1 --ping 10 --ping-restart 0 \
        >"$TMPDIR_TEST/ovpn-b.log" 2>&1 &
    PID_OB=$!

    local i
    for i in $(seq 1 40); do
        if ip netns exec "$NS_OB" ping -c 1 -W 1 "$TUN_OA_IP" >/dev/null 2>&1; then
            break
        fi
        sleep 0.25
    done
    if [ "$i" -ge 40 ]; then
        echo "[ovpn] SKIP: baseline ping failed"
        tail -10 "$TMPDIR_TEST/ovpn-a.log" "$TMPDIR_TEST/ovpn-b.log" 2>/dev/null || true
        stop_ovpn
        OVPN_AVAILABLE=false
        return 1
    fi

    ip netns exec "$NS_OA" ip -6 addr add "${TUN_OA_IP6}/64" dev tun0 nodad 2>/dev/null || true
    ip netns exec "$NS_OB" ip -6 addr add "${TUN_OB_IP6}/64" dev tun0 nodad 2>/dev/null || true
    ip netns exec "$NS_OA" ip link set dev tun0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_OB" ip link set dev tun0 txqueuelen 10000 2>/dev/null || true

    sleep 0.5
    ip netns exec "$NS_OB" ping -6 -c 3 -W 5 "$TUN_OA_IP6" >/dev/null 2>&1 || true

    echo "[ovpn] tunnel up"
    OVPN_AVAILABLE=true
    return 0
}

stop_ovpn() {
    LAST_CHECK_PIDS=("$PID_OA:ovpnA" "$PID_OB:ovpnB")
    reap_pids "$PID_OA" "$PID_OB"
    PID_OA=""; PID_OB=""
    clean_netns "$NS_OA" "$NS_OB"
    rm -f "$TMPDIR_TEST/ovpn-a.key" "$TMPDIR_TEST/ovpn-a.crt" "$TMPDIR_TEST/ovpn-b.key" "$TMPDIR_TEST/ovpn-b.crt" "$TMPDIR_TEST/ovpn-a.log" "$TMPDIR_TEST/ovpn-b.log" 2>/dev/null || true
}

# ── 5. n2n ────────────────────────────────────────────────────────────────────
start_n2n() {
    if ! command -v edge >/dev/null 2>&1 || ! command -v supernode >/dev/null 2>&1; then
        echo "[n2n] SKIP: edge or supernode not installed"
        N2N_AVAILABLE=false
        return 1
    fi
    echo "[n2n] creating namespaces and veth pair"
    make_pair "$NS_NA" "$NS_NB" "$VNA" "$VNB" "$VNA_IP" "$VNB_IP"

    echo "[n2n] launching supernode on Node A"
    ip netns exec "$NS_NA" supernode -f -M -p "$N2N_PORT" >"$TMPDIR_TEST/n2n_sn.log" 2>&1 &
    PID_N2N_SN=$!
    sleep 0.3

    echo "[n2n] launching edge daemons on Node A and Node B"
    ip netns exec "$NS_NA" edge -f -d n2n0 -a "${OVL_NA_IP}" -c yipbench -k benchpass -l "${VNA_IP}:${N2N_PORT}" -E -r >"$TMPDIR_TEST/n2n_ea.log" 2>&1 &
    PID_N2N_EA=$!
    ip netns exec "$NS_NB" edge -f -d n2n0 -a "${OVL_NB_IP}" -c yipbench -k benchpass -l "${VNA_IP}:${N2N_PORT}" -E -r >"$TMPDIR_TEST/n2n_eb.log" 2>&1 &
    PID_N2N_EB=$!

    local i
    for i in $(seq 1 40); do
        if ip netns exec "$NS_NB" ping -c 1 -W 1 "$OVL_NA_IP" >/dev/null 2>&1; then
            break
        fi
        sleep 0.25
    done
    if [ "$i" -ge 40 ]; then
        echo "[n2n] SKIP: baseline ping failed"
        tail -10 "$TMPDIR_TEST/n2n_ea.log" "$TMPDIR_TEST/n2n_eb.log" 2>/dev/null || true
        stop_n2n
        N2N_AVAILABLE=false
        return 1
    fi

    ip netns exec "$NS_NA" ip -6 addr add "${OVL_NA_IP6}/64" dev n2n0 nodad 2>/dev/null || true
    ip netns exec "$NS_NB" ip -6 addr add "${OVL_NB_IP6}/64" dev n2n0 nodad 2>/dev/null || true
    ip netns exec "$NS_NA" ip link set dev n2n0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_NB" ip link set dev n2n0 txqueuelen 10000 2>/dev/null || true

    sleep 0.5
    ip netns exec "$NS_NB" ping -6 -c 3 -W 5 "$OVL_NA_IP6" >/dev/null 2>&1 || true

    echo "[n2n] network up"
    N2N_AVAILABLE=true
    return 0
}

stop_n2n() {
    LAST_CHECK_PIDS=("$PID_N2N_EA:n2n_ea" "$PID_N2N_EB:n2n_eb" "$PID_N2N_SN:n2n_sn")
    reap_pids "$PID_N2N_EA" "$PID_N2N_EB" "$PID_N2N_SN"
    PID_N2N_EA=""; PID_N2N_EB=""; PID_N2N_SN=""
    clean_netns "$NS_NA" "$NS_NB"
    rm -f "$TMPDIR_TEST/n2n_sn.log" "$TMPDIR_TEST/n2n_ea.log" "$TMPDIR_TEST/n2n_eb.log" 2>/dev/null || true
}

# ── 6. AmneziaWG ──────────────────────────────────────────────────────────────
start_awg() {
    if ! command -v awg >/dev/null 2>&1; then
        echo "[awg] SKIP: 'awg' command not found"
        AWG_AVAILABLE=false
        return 1
    fi
    local use_go=false
    if ! modprobe amneziawg 2>/dev/null; then
        if command -v amneziawg-go >/dev/null 2>&1; then
            use_go=true
        else
            echo "[awg] SKIP: neither amneziawg kernel module nor amneziawg-go found"
            AWG_AVAILABLE=false
            return 1
        fi
    fi
    echo "[awg] generating keypairs"
    local privA pubA privB pubB
    privA="$(awg genkey 2>/dev/null || true)"; pubA="$(echo "$privA" | awg pubkey 2>/dev/null || true)"
    privB="$(awg genkey 2>/dev/null || true)"; pubB="$(echo "$privB" | awg pubkey 2>/dev/null || true)"
    if [ -z "$privA" ] || [ -z "$privB" ]; then
        echo "[awg] SKIP: key generation failed"
        AWG_AVAILABLE=false
        return 1
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
            echo "[awg] SKIP: amneziawg link add failed"
            stop_awg
            AWG_AVAILABLE=false
            return 1
        fi
    fi

    local awg_up=false
    for _ in $(seq 1 20); do
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
        stop_awg
        AWG_AVAILABLE=false
        return 1
    fi

    local keyA="$TMPDIR_TEST/awg_a"
    local keyB="$TMPDIR_TEST/awg_b"
    printf '%s' "$privA" > "$keyA"
    printf '%s' "$privB" > "$keyB"
    chmod 600 "$keyA" "$keyB"

    local awg_err=""
    if ! awg_err="$(ip netns exec "$NS_AA" awg set awg0 private-key "$keyA" listen-port "$APORT_A" \
            jc 4 jmin 40 jmax 70 s1 15 s2 20 h1 1000000001 h2 1000000002 h3 1000000003 h4 1000000004 \
            peer "$pubB" endpoint "${VAB_IP}:${APORT_B}" allowed-ips "${TUN_AB_IP}/32,fd00:19::/64" 2>&1)" || \
       ! awg_err="$(ip netns exec "$NS_AB" awg set awg0 private-key "$keyB" listen-port "$APORT_B" \
            jc 4 jmin 40 jmax 70 s1 15 s2 20 h1 1000000001 h2 1000000002 h3 1000000003 h4 1000000004 \
            peer "$pubA" endpoint "${VAA_IP}:${APORT_A}" allowed-ips "${TUN_AA_IP}/32,fd00:19::/64" 2>&1)"; then
        echo "[awg] SKIP: awg set configuration failed: $awg_err"
        stop_awg
        AWG_AVAILABLE=false
        return 1
    fi

    if ! ip netns exec "$NS_AA" ip addr add "${TUN_AA_IP}/24" dev awg0 2>/dev/null || \
       ! ip netns exec "$NS_AB" ip addr add "${TUN_AB_IP}/24" dev awg0 2>/dev/null || \
       ! ip netns exec "$NS_AA" ip -6 addr add "${TUN_AA_IP6}/64" dev awg0 nodad 2>/dev/null || \
       ! ip netns exec "$NS_AB" ip -6 addr add "${TUN_AB_IP6}/64" dev awg0 nodad 2>/dev/null; then
        echo "[awg] SKIP: interface setup failed"
        stop_awg
        AWG_AVAILABLE=false
        return 1
    fi

    ip netns exec "$NS_AA" ip link set dev awg0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_AB" ip link set dev awg0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_AA" ip link set dev awg0 mtu 1420 2>/dev/null || true
    ip netns exec "$NS_AB" ip link set dev awg0 mtu 1420 2>/dev/null || true

    if ! ip netns exec "$NS_AA" ip link set awg0 up 2>/dev/null || \
       ! ip netns exec "$NS_AB" ip link set awg0 up 2>/dev/null; then
        echo "[awg] SKIP: interface set up failed"
        stop_awg
        AWG_AVAILABLE=false
        return 1
    fi

    sleep 0.5
    if ! ip netns exec "$NS_AB" ping -c 3 -W 5 "$TUN_AA_IP" >/dev/null 2>&1; then
        echo "[awg] SKIP: baseline IPv4 ping failed"
        stop_awg
        AWG_AVAILABLE=false
        return 1
    fi
    if ! ip netns exec "$NS_AB" ping -6 -c 3 -W 5 "$TUN_AA_IP6" >/dev/null 2>&1; then
        echo "[awg] SKIP: baseline IPv6 ping failed"
        stop_awg
        AWG_AVAILABLE=false
        return 1
    fi
    echo "[awg] tunnel up"
    AWG_AVAILABLE=true
    return 0
}

stop_awg() {
    LAST_CHECK_PIDS=("$PID_AA:awgA" "$PID_AB:awgB")
    reap_pids "$PID_AA" "$PID_AB"
    PID_AA=""; PID_AB=""
    ip netns exec "$NS_AA" ip link del awg0 2>/dev/null || true
    ip netns exec "$NS_AB" ip link del awg0 2>/dev/null || true
    rm -rf "/etc/netns/$NS_AA" "/etc/netns/$NS_AB" /etc/amneziawg-run 2>/dev/null || true
    if [ -L /run/amneziawg ]; then rm -f /run/amneziawg 2>/dev/null || true; fi
    if [ -L /var/run/amneziawg ]; then rm -f /var/run/amneziawg 2>/dev/null || true; fi
    rm -f "$TMPDIR_TEST/awg_a" "$TMPDIR_TEST/awg_b" 2>/dev/null || true
    clean_netns "$NS_AA" "$NS_AB"
}

# ── 7. ZeroTier ───────────────────────────────────────────────────────────────
start_zerotier() {
    if ! command -v zerotier-one >/dev/null 2>&1; then
        echo "[zerotier] SKIP: 'zerotier-one' not found"
        ZT_AVAILABLE=false
        return 1
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
        echo "[zerotier] SKIP: daemon failed to initialize"
        stop_zerotier
        ZT_AVAILABLE=false
        return 1
    fi
    for i in $(seq 1 40); do
        node_a="$(ip netns exec "$NS_ZA" zerotier-cli -D"$zt_dir_a" info 2>/dev/null | awk '$1=="200" && $3!="OFFLINE" && length($3)>=10 {print $3}' || true)"
        [ -n "$node_a" ] && break
        sleep 0.25
    done
    for i in $(seq 1 40); do
        node_b="$(ip netns exec "$NS_ZB" zerotier-cli -D"$zt_dir_b" info 2>/dev/null | awk '$1=="200" && $3!="OFFLINE" && length($3)>=10 {print $3}' || true)"
        [ -n "$node_b" ] && break
        sleep 0.25
    done
    if [ -z "$node_a" ] || [ -z "$node_b" ]; then
        echo "[zerotier] SKIP: failed to get node identity"
        stop_zerotier
        ZT_AVAILABLE=false
        return 1
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
        echo "[zerotier] SKIP: overlay assignment timed out"
        stop_zerotier
        ZT_AVAILABLE=false
        return 1
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
        echo "[zerotier] SKIP: overlay ping failed"
        stop_zerotier
        ZT_AVAILABLE=false
        return 1
    fi
    echo "[zerotier] network up"
    ZT_AVAILABLE=true
    return 0
}

stop_zerotier() {
    LAST_CHECK_PIDS=("$PID_ZT_A:ztA" "$PID_ZT_B:ztB")
    reap_pids "$PID_ZT_A" "$PID_ZT_B"
    PID_ZT_A=""; PID_ZT_B=""
    clean_netns "$NS_ZA" "$NS_ZB"
    rm -rf "$TMPDIR_TEST/zt_a" "$TMPDIR_TEST/zt_b" 2>/dev/null || true
}

# ── 8. Tailscale ──────────────────────────────────────────────────────────────
start_tailscale() {
    if ! command -v tailscaled >/dev/null 2>&1 || ! command -v headscale >/dev/null 2>&1; then
        echo "[tailscale] SKIP: 'tailscaled' or 'headscale' not found"
        TS_AVAILABLE=false
        return 1
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
    for _ in $(seq 1 30); do
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
        stop_tailscale
        TS_AVAILABLE=false
        return 1
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
    for _ in $(seq 1 40); do
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
        echo "[tailscale] SKIP: tailscale tunnel activation timed out"
        stop_tailscale
        TS_AVAILABLE=false
        return 1
    fi
    TUN_TA_IP="$ts_dyn_a"
    TUN_TB_IP="$ts_dyn_b"
    TUN_TA_IP6="$ts_dyn6_a"
    TUN_TB_IP6="$ts_dyn6_b"
    ip netns exec "$NS_TA" ip link set dev tailscale0 txqueuelen 10000 2>/dev/null || true
    ip netns exec "$NS_TB" ip link set dev tailscale0 txqueuelen 10000 2>/dev/null || true
    local ts_up=false
    for _ in $(seq 1 20); do
        if ip netns exec "$NS_TB" ping -c 1 -W 1 "$TUN_TA_IP" >/dev/null 2>&1 && \
           ip netns exec "$NS_TB" ping -6 -c 1 -W 1 "$TUN_TA_IP6" >/dev/null 2>&1; then
            ts_up=true
            break
        fi
        sleep 0.5
    done
    if [ "$ts_up" = false ]; then
        echo "[tailscale] SKIP: baseline ping failed"
        stop_tailscale
        TS_AVAILABLE=false
        return 1
    fi
    echo "[tailscale] tunnel up"
    TS_AVAILABLE=true
    return 0
}

stop_tailscale() {
    LAST_CHECK_PIDS=("$PID_TS_DA:tailscaledA" "$PID_TS_DB:tailscaledB" "$PID_TS_HS:headscale")
    reap_pids "$PID_TS_DA" "$PID_TS_DB" "$PID_TS_HS"
    PID_TS_DA=""; PID_TS_DB=""; PID_TS_HS=""
    clean_netns "$NS_TA" "$NS_TB"
    rm -rf "$TMPDIR_TEST/headscale" "$TMPDIR_TEST/ts_a" "$TMPDIR_TEST/ts_b" 2>/dev/null || true
}

# ── 9. NetBird ────────────────────────────────────────────────────────────────
start_netbird() {
    if ! command -v netbird >/dev/null 2>&1; then
        echo "[netbird] SKIP: 'netbird' not found"
        NB_AVAILABLE=false
        return 1
    fi
    ip netns pids "$NS_BA" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns pids "$NS_BB" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    local mgmt_url="${NETBIRD_MGMT_URL:-}"
    local setup_key="${NETBIRD_SETUP_KEY:-}"

    echo "[netbird] creating namespaces and veth pair"
    make_pair "$NS_BA" "$NS_BB" "$VBA" "$VBB" "$VBA_IP" "$VBB_IP"

    if [ -z "$mgmt_url" ] || [ -z "$setup_key" ]; then
        if ! command -v netbird-mgmt >/dev/null 2>&1 || ! command -v netbird-signal >/dev/null 2>&1; then
            echo "[netbird] SKIP: 'netbird-mgmt' or 'netbird-signal' not found"
            NB_AVAILABLE=false
            return 1
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
            for _ in $(seq 1 30); do
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
        for _ in $(seq 1 40); do
            if [ -f "$nb_dir/data/store.db" ]; then
                break
            fi
            sleep 0.2
        done
        if [ ! -f "$nb_dir/data/store.db" ]; then
            echo "[netbird] SKIP: store.db initialization timed out"
            stop_netbird
            NB_AVAILABLE=false
            return 1
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
        for _ in $(seq 1 60); do
            if ip netns exec "$NS_BA" ss -tlpn 2>/dev/null | grep -q ":8080"; then
                mgmt_ok=true
                break
            fi
            sleep 0.25
        done
        if [ "$mgmt_ok" = false ]; then
            echo "[netbird] SKIP: netbird-mgmt port 8080 not listening"
            tail -15 "$TMPDIR_TEST/nb-mgmt.log" 2>/dev/null || true
            stop_netbird
            NB_AVAILABLE=false
            return 1
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
    for _ in $(seq 1 40); do
        if [ -S "$nb_dir_a/daemon.sock" ] && [ -S "$nb_dir_b/daemon.sock" ]; then
            break
        fi
        sleep 0.25
    done
    for _ in $(seq 1 10); do
        timeout 6 ip netns exec "$NS_BA" netbird up --daemon-addr "unix://$nb_dir_a/daemon.sock" --management-url "$mgmt_url" --setup-key "$setup_key" --disable-dns --disable-firewall >/dev/null 2>&1 && break || sleep 0.5
    done
    for _ in $(seq 1 10); do
        timeout 6 ip netns exec "$NS_BB" netbird up --daemon-addr "unix://$nb_dir_b/daemon.sock" --management-url "$mgmt_url" --setup-key "$setup_key" --disable-dns --disable-firewall >/dev/null 2>&1 && break || sleep 0.5
    done
    local found=false
    for _ in $(seq 1 40); do
        if ip netns exec "$NS_BA" ip link show wt0 >/dev/null 2>&1 && \
           ip netns exec "$NS_BB" ip link show wt0 >/dev/null 2>&1; then
            found=true; break
        fi
        sleep 0.5
    done
    if [ "$found" = false ]; then
        echo "[netbird] SKIP: wt0 interface creation timed out"
        tail -15 "$TMPDIR_TEST/nb-mgmt.log" "$TMPDIR_TEST/nb-a.log" "$TMPDIR_TEST/nb-b.log" 2>/dev/null || true
        stop_netbird
        NB_AVAILABLE=false
        return 1
    fi
    local nb_dyn_a="" nb_dyn_b="" nb_dyn6_a="" nb_dyn6_b=""
    for _ in $(seq 1 40); do
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
    for _ in $(seq 1 30); do
        if ip netns exec "$NS_BB" ping -c 1 -W 1 "$TUN_BA_IP" >/dev/null 2>&1; then
            nb_up=true
            break
        fi
        sleep 0.5
    done
    if [ "$nb_up" = false ]; then
        echo "[netbird] SKIP: baseline ping failed"
        stop_netbird
        NB_AVAILABLE=false
        return 1
    fi
    if [ -n "$TUN_BA_IP6" ]; then
        for _ in $(seq 1 30); do
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
    reap_pids "$PID_NB_SA" "$PID_NB_SB" "$PID_NB_MGMT" "$PID_NB_SIG"
    PID_NB_SA=""; PID_NB_SB=""; PID_NB_MGMT=""; PID_NB_SIG=""
    clean_netns "$NS_BA" "$NS_BB"
    rm -rf "$TMPDIR_TEST/nb_coord" "$TMPDIR_TEST/nb_a" "$TMPDIR_TEST/nb_b" 2>/dev/null || true
}

# ── 10. Nebula ────────────────────────────────────────────────────────────────
start_nebula() {
    if ! command -v nebula >/dev/null 2>&1 || ! command -v nebula-cert >/dev/null 2>&1; then
        echo "[nebula] SKIP: nebula or nebula-cert binary not found"
        NEB_AVAILABLE=false
        return 1
    fi
    echo "[nebula] setting up Nebula overlay tunnel"
    make_pair "$NS_EA" "$NS_EB" "$VEA" "$VEB" "$VEA_IP" "$VEB_IP"

    local neb_dir="$TMPDIR_TEST/nebula"
    mkdir -p "$neb_dir"

    nebula-cert ca -name "yip-bench-ca" -out-crt "$neb_dir/ca.crt" -out-key "$neb_dir/ca.key" -duration "24h" >/dev/null 2>&1
    nebula-cert sign -name "node-a" -networks "${TUN_EA_IP}/24,${TUN_EA_IP6}/64" -ca-crt "$neb_dir/ca.crt" -ca-key "$neb_dir/ca.key" -out-crt "$neb_dir/a.crt" -out-key "$neb_dir/a.key" >/dev/null 2>&1
    nebula-cert sign -name "node-b" -networks "${TUN_EB_IP}/24,${TUN_EB_IP6}/64" -ca-crt "$neb_dir/ca.crt" -ca-key "$neb_dir/ca.key" -out-crt "$neb_dir/b.crt" -out-key "$neb_dir/b.key" >/dev/null 2>&1

    cat > "$neb_dir/a.yaml" <<EOF
pki:
  ca: $neb_dir/ca.crt
  cert: $neb_dir/a.crt
  key: $neb_dir/a.key
static_host_map: {}
lighthouse:
  am_lighthouse: true
  interval: 10
listen:
  host: 0.0.0.0
  port: ${NEB_PORT}
punchy:
  punch: true
tun:
  disabled: false
  dev: neb0
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 10000
  mtu: 1300
firewall:
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
EOF

    cat > "$neb_dir/b.yaml" <<EOF
pki:
  ca: $neb_dir/ca.crt
  cert: $neb_dir/b.crt
  key: $neb_dir/b.key
static_host_map:
  "${TUN_EA_IP}": ["${VEA_IP}:${NEB_PORT}"]
  "${TUN_EA_IP6}": ["${VEA_IP}:${NEB_PORT}"]
lighthouse:
  am_lighthouse: false
  interval: 10
  hosts:
    - "${TUN_EA_IP}"
    - "${TUN_EA_IP6}"
listen:
  host: 0.0.0.0
  port: ${NEB_PORT}
punchy:
  punch: true
tun:
  disabled: false
  dev: neb0
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 10000
  mtu: 1300
firewall:
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
EOF

    ip netns exec "$NS_EA" nebula -config "$neb_dir/a.yaml" > "$TMPDIR_TEST/nebula_a.log" 2>&1 &
    PID_NEB_A=$!
    ip netns exec "$NS_EB" nebula -config "$neb_dir/b.yaml" > "$TMPDIR_TEST/nebula_b.log" 2>&1 &
    PID_NEB_B=$!

    # Wait for handshake
    local elapsed=0 interval=0.5 max_wait=15
    while true; do
        if ip netns exec "$NS_EB" ping -c 1 -W 1 "$TUN_EA_IP" >/dev/null 2>&1 && \
           ip netns exec "$NS_EB" ping -6 -c 1 -W 1 "$TUN_EA_IP6" >/dev/null 2>&1; then
            break
        fi
        if ! kill -0 "$PID_NEB_A" 2>/dev/null || ! kill -0 "$PID_NEB_B" 2>/dev/null; then
            echo "[error] nebula daemon died during startup" >&2
            cat "$TMPDIR_TEST/nebula_a.log" "$TMPDIR_TEST/nebula_b.log" >&2 || true
            stop_nebula
            NEB_AVAILABLE=false
            return 1
        fi
        elapsed=$(awk "BEGIN {print $elapsed + $interval}")
        if awk "BEGIN {exit ($elapsed >= $max_wait) ? 0 : 1}"; then
            echo "[error] timed out waiting for nebula tunnel ping" >&2
            cat "$TMPDIR_TEST/nebula_a.log" "$TMPDIR_TEST/nebula_b.log" >&2 || true
            stop_nebula
            NEB_AVAILABLE=false
            return 1
        fi
        sleep "$interval"
    done
    NEB_AVAILABLE=true
    return 0
}

stop_nebula() {
    LAST_CHECK_PIDS=("$PID_NEB_A:nebA" "$PID_NEB_B:nebB")
    reap_pids "$PID_NEB_A" "$PID_NEB_B"
    PID_NEB_A=""; PID_NEB_B=""
    clean_netns "$NS_EA" "$NS_EB"
    rm -rf "$TMPDIR_TEST/nebula" "$TMPDIR_TEST/nebula_a.log" "$TMPDIR_TEST/nebula_b.log" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════════════
# Contender Query & Dispatch
# ══════════════════════════════════════════════════════════════════════════════

get_contender_info() {
    local name="$1"
    case "$name" in
        yip)
            CONTENDER_CANONICAL="yip"
            NS_A="$NS_YA"; NS_B="$NS_YB"; VETH_A="$VYA"; VETH_B="$VYB"
            VETH_A_IP="$VYA_IP"; VETH_B_IP="$VYB_IP"
            TUN_A_IP="$TUN_YA_IP"; TUN_B_IP="$TUN_YB_IP"
            TUN_A_IP6="$TUN_YA_IP6"; TUN_B_IP6="$TUN_YB_IP6"
            ;;
        wireguard|wg)
            CONTENDER_CANONICAL="wireguard"
            NS_A="$NS_WA"; NS_B="$NS_WB"; VETH_A="$VWA"; VETH_B="$VWB"
            VETH_A_IP="$VWA_IP"; VETH_B_IP="$VWB_IP"
            TUN_A_IP="$TUN_WA_IP"; TUN_B_IP="$TUN_WB_IP"
            TUN_A_IP6="$TUN_WA_IP6"; TUN_B_IP6="$TUN_WB_IP6"
            ;;
        wireguard-go|wggo)
            CONTENDER_CANONICAL="wireguard-go"
            NS_A="$NS_GGA"; NS_B="$NS_GGB"; VETH_A="$VGGA"; VETH_B="$VGGB"
            VETH_A_IP="$VGGA_IP"; VETH_B_IP="$VGGB_IP"
            TUN_A_IP="$TUN_GGA_IP"; TUN_B_IP="$TUN_GGB_IP"
            TUN_A_IP6="$TUN_GGA_IP6"; TUN_B_IP6="$TUN_GGB_IP6"
            ;;
        amneziawg|awg)
            CONTENDER_CANONICAL="amneziawg"
            NS_A="$NS_AA"; NS_B="$NS_AB"; VETH_A="$VAA"; VETH_B="$VAB"
            VETH_A_IP="$VAA_IP"; VETH_B_IP="$VAB_IP"
            TUN_A_IP="$TUN_AA_IP"; TUN_B_IP="$TUN_AB_IP"
            TUN_A_IP6="$TUN_AA_IP6"; TUN_B_IP6="$TUN_AB_IP6"
            ;;
        openvpn|ovpn)
            CONTENDER_CANONICAL="openvpn"
            NS_A="$NS_OA"; NS_B="$NS_OB"; VETH_A="$VOA"; VETH_B="$VOB"
            VETH_A_IP="$VOA_IP"; VETH_B_IP="$VOB_IP"
            TUN_A_IP="$TUN_OA_IP"; TUN_B_IP="$TUN_OB_IP"
            TUN_A_IP6="$TUN_OA_IP6"; TUN_B_IP6="$TUN_OB_IP6"
            ;;
        n2n)
            CONTENDER_CANONICAL="n2n"
            NS_A="$NS_NA"; NS_B="$NS_NB"; VETH_A="$VNA"; VETH_B="$VNB"
            VETH_A_IP="$VNA_IP"; VETH_B_IP="$VNB_IP"
            TUN_A_IP="$OVL_NA_IP"; TUN_B_IP="$OVL_NB_IP"
            TUN_A_IP6="$OVL_NA_IP6"; TUN_B_IP6="$OVL_NB_IP6"
            ;;
        zerotier|zt)
            CONTENDER_CANONICAL="zerotier"
            NS_A="$NS_ZA"; NS_B="$NS_ZB"; VETH_A="$VZA"; VETH_B="$VZB"
            VETH_A_IP="$VZA_IP"; VETH_B_IP="$VZB_IP"
            TUN_A_IP="$TUN_ZA_IP"; TUN_B_IP="$TUN_ZB_IP"
            TUN_A_IP6="$TUN_ZA_IP6"; TUN_B_IP6="$TUN_ZB_IP6"
            ;;
        tailscale|ts)
            CONTENDER_CANONICAL="tailscale"
            NS_A="$NS_TA"; NS_B="$NS_TB"; VETH_A="$VTA"; VETH_B="$VTB"
            VETH_A_IP="$VTA_IP"; VETH_B_IP="$VTB_IP"
            TUN_A_IP="$TUN_TA_IP"; TUN_B_IP="$TUN_TB_IP"
            TUN_A_IP6="$TUN_TA_IP6"; TUN_B_IP6="$TUN_TB_IP6"
            ;;
        netbird|nb)
            CONTENDER_CANONICAL="netbird"
            NS_A="$NS_BA"; NS_B="$NS_BB"; VETH_A="$VBA"; VETH_B="$VBB"
            VETH_A_IP="$VBA_IP"; VETH_B_IP="$VBB_IP"
            TUN_A_IP="$TUN_BA_IP"; TUN_B_IP="$TUN_BB_IP"
            TUN_A_IP6="$TUN_BA_IP6"; TUN_B_IP6="$TUN_BB_IP6"
            ;;
        nebula|neb)
            CONTENDER_CANONICAL="nebula"
            NS_A="$NS_EA"; NS_B="$NS_EB"; VETH_A="$VEA"; VETH_B="$VEB"
            VETH_A_IP="$VEA_IP"; VETH_B_IP="$VEB_IP"
            TUN_A_IP="$TUN_EA_IP"; TUN_B_IP="$TUN_EB_IP"
            TUN_A_IP6="$TUN_EA_IP6"; TUN_B_IP6="$TUN_EB_IP6"
            ;;
        *)
            return 1
            ;;
    esac
    return 0
}

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
        nebula|neb) start_nebula || rc=$? ;;
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
        nebula|neb) stop_nebula ;;
        *) echo "[error] unknown contender: $name" >&2; return 1 ;;
    esac
}

start_all_contenders() {
    start_contender "yip" || true
    start_contender "wireguard" || true
    start_contender "wireguard-go" || true
    start_contender "amneziawg" || true
    start_contender "openvpn" || true
    start_contender "n2n" || true
    start_contender "zerotier" || true
    start_contender "tailscale" || true
    start_contender "netbird" || true
    start_contender "nebula" || true
}

stop_all_contenders() {
    for c in yip wireguard wireguard-go amneziawg openvpn n2n zerotier tailscale netbird nebula; do
        stop_contender "$c"
    done
}
