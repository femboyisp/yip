#!/usr/bin/env bash
# run-scp-compare.sh — Real-world SCP file transfer benchmark under netem loss.
#
# Measures real OpenSSH scp throughput and goodput under packet loss across
# VPN contenders (yip, kernel WireGuard, OpenVPN).
#
# Sweeps configurable payload sizes (FILE_SIZES_MB, default: 100) and loss rates
# (LOSS_RATES, default: 0 5 10). Contenders are isolated with start/stop lifecycles.
#
# Emits a formatted Markdown results table and optional JSON telemetry (OUTPUT_JSON).
#
# Usage: run-scp-compare.sh [<path-to-yipd>]
set -euo pipefail

# ── availability checks ───────────────────────────────────────────────────────
if ! command -v scp >/dev/null 2>&1; then
    echo "[SKIP] scp not found — skipping scp throughput comparison"
    exit 0
fi
if [ ! -x /usr/sbin/sshd ]; then
    echo "[SKIP] /usr/sbin/sshd not found — skipping scp throughput comparison"
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

# ── configuration ─────────────────────────────────────────────────────────────
CONTENDERS="${CONTENDERS:-yip wg ovpn}"
LOSS_RATES="${LOSS_RATES:-0 5 10}"
FILE_SIZES_MB="${FILE_SIZES_MB:-100}"
OUTPUT_JSON="${OUTPUT_JSON:-}"
SSH_PORT="2222"

# ── tmpdir ────────────────────────────────────────────────────────────────────
TMPDIR_TEST="$(mktemp -d /dev/shm/yip-scp-compare.XXXXXX 2>/dev/null || mktemp -d /tmp/yip-scp-compare.XXXXXX)"
chmod 777 "$TMPDIR_TEST"

# ── IP and namespace configuration ───────────────────────────────────────────
# yip
NS_YA="yipA"; NS_YB="yipB"
VETH_YA="vethYA"; VETH_YB="vethYB"
VETH_YA_IP="10.0.0.1"; VETH_YB_IP="10.0.0.2"
TUN_YA_IP="10.9.0.1"; TUN_YB_IP="10.9.0.2"
YIP_PORT_A="443"; YIP_PORT_B="443"
YIP_TUN_DEV="yip0"
YIP_MTU="${YIP_MTU:-1184}"
YIP_SHARDS="${YIP_SHARDS:-1}"
PID_YA=""; PID_YB=""

# WireGuard
NS_WGA="wgA"; NS_WGB="wgB"
VETH_WA="vethWA"; VETH_WB="vethWB"
VETH_WA_IP="10.1.0.1"; VETH_WB_IP="10.1.0.2"
WG_A_TUN_IP="10.99.0.1"; WG_B_TUN_IP="10.99.0.2"
WG_PORT_A="51830"; WG_PORT_B="51831"

# OpenVPN
NS_OA="ovpnA"; NS_OB="ovpnB"
VETH_OA="vethOA"; VETH_OB="vethOB"
VETH_OA_IP="10.2.0.1"; VETH_OB_IP="10.2.0.2"
TUN_OA_IP="10.8.0.1"; TUN_OB_IP="10.8.0.2"
PID_OA=""; PID_OB=""

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo "[cleanup] cleaning up active processes and namespaces"
    # Kill any active sshd
    for _pidfile in "$TMPDIR_TEST"/sshd-*.pid; do
        [ -f "$_pidfile" ] || continue
        _pid="$(cat "$_pidfile" 2>/dev/null || true)"
        [ -n "$_pid" ] && kill -9 "$_pid" 2>/dev/null || true
    done
    # Kill any active daemons
    [ -n "$PID_YA" ] && kill -9 "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill -9 "$PID_YB" 2>/dev/null || true
    [ -n "$PID_OA" ] && kill -9 "$PID_OA" 2>/dev/null || true
    [ -n "$PID_OB" ] && kill -9 "$PID_OB" 2>/dev/null || true
    # Remove interfaces and namespaces
    for ns in "$NS_YA" "$NS_YB" "$NS_WGA" "$NS_WGB" "$NS_OA" "$NS_OB"; do
        ip netns exec "$ns" ip link del wg0 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── SSH key generation ────────────────────────────────────────────────────────
echo "[ssh] generating host and client keys"
ssh-keygen -t ed25519 -f "$TMPDIR_TEST/host" -N '' -q
ssh-keygen -t ed25519 -f "$TMPDIR_TEST/client" -N '' -q
cat "$TMPDIR_TEST/client.pub" > "$TMPDIR_TEST/authkeys"
chmod 600 "$TMPDIR_TEST/authkeys" "$TMPDIR_TEST/host"

# ── Helper: sshd lifecycle ────────────────────────────────────────────────────
start_sshd() {
    local ns="$1"
    local pidfile="$2"
    local logfile="$3"
    rm -f "$pidfile"
    mkdir -p /run/sshd && chmod 0755 /run/sshd
    local rc=0
    ip netns exec "$ns" /usr/sbin/sshd -p "$SSH_PORT" -h "$TMPDIR_TEST/host" \
        -o "PidFile=$pidfile" \
        -o "AuthorizedKeysFile=$TMPDIR_TEST/authkeys" \
        -o "UsePAM=no" \
        -o "PasswordAuthentication=no" \
        -o "StrictModes=no" \
        -o "PermitRootLogin=yes" \
        -E "$logfile" || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "[error] sshd failed to start in netns $ns (exit $rc)" >&2
        [ -s "$logfile" ] && cat "$logfile" >&2
        return "$rc"
    fi
    local wait=0
    while [ ! -f "$pidfile" ] && [ "$wait" -lt 50 ]; do
        sleep 0.1
        wait=$((wait + 1))
    done
}

stop_sshd() {
    local pidfile="$1"
    if [ -f "$pidfile" ]; then
        local pid
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            for _ in $(seq 1 10); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.05
            done
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$pidfile"
    fi
}

make_pair() {
    local ns1="$1" ns2="$2" v1="$3" v2="$4" ip1="$5" ip2="$6"
    ip netns add "$ns1"
    ip netns add "$ns2"
    ip link add "$v1" type veth peer name "$v2"
    ip link set "$v1" netns "$ns1"
    ip link set "$v2" netns "$ns2"
    ip netns exec "$ns1" ip addr add "${ip1}/24" dev "$v1"
    ip netns exec "$ns1" ip link set "$v1" up
    ip netns exec "$ns1" ip link set lo up
    ip netns exec "$ns2" ip addr add "${ip2}/24" dev "$v2"
    ip netns exec "$ns2" ip link set "$v2" up
    ip netns exec "$ns2" ip link set lo up
}

# ── Contender: Yip ────────────────────────────────────────────────────────────
start_yip() {
    echo "[yip] setting up yip tunnel"
    local GENKEY_A GENKEY_B PRIV_A PUB_A PRIV_B PUB_B CFG_A CFG_B LOG_A LOG_B
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
listen=${VETH_YA_IP}:${YIP_PORT_A}
peer_endpoint=${VETH_YB_IP}:${YIP_PORT_B}
device=${YIP_TUN_DEV}
initiate=false
shards=${YIP_SHARDS}
EOF

    cat > "$CFG_B" <<EOF
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_YB_IP}:${YIP_PORT_B}
peer_endpoint=${VETH_YA_IP}:${YIP_PORT_A}
device=${YIP_TUN_DEV}
initiate=true
shards=${YIP_SHARDS}
EOF

    make_pair "$NS_YA" "$NS_YB" "$VETH_YA" "$VETH_YB" "$VETH_YA_IP" "$VETH_YB_IP"

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
    ip netns exec "$NS_YA" ip link set "$YIP_TUN_DEV" up
    ip netns exec "$NS_YB" ip link set "$YIP_TUN_DEV" up
    ip netns exec "$NS_YA" ip link set "$YIP_TUN_DEV" mtu "$YIP_MTU"
    ip netns exec "$NS_YB" ip link set "$YIP_TUN_DEV" mtu "$YIP_MTU"
    sleep 0.5
    ip netns exec "$NS_YB" ping -c 3 -W 5 "$TUN_YA_IP" >/dev/null 2>&1
}

stop_yip() {
    [ -n "$PID_YA" ] && kill "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill "$PID_YB" 2>/dev/null || true
    wait "$PID_YA" 2>/dev/null || true
    wait "$PID_YB" 2>/dev/null || true
    [ -n "$PID_YA" ] && kill -9 "$PID_YA" 2>/dev/null || true
    [ -n "$PID_YB" ] && kill -9 "$PID_YB" 2>/dev/null || true
    wait "$PID_YA" 2>/dev/null || true
    wait "$PID_YB" 2>/dev/null || true
    PID_YA=""; PID_YB=""
    ip netns del "$NS_YA" 2>/dev/null || true
    ip netns del "$NS_YB" 2>/dev/null || true
}

# ── Contender: WireGuard ──────────────────────────────────────────────────────
start_wg() {
    if ! command -v wg >/dev/null 2>&1 || ! modprobe wireguard 2>/dev/null; then
        echo "[wg] SKIP: wg or wireguard kernel module not available"
        return 1
    fi
    echo "[wg] setting up WireGuard tunnel"
    make_pair "$NS_WGA" "$NS_WGB" "$VETH_WA" "$VETH_WB" "$VETH_WA_IP" "$VETH_WB_IP"
    local WG_PRIV_A WG_PUB_A WG_PRIV_B WG_PUB_B
    WG_PRIV_A="$(wg genkey)"; WG_PUB_A="$(echo "$WG_PRIV_A" | wg pubkey)"
    WG_PRIV_B="$(wg genkey)"; WG_PUB_B="$(echo "$WG_PRIV_B" | wg pubkey)"
    printf '%s' "$WG_PRIV_A" > "$TMPDIR_TEST/wg_priv_a"
    printf '%s' "$WG_PRIV_B" > "$TMPDIR_TEST/wg_priv_b"

    ip netns exec "$NS_WGA" ip link add wg0 type wireguard
    ip netns exec "$NS_WGB" ip link add wg0 type wireguard
    ip netns exec "$NS_WGA" wg set wg0 private-key "$TMPDIR_TEST/wg_priv_a" listen-port "$WG_PORT_A" \
        peer "$WG_PUB_B" allowed-ips "10.99.0.0/24" endpoint "${VETH_WB_IP}:${WG_PORT_B}"
    ip netns exec "$NS_WGB" wg set wg0 private-key "$TMPDIR_TEST/wg_priv_b" listen-port "$WG_PORT_B" \
        peer "$WG_PUB_A" allowed-ips "10.99.0.0/24" endpoint "${VETH_WA_IP}:${WG_PORT_A}"

    ip netns exec "$NS_WGA" ip addr add "${WG_A_TUN_IP}/24" dev wg0
    ip netns exec "$NS_WGA" ip link set wg0 up
    ip netns exec "$NS_WGB" ip addr add "${WG_B_TUN_IP}/24" dev wg0
    ip netns exec "$NS_WGB" ip link set wg0 up
    sleep 0.5
    ip netns exec "$NS_WGB" ping -c 3 -W 5 "$WG_A_TUN_IP" >/dev/null 2>&1
}

stop_wg() {
    ip netns exec "$NS_WGA" ip link del wg0 2>/dev/null || true
    ip netns exec "$NS_WGB" ip link del wg0 2>/dev/null || true
    ip netns del "$NS_WGA" 2>/dev/null || true
    ip netns del "$NS_WGB" 2>/dev/null || true
}

# ── Contender: OpenVPN ────────────────────────────────────────────────────────
start_ovpn() {
    if ! command -v openvpn >/dev/null 2>&1; then
        echo "[ovpn] SKIP: openvpn not found"
        return 1
    fi
    echo "[ovpn] setting up OpenVPN tunnel"
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

    make_pair "$NS_OA" "$NS_OB" "$VETH_OA" "$VETH_OB" "$VETH_OA_IP" "$VETH_OB_IP"
    ip netns exec "$NS_OA" openvpn \
        --dev tun0 --dev-type tun \
        --local "$VETH_OA_IP" --port 1194 --ifconfig "$TUN_OA_IP" "$TUN_OB_IP" \
        --tls-server --cert "$TMPDIR_TEST/ovpn-a.crt" --key "$TMPDIR_TEST/ovpn-a.key" \
        --peer-fingerprint "$FB" --data-ciphers AES-256-GCM \
        --proto udp --verb 1 --ping 10 --ping-restart 0 \
        >"$TMPDIR_TEST/ovpn-a.log" 2>&1 &
    PID_OA=$!

    ip netns exec "$NS_OB" openvpn \
        --dev tun0 --dev-type tun \
        --remote "$VETH_OA_IP" --rport 1194 --ifconfig "$TUN_OB_IP" "$TUN_OA_IP" \
        --tls-client --cert "$TMPDIR_TEST/ovpn-b.crt" --key "$TMPDIR_TEST/ovpn-b.key" \
        --peer-fingerprint "$FA" --data-ciphers AES-256-GCM \
        --proto udp --verb 1 --ping 10 --ping-restart 0 \
        >"$TMPDIR_TEST/ovpn-b.log" 2>&1 &
    PID_OB=$!

    local i
    for i in $(seq 1 40); do
        if ip netns exec "$NS_OB" ping -c 1 -W 1 "$TUN_OA_IP" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    echo "[ovpn] baseline ping failed" >&2
    return 1
}

stop_ovpn() {
    [ -n "$PID_OA" ] && kill "$PID_OA" 2>/dev/null || true
    [ -n "$PID_OB" ] && kill "$PID_OB" 2>/dev/null || true
    wait "$PID_OA" 2>/dev/null || true
    wait "$PID_OB" 2>/dev/null || true
    [ -n "$PID_OA" ] && kill -9 "$PID_OA" 2>/dev/null || true
    [ -n "$PID_OB" ] && kill -9 "$PID_OB" 2>/dev/null || true
    wait "$PID_OA" 2>/dev/null || true
    wait "$PID_OB" 2>/dev/null || true
    PID_OA=""; PID_OB=""
    ip netns del "$NS_OA" 2>/dev/null || true
    ip netns del "$NS_OB" 2>/dev/null || true
}

# ── Benchmark execution loop ──────────────────────────────────────────────────
declare -A RESULT_TIME
declare -A RESULT_MBPS
declare -A RESULT_INTEGRITY

echo "=========================================================="
echo "  SCP File Transfer Benchmark under netem packet loss"
echo "  Payloads: ${FILE_SIZES_MB} MB | Loss: ${LOSS_RATES}% | Delay: 5ms"
echo "  Contenders: ${CONTENDERS}"
echo "=========================================================="

start_contender() {
    local name="$1"
    case "$name" in
        yip) start_yip ;;
        wg|wireguard) start_wg ;;
        ovpn|openvpn) start_ovpn ;;
        *) echo "[skip] unknown contender: $name" >&2; return 1 ;;
    esac
}

stop_contender() {
    local name="$1"
    case "$name" in
        yip) stop_yip ;;
        wg|wireguard) stop_wg ;;
        ovpn|openvpn) stop_ovpn ;;
        *) return 0 ;;
    esac
}

for CONTENDER in $CONTENDERS; do
    echo ""
    echo "── Running contender: $CONTENDER ──"

    case "$CONTENDER" in
        yip)
            SRV_NS="$NS_YA"; CLI_NS="$NS_YB"
            SRV_IP="$TUN_YA_IP"; CLI_IP="$TUN_YB_IP"
            VETH_SRV="$VETH_YA"; VETH_CLI="$VETH_YB"
            ;;
        wg|wireguard)
            SRV_NS="$NS_WGA"; CLI_NS="$NS_WGB"
            SRV_IP="$WG_A_TUN_IP"; CLI_IP="$WG_B_TUN_IP"
            VETH_SRV="$VETH_WA"; VETH_CLI="$VETH_WB"
            ;;
        ovpn|openvpn)
            SRV_NS="$NS_OA"; CLI_NS="$NS_OB"
            SRV_IP="$TUN_OA_IP"; CLI_IP="$TUN_OB_IP"
            VETH_SRV="$VETH_OA"; VETH_CLI="$VETH_OB"
            ;;
        *)
            echo "[skip] unknown contender $CONTENDER"
            continue
            ;;
    esac

    if ! start_contender "$CONTENDER"; then
        echo "[$CONTENDER] startup skipped or failed"
        stop_contender "$CONTENDER" 2>/dev/null || true
        continue
    fi

    for SIZE_MB in $FILE_SIZES_MB; do
        PAYLOAD="$TMPDIR_TEST/payload_${SIZE_MB}MB"
        if [ ! -f "$PAYLOAD" ]; then
            echo "[payload] generating ${SIZE_MB} MB payload file"
            dd if=/dev/zero of="$PAYLOAD" bs=1M count="$SIZE_MB" status=none
        fi

        for LOSS in $LOSS_RATES; do
            echo "[$CONTENDER] applying loss=${LOSS}% delay=5ms (payload=${SIZE_MB}MB)"
            ip netns exec "$SRV_NS" tc qdisc replace dev "$VETH_SRV" root netem loss "${LOSS}%" delay 5ms
            ip netns exec "$CLI_NS" tc qdisc replace dev "$VETH_CLI" root netem loss "${LOSS}%" delay 5ms

            SSHD_PID="$TMPDIR_TEST/sshd-${CONTENDER}.pid"
            SSHD_LOG="$TMPDIR_TEST/sshd-${CONTENDER}.log"
            start_sshd "$SRV_NS" "$SSHD_PID" "$SSHD_LOG"

            # Timeout scaled: 60s base + 3s per MB
            TIMEOUT_SEC=$(( 60 + SIZE_MB * 3 ))
            REMOTE_DEST="/tmp/payload-${CONTENDER}-${SIZE_MB}.copy"
            ip netns exec "$SRV_NS" rm -f "$REMOTE_DEST"

            echo "[$CONTENDER] transferring ${SIZE_MB}MB via scp (timeout: ${TIMEOUT_SEC}s)..."
            t_start=$(date +%s.%N)
            transfer_ok=0
            if ip netns exec "$CLI_NS" timeout "$TIMEOUT_SEC" scp -q -P "$SSH_PORT" \
                -i "$TMPDIR_TEST/client" \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout=10 \
                "$PAYLOAD" "root@${SRV_IP}:${REMOTE_DEST}"; then
                transfer_ok=1
            fi
            t_end=$(date +%s.%N)

            stop_sshd "$SSHD_PID"

            KEY="${CONTENDER}:${SIZE_MB}:${LOSS}"
            if [ "$transfer_ok" -eq 1 ]; then
                elapsed=$(awk "BEGIN {print $t_end - $t_start}")
                mbps=$(awk "BEGIN { if ($elapsed > 0) printf \"%.2f\", $SIZE_MB / $elapsed; else print \"0.00\" }")
                RESULT_TIME["$KEY"]="$elapsed"
                RESULT_MBPS["$KEY"]="$mbps"

                integrity="OK"
                if [ "$LOSS" -eq 0 ]; then
                    if ! ip netns exec "$SRV_NS" cmp -s "$PAYLOAD" "$REMOTE_DEST"; then
                        integrity="FAIL"
                    fi
                fi
                RESULT_INTEGRITY["$KEY"]="$integrity"
                echo "[$CONTENDER] size=${SIZE_MB}MB loss=${LOSS}%: time=${elapsed}s throughput=${mbps} MB/s integrity=${integrity}"
            else
                RESULT_TIME["$KEY"]="TIMEOUT"
                RESULT_MBPS["$KEY"]="0.00"
                RESULT_INTEGRITY["$KEY"]="FAIL"
                echo "[$CONTENDER] size=${SIZE_MB}MB loss=${LOSS}%: TIMEOUT/FAILED"
            fi
            ip netns exec "$SRV_NS" rm -f "$REMOTE_DEST" 2>/dev/null || true
        done
    done

    stop_contender "$CONTENDER"
done

# ── Summary Markdown Table ────────────────────────────────────────────────────
echo ""
echo "=========================================================="
echo "  SCP Transfer Benchmark Summary"
echo "=========================================================="
echo ""

for SIZE_MB in $FILE_SIZES_MB; do
    echo "### Payload: ${SIZE_MB} MB"
    echo ""
    echo "| contender | loss% | transfer_time(s) | throughput(MB/s) | integrity |"
    echo "|-----------|-------|------------------|------------------|-----------|"
    for CONTENDER in $CONTENDERS; do
        for LOSS in $LOSS_RATES; do
            KEY="${CONTENDER}:${SIZE_MB}:${LOSS}"
            t="${RESULT_TIME["$KEY"]:-N/A}"
            mb="${RESULT_MBPS["$KEY"]:-N/A}"
            integ="${RESULT_INTEGRITY["$KEY"]:-N/A}"
            printf "| %-9s | %-5s | %-16s | %-16s | %-9s |\n" "$CONTENDER" "$LOSS" "$t" "$mb" "$integ"
        done
    done
    echo ""
done

# ── JSON Telemetry Export ─────────────────────────────────────────────────────
if [ -n "$OUTPUT_JSON" ]; then
    echo "[telemetry] exporting JSON to $OUTPUT_JSON"
    mkdir -p "$(dirname "$OUTPUT_JSON")" 2>/dev/null || true
    cat > "$OUTPUT_JSON" <<EOF
{
  "benchmark": "scp-transfer",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "file_sizes_mb": [$(echo "$FILE_SIZES_MB" | sed 's/  */, /g')],
  "loss_rates": [$(echo "$LOSS_RATES" | sed 's/  */, /g')],
  "results": [
EOF
    first=1
    for SIZE_MB in $FILE_SIZES_MB; do
        for CONTENDER in $CONTENDERS; do
            for LOSS in $LOSS_RATES; do
                KEY="${CONTENDER}:${SIZE_MB}:${LOSS}"
                [ -n "${RESULT_TIME["$KEY"]:-}" ] || continue
                t="${RESULT_TIME["$KEY"]}"
                mb="${RESULT_MBPS["$KEY"]}"
                integ="${RESULT_INTEGRITY["$KEY"]}"
                if [ "$first" -eq 0 ]; then
                    echo "    ," >> "$OUTPUT_JSON"
                fi
                first=0
                cat >> "$OUTPUT_JSON" <<EOF
    {
      "contender": "$CONTENDER",
      "file_size_mb": $SIZE_MB,
      "loss_percent": $LOSS,
      "transfer_time_sec": $([ "$t" = "TIMEOUT" ] && echo "null" || echo "$t"),
      "throughput_mb_s": $mb,
      "integrity": "$integ"
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

echo "[done] scp benchmark sweep complete"
