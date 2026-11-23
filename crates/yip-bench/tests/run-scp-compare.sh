#!/usr/bin/env bash
# run-scp-compare.sh — Real-world SCP file transfer benchmark under netem loss.
#
# Measures real OpenSSH scp throughput and goodput under packet loss across
# VPN contenders (yip, wireguard, wireguard-go, amneziawg, openvpn, n2n, zerotier, tailscale, netbird, nebula).
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

# ── configuration ─────────────────────────────────────────────────────────────
CONTENDERS="${CONTENDERS:-yip wireguard wireguard-go amneziawg openvpn n2n zerotier tailscale netbird nebula}"
LOSS_RATES="${LOSS_RATES:-0 5 10}"
FILE_SIZES_MB="${FILE_SIZES_MB:-100}"
OUTPUT_JSON="${OUTPUT_JSON:-}"
SSH_PORT="${SSH_PORT:-2222}"

# ── tmpdir ────────────────────────────────────────────────────────────────────
TMPDIR_TEST="$(mktemp -d /dev/shm/yip-scp-compare.XXXXXX 2>/dev/null || mktemp -d /tmp/yip-scp-compare.XXXXXX)"
chmod 777 "$TMPDIR_TEST"

# Source unified contender definitions, topology, and lifecycles
# shellcheck source=./contenders-lib.sh
source "$SCRIPT_DIR/contenders-lib.sh"

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo "[cleanup] cleaning up active processes and namespaces"
    # Kill any active sshd
    for _pidfile in "$TMPDIR_TEST"/sshd-*.pid; do
        [ -f "$_pidfile" ] || continue
        _pid="$(cat "$_pidfile" 2>/dev/null || true)"
        [ -n "$_pid" ] && kill -9 "$_pid" 2>/dev/null || true
    done
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

# ── Benchmark execution loop ──────────────────────────────────────────────────
declare -A RESULT_TIME
declare -A RESULT_MBPS
declare -A RESULT_INTEGRITY

echo "=========================================================="
echo "  SCP File Transfer Benchmark under netem packet loss"
echo "  Payloads: ${FILE_SIZES_MB} MB | Loss: ${LOSS_RATES}% | Delay: 5ms"
echo "  Contenders: ${CONTENDERS}"
echo "=========================================================="

for CONTENDER in $CONTENDERS; do
    echo ""
    echo "── Running contender: $CONTENDER ──"

    if ! get_contender_info "$CONTENDER"; then
        echo "[skip] unknown contender $CONTENDER"
        continue
    fi

    if ! start_contender "$CONTENDER_CANONICAL"; then
        echo "[$CONTENDER_CANONICAL] startup skipped or failed"
        stop_contender "$CONTENDER_CANONICAL" 2>/dev/null || true
        continue
    fi

    # Refresh contender info in case of dynamically allocated overlay addresses
    get_contender_info "$CONTENDER_CANONICAL"
    SRV_NS="$NS_A"; CLI_NS="$NS_B"
    SRV_IP="$TUN_A_IP"; CLI_IP="$TUN_B_IP"
    VETH_SRV="$VETH_A"; VETH_CLI="$VETH_B"

    for SIZE_MB in $FILE_SIZES_MB; do
        PAYLOAD="$TMPDIR_TEST/payload_${SIZE_MB}MB"
        if [ ! -f "$PAYLOAD" ]; then
            echo "[payload] generating ${SIZE_MB} MB payload file"
            dd if=/dev/zero of="$PAYLOAD" bs=1M count="$SIZE_MB" status=none
        fi

        for LOSS in $LOSS_RATES; do
            echo "[$CONTENDER_CANONICAL] applying loss=${LOSS}% delay=5ms (payload=${SIZE_MB}MB)"
            apply_netem "$SRV_NS" "$CLI_NS" "$VETH_SRV" "$VETH_CLI" "$LOSS"

            SSHD_PID="$TMPDIR_TEST/sshd-${CONTENDER_CANONICAL}.pid"
            SSHD_LOG="$TMPDIR_TEST/sshd-${CONTENDER_CANONICAL}.log"
            start_sshd "$SRV_NS" "$SSHD_PID" "$SSHD_LOG"

            # Timeout scaled: 60s base + 3s per MB
            TIMEOUT_SEC=$(( 60 + SIZE_MB * 3 ))
            REMOTE_DEST="/tmp/payload-${CONTENDER_CANONICAL}-${SIZE_MB}.copy"
            ip netns exec "$SRV_NS" rm -f "$REMOTE_DEST"

            echo "[$CONTENDER_CANONICAL] transferring ${SIZE_MB}MB via scp (timeout: ${TIMEOUT_SEC}s)..."
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

            KEY="${CONTENDER_CANONICAL}:${SIZE_MB}:${LOSS}"
            if [ "$transfer_ok" -eq 1 ]; then
                elapsed=$(awk "BEGIN {print $t_end - $t_start}")
                mbps=$(awk "BEGIN { if ($elapsed > 0) printf \"%.2f\", $SIZE_MB / $elapsed; else print \"0.00\" }")
                RESULT_TIME["$KEY"]="$elapsed"
                RESULT_MBPS["$KEY"]="$mbps"

                integrity="OK"
                if ! ip netns exec "$SRV_NS" cmp -s "$PAYLOAD" "$REMOTE_DEST"; then
                    integrity="FAIL"
                fi
                RESULT_INTEGRITY["$KEY"]="$integrity"
                echo "[$CONTENDER_CANONICAL] size=${SIZE_MB}MB loss=${LOSS}%: time=${elapsed}s throughput=${mbps} MB/s integrity=${integrity}"
            else
                RESULT_TIME["$KEY"]="TIMEOUT"
                RESULT_MBPS["$KEY"]="0.00"
                RESULT_INTEGRITY["$KEY"]="FAIL"
                echo "[$CONTENDER_CANONICAL] size=${SIZE_MB}MB loss=${LOSS}%: TIMEOUT/FAILED"
            fi
            ip netns exec "$SRV_NS" rm -f "$REMOTE_DEST" 2>/dev/null || true
        done
    done

    stop_contender "$CONTENDER_CANONICAL"
    verify_isolation "$CONTENDER_CANONICAL"
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
        CANON="$CONTENDER"
        if get_contender_info "$CONTENDER"; then
            CANON="$CONTENDER_CANONICAL"
        fi
        for LOSS in $LOSS_RATES; do
            KEY="${CANON}:${SIZE_MB}:${LOSS}"
            t="${RESULT_TIME["$KEY"]:-N/A}"
            mb="${RESULT_MBPS["$KEY"]:-N/A}"
            integ="${RESULT_INTEGRITY["$KEY"]:-N/A}"
            printf "| %-14s | %-5s | %-16s | %-16s | %-9s |\n" "$CANON" "$LOSS" "$t" "$mb" "$integ"
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
            CANON="$CONTENDER"
            if get_contender_info "$CONTENDER"; then
                CANON="$CONTENDER_CANONICAL"
            fi
            for LOSS in $LOSS_RATES; do
                KEY="${CANON}:${SIZE_MB}:${LOSS}"
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
      "contender": "$CANON",
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
