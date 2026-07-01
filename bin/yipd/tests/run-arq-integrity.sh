#!/usr/bin/env bash
# run-arq-integrity.sh — End-to-end ARQ integrity test.
#
# Proves that reactive ARQ fires and recovers bulk UDP loss end-to-end:
#
#   1. Set up two yipd in separate netns over a veth pair (no loss yet).
#   2. Complete the Noise handshake and confirm baseline connectivity on a
#      CLEAN link (loss during handshake breaks establishment).
#   3. THEN apply tc netem loss 5% delay 5ms on both veth ends.
#   4. Drive a Bulk-classified UDP flow (1400-byte payloads at high rate).
#      - Bulk classification: ewma_size > 1000 bytes → arq=true.
#   5. Assert UDP delivery ≥ 98% (FEC+ARQ recover ~5% loss).
#   6. Assert the receiver-side yipd log contains "ARQ retransmits: N" with N > 0.
#      This proves ARQ fired, distinct from proactive FEC alone.
#
# Usage: run-arq-integrity.sh [<path-to-yipd>]
#
# Skips cleanly (exit 0) if required tools are missing.
set -euo pipefail

# ── tool checks ───────────────────────────────────────────────────────────────
for tool in ip tc python3 awk grep; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[SKIP] run-arq-integrity: required tool '$tool' not found"
        exit 0
    fi
done

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

if [ ! -x "$YIPD" ]; then
    echo "[SKIP] run-arq-integrity: yipd binary not found or not executable: $YIPD"
    exit 0
fi

# ── locate udp_tx.py / udp_rx.py ─────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Try the local tests dir, then workspace-relative yip-bench tests dir.
PY_DIR="$SCRIPT_DIR"
if [ ! -f "$PY_DIR/udp_tx.py" ]; then
    # bin/yipd/tests → workspace root is three levels up
    WORKSPACE_ROOT_PY="$(cd "$SCRIPT_DIR/../../.." && pwd)"
    BENCH_PY="$WORKSPACE_ROOT_PY/crates/yip-bench/tests"
    if [ -f "$BENCH_PY/udp_tx.py" ]; then
        PY_DIR="$BENCH_PY"
    else
        echo "[SKIP] run-arq-integrity: udp_tx.py not found (tried $SCRIPT_DIR and $BENCH_PY)"
        exit 0
    fi
fi

# ── parameters ────────────────────────────────────────────────────────────────
# 20000 packets at 1400 bytes each. 5% loss → ~1000 lost; FEC+ARQ should
# recover to ≥98%. High PPS (5000) saturates the flow table quickly so
# Bulk classification kicks in within the first few milliseconds.
N="${N:-20000}"
PPS="${PPS:-5000}"
PAYLOAD="${PAYLOAD:-1400}"
LOSS_PCT="5"
MIN_DELIVERY_PCT="98"

# ── netns / veth names ────────────────────────────────────────────────────────
NS_A="arqA"
NS_B="arqB"
VETH_A="arqvA"
VETH_B="arqvB"
VETH_A_IP="10.50.0.1"
VETH_B_IP="10.50.0.2"
TUN_A_IP="10.51.0.1"
TUN_B_IP="10.51.0.2"
PORT_A="51860"
PORT_B="51861"
TUN_DEV="yip0"

TMPDIR_TEST="$(mktemp -d /tmp/yip-arq-integrity.XXXXXX)"
PID_A=""
PID_B=""

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    for ns in "$NS_A" "$NS_B"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. generate keypairs ──────────────────────────────────────────────────────
echo "[setup] generating keypairs"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"
PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A"  | grep '^public='  | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B"  | grep '^public='  | cut -d= -f2)"

# ── 2. write config files ─────────────────────────────────────────────────────
CFG_A="$TMPDIR_TEST/arqA.conf"
CFG_B="$TMPDIR_TEST/arqB.conf"
cat > "$CFG_A" <<EOF
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT_A}
peer_endpoint=${VETH_B_IP}:${PORT_B}
device=${TUN_DEV}
initiate=false
EOF
cat > "$CFG_B" <<EOF
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT_B}
peer_endpoint=${VETH_A_IP}:${PORT_A}
device=${TUN_DEV}
initiate=true
EOF

# ── 3. create namespaces and veth pair (NO loss yet) ─────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"

echo "[setup] creating veth pair"
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

ip netns exec "$NS_A" ip addr add "${VETH_A_IP}/24" dev "$VETH_A"
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_A" ip link set lo up

ip netns exec "$NS_B" ip addr add "${VETH_B_IP}/24" dev "$VETH_B"
ip netns exec "$NS_B" ip link set "$VETH_B" up
ip netns exec "$NS_B" ip link set lo up

# ── 4. start daemons on CLEAN link ───────────────────────────────────────────
LOG_A="$TMPDIR_TEST/arqA.log"
LOG_B="$TMPDIR_TEST/arqB.log"

echo "[start] starting arqA (responder)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting arqB (initiator)"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 5. wait for TUN devices ───────────────────────────────────────────────────
TUN_WAIT=20
INTERVAL=0.25
echo "[wait] waiting for TUN devices to appear (up to ${TUN_WAIT}s)"
elapsed=0
while true; do
    A_UP=0; B_UP=0
    ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true
    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ]; then
        echo "[wait] both TUN devices are up"; break
    fi
    if ! kill -0 "$PID_A" 2>/dev/null; then
        echo "[error] arqA daemon died"; cat "$LOG_A" || true; exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] arqB daemon died"; cat "$LOG_B" || true; exit 1
    fi
    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for TUN devices"
        cat "$LOG_A" "$LOG_B" || true; exit 1
    fi
    sleep "$INTERVAL"
done

# ── 6. assign tunnel IPs ──────────────────────────────────────────────────────
echo "[setup] assigning tunnel IPs"
ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_A" ip link set "$TUN_DEV" up
ip netns exec "$NS_B" ip link set "$TUN_DEV" up
sleep 0.5

# ── 7. baseline connectivity check on CLEAN link ─────────────────────────────
echo "[check] baseline ping on clean link"
ip netns exec "$NS_B" ping -c 3 -W 5 "$TUN_A_IP" >/dev/null || {
    echo "[error] baseline ping failed (clean link)"; cat "$LOG_A" "$LOG_B" || true; exit 1
}
echo "[check] baseline connectivity OK"

# ── 8. NOW apply netem loss ───────────────────────────────────────────────────
# CRITICAL: handshake must complete BEFORE applying loss.
echo "[netem] applying ${LOSS_PCT}% loss + 5ms delay on veth pair"
ip netns exec "$NS_A" tc qdisc replace dev "$VETH_A" root netem loss "${LOSS_PCT}%" delay 5ms
ip netns exec "$NS_B" tc qdisc replace dev "$VETH_B" root netem loss "${LOSS_PCT}%" delay 5ms

# Brief settle: let the first feedback cycles run under the lossy link so the
# controller knows there is loss before we start the bulk blast.
sleep 0.5

# ── 9. drive a Bulk-classified UDP flow ──────────────────────────────────────
# 1400-byte payloads guarantee ewma_size > LARGE_BYTES (1000) → Bulk after 4+
# packets.  5000 pps is well above MIN_RATE_PPS (20), reaching Bulk quickly.
echo "[blast] sending N=${N} UDP packets (${PAYLOAD} bytes) at ${PPS} pps"

# Receiver: bind on arqA's tunnel IP, 10s idle timeout (generous for ARQ round-trips)
ip netns exec "$NS_A" python3 "$PY_DIR/udp_rx.py" "$TUN_A_IP" 7890 "$N" 10 \
    >"$TMPDIR_TEST/arq.out" 2>&1 &
RX_PID=$!

# Brief pause to ensure receiver is bound before sender fires
sleep 0.4

# Sender: blast from arqB's tunnel IP toward arqA's tunnel IP
ip netns exec "$NS_B" python3 "$PY_DIR/udp_tx.py" "$TUN_A_IP" 7890 "$N" "$PPS" "$PAYLOAD" \
    >/dev/null 2>&1

# Wait for receiver to finish (it exits after the idle timeout or all N received)
wait "$RX_PID" || true

# ── 10. parse delivery results ────────────────────────────────────────────────
RECV_LINE="$(cat "$TMPDIR_TEST/arq.out")"
echo "[result] $RECV_LINE"

RECV_K="$(echo "$RECV_LINE" | grep -oP 'received=\K[0-9]+' || echo 0)"
RECV_PCT="$(awk "BEGIN { if ($N > 0) printf \"%.1f\", 100.0*$RECV_K/$N; else print \"0.0\" }")"

echo "[result] UDP delivered: ${RECV_PCT}% of ${N} packets (${RECV_K} received)"
echo "[result] Minimum required: ${MIN_DELIVERY_PCT}%"

# ── 11. let the log collector run a bit so periodic ARQ log line appears ─────
# The periodic log fires every 5s; wait up to 12s for it.
# The UDP blast goes B → A (arqB sends, arqA receives).  A's ingress sees gaps
# in the incoming FEC stream and emits NACKs back to B.  B's ingress receives
# the NACKs and retransmits — so ARQ retransmit counts accumulate in arqB's log.
echo "[wait] waiting up to 12s for ARQ periodic log line in sender (arqB)"
ARQ_WAIT=12
ARQ_ELAPSED=0
while [ "$ARQ_ELAPSED" -lt "$ARQ_WAIT" ]; do
    if grep -q "ARQ retransmits:" "$LOG_B" 2>/dev/null; then
        break
    fi
    sleep 1
    ARQ_ELAPSED=$((ARQ_ELAPSED + 1))
done

# ── 12. assertions ────────────────────────────────────────────────────────────
PASS=1

# Assert delivery >= MIN_DELIVERY_PCT
if awk "BEGIN { exit (${RECV_PCT} >= ${MIN_DELIVERY_PCT}) ? 0 : 1 }"; then
    echo "[PASS] delivery ${RECV_PCT}% >= ${MIN_DELIVERY_PCT}%"
else
    echo "[FAIL] delivery ${RECV_PCT}% < ${MIN_DELIVERY_PCT}% (FEC+ARQ did not recover enough loss)"
    PASS=0
fi

# Assert ARQ fired: find the LAST "ARQ retransmits: N" line in arqB's log (sender).
# The UDP flow is B→A, so B's ingress is where NACKs arrive and retransmits happen.
ARQ_COUNT=0
if [ -f "$LOG_B" ]; then
    ARQ_LINE="$(grep "ARQ retransmits:" "$LOG_B" | tail -1 || true)"
    if [ -n "$ARQ_LINE" ]; then
        ARQ_COUNT="$(echo "$ARQ_LINE" | grep -oP 'ARQ retransmits: \K[0-9]+' || echo 0)"
    fi
fi

echo "[result] ARQ retransmit count (sender arqB): ${ARQ_COUNT}"

if [ "$ARQ_COUNT" -gt 0 ]; then
    echo "[PASS] ARQ fired: ${ARQ_COUNT} objects retransmitted"
else
    echo "[FAIL] ARQ did not fire (retransmit count = 0)"
    echo "[debug] arqA log tail:"
    tail -30 "$LOG_A" || true
    echo "[debug] arqB log tail:"
    tail -30 "$LOG_B" || true
    PASS=0
fi

echo ""
echo "=========================================================="
echo "  ARQ integrity test results"
echo "  UDP delivered: ${RECV_PCT}% of ${N}  (min: ${MIN_DELIVERY_PCT}%)"
echo "  ARQ retransmits (sender arqB): ${ARQ_COUNT}  (must be > 0)"
echo "=========================================================="

if [ "$PASS" -eq 1 ]; then
    echo "[PASS] run-arq-integrity: all assertions passed"
    exit 0
else
    echo "[FAIL] run-arq-integrity: one or more assertions failed"
    exit 1
fi
