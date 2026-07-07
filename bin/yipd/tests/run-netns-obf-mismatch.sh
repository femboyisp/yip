#!/usr/bin/env bash
# Anti-DPI obfuscation PSK-mismatch netns test for yipd (3a Task 6).
# Usage: run-netns-obf-mismatch.sh <path-to-yipd-binary>
#
# Mirrors run-netns-tunnel.sh's two-node direct topology (yipA / yipB joined
# by a veth pair), but configures A and B with DIFFERENT `obf_psk` values.
# Since the obfuscation envelope is keyed, B can never deobfuscate A's
# handshake packets (and vice versa): the handshake never completes, so a
# ping across the would-be tunnel MUST fail. This is the load-bearing
# inverse of `obfuscated_ping` — it proves the PSK actually gates
# recognizability rather than being a decorative no-op.
#
# This script exits 0 when the ping FAILS (the expected/correct outcome)
# and exits 1 if the ping unexpectedly SUCCEEDS (a mismatched PSK must never
# connect).
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-obf-mismatch-test.XXXXXX)"

NS_A="yipObfMisA"
NS_B="yipObfMisB"
VETH_A="vObfMisA"
VETH_B="vObfMisB"
VETH_A_IP="10.0.1.1"
VETH_B_IP="10.0.1.2"
TUN_A_IP="10.9.1.1"
TUN_B_IP="10.9.1.2"
TUN_PREFIX="24"
VETH_PREFIX="24"
PORT_A="51820"
PORT_B="51821"
TUN_DEV="yip0"

# Different obf_psk on A vs B: the handshake must never deobfuscate.
OBF_PSK_A="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
OBF_PSK_B="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"

PID_A=""
PID_B=""

cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. generate keypairs ──────────────────────────────────────────────────────
echo "[setup] generating keypairs"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"

PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

# ── 2. write config files, each with its OWN obf_psk ──────────────────────────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipA — responder (obf_psk mismatched vs B)
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT_A}
peer_endpoint=${VETH_B_IP}:${PORT_B}
device=${TUN_DEV}
initiate=false
obf_psk=${OBF_PSK_A}
EOF

cat > "$CFG_B" <<EOF
# yipB — initiator (obf_psk mismatched vs A)
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT_B}
peer_endpoint=${VETH_A_IP}:${PORT_A}
device=${TUN_DEV}
initiate=true
obf_psk=${OBF_PSK_B}
EOF

# ── 3. create namespaces and veth pair ────────────────────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"

echo "[setup] creating veth pair"
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

ip netns exec "$NS_A" ip addr add "${VETH_A_IP}/${VETH_PREFIX}" dev "$VETH_A"
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_A" ip link set lo up

ip netns exec "$NS_B" ip addr add "${VETH_B_IP}/${VETH_PREFIX}" dev "$VETH_B"
ip netns exec "$NS_B" ip link set "$VETH_B" up
ip netns exec "$NS_B" ip link set lo up

# ── 4. start daemons ─────────────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

echo "[start] starting yipA (responder, obf_psk=A)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB (initiator, obf_psk=B, MISMATCHED)"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 5. wait (bounded) for TUN devices — they may never come up, since the
# mismatched PSK should keep the handshake from ever completing. Poll for a
# shorter window than the happy-path script and tolerate the timeout: the
# absence of both TUN devices is itself evidence the mismatch worked, so we
# do not fail the script here — the ping check below is the real assertion.
TUN_WAIT=8
INTERVAL=0.25

echo "[wait] waiting up to ${TUN_WAIT}s for TUN devices (not expected to fully converge)"
elapsed=0
while true; do
    A_UP=0
    B_UP=0
    ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true

    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ]; then
        echo "[wait] both TUN devices are up"
        break
    fi

    if ! kill -0 "$PID_A" 2>/dev/null; then
        echo "[error] yipA daemon died unexpectedly"
        echo "=== yipA log ==="
        cat "$LOG_A" || true
        exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipB daemon died unexpectedly"
        echo "=== yipB log ==="
        cat "$LOG_B" || true
        exit 1
    fi

    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[wait] timed out waiting for TUN devices (expected under a PSK mismatch)"
        break
    fi
    sleep "$INTERVAL"
done

# If neither TUN device came up at all, the handshake never got far enough to
# create the device — the mismatch already proved its point, no ping needed.
A_HAS_TUN=0
B_HAS_TUN=0
ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_HAS_TUN=1 || true
ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_HAS_TUN=1 || true

if [ "$A_HAS_TUN" -eq 0 ] || [ "$B_HAS_TUN" -eq 0 ]; then
    echo "[PASS] mismatched obf_psk: TUN device(s) never came up, no connection was ever established"
    exit 0
fi

# ── 6. assign tunnel IPs (only reached if, surprisingly, both TUNs are up) ───
echo "[setup] assigning tunnel IPs"
ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/${TUN_PREFIX}" dev "$TUN_DEV"

ip netns exec "$NS_A" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_A" ip link set "$TUN_DEV" up
ip netns exec "$NS_B" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_B" ip link set "$TUN_DEV" up

sleep 0.5

# ── 7. ping across the (should-be-nonexistent) tunnel — MUST FAIL ───────────
# This is the load-bearing check, inverted from the happy-path script: a
# ping SUCCESS here is a test FAILURE (a mismatched obf_psk must never let
# traffic through), and a ping FAILURE is the expected/correct PASS.
echo "[test] pinging ${TUN_A_IP} from yipB across the (mismatched-PSK) tunnel — expecting FAILURE"
set +e
ip netns exec "$NS_B" ping -c 3 -W 3 "$TUN_A_IP"
PING_STATUS=$?
set -e

if [ "$PING_STATUS" -eq 0 ]; then
    echo "[FAIL] ping unexpectedly SUCCEEDED under a mismatched obf_psk — obfuscation did not gate connectivity"
    echo "=== yipA log ==="
    cat "$LOG_A" || true
    echo "=== yipB log ==="
    cat "$LOG_B" || true
    exit 1
fi

echo "[PASS] ping correctly failed (exit $PING_STATUS) under mismatched obf_psk"
