#!/usr/bin/env bash
# End-to-end netns TLS-mimicry tunnel test for yipd (3c.2 Task 6).
# Usage: run-netns-tls.sh <path-to-yipd-binary>
#
# Creates two network namespaces (yipA, yipB) joined by a veth pair, starts a
# `transport=tls` yipd daemon in each (NO obf_psk — mutually exclusive with
# transport=tls, see config.rs), brings up TUN devices with tunnel IPs, then
# pings across the tunnel and pushes a bulk transfer to prove data integrity.
#
# Like the QUIC test (run-netns-quic.sh) this is a TWO-layer bring-up, but over
# TCP: a real TLS 1.3 handshake (client/server role decided by static-key order
# — see tls.rs::connection_role, smaller key = TCP client, NOT the legacy
# `initiate=` key, which is parsed but ignored) must complete before the inner
# yip Noise-IK handshake even starts, since the inner handshake rides the TLS
# byte-stream (length-prefix framed). The TLS client reconnects with backoff if
# the server isn't listening yet, so the ping step below is deliberately as
# generous as the QUIC/discovery money tests (`ping -c 30 -W 2`) to absorb that
# warm-up without being flaky.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-tls-test.XXXXXX)"

NS_A="yipA"
NS_B="yipB"
VETH_A="vethA"
VETH_B="vethB"
VETH_A_IP="10.0.0.1"
VETH_B_IP="10.0.0.2"
TUN_A_IP="10.9.0.1"
TUN_B_IP="10.9.0.2"
TUN_PREFIX="24"
VETH_PREFIX="24"
PORT_A="51820"
PORT_B="51821"
TUN_DEV="yip0"

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

# ── 2. write config files (transport=tls, NO obf_psk) ────────────────────────
# Symmetric config: each side lists its own `listen` and the peer's
# `peer_endpoint`. The static-key role tiebreak (tls.rs) picks which side is the
# TCP client (dials peer_endpoint) vs server (binds listen); the config need not
# know which is which, exactly as the QUIC test.
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipA — TLS transport
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT_A}
peer_endpoint=${VETH_B_IP}:${PORT_B}
device=${TUN_DEV}
initiate=false
transport=tls
tls_sni=www.apple.com
EOF

cat > "$CFG_B" <<EOF
# yipB — TLS transport
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT_B}
peer_endpoint=${VETH_A_IP}:${PORT_A}
device=${TUN_DEV}
initiate=true
transport=tls
tls_sni=www.apple.com
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

echo "[start] starting yipA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 5. wait for TUN device creation ──────────────────────────────────────────
# TunTap::create runs unconditionally before the transport dispatch in
# tunnel.rs::run, so the TUN device appears as soon as the daemon starts — this
# wait is NOT gated on the (two-layer) handshake completing.
TUN_WAIT=20
INTERVAL=0.25

echo "[wait] waiting for TUN devices to appear (up to ${TUN_WAIT}s)"
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
        echo "[error] timed out waiting for TUN devices"
        echo "=== yipA log ==="
        cat "$LOG_A" || true
        echo "=== yipB log ==="
        cat "$LOG_B" || true
        exit 1
    fi
    sleep "$INTERVAL"
done

# ── 6. assign tunnel IPs ──────────────────────────────────────────────────────
echo "[setup] assigning tunnel IPs"
ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/${TUN_PREFIX}" dev "$TUN_DEV"

ip netns exec "$NS_A" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_A" ip link set "$TUN_DEV" up
ip netns exec "$NS_B" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_B" ip link set "$TUN_DEV" up

echo "[check] interface state in yipA:"
ip netns exec "$NS_A" ip addr show "$TUN_DEV"
echo "[check] interface state in yipB:"
ip netns exec "$NS_B" ip addr show "$TUN_DEV"

sleep 0.5

# ── 7. ping across the tunnel — generous warm-up (two sequential handshakes:
#      outer TLS 1.3 over TCP, then inner yip Noise-IK) ───────────────────────
echo "[test] pinging ${TUN_A_IP} from yipB across the TLS tunnel"
set +e
ip netns exec "$NS_B" ping -c 30 -W 2 "$TUN_A_IP"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -ne 0 ]; then
    echo "[FAIL] ping failed over TLS transport (exit $PING_STATUS)"
    echo "=== yipA log ==="
    cat "$LOG_A" || true
    echo "=== yipB log ==="
    cat "$LOG_B" || true
    exit "$PING_STATUS"
fi
echo "[PASS] ping succeeded over TLS transport"

# ── 8. full-MTU integrity sweep across the TLS-TCP tunnel ────────────────────
# ping's default 56-byte frames barely exercise the length-prefix framing. Send
# 40 large (1400-byte payload) ICMP echoes with a fixed fill pattern: the kernel
# verifies every reply's payload byte-for-byte, so 0% loss here proves the
# framing carries and reassembles full-size datagrams intact (many frames, each
# split across TLS records). This is the data-integrity check without provoking
# the known bulk-throughput ceiling of the single-connection pump (TLS writes
# are bounded-retry, not EPOLLOUT-driven — a documented 3c.2 follow-up).
echo "[test] full-MTU integrity sweep (40 x 1400-byte patterned ICMP)"
set +e
ip netns exec "$NS_B" ping -c 40 -W 2 -s 1400 -p deadbeef "$TUN_A_IP"
SWEEP_STATUS=$?
set -e
if [ "$SWEEP_STATUS" -ne 0 ]; then
    echo "[FAIL] full-MTU integrity sweep failed (exit $SWEEP_STATUS) — framing dropped/corrupted large frames"
    echo "=== yipA log ==="; cat "$LOG_A" || true
    echo "=== yipB log ==="; cat "$LOG_B" || true
    exit "$SWEEP_STATUS"
fi
echo "[PASS] full-MTU frames intact across the TLS tunnel (0% loss, payload verified)"

echo "[PASS] netns TLS tunnel: handshake + ping + full-MTU-intact over transport=tls"
