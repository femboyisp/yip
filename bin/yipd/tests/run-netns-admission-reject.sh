#!/usr/bin/env bash
# "admission_rejects_uncertified" money test for yipd's mesh admission gate (2c).
# Usage: run-netns-admission-reject.sh <path-to-yipd-binary> <path-to-yip-ca-binary>
#
# Topology: two netns joined by a single veth pair — X (uncertified) and Y
# (mesh-enabled, in-network). X is configured pure 2a/2b style: it knows Y's
# public key + underlay endpoint via a `[peer]` block and will happily
# initiate a handshake toward it, but X has NO mesh config at all (no CA, no
# cert) — it presents an EMPTY payload in its `HandshakeInit`, exactly like
# any 2a/2b node. Y is a real in-network member: mesh mode enabled (CA
# trusted, own CA-issued cert, a (empty) signed root set, network id), but Y
# has NO `[peer]` block for X — X is not, and must never become, a
# configured or cert-admitted peer of Y.
#
# `PeerManager::handle_handshake_init`'s admission rule (2c Task 6): a
# `HandshakeInit` is admitted iff its static key matches an already-known
# peer OR (with membership enabled) its payload decodes to a CA-signed cert
# that verifies for that static key. X is neither — Y silently drops X's
# `Init` pre-session (no reply, no peer created, no tunnel), exactly like
# 2a/2b's allowlist drop for an unconfigured key. From X's side this looks
# like Y is simply unreachable: the handshake never completes, so no TUN
# route ever comes up on X's end via Y and the ping fails outright.
#
# Assert (load-bearing): the ping FAILS — no tunnel forms between the
# uncertified X and the in-network Y.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-ca-binary>}"
YIPCA="${2:?Usage: $0 <yipd-binary> <yip-ca-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-admission-reject-test.XXXXXX)"

NS_X="yipAdmX"
NS_Y="yipAdmY"
VETH_X="vAdmX"
VETH_Y="vAdmY"
IP_X="10.91.0.1"
IP_Y="10.91.0.2"
VETH_PREFIX="24"
PORT="51820"
TUN_DEV="yip0"
NETWORK_ID="beefbeefbeefbeefbeefbeefbeefbee1"

PID_X=""
PID_Y=""

cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_X" ] && kill "$PID_X" 2>/dev/null || true
    [ -n "$PID_Y" ] && kill "$PID_Y" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_X" ] && kill -9 "$PID_X" 2>/dev/null || true
    [ -n "$PID_Y" ] && kill -9 "$PID_Y" 2>/dev/null || true
    ip netns del "$NS_X" 2>/dev/null || true
    ip netns del "$NS_Y" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. Y's CA + cert (X gets none: it is not, and must not become, a member) ─
echo "[setup] minting CA + Y's cert (X stays uncertified — no CA, no cert)"
CA_OUT="$("$YIPCA" genkey)"
CA_PRIV="$(echo "$CA_OUT" | grep '^ca_private=' | cut -d= -f2)"
CA_PUB="$(echo "$CA_OUT" | grep '^ca_public=' | cut -d= -f2)"

GENKEY_X="$("$YIPD" --genkey)"
PRIV_X="$(echo "$GENKEY_X" | grep '^private=' | cut -d= -f2)"
PUB_X="$(echo "$GENKEY_X" | grep '^public=' | cut -d= -f2)"

GENKEY_Y="$("$YIPD" --genkey)"
PRIV_Y="$(echo "$GENKEY_Y" | grep '^private=' | cut -d= -f2)"
PUB_Y="$(echo "$GENKEY_Y" | grep '^public=' | cut -d= -f2)"
SIGNKEY_Y="$("$YIPCA" genkey)"
SIGNPRIV_Y="$(echo "$SIGNKEY_Y" | grep '^ca_private=' | cut -d= -f2)"
SIGNPUB_Y="$(echo "$SIGNKEY_Y" | grep '^ca_public=' | cut -d= -f2)"

ADDR_X="$("$YIPD" --addr "$PUB_X")"
ADDR_Y="$("$YIPD" --addr "$PUB_Y")"
echo "[setup] node_addr X=$ADDR_X Y=$ADDR_Y"

CERT_Y_FILE="$TMPDIR_TEST/certY.hex"
echo "$CA_PRIV" | "$YIPCA" sign-cert \
    --member "$PUB_Y" --member-sign "$SIGNPUB_Y" \
    --network "$NETWORK_ID" --days 30 > "$CERT_Y_FILE"

# An empty (no roots) but validly CA-signed root set: Y only needs mesh mode
# ENABLED (to activate cert-based admission) for this test, not an actual
# bootstrap root or gossip.
ROOTS_IN="$TMPDIR_TEST/roots.in"
: > "$ROOTS_IN"
ROOTS_FILE="$TMPDIR_TEST/roots.hex"
echo "$CA_PRIV" | "$YIPCA" sign-roots --roots "$ROOTS_IN" --version 1 > "$ROOTS_FILE"

# ── 2. write configs ──────────────────────────────────────────────────────────
# X: pure 2a/2b — no mesh config, knows Y's key+endpoint as a plain `[peer]`.
CFG_X="$TMPDIR_TEST/yipX.conf"
cat > "$CFG_X" <<EOF
local_private=${PRIV_X}
local_public=${PUB_X}
listen=${IP_X}:${PORT}
device=${TUN_DEV}
device_kind=tun
[peer]
public_key=${PUB_Y}
endpoint=${IP_Y}:${PORT}
EOF

# Y: full mesh mode, zero configured peers (X is deliberately absent).
CFG_Y="$TMPDIR_TEST/yipY.conf"
cat > "$CFG_Y" <<EOF
local_private=${PRIV_Y}
local_public=${PUB_Y}
listen=${IP_Y}:${PORT}
device=${TUN_DEV}
device_kind=tun
ca_public=${CA_PUB}
member_sign_private=${SIGNPRIV_Y}
network_id=${NETWORK_ID}
cert=${CERT_Y_FILE}
roots=${ROOTS_FILE}
EOF

# ── 3. create namespaces + veth pair ──────────────────────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_X"
ip netns add "$NS_Y"

ip link add "$VETH_X" type veth peer name "$VETH_Y"
ip link set "$VETH_X" netns "$NS_X"
ip link set "$VETH_Y" netns "$NS_Y"
ip netns exec "$NS_X" ip addr add "${IP_X}/${VETH_PREFIX}" dev "$VETH_X"
ip netns exec "$NS_X" ip link set "$VETH_X" up
ip netns exec "$NS_X" ip link set lo up
ip netns exec "$NS_Y" ip addr add "${IP_Y}/${VETH_PREFIX}" dev "$VETH_Y"
ip netns exec "$NS_Y" ip link set "$VETH_Y" up
ip netns exec "$NS_Y" ip link set lo up

# ── 4. start daemons ───────────────────────────────────────────────────────────
LOG_X="$TMPDIR_TEST/yipX.log"
LOG_Y="$TMPDIR_TEST/yipY.log"

dump_logs() {
    echo "=== yipAdmX (uncertified) log ==="
    cat "$LOG_X" || true
    echo "=== yipAdmY (in-network) log ==="
    cat "$LOG_Y" || true
}

echo "[start] starting yipAdmY (in-network, mesh-enabled)"
ip netns exec "$NS_Y" "$YIPD" "$CFG_Y" >"$LOG_Y" 2>&1 &
PID_Y=$!

echo "[start] starting yipAdmX (uncertified)"
ip netns exec "$NS_X" "$YIPD" "$CFG_X" >"$LOG_X" 2>&1 &
PID_X=$!

# ── 5. wait for TUN devices to appear ─────────────────────────────────────────
TUN_WAIT=20
INTERVAL=0.25

echo "[wait] waiting for TUN devices to appear (up to ${TUN_WAIT}s)"
elapsed=0
while true; do
    X_UP=0; Y_UP=0
    ip netns exec "$NS_X" ip link show "$TUN_DEV" >/dev/null 2>&1 && X_UP=1 || true
    ip netns exec "$NS_Y" ip link show "$TUN_DEV" >/dev/null 2>&1 && Y_UP=1 || true

    if [ "$X_UP" -eq 1 ] && [ "$Y_UP" -eq 1 ]; then
        echo "[wait] both TUN devices are up"
        break
    fi

    if ! kill -0 "$PID_X" 2>/dev/null; then
        echo "[error] yipAdmX daemon died unexpectedly"; dump_logs; exit 1
    fi
    if ! kill -0 "$PID_Y" 2>/dev/null; then
        echo "[error] yipAdmY daemon died unexpectedly"; dump_logs; exit 1
    fi

    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for TUN devices"; dump_logs; exit 1
    fi
    sleep "$INTERVAL"
done

# ── 6. assign each TUN its node_addr/128 + the mesh-prefix route ────────────
echo "[setup] assigning node_addr/128 + fd00::/8 route on each TUN"
assign_mesh() {
    local ns="$1" addr="$2"
    ip netns exec "$ns" ip -6 addr add "${addr}/128" dev "$TUN_DEV" 2>/dev/null || true
    ip netns exec "$ns" ip -6 route add fd00::/8 dev "$TUN_DEV" 2>/dev/null || true
    ip netns exec "$ns" ip link show "$TUN_DEV" | grep -q "UP" || \
        ip netns exec "$ns" ip link set "$TUN_DEV" up
}
assign_mesh "$NS_X" "$ADDR_X"
assign_mesh "$NS_Y" "$ADDR_Y"

echo "[check] interface state in yipAdmX:"
ip netns exec "$NS_X" ip -6 addr show "$TUN_DEV"
echo "[check] interface state in yipAdmY:"
ip netns exec "$NS_Y" ip -6 addr show "$TUN_DEV"

# ── 7. ping X -> Y: MUST fail — Y refuses X's uncertified handshake ─────────
# X retries its HandshakeInit for a while (HANDSHAKE_TOTAL_MS) before giving
# up; a generous count/timeout gives that retry window a fair chance to
# (fail to) complete, so a real bug that admits X isn't masked by too short a
# test. The measured result IS the assertion here, so — unlike the other
# money tests — a non-zero exit is the PASS condition; nothing is || true'd
# away.
echo "[test] pinging ${ADDR_Y} from yipAdmX (expect: Y refuses, ping FAILS)"
set +e
ip netns exec "$NS_X" ping -6 -c 10 -W 2 "$ADDR_Y"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -eq 0 ]; then
    echo "[FAIL] ping X->Y unexpectedly SUCCEEDED — Y admitted an uncertified peer!"
    dump_logs
    exit 1
fi
echo "[PASS] ping X->Y failed (exit $PING_STATUS): Y correctly refused the uncertified handshake"
