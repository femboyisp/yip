#!/usr/bin/env bash
# "discovery_dynamic_ping" money test for yipd's decentralized discovery (2c).
# Usage: run-netns-discovery.sh <path-to-yipd-binary> <path-to-yip-ca-binary>
#
# Topology: three netns, A / B / R, all on ONE shared Linux bridge underlay
# (mirrors run-netns-triangle.sh's bridge setup). R is a normal `yipd` in
# mesh mode acting as the seed root: its pubkey + underlay address are named
# in the CA-signed root set that A and B both load. A and B are ALSO in mesh
# mode (ca_public/cert/roots/member_sign_private/network_id all set) but —
# this is the whole point — carry NO `[peer]` block for each other, and NO
# `[peer]` block for R either: the only static config any of the three holds
# is the signed root set, everyone else is discovered.
#
# Offline CA workflow, entirely before any daemon starts:
#   1. `yip-ca genkey` mints the CA's Ed25519 keypair.
#   2. For each of R/A/B: `yipd --genkey` mints its X25519 data-plane keypair
#      (the cert's `member_pubkey`); `yip-ca genkey` mints a SEPARATE Ed25519
#      keypair reused as the node's record-signing key (`member_sign_private`
#      / the cert's `member_sign_pubkey` — unrelated to the CA key, just the
#      same generator); `yip-ca sign-cert` issues its 30-day cert.
#   3. A roots-input file lists R's data-plane pubkey + R's underlay
#      `IP:port`; `yip-ca sign-roots` signs it into the shared root set file
#      A, B, and R all load via `roots=`.
#
# Timing: A and B each independently bootstrap-handshake to R (always-admit,
# pre-vetted by the signed root set), gossip their own record to R, then wait
# for R's own periodic digest (min 5s gossip-debounce interval) to relay the
# other's record back. Only once A's directory holds B's record does A's
# `on_tun` resolve B's mesh address into a real endpoint + admit + handshake.
# This is the "gossip tick interval + 2 handshakes" warm-up the money test
# must tolerate — a generous ping count/timeout (like run-netns-relay.sh's
# escalation warm-up) absorbs it; ping's own exit code already only requires
# >=1 reply, so no `|| true` is needed to keep the measured result
# load-bearing.
#
# Assert: (1) the ping succeeds, AND (2) — load-bearing, proves this is
# DISCOVERY and not static config — grepping A's config file for B's
# public key or a `[peer]` block finds nothing.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-ca-binary>}"
YIPCA="${2:?Usage: $0 <yipd-binary> <yip-ca-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-discovery-test.XXXXXX)"

BR="brDisc0"

NS_A="yipDiscA"
NS_B="yipDiscB"
NS_R="yipDiscR"

VETH_A_H="vDiscA0"; VETH_A_N="vDiscA1"
VETH_B_H="vDiscB0"; VETH_B_N="vDiscB1"
VETH_R_H="vDiscR0"; VETH_R_N="vDiscR1"

IP_A="10.90.0.1"
IP_B="10.90.0.2"
IP_R="10.90.0.3"
VETH_PREFIX="24"
PORT="51820"
TUN_DEV="yip0"
NETWORK_ID="dadedadedadedadedadedadedadedad1"

PID_A=""
PID_B=""
PID_R=""

cleanup() {
    echo "[cleanup] killing daemons and removing namespaces/bridge"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_R" ] && kill "$PID_R" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    [ -n "$PID_R" ] && kill -9 "$PID_R" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip netns del "$NS_R" 2>/dev/null || true
    ip link del "$BR" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. offline CA + per-node keys/certs + signed root set ────────────────────
echo "[setup] minting CA"
CA_OUT="$("$YIPCA" genkey)"
CA_PRIV="$(echo "$CA_OUT" | grep '^ca_private=' | cut -d= -f2)"
CA_PUB="$(echo "$CA_OUT" | grep '^ca_public=' | cut -d= -f2)"

# `<name> <priv> <pub> <sign_priv> <sign_pub>`, one line per node.
gen_node() {
    local gk sk
    gk="$("$YIPD" --genkey)"
    sk="$("$YIPCA" genkey)"
    local priv pub signpriv signpub
    priv="$(echo "$gk" | grep '^private=' | cut -d= -f2)"
    pub="$(echo "$gk" | grep '^public=' | cut -d= -f2)"
    signpriv="$(echo "$sk" | grep '^ca_private=' | cut -d= -f2)"
    signpub="$(echo "$sk" | grep '^ca_public=' | cut -d= -f2)"
    echo "$priv $pub $signpriv $signpub"
}

echo "[setup] generating per-node data-plane + record-signing keypairs"
read -r PRIV_A PUB_A SIGNPRIV_A SIGNPUB_A <<<"$(gen_node)"
read -r PRIV_B PUB_B SIGNPRIV_B SIGNPUB_B <<<"$(gen_node)"
read -r PRIV_R PUB_R SIGNPRIV_R SIGNPUB_R <<<"$(gen_node)"

ADDR_A="$("$YIPD" --addr "$PUB_A")"
ADDR_B="$("$YIPD" --addr "$PUB_B")"
ADDR_R="$("$YIPD" --addr "$PUB_R")"
echo "[setup] node_addr A=$ADDR_A B=$ADDR_B R=$ADDR_R"

sign_cert() {
    local member_pub="$1" member_sign_pub="$2"
    echo "$CA_PRIV" | "$YIPCA" sign-cert \
        --member "$member_pub" --member-sign "$member_sign_pub" \
        --network "$NETWORK_ID" --days 30
}
CERT_A_FILE="$TMPDIR_TEST/certA.hex"
CERT_B_FILE="$TMPDIR_TEST/certB.hex"
CERT_R_FILE="$TMPDIR_TEST/certR.hex"
sign_cert "$PUB_A" "$SIGNPUB_A" > "$CERT_A_FILE"
sign_cert "$PUB_B" "$SIGNPUB_B" > "$CERT_B_FILE"
sign_cert "$PUB_R" "$SIGNPUB_R" > "$CERT_R_FILE"

ROOTS_IN="$TMPDIR_TEST/roots.in"
echo "$PUB_R ${IP_R}:${PORT}" > "$ROOTS_IN"
ROOTS_FILE="$TMPDIR_TEST/roots.hex"
echo "$CA_PRIV" | "$YIPCA" sign-roots --roots "$ROOTS_IN" --version 1 > "$ROOTS_FILE"

# ── 2. write mesh config files — NO [peer] blocks anywhere ───────────────────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"
CFG_R="$TMPDIR_TEST/yipR.conf"

write_mesh_cfg() {
    local file="$1" priv="$2" pub="$3" ip="$4" certfile="$5" signpriv="$6"
    cat > "$file" <<EOF
local_private=${priv}
local_public=${pub}
listen=${ip}:${PORT}
device=${TUN_DEV}
device_kind=tun
ca_public=${CA_PUB}
member_sign_private=${signpriv}
network_id=${NETWORK_ID}
cert=${certfile}
roots=${ROOTS_FILE}
EOF
    # NOTE: an `[ ] && echo` one-liner here would make this the function's LAST
    # command; when OBF_PSK is unset the test returns 1, and under `set -e` the
    # `write_mesh_cfg` call aborts the whole script. Use an `if` (returns 0 when
    # the condition is false) so the obf-off path stays byte-identical.
    if [ -n "${OBF_PSK:-}" ]; then
        echo "obf_psk=${OBF_PSK}" >> "$file"
    fi
}
write_mesh_cfg "$CFG_A" "$PRIV_A" "$PUB_A" "$IP_A" "$CERT_A_FILE" "$SIGNPRIV_A"
write_mesh_cfg "$CFG_B" "$PRIV_B" "$PUB_B" "$IP_B" "$CERT_B_FILE" "$SIGNPRIV_B"
write_mesh_cfg "$CFG_R" "$PRIV_R" "$PUB_R" "$IP_R" "$CERT_R_FILE" "$SIGNPRIV_R"

# ── 3. create namespaces + shared bridge underlay ─────────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"
ip netns add "$NS_R"

echo "[setup] creating bridge $BR in the root namespace"
ip link add "$BR" type bridge
ip link set "$BR" up

setup_leg() {
    local ns="$1" veth_h="$2" veth_n="$3" ip_addr="$4"
    ip link add "$veth_h" type veth peer name "$veth_n"
    ip link set "$veth_n" netns "$ns"
    ip link set "$veth_h" master "$BR"
    ip link set "$veth_h" up
    ip netns exec "$ns" ip addr add "${ip_addr}/${VETH_PREFIX}" dev "$veth_n"
    ip netns exec "$ns" ip link set "$veth_n" up
    ip netns exec "$ns" ip link set lo up
}
echo "[setup] wiring veths to the bridge"
setup_leg "$NS_A" "$VETH_A_H" "$VETH_A_N" "$IP_A"
setup_leg "$NS_B" "$VETH_B_H" "$VETH_B_N" "$IP_B"
setup_leg "$NS_R" "$VETH_R_H" "$VETH_R_N" "$IP_R"

# ── 4. start daemons: seed root first, then A and B ───────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"
LOG_R="$TMPDIR_TEST/yipR.log"

dump_logs() {
    echo "=== yipDiscR (root) log ==="
    cat "$LOG_R" || true
    echo "=== yipDiscA log ==="
    cat "$LOG_A" || true
    echo "=== yipDiscB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipDiscR (seed root)"
ip netns exec "$NS_R" "$YIPD" "$CFG_R" >"$LOG_R" 2>&1 &
PID_R=$!

echo "[start] starting yipDiscA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipDiscB"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 5. wait for TUN devices to appear in all three namespaces ─────────────────
TUN_WAIT=20
INTERVAL=0.25

echo "[wait] waiting for TUN devices to appear (up to ${TUN_WAIT}s)"
elapsed=0
while true; do
    A_UP=0; B_UP=0; R_UP=0
    ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true
    ip netns exec "$NS_R" ip link show "$TUN_DEV" >/dev/null 2>&1 && R_UP=1 || true

    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ] && [ "$R_UP" -eq 1 ]; then
        echo "[wait] all three TUN devices are up"
        break
    fi

    for pid_var_name in PID_A:yipDiscA PID_B:yipDiscB PID_R:yipDiscR; do
        pid_var="${pid_var_name%%:*}"
        node_name="${pid_var_name##*:}"
        pid="${!pid_var}"
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[error] $node_name daemon died unexpectedly"
            dump_logs
            exit 1
        fi
    done

    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for TUN devices"
        dump_logs
        exit 1
    fi
    sleep "$INTERVAL"
done

# ── 6. assign each TUN its own node_addr/128 + the mesh-prefix route ─────────
echo "[setup] assigning node_addr/128 + fd00::/8 route on each TUN"
assign_mesh() {
    local ns="$1" addr="$2"
    ip netns exec "$ns" ip -6 addr add "${addr}/128" dev "$TUN_DEV" 2>/dev/null || true
    ip netns exec "$ns" ip -6 route add fd00::/8 dev "$TUN_DEV" 2>/dev/null || true
    ip netns exec "$ns" ip link show "$TUN_DEV" | grep -q "UP" || \
        ip netns exec "$ns" ip link set "$TUN_DEV" up
}
assign_mesh "$NS_A" "$ADDR_A"
assign_mesh "$NS_B" "$ADDR_B"
assign_mesh "$NS_R" "$ADDR_R"

echo "[check] interface state in yipDiscA:"
ip netns exec "$NS_A" ip -6 addr show "$TUN_DEV"
echo "[check] interface state in yipDiscB:"
ip netns exec "$NS_B" ip -6 addr show "$TUN_DEV"

# ── 7. load-bearing: A's config has no static knowledge of B whatsoever ──────
echo "[check] asserting A's config has no [peer] block and no knowledge of B's key"
if grep -q '\[peer\]' "$CFG_A"; then
    echo "[FAIL] A's config unexpectedly contains a [peer] block — this test requires pure discovery"
    cat "$CFG_A"
    exit 1
fi
if grep -qi "$PUB_B" "$CFG_A"; then
    echo "[FAIL] A's config unexpectedly contains B's public key — this test requires pure discovery"
    cat "$CFG_A"
    exit 1
fi
echo "[PASS] A's config names neither a [peer] block nor B's public key"

# ── 8. ping A -> B's node_addr, tolerating warm-up loss during discovery ─────
# A must: bootstrap-handshake to R, gossip its own record, wait for R's
# periodic digest to relay B's record back, resolve B's mesh address,
# admit B, and handshake B directly (B's underlay endpoint is on the same
# shared bridge, so it's directly reachable once resolved). A generous
# count/timeout (60s budget) absorbs this; ping's own exit code already only
# requires >=1 reply, so no `|| true` is needed to keep the result
# load-bearing. If discovery is mis-wired this will time out well before 60s
# of no replies at all.
echo "[test] pinging ${ADDR_B} from yipDiscA (expect discovery+handshake, then success)"
set +e
ip netns exec "$NS_A" ping -6 -c 30 -W 2 "$ADDR_B"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -ne 0 ]; then
    echo "[FAIL] ping A->B did not succeed (exit $PING_STATUS) — dynamic discovery did not converge"
    dump_logs
    exit 1
fi
echo "[PASS] ping A->B succeeded: A discovered B via gossip and handshake completed"
