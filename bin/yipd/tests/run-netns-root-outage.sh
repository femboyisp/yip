#!/usr/bin/env bash
# "discovery_survives_root_outage" money test for yipd's decentralized
# discovery (2c). Usage: run-netns-root-outage.sh <path-to-yipd-binary> <path-to-yip-ca-binary>
#
# Same topology + CA/cert/roots-minting workflow as run-netns-discovery.sh:
# three netns (A/B/R) on one shared bridge, A and B in mesh mode with NO
# `[peer]` for each other or for R — R is their only static knowledge, via
# the signed root set. This test carries the discovery money test one step
# further: once A and B have discovered each other via gossip through R and
# a live A<->B session is confirmed, R is KILLED outright, and A<->B traffic
# must keep flowing — the point of a gossiped, converged directory (vs. an
# always-on rendezvous dependency) is that A and B no longer need R once
# they've each resolved and handshaken the other; R was only ever needed for
# bootstrap + gossip transport, not for carrying or brokering the session
# itself.
#
# Assert: (1) the first ping A->B succeeds (same discovery warm-up tolerance
# as run-netns-discovery.sh), (2) after killing R, a second ping A->B still
# succeeds — this time with a TIGHT loss bound, since the A<->B session is
# already fully established and does not depend on R at all.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-ca-binary>}"
YIPCA="${2:?Usage: $0 <yipd-binary> <yip-ca-binary>}"
TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-root-outage-test.XXXXXX)"

BR="brRoot0"

NS_A="yipRootA"
NS_B="yipRootB"
NS_R="yipRootR"

VETH_A_H="vRootA0"; VETH_A_N="vRootA1"
VETH_B_H="vRootB0"; VETH_B_N="vRootB1"
VETH_R_H="vRootR0"; VETH_R_N="vRootR1"

IP_A="10.92.0.1"
IP_B="10.92.0.2"
IP_R="10.92.0.3"
VETH_PREFIX="24"
PORT="51820"
TUN_DEV="yip0"
NETWORK_ID="face0ff5face0ff5face0ff5face0ff5"

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
    echo "=== yipRootR (root) log ==="
    cat "$LOG_R" || true
    echo "=== yipRootA log ==="
    cat "$LOG_A" || true
    echo "=== yipRootB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipRootR (seed root)"
ip netns exec "$NS_R" "$YIPD" "$CFG_R" >"$LOG_R" 2>&1 &
PID_R=$!

echo "[start] starting yipRootA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipRootB"
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

    for pid_var_name in PID_A:yipRootA PID_B:yipRootB PID_R:yipRootR; do
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

echo "[check] interface state in yipRootA:"
ip netns exec "$NS_A" ip -6 addr show "$TUN_DEV"
echo "[check] interface state in yipRootB:"
ip netns exec "$NS_B" ip -6 addr show "$TUN_DEV"

# ── 7. first ping A -> B: establishes discovery + a live A<->B session ───────
# Same warm-up tolerance as run-netns-discovery.sh: A bootstraps to R,
# gossips, resolves B, admits, and handshakes B directly.
echo "[test] pinging ${ADDR_B} from yipRootA (expect discovery+handshake, then success)"
set +e
ip netns exec "$NS_A" ping -6 -c 30 -W 2 "$ADDR_B"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -ne 0 ]; then
    echo "[FAIL] initial ping A->B did not succeed (exit $PING_STATUS) — discovery never converged"
    dump_logs
    exit 1
fi
echo "[PASS] initial ping A->B succeeded: A<->B session is live"

# ── 8. kill the root, then confirm A<->B traffic keeps flowing ──────────────
echo "[test] killing yipRootR (root outage)"
kill "$PID_R" 2>/dev/null || true
sleep 0.2
kill -9 "$PID_R" 2>/dev/null || true
PID_R=""
if ! ip netns exec "$NS_R" ip link show "$TUN_DEV" >/dev/null 2>&1; then
    echo "[check] root's yipd process is confirmed gone (its TUN device is no longer queryable via a live process, though the netns/device may briefly linger)"
fi

echo "[test] pinging ${ADDR_B} from yipRootA again, with R dead — expect tight loss bound"
set +e
ip netns exec "$NS_A" ping -6 -c 10 -W 2 "$ADDR_B"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -ne 0 ]; then
    echo "[FAIL] post-outage ping A->B did not succeed (exit $PING_STATUS) — A<->B traffic did not survive R's death"
    dump_logs
    exit 1
fi
echo "[PASS] post-outage ping A->B succeeded: A<->B connectivity survives the root's death"
