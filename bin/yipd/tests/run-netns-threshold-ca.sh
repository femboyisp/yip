#!/usr/bin/env bash
# Integration test for decentralized threshold CA (RFC 9591 FROST) with yipd.
# Usage: run-netns-threshold-ca.sh <path-to-yipd-binary> <path-to-yip-ca-binary>
#
# Topology:
#   Bridge brThresh0 (10.99.0.0/24)
#   - nsCoord: 10.99.0.10 (yip-ca serve --role coordinator)
#   - nsSign1: 10.99.0.11 (yip-ca serve --role signer)
#   - nsSign2: 10.99.0.12 (yip-ca serve --role signer)
#   - nsNode:  10.99.0.20 (yipd mesh node with threshold_ca_server)
#
# Flow:
#   1. Generate 2-of-3 FROST threshold keys using `yip-ca dealer-gen`.
#   2. Start Coordinator in nsCoord and Signer 1 & 2 in nsSign1/nsSign2.
#   3. Enroll a node certificate using `yip-ca enroll` against nsCoord.
#   4. Start yipd in nsNode using the threshold-issued certificate.
#   5. Query certificate status via control socket: `yipd cert status`.
#   6. Trigger online certificate renewal: `yipd cert renew` and assert success.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-ca-binary>}"
YIPCA="${2:?Usage: $0 <yipd-binary> <yip-ca-binary>}"

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] $0 requires root privileges for netns and veth setup."
    exit 1
fi

TMPDIR="$(mktemp -d /tmp/yip-netns-thresh-test.XXXXXX)"

BR="brThresh0"
NS_COORD="nsThreshCoord"
NS_SIGN1="nsThreshSign1"
NS_SIGN2="nsThreshSign2"
NS_NODE="nsThreshNode"

VETH_COORD_H="vThCoord0"; VETH_COORD_N="vThCoord1"
VETH_SIGN1_H="vThSign10"; VETH_SIGN1_N="vThSign11"
VETH_SIGN2_H="vThSign20"; VETH_SIGN2_N="vThSign21"
VETH_NODE_H="vThNode0";   VETH_NODE_N="vThNode1"

IP_COORD="10.99.0.10"
IP_SIGN1="10.99.0.11"
IP_SIGN2="10.99.0.12"
IP_NODE="10.99.0.20"
VETH_PREFIX="24"
CA_PORT="9099"
NETWORK_ID="ca4eca4eca4eca4eca4eca4eca4eca4e"

PID_COORD=""
PID_SIGN1=""
PID_SIGN2=""
PID_NODE=""

cleanup() {
    echo "[cleanup] stopping daemons and deleting namespaces"
    [ -n "$PID_NODE" ] && kill "$PID_NODE" 2>/dev/null || true
    [ -n "$PID_SIGN2" ] && kill "$PID_SIGN2" 2>/dev/null || true
    [ -n "$PID_SIGN1" ] && kill "$PID_SIGN1" 2>/dev/null || true
    [ -n "$PID_COORD" ] && kill "$PID_COORD" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_NODE" ] && kill -9 "$PID_NODE" 2>/dev/null || true
    [ -n "$PID_SIGN2" ] && kill -9 "$PID_SIGN2" 2>/dev/null || true
    [ -n "$PID_SIGN1" ] && kill -9 "$PID_SIGN1" 2>/dev/null || true
    [ -n "$PID_COORD" ] && kill -9 "$PID_COORD" 2>/dev/null || true
    ip netns del "$NS_NODE" 2>/dev/null || true
    ip netns del "$NS_SIGN2" 2>/dev/null || true
    ip netns del "$NS_SIGN1" 2>/dev/null || true
    ip netns del "$NS_COORD" 2>/dev/null || true
    ip link del "$BR" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

echo "[1/6] Generating 2-of-3 FROST threshold keys with yip-ca dealer-gen..."
DEALER_OUT="$("$YIPCA" dealer-gen --threshold 2 --signers 3 --out-dir "$TMPDIR/keys")"
echo "$DEALER_OUT"
ROOT_PUB="$(echo "$DEALER_OUT" | grep "threshold_ca_public=" | cut -d= -f2)"
echo "Group Verifying Key: $ROOT_PUB"

echo "[2/6] Setting up network namespaces and bridge..."
ip link add "$BR" type bridge
ip link set "$BR" up

setup_ns() {
    local ns="$1"
    local vh="$2"
    local vn="$3"
    local ip="$4"
    ip netns add "$ns"
    ip link add "$vh" type veth peer name "$vn"
    ip link set "$vh" master "$BR"
    ip link set "$vh" up
    ip link set "$vn" netns "$ns"
    ip -netns "$ns" addr add "$ip/$VETH_PREFIX" dev "$vn"
    ip -netns "$ns" link set "$vn" up
    ip -netns "$ns" link set lo up
}

setup_ns "$NS_COORD" "$VETH_COORD_H" "$VETH_COORD_N" "$IP_COORD"
setup_ns "$NS_SIGN1" "$VETH_SIGN1_H" "$VETH_SIGN1_N" "$IP_SIGN1"
setup_ns "$NS_SIGN2" "$VETH_SIGN2_H" "$VETH_SIGN2_N" "$IP_SIGN2"
setup_ns "$NS_NODE"  "$VETH_NODE_H"  "$VETH_NODE_N"  "$IP_NODE"

# Verify underlay connectivity
ip netns exec "$NS_NODE" ping -c 1 -W 1 "$IP_COORD" >/dev/null

echo "[3/6] Starting Coordinator and Signer daemons in namespaces..."
ip netns exec "$NS_COORD" "$YIPCA" serve \
    --role coordinator \
    --bind "$IP_COORD:$CA_PORT" \
    --threshold 2 \
    --pubkey "$TMPDIR/keys/pubkey_package.json" > "$TMPDIR/coord.log" 2>&1 &
PID_COORD=$!

sleep 0.3

ip netns exec "$NS_SIGN1" "$YIPCA" serve \
    --role signer \
    --coordinator "$IP_COORD:$CA_PORT" \
    --key "$TMPDIR/keys/signer_1.json" \
    --pubkey "$TMPDIR/keys/pubkey_package.json" > "$TMPDIR/signer1.log" 2>&1 &
PID_SIGN1=$!

ip netns exec "$NS_SIGN2" "$YIPCA" serve \
    --role signer \
    --coordinator "$IP_COORD:$CA_PORT" \
    --key "$TMPDIR/keys/signer_2.json" \
    --pubkey "$TMPDIR/keys/pubkey_package.json" > "$TMPDIR/signer2.log" 2>&1 &
PID_SIGN2=$!

# Allow signers to connect and register commitments
sleep 1.0

echo "[4/6] Enrolling node certificate via threshold CA..."
NODE_GENKEY="$("$YIPD" --genkey)"
NODE_PRIV="$(echo "$NODE_GENKEY" | grep "private=" | cut -d= -f2)"
NODE_PUB="$(echo "$NODE_GENKEY" | grep "public=" | cut -d= -f2)"

NODE_SIGN_GENKEY="$("$YIPCA" genkey)"
NODE_SIGN_PRIV="$(echo "$NODE_SIGN_GENKEY" | grep "ca_private=" | cut -d= -f2)"
NODE_SIGN_PUB="$(echo "$NODE_SIGN_GENKEY" | grep "ca_public=" | cut -d= -f2)"

ip netns exec "$NS_NODE" "$YIPCA" enroll \
    --server "$IP_COORD:$CA_PORT" \
    --member "$NODE_PUB" \
    --member-sign "$NODE_SIGN_PUB" \
    --network "$NETWORK_ID" \
    --client-key "$NODE_SIGN_PRIV" \
    --out "$TMPDIR/node.cert"

if [ ! -s "$TMPDIR/node.cert" ]; then
    echo "[!] Failed to enroll certificate via threshold CA!"
    cat "$TMPDIR/coord.log"
    cat "$TMPDIR/signer1.log"
    exit 1
fi
echo "Certificate issued successfully ($(wc -c < "$TMPDIR/node.cert") bytes)."

echo "[5/6] Starting yipd with threshold-issued certificate..."
# Dummy signed rootset trusting root_pub
echo "$ROOT_PUB 10.99.0.254:51820" > "$TMPDIR/roots.txt"
# Create rootset file
# We create a dummy rootset hex by running yip-ca
ROOT_GENKEY="$("$YIPCA" genkey)"
ROOT_GEN_PRIV="$(echo "$ROOT_GENKEY" | grep "ca_private=" | cut -d= -f2)"
ROOT_GEN_PUB="$(echo "$ROOT_GENKEY" | grep "ca_public=" | cut -d= -f2)"
"$YIPCA" sign-roots --roots "$TMPDIR/roots.txt" --version 1 --ca-private "$ROOT_GEN_PRIV" > "$TMPDIR/roots.signed"

# Hex encode the cert binary for config cert=<path>
xxd -p -c 10000 "$TMPDIR/node.cert" > "$TMPDIR/node.cert.hex"

cat <<EOF > "$TMPDIR/node.conf"
local_private=$NODE_PRIV
local_public=$NODE_PUB
listen=$IP_NODE:51820
device=yip0
ca_public=$ROOT_PUB
ca_public=$ROOT_GEN_PUB
cert=$TMPDIR/node.cert.hex
roots=$TMPDIR/roots.signed
member_sign_private=$NODE_SIGN_PRIV
network_id=$NETWORK_ID
threshold_ca_server=$IP_COORD:$CA_PORT
control_socket=$TMPDIR/node.sock
EOF

ip netns exec "$NS_NODE" "$YIPD" "$TMPDIR/node.conf" > "$TMPDIR/yipd.log" 2>&1 &
PID_NODE=$!

sleep 1.0

echo "[6/6] Verifying control socket status and renewal..."
# Query status
STATUS_OUT="$(ip netns exec "$NS_NODE" "$YIPD" cert status -c "$TMPDIR/node.sock")"
echo "$STATUS_OUT"
echo "$STATUS_OUT" | grep -q "Threshold CA:      configured"
echo "$STATUS_OUT" | grep -q "TTL Remaining:"

# Query renew
RENEW_OUT="$(ip netns exec "$NS_NODE" "$YIPD" cert renew -c "$TMPDIR/node.sock")"
echo "$RENEW_OUT"
echo "$RENEW_OUT" | grep -q "certificate renewed successfully"
echo "$RENEW_OUT" | grep -q "New Not After:"

echo "[SUCCESS] Decentralized Threshold CA netns test passed completely!"
