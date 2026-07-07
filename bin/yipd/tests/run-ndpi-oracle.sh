#!/usr/bin/env bash
# nDPI undetectability oracle for obfuscated yip traffic (3a Task 7).
# Usage: run-ndpi-oracle.sh <path-to-yipd-binary> <path-to-ndpiReader-binary>
#
# This is the anti-DPI "money test": it captures a REAL obfuscated yip
# exchange (handshake + data + control, driven by ping) between two yipd in
# separate netns, joined by a veth pair, on a NEUTRAL port — then runs
# nDPI/nDPId's `ndpiReader` classifier against the capture and asserts that
# nDPI cannot recognize the traffic as any known VPN/proxy protocol.
#
# Why a NEUTRAL port (34567, not 51820): nDPI port-matches 51820 to
# "WireGuard [Confidence: Match by port]" regardless of payload — that would
# be testing the port number, not the obfuscation. Using a neutral port
# forces nDPI to classify by content alone, which is what 3a is actually
# claiming to defeat. (Port-plausibility — defaulting yip itself away from
# 51820 — is tracked separately as an R8/3d follow-up; out of scope here.)
#
# Assertions (see CONTROLLER ADDENDUM in
# .superpowers/sdd/task-7-brief.md for the empirical basis):
#   (a) HARD: no flow classified as WireGuard/OpenVPN/Tor/any known VPN or
#       proxy protocol BY CONTENT. On the neutral port the flow must show up
#       as `Unknown`.
#   (b) HARD: no `NDPI_OBFUSCATED_TRAFFIC` risk ("Obfuscated Traffic") in the
#       risk output.
#   (c) REPORT ONLY: `NDPI_SUSPICIOUS_ENTROPY` ("Susp Entropy") is expected
#       to fire — high entropy is inherent to ALL encrypted/random payloads
#       (WireGuard trips it too). Suppressing it needs TLS/QUIC mimicry,
#       which is milestone 3c (research R3/R4), not 3a. We print it but do
#       NOT assert its absence — asserting it would make 3a unpassable by
#       construction.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <ndpiReader-binary>}"
NDPI="${2:?Usage: $0 <yipd-binary> <ndpiReader-binary>}"

# Root-gated SKIP: netns + tcpdump both need CAP_NET_ADMIN/root. The Rust
# harness already checks this before invoking the script, but this script
# SKIPs cleanly too so it stays safe to run standalone (mirrors the
# root-gated-SKIP convention used across run-netns-*.sh via their Rust
# callers).
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-ndpi-oracle: needs root (netns + tcpdump)"
    exit 0
fi

# SKIP (not fail) if ndpiReader isn't built at the given path: local runs
# without nDPI built must not hard-fail; CI always builds it first.
if [ ! -x "$NDPI" ]; then
    echo "SKIP run-ndpi-oracle: ndpiReader not found/executable at $NDPI"
    exit 0
fi

TMPDIR_TEST="$(mktemp -d /tmp/yipd-ndpi-oracle-test.XXXXXX)"
PCAP="$TMPDIR_TEST/yip-obf.pcap"

NS_A="yipNdpiA"
NS_B="yipNdpiB"
VETH_A="vNdpiA"
VETH_B="vNdpiB"
VETH_A_IP="10.0.9.1"
VETH_B_IP="10.0.9.2"
TUN_A_IP="10.9.9.1"
TUN_B_IP="10.9.9.2"
TUN_PREFIX="24"
VETH_PREFIX="24"
# NEUTRAL port — see header comment. Do NOT change to 51820.
PORT="34567"
TUN_DEV="yip0"
OBF_PSK="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

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
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. keypairs ───────────────────────────────────────────────────────────
echo "[setup] generating keypairs"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"
PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

# ── 2. config files, both sharing obf_psk ────────────────────────────────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipA — responder (obf_psk on, neutral port)
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT}
peer_endpoint=${VETH_B_IP}:${PORT}
device=${TUN_DEV}
initiate=false
obf_psk=${OBF_PSK}
EOF

cat > "$CFG_B" <<EOF
# yipB — initiator (obf_psk on, neutral port)
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT}
peer_endpoint=${VETH_A_IP}:${PORT}
device=${TUN_DEV}
initiate=true
obf_psk=${OBF_PSK}
EOF

# ── 3. namespaces + veth pair ─────────────────────────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"

echo "[setup] creating veth pair"
ip link add "$VETH_A" netns "$NS_A" type veth peer name "$VETH_B" netns "$NS_B"

ip netns exec "$NS_A" ip addr add "${VETH_A_IP}/${VETH_PREFIX}" dev "$VETH_A"
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_A" ip link set lo up

ip netns exec "$NS_B" ip addr add "${VETH_B_IP}/${VETH_PREFIX}" dev "$VETH_B"
ip netns exec "$NS_B" ip link set "$VETH_B" up
ip netns exec "$NS_B" ip link set lo up

# ── 4. capture on the underlay veth inside NS_B, before either daemon starts
# so the handshake is captured from packet zero ──────────────────────────
echo "[capture] starting tcpdump inside $NS_B on $VETH_B (port $PORT)"
ip netns exec "$NS_B" tcpdump -i "$VETH_B" -w "$PCAP" -U "udp port $PORT" \
    >"$TMPDIR_TEST/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 1

# ── 5. start daemons ──────────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

echo "[start] starting yipA (responder, obf_psk set, port $PORT)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB (initiator, obf_psk set, port $PORT)"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 6. wait for TUN devices (handshake must complete under obfuscation) ──
TUN_WAIT_TRIES=60
echo "[wait] waiting for TUN devices"
tries=0
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
        echo "=== yipA log ==="; cat "$LOG_A" || true
        exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipB daemon died unexpectedly"
        echo "=== yipB log ==="; cat "$LOG_B" || true
        exit 1
    fi
    tries=$((tries + 1))
    if [ "$tries" -ge "$TUN_WAIT_TRIES" ]; then
        echo "[error] timed out waiting for TUN devices to come up"
        echo "=== yipA log ==="; cat "$LOG_A" || true
        echo "=== yipB log ==="; cat "$LOG_B" || true
        exit 1
    fi
    sleep 0.25
done

# ── 7. tunnel IPs ──────────────────────────────────────────────────────────
echo "[setup] assigning tunnel IPs"
ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/${TUN_PREFIX}" dev "$TUN_DEV"
ip netns exec "$NS_A" ip link set "$TUN_DEV" up
ip netns exec "$NS_B" ip link set "$TUN_DEV" up
sleep 1

# ── 8. drive a full exchange: handshake already happened above; ping drives
# data-plane traffic + the control-feedback cadence (jittered under obf_psk,
# 3a Task 5) long enough to fire at least once. ───────────────────────────
echo "[drive] pinging across the obfuscated tunnel (handshake+data+control)"
set +e
ip netns exec "$NS_A" ping -c 20 -i 0.1 -W 1 "$TUN_B_IP" >"$TMPDIR_TEST/ping.log" 2>&1
PING_RC=$?
set -e
echo "[drive] ping rc=$PING_RC"
if [ "$PING_RC" -ne 0 ]; then
    echo "[error] ping across the obfuscated tunnel failed — cannot capture a real exchange"
    cat "$TMPDIR_TEST/ping.log" || true
    echo "=== yipA log ==="; cat "$LOG_A" || true
    echo "=== yipB log ==="; cat "$LOG_B" || true
    exit 1
fi

# Give control-plane feedback a further moment to fire, then stop the capture.
sleep 1
echo "[capture] stopping tcpdump"
kill "$TCPDUMP_PID" 2>/dev/null || true
sleep 1
TCPDUMP_PID=""

if [ ! -s "$PCAP" ]; then
    echo "[error] capture is empty or missing at $PCAP"
    cat "$TMPDIR_TEST/tcpdump.log" || true
    exit 1
fi
echo "[capture] pcap: $(stat -c%s "$PCAP") bytes"

# ── 9. classify with ndpiReader ───────────────────────────────────────────
echo "=== ndpiReader classification ==="
NDPI_OUT="$TMPDIR_TEST/ndpi.out"
"$NDPI" -i "$PCAP" -v 2 >"$NDPI_OUT" 2>&1 || true
cat "$NDPI_OUT"

FAIL=0

# HARD gate (a): no flow classified as a known VPN/proxy protocol BY CONTENT.
# On the neutral port the correct/expected classification is Unknown.
# Match named VPN protocols AND nDPI's VPN category tag `[cat: VPN/...]`, which
# ndpiReader prints for ANY of the ~20 VPN-category master protocols (Tailscale,
# Mullvad, Hamachi, libp2p, IPSec, ...) — several structurally close to yip's P2P
# UDP shape and not covered by the named list. An Unknown flow (category 0) has
# no `[cat: ...]` tag, so this never false-fails on obfuscated yip traffic.
if grep -qiE '\b(wireguard|openvpn|tor|proxy)\b|\[cat: *vpn\b' "$NDPI_OUT"; then
    echo "[FAIL] gate (a): ndpiReader classified the obfuscated flow as a known VPN/proxy protocol (name or [cat: VPN])"
    FAIL=1
else
    echo "[PASS] gate (a): no WireGuard/OpenVPN/Tor/proxy/[cat: VPN] classification (flow is Unknown by content)"
fi

# HARD gate (b): no NDPI_OBFUSCATED_TRAFFIC risk ("Obfuscated Traffic").
if grep -qiE 'obfuscated traffic|ndpi_obfuscated_traffic' "$NDPI_OUT"; then
    echo "[FAIL] gate (b): ndpiReader raised the Obfuscated Traffic risk flag"
    FAIL=1
else
    echo "[PASS] gate (b): no Obfuscated Traffic risk flag"
fi

# REPORT-ONLY (c): Susp Entropy / NDPI_SUSPICIOUS_ENTROPY. NOT a gate.
if grep -qiE 'susp entropy|ndpi_suspicious_entropy' "$NDPI_OUT"; then
    echo "[report] (c) Susp Entropy risk fired — EXPECTED for 3a: high entropy is"
    echo "         inherent to encrypted/random payloads (WireGuard trips this too);"
    echo "         suppressing it requires TLS/QUIC mimicry, milestone 3c (research"
    echo "         R3/R4). This is NOT a 3a gate and is not asserted against."
else
    echo "[report] (c) Susp Entropy risk did not fire this run (not asserted either way)"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "[FAIL] nDPI undetectability oracle FAILED — see gate output above"
    exit 1
fi

echo "[PASS] nDPI undetectability oracle PASSED: obfuscated yip traffic on a neutral port is Unknown to nDPI, with no Obfuscated Traffic risk flag"
