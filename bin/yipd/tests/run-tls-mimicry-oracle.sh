#!/usr/bin/env bash
# nDPI TLS-classification oracle for yip's TLS mimicry transport (3c.2 Task 6).
# The TCP sibling of run-quic-mimicry-oracle.sh: instead of merely being
# `Unknown` to nDPI (3a's win), a `transport=tls` yip flow is POSITIVELY
# classified as TLS/HTTPS — a real TLS 1.3 handshake with a browser-parrot
# ClientHello (BoringSSL, GREASE) carrying the yip Noise-IK inner handshake
# (see bin/yipd/src/tls.rs), with the configured SNI and no VPN/entropy risk.
#
# Usage: run-tls-mimicry-oracle.sh <path-to-yipd-binary> <path-to-ndpiReader-binary>
#
# Setup mirrors run-netns-tls.sh (transport=tls, NO obf_psk — mutually
# exclusive) for the netns/veth/config plumbing, and run-quic-mimicry-oracle.sh
# for the tcpdump-then-ndpiReader capture harness (TCP capture here, not UDP).
#
# NEUTRAL port (34567, not 443, not 51820): matches the QUIC oracle's reasoning
# — a content classification, not a port-based one. nDPI recognizes a real
# TLS 1.3 handshake by its ClientHello bytes (SNI, extensions, JA3/JA4)
# regardless of port. The consequence of NOT running on 443 is a single MEDIUM
# risk, `NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT` — the R8 port-plausibility
# concern deferred to milestone 3d (defaulting yip to 443), NOT an
# entropy/obfuscation regression, and this oracle does not fail on it.
#
# Assertions:
#   (a) HARD: the flow IS classified as TLS — "TLS" appears in the `[proto: ...]`
#       or `[Stack: ...]` bracket of `ndpiReader -v 2` output, positively (NOT
#       `Unknown`). Proof of the mimicry win.
#   (b) HARD: the configured SNI (www.apple.com) is extracted from the
#       ClientHello — proof it is a real, parseable TLS handshake with a
#       plausible server name, not a random-looking stream.
#   (c) HARD: NO VPN/proxy classification and NO `NDPI_OBFUSCATED_TRAFFIC`
#       risk (the costume must look like HTTPS, not a tunnel).
#   (d) HARD: NO `Susp Entropy` / `NDPI_SUSPICIOUS_ENTROPY` risk — the concrete
#       proof 3c defeats the entropy heuristic 3a/3b could only report on.
#   (e) REPORT ONLY: the JA3/JA4 fingerprint (printed for visibility / drift
#       tracking) and `Known Proto on Non Std Port` (EXPECTED on the neutral
#       port; the R8/3d follow-up, never asserted).
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <ndpiReader-binary>}"
NDPI="${2:?Usage: $0 <yipd-binary> <ndpiReader-binary>}"

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-tls-mimicry-oracle: needs root (netns + tcpdump)"
    exit 0
fi
if [ ! -x "$NDPI" ]; then
    echo "SKIP run-tls-mimicry-oracle: ndpiReader not found/executable at $NDPI"
    exit 0
fi

TMPDIR_TEST="$(mktemp -d /tmp/yipd-tls-mimicry-oracle-test.XXXXXX)"
PCAP="$TMPDIR_TEST/yip-tls.pcap"

NS_A="yipTdpiA"
NS_B="yipTdpiB"
VETH_A="vTdpiA"
VETH_B="vTdpiB"
VETH_A_IP="10.0.11.1"
VETH_B_IP="10.0.11.2"
TUN_A_IP="10.11.11.1"
TUN_B_IP="10.11.11.2"
TUN_PREFIX="24"
VETH_PREFIX="24"
# NEUTRAL port — see header. Do NOT change to 443 or 51820.
PORT="34567"
TUN_DEV="yip0"
SNI="www.apple.com"

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

# ── 2. config files, transport=tls, NO obf_psk (mutually exclusive) ──────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipA — TLS transport, neutral port
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT}
peer_endpoint=${VETH_B_IP}:${PORT}
device=${TUN_DEV}
initiate=false
transport=tls
tls_sni=${SNI}
EOF

cat > "$CFG_B" <<EOF
# yipB — TLS transport, neutral port
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT}
peer_endpoint=${VETH_A_IP}:${PORT}
device=${TUN_DEV}
initiate=true
transport=tls
tls_sni=${SNI}
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
# so the full TLS handshake (ClientHello onward) is captured from packet zero ─
echo "[capture] starting tcpdump inside $NS_B on $VETH_B (tcp port $PORT)"
ip netns exec "$NS_B" tcpdump -i "$VETH_B" -w "$PCAP" -U "tcp port $PORT" \
    >"$TMPDIR_TEST/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 1

# ── 5. start daemons ──────────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

echo "[start] starting yipA (responder, transport=tls, port $PORT)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB (initiator, transport=tls, port $PORT)"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 6. wait for TUN devices ───────────────────────────────────────────────
TUN_WAIT_TRIES=80
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
ip netns exec "$NS_A" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_A" ip link set "$TUN_DEV" up
ip netns exec "$NS_B" ip link show "$TUN_DEV" | grep -q "UP" || \
    ip netns exec "$NS_B" ip link set "$TUN_DEV" up
sleep 1

# ── 8. drive a full exchange: outer TLS handshake, inner yip Noise-IK, data ─
echo "[drive] pinging across the TLS-mimicry tunnel (handshake+data)"
set +e
ip netns exec "$NS_B" ping -c 30 -W 2 "$TUN_A_IP" >"$TMPDIR_TEST/ping.log" 2>&1
PING_RC=$?
set -e
echo "[drive] ping rc=$PING_RC"
if [ "$PING_RC" -ne 0 ]; then
    echo "[error] ping across the TLS-mimicry tunnel failed — cannot capture a real exchange"
    cat "$TMPDIR_TEST/ping.log" || true
    echo "=== yipA log ==="; cat "$LOG_A" || true
    echo "=== yipB log ==="; cat "$LOG_B" || true
    exit 1
fi

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

# HARD gate (a): the flow IS classified as TLS. A positive, content-based match
# inside the `[proto: N.M/<name>]` or `[Stack: <name>]` bracket; `Unknown` has
# neither, so this also fails on Unknown.
if grep -qiE '\[proto: [0-9]+(\.[0-9]+)?/[^]]*tls[^]]*\]|\[stack: [^]]*tls[^]]*\]' "$NDPI_OUT"; then
    echo "[PASS] gate (a): flow positively classified as TLS"
else
    echo "[FAIL] gate (a): ndpiReader did NOT classify the flow as TLS (expected [proto: .../TLS...] or [Stack: TLS...])"
    FAIL=1
fi

# HARD gate (b): the configured SNI is extracted from the ClientHello.
if grep -qiF "$SNI" "$NDPI_OUT"; then
    echo "[PASS] gate (b): configured SNI ($SNI) extracted from the ClientHello"
else
    echo "[FAIL] gate (b): SNI ($SNI) not found in ndpiReader output — handshake not parsed as real TLS with our SNI"
    FAIL=1
fi

# HARD gate (c): NO VPN/proxy classification and NO Obfuscated Traffic risk.
if grep -qiE 'wireguard|openvpn|\[cat: VPN\]|ndpi_obfuscated_traffic|obfuscated traffic' "$NDPI_OUT"; then
    echo "[FAIL] gate (c): a VPN/proxy classification or Obfuscated Traffic risk fired — the TLS costume is not clean"
    FAIL=1
else
    echo "[PASS] gate (c): no VPN/proxy classification, no Obfuscated Traffic risk"
fi

# HARD gate (d): NO Susp Entropy / NDPI_SUSPICIOUS_ENTROPY risk.
if grep -qiE 'susp entropy|ndpi_suspicious_entropy' "$NDPI_OUT"; then
    echo "[FAIL] gate (d): ndpiReader raised the Susp Entropy risk flag — TLS mimicry did not suppress it"
    FAIL=1
else
    echo "[PASS] gate (d): no Susp Entropy / NDPI_SUSPICIOUS_ENTROPY risk flag"
fi

# REPORT-ONLY (e): JA3/JA4 fingerprint + browser identity + Non Std Port.
# nDPI's own JA4 database tags the client with a browser name (e.g. `[Chrome]`)
# when the fingerprint matches — the headline signal that the parrot is
# convincing. Kept report-only: nDPI's fingerprint DB and the exact JA4 drift
# over time, so hard-gating a specific browser/JA4 string would be brittle. The
# HARD gates above (real TLS + our SNI + no VPN/entropy) are the durable win.
echo "[report] (e) JA3/JA4 fingerprint(s) observed (visibility / drift tracking):"
grep -oiE 'JA[34][SC]?: ?[0-9a-z_]+' "$NDPI_OUT" | sort -u | sed 's/^/         /' || true
BROWSER="$(grep -oiE '\[(Chrome|Firefox|Safari|Edge|Opera)\]' "$NDPI_OUT" | head -1 || true)"
if [ -n "$BROWSER" ]; then
    echo "[report] (e) nDPI's JA4 database identifies the client as: ${BROWSER} — the parrot is convincing"
else
    echo "[report] (e) nDPI did not attach a browser tag this run (JA4 DB drift; not asserted)"
fi
if grep -qiE 'known proto on non std port|ndpi_known_protocol_on_non_standard_port' "$NDPI_OUT"; then
    echo "[report] (e) Known Proto on Non Std Port risk fired — EXPECTED on the neutral"
    echo "         non-443 test port; the R8 port-plausibility follow-up for milestone 3d,"
    echo "         NOT a 3c gate."
else
    echo "[report] (e) Known Proto on Non Std Port risk did not fire this run (not asserted)"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "[FAIL] nDPI TLS-classification oracle FAILED — see gate output above"
    exit 1
fi

echo "[PASS] nDPI TLS-classification oracle PASSED: yip-over-TLS on a neutral port is classified as TLS by content, with the configured SNI and no VPN/entropy risk"
