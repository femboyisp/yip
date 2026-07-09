#!/usr/bin/env bash
# nDPI QUIC-classification oracle for yip's QUIC mimicry transport (3c.1
# Task 7). This is the headline flip that 3a/3b could not achieve: instead
# of merely being `Unknown` to nDPI (3a's win — see run-ndpi-oracle.sh), a
# `transport=quic` yip flow is POSITIVELY classified as QUIC, with the
# `NDPI_SUSPICIOUS_ENTROPY` risk that dogged 3a/3b now suppressed too,
# because the flow genuinely IS a real QUIC/TLS1.3 handshake wrapping the
# yip Noise-IK inner handshake (see bin/yipd/src/quic.rs: real quinn-proto
# QUIC, ALPN `h3`, client SNI `www.cloudflare.com`).
#
# Usage: run-quic-mimicry-oracle.sh <path-to-yipd-binary> <path-to-ndpiReader-binary>
#
# Setup mirrors run-netns-quic.sh (transport=quic, NO obf_psk — mutually
# exclusive with transport=quic per config.rs) for the netns/veth/config
# plumbing, and run-ndpi-oracle.sh for the tcpdump-then-ndpiReader capture
# harness.
#
# NEUTRAL port (34567, not 443, not 51820): matches run-ndpi-oracle.sh's
# reasoning — this must be a content classification, not a port-based one.
# nDPI recognizes real QUIC/TLS1.3 handshakes by their wire bytes (ClientHello
# extensions, QUIC long-header version, ALPN) regardless of port, so a
# neutral port proves the win is genuine and not port-assisted. The
# consequence of NOT running on 443 is a single MEDIUM risk,
# `NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT` ("Known Proto on Non Std Port")
# — that is the R8 port-plausibility concern explicitly deferred to milestone
# 3d (defaulting yip's real listen port to 443), NOT an entropy/obfuscation
# regression, and this oracle deliberately does not fail on it (see gate (c)
# below).
#
# Assertions (see CONTROLLER ADDENDUM in .superpowers/sdd/task-7-brief.md for
# the empirically verified baseline this asserts against):
#   (a) HARD: the flow IS classified as QUIC — the `[proto: .../QUIC...]`
#       and/or `[Stack: QUIC...]` fields in `ndpiReader -v 2` output contain
#       "QUIC" (case-insensitive), positively — NOT `Unknown`. This is the
#       proof of the mimicry win itself.
#   (b) HARD: NO `Susp Entropy` / `NDPI_SUSPICIOUS_ENTROPY` risk fires. This
#       is the concrete proof 3c beats the entropy heuristic that 3a/3b could
#       only report on, never suppress (see run-ndpi-oracle.sh gate (c)).
#   (c) REPORT ONLY, not gated: `Known Proto on Non Std Port` is EXPECTED on
#       the neutral port and is the R8/3d port-plausibility follow-up, not an
#       obfuscation regression — printed for visibility, never asserted.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <ndpiReader-binary>}"
NDPI="${2:?Usage: $0 <yipd-binary> <ndpiReader-binary>}"

# Root-gated SKIP: netns + tcpdump both need CAP_NET_ADMIN/root. The Rust
# harness already checks this before invoking the script, but this script
# SKIPs cleanly too so it stays safe to run standalone.
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-quic-mimicry-oracle: needs root (netns + tcpdump)"
    exit 0
fi

# SKIP (not fail) if ndpiReader isn't built at the given path: local runs
# without nDPI built must not hard-fail; CI always builds it first.
if [ ! -x "$NDPI" ]; then
    echo "SKIP run-quic-mimicry-oracle: ndpiReader not found/executable at $NDPI"
    exit 0
fi

TMPDIR_TEST="$(mktemp -d /tmp/yipd-quic-mimicry-oracle-test.XXXXXX)"
PCAP="$TMPDIR_TEST/yip-quic.pcap"

NS_A="yipQdpiA"
NS_B="yipQdpiB"
VETH_A="vQdpiA"
VETH_B="vQdpiB"
VETH_A_IP="10.0.10.1"
VETH_B_IP="10.0.10.2"
TUN_A_IP="10.10.10.1"
TUN_B_IP="10.10.10.2"
TUN_PREFIX="24"
VETH_PREFIX="24"
# NEUTRAL port — see header comment. Do NOT change to 443 or 51820.
PORT="34567"
TUN_DEV="yip0"

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

# ── 2. config files, transport=quic, NO obf_psk (mutually exclusive) ─────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipA — responder, QUIC transport, neutral port
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT}
peer_endpoint=${VETH_B_IP}:${PORT}
device=${TUN_DEV}
initiate=false
transport=quic
EOF

cat > "$CFG_B" <<EOF
# yipB — initiator, QUIC transport, neutral port
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT}
peer_endpoint=${VETH_A_IP}:${PORT}
device=${TUN_DEV}
initiate=true
transport=quic
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
# so both the outer QUIC handshake and the inner yip Noise-IK handshake (which
# rides QUIC DATAGRAM frames) are captured from packet zero ─────────────────
echo "[capture] starting tcpdump inside $NS_B on $VETH_B (port $PORT)"
ip netns exec "$NS_B" tcpdump -i "$VETH_B" -w "$PCAP" -U "udp port $PORT" \
    >"$TMPDIR_TEST/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 1

# ── 5. start daemons ──────────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

echo "[start] starting yipA (responder, transport=quic, port $PORT)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB (initiator, transport=quic, port $PORT)"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 6. wait for TUN devices (TUN creation is not gated on the two-layer
# handshake — see run-netns-quic.sh — so this budget matches that test) ────
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

# ── 8. drive a full exchange: outer QUIC handshake, inner yip Noise-IK
# handshake (over QUIC DATAGRAM frames), then data — generous budget since
# it's a two-layer bring-up (mirrors run-netns-quic.sh: ping -c 30 -W 2) ───
echo "[drive] pinging across the QUIC-mimicry tunnel (handshake+data)"
set +e
ip netns exec "$NS_B" ping -c 30 -W 2 "$TUN_A_IP" >"$TMPDIR_TEST/ping.log" 2>&1
PING_RC=$?
set -e
echo "[drive] ping rc=$PING_RC"
if [ "$PING_RC" -ne 0 ]; then
    echo "[error] ping across the QUIC-mimicry tunnel failed — cannot capture a real exchange"
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

# HARD gate (a): the flow IS classified as QUIC. ndpiReader (-v 2) prints a
# per-flow line of the form
#   [proto: 188.220/QUIC.Cloudflare][Stack: QUIC.Cloudflare][IP: ...]
# (see example/ndpiReader.c's per-flow `fprintf(out, "[proto: ...][Stack: ...")`
# formatting). Matching "QUIC" inside either the `[proto: N.M/<name>]` or
# `[Stack: <name>]` bracket is a positive, content-based classification —
# an `Unknown` flow has neither bracket contain "QUIC" (it prints
# `[proto: 0/Unknown]`), so this also naturally fails on Unknown without a
# separate negative check.
if grep -qiE '\[proto: [0-9]+\.[0-9]+/[^]]*quic[^]]*\]|\[stack: [^]]*quic[^]]*\]' "$NDPI_OUT"; then
    echo "[PASS] gate (a): flow positively classified as QUIC"
else
    echo "[FAIL] gate (a): ndpiReader did NOT classify the flow as QUIC (expected [proto: .../QUIC...] or [Stack: QUIC...])"
    FAIL=1
fi

# HARD gate (b): NO Susp Entropy / NDPI_SUSPICIOUS_ENTROPY risk. This is the
# concrete proof 3c defeats the entropy heuristic that 3a/3b could only
# report on (run-ndpi-oracle.sh gate (c)) — ndpi_risk2str(NDPI_SUSPICIOUS_ENTROPY)
# == "Susp Entropy" (src/lib/ndpi_utils.c), printed via `** %s **` per-risk
# and in the summary risk table.
if grep -qiE 'susp entropy|ndpi_suspicious_entropy' "$NDPI_OUT"; then
    echo "[FAIL] gate (b): ndpiReader raised the Susp Entropy risk flag — QUIC mimicry did not suppress it"
    FAIL=1
else
    echo "[PASS] gate (b): no Susp Entropy / NDPI_SUSPICIOUS_ENTROPY risk flag"
fi

# REPORT-ONLY (c): Known Proto on Non Std Port. NOT a gate — this is the R8
# port-plausibility concern (yip's default port isn't 443), explicitly
# deferred to milestone 3d, not an entropy/obfuscation regression. ndpi_risk2str
# (NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT) == "Known Proto on Non Std Port".
if grep -qiE 'known proto on non std port|ndpi_known_protocol_on_non_standard_port' "$NDPI_OUT"; then
    echo "[report] (c) Known Proto on Non Std Port risk fired — EXPECTED on the neutral"
    echo "         non-443 test port; this is the R8 port-plausibility follow-up tracked"
    echo "         for milestone 3d (defaulting yip to port 443), NOT a 3c gate."
else
    echo "[report] (c) Known Proto on Non Std Port risk did not fire this run (not asserted either way)"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "[FAIL] nDPI QUIC-classification oracle FAILED — see gate output above"
    exit 1
fi

echo "[PASS] nDPI QUIC-classification oracle PASSED: yip-over-QUIC traffic on a neutral port is classified as QUIC by content, with no Susp Entropy risk"
