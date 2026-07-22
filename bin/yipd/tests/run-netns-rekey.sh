#!/usr/bin/env bash
# The milestone 9a money test: two yipd peers held to a FAST
# YIP_REKEY_INTERVAL_MS=2000 rekey cadence (~10 rotations over a ~20s ping
# stream) must (1) never black-hole the session across a rotation (loss-free
# continuity) and (2) actually rotate the wire `conn_tag` per epoch, proven
# for real -- not just asserted from source.
#
# Usage: run-netns-rekey.sh <path-to-yipd-binary>
#
# Forked from run-netns-tunnel.sh (same netns/veth/config plumbing, same
# PASS/FAIL conventions); the two additions are YIP_REKEY_INTERVAL_MS=2000
# and the conn_tag-rotation proof below.
#
# Obfuscation: deliberately OFF (no obf_psk). With obf on, the masked
# conn_tag rides inside the obf envelope and this script's decode tool
# cannot locate the [HandshakeInit]/[Data] `PacketType` prefixes it needs
# (bin/yipd/src/handshake.rs's "Pre-obfuscation note": those prefixes are
# only fixed/unmasked bytes when obf_psk is unset). obf_psk's own
# obfuscation behavior is covered by the 3a/3c netns suites; this script's
# job is purely the rekey machinery.
#
# ── conn_tag rotation: why this script does NOT just diff raw wire bytes ──
#
# `crates/yip-wire`'s `Codec::frame` XORs the entire 15-byte logical header
# -- including the 8 `conn_tag` bytes -- under a keystream reseeded by each
# individual frame's own auth tag (see also bin/yipd/src/peer_manager.rs's
# "UDP demux: why routing is by source address, not raw conn_tag bytes" doc
# comment, which independently documents the same fact). That means the
# masked bytes at `dg[1..9]` differ on *every* Data datagram, even two
# datagrams of the exact same epoch/conn_tag. A coarse "capture dg[1..9],
# assert more than one distinct value across the run" check is therefore
# true UNCONDITIONALLY: it would read >1 in a single-epoch, zero-rekey run
# too, so it cannot actually distinguish "rotated" from "never rotated".
# This script reports that raw count anyway (RAW_DISTINCT_HEADER_PREFIXES,
# non-gated, informational) to honor the letter of the coarse-check
# request, but the money assertion is the rigorous one below.
#
# A first version of this script instead tried to literally re-derive each
# epoch's real (auth_key, hp_key, conn_tag) by replaying captured
# [HandshakeInit] messages through a fresh responder-role handshake (using
# this test's own generated private keys) and then deframing captured Data
# datagrams under the result. That is cryptographically UNSOUND, not just
# impractical: Noise_IK's responder generates its own fresh random
# ephemeral key while producing message 2, and that ephemeral (never
# transmitted, never recoverable from a passive capture) feeds the
# transcript hash the session keys derive from -- a locally-replayed
# responder computes a different, unrelated session every time. It failed
# 100% of the time in testing, exactly as this predicts. Recovering it is
# Noise's forward-secrecy property working as intended, not a bug.
#
# `bin/yipd/examples/rekey_epoch_witness` (a standalone tool, built
# alongside yipd -- see step 0 below) instead counts DISTINCT CLEARTEXT
# ephemeral public keys: Noise_IK's first message token on both
# [HandshakeInit] and [HandshakeResp] is the sender's ephemeral public key,
# written UNENCRYPTED (there is no cipher key yet when the first token of
# message 1 is written, and message 2's leading token is likewise
# cleartext) -- visible to any passive observer, no key material needed.
# N distinct cleartext ephemerals is a rigorous, on-wire, non-vacuous proof
# of N independently-completed Noise-IK rounds, and since
# `conn_tag = conn_tag_from_keys(derive_wire_keys(channel_binding))` and
# `channel_binding` mixes in both ephemerals' Diffie-Hellman product, N
# distinct ephemeral pairs implies N distinct `conn_tag`s with
# cryptographic-strength probability -- even though (per the paragraph
# above) neither this tool nor a real passive observer can ever learn what
# those N values actually are. See the tool's module doc for the full
# argument.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary>}"
WITNESS_BIN="$(dirname "$YIPD")/examples/rekey_epoch_witness"

# ── 0. root + tool preflight (this script is invoked directly by CI, not
# through the tunnel_netns.rs Rust harness, so it does its own SKIP-gating
# per the run-netns-reality-probe.sh / run-netns-relay-tls.sh convention) ──
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-netns-rekey: needs root (netns + TUN + tcpdump)"
    exit 0
fi
for tool in tcpdump ping; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP run-netns-rekey: required tool '$tool' not found"
        exit 0
    fi
done
if [ ! -x "$WITNESS_BIN" ]; then
    echo "SKIP run-netns-rekey: rekey_epoch_witness not built at $WITNESS_BIN"
    echo "  build it with: cargo build --release -p yipd --example rekey_epoch_witness"
    exit 0
fi

TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-rekey-test.XXXXXX)"

NS_A="yipRekeyA"
NS_B="yipRekeyB"
VETH_A="vRekeyA"
VETH_B="vRekeyB"
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

# ── 1. generate keypairs ──────────────────────────────────────────────────────
echo "[setup] generating keypairs"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"

PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

# ── 2. write config files (obf deliberately OFF -- see header comment) ────────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipA — responder
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VETH_A_IP}:${PORT_A}
peer_endpoint=${VETH_B_IP}:${PORT_B}
device=${TUN_DEV}
initiate=false
EOF

cat > "$CFG_B" <<EOF
# yipB — initiator
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT_B}
peer_endpoint=${VETH_A_IP}:${PORT_A}
device=${TUN_DEV}
initiate=true
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

# ── 4. start daemons with a fast rekey cadence ────────────────────────────────
# YIP_REKEY_INTERVAL_MS=2000 (vs. the 120_000 production default) so ~10
# rotations happen over the ~20s ping stream below. `ip netns exec` (unlike
# `sudo`) does not clear the environment, so this and any caller-set
# YIP_USE_URING both flow through to the daemons unmodified -- run this
# script itself as `sudo YIP_USE_URING=1 bash run-netns-rekey.sh <yipd>` to
# exercise the uring driver.
export YIP_REKEY_INTERVAL_MS=2000

LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

echo "[start] starting yipA (responder) with YIP_REKEY_INTERVAL_MS=$YIP_REKEY_INTERVAL_MS"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipB (initiator) with YIP_REKEY_INTERVAL_MS=$YIP_REKEY_INTERVAL_MS"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 5. wait for handshake and TUN device creation ────────────────────────────
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

sleep 0.5

# ── 7. capture the veth while a steady ping stream crosses ~10 rotations ──────
PCAP="$TMPDIR_TEST/rekey.pcap"
PING_LOG="$TMPDIR_TEST/ping.log"

echo "[capture] starting tcpdump on $VETH_A (udp) -> $PCAP"
ip netns exec "$NS_A" tcpdump -i "$VETH_A" -w "$PCAP" -U udp \
    >"$TMPDIR_TEST/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 0.3

echo "[test] ping -i 0.2 -c 100 (~20s, ~10 rotations at 2000ms) yipB -> ${TUN_A_IP}"
set +e
ip netns exec "$NS_B" ping -i 0.2 -c 100 -W 1 "$TUN_A_IP" >"$PING_LOG" 2>&1
PING_STATUS=$?
set -e
cat "$PING_LOG"

sleep 0.5
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""

if ! kill -0 "$PID_A" 2>/dev/null; then
    echo "[error] yipA daemon died during the ping stream"
    echo "=== yipA log ==="
    cat "$LOG_A" || true
    exit 1
fi
if ! kill -0 "$PID_B" 2>/dev/null; then
    echo "[error] yipB daemon died during the ping stream"
    echo "=== yipB log ==="
    cat "$LOG_B" || true
    exit 1
fi

# ── assertion 1: rekey_continuity — ≤1% loss across ~10 rotations ────────────
LOSS_PCT="$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' "$PING_LOG" | grep -oE '^[0-9]+(\.[0-9]+)?' || true)"
if [ -z "$LOSS_PCT" ]; then
    echo "[FAIL] rekey_continuity: could not parse packet loss from ping output"
    exit 1
fi
echo "[metric] rekey_continuity: packet loss = ${LOSS_PCT}%"
if awk "BEGIN {exit ($LOSS_PCT <= 1.0) ? 0 : 1}"; then
    echo "[PASS] rekey_continuity: ${LOSS_PCT}% loss (<=1%) across the rekey stream"
else
    echo "[FAIL] rekey_continuity: ${LOSS_PCT}% loss (>1%) — a rotation likely black-holed traffic"
    echo "=== yipA log ==="
    cat "$LOG_A" || true
    echo "=== yipB log ==="
    cat "$LOG_B" || true
    exit 1
fi
if [ "$PING_STATUS" -ne 0 ] && [ "$LOSS_PCT" != "100" ]; then
    echo "[note] ping exited $PING_STATUS despite <=1% loss (non-fatal; proceeding)"
fi

if [ ! -s "$PCAP" ]; then
    echo "[FAIL] conn_tag rotation: capture is empty or missing at $PCAP"
    exit 1
fi

# ── assertion 2: conn_tag rotation — distinct completed Noise-IK rounds ──────
WITNESS_LOG="$TMPDIR_TEST/witness.log"
"$WITNESS_BIN" "$PCAP" >"$WITNESS_LOG"
cat "$WITNESS_LOG"

COMPLETED_ROUNDS="$(grep -oE '^COMPLETED_ROUNDS=[0-9]+' "$WITNESS_LOG" | cut -d= -f2)"

if [ -z "$COMPLETED_ROUNDS" ]; then
    echo "[FAIL] conn_tag rotation: could not parse rekey_epoch_witness output"
    exit 1
fi

# Threshold: a 20s run at a 2000ms interval predicts ~10 rekey rounds;
# require >=3 completed rounds (well below the expected ~10, so rekey
# backoff/jitter cannot make this flaky). Each completed round is a
# distinct cleartext-ephemeral Noise-IK handshake that mathematically
# implies a distinct conn_tag on both peers (see the header comment above
# and rekey_epoch_witness's module doc for the full argument).
if [ "$COMPLETED_ROUNDS" -ge 3 ]; then
    echo "[PASS] conn_tag rotation: $COMPLETED_ROUNDS distinct completed rekey rounds observed on the wire"
else
    echo "[FAIL] conn_tag rotation: only $COMPLETED_ROUNDS distinct completed rounds (need >=3) — conn_tag is not rotating on the wire as expected"
    echo "=== yipA log ==="
    cat "$LOG_A" || true
    echo "=== yipB log ==="
    cat "$LOG_B" || true
    exit 1
fi

echo "[PASS] run-netns-rekey: loss-free rotation + on-wire conn_tag rotation both verified"
