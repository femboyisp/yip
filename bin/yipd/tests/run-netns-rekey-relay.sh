#!/usr/bin/env bash
# The rekey.91 Task 4 money test: relay-FORCED peers (no direct/punch path
# possible, per run-netns-relay.sh's topology) held to a FAST
# YIP_REKEY_INTERVAL_MS=2000 rekey cadence (~10 rotations over a ~20s ping
# stream) must (1) actually carry their traffic over the blind relay (not a
# direct/punched path) and (2) never black-hole the relayed session across a
# rotation (loss-free continuity) and (3) really rotate the wire session
# per epoch, proven on the wire — not just asserted from source.
#
# Usage: run-netns-rekey-relay.sh <path-to-yipd-binary> <path-to-yip-rendezvous-binary>
#
# Forked from two siblings:
#   - run-netns-relay.sh: the RELAY-FORCED topology (three netns A/B/R; two
#     point-to-point veth pairs A<->R, B<->R; no shared bridge; R does NOT
#     forward IPv4, so A and B are mutually unreachable and can only ever
#     reach each other via R's blind relay). Peers list each other by
#     public_key only (no endpoint) + rendezvous=<R's address>.
#   - run-netns-rekey.sh: the fast YIP_REKEY_INTERVAL_MS=2000 cadence, the
#     ping -i 0.2 -c 100 loss-continuity assertion, and the
#     rekey_epoch_witness on-wire distinct-rounds proof.
#
# ── why a warm-up ping precedes the measured/captured one ──
# run-netns-relay.sh's own money test documents ~PUNCH_MS (5s) of
# unavoidable warm-up loss while each peer's path state machine escalates
# from a silently-dropped direct punch to the blind relay. The measured
# ping below has only a 1% loss budget (matching the 9a direct-path
# script), which that 5s of warm-up would blow on its own — so this script
# runs a generous, ungated warm-up ping first (tolerating exactly the same
# escalation loss run-netns-relay.sh does) to force the relay session up,
# and only starts the tcpdump capture + tight-budget measured ping once a
# relayed session is already flowing.
#
# ── proving on-wire rekey rounds through the relay envelope ──
# On this topology, `PeerManager::relay_wrap` wraps every relay-routed
# [HandshakeInit]/[HandshakeResp] in a `yip_rendezvous::Message::RelaySend`
# (client -> server, tag=5) or `RelayDeliver` (server -> client, tag=6)
# envelope (crates/yip-rendezvous/src/proto.rs) -- the bare
# [PacketType][ephemeral] prefix `rekey_epoch_witness` looks for is not at
# offset 0 anymore. This script uses option (a) from the task-4 brief: the
# witness tool itself grew an opt-in `YIP_WITNESS_UNWRAP_RELAY=1` mode
# (bin/yipd/examples/rekey_epoch_witness.rs) that strips the envelope
# (RelaySend -> inner at offset 33, RelayDeliver -> inner at offset 17)
# before applying its existing distinct-cleartext-ephemeral logic. The 9a
# direct-path run-netns-rekey.sh never sets that env var, so its behavior
# is unchanged.
#
# The pcap is captured on A's own veth into R (VETH_A_N, inside NS_A) --
# since A and B are the only two mesh peers, every relayed datagram either
# originates at A (RelaySend) or is addressed to A (RelayDeliver), so this
# single capture point sees the full relayed Init/Resp traffic in both
# directions, exactly as run-netns-rekey.sh's single veth capture does for
# the direct path.
#
# Assertions (any failure is non-zero exit, [PASS]/[FAIL] markers):
#   1. relay_forwarded: R's stderr shows `relay-forwarded=<N>`, N>0 --
#      the blind relay, not a direct/punched path, carried the traffic.
#   2. rekey_continuity: ping -i 0.2 -c 100 A->B over the relay, <=1% loss
#      across ~10 rotations -- a rotation that black-holed the relayed
#      session would drop many.
#   3. rekey rotation: rekey_epoch_witness (YIP_WITNESS_UNWRAP_RELAY=1)
#      reports COMPLETED_ROUNDS >= 3 distinct completed Noise-IK rounds
#      unwrapped from the relay envelope.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
RDV="${2:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
WITNESS_BIN="$(dirname "$YIPD")/examples/rekey_epoch_witness"

# ── 0. root + tool preflight (invoked directly by CI, not through the
# tunnel_netns.rs Rust harness, so it does its own SKIP-gating per the
# run-netns-rekey.sh / run-netns-relay-tls.sh convention) ──
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-netns-rekey-relay: needs root (netns + TUN + tcpdump)"
    exit 0
fi
for tool in tcpdump ping; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP run-netns-rekey-relay: required tool '$tool' not found"
        exit 0
    fi
done
if [ ! -x "$WITNESS_BIN" ]; then
    echo "SKIP run-netns-rekey-relay: rekey_epoch_witness not built at $WITNESS_BIN"
    echo "  build it with: cargo build --release -p yipd --example rekey_epoch_witness"
    exit 0
fi

TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-rekey-relay-test.XXXXXX)"

NS_A="yipRkRelA"
NS_B="yipRkRelB"
NS_R="yipRkRelR"

VETH_A_N="vRkRelA1"; VETH_A_R="vRkRelA0"   # A<->R pair: A-side, R-side
VETH_B_N="vRkRelB1"; VETH_B_R="vRkRelB0"   # B<->R pair: B-side, R-side

IP_A="10.72.0.2"
IP_R_A="10.72.0.1"   # R's address on A's subnet
IP_B="10.73.0.2"
IP_R_B="10.73.0.1"   # R's address on B's subnet
PREFIX="24"

PORT_A="51820"
PORT_B="51820"
RDV_PORT="51821"
TUN_DEV="yip0"

PID_A=""
PID_B=""
PID_RDV=""
TCPDUMP_PID=""

cleanup() {
    echo "[cleanup] killing daemons/tcpdump, removing namespaces"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill "$PID_RDV" 2>/dev/null || true
    [ -n "$TCPDUMP_PID" ] && kill "$TCPDUMP_PID" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill -9 "$PID_RDV" 2>/dev/null || true
    [ -n "$TCPDUMP_PID" ] && kill -9 "$TCPDUMP_PID" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip netns del "$NS_R" 2>/dev/null || true
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

ADDR_A="$("$YIPD" --addr "$PUB_A")"
ADDR_B="$("$YIPD" --addr "$PUB_B")"
echo "[setup] node_addr A=$ADDR_A B=$ADDR_B"

# ── 2. write config files (rendezvous-only peers: public_key, no endpoint) ────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipRkRelA
local_private=${PRIV_A}
local_public=${PUB_A}
listen=${IP_A}:${PORT_A}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_R_A}:${RDV_PORT}
[peer]
public_key=${PUB_B}
EOF

cat > "$CFG_B" <<EOF
# yipRkRelB
local_private=${PRIV_B}
local_public=${PUB_B}
listen=${IP_B}:${PORT_B}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_R_B}:${RDV_PORT}
[peer]
public_key=${PUB_A}
EOF

# ── 3. create namespaces + point-to-point veths into R ────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"
ip netns add "$NS_R"

echo "[setup] wiring A<->R"
ip link add "$VETH_A_R" type veth peer name "$VETH_A_N"
ip link set "$VETH_A_N" netns "$NS_A"
ip link set "$VETH_A_R" netns "$NS_R"
ip netns exec "$NS_A" ip addr add "${IP_A}/${PREFIX}" dev "$VETH_A_N"
ip netns exec "$NS_A" ip link set "$VETH_A_N" up
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_R" ip addr add "${IP_R_A}/${PREFIX}" dev "$VETH_A_R"
ip netns exec "$NS_R" ip link set "$VETH_A_R" up

echo "[setup] wiring B<->R"
ip link add "$VETH_B_R" type veth peer name "$VETH_B_N"
ip link set "$VETH_B_N" netns "$NS_B"
ip link set "$VETH_B_R" netns "$NS_R"
ip netns exec "$NS_B" ip addr add "${IP_B}/${PREFIX}" dev "$VETH_B_N"
ip netns exec "$NS_B" ip link set "$VETH_B_N" up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_R" ip addr add "${IP_R_B}/${PREFIX}" dev "$VETH_B_R"
ip netns exec "$NS_R" ip link set "$VETH_B_R" up
ip netns exec "$NS_R" ip link set lo up

# A's and B's only route beyond their own /24 is via R -- and R does NOT
# forward, so a cross-subnet packet dies silently at R (see
# run-netns-relay.sh's header comment for the full reasoning: this keeps
# the punch attempt a normal, silently-dropped packet rather than a
# synchronous socket error that would kill yipd's event loop).
ip netns exec "$NS_A" ip route add default via "$IP_R_A" dev "$VETH_A_N"
ip netns exec "$NS_B" ip route add default via "$IP_R_B" dev "$VETH_B_N"

# Explicitly disable IPv4 forwarding in R (belt-and-suspenders: a fresh
# netns already defaults to this, but the isolation invariant this whole
# test rests on deserves to be asserted, not assumed).
ip netns exec "$NS_R" sysctl -q -w net.ipv4.ip_forward=0
ip netns exec "$NS_R" sysctl -q -w net.ipv4.conf.all.forwarding=0

# ── 4. start yip-rendezvous in R, bound on both subnets ───────────────────────
LOG_RDV="$TMPDIR_TEST/rdv.log"
echo "[start] starting yip-rendezvous in R on 0.0.0.0:${RDV_PORT}"
ip netns exec "$NS_R" "$RDV" "0.0.0.0:${RDV_PORT}" >"$LOG_RDV" 2>&1 &
PID_RDV=$!
sleep 0.3

# ── 5. start yipd in A and B with a fast rekey cadence ────────────────────────
# YIP_REKEY_INTERVAL_MS=2000 (vs. the 120_000 production default) so ~10
# rotations happen over the ~20s measured ping stream below. `ip netns
# exec` (unlike `sudo`) does not clear the environment, so this and any
# caller-set YIP_USE_URING both flow through to the daemons unmodified --
# run this script itself as `sudo YIP_USE_URING=1 bash
# run-netns-rekey-relay.sh <yipd> <yip-rendezvous>` to exercise the uring
# driver.
export YIP_REKEY_INTERVAL_MS=2000

LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

dump_logs() {
    echo "=== rendezvous log ==="
    cat "$LOG_RDV" || true
    echo "=== yipRkRelA log ==="
    cat "$LOG_A" || true
    echo "=== yipRkRelB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipRkRelA with YIP_REKEY_INTERVAL_MS=$YIP_REKEY_INTERVAL_MS"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipRkRelB with YIP_REKEY_INTERVAL_MS=$YIP_REKEY_INTERVAL_MS"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 6. wait for TUN devices to appear in A and B ──────────────────────────────
TUN_WAIT=20
INTERVAL=0.25

echo "[wait] waiting for TUN devices to appear (up to ${TUN_WAIT}s)"
elapsed=0
while true; do
    A_UP=0; B_UP=0
    ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true

    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ]; then
        echo "[wait] both TUN devices are up"
        break
    fi

    if ! kill -0 "$PID_A" 2>/dev/null; then
        echo "[error] yipRkRelA daemon died unexpectedly"; dump_logs; exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipRkRelB daemon died unexpectedly"; dump_logs; exit 1
    fi
    if ! kill -0 "$PID_RDV" 2>/dev/null; then
        echo "[error] yip-rendezvous died unexpectedly"; dump_logs; exit 1
    fi

    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] timed out waiting for TUN devices"; dump_logs; exit 1
    fi
    sleep "$INTERVAL"
done

# ── 7. assign each TUN its node_addr/128 + the mesh-prefix route ─────────────
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

# ── 8. warm-up ping: absorb the punch->escalate->relay-handshake loss ───────
# Same tolerance as run-netns-relay.sh's own money test (ungated, generous
# count/timeout) -- this just gets a relayed session flowing before the
# tight-budget measured ping + capture below start.
echo "[warmup] pinging ${ADDR_B} from yipRkRelA (expect escalate-to-relay warm-up loss, then success)"
set +e
ip netns exec "$NS_A" ping -6 -c 20 -W 2 "$ADDR_B"
WARMUP_STATUS=$?
set -e
if [ "$WARMUP_STATUS" -ne 0 ]; then
    echo "[FAIL] warm-up ping A->B did not succeed (exit $WARMUP_STATUS) -- relay path never came up"
    dump_logs
    exit 1
fi
echo "[PASS] warm-up ping A->B succeeded -- relayed session is up"

# ── 9. capture A's veth into R while a steady ping stream crosses ~10 rotations
# Every relayed datagram either originates at A (RelaySend) or is addressed
# to A (RelayDeliver) -- A and B are the only two mesh peers -- so this
# single capture point sees the full relayed Init/Resp traffic.
PCAP="$TMPDIR_TEST/rekey-relay.pcap"
PING_LOG="$TMPDIR_TEST/ping.log"

echo "[capture] starting tcpdump on $VETH_A_N (udp) -> $PCAP"
ip netns exec "$NS_A" tcpdump -i "$VETH_A_N" -w "$PCAP" -U udp \
    >"$TMPDIR_TEST/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 0.3

echo "[test] ping -i 0.2 -c 100 (~20s, ~10 rotations at 2000ms) yipRkRelA -> ${ADDR_B} over the relay"
set +e
ip netns exec "$NS_A" ping -6 -i 0.2 -c 100 -W 1 "$ADDR_B" >"$PING_LOG" 2>&1
PING_STATUS=$?
set -e
cat "$PING_LOG"

sleep 0.5
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""

if ! kill -0 "$PID_A" 2>/dev/null; then
    echo "[error] yipRkRelA daemon died during the ping stream"
    echo "=== yipRkRelA log ==="; cat "$LOG_A" || true
    exit 1
fi
if ! kill -0 "$PID_B" 2>/dev/null; then
    echo "[error] yipRkRelB daemon died during the ping stream"
    echo "=== yipRkRelB log ==="; cat "$LOG_B" || true
    exit 1
fi

# ── assertion 1: relay carried the traffic -- relay-forwarded=<N>, N>0 ──────
# One more sweep interval so R's final line reflects the traffic that just
# flowed (same convention as run-netns-relay.sh's money test).
sleep 5.5
FINAL_COUNT="$(grep -oE 'relay-forwarded=[0-9]+' "$LOG_RDV" | tail -1 | cut -d= -f2)"
echo "[check] server's final relay-forwarded count: ${FINAL_COUNT:-<none>}"
if [ -z "${FINAL_COUNT:-}" ] || [ "$FINAL_COUNT" -eq 0 ]; then
    echo "[FAIL] relay-forwarded count is 0 (or missing) — traffic did not go through the relay"
    dump_logs
    exit 1
fi
echo "[PASS] relay-forwarded=${FINAL_COUNT} (>0): the blind relay carried the traffic"

# ── assertion 2: rekey_continuity — ≤1% loss across ~10 relayed rotations ───
LOSS_PCT="$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' "$PING_LOG" | grep -oE '^[0-9]+(\.[0-9]+)?' || true)"
if [ -z "$LOSS_PCT" ]; then
    echo "[FAIL] rekey_continuity: could not parse packet loss from ping output"
    exit 1
fi
echo "[metric] rekey_continuity: packet loss = ${LOSS_PCT}%"
if awk "BEGIN {exit ($LOSS_PCT <= 1.0) ? 0 : 1}"; then
    echo "[PASS] rekey_continuity: ${LOSS_PCT}% loss (<=1%) across the relayed rekey stream"
else
    echo "[FAIL] rekey_continuity: ${LOSS_PCT}% loss (>1%) — a rotation likely black-holed the relayed session"
    dump_logs
    exit 1
fi
if [ "$PING_STATUS" -ne 0 ] && [ "$LOSS_PCT" != "100" ]; then
    echo "[note] ping exited $PING_STATUS despite <=1% loss (non-fatal; proceeding)"
fi

if [ ! -s "$PCAP" ]; then
    echo "[FAIL] rekey rotation: capture is empty or missing at $PCAP"
    exit 1
fi

# ── assertion 3: rekey rotation — distinct completed Noise-IK rounds,
# unwrapped from the RelaySend/RelayDeliver envelope (YIP_WITNESS_UNWRAP_RELAY=1;
# see rekey_epoch_witness.rs's module doc for the offsets and why this is
# opt-in) ──
WITNESS_LOG="$TMPDIR_TEST/witness.log"
YIP_WITNESS_UNWRAP_RELAY=1 "$WITNESS_BIN" "$PCAP" >"$WITNESS_LOG"
cat "$WITNESS_LOG"

COMPLETED_ROUNDS="$(grep -oE '^COMPLETED_ROUNDS=[0-9]+' "$WITNESS_LOG" | cut -d= -f2)"

if [ -z "$COMPLETED_ROUNDS" ]; then
    echo "[FAIL] rekey rotation: could not parse rekey_epoch_witness output"
    exit 1
fi

# Threshold: a 20s run at a 2000ms interval predicts ~10 rekey rounds;
# require >=3 completed rounds (well below the expected ~10, so rekey
# backoff/jitter cannot make this flaky) -- same threshold as the 9a
# direct-path script.
if [ "$COMPLETED_ROUNDS" -ge 3 ]; then
    echo "[PASS] rekey rotation: $COMPLETED_ROUNDS distinct completed rekey rounds observed over the relay"
else
    echo "[FAIL] rekey rotation: only $COMPLETED_ROUNDS distinct completed rounds (need >=3) — relay-path rekey is not rotating on the wire as expected"
    dump_logs
    exit 1
fi

echo "[PASS] run-netns-rekey-relay: relay-forwarded traffic + loss-free rotation + on-wire rekey rotation, all over the blind relay"
