#!/usr/bin/env bash
# The M2 endpoint-roaming money test: a direct, established, obfuscation-ON
# peer whose SOURCE ADDRESS changes mid-session (a NAT rebind) must keep
# being delivered to — B relearns A's new endpoint from an authenticated,
# non-replayed inbound packet (Task 1, `PeerManager::relearn_endpoint`) and
# deobfuscates A's data arriving from that new source by trialling
# Established peers' session keys (Task 2, `deobf_ingress`'s (a') step).
#
# Usage: run-netns-roaming.sh <path-to-yipd-binary> <path-to-yip-rendezvous-binary>
#
# ── why obfuscation MUST be ON ──
# Under plaintext, a roamed peer's Data already gets found via the
# `handle_data_or_control` fallback loop's raw per-peer decrypt attempts —
# that path predates M2. Under `obf_psk`, the wire bytes are masked and the
# ONLY way to find a roamed peer's session is `deobf_ingress`'s (a') trial
# loop added in Task 2; without it, roamed obfuscated traffic black-holes
# even though the underlying session is perfectly healthy. This script
# therefore hardcodes `obf_psk` on both peers AND on yip-rendezvous
# unconditionally — this is not the optional `[ -n "${OBF_PSK:-}" ]` pattern
# sibling scripts use, because for THIS test obf off would prove nothing.
#
# ── topology (forked from run-netns-punch.sh's A-T-B punch topology) ──
#   A --10.86.0.0/24-- T --10.87.0.0/24-- B
# T forwards between the two client subnets (ip_forward=1 + FORWARD ACCEPT
# both directions, same as run-netns-punch.sh), so A and B establish DIRECTLY
# through T (T is a transparent router here, not a relay) — the punch path
# converges immediately, exactly like run-netns-punch.sh's own money
# assertion (relay-forwarded stays 0), which this script re-checks after the
# rebind too. Unlike run-netns-punch.sh, A's and B's netns do NOT get a local
# MASQUERADE rule: that rule is decorative there (single-homed netns, a
# provable no-op per its own header comment) and would actively interfere
# here, since A's netns becomes dual-addressed for the rebind (MASQUERADE's
# conntrack-based source rewrite would fight the explicit route-`src`
# mechanism below).
#
# ── the rebind mechanic: a real on-wire source-address change, no NAT box ──
# A's yipd binds `listen=0.0.0.0:<port>` (wildcard) rather than a fixed local
# IP. Its UDP socket is unconnected (recvfrom/sendto, addressed per
# datagram — see tunnel.rs's `bind_dataplane_udp` doc comment), so with a
# wildcard bind the kernel selects the OUTBOUND SOURCE ADDRESS for each
# sendto() from the matching route's preferred-source hint, not from any
# fixed socket-level address. A's netns starts with a single address
# (10.86.0.2); mid-session, this script adds a SECOND address (10.86.0.3) to
# A's veth and does `ip route replace default ... src 10.86.0.3` — one
# atomic command that flips every subsequent packet A's yipd sends toward B
# onto the new source address, with A's yipd PROCESS untouched (no restart,
# no re-handshake, no socket rebind) and B's session state for A (keys,
# `conn_tag`) completely unchanged. This is the "change the SNAT mapping /
# bounce A's egress" mechanic the task brief documents, realized without a
# NAT box: T's FORWARD rules key on interface, not source address, and the
# new address is already inside T's connected route for A's /24, so no
# topology change is needed anywhere except inside A's own netns.
#
# Assertions (each a non-zero exit on failure, [PASS]/[FAIL] markers):
#   1. warm-up: ping -6 -c 20 -W 2 A->B succeeds BEFORE any rebind (confirms
#      direct punch convergence; its own warm-up loss is not counted).
#   2. rebind continuity: a SEPARATE measured `ping -i 0.2 -c 100` A->B,
#      started AFTER the warm-up above, with the rebind triggered partway
#      through its run (so the window genuinely spans the transition) —
#      packet loss must be <=1%. This is the money assertion: 1% (1 of 100)
#      is exactly enough budget to absorb the single-packet transition the
#      brief calls out, not a sustained black hole.
#   3. relay-forwarded stays 0 (checked once at the end, covering traffic
#      both before and after the rebind) — proving B's recovery is via
#      Task 1/2's endpoint-relearn + obf-trial machinery on the still-direct
#      path, not a fallback escalation to the relay masking the result.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
RDV="${2:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"

# ── 0. root + tool preflight (invoked directly by CI, not through the
# tunnel_netns.rs Rust harness, so it does its own SKIP-gating per the
# run-netns-rekey.sh / run-netns-pathswitch-rehandshake.sh convention) ──
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-netns-roaming: needs root (netns + TUN)"
    exit 0
fi
for tool in ip iptables ping; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP run-netns-roaming: required tool '$tool' not found"
        exit 0
    fi
done

TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-roaming-test.XXXXXX)"

NS_A="yipRoamA"
NS_B="yipRoamB"
NS_T="yipRoamT"

VETH_A_N="vRmA1"; VETH_A_T="vRmA0"   # A<->T pair: A-side, T-side
VETH_B_N="vRmB1"; VETH_B_T="vRmB0"   # B<->T pair: B-side, T-side

IP_A="10.86.0.2"      # A's address before the rebind
IP_A2="10.86.0.3"     # A's address after the rebind (added mid-session)
IP_T_A="10.86.0.1"    # T's address on A's subnet
IP_B="10.87.0.2"
IP_T_B="10.87.0.1"    # T's address on B's subnet
PREFIX="24"

PORT_A="51820"
PORT_B="51820"
RDV_PORT="51821"
TUN_DEV="yip0"

# Obfuscation MUST be on for this test (see header comment) — hardcoded, not
# gated behind an opt-in env var like sibling scripts' OBF_PSK.
OBF_PSK="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

PID_A=""
PID_B=""
PID_RDV=""

cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill "$PID_RDV" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill -9 "$PID_RDV" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip netns del "$NS_T" 2>/dev/null || true
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

# A binds the WILDCARD address (0.0.0.0), not a fixed local IP: this is what
# lets the rebind below change A's on-wire source without touching A's
# process at all (see header comment).
cat > "$CFG_A" <<EOF
# yipRoamA
local_private=${PRIV_A}
local_public=${PUB_A}
listen=0.0.0.0:${PORT_A}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_T_A}:${RDV_PORT}
obf_psk=${OBF_PSK}
[peer]
public_key=${PUB_B}
EOF

cat > "$CFG_B" <<EOF
# yipRoamB
local_private=${PRIV_B}
local_public=${PUB_B}
listen=${IP_B}:${PORT_B}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_T_B}:${RDV_PORT}
obf_psk=${OBF_PSK}
[peer]
public_key=${PUB_A}
EOF

# ── 3. create namespaces + point-to-point veths into T ────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"
ip netns add "$NS_T"

echo "[setup] wiring A<->T"
ip link add "$VETH_A_T" type veth peer name "$VETH_A_N"
ip link set "$VETH_A_N" netns "$NS_A"
ip link set "$VETH_A_T" netns "$NS_T"
ip netns exec "$NS_A" ip addr add "${IP_A}/${PREFIX}" dev "$VETH_A_N"
ip netns exec "$NS_A" ip link set "$VETH_A_N" up
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_T" ip addr add "${IP_T_A}/${PREFIX}" dev "$VETH_A_T"
ip netns exec "$NS_T" ip link set "$VETH_A_T" up

echo "[setup] wiring B<->T"
ip link add "$VETH_B_T" type veth peer name "$VETH_B_N"
ip link set "$VETH_B_N" netns "$NS_B"
ip link set "$VETH_B_T" netns "$NS_T"
ip netns exec "$NS_B" ip addr add "${IP_B}/${PREFIX}" dev "$VETH_B_N"
ip netns exec "$NS_B" ip link set "$VETH_B_N" up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_T" ip addr add "${IP_T_B}/${PREFIX}" dev "$VETH_B_T"
ip netns exec "$NS_T" ip link set "$VETH_B_T" up
ip netns exec "$NS_T" ip link set lo up

# A's and B's only route beyond their own /24 is via T. No NAT/MASQUERADE
# rule here (see header comment for why: it would fight the rebind's
# explicit route `src` below).
ip netns exec "$NS_A" ip route add default via "$IP_T_A" dev "$VETH_A_N"
ip netns exec "$NS_B" ip route add default via "$IP_T_B" dev "$VETH_B_N"

# T routes between the two client subnets: this is what makes each peer's
# server-observed reflexive addr directly reachable, so the punch succeeds
# without ever needing the relay -- same as run-netns-punch.sh.
ip netns exec "$NS_T" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$NS_T" iptables -P FORWARD ACCEPT
ip netns exec "$NS_T" iptables -A FORWARD -i "$VETH_A_T" -o "$VETH_B_T" -j ACCEPT
ip netns exec "$NS_T" iptables -A FORWARD -i "$VETH_B_T" -o "$VETH_A_T" -j ACCEPT

# ── 4. start yip-rendezvous in T, bound on both subnets, obf ON ──────────────
LOG_RDV="$TMPDIR_TEST/rdv.log"
echo "[start] starting yip-rendezvous in T on 0.0.0.0:${RDV_PORT} (obf on)"
ip netns exec "$NS_T" "$RDV" "0.0.0.0:${RDV_PORT}" --obf-psk "${OBF_PSK}" \
    >"$LOG_RDV" 2>&1 &
PID_RDV=$!
sleep 0.3

# ── 5. start yipd in A and B ───────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

dump_logs() {
    echo "=== rendezvous log ==="
    cat "$LOG_RDV" || true
    echo "=== yipRoamA log ==="
    cat "$LOG_A" || true
    echo "=== yipRoamB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipRoamA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipRoamB"
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
        echo "[error] yipRoamA daemon died unexpectedly"; dump_logs; exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipRoamB daemon died unexpectedly"; dump_logs; exit 1
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

echo "[check] interface state in yipRoamA:"
ip netns exec "$NS_A" ip -6 addr show "$TUN_DEV"
echo "[check] interface state in yipRoamB:"
ip netns exec "$NS_B" ip -6 addr show "$TUN_DEV"

# ── 8. warm-up ping A->B: confirm direct/obf-established convergence ─────────
# NOT counted toward the rebind-continuity bound below; this only absorbs
# ordinary lookup/handshake/obf warm-up, same tolerance run-netns-punch.sh
# documents.
echo "[test] warm-up: pinging ${ADDR_B} from yipRoamA (obf on, expect direct success)"
set +e
ip netns exec "$NS_A" ping -6 -c 20 -W 2 "$ADDR_B"
WARMUP_STATUS=$?
set -e
if [ "$WARMUP_STATUS" -ne 0 ]; then
    echo "[FAIL] warm-up ping A->B did not succeed (exit $WARMUP_STATUS)"
    dump_logs
    exit 1
fi
echo "[PASS] warm-up ping A->B succeeded (session established, obf on)"

# ── 9. measured ping A->B spanning a mid-session rebind of A's source ────────
PING_LOG="$TMPDIR_TEST/rebind_ping.log"
echo "[test] measured ping ${ADDR_B} from yipRoamA (-i 0.2 -c 100), rebind triggered mid-stream"
set +e
ip netns exec "$NS_A" ping -6 -i 0.2 -c 100 -W 1 "$ADDR_B" >"$PING_LOG" 2>&1 &
PING_PID=$!
set -e

# Let ~20 packets go out on the pre-rebind source before flipping it.
sleep 4

echo "[rebind] adding ${IP_A2} to yipRoamA's veth and flipping the default route's preferred source"
ip netns exec "$NS_A" ip addr add "${IP_A2}/${PREFIX}" dev "$VETH_A_N"
ip netns exec "$NS_A" ip route replace default via "$IP_T_A" dev "$VETH_A_N" src "$IP_A2"
echo "[rebind] done — yipRoamA's session (keys, conn_tag) is untouched; only its on-wire source address changed"

set +e
wait "$PING_PID"
PING_STATUS=$?
set -e
cat "$PING_LOG"

if ! kill -0 "$PID_A" 2>/dev/null; then
    echo "[error] yipRoamA daemon died during the rebind ping"; dump_logs; exit 1
fi
if ! kill -0 "$PID_B" 2>/dev/null; then
    echo "[error] yipRoamB daemon died during the rebind ping"; dump_logs; exit 1
fi

# ── assertion: rebind_continuity — <=1% loss across the rebind ──────────────
LOSS_PCT="$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' "$PING_LOG" | grep -oE '^[0-9]+(\.[0-9]+)?' || true)"
if [ -z "$LOSS_PCT" ]; then
    echo "[FAIL] rebind_continuity: could not parse packet loss from ping output"
    dump_logs
    exit 1
fi
echo "[metric] rebind_continuity: packet loss = ${LOSS_PCT}%"
if awk "BEGIN {exit ($LOSS_PCT <= 1.0) ? 0 : 1}"; then
    echo "[PASS] rebind_continuity: ${LOSS_PCT}% loss (<=1%) across the mid-session NAT rebind"
else
    echo "[FAIL] rebind_continuity: ${LOSS_PCT}% loss (>1%) — B did not recover A's roamed, obfuscated source"
    dump_logs
    exit 1
fi
if [ "$PING_STATUS" -ne 0 ] && [ "$LOSS_PCT" != "100" ]; then
    echo "[note] ping exited $PING_STATUS despite <=1% loss (non-fatal; proceeding)"
fi

# ── assertion: relay was NOT used, before or after the rebind ───────────────
sleep 5.5
FINAL_COUNT="$(grep -oE 'relay-forwarded=[0-9]+' "$LOG_RDV" | tail -1 | cut -d= -f2)"
echo "[check] server's final relay-forwarded count: ${FINAL_COUNT:-<none>}"
if [ -n "${FINAL_COUNT:-}" ] && [ "$FINAL_COUNT" -ne 0 ]; then
    echo "[FAIL] relay-forwarded=${FINAL_COUNT} (expected 0) — traffic went through the relay, not the still-direct path"
    dump_logs
    exit 1
fi
echo "[PASS] relay-forwarded=${FINAL_COUNT:-0}: the direct path carried the rebind recovery, relay unused"

echo "[PASS] run-netns-roaming: B kept delivering to A across a mid-session, obfuscation-on NAT rebind"
