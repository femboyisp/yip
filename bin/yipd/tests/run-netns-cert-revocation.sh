#!/usr/bin/env bash
# The hardening.41 money test: proves the #41 fix end-to-end — a revoked
# (cert-expired) mesh member must lose its session within a bounded window
# of its cert expiring, not just at process restart, and must not be able to
# re-establish afterward.
#
# Usage: run-netns-cert-revocation.sh <path-to-yipd-binary> <path-to-yip-ca-binary> <path-to-yip-rendezvous-binary>
#
# ── topology: three netns, A / B / R, all on ONE shared bridge underlay ──
# Forked from run-netns-discovery.sh's mesh CA/cert/roots/gossip setup: R is
# a seed root (always-admit, named in the CA-signed root set A and B both
# load); A and B carry NO `[peer]` block for each other, only the roots
# file — they discover each other via R's periodic gossip digest, exactly
# like run-netns-discovery.sh.
#
# This is NOT incidental — it is required by the mechanism under test.
# `Membership::member_cert_valid` (the periodic cert-liveness sweep's
# predicate, bin/yipd/src/membership.rs) checks a peer's cert via the LOCAL
# DIRECTORY record for that peer (`self.directory.get(node_id(pubkey))`),
# not any statically-configured value. A purely static `[peer]`-block config
# (no gossip) would never populate that directory at all, and the sweep
# would then treat EVERY established mesh peer as unknown/invalid
# (`None => false`) regardless of its cert's real validity — the wrong
# behavior for this test to exercise. Gossip-based discovery is what
# actually seeds each side's directory with the other's cert (ingested while
# still valid), which is what the sweep re-checks against wall-clock time on
# every cadence tick.
#
# ── the two enforcement mechanisms this test exercises together ──
#   (a) rekey Init cert re-verify (`responder_cert_ok` on the rekey Init's
#       OWN attached cert payload) — drops the session the moment either
#       side sends a rekey Init carrying an expired cert.
#   (b) periodic cert-liveness sweep (`member_cert_valid` against the
#       directory) — drops any Established mesh peer whose directory-cached
#       cert has expired, independent of any inbound message, throttled to
#       once per `rekey_interval_ms`.
# Both are driven by the SAME `Membership::verify_cert` / free `verify_cert`
# path and therefore the SAME `CLOCK_SKEW_SECS` widening (see next section).
# This test does not (and cannot, from the outside) distinguish which one
# fires first — either is a correct #41 fix; the observable is the same.
#
# ── CRITICAL TIMING NOTE: CLOCK_SKEW_SECS, not just cert validity ──
# `bin/yipd/src/membership.rs` widens EVERY cert-validity check (both
# mechanisms above) by a hardcoded `CLOCK_SKEW_SECS = 300` (5 minutes) —
# a cert is not treated as expired until `now > cert.not_after + 300`, and
# this constant is NOT configurable via env (unlike `YIP_REKEY_INTERVAL_MS`).
# A test that only waits `cert_secs + rekey_interval + a small margin` after
# minting will observe NO drop and fail confusingly. This script's post-
# expiry wait is `CERT_A_SECS + CLOCK_SKEW_SECS(300) + REKEY_INTERVAL_S +
# MARGIN` — i.e. the test genuinely takes several minutes past establishment
# by design, not by accident. If `CLOCK_SKEW_SECS` in membership.rs ever
# changes, update `CLOCK_SKEW_SECS` below to match.
#
# Assertions (any failure is non-zero exit, [PASS]/[FAIL] markers):
#   1. discovery: A's config has no `[peer]` block / no knowledge of B's key
#      (load-bearing — proves the directory is populated by gossip, which
#      the sweep depends on, not static config).
#   2. establishment: a steady ping A->B succeeds while A's cert is valid.
#   3. revocation: once well past A's cert's expiry (skew-widened), a fresh
#      ping A->B FAILS — B dropped the session.
#   4. no re-admission: a further generous ping window still FAILS — A's
#      expired cert is refused by the re-admission gate on any subsequent
#      handshake attempt, not just coincidentally not-yet-retried.
# BOTH drivers (reads YIP_USE_URING from the caller's env; `ip netns exec`,
# unlike `sudo`, does not clear the environment, so it flows through to the
# daemons unmodified).
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-ca-binary> <yip-rendezvous-binary>}"
YIPCA="${2:?Usage: $0 <yipd-binary> <yip-ca-binary> <yip-rendezvous-binary>}"
RDV="${3:?Usage: $0 <yipd-binary> <yip-ca-binary> <yip-rendezvous-binary>}"

# ── 0. root preflight (invoked directly by CI, not through the
# tunnel_netns.rs Rust harness, so it does its own SKIP-gating per the
# run-netns-rekey.sh convention) ──
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-netns-cert-revocation: needs root (netns + TUN)"
    exit 0
fi
if ! command -v ping >/dev/null 2>&1; then
    echo "SKIP run-netns-cert-revocation: required tool 'ping' not found"
    exit 0
fi

TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-cert-revocation-test.XXXXXX)"

BR="brRev0"

NS_A="yipRevA"
NS_B="yipRevB"
NS_R="yipRevR"

VETH_A_H="vRevA0"; VETH_A_N="vRevA1"
VETH_B_H="vRevB0"; VETH_B_N="vRevB1"
VETH_R_H="vRevR0"; VETH_R_N="vRevR1"

IP_A="10.93.0.1"
IP_B="10.93.0.2"
IP_R="10.93.0.3"
VETH_PREFIX="24"
PORT="51820"
TUN_DEV="yip0"
NETWORK_ID="c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"

# `bin/yipd/src/membership.rs`'s hardcoded, non-configurable clock-skew
# widening -- see the header comment above. Keep in sync with that constant.
CLOCK_SKEW_SECS=300
# A's cert validity window (seconds). Generous enough to comfortably cover
# netns/CA setup + daemon startup + TUN wait + gossip discovery warm-up
# (run-netns-discovery.sh documents up to a 60s budget for that warm-up)
# before we need it to still be valid for the "establish while valid" step.
CERT_A_SECS=60
# Extra slack past cert_secs+skew+rekey_interval before we check for the
# drop: covers scheduling jitter in the sweep's throttle and the rekey
# cadence (a few missed 2s cycles is nothing against this margin).
DROP_MARGIN_SECS=20
YIP_REKEY_INTERVAL_MS=2000
REKEY_INTERVAL_SECS=$((YIP_REKEY_INTERVAL_MS / 1000))

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

# R and B get ordinary long-lived certs (R is a root and exempt from
# cert-based revocation entirely; B must stay valid for the whole test).
CERT_R_FILE="$TMPDIR_TEST/certR.hex"
echo "$CA_PRIV" | "$YIPCA" sign-cert \
    --member "$PUB_R" --member-sign "$SIGNPUB_R" \
    --network "$NETWORK_ID" --days 30 > "$CERT_R_FILE"

CERT_B_FILE="$TMPDIR_TEST/certB.hex"
echo "$CA_PRIV" | "$YIPCA" sign-cert \
    --member "$PUB_B" --member-sign "$SIGNPUB_B" \
    --network "$NETWORK_ID" --days 30 > "$CERT_B_FILE"

# A's cert: short-validity (`--secs`), minted last so as little of its
# window as possible is spent before daemons even start. MINT_TIME anchors
# every deadline computed below.
CERT_A_FILE="$TMPDIR_TEST/certA.hex"
echo "$CA_PRIV" | "$YIPCA" sign-cert \
    --member "$PUB_A" --member-sign "$SIGNPUB_A" \
    --network "$NETWORK_ID" --secs "$CERT_A_SECS" > "$CERT_A_FILE"
MINT_TIME=$(date +%s)
EXPIRY_TIME=$((MINT_TIME + CERT_A_SECS))
DROP_CHECK_TIME=$((EXPIRY_TIME + CLOCK_SKEW_SECS + REKEY_INTERVAL_SECS + DROP_MARGIN_SECS))
echo "[setup] A's cert minted at $MINT_TIME, expires at $EXPIRY_TIME (+${CERT_A_SECS}s); drop expected observable by $DROP_CHECK_TIME (+$((DROP_CHECK_TIME - MINT_TIME))s from mint)"

ROOTS_IN="$TMPDIR_TEST/roots.in"
echo "$PUB_R ${IP_R}:${PORT}" > "$ROOTS_IN"
ROOTS_FILE="$TMPDIR_TEST/roots.hex"
echo "$CA_PRIV" | "$YIPCA" sign-roots --roots "$ROOTS_IN" --version 1 > "$ROOTS_FILE"

# ── 2. write mesh config files — NO [peer] blocks anywhere (discovery) ───────
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

# ── 4. start daemons: seed root first, then A and B, at a fast rekey cadence ──
export YIP_REKEY_INTERVAL_MS

LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"
LOG_R="$TMPDIR_TEST/yipR.log"

dump_logs() {
    echo "=== yipRevR (root) log ==="
    cat "$LOG_R" || true
    echo "=== yipRevA log ==="
    cat "$LOG_A" || true
    echo "=== yipRevB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipRevR (seed root)"
ip netns exec "$NS_R" "$YIPD" "$CFG_R" >"$LOG_R" 2>&1 &
PID_R=$!

echo "[start] starting yipRevA (YIP_REKEY_INTERVAL_MS=$YIP_REKEY_INTERVAL_MS)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipRevB"
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

    for pid_var_name in PID_A:yipRevA PID_B:yipRevB PID_R:yipRevR; do
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

# ── 7. load-bearing: A's config has no static knowledge of B whatsoever ──────
echo "[check] asserting A's config has no [peer] block and no knowledge of B's key"
if grep -q '\[peer\]' "$CFG_A"; then
    echo "[FAIL] A's config unexpectedly contains a [peer] block — this test requires the gossip-populated directory the sweep depends on"
    cat "$CFG_A"
    exit 1
fi
if grep -qi "$PUB_B" "$CFG_A"; then
    echo "[FAIL] A's config unexpectedly contains B's public key — this test requires pure discovery"
    cat "$CFG_A"
    exit 1
fi
echo "[PASS] A's config names neither a [peer] block nor B's public key"

# ── 8. establish: a steady ping A->B succeeds WHILE A's cert is still valid ──
NOW=$(date +%s)
REMAINING=$((EXPIRY_TIME - NOW))
echo "[check] ${REMAINING}s remain on A's cert before it expires — establishing now"
if [ "$REMAINING" -lt 10 ]; then
    echo "[FAIL] setup + discovery warm-up ate too much of A's cert validity window (only ${REMAINING}s left) — raise CERT_A_SECS"
    dump_logs
    exit 1
fi
echo "[test] pinging ${ADDR_B} from yipRevA (expect discovery+handshake, then success, while A's cert is valid)"
set +e
ip netns exec "$NS_A" ping -6 -c 20 -W 2 "$ADDR_B"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -ne 0 ]; then
    echo "[FAIL] ping A->B did not converge (exit $PING_STATUS) — could not establish A<->B before cert expiry"
    dump_logs
    exit 1
fi
echo "[PASS] ping A->B succeeded: A<->B established while A's cert is valid"

NOW=$(date +%s)
if [ "$NOW" -gt "$EXPIRY_TIME" ]; then
    echo "[FAIL] A's cert already expired (now=$NOW > expiry=$EXPIRY_TIME) by the time establishment finished — raise CERT_A_SECS"
    dump_logs
    exit 1
fi

# ── 9. wait past expiry + CLOCK_SKEW_SECS + rekey_interval + margin ──────────
NOW=$(date +%s)
WAIT_SECS=$((DROP_CHECK_TIME - NOW))
if [ "$WAIT_SECS" -gt 0 ]; then
    echo "[wait] sleeping ${WAIT_SECS}s for A's cert to expire past the ${CLOCK_SKEW_SECS}s clock-skew grace + rekey cadence"
    sleep "$WAIT_SECS"
fi

for pid_var_name in PID_A:yipRevA PID_B:yipRevB PID_R:yipRevR; do
    pid_var="${pid_var_name%%:*}"
    node_name="${pid_var_name##*:}"
    pid="${!pid_var}"
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[error] $node_name daemon died during the wait"
        dump_logs
        exit 1
    fi
done

# ── 10. revocation: ping A->B must now FAIL — B dropped the session ─────────
echo "[test] pinging ${ADDR_B} from yipRevA again (expect FAIL: B has dropped A's revoked session)"
set +e
ip netns exec "$NS_A" ping -6 -c 10 -W 2 "$ADDR_B"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -eq 0 ]; then
    echo "[FAIL] ping A->B unexpectedly SUCCEEDED after A's cert expired — B did not drop the revoked session"
    dump_logs
    exit 1
fi
echo "[PASS] ping A->B failed (exit $PING_STATUS): B dropped A's session after cert expiry"

# ── 11. no re-admission: a further generous window must STILL fail ──────────
# A keeps thinking it's Established (nothing tells it otherwise) and will
# keep re-attempting via its own rekey schedule with the SAME expired cert
# attached; B's re-admission gate must keep refusing every attempt, not just
# have not-yet-retried. This is the durable, black-box observable for "A
# cannot re-establish" — whether B's refusal is via the rekey re-verify path
# or the cold-start re-admission gate is an internal detail this test cannot
# see (no stderr markers exist for either), so it asserts the sustained
# outcome instead of the mechanism.
echo "[test] pinging ${ADDR_B} from yipRevA once more (expect FAIL: re-admission gate keeps refusing the expired cert)"
set +e
ip netns exec "$NS_A" ping -6 -c 15 -W 2 "$ADDR_B"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -eq 0 ]; then
    echo "[FAIL] ping A->B unexpectedly SUCCEEDED on retry — A re-established with a revoked cert!"
    dump_logs
    exit 1
fi
echo "[PASS] ping A->B still failed (exit $PING_STATUS): A cannot re-establish with its expired cert"

echo "[PASS] run-netns-cert-revocation: A's session was dropped within a bounded window of cert expiry, and re-admission stays refused"
