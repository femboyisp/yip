#!/usr/bin/env bash
# REALITY.4a netns money test: two UDP-blocked yipd peers bring a tunnel up
# THROUGH a REALITY relay (`yip-rendezvous --reality-dest/--reality-private-key/
# --reality-short-id/--reality-server-name`), and A pings B. Also a
# wrong-pubkey negative test: a mismatched `pbk=` yields NO tunnel — the
# relay's seal-open fails, so it transparently splices the connection to
# `--reality-dest` instead of treating it as an authed relay client, and the
# inner Noise-IK handshake never gets a chance to run.
#
# Modeled directly on the 3c.4 `run-netns-relay-tls.sh` (same netns/veth
# topology, same UDP-blocking, same relay-forwarded assertion). The two
# differences: the relay is launched with the `--reality-*` flags instead of
# `--tls-cert`/`--tls-key`, and the clients use `rendezvous=reality://...`
# with the relay's REALITY public key / short-id / SNI instead of
# `rendezvous=tls://...`.
#
# REALITY_PUB is the X25519 public key matching the pinned REALITY_PRIV
# below. The relay derives its shared secret via
# `x25519_dalek::StaticSecret::from(priv_bytes)` (which CLAMPS the scalar),
# so the client must pin the public key derived the same way:
# `x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(priv_bytes)).to_bytes()`.
# Computed once (via a throwaway `#[test]` using the `pubkey_of` helper
# already in `bin/yip-rendezvous/src/reality.rs`'s test module, then deleted)
# and independently cross-checked with Python's `cryptography` X25519
# implementation — both gave the same 64-hex value, pinned here.
#
# Usage: run-netns-reality-relay.sh <path-to-yipd-binary> <path-to-yip-rendezvous-binary>
#
# Topology: three netns, A / B / R (the REALITY relay), mirroring
# run-netns-relay-tls.sh's structure:
#   A --10.90.0.0/24-- R --10.91.0.0/24-- B
# Two point-to-point veth pairs (A<->R, B<->R); R does NOT forward IPv4
# between them (relay_only mode never attempts a direct route anyway). A and
# B each list the OTHER by `public_key` ONLY (no endpoint).
#
# UDP is DROPped (iptables OUTPUT/INPUT) inside A's and B's netns before
# either daemon starts — belt-and-suspenders on top of relay_only mode
# already never emitting UDP on this path.
#
# `--reality-dest` requires a REAL TLS server to steal a leaf certificate's
# fields from at startup (`RealityCertCache::prewarm`) — an unreachable/
# closed dest makes the relay refuse to start entirely (0 SNIs pre-warmed).
# So DEST here is a local `openssl s_server` self-signed TLS listener inside
# R's own netns (loopback-only, never dialed by A/B — cert verification is
# disabled on the fetch side, so an ordinary self-signed cert is fine).
#
# Assert:
#   1. money test: ping A->B across the tunnel succeeds (generous budget: TLS
#      handshake to the relay + Register + inner Noise-IK handshake, all
#      serial), and the relay's stderr shows relay-forwarded=<N> with N>0.
#   2. wrong-pubkey test: with A reconfigured to a bogus (all-zero) `pbk=`,
#      A restarted, ping A->B FAILS within a bounded timeout (the relay
#      splices A's connection to DEST instead of treating it as authed, so no
#      tunnel ever forms).
#
# Root-gated SKIP + trap-based cleanup, mirroring the sibling scripts.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
RDV="${2:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-netns-reality-relay: needs root (netns + TUN)"
    exit 0
fi
for tool in openssl iptables ip; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP run-netns-reality-relay: required tool '$tool' not found"
        exit 0
    fi
done

TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-reality-relay-test.XXXXXX)"

NS_A="yipRealA"
NS_B="yipRealB"
NS_R="yipRealR"

VETH_A_N="vRealA1"; VETH_A_R="vRealA0"   # A<->R pair: A-side, R-side
VETH_B_N="vRealB1"; VETH_B_R="vRealB0"   # B<->R pair: B-side, R-side

IP_A="10.90.0.2"
IP_R_A="10.90.0.1"   # R's address on A's subnet
IP_B="10.91.0.2"
IP_R_B="10.91.0.1"   # R's address on B's subnet
PREFIX="24"

PORT_A="51820"
PORT_B="51820"
RDV_UDP_PORT="51821"   # bound by yip-rendezvous but never reachable/used —
                        # UDP is blocked in A/B and relay_only mode never
                        # tries it anyway.
RDV_TCP_PORT="8443"
DEST_PORT="9443"       # the local openssl s_server standing in for
                        # --reality-dest's real upstream (loopback in R only)
TUN_DEV="yip0"

# The pinned REALITY relay keypair (see header comment for the derivation).
REALITY_PRIV="2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
REALITY_PUB="07aaff3e9fc167275544f4c3a6a17cd837f2ec6e78cd8a57b1e3dfb3cc035a76"
if [ "${#REALITY_PRIV}" -ne 64 ] || [ "${#REALITY_PUB}" -ne 64 ]; then
    echo "[error] pinned REALITY_PRIV/REALITY_PUB must each be 64 hex chars"
    exit 1
fi
SHORT_ID="00112233445566ff"
if [ "${#SHORT_ID}" -ne 16 ]; then
    echo "[error] pinned SHORT_ID must be 16 hex chars"
    exit 1
fi
SNI="www.microsoft.com"

PID_A=""
PID_B=""
PID_RDV=""
PID_DEST=""

cleanup() {
    echo "[cleanup] killing daemons and removing namespaces"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill "$PID_RDV" 2>/dev/null || true
    [ -n "$PID_DEST" ] && kill "$PID_DEST" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill -9 "$PID_RDV" 2>/dev/null || true
    [ -n "$PID_DEST" ] && kill -9 "$PID_DEST" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip netns del "$NS_R" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. generate keypairs + a shared obf_psk ───────────────────────────────
echo "[setup] generating keypairs + obf_psk"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"

PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"
OBF_PSK="$(openssl rand -hex 32)"

ADDR_A="$("$YIPD" --addr "$PUB_A")"
ADDR_B="$("$YIPD" --addr "$PUB_B")"
echo "[setup] node_addr A=$ADDR_A B=$ADDR_B"

# ── 2. write config files (rendezvous=reality://, peers by public_key ONLY) ─
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

write_cfg_a() {
    local pbk="$1"
    cat > "$CFG_A" <<EOF
# yipRealA — relay-dial over REALITY, UDP blocked
local_private=${PRIV_A}
local_public=${PUB_A}
listen=${IP_A}:${PORT_A}
device=${TUN_DEV}
device_kind=tun
rendezvous=reality://${IP_R_A}:${RDV_TCP_PORT}?pbk=${pbk}&sid=${SHORT_ID}&sni=${SNI}
obf_psk=${OBF_PSK}
[peer]
public_key=${PUB_B}
EOF
}
write_cfg_a "$REALITY_PUB"

cat > "$CFG_B" <<EOF
# yipRealB — relay-dial over REALITY, UDP blocked
local_private=${PRIV_B}
local_public=${PUB_B}
listen=${IP_B}:${PORT_B}
device=${TUN_DEV}
device_kind=tun
rendezvous=reality://${IP_R_B}:${RDV_TCP_PORT}?pbk=${REALITY_PUB}&sid=${SHORT_ID}&sni=${SNI}
obf_psk=${OBF_PSK}
[peer]
public_key=${PUB_A}
EOF

# ── 3. create namespaces + point-to-point veths into R ────────────────────
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

# Belt-and-suspenders: R does not forward IPv4 between A's and B's subnets
# (relay_only mode never attempts a direct route anyway — see header).
ip netns exec "$NS_R" sysctl -q -w net.ipv4.ip_forward=0
ip netns exec "$NS_R" sysctl -q -w net.ipv4.conf.all.forwarding=0

# ── 4. block UDP in A's and B's netns — ONLY TCP/TLS can carry traffic ────
echo "[setup] DROPping all UDP in A and B (proves relay-over-REALITY is the carrier)"
ip netns exec "$NS_A" iptables -A OUTPUT -p udp -j DROP
ip netns exec "$NS_A" iptables -A INPUT -p udp -j DROP
ip netns exec "$NS_B" iptables -A OUTPUT -p udp -j DROP
ip netns exec "$NS_B" iptables -A INPUT -p udp -j DROP

# ── 5. start the local DEST TLS server (self-signed, loopback in R only) ──
# `--reality-dest` needs a real TLS server to steal leaf-certificate fields
# from at startup (RealityCertCache::prewarm); cert verification is disabled
# on that fetch, so a throwaway self-signed cert is fine. This is NEVER
# dialed by A/B (they only ever reach the relay's REALITY front) — it is
# purely so the relay itself can boot with `--reality-server-name` set.
echo "[setup] generating self-signed cert for the local REALITY dest stand-in"
DEST_CERT="$TMPDIR_TEST/dest-cert.pem"
DEST_KEY="$TMPDIR_TEST/dest-key.pem"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DEST_KEY" -out "$DEST_CERT" \
    -days 1 -subj '/CN=dest.test' >"$TMPDIR_TEST/openssl-dest-req.log" 2>&1

LOG_DEST="$TMPDIR_TEST/dest.log"
echo "[start] starting local DEST TLS server in R (127.0.0.1:${DEST_PORT})"
ip netns exec "$NS_R" openssl s_server \
    -accept "127.0.0.1:${DEST_PORT}" \
    -cert "$DEST_CERT" -key "$DEST_KEY" \
    -naccept 50 -quiet \
    >"$LOG_DEST" 2>&1 < /dev/null &
PID_DEST=$!

echo "[wait] waiting for DEST TLS server to accept connections"
DEST_WAIT=0
while ! ip netns exec "$NS_R" bash -c "exec 3<>/dev/tcp/127.0.0.1/${DEST_PORT}" 2>/dev/null; do
    DEST_WAIT=$((DEST_WAIT + 1))
    if [ "$DEST_WAIT" -ge 100 ]; then
        echo "[error] DEST TLS server never started listening"
        cat "$LOG_DEST" || true
        exit 1
    fi
    sleep 0.1
done

# ── 6. start yip-rendezvous in R, REALITY front on :8443 ──────────────────
LOG_RDV="$TMPDIR_TEST/rdv.log"
echo "[start] starting yip-rendezvous in R (udp:0.0.0.0:${RDV_UDP_PORT} [unused], reality-tls:0.0.0.0:${RDV_TCP_PORT})"
ip netns exec "$NS_R" "$RDV" "0.0.0.0:${RDV_UDP_PORT}" \
    --listen-tcp "0.0.0.0:${RDV_TCP_PORT}" \
    --obf-psk "$OBF_PSK" \
    --reality-dest "127.0.0.1:${DEST_PORT}" \
    --reality-private-key "$REALITY_PRIV" \
    --reality-short-id "$SHORT_ID" \
    --reality-server-name "$SNI" \
    >"$LOG_RDV" 2>&1 &
PID_RDV=$!
sleep 0.5
if ! kill -0 "$PID_RDV" 2>/dev/null; then
    echo "[error] yip-rendezvous (REALITY front) died at startup — likely a prewarm/cert-fetch failure"
    cat "$LOG_RDV" || true
    exit 1
fi

# ── 7. start yipd in A and B ────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

dump_logs() {
    echo "=== dest log ==="
    cat "$LOG_DEST" || true
    echo "=== rendezvous log ==="
    cat "$LOG_RDV" || true
    echo "=== yipRealA log ==="
    cat "$LOG_A" || true
    echo "=== yipRealB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipRealA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipRealB"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 8. wait for TUN devices to appear in A and B ──────────────────────────
TUN_WAIT=30
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
        echo "[error] yipRealA daemon died unexpectedly"; dump_logs; exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipRealB daemon died unexpectedly"; dump_logs; exit 1
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

# ── 9. assign each TUN its node_addr/128 + the mesh-prefix route ─────────
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

echo "[check] interface state in yipRealA:"
ip netns exec "$NS_A" ip -6 addr show "$TUN_DEV"
echo "[check] interface state in yipRealB:"
ip netns exec "$NS_B" ip -6 addr show "$TUN_DEV"

# ── 10. money test: ping A->B, tolerating warm-up loss while both serial
# handshakes complete (outer REALITY TLS to the relay + Register, then inner
# Noise-IK) ─────────────────────────────────────────────────────────────────
echo "[test] pinging ${ADDR_B} from yipRealA (expect REALITY+Register+Noise-IK warm-up, then success)"
set +e
ip netns exec "$NS_A" ping -6 -c 30 -W 2 "$ADDR_B"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -ne 0 ]; then
    echo "[FAIL] ping A->B did not succeed over the REALITY relay (exit $PING_STATUS)"
    dump_logs
    exit 1
fi
echo "[PASS] ping A->B succeeded over the REALITY relay"

# ── 11. assert the relay actually carried it: relay-forwarded=<N>, N>0 ────
# Give the server one more sweep interval to emit a final relay-forwarded
# line reflecting the traffic that just flowed.
sleep 5.5
FINAL_COUNT="$(grep -oE 'relay-forwarded=[0-9]+' "$LOG_RDV" | tail -1 | cut -d= -f2)"
echo "[check] server's final relay-forwarded count: ${FINAL_COUNT:-<none>}"
if [ -z "${FINAL_COUNT:-}" ] || [ "$FINAL_COUNT" -eq 0 ]; then
    echo "[FAIL] relay-forwarded count is 0 (or missing) — traffic did not go through the REALITY relay"
    dump_logs
    exit 1
fi
echo "[PASS] relay-forwarded=${FINAL_COUNT} (>0): the REALITY relay carried the traffic"
echo "[PASS] netns REALITY-relay money test PASSED: two UDP-blocked peers tunneled via the REALITY relay, blindly forwarded (relay-forwarded=${FINAL_COUNT})"

# ── 12. negative test: wrong pbk -> NO tunnel ──────────────────────────────
# Rewrite A's config with a bogus (all-zero) pbk and restart A. The relay's
# seal-open must fail against the wrong pubkey, so it splices A's connection
# to DEST instead of treating it as an authed relay client — no Register is
# ever accepted, so the inner Noise-IK handshake never gets a chance to run,
# and the ping must fail within a bounded timeout.
echo "[test] wrong-pubkey negative test: restarting yipRealA with an all-zero pbk"
kill "$PID_A" 2>/dev/null || true
wait "$PID_A" 2>/dev/null || true
PID_A=""

ZERO_PUB="0000000000000000000000000000000000000000000000000000000000000000"
if [ "${#ZERO_PUB}" -ne 64 ]; then
    echo "[error] ZERO_PUB must be 64 hex chars"
    exit 1
fi
write_cfg_a "$ZERO_PUB"

LOG_A_WRONG="$TMPDIR_TEST/yipA-wrongpbk.log"
echo "[start] restarting yipRealA with rendezvous pbk=${ZERO_PUB}"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A_WRONG" 2>&1 &
PID_A=$!
sleep 1

echo "[test] pinging ${ADDR_B} from yipRealA (expect FAILURE: wrong pbk never authenticates)"
set +e
timeout 15 ip netns exec "$NS_A" ping -6 -c 10 -W 2 "$ADDR_B"
WRONG_PING_STATUS=$?
set -e
if [ "$WRONG_PING_STATUS" -eq 0 ]; then
    echo "[FAIL] ping A->B succeeded with a WRONG pbk — the relay accepted an unauthenticated connection as a real relay client"
    echo "=== yipRealA (wrong pbk) log ==="
    cat "$LOG_A_WRONG" || true
    dump_logs
    exit 1
fi
echo "[PASS] ping A->B failed as expected with a wrong pbk (relay spliced to DEST, no tunnel formed)"

echo "[PASS] netns REALITY-relay wrong-pubkey negative test PASSED"
