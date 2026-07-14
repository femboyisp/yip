#!/usr/bin/env bash
# The 3c.4 headline money test: two UDP-blocked yipd peers tunnel to each
# other THROUGH the 3c.3 TLS relay. This is the end-to-end proof that the
# whole relay-dial path works: `rendezvous=tls://host:port` + `obf_psk`
# dials the relay over browser-parrot TLS (relay_client.rs, a dedicated
# thread), registers, and the relay blindly forwards ALL peer traffic
# (RelaySend/RelayDeliver) — never touching the unchanged inner Noise/FEC/AEAD
# payload it carries.
#
# Usage: run-netns-relay-tls.sh <path-to-yipd-binary> <path-to-yip-rendezvous-binary>
#
# Topology: three netns, A / B / R (the TLS relay), mirroring
# run-netns-relay.sh's point-to-point structure:
#   A --10.80.0.0/24-- R --10.81.0.0/24-- B
# Two point-to-point veth pairs (A<->R, B<->R); no shared bridge, and R does
# NOT forward IPv4 between them (belt-and-suspenders — relay_only mode never
# even attempts a route to the peer's subnet, since PeerManager starts every
# peer straight in Relaying and skips Direct/UDP-punch entirely for
# `rendezvous=tls://`, see tunnel.rs). A and B each list the OTHER by
# `public_key` ONLY (no endpoint) — there is no direct-reachability
# information to leak even if a route existed.
#
# UDP is additionally DROPped (iptables OUTPUT/INPUT) inside A's and B's
# netns before either daemon starts. This is belt-and-suspenders on top of
# relay_only mode already never emitting UDP on this path: it proves that
# even if a wiring bug tried to fall back to a direct/punch UDP send, the
# ping would still succeed — only the TCP/TLS relay path can possibly be
# carrying the traffic.
#
# Assert:
#   1. ping A->B across the tunnel succeeds (generous budget: TLS handshake
#      to the relay + Register + inner Noise-IK handshake, all serial).
#   2. the relay's stderr shows `relay-forwarded=<N>` with N>0 — the blind
#      relay actually carried the traffic (same assertion style as
#      run-netns-relay.sh's 2b money test).
#   3. a tcpdump capture on the A<->R veth link shows TCP (port 8443)
#      carrying the exchange, and exactly zero UDP packets (proving nothing
#      slipped past the iptables DROP).
#
# Root-gated SKIP + trap-based cleanup, mirroring the sibling scripts.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
RDV="${2:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-netns-relay-tls: needs root (netns + TUN + tcpdump)"
    exit 0
fi
for tool in openssl tcpdump iptables ip; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP run-netns-relay-tls: required tool '$tool' not found"
        exit 0
    fi
done

TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-relay-tls-test.XXXXXX)"
PCAP="$TMPDIR_TEST/relay-tls.pcap"

NS_A="yipRtlsA"
NS_B="yipRtlsB"
NS_R="yipRtlsR"

VETH_A_N="vRtlsA1"; VETH_A_R="vRtlsA0"   # A<->R pair: A-side, R-side
VETH_B_N="vRtlsB1"; VETH_B_R="vRtlsB0"   # B<->R pair: B-side, R-side

IP_A="10.80.0.2"
IP_R_A="10.80.0.1"   # R's address on A's subnet
IP_B="10.81.0.2"
IP_R_B="10.81.0.1"   # R's address on B's subnet
PREFIX="24"

PORT_A="51820"
PORT_B="51820"
RDV_UDP_PORT="51821"   # bound by yip-rendezvous but never reachable/used —
                        # UDP is blocked in A/B and relay_only mode never
                        # tries it anyway.
RDV_TCP_PORT="8443"
TUN_DEV="yip0"

PID_A=""
PID_B=""
PID_RDV=""
TCPDUMP_PID=""

cleanup() {
    echo "[cleanup] killing daemons/tcpdump and removing namespaces"
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

# ── 2. write config files (rendezvous=tls://, peers by public_key ONLY) ───
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipRtlsA — relay-dial over TLS, UDP blocked
local_private=${PRIV_A}
local_public=${PUB_A}
listen=${IP_A}:${PORT_A}
device=${TUN_DEV}
device_kind=tun
rendezvous=tls://${IP_R_A}:${RDV_TCP_PORT}
obf_psk=${OBF_PSK}
[peer]
public_key=${PUB_B}
EOF

cat > "$CFG_B" <<EOF
# yipRtlsB — relay-dial over TLS, UDP blocked
local_private=${PRIV_B}
local_public=${PUB_B}
listen=${IP_B}:${PORT_B}
device=${TUN_DEV}
device_kind=tun
rendezvous=tls://${IP_R_B}:${RDV_TCP_PORT}
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
echo "[setup] DROPping all UDP in A and B (proves relay-over-TLS is the carrier)"
ip netns exec "$NS_A" iptables -A OUTPUT -p udp -j DROP
ip netns exec "$NS_A" iptables -A INPUT -p udp -j DROP
ip netns exec "$NS_B" iptables -A OUTPUT -p udp -j DROP
ip netns exec "$NS_B" iptables -A INPUT -p udp -j DROP

# ── 5. self-signed cert for the relay + start yip-rendezvous in R ─────────
echo "[setup] generating self-signed cert for relay.test"
CERT="$TMPDIR_TEST/cert.pem"
KEY="$TMPDIR_TEST/key.pem"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CERT" \
    -days 1 -subj '/CN=relay.test' >"$TMPDIR_TEST/openssl-req.log" 2>&1

LOG_RDV="$TMPDIR_TEST/rdv.log"
echo "[start] starting yip-rendezvous in R (udp:0.0.0.0:${RDV_UDP_PORT} [unused], tls:0.0.0.0:${RDV_TCP_PORT})"
ip netns exec "$NS_R" "$RDV" "0.0.0.0:${RDV_UDP_PORT}" \
    --listen-tcp "0.0.0.0:${RDV_TCP_PORT}" \
    --tls-cert "$CERT" \
    --tls-key "$KEY" \
    --obf-psk "$OBF_PSK" \
    >"$LOG_RDV" 2>&1 &
PID_RDV=$!
sleep 0.3

# ── 6. capture on A's side of the A<->R link, before either daemon starts,
# so the full TLS handshake (ClientHello onward) is captured from packet
# zero. `-nn` avoids DNS/service-name lookups (which would themselves emit
# traffic); no BPF filter, so both TCP and any (unexpected) UDP show up. ────
echo "[capture] starting tcpdump inside $NS_A on $VETH_A_N"
ip netns exec "$NS_A" tcpdump -i "$VETH_A_N" -nn -q -w "$PCAP" \
    >"$TMPDIR_TEST/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 1

# ── 7. start yipd in A and B ───────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

dump_logs() {
    echo "=== rendezvous log ==="
    cat "$LOG_RDV" || true
    echo "=== yipRtlsA log ==="
    cat "$LOG_A" || true
    echo "=== yipRtlsB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipRtlsA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipRtlsB"
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
        echo "[error] yipRtlsA daemon died unexpectedly"; dump_logs; exit 1
    fi
    if ! kill -0 "$PID_B" 2>/dev/null; then
        echo "[error] yipRtlsB daemon died unexpectedly"; dump_logs; exit 1
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

echo "[check] interface state in yipRtlsA:"
ip netns exec "$NS_A" ip -6 addr show "$TUN_DEV"
echo "[check] interface state in yipRtlsB:"
ip netns exec "$NS_B" ip -6 addr show "$TUN_DEV"

# ── 10. ping A->B, tolerating warm-up loss while both serial handshakes
# complete (outer TLS to the relay + Register, then inner Noise-IK) ────────
echo "[test] pinging ${ADDR_B} from yipRtlsA (expect TLS+Register+Noise-IK warm-up, then success)"
set +e
ip netns exec "$NS_A" ping -6 -c 30 -W 2 "$ADDR_B"
PING_STATUS=$?
set -e
if [ "$PING_STATUS" -ne 0 ]; then
    echo "[FAIL] ping A->B did not succeed over the TLS relay (exit $PING_STATUS)"
    dump_logs
    exit 1
fi
echo "[PASS] ping A->B succeeded over the TLS relay"

# ── 11. stop capture ────────────────────────────────────────────────────────
sleep 1
echo "[capture] stopping tcpdump"
kill "$TCPDUMP_PID" 2>/dev/null || true
sleep 1
TCPDUMP_PID=""

if [ ! -s "$PCAP" ]; then
    echo "[FAIL] capture is empty or missing at $PCAP"
    cat "$TMPDIR_TEST/tcpdump.log" || true
    dump_logs
    exit 1
fi
echo "[capture] pcap: $(stat -c%s "$PCAP") bytes"

# ── 12. assert the relay actually carried it: relay-forwarded=<N>, N>0 ────
# Give the server one more sweep interval to emit a final relay-forwarded
# line reflecting the traffic that just flowed.
sleep 5.5
FINAL_COUNT="$(grep -oE 'relay-forwarded=[0-9]+' "$LOG_RDV" | tail -1 | cut -d= -f2)"
echo "[check] server's final relay-forwarded count: ${FINAL_COUNT:-<none>}"
if [ -z "${FINAL_COUNT:-}" ] || [ "$FINAL_COUNT" -eq 0 ]; then
    echo "[FAIL] relay-forwarded count is 0 (or missing) — traffic did not go through the TLS relay"
    dump_logs
    exit 1
fi
echo "[PASS] relay-forwarded=${FINAL_COUNT} (>0): the blind TLS relay carried the traffic"

# ── 13. assert TCP (port 8443) carried it, and exactly zero UDP crossed
# the wire (nothing slipped past the iptables DROP) ────────────────────────
TCPDUMP_OUT="$TMPDIR_TEST/tcpdump-read.log"
tcpdump -nn -q -r "$PCAP" >"$TCPDUMP_OUT" 2>/dev/null || true
cat "$TCPDUMP_OUT"

# tcpdump -q line shape: "<ts> IP src.port > dst.port: tcp N" (lowercase
# "tcp") or "<ts> IP src.port > dst.port: UDP, length N" (uppercase "UDP") —
# the TCP port number appears as ".<port>" on one side of the address pair,
# BEFORE the " tcp " marker, so match both independently rather than
# requiring one particular order.
TCP_COUNT="$(grep -E "\.${RDV_TCP_PORT}[ :]" "$TCPDUMP_OUT" | grep -c " tcp " || true)"
UDP_COUNT="$(grep -c " UDP" "$TCPDUMP_OUT" || true)"

echo "[check] captured TCP:${RDV_TCP_PORT} packets: ${TCP_COUNT}, UDP packets: ${UDP_COUNT}"

FAIL=0
if [ "${TCP_COUNT:-0}" -eq 0 ]; then
    echo "[FAIL] no TCP packets to/from port ${RDV_TCP_PORT} were captured on the A<->R link"
    FAIL=1
else
    echo "[PASS] TCP (port ${RDV_TCP_PORT}) carried the exchange (${TCP_COUNT} packets)"
fi
if [ "${UDP_COUNT:-0}" -ne 0 ]; then
    echo "[FAIL] ${UDP_COUNT} UDP packet(s) were captured on the A<->R link — the iptables DROP was bypassed"
    FAIL=1
else
    echo "[PASS] zero UDP packets crossed the A<->R link"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "[FAIL] netns relay-over-TLS money test FAILED — see gate output above"
    dump_logs
    exit 1
fi

echo "[PASS] netns relay-over-TLS money test PASSED: two UDP-blocked peers tunneled via the TLS relay, blindly forwarded (relay-forwarded=${FINAL_COUNT}), TCP-carried"
