#!/usr/bin/env bash
# The anti-replay.34 money test for yipd's freshness-gated Init admission:
# proves (1) a captured-and-replayed HandshakeInit from an off-path attacker
# is REFUSED by the freshness gate (observed black-box via B's stderr marker)
# and does not disrupt the victim's live session with the real peer, and
# (2) a genuine peer restart (fresh ephemeral + newer wall-clock ts) still
# recovers, bounded in time.
#
# Scope note: A and B are ESTABLISHED, so the replayed Init routes through the
# rekey admission path (`rekey_init_core` + `accept_fresh_init`), which is
# where the freshness gate refuses it (assertion 2 below is the discriminating
# check — it greps B's refusal marker). That rekey path never writes
# `peers[idx].endpoint`, so the ping check (assertion 1) proves the replay
# neither wedges nor corrupts B's live session, NOT that an endpoint write was
# suppressed. The cold-start Idle-arm case — where a stale Init WOULD otherwise
# set `endpoint = Some(src)` and the freshness gate suppresses it — is covered
# at unit level by `stale_replayed_cold_start_init_does_not_hijack_endpoint`
# in peer_manager.rs.
#
# Usage: run-netns-replay-hijack.sh <path-to-yipd-binary> <path-to-yip-rendezvous-binary>
#
# ── topology: four netns, A / B / T / S ──
#   A --10.86.0.0/24-- T --10.87.0.0/24-- B
#                       |
#                  10.88.0.0/24
#                       |
#                       S
# Forked from run-netns-punch.sh's topology (T DOES route between subnets,
# IPv4 forwarding enabled — so A and B converge over a direct/punched path,
# never the blind relay), with a fourth point-to-point leg into T for S, the
# attacker namespace. yip-rendezvous runs in T (bound on all three subnets);
# A and B are configured rendezvous-only (public_key, no endpoint), exactly
# like run-netns-punch.sh.
#
# ── why S doesn't need raw-socket IP spoofing ──
# The brief scenario is "a THIRD namespace with a spoofed source" replaying a
# captured Init at B. A literal forged IP source (matching A's real address
# bit-for-bit) would be UNOBSERVABLE in this topology: yipd's admission match
# is keyed off the Noise `remote_static` embedded IN the ciphertext payload,
# not the UDP source address (see `handle_handshake_init`'s
# `self.peers.iter().position(|p| p.pubkey == remote_static)`), and IP
# routing is destination-based, so B's replies would route back to A's real
# interface regardless of which physical netns actually sent the spoofed
# packet — the "hijack" would be invisible either way. So S uses its own
# real, distinct address — no raw sockets, no CAP_NET_RAW, just a concocted
# duplicated ciphertext. The endpoint-write vector the #34 freshness gate
# closes (pre-#34, ANY successfully-parsed Init from an admitted peer updated
# `endpoint` unconditionally) lives on the cold-start Idle arm; against these
# already-established peers the replay instead exercises the rekey admission
# path, and what this test proves black-box is that the gate REFUSES the
# replay (marker) without disrupting the live session (ping).
#
# ── forcing the replay through the freshness gate, not the retransmit dedup ──
# `rekey_init_core`'s cases 1/2 (`cached_resp_init_eph` / `next_cached_resp_for`
# match) deliberately bypass the freshness gate for a genuine retransmit —
# that is by design (see peer_manager.rs's `accept_fresh_init` doc comment).
# A byte-for-byte replay of the captured Init would therefore only prove
# something if it is no longer reachable via EITHER dedup cache by the time
# it's replayed. Two different things must therefore NOT be the round this
# test replays:
#   - round 0 (the cold-start Init): `self.peers[idx].cached_resp_init_eph`
#     is a STICKY field, set ONLY on the Idle->Established cold-start
#     transition (`handle_handshake_init`'s establish arm) and never touched
#     again by any later rekey round (`rekey_init_core`'s case 4 install only
#     calls `epochs.install_next(..)`, a DIFFERENT, per-`EpochSet` field). A
#     replay of round 0 would ALWAYS hit case 1's dedup, no matter how many
#     rekey rounds have since completed.
#   - the CURRENT (most recently installed, not-yet-superseded) rekey round:
#     `install_next` unconditionally REPLACES `epochs.next` on every call, so
#     `next_cached_resp_for` only ever matches the latest round.
# So this script captures round 1 (the SECOND Init frame — A's first rekey
# round, after cold-start) and replays it only once at least one FURTHER
# round has completed (superseding round 1's `next` slot). Both peers are
# held to a fast YIP_REKEY_INTERVAL_MS=2000 cadence (same constant
# run-netns-rekey.sh uses) and a burn-in ping stream runs long enough for
# several rounds to complete, so round 1 is safely stale-on-both-counts by
# replay time: neither cached slot matches its ephemeral, so it falls
# through to `accept_fresh_init`, whose `ts` is now stale relative to what B
# has since accepted from A — landing on the actual freshness-gate refusal
# (`peer_manager: stale/replayed Init refused (freshness gate)`, added by
# this task since no such marker existed before).
#
# ── obfuscation deliberately OFF ──
# Same reasoning as run-netns-rekey.sh: this script identifies a captured
# [HandshakeInit] by its first cleartext wire byte (`PacketType::HandshakeInit
# as u8 == 0`, via a tshark `udp.payload[0:1] == 00` filter). With obf on,
# that prefix rides inside the obf envelope and is unrecoverable from a
# passive capture.
#
# Assertions (any failure is non-zero exit, [PASS]/[FAIL] markers):
#   1. no_disruption: a steady `ping A->B` (over the mesh v6 addr) spanning
#      the replay send shows <=1% loss — the replay neither wedged nor
#      corrupted B's live session with A. (The endpoint-write suppression this
#      gate provides is unit-tested; see the scope note above.)
#   2. freshness_gate_refusal: B's stderr contains the freshness-gate marker
#      after the replay — the discriminating check that the replay was refused.
#   3. restart_recovery: killing and restarting A (same identity, fresh
#      ephemeral + newer wall-clock ts) re-establishes A<->B within a
#      generous bounded ping window (bounded, unlike the pre-#34 stuck state
#      this replaces).
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"
RDV="${2:?Usage: $0 <yipd-binary> <yip-rendezvous-binary>}"

# ── 0. root + tool preflight (invoked directly by CI, not through the
# tunnel_netns.rs Rust harness, so it does its own SKIP-gating per the
# run-netns-rekey.sh / run-netns-pathswitch-rehandshake.sh convention) ──
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-netns-replay-hijack: needs root (netns + TUN + tcpdump)"
    exit 0
fi
for tool in tcpdump tshark ping python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP run-netns-replay-hijack: required tool '$tool' not found"
        exit 0
    fi
done

TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-replay-hijack-test.XXXXXX)"

NS_A="yipReplA"
NS_B="yipReplB"
NS_T="yipReplT"
NS_S="yipReplS"

VETH_A_N="vReplA1"; VETH_A_T="vReplA0"   # A<->T pair: A-side, T-side
VETH_B_N="vReplB1"; VETH_B_T="vReplB0"   # B<->T pair: B-side, T-side
VETH_S_N="vReplS1"; VETH_S_T="vReplS0"   # S<->T pair: S-side, T-side

IP_A="10.86.0.2"
IP_T_A="10.86.0.1"   # T's address on A's subnet
IP_B="10.87.0.2"
IP_T_B="10.87.0.1"   # T's address on B's subnet
IP_S="10.88.0.2"
IP_T_S="10.88.0.1"   # T's address on S's subnet
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
    ip netns del "$NS_T" 2>/dev/null || true
    ip netns del "$NS_S" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. generate keypairs, retrying until PUB_A < PUB_B ────────────────────
# `handle_handshake_init`'s glare tie-break (`self.local_pub <
# self.peers[idx].pubkey`) makes the SMALLER public key the deterministic,
# persistent initiator — for BOTH the cold-start handshake and every
# subsequent rekey round (`drive_rekey_schedule` reuses the exact same
# comparison). This test needs to capture-and-replay an Init that A itself
# SENT and B ACCEPTED (that's what populates B's `cached_resp_init_eph`/
# `last_accepted_init_ts` for A) — without this, a ~50% coin flip would make
# B the initiator instead, and A's own captured "src host $IP_A" traffic
# would carry [HandshakeResp]s, not [HandshakeInit]s, making the test
# non-deterministically vacuous rather than reliably proving anything. Same
# fix run-netns-pathswitch-rehandshake.sh uses. hex_encode is
# byte-order-preserving, so a plain bash string `<` comparison of the two hex
# pubkeys is equivalent to Rust's `[u8; 32]` lexicographic `<`. ~50% chance
# per attempt; capped well above what randomness could plausibly need.
echo "[setup] generating keypairs (retrying until PUB_A < PUB_B, for a deterministic initiator)"
PUB_A=""
PUB_B=""
for _attempt in $(seq 1 50); do
    GENKEY_A="$("$YIPD" --genkey)"
    GENKEY_B="$("$YIPD" --genkey)"
    CAND_PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
    CAND_PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"
    if [[ "$CAND_PUB_A" < "$CAND_PUB_B" ]]; then
        PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
        PUB_A="$CAND_PUB_A"
        PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
        PUB_B="$CAND_PUB_B"
        break
    fi
done
if [ -z "$PUB_A" ]; then
    echo "[error] could not generate PUB_A < PUB_B after 50 attempts (something is very wrong)"
    exit 1
fi

ADDR_A="$("$YIPD" --addr "$PUB_A")"
ADDR_B="$("$YIPD" --addr "$PUB_B")"
echo "[setup] node_addr A=$ADDR_A B=$ADDR_B (A is the deterministic glare-winner/initiator)"

# ── 2. write config files (rendezvous-only peers: public_key, no endpoint) ────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

cat > "$CFG_A" <<EOF
# yipReplA
local_private=${PRIV_A}
local_public=${PUB_A}
listen=${IP_A}:${PORT_A}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_T_A}:${RDV_PORT}
[peer]
public_key=${PUB_B}
EOF

cat > "$CFG_B" <<EOF
# yipReplB
local_private=${PRIV_B}
local_public=${PUB_B}
listen=${IP_B}:${PORT_B}
device=${TUN_DEV}
device_kind=tun
rendezvous=${IP_T_B}:${RDV_PORT}
[peer]
public_key=${PUB_A}
EOF

# ── 3. create namespaces + point-to-point veths into T ────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"
ip netns add "$NS_T"
ip netns add "$NS_S"

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

echo "[setup] wiring S<->T (S is the off-path attacker namespace)"
ip link add "$VETH_S_T" type veth peer name "$VETH_S_N"
ip link set "$VETH_S_N" netns "$NS_S"
ip link set "$VETH_S_T" netns "$NS_T"
ip netns exec "$NS_S" ip addr add "${IP_S}/${PREFIX}" dev "$VETH_S_N"
ip netns exec "$NS_S" ip link set "$VETH_S_N" up
ip netns exec "$NS_S" ip link set lo up
ip netns exec "$NS_T" ip addr add "${IP_T_S}/${PREFIX}" dev "$VETH_S_T"
ip netns exec "$NS_T" ip link set "$VETH_S_T" up
ip netns exec "$NS_T" ip link set lo up

# A/B/S each default-route via T (their only path off-subnet).
ip netns exec "$NS_A" ip route add default via "$IP_T_A" dev "$VETH_A_N"
ip netns exec "$NS_B" ip route add default via "$IP_T_B" dev "$VETH_B_N"
ip netns exec "$NS_S" ip route add default via "$IP_T_S" dev "$VETH_S_N"

# T routes between all three subnets: this is what makes A and B directly
# reachable (no relay needed) and lets S's replay actually arrive at B.
ip netns exec "$NS_T" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$NS_T" iptables -P FORWARD ACCEPT

# ── 4. start yip-rendezvous in T, bound on all three subnets ──────────────────
LOG_RDV="$TMPDIR_TEST/rdv.log"
echo "[start] starting yip-rendezvous in T on 0.0.0.0:${RDV_PORT}"
ip netns exec "$NS_T" "$RDV" "0.0.0.0:${RDV_PORT}" >"$LOG_RDV" 2>&1 &
PID_RDV=$!
sleep 0.3

# ── 5. start the capture on A's link BEFORE A starts ──────────────────────────
# Must be attached before A's very first cold-start Init (t=0) so that Init
# (the one this test replays) is actually captured. `src host $IP_A and dst
# host $IP_B` restricts the capture to A's own P2P datagrams TO B specifically
# — excluding A's rendezvous Register/Lookup traffic to T. That exclusion is
# not just tidiness: `yip-rendezvous`'s own wire format
# (crates/yip-rendezvous/src/proto.rs) tags `Register` messages with a
# leading byte of `0`, colliding with `PacketType::HandshakeInit as u8 == 0`
# (bin/yipd/src/handshake.rs) — an unfiltered capture's EARLIEST 0x00-prefixed
# datagram would be A's Register call to T, not its cold-start Init to B.
PCAP="$TMPDIR_TEST/replay.pcap"
echo "[capture] starting tcpdump on $VETH_A_N (udp, src host $IP_A, dst host $IP_B) -> $PCAP"
ip netns exec "$NS_A" tcpdump -i "$VETH_A_N" -w "$PCAP" -U udp and src host "$IP_A" and dst host "$IP_B" \
    >"$TMPDIR_TEST/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 0.3

# ── 6. start yipd in A and B with a fast rekey cadence ─────────────────────────
# YIP_REKEY_INTERVAL_MS=2000 (same constant run-netns-rekey.sh uses) so
# several rekey rounds complete during the burn-in ping below, making the
# captured round-1 Init genuinely stale (both in ephemeral and in ts) by the
# time it's replayed -- see the header comment for why that's required to
# actually exercise the freshness gate rather than the retransmit dedup.
export YIP_REKEY_INTERVAL_MS=2000

LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

dump_logs() {
    echo "=== rendezvous log ==="
    cat "$LOG_RDV" || true
    echo "=== yipReplA log ==="
    cat "$LOG_A" || true
    if [ -n "${LOG_A_RESTART:-}" ] && [ -f "$LOG_A_RESTART" ]; then
        echo "=== yipReplA log (post-restart) ==="
        cat "$LOG_A_RESTART" || true
    fi
    echo "=== yipReplB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipReplA (YIP_REKEY_INTERVAL_MS=$YIP_REKEY_INTERVAL_MS)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipReplB (YIP_REKEY_INTERVAL_MS=$YIP_REKEY_INTERVAL_MS)"
ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
PID_B=$!

# ── 7. wait for TUN devices to appear ─────────────────────────────────────────
TUN_WAIT=20
INTERVAL=0.25

wait_for_tun() {
    local ns="$1" label="$2" pid="$3"
    local elapsed=0
    echo "[wait] waiting for $label's TUN device to appear (up to ${TUN_WAIT}s)"
    while true; do
        if ip netns exec "$ns" ip link show "$TUN_DEV" >/dev/null 2>&1; then
            echo "[wait] $label's TUN device is up"
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[error] $label daemon died unexpectedly"; dump_logs; exit 1
        fi
        if ! kill -0 "$PID_RDV" 2>/dev/null; then
            echo "[error] yip-rendezvous died unexpectedly"; dump_logs; exit 1
        fi
        elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
        if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
            echo "[error] timed out waiting for $label's TUN device"; dump_logs; exit 1
        fi
        sleep "$INTERVAL"
    done
}

assign_mesh() {
    local ns="$1" addr="$2"
    ip netns exec "$ns" ip -6 addr add "${addr}/128" dev "$TUN_DEV" 2>/dev/null || true
    ip netns exec "$ns" ip -6 route add fd00::/8 dev "$TUN_DEV" 2>/dev/null || true
    ip netns exec "$ns" ip link show "$TUN_DEV" | grep -q "UP" || \
        ip netns exec "$ns" ip link set "$TUN_DEV" up
}

wait_for_tun "$NS_A" "yipReplA" "$PID_A"
wait_for_tun "$NS_B" "yipReplB" "$PID_B"

echo "[setup] assigning node_addr/128 + fd00::/8 route on each TUN"
assign_mesh "$NS_A" "$ADDR_A"
assign_mesh "$NS_B" "$ADDR_B"

# ── 8. establish + burn in several rekey rounds ───────────────────────────────
# Long enough (>= ~7 rounds at 2000ms) that by the time the capture below is
# extracted, round 1 (the round this test replays) has long since been
# superseded in `epochs.next`, and B's `last_accepted_init_ts` has moved well
# past round 1's ts.
BURNIN_LOG="$TMPDIR_TEST/burnin_ping.log"
echo "[test] establishing + burning in rekey rounds: ping ${ADDR_B} from yipReplA (~14s)"
set +e
ip netns exec "$NS_A" ping -6 -i 0.2 -c 70 -W 1 "$ADDR_B" >"$BURNIN_LOG" 2>&1
BURNIN_STATUS=$?
set -e
cat "$BURNIN_LOG"
if [ "$BURNIN_STATUS" -ne 0 ]; then
    echo "[FAIL] initial establishment / burn-in ping A->B did not succeed (exit $BURNIN_STATUS)"
    dump_logs
    exit 1
fi
echo "[PASS] A<->B established and burned in several rekey rounds"

# ── 9. stop the capture, extract round 1 (now-stale) Init ─────────────────
sleep 0.3
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""

if [ ! -s "$PCAP" ]; then
    echo "[FAIL] capture is empty or missing at $PCAP"
    dump_logs
    exit 1
fi

# PacketType::HandshakeInit as u8 == 0 (bin/yipd/src/handshake.rs), so the
# first byte of a [HandshakeInit] datagram's UDP payload is always 0x00 (no
# obf on this run — see header comment). `udp.length >= 41` (8-byte UDP
# header + a 33-byte minimum [PacketType][32-byte ephemeral] payload, the
# same MIN_HANDSHAKE_LEN bin/yipd/examples/rekey_epoch_witness.rs uses) is a
# defense-in-depth belt to the capture filter's dst-host suspenders above,
# in case anything else ever emits a short 0x00-prefixed datagram on this
# link.
#
# Take the SECOND such frame (round 1: A's first rekey round), not the
# first (round 0: the cold-start Init) -- see the header comment's "forcing
# the replay through the freshness gate" section for why round 0 would
# always hit the sticky `cached_resp_init_eph` dedup instead, no matter how
# stale it is. Non-vacuity: need >=3 captured Inits (round 0 + round 1 +
# something that supersedes round 1's `next` slot), else round 1 could
# still be the CURRENT round at replay time.
INIT_FRAMES="$TMPDIR_TEST/init_frames.txt"
tshark -r "$PCAP" -Y "udp && udp.payload[0:1] == 00 && udp.length >= 41" \
    -T fields -e udp.payload 2>/dev/null | tr -d ':' > "$INIT_FRAMES"
INIT_FRAME_COUNT="$(wc -l < "$INIT_FRAMES" | tr -d ' ')"
echo "[check] captured $INIT_FRAME_COUNT HandshakeInit frame(s) from A during burn-in"
if [ "$INIT_FRAME_COUNT" -lt 3 ]; then
    echo "[FAIL] only $INIT_FRAME_COUNT Init frame(s) captured (need >=3: cold-start + a round to replay + a round that supersedes it) — burn-in did not produce enough rekey rounds"
    dump_logs
    exit 1
fi
INIT_HEX="$(sed -n '2p' "$INIT_FRAMES")"
if [ -z "$INIT_HEX" ]; then
    echo "[FAIL] could not extract round 1's captured [HandshakeInit] payload from $PCAP"
    dump_logs
    exit 1
fi
echo "[check] captured round-1 Init to replay: ${#INIT_HEX} hex chars"

# ── 10. replay the captured Init from S (a different, real address) at B,
# concurrently with a steady ping A->B, and assert no session disruption ────
REPLAY_PY="$TMPDIR_TEST/replay.py"
cat > "$REPLAY_PY" <<'PYEOF'
import socket
import sys

hex_payload, dst_ip, dst_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
payload = bytes.fromhex(hex_payload)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(payload, (dst_ip, dst_port))
s.close()
PYEOF

HIJACK_PING_LOG="$TMPDIR_TEST/hijack_ping.log"
echo "[test] pinging ${ADDR_B} from yipReplA while S replays the captured Init at B"
set +e
ip netns exec "$NS_A" ping -6 -i 0.2 -c 40 -W 1 "$ADDR_B" >"$HIJACK_PING_LOG" 2>&1 &
PING_PID=$!
sleep 1.5
echo "[attack] S (${IP_S}) replaying captured round-1 Init at B (${IP_B}:${PORT_B})"
ip netns exec "$NS_S" python3 "$REPLAY_PY" "$INIT_HEX" "$IP_B" "$PORT_B"
REPLAY_STATUS=$?
wait "$PING_PID"
PING_STATUS=$?
set -e
cat "$HIJACK_PING_LOG"

if [ "$REPLAY_STATUS" -ne 0 ]; then
    echo "[FAIL] the replay send from S failed (exit $REPLAY_STATUS)"
    dump_logs
    exit 1
fi

if ! kill -0 "$PID_A" 2>/dev/null; then
    echo "[error] yipReplA daemon died during the replay"; dump_logs; exit 1
fi
if ! kill -0 "$PID_B" 2>/dev/null; then
    echo "[error] yipReplB daemon died during the replay"; dump_logs; exit 1
fi

LOSS_PCT="$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' "$HIJACK_PING_LOG" | grep -oE '^[0-9]+(\.[0-9]+)?' || true)"
if [ -z "$LOSS_PCT" ]; then
    echo "[FAIL] no_disruption: could not parse packet loss from ping output"
    dump_logs
    exit 1
fi
echo "[metric] no_disruption: packet loss during replay = ${LOSS_PCT}%"
if awk "BEGIN {exit ($LOSS_PCT <= 1.0) ? 0 : 1}"; then
    echo "[PASS] no_disruption: ${LOSS_PCT}% loss (<=1%) across the replay -- B's live session with A was not disrupted"
else
    echo "[FAIL] no_disruption: ${LOSS_PCT}% loss (>1%) -- the replay may have disrupted B's session with A"
    dump_logs
    exit 1
fi
if [ "$PING_STATUS" -ne 0 ] && [ "$LOSS_PCT" != "100" ]; then
    echo "[note] ping exited $PING_STATUS despite <=1% loss (non-fatal; proceeding)"
fi

# ── assertion: the replay was actually refused by the freshness gate ────────
if grep -q "stale/replayed Init refused (freshness gate)" "$LOG_B"; then
    echo "[PASS] freshness_gate_refusal: B's stderr shows the replay was refused"
else
    echo "[FAIL] freshness_gate_refusal: no freshness-gate marker in B's stderr -- the replay was not observed to be refused there"
    dump_logs
    exit 1
fi

# ── 11. restart leg: kill A, restart it, assert bounded recovery ────────────
echo "[test] restart leg: killing yipReplA"
kill "$PID_A" 2>/dev/null || true
sleep 0.3
kill -9 "$PID_A" 2>/dev/null || true
wait "$PID_A" 2>/dev/null || true
PID_A=""

# Killing the process tears down its TUN device (non-persistent); wait for it
# to actually disappear before restarting, so the "wait for TUN" loop below
# isn't fooled by the old interface still lingering.
TUN_GONE_WAIT=10
elapsed=0
while ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1; do
    elapsed=$(awk "BEGIN {print $elapsed + 0.25}")
    if awk "BEGIN {exit ($elapsed >= $TUN_GONE_WAIT) ? 0 : 1}"; then
        echo "[error] yipReplA's old TUN device did not disappear after kill"; dump_logs; exit 1
    fi
    sleep 0.25
done

LOG_A_RESTART="$TMPDIR_TEST/yipA-restart.log"
echo "[start] restarting yipReplA (same identity, fresh ephemeral + newer ts on its next Init)"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A_RESTART" 2>&1 &
PID_A=$!

wait_for_tun "$NS_A" "yipReplA (restarted)" "$PID_A"
assign_mesh "$NS_A" "$ADDR_A"

RESTART_PING_LOG="$TMPDIR_TEST/restart_ping.log"
# Generous bound (worst case ~60s): still far under the pre-#34 stuck state
# (bounded only by the responder's own attempt timeout), and ping's own exit
# code already only requires >=1 reply, so no `|| true` is needed to keep the
# measured result load-bearing.
echo "[test] restart recovery: pinging ${ADDR_B} from restarted yipReplA (bounded window)"
set +e
ip netns exec "$NS_A" ping -6 -c 30 -W 2 "$ADDR_B" >"$RESTART_PING_LOG" 2>&1
RESTART_PING_STATUS=$?
set -e
cat "$RESTART_PING_LOG"

if [ "$RESTART_PING_STATUS" -ne 0 ]; then
    echo "[FAIL] restart_recovery: ping A->B did not resume after A's restart (exit $RESTART_PING_STATUS)"
    dump_logs
    exit 1
fi
echo "[PASS] restart_recovery: A<->B re-established within the bounded ping window"

echo "[PASS] run-netns-replay-hijack: replay refused with no session disruption, restart recovered"
