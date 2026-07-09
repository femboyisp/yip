#!/usr/bin/env bash
# Lightweight deterministic flow-shape structural check for the 3b junk
# burst (Task 7, Deliverable 2).
# Usage: run-flowshape-check.sh <path-to-yipd-binary>
#
# This is NOT the nDPId -A ML harness — it is a packet-count analogue of
# 3a's `no_byte_position_is_constant` test: bring up two yipd in separate
# netns with obf_psk set (reusing the run-ndpi-oracle.sh setup shape, on a
# neutral port), and for N independent sessions (fresh handshake each —
# each session gets its own netns/veth pair so the daemons are genuinely
# restarted and every Jc junk burst is redrawn), tcpdump the underlay and
# measure the handshake-phase datagram count before data/control-feedback
# traffic settles into its steady periodic cadence.
#
# IMPORTANT — there is no single "initiator": the `initiate=` config key was
# dropped in 2a (bin/yipd/src/config.rs silently ignores it; see git history
# for the drop). Both peers bootstrap-initiate a handshake independently at
# startup and glare-resolve by static-key comparison (peer_manager.rs, the
# `Glare:` comment). With obf_psk set, EACH side's `begin_handshake` prepends
# its own burst of `Jc ∈ [JUNK_BURST_MIN, JUNK_BURST_MAX] = [3, 12]` plaintext
# junk datagrams ahead of its `[HandshakeInit]` (peer_manager.rs), so in
# practice both bursts interleave on the wire within microseconds of process
# start, followed (once the glare tie is broken) by a single `[HandshakeResp]`
# — verified empirically: capturing a real session and computing inter-packet
# gaps shows a tight cluster of sub-millisecond gaps (the two bursts + Init(s)
# + Resp) followed by a hard cutover to the periodic ~22-38ms
# Control-feedback cadence (`FEEDBACK_INTERVAL_MS` jittered under obf_psk,
# bin/yipd/src/dataplane.rs) that starts ticking in both directions forever
# afterward, data or no data.
#
# That inter-packet-gap structure is what this script measures, and it is
# what makes the count deterministic to compute regardless of which side
# ends up as Noise responder: read the capture in arrival order and count
# the leading run of datagrams whose inter-arrival gap never exceeds a fixed
# threshold (5 ms — two orders of magnitude above the observed intra-burst
# gaps of low single-digit microseconds, and well below the lowest possible
# steady-state feedback gap of ~22.5 ms). That leading run IS the
# handshake-phase: both sides' junk bursts, their Init(s), and the Resp.
#
# Assertions (see CONTROLLER ADDENDUM, Deliverable 2, in
# .superpowers/sdd/task-7-brief.md for the empirical basis):
#   (a) HARD, per-session: the handshake-phase datagram count is > 4. This
#       is NOT ">2 => junk present" — both peers glare-initiate (each
#       self-initiates at bring-up; the loser's Init still reaches the wire
#       before glare-resolution — see peer_manager.rs's `Glare:` comment),
#       so a JUNK-FREE two-sided-glare handshake already puts Init(A) +
#       Init(B) + Resp = 3 datagrams on the wire before data, and a >2
#       threshold would pass even with junk disabled. 4 sits strictly above
#       that junk-free glare baseline (with a +1 retransmit margin) and
#       strictly below the observed junk-present minimum (~7-8, clipped
#       down from the ~9 theoretical floor of 2*(JUNK_BURST_MIN+1)+1 by the
#       leading-gap window occasionally swallowing the trailing Resp). So
#       gate (a) shows the opener carries MORE datagrams than a junk-free
#       glare handshake would — i.e. junk is present — without false-failing
#       on Resp-clipping.
#   (b) HARD, across sessions: the N counts are not all identical — i.e.
#       take > 1 distinct value. Gate (a) alone only proves junk is present
#       on top of the glare baseline; it says nothing about whether that
#       junk is randomized. Gate (b) is the primary non-vacuous proof that
#       the Jc burst actually varies the opener's shape: if junk were
#       disabled (or fixed-size), the handshake-phase count would be the
#       same constant every session (2-sided glare always yields exactly 3
#       junk-free datagrams), so gate (b) would fail. This is NOT a claim of
#       "provably unclassifiable" traffic; it only shows the handshake
#       opener's packet cardinality is not obviously constant (both Jc
#       bursts are redrawn per handshake), which is what would make
#       packet-count-based fingerprinting of the opener unreliable.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary>}"

# Root-gated SKIP: netns + tcpdump both need CAP_NET_ADMIN/root. Matches the
# honesty-guard SKIP string convention used across run-netns-*.sh /
# run-ndpi-oracle.sh (and checked verbatim by their Rust callers / CI).
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP flowshape_not_obviously_constant: needs root"
    exit 0
fi

# N >= 5 per the brief; use 8 for a negligible (~1e-4) false-fail probability
# on assertion (b) even under adversarial-looking bad luck.
N=8

# Inter-packet-gap threshold (seconds) separating the handshake-phase burst
# from the steady-state Control-feedback cadence. Empirically: intra-burst
# gaps are low single-digit microseconds (occasionally ~0.2-0.4ms while a
# side computes its Resp); the steady-state cadence never goes below
# ~10ms in practice (its floor is FEEDBACK_INTERVAL_MS jittered to
# ~22.5ms, minus scheduling slop) and is usually 20-30ms. 5ms sits with
# an order of magnitude of margin on both sides.
GAP_THRESHOLD_S="0.005"

TMPDIR_TEST="$(mktemp -d /tmp/yipd-flowshape-test.XXXXXX)"

VETH_A_IP="10.0.12.1"
VETH_B_IP="10.0.12.2"
VETH_PREFIX="24"
# NEUTRAL port, matching run-ndpi-oracle.sh's rationale: irrelevant here
# (this script never invokes nDPI), kept neutral anyway for consistency
# with the rest of the obf-on test suite.
PORT="34568"
TUN_DEV="yip0"
OBF_PSK="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

CUR_NS_A=""
CUR_NS_B=""
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
    [ -n "$CUR_NS_A" ] && ip netns del "$CUR_NS_A" 2>/dev/null || true
    [ -n "$CUR_NS_B" ] && ip netns del "$CUR_NS_B" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── keypairs + config (fixed across sessions; only the netns/veth pair and
# the daemon processes are fresh per session) ─────────────────────────────
echo "[setup] generating keypairs"
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"
PRIV_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

# `initiate=` is a dead key (silently ignored by config.rs, kept in the
# fixture only for readability/consistency with the other run-netns-*.sh
# scripts) — both peers actually bootstrap-initiate; see the header comment.
cat > "$CFG_A" <<EOF
# yipA (obf_psk on, neutral port)
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
# yipB (obf_psk on, neutral port)
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VETH_B_IP}:${PORT}
peer_endpoint=${VETH_A_IP}:${PORT}
device=${TUN_DEV}
initiate=true
obf_psk=${OBF_PSK}
EOF

COUNTS=()

for i in $(seq 1 "$N"); do
    NS_A="yipFsA${i}"
    NS_B="yipFsB${i}"
    VETH_A="vfsA${i}"
    VETH_B="vfsB${i}"
    CUR_NS_A="$NS_A"
    CUR_NS_B="$NS_B"

    echo "[session $i/$N] creating netns + veth pair"
    ip netns add "$NS_A"
    ip netns add "$NS_B"
    ip link add "$VETH_A" netns "$NS_A" type veth peer name "$VETH_B" netns "$NS_B"

    ip netns exec "$NS_A" ip addr add "${VETH_A_IP}/${VETH_PREFIX}" dev "$VETH_A"
    ip netns exec "$NS_A" ip link set "$VETH_A" up
    ip netns exec "$NS_A" ip link set lo up

    ip netns exec "$NS_B" ip addr add "${VETH_B_IP}/${VETH_PREFIX}" dev "$VETH_B"
    ip netns exec "$NS_B" ip link set "$VETH_B" up
    ip netns exec "$NS_B" ip link set lo up

    # Capture on A's end of the veth — sees both directions of the pair —
    # BEFORE either daemon starts, so packet zero (the first junk datagram,
    # from whichever side the kernel schedules first) is captured.
    PCAP="$TMPDIR_TEST/session-$i.pcap"
    echo "[session $i/$N] starting tcpdump inside $NS_A on $VETH_A (port $PORT)"
    ip netns exec "$NS_A" tcpdump -i "$VETH_A" -w "$PCAP" -U "udp port $PORT" \
        >"$TMPDIR_TEST/tcpdump-$i.log" 2>&1 &
    TCPDUMP_PID=$!
    sleep 0.3

    LOG_A="$TMPDIR_TEST/yipA-$i.log"
    LOG_B="$TMPDIR_TEST/yipB-$i.log"

    echo "[session $i/$N] starting yipA + yipB"
    ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
    PID_A=$!
    ip netns exec "$NS_B" "$YIPD" "$CFG_B" >"$LOG_B" 2>&1 &
    PID_B=$!

    # Wait for both TUN devices to come up — that is the handshake
    # completing. No tunnel IPs are assigned and no ping is driven, but once
    # established both sides start ticking Control-feedback on their own
    # (dataplane.rs `tick`, unconditional on data flow) — the capture keeps
    # running a little past this point on purpose, to also record a few
    # steady-state datagrams; the gap-based count below discards them.
    TUN_WAIT_TRIES=40
    tries=0
    while true; do
        A_UP=0
        B_UP=0
        ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A_UP=1 || true
        ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B_UP=1 || true
        if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ]; then
            break
        fi
        if ! kill -0 "$PID_A" 2>/dev/null; then
            echo "[error] session $i: yipA daemon died unexpectedly"
            echo "=== yipA log ==="; cat "$LOG_A" || true
            exit 1
        fi
        if ! kill -0 "$PID_B" 2>/dev/null; then
            echo "[error] session $i: yipB daemon died unexpectedly"
            echo "=== yipB log ==="; cat "$LOG_B" || true
            exit 1
        fi
        tries=$((tries + 1))
        if [ "$tries" -ge "$TUN_WAIT_TRIES" ]; then
            echo "[error] session $i: timed out waiting for TUN devices to come up"
            echo "=== yipA log ==="; cat "$LOG_A" || true
            echo "=== yipB log ==="; cat "$LOG_B" || true
            exit 1
        fi
        sleep 0.25
    done

    # tcpdump's userspace read loop can lag real kernel packet delivery by
    # up to ~1s under scheduling contention (observed empirically: the BPF
    # filter's kernel-side "packets received" counter updates immediately,
    # but the pcap file can sit at just its empty-file header for a while
    # after that). Poll the growing pcap file for its first real growth
    # beyond the empty-file header (24 bytes) instead of assuming a fixed
    # short grace is enough — bounded so a genuine capture failure (no
    # packets at all) still times out and fails loudly rather than hanging.
    PCAP_WAIT_TRIES=40 # 40 * 0.25s = 10s max
    tries=0
    while true; do
        SIZE="$(stat -c%s "$PCAP" 2>/dev/null || echo 0)"
        if [ "$SIZE" -gt 24 ]; then
            break
        fi
        tries=$((tries + 1))
        if [ "$tries" -ge "$PCAP_WAIT_TRIES" ]; then
            echo "[error] session $i: tcpdump captured no packets within timeout (pcap still $SIZE bytes)"
            cat "$TMPDIR_TEST/tcpdump-$i.log" || true
            exit 1
        fi
        sleep 0.25
    done
    # Short fixed buffer past first growth: the burst itself is
    # sub-millisecond internally (see header comment) — this only needs to
    # outlast tcpdump's own per-packet write latency, plus give at least
    # one steady-state Control-feedback gap for the counting algorithm's
    # cutoff marker.
    sleep 0.5

    # SIGTERM then a full second of grace so tcpdump's pcap writer actually
    # flushes before the file is read — a short grace here previously raced
    # the writer (kernel-side "packets received by filter" stats update
    # instantly, but the flush to disk does not) and silently produced
    # empty/truncated captures. Only escalate to SIGKILL if it is still
    # alive after that.
    kill "$TCPDUMP_PID" 2>/dev/null || true
    sleep 1
    if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        kill -9 "$TCPDUMP_PID" 2>/dev/null || true
    fi
    TCPDUMP_PID=""

    kill "$PID_A" 2>/dev/null || true
    kill "$PID_B" 2>/dev/null || true
    sleep 0.2
    kill -9 "$PID_A" 2>/dev/null || true
    kill -9 "$PID_B" 2>/dev/null || true
    PID_A=""
    PID_B=""

    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    CUR_NS_A=""
    CUR_NS_B=""

    if [ ! -s "$PCAP" ]; then
        echo "[error] session $i: capture is empty or missing at $PCAP"
        cat "$TMPDIR_TEST/tcpdump-$i.log" || true
        exit 1
    fi

    # Handshake-phase datagram count = the leading run of packets (in
    # capture order, both directions) whose inter-arrival gap never exceeds
    # GAP_THRESHOLD_S. This is a deterministic function of the pcap's own
    # packet timestamps — integer in, integer out, no ML/heuristics — and
    # is robust to which side wins the glare tie-break (see header comment).
    COUNT="$(tcpdump -tt -r "$PCAP" -nn 2>/dev/null | awk -v thresh="$GAP_THRESHOLD_S" '
        NR == 1 { count = 1; prev = $1; next }
        {
            gap = $1 - prev
            if (gap > thresh) { exit }
            count++
            prev = $1
        }
        END { print count + 0 }
    ')"
    echo "[session $i/$N] handshake-phase datagram count = $COUNT"
    COUNTS+=("$COUNT")
done

echo "[result] per-session handshake-phase counts: ${COUNTS[*]}"

FAIL=0

# HARD gate (a): junk present in every session — count > 4. This threshold
# sits strictly above the junk-free two-sided-glare baseline of 3 datagrams
# (Init(A) + Init(B) + Resp, +1 retransmit margin) and strictly below the
# observed junk-present minimum (~7-8), so it robustly distinguishes "junk
# present" from "junk-free glare handshake" without false-failing on
# occasional Resp-clipping. See the header comment for the full derivation.
for idx in "${!COUNTS[@]}"; do
    c="${COUNTS[$idx]}"
    session_num=$((idx + 1))
    if [ "$c" -le 4 ]; then
        echo "[FAIL] gate (a): session $session_num count=$c is <= 4 — at or below the junk-free two-sided-glare baseline (3, +1 margin); junk burst did not reach the wire"
        FAIL=1
    fi
done
if [ "$FAIL" -eq 0 ]; then
    echo "[PASS] gate (a): every session's handshake-phase count is > 4 (above the junk-free two-sided-glare baseline of 3 — junk present)"
fi

# HARD gate (b): not obviously constant — the N counts take > 1 distinct
# value (both sides' Jc in [3, 12] bursts are redrawn per handshake). This
# is the primary non-vacuous proof of randomization: a junk-free (or
# fixed-size-junk) two-sided-glare handshake would produce the SAME count
# every session, so gate (b) is what would actually fail if junk were
# disabled — gate (a) alone only proves "more than the glare baseline",
# not "randomized".
DISTINCT="$(printf '%s\n' "${COUNTS[@]}" | sort -u | wc -l)"
if [ "$DISTINCT" -le 1 ]; then
    echo "[FAIL] gate (b): all $N sessions produced the identical handshake-phase count — handshake cardinality looks constant"
    FAIL=1
else
    echo "[PASS] gate (b): $DISTINCT distinct handshake-phase counts across $N sessions — no obviously-constant handshake cardinality (Jc junk randomizes the opener)"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "[FAIL] flow-shape structural check FAILED — see gate output above"
    exit 1
fi

echo "[PASS] flow-shape structural check PASSED: obf-on handshake opener carries more datagrams than a junk-free two-sided-glare handshake (>4, gate a) and shows no obviously-constant handshake cardinality across independent sessions (gate b, the primary proof of randomization)"
