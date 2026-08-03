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
# junk datagrams ahead of its `[HandshakeInit]` (peer_manager.rs), so within
# microseconds of process start each side emits a dense sub-millisecond burst
# (its Jc junk + Init), the two bursts separated by a short scheduling handoff,
# then (once the glare tie is broken) the Noise completion / `[HandshakeResp]`
# messages — also dense but after a ~30ms round-trip wait. Eventually the
# periodic Control-feedback cadence takes over (`FEEDBACK_INTERVAL_MS`=30ms
# jittered to [23, 37]ms under obf_psk, bin/yipd/src/dataplane.rs), ticking in
# both directions forever afterward, data or no data. The exact structure and
# why the boundary is NOT a single clean gap are detailed in the MEASUREMENT
# block below.
#
# MEASUREMENT — count the handshake DENSE-CLUSTER SPAN, not a gap-cutoff run.
# An earlier version stopped the count at the first inter-packet gap above a
# fixed threshold ("leading run"). That is not robust: empirically the
# handshake phase is NOT one uninterrupted dense run separated from steady
# state by a single big gap. A real idle capture (both directions, in arrival
# order) looks like:
#   * a dense burst from one side (its Jc junk + Init), gaps ~microseconds;
#   * a ~5 ms scheduling handoff, then the other side's dense burst;
#   * a ~30 ms round-trip WAIT (inside the handshake) before the Noise
#     completion / Resp messages, which are themselves dense;
#   * only then steady-state feedback: two independent ~30 ms streams whose
#     merged inter-packet gaps swing between ~0 ms (coincident cross-response
#     pairs) and ~30 ms.
# So gap MAGNITUDE alone cannot say which phase a packet is in: a ~30 ms gap
# occurs INSIDE the handshake (the round-trip wait) and coincident sub-ms
# pairs occur INSIDE steady state. Any single gap threshold either truncates
# the handshake mid-burst on a scheduling stall (the CI flake this replaced —
# a burst of ~20 datagrams was counted as 4) or plows deep into steady state.
#
# The reliable discriminator is CLUSTER DENSITY: the handshake phase is built
# of dense clusters of >= MIN_CLUSTER packets spaced < DENSE_GAP_S apart (both
# junk bursts, both Inits, and the Noise completion), whereas steady state
# never forms a run of 3 packets that close — at most a coincident PAIR. So
# the count is the index of the LAST packet belonging to a >= MIN_CLUSTER
# dense cluster. This is robust to scheduling stalls: a stall merely splits
# one dense cluster into two (both still counted, since we anchor on the last
# qualifying cluster, not a leading run), and it never mistakes steady state
# for handshake (steady state has no >= 3 dense run). Empirically stable:
# across 20+ captures on an idle box AND under 2x CPU oversubscription the
# count never dropped into the gate's failure band, where the naive
# gap-cutoff hit 4.
#
# Assertions (see CONTROLLER ADDENDUM, Deliverable 2, in
# .superpowers/sdd/task-7-brief.md for the original empirical basis; the
# numbers below were re-derived for the cluster-span measurement by capturing
# junk-on vs junk-off sessions, idle and under load — see the CLUSTER_MIN
# comment):
#   (a) HARD, per-session: the dense-cluster span is > CLUSTER_MIN (12).
#       Junk-OFF (obf_psk unset) still produces a dense handshake cluster —
#       the 3 Noise messages plus retransmits and the completion exchange —
#       measured empirically at 6-10 datagrams. Junk-ON adds both sides' Jc
#       bursts (Jc in [3,12] each) and measures 15-32. So >12 sits strictly
#       above the junk-OFF ceiling (10) and strictly below the junk-ON floor
#       (15): it proves the opener carries MORE datagrams than a junk-free
#       handshake would, i.e. junk is present. (A bare ">2 => junk present"
#       or the old ">4" would BOTH pass junk-off here, since the junk-free
#       dense handshake alone already reaches ~10 — the cluster measurement
#       counts the whole dense handshake, not just the leading Init(s).)
#   (b) HARD, across sessions: the N counts are not all identical — i.e.
#       take > 1 distinct value. Gate (a) alone only proves junk is present;
#       it says nothing about whether that junk is randomized. Gate (b) is
#       the primary non-vacuous proof that the Jc burst actually varies the
#       opener's shape: fixed-size (or disabled) junk yields a near-constant
#       span every session (junk-off clusters at a tight 9-10), so gate (b)
#       would fail. This is NOT a claim of "provably unclassifiable" traffic;
#       it only shows the handshake opener's packet cardinality is not
#       obviously constant (both Jc bursts are redrawn per handshake), which
#       is what would make packet-count-based fingerprinting of the opener
#       unreliable.
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

# Dense-cluster parameters (see the MEASUREMENT block in the header).
#
# DENSE_GAP_S: two consecutive datagrams belong to the same dense cluster if
# their inter-arrival gap is below this. Empirically the valley is between
# intra-cluster gaps (mostly microseconds, spiking to ~2.8ms under load) and
# the nearest separator gap (>= ~3.8ms under load, usually >= 5ms). 1ms sits
# in that valley; the choice is not delicate because we anchor on the LAST
# qualifying cluster, not a leading run — 0.5ms, 1ms and 2ms produced an
# IDENTICAL count on every one of 20+ idle-and-loaded captures.
DENSE_GAP_S="0.001"
# MIN_CLUSTER: a run of at least this many datagrams closer than DENSE_GAP_S
# apart counts as a handshake dense cluster. Steady-state feedback (two
# independent ~30ms streams) never puts 3 datagrams that close — at most a
# coincident cross-response pair — so 3 excludes steady state while including
# every junk burst / Init / completion cluster.
MIN_CLUSTER=3
# CLUSTER_MIN: gate (a) requires each session's span to exceed this. Junk-OFF
# spans measured 6-10 (the junk-free dense handshake); junk-ON 15-32. 12 sits
# strictly between (junk-off ceiling 10, junk-on floor 15).
CLUSTER_MIN=12

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

    # Handshake dense-cluster span = the index of the LAST datagram (in
    # capture order, both directions) that belongs to a run of >= MIN_CLUSTER
    # datagrams spaced < DENSE_GAP_S apart. This is a deterministic function
    # of the pcap's own packet timestamps — integer in, integer out, no
    # ML/heuristics — robust to which side wins the glare tie-break and to
    # scheduling stalls (a stall only splits one dense cluster into two, both
    # of which precede the anchor). See the header MEASUREMENT block for why
    # this beats a gap-cutoff leading run.
    #
    # Emits three fields: the span count, and two DIAGNOSTIC-ONLY values that
    # gate nothing but make a future failure self-explaining — the largest
    # intra-cluster gap (< 3ms) and the smallest separator gap (>= 3ms), i.e.
    # the two walls of the density valley. If they ever cross (max intra >=
    # min separator) the DENSE_GAP_S assumption has broken and the count is
    # untrustworthy; normally they straddle DENSE_GAP_S comfortably.
    read -r COUNT MAXDENSE MINSEP < <(tcpdump -tt -r "$PCAP" -nn 2>/dev/null | awk \
        -v dense="$DENSE_GAP_S" -v minc="$MIN_CLUSTER" '
        { t[NR] = $1 }
        END {
            n = NR
            last = 0; cs = 1
            maxdense = 0; minsep = 999
            for (i = 2; i <= n; i++) {
                g = t[i] - t[i-1]
                if (g < dense) { cs++ }
                else { if (cs >= minc) last = i - 1; cs = 1 }
                if (g < 0.003 && g > maxdense) maxdense = g
                if (g >= 0.003 && g < minsep) minsep = g
            }
            if (cs >= minc) last = n
            printf "%d %.3f %.3f\n", last, maxdense * 1000, minsep * 1000
        }
    ')
    echo "[session $i/$N] handshake dense-cluster span = $COUNT datagrams (density valley: max intra-cluster gap ${MAXDENSE}ms < min separator gap ${MINSEP}ms; DENSE_GAP_S=${DENSE_GAP_S}s)"
    COUNTS+=("$COUNT")
done

echo "[result] per-session handshake dense-cluster spans: ${COUNTS[*]}"

FAIL=0

# HARD gate (a): junk present in every session — span > CLUSTER_MIN. The
# junk-free dense handshake alone measures 6-10; both sides' Jc bursts lift it
# to 15-32. CLUSTER_MIN (12) sits strictly between, so this distinguishes
# "junk present" from "junk-free handshake". See the header comment for the
# full derivation and the junk-on/junk-off measurements.
for idx in "${!COUNTS[@]}"; do
    c="${COUNTS[$idx]}"
    session_num=$((idx + 1))
    if [ "$c" -le "$CLUSTER_MIN" ]; then
        echo "[FAIL] gate (a): session $session_num span=$c is <= CLUSTER_MIN ($CLUSTER_MIN) — within the junk-free dense-handshake range (6-10); junk burst did not reach the wire"
        FAIL=1
    fi
done
if [ "$FAIL" -eq 0 ]; then
    echo "[PASS] gate (a): every session's dense-cluster span is > CLUSTER_MIN ($CLUSTER_MIN) — above the junk-free dense-handshake ceiling of 10, junk present"
fi

# HARD gate (b): not obviously constant — the N spans take > 1 distinct
# value (both sides' Jc in [3, 12] bursts are redrawn per handshake). This
# is the primary non-vacuous proof of randomization: a junk-free (or
# fixed-size-junk) handshake produces a near-constant span every session
# (junk-off clusters at a tight 9-10), so gate (b) is what would actually
# fail if junk were disabled — gate (a) alone only proves "more than the
# junk-free handshake", not "randomized".
DISTINCT="$(printf '%s\n' "${COUNTS[@]}" | sort -u | wc -l)"
if [ "$DISTINCT" -le 1 ]; then
    echo "[FAIL] gate (b): all $N sessions produced the identical dense-cluster span — handshake cardinality looks constant"
    FAIL=1
else
    echo "[PASS] gate (b): $DISTINCT distinct dense-cluster spans across $N sessions — no obviously-constant handshake cardinality (Jc junk randomizes the opener)"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "[FAIL] flow-shape structural check FAILED — see gate output above"
    exit 1
fi

echo "[PASS] flow-shape structural check PASSED: obf-on handshake opener carries more datagrams than a junk-free handshake (span > CLUSTER_MIN, gate a) and shows no obviously-constant handshake cardinality across independent sessions (gate b, the primary proof of randomization)"
