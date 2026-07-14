#!/usr/bin/env bash
# Probe-resistance money test for the 3c.3 REALITY-style relay TLS front.
#
# This is the headline property of 3c.3: an ACTIVE prober (a real `curl`
# client, an `openssl s_client` sending garbage bytes, or simply an idle
# connection) must see nothing but an ordinary decoy web server — never any
# rendezvous/tunnel behavior, and never a relay-shaped *timing* signature
# either. Unlike run-tls-mimicry-oracle.sh (3c.2, which proves nDPI
# classifies yipd's TLS costume as real TLS by content), this script proves
# the ACTIVE half of the threat model: what does a censor see when it dials
# the relay itself and prods it? The relay presents a real CA-style
# self-signed cert with a real SNI (relay.test) here, so nDPI's passive
# "is this TLS" classification is trivially satisfied and is not
# re-asserted (see spec §7 / task-8-brief.md) — the novel, testable claim
# this script gates is probe -> decoy, plus no classification-timeout close.
#
# Usage: run-netns-reality-probe.sh <path-to-yip-rendezvous-binary>
#
# Topology: a single netns (only loopback is used — the relay, the decoy,
# and every probing client all run inside it) so the whole exchange stays
# off the host's network stack, mirroring the root-gated netns/veth
# structure of run-quic-mimicry-oracle.sh even though no veth pair is
# needed for a loopback-only scenario.
#
# Assertions:
#   (a) HARD: PROBE -> DECOY. `curl -sk https://127.0.0.1:8443/` (a stand-in
#       for a censor's active TLS probe / vanilla HTTPS client) receives the
#       decoy site's real index.html body, not any rendezvous/tunnel bytes.
#   (b) HARD: GARBAGE -> DECOY. A connection that sends a few non-HTTP,
#       non-rendezvous bytes over TLS is handled (proxied to the decoy)
#       without hanging past a bounded timeout, does not crash the relay
#       process, AND — the same rigor as gate (a) — is POSITIVELY confirmed
#       by content to have been routed to the decoy: the captured reply must
#       contain the decoy backend's own HTTP response marker. "No hang, no
#       crash" alone would not catch a regression where garbage got
#       misclassified into a rendezvous-shaped reply, so this gate also
#       asserts on the reply bytes.
#   (c) HARD: TIMING PARITY. An idle TLS connection (no bytes sent either
#       way) is NOT closed by the relay at its ~3s internal classification
#       timeout (see bin/yip-rendezvous/src/conn.rs CLASSIFY_TIMEOUT) — it
#       must still be open at >=5s, proving the classification deadline is
#       an internal decision boundary, not an observable close signature.
#       NOTE (#63, filed follow-up): a fully-silent connection's *decoy
#       connect* is only dialed once the 3s classification timeout fires,
#       so the first byte of the decoy's response is delayed by up to ~3s
#       relative to a real web server dialing its backend immediately. That
#       sub-second timing-parity gap is a KNOWN, tracked follow-up — this
#       gate does NOT assert sub-second parity, only that the relay itself
#       does not hard-close the connection at the classification boundary.
set -euo pipefail

RDV="${1:?Usage: $0 <yip-rendezvous-binary>}"

# Root-gated SKIP: netns needs CAP_NET_ADMIN/root. The Rust harness already
# checks this before invoking the script, but this script SKIPs cleanly too
# so it stays safe to run standalone.
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-netns-reality-probe: needs root (netns)"
    exit 0
fi

if [ ! -x "$RDV" ]; then
    echo "SKIP run-netns-reality-probe: yip-rendezvous binary not found/executable at $RDV"
    exit 0
fi

for tool in openssl curl python3 ip; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP run-netns-reality-probe: required tool '$tool' not found"
        exit 0
    fi
done

TMPDIR_TEST="$(mktemp -d /tmp/yip-rdv-reality-probe-test.XXXXXX)"

NS="yipRealityP"

RDV_UDP_PORT="51821"
RDV_TCP_PORT="8443"
DECOY_PORT="8080"

PID_RDV=""
PID_DECOY=""

cleanup() {
    echo "[cleanup] killing daemons, removing namespace"
    # Close our end of the idle-connection fifo, if it's still open, so the
    # backgrounded openssl process (if any survived) isn't left blocked.
    exec 9>&- 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill "$PID_RDV" 2>/dev/null || true
    [ -n "$PID_DECOY" ] && kill "$PID_DECOY" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_RDV" ] && kill -9 "$PID_RDV" 2>/dev/null || true
    [ -n "$PID_DECOY" ] && kill -9 "$PID_DECOY" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. netns (loopback only) ──────────────────────────────────────────────
echo "[setup] creating network namespace"
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

# ── 2. self-signed cert for relay.test ──────────────────────────────────────
echo "[setup] generating self-signed cert for relay.test"
CERT="$TMPDIR_TEST/cert.pem"
KEY="$TMPDIR_TEST/key.pem"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CERT" \
    -days 1 -subj '/CN=relay.test' >"$TMPDIR_TEST/openssl-req.log" 2>&1

# ── 3. decoy HTTP server: a real static site with a known marker ───────────
echo "[setup] preparing decoy site + starting decoy HTTP server"
DECOY_DIR="$TMPDIR_TEST/decoy-site"
mkdir -p "$DECOY_DIR"
DECOY_MARKER="YIP-REALITY-DECOY-MARKER-1f6c2e9a"
cat >"$DECOY_DIR/index.html" <<EOF
<!doctype html>
<title>Totally Ordinary Website</title>
<p>${DECOY_MARKER}</p>
EOF

ip netns exec "$NS" bash -c "cd '$DECOY_DIR' && exec python3 -m http.server $DECOY_PORT --bind 127.0.0.1" \
    >"$TMPDIR_TEST/decoy.log" 2>&1 &
PID_DECOY=$!

echo "[wait] waiting for decoy HTTP server"
tries=0
while true; do
    if ip netns exec "$NS" curl -s -o /dev/null "http://127.0.0.1:${DECOY_PORT}/" 2>/dev/null; then
        echo "[wait] decoy HTTP server is up"
        break
    fi
    if ! kill -0 "$PID_DECOY" 2>/dev/null; then
        echo "[error] decoy HTTP server died unexpectedly"
        cat "$TMPDIR_TEST/decoy.log" || true
        exit 1
    fi
    tries=$((tries + 1))
    if [ "$tries" -ge 40 ]; then
        echo "[error] timed out waiting for decoy HTTP server"
        cat "$TMPDIR_TEST/decoy.log" || true
        exit 1
    fi
    sleep 0.25
done

# ── 4. the relay itself, TLS front enabled ──────────────────────────────────
echo "[setup] generating obf-psk"
OBF_PSK="$(openssl rand -hex 32)"

echo "[start] starting yip-rendezvous (udp:$RDV_UDP_PORT, tls:$RDV_TCP_PORT, decoy:127.0.0.1:$DECOY_PORT)"
ip netns exec "$NS" "$RDV" "127.0.0.1:${RDV_UDP_PORT}" \
    --listen-tcp "127.0.0.1:${RDV_TCP_PORT}" \
    --tls-cert "$CERT" \
    --tls-key "$KEY" \
    --decoy "127.0.0.1:${DECOY_PORT}" \
    --obf-psk "$OBF_PSK" \
    >"$TMPDIR_TEST/rdv.log" 2>&1 &
PID_RDV=$!

echo "[wait] waiting for the relay's TLS front to accept connections"
tries=0
while true; do
    if ip netns exec "$NS" bash -c "exec 3<>/dev/tcp/127.0.0.1/${RDV_TCP_PORT}" >/dev/null 2>&1; then
        echo "[wait] relay TLS front is accepting TCP connections"
        break
    fi
    if ! kill -0 "$PID_RDV" 2>/dev/null; then
        echo "[error] yip-rendezvous died unexpectedly"
        cat "$TMPDIR_TEST/rdv.log" || true
        exit 1
    fi
    tries=$((tries + 1))
    if [ "$tries" -ge 40 ]; then
        echo "[error] timed out waiting for the relay TLS front"
        cat "$TMPDIR_TEST/rdv.log" || true
        exit 1
    fi
    sleep 0.25
done

FAIL=0

# ── 5. gate (a): PROBE -> DECOY ─────────────────────────────────────────────
echo "[probe] curl -sk https://127.0.0.1:${RDV_TCP_PORT}/"
set +e
CURL_OUT="$(ip netns exec "$NS" curl -sk --max-time 5 "https://127.0.0.1:${RDV_TCP_PORT}/")"
CURL_RC=$?
set -e
if [ "$CURL_RC" -ne 0 ]; then
    echo "[FAIL] gate (a): curl probe failed (rc=$CURL_RC) — relay did not behave like a normal HTTPS server"
    FAIL=1
elif echo "$CURL_OUT" | grep -q "$DECOY_MARKER"; then
    echo "[PASS] gate (a): probe -> decoy (curl received the real decoy site's index.html, not rendezvous/tunnel bytes)"
else
    echo "[FAIL] gate (a): curl probe did not receive the decoy marker; got: $CURL_OUT"
    FAIL=1
fi

# ── 6. gate (b): GARBAGE -> DECOY (no hang, no crash, decoy content) ───────
echo "[probe] sending non-HTTP garbage bytes over a fresh TLS connection"
# Trailing CRLF CRLF gives the decoy (an ordinary Python http.server, whose
# request parser blocks on readline() until a line terminator) a complete
# "line" to reject — mirroring how any real web server would actually
# respond to a garbage request (fast 400, then close) rather than hanging
# forever on a request line that never arrives. That termination behavior is
# a property of the decoy backend, not of the relay; the point of this gate
# is that the relay handed the bytes off to the decoy at all, and didn't
# itself hang or crash. `-ign_eof` keeps s_client reading after stdin (the
# printf) hits EOF, so the decoy's response has time to arrive and be
# flushed to garbage.out before the process exits or the outer `timeout`
# fires — without it, s_client can tear the connection down right after
# writing and race the decoy's reply out of the capture.
set +e
timeout 5 ip netns exec "$NS" bash -c \
    "printf '\x00\x01\x02\x03\r\n\r\n' | openssl s_client -quiet -ign_eof -connect 127.0.0.1:${RDV_TCP_PORT} 2>/dev/null" \
    >"$TMPDIR_TEST/garbage.out" 2>&1
GARBAGE_RC=$?
set -e
if [ "$GARBAGE_RC" -eq 124 ]; then
    echo "[FAIL] gate (b): garbage-bytes probe hung past the 5s bound — the relay did not hand it off to the decoy"
    FAIL=1
elif ! kill -0 "$PID_RDV" 2>/dev/null; then
    echo "[FAIL] gate (b): relay process died after receiving garbage bytes — must fail closed, not crash"
    FAIL=1
elif grep -q -e "HTTP/1\." -e "Error code: 400" -e "Bad request syntax" "$TMPDIR_TEST/garbage.out" 2>/dev/null; then
    # The decoy backend (python http.server) is what governs this response
    # shape — we assert the reply IS an HTTP/decoy response (positive
    # confirmation of decoy routing), not that it merely lacks
    # rendezvous/obf-looking bytes. This is the same rigor as gate (a).
    #
    # NOTE: empirically (this Python's http.server, verified across
    # multiple runs), a genuinely unparseable request line like our garbage
    # payload never negotiates an HTTP version, so http.server treats it as
    # HTTP/0.9 and omits the "HTTP/1.x 400 ..." status line entirely,
    # emitting only its DEFAULT_ERROR_MESSAGE body ("Error code: 400",
    # "Bad request syntax (...)"). That body text is just as
    # decoy-backend-specific and unambiguous a positive signal as a status
    # line would be, so it's included as an alternative match; "HTTP/1."
    # is kept in case a differently-shaped garbage payload (or a different
    # decoy backend) does produce a status line.
    echo "[PASS] gate (b): garbage bytes handled without hanging/crashing, and the reply is confirmed decoy HTTP content"
else
    echo "[FAIL] gate (b): garbage did not yield a decoy HTTP response (possible tunnel/rendezvous leak)"
    echo "[FAIL] gate (b): captured reply was:"
    cat "$TMPDIR_TEST/garbage.out" || true
    FAIL=1
fi

# ── 7. gate (c): TIMING PARITY — idle connection not closed at ~3s ─────────
# See #63 in the header comment: sub-second decoy-connect timing parity for
# a fully-silent connection is a known, tracked follow-up and is NOT
# asserted here. What IS asserted: the relay does not itself hard-close the
# connection at its ~3s classification deadline.
echo "[probe] opening an idle TLS connection and checking it survives >=5s"
FIFO="$TMPDIR_TEST/idle.fifo"
mkfifo "$FIFO"
# Open our own read+write fd on the fifo: this open call does not block (a
# RDWR open on a FIFO never blocks waiting for a peer), and holding fd 9
# open for writing keeps the fifo's read side from seeing EOF until we
# close it below — i.e. keeps openssl's stdin open with zero bytes sent.
exec 9<>"$FIFO"
ip netns exec "$NS" openssl s_client -quiet -connect "127.0.0.1:${RDV_TCP_PORT}" \
    <"$FIFO" >"$TMPDIR_TEST/idle.log" 2>&1 &
IDLE_PID=$!
sleep 5
if kill -0 "$IDLE_PID" 2>/dev/null; then
    echo "[PASS] gate (c): idle TLS connection is still open at >=5s (relay did not close at its ~3s classification timeout)"
else
    echo "[FAIL] gate (c): idle TLS connection was closed before 5s — the relay's classification timeout is an observable close signature"
    FAIL=1
fi
exec 9<&-
kill "$IDLE_PID" 2>/dev/null || true
wait "$IDLE_PID" 2>/dev/null || true

if [ "$FAIL" -ne 0 ]; then
    echo "[FAIL] probe-resistance oracle FAILED — see gate output above"
    exit 1
fi

echo "[PASS] probe-resistance oracle PASSED: an active prober sees only the decoy site, with no relay-shaped classification-timeout close"
