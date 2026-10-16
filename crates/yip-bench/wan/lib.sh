# Shared helpers for the WAN benchmark suite. Source this from every script:
#   SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$SUITE_DIR/lib.sh"
# It loads wan.env, defines A()/B() remote-exec helpers, logging, and CSV output.
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/../../.." && pwd)"

# ── config ──────────────────────────────────────────────────────────────────
if [[ -f "$SUITE_DIR/wan.env" ]]; then
    # shellcheck disable=SC1091
    . "$SUITE_DIR/wan.env"
elif [[ -f "$SUITE_DIR/wan.env.example" && "${ALLOW_EXAMPLE_ENV:-0}" == "1" ]]; then
    # shellcheck disable=SC1091
    . "$SUITE_DIR/wan.env.example"
else
    echo "FATAL: $SUITE_DIR/wan.env not found — copy wan.env.example and fill it in." >&2
    exit 1
fi
: "${HOST_A:?}" "${HOST_B:?}" "${SSH_USER:?}" "${SSH_KEY:?}"
: "${YIP_PORT:=51833}" "${WG_PORT:=51834}" "${OVPN_PORT:=51835}" "${OVERLAY_MTU:=1380}"

# Overlay addressing (each tunnel on its own /30; A always .1, B always .2).
YIP_A=10.77.0.1  YIP_B=10.77.0.2
WG_A=10.77.1.1   WG_B=10.77.1.2
OVPN_A=10.77.2.1 OVPN_B=10.77.2.2

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new
          -o ServerAliveInterval=5 -i "$SSH_KEY")

# ── remote exec ─────────────────────────────────────────────────────────────
# A "<cmd>"  runs <cmd> on node A;  B "<cmd>" on node B.  Both fail-fast (-e).
A() { ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST_A" "$@"; }
B() { ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST_B" "$@"; }
# Non-fatal variants (return status, never abort the caller under set -e).
Aq() { ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST_A" "$@" || true; }
Bq() { ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST_B" "$@" || true; }
put_A() { scp -q "${SSH_OPTS[@]}" "$1" "$SSH_USER@$HOST_A:$2"; }
put_B() { scp -q "${SSH_OPTS[@]}" "$1" "$SSH_USER@$HOST_B:$2"; }

# ── logging ─────────────────────────────────────────────────────────────────
# No Date.now in scripts here — plain shell `date` is fine (these are host tools).
log()  { printf '\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '\033[1;33m[%s] WARN:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '\033[1;31m[%s] FATAL:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

# ── CSV output ──────────────────────────────────────────────────────────────
# csv_row <tunnel> <profile> <param> <metric> <value> <conditions>
CSV_HEADER="ts,host_pair,commit,tunnel,profile,param,metric,value,conditions"
csv_row() {
    local ts commit
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    commit="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    printf '%s,%s->%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$ts" "$HOST_A" "$HOST_B" "$commit" "$1" "$2" "$3" "$4" "$5" "$6" \
        >> "$CSV_FILE"
}
