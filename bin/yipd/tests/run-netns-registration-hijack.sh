#!/usr/bin/env bash
# The rdv.37 money test: proves the #37 fix end-to-end -- a ROOTED (mesh-mode)
# yip-rendezvous server, started with --roots/--network-id, refuses a forged
# registration attempt that claims an established member's identity, and the
# victim stays reachable throughout.
#
# Usage: run-netns-registration-hijack.sh <path-to-yipd-binary> \
#          <path-to-yip-ca-binary> <path-to-yip-rendezvous-binary>
#
# ── topology: four netns, A / B / S / R, all on ONE shared bridge underlay ──
# Forked from run-netns-discovery.sh's CA/cert/roots minting (`yip-ca genkey`
# + per-node `yipd --genkey` + `sign-cert`) and run-netns-punch.sh's
# rendezvous-only peer config style (`rendezvous=<ip:port>`, `[peer]
# public_key=` with no endpoint -- no static knowledge of the peer's
# address). NEW here (this milestone's Task 3 wired it): R runs the
# STANDALONE `yip-rendezvous` binary in MESH mode (`--roots <file>
# --network-id <hex32>`), not a `yipd` seed root as run-netns-discovery.sh
# uses -- that combination (mesh-cert config + `rendezvous=` + a rooted
# standalone server) had no existing netns test before this task.
#
# ── the roots file's pubkey entry: the CA's own key, not a bootstrap peer ──
# `RootSet.roots` is a generic `Vec<(pubkey, addr)>` reused for two BY-DESIGN
# different purposes depending on deployment:
#   - run-netns-discovery.sh's gossip-bootstrap deployment: the pubkey is a
#     root PEER's data-plane key (used to seed the initial handshake).
#   - this rendezvous-only deployment (no gossip, no root peer -- everyone
#     reaches everyone only via the rendezvous server + direct handshake):
#     `Membership::verify_record` (bin/yipd/src/membership.rs) and
#     `yip-rendezvous`'s own `roots_cfg_from` (bin/yip-rendezvous/src/main.rs)
#     BOTH derive their trusted-CA set as `roots.roots.iter().map(|(pk,_)|
#     pk)` -- i.e. the roots file's pubkey entries must be the CA's OWN
#     Ed25519 key for `verify_record` (which gates trusting a `PeerCandidate`
#     record from the server) to ever succeed. Confirmed against
#     `.superpowers/sdd/task-3-report.md`'s real-binary smoke check, which
#     documents exactly this: "CA's own pubkey as a root entry (verify_rootset
#     needs the CA's own pubkey inside the rootset's own listed entries)".
#     The address half of that pair is unused by this deployment (no
#     bootstrap dial happens) and is a placeholder.
# `ca_public=<hex64>` (yipd's config, separate from `roots=`) is what feeds
# handshake-payload cert verification (`Membership::verify_cert`) and gossip
# ingestion; it is set to the SAME CA_PUB for both A and B.
#
# ── the attacker (S) ──
# S runs NO yipd process and holds no cert at all -- it is a bare UDP sender.
# A genuine `yipd`, even with its own valid cert, can only ever sign a
# registration for ITS OWN node_id (`Membership::sign_registration` always
# signs the node's own cert/endpoints -- bin/yipd/src/membership.rs); there is
# no config knob or code path that lets a real `yipd` register as someone
# else's identity, so a second real daemon cannot be coaxed into attacking A
# at all. S instead crafts the ONE forgery that IS a real off-path threat and
# needs no cryptography to construct: a legacy, UNSIGNED `Register { node:
# A's rendezvous node_id, counter: <huge> }` (crates/yip-rendezvous/src/proto.rs
# tag 0 -- a bare `[0x00][node:16][counter:8 BE]`, 25 bytes). Pre-#37 this
# would silently steal A's directory slot; post-#37 a ROOTED server drops
# every unsigned `Register` outright, unconditionally, before even looking at
# the node id (crates/yip-rendezvous/src/server.rs's `handle`,
# `self.roots_cfg.is_some()` arm) -- what this test proves end-to-end.
#
# The companion forgery -- a `RegisterSigned` carrying a record signed by a
# DIFFERENT member's own valid key but claiming A's node_id (the
# `Record::verify` node_id-binding / "squatting" check) -- needs a real
# ed25519 signature to construct, which requires either a crypto-capable
# scripting dependency not guaranteed present on the runner, or a bespoke
# Rust helper this task's scope (shell + CI yaml) doesn't call for. That path
# is already proven, adversarially, at the crate unit level by
# `rooted_server_rejects_overwrite_by_non_holder` (crates/yip-rendezvous/src/
# server.rs) and `wrong_node_id_fails_verify` (crates/yip-membership/src/
# record.rs) -- both construct exactly this attack (valid CA-signed cert for
# the attacker's OWN key, record.node_id forged to the victim's) and assert
# it is rejected without disturbing the victim's real entry. This script's
# unsigned-Register attack is the wire-level, no-crypto-needed sibling of the
# same property, and is the form the task brief explicitly endorses as the
# "simplest credible attacker" when raw signed-packet crafting is impractical.
#
# ── how the forged Register's rejection is observed (black-box) ──
# The server never replies to a `Register` (signed or not, accepted or
# refused -- see `handle`), so silence alone cannot distinguish "accepted"
# from "refused". Instead: a small python3 probe (no external deps, stdlib
# `socket`/`hashlib`/`struct` only) sends a raw `Lookup` for A's rendezvous
# node_id and decodes the `PeerInfo` reply's reflexive address directly off
# the wire, BOTH before and after the attack. If the forged Register had been
# accepted, A's directory entry would now point at S's address; assertion (a)
# below is that the reflexive address is IDENTICAL (still A's real
# `IP_A:PORT`) across the attack. `hashlib.blake2s(..., digest_size=16)` is
# confirmed bit-for-bit equal to `crates/yip-rendezvous/src/proto.rs`'s
# `Blake2sVar::new(16)` node-id derivation (both are standard-compliant
# BLAKE2s with the digest length folded into the parameter block) --
# verified directly against the crate's own `node_id_is_deterministic_and_
# 16_bytes` fixture before this script was written.
#
# ── obfuscation deliberately OFF ──
# Same reasoning as run-netns-replay-hijack.sh: the attack and probe scripts
# send/parse the PLAIN rendezvous wire format; under obf, that framing rides
# inside an obfuscation envelope this test does not construct.
#
# Assertions (any failure is non-zero exit, [PASS]/[FAIL] markers):
#   1. establishment: a steady ping B->A (over the mesh v6 addr) succeeds --
#      A and B found each other purely via signed registration + Lookup
#      against the rooted server (no `[peer]` endpoint, no gossip).
#   2. no_overwrite: A's `Lookup` reflexive address is byte-identical before
#      and after the forged-Register attack -- the server did not accept it.
#   3. no_disruption: a steady ping B->A spanning the attack window stays
#      <=1% loss -- the forged registrations, even though refused, did not
#      disrupt the live B<->A session either.
# The script supports both drivers (reads YIP_USE_URING from the caller's
# env; `ip netns exec`, unlike `sudo`, does not clear the environment, so it
# flows through to the daemons unmodified). CI runs it POLL-ONLY, matching
# its fork sources run-netns-discovery.sh / run-netns-cert-revocation.sh:
# mesh discovery/registration convergence is flaky under io_uring, and the
# rooted server's forged-registration refusal is a rendezvous-server-side
# property (`crates/yip-rendezvous/src/server.rs`, no yipd I/O driver
# involved at all) -- the poll run exercises it identically.
set -euo pipefail

YIPD="${1:?Usage: $0 <yipd-binary> <yip-ca-binary> <yip-rendezvous-binary>}"
YIPCA="${2:?Usage: $0 <yipd-binary> <yip-ca-binary> <yip-rendezvous-binary>}"
RDV="${3:?Usage: $0 <yipd-binary> <yip-ca-binary> <yip-rendezvous-binary>}"

# ── 0. root + tool preflight (invoked directly by CI, not through the
# tunnel_netns.rs Rust harness, so it does its own SKIP-gating per the
# run-netns-cert-revocation.sh / run-netns-replay-hijack.sh convention) ──
if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP run-netns-registration-hijack: needs root (netns + TUN)"
    exit 0
fi
for tool in python3 ping; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP run-netns-registration-hijack: required tool '$tool' not found"
        exit 0
    fi
done

TMPDIR_TEST="$(mktemp -d /tmp/yipd-netns-registration-hijack-test.XXXXXX)"

BR="brRegHijk0"

NS_A="yipHijkA"
NS_B="yipHijkB"
NS_S="yipHijkS"   # the attacker -- no yipd, no cert, no identity
NS_R="yipHijkR"   # the rooted standalone yip-rendezvous server

VETH_A_H="vHijkA0"; VETH_A_N="vHijkA1"
VETH_B_H="vHijkB0"; VETH_B_N="vHijkB1"
VETH_S_H="vHijkS0"; VETH_S_N="vHijkS1"
VETH_R_H="vHijkR0"; VETH_R_N="vHijkR1"

IP_A="10.99.0.1"
IP_B="10.99.0.2"
IP_S="10.99.0.3"
IP_R="10.99.0.4"
VETH_PREFIX="24"
PORT="51820"
RDV_PORT="51821"
TUN_DEV="yip0"
NETWORK_ID="abadcafeabadcafeabadcafeabadcafe"

PID_A=""
PID_B=""
PID_RDV=""

cleanup() {
    echo "[cleanup] killing daemons and removing namespaces/bridge"
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill "$PID_RDV" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    [ -n "$PID_RDV" ] && kill -9 "$PID_RDV" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip netns del "$NS_S" 2>/dev/null || true
    ip netns del "$NS_R" 2>/dev/null || true
    ip link del "$BR" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

# ── 1. offline CA + per-node keys/certs + a roots file naming the CA itself ──
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

ADDR_A="$("$YIPD" --addr "$PUB_A")"
ADDR_B="$("$YIPD" --addr "$PUB_B")"
echo "[setup] node_addr A=$ADDR_A B=$ADDR_B"

sign_cert() {
    local member_pub="$1" member_sign_pub="$2"
    echo "$CA_PRIV" | "$YIPCA" sign-cert \
        --member "$member_pub" --member-sign "$member_sign_pub" \
        --network "$NETWORK_ID" --days 30
}
CERT_A_FILE="$TMPDIR_TEST/certA.hex"
CERT_B_FILE="$TMPDIR_TEST/certB.hex"
sign_cert "$PUB_A" "$SIGNPUB_A" > "$CERT_A_FILE"
sign_cert "$PUB_B" "$SIGNPUB_B" > "$CERT_B_FILE"

# The roots file's pubkey entry is the CA's OWN key (see header comment) --
# NOT a bootstrap peer's data-plane key. The address half is unused by this
# rendezvous-only deployment (no gossip bootstrap dial ever happens); any
# well-formed placeholder is fine.
ROOTS_IN="$TMPDIR_TEST/roots.in"
echo "$CA_PUB 127.0.0.1:1" > "$ROOTS_IN"
ROOTS_FILE="$TMPDIR_TEST/roots.hex"
echo "$CA_PRIV" | "$YIPCA" sign-roots --roots "$ROOTS_IN" --version 1 > "$ROOTS_FILE"

# ── 2. write mesh + rendezvous-only configs for A and B ──────────────────────
CFG_A="$TMPDIR_TEST/yipA.conf"
CFG_B="$TMPDIR_TEST/yipB.conf"

write_cfg() {
    local file="$1" priv="$2" pub="$3" ip="$4" certfile="$5" signpriv="$6" peer_pub="$7"
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
rendezvous=${IP_R}:${RDV_PORT}
[peer]
public_key=${peer_pub}
EOF
}
write_cfg "$CFG_A" "$PRIV_A" "$PUB_A" "$IP_A" "$CERT_A_FILE" "$SIGNPRIV_A" "$PUB_B"
write_cfg "$CFG_B" "$PRIV_B" "$PUB_B" "$IP_B" "$CERT_B_FILE" "$SIGNPRIV_B" "$PUB_A"

# ── 3. create namespaces + shared bridge underlay ─────────────────────────────
echo "[setup] creating network namespaces"
ip netns add "$NS_A"
ip netns add "$NS_B"
ip netns add "$NS_S"
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
setup_leg "$NS_S" "$VETH_S_H" "$VETH_S_N" "$IP_S"
setup_leg "$NS_R" "$VETH_R_H" "$VETH_R_N" "$IP_R"

# ── 4. start the ROOTED standalone yip-rendezvous server in R ────────────────
LOG_RDV="$TMPDIR_TEST/rdv.log"
echo "[start] starting yip-rendezvous (mesh mode) in R on 0.0.0.0:${RDV_PORT}"
ip netns exec "$NS_R" "$RDV" "0.0.0.0:${RDV_PORT}" \
    --roots "$ROOTS_FILE" --network-id "$NETWORK_ID" \
    >"$LOG_RDV" 2>&1 &
PID_RDV=$!
sleep 0.3
if ! kill -0 "$PID_RDV" 2>/dev/null; then
    echo "[error] yip-rendezvous failed to start"
    cat "$LOG_RDV" || true
    exit 1
fi
if ! grep -q "mesh mode" "$LOG_RDV"; then
    echo "[FAIL] yip-rendezvous did not report mesh mode on startup"
    cat "$LOG_RDV" || true
    exit 1
fi
echo "[check] yip-rendezvous confirmed mesh mode: $(grep 'mesh mode' "$LOG_RDV")"

# ── 5. start yipd A and B ──────────────────────────────────────────────────
LOG_A="$TMPDIR_TEST/yipA.log"
LOG_B="$TMPDIR_TEST/yipB.log"

dump_logs() {
    echo "=== yip-rendezvous log ==="
    cat "$LOG_RDV" || true
    echo "=== yipHijkA log ==="
    cat "$LOG_A" || true
    echo "=== yipHijkB log ==="
    cat "$LOG_B" || true
}

echo "[start] starting yipHijkA"
ip netns exec "$NS_A" "$YIPD" "$CFG_A" >"$LOG_A" 2>&1 &
PID_A=$!

echo "[start] starting yipHijkB"
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

    for pid_var_name in PID_A:yipHijkA PID_B:yipHijkB PID_RDV:yip-rendezvous; do
        pid_var="${pid_var_name%%:*}"
        node_name="${pid_var_name##*:}"
        pid="${!pid_var}"
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[error] $node_name died unexpectedly"
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

# ── 7. assign each TUN its own node_addr/128 + the mesh-prefix route ─────────
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

# ── 8. establishment: poll until a steady ping B->A converges ────────────────
# Neither side has the other's endpoint statically (rendezvous-only [peer]
# blocks) -- A and B must each register (signed) with R, then Lookup the
# other and verify the returned record against the shared roots before
# admitting/handshaking (#37 Task 5). Poll rather than one-shot, mirroring
# run-netns-cert-revocation.sh's establishment step: this exact mesh-cert +
# rooted-rendezvous combination is new in this milestone.
echo "[test] establishing B<->A via signed registration + rooted rendezvous (up to 60s)"
ESTABLISHED=0
DEADLINE=$(($(date +%s) + 60))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    for pid_var_name in PID_A:yipHijkA PID_B:yipHijkB PID_RDV:yip-rendezvous; do
        pid_var="${pid_var_name%%:*}"
        node_name="${pid_var_name##*:}"
        pid="${!pid_var}"
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[error] $node_name died during establishment"
            dump_logs
            exit 1
        fi
    done
    if ip netns exec "$NS_B" ping -6 -c 3 -W 2 "$ADDR_A" >/dev/null 2>&1; then
        ESTABLISHED=1
        break
    fi
    sleep 1
done
if [ "$ESTABLISHED" -ne 1 ]; then
    echo "[FAIL] establishment: ping B->A did not converge within 60s"
    dump_logs
    exit 1
fi
echo "[PASS] establishment: B<->A established via signed registration + discovery"

# ── 9. the forged-registration probe/attack tool (S has no yipd, no cert) ────
# stdlib-only (socket/hashlib/struct); mirrors crates/yip-rendezvous/src/
# proto.rs's Message codec exactly (see header comment for the full
# rationale). No obf: plain wire bytes only.
PROBE_PY="$TMPDIR_TEST/rdv_probe.py"
cat > "$PROBE_PY" <<'PYEOF'
import hashlib
import socket
import struct
import sys

DOMAIN = b"yip-rdv-v1"


def node_id_hex(pubkey_hex):
    pk = bytes.fromhex(pubkey_hex)
    assert len(pk) == 32, f"pubkey must be 32 bytes, got {len(pk)}"
    h = hashlib.blake2s(digest_size=16)
    h.update(DOMAIN)
    h.update(pk)
    return h.hexdigest()


def cmd_nodeid(argv):
    print(node_id_hex(argv[0]))


def cmd_register(argv):
    rdv_ip, rdv_port, node_hex, counter = argv[0], int(argv[1]), argv[2], int(argv[3])
    node = bytes.fromhex(node_hex)
    assert len(node) == 16
    pkt = bytes([0]) + node + struct.pack(">Q", counter)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (rdv_ip, rdv_port))
    s.close()


def cmd_lookup(argv):
    rdv_ip, rdv_port, node_hex = argv[0], int(argv[1]), argv[2]
    timeout = float(argv[3]) if len(argv) > 3 else 2.0
    node = bytes.fromhex(node_hex)
    assert len(node) == 16
    pkt = bytes([1]) + node
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(pkt, (rdv_ip, rdv_port))
    try:
        data, _ = s.recvfrom(2048)
    except socket.timeout:
        print("TIMEOUT")
        return
    finally:
        s.close()
    if len(data) < 1:
        print("TIMEOUT")
        return
    tag = data[0]
    if tag == 3:
        print("NOTFOUND")
        return
    if tag != 2:
        print(f"UNEXPECTED tag={tag}")
        return
    # PeerInfo: [2][node:16][fam:1][ip...][port:2 BE][record presence...]
    off = 1 + 16
    fam = data[off]
    off += 1
    if fam == 4:
        ip = socket.inet_ntop(socket.AF_INET, data[off:off + 4])
        off += 4
    elif fam == 6:
        ip = socket.inet_ntop(socket.AF_INET6, data[off:off + 16])
        off += 16
    else:
        print(f"BADFAMILY {fam}")
        return
    port = struct.unpack(">H", data[off:off + 2])[0]
    print(f"REFLEXIVE={ip}:{port}")


CMDS = {"nodeid": cmd_nodeid, "register": cmd_register, "lookup": cmd_lookup}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in CMDS:
        print(f"usage: {sys.argv[0]} <nodeid|register|lookup> ...", file=sys.stderr)
        sys.exit(2)
    CMDS[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    main()
PYEOF

A_NODE_ID="$(ip netns exec "$NS_S" python3 "$PROBE_PY" nodeid "$PUB_A")"
echo "[setup] A's rendezvous node_id (independently derived by S): $A_NODE_ID"

# ── 10. baseline: S's own Lookup for A resolves to A's real address ─────────
# Also validates the probe's node_id derivation is actually correct -- a
# wrong node_id here would come back NOTFOUND, not a false pass.
BASELINE="$(ip netns exec "$NS_S" python3 "$PROBE_PY" lookup "$IP_R" "$RDV_PORT" "$A_NODE_ID" 3)"
echo "[check] baseline Lookup(A) from S: $BASELINE"
EXPECT_REFLEXIVE="REFLEXIVE=${IP_A}:${PORT}"
if [ "$BASELINE" != "$EXPECT_REFLEXIVE" ]; then
    echo "[FAIL] baseline Lookup(A) did not resolve to A's real address (expected $EXPECT_REFLEXIVE, got $BASELINE)"
    dump_logs
    exit 1
fi
echo "[PASS] baseline: A's registration resolves to its real reflexive address"

# ── 11. attack: forged unsigned Register(node=A) from S, concurrently with a
# steady ping B->A ─────────────────────────────────────────────────────────
HIJACK_PING_LOG="$TMPDIR_TEST/hijack_ping.log"
echo "[test] pinging ${ADDR_A} from B while S sends forged unsigned Register(A) at R"
set +e
ip netns exec "$NS_B" ping -6 -i 0.2 -c 40 -W 1 "$ADDR_A" >"$HIJACK_PING_LOG" 2>&1 &
PING_PID=$!
sleep 1.0
echo "[attack] S (${IP_S}) sending forged unsigned Register claiming A's node_id ($A_NODE_ID) at R"
for counter in 1 100000 999999999; do
    ip netns exec "$NS_S" python3 "$PROBE_PY" register "$IP_R" "$RDV_PORT" "$A_NODE_ID" "$counter"
    ATTACK_STATUS=$?
    if [ "$ATTACK_STATUS" -ne 0 ]; then
        echo "[FAIL] the forged Register send from S failed (exit $ATTACK_STATUS)"
        kill "$PING_PID" 2>/dev/null || true
        dump_logs
        exit 1
    fi
    sleep 0.3
done
wait "$PING_PID"
PING_STATUS=$?
set -e
cat "$HIJACK_PING_LOG"

for pid_var_name in PID_A:yipHijkA PID_B:yipHijkB PID_RDV:yip-rendezvous; do
    pid_var="${pid_var_name%%:*}"
    node_name="${pid_var_name##*:}"
    pid="${!pid_var}"
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[error] $node_name died during the attack"; dump_logs; exit 1
    fi
done

LOSS_PCT="$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' "$HIJACK_PING_LOG" | grep -oE '^[0-9]+(\.[0-9]+)?' || true)"
if [ -z "$LOSS_PCT" ]; then
    echo "[FAIL] no_disruption: could not parse packet loss from ping output"
    dump_logs
    exit 1
fi
echo "[metric] no_disruption: packet loss during attack = ${LOSS_PCT}%"
if awk "BEGIN {exit ($LOSS_PCT <= 1.0) ? 0 : 1}"; then
    echo "[PASS] no_disruption: ${LOSS_PCT}% loss (<=1%) across the attack -- B's live session with A was not disrupted"
else
    echo "[FAIL] no_disruption: ${LOSS_PCT}% loss (>1%) -- the forged registration may have disrupted B's session with A"
    dump_logs
    exit 1
fi
if [ "$PING_STATUS" -ne 0 ] && [ "$LOSS_PCT" != "100" ]; then
    echo "[note] ping exited $PING_STATUS despite <=1% loss (non-fatal; proceeding)"
fi

# ── 12. no_overwrite: A's Lookup reflexive is unchanged after the attack ────
AFTER="$(ip netns exec "$NS_S" python3 "$PROBE_PY" lookup "$IP_R" "$RDV_PORT" "$A_NODE_ID" 3)"
echo "[check] post-attack Lookup(A) from S: $AFTER"
if [ "$AFTER" != "$EXPECT_REFLEXIVE" ]; then
    echo "[FAIL] no_overwrite: A's registration changed after the forged Register (expected $EXPECT_REFLEXIVE, got $AFTER) -- the rooted server accepted a forged overwrite!"
    dump_logs
    exit 1
fi
echo "[PASS] no_overwrite: A's registration is unchanged after the forged-Register attack -- the rooted server refused it"

echo "[PASS] run-netns-registration-hijack: the rooted server refused the forged registration; B<->A stayed reachable throughout"
