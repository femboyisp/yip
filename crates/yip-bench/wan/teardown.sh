#!/usr/bin/env bash
# Tear down everything the WAN benchmark created: stop all transient units,
# bring down the three tunnels, and clear any netem qdisc. Leaves installed
# packages in place (idempotent re-provisioning). Never fails hard — best effort.
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SUITE_DIR/lib.sh"
set +e

log "tearing down tunnels + netem on both hosts"
for host in A B; do
    EG="$("$host" "ip route get 1.1.1.1 | grep -oE 'dev [a-z0-9]+' | awk '{print \$2}' | head -1" 2>/dev/null)"
    "$host" "
        for u in yipbench-yip yipbench-ovpn yipbench-iperf yipbench-mgen; do
            systemctl stop \$u 2>/dev/null; systemctl reset-failed \$u 2>/dev/null
        done
        wg-quick down wgbench 2>/dev/null
        pkill -9 -x yipd 2>/dev/null; pkill -9 -x openvpn 2>/dev/null
        ip link del yipbench0 2>/dev/null
        ip link del tunovpn0 2>/dev/null
        ${EG:+tc qdisc del dev $EG root 2>/dev/null}
        true
    " >/dev/null 2>&1
    log "  $("$host" 'hostname'): torn down (netem cleared on ${EG:-?})"
done

log "verifying the bare path is clean (A -> B, no tunnel, no netem)"
out="$(Aq "ping -c 5 -i 0.2 -W 2 $HOST_B | tail -1")"
log "  bare path: $out"
log "teardown complete (packages left installed for idempotent re-provisioning)"
