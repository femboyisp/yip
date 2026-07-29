#!/usr/bin/env bash
# yip-iperf-solo.sh — focused single-tunnel yip throughput probe.
# ONE yip netns pair, loss=0 (max throughput), one iperf3 TCP run + one ping.
# No WG/OpenVPN/n2n, no loss sweep — just yip's number, fast and hard to wedge.
#
# Usage: yip-iperf-solo.sh <path-to-yipd> [loss%]
set -euo pipefail

YIPD="${1:?usage: yip-iperf-solo.sh <yipd> [loss%]}"
LOSS="${2:-0}"

NS_A="soloYA"; NS_B="soloYB"; VA="solovYA"; VB="solovYB"
VA_IP="10.20.0.1"; VB_IP="10.20.0.2"
TUN_A_IP="10.21.0.1"; TUN_B_IP="10.21.0.2"
PORT_A="51870"; PORT_B="51871"; TUN_DEV="yip0"; YIP_MTU=1184
PID_A=""; PID_B=""
TMP="$(mktemp -d /tmp/yip-solo.XXXXXX)"

cleanup() {
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null || true
    for ns in "$NS_A" "$NS_B"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$TMP"
}
trap cleanup EXIT

echo "[keys]"
GA="$("$YIPD" --genkey)"; GB="$("$YIPD" --genkey)"
PRIV_A="$(echo "$GA" | grep '^private=' | cut -d= -f2)"
PUB_A="$(echo "$GA"  | grep '^public='  | cut -d= -f2)"
PRIV_B="$(echo "$GB" | grep '^private=' | cut -d= -f2)"
PUB_B="$(echo "$GB"  | grep '^public='  | cut -d= -f2)"
cat > "$TMP/a.conf" <<EOF
local_private=${PRIV_A}
local_public=${PUB_A}
peer_public=${PUB_B}
listen=${VA_IP}:${PORT_A}
peer_endpoint=${VB_IP}:${PORT_B}
device=${TUN_DEV}
initiate=false
EOF
cat > "$TMP/b.conf" <<EOF
local_private=${PRIV_B}
local_public=${PUB_B}
peer_public=${PUB_A}
listen=${VB_IP}:${PORT_B}
peer_endpoint=${VA_IP}:${PORT_A}
device=${TUN_DEV}
initiate=true
EOF

echo "[netns]"
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add "$VA" type veth peer name "$VB"
ip link set "$VA" netns "$NS_A"; ip link set "$VB" netns "$NS_B"
ip netns exec "$NS_A" ip addr add "$VA_IP/24" dev "$VA"
ip netns exec "$NS_A" ip link set "$VA" up; ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip addr add "$VB_IP/24" dev "$VB"
ip netns exec "$NS_B" ip link set "$VB" up; ip netns exec "$NS_B" ip link set lo up

if [ "$LOSS" != "0" ]; then
    echo "[netem] loss=${LOSS}% delay=5ms"
    ip netns exec "$NS_A" tc qdisc replace dev "$VA" root netem loss "${LOSS}%" delay 5ms
    ip netns exec "$NS_B" tc qdisc replace dev "$VB" root netem loss "${LOSS}%" delay 5ms
fi

echo "[yipd]"
ip netns exec "$NS_A" "$YIPD" "$TMP/a.conf" >"$TMP/a.log" 2>&1 & PID_A=$!
ip netns exec "$NS_B" "$YIPD" "$TMP/b.conf" >"$TMP/b.log" 2>&1 & PID_B=$!

echo "[wait tun]"
elapsed=0
while true; do
    A=0; B=0
    ip netns exec "$NS_A" ip link show "$TUN_DEV" >/dev/null 2>&1 && A=1 || true
    ip netns exec "$NS_B" ip link show "$TUN_DEV" >/dev/null 2>&1 && B=1 || true
    [ "$A" -eq 1 ] && [ "$B" -eq 1 ] && break
    kill -0 "$PID_A" 2>/dev/null || { echo "[err] A died"; cat "$TMP/a.log"; exit 1; }
    kill -0 "$PID_B" 2>/dev/null || { echo "[err] B died"; cat "$TMP/b.log"; exit 1; }
    elapsed=$(awk "BEGIN{print $elapsed+0.25}")
    awk "BEGIN{exit ($elapsed>=20)?0:1}" && { echo "[err] tun timeout"; cat "$TMP/a.log" "$TMP/b.log"; exit 1; }
    sleep 0.25
done
ip netns exec "$NS_A" ip addr add "${TUN_A_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_B" ip addr add "${TUN_B_IP}/24" dev "$TUN_DEV"
ip netns exec "$NS_A" ip link set "$TUN_DEV" mtu "$YIP_MTU"
ip netns exec "$NS_B" ip link set "$TUN_DEV" mtu "$YIP_MTU"
ip netns exec "$NS_A" ip link set "$TUN_DEV" up
ip netns exec "$NS_B" ip link set "$TUN_DEV" up
sleep 0.5

echo "[ping]"
ip netns exec "$NS_B" ping -c 5 -i 0.2 -W 2 "$TUN_A_IP" | tail -2

echo "[iperf3] server in $NS_A, client in $NS_B, 10s"
ip netns exec "$NS_A" iperf3 -s -1 -B "$TUN_A_IP" >"$TMP/srv.log" 2>&1 &
sleep 0.5
ip netns exec "$NS_B" iperf3 -c "$TUN_A_IP" -t 10 -O 1 || { echo "[err] iperf client failed"; cat "$TMP/srv.log"; exit 1; }

echo "[done]"
