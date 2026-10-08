#!/usr/bin/env bash
# End-to-end comparative WireGuard vs yip benchmark in network namespaces.
# Usage: run-netns-wireguard-comp.sh [path-to-yipd-binary]
#
# Requires:
#   - Root privileges (sudo)
#   - ip, wg, iperf3, tc, ping, python3
#
# Topology:
#   - Namespaces: wg_ns_a and wg_ns_b
#   - Veth pair: veth_wg_a (10.44.0.1/24) <-> veth_wg_b (10.44.0.2/24)
#   - Linux kernel WireGuard (wg0): 10.88.0.1/24 (A:51820) <-> 10.88.0.2/24 (B:51821)
#   - yip daemon tunnel (yip0): 10.99.0.1/24 (A:52820) <-> 10.99.0.2/24 (B:52821)
#
# Evaluates head-to-head performance across three channel conditions:
#   1. 0% packet loss (baseline)
#   2. 1% simulated packet loss
#   3. 5% simulated packet loss
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[error] This script must be run as root (or via sudo)." >&2
    exit 1
fi

YIPD="${1:-./target/release/yipd}"
if [ ! -x "$YIPD" ]; then
    echo "[error] yipd binary not found or not executable at: $YIPD" >&2
    echo "        Build with: cargo build --release -p yipd" >&2
    exit 1
fi

for cmd in ip wg iperf3 tc ping python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[error] Required command '$cmd' is not installed or not in PATH." >&2
        exit 1
    fi
done

TMPDIR_TEST="$(mktemp -d /tmp/yip-wg-comp.XXXXXX)"

NS_A="wg_ns_a"
NS_B="wg_ns_b"
VETH_A="veth_wg_a"
VETH_B="veth_wg_b"
VETH_A_IP="10.44.0.1"
VETH_B_IP="10.44.0.2"
VETH_PREFIX="24"

WG_DEV="wg0"
WG_A_IP="10.88.0.1"
WG_B_IP="10.88.0.2"
WG_PREFIX="24"
WG_PORT_A="51820"
WG_PORT_B="51821"

YIP_DEV="yip0"
YIP_A_IP="10.99.0.1"
YIP_B_IP="10.99.0.2"
YIP_PREFIX="24"
YIP_PORT_A="52820"
YIP_PORT_B="52821"

PID_YIP_A=""
PID_YIP_B=""

cleanup() {
    echo
    echo "[cleanup] Tearing down processes, interfaces, and namespaces..."
    ip netns exec "$NS_A" pkill -9 iperf3 2>/dev/null || true
    ip netns exec "$NS_B" pkill -9 iperf3 2>/dev/null || true

    [ -n "$PID_YIP_A" ] && kill "$PID_YIP_A" 2>/dev/null || true
    [ -n "$PID_YIP_B" ] && kill "$PID_YIP_B" 2>/dev/null || true
    sleep 0.2
    [ -n "$PID_YIP_A" ] && kill -9 "$PID_YIP_A" 2>/dev/null || true
    [ -n "$PID_YIP_B" ] && kill -9 "$PID_YIP_B" 2>/dev/null || true

    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    rm -rf "$TMPDIR_TEST"
    echo "[cleanup] Complete."
}
trap cleanup EXIT INT TERM

echo "================================================================================"
echo "    Live WireGuard vs yip Parity Netns Benchmark Harness"
echo "================================================================================"
echo "[init] Using yipd: $YIPD"
echo "[init] Scratch directory: $TMPDIR_TEST"

# ── 1. Create Network Namespaces and Veth Pair ───────────────────────────────
echo "[setup] Creating network namespaces ($NS_A, $NS_B) and veth pair..."
ip netns add "$NS_A"
ip netns add "$NS_B"

ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

ip netns exec "$NS_A" ip addr add "${VETH_A_IP}/${VETH_PREFIX}" dev "$VETH_A"
ip netns exec "$NS_B" ip addr add "${VETH_B_IP}/${VETH_PREFIX}" dev "$VETH_B"
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_B" ip link set "$VETH_B" up
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip link set lo up

# Verify veth baseline connectivity
if ! ip netns exec "$NS_B" ping -c 2 -W 2 "$VETH_A_IP" >/dev/null 2>&1; then
    echo "[error] Veth link connectivity failed between namespaces." >&2
    exit 1
fi
echo "[setup] Veth transport link verified (${VETH_A_IP} <-> ${VETH_B_IP})."

# ── 2. Configure Linux Kernel WireGuard (wg0) ─────────────────────────────────
echo "[setup] Configuring Linux kernel WireGuard tunnel ($WG_DEV)..."
WG_KEY_A="$(wg genkey)"
WG_PUB_A="$(echo "$WG_KEY_A" | wg pubkey)"
WG_KEY_B="$(wg genkey)"
WG_PUB_B="$(echo "$WG_KEY_B" | wg pubkey)"

echo "$WG_KEY_A" > "$TMPDIR_TEST/wg_a.key"
echo "$WG_KEY_B" > "$TMPDIR_TEST/wg_b.key"
chmod 600 "$TMPDIR_TEST/wg_a.key" "$TMPDIR_TEST/wg_b.key"

# Namespace A wg0
ip netns exec "$NS_A" ip link add dev "$WG_DEV" type wireguard
ip netns exec "$NS_A" ip addr add "${WG_A_IP}/${WG_PREFIX}" dev "$WG_DEV"
ip netns exec "$NS_A" wg set "$WG_DEV" \
    private-key "$TMPDIR_TEST/wg_a.key" \
    listen-port "$WG_PORT_A" \
    peer "$WG_PUB_B" \
    endpoint "${VETH_B_IP}:${WG_PORT_B}" \
    allowed-ips "10.88.0.0/24" \
    persistent-keepalive 25
ip netns exec "$NS_A" ip link set "$WG_DEV" up

# Namespace B wg0
ip netns exec "$NS_B" ip link add dev "$WG_DEV" type wireguard
ip netns exec "$NS_B" ip addr add "${WG_B_IP}/${WG_PREFIX}" dev "$WG_DEV"
ip netns exec "$NS_B" wg set "$WG_DEV" \
    private-key "$TMPDIR_TEST/wg_b.key" \
    listen-port "$WG_PORT_B" \
    peer "$WG_PUB_A" \
    endpoint "${VETH_A_IP}:${WG_PORT_A}" \
    allowed-ips "10.88.0.0/24" \
    persistent-keepalive 25
ip netns exec "$NS_B" ip link set "$WG_DEV" up

# Verify WireGuard ping
if ! ip netns exec "$NS_B" ping -c 3 -W 3 "$WG_A_IP" >/dev/null 2>&1; then
    echo "[error] WireGuard tunnel ping failed." >&2
    exit 1
fi
echo "[setup] WireGuard tunnel active and responsive (${WG_A_IP} <-> ${WG_B_IP})."

# ── 3. Configure yip Tunnel (yip0) ───────────────────────────────────────────
echo "[setup] Configuring yip daemon tunnel ($YIP_DEV)..."
GENKEY_A="$("$YIPD" --genkey)"
GENKEY_B="$("$YIPD" --genkey)"
PRIV_YIP_A="$(echo "$GENKEY_A" | grep '^private=' | cut -d= -f2)"
PUB_YIP_A="$(echo "$GENKEY_A" | grep '^public=' | cut -d= -f2)"
PRIV_YIP_B="$(echo "$GENKEY_B" | grep '^private=' | cut -d= -f2)"
PUB_YIP_B="$(echo "$GENKEY_B" | grep '^public=' | cut -d= -f2)"

CFG_YIP_A="$TMPDIR_TEST/yip_a.conf"
CFG_YIP_B="$TMPDIR_TEST/yip_b.conf"
LOG_YIP_A="$TMPDIR_TEST/yip_a.log"
LOG_YIP_B="$TMPDIR_TEST/yip_b.log"

cat > "$CFG_YIP_A" <<EOF
# yipA (responder)
local_private=${PRIV_YIP_A}
local_public=${PUB_YIP_A}
peer_public=${PUB_YIP_B}
listen=${VETH_A_IP}:${YIP_PORT_A}
peer_endpoint=${VETH_B_IP}:${YIP_PORT_B}
device=${YIP_DEV}
initiate=false
shards=4
EOF

cat > "$CFG_YIP_B" <<EOF
# yipB (initiator)
local_private=${PRIV_YIP_B}
local_public=${PUB_YIP_B}
peer_public=${PUB_YIP_A}
listen=${VETH_B_IP}:${YIP_PORT_B}
peer_endpoint=${VETH_A_IP}:${YIP_PORT_A}
device=${YIP_DEV}
initiate=true
shards=4
EOF

# Start yipd daemons
ip netns exec "$NS_A" "$YIPD" "$CFG_YIP_A" >"$LOG_YIP_A" 2>&1 &
PID_YIP_A=$!
ip netns exec "$NS_B" "$YIPD" "$CFG_YIP_B" >"$LOG_YIP_B" 2>&1 &
PID_YIP_B=$!

# Wait for TUN devices to appear
TUN_WAIT=20
INTERVAL=0.25
elapsed=0
while true; do
    A_UP=0
    B_UP=0
    ip netns exec "$NS_A" ip link show "$YIP_DEV" >/dev/null 2>&1 && A_UP=1 || true
    ip netns exec "$NS_B" ip link show "$YIP_DEV" >/dev/null 2>&1 && B_UP=1 || true

    if [ "$A_UP" -eq 1 ] && [ "$B_UP" -eq 1 ]; then
        break
    fi

    if ! kill -0 "$PID_YIP_A" 2>/dev/null; then
        echo "[error] yipA daemon died unexpectedly." >&2
        cat "$LOG_YIP_A" >&2
        exit 1
    fi
    if ! kill -0 "$PID_YIP_B" 2>/dev/null; then
        echo "[error] yipB daemon died unexpectedly." >&2
        cat "$LOG_YIP_B" >&2
        exit 1
    fi

    elapsed=$(awk "BEGIN {print $elapsed + $INTERVAL}")
    if awk "BEGIN {exit ($elapsed >= $TUN_WAIT) ? 0 : 1}"; then
        echo "[error] Timed out waiting for yip TUN devices." >&2
        exit 1
    fi
    sleep "$INTERVAL"
done

# Assign tunnel IPs to yip0
ip netns exec "$NS_A" ip addr add "${YIP_A_IP}/${YIP_PREFIX}" dev "$YIP_DEV"
ip netns exec "$NS_B" ip addr add "${YIP_B_IP}/${YIP_PREFIX}" dev "$YIP_DEV"
ip netns exec "$NS_A" ip link set "$YIP_DEV" up
ip netns exec "$NS_B" ip link set "$YIP_DEV" up

# Verify yip ping
sleep 0.5
if ! ip netns exec "$NS_B" ping -c 3 -W 3 "$YIP_A_IP" >/dev/null 2>&1; then
    echo "[error] yip tunnel ping failed." >&2
    cat "$LOG_YIP_A" >&2
    cat "$LOG_YIP_B" >&2
    exit 1
fi
echo "[setup] yip tunnel active and responsive (${YIP_A_IP} <-> ${YIP_B_IP})."

# ── 4. Head-to-Head Comparative Benchmark Suite ──────────────────────────────
CONDITIONS=("0" "1" "5")
IPERF_DURATION=3
IPERF_STREAMS=4
PING_COUNT=50
PING_INTERVAL=0.05

echo
echo "================================================================================"
echo "    Executing Comparative Benchmarks Across Channel Conditions"
echo "================================================================================"

for loss in "${CONDITIONS[@]}"; do
    echo
    if [ "$loss" -eq 0 ]; then
        echo ">>> [Condition] 0% loss (baseline unconstrained channel)"
        ip netns exec "$NS_A" tc qdisc del dev "$VETH_A" root 2>/dev/null || true
        ip netns exec "$NS_B" tc qdisc del dev "$VETH_B" root 2>/dev/null || true
    else
        echo ">>> [Condition] ${loss}% packet loss (simulated via netem)"
        ip netns exec "$NS_A" tc qdisc replace dev "$VETH_A" root netem loss "${loss}%"
        ip netns exec "$NS_B" tc qdisc replace dev "$VETH_B" root netem loss "${loss}%"
    fi
    sleep 0.5

    # ── WireGuard Benchmark ──────────────────────────────────────────────────
    echo "  [WireGuard] Measuring ICMP latency (${PING_COUNT} packets @ ${PING_INTERVAL}s)..."
    WG_PING_OUT="$TMPDIR_TEST/ping_wg_${loss}.log"
    ip netns exec "$NS_B" ping -c "$PING_COUNT" -i "$PING_INTERVAL" "$WG_A_IP" > "$WG_PING_OUT" 2>&1 || true

    echo "  [WireGuard] Measuring TCP throughput (${IPERF_STREAMS} streams, ${IPERF_DURATION}s)..."
    WG_IPERF_OUT="$TMPDIR_TEST/iperf_wg_${loss}.json"
    ip netns exec "$NS_A" iperf3 -s -p 5201 -1 >/dev/null 2>&1 &
    IPERF_SRV_WG=$!
    sleep 0.3
    ip netns exec "$NS_B" iperf3 -c "$WG_A_IP" -p 5201 -P "$IPERF_STREAMS" -t "$IPERF_DURATION" -J > "$WG_IPERF_OUT" 2>&1 || true
    kill "$IPERF_SRV_WG" 2>/dev/null || true
    wait "$IPERF_SRV_WG" 2>/dev/null || true

    sleep 0.5

    # ── yip Benchmark ─────────────────────────────────────────────────────────
    echo "  [yip]       Measuring ICMP latency (${PING_COUNT} packets @ ${PING_INTERVAL}s)..."
    YIP_PING_OUT="$TMPDIR_TEST/ping_yip_${loss}.log"
    ip netns exec "$NS_B" ping -c "$PING_COUNT" -i "$PING_INTERVAL" "$YIP_A_IP" > "$YIP_PING_OUT" 2>&1 || true

    echo "  [yip]       Measuring TCP throughput (${IPERF_STREAMS} streams, ${IPERF_DURATION}s)..."
    YIP_IPERF_OUT="$TMPDIR_TEST/iperf_yip_${loss}.json"
    ip netns exec "$NS_A" iperf3 -s -p 5202 -1 >/dev/null 2>&1 &
    IPERF_SRV_YIP=$!
    sleep 0.3
    ip netns exec "$NS_B" iperf3 -c "$YIP_A_IP" -p 5202 -P "$IPERF_STREAMS" -t "$IPERF_DURATION" -J > "$YIP_IPERF_OUT" 2>&1 || true
    kill "$IPERF_SRV_YIP" 2>/dev/null || true
    wait "$IPERF_SRV_YIP" 2>/dev/null || true
done

# ── 5. Generate and Print Markdown Comparison Report ─────────────────────────
echo
echo "================================================================================"
echo "    Benchmark Results & WireGuard Parity Summary"
echo "================================================================================"

TMPDIR_TEST="$TMPDIR_TEST" python3 - <<'PYEOF'
import json
import os
import re
import statistics

tmpdir = os.environ["TMPDIR_TEST"]
conditions = ["0", "1", "5"]

def parse_ping(file_path):
    times = []
    loss_pct = 100.0
    if not os.path.exists(file_path):
        return {"loss": 100.0, "min": 0.0, "avg": 0.0, "max": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0}

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    for line in text.splitlines():
        m_loss = re.search(r"(\d+(?:\.\d+)?)%\s+packet\s+loss", line)
        if m_loss:
            loss_pct = float(m_loss.group(1))
        m_time = re.search(r"time=([0-9\.]+)\s*ms", line)
        if m_time:
            times.append(float(m_time.group(1)))

    if not times:
        return {"loss": loss_pct, "min": 0.0, "avg": 0.0, "max": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0}

    times.sort()
    n = len(times)
    def pct(p):
        k = int(round((n - 1) * p))
        return times[k]

    return {
        "loss": loss_pct,
        "min": times[0],
        "avg": statistics.mean(times),
        "max": times[-1],
        "p50": pct(0.50),
        "p90": pct(0.90),
        "p99": pct(0.99),
    }

def parse_iperf(file_path):
    if not os.path.exists(file_path):
        return 0.0
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        bps = data.get("end", {}).get("sum_received", {}).get("bits_per_second", 0)
        if not bps:
            bps = data.get("end", {}).get("sum_sent", {}).get("bits_per_second", 0)
        return bps / 1e9  # Gbps
    except Exception:
        return 0.0

results = {}
for cond in conditions:
    wg_ping = parse_ping(os.path.join(tmpdir, f"ping_wg_{cond}.log"))
    wg_iperf = parse_iperf(os.path.join(tmpdir, f"iperf_wg_{cond}.json"))
    yip_ping = parse_ping(os.path.join(tmpdir, f"ping_yip_{cond}.log"))
    yip_iperf = parse_iperf(os.path.join(tmpdir, f"iperf_yip_{cond}.json"))
    results[cond] = {
        "wg": {"iperf": wg_iperf, "ping": wg_ping},
        "yip": {"iperf": yip_iperf, "ping": yip_ping},
    }

# Print Detailed Markdown Comparison Table
print("\n### Head-to-Head Performance Comparison: WireGuard (`wg0`) vs `yip` (`yip0`)\n")
print("| Channel Condition | Protocol | TCP Throughput (Gbps) | Packet Loss (%) | RTT p50 (ms) | RTT p90 (ms) | RTT p99 (ms) |")
print("|:------------------|:---------|----------------------:|----------------:|-------------:|-------------:|-------------:|")

for cond in conditions:
    cond_label = "0% loss (baseline)" if cond == "0" else f"{cond}% netem loss"
    r = results[cond]

    wg = r["wg"]
    print(f"| {cond_label} | Linux WireGuard (`wg0`) | {wg['iperf']:.2f} Gbps | {wg['ping']['loss']:.1f}% | {wg['ping']['p50']:.3f} ms | {wg['ping']['p90']:.3f} ms | {wg['ping']['p99']:.3f} ms |")

    yp = r["yip"]
    print(f"| {cond_label} | `yip` Daemon (`yip0`) | {yp['iperf']:.2f} Gbps | {yp['ping']['loss']:.1f}% | {yp['ping']['p50']:.3f} ms | {yp['ping']['p90']:.3f} ms | {yp['ping']['p99']:.3f} ms |")

print("\n### Executive Parity & Loss Resilience Summary\n")
print("| Simulated Loss | WireGuard TCP Goodput | `yip` TCP Goodput | WireGuard RTT p99 | `yip` RTT p99 | Goodput Retention |")
print("|:---------------|----------------------:|------------------:|------------------:|--------------:|-------------------:|")

for cond in conditions:
    label = "0% (Baseline)" if cond == "0" else f"{cond}%"
    r = results[cond]
    wg_tp = r["wg"]["iperf"]
    yp_tp = r["yip"]["iperf"]
    wg_p99 = r["wg"]["ping"]["p99"]
    yp_p99 = r["yip"]["ping"]["p99"]

    base_yp = results["0"]["yip"]["iperf"]
    retention = f"{(yp_tp / base_yp * 100):.1f}%" if base_yp > 0 else "N/A"
    print(f"| {label} | {wg_tp:.2f} Gbps | {yp_tp:.2f} Gbps | {wg_p99:.3f} ms | {yp_p99:.3f} ms | {retention} |")

print()
PYEOF

echo "[success] Live WireGuard parity benchmark complete."
