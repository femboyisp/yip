#!/usr/bin/env bash
# Multi-Engine DPI Evaluation Oracle for yip traffic (#70).
# Evaluates traffic across four engines: nDPI, tshark, Suricata, Zeek
# across four transport modes: raw-obf, quic, tls, relay.
#
# Usage:
#   Offline PCAP mode:
#     run-multi-dpi-oracle.sh --pcap-dir <dir> [out-dir]
#     run-multi-dpi-oracle.sh --obf-pcap <f> --quic-pcap <f> --tls-pcap <f> --relay-pcap <f> [--out-dir <dir>]
#   Live netns mode (Task 2):
#     run-multi-dpi-oracle.sh <yipd-binary> <ndpiReader-binary> [out-dir]
#
set -euo pipefail

# Global Configuration & Defaults
TLS_SNI="${TLS_SNI:-gateway.icloud.com}"
NDPI="${NDPI:-}"
RDV="${RDV:-}"
TSHARK="${TSHARK:-}"
SURICATA="${SURICATA:-}"
ZEEK="${ZEEK:-}"
IS_CI="${CI:-${GITHUB_ACTIONS:-false}}"

# Check if a tool is present and executable
check_tool() {
    local tool="$1"
    if [ -z "$tool" ]; then
        return 1
    fi
    if [ -x "$tool" ]; then
        return 0
    fi
    if command -v "$tool" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Resolve tool binaries
resolve_ndpi() {
    if [ -n "$NDPI" ] && [ -x "$NDPI" ]; then
        echo "$NDPI"
    elif [ -n "$NDPI" ] && command -v "$NDPI" >/dev/null 2>&1; then
        command -v "$NDPI"
    elif [ -x "refrences/nDPI/example/ndpiReader" ]; then
        echo "refrences/nDPI/example/ndpiReader"
    elif command -v ndpiReader >/dev/null 2>&1; then
        command -v ndpiReader
    else
        echo ""
    fi
}

resolve_tshark() {
    if [ -n "$TSHARK" ] && [ -x "$TSHARK" ]; then
        echo "$TSHARK"
    elif [ -n "$TSHARK" ] && command -v "$TSHARK" >/dev/null 2>&1; then
        command -v "$TSHARK"
    elif command -v tshark >/dev/null 2>&1; then
        command -v tshark
    else
        echo ""
    fi
}

resolve_suricata() {
    if [ -n "$SURICATA" ] && [ -x "$SURICATA" ]; then
        echo "$SURICATA"
    elif [ -n "$SURICATA" ] && command -v "$SURICATA" >/dev/null 2>&1; then
        command -v "$SURICATA"
    elif command -v suricata >/dev/null 2>&1; then
        command -v suricata
    else
        echo ""
    fi
}

resolve_zeek() {
    if [ -n "$ZEEK" ] && [ -x "$ZEEK" ]; then
        echo "$ZEEK"
    elif [ -n "$ZEEK" ] && command -v "$ZEEK" >/dev/null 2>&1; then
        command -v "$ZEEK"
    elif command -v zeek >/dev/null 2>&1; then
        command -v zeek
    elif [ -x "/opt/zeek/bin/zeek" ]; then
        echo "/opt/zeek/bin/zeek"
    else
        echo ""
    fi
}

resolve_rdv() {
    local rdv_candidate="${1:-}"
    if [ -n "$rdv_candidate" ] && [ -x "$rdv_candidate" ]; then
        echo "$rdv_candidate"
    elif [ -n "${RDV:-}" ] && [ -x "$RDV" ]; then
        echo "$RDV"
    elif [ -x "target/release/yip-rendezvous" ]; then
        echo "target/release/yip-rendezvous"
    elif [ -x "target/debug/yip-rendezvous" ]; then
        echo "target/debug/yip-rendezvous"
    elif command -v yip-rendezvous >/dev/null 2>&1; then
        command -v yip-rendezvous
    elif command -v cargo >/dev/null 2>&1; then
        if [ -f "Cargo.toml" ] && grep -q "yip-rendezvous" Cargo.toml; then
            cargo build --release --bin yip-rendezvous >&2 2>/dev/null || cargo build --bin yip-rendezvous >&2 2>/dev/null || true
            if [ -x "target/release/yip-rendezvous" ]; then
                echo "target/release/yip-rendezvous"
            elif [ -x "target/debug/yip-rendezvous" ]; then
                echo "target/debug/yip-rendezvous"
            fi
        fi
    else
        echo ""
    fi
}

# -----------------------------------------------------------------------------
# Process & Netns Resource Management
# -----------------------------------------------------------------------------

ACTIVE_PIDS=()
ACTIVE_NETNS=()
CLEANUP_DIRS=()

register_pid() {
    ACTIVE_PIDS+=("$1")
}

unregister_pid() {
    local target="$1"
    local new_pids=()
    for pid in "${ACTIVE_PIDS[@]+"${ACTIVE_PIDS[@]}"}"; do
        if [ "$pid" != "$target" ]; then
            new_pids+=("$pid")
        fi
    done
    ACTIVE_PIDS=("${new_pids[@]+"${new_pids[@]}"}")
}

register_netns() {
    ACTIVE_NETNS+=("$1")
}

unregister_netns() {
    local target="$1"
    local new_netns=()
    for ns in "${ACTIVE_NETNS[@]+"${ACTIVE_NETNS[@]}"}"; do
        if [ "$ns" != "$target" ]; then
            new_netns+=("$ns")
        fi
    done
    ACTIVE_NETNS=("${new_netns[@]+"${new_netns[@]}"}")
}

register_cleanup_dir() {
    CLEANUP_DIRS+=("$1")
}

unregister_cleanup_dir() {
    local target="$1"
    local new_dirs=()
    for dir in "${CLEANUP_DIRS[@]+"${CLEANUP_DIRS[@]}"}"; do
        if [ "$dir" != "$target" ]; then
            new_dirs+=("$dir")
        fi
    done
    CLEANUP_DIRS=("${new_dirs[@]+"${new_dirs[@]}"}")
}

stop_pids() {
    set +e
    for pid in "$@"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    sleep 0.2
    for pid in "$@"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        unregister_pid "$pid"
    done
    set -e
}

delete_netns() {
    set +e
    for ns in "$@"; do
        if [ -n "$ns" ]; then
            ip netns del "$ns" 2>/dev/null || true
            unregister_netns "$ns"
        fi
    done
    set -e
}

remove_dir() {
    local dir="$1"
    if [ -n "$dir" ] && [ -d "$dir" ]; then
        rm -rf "$dir"
        unregister_cleanup_dir "$dir"
    fi
}

cleanup_all() {
    set +e
    if [ "${#ACTIVE_PIDS[@]}" -gt 0 ]; then
        for pid in "${ACTIVE_PIDS[@]}"; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done
        sleep 0.2
        for pid in "${ACTIVE_PIDS[@]}"; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        done
        ACTIVE_PIDS=()
    fi
    if [ "${#ACTIVE_NETNS[@]}" -gt 0 ]; then
        for ns in "${ACTIVE_NETNS[@]}"; do
            if [ -n "$ns" ]; then
                ip netns del "$ns" 2>/dev/null || true
            fi
        done
        ACTIVE_NETNS=()
    fi
    if [ "${#CLEANUP_DIRS[@]}" -gt 0 ]; then
        for dir in "${CLEANUP_DIRS[@]}"; do
            if [ -n "$dir" ] && [ -d "$dir" ]; then
                rm -rf "$dir"
            fi
        done
        CLEANUP_DIRS=()
    fi
}

# -----------------------------------------------------------------------------
# Live Netns Capture Pipeline
# -----------------------------------------------------------------------------

capture_raw_obf() {
    local yipd_bin="${1:?Usage: capture_raw_obf <yipd-bin> <pcap_out>}"
    local pcap_out="${2:?Usage: capture_raw_obf <yipd-bin> <pcap_out>}"

    if [ "$(id -u)" -ne 0 ]; then
        echo "SKIP capture_raw_obf: needs root (netns + tcpdump)"
        return 0
    fi

    mkdir -p "$(dirname "$pcap_out")"
    local tmp_dir
    tmp_dir="$(mktemp -d /tmp/yipd-cap-raw-obf.XXXXXX)"
    register_cleanup_dir "$tmp_dir"

    local ns_a="yipMdObfA"
    local ns_b="yipMdObfB"
    local veth_a="vMdObfA"
    local veth_b="vMdObfB"
    local veth_a_ip="10.0.9.1"
    local veth_b_ip="10.0.9.2"
    local tun_a_ip="10.9.9.1"
    local tun_b_ip="10.9.9.2"
    local veth_prefix="24"
    local tun_prefix="24"
    local port="34567"
    local tun_dev="yip0"
    local obf_psk="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

    delete_netns "$ns_a" "$ns_b"
    register_netns "$ns_a"
    register_netns "$ns_b"

    local genkey_a genkey_b priv_a pub_a priv_b pub_b
    genkey_a="$("$yipd_bin" --genkey)"
    genkey_b="$("$yipd_bin" --genkey)"
    priv_a="$(echo "$genkey_a" | grep '^private=' | cut -d= -f2)"
    pub_a="$(echo "$genkey_a" | grep '^public=' | cut -d= -f2)"
    priv_b="$(echo "$genkey_b" | grep '^private=' | cut -d= -f2)"
    pub_b="$(echo "$genkey_b" | grep '^public=' | cut -d= -f2)"

    local cfg_a="$tmp_dir/yipA.conf"
    local cfg_b="$tmp_dir/yipB.conf"

    cat > "$cfg_a" <<EOF
local_private=${priv_a}
local_public=${pub_a}
peer_public=${pub_b}
listen=${veth_a_ip}:${port}
peer_endpoint=${veth_b_ip}:${port}
device=${tun_dev}
transport=raw
obf_psk=${obf_psk}
EOF

    cat > "$cfg_b" <<EOF
local_private=${priv_b}
local_public=${pub_b}
peer_public=${pub_a}
listen=${veth_b_ip}:${port}
peer_endpoint=${veth_a_ip}:${port}
device=${tun_dev}
transport=raw
obf_psk=${obf_psk}
EOF

    ip netns add "$ns_a"
    ip netns add "$ns_b"

    ip link add "$veth_a" netns "$ns_a" type veth peer name "$veth_b" netns "$ns_b"
    ip netns exec "$ns_a" ip addr add "${veth_a_ip}/${veth_prefix}" dev "$veth_a"
    ip netns exec "$ns_a" ip link set "$veth_a" up
    ip netns exec "$ns_a" ip link set lo up

    ip netns exec "$ns_b" ip addr add "${veth_b_ip}/${veth_prefix}" dev "$veth_b"
    ip netns exec "$ns_b" ip link set "$veth_b" up
    ip netns exec "$ns_b" ip link set lo up

    local tcpdump_pid
    ip netns exec "$ns_b" tcpdump -nn -i "$veth_b" -w "$pcap_out" -U "udp port $port" \
        >"$tmp_dir/tcpdump.log" 2>&1 &
    tcpdump_pid=$!
    register_pid "$tcpdump_pid"
    sleep 0.5

    local pid_a pid_b
    ip netns exec "$ns_a" "$yipd_bin" "$cfg_a" >"$tmp_dir/yipA.log" 2>&1 &
    pid_a=$!
    register_pid "$pid_a"

    ip netns exec "$ns_b" "$yipd_bin" "$cfg_b" >"$tmp_dir/yipB.log" 2>&1 &
    pid_b=$!
    register_pid "$pid_b"

    local tries=0
    while true; do
        local a_up=0 b_up=0
        ip netns exec "$ns_a" ip link show "$tun_dev" >/dev/null 2>&1 && a_up=1 || true
        ip netns exec "$ns_b" ip link show "$tun_dev" >/dev/null 2>&1 && b_up=1 || true
        if [ "$a_up" -eq 1 ] && [ "$b_up" -eq 1 ]; then
            break
        fi
        if ! kill -0 "$pid_a" 2>/dev/null || ! kill -0 "$pid_b" 2>/dev/null; then
            echo "[error] yipd died unexpectedly during raw-obf capture"
            cat "$tmp_dir/yipA.log" || true
            cat "$tmp_dir/yipB.log" || true
            stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
            delete_netns "$ns_a" "$ns_b"
            remove_dir "$tmp_dir"
            return 1
        fi
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            echo "[error] timed out waiting for TUN devices in raw-obf capture"
            cat "$tmp_dir/yipA.log" || true
            cat "$tmp_dir/yipB.log" || true
            stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
            delete_netns "$ns_a" "$ns_b"
            remove_dir "$tmp_dir"
            return 1
        fi
        sleep 0.25
    done

    ip netns exec "$ns_a" ip addr add "${tun_a_ip}/${tun_prefix}" dev "$tun_dev"
    ip netns exec "$ns_b" ip addr add "${tun_b_ip}/${tun_prefix}" dev "$tun_dev"
    ip netns exec "$ns_a" ip link set "$tun_dev" up
    ip netns exec "$ns_b" ip link set "$tun_dev" up
    sleep 0.5

    set +e
    ip netns exec "$ns_a" ping -c 20 -i 0.1 -W 1 "$tun_b_ip" >"$tmp_dir/ping.log" 2>&1
    local ping_rc=$?
    set -e
    if [ "$ping_rc" -ne 0 ]; then
        echo "[error] ping across raw-obf tunnel failed (rc=$ping_rc)"
        cat "$tmp_dir/ping.log" || true
        cat "$tmp_dir/yipA.log" || true
        cat "$tmp_dir/yipB.log" || true
        stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
        delete_netns "$ns_a" "$ns_b"
        remove_dir "$tmp_dir"
        return 1
    fi

    sleep 0.5
    stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
    delete_netns "$ns_a" "$ns_b"
    remove_dir "$tmp_dir"

    if [ ! -s "$pcap_out" ]; then
        echo "[error] captured PCAP is empty: $pcap_out"
        return 1
    fi
    echo "[capture] raw-obf: $(stat -c%s "$pcap_out") bytes written to $pcap_out"
}

capture_quic() {
    local yipd_bin="${1:?Usage: capture_quic <yipd-bin> <pcap_out>}"
    local pcap_out="${2:?Usage: capture_quic <yipd-bin> <pcap_out>}"

    if [ "$(id -u)" -ne 0 ]; then
        echo "SKIP capture_quic: needs root (netns + tcpdump)"
        return 0
    fi

    mkdir -p "$(dirname "$pcap_out")"
    local tmp_dir
    tmp_dir="$(mktemp -d /tmp/yipd-cap-quic.XXXXXX)"
    register_cleanup_dir "$tmp_dir"

    local ns_a="yipMdQuicA"
    local ns_b="yipMdQuicB"
    local veth_a="vMdQuicA"
    local veth_b="vMdQuicB"
    local veth_a_ip="10.0.10.1"
    local veth_b_ip="10.0.10.2"
    local tun_a_ip="10.10.10.1"
    local tun_b_ip="10.10.10.2"
    local veth_prefix="24"
    local tun_prefix="24"
    local port="34567"
    local tun_dev="yip0"

    delete_netns "$ns_a" "$ns_b"
    register_netns "$ns_a"
    register_netns "$ns_b"

    local genkey_a genkey_b priv_a pub_a priv_b pub_b
    genkey_a="$("$yipd_bin" --genkey)"
    genkey_b="$("$yipd_bin" --genkey)"
    priv_a="$(echo "$genkey_a" | grep '^private=' | cut -d= -f2)"
    pub_a="$(echo "$genkey_a" | grep '^public=' | cut -d= -f2)"
    priv_b="$(echo "$genkey_b" | grep '^private=' | cut -d= -f2)"
    pub_b="$(echo "$genkey_b" | grep '^public=' | cut -d= -f2)"

    local cfg_a="$tmp_dir/yipA.conf"
    local cfg_b="$tmp_dir/yipB.conf"

    cat > "$cfg_a" <<EOF
local_private=${priv_a}
local_public=${pub_a}
peer_public=${pub_b}
listen=${veth_a_ip}:${port}
peer_endpoint=${veth_b_ip}:${port}
device=${tun_dev}
transport=quic
EOF

    cat > "$cfg_b" <<EOF
local_private=${priv_b}
local_public=${pub_b}
peer_public=${pub_a}
listen=${veth_b_ip}:${port}
peer_endpoint=${veth_a_ip}:${port}
device=${tun_dev}
transport=quic
EOF

    ip netns add "$ns_a"
    ip netns add "$ns_b"

    ip link add "$veth_a" netns "$ns_a" type veth peer name "$veth_b" netns "$ns_b"
    ip netns exec "$ns_a" ip addr add "${veth_a_ip}/${veth_prefix}" dev "$veth_a"
    ip netns exec "$ns_a" ip link set "$veth_a" up
    ip netns exec "$ns_a" ip link set lo up

    ip netns exec "$ns_b" ip addr add "${veth_b_ip}/${veth_prefix}" dev "$veth_b"
    ip netns exec "$ns_b" ip link set "$veth_b" up
    ip netns exec "$ns_b" ip link set lo up

    local tcpdump_pid
    ip netns exec "$ns_b" tcpdump -nn -i "$veth_b" -w "$pcap_out" -U "udp port $port" \
        >"$tmp_dir/tcpdump.log" 2>&1 &
    tcpdump_pid=$!
    register_pid "$tcpdump_pid"
    sleep 0.5

    local pid_a pid_b
    ip netns exec "$ns_a" "$yipd_bin" "$cfg_a" >"$tmp_dir/yipA.log" 2>&1 &
    pid_a=$!
    register_pid "$pid_a"

    ip netns exec "$ns_b" "$yipd_bin" "$cfg_b" >"$tmp_dir/yipB.log" 2>&1 &
    pid_b=$!
    register_pid "$pid_b"

    local tries=0
    while true; do
        local a_up=0 b_up=0
        ip netns exec "$ns_a" ip link show "$tun_dev" >/dev/null 2>&1 && a_up=1 || true
        ip netns exec "$ns_b" ip link show "$tun_dev" >/dev/null 2>&1 && b_up=1 || true
        if [ "$a_up" -eq 1 ] && [ "$b_up" -eq 1 ]; then
            break
        fi
        if ! kill -0 "$pid_a" 2>/dev/null || ! kill -0 "$pid_b" 2>/dev/null; then
            echo "[error] yipd died unexpectedly during quic capture"
            cat "$tmp_dir/yipA.log" || true
            cat "$tmp_dir/yipB.log" || true
            stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
            delete_netns "$ns_a" "$ns_b"
            remove_dir "$tmp_dir"
            return 1
        fi
        tries=$((tries + 1))
        if [ "$tries" -ge 80 ]; then
            echo "[error] timed out waiting for TUN devices in quic capture"
            cat "$tmp_dir/yipA.log" || true
            cat "$tmp_dir/yipB.log" || true
            stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
            delete_netns "$ns_a" "$ns_b"
            remove_dir "$tmp_dir"
            return 1
        fi
        sleep 0.25
    done

    ip netns exec "$ns_a" ip addr add "${tun_a_ip}/${tun_prefix}" dev "$tun_dev"
    ip netns exec "$ns_b" ip addr add "${tun_b_ip}/${tun_prefix}" dev "$tun_dev"
    ip netns exec "$ns_a" ip link set "$tun_dev" up
    ip netns exec "$ns_b" ip link set "$tun_dev" up
    sleep 0.5

    set +e
    ip netns exec "$ns_b" ping -c 25 -i 0.1 -W 2 "$tun_a_ip" >"$tmp_dir/ping.log" 2>&1
    local ping_rc=$?
    set -e
    if [ "$ping_rc" -ne 0 ]; then
        echo "[error] ping across quic tunnel failed (rc=$ping_rc)"
        cat "$tmp_dir/ping.log" || true
        cat "$tmp_dir/yipA.log" || true
        cat "$tmp_dir/yipB.log" || true
        stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
        delete_netns "$ns_a" "$ns_b"
        remove_dir "$tmp_dir"
        return 1
    fi

    sleep 0.5
    stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
    delete_netns "$ns_a" "$ns_b"
    remove_dir "$tmp_dir"

    if [ ! -s "$pcap_out" ]; then
        echo "[error] captured PCAP is empty: $pcap_out"
        return 1
    fi
    echo "[capture] quic: $(stat -c%s "$pcap_out") bytes written to $pcap_out"
}

capture_tls() {
    local yipd_bin="${1:?Usage: capture_tls <yipd-bin> <pcap_out>}"
    local pcap_out="${2:?Usage: capture_tls <yipd-bin> <pcap_out>}"

    if [ "$(id -u)" -ne 0 ]; then
        echo "SKIP capture_tls: needs root (netns + tcpdump)"
        return 0
    fi

    mkdir -p "$(dirname "$pcap_out")"
    local tmp_dir
    tmp_dir="$(mktemp -d /tmp/yipd-cap-tls.XXXXXX)"
    register_cleanup_dir "$tmp_dir"

    local ns_a="yipMdTlsA"
    local ns_b="yipMdTlsB"
    local veth_a="vMdTlsA"
    local veth_b="vMdTlsB"
    local veth_a_ip="10.0.11.1"
    local veth_b_ip="10.0.11.2"
    local tun_a_ip="10.11.11.1"
    local tun_b_ip="10.11.11.2"
    local veth_prefix="24"
    local tun_prefix="24"
    local port="34567"
    local tun_dev="yip0"
    local cover_sni="${TLS_SNI:-gateway.icloud.com}"

    delete_netns "$ns_a" "$ns_b"
    register_netns "$ns_a"
    register_netns "$ns_b"

    local genkey_a genkey_b priv_a pub_a priv_b pub_b
    genkey_a="$("$yipd_bin" --genkey)"
    genkey_b="$("$yipd_bin" --genkey)"
    priv_a="$(echo "$genkey_a" | grep '^private=' | cut -d= -f2)"
    pub_a="$(echo "$genkey_a" | grep '^public=' | cut -d= -f2)"
    priv_b="$(echo "$genkey_b" | grep '^private=' | cut -d= -f2)"
    pub_b="$(echo "$genkey_b" | grep '^public=' | cut -d= -f2)"

    local cfg_a="$tmp_dir/yipA.conf"
    local cfg_b="$tmp_dir/yipB.conf"

    cat > "$cfg_a" <<EOF
local_private=${priv_a}
local_public=${pub_a}
peer_public=${pub_b}
listen=${veth_a_ip}:${port}
peer_endpoint=${veth_b_ip}:${port}
device=${tun_dev}
transport=tls
tls_sni=${cover_sni}
EOF

    cat > "$cfg_b" <<EOF
local_private=${priv_b}
local_public=${pub_b}
peer_public=${pub_a}
listen=${veth_b_ip}:${port}
peer_endpoint=${veth_a_ip}:${port}
device=${tun_dev}
transport=tls
tls_sni=${cover_sni}
EOF

    ip netns add "$ns_a"
    ip netns add "$ns_b"

    ip link add "$veth_a" netns "$ns_a" type veth peer name "$veth_b" netns "$ns_b"
    ip netns exec "$ns_a" ip addr add "${veth_a_ip}/${veth_prefix}" dev "$veth_a"
    ip netns exec "$ns_a" ip link set "$veth_a" up
    ip netns exec "$ns_a" ip link set lo up

    ip netns exec "$ns_b" ip addr add "${veth_b_ip}/${veth_prefix}" dev "$veth_b"
    ip netns exec "$ns_b" ip link set "$veth_b" up
    ip netns exec "$ns_b" ip link set lo up

    local tcpdump_pid
    ip netns exec "$ns_b" tcpdump -nn -i "$veth_b" -w "$pcap_out" -U "tcp port $port" \
        >"$tmp_dir/tcpdump.log" 2>&1 &
    tcpdump_pid=$!
    register_pid "$tcpdump_pid"
    sleep 0.5

    local pid_a pid_b
    ip netns exec "$ns_a" "$yipd_bin" "$cfg_a" >"$tmp_dir/yipA.log" 2>&1 &
    pid_a=$!
    register_pid "$pid_a"

    ip netns exec "$ns_b" "$yipd_bin" "$cfg_b" >"$tmp_dir/yipB.log" 2>&1 &
    pid_b=$!
    register_pid "$pid_b"

    local tries=0
    while true; do
        local a_up=0 b_up=0
        ip netns exec "$ns_a" ip link show "$tun_dev" >/dev/null 2>&1 && a_up=1 || true
        ip netns exec "$ns_b" ip link show "$tun_dev" >/dev/null 2>&1 && b_up=1 || true
        if [ "$a_up" -eq 1 ] && [ "$b_up" -eq 1 ]; then
            break
        fi
        if ! kill -0 "$pid_a" 2>/dev/null || ! kill -0 "$pid_b" 2>/dev/null; then
            echo "[error] yipd died unexpectedly during tls capture"
            cat "$tmp_dir/yipA.log" || true
            cat "$tmp_dir/yipB.log" || true
            stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
            delete_netns "$ns_a" "$ns_b"
            remove_dir "$tmp_dir"
            return 1
        fi
        tries=$((tries + 1))
        if [ "$tries" -ge 80 ]; then
            echo "[error] timed out waiting for TUN devices in tls capture"
            cat "$tmp_dir/yipA.log" || true
            cat "$tmp_dir/yipB.log" || true
            stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
            delete_netns "$ns_a" "$ns_b"
            remove_dir "$tmp_dir"
            return 1
        fi
        sleep 0.25
    done

    ip netns exec "$ns_a" ip addr add "${tun_a_ip}/${tun_prefix}" dev "$tun_dev"
    ip netns exec "$ns_b" ip addr add "${tun_b_ip}/${tun_prefix}" dev "$tun_dev"
    ip netns exec "$ns_a" ip link set "$tun_dev" up
    ip netns exec "$ns_b" ip link set "$tun_dev" up
    sleep 0.5

    set +e
    ip netns exec "$ns_b" ping -c 25 -i 0.1 -W 2 "$tun_a_ip" >"$tmp_dir/ping.log" 2>&1
    local ping_rc=$?
    set -e
    if [ "$ping_rc" -ne 0 ]; then
        echo "[error] ping across tls tunnel failed (rc=$ping_rc)"
        cat "$tmp_dir/ping.log" || true
        cat "$tmp_dir/yipA.log" || true
        cat "$tmp_dir/yipB.log" || true
        stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
        delete_netns "$ns_a" "$ns_b"
        remove_dir "$tmp_dir"
        return 1
    fi

    sleep 0.5
    stop_pids "$tcpdump_pid" "$pid_a" "$pid_b"
    delete_netns "$ns_a" "$ns_b"
    remove_dir "$tmp_dir"

    if [ ! -s "$pcap_out" ]; then
        echo "[error] captured PCAP is empty: $pcap_out"
        return 1
    fi
    echo "[capture] tls: $(stat -c%s "$pcap_out") bytes written to $pcap_out"
}

capture_relay() {
    local yipd_bin="${1:?Usage: capture_relay <yipd-bin> [rdv-bin] <pcap_out>}"
    local rdv_bin=""
    local pcap_out=""

    if [ $# -ge 3 ]; then
        rdv_bin="$2"
        pcap_out="$3"
    elif [ $# -ge 2 ]; then
        pcap_out="$2"
        rdv_bin="$(resolve_rdv)"
    else
        echo "Usage: capture_relay <yipd-bin> [rdv-bin] <pcap_out>"
        return 1
    fi

    if [ "$(id -u)" -ne 0 ]; then
        echo "SKIP capture_relay: needs root (netns + tcpdump)"
        return 0
    fi

    if [ -z "$rdv_bin" ] || [ ! -x "$rdv_bin" ]; then
        rdv_bin="$(resolve_rdv "$rdv_bin")"
    fi
    if [ -z "$rdv_bin" ] || [ ! -x "$rdv_bin" ]; then
        echo "[error] yip-rendezvous binary not found or not executable"
        return 1
    fi

    if ! check_tool openssl; then
        echo "[error] openssl required for relay TLS cert generation"
        return 1
    fi

    mkdir -p "$(dirname "$pcap_out")"
    local tmp_dir
    tmp_dir="$(mktemp -d /tmp/yipd-cap-relay.XXXXXX)"
    register_cleanup_dir "$tmp_dir"

    local ns_a="yipMdRlyA"
    local ns_b="yipMdRlyB"
    local ns_r="yipMdRlyR"

    local veth_a_n="vMdRlyA1"
    local veth_a_r="vMdRlyA0"
    local veth_b_n="vMdRlyB1"
    local veth_b_r="vMdRlyB0"

    local ip_a="10.80.0.2"
    local ip_r_a="10.80.0.1"
    local ip_b="10.81.0.2"
    local ip_r_b="10.81.0.1"
    local prefix="24"

    local port_a="51820"
    local port_b="51820"
    local rdv_udp_port="51821"
    local rdv_tcp_port="8443"
    local tun_dev="yip0"

    delete_netns "$ns_a" "$ns_b" "$ns_r"
    register_netns "$ns_a"
    register_netns "$ns_b"
    register_netns "$ns_r"

    local genkey_a genkey_b priv_a pub_a priv_b pub_b obf_psk addr_a addr_b
    genkey_a="$("$yipd_bin" --genkey)"
    genkey_b="$("$yipd_bin" --genkey)"
    priv_a="$(echo "$genkey_a" | grep '^private=' | cut -d= -f2)"
    pub_a="$(echo "$genkey_a" | grep '^public=' | cut -d= -f2)"
    priv_b="$(echo "$genkey_b" | grep '^private=' | cut -d= -f2)"
    pub_b="$(echo "$genkey_b" | grep '^public=' | cut -d= -f2)"
    obf_psk="$(openssl rand -hex 32)"
    addr_a="$("$yipd_bin" --addr "$pub_a")"
    addr_b="$("$yipd_bin" --addr "$pub_b")"

    local cfg_a="$tmp_dir/yipA.conf"
    local cfg_b="$tmp_dir/yipB.conf"

    cat > "$cfg_a" <<EOF
local_private=${priv_a}
local_public=${pub_a}
listen=${ip_a}:${port_a}
device=${tun_dev}
device_kind=tun
rendezvous=tls://${ip_r_a}:${rdv_tcp_port}
obf_psk=${obf_psk}
[peer]
public_key=${pub_b}
EOF

    cat > "$cfg_b" <<EOF
local_private=${priv_b}
local_public=${pub_b}
listen=${ip_b}:${port_b}
device=${tun_dev}
device_kind=tun
rendezvous=tls://${ip_r_b}:${rdv_tcp_port}
obf_psk=${obf_psk}
[peer]
public_key=${pub_a}
EOF

    ip netns add "$ns_a"
    ip netns add "$ns_b"
    ip netns add "$ns_r"

    ip link add "$veth_a_r" type veth peer name "$veth_a_n"
    ip link set "$veth_a_n" netns "$ns_a"
    ip link set "$veth_a_r" netns "$ns_r"
    ip netns exec "$ns_a" ip addr add "${ip_a}/${prefix}" dev "$veth_a_n"
    ip netns exec "$ns_a" ip link set "$veth_a_n" up
    ip netns exec "$ns_a" ip link set lo up
    ip netns exec "$ns_r" ip addr add "${ip_r_a}/${prefix}" dev "$veth_a_r"
    ip netns exec "$ns_r" ip link set "$veth_a_r" up

    ip link add "$veth_b_r" type veth peer name "$veth_b_n"
    ip link set "$veth_b_n" netns "$ns_b"
    ip link set "$veth_b_r" netns "$ns_r"
    ip netns exec "$ns_b" ip addr add "${ip_b}/${prefix}" dev "$veth_b_n"
    ip netns exec "$ns_b" ip link set "$veth_b_n" up
    ip netns exec "$ns_b" ip link set lo up
    ip netns exec "$ns_r" ip addr add "${ip_r_b}/${prefix}" dev "$veth_b_r"
    ip netns exec "$ns_r" ip link set "$veth_b_r" up
    ip netns exec "$ns_r" ip link set lo up

    ip netns exec "$ns_r" sysctl -q -w net.ipv4.ip_forward=0
    ip netns exec "$ns_r" sysctl -q -w net.ipv4.conf.all.forwarding=0

    if command -v iptables >/dev/null 2>&1; then
        ip netns exec "$ns_a" iptables -A OUTPUT -p udp -j DROP 2>/dev/null || true
        ip netns exec "$ns_a" iptables -A INPUT -p udp -j DROP 2>/dev/null || true
        ip netns exec "$ns_b" iptables -A OUTPUT -p udp -j DROP 2>/dev/null || true
        ip netns exec "$ns_b" iptables -A INPUT -p udp -j DROP 2>/dev/null || true
    fi

    local cert="$tmp_dir/cert.pem"
    local key="$tmp_dir/key.pem"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$key" -out "$cert" \
        -days 1 -subj '/CN=relay.test' >"$tmp_dir/openssl.log" 2>&1

    local pid_rdv
    ip netns exec "$ns_r" "$rdv_bin" "0.0.0.0:${rdv_udp_port}" \
        --listen-tcp "0.0.0.0:${rdv_tcp_port}" \
        --tls-cert "$cert" \
        --tls-key "$key" \
        --obf-psk "$obf_psk" \
        >"$tmp_dir/rdv.log" 2>&1 &
    pid_rdv=$!
    register_pid "$pid_rdv"
    sleep 0.5

    local tcpdump_pid
    ip netns exec "$ns_a" tcpdump -nn -i "$veth_a_n" -w "$pcap_out" -U "tcp port $rdv_tcp_port" \
        >"$tmp_dir/tcpdump.log" 2>&1 &
    tcpdump_pid=$!
    register_pid "$tcpdump_pid"
    sleep 0.5

    local pid_a pid_b
    ip netns exec "$ns_a" "$yipd_bin" "$cfg_a" >"$tmp_dir/yipA.log" 2>&1 &
    pid_a=$!
    register_pid "$pid_a"

    ip netns exec "$ns_b" "$yipd_bin" "$cfg_b" >"$tmp_dir/yipB.log" 2>&1 &
    pid_b=$!
    register_pid "$pid_b"

    local tries=0
    while true; do
        local a_up=0 b_up=0
        ip netns exec "$ns_a" ip link show "$tun_dev" >/dev/null 2>&1 && a_up=1 || true
        ip netns exec "$ns_b" ip link show "$tun_dev" >/dev/null 2>&1 && b_up=1 || true
        if [ "$a_up" -eq 1 ] && [ "$b_up" -eq 1 ]; then
            break
        fi
        if ! kill -0 "$pid_a" 2>/dev/null || ! kill -0 "$pid_b" 2>/dev/null || ! kill -0 "$pid_rdv" 2>/dev/null; then
            echo "[error] daemon died unexpectedly during relay capture"
            cat "$tmp_dir/rdv.log" || true
            cat "$tmp_dir/yipA.log" || true
            cat "$tmp_dir/yipB.log" || true
            stop_pids "$tcpdump_pid" "$pid_a" "$pid_b" "$pid_rdv"
            delete_netns "$ns_a" "$ns_b" "$ns_r"
            remove_dir "$tmp_dir"
            return 1
        fi
        tries=$((tries + 1))
        if [ "$tries" -ge 80 ]; then
            echo "[error] timed out waiting for TUN devices in relay capture"
            cat "$tmp_dir/rdv.log" || true
            cat "$tmp_dir/yipA.log" || true
            cat "$tmp_dir/yipB.log" || true
            stop_pids "$tcpdump_pid" "$pid_a" "$pid_b" "$pid_rdv"
            delete_netns "$ns_a" "$ns_b" "$ns_r"
            remove_dir "$tmp_dir"
            return 1
        fi
        sleep 0.25
    done

    ip netns exec "$ns_a" ip -6 addr add "${addr_a}/128" dev "$tun_dev" 2>/dev/null || true
    ip netns exec "$ns_a" ip -6 route add fd00::/8 dev "$tun_dev" 2>/dev/null || true
    ip netns exec "$ns_a" ip link set "$tun_dev" up

    ip netns exec "$ns_b" ip -6 addr add "${addr_b}/128" dev "$tun_dev" 2>/dev/null || true
    ip netns exec "$ns_b" ip -6 route add fd00::/8 dev "$tun_dev" 2>/dev/null || true
    ip netns exec "$ns_b" ip link set "$tun_dev" up
    sleep 0.5

    set +e
    ip netns exec "$ns_a" ping -6 -c 25 -i 0.2 -W 2 "$addr_b" >"$tmp_dir/ping.log" 2>&1
    local ping_rc=$?
    set -e
    if [ "$ping_rc" -ne 0 ]; then
        echo "[error] ping across relay tunnel failed (rc=$ping_rc)"
        cat "$tmp_dir/ping.log" || true
        cat "$tmp_dir/rdv.log" || true
        cat "$tmp_dir/yipA.log" || true
        cat "$tmp_dir/yipB.log" || true
        stop_pids "$tcpdump_pid" "$pid_a" "$pid_b" "$pid_rdv"
        delete_netns "$ns_a" "$ns_b" "$ns_r"
        remove_dir "$tmp_dir"
        return 1
    fi

    sleep 0.5
    stop_pids "$tcpdump_pid" "$pid_a" "$pid_b" "$pid_rdv"
    delete_netns "$ns_a" "$ns_b" "$ns_r"
    remove_dir "$tmp_dir"

    if [ ! -s "$pcap_out" ]; then
        echo "[error] captured PCAP is empty: $pcap_out"
        return 1
    fi
    echo "[capture] relay: $(stat -c%s "$pcap_out") bytes written to $pcap_out"
}

# -----------------------------------------------------------------------------
# Engine Evaluators
# -----------------------------------------------------------------------------

eval_ndpi() {
    local transport="$1"
    local pcap="$2"
    local out_dir="$3"
    local ndpi_bin
    ndpi_bin="$(resolve_ndpi)"

    mkdir -p "$out_dir"
    local ndpi_log="$out_dir/ndpi-${transport}.log"

    # If log doesn't exist and ndpiReader is available, execute it
    if [ ! -f "$ndpi_log" ]; then
        if [ -f "$out_dir/ndpi.log" ]; then
            ndpi_log="$out_dir/ndpi.log"
        elif [ -n "$pcap" ] && [ ! -f "$pcap" ]; then
            echo "FAIL (PCAP file not found: $pcap)"
            return 0
        elif [ -n "$ndpi_bin" ] && [ -f "$pcap" ]; then
            local abs_pcap
            abs_pcap="$(readlink -f "$pcap" 2>/dev/null || realpath "$pcap" 2>/dev/null || echo "$pcap")"
            "$ndpi_bin" -i "$abs_pcap" -v 2 >"$ndpi_log" 2>&1 || true
        else
            echo "SKIP (ndpiReader missing)"
            return 0
        fi
    fi

    # Evaluation rules per transport
    case "$transport" in
        raw-obf|raw/obf|obf)
            # Flow must be Unknown
            if ! grep -qiE '\[proto: 0/Unknown\]|\bUnknown\b' "$ndpi_log"; then
                echo "FAIL (flow not Unknown)"
                return 0
            fi
            # Zero detection of WireGuard, OpenVPN, Tor, or VPN categories
            if grep -qiE '\b(wireguard|openvpn|tor|proxy)\b|\[cat: *vpn\b' "$ndpi_log"; then
                echo "FAIL (VPN/proxy detected)"
                return 0
            fi
            # Zero NDPI_OBFUSCATED_TRAFFIC risk
            if grep -qiE 'obfuscated traffic|ndpi_obfuscated_traffic' "$ndpi_log"; then
                echo "FAIL (Obfuscated Traffic risk)"
                return 0
            fi
            echo "PASS (Unknown)"
            ;;
        quic)
            # Positive QUIC classification
            if ! grep -qiE '\[proto: [0-9]+\.[0-9]+/[^]]*quic[^]]*\]|\[stack: [^]]*quic[^]]*\]|\bquic\b' "$ndpi_log"; then
                echo "FAIL (flow not QUIC)"
                return 0
            fi
            # Zero Susp Entropy risk
            if grep -qiE 'susp entropy|ndpi_suspicious_entropy' "$ndpi_log"; then
                echo "FAIL (Susp Entropy risk)"
                return 0
            fi
            # Zero Obfuscated Traffic risk
            if grep -qiE 'obfuscated traffic|ndpi_obfuscated_traffic' "$ndpi_log"; then
                echo "FAIL (Obfuscated Traffic risk)"
                return 0
            fi
            # Zero VPN detection
            if grep -qiE '\b(wireguard|openvpn|tor|proxy)\b|\[cat: *vpn\b' "$ndpi_log"; then
                echo "FAIL (VPN/proxy detected)"
                return 0
            fi
            echo "PASS (QUIC)"
            ;;
        tls)
            # Positive TLS classification
            if ! grep -qiE '\[proto: [0-9]+(\.[0-9]+)?/[^]]*tls[^]]*\]|\[stack: [^]]*tls[^]]*\]|\btls\b' "$ndpi_log"; then
                echo "FAIL (flow not TLS)"
                return 0
            fi
            # SNI detected
            if ! grep -qiF "$TLS_SNI" "$ndpi_log"; then
                echo "FAIL (SNI $TLS_SNI not detected)"
                return 0
            fi
            # Zero VPN detection
            if grep -qiE '\b(wireguard|openvpn|tor|proxy)\b|\[cat: *vpn\b' "$ndpi_log"; then
                echo "FAIL (VPN/proxy detected)"
                return 0
            fi
            # Zero Obfuscated Traffic risk
            if grep -qiE 'obfuscated traffic|ndpi_obfuscated_traffic' "$ndpi_log"; then
                echo "FAIL (Obfuscated Traffic risk)"
                return 0
            fi
            # Zero Susp Entropy risk
            if grep -qiE 'susp entropy|ndpi_suspicious_entropy' "$ndpi_log"; then
                echo "FAIL (Susp Entropy risk)"
                return 0
            fi
            echo "PASS (TLS+SNI)"
            ;;
        relay)
            # Positive TLS classification
            if ! grep -qiE '\[proto: [0-9]+(\.[0-9]+)?/[^]]*tls[^]]*\]|\[stack: [^]]*tls[^]]*\]|\btls\b' "$ndpi_log"; then
                echo "FAIL (flow not TLS)"
                return 0
            fi
            # Zero VPN detection
            if grep -qiE '\b(wireguard|openvpn|tor|proxy)\b|\[cat: *vpn\b' "$ndpi_log"; then
                echo "FAIL (VPN/proxy detected)"
                return 0
            fi
            echo "PASS (TLS Front)"
            ;;
        *)
            echo "FAIL (unknown transport $transport)"
            ;;
    esac
}

eval_tshark() {
    local transport="$1"
    local pcap="$2"
    local out_dir="$3"
    local tshark_bin
    tshark_bin="$(resolve_tshark)"

    mkdir -p "$out_dir"
    local phs_file="$out_dir/tshark-${transport}-phs.txt"
    local fields_file="$out_dir/tshark-${transport}-fields.txt"

    # If outputs don't exist and tshark is available, run tshark
    if [ ! -f "$phs_file" ] || [ ! -f "$fields_file" ]; then
        if [ -f "$out_dir/tshark-phs.txt" ] && [ -f "$out_dir/tshark-fields.txt" ]; then
            phs_file="$out_dir/tshark-phs.txt"
            fields_file="$out_dir/tshark-fields.txt"
        elif [ -n "$pcap" ] && [ ! -f "$pcap" ]; then
            echo "FAIL (PCAP file not found: $pcap)"
            return 0
        elif [ -n "$tshark_bin" ] && [ -f "$pcap" ]; then
            local abs_pcap
            abs_pcap="$(readlink -f "$pcap" 2>/dev/null || realpath "$pcap" 2>/dev/null || echo "$pcap")"
            "$tshark_bin" -r "$abs_pcap" -q -z io,phs >"$phs_file" 2>&1 || true
            "$tshark_bin" -r "$abs_pcap" -T fields -e frame.protocols -e tls.handshake.extensions_server_name >"$fields_file" 2>&1 || true
        else
            echo "SKIP (tshark missing)"
            return 0
        fi
    fi

    case "$transport" in
        raw-obf|raw/obf|obf)
            # Zero VPN dissectors
            if grep -qiE '\b(wireguard|openvpn|socks|ssh|ipsec|tor|vpn)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (VPN dissector detected)"
                return 0
            fi
            # Generic data / udp
            if ! grep -qiE '\b(data|udp)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (missing data/udp in protocol hierarchy)"
                return 0
            fi
            echo "PASS (Data/UDP)"
            ;;
        quic)
            # Zero VPN dissectors
            if grep -qiE '\b(wireguard|openvpn|socks|ssh|ipsec|tor|vpn)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (VPN dissector detected)"
                return 0
            fi
            # Protocols contain quic
            if ! grep -qiE '\bquic\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (quic not detected in protocols)"
                return 0
            fi
            echo "PASS (quic)"
            ;;
        tls)
            # Zero VPN dissectors
            if grep -qiE '\b(wireguard|openvpn|socks|ssh|ipsec|tor|vpn)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (VPN dissector detected)"
                return 0
            fi
            # Protocols contain tls or ssl
            if ! grep -qiE '\b(tls|ssl)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (tls/ssl not detected in protocols)"
                return 0
            fi
            # SNI matches configured target
            if ! grep -qiF "$TLS_SNI" "$fields_file" 2>/dev/null; then
                echo "FAIL (SNI $TLS_SNI not found in ClientHello)"
                return 0
            fi
            echo "PASS (tls+SNI)"
            ;;
        relay)
            # Zero VPN dissectors
            if grep -qiE '\b(wireguard|openvpn|socks|ssh|ipsec|tor|vpn)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (VPN dissector detected)"
                return 0
            fi
            # Protocols contain tls or ssl
            if ! grep -qiE '\b(tls|ssl)\b' "$fields_file" "$phs_file" 2>/dev/null; then
                echo "FAIL (tls not detected in protocols)"
                return 0
            fi
            echo "PASS (tls+SNI)"
            ;;
        *)
            echo "FAIL (unknown transport $transport)"
            ;;
    esac
}

eval_suricata() {
    local transport="$1"
    local pcap="$2"
    local out_dir="$3"
    local suricata_bin
    suricata_bin="$(resolve_suricata)"

    local suricata_dir="$out_dir/suricata-${transport}"
    local eve_file="$suricata_dir/eve.json"

    # Check for direct or transport-specific eve.json
    if [ ! -f "$eve_file" ]; then
        if [ -f "$out_dir/eve.json" ]; then
            eve_file="$out_dir/eve.json"
        elif [ -n "$pcap" ] && [ ! -f "$pcap" ]; then
            echo "FAIL (PCAP file not found: $pcap)"
            return 0
        elif [ -n "$suricata_bin" ] && [ -f "$pcap" ]; then
            mkdir -p "$suricata_dir"
            local abs_pcap
            abs_pcap="$(readlink -f "$pcap" 2>/dev/null || realpath "$pcap" 2>/dev/null || echo "$pcap")"
            "$suricata_bin" -r "$abs_pcap" -l "$suricata_dir" -k none --runmode single >/dev/null 2>&1 || true
        else
            echo "SKIP (suricata missing)"
            return 0
        fi
    fi

    if [ ! -f "$eve_file" ]; then
        echo "FAIL (eve.json not generated)"
        return 0
    fi

    # Zero alerts matching VPN/tunnel signatures (or alerts count = 0)
    if grep -qiE '"event_type":\s*"alert"' "$eve_file" 2>/dev/null; then
        if grep -iE '"event_type":\s*"alert"' "$eve_file" | grep -qiE 'vpn|tunnel|wireguard|openvpn|tor|shadowsocks|proxy'; then
            echo "FAIL (VPN/tunnel alert triggered)"
            return 0
        else
            echo "FAIL (Suricata alert triggered)"
            return 0
        fi
    fi

    case "$transport" in
        raw-obf|raw/obf|obf)
            # app_proto should not be a recognized VPN or L7 protocol
            if grep -qiE '"app_proto":\s*"(wireguard|openvpn|tor|shadowsocks|quic|tls)"' "$eve_file" 2>/dev/null; then
                echo "FAIL (unexpected app_proto recognized)"
                return 0
            fi
            echo "PASS (0 alerts)"
            ;;
        quic)
            # app_proto identified as quic (or quic event)
            if ! grep -qiE '"app_proto":\s*"quic"|"event_type":\s*"quic"' "$eve_file" 2>/dev/null; then
                echo "FAIL (quic not identified by app_proto)"
                return 0
            fi
            echo "PASS (0 alerts, quic)"
            ;;
        tls)
            # tls event in eve.json with matching SNI
            if ! grep -qiE '"app_proto":\s*"tls"|"event_type":\s*"tls"' "$eve_file" 2>/dev/null; then
                echo "FAIL (tls not identified by app_proto)"
                return 0
            fi
            if ! grep -qiF "$TLS_SNI" "$eve_file" 2>/dev/null; then
                echo "FAIL (SNI $TLS_SNI not found in tls eve events)"
                return 0
            fi
            echo "PASS (0 alerts, tls)"
            ;;
        relay)
            # tls identified by app_proto
            if ! grep -qiE '"app_proto":\s*"tls"|"event_type":\s*"tls"' "$eve_file" 2>/dev/null; then
                echo "FAIL (tls not identified by app_proto)"
                return 0
            fi
            echo "PASS (0 alerts)"
            ;;
        *)
            echo "FAIL (unknown transport $transport)"
            ;;
    esac
}

eval_zeek() {
    local transport="$1"
    local pcap="$2"
    local out_dir="$3"
    local zeek_bin
    zeek_bin="$(resolve_zeek)"

    local zeek_dir="$out_dir/zeek-${transport}"
    local conn_log="$zeek_dir/conn.log"
    local notice_log="$zeek_dir/notice.log"
    local ssl_log="$zeek_dir/ssl.log"

    # Check for logs in $out_dir or run zeek
    if [ ! -f "$conn_log" ]; then
        if [ -f "$out_dir/conn.log" ]; then
            zeek_dir="$out_dir"
            conn_log="$out_dir/conn.log"
            notice_log="$out_dir/notice.log"
            ssl_log="$out_dir/ssl.log"
        elif [ -n "$pcap" ] && [ ! -f "$pcap" ]; then
            echo "FAIL (PCAP file not found: $pcap)"
            return 0
        elif [ -n "$zeek_bin" ] && [ -f "$pcap" ]; then
            mkdir -p "$zeek_dir"
            local abs_pcap
            abs_pcap="$(readlink -f "$pcap" 2>/dev/null || realpath "$pcap" 2>/dev/null || echo "$pcap")"
            (cd "$zeek_dir" && "$zeek_bin" -C -r "$abs_pcap" local >/dev/null 2>&1 || true)
        else
            echo "SKIP (zeek missing)"
            return 0
        fi
    fi

    # notice.log must not contain tunnel/anomaly notices
    if [ -f "$notice_log" ]; then
        if grep -v '^#' "$notice_log" | grep -qiE 'tunnel|vpn|wireguard|openvpn|tor|proxy|anomaly'; then
            echo "FAIL (tunnel notice triggered)"
            return 0
        fi
    fi

    if [ ! -f "$conn_log" ]; then
        echo "FAIL (conn.log not generated)"
        return 0
    fi

    case "$transport" in
        raw-obf|raw/obf|obf)
            # service must be unclassified '-' and no VPN
            if grep -v '^#' "$conn_log" | grep -qiE '\b(wireguard|openvpn|tor|shadowsocks|vpn)\b'; then
                echo "FAIL (VPN service detected)"
                return 0
            fi
            if grep -v '^#' "$conn_log" | grep -qiE '\b(ssl|quic|http)\b'; then
                echo "FAIL (unexpected L7 service recognized in conn.log)"
                return 0
            fi
            echo "PASS (0 notices)"
            ;;
        quic)
            # service field contains quic or ssl
            if ! grep -v '^#' "$conn_log" | grep -qiE '\b(quic|ssl)\b'; then
                echo "FAIL (quic service not recognized in conn.log)"
                return 0
            fi
            echo "PASS (0 notices, quic)"
            ;;
        tls)
            # service field contains ssl
            if ! grep -v '^#' "$conn_log" | grep -qiE '\bssl\b'; then
                echo "FAIL (ssl service not recognized in conn.log)"
                return 0
            fi
            # If ssl.log is generated, verify server_name
            if [ -f "$ssl_log" ]; then
                if ! grep -v '^#' "$ssl_log" | grep -qiF "$TLS_SNI"; then
                    echo "FAIL (server_name $TLS_SNI not in ssl.log)"
                    return 0
                fi
            fi
            echo "PASS (0 notices, ssl)"
            ;;
        relay)
            # service field contains ssl
            if ! grep -v '^#' "$conn_log" | grep -qiE '\bssl\b'; then
                echo "FAIL (ssl service not recognized in conn.log)"
                return 0
            fi
            echo "PASS (0 notices, ssl)"
            ;;
        *)
            echo "FAIL (unknown transport $transport)"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Verdict Table Generation
# -----------------------------------------------------------------------------

format_verdict_table() {
    local out_dir="$1"
    shift
    # Remaining args are key=value pairs: e.g. raw_obf_ndpi="PASS (...)"
    declare -A verdicts
    for arg in "$@"; do
        local key="${arg%%=*}"
        local val="${arg#*=}"
        verdicts["$key"]="$val"
    done

    local md_file="$out_dir/verdict-summary.md"
    mkdir -p "$out_dir"

    local transports=("raw-obf" "quic" "tls" "relay")
    local display_names=("raw/obf" "quic" "tls" "relay")

    local any_fail=0
    local any_skip=0

    {
        echo "| Transport | nDPI Verdict | tshark Verdict | Suricata Verdict | Zeek Verdict | Overall |"
        echo "| :--- | :--- | :--- | :--- | :--- | :--- |"
        for i in "${!transports[@]}"; do
            local t="${transports[$i]}"
            local d="${display_names[$i]}"
            local t_key="${t//-/_}"
            local v_ndpi="${verdicts[${t_key}_ndpi]:-SKIP}"
            local v_tshark="${verdicts[${t_key}_tshark]:-SKIP}"
            local v_suricata="${verdicts[${t_key}_suricata]:-SKIP}"
            local v_zeek="${verdicts[${t_key}_zeek]:-SKIP}"

            local row_fail=0
            local row_all_skip=1
            for v in "$v_ndpi" "$v_tshark" "$v_suricata" "$v_zeek"; do
                if [[ "$v" =~ ^FAIL ]]; then
                    row_fail=1
                    any_fail=1
                fi
                if [[ "$v" =~ ^SKIP ]]; then
                    any_skip=1
                else
                    row_all_skip=0
                fi
            done

            local row_overall="**PASS**"
            if [ "$row_fail" -eq 1 ]; then
                row_overall="**FAIL**"
            elif [ "$row_all_skip" -eq 1 ]; then
                row_overall="**SKIP**"
            fi

            echo "| \`$d\` | $v_ndpi | $v_tshark | $v_suricata | $v_zeek | $row_overall |"
        done
    } > "$md_file"

    echo ""
    echo "============================= VERDICT SUMMARY ============================="
    cat "$md_file"
    echo "==========================================================================="
    echo "Verdict table written to: $md_file"
    echo ""

    if [ "$any_fail" -ne 0 ]; then
        return 1
    fi
    if [ "$IS_CI" = "true" ] && [ "$any_skip" -ne 0 ]; then
        echo "[ERROR] Honesty guard: engine(s) were skipped in CI environment!"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Main CLI & Dispatcher
# -----------------------------------------------------------------------------

main() {
    trap cleanup_all EXIT INT TERM

    local pcap_dir=""
    local obf_pcap=""
    local quic_pcap=""
    local tls_pcap=""
    local relay_pcap=""
    local out_dir=""
    local yipd_bin=""
    local ndpi_bin=""

    # Argument parsing
    while [ $# -gt 0 ]; do
        case "$1" in
            --pcap-dir)
                pcap_dir="$2"
                shift 2
                ;;
            --obf-pcap|--raw-obf-pcap)
                obf_pcap="$2"
                shift 2
                ;;
            --quic-pcap)
                quic_pcap="$2"
                shift 2
                ;;
            --tls-pcap)
                tls_pcap="$2"
                shift 2
                ;;
            --relay-pcap)
                relay_pcap="$2"
                shift 2
                ;;
            --out-dir)
                out_dir="$2"
                shift 2
                ;;
            --ndpi-bin)
                NDPI="$2"
                shift 2
                ;;
            --rdv-bin)
                RDV="$2"
                shift 2
                ;;
            --sni)
                TLS_SNI="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [--pcap-dir <dir> | <yipd-binary> <ndpiReader-binary> [out-dir]]"
                exit 0
                ;;
            *)
                if [ -z "$yipd_bin" ] && [ -z "$pcap_dir" ]; then
                    yipd_bin="$1"
                    shift
                elif [ -z "$ndpi_bin" ] && [ -n "$yipd_bin" ]; then
                    ndpi_bin="$1"
                    NDPI="$ndpi_bin"
                    shift
                elif [ -z "$out_dir" ]; then
                    out_dir="$1"
                    shift
                else
                    shift
                fi
                ;;
        esac
    done

    # Resolve output directory
    if [ -z "$out_dir" ]; then
        out_dir="$(mktemp -d /tmp/yipd-multi-dpi-oracle.XXXXXX)"
    else
        mkdir -p "$out_dir"
    fi

    # Handle PCAP directory ingestion
    if [ -n "$pcap_dir" ]; then
        [ -z "$obf_pcap" ] && obf_pcap="$pcap_dir/raw-obf.pcap"
        [ ! -f "$obf_pcap" ] && [ -f "$pcap_dir/yip-obf.pcap" ] && obf_pcap="$pcap_dir/yip-obf.pcap"
        [ -z "$quic_pcap" ] && quic_pcap="$pcap_dir/quic.pcap"
        [ ! -f "$quic_pcap" ] && [ -f "$pcap_dir/yip-quic.pcap" ] && quic_pcap="$pcap_dir/yip-quic.pcap"
        [ -z "$tls_pcap" ] && tls_pcap="$pcap_dir/tls.pcap"
        [ ! -f "$tls_pcap" ] && [ -f "$pcap_dir/yip-tls.pcap" ] && tls_pcap="$pcap_dir/yip-tls.pcap"
        [ -z "$relay_pcap" ] && relay_pcap="$pcap_dir/relay.pcap"
        [ ! -f "$relay_pcap" ] && [ -f "$pcap_dir/yip-relay.pcap" ] && relay_pcap="$pcap_dir/yip-relay.pcap"
    fi

    # If PCAPs are still not provided, check if live capture was requested
    if [ -z "$obf_pcap" ] && [ -z "$quic_pcap" ] && [ -z "$tls_pcap" ] && [ -z "$relay_pcap" ]; then
        if [ -n "$yipd_bin" ]; then
            if [ "$(id -u)" -ne 0 ]; then
                echo "SKIP run-multi-dpi-oracle: needs root (netns + tcpdump) for live capture, or use --pcap-dir <dir>"
                exit 0
            fi

            for req_tool in tcpdump ip; do
                if ! check_tool "$req_tool"; then
                    echo "SKIP run-multi-dpi-oracle: required tool '$req_tool' not found"
                    exit 0
                fi
            done

            if [ ! -x "$yipd_bin" ]; then
                echo "Error: yipd binary not executable at '$yipd_bin'"
                exit 1
            fi

            local rdv_bin
            rdv_bin="$(resolve_rdv "${RDV:-}")"
            if [ -z "$rdv_bin" ] || [ ! -x "$rdv_bin" ]; then
                echo "Error: yip-rendezvous binary not found or not executable. Use --rdv-bin <path> or build target/release/yip-rendezvous"
                exit 1
            fi

            local pcap_capture_dir="$out_dir/pcaps"
            mkdir -p "$pcap_capture_dir"
            obf_pcap="$pcap_capture_dir/raw-obf.pcap"
            quic_pcap="$pcap_capture_dir/quic.pcap"
            tls_pcap="$pcap_capture_dir/tls.pcap"
            relay_pcap="$pcap_capture_dir/relay.pcap"

            echo "=== Executing Live Netns Capture Pipeline ==="
            echo "[capture 1/4] raw-obf -> $obf_pcap"
            capture_raw_obf "$yipd_bin" "$obf_pcap"

            echo "[capture 2/4] quic -> $quic_pcap"
            capture_quic "$yipd_bin" "$quic_pcap"

            echo "[capture 3/4] tls -> $tls_pcap"
            capture_tls "$yipd_bin" "$tls_pcap"

            echo "[capture 4/4] relay -> $relay_pcap"
            capture_relay "$yipd_bin" "$rdv_bin" "$relay_pcap"

            echo "=== Live Netns Captures Completed ==="
        else
            echo "Error: no PCAP inputs provided and no yipd binary specified."
            echo "Usage: $0 [--pcap-dir <dir> | <yipd-binary> <ndpiReader-binary> [out-dir]]"
            exit 1
        fi
    fi

    echo "=== Running Multi-Engine DPI Oracle ==="
    echo "Output directory: $out_dir"
    echo "TLS Target SNI:   $TLS_SNI"

    local pcap_map=(
        "raw_obf:$obf_pcap"
        "quic:$quic_pcap"
        "tls:$tls_pcap"
        "relay:$relay_pcap"
    )

    local verdict_args=()

    for item in "${pcap_map[@]}"; do
        local t_key="${item%%:*}"
        local pcap="${item#*:}"
        local transport="${t_key//_/-}"

        echo "--- Evaluating Transport: $transport ---"
        echo "PCAP file: $pcap"

        local v_ndpi v_tshark v_suricata v_zeek
        v_ndpi="$(eval_ndpi "$transport" "$pcap" "$out_dir")"
        echo "  nDPI:     $v_ndpi"
        v_tshark="$(eval_tshark "$transport" "$pcap" "$out_dir")"
        echo "  tshark:   $v_tshark"
        v_suricata="$(eval_suricata "$transport" "$pcap" "$out_dir")"
        echo "  Suricata: $v_suricata"
        v_zeek="$(eval_zeek "$transport" "$pcap" "$out_dir")"
        echo "  Zeek:     $v_zeek"

        verdict_args+=("${t_key}_ndpi=$v_ndpi")
        verdict_args+=("${t_key}_tshark=$v_tshark")
        verdict_args+=("${t_key}_suricata=$v_suricata")
        verdict_args+=("${t_key}_zeek=$v_zeek")
    done

    format_verdict_table "$out_dir" "${verdict_args[@]}"
    local rc=$?
    exit $rc
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
