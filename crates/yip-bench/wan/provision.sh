#!/usr/bin/env bash
# Provision both hosts for the WAN benchmark: install tooling, ship the yipd
# binary, and bring up three coexisting tunnels (yip / WireGuard / OpenVPN) on
# distinct /30 overlays, then verify connectivity through each. Idempotent:
# safe to re-run; it tears down its own prior instances first.
#
# Usage: ./provision.sh            (uses wan.env)
#        KEEP_YIPD_BUILD=1 ./...   (skip the local cargo build; reuse the binary)
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SUITE_DIR/lib.sh"

REMOTE_BIN=/usr/local/bin/yipd
REMOTE_ETC=/etc/yipbench

# ── yipd binary ────────────────────────────────────────────────────────────
build_and_ship_yipd() {
    local bin="$REPO_ROOT/target/release/yipd"
    if [[ -z "${KEEP_YIPD_BUILD:-}" || ! -x "$bin" ]]; then
        log "building yipd release locally (glibc match: local == server)"
        ( cd "$REPO_ROOT" && cargo build --release -p yipd >/dev/null )
    fi
    [[ -x "$bin" ]] || die "yipd binary missing at $bin"
    log "shipping yipd to both hosts"
    # Stop any running instance first, and ship to a temp path then mv into
    # place — you cannot scp-overwrite a running executable (ETXTBSY); a rename
    # swaps the directory entry cleanly while the old process keeps its inode.
    A "systemctl stop yipbench-yip 2>/dev/null; mkdir -p $REMOTE_ETC"
    B "systemctl stop yipbench-yip 2>/dev/null; mkdir -p $REMOTE_ETC"
    put_A "$bin" "$REMOTE_BIN.new"; put_B "$bin" "$REMOTE_BIN.new"
    A "chmod +x $REMOTE_BIN.new && mv -f $REMOTE_BIN.new $REMOTE_BIN"
    B "chmod +x $REMOTE_BIN.new && mv -f $REMOTE_BIN.new $REMOTE_BIN"
    local test_err
    if ! test_err=$(A "$REMOTE_BIN --genkey" 2>&1 >/dev/null); then
        if [[ "$test_err" =~ "GLIBC_" ]]; then
            die "yipd binary failed to run on host A due to glibc mismatch: $test_err\nEnsure local build glibc matches or is older than the server (e.g. build with ubuntu-22.04 for Debian 12)."
        fi
        die "yipd will not run on host A: $test_err"
    fi
}

# ── packages ────────────────────────────────────────────────────────────────
install_packages() {
    log "installing wireguard-tools/openvpn/iperf3/mgen on both hosts (idempotent)"
    local pkgs="wireguard-tools openvpn iperf3 mgen"
    for host in A B; do
        "$host" "export DEBIAN_FRONTEND=noninteractive; \
                 apt-get update -qq >/dev/null 2>&1 || true; \
                 apt-get install -y -qq $pkgs >/dev/null 2>&1 || true; \
                 modprobe wireguard 2>/dev/null || true"
    done
}

# ── host tuning ─────────────────────────────────────────────────────────────
# Raise UDP socket-buffer ceilings so yipd's requested 4 MiB SO_RCVBUF/SO_SNDBUF
# actually takes effect (the stock 208 KB cap silently throttles a userspace
# tunnel and causes drops under load; in-kernel WireGuard is unaffected). This
# is standard VPN-host tuning, applied equally to both hosts and disclosed in
# RESULTS.md so the comparison stays fair and reproducible.
tune_sysctls() {
    log "raising UDP socket-buffer ceilings (fair host tuning; disclosed in results)"
    local s="net.core.rmem_max=16777216 net.core.wmem_max=16777216 net.core.netdev_max_backlog=5000"
    A "sysctl -qw $s"; B "sysctl -qw $s"
}

# ── yip tunnel ──────────────────────────────────────────────────────────────
setup_yip() {
    log "bringing up yip tunnel ($YIP_A <-> $YIP_B, udp/$YIP_PORT, transport=raw)"
    local ka kb pa pb sa sb
    ka="$("$REPO_ROOT/target/release/yipd" --genkey)"
    kb="$("$REPO_ROOT/target/release/yipd" --genkey)"
    pa="$(sed -n 's/public=//p'  <<<"$ka")"; sa="$(sed -n 's/private=//p' <<<"$ka")"
    pb="$(sed -n 's/public=//p'  <<<"$kb")"; sb="$(sed -n 's/private=//p' <<<"$kb")"

    local tmp="$SUITE_DIR/results/.yipconf"; mkdir -p "$tmp"
    _yip_conf() { # <priv> <pub> <peerpub> <peer_ip> > file
        cat <<EOF
local_private=$1
local_public=$2
listen=0.0.0.0:$YIP_PORT
device=yipbench0
device_kind=tun
[peer]
public_key=$3
endpoint=$4:$YIP_PORT
EOF
    }
    _yip_conf "$sa" "$pa" "$pb" "$HOST_B" > "$tmp/a.conf"
    _yip_conf "$sb" "$pb" "$pa" "$HOST_A" > "$tmp/b.conf"
    put_A "$tmp/a.conf" "$REMOTE_ETC/yip.conf"
    put_B "$tmp/b.conf" "$REMOTE_ETC/yip.conf"

    _yip_up() { # host-fn overlay-ip
        "$1" "bash -s $2" <<'REMOTE'
OIP="$1"
systemctl reset-failed yipbench-yip 2>/dev/null; systemctl stop yipbench-yip 2>/dev/null
pkill -9 -x yipd 2>/dev/null; sleep 0.4
ip link del yipbench0 2>/dev/null || true
systemd-run --unit=yipbench-yip --collect /usr/local/bin/yipd /etc/yipbench/yip.conf >/dev/null 2>&1
for i in $(seq 1 25); do ip link show yipbench0 >/dev/null 2>&1 && break; sleep 0.2; done
ip addr add "$OIP/30" dev yipbench0 2>/dev/null || true
ip link set yipbench0 mtu 1380 up
REMOTE
    }
    _yip_up A "$YIP_A"; _yip_up B "$YIP_B"
}

# ── WireGuard tunnel ────────────────────────────────────────────────────────
setup_wireguard() {
    log "bringing up WireGuard tunnel ($WG_A <-> $WG_B, udp/$WG_PORT)"
    local pa pb sa sb
    pa="$(A "wg genkey | tee $REMOTE_ETC/wg.key | wg pubkey")"; sa="$(A "cat $REMOTE_ETC/wg.key")"
    pb="$(B "wg genkey | tee $REMOTE_ETC/wg.key | wg pubkey")"; sb="$(B "cat $REMOTE_ETC/wg.key")"

    _wg_conf() { # <priv> <addr> <peerpub> <peer_ip> <allowed>
        cat <<EOF
[Interface]
Address = $2/30
ListenPort = $WG_PORT
PrivateKey = $1
MTU = $OVERLAY_MTU
[Peer]
PublicKey = $3
Endpoint = $4:$WG_PORT
AllowedIPs = $5/32
PersistentKeepalive = 25
EOF
    }
    local tmp="$SUITE_DIR/results/.wgconf"; mkdir -p "$tmp"
    _wg_conf "$sa" "$WG_A" "$pb" "$HOST_B" "$WG_B" > "$tmp/a.conf"
    _wg_conf "$sb" "$WG_B" "$pa" "$HOST_A" "$WG_A" > "$tmp/b.conf"
    put_A "$tmp/a.conf" "/etc/wireguard/wgbench.conf"
    put_B "$tmp/b.conf" "/etc/wireguard/wgbench.conf"
    A "wg-quick down wgbench 2>/dev/null; wg-quick up wgbench >/dev/null 2>&1"
    B "wg-quick down wgbench 2>/dev/null; wg-quick up wgbench >/dev/null 2>&1"
}

# ── OpenVPN tunnel (static-key P2P, UDP) ────────────────────────────────────
setup_openvpn() {
    log "bringing up OpenVPN tunnel ($OVPN_A <-> $OVPN_B, udp/$OVPN_PORT)"
    # Static key generated on A, copied to B (no PKI). Try AES-256-GCM, fall
    # back to AES-256-CBC if the OpenVPN build rejects GCM in --secret mode.
    A "test -f $REMOTE_ETC/ovpn.key || openvpn --genkey secret $REMOTE_ETC/ovpn.key"
    local key; key="$(A "cat $REMOTE_ETC/ovpn.key | base64 -w0")"
    B "echo '$key' | base64 -d > $REMOTE_ETC/ovpn.key; chmod 600 $REMOTE_ETC/ovpn.key"

    _ovpn_up() { # host-fn local-ip remote-ip remote-host
        "$1" "bash -s '$2' '$3' '$4' '$OVPN_PORT' '$OVERLAY_MTU' '$REMOTE_ETC'" <<'REMOTE'
LOCAL="$1"; REMOTE="$2"; RHOST="$3"; PORT="$4"; MTU="$5"; ETC="$6"
systemctl reset-failed yipbench-ovpn 2>/dev/null; systemctl stop yipbench-ovpn 2>/dev/null
pkill -9 -x openvpn 2>/dev/null; ip link del tunovpn0 2>/dev/null; sleep 0.3
start() { # <cipher>
  systemd-run --unit=yipbench-ovpn --collect openvpn \
    --dev tunovpn0 --dev-type tun --proto udp \
    --lport "$PORT" --rport "$PORT" --remote "$RHOST" \
    --ifconfig "$LOCAL" "$REMOTE" --secret "$ETC/ovpn.key" \
    --cipher "$1" --auth SHA256 --tun-mtu "$MTU" \
    --ping 10 --ping-restart 30 --verb 1 >/dev/null 2>&1
}
start AES-256-GCM
for i in $(seq 1 15); do ip link show tunovpn0 >/dev/null 2>&1 && break; sleep 0.2; done
if ! ip link show tunovpn0 >/dev/null 2>&1; then
  systemctl reset-failed yipbench-ovpn 2>/dev/null; systemctl stop yipbench-ovpn 2>/dev/null; sleep 0.3
  start AES-256-CBC
  for i in $(seq 1 15); do ip link show tunovpn0 >/dev/null 2>&1 && break; sleep 0.2; done
fi
ip link set tunovpn0 mtu "$MTU" up 2>/dev/null || true
echo "ovpn-cipher=$(journalctl -u yipbench-ovpn --no-pager -o cat 2>/dev/null | grep -oiE 'AES-256-(GCM|CBC)' | head -1)"
REMOTE
    }
    _ovpn_up A "$OVPN_A" "$OVPN_B" "$HOST_B"
    _ovpn_up B "$OVPN_B" "$OVPN_A" "$HOST_A"
}

# ── verify ──────────────────────────────────────────────────────────────────
verify() {
    log "verifying connectivity through each overlay (A -> B)"
    local ok=1
    for t in "yip:$YIP_B" "wireguard:$WG_B" "openvpn:$OVPN_B"; do
        local name="${t%%:*}" dst="${t##*:}" out
        out="$(Aq "ping -c 5 -i 0.3 -W 2 $dst | tail -2 | tr '\n' ' '")"
        if grep -q "0% packet loss" <<<"$out"; then
            log "  $name: UP  ($(grep -oE 'rtt[^ ]* = [0-9./]+ ms' <<<"$out" | head -1))"
        else
            warn "  $name: DOWN — $out"; ok=0
        fi
    done
    [[ $ok -eq 1 ]] || die "one or more tunnels failed connectivity"
    log "all tunnels up"
}

main() {
    build_and_ship_yipd
    install_packages
    tune_sysctls
    setup_yip
    setup_wireguard
    setup_openvpn
    verify
}
main "$@"
