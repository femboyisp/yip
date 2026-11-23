#!/usr/bin/env bash
# setup-contenders.sh — Turnkey helper to install or build optional benchmark contenders:
#   wireguard-go, AmneziaWG, ZeroTier, Tailscale (with Headscale coordinator), NetBird, and Nebula.
#
# Usage:
#   sudo ./setup-contenders.sh --all
#   sudo ./setup-contenders.sh --wireguard-go
#   sudo ./setup-contenders.sh --amneziawg
#   sudo ./setup-contenders.sh --zerotier
#   sudo ./setup-contenders.sh --tailscale
#   sudo ./setup-contenders.sh --netbird
#   sudo ./setup-contenders.sh --nebula
#   ./setup-contenders.sh --check
set -euo pipefail

TARGET_BIN_DIR="/usr/local/bin"

# Discover Go toolchain if not in PATH (e.g. running under bare sudo or CI)
if ! command -v go >/dev/null 2>&1; then
    for candidate in /usr/local/go/bin/go /usr/lib/go/bin/go /home/runner/go/bin/go /opt/hostedtoolcache/go/*/x64/bin/go; do
        if [ -x "$candidate" ]; then
            export PATH="$(dirname "$candidate"):$PATH"
            break
        fi
    done
fi

log() { echo -e "\033[1;34m[setup-contenders]\033[0m $*"; }
warn() { echo -e "\033[1;33m[setup-contenders:WARN]\033[0m $*"; }
err() { echo -e "\033[1;31m[setup-contenders:ERROR]\033[0m $*" >&2; exit 1; }

check_status() {
    log "Checking contender tool availability:"
    printf "  %-12s : " "WireGuard"
    command -v wg >/dev/null 2>&1 && echo "INSTALLED ($(which wg))" || echo "MISSING"
    printf "  %-12s : " "WireGuard-Go"
    command -v wireguard-go >/dev/null 2>&1 && echo "INSTALLED ($(which wireguard-go))" || echo "MISSING"
    printf "  %-12s : " "OpenVPN"
    command -v openvpn >/dev/null 2>&1 && echo "INSTALLED ($(which openvpn))" || echo "MISSING"
    printf "  %-12s : " "n2n"
    (command -v edge >/dev/null 2>&1 && command -v supernode >/dev/null 2>&1) && echo "INSTALLED ($(which edge))" || echo "MISSING"
    printf "  %-12s : " "AmneziaWG"
    (command -v awg >/dev/null 2>&1 && (command -v amneziawg-go >/dev/null 2>&1 || modprobe amneziawg 2>/dev/null)) && echo "INSTALLED ($(which awg))" || echo "MISSING"
    printf "  %-12s : " "ZeroTier"
    command -v zerotier-one >/dev/null 2>&1 && echo "INSTALLED ($(which zerotier-one))" || echo "MISSING"
    printf "  %-12s : " "Tailscale"
    (command -v tailscaled >/dev/null 2>&1 && command -v headscale >/dev/null 2>&1) && echo "INSTALLED" || echo "MISSING"
    printf "  %-12s : " "NetBird"
    (command -v netbird >/dev/null 2>&1 && command -v netbird-mgmt >/dev/null 2>&1 && command -v netbird-signal >/dev/null 2>&1) && echo "INSTALLED ($(which netbird))" || (command -v netbird >/dev/null 2>&1 && echo "CLIENT-ONLY ($(which netbird))" || echo "MISSING")
    printf "  %-12s : " "Nebula"
    (command -v nebula >/dev/null 2>&1 && command -v nebula-cert >/dev/null 2>&1) && echo "INSTALLED ($(which nebula))" || echo "MISSING"
}

setup_wireguard_go() {
    log "Building wireguard-go..."
    if ! command -v go >/dev/null 2>&1; then err "Go toolchain required to build wireguard-go"; fi
    GOBIN="$TARGET_BIN_DIR" go install golang.zx2c4.com/wireguard@latest || warn "wireguard-go compile failed"
    if [ -f "$TARGET_BIN_DIR/wireguard" ] && [ ! -f "$TARGET_BIN_DIR/wireguard-go" ]; then
        ln -sf "$TARGET_BIN_DIR/wireguard" "$TARGET_BIN_DIR/wireguard-go" 2>/dev/null || cp -f "$TARGET_BIN_DIR/wireguard" "$TARGET_BIN_DIR/wireguard-go" 2>/dev/null || true
    fi
    log "wireguard-go setup step complete."
}

setup_amneziawg() {
    log "Building AmneziaWG (amneziawg-go & awg-tools)..."
    if ! command -v go >/dev/null 2>&1; then err "Go toolchain required to build AmneziaWG"; fi
    local tmp; tmp="$(mktemp -d /tmp/build-awg.XXXXXX)"
    pushd "$tmp" >/dev/null
    log "Compiling amneziawg-go..."
    GOBIN="$TARGET_BIN_DIR" go install github.com/amnezia-vpn/amneziawg-go@latest || warn "amneziawg-go compile failed"
    log "Cloning and building awg CLI tool..."
    if command -v git >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
        git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools.git awg-tools 2>/dev/null || true
        if [ -d awg-tools/src ]; then
            make -C awg-tools/src
            install -m 755 awg-tools/src/wg "$TARGET_BIN_DIR/awg"
        fi
    else
        warn "git/make missing; cannot build awg CLI tool from source"
    fi
    popd >/dev/null
    rm -rf "$tmp"
    log "AmneziaWG setup step complete."
}

setup_zerotier() {
    log "Installing ZeroTier..."
    if command -v zerotier-one >/dev/null 2>&1; then
        log "ZeroTier is already installed ($(which zerotier-one))"
        return
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -s https://install.zerotier.com | bash 2>/dev/null || warn "ZeroTier quick install script failed"
    fi
    if ! command -v zerotier-one >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
        local release
        release="$(lsb_release -cs 2>/dev/null || echo 'noble')"
        curl -fsSL 'https://raw.githubusercontent.com/zerotier/ZeroTierOne/master/doc/contact%40zerotier.com.gpg' | gpg --dearmor -o /usr/share/keyrings/zerotierone-archive-keyring.gpg 2>/dev/null || true
        echo "deb [signed-by=/usr/share/keyrings/zerotierone-archive-keyring.gpg] http://download.zerotier.com/debian/$release $release main" > /etc/apt/sources.list.d/zerotier.list 2>/dev/null || true
        apt-get update && apt-get install -y zerotier-one || warn "apt-get install zerotier-one failed"
    fi
    if ! command -v zerotier-one >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 && command -v ar >/dev/null 2>&1; then
        log "Extracting prebuilt ZeroTier binary from debian pool..."
        local zt_tmp; zt_tmp="$(mktemp -d /tmp/zt_deb.XXXXXX)"
        local zt_deb="zerotier-one_1.16.2_amd64.deb"
        if curl -fsSL -o "$zt_tmp/$zt_deb" "http://download.zerotier.com/debian/noble/pool/main/z/zerotier-one/$zt_deb" 2>/dev/null; then
            (cd "$zt_tmp" && ar -x "$zt_deb" && tar -xf data.tar.* 2>/dev/null)
            if [ -x "$zt_tmp/usr/sbin/zerotier-one" ]; then
                install -m 755 "$zt_tmp/usr/sbin/zerotier-one" "$TARGET_BIN_DIR/zerotier-one" 2>/dev/null || true
                ln -sf "$TARGET_BIN_DIR/zerotier-one" "$TARGET_BIN_DIR/zerotier-cli" 2>/dev/null || true
                ln -sf "$TARGET_BIN_DIR/zerotier-one" "$TARGET_BIN_DIR/zerotier-idtool" 2>/dev/null || true
            fi
        fi
        rm -rf "$zt_tmp"
    fi
    log "ZeroTier setup step complete."
}

setup_n2n() {
    log "Installing n2n (edge & supernode version 3+)..."
    local need_install=true
    if command -v edge >/dev/null 2>&1 && command -v supernode >/dev/null 2>&1; then
        local ver
        ver="$(edge -h 2>&1 | grep -iE 'v\.[0-9]+|version [0-9]+' | head -1 || true)"
        if [[ "$ver" == *"v.3"* ]] || [[ "$ver" == *"v.4"* ]] || [[ "$ver" == *"version 3"* ]]; then
            log "n2n version 3+ is already installed ($ver at $(which edge))"
            need_install=false
        else
            warn "Found legacy n2n ($ver); upgrading to n2n version 3+..."
        fi
    fi
    if [ "$need_install" = true ]; then
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y n2n autoconf automake libtool build-essential libssl-dev || true
        fi
        local cur_ver=""
        if command -v edge >/dev/null 2>&1; then
            cur_ver="$(edge -h 2>&1 | grep -iE 'v\.[0-9]+|version [0-9]+' | head -1 || true)"
        fi
        if [[ "$cur_ver" != *"v.3"* ]] && [[ "$cur_ver" != *"v.4"* ]] && [[ "$cur_ver" != *"version 3"* ]]; then
            log "Building n2n v3 from release source..."
            local n2n_tmp; n2n_tmp="$(mktemp -d /tmp/build-n2n.XXXXXX)"
            if (curl -fsSL "https://github.com/ntop/n2n/archive/refs/tags/3.0.tar.gz" 2>/dev/null | tar -xz -C "$n2n_tmp" --strip-components=1 2>/dev/null) || \
               git clone --depth 1 https://github.com/ntop/n2n.git "$n2n_tmp" 2>/dev/null; then
                rm -rf "$n2n_tmp/.git"
                (cd "$n2n_tmp" && ./autogen.sh && ./configure && make -j"$(nproc 2>/dev/null || echo 2)" && install -m 755 edge "$TARGET_BIN_DIR/edge" && install -m 755 supernode "$TARGET_BIN_DIR/supernode") || warn "Building n2n from source failed"
            fi
            rm -rf "$n2n_tmp"
        fi
    fi
    log "n2n setup step complete."
}

setup_tailscale() {
    log "Setting up Tailscale & Headscale..."
    if ! command -v tailscaled >/dev/null 2>&1; then
        log "Fetching prebuilt tailscale & tailscaled..."
        local ts_tmp; ts_tmp="$(mktemp -d /tmp/tailscale.XXXXXX)"
        if curl -fsSL https://pkgs.tailscale.com/stable/tailscale_latest_amd64.tgz | tar -xz -C "$ts_tmp" 2>/dev/null; then
            install -m 755 "$ts_tmp"/tailscale_*/tailscale "$TARGET_BIN_DIR/tailscale" 2>/dev/null || true
            install -m 755 "$ts_tmp"/tailscale_*/tailscaled "$TARGET_BIN_DIR/tailscaled" 2>/dev/null || true
        fi
        rm -rf "$ts_tmp"
    fi
    if ! command -v headscale >/dev/null 2>&1; then
        log "Fetching prebuilt headscale coordinator..."
        local hs_tag hs_url
        hs_tag="$(curl -sIL https://github.com/juanfont/headscale/releases/latest | grep -i location | tr -d '\r' | awk -F'/' '{print $NF}' || true)"
        if [ -n "$hs_tag" ]; then
            hs_url="https://github.com/juanfont/headscale/releases/download/${hs_tag}/headscale_${hs_tag#v}_linux_amd64"
            curl -fsSL -o "$TARGET_BIN_DIR/headscale" "$hs_url" 2>/dev/null && chmod 755 "$TARGET_BIN_DIR/headscale" || warn "headscale direct fetch failed"
        fi
    fi
    if ! command -v tailscaled >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
        log "Compiling tailscale & tailscaled via Go toolchain..."
        GOBIN="$TARGET_BIN_DIR" go install tailscale.com/cmd/tailscale@latest || warn "tailscale build failed"
        GOBIN="$TARGET_BIN_DIR" go install tailscale.com/cmd/tailscaled@latest || warn "tailscaled build failed"
    fi
    if ! command -v headscale >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
        log "Compiling headscale via Go toolchain..."
        GOBIN="$TARGET_BIN_DIR" go install github.com/juanfont/headscale/cmd/headscale@latest || warn "headscale build failed"
    fi
    log "Tailscale / Headscale setup step complete."
}

setup_netbird() {
    log "Setting up NetBird (client, management, signal)..."
    if ! command -v netbird >/dev/null 2>&1; then
        log "Fetching prebuilt netbird client..."
        local nb_tag nb_ver nb_url
        nb_tag="$(curl -sIL https://github.com/netbirdio/netbird/releases/latest | grep -i location | tr -d '\r' | awk -F'/' '{print $NF}' || true)"
        if [ -n "$nb_tag" ]; then
            nb_ver="${nb_tag#v}"
            nb_url="https://github.com/netbirdio/netbird/releases/download/${nb_tag}/netbird_${nb_ver}_linux_amd64.tar.gz"
            local nb_tmp; nb_tmp="$(mktemp -d /tmp/netbird.XXXXXX)"
            if curl -fsSL "$nb_url" 2>/dev/null | tar -xz -C "$nb_tmp" 2>/dev/null; then
                install -m 755 "$nb_tmp/netbird" "$TARGET_BIN_DIR/netbird" 2>/dev/null || true
            fi
            rm -rf "$nb_tmp"
        fi
    fi
    if ! command -v netbird >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
        log "Attempting official NetBird install script..."
        curl -fsSL https://pkgs.netbird.io/install.sh 2>/dev/null | sh 2>/dev/null || warn "NetBird official install script failed"
    fi
    if ! command -v netbird >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
        log "Compiling netbird client via Go toolchain..."
        GOBIN="$TARGET_BIN_DIR" go install github.com/netbirdio/netbird/client@latest || warn "netbird build failed"
        if [ -f "$TARGET_BIN_DIR/client" ] && [ ! -f "$TARGET_BIN_DIR/netbird" ]; then
            ln -sf "$TARGET_BIN_DIR/client" "$TARGET_BIN_DIR/netbird" 2>/dev/null || cp -f "$TARGET_BIN_DIR/client" "$TARGET_BIN_DIR/netbird" 2>/dev/null || true
        fi
    fi

    # Management and signal daemons for isolated local benchmarking
    if (! command -v netbird-mgmt >/dev/null 2>&1 || ! command -v netbird-signal >/dev/null 2>&1) && command -v docker >/dev/null 2>&1; then
        log "Extracting netbird-mgmt and netbird-signal from official container images..."
        docker pull netbirdio/management:latest >/dev/null 2>&1 || true
        local cid_mgmt; cid_mgmt="$(docker create netbirdio/management:latest 2>/dev/null || true)"
        if [ -n "$cid_mgmt" ]; then
            docker cp "$cid_mgmt:/go/bin/netbird-mgmt" "$TARGET_BIN_DIR/netbird-mgmt" 2>/dev/null || true
            chmod 755 "$TARGET_BIN_DIR/netbird-mgmt" 2>/dev/null || true
            docker rm -f "$cid_mgmt" >/dev/null 2>&1 || true
        fi
        docker pull netbirdio/signal:latest >/dev/null 2>&1 || true
        local cid_sig; cid_sig="$(docker create netbirdio/signal:latest 2>/dev/null || true)"
        if [ -n "$cid_sig" ]; then
            docker cp "$cid_sig:/go/bin/netbird-signal" "$TARGET_BIN_DIR/netbird-signal" 2>/dev/null || true
            chmod 755 "$TARGET_BIN_DIR/netbird-signal" 2>/dev/null || true
            docker rm -f "$cid_sig" >/dev/null 2>&1 || true
        fi
    fi

    # Geolocation databases for management daemon in offline/isolated network namespaces
    local geo_dir="/usr/local/share/netbird-geo"
    mkdir -p "$geo_dir" 2>/dev/null || true
    if command -v netbird-mgmt >/dev/null 2>&1 && { [ ! -f "$geo_dir"/GeoLite2-City_*.mmdb ] || [ ! -f "$geo_dir"/geonames_*.db ]; }; then
        log "Initializing netbird-mgmt geolocation databases..."
        local tmp_geo; tmp_geo="$(mktemp -d /tmp/nb-geo.XXXXXX)"
        cat > "$tmp_geo/config.json" <<EOF
{
  "Signal": { "Proto": "http", "URI": "127.0.0.1:10000" },
  "EmbeddedIdP": { "Enabled": true, "Issuer": "http://127.0.0.1:18999" },
  "Datadir": "$geo_dir"
}
EOF
        netbird-mgmt management --config "$tmp_geo/config.json" --datadir "$geo_dir" --port 18999 --metrics-port 19098 >/dev/null 2>&1 &
        local pid_geo=$!
        for i in $(seq 1 40); do
            if ls "$geo_dir"/GeoLite2-City_*.mmdb >/dev/null 2>&1 && ls "$geo_dir"/geonames_*.db >/dev/null 2>&1; then
                break
            fi
            sleep 0.5
        done
        kill -9 $pid_geo 2>/dev/null || true
        wait $pid_geo 2>/dev/null || true
        rm -rf "$tmp_geo" "$geo_dir"/store.db "$geo_dir"/events.db "$geo_dir"/access_logs.db "$geo_dir"/idp 2>/dev/null || true
    fi
    log "NetBird setup step complete."
}

setup_nebula() {
    log "Setting up Nebula (nebula & nebula-cert)..."
    if ! command -v nebula >/dev/null 2>&1 || ! command -v nebula-cert >/dev/null 2>&1; then
        log "Fetching prebuilt nebula & nebula-cert..."
        local neb_tag neb_url neb_tmp neb_arch
        neb_tag="$(curl -sIL https://github.com/slackhq/nebula/releases/latest | grep -i location | tr -d '\r' | awk -F'/' '{print $NF}' || true)"
        if [ -n "$neb_tag" ]; then
            neb_arch="amd64"
            [ "$(uname -m)" = "aarch64" ] && neb_arch="arm64"
            neb_url="https://github.com/slackhq/nebula/releases/download/${neb_tag}/nebula-linux-${neb_arch}.tar.gz"
            neb_tmp="$(mktemp -d /tmp/nebula.XXXXXX)"
            if curl -fsSL "$neb_url" 2>/dev/null | tar -xz -C "$neb_tmp" 2>/dev/null; then
                install -m 755 "$neb_tmp/nebula" "$TARGET_BIN_DIR/nebula" 2>/dev/null || true
                install -m 755 "$neb_tmp/nebula-cert" "$TARGET_BIN_DIR/nebula-cert" 2>/dev/null || true
            fi
            rm -rf "$neb_tmp"
        fi
    fi
    if (! command -v nebula >/dev/null 2>&1 || ! command -v nebula-cert >/dev/null 2>&1) && command -v go >/dev/null 2>&1; then
        log "Compiling nebula & nebula-cert via Go toolchain..."
        GOBIN="$TARGET_BIN_DIR" go install github.com/slackhq/nebula/cmd/nebula@latest || warn "nebula build failed"
        GOBIN="$TARGET_BIN_DIR" go install github.com/slackhq/nebula/cmd/nebula-cert@latest || warn "nebula-cert build failed"
    fi
    log "Nebula setup step complete."
}

# ── Entrypoint ────────────────────────────────────────────────────────────────
if [ $# -eq 0 ] || [ "${1:-}" = "--check" ]; then
    check_status
    exit 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --all)
            setup_wireguard_go
            setup_amneziawg
            setup_n2n
            setup_zerotier
            setup_tailscale
            setup_netbird
            setup_nebula
            ;;
        --wireguard-go)
            setup_wireguard_go
            ;;
        --amneziawg)
            setup_amneziawg
            ;;
        --n2n)
            setup_n2n
            ;;
        --zerotier)
            setup_zerotier
            ;;
        --tailscale)
            setup_tailscale
            ;;
        --netbird)
            setup_netbird
            ;;
        --nebula)
            setup_nebula
            ;;
        --check)
            check_status
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--all | --wireguard-go | --amneziawg | --n2n | --zerotier | --tailscale | --netbird | --nebula | --check]"
            exit 1
            ;;
    esac
    shift
done

log "Selected contenders processed. Re-checking status:"
check_status
