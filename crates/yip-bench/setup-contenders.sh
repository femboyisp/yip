#!/usr/bin/env bash
# setup-contenders.sh — Turnkey helper to install or build optional benchmark contenders:
#   wireguard-go, AmneziaWG, ZeroTier, Tailscale (with Headscale coordinator), and NetBird.
#
# Usage:
#   sudo ./setup-contenders.sh --all
#   sudo ./setup-contenders.sh --wireguard-go
#   sudo ./setup-contenders.sh --amneziawg
#   sudo ./setup-contenders.sh --zerotier
#   sudo ./setup-contenders.sh --tailscale
#   sudo ./setup-contenders.sh --netbird
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
    command -v netbird >/dev/null 2>&1 && echo "INSTALLED ($(which netbird))" || echo "MISSING"
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
    if command -v apt-get >/dev/null 2>&1; then
        curl -s 'https://raw.githubusercontent.com/zerotier/ZeroTierOne/master/doc/contact%40zerotier.com.gpg' | gpg --dearmor -o /usr/share/keyrings/zerotierone-archive-keyring.gpg 2>/dev/null || true
        apt-get update && apt-get install -y zerotier-one || warn "apt-get install zerotier-one failed"
    elif command -v curl >/dev/null 2>&1; then
        curl -s https://install.zerotier.com | bash || warn "ZeroTier quick install script failed"
    else
        warn "Package manager or curl not found; please install zerotier-one manually."
    fi
}

setup_n2n() {
    log "Installing n2n (edge & supernode)..."
    if command -v edge >/dev/null 2>&1 && command -v supernode >/dev/null 2>&1; then
        log "n2n is already installed ($(which edge))"
        return
    fi
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y n2n || warn "apt-get install n2n failed"
    else
        warn "Package manager not found; please install n2n manually."
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
        local hs_url; hs_url="$(curl -s https://api.github.com/repos/juanfont/headscale/releases/latest | grep "browser_download_url.*linux_amd64\"" | head -1 | cut -d '"' -f 4 || true)"
        if [ -n "$hs_url" ]; then
            curl -fsSL -o "$TARGET_BIN_DIR/headscale" "$hs_url" 2>/dev/null && chmod 755 "$TARGET_BIN_DIR/headscale" || warn "headscale fetch failed"
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
    log "Setting up NetBird..."
    if command -v netbird >/dev/null 2>&1; then
        log "NetBird is already installed ($(which netbird))"
        return
    fi
    log "Fetching prebuilt netbird binary..."
    local nb_url; nb_url="$(curl -s https://api.github.com/repos/netbirdio/netbird/releases/latest | grep "browser_download_url.*netbird_.*linux_amd64.tar.gz\"" | head -1 | cut -d '"' -f 4 || true)"
    if [ -n "$nb_url" ]; then
        local nb_tmp; nb_tmp="$(mktemp -d /tmp/netbird.XXXXXX)"
        if curl -fsSL "$nb_url" 2>/dev/null | tar -xz -C "$nb_tmp" 2>/dev/null; then
            install -m 755 "$nb_tmp/netbird" "$TARGET_BIN_DIR/netbird" 2>/dev/null || true
        fi
        rm -rf "$nb_tmp"
    fi
    if ! command -v netbird >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
        log "Compiling netbird via Go toolchain..."
        GOBIN="$TARGET_BIN_DIR" go install github.com/netbirdio/netbird@latest || warn "netbird build failed"
    fi
    log "NetBird setup step complete."
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
        --check)
            check_status
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--all | --wireguard-go | --amneziawg | --n2n | --zerotier | --tailscale | --netbird | --check]"
            exit 1
            ;;
    esac
    shift
done

log "Selected contenders processed. Re-checking status:"
check_status
