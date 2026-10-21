#!/usr/bin/env bash
# setup-contenders.sh — Turnkey helper to install or build optional benchmark contenders:
#   AmneziaWG, ZeroTier, Tailscale (with Headscale coordinator), and NetBird.
#
# Usage:
#   sudo ./setup-contenders.sh --all
#   sudo ./setup-contenders.sh --amneziawg
#   sudo ./setup-contenders.sh --zerotier
#   sudo ./setup-contenders.sh --tailscale
#   sudo ./setup-contenders.sh --netbird
#   ./setup-contenders.sh --check
set -euo pipefail

TARGET_BIN_DIR="/usr/local/bin"

log() { echo -e "\033[1;34m[setup-contenders]\033[0m $*"; }
warn() { echo -e "\033[1;33m[setup-contenders:WARN]\033[0m $*"; }
err() { echo -e "\033[1;31m[setup-contenders:ERROR]\033[0m $*" >&2; exit 1; }

check_status() {
    log "Checking contender tool availability:"
    printf "  %-12s : " "WireGuard"
    command -v wg >/dev/null 2>&1 && echo "INSTALLED ($(which wg))" || echo "MISSING"
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

setup_tailscale() {
    log "Setting up Tailscale & Headscale..."
    if ! command -v go >/dev/null 2>&1; then err "Go toolchain required to build Tailscale & Headscale"; fi
    log "Compiling tailscale & tailscaled..."
    GOBIN="$TARGET_BIN_DIR" go install tailscale.com/cmd/tailscale@latest || warn "tailscale build failed"
    GOBIN="$TARGET_BIN_DIR" go install tailscale.com/cmd/tailscaled@latest || warn "tailscaled build failed"
    log "Compiling headscale (local air-gapped coordinator)..."
    GOBIN="$TARGET_BIN_DIR" go install github.com/juanfont/headscale/cmd/headscale@latest || warn "headscale build failed"
    log "Tailscale / Headscale setup step complete."
}

setup_netbird() {
    log "Setting up NetBird..."
    if ! command -v go >/dev/null 2>&1; then err "Go toolchain required to build NetBird"; fi
    log "Compiling netbird..."
    GOBIN="$TARGET_BIN_DIR" go install github.com/netbirdio/netbird@latest || warn "netbird build failed"
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
            setup_amneziawg
            setup_zerotier
            setup_tailscale
            setup_netbird
            ;;
        --amneziawg)
            setup_amneziawg
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
            echo "Usage: $0 [--all | --amneziawg | --zerotier | --tailscale | --netbird | --check]"
            exit 1
            ;;
    esac
    shift
done

log "Selected contenders processed. Re-checking status:"
check_status
