#!/usr/bin/env bash
# Production deployment setup script for yip-rendezvous on rendezvous.yipmesh.tech:443
# Strictly zero emojis
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "[deploy] preparing yip-rendezvous system service"

# 1. System user and group creation
if ! id -u yip-rendezvous >/dev/null 2>&1; then
    echo "[deploy] creating system user and group yip-rendezvous"
    $SUDO useradd -r -U -s /usr/sbin/nologin -d /var/empty yip-rendezvous 2>/dev/null || \
    $SUDO useradd -r -U -s /bin/false -d /var/empty yip-rendezvous
fi

# 2. Build binary if missing from target/release
if [ ! -f "$WORKSPACE_ROOT/target/release/yip-rendezvous" ]; then
    echo "[deploy] building yip-rendezvous in release mode"
    cargo build --release -p yip-rendezvous-bin --manifest-path "$WORKSPACE_ROOT/Cargo.toml"
fi

# 3. Install binary
echo "[deploy] installing /usr/local/bin/yip-rendezvous"
$SUDO install -m 755 "$WORKSPACE_ROOT/target/release/yip-rendezvous" /usr/local/bin/yip-rendezvous

# Grant CAP_NET_BIND_SERVICE to binary for privileged port 443 binding without root
if command -v setcap >/dev/null 2>&1; then
    echo "[deploy] setting cap_net_bind_service on /usr/local/bin/yip-rendezvous"
    $SUDO setcap 'cap_net_bind_service=+ep' /usr/local/bin/yip-rendezvous || true
fi

# 4. Install systemd unit
echo "[deploy] installing /etc/systemd/system/yip-rendezvous.service"
$SUDO cp "$SCRIPT_DIR/yip-rendezvous.service" /etc/systemd/system/yip-rendezvous.service

# 5. Open firewall ports (UDP 443)
if command -v ufw >/dev/null 2>&1 && $SUDO ufw status | grep -q "Status: active"; then
    echo "[deploy] configuring ufw firewall rules for port 443"
    $SUDO ufw allow 443/udp comment 'yip-rendezvous UDP' || true
fi

# 6. Enable and start service
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    echo "[deploy] reloading systemd daemon and enabling yip-rendezvous"
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable --now yip-rendezvous
    $SUDO systemctl status yip-rendezvous --no-pager || true
fi

echo "[deploy] yip-rendezvous deployment setup complete"
