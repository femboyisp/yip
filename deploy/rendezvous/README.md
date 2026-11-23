# Public Rendezvous Deployment Guide

This guide documents the production deployment of the public `yip-rendezvous` daemon on `rendezvous.yipmesh.tech:443` (addressing Issue #264).

## 1. Network & DNS Requirements

1. **DNS Records:**
   - `A` record: `rendezvous.yipmesh.tech` pointing to the public IPv4 address of the rendezvous host.
   - `AAAA` record: `rendezvous.yipmesh.tech` pointing to the public IPv6 address of the rendezvous host.
2. **Firewall Ingress Rules:**
   - **UDP port 443**: Primary rendezvous discovery, NAT traversal (STUN-like reflexive address discovery), hole-punching coordination, and blind relay path.
   - **TCP port 443**: Fallback TLS Trojan transport front for networks where UDP is strictly throttled or dropped.

## 2. Automated Service Installation

Run the setup script with administrative privileges:

```bash
sudo bash deploy/rendezvous/setup-rendezvous.sh
```

The script:
1. Provisions the unprivileged system user `yip-rendezvous`.
2. Compiles `bin/yip-rendezvous` with release optimizations (`--release`).
3. Installs the executable into `/usr/local/bin/yip-rendezvous`.
4. Grants `CAP_NET_BIND_SERVICE` so the service binds low-numbered port `443` without root permissions.
5. Installs and starts the hardened systemd unit file at `/etc/systemd/system/yip-rendezvous.service`.
6. Configures `ufw` firewall rules allowing ports `443/udp` and `443/tcp`.

## 3. Systemd Service Management

Check service status:
```bash
sudo systemctl status yip-rendezvous
```

View live service logs:
```bash
sudo journalctl -u yip-rendezvous -f
```

Restart service:
```bash
sudo systemctl restart yip-rendezvous
```

## 4. Health Verification

Run the verification probe against the local host or remote domain:

```bash
bash deploy/rendezvous/verify-rendezvous.sh 127.0.0.1 443
bash deploy/rendezvous/verify-rendezvous.sh rendezvous.yipmesh.tech 443
```
