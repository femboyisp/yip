# Migrating from WireGuard to yip

This guide provides a practical, step-by-step walkthrough for migrating existing Linux WireGuard tunnels (`wg0.conf`, `wg-quick`) to `yip` (`yipd.conf`).

---

## 1. Why Migrate from WireGuard to yip?

While WireGuard revolutionized VPN technology with its Noise IK handshake and minimal codebase, modern network reality imposes severe constraints on traditional tunnels:

1. **In-Flight Loss Immunity**: WireGuard treats all packet drops as congestion signals, throttling TCP goodput by 98%+ under minor 1%–5% loss. `yip` computes Cauchy Reed-Solomon forward error correction in-flight, sustaining line-rate multi-gigabit throughput (>1.88 Gbps at 5% loss on 2G links).
2. **Post-Quantum Forward Secrecy**: WireGuard's static Curve25519 keys are vulnerable to store-now-decrypt-later adversaries. `yip` implements NIST FIPS 203 ML-KEM-768/1024/512 hybrid handshakes out of the box.
3. **Censorship & DPI Resistance**: WireGuard headers and fixed handshakes are trivially fingerprinted and filtered by state firewalls. `yip` provides 4 anti-DPI armor modes, including authentic Chrome TLS 1.3 mimicry (`yip-utls`).
4. **Built-in NAT Traversal**: WireGuard requires static public IPs or manual port forwarding. `yip` features native STUN hole punching and blind relays.
5. **No Kernel Module Requirement**: `yip` runs in userspace with standard Linux sockets (`epoll` + GSO/GRO) reaching **21.56 Gbps**, eliminating the need for out-of-tree kernel modules or root eBPF loaders.

---

## 2. Configuration Translation Reference

The following table maps standard WireGuard configuration directives directly to their `yip` equivalents:

| WireGuard (`/etc/wireguard/wg0.conf`) | yip (`/etc/yip/yipd.conf`) | Description & Notes |
| :--- | :--- | :--- |
| `[Interface]` | Global Section (top-level) | Global daemon directives |
| `PrivateKey = <32-byte-base64>` | `local_private = <64-character-hex>` | Node secret key (converted to hex) |
| *(Derived Public Key)* | `local_public = <64-character-hex>` | Node public key (extracted from `yipd --genkey`) |
| `ListenPort = 51820` | `listen = 0.0.0.0:443` | `yip` defaults to port 443 to evade DPI port blocks |
| `Address = 10.0.0.1/24` | `device = yip0` + overlay | Interface name; overlay IP derived cryptographically |
| `MTU = 1420` | Automatic (1280–1420) | `yip` automatically negotiates optimal MTU |
| `[Peer]` | `[peer]` | Peer definition block |
| `PublicKey = <32-byte-base64>` | `public_key = <64-character-hex>` | Remote peer public identity (in hex) |
| `Endpoint = 198.51.100.2:51820` | `endpoint = 198.51.100.2:443` | Remote peer UDP endpoint |
| `AllowedIPs = 0.0.0.0/0, ::/0` | `route_mode = "ExitNode"` | Full-tunnel default gateway mode |
| `AllowedIPs = 10.0.0.2/32` | `route_mode = "MeshOnly"` | Default point-to-point overlay routing |
| `AllowedIPs = 192.168.1.0/24` | `route_mode = "SplitTunnel"` | Subnet routing with explicit CIDRs |
| `PersistentKeepalive = 25` | Handled automatically | `yip` sends adaptive heartbeats dynamically |
| *(None / Classical only)* | `kem = mlkem768` | NIST FIPS 203 hybrid post-quantum KEM (`mlkem768`, `mlkem1024`, `mlkem512`) |

---

## 3. Key Format Conversion

WireGuard encodes its 32-byte Curve25519 keys in base64. `yip` uses standard 64-character hexadecimal encoding.

### Convert WireGuard Base64 Key to yip Hex
To convert an existing 32-byte WireGuard key to hex:

```bash
# Convert base64 private or public key to hex
echo "<base64-key>" | base64 -d | xxd -p -c 32
```

### Generate Native yip Keypair
Alternatively, generate a fresh native `yip` keypair:

```bash
yipd --genkey > /etc/yip/node.key
chmod 600 /etc/yip/node.key

# View generated keys and self-certifying overlay IPv6 address
cat /etc/yip/node.key
yipd --addr $(grep '^public=' /etc/yip/node.key | cut -d= -f2)
```

---

## 4. Side-by-Side Configuration Examples

### Example 1: Point-to-Point VPS Interconnect

#### Before: WireGuard (`/etc/wireguard/wg0.conf` on Host A)
```ini
[Interface]
PrivateKey = YH5...=
Address = 10.10.0.1/24
ListenPort = 51820

[Peer]
PublicKey = 8fK...=
Endpoint = 203.0.113.2:51820
AllowedIPs = 10.10.0.2/32
PersistentKeepalive = 25
```

#### After: yip (`/etc/yip/yipd.conf` on Host A)
```ini
local_private = 2f2b5880cc15f29f826e876f5396c6f418e2366b73b415c5441f152b23c0334d
local_public  = 4cbc48cf095389d829abf3c7d78747ca35c96483375bd73860b2ebba94c99d50
kem           = mlkem768
listen        = 0.0.0.0:443
device        = yip0

[peer]
public_key    = 6ed3f82ba6450cd14ec52509deb42a87c6a8d2fa91a5a145f2ddcfdb0d675d12
endpoint      = 203.0.113.2:443
```

---

### Example 2: Client to Internet Gateway (Exit Node)

#### Before: WireGuard Full Tunnel (`wg-quick` on Client)
```ini
[Interface]
PrivateKey = cGF...=
Address = 10.200.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = XvN...=
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
```

#### After: yip Full Tunnel (`/etc/yip/yipd.conf` on Client)
```ini
local_private = dd152fc311a115549005da852d101a7d3a14594c728f71ff87aa0872da6c0fa9
local_public  = bf923deeaddb66dde39e99987abdfd789c54eb882a570c340cd338071727ceeb
kem           = mlkem768
listen        = 0.0.0.0:443
device        = yip0
route_mode    = "ExitNode"

[peer]
public_key    = 1f5b6b76d9723a79221777a7450522c32faa7300efd59b0a5efa42665cac0a0a
endpoint      = 198.51.100.1:443
```

---

## 5. Service & CLI Command Migration

| Operation | WireGuard | yip |
| :--- | :--- | :--- |
| **Start Service** | `sudo systemctl start wg-quick@wg0` | `sudo systemctl start yipd` |
| **Enable on Boot** | `sudo systemctl enable wg-quick@wg0` | `sudo systemctl enable yipd` |
| **Stop Service** | `sudo systemctl stop wg-quick@wg0` | `sudo systemctl stop yipd` |
| **Inspect Status** | `sudo wg show` | `yipctl status` |
| **Inspect Peer RTT** | `ping 10.10.0.2` | `yipctl ping <peer-pubkey>` |
| **Generate Keys** | `wg genkey \| tee private.key \| wg pubkey` | `yipd --genkey > node.key` |
| **Reload Config** | `wg syncconf wg0 <(wg-quick strip wg0)` | `sudo yipctl reload` |

---

## 6. Verifying the Migration

After starting `yipd`:

1. **Check Service Telemetry**:
   ```bash
   yipctl status
   ```
   Verify that the peer session state is `Established`, noting the negotiated RTT and active driver engine (`epoll` or `io_uring`).

2. **Verify Loss Resilience**:
   Test line-rate transfer using `iperf3`:
   ```bash
   # Server (Host B)
   iperf3 -s

   # Client (Host A)
   iperf3 -c <peer-overlay-ip> -t 10
   ```

3. **Validate In-Flight Parity Protection**:
   Inject artificial packet loss on the underlying transport using `tc-netem`:
   ```bash
   sudo tc qdisc add dev eth0 root netem loss 5%
   ```
   Re-run `iperf3`. While WireGuard drops to single-digit megabits, `yip` sustains near line-rate throughput without connection stalling.
