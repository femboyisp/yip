# Point-to-Point Tunnel with Post-Quantum Hybrid Cryptography

This example demonstrates deploying a direct, point-to-point overlay tunnel between two Linux hosts using `yipd` with NIST FIPS 203 post-quantum hybrid key exchange.

---

## 1. Architecture Overview

```text
+-----------------------------------+              +-----------------------------------+
|              HOST A               |              |              HOST B               |
| Public IP:  198.51.100.1          |              | Public IP:  203.0.113.2           |
| Overlay IP: fc00::1/64            | <==========> | Overlay IP: fc00::2/64            |
| Tunnel Dev: yip0 (L3 TUN)         |   Encrypted  | Tunnel Dev: yip0 (L3 TUN)         |
| Listen:     0.0.0.0:443 (UDP)     |    PQNoise   | Listen:     0.0.0.0:443 (UDP)     |
| KEM:        ML-KEM-768 (Level 3)  |   Handshake  | KEM:        ML-KEM-768 (Level 3)  |
+-----------------------------------+              +-----------------------------------+
```

- **Protocol**: PQNoise-IKpsk2 (`PQNoise_IKpsk2_25519_MLKEM768_ChaChaPoly_BLAKE3`).
- **Post-Quantum KEM**: NIST FIPS 203 ML-KEM-768 (Level 3 security margin, immune to Harvest-Now-Decrypt-Later quantum adversaries).
- **Symmetric Cipher**: ChaCha20-Poly1305 AEAD with BLAKE3 keyed ratchets.
- **Port**: UDP 443 (avoids standard VPN port fingerprinting).

---

## 2. Configuration Files

- [`yipd-host-a.conf`](yipd-host-a.conf): Configuration for Host A (`198.51.100.1`).
- [`yipd-host-b.conf`](yipd-host-b.conf): Configuration for Host B (`203.0.113.2`).

### Post-Quantum KEM Parameter Sets

`yipd` supports three NIST FIPS 203 parameter sets via the `kem` directive:

| Parameter Value | Security Category | Encapsulation Key (Bytes) | Ciphertext (Bytes) | Recommended Use |
| :--- | :--- | :--- | :--- | :--- |
| `mlkem768` | NIST Level 3 | 1,184 | 1,088 | Standard default; balanced high security and efficiency |
| `mlkem1024` | NIST Level 5 | 1,568 | 1,568 | Ultra-paranoid / top-secret quantum security margin |
| `mlkem512` | NIST Level 1 | 800 | 768 | Lightweight; restricted MTU / low-bandwidth links |

---

## 3. Quickstart Deployment

### Step 1: Install Configuration

On Host A:
```sh
sudo mkdir -p /etc/yip
sudo cp yipd-host-a.conf /etc/yip/yipd.conf
sudo chmod 0600 /etc/yip/yipd.conf
```

On Host B:
```sh
sudo mkdir -p /etc/yip
sudo cp yipd-host-b.conf /etc/yip/yipd.conf
sudo chmod 0600 /etc/yip/yipd.conf
```

### Step 2: Start the Daemons

```sh
# On both hosts
sudo systemctl restart yipd
```

### Step 3: Configure Overlay IP Addresses

On Host A:
```sh
sudo ip link set yip0 up
sudo ip -6 addr add fc00::1/64 dev yip0
```

On Host B:
```sh
sudo ip link set yip0 up
sudo ip -6 addr add fc00::2/64 dev yip0
```

### Step 4: Verify Connectivity & Crypto Status

Ping across the encrypted overlay:
```sh
ping -c 4 fc00::2
```

Inspect the active post-quantum cryptographic session and link health:
```sh
yipctl status
yipctl peers
```
