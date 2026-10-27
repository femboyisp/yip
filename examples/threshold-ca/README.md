# Decentralized Threshold CA Example & Quickstart

This directory contains reference configurations and an operational guide for deploying an online, distributed **Threshold Certificate Authority** (*t*-of-*n*) using RFC 9591 FROST (Flexible Round-Optimized Schnorr Threshold) signatures over Ed25519.

---

## Architecture Overview

Unlike the offline single-key CA model where an operator holds the master private key on an air-gapped machine, the decentralized threshold CA distributes signing shares across *n* independent signer daemons:

```text
               ┌────────────────────────────────────────────────────────┐
               │              Online Coordinator Gateway                │
               │               `yip-ca serve --role coordinator`        │
               │             (Listens on 0.0.0.0:4443 / WAN)            │
               └───────────▲───────────────────────────▲────────────────┘
                           │                           │
              mTLS / Noise │ Persistent                │ Persistent
              Stream       │ Nonce Stock               │ Nonce Stock
                           ▼                           ▼
            ┌────────────────────────────┐  ┌────────────────────────────┐
            │       Signer Daemon 1      │  │       Signer Daemon 2      │
            │ `yip-ca serve --role signer│  │ `yip-ca serve --role signer│
            │   (KeyPackage Share 1)     │  │   (KeyPackage Share 2)     │
            │  Policy Engine & Nonces    │  │  Policy Engine & Nonces    │
            └────────────────────────────┘  └────────────────────────────┘
                           ▲
                           │ Single-Round 1-RTT Enrollment / Renewal
                           │
             ┌─────────────┴────────────────────────────┐
             │            Enrolling Mesh Node           │
             │        `yip-ca enroll` or `yipd`         │
             │    (Background 70% TTL Auto-Renewal)     │
             └──────────────────────────────────────────┘
```

### Key Properties
- **Standard Ed25519 Certificates**: FROST signatures aggregate linearly into standard 64-byte Ed25519 signatures. Mesh nodes, root sets, and verifiers validate threshold-issued certificates identically to single-signer certificates with zero wire-format changes.
- **Single-Round (1-RTT) Online Enrollment**: Signers pre-generate nonce commitment pools (`frost_ed25519::round1::preprocess`) and register them with the coordinator, eliminating Round 1 commitment exchange at enrollment time.
- **Asynchronous Fault Tolerance (ROAST)**: Certificate issuance succeeds as long as any *t* of *n* signers respond, even if *n* - *t* signers are offline, high-latency, or malicious.
- **Rollback-Immune Nonce Vault**: Ephemeral nonces are memory-locked (`libc::mlock`), wiped immediately on single-use consumption (`take_once`), and bound to monotonic 128-bit CSPRNG boot epochs to defeat VM snapshot key-recovery attacks.
- **Automated Lifecycle**: Nodes running `yipd` automatically monitor certificate lifetime and renew in the background at ≥ 70% of TTL.

---

## 1. Key Generation (2-of-3 Quorum)

Generate a 2-of-3 threshold key set using `yip-ca dealer-gen`:

```bash
mkdir -p /etc/yip/ca-shares
yip-ca dealer-gen --threshold 2 --signers 3 --out-dir /etc/yip/ca-shares
```

This creates:
- `pubkey_package.json`: Contains the group verifying key (`threshold_ca_public`) and individual signer verification keys. Distribute this to the coordinator and all signers.
- `signer_1.json`, `signer_2.json`, `signer_3.json`: Private `KeyPackage` shares. **Distribute exactly one file to each respective signer host and keep them secret (`chmod 0600`)**.

Take note of the printed group public key, for example:
```text
threshold_ca_public=8a03a4cf43c2907041efb394c0effabad5bdb4cbbc35d17c924c0b6cbfa8ba75
generated 2-of-3 keys in /etc/yip/ca-shares
```

---

## 2. Launching the Coordinator

On the coordinator host (e.g. `198.51.100.10:4443`):

```bash
yip-ca serve \
  --role coordinator \
  --bind 0.0.0.0:4443 \
  --threshold 2 \
  --pubkey /etc/yip/ca-shares/pubkey_package.json
```

The coordinator will open a TCP socket, wait for signers to connect and register commitment pools, and serve incoming enrollment requests.

---

## 3. Launching Signer Daemons

On each signer host, connect outbound to the coordinator. Signers maintain a live pool of single-use nonces and independently evaluate local signing policies:

```bash
# On Signer Host 1:
yip-ca serve \
  --role signer \
  --coordinator 198.51.100.10:4443 \
  --key /etc/yip/ca-shares/signer_1.json \
  --pubkey /etc/yip/ca-shares/pubkey_package.json \
  --max-ttl 2592000

# On Signer Host 2:
yip-ca serve \
  --role signer \
  --coordinator 198.51.100.10:4443 \
  --key /etc/yip/ca-shares/signer_2.json \
  --pubkey /etc/yip/ca-shares/pubkey_package.json \
  --max-ttl 2592000

# On Signer Host 3:
yip-ca serve \
  --role signer \
  --coordinator 198.51.100.10:4443 \
  --key /etc/yip/ca-shares/signer_3.json \
  --pubkey /etc/yip/ca-shares/pubkey_package.json \
  --max-ttl 2592000
```

---

## 4. Client Enrollment

A new or existing node enrolls via `yip-ca enroll`:

```bash
# Generate node keys if not already created
yipd --genkey > /etc/yip/node.key
yip-ca genkey > /etc/yip/member-sign.key

NODE_PUB=$(grep '^public=' /etc/yip/node.key | cut -d= -f2)
SIGN_PUB=$(grep '^ca_public=' /etc/yip/member-sign.key | cut -d= -f2)

# Request a signed certificate from the threshold quorum
yip-ca enroll \
  --server 198.51.100.10:4443 \
  --member "$NODE_PUB" \
  --member-sign "$SIGN_PUB" \
  --network f11a8e0df8fa6352eeb62192de7ece47 \
  --out /etc/yip/node.cert
```

---

## 5. Configuring yipd for Zero-Touch Background Renewal

In `/etc/yip/yipd.conf`, specify `ca_public` and `threshold_ca_server`:

```ini
local_private=50b522bb0b57e7eb133e9b11b5275ea011cf8c3f4e24eb37452d192131b0e01c
local_public=9b49ffeb4566b53a0f78cae08920bc9e30a6e0c60f252cfdf4740e74f8c92b21
listen=0.0.0.0:443
device=yip0

# Mesh PKI Settings
ca_public=8a03a4cf43c2907041efb394c0effabad5bdb4cbbc35d17c924c0b6cbfa8ba75
cert=/etc/yip/node.cert
roots=/etc/yip/network.roots
member_sign_private=c22239d00522843313aa03a662e8f0cb6abb7889f8f103510ebb5dee0e924857
network_id=f11a8e0df8fa6352eeb62192de7ece47

# Online Threshold CA Coordinator
threshold_ca_server=198.51.100.10:4443
```

When `threshold_ca_server` is present:
- `yipd` periodically checks certificate validity.
- At ≥ 70% elapsed TTL, `yipd` initiates a non-blocking background renewal directly with the coordinator.
- Upon successful aggregation, the new certificate replaces the active certificate in memory and writes atomically to disk.

---

## 6. Runtime Inspection & Manual Rotation

You can inspect certificate status or trigger an immediate renewal through the UNIX domain control socket:

```bash
# Query active certificate lifetime and renewal threshold
sudo yipd cert status

# Output:
# Certificate Status:
#   Valid:             true
#   Remaining TTL:     604800s
#   Renewal Threshold: 423360s (70% TTL)
#   Threshold CA:      true (198.51.100.10:4443)

# Force an immediate threshold renewal
sudo yipd cert renew

# Output:
# Certificate renewal requested successfully
```
