# yip

[![Crates.io](https://img.shields.io/crates/v/yip.svg)](https://crates.io/crates/yip)
[![Documentation](https://docs.rs/yip/badge.svg)](https://docs.rs/yip)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.html)

The unified Rust library and SDK for the **yip** high-performance overlay network protocol.

## Features

The `yip` crate provides modular facade access to all underlying protocol components:

- **`crypto`** (default): AEAD ciphers (ChaCha20-Poly1305, AES-256-GCM, AES-128-GCM), Noise-IK handshakes, BLAKE2s hashing, and key derivations.
- **`wire`** (default): Zero-allocation framing, wire codec parsing, header obfuscation, and control frame encoding.
- **`transport`** (default): Slotted Reed-Solomon Forward Error Correction (FEC), sliding window packet reassembly, and selective ARQ.
- **`membership`** (default): Cryptographic node identity, self-certifying IPv6 mesh addresses, certificate verification, root sets, and anti-entropy gossip.
- **`device`**: TUN/TAP virtual network device abstractions across Linux.
- **`io`**: High-throughput I/O engines supporting Linux `epoll` and `io_uring` with ring buffer pools.
- **`rendezvous`**: STUN/TURN-independent symmetric NAT traversal with authenticated ticket exchange.
- **`obf`**: Steganographic wire framing, padding transforms, and timing-jitter obfuscation.
- **`utls`**: TLS 1.3 browser mimicry and REALITY camouflage transport.
- **`ca`**: RFC 9591 FROST threshold certificate authority signer and coordinator protocols.
- **`full`**: Enables all modules above.

## Quickstart

Add `yip` to your `Cargo.toml`:

```toml
[dependencies]
yip = { version = "0.1", features = ["full"] }
```

### Self-Certifying Mesh Address Generation

```rust
use yip::membership::cert::Cert;
use yip::membership::addr::MeshAddr;
```
