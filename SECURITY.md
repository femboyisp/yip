# Security Policy

yip is a VPN — its whole job is security — but it is **pre-1.0 software with one maintainer
and no external audit**. Treat it accordingly. If you rely on it in a threat-model where
compromise is dangerous, read the honest accounting below first.

## Reporting a vulnerability

> [!CAUTION]
> Do not open a public issue for a security vulnerability.

Report privately via GitHub's [private vulnerability
reporting](https://github.com/femboyisp/yip/security/advisories/new), or email the maintainer
at the address in the repo profile. Include enough to reproduce (affected version/commit,
config, and a description or PoC). We'll acknowledge, work a fix, and credit you unless you'd
rather stay anonymous. There is no bounty program.

## Supported versions

| Version | Supported |
| :--- | :--- |
| 0.1.x | :white_check_mark: |
| < 0.1.0 | :x: |

Fixes land on `main` and are tagged for release.

## What yip protects

- **Confidentiality + integrity**: ChaCha20-Poly1305 AEAD over a Noise-IK session, per-direction keys, a sliding replay window, and ~120 s forward-secret rekeys.
- **Post-Quantum Security Margin**: Single-RTT hybrid key exchange pairing NIST FIPS 203 ML-KEM-512 (Kyber) with classical X25519 Diffie-Hellman to defeat Harvest-Now, Decrypt-Later (HNDL) attacks.
- **Decentralized Root Authority**: Optional RFC 9591 FROST(Ed25519, SHA-512) threshold CA with ROAST asynchronous coordination, preprocessed 1-RTT nonces, and memory-locked (`mlock`) rollback-immune nonce vaults to eliminate single-point-of-compromise root key theft.
- **Identity & Admission**: Mesh membership requires CA-signed certificates; handshake admission checks static keys; TAI64N monotonic timestamps prevent replay and endpoint-hijacking; endpoint roaming follows only authenticated packets; and rendezvous registration is cryptographically authenticated.
- **Traffic Analysis Defense (DAITA)**: Discrete packet-length bucketing, stochastic multi-packet cover traffic bursts during idle periods, and bounded egress micro-jitter delay queues prevent statistical flow analysis.
- **Content-DPI Resistance**: No fixed wire bytes or constant offsets; verified clean against a 4-engine DPI oracle panel (nDPI, tshark, Suricata, Zeek); an Xray-REALITY transport mimics real Chrome TLS 1.3 for hostile networks and splices unauthorized probers to authentic decoy servers.

## What yip does *not* protect — read this

- **Physical Peer IP Concealment**: yip is a peer-to-peer overlay network, not an anonymizing mix-net like Tor. Connected nodes authenticate directly and see each other's physical IP addresses.
- **No independent commercial audit**: The implementation uses audited cryptographic primitives (`ring`, `snow`, `frost-ed25519`), but the full protocol composition and daemon have not yet undergone an external third-party commercial audit.

If a documented limitation above matters to your threat model, that's a reason to plan accordingly — but a *new* way to break the stated guarantees is exactly what we want to hear about privately.
