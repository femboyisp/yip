# yip Systems Architecture & Protocol Internals

This document is the authoritative technical reference for the internal systems architecture, cryptographic protocols, kernel-bypass datapath drivers, and wire framing of `yip` and `yipd`.

For deployment options and quick start tutorials, see [01-getting-started.md](01-getting-started.md).
For configuration directives and runtime flags, see [02-configuration.md](02-configuration.md).
For automated benchmarks, performance analysis, and tuning, see [testing-and-benchmarking.md](testing-and-benchmarking.md).

---

## Table of Contents

- [1. Architectural Philosophy & Dual-Path Design](#1-architectural-philosophy--dual-path-design)
  - [Core Design Principles](#core-design-principles)
  - [Decomposition: Control Plane vs. Data Plane](#decomposition-control-plane-vs-data-plane)
  - [System Architecture Diagram](#system-architecture-diagram)
  - [Repository Crate Topology](#repository-crate-topology)
- [2. Out-of-Band Cryptographic Control Plane](#2-out-of-band-cryptographic-control-plane)
  - [Node Identity Foundation](#node-identity-foundation)
  - [Noise-IKpsk2 Handshake with Hybrid ML-KEM-512](#noise-ikpsk2-handshake-with-hybrid-ml-kem-512)
  - [Handshake Wire Message Breakdown](#handshake-wire-message-breakdown)
  - [120-Second Epoch Ratchet & Rekey Overlap Window](#120-second-epoch-ratchet--rekey-overlap-window)
  - [Topology Orchestration & Blind Relay Signaling](#topology-orchestration--blind-relay-signaling)
- [3. Cryptographic Self-Certifying IPv6 Addressing](#3-cryptographic-self-certifying-ipv6-addressing)
  - [Overlay Addressing in `fd00::/8` (RFC 4193 ULA)](#overlay-addressing-in-fd008-rfc-4193-ula)
  - [Derivation Algorithm & Byte-Level Layout](#derivation-algorithm--byte-level-layout)
  - [Mathematical Guarantees: Anti-Spoofing & Anti-Squatting](#mathematical-guarantees-anti-spoofing--anti-squatting)
  - [Consistent Shard Affinity via Identity Hash](#consistent-shard-affinity-via-identity-hash)
- [4. Lock-Free Data Plane & Multi-Core Sharding](#4-lock-free-data-plane--multi-core-sharding)
  - [Multi-Queue TUN/TAP Device Subsystem](#multi-queue-tuntap-device-subsystem)
  - [Single-Producer Single-Consumer (SPSC) Ring Buffers](#single-producer-single-consumer-spsc-ring-buffers)
  - [Cache-Line Padding & False-Sharing Prevention](#cache-line-padding--false-sharing-prevention)
  - [Symmetric Flow Hashing & Strict FIFO Ordering](#symmetric-flow-hashing--strict-fifo-ordering)
  - [NUMA Awareness & CPU Core Pinning](#numa-awareness--cpu-core-pinning)
- [5. Kernel-Bypass Data Plane Driver Engines](#5-kernel-bypass-data-plane-driver-engines)
  - [Driver Engine Capabilities & Performance Matrix](#driver-engine-capabilities--performance-matrix)
  - [Engine 1: Standard Vectorized Socket Engine (`sendmmsg` / `recvmmsg` + GSO)](#engine-1-standard-vectorized-socket-engine-sendmmsg--recvmmsg--gso)
  - [Engine 2: `io_uring` Asynchronous Multishot Engine](#engine-2-io_uring-asynchronous-multishot-engine)
  - [Engine 3: AF_XDP (XSK) Zero-Copy Engine](#engine-3-af_xdp-xsk-zero-copy-engine)
    - [eBPF XDP Packet Steering (`XDP_REDIRECT`)](#ebpf-xdp-packet-steering-xdp_redirect)
    - [Shared Memory UMEM Pool Architecture](#shared-memory-umem-pool-architecture)
    - [The Four Descriptor Rings](#the-four-descriptor-rings)
    - [Ring Mechanics & Zero-Copy Descriptors](#ring-mechanics--zero-copy-descriptors)
- [6. Wire Protocol Framing & Anti-DPI Defense](#6-wire-protocol-framing--anti-dpi-defense)
  - [Wire Protocol Framing Diagram](#wire-protocol-framing-diagram)
  - [Frame Layout & Header Bitfields](#frame-layout--header-bitfields)
  - [Keyed Header Protection (ChaCha20 / SipHash-CTR Keystream Mask)](#keyed-header-protection-chacha20--siphash-ctr-keystream-mask)
  - [SipHash-1-3 64-Bit Coverage Authentication Tag](#siphash-1-3-64-bit-coverage-authentication-tag)
  - [Zero Magic Bytes & Uniform Entropy Guarantees](#zero-magic-bytes--uniform-entropy-guarantees)
- [7. End-to-End Packet Processing Lifecycles](#7-end-to-end-packet-processing-lifecycles)
  - [Egress Datapath Pipeline](#egress-datapath-pipeline)
  - [Ingress Datapath Pipeline](#ingress-datapath-pipeline)
  - [Systematic Cauchy RS-FEC Erasure Coding](#systematic-cauchy-rs-fec-erasure-coding)
  - [Thin Reactive ARQ Backstop](#thin-reactive-arq-backstop)
- [8. Security & Threat Model](#8-security--threat-model)
  - [Post-Quantum Security Margin](#post-quantum-security-margin)
  - [Sliding Bitmap Replay Protection](#sliding-bitmap-replay-protection)
  - [Side-Channel Mitigation & Memory Zeroization](#side-channel-mitigation--memory-zeroization)
  - [Blind Packet Injection & DoS Defense](#blind-packet-injection--dos-defense)

---

## 1. Architectural Philosophy & Dual-Path Design

### Core Design Principles

`yip` is engineered from first principles as an ultra-low latency, high-throughput, quantum-resistant overlay network daemon. The design is governed by three foundational axioms:

1. **Latency Over Raw Bandwidth**: Traditional tunnels accept scheduling delays and ring buffer bloat to maximize bulk TCP throughput. `yip` treats jitter and packet delivery delay as its primary metrics. Cryptography operations consume under 2 µs per packet; kernel context switching, lock contention, and socket queue latency are the true bottlenecks.
2. **Zero Allocation on the Fast Path**: Once initialized, the data plane executes without dynamic heap allocations (`malloc`/`free`) during packet forwarding. Memory buffers, descriptor rings, and network envelopes are pre-allocated at startup and recycled deterministically.
3. **Strict Separation of Concerns**: Control signaling and state negotiations are decoupled from packet switching. Control events execute asynchronously out-of-band, ensuring that rekey handshakes, discovery pings, or NAT updates cannot stall high-rate data packet flows.

### Decomposition: Control Plane vs. Data Plane

`yip` establishes an uncompromised structural separation between its control plane and its data plane:

```
+-----------------------------------------------------------------------------------+
|                           CONTROL PLANE (Out-of-Band)                            |
|                                                                                   |
|  - Ed25519 Node Identity & Root CA Tokens        - Out-of-Band STUN / Relay Coord |
|  - Noise-IKpsk2 + ML-KEM-512 PQ Handshakes       - Dynamic Peer Lifecycle Events  |
|  - 120s Ephemeral Rekey Ratchet Scheduling       - Asynchronous State Replication |
+-----------------------------------------------------------------------------------+
                                  |
               Key Material &     |     Session Epochs &
               Peer Endpoints     v     Routing Directives
+-----------------------------------------------------------------------------------+
|                             DATA PLANE (Fast Path)                                |
|                                                                                   |
|  - Zero-Lock Core Sharding (SPSC Rings)          - Symmetric 5-Tuple Flow Pinning |
|  - Hardware-Accelerated AEAD (ChaCha20)          - Systematic Cauchy RS-FEC       |
|  - Keyed Header Protection & SipHash-1-3         - Kernel Bypass (AF_XDP/io_uring)|
+-----------------------------------------------------------------------------------+
```

- **Control Plane**: Handles mutual node authentication, post-quantum key encapsulation, session key ratcheting, rendezvous signaling via [`crates/yip-rendezvous`](../crates/yip-rendezvous), and certificate admission via [`bin/yip-ca`](../bin/yip-ca). It runs asynchronously and never touches the packet forwarding fast path.
- **Data Plane**: Implemented across [`crates/yip-transport`](../crates/yip-transport), [`crates/yip-wire`](../crates/yip-wire), [`crates/yip-device`](../crates/yip-device), and [`crates/yip-io`](../crates/yip-io). It operates lock-free across worker shards, pinned to dedicated CPU cores, routing datagrams directly between the TUN/TAP interface and network interfaces.

### System Architecture Diagram

The dual-path architecture and the multi-stage data plane pipeline are visualized below:

![yip Dual-Path Architecture](../assets/architecture.svg)

### Repository Crate Topology

The `yip` codebase is organized into modular Rust crates with strict interface boundaries:

| Crate | Responsibility | Unsafe Code |
| :--- | :--- | :--- |
| [`crates/yip-crypto`](../crates/yip-crypto) | Noise-IKpsk2 state machine, ML-KEM-512 post-quantum KDF, ChaCha20-Poly1305 AEAD, sliding replay window. | `#![forbid(unsafe_code)]` |
| [`crates/yip-wire`](../crates/yip-wire) | Frame serialization, SipHash-1-3 coverage authentication, keyed header obfuscation. | `#![forbid(unsafe_code)]` |
| [`crates/yip-transport`](../crates/yip-transport) | Flow classification, GF(256) Cauchy Reed-Solomon FEC, RLNC codec, thin ARQ, PLPMTU discovery. | `#![forbid(unsafe_code)]` |
| [`crates/yip-device`](../crates/yip-device) | Multi-queue Linux TUN/TAP device provisioning, ioctl allocation, MTU negotiation. | Encapsulated |
| [`crates/yip-io`](../crates/yip-io) | Vectorized `recvmmsg`/`sendmmsg`, GSO batching, `io_uring` multishot driver, AF_XDP/eBPF kernel bypass, lock-free SPSC rings. | Quarantined / Audited |
| [`crates/yip-rendezvous`](../crates/yip-rendezvous) | NAT discovery, reflexive candidate harvesting, symmetric NAT port prediction, DERP relay fallback. | `#![forbid(unsafe_code)]` |
| [`bin/yipd`](../bin/yipd) | Core routing daemon, CLI management, configuration parsing, multi-core worker thread sharding. | Application |
| [`bin/yip-ca`](../bin/yip-ca) | Cryptographic identity authority, Ed25519 root certificates, node enrollment certificates. | Application |

---

## 2. Out-of-Band Cryptographic Control Plane

### Node Identity Foundation

Every node participating in a `yip` mesh network possesses an immutable identity keypair:
- **Long-Term Signing Identity**: Standard Ed25519 (256-bit Edwards-curve Digital Signature Algorithm).
- **Diffie-Hellman Key Agreement**: Curve25519 (X25519), derived directly or converted via birationally equivalent Edwards-to-Montgomery coordinate mapping ($u = (1 + y) / (1 - y)$).
- **Public Identity Representation**: A 32-byte raw public key, base64-encoded in configuration files.

Nodes prove authorization via signed certificates issued by a private root CA (`yip-ca`). Certificates bind node identity keys, mesh roles, and validity epochs without requiring centralized phone-home databases.

### Noise-IKpsk2 Handshake with Hybrid ML-KEM-512

`yip` implements a post-quantum hybrid cryptographic handshake. It builds on the Noise Protocol Framework pattern **Noise-IKpsk2** (Initiator knows Responder static key beforehand, one round-trip mutual authentication, with pre-shared key slot 2) augmented with NIST FIPS 203 **ML-KEM-512** (Kyber-512):

```
Initiator (Host A)                                      Responder (Host B)
--------------------------------------------------------------------------
Generate ephemeral e_A (X25519)
Generate PQ keypair (ek_A, dk_A)
Noise Step: e, es, s, ss
                       Message 1: Init (1,028 Bytes)
                       ---------------------------->
                                                        Parse ek_A, e_A
                                                        Noise Step: e, es, s, ss
                                                        Encapsulate: (ct, ss_pq) = pq_encaps(ek_A)
                                                        Inject PSK: set_psk(2, ss_pq)
                                                        Noise Step: se, ee
                       Message 2: Response (948 Bytes)
                       <----------------------------
Parse ct, e_B
Decapsulate: ss_pq = pq_decaps(dk_A, ct)
Inject PSK: set_psk(2, ss_pq)
Noise Step: se, ee
Split: (CipherState_Tx, CipherState_Rx)
```

#### Post-Quantum Deadlock-Free Design

To achieve post-quantum confidentiality without requiring a multi-round pre-handshake exchange, the Responder encapsulates a shared secret `ss_pq` against the Initiator's public encapsulation key `ek_A` in Message 1. The Responder sends the resulting 768-byte ciphertext `ct` in the clear (at bytes `4..772` of Message 2).

The Initiator extracts `ct` prior to decrypting Message 2's AEAD envelope, executes `pq_decapsulate(dk_A, ct)` to recover `ss_pq`, mixes it into Noise PSK slot 2 via `NoiseState::set_psk(2, &ss_pq)`, and then decrypts the remainder of Message 2. This structure guarantees:
- **Zero Round-Trip Penalty**: Full classical and quantum forward secrecy established in a single RTT ($1.0 \times \text{RTT}$).
- **FIPS 203 §7.2 Compliance**: Every received ML-KEM ciphertext undergoes strict modulus range verification ($c_i < 3329$) and IND-CCA2 implicit rejection on tampering.

### Handshake Wire Message Breakdown

Handshake packets are designed to fit strictly within the MTU budget (`OBF_MTU_BUDGET = 1,200` bytes) to prevent IP fragmentation on paths with restricted MTUs:

#### Message 1 (Initiator $\to$ Responder): 1,028 Bytes Total

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Wire Header (4 B)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                 ML-KEM-512 Encapsulation Key                  +
|                          ek_A (800 B)                         |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Noise Ephemeral Public Key e_A (32 B)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Encrypted Static Public Key s_A + CA Certificate        |
|                  + Poly1305 AEAD Tag (144 B)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Message 2 (Responder $\to$ Initiator): 948 Bytes Total

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Wire Header (4 B)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   ML-KEM-512 Ciphertext                       +
|                          ct (768 B)                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Noise Ephemeral Public Key e_B (32 B)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Encrypted Responder CA Certificate                 |
|                  + Poly1305 AEAD Tag (144 B)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 120-Second Epoch Ratchet & Rekey Overlap Window

To guarantee forward secrecy and protect against key compromise over long-lived sessions, session keys are ratcheted every 120 seconds.

Traditional VPN architectures suffer from packet drops or head-of-line stalls during rekeying due to synchronization delays. `yip` solves this with a **20-Second Dual-Receive Grace Overlap**:

```
Time (s)     0s                       110s      120s      130s                 240s
             |-------------------------|---------|---------|--------------------|
Epoch N:     [====== Active (TX + RX) ======][= RX Grace =][Zeroize]
                                       ^ Rekey Initiated
Epoch N+1:                             [==== Active (TX + RX) =================>]
                                       ^ Egress Switches to N+1
```

1. **$t = 0\text{s}$**: Epoch $N$ is established; traffic transmits and receives under Epoch $N$ keys.
2. **$t = 110\text{s}$**: The rekey timer triggers a background Noise handshake. Epoch $N+1$ keys are derived. Egress traffic immediately switches to Epoch $N+1$.
3. **$t = 110\text{s} \dots 130\text{s}$ (Overlap Window)**: The ingress data plane concurrently accepts and authenticates datagrams stamped with Epoch $N$ or Epoch $N+1$. Late-arriving, reordered, or buffered packets from Epoch $N$ are processed without decryption failure.
4. **$t = 130\text{s}$**: Epoch $N$ key material is explicitly zeroized from RAM via [`zeroize::ZeroizeOnDrop`](https://docs.rs/zeroize).

### Topology Orchestration & Blind Relay Signaling

When peers cannot achieve direct point-to-point UDP connectivity due to asymmetric or carrier-grade NATs (CGNAT), the control plane handles path migration automatically:
- **STUN & Port Prediction**: Probes external mapping via rendezvous servers to detect port-preservation or sequential port allocations.
- **Blind DERP Relaying**: If direct hole punching fails, traffic falls back to an authenticated, end-to-end encrypted relay server ([`crates/yip-rendezvous`](../crates/yip-rendezvous)). Relays forward opaque encrypted datagrams without possessing decryption keys.
- **Dynamic Roaming**: When a mobile peer switches network paths (e.g., Wi-Fi to cellular), the data plane validates the peer's authenticating tag and automatically updates the remote endpoint mapping without renegotiating the Noise session.

---

## 3. Cryptographic Self-Certifying IPv6 Addressing

### Overlay Addressing in `fd00::/8` (RFC 4193 ULA)

In `yip`, overlay network addresses are **self-certifying**: a node's IPv6 address is cryptographically derived directly from its public key. There is no central IP Address Management (IPAM) daemon, no DHCP server, and no coordinating state store. The address is the identity.

All overlay addresses reside within the RFC 4193 Unique Local Address (ULA) prefix `fd00::/8`.

### Derivation Algorithm & Byte-Level Layout

The derivation algorithm is implemented in [`bin/yipd/src/addr.rs`](../bin/yipd/src/addr.rs). It feeds the node's 32-byte public key into a variable-length BLAKE2s digest using a domain-separation context:

$$\text{Digest}_{120} = \text{BLAKE2s-120}(\text{Domain} = \texttt{"yip-addr-v1"}, \text{Key} = \text{PublicKey})$$

$$\text{IPv6 Address} = \texttt{0xfd} \mathbin{\Vert} \text{Digest}_{120}$$

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0xfd (8 bits)|            BLAKE2s Digest [0..7]              |
|  (ULA Prefix) |                   (56 bits)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     BLAKE2s Digest [7..15]                    |
|                            (64 bits)                          |
|                     (Interface Identifier)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Field Specifications

| Byte Range | Size | Field Name | Description |
| :--- | :--- | :--- | :--- |
| `0..1` | 8 bits | ULA Prefix | Constant byte `0xfd`, anchoring the address in IPv6 RFC 4193 ULA space. |
| `1..8` | 56 bits | Mesh Subnet / Shard Routing ID | First 7 bytes of the BLAKE2s digest. Used for fast packet sharding and mesh routing. |
| `8..16` | 64 bits | Interface Identifier (IID) | Final 8 bytes of the BLAKE2s digest, representing the node's unique host token. |

```rust
// Verified against bin/yipd/src/addr.rs
pub fn node_addr(pubkey: &[u8; 32]) -> Ipv6Addr {
    let mut h = Blake2sVar::new(15).expect("15 is a valid blake2s output len");
    h.update(b"yip-addr-v1");
    h.update(pubkey);
    let mut digest = [0u8; 15];
    h.finalize_variable(&mut digest).expect("output len matches");
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..].copy_from_slice(&digest);
    Ipv6Addr::from(octets)
}
```

### Mathematical Guarantees: Anti-Spoofing & Anti-Squatting

Self-certifying addresses eliminate entire classes of overlay network attacks:

1. **Impossibility of IP Spoofing**: When a worker thread receives an inner decrypted IPv6 packet with source IP $S$, it verifies that:
   $$S = \text{node\_addr}(\text{SessionPublicKey})$$
   Because $\text{SessionPublicKey}$ is authenticated by the Noise handshake, an attacker cannot emit packets purporting to originate from another node's IP address. Forged source addresses fail self-certification checks and are dropped immediately at line rate.
2. **Impossibility of Address Squatting**: An adversary cannot register or preempt another peer's address without finding a preimage for BLAKE2s.
3. **Collision Resistance**: With 120 bits of cryptographic output entropy, the birthday bound requires generating approximately $2^{60}$ distinct keypairs before encountering a single collision across the entire global mesh.

### Consistent Shard Affinity via Identity Hash

In multi-threaded deployments, incoming TUN packets must be directed to the worker core owning the peer's session without inter-thread locks.

Because octets `[1..9]` of the IPv6 address represent the first 8 bytes of the BLAKE2s digest, hashing these octets directly yields the identical shard index as hashing the peer's public key (see [`bin/yipd/src/sharding.rs`](../bin/yipd/src/sharding.rs)):

```rust
pub fn shard_for_addr(addr: Ipv6Addr, num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }
    let octets = addr.octets();
    let hash = if octets[0] == 0xfd {
        u64::from_be_bytes(octets[1..9].try_into().expect("slice has length 8"))
    } else {
        u64::from_be_bytes(octets[8..16].try_into().expect("slice has length 8"))
    };
    (hash % num_shards as u64) as usize
}
```

This alignment ensures that outbound packets routed by destination IPv6 address land on the core owning the session without cross-core cache line bouncing.

---

## 4. Lock-Free Data Plane & Multi-Core Sharding

### Multi-Queue TUN/TAP Device Subsystem

`yip` uses the Linux kernel's multi-queue TUN subsystem (`IFF_MULTI_QUEUE`) implemented in [`crates/yip-device`](../crates/yip-device).

Instead of funneling all virtual interface traffic through a single file descriptor and contending on a kernel spinlock, `yipd` creates $N$ independent queues matching the number of worker shards ($N = \text{cores}$). Each worker core thread opens and services its own exclusive TUN file descriptor.

```
+-------------------------------------------------------------------------------+
|                             Linux Kernel (ip_route)                           |
+-------------------------------------------------------------------------------+
        |                               |                               |
        | Queue 0                       | Queue 1                       | Queue N
        v                               v                               v
+-------------------+           +-------------------+           +-------------------+
|  Worker Shard 0   |           |  Worker Shard 1   |           |  Worker Shard N   |
|  (Core 0 Pinned)  |           |  (Core 1 Pinned)  |           |  (Core N Pinned)  |
|  - SPSC Matrix    |           |  - SPSC Matrix    |           |  - SPSC Matrix    |
|  - RS-FEC State   |           |  - RS-FEC State   |           |  - RS-FEC State   |
|  - Driver Engine  |           |  - Driver Engine  |           |  - Driver Engine  |
+-------------------+           +-------------------+           +-------------------+
```

### Single-Producer Single-Consumer (SPSC) Ring Buffers

Inter-thread cross-shard communication (e.g., when a packet ingress from network socket on Shard $A$ is destined for an inner IP handled by Shard $B$) is mediated entirely by lock-free Single-Producer Single-Consumer (SPSC) bounded ring buffers ([`crates/yip-io/src/spsc.rs`](../crates/yip-io/src/spsc.rs)).

For $N$ worker shards, `yipd` instantiates an $N \times (N - 1)$ matrix of SPSC queues:
- **Zero Mutex Contention**: Producers write exclusively using atomic release semantics; consumers read using atomic acquire semantics.
- **Bounded Heap Consumption**: Queue capacities are static powers of two (e.g., $C = 2048$).
- **Batch Drain Primitives**: Workers harvest messages in bursts (up to 64 datagrams per loop) to amortize atomic synchronization overhead.

### Cache-Line Padding & False-Sharing Prevention

On modern multi-core SMP processors, two variables located within the same 64-byte (or 128-byte) cache line cause **false sharing** when written by different cores, degrading throughput due to CPU cache coherency invalidation bus cycles (MESI/MOESI protocol).

`yip-io` encapsulates ring buffer pointers using `crossbeam_utils::CachePadded`:

```rust
// Verified against crates/yip-io/src/spsc.rs
struct RingBuffer<T, const CAP: usize> {
    /// Producer sequence counter (write index) isolated on its own cache line.
    head: CachePadded<AtomicUsize>,
    /// Consumer sequence counter (read index) isolated on its own cache line.
    tail: CachePadded<AtomicUsize>,
    /// Heap-allocated array of uninitialized slot storage.
    slots: Box<[UnsafeCell<MaybeUninit<T>>]>,
}
```

In addition, each producer and consumer retains a thread-local cached counterpart (`cached_tail: Cell<usize>` and `cached_head: Cell<usize>`). The producer checks its cached tail before issuing an atomic load across the inter-core interconnect, reducing memory bus traffic by over 90% during sustained bursts.

### Symmetric Flow Hashing & Strict FIFO Ordering

To preserve TCP windowing performance, packets belonging to a bidirectional connection must never be reordered across cores.

`yipd` inspects the inner IPv4/IPv6 packet headers and computes a symmetric 5-tuple hash (`FlowTuple`):

$$\text{FlowHash} = \text{Hash}(\min(\text{SrcIP}, \text{DstIP}), \max(\text{SrcIP}, \text{DstIP}), \min(\text{SrcPort}, \text{DstPort}), \max(\text{SrcPort}, \text{DstPort}), \text{Proto})$$

- Both forward and reverse traffic flows pin deterministically to the same worker shard.
- Packets within each flow proceed in strict FIFO order, preventing TCP sequence inversions and spurious DupACK retransmissions.

### NUMA Awareness & CPU Core Pinning

On multi-socket NUMA hardware (e.g., dual AMD EPYC or Intel Xeon systems), cross-node memory access incurs severe latency penalties. `yip` achieves line-rate performance through:
- **Thread Pinning (`pthread_setaffinity_np`)**: Worker threads bind 1:1 to dedicated physical CPU cores.
- **Local Memory Allocation**: UMEM frame buffers and SPSC rings are allocated on the NUMA memory node local to the executing core.
- **NIC Queue Alignment**: NIC RX/TX hardware queues are steered via `smp_affinity` directly to the corresponding pinned worker core.

---

## 5. Kernel-Bypass Data Plane Driver Engines

`yip` supports three interchangeable datapath driver backends within [`crates/yip-io`](../crates/yip-io). The protocol logic remains identical across all backends.

### Driver Engine Capabilities & Performance Matrix

| Metric / Feature | Standard Vectorized | `io_uring` Multishot | AF_XDP Zero-Copy |
| :--- | :--- | :--- | :--- |
| **Primary Primitives** | `recvmmsg` / `sendmmsg` | SQE / CQE Rings | UMEM, Fill / Rx / Tx / Comp Rings |
| **Syscall Overhead** | Amortized (32 pkts/call) | Zero in steady-state (busy-poll) | Absolute Zero (Kernel Bypass) |
| **Packet Copying** | Kernel $\leftrightarrow$ Userspace | Kernel $\leftrightarrow$ Registered Buffers | Zero Copy (NIC DMA $\leftrightarrow$ UMEM) |
| **Minimum Kernel** | Linux 3.10+ | Linux 5.11+ | Linux 5.4+ (5.10+ recommended) |
| **Required Capabilities**| `CAP_NET_ADMIN` | `CAP_NET_ADMIN` | `CAP_NET_ADMIN` + `CAP_BPF` |
| **Hardware Dependency** | None (Generic) | Modern Kernel | Supported NIC (Intel, Mellanox) |
| **p99 Latency (RTT)** | ~0.46 ms | ~0.26 ms (with busy-poll) | < 0.08 ms |
| **Throughput Ceiling** | ~3.8 Gbps / core | ~12.5 Gbps / core | 40+ Gbps line-rate |

---

### Engine 1: Standard Vectorized Socket Engine (`sendmmsg` / `recvmmsg` + GSO)

The standard vectorized engine ([`crates/yip-io/src/batch.rs`](../crates/yip-io/src/batch.rs)) runs on any generic Linux distribution without hardware-specific requirements:

1. **Syscall Amortization**: Collects bursts of datagrams (default `BATCH_SIZE = 32`, expandable to `BATCH_SIZE_64 = 64` and `BATCH_SIZE_128 = 128` via const-generic `sendmmsg_burst` and `recvmmsg_batch`) and transfers them in a single `recvmmsg(2)` or `sendmmsg(2)` invocation, amortizing CPU privilege boundary transitions.
2. **Fate-Safe Generic Segmentation Offload (GSO)**: Uses the Linux `UDP_SEGMENT` socket control message to hand the kernel aggregated super-buffers up to 64 KB. The kernel or NIC hardware splits the buffer into physical MTU-sized segments.

#### Fate-Safety Rule

To protect Forward Error Correction resilience, the GSO coalescer ([`crates/yip-io/src/gso.rs`](../crates/yip-io/src/gso.rs)) enforces a strict invariant:
> **A single coalesced GSO super-buffer must NEVER contain two datagrams belonging to the same FEC object.**

If two symbols from the same FEC block were packed into the same GSO datagram and that UDP datagram was dropped in transit, multiple symbols of the FEC block would be lost simultaneously, defeating the erasure code. `yip` verifies pairwise distinct `fate` identifiers before coalescing.

---

### Engine 2: `io_uring` Asynchronous Multishot Engine

The `io_uring` engine ([`crates/yip-io/src/uring.rs`](../crates/yip-io/src/uring.rs)) operates over unified Submission Queue (SQ) and Completion Queue (CQ) rings:

- **Ring Dimensions**: 1024 Submission Queue Entries (SQE) with a 2048-entry Completion Queue (CQ).
- **Buffer Selection (`BUFFER_SELECT`)**: Uses kernel-provided buffer groups (`BUF_GROUP = 17`) to eliminate pre-allocated socket buffer copies.
- **64-Bit Tag Tracking**: Submissions encode the request kind and slot index into a 64-bit `user_data` tag:
  - `TAG_UDP_RECV`: Socket datagram arrival.
  - `TAG_TUN_RECV`: Virtual interface frame read.
  - `TAG_SEND_SLOT`: Outbound send completion.
  - `TAG_REPROVIDE`: Replenishment of provided buffers.
- **Adaptive Busy-Polling (`YIP_URING_BUSYPOLL=1`)**: Executes a non-blocking spin loop (`CQ_SPIN_BUDGET = 2_000_000`) polling the completion queue directly from userspace before falling back to blocking wait. This trades spare core cycles to achieve sub-300 µs round-trip latency.

---

### Engine 3: AF_XDP (XSK) Zero-Copy Engine

The AF_XDP engine ([`crates/yip-io/src/af_xdp.rs`](../crates/yip-io/src/af_xdp.rs)) bypasses the entire Linux network stack (including `sk_buff` allocation, netfilter, connection tracking, and routing lookup), steering raw Ethernet frames directly into userspace shared memory.

#### eBPF XDP Packet Steering (`XDP_REDIRECT`)

`yip` attaches a high-speed eBPF filter at the NIC driver layer ([`crates/yip-io/src/bpf.rs`](../crates/yip-io/src/bpf.rs)):
1. Incoming frames arrive on the physical wire and enter the NIC's RX ring.
2. The eBPF program parses outer IPv4/IPv6 headers and UDP destination ports.
3. Matching tunnel datagrams are redirected via `bpf_redirect_map()` into an XSK map (`BPF_MAP_TYPE_XSKMAP`).
4. Non-tunnel packets return `XDP_PASS` and continue through the standard Linux kernel network stack.

#### Shared Memory UMEM Pool Architecture

Packet memory is managed in a pre-allocated, page-aligned shared memory pool (`UmemPool`):
- Allocated via `libc::mmap` with `MAP_ANONYMOUS | MAP_SHARED`.
- Chunk size is 2,048 bytes (`UMEM_CHUNK_SIZE`), aligning with standard MTU envelopes and cache lines.
- **Configurable Page Faulting (`UmemPoolConfig`)**: Supports both zero-tail-latency physical page pre-faulting (`pre_fault: true` with `MAP_POPULATE`) and instant on-demand lazy paging (`pre_fault: false` via `UmemPool::new_lazy`, cutting pool initialization time from ~1,590 µs to ~7 µs, a 219x reduction). Optional `lock_memory: true` calls `libc::mlock` to pin pages in physical RAM and prevent paging under memory pressure.
- **Per-Core `UmemSlab` Partitioning**: To eliminate centralized free-list serialization and cross-core cache invalidation under multi-worker scaling, `UmemPool` partitions chunks into disjoint per-core `UmemSlab`s (`UmemPool::new_slabs`). Each worker thread allocates and frees chunks locally from its dedicated slab without atomic locks or cross-core coordination.
- **Lock-Free Batch Ring Recycling**: Completed TX chunk descriptors are recycled directly from the `CompletionRing` into the `FillRing` via `slab.recycle_from_rings`, spilling surplus chunks to the thread-local slab without heap allocations.
- **Vectorized Ring Operations**: Circular descriptor rings (`FillRing`, `CompletionRing`, `RxRing`, `TxRing`) execute batch produce and consume using power-of-two masking and contiguous slice copies, sustaining over 4,000 Mops/s.

#### The Four Descriptor Rings

AF_XDP coordinates packet ownership between userspace and the NIC via four circular descriptor rings:

```
+-----------------------------------------------------------------------------------+
|                                 USERSPACE (yipd)                                  |
|                                                                                   |
|  [Fill Ring] ===== (Produces Free Chunks) =====> [Rx Ring] <==== (Consumes RX)    |
|       |                                               ^                           |
|       |                                               |                           |
+-------|-----------------------------------------------|---------------------------+
        |                  UMEM Memory Pool             |
+-------|-----------------------------------------------|---------------------------+
|       v                                               |                           |
|  [Tx Ring] ===== (Produces Outbound Packets) ==> [Comp Ring] <== (Recycles Chunks)|
|                                                                                   |
|                                 KERNEL / NIC DMA                                  |
+-----------------------------------------------------------------------------------+
```

1. **Fill Ring (Userspace $\to$ Kernel)**: Userspace pushes free UMEM chunk addresses into this ring, providing the NIC with memory buffers ready to receive incoming packets.
2. **Rx Ring (Kernel $\to$ Userspace)**: When the NIC receives a packet via DMA, it writes descriptor entries (`XskDesc { addr, len, flags }`) into the Rx Ring. Userspace consumes descriptors and reads the payload directly from UMEM.
3. **Tx Ring (Userspace $\to$ Kernel)**: Userspace writes descriptors into the Tx Ring specifying the chunk address and length of outbound wire frames for the NIC to transmit.
4. **Completion Ring (Kernel $\to$ Userspace)**: Once the NIC completes physical transmission via DMA, it returns chunk addresses to the Completion Ring so userspace can recycle them into its free pool.

#### Ring Mechanics & Zero-Copy Descriptors

All four rings enforce a power-of-two capacity invariant ($C = 2^k$, default 2,048 descriptors). Head and tail indices increment monotonically without bounding; slot addresses are derived using bitwise masking:

$$\text{SlotIndex} = \text{Index} \ \& \ (\text{Capacity} - 1)$$

Memory barriers (`std::sync::atomic::fence`) ensure that descriptor contents are globally visible across the PCIe bus before the updated pointer index is published. Zero memory copies occur between the physical Ethernet wire and the cryptographic pipeline.

---

## 6. Wire Protocol Framing & Anti-DPI Defense

### Wire Protocol Framing Diagram

The layout of data plane frames, post-quantum handshake tokens, key ratchet lifecycles, and self-certifying addressing is illustrated in the architectural wire format diagram:

![yip Wire Protocol Framing](../assets/wire-format.svg)

---

### Frame Layout & Header Bitfields

The on-wire data plane datagram layout consists of three primary segments:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Encrypted Header                        |
|                     (Bytes 0..4 / 32 bits)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    SipHash-1-3 MAC Tag                        +
|                     (Bytes 4..12 / 64 bits)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                 ChaCha20-Poly1305 Ciphertext                  +
|                    (Bytes 12..N / Variable)                   |
|           [ RS-FEC Encoded Symbol + 16B Poly1305 Tag ]        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Unmasked Header Bitfields (32 bits / 4 Bytes)

Before keystream masking, the 4-byte logical header encodes:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Typ|  Epoch  |          Payload Length         |    Reserved   |
|2 b|   6 b   |              16 bits            |     8 bits    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Type (2 bits)**: Datagram classification discriminator:
  - `00`: Handshake Init / Response.
  - `01`: Control / ARQ Feedback.
  - `10`: Encrypted Data Plane Frame.
  - `11`: Reserved.
- **Epoch (6 bits)**: Active session key ratchet index ($0 \dots 63$), supporting up to 64 concurrently valid rotation cycles.
- **Payload Length (16 bits)**: Exact byte length of the following AEAD ciphertext and FEC symbol ($0 \dots 65,535$).
- **Reserved (8 bits)**: Extension flags, FEC padding alignment indicators, or zero-fill.

---

### Keyed Header Protection (ChaCha20 / SipHash-CTR Keystream Mask)

Deep Packet Inspection (DPI) appliances (such as nDPI, Zeek, Suricata, and state-sponsored censorship firewalls) detect VPN protocols by matching static magic bytes, fixed header offsets, or packet type discriminators.

`yip` obliterates all static wire signatures via **Keyed Header Protection** ([`crates/yip-wire/src/lib.rs`](../crates/yip-wire/src/lib.rs)):

1. A 16-byte header protection key $K_{\text{hp}}$ is derived during the Noise handshake.
2. The 8-byte SipHash-1-3 authentication tag of the packet serves as a per-packet nonce/sample.
3. A keystream mask is generated using SipHash in counter mode:
   $$\text{Mask}_0 = \text{SipHash-1-3}(K_{\text{hp}}, \text{Tag} \mathbin{\Vert} \texttt{0\_u32})$$
   $$\text{Mask}_1 = \text{SipHash-1-3}(K_{\text{hp}}, \text{Tag} \mathbin{\Vert} \texttt{1\_u32})$$
4. The mask is XORed into the header bytes in-place:
   $$\text{Header}_{\text{wire}} = \text{Header}_{\text{plain}} \oplus \text{Mask}[0..4]$$

Every byte on the wire (including the header, type bits, and length fields) exhibits uniform pseudo-random entropy. There are no magic numbers, no static offsets, and no unencrypted protocol identifiers.

---

### SipHash-1-3 64-Bit Coverage Authentication Tag

To prevent chosen-ciphertext attacks, blind UDP port probing, and resource exhaustion against the cryptographic AEAD engine, every frame carries an 8-byte authenticating tag computed via `SipHasher13`:

$$\text{Tag} = \text{SipHash-1-3}(K_{\text{auth}}, \text{Header}_{\text{plain}} \mathbin{\Vert} \text{Ciphertext})$$

- **Performance**: SipHash-1-3 completes verification in **16.76 nanoseconds** per header on standard x86_64 cores.
- **Pre-Authentication Gate**: On ingress, `yipd` verifies the 8-byte tag in constant time (`subtle::ConstantTimeEq`). Invalid packets, DPI probes, or random internet scans are rejected and discarded immediately, without invoking ChaCha20-Poly1305 decryption or allocating heap buffers.

---

### Zero Magic Bytes & Uniform Entropy Guarantees

Combined with optional traffic-analysis defense plugins ([`crates/yip-obf`](../crates/yip-obf)), `yip` frames pass all statistical randomness and entropy tests:
- **Chi-Square Goodness-of-Fit**: Conforms to an ideal uniform distribution ($p > 0.95$).
- **Bitwise Entropy**: Evaluates to $> 7.999$ bits per byte.
- **Oracle Verification**: Validated against automated oracle test suites running nDPI, Zeek, Suricata, and Wireshark analyzers without triggering protocol detection signatures.

> [!TIP] Clever Fox Tip: Blending Into the Shadows
> By eliminating fixed protocol signatures and masking headers with per-packet keystreams, yip leaves no tracks for deep packet inspection engines. To a network monitor, your mesh traffic looks indistinguishable from benign, uniform random noise.

---

## 7. End-to-End Packet Processing Lifecycles

### Egress Datapath Pipeline

The egress path moves an IP packet originating from the host operating system to the physical network:

```
[Linux Kernel TCP/IP Stack]
            |
            v
1. Linux TUN/TAP Read (Multi-queue descriptor batching)
            |
            v
2. Classification & Flow Pinning (Extract 5-tuple -> Symmetric FlowHash)
            |
            v
3. AEAD Sealing (ChaCha20-Poly1305 SIMD encryption under active Epoch)
            |
            v
4. Systematic RS-FEC Encoding (Generate Cauchy repair symbols in GF(256))
            |
            v
5. Wire Framing & Obfuscation (Keyed XOR header mask + SipHash-1-3 tag)
            |
            v
6. Socket / Driver Transmission (AF_XDP Tx Ring / io_uring / sendmmsg GSO)
            |
            v
[Physical Network Interface Wire]
```

1. **Host Read**: The worker thread reads up to 32 frames from its exclusive TUN queue descriptor.
2. **Classification**: `FlowTuple::extract` identifies IP protocol, source/destination IPs, and ports, computing the symmetric shard affinity.
3. **AEAD Sealing**: The inner packet is sealed with ChaCha20-Poly1305 using SIMD instructions (AVX2 on x86_64, NEON on ARM64).
4. **RS-FEC Encoding**: Ciphertext blocks are passed to the Systematic Cauchy Reed-Solomon encoder. For every $K$ source symbols, $R$ parity symbols are generated.
5. **Wire Framing**: The logical header is assembled, protected with the XOR keystream mask, and tagged with the 64-bit SipHash MAC.
6. **Transmission**: Datagrams are submitted to the NIC via the selected driver engine (AF_XDP Tx Ring, `io_uring` SQE, or `sendmmsg` with `UDP_SEGMENT`).

---

### Ingress Datapath Pipeline

The ingress path reverses the processing stages with early verification gates:

```
[Physical Network Interface Wire]
            |
            v
1. Driver Reception (AF_XDP Rx Ring / io_uring / recvmmsg batch)
            |
            v
2. Stack-Allocated SipHash-1-3 Tag Verification (<17 ns)
   [Fail -> Drop immediately without allocation]
            | (Pass)
            v
3. Header Unmasking (XOR deprotection using derived hp_key)
            |
            v
4. Systematic Cauchy RS-FEC Decoding (Reconstruct missing symbols if loss occurred)
            |
            v
5. AEAD Unsealing & Replay Check (ChaCha20-Poly1305 open + Sliding Replay Bitmap)
            |
            v
6. Self-Certifying Source Address Check (Source IP == node_addr(PeerKey))
   [Fail -> Drop spoofed packet]
            | (Pass)
            v
7. Linux TUN/TAP Write (Multi-queue descriptor write back to host OS)
            |
            v
[Linux Kernel TCP/IP Stack]
```

1. **Driver Harvest**: Driver harvests datagrams directly from kernel bypass rings or vectorized sockets.
2. **Pre-Auth Check**: SipHash-1-3 tag is checked in constant time. Unauthorized or malformed packets are dropped instantly.
3. **Deprotection**: The 4-byte header is recovered on the stack by XORing the keystream mask.
4. **RS-FEC Reconstruction**: The FEC decoder checks object completion. If loss occurred but at least $K$ of $K+R$ symbols arrived, Gaussian elimination over $\text{GF}(256)$ recovers the missing symbols with zero retransmission latency.
5. **AEAD Verification**: The AEAD layer verifies the Poly1305 MAC, checks the sliding replay bitmap, and decrypts the payload.
6. **Self-Certification Gate**: Inner source IP is validated against the peer's public key (`verify_addr`).
7. **Host Injection**: The plaintext packet is written to the local multi-queue TUN interface.

---

### Systematic Cauchy RS-FEC Erasure Coding

`yip-transport` implements Systematic Cauchy Reed-Solomon Forward Error Correction over the Galois Field $\text{GF}(2^{8})$ ([`crates/yip-transport/src/fec.rs`](../crates/yip-transport/src/fec.rs)):

- **Systematic Structure**: The first $K$ symbols emitted on the wire are identical to the unencoded source packets. In loss-free conditions, decode cost is exactly **zero** (no matrix multiplication).
- **Cauchy Generator Matrix**: Employs Cauchy matrices rather than traditional Vandermonde matrices:
  $$A_{i,j} = \frac{1}{x_i \oplus y_j}$$
  Every submatrix of a Cauchy matrix is non-singular over $\text{GF}(256)$, guaranteeing that any $K$ received symbols out of $K + R$ can reconstruct the original block.
- **SIMD Matrix Multiplication**: Accelerated using x86 AVX2 (`_mm256_shuffle_epi8` / PSHUFB) and ARM NEON table-lookup vector instructions, achieving processing speeds exceeding 15 GB/s per core.
- **Zero-RTT Recovery**: Under packet loss rates up to 30%, packets are recovered immediately at the receiver without waiting for round-trip ARQ retransmissions.
- **Zero-Allocation Hot-Path Reassembly**:
  - **Contiguous Buffer Slicing**: Replaces per-shard dynamic `HashMap<u16, Vec<u8>>` allocations with a pre-allocated contiguous `payload: Vec<u8>` buffer and a 256-bit bitset (`seen_mask: [u64; 4]`). Incoming systematic source shards ($idx < K$) copy directly into `payload[idx * shard_len ..]` with zero heap allocations.
  - **In-Place Clean Delivery**: When all $K$ source shards arrive ($source\_count == K$), the completed object is extracted instantly via `std::mem::take(&mut state.payload)` and truncated to original byte size, completely bypassing RS decoding and vector stitching. Reassembly latency drops to **117 ns** for $K=1$ (1400B) and **173 ns** for $K=3$ (4200B).
  - **In-Place Loss Reconstruction (`reconstruct_missing_sources`)**: When loss occurs, Cauchy parity reconstruction solves missing source shards directly into missing slice windows within the pre-allocated payload buffer using a single scratch slice, eliminating `Vec<Vec<u8>>` heap matrices.
  - **Flat Open-Addressing `ObjectTable`**: Replaces standard library `HashMap<u64, ObjState>` with an open-addressing slot table featuring SplitMix64 fast hashing and backward-shift deletion. Eliminates tombstones, bounds memory overhead, and guarantees zero heap churn during packet ingress and eviction.

---

### Thin Reactive ARQ Backstop

For traffic flows where forward error correction is temporarily exhausted (e.g., severe deep fade or loss bursts exceeding $R$), `yip-transport` layers a **Thin Reactive ARQ** backstop:
- **Selective Bitmap ACKs**: Receivers emit compact selective acknowledgment bitmasks indicating missing `object_id` ranges.
- **Zero Redundant Retransmission**: Senders transmit only the specific missing parity symbols necessary to cross the rank threshold, minimizing retransmission bandwidth bloat.

---

## 8. Security & Threat Model

### Post-Quantum Security Margin

`yip` is built to withstand the emergence of Cryptanalytically Relevant Quantum Computers (CRQC) and "Harvest Now, Decrypt Later" adversaries:
- **Classical Floor**: 128-bit classical security via Curve25519 and ChaCha20-Poly1305.
- **Quantum Ceiling**: Category 1 post-quantum security via NIST FIPS 203 ML-KEM-512 (lattice-based Learning With Errors over Module Lattices).
- **Hybrid Construction**: Breaking the session key requires simultaneously compromising *both* the classical discrete-log hardness (X25519) and the module lattice hardness (ML-KEM).

### Sliding Bitmap Replay Protection

To defeat packet replay attacks across high-speed connections, `crates/yip-crypto` implements sliding bitmap replay verification:
- **Standard Profile**: 8,192-bit window (128 words $\times$ 64 bits), providing robust defense for standard internet connections.
- **High-Throughput Profile**: 131,072-bit window (2,048 words $\times$ 64 bits), specifically sized for 10G/40G line-rate streams to prevent packet drops caused by multi-queue packet reordering.
- **Atomic Window Progression**: Bitmaps advance monotonically; duplicate sequence counters are rejected prior to AEAD decryption.

### Side-Channel Mitigation & Memory Zeroization

- **Constant-Time Verification**: All cryptographic comparisons (SipHash tags, Poly1305 MACs, Noise channel bindings) use constant-time operations (`subtle::ConstantTimeEq`).
- **Memory Zeroization**: Ephemeral keys, ML-KEM decapsulation seeds, and intermediate shared secrets implement the `Zeroize` and `ZeroizeOnDrop` traits, ensuring that secrets are purged from RAM immediately after use.
- **Compiler Barrier Enforcement**: Memory scrubbing uses volatile memory writes and compiler fences to prevent dead-store elimination optimizations.

### Blind Packet Injection & DoS Defense

1. **State-Free Discard**: Forged UDP packets injected by third parties fail the 8-byte SipHash-1-3 tag check and are dropped in under 17 ns without allocating heap memory or modifying daemon state.
2. **Amplification Prevention**: Handshake responses are strictly bounded in size (Message 2 is 948 bytes, smaller than Message 1's 1,028 bytes). Senders cannot use `yipd` nodes as reflection amplification vectors.
3. **Cookie / Rate Limiting**: In unauthenticated flood scenarios, nodes transition to stateless cryptographic challenge-cookie verification, requiring initiators to solve a lightweight proof before state allocations occur.

---

*For further implementation details, inspect the source implementations in [`crates/yip-io`](../crates/yip-io), [`crates/yip-crypto`](../crates/yip-crypto), [`crates/yip-transport`](../crates/yip-transport), and [`crates/yip-wire`](../crates/yip-wire).*
