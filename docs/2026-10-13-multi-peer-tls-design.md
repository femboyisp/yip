# Design Spec: Multi-Peer TLS Transport Support (#136)

**Date:** 2026-10-13
**Status:** Approved by User
**Issue:** femboyisp/yip#136
**Related Issues:** #61 (Single-connection pump hardening), #49 (QUIC connection bounding)

---

## 1. Context & Motivation

In `bin/yipd/src/tls.rs` (the 3c.2 TLS-mimicry transport), `yipd` wraps its inner Noise-IK/FEC/AEAD datagrams in length-prefixed TLS byte-streams over BoringSSL.
Historically, `run_tls` was hardcoded to a single peer:
- It only processed `peers[0]`, dropping/ignoring any subsequent configured peers.
- The `yip_io::epoll::Epoll` abstraction only watched two fixed file descriptors (`tun_fd` and a single `udp_fd`/`tcp_fd`).
- Issue #61 hardened this single-connection pump with an `INNER_HANDSHAKE_TIMEOUT` (10s) and added an explicit log warning if multiple peers were configured.

Issue #136 calls for full multi-peer mesh support under `transport = tls`, bringing parity with `transport = quic` and `transport = udp`.

---

## 2. Architecture & Design Principles

### 2.1 Invariants
1. **Zero Wire Format Changes:** Length-prefixed framing `[u16 BE length][datagram]` and BoringSSL outer TLS 1.3 parameters (ClientHello GREASE, ALPN, SNI, self-signed throwaway certs) remain identical.
2. **Deterministic Role Tiebreak (Glare Prevention):** Pairwise role assignment follows static public key ordering:
   - `local_public < peer_public` $\implies$ **Client** (dials outbound `TcpStream::connect`).
   - `local_public > peer_public` $\implies$ **Server** (listens on `TcpListener`, accepts inbound).
   This eliminates dual-connection glare races and matches `quic.rs`.
3. **Non-Blocking Epoll Event Loop:** `#![forbid(unsafe_code)]` in `yipd` remains strictly enforced. All unsafe system calls for epoll manipulation reside in `yip-io`.
4. **Fail-Closed Security & Slot Recovery:** Unconfirmed connections (where the inner Noise-IK handshake does not complete within `INNER_HANDSHAKE_TIMEOUT = 10s`) are cleanly torn down.

---

## 3. Subsystem Specifications

### 3.1 `yip-io::epoll`: Dynamic Epoll Primitive
Update or extend `crates/yip-io/src/epoll.rs` to support dynamic multi-fd registration:
- `Epoll::new() -> io::Result<Epoll>`: Creates an epoll instance (`epoll_create1(EPOLL_CLOEXEC)`).
- `Epoll::add(&self, fd: RawFd, token: u64) -> io::Result<()>`: Sets non-blocking and registers `EPOLLIN` with user-data `token`.
- `Epoll::remove(&self, fd: RawFd) -> io::Result<()>`: Unregisters `fd` from epoll (`EPOLL_CTL_DEL`).
- `Epoll::wait_events(&self, timeout_ms: i32, out: &mut Vec<u64>) -> io::Result<()>`: Collects up to $N$ ready tokens into `out`.

Existing two-fd `Epoll::wait(&self, timeout_ms: i32) -> io::Result<Ready>` is retained for backward compatibility with `quic.rs`.

### 3.2 Token Assignment in `run_tls`
- `TOKEN_TUN: u64 = 0` (TUN interface packet egress).
- `TOKEN_LISTENER: u64 = 1` (Inbound TCP listener for server-role peers).
- `TOKEN_PEER_BASE: u64 = 100` (Dynamic token for peer connections: `TOKEN_PEER_BASE + peer_idx`).

### 3.3 Connection Lifecycle & State Machine
For each configured peer $i \in \{0 \dots N-1\}$:
- **Client Role (`local_public < peer_public`):**
  - `Disconnected { backoff_ms: u64, next_dial: Instant }`: Exponential backoff (`INITIAL_BACKOFF_MS` to `MAX_BACKOFF_MS`). When `now >= next_dial`, starts non-blocking connect and TLS handshake.
  - `Connecting { stream: SslStream<TcpStream>, start: Instant }`: Handshake in progress.
  - `Connected { stream: SslStream<TcpStream>, reader: FrameReader, start: Instant, inner_confirmed: bool }`: Active connection registered in Epoll.
- **Server Role (`local_public > peer_public`):**
  - Single `TcpListener` registered under `TOKEN_LISTENER`.
  - Inbound connection accepted $\implies$ TLS server handshake $\implies$ maps to peer by socket address or assigns to pending server slot until inner Noise-IK packet identifies the peer.
  - Enforces `INNER_HANDSHAKE_TIMEOUT` (10s) on pending/unconfirmed connections.

### 3.4 Data Plane & Routing
1. **Ingress (TLS $\to$ PeerManager $\to$ TUN):**
   - Readable peer stream drains TLS plaintext $\to$ `FrameReader` extracts length-prefixed datagrams.
   - For each datagram: `manager.on_udp(peer_addr, &dg, now_ms)`.
   - Inner confirmation gate: if transitioned to established or produced TUN/egress, set `inner_confirmed = true`.
   - TUN packet decrypted $\implies$ write to `tun_fd`.
   - Immediate replies $\implies$ frame and write back to peer's `SslStream`.
2. **Egress (TUN $\to$ PeerManager $\to$ TLS):**
   - Readable `tun_fd` drains packets $\to$ `manager.on_tun(&buf, now_ms)` $\implies$ produces `&[EgressDatagram]`.
   - For each datagram, routes to the matching active peer stream by `d.dst`.
3. **Tick & Maintenance:**
   - On $\le 10$ ms cadence, call `manager.tick(now_ms)` and route egress datagrams to peer streams by `d.dst`.
   - Check reconnect timers for disconnected client peers.
   - Reap streams exceeding `INNER_HANDSHAKE_TIMEOUT` without inner confirmation.

---

## 4. Testing & Verification

1. **Unit Tests in `yip-io`:**
   - Multi-fd registration, token dispatch, deletion, and timeout behavior.
2. **Unit Tests in `yipd::tls`:**
   - Role assignment for multiple peers.
   - Multi-peer mock/loopback pump test driving 2+ concurrent peers over TLS.
   - Inner handshake deadline enforcement per peer without affecting healthy peers.
3. **Integration & Netns Tests:**
   - Multi-peer TLS tunnel ping test (e.g. 3-node topology or 2-peer client/server configuration).
   - Zero clippy warnings (`cargo clippy --all-targets -- -D warnings`) and clean formatting (`cargo fmt --check`).
