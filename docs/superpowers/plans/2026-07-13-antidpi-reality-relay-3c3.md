# Anti-DPI 3c.3 — REALITY-style Relay (Trojan front) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the `yip-rendezvous` relay a Trojan-style TCP/TLS/443 front that terminates real-cert TLS, routes a valid fresh obfuscated `Register` to the tunnel and every other connection (probes, scanners, humans) to a real decoy website — so the relay is indistinguishable from an ordinary HTTPS server under active probing.

**Architecture:** Upgrade `yip-rendezvous` from a blocking single-thread UDP loop to a multi-threaded **tokio** service running the existing UDP task **plus** a new TCP/TLS listener (`tokio-boring`/BoringSSL). Each TLS connection is trial-read: deobfuscate the first framed message with the network `obf_psk`, and if it is a fresh (monotonic-counter) `Register` upgrade to a relay tunnel, else `copy_bidirectional` to a local decoy backend. The pure `RendezvousServer` state machine gains a per-`NodeId` monotonic counter and is shared behind a single `Arc<Mutex<…>>`.

**Tech Stack:** Rust, tokio (multi-thread runtime), tokio-boring + boring (BoringSSL, already used by `yipd`), the existing `yip-obf` envelope, `yip-rendezvous` proto/state-machine crate.

## Global Constraints

- `#![forbid(unsafe_code)]` stays on every `yip-rendezvous` crate/binary — tokio/boring keep `unsafe` inside dependencies.
- **No tokio on the `yipd` data plane.** This milestone touches `yip-rendezvous` **only**. Do not add tokio to `yipd`, `yip-io`, `yip-transport`, or any data-plane crate. (Permanent non-goal from the spec.)
- No `as` numeric casts except enum discriminants / libc-ABI — use `try_from`. No bare `#[allow]` — use `#[expect(reason = "…")]`.
- Pinned deps: `tokio-boring = "4.22.0"` (matches the `boring = "4.22.0"` already in `yipd`), `tokio = "1"` with explicit features. cmake + a BoringSSL compile are already a build dep (from 3c.2); this extends it to `yip-rendezvous`.
- The relay stays a **blind** relay: no peer static keys, no membership-cert verification. Its only secret is the network-wide `obf_psk`; probe-resistance == `obf_psk` secrecy (documented threat boundary, cross-ref #37).
- The UDP rendezvous path stays **behavior-identical** — `--listen-tcp` absent ⇒ no TCP listener, no new bytes, existing netns rendezvous suite green.
- Server-side TLS config mirrors a mainstream web server (mozilla-intermediate / nginx-like: TLS 1.3+1.2, session tickets, ALPN `h2` then `http/1.1`).
- The decoy path must never expose a relay-specific timing signature: an idle connection is governed by the decoy backend's timeout, not our classification timeout.

---

### Task 1: Add a monotonic `counter` to `Message::Register` (wire + codec)

**Files:**
- Modify: `crates/yip-rendezvous/src/proto.rs` (the `Register` variant + `encode`/`decode`)
- Test: inline `#[cfg(test)]` in `crates/yip-rendezvous/src/proto.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Message::Register { node: NodeId, counter: u64 }`; `encode`/`decode` carry the 8-byte big-endian counter after the 16-byte node id.

- [ ] **Step 1: Update the existing Register round-trip test to carry a counter**

In `crates/yip-rendezvous/src/proto.rs`, the codec test currently has `roundtrip(Message::Register { node: n });`. Replace it and add a counter-preserving assertion:

```rust
    #[test]
    fn register_roundtrips_with_counter() {
        let n = node_id(&[7u8; 32]);
        let msg = Message::Register {
            node: n,
            counter: 0x0102_0304_0506_0708,
        };
        let mut buf = Vec::new();
        encode(&msg, &mut buf);
        assert_eq!(decode(&buf), Some(msg));
    }

    #[test]
    fn register_truncated_counter_is_none() {
        // tag(1) + node(16) + only 4 of the 8 counter bytes
        let mut buf = vec![0u8]; // Tag::Register
        buf.extend_from_slice(&[9u8; 16]);
        buf.extend_from_slice(&[0u8; 4]);
        assert_eq!(decode(&buf), None);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p yip-rendezvous register_ -- --exact register_roundtrips_with_counter register_truncated_counter_is_none`
Expected: FAIL to compile — `Message::Register` has no `counter` field.

- [ ] **Step 3: Add the field and update the codec**

In the `Message` enum, change the `Register` variant:

```rust
    Register {
        node: NodeId,
        /// Monotonic per-node freshness counter (anti-replay). Strictly
        /// increasing across a node's registrations; the relay rejects any
        /// Register whose counter is not greater than the last seen.
        counter: u64,
    },
```

In `encode`, replace the `Register` arm:

```rust
        Message::Register { node, counter } => {
            out.push(Tag::Register as u8);
            out.extend_from_slice(node);
            out.extend_from_slice(&counter.to_be_bytes());
        }
```

In `decode`, replace the `Register` arm:

```rust
        t if t == Tag::Register as u8 => {
            let node = node16(rest)?;
            let counter = u64::from_be_bytes(rest.get(16..24)?.try_into().ok()?);
            Some(Message::Register { node, counter })
        }
```

- [ ] **Step 4: Fix the other `Register` construction site in this file's tests**

The existing `codec_roundtrips_each_variant` test (or equivalent) constructs `Message::Register { node: n }`. Update it to `Message::Register { node: n, counter: 1 }`.

- [ ] **Step 5: Run the crate tests to verify they pass**

Run: `cargo test -p yip-rendezvous`
Expected: PASS (all codec tests green).

- [ ] **Step 6: Find and fix every other `Register` construction in the workspace**

Run: `grep -rn "Register {" --include=*.rs crates bin | grep -v proto.rs`
For each hit (notably `crates/yip-rendezvous/src/server.rs` tests and `bin/yipd/src/rendezvous.rs` where the client builds a `Register`), add `counter: <value>`. In `bin/yipd/src/rendezvous.rs`, the client currently sends `Register { node }` — give it `counter: 0` for now (the client-side monotonic counter is wired in 3c.4; a constant 0 keeps 2b behavior and the relay's first-seen accepts it). Leave a comment: `// counter bumped per-registration in 3c.4; 0 is accepted as first-seen`.

- [ ] **Step 7: Build the workspace to confirm no stragglers**

Run: `cargo build --workspace`
Expected: builds clean.

- [ ] **Step 8: Commit**

```bash
git add crates/yip-rendezvous/src/proto.rs bin/yipd/src/rendezvous.rs
git commit -m "feat(rendezvous): add monotonic counter to Register (3c.3 anti-replay field)"
```

---

### Task 2: Per-`NodeId` monotonic freshness in `RendezvousServer`

**Files:**
- Modify: `crates/yip-rendezvous/src/server.rs` (`Reg` struct, `handle` Register arm, sweep)
- Test: inline `#[cfg(test)]` in `crates/yip-rendezvous/src/server.rs`

**Interfaces:**
- Consumes: `Message::Register { node, counter }` (Task 1).
- Produces: `RendezvousServer::handle` accepts a `Register` only when `counter` is strictly greater than the last accepted counter for that `node` (or the node is not currently registered). A rejected (stale/equal) Register returns `Vec::new()` and does **not** refresh the registration. Adds `pub fn is_registered(&self, node: &NodeId, now_ms: u64) -> bool` for the TLS handler to consult.

- [ ] **Step 1: Write the freshness test**

In the `tests` module of `server.rs`:

```rust
    #[test]
    fn register_rejects_stale_or_equal_counter() {
        let mut s = RendezvousServer::new(0);
        let n = node_id(&[1u8; 32]);
        let a = addr(10, 0, 0, 1);
        // First registration at counter 5 is accepted.
        s.handle(a, Message::Register { node: n, counter: 5 }, 0);
        assert!(s.is_registered(&n, 0), "counter 5 accepted");
        // Replay at counter 5 is rejected: a Lookup still resolves to the
        // ORIGINAL addr, proving the stale Register did not overwrite it.
        let a2 = addr(10, 0, 0, 2);
        s.handle(a2, Message::Register { node: n, counter: 5 }, 1);
        let out = s.handle(a, Message::Lookup { node: n }, 2);
        match &out[0].1 {
            Message::PeerInfo { reflexive, .. } => assert_eq!(*reflexive, a),
            other => panic!("expected PeerInfo, got {other:?}"),
        }
        // A greater counter is accepted and updates the addr.
        s.handle(a2, Message::Register { node: n, counter: 6 }, 3);
        let out = s.handle(a, Message::Lookup { node: n }, 4);
        match &out[0].1 {
            Message::PeerInfo { reflexive, .. } => assert_eq!(*reflexive, a2),
            other => panic!("expected PeerInfo, got {other:?}"),
        }
    }
```

(The `addr` helper already exists in this test module — it builds a `SocketAddr` from four octets.)

- [ ] **Step 2: Run it to verify failure**

Run: `cargo test -p yip-rendezvous register_rejects_stale_or_equal_counter`
Expected: FAIL to compile (`is_registered` missing) / then assertion fail.

- [ ] **Step 3: Add the counter to `Reg` and enforce monotonicity**

Add a `last_counter: u64` field to the `Reg` struct:

```rust
struct Reg {
    addr: SocketAddr,
    expiry_ms: u64,
    last_counter: u64,
}
```

Replace the `Message::Register` arm of `handle`:

```rust
            Message::Register { node, counter } => {
                // Reject a stale/replayed registration: the counter must be
                // strictly greater than the last accepted one for this node.
                // (An unknown node is first-seen and always accepted.)
                if let Some(existing) = self.regs.get(&node) {
                    if existing.expiry_ms > now_ms && counter <= existing.last_counter {
                        return Vec::new();
                    }
                }
                if self.regs.len() >= MAX_REGISTRATIONS && !self.regs.contains_key(&node) {
                    return Vec::new(); // at capacity; refuse new ids (existing refresh ok)
                }
                self.regs.insert(
                    node,
                    Reg {
                        addr: src,
                        expiry_ms: now_ms.saturating_add(REG_TTL_MS),
                        last_counter: counter,
                    },
                );
                Vec::new()
            }
```

Add the `is_registered` accessor in the `impl`:

```rust
    /// True iff `node` has a live (unexpired) registration. Used by the TLS
    /// front to distinguish an upgraded tunnel client from a decoy request.
    pub fn is_registered(&self, node: &NodeId, now_ms: u64) -> bool {
        self.regs.get(node).is_some_and(|r| r.expiry_ms > now_ms)
    }
```

- [ ] **Step 4: Run the crate tests to verify they pass**

Run: `cargo test -p yip-rendezvous`
Expected: PASS. (The existing `Register` tests in this module were updated to carry a counter in Task 1 Step 6.)

- [ ] **Step 5: Commit**

```bash
git add crates/yip-rendezvous/src/server.rs
git commit -m "feat(rendezvous): enforce per-node monotonic Register freshness (3c.3)"
```

---

### Task 3: Port `yip-rendezvous` to a tokio runtime (UDP path, behavior-identical)

**Files:**
- Modify: `bin/yip-rendezvous/src/main.rs` (blocking loop → tokio UDP task), `bin/yip-rendezvous/Cargo.toml` (tokio dep)
- Test: the existing `obf_tests` module in `main.rs` stays; behavior verified by the netns relay suite (Task 8 / no-regression).

**Interfaces:**
- Consumes: `RendezvousServer` (now `Arc<Mutex<…>>`-shared), `decode_inbound`/`wrap_reply` (unchanged).
- Produces: an async `run_udp(sock: tokio::net::UdpSocket, server: Arc<Mutex<RendezvousServer>>, obf_key: Option<[u8;16]>, base: Instant)` task; `main` is `#[tokio::main(flavor = "multi_thread")]`.

- [ ] **Step 1: Add tokio to the binary**

In `bin/yip-rendezvous/Cargo.toml` `[dependencies]`:

```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "time", "io-util", "sync"] }
```

- [ ] **Step 2: Convert `main` and the UDP loop to tokio**

Replace the synchronous `main` body (from `let sock = UdpSocket::bind…` onward) so the binary is tokio-driven. Keep `decode_inbound`, `wrap_reply`, `random_pad`, `hex_to_32`, arg parsing, and the `now_ms` closure. New shape:

```rust
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    // ... existing arg parsing produces `listen: String` and
    //     `obf_key: Option<[u8;16]>` exactly as before ...

    let base = Instant::now();
    let server = Arc::new(Mutex::new(RendezvousServer::new(0)));

    let sock = tokio::net::UdpSocket::bind(&listen).await?;
    eprintln!("yip-rendezvous listening on {listen} (udp)");

    run_udp(sock, Arc::clone(&server), obf_key, base).await
}

/// The UDP rendezvous task: recover a Message, drive the shared state machine,
/// send replies. Sweeps on a 5 s interval. Behavior-identical to the previous
/// blocking loop.
async fn run_udp(
    sock: tokio::net::UdpSocket,
    server: Arc<Mutex<RendezvousServer>>,
    obf_key: Option<[u8; 16]>,
    base: Instant,
) -> std::io::Result<()> {
    let now_ms = |base: Instant| -> u64 {
        u64::try_from(base.elapsed().as_millis()).unwrap_or(u64::MAX)
    };
    let mut rx = [0u8; 2048];
    let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        tokio::select! {
            r = sock.recv_from(&mut rx) => {
                let (n, src) = r?;
                if let Some(msg) = decode_inbound(obf_key.as_ref(), &rx[..n]) {
                    let replies = {
                        let mut s = server.lock().await;
                        s.handle(src, msg, now_ms(base))
                    };
                    for (dst, reply) in replies {
                        let wire = wrap_reply(obf_key.as_ref(), &reply);
                        let _ = sock.send_to(&wire, dst).await;
                    }
                }
            }
            _ = sweep.tick() => {
                let mut s = server.lock().await;
                s.sweep(now_ms(base));
                eprintln!("relay-forwarded={}", s.forwarded_count());
            }
        }
    }
}
```

Remove the now-unused `use std::net::UdpSocket;` and the old `set_read_timeout` logic. Keep `SWEEP_INTERVAL` (it is now a `tokio::time::interval` period).

- [ ] **Step 3: Build and run the existing unit tests**

Run: `cargo test -p yip-rendezvous-bin`
Expected: PASS — the `obf_tests` round-trip module is unchanged and still green.

- [ ] **Step 4: Manual smoke — the relay still starts and serves UDP**

Run: `cargo build -p yip-rendezvous-bin && ./target/debug/yip-rendezvous 127.0.0.1:51821 &` then `sleep 1; kill %1`
Expected: prints `yip-rendezvous listening on 127.0.0.1:51821 (udp)` and a `relay-forwarded=0` line, exits cleanly on kill.

- [ ] **Step 5: Commit**

```bash
git add bin/yip-rendezvous/src/main.rs bin/yip-rendezvous/Cargo.toml
git commit -m "refactor(rendezvous): tokio multi-thread runtime; UDP path behavior-identical (3c.3)"
```

---

### Task 4: TCP/TLS listener + CLI flags (real-cert termination, nginx-like config)

**Files:**
- Create: `bin/yip-rendezvous/src/tls_front.rs` (the TLS listener + acceptor builder)
- Modify: `bin/yip-rendezvous/src/main.rs` (new CLI flags; spawn the TLS task), `bin/yip-rendezvous/Cargo.toml` (tokio-boring, boring)
- Test: inline test for the acceptor builder + a localhost TLS-handshake smoke test in `tls_front.rs`

**Interfaces:**
- Consumes: `Arc<Mutex<RendezvousServer>>`, `obf_key`.
- Produces: `pub async fn run_tls_front(listener: tokio::net::TcpListener, acceptor: Arc<boring::ssl::SslAcceptor>, cfg: TlsFrontCfg)`; `pub struct TlsFrontCfg { pub server: Arc<Mutex<RendezvousServer>>, pub obf_key: [u8;16], pub decoy: Option<SocketAddr>, pub base: Instant }`; `pub fn build_acceptor(cert_path: &str, key_path: &str) -> Result<SslAcceptor, ErrorStack>`.

- [ ] **Step 1: Add the TLS deps**

In `bin/yip-rendezvous/Cargo.toml` `[dependencies]`:

```toml
boring = "4.22.0"
tokio-boring = "4.22.0"
```

- [ ] **Step 2: Write the acceptor-builder test**

Create `bin/yip-rendezvous/src/tls_front.rs` with a test that builds an acceptor from a generated self-signed cert (the test writes a temp cert/key with `rcgen`, mirroring `yipd`'s tls.rs test helpers). Add `rcgen = { version = "0.13.2", default-features = false, features = ["ring", "crypto"] }` to `[dev-dependencies]`.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn write_self_signed(dir: &std::path::Path) -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["relay.test".into()]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        (
            cert_path.to_str().unwrap().to_owned(),
            key_path.to_str().unwrap().to_owned(),
        )
    }

    #[test]
    fn build_acceptor_from_pem_succeeds() {
        let dir = std::env::temp_dir().join(format!("yip-rdv-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = write_self_signed(&dir);
        assert!(build_acceptor(&cert, &key).is_ok());
    }
}
```

- [ ] **Step 3: Run it to verify failure**

Run: `cargo test -p yip-rendezvous-bin build_acceptor_from_pem_succeeds`
Expected: FAIL to compile — `build_acceptor` / `tls_front` module not present.

- [ ] **Step 4: Implement the acceptor builder + listener skeleton**

At the top of `tls_front.rs`:

```rust
//! The TCP/TLS Trojan front for the relay (3c.3). Terminates real-cert TLS,
//! trial-reads the first framed message, and routes a fresh obfuscated
//! Register to the tunnel or everything else to the decoy backend.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use boring::error::ErrorStack;
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod};
use tokio::sync::Mutex;
use yip_rendezvous::RendezvousServer;

pub struct TlsFrontCfg {
    pub server: Arc<Mutex<RendezvousServer>>,
    pub obf_key: [u8; 16],
    pub decoy: Option<SocketAddr>,
    pub base: Instant,
}

/// Build a server TLS acceptor from PEM cert-chain + key files, configured to
/// resemble a mainstream web server (mozilla-intermediate profile: TLS 1.3+1.2,
/// standard ciphers, session tickets) with ALPN `h2`,`http/1.1`.
pub fn build_acceptor(cert_path: &str, key_path: &str) -> Result<SslAcceptor, ErrorStack> {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    b.set_certificate_chain_file(cert_path)?;
    b.set_private_key_file(key_path, SslFiletype::PEM)?;
    b.check_private_key()?;
    // ALPN in the conventional browser-server order.
    b.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    Ok(b.build())
}

/// Accept TLS connections forever, spawning one handler task per connection.
pub async fn run_tls_front(
    listener: tokio::net::TcpListener,
    acceptor: Arc<SslAcceptor>,
    cfg: Arc<TlsFrontCfg>,
) {
    loop {
        let (tcp, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("tls-front: accept error: {e}");
                continue;
            }
        };
        let acceptor = Arc::clone(&acceptor);
        let cfg = Arc::clone(&cfg);
        tokio::spawn(async move {
            match tokio_boring::accept(&acceptor, tcp).await {
                Ok(stream) => super::conn::handle_connection(stream, cfg).await,
                Err(e) => eprintln!("tls-front: handshake failed: {e}"),
            }
        });
    }
}
```

(The `handle_connection` referenced here is created in Task 5/6; to keep this task compiling on its own, add a temporary stub in a new `bin/yip-rendezvous/src/conn.rs`: `pub async fn handle_connection(_s: tokio_boring::SslStream<tokio::net::TcpStream>, _cfg: std::sync::Arc<crate::tls_front::TlsFrontCfg>) {}` — Task 5 fills it in.)

- [ ] **Step 5: Wire the CLI flags + spawn the TLS task in `main.rs`**

Add `mod tls_front;` and `mod conn;` near the top of `main.rs`. Extend arg parsing with `--listen-tcp <addr>`, `--tls-cert <path>`, `--tls-key <path>`, `--decoy <addr>` (all `Option<String>`; `--decoy` parsed to `SocketAddr`). Update `usage_exit`. After binding the UDP socket, if `--listen-tcp` is set:

```rust
    // TLS Trojan front (3c.3): opt-in via --listen-tcp. Requires --tls-cert,
    // --tls-key, and (as the discriminator) --obf-psk.
    if let Some(tcp_addr) = listen_tcp {
        let (Some(cert), Some(key)) = (tls_cert.as_deref(), tls_key.as_deref()) else {
            eprintln!("--listen-tcp requires --tls-cert and --tls-key");
            std::process::exit(2);
        };
        let Some(obf_key) = obf_key else {
            eprintln!("--listen-tcp requires --obf-psk (it is the tunnel discriminator)");
            std::process::exit(2);
        };
        let acceptor = Arc::new(
            tls_front::build_acceptor(cert, key)
                .unwrap_or_else(|e| { eprintln!("tls cert/key error: {e}"); std::process::exit(2); }),
        );
        let tcp = tokio::net::TcpListener::bind(&tcp_addr).await?;
        eprintln!("yip-rendezvous TLS front listening on {tcp_addr} (tcp)");
        let cfg = Arc::new(tls_front::TlsFrontCfg {
            server: Arc::clone(&server),
            obf_key,
            decoy: decoy_addr,
            base,
        });
        tokio::spawn(tls_front::run_tls_front(tcp, acceptor, cfg));
    }
```

(Place this before the final `run_udp(...).await`. The UDP task remains the process's main future.)

- [ ] **Step 6: Localhost TLS-handshake smoke test**

Add to `tls_front.rs` tests: bind a `TcpListener` on `127.0.0.1:0`, spawn `run_tls_front` with a dummy cfg (a fresh `RendezvousServer`, zero obf key, `decoy: None`), connect with `tokio-boring`'s client (accept-any-cert verifier), and assert the TLS handshake completes. Model the client setup on `yipd`'s `build_client_connector` (`SslConnector::builder(SslMethod::tls())`, `set_verify(SslVerifyMode::NONE)`). Because `handle_connection` is a stub, the connection completes the handshake then closes — assert `connect(...).await.is_ok()`.

- [ ] **Step 7: Run the tests**

Run: `cargo test -p yip-rendezvous-bin`
Expected: PASS (acceptor build + handshake smoke).

- [ ] **Step 8: Commit**

```bash
git add bin/yip-rendezvous/src/tls_front.rs bin/yip-rendezvous/src/conn.rs bin/yip-rendezvous/src/main.rs bin/yip-rendezvous/Cargo.toml
git commit -m "feat(rendezvous): TCP/TLS front listener + acceptor + CLI flags (3c.3)"
```

---

### Task 5: The discriminator — classify the first framed message

**Files:**
- Modify: `bin/yip-rendezvous/src/conn.rs` (the classifier + the read-first-frame logic)
- Test: inline `#[cfg(test)]` unit tests for the pure classifier

**Interfaces:**
- Consumes: `TlsFrontCfg`, `yip_obf::deobfuscate`, `yip_rendezvous::{decode, Message}`, `RendezvousServer::{handle, is_registered}`.
- Produces: `enum Classify { Upgrade { node: NodeId, reply: Vec<u8> }, Decoy }`; `fn classify_first_frame(buf: &[u8], obf_key: &[u8;16], server: &mut RendezvousServer, src: SocketAddr, now_ms: u64) -> Classify` — a **pure** function (no I/O) that de-frames, deobfuscates, checks for a fresh `Register`, applies it to the server, and returns the framed obf reply to send, or `Decoy`.

- [ ] **Step 1: Write the classifier unit tests**

In `conn.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use yip_rendezvous::{encode, node_id, Message};

    fn framed_register(obf_key: &[u8; 16], node: yip_rendezvous::NodeId, counter: u64) -> Vec<u8> {
        let mut plain = Vec::new();
        encode(&Message::Register { node, counter }, &mut plain);
        let env = yip_obf::obfuscate(obf_key, yip_obf::RDV_TYPE, &plain, 0);
        let mut framed = Vec::new();
        framed.extend_from_slice(&u16::try_from(env.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(&env);
        framed
    }

    #[test]
    fn fresh_register_upgrades() {
        let key = yip_obf::derive_key(&[4u8; 32]);
        let node = node_id(&[1u8; 32]);
        let mut s = RendezvousServer::new(0);
        let frame = framed_register(&key, node, 1);
        let src = "127.0.0.1:9".parse().unwrap();
        match classify_first_frame(&frame, &key, &mut s, src, 0) {
            Classify::Upgrade { node: got, reply } => {
                assert_eq!(got, node);
                assert!(!reply.is_empty());
                assert!(s.is_registered(&node, 0));
            }
            Classify::Decoy => panic!("fresh Register must upgrade"),
        }
    }

    #[test]
    fn http_get_is_decoy() {
        let key = yip_obf::derive_key(&[4u8; 32]);
        let mut s = RendezvousServer::new(0);
        let src = "127.0.0.1:9".parse().unwrap();
        // A censor probe: raw HTTP, no length-prefixed obf envelope.
        let buf = b"GET / HTTP/1.1\r\nHost: relay.test\r\n\r\n";
        assert!(matches!(classify_first_frame(buf, &key, &mut s, src, 0), Classify::Decoy));
    }

    #[test]
    fn wrong_obf_key_is_decoy() {
        let real = yip_obf::derive_key(&[4u8; 32]);
        let attacker = yip_obf::derive_key(&[5u8; 32]);
        let node = node_id(&[1u8; 32]);
        let mut s = RendezvousServer::new(0);
        let frame = framed_register(&attacker, node, 1); // obf'd with the WRONG key
        let src = "127.0.0.1:9".parse().unwrap();
        assert!(matches!(classify_first_frame(&frame, &real, &mut s, src, 0), Classify::Decoy));
    }

    #[test]
    fn stale_replayed_register_is_decoy() {
        let key = yip_obf::derive_key(&[4u8; 32]);
        let node = node_id(&[1u8; 32]);
        let mut s = RendezvousServer::new(0);
        let src = "127.0.0.1:9".parse().unwrap();
        let frame = framed_register(&key, node, 7);
        assert!(matches!(classify_first_frame(&frame, &key, &mut s, src, 0), Classify::Upgrade { .. }));
        // Replaying the identical frame (counter 7) must now be a decoy.
        assert!(matches!(classify_first_frame(&frame, &key, &mut s, src, 1), Classify::Decoy));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-rendezvous-bin classify`
Expected: FAIL to compile (`classify_first_frame`, `Classify` missing).

- [ ] **Step 3: Implement the classifier**

At the top of `conn.rs`:

```rust
//! Per-connection TLS handling for the relay Trojan front (3c.3): classify the
//! first framed message, then either upgrade to a relay tunnel or hand off to
//! the decoy. No `unsafe`; all TLS/socket work is via tokio-boring / tokio.
use std::net::SocketAddr;
use std::sync::Arc;

use yip_rendezvous::{decode, Message, NodeId, RendezvousServer};

use crate::tls_front::TlsFrontCfg;

/// Largest first-frame we will buffer before deciding (a rendezvous Register is
/// tiny; anything larger is a decoy request). Matches yipd's TLS frame cap.
const MAX_FIRST_FRAME: usize = 2048;

/// Result of inspecting a connection's first framed message.
pub enum Classify {
    /// A valid, fresh Register from a client that knows `obf_psk`. `reply` is
    /// the framed obfuscated response to write back before entering the pump.
    Upgrade { node: NodeId, reply: Vec<u8> },
    /// Anything else — proxy this connection to the decoy backend.
    Decoy,
}

/// Pure classification of the first frame. De-frames `[u16 len][obf env]`,
/// deobfuscates with `obf_key` (requiring RDV_TYPE), decodes, and accepts only
/// a fresh `Register` (monotonic counter enforced by `server.handle`).
pub fn classify_first_frame(
    buf: &[u8],
    obf_key: &[u8; 16],
    server: &mut RendezvousServer,
    src: SocketAddr,
    now_ms: u64,
) -> Classify {
    // Length prefix present and plausible?
    let Some(len_bytes) = buf.get(..2) else { return Classify::Decoy };
    let len = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
    if len == 0 || len > MAX_FIRST_FRAME {
        return Classify::Decoy;
    }
    let Some(env) = buf.get(2..2 + len) else { return Classify::Decoy };
    // Deobfuscate; require the rendezvous packet type.
    let Some((ptype, body)) = yip_obf::deobfuscate(obf_key, env) else { return Classify::Decoy };
    if ptype != yip_obf::RDV_TYPE {
        return Classify::Decoy;
    }
    // Must be a Register.
    let Some(Message::Register { node, counter }) = decode(&body) else { return Classify::Decoy };
    // Apply via the state machine, which enforces monotonic freshness. If it
    // did not become registered, it was stale/at-capacity ⇒ decoy.
    server.handle(src, Message::Register { node, counter }, now_ms);
    if !server.is_registered(&node, now_ms) {
        return Classify::Decoy;
    }
    // Build the framed obfuscated ack (an empty-payload Register echo is
    // enough for 3c.3; 3c.4's client only needs to see a well-formed reply).
    let reply = crate::frame_obf(obf_key, &Message::Register { node, counter });
    Classify::Upgrade { node, reply }
}
```

Add a small shared framing helper in `main.rs` (used by both classifier and pump), next to `wrap_reply`:

```rust
/// Frame a rendezvous Message for the TLS byte-stream: `[u16 BE len][obf env]`.
pub(crate) fn frame_obf(obf_key: &[u8; 16], msg: &Message) -> Vec<u8> {
    let mut plain = Vec::new();
    encode(msg, &mut plain);
    let env = yip_obf::obfuscate(obf_key, yip_obf::RDV_TYPE, &plain, random_pad(OBF_PAD_MAX));
    let mut out = Vec::with_capacity(2 + env.len());
    let len = u16::try_from(env.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&env);
    out
}
```

- [ ] **Step 4: Run the classifier tests**

Run: `cargo test -p yip-rendezvous-bin classify`
Expected: PASS (all four classifier cases).

- [ ] **Step 5: Commit**

```bash
git add bin/yip-rendezvous/src/conn.rs bin/yip-rendezvous/src/main.rs
git commit -m "feat(rendezvous): first-frame discriminator (fresh obf Register vs decoy) (3c.3)"
```

---

### Task 6: Connection handler — trial-read + decoy handoff

**Files:**
- Modify: `bin/yip-rendezvous/src/conn.rs` (`handle_connection`, `read_first_frame`, `into_decoy`)
- Test: a localhost integration test (real TLS + a stub decoy TCP server) asserting a probe reaches the decoy

**Interfaces:**
- Consumes: `classify_first_frame` (Task 5), `TlsFrontCfg`.
- Produces: `pub async fn handle_connection(stream: tokio_boring::SslStream<tokio::net::TcpStream>, cfg: Arc<TlsFrontCfg>)`; on `Decoy`, connects to `cfg.decoy` and `copy_bidirectional` after replaying buffered bytes; on `Upgrade`, calls `run_tunnel` (Task 7).

- [ ] **Step 1: Write the decoy-handoff integration test**

In `conn.rs` tests, add an async test (needs `#[tokio::test]`): start a stub "decoy" TCP server on `127.0.0.1:0` that reads the incoming request and replies `HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi`. Stand up `run_tls_front` with `decoy: Some(stub_addr)` and `obf_key = derive_key(&[4u8;32])`. Connect a TLS client (accept-any-cert), send a raw `GET / HTTP/1.1\r\n\r\n`, and assert the client reads back `...200 OK...hi` — proving a probe was transparently proxied to the decoy.

```rust
    #[tokio::test]
    async fn probe_is_proxied_to_decoy() {
        // (full setup: spawn stub decoy, spawn run_tls_front with a self-signed
        // cert + decoy addr, connect TLS client, send GET, assert 200 OK body)
        // See build_acceptor test for the self-signed cert helper and
        // yipd tls.rs for the accept-any-cert client connector pattern.
    }
```

Write the full body following the acceptor test's cert helper and a tokio-boring client connector with `SslVerifyMode::NONE`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-rendezvous-bin probe_is_proxied_to_decoy`
Expected: FAIL — `handle_connection` is still the empty stub.

- [ ] **Step 3: Implement `handle_connection` + decoy handoff**

Replace the stub in `conn.rs`:

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Short budget to decide tunnel-vs-decoy. NOT a connection lifetime: on the
/// decoy path we hand the stream to the backend and let ITS idle timeout
/// govern, so this classification window is never an observable close signature.
const CLASSIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

pub async fn handle_connection(
    mut stream: tokio_boring::SslStream<TcpStream>,
    cfg: Arc<TlsFrontCfg>,
) {
    let now_ms = u64::try_from(cfg.base.elapsed().as_millis()).unwrap_or(u64::MAX);
    // The relay is blind to the real TCP peer identity; use a fixed synthetic
    // src for state-machine rate-limiting/registration keying on this path.
    let src: SocketAddr = "0.0.0.0:0".parse().expect("valid addr");

    let mut buf = Vec::new();
    let decision = read_and_classify(&mut stream, &cfg, &mut buf, src, now_ms).await;

    match decision {
        Some(Classify::Upgrade { node, reply }) => {
            if stream.write_all(&reply).await.is_err() {
                return;
            }
            super::conn_tunnel::run_tunnel(stream, cfg, node).await;
        }
        _ => into_decoy(stream, &cfg, buf).await,
    }
}

/// Read the first frame (up to CLASSIFY_TIMEOUT) and classify it. Returns
/// `None` on idle-timeout/read-error (caller treats as decoy). All bytes read
/// are accumulated in `buf` so they can be replayed to the decoy.
async fn read_and_classify(
    stream: &mut tokio_boring::SslStream<TcpStream>,
    cfg: &TlsFrontCfg,
    buf: &mut Vec<u8>,
    src: SocketAddr,
    now_ms: u64,
) -> Option<Classify> {
    let deadline = tokio::time::sleep(CLASSIFY_TIMEOUT);
    tokio::pin!(deadline);
    let mut chunk = [0u8; 2048];
    loop {
        // Enough to read the length prefix and the full framed body?
        if buf.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
            if len > 0 && len <= MAX_FIRST_FRAME && buf.len() >= 2 + len {
                let mut server = cfg.server.lock().await;
                return Some(classify_first_frame(buf, &cfg.obf_key, &mut server, src, now_ms));
            }
            if len == 0 || len > MAX_FIRST_FRAME {
                return Some(Classify::Decoy); // implausible length ⇒ decoy now
            }
        }
        tokio::select! {
            _ = &mut deadline => return None, // idle ⇒ decoy (empty/partial buf)
            r = stream.read(&mut chunk) => match r {
                Ok(0) => return Some(Classify::Decoy), // peer closed
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => return Some(Classify::Decoy),
            },
        }
    }
}

/// Proxy this connection to the decoy backend: replay the buffered bytes, then
/// splice bidirectionally. The decoy's own behavior/timing governs from here.
async fn into_decoy(
    mut stream: tokio_boring::SslStream<TcpStream>,
    cfg: &TlsFrontCfg,
    buffered: Vec<u8>,
) {
    let Some(decoy_addr) = cfg.decoy else {
        // No decoy configured: minimal static fallback (documented weaker path).
        let page = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 40\r\nConnection: close\r\n\r\n<!doctype html><title>OK</title><p>OK</p>";
        let _ = stream.write_all(page).await;
        return;
    };
    let Ok(mut backend) = TcpStream::connect(decoy_addr).await else { return };
    if !buffered.is_empty() && backend.write_all(&buffered).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut backend).await;
}
```

(Add `mod conn_tunnel;` in `main.rs`; create `bin/yip-rendezvous/src/conn_tunnel.rs` with a temporary stub `pub async fn run_tunnel(_s: tokio_boring::SslStream<tokio::net::TcpStream>, _cfg: std::sync::Arc<crate::tls_front::TlsFrontCfg>, _node: yip_rendezvous::NodeId) {}` — Task 7 fills it in.)

- [ ] **Step 4: Run the decoy test**

Run: `cargo test -p yip-rendezvous-bin probe_is_proxied_to_decoy`
Expected: PASS — the probe's `GET /` is proxied and the `200 OK` body comes back.

- [ ] **Step 5: Commit**

```bash
git add bin/yip-rendezvous/src/conn.rs bin/yip-rendezvous/src/conn_tunnel.rs bin/yip-rendezvous/src/main.rs
git commit -m "feat(rendezvous): trial-read + decoy reverse-proxy handoff (3c.3)"
```

---

### Task 7: Active tunnel path — TLS registration + relay routing

**Files:**
- Create: `bin/yip-rendezvous/src/conn_tunnel.rs` (the upgraded-client pump)
- Modify: `crates/yip-rendezvous/src/server.rs` (a TLS writer-channel registry keyed by `NodeId`), `bin/yip-rendezvous/src/conn.rs` (unchanged call site)
- Test: an integration test — two TLS clients register and relay a payload A→B over TLS

**Interfaces:**
- Consumes: `Classify::Upgrade`, `frame_obf`, `RendezvousServer`.
- Produces: `pub async fn run_tunnel(stream, cfg, node)`; a per-connection `tokio::sync::mpsc` sender registered in a shared `TlsRoutes` map (`Arc<Mutex<HashMap<NodeId, mpsc::Sender<Vec<u8>>>>>` added to `TlsFrontCfg`) so `RelaySend{dst}` to a TLS-connected peer is delivered by pushing a framed `RelayDeliver` to `dst`'s channel.

- [ ] **Step 1: Add the TLS route registry to `TlsFrontCfg`**

In `tls_front.rs`, add to `TlsFrontCfg`:

```rust
    pub routes: Arc<Mutex<std::collections::HashMap<yip_rendezvous::NodeId, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
```

Initialize it (`Arc::new(Mutex::new(HashMap::new()))`) where `TlsFrontCfg` is built in `main.rs`.

- [ ] **Step 2: Write the A→B relay-over-TLS integration test**

In `conn_tunnel.rs` tests (`#[tokio::test]`): stand up the TLS front (obf key set, no decoy needed), connect two TLS clients A and B, each sends a framed `Register` (counter 1) and stays connected. Then A sends a framed `RelaySend { src: A, dst: B, payload: b"hello" }`; assert B reads a framed `RelayDeliver { src: A, payload: b"hello" }`. Use `frame_obf` to build frames and `deobfuscate` + `decode` to parse B's received frame.

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p yip-rendezvous-bin relay_over_tls`
Expected: FAIL — `run_tunnel` is the stub; no routing.

- [ ] **Step 4: Implement `run_tunnel`**

```rust
//! The upgraded-client pump for a TLS-connected relay peer (3c.3): register a
//! delivery channel by NodeId, then read framed obf messages and route
//! RelaySend to the destination's UDP addr or TLS channel.
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use yip_rendezvous::{decode, Message, NodeId};

use crate::tls_front::TlsFrontCfg;

const CHANNEL_DEPTH: usize = 64;

pub async fn run_tunnel(
    mut stream: tokio_boring::SslStream<TcpStream>,
    cfg: Arc<TlsFrontCfg>,
    node: NodeId,
) {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
    cfg.routes.lock().await.insert(node, tx);

    let mut read_buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        tokio::select! {
            // Deliveries destined for THIS peer (framed already).
            Some(frame) = rx.recv() => {
                if stream.write_all(&frame).await.is_err() { break; }
            }
            r = stream.read(&mut chunk) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    read_buf.extend_from_slice(&chunk[..n]);
                    if !drain_frames(&mut read_buf, &cfg, node).await { break; }
                }
            },
        }
    }
    cfg.routes.lock().await.remove(&node);
}

/// Parse and act on every complete `[u16 len][obf Message]` frame in `buf`.
/// Returns false on a fail-closed condition (malformed frame ⇒ tear down).
async fn drain_frames(buf: &mut Vec<u8>, cfg: &TlsFrontCfg, _self_node: NodeId) -> bool {
    loop {
        if buf.len() < 2 { return true; }
        let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
        if len == 0 || len > 2048 { return false; }
        if buf.len() < 2 + len { return true; }
        let env: Vec<u8> = buf[2..2 + len].to_vec();
        buf.drain(..2 + len);
        let Some((pt, body)) = yip_obf::deobfuscate(&cfg.obf_key, &env) else { return false };
        if pt != yip_obf::RDV_TYPE { return false; }
        let Some(msg) = decode(&body) else { return false };
        route(msg, cfg).await;
    }
}

/// Route one decoded message from a TLS-connected peer.
async fn route(msg: Message, cfg: &TlsFrontCfg) {
    if let Message::RelaySend { src, dst, payload } = msg {
        let deliver = Message::RelayDeliver { src, payload };
        // Prefer a TLS-connected destination; the framed delivery goes on its
        // channel. (UDP-connected destinations are served by the UDP task via
        // the shared RendezvousServer; a future refinement can bridge here.)
        let frame = crate::frame_obf(&cfg.obf_key, &deliver);
        if let Some(tx) = cfg.routes.lock().await.get(&dst) {
            let _ = tx.send(frame).await;
        }
    }
    // Register refreshes and other control messages on an established tunnel
    // are handled by the shared state machine in a later refinement; 3c.3's
    // money path is RelaySend A->B over TLS.
}
```

- [ ] **Step 5: Run the relay test**

Run: `cargo test -p yip-rendezvous-bin relay_over_tls`
Expected: PASS — B receives A's relayed payload.

- [ ] **Step 6: Commit**

```bash
git add bin/yip-rendezvous/src/conn_tunnel.rs bin/yip-rendezvous/src/tls_front.rs bin/yip-rendezvous/src/main.rs
git commit -m "feat(rendezvous): TLS tunnel registration + RelaySend routing (3c.3)"
```

---

### Task 8: Probe-resistance oracle (netns money test)

**Files:**
- Create: `bin/yipd/tests/run-netns-reality-probe.sh` (the probe-resistance money test), and a harness test in `bin/yipd/tests/tunnel_netns.rs`
- Modify: `.github/workflows/integration.yml` (run the new oracle under sudo)

**Interfaces:**
- Consumes: the `yip-rendezvous` binary with `--listen-tcp`, a local decoy server (python3 `http.server` or a bundled static file server), `openssl`/`rcgen`-made test cert.

- [ ] **Step 1: Write the money-test script**

`run-netns-reality-probe.sh <yip-rendezvous-binary>`: in a netns, generate a self-signed cert for `relay.test`, start a trivial decoy HTTP server on `127.0.0.1:8080` (`python3 -m http.server 8080` serving a temp dir with an `index.html`), start `yip-rendezvous 0.0.0.0:51821 --listen-tcp 0.0.0.0:8443 --tls-cert … --tls-key … --decoy 127.0.0.1:8080 --obf-psk <hex64>`. Then assert:
  - **Probe → decoy:** `curl -sk https://127.0.0.1:8443/` returns the decoy `index.html` body. `[PASS]`.
  - **Garbage → decoy:** `printf '\x00\x01\x02' | openssl s_client -quiet -connect 127.0.0.1:8443` does not hang past the decoy timeout and yields no rendezvous bytes.
  - **Timing parity:** an idle TLS connection is NOT closed at ~3 s (assert the socket stays open ≥5 s — the decoy governs).
Mirror `run-quic-mimicry-oracle.sh`'s root-gated SKIP + cleanup structure. (Spec §7's "nDPI classifies as TLS/HTTPS" check is trivially satisfied here — the relay presents a *real* CA-style cert with a real SNI, unlike 3c.2's fake-SNI costume — so no separate nDPI capture arm is added; the novel, testable property is probe→decoy, which this script gates.)

- [ ] **Step 2: Write the harness test**

In `tunnel_netns.rs`, add `reality_probe_serves_decoy` (root-gated like `quic_classified_as_quic`) that builds `yip-rendezvous-bin` and runs the script, asserting exit 0.

- [ ] **Step 3: Run the oracle locally**

Run: `cargo build -p yip-rendezvous-bin && sudo bash bin/yipd/tests/run-netns-reality-probe.sh ./target/debug/yip-rendezvous`
Expected: `[PASS]` on probe→decoy, garbage→decoy, timing-parity.

- [ ] **Step 4: Wire into CI**

Add a step to the `dpi-undetectability` job (which already installs cmake + builds under sudo) running the new script; honesty-guard on `^SKIP`/`[FAIL]` exactly like the QUIC oracle step.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/tests/run-netns-reality-probe.sh bin/yipd/tests/tunnel_netns.rs .github/workflows/integration.yml
git commit -m "test(rendezvous): active-probe-resistance oracle (probe->decoy, timing parity) (3c.3)"
```

---

### Task 9: Docs — relay TLS front + config

**Files:**
- Modify: `docs/configuration.md`, `CHANGELOG.md`, and the `yip-rendezvous` usage string (already updated in Task 4)

- [ ] **Step 1: Document the relay TLS front**

In `docs/configuration.md`, add a subsection under the rendezvous/relay docs describing `--listen-tcp`, `--tls-cert`, `--tls-key`, `--decoy`, that `--obf-psk` is required with `--listen-tcp` (it is the discriminator), the `rendezvous = "tls://host:443"` client scheme (noting the client dialer ships in 3c.4), and the threat boundary (probe-resistance == `obf_psk` secrecy; #37 is the durable fix; replay horizon = 60 s TTL).

- [ ] **Step 2: CHANGELOG entry**

Add an `### Added` entry: "REALITY-style Trojan relay front (anti-DPI 3c.3): `yip-rendezvous` gains an opt-in TCP/TLS/443 listener (`--listen-tcp`/`--tls-cert`/`--tls-key`/`--decoy`) that terminates real-cert TLS and routes a fresh obfuscated `Register` to the relay tunnel while reverse-proxying every other connection (active probes, scanners) to a real decoy site — so the relay is indistinguishable from an ordinary HTTPS server. tokio runtime added to `yip-rendezvous` (control tier only; the `yipd` data plane stays async-free). The `yipd` TLS-relay-dial client is 3c.4."

- [ ] **Step 3: Commit**

```bash
git add docs/configuration.md CHANGELOG.md
git commit -m "docs(rendezvous): document the 3c.3 relay TLS front + threat model"
```

---

### Task 10: No-regression sweep

**Files:** none expected (verification; fix in place if a regression appears).

- [ ] **Step 1: Full workspace tests** — `cargo test --workspace` → 0 failures.
- [ ] **Step 2: Strict clippy** — `cargo clippy --workspace --all-targets -- -D warnings` → clean.
- [ ] **Step 3: UDP rendezvous unchanged** — run the existing relay/discovery netns cases under both drivers: `relay_path_ping`, `hole_punch_ping`, `discovery_dynamic_ping`, `relay_path_ping_obfuscated` (root, via the compiled `tunnel_netns` binary). All PASS — the tokio port is behavior-preserving and `--listen-tcp` absent means no TCP front.
- [ ] **Step 4: Commit** any regression fix (else skip).

---

## Notes for the executor

- **Mirror existing patterns.** The obf framing (`[u16 len][obf env]`) is exactly 3c.2's `tls.rs` framing + `yip-obf`'s `RDV_TYPE` envelope already used by the UDP relay. The TLS acceptor/connector patterns mirror `yipd`'s `bin/yipd/src/tls.rs` (`build_client_connector`, `SslVerifyMode::NONE` for test clients). The netns oracle mirrors `run-quic-mimicry-oracle.sh`.
- **tokio stays on this tier only.** Do not let any tokio type cross into `yipd`/`yip-io`/`yip-transport`. If a shared helper is tempting, duplicate it in `yip-rendezvous` instead.
- **The relay is blind.** `run_tunnel` never inspects inner tunnel plaintext — it routes `RelaySend`/`RelayDeliver` envelopes only. Peers run Noise-IK end-to-end over the relayed payload.
- **Decoy timing is load-bearing.** Never impose a relay-specific close on the decoy path; hand off and let the backend govern (Task 6). The classification timeout only bounds the upgrade decision.
- **3c.4 depends on the frozen wire contract** (spec §5.3): `[u16 BE len][ obf(RDV_TYPE, Register{node,counter}) ]` first, monotonic `counter`, browser-parrot ClientHello. Do not change it here without updating the spec.
