# Anti-DPI 3c.4 — TLS relay-dial client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `yipd` a `rendezvous = "tls://host:443"` mode that reaches the 3c.3 relay over a persistent browser-parrot TLS connection (a dedicated thread), so two UDP-blocked peers tunnel through the relay — the inner Noise/FEC/AEAD protocol unchanged, carried as the relayed payload.

**Architecture:** A dedicated `std::thread` (the *relay client*) owns one TLS connection to the relay (reusing 3c.2's `run_tls` client), sends the obfuscated monotonic-`counter` `Register` first-on-connect + keepalive, and pipes obf-wrapped `RelaySend`/`RelayDeliver` envelopes to/from the data plane over a `UnixStream` socketpair. A sibling data-plane loop `run_relay_tls` (like `run_quic`/`run_tls`) drives `PeerManager` over `Epoll(tun_fd, socketpair_fd)`. `PeerManager` addresses the relay as a `SocketAddr` routing key; a relay-only path mode skips Direct/UDP-punch.

**Tech Stack:** Rust, `boring` (BoringSSL, from 3c.2), `yip_io::epoll::Epoll`, `std::os::unix::net::UnixStream` (safe socketpair), `yip_rendezvous` codec, `yip-obf`.

## Global Constraints

- `#![forbid(unsafe_code)]` in `yipd` — all `unsafe` stays in `yip-io`/deps. Use `UnixStream::pair()` (safe std) for the socketpair; no eventfd/libc.
- **No tokio.** The relay client is a plain `std::thread`; the data plane stays the bespoke epoll loop. This is a hard non-goal.
- No `as` numeric casts except enum discriminants / libc-ABI — use `try_from`. No bare `#[allow]` — use `#[expect(reason = "...")]`.
- **Inner protocol unchanged**: Noise-IK, FEC, AEAD, cert admission, rekey are byte-for-byte the raw-path logic. 3c.4 touches only config, the `Rendezvous` trait/impl, the path SM, and the new transport loop/thread.
- **Opt-in, default byte-identical**: `rendezvous` absent or `<ip:port>` ⇒ no relay thread, no TLS — exactly today's 2b behavior.
- `rendezvous = tls://` **requires `obf_psk`** (the relay discriminator) and **forces the poll driver** (consistent with `transport=quic`/`tls`).
- Reuse 3c.2's `bin/yipd/src/tls.rs` client primitives (`build_client_connector`, `drive_handshake`, `FrameReader`, `frame_datagram`, `HANDSHAKE_TIMEOUT`, backoff consts) — do not re-implement TLS.

---

### Task 1: Config — `Rendezvous` enum, `tls://` parse, `obf_psk`-required

**Files:**
- Modify: `bin/yipd/src/config.rs` (the `rendezvous` field + parse + the load-time check)
- Test: inline `#[cfg(test)]` in `config.rs`

**Interfaces:**
- Produces: `pub enum Rendezvous { Udp(SocketAddr), Tls { host: String, port: u16 } }`; `Config.rendezvous: Option<Rendezvous>`. `tls://host:port` ⇒ `Tls`; a bare `ip:port` ⇒ `Udp`. `Tls` without `obf_psk` set ⇒ load error.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn parses_tls_rendezvous_scheme() {
        let cfg = Config::parse(
            "local_private=aa..\nlocal_public=bb..\nlisten=0.0.0.0:51820\ndevice=yip0\n\
             obf_psk=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
             rendezvous=tls://relay.example.com:443\n[peer]\npublic_key=cc..\n",
        )
        .unwrap();
        assert!(matches!(
            cfg.rendezvous,
            Some(Rendezvous::Tls { ref host, port }) if host == "relay.example.com" && port == 443
        ));
    }

    #[test]
    fn tls_rendezvous_without_obf_psk_is_error() {
        let err = Config::parse(
            "local_private=aa..\nlocal_public=bb..\nlisten=0.0.0.0:51820\ndevice=yip0\n\
             rendezvous=tls://relay.example.com:443\n[peer]\npublic_key=cc..\n",
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn parses_udp_rendezvous_unchanged() {
        let cfg = Config::parse(
            "local_private=aa..\nlocal_public=bb..\nlisten=0.0.0.0:51820\ndevice=yip0\n\
             rendezvous=203.0.113.9:51821\n[peer]\npublic_key=cc..\n",
        )
        .unwrap();
        assert!(matches!(cfg.rendezvous, Some(Rendezvous::Udp(_))));
    }
```

(Use the real hex fixtures the other config tests use for `local_private`/`public`/`public_key` — copy an existing passing test's values; the `aa..` above is shorthand.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --bin yipd config:: 2>&1 | grep -E "tls_rendezvous|udp_rendezvous"`
Expected: FAIL to compile (`Rendezvous` enum missing).

- [ ] **Step 3: Add the enum and change the field**

Add near the other config types in `config.rs`:

```rust
/// Where and how to reach the rendezvous+relay server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rendezvous {
    /// Plain UDP rendezvous (2b), `rendezvous=<ip:port>`.
    Udp(SocketAddr),
    /// TLS relay-dial (3c.4), `rendezvous=tls://host:port`.
    Tls { host: String, port: u16 },
}
```

Change the field: `pub rendezvous: Option<Rendezvous>,`.

- [ ] **Step 4: Parse both forms**

Replace the `"rendezvous"` parse arm:

```rust
                "rendezvous" => {
                    rendezvous = Some(if let Some(rest) = val.strip_prefix("tls://") {
                        let (host, port_str) = rest.rsplit_once(':').ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "tls:// rendezvous must be tls://host:port",
                            )
                        })?;
                        let port = port_str.parse::<u16>().map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?;
                        Rendezvous::Tls { host: host.to_owned(), port }
                    } else {
                        Rendezvous::Udp(val.parse::<SocketAddr>().map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?)
                    });
                }
```

Change the local `let mut rendezvous: Option<Rendezvous> = None;`.

- [ ] **Step 5: Enforce `obf_psk` required for TLS**

Where the config is finalized (after parsing, near the other cross-field validations — find the block that returns the assembled `Config`), add:

```rust
        if matches!(rendezvous, Some(Rendezvous::Tls { .. })) && obf_psk.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rendezvous=tls:// requires obf_psk (it is the relay's discriminator)",
            ));
        }
```

- [ ] **Step 6: Run the tests + build the workspace**

Run: `cargo test -p yipd --bin yipd config::`
Expected: PASS. Then `cargo build --workspace` — the `Config.rendezvous` type change will break `tunnel.rs`'s use site (which maps `config.rendezvous` to `ConfiguredServerRendezvous::new(addr)`); fix that call site to match on `Rendezvous::Udp(addr) => …` for now and leave a `Rendezvous::Tls { .. } => todo!("3c.4 Task 6")` arm (Task 6 replaces it). The workspace must build.

- [ ] **Step 7: Commit**

```bash
git add bin/yipd/src/config.rs bin/yipd/src/tunnel.rs
git commit -m "feat(yipd): rendezvous Rendezvous enum + tls:// parse + obf_psk-required (3c.4)"
```

---

### Task 2: `Rendezvous::register()` → `Option` + `TlsRelayRendezvous` impl

**Files:**
- Modify: `bin/yipd/src/rendezvous.rs` (trait + new impl), `bin/yipd/src/peer_manager.rs` (the one `register()` call site)
- Test: inline `#[cfg(test)]` in `rendezvous.rs`

**Interfaces:**
- Produces: `Rendezvous::register(&mut self, node) -> Option<EgressDatagram>` (None ⇒ caller sends no register — the relay thread owns it). New `pub struct TlsRelayRendezvous { relay_addr: SocketAddr }` whose `register()` returns `None`, `relay()`/`parse()`/`server_addr()` behave like `ConfiguredServerRendezvous`, and `lookup()` is never called on the straight-to-relay path.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn tls_relay_register_is_none_but_relay_works() {
        let addr: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let mut r = TlsRelayRendezvous::new(addr);
        let n = node_id(&[7u8; 32]);
        assert!(r.register(n).is_none(), "thread owns Register on the TLS path");
        let dg = r.relay(node_id(&[1u8; 32]), n, b"payload");
        assert_eq!(dg.dst, addr, "relay egress is addressed to the relay");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --bin yipd tls_relay_register`
Expected: FAIL to compile.

- [ ] **Step 3: Change the trait + update `ConfiguredServerRendezvous` + the call site**

In `rendezvous.rs`, change the trait method:

```rust
    /// Emit a registration datagram, or `None` if registration is handled
    /// elsewhere (the 3c.4 relay thread sends `Register` itself). UDP impls
    /// return `Some`.
    fn register(&mut self, node: NodeId) -> Option<EgressDatagram>;
```

Update `ConfiguredServerRendezvous::register` to wrap its result in `Some(...)`.

In `peer_manager.rs` (the tick call site, ~line 1902-1903):

```rust
            if let Some(r) = self.rendezvous.as_mut() {
                if let Some(dg) = r.register(node) {
                    self.tick_egress.push(dg);
                }
            }
```

- [ ] **Step 4: Add `TlsRelayRendezvous`**

In `rendezvous.rs`:

```rust
/// The 3c.4 relay-dial client's `Rendezvous` view: `Register` is owned by the
/// relay thread (so `register` is `None`), and `relay`/`parse` behave exactly
/// like the UDP impl but addressed at the relay's routing-key `SocketAddr`.
pub struct TlsRelayRendezvous {
    relay_addr: SocketAddr,
}

impl TlsRelayRendezvous {
    pub fn new(relay_addr: SocketAddr) -> Self {
        Self { relay_addr }
    }
    fn to_server(&self, msg: &Message) -> EgressDatagram {
        let mut bytes = Vec::new();
        encode(msg, &mut bytes);
        EgressDatagram { fate: 0, dst: self.relay_addr, bytes }
    }
}

impl Rendezvous for TlsRelayRendezvous {
    fn register(&mut self, _node: NodeId) -> Option<EgressDatagram> {
        None // the relay thread owns Register (first-on-connect + keepalive)
    }
    fn lookup(&mut self, _node: NodeId) -> EgressDatagram {
        // Never called on the straight-to-relay path (no hole-punch). Kept a
        // harmless server-addressed no-op rather than `unreachable!` so a stray
        // call can never panic the data plane.
        self.to_server(&Message::Lookup { node: [0u8; 16] })
    }
    fn relay(&mut self, src: NodeId, dst: NodeId, payload: &[u8]) -> EgressDatagram {
        self.to_server(&Message::RelaySend { src, dst, payload: payload.to_vec() })
    }
    fn parse(&self, dg: &[u8]) -> RdvEvent {
        // Same decode as ConfiguredServerRendezvous — factor a shared free fn if
        // ConfiguredServerRendezvous::parse is non-trivial; else inline the
        // `decode(dg)` → RdvEvent mapping identically.
        ConfiguredServerRendezvous::new(self.relay_addr).parse(dg)
    }
    fn server_addr(&self) -> SocketAddr {
        self.relay_addr
    }
}
```

(If `ConfiguredServerRendezvous::parse` holds no state, calling it as above is fine; otherwise extract the decode into a `fn parse_rdv(dg: &[u8]) -> RdvEvent` shared by both impls.)

- [ ] **Step 5: Run tests + build**

Run: `cargo test -p yipd --bin yipd rendezvous:: tls_relay_register` then `cargo build --workspace`.
Expected: PASS + clean build (the `register()` → `Option` change compiles everywhere).

- [ ] **Step 6: Commit**

```bash
git add bin/yipd/src/rendezvous.rs bin/yipd/src/peer_manager.rs
git commit -m "feat(yipd): Rendezvous::register->Option + TlsRelayRendezvous (thread owns Register) (3c.4)"
```

---

### Task 3: Path SM — relay-only "start in Relay" mode

**Files:**
- Modify: `bin/yipd/src/path.rs` (a relay-only constructor/flag), `bin/yipd/src/peer_manager.rs` (pass it when rendezvous is TLS)
- Test: inline `#[cfg(test)]` in `path.rs`

**Interfaces:**
- Produces: `PathState::relay_only(now_ms)` — starts in `PathStage::Relaying` and `advance()` returns `PathAction::Relay` forever (never Direct/Punch). Existing enums: `PathStage { Direct, Punching, Relaying, Failed }`, `PathAction { …, Relay, … }`; existing methods `stage() -> PathStage`, `enter(stage, now_ms)`, `advance(now_ms) -> PathAction`.

- [ ] **Step 1: Write the failing test** (in `path.rs`'s test module)

```rust
    #[test]
    fn relay_only_starts_and_stays_in_relay() {
        let mut p = PathState::relay_only(0);
        assert_eq!(p.stage(), PathStage::Relaying, "relay-only starts in Relaying");
        for t in [1_000, 5_000, 30_000, 120_000] {
            assert_eq!(p.advance(t), PathAction::Relay, "relay-only stays Relay (t={t})");
            assert_eq!(p.stage(), PathStage::Relaying);
        }
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --bin yipd relay_only_starts_and_stays_in_relay`
Expected: FAIL to compile (`relay_only` missing).

- [ ] **Step 3: Add a `relay_only` field + constructor + `advance` short-circuit**

Add `relay_only: bool` to the `PathState` struct (default `false` in `new`). Add the constructor:

```rust
    /// A path that goes straight to Relay and never attempts Direct/UDP-punch —
    /// used by the `rendezvous=tls://` client (3c.4), where UDP (hence Direct
    /// and hole-punch) is blocked, so relaying from the first packet is correct
    /// and avoids the ~8 s of failing Direct/Punch windows.
    pub fn relay_only(now_ms: u64) -> Self {
        let mut s = Self::new(false, true, now_ms);
        s.enter(PathStage::Relaying, now_ms);
        s.relay_only = true;
        s
    }
```

At the top of `advance`, short-circuit:

```rust
    pub fn advance(&mut self, now_ms: u64) -> PathAction {
        if self.relay_only {
            return PathAction::Relay;
        }
        // ... existing body unchanged ...
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p yipd --bin yipd relay_only_starts_and_stays_in_relay`
Expected: PASS.

- [ ] **Step 5: Wire it in `peer_manager.rs`**

Where peers' `PathState` is constructed (the `PathState::new(...)` sites at ~line 394 and ~468), when the configured rendezvous is the TLS relay use `PathState::relay_only(now_ms)` instead. Thread a `relay_only: bool` (derived from the injected rendezvous kind, or a `PeerManager` field set at construction) to those sites. Keep the UDP path using `PathState::new(...)` unchanged.

- [ ] **Step 6: Run path + peer_manager tests + build**

Run: `cargo test -p yipd --bin yipd path:: relay_only` then `cargo build --workspace`.
Expected: PASS. UDP-path peer tests unchanged.

- [ ] **Step 7: Commit**

```bash
git add bin/yipd/src/path.rs bin/yipd/src/peer_manager.rs
git commit -m "feat(yipd): relay-only path mode (start in Relay, skip Direct/punch) for tls:// (3c.4)"
```

---

### Task 4: `relay_client` framing + `Register` construction (pure, unit-tested)

**Files:**
- Create: `bin/yipd/src/relay_client.rs` (the pure helpers; the thread itself is Task 5)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces: `pub(crate) fn build_register(obf_key: &[u8;16], node: NodeId, counter: u64) -> Vec<u8>` — the framed `[u16 BE len][ obf(RDV_TYPE, Register{node,counter}) ]` bytes to write to TLS; a `Counter` helper (`fn next(&mut self) -> u64`, monotonic from 1). Reuse `crate::tls::{frame_datagram, FrameReader}` for the TLS framing (do NOT re-implement).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_frame_deobfuscates_to_fresh_register() {
        let key = yip_obf::derive_key(&[9u8; 32]);
        let node = yip_rendezvous::node_id(&[1u8; 32]);
        let framed = build_register(&key, node, 1);
        // Strip the [u16 len] TLS frame, then deobf + decode.
        let mut r = crate::tls::FrameReader::default();
        r.push(&framed);
        let env = r.next().unwrap().unwrap();
        let (pt, body) = yip_obf::deobfuscate(&key, &env).unwrap();
        assert_eq!(pt, yip_obf::RDV_TYPE);
        assert_eq!(
            yip_rendezvous::decode(&body),
            Some(yip_rendezvous::Message::Register { node, counter: 1 })
        );
    }

    #[test]
    fn counter_is_monotonic_from_one() {
        let mut c = Counter::default();
        assert_eq!(c.next(), 1);
        assert_eq!(c.next(), 2);
        assert_eq!(c.next(), 3);
    }
}
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement**

```rust
//! The 3c.4 TLS relay-dial client: a dedicated thread holds one browser-parrot
//! TLS connection to the relay, sends the obfuscated monotonic `Register`
//! (first-on-connect + keepalive), and pipes obf-wrapped RelaySend/RelayDeliver
//! envelopes to/from the data plane over a UnixStream socketpair. No tokio; all
//! TLS via 3c.2's `crate::tls` client primitives.
use yip_rendezvous::{encode, node_id, Message, NodeId};

/// Per-boot monotonic Register counter (starts at 1; the relay's freshness gate
/// requires strictly-greater).
#[derive(Default)]
pub(crate) struct Counter(u64);
impl Counter {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }
}

/// Build the framed `[u16 len][obf(RDV_TYPE, Register{node,counter})]` bytes.
pub(crate) fn build_register(obf_key: &[u8; 16], node: NodeId, counter: u64) -> Vec<u8> {
    let mut plain = Vec::new();
    encode(&Message::Register { node, counter }, &mut plain);
    let env = yip_obf::obfuscate(obf_key, yip_obf::RDV_TYPE, &plain, 0);
    let mut out = Vec::new();
    crate::tls::frame_datagram(&env, &mut out).expect("register envelope within frame cap");
    out
}
```

Add `mod relay_client;` to `main.rs`. Silence unused-until-Task-5 items with `#[expect(dead_code, reason = "the thread in Task 5 consumes these")]` as needed (remove in Task 5).

- [ ] **Step 4: Run tests to pass. Step 5: Commit**

```bash
git add bin/yipd/src/relay_client.rs bin/yipd/src/main.rs
git commit -m "feat(yipd): relay_client Register framing + monotonic counter (3c.4)"
```

---

### Task 5: `relay_client` thread — TLS connect, Register-first, pump, reconnect

**Files:**
- Modify: `bin/yipd/src/relay_client.rs` (the thread entry + pump)
- Test: a localhost integration test (a stub TLS server that expects Register-first, echoes a frame)

**Interfaces:**
- Consumes: `crate::tls::{build_client_connector, drive_handshake, FrameReader, frame_datagram, HANDSHAKE_TIMEOUT, INITIAL_BACKOFF_MS, MAX_BACKOFF_MS}`, `yip_io::epoll::Epoll`.
- Produces: `pub(crate) fn spawn(host: String, port: u16, sni: String, obf_key: [u8;16], self_node: NodeId, sock: std::os::unix::net::UnixStream) -> std::thread::JoinHandle<()>` — the thread owns one end of the socketpair (`sock`) and the TLS connection; it runs forever (reconnect-with-backoff).

- [ ] **Step 1: Read `crate::tls`** (`connect_and_handshake`, `build_client_connector`, `drive_handshake`, the non-blocking `SslStream` read/write pattern with `WANT_READ`/`WANT_WRITE` + `Epoll`, backoff consts) to mirror it exactly.

- [ ] **Step 2: Write the localhost integration test**

Stand up a stub TLS **server** (reuse `crate::tls::build_server_acceptor` + a self-signed cert from the tls.rs test helper) on `127.0.0.1:0` that: accepts, reads the first framed message, asserts it deobfuscates to a `Register{self_node, counter=1}`, then writes back a framed `obf(RDV_TYPE, RelayDeliver{src, payload=b"pong"})`. Call `spawn(...)` pointing at that server with one socketpair end; on the other end, read a framed message and assert it is the `RelayDeliver` payload `b"pong"` (proving the thread: connected, sent Register-first, and piped an inbound relay frame to the data-plane side). Bound the test with a timeout.

- [ ] **Step 3: Implement the thread**

The pump (mirroring `crate::tls::run_tls`, but the two epoll fds are the **TLS socket** and the **socketpair**, and Register is sent first):

```
spawn → thread:
  set `sock` non-blocking
  let mut counter = Counter::default()
  let mut backoff = INITIAL_BACKOFF_MS
  loop {                                   // reconnect loop
    let (stream, poller) = match connect(host,port,sni, sock_fd) {
        Ok(x) => x, Err(_) => { sleep(backoff); backoff = (backoff*2).min(MAX); continue }
    };
    backoff = INITIAL_BACKOFF_MS;
    // Register FIRST — the relay classifies on the first frame.
    if write_all_tls(&mut stream, &poller, &build_register(&obf_key, self_node, counter.next())).is_err() { continue }
    let mut last_reg = Instant::now();
    let mut tls_reader = FrameReader::default();
    let mut sock_reader = FrameReader::default();   // frames from the data plane
    loop {                                          // pump
        let ready = poller.wait(min(REG_KEEPALIVE_MS, ...))?;
        if ready.udp /* = TLS fd */ {
            drain: read TLS → tls_reader.push; for each full frame → write it framed to `sock` (best-effort, drop on WouldBlock)
            on TLS error/eof → break to reconnect
        }
        if ready.tun /* = socketpair fd */ {
            drain: read `sock` → sock_reader.push; for each full frame (an obf RelaySend env) → write_all_tls(stream, frame)
        }
        if last_reg.elapsed() >= REG_KEEPALIVE (~30s) {
            write_all_tls(stream, build_register(&obf_key, self_node, counter.next())); last_reg = now
        }
    }
  }
```

Key points: `Epoll::new(tls_fd, sock_fd)` — `Ready.udp` = TLS fd, `Ready.tun` = socketpair fd (name reuse is fine — they are just "first/second watched fd"). Reuse `crate::tls`'s `write_all_tls`/`drain_tls_read` helpers if `pub(crate)`; else mirror them. Register keepalive `const REG_KEEPALIVE_MS: u64 = 30_000;`. Socketpair→TLS carries the already-obf'd RelaySend envelope verbatim (deframe from socketpair, re-frame to TLS). TLS→socketpair carries the obf'd RelayDeliver envelope verbatim.

- [ ] **Step 4: Run the integration test to pass.** Remove any Task-4 `#[expect]` now consumed.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/relay_client.rs
git commit -m "feat(yipd): relay_client thread — TLS connect, Register-first, pump, reconnect (3c.4)"
```

---

### Task 6: `run_relay_tls` data-plane loop + dispatch

**Files:**
- Create: the `run_relay_tls` loop (in `bin/yipd/src/relay_client.rs` or a `bin/yipd/src/tunnel.rs` helper)
- Modify: `bin/yipd/src/tunnel.rs` (dispatch `Rendezvous::Tls` → spawn thread + run loop; force poll driver; build `PeerManager` with `TlsRelayRendezvous` + relay-only path)
- Test: covered by the netns money test (Task 7); this task's gate is build + a smoke run

**Interfaces:**
- Consumes: `relay_client::spawn`, `PeerManager` (built with `TlsRelayRendezvous::new(relay_addr)`), `yip_io::epoll::Epoll`, `crate::tls::{FrameReader, frame_datagram}`.
- Produces: `pub(crate) fn run_relay_tls(tun_fd: RawFd, manager: &mut PeerManager, relay_addr: SocketAddr, sock: UnixStream) -> io::Result<()>` — the poll loop over `Epoll(tun_fd, sock_fd)`.

- [ ] **Step 1: Implement `run_relay_tls`** (mirrors `run_tls`/`run_quic`; the two epoll fds are TUN and the socketpair):

```
run_relay_tls(tun_fd, manager, relay_addr, sock):
  set sock non-blocking; let poller = Epoll::new(sock_fd, tun_fd)?
  let mut reader = FrameReader::default()   // frames from the relay thread
  loop {
    let ready = poller.wait(TICK_MS)?; now = ...
    if ready on sock_fd {                    // inbound RelayDeliver envelopes
        read sock → reader.push; for each full frame (obf RelayDeliver env):
            match manager.on_udp(relay_addr, &env, now) { Outcome::TunWrite(p)=>write_tun; Outcome::Send(egr)|TunWriteThenSend(..)=> for each e in egr: frame e.bytes → write to sock }
    }
    if ready on tun_fd {
        read tun → manager.on_tun(inner, now) → for each egress e: frame e.bytes → write to sock (best-effort)
    }
    for e in manager.tick(now): frame e.bytes → write to sock
  }
```

All egress `e.bytes` are obf'd RelaySend envelopes (straight-to-relay); `e.dst` is `relay_addr` and is ignored here (everything goes to the relay thread). Reuse `write_tun` from `tls.rs`/`quic.rs`.

- [ ] **Step 2: Dispatch in `tunnel.rs`**

Replace the Task-1 `Rendezvous::Tls { .. } => todo!()` arm. When `config.rendezvous` is `Tls { host, port }`:
- Resolve `host:port` → a `SocketAddr` (`(host.as_str(), port).to_socket_addrs()?.next()`), the relay routing key `relay_addr`.
- Build `PeerManager` with `Box::new(TlsRelayRendezvous::new(relay_addr))` and relay-only path (Task 3).
- `let (a, b) = UnixStream::pair()?;` spawn `relay_client::spawn(host, port, /*sni=*/host, obf_key, node_id(local_public), b)`.
- Force the poll driver (ignore `YIP_USE_URING`) and `return run_relay_tls(tun_fd, &mut manager, relay_addr, a);`.

Place this dispatch next to the `quic`/`tls` transport dispatch (early, before the raw-UDP `run_poll`). Note: the UDP socket is bound but unused on this path (like the `tls`/`quic` note) — that's fine.

- [ ] **Step 3: Build + smoke**

Run: `cargo build --release -p yipd`. Expected: builds. (Behavioral verification is Task 7.)

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/relay_client.rs bin/yipd/src/tunnel.rs
git commit -m "feat(yipd): run_relay_tls loop + tls:// rendezvous dispatch (3c.4)"
```

---

### Task 7: netns money test — two UDP-blocked peers tunnel via the TLS relay

**Files:**
- Create: `bin/yipd/tests/run-netns-relay-tls.sh`, a harness test in `bin/yipd/tests/tunnel_netns.rs`
- Modify: `.github/workflows/integration.yml`

- [ ] **Step 1: Write the money-test script** `run-netns-relay-tls.sh <yipd> <yip-rendezvous>`:
  - Three netns joined by a bridge (or a relay netns reachable by both peer netns). Generate keypairs for A, B, and a shared `obf_psk` (64 hex).
  - Relay: self-signed cert for `relay.test`; start `yip-rendezvous <udp> --listen-tcp <relay-ip>:8443 --tls-cert … --tls-key … --obf-psk <hex>` (no `--decoy` needed — this test drives the tunnel path, not the decoy).
  - **Block UDP between the peers** (and to the relay's UDP) with `nft`/`iptables` in the peer netns, so only TCP/443-style paths work — proving relay-over-TLS is what carries traffic.
  - A config: `rendezvous=tls://relay.test:8443` (add `relay.test` → relay IP via `--add-host`/`/etc/hosts` in the netns, or use the IP literal `tls://<relay-ip>:8443`), `obf_psk=<hex>`, peer B by `public_key` only (no endpoint). B config symmetric.
  - Bring up TUN IPs; **ping A→B across the tunnel**. Assert: ping succeeds; the relay's stderr shows `relay-forwarded=<N>` with **N>0** (traffic went through the blind relay); and a `tcpdump` on the peer↔relay link shows **TCP** (not UDP) carrying it. Root-gated SKIP + cleanup trap, mirroring `run-netns-relay.sh` + `run-tls-mimicry-oracle.sh`.

- [ ] **Step 2: Harness test** `relay_tls_tunnel_ping` in `tunnel_netns.rs` (root-gated like `quic_tunnel_ping`), building both binaries and running the script, asserting exit 0.

- [ ] **Step 3: Run locally under sudo** — `cargo build --release -p yipd -p yip-rendezvous-bin && sudo bash bin/yipd/tests/run-netns-relay-tls.sh ./target/release/yipd ./target/release/yip-rendezvous`. Expected: ping PASS, relay-forwarded>0, TCP-carried.

- [ ] **Step 4: CI** — add the test to `integration.yml` (the `dpi-undetectability` or `netns-tunnel-test` job; it needs cmake for boring + a built `yip-rendezvous`), honesty-guarded on `^SKIP`/`[FAIL]`.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/tests/run-netns-relay-tls.sh bin/yipd/tests/tunnel_netns.rs .github/workflows/integration.yml
git commit -m "test(yipd): netns money test — UDP-blocked peers tunnel via the TLS relay (3c.4)"
```

---

### Task 8: Docs

**Files:** Modify `docs/configuration.md`, `CHANGELOG.md`

- [ ] **Step 1: Document `rendezvous=tls://`** in `docs/configuration.md` (in the rendezvous section): the `tls://host:port` form, that it dials the 3c.3 relay over browser-parrot TLS, requires `obf_psk`, forces the poll driver, is straight-to-relay (no Direct/punch), SNI = the relay host, and carries the unchanged inner protocol as relayed payload. Cross-ref the 3c.3 relay `--listen-tcp` docs and the threat boundary (probe-resistance == `obf_psk` secrecy; #64/#37).

- [ ] **Step 2: `CHANGELOG.md`** `### Added` entry: "TLS relay-dial client (`rendezvous = tls://host:443`, anti-DPI 3c.4): a `yipd` node reaches the 3c.3 relay over a persistent browser-parrot TLS connection (a dedicated thread; the data plane stays tokio-free) and relays the unchanged inner protocol through it — so two UDP-blocked peers can tunnel to each other. Requires `obf_psk`; poll-driver-only; straight-to-relay."

- [ ] **Step 3: Commit**

```bash
git add docs/configuration.md CHANGELOG.md
git commit -m "docs(yipd): document rendezvous=tls:// relay-dial (3c.4)"
```

---

### Task 9: No-regression

**Files:** none expected (verification; fix in place if a regression appears).

- [ ] **Step 1: Full workspace** — `cargo test --workspace` → 0 failures.
- [ ] **Step 2: Strict clippy** — `cargo clippy --workspace --all-targets -- -D warnings` → clean.
- [ ] **Step 3: UDP rendezvous unchanged** — run `relay_path_ping`, `hole_punch_ping`, `discovery_dynamic_ping` under sudo (the UDP path, `PeerManager`, and `ConfiguredServerRendezvous` are behavior-preserving apart from the `register()`→`Option` wrap). All PASS.
- [ ] **Step 4: Commit** any regression fix (else skip).

---

## Notes for the executor

- **Reuse `crate::tls` for ALL TLS.** `build_client_connector` (browser-parrot GREASE), `drive_handshake` (with `HANDSHAKE_TIMEOUT`), `FrameReader`/`frame_datagram`, the non-blocking `SslStream` + `Epoll` read/write pattern, the backoff consts. Do not re-implement TLS or framing.
- **The relay thread and `run_relay_tls` each own one end of a `UnixStream::pair()`** and one `Epoll` over two fds (thread: TLS + socketpair; loop: TUN + socketpair). Bytes over the socketpair are `[u16 len]`-framed obf envelopes, passed through verbatim (deframe one side, re-frame the other).
- **Register is the thread's, and must be the FIRST frame on every (re)connect** — the relay classifies on the first frame; a `RelaySend` first ⇒ the relay serves the decoy and the tunnel silently fails.
- **Inner protocol untouched.** `PeerManager`'s crypto/FEC/AEAD/admission are unchanged; 3c.4 changes only config, the `Rendezvous` trait/impl (register→Option + TlsRelayRendezvous), the path SM (relay-only), and adds the transport loop + thread.
- **No tokio, `forbid(unsafe_code)` in `yipd`.** `UnixStream::pair()` is safe std; `Epoll` keeps `unsafe` in `yip-io`.
