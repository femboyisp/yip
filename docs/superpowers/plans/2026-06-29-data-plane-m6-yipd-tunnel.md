# Data Plane M6 — `yipd` End-to-End Tunnel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the five data-plane crates into `yipd` — a working VPN daemon that establishes a Noise-IK session between two statically-configured peers over UDP and tunnels L3 (TUN) traffic through the adaptive-FEC encrypted transport, demonstrable by pinging across the tunnel.

**Architecture:** `yipd` performs a handshake-over-UDP (type-prefixed datagrams), derives the wire codec keys from the session's channel-binding hash, then runs two directions: **egress** (device → seal → FEC-encode → wire-frame → UDP) and **ingress** (UDP → wire-deframe → FEC-decode → open → device). Per the verified composition spike, each symbol's wire payload is `[counter:8][object_size:4][symbol bytes]` with the FlowClass in `Frame.flags` — all authenticated by the wire codec's coverage-auth tag, so no `yip-wire` change is needed. Shared crypto/transport state sits behind `Arc<Mutex<…>>`; the device and UDP socket are duplicated per direction so the two loops don't contend on I/O. The unified single-io_uring-ring busy-poll loop and a lock-free direction-split are noted perf follow-ons.

**Tech Stack:** Rust, the five `yip-*` crates, `std::net::UdpSocket`, threads.

## Global Constraints

- License MPL-2.0. `unsafe` only in `yip-io`/`yip-device` (the `dup` in Task 2); `yipd` and the protocol crates stay clean (`yipd` is not `forbid(unsafe)` but should contain no `unsafe`).
- Lints: workspace set, CI `--deny warnings`. **No `as` numeric casts** (use `try_from`/`from`/`to_be_bytes`).
- No new external deps (use std threads + sockets). If a tiny helper is unavoidable, justify it.
- Borrowed types in signatures; UTF-8/LF/final-newline/no-trailing-ws.
- Commits imperative+capitalized ≤72-char subject, body ends with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Pre-commit hook runs fmt+clippy+test; each commit must pass it.
- Coverage: the glue logic (key derivation, Symbol↔Frame codec, handshake framing) is held to ≥90% via unit tests; the tunnel-loop + device wiring is covered by a **sudo-gated netns integration test** (honest-exclusion, like M4's device tests), not the hermetic gate.

## Verified composition (the M6 spike)

The full path round-trips through 25% symbol loss (spiked against the real crates):
```
inner ─ seal ─▶ Sealed{counter, ciphertext}
ciphertext, inner ─ Transport::encode(.., now_ms) ─▶ (class, Vec<Symbol>)
per symbol: Frame{ conn_tag, object_id: sym.object_id, payload_id: sym.payload_id,
                   flags: class_bits, payload: counter.be(8) ++ object_size.be(4) ++ sym.data }
            ─ Codec::frame ─▶ udp datagram
udp ─ Codec::deframe ─▶ Frame ─ parse(flags→class, payload→counter/object_size/data) ─▶ Symbol
Transport::decode(sym, class) ─▶ Some(ciphertext) ─ Session::open(counter, ct) ─▶ inner ✓
```
Wire keys derive from `get_handshake_hash()` (symmetric 32 bytes, both peers).

---

### Task 1: `yip-crypto` — expose the channel-binding hash

**Files:**
- Modify: `crates/yip-crypto/src/lib.rs`

**Interfaces:**
- Produces: `impl Handshake { pub fn channel_binding(&self) -> [u8; 32] }` — returns snow's `get_handshake_hash()` (identical on both peers; used to derive wire keys). Must be called after the handshake completes.

- [ ] **Step 1: Write the failing test**

In `crates/yip-crypto/src/lib.rs` tests:

```rust
#[test]
fn channel_binding_matches_on_both_peers() {
    let resp_kp = generate_keypair();
    let init_kp = generate_keypair();
    let mut ini = Handshake::initiator(&init_kp.private, &resp_kp.public).unwrap();
    let mut res = Handshake::responder(&resp_kp.private).unwrap();
    let m1 = ini.write_message().unwrap();
    res.read_message(&m1).unwrap();
    let m2 = res.write_message().unwrap();
    ini.read_message(&m2).unwrap();
    assert!(ini.is_finished() && res.is_finished());
    assert_eq!(ini.channel_binding(), res.channel_binding(), "both peers derive the same binding");
    assert_ne!(ini.channel_binding(), [0u8; 32]);
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-crypto channel_binding`
Expected: FAIL (`channel_binding` undefined).

- [ ] **Step 3: Implement**

In `impl Handshake`, add:

```rust
/// The Noise channel-binding hash (snow's handshake hash), identical on both
/// peers after the handshake completes. Use it to derive subkeys (e.g. the
/// wire codec keys) bound to this session.
pub fn channel_binding(&self) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(self.inner.get_handshake_hash());
    out
}
```

- [ ] **Step 4: Run the test — expect pass**

Run: `cargo test -p yip-crypto channel_binding`
Expected: PASS. clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-crypto/src/lib.rs
git commit -m "Expose the Noise channel-binding hash in yip-crypto

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `yip-device` — split a `TunTap` into concurrent reader/writer halves

**Files:**
- Modify: `crates/yip-device/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub struct TunReader { file: std::fs::File }` with `impl TunReader { pub fn read_frame(&mut self, buf: &mut [u8]) -> std::io::Result<usize> }`
  - `pub struct TunWriter { file: std::fs::File }` with `impl TunWriter { pub fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<usize> }`
  - `impl TunTap { pub fn split(self) -> Result<(TunReader, TunWriter), DeviceError> }` — duplicates the underlying fd (`libc::dup`) so the two halves can be read/written from separate threads.

- [ ] **Step 1: Write the failing test (sudo-gated)**

```rust
#[test]
fn split_yields_independent_reader_writer() {
    if !can_create_devices() {
        eprintln!("SKIP split_yields_independent_reader_writer: needs CAP_NET_ADMIN");
        return;
    }
    let dev = TunTap::create("yipsplit0", DeviceKind::Tun).unwrap();
    let (_reader, mut writer) = dev.split().unwrap();
    // the writer half can still inject a frame
    let pkt = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 9, 9, 1, 10, 9, 9, 2];
    assert_eq!(writer.write_frame(&pkt).unwrap(), pkt.len());
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-device split_yields`
Expected: FAIL (`split`/`TunReader`/`TunWriter` undefined).

- [ ] **Step 3: Implement**

```rust
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// The read half of a split [`TunTap`].
pub struct TunReader {
    file: std::fs::File,
}

/// The write half of a split [`TunTap`].
pub struct TunWriter {
    file: std::fs::File,
}

impl TunReader {
    /// Read one inner frame.
    pub fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.file.read(buf)
    }
}

impl TunWriter {
    /// Write one inner frame.
    pub fn write_frame(&mut self, frame: &[u8]) -> io::Result<usize> {
        use std::io::Write;
        self.file.write(frame)
    }
}

impl TunTap {
    /// Split into independent reader/writer halves backed by duplicated fds,
    /// so one thread can read while another writes the same device.
    pub fn split(self) -> Result<(TunReader, TunWriter), DeviceError> {
        let raw = self.file.as_raw_fd();
        // SAFETY: `raw` is a valid open fd owned by `self.file`; `dup` returns a new
        // independent fd referring to the same TUN/TAP device, or -1 on error.
        let dup = unsafe { libc::dup(raw) };
        if dup < 0 {
            return Err(DeviceError::Io(io::Error::last_os_error()));
        }
        // SAFETY: `dup` is a fresh, valid, exclusively-owned fd from `dup`.
        let dup_file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(dup) });
        let reader = TunReader { file: dup_file };
        let writer = TunWriter { file: self.file };
        Ok((reader, writer))
    }
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p yip-device` (SKIPs unprivileged). Under sudo verify it really splits + writes (use the test-binary-under-sudo pattern from M4). clippy clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-device/src/lib.rs
git commit -m "Split TunTap into concurrent reader and writer halves

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `yipd` — wire-key derivation + Symbol↔Frame codec glue

**Files:**
- Create: `bin/yipd/src/wire_glue.rs`
- Modify: `bin/yipd/Cargo.toml`, `bin/yipd/src/main.rs`

**Interfaces:**
- Produces (in `wire_glue.rs`):
  - `pub fn derive_wire_keys(channel_binding: &[u8; 32]) -> ([u8; 16], [u8; 16])` — splits/KDFs the binding into `(auth_key, hp_key)`.
  - `pub fn class_to_flags(c: FlowClass) -> u8` / `pub fn flags_to_class(f: u8) -> FlowClass`.
  - `pub fn symbol_to_frame(conn_tag: u64, sym: &Symbol, counter: u64, class: FlowClass) -> Frame`
  - `pub fn frame_to_symbol(frame: &Frame) -> Option<(Symbol, u64, FlowClass)>` — returns `(symbol, counter, class)`, or None if the payload is shorter than the 12-byte prefix.

- [ ] **Step 1: Write the failing test**

`bin/yipd/src/wire_glue.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_keys_are_deterministic_and_distinct() {
        let cb = [7u8; 32];
        let (a, h) = derive_wire_keys(&cb);
        let (a2, h2) = derive_wire_keys(&cb);
        assert_eq!((a, h), (a2, h2), "deterministic");
        assert_ne!(a, h, "auth and hp keys differ");
    }

    #[test]
    fn symbol_frame_roundtrips_with_counter_and_class() {
        let sym = Symbol { object_id: 5, object_size: 1234, payload_id: [1, 2, 3, 4], data: vec![9, 8, 7] };
        let frame = symbol_to_frame(42, &sym, 99, FlowClass::Bulk);
        assert_eq!(frame.object_id, 5);
        assert_eq!(frame.payload_id, [1, 2, 3, 4]);
        let (got, counter, class) = frame_to_symbol(&frame).unwrap();
        assert_eq!(got, sym);
        assert_eq!(counter, 99);
        assert_eq!(class, FlowClass::Bulk);
    }

    #[test]
    fn frame_to_symbol_rejects_short_payload() {
        let frame = Frame { conn_tag: 1, object_id: 0, payload_id: [0; 4], flags: 0, payload: vec![0; 4] };
        assert!(frame_to_symbol(&frame).is_none());
    }
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yipd wire_glue` (after adding `mod wire_glue;` to main.rs)
Expected: FAIL.

- [ ] **Step 3: Implement**

Add deps to `bin/yipd/Cargo.toml` (remove the cargo-shear ignores for the crates now actually used): `yip-wire`, `yip-transport`, `yip-crypto` become real deps. Add `blake2 = "0.10.6"` for the key derivation (already in the lockfile via snow's tree — confirm, else use a std hash). In `wire_glue.rs`:

```rust
//! Glue mapping the FEC transport's `Symbol`s onto authenticated wire `Frame`s,
//! and deriving the wire codec keys from the session channel binding.

use yip_transport::{FlowClass, Symbol};
use yip_wire::Frame;

/// Derive the wire codec's (auth_key, hp_key) from the session channel binding.
/// Both peers compute the same binding, so both derive the same keys.
pub fn derive_wire_keys(channel_binding: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
    use blake2::{Blake2s256, Digest};
    let mut auth = [0u8; 16];
    let mut hp = [0u8; 16];
    let a = Blake2s256::new_with_prefix(b"yip wire auth").chain_update(channel_binding).finalize();
    let h = Blake2s256::new_with_prefix(b"yip wire hp").chain_update(channel_binding).finalize();
    auth.copy_from_slice(&a[..16]);
    hp.copy_from_slice(&h[..16]);
    (auth, hp)
}

/// Encode a flow class into the low bits of the frame flags byte.
pub fn class_to_flags(c: FlowClass) -> u8 {
    match c {
        FlowClass::Realtime => 0,
        FlowClass::Bulk => 1,
        FlowClass::Default => 2,
    }
}

/// Decode the flow class from the frame flags byte.
pub fn flags_to_class(f: u8) -> FlowClass {
    match f & 0x03 {
        0 => FlowClass::Realtime,
        1 => FlowClass::Bulk,
        _ => FlowClass::Default,
    }
}

/// Build a wire frame for one FEC symbol: the AEAD counter and object size ride
/// in the (authenticated) payload prefix; the class rides in flags.
pub fn symbol_to_frame(conn_tag: u64, sym: &Symbol, counter: u64, class: FlowClass) -> Frame {
    let mut payload = Vec::with_capacity(12 + sym.data.len());
    payload.extend_from_slice(&counter.to_be_bytes());
    payload.extend_from_slice(&sym.object_size.to_be_bytes());
    payload.extend_from_slice(&sym.data);
    Frame {
        conn_tag,
        object_id: sym.object_id,
        payload_id: sym.payload_id,
        flags: class_to_flags(class),
        payload,
    }
}

/// Parse a received frame back into a `(Symbol, counter, class)`, or None if the
/// payload is shorter than the 12-byte counter+object_size prefix.
pub fn frame_to_symbol(frame: &Frame) -> Option<(Symbol, u64, FlowClass)> {
    if frame.payload.len() < 12 {
        return None;
    }
    let counter = u64::from_be_bytes(frame.payload[0..8].try_into().ok()?);
    let object_size = u32::from_be_bytes(frame.payload[8..12].try_into().ok()?);
    let sym = Symbol {
        object_id: frame.object_id,
        object_size,
        payload_id: frame.payload_id,
        data: frame.payload[12..].to_vec(),
    };
    Some((sym, counter, flags_to_class(frame.flags)))
}
```

- [ ] **Step 4: Run the tests — expect pass**

Run: `cargo test -p yipd wire_glue`
Expected: PASS. clippy clean. `cargo shear` clean (the three crates are now used; drop their shear-ignore entries from `yipd`'s Cargo.toml metadata, leaving only `yip-io`/`yip-device` if still unused-at-this-step — but they ARE used by Task 5, so by milestone end no ignores remain).

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/Cargo.toml bin/yipd/src/main.rs bin/yipd/src/wire_glue.rs
git commit -m "Add wire-key derivation and Symbol-Frame glue to yipd

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `yipd` — handshake-over-UDP

**Files:**
- Create: `bin/yipd/src/handshake.rs`
- Modify: `bin/yipd/src/main.rs`

**Interfaces:**
- Produces:
  - `pub enum PacketType { HandshakeInit = 0, HandshakeResp = 1, Data = 2 }` (a 1-byte datagram prefix; documented as pre-obfuscation — sub-project #3 removes fixed prefixes).
  - `pub struct Established { pub session: yip_crypto::Session, pub auth_key: [u8; 16], pub hp_key: [u8; 16] }`
  - `pub fn run_initiator(sock: &std::net::UdpSocket, peer: std::net::SocketAddr, local_priv: &[u8; 32], peer_pub: &[u8; 32]) -> std::io::Result<Established>`
  - `pub fn run_responder(sock: &std::net::UdpSocket, local_priv: &[u8; 32]) -> std::io::Result<(Established, std::net::SocketAddr)>`

- [ ] **Step 1: Write the failing test (in-process loopback over two UDP sockets)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use yip_crypto::generate_keypair;

    #[test]
    fn handshake_over_udp_establishes_matching_keys() {
        let rkp = generate_keypair();
        let ikp = generate_keypair();
        let resp_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let resp_addr = resp_sock.local_addr().unwrap();
        let init_sock = UdpSocket::bind("127.0.0.1:0").unwrap();

        let r_priv = rkp.private;
        let resp = std::thread::spawn(move || run_responder(&resp_sock, &r_priv).unwrap());
        let est_i = run_initiator(&init_sock, resp_addr, &ikp.private, &rkp.public).unwrap();
        let (est_r, _peer) = resp.join().unwrap();

        // both derived the same wire keys
        assert_eq!(est_i.auth_key, est_r.auth_key);
        assert_eq!(est_i.hp_key, est_r.hp_key);

        // and the established sessions actually talk
        let mut si = est_i.session;
        let mut sr = est_r.session;
        let sealed = si.seal(b"after handshake").unwrap();
        assert_eq!(sr.open(sealed.counter, &sealed.ciphertext).unwrap(), b"after handshake");
    }
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yipd handshake_over_udp`
Expected: FAIL.

- [ ] **Step 3: Implement**

Implement `run_initiator` / `run_responder` driving `yip_crypto::Handshake`: the initiator sends `[HandshakeInit] ++ handshake.write_message()`, waits for `[HandshakeResp] ++ msg2`, reads it, then `into_session()` + `derive_wire_keys(channel_binding)`. The responder receives the init, replies with the response, derives the session + keys, and returns the peer's address. Set a read timeout and a bounded retry on the initiator (resend init if no response within, say, 1s, up to 5 tries) so the test is not flaky. Use `wire_glue::derive_wire_keys`. Map the `CryptoError` into `io::Error::other` as needed.

- [ ] **Step 4: Run the test — expect pass**

Run: `cargo test -p yipd handshake_over_udp`
Expected: PASS (the two threads complete the handshake and derive matching keys). clippy clean.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/handshake.rs bin/yipd/src/main.rs
git commit -m "Add Noise handshake over UDP to yipd

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `yipd` — the tunnel data loops, config, and main wiring

**Files:**
- Create: `bin/yipd/src/tunnel.rs`, `bin/yipd/src/config.rs`
- Modify: `bin/yipd/src/main.rs`

**Interfaces:**
- Produces:
  - `config.rs`: `pub struct Config { pub local_private: [u8;32], pub local_public: [u8;32], pub peer_public: [u8;32], pub peer_endpoint: std::net::SocketAddr, pub listen: std::net::SocketAddr, pub device: String, pub initiate: bool }` plus a simple loader (CLI args via `std::env::args`, or a small hand-parsed key=value file — no clap dep; keep it minimal).
  - `tunnel.rs`: `pub fn run(config: Config) -> std::io::Result<()>` — binds the socket, runs the handshake (initiator or responder per `config.initiate`), creates + splits the TUN device, derives the codec, and spawns the two loops; blocks until they exit.
  - The egress loop: `reader.read_frame` → `session.seal` (Arc<Mutex>) → `transport.encode` (Arc<Mutex>, with a monotonic `now_ms`) → per symbol `symbol_to_frame` → `codec.frame` → `sock.send([Data] ++ dg)`.
  - The ingress loop: `sock.recv` → match prefix; on Data, `codec.deframe` → `frame_to_symbol` → `transport.decode` → `session.open` → `writer.write_frame`.

- [ ] **Step 1: Write the failing test**

A unit test for `config.rs` parsing (the loops themselves are exercised by the netns integration test in Task 6, which can't run hermetically):

```rust
// in config.rs
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_config_from_kv() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\npeer_endpoint=10.0.0.2:51820\ninitiate=true\n\
                    local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                    local_public=00000000000000000000000000000000000000000000000000000000000000aa\n\
                    peer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";
        let c = Config::parse(text).unwrap();
        assert_eq!(c.device, "yip0");
        assert!(c.initiate);
        assert_eq!(c.local_private[31], 0xff);
        assert_eq!(c.peer_public[31], 0xbb);
    }
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yipd parse_config`
Expected: FAIL.

- [ ] **Step 3: Implement**

Implement `Config` + `Config::parse(&str)` (hand-parse `key=value` lines; hex-decode the 32-byte keys; bounded errors via `io::Error`). Implement `tunnel::run`: bind UDP, handshake, `TunTap::create(&config.device, DeviceKind::Tun)?.split()?`, build `Codec::new(auth_key, hp_key)`, wrap `Session`/`Transport` in `Arc<Mutex<…>>`, `try_clone` the socket per direction, spawn the egress and ingress threads (each owning its reader/writer half + socket clone + Arc'd shared state), and `join`. Use a monotonic clock: `let start = std::time::Instant::now();` and `now_ms = start.elapsed().as_millis()` converted with `u64::try_from(...).unwrap_or(u64::MAX)`. Wire `main.rs` to load the config (CLI arg = path) and call `tunnel::run`. Keep `main`'s existing `banner()` for `--version`.

- [ ] **Step 4: Run the test + build the binary**

Run: `cargo test -p yipd && cargo build -p yipd`
Expected: config test passes; `yipd` builds. clippy clean. (The loops aren't unit-tested here; Task 6 covers them.)

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/src/config.rs bin/yipd/src/tunnel.rs bin/yipd/src/main.rs
git commit -m "Wire the yipd tunnel data loops and config

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: netns integration test — ping across the tunnel

**Files:**
- Create: `bin/yipd/tests/tunnel_netns.rs`
- Create: `bin/yipd/tests/run-netns-tunnel.sh`
- Modify: `.github/workflows/integration.yml`

**Interfaces:**
- A sudo-gated test script that: creates two network namespaces joined by a veth pair, writes a config for each peer (responder in ns A, initiator in ns B, peer endpoints = the veth IPs), starts both `yipd`, assigns tunnel IPs (e.g. 10.9.0.1/24 and 10.9.0.2/24 to the `yip0` TUN in each ns), and `ping`s from one tunnel IP to the other across the encrypted FEC tunnel. The Rust `tests/tunnel_netns.rs` shells out to the script and asserts success, SKIPping when not root.

- [ ] **Step 1: Write the integration test + script**

`bin/yipd/tests/tunnel_netns.rs`:

```rust
//! End-to-end tunnel test: two yipd in separate netns ping across the tunnel.
//! Requires root (CAP_NET_ADMIN + netns); SKIPs otherwise. Run in CI under sudo.
use std::process::Command;

#[test]
fn ping_across_yipd_tunnel() {
    // Only run as root (the script needs netns + TUN).
    let is_root = Command::new("id").arg("-u").output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    if !is_root {
        eprintln!("SKIP ping_across_yipd_tunnel: needs root (run under sudo in CI)");
        return;
    }
    let yipd = env!("CARGO_BIN_EXE_yipd");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/run-netns-tunnel.sh");
    let status = Command::new("bash").arg(script).arg(yipd).status().unwrap();
    assert!(status.success(), "netns tunnel ping failed");
}
```

`bin/yipd/tests/run-netns-tunnel.sh` — a bash script (set -euo pipefail) that builds the two-namespace topology, generates two keypairs (use a tiny `yipd --genkey`-style helper OR pre-baked test keys written into the configs), launches both daemons, brings up the TUN devices with tunnel IPs, runs `ip netns exec nsB ping -c 3 -W 5 10.9.0.1`, and tears everything down in a trap. Exit non-zero on ping failure. Follow the M4 device-test conventions (cleanup trap, `ip netns del` on exit).

Note for the implementer: you'll need `yipd` to print its static public key for a private key, or accept pre-baked keys in the config. The simplest path: add a `yipd --genkey` subcommand (prints a fresh private+public hex pair) OR bake two fixed test keypairs into the script's configs (generate them once with a throwaway and hardcode). Pick the simpler one that makes the test deterministic.

- [ ] **Step 2: Build + run unprivileged (SKIPs)**

Run: `cargo test -p yipd --test tunnel_netns`
Expected: builds; SKIPs (not root) and passes.

- [ ] **Step 3: Run for real under sudo**

Run: `sudo -E "$(cargo test -p yipd --test tunnel_netns --no-run --message-format=json | jq -r 'select(.executable != null) | .executable' | tail -1)" --nocapture`
Expected: the script builds the netns topology, both daemons handshake, and `ping -c 3` across the tunnel SUCCEEDS. Iterate on the script until the ping passes. Clean up any leftover namespaces/interfaces.

- [ ] **Step 4: Add to the integration CI job**

In `.github/workflows/integration.yml`, add a step (or a second job) that builds and runs the `tunnel_netns` test binary under `sudo -E ... --test-threads=1`, with the same honesty guard (fail if it SKIPs — the CI runner is root-capable). Reuse the binary-discovery pattern already in that file.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/tests/tunnel_netns.rs bin/yipd/tests/run-netns-tunnel.sh .github/workflows/integration.yml
git commit -m "Add netns end-to-end tunnel ping integration test

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: coverage, changelog, full gate

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Coverage of the glue logic**

Run: `cargo llvm-cov --package yipd --lib --fail-under-lines 90 --summary-only`
(Scope to the library/glue units — `wire_glue`, `config`, `handshake` framing; the tunnel loops + device are integration-tested, not in the hermetic gate.) If the glue is under 90%, add a focused unit test. Note in the report which `yipd` modules are integration-covered vs unit-covered.

- [ ] **Step 2: Changelog**

Under `## [Unreleased]` → `### Added` in `CHANGELOG.md`:

```markdown
- `yipd` end-to-end tunnel: Noise handshake over UDP, session-derived wire keys,
  and L3 (TUN) traffic tunneled through the encrypted adaptive-FEC transport
  between two static peers (ping-tested across network namespaces).
```

- [ ] **Step 3: Full gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo shear && cargo deny check`
Expected: all clean/pass. No remaining `cargo-shear` ignores in `yipd` (every dep is now used).

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md
git commit -m "Record the yipd end-to-end tunnel in changelog

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (M6 slice):** two static peers ✓; Noise-IK handshake over UDP ✓ (T4); L3 (TUN) tunnel end-to-end ✓ (T5–T6); encrypt-then-FEC data path wired exactly as the verified spike ✓ (T3,T5); wire keys bound to the session via channel binding ✓ (T1,T3); the Symbol↔Frame mapping carries the AEAD counter + object_size + class in authenticated wire territory ✓ (T3); ping across the tunnel proves it ✓ (T6). **Deferred-by-design (noted):** L2/TAP bridging works through the same loops (the device supports it from M4) but the integration test uses L3/ping; the **benchmark harness** (`yip-bench` vs WireGuard/n2n/ZeroTier) is the final follow-on milestone; the **unified single-io_uring-ring busy-poll loop** and a **lock-free direction-split** (replacing the Arc<Mutex>) are perf follow-ons; reactive **ARQ** and **deadline-based FEC eviction** layer onto these loops next; **rekey** (re-handshake every ~120s) is a follow-on (M6 establishes one session).

**Placeholder scan:** all code is concrete and grounded in the verified composition spike. The `--genkey`-vs-baked-keys choice in T6 is explicit implementer latitude, not a placeholder.

**Type consistency:** `Symbol`/`FlowClass` (yip-transport), `Frame`/`Codec`/`WireCodec` (yip-wire), `Handshake`/`Session`/`Sealed`/`generate_keypair` (yip-crypto), `TunTap`/`TunReader`/`TunWriter`/`DeviceKind` (yip-device) are used with the signatures those crates expose. `derive_wire_keys`/`symbol_to_frame`/`frame_to_symbol`/`class_to_flags`/`flags_to_class` are consistent across `wire_glue`, `handshake`, and `tunnel`.

**Definition of done for M6:** `cargo test --workspace` green; `yipd` glue ≥90% covered; **two `yipd` in separate netns complete the handshake and successfully ping across the encrypted FEC tunnel** (run under sudo in CI); whole-workspace fmt/clippy/shear/deny green; CI (incl. the privileged tunnel job) passes on push.
