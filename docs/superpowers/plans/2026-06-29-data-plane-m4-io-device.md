# Data Plane M4 — `yip-device` + `yip-io` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the data plane real packet I/O: a `yip-device` that creates and reads/writes L3 (TUN) and L2 (TAP) tunnel endpoints, and a `yip-io` io_uring backend (plus a portable plain-socket fallback) that moves wire datagrams over UDP.

**Architecture:** `yip-device` opens `/dev/net/tun` and issues `TUNSETIFF` to create a TUN or TAP interface, then reads/writes inner frames on the resulting fd (one small documented `unsafe` ioctl; everything else is safe `File` I/O). `yip-io` provides two `DataPlaneIo` backends: `IoUringIo` (an `io_uring` ring submitting `Read`/`Write` ops against a UDP socket — the low-latency path) and `PlainIo` (a portable `std::net::UdpSocket` fallback), with a `select_backend` probe. The two I/O crates are the only ones allowed `unsafe`; they're wired into an end-to-end tunnel in M6.

**Tech Stack:** Rust, `io-uring` (raw io_uring), `libc` (ioctl + constants).

## Global Constraints

- License MPL-2.0. `unsafe` allowed ONLY in `yip-io` and `yip-device`, every block with a `// SAFETY:` comment; `yip-wire`/`yip-crypto`/`yip-transport` stay `#![forbid(unsafe_code)]`.
- Lints: workspace set, CI `--deny warnings`. **No `as` numeric casts** EXCEPT where an FFI signature requires a specific C type and a `From`/`TryFrom` is unavailable — in that case use `TryFrom`/`u32::try_from(...)?` where possible, and only fall back to `as` for pointer/length args that `io-uring`/`libc` demand, with a comment. Prefer `.try_into()`.
- Deps pinned full `x.y.z`: `io-uring = "0.7.10"`, `libc = "0.2.180"`.
- Borrowed types in signatures (`&[u8]`, `&mut [u8]`).
- Files UTF-8/LF/final-newline/no-trailing-ws; commits imperative+capitalized ≤72-char subject, body ends with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- A pre-commit hook runs fmt+clippy+test on commit; each task's commit must pass it.
- **Coverage:** `yip-io`'s io_uring path is testable caps-free over UDP loopback → held to the ≥90% bar. `yip-device`'s device-creation/read/write path needs `CAP_NET_ADMIN` (not in hermetic CI) → its privileged lines are covered by a **sudo-gated integration job**, not the hermetic 90% gate (honest-exclusion per the spec); its pure-logic helpers are unit-tested.

## Verified platform facts (spiked on kernel 6.18, this environment)

- `io_uring` is enabled (`/proc/sys/kernel/io_uring_disabled = 0`); ring create + `Read`/`Write` ops over a UDP socket work with NO privileges.
- TUN creation via `TUNSETIFF` needs `CAP_NET_ADMIN` → fails EPERM unprivileged, succeeds under `sudo`. `sudo -n` and `ip netns`/`ip tuntap` work here and on GitHub Actions runners.
- Verified constants: `TUNSETIFF = 0x400454ca`, `IFF_TUN = 0x0001`, `IFF_TAP = 0x0002`, `IFF_NO_PI = 0x1000`.

## Verified `io-uring` 0.7.10 API

```rust
use io_uring::{opcode, types, IoUring};
let mut ring = IoUring::new(8)?;                       // entries
let e = opcode::Read::new(types::Fd(raw_fd), buf.as_mut_ptr(), buf.len() as u32)
    .build().user_data(1);
// SAFETY: buf outlives the operation (we submit_and_wait before returning).
unsafe { ring.submission().push(&e)?; }
ring.submit_and_wait(1)?;
let cqe = ring.completion().next().expect("one completion");
let n = cqe.result();   // i32: >=0 bytes, <0 is -errno
// Write is opcode::Write::new(types::Fd(fd), buf.as_ptr(), len).build()
```

---

### Task 1: `yip-device` — deps, flags, and interface-name encoding

**Files:**
- Modify: `crates/yip-device/Cargo.toml`
- Modify: `crates/yip-device/src/lib.rs`

**Interfaces:**
- Consumes: `libc`.
- Produces (private/internal): `const TUN_PATH`, `const IFF_TUN/IFF_TAP/IFF_NO_PI/TUNSETIFF`, and `fn encode_ifname(name: &str) -> Result<[u8; libc::IFNAMSIZ], DeviceError>` (rejects names ≥ IFNAMSIZ). Adds `pub enum DeviceError`. Removes `#![forbid(unsafe_code)]` (device ioctl needs unsafe; replaced by `#![deny(unsafe_op_in_unsafe_fn)]`).

- [ ] **Step 1: Write the failing test**

In `crates/yip-device/src/lib.rs` test module:

```rust
#[test]
fn ifname_encodes_and_rejects_too_long() {
    let enc = encode_ifname("yip0").unwrap();
    assert_eq!(&enc[..4], b"yip0");
    assert_eq!(enc[4], 0, "NUL-padded");
    let long = "x".repeat(libc::IFNAMSIZ); // == IFNAMSIZ chars, no room for NUL
    assert!(matches!(encode_ifname(&long), Err(DeviceError::NameTooLong)));
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-device ifname_encodes`
Expected: FAIL (`encode_ifname`/`DeviceError` undefined).

- [ ] **Step 3: Add the dep**

`crates/yip-device/Cargo.toml` `[dependencies]`:

```toml
[dependencies]
libc = "0.2.180"
```

- [ ] **Step 4: Implement**

Replace the `#![forbid(unsafe_code)]` line at the top of `crates/yip-device/src/lib.rs` with `#![deny(unsafe_op_in_unsafe_fn)]`, keep the module doc and the existing `DeviceKind`/`Device` trait, and add:

```rust
use std::io;

const TUN_PATH: &str = "/dev/net/tun";
const IFF_TUN: libc::c_short = 0x0001;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
// _IOW('T', 202, int) on Linux.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// Errors creating or configuring a tunnel device.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    /// Interface name does not fit in `IFNAMSIZ` (including the NUL terminator).
    #[error("interface name too long")]
    NameTooLong,
    /// Underlying OS error (open / ioctl / read / write).
    #[error("device io error: {0}")]
    Io(#[from] io::Error),
}

/// Encode an interface name into a NUL-padded `IFNAMSIZ` buffer.
fn encode_ifname(name: &str) -> Result<[u8; libc::IFNAMSIZ], DeviceError> {
    let bytes = name.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(DeviceError::NameTooLong);
    }
    let mut buf = [0u8; libc::IFNAMSIZ];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(buf)
}
```

Add `thiserror = { workspace = true }` to `[dependencies]` as well.

- [ ] **Step 5: Run the test — expect pass**

Run: `cargo test -p yip-device ifname_encodes`
Expected: PASS. The M1 `device_kinds_are_distinct` test still passes. Run `cargo clippy -p yip-device --all-targets -- -D warnings` — clean.

- [ ] **Step 6: Commit**

```bash
git add crates/yip-device/Cargo.toml crates/yip-device/src/lib.rs
git commit -m "Add device flags and interface-name encoding to yip-device

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `yip-device` — `TunTap::create` + `Device` impl (L3 TUN), sudo-gated round-trip

**Files:**
- Modify: `crates/yip-device/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub struct TunTap { file: std::fs::File, kind: DeviceKind, name: String }`
  - `impl TunTap { pub fn create(name: &str, kind: DeviceKind) -> Result<TunTap, DeviceError>; pub fn name(&self) -> &str }`
  - `impl Device for TunTap` (the M1 trait: `kind`, `read_frame`, `write_frame`).

- [ ] **Step 1: Write the failing test (sudo-gated integration)**

```rust
/// Returns true if we can create tunnel devices (root / CAP_NET_ADMIN).
#[cfg(test)]
fn can_create_devices() -> bool {
    TunTap::create("yipcap0", DeviceKind::Tun)
        .map(|d| drop(d))
        .is_ok()
}

#[test]
fn tun_create_roundtrips_a_write() {
    if !can_create_devices() {
        eprintln!("SKIP tun_create_roundtrips_a_write: needs CAP_NET_ADMIN (run under sudo)");
        return;
    }
    let mut dev = TunTap::create("yiptun0", DeviceKind::Tun).unwrap();
    assert_eq!(dev.kind(), DeviceKind::Tun);
    assert_eq!(dev.name(), "yiptun0");
    // Writing a minimal IPv4 packet to the device must not error (kernel accepts the inject).
    let pkt = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 9, 9, 1, 10, 9, 9, 2];
    let n = dev.write_frame(&pkt).unwrap();
    assert_eq!(n, pkt.len());
}
```

- [ ] **Step 2: Run it — expect failure (unprivileged: SKIPs and passes vacuously; that is fine — it must at least compile and not panic)**

Run: `cargo test -p yip-device tun_create`
Expected: FAIL to compile (`TunTap` undefined).

- [ ] **Step 3: Implement `TunTap`**

```rust
use std::os::fd::AsRawFd;

/// A TUN (L3) or TAP (L2) tunnel device.
pub struct TunTap {
    file: std::fs::File,
    kind: DeviceKind,
    name: String,
}

impl TunTap {
    /// Create a tunnel device of `kind` named `name`. Requires `CAP_NET_ADMIN`.
    pub fn create(name: &str, kind: DeviceKind) -> Result<TunTap, DeviceError> {
        let ifname = encode_ifname(name)?;
        let file = std::fs::OpenOptions::new().read(true).write(true).open(TUN_PATH)?;

        // struct ifreq: name[IFNAMSIZ] then a union; we only set ifr_flags.
        #[repr(C)]
        struct IfReq {
            name: [u8; libc::IFNAMSIZ],
            flags: libc::c_short,
            _pad: [u8; 22],
        }
        let type_flag = match kind {
            DeviceKind::Tun => IFF_TUN,
            DeviceKind::Tap => IFF_TAP,
        };
        let mut req = IfReq { name: ifname, flags: type_flag | IFF_NO_PI, _pad: [0; 22] };

        // SAFETY: `req` is a correctly-sized, properly-initialized `ifreq` for TUNSETIFF;
        // the fd is a freshly-opened /dev/net/tun. The kernel reads `req` and writes back
        // the resolved name into the same buffer, which we own exclusively here.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut req as *mut IfReq) };
        if rc != 0 {
            return Err(DeviceError::Io(io::Error::last_os_error()));
        }
        Ok(TunTap { file, kind, name: name.to_owned() })
    }

    /// The interface name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Device for TunTap {
    fn kind(&self) -> DeviceKind {
        self.kind
    }
    fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.file.read(buf)
    }
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<usize> {
        use std::io::Write;
        self.file.write(frame)
    }
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p yip-device` (unprivileged — the integration test SKIPs and passes).
Then, if you have sudo, prove it really works:
Run: `cargo test -p yip-device --no-run` then `sudo -n target/debug/deps/yip_device-*  tun_create_roundtrips_a_write --nocapture` (use the actual test binary path from `--no-run` output).
Expected unprivileged: PASS (with SKIP line). Under sudo: PASS with the write round-trip exercised. `cargo clippy -p yip-device --all-targets -- -D warnings` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-device/src/lib.rs
git commit -m "Implement TUN device create and read/write in yip-device

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `yip-device` — L2 (TAP) create test + MAC-learning note

**Files:**
- Modify: `crates/yip-device/src/lib.rs`

**Interfaces:**
- Consumes: `TunTap::create`.
- Produces: a sudo-gated test proving TAP creation; a doc note that MAC-learning lives in the L2 forwarding path (M6), not the device.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn tap_create_reports_l2_kind() {
    if !can_create_devices() {
        eprintln!("SKIP tap_create_reports_l2_kind: needs CAP_NET_ADMIN (run under sudo)");
        return;
    }
    let dev = TunTap::create("yiptap0", DeviceKind::Tap).unwrap();
    assert_eq!(dev.kind(), DeviceKind::Tap);
    assert_eq!(dev.name(), "yiptap0");
}
```

- [ ] **Step 2: Run it**

Run: `cargo test -p yip-device tap_create`
Expected: PASS (SKIP unprivileged; real create under sudo). The implementation from Task 2 already handles `DeviceKind::Tap` via `IFF_TAP`, so no new code beyond the test — confirm it passes.

- [ ] **Step 3: Add the MAC-learning doc note**

Above `impl Device for TunTap`, add a doc comment:

```rust
// NOTE: a TAP device yields raw Ethernet frames. MAC learning and L2 forwarding
// (bridging frames between peers by destination MAC) belong to the data-plane
// forwarding loop wired in M6, not to the device itself, which is a dumb fd.
```

- [ ] **Step 4: Run + clippy**

Run: `cargo test -p yip-device && cargo clippy -p yip-device --all-targets -- -D warnings`
Expected: pass / clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-device/src/lib.rs
git commit -m "Cover TAP (L2) device creation in yip-device

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `yip-io` — `IoUringIo` backend (send/recv over UDP via the ring)

**Files:**
- Modify: `crates/yip-io/Cargo.toml`
- Modify: `crates/yip-io/src/lib.rs`

**Interfaces:**
- Consumes: `io-uring`.
- Produces:
  - `pub struct IoUringIo { ring: io_uring::IoUring, socket: std::net::UdpSocket }`
  - `impl IoUringIo { pub fn new(socket: std::net::UdpSocket) -> std::io::Result<IoUringIo> }`
  - `impl DataPlaneIo for IoUringIo` (M1 trait: `backend` → `Backend::IoUring`, `send`, `recv`).

- [ ] **Step 1: Write the failing test (caps-free — io_uring over UDP loopback)**

In `crates/yip-io/src/lib.rs` test module:

```rust
#[test]
fn iouring_sends_and_receives_over_udp() {
    use std::net::UdpSocket;
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.connect(rx.local_addr().unwrap()).unwrap();
    rx.connect(tx.local_addr().unwrap()).unwrap();

    let mut tx_io = IoUringIo::new(tx).unwrap();
    let mut rx_io = IoUringIo::new(rx).unwrap();
    assert_eq!(tx_io.backend(), Backend::IoUring);

    tx_io.send(b"datagram via uring").unwrap();
    let mut buf = [0u8; 64];
    let n = rx_io.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"datagram via uring");
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cargo test -p yip-io iouring_sends`
Expected: FAIL (`IoUringIo` undefined).

- [ ] **Step 3: Add the dep**

`crates/yip-io/Cargo.toml` `[dependencies]`:

```toml
[dependencies]
io-uring = "0.7.10"
```

- [ ] **Step 4: Implement `IoUringIo`**

Add to `crates/yip-io/src/lib.rs` (the crate already permits `unsafe`):

```rust
use io_uring::{opcode, types, IoUring};
use std::io;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

/// A `DataPlaneIo` backend that submits Read/Write ops on a connected UDP
/// socket through an `io_uring` ring.
pub struct IoUringIo {
    ring: IoUring,
    socket: UdpSocket,
}

impl IoUringIo {
    /// Wrap a (connected) UDP socket with an io_uring ring.
    pub fn new(socket: UdpSocket) -> io::Result<IoUringIo> {
        let ring = IoUring::new(8)?;
        Ok(IoUringIo { ring, socket })
    }

    fn submit_and_reap(&mut self, entry: &io_uring::squeue::Entry) -> io::Result<usize> {
        // SAFETY: the buffer referenced by `entry` is owned by the caller and outlives
        // this call — we submit and wait for completion before returning, so the kernel
        // is done with the buffer by the time we hand control back.
        unsafe {
            self.ring
                .submission()
                .push(entry)
                .map_err(|_| io::Error::other("submission queue full"))?;
        }
        self.ring.submit_and_wait(1)?;
        let cqe = self
            .ring
            .completion()
            .next()
            .ok_or_else(|| io::Error::other("missing completion"))?;
        let res = cqe.result();
        if res < 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }
        Ok(usize::try_from(res).expect("non-negative result fits usize"))
    }
}

impl DataPlaneIo for IoUringIo {
    fn backend(&self) -> Backend {
        Backend::IoUring
    }

    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        let len = u32::try_from(datagram.len())
            .map_err(|_| io::Error::other("datagram too large"))?;
        let entry = opcode::Write::new(types::Fd(self.socket.as_raw_fd()), datagram.as_ptr(), len)
            .build()
            .user_data(0);
        self.submit_and_reap(&entry)?;
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = u32::try_from(buf.len()).map_err(|_| io::Error::other("buffer too large"))?;
        let entry = opcode::Read::new(types::Fd(self.socket.as_raw_fd()), buf.as_mut_ptr(), len)
            .build()
            .user_data(1);
        self.submit_and_reap(&entry)
    }
}
```

- [ ] **Step 5: Run the test — expect pass**

Run: `cargo test -p yip-io iouring_sends`
Expected: PASS. Then `cargo clippy -p yip-io --all-targets -- -D warnings` — clean (note: the two `as`-free conversions use `try_from`; the only remaining raw casts, if any, must carry a justification comment).

- [ ] **Step 6: Commit**

```bash
git add crates/yip-io/Cargo.toml crates/yip-io/src/lib.rs
git commit -m "Implement io_uring DataPlaneIo backend in yip-io

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `yip-io` — `PlainIo` fallback + `select_backend` probe

**Files:**
- Modify: `crates/yip-io/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub struct PlainIo { socket: std::net::UdpSocket }` + `impl DataPlaneIo` (backend → `Backend::Mmsg`, send/recv via std socket).
  - `pub fn select_backend(socket: std::net::UdpSocket) -> Box<dyn DataPlaneIo>` — returns `IoUringIo` if the ring builds, else `PlainIo`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn plain_io_sends_and_receives() {
    use std::net::UdpSocket;
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.connect(rx.local_addr().unwrap()).unwrap();
    rx.connect(tx.local_addr().unwrap()).unwrap();
    let mut t = PlainIo::new(tx);
    let mut r = PlainIo::new(rx);
    assert_eq!(t.backend(), Backend::Mmsg);
    t.send(b"plain path").unwrap();
    let mut buf = [0u8; 32];
    let n = r.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"plain path");
}

#[test]
fn select_backend_prefers_io_uring_when_available() {
    use std::net::UdpSocket;
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let io = select_backend(s);
    // On any modern kernel (CI included) io_uring builds, so we expect it.
    assert_eq!(io.backend(), Backend::IoUring);
}
```

- [ ] **Step 2: Run them — expect failure**

Run: `cargo test -p yip-io plain_io select_backend`
Expected: FAIL (`PlainIo`/`select_backend` undefined).

- [ ] **Step 3: Implement**

```rust
/// A portable fallback backend over a plain (connected) UDP socket.
pub struct PlainIo {
    socket: UdpSocket,
}

impl PlainIo {
    /// Wrap a connected UDP socket.
    pub fn new(socket: UdpSocket) -> PlainIo {
        PlainIo { socket }
    }
}

impl DataPlaneIo for PlainIo {
    fn backend(&self) -> Backend {
        Backend::Mmsg
    }
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.socket.send(datagram).map(|_| ())
    }
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf)
    }
}

/// Choose the lowest-latency backend that initializes: io_uring if its ring
/// builds on this kernel, else the portable plain-socket fallback.
pub fn select_backend(socket: UdpSocket) -> Box<dyn DataPlaneIo> {
    match IoUringIo::new(socket.try_clone().expect("clone udp socket")) {
        Ok(io) => Box::new(io),
        Err(_) => Box::new(PlainIo::new(socket)),
    }
}
```

Note: `select_backend` clones the socket fd so that on the io_uring path the original is dropped and the ring owns its clone; on fallback the original is used. Both refer to the same underlying socket. If the clone semantics complicate ownership, simplify by having `select_backend` build the ring first and only construct `PlainIo` from `socket` on the error path (move `socket` into whichever backend wins) — the implementer should pick the cleaner ownership that compiles without `try_clone` if possible.

- [ ] **Step 4: Run the tests — expect pass**

Run: `cargo test -p yip-io`
Expected: all pass. `cargo clippy -p yip-io --all-targets -- -D warnings` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/lib.rs
git commit -m "Add plain-socket fallback and backend selection to yip-io

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: coverage, sudo integration CI job, changelog, full gate

**Files:**
- Create: `.github/workflows/integration.yml`
- Modify: `CHANGELOG.md`
- Modify: `.github/workflows/coverage.yml`

**Interfaces:**
- Consumes: the full `yip-io`/`yip-device` suites.
- Produces: a sudo-gated integration CI job that exercises the device tests; `yip-io` ≥90% coverage; `yip-device` added to the coverage exclusion (privileged path); a changelog entry.

- [ ] **Step 1: Verify `yip-io` coverage**

Run: `cargo llvm-cov --package yip-io --fail-under-lines 90 --summary-only`
Expected: exits 0 (the io_uring + plain paths are exercised caps-free). If under 90%, add a focused test for the uncovered branch (e.g. `send` of an oversized datagram returning an error, or `recv` error mapping) and re-run.

- [ ] **Step 2: Exclude `yip-device` from the hermetic coverage gate**

In `.github/workflows/coverage.yml`, add `--exclude yip-device` to the existing `cargo llvm-cov` command (alongside the existing `--exclude yip-io`... — wait: `yip-io` is now testable, so REMOVE `yip-io` from the excludes and ADD `yip-device`). The command becomes:

```yaml
      - name: Coverage (logic + io_uring crates)
        run: >
          cargo llvm-cov --workspace
          --exclude yip-device --exclude yipd
          --fail-under-lines 90 --summary-only
```

(`yip-device`'s privileged create/read/write lines can't run in hermetic CI; it's covered by the sudo integration job below. `yip-io` is now included in the gate.)

- [ ] **Step 3: Add the sudo integration CI job**

Create `.github/workflows/integration.yml`:

```yaml
---
name: Integration (privileged)
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  device-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Build device tests
        run: cargo test -p yip-device --no-run
      - name: Run device tests under sudo (CAP_NET_ADMIN)
        run: |
          BIN=$(cargo test -p yip-device --no-run --message-format=json \
            | jq -r 'select(.profile.test == true and (.target.name == "yip-device")) | .executable' \
            | head -n1)
          echo "running $BIN under sudo"
          sudo -E "$BIN" --nocapture
```

Note: GitHub-hosted Ubuntu runners provide passwordless `sudo` and allow TUN/TAP creation, so the device round-trip tests actually execute here (they SKIP only in unprivileged environments).

- [ ] **Step 4: Add the changelog entry**

Under `## [Unreleased]` → `### Added` in `CHANGELOG.md`:

```markdown
- `yip-device` TUN (L3) and TAP (L2) tunnel devices, and `yip-io` io_uring
  DataPlaneIo backend with a portable plain-socket fallback.
```

- [ ] **Step 5: Full local gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo shear && cargo deny check`
Expected: all clean/pass. (`io-uring` and `libc` are real used deps — no shear-ignore needed.)

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/integration.yml .github/workflows/coverage.yml CHANGELOG.md
git commit -m "Add sudo device-integration CI job and record M4 in changelog

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (M4 slice):** TUN (L3) device ✓ (T2); TAP (L2) device ✓ (T3); io_uring `DataPlaneIo` backend ✓ (T4); portable fallback + backend selection ✓ (T5); coverage + honest-exclusion of the privileged `yip-device` path with a sudo CI job that actually runs it ✓ (T6). Deferred-by-design (noted, not gaps): the single ring servicing BOTH the UDP and TUN fds in one busy-poll loop, GSO/GRO batching, and AF_XDP zero-copy are the *unified tunnel loop* + perf work wired in M6 / the AF_XDP follow-on; M4 delivers the two I/O crates as independently-tested units. MAC-learning/L2-forwarding is M6 (noted in T3).

**Placeholder scan:** every code/command step uses the spiked-and-verified `io-uring`/`libc`/TUN API. The `select_backend` ownership note in T5 gives the implementer explicit latitude to pick the cleaner compiling form — that is guidance, not a placeholder.

**Type consistency:** `DeviceKind`/`Device` (from M1) used by `TunTap`; `DataPlaneIo`/`Backend` (from M1) used by `IoUringIo`/`PlainIo`; `DeviceError` and `encode_ifname` shared across device tasks. `Backend::IoUring`/`Backend::Mmsg` match the M1 enum.

**Unsafe audit:** exactly two `unsafe` sites — the `ioctl` in `TunTap::create` and the `submission().push` in `IoUringIo::submit_and_reap` — each with a `// SAFETY:` comment. `yip-device` drops `forbid(unsafe_code)`; the three protocol crates keep it.

**Definition of done for M4:** `cargo test --workspace` green; `yip-io` ≥90% covered; device tests pass (SKIP unprivileged, run for real under sudo in the integration job); whole-workspace fmt/clippy/shear/deny green; CI (incl. the new privileged job) passes on push.
