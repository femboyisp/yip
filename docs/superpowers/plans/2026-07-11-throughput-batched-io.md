# Batched UDP I/O (sendmmsg/recvmmsg) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Batch the UDP send/recv on the default poll hot path with `sendmmsg`/`recvmmsg` so per-packet I/O syscalls collapse into per-burst syscalls, cutting I/O toward ~0.1–0.3 µs/packet.

**Architecture:** Add two addressed batch-syscall free functions in `crates/yip-io/src/poll.rs` (`send_mmsg` carries per-datagram `dst`, `recv_mmsg` captures per-datagram `src`), then rewrite `drain_udp` to `recv_mmsg` the rx burst and `drain_tun` to accumulate a TUN burst's egress symbols into one `send_mmsg`. Opportunistic and latency-neutral — batch only what's already queued.

**Tech Stack:** Rust, `libc` (`sendmmsg`/`recvmmsg`), the existing epoll `run_poll` loop.

**Spec:** `docs/superpowers/specs/2026-07-11-throughput-batched-io-design.md`.

## Global Constraints

- `unsafe` is permitted ONLY in `yip-io`/`yip-device`; all new syscall code lives in `crates/yip-io/src/poll.rs`, each `unsafe` block with a `// SAFETY:` comment (existing convention). `yipd` stays `#![forbid(unsafe_code)]`.
- No `as` numeric casts except enum discriminants — use `try_from`/`from` (the existing code uses `u32::try_from`, `usize::try_from`; `x as u32`-style is only used for the pointer/fd casts the libc ABI requires — mirror the file's existing pattern).
- **Latency-neutral:** never wait to fill a batch — drain whatever the burst already holds. A single ready packet still does one recv + one send syscall.
- **No GSO / no coalescing:** each datagram is its own independent UDP packet (`sendmmsg`, not `UDP_SEGMENT`), so FEC symbol loss-independence is preserved. `EgressDatagram.fate` is irrelevant here.
- Batch cap = `MAX_DATAGRAM_BATCH` (existing const = 64). Handle partial `sendmmsg` (loop remainder) and `recvmmsg` (fewer than requested = burst drained).
- **Poll path only:** `uring.rs` and the QUIC `run_quic` path are untouched.
- Preserve the `Dispatch` trait + `EgressDatagram` type (read `dst`/`bytes` off existing fields; no type changes).
- `refrences/` is read-only.

---

## File Structure

- `crates/yip-io/src/poll.rs` — **modify.** Add `send_mmsg(udp_fd, &[EgressDatagram]) -> io::Result<usize>` and `recv_mmsg(udp_fd, bufs, lens, srcs) -> io::Result<usize>` (co-located with `EgressDatagram` + the existing `recvfrom`/`sendto` code + the `sockaddr_to_std`/`std_to_sockaddr` helpers). Rewrite `drain_udp`/`drain_tun`; add reusable buffers to `run_poll`.
- `crates/yip-bench/RESULTS.md` — **modify (Task 3).** iperf before/after.

---

### Task 1: Addressed `send_mmsg` / `recv_mmsg` in `poll.rs`

**Files:**
- Modify: `crates/yip-io/src/poll.rs`

**Interfaces:**
- Consumes: `crate::{MAX_WIRE_DATAGRAM, sockaddr_to_std, std_to_sockaddr}` (already imported at the top of poll.rs), `crate::MAX_DATAGRAM_BATCH` (add to the `use crate::{...}` line), `EgressDatagram` (same module), `std::os::fd::RawFd`.
- Produces:
  - `fn send_mmsg(udp_fd: RawFd, datagrams: &[EgressDatagram]) -> io::Result<usize>` — one `sendmmsg`, each datagram to its own `dst`; returns count accepted (≤ `datagrams.len().min(64)`).
  - `fn recv_mmsg(udp_fd: RawFd, bufs: &mut [[u8; MAX_WIRE_DATAGRAM]], lens: &mut [usize], srcs: &mut [SocketAddr]) -> io::Result<usize>` — one non-blocking `recvmmsg`; fills `bufs`/`lens`/`srcs[0..n]`; returns `n` (0 if none ready). Errors: maps `EWOULDBLOCK`/`EAGAIN` to `Ok(0)`.

- [ ] **Step 1: Write the failing tests**

Add to `crates/yip-io/src/poll.rs`'s `#[cfg(test)] mod tests` (there is one already — the existing `drain_udp_*` tests live there):

```rust
#[test]
fn send_mmsg_delivers_each_datagram_to_its_own_dst() {
    use std::net::UdpSocket;
    // Two receiver sockets on distinct ports; one sender.
    let rx_a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rx_b = UdpSocket::bind("127.0.0.1:0").unwrap();
    rx_a.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    rx_b.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dst_a = rx_a.local_addr().unwrap();
    let dst_b = rx_b.local_addr().unwrap();

    let batch = vec![
        EgressDatagram { fate: 0, dst: dst_a, bytes: b"to-a-1".to_vec() },
        EgressDatagram { fate: 0, dst: dst_b, bytes: b"to-b".to_vec() },
        EgressDatagram { fate: 0, dst: dst_a, bytes: b"to-a-2".to_vec() },
    ];
    let mut sent = 0;
    while sent < batch.len() {
        sent += send_mmsg(tx.as_raw_fd(), &batch[sent..]).unwrap();
    }
    assert_eq!(sent, 3);

    let mut buf = [0u8; 64];
    // rx_a receives two datagrams (order preserved within a dst).
    let (n1, _) = rx_a.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n1], b"to-a-1");
    let (n2, _) = rx_a.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n2], b"to-a-2");
    // rx_b receives its one.
    let (n3, _) = rx_b.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n3], b"to-b");
}

#[test]
fn recv_mmsg_returns_bytes_and_source_per_datagram() {
    use std::net::UdpSocket;
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rx_addr = rx.local_addr().unwrap();
    let tx_addr = tx.local_addr().unwrap();
    tx.send_to(b"hello", rx_addr).unwrap();
    tx.send_to(b"world!!", rx_addr).unwrap();
    // Give the datagrams time to queue, then drain non-blocking.
    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut bufs = [[0u8; MAX_WIRE_DATAGRAM]; 4];
    let mut lens = [0usize; 4];
    let mut srcs = [std::net::SocketAddr::from(([0, 0, 0, 0], 0)); 4];
    let n = recv_mmsg(rx.as_raw_fd(), &mut bufs, &mut lens, &mut srcs).unwrap();
    assert_eq!(n, 2);
    assert_eq!(&bufs[0][..lens[0]], b"hello");
    assert_eq!(&bufs[1][..lens[1]], b"world!!");
    assert_eq!(srcs[0], tx_addr);
    assert_eq!(srcs[1], tx_addr);
}

#[test]
fn recv_mmsg_returns_zero_when_nothing_queued() {
    use std::net::UdpSocket;
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut bufs = [[0u8; MAX_WIRE_DATAGRAM]; 4];
    let mut lens = [0usize; 4];
    let mut srcs = [std::net::SocketAddr::from(([0, 0, 0, 0], 0)); 4];
    assert_eq!(recv_mmsg(rx.as_raw_fd(), &mut bufs, &mut lens, &mut srcs).unwrap(), 0);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-io --lib send_mmsg recv_mmsg`
Expected: FAIL to compile (`send_mmsg`/`recv_mmsg` not defined).

- [ ] **Step 3: Implement the two functions**

Add `MAX_DATAGRAM_BATCH` to the poll.rs imports: change `use crate::{sockaddr_to_std, std_to_sockaddr, MAX_WIRE_DATAGRAM};` to `use crate::{sockaddr_to_std, std_to_sockaddr, MAX_DATAGRAM_BATCH, MAX_WIRE_DATAGRAM};`. Then add these functions to `poll.rs` (near `send_to_udp`):

```rust
/// Send up to `datagrams.len().min(MAX_DATAGRAM_BATCH)` datagrams in one
/// `sendmmsg(2)`, each to its own [`EgressDatagram::dst`]. Returns the count the
/// kernel accepted (may be fewer; the caller loops the remainder).
fn send_mmsg(udp_fd: RawFd, datagrams: &[EgressDatagram]) -> io::Result<usize> {
    if datagrams.is_empty() {
        return Ok(0);
    }
    let count = datagrams.len().min(MAX_DATAGRAM_BATCH);

    // Parallel per-datagram arrays; all live on this stack frame until sendmmsg
    // returns, so the pointers stored in `msgs` stay valid across the syscall.
    // SAFETY: `sockaddr_storage` is plain-old-data; an all-zero value is a valid
    // (unspecified) initial state that we fully overwrite per datagram below.
    let mut storages: [libc::sockaddr_storage; MAX_DATAGRAM_BATCH] =
        unsafe { std::mem::zeroed() };
    let mut addrlens = [0 as libc::socklen_t; MAX_DATAGRAM_BATCH];
    let mut iovecs = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; MAX_DATAGRAM_BATCH];
    let mut msgs = [libc::mmsghdr {
        msg_hdr: libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        },
        msg_len: 0,
    }; MAX_DATAGRAM_BATCH];

    for (i, dg) in datagrams[..count].iter().enumerate() {
        let (storage, addr_len) = std_to_sockaddr(dg.dst);
        storages[i] = storage;
        addrlens[i] = addr_len;
        // SAFETY: cast a shared slice to *mut c_void for the iovec ABI; sendmmsg
        // only reads through iov_base. `dg.bytes` outlives the syscall (borrowed
        // for this fn).
        iovecs[i].iov_base = dg.bytes.as_ptr().cast_mut().cast::<libc::c_void>();
        iovecs[i].iov_len = dg.bytes.len();
        msgs[i].msg_hdr.msg_iov = &raw mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = std::ptr::from_mut(&mut storages[i]).cast::<libc::c_void>();
        msgs[i].msg_hdr.msg_namelen = addrlens[i];
    }

    // SAFETY: `msgs[..count]` is fully initialised; each msg_iov/msg_name points
    // into `iovecs`/`storages` on this frame, valid until sendmmsg returns.
    // MSG_NOSIGNAL suppresses SIGPIPE on a closed peer.
    let ret = unsafe {
        libc::sendmmsg(
            udp_fd,
            msgs.as_mut_ptr(),
            u32::try_from(count).expect("count ≤ 64 fits u32"),
            libc::MSG_NOSIGNAL,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        let raw = e.raw_os_error().unwrap_or(0);
        // Transient full send buffer: report 0 sent (caller drops this burst's tail).
        if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN || raw == libc::ENOBUFS {
            return Ok(0);
        }
        return Err(e);
    }
    Ok(usize::try_from(ret).expect("non-negative sendmmsg return fits usize"))
}

/// Non-blocking `recvmmsg(2)`: drain up to `bufs.len().min(MAX_DATAGRAM_BATCH)`
/// queued datagrams in one syscall, writing each datagram's byte count into
/// `lens` and source address into `srcs`. Returns the count received (0 if the
/// socket is momentarily empty). Requires a non-blocking `udp_fd`.
fn recv_mmsg(
    udp_fd: RawFd,
    bufs: &mut [[u8; MAX_WIRE_DATAGRAM]],
    lens: &mut [usize],
    srcs: &mut [SocketAddr],
) -> io::Result<usize> {
    let count = bufs.len().min(lens.len()).min(srcs.len()).min(MAX_DATAGRAM_BATCH);
    if count == 0 {
        return Ok(0);
    }
    // SAFETY: all-zero sockaddr_storage is a valid initial out-buffer that
    // recvmmsg fills; we read it back only for the datagrams it reports received.
    let mut storages: [libc::sockaddr_storage; MAX_DATAGRAM_BATCH] =
        unsafe { std::mem::zeroed() };
    let mut addrlens =
        [libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
            .expect("size fits socklen_t"); MAX_DATAGRAM_BATCH];
    let mut iovecs = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; MAX_DATAGRAM_BATCH];
    let mut msgs = [libc::mmsghdr {
        msg_hdr: libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        },
        msg_len: 0,
    }; MAX_DATAGRAM_BATCH];

    for i in 0..count {
        // SAFETY: each iov_base/msg_name points to a distinct element of
        // `bufs`/`storages` on this frame — no aliasing — valid until recvmmsg returns.
        iovecs[i].iov_base = bufs[i].as_mut_ptr().cast::<libc::c_void>();
        iovecs[i].iov_len = MAX_WIRE_DATAGRAM;
        msgs[i].msg_hdr.msg_iov = &raw mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = std::ptr::from_mut(&mut storages[i]).cast::<libc::c_void>();
        msgs[i].msg_hdr.msg_namelen = addrlens[i];
    }

    // SAFETY: `msgs[..count]` fully initialised; msg_iov/msg_name point into
    // distinct `bufs`/`storages` elements. MSG_DONTWAIT: non-blocking (the fd is
    // epoll-ready); null timeout. On empty socket, returns EWOULDBLOCK → Ok(0).
    let ret = unsafe {
        libc::recvmmsg(
            udp_fd,
            msgs.as_mut_ptr(),
            u32::try_from(count).expect("count ≤ 64 fits u32"),
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        let raw = e.raw_os_error().unwrap_or(0);
        if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN {
            return Ok(0);
        }
        return Err(e);
    }
    let received = usize::try_from(ret).expect("non-negative recvmmsg return fits usize");
    for i in 0..received {
        lens[i] = usize::try_from(msgs[i].msg_len).expect("msg_len fits usize");
        // recvmmsg writes the actual namelen back into each msg_hdr.
        srcs[i] = sockaddr_to_std(&storages[i], msgs[i].msg_hdr.msg_namelen)
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    }
    Ok(received)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p yip-io --lib`
Expected: PASS (the 3 new tests + all existing yip-io tests).
Run: `cargo clippy -p yip-io --all-targets -- -D warnings && cargo fmt -p yip-io -- --check`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/poll.rs
git commit -m "feat(yip-io): addressed send_mmsg/recv_mmsg (per-datagram dst/src)"
```

---

### Task 2: Wire batching into `drain_udp` / `drain_tun`

**Files:**
- Modify: `crates/yip-io/src/poll.rs`

**Interfaces:**
- Consumes: `send_mmsg`/`recv_mmsg` from Task 1; `Dispatch`, `EgressDatagram`, `DispatchOut`, `send_to_tun`, `send_to_udp` (existing).
- Produces: batched `drain_udp`/`drain_tun` with the same external behavior (same datagrams to the wire, same TUN writes), fewer syscalls. `run_poll` owns reusable batch buffers.

- [ ] **Step 1: Rewrite `drain_udp` to use `recv_mmsg`**

Replace the body of `drain_udp` (poll.rs:102-179) with a batched drain. It takes the reusable buffers as params (allocated in `run_poll`):

```rust
/// Drain pending datagrams from `udp_fd` with `recvmmsg`, dispatching each and
/// forwarding the outcome. Loops until the socket is empty (recv_mmsg returns 0).
fn drain_udp(
    udp_fd: RawFd,
    tun_fd: RawFd,
    d: &mut impl Dispatch,
    now_ms: u64,
    bufs: &mut [[u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH],
    lens: &mut [usize; MAX_DATAGRAM_BATCH],
    srcs: &mut [SocketAddr; MAX_DATAGRAM_BATCH],
    tx: &mut Vec<EgressDatagram>,
) -> io::Result<()> {
    loop {
        let n = recv_mmsg(udp_fd, bufs, lens, srcs)?;
        if n == 0 {
            break; // socket drained
        }
        for i in 0..n {
            let dg = &bufs[i][..lens[i]];
            match d.on_udp(srcs[i], dg, now_ms) {
                DispatchOut::None => {}
                DispatchOut::Tun(inner) => send_to_tun(tun_fd, inner),
                DispatchOut::Udp(pkts) => tx.extend(pkts.iter().cloned()),
                DispatchOut::Both(inner, pkts) => {
                    send_to_tun(tun_fd, inner);
                    tx.extend(pkts.iter().cloned());
                }
            }
        }
        flush_tx(udp_fd, tx)?; // send any UDP replies for this recv burst
        if n < MAX_DATAGRAM_BATCH {
            break; // partial batch → socket drained
        }
    }
    Ok(())
}
```

- [ ] **Step 2: Rewrite `drain_tun` to accumulate + `send_mmsg`, and add `flush_tx`**

Replace `drain_tun` (poll.rs:183-218). It reads the TUN burst per-packet, accumulates all egress into `tx`, flushing whenever it reaches the batch cap and once at the end:

```rust
/// Drain pending TUN frames, accumulating each frame's egress datagrams into `tx`
/// and flushing them with `send_mmsg` (chunked at the batch cap).
fn drain_tun(
    tun_fd: RawFd,
    udp_fd: RawFd,
    d: &mut impl Dispatch,
    now_ms: u64,
    tx: &mut Vec<EgressDatagram>,
) -> io::Result<()> {
    let mut buf = [0u8; MAX_WIRE_DATAGRAM];
    loop {
        // SAFETY: `buf` is a valid stack buffer; `tun_fd` is a valid non-blocking
        // TUN fd. TUN is not a socket, so we `read` rather than `recv`.
        let n = unsafe { libc::read(tun_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            let raw = e.raw_os_error().unwrap_or(0);
            if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN {
                break;
            }
            if raw == libc::EINTR {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            break;
        }
        let inner = &buf[..usize::try_from(n).expect("non-negative read return fits usize")];
        tx.extend(d.on_tun(inner, now_ms).iter().cloned());
        if tx.len() >= MAX_DATAGRAM_BATCH {
            flush_tx(udp_fd, tx)?;
        }
    }
    flush_tx(udp_fd, tx)?; // send the burst's remaining egress
    Ok(())
}

/// Send everything queued in `tx` via `send_mmsg` (looping over partial sends and
/// batch-cap chunks), then clear it. A momentarily-full send buffer drops the tail
/// (same acceptable single-packet loss as the old per-datagram `send_to_udp`).
fn flush_tx(udp_fd: RawFd, tx: &mut Vec<EgressDatagram>) -> io::Result<()> {
    let mut sent = 0;
    while sent < tx.len() {
        let n = send_mmsg(udp_fd, &tx[sent..])?;
        if n == 0 {
            break; // send buffer full — drop the rest of this burst
        }
        sent += n;
    }
    tx.clear();
    Ok(())
}
```

- [ ] **Step 3: Give `run_poll` the reusable buffers and thread them in**

In `run_poll` (poll.rs:287+), before the `loop {`, allocate the reusable buffers once:

```rust
    // Reusable batch buffers (one allocation for the loop's lifetime).
    let mut rx_bufs = Box::new([[0u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH]);
    let mut rx_lens = [0usize; MAX_DATAGRAM_BATCH];
    let mut rx_srcs = [SocketAddr::from(([0, 0, 0, 0], 0)); MAX_DATAGRAM_BATCH];
    let mut tx_batch: Vec<EgressDatagram> = Vec::with_capacity(MAX_DATAGRAM_BATCH);
```

(`rx_bufs` is `Box`ed — `[[u8; 2048]; 64]` is 128 KiB, too large for the loop's stack frame.) Update the two call sites in the event loop:

```rust
            if ready_fd == udp_fd {
                if let Err(e) = drain_udp(
                    udp_fd, tun_fd, d, now_ms,
                    &mut rx_bufs, &mut rx_lens, &mut rx_srcs, &mut tx_batch,
                ) { unsafe { libc::close(epoll_fd) }; return Err(e); }
            } else if ready_fd == tun_fd {
                if let Err(e) = drain_tun(tun_fd, udp_fd, d, now_ms, &mut tx_batch) {
                    unsafe { libc::close(epoll_fd) }; return Err(e);
                }
            }
```

And the `tick` egress at poll.rs:376 — send its datagrams via the batch too:

```rust
        if let Some(pkts) = d.tick(now_ms) {
            tx_batch.extend(pkts.iter().cloned());
            if let Err(e) = flush_tx(udp_fd, &mut tx_batch) {
                unsafe { libc::close(epoll_fd) }; return Err(e);
            }
        }
```

(Replace the existing `for pkt in pkts { send_to_udp(...) }` tick loop.)

- [ ] **Step 4: Update the existing poll tests to the new call shape**

The existing `drain_udp_*` / TUN-egress tests call `drain_udp`/`drain_tun` directly with the old signatures. Update each call site to pass the new buffer params (construct them locally in the test), WITHOUT weakening what the test asserts (they still verify a datagram is delivered / forwarded). For a `drain_udp` test, add:

```rust
    let mut bufs = Box::new([[0u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH]);
    let mut lens = [0usize; MAX_DATAGRAM_BATCH];
    let mut srcs = [std::net::SocketAddr::from(([0, 0, 0, 0], 0)); MAX_DATAGRAM_BATCH];
    let mut tx = Vec::new();
    drain_udp(udp_fd, tun_fd, &mut d, 0, &mut bufs, &mut lens, &mut srcs, &mut tx).unwrap();
```

and for `drain_tun` tests: `let mut tx = Vec::new(); drain_tun(tun_fd, udp_fd, &mut d, 0, &mut tx).unwrap();`. Note the recv tests may need the udp_fd set non-blocking (the tests bind real sockets — `set_nonblocking(true)` on the receiver fd before `drain_udp`, since `recv_mmsg` uses `MSG_DONTWAIT` and the drain loop relies on `Ok(0)` to stop).

- [ ] **Step 5: Run tests + lints**

Run: `cargo test -p yip-io`
Expected: PASS — the Task-1 mmsg tests, the updated `drain_udp`/`drain_tun` tests, and all other yip-io tests.
Run: `cargo build --workspace` (yipd's `run_poll` call is unchanged — same signature).
Run: `cargo clippy -p yip-io --all-targets -- -D warnings && cargo fmt -p yip-io -- --check`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/yip-io/src/poll.rs
git commit -m "perf(yip-io): batch UDP send/recv on the poll hot path (sendmmsg/recvmmsg)

drain_udp drains the rx burst with one recvmmsg; drain_tun accumulates a TUN
burst's egress symbols into one sendmmsg. Opportunistic/latency-neutral, no GSO
(FEC symbol independence preserved), reusable buffers, poll-path only."
```

---

### Task 3: Throughput benchmark + netns no-regression

**Files:**
- Modify: `crates/yip-bench/RESULTS.md`
- Run-only: `crates/yip-bench/tests/run-iperf-compare.sh` (or the netem/iperf harness), `bin/yipd/tests/run-netns-*.sh`.

**Interfaces:** Consumes the batched poll loop via the release `yipd` binary (unchanged `run_poll` API).

- [ ] **Step 1: Build release + capture the throughput before/after**

Run: `cargo build --release`
Run the single-core iperf throughput harness (`crates/yip-bench/tests/run-iperf-compare.sh`, needs sudo/netns). Capture the TCP Mbit/s. The "before" number is the pre-batching baseline recorded in `RESULTS.md` (prior runs ~355 Mbit/s raw; after levers 1–2 the FEC/AEAD are cheap so I/O now dominates); the "after" is this run. If the harness needs a yipd path arg, pass `target/release/yipd`.

- [ ] **Step 2: Record results**

Append a dated "Batched UDP I/O (sendmmsg/recvmmsg)" section to `crates/yip-bench/RESULTS.md`: single-core TCP throughput before vs after, and the takeaway (per-packet UDP syscalls collapsed to per-burst; I/O no longer the single-core bottleneck).

- [ ] **Step 3: No-regression — full suite + netns**

Run: `cargo test`
Expected: all green.
Run the FEC-exercising netns tests (batched sends must still recover loss end-to-end):

```bash
cargo build --release
for s in run-netns-tunnel run-netns-tunnel-loss run-netns-tunnel-l2 run-arq-integrity; do
  echo "== $s =="; sudo bin/yipd/tests/$s.sh target/release/yipd || echo "FAILED: $s"
done
```
Expected: each PASS — a session establishes and passes traffic; the loss variant proves FEC still recovers with batched sends (each datagram is its own UDP packet, so loss-independence holds); ARQ intact. If sudo/netns unavailable, record skipped-for-environment truthfully; the yip-io unit tests + preserved drain tests are the correctness guarantee.

- [ ] **Step 4: Commit**

```bash
git add crates/yip-bench/RESULTS.md
git commit -m "bench(throughput): record batched-I/O single-core throughput + no-regression"
```

---

## Self-Review

**1. Spec coverage:**
- §3.1 addressed `send_mmsg`/`recv_mmsg` → Task 1. ✅
- §3.2 `drain_udp` via recvmmsg → Task 2 Step 1. ✅
- §3.3 `drain_tun` accumulate + sendmmsg (chunked at cap) → Task 2 Step 2. ✅
- §3.4 reusable buffers in `run_poll` → Task 2 Step 3. ✅
- §4 invariants: latency-neutral (drain-what's-ready, no wait), FEC independence (separate datagrams, no GSO), unsafe-in-yip-io, partial send/recv handled → Task 1/2 code + constraints. ✅
- §5 tests (addressed-mmsg unit, preserved poll tests, netns iperf + loss/arq) → Tasks 1–3. ✅
- §6 scope (poll only; uring/quic untouched) → not in any task's file list beyond poll.rs. ✅

**2. Placeholder scan:** No TBD/TODO; every code step carries complete code (the mmsg unsafe bodies, the drain rewrites, the buffer wiring, the tests).

**3. Type consistency:** `send_mmsg(RawFd, &[EgressDatagram]) -> io::Result<usize>`, `recv_mmsg(RawFd, &mut [[u8; MAX_WIRE_DATAGRAM]; …], &mut [usize; …], &mut [SocketAddr; …]) -> io::Result<usize>`, `flush_tx(RawFd, &mut Vec<EgressDatagram>)`, and the `drain_udp`/`drain_tun` new signatures are used consistently across Task 2's call-site edits and the test updates. `MAX_DATAGRAM_BATCH`/`MAX_WIRE_DATAGRAM`/`sockaddr_to_std`/`std_to_sockaddr`/`SocketAddr` all exist (imports adjusted in Task 1 Step 3).
