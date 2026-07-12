//! Single-threaded epoll-driven event loop for the yip data plane.
//!
//! `run_poll` drives both the UDP socket and TUN fd from a single OS thread,
//! eliminating the need for `Arc<Mutex<...>>` across two threads.  The caller
//! provides a [`Dispatch`] implementor that owns all mutable data-plane state.
//!
//! This module contains all Linux `epoll`/`fcntl` unsafe code for yipd.  Every
//! `unsafe` block carries a `// SAFETY:` comment explaining the invariants.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::time::Instant;

use crate::{sockaddr_to_std, std_to_sockaddr, MAX_DATAGRAM_BATCH, MAX_WIRE_DATAGRAM};

/// `UDP_SEGMENT` cmsg payload is a single `u16` (the segment size).
const GSO_CONTROL_PAYLOAD_LEN: u32 = 2;
/// Control-message scratch space for one `UDP_SEGMENT` cmsg.
const GSO_CONTROL_SPACE: usize = 64;

/// A single-threaded data-plane dispatch interface.
///
/// Implementors hold all mutable state (AEAD session, FEC transport, codec,
/// auxiliary logs).  [`run_poll`] drives this trait from an `epoll` loop.
///
/// # Addressing (multipeer 2a seam)
///
/// `on_udp` is told the datagram's source address and every egress datagram
/// carries its own destination (see [`EgressDatagram::dst`]), so a future
/// multi-peer `Dispatch` can route by address. A single-peer implementor is
/// free to ignore `src` and stamp a fixed `dst` on everything it emits —
/// exactly what [`crate::poll`]'s test dispatches below do, and what
/// `yipd`'s `DataPlane` does until the Task 5 `PeerManager` lands.
pub trait Dispatch {
    /// Called when a UDP datagram arrives, with the address it came from.
    /// Returns what [`run_poll`] must forward (to TUN, back to UDP, both, or
    /// nothing).
    fn on_udp(&mut self, src: SocketAddr, dg: &[u8], now_ms: u64) -> DispatchOut<'_>;

    /// Called when a TUN frame arrives.  Returns egress datagrams to send on
    /// the UDP socket (may be empty), each tagged with its FEC fate group and
    /// destination so a GSO-capable driver can coalesce safely (see
    /// [`EgressDatagram`]).
    fn on_tun(&mut self, inner: &[u8], now_ms: u64) -> &[EgressDatagram];

    /// Called at least every 10 ms.  Returns addressed feedback/keepalive
    /// datagrams (usually 0 or 1) that should be sent on the UDP socket.
    fn tick(&mut self, now_ms: u64) -> Option<&[EgressDatagram]>;
}

/// One egress datagram: its destination, plus the FEC "fate group" it
/// belongs to.
///
/// GSO coalesces same-length, same-destination UDP datagrams into one
/// `UDP_SEGMENT` super-skb; under loss the whole skb is dropped/delayed as a
/// unit (segmentation is deferred to the receiver). Two datagrams that are
/// symbols of the same RaptorQ object must never share a skb — losing them
/// together can defeat FEC recovery for that object. `fate` is the RaptorQ
/// object id (source symbols and this object's repair symbols share it; a
/// different object gets a different value). A GSO-capable driver must
/// guarantee at most one datagram per distinct `fate` *and* per distinct
/// `dst` in any single coalesced send (datagrams to different peers must
/// never share a skb either). Non-GSO drivers ignore `fate`.
#[derive(Debug, Clone)]
pub struct EgressDatagram {
    pub fate: u16,
    pub dst: SocketAddr,
    pub bytes: Vec<u8>,
}

impl AsRef<[u8]> for EgressDatagram {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// What [`run_poll`] must do after a call to [`Dispatch::on_udp`].
pub enum DispatchOut<'a> {
    /// Nothing to forward.
    None,
    /// Write this slice to the TUN device (decoded inner packet).
    Tun(&'a [u8]),
    /// Send these datagrams on the UDP socket (ARQ retransmits).
    Udp(&'a [EgressDatagram]),
    /// Write to TUN *and* send datagrams.
    Both(&'a [u8], &'a [EgressDatagram]),
}

// ── internal helpers ──────────────────────────────────────────────────────────

/// Set a file descriptor to non-blocking mode via `fcntl(O_NONBLOCK)`.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid open file descriptor supplied by the caller.
    // `fcntl(F_SETFL, O_NONBLOCK)` is a pure flag-set on the open-file
    // description; it cannot invalidate memory or cause UB.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Drain pending datagrams from `udp_fd` with `recvmmsg`, dispatching each and
/// forwarding the outcome. Loops until the socket is empty (recv_mmsg returns 0).
///
/// When `vnet_hdr` is set (kernel GSO/GRO offload active on the TUN fd),
/// decoded inner packets destined for TUN are pushed through `coalescer`
/// instead of written straight through: same-flow contiguous TCP segments
/// merge into one GSO super-frame, flushed once the whole UDP socket has been
/// drained for this call (not per recv burst) so a burst of same-flow packets
/// coalesces maximally. `!vnet_hdr` is byte-for-byte today's plain-write path.
#[expect(
    clippy::too_many_arguments,
    reason = "batch buffers (the GSO scratch `gso`, and the TUN-offload `vnet_hdr`/`coalescer` \
              state) are owned by run_poll and threaded through explicitly rather than bundled \
              into a struct, to keep the hot-path buffers' aliasing/lifetimes obvious"
)]
fn drain_udp(
    udp_fd: RawFd,
    tun_fd: RawFd,
    d: &mut impl Dispatch,
    now_ms: u64,
    bufs: &mut [[u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH],
    lens: &mut [usize; MAX_DATAGRAM_BATCH],
    srcs: &mut [SocketAddr; MAX_DATAGRAM_BATCH],
    tx: &mut Vec<EgressDatagram>,
    gso: &mut GsoScratch,
    vnet_hdr: bool,
    coalescer: &mut crate::tun_offload::Coalescer,
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
                DispatchOut::Tun(inner) => write_to_tun(tun_fd, inner, vnet_hdr, coalescer),
                DispatchOut::Udp(pkts) => tx.extend(pkts.iter().cloned()),
                DispatchOut::Both(inner, pkts) => {
                    write_to_tun(tun_fd, inner, vnet_hdr, coalescer);
                    tx.extend(pkts.iter().cloned());
                }
            }
        }
        flush_tx(udp_fd, tx, gso)?; // send any UDP replies for this recv burst
        if n < MAX_DATAGRAM_BATCH {
            break; // partial batch → socket drained
        }
    }
    if vnet_hdr {
        if let Some(frame) = coalescer.flush() {
            send_to_tun(tun_fd, frame);
        }
    }
    Ok(())
}

/// Write a decoded inner packet destined for TUN. With `vnet_hdr` active,
/// route it through `coalescer` (which may hold it pending a same-flow
/// contiguous follow-up, or return a just-flushed super-frame to write now);
/// otherwise write it straight through, unchanged from today's behaviour.
#[inline]
fn write_to_tun(
    tun_fd: RawFd,
    inner: &[u8],
    vnet_hdr: bool,
    coalescer: &mut crate::tun_offload::Coalescer,
) {
    if vnet_hdr {
        if let Some(frame) = coalescer.push(inner) {
            send_to_tun(tun_fd, frame);
        }
    } else {
        send_to_tun(tun_fd, inner);
    }
}

/// Drain pending TUN frames, accumulating each frame's egress datagrams into `tx`
/// and flushing them with `send_mmsg` (chunked at the batch cap).
///
/// When `vnet_hdr` is set (kernel GSO/GRO offload active on the TUN fd), each
/// read may be a kernel-GRO'd super-frame prefixed with a `virtio_net_hdr`;
/// `split_gro` splits it into `split_out`/`split_offs` and each resulting MTU
/// packet is fed to `d.on_tun` individually, exactly as the non-offload path
/// feeds one packet per read. A read that fails to parse as valid vnet_hdr
/// framing falls back to feeding the frame body (post-prefix) as-is. `buf` is
/// the (possibly GSO-sized) reusable read buffer owned by `run_poll`.
/// `!vnet_hdr` is byte-for-byte today's plain-read path.
#[expect(
    clippy::too_many_arguments,
    reason = "batch buffers (the GSO scratch `gso`, the reusable read buffer `buf`, and the \
              TUN-offload `vnet_hdr`/split scratch) are owned by run_poll and threaded through \
              explicitly rather than bundled into a struct, to keep the hot-path buffers' \
              aliasing/lifetimes obvious"
)]
fn drain_tun(
    tun_fd: RawFd,
    udp_fd: RawFd,
    d: &mut impl Dispatch,
    now_ms: u64,
    tx: &mut Vec<EgressDatagram>,
    gso: &mut GsoScratch,
    vnet_hdr: bool,
    buf: &mut [u8],
    split_out: &mut Vec<u8>,
    split_offs: &mut Vec<(usize, usize)>,
) -> io::Result<()> {
    loop {
        // SAFETY: `buf` is a valid caller-owned buffer; `tun_fd` is a valid
        // non-blocking TUN fd. TUN is not a socket, so we `read` rather than `recv`.
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
        let n = usize::try_from(n).expect("non-negative read return fits usize");
        if vnet_hdr {
            if crate::tun_offload::split_gro(&buf[..n], split_out, split_offs) {
                for &(s, l) in split_offs.iter() {
                    tx.extend(d.on_tun(&split_out[s..s + l], now_ms).iter().cloned());
                    if tx.len() >= MAX_DATAGRAM_BATCH {
                        flush_tx(udp_fd, tx, gso)?;
                    }
                }
            } else if let Some(body) = buf.get(crate::tun_offload::VNET_HDR_LEN..n) {
                // Unparseable vnet_hdr framing (e.g. GSO_NONE with a non-IPv4/TCP
                // body, or any other read that isn't a segmentable TCP run):
                // feed the frame body as a single packet, same as the plain path.
                tx.extend(d.on_tun(body, now_ms).iter().cloned());
                if tx.len() >= MAX_DATAGRAM_BATCH {
                    flush_tx(udp_fd, tx, gso)?;
                }
            }
            // else: read shorter than the vnet_hdr prefix itself — drop it.
        } else {
            let inner = &buf[..n];
            tx.extend(d.on_tun(inner, now_ms).iter().cloned());
            if tx.len() >= MAX_DATAGRAM_BATCH {
                flush_tx(udp_fd, tx, gso)?;
            }
        }
    }
    flush_tx(udp_fd, tx, gso)?; // send the burst's remaining egress
    Ok(())
}

/// Reusable scratch + latched capability for GSO sends on the poll path.
struct GsoScratch {
    /// Latched to `false` the first time a GSO send reports the feature
    /// unsupported (`EIO`/`EINVAL`); thereafter `flush_tx` uses plain sends only.
    enabled: bool,
    runs: Vec<crate::gso::GsoRun>,
    payload: Vec<u8>,
}

impl GsoScratch {
    fn new() -> Self {
        Self {
            enabled: true,
            runs: Vec::with_capacity(MAX_DATAGRAM_BATCH),
            payload: Vec::with_capacity(MAX_WIRE_DATAGRAM * crate::gso::MAX_GSO_SEGMENTS_PER_SEND),
        }
    }
}

/// Plain-send `run` via `send_mmsg` (looping partial sends). A momentarily-full
/// send buffer drops the remainder of the run (same acceptable single-burst loss
/// as the old per-datagram send).
fn send_run_plain(udp_fd: RawFd, run: &[EgressDatagram]) -> io::Result<()> {
    let mut sent = 0;
    while sent < run.len() {
        let n = send_mmsg(udp_fd, &run[sent..])?;
        if n == 0 {
            break;
        }
        sent += n;
    }
    Ok(())
}

/// Send everything queued in `tx`, then clear it. With GSO enabled, partitions
/// `tx` into fate-safe runs and sends each run of ≥2 as one `UDP_SEGMENT` send
/// (falling back to plain sends for singletons and, after latching GSO off, on
/// any "unsupported" result). Wire-identical to plain `send_mmsg`; the datagram
/// bytes, sizes, count, and destinations on the wire are unchanged.
fn flush_tx(udp_fd: RawFd, tx: &mut Vec<EgressDatagram>, gso: &mut GsoScratch) -> io::Result<()> {
    if !gso.enabled {
        let r = send_run_plain(udp_fd, tx);
        tx.clear();
        return r;
    }
    crate::gso::partition_fate_safe(tx, MAX_DATAGRAM_BATCH, &mut gso.runs);
    // Detach the runs scratch so we can borrow `gso.payload`/`gso.enabled` mutably
    // while iterating (the runs hold only indices into `tx`); restore it after.
    let runs = std::mem::take(&mut gso.runs);
    let mut outcome = Ok(());
    for run in &runs {
        if gso.enabled && run.members.len() >= 2 && run.segment_size > 0 {
            let dst = tx[run.members[0]].dst;
            match send_gso_indexed(
                udp_fd,
                tx,
                &run.members,
                run.segment_size,
                dst,
                &mut gso.payload,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    gso.enabled = false; // latch: GSO unsupported here
                    for &i in &run.members {
                        if let Err(e) = send_run_plain(udp_fd, std::slice::from_ref(&tx[i])) {
                            outcome = Err(e);
                            break;
                        }
                    }
                }
                Err(e) => outcome = Err(e),
            }
        } else {
            for &i in &run.members {
                if let Err(e) = send_run_plain(udp_fd, std::slice::from_ref(&tx[i])) {
                    outcome = Err(e);
                    break;
                }
            }
        }
        if outcome.is_err() {
            break;
        }
    }
    gso.runs = runs; // restore the reusable scratch allocation
    tx.clear();
    outcome
}

/// Write one packet to the TUN device.
///
/// Errors are logged and swallowed — a single failed TUN write should not
/// tear down the tunnel.
#[inline]
fn send_to_tun(tun_fd: RawFd, buf: &[u8]) {
    // SAFETY: `buf` is a valid slice and `tun_fd` is a valid TUN fd.
    // `write` writes at most `buf.len()` bytes from `buf`; partial writes
    // are unusual on TUN devices (atomic for MTU-sized frames) but we do
    // not retry them here — a dropped inner frame is less harmful than a
    // busy-loop.
    let rc = unsafe { libc::write(tun_fd, buf.as_ptr().cast(), buf.len()) };
    if rc < 0 {
        eprintln!("poll: tun write error: {}", io::Error::last_os_error());
    }
}

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
    let mut storages: [libc::sockaddr_storage; MAX_DATAGRAM_BATCH] = unsafe { std::mem::zeroed() };
    let mut addrlens = [0 as libc::socklen_t; MAX_DATAGRAM_BATCH];
    let mut iovecs = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; MAX_DATAGRAM_BATCH];
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

/// Send an already-assembled `payload` (N × `segment_size` bytes) as ONE
/// `sendmsg` with a `UDP_SEGMENT` cmsg to `dst`. `Ok(true)`: accepted, or a
/// transient full send buffer dropped it (acceptable single-burst loss, as in
/// `send_mmsg`). `Ok(false)`: GSO unsupported (`EIO`/`EINVAL`) — caller latches
/// GSO off and plain-sends the run.
fn send_gso_payload(
    udp_fd: RawFd,
    payload: &[u8],
    segment_size: u16,
    dst: SocketAddr,
) -> io::Result<bool> {
    let (mut storage, addr_len) = std_to_sockaddr(dst);
    let mut iov = libc::iovec {
        // SAFETY: cast a shared slice to *mut for the iovec ABI; sendmsg only
        // reads through iov_base. `payload` outlives the syscall.
        iov_base: payload.as_ptr().cast_mut().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut control = [0u8; GSO_CONTROL_SPACE];
    // SAFETY: msghdr is plain-old-data; zeroed is a valid initial state we fully
    // populate below before the syscall.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::from_mut(&mut storage).cast::<libc::c_void>();
    msg.msg_namelen = addr_len;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    // SAFETY: `CMSG_SPACE` is a pure size computation; no pointer deref.
    let cmsg_space = usize::try_from(unsafe { libc::CMSG_SPACE(GSO_CONTROL_PAYLOAD_LEN) })
        .expect("cmsg space fits usize");
    if cmsg_space > control.len() {
        return Err(io::Error::other("GSO control buffer too small"));
    }
    msg.msg_controllen = cmsg_space;

    // SAFETY: `msg` points to valid in-frame iovec/control storage; we write
    // exactly one SOL_UDP/UDP_SEGMENT cmsg (a u16 segment size) into `control`.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        if cmsg.is_null() {
            return Err(io::Error::other("missing first cmsg header"));
        }
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len =
            usize::try_from(libc::CMSG_LEN(GSO_CONTROL_PAYLOAD_LEN)).expect("cmsg len fits usize");
        let seg_ptr = libc::CMSG_DATA(cmsg).cast::<u16>();
        *seg_ptr = segment_size;
    }

    // SAFETY: `msg` is fully initialised; its iov/name/control point into this
    // frame's storage, valid until sendmsg returns. MSG_NOSIGNAL suppresses SIGPIPE.
    let ret = unsafe { libc::sendmsg(udp_fd, &raw const msg, libc::MSG_NOSIGNAL) };
    if ret < 0 {
        let e = io::Error::last_os_error();
        let raw = e.raw_os_error().unwrap_or(0);
        if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN || raw == libc::ENOBUFS {
            return Ok(true); // transient full buffer: drop this run (acceptable)
        }
        if raw == libc::EIO || raw == libc::EINVAL {
            return Ok(false); // GSO unsupported → caller latches off + plain-sends
        }
        return Err(e);
    }
    Ok(true)
}

/// Assemble `run`'s payloads into `payload` (reused) and GSO-send them.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "run-slice wrapper kept for its own unit test; flush_tx uses \
                  send_gso_indexed to avoid copying the run out of the egress batch"
    )
)]
fn send_gso(
    udp_fd: RawFd,
    run: &[EgressDatagram],
    segment_size: u16,
    dst: SocketAddr,
    payload: &mut Vec<u8>,
) -> io::Result<bool> {
    payload.clear();
    for dg in run {
        payload.extend_from_slice(&dg.bytes);
    }
    send_gso_payload(udp_fd, payload, segment_size, dst)
}

/// Like `send_gso`, but reads the run's datagrams from `tx` by `indices`
/// (avoids copying the run out of the egress batch).
fn send_gso_indexed(
    udp_fd: RawFd,
    tx: &[EgressDatagram],
    indices: &[usize],
    segment_size: u16,
    dst: SocketAddr,
    payload: &mut Vec<u8>,
) -> io::Result<bool> {
    payload.clear();
    for &i in indices {
        payload.extend_from_slice(&tx[i].bytes);
    }
    send_gso_payload(udp_fd, payload, segment_size, dst)
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
    let count = bufs
        .len()
        .min(lens.len())
        .min(srcs.len())
        .min(MAX_DATAGRAM_BATCH);
    if count == 0 {
        return Ok(0);
    }
    // SAFETY: all-zero sockaddr_storage is a valid initial out-buffer that
    // recvmmsg fills; we read it back only for the datagrams it reports received.
    let mut storages: [libc::sockaddr_storage; MAX_DATAGRAM_BATCH] = unsafe { std::mem::zeroed() };
    let addrlens = [libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
        .expect("size fits socklen_t"); MAX_DATAGRAM_BATCH];
    let mut iovecs = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; MAX_DATAGRAM_BATCH];
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

// ── public entry point ────────────────────────────────────────────────────────

/// Run the epoll event loop until an I/O error is returned.
///
/// Both `udp_fd` and `tun_fd` are set non-blocking.  An `epoll` instance
/// watches both for `EPOLLIN`.  `epoll_wait` uses a 10 ms timeout so that
/// [`Dispatch::tick`] fires on cadence even when there is no network traffic.
///
/// The function returns when:
/// - `drain_udp` or `drain_tun` returns a fatal I/O error, OR
/// - `flush_tx` (via `send_mmsg`) returns a fatal I/O error (e.g. socket closed).
///
/// `vnet_hdr` must reflect whether `tun_fd` was actually opened with
/// `IFF_VNET_HDR` + kernel GSO/GRO offload (`TunTap::vnet_hdr_len().is_some()`
/// — see `yip-device`); passing `true` for a plain fd corrupts every TUN
/// read/write with a bogus `virtio_net_hdr` prefix.
pub fn run_poll<D: Dispatch>(
    udp_fd: RawFd,
    tun_fd: RawFd,
    vnet_hdr: bool,
    d: &mut D,
) -> io::Result<()> {
    set_nonblocking(udp_fd)?;
    set_nonblocking(tun_fd)?;

    // SAFETY: `epoll_create1` creates a new epoll instance.  EPOLL_CLOEXEC
    // is the only valid flag; passing it is safe.  We check the return value.
    let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epoll_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Register `udp_fd` with the epoll instance.
    let mut ev_udp = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: udp_fd as u64,
    };
    // SAFETY: `epoll_fd` and `udp_fd` are valid fds.  `ev_udp` is a
    // correctly initialised `epoll_event` with EPOLLIN and `udp_fd` as the
    // user data so we can identify which fd is ready in the event loop.
    let rc = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, udp_fd, &raw mut ev_udp) };
    if rc < 0 {
        // SAFETY: `epoll_fd` is a valid fd we just created.
        unsafe { libc::close(epoll_fd) };
        return Err(io::Error::last_os_error());
    }

    // Register `tun_fd` with the epoll instance.
    let mut ev_tun = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: tun_fd as u64,
    };
    // SAFETY: same rationale as for `ev_udp` above; `tun_fd` is a valid
    // open TUN device fd.
    let rc = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, tun_fd, &raw mut ev_tun) };
    if rc < 0 {
        // SAFETY: `epoll_fd` is a valid fd we just created.
        unsafe { libc::close(epoll_fd) };
        return Err(io::Error::last_os_error());
    }

    let start = Instant::now();
    // Stack-allocated event buffer: 4 events per wait is ample since we
    // only have 2 fds registered.
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];

    // Reusable batch buffers (one allocation for the loop's lifetime).
    let mut rx_bufs = Box::new([[0u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH]);
    let mut rx_lens = [0usize; MAX_DATAGRAM_BATCH];
    let mut rx_srcs = [SocketAddr::from(([0, 0, 0, 0], 0)); MAX_DATAGRAM_BATCH];
    let mut tx_batch: Vec<EgressDatagram> = Vec::with_capacity(MAX_DATAGRAM_BATCH);
    let mut gso = GsoScratch::new();

    // TUN-offload state (active only when `vnet_hdr`): `coalescer` merges
    // decrypted packets into GSO super-frames on write; `split_out`/
    // `split_offs` are the per-read scratch for splitting a kernel-GRO'd read
    // into individual MTU packets. `tun_buf` is sized to hold a whole GSO
    // super-frame (`VNET_HDR_LEN + MAX_GSO_PAYLOAD`) when offload is active,
    // or `MAX_WIRE_DATAGRAM` — identical to today's stack buffer — otherwise.
    let mut coalescer = crate::tun_offload::Coalescer::new();
    let mut split_out: Vec<u8> = Vec::new();
    let mut split_offs: Vec<(usize, usize)> = Vec::new();
    let mut tun_buf = vec![
        0u8;
        if vnet_hdr {
            crate::tun_offload::VNET_HDR_LEN + crate::tun_offload::MAX_GSO_PAYLOAD
        } else {
            MAX_WIRE_DATAGRAM
        }
    ];

    loop {
        // SAFETY: `epoll_fd` is a valid epoll fd.  `events` is a valid
        // stack-allocated array; we pass its length as `maxevents`.
        // A timeout of 10 ms ensures `tick` fires on cadence.
        let nfds = unsafe {
            libc::epoll_wait(
                epoll_fd,
                events.as_mut_ptr(),
                libc::c_int::try_from(events.len()).expect("event array len fits c_int"),
                10, // 10 ms timeout
            )
        };

        if nfds < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                // Interrupted by a signal — retry.
                continue;
            }
            // SAFETY: `epoll_fd` is valid.
            unsafe { libc::close(epoll_fd) };
            return Err(e);
        }

        let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        for ev in &events[..usize::try_from(nfds).expect("non-negative nfds fits usize")] {
            let ready_fd = ev.u64 as RawFd;
            if ready_fd == udp_fd {
                if let Err(e) = drain_udp(
                    udp_fd,
                    tun_fd,
                    d,
                    now_ms,
                    &mut rx_bufs,
                    &mut rx_lens,
                    &mut rx_srcs,
                    &mut tx_batch,
                    &mut gso,
                    vnet_hdr,
                    &mut coalescer,
                ) {
                    // SAFETY: `epoll_fd` is valid.
                    unsafe { libc::close(epoll_fd) };
                    return Err(e);
                }
            } else if ready_fd == tun_fd {
                if let Err(e) = drain_tun(
                    tun_fd,
                    udp_fd,
                    d,
                    now_ms,
                    &mut tx_batch,
                    &mut gso,
                    vnet_hdr,
                    &mut tun_buf,
                    &mut split_out,
                    &mut split_offs,
                ) {
                    // SAFETY: `epoll_fd` is valid.
                    unsafe { libc::close(epoll_fd) };
                    return Err(e);
                }
            }
        }

        // Always tick — even on timeout with no events.
        if let Some(pkts) = d.tick(now_ms) {
            tx_batch.extend(pkts.iter().cloned());
            if let Err(e) = flush_tx(udp_fd, &mut tx_batch, &mut gso) {
                // SAFETY: `epoll_fd` is valid.
                unsafe { libc::close(epoll_fd) };
                return Err(e);
            }
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    /// A minimal [`Dispatch`] that records received UDP payloads and counts
    /// calls.
    struct CountDispatch {
        received: Vec<Vec<u8>>,
        call_count: usize,
    }

    impl CountDispatch {
        fn new() -> Self {
            Self {
                received: Vec::new(),
                call_count: 0,
            }
        }
    }

    impl Dispatch for CountDispatch {
        fn on_udp(&mut self, _src: SocketAddr, dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            self.received.push(dg.to_vec());
            self.call_count += 1;
            DispatchOut::None
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[EgressDatagram] {
            &[]
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[EgressDatagram]> {
            None
        }
    }

    /// Verify that `drain_udp` reads a datagram from a ready UDP socket and
    /// passes it to the `Dispatch::on_udp` callback.
    #[test]
    fn drain_udp_delivers_datagram() {
        // Two connected loopback sockets.
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect(b.local_addr().unwrap()).unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();

        // Set `b` non-blocking so drain_udp can drain it without blocking.
        set_nonblocking(b.as_raw_fd()).unwrap();

        // Send a payload to `b` before draining.
        a.send(b"hello from drain_udp test").unwrap();

        // We need a throwaway tun_fd for drain_udp; use /dev/null (write-only
        // is fine — we never actually write for DispatchOut::None).
        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let null_fd = devnull.as_raw_fd();

        let mut d = CountDispatch::new();
        let mut bufs = Box::new([[0u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH]);
        let mut lens = [0usize; MAX_DATAGRAM_BATCH];
        let mut srcs = [std::net::SocketAddr::from(([0, 0, 0, 0], 0)); MAX_DATAGRAM_BATCH];
        let mut tx = Vec::new();
        let mut gso = GsoScratch::new();
        let mut coalescer = crate::tun_offload::Coalescer::new();
        drain_udp(
            b.as_raw_fd(),
            null_fd,
            &mut d,
            0,
            &mut bufs,
            &mut lens,
            &mut srcs,
            &mut tx,
            &mut gso,
            false,
            &mut coalescer,
        )
        .unwrap();

        assert_eq!(d.call_count, 1, "on_udp must be called exactly once");
        assert_eq!(d.received[0], b"hello from drain_udp test");
    }

    /// Verify that `drain_udp` handles multiple queued datagrams in one call.
    #[test]
    fn drain_udp_drains_multiple_datagrams() {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect(b.local_addr().unwrap()).unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();
        set_nonblocking(b.as_raw_fd()).unwrap();

        a.send(b"first").unwrap();
        a.send(b"second").unwrap();
        a.send(b"third").unwrap();

        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let null_fd = devnull.as_raw_fd();

        let mut d = CountDispatch::new();
        let mut bufs = Box::new([[0u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH]);
        let mut lens = [0usize; MAX_DATAGRAM_BATCH];
        let mut srcs = [std::net::SocketAddr::from(([0, 0, 0, 0], 0)); MAX_DATAGRAM_BATCH];
        let mut tx = Vec::new();
        let mut gso = GsoScratch::new();
        let mut coalescer = crate::tun_offload::Coalescer::new();
        drain_udp(
            b.as_raw_fd(),
            null_fd,
            &mut d,
            0,
            &mut bufs,
            &mut lens,
            &mut srcs,
            &mut tx,
            &mut gso,
            false,
            &mut coalescer,
        )
        .unwrap();

        assert_eq!(d.call_count, 3);
    }

    /// Verify that `set_nonblocking` idempotently works on a socket fd.
    #[test]
    fn set_nonblocking_is_idempotent() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_nonblocking(sock.as_raw_fd()).unwrap();
        set_nonblocking(sock.as_raw_fd()).unwrap(); // second call must not error
    }

    /// A [`Dispatch`] whose `on_udp` returns `DispatchOut::Udp` — i.e. it
    /// reflects the received datagram back out on the UDP socket (to the
    /// datagram's own source address), optionally replacing its payload.
    /// This exercises the forwarding arm and `flush_tx`/`send_mmsg` end-to-end
    /// via `drain_udp`.
    struct ForwardDispatch {
        /// Payload to send back.  Cloned once per `on_udp` call.
        reply: Vec<u8>,
        /// Scratch storage so the `&[EgressDatagram]` returned by `on_udp`
        /// lives long enough (it borrows `self`).
        scratch: Vec<EgressDatagram>,
    }

    impl ForwardDispatch {
        fn new(reply: impl Into<Vec<u8>>) -> Self {
            Self {
                reply: reply.into(),
                scratch: Vec::new(),
            }
        }
    }

    impl Dispatch for ForwardDispatch {
        fn on_udp(&mut self, src: SocketAddr, _dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            self.scratch = vec![EgressDatagram {
                fate: 0,
                dst: src,
                bytes: self.reply.clone(),
            }];
            DispatchOut::Udp(&self.scratch)
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[EgressDatagram] {
            &[]
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[EgressDatagram]> {
            None
        }
    }

    /// Verify that `drain_udp` honours `DispatchOut::Udp`: a datagram arriving
    /// on socket `b` causes `on_udp` to return `DispatchOut::Udp`, whose
    /// payload is forwarded by `flush_tx`/`send_mmsg` and received on the peer
    /// socket `a`.
    #[test]
    fn drain_udp_forwards_dispatch_out_udp_to_peer() {
        // Two connected loopback sockets: a ↔ b.
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect(b.local_addr().unwrap()).unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();

        // `b` must be non-blocking so drain_udp can drain it.
        set_nonblocking(b.as_raw_fd()).unwrap();
        // `a` must be non-blocking so we can do a best-effort receive check.
        set_nonblocking(a.as_raw_fd()).unwrap();

        // Send a trigger datagram from `a` → `b`.
        a.send(b"trigger").unwrap();

        // Use /dev/null as the TUN fd (DispatchOut::Udp never writes to TUN).
        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let null_fd = devnull.as_raw_fd();

        // `ForwardDispatch` will reply with "forwarded" for each received dg.
        let mut d = ForwardDispatch::new(b"forwarded".as_slice());
        let mut bufs = Box::new([[0u8; MAX_WIRE_DATAGRAM]; MAX_DATAGRAM_BATCH]);
        let mut lens = [0usize; MAX_DATAGRAM_BATCH];
        let mut srcs = [std::net::SocketAddr::from(([0, 0, 0, 0], 0)); MAX_DATAGRAM_BATCH];
        let mut tx = Vec::new();
        let mut gso = GsoScratch::new();
        let mut coalescer = crate::tun_offload::Coalescer::new();
        drain_udp(
            b.as_raw_fd(),
            null_fd,
            &mut d,
            0,
            &mut bufs,
            &mut lens,
            &mut srcs,
            &mut tx,
            &mut gso,
            false,
            &mut coalescer,
        )
        .unwrap();

        // The forwarded datagram must now be readable on `a`.
        let mut recv_buf = [0u8; 64];
        let n = a
            .recv(&mut recv_buf)
            .expect("forwarded datagram must arrive on peer socket");
        assert_eq!(&recv_buf[..n], b"forwarded");
    }

    #[test]
    fn send_mmsg_delivers_each_datagram_to_its_own_dst() {
        use std::net::UdpSocket;
        // Two receiver sockets on distinct ports; one sender.
        let rx_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_a.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        rx_b.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst_a = rx_a.local_addr().unwrap();
        let dst_b = rx_b.local_addr().unwrap();

        let batch = [
            EgressDatagram {
                fate: 0,
                dst: dst_a,
                bytes: b"to-a-1".to_vec(),
            },
            EgressDatagram {
                fate: 0,
                dst: dst_b,
                bytes: b"to-b".to_vec(),
            },
            EgressDatagram {
                fate: 0,
                dst: dst_a,
                bytes: b"to-a-2".to_vec(),
            },
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
        assert_eq!(
            recv_mmsg(rx.as_raw_fd(), &mut bufs, &mut lens, &mut srcs).unwrap(),
            0
        );
    }

    #[test]
    fn send_gso_delivers_each_segment_when_supported() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();

        let run = vec![
            EgressDatagram {
                fate: 1,
                dst: rx_addr,
                bytes: vec![0xAA; 1000],
            },
            EgressDatagram {
                fate: 2,
                dst: rx_addr,
                bytes: vec![0xBB; 1000],
            },
            EgressDatagram {
                fate: 3,
                dst: rx_addr,
                bytes: vec![0xCC; 1000],
            },
        ];
        let mut payload = Vec::new();
        let accepted =
            send_gso(tx.as_raw_fd(), &run, 1000, rx_addr, &mut payload).expect("send_gso");
        if !accepted {
            return; // kernel lacks UDP_SEGMENT here — nothing to assert.
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut got = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok((n, _)) = rx.recv_from(&mut buf) {
            got.push(buf[..n].to_vec());
        }
        assert_eq!(got.len(), 3, "GSO must segment into 3 separate datagrams");
        assert!(got.iter().all(|d| d.len() == 1000));
    }

    #[test]
    fn flush_tx_delivers_all_datagrams_gso_or_fallback() {
        use std::net::UdpSocket;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();

        // fates [1,2,3,1]: one 3-run (0,1,2) + a deferred singleton (3).
        let mut tx: Vec<EgressDatagram> = [1u16, 2, 3, 1]
            .iter()
            .map(|&f| EgressDatagram {
                fate: f,
                dst: rx_addr,
                bytes: vec![f as u8; 1000],
            })
            .collect();
        let mut gso = GsoScratch::new();
        flush_tx(tx_sock.as_raw_fd(), &mut tx, &mut gso).expect("flush_tx");
        assert!(tx.is_empty(), "flush_tx must drain tx");

        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut count = 0;
        let mut buf = [0u8; 2048];
        while let Ok((n, _)) = rx.recv_from(&mut buf) {
            assert_eq!(n, 1000);
            count += 1;
        }
        assert_eq!(
            count, 4,
            "all four datagrams must arrive (GSO or plain fallback)"
        );
    }
}
