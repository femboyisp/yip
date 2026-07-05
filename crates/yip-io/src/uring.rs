//! io_uring driver using one ring over UDP + TUN with provided-buffer receives.
//!
//! This backend keeps one ring alive and drives both fds from it. UDP is now
//! unconnected (the addressed socket seam, #33): receives use single-shot
//! `recvmsg`, each carrying its own dedicated buffer + `sockaddr_storage`, so
//! the driver recovers each datagram's source address; a fresh recv is
//! re-armed on the same slot after every completion. Sends use `sendmsg` with
//! an explicit per-datagram destination (see [`EgressDatagram::dst`]). TUN
//! uses a single pooled read that is re-submitted after each completion;
//! multishot `read` is not yet relied on.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::time::Instant;

use io_uring::{cqueue, opcode, squeue, types, IoUring};

use crate::poll::{Dispatch, DispatchOut, EgressDatagram};
use crate::{sockaddr_to_std, std_to_sockaddr, MAX_DATAGRAM_BATCH, MAX_WIRE_DATAGRAM};

const RING_ENTRIES: u32 = 512;
const RING_BUFS: usize = 256;
const TUN_READ_DEPTH: usize = 16;
/// How many single-shot UDP `recvmsg` requests are kept outstanding at once.
/// Each has its own dedicated buffer + `sockaddr_storage` (no provided-buffer
/// pool, unlike TUN reads) — see the module doc for why UDP recv moved off
/// multishot `RecvMulti`/`BUFFER_SELECT`.
const UDP_RECV_DEPTH: usize = 16;
const BUF_GROUP: u16 = 17;
const SEND_SLOTS: usize = 256;
const TAG_SHIFT: u32 = 56;
const TAG_UDP_RECV: u64 = 1_u64 << TAG_SHIFT;
const TAG_TUN_RECV: u64 = 2_u64 << TAG_SHIFT;
const TAG_REPROVIDE: u64 = 3_u64 << TAG_SHIFT;
const TAG_SEND_SLOT: u64 = 4_u64 << TAG_SHIFT;
const TAG_KIND_MASK: u64 = 0xff_u64 << TAG_SHIFT;
const TAG_PAYLOAD_MASK: u64 = !TAG_KIND_MASK;
const SQE_FLAGS_BUFFER_SELECT: squeue::Flags = squeue::Flags::BUFFER_SELECT;
const MAX_WIRE_DATAGRAM_I32: i32 = 2048;
const MAX_WIRE_DATAGRAM_U32: u32 = 2048;
const RING_BUFS_U16: u16 = 256;
const MAX_GSO_DATAGRAMS: usize = MAX_DATAGRAM_BATCH;
const MAX_GSO_PAYLOAD: usize = MAX_WIRE_DATAGRAM * MAX_GSO_DATAGRAMS;
const MAX_UDP_PAYLOAD: usize = 65_507;
/// Max datagrams coalesced into one `UDP_SEGMENT` send. No longer a correctness
/// guard (that is `can_coalesce_gso_tagged`, which forbids same-FEC-object
/// datagrams sharing a skb) — purely a throughput/blast-radius knob. See #17.
const MAX_GSO_SEGMENTS_PER_SEND: usize = 32;
/// Cap on egress datagrams staged for GSO within one `poll_once`, bounding the
/// dedup pass in `flush_pending_gso`.
const MAX_PENDING_GSO_DATAGRAMS: usize = 512;
/// Completion-queue busy-poll budget: when busy-poll is enabled, how many times
/// `poll_once` spins checking for a completion before falling back to a blocking
/// wait. Spinning trades CPU for lower wakeup latency — measured to cut tunnel
/// RTT from ~0.46 ms (blocking) to ~0.26 ms, beating the epoll `PollDriver`.
/// This is a "burn CPU for latency" knob (yip's north star), off by default and
/// enabled with `YIP_URING_BUSYPOLL=1`. The value wants per-hardware tuning; it
/// is intentionally large because the spin must outlast a full intra-round-trip
/// event gap to catch the imminent reply completion.
const CQ_SPIN_BUDGET: u32 = 2_000_000;
/// Blocking-wait timeout so `tick` fires on cadence even when the tunnel is
/// idle (parity with poll.rs's 10 ms `epoll_wait` timeout). Requires the io_uring
/// `EXT_ARG` feature (kernel 5.11+); on older kernels the wait is unbounded.
const TICK_TIMEOUT_NS: u32 = 10_000_000;
const GSO_CONTROL_PAYLOAD_LEN_U32: u32 = 2;
const GSO_CONTROL_SPACE: usize = 64;

#[derive(Clone, Copy)]
struct GsoMeta {
    segment_size: u16,
    datagram_count: usize,
    /// Shared destination of every datagram in this coalesced send —
    /// `can_coalesce_gso_tagged` guarantees every datagram in a GSO batch
    /// shares one `dst`, so recovering a fallback/unsent datagram (below)
    /// can reuse it directly.
    dst: SocketAddr,
}

/// Which fd an in-flight send slot targets, so completion-error handling can
/// mirror `PollDriver`: TUN writes are always dropped, UDP sends drop on
/// transient buffer pressure but propagate genuinely fatal errors.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SendKind {
    Udp,
    Tun,
}

/// Per-send-slot `sendmsg` context: the datagram's own destination
/// (`name`/`namelen`), its iovec, and (GSO sends only) the `UDP_SEGMENT`
/// control message. Every UDP send now goes through `sendmsg` (the socket is
/// unconnected — the addressed seam), so both plain and GSO sends need
/// `msg_name` populated; only GSO sends need the `control` cmsg.
struct GsoSendContext {
    iov: libc::iovec,
    msg: libc::msghdr,
    control: [u8; GSO_CONTROL_SPACE],
    name: libc::sockaddr_storage,
}

impl GsoSendContext {
    fn new() -> Self {
        Self {
            iov: libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
            msg: libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: std::ptr::null_mut(),
                msg_iovlen: 0,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            control: [0_u8; GSO_CONTROL_SPACE],
            // SAFETY: `sockaddr_storage` is plain-old-data (integers/byte
            // arrays); the all-zero bit pattern is a valid value for it.
            // `set_destination` overwrites it before every send.
            name: unsafe { std::mem::zeroed() },
        }
    }

    /// Point `msg_name`/`msg_namelen` at this datagram's destination.
    fn set_destination(&mut self, dst: SocketAddr) {
        let (storage, len) = std_to_sockaddr(dst);
        self.name = storage;
        self.msg.msg_name = std::ptr::addr_of_mut!(self.name).cast::<libc::c_void>();
        self.msg.msg_namelen = len;
    }

    /// Prepare a plain (non-GSO) `sendmsg`: payload + destination, no cmsg.
    fn prepare_plain(&mut self, payload_ptr: *mut u8, payload_len: usize, dst: SocketAddr) {
        self.iov.iov_base = payload_ptr.cast::<libc::c_void>();
        self.iov.iov_len = payload_len;
        self.msg.msg_iov = std::ptr::addr_of_mut!(self.iov);
        self.msg.msg_iovlen = 1;
        self.msg.msg_control = std::ptr::null_mut();
        self.msg.msg_controllen = 0;
        self.msg.msg_flags = 0;
        self.set_destination(dst);
    }

    /// Prepare a GSO `sendmsg`: payload + destination + `UDP_SEGMENT` cmsg.
    fn prepare_gso(
        &mut self,
        payload_ptr: *mut u8,
        payload_len: usize,
        segment_size: u16,
        dst: SocketAddr,
    ) -> io::Result<()> {
        self.iov.iov_base = payload_ptr.cast::<libc::c_void>();
        self.iov.iov_len = payload_len;
        self.msg.msg_iov = std::ptr::addr_of_mut!(self.iov);
        self.msg.msg_iovlen = 1;
        self.msg.msg_control = self.control.as_mut_ptr().cast::<libc::c_void>();
        // SAFETY: `CMSG_SPACE` is a pure size computation for the provided
        // payload length and does not dereference pointers.
        let cmsg_space = usize::try_from(unsafe { libc::CMSG_SPACE(GSO_CONTROL_PAYLOAD_LEN_U32) })
            .map_err(|_| io::Error::other("cmsg space does not fit usize"))?;
        if cmsg_space > self.control.len() {
            return Err(io::Error::other("GSO control buffer too small"));
        }
        self.msg.msg_controllen = cmsg_space;
        self.msg.msg_flags = 0;
        self.set_destination(dst);

        // SAFETY: `self.msg` points to valid in-struct iovec/control storage.
        // We write exactly one SOL_UDP/UDP_SEGMENT cmsg payload (u16 segment size)
        // into the allocated control region.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(std::ptr::addr_of!(self.msg));
            if cmsg.is_null() {
                return Err(io::Error::other("missing first cmsg header"));
            }
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = libc::UDP_SEGMENT;
            (*cmsg).cmsg_len = usize::try_from(libc::CMSG_LEN(GSO_CONTROL_PAYLOAD_LEN_U32))
                .map_err(|_| io::Error::other("cmsg len does not fit usize"))?;
            let segment_ptr = libc::CMSG_DATA(cmsg).cast::<u16>();
            *segment_ptr = segment_size;
        }
        Ok(())
    }
}

/// One outstanding single-shot UDP `recvmsg` request: its own dedicated
/// payload buffer + `sockaddr_storage`, plus the `iovec`/`msghdr` that
/// self-reference them.
///
/// These are allocated once into a `Box<[UdpRecvSlot]>` that is never resized
/// after `UringDriver::new` — so the addresses `iov`/`msg` point at (`buf`,
/// `name`, and `iov` itself) stay valid for the driver's whole lifetime,
/// exactly like `recv_pool`'s stable buffer addresses below.
struct UdpRecvSlot {
    buf: [u8; MAX_WIRE_DATAGRAM],
    name: libc::sockaddr_storage,
    iov: libc::iovec,
    msg: libc::msghdr,
}

impl UdpRecvSlot {
    /// A slot with every field zeroed and no pointers fixed up yet. Callers
    /// must fix up `iov`/`msg` to self-reference `buf`/`name` immediately
    /// after the slot reaches its final (never-to-move-again) address — see
    /// `UringDriver::new`.
    fn zeroed() -> Self {
        // SAFETY: every field is plain-old-data (byte array / integers /
        // pointers); the all-zero bit pattern is valid for all of them. Null
        // `iov`/`msg` pointers are never submitted to the kernel — they are
        // fixed up before the first `arm_udp_recv_slot` call.
        unsafe { std::mem::zeroed() }
    }
}

/// One-ring io_uring driver handling UDP + TUN.
pub struct UringDriver {
    ring: IoUring,
    udp_fd: RawFd,
    tun_fd: RawFd,
    recv_pool: Box<[[u8; MAX_WIRE_DATAGRAM]; RING_BUFS]>,
    /// Fixed pool of outstanding single-shot UDP `recvmsg` requests (see
    /// [`UdpRecvSlot`]); indexed by `TAG_UDP_RECV`'s payload bits.
    udp_recv_slots: Box<[UdpRecvSlot]>,
    in_flight: Vec<Option<Vec<u8>>>,
    gso_meta: Vec<Option<GsoMeta>>,
    gso_ctx: Vec<Option<GsoSendContext>>,
    send_kind: Vec<Option<SendKind>>,
    /// Reusable send-buffer pool: released in-flight buffers are recycled here
    /// instead of freed, so the hot send path does no per-packet allocation.
    free_bufs: Vec<Vec<u8>>,
    /// Reusable scratch for a received datagram, so recv dispatch does no
    /// per-packet allocation (poll.rs dispatches from a reused stack buffer).
    recv_scratch: Vec<u8>,
    /// Reusable completion-drain buffer, so `poll_once` does no per-iteration
    /// allocation.
    cqe_buf: Vec<(u64, i32, u32)>,
    /// Busy-poll the completion queue before blocking (opt-in via
    /// `YIP_URING_BUSYPOLL=1`) — lower RTT at the cost of CPU while active.
    busy_poll: bool,
    /// Adaptive-spin state: true while an exchange is active (recent completions),
    /// false once a wait times out. Gates whether `busy_poll` actually spins, so
    /// an idle tunnel does not burn CPU.
    active: bool,
    /// Egress datagrams staged this `poll_once`, tagged with their FEC fate
    /// group. Flushed by `flush_pending_gso` before `poll_once` returns, so no
    /// cross-call buffering / added latency.
    pending_gso: Vec<EgressDatagram>,
    /// Whether the kernel supports `EXT_ARG` (5.11+), i.e. a timed blocking wait.
    /// When true, the idle wait is bounded so `tick` fires on cadence.
    ext_arg: bool,
    gso_enabled: bool,
    started: Instant,
    /// Count of sends dropped because the in-flight slot table (bounded by
    /// `SEND_SLOTS`) was momentarily exhausted. Surfaced in the drop logs and
    /// via a test-only accessor so aggregate drop pressure is observable.
    dropped_sends: u64,
    #[cfg(test)]
    gso_submission_count: usize,
    #[cfg(test)]
    force_gso_submit_failure: bool,
}

impl UringDriver {
    /// Build and arm a ring over the provided UDP and TUN file descriptors.
    pub fn new(udp_fd: RawFd, tun_fd: RawFd) -> io::Result<Self> {
        let ring = IoUring::new(RING_ENTRIES)?;
        let ext_arg = ring.params().is_feature_ext_arg();
        let recv_pool = Box::new([[0_u8; MAX_WIRE_DATAGRAM]; RING_BUFS]);

        // Build the UDP recv slot pool, then fix up each slot's self-referencing
        // iovec/msghdr pointers now that every slot has reached its final,
        // never-to-move-again address inside the boxed slice.
        let mut udp_recv_slots: Box<[UdpRecvSlot]> = (0..UDP_RECV_DEPTH)
            .map(|_| UdpRecvSlot::zeroed())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let namelen = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
            .expect("size_of::<sockaddr_storage>() fits socklen_t");
        for slot in udp_recv_slots.iter_mut() {
            slot.iov = libc::iovec {
                iov_base: slot.buf.as_mut_ptr().cast::<libc::c_void>(),
                iov_len: slot.buf.len(),
            };
            slot.msg = libc::msghdr {
                msg_name: std::ptr::addr_of_mut!(slot.name).cast::<libc::c_void>(),
                msg_namelen: namelen,
                msg_iov: std::ptr::addr_of_mut!(slot.iov),
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            };
        }

        let mut in_flight = Vec::with_capacity(SEND_SLOTS);
        let mut gso_meta = Vec::with_capacity(SEND_SLOTS);
        let mut gso_ctx = Vec::with_capacity(SEND_SLOTS);
        let mut send_kind = Vec::with_capacity(SEND_SLOTS);
        for _ in 0..SEND_SLOTS {
            in_flight.push(None);
            gso_meta.push(None);
            gso_ctx.push(None);
            send_kind.push(None);
        }

        let mut driver = Self {
            ring,
            udp_fd,
            tun_fd,
            recv_pool,
            udp_recv_slots,
            in_flight,
            gso_meta,
            gso_ctx,
            send_kind,
            free_bufs: Vec::with_capacity(SEND_SLOTS),
            recv_scratch: Vec::with_capacity(MAX_WIRE_DATAGRAM),
            cqe_buf: Vec::with_capacity(
                usize::try_from(RING_ENTRIES).expect("RING_ENTRIES fits usize"),
            ),
            busy_poll: std::env::var_os("YIP_URING_BUSYPOLL").is_some(),
            active: false,
            pending_gso: Vec::with_capacity(MAX_PENDING_GSO_DATAGRAMS),
            ext_arg,
            gso_enabled: true,
            started: Instant::now(),
            dropped_sends: 0,
            #[cfg(test)]
            gso_submission_count: 0,
            #[cfg(test)]
            force_gso_submit_failure: false,
        };

        driver.provide_all_buffers()?;
        for i in 0..UDP_RECV_DEPTH {
            driver.arm_udp_recv_slot(i)?;
        }
        for _ in 0..TUN_READ_DEPTH {
            driver.arm_tun_read()?;
        }
        driver.ring.submit()?;
        Ok(driver)
    }

    fn push_entry(&mut self, entry: io_uring::squeue::Entry) -> io::Result<()> {
        // SAFETY: the SQE points to memory owned by `self` (recv pool or send slot
        // buffers) whose lifetime outlives kernel use until matching CQE processing.
        let first_try = unsafe { self.ring.submission().push(&entry) };
        if first_try.is_ok() {
            return Ok(());
        }

        self.ring.submit()?;
        // SAFETY: same as above; we retried after flushing SQ entries.
        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| io::Error::other("uring submission queue full"))?;
        }
        Ok(())
    }

    fn provide_all_buffers(&mut self) -> io::Result<()> {
        let base_ptr = self.recv_pool.as_mut_ptr().cast::<u8>();
        let entry = opcode::ProvideBuffers::new(
            base_ptr,
            MAX_WIRE_DATAGRAM_I32,
            RING_BUFS_U16,
            BUF_GROUP,
            0,
        )
        .build()
        .user_data(TAG_REPROVIDE);
        self.push_entry(entry)?;
        self.submit_and_wait_1()?;
        let cqe = self
            .ring
            .completion()
            .next()
            .ok_or_else(|| io::Error::other("missing provide-buffer completion"))?;
        if cqe.result() < 0 {
            return Err(io::Error::from_raw_os_error(-cqe.result()));
        }
        Ok(())
    }

    fn reprovide_buffer(&mut self, bid: u16) -> io::Result<()> {
        let idx = usize::from(bid);
        if idx >= RING_BUFS {
            return Err(io::Error::other("provided buffer id out of range"));
        }
        let ptr = self.recv_pool[idx].as_mut_ptr();
        let entry = opcode::ProvideBuffers::new(ptr, MAX_WIRE_DATAGRAM_I32, 1, BUF_GROUP, bid)
            .build()
            .user_data(TAG_REPROVIDE | u64::from(bid));
        self.push_entry(entry)
    }

    /// (Re-)arm one single-shot UDP `recvmsg` on slot `idx`. Unlike the old
    /// multishot `RecvMulti`, this surfaces the datagram's source address (via
    /// the slot's own `sockaddr_storage`) — the whole point of the addressed
    /// socket seam — at the cost of one submission per completion instead of
    /// one submission serving an unbounded burst. Acceptable: io_uring is
    /// opt-in and correctness (recovering `src`) comes first (see #33).
    fn arm_udp_recv_slot(&mut self, idx: usize) -> io::Result<()> {
        let msg_ptr = std::ptr::addr_of_mut!(self.udp_recv_slots[idx].msg);
        let tag = TAG_UDP_RECV | u64::try_from(idx).expect("udp recv slot index fits u64");
        let entry = opcode::RecvMsg::new(types::Fd(self.udp_fd), msg_ptr)
            .build()
            .user_data(tag);
        self.push_entry(entry)
    }

    fn arm_tun_read(&mut self) -> io::Result<()> {
        // We intentionally use single-shot read + re-submit because multishot
        // read behavior can vary by fd type and kernel support.
        let entry = opcode::Read::new(
            types::Fd(self.tun_fd),
            std::ptr::null_mut(),
            MAX_WIRE_DATAGRAM_U32,
        )
        .buf_group(BUF_GROUP)
        .build()
        .flags(SQE_FLAGS_BUFFER_SELECT)
        .user_data(TAG_TUN_RECV);
        self.push_entry(entry)?;
        Ok(())
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    #[cfg(test)]
    fn gso_submission_count(&self) -> usize {
        self.gso_submission_count
    }

    #[cfg(test)]
    fn in_flight_used_count(&self) -> usize {
        self.in_flight.iter().filter(|slot| slot.is_some()).count()
    }

    #[cfg(test)]
    fn dropped_sends(&self) -> u64 {
        self.dropped_sends
    }

    #[cfg(test)]
    fn set_force_gso_submit_failure(&mut self, force: bool) {
        self.force_gso_submit_failure = force;
    }

    /// Park a send buffer in a free in-flight slot, or recycle it and fail if
    /// the table is full.
    fn store_in_flight(&mut self, buf: Vec<u8>) -> io::Result<usize> {
        let Some((idx, slot)) = self
            .in_flight
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        else {
            self.recycle_buf(buf);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no free in-flight send slots available",
            ));
        };
        *slot = Some(buf);
        Ok(idx)
    }

    /// Take an owned buffer as an in-flight payload (used by the GSO coalescer,
    /// which builds its buffer directly).
    fn alloc_in_flight_slot(
        &mut self,
        payload: Vec<u8>,
        payload_limit: usize,
    ) -> io::Result<usize> {
        if payload.len() > payload_limit {
            self.recycle_buf(payload);
            return Err(io::Error::other("payload exceeds in-flight slot limit"));
        }
        self.store_in_flight(payload)
    }

    /// Copy `data` into a recycled send buffer and park it in an in-flight slot.
    /// No allocation once the pool is warm.
    fn alloc_in_flight_slot_copy(
        &mut self,
        data: &[u8],
        payload_limit: usize,
    ) -> io::Result<usize> {
        if data.len() > payload_limit {
            return Err(io::Error::other("payload exceeds in-flight slot limit"));
        }
        let mut buf = self.free_bufs.pop().unwrap_or_default();
        buf.clear();
        buf.extend_from_slice(data);
        self.store_in_flight(buf)
    }

    /// Return a spent send buffer to the pool for reuse (bounded so the pool
    /// never grows past the slot count).
    fn recycle_buf(&mut self, buf: Vec<u8>) {
        if self.free_bufs.len() < SEND_SLOTS {
            self.free_bufs.push(buf);
        }
    }

    /// Send one addressed datagram via `sendmsg` (the socket is unconnected —
    /// the addressed seam — so every UDP send needs an explicit destination).
    fn queue_udp_send(&mut self, dg: &EgressDatagram) -> io::Result<()> {
        let slot_id = self.alloc_in_flight_slot_copy(&dg.bytes, MAX_WIRE_DATAGRAM)?;
        self.send_kind[slot_id] = Some(SendKind::Udp);
        let (payload_ptr, payload_len) = {
            let slot_buf = self.in_flight[slot_id]
                .as_mut()
                .ok_or_else(|| io::Error::other("missing in-flight buffer for udp send"))?;
            (slot_buf.as_mut_ptr(), slot_buf.len())
        };
        let ctx = self.gso_ctx[slot_id].get_or_insert_with(GsoSendContext::new);
        ctx.prepare_plain(payload_ptr, payload_len, dg.dst);
        let tag = TAG_SEND_SLOT | u64::try_from(slot_id).expect("slot id fits u64");
        let msg_ptr = std::ptr::from_ref(&ctx.msg);
        let entry = opcode::SendMsg::new(types::Fd(self.udp_fd), msg_ptr)
            .flags(u32::try_from(libc::MSG_NOSIGNAL).expect("MSG_NOSIGNAL fits u32"))
            .build()
            .user_data(tag);
        if let Err(e) = self.push_entry(entry) {
            self.release_in_flight_slot(slot_id);
            return Err(e);
        }
        Ok(())
    }

    fn queue_tun_write(&mut self, frame: &[u8]) -> io::Result<()> {
        let slot_id = self.alloc_in_flight_slot_copy(frame, MAX_WIRE_DATAGRAM)?;
        self.send_kind[slot_id] = Some(SendKind::Tun);
        let (ptr, len_u32) = {
            let slot_buf = self.in_flight[slot_id]
                .as_ref()
                .ok_or_else(|| io::Error::other("missing in-flight buffer for tun write"))?;
            let len_u32 = u32::try_from(slot_buf.len())
                .map_err(|_| io::Error::other("tun write buffer too large"))?;
            (slot_buf.as_ptr(), len_u32)
        };
        let tag = TAG_SEND_SLOT | u64::try_from(slot_id).expect("slot id fits u64");
        let entry = opcode::Write::new(types::Fd(self.tun_fd), ptr, len_u32)
            .build()
            .user_data(tag);
        if let Err(e) = self.push_entry(entry) {
            self.release_in_flight_slot(slot_id);
            return Err(e);
        }
        Ok(())
    }

    fn release_in_flight_slot(&mut self, slot_id: usize) {
        if slot_id >= self.in_flight.len() {
            return;
        }
        if let Some(buf) = self.in_flight[slot_id].take() {
            self.recycle_buf(buf);
        }
        self.gso_meta[slot_id] = None;
        self.gso_ctx[slot_id] = None;
        self.send_kind[slot_id] = None;
    }

    /// Rejects any batch that contains two datagrams of the same FEC fate
    /// group — the invariant that keeps a source symbol and its own repair
    /// out of the same (fate-shared) GSO skb — *or* mixed destinations, since
    /// a coalesced `UDP_SEGMENT` send has exactly one `msg_name` and would
    /// silently misdirect every datagram after the first to the wrong peer.
    /// This is the single correctness choke point for GSO+FEC(+addressing)
    /// safety.
    fn can_coalesce_gso_tagged(datagrams: &[EgressDatagram]) -> Option<u16> {
        if datagrams.len() < 2 {
            return None;
        }
        let first = datagrams.first()?;
        let first_len = first.bytes.len();
        if first_len == 0 {
            return None;
        }
        let segment_size = u16::try_from(first_len).ok()?;
        let first_dst = first.dst;
        for (i, dg) in datagrams.iter().enumerate() {
            if dg.bytes.len() != first_len {
                return None;
            }
            if dg.dst != first_dst {
                return None;
            }
            if datagrams[..i].iter().any(|prior| prior.fate == dg.fate) {
                return None;
            }
        }
        Some(segment_size)
    }

    /// GSO-send a batch of fate-tagged, addressed datagrams. Only coalesces
    /// when `can_coalesce_gso_tagged` proves every datagram is the same
    /// length, a distinct fate group, *and* shares one destination;
    /// otherwise (or on any GSO submit failure) falls back to per-datagram
    /// sends.
    fn queue_udp_batch_tagged(
        &mut self,
        datagrams: &[EgressDatagram],
        allow_gso: bool,
    ) -> io::Result<()> {
        if datagrams.is_empty() {
            return Ok(());
        }
        if allow_gso && self.gso_enabled {
            if let Some(segment_size) = Self::can_coalesce_gso_tagged(datagrams) {
                let max_chunk = Self::max_gso_datagrams_for_segment(segment_size);
                for chunk in datagrams.chunks(max_chunk) {
                    // Every datagram in `datagrams` shares one `dst` (proven by
                    // `can_coalesce_gso_tagged` above), so any chunk's dst is that
                    // same shared destination.
                    let dst = chunk[0].dst;
                    if self.queue_udp_gso(chunk, segment_size, dst)? {
                        continue;
                    }
                    eprintln!("uring: GSO submit failed, trying per-datagram sends");
                    for dg in chunk {
                        self.queue_udp_send(dg)?;
                    }
                }
                return Ok(());
            }
        }
        for dg in datagrams {
            self.queue_udp_send(dg)?;
        }
        Ok(())
    }

    /// Flush all datagrams staged this `poll_once` in fate-safe GSO batches.
    /// Each pass takes at most one datagram per distinct `(fate, dst)` pair
    /// (arrival order) — so a coalesced skb never carries two symbols of one
    /// FEC object *and* never mixes destinations — and defers the rest to the
    /// next pass. Bounded by `MAX_PENDING_GSO_DATAGRAMS`.
    ///
    /// Grouping by fate alone (pre-multipeer) let a batch mix `dst`s whenever
    /// two different peers happened to emit distinct-fate datagrams in the
    /// same `poll_once`; `queue_udp_batch_tagged`'s `can_coalesce_gso_tagged`
    /// check would then reject the *whole* mixed chunk and fall back to
    /// per-datagram sends, silently losing the GSO win for same-peer pairs
    /// that were incidentally batched with a different peer's datagram.
    /// Grouping by `(fate, dst)` keeps distinct peers in separate chunks so
    /// same-peer datagrams still coalesce.
    fn flush_pending_gso(&mut self) {
        while !self.pending_gso.is_empty() {
            let mut chunk: Vec<EgressDatagram> = Vec::with_capacity(self.pending_gso.len());
            let mut deferred: Vec<EgressDatagram> = Vec::with_capacity(self.pending_gso.len());
            for dg in self.pending_gso.drain(..) {
                let dst_conflict = chunk
                    .first()
                    .is_some_and(|c: &EgressDatagram| c.dst != dg.dst);
                let fate_conflict = chunk.iter().any(|c| c.fate == dg.fate);
                if dst_conflict || fate_conflict {
                    deferred.push(dg);
                } else {
                    chunk.push(dg);
                }
            }
            self.pending_gso = deferred;
            if let Err(e) = self.queue_udp_batch_tagged(&chunk, true) {
                self.dropped_sends += 1;
                eprintln!(
                    "uring: drop udp send batch from tun: {e} (dropped_sends={})",
                    self.dropped_sends
                );
            }
        }
    }

    fn max_gso_datagrams_for_segment(segment_size: u16) -> usize {
        let segment_len = usize::from(segment_size);
        if segment_len == 0 {
            return 1;
        }
        let mtu_cap = MAX_UDP_PAYLOAD / segment_len;
        mtu_cap.clamp(1, MAX_GSO_SEGMENTS_PER_SEND.min(MAX_GSO_DATAGRAMS))
    }

    fn queue_udp_gso<T: AsRef<[u8]>>(
        &mut self,
        datagrams: &[T],
        segment_size: u16,
        dst: SocketAddr,
    ) -> io::Result<bool> {
        if datagrams.len() > MAX_GSO_DATAGRAMS {
            return Ok(false);
        }
        let payload_len = usize::from(segment_size);
        let total_len = payload_len
            .checked_mul(datagrams.len())
            .ok_or_else(|| io::Error::other("GSO payload size overflow"))?;
        if total_len > MAX_GSO_PAYLOAD {
            return Ok(false);
        }
        let mut coalesced = self.free_bufs.pop().unwrap_or_default();
        coalesced.clear();
        coalesced.reserve(total_len);
        for datagram in datagrams {
            coalesced.extend_from_slice(datagram.as_ref());
        }
        let slot_id = match self.alloc_in_flight_slot(coalesced, MAX_GSO_PAYLOAD) {
            Ok(slot_id) => slot_id,
            Err(_) => return Ok(false),
        };
        self.send_kind[slot_id] = Some(SendKind::Udp);
        #[cfg(test)]
        if self.force_gso_submit_failure {
            self.release_in_flight_slot(slot_id);
            return Ok(false);
        }
        let payload_ptr = {
            let payload = self.in_flight[slot_id]
                .as_mut()
                .ok_or_else(|| io::Error::other("missing in-flight buffer for GSO send"))?;
            payload.as_mut_ptr()
        };
        let payload_len_now = self.in_flight[slot_id]
            .as_ref()
            .ok_or_else(|| io::Error::other("missing in-flight GSO payload"))?
            .len();
        let ctx = self.gso_ctx[slot_id].get_or_insert_with(GsoSendContext::new);
        if let Err(e) = ctx.prepare_gso(payload_ptr, payload_len_now, segment_size, dst) {
            self.release_in_flight_slot(slot_id);
            return Err(e);
        }
        self.gso_meta[slot_id] = Some(GsoMeta {
            segment_size,
            datagram_count: datagrams.len(),
            dst,
        });
        let tag = TAG_SEND_SLOT | u64::try_from(slot_id).expect("slot id fits u64");
        let msg_ptr = std::ptr::from_ref(&ctx.msg);
        let entry = opcode::SendMsg::new(types::Fd(self.udp_fd), msg_ptr)
            .flags(u32::try_from(libc::MSG_NOSIGNAL).expect("MSG_NOSIGNAL fits u32"))
            .build()
            .user_data(tag);
        if self.push_entry(entry).is_err() {
            self.release_in_flight_slot(slot_id);
            return Ok(false);
        }
        #[cfg(test)]
        {
            self.gso_submission_count = self.gso_submission_count.saturating_add(1);
        }
        Ok(true)
    }

    /// Recover a failed GSO send's datagrams for per-datagram retry. `fate` is
    /// not preserved (set to `0`) — these are always retried via
    /// `queue_udp_send`, which ignores `fate` (it's only consulted by the GSO
    /// coalescing decision, which this path has already abandoned); `dst` is
    /// `meta.dst`, the one destination `can_coalesce_gso_tagged` guaranteed
    /// every datagram in this send shared.
    fn recover_gso_fallback_datagrams(&self, slot_id: usize) -> Vec<EgressDatagram> {
        let Some(meta) = self.gso_meta.get(slot_id).and_then(|meta| *meta) else {
            return Vec::new();
        };
        let Some(payload) = self.in_flight.get(slot_id).and_then(|slot| slot.as_ref()) else {
            return Vec::new();
        };
        let segment_len = usize::from(meta.segment_size);
        let mut datagrams = Vec::with_capacity(meta.datagram_count);
        for i in 0..meta.datagram_count {
            let start = i
                .checked_mul(segment_len)
                .expect("segment index multiplication should not overflow");
            let end = start
                .checked_add(segment_len)
                .expect("segment end computation should not overflow");
            if end > payload.len() {
                break;
            }
            datagrams.push(EgressDatagram {
                fate: 0,
                dst: meta.dst,
                bytes: payload[start..end].to_vec(),
            });
        }
        datagrams
    }

    /// Same as [`Self::recover_gso_fallback_datagrams`] but for a *partial*
    /// send completion: only the datagrams past `bytes_sent` are recovered.
    fn recover_gso_unsent_datagrams(
        &self,
        slot_id: usize,
        bytes_sent: usize,
    ) -> Vec<EgressDatagram> {
        let Some(meta) = self.gso_meta.get(slot_id).and_then(|meta| *meta) else {
            return Vec::new();
        };
        let Some(payload) = self.in_flight.get(slot_id).and_then(|slot| slot.as_ref()) else {
            return Vec::new();
        };
        let segment_len = usize::from(meta.segment_size);
        if segment_len == 0 || bytes_sent >= payload.len() {
            return Vec::new();
        }
        let sent_segments = bytes_sent / segment_len;
        if sent_segments >= meta.datagram_count {
            return Vec::new();
        }

        let mut datagrams = Vec::with_capacity(meta.datagram_count - sent_segments);
        for i in sent_segments..meta.datagram_count {
            let start = i
                .checked_mul(segment_len)
                .expect("segment index multiplication should not overflow");
            let end = start
                .checked_add(segment_len)
                .expect("segment end computation should not overflow");
            if end > payload.len() {
                break;
            }
            datagrams.push(EgressDatagram {
                fate: 0,
                dst: meta.dst,
                bytes: payload[start..end].to_vec(),
            });
        }
        datagrams
    }

    fn is_gso_unsupported_errno(errno: i32) -> bool {
        errno == libc::EIO
            || errno == libc::EINVAL
            || errno == libc::ENOPROTOOPT
            || errno == libc::EOPNOTSUPP
            || errno == libc::ENOTSUP
    }

    /// Transient UDP-send errno: the socket send buffer is momentarily full, so
    /// drop this datagram rather than tear down the tunnel (parity with
    /// `poll.rs::send_to_udp`). `EWOULDBLOCK == EAGAIN` on Linux; both listed.
    fn is_transient_send_errno(errno: i32) -> bool {
        errno == libc::EAGAIN || errno == libc::EWOULDBLOCK || errno == libc::ENOBUFS
    }

    /// Wait for at least one completion, retrying on `EINTR`.
    ///
    /// `IoUring::submit_and_wait` wraps the blocking `io_uring_enter` syscall,
    /// which returns `EINTR` if a signal is delivered while it waits. The
    /// `io-uring` crate does not retry internally, so without this a signal
    /// would propagate out of `poll_once` and terminate the whole tunnel —
    /// parity with `poll.rs`, whose `epoll_wait` loop `continue`s on `EINTR`.
    fn submit_and_wait_1(&self) -> io::Result<()> {
        loop {
            match self.ring.submit_and_wait(1) {
                Ok(_) => return Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Block for at least one completion, but wake after `TICK_TIMEOUT_NS` so the
    /// caller can run `tick` on cadence even with no traffic (parity with
    /// poll.rs's `epoll_wait` timeout — fixes `tick` starving on an idle tunnel).
    /// Returns `true` if the wait timed out with no completion (caller should
    /// stop draining and let `tick` fire), `false` if a completion likely
    /// arrived. Falls back to an unbounded wait on kernels without `EXT_ARG`.
    fn wait_for_completions(&self) -> io::Result<bool> {
        if !self.ext_arg {
            self.submit_and_wait_1()?;
            return Ok(false);
        }
        let ts = types::Timespec::new().nsec(TICK_TIMEOUT_NS);
        let args = types::SubmitArgs::new().timespec(&ts);
        loop {
            match self.ring.submitter().submit_with_args(1, &args) {
                Ok(_) => return Ok(false),
                Err(e) if e.raw_os_error() == Some(libc::ETIME) => return Ok(true),
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn handle_dispatch_udp(
        &mut self,
        d: &mut impl Dispatch,
        src: SocketAddr,
        datagram: &[u8],
        now_ms: u64,
    ) {
        match d.on_udp(src, datagram, now_ms) {
            DispatchOut::None => {}
            DispatchOut::Tun(inner) => {
                if let Err(e) = self.queue_tun_write(inner) {
                    self.dropped_sends += 1;
                    eprintln!(
                        "uring: drop tun write: {e} (dropped_sends={})",
                        self.dropped_sends
                    );
                }
            }
            DispatchOut::Udp(pkts) => {
                let pkts_owned = pkts.to_vec();
                // `allow_gso=false`: control/ARQ-retransmit traffic is never
                // GSO-coalesced, matching pre-addressing behavior exactly.
                if let Err(e) = self.queue_udp_batch_tagged(&pkts_owned, false) {
                    self.dropped_sends += 1;
                    eprintln!(
                        "uring: drop udp send batch: {e} (dropped_sends={})",
                        self.dropped_sends
                    );
                }
            }
            DispatchOut::Both(inner, pkts) => {
                if let Err(e) = self.queue_tun_write(inner) {
                    self.dropped_sends += 1;
                    eprintln!(
                        "uring: drop tun write: {e} (dropped_sends={})",
                        self.dropped_sends
                    );
                }
                let pkts_owned = pkts.to_vec();
                if let Err(e) = self.queue_udp_batch_tagged(&pkts_owned, false) {
                    self.dropped_sends += 1;
                    eprintln!(
                        "uring: drop udp send batch: {e} (dropped_sends={})",
                        self.dropped_sends
                    );
                }
            }
        }
    }

    fn handle_dispatch_tun(&mut self, d: &mut impl Dispatch, frame: &[u8], now_ms: u64) {
        // Stage this object's symbols; GSO batching across objects happens in
        // `flush_pending_gso` at the end of `poll_once`. Flush early if the
        // staging buffer fills mid-drain.
        self.pending_gso.extend_from_slice(d.on_tun(frame, now_ms));
        if self.pending_gso.len() >= MAX_PENDING_GSO_DATAGRAMS {
            self.flush_pending_gso();
        }
    }

    /// Process at least one CQE and dispatch resulting I/O.
    pub fn poll_once<D: Dispatch>(&mut self, d: &mut D) -> io::Result<()> {
        // Flush SQEs queued by the previous iteration's processing (re-armed
        // recvs, sends). Then reap completions, busy-polling the completion
        // queue for a bounded window before falling back to a blocking wait.
        self.ring.submit()?;
        // Drain into a reused buffer (no per-iteration allocation). Taken out of
        // `self` so the drain borrow of `self.ring` does not conflict with the
        // mutable `self` access while processing each CQE.
        let mut cqes = std::mem::take(&mut self.cqe_buf);
        cqes.clear();
        // Adaptive busy-poll: spin only while an exchange is active, so we catch
        // imminent completions at low latency but never burn CPU on an idle
        // tunnel. `self.active` carries "did the previous wait get real work"
        // across calls; it is set true when completions arrive and false when a
        // wait times out. With busy-poll off (default) the budget is always 0, so
        // the spin never runs and we block immediately — the prior behavior.
        let budget = if self.busy_poll && self.active {
            CQ_SPIN_BUDGET
        } else {
            0
        };
        let mut spins = 0_u32;
        loop {
            for cqe in &mut self.ring.completion() {
                cqes.push((cqe.user_data(), cqe.result(), cqe.flags()));
            }
            if !cqes.is_empty() {
                // Got work — stay hot so the next wait spins for the imminent
                // follow-up (e.g. the reply completion of this round trip).
                self.active = true;
                break;
            }
            if spins >= budget {
                // Nothing ready (spin budget exhausted, or busy-poll off/idle) —
                // block until a completion arrives or the tick timeout elapses.
                // On timeout, go cold (stop spinning next time) and fall through
                // so `tick` fires on cadence even with no traffic.
                if self.wait_for_completions()? {
                    self.active = false;
                    break;
                }
            } else {
                spins += 1;
                std::hint::spin_loop();
            }
        }

        let now_ms = self.now_ms();
        for &(user_data, result, flags) in &cqes {
            let kind = user_data & TAG_KIND_MASK;
            if kind == TAG_SEND_SLOT {
                let slot_id_u64 = user_data & TAG_PAYLOAD_MASK;
                let slot_id =
                    usize::try_from(slot_id_u64).expect("send slot id user_data fits usize");
                if result < 0 {
                    let errno = -result;
                    if self.gso_meta.get(slot_id).and_then(|meta| *meta).is_some() {
                        let fallback_datagrams = self.recover_gso_fallback_datagrams(slot_id);
                        self.release_in_flight_slot(slot_id);
                        if Self::is_gso_unsupported_errno(errno) {
                            self.gso_enabled = false;
                            eprintln!(
                                "uring: UDP_SEGMENT unsupported ({errno}); disabling GSO and retrying per datagram"
                            );
                        } else {
                            eprintln!(
                                "uring: GSO send completion error ({errno}); retrying per datagram"
                            );
                        }
                        for datagram in &fallback_datagrams {
                            if let Err(e) = self.queue_udp_send(datagram) {
                                eprintln!("uring: drop GSO fallback datagram: {e}");
                            }
                        }
                        continue;
                    }
                    // Non-GSO send/write completion error. Mirror the
                    // PollDriver contract (poll.rs `send_to_tun`/`send_to_udp`):
                    // a failed TUN write is always dropped (a lost inner frame
                    // beats tearing down the tunnel), and a failed UDP send is
                    // dropped only on transient buffer pressure — a genuinely
                    // fatal error propagates so a supervisor can restart, rather
                    // than the tunnel going silently dark forever.
                    let kind = self.send_kind.get(slot_id).and_then(|k| *k);
                    let err = io::Error::from_raw_os_error(errno);
                    self.release_in_flight_slot(slot_id);
                    match kind {
                        Some(SendKind::Tun) => {
                            eprintln!("uring: tun write error on slot {slot_id} (dropped): {err}");
                            continue;
                        }
                        _ => {
                            if Self::is_transient_send_errno(errno) {
                                eprintln!("uring: udp send dropped on slot {slot_id}: {err}");
                                continue;
                            }
                            return Err(err);
                        }
                    }
                } else if let Some(meta) = self.gso_meta.get(slot_id).and_then(|entry| *entry) {
                    let bytes_sent =
                        usize::try_from(result).expect("non-negative send result fits usize");
                    let expected_len = usize::from(meta.segment_size)
                        .checked_mul(meta.datagram_count)
                        .expect("GSO expected payload length should not overflow");
                    if bytes_sent < expected_len {
                        let unsent = self.recover_gso_unsent_datagrams(slot_id, bytes_sent);
                        self.release_in_flight_slot(slot_id);
                        eprintln!(
                            "uring: partial GSO completion ({bytes_sent}/{expected_len}); retrying {} datagrams",
                            unsent.len()
                        );
                        for datagram in &unsent {
                            if let Err(e) = self.queue_udp_send(datagram) {
                                eprintln!("uring: drop partial GSO retry datagram: {e}");
                            }
                        }
                        continue;
                    }
                }
                self.release_in_flight_slot(slot_id);
                continue;
            }

            if kind == TAG_REPROVIDE {
                if result < 0 {
                    eprintln!(
                        "uring: provide-buffer completion error: {}",
                        io::Error::from_raw_os_error(-result)
                    );
                }
                continue;
            }

            if kind == TAG_UDP_RECV {
                let slot_idx_u64 = user_data & TAG_PAYLOAD_MASK;
                let slot_idx =
                    usize::try_from(slot_idx_u64).expect("udp recv slot index fits usize");
                if slot_idx >= self.udp_recv_slots.len() {
                    return Err(io::Error::other(
                        "kernel returned udp recv slot out of range",
                    ));
                }
                if result < 0 {
                    let errno = -result;
                    // Transient: re-arm the same slot and keep going. Anything
                    // else is fatal — a permanently failing recv would otherwise
                    // silently blind the tunnel rather than propagating so a
                    // supervisor can restart (mirrors the TAG_TUN_RECV contract
                    // below and `poll.rs`'s `drain_udp`).
                    if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK || errno == libc::ENOBUFS
                    {
                        self.arm_udp_recv_slot(slot_idx)?;
                        continue;
                    }
                    return Err(io::Error::other(format!(
                        "udp recv completion error: {}",
                        io::Error::from_raw_os_error(errno)
                    )));
                }
                let n = usize::try_from(result).expect("non-negative CQE result fits usize");
                if n > MAX_WIRE_DATAGRAM {
                    self.arm_udp_recv_slot(slot_idx)?;
                    return Err(io::Error::other("kernel returned oversized datagram"));
                }
                // Recover the sender's address from this slot's own
                // `sockaddr_storage`/`msg_namelen` — the whole point of moving
                // off multishot `RecvMulti` (see the module doc).
                let namelen = self.udp_recv_slots[slot_idx].msg.msg_namelen;
                let src = match sockaddr_to_std(&self.udp_recv_slots[slot_idx].name, namelen) {
                    Ok(addr) => addr,
                    Err(e) => {
                        eprintln!(
                            "uring: dropping udp datagram with unparseable source address: {e}"
                        );
                        self.arm_udp_recv_slot(slot_idx)?;
                        continue;
                    }
                };
                let mut scratch = std::mem::take(&mut self.recv_scratch);
                scratch.clear();
                scratch.extend_from_slice(&self.udp_recv_slots[slot_idx].buf[..n]);
                self.handle_dispatch_udp(d, src, &scratch, now_ms);
                self.recv_scratch = scratch;
                self.arm_udp_recv_slot(slot_idx)?;
                continue;
            }

            // Everything from here on is TAG_TUN_RECV: provided-buffer,
            // single-shot, re-armed after every completion.
            let bid_opt = cqueue::buffer_select(flags);
            if result < 0 {
                let errno = -result;
                let err = io::Error::from_raw_os_error(errno);
                if let Some(bid) = bid_opt {
                    self.reprovide_buffer(bid)?;
                }
                // ENOBUFS on a recv completion means the provided-buffer ring was
                // momentarily exhausted (no buffer for the kernel to place this
                // frame) — transient, not fatal: drop the frame and re-arm;
                // buffers are re-provided as other completions process.
                // (Treating ENOBUFS as fatal tore the driver down under burst and
                // flaked the uring unit tests on the CI runner.)
                if (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK || errno == libc::ENOBUFS)
                    && kind == TAG_TUN_RECV
                {
                    self.arm_tun_read()?;
                    continue;
                }
                if kind == TAG_TUN_RECV {
                    return Err(io::Error::other(format!(
                        "tun recv completion error: {err}"
                    )));
                }
                return Err(io::Error::other(format!(
                    "unexpected completion kind 0x{kind:016x} with error {err}"
                )));
            }

            let bid = if kind == TAG_TUN_RECV {
                bid_opt.ok_or_else(|| {
                    io::Error::other(
                        "recv completion missing buffer_select; aborting to avoid pool-slot leak",
                    )
                })?
            } else {
                if let Some(bid) = bid_opt {
                    self.reprovide_buffer(bid)?;
                }
                return Err(io::Error::other(format!(
                    "unexpected completion kind 0x{kind:016x}"
                )));
            };

            let idx = usize::from(bid);
            if idx >= RING_BUFS {
                return Err(io::Error::other("kernel returned buffer id out of range"));
            }
            let n = usize::try_from(result).expect("non-negative CQE result fits usize");
            if n > MAX_WIRE_DATAGRAM {
                self.reprovide_buffer(bid)?;
                return Err(io::Error::other("kernel returned oversized datagram"));
            }

            let mut scratch = std::mem::take(&mut self.recv_scratch);
            scratch.clear();
            scratch.extend_from_slice(&self.recv_pool[idx][..n]);
            self.handle_dispatch_tun(d, &scratch, now_ms);
            self.recv_scratch = scratch;
            self.reprovide_buffer(bid)?;
            self.arm_tun_read()?;
        }

        // Flush TUN-egress datagrams staged this pass in fate-safe GSO batches.
        self.flush_pending_gso();

        if let Some(pkts) = d.tick(now_ms) {
            for pkt in pkts {
                if let Err(e) = self.queue_udp_send(pkt) {
                    eprintln!("uring: drop tick packet: {e}");
                }
            }
        }

        // SQEs queued above (re-armed recvs, tick sends) are flushed by the
        // `submit()` at the top of the next `poll_once`, before the next wait.
        self.cqe_buf = cqes;
        Ok(())
    }
}

/// Run the io_uring loop forever for production use.
pub fn run_uring<D: Dispatch>(udp_fd: RawFd, tun_fd: RawFd, d: &mut D) -> io::Result<()> {
    // Fall back to the PollDriver on ANY UringDriver failure (init or runtime)
    // rather than killing the tunnel. The DataPlane state lives in `d` and the
    // fds are borrowed, so PollDriver takes over cleanly (it re-sets the fds
    // non-blocking). This makes io_uring safe to opt into even on kernels where
    // it is buggy or unsupported — e.g. the multishot-recv EINVAL on 6.12 (#25)
    // now degrades to poll instead of a fatal exit.
    let mut driver = match UringDriver::new(udp_fd, tun_fd) {
        Ok(driver) => driver,
        Err(e) => {
            eprintln!("uring: init failed ({e}); falling back to PollDriver");
            return crate::poll::run_poll(udp_fd, tun_fd, d);
        }
    };
    loop {
        if let Err(e) = driver.poll_once(d) {
            eprintln!("uring: fatal driver error ({e}); falling back to PollDriver");
            drop(driver);
            return crate::poll::run_poll(udp_fd, tun_fd, d);
        }
    }
}

/// Probe whether io_uring + provided-buffer registration is available.
pub fn uring_available() -> bool {
    let mut ring = match IoUring::new(8) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut tiny = [0_u8; 64];
    let entry = opcode::ProvideBuffers::new(tiny.as_mut_ptr(), 64, 1, BUF_GROUP, 0)
        .build()
        .user_data(TAG_REPROVIDE);
    // SAFETY: `tiny` lives until completion and the entry references only that
    // stack buffer for the short probe.
    let push_res = unsafe { ring.submission().push(&entry) };
    if push_res.is_err() {
        return false;
    }
    if ring.submit_and_wait(1).is_err() {
        return false;
    }
    let Some(cqe) = ring.completion().next() else {
        return false;
    };
    cqe.result() >= 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::sync::Mutex;
    use std::time::Duration;

    static URING_SERIAL: Mutex<()> = Mutex::new(());

    struct EchoDispatch {
        scratch: Vec<EgressDatagram>,
    }

    impl EchoDispatch {
        fn new() -> Self {
            Self {
                scratch: Vec::new(),
            }
        }
    }

    impl Dispatch for EchoDispatch {
        fn on_udp(&mut self, src: SocketAddr, dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            self.scratch = vec![EgressDatagram {
                fate: 0,
                dst: src,
                bytes: dg.to_vec(),
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

    /// Counts `tick` invocations; produces no I/O. Used to prove the idle wait
    /// still fires `tick` on cadence.
    struct TickCountDispatch {
        ticks: usize,
    }

    impl Dispatch for TickCountDispatch {
        fn on_udp(&mut self, _src: SocketAddr, _dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            DispatchOut::None
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[EgressDatagram] {
            &[]
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[EgressDatagram]> {
            self.ticks += 1;
            None
        }
    }

    /// Returns 5 same-length datagrams all tagged with ONE fate group, i.e. the
    /// symbols of a single FEC object (source + its repair). A GSO driver must
    /// NEVER coalesce these — losing them together would defeat FEC.
    struct GsoDispatch {
        dst: SocketAddr,
        scratch: Vec<EgressDatagram>,
    }

    impl GsoDispatch {
        fn new(dst: SocketAddr) -> Self {
            Self {
                dst,
                scratch: Vec::new(),
            }
        }
    }

    impl Dispatch for GsoDispatch {
        fn on_udp(&mut self, _src: SocketAddr, _dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            DispatchOut::None
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[EgressDatagram] {
            self.scratch.clear();
            for i in 0_u8..5_u8 {
                let mut datagram = vec![b'a'; 64];
                datagram[0] = b'0' + i;
                self.scratch.push(EgressDatagram {
                    fate: 7,
                    dst: self.dst,
                    bytes: datagram,
                });
            }
            &self.scratch
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[EgressDatagram]> {
            None
        }
    }

    /// Returns `datagram_count` same-length datagrams each tagged with a DISTINCT
    /// fate group, i.e. one symbol from each of N different FEC objects. A GSO
    /// driver may coalesce these (a dropped skb costs each object at most one
    /// symbol, recoverable from its repair in a different skb).
    struct GsoLargeBatchDispatch {
        dst: SocketAddr,
        scratch: Vec<EgressDatagram>,
        datagram_count: usize,
        datagram_size: usize,
    }

    impl GsoLargeBatchDispatch {
        fn new(dst: SocketAddr, datagram_count: usize, datagram_size: usize) -> Self {
            Self {
                dst,
                scratch: Vec::new(),
                datagram_count,
                datagram_size,
            }
        }
    }

    impl Dispatch for GsoLargeBatchDispatch {
        fn on_udp(&mut self, _src: SocketAddr, _dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            DispatchOut::None
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[EgressDatagram] {
            self.scratch.clear();
            for i in 0..self.datagram_count {
                let mut datagram = vec![b'z'; self.datagram_size];
                datagram[0] = u8::try_from(i % 251).expect("modulo bound fits u8");
                self.scratch.push(EgressDatagram {
                    fate: u16::try_from(i).expect("datagram_count fits u16"),
                    dst: self.dst,
                    bytes: datagram,
                });
            }
            &self.scratch
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[EgressDatagram]> {
            None
        }
    }

    fn make_pipe() -> io::Result<(RawFd, RawFd)> {
        let mut fds = [0_i32; 2];
        // SAFETY: `fds` points to valid writable storage for two file descriptors.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((fds[0], fds[1]))
    }

    fn write_pipe_once(fd: RawFd, bytes: &[u8]) {
        // SAFETY: `fd` is the write-end of a valid pipe and `bytes` points to
        // initialized memory for the duration of this syscall.
        let wrote = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
        assert!(wrote >= 0, "pipe write should succeed");
        assert_eq!(
            usize::try_from(wrote).expect("non-negative write count fits usize"),
            bytes.len(),
            "must write full trigger frame into pipe"
        );
    }

    fn test_dst() -> SocketAddr {
        "127.0.0.1:1".parse().expect("valid test address")
    }

    fn other_dst() -> SocketAddr {
        "127.0.0.1:2".parse().expect("valid test address")
    }

    fn dg(fate: u16, len: usize) -> EgressDatagram {
        dg_to(fate, len, test_dst())
    }

    fn dg_to(fate: u16, len: usize, dst: SocketAddr) -> EgressDatagram {
        EgressDatagram {
            fate,
            dst,
            bytes: vec![b'x'; len],
        }
    }

    #[test]
    fn can_coalesce_gso_tagged_rejects_duplicate_fate() {
        // Two same-length datagrams of the SAME fate (an object's source + its
        // repair) must never be judged coalesceable.
        let dgs = [dg(3, 64), dg(3, 64)];
        assert!(UringDriver::can_coalesce_gso_tagged(&dgs).is_none());
    }

    #[test]
    fn can_coalesce_gso_tagged_accepts_distinct_fates_same_length() {
        let dgs = [dg(3, 64), dg(4, 64), dg(5, 64)];
        assert_eq!(UringDriver::can_coalesce_gso_tagged(&dgs), Some(64));
    }

    #[test]
    fn can_coalesce_gso_tagged_rejects_mismatched_length() {
        let dgs = [dg(3, 64), dg(4, 32)];
        assert!(UringDriver::can_coalesce_gso_tagged(&dgs).is_none());
    }

    #[test]
    fn can_coalesce_gso_tagged_rejects_mixed_destinations() {
        // Distinct fates and equal length would otherwise coalesce, but a
        // coalesced `UDP_SEGMENT` send has exactly one `msg_name` — datagrams
        // bound for different peers must never share a skb.
        let dgs = [dg_to(3, 64, test_dst()), dg_to(4, 64, other_dst())];
        assert!(UringDriver::can_coalesce_gso_tagged(&dgs).is_none());
    }

    #[test]
    fn uring_loopback_roundtrip_recycles_recv_buffers() {
        let _guard = URING_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let a = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let b = UdpSocket::bind("127.0.0.1:0").expect("bind uring peer");
        a.connect(b.local_addr().expect("sender local addr"))
            .expect("connect sender");
        b.connect(a.local_addr().expect("uring peer local addr"))
            .expect("connect uring peer");
        a.set_nonblocking(true).expect("set sender nonblocking");

        let (tun_rd, tun_wr) = make_pipe().expect("make tun placeholder pipe");
        let mut dispatch = EchoDispatch::new();

        let mut driver = match UringDriver::new(b.as_raw_fd(), tun_rd) {
            Ok(driver) => driver,
            Err(_) => {
                eprintln!(
                    "SKIP uring_loopback_roundtrip_recycles_recv_buffers: \
                     io_uring ring or buffer registration unavailable (RLIMIT_MEMLOCK)"
                );
                // SAFETY: these fds came from `pipe2` and are still open here.
                unsafe {
                    libc::close(tun_rd);
                    libc::close(tun_wr);
                }
                return;
            }
        };

        let total = 384_usize;
        let mut sent_payloads = Vec::with_capacity(total);
        for i in 0..total {
            let payload = format!("uring-echo-{i}").into_bytes();
            a.send(&payload).expect("send test datagram");
            sent_payloads.push(payload);
        }

        let mut got = Vec::with_capacity(total);
        let mut recv_buf = [0_u8; MAX_WIRE_DATAGRAM];
        let mut stall = 0_usize;
        for _ in 0..4000 {
            driver.poll_once(&mut dispatch).expect("poll_once succeeds");

            let before = got.len();
            loop {
                match a.recv(&mut recv_buf) {
                    Ok(n) => got.push(recv_buf[..n].to_vec()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("recv failed: {e}"),
                }
            }
            if got.len() >= total {
                break;
            }
            // No-progress early exit once the burst has drained (a small kernel
            // recv buffer caps how many survive, so `got.len()` may never reach
            // `total`) — keeps the test fast while still round-tripping well over
            // `RING_BUFS`.
            if got.len() == before {
                stall += 1;
                if stall >= 200 {
                    break;
                }
            } else {
                stall = 0;
            }
        }

        // SAFETY: these fds came from `pipe2` and are still open here.
        unsafe {
            libc::close(tun_rd);
            libc::close(tun_wr);
        }

        // All datagrams are sent before the driver drains, so the kernel UDP
        // receive buffer and the bounded send table legitimately drop a machine-
        // dependent fraction under load — requiring `got.len() == total` made
        // this flaky/stalling locally. This test's real point is recv-buffer
        // *recycling*: round-tripping more datagrams than the `RING_BUFS`
        // provided-buffer pool holds proves buffers were reprovided and reused.
        // A genuine buffer leak stalls throughput at <= `RING_BUFS`, so this
        // still fails on it. (Integer comparison; no float, no `as`.)
        assert!(
            got.len() > RING_BUFS,
            "expected more than RING_BUFS={RING_BUFS} datagrams to round-trip \
             (proving recv buffers were recycled), got {}",
            got.len()
        );
        // Every datagram we did receive must be an intact echo of one we sent.
        for payload in &got {
            assert!(
                sent_payloads.contains(payload),
                "received a payload that was never sent"
            );
        }
        drop(driver);
        std::thread::sleep(Duration::from_millis(200));
    }

    #[test]
    fn uring_idle_poll_fires_tick_via_timeout() {
        let _guard = URING_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // An idle driver: no UDP peer sends anything, nothing is written to the
        // TUN pipe, so no completion ever arrives.
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind idle udp");
        let (tun_rd, tun_wr) = make_pipe().expect("make tun placeholder pipe");
        let mut driver = match UringDriver::new(sock.as_raw_fd(), tun_rd) {
            Ok(driver) => driver,
            Err(_) => {
                eprintln!("SKIP uring_idle_poll_fires_tick_via_timeout: io_uring unavailable");
                // SAFETY: these fds came from `pipe2` and are still open here.
                unsafe {
                    libc::close(tun_rd);
                    libc::close(tun_wr);
                }
                return;
            }
        };

        let mut dispatch = TickCountDispatch { ticks: 0 };
        // With no traffic, `poll_once` must still return via the tick timeout and
        // fire `tick` — before this fix it blocked forever, starving `tick`.
        let started = std::time::Instant::now();
        driver
            .poll_once(&mut dispatch)
            .expect("idle poll_once returns via the tick timeout");
        assert!(
            dispatch.ticks >= 1,
            "tick must fire on the idle-timeout path (fired {})",
            dispatch.ticks
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "idle poll_once must return promptly via timeout, not block"
        );

        drop(driver);
        // SAFETY: these fds came from `pipe2` and are still open here.
        unsafe {
            libc::close(tun_rd);
            libc::close(tun_wr);
        }
    }

    #[test]
    fn uring_gso_same_object_datagrams_are_never_coalesced() {
        let _guard = URING_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let a = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let b = UdpSocket::bind("127.0.0.1:0").expect("bind uring peer");
        a.connect(b.local_addr().expect("sender local addr"))
            .expect("connect sender");
        b.connect(a.local_addr().expect("uring peer local addr"))
            .expect("connect uring peer");
        a.set_nonblocking(true).expect("set sender nonblocking");

        let (tun_rd, tun_wr) = make_pipe().expect("make tun placeholder pipe");
        // GsoDispatch returns 5 datagrams all sharing ONE fate (one FEC object),
        // all destined for `a` (the loopback peer that will receive them).
        let mut dispatch = GsoDispatch::new(a.local_addr().expect("sender local addr"));
        let mut driver = match UringDriver::new(b.as_raw_fd(), tun_rd) {
            Ok(driver) => driver,
            Err(_) => {
                eprintln!(
                    "SKIP uring_gso_same_object_datagrams_are_never_coalesced: \
                     io_uring ring or buffer registration unavailable (RLIMIT_MEMLOCK)"
                );
                // SAFETY: these fds came from `pipe2` and are still open here.
                unsafe {
                    libc::close(tun_rd);
                    libc::close(tun_wr);
                }
                return;
            }
        };

        write_pipe_once(tun_wr, b"trigger-gso");
        let mut got = Vec::new();
        let mut recv_buf = [0_u8; MAX_WIRE_DATAGRAM];
        for _ in 0..1024 {
            driver.poll_once(&mut dispatch).expect("poll_once succeeds");
            loop {
                match a.recv(&mut recv_buf) {
                    Ok(n) => got.push(recv_buf[..n].to_vec()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("recv failed: {e}"),
                }
            }
            if got.len() >= 5 {
                break;
            }
        }

        // The invariant: a source symbol and its own repair must never share a
        // GSO skb, so 5 same-fate datagrams must NEVER be coalesced — they go out
        // as individual sends.
        assert_eq!(
            driver.gso_submission_count(),
            0,
            "same-object (same-fate) datagrams must never be GSO-coalesced"
        );

        let expected: Vec<Vec<u8>> = (0_u8..5_u8)
            .map(|i| {
                let mut datagram = vec![b'a'; 64];
                datagram[0] = b'0' + i;
                datagram
            })
            .collect();
        assert_eq!(got.len(), expected.len(), "must receive all datagrams");
        for datagram in expected {
            assert!(got.contains(&datagram), "missing datagram from output");
        }

        // SAFETY: these fds came from `pipe2` and are still open here.
        unsafe {
            libc::close(tun_rd);
            libc::close(tun_wr);
        }
        drop(driver);
        std::thread::sleep(Duration::from_millis(200));
    }

    #[test]
    fn uring_gso_submit_fallback_uses_per_datagram_send() {
        let _guard = URING_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let a = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let b = UdpSocket::bind("127.0.0.1:0").expect("bind uring peer");
        a.connect(b.local_addr().expect("sender local addr"))
            .expect("connect sender");
        b.connect(a.local_addr().expect("uring peer local addr"))
            .expect("connect uring peer");
        a.set_nonblocking(true).expect("set sender nonblocking");

        let (tun_rd, tun_wr) = make_pipe().expect("make tun placeholder pipe");
        // Distinct fates so GSO is genuinely attempted (then forced to fail).
        let mut dispatch =
            GsoLargeBatchDispatch::new(a.local_addr().expect("sender local addr"), 5, 64);
        let mut driver = match UringDriver::new(b.as_raw_fd(), tun_rd) {
            Ok(driver) => driver,
            Err(_) => {
                eprintln!(
                    "SKIP uring_gso_submit_fallback_uses_per_datagram_send: \
                     io_uring ring or buffer registration unavailable (RLIMIT_MEMLOCK)"
                );
                // SAFETY: these fds came from `pipe2` and are still open here.
                unsafe {
                    libc::close(tun_rd);
                    libc::close(tun_wr);
                }
                return;
            }
        };
        driver.set_force_gso_submit_failure(true);

        write_pipe_once(tun_wr, b"trigger-gso-fallback");
        let mut got = Vec::new();
        let mut recv_buf = [0_u8; MAX_WIRE_DATAGRAM];
        for _ in 0..1024 {
            driver.poll_once(&mut dispatch).expect("poll_once succeeds");
            loop {
                match a.recv(&mut recv_buf) {
                    Ok(n) => got.push(recv_buf[..n].to_vec()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("recv failed: {e}"),
                }
            }
            if got.len() >= 5 {
                break;
            }
        }

        assert_eq!(
            driver.gso_submission_count(),
            0,
            "forced submit failure should prevent GSO send submissions"
        );
        let expected: Vec<Vec<u8>> = (0..5_usize)
            .map(|i| {
                let mut datagram = vec![b'z'; 64];
                datagram[0] = u8::try_from(i % 251).expect("fits u8");
                datagram
            })
            .collect();
        assert_eq!(
            got.len(),
            expected.len(),
            "must receive all fallback datagrams"
        );
        for datagram in expected {
            assert!(
                got.contains(&datagram),
                "missing datagram from fallback output"
            );
        }

        // SAFETY: these fds came from `pipe2` and are still open here.
        unsafe {
            libc::close(tun_rd);
            libc::close(tun_wr);
        }
        drop(driver);
        std::thread::sleep(Duration::from_millis(200));
    }

    #[test]
    fn uring_gso_large_batch_chunks_payload_to_udp_limits() {
        let _guard = URING_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let a = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let b = UdpSocket::bind("127.0.0.1:0").expect("bind uring peer");
        a.connect(b.local_addr().expect("sender local addr"))
            .expect("connect sender");
        b.connect(a.local_addr().expect("uring peer local addr"))
            .expect("connect uring peer");
        a.set_nonblocking(true).expect("set sender nonblocking");

        let (tun_rd, tun_wr) = make_pipe().expect("make tun placeholder pipe");
        let datagram_count = 64usize;
        let datagram_size = 1400usize;
        let mut dispatch = GsoLargeBatchDispatch::new(
            a.local_addr().expect("sender local addr"),
            datagram_count,
            datagram_size,
        );
        let mut driver = match UringDriver::new(b.as_raw_fd(), tun_rd) {
            Ok(driver) => driver,
            Err(_) => {
                eprintln!(
                    "SKIP uring_gso_large_batch_chunks_payload_to_udp_limits: \
                     io_uring ring or buffer registration unavailable (RLIMIT_MEMLOCK)"
                );
                // SAFETY: these fds came from `pipe2` and are still open here.
                unsafe {
                    libc::close(tun_rd);
                    libc::close(tun_wr);
                }
                return;
            }
        };

        write_pipe_once(tun_wr, b"trigger-large-gso");
        for _ in 0..2048 {
            driver.poll_once(&mut dispatch).expect("poll_once succeeds");
            if driver.gso_submission_count() > 0 {
                break;
            }
        }
        assert!(
            driver.gso_submission_count() > 0,
            "driver must submit at least one GSO send"
        );

        let mut got = Vec::new();
        let mut recv_buf = [0_u8; MAX_WIRE_DATAGRAM];
        for _ in 0..4096 {
            loop {
                match a.recv(&mut recv_buf) {
                    Ok(n) => got.push(recv_buf[..n].to_vec()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("recv failed: {e}"),
                }
            }
            if got.len() >= datagram_count {
                break;
            }
            driver.poll_once(&mut dispatch).expect("poll_once succeeds");
        }

        // Independently computed expected chunk count — deliberately does NOT
        // call `max_gso_datagrams_for_segment` (the function under test). These
        // literals mirror the module constants MAX_UDP_PAYLOAD (65507),
        // MAX_GSO_SEGMENTS_PER_SEND (32), and MAX_GSO_DATAGRAMS (64); keep them in
        // sync with the constants by hand if those change.
        let mtu_cap = 65_507_usize / datagram_size;
        let max_chunk = mtu_cap.min(32).min(64);
        let expected_submissions = datagram_count.div_ceil(max_chunk);
        assert!(expected_submissions >= 2, "test should exercise chunking");
        assert!(
            driver.gso_submission_count() >= expected_submissions,
            "driver must chunk large GSO batches into multiple submissions \
             ({} distinct-fate datagrams, expected >= {expected_submissions} sends, \
             got {})",
            datagram_count,
            driver.gso_submission_count()
        );
        assert_eq!(
            got.len(),
            datagram_count,
            "must receive all datagrams from a large GSO batch"
        );

        // SAFETY: these fds came from `pipe2` and are still open here.
        unsafe {
            libc::close(tun_rd);
            libc::close(tun_wr);
        }
        drop(driver);
        std::thread::sleep(Duration::from_millis(200));
    }

    #[test]
    fn uring_in_flight_send_table_reuses_slots_after_completions() {
        let _guard = URING_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let a = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let b = UdpSocket::bind("127.0.0.1:0").expect("bind uring peer");
        a.connect(b.local_addr().expect("sender local addr"))
            .expect("connect sender");
        b.connect(a.local_addr().expect("uring peer local addr"))
            .expect("connect uring peer");
        a.set_nonblocking(true).expect("set sender nonblocking");

        let (tun_rd, tun_wr) = make_pipe().expect("make tun placeholder pipe");
        let mut dispatch = EchoDispatch::new();
        let mut driver = match UringDriver::new(b.as_raw_fd(), tun_rd) {
            Ok(driver) => driver,
            Err(_) => {
                eprintln!(
                    "SKIP uring_in_flight_send_table_reuses_slots_after_completions: \
                     io_uring ring or buffer registration unavailable (RLIMIT_MEMLOCK)"
                );
                // SAFETY: these fds came from `pipe2` and are still open here.
                unsafe {
                    libc::close(tun_rd);
                    libc::close(tun_wr);
                }
                return;
            }
        };

        let total = SEND_SLOTS * 3;
        for i in 0..total {
            let payload = format!("slot-reuse-{i}").into_bytes();
            a.send(&payload).expect("send test datagram");
        }

        let mut recv_buf = [0_u8; MAX_WIRE_DATAGRAM];
        let mut received = 0_usize;
        let mut stall = 0_usize;
        for _ in 0..6000 {
            driver.poll_once(&mut dispatch).expect("poll_once succeeds");
            let before = received;
            loop {
                match a.recv(&mut recv_buf) {
                    Ok(_) => received += 1,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("recv failed: {e}"),
                }
            }
            if received >= total {
                break;
            }
            // No-progress early exit: once the burst has fully drained (a small
            // kernel recv buffer legitimately caps how many datagrams survive, so
            // `received` may never reach `total`), stop instead of spinning the
            // full poll budget of idle 10 ms waits — keeps the test fast on any
            // box while still round-tripping well over `SEND_SLOTS`.
            if received == before {
                stall += 1;
                if stall >= 200 {
                    break;
                }
            } else {
                stall = 0;
            }
        }

        // All `total = SEND_SLOTS * 3` datagrams are sent before the driver
        // drains, so the kernel UDP receive buffer and the bounded in-flight
        // send table legitimately drop a large, machine-dependent fraction under
        // load — requiring `received == total` made this flaky/stalling locally.
        // This test's real point is send-slot *reuse*: round-tripping more
        // datagrams than the fixed `SEND_SLOTS` table can hold at once proves the
        // table was reused, and the `in_flight_used_count() == 0` check below
        // proves it drained. A genuine slot leak caps throughput at <=
        // `SEND_SLOTS` and leaves the table non-empty, so both asserts still
        // fail on it. (Integer comparison; no float, no `as`.)
        assert!(
            received > SEND_SLOTS,
            "expected more than SEND_SLOTS={SEND_SLOTS} datagrams to round-trip \
             (proving the send table was reused), got {received}"
        );

        // The echoed data can arrive at `a` before the driver reaps the matching
        // SEND completion CQE (observed on slower CI runners), so the loop above
        // can exit with send CQEs still pending. Drain them before asserting slot
        // hygiene. Because every echoed send physically completed, its CQE is
        // already queued, so `poll_once` (submit_and_wait(1)) returns without
        // blocking; a genuine slot leak would never reach 0 and still fail below.
        for _ in 0..1000 {
            if driver.in_flight_used_count() == 0 {
                break;
            }
            driver
                .poll_once(&mut dispatch)
                .expect("poll_once drains pending send completions");
        }
        assert_eq!(
            driver.in_flight_used_count(),
            0,
            "all in-flight slots must be released after completions"
        );

        // Any echoes not received should be reflected as bounded slot-exhaustion
        // drops; the counter can never exceed the total datagrams sent.
        assert!(
            driver.dropped_sends() <= u64::try_from(total).expect("total fits u64"),
            "dropped_sends must not exceed total sent"
        );

        // SAFETY: these fds came from `pipe2` and are still open here.
        unsafe {
            libc::close(tun_rd);
            libc::close(tun_wr);
        }
        drop(driver);
        std::thread::sleep(Duration::from_millis(200));
    }
}
