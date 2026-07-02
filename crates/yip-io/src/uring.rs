//! io_uring driver using one ring over UDP + TUN with provided-buffer receives.
//!
//! This backend keeps one ring alive and drives both fds from it. UDP receives
//! use multishot `recv` with `BUFFER_SELECT`. TUN uses a single pooled read that
//! is re-submitted after each completion; multishot `read` is not yet relied on.

use std::io;
use std::os::fd::RawFd;
use std::time::Instant;

use io_uring::{cqueue, opcode, squeue, types, IoUring};

use crate::poll::{Dispatch, DispatchOut};
use crate::{MAX_DATAGRAM_BATCH, MAX_WIRE_DATAGRAM};

const RING_ENTRIES: u32 = 512;
const RING_BUFS: usize = 256;
const TUN_READ_DEPTH: usize = 16;
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
const MAX_GSO_SEGMENTS_PER_SEND: usize = 1;
const GSO_CONTROL_PAYLOAD_LEN_U32: u32 = 2;
const GSO_CONTROL_SPACE: usize = 64;

#[derive(Clone, Copy)]
struct GsoMeta {
    segment_size: u16,
    datagram_count: usize,
}

/// Which fd an in-flight send slot targets, so completion-error handling can
/// mirror `PollDriver`: TUN writes are always dropped, UDP sends drop on
/// transient buffer pressure but propagate genuinely fatal errors.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SendKind {
    Udp,
    Tun,
}

struct GsoSendContext {
    iov: libc::iovec,
    msg: libc::msghdr,
    control: [u8; GSO_CONTROL_SPACE],
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
        }
    }

    fn prepare(
        &mut self,
        payload_ptr: *mut u8,
        payload_len: usize,
        segment_size: u16,
    ) -> io::Result<()> {
        self.iov.iov_base = payload_ptr.cast::<libc::c_void>();
        self.iov.iov_len = payload_len;
        self.msg.msg_name = std::ptr::null_mut();
        self.msg.msg_namelen = 0;
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

/// One-ring io_uring driver handling UDP + TUN.
pub struct UringDriver {
    ring: IoUring,
    udp_fd: RawFd,
    tun_fd: RawFd,
    recv_pool: Box<[[u8; MAX_WIRE_DATAGRAM]; RING_BUFS]>,
    in_flight: Vec<Option<Vec<u8>>>,
    gso_meta: Vec<Option<GsoMeta>>,
    gso_ctx: Vec<Option<GsoSendContext>>,
    send_kind: Vec<Option<SendKind>>,
    gso_enabled: bool,
    started: Instant,
    udp_armed: bool,
    tun_armed: bool,
    #[cfg(test)]
    gso_submission_count: usize,
    #[cfg(test)]
    force_gso_submit_failure: bool,
}

impl UringDriver {
    /// Build and arm a ring over the provided UDP and TUN file descriptors.
    pub fn new(udp_fd: RawFd, tun_fd: RawFd) -> io::Result<Self> {
        let ring = IoUring::new(RING_ENTRIES)?;
        let recv_pool = Box::new([[0_u8; MAX_WIRE_DATAGRAM]; RING_BUFS]);
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
            in_flight,
            gso_meta,
            gso_ctx,
            send_kind,
            gso_enabled: true,
            started: Instant::now(),
            udp_armed: false,
            tun_armed: false,
            #[cfg(test)]
            gso_submission_count: 0,
            #[cfg(test)]
            force_gso_submit_failure: false,
        };

        driver.provide_all_buffers()?;
        driver.arm_udp_recv()?;
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

    fn arm_udp_recv(&mut self) -> io::Result<()> {
        let entry = opcode::RecvMulti::new(types::Fd(self.udp_fd), BUF_GROUP)
            .len(MAX_WIRE_DATAGRAM_U32)
            .build()
            .user_data(TAG_UDP_RECV);
        self.push_entry(entry)?;
        self.udp_armed = true;
        Ok(())
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
        self.tun_armed = true;
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
    fn set_force_gso_submit_failure(&mut self, force: bool) {
        self.force_gso_submit_failure = force;
    }

    fn alloc_in_flight_slot(
        &mut self,
        payload: Vec<u8>,
        payload_limit: usize,
    ) -> io::Result<usize> {
        if payload.len() > payload_limit {
            return Err(io::Error::other("payload exceeds in-flight slot limit"));
        }
        let Some((idx, slot)) = self
            .in_flight
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no free in-flight send slots available",
            ));
        };
        *slot = Some(payload);
        Ok(idx)
    }

    fn queue_udp_send(&mut self, datagram: &[u8]) -> io::Result<()> {
        let slot_id = self.alloc_in_flight_slot(datagram.to_vec(), MAX_WIRE_DATAGRAM)?;
        self.send_kind[slot_id] = Some(SendKind::Udp);
        let (ptr, len_u32) = {
            let slot_buf = self.in_flight[slot_id]
                .as_ref()
                .ok_or_else(|| io::Error::other("missing in-flight buffer for udp send"))?;
            let len_u32 = u32::try_from(slot_buf.len())
                .map_err(|_| io::Error::other("send buffer too large"))?;
            (slot_buf.as_ptr(), len_u32)
        };
        let tag = TAG_SEND_SLOT | u64::try_from(slot_id).expect("slot id fits u64");
        let entry = opcode::Send::new(types::Fd(self.udp_fd), ptr, len_u32)
            .flags(libc::MSG_NOSIGNAL)
            .build()
            .user_data(tag);
        if let Err(e) = self.push_entry(entry) {
            self.release_in_flight_slot(slot_id);
            return Err(e);
        }
        Ok(())
    }

    fn queue_tun_write(&mut self, frame: &[u8]) -> io::Result<()> {
        let slot_id = self.alloc_in_flight_slot(frame.to_vec(), MAX_WIRE_DATAGRAM)?;
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
        self.in_flight[slot_id] = None;
        self.gso_meta[slot_id] = None;
        self.gso_ctx[slot_id] = None;
        self.send_kind[slot_id] = None;
    }

    fn can_coalesce_gso(datagrams: &[Vec<u8>]) -> Option<u16> {
        if datagrams.len() < 2 {
            return None;
        }
        let first_len = datagrams.first()?.len();
        if first_len == 0 {
            return None;
        }
        let segment_size = u16::try_from(first_len).ok()?;
        if datagrams.iter().any(|dg| dg.len() != first_len) {
            return None;
        }
        Some(segment_size)
    }

    fn queue_udp_batch(&mut self, datagrams: &[Vec<u8>], allow_gso: bool) -> io::Result<()> {
        if datagrams.is_empty() {
            return Ok(());
        }
        if allow_gso && self.gso_enabled {
            if let Some(segment_size) = Self::can_coalesce_gso(datagrams) {
                let max_chunk = Self::max_gso_datagrams_for_segment(segment_size);
                for chunk in datagrams.chunks(max_chunk) {
                    if self.queue_udp_gso(chunk, segment_size)? {
                        continue;
                    }
                    eprintln!("uring: GSO submit failed, trying per-datagram sends");
                    for datagram in chunk {
                        self.queue_udp_send(datagram)?;
                    }
                }
                return Ok(());
            }
        }
        for datagram in datagrams {
            self.queue_udp_send(datagram)?;
        }
        Ok(())
    }

    fn max_gso_datagrams_for_segment(segment_size: u16) -> usize {
        let segment_len = usize::from(segment_size);
        if segment_len == 0 {
            return 1;
        }
        let mtu_cap = MAX_UDP_PAYLOAD / segment_len;
        mtu_cap.clamp(1, MAX_GSO_SEGMENTS_PER_SEND.min(MAX_GSO_DATAGRAMS))
    }

    fn queue_udp_gso(&mut self, datagrams: &[Vec<u8>], segment_size: u16) -> io::Result<bool> {
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
        let mut coalesced = Vec::with_capacity(total_len);
        for datagram in datagrams {
            coalesced.extend_from_slice(datagram);
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
        if let Err(e) = ctx.prepare(payload_ptr, payload_len_now, segment_size) {
            self.release_in_flight_slot(slot_id);
            return Err(e);
        }
        self.gso_meta[slot_id] = Some(GsoMeta {
            segment_size,
            datagram_count: datagrams.len(),
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

    fn recover_gso_fallback_datagrams(&self, slot_id: usize) -> Vec<Vec<u8>> {
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
            datagrams.push(payload[start..end].to_vec());
        }
        datagrams
    }

    fn recover_gso_unsent_datagrams(&self, slot_id: usize, bytes_sent: usize) -> Vec<Vec<u8>> {
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
            datagrams.push(payload[start..end].to_vec());
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

    fn handle_dispatch_udp(&mut self, d: &mut impl Dispatch, datagram: &[u8], now_ms: u64) {
        match d.on_udp(datagram, now_ms) {
            DispatchOut::None => {}
            DispatchOut::Tun(inner) => {
                if let Err(e) = self.queue_tun_write(inner) {
                    eprintln!("uring: drop tun write: {e}");
                }
            }
            DispatchOut::Udp(pkts) => {
                let pkts_owned = pkts.to_vec();
                if let Err(e) = self.queue_udp_batch(&pkts_owned, false) {
                    eprintln!("uring: drop udp send batch: {e}");
                }
            }
            DispatchOut::Both(inner, pkts) => {
                if let Err(e) = self.queue_tun_write(inner) {
                    eprintln!("uring: drop tun write: {e}");
                }
                let pkts_owned = pkts.to_vec();
                if let Err(e) = self.queue_udp_batch(&pkts_owned, false) {
                    eprintln!("uring: drop udp send batch: {e}");
                }
            }
        }
    }

    fn handle_dispatch_tun(&mut self, d: &mut impl Dispatch, frame: &[u8], now_ms: u64) {
        let pkts_owned = d.on_tun(frame, now_ms).to_vec();
        if let Err(e) = self.queue_udp_batch(&pkts_owned, true) {
            eprintln!("uring: drop udp send batch from tun: {e}");
        }
    }

    /// Process at least one CQE and dispatch resulting I/O.
    pub fn poll_once<D: Dispatch>(&mut self, d: &mut D) -> io::Result<()> {
        self.submit_and_wait_1()?;
        let mut cqes = Vec::new();
        for cqe in &mut self.ring.completion() {
            cqes.push((cqe.user_data(), cqe.result(), cqe.flags()));
        }

        let now_ms = self.now_ms();
        for (user_data, result, flags) in cqes {
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

            let bid_opt = cqueue::buffer_select(flags);
            if result < 0 {
                let errno = -result;
                let err = io::Error::from_raw_os_error(errno);
                if let Some(bid) = bid_opt {
                    self.reprovide_buffer(bid)?;
                }
                // ENOBUFS on a recv completion means the provided-buffer ring was
                // momentarily exhausted (no buffer for the kernel to place this
                // datagram) — the multishot recv stops and must be re-armed. Like
                // EAGAIN, this is transient, not fatal: drop the datagram and
                // re-arm; buffers are re-provided as other completions process.
                // (Treating ENOBUFS as fatal tore the driver down under burst and
                // flaked the uring unit tests on the CI runner.)
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK || errno == libc::ENOBUFS {
                    if kind == TAG_UDP_RECV {
                        self.udp_armed = false;
                        self.arm_udp_recv()?;
                        continue;
                    }
                    if kind == TAG_TUN_RECV {
                        self.tun_armed = false;
                        self.arm_tun_read()?;
                        continue;
                    }
                }
                if kind == TAG_UDP_RECV {
                    self.udp_armed = false;
                    return Err(io::Error::other(format!(
                        "udp recv completion error: {err}"
                    )));
                }
                if kind == TAG_TUN_RECV {
                    self.tun_armed = false;
                    return Err(io::Error::other(format!(
                        "tun recv completion error: {err}"
                    )));
                }
                return Err(io::Error::other(format!(
                    "unexpected completion kind 0x{kind:016x} with error {err}"
                )));
            }

            let bid = if kind == TAG_UDP_RECV || kind == TAG_TUN_RECV {
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

            if kind == TAG_UDP_RECV {
                let datagram = self.recv_pool[idx][..n].to_vec();
                self.handle_dispatch_udp(d, &datagram, now_ms);
                self.reprovide_buffer(bid)?;
                if !cqueue::more(flags) {
                    self.udp_armed = false;
                    self.arm_udp_recv()?;
                }
                continue;
            }

            let frame = self.recv_pool[idx][..n].to_vec();
            self.handle_dispatch_tun(d, &frame, now_ms);
            self.reprovide_buffer(bid)?;
            self.tun_armed = false;
            self.arm_tun_read()?;
        }

        if let Some(pkt) = d.tick(now_ms) {
            if let Err(e) = self.queue_udp_send(pkt) {
                eprintln!("uring: drop tick packet: {e}");
            }
        }

        self.ring.submit()?;
        Ok(())
    }
}

/// Run the io_uring loop forever for production use.
pub fn run_uring<D: Dispatch>(udp_fd: RawFd, tun_fd: RawFd, d: &mut D) -> io::Result<()> {
    let mut driver = UringDriver::new(udp_fd, tun_fd)?;
    loop {
        driver.poll_once(d)?;
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
        scratch: Vec<Vec<u8>>,
    }

    impl EchoDispatch {
        fn new() -> Self {
            Self {
                scratch: Vec::new(),
            }
        }
    }

    impl Dispatch for EchoDispatch {
        fn on_udp(&mut self, dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            self.scratch = vec![dg.to_vec()];
            DispatchOut::Udp(&self.scratch)
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[Vec<u8>] {
            &[]
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[u8]> {
            None
        }
    }

    struct GsoDispatch {
        scratch: Vec<Vec<u8>>,
    }

    impl GsoDispatch {
        fn new() -> Self {
            Self {
                scratch: Vec::new(),
            }
        }
    }

    impl Dispatch for GsoDispatch {
        fn on_udp(&mut self, _dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            DispatchOut::None
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[Vec<u8>] {
            self.scratch.clear();
            for i in 0_u8..5_u8 {
                let mut datagram = vec![b'a'; 64];
                datagram[0] = b'0' + i;
                self.scratch.push(datagram);
            }
            &self.scratch
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[u8]> {
            None
        }
    }

    struct GsoLargeBatchDispatch {
        scratch: Vec<Vec<u8>>,
        datagram_count: usize,
        datagram_size: usize,
    }

    impl GsoLargeBatchDispatch {
        fn new(datagram_count: usize, datagram_size: usize) -> Self {
            Self {
                scratch: Vec::new(),
                datagram_count,
                datagram_size,
            }
        }
    }

    impl Dispatch for GsoLargeBatchDispatch {
        fn on_udp(&mut self, _dg: &[u8], _now_ms: u64) -> DispatchOut<'_> {
            DispatchOut::None
        }

        fn on_tun(&mut self, _inner: &[u8], _now_ms: u64) -> &[Vec<u8>] {
            self.scratch.clear();
            for i in 0..self.datagram_count {
                let mut datagram = vec![b'z'; self.datagram_size];
                datagram[0] = u8::try_from(i % 251).expect("modulo bound fits u8");
                self.scratch.push(datagram);
            }
            &self.scratch
        }

        fn tick(&mut self, _now_ms: u64) -> Option<&[u8]> {
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
        for _ in 0..4000 {
            driver.poll_once(&mut dispatch).expect("poll_once succeeds");

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
        }

        // SAFETY: these fds came from `pipe2` and are still open here.
        unsafe {
            libc::close(tun_rd);
            libc::close(tun_wr);
        }

        assert_eq!(got.len(), total, "all loopback datagrams must round-trip");
        for payload in sent_payloads {
            assert!(got.contains(&payload), "missing echoed payload");
        }
        drop(driver);
        std::thread::sleep(Duration::from_millis(200));
    }

    #[test]
    fn uring_gso_loopback_preserves_multi_datagram_payloads() {
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
        let mut dispatch = GsoDispatch::new();
        let mut driver = match UringDriver::new(b.as_raw_fd(), tun_rd) {
            Ok(driver) => driver,
            Err(_) => {
                eprintln!(
                    "SKIP uring_gso_loopback_preserves_multi_datagram_payloads: \
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
        for _ in 0..1024 {
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
        for _ in 0..1024 {
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
            driver.poll_once(&mut dispatch).expect("poll_once succeeds");
        }

        let expected: Vec<Vec<u8>> = (0_u8..5_u8)
            .map(|i| {
                let mut datagram = vec![b'a'; 64];
                datagram[0] = b'0' + i;
                datagram
            })
            .collect();
        assert_eq!(got.len(), expected.len(), "must receive all GSO datagrams");
        for datagram in expected {
            assert!(got.contains(&datagram), "missing datagram from GSO output");
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
        let mut dispatch = GsoDispatch::new();
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
        driver.poll_once(&mut dispatch).expect("poll_once succeeds");

        let mut got = Vec::new();
        let mut recv_buf = [0_u8; MAX_WIRE_DATAGRAM];
        for _ in 0..1024 {
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
            driver.poll_once(&mut dispatch).expect("poll_once succeeds");
        }

        assert_eq!(
            driver.gso_submission_count(),
            0,
            "forced submit failure should prevent GSO send submissions"
        );
        let expected: Vec<Vec<u8>> = (0_u8..5_u8)
            .map(|i| {
                let mut datagram = vec![b'a'; 64];
                datagram[0] = b'0' + i;
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
        let mut dispatch = GsoLargeBatchDispatch::new(datagram_count, datagram_size);
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

        let expected_submissions =
            datagram_count.div_ceil(UringDriver::max_gso_datagrams_for_segment(
                u16::try_from(datagram_size).expect("test datagram size fits u16"),
            ));
        assert!(
            driver.gso_submission_count() >= expected_submissions,
            "driver must chunk large GSO batches into multiple submissions"
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
        for _ in 0..6000 {
            driver.poll_once(&mut dispatch).expect("poll_once succeeds");
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
        }

        assert_eq!(received, total, "must echo all datagrams");

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

        // SAFETY: these fds came from `pipe2` and are still open here.
        unsafe {
            libc::close(tun_rd);
            libc::close(tun_wr);
        }
        drop(driver);
        std::thread::sleep(Duration::from_millis(200));
    }
}
