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
use crate::MAX_WIRE_DATAGRAM;

const RING_ENTRIES: u32 = 512;
const RING_BUFS: usize = 256;
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

#[derive(Default)]
struct SendSlot {
    in_use: bool,
    buf: Vec<u8>,
}

/// One-ring io_uring driver handling UDP + TUN.
pub struct UringDriver {
    ring: IoUring,
    udp_fd: RawFd,
    tun_fd: RawFd,
    recv_pool: Box<[[u8; MAX_WIRE_DATAGRAM]; RING_BUFS]>,
    send_slots: Vec<SendSlot>,
    started: Instant,
    udp_armed: bool,
    tun_armed: bool,
}

impl UringDriver {
    /// Build and arm a ring over the provided UDP and TUN file descriptors.
    pub fn new(udp_fd: RawFd, tun_fd: RawFd) -> io::Result<Self> {
        let ring = IoUring::new(RING_ENTRIES)?;
        let recv_pool = Box::new([[0_u8; MAX_WIRE_DATAGRAM]; RING_BUFS]);
        let mut send_slots = Vec::with_capacity(SEND_SLOTS);
        for _ in 0..SEND_SLOTS {
            send_slots.push(SendSlot {
                in_use: false,
                buf: Vec::with_capacity(MAX_WIRE_DATAGRAM),
            });
        }

        let mut driver = Self {
            ring,
            udp_fd,
            tun_fd,
            recv_pool,
            send_slots,
            started: Instant::now(),
            udp_armed: false,
            tun_armed: false,
        };

        driver.provide_all_buffers()?;
        driver.arm_udp_recv()?;
        driver.arm_tun_read()?;
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
        self.ring.submit_and_wait(1)?;
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

    fn alloc_send_slot(&mut self, payload: &[u8]) -> io::Result<usize> {
        if payload.len() > MAX_WIRE_DATAGRAM {
            return Err(io::Error::other("payload exceeds MAX_WIRE_DATAGRAM"));
        }
        let Some((idx, slot)) = self
            .send_slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| !slot.in_use)
        else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no free send slots available",
            ));
        };
        slot.in_use = true;
        slot.buf.clear();
        slot.buf.extend_from_slice(payload);
        Ok(idx)
    }

    fn queue_udp_send(&mut self, datagram: &[u8]) -> io::Result<()> {
        let slot_id = self.alloc_send_slot(datagram)?;
        let (ptr, len_u32) = {
            let slot = &self.send_slots[slot_id];
            let len_u32 = u32::try_from(slot.buf.len())
                .map_err(|_| io::Error::other("send buffer too large"))?;
            (slot.buf.as_ptr(), len_u32)
        };
        let tag = TAG_SEND_SLOT | u64::try_from(slot_id).expect("slot id fits u64");
        let entry = opcode::Send::new(types::Fd(self.udp_fd), ptr, len_u32)
            .build()
            .user_data(tag);
        self.push_entry(entry)
    }

    fn queue_tun_write(&mut self, frame: &[u8]) -> io::Result<()> {
        let slot_id = self.alloc_send_slot(frame)?;
        let (ptr, len_u32) = {
            let slot = &self.send_slots[slot_id];
            let len_u32 = u32::try_from(slot.buf.len())
                .map_err(|_| io::Error::other("tun write buffer too large"))?;
            (slot.buf.as_ptr(), len_u32)
        };
        let tag = TAG_SEND_SLOT | u64::try_from(slot_id).expect("slot id fits u64");
        let entry = opcode::Write::new(types::Fd(self.tun_fd), ptr, len_u32)
            .build()
            .user_data(tag);
        self.push_entry(entry)
    }

    fn release_send_slot(&mut self, slot_id: usize) {
        if slot_id >= self.send_slots.len() {
            return;
        }
        let slot = &mut self.send_slots[slot_id];
        slot.in_use = false;
        slot.buf.clear();
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
                for pkt in &pkts_owned {
                    if let Err(e) = self.queue_udp_send(pkt) {
                        eprintln!("uring: drop udp send: {e}");
                    }
                }
            }
            DispatchOut::Both(inner, pkts) => {
                if let Err(e) = self.queue_tun_write(inner) {
                    eprintln!("uring: drop tun write: {e}");
                }
                let pkts_owned = pkts.to_vec();
                for pkt in &pkts_owned {
                    if let Err(e) = self.queue_udp_send(pkt) {
                        eprintln!("uring: drop udp send: {e}");
                    }
                }
            }
        }
    }

    fn handle_dispatch_tun(&mut self, d: &mut impl Dispatch, frame: &[u8], now_ms: u64) {
        let pkts_owned = d.on_tun(frame, now_ms).to_vec();
        for pkt in &pkts_owned {
            if let Err(e) = self.queue_udp_send(pkt) {
                eprintln!("uring: drop udp send from tun: {e}");
            }
        }
    }

    /// Process at least one CQE and dispatch resulting I/O.
    pub fn poll_once<D: Dispatch>(&mut self, d: &mut D) -> io::Result<()> {
        self.ring.submit_and_wait(1)?;
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
                    eprintln!(
                        "uring: send/write completion error on slot {slot_id}: {}",
                        io::Error::from_raw_os_error(-result)
                    );
                }
                self.release_send_slot(slot_id);
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

            if result < 0 {
                let err = io::Error::from_raw_os_error(-result);
                if kind == TAG_UDP_RECV {
                    self.udp_armed = false;
                    if let Err(rearm_err) = self.arm_udp_recv() {
                        return Err(io::Error::other(format!(
                            "failed to re-arm udp recv after {err}: {rearm_err}"
                        )));
                    }
                } else if kind == TAG_TUN_RECV {
                    self.tun_armed = false;
                    if let Err(rearm_err) = self.arm_tun_read() {
                        return Err(io::Error::other(format!(
                            "failed to re-arm tun read after {err}: {rearm_err}"
                        )));
                    }
                }
                continue;
            }

            let Some(bid) = cqueue::buffer_select(flags) else {
                if kind == TAG_UDP_RECV {
                    self.udp_armed = false;
                    self.arm_udp_recv()?;
                } else if kind == TAG_TUN_RECV {
                    self.tun_armed = false;
                    self.arm_tun_read()?;
                }
                continue;
            };

            let idx = usize::from(bid);
            if idx >= RING_BUFS {
                return Err(io::Error::other("kernel returned buffer id out of range"));
            }
            let n = usize::try_from(result).expect("non-negative CQE result fits usize");
            if n > MAX_WIRE_DATAGRAM {
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
            } else if kind == TAG_TUN_RECV {
                let frame = self.recv_pool[idx][..n].to_vec();
                self.handle_dispatch_tun(d, &frame, now_ms);
                self.reprovide_buffer(bid)?;
                self.tun_armed = false;
                self.arm_tun_read()?;
            }
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

    fn make_pipe() -> io::Result<(RawFd, RawFd)> {
        let mut fds = [0_i32; 2];
        // SAFETY: `fds` points to valid writable storage for two file descriptors.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((fds[0], fds[1]))
    }

    #[test]
    fn uring_loopback_roundtrip_recycles_recv_buffers() {
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
    }
}
