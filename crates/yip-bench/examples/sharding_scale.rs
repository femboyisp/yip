//! Sharding-scale spike, task 2: core-pinned N-worker sweep (level 1).
//!
//! De-risking spike for multi-core sharding (#10). This example reassembles
//! the REAL yip receive chain from the library crates (`yip-crypto`,
//! `yip-wire`, `yip-transport`) — the authoritative reference is
//! `bin/yipd/src/dataplane.rs` (`on_udp_datagram`'s data arm) plus
//! `bin/yipd/src/wire_glue.rs` for how a FEC `Symbol` maps to/from a wire
//! `Frame`. `yip-bench` is a separate crate and cannot import `yipd`'s
//! `DataPlane`, so the `symbol_to_frame`/`frame_to_symbol` glue below is a
//! direct port of `wire_glue.rs` (same field layout, same 12-byte
//! counter+object_size prefix), not a fallback: the full
//! deframe -> parse Symbol -> FEC-decode -> AEAD-open chain runs per packet.
//!
//! Task 1 built the self-contained `Worker` + single-threaded `run_worker`
//! loop (N=1, ~1.69 Gbps on the reference box). Task 2 extends this to a
//! core-pinned N-worker sweep ([1, 2, 4, 6, 8, 12] -- N=6 is this box's last
//! all-physical-core point before N=8/N=12 double up on SMT siblings) to
//! see how the receive chain scales across real cores, with measurement-
//! honesty requirements: (a) each worker owns a distinct, L3-exceeding
//! fixture (not a shared/cache-resident fixture, which would inflate the
//! scaling result), (b) a start barrier so all worker threads begin their
//! timing window together, and (c) an average per-core clock (MHz) reading
//! over the same timing window, since this is a mobile APU under a package
//! power limit and DVFS clock-droop at high N must not be mistaken for
//! sharding/SMT contention.
//!
//! Task 3 (level 2) swaps the in-process loopback of level 1 for a REAL
//! `SO_REUSEPORT` UDP delivery path: `n` sockets bound to the same
//! `127.0.0.1:PORT`, each owned by a core-pinned receiver thread, fed by a
//! separate blaster thread group (pinned to a disjoint core set) sending
//! from many distinct source sockets so the kernel's 4-tuple hash is what
//! decides which receiver socket each datagram lands on -- confirming that
//! `SO_REUSEPORT` actually spreads load evenly across the `n` sockets
//! (`imbalance_ratio` near 1.0) and that the `recv()` syscall + deframe +
//! decrypt-attempt path holds up under real UDP delivery. Level 2's absolute
//! Gbps and its scaling across `n` must NOT be read as a receiver throughput
//! ceiling or compared in magnitude to level 1: on this box (6 physical
//! cores / 12 threads, `MAX_BLASTER_THREADS` = 8), `cores[n..n +
//! blaster_core_count]` includes the SMT siblings of `cores[..n]` at every
//! `n` this sweep uses ([1, 2, 4, 6]), so every level-2 receiver shares a
//! physical core with an active blaster thread -- level 2's throughput
//! numbers are blaster-/SMT-/loopback-bound, unlike level 1's idle-sibling
//! measurement. Level 1 remains the authoritative compute-scaling result;
//! level 2 only confirms even kernel *distribution* and exercises the real
//! per-packet receive cost.
//!
//! Level 2 uses independently-established blaster/receiver sessions BY
//! CONSTRUCTION: the blaster's AEAD session is independent of every
//! receiver's session (each `Worker` establishes its own handshake pair, and
//! per this file's "never share a Session/Worker across threads" rule the
//! blaster cannot borrow a specific receiver's session either), so `open()`
//! is expected to reject every datagram on a key mismatch -- not a
//! replay-window false reject, a hard decrypt failure. `Worker::receive`
//! still attempts `open()` (so a real acceptance would be visible/reported),
//! but level 2's byte-counting falls back to the FEC-decoded ciphertext
//! length whenever `open()` doesn't succeed. This is deliberate and honest,
//! not a shortcut: every datagram still pays the full ChaCha20-Poly1305
//! decrypt + tag-verify cost inside `open()`, it just never commits a
//! plaintext, so the measurement covers the FULL deframe -> FEC-decode ->
//! decrypt-attempt cost over real UDP delivery -- just not a successful
//! decrypt. The wire codec's coverage-auth key, unlike the AEAD session, is
//! a fixed constant baked into every `Worker::new()` (`Codec::new([1u8; 16],
//! [2u8; 16])`), so deframing across independently-constructed `Worker`s
//! (receiver vs. blaster) works fine -- that's what makes the SO_REUSEPORT
//! delivery path exercisable at all without a shared session.
//!
//! Run: `cargo run --release -p yip-bench --example sharding_scale`
//! Test: `cargo test -p yip-bench --example sharding_scale`

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use socket2::{Domain, SockAddr, Socket, Type};

use yip_bench::{established_pair, sample_inner};
use yip_crypto::Session;
use yip_transport::{FlowClass, Symbol, Transport};
use yip_wire::{Codec, Frame, WireCodec};

/// A fixed connection tag for this synthetic single-connection worker.
const CONN_TAG: u64 = 1;

/// Build a wire frame for one FEC symbol (port of `yipd`'s
/// `wire_glue::symbol_to_frame`): the AEAD counter and object size ride in
/// the (authenticated) payload prefix; the class rides in flags.
fn symbol_to_frame(conn_tag: u64, sym: &Symbol, counter: u64, class: FlowClass) -> Frame {
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

/// Parse a received frame back into a `(Symbol, counter, class)` (port of
/// `yipd`'s `wire_glue::frame_to_symbol`), or `None` if the payload is
/// shorter than the 12-byte counter+object_size prefix.
fn frame_to_symbol(frame: &Frame) -> Option<(Symbol, u64, FlowClass)> {
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

/// Encode a flow class into the low bits of the frame flags byte.
fn class_to_flags(c: FlowClass) -> u8 {
    match c {
        FlowClass::Realtime => 0,
        FlowClass::Bulk => 1,
        FlowClass::Default => 2,
    }
}

/// Decode the flow class from the frame flags byte.
fn flags_to_class(f: u8) -> FlowClass {
    match f & 0x03 {
        0 => FlowClass::Realtime,
        1 => FlowClass::Bulk,
        _ => FlowClass::Default,
    }
}

/// A fully self-contained receive-chain worker: one AEAD session pair, one
/// wire codec, and one send-side / receive-side FEC transport. No globals,
/// no shared state — later tasks spawn N of these across pinned cores.
struct Worker {
    sender: Session,
    receiver: Session,
    codec: Codec,
    tx: Transport,
    rx: Transport,
}

impl Worker {
    fn new() -> Self {
        let (sender, receiver) = established_pair();
        Worker {
            sender,
            receiver,
            codec: Codec::new([1u8; 16], [2u8; 16]),
            tx: Transport::new(vec![], 1200),
            rx: Transport::new(vec![], 1200),
        }
    }

    /// Send-only half of the chain for one object: seal -> FEC-encode ->
    /// frame, producing the wire datagrams a receiver would see for this
    /// `inner` payload. Shared by `step` (in-process loopback, level 1) and
    /// the level-2 blaster (which sends these bytes over a real UDP socket
    /// to a SO_REUSEPORT-bound receiver in a different thread/`Worker`
    /// instead of looping them back in-process).
    fn send(&mut self, inner: &[u8]) -> Vec<Vec<u8>> {
        let sealed = self.sender.seal(inner).expect("seal");
        let (class, symbols) = self.tx.encode(&sealed.ciphertext, inner, false, 0);
        symbols
            .iter()
            .map(|sym| {
                let frame = symbol_to_frame(CONN_TAG, sym, sealed.counter, class);
                self.codec.frame(&frame)
            })
            .collect()
    }

    /// Like `send`, but assigns an EXPLICIT `object_id` (via
    /// `Transport::repair_object`, the same "re-encode under a caller-chosen
    /// id" entry point production ARQ retransmits use) instead of letting
    /// `self.tx`'s internal `FecEncoder` auto-increment its own counter.
    ///
    /// This exists only for the level-2 blaster: every blaster thread owns
    /// its own `Worker` (own `Transport`, own `FecEncoder` starting at
    /// object_id 0), so with plain `send` every thread's Nth call would
    /// carry the SAME object_id. Two different threads' equal-object_id
    /// bursts landing on the same SO_REUSEPORT receiver socket (entirely
    /// possible -- the kernel picks by 4-tuple hash, not by content) would
    /// interleave into that receiver's ONE `FecReassembler` slot for that
    /// id, corrupting both objects' shard sets. `blast_worker` instead hands
    /// every pre-built object a globally unique id (a disjoint `u16` range
    /// per thread) so no two blaster threads can ever collide.
    ///
    /// `class` is passed explicitly rather than re-derived from
    /// `self.tx`'s classifier (which `repair_object` does not consult) --
    /// callers must classify `inner` themselves first if it isn't already
    /// known, as `blast_worker`'s fixture is (always DSCP EF -> `Realtime`,
    /// see `build_fixture`'s doc comment).
    fn send_with_id(
        &mut self,
        inner: &[u8],
        class: FlowClass,
        object_id: u16,
        extra_repair: u32,
    ) -> Vec<Vec<u8>> {
        let sealed = self.sender.seal(inner).expect("seal");
        let symbols = self
            .tx
            .repair_object(&sealed.ciphertext, class, object_id, extra_repair);
        symbols
            .iter()
            .map(|sym| {
                let frame = symbol_to_frame(CONN_TAG, sym, sealed.counter, class);
                self.codec.frame(&frame)
            })
            .collect()
    }

    /// Receive-only half of the chain for one arbitrary wire datagram:
    /// deframe -> parse Symbol -> FEC-decode -> AEAD-open. Shared by `step`
    /// (which drives its own send half first, so `open` always matches) and
    /// the level-2 SO_REUSEPORT sweep (which receives datagrams produced by
    /// a separate blaster thread with its own, unrelated `Session`).
    ///
    /// Returns `None` if deframe/parse/FEC-decode did not complete this call
    /// (garbage on the wire, or an object not yet fully reassembled --
    /// normal for FEC, not a failure). Otherwise returns
    /// `Some((len, opened))`: `opened` is whether `open` accepted the
    /// decoded ciphertext under this `Worker`'s own receiver `Session`, and
    /// `len` is the inner byte length when `opened`, or the FEC-decoded
    /// ciphertext length when not -- level 2 relies on this fallback because
    /// its blaster's session is never the matching pair for an arbitrary
    /// receiver (see the module doc comment).
    fn receive(&mut self, dg: &[u8]) -> Option<(usize, bool)> {
        let frame = self.codec.deframe(dg).ok()?;
        let (sym, counter, class) = frame_to_symbol(&frame)?;
        let ciphertext = self.rx.decode(&sym, class)?;
        match self.receiver.open(counter, &ciphertext) {
            Ok(inner_bytes) => Some((inner_bytes.len(), true)),
            Err(_) => Some((ciphertext.len(), false)),
        }
    }

    /// One fresh-counter roundtrip through the real receive chain: `send`
    /// followed by `receive` on every resulting datagram. Each call uses a
    /// strictly increasing AEAD counter (own `Session`, never shared), so
    /// the replay window never rejects and `receive` always reports
    /// `opened == true` here.
    ///
    /// Returns the number of inner bytes recovered (0 if the chain didn't
    /// produce a decoded frame this call, which should not happen since no
    /// datagrams are dropped here).
    fn step(&mut self, inner: &[u8]) -> usize {
        let datagrams = self.send(inner);
        let mut recovered_len = 0usize;
        for dg in &datagrams {
            if let Some((len, opened)) = self.receive(dg) {
                if opened {
                    recovered_len = len;
                }
            }
        }
        recovered_len
    }
}

/// Run `w` for `dur`, cycling through `inners`, returning the total number
/// of recovered inner bytes processed in the window.
///
/// Takes an already-constructed `Worker` (rather than building one itself)
/// so callers can do the one-time handshake cost of `Worker::new()` before
/// starting the timed window — required by `level1_sweep` below, which puts
/// `Worker::new()` before a start barrier and only calls `run_worker` after
/// every thread has been released, so the timing window is apples-to-apples
/// across all N threads.
fn run_worker(w: &mut Worker, inners: &[Vec<u8>], dur: Duration) -> u64 {
    let deadline = Instant::now() + dur;
    let mut bytes = 0u64;
    let mut i = 0usize;
    while Instant::now() < deadline {
        let inner = &inners[i % inners.len()];
        bytes += w.step(inner) as u64;
        i += 1;
    }
    bytes
}

/// Number of distinct 1300-byte payloads each worker owns. At 1300 bytes each
/// this is ~3.8 MB per worker — a few MB, as required — so the combined
/// footprint across all N workers in the sweep (N up to 12) reaches ~46 MB,
/// well past this box's ~16 MB L3, forcing real memory-bandwidth contention
/// at high N instead of everything living cache-resident.
const PAYLOADS_PER_WORKER: usize = 3000;

/// Build one worker's own fixture: `PAYLOADS_PER_WORKER` distinct 1300-byte
/// inner packets, each with a distinct IPv4/UDP 5-tuple (src/dst address +
/// src/dst port), and distinct *across workers too* (the `worker_id` feeds
/// the source address). The distinctness is what defeats cache residency: a
/// single shared/repeated payload would let the whole fixture (and any
/// per-flow state touching it) stay pinned in a tiny working set, so the
/// combined multi-MB, L3-exceeding footprint across N workers (see
/// `PAYLOADS_PER_WORKER` above) would never actually get exercised as real
/// memory traffic. That inflated-scaling failure mode is what this fixture
/// avoids.
///
/// Note on what the 5-tuple mutation does *not* currently exercise:
/// `sample_inner` sets DSCP = 46 (EF), and `Classifier::classify`
/// (`yip_transport::classify`) short-circuits straight to
/// `FlowClass::Realtime` on that DSCP match before it ever consults the
/// flow table keyed by the 5-tuple. So varying src/dst address/port here
/// does *not* create extra flow-table entries or exercise extra classifier
/// code paths in this fixture -- it only guarantees the payload bytes
/// (and therefore the fixture's memory footprint) are distinct. The 5-tuple
/// variation is harmless (verified by `fixture_payloads_all_roundtrip`
/// below) and kept because it costs nothing and would matter the moment
/// `sample_inner`'s DSCP stops being fixed at EF, but it is not currently
/// doing multi-flow classification work.
///
/// Header layout (see `yip_bench::sample_inner` and
/// `yip_transport::classify::parse_ip`): IPv4 src addr at bytes 12..16, dst
/// addr at 16..20, then (proto 17 = UDP) src port at 20..22, dst port at
/// 22..24. `sample_inner` zeroes these, so every payload would otherwise be
/// byte-identical.
fn build_fixture(worker_id: usize, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let mut p = sample_inner(1300);
            let src_ip = (worker_id as u32) + 1; // distinct per worker
            let dst_ip = (i as u32) + 1; // distinct per payload
            let src_port = ((i as u16) ^ 0x5A5A).wrapping_add(1);
            let dst_port = ((i as u16).wrapping_mul(7)).wrapping_add(1);
            p[12..16].copy_from_slice(&src_ip.to_be_bytes());
            p[16..20].copy_from_slice(&dst_ip.to_be_bytes());
            p[20..22].copy_from_slice(&src_port.to_be_bytes());
            p[22..24].copy_from_slice(&dst_port.to_be_bytes());
            p
        })
        .collect()
}

/// Pin the calling thread to `core` via `sched_setaffinity` (pid 0 = current
/// thread/process, per `man 2 sched_setaffinity`).
///
/// Panics if the syscall fails: the entire "core-pinned" premise of this
/// sweep rests on this succeeding, so a silently-ignored failure (e.g. a
/// restricted cpuset) would quietly degrade the whole table to an unpinned,
/// scheduler-shuffled measurement with no indication in the output.
fn pin_current_thread(core: usize) {
    // SAFETY: `set` is a valid, fully-initialized (zeroed then CPU_ZERO'd)
    // `cpu_set_t` local; `CPU_SET`/`sched_setaffinity` only read/write within
    // its bounds, and `size_of::<cpu_set_t>()` matches the buffer we pass.
    let rc = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core, &mut set);
        // pin the calling thread (pid 0 = current)
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw const set)
    };
    assert_eq!(
        rc,
        0,
        "sched_setaffinity(core={core}) failed: {}",
        std::io::Error::last_os_error()
    );
}

/// Parse a Linux sysfs CPU list (e.g. `"0-1"`, `"0,2,4"`, `"0"`) into the
/// individual CPU indices it names, in ascending order.
fn parse_cpu_list(s: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in s.trim().split(',') {
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse::<usize>(), b.parse::<usize>()) {
                out.extend(a..=b);
            }
        } else if let Ok(v) = part.parse::<usize>() {
            out.push(v);
        }
    }
    out
}

/// Build a physical-core-first CPU ordering by reading SMT sibling groups
/// from sysfs, so `cores[0..k]` always lands on `k` *distinct physical
/// cores* before doubling up on hyperthreads.
///
/// This matters because a naive `(0..n).collect()` is wrong on SMT hardware:
/// on this box (Ryzen 5 7640U, 6 cores / 12 threads) `cpu0` and `cpu1` are
/// SMT siblings on the *same* physical core (confirmed via
/// `/sys/devices/system/cpu/cpu0/topology/thread_siblings_list` == `"0-1"`).
/// With naive ordering the N=2 sweep point would pin both workers onto one
/// physical core (measuring SMT contention, not 2-core scaling), and N=4/N=8
/// would similarly under-count distinct cores. That would silently corrupt
/// exactly the number this spike exists to produce honestly. Ordering
/// physical-core-first means `cores[0..6]` are 6 distinct physical cores and
/// `cores[6..12]` are their SMT siblings, so the sweep's low-N points
/// measure real multi-core scaling and only N=8/N=12 (which exceed 6
/// physical cores) reflect SMT sharing -- which is real and worth seeing,
/// just not conflated with the N=2/N=4 points.
///
/// Falls back to a plain `(0..n).collect()` if sysfs topology info isn't
/// available (e.g. non-Linux, or a sandboxed environment without
/// `/sys/devices/system/cpu`).
fn topology_ordered_cores() -> Vec<usize> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cpu = 0usize;
    loop {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
        let Ok(contents) = std::fs::read_to_string(&path) else {
            break;
        };
        if !seen.contains(&cpu) {
            let siblings = parse_cpu_list(&contents);
            for &s in &siblings {
                seen.insert(s);
            }
            groups.push(siblings);
        }
        cpu += 1;
    }

    if groups.is_empty() {
        eprintln!(
            "warning: could not read SMT topology from /sys/devices/system/cpu; \
             falling back to naive (0..n) core ordering, which may place SMT \
             siblings together and reintroduce the same-physical-core bias \
             this ordering exists to avoid"
        );
        let n = std::thread::available_parallelism().map_or(12, |p| p.get());
        return (0..n).collect();
    }

    // Round-robin across groups: first thread of every core, then second
    // thread of every core, etc.
    let max_len = groups.iter().map(|g| g.len()).max().unwrap_or(0);
    let mut ordered = Vec::with_capacity(seen.len());
    for round in 0..max_len {
        for g in &groups {
            if let Some(&c) = g.get(round) {
                ordered.push(c);
            }
        }
    }
    ordered
}

/// Fallback: parse `/proc/cpuinfo`'s per-processor `"cpu MHz"` line for
/// logical CPU `core`, for systems without cpufreq sysfs.
fn proc_cpuinfo_mhz(core: usize) -> Option<f64> {
    let contents = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    let mut current: Option<usize> = None;
    for line in contents.lines() {
        let (key, val) = line.split_once(':')?;
        let (key, val) = (key.trim(), val.trim());
        if key == "processor" {
            current = val.parse().ok();
        } else if key == "cpu MHz" && current == Some(core) {
            return val.parse().ok();
        }
    }
    None
}

/// Sample the current clock speed (MHz) for each of `cores`, averaged.
///
/// This box is a Ryzen 5 7640U -- a mobile APU under a package power limit
/// (`CPU scaling MHz ~91%` in `lscpu`), where single-core boost clock is
/// well above sustained all-core clock. That means part of any efficiency
/// drop at high N is DVFS clock-droop (the package throttling per-core
/// clocks as more cores go active), not sharding/SMT contention -- and
/// without a clock reading alongside the sweep there is no way to tell the
/// two apart. Prefers `scaling_cur_freq` (kHz, per-core, cpufreq sysfs);
/// falls back to `/proc/cpuinfo`'s per-processor `"cpu MHz"` lines when
/// cpufreq sysfs isn't present.
fn sample_core_mhz(cores: &[usize]) -> Option<f64> {
    let mut total = 0.0;
    let mut count = 0usize;
    for &c in cores {
        let path = format!("/sys/devices/system/cpu/cpu{c}/cpufreq/scaling_cur_freq");
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(khz) = contents.trim().parse::<f64>() {
                total += khz / 1000.0;
                count += 1;
                continue;
            }
        }
        if let Some(mhz) = proc_cpuinfo_mhz(c) {
            total += mhz;
            count += 1;
        }
    }
    if count == 0 {
        None
    } else {
        Some(total / count as f64)
    }
}

/// Run the core-pinned N-worker sweep: for each `n` in `cores.len()`-bounded
/// group sizes, spawn `n` threads (thread `i` pinned to `cores[i]`), each
/// building its own `Worker` + its own fixture, then run all `n` for `dur`
/// wall-clock seconds starting from a shared barrier so ramp-up skew doesn't
/// distort the aggregate. An extra sampler thread joins the same barrier and
/// polls `sample_core_mhz` over the pinned cores for the same window, so the
/// returned average clock is measured over the identical timing window as
/// the throughput -- not before ramp-up, not after cool-down. Returns
/// `(n, aggregate_gbps, avg_mhz)` per sweep point. `n = 6` is this box's
/// last all-physical-core point (6 cores / 12 SMT threads) before N=8/N=12
/// necessarily double up on hyperthreads.
fn level1_sweep(cores: &[usize], dur: Duration) -> Vec<(usize, f64, f64)> {
    let ns = [1usize, 2, 4, 6, 8, 12];
    let mut rows = Vec::with_capacity(ns.len());

    for &n in &ns {
        assert!(
            n <= cores.len(),
            "sweep point N={n} exceeds available cores ({})",
            cores.len()
        );
        let used_cores: Vec<usize> = cores[..n].to_vec();
        // n workers + 1 clock sampler, all released together.
        let barrier = Arc::new(Barrier::new(n + 1));

        let handles: Vec<_> = (0..n)
            .map(|i| {
                let core = cores[i];
                let barrier = Arc::clone(&barrier);
                thread::Builder::new()
                    .name(format!("worker-{i}"))
                    .spawn(move || {
                        pin_current_thread(core);
                        // Build fixture + handshake BEFORE the barrier so the
                        // timed window below starts from a cold, identical
                        // footing across all N threads.
                        let inners = build_fixture(i, PAYLOADS_PER_WORKER);
                        let mut w = Worker::new();
                        barrier.wait();
                        run_worker(&mut w, &inners, dur)
                    })
                    .expect("spawn worker thread")
            })
            .collect();

        let sampler_barrier = Arc::clone(&barrier);
        let sampler = thread::Builder::new()
            .name("mhz-sampler".to_string())
            .spawn(move || {
                sampler_barrier.wait();
                let deadline = Instant::now() + dur;
                let mut samples = Vec::new();
                while Instant::now() < deadline {
                    if let Some(mhz) = sample_core_mhz(&used_cores) {
                        samples.push(mhz);
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                if samples.is_empty() {
                    0.0
                } else {
                    samples.iter().sum::<f64>() / samples.len() as f64
                }
            })
            .expect("spawn mhz sampler thread");

        let total_bytes: u64 = handles.into_iter().map(|h| h.join().expect("join")).sum();
        let avg_mhz = sampler.join().expect("join mhz sampler");
        let gbps = (total_bytes as f64 * 8.0) / dur.as_secs_f64() / 1e9;
        rows.push((n, gbps, avg_mhz));
    }
    rows
}

/// Number of dedicated sender sockets each blaster thread pre-binds to
/// `127.0.0.1:0`. Every distinct source port is a distinct 4-tuple, which is
/// what gives the kernel's SO_REUSEPORT hash something to spread across the
/// `n` receiver sockets -- one socket alone would always land on the same
/// receiver every time. A single object's whole datagram set is always sent
/// from ONE of these sockets (see `blast_thread`), so an object's shards
/// stay together (same receiver), while different objects fan out across
/// receivers as they rotate through this pool.
///
/// Kept at 16 (not dozens) so `OBJECTS_PER_BLASTER_THREAD` divided across
/// this many sockets still leaves each socket a large distinct-object count
/// per rotation -- see that constant's doc comment for why the ratio
/// between the two matters. 16 (rather than the 8 this started at) also
/// matters for `imbalance_ratio`: with only `MAX_BLASTER_THREADS * 8` = 48
/// distinct sender sockets hashed across up to 6 receiver sockets, sampling
/// noise alone produced imbalance ratios over the brief's "< ~2x" guideline
/// at N=6 across repeated runs -- doubling the distinct-flow count reduces
/// that sampling noise (still not a proof of perfect fairness, but a lot
/// less likely to look unfair by chance alone).
const SENDER_SOCKETS_PER_BLASTER_THREAD: usize = 16;

/// Number of distinct payloads each blaster thread cycles through when
/// pre-building its object pool. Kept small (unlike level 1's L3-exceeding
/// `PAYLOADS_PER_WORKER`) because level 2 is measuring delivery/decode
/// scaling, not memory-bandwidth contention; repeated payload *content* is
/// harmless here since each pre-built object still gets its own object_id
/// (see `OBJECTS_PER_BLASTER_THREAD`).
const BLAST_PAYLOADS_PER_THREAD: usize = 64;

/// Number of distinct objects (each a `Worker::send` call: seal -> FEC
/// -encode -> frame) each blaster thread pre-builds before the timed window
/// starts, so the hot send loop (`blast_thread`) does nothing but
/// `send_to` -- no seal/encode/allocation on the critical path.
///
/// Sized well above `FecReassembler`'s `max_objects` window (256, see
/// `yip_transport::fec::FecReassembler::new`'s caller in `Worker::new`'s
/// `rx: Transport::new(..)`): a fixed sender socket's traffic always lands
/// on the SAME receiver socket (deterministic kernel 4-tuple hash), and this
/// pool is replayed on a loop, so each receiver sees the same object_id
/// again after `OBJECTS_PER_BLASTER_THREAD / SENDER_SOCKETS_PER_BLASTER_THREAD`
/// (8192 / 16 = 512) other distinct object_ids from that socket -- comfortably
/// above 256, so the repeat is always evicted from the reassembler's window
/// by the time it recurs (worst case: that one sender socket is a receiver's
/// only traffic source; any additional sockets sharing that receiver only
/// interleave MORE distinct ids in between, which is even safer). Without
/// this margin, replaying the same `object_id` while it's still resident hits
/// `FecReassembler::push`'s `if state.done { return None }` guard and
/// `receive()` would silently stop decoding -- exactly the failure mode the
/// task brief calls out ("Do NOT let replay-window rejection silently zero
/// out the measurement").
///
/// `MAX_BLASTER_THREADS * OBJECTS_PER_BLASTER_THREAD` (8 * 8192 = 65536)
/// exactly fills the `u16` object_id space `Worker::send_with_id`'s
/// per-thread partitioning relies on -- see `MAX_BLASTER_THREADS`'s doc
/// comment for why thread count is capped to make this fit.
const OBJECTS_PER_BLASTER_THREAD: usize = 8192;

/// Set `SO_REUSEPORT` on `sock` via a raw `setsockopt`, rather than
/// `socket2::Socket::set_reuse_port` (the safe wrapper for the same
/// syscall): that wrapper is gated behind `socket2`'s `"all"` Cargo feature,
/// which is off by default for this crate's `socket2` dependency, and
/// turning it on would mean editing `Cargo.toml` -- a second file, when this
/// task is scoped to `sharding_scale.rs` alone. This makes the identical
/// `setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)` call directly instead.
fn set_so_reuseport(sock: &Socket) {
    let val: libc::c_int = 1;
    // SAFETY: `sock.as_raw_fd()` is a valid, open socket fd for the
    // duration of this call (borrowed from `sock`, which outlives it); `val`
    // is a fully-initialized `c_int` and the length argument matches its
    // size, satisfying `setsockopt`'s buffer contract.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            std::ptr::from_ref(&val).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "setsockopt(SO_REUSEPORT) failed: {}",
        std::io::Error::last_os_error()
    );
}

/// Bind one UDP socket for the level-2 receiver group. `port` is `None` for
/// the very first socket (ephemeral bind, whose assigned port becomes the
/// shared target) and `Some(port)` for every subsequent socket in the group
/// (bound to that exact port). `SO_REUSEPORT` is set on every socket BEFORE
/// bind -- including the first -- because Linux requires every socket
/// sharing an address:port tuple to carry the option, not just the ones
/// added after the first.
fn bind_reuseport_socket(port: Option<u16>) -> (UdpSocket, u16) {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, None).expect("create UDP socket");
    set_so_reuseport(&sock);
    // Linux's default UDP receive buffer (a few hundred KB) is a genuine
    // bottleneck once the blaster group (all of `cores[n..]`, which can be
    // 10+ threads at low `n`) floods a single socket faster than one
    // core-pinned thread can `recv` + deframe + FEC-decode it: bursts
    // overflow the kernel queue and are dropped there, before this
    // benchmark's own recv/decode path is even exercised. That's a socket-
    // buffer-size artifact, not the recv-syscall/decode scaling question
    // level 2 is trying to answer, so size the buffer generously (8 MiB) to
    // keep drops attributable to the receive path itself, not queue depth.
    sock.set_recv_buffer_size(8 * 1024 * 1024)
        .expect("set SO_RCVBUF");
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port.unwrap_or(0));
    sock.bind(&SockAddr::from(addr)).expect("bind");
    let bound_port = if let Some(p) = port {
        p
    } else {
        sock.local_addr()
            .expect("local_addr")
            .as_socket_ipv4()
            .expect("IPv4 local addr")
            .port()
    };
    (sock.into(), bound_port)
}

/// One level-2 receiver: pin to `core`, own a fresh `Worker` (its own
/// AEAD session -- never shared, see the module doc comment), wait on the
/// start barrier, then recv-loop `sock` until `dur` elapses, running
/// `Worker::receive` (deframe -> FEC-decode -> open) on every datagram.
///
/// Returns `(datagrams_seen, bytes_counted, opens_succeeded,
/// objects_completed)`. `bytes_counted` uses `receive`'s fallback semantics:
/// inner-plaintext length when `open` accepted the frame, FEC-decoded
/// ciphertext length otherwise (expected to be the common case here -- see
/// the module doc comment on why `open` cannot match across independently-
/// established sessions).
///
/// `objects_completed` counts `receive`'s `Some(..)` returns, i.e. datagrams
/// that triggered a completed FEC decode (one per object, on whichever
/// shard supplies the object's K-th distinct index). It is NOT the same as
/// "datagrams received": most received datagrams legitimately return `None`
/// from `receive` -- either still-accumulating shards for an object that
/// hasn't reached K distinct indices yet, or late/redundant shards for an
/// object that already completed (`FecReassembler::push`'s `if state.done`
/// guard). With this file's fixture (K=2 source symbols, blaster
/// `extra_repair=2`, so 4 symbols/object under no loss), the steady-state
/// expectation is exactly 1 completion per 4 datagrams received -- i.e.
/// `received / objects_completed.max(1) ~= 4`. `level2_sweep` checks that
/// ratio (not a flat "None rate") to catch the task brief's "detect it,
/// don't silently zero out the measurement" failure mode: a datagram count
/// that stays healthy while completions collapse toward 0 (ratio blowing up
/// far past ~4) would mean objects are arriving but not decoding -- e.g. an
/// object-id collision or an eviction-window regression -- while a flat
/// None-rate check would false-alarm on this file's own expected ~75% rate.
fn recv_worker(
    sock: UdpSocket,
    core: usize,
    barrier: Arc<Barrier>,
    dur: Duration,
) -> (u64, u64, u64, u64) {
    pin_current_thread(core);
    let mut w = Worker::new();
    // Bounded so the recv loop below can re-check the deadline instead of
    // blocking forever once the blaster stops sending.
    sock.set_read_timeout(Some(Duration::from_millis(20)))
        .expect("set_read_timeout");
    let mut buf = [0u8; 2048]; // frame overhead + 1200B symbol comfortably fits
    barrier.wait();
    let deadline = Instant::now() + dur;
    let (mut datagrams, mut bytes, mut opened, mut completed) = (0u64, 0u64, 0u64, 0u64);
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, _src)) => {
                datagrams += 1;
                if let Some((len, was_opened)) = w.receive(&buf[..n]) {
                    bytes += len as u64;
                    completed += 1;
                    if was_opened {
                        opened += 1;
                    }
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) => {
                eprintln!("recv_worker(core={core}): recv_from error: {e}");
                continue;
            }
        }
    }
    (datagrams, bytes, opened, completed)
}

/// One level-2 blaster thread: pin to `core`, own a fresh `Worker` (used
/// ONLY for its send half -- `Worker::send`) and its own payload fixture,
/// pre-bind `SENDER_SOCKETS_PER_BLASTER_THREAD` sender sockets, PRE-BUILD
/// `OBJECTS_PER_BLASTER_THREAD` whole objects (each one `Worker::send` call's
/// full set of framed datagrams) so the timed hot loop below does nothing
/// but `send_to`, then wait on the start barrier and loop for `dur` sending
/// whole objects (all of one object's datagrams via the SAME sender socket,
/// rotating sender sockets object-to-object) to `target`.
///
/// Building the pool before the barrier -- rather than calling
/// `Worker::send` (seal + FEC-encode + frame + several `Vec` allocations)
/// live in the hot loop -- matters for measurement honesty here: this
/// benchmark exists to measure the RECEIVE path's scaling, and a blaster
/// thread spending its cycles on send-side crypto/FEC work instead of
/// `send_to` calls understates the load actually offered, making receivers
/// look artificially unsaturated (near-zero drop%) when they were simply
/// never given enough traffic to test.
///
/// Returns the number of datagrams sent.
fn blast_worker(
    core: usize,
    target: SocketAddrV4,
    barrier: Arc<Barrier>,
    dur: Duration,
    thread_id: usize,
) -> u64 {
    pin_current_thread(core);
    assert!(
        thread_id * OBJECTS_PER_BLASTER_THREAD + OBJECTS_PER_BLASTER_THREAD
            <= u16::MAX as usize + 1,
        "blast_worker: thread_id={thread_id} would overflow the u16 object_id \
         space at {OBJECTS_PER_BLASTER_THREAD} objects/thread -- this box has \
         more blaster threads than this partitioning scheme supports"
    );
    let mut template = Worker::new();
    let inners = build_fixture(10_000 + thread_id, BLAST_PAYLOADS_PER_THREAD);
    // See `Worker::send_with_id`'s doc comment: every blaster thread gets a
    // disjoint slice of the u16 object_id space so independently-running
    // threads can never collide on the same id.
    let id_base = (thread_id * OBJECTS_PER_BLASTER_THREAD) as u16;
    let objects: Vec<Vec<Vec<u8>>> = (0..OBJECTS_PER_BLASTER_THREAD)
        .map(|i| {
            let object_id = id_base + i as u16;
            template.send_with_id(&inners[i % inners.len()], FlowClass::Realtime, object_id, 2)
        })
        .collect();
    let senders: Vec<UdpSocket> = (0..SENDER_SOCKETS_PER_BLASTER_THREAD)
        .map(|_| {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, None).expect("create UDP socket");
            // See `bind_reuseport_socket`'s SO_RCVBUF comment: give the send
            // side matching headroom so a burst isn't dropped on the way out
            // either.
            s.set_send_buffer_size(8 * 1024 * 1024)
                .expect("set SO_SNDBUF");
            let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
            s.bind(&SockAddr::from(addr)).expect("bind ephemeral");
            s.into()
        })
        .collect();

    barrier.wait();
    let deadline = Instant::now() + dur;
    let mut sent = 0u64;
    let mut obj_idx = 0usize;
    while Instant::now() < deadline {
        let datagrams = &objects[obj_idx % objects.len()];
        let sock = &senders[obj_idx % senders.len()];
        for dg in datagrams {
            if sock.send_to(dg, target).is_ok() {
                sent += 1;
            }
        }
        obj_idx += 1;
    }
    sent
}

/// Minimum number of cores reserved for the blaster group, disjoint BY INDEX
/// from the `n` receiver cores, so the blaster is never starved down to a
/// handful of logical CPUs and therefore never throttles the offered load.
/// This is NOT SMT-level isolation: on this box (`cores` physical-core-first,
/// see `topology_ordered_cores`) `cores[n..]` still contains the SMT
/// siblings of `cores[..n]` at the `n` values this sweep uses, so the
/// blaster DOES contend with the receivers at the physical-core level --
/// see `level2_sweep`'s doc comment.
const MIN_BLASTER_CORES: usize = 2;

/// Upper bound on how many blaster threads a single sweep point spawns,
/// even if more disjoint cores are free (e.g. 11 at N=1 on a 12-thread box).
/// Two reasons, not one:
///
/// 1. `Worker::send_with_id` partitions the `u16` object_id space into one
///    disjoint block per blaster thread (see its doc comment) so no two
///    threads ever collide on an id; `MAX_BLASTER_THREADS *
///    OBJECTS_PER_BLASTER_THREAD` must fit in that 65536-id space, which
///    bounds how many threads can run at once.
/// 2. Unboundedly following "all remaining cores" produces a MASSIVE,
///    N-dependent oversubscription ratio at low N (11 blaster threads vs. 1
///    receiver) that just drives loopback-buffer drop% higher without
///    telling us anything more about receive-path scaling than a smaller,
///    still-comfortably-saturating ratio would.
const MAX_BLASTER_THREADS: usize = 8;

/// Run the SO_REUSEPORT delivery-scaling sweep (level 2): for each sweep
/// point `n`, bind `n` UDP sockets to the SAME `127.0.0.1:PORT` via
/// `SO_REUSEPORT`, hand each to a core-pinned receiver thread (`cores[..n]`),
/// and drive them with a blaster thread group pinned to a core set
/// (`cores[n..n + blaster_core_count]`) disjoint by *index* from the
/// receivers' -- but NOT disjoint by physical core: `cores` is
/// physical-core-first (see `topology_ordered_cores`), and on this box (6
/// physical cores / 12 threads) that range contains the SMT siblings of
/// `cores[..n]` at every `n` this sweep uses, meaning every receiver in this
/// sweep shares a physical core with an active blaster thread. Datagrams are
/// sent from many source sockets so the kernel's 4-tuple hash -- not this
/// code -- decides which receiver socket each datagram lands on.
///
/// Sweep points are capped so at least `MIN_BLASTER_CORES` cores always
/// remain free for the blaster group; on a box with fewer usable cores than
/// that, level 2 is skipped (returns an empty `Vec`) rather than starving
/// the blaster and silently measuring an artificially throttled sender.
///
/// Returns `(n, aggregate_gbps, imbalance_ratio, offered, drop_pct)` per
/// sweep point. The first three columns match `level1_sweep`'s row shape by
/// convention only -- because of the SMT overlap above, `aggregate_gbps`
/// here is NOT comparable in magnitude to level 1's and must not be read as
/// a receiver throughput ceiling; it (and its scaling across `n`) is
/// blaster-/SMT-/loopback-bound. `offered` and `drop_pct` are carried in the
/// return value (in addition to being printed directly by this function
/// alongside the other per-socket counts) so the go/no-go-facing summary in
/// `main` can surface the blaster-bound nature of these numbers too.
fn level2_sweep(cores: &[usize], dur: Duration) -> Vec<(usize, f64, f64, u64, f64)> {
    let total = cores.len();
    let ns: Vec<usize> = [1usize, 2, 4, 6]
        .into_iter()
        .filter(|&n| n + MIN_BLASTER_CORES <= total)
        .collect();
    if ns.is_empty() {
        eprintln!(
            "level2_sweep: only {total} usable cores (need >=1 receiver + \
             {MIN_BLASTER_CORES} disjoint blaster cores) -- skipping level 2"
        );
        return Vec::new();
    }

    println!("\nlevel 2 (SO_REUSEPORT delivery) per-N detail:");
    println!(
        " N   recv_Gbps   imbalance   offered   received    drop%   dgrams/object   per_socket_datagrams"
    );
    let mut rows = Vec::with_capacity(ns.len());

    for &n in &ns {
        // --- n SO_REUSEPORT receiver sockets, all bound to the same port ---
        let (first_sock, port) = bind_reuseport_socket(None);
        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        let mut sockets = Vec::with_capacity(n);
        sockets.push(first_sock);
        for _ in 1..n {
            let (sock, _) = bind_reuseport_socket(Some(port));
            sockets.push(sock);
        }

        // Up to `MAX_BLASTER_THREADS` of the remaining cores blast. This is
        // NOT the same mistake as an earlier, too-small fixed cap: at every
        // sweep point here the blaster group is either "all remaining cores"
        // (when that's <= MAX_BLASTER_THREADS, e.g. N=6 on this box) or a
        // comfortably-saturating 8 threads (see `MAX_BLASTER_THREADS`'s doc
        // comment) -- never starved down to a handful of threads regardless
        // of how many receiver cores are in use.
        let blaster_core_count = (total - n).min(MAX_BLASTER_THREADS);
        let blaster_cores = &cores[n..n + blaster_core_count];

        // n receivers + the blaster threads, all released together.
        let barrier = Arc::new(Barrier::new(n + blaster_cores.len()));

        let recv_handles: Vec<_> = sockets
            .into_iter()
            .enumerate()
            .map(|(i, sock)| {
                let core = cores[i];
                let barrier = Arc::clone(&barrier);
                thread::Builder::new()
                    .name(format!("l2-recv-{i}"))
                    .spawn(move || recv_worker(sock, core, barrier, dur))
                    .expect("spawn receiver thread")
            })
            .collect();

        let blast_handles: Vec<_> = blaster_cores
            .iter()
            .enumerate()
            .map(|(i, &core)| {
                let barrier = Arc::clone(&barrier);
                thread::Builder::new()
                    .name(format!("l2-blast-{i}"))
                    .spawn(move || blast_worker(core, target, barrier, dur, i))
                    .expect("spawn blaster thread")
            })
            .collect();

        let recv_results: Vec<(u64, u64, u64, u64)> = recv_handles
            .into_iter()
            .map(|h| h.join().expect("join receiver thread"))
            .collect();
        let offered: u64 = blast_handles
            .into_iter()
            .map(|h| h.join().expect("join blaster thread"))
            .sum();

        let counts: Vec<u64> = recv_results.iter().map(|r| r.0).collect();
        let received: u64 = counts.iter().sum();
        let total_bytes: u64 = recv_results.iter().map(|r| r.1).sum();
        let total_opened: u64 = recv_results.iter().map(|r| r.2).sum();
        let total_completed: u64 = recv_results.iter().map(|r| r.3).sum();

        let max_c = *counts.iter().max().unwrap_or(&0);
        let min_c = *counts.iter().min().unwrap_or(&0);
        let imbalance = max_c as f64 / (min_c.max(1) as f64);
        let gbps = (total_bytes as f64 * 8.0) / dur.as_secs_f64() / 1e9;
        let drop_pct = if offered > 0 {
            100.0 * (1.0 - received as f64 / offered as f64)
        } else {
            0.0
        };
        // See `recv_worker`'s doc comment: with this file's fixture (K=2
        // source symbols, blaster `extra_repair=2`), ~4 datagrams arrive per
        // completed object under no loss -- this is the "is `receive`
        // actually decoding, or silently zeroing out?" health signal, NOT
        // the raw per-datagram None rate (which is expected to be ~75% and
        // would false-alarm on every run).
        let dgrams_per_object = received as f64 / total_completed.max(1) as f64;

        println!(
            " {n:<3} {gbps:>9.2}   {imbalance:>9.2}   {offered:>7}   {received:>8}   {drop_pct:>5.1}   {dgrams_per_object:>11.2}   {counts:?}"
        );
        // `open()` succeeding at all here would mean the blaster's session
        // happened to match a receiver's -- see the module doc comment on
        // why that should never happen. Surfacing it rather than silently
        // folding it into `gbps` is the "detect it" requirement from the
        // task brief: a real acceptance would need investigating, not
        // quietly trusting the byte count.
        if total_opened > 0 {
            eprintln!(
                "level2_sweep(N={n}): {total_opened} datagram(s) AEAD-opened \
                 successfully despite independent blaster/receiver sessions \
                 -- unexpected, see report"
            );
        }
        // A datagram count that stays healthy while completions collapse is
        // exactly the silent-zeroing failure mode the task brief warns
        // about (e.g. an object-id collision, or the FecReassembler's
        // `state.done` guard rejecting a repeated id before enough distinct
        // ids evicted it -- see `OBJECTS_PER_BLASTER_THREAD`'s doc comment).
        // 12 is 3x the ~4 expected under no loss -- generous headroom for
        // real loopback loss (which raises this ratio legitimately, since
        // lost shards mean more received-but-still-incomplete objects) while
        // still catching a genuine "objects aren't completing" regression.
        if received > 0 && total_completed > 0 && dgrams_per_object > 12.0 {
            eprintln!(
                "level2_sweep(N={n}): {dgrams_per_object:.1} datagrams received per \
                 completed object (expected ~4) -- objects may not be decoding \
                 as expected, see report"
            );
        } else if received > 0 && total_completed == 0 {
            eprintln!(
                "level2_sweep(N={n}): {received} datagrams received but ZERO objects \
                 completed -- gbps is silently zero, see report"
            );
        }

        rows.push((n, gbps, imbalance, offered, drop_pct));
    }
    rows
}

fn main() {
    let cores = topology_ordered_cores();
    let dur = Duration::from_secs(5);

    let rows = level1_sweep(&cores, dur);

    let gbps_1 = rows
        .iter()
        .find(|(n, _, _)| *n == 1)
        .map(|(_, g, _)| *g)
        .unwrap_or(1.0);

    println!("level 1 (in-process compute scaling):");
    println!(" N   aggregate_Gbps   per_core   efficiency   avg_MHz");
    for (n, gbps, avg_mhz) in &rows {
        let per_core = gbps / *n as f64;
        let efficiency = gbps / (*n as f64 * gbps_1);
        println!(" {n:<3} {gbps:>13.2}   {per_core:>8.2}   {efficiency:>10.2}   {avg_mhz:>7.0}");
    }

    let rows2 = level2_sweep(&cores, dur);
    println!(
        "\nlevel 2 (SO_REUSEPORT delivery scaling) summary -- blaster-/SMT-/loopback-bound, \
         NOT a receiver throughput ceiling and NOT comparable in magnitude to level 1 above \
         (see module doc comment):"
    );
    println!(" N   recv_Gbps   imbalance   offered    drop%");
    for (n, gbps, imbalance, offered, drop_pct) in &rows2 {
        println!(" {n:<3} {gbps:>11.2}   {imbalance:>9.2}   {offered:>7}   {drop_pct:>5.1}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_roundtrips_inner() {
        let mut w = Worker::new();
        let inner = sample_inner(1300);
        assert_eq!(w.step(&inner), inner.len());
    }

    /// `run_worker` silently under-counts on failure: `Worker::step` returns
    /// 0 for any payload the receive chain rejects, and the sweep's total
    /// byte count would still print a clean (if smaller) number with no
    /// indication that the 5-tuple mutation in `build_fixture` broke
    /// anything. This test makes that failure mode visible: every mutated
    /// payload in a worker's fixture must round-trip exactly like the
    /// untouched fixture above.
    #[test]
    fn fixture_payloads_all_roundtrip() {
        let mut w = Worker::new();
        let inners = build_fixture(0, PAYLOADS_PER_WORKER);
        for (idx, inner) in inners.iter().enumerate() {
            let recovered = w.step(inner);
            assert_eq!(
                recovered,
                inner.len(),
                "fixture payload {idx} failed to roundtrip (got {recovered} bytes, expected {})",
                inner.len()
            );
        }
    }

    #[test]
    fn parse_cpu_list_handles_ranges_and_singletons() {
        assert_eq!(parse_cpu_list("0-1"), vec![0, 1]);
        assert_eq!(parse_cpu_list("3"), vec![3]);
        assert_eq!(parse_cpu_list("0,2,4"), vec![0, 2, 4]);
    }

    /// The core `SO_REUSEPORT` claim underpinning level 2: two sockets can
    /// bind the SAME `127.0.0.1:port` at once. If this ever stopped holding
    /// (e.g. a missing/failed `setsockopt` on some kernel), the second
    /// `bind_reuseport_socket` call would fail with `EADDRINUSE` instead of
    /// succeeding, and level 2's entire premise would be broken silently
    /// upstream of any Gbps/imbalance number.
    #[test]
    fn bind_reuseport_socket_allows_multiple_binds_same_port() {
        let (first, port) = bind_reuseport_socket(None);
        // Without SO_REUSEPORT this second bind to the same port would fail
        // with EADDRINUSE; succeeding (and `.expect("bind")` not panicking)
        // is the actual claim under test, not the returned port number.
        let (second, port2) = bind_reuseport_socket(Some(port));
        let (third, port3) = bind_reuseport_socket(Some(port));
        for (sock, p) in [(&first, port), (&second, port2), (&third, port3)] {
            assert_eq!(sock.local_addr().expect("local_addr").port(), p);
        }
    }
}

#[cfg(test)]
mod wrap_check {
    use super::*;

    #[test]
    #[ignore]
    fn wraparound_sanity() {
        let mut w = Worker::new();
        let inner = sample_inner(1300);
        let mut fails = 0u32;
        for i in 0..70_000u32 {
            let r = w.step(&inner);
            if r != inner.len() {
                fails += 1;
                if fails <= 5 {
                    eprintln!("step {i} returned {r}, expected {}", inner.len());
                }
            }
        }
        eprintln!("total fails: {fails} / 70000");
        assert_eq!(fails, 0);
    }
}
