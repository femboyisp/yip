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
//! Run: `cargo run --release -p yip-bench --example sharding_scale`
//! Test: `cargo test -p yip-bench --example sharding_scale`

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

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

    /// One fresh-counter roundtrip through the real receive chain:
    /// seal -> FEC-encode -> frame -> deframe -> parse Symbol -> FEC-decode
    /// -> AEAD-open. Each call uses a strictly increasing AEAD counter (own
    /// `Session`, never shared), so the replay window never rejects.
    ///
    /// Returns the number of inner bytes recovered (0 if the chain didn't
    /// produce a decoded frame this call, which should not happen since no
    /// datagrams are dropped here).
    fn step(&mut self, inner: &[u8]) -> usize {
        let sealed = self.sender.seal(inner).expect("seal");
        let (class, symbols) = self.tx.encode(&sealed.ciphertext, inner, false, 0);

        let datagrams: Vec<Vec<u8>> = symbols
            .iter()
            .map(|sym| {
                let frame = symbol_to_frame(CONN_TAG, sym, sealed.counter, class);
                self.codec.frame(&frame)
            })
            .collect();

        let mut recovered_len = 0usize;
        for dg in &datagrams {
            let Ok(frame) = self.codec.deframe(dg) else {
                continue;
            };
            let Some((sym, counter, class)) = frame_to_symbol(&frame) else {
                continue;
            };
            if let Some(ciphertext) = self.rx.decode(&sym, class) {
                if let Ok(inner_bytes) = self.receiver.open(counter, &ciphertext) {
                    recovered_len = inner_bytes.len();
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

fn main() {
    let cores = topology_ordered_cores();
    let dur = Duration::from_secs(5);

    let rows = level1_sweep(&cores, dur);

    let gbps_1 = rows
        .iter()
        .find(|(n, _, _)| *n == 1)
        .map(|(_, g, _)| *g)
        .unwrap_or(1.0);

    println!(" N   aggregate_Gbps   per_core   efficiency   avg_MHz");
    for (n, gbps, avg_mhz) in &rows {
        let per_core = gbps / *n as f64;
        let efficiency = gbps / (*n as f64 * gbps_1);
        println!(" {n:<3} {gbps:>13.2}   {per_core:>8.2}   {efficiency:>10.2}   {avg_mhz:>7.0}");
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
