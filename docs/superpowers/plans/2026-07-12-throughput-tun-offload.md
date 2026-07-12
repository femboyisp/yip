# TUN vnet-header GSO/GRO offload (lever 4b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut the per-packet TUN device I/O cost (the dominant single-core cost after 4a) by batching yipd's TUN reads/writes through a `virtio_net_hdr` — RX-coalesce decrypted same-flow packets into one GSO super-frame the kernel segments on write (~20%), and split kernel-GRO'd reads back into MTU packets (~7%) — with **no wire/FEC/AEAD change**.

**Architecture:** vnet-hdr framing is local to each box's yipd↔kernel-TUN boundary. A new `crates/yip-io/src/tun_offload.rs` holds the `virtio_net_hdr` codec, the RX userspace-GRO **coalescer** (build merged super-frame; the kernel does segmentation+checksum on write), and the TX **splitter** (software-segment a GRO'd read into MTU packets with per-segment seq+checksum, since those go out as independent encrypted wire datagrams). `yip-device` opens the TUN with `IFF_VNET_HDR`+`TUNSETOFFLOAD` gated on a `want_vnet_hdr` intent (poll driver only). The poll path splits on read and coalesces on write; a plain per-packet fallback runs whenever vnet-hdr is off.

**Tech Stack:** Rust, `libc` (`ioctl` TUNSETIFF/TUNSETOFFLOAD, `IFF_VNET_HDR`, `read`/`write`), Linux ≥ 3.x TUN GSO. No new crate deps.

## Global Constraints

- **Byte-exact packet preservation:** split(super-frame) yields exactly the MTU packets the kernel would deliver un-GRO'd; coalesce(packets)→kernel-GSO yields exactly the packets that were decrypted. A round-trip `coalesce → split` (and vice-versa) reproduces inputs byte-for-byte.
- **No wire / FEC / AEAD change:** each wire datagram stays one encrypted MTU packet. Coalescer only merges *already-decrypted* packets; splitter runs *before* encryption. `yip-wire`, FEC symbol sizing, replay, nonce untouched.
- **vnet-hdr gated on the poll driver:** `want_vnet_hdr` is true only when `PollDriver` runs (false under `YIP_USE_URING=1`), so the TUN fd's framing always matches its consumer. uring TUN path unchanged.
- **Correctness-preserving fallback:** no `IFF_VNET_HDR`/`TUNSETOFFLOAD` support → plain per-packet TUN I/O (today's behavior). Any coalescer/splitter uncertainty falls back to singleton handling, never corrupts packets.
- **Latency-neutral:** RX coalescing flushes at end-of-burst; a lone/`PSH`/`FIN` packet writes immediately. TX split is immediate.
- **`unsafe` only in `yip-io`/`yip-device`;** `yipd` stays `#![forbid(unsafe_code)]`. Every `unsafe` block has a `// SAFETY:` comment. No `as` numeric casts except libc-ABI/discriminants. No bare `#[allow]` — `#[expect(reason=…)]` only.
- **`refrences/` is read-only.**
- **Spike gate (Task 0) is binding:** if vnet-hdr GSO/GRO does not meaningfully cut TUN CPU on the target kernel with bulk TCP, STOP — do not implement Tasks 1–7.

---

### Task 0: De-risking spike — does TUN vnet-hdr GSO/GRO pay off? (throwaway)

**Purpose:** Before any production code, prove on the target boxes that (a) a TUN opened with `IFF_VNET_HDR`+`TUNSETOFFLOAD` delivers GRO'd super-frames on read under bulk TCP, and (b) writing a coalesced GSO super-frame costs less CPU than per-packet writes. Also nail down the empirical kernel semantics the later tasks depend on: `virtio_net_hdr` field endianness, whether write-GSO needs `VIRTIO_NET_HDR_F_NEEDS_CSUM` + `csum_start`/`csum_offset`, and the header length (10 vs 12). **Hard gate: no meaningful TUN-CPU reduction under bulk TCP → STOP and report.** Throwaway; not committed to the crate.

**Files:**
- Create (scratchpad, NOT under `crates/`): `tun_gso_spike.c` (standalone, built with `gcc -O2`).

- [ ] **Step 1: Write a TUN vnet-hdr probe**

A single-file C program that opens `/dev/net/tun` with `IFF_TUN|IFF_NO_PI|IFF_VNET_HDR`, `ioctl(TUNSETOFFLOAD, TUN_F_CSUM|TUN_F_TSO4|TUN_F_TSO6)`, assigns an IP, brings it up, and in two modes:
- `read`: loop `read()` the fd; for each, parse the 10-byte `virtio_net_hdr`, print `gso_type`/`gso_size`/`hdr_len` and the total L3 length. Reports the distribution of read sizes (are they > MTU, i.e. GRO firing?).
- `writeperf`: given a captured single TCP packet, (a) write it N times per-packet, then (b) build one coalesced GSO super-frame (vnet_hdr gso_type=TCPV4, gso_size=MSS, `F_NEEDS_CSUM`+csum fields, merged IP/TCP header + concatenated payload) and write it once carrying the same N segments; compare wall time + `/proc/self/stat` CPU for the two.

```c
// tun_gso_spike.c — build: gcc -O2 tun_gso_spike.c -o tun_gso_spike
// modes: ./tun_gso_spike <ifname> read   |   ./tun_gso_spike <ifname> writeperf
// Prints virtio_net_hdr fields + read-size distribution (read), or per-packet vs
// coalesced-GSO write CPU (writeperf). Reference: linux Documentation/networking/tuntap
```

- [ ] **Step 2: Drive bulk TCP through it on Y1/Y2**

On Y1 (`45.61.149.155`) / Y2 (`144.172.98.216`): create the vnet-hdr TUN, route a netns or a real `iperf3 -c … (TCP, -P 4)` bulk flow into it, run `tun_gso_spike <if> read` on the receiving side and confirm reads return super-frames (gso_size set, total > 1500). Run `writeperf` and record the per-packet-vs-coalesced CPU delta.

- [ ] **Step 3: Record the decision + the confirmed kernel constants**

Append a "4b TUN-offload spike" section to `crates/yip-bench/RESULTS.md` (committed): GRO-firing evidence, write CPU delta, and the confirmed constants (`virtio_net_hdr` size = 10 or 12, field endianness, whether write-GSO required `F_NEEDS_CSUM`+`csum_start`/`csum_offset`, which `TUN_F_*` the kernel accepted). State the verdict:
- meaningful TUN-CPU reduction under bulk TCP → proceed to Task 1, using the confirmed constants.
- no reduction → STOP; report; do not implement Tasks 1–7.

- [ ] **Step 4: Commit the recorded result**

```bash
git add crates/yip-bench/RESULTS.md
git commit -m "spike(throughput-4b): TUN vnet-hdr GSO/GRO on target kernel — decision gate + confirmed constants"
```

---

### Task 1: `virtio_net_hdr` codec (`tun_offload.rs`)

**Files:**
- Create: `crates/yip-io/src/tun_offload.rs`
- Modify: `crates/yip-io/src/lib.rs` (add `pub(crate) mod tun_offload;` beside the other `mod`s, lines 5-8)

**Interfaces:**
- Produces:
  - `pub(crate) const VNET_HDR_LEN: usize = 10;` (spike-confirmed; 12 only if mrg-rxbuf negotiated — Task 0 confirms)
  - `pub(crate) const GSO_NONE: u8 = 0; GSO_TCPV4: u8 = 1; GSO_TCPV6: u8 = 4; GSO_UDP_L4: u8 = 5;`
  - `pub(crate) const F_NEEDS_CSUM: u8 = 1; F_DATA_VALID: u8 = 2;`
  - `pub(crate) struct VnetHdr { pub flags: u8, pub gso_type: u8, pub hdr_len: u16, pub gso_size: u16, pub csum_start: u16, pub csum_offset: u16 }`
  - `pub(crate) fn read_vnet_hdr(buf: &[u8]) -> Option<VnetHdr>` — parse the first `VNET_HDR_LEN` bytes (host byte order, per Task 0); `None` if `buf.len() < VNET_HDR_LEN`.
  - `pub(crate) fn write_vnet_hdr(h: &VnetHdr, out: &mut [u8])` — serialize into the first `VNET_HDR_LEN` bytes of `out`.

- [ ] **Step 1: Write the failing round-trip test**

Create `crates/yip-io/src/tun_offload.rs` with only a `#[cfg(test)] mod tests`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vnet_hdr_roundtrip() {
        let h = VnetHdr { flags: F_NEEDS_CSUM, gso_type: GSO_TCPV4, hdr_len: 40,
                          gso_size: 1400, csum_start: 20, csum_offset: 16 };
        let mut buf = [0u8; VNET_HDR_LEN];
        write_vnet_hdr(&h, &mut buf);
        let got = read_vnet_hdr(&buf).expect("parse");
        assert_eq!(got.gso_type, GSO_TCPV4);
        assert_eq!(got.gso_size, 1400);
        assert_eq!(got.hdr_len, 40);
        assert_eq!(got.csum_start, 20);
        assert_eq!(got.csum_offset, 16);
        assert_eq!(got.flags, F_NEEDS_CSUM);
    }

    #[test]
    fn read_vnet_hdr_rejects_short() {
        assert!(read_vnet_hdr(&[0u8; VNET_HDR_LEN - 1]).is_none());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-io --lib tun_offload::`
Expected: FAIL — types/fns not found.

- [ ] **Step 3: Implement the codec**

Prepend to `tun_offload.rs` (host-byte-order per Task 0; adjust to LE only if the spike found VERSION_1 semantics):

```rust
//! Local TUN `virtio_net_hdr` (GSO/GRO) framing + the RX coalescer / TX splitter.
//! Purely local to the yipd↔kernel-TUN boundary — never touches the wire.

pub(crate) const VNET_HDR_LEN: usize = 10;
pub(crate) const GSO_NONE: u8 = 0;
pub(crate) const GSO_TCPV4: u8 = 1;
pub(crate) const GSO_TCPV6: u8 = 4;
pub(crate) const GSO_UDP_L4: u8 = 5;
pub(crate) const F_NEEDS_CSUM: u8 = 1;
pub(crate) const F_DATA_VALID: u8 = 2;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct VnetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

pub(crate) fn read_vnet_hdr(buf: &[u8]) -> Option<VnetHdr> {
    if buf.len() < VNET_HDR_LEN {
        return None;
    }
    let u16h = |a: usize| u16::from_ne_bytes([buf[a], buf[a + 1]]);
    Some(VnetHdr {
        flags: buf[0],
        gso_type: buf[1],
        hdr_len: u16h(2),
        gso_size: u16h(4),
        csum_start: u16h(6),
        csum_offset: u16h(8),
    })
}

pub(crate) fn write_vnet_hdr(h: &VnetHdr, out: &mut [u8]) {
    assert!(out.len() >= VNET_HDR_LEN);
    out[0] = h.flags;
    out[1] = h.gso_type;
    out[2..4].copy_from_slice(&h.hdr_len.to_ne_bytes());
    out[4..6].copy_from_slice(&h.gso_size.to_ne_bytes());
    out[6..8].copy_from_slice(&h.csum_start.to_ne_bytes());
    out[8..10].copy_from_slice(&h.csum_offset.to_ne_bytes());
}
```

- [ ] **Step 4: Run tests + clippy**

Run: `cargo test -p yip-io --lib tun_offload:: && cargo clippy -p yip-io --all-targets -- -D warnings`
Expected: PASS, clean. (Add `#[cfg_attr(not(test), expect(dead_code, reason = "wired into poll in Task 5"))]` on any item clippy reports unused until then.)

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/tun_offload.rs crates/yip-io/src/lib.rs
git commit -m "feat(yip-io): virtio_net_hdr codec for TUN GSO/GRO offload"
```

---

### Task 2: Flow key + IPv4/TCP header parsing helpers (`tun_offload.rs`)

**Purpose:** Both the coalescer and splitter need to parse an inner IPv4/TCP packet's fields (addresses, ports, seq, flags, header lengths) and recompute IP/TCP checksums. Isolate these pure helpers with exhaustive unit tests before the stateful coalescer/splitter use them.

**Files:**
- Modify: `crates/yip-io/src/tun_offload.rs`

**Interfaces:**
- Produces:
  - `pub(crate) struct FlowKey { pub src: [u8;4], pub dst: [u8;4], pub sport: u16, pub dport: u16 }`
  - `pub(crate) struct Ipv4Tcp<'a> { pub ip_hdr_len: usize, pub tcp_hdr_len: usize, pub total_len: usize, pub key: FlowKey, pub seq: u32, pub flags: u8, pub payload_off: usize, pub payload_len: usize, pub bytes: &'a [u8] }`
  - `pub(crate) fn parse_ipv4_tcp(pkt: &[u8]) -> Option<Ipv4Tcp<'_>>` — `None` if not IPv4+TCP, if IP-fragmented (MF set or frag offset != 0), or if truncated.
  - `pub(crate) fn ipv4_checksum(hdr: &mut [u8])` — zero then set the IPv4 header checksum in place.
  - `pub(crate) const TCP_FLAG_FIN: u8 = 0x01; TCP_FLAG_RST: u8 = 0x04; TCP_FLAG_PSH: u8 = 0x08; TCP_FLAG_URG: u8 = 0x20;`

- [ ] **Step 1: Write failing tests with a hand-built IPv4/TCP packet**

Add to `tun_offload.rs` tests. `mk_tcp` builds a minimal IPv4+TCP packet with a payload:

```rust
    fn mk_tcp(src: [u8;4], dst: [u8;4], sport: u16, dport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let ihl = 20usize; let thl = 20usize;
        let total = ihl + thl + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45; // v4, IHL=5
        p[2..4].copy_from_slice(&(u16::try_from(total).unwrap()).to_be_bytes());
        p[8] = 64; p[9] = 6; // TTL, proto=TCP
        p[12..16].copy_from_slice(&src); p[16..20].copy_from_slice(&dst);
        // TCP
        let t = ihl;
        p[t..t+2].copy_from_slice(&sport.to_be_bytes());
        p[t+2..t+4].copy_from_slice(&dport.to_be_bytes());
        p[t+4..t+8].copy_from_slice(&seq.to_be_bytes());
        p[t+12] = 0x50; // data offset = 5 (20 bytes)
        p[t+13] = flags;
        p[t+20..].copy_from_slice(payload);
        ipv4_checksum(&mut p[..ihl]);
        p
    }

    #[test]
    fn parse_ipv4_tcp_extracts_fields() {
        let p = mk_tcp([10,0,0,1],[10,0,0,2], 1234, 80, 1000, TCP_FLAG_PSH, b"hello");
        let x = parse_ipv4_tcp(&p).expect("parse");
        assert_eq!(x.key, FlowKey { src:[10,0,0,1], dst:[10,0,0,2], sport:1234, dport:80 });
        assert_eq!(x.seq, 1000);
        assert_eq!(x.flags & TCP_FLAG_PSH, TCP_FLAG_PSH);
        assert_eq!(x.ip_hdr_len, 20);
        assert_eq!(x.tcp_hdr_len, 20);
        assert_eq!(x.payload_len, 5);
        assert_eq!(&x.bytes[x.payload_off..x.payload_off + x.payload_len], b"hello");
    }

    #[test]
    fn parse_rejects_non_tcp_and_fragments() {
        let mut udp = mk_tcp([10,0,0,1],[10,0,0,2],1,2,0,0,b"x"); udp[9] = 17; // proto=UDP
        assert!(parse_ipv4_tcp(&udp).is_none());
        let mut frag = mk_tcp([10,0,0,1],[10,0,0,2],1,2,0,0,b"x"); frag[6] = 0x20; // MF set
        assert!(parse_ipv4_tcp(&frag).is_none());
    }

    #[test]
    fn ipv4_checksum_is_valid() {
        let p = mk_tcp([1,2,3,4],[5,6,7,8], 1,2,0,0, b"z");
        // A correct IPv4 checksum makes the one's-complement sum of the header 0xFFFF.
        let sum: u32 = p[..20].chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]]) as u32).sum();
        let folded = ((sum & 0xFFFF) + (sum >> 16)) as u16;
        assert_eq!(folded, 0xFFFF);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-io --lib tun_offload::`
Expected: FAIL — `parse_ipv4_tcp`/`ipv4_checksum`/`FlowKey` not found.

- [ ] **Step 3: Implement the parse + checksum helpers**

Add to `tun_offload.rs` (uses `usize::from`/`u16::from_be_bytes`, no `as` casts):

```rust
pub(crate) const TCP_FLAG_FIN: u8 = 0x01;
pub(crate) const TCP_FLAG_RST: u8 = 0x04;
pub(crate) const TCP_FLAG_PSH: u8 = 0x08;
pub(crate) const TCP_FLAG_URG: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlowKey { pub src: [u8;4], pub dst: [u8;4], pub sport: u16, pub dport: u16 }

pub(crate) struct Ipv4Tcp<'a> {
    pub ip_hdr_len: usize, pub tcp_hdr_len: usize, pub total_len: usize,
    pub key: FlowKey, pub seq: u32, pub flags: u8,
    pub payload_off: usize, pub payload_len: usize, pub bytes: &'a [u8],
}

pub(crate) fn parse_ipv4_tcp(pkt: &[u8]) -> Option<Ipv4Tcp<'_>> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 { return None; }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    if ihl < 20 || pkt.len() < ihl { return None; }
    if pkt[9] != 6 { return None; } // not TCP
    // fragmentation: MF (bit) or non-zero frag offset in bytes 6..8
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if (frag & 0x2000) != 0 || (frag & 0x1FFF) != 0 { return None; }
    let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if total_len < ihl || pkt.len() < total_len { return None; }
    if total_len < ihl + 20 { return None; }
    let t = ihl;
    let data_off = usize::from(pkt[t + 12] >> 4) * 4;
    if data_off < 20 || total_len < ihl + data_off { return None; }
    let sport = u16::from_be_bytes([pkt[t], pkt[t + 1]]);
    let dport = u16::from_be_bytes([pkt[t + 2], pkt[t + 3]]);
    let seq = u32::from_be_bytes([pkt[t + 4], pkt[t + 5], pkt[t + 6], pkt[t + 7]]);
    let flags = pkt[t + 13];
    let payload_off = ihl + data_off;
    Some(Ipv4Tcp {
        ip_hdr_len: ihl, tcp_hdr_len: data_off, total_len,
        key: FlowKey { src: [pkt[12],pkt[13],pkt[14],pkt[15]],
                       dst: [pkt[16],pkt[17],pkt[18],pkt[19]], sport, dport },
        seq, flags, payload_off, payload_len: total_len - payload_off, bytes: pkt,
    })
}

pub(crate) fn ipv4_checksum(hdr: &mut [u8]) {
    hdr[10] = 0; hdr[11] = 0;
    let mut sum: u32 = 0;
    for c in hdr.chunks(2) {
        let word = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { u16::from(c[0]) << 8 };
        sum += u32::from(word);
    }
    while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    let ck = !u16::try_from(sum & 0xFFFF).expect("folded sum fits u16");
    hdr[10..12].copy_from_slice(&ck.to_be_bytes());
}
```

- [ ] **Step 4: Run tests + clippy**

Run: `cargo test -p yip-io --lib tun_offload:: && cargo clippy -p yip-io --all-targets -- -D warnings`
Expected: PASS, clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/tun_offload.rs
git commit -m "feat(yip-io): IPv4/TCP parse + IP checksum helpers for TUN offload"
```

---

### Task 3: RX userspace-GRO coalescer (the big-win half, ~20%)

**Purpose:** Merge consecutive decrypted same-flow TCP segments into one GSO super-frame the kernel segments on write. The kernel does per-segment checksums (`F_NEEDS_CSUM` + `csum_start`/`csum_offset`), so the coalescer only merges headers + concatenates payloads + sets the `VnetHdr`. This is the load-bearing correctness path — the tests are exhaustive over the flush triggers.

**Files:**
- Modify: `crates/yip-io/src/tun_offload.rs`

**Interfaces:**
- Consumes: `parse_ipv4_tcp`, `VnetHdr`, `write_vnet_hdr`, `GSO_TCPV4`, `F_NEEDS_CSUM`, `ipv4_checksum`, the `TCP_FLAG_*` consts.
- Produces:
  - `pub(crate) struct Coalescer { … }` with `pub(crate) fn new() -> Self`.
  - `pub(crate) fn push<'a>(&'a mut self, pkt: &[u8]) -> Option<&'a [u8]>` — returns `Some(super_frame_with_vnet_hdr)` when pushing this packet forces a *previous* run to flush (the caller writes it), else `None` (packet buffered/started a run). The returned slice is `[vnet_hdr][merged IP/TCP hdr][concatenated payloads]`.
  - `pub(crate) fn flush(&mut self) -> Option<&[u8]>` — flush any buffered run at end-of-burst.
  - A run flushes (before appending the new packet) when the new packet: is not IPv4/TCP, has a different `FlowKey`, is not `seq == run.next_seq` (gap/reorder), carries `PSH|FIN|RST|URG`, has a differing TCP/IP header, would exceed the segment cap (`MAX_GSO_SEGMENTS`), or would exceed `MAX_GSO_PAYLOAD`. A non-coalescible packet is emitted as its own singleton (`gso_type = GSO_NONE`, no merge).

- [ ] **Step 1: Write the failing coalescer tests**

Add to `tun_offload.rs` tests (reuses `mk_tcp` from Task 2):

```rust
    // Helper: run a sequence of packets through a Coalescer, collecting every emitted frame
    // (both push-flushes and the final flush), returned as owned Vecs.
    fn run_coalescer(pkts: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut c = Coalescer::new();
        let mut out = Vec::new();
        for p in pkts { if let Some(f) = c.push(p) { out.push(f.to_vec()); } }
        if let Some(f) = c.flush() { out.push(f.to_vec()); }
        out
    }

    #[test]
    fn coalesces_contiguous_same_flow() {
        // three 100-byte segments, seq 0,100,200 — must merge into ONE super-frame.
        let p0 = mk_tcp([10,0,0,1],[10,0,0,2],9,80, 0,   0, &[0xAA;100]);
        let p1 = mk_tcp([10,0,0,1],[10,0,0,2],9,80, 100, 0, &[0xBB;100]);
        let p2 = mk_tcp([10,0,0,1],[10,0,0,2],9,80, 200, 0, &[0xCC;100]);
        let out = run_coalescer(&[p0, p1, p2]);
        assert_eq!(out.len(), 1, "one coalesced super-frame");
        let h = read_vnet_hdr(&out[0]).unwrap();
        assert_eq!(h.gso_type, GSO_TCPV4);
        assert_eq!(h.gso_size, 100);
        // super-frame payload = 300 bytes after vnet_hdr + IP(20) + TCP(20)
        assert_eq!(out[0].len(), VNET_HDR_LEN + 20 + 20 + 300);
    }

    #[test]
    fn flushes_on_seq_gap() {
        let p0 = mk_tcp([10,0,0,1],[10,0,0,2],9,80, 0,   0, &[0;100]);
        let gap = mk_tcp([10,0,0,1],[10,0,0,2],9,80, 500, 0, &[0;100]); // non-contiguous
        assert_eq!(run_coalescer(&[p0, gap]).len(), 2);
    }

    #[test]
    fn flushes_on_flow_change() {
        let a = mk_tcp([10,0,0,1],[10,0,0,2],9,80, 0, 0, &[0;100]);
        let b = mk_tcp([10,0,0,1],[10,0,0,3],9,80, 0, 0, &[0;100]); // different dst
        assert_eq!(run_coalescer(&[a, b]).len(), 2);
    }

    #[test]
    fn psh_and_fin_force_immediate_flush() {
        let p0 = mk_tcp([10,0,0,1],[10,0,0,2],9,80, 0,   TCP_FLAG_PSH, &[0;100]);
        let p1 = mk_tcp([10,0,0,1],[10,0,0,2],9,80, 100, 0,            &[0;100]);
        // p0 has PSH → emitted immediately as its own frame; p1 starts a new run flushed at end.
        assert_eq!(run_coalescer(&[p0, p1]).len(), 2);
    }

    #[test]
    fn non_tcp_is_singleton_passthrough() {
        let mut udp = mk_tcp([10,0,0,1],[10,0,0,2],9,80,0,0,&[0;100]); udp[9] = 17;
        let out = run_coalescer(&[udp.clone()]);
        assert_eq!(out.len(), 1);
        // singleton: gso_type NONE, body == original packet bytes exactly
        assert_eq!(read_vnet_hdr(&out[0]).unwrap().gso_type, GSO_NONE);
        assert_eq!(&out[0][VNET_HDR_LEN..], &udp[..]);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-io --lib tun_offload::`
Expected: FAIL — `Coalescer` not found.

- [ ] **Step 3: Implement the `Coalescer` (sealed-run model — `push` returns ≤1 frame)**

Add to `tun_offload.rs`. **Model:** there is at most one *pending run* buffered as
`[vnet_hdr | first IP+TCP header | payloads…]`. Each pushed packet either (a) **extends** the
pending run (open, same flow, `seq == next_seq`, no seal flags, under caps) → return `None`; or
(b) **flushes** the pending run (finalize it into `out`, return the borrow) and starts a new
pending run from this packet. A packet that is non-TCP, or carries `PSH|FIN|RST|URG`, or has no
payload starts a **sealed** pending run (`gso_type = GSO_NONE` for non-TCP, or a one-segment
TCP run) that the *next* push always flushes. `flush()` emits the final pending run. Because a
pending run is always buffered (never emitted mid-`push`), `push` returns at most one frame.
The kernel recomputes L4 checksums via `F_NEEDS_CSUM`; we only patch IP length + IP checksum.

```rust
pub(crate) const MAX_GSO_SEGMENTS: usize = 64;
pub(crate) const MAX_GSO_PAYLOAD: usize = 65_535;

pub(crate) struct Coalescer {
    pending: Vec<u8>,      // [vnet_hdr | ip+tcp hdr | payloads]; empty ⇒ nothing pending
    out: Vec<u8>,          // holds a flushed frame for the returned borrow
    has_pending: bool,
    is_tcp_run: bool,      // false ⇒ pending is a GSO_NONE singleton
    sealed: bool,          // pending cannot be extended (PSH/FIN/non-TCP/no-payload)
    key: FlowKey,
    next_seq: u32,
    gso_size: u16,
    ip_hdr_len: usize,
    l3_hdr_len: usize,     // ip_hdr_len + tcp_hdr_len (payload offset within the L3 packet)
    segs: usize,
}

impl Coalescer {
    pub(crate) fn new() -> Self {
        Self { pending: Vec::with_capacity(MAX_GSO_PAYLOAD + 64),
               out: Vec::with_capacity(MAX_GSO_PAYLOAD + 64),
               has_pending: false, is_tcp_run: false, sealed: false,
               key: FlowKey { src:[0;4], dst:[0;4], sport:0, dport:0 },
               next_seq: 0, gso_size: 0, ip_hdr_len: 0, l3_hdr_len: 0, segs: 0 }
    }

    /// Finalize the pending run into `self.out` and return the borrow (or None).
    fn take_pending(&mut self) -> Option<&[u8]> {
        if !self.has_pending { return None; }
        if self.is_tcp_run {
            // patch IP total-length + IP checksum, then set the vnet_hdr.
            let ip = VNET_HDR_LEN;
            let l3_len = self.pending.len() - VNET_HDR_LEN;
            let total = u16::try_from(l3_len).unwrap_or(u16::MAX);
            self.pending[ip + 2..ip + 4].copy_from_slice(&total.to_be_bytes());
            ipv4_checksum(&mut self.pending[ip..ip + self.ip_hdr_len]);
            let h = VnetHdr {
                flags: F_NEEDS_CSUM, gso_type: GSO_TCPV4,
                hdr_len: u16::try_from(self.l3_hdr_len).unwrap_or(0),
                gso_size: self.gso_size,
                csum_start: u16::try_from(self.ip_hdr_len).unwrap_or(0), // L4 offset within L3 frame
                csum_offset: 16,                                          // TCP checksum offset
            };
            write_vnet_hdr(&h, &mut self.pending[..VNET_HDR_LEN]);
        }
        // (non-TCP singleton already has its GSO_NONE vnet_hdr written at start_singleton)
        std::mem::swap(&mut self.pending, &mut self.out);
        self.pending.clear();
        self.has_pending = false;
        Some(&self.out)
    }

    fn start_tcp_run(&mut self, x: &Ipv4Tcp<'_>, sealed: bool) {
        self.pending.clear();
        self.pending.resize(VNET_HDR_LEN, 0);
        self.pending.extend_from_slice(&x.bytes[..x.total_len]); // full first L3 packet
        self.has_pending = true; self.is_tcp_run = true; self.sealed = sealed;
        self.key = x.key; self.ip_hdr_len = x.ip_hdr_len; self.l3_hdr_len = x.payload_off;
        self.gso_size = u16::try_from(x.payload_len).unwrap_or(0);
        self.next_seq = x.seq.wrapping_add(u32::try_from(x.payload_len).unwrap_or(0));
        self.segs = 1;
    }

    fn start_singleton(&mut self, pkt: &[u8]) {
        self.pending.clear();
        self.pending.resize(VNET_HDR_LEN, 0);
        write_vnet_hdr(&VnetHdr { gso_type: GSO_NONE, ..VnetHdr::default() }, &mut self.pending);
        self.pending.extend_from_slice(pkt);
        self.has_pending = true; self.is_tcp_run = false; self.sealed = true;
    }

    pub(crate) fn push(&mut self, pkt: &[u8]) -> Option<&[u8]> {
        let parsed = parse_ipv4_tcp(pkt);
        // Can this packet extend the current (open, tcp) pending run?
        if self.has_pending && self.is_tcp_run && !self.sealed {
            if let Some(x) = &parsed {
                let cont = x.payload_len > 0
                    && (x.flags & (TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_URG)) == 0
                    && x.key == self.key && x.seq == self.next_seq
                    && x.payload_off == self.l3_hdr_len
                    && self.segs < MAX_GSO_SEGMENTS
                    && (self.pending.len() - VNET_HDR_LEN - self.l3_hdr_len) + x.payload_len <= MAX_GSO_PAYLOAD;
                if cont {
                    self.pending.extend_from_slice(&x.bytes[x.payload_off..x.payload_off + x.payload_len]);
                    self.next_seq = self.next_seq.wrapping_add(u32::try_from(x.payload_len).unwrap_or(0));
                    self.segs += 1;
                    return None;
                }
            }
        }
        // Cannot extend: flush the pending run (if any), then start a new one from `pkt`.
        // Buffer the flushed frame's bytes so we can start the new run before returning it.
        let flushed: Option<Vec<u8>> = self.take_pending().map(<[u8]>::to_vec);
        match &parsed {
            Some(x) if x.payload_len > 0 => {
                let sealed = (x.flags & (TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_URG)) != 0;
                self.start_tcp_run(x, sealed);
            }
            _ => self.start_singleton(pkt),
        }
        match flushed { Some(f) => { self.out = f; Some(&self.out) } None => None }
    }

    pub(crate) fn flush(&mut self) -> Option<&[u8]> { self.take_pending() }
}
```

> **Implementer note:** the `to_vec()` of a flushed frame in `push` (needed so we can start the
> next run before returning the prior frame) is a per-flush allocation only on the *boundary*
> between runs — not per packet. If profiling shows it matters, swap `out` to a small ring of two
> buffers; the tests pin behavior, not the allocation strategy. The `F_NEEDS_CSUM` +
> `csum_start`/`csum_offset` values assume Task 0 confirmed the kernel wants partial-checksum GSO
> writes (the standard TUN GSO contract); adjust the constants if the spike found otherwise.

- [ ] **Step 4: Run coalescer tests + clippy**

Run: `cargo test -p yip-io --lib tun_offload:: && cargo clippy -p yip-io --all-targets -- -D warnings`
Expected: PASS (all coalescer tests), clean.

- [ ] **Step 5: Commit**

```bash
git add crates/yip-io/src/tun_offload.rs
git commit -m "feat(yip-io): RX userspace-GRO coalescer (TUN GSO write path)"
```

---

### Task 4: TX super-frame splitter (~7% half)

**Purpose:** Split a kernel-GRO'd read (one large TCP super-frame + vnet_hdr) back into individual MTU packets with correct per-segment IP total-length, IP ID, TCP sequence numbers, and **fully-computed** IP+TCP checksums (these packets are encrypted and sent as independent wire datagrams — nothing downstream re-segments them).

**Files:**
- Modify: `crates/yip-io/src/tun_offload.rs`

**Interfaces:**
- Produces: `pub(crate) fn split_gro<'a>(frame: &[u8], out: &'a mut Vec<u8>, offsets: &'a mut Vec<(usize, usize)>) -> bool` — `frame` is `[vnet_hdr][one big IPv4/TCP packet]`. When `gso_type == GSO_NONE`, pushes the single packet (bytes after the vnet_hdr) and returns `true`. When `gso_type == GSO_TCPV4`, writes each segment into `out` and records `(start,len)` per segment in `offsets`. Returns `false` (caller falls back to a raw pass-through of `frame[VNET_HDR_LEN..]`) if the frame is malformed. `out`/`offsets` are reusable, cleared on entry.
- Produces: `pub(crate) fn tcp_checksum(ip_tcp: &mut [u8], ip_hdr_len: usize)` — compute+set the TCP checksum (with IPv4 pseudo-header) over a single already-segmented packet.

- [ ] **Step 1: Write the failing splitter tests**

```rust
    #[test]
    fn split_none_passthrough() {
        let pkt = mk_tcp([10,0,0,1],[10,0,0,2],9,80,0,TCP_FLAG_PSH,b"hi");
        let mut frame = vec![0u8; VNET_HDR_LEN];
        write_vnet_hdr(&VnetHdr{gso_type: GSO_NONE, ..Default::default()}, &mut frame);
        frame.extend_from_slice(&pkt);
        let (mut out, mut offs) = (Vec::new(), Vec::new());
        assert!(split_gro(&frame, &mut out, &mut offs));
        assert_eq!(offs.len(), 1);
        assert_eq!(&out[offs[0].0..offs[0].0+offs[0].1], &pkt[..]);
    }

    #[test]
    fn split_gro_segments_and_checksums() {
        // one super-frame: gso_size=100, 250 bytes payload → segments of 100,100,50.
        let mut big = mk_tcp([10,0,0,1],[10,0,0,2],9,80, 1000, 0, &vec![0xEE; 250]);
        // fix IP total-length already set by mk_tcp; build the framed input:
        let mut frame = vec![0u8; VNET_HDR_LEN];
        write_vnet_hdr(&VnetHdr{ flags: F_NEEDS_CSUM, gso_type: GSO_TCPV4, hdr_len: 40,
                                 gso_size: 100, csum_start: 20, csum_offset: 16 }, &mut frame);
        frame.extend_from_slice(&big);
        let (mut out, mut offs) = (Vec::new(), Vec::new());
        assert!(split_gro(&frame, &mut out, &mut offs));
        assert_eq!(offs.len(), 3);
        // each segment parses as valid IPv4/TCP with the right seq + payload size
        let sizes = [100usize, 100, 50];
        let mut expect_seq = 1000u32;
        for (i, &(s, l)) in offs.iter().enumerate() {
            let seg = &out[s..s+l];
            let x = parse_ipv4_tcp(seg).expect("valid segment");
            assert_eq!(x.payload_len, sizes[i]);
            assert_eq!(x.seq, expect_seq);
            expect_seq += u32::try_from(sizes[i]).unwrap();
            // IP checksum valid (header folds to 0xFFFF)
            let sum: u32 = seg[..20].chunks(2).map(|c| u16::from_be_bytes([c[0],c[1]]) as u32).sum();
            assert_eq!((((sum & 0xFFFF)+(sum>>16)) as u16), 0xFFFF);
        }
        let _ = &mut big;
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-io --lib tun_offload::`
Expected: FAIL — `split_gro`/`tcp_checksum` not found.

- [ ] **Step 3: Implement `split_gro` + `tcp_checksum`**

```rust
pub(crate) fn tcp_checksum(pkt: &mut [u8], ip_hdr_len: usize) {
    let total = pkt.len();
    let tcp_off = ip_hdr_len;
    // zero the checksum field
    pkt[tcp_off + 16] = 0; pkt[tcp_off + 17] = 0;
    let tcp_len = total - tcp_off;
    let mut sum: u32 = 0;
    // pseudo-header: src(4)+dst(4)+zero+proto(6)+tcp_len
    for i in (12..20).step_by(2) { sum += u32::from(u16::from_be_bytes([pkt[i], pkt[i+1]])); }
    sum += u32::from(6u16);
    sum += u32::try_from(tcp_len).expect("tcp_len fits u32") & 0xFFFF;
    for c in pkt[tcp_off..total].chunks(2) {
        let w = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { u16::from(c[0]) << 8 };
        sum += u32::from(w);
    }
    while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    let ck = !u16::try_from(sum & 0xFFFF).expect("folded fits u16");
    pkt[tcp_off + 16..tcp_off + 18].copy_from_slice(&ck.to_be_bytes());
}

pub(crate) fn split_gro(frame: &[u8], out: &mut Vec<u8>, offsets: &mut Vec<(usize, usize)>) -> bool {
    out.clear(); offsets.clear();
    let Some(h) = read_vnet_hdr(frame) else { return false; };
    let body = &frame[VNET_HDR_LEN..];
    if h.gso_type == GSO_NONE || h.gso_size == 0 {
        let start = out.len(); out.extend_from_slice(body); offsets.push((start, body.len())); return true;
    }
    let Some(x) = parse_ipv4_tcp(body) else { return false; };
    let seg = usize::from(h.gso_size);
    let hdr = x.payload_off; // ip_hdr_len + tcp_hdr_len
    let payload = &body[x.payload_off..x.payload_off + x.payload_len];
    let mut seq = x.seq;
    let mut ip_id = u16::from_be_bytes([body[4], body[5]]);
    let mut off = 0usize;
    while off < payload.len() {
        let n = seg.min(payload.len() - off);
        let start = out.len();
        out.extend_from_slice(&body[..hdr]);        // clone IP+TCP header
        out.extend_from_slice(&payload[off..off + n]);
        let s = &mut out[start..start + hdr + n];
        // patch IP total-length, IP ID, TCP seq; recompute both checksums
        let total = u16::try_from(hdr + n).expect("segment fits u16");
        s[2..4].copy_from_slice(&total.to_be_bytes());
        s[4..6].copy_from_slice(&ip_id.to_be_bytes());
        s[x.ip_hdr_len + 4..x.ip_hdr_len + 8].copy_from_slice(&seq.to_be_bytes());
        ipv4_checksum(&mut s[..x.ip_hdr_len]);
        tcp_checksum(s, x.ip_hdr_len);
        offsets.push((start, hdr + n));
        seq = seq.wrapping_add(u32::try_from(n).expect("n fits u32"));
        ip_id = ip_id.wrapping_add(1);
        off += n;
    }
    true
}
```

- [ ] **Step 4: Run splitter tests + clippy**

Run: `cargo test -p yip-io --lib tun_offload:: && cargo clippy -p yip-io --all-targets -- -D warnings`
Expected: PASS, clean.

- [ ] **Step 5: Round-trip test — split then coalesce reproduces segments**

Add and run a test that builds a GRO super-frame, `split_gro`s it into N packets, feeds those packets through a `Coalescer`, and asserts the coalesced payload bytes equal the original super-frame payload (byte-exact round-trip). Commit.

```bash
git add crates/yip-io/src/tun_offload.rs
git commit -m "feat(yip-io): TX GRO super-frame splitter (software TSO) + round-trip test"
```

---

### Task 5: Device offload open + poll-path wiring

**Files:**
- Modify: `crates/yip-device/src/lib.rs` (`TunTap::create` → accept `want_vnet_hdr`; add `TUNSETOFFLOAD`; expose `vnet_hdr_len() -> Option<usize>`), `crates/yip-io/src/poll.rs` (`run_poll` takes vnet-hdr state; `drain_tun` splits; `drain_udp` coalesces), `bin/yipd/src/tunnel.rs` (decide driver first, pass `want_vnet_hdr`, thread state into `run_poll`).

**Interfaces:**
- Consumes: `tun_offload::{Coalescer, split_gro, VNET_HDR_LEN}`.
- Produces: `TunTap::create(name, kind, want_vnet_hdr: bool)`; `TunTap::vnet_hdr_len(&self) -> Option<usize>`; `run_poll(udp_fd, tun_fd, vnet_hdr: bool, d)`.

- [ ] **Step 1: `yip-device` — open with `IFF_VNET_HDR` + `TUNSETOFFLOAD`, feature-fallback**

Add the const `IFF_VNET_HDR: c_short = 0x4000;`, `TUNSETOFFLOAD: c_ulong = 0x4004_54d0;`, and `TUN_F_CSUM=0x01, TUN_F_TSO4=0x02, TUN_F_TSO6=0x04`. In `create`, when `want_vnet_hdr`, add `IFF_VNET_HDR` to `flags`; after `TUNSETIFF`, `ioctl(TUNSETOFFLOAD, TUN_F_CSUM|TUN_F_TSO4|TUN_F_TSO6)`; on `EINVAL`, retry with `TUN_F_CSUM` only, then clear vnet-hdr entirely (reopen without the flag). Store `vnet_hdr_len: Option<usize>` (Some(VNET_HDR_LEN) if active). Change the two call sites' signature. Show the full edited `create` body and the new `vnet_hdr_len` accessor. Add a `#[test]` that `create("…", Tun, false)` yields `vnet_hdr_len()==None` (the `true` path needs root/netns → covered by netns tests in Task 6).

- [ ] **Step 2: `run_poll` — thread vnet-hdr state + reusable offload buffers**

Change `run_poll` signature to `run_poll<D>(udp_fd, tun_fd, vnet_hdr: bool, d: &mut D)`. In the loop, own `let mut coalescer = tun_offload::Coalescer::new();`, a `split_out: Vec<u8>`, `split_offs: Vec<(usize,usize)>`, and grow the TUN read buffer to `VNET_HDR_LEN + MAX_GSO_PAYLOAD` when `vnet_hdr`. Pass `vnet_hdr`, `&mut coalescer`, and the split scratch through to `drain_tun`/`drain_udp`.

- [ ] **Step 3: `drain_tun` — split on read when vnet-hdr active**

When `vnet_hdr`: after each `read()`, `split_gro(&buf[..n], &mut split_out, &mut split_offs)`; for each `(s,l)` offset, feed `&split_out[s..s+l]` to `d.on_tun(...)` exactly as the per-packet path does today. When `!vnet_hdr`: today's path unchanged. Show the edited `drain_tun`.

- [ ] **Step 4: `drain_udp` — coalesce TUN writes when vnet-hdr active**

When `vnet_hdr`: replace `DispatchOut::Tun(inner) => send_to_tun(tun_fd, inner)` with `if let Some(frame) = coalescer.push(inner) { send_to_tun(tun_fd, frame) }`; after the recv burst loop, `if let Some(frame) = coalescer.flush() { send_to_tun(tun_fd, frame) }`. `send_to_tun` writes the frame verbatim (it already includes the vnet_hdr). When `!vnet_hdr`: today's path. Show the edited `drain_udp` + the end-of-burst flush placement.

- [ ] **Step 5: `bin/yipd/tunnel.rs` — decide driver first, pass `want_vnet_hdr`**

Reorder so the `YIP_USE_URING` decision is computed *before* `TunTap::create`; pass `want_vnet_hdr = !use_uring` to `create`; call `run_poll(udp_fd, tun_fd, tun.vnet_hdr_len().is_some(), &mut manager)`. The uring branch is unchanged (plain TUN, `want_vnet_hdr=false`). Show the edited region (tunnel.rs:115-168).

- [ ] **Step 6: Build, clippy, workspace unit tests**

Run: `cargo build --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p yip-io -p yip-device --lib`
Expected: builds, clean, tests pass. Commit.

```bash
git add crates/yip-device/src/lib.rs crates/yip-io/src/poll.rs bin/yipd/src/tunnel.rs
git commit -m "feat(yip-io,yip-device,yipd): wire TUN GSO/GRO offload into the poll path"
```

---

### Task 6: No-regression — netns both drivers, bulk TCP, fallback

**Files:** none expected (verification; fix in place if a regression appears).

- [ ] **Step 1: Full workspace tests** — `cargo test --workspace` → 0 failures.
- [ ] **Step 2: Build release yipd** — `cargo build --release -p yipd`.
- [ ] **Step 3: netns core, POLL driver (offload active).** Build the `tunnel_netns` test binary (`cargo test -p yipd --test tunnel_netns --no-run --message-format=json | jq -r 'select(.executable!=null).executable' | grep tunnel_netns | tail -1`). Run under `sudo -E`: `ping_across_yipd_tunnel`, `ping_across_yipd_tunnel_under_loss` (10% — FEC still recovers with offload), `arq_recovers_bulk_loss` → all PASS.
- [ ] **Step 4: netns, URING driver (plain TUN, offload off).** Same three with `env YIP_USE_URING=1` → all PASS (confirms the driver-gating: uring fd has no vnet_hdr).
- [ ] **Step 5: Bulk-TCP netns transfer.** Bring up the netns yip tunnel, run a bulk `iperf3 -c … (TCP)` or a large `dd`-over-`nc` across it, assert bytes arrive intact (the offload path's real workload; a hash of the transferred payload matches). If no harness exists, add a minimal `bin/yipd/tests/` script mirroring the netns setup that pipes a known payload through and diffs it.
- [ ] **Step 6: Commit** any regression fix (else skip).

---

### Task 7: Benchmark gate — bulk-TCP before/after on Y1/Y2

**Files:** Modify `crates/yip-bench/RESULTS.md`.

- [ ] **Step 1: Build both binaries** — 4b (this branch) and baseline (`main` `ec3ae21`, via a worktree). `scp` to Y1/Y2 as `/root/yipd-4b` and `/root/yipd-base`. Use `device=yip4b0`, a non-conflicting port, and a config path that does **not** touch the user's `/root/yip.conf` — the user's pre-existing `yip0` self-cert tunnel stays undisturbed.
- [ ] **Step 2: Bulk-TCP A/B.** For each binary: bring up the Y1↔Y2 tunnel, run bulk `iperf3 -c <tun> -P 4 -t 20` (TCP — the case offload targets) through it, and sample the *receiver* yipd's `tun_chr_write_iter` share via `perf record`/`perf report` (perf is installed on both boxes) plus total CPU. Record delivered throughput + receiver TUN CPU% for base vs 4b.
- [ ] **Step 3: Record** a "4b TUN offload" section in `RESULTS.md`: throughput before/after, receiver TUN-write CPU before/after, and honest interpretation (GSO/GRO helps bulk TCP; UDP-flood unaffected). Tear down (remove `yip4b0`, kill test yipd/iperf, delete `/root/yipd-{4b,base}`), and **verify the user's original `yip0` tunnel still pings** its self-cert peer.
- [ ] **Step 4: Commit** — `git add crates/yip-bench/RESULTS.md && git commit -m "bench(throughput-4b): bulk-TCP before/after for TUN GSO/GRO offload"`.

---

## Notes for the executor

- **Task 0 is a hard gate** and confirms the kernel constants (`virtio_net_hdr` size/endianness, `F_NEEDS_CSUM`/csum semantics, accepted `TUN_F_*`). If those differ from the assumptions in Tasks 1/3/4, adjust the constants there — the tests pin behavior, not kernel trivia.
- **The Coalescer's `push` borrow shape** (returning a flushed prior frame while buffering the current packet) is the fiddliest code; if the borrow checker resists, hold the pending flushed frame in an owned `Vec` field and return `&that`. Do not weaken the tests.
- **Byte-exactness is the invariant** — the split↔coalesce round-trip test (Task 4 Step 5) and the bulk-TCP netns transfer (Task 6 Step 5) are its guards. A checksum or seq bug shows up as a failed TCP transfer, not a crash.
- **`unsafe` only in `yip-io`/`yip-device`.** The offload logic (`tun_offload.rs`) is pure safe Rust (slice/byte math); the only new `unsafe` is the `yip-device` `ioctl`s. No `as` casts (use `try_from`), no bare `#[allow]`.
- **Do not disturb the user's Y1/Y2 tunnel** — separate device/port, and verify its self-cert peer still pings after Task 7 teardown.
