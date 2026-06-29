# 05 — Transport / Reliable-UDP / FEC / Tunneling Reference Survey

Research notes for the Rust P2P mesh VPN. Goals: **low latency**, **lossy-link
resilience**, plus secondary interest in **anti-DPI / transport mimicry** and
**NAT traversal**. Planned FEC scheme: **RaptorQ** (fountain code). These are
analyses of locally-cloned reference repos under
`/home/zoa/projects/femboy/yip/refrences/`.

Quick taxonomy:

| Repo | Layer | Core trick | Reuse value |
|------|-------|-----------|-------------|
| kcp (C→Rust port) | reliable transport | ARQ over UDP | High (ARQ ideas, Rust crate) |
| kcp2k-rust | reliable transport | KCP wrapper, dual-channel | Medium (config/session model) |
| UDPspeeder | FEC tunnel | Reed-Solomon block FEC | High (FEC tunnel design, knobs) |
| udpfrag | fragmentation lib | app-level frag/reassembly | Medium (header format) |
| udplistener | session demux | per-peer pseudo-conn over UDP | Medium (demux pattern) |
| tcp-in-udp | encapsulation | TCP↔UDP rewrite in eBPF/TC | High (anti-DPI idea) |
| icmptunnel | encapsulation | IP-over-ICMP echo/reply | Medium (fallback transport) |
| etherconn | raw socket I/O | AF_PACKET / AF_XDP bypass | Medium (raw-socket performance) |
| norp | routing+encap proto | identity-routed encrypted records | High (architecture/crypto framing) |
| nyxpsi | abandoned | RaptorQ-over-UDP-Lite demo | Low (cautionary; OTI handling) |

---

## kcp (`/refrences/kcp`)

- **What it does:** A pure-Rust port of skywind3000's KCP — a fast, reliable
  ARQ protocol layered on top of an unreliable datagram channel (UDP). Trades
  ~10–20% extra bandwidth for ~30–40% lower average latency vs TCP.
- **Language / license:** Rust, MIT. ~45 KB single core file (`src/kcp.rs`),
  optional `tokio` AsyncWrite feature. Deps: `bytes`, `log`, `thiserror`.
- **Mechanism:** Selective-repeat **ARQ** (no FEC). 24-byte per-segment header
  (`KCP_OVERHEAD = 24`): conv id, cmd (`PUSH`/`ACK`/`WASK`/`WINS`), frag count,
  window, timestamp, sn, una, len. RTT-estimated RTO (SRTT/RTTVAR, `update_ack`),
  **fast retransmit** on N duplicate ACKs (`fastresend`), selective ACK list,
  and a sliding send/recv window with optional congestion window (`nocwnd`
  toggles it off). Driven by an external clock: caller pumps `input()` (feed
  received UDP bytes), `send()`/`recv()` (app data), and `update()`/`check()`
  on a timer. KCP itself does **not** own a socket — purely a state machine over
  byte buffers.
- **Latency / throughput & knobs:** Knobs are the heart of KCP.
  `set_nodelay(nodelay, interval, resend, nc)` — "fastest" config is
  `(true, 20, 2, true)`: nodelay on, 20 ms tick, fast-resend after 2 dup-acks,
  congestion control **disabled**. Other knobs: window sizes (`KCP_WND_SND=32`,
  `KCP_WND_RCV=128`), MTU (`KCP_MTU_DEF=1400`, mss = mtu−24), RTO floor
  (`KCP_RTO_MIN=100`, `KCP_RTO_NDL=30` in nodelay), `KCP_DEADLINK=20`
  retransmits before declaring the link dead. Disabling congestion window is
  what gives KCP its aggressive low-latency behavior — at the cost of being a
  bad network citizen under congestion.
- **Where it sits:** Transport substrate **directly above UDP, below
  encryption** (you'd run KCP, then encrypt the KCP output, or encrypt payload
  before `send()`). It's a session/stream layer; you bring your own socket,
  crypto, and multiplexing.
- **Strengths:** Battle-tested algorithm, tiny dependency-free core, fully
  tunable, clock-driven design integrates with any async runtime. Selective
  ACK + fast retransmit recover from loss far faster than TCP's
  RTO-based recovery.
- **Weaknesses:** ARQ means **every lost packet costs at least one RTT** to
  recover — fundamentally bad for interactive traffic on high-RTT lossy links.
  No FEC. Congestion control is weak/optional (can cause collapse). Header is
  24 bytes/segment. Single-stream; no built-in crypto or multiplexing.
- **Could be done better / fit to goals:** For a low-latency lossy-link VPN,
  pure ARQ is the wrong primary tool — RTT-multiplied recovery kills tail
  latency. Better: pair an ARQ-style reliability layer with **proactive FEC** so
  most losses never trigger a retransmit (hybrid; see RaptorQ note). The KCP
  *knobs philosophy* (expose nodelay/interval/resend/window, allow turning off
  congestion control) is worth copying.
- **Reusable for us:** Use the crate directly if we want a reliable *control
  channel*. Borrow: the RTT/RTO estimator, the fast-retransmit-on-dup-ack
  trigger, the SACK encoding, and the external-clock `update/check` model
  (lets us drive many sessions from one timer wheel). For bulk data we'd front
  it with RaptorQ rather than rely on ARQ alone.

---

## kcp2k-rust (`/refrences/kcp2k-rust`)

- **What it does:** A higher-level Rust KCP implementation (port of Mirror's
  `kcp2k`) providing ready-to-use **client/server** sessions with connection
  lifecycle, cookies, and dual reliable/unreliable channels. Wraps the `kcp`
  crate above.
- **Language / license:** Rust, license-file (custom; appears MIT-style), edition
  2024. Deps: `revel_cell` (thread-safe cell), `socket2`, `kcp`, `log`.
- **Mechanism:** Adds a session layer over KCP: handshake with a 4-byte
  **cookie** (anti-spoof / connection validation), 1-byte **channel header**
  selecting `Reliable` (KCP) vs `Unreliable` (raw UDP passthrough), ping/timeout
  keepalive, and an event-callback API (`OnConnected/OnData/OnError/
  OnDisconnected`). One UDP socket multiplexes many connections; `tick()` pumps
  the state machine.
- **Latency / throughput & knobs:** `Kcp2KConfig` exposes: `mtu` (default 1200,
  smaller than KCP's 1400 to leave room for encryption/relay headers),
  `no_delay` (default **true**), `interval` (10 ms), `fast_resend`,
  `congestion_window` (default **false** — disabled for latency),
  `send_window_size`/`receive_window_size` (32/128), `recv/send_buffer_size`
  (7 MB each), `timeout` (2000 ms), `max_retransmits` (20), `is_reliable_ping`.
  Dual-mode IPv4/IPv6 optional.
- **Where it sits:** Session/transport above UDP. Same "below encryption"
  position as KCP, but it owns the socket and demuxes peers.
- **Strengths:** Concrete, copyable session model — cookie handshake, channel
  byte, keepalive, callback dispatch, the explicit MTU headroom for an
  encryption layer. Good reference for "how to wrap raw KCP into a usable
  endpoint."
- **Weaknesses:** Game-netcode heritage (Mirror/Unity): single-socket
  `tick()`-loop, no async, `revel_cell` thread-safety is bespoke. Docs are
  Chinese-only. Still ARQ-only (inherits KCP's loss-recovery latency).
  Unreliable channel has no FEC — it's just bare UDP.
- **Could be done better / fit to goals:** The **dual-channel** idea maps well
  to a VPN: reliable channel for control/handshake, unreliable+FEC channel for
  tunneled IP packets. We'd replace the bare unreliable path with a
  RaptorQ-coded path and make the whole thing async (tokio).
- **Reusable for us:** Cookie-based handshake (cheap NAT/spoof validation),
  channel-tagging byte, MTU-headroom convention, keepalive/timeout logic, and
  the single-socket-many-peers demux structure.

---

## UDPspeeder (`/refrences/UDPspeeder`)

- **What it does:** A UDP tunnel that **reduces effective packet-loss rate using
  Forward Error Correction (Reed-Solomon)** at the cost of redundant bandwidth.
  Pair it with any UDP VPN (OpenVPN/etc.) to improve TCP/UDP/ICMP over a lossy
  high-latency link. Author reports cutting 10% loss to <0.01%.
- **Language / license:** C++ (libev event loop), MIT. Core: `fec_manager.cpp/.h`,
  `lib/rs.*` (Reed-Solomon).
- **Mechanism:** **Block FEC, no ARQ.** Groups `x` original packets and emits
  `y` redundant packets (`-f x:y`, e.g. `-f20:10` = 10 parity for 20 data).
  Uses Reed-Solomon (`rs_encode2`, max 255 packets/group — the RS field limit).
  Two modes: **mode 0** chops/pads packets into equal-length shards inside a
  "blob" then RS-codes them (no MTU worry, more CPU); **mode 1** treats whole
  packets as symbols (lower latency, MTU-sensitive). Each shard carries a 32-bit
  `seq`. Decoder buffers a sliding window (`fec_buff_num=2000`) and recovers the
  group once ≥x of the x+y shards arrive. Optional **fine-grained FEC**
  (`-f 1:3,2:4,10:6,20:10`) interpolates redundancy ratio by group size.
  Anti-replay buffer, optional XOR "obscure," simple XOR key.
- **Latency / throughput & knobs:** `--timeout` (8 ms default) — how long a group
  waits before being coded/flushed; the central **latency↔efficiency** dial.
  `-q queue-len` (200) flush-when-full. `-i interval` **scatters a group's
  packets over N ms to survive burst loss** (anti-burst spreading — a great
  idea). `-j jitter`. `--mtu` (1250). `--fix-latency` to stabilize jitter.
  Runtime reconfig via FIFO (`echo fec 19:9 > fifo.file`) — dynamic redundancy
  without restart.
- **Where it sits:** A **transport substrate below the VPN/encryption** — it's a
  loss-masking tunnel that the VPN runs inside. FEC is applied to opaque bytes;
  it doesn't care about payload semantics.
- **Strengths:** Proves the FEC-tunnel thesis end-to-end. Excellent, practical
  knob set (timeout-based group flushing, burst-spreading interval, dynamic
  redundancy via FIFO, fine-grained ratio curve). Decouples loss recovery from
  RTT entirely — recovers within one group, **zero retransmit round-trips**.
- **Weaknesses:** Reed-Solomon is **fixed-rate and block-bounded** (≤255
  symbols, must pick x:y ahead of time; the fine-grained table is a manual
  workaround). RS encode/decode is O(n·k) matrix work — CPU-heavy at high rates.
  C++/libev, not embeddable in Rust. XOR "encryption" is not real security.
  Wastes bandwidth when the link is actually clean (fixed redundancy).
- **Could be done better / fit to goals:** This is the closest analog to what we
  want, but **RaptorQ replaces RS** for us: rateless (generate as many repair
  symbols as needed without re-picking k:r), near-linear coding cost, no 255
  cap, and graceful adaptivity. We should keep UDPspeeder's *operational*
  ideas: timeout-bounded coding groups, burst-spreading over an interval,
  closed-loop adaptive redundancy driven by measured loss, runtime tunability.
- **Reusable for us:** The whole FEC-tunnel control loop. Specifically: per-group
  `seq`, group-flush-on-timeout-or-full, anti-burst packet scattering,
  loss-rate feedback → redundancy adjustment, and the mode-0/mode-1
  (shard-padding vs whole-packet) distinction.

---

## udpfrag (`/refrences/udpfrag`)

- **What it does:** A small Go library that splits messages larger than MTU into
  UDP fragments and reassembles them, with a `net.Conn`-like client helper.
  **Size-limit solver only — adds no reliability.**
- **Language / license:** Go, MIT.
- **Mechanism:** 10-byte fragment header (`FragmentHeader`: `MessageID u32`,
  `FragmentNumber u16`, `TotalFragments u16`, flags), big-endian, prepended to
  each fragment. Default payload `1400−10`. Reassembler keys on `MessageID`
  (random per message), uses **sharded maps** (`MessageID % numShards`) to
  reduce lock contention, `sync.Pool` buffer reuse, and a
  `ReassemblyTimeout`/`CleanupInterval` GC for incomplete messages.
- **Latency / throughput & knobs:** `MaxFragmentSize`, `ReassemblyTimeout` (5 s),
  `CleanupInterval` (10 s). No congestion/loss handling — if any fragment of a
  message is lost, the **entire message is dropped** after timeout.
- **Where it sits:** Thin layer just above UDP; below any reliability/crypto.
- **Strengths:** Clean, minimal, well-documented header format. Sharded-map +
  pool design is a good concurrency pattern. README is honest about its
  limitations.
- **Weaknesses:** No FEC, no ARQ, no ordering between messages — fragment loss =
  whole-message loss, which is *worse* than not fragmenting on a lossy link.
- **Could be done better / fit to goals:** For our use, app-level fragmentation
  should be **avoided where possible** (echoing NORP's principle — discover MTU
  and size records to fit). Where fragmentation is unavoidable, it must be
  combined with FEC so a single lost fragment doesn't sink the message. RaptorQ
  naturally subsumes fragmentation: it splits an object into symbols and you
  only need *enough* symbols, so loss of any one is fine.
- **Reusable for us:** The compact frag header layout (MessageID/index/total) and
  the sharded reassembly-buffer concurrency pattern, if/when we frame >MTU
  objects.

---

## udplistener (`/refrences/udplistener`)

- **What it does:** Go package giving UDP a `net.Listener`/`net.Conn`-style API:
  `Accept()` yields a per-remote-peer pseudo-connection; built on `udpfrag` for
  transparent frag/reassembly.
- **Language / license:** Go, MIT.
- **Mechanism:** One `net.UDPConn` + a `readLoop` goroutine. Each packet →
  `udpfrag.ReassembleData`; completed messages are **demultiplexed by source
  address** into a `map[remoteAddr]*UDPpseudoConn`. New address → create
  pseudo-conn + push to `acceptChan`. Each `UDPpseudoConn` has its own buffered
  `incoming` channel and read deadlines (via context). Writes fragment and send
  on the shared socket. Non-blocking channel sends — **drops on overflow**.
- **Latency / throughput & knobs:** `IncomingBufferSize` (1024),
  `AcceptChanSize` (128), OS socket buffers `SO_RCVBUF`/`SO_SNDBUF` (1 MB
  default, with explicit notes about `net.core.rmem_max` limits).
  `SetWriteDeadline` unsupported (single shared socket).
- **Where it sits:** Session-demux layer above UDP; below reliability/crypto.
- **Strengths:** Clean reference for **single-socket / many-virtual-connections**
  demux — exactly the structure a mesh VPN endpoint needs. Sensible OS
  socket-buffer tuning guidance.
- **Weaknesses:** Inherits udpfrag's no-reliability/loss-amplification. Lossy
  drop-on-full channels. No crypto, no NAT keepalive, addr-based identity is
  spoofable.
- **Could be done better / fit to goals:** Identity should be **cryptographic**
  (peer pubkey), not source-address — addresses change under NAT rebinding and
  are forgeable. Otherwise the demux model is sound.
- **Reusable for us:** The per-peer pseudo-conn map + accept-channel pattern, the
  read-deadline-via-context approach, and the OS-buffer sizing advice.

---

## tcp-in-udp (`/refrences/tcp-in-udp`)

- **What it does:** An **eBPF/TC program that rewrites packets between TCP and
  UDP wire format on the fly**, so a real TCP flow travels across the network
  encapsulated as UDP (and vice-versa) — to stop middleboxes that mangle/strip
  TCP options (e.g. MPTCP) or to evade TCP-specific handling.
- **Language / license:** C (eBPF), AGPL-3.0-or-later. Based on the
  `draft-cheshire-tcp-over-udp` IETF draft. From the MPTCP project.
- **Mechanism:** No userspace tunnel/socket — pure **TC clsact** hooks
  (`tcp_in_udp_tc.o`, sections `tc`/`tc_l3`). Egress: reorders the TCP header
  fields to fit a UDP header shape (swaps seq/ack-num with urgent-ptr/checksum,
  sets `Length` where TCP's urgent-pointer was, zeroes URG), and **incrementally
  recomputes the checksum** by adjusting only for the protocol-number change
  (the addresses/data/length are invariant). Ingress reverses it. Loaded via
  `tc filter ... bpf object-file ...`. Notes: must disable GSO/GRO (each UDP
  packet carries TCP-header fragments that can't be coalesced); use `SO_MARK`
  and non-ephemeral ports to scope which traffic the program touches.
- **Latency / throughput & knobs:** Effectively zero added latency/overhead — it
  is a header transform in the datapath, not a tunnel (no extra encapsulation
  bytes, no userspace copy). Knobs are `tc` filter matches (ports), MTU/MSS
  (MSS clamping won't apply once it's UDP, so MTU must be managed manually).
- **Where it sits:** Pure L4 wire-format transform, **below everything** — kernel
  datapath. Transparent to the application's TCP stack.
- **Strengths:** Brilliant anti-DPI / anti-middlebox primitive with **no
  per-packet overhead and no userspace involvement**. The incremental-checksum
  trick (derive new checksum from protocol delta) is elegant and cheap.
- **Weaknesses:** Linux-only, root + eBPF/TC toolchain, must wrangle GSO/GRO and
  MTU. Format mapping only works because TCP and UDP headers happen to be
  rearrangeable — it's a narrow trick. AGPL.
- **Could be done better / fit to goals (anti-DPI):** The deeper lesson:
  **transport mimicry can be a stateless header rewrite** rather than a stateful
  tunnel. For our VPN we could present traffic as benign UDP (or even as
  TCP-looking) on the wire while keeping our real framing inside, with minimal
  cost. We don't need eBPF necessarily, but the incremental-checksum and
  field-reshuffle techniques transfer.
- **Reusable for us:** The wire-format-mimicry concept, incremental checksum
  recomputation, and the GSO/GRO/MTU caveats for any packet-rewriting path.

---

## icmptunnel (`/refrences/icmptunnel`)

- **What it does:** Tunnels arbitrary IP traffic inside **ICMP echo (type 8) /
  echo-reply (type 0)** packets, client↔proxy-server, to bypass captive
  portals/firewalls that let ping through but block other traffic.
- **Language / license:** C, MIT.
- **Mechanism:** A `tun0` virtual interface captures the client's IP packets;
  the program stuffs each IP packet into the **data field of an ICMP echo**
  (RFC 792 allows arbitrary echo payload length) via a **raw socket**, sends to
  the proxy. Proxy decapsulates, NATs/masquerades to the real Internet, and
  returns responses inside ICMP echo-replies. Checksum per RFC 1071. Routing
  redirected to `tun0`; server toggles `icmp_echo_ignore_all` and IP forwarding.
- **Latency / throughput & knobs:** Minimal protocol logic — essentially a raw
  encapsulation pipe; throughput limited by single-threaded raw-socket I/O and
  whatever rate-limits the network applies to ICMP. No FEC/ARQ/ordering.
- **Where it sits:** Encapsulation/transport layer below IP routing; a covert
  *carrier* you could run other transports over.
- **Strengths:** Classic, simple, effective covert-channel/fallback transport.
  `tun` + raw-socket pattern is a clean reference. Works where UDP/TCP are
  filtered but ICMP isn't.
- **Weaknesses:** Trivially detectable by modern DPI (large/asymmetric ICMP
  payloads are a red flag), ICMP is heavily rate-limited/blocked on real
  networks, no reliability, root required, IPv4-centric, abandoned.
- **Could be done better / fit to goals (anti-DPI / NAT):** Useful only as a
  **last-resort fallback carrier** in a pluggable-transport set. If used, it
  needs payload obfuscation and realistic ping cadence to avoid trivial
  detection. Not a primary path.
- **Reusable for us:** The `tun`-device + raw-socket encapsulation skeleton, and
  the idea of carrying our framed/encrypted datagrams over an alternate L3/L4
  carrier as a pluggable transport.

---

## etherconn (`/refrences/etherconn`)

- **What it does:** Go library to send/receive **raw Ethernet frames (and
  UDP/IP) without an OS-configured interface** — custom MAC/VLAN, bypassing the
  kernel IP stack. Implements `net.PacketConn` so it drops into existing code.
- **Language / license:** Go, BSD-2-Clause.
- **Mechanism:** A `PacketRelay` bound to a NIC does raw send/recv; pluggable
  engines: **`RawSocketRelay` (AF_PACKET)**, **`XDPRelay` (AF_XDP, includes a
  built-in XDP kernel program)**, and `RawSocketRelayPcap` (libpcap, cross-OS).
  `EtherConn` (per MAC+VLAN+EtherType) sits above the relay; `RUDPConn` (per
  IP+port) crafts/parses UDP+IP headers itself. BPF filters demux ingress.
  `SharedEtherConn`/`SharingRUDPConn` allow many L4 endpoints over one L2
  endpoint.
- **Latency / throughput & knobs:** Built for scale — **bypasses kernel
  socket/fd limits and UDP buffer ceilings**; XDPRelay hits ~1 Mpps (1000 B) on
  a 10 GbE NIC across 8 hyperthreads. Knobs: relay engine choice, BPF filter,
  VLAN stack, multi-queue/multi-core for XDP.
- **Where it sits:** Below the OS IP stack — a raw L2/L3/L4 I/O substrate.
- **Strengths:** Demonstrates **AF_XDP / AF_PACKET as a high-throughput,
  many-endpoint datapath**. The relay/conn/sharing layering is a clean model for
  one NIC serving thousands of logical endpoints (mesh-relevant). `net.PacketConn`
  compatibility is a nice integration story.
- **Weaknesses:** Linux/Windows only, root required, you must supply your own
  routing next-hop and ARP/ND resolution, **no fragmentation/reassembly**, no
  reliability/crypto. Heavy for endpoints that don't need raw-socket scale.
- **Could be done better / fit to goals (performance / p2p):** For most mesh
  nodes a normal UDP socket is fine; AF_XDP matters mainly for high-fan-out
  relay/super-nodes. The pattern to steal is **one raw datapath → many logical
  conns demuxed by a filter**, plus AF_XDP for relay nodes that aggregate many
  peers.
- **Reusable for us (Rust):** Architectural — relay/engine abstraction and the
  shared-L2/many-L4 demux. In Rust we'd reach for `aya`/`libxdp` or `xsk-rs`
  for AF_XDP if we build a high-throughput relay node.

---

## norp (`/refrences/norp`)

- **What it does:** "Not Only a Routeing Protocol" — a generic, identity-based
  **routing and encapsulation protocol**: nodes are identified by Ed25519
  fingerprints, messages are directed at opaque addresses, and records are
  bundled into authenticated/encrypted **containers** carried over many possible
  transports.
- **Language / license:** Rust (workspace: `norp`, `norp-proto`, `norp-types`),
  no LICENSE file present in clone (authors from nyantec; treat as
  source-available). Uses `#![feature(...)]` → **nightly Rust**. Crypto via
  ed25519-dalek-fiat / x25519-dalek-fiat.
- **Mechanism:** Layered, spec-driven design:
  - **Records** = atomic comms units; **Containers** = bundles of records sent
    per packet. Container has a version + a 2-bit **coverage** field controlling
    how much lower-layer context (L4 / L3 / EUI-48 pseudo-headers) the
    authenticator covers — coverage 0 survives NAT/PAT, coverage 2 is the
    routed-network default. This is a thoughtful answer to "authenticate the
    transport binding without breaking NAT."
  - **Crypto suite (fixed, no agility):** SipHash-2-4, Blake2b, Ed25519, X25519,
    ChaCha20 / ChaCha20-Poly1305, AES-CFB. Forward secrecy via rotating
    ephemeral/address keys. Non-interactive key exchange (address keys derived by
    originator). Explicitly weighs post-quantum (CSIDH/SQIsign/Hawk) and rejects
    them mainly because **their key/sig sizes would force packet fragmentation**,
    violating a core design rule.
  - **Semantics:** at-most-once delivery of **unordered** messages; reliability/
    ordering is explicitly **punted to the application or to the transport**
    (run TCP/QUIC/SCTP on top if you need it).
  - **No app-level fragmentation:** discover MTU, size records to fit (≤1024 B
    rule of thumb for internal records).
  - **Transports:** pluggable — UDP/UDP-Lite (preferred for routed L3, the main
    mode), raw IP proto 253 (closed nets), SCTP (lossy nets needing hop-by-hop
    retransmit), QUIC (DATAGRAM frames + TLS 1.3 + ECH for hop-by-hop security),
    TCP (discouraged, HOL blocking). QoS of record data is exposed to the
    transport; ECN/multicast used where available.
- **Latency / throughput & knobs:** Not a perf project per se; design optimizes
  for **avoiding fragmentation** and **localized routing** (no node needs a
  global view). Tunables are conceptual: coverage level, transport choice,
  record/container packing strategy (combine records of similar QoS).
- **Where it sits:** Sits **above the transport, integrating encryption** —
  it *is* the encrypted-routing layer; transports (UDP/QUIC/…) sit below it,
  applications above.
- **Strengths:** Mature, carefully-reasoned **architecture** for an
  identity-routed encrypted mesh — exactly our problem domain. The
  coverage/pseudo-header authentication model, the container/record framing, the
  fixed-suite crypto, the "size to MTU, never fragment" principle, and the
  pluggable-transport abstraction are all directly relevant.
- **Weaknesses:** Spec-heavy, nightly Rust, no FEC/loss-resilience story (it
  punts reliability entirely to transport/app), licensing unclear in our clone,
  appears low-activity. No latency/throughput engineering.
- **Could be done better / fit to goals (p2p / anti-DPI):** NORP gives us the
  *control-plane and framing* blueprint but **leaves the lossy-link problem
  unsolved** — which is precisely where our RaptorQ-FEC transport slots in
  *underneath* NORP-style containers. The QUIC-DATAGRAM + ECH transport idea is
  a strong anti-DPI direction.
- **Reusable for us:** Identity = pubkey fingerprint; container/record framing;
  the 2-bit coverage idea for NAT-friendly authentication; fixed crypto suite;
  no-fragmentation discipline; pluggable-transport trait. Borrow heavily for our
  control plane and encryption framing.

---

## nyxpsi (`/refrences/nyxpsi`) — ABANDONED

- **What it does:** *Claimed* to be a next-gen resilient transport for extreme
  packet loss using FEC. **In reality it's an abandoned proof-of-concept:** two
  binaries (client/server) that RaptorQ-encode a single 1300-byte random buffer
  and ping-pong it over **UDP-Lite**, plus a benchmark.
- **Language / license:** Rust, MPL-2.0. Deps: `raptorq = 2.0`, `tokio`,
  `udplite`, `rand`. (Note: this is the **same `raptorq` crate we plan to use.**)
- **Mechanism (what's actually there):** Client builds a RaptorQ `Encoder`
  (`ObjectTransmissionInformation::with_defaults(DATA_SIZE, symbol_size)`),
  generates N encoded packets, sends them, waits for a `"Meow:<symbol_size>"`
  ack ("pong"), then crudely AIMDs the packet count (−1 after 2 successes, +2
  after a failure) and recomputes a `symbol_size` from a hand-rolled
  "network quality" score (EWMA loss + normalized latency). Server makes a
  `Decoder`, feeds packets until `decode()` returns `Some`, replies pong.
- **Why it failed / is broken:**
  - **No object/sequence framing:** the server infers `symbol_size` from the
    *received datagram length* (`packet_symbol_size = size as u16`) and rebuilds
    the decoder whenever it changes — fragile and wrong in general; there's no
    message id, no notion of multiple concurrent objects, no stream.
  - **Latency "measurement" is meaningless:** server measures
    `start_time.elapsed()` *around its own `recv_from`*, not an actual RTT.
  - **Strictly stop-and-wait, one object at a time** — no pipelining, no real
    throughput path; the "benchmark" transfers 1 MB as repeated single-object
    pingpongs.
  - **The headline benchmark table is misleading:** nyxpsi shows constant 1.07 s
    at 0/10/50% loss "100% success" while UDP shows 0% success — but that's
    because nyxpsi just keeps sending repair symbols until it gets through on a
    loopback, and the comparison harness for TCP/UDP reports 0% by construction.
    It demonstrates *that RaptorQ recovers from erasures* (true) but proves
    nothing about latency or throughput.
  - **UDP-Lite with `checksum_coverage(8)`** (cover only the 8-byte header) is an
    interesting choice — lets corrupted-but-delivered payloads reach the FEC
    decoder instead of being dropped by the kernel — but UDP-Lite is widely
    dropped by middleboxes/NAT, undermining real-world use.
- **What's salvageable:** Honestly, **very little code**, but a few concrete
  takeaways: (1) a **working minimal example of the `raptorq` 2.0 API** we'll
  use — `Encoder::new` + `get_encoded_packets(n)`, `Decoder::new(oti)` +
  `decode()`, `EncodingPacket::serialize/deserialize`, and the
  `ObjectTransmissionInformation` (OTI: object size + symbol size) that **must be
  shared/derivable on both ends**; (2) the *idea* of adapting redundancy and
  symbol size to a measured loss/latency estimate (the execution is bad, the
  instinct is right); (3) UDP-Lite + partial checksum coverage as a way to hand
  corrupt payloads to FEC. Everything else (framing, RTT, pipelining, congestion)
  has to be designed properly from scratch.
- **Lesson for us:** RaptorQ-over-UDP is the right core, but **the hard parts
  nyxpsi skipped are the actual product**: object/symbol framing with explicit
  OTI signaling, multiplexing many concurrent objects/streams, real RTT and loss
  estimation, congestion control, and a pipelined send path. Treat nyxpsi as a
  "what not to do" plus a 30-line RaptorQ cheat-sheet.

---

## Cross-cutting synthesis for our design

**ARQ vs FEC.** KCP/kcp2k (ARQ) recover losses by retransmitting after detecting
a gap — cost is **≥1 RTT per loss event**, which is fatal for interactive,
high-RTT, lossy links (our target). UDPspeeder/nyxpsi (FEC) recover **within the
coding group, zero round-trips**, at the cost of constant redundant bandwidth.
For a low-latency lossy-link VPN, **FEC should be primary** for tunneled data,
with a *thin* ARQ-style mechanism only for control or for the rare residual
losses FEC can't cover (hybrid). Adopt KCP's tunable philosophy (nodelay,
no-congestion-window option) and UDPspeeder's operational loop (timeout-bounded
groups, burst-spreading, adaptive redundancy from measured loss).

**RaptorQ vs Reed-Solomon.** RS (UDPspeeder) is **block-bounded (≤255 symbols)
and fixed-rate** — you must choose k:r in advance and re-pick it to adapt, and
decode is O(n·k) matrix algebra. RaptorQ (RFC 6330, the `raptorq` crate) is a
**rateless fountain code**: from k source symbols you can mint *practically
unlimited* distinct repair symbols on demand, the receiver decodes after
receiving any ~k(1+ε) symbols (ε≈0–2 symbols overhead), and encode/decode are
**near-linear** time. This means redundancy can be tuned continuously to live
loss without re-parameterizing, there's no 255-symbol ceiling, and large objects
code cheaply — strictly better for adaptive, lossy, low-latency operation.
Trade-off: per-symbol RaptorQ overhead and the need to **signal/derive OTI
(object & symbol size) on both ends** (the framing nyxpsi got wrong).

**Encapsulation / anti-DPI / NAT tricks.** *tcp-in-udp* shows mimicry as a
**stateless, zero-overhead header rewrite** (with the incremental-checksum trick)
— make our wire bytes look like benign UDP/TCP. *icmptunnel* is a covert
**fallback carrier** (IP-over-ICMP) — only useful as a low-priority pluggable
transport, easily detected/rate-limited. *etherconn* shows **AF_XDP/AF_PACKET**
raw datapaths for high-fan-out relay nodes (one NIC → thousands of demuxed
conns). NORP contributes the **2-bit coverage** idea (authenticate the transport
binding loosely enough to survive NAT) and a **pluggable-transport** abstraction
(UDP/QUIC-DATAGRAM+ECH/SCTP). Net: design transport as a pluggable trait, default
to UDP with optional mimicry, keep raw-socket/AF_XDP for relays, treat ICMP as a
break-glass fallback.

**Reusable Rust components shortlist.** `kcp` crate (control-channel reliability,
RTT/RTO + fast-retransmit ideas); kcp2k's session model (cookie handshake,
channel byte, MTU headroom, keepalive, single-socket demux); UDPspeeder's FEC
control loop (group flush-on-timeout, anti-burst scattering, adaptive redundancy);
udpfrag/udplistener demux + reassembly patterns (per-peer pseudo-conn,
sharded buffers) — but key peers by **pubkey, not address**; NORP's container/
record framing, coverage-based auth, fixed crypto suite, and no-fragmentation
discipline; `raptorq` 2.0 as the FEC core (per nyxpsi's API cheat-sheet, done
properly with explicit OTI framing and multiplexing).
