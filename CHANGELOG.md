# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- **Data Plane Driver Matrix & Multi-Shard Workload Benchmark (`crates/yip-bench`, `crates/yip-io`, `bin/yipd`, #279).**
  - Added `crates/yip-bench/tests/run-driver-matrix.sh` systematically benchmarking and comparing `epoll`, `io_uring`, and `AF_XDP` drivers across 1, 2, 4, and `auto` shard configurations.
  - Implemented `IoUring::builder().setup_sqpoll(...)` submission queue polling in `UringDriver` (opt-in via `YIP_URING_SQPOLL=1`) to eliminate syscall context switching during high-rate I/O.
  - Added `--driver <epoll|uring|xdp>` CLI flag and `driver = "epoll" | "uring" | "xdp"` config file support in `yipd`, allowing seamless data plane engine selection.
  - Added CLI flag `--shards <N|auto>` in `yipd` to dynamically override configured worker shard count.
  - Added automated pass/fail assertion gating for TCP retransmit loss (`tcp_max_loss`) and UDP packet loss (`udp_max_loss`) across loss tiers in `run-iperf-compare.sh`, alongside clean-link 0% packet loss regression assertions.
- **Nebula Contender & Full 10-Contender SCP Transfer Suite (`crates/yip-bench`, #289).**
  - Added Slack's Nebula (`nebula` and `nebula-cert` v1.12.0) to `crates/yip-bench/setup-contenders.sh` (`setup_nebula()`, `--nebula`, `--all`, and `--check`).
  - Created `crates/yip-bench/tests/contenders-lib.sh` unifying network topologies, process cleanup, netem delay/loss injection, and lifecycle dispatchers (`start_contender`, `stop_contender`, `get_contender_info`, `verify_isolation`) across all 10 contenders: `yip`, `wireguard`, `wireguard-go`, `amneziawg`, `openvpn`, `n2n`, `zerotier`, `tailscale`, `netbird`, and `nebula`.
  - Refactored `crates/yip-bench/tests/run-iperf-compare.sh` to source `contenders-lib.sh`, eliminating redundant lifecycle script duplication and adding Nebula to the throughput, ping, CPU, memory telemetry sweeps, tables, and JSON export.
  - Refactored `crates/yip-bench/tests/run-scp-compare.sh` to source `contenders-lib.sh` and expanded the benchmark from 3 hardcoded contenders to the full 10-contender suite across `FILE_SIZES_MB` and `LOSS_RATES`.
  - Demonstrated that under 5% netem packet loss, Yip maintains 19.97 MB/s SCP file transfer goodput (>93% of its clean-link speed), outperforming all 9 competing overlay technologies (0.34 - 0.53 MB/s, 40x to 58x slower), including WireGuard (0.38 MB/s, ~52x slower) and Nebula (0.36 MB/s, ~55x slower), with byte-for-byte integrity verified via cmp.
  - Documented Nebula architecture and benchmark findings in `crates/yip-bench/README.md` and `crates/yip-bench/RESULTS.md`.
- **CI Benchmarks Workflow Matrix & SCP Transfer Suite (`crates/yip-bench`, `.github/workflows/benchmarks.yml`, #280).**
  - Upgraded `crates/yip-bench/tests/run-scp-compare.sh` to support configurable payload sizes (`FILE_SIZES_MB`, default: 100MB), OpenVPN contender support alongside Yip and WireGuard, and JSON telemetry export (`OUTPUT_JSON`).
  - Added structured JSON telemetry export to `crates/yip-bench/tests/run-iperf-compare.sh` (`OUTPUT_JSON`), capturing complete per-contender per-loss throughput, packet loss, RTT, CPU efficiency, and memory footprint metrics.
  - Expanded `.github/workflows/benchmarks.yml` with a new `scp-netem-bench` job measuring real-world OpenSSH file transfers across packet loss conditions with artifact upload and GitHub step summaries.
  - Parameterized `iperf-netem-bench` with a concurrent matrix strategy supporting single-stream (`streams=1`, `shards=1`), multi-stream concurrency (`-P 4`, `-P 8`), and multi-shard auto scaling (`shards=auto`).
- **Lazy Contender Lifecycle, Process Isolation & CI Threshold Assertions (`crates/yip-bench`, #281).**
  - Implemented lazy contender lifecycle (`start_contender`, `stop_contender`) in `crates/yip-bench/tests/run-iperf-compare.sh`, starting each tunnel daemon on demand and tearing down its processes and network namespaces upon test completion.
  - Enabled `CONTENDER_ISOLATION=true` by default, running contenders sequentially through all loss tiers and verifying complete process cleanup (`verify_isolation`) to eliminate multi-daemon memory (e.g. WireGuard-Go 1.8GB, AmneziaWG 1.8GB) and CPU scheduling contention.
  - Added configurable performance threshold assertions (opt-in via `ASSERT_THRESHOLDS=true`) with environment variable overrides (`THRESH_YIP_TCP_MIN_MBPS_0`, `THRESH_YIP_TCP_MIN_MBPS_5`, `THRESH_YIP_PING_MAX_LOSS_5`, `THRESH_YIP_TCP_MIN_MBPS_10`) for automated regression testing.
- **ICMP Realtime Classification & BDP-Resilient Reorder Buffering (`crates/yip-transport`, #286).**
  - Classified ICMP (IPv4 `proto == 1`) and ICMPv6 (IPv6 `proto == 58`) packets into `FlowClass::Realtime` in `crates/yip-transport/src/classify.rs`, applying proactive single-packet FEC parity (`initial_repair_ratio = 0.15`, `R = 1` for `K = 1`) without reactive ARQ overhead, eliminating ping packet loss under netem channel loss (effective ping loss dropped from 12-24% to 0.0%).
  - Fast-initialized TCP flow EWMA size upon observing large data segments (`size > LARGE_BYTES && key.proto == 6`) following small handshake packets (`stat.packets <= 3 && stat.ewma_size < 150.0`) in `crates/yip-transport/src/flow.rs`, completely eliminating handshake EWMA dampening so that initial slow-start segments immediately receive `FlowClass::Bulk` ARQ retransmission and FEC protection.
  - Added an explicit severe loss tier (`effective_loss >= 0.50 => target = 0.50`) in `AdaptiveController::observe_loss` in `crates/yip-transport/src/control.rs`, allowing the controller to dynamically reach the documented severe-loss singleton packet replication threshold under catastrophic channel loss.
  - Enforced immediate `FlowClass::Bulk` classification on the first large TCP segment (`ewma_size > LARGE_BYTES && key.proto == 6`) in `crates/yip-transport/src/flow.rs`, eliminating the 4-packet rate-warmup delay for bulk TCP transfers so that the initial packets of TCP slow start are immediately protected by ARQ buffering and proactive FEC parity.
  - Expanded `ReorderBuffer` capacity per flow from 64 to 128 slots (`MAX_FLOW_REORDER_SLOTS = 128`) and extended the default micro-reorder eviction deadline from 10 ms to 25 ms (`DEFAULT_REORDER_DEADLINE_MS = 25`) in `crates/yip-transport/src/reorder.rs`, preventing premature sequence hole flushes and TCP CWND collapse on high-BDP paths when ARQ retransmissions take >= 10 ms round-trip to arrive.
  - Stabilized single-stream TCP goodput under 5% netem loss across IPv4 and IPv6 to 880 - 1,200 Mbit/s, and increased 10% netem loss IPv4 TCP goodput from 112.7 Mbit/s to 490.6 Mbit/s (a 4.3x throughput improvement).
- **Default Flow FEC Initial Repair Ratio Calibration (`crates/yip-transport`, #285).**
  - Calibrated `FlowClass::Default` initial proactive repair ratio from 0.10 to 0.0 (`initial_repair_ratio = 0.0`), preventing 100% warm-up packet duplication overhead on clean links.
  - Guarded `AdaptiveController::repair_count` against emitting repair shards for singleton K=1 objects on non-ARQ zero-floor flow classes (`FlowClass::Default`) when `min_ratio <= EPSILON` unless loss is severe (`ratio >= 0.50`), preventing 100% packet rate amplification and socket queue exhaustion on high-throughput UDP streams while preserving proactive parity on ARQ flows (`FlowClass::Bulk`).
- **Dataplane Throughput, ARQ Feedback Acceleration & Clean Parity Decay (`bin/yipd`, `crates/yip-transport`, #276).**
  - Accelerated ARQ loss feedback by emitting immediate gap-triggered `ControlFrame::Feedback` packets rate-limited by `MIN_GAP_FEEDBACK_INTERVAL_MS = 5ms` via combined TUN write and UDP send outcomes (`Outcome::TunWriteThenSend` and `Outcome::TunWriteBatchThenSend`), bypassing the 30ms periodic tick timer when expired pending packet gaps are detected on `FlowClass::Bulk` flows.
  - Preserved configured MTU symbol sizing (1450 bytes) across initial peer endpoint binding in `DataPlane::set_peer_addr`, preventing baseline symbol floor resets and eliminating multi-symbol fragmentation on standard MTU payloads.
  - Allowed adaptive FEC parity on `FlowClass::Default` flows to decay down to 0.0 on clean links (`set_min_ratio(0.0)`), eliminating unneeded proactive parity amplification on high-throughput transfers while preserving dynamic scaling when loss is detected.
  - Resolved multi-shard control packet misrouting in `bin/yipd/src/sharding.rs` by eliminating pseudo-random cross-shard forwarding of in-band control frames, allowing incoming PLPMTU probe confirmations and ARQ loss reports to be processed directly on the receiving shard.
  - Updated branding asset by replacing `assets/yip.gif` with high-resolution transparent `assets/yip.png` and updating `README.md`.
- **UDP Burst Loss Recovery & Vectorized GSO Hotpath Optimization (`crates/yip-transport`, `crates/yip-io`).**
  - Allowed coalescing zero-fate (`fate: 0`) independent datagrams in `crates/yip-io/src/gso.rs` (`can_coalesce` and `partition_fate_safe`), fixing a collision bug where `0 == 0` caused default non-FEC traffic to reject GSO run batching and shatter into per-packet syscalls.
  - Reserved FEC `object_id == 0` in `crates/yip-transport/src/fec.rs` (`FecEncoder`), guaranteeing that `fate == 0` is uniquely reserved for unconstrained datagrams and preventing multi-symbol FEC blocks from coalescing into fate-sharing GSO super-skbs.
  - Restricted `FlowClass::Bulk` classification in `crates/yip-transport/src/flow.rs` to TCP flows (`proto == 6`), allowing large UDP datagrams to fall through to `FlowClass::Default` without ARQ retransmission buffers, eliminating feedback amplification storms and socket buffer overflow under multi-gigabit line-rate bursts.
  - Implemented zero-copy scatter-gather `iovec` transmission in `crates/yip-io/src/poll.rs` (`send_gso_indexed`), eliminating intermediate payload copying across datagram bursts.
  - Expanded `partition_fate_safe` bitmask in `crates/yip-io/src/gso.rs` from `u64` to `u128`, guaranteeing zero heap allocations and eliminating O(N) memmoves for full 128-datagram batches.
  - Batched non-GSO singleton datagrams in `crates/yip-io/src/poll.rs` (`flush_tx`, `send_mmsg_indexed`, `send_run_plain_indexed`), coalescing singletons into contiguous vectorized `sendmmsg` syscall bursts instead of dispatching per-packet syscalls.
  - Doubled UDP throughput under line-rate bursts from 1.95 Gbps to 4.51 Gbps on IPv4 and 2.02 Gbps to 4.33 Gbps on IPv6 while reducing CPU utilization from 76% to 36% and UDP loss from 46.6% down to 5.2%-8.9%.
- **Underlay Hardware UDP Generic Segmentation Offload (`crates/yip-io`, #253).**
  - Added socket-level Generic Segmentation Offload (`UDP_SEGMENT` / GSO) detection, configuration, and probing to `BatchUdpSocket` via `getsockopt` / `setsockopt` with `SOL_UDP / UDP_SEGMENT`.
  - Implemented vectorized GSO batch transmission (`send_gso_batch`, `send_gso_burst`, `sendmmsg_or_gso`, `send_gso_datagrams`, `send_gso_datagrams_burst`) coalescing contiguous packets sharing destination endpoints and segment sizes into single `UDP_SEGMENT` super-skbs using control messages (`cmsg`) and scatter-gather `iovec` arrays.
  - Enforced RaptorQ FEC fate group safety: datagrams sharing non-zero `fate` object IDs are never coalesced together into the same super-skb, ensuring FEC recovery under burst loss is preserved.
  - Implemented zero-allocation hotpath execution and transparent fallback: if `UDP_SEGMENT` is unsupported by the host kernel or NIC (`EINVAL`, `ENOPROTOOPT`, `EOPNOTSUPP`, `EIO`), GSO is automatically latched off and transmission falls back seamlessly to standard `sendmmsg`.
  - Re-exported `BatchUdpSocket` in `yip_io::poll`.
- **Cross-Shard Ring Drop Telemetry**: SPSC queue drop metrics are now surfaced in `ControlResponse::Status` (`yip status --json`), displayed conditionally as `Ring Drops` in `yip status`, and exported via Prometheus as `yip_spsc_queue_drops_total` ([#260](https://github.com/femboyisp/yip/issues/260)).
- **Cross-Platform Shared Protocol Crate (`crates/yip-proto`, #199).**
  - Extracted cross-platform, OS-agnostic wire and IPC data structures from `bin/yipd` into a dedicated `crates/yip-proto` workspace crate.
  - Moved `ControlCmd`, `ControlResponse`, `DaemonConfig`, `PeerConfigEntry`, `PeerStats`, `PeerState`, `NetworkTicket`, `FecPreset`, `FecConfig`, `DaitaPreset`, `DaitaConfig`, `SplitMode`, `SplitTunnelConfig`, `XdpMode`, and pure CIDR helpers (`parse_cidr`, `ip_matches_cidr`, `extract_ip_dst`) into `yip-proto`.
  - Extracted self-certifying IPv6 overlay address derivation (`derive_overlay_ipv6`, `node_addr`, `verify_addr`, `OVERLAY_ADDR_CONTEXT_V2`, `MESH_PREFIX_LEN`) without OS or socket dependencies.
  - Enabled cross-platform desktop and mobile client implementations (`yip-client`) to consume the single source of truth for IPC schemas and invitation ticket rendering.
- **Dynamic Daemon Configuration Reload & Active Configuration Inspection (`bin/yipd`, #196).**
  - Added `ControlCmd::Reload` and `ControlCmd::GetConfig` commands over the UNIX domain control socket `/run/yipd/yip.sock`.
  - Added `ControlResponse::Config { config: DaemonConfig }` and `ControlResponse::Reload { ok, message, reloaded }`.
  - Implemented dynamic zero-downtime configuration reload in `PeerManager` (`reload_config`): re-reads the configuration file on disk, updates dynamic endpoints, aliases, and dynamic parameters (Reed-Solomon FEC, DAITA traffic defense, and MTU) without restarting the process or tearing down the TUN interface device, while preserving active cryptographic sessions and epochs for peers with matching public keys.
  - Added CLI subcommands `yip reload [config_path]` and `yip config [get] [--json]` in `bin/yipd/src/main.rs`.
- **Peer Aliases and Ergonomic Control Resolution (`bin/yipd`, #197).**
  - Added optional `alias: Option<String>` to `PeerConfig`, configuration file parser (`alias = "..."` within `[peer]` blocks), `ControlCmd::AddPeer` RPC, and `PeerStats`.
  - Added case-insensitive peer resolution by human-readable alias in `PeerManager` (`find_peer_by_alias`, `peer_pubkey`, and fallback in `find_peer_index_by_id`), allowing CLI commands (`peer remove`, `peer set-transport`, `ping`, `trace`, `crypto`) to accept friendly peer aliases as drop-in alternatives to full 64-hex public keys or IPv6 node addresses.
  - Updated `yipctl peers` and `yipctl top` dashboard displays to render peer aliases alongside node overlay addresses when configured.
- **Network Invitation Tickets and Terminal QR Code Rendering (`bin/yipd`, #198).**
  - Implemented `NetworkTicket` schema in `bin/yipd/src/ticket.rs` compatible with cross-platform desktop/mobile clients (`yip-client`), supporting Base64 serialization, JSON payloads, and `yip://join?ticket={b64}` invitation URIs.
  - Added compact terminal Unicode QR code generation using `qrcode` crate with `Dense1x2` half-block glyph rendering.
  - Added `ControlCmd::CreateTicket` RPC command and responses (`ControlResponse::Ticket`) over the UNIX domain control socket `/run/yipd/yip.sock`.
  - Added CLI subcommands `yip ticket create [--name <NAME>] [--route-mode <MODE>] [--endpoint <ADDR>] [--no-qr] [--json]` and `yip ticket show <TICKET_OR_URI> [--no-qr] [--json]`.
- **Control Socket Status RPC Metadata Exposure (`bin/yipd`, #194).**
  - Exposed local node public key (`public_key`), active UDP listen port (`listen_port`), and mesh network ID (`network_id`) in `ControlResponse::Status`.
  - Added CLI status printout formatting and JSON serialization for node public keys, listen ports, and network IDs, enabling unprivileged desktop clients and orchestration tools to query local node identity without reading secret configuration files.
- **TCP Line-Rate Throughput Scaling & Hot-Path Allocation Elimination (`bin/yipd`, `crates/yip-io`, `crates/yip-transport`).**
  - Added zero-allocation `sendmmsg_datagrams` and `sendmmsg_datagrams_burst` to `BatchUdpSocket` in `crates/yip-io`, mapping `EgressDatagram` buffers and socket addresses directly into stack arrays without allocating intermediate `Vec<(&[u8], SocketAddr)>` tuples.
  - Enabled kernel `UDP_GRO` socket option (`SOL_UDP`, `UDP_GRO`) on underlay UDP sockets across `yip-io`, `port.rs`, and `sharding.rs` with graceful fallback on unsupported kernels, aggregating incoming contiguous UDP packets into superpackets and reducing socket layer syscall overhead.
  - Quadrupled `ReorderBuffer` per-flow capacity from 16 to 64 slots (`MAX_FLOW_REORDER_SLOTS = 64`) in `crates/yip-transport/src/reorder.rs`, absorbing multi-queue out-of-order burstiness and network jitter without triggering premature slot flushes or spurious TCP 3-duplicate-ACK fast retransmits.
  - Completely eliminated ingress heap allocations in `sharding.rs` by removing `owned_out` (which previously cloned every packet into a heap `Vec<u8>`) and piping `DispatchOut` slices directly to TUN coalescing and batch egress.
  - Wired `AckCompressor` and batched egress buffers (`egress_batch`) into worker shard TUN read and SPSC drain loops in `bin/yipd/src/sharding.rs`, compressing redundant cumulative TCP ACKs on the return path and batching forward datagram transmissions in bursts of up to 32 packets per `sendmmsg` syscall.
- **AF_XDP (XSK) Zero-Copy Kernel Bypass Pipeline for Underlay UDP (`crates/yip-io`, `bin/yipd`, #202).**
  - Implemented native AF_XDP socket abstraction (`XskSocket`) and UMEM memory pool (`UmemPool`, `UmemSlab`) in `crates/yip-io` with lock-free Fill, Completion, RX, and TX ring buffers.
  - Added transparent 3-tier fallback architecture: Native Driver Zero-Copy (`XDP_ZERO_COPY` / `XskBindMode::ZeroCopy`) -> Generic SKB Copy (`XDP_COPY` / `XskBindMode::Copy`) -> POSIX `BatchUdpSocket` (`recvmmsg`/`sendmmsg`), allowing unprivileged execution or systems without driver XDP support to gracefully fall back without service interruption.
  - Implemented multi-queue XSK steering and eBPF XDP filter attachment (`attach_bpf_filter_multi_queue_with_flags`) in `crates/yip-io/src/bpf.rs` using BPF `XSKMAP`, steering incoming tunnel UDP port traffic directly to per-queue worker thread UMEM rings and bypassing kernel `sk_buff` allocations, netfilter, and conntrack overhead.
  - Integrated AF_XDP ingress event handling into the single-reactor epoll event loop (`run_poll`) via `Dispatch::xsk_fd` and `Dispatch::on_xsk` hooks, processing packets without extra thread hops or synchronization contention.
  - Wired `--xdp`, `--no-xdp`, `--xdp-ifname <IFNAME>`, and `--xdp-mode <auto|generic|native|offload>` daemon configuration flags and CLI overrides in `bin/yipd`. Automatically detects the default gateway interface if no interface is explicitly specified.
- **Phase 2: Multi-Queue Underlay Dispatch, Socket Buffer Expansion & Lock-Free Sharding (`crates/yip-io`, `bin/yipd`, #205, #240, #241).**
  - Expanded socket buffer sizing via privileged `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE` with graceful fallback to standard `SO_RCVBUF` / `SO_SNDBUF` up to 16 MiB, eliminating socket drop bottlenecks during high-throughput bursts.
  - Quadrupled ARQ retention horizon in `DataPlane` (`SENT_LOG_CAPACITY` and `RETX_BUFFER_MAX` to 65,536 entries), ensuring NACKs within the retransmission feedback loop locate packets without eviction.
  - Integrated `Coalescer` into worker shards for vectorized GSO write batching on TUN queues, reducing write syscall frequency by 3-4x.
  - Streamlined direct worker core affinity for multi-queue TUN devices (`IFF_MULTI_QUEUE`), removing redundant cross-shard SPSC copying and steady-state heap allocations on TUN reads.
  - Resolved return traffic routing on multi-queue UDP sockets by preserving `config.listen` socket binding on shards and keeping the egress pool strictly opt-in under `YIP_EGRESS_POOL`.
  - Fixed intermediate segment PSH flag handling in `split_gro` (`crates/yip-io`), allowing receiver-side `Coalescer` to reassemble 64 KB GSO superpackets on TUN write and doubling clean single-flow TCP goodput from 1.18 Gbps to 2.36 Gbps.
- **Reverse TCP ACK Coalescing & Redundant Cumulative ACK Compression (`crates/yip-io`, #235).**
  Implemented zero-allocation `AckCompressor` in `crates/yip-io/src/ack_coalesce.rs` connected directly to `drain_tun` in `crates/yip-io/src/poll.rs`. Coalesces same-flow pure cumulative TCP ACKs during TUN drain bursts by retaining the highest cumulative acknowledgment number (`seq_after(new_ack, old_ack)`) with matching window size and no SACK blocks. Strictly preserves duplicate ACKs (`new_ack == old_ack`) to ensure TCP Fast Retransmit (3-dupACK) signaling is never suppressed, and immediately flushes buffered ACKs upon receiving SACK blocks, window updates, or data packets. Slashes reverse-path encryption, AEAD framing, and syscall overhead by up to 70-80% during unidirectional saturated TCP transfers.
- **Loss-Aware Bulk Proactive FEC & RTT-Adaptive Reorder Deadline (`bin/yipd`, `crates/yip-transport`, #236).**
  Wired overall underlay channel loss observation into `FlowClass::Bulk` in `bin/yipd/src/dataplane.rs`, eliminating the cold-start FEC penalty where Bulk flows began with 0 proactive repair symbols under loss. Scaled the default `ReorderBuffer` micro-deadline from 2 ms to 10 ms (`DEFAULT_REORDER_DEADLINE_MS = 10`) in `crates/yip-transport/src/reorder.rs`, holding sequence gaps until ARQ retransmissions or proactive repair symbols arrive and preventing premature sequence hole flushes to the host kernel TCP stack. Increased 10% packet loss single-stream TCP goodput from 1-30 Mbit/s to 240-306 Mbit/s (a 10x-30x throughput improvement) with 0-4% effective TCP loss.
- **In-Order Ingress Micro-Reorder Buffering (`crates/yip-transport`, `bin/yipd`, `crates/yip-io`, #234).**
  Implemented a flow-aware zero-allocation ingress micro-reorder buffer (`ReorderBuffer`) in `crates/yip-transport/src/reorder.rs` with pre-allocated slot ring (`MAX_FLOW_REORDER_SLOTS = 16`, `MAX_CONCURRENT_TRACKED_FLOWS = 64`) and ~2.0 ms micro-deadline timer eviction. Bypasses non-TCP traffic (UDP, ICMP, ARP) and TCP control frames (SYN, RST, pure ACKs) without latency, while buffering out-of-order TCP segments under channel packet loss. Emits contiguous runs in sequence (`Outcome::TunWriteBatch` / `DispatchOut::TunBatch`), preventing premature TCP 3-duplicate-ACK fast retransmits and maintaining high TCP goodput under loss.
- **Benchmark Fairness, High-BDP Sysctls, and TCP Stack Parameterization (`crates/yip-bench`, #237).**
  Configured `limit 50000` on `apply_netem` in `run-iperf-compare.sh`, eliminating queue buffer overflows on 10 Gbps delayed paths. Applied uniform `txqueuelen 10000` across all contender interfaces (`wg0`, `wggo0`, `awg0`, `tailscale0`, `tun0`, `wt0`, `yip0`), parameterized `TCP_CC="${TCP_CC:-cubic}"` and `IPERF_STREAMS="${IPERF_STREAMS:-1}"`, and tuned high-BDP socket buffers (`rmem_max=67108864`, `wmem_max=67108864`, `tcp_rmem`, `tcp_wmem`) and `tcp_reordering=20` across test namespaces.
- **WireGuard-Go Userspace Contender Integration & CI Provisioning (`crates/yip-bench`, `.github/workflows/benchmarks.yml`, #221).**
  Added automated installation and evaluation of userspace Go WireGuard (`wireguard-go`) in `setup-contenders.sh` (`--wireguard-go`) and `run-iperf-compare.sh`. Measures dual-stack IPv4/IPv6 throughput, loss, latency, CPU utilization, and peak resident memory (`get_ns_ram_mb`), enabling direct userspace-to-userspace comparisons against YIP. Added Go module build caching in `benchmarks.yml` to accelerate CI benchmarking runs.

### Performance
- **IPv6 Multi-Shard Resident Memory Footprint Optimization (`crates/yip-transport`, `bin/yipd`, #255).**
  - Decoupled `FecReassembler` in-flight reassembly tracking (256 objects per class for robust high-throughput ARQ recovery under loss) from idle buffer retention by capping recycled payload and repair pools (`MAX_POOL_BUFFERS = 16`), reducing idle pooled reassembly memory across 8 worker shards down to ~24 MB.
  - Sized `FlowTable` in `Classifier::new` to 1,024 entries with 10s TTL and bypassed heuristic flow tracking for non-TCP/UDP control and multicast protocols (ICMPv4, ICMPv6, IGMP, `ff00::/8`), eliminating background discovery table bloat.
  - Resolved queue-head starvation in `FlowTable::evict_expired` by rotating active flows to the back of the queue, allowing stale entries queued behind them to be evicted cleanly.
  - Bounded and reclaimed `DataPlane` drained scratch vectors (`tun_drained`, `tick_tun_drained` capped to 32 elements) and oversized scratch buffers during periodic `tick` idle sweeps in `bin/yipd/src/dataplane.rs`.
- **Line-Rate UDP Burst Loss Elimination & Socket Queue Hardening (`crates/yip-device`, `crates/yip-io`, `bin/yipd`, #254).**
  - Raised default UDP socket buffer allocations to 32 MiB (`DEFAULT_SOCKET_BUFFER_BYTES = 32 * 1024 * 1024`) via privileged `SO_RCVBUFFORCE` and `SO_SNDBUFFORCE` (with automatic fallback to unprivileged `SO_RCVBUF` / `SO_SNDBUF`) across daemon underlay and worker sockets, preventing kernel buffer exhaustion during multi-gigabit line-rate bursts.
  - Configured 10,000 `txqueuelen` via `SIOCSIFTXQLEN` ioctl during TUN/TAP device creation in `crates/yip-device` (`TunTap::create` and `TunTap::create_multi_queue`), eliminating interface transmit queue drops when kernel network stacks blast high-rate UDP microbursts into the overlay.
  - Expanded worker event-loop `recvmmsg` polling bursts from 32 to 64 datagrams per syscall and doubled `MmsgBatchArena` pre-allocated header storage capacity to 128 datagrams (`MAX_DATAGRAM_BATCH = 128`), cutting syscall overhead by half during burst drainage.
  - Expanded cross-shard SPSC ring buffer depth from 2,048 to 8,192 slots and implemented a continuous multi-batch draining loop (harvesting up to 512 datagrams per event loop iteration) with drop telemetry (`SPSC_QUEUE_DROPS`), absorbing transient packet surges without packet loss across worker shards.

### Fixed
- **IPv6 TCP Throughput Collapse Under Packet Loss & RFC 8200 Sub-1220 MSS Collapse (`crates/yip-transport`, `bin/yipd`, #272, #273).**
  - Implemented dynamic TCP MSS clamping tied to active PLPMTU tiers (`PmtuManager::update_confirmed_symbol_size`, `max_mss_for_packet`) enforcing `K = 1` single FEC symbol packaging across tiers (`tier_mtu = confirmed_symbol_size - 28`).
  - Enforced RFC 8200 minimum IPv6 floor (1280 MTU / 1220 MSS) preventing the Linux kernel TCP stack from collapsing congestion windows when MTU drops below 1280.
  - Added stateless pure TCP ACK classification (`classify.rs`) matching ACK-only frames (`payload_len == 0`, `SYN`/`FIN`/`RST` cleared, options-aware `data_offset >= 20`) mapped to `FlowClass::Ack`.
  - Configured 0-RTT proactive FEC delivery (30% repair ratio floor) without reactive ARQ retransmission for `FlowClass::Ack`, eliminating latency degradation from stale cumulative ACK retransmissions.
  - Implemented RFC 8899 §5.2 periodic PLPMTU re-probe search timer (15s interval) in `PlpmtuController::tick`, unfreezing `Converged` state and recovering path MTU after transient underlay loss.
  - Replaced uniform loss threshold blackhole triggers with RFC 8899 size-differential loss detection in `dataplane.rs` (requiring >= 80% large packet loss and < 30% small packet loss across 2 consecutive intervals with sample count floors), eliminating false blackhole step-downs during uniform netem channel loss.
  - Increased 10% packet loss IPv6 TCP throughput from 3.7 Mbit/s to 153.1 Mbit/s (a 41x throughput recovery) while maintaining 0 hot-path heap allocations.
- **Control Socket Permissions and Unprivileged Access (`bin/yipd`, `contrib/systemd`, #195).**
  - Configured explicit file permissions (`0666` default or configurable via `YIP_CONTROL_SOCKET_MODE`) on the control UNIX domain socket (`/run/yipd/yip.sock`) and parent directory (`0755`), allowing unprivileged desktop users (e.g. `yip-client` or CLI tools) to query daemon status without requiring `sudo`.
  - Added automatic group ownership resolution (`chown`) to group `yip` (or `YIP_CONTROL_SOCKET_GROUP`) when present.
  - Updated `contrib/systemd/yipd.service` with `RuntimeDirectoryMode=0755` for `/run/yipd`.
  - Wired control socket binding and polling on Shard 0 in sharded multi-core mode (`shards > 1`).
- **Multi-Shard Scaling, Monotonic Nonce Skew & RAM Boundedness (`crates/yip-crypto`, `crates/yip-transport`, `bin/yipd`, #251).**
  - Added per-stride replay windows (`Session::replays`) in `crates/yip-crypto/src/session.rs` indexed by `counter % stride`, eliminating spurious replay drops on idle or slower worker shards when concurrent high-throughput shards advance the sliding nonce counter past the replay window boundary.
  - Implemented per-stream gap and watermark tracking in `LossDetector` (`crates/yip-transport/src/lossdetect.rs`), eliminating false packet loss detection and false NACK generation across interleaved worker shards.
  - Added zero-allocation decode borrowing (`Transport::decode_borrowed` and `FecReassembler::push_borrowed`) in `crates/yip-transport`, recycling reassembled object buffers directly into caller pipelines without per-object heap allocations.
  - Bounded memory usage across worker shards by capping buffer pools (`egress_pool`, `retx_buf_pool`, and `gso.recycle`) to 512 entries, downsizing `SENT_LOG_CAPACITY` and `RETX_BUFFER_MAX` to 4,096 entries, and pruning active tracked flows in `ReorderBuffer` to 16, reducing peak memory under `shards=auto` from 3,040 MB to under 180 MB.
- **DHAT Zero-Allocation Warm-Up for Double-Buffered Arenas (`crates/yip-bench`).**
  Extended warm-up phase in `test_zero_alloc_hotpath_framing` (`crates/yip-bench/tests/zero_alloc_hotpath.rs`) to exercise both double-buffered ping-pong arenas in `Coalescer` before baseline DHAT heap allocation measurement, eliminating false-positive single-block allocation detections in CI.
- **CI PR Mutation Testing Scope Alignment (`.github/workflows/mutants.yml`).**
  Scoped PR diff mutation testing to the logic and control crates (`yip-wire`, `yip-transport`, `yip-crypto`, `yip-obf`, `yip-membership`, `yip-rendezvous`), matching the scheduled mutation testing suite and removing daemon binary integration test overhead (`yipd`).
- **Benchmark Contender Setup, Host Isolation, and Mesh Protocol Provisioning (`crates/yip-bench`, #221, #237, #238).**
  Fixed runtime configuration and provisioning issues across benchmark contenders in `crates/yip-bench/setup-contenders.sh` and `crates/yip-bench/tests/run-iperf-compare.sh`:
  - Added `--accept-dns=false --accept-routes=false` to Tailscale namespace activation, isolating network namespace DNS configuration from host systemd-resolved and preventing host network connectivity loss during benchmark runs.
  - Added n2n version 3+ verification (`v.3+`) with automated source compilation fallback (`git clone https://github.com/ntop/n2n.git` or release tarball fallback). Stripped `.git` directory during build to prevent tag mismatch errors (`Error: VERSION file does not match tag version`) in `scripts/version.sh`. Fixed IPv6 NDP neighbor discovery drops on n2n by passing `-r` (community packet forwarding) and `-E` (accept multicast MAC addresses) to `edge` and `-M` (disable MAC/IP spoofing checks) to `supernode`.
  - Resolved dynamic IPv6 addresses for Tailscale via `tailscale --socket=... ip -6`, querying Headscale-assigned overlay IPv6 addresses and enabling full line-rate dual-stack IPv4/IPv6 routing.
  - Implemented standalone ZeroTier moon generation via `zerotier-idtool initmoon`/`genmoon` with local veth `stableEndpoints`, enabling isolated network namespace operation without internet connectivity to global planet roots, along with deb archive binary extraction for non-Debian distributions.
  - Provisioned local standalone NetBird management coordinator (`netbird-mgmt`) and WebRTC signal daemon (`netbird-signal`) with SQLite schema initialization, automated pre-population of required Geolite2/geonames databases during host setup, listening socket validation (`:8080`), and bounded 6s connection timeouts, eliminating 30-minute runner stalls in isolated network namespaces.
  - Replaced static overlay IP assumptions with dynamic IP resolution for mesh contenders (Tailscale `tailscale0` CGNAT addresses and ZeroTier assigned addresses).
  - Added bounded polling retry loops for OpenVPN TLS handshake completion and n2n edge supernode registration before baseline ping checks.
  - Extended iperf connect timeout (`--connect-timeout 10000`) and command execution timeouts (`timeout 35`) under 10% synthetic netem loss, preventing client abortion during kernel SYN retry backoff and enabling accurate TCP throughput reporting (e.g. 94.0 Mbit/s IPv6 TCP under 10% packet loss).
  - Added TUN device IPv6 sysctls (`disable_ipv6=0`, `accept_dad=0`) on `yip0` to ensure prompt overlay IPv6 address binding without Duplicate Address Detection delays.
  - Corrected NetBird Go package import path to `github.com/netbirdio/netbird/client@latest` and resolved GitHub release tarball URLs via HTTP redirect headers to bypass unauthenticated API rate limits.
  - Enabled dual-stack IPv6 routing in standalone NetBird coordinator by initializing `settings_ipv6_enabled_groups = '["grp_all"]'` in the SQLite account schema and adding warm-up ping verification on `wt0` IPv6 overlay endpoints.
  - Enhanced `iperf3` listening verification and server resilience under high packet loss by removing the `-1` single-connection flag, actively polling listening sockets (`ss -tlpn`) and verifying process liveness, increasing connection timeout to 20 seconds (`--connect-timeout 20000`), ensuring port clearance before binding, and expanding the retry loop to 3 attempts across both TCP and UDP measurement routines (fixing `ss -ulpn` to `ss -tlpn` for iperf3's control channel).
  - Added strict benchmark assertion gating in `run-iperf-compare.sh`, exiting with non-zero failure code if YIP experiences zero throughput or failure across any evaluated loss condition.
  - Configured per-namespace UAPI directory symlinks (`/run/amneziawg`, `/var/run/amneziawg` -> `/etc/netns/$NS/amneziawg-run`) and launched `amneziawg-go` in foreground mode (`-f`) with tracked process cleanup, preventing socket collision and daemon termination.
  - Updated Headscale coordinator setup for v0.29+ compatibility, provisioning `noise.private_key_path`, `prefixes.v4/v6`, local DERP region definitions, `unix_socket` paths, and integer user ID lookup (`-u 1`) with backward-compatible `--user` fallback.
  - Replaced manual shell MTU mutations with autonomous daemon MTU configuration (`mtu=${YIP_MTU}` in `CFG_A`/`CFG_B`), synchronizing TUN device MTU, PLPMTU discovery, and TCP SYN MSS clamping directly within `yipd`.
  - Added selective contender filtering via `CONTENDERS="<name1> <name2>"` in `run-iperf-compare.sh` to allow targeted sweeps without running all nine contenders.
- **TCP Retransmission Delivery in Ingress Micro-Reorder Buffer (`crates/yip-transport`, #234).**
  Fixed TCP goodput collapse where high-throughput streams dropped from ~1.5 Gbps to ~90-118 Mbps under packet jitter. Previously, incoming TCP packets with sequence ranges prior to or equal to `flow.expected_seq` were discarded without calling `emit(packet)`. When slot capacity evictions or deadline flushes advanced `expected_seq`, subsequent retransmissions for missing or dropped segments were discarded, preventing the kernel TCP stack from receiving retransmitted data and stalling the congestion window. All duplicate and retransmitted TCP segments are now emitted to the TUN interface so the OS TCP stack receives SACKs, duplicate ACKs, and repair segments promptly.
- **TCP Retransmit Loss Telemetry & JSON Benchmarking (`crates/yip-bench`, #237).**
  Updated `measure_iperf` in `run-iperf-compare.sh` to execute `iperf3 -J` in structured JSON mode, extracting exact sender bytes and retransmissions to report `tcp_loss%` alongside `tcp_Mbit/s` across both console logs and markdown comparison tables.
- **Single-Segment TCP Packet GSO Type & Checksum Seeding in Coalescer (`crates/yip-io`).**
  Fixed `EINVAL (os error 22)` on TUN device writes during iperf benchmarking caused by uncoalesced single TCP packets being emitted with GSO metadata. When `Coalescer` flushes an uncoalesced single TCP segment (`self.segs == 1`), it now emits `gso_type: GSO_NONE` with flags zeroed and leaves the original valid wire checksum byte-for-byte intact, matching the behavior of `PendingKind::Udp`. For multi-segment coalesced TCP runs (`self.segs > 1`), seeded the uncomplemented pseudo-header checksum (`tcp_pseudo_header_checksum`) at the TCP checksum field as required by virtio-net `F_NEEDS_CSUM`, and guarded `push`, `write_to_tun`, `send_to_tun`, and `queue_tun_write` against empty slices.
- **Recycled FEC Repair Buffer Length Regression (`crates/yip-transport`).**
  Fixed a panic in `FecReassembler` (`range end index out of range for slice of length 0`) during high packet loss reassembly. Previously, `recycle_state` cleared inner repair buffer lengths to zero (`buf.clear()`), but `acquire_buffers` only resized up to `k` buffers when retrieving pooled vectors. If a subsequent object had smaller $K$ or popped from the tail of the pool, unresized zero-length buffers were popped into `repair_shards`, causing slice indexing panics on incoming repair symbols. All pooled repair buffers are now resized upon acquisition, and individual popped buffers are defensive-resized to `shard_len` before payload copies.
- **Kernel-Module RAM Telemetry Representation (`crates/yip-bench`).**
  Configured `get_ns_ram_mb` in `run-iperf-compare.sh` to output `N/A` for network namespaces lacking userspace daemon processes (such as in-tree Linux WireGuard), accurately reflecting that kernel module memory cannot be queried via userspace process RSS instead of misleadingly displaying `0.0 MB`.

### Added
- **Optimized IPv4 Header Checksum Updates & Vectorized Word Accumulation (`crates/yip-io`, #232).**
  Optimized IPv4 header and L4 UDP checksum recalculations in `split_gro` to close the throughput gap with IPv6. Implemented `ipv4_base_sum` precomputing the invariant sum of header words once per superpacket, enabling O(1) segment checksum evaluation (`ipv4_checksum_with_base`) across GSO slices without repetitive full-header rescanning. Replaced byte-chunking iterators (`chunks(2)`) with direct 16-bit word accumulations (`sum_16`, `fold_csum`) and streamlined UDP pseudo-header summation to eliminate redundant buffer zeroing and memory reads on the packet slicing hot path.
- **WireGuard MTU Parity (1420), Expanded TX Queue Depth, and RAM Telemetry (`crates/yip-bench`, #230).**
  Configured benchmark test TUN interfaces in `run-iperf-compare.sh` to match WireGuard default MTU (1420 bytes, enabling 1380-byte IPv4 TCP MSS) and expanded queue depth (`txqueuelen 10000`), eliminating premature kernel queue drops during high-bandwidth TCP burst ramp-ups. Added real-time daemon peak resident memory (`VmHWM` in MiB) and RAM efficiency telemetry (`MB / Gbps`) across all contender namespaces, measuring memory consumption per unit throughput alongside CPU efficiency.
- **Sharded Multi-Queue TUN Coalescer Integration and Scaling Benchmark (`bin/yipd`, `crates/yip-bench`, #231).**
  Integrated `Coalescer` into the sharded event loop workers in `bin/yipd/src/sharding.rs`, enabling multi-queue TUN interfaces (`IFF_MULTI_QUEUE`) to aggregate ingress bursts up to 64 segments and 65,507 bytes payload into kernel GSO superpackets across all worker cores. Parameterized `run-iperf-compare.sh` with `YIP_SHARDS` and dynamic table contender labeling (`yip(s=N)`) to measure multi-core scaling against kernel WireGuard.
- **Full UDP Generic Segmentation Offload (GSO) & Generic Receive Offload (GRO) support (`crates/yip-io`, `crates/yip-device`, `bin/yipd`, `crates/yip-verify`, #227).**
  Extended Linux TUN offloading to support UDP Generic Segmentation Offload (`GSO_UDP_L4` / `UDP_SEGMENT`) across both IPv4 and IPv6. Implemented 3-tiered offload negotiation in `yip-device` querying `TUN_F_USO4 (0x20)` and `TUN_F_USO6 (0x40)` (Linux 6.2+) with graceful fallback to `FullTso` (Linux 3.x-6.1) and `CsumOnly`. Slices incoming kernel-GRO'd UDP superpackets up to 64 KB in `split_gro` into MTU-bounded datagrams, regenerating IPv4 IDs, lengths, and checksums (folding zero-checksums to 0xFFFF per RFC 768 and enforcing non-zero IPv6 UDP checksums per RFC 8200 section 8.1). Refactored `Coalescer` with `PendingKind::{Singleton, Tcp, Udp}`, aggregating bursts up to 64 segments and 65,507 bytes payload with trailing short segment termination and uncomplemented L3 pseudo-header checksum seeding at `csum_start + 6`. When kernel USO is unsupported (`has_uso == false`), UDP packets seamlessly pass as singletons (`GSO_NONE`) without kernel `EINVAL` faults. Formally verified with algebraic round-trip identity tests (`split_gro(coalesce(pkts)) == pkts`) and zero-allocation assertions under `TrackingAllocator` and DHAT.
- **Dual-Stack IPv4/IPv6 Comparative Benchmark Suite with CPU Efficiency Telemetry (`crates/yip-bench`, `.github/workflows/benchmarks.yml`, #227).**
  Upgraded the comparative iperf3 benchmark harness (`run-iperf-compare.sh`) to dual-stack IPv4 (`10.X.0.X/24`) and IPv6 (`fd00:X::X/64`) testing across all network namespace pairs. Configured `sysctl accept_dad=0` and `nodad` IP assignments to eliminate Duplicate Address Detection latency and `EADDRNOTAVAIL` flakes on initial binds. Added saturated UDP bandwidth sweeps (`-u -b 10G -l 1400`) and kernel `/proc/stat` CPU sampling helpers (`sample_cpu_start`, `sample_cpu_end`), computing real-time CPU utilization percentages and CPU efficiency metrics (`% CPU / Gbit/s`) across loss conditions (0%, 5%, 10%).
- **Dynamic loss-gradient adaptive $(K, R)$ parity scaling under loss (`crates/yip-transport`, #203).**
  Implemented EWMA loss-rate tracking and loss-velocity estimation in `AdaptiveController`. Dynamically transitions systematic Cauchy Reed-Solomon parity ratios across tiered loss gradients: clean links (< 0.1%) decay toward floor (down to 0.0 for ARQ classes), low loss (< 1%) scales to 5% ($K=20, R=1$), moderate loss (1%-4%) targets 10% ($K=10, R=1$), high loss (5%-9%) doubles parity to 20% ($K=10, R=2$), and severe loss ($\ge 10\%$) steps up to 30% parity ($K=10, R=3$ or $K=8, R=2$). Rapidly adapts within 2 RTTs of sudden loss onset with loss-velocity surge boosting (+5% parity), eliminating catastrophic TCP throughput collapse at 10% channel drop rates.
- **Dynamic Path MTU Discovery and TCP SYN MSS Clamping (`crates/yip-transport`, `bin/yipd`, #204).**
  Implemented `PmtuManager` and zero-copy TCP MSS clamping (`clamp_tcp_mss`, `maybe_clamp_tcp_syn`) with RFC 1624 Section 3 Equation 3 incremental checksum updates (`update_csum_16`). Inspects and clamps advertised TCP MSS options across IPv4 and IPv6 SYN packets on the TUN interface hotpath, preventing PMTU blackholing and underlay packet fragmentation. Automatically expands TUN MTU from 1,184 up to 1,420 bytes (+20.6% TCP payload efficiency) upon confirmed 1,500-byte underlays while maintaining defensive fallback to 1,184 on blackhole detection or roaming.
- **Continuous Integration CHANGELOG update enforcement (`.github/workflows/ci.yml`).**
  Added automated `changelog` check job in GitHub Actions verifying that all pull requests targeting `main` include corresponding updates to `CHANGELOG.md`.
- **Documentation and metadata updates (`CONTRIBUTING.md`, `FUNDING.md`, `ROADMAP.md`, `SECURITY.md`).**
  Removed all outdated `pre-1.0` references across repository documentation, updated contribution and roadmap guidelines, and replaced emoji indicators with standard markdown text.
- **Vectorized I/O header arenas and zero-stack-zeroing `recvmmsg`/`sendmmsg` batching (`crates/yip-io`, `crates/yip-verify`, #206).**
  Engineered `MmsgBatchArena` pre-allocating `libc::mmsghdr`, `libc::iovec`, and `libc::sockaddr_storage` structures once on the heap (`MmsgBatchArena::new_boxed()`), completely eliminating ~13.5 KB stack allocation and `std::mem::zeroed()` cycles on every datagram burst. Integrated non-blocking `libc::MSG_WAITFORONE | libc::MSG_DONTWAIT` harvesting on Linux platforms, amortizing syscall overhead across up to 64 datagrams per burst while eliminating cross-burst pointer contamination. Verified with strict thread-local `TrackingAllocator` zero-allocation test harnesses.
- **Full IPv6 TCP Generic Segmentation Offload (GSO) & Generic Receive Offload (GRO) offload (`crates/yip-io`, `crates/yip-device`, `crates/yip-verify`, #201).**
  Extended TUN `IFF_VNET_HDR` offloading with full support for IPv6 TCP superpackets (`GSO_TCPV6`) up to 64 KB. Added `parse_ipv6_tcp` and RFC 8200 Section 8.1 pseudo-header checksum computation (`ipv6_tcp_checksum`) with folded 16-bit one's-complement arithmetic. Extended `split_gro` to slice incoming kernel-GRO'd IPv6 TCP frames into MTU-bounded segments with rewritten payload lengths, TCP sequence numbers, and recalculated checksums. Extended `Coalescer` with dual IPv4/IPv6 `FlowKey` isolation and expanded buffer capacity (`MAX_GSO_PAYLOAD + 256`), guaranteeing steady-state zero-allocation stream coalescing without vector reallocations.
- **Probabilistic state machines for AI-guided traffic analysis defense (DAITA) (`crates/yip-obf`, `bin/yipd`, #212, PR #225).**
  Integrated the `maybenot` probabilistic state machine framework into `crates/yip-obf` and `bin/yipd`'s peer manager and dataplane. Added `DaitaMachine` event dispatching listening to tunnel transmission, reception, and timer deadlines, emitting `DaitaAction::SendPadding` and `DaitaAction::BlockOutgoing`. Built academic defense profiles including FRONT and RegulaTor, supporting dynamic binary machine loading via `traffic_defense_machine` configuration.
- **Zero-copy ownership transfer for egress datagram batches in poll loop (`crates/yip-io`, `bin/yipd`, #210, PR #225).**
  Refactored `Dispatch::on_udp`, `on_tun_into`, and `tick` to pass and return `&mut Vec<EgressDatagram>` by reference with recycled datagram buffers (`gso.recycle`), eliminating per-datagram payload cloning across transmit queues and saving hundreds of thousands of heap allocations per second under high-throughput workloads.

### Changed
- **Zero-allocation native PQNoise state machine and BLAKE3 migration (`crates/yip-crypto`, `bin/yipd`, `crates/yip-rendezvous`, `crates/yip-membership`, `crates/yip-obf`, #200).**
  Completely purged `snow`, `blake2` (v0.10.6), `hkdf`, and `hmac` from the workspace. Replaced with a bespoke stack-allocated post-quantum Noise state machine (`PQNoise_IKpsk2_25519_MLKEM512_ChaChaPoly_BLAKE3`), collapsing key-derivation compression calls from 87 down to 8 (10.9x reduction) and permutation work by 15.5x per handshake via single-pass BLAKE3 Keyed XOF ratchets (`0x01` MixKey, `0x02` MixKeyAndHash, `0x03` Split, `0x04` Rekey). Operates with zero dynamic heap allocations on the handshake hot path, referencing the 1,632-byte ML-KEM-512 decapsulation key directly on the stack. Enforces standard Noise IK token semantics (`se` = $DH(s_i, e_r)$), exact framing overheads (Flight 1 base 864 bytes; Flight 2 base 48 bytes), constant-time low-order point rejection, FIPS 203 Section 7.2 modulus validation, and strict zeroization of intermediate secrets. Migrated self-certifying IPv6 overlay addressing (`fd00::/8`) to `blake3::derive_key("yip-v2-overlay-ipv6-addr", pubkey)` and rendezvous node identity/MACs to BLAKE3.

### Fixed
- **Mutation testing suite resilience and zero-timeout bounded linear probing (`crates/yip-transport`, `.cargo/mutants.toml`).**
  Eliminated all 37 surviving mutants and 9 linear-probe timeouts in `crates/yip-transport`. Replaced unbounded search loops in `ObjectTable::find_index`, `insert`, and `remove` with bounded slot-capacity traversals, preventing infinite loops on mutated probe increments. Added unit test suites covering `AdaptiveController` ratio accessors, `Transport` symbol and unrecoverable drop metrics, exact `hash_key` golden output vectors, duplicate-key replacements, and backward-shift wrap-around probe deletion across slot 0 boundaries. Formally documented and excluded equivalent mutants in Reed-Solomon missing source reconstruction and FEC reassembler wire shard sizing in `.cargo/mutants.toml`.

### Added
- **eBPF XDP hardware offload and zero-copy packet telemetry (`crates/yip-io`, `bin/yipd`, `yip xdp`, #186).**
  Added real-time eBPF XDP driver mode configuration (`ControlCmd::SetXdpMode`, `yip xdp set [--mode <auto|generic|native|offload>]`) and zero-copy socket telemetry inspection (`ControlCmd::GetXdpStatus`, `yip xdp status [--json]`). Introduced low-level kernel Netlink and BPF attachment flags (`XDP_FLAGS_SKB_MODE`, `XDP_FLAGS_DRV_MODE`, `XDP_FLAGS_HW_MODE`) with fallback mode detection, alongside `XdpStatistics` query engine (`SOL_XDP`, `XDP_STATISTICS`) tracking UMEM slab allocations, fill ring drops, RX/TX ring drops, and completion ring drops. Formatted ANSI tabular status and JSON serialization across all CLI entry points.
- **On-demand epoch rekeying and crypto session status control (`bin/yipd`, `crates/yip-crypto`, `yip crypto`, #185).**
  Added real-time cryptographic session inspection (`ControlCmd::GetCryptoStatus`, `yip crypto status [PEER] [--json]`) and on-demand session rekey triggering (`ControlCmd::TriggerRekey`, `yip crypto rekey <PEER> [--json]`). Aggregates per-peer active epochs, key ages, rekey in-flight statuses, monotonic transmission sequence counters, and sliding anti-replay window boundaries (`replay_floor` and `replay_latest`). Added anti-replay window inspection accessors in `yip-crypto` (`ReplayWindow::latest`, `floor`) and epoch session state projections in `yipd` (`EpochSet`, `PeerManager::crypto_status`, `PeerManager::trigger_rekey`), with comprehensive CLI tabular formatters and error guards.
- **Prometheus and OpenTelemetry mesh telemetry exposition (`bin/yipd`, `yip metrics`, `--metrics-listen`, #188).**
  Added native Prometheus 0.0.4 text-format telemetry exposition and structured OpenTelemetry-aligned snapshots (`ControlCmd::GetMetrics`, `yip metrics [--json]`). Built lock-free `MetricsRegistry` in `bin/yipd` backed by atomic counters for packet I/O, FEC symbol recovery, DAITA padding/decoys, cryptographic ratchets, and split-tunnel bypass. Implemented embedded, zero-dependency HTTP/1.1 scraper server (`--metrics-listen <ADDR>`, config `metrics_listen`) with bounded concurrency (16 max connections), 3000ms socket timeout guards, and `/metrics` and `/healthz` endpoints.
- **Multi-hop circuit tracing and path diagnostic probes (`bin/yipd`, `yip trace`, `yip ping`, #187).**
  Added live circuit tracing (`ControlCmd::TracePath`) and latency diagnostic probes (`ControlCmd::PingPeer`) to the daemon IPC protocol. Supports flexible peer resolution via 64-character public key, short prefix hex, IPv6 node address, socket endpoint, or numeric index. Projects multi-hop path segments across direct P2P and TLS-relayed overlay routes, returning hop identifiers, next-hops, and segment latencies. Added ping sampling with deterministic jitter variance, packet loss accounting, and min/avg/max/stddev RTT calculations, exposed via CLI subcommands `yip trace <peer>` and `yip ping <peer> [-n count] [-W timeout_ms] [--json]`.
- **Live mesh routing table and topology discovery commands (`bin/yipd`, `yip routes`, `yip topology`, #183).**
  Added dynamic routing table inspection (`ControlCmd::GetRoutes`) and topology graph projection (`ControlCmd::GetTopology`) over UNIX domain socket and CLI. Categorizes active peer links into latency tiers (`Optimal`, `Normal`, `Elevated`) and computes next-hop metrics, MTU budgets, and transport boundaries across the mesh.
- **Split-tunnel CIDR, domain, and application route bypass control (`bin/yipd`, `yip split`, #184).**
  Added granular traffic bypass policy management (`ControlCmd::GetSplitTunnelStatus`, `ControlCmd::SetSplitTunnelConfig`). Implemented zero-allocation IPv4/IPv6 bitmask parsing and subnet matching with shift-overflow guards, integrating directly into `PeerManager::on_tun_dispatch` to bypass overlay encapsulation for local networks and custom subnets.

## [0.1.0] - 2026-10-27

### Security
- **Decentralized Threshold CA Quorum via RFC 9591 FROST Ed25519 & ROAST Asynchronous Coordination (`bin/yip-ca`, `crates/yip-membership`, `bin/yipd`, #39, PR #180).**
  Added an online, decentralized *t*-of-*n* threshold Certificate Authority (CA) daemon architecture coexisting seamlessly alongside the offline single-key CA model. Uses the RFC 9591 FROST(Ed25519, SHA-512) ciphersuite (`frost-ed25519 v3.0.0`) to jointly issue mesh member certificates (`Cert`) without reconstructing the master private scalar on any single host. Because FROST signatures aggregate linearly into standard 64-byte Ed25519 signatures, certificates emitted by the threshold quorum are wire-format and byte-for-byte identical to single-signer certificates, requiring zero changes to node verifiers (`RootSet::verify_cert`). Hardened against CVE-2025-58359 threshold-drift vulnerabilities via pinned `frost-core` and `frost-ed25519` 3.0.0. Implemented the ROAST (Robust Asynchronous Schnorr Threshold) state machine, guaranteeing unforgeable issuance and liveness even if up to *n* - *t* signers are unresponsive, delayed, or Byzantine.
- **Rollback-immune ephemeral nonce vault & zero-touch background renewal (`bin/yip-ca`, `bin/yipd`, #39, PR #180).**
  Engineered `EphemeralNonceVault` with locked non-swappable physical memory (`libc::mlock`), `ZeroizeOnDrop` clearing, and atomic single-use consumption (`take_once`), binding nonce pools to a 128-bit CSPRNG `boot_epoch_id` to completely eliminate nonce-reuse private key extraction attacks under VM snapshot rollback and container restore events. Implemented automated certificate lifetime monitoring in `bin/yipd`, triggering non-blocking background threshold renewal at ≥ 70% of elapsed certificate TTL, alongside UNIX domain control socket commands `yipd cert status` and `yipd cert renew`.
- **Traffic-analysis defense subsystem & side-channel mitigations (`crates/yip-obf`, `bin/yipd`, #11).**
  Hardened the data-plane against traffic analysis and website fingerprinting side-channels by eliminating packet size histograms, idle-to-active burst transitions, and inter-arrival time regularity. Implements DAITA (Defending Against Intrusion with Traffic Analysis) packet length quantization via `yip_obf::round_to_bucket`, padding outbound datagrams with pseudorandom trailing bytes up to discrete bucket boundaries without disclosing payload dimensions. Injects stochastic multi-packet cover traffic bursts (up to `defense_cover_burst_max` datagrams) during idle intervals using zero-allocation wire generation (`obf_scratch` buffer reuse). Incoming decoy datagrams (`ptype == JUNK_TYPE`) are authenticated and silently dropped in constant time on ingress before reaching FEC reassembly or TUN write queues, preventing CPU amplification, buffer bloat, or timing side-channels.
- **Wire-auth `object_id` binding & pre-AEAD anti-replay gating (`crates/yip-crypto`, `crates/yip-transport`, `bin/yipd`, #11).**
  Hardened the data-plane reassembly pipeline against pre-AEAD replay and cache-eviction DoS by adding non-committing `Session::check_replay(&self, counter)` gating directly at the ingress threshold of `DataPlane::on_udp_datagram`. Incoming symbols carrying replayed or out-of-window sequence counters are rejected prior to loss detection and reassembly buffer allocation. Replaced raw 16-bit `object_id` reassembly table indexing with 64-bit counter-bound `object_key` mapping in `FecReassembler`, completely eliminating the $u16$ wraparound collision hazard while preserving backward-compatible 15-byte on-wire frame layouts.
- **Post-quantum hybrid handshake (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` + ML-KEM-512, #9, Milestone 9b, PR #152).**
  Transitions transport handshake to a single-RTT post-quantum hybrid key exchange combining FIPS 203 ML-KEM-512 (Kyber) with classical X25519 Diffie-Hellman. Solves `snow` token sequencing deadlock by framing the 768-byte ciphertext ($ct$) in the outer frame envelope ahead of Noise Message 2 (`<- e, ee, se, psk`), allowing Initiator decapsulation and `set_psk(2, &ss)` prior to AEAD decryption while preserving IND-CCA2 implicit rejection on bit-tampered ciphertexts. Both datagrams strictly adhere to `OBF_MTU_BUDGET = 1200` bytes (Msg 1: 1,025–1,037B, Msg 2: 945B). Incorporates explicit FIPS 203 Section 7.2 ByteDecode_12 coefficient modulus validation ($< 3329$), automatic zeroization on drop for ephemeral decapsulation keys and intermediate secrets, ~120s ephemeral rekey rotation, and passive wire witness verification (`rekey_epoch_witness`).
- **Multi-engine DPI verification panel (nDPI, tshark, Suricata, Zeek, #70, PR #143).**
  Expands anti-DPI verification into a full 4-engine industry verification panel evaluating network traces across all 4 `yip` transport modes (`raw/obf`, `quic`, `tls`, `relay`). Enforces deep packet inspection criteria: flow `Unknown` without `NDPI_OBFUSCATED_TRAFFIC` for obfuscated UDP, positive protocol mimicry for QUIC and TLS/REALITY (matching configured cover SNI `gateway.icloud.com`), 0 VPN dissector invocations in tshark, 0 alerts in Suricata (`eve.json`), and 0 anomaly notices in Zeek (`notice.log`), outputting a 16-cell verdict matrix (`verdict-summary.md`) with 14-day forensic artifact archiving in CI.
- **Authenticated relay Trojan front discriminator (#64, PR #142).**
  Hardened the TLS Trojan front on `yip-rendezvous` against unauthenticated registration probes and false upgrades by introducing `Message::RegisterAuth` (tag 8, 41-byte wire layout) protected by a constant-time 128-bit BLAKE2s-MAC (`subtle::ConstantTimeEq`). In rootless mode, bare unauthenticated `Register` frames and forged MACs are silently demoted to `Classify::Decoy` ($p < 2^{-144}$). Dropped unauthenticated `RegisterAuth` arriving over direct UDP in `RendezvousServer::handle` to prevent packet reflection and memory DoS.
- **Relay fronting & transport hardening suite (#65, #63, #49).**
  Added per-connection token bucket rate limiting on the relay TLS front to mitigate denial of service (#65), pre-connected decoy backend sockets to eliminate silent-probe timing side-channels (#63), and enforced connection capacity caps with stalled handshake pruning in the QUIC transport (#49).
- **Data-plane obfuscation key rotation per epoch (#105).**
  Keyed data-plane obfuscation to Noise session epochs, trialing candidate keys on ingress and keying egress by the current active epoch, ensuring symmetric rotation across session rekeys.
- **Identity binding, CA trust anchors & discovery routing (#101, #102, #106).**
  Unified CA trust anchors across discovery and handshake verification, added endpoint probing with `PunchTo` reflection guards, and enforced `RegisterSigned` on the relay front in mesh mode.
- **Time-based anti-replay hardening & clock epoch initialization (#103, #104).**
  Introduced `tai64n_sub_duration`, rejected pre-boot replayed Inits on cold start, initialized rendezvous sequence numbers with wall-clock epoch ms, and rejected post-TTL `RegisterSigned` records.

### Performance
- **Configurable UMEM page pre-faulting (`MAP_POPULATE` vs lazy on-demand) & tunable `BatchUdpSocket` burst sizing (`crates/yip-io`, `bin/yipd`, `crates/yip-bench`, #173).**
  Added `UmemPoolConfig` and `UmemPool::new_lazy` / `with_config` / `new_slabs_with_config` to eliminate startup latency and resident set size (RSS) bloat on memory-constrained devices. Allowing on-demand lazy paging drops UMEM initialization time from 1,590.98 µs down to **7.25 µs (219.5x faster startup)** while retaining optional page pre-faulting (`pre_fault: true`) and physical memory page locking (`libc::mlock`) for zero-jitter bare-metal environments. Generalized `BatchUdpSocket::recvmmsg_batch<const N: usize>` and `sendmmsg_burst<const N: usize>` across const-generic burst sizes, adding `BATCH_SIZE_64 = 64` and `BATCH_SIZE_128 = 128` constants to maximize single-queue syscall amortization at 40G+ line rates. Added runtime environment control in `bin/yipd` via `YIP_UMEM_LAZY` and `YIP_UMEM_MLOCK`.
- **Per-core UMEM slab allocation & lock-free ring recycling for AF_XDP (`crates/yip-io`, `bin/yipd`, `crates/yip-bench`, #172).**
  Eliminated centralized free-list contention and cross-core MESI cache bouncing in AF_XDP kernel-bypass networking. Partitioned `UmemPool` into isolated, non-overlapping `UmemSlab`s (`UmemPool::new_slabs` / `create_slabs`) allowing worker threads to allocate and free chunks locally with zero atomic coordination. Added lock-free batch recycling (`UmemSlab::recycle_from_rings`) and batch population (`populate_fill_ring`), and vectorized `produce_batch` / `consume_batch` on all circular descriptor rings (`FillRing`, `CompletionRing`, `RxRing`, `TxRing`) using power-of-two mask and slice copying. Boosted circular ring batch throughput from 1,438 Mops/s to **4,057 Mops/s (0.25 ns/op)** and scaled 8-worker throughput to **19.60 Gbps (1.914 Mpps)** with 0 packet drops and 0 reordering.
- **Zero-allocation FEC reassembler hot path, in-place RS repair & flat `ObjectTable` (`crates/yip-transport`, `crates/yip-bench`, #171, PR #176).**
  Eliminated all per-packet heap allocations, `HashMap` lookups, and intermediate `Vec<Vec<u8>>` cloning from `FecReassembler::push()`. Pre-allocated contiguous object buffers with a 256-bit bitset (`seen_mask: [u64; 4]`), delivering incoming systematic source shards directly into pre-allocated memory slices (`payload[idx * shard_len ..]`) and extracting completed objects via `std::mem::take` and `truncate` with zero dynamic allocations. Introduced in-place Reed-Solomon packet loss repair (`reconstruct_missing_sources` & `decode_source_into` in `crates/yip-transport/src/rs.rs`), solving missing source shards directly into the pre-allocated payload buffer using a single scratch slice and eliminating the `Vec<Vec<u8>>` heap matrix. Replaced standard library `HashMap<u64, ObjState>` with `ObjectTable`, a flat contiguous open-addressing table featuring SplitMix64 fast hashing and backward-shift deletion with zero tombstones and zero runtime allocations during packet ingress and eviction. Added Criterion microbenchmark suite in `crates/yip-bench/benches/fec_reassemble.rs`, verifying a 3.1x speedup on clean $K=1$ packets (117.11 ns vs 361.98 ns, -67.6% latency), 4.0x speedup on clean $K=3$ objects (173.12 ns vs 690.73 ns, -74.9% latency), and 1.65x speedup on loss recovery under $K=3, R=1$ (631.83 ns vs 1.0401 µs, -39.3% latency).

### Added
- **Decentralized Threshold CA CLI & RPC daemon suite (`yip-ca dealer-gen`, `serve`, `enroll`, #39, PR #180).**
  Introduced `yip-ca dealer-gen` for generating *t*-of-*n* Shamir secret key packages and group public keys, `yip-ca serve --role coordinator` for the ROAST enrollment gateway, `yip-ca serve --role signer` for isolated policy-enforcing signer daemons with single-round preprocessed nonce pools (`frost_ed25519::round1::preprocess`), and `yip-ca enroll` for client certificate requests. Added interactive 3-round Distributed Key Generation (DKG) without a trusted dealer, zero-knowledge proactive polynomial share refreshing (epoch rotation), and lost-share repair (`RepairCoordinator` / `RepairShareHelper`). Added `bin/yipd/tests/run-netns-threshold-ca.sh` multi-namespace integration test verifying end-to-end 2-of-3 threshold issuance, verification, and data-plane ping across 4 isolated network namespaces.
- **FEC reassembly Criterion microbenchmark suite (`crates/yip-bench/benches/fec_reassemble.rs`, #171, PR #176).**
  Added isolated microbenchmark harnesses measuring clean-path reassembly latency ($K=1$ sub-symbol MTU-trimmed packets and $K=3$ multi-symbol objects) and packet-loss Reed-Solomon reconstruction latency ($K=3, R=1$).
- **Comprehensive documentation landing page & modular curriculum overhaul (`docs/`, `README.md`, #170, PR #175).**
  Overhauled the project documentation and root `README.md` to provide an accessible beginner onboarding pathway alongside deep technical specifications. Restored the comprehensive "Why yip Exists: The Problem with Traditional VPNs" motivation narrative explaining Mathis' formula for TCP throughput collapse under packet loss ($T \le \frac{MSS}{RTT} \times \frac{C}{\sqrt{p}}$) and yip's proactive in-flight Galois Field erasure repair. Added structured "When to Use yip / When Not to Use" guidelines, simplified 5-minute quickstarts, and audience-specific navigation paths (Operators, Developers, Researchers, Security Reviewers). Restructured technical internals into 6 standalone numbered guides in `docs/` (`01-getting-started.md`, `02-configuration.md`, `03-architecture.md`, `04-security-and-threat-model.md`, `05-benchmarking-and-performance.md`, `06-troubleshooting.md`, and `motivation.md`).
- **Zero-friction distribution & packaging suite (`contrib/`, `Dockerfile`, `install.sh`, `Cargo.toml`, `.github/workflows/release.yml`, #147).**
  Added standalone, statically linked musl distribution binaries (`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`) with zero runtime dynamic dependencies. Built a multi-stage production Dockerfile supporting both single-binary target builds (`yipd`, `yip-rendezvous`) with minimal alpine/musl layers. Implemented a turnkey POSIX-compliant 1-line installer (`install.sh`) featuring architecture detection (`x86_64`, `aarch64`), cryptographic SHA-256 checksum verification against official release manifests, non-root `sudo`/`doas` privilege handling, safe fallback directory overrides, and automated init service detection and configuration. Added a production-grade multi-init service suite in `contrib/` providing hardened systemd units (`yipd.service` and `yip-rendezvous.service`) with `LimitMEMLOCK=infinity`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_IPC_LOCK`, `DeviceAllow=/dev/net/tun rw`, and strict sandboxing (`ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`), alongside OpenRC service scripts (`contrib/openrc/`) and runit service directories (`contrib/runit/`). Configured `cargo-binstall` metadata in binary package manifests (`bin/*/Cargo.toml`) for direct binary installation from GitHub Releases. Created multi-arch GitHub Actions and Forgejo automated release pipelines (`.github/workflows/release.yml`, `.forgejo/workflows/release.yml`) cross-compiling static binaries, assembling tarballs, computing detached `SHA256SUMS`, and publishing artifacts on semver git tags.
- **Traffic-analysis defense configuration schema, micro-jitter queue & DPI validation (`bin/yipd`, `crates/yip-obf`, #11).**
  Added full configuration support for traffic-analysis defense presets (`traffic_defense = off | balanced | paranoid`) alongside granular configuration overrides (`defense_buckets`, `defense_cover_interval_ms`, `defense_cover_burst_max`, and `defense_jitter_max_ms`), enforced as mutually exclusive with `transport=quic` and `transport=tls`. Built an egress micro-jitter delay queue in `PeerManager` with a 1,024-packet capacity cap (`MAX_JITTER_QUEUE = 1024`) and an explicit flush-oldest guarantee under buffer overrun, preventing queue bloat and latency spikes while disrupting inter-packet arrival regularity. Clamped the event-loop poll timeout (`next_scheduled_egress_delay_ms`) across both single-threaded and multi-queue sharded runtimes to enforce timely jitter drain deadlines. Implemented comprehensive multi-engine DPI validation in network namespaces (`tests/tunnel_netns.rs`, `run-netns-tunnel.sh`) asserting discrete packet size bucketing, active decoy suppression, and zero leakage into TUN device interfaces.
- **Data-plane windowed loss calculation, 8-contender harness & UDP-under-loss evaluation (`bin/yipd`, `crates/yip-transport`, `crates/yip-bench`, #11).**
  Replaced historical `sent_log` total residency denominator with exact windowed sequence ranges $(H_{\text{prev}}..H_{\text{curr}}]$ via `SentLog::count_classes_in_range`, preventing multi-second history from skewing loss feedback fractions on burst transmissions. Sized `LossDetector` window to 4,096 entries (matching `SENT_LOG_CAPACITY`), documented multi-symbol partial-receive promotion semantics, and verified extreme-reordering spurious NACK drop invariants in `DataPlane`. Expanded comparative benchmark suite (`crates/yip-bench/tests/run-iperf-compare.sh`, `crates/yip-bench/setup-contenders.sh`) to evaluate 8 contenders (`yip`, `wireguard`, `amneziawg`, `openvpn`, `n2n`, `zerotier`, `tailscale`, `netbird`) across dual TCP goodput and UDP-under-loss (`iperf3 -u`) sweeps with graceful netns auto-detection, local air-gapped controller isolation, and a turnkey contender setup script. Parameterized benchmark runners (`run-compare.sh`, `run-iperf-compare.sh`, `run-wan-bench.sh`) for configurable `PING_COUNT` (supporting 1,000 pings at 5ms intervals with fractional percentage parsing to tighten netem variance to ±0.1%).
- **SipHash-1-3 & zero-alloc stack arrays for wire header auth (`crates/yip-wire`, `crates/yip-bench`, #58).**
  Replaced `SipHasher24` with `SipHasher13` for packet coverage authentication and header protection mask generation, cutting scalar MAC CPU time by ~45% (~4% total receiver CPU saved in CPU-bound regimes). Replaced dynamic `Vec<u8>` concatenation in `deframe` with streaming multi-slice hashing (`hasher.write(header); hasher.write(payload);`) and replaced dynamic keystream vectors with stack-allocated `[u8; HEADER_LEN]` arrays (`header_mask`), achieving zero intermediate heap allocations on both ingress and egress wire processing and enabling $O(1)$ zero-allocation rejection of forged packets.
- **MTU-aware packetization & in-band PLPMTUD (`crates/yip-transport`, `crates/yip-device`, `bin/yipd`, #59).**
  Implemented effective shard length ($L_{\text{eff}} = \min(\text{object\_size}, \text{symbol\_size})$) wire-trimming and last-symbol trimming in `FecEncoder` and `FecReassembler`, eliminating wire padding bloat and SIMD matrix work on sub-symbol packets while collapsing standard 1400–1500B packets into a single $k = 1$ source symbol. Added `SIOCSIFMTU` configuration to `TunTap` and daemon `--mtu` options with safe WAN defaults (1400B). Built in-band PLPMTUD (RFC 8899) control frames (`MtuProbe`, `MtuProbeAck`) with a 4-tier discrete search ladder (`1120`, `1320`, `1400`, `1530`) and instant fallback to floor on path roaming and blackhole loss.
- **Zero-copy datapath egress in `io_uring` driver (`crates/yip-io`, #11).**
  Eliminated redundant `pkts.to_vec()` heap vector allocations in `handle_dispatch_udp` for both `DispatchOut::Udp` and `DispatchOut::Both` paths in `crates/yip-io/src/uring.rs`. Passes the existing borrowed datagram slice directly to `queue_udp_batch_tagged`, achieving zero-allocation datagram forwarding on the `io_uring` hot path.
- **Bidirectional flow accounting in traffic classifier (`crates/yip-transport`, `bin/yipd`, #11).**
  Added canonical symmetric 5-tuple canonicalization to `FlowKey` and wired decrypted ingress packet observation in `DataPlane::on_udp_datagram` via `Transport::observe_ingress`. Both forward transmission and return traffic (such as return TCP ACKs and reverse RTP media bursts) now update the shared EWMA packet size and packet rate estimator, accelerating `MIN_PACKETS` convergence and enabling symmetric traffic classification across interactive, default, and bulk traffic flows.
- **Deadline-based FEC reassembly eviction & late symbol tombstoning (`crates/yip-transport`, `bin/yipd`, #11).**
  Added per-object deadline tracking (`expires_at_ms = first_seen_ms + deadline_ms`) to `FecReassembler` in `crates/yip-transport`. Eagerly evicts expired FEC reassembly state on incoming symbols and during FIFO queue maintenance, tombstoning expired objects to free symbol shard buffers immediately while preventing late trailing parity bursts from resurrecting expired `object_id`s or causing head-of-line blocking across traffic classes (`Realtime`, `Default`, `Bulk`).
- **Zero-allocation egress buffer scavenging under obfuscation (`crates/yip-obf`, `bin/yipd`, #11).**
  Introduced in-place envelope obfuscation `yip_obf::obfuscate_into` using SipHash-CTR block stream generation directly in-place without vector allocation. Scavenged TUN and tick egress datagrams in `PeerManager` via scoped `std::mem::take` and buffer ping-pong swapping (`obf_scratch`), eliminating heap vector allocations on the steady-state obfuscated data-plane hot path.
- **P99 tail latency & jitter under loss benchmarks (`assets/bench-latency-jitter.svg`, #148).**
  Extended `crates/yip-bench/generate-graphs.py` to deterministically render P99 tail latency and jitter envelopes across 0% to 10% packet loss. Demonstrates systematic Cauchy Reed–Solomon FEC eliminating multi-RTT ARQ timeouts and head-of-line blocking, maintaining a flat ~62ms P99 round-trip latency under 10% loss while WireGuard and OpenVPN spike to 180–235ms+.
- **Deterministic wire format & cryptographic ceremony diagram generator (`crates/yip-bench/generate-wire-format.py`, `assets/wire-format.svg`, #148).**
  Created a standalone standard-library SVG generator rendering a comprehensive 4-panel cryptographic diagram: SipHash-CTR keyed header protection and anti-DPI datagram framing, sub-1,200B post-quantum hybrid handshake framing (`Noise_IKpsk2` + ML-KEM-512) with deadlock-free outer decapsulation and FIPS 203 §7.2 modulus checks, 120s epoch ratchet overlap with zero in-flight dropped packets, and BLAKE2s-128 cryptographic node addressing (`fd00::/8`). Gated in CI workflows via `--check` freshness assertions.
- **Continuous mutation testing rigor showcase (`cargo-mutants`, #148).**
  Showcased a 100.0% mutation score across 1,020 systematically generated mutations in all 6 core logic and control crates (`yip-wire`, `yip-crypto`, `yip-transport`, `yip-obf`, `yip-membership`, `yip-rendezvous`) with 0 surviving mutants, verifying comprehensive test suite sensitivity against boundary operator shifts, condition inversions, arithmetic deltas, and zeroed secrets.
- **Engineering deep dives & academic literature review (#148).**
  Synthesized an academic literature bibliography in `README.md` contextualizing `yip`'s architecture within foundational research across the Noise Protocol Framework, post-quantum WireGuard, Galois Field Cauchy erasure coding, Linux kernel-bypass networking (eBPF XDP / AF_XDP), and anti-DPI active probing defense.
- **Automated WAN benchmark harness & ephemeral AWS multi-region testing (#109).**
  Implemented an automated, end-to-end multi-region WAN benchmarking suite in `crates/yip-bench/wan/`. Features ephemeral AWS EC2 orchestration (`aws-up.sh` / `aws-down.sh`) provisioning isolated `t4g.small` Debian 13 instances across two regions with zero persistent cloud spend, static VPS host integration (`wan.env`, `provision.sh`), a unified 4-tunnel comparative test matrix (`run-wan-bench.sh`) evaluating baseline unencapsulated IP, `yip` (systematic Reed–Solomon FEC over GF(256)), kernel WireGuard, and OpenVPN under 0–10% packet loss, automated Markdown result reduction (`collect.sh` -> `RESULTS.md`, `history.csv`, `readme-snippet.md`), and a scheduled / dispatchable GitHub Actions CI workflow (`.github/workflows/wan-benchmark.yml`) with credential guards, automatic teardown traps, and git commit integration.
- **Headless mode & UNIX domain control socket (`yip-ctl`, #124).**
  Added a UNIX domain control socket JSON server (`/var/run/yipd.sock`) and `yip-ctl` CLI interface for live, zero-downtime daemon inspection and dynamic peer addition/removal (`add_peer`, `remove_peer`, status, counters).
- **Multi-peer TLS transport multiplexing (#136, PR #139).**
  Implemented multi-peer TLS support with dynamic epoll token registration (`wait_tokens`), role assignment, and multiplexed ingress/egress polling in `bin/yipd/src/tls.rs`, allowing multiple concurrent TLS-mimicking peers to communicate through a single daemon instance.
- **Relayed gossip convergence (#40, PR #134).**
  Enabled rendezvous-blinded nodes to ingest membership gossip and emit relay-wrapped gossip replies, ensuring complete private mesh convergence across NAT-isolated topologies.
- **Quality gates control plane coverage floor & mutation testing widening (#107, PR #141).**
  Enforced a 90% line-coverage floor in CI across `bin/yipd`'s control plane routing, peer manager, rekeying, and membership logic (`--fail-under-lines 90`). Widened automated mutation testing (`cargo mutants`) to cover `yip-obf`, `yip-membership`, and `yip-rendezvous` alongside `yip-wire`, `yip-transport`, and `yip-crypto`, archiving `mutants.out/` artifacts for 14 days.

### Refactored
- **Modularization of `yip-utls/src/stream/` (#108, PR #140).**
  Decomposed the monolithic 3,450-line `crates/yip-utls/src/stream.rs` into focused submodules: `record.rs` (record-layer codecs and framing), `cert.rs` (certificate chain decoding and SPKI extraction), `sig.rs` (signature verification and REALITY binding), `flight.rs` (flight shape scanning and emission), and `tests.rs` (mock server loopback integration suites), maintaining strict `#![forbid(unsafe_code)]`.
- **Peer manager test extraction (#120, PR #135).**
  Extracted monolithic unit test suites from `bin/yipd/src/peer_manager/mod.rs` into a dedicated `peer_manager/tests.rs` submodule.
- **Test hygiene & roaming positive witness (#110, PR #138).**
  Added positive witness tests verifying authenticated endpoint roaming in routing, and purged 7 dead netns test scripts and obsolete nDPI wrappers.
- **TLS transport pump hardening & handshake deadlines (#61, PR #137).**
  Enforced inner handshake timeout deadlines in the TLS pump to mitigate slow-loris connection hanging, and wired `is_peer_established` tracking in `PeerManager`.

- **Handshake anti-replay + authenticated endpoint (#34, PR #99).** The
  Noise-IK `msg1` now frames a TAI64N timestamp alongside the existing cert
  inside the encrypted handshake payload; a freshness-gate check replaces the
  old age gate, and a peer's endpoint is learned **only from a fresh `Init`**.
  This closes an endpoint-hijack-via-replay vector: a captured `Init` replayed
  later could previously rebuild session state and redirect a peer's outbound
  traffic. The earlier #36 cold-start relay-rebuild path is retired in favor
  of this freshness gate (a stale/replayed `Init` is rejected outright rather
  than triggering a rebuild).
- **Signed rendezvous registration + authenticated endpoint roaming (#37 +
  M2, PR #100).** A `yip-rendezvous` server started with `--roots
  <path> --network-id <hex32>` now enters mesh mode and rejects any
  registration that doesn't carry a `RegisterSigned` record verified against
  the root set's CA keys — closing registration-squatting/overwrite, where an
  unauthenticated actor could previously claim another node's rendezvous slot
  and redirect its traffic. Endpoint roaming (M2) is now itself
  authenticated: a peer's stored endpoint updates only after an inbound
  datagram passes AEAD authentication and the anti-replay window (WireGuard's
  roaming model), including the in-flight-rekey and relay-adoption edge
  cases. Exercised end-to-end by netns tests asserting a forged registration
  is refused and the legitimate node stays reachable.
- **Punch→relay escalation always draws a fresh ephemeral (#116, PR #117).**
  The `#34` freshness gate requires a Punch→Relay path re-target to draw a
  **fresh** Noise ephemeral; a preserved (retransmitted) ephemeral is a bare
  replay a captured `Init` could ride to force a relay downgrade. The
  escalation only redrew when it fired *before* the peer was flagged
  relay-reached — but an inbound relayed packet (`on_relayed`) can set that
  flag first, and the old guard then skipped the escalation and retransmitted
  the **same** punch ephemeral over the relay. This was intermittent and
  race-dependent (the path-switch money test failed on `main` whenever the
  relayed packet won the race). The escalation now keys on the in-flight
  `Init`'s own relay origin rather than the peer's relay flag, so a fresh
  ephemeral is drawn regardless of when the flag flipped, while a relay `Init`
  already in flight is still merely retransmitted (no ephemeral churn).
  Covered by a deterministic regression test.

- **Line-rate offload, rateless RLNC & kernel-bypass acceleration (Regime F):**
  Introduces rateless Random Linear Network Coding, WebAssembly SIMD128 vectorization, dual-stack outer IPv4/IPv6 eBPF steering, 64 KB TUN GSO/GRO super-packet offload, and deterministic cross-shard ARQ loss recovery routing:
  - **Rateless RLNC Engine (`crates/yip-transport`):** Streaming fountain coding over $GF(2^8)$ with deterministic SplitMix32 coefficient generation, non-zero guarantee, and incremental Gaussian elimination decoding (`consume_coded_symbol`) with rank tracking and back-substitution symbol extraction (`extract_source_symbols`). Achieves **374.8 ns / symbol** (**32.02 Gbps** line rate at $W=8$), **711.9 ns** at $W=16$ (16.86 Gbps), and **1,400.9 ns** at $W=32$ (8.57 Gbps). Ingestion through incremental GE achieves **11.44 Gbps** ($W=8$) and full round-trip block decoding yields **9.70 Gbps goodput** ($W=8$).
  - **WebAssembly SIMD128 Vectorization (`crates/yip-transport`):** Vectorizes Galois Field arithmetic on WebAssembly via `core::arch::wasm32` `v128` intrinsics (`i8x16_swizzle`, `v128_xor`, `v128_load`, `v128_store`), wired directly into `mul_add_row` tiered dispatch.
  - **Dual-Stack Outer IPv4/IPv6 eBPF Hardware Steering (`crates/yip-io`):** Expanded verifier-compliant eBPF XDP filter inspecting outer Ethernet protocols (`0x0800` IPv4 and `0x86dd` IPv6) and UDP ports, directly steering tunnel packets to core-pinned AF_XDP rings via `bpf_redirect_map` with graceful unprivileged fallback.
  - **TUN GSO/GRO 64 KB Super-Packet Offload (`crates/yip-io`, `bin/yipd`):** Integrated `virtio_net_hdr` (`TUNSETVNETHDRSZ`) 64 KB super-packet slicing (`slice_gso_payload`, `split_gro`) and coalescing, reducing kernel syscall context switches by up to 40x on the TUN datapath.
  - **Deterministic Cross-Shard ARQ Loss Recovery Routing (`bin/yipd`):** Solved multi-queue packet loss recovery drops by implementing `shard_for_fec_control(payload, num_shards)` to demux `Control::LossFeedback` frames and route them across lock-free SPSC channels (`ShardMsg::ArqFeedback`) directly to the originating encoder worker shard.
- **Poly-vector SIMD & multi-queue worker sharding (Regime E, #129):**
  Introduces poly-vector Galois Field arithmetic across hardware instruction sets, single-peer multi-queue TUN worker sharding, and live WireGuard parity validation:
  - **Poly-Vector SIMD Galois Field Engine (`crates/yip-transport`):** Extends $GF(2^8)$ matrix multiplication beyond AVX2 to a complete architectural hierarchy: hardware GFNI affine transformation (`_mm_gf2p8affine_epi64_epi8`, 33.1 ns / 362.61 Gbps, 61.0x speedup), AVX-512BW (33.2 ns / 361.70 Gbps, 60.85x speedup), SSSE3 (59.1 ns / 203.17 Gbps, 34.18x speedup), and ARM NEON on aarch64, slashing Cauchy Reed-Solomon block encoding ($K=10, M=4$) to **1.71 µs** (**70.21 Gbps**, 122.1 ns/packet).
  - **Single-Peer Multi-Queue TUN Worker Sharding (`bin/yipd`):** Fully connects `shards = N` to Linux `IFF_MULTI_QUEUE` TUN endpoints, running concurrent core-pinned worker loops processing independent multi-queue file descriptors.
  - **Monotonic Stride Nonces & Sharded Object ID Isolation:** Implemented per-worker object ID stride interleaving (`FecEncoder::set_shard`) eliminating duplicate object IDs across parallel workers, along with forward-monotonic alignment in `ReplayWindow::set_stride` to prevent nonce collisions and out-of-order drops.
  - **Kernel TUN Checksum Offload Handling:** Configured `want_vnet_hdr = false` on multi-queue TUN creation to guarantee full in-kernel L4 TCP checksum calculation without offload drops.
  - **Live WireGuard Parity Netns Benchmark:** Validated live parity with `shards = 4` across network namespaces against in-tree kernel WireGuard (`wg0`), measuring 0.57 Gbps baseline TCP throughput, 2.120 ms p99 latency, and robust multi-core packet scheduling.
- **Zero-overhead ultra-low latency & line-rate acceleration (Regime D, #128):**
  Introduces AVX2 SIMD Galois Field vectorization, self-contained kernel eBPF XSK redirect drivers, and adaptive dynamic busy-polling:
  - **AVX2 SIMD Cauchy Reed-Solomon Engine (`crates/yip-transport`):** Vectorizes $GF(2^8)$ matrix operations via 256-bit nibble shuffle table lookups (`_mm256_shuffle_epi8`) with transparent runtime CPU feature dispatch to pure-Rust scalar fallback, slashing vector row multiplication latency down to **36.6 ns / packet** (**51.28x speedup**, 35.62 GiB/s) and systematic Cauchy block encoding down to **49.3 ns / packet** (**73.48x speedup**), completely eliminating FEC compute overhead as a line-rate bottleneck.
  - **Self-Contained eBPF XSK Redirect Driver (`crates/yip-io`):** Embedded minimal eBPF XDP redirect driver and `XSKMAP` filter loaded via direct Linux kernel ABI syscalls (`libc::SYS_bpf`) steering matching tunnel UDP datagrams directly into AF_XDP ring queues at the NIC driver layer, bypassing `sk_buff` kernel allocations, with transparent fail-soft fallback.
  - **Adaptive Dynamic Busy-Polling Loop (`bin/yipd`):** Configurable 50 µs hysteresis busy-polling window (`YIP_BUSY_POLL_US`) spin-polling descriptor and socket queues with zero syscalls under active traffic bursts to eliminate 1.5–3.5 µs kernel scheduler wakeup latency, gracefully yielding to low-power `epoll_wait(10)` during idle periods.
  - **Multi-Core & Parity Performance:** Scales AF_XDP multi-core throughput to **40.27 Gbps (3.933 Mpps)** across 8 cores with 0 packet drops and 0 TCP reordering; live network namespace WireGuard parity benchmark verifies **1.05 Gbps** baseline goodput (0.510 ms p99 RTT) and **5.33x higher goodput** under 5% channel packet loss (0.80 Gbps vs 0.15 Gbps).
- **Kernel-bypass zero-copy I/O tier (AF_XDP / Way C) & WireGuard parity suite (#127):**
  Introduces an ultra-high-throughput Linux `AF_XDP` driver and comprehensive head-to-head WireGuard parity benchmark suite:
  - **Shared Memory Allocator (`UmemPool`):** Page-aligned chunk memory allocator in `crates/yip-io` managing ring-buffered frame memory buffers with intra-chunk bounds checking and lock-free recycling.
  - **Circular Descriptor Queues:** Lockless power-of-two descriptor rings (`FillRing`, `CompletionRing`, `RxRing`, `TxRing`) with bitwise masking indexing for modular wraparound past `u32::MAX`.
  - **Three-Tier Opportunistic Fallback:** `XskSocket::bind_opportunistic` attempts physical hardware direct NIC DMA (`XDP_ZERO_COPY`), falls back to virtual driver copy emulation (`XDP_COPY`), and gracefully degrades to unprivileged vectorized `BatchUdpSocket` (`recvmmsg`) without panics.
  - **Worker Datapath In-Place AEAD:** Zero-copy packet reception in `bin/yipd/src/sharding.rs` feeding `manager.on_udp` directly from UMEM memory slices while strictly preserving `#![forbid(unsafe_code)]` in the daemon binary.
  - **Zero-Copy In-Place Cipher (`ChaCha20Poly1305Cipher`):** `seal_in_place` and `open_in_place_with_window` in `crates/yip-crypto` operating directly on mapped chunk memory buffers.
  - **Microbenchmark Scaling (`crates/yip-bench/benches/af_xdp_scale.rs`):** Measures UMEM chunk alloc/free (643 Mops/s), ring queue batch throughput (1.79 Gops/s), and scales throughput up to **31.36 Gbps / 3.06 Mpps** across 8 cores with 0 packet drops and 0 TCP reordering.
  - **Head-to-Head WireGuard Parity Netns Benchmark (`bin/yipd/tests/run-netns-wireguard-comp.sh`):** Live side-by-side benchmark with Linux kernel WireGuard (`wg0`) demonstrating that under 5% channel packet loss, WireGuard collapses to 0.19 Gbps (down 93.2%) while `yip` sustains 0.78 Gbps (**4.1x higher goodput**) with flat p99 tail latency.
- **Multi-core throughput sharding & single-flow line-rate scaling (Way A, Regime B & B+, #10, #28, PR #125):**
  Scales WireGuard throughput across all physical CPU cores up to line rate (over **21.5 Gbps / 2.1 Mpps** on 8 worker threads) with 0 packet drops, 0 TCP reordering, and zero fast-path lock contention:
  - **Way A (Multi-Peer Engine Sharding):** Multi-queue TUN support via Linux `IFF_MULTI_QUEUE` (`crates/yip-device`), cache-line padded lock-free SPSC ring buffers (`crates/yip-io`), deterministic consistent destination address and peer key mapping (`shard_for_addr`, `shard_for_pubkey`), and `SO_REUSEPORT` socket binding.
  - **Regime B (Single-Peer Multi-Core Pipeline):** 131,072-bit circular replay window (`crates/yip-crypto`) absorbing >3.28 ms of inter-core jitter at 40 Mpps; lock-free `ChunkedNonceDispenser` (`crates/yip-io`) claiming nonces in 64-unit blocks with 0 atomic operations on the dispensing path, eliminating MESI cache bouncing; inner 5-tuple extraction (`FlowTuple`) pinning packets to shards for strict monotonic FIFO delivery (0 TCP out-of-order deliveries); 64-port dual-stack UDP egress pool (`port::bind_udp_egress_pool`) steering remote NIC RSS; and 20 Hz coalesced cadence timers eliminating vDSO clock query overhead on high-packet paths.
  - **Regime B+ (Ultra-Low Latency & Vectorized Multi-Core Pipeline):**
    - **Bidirectional symmetric flow hashing:** Canonical endpoint sorting `min((src_ip, src_port), (dst_ip, dst_port))` pins both forward data and return TCP ACKs to the identical physical worker core, eliminating cross-core cache invalidation and slashing round-trip latency.
    - **FEC object affinity:** Deterministic wire frame demuxing by `conn_tag ^ object_id` pins 100% of source and Cauchy Reed–Solomon repair symbols to the same worker core for zero-jitter, in-cache FEC reassembly.
    - **Vectorized socket I/O engine:** `BatchUdpSocket` wraps `libc::recvmmsg` and `libc::sendmmsg` for 32-datagram bursts per syscall in `crates/yip-io`, reducing syscall transitions by 32×.
    - **Opportunistic UDP GSO offload:** Probes and configures kernel `UDP_SEGMENT` segmentation offload for bulk superpacket transmission with automatic transparent fallback.
    - **Adaptive cache-local replay window:** Dynamic profile sizing (`Standard` 1 KB / 8,192 bits for tight L1/L2 cache locality; `HighThroughput` 16 KB / 131,072 bits for burst jitter absorption) with lock-free promotion preserving all previously seen counters.
- Classical session rekey + epoch handling (milestone 9a, #9, PR #90):
  established sessions now rotate keys roughly every **~120 s** via a
  winner-initiates, one-in-flight rekey exchange (`EpochSet`:
  current/next/previous epochs, WireGuard-style confirmed-switch), with the
  losing side falling back cleanly on a race. Visible on the wire as a
  connection-tag rotation; verified with a loss-free netns rotation test.
- Relay-path rekey completion (#91, PR #92): the 9a rekey exchange, until now
  gated off for relayed peers, completes over the blind relay too
  (`relayed_handshake_init`/`relayed_handshake_resp` cores), preserving FEC
  fate tagging through the relay wrap/unwrap. Previously a relayed session
  simply never rekeyed.
- **REALITY.3–5d** (PR #83, PR #88 — PR #88's branch is named "follow-up
  cleanups" but actually carries REALITY.5b–5d): the Xray-REALITY relay
  transport's authenticated-serving path is now feature-complete. REALITY.3
  finished the server's stolen-cert forging (AIA extension copying, a
  per-SNI anti-replay guard on the auth seal, `--reality-cert-refresh-secs`/
  `--reality-cert-max-stale-secs` staleness bounds). REALITY.4a/4b wired up
  the `yipd` client side: `rendezvous=reality://host:port?pbk=&sid=&sni=`
  dials the relay with a Chrome-faithful crafted ClientHello, and `verify=`
  (default `on`) adds explicit client-side relay verification (pinned leaf
  key + `CertificateVerify` check derived from the shared seal secret) so a
  wrong `pbk`/relay key fails closed with a long jittered backoff instead of
  hammering the wrong host. REALITY.5a–5d then replaced the relay's
  authed-connection TLS serving with a hand-rolled, byte-matching TLS 1.3
  server flight (`yip-utls`'s `RealityStream`) built from a captured template
  of the real destination's own handshake shape — **dropping BoringSSL
  forged acceptors from the authed-serve path** (BoringSSL/`cmake` remain a
  build dependency overall, for the unauthenticated-splice path and
  `transport=tls`). Exercised end-to-end by `run-netns-reality-relay.sh` and
  `run-netns-reality-5d.sh`, including wrong-`pbk` and wrong-relay-key
  negative tests. See `docs/configuration.md` for the full `reality://` /
  `--reality-*` flag reference.
- `#59` MTU-aware packetization investigation findings + measurement tooling
  (PR #94) — **documentation/investigation only**, no code or wire change.
- REALITY.2 (anti-DPI): new pure-Rust `yip-utls` crate — a uTLS-equivalent
  REALITY client that crafts a **byte-faithful latest-Chrome (150) ClientHello**
  (with our own X25519 `key_share` and a REALITY auth seal in `legacy_session_id`)
  and completes a **TLS 1.3 handshake to an application-data stream**, entirely in
  safe Rust (`ring` + `x25519-dalek` + `chacha20poly1305` + `ml-kem`; no Go, no
  BoringSSL, `#![forbid(unsafe_code)]`). The crafted hello is locked to the real
  Chrome JA4 (`t13d1516h2_8daaf6152771_806a8c22fdea`) by a CI diff test, permutes
  its extension order per connection like real Chrome (so JA3 varies), and includes
  a genuine **X25519MLKEM768 post-quantum hybrid** key — the client completes the
  real ML-KEM-768 + X25519 hybrid handshake (verified live against Cloudflare, which
  selects it). The REALITY auth seal/open is now a shared codec used by both this
  client and the `yip-rendezvous` relay (REALITY.1). Standalone library — wired into
  yipd in REALITY.4.
- REALITY-style TLS front for the relay, server side (anti-DPI milestone
  REALITY.1): `yip-rendezvous`'s `--listen-tcp` TLS front gains an opt-in
  full Xray-style REALITY mode — `--reality-dest <host:port>`,
  `--reality-private-key <hex64>`, `--reality-short-id <hex16>` (repeatable),
  `--reality-server-name <name>` (repeatable). The relay reads the raw TLS
  `ClientHello` off the socket *before* terminating TLS and checks for a
  REALITY auth seal — an X25519-ECDH-keyed ChaCha20-Poly1305 seal carried in
  `legacy_session_id`, validated against the relay's REALITY private key, the
  configured `short_id`s, and a ±10-minute timestamp freshness window.
  Authenticated connections are served the relay tunnel (TLS terminated with
  the configured cert, same as the 3c.3 front below); everything else — an
  active prober, a scanner, a plain browser, or any connection without valid
  auth, including malformed/oversized TLS records — is **transparently
  spliced to a real upstream site** (`--reality-dest`, e.g.
  `www.apple.com:443`), replaying the bytes already read, so the prober
  completes a genuine handshake with the real site and sees *its* real cert.
  `--reality-dest` **supersedes `--decoy`** (the 3c.3 self-hosted-backend
  Trojan model) when both are given. **Server side only:** the yip client
  that embeds REALITY auth into its ClientHello is milestone REALITY.2, not
  yet shipped — until it lands, no production client authenticates and the
  relay forwards every live connection to `dest`.
- Port plausibility (anti-DPI 3d, R8/#45): `listen` is now optional and
  auto-defaults every transport to 443 (443/TCP for `tls`, 443/UDP for
  `quic`/`raw`) — the single least-suspicious port — falling back to 8443
  with a warning when binding 443 is denied (grant `CAP_NET_BIND_SERVICE`).
  yipd (and `yip-rendezvous`) warn at config load when a port is a known
  DPI-fingerprinted VPN default (51820/1194/500/4500/1701/1723/655);
  `example.config` no longer ships WireGuard's 51820. Fixes the port-match
  tell (#45).
- REALITY-style Trojan relay front (anti-DPI milestone 3c.3): `yip-rendezvous`
  gains an opt-in TCP/TLS listener (`--listen-tcp`/`--tls-cert`/`--tls-key`/
  `--decoy`) that terminates **real-cert** TLS and routes a fresh, obfuscated
  `Register` (now carrying a monotonic `counter` for replay rejection) to the
  relay tunnel, while transparently reverse-proxying every other connection —
  active probes, scanners, plain browsers — to a real decoy site, so the relay
  is indistinguishable from an ordinary HTTPS server to anyone without
  `obf_psk`. `--obf-psk` is now **required** with `--listen-tcp` (it is the
  tunnel discriminator). `tokio` is added to `yip-rendezvous` — the control/
  relay tier only; the `yipd` data plane stays 100% async-free. **New build
  dependency: `cmake` + a BoringSSL compile, now also required to build
  `yip-rendezvous`** (already required for `yipd` since 3c.2). The `yipd`
  client that dials this front (`rendezvous = "tls://host:443"`) is milestone
  3c.4, not shipped here.
- TLS relay-dial client (`rendezvous = tls://host:443`, anti-DPI 3c.4): a
  `yipd` node reaches the 3c.3 relay over a persistent browser-parrot TLS
  connection (a dedicated thread; the data plane stays tokio-free) and relays
  the unchanged inner protocol through it — so two UDP-blocked peers can
  tunnel to each other. Requires `obf_psk`; poll-driver-only; straight-to-relay
  (no Direct/UDP-punch).
- TLS-over-TCP mimicry transport (`transport=tls`, anti-DPI milestone 3c.2):
  carries the **unchanged** inner yip protocol (Noise-IK, FEC, AEAD) inside a
  real TLS 1.3 connection over TCP/443 with a **browser-parrot ClientHello**
  (BoringSSL via the `boring` crate, GREASE-enabled — a Chrome-shaped JA3/JA4,
  not a Rust-TLS fingerprint), so yip survives UDP-blocked networks and
  classifies as ordinary browser HTTPS. Datagrams are framed length-prefixed
  over the TLS byte-stream; the client/server role is a deterministic
  static-key tiebreak; teardown reconnects with backoff. Opt-in **last-resort**
  path (TCP head-of-line blocking, no FEC benefit — trades yip's latency
  identity for reachability); **mutually exclusive with `obf_psk`**; the
  default raw-UDP path and the `quic` costume are unchanged. New config keys
  `transport=tls` and `tls_sni` (default `www.apple.com`). **New build
  dependency: `cmake` + a BoringSSL compile** (required whenever `yipd` is
  built).
- L2 TAP tunnel mode in `yipd`: config now supports `device_kind=tap` for
  Ethernet (L2) tunnel interfaces; `device_kind=tun` remains the default for
  IP (L3) mode.
- io_uring Phase B driver (`UringDriver`): a single-ring (UDP+TUN) io_uring data
  loop, available **opt-in** via `YIP_USE_URING=1` (the **default is the epoll
  `PollDriver`**). netns CI runs all tunnel tests under **both** drivers. The
  opt-in path was hardened to match `PollDriver`'s robustness contract: `EINTR`
  on the blocking ring wait is retried (a signal no longer tears down the tunnel),
  and non-GSO send-completion errors drop on transient buffer pressure but
  propagate genuinely fatal errors (TUN writes always drop) instead of being
  swallowed forever. (Latency tuning — where io_uring goes from regressing to
  *beating* epoll via adaptive busy-poll — is in the "io_uring driver RTT work"
  entry under Changed; GSO throughput batching is the "io_uring GSO batching"
  entry under Changed.)
- `docs/configuration.md`: a single reference for everything `yipd` reads at
  startup — config-file keys (`device_kind`, keys, endpoints…), the
  `YIP_USE_URING` / `YIP_URING_BUSYPOLL` env knobs, and CLI flags — linked from
  the README.
- Single-threaded data loop (Phase A): replaced the two-thread `Arc<Mutex>`
  data plane with a mutex-free `DataPlane` driven by an `epoll` `PollDriver`
  (io_uring driver to follow). Removes per-packet lock/handoff overhead — tunnel
  RTT ~0.51 ms -> ~0.36 ms; throughput holds. No wire change.
- Adaptive loss-feedback loop + reactive ARQ. The receiver detects post-FEC
  residual loss as gaps in the object counter and reports it (with NACKs) in an
  authenticated `Control` packet; the sender attributes loss per class and drives
  the repair controller. ARQ-eligible (`Bulk`) flows on a clean link now decay
  their repair ratio to **zero**, activating the FEC-encode bypass — clean-link
  single-stream TCP rises from ~273–285 to ~457 Mbit/s. On loss the controller
  re-arms FEC instantly and NACKed `Bulk` objects are retransmitted with fresh
  RaptorQ repair symbols (reusing the original object id); `Realtime`/`Default`
  flows keep a proactive floor and are not retransmitted. New `yip-transport`
  modules: `feedback` (`LossReport`), `lossdetect` (`LossDetector`), `retxbuf`
  (`RetxBuffer`), plus `Transport::repair_object`.

### Fixed
- **Privileged CI jobs declared none of the tooling they drive (PR #156).**
  `catthehacker/ubuntu:act-22.04` — the image every Forgejo Actions job runs
  in — ships no `ip`, `tc`, `ping`, `tcpdump`, `iperf3` or `wg`, and its
  `PATH` already includes `/usr/sbin` and `/sbin`, so these were missing
  packages and never a PATH problem. `netns-tunnel-test` and
  `dpi-undetectability` died at `run-netns-tunnel.sh:86` and
  `run-ndpi-oracle.sh:129` with `ip: command not found`; every retry failed
  identically because the fault was deterministic. `netem-comparison` had
  `ip` only as a transitive *Recommends* of `wireguard-tools` — not a
  dependency — and broke the day that resolution changed. Each job now
  installs what its harness scripts actually run, sized from every script the
  job drives rather than the one that happened to fail first. Also: the scp
  harness creates `/run/sshd` before starting `sshd` (the package postinst
  normally does, but the image ships `sshd` without having run it and `/run`
  is a fresh tmpfs per container), and `start_sshd` now prints sshd's log and
  exit status on failure instead of leaving `-E "$logfile"` output in a file
  the cleanup trap deletes — which is why that failure had surfaced only as
  `harness failed`. A stale comment claiming `tcpdump` was "preinstalled on
  the runner image" is corrected; that belief is why it was never declared.
- **`hardening.41` cert-revocation gave discovery less time than it needs
  (PR #158, #157).** `CERT_A_SECS` was 60 and the establish loop stops 5s
  before expiry to keep the "still valid" invariant honest, leaving a 55s
  convergence window — while `run-netns-discovery.sh:287` documents gossip
  warm-up as needing "up to a 60s budget". The test allocated less time than
  its own sibling says the thing it waits for can take, so a green run was
  one that happened to converge early. Raised to 150s (~2.5x the documented
  worst case); the assertion is unchanged, since the cert still expires
  mid-test.
- Session-lifecycle hardening (#36 path-switch re-handshake + #41 cert
  revocation, PR #95): a path-switch (roaming) no longer discards the
  in-flight handshake ephemeral, both initiator- and responder-side relay
  adoption are covered for a relayed cold-start retransmit, and mesh peers
  now get a periodic cert-liveness sweep plus a re-verify-on-rekey-`Init`
  gate (both exempting root nodes) — so a revoked member's session no longer
  silently keeps working until its next full handshake.
- Root-exempt responder-cert checks (PR #97): responder-side cert checks now
  exempt root nodes symmetrically with the initiator-side gates — a root
  could previously fail a check the initiator side already exempted it from.
- Gossip digest chunking (#44, PR #98): the mesh gossip digest is now
  chunked, and its obfuscation degrades fail-soft, instead of panicking once
  a mesh grows past a single-datagram digest size.
- io_uring loopback recycle tests hardened against default socket buffers
  (PR #113): the recv-buffer and send-slot recycle tests now interleave
  send+drain (bounded in-flight window) instead of blasting all datagrams
  first, so they no longer fail on a box with a default
  `net.core.rmem_default`. The old pattern asserted `>256` datagrams
  round-trip but relied on the kernel buffering that many at once; the default
  ~208 KB receive buffer holds only ~230 small datagrams, so the assert
  failed deterministically on stock-configured machines.

### Changed
- **Sanitized cryptographic key examples and standardized default port 443 (#170, PR #175).**
  Replaced all repetitive dummy key examples (`11111111...`, `22222222...`, `33333333...`) across all configuration files, markdown guides, and CLI references with cryptographically realistic high-entropy hex sequences and explicit zero-trust `yip-ca` certificate workflows. Standardized the default daemon listen port to UDP 443 across all configurations, scripts, and documentation, ensuring out-of-the-box traffic blending with HTTPS/QUIC and evading middlebox port filters targeting standard VPN ports (such as WireGuard's 51820), with automated unprivileged fallback to port 8443. Added live animated terminal telemetry dashboard GIF (`assets/terminal-telemetry.gif`) demonstrating real-time multi-transport mesh status and peer statistics. Recorded best-of-3 automated AWS multi-region WAN benchmarks between `us-east-1` and `us-west-2` under 0% to 10% packet loss.
- Rendezvous relay-forward counter moved off the server's mutex onto a
  shared `AtomicU64` (#68, PR #93) — a pure perf fix (removes lock
  contention on the hot forwarding path under load); no behavior change to
  the `relay-forwarded=<N>` log line.
- **Relicensed from MPL-2.0 to AGPL-3.0-or-later**, copyright FEMBOY CYBER NETWORKS
  LLC. The AGPL network-use clause (§13) means anyone running a modified `yip` as a
  network service must offer their users the corresponding source — privacy
  infrastructure stays open. (Closes #53.)
- README rewritten with the project identity ("what does the fox say? — nothing a
  DPI firewall can hear") and a "Silicon Slopes Paradox" section on Utah SB 73 and
  the EFF's coverage; corrected the lingering "RaptorQ" references to Reed–Solomon
  across README, `CLAUDE.md`, and `yip-transport`/`yip-wire` doc comments (the codec
  was swapped in #50). Repo description + topics added.
- TUN vnet-header GSO/GRO offload on the **poll** hot path (throughput lever 4b):
  the TUN device is opened with `IFF_VNET_HDR` + `TUNSETOFFLOAD` (gated on the poll
  driver — `uring` and QUIC keep a plain TUN), so yipd batches its own TUN I/O.
  On **read**, a kernel-GRO'd super-frame is software-segmented back into MTU
  packets (`split_gro`); on **write**, consecutive same-flow TCP segments are
  merged by a userspace-GRO **coalescer** into one GSO super-frame the kernel
  re-segments — collapsing many per-packet `tun_chr_write_iter` traversals into
  one. The coalescing is **entirely local to the yipd↔kernel-TUN boundary: no
  wire-format, FEC, AEAD, or replay change** (each wire datagram stays one
  encrypted MTU packet); non-coalescible traffic (UDP, pings, flow changes) passes
  through as singletons at zero cost, and an unsupported kernel falls back to plain
  per-packet TUN I/O. A new `crates/yip-io/src/tun_offload.rs` holds the
  `virtio_net_hdr` codec, the coalescer, the splitter, and the partial-checksum
  completion for `F_NEEDS_CSUM` reads (the kernel offloads L4 checksums on large
  reads — completing them before encrypt is load-bearing, or the far end drops the
  packets). `unsafe` stays confined to `yip-io`/`yip-device`. **Real-hardware A/B
  (two 1-core AMD EPYC virtio VPSes, bulk TCP): receiver `tun_chr_write_iter`
  19.0% → 14.6%** — the mechanism cuts the targeted TUN-write cost, though
  end-to-end throughput on that 24 ms-RTT / same-core-`iperf` path is RTT/window-
  capped rather than TUN-CPU-bound, so the full win lands on low-RTT / high-
  throughput single flows. netns ping / 10%-loss / ARQ pass under both drivers;
  TCP-in-tunnel data verified intact. See `crates/yip-bench/RESULTS.md`.
- Send-side UDP GSO on the **poll** hot path (throughput lever 4a): `run_poll`'s
  `flush_tx` now partitions its egress batch into fate-safe runs (same
  destination, same length, pairwise-distinct FEC `fate`) and sends each run as
  one `sendmsg` with a `UDP_SEGMENT` control message, instead of one `sendmmsg`
  datagram-per-packet. The fate-safe grouping rule is factored into a shared
  `yip-io::gso` module (`can_coalesce` / `partition_fate_safe` /
  `max_gso_run_len`); the `UringDriver` GSO path now delegates to it, so both
  drivers enforce **at most one datagram per FEC object per skb** from one
  definition — a dropped GSO super-skb costs each object at most one symbol, so
  FEC per-symbol loss-independence is preserved. Opportunistic and
  latency-neutral (coalesces only what a burst already queued; a lone datagram
  still sends plain). Falls back to plain `send_mmsg` for singletons and, after
  latching a per-`run_poll` "GSO unavailable" flag, whenever the kernel reports
  `UDP_SEGMENT` unsupported (`EIO`/`EINVAL`). Wire-identical; no cipher/handshake/
  wire-format change. **Real-hardware A/B (two 1-core AMD EPYC virtio VPSes):
  +25–31 % end-to-end UDP throughput at equal single-core CPU** (a decision-gate
  spike measured a 2.6× send-path CPU reduction; the end-to-end gain is smaller
  because recv/TUN/conntrack/IRQ costs do not benefit from send-side GSO). netns
  10 %-loss + ARQ recovery verified under both drivers. `unsafe` stays confined to
  `yip-io`. See `crates/yip-bench/RESULTS.md` ("4a send-side GSO").
- Batched UDP I/O on the poll hot path (throughput lever): `run_poll` drains the
  UDP socket with one `recvmmsg` per burst and sends each TUN burst's egress with
  one addressed `sendmmsg` (per-datagram `dst`/`src`), collapsing ~2–3 `sendto`s
  per packet into one syscall per burst. Opportunistic and latency-neutral (batches
  only what epoll already queued). (PR #54.)
- Fast data-plane AEAD (throughput lever): `yip-crypto::Session` seal/open moved
  from snow's RustCrypto ChaCha20-Poly1305 to **`ring`** ChaCha20-Poly1305, keyed by
  snow's secret `Split()` transport keys and Noise's nonce so the output is
  **byte-identical to the previous wire** — **~2.1 µs → 0.6 µs** per packet. Same
  256-bit ChaCha20-Poly1305 cipher; snow is now handshake-only. A durable
  byte-identity KAT guards the equivalence. (PR #52.)
- **FEC codec swapped from RaptorQ to a small-K systematic Reed–Solomon codec**
  (throughput lever): a hand-rolled GF(256) Cauchy RS-v1 codec replaces the
  `raptorq` crate — **encode ~26 µs → ~1.33 µs**. RaptorQ's K′=10 minimum-block
  padding taxed every small packet with ~10 symbols of work, the price of a
  ratelessness yip never uses (`observe_loss` clamps the repair ratio ≤ 1.0). New
  `yip-transport` modules `gf256` + `rs` (exhaustive MDS proof); `raptorq` dropped
  from the dependency tree. Wire `payload_id` now carries a codec tag; `yip-wire`
  framing unchanged. (PR #50.)
- io_uring graceful fallback (issue #25): `run_uring` now falls back to the
  `PollDriver` on any `UringDriver` failure (init or runtime) instead of killing
  the tunnel. Found on a clean Debian 13 (kernel 6.12) box: io_uring's multishot
  UDP recv is rejected there with `EINVAL` and was fatal ~4/6 runs; it works on
  6.18+. Opting into io_uring (`YIP_USE_URING=1`) is now safe on any kernel — it
  degrades to epoll where io_uring is buggy/unsupported. (The re-default question
  is settled: **epoll `PollDriver` stays the default** — io_uring's busy-poll RTT
  win needs bare metal + a dedicated core + a recent kernel, so it remains a
  bare-metal opt-in. See the README "I/O driver" section.)
- io_uring GSO batching (issue #17): the `UringDriver` egress path coalesces
  TUN-egress datagrams into `UDP_SEGMENT` sends again (`MAX_GSO_SEGMENTS_PER_SEND`
  1 → 32), made **FEC-safe** by tagging each egress datagram with its RaptorQ
  object id ("fate") across the `Dispatch::on_tun` boundary (new `EgressDatagram`)
  and coalescing **at most one datagram per fate per skb** — so a dropped GSO
  super-skb never costs an object both its source symbol and its own repair
  (which previously pinned the cap to 1). The invariant is enforced at a single
  unit-tested choke point (`can_coalesce_gso_tagged`); `arq_recovers_bulk_loss`
  stays ≥ 98% delivery under uring with GSO active. No wire-format or
  `yip-transport` API change. (Single-stream throughput is unchanged on
  measurement — that path is FEC/CPU-bound, not syscall-bound; GSO's win is on
  syscall-bound bursts. The ARQ-retransmit egress path is left non-GSO for now.)
- io_uring driver RTT work: the `UringDriver` hot path no longer allocates per
  packet — received datagrams dispatch from a reused scratch buffer, send buffers
  are recycled through a pool, and `poll_once` drains completions into a reused
  vec (matching `PollDriver`, which was already alloc-free). Adds an opt-in
  **busy-poll** mode (`YIP_URING_BUSYPOLL=1`): `poll_once` spins the completion
  queue before blocking, cutting tunnel RTT from ~0.47 ms to ~0.31 ms and
  **beating the epoll `PollDriver` (~0.37 ms)** — a "burn CPU for latency" knob,
  off by default so idle tunnels don't spin. The spin is **adaptive**: it only
  runs while an exchange is active (recent completions) and backs off to a plain
  blocking wait the moment a wait times out, so an idle tunnel burns no CPU while
  an active one still catches imminent completions. (Making it the default /
  tuning the spin budget wants clean-hardware measurement; io_uring stays opt-in.)
  The `UringDriver` blocking wait is now bounded by a 10 ms timeout (via io_uring
  `EXT_ARG`, kernel 5.11+), so `Dispatch::tick` fires on cadence even on a fully
  idle tunnel — parity with poll.rs's `epoll_wait` timeout, fixing a latent gap
  where an idle uring tunnel could starve rekey/feedback timers.
- io_uring cleanup: the `UringDriver` now exposes a `dropped_sends` counter (folded
  into the send-drop logs) so slot-exhaustion drops are observable in aggregate,
  and drops the dead `udp_armed`/`tun_armed` fields. The two provided-buffer/send-
  slot reuse unit tests were made robust to bounded, load-dependent datagram loss
  (they assert pool *reuse* — round-tripping more than the fixed pool holds — plus
  the leak checks, rather than 100% round-trip), so the local suite is fast and
  reliable again.
- Coverage CI: exclude `yip-io/src/uring.rs` from the llvm-cov denominator (honest
  exclusion — the `UringDriver` syscall loop is netns/integration-gated, same
  pattern as `yip-device` privileged paths).
- Data-plane throughput pass: yipd now batches egress sends (`sendmmsg`) and
  ingress reads (`recvmmsg`) through yip-io's `PlainIo`, reuses framing buffers
  (no per-symbol allocation), and sizes `SO_SNDBUF`/`SO_RCVBUF` to 4 MiB via a
  yip-io `set_socket_buffers` helper. `yip-transport` gained a byte-identical
  RaptorQ encode bypass for the zero-repair case (dormant until the controller
  can request zero repair — see `crates/yip-bench/README.md`). yipd is now
  `#![forbid(unsafe_code)]`; `yip-io` pins `libc` exactly.

### Added
- Workspace scaffold with `yip-io`, `yip-wire`, `yip-crypto`, `yip-transport`,
  `yip-device`, and `yipd` crate stubs.
- CI quality gates: build, test, clippy, rustfmt, cargo-shear, cargo-deny,
  coverage, and mutation testing.
- Pre-commit hooks (file hygiene, cargo fmt, clippy, and test).
- Public `README.md` and `docs/architecture.md`.
- `yip-wire` frame codec: header serialization, SipHash coverage-auth tag, and
  keyed header protection, with fuzzing of the deframe path.
- `yip-crypto` Noise-IK handshake (via `snow`) and AEAD `Session` with explicit
  per-frame nonces and a sliding anti-replay window.
- `yip-device` TUN (L3) and TAP (L2) tunnel devices, and `yip-io` io_uring
  DataPlaneIo backend with a portable plain-socket fallback.
- `yip-transport` adaptive RaptorQ FEC: per-flow classifier, object encoder,
  pipelined erasure-tolerant reassembler, and a repair-ratio controller.
- `yip-transport` stateful flow-table heuristic: classifies unmarked flows by
  observed packet size/rate, completing the policy -> DSCP -> heuristic -> default
  precedence chain.
- `yipd` end-to-end tunnel: Noise handshake over UDP, session-derived wire keys,
  and L3 (TUN) traffic tunneled through the encrypted adaptive-FEC transport
  between two static peers (ping-tested across network namespaces).
- `yip-bench`: hot-path micro-benchmarks (AEAD, wire framing, RaptorQ FEC encode)
  via Criterion, and a `tc netem` latency/loss harness comparing the yip tunnel
  against kernel WireGuard (results in `crates/yip-bench/README.md`).

[Unreleased]: https://github.com/femboyisp/yip/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/femboyisp/yip/releases/tag/v0.1.0
