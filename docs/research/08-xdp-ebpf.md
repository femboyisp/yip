# XDP / eBPF — reference notes for yip-io + shared xdp-io

These notes synthesize three sources to inform yip's planned AF_XDP zero-copy backend in `yip-io` and the `xdp-io` crate shared with the `blackwall` firewall. Section 3 (testing) is the load-bearing one for us.

## 1. xdpcap — debugging/observability for XDP programs

xdpcap (Cloudflare) is a tcpdump replacement for XDP. The problem it solves: XDP runs at the driver level, *before* the kernel network stack, so packets an XDP program drops or redirects are invisible to `tcpdump` and other stack-level tooling ([cloudflare.com/xdpcap](https://blog.cloudflare.com/xdpcap/)).

**How it hooks (tail-call to a capture program at return points):** instead of modifying the target program's logic, xdpcap rewrites each XDP *return* so the program tail-calls into a `BPF_MAP_TYPE_PROG_ARRAY` keyed by the intended action — index 0 = `XDP_ABORTED`, 1 = `XDP_DROP`, 2 = `XDP_PASS`, 3 = `XDP_TX`. Each slot holds a filter program that is hard-coded to return that same action, so the original verdict is preserved while a capture hook runs at the exact exit point ([cloudflare.com/xdpcap](https://blog.cloudflare.com/xdpcap/)). Filters are written in ordinary libpcap syntax (e.g. `"ip and udp port 53"`) and compiled to eBPF via Cloudflare's open-sourced **cbpfc** compiler, which emits the verifier-required bounds checks and byte-swaps. Matched packets reach userspace through the `perf_event_output` helper, which ships the packet plus metadata (including the original action) over a perf ring buffer to be written as a pcap or piped to tcpdump live ([cloudflare.com/xdpcap](https://blog.cloudflare.com/xdpcap/)).

**Reusable for yip/blackwall:** the prog-array-indexed-by-verdict pattern is a clean, low-overhead debug hook we can build into `xdp-io` once and share. For yip's AF_XDP datapath it lets us observe encrypted/FEC frames that get dropped or TX'd before the stack sees them; for blackwall it lets us confirm *which* fast-drop rule discarded a packet during an attack, without a separate capture path. Adopt the convention of structuring XDP programs so every return is a single tail-call site that an optional capture array can be slotted into.

## 2. Stateful XDP firewall patterns (lapeyre)

The lapeyre article ([blog.lapeyre.ovh](https://blog.lapeyre.ovh/building-a-high-performance-stateful-firewall-with-xdp-and-bgp-part-1-df1d3cacecf0)) was only partially retrievable (the body is gated behind a Medium redirect; only the intro rendered). What it establishes: a **fast-path / slow-path split** — XDP makes per-packet decisions at the driver level ("sub-microsecond latency, kernel-bypass efficiency", "millions of packets per second"), while **goBGP** runs in userspace as the control plane for dynamic route advertisement and policy updates, with zone-based stateful connection tracking. Details below are the standard pattern for this architecture, since the article's specifics were inaccessible.

**State in eBPF maps:** conntrack state is kept in a `BPF_MAP_TYPE_LRU_HASH` keyed by the 5-tuple; LRU is chosen because it auto-evicts the oldest entries when full, bounding memory and surviving connection floods without manual GC. The XDP program looks up the tuple, allows established flows (`XDP_PASS`), and applies policy to new ones.

**Fast-path/control-plane split:** XDP is the data plane making verdicts; the userspace daemon owns policy. The two communicate *only* through shared maps — userspace writes blocklists/policy into maps that XDP reads per-packet. This keeps the hot path branch-light.

**BGP integration:** goBGP injects/withdraws routes and implements Remote-Triggered Black Hole (RTBH) — under attack, the control plane advertises a blackhole route and/or populates a drop map that XDP enforces with `XDP_DROP` at line rate.

**Patterns for `xdp-io` / blackwall DDoS fast-drop:** (a) map-mediated control/data split, never syscalls on the hot path; (b) LRU hash for any per-flow state so attack traffic can't exhaust it; (c) a dedicated drop-set map populated by userspace (from BGP/RTBH or local detection) and read first in the XDP program so the cheapest `XDP_DROP` happens earliest. `xdp-io` should expose these maps as typed Rust handles both projects share.

## 3. Unit-testing eBPF programs (mranv) — most important for us

The core mechanism is the **`BPF_PROG_RUN`** bpf() command (formerly `BPF_PROG_TEST_RUN`), which executes an eBPF program in a userspace sandbox with a synthetic packet — no NIC, no namespace, fully CI-friendly ([mranv.pages.dev](https://mranv.pages.dev/posts/unit-testing-ebpf-programs/)). libbpf wraps it as `bpf_prog_test_run_opts(prog_fd, &opts)`.

**The opts struct** carries `data_in`/`data_size_in` (input packet), `data_out`/`data_size_out` (mutated packet captured back), `retval` (the XDP verdict the program returned), `duration` (ns), `repeat` (iterations), and `ctx_in`/`ctx_out` ([mranv.pages.dev](https://mranv.pages.dev/posts/unit-testing-ebpf-programs/)).

**Synthetic packets** are built by laying real headers over a byte buffer — cast an `ethhdr` at offset 0, an `iphdr` after it, set `h_proto = htons(ETH_P_IP)`, `ip->protocol`, `saddr`/`daddr`, then append L4 — giving a precise, repeatable fixture per test case.

**Asserting verdicts:** the program's return is read back as `opts.retval` and compared against the standard codes — `XDP_ABORTED` 0, `XDP_DROP` 1, `XDP_PASS` 2, `XDP_TX` 3, `XDP_REDIRECT` 4 (e.g. `ASSERT_EQ(opts.retval, XDP_DROP)`) ([mranv.pages.dev](https://mranv.pages.dev/posts/unit-testing-ebpf-programs/)).

**Asserting map state:** maps populated *during* the run stay queryable afterward — `bpf_object__find_map_by_name` then `bpf_map_lookup_elem(map_fd, &key, value)` — so a test can run one packet and assert that a conntrack/drop entry was created with the expected value. This is exactly how we'd test that blackwall's fast-drop inserted a blocked tuple, or that yip's RX path recorded a peer.

**Rust tooling:** two options. **aya** gives pure-Rust load/attach (`Ebpf::load`, `program_mut::<Xdp>`, `.load()`, `.attach(...)`) with no C toolchain. **libbpf-rs** wraps C libbpf (`ObjectBuilder::build_from_file`, `obj.program(...).test_run(&opts)`), exposing `bpf_test_run_opts` directly ([mranv.pages.dev](https://mranv.pages.dev/posts/unit-testing-ebpf-programs/)).

**Benchmarking:** set `repeat` high (e.g. 1,000,000) and divide `opts.duration` by the count for ns/packet — a cheap regression guard on hot-path cost.

**CI wiring:** build with `clang -target bpf -O2`, run the test binary under `sudo` (or `CAP_BPF` + `CAP_PERFMON` on Linux 5.8+), and gate on kernel version — `BPF_PROG_RUN` for XDP needs ≥ 5.1 ([mranv.pages.dev](https://mranv.pages.dev/posts/unit-testing-ebpf-programs/)). GitHub Actions Ubuntu runners satisfy this.

## 4. Takeaways for yip's AF_XDP backend + shared `xdp-io` crate

- **Test strategy:** make `BPF_PROG_RUN` the unit-test foundation for `xdp-io` — synthetic packet in, assert `retval` verdict + map state out. No live NIC, runs on stock GitHub Actions runners under `sudo`/`CAP_BPF`, gated on kernel ≥ 5.1. Add `repeat`-based microbenchmarks as a per-packet cost regression guard.
- **Toolchain choice:** prefer **aya** for a pure-Rust build (no clang/libbpf C dependency, idiomatic for a Rust VPN); keep `libbpf-rs` in mind only if we need a C feature aya lacks. Decide once in `xdp-io` so yip and blackwall share it.
- **Map design:** standardize on `BPF_MAP_TYPE_LRU_HASH` for all per-flow state (yip peer/conntrack, blackwall conntrack) so floods can't exhaust it; expose maps as typed Rust handles; enforce a strict control-plane-writes / data-plane-reads split with *no* syscalls on the hot path.
- **Fast-drop ordering:** read a userspace-populated drop-set map first in the XDP program so the cheapest `XDP_DROP` is the earliest branch — directly serves blackwall's DDoS path and protects yip from junk.
- **Debug hooks:** build the xdpcap-style verdict-indexed `PROG_ARRAY` tail-call convention into `xdp-io` so both projects get tcpdump-grade visibility into pre-stack drops/TX for free; structure every XDP return as a single tail-call site.
- **Cautions:** (1) The lapeyre article was paywall-truncated — verify its exact conntrack/BGP specifics against the full text before quoting in a spec; the patterns above are the well-established defaults, not its literal claims. (2) AF_XDP zero-copy needs driver `XDP_ZEROCOPY` support — test environments and many CI VMs only offer SKB/generic mode, so separate functional tests (`BPF_PROG_RUN`, mode-agnostic) from zero-copy performance tests (real NIC). (3) `BPF_PROG_RUN` validates program logic but not the full XDP attach/redirect path — keep a thin integration layer of veth-based tests for that.

Sources: [cloudflare.com/xdpcap](https://blog.cloudflare.com/xdpcap/), [blog.lapeyre.ovh — stateful XDP+BGP firewall (partially accessible)](https://blog.lapeyre.ovh/building-a-high-performance-stateful-firewall-with-xdp-and-bgp-part-1-df1d3cacecf0), [mranv.pages.dev — unit testing eBPF](https://mranv.pages.dev/posts/unit-testing-ebpf-programs/).
