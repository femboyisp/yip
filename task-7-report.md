## 2026-07-02: Uring GSO default re-enable + netns parity

- Branch: `feat/uring-phase-b`
- Status: complete
- Change: `UringDriver` now starts with `gso_enabled: true`; GSO completion handling retries fallback datagrams on errors/partial sends; ARQ resend path (`on_udp`) uses per-datagram sends; TUN egress keeps GSO path enabled.
- Safety cap: `MAX_GSO_SEGMENTS_PER_SEND=1` keeps UDP_SEGMENT path on while preventing lossy coalesced bursts under `tc netem` in `arq_recovers_bulk_loss`.

### Required gates

- `cargo test -p yip-io uring` -> pass
- `cargo clippy -p yip-io -- -D warnings` -> pass
- `cargo build --release -p yipd` -> pass

### Netns runs (root)

- default / `ping_across_yipd_tunnel` -> pass
- default / `ping_across_yipd_tunnel_under_loss` -> pass
- default / `arq_recovers_bulk_loss` -> pass (`19837/20000`, `99.2%`, ARQ retransmits `152`)
- `YIP_FORCE_POLL=1` / `ping_across_yipd_tunnel` -> pass
- `YIP_FORCE_POLL=1` / `ping_across_yipd_tunnel_under_loss` -> pass
- `YIP_FORCE_POLL=1` / `arq_recovers_bulk_loss` -> pass (`19836/20000`, `99.2%`, ARQ retransmits `163`)
