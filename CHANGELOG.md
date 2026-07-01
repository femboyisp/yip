# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
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

### Changed
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
