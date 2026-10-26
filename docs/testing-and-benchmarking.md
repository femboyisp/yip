# Documentation Has Moved: Testing & Benchmarking

> [!IMPORTANT]
> The `docs/testing-and-benchmarking.md` document has been substantially expanded and restructured into our canonical performance and benchmarking guide. This document is maintained for link compatibility.

## Canonical Guide

Please refer to:

- **[`05-benchmarking-and-performance.md`](05-benchmarking-and-performance.md)**: Comprehensive guide for running and reproducing unit tests, network namespace integration tests, netem loss-injection benchmarks, comparative evaluations against WireGuard/OpenVPN/n2n, and SVG generation pipelines.

### Quick Verification Commands

- **Unit Tests**: `cargo test --workspace`
- **Integration Tests (root)**: `cargo test --test tunnel_netns`
- **Performance Benchmarks**: `cargo bench -p yip-bench`
- **Verify Benchmark SVGs**: `python3 crates/yip-bench/generate-graphs.py --check`

---

### Full Documentation Curriculum

- **[01 — Getting Started & Quickstart](01-getting-started.md)**: Operational onboarding and quickstarts.
- **[02 — Configuration Reference](02-configuration.md)**: Complete parameter, flag, and deployment reference.
- **[03 — Architecture & Internals](03-architecture.md)**: Wire format, FEC pipeline, engine state machines, and data-plane design.
- **[04 — Security & Threat Model](04-security-and-threat-model.md)**: Cryptographic guarantees, session state, key ratchets, and threat mitigations.
- **[05 — Benchmarking & Performance](05-benchmarking-and-performance.md)**: Benchmarks, methodology, comparative evaluations, and netem loss recovery.
- **[06 — Troubleshooting Runbook](06-troubleshooting.md)**: Diagnostic flowcharts, error resolutions, and operational mitigation procedures.
