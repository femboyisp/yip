# Documentation Has Moved: Architecture & Internals

> [!IMPORTANT]
> The `docs/architecture.md` document has been substantially reorganized and expanded into our canonical architecture and technical design guide. This document is maintained for link compatibility.

## Canonical Guide

Please refer to:

- **[`03-architecture.md`](03-architecture.md)**: Exhaustive architectural reference for the `yip` overlay network protocol, including the zero-copy AF_XDP and `io_uring` packet pipeline, systematic Cauchy Reed-Solomon FEC engine, post-quantum hybrid Noise-IK handshake, RFC 9591 FROST decentralized threshold CA, and 4-mode anti-DPI subsystem.

---

### Full Documentation Curriculum

- **[01. Getting Started & Quickstart](01-getting-started.md)**: Operational onboarding, prerequisites, and first tunnel setup.
- **[02. Configuration Reference](02-configuration.md)**: Complete parameter, flag, and deployment reference.
- **[03. Architecture & Internals](03-architecture.md)**: Wire format, FEC pipeline, engine state machines, and data-plane design.
- **[04. Security & Threat Model](04-security-and-threat-model.md)**: Cryptographic guarantees, session state, key ratchets, and threat mitigations.
- **[05. Benchmarking & Performance](05-benchmarking-and-performance.md)**: Benchmarks, methodology, comparative evaluations, and netem loss recovery.
- **[06. Troubleshooting Runbook](06-troubleshooting.md)**: Diagnostic flowcharts, common pitfalls, and telemetry inspection.
