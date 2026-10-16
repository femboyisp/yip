# Multi-Engine DPI Verification Harness (Zeek, Suricata, tshark, nDPI)

- **Issue:** #70 (R9+: multi-engine DPI verification harness)
- **Status:** Approved
- **Date:** 2026-10-15
- **Branch:** `feat/multi-engine-dpi-harness`

---

## 1. Background & Motivation

`yip` is designed to be resilient against modern Deep Packet Inspection (DPI) and traffic analysis by state-level and enterprise adversaries. Currently, the continuous integration suite gates obfuscation and mimicry using a single DPI engine: `nDPI` (`ndpiReader`, pinned commit `6dcb2622`). While nDPI is a standard library for protocol classification and risk scoring, single-engine evaluation leaves significant blind spots:
1. **Diverse Dissection Engines:** Adversarial middleboxes, enterprise firewalls, and ISP taps run heterogeneous detection stacks, including signature-based Intrusion Detection Systems (Suricata/Snort), deep protocol parsing state machines (Zeek / Bro), and deep packet dissection trees (tshark / Wireshark).
2. **Distinct Behavioral Heuristics:**
   - **nDPI** relies on C-level pattern scanners, entropy thresholds, and flow risk flags (`NDPI_OBFUSCATED_TRAFFIC`, `NDPI_SUSPICIOUS_ENTROPY`).
   - **tshark** applies strict RFC protocol hierarchy dissection (`io,phs`) and protocol tree validation (e.g. valid QUIC long/short headers, TLS extension parsing).
   - **Suricata** applies rule-based signature matching (`eve.json` alerts) and application protocol tracking (`app_proto`) to identify known VPNs (WireGuard, OpenVPN, Tor, Shadowsocks).
   - **Zeek** performs stateful protocol analysis, logging structured connection metadata (`conn.log`), certificate validation (`ssl.log`), and behavioral anomaly notices (`notice.log`).

Issue #70 addresses this by establishing an offline, 4-engine industry panel (**nDPI + tshark + Suricata + Zeek**) that analyzes real network captures across all four of `yip`'s supported transport modes (`raw/obf`, `quic`, `tls`, and `relay`).

---

## 2. Architecture & Pipeline Overview

The verification harness is orchestrated by [`bin/yipd/tests/run-multi-dpi-oracle.sh`](file:///home/zoa/projects/femboy/yip/bin/yipd/tests/run-multi-dpi-oracle.sh).

```
                      ┌────────────────────────────────────────┐
                      │    Capture / Ingestion Phase           │
                      │  (Generates or takes PCAPs for:        │
                      │   1. raw/obf, 2. quic, 3. tls, 4. relay)│
                      └──────────────────┬─────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │    Multi-Engine Evaluation Pipeline    │
                      └───────┬──────────┬──────────┬──────────┘
                              │          │          │
                 ┌────────────┴─┐ ┌──────┴─────┐ ┌──┴───────────┐ ┌────────────┐
                 │  nDPI Reader │ │   tshark   │ │   Suricata   │ │    Zeek    │
                 │ (Deep Inspect│ │ (Protocol  │ │ (IDS Rules   │ │ (Protocol  │
                 │  + Risk Flags│ │  Hierarchy │ │  + EVE Log)  │ │  Analyzer  │
                 │    -v 2)     │ │   & Dissect│ │  eve.json)   │ │ conn/notice│
                 └────────────┬─┘ └──────┬─────┘ └──┬───────────┘ └──────┬─────┘
                              │          │          │                    │
                              └──────────┴──────────┴────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │     Unified Verdict Table & Gating     │
                      │   - Per-(transport, engine) matrix     │
                      │   - Exit 0 if all PASS, 1 if any FAIL  │
                      └────────────────────────────────────────┘
```

The runner operates in two modes:
1. **Self-Capture Mode (Root / CI):** Automatically boots isolated network namespace (`netns`) pairs across veth interfaces, runs real `yipd` handshakes + data ping exchanges, and captures PCAP traces with `tcpdump`.
2. **Pre-Captured Mode (Rootless / Ingestion):** Accepts an input directory of PCAPs (`--pcap-dir <dir>` or individual `--obf-pcap`, `--quic-pcap`, `--tls-pcap`, `--relay-pcap`), allowing fast offline re-evaluation across engines without needing `CAP_NET_ADMIN`.

---

## 3. The 4 Evaluated Transports

1. **`raw/obf`**: Direct obfuscated UDP transport running on a neutral port (`34567`). Noise-IK handshake + continuous BLAKE3-keyed stream cipher / AEAD payload.
2. **`quic`**: QUIC mimicry transport (`quinn-proto` wrapper, ALPN `h3`, SNI `www.cloudflare.com`).
3. **`tls`**: TLS 1.3 REALITY / Costume transport (BoringSSL client mimicry, browser-parrot ClientHello, GREASE, SNI `gateway.icloud.com`).
4. **`relay`**: Authenticated Relay Trojan front (`yip-rendezvous`), multiplexing control + inner encrypted tunnel over TLS on port `443`.

---

## 4. Per-Engine Verdict Criteria & Gating Rules

The harness computes a 16-cell evaluation matrix ($4 \times 4$). Every cell must satisfy its pass conditions:

### 4.1. Transport: `raw/obf` (Direct Obfuscated UDP on neutral port)
- **nDPI**:
  - Gated: Flow protocol must be `Unknown`. Zero detection of WireGuard, OpenVPN, Tor, or any VPN/tunneling protocol.
  - Gated: Zero `NDPI_OBFUSCATED_TRAFFIC` flow risk.
  - Report-Only: `NDPI_SUSPICIOUS_ENTROPY` is reported but not gated (high entropy is mathematically expected on pure ciphertexts).
- **tshark**:
  - Gated: Protocol hierarchy (`frame.protocols`) must parse strictly as generic UDP/data (e.g. `eth:ip:udp:data`).
  - Gated: Zero invocation of dissectors: `wireguard`, `openvpn`, `socks`, `ssh`, etc.
- **Suricata**:
  - Gated: `eve.json` alerts count = 0 (0 matching VPN/tunnel/proxy signatures).
  - Gated: `app_proto` must be `failed` or null (unrecognized generic UDP).
- **Zeek**:
  - Gated: `notice.log` contains 0 tunnel/anomaly notices.
  - Gated: `conn.log` service field is empty (`"-"`), indicating no recognized L7 protocol.

### 4.2. Transport: `quic` (QUIC Mimicry)
- **nDPI**:
  - Gated: Flow protocol must be `QUIC`.
  - Gated: Zero VPN/tunnel classifications.
  - Gated: Zero `NDPI_SUSPICIOUS_ENTROPY` and zero `NDPI_OBFUSCATED_TRAFFIC` risks.
- **tshark**:
  - Gated: `frame.protocols` contains `quic`.
  - Gated: Dissects Initial, Handshake, and 1-RTT short header packets cleanly without dissection errors.
  - Gated: Zero VPN dissector matches.
- **Suricata**:
  - Gated: `eve.json` alerts count = 0.
  - Gated: `app_proto` identified as `quic` (or clean UDP without tunnel alerts).
- **Zeek**:
  - Gated: `notice.log` contains 0 tunnel notices.
  - Gated: `conn.log` service contains `quic` (or recognizes initial connection tokens cleanly).

### 4.3. Transport: `tls` (TLS 1.3 REALITY / Costume Mimicry)
- **nDPI**:
  - Gated: Flow classified as `TLS` / `TLS.Generic`.
  - Gated: Detected SNI matches configured target (`gateway.icloud.com`).
  - Gated: Zero VPN or `NDPI_OBFUSCATED_TRAFFIC` risks.
  - Gated: Zero `NDPI_SUSPICIOUS_ENTROPY` risk.
- **tshark**:
  - Gated: `frame.protocols` contains `tls` or `ssl`.
  - Gated: `tls.handshake.extensions_server_name` matches configured target SNI.
  - Gated: Zero VPN dissector matches.
- **Suricata**:
  - Gated: `eve.json` alerts count = 0.
  - Gated: `tls` event in `eve.json` with `sni` matching configured target.
- **Zeek**:
  - Gated: `notice.log` contains 0 tunnel notices.
  - Gated: `conn.log` service is `ssl`.
  - Gated: `ssl.log` contains `server_name` matching configured target SNI.

### 4.4. Transport: `relay` (Authenticated Relay Trojan Front)
- **nDPI**:
  - Gated: Classified as `TLS`.
  - Gated: Zero WireGuard or YIP internal markers.
- **tshark**:
  - Gated: Dissects cleanly as `eth:ip:tcp:tls`. Zero unencrypted frame leakage.
- **Suricata**:
  - Gated: `eve.json` alerts count = 0.
  - Gated: `app_proto` = `tls`.
- **Zeek**:
  - Gated: `notice.log` contains 0 tunnel notices.
  - Gated: `conn.log` service is `ssl`.

---

## 5. Harness Script & Diagnostics Output

[`bin/yipd/tests/run-multi-dpi-oracle.sh`](file:///home/zoa/projects/femboy/yip/bin/yipd/tests/run-multi-dpi-oracle.sh) produces:
1. **Interactive Console Progress & Diffs**: Clear PASS / FAIL logs per transport and per engine.
2. **Structured Artifact Directory**:
   - `artifacts/pcaps/{raw-obf,quic,tls,relay}.pcap`
   - `artifacts/ndpi/{raw-obf,quic,tls,relay}.log`
   - `artifacts/tshark/{raw-obf,quic,tls,relay}-phs.txt`
   - `artifacts/suricata/{raw-obf,quic,tls,relay}/eve.json`
   - `artifacts/zeek/{raw-obf,quic,tls,relay}/{conn,ssl,notice}.log`
   - `artifacts/verdict-summary.md`
3. **Markdown Summary Table**:
```markdown
| Transport | nDPI Verdict | tshark Verdict | Suricata Verdict | Zeek Verdict | Overall |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `raw/obf` | PASS (Unknown) | PASS (Data/UDP) | PASS (0 alerts) | PASS (0 notices) | **PASS** |
| `quic` | PASS (QUIC) | PASS (quic) | PASS (0 alerts, quic) | PASS (0 notices, quic) | **PASS** |
| `tls` | PASS (TLS+SNI) | PASS (tls+SNI) | PASS (0 alerts, tls) | PASS (0 notices, ssl) | **PASS** |
| `relay` | PASS (TLS Front) | PASS (tls+SNI) | PASS (0 alerts) | PASS (0 notices, ssl) | **PASS** |
```

---

## 6. CI Integration & Toolchain Pinning

In [`.github/workflows/integration.yml`](file:///home/zoa/projects/femboy/yip/.github/workflows/integration.yml), the `dpi-undetectability` job is updated:
1. **Toolchain Installation**:
   - `tshark`: Non-interactive apt installation.
   - `suricata`: Standard Ubuntu package.
   - `zeek`: Pinned LTS release from official openSUSE OBS repository (`http://download.opensuse.org/repositories/security:/zeek/`).
   - `ndpiReader`: Built from pinned commit `6dcb2622360edb28304d76b2f6a25984b706c618`.
2. **Honesty Guards**:
   - Asserts all 4 engines execute for real in CI (fails if any engine skips due to missing binaries).
   - Asserts exit code `0` from `run-multi-dpi-oracle.sh`.
3. **Artifact Upload**:
   - Uses `actions/upload-artifact@v4` with a 14-day retention period for `artifacts/`.

---

## 7. Security & Invariant Guarantees

- **Zero Wire Format / Protocol Changes**: Existing wire formats, cryptosystems, and state machines remain unmodified.
- **Strictly Safe Code**: `#![forbid(unsafe_code)]` remains intact across all workspace crates.
- **Replay & Probe Resistance**: Verifies that active probing or decoy classification continues to hide internal topology.
