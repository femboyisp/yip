# Anti-DPI 3d — Port plausibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the port fingerprint (R8/#45): stop yip looking like WireGuard-on-51820. Make `listen` optional and auto-default every transport to **443** (443/TCP for `tls`, 443/UDP for `quic`/`raw`), fall back to **8443** with a warning if 443 can't bind, warn on known DPI-fingerprinted VPN ports, and prove the win with the nDPI oracle.

**Architecture:** The port *intent* is resolved at config load (`listen` optional; port defaults to 443 when unspecified; an `listen_port_auto` flag). The 443→8443 `EACCES` fallback happens at the socket bind sites via a small helper. No wire/crypto change — only the bind address.

**Tech Stack:** Rust, `std::net::{UdpSocket, TcpListener, SocketAddr, IpAddr}`, the existing `bin/yipd` config + `tunnel.rs` transport dispatch.

## Global Constraints

- `#![forbid(unsafe_code)]` (yipd); no `as` numeric casts except enum discriminants; no bare `#[allow]` (use `#[expect(reason=)]`).
- **Wire/crypto untouched** — 3d changes ONLY the bind address selection. Nothing on the wire, in Noise/FEC/AEAD, or in the obfuscation layer.
- **Explicit config always wins** — a configured port is honored exactly; 3d only auto-selects when the port is unspecified, and only *warns* (never rejects/overrides) on a configured known-bad port.
- **No ephemeral/random listen port** — auto-selection is always a fixed plausible port (443, or 8443 on fallback).
- **Backward-compatible** — existing `listen=IP:port` configs run identically (plus a warning only if the port is known-bad).
- Warnings are greppable (no themed strings), logged to stderr like the existing `yipd:` / `eprintln!` warnings.

---

### Task 1: Config — known-bad-port lint + optional `listen` (443 default + auto flag)

**Files:**
- Modify: `bin/yipd/src/config.rs` (the `listen` parse + required-check, a new lint fn, a new `listen_port_auto` field)
- Test: inline `#[cfg(test)]` in `config.rs`

**Interfaces:**
- Produces: `pub fn fingerprinted_vpn_port(port: u16) -> Option<&'static str>`; `Config.listen: SocketAddr` (port = 443 when unspecified); `Config.listen_port_auto: bool` (true when the port was auto-selected, so the bind site may fall back to 8443).

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn fingerprinted_vpn_ports_are_flagged() {
        assert_eq!(fingerprinted_vpn_port(51820), Some("WireGuard"));
        assert_eq!(fingerprinted_vpn_port(1194), Some("OpenVPN"));
        assert_eq!(fingerprinted_vpn_port(500), Some("IPsec/IKE"));
        assert_eq!(fingerprinted_vpn_port(4500), Some("IPsec/IKE"));
        assert_eq!(fingerprinted_vpn_port(1701), Some("L2TP"));
        assert_eq!(fingerprinted_vpn_port(1723), Some("PPTP"));
        assert_eq!(fingerprinted_vpn_port(655), Some("tinc"));
        assert_eq!(fingerprinted_vpn_port(443), None);
        assert_eq!(fingerprinted_vpn_port(8443), None);
    }

    #[test]
    fn listen_absent_defaults_to_auto_443() {
        let cfg = Config::parse(
            "local_private=<64hex>\nlocal_public=<64hex>\ndevice=yip0\n[peer]\npublic_key=<64hex>\n",
        )
        .unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:443".parse().unwrap());
        assert!(cfg.listen_port_auto);
    }

    #[test]
    fn listen_ip_only_defaults_port_to_auto_443() {
        let cfg = Config::parse(
            "local_private=<64hex>\nlocal_public=<64hex>\ndevice=yip0\nlisten=127.0.0.1\n[peer]\npublic_key=<64hex>\n",
        )
        .unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:443".parse().unwrap());
        assert!(cfg.listen_port_auto);
    }

    #[test]
    fn listen_explicit_port_is_honored_not_auto() {
        let cfg = Config::parse(
            "local_private=<64hex>\nlocal_public=<64hex>\ndevice=yip0\nlisten=0.0.0.0:9999\n[peer]\npublic_key=<64hex>\n",
        )
        .unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:9999".parse().unwrap());
        assert!(!cfg.listen_port_auto);
    }
```

(Replace `<64hex>` with real 64-hex fixtures copied from an existing passing config test.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yipd --bin yipd config:: 2>&1 | grep -E "fingerprinted|listen_absent|listen_ip_only|listen_explicit"`
Expected: FAIL to compile (`fingerprinted_vpn_port` / `listen_port_auto` missing).

- [ ] **Step 3: Add the lint table**

In `config.rs`:

```rust
/// If `port` is a canonical VPN/tunnel default port that DPI port-matches,
/// return the protocol it makes yip look like; `None` for a plausible port.
/// Used to warn (not reject) at config load — anti-DPI R8 (#45).
pub fn fingerprinted_vpn_port(port: u16) -> Option<&'static str> {
    match port {
        51820 => Some("WireGuard"),
        1194 => Some("OpenVPN"),
        500 | 4500 => Some("IPsec/IKE"),
        1701 => Some("L2TP"),
        1723 => Some("PPTP"),
        655 => Some("tinc"),
        _ => None,
    }
}
```

- [ ] **Step 4: Make `listen` optional with the 443 default + auto flag**

Add the field: `pub listen_port_auto: bool,`. Change the `"listen"` parse arm to accept an IP-only form and record whether the port was explicit:

```rust
                "listen" => {
                    // Accept `IP:port` (explicit) or `IP` (auto port). An
                    // explicit VPN-default port is warned about (R8) but honored.
                    if let Ok(sa) = val.parse::<SocketAddr>() {
                        if let Some(proto) = fingerprinted_vpn_port(sa.port()) {
                            eprintln!(
                                "yipd: listen port {} is {}'s default; DPI classifies yip as {} \
                                 by port regardless of payload — prefer 443 (anti-DPI R8)",
                                sa.port(), proto, proto
                            );
                        }
                        listen = Some(sa);
                        listen_port_auto = false;
                    } else if let Ok(ip) = val.parse::<IpAddr>() {
                        listen = Some(SocketAddr::new(ip, DEFAULT_LISTEN_PORT));
                        listen_port_auto = true;
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid listen address: {val}"),
                        ));
                    }
                }
```

Add locals `let mut listen: Option<SocketAddr> = None;` (already present) and `let mut listen_port_auto = false;`. Add `const DEFAULT_LISTEN_PORT: u16 = 443;` and `const FALLBACK_LISTEN_PORT: u16 = 8443;` (the latter is used by Task 2; define both here). Ensure `use std::net::IpAddr;`.

- [ ] **Step 5: Default `listen` when absent (drop the required-check)**

Just before assembling the `Config`, resolve `listen` + the auto flag into locals
(so neither is used after a move), then use both in the struct literal. Replace
the `listen: listen.ok_or_else(|| missing("listen"))?,` line accordingly:

```rust
        // `listen` absent ⇒ auto-select all interfaces on the plausible default
        // port (443; the 8443 fallback is applied at bind time — see tunnel.rs).
        let listen_port_auto = listen.is_none() || listen_port_auto;
        let listen = listen.unwrap_or_else(|| {
            SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), DEFAULT_LISTEN_PORT)
        });
```

then in the `Config { … }` literal use `listen,` and `listen_port_auto,`. (These
`let` bindings must come after the parse loop and before the `Config` literal.)

- [ ] **Step 6: Fix the existing config tests + example expectations**

Existing config tests set `listen=0.0.0.0:51820` etc. — those still parse (now emitting the WireGuard warning to stderr, which is fine for tests). The `// missing 'listen'` test (config.rs:494) that expected an error must change: absent `listen` is now valid (auto-443). Update that test to assert `cfg.listen_port_auto == true` and `cfg.listen.port() == 443` instead of expecting an error.

- [ ] **Step 7: Run tests + build**

Run: `cargo test -p yipd --bin yipd config::` then `cargo build --workspace`.
Expected: PASS + clean build (the new `listen_port_auto` field is set at every `Config` construction; fix any struct-literal test builders that construct `Config` directly).

- [ ] **Step 8: Commit**

```bash
git add bin/yipd/src/config.rs
git commit -m "feat(yipd): optional listen w/ 443 default + auto flag + VPN-port lint (3d)"
```

---

### Task 2: Bind-with-443-fallback helpers

**Files:**
- Create: `bin/yipd/src/port.rs` (the fallback bind helpers)
- Modify: `bin/yipd/src/main.rs` (`mod port;`)
- Test: inline `#[cfg(test)]` in `port.rs`

**Interfaces:**
- Consumes: `config::FALLBACK_LISTEN_PORT` (8443).
- Produces: `pub(crate) fn bind_udp(addr: SocketAddr, port_auto: bool) -> io::Result<UdpSocket>` and `pub(crate) fn bind_tcp(addr: SocketAddr, port_auto: bool) -> io::Result<TcpListener>` — bind `addr`; if `port_auto` and it fails with `PermissionDenied`, retry on `FALLBACK_LISTEN_PORT` with a greppable warning; otherwise propagate the error.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn bind_udp_explicit_high_port_binds_directly() {
        // An explicit, unprivileged port binds with no fallback.
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0); // 0 = OS-assigned, always bindable
        let sock = bind_udp(addr, false).unwrap();
        assert!(sock.local_addr().is_ok());
    }

    #[test]
    fn bind_tcp_auto_falls_back_when_privileged_port_denied() {
        // As a non-root test process, binding 443 yields PermissionDenied and,
        // with port_auto, falls back to 8443. If the test runs AS root (CI sudo),
        // 443 binds directly — accept either a 443 or 8443 result, but never an error.
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443);
        match bind_tcp(addr, true) {
            Ok(l) => {
                let p = l.local_addr().unwrap().port();
                assert!(p == 443 || p == super::super::config::FALLBACK_LISTEN_PORT);
            }
            Err(e) => panic!("auto bind must not error (443 or 8443): {e}"),
        }
    }
}
```

(If 8443 is itself occupied in the test env, the fallback bind could fail — acceptable to flag; prefer `Ipv4Addr::LOCALHOST` to avoid cross-test interference. Adjust to a per-run unique fallback only if the fixed-8443 test proves flaky.)

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement**

```rust
//! Plausible-port bind helpers (anti-DPI 3d, R8/#45): auto-selected ports try
//! 443 and fall back to 8443 (with a warning) when binding a privileged port is
//! denied. Explicit operator ports never fall back.
use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};

use crate::config::FALLBACK_LISTEN_PORT;

fn fallback_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip(), FALLBACK_LISTEN_PORT)
}

fn warn_fallback(kind: &str, addr: SocketAddr) {
    eprintln!(
        "yipd: cannot bind {kind} {addr} (needs CAP_NET_BIND_SERVICE); using {} — grant it \
         with 'setcap cap_net_bind_service+ep <yipd>' or run privileged (anti-DPI R8)",
        FALLBACK_LISTEN_PORT
    );
}

pub(crate) fn bind_udp(addr: SocketAddr, port_auto: bool) -> io::Result<UdpSocket> {
    match UdpSocket::bind(addr) {
        Ok(s) => Ok(s),
        Err(e) if port_auto && e.kind() == io::ErrorKind::PermissionDenied => {
            warn_fallback("udp", addr);
            UdpSocket::bind(fallback_addr(addr))
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn bind_tcp(addr: SocketAddr, port_auto: bool) -> io::Result<TcpListener> {
    match TcpListener::bind(addr) {
        Ok(s) => Ok(s),
        Err(e) if port_auto && e.kind() == io::ErrorKind::PermissionDenied => {
            warn_fallback("tcp", addr);
            TcpListener::bind(fallback_addr(addr))
        }
        Err(e) => Err(e),
    }
}
```

Make `FALLBACK_LISTEN_PORT` (and `DEFAULT_LISTEN_PORT`) `pub(crate)` in `config.rs`. Add `mod port;` to `main.rs`.

- [ ] **Step 4: Run tests to pass. Step 5: Commit**

```bash
git add bin/yipd/src/port.rs bin/yipd/src/main.rs bin/yipd/src/config.rs
git commit -m "feat(yipd): 443->8443 bind-with-fallback helpers (3d)"
```

---

### Task 3: Wire the fallback into the transport binds

**Files:**
- Modify: `bin/yipd/src/tunnel.rs` (the UDP bind at ~line 58; the `run_tls` dispatch), `bin/yipd/src/tls.rs` (the internal `TcpListener::bind` in `run_tls`'s server path)

**Interfaces:**
- Consumes: `crate::port::{bind_udp, bind_tcp}`, `config.listen`, `config.listen_port_auto`.

- [ ] **Step 1: UDP bind (raw + quic).** In `tunnel.rs`, replace `let sock = UdpSocket::bind(config.listen)?;` (~line 58) with:

```rust
    let sock = crate::port::bind_udp(config.listen, config.listen_port_auto)?;
```

This covers `transport=raw` (run_poll) and `transport=quic` (run_quic) — both use `sock`. (The UDP `sock` is also bound-but-unused on the `transport=tls` and `rendezvous=tls://` paths; binding it on the plausible port is harmless and avoids leaving a 51820 listener open.)

- [ ] **Step 2: TLS transport TCP listener.** `run_tls` (3c.2) binds a `TcpListener` internally for the server role (find `TcpListener::bind(listen)` in `tls.rs`'s `accept_and_handshake` / server setup). Thread the auto flag: change `run_tls(..., listen: SocketAddr, ...)` to also take `port_auto: bool`, and replace its `TcpListener::bind(listen)?` with `crate::port::bind_tcp(listen, port_auto)?`. Update the `run_tls` call in `tunnel.rs` to pass `config.listen_port_auto`.

- [ ] **Step 3: Build + a smoke run**

Run: `cargo build --release -p yipd`. Then a smoke run with an absent-`listen` config (auto-443): `sudo ./target/release/yipd <cfg>` binds 443; a non-root run falls back to 8443 with the warning. Confirm no panic and the warning text for the non-root case.
Expected: builds; auto-443 under sudo, 8443+warning without.

- [ ] **Step 4: Commit**

```bash
git add bin/yipd/src/tunnel.rs bin/yipd/src/tls.rs
git commit -m "feat(yipd): bind transports on the plausible port with 443->8443 fallback (3d)"
```

---

### Task 4: Relay known-bad-port warning

**Files:**
- Modify: `bin/yip-rendezvous/src/main.rs` (warn on its UDP `listen`)

**Interfaces:**
- Consumes: a local copy of the port-lint (the `yip-rendezvous` binary is a separate crate from `yipd`; do NOT add a `yipd` dependency — duplicate the tiny `fingerprinted_vpn_port` match, as `hex_to_32` is already duplicated there per its own comment).

- [ ] **Step 1: Add the lint + warn**

After the `listen` address is finalized in `main`, parse its port and warn:

```rust
    if let Ok(sa) = listen.parse::<std::net::SocketAddr>() {
        if let Some(proto) = fingerprinted_vpn_port(sa.port()) {
            eprintln!(
                "yip-rendezvous: listen port {} is {}'s default; DPI classifies the relay's UDP \
                 traffic as {} by port — prefer a neutral/plausible port (anti-DPI R8)",
                sa.port(), proto, proto
            );
        }
    }
```

with a local `fn fingerprinted_vpn_port(port: u16) -> Option<&'static str>` mirroring Task 1's table.

- [ ] **Step 2: Run + build**

Run: `cargo test -p yip-rendezvous-bin` then `cargo build -p yip-rendezvous-bin`.
Expected: builds; a manual start on `:51820` prints the warning (optional smoke).

- [ ] **Step 3: Commit**

```bash
git add bin/yip-rendezvous/src/main.rs
git commit -m "feat(rendezvous): warn on DPI-fingerprinted VPN listen port (3d)"
```

---

### Task 5: Docs + example rewrite (drop 51820)

**Files:**
- Modify: `example.config`, `docs/configuration.md`, `CHANGELOG.md`

- [ ] **Step 1: `example.config`** — replace `listen=0.0.0.0:51820` with `listen=0.0.0.0` (rely on the 443 default) and a comment block: 443 default per transport, the VPN-port warning, `setcap cap_net_bind_service+ep` for 443, the 8443 fallback. Change peer/endpoint examples off `:51820` → `:443`. Update the rendezvous example off any VPN-default port.

- [ ] **Step 2: `docs/configuration.md`** — change the `listen` row: now **optional**, defaults to `0.0.0.0:443` (auto), with an 8443 fallback; document the VPN-port warning, the `CAP_NET_BIND_SERVICE`/`setcap` requirement for 443, and that an explicit `IP:port` is honored (with a warning only on known-bad ports). Remove the "Missing … `listen` … is a fatal config error" line's `listen` mention.

- [ ] **Step 3: `CHANGELOG.md`** — `### Added`/`### Changed` entry: "Port plausibility (anti-DPI 3d, R8/#45): `listen` is now optional and auto-defaults every transport to 443 (443/TCP for `tls`, 443/UDP for `quic`/`raw`) — the single least-suspicious port — falling back to 8443 with a warning when binding 443 is denied (grant `CAP_NET_BIND_SERVICE`). yipd warns at config load when a port is set to a known DPI-fingerprinted VPN default (51820/1194/500/4500/1701/1723/655); `example.config` no longer ships WireGuard's 51820. Fixes the port-match tell (#45)."

- [ ] **Step 4: Commit**

```bash
git add example.config docs/configuration.md CHANGELOG.md
git commit -m "docs(yipd): document 443 default + port-plausibility (3d)"
```

---

### Task 6: nDPI 443-proof + 51820 contrast

**Files:**
- Create/modify: an nDPI oracle arm (extend `bin/yipd/tests/run-tls-mimicry-oracle.sh` or `run-quic-mimicry-oracle.sh`, or a new `run-port-plausibility-oracle.sh`), + a harness test in `tunnel_netns.rs`; `.github/workflows/integration.yml`

- [ ] **Step 1: The 443 win.** Reuse the 3c.2 (or 3c.1) mimicry-oracle harness but bind the mimicry transport on **443** instead of the neutral port. Assert: `ndpiReader` classifies the flow as the cover protocol (TLS/QUIC), **no WireGuard**, and — the R8 payoff — the `Known Proto on Non Std Port` risk that the neutral-port oracle *reported* is now **ABSENT** (grep the ndpiReader output and assert the string does not appear). This is the concrete proof the port fix works.

- [ ] **Step 2: The 51820 contrast.** Capture obfuscated **raw** yip (obf_psk on) on UDP **51820**, run `ndpiReader`, and assert it classifies as **WireGuard** by port (`grep -i wireguard` present, and/or `Match by port`). This documents the tell #45 describes and justifies the lint. (Reuse `run-ndpi-oracle.sh`'s obf capture harness, changing the port to 51820.)

- [ ] **Step 3: Harness test + run.** Add a root-gated `port_plausibility_oracle` test in `tunnel_netns.rs` (like `tls_classified_as_tls`), building the binaries and running the script; assert exit 0. Run locally under sudo: `sudo bash bin/yipd/tests/run-port-plausibility-oracle.sh <yipd> <ndpiReader>`. Expected: 443 arm shows no Non-Std-Port risk + no WireGuard; 51820 arm shows WireGuard-by-port.

- [ ] **Step 4: CI.** Add the oracle to `integration.yml`'s `dpi-undetectability` job (cmake + ndpiReader already there), honesty-guarded on `^SKIP`/`[FAIL]`.

- [ ] **Step 5: Commit**

```bash
git add bin/yipd/tests/ .github/workflows/integration.yml
git commit -m "test(yipd): nDPI proof — 443 kills the Non-Std-Port risk; 51820 port-matches WireGuard (3d)"
```

---

### Task 7: No-regression

**Files:** none expected (verification; fix in place if a regression appears).

- [ ] **Step 1: Full workspace** — `cargo test --workspace` → 0 failures.
- [ ] **Step 2: Strict clippy** — `cargo clippy --workspace --all-targets -- -D warnings` → clean.
- [ ] **Step 3: Existing netns money tests still pass** — the tunnel/relay/quic/tls netns tests (which use explicit `listen=…` in their scripts) are unchanged; run a representative set under sudo (`ping_across_yipd_tunnel`, `quic_tunnel_ping`, `tls_tunnel_ping`, `relay_path_ping`) — all PASS. The existing neutral-port 3c oracles are unchanged and still pass.
- [ ] **Step 4: Commit** any regression fix (else skip).

---

## Notes for the executor

- **Wire/crypto is untouched.** 3d only changes which address the sockets bind. Do not touch any transport's pump, framing, Noise/FEC/AEAD, or the obfuscation layer.
- **Explicit ports are never overridden.** `port_auto` is the gate: only auto-selected ports (absent/IP-only `listen`) fall back 443→8443; an explicit operator port binds as given and errors if it can't (no silent fallback), with only a warning if it's a known-bad port.
- **The 443 default needs privilege.** yipd already needs `CAP_NET_ADMIN` for TUN, so a privileged run binds 443; the 8443 fallback + `setcap` warning cover the rootless case. The netns CI runs under sudo, so `listen=0.0.0.0` binds 443 there.
- **The oracle is the milestone's point.** Task 6's "Non-Std-Port risk disappears on 443" is the exact R8 win 3c.1/3c.2 deferred — make that assertion real (grep the ndpiReader output for the risk string's absence), not vacuous.
