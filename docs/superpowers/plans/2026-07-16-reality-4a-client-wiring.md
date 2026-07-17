# REALITY.4a — Client Wiring (`reality://` + yip_utls) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the live-proven `yip_utls::connect` REALITY client into yipd's relay-dial path via a new `reality://` rendezvous scheme, so a yipd client tunnels to a peer through a REALITY relay with a Chrome-faithful ClientHello.

**Architecture:** Only the relay-dial thread changes. A new `Rendezvous::Reality` config variant (parsed from `reality://host:port?pbk=&sid=&sni=`) drives a new `relay_client::spawn_reality` thread that hosts a **confined current-thread tokio runtime**: `tokio::TcpStream` → `yip_utls::connect` → `RealityStream`, with an async `select!` pump between that stream and the existing socketpair. The sync/epoll data-plane loop (`run_relay_tls` + `PeerManager`) is untouched and stays tokio-free.

**Tech Stack:** Rust, tokio (current-thread runtime — new dep on yipd, confined to the relay-dial thread), `yip_utls` (REALITY.2, used as-shipped), the existing `yip_obf`/framing helpers.

## Global Constraints

- `yipd` is `#![forbid(unsafe_code)]` (outside `yip-io`/`yip-device`) — NO `unsafe` in any new code.
- NO `as` numeric casts — use `try_from`/`to_be_bytes`/`from_be_bytes`/`usize::from`.
- NO bare `#[allow(...)]` — use `#[expect(reason = "...")]` if a lint must be suppressed.
- The data-plane loop (`relay_client::run_relay_tls` + `PeerManager`) MUST stay tokio-free and unchanged.
- `yip_utls` is used exactly as shipped in REALITY.2 — **no new `yip_utls` API**; do not modify `crates/yip-utls`.
- The outer REALITY TLS is zero-cert-auth by design; the tunnel's security is the inner peer Noise-IK. Do NOT add cert validation (that's REALITY.4b).
- `reality://` requires `obf_psk` (the inner tunnel discriminator), exactly as `tls://` does.
- Xray-style relay verification and the `verify=` param are **out of scope** (REALITY.4b). 4a hard-rejects `verify=`.
- Every task ends green: `cargo test -p yipd`, `cargo clippy -p yipd --all-targets -- -D warnings`, `cargo fmt`.
- This is PR 1 of the REALITY.4a+.4b pair. **Never merge the PR** — open it and leave it for the user.

**Spec:** `docs/superpowers/specs/2026-07-16-reality-4a-client-wiring-design.md`. Read it before starting.

---

### Task 1: `reality://` config scheme (`config.rs`)

Add the `Rendezvous::Reality` variant and its fail-closed parser. No networking — pure config parsing + tests.

**Files:**
- Modify: `bin/yipd/src/config.rs` (add `Reality` variant to `Rendezvous`; add `hex_to_8`; generalize `parse_tls_rendezvous_host_port`; add `reality://` parse in the `"rendezvous"` arm; extend the obf_psk requirement; add tests)

**Interfaces:**
- Produces: `Rendezvous::Reality { host: String, port: u16, pubkey: [u8; 32], short_id: [u8; 8], sni: String }`
- Produces: `pub(crate) fn hex_to_8(hex: &str) -> io::Result<[u8; 8]>`
- Consumes (existing): `hex_to_32`, `hex_nibble`, the `"rendezvous"` match arm, the obf_psk requirement check.

- [ ] **Step 1: Write the failing parse tests**

Add to the `#[cfg(test)]` module in `bin/yipd/src/config.rs`. Use the file's existing test helper style (build a config string, call the loader). Look at the existing `tls://` tests (around the `tls:// rendezvous (3c.4 Task 1)` comment) and mirror their structure — they build a minimal config with `obf_psk` set. The exact loader/helper name is whatever those tls tests call; reuse it verbatim.

```rust
    // ── reality:// rendezvous (REALITY.4a) ──────────────────────────────
    #[test]
    fn reality_rendezvous_parses_all_fields() {
        let cfg = load_config_str(&format!(
            "local_private={LOCAL_PRIV_HEX}\n\
             obf_psk=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
             rendezvous=reality://relay.example.test:8443?pbk={PBK}&sid=0011223344556677&sni=www.microsoft.com\n",
            PBK = "a".repeat(64),
        ))
        .expect("reality:// config parses");
        match cfg.rendezvous {
            Some(Rendezvous::Reality { host, port, pubkey, short_id, sni }) => {
                assert_eq!(host, "relay.example.test");
                assert_eq!(port, 8443);
                assert_eq!(pubkey, [0xAA; 32]);
                assert_eq!(short_id, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
                assert_eq!(sni, "www.microsoft.com");
            }
            other => panic!("expected Rendezvous::Reality, got {other:?}"),
        }
    }

    #[test]
    fn reality_rendezvous_ipv6_host() {
        let cfg = load_config_str(&format!(
            "local_private={LOCAL_PRIV_HEX}\n\
             obf_psk=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
             rendezvous=reality://[2001:db8::1]:443?pbk={PBK}&sid=0011223344556677&sni=a.test\n",
            PBK = "b".repeat(64),
        ))
        .expect("reality:// ipv6 parses");
        match cfg.rendezvous {
            Some(Rendezvous::Reality { host, port, .. }) => {
                assert_eq!(host, "2001:db8::1");
                assert_eq!(port, 443);
            }
            other => panic!("expected Rendezvous::Reality ipv6, got {other:?}"),
        }
    }

    #[test]
    fn reality_rendezvous_rejects_bad_and_missing_params() {
        let base_psk = "obf_psk=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
        // verify= is 4b-only → hard reject
        let with_verify = format!(
            "local_private={LOCAL_PRIV_HEX}\n{base_psk}\
             rendezvous=reality://h.test:443?pbk={p}&sid=0011223344556677&sni=a.test&verify=on\n",
            p = "a".repeat(64), base_psk = base_psk,
        );
        assert!(load_config_str(&with_verify).is_err(), "verify= must be rejected (4b-only)");

        // unknown param
        let unknown = format!(
            "local_private={LOCAL_PRIV_HEX}\n{base_psk}\
             rendezvous=reality://h.test:443?pbk={p}&sid=0011223344556677&sni=a.test&fp=chrome\n",
            p = "a".repeat(64), base_psk = base_psk,
        );
        assert!(load_config_str(&unknown).is_err(), "unknown param must be rejected");

        // short pbk
        let short_pbk = format!(
            "local_private={LOCAL_PRIV_HEX}\n{base_psk}\
             rendezvous=reality://h.test:443?pbk=deadbeef&sid=0011223344556677&sni=a.test\n",
            base_psk = base_psk,
        );
        assert!(load_config_str(&short_pbk).is_err(), "short pbk must be rejected");

        // missing sni
        let no_sni = format!(
            "local_private={LOCAL_PRIV_HEX}\n{base_psk}\
             rendezvous=reality://h.test:443?pbk={p}&sid=0011223344556677\n",
            p = "a".repeat(64), base_psk = base_psk,
        );
        assert!(load_config_str(&no_sni).is_err(), "missing sni must be rejected");

        // no obf_psk
        let no_psk = format!(
            "local_private={LOCAL_PRIV_HEX}\n\
             rendezvous=reality://h.test:443?pbk={p}&sid=0011223344556677&sni=a.test\n",
            p = "a".repeat(64),
        );
        assert!(load_config_str(&no_psk).is_err(), "reality:// without obf_psk must be rejected");
    }

    #[test]
    fn hex_to_8_roundtrip_and_length() {
        assert_eq!(hex_to_8("0011223344556677").unwrap(), [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert!(hex_to_8("00112233").is_err());
        assert!(hex_to_8("zzzzzzzzzzzzzzzz").is_err());
    }
```

Notes for the implementer:
- `LOCAL_PRIV_HEX` and the `load_config_str` helper (or whatever the existing tls tests use) already exist in the test module — reuse them; do not invent new ones. If the existing tests call a differently-named loader, use that name.
- If the existing tls tests construct the config differently (e.g. a temp file), match that exact pattern instead of `load_config_str`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p yipd config::tests::reality_rendezvous config::tests::hex_to_8`
Expected: FAIL — `no variant Reality`, `cannot find function hex_to_8`.

- [ ] **Step 3: Add `hex_to_8` (mirror `hex_to_32`)**

In `bin/yipd/src/config.rs`, next to `hex_to_32`/`hex_to_16`:

```rust
/// Decode a 16-char hex string into 8 bytes (REALITY `sid=<hex16>`).
pub(crate) fn hex_to_8(hex: &str) -> io::Result<[u8; 8]> {
    if hex.len() != 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected 16 hex chars, got {}", hex.len()),
        ));
    }
    let mut out = [0u8; 8];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}
```

- [ ] **Step 4: Add the `Reality` variant + generalize the host:port splitter**

Add the variant to the `Rendezvous` enum:

```rust
pub enum Rendezvous {
    Udp(SocketAddr),
    Tls { host: String, port: u16 },
    /// REALITY relay-dial (REALITY.4a), `rendezvous=reality://host:port?pbk=&sid=&sni=`.
    Reality {
        host: String,
        port: u16,
        /// Relay's REALITY X25519 public key (pinned; `pbk=` 64 hex).
        pubkey: [u8; 32],
        /// Auth short-id (`sid=` 16 hex).
        short_id: [u8; 8],
        /// Borrowed SNI presented in the crafted ClientHello (`sni=`).
        sni: String,
    },
}
```

Generalize the existing `parse_tls_rendezvous_host_port` to be scheme-agnostic (rename to `parse_rendezvous_host_port`, take a `scheme` label for error messages). Replace the function and its one existing `tls://` call site:

```rust
/// Split a scheme-stripped rendezvous value into `(host, port_str)`. Handles a
/// bracketed IPv6 literal (`[::1]:443`) as its own case; the common
/// hostname/IPv4 case is a single `rsplit_once(':')`. `scheme` names the caller
/// (`"tls://"` / `"reality://"`) only for error messages.
fn parse_rendezvous_host_port<'a>(rest: &'a str, scheme: &str) -> io::Result<(String, &'a str)> {
    if let Some(after_bracket) = rest.strip_prefix('[') {
        let (host, tail) = after_bracket.split_once(']').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{scheme} rendezvous has an unterminated IPv6 literal (missing ']')"),
            )
        })?;
        let port_str = tail.strip_prefix(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{scheme} rendezvous IPv6 literal must be followed by :port"),
            )
        })?;
        Ok((host.to_owned(), port_str))
    } else {
        let (host, port_str) = rest.rsplit_once(':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{scheme} rendezvous must be {scheme}host:port"),
            )
        })?;
        Ok((host.to_owned(), port_str))
    }
}
```

Update the existing `tls://` call site to pass `"tls://"` and add a `reality://` branch. In the `"rendezvous"` match arm, the current shape is `if let Some(rest) = val.strip_prefix("tls://") { … Rendezvous::Tls } else { Rendezvous::Udp }`. Restructure to check `reality://` first:

```rust
"rendezvous" => {
    rendezvous = Some(if let Some(rest) = val.strip_prefix("reality://") {
        parse_reality_rendezvous(rest)?
    } else if let Some(rest) = val.strip_prefix("tls://") {
        let (host, port_str) = parse_rendezvous_host_port(rest, "tls://")?;
        let port = port_str.parse::<u16>().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid tls:// port: {e}"))
        })?;
        Rendezvous::Tls { host, port }
    } else {
        Rendezvous::Udp(val.parse::<SocketAddr>().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid rendezvous: {e}"))
        })?)
    });
}
```

(If the existing `tls://` arm already parses the port inline, keep its exact logic — just route it through `parse_rendezvous_host_port(rest, "tls://")`.)

- [ ] **Step 5: Add the `reality://` parser**

Add near the host:port splitter:

```rust
/// Parse a `reality://`-stripped value: `host:port?pbk=<64hex>&sid=<16hex>&sni=<domain>`.
/// Fail-closed: missing/duplicate/unknown params, malformed hex, empty sni, or the
/// 4b-only `verify=` param all error. `verify=` is rejected here (REALITY.4a does no
/// relay verification — that is REALITY.4b).
fn parse_reality_rendezvous(rest: &str) -> io::Result<Rendezvous> {
    let (hostport, query) = rest.split_once('?').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "reality:// rendezvous must be reality://host:port?pbk=&sid=&sni=",
        )
    })?;
    let (host, port_str) = parse_rendezvous_host_port(hostport, "reality://")?;
    let port = port_str.parse::<u16>().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid reality:// port: {e}"))
    })?;

    let mut pbk: Option<[u8; 32]> = None;
    let mut sid: Option<[u8; 8]> = None;
    let mut sni: Option<String> = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("reality:// query param '{pair}' is not key=value"),
            )
        })?;
        match key {
            "pbk" => pbk = Some(hex_to_32(value)?),
            "sid" => sid = Some(hex_to_8(value)?),
            "sni" => {
                if value.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "reality:// sni is empty"));
                }
                sni = Some(value.to_owned());
            }
            "verify" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reality:// verify= is not supported yet (REALITY.4b)",
                ));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("reality:// unknown query param '{other}'"),
                ));
            }
        }
    }

    let pubkey = pbk.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reality:// missing pbk="))?;
    let short_id = sid.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reality:// missing sid="))?;
    let sni = sni.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reality:// missing sni="))?;
    Ok(Rendezvous::Reality { host, port, pubkey, short_id, sni })
}
```

- [ ] **Step 6: Extend the obf_psk requirement to `Reality`**

Find the existing check (around the `rendezvous=tls:// requires obf_psk` message) and widen it to cover both TLS relay schemes:

```rust
if matches!(rendezvous, Some(Rendezvous::Tls { .. } | Rendezvous::Reality { .. })) && obf_psk.is_none() {
    return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "rendezvous=tls://|reality:// requires obf_psk (it is the relay's discriminator)",
    ));
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p yipd config::tests::reality_rendezvous config::tests::hex_to_8`
Expected: PASS (all four reality tests + hex_to_8). Also run `cargo test -p yipd config` to confirm the existing tls/udp tests still pass (the splitter refactor must not break them).

- [ ] **Step 8: Clippy, fmt, commit**

```bash
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt -p yipd
git add bin/yipd/src/config.rs
git commit -m "feat(reality.4a): reality:// rendezvous scheme (pbk/sid/sni, fail-closed, verify-reject)"
```

---

### Task 2: async REALITY relay-dial (`relay_client.rs` + `Cargo.toml`)

Add tokio + yip_utls deps and `spawn_reality`: a confined current-thread tokio runtime that dials the relay with `yip_utls::connect` and pumps frames between `RealityStream` and the socketpair. Reuses the existing framing/Register/backoff helpers.

**Files:**
- Modify: `bin/yipd/Cargo.toml` (add `tokio` + `yip-utls` deps)
- Modify: `bin/yipd/src/relay_client.rs` (add `spawn_reality` + the async reconnect loop + async pump + an in-process test)

**Interfaces:**
- Consumes (existing `pub(crate)` in this crate): `build_register(obf_key, node, counter) -> Vec<u8>`, `Counter::seeded_now()`/`next()`, `crate::tls::frame_datagram(dg, &mut out)`, `crate::tls::FrameReader` (`push`/`next`), `REG_KEEPALIVE_MS`, `INITIAL_BACKOFF_MS`, `MAX_BACKOFF_MS`, `TLS_FRAME_MAX`.
- Consumes (external): `yip_utls::connect(stream, sni, &pubkey, short_id) -> Result<RealityStream<S>, _>`.
- Produces: `pub(crate) fn spawn_reality(host: String, port: u16, pubkey: [u8; 32], short_id: [u8; 8], sni: String, obf_key: [u8; 16], self_node: NodeId, sock: UnixDatagram)` — spawns the relay-dial thread.

- [ ] **Step 1: Add deps to `bin/yipd/Cargo.toml`**

Under `[dependencies]`:

```toml
# REALITY.4a: the relay-dial thread hosts a CONFINED current-thread tokio
# runtime to drive yip_utls's async REALITY client. The data-plane loop
# (run_relay_tls + PeerManager) stays sync/epoll and tokio-free. tokio already
# enters yipd transitively via yip-utls, so this is not a new heavyweight dep.
tokio = { version = "1", features = ["rt", "net", "time", "io-util", "sync", "macros"] }
yip-utls = { path = "../../crates/yip-utls" }
```

- [ ] **Step 2: Write the failing in-process test**

Mirror the existing `relay_client_registers_first_and_pipes_relay_deliver_to_data_plane` test (find it in the `#[cfg(test)]` module — it stands up a loopback `TcpListener` + a boring server acceptor, accepts one connection, and asserts Register-first + inbound piping). Add a REALITY variant that drives `spawn_reality` against a **plain local boring TLS 1.3 server** — `yip_utls::connect` completes zero-cert-auth against any TLS 1.3 server (it proved this against Cloudflare in REALITY.2), so this exercises the real handshake + pump + framing offline, without a REALITY-aware server.

```rust
    /// REALITY.4a: `spawn_reality` completes a real `yip_utls` TLS 1.3 handshake
    /// against a plain local boring server (zero-cert-auth, so any TLS 1.3 server
    /// works), sends `Register` as the first frame, and pipes an inbound obf'd
    /// frame through to the data-plane socketpair end — proving handshake + pump
    /// + framing independent of REALITY auth (which the netns test covers).
    #[test]
    fn spawn_reality_handshakes_registers_first_and_pipes_inbound() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local_addr");
        let sni = "relay.example.test";
        let obf_key = yip_obf::derive_key(&[9u8; 32]);
        let self_node = yip_rendezvous::node_id(&[1u8; 32]);

        // Data-plane end of the socketpair, with a read timeout so a hang fails loudly.
        let (relay_sock, data_plane_sock) = UnixDatagram::pair().expect("socketpair");
        data_plane_sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");

        // Stub relay: accept one TLS connection, read the first frame (Register),
        // then send one obf'd RelayDeliver frame back.
        let server_obf = obf_key;
        let server = std::thread::spawn(move || {
            let acceptor = crate::tls::build_server_acceptor(sni).expect("server acceptor");
            let (tcp, _peer) = listener.accept().expect("accept");
            let mut tls = acceptor.accept(tcp).expect("server tls accept");
            // Read the client's first framed message (the Register) so the pump
            // is past Register-first before we send anything back.
            let mut hdr = [0u8; 2];
            read_exact_ssl(&mut tls, &mut hdr);
            let len = usize::from(u16::from_be_bytes(hdr));
            let mut body = vec![0u8; len];
            read_exact_ssl(&mut tls, &mut body);
            // Send an inbound obf'd datagram, framed, and hold the conn open briefly.
            let deliver = yip_obf::obfuscate(&server_obf, yip_obf::RDV_TYPE, b"inbound-proof", 0);
            let mut framed = Vec::new();
            crate::tls::frame_datagram(&deliver, &mut framed).expect("frame");
            blocking_write_all_tls(&mut tls, &framed);
            std::thread::sleep(Duration::from_millis(300));
        });

        spawn_reality(
            "127.0.0.1".to_string(),
            addr.port(),
            [0u8; 32], // pbk: unused by a plain TLS server (zero-cert-auth handshake still completes)
            [0u8; 8],
            sni.to_string(),
            obf_key,
            self_node,
            relay_sock,
        );

        // The data-plane end must receive exactly the inbound datagram (deobf'd on
        // the data plane in production; here we just prove the framed bytes arrived
        // as one datagram).
        let mut buf = [0u8; TLS_FRAME_MAX];
        let n = data_plane_sock.recv(&mut buf).expect("recv inbound within 5s");
        let got = yip_obf::deobfuscate(&obf_key, &buf[..n]);
        assert_eq!(got.map(|(_t, b)| b), Some(b"inbound-proof".to_vec()));
        server.join().expect("server thread");
    }
```

If a `read_exact_ssl` helper doesn't already exist in the test module, add a small one next to `blocking_write_all_tls`:

```rust
    fn read_exact_ssl(stream: &mut SslStream<TcpStream>, mut buf: &mut [u8]) {
        while !buf.is_empty() {
            let n = stream.ssl_read(buf).expect("ssl_read");
            buf = &mut buf[n..];
        }
    }
```

(If `build_server_acceptor`/`blocking_write_all_tls` live under different names, use whatever the existing relay test uses — read that test first and match it.)

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p yipd relay_client::tests::spawn_reality_handshakes`
Expected: FAIL — `cannot find function spawn_reality`.

- [ ] **Step 4: Implement `spawn_reality` + the async loop/pump**

Add to `bin/yipd/src/relay_client.rs`. Keep `use` additions at the top of the file.

```rust
/// Spawn the REALITY relay-dial client thread (REALITY.4a). Mirrors [`spawn`]
/// but dials via `yip_utls::connect` (a Chrome-faithful REALITY ClientHello +
/// TLS 1.3 handshake) instead of boring, driven by a CONFINED current-thread
/// tokio runtime. The data-plane loop (`run_relay_tls` + `PeerManager`) is a
/// separate thread and stays sync/epoll/tokio-free.
///
/// The outer REALITY TLS is zero-cert-auth by design (the camouflage). The
/// tunnel's confidentiality/integrity come from the end-to-end peer Noise-IK,
/// so an outer MITM / malicious relay sees only inner peer ciphertext and can
/// at worst DoS. REALITY.4b adds explicit Xray-style relay verification on top.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the existing sync `spawn`; the dial parameters are all distinct config-derived values"
)]
pub(crate) fn spawn_reality(
    host: String,
    port: u16,
    pubkey: [u8; 32],
    short_id: [u8; 8],
    sni: String,
    obf_key: [u8; 16],
    self_node: NodeId,
    sock: UnixDatagram,
) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("relay_client(reality): failed to build tokio runtime: {e}");
                return;
            }
        };
        rt.block_on(run_reality(&host, port, &pubkey, short_id, &sni, &obf_key, self_node, sock));
    });
}

/// The async reconnect-with-backoff loop for the REALITY relay-dial thread.
#[expect(
    clippy::too_many_arguments,
    reason = "parameters mirror `spawn_reality`; threading them is clearer than a struct here"
)]
async fn run_reality(
    host: &str,
    port: u16,
    pubkey: &[u8; 32],
    short_id: [u8; 8],
    sni: &str,
    obf_key: &[u8; 16],
    self_node: NodeId,
    sock: UnixDatagram,
) {
    // Wrap the socketpair as tokio (datagram boundaries preserved by SOCK_DGRAM).
    if let Err(e) = sock.set_nonblocking(true) {
        eprintln!("relay_client(reality): set_nonblocking failed: {e}");
        return;
    }
    let sock = match tokio::net::UnixDatagram::from_std(sock) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("relay_client(reality): tokio UnixDatagram wrap failed: {e}");
            return;
        }
    };
    let mut counter = Counter::seeded_now();
    let mut backoff_ms = INITIAL_BACKOFF_MS;

    loop {
        let tcp = match tokio::net::TcpStream::connect((host, port)).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("relay_client(reality): connect to {host}:{port} failed: {e}");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }
        };
        // Disable Nagle: the pump issues many small writes; Nagle+delayed-ACK
        // would add ~40ms latency, gratuitous on a latency-sensitive VPN.
        let _ = tcp.set_nodelay(true);

        let stream = match yip_utls::connect(tcp, sni, pubkey, short_id).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("relay_client(reality): REALITY handshake to {sni} failed: {e}");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                continue;
            }
        };
        // Handshake done → reset backoff for the next disconnect.
        backoff_ms = INITIAL_BACKOFF_MS;

        if let Err(e) = pump_reality(stream, &sock, obf_key, self_node, &mut counter).await {
            eprintln!("relay_client(reality): connection error, reconnecting: {e}");
        }
        // Loop back and reconnect (fresh backoff since the last connection did
        // complete a handshake + Register).
    }
}

/// The steady-state async pump: Register-first, then `select!` between the
/// `RealityStream` (inbound relay frames → socketpair), the socketpair
/// (outbound datagrams → framed → RealityStream), and a keepalive timer
/// (re-`Register`). Returns on any stream error/EOF so the caller reconnects.
async fn pump_reality<S>(
    mut stream: yip_utls::RealityStream<S>,
    sock: &tokio::net::UnixDatagram,
    obf_key: &[u8; 16],
    self_node: NodeId,
    counter: &mut Counter,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Register FIRST — the relay classifies the connection on its first frame.
    let reg = build_register(obf_key, self_node, counter.next());
    stream.write_all(&reg).await?;

    let mut reader = crate::tls::FrameReader::default();
    let mut tls_read_buf = [0u8; TLS_FRAME_MAX];
    let mut sock_read_buf = [0u8; TLS_FRAME_MAX];
    let mut keepalive = tokio::time::interval(Duration::from_millis(REG_KEEPALIVE_MS));
    keepalive.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            r = stream.read(&mut tls_read_buf) => {
                let n = r?;
                if n == 0 {
                    return Ok(()); // relay closed → reconnect
                }
                reader.push(&tls_read_buf[..n]);
                while let Some(dg) = reader.next()? {
                    // One datagram → one socketpair send (SOCK_DGRAM atomic).
                    sock.send(&dg).await?;
                }
            }
            r = sock.recv(&mut sock_read_buf) => {
                let n = r?;
                let mut framed = Vec::new();
                crate::tls::frame_datagram(&sock_read_buf[..n], &mut framed)?;
                stream.write_all(&framed).await?;
            }
            _ = keepalive.tick() => {
                let reg = build_register(obf_key, self_node, counter.next());
                stream.write_all(&reg).await?;
            }
        }
    }
}
```

Notes:
- `crate::tls::FrameReader` has a private `buf: Vec<u8>`. If it does not already `#[derive(Default)]`, add `#[derive(Default)]` to the struct in `bin/yipd/src/tls.rs` (single `Vec<u8>` field — trivially defaultable) so `FrameReader::default()` works. Do not add any other constructor.
- Confirm `yip_utls::RealityStream` is re-exported at the crate root (`yip_utls::RealityStream`). If it lives at `yip_utls::stream::RealityStream`, use that path; check `crates/yip-utls/src/lib.rs` re-exports.
- Do not touch `run`, `run_relay_tls`, or any `PeerManager` code.

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p yipd relay_client::tests::spawn_reality_handshakes`
Expected: PASS. Then `cargo test -p yipd relay_client` to confirm the existing sync `spawn` test still passes.

- [ ] **Step 6: Clippy, fmt, commit**

```bash
cargo clippy -p yipd --all-targets -- -D warnings
cargo fmt -p yipd
git add bin/yipd/Cargo.toml bin/yipd/src/relay_client.rs bin/yipd/src/tls.rs
git commit -m "feat(reality.4a): async REALITY relay-dial via yip_utls on a confined tokio runtime"
```

---

### Task 3: wire the `Reality` arm + netns money/wrong-pubkey tests + docs (`tunnel.rs`, tests, docs)

Reach the new dial path from config, prove it end-to-end through a real REALITY relay, and document the scheme.

**Files:**
- Modify: `bin/yipd/src/tunnel.rs` (add the `Rendezvous::Reality` match arm mirroring the `Tls` arm)
- Create: `bin/yipd/tests/run-netns-reality-relay.sh` (netns money + wrong-pubkey tests)
- Modify: `bin/yipd/example.config` (commented `reality://` example)
- Modify: `docs/configuration.md` (the `reality://` scheme)

**Interfaces:**
- Consumes: `relay_client::spawn_reality` (Task 2), `Rendezvous::Reality` (Task 1), the existing `run_relay_tls`, `UnixDatagram::pair`, `node_id`.

- [ ] **Step 1: Add the `Rendezvous::Reality` arm in `tunnel.rs`**

Find the `Some(crate::config::Rendezvous::Tls { host, port }) => { … }` arm and the block below it that creates the socketpair, calls `relay_client::spawn(...)`, and returns `run_relay_tls(...)`. Add a parallel arm for `Reality`. It resolves the relay address the same way, then spawns `spawn_reality` (which carries pubkey/short_id/sni from the config) and enters the identical `run_relay_tls` data-plane loop.

Because the two arms share the socketpair + `run_relay_tls` tail, structure it so the `Reality` arm reuses that tail. Concretely, in the match that currently special-cases `Tls`, add:

```rust
        Some(crate::config::Rendezvous::Reality { host, port, pubkey, short_id, sni }) => {
            let relay_addr = (host.as_str(), *port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("rendezvous relay {host}:{port} resolved to no addresses"),
                    )
                })?;
            relay_reality = Some((host.clone(), *port, *pubkey, *short_id, sni.clone(), relay_addr));
            Some(
                Box::new(crate::rendezvous::TlsRelayRendezvous::new(relay_addr))
                    as Box<dyn crate::rendezvous::Rendezvous>,
            )
        }
```

Then, next to the existing block that consumes `relay_tls` (the `if let Some((host, port, relay_addr)) = relay_tls { … spawn(...) ; return run_relay_tls(...) }`), add the mirror for `relay_reality`. Reuse `obf_key` (required, enforced at config load), `self_node`, and the same `UnixDatagram::pair()` + `run_relay_tls` tail:

```rust
    if let Some((host, port, pubkey, short_id, sni, relay_addr)) = relay_reality {
        let obf_key = obf_key
            .expect("rendezvous=reality:// requires obf_psk (enforced at config load)");
        let self_node = yip_rendezvous::node_id(&config.local_public);
        let (relay_thread_sock, data_plane_sock) = UnixDatagram::pair()?;
        crate::relay_client::spawn_reality(
            host, port, pubkey, short_id, sni, obf_key, self_node, relay_thread_sock,
        );
        return crate::relay_client::run_relay_tls(tun_fd, &mut manager, relay_addr, data_plane_sock);
    }
```

Declare `let mut relay_reality: Option<(String, u16, [u8; 32], [u8; 8], String, SocketAddr)> = None;` alongside the existing `relay_tls` declaration. Match the existing arm's exact surrounding style (it may bind into a tuple var like `relay_tls`; mirror that). The `run_relay_tls` call is byte-for-byte the same as the `Tls` path — the data plane is scheme-agnostic.

- [ ] **Step 2: Verify it compiles and the whole unit suite is green**

Run: `cargo test -p yipd`
Expected: PASS (Task 1 + Task 2 tests + existing). Run `cargo clippy -p yipd --all-targets -- -D warnings` — clean.

- [ ] **Step 3: Write the netns money + wrong-pubkey test script**

Create `bin/yipd/tests/run-netns-reality-relay.sh`. Model it on the existing 3c.4 `run-netns-relay-tls.sh` (read that script first — reuse its netns setup, its UDP-blocking, its `yip-rendezvous` relay launch, and its ping/assert helpers). The only differences: the relay is launched with the REALITY flags, and the two clients use `rendezvous=reality://…` with the relay's real `pbk`/`sid`/`sni`.

Key content (adapt exact netns/veth/naming to the existing script):

```bash
#!/usr/bin/env bash
# REALITY.4a netns money test: two UDP-blocked yipd peers bring a tunnel up
# THROUGH a REALITY relay (yip-rendezvous --reality-*), and A pings B. Also a
# wrong-pubkey negative test: a mismatched pbk yields NO tunnel (the relay
# splices the client to `dest`).
set -euo pipefail

# ... (reuse run-netns-relay-tls.sh's netns/veth/cleanup scaffolding) ...

REALITY_PRIV="1111111111111111111111111111111111111111111111111111111111111111"
# The matching public key for REALITY_PRIV (X25519). Compute once and pin it
# here; the script asserts it is 64 hex. (Derivable via `yipd`'s keygen or a
# one-liner; hardcode the known pair used by the existing reality tests.)
REALITY_PUB="<64-hex X25519 public key for REALITY_PRIV>"
SHORT_ID="00112233445566ff"
SNI="www.microsoft.com"
DEST="127.0.0.1:9"   # a closed/refusing dest is fine for the money test:
                     # authed clients never reach the splice path.
OBF_PSK="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

# Relay (in its own netns), REALITY front on :8443:
ip netns exec "$NS_RELAY" ./target/release/yip-rendezvous "$RELAY_UDP" \
  --listen-tcp 0.0.0.0:8443 \
  --obf-psk "$OBF_PSK" \
  --reality-dest "$DEST" \
  --reality-private-key "$REALITY_PRIV" \
  --reality-short-id "$SHORT_ID" \
  --reality-server-name "$SNI" &
# ... wait for :8443 ...

# Peer A config (reality://), UDP blocked so it MUST relay:
cat > "$CONF_A" <<EOF
local_private=$A_PRIV
obf_psk=$OBF_PSK
listen=0.0.0.0:0
device=yipA
peers=$B_PUB
rendezvous=reality://$RELAY_IP:8443?pbk=$REALITY_PUB&sid=$SHORT_ID&sni=$SNI
EOF
# ... same for B ...

# Bring up both yipd, ping A→B through the relay, assert success + relay-forwarded>0
# (reuse the existing script's assertion that the relay counted forwards).

# ---- Negative: wrong pbk → no tunnel ----
# Rewrite A's config with a bogus pbk (all-zeros), restart A, and assert the
# ping FAILS within a bounded timeout (the relay's seal-open fails → the client
# is spliced to DEST → no relay path).
```

Add the exact `REALITY_PUB` for `REALITY_PRIV` by reusing the known keypair the existing reality tests already use (grep the repo for `--reality-private-key`/`reality_priv` test fixtures, or compute it via yipd's key derivation). Do not leave it as a placeholder — pin the real 64-hex value. Mark the script executable (`chmod +x`).

- [ ] **Step 4: Run the netns test (requires root/netns; skip cleanly if unavailable)**

Run: `sudo bash bin/yipd/tests/run-netns-reality-relay.sh` (after `cargo build --release -p yipd -p yip-rendezvous-bin`)
Expected: the money test prints success (A→B ping through the relay, relay-forwarded > 0) and the wrong-pubkey test prints that the ping failed as expected. If netns/root is unavailable in the environment, note that the script is written and must be run in a netns-capable CI job (mirror how `run-netns-relay-tls.sh` is gated in `integration.yml`).

- [ ] **Step 5: Wire the script into CI (mirror the existing netns job)**

In the CI workflow that runs `run-netns-relay-tls.sh` (grep `.github/workflows/` for it — likely `integration.yml`), add a step that runs `run-netns-reality-relay.sh` the same way (same build deps: it needs both `yipd` and `yip-rendezvous-bin` release binaries + cmake for boring). Keep it in the existing netns/integration job.

- [ ] **Step 6: Docs — `example.config` + `configuration.md`**

In `bin/yipd/example.config`, next to the commented `tls://` rendezvous example, add:

```
# REALITY relay-dial (REALITY.4a): dial the relay with a Chrome-faithful REALITY
# ClientHello. Requires obf_psk. pbk = relay's REALITY public key (64 hex),
# sid = auth short-id (16 hex), sni = the borrowed domain to present.
# The outer TLS is zero-cert-auth (the camouflage); the tunnel is secured by the
# inner peer handshake. REALITY.4b adds optional relay verification (verify=).
# rendezvous=reality://relay.example.com:443?pbk=<64hex>&sid=<16hex>&sni=www.microsoft.com
```

In `docs/configuration.md`, in the rendezvous section (find where `tls://` is documented), add a `reality://` subsection: the URL form, the three required params, the `obf_psk` requirement, the zero-cert-auth / inner-Noise-IK security note, and that `verify=` is reserved for REALITY.4b (currently rejected).

- [ ] **Step 7: Full suite, clippy, fmt, commit**

Run: `cargo test -p yipd && cargo clippy -p yipd --all-targets -- -D warnings`
Expected: PASS / clean.

```bash
cargo fmt -p yipd
git add bin/yipd/src/tunnel.rs bin/yipd/tests/run-netns-reality-relay.sh bin/yipd/example.config docs/configuration.md .github/workflows/
git commit -m "feat(reality.4a): wire reality:// into tunnel dispatch + netns money/wrong-pubkey tests + docs"
```

---

## Self-Review

**1. Spec coverage:**
- §1 `reality://` scheme + `Rendezvous::Reality` + fail-closed parse + IPv6 + verify-reject + unknown-param-reject + obf_psk req → Task 1. ✓
- §2 Approach-A async relay-dial (confined runtime, `yip_utls::connect`, async pump, Register-first, reconnect/backoff, keepalive, framing unchanged) → Task 2. ✓
- §3 zero-cert-auth handling (documented caveat + wrong-pubkey no-tunnel test) → Task 2 module doc + Task 3 netns negative test. ✓
- §4 `tunnel.rs` Reality arm → Task 3. ✓
- Testing (config units, netns money, wrong-pubkey, JA3/JA4 inherited) → Tasks 1 + 3 (JA4 is REALITY.2's, unchanged). ✓
- Docs (example.config, configuration.md) → Task 3. ✓
- Non-goals (4b verify, data-plane changes) respected — no task touches `run_relay_tls`/`PeerManager`/`yip_utls`. ✓

**2. Placeholder scan:** Two intentional fill-ins in Task 3's netns script (`REALITY_PUB` hex and the exact netns scaffolding) are explicitly flagged with how to resolve them (reuse the existing test keypair / model on `run-netns-relay-tls.sh`) rather than left vague — the implementer pins the real value. No code-step placeholders.

**3. Type consistency:** `Rendezvous::Reality { host, port, pubkey: [u8;32], short_id: [u8;8], sni }` (Task 1) is consumed with those exact field types/names in `tunnel.rs` (Task 3) and passed to `spawn_reality(host, port, pubkey, short_id, sni, obf_key, self_node, sock)` (Task 2). `build_register`/`Counter`/`FrameReader`/`frame_datagram`/`REG_KEEPALIVE_MS`/`INITIAL_BACKOFF_MS`/`MAX_BACKOFF_MS`/`TLS_FRAME_MAX` are all existing `pub(crate)` symbols used as-is. `hex_to_8` defined in Task 1, used in Task 1's parser.

**Flags for the user at handoff:**
1. **`FrameReader` may need a `#[derive(Default)]`** added in `tls.rs` (Task 2) — a one-line, behavior-neutral change to an existing struct. OK?
2. **`yip_utls::RealityStream` import path** — the plan assumes it's re-exported at `yip_utls::RealityStream`; the implementer verifies against `crates/yip-utls/src/lib.rs` and uses the real path.
3. **The netns test needs the real X25519 public key** for the fixed `--reality-private-key` — reused from the existing reality test fixtures, pinned in the script (not a placeholder).
