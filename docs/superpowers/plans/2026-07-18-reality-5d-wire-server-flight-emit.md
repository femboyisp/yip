# REALITY.5d — wire the hand-rolled server flight into the relay — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the BoringSSL `SslAcceptor` on the relay's authed REALITY path with the hand-rolled 5b `emit_server_hello` + 5c `serve`, so the relay serves a dest-faithful server flight — closing the last passive-DPI gap.

**Architecture:** Four changes in `yip-rendezvous`: expose the group-4588 x25519 tail in `ClientHelloInfo`; genericize the `conn.rs` connection pump over `AsyncRead+AsyncWrite` (so it accepts a `RealityStream`); rewrite `tls_front::run_reality_conn`'s `Decision::Accept` branch to forge a leaf + emit the ServerHello + `serve` the flight (deleting the dead BoringSSL acceptor builders); and a netns money test proving a real `verify=on` client tunnels through.

**Tech Stack:** Rust, `yip-rendezvous` bin crate, `yip_utls` (5b/5c/4b/3 primitives), `rcgen` (leaf forge), `tokio` (async), `getrandom` (OS CSPRNG).

## Global Constraints

- `#![forbid(unsafe_code)]` (outside yip-io/yip-device) — NO `unsafe`, NO `as` casts, NO bare `#[allow]` (use `#[expect(reason = "...")]`).
- Reuse REALITY.5b `emit_server_hello` / 5c `serve` / 4b `auth::derive_cert_key` / 3 `forge_leaf` **unchanged** — this PR calls them, it does not modify them.
- Fail-closed: **pre-write** failures (no template, unsupported group, missing client share, forge/emit error) → **splice** to dest; **post-write** failures (`serve`/timeout/IO after the ServerHello is on the wire) → **drop** (log). No panic on the connection path — every slice is bounded (`rec.get(5..)`), every `Option`/`Result` matched.
- `serve` is bounded by `HANDSHAKE_TIMEOUT` (the CCS-drain is otherwise unbounded).
- The ServerHello rng is an OS-CSPRNG-backed `RandomSource` — never seeded/deterministic.
- NO client changes (4a/4b shipped); NO anti-replay changes (`decide_authed`/`ReplayGuard`); NO 5b/5c construction changes; NO P256/P384+HRR (#84 — such a group → splice); NO exact leaf-length padding (natural leaf, user decision); do NOT drop the `boring` dependency.
- Every task: `cargo test -p yip-rendezvous-bin` green (plus the netns script for Task 4), `cargo clippy -p yip-rendezvous-bin --all-targets -- -D warnings` clean, `cargo fmt`.
- Branch stacked on 5c (PR #86). Leave the PR for the user; do NOT merge; no "not merging" line.
- **Known pre-existing flake (NOT yours):** the pre-commit hook runs the whole workspace suite, which fails only on two `yip-io::uring::tests::uring_*` loopback tests (237 < 256 datagrams under load, unrelated crate, confirmed on clean base). If the commit is blocked *solely* by those, commit with `--no-verify` and say so. Any `yip-rendezvous`/`yip-utls` failure is yours.

---

### Task 1: Expose the group-4588 x25519 tail in `ClientHelloInfo`

The authed path keys the group-4588 TLS DH against the x25519 bundled in the client's 4588 key_share entry (`mlkem_ek(1184) ‖ x25519(32)`), not the standalone `0x001d` entry. The parser already walks that entry for the ML-KEM ek; also capture its trailing 32 bytes.

**Files:**
- Modify: `bin/yip-rendezvous/src/reality.rs` (`ClientHelloInfo` struct; `parse_extensions`/`parse_key_share_mlkem_ek` area; every `ClientHelloInfo { .. }` construction site — `grep -c "ClientHelloInfo {"` reports **11**)

**Interfaces:**
- Produces: `ClientHelloInfo { …, pub key_share_mlkem_x25519: Option<[u8; 32]> }` — the trailing 32-byte x25519 of the group-4588 key_share entry; `None` when there is no valid 4588 entry.

- [ ] **Step 1: Write the failing tests**

Add to `reality.rs`'s `#[cfg(test)] mod tests`. The existing `build_test_client_hello_with_4588_key_share(mlkem_ek, standalone_x25519, hybrid_x25519)` helper already builds a 4588 entry whose tail is `hybrid_x25519` distinct from the standalone `0x001d` entry — reuse it:

```rust
    #[test]
    fn parse_client_hello_extracts_mlkem_x25519_tail() {
        let mlkem_ek = vec![0xABu8; 1184];
        let standalone_x25519 = [0xCDu8; 32];
        let hybrid_x25519 = [0xEEu8; 32];
        let ch = build_test_client_hello_with_4588_key_share(
            &mlkem_ek,
            &standalone_x25519,
            &hybrid_x25519,
        );
        let info = parse_client_hello(&ch).expect("parse");
        // The 4588 tail is the hybrid x25519, NOT the standalone 0x001d one.
        assert_eq!(info.key_share_mlkem_x25519, Some(hybrid_x25519));
        assert_eq!(info.key_share_x25519, Some(standalone_x25519));
        assert_eq!(info.key_share_mlkem_ek.as_deref(), Some(&mlkem_ek[..]));
    }

    #[test]
    fn parse_client_hello_mlkem_x25519_wrong_length_is_none() {
        // A 4588 entry that isn't exactly 1184+32 = 1216 bytes → tail is None
        // (same gate as key_share_mlkem_ek).
        let wrong_key = vec![0xEFu8; 100];
        let mut entries = Vec::new();
        entries.extend_from_slice(&super::GROUP_X25519MLKEM768.to_be_bytes());
        entries.extend_from_slice(&u16::try_from(wrong_key.len()).unwrap().to_be_bytes());
        entries.extend_from_slice(&wrong_key);
        let mut ks_body = Vec::new();
        ks_body.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_be_bytes());
        ks_body.extend_from_slice(&entries);
        let mut exts = Vec::new();
        exts.extend_from_slice(&super::EXT_KEY_SHARE.to_be_bytes());
        exts.extend_from_slice(&u16::try_from(ks_body.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&ks_body);
        let msg = build_client_hello_with_raw_exts([12u8; 32], &[13u8; 32], &exts);
        let info = parse_client_hello(&msg).expect("rest of hello still parses");
        assert_eq!(info.key_share_mlkem_x25519, None);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-rendezvous-bin --bin yip-rendezvous reality::tests::parse_client_hello_extracts_mlkem_x25519_tail`
Expected: FAIL — no field `key_share_mlkem_x25519`.

- [ ] **Step 3: Add the field + extract the tail**

Add `pub key_share_mlkem_x25519: Option<[u8; 32]>` to `ClientHelloInfo` (with a doc comment mirroring `key_share_mlkem_ek`'s). The existing `parse_key_share_mlkem_ek` finds the group-4588 entry and returns its first 1184 bytes when the entry is exactly `1184 + 32` bytes. Extend the extraction so the SAME parse also yields the trailing 32 bytes. The cleanest shape: a single helper that returns both, e.g.

```rust
/// From the `key_share` extension body, find the group-4588 entry
/// (`mlkem_ek(1184) ‖ x25519(32)`, exactly 1216 bytes) and return
/// `(mlkem_ek: Vec<u8>, x25519_tail: [u8; 32])`. Any other length or a
/// missing entry → `None` (fail-closed, bounded `.get(..)`).
fn parse_key_share_mlkem768(body: &[u8]) -> Option<(Vec<u8>, [u8; 32])> {
    let shares_len = usize::from(u16_be(body.get(..2)?)?);
    let mut entries = body.get(2..2 + shares_len)?;
    while !entries.is_empty() {
        let group = u16_be(entries.get(..2)?)?;
        let key_len = usize::from(u16_be(entries.get(2..4)?)?);
        let key_bytes = entries.get(4..4 + key_len)?;
        if group == GROUP_X25519MLKEM768 && key_bytes.len() == MLKEM768_EK_LEN + 32 {
            let ek = key_bytes.get(..MLKEM768_EK_LEN)?.to_vec();
            let tail: [u8; 32] = key_bytes.get(MLKEM768_EK_LEN..)?.try_into().ok()?;
            return Some((ek, tail));
        }
        entries = entries.get(4 + key_len..)?;
    }
    None
}
```

Replace the current `key_share_mlkem_ek` extraction call so both fields come from this one walk (e.g. `let (ek, tail) = parse_key_share_mlkem768(body).map_or((None, None), |(e, t)| (Some(e), Some(t)));`), keeping the existing `parse_extensions` return-tuple shape (extend it with the tail, or set both on the `ClientHelloInfo`). Use the existing `GROUP_X25519MLKEM768` / `MLKEM768_EK_LEN` constants (already defined for Task-5b work; if `MLKEM768_EK_LEN` isn't a local const, use the literal `1184` as the existing `key_share_mlkem_ek` code does). **Initialize `key_share_mlkem_x25519` at every `ClientHelloInfo { .. }` site** — the real one in `parse_client_hello` (to the parsed value) and all test sites (to `None`). `cargo build -p yip-rendezvous-bin` fails until all 11 are updated; fix each "missing field" error.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p yip-rendezvous-bin --bin yip-rendezvous reality` then `cargo test -p yip-rendezvous-bin`
Expected: PASS (all existing reality/auth/anti-replay tests green — the field is additive).

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-rendezvous-bin --all-targets -- -D warnings
cargo fmt
git add bin/yip-rendezvous/src/reality.rs
git commit -m "feat(reality.5d): extract group-4588 x25519 tail from ClientHello (for server-side hybrid DH)"
```

---

### Task 2: Genericize the connection pump over the stream type

`handle_connection` and its helpers `read_and_classify` and `into_decoy` are typed to `tokio_boring::SslStream<S>`, but their bodies only use `AsyncRead`/`AsyncWrite`. Genericize the whole chain so it can also carry a `yip_utls::RealityStream`. (`reality_reject<S>(stream: S)` is already generic — leave it.)

**Files:**
- Modify: `bin/yip-rendezvous/src/conn.rs` (`handle_connection` ~82, `read_and_classify` ~146, `into_decoy` ~183)

**Interfaces:**
- Produces: `pub async fn handle_connection<St>(stream: St, cfg: Arc<TlsFrontCfg>) where St: AsyncRead + AsyncWrite + Unpin + Send` — accepts any async byte stream (the existing `SslStream` caller and the new `RealityStream` caller both satisfy the bound).

- [ ] **Step 1: Find every `SslStream` mention in the chain**

Run: `grep -n "SslStream" bin/yip-rendezvous/src/conn.rs`
Expected: `handle_connection` (param `tokio_boring::SslStream<S>`), `read_and_classify` (param `&mut tokio_boring::SslStream<S>`), `into_decoy` (param `tokio_boring::SslStream<S>`), plus comments mentioning close_notify. These three function signatures are what changes; the bodies don't.

- [ ] **Step 2: Genericize the three signatures**

Change each from the `SslStream<S>`-typed form to a generic `St` bounded by `AsyncRead + AsyncWrite + Unpin + Send`. Concretely:

```rust
pub async fn handle_connection<St>(mut stream: St, cfg: Arc<TlsFrontCfg>)
where
    St: AsyncRead + AsyncWrite + Unpin + Send,
{ /* body unchanged */ }

async fn read_and_classify<St>(
    stream: &mut St,
    /* ...other params unchanged... */
)
where
    St: AsyncRead + AsyncWrite + Unpin + Send,
{ /* body unchanged */ }

async fn into_decoy<St>(mut stream: St, cfg: &TlsFrontCfg, buffered: Vec<u8>)
where
    St: AsyncRead + AsyncWrite + Unpin + Send,
{ /* body unchanged */ }
```

Keep every call site inside `conn.rs` as-is (they pass the stream through; type inference resolves `St`). Leave the `// close_notify on SslStream` comments or soften them to "on a TLS stream" — cosmetic. Do NOT change `reality_reject` (already generic). Ensure `use tokio::io::{AsyncRead, AsyncWrite}` (and `AsyncWriteExt` for `.shutdown()`) are in scope — they already are (the file uses them), but confirm after editing.

- [ ] **Step 3: Verify the non-REALITY caller still compiles**

The existing caller is `run_tls_front` in `tls_front.rs`: `handle_connection(s, ...)` where `s` is a `tokio_boring::SslStream<...>`. `SslStream` implements `AsyncRead + AsyncWrite + Unpin + Send`, so it still satisfies the new bound — no caller change needed.

Run: `cargo build -p yip-rendezvous-bin`
Expected: compiles clean.

- [ ] **Step 4: Run the full suite (behavior-preserving gate)**

Run: `cargo test -p yip-rendezvous-bin`
Expected: PASS — every existing test (incl. `probe_is_proxied_to_decoy`, `reality_inner_fail_writes_generic_error_not_decoy`) stays green. The signature change is behavior-identical.

- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p yip-rendezvous-bin --all-targets -- -D warnings
cargo fmt
git add bin/yip-rendezvous/src/conn.rs
git commit -m "refactor(reality.5d): genericize handle_connection pump over AsyncRead+AsyncWrite (accept RealityStream)"
```

---

### Task 3: Rewrite the authed path to serve the hand-rolled flight + drop the dead acceptors

Replace `run_reality_conn`'s `Decision::Accept` branch (BoringSSL) with the 5b+5c hand-rolled handshake, and delete the now-dead `build_forged_acceptor*` + `CacheEntry.acceptor`.

**Files:**
- Modify: `bin/yip-rendezvous/src/tls_front.rs` (the `Decision::Accept` arm ~258-291; add an `OsRandomSource` + a pure `select_client_x25519` helper + its tests)
- Modify: `bin/yip-rendezvous/src/reality_cert.rs` (remove `build_forged_acceptor`, `build_forged_acceptor_with_pkcs8`, `build_forged_acceptor_with_key`, `CacheEntry.acceptor`; adjust `apply_refresh`/pre-warm to not build an acceptor)

**Interfaces:**
- Consumes: `ClientHelloInfo.key_share_mlkem_x25519` (Task 1); `handle_connection<St>` (Task 2); `RealityCertCache::{template_for, fields_for}`; `yip_utls::{emit_server_hello, serve}`, `yip_utls::auth::derive_cert_key`, `yip_utls::hello::RandomSource`; `reality_cert::forge_leaf`.
- Produces: `fn select_client_x25519(group: u16, info: &ClientHelloInfo) -> Option<[u8; 32]>` (pure, testable).

- [ ] **Step 1: Write the failing unit test for the pure decision**

Add to `tls_front.rs`'s `#[cfg(test)] mod tests` (build a minimal `ClientHelloInfo` — set `key_share_x25519 = Some([1;32])`, `key_share_mlkem_x25519 = Some([2;32])`, other fields defaults/`None`):

```rust
    fn info_with_shares(x0: Option<[u8; 32]>, x4588: Option<[u8; 32]>) -> ClientHelloInfo {
        ClientHelloInfo {
            sni: Some("example.com".to_string()),
            client_random: [0u8; 32],
            legacy_session_id: vec![0u8; 32],
            key_share_x25519: x0,
            key_share_mlkem_ek: None,
            key_share_mlkem_x25519: x4588,
        }
    }

    #[test]
    fn select_client_x25519_by_group() {
        let info = info_with_shares(Some([1u8; 32]), Some([2u8; 32]));
        // group 4588 → the 4588-entry tail; group 29 → the 0x001d entry.
        assert_eq!(select_client_x25519(4588, &info), Some([2u8; 32]));
        assert_eq!(select_client_x25519(29, &info), Some([1u8; 32]));
        // unsupported group → None (→ splice).
        assert_eq!(select_client_x25519(23, &info), None);
        // missing share for the selected group → None.
        assert_eq!(select_client_x25519(4588, &info_with_shares(Some([1u8; 32]), None)), None);
        assert_eq!(select_client_x25519(29, &info_with_shares(None, Some([2u8; 32]))), None);
    }
```

(Adjust the `ClientHelloInfo` literal to the real field set — check `reality.rs` for the exact fields after Task 1. `ClientHelloInfo` derives `Clone`/`PartialEq` per its existing `#[derive]`.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p yip-rendezvous-bin --bin yip-rendezvous tls_front::tests::select_client_x25519_by_group`
Expected: FAIL — `select_client_x25519` not defined.

- [ ] **Step 3: Add the pure helper + the `OsRandomSource`**

In `tls_front.rs`:

```rust
/// Which client X25519 public key feeds the server-side TLS DH, by negotiated
/// group: for X25519MLKEM768 (4588) it is the x25519 bundled in the client's
/// 4588 key_share entry (`key_share_mlkem_x25519`); for X25519 (29) it is the
/// standalone `0x001d` entry (`key_share_x25519`). Any other group is
/// unsupported here (P256/P384 + HelloRetryRequest is #84) → `None` → splice.
fn select_client_x25519(group: u16, info: &ClientHelloInfo) -> Option<[u8; 32]> {
    match group {
        4588 => info.key_share_mlkem_x25519,
        29 => info.key_share_x25519,
        _ => None,
    }
}

/// An OS-CSPRNG-backed [`yip_utls::hello::RandomSource`] for `emit_server_hello`
/// (mirrors yip_utls's own private `OsRng`: a `getrandom` bridge that latches
/// the first error so the caller fail-closes instead of emitting predictable
/// bytes). NEVER seed this — a predictable rng here makes the ML-KEM
/// encapsulation predictable.
#[derive(Default)]
struct OsRandomSource {
    error: bool,
}

impl yip_utls::hello::RandomSource for OsRandomSource {
    fn fill(&mut self, buf: &mut [u8]) {
        if self.error {
            return;
        }
        if getrandom::getrandom(buf).is_err() {
            self.error = true;
        }
    }
}
```

(`getrandom = "0.2"` and `p256 = { version = "0.13", features = ["ecdsa", "pkcs8"] }` are ALREADY direct deps of `yip-rendezvous` — no Cargo.toml change needed. `p256`'s `pkcs8` feature provides `SigningKey::from_pkcs8_der` via the `DecodePrivateKey` trait used in Step 4b.)

- [ ] **Step 4a: Thread `info` into the decision tuple**

`info` is NOT in the `Accept` branch's scope today — the decision closure returns `Some((sni.to_owned(), ts_min, seal, shared, fields))`. The hand-rolled handshake needs the client's key shares + `legacy_session_id`, so add the parsed hello to the tuple. `ClientHelloInfo` derives `Clone`. Change the closure's return to `Some((sni.to_owned(), ts_min, seal, shared, fields, info.clone()))` and the destructure to:

```rust
    if let Some((sni, ts_min, seal, shared, Some(fields), info)) = decision {
```

(`fields` is the `Arc<StolenFields>` already bound from `r.certs.fields_for(sni)` — do NOT re-fetch it. `r = cfg.reality.as_ref()`, so the cache is `r.certs`; splice uses `r.dest`; the pump gets `Arc::clone(cfg)`.)

- [ ] **Step 4b: Rewrite the `Decision::Accept` branch**

Replace the `Decision::Accept => { … }` arm's body. In scope: `sni` (String), `fields` (`Arc<StolenFields>`), `shared`, `info` (`ClientHelloInfo`), `rec`, `r`, `tcp`, `cfg`. The new body (splice pre-write, drop post-write):

```rust
            Decision::Accept => {
                // --- Pre-write: any failure SPLICES (connection still pristine). ---
                let Some(template) = r.certs.template_for(&sni) else {
                    splice_to_dest(tcp, r.dest, &rec).await;
                    return;
                };

                let group = template.server_hello.key_share_group;
                let Some(client_x25519) = select_client_x25519(group, &info) else {
                    splice_to_dest(tcp, r.dest, &rec).await;
                    return;
                };

                let dk = yip_utls::auth::derive_cert_key(&shared);

                // Forge the natural leaf (no exact-length padding); SPKI = dk.
                let leaf_keypair = match rcgen::KeyPair::try_from(dk.pkcs8_der.as_slice()) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("tls-front: reality leaf keypair load failed ({sni}): {e}");
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };
                let forged_leaf_der = match crate::reality_cert::forge_leaf(&fields, &leaf_keypair) {
                    Ok(cert) => cert.der().as_ref().to_vec(),
                    Err(e) => {
                        eprintln!("tls-front: reality forge_leaf failed ({sni}): {e}");
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };

                let ch_msg = match rec.get(5..) {
                    Some(m) => m,
                    None => {
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };

                let mut rng = OsRandomSource::default();
                let (sh_msg, keys) = match yip_utls::emit_server_hello(
                    &template.server_hello,
                    ch_msg,
                    &info.legacy_session_id,
                    &client_x25519,
                    info.key_share_mlkem_ek.as_deref(),
                    &mut rng,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("tls-front: reality emit_server_hello failed ({sni}): {e}");
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };
                if rng.error {
                    // getrandom failed → fail closed (still pre-write).
                    eprintln!("tls-front: reality OS rng failed ({sni})");
                    splice_to_dest(tcp, r.dest, &rec).await;
                    return;
                }

                // --- Commit point: write the ServerHello. From here, DROP on error. ---
                let mut transcript_ch_sh = Vec::with_capacity(ch_msg.len() + sh_msg.len());
                transcript_ch_sh.extend_from_slice(ch_msg);
                transcript_ch_sh.extend_from_slice(&sh_msg);

                let mut sh_record = Vec::with_capacity(5 + sh_msg.len());
                sh_record.push(0x16); // handshake
                sh_record.extend_from_slice(&[0x03, 0x03]); // legacy record version
                // Still pre-write (nothing on the wire yet) → splice. A
                // ServerHello never exceeds u16, so this is unreachable in
                // practice, but it keeps the fail-safe boundary honest.
                let sh_len = match u16::try_from(sh_msg.len()) {
                    Ok(l) => l,
                    Err(_) => {
                        eprintln!("tls-front: reality ServerHello too large ({sni})");
                        splice_to_dest(tcp, r.dest, &rec).await;
                        return;
                    }
                };
                sh_record.extend_from_slice(&sh_len.to_be_bytes());
                sh_record.extend_from_slice(&sh_msg);
                if let Err(e) = tcp.write_all(&sh_record).await {
                    eprintln!("tls-front: reality ServerHello write failed ({sni}): {e}");
                    return;
                }

                let signing_key =
                    match p256::ecdsa::SigningKey::from_pkcs8_der(&dk.pkcs8_der) {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("tls-front: reality signing key load failed ({sni}): {e}");
                            return;
                        }
                    };

                let reality_stream = match tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    yip_utls::serve(
                        tcp,
                        &keys,
                        &template.encrypted_flight,
                        &template.cert_chain,
                        &forged_leaf_der,
                        &signing_key,
                        &transcript_ch_sh,
                    ),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        eprintln!("tls-front: reality serve failed ({sni}): {e}");
                        return;
                    }
                    Err(_) => {
                        eprintln!("tls-front: reality serve timed out ({sni})");
                        return;
                    }
                };

                super::conn::handle_connection(reality_stream, Arc::clone(cfg)).await;
                return;
            }
```

Notes for the implementer:
- Confirm `cfg.certs` is the `RealityCertCache` and that `template_for`/`fields_for` take `&str` and return `Option<Arc<...>>` — adjust the borrow/deref (`&template.server_hello`, `&template.encrypted_flight`, `&template.cert_chain`) to match (`Arc<ServerFlightTemplate>` derefs to `ServerFlightTemplate`, so `&template.server_hello` works).
- `p256::pkcs8::DecodePrivateKey` must be in scope for `SigningKey::from_pkcs8_der` (`use p256::pkcs8::DecodePrivateKey as _;`).
- Remove the now-unused imports the old branch needed (`build_forged_acceptor_with_pkcs8`, `PrefixedStream` if only this branch used it — **check**: `PrefixedStream` may still be used by the splice path; grep before removing its import). `tokio_boring::accept` import for this branch goes away (keep it if `run_tls_front` still uses it).
- `tcp` is moved into `serve`; ensure nothing uses it afterward.

- [ ] **Step 5: Delete the dead BoringSSL acceptor builders**

In `reality_cert.rs`, remove `build_forged_acceptor`, `build_forged_acceptor_with_pkcs8`, `build_forged_acceptor_with_key`, and the `CacheEntry.acceptor` field. Update `apply_refresh` and the startup pre-warm so a cache entry is populated from `(fields, template)` **without** building an acceptor (the capture via `capture_dest_flight` and the degrade-to-splice-on-capture-failure are unchanged — only the acceptor construction is dropped). Keep `forge_leaf`, `extract_fields`, `fields_for`, `template_for`, and the capture/refresh/staleness machinery. Drop the `use boring::ssl::{SslAcceptor, …}` imports that only the removed builders used (keep any `boring` imports `extract_fields` still needs, e.g. `boring::x509`).

Run: `cargo build -p yip-rendezvous-bin`
Expected: compiles (fix any remaining reference to the removed items — e.g. a test that called `build_forged_acceptor` should be removed or repointed at `forge_leaf`).

- [ ] **Step 6: Run tests**

Run: `cargo test -p yip-rendezvous-bin --bin yip-rendezvous tls_front::tests::select_client_x25519_by_group` then the full `cargo test -p yip-rendezvous-bin`
Expected: PASS — the new pure-decision test, and every existing test (the un-authed splice path, `decide_authed`, anti-replay, `reality_cert` capture/refresh, `conn` decoy) stays green. If a `reality_cert` test exercised a removed acceptor builder, it was testing dead code — remove it (note this in the report) rather than resurrecting the builder.

- [ ] **Step 7: Clippy, fmt, commit**

```bash
cargo clippy -p yip-rendezvous-bin --all-targets -- -D warnings
cargo fmt
git add bin/yip-rendezvous/src/tls_front.rs bin/yip-rendezvous/src/reality_cert.rs
git commit -m "feat(reality.5d): serve hand-rolled 5b+5c flight on the authed path; drop BoringSSL forged acceptors"
```

---

### Task 4: netns money test — a real `verify=on` client tunnels through the 5d relay

Prove the integration end-to-end: a real yipd client (`reality://…&verify=on`) tunnels to a peer through a relay whose authed path now hand-rolls the flight (5b+5c), and a wrong-key client fails closed.

**Files:**
- Create: `bin/yipd/tests/run-netns-reality-5d.sh` (fork the closest existing REALITY relay netns script)
- Modify: the CI workflow that runs the other REALITY netns scripts, if they're wired in (add this one)

**Interfaces:**
- Consumes: the shipped yipd `reality://host:port?pbk=&sid=&sni=[&verify=on]` client (4a/4b); the yip-rendezvous relay's `--reality-dest`/`--reality-private-key`/`--reality-short-id`/`--reality-server-name` flags (REALITY.3); the 5d authed path (Task 3).

- [ ] **Step 1: Read the existing REALITY netns scripts to reuse the plumbing**

Run: `ls bin/yipd/tests/run-netns-*.sh` and read the REALITY relay one (e.g. `run-netns-relay-tls.sh` and/or the REALITY probe script) — reuse its netns setup (namespaces, veth, the relay + two peers, UDP-blocking so peers must relay), its `--reality-*` relay flags, and its dest/decoy setup.

- [ ] **Step 2: Provide a local mock `dest` the relay captures a template from**

The relay pre-warms its `ServerFlightTemplate` by probing `--reality-dest` at startup (`capture_dest_flight`). For a hermetic test, run a local TLS 1.3 server as the dest inside the netns — an `openssl s_server -tls1_3 -www` with a self-signed cert on a fixed port is sufficient (the client offers both X25519MLKEM768 and X25519; openssl selects X25519 (group 29), so the captured `key_share_group` is 29 and the authed path keys group 29 — fully supported by 5b/5c). Point `--reality-dest` at it. (If the existing REALITY scripts already stand up a dest, reuse that; only ensure it speaks TLS 1.3.)

- [ ] **Step 3: The money assertions**

The script must assert, with non-zero exit on any failure:
1. **Tunnel works:** with the client dialing `reality://<relay>:<port>?pbk=<relay-pub>&sid=<short-id>&sni=<dest-sni>&verify=on`, peer A pings peer B *through the relay* (relay-forwarded packet count > 0), i.e. the client completed the hand-rolled handshake AND verified the 4b binding (`verify=on` only succeeds if the relay's hand-rolled `CertificateVerify` verifies).
2. **Wrong key fails closed:** a client dialing with a WRONG `pbk` (relay public key) gets no tunnel (the seal fails to open → the relay splices → no authed handshake → no relayed packets). Assert the ping FAILS / relay-forwarded count stays 0 for this variant.

Model the ping/relay-count checks on the existing REALITY relay script's assertions (it already counts relay-forwarded packets). Print a clear `PASS`/`FAIL` and `exit 1` on failure.

- [ ] **Step 4: Run the script under sudo**

Run: `sudo bash bin/yipd/tests/run-netns-reality-5d.sh`
Expected: prints `PASS`, exit 0 — the `verify=on` client tunnels through the hand-rolled relay; the wrong-key variant gets no tunnel.

(If the harness can't run in this environment — netns needs root + kernel support — capture the exact failure and report it; do not mark the task done on an unrun money test. The controller decides whether to run it or defer to the user's environment.)

- [ ] **Step 5: Wire into CI (if the peers do) + commit**

If the other `run-netns-*.sh` scripts are invoked by a CI workflow (grep `.github/workflows/` for `run-netns`), add this script alongside them.

```bash
chmod +x bin/yipd/tests/run-netns-reality-5d.sh
git add bin/yipd/tests/run-netns-reality-5d.sh .github/workflows/  # if modified
git commit -m "test(reality.5d): netns money test — verify=on client tunnels through the hand-rolled relay"
```

---

## After all tasks

- Final whole-branch review (opus) over the 5d delta (base = 5c tip / PR #86 head), focused on: the splice-vs-drop boundary (no post-ServerHello splice; every pre-write failure splices), no panic on the connection path, the group→x25519 selection, the OS rng being unseeded + fail-closed, and that the `reality_cert` cleanup didn't drop a still-live path.
- Push the branch; open a PR **stacked on #86** (base = `feat/reality-5c-server-flight-emit`). Leave it for the user; do NOT merge; no "not merging" line.
- Update the ledger + `yip-antidpi-status.md` (REALITY.5 COMPLETE — 5a/5b/5c/5d; the authed path is now end-to-end dest-faithful; the last anti-DPI item is done).

## Self-Review notes

- The `select_client_x25519` helper is the one pure, unit-tested decision; the template-missing and forge/emit failures are direct guards in the async branch (obvious splice), so they don't each need a pure helper.
- The `rng.error` check runs **before** the ServerHello write, so an OS-rng failure still splices (pre-write), consistent with the fail-safe boundary.
- `serve` moves `tcp`; the ServerHello is written to `tcp` *before* the `serve` call, so the write and the serve share the same stream in sequence (write, then hand the same `tcp` to `serve`) — the implementer must write the ServerHello to `tcp` and then pass that same `tcp` into `serve` (as the code in Step 4 does).
