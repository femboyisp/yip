# REALITY.5d — wire the hand-rolled server flight into the relay — design spec

**Date:** 2026-07-18
**Status:** design (pending user review)
**Parent:** [`2026-07-15-reality-tls-milestone-design.md`](2026-07-15-reality-tls-milestone-design.md) — REALITY.5 (#76).
**Depends on:** REALITY.5c (`yip_utls::serve` + `emit_server_flight`), REALITY.5b (`yip_utls::emit_server_hello`), REALITY.5a (`ServerFlightTemplate` capture + `RealityCertCache`), REALITY.4b (`auth::derive_cert_key`, per-connection binding), REALITY.3 (`forge_leaf`, `StolenFields`, the authed/splice front).
**Scope:** `yip-rendezvous` (the relay's authed REALITY path). PR 4 of 4 (the LAST) of REALITY.5.

## Goal

Replace the BoringSSL `SslAcceptor` on the relay's authed REALITY path with the hand-rolled 5b+5c handshake, so the relay actually **serves** the dest-faithful server flight it can now build. After 5d, an authed connection to the relay is byte/length-indistinguishable from a genuine Chrome↔`dest` TLS 1.3 session end to end — cleartext ServerHello (5b) *and* encrypted flight framed to `dest`'s record lengths (5c) — closing the passive-DPI gap REALITY.3 explicitly left open for the authed path (the last anti-DPI item).

## Where it changes

Only `tls_front::run_reality_conn`'s `Decision::Accept` branch (`bin/yip-rendezvous/src/tls_front.rs`) changes behavior; four supporting edits enable it. Today that branch does: `derive_cert_key(shared)` → `build_forged_acceptor_with_pkcs8` (BoringSSL) → `tokio_boring::accept` → `handle_connection(SslStream)`. The un-authed splice path, the non-REALITY relay-Trojan front (`run_tls_front`), the anti-replay guard (`decide_authed`/`ReplayGuard`), and the client side (4a/4b) are all unchanged.

## The new authed-path flow (`Decision::Accept`)

Given the already-read first record `rec` (the ClientHello record; the handshake message is `rec[5..]`), the parsed `info: ClientHelloInfo`, and this connection's seal secret `shared` (from `reality_auth_recover_shared`):

1. **Template lookup.** Fetch the captured `ServerFlightTemplate` + `StolenFields` for `sni` from `RealityCertCache` (`template_for`/`fields_for`). No template (capture failed or the SNI degraded to splice-only at pre-warm) → **splice to dest** (fail-safe).
2. **Binding key.** `dk = yip_utls::auth::derive_cert_key(&shared)` (unchanged — the per-connection ECDSA-P256 key the client pins against, REALITY.4b).
3. **Forge the leaf.** `forge_leaf(&fields, <dk as rcgen KeyPair>)?.der().as_ref().to_vec()` → `forged_leaf_der` (`forge_leaf` returns an `rcgen::Certificate`; take its DER): the natural mimicking leaf (copies `dest`'s subject/SAN/validity/serial/keyUsage/EKU/basicConstraints), SPKI = `dk`'s P-256 public key. **No exact-length padding** (user decision — see "Leaf sizing"). A forge error → **splice**.
4. **Pick `client_x25519` by group.** For `template.server_hello.key_share_group == 4588` (X25519MLKEM768): use the client's **4588-entry x25519 tail** (`info.key_share_mlkem_x25519`). For group `29` (X25519): use `info.key_share_x25519` (the `0x001d` entry). A missing/`None` value for the selected group → **splice**.
5. **Emit + write the ServerHello (5b).** `emit_server_hello(&template.server_hello, rec[5..], &info.legacy_session_id, &client_x25519, info.key_share_mlkem_ek.as_deref(), &mut os_rng)` → `(sh_msg, keys)`. Write `sh_msg` to the socket as a plaintext handshake record (`0x16 ‖ 0x0303 ‖ u16 len ‖ sh_msg`). An `emit_server_hello` error (e.g. `UnsupportedGroup`) is caught **before** writing → **splice**; once the ServerHello bytes are written, we are committed (step 6+ failures **drop**).
6. **Serve the encrypted flight (5c), bounded.** `timeout(HANDSHAKE_TIMEOUT, serve(tcp, &keys, &template.encrypted_flight, &template.cert_chain, &forged_leaf_der, &<dk as p256 SigningKey>, transcript_ch_sh))` where `transcript_ch_sh = rec[5..] ‖ sh_msg`. Returns a `RealityStream`. Any error (`FlightTooLarge`, timeout, I/O) → **drop** (log; the client falls back per 4b).
7. **Pump the tunnel.** `handle_connection(reality_stream, cfg)` — the same inner relay logic as the old BoringSSL branch.

### The splice-vs-drop boundary (load-bearing)

Splicing forwards the pristine connection to the real `dest` so a prober completes a genuine handshake — but that only works while we have **not yet written our own bytes**. Once we write our ServerHello (step 5), `dest` never saw this ClientHello, so we cannot retroactively splice. Therefore:
- **Steps 1–5 (before any write):** every failure → **splice** (preserves REALITY.3's "any failure looks like a real visit").
- **Steps 5-write through 7 (after the ServerHello is on the wire):** every failure → **drop** (matches how the current BoringSSL branch already treats a mid-handshake failure; the client's 4b fallback covers it).

`FlightTooLarge` (an oversized forged leaf overflowing `dest`'s record budget) fires inside `serve` (step 6) → a drop. This is rare because the natural leaf ≈ `dest`'s size; the fail-safe exists so an unlucky template never crashes or hangs the relay.

## Leaf sizing (user decision: natural leaf, no exact padding)

The passive DPI — the only in-scope adversary — sees only the **encrypted record framing** (`record_lengths`), which 5c already matches exactly. The Certificate *message* size lives inside the AEAD, visible only to a party holding the session keys (out of the zero-CA-auth threat model). The forged leaf already copies `dest`'s fields, so it is naturally ≈ `dest`'s `leaf_der_len`. 5d therefore ships the natural forged leaf and relies on 5c's record padding to absorb the small size delta; if a leaf ever exceeds `dest`'s total record budget, `emit_server_flight` returns `FlightTooLarge` → the connection drops (fail-safe). Exact-length DER padding (a computed dummy X.509 extension) is **not** implemented — it would harden only against a decryptor that does not exist in this threat model, at real implementation cost.

## Supporting changes

### 1. Parser — expose the 4588-entry x25519 tail (`bin/yip-rendezvous/src/reality.rs`)

`ClientHelloInfo` has `key_share_x25519` (`0x001d`) and `key_share_mlkem_ek` (first 1184 bytes of the group-4588 entry). Add `pub key_share_mlkem_x25519: Option<[u8; 32]>` — the trailing 32 bytes of that same 4588 entry (`mlkem_ek(1184) ‖ x25519(32)`). The parser already walks the entry for the ek, so the tail is a bounded slice more. Fail-closed: a 4588 entry that is not exactly `1184 + 32` bytes → both `key_share_mlkem_ek` and `key_share_mlkem_x25519` are `None`. This is what step 4 threads into the group-4588 TLS DH — correct-by-construction, not relying on the client reusing one ephemeral across its `0x001d` and 4588 shares (though our client does; a non-reuse client would simply fail closed with a dead session).

### 2. `reality_cert.rs` — read template/fields, drop the dead acceptors

- **Use** the per-SNI accessors the authed path reads: `template_for(sni) -> Option<Arc<ServerFlightTemplate>>` and `fields_for(sni) -> Option<Arc<StolenFields>>` (both already `pub`; if `template_for` still carries a dead-code `#[allow]`/`#[cfg]` gate from 5a, drop it now that there is a real caller).
- **Remove** the now-dead `build_forged_acceptor`, `build_forged_acceptor_with_pkcs8`, `build_forged_acceptor_with_key`, and `CacheEntry.acceptor` — nothing serves a BoringSSL acceptor anymore. Adjust `apply_refresh`/pre-warm to populate `fields`+`template` without building an acceptor (capture still probes `dest` via `capture_dest_flight`; an SNI whose capture fails still degrades to splice-only exactly as in 5a).
- **Keep** `forge_leaf`, `extract_fields`, the capture/refresh/staleness machinery, and the startup pre-warm (minus the acceptor build).

### 3. Genericize the pump (`bin/yip-rendezvous/src/conn.rs`)

`handle_connection` is hardcoded to `tokio_boring::SslStream<S>` but its body uses only `AsyncRead`/`AsyncWrite`. Change the signature to `pub async fn handle_connection<St>(stream: St, cfg: Arc<TlsFrontCfg>) where St: AsyncRead + AsyncWrite + Unpin + Send`. The existing non-REALITY relay-Trojan caller passes an `SslStream` (still satisfies the bound); the new authed caller passes a `yip_utls::RealityStream`.

### 4. OS-CSPRNG for the ServerHello (`tls_front.rs`)

`emit_server_hello` draws the ServerHello random, the server X25519 ephemeral, and the ML-KEM encapsulation randomness from its `rng: &mut dyn RandomSource`. 5d passes the same OS-CSPRNG-backed `RandomSource` `yip_utls::connect`/`capture_dest_flight` use — never a seeded/deterministic one (a predictable rng here would make the KEM encapsulation predictable).

## Error handling summary (fail-closed)

- Pre-write failures (no template, unsupported group, missing client key share, forge error, `emit_server_hello` error) → **splice** (pristine connection, indistinguishable).
- Post-write failures (`serve`/`emit_server_flight` error incl. `FlightTooLarge`, timeout, I/O) → **drop** (log; client 4b-falls-back).
- Anti-replay (`decide_authed`) runs before this branch, unchanged.
- No panics on the connection path: every parse/slice is bounded (`rec[5..]` via `.get(5..)`), every `Option`/`Result` from the template/parse/emit/serve chain is matched and routed to splice-or-drop.

## Testing / adversary

- **Unit (pure, fast):** (a) the parser's `key_share_mlkem_x25519` extraction — a fixture group-4588 key_share `mlkem_ek(1184) ‖ x25519(32)` yields the correct 32-byte tail; a wrong-length 4588 entry → `None`. (b) the group→`client_x25519` selection (4588 → tail, 29 → `0x001d`). (c) the pre-write splice decisions (template-missing, unsupported group → splice; assert `run_reality_conn` splices rather than drops).
- **Integration / money test (netns, sudo — the end-to-end gate):** a real yipd client dialing `reality://…&verify=on` tunnels to a peer *through* a 5d relay whose authed path hand-rolls the flight (5b+5c). The relay captures its template from a **local mock `dest`** at startup (hermetic). Assert: the tunnel works (ping A→B through the relay); the client's `verify=on` binding holds against the hand-rolled `CertificateVerify`; and a **wrong-key** client fails closed (no tunnel). This proves 5b+5c+5d compose into a working authed handshake against the **real shipped client**.
- **Regression:** the `handle_connection` genericization keeps the non-REALITY relay-Trojan (`SslStream`) path green; the un-authed splice path, `decide_authed`, and the anti-replay tests are unchanged and stay green.
- Byte-fidelity itself is already proven by 5b's ServerHello byte-match, 5c's `record_lengths` byte-framing, and the 5c client round-trip — 5d is the wiring, so it proves the *integration*, not the framing.

## Risks

- **Committed-write drop vs splice.** Once the ServerHello is written we can only drop on failure, not splice — a narrower fail-safe than the un-authed path. Mitigation: all *predictable* failures (no template, unsupported group, missing share) are caught pre-write and splice; only genuinely-mid-handshake failures drop, which the client's 4b fallback already handles. Accepted.
- **`handle_connection` genericization** touches a shared function used by the non-REALITY path. Mitigation: signature-only change (body unchanged); the existing `SslStream` caller and its tests are the regression net.
- **Template freshness.** The served flight matches the last captured template, not `dest`'s live one (accepted in 5a; refresh mitigates). An authed connection whose `dest` changed its stack between capture and serve is still internally consistent (the client verifies the binding, not dest-liveness); worst case is a stale-but-plausible template.
- **`serve` CCS-drain is unbounded** (5c note): 5d wraps `serve` in `HANDSHAKE_TIMEOUT`, so a hostile client sending endless `ChangeCipherSpec` records is bounded by the timeout, not hung forever.

## Non-goals

- No client-side changes (4a/4b shipped); no anti-replay changes (3); no ServerHello/flight construction changes (5b/5c).
- No P256/P384 server KEX + HelloRetryRequest (#84) — an authed hello whose `dest` selected such a group has `template.server_hello.key_share_group ∉ {4588, 29}`; step 4/5 → splice.
- No exact leaf-length padding (user decision).
- The deferred 5c cleanups (`Error::MessageTooLarge`, u24-helper extraction) are a separate follow-up.
- Dropping the `boring` dependency — the non-REALITY relay-Trojan front and `extract_fields` still use it; out of scope.

## Success criteria

1. The relay's authed REALITY path serves a hand-rolled 5b ServerHello + 5c encrypted flight (no BoringSSL `SslAcceptor`); the dead `build_forged_acceptor*` + `CacheEntry.acceptor` are removed.
2. `ClientHelloInfo` exposes the group-4588 x25519 tail; the authed path keys the 4588 TLS DH against it (and the `0x001d` share for group 29), fail-closed on a missing/short share.
3. Pre-write failures splice (indistinguishable); post-write failures drop; `serve` is bounded by `HANDSHAKE_TIMEOUT`; the ServerHello rng is OS-CSPRNG-backed.
4. `handle_connection` is generic over `AsyncRead + AsyncWrite + Unpin + Send`; the non-REALITY path stays green.
5. The netns money test passes: a real `verify=on` yipd client tunnels through the 5d relay (hand-rolled flight accepted + binding verified), and a wrong-key client fails closed.
6. `forbid-unsafe` (outside yip-io/yip-device); no `as` casts; clippy clean.
