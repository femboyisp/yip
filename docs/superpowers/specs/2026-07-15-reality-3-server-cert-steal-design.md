# REALITY.3 — server: on-the-fly stolen-cert authed path + anti-replay + splice-faithful fallback — design spec

**Date:** 2026-07-15
**Status:** design (pending user review)
**Parent:** [`2026-07-15-reality-tls-milestone-design.md`](2026-07-15-reality-tls-milestone-design.md)
**Depends on:** REALITY.1 (merged, the server front) + REALITY.2 (merged, the shared auth codec).
**Scope:** `yip-rendezvous` server only. PR 1 of the REALITY.3+.4 pair (REALITY.4 = client wiring, separate).

## Goal

Finalize the REALITY relay's **authenticated** branch so it is fully cover-faithful, and
close the two REALITY.1-review prerequisites that must land before a real client (REALITY.4)
connects:

1. **Stolen-cert authed TLS:** when an authenticated connection is accepted, terminate TLS
   presenting a certificate that mimics the real `dest` site (its subject/SAN/validity),
   generated on the fly from `dest`'s live chain — not the operator's own cert (no operator
   domain cert required, and the authed session's cert matches the borrowed identity). Matches
   Xray REALITY; enables optional REALITY-key-based outer-TLS server auth later.
2. **Anti-replay (REALITY.1 I-1):** reject a captured-and-replayed authed ClientHello.
3. **Splice-faithful authed fallback (REALITY.1):** an authed connection whose *inner*
   classification fails must splice to `dest`, not serve the decoy — so a replay or a
   misbehaving authed peer stays indistinguishable from the real site.

## Background (current authed path)

`tls_front::run_reality_conn` (REALITY.1): reads the raw ClientHello, checks the REALITY seal.
**Authed** ⇒ `tokio_boring::accept(&acceptor, PrefixedStream::new(rec, tcp))` then
`conn::handle_connection`, where the acceptor is built by `build_acceptor(cert_path, key_path)`
from `--tls-cert`/`--tls-key`. `handle_connection` reads the first inner frame (obf-Register),
routing to the relay tunnel or, on classification failure, `into_decoy`.

## Design

### 1. Stolen-cert acceptor (`reality_cert.rs`, new module)

- **Fetch `dest`'s chain, cached.** On first need (lazily, then cached per `dest`), the relay
  dials `reality_dest` as a TLS client (`tokio_boring::connect`, SNI = the borrowed domain) and
  reads the peer leaf certificate via `ssl.peer_cert_chain()`. Extract the leaf's **subject,
  subjectAltNames, notBefore/notAfter, and serial** (`boring::x509` / `X509` accessors). A fetch
  failure falls back to a self-signed cert for the SNI (fail-open to *a* valid TLS termination —
  never break the authed path on a transient dest outage), logged.
- **Forge a leaf.** Using `rcgen`, build a leaf whose subject + SANs + validity **copy `dest`'s**,
  signed by a **relay-ephemeral key** (generated once at startup; the chain won't validate against
  real CAs, which is fine — the outer TLS is zero-CA-auth by design; a REALITY.4 client may later
  verify it against the REALITY key). Cache the `(cert, key)` acceptor per SNI/dest.
- **Serve it.** Build the authed-branch `SslAcceptor` from this forged `(cert, key)` (mozilla-
  intermediate profile, ALPN `h2`/`http/1.1`, matching `build_acceptor`) instead of the operator
  PEM. `--tls-cert`/`--tls-key` become OPTIONAL when REALITY is configured (used only for the
  legacy non-REALITY Trojan front).

### 2. Anti-replay (`reality.rs` / the auth-decision site)

A **time-bounded dedup set** keyed on the 32-byte seal (`legacy_session_id`) — equivalently the
`(client_random, seal)` pair. On an authed decision, if the seal was seen within the freshness
window (±`REALITY_SKEW_MIN` = 10 min), treat the connection as **un-authed** (⇒ splice to `dest`).
Insert on first accept; evict entries older than the window on each insert (or a periodic sweep).
Bounded memory (only seals within a ~20-min window). This lives in `tls_front`'s per-connection
decision, guarded by an `Arc<Mutex<HashMap<[u8;32], unix_minutes>>>` on `TlsFrontCfg` (or a small
dedicated type). Concurrency: the relay is tokio/multi-thread; the mutex is held only for the
O(1) check+insert, not across the handshake.

### 3. Splice-faithful authed fallback (`conn.rs`)

Today `handle_connection` → on inner-classification failure → `into_decoy` (serves the static
decoy or `--decoy`). Under REALITY, that path must instead **splice to `dest`** (reuse REALITY.1's
`splice_to_dest`). Thread the REALITY `dest` (and the fact that we're in REALITY mode) into
`handle_connection`/`into_decoy` so the failure branch forwards to `dest` when REALITY is on.
**Subtlety:** by this point TLS is already terminated (we hold an `SslStream`), so we cannot
byte-replay the ClientHello to `dest` — instead, on inner-classification failure we open a fresh
TLS connection to `dest`, and proxy the *decrypted* application stream both ways (the authed peer
already completed our TLS, so it speaks plaintext-inside-TLS to us; we relay that to a real TLS
session with `dest`). Simplest correct behavior: treat it like the existing decoy reverse-proxy
but pointed at a fresh TLS-wrapped `dest` connection. (A misbehaving authed peer is rare — this is
belt-and-suspenders; keep it simple.)

## Config

- Reuse REALITY.1's `--reality-dest`/`--reality-private-key`/`--reality-short-id`/`--reality-server-name`.
- `--tls-cert`/`--tls-key` become optional when `--reality-dest` is set (the stolen/self-signed cert
  supersedes them for the authed branch). Keep them required for the legacy `--listen-tcp`-only
  Trojan front (no REALITY).

## Testing / adversary
- Unit: stolen-cert forgery copies subject/SAN/validity from a sample cert; anti-replay set accepts
  a fresh seal once and rejects the second within-window, accepts again after eviction.
- netns/integration: an authed connection (crafted with `yip_utls::auth::seal` + a `yip_utls`-style
  hello) terminates TLS and the presented cert's subject matches the configured `dest`'s (against a
  local stand-in `dest` TLS server); a replayed authed ClientHello is spliced to `dest`; an authed
  connection that sends a bogus inner frame is spliced to `dest` (not decoy).
- Keep the REALITY.1 active-probe property intact (un-authed ⇒ `dest`).

## Risks
- **Fetching `dest`'s cert adds an outbound TLS dial** (cached); a slow/blocked `dest` must not
  stall the authed path — bounded by a timeout + self-signed fallback.
- **The forged cert won't CA-validate** — intended (zero-CA-auth outer); documented. A future
  REALITY.4 option can add REALITY-key-based verification client-side.
- **Splice-after-termination** can't replay the ClientHello — the authed-fail fallback is a
  decrypted-stream proxy to a fresh `dest` TLS session, a slightly weaker mimic than the pre-
  termination splice; acceptable because it only fires for authenticated-but-misbehaving peers.

## Non-goals
- Client wiring / `reality://` scheme (REALITY.4). REALITY-key-based client cert verification
  (optional REALITY.4 follow-up). Changing the un-authed splice (REALITY.1, unchanged).

## Success criteria
1. Authed branch presents a cert whose subject/SAN match `dest` (or a self-signed SNI cert on dest-fetch failure); no operator cert required.
2. A replayed authed ClientHello within the window is spliced to `dest`, not served the tunnel.
3. An authed-but-inner-classification-fail connection is spliced to `dest`, not the decoy.
4. REALITY.1's un-authed→`dest` property and all existing reality tests stay green. `forbid-unsafe`, no `as`, clippy clean.
