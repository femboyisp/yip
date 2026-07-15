# REALITY.1 — server ClientHello parse + transparent `dest` forwarding — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** The relay peeks the raw TLS ClientHello *before terminating*, checks for
REALITY auth, and either (un-authed) transparently splices the connection to the real
`dest` — so a prober gets `dest`'s genuine cert — or (authed) replays the buffered
hello into the existing `boring` acceptor + `handle_connection` path.

**Architecture:** New `reality` module in `bin/yip-rendezvous` (async tier). `run_tls_front`
gains a REALITY branch: read first TLS record → parse → auth-check → splice or accept.
Until REALITY.2 ships a client that embeds auth, no connection authenticates, so every
connection forwards to `dest` (a correct, probe-faithful "relay is just a website" state).

**Tech stack:** tokio, `ring` (X25519 agreement, HMAC-SHA256 HKDF, AEAD), boring (authed
branch only).

## Global Constraints
- `bin/yip-rendezvous` is the async/relay tier (tokio allowed); the `yipd` data plane stays tokio-free.
- No `unsafe`; no bare `#[allow]` (use `#[expect(reason=)]`); no `as` casts except discriminants/libc.
- Reuse the front's existing slowloris caps (`HANDSHAKE_TIMEOUT`, `MAX_TLS_CONNS`).
- Auth-fail and forward paths must be timing/behaviour-indistinguishable: decide fully, then act.
- Inner yip protocol UNCHANGED.

---

### Task 1: REALITY crypto + ClientHello parser (`reality.rs`, pure, unit-tested)

**Files:** Create `bin/yip-rendezvous/src/reality.rs`; modify `bin/yip-rendezvous/Cargo.toml` (add `ring = "0.17"`), `bin/yip-rendezvous/src/main.rs` (`mod reality;`).

**Interfaces (Produces):**
- `struct ClientHelloInfo { sni: Option<String>, client_random: [u8;32], legacy_session_id: Vec<u8>, key_share_x25519: Option<[u8;32]> }`
- `fn parse_client_hello(record_payload: &[u8]) -> Option<ClientHelloInfo>` — parses one handshake-record payload (the `0x01` ClientHello message); `None` on malformed (fail-closed).
- `fn reality_auth_open(priv_key: &[u8;32], info: &ClientHelloInfo, short_ids: &[[u8;8]], now_unix_min: u64, skew_min: u64) -> bool` — ECDH(`priv_key`, `info.key_share_x25519`) → HKDF → AEAD-open `legacy_session_id` (nonce = `client_random[..12]`); accept iff opens AND `short_id` ∈ `short_ids` AND `|ts - now| ≤ skew_min`.
- `#[cfg(test)] fn reality_seal(server_pub:&[u8;32], eph_priv:&[u8;32], client_random:&[u8;32], short_id:[u8;8], ts_min:u64) -> [u8;32]` — the inverse, for tests (and the REALITY.2 client later).

**Steps:** write failing tests first: (1) parse a captured minimal ClientHello → correct SNI/key_share/session_id; (2) malformed/truncated → `None`; (3) seal→open round-trip authenticates; (4) wrong `short_id` → false; (5) stale `ts` (skew exceeded) → false; (6) tampered session_id → false. Then implement. Commit.

### Task 2: `PrefixedStream` + raw first-record reader (async)

**Files:** Create `bin/yip-rendezvous/src/reality_io.rs`; `mod reality_io;` in main.rs.

**Interfaces (Produces):**
- `struct PrefixedStream<S> { prefix: Vec<u8>, pos: usize, inner: S }` implementing `tokio::io::AsyncRead`/`AsyncWrite` — yields `prefix` bytes first (the buffered ClientHello) then delegates to `inner`. (For handing the authed stream to `tokio_boring::accept`, which must re-see the hello.)
- `async fn read_first_tls_record(tcp: &mut TcpStream, deadline) -> io::Result<Vec<u8>>` — reads the 5-byte record header + full record body; returns the raw record bytes (kept for replay) — the ClientHello handshake message is `record[5..]`.

**Steps:** failing test: write a fake ClientHello record into a duplex, `read_first_tls_record` returns exactly those bytes; `PrefixedStream` over a duplex yields prefix then live bytes. Implement. Commit.

### Task 3: wire the REALITY branch into `run_tls_front` + transparent splice

**Files:** Modify `bin/yip-rendezvous/src/tls_front.rs`.

**Interfaces (Consumes):** Task 1 `parse_client_hello`/`reality_auth_open`; Task 2 `PrefixedStream`/`read_first_tls_record`. **Add** to `TlsFrontCfg`: `reality: Option<RealityCfg>` where `RealityCfg { dest: SocketAddr, priv_key: [u8;32], short_ids: Vec<[u8;8]>, server_names: Vec<String> }`.

**Behaviour:** when `cfg.reality.is_some()`, replace the direct `tokio_boring::accept` with:
1. `let rec = read_first_tls_record(&mut tcp, deadline)?` (under `HANDSHAKE_TIMEOUT`).
2. `let info = parse_client_hello(&rec[5..])`.
3. authed = `info` present && `reality_auth_open(...)` && (server_names empty || SNI ∈ server_names).
4. **authed:** `tokio_boring::accept(&acceptor, PrefixedStream::new(rec, tcp))` → `handle_connection`.
5. **un-authed / any parse failure:** `let up = TcpStream::connect(dest).await?`; `up.write_all(&rec).await?`; `tokio::io::copy_bidirectional(&mut tcp, &mut up)` to EOF. Errors → drop (the prober just sees a closed upstream).

**Steps:** integration test in Task 5; here, implement + keep it compiling with the existing non-REALITY path intact (`reality: None` → unchanged 3c.3 behaviour). Commit.

### Task 4: config plumbing

**Files:** Modify `bin/yip-rendezvous/src/main.rs` (arg parse), `example.config`/docs later (Task 6).

**Add CLI/args:** `--reality-dest <host:port>`, `--reality-private-key <hex64>`, `--reality-short-id <hex16>` (repeatable), `--reality-server-name <name>` (repeatable). Build `RealityCfg`, set `TlsFrontCfg.reality`. `--reality-dest` implies REALITY mode; require `--reality-private-key` with it (error if missing). Mutually independent from the existing `--tls-cert`/`--decoy` Trojan path (REALITY supersedes the decoy when set). Commit.

### Task 5: tests — auth paths + transparent splice integration

**Files:** `bin/yip-rendezvous/src/reality.rs` tests (unit, Task 1) + a new `bin/yip-rendezvous/tests/reality_front.rs` integration test.

**Integration cases:**
- **un-authed → splice:** stand up a local "dest" TCP server that replies a fixed banner; connect to the REALITY front with a plain (no-auth) `boring` ClientHello; assert the client receives the dest banner bytes (proves the raw splice + ClientHello replay).
- **authed → accept:** craft an authed ClientHello via `reality_seal` (Task 1 test helper) embedded in a real `boring` connect is not possible (boring won't set session_id) — so assert the *server-side* decision directly: feed a captured authed record to the Task-3 decision fn and assert it routes to the accept branch. (Full authed E2E lands in REALITY.2.)
- Reuse `write_self_signed`/`build_test_client_connector`.

Commit.

### Task 6: docs + active-probe oracle note

**Files:** `docs/configuration.md`, `example.config`, `CHANGELOG.md`, and a note in the DPI-oracle script comments.

Document the four `--reality-*` flags, the "un-authed → real dest" behaviour, and that REALITY supersedes the `--decoy` Trojan path. CHANGELOG "Added" entry. Note the future active-probe CI oracle (probe with no key ⇒ must receive dest's cert). Commit.

## Self-review checklist
- Parser is fail-closed (`None` on any malformed field; never panics on attacker input).
- Forward and auth-fail paths are indistinguishable (no early return that leaks timing before `dest` connect).
- `reality: None` leaves the 3c.3 Trojan path byte-identical.
- No `unsafe`, no `as` casts, no bare `#[allow]`.
