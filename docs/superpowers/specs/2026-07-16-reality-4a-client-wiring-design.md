# REALITY.4a — client: wire `yip_utls::connect` into yipd's relay-dial (`reality://` scheme) — design spec

**Date:** 2026-07-16
**Status:** design (pending user review)
**Parent:** [`2026-07-15-reality-tls-milestone-design.md`](2026-07-15-reality-tls-milestone-design.md)
**Depends on:** REALITY.2 (merged, `crates/yip-utls` — the live-proven pure-Rust REALITY client) + REALITY.3 (merged, #77 — the server stolen-cert authed path). 3c.4 (merged) provides the relay-dial thread + socketpair bridge this replaces.
**Scope:** `yipd` client only. PR 1 of the REALITY.4 pair (**REALITY.4b** = Xray-style relay verification, separate — see Non-goals).

## Goal

Close the REALITY loop on the client: replace the 3c.4 boring TLS relay-dial handshake with
`yip_utls::connect` (the Chrome-150-faithful, PQ-hybrid, live-proven REALITY client from
REALITY.2), reached via a new `reality://` rendezvous scheme. After this lands, a yipd client can
tunnel to a peer **through a REALITY relay**, presenting a ClientHello indistinguishable from real
Chrome and authenticating to the relay via the REALITY seal — while an active prober that dials the
relay without the key still gets spliced to the real `dest` (REALITY.1/.3, unchanged).

The tunnel's security in 4a rests on the **inner peer Noise-IK** (the outer REALITY TLS is
zero-cert-auth by design). 4a documents this and proves it with a test; **REALITY.4b** adds explicit
Xray-style relay authentication on top.

## Background (current 3c.4 relay-dial path)

`rendezvous=tls://host:port` (`Rendezvous::Tls { host, port }`) drives a relay-dial client that is
deliberately **tokio-free**:

- `tunnel.rs` creates a `UnixDatagram::pair()` → `(relay_thread_sock, data_plane_sock)`, spawns the
  **relay-dial thread** (`relay_client::spawn` → `run`), and runs the **data-plane loop**
  (`relay_client::run_relay_tls`) on the tunnel thread.
- The **relay-dial thread** (`run`, a `std::thread`) loops: `connect_and_handshake` (a synchronous
  boring `SslConnector` dial driven by a hand-rolled `Epoll` handshake, returning
  `SslStream<TcpStream>`) → write the obf'd monotonic `Register` **first** → pump length-prefixed
  `[u16 BE len][datagram]` frames between the `SslStream` and the socketpair → on any error, back off
  and reconnect.
- The **data-plane loop** (`run_relay_tls`) epolls the socketpair + TUN and runs `PeerManager`
  (`on_udp`/`on_tun`/`tick`), bridging to the relay thread over the socketpair. This is the
  latency-critical packet path and **stays sync/epoll, tokio-free, unchanged**.

## Design

Only the **relay-dial thread** changes. The socketpair bridge, the framing, Register-first,
reconnect-with-backoff, and the entire data-plane loop are preserved.

### 1. Config — the `reality://` scheme (`config.rs`)

Add a `Rendezvous::Reality` variant carrying everything the client needs to dial:

```rust
pub enum Rendezvous {
    Udp(SocketAddr),
    Tls { host: String, port: u16 },
    Reality {
        host: String,
        port: u16,
        /// Relay's REALITY X25519 public key (pinned; `pbk=` 64 hex).
        pubkey: [u8; 32],
        /// Auth short-id (`sid=` 16 hex).
        short_id: [u8; 8],
        /// Borrowed SNI presented in the ClientHello (`sni=` domain).
        sni: String,
    },
}
```

Parse `rendezvous=reality://<host>:<port>?pbk=<64hex>&sid=<16hex>&sni=<domain>`:

- **Host:port** reuses the existing `tls://` splitter (`split_tls_host_port`-style), including
  bracketed IPv6 (`reality://[2001:db8::1]:443?...`). Refactor that helper to be scheme-agnostic
  (shared by `tls://` and `reality://`) rather than duplicating it.
- **Query params** (`pbk`, `sid`, `sni`) mirror Xray's REALITY naming for operator familiarity.
  Parse the `?…` tail into key=value pairs (simple `split('&')` / `split_once('=')`; no percent-
  decoding needed — hosts/hex/domains don't require it, and rejecting `%` keeps it strict).
  Fail-closed on: missing any of the three required params, `pbk` not exactly 64 hex (→ `[u8;32]`
  via the existing `hex_to_32`), `sid` not exactly 16 hex (→ `[u8;8]` via `hex_to_8`), empty `sni`,
  or an unknown param key.
- **`verify=` is reserved for REALITY.4b** — 4a **rejects** it with a clear "not yet supported
  (REALITY.4b)" error rather than silently ignoring it, so a config written for 4b fails loudly on a
  4a binary instead of running unverified.
- `reality://` **requires `obf_psk`** (the inner tunnel discriminator), exactly as `tls://` does —
  reuse the existing check.

### 2. Async relay-dial (Approach A) — confined tokio runtime (`relay_client.rs`)

Replace the relay-dial thread's boring path with an async one, confined to this one thread. The
data-plane loop and socketpair are untouched.

- **New entry point** `relay_client::spawn_reality(host, port, pubkey, short_id, sni, obf_key,
  self_node, relay_thread_sock)`, spawned from `tunnel.rs` for the `Reality` arm (mirrors the
  existing `spawn`). It `std::thread::spawn`s a thread whose body builds a **current-thread tokio
  runtime** (`tokio::runtime::Builder::new_current_thread().enable_all().build()`) and
  `block_on`s the reconnect loop.
- **Reconnect loop** (async): `tokio::net::TcpStream::connect((host, port))` (re-resolve each
  attempt, as today) → `tcp.set_nodelay(true)` → `yip_utls::connect(tcp, &sni, &pubkey, short_id)`
  → `RealityStream`. On connect/handshake error: log, back off (reuse the existing backoff
  schedule), retry.
- **Register-first**: immediately write the obf'd monotonic `Register` frame over the
  `RealityStream` before pumping (the relay classifies on the first frame — unchanged requirement).
- **Async pump**: wrap `relay_thread_sock` as `tokio::net::UnixDatagram` (`UnixDatagram::from_std`
  after `set_nonblocking(true)`), then `tokio::select!` between:
  - `RealityStream` readable → read length-prefixed frames (reuse the framing: `[u16 BE len][dg]`),
    each decoded datagram → `sock.send(dg)` to the data-plane thread.
  - `sock.recv(dg)` from the data-plane thread → length-prefix + `RealityStream.write_all`.
  - a keepalive/Register-refresh timer (`tokio::time::interval`) → rewrite `Register` (preserve the
    3c.4 keepalive cadence that stops the relay expiring the connection).
  On any stream error / EOF, break → the reconnect loop backs off and redials.
- **Framing** is unchanged (`frame_datagram` / a `FrameReader`-equivalent over the async stream).
  The socketpair remains one-datagram-per-`send`/`recv` (`SOCK_DGRAM`, atomic — the 3c.4 review's
  backpressure decision stands).
- **No new `yip_utls` API** — `connect` + `RealityStream` (AsyncRead/AsyncWrite) are used exactly as
  REALITY.2 shipped and proved against Cloudflare.

### 3. Zero-cert-auth handling (4a)

`yip_utls::connect` validates no server certificate (the REALITY camouflage). In yip the relay is a
**dumb forwarder**; the tunnel's confidentiality/integrity come from the **end-to-end peer
Noise-IK** (self-certifying pubkey addresses). So an outer-TLS MITM or a malicious relay sees only
inner peer ciphertext and can, at worst, **DoS** (drop/garble) — never read or forge tunnel traffic.

4a makes this explicit:

- A prominent module-doc caveat in the reality relay-dial path stating the outer TLS is zero-auth
  and the inner peer handshake is the security boundary (cross-referencing the milestone spec's
  REALITY.4 hard caveat).
- A **wrong-relay-pubkey test** (see Testing): configuring a `pbk` that does not match the relay's
  real REALITY key ⇒ the server's seal-open fails ⇒ the connection is **spliced to `dest`** ⇒ the
  client never establishes a tunnel (no valid inner path). This proves, end to end, that the outer
  layer authenticates nothing and the inner layer is what gates a working tunnel.

### 4. `tunnel.rs` wiring

Add a `Some(Rendezvous::Reality { host, port, pubkey, short_id, sni })` arm mirroring the existing
`Tls` arm: create the `UnixDatagram::pair()`, `relay_client::spawn_reality(...)` the relay-dial
thread, then `run_relay_tls(...)` the data-plane loop (identical call — the data plane is
scheme-agnostic; it only speaks obf'd envelopes over the socketpair). The `Tls` arm stays for the
non-REALITY 3c.4 path.

## Config surface / docs

- `rendezvous=reality://host:port?pbk=<64hex>&sid=<16hex>&sni=<domain>` (requires `obf_psk`).
- Update `bin/yipd/example.config` (add a commented `reality://` example next to the `tls://` one)
  and `docs/configuration.md` (the scheme, its params, the obf_psk requirement, and a one-line note
  that outer TLS is zero-cert-auth / inner Noise-IK is the security boundary, with REALITY.4b adding
  relay verification).

## Testing / adversary

- **Unit (config):** `reality://` parses to the right `Rendezvous::Reality` (host/port/pubkey/
  short_id/sni); bracketed IPv6 host; fail-closed on missing/short/long `pbk`/`sid`, empty `sni`,
  missing params, unknown param key, and `verify=` (rejected as 4b-only); `reality://` without
  `obf_psk` is rejected.
- **netns money test** (`bin/yipd/tests/`): two UDP-blocked peers bring a tunnel up **through a
  REALITY relay** (a `yip-rendezvous` started with `--reality-dest`/`--reality-private-key`/
  `--reality-short-id`/`--reality-server-name`), A pings B, relay-forwarded count > 0, and the
  client's dial is REALITY (crafted Chrome hello, seal auth). Mirrors the 3c.4
  `run-netns-relay-tls.sh` money test, swapping `tls://` for `reality://`.
- **Wrong-pubkey no-tunnel test:** same setup but the client's `pbk` ≠ the relay's real key ⇒ no
  tunnel comes up (server splices to `dest`); asserts the client does not get a working relay path.
- **Active-probe** property is already covered server-side (REALITY.1/.3): un-authed dial ⇒ spliced
  to `dest`, never a relay/self-signed cert. No new server work here; the netns test's relay is the
  REALITY.3 server unchanged.
- **JA3/JA4** fidelity is REALITY.2's (`yip-utls` JA4-diff CI test), inherited unchanged.

## Risks

- **Async runtime on the relay-dial thread.** Approach A gives that one thread a current-thread
  tokio runtime. Mitigation: it is confined to the relay-dial thread; the latency-critical
  data-plane loop (`run_relay_tls` + `PeerManager`) stays sync/epoll and untouched. tokio already
  enters yipd transitively via `yip_utls`, so this is not a new heavyweight dependency.
- **Socketpair ↔ async bridging.** Wrapping the `std` `UnixDatagram` as tokio must preserve the
  `SOCK_DGRAM` atomic-datagram semantics (one `send` = one envelope). Mitigation: `set_nonblocking`
  + `UnixDatagram::from_std`; datagram boundaries are preserved by the socket type, not the wrapper.
- **Reconnect/backoff parity.** The async loop must keep the 3c.4 reconnect-with-backoff +
  Register-first + keepalive cadence so a dropped relay connection recovers identically. Mitigation:
  port the existing schedule verbatim; covered by the netns test surviving a relay bounce.
- **Fingerprint drift** (inherited): `yip_utls`'s Chrome-150 hello is a maintenance surface; the
  REALITY.2 JA4-diff test guards it. Out of scope to re-solve here.

## Non-goals (REALITY.4b and beyond)

- **REALITY.4b — Xray-style relay verification (default ON).** The server binds the seal's ECDH
  shared secret into the cert/handshake it presents; the client verifies (it derives the same
  shared secret) and, on failure, **falls back to plain-browser behavior** instead of retry-looping
  (client-side active-probe resistance). Configurable via `verify=` on the `reality://` URL, default
  ON. Requires a server-side addition (REALITY.3's forged leaf is self-signed by a throwaway key and
  does **not** bind the shared secret) plus client verification + fallback in `yip_utls`.
  Security-sensitive; its own spec. (Recorded here + in the milestone spec so it is not lost.)
- Changing the un-authed splice, the server authed path, or the data-plane loop.
- P2P `transport=tls`/direct REALITY (relay path only here, as in 3c.4).

## Success criteria

1. `rendezvous=reality://host:port?pbk=…&sid=…&sni=…` parses fail-closed into `Rendezvous::Reality`;
   `verify=` is rejected as 4b-only; `reality://` requires `obf_psk`.
2. A yipd client dials a REALITY relay via `yip_utls::connect` on a confined async relay-dial thread
   (data plane untouched), Register-first + reconnect-with-backoff + keepalive preserved, framing
   unchanged; two UDP-blocked peers tunnel end-to-end through the relay (netns money test green).
3. A wrong `pbk` yields no tunnel (server splices to `dest`) — proving the outer TLS authenticates
   nothing and the inner Noise-IK is the security boundary; documented as the 4a caveat.
4. `yip_utls` is used as-shipped (no new API); the JA3/JA4 fidelity test stays green. `yipd` stays
   `forbid-unsafe` outside `yip-io`/`yip-device`; no `as` casts; clippy clean.
