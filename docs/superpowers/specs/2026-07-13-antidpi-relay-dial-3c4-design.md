# Sub-project #3 Milestone 3c.4: TLS relay-dial client — Design

**Status:** draft (under review)
**Sub-project:** #3 (anti-DPI / censorship resistance), milestone 3c.4. 3a
(`obf_psk`) #43, 3b #47, 3c.1 (QUIC mimicry) #48, 3c.2 (TLS costume) #62, and
3c.3 (REALITY-style relay front) #66 are merged. On main after #66.

---

## 1. Goal

Give `yipd` the **client half** of the 3c.3 relay: when configured with
`rendezvous = "tls://relay.example.com:443"`, a node reaches the relay over a
**persistent, browser-looking TLS connection** instead of UDP — so a user on a
UDP-blocked network can actually *use* the relay we built in 3c.3. Both peers
dial the relay over 443, register, and the relay bridges their traffic.

3c.3 built the relay's Trojan front (it terminates real-cert TLS and routes a
fresh obfuscated `Register` to the tunnel). 3c.4 is the `yipd` side that dials
it: reuse 3c.2's browser-parrot TLS client to connect, speak the **frozen wire
contract** (3c.3 §5.3) — obf'd `Register` first, then `RelaySend`/`RelayDeliver`
framed over the TLS byte-stream — and carry the unchanged inner yip protocol as
the relayed payload.

## 2. What this is NOT (non-goals + hard boundaries)

- **Not tokio on the data plane.** The persistent TLS-relay connection runs on a
  dedicated `std::thread`; the single-threaded epoll/uring data-plane hot loop
  stays **tokio-free** (the guardrail defended in 3c.3). The thread bridges to
  the data plane through channels + an eventfd.
- **Not a Direct/hole-punch path.** `tls://` *means* UDP is blocked, so the 2b
  Direct → UDP-punch → Relay escalation is skipped entirely — there is no point
  spending ~8 s failing UDP attempts. The path is **straight-to-relay**: register,
  then relay all peer traffic. Hole-punching is inherently UDP and does not apply.
- **Not discovery/`Lookup` over TLS.** Peers relay by `NodeId` (the sender
  `RelaySend`s to the destination `NodeId`; the relay bridges two registered
  peers), so no `Lookup` signaling is carried. 2c mesh discovery/gossip over the
  relay is future work.
- **Not the direct `transport=tls` peer path.** Dialing a *peer's own* TCP/443
  endpoint is 3c.2 (`transport=tls`, a per-peer data transport). 3c.4 dials the
  **relay** (`rendezvous = tls://`, a signaling+relay axis). They are distinct
  config axes and may coexist later without extra work; 3c.4 is the relay-dial
  half only.
- **Not a change to the inner protocol.** Noise-IK, FEC, AEAD, cert admission,
  rekey are byte-for-byte the raw-path logic. 3c.4 changes only how relay-path
  bytes reach the relay.

## 3. Approach (in one line)

Spawn a dedicated **relay-client thread** that holds one persistent
browser-parrot TLS 1.3 connection to the relay (reusing 3c.2's `run_tls`
client), sends the obfuscated `Register` and keepalives, and pipes obf-wrapped
`RelaySend`/`RelayDeliver` envelopes between the TLS stream and the data plane
over channels — while `PeerManager` runs unchanged, addressing the relay exactly
as it addresses a UDP relay today.

## 4. Architecture

### 4.1 Concurrency: a dedicated relay-client thread

`tunnel.rs` spawns one `std::thread` (only when `rendezvous = Tls{…}`) that owns
the TLS connection and is the sole place TLS/handshake/reconnect logic lives. It
is driven by its own small `yip_io::epoll` watching **two** fds:
- the **TLS socket** (readable ⇒ incoming relay frames);
- a **wakeup eventfd/pipe** the data plane pokes when it has bytes to send.

No tokio; off the hot loop. The already-slow relay path makes the channel-hop
latency irrelevant.

### 4.2 The two channels + the eventfd

- **data-plane → thread** (`mpsc`): an obf-wrapped `RelaySend` envelope destined
  for the relay. The data plane writes it and signals the wakeup eventfd; the
  thread `[u16 BE len]`-frames it and writes it to TLS.
- **thread → data-plane** (`mpsc` + an eventfd the poll loop watches): a relay
  frame arrived; the thread deframes it and pushes the obf-wrapped envelope
  bytes. The poll loop, on the eventfd, drains the queue into
  `PeerManager::on_udp(relay_addr, bytes)`.

The thread is otherwise a **framed pipe**: it does not parse
`RelaySend`/`RelayDeliver` — those stay opaque obf'd envelopes that `PeerManager`
builds and consumes. The one exception is `Register` (§4.4), which is
connection-lifecycle and therefore the thread's to own.

### 4.3 `PeerManager` is unchanged; the relay is an addressed endpoint

`PeerManager` already talks to "the relay" as a `SocketAddr` and already
produces obf-wrapped `RelaySend` envelopes for relay-path peers (2b). 3c.4
resolves the relay to a `SocketAddr` (its real IP:port) used purely as a
**routing key**:
- an egress whose `dst == relay_addr` is routed to the **channel** (not
  `udp.send_to`);
- channel-received bytes are fed to `PeerManager::on_udp(relay_addr, bytes)`.

So `PeerManager` believes it is talking to a UDP relay at that address; the poll
loop bridges that address to the thread's channels. No `PeerManager` inner
change. **Straight-to-relay** means every peer's path is relay-only (no
Direct/punch), so all peer egress flows to the channel.

### 4.4 `Register` lifecycle (owned by the thread)

`Register` is connection-scoped, not per-peer, so the thread owns it: it builds,
obf-wraps (with the `obf_psk`-derived key), and sends
`Register{node = self, counter}` on connect and on a **~30 s keepalive** (the
relay's registration TTL is 60 s). `counter` is a **per-boot monotonic** value
starting at 1, incremented on every `Register`, satisfying the relay's
`register_if_fresh_tls` strictly-greater gate. The thread needs only self
`NodeId`, the obf key, and the counter for this.

### 4.5 Connection lifecycle

Reusing 3c.2's `run_tls` client primitives:
- Connect (TCP) → browser-parrot TLS handshake (SNI = the relay host, accept-any
  cert, bounded by 3c.2's `HANDSHAKE_TIMEOUT`) → send `Register`.
- **Reconnect-with-backoff** on any teardown (3c.2's
  `INITIAL_BACKOFF_MS`→`MAX_BACKOFF_MS`); re-`Register` (counter++) on reconnect.
- The data plane **never blocks** on reconnect: outbound `RelaySend`s while
  disconnected are dropped (inner FEC/ARQ recovers, as on any transport blip);
  inner Noise sessions re-handshake.

### 4.6 Poll-driver-only

`rendezvous = tls://` forces the poll driver, consistent with the existing
mimicry paths (`transport=quic`/`tls` are poll-only). Only the poll loop needs
the eventfd wiring; the uring driver is untouched.

## 5. Config surface

The `rendezvous` key gains the `tls://` scheme (frozen in 3c.3 §5.3).
`Config.rendezvous` becomes an enum:

| Value | Parses to | Notes |
|---|---|---|
| `rendezvous = 203.0.113.9:51821` | `Rendezvous::Udp(SocketAddr)` | Today's behavior, unchanged. |
| `rendezvous = tls://relay.example.com:443` | `Rendezvous::Tls { host, port }` | Dials the relay over browser-parrot TLS. |

- **SNI = the relay host** (from the URL). The 3c.3 relay owns a real cert for
  that domain, which resolves to its IP — no SNI/IP mismatch (3c.3's self-decoy
  model). No separate SNI key.
- **`obf_psk` is REQUIRED** with a `tls://` rendezvous — it is the relay's
  discriminator (the `Register` obfuscation key). Config load errors if `tls://`
  is set without `obf_psk`. (The `transport=tls` ⊥ `obf_psk` rule governs the
  peer **data** transport axis; the rendezvous **signaling** axis requires
  `obf_psk`. The loader must permit — and here require — that combination.)
- **Cert handling: accept-any** (reusing 3c.2's client verifier). The relay is a
  blind relay; the real end-to-end authentication is the inner Noise-IK between
  peers, and a TLS-MITM of the relay connection sees only obf-wrapped ciphertext
  and, lacking `obf_psk`, cannot even confirm it is yip. Real cert validation
  would be marginally more browser-like but changes nothing on the wire — noted
  as optional hardening, out of scope.

## 6. Security & correctness invariants

1. **Inner protocol unchanged.** 3c.4 is transport only; the relay stays blind
   (obf-wrapped ciphertext end to end).
2. **Opt-in, default byte-identical.** `rendezvous` absent or `<ip:port>` ⇒ no
   relay thread, no TLS — exactly today's 2b behavior. Only `tls://` spawns the
   thread.
3. **Data plane stays tokio-free & low-latency.** A plain `std::thread`; the hot
   loop gains only an eventfd drain (poll-only). No tokio in the data plane.
4. **`obf_psk` required and is the discriminator.**
5. **Browser-parrot handshake, SNI = real relay host** (3c.2's proven Chrome-JA4
   client; no SNI/IP mismatch).
6. **Fail-safe reconnect.** A teardown never blocks the data plane; outbound
   drops during a disconnect; inner Noise re-handshakes. `counter` monotonic per
   boot.
7. **Probe/threat boundary inherited from 3c.3.** Relay probe-resistance is
   `obf_psk` secrecy (the ~21-bit-discriminator caveat, #64) and signed
   registrations (#37) remain the durable fixes — 3c.4 does not change the
   relay's boundary, it only dials in.

## 7. Testing

- **Unit:** config parse (`tls://` ⇒ `Rendezvous::Tls`; `tls://` without
  `obf_psk` ⇒ load error; the UDP form and the absent case unchanged); the
  relay-client `[u16 BE len]` framing round-trip (reuse the 3c.2 framing test
  shape); `Register` counter monotonically increments across (re)connects.
- **netns money test (the headline):** two `yipd` in separate netns with **UDP
  dropped between them** (nft/iptables), each configured `rendezvous = tls://
  relay`, peers referenced by `NodeId` only (no endpoint), plus a `yip-rendezvous
  --listen-tcp` relay with a test cert + `--obf-psk`. Assert: both register over
  TLS; a **ping A→B succeeds, relayed through the relay** (`relay-forwarded > 0`
  on the server); and the peer↔relay traffic is **TCP/TLS, not UDP**. This is the
  end-to-end proof that two UDP-blocked peers tunnel via the TLS relay.
- **nDPI:** the money test's capture of the `yipd`→relay handshake classifies as
  TLS/HTTPS with the relay SNI (largely inherited — the client reuses 3c.2's
  proven browser-parrot ClientHello, JA4 = Chrome).
- **No-regression:** the UDP rendezvous suite (`relay_path_ping`,
  `hole_punch_ping`, discovery) stays green — the UDP path and `PeerManager` are
  unchanged; full workspace tests + `clippy -D warnings`.

## 8. Scope & files

- **Create:** `bin/yipd/src/relay_client.rs` (the relay thread: TLS connection +
  `Register` lifecycle + framed pipe + reconnect + the epoll/eventfd/channels),
  the netns money-test script (`bin/yipd/tests/run-netns-relay-tls.sh`) + its
  harness test.
- **Modify:** `bin/yipd/src/config.rs` (the `Rendezvous` enum, `tls://` parse,
  `obf_psk`-required check), `bin/yipd/src/tunnel.rs` (spawn the thread + wire
  the channels/eventfd into the poll loop; force the poll driver for `tls://`;
  route relay-addressed egress to the channel and drain the channel into
  `on_udp`), `bin/yipd/Cargo.toml` (no new deps expected — `boring`/`rcgen`
  already present from 3c.2), docs (`docs/configuration.md`, `CHANGELOG.md`),
  `.github/workflows/integration.yml` (the new netns money test).
- **Untouched:** `PeerManager` inner logic (Noise/FEC/AEAD/admission), `yip-wire`,
  `yip-crypto`, `yip-transport`, the UDP rendezvous path, the uring driver, the
  3c.1/3c.2 peer transports, the 3c.3 relay.

**Out of scope (later):** `Lookup`/discovery over the TLS relay; 2c mesh
discovery/gossip over the relay; real relay-cert validation (optional
hardening); composing a direct `transport=tls` peer path with a `tls://`
rendezvous in one session.
