# Sub-project #3 Milestone 3c.3: REALITY-style Relay (the Trojan-front relay) — Design

**Status:** draft (under review)
**Sub-project:** #3 (anti-DPI / censorship resistance), milestone 3c.3. 3a
(`obf_psk`) #43, 3b (junk/traffic-shaping) #47, 3c.1 (QUIC mimicry) #48 are
merged; 3c.2 (TLS costume) is in review (#62). This milestone builds the
**active-probe defense** the 3c.2 spec explicitly deferred to the relay tier.

---

## 1. Goal

Make the yip **relay** (`yip-rendezvous`) survive an **active probe**. 3c.1/3c.2
defeat *passive* classification (the flow looks like QUIC/HTTPS). They do **not**
survive a censor that *connects to the relay itself* and checks whether a real
website answers: 3c.2's TLS costume is zero-auth, so a self-signed cert for a
fake SNI is unmasked on the first probe.

3c.3 gives the relay a **Trojan-style front**: it terminates a *real* TLS 1.3
connection with a *real* certificate for a *real* domain the operator owns, and
multiplexes **inside** the encrypted stream. A genuine yip client proves itself
with a fresh, obfuscated rendezvous `Register`; **anyone else — a censor's probe,
a scanner, a curious human — is transparently proxied to a real decoy website**
and sees exactly what a normal HTTPS site serves. The relay is indistinguishable
from an ordinary web server to anyone who does not hold the network secret.

This is the **Trojan** model (own the cert, authenticate in-stream), **not** the
literal Xray **REALITY** model (borrow a third party's cert, authenticate in the
ClientHello). We keep "REALITY-style" as the milestone label because the *goal*
(hide a tunnel behind a real site, reverse-proxy probes) is REALITY's; the
*mechanism* is Trojan's, which is the correct choice once the operator owns the
certificate (see §3).

## 2. What this is NOT (non-goals + hard boundaries)

- **Not the `yipd` client dialer.** 3c.3 is the **relay/server** front only. The
  `yipd` side — dialing the relay over TLS/443 with a browser-parrot ClientHello
  and speaking rendezvous over the TLS stream — is milestone **3c.4**. To keep
  3c.4 implementable against a frozen interface, 3c.3 **specifies the
  client-facing wire contract** (§5.3) even though no production client is built
  here; 3c.3 is verified with a test-only client harness (§7).
- **Not tokio on the data plane.** tokio is introduced **only** in
  `yip-rendezvous` (control/relay tier, already latency-traded-for-reachability).
  The `yipd` data-plane hot path (`run_poll`/`run_uring`, the single-threaded
  mutex-free loop from the 4a/4b throughput campaign) stays **100% async-free** —
  no tokio, no scheduler, bespoke epoll/uring drivers only. This boundary is a
  hard invariant, restated here so no later change "helpfully" tokio-ifies the
  fast path.
- **Not cryptographic peer authentication at the relay.** The relay is a **blind**
  relay (2b): it has no peer static keys and does not verify end-to-end
  membership certs. Its probe-discriminator is knowledge of the network-wide
  `obf_psk` (§4.3), so relay probe-resistance is **exactly as strong as `obf_psk`
  secrecy** (§6). This is the same trust boundary as all of 3a, and the same
  shape as REALITY's own server-side preshared secret (its `ShortId`). Signed
  registrations (#37) are the durable hardening and are out of scope here.
- **Not a bundled web server.** The convincing decoy is a **real** local site the
  operator runs and points `--decoy` at. 3c.3 ships only a minimal static
  fallback page for zero-config deployments, explicitly documented as the
  *weaker* option (a page that never changes / has no working links is itself a
  tell).
- **Not port-plausibility defaults.** Defaulting the relay to `:443` is the
  operator's deployment choice; yip's default-port work is 3d (#45).

## 3. Approach (in one line)

Upgrade `yip-rendezvous` to a **tokio** async service that runs its existing UDP
rendezvous loop **and** a new **TCP/TLS/443** listener; the TLS listener
terminates a real-cert TLS 1.3 handshake, trial-reads the first in-stream frame,
routes a **valid fresh obfuscated `Register`** to the tunnel and **everything
else** to a real decoy website via bidirectional proxy.

## 4. Architecture

### 4.1 Concurrency model (`yip-rendezvous` → tokio)

`yip-rendezvous` moves from a single-threaded blocking UDP loop to a
**multi-threaded tokio runtime** running two concurrent listener tasks:

- **UDP listener task** — drives the existing `RendezvousServer` soft-state
  registration, rate-limiting, and blind relay forwarding, unchanged in
  behavior.
- **TCP/TLS listener task** — accepts on the configured TCP port, terminates TLS
  with `tokio-boring` (BoringSSL), and `tokio::spawn`s one `handle_connection`
  task per accepted connection.

`RendezvousServer` is currently a **pure, no-I/O state machine**. It is shared
across tasks by a **single coordinator** (either `Arc<Mutex<RendezvousServer>>`
or one owner task fed by an `mpsc` channel — implementation choice at plan time),
so every mutation is serialized and the pure state machine is unchanged. The
crate stays `#![forbid(unsafe_code)]` (tokio + tokio-boring keep unsafe in
dependencies).

### 4.2 TLS termination (the real costume)

The TCP/TLS listener presents the operator's **real certificate** (e.g. Let's
Encrypt `fullchain.pem` + `privkey.pem`) for a domain that genuinely resolves to
the relay's IP. This structurally eliminates the SNI-vs-IP/ASN mismatch that is
the documented way REALITY-style setups are caught (and which our own 3c.2 nDPI
oracle already surfaced as a risk).

The **server-side** TLS configuration must mirror a mainstream web server
(**nginx 1.24+**): TLS 1.3 + 1.2, standard cipher order, session tickets on,
ALPN offering `h2` then `http/1.1` in the conventional order. The real cert is
not sufficient — a nonstandard *server* handshake is itself a fingerprint.

### 4.3 The discriminator (trial-read → obf → fresh `Register`)

After the TLS handshake completes, `handle_connection`:

1. **Trial-read** decrypted application bytes into a buffer under a short
   `CLASSIFICATION_TIMEOUT` (~3 s), used **only** to make the routing decision
   (see §4.4 for why this timeout is not a fingerprint).
2. Parse a length prefix `len = u16::from_be_bytes(buf[0..2])` (the same
   `[u16 BE len][payload]` framing 3c.2 uses on the TLS byte-stream). Read until
   `2 + len` bytes are buffered or the timeout fires. Implausible `len` (below a
   minimum rendezvous-message size or `> TLS_FRAME_MAX`) ⇒ **decoy**.
3. **Deobfuscate** `envelope = buf[2..2+len]` with `obf_key` (derived from the
   relay's configured `--obf-psk`, exactly as the UDP path already does), requiring
   the dedicated `yip_obf::RDV_TYPE`. Failure ⇒ **decoy**.
4. **Decode** the plaintext as a `yip_rendezvous::Message`. Not a well-formed
   `Message::Register` ⇒ **decoy**.
5. **Freshness check** (§4.6): the `Register`'s monotonic counter must be strictly
   greater than the last one recorded for this `NodeId`. Stale/replayed ⇒
   **decoy**.

Only if **all** checks pass is the connection upgraded to a tunnel (§4.5).
Crucially, the branch is on **input** — a probe never observes tunnel behavior,
because anything that is not a valid fresh `Register` is proxied to the decoy
before the relay emits any rendezvous-shaped response.

### 4.4 Decoy handoff (the Trojan path)

On any decoy classification (including the idle-timeout case):

- If `--decoy <addr>` is set, open a plain TCP connection to it, **write the
  entire buffered plaintext** (the probe's `GET /…` or whatever bytes arrived) to
  the decoy socket, then `tokio::io::copy_bidirectional` between the decrypted TLS
  stream and the decoy socket. The relay is now a transparent TLS-terminating
  reverse proxy in front of a real website; the prober's experience *is* that
  website.
- **Idle case (no bytes within the timeout):** do **not** close. Hand the
  (empty) stream to the decoy immediately and let the **decoy server's native
  idle timeout** (nginx ~60–75 s) govern when the connection closes. Imposing our
  own short close would be a timing fingerprint distinct from a real server; the
  fix is to never let our classification timeout be observable — the decoy's
  behavior is the only behavior a probe ever measures.
- If `--decoy` is unset, serve the bundled minimal static `200 OK` page and close
  (documented weaker fallback, §2).

### 4.5 Active tunnel path (upgrade)

On a valid fresh `Register`:

- Record the connection's **writer channel** in the shared state, keyed by
  `NodeId` (a TCP/TLS registration alongside the existing UDP registrations).
- Process the `Register` and send a framed, obfuscated reply
  (`[u16 len][obf envelope]`) back over the TLS stream.
- Enter the frame loop: read `[u16 len][obf Message]` frames; on
  `RelaySend { dst, payload }`, look up `dst`'s active registration — which may be
  a **UDP source address** (UDP-connected peer) *or* **another TCP/TLS writer
  channel** (TLS-connected peer) — and forward as `RelayDeliver` over whichever
  transport that peer is on. The realistic hostile-network path is
  **TLS-client-A ↔ relay ↔ TLS-client-B**, both over 443; UDP↔TLS bridging is
  supported for mixed reachability.
- On close/error, evict the `NodeId`'s TCP/TLS registration.

### 4.6 `Register` freshness field (wire addition)

`Message::Register` currently carries **only** `{ node: NodeId }` — there is no
timestamp or sequence, so replay protection has nothing to check. 3c.3 **adds a
monotonic `counter: u64`** to `Register`:

```
Register { node: NodeId, counter: u64 }
```

The relay records the highest `counter` seen per `NodeId` (in the same soft-state
map as the registration) and rejects any `Register` whose counter is not strictly
greater. This is encoded inside the obf envelope, so it is confidential and
integrity-covered by the existing obf construction. The UDP rendezvous path adopts
the same field (one shared codec), so the UDP and TLS paths stay wire-compatible.

## 5. Config surface

### 5.1 `yip-rendezvous` (new CLI flags)
| Flag | Value | Notes |
|---|---|---|
| `--listen-tcp <addr>` | e.g. `0.0.0.0:443` | Enables the TCP/TLS Trojan front. Absent ⇒ UDP-only, byte-identical to today. |
| `--tls-cert <path>` | PEM chain | The real domain's `fullchain.pem`. Required with `--listen-tcp`. |
| `--tls-key <path>` | PEM key | `privkey.pem`. Required with `--listen-tcp`. |
| `--decoy <addr>` | e.g. `127.0.0.1:8080` | Local real decoy site. Absent ⇒ bundled static-page fallback. |

`--obf-psk` is **required** with `--listen-tcp` (it is the discriminator).

### 5.2 `yipd` (config, consumed in 3c.4 — specified now to freeze the contract)
The `rendezvous` key gains a URL scheme so the TLS-relay path is unambiguous and
does **not** collide with the 3c.2 `transport=tls` ⊥ `obf_psk` guard (that guard
governs the peer **data** transport; this is the rendezvous **signaling** axis):

- `rendezvous = "203.0.113.9:51821"` ⇒ UDP (today's behavior).
- `rendezvous = "tls://relay.example.com:443"` ⇒ dial over TCP/TLS (3c.4).

`obf_psk` remains set on the node for rendezvous signaling in both cases; the
`transport=tls`/`obf_psk` mutual-exclusion applies only to peer data transport,
so the config loader must permit `obf_psk` + a `tls://` rendezvous together.

### 5.3 Frozen client-facing wire contract (for 3c.4)
1. TCP connect to the relay's `--listen-tcp` address; TLS 1.3 handshake with a
   **browser-parrot ClientHello** (reuse 3c.2 `run_tls` client + boring GREASE).
2. First application record: `[u16 BE len][ obf(RDV_TYPE, Register{node,counter}) ]`,
   `counter` strictly increasing per relay session/boot.
3. Relay reply: `[u16 BE len][ obf(RDV_TYPE, <reply Message>) ]`.
4. Subsequent frames: `[u16 BE len][ obf(RDV_TYPE, Message) ]` (`RelaySend` etc.).
A client that deviates (plain HTTP, wrong/absent obf, stale counter) is served the
decoy — so 3c.4 must implement this exactly.

## 6. Security & threat model

1. **Probe-resistance == `obf_psk` secrecy.** A prober without `obf_psk` cannot
   forge a `Register`, so it is always routed to the decoy and sees a real
   website. If `obf_psk` **leaks**, a prober can forge a `Register` and unmask the
   relay. This is the same boundary as all of 3a (compromise ⇒ fingerprintable,
   not decryptable) and the same shape as REALITY's server-side `ShortId` secret.
   The durable fix is **signed registrations (#37)**; cross-referenced, not solved
   here.
2. **Replay horizon = registration TTL (`REG_TTL_MS` = 60 s).** The monotonic
   counter (§4.6) rejects a replayed `Register` — but the per-`NodeId` counter
   lives in soft state, so once a `NodeId` is swept (60 s idle) its last counter
   is forgotten and a captured envelope could be replayed again. Bounded, and
   #37's signing is the durable fix. **Narrowing nuance:** the obf'd `Register`
   rides *inside* TLS, so a **passive** on-path censor cannot capture it to replay
   — replay requires already holding a valid envelope (needs `obf_psk`) or being
   the TLS endpoint (needs the relay's cert key). The counter is therefore
   defense-in-depth against a leaked/defector-held capture, not the primary
   probe defense.
3. **Blind relay unchanged.** The relay still never sees inner tunnel plaintext
   (peers run Noise-IK end-to-end over the relayed payload). 3c.3 changes how
   peers *reach* the relay, not what the relay can read.
4. **Server-handshake realism.** §4.2 — the server TLS config mirrors nginx so
   the *server* side of the handshake is not itself a fingerprint.
5. **Resource safety.** Per-connection tokio tasks with the classification
   timeout; the decoy path hands off promptly so a flood of probes costs a proxy
   connection each (bounded by the existing rate-limit posture), not unbounded
   relay state.

## 7. Testing

- **Unit (`yip-rendezvous`):** the `Register{node,counter}` codec round-trip and
  monotonic-freshness accept/reject; the trial-read framing/deobfuscation
  classifier (valid fresh `Register` ⇒ upgrade; bad len / bad obf / non-Register
  / stale counter ⇒ decoy) driven by in-memory buffers.
- **Probe-resistance oracle (the money test, root/netns):** stand up
  `yip-rendezvous --listen-tcp` with a real (self-signed-for-test) cert and a
  local decoy HTTP server, then:
  - `curl https://relay/…` (a probe) ⇒ receives the **decoy** page; the relay
    emits no rendezvous-shaped bytes.
  - garbage bytes / a stale replayed `Register` ⇒ **decoy**.
  - a **test-only client** sending a valid fresh obf'd `Register` ⇒ **upgrade**
    (relay replies with a framed obf reply; a relayed round-trip succeeds).
  - **timing parity:** an idle connection is governed by the decoy backend's
    timeout, not a relay-specific short close (assert the connection is not closed
    at ~`CLASSIFICATION_TIMEOUT`).
- **nDPI classification:** capture the relay's TLS handshake and assert
  `ndpiReader` classifies it as TLS/HTTPS with the real SNI, no VPN/obfuscated/
  Susp-Entropy risk — reusing the 3c.2 oracle harness against the relay.
- **No-regression:** the existing UDP rendezvous netns suite (register / lookup /
  relay / punch / discovery, obf on and off) stays green — the UDP path behavior
  is unchanged; the tokio port is additive.

## 8. Scope & files

- **Modify:** `crates/yip-rendezvous/src/proto.rs` (add `counter: u64` to
  `Register`; codec), `crates/yip-rendezvous/src/server.rs` (record/enforce
  per-`NodeId` monotonic counter; TCP/TLS writer-channel registrations alongside
  UDP), `bin/yip-rendezvous/src/main.rs` (tokio runtime; UDP task + new TCP/TLS
  listener task; `handle_connection`; decoy proxy; CLI flags),
  `bin/yip-rendezvous/Cargo.toml` + `crates/yip-rendezvous/Cargo.toml` (tokio,
  tokio-boring, pinned), docs (`docs/configuration.md`, rendezvous usage,
  `CHANGELOG.md`).
- **Create:** the TCP/TLS connection handler + decoy proxy module in
  `bin/yip-rendezvous`, the bundled static fallback page, the probe-resistance
  netns oracle script + its harness test, a test-only TLS+obf client helper.
- **Untouched:** `yipd` data plane (`run_poll`/`run_uring`, PeerManager, Noise/
  FEC/AEAD), the 3c.1/3c.2 peer transports, all of 3a/3b. The `yipd` rendezvous
  **client** (`ConfiguredServerRendezvous`) is **3c.4**, not here.

**Out of scope (later):** `yipd` TLS-relay-dial client (**3c.4**); signed
rendezvous registrations (**#37**); default `:443` port plausibility (**3d**,
#45); tokio anywhere on the `yipd` data plane (permanent non-goal).
