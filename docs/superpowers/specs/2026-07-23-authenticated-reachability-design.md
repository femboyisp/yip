# Authenticated Reachability — design spec (#37 + M2)

**Status:** approved (2026-07-23). Builds on #34 (handshake anti-replay + authenticated
endpoint learning, PR #99). One spec, two implementation plans / PRs across different
subsystems, both stacked on the #34 branch.

## Problem

Two gaps let an adversary or an ordinary network event deny a peer's reachability, both
rooted in trusting *unauthenticated* source/registration information:

1. **#37 — unauthenticated rendezvous registration (overwrite DoS).** `Register { node,
   counter }` carries no signature. `node` is a public hash of the member's key and
   `counter` is guessable, so anyone can send `Register { node: victim, counter: huge }`
   from their own address and overwrite the victim's entry (`server.rs:register_if_fresh`
   accepts any strictly-greater counter). The victim becomes unreachable / misdirected.

2. **M2 — no authenticated endpoint roaming.** After #34, a peer's `endpoint` is immovable
   while Established: it is written only on a fresh cold-start accept (`peer_manager.rs`
   ~1810), never on the rekey path. So a legitimate peer that changes address (NAT rebind,
   mobility) is never followed. Because `endpoint` is also the demux key that selects a
   peer's `session_obf_key` in `deobf_ingress` (`peer_manager.rs` ~2458), under the
   obfuscation path B cannot even deobfuscate the roamed peer's data — an ingress
   black-hole that persists until a full re-handshake, up to a rekey interval (~120 s).
   This is the M2 follow-up filed in #34's final review, understated there.

Both are "don't trust an unauthenticated source." The unifying fix is to require a
cryptographic proof of identity before acting on a claimed address.

## Non-goals

- No change to #34's Init anti-replay or the cold-start endpoint gate — that path stays
  exactly as shipped.
- No new crypto primitives. #37 reuses `membership::Record` / `Record::verify`; M2 reuses
  the existing AEAD replay window.
- No attempt to make the rendezvous server trusted for *address* integrity — address
  correctness remains backstopped end-to-end by the 2b invariant (egress commits only on a
  completed Noise handshake over the learned address).

---

## Part A — #37: signed rendezvous registration (control-plane)

### Key insight — the registration IS a `Record`

`membership::Record { node_id, cert, endpoints, seq, sig }` is already a member-signed,
cert-carrying, `seq`-monotonic directory entry, and `Record::verify(ca_pubkeys,
network_id, now, skew)` already performs the entire chain we need:

1. `verify_cert` — the embedded cert is CA-signed against the roots, matches `network_id`,
   and is within its validity window;
2. the record signature verifies over `record_signing_body` under the cert's
   record-signing key;
3. `node_id == node_id(cert.member_pubkey)` — the record is not claiming another identity
   (**squatting closed**).

So the rendezvous registration and the gossip directory entry become the same signed
object. `Record.seq` **is** the freshness counter. No new crypto is introduced.

### Wire change

The signed registration is an **additional** message, so the legacy unsigned path is left
untouched (non-mesh stays byte-identical):

- Add `Message::RegisterSigned { record: Record }` (new `Tag = 7`). `record.node_id` is the
  registered id; `record.seq` is the freshness counter. The existing
  `Register { node, counter }` (`Tag = 0`) is unchanged.
- `Message::PeerInfo` gains an optional trailing `record: Option<Record>` (a presence byte
  then the record when present). It is populated only in mesh mode; the legacy no-record
  encoding is preserved when absent.

`Record` already has `encode`/`decode` with length-prefixed codecs. This is a coordinated
rendezvous+client bump for mesh deployments — see Compatibility.

### Trust model — Option 3 (defense in depth), full-CA server

**Server (authoritative for reachability).** On `Register`, before touching the table:

1. `record.verify(&self.roots, &self.network_id, now_secs, skew)` — reject on any error.
2. Monotonic seq: keep the existing `register_if_fresh` discriminator, keyed on
   `record.seq` (first-seen/expired, or strictly greater than the last accepted).
3. On accept, store the **observed `src`** as the reachable address (unchanged) *and* the
   verified `Record` (for `PeerInfo` responses).

The server gains one new input: the mesh's CA root set + `network_id`. It is already
per-mesh infrastructure (the bootstrap seed), so this coupling is acceptable. This is the
load-bearing half — a forged/squatted register never enters the table, so the victim's
real entry survives and it stays reachable.

**Peer (defense in depth for targeting).** `Lookup` responses (`PeerInfo`) carry the
`Record`; the looking-up peer runs `record.verify(...)` against *its own* roots before
spending a probe. A malicious or buggy server therefore cannot make a peer chase a phantom
or a non-member entry. Address integrity is still the handshake's job: the peer probes the
server-observed address, and if it is wrong the Noise handshake simply fails to complete
(no traffic is misdirected — the existing 2b commit-on-completion invariant).

### What it closes

- **Overwrite DoS** — an attacker cannot forge the victim's record signature, so
  `record.verify` rejects the overwrite at ingress; the victim's entry survives.
- **Squatting** — `node_id` is bound to `cert.member_pubkey` inside `record.verify`, so an
  attacker cannot pre-register a victim's node_id under its own key.
- **Server-injected phantoms** — the peer-side verify rejects any `PeerInfo` not backed by
  a valid member record.

### Mesh-only

Registration signing is required **only when membership is configured** (mesh mode). A
non-mesh deployment has no CA and keeps the current unsigned `Register` path. Concretely: a
`yipd` with membership sends `RegisterSigned`; a rendezvous server started with roots
serves the mesh — it requires a valid `Record` via `RegisterSigned` and drops the legacy
unsigned `Register` (a mesh must not accept unauthenticated registrations); a server
started without roots keeps the legacy identity-agnostic behavior (accepts `Register`,
ignores `RegisterSigned`). A mesh client against a rootless server (or vice-versa) fails
closed — the expected message type is dropped, so no registration lands. Deploy
consistently per mesh.

### Server configuration

`bin/yip-rendezvous` gains `--roots <file>` (a signed `RootSet`, verified via
`verify_rootset` at load) and `--network-id <hex16>`. Absent → legacy mode. The server
holds no private keys and no member certs beyond what each `Register` carries.

---

## Part B — M2: authenticated endpoint roaming (data-plane)

### The WireGuard rule

Update a peer's `endpoint` to the source of a received packet **iff that packet both
decrypts under the session AEAD key and passes the replay window** — i.e. only for a fresh,
authentic, non-replayed data packet. In yip this signal already exists: a successful
`SessionKeys::open(counter, ciphertext)` (`yip-crypto/src/lib.rs` ~291) runs
`ReplayWindow::check_and_set` and returns `Ok` only for a fresh, authentic packet. A
replayed or spoofed packet returns `Err` and never reaches the update.

### Change

In the data-ingress path, thread the datagram's `src` down to the point of a successful
`open()`. On success, if `src != peers[idx].endpoint`, set `peers[idx].endpoint =
Some(src)` (direct peers only; a `relay` peer's endpoint is the rendezvous placeholder and
must not roam). Apply on both the `current` and `next` epochs (a roamed peer may complete a
rekey from the new address). No wire change.

Because `endpoint` also keys `deobf_ingress`'s session-key selection and the handshake
demux (`peer_manager.rs` ~1464/2043/2458/2525), a single authenticated data packet from the
new address heals all of them at once.

### Why it preserves #34's anti-hijack

#34's property is that an *unauthenticated Init* cannot move an Established peer's endpoint.
That path is untouched: the cold-start endpoint gate and the rekey path still never learn
an endpoint from an Init's source. M2 moves `endpoint` **only** on an AEAD-authenticated,
non-replayed *data* packet — which an attacker cannot forge (no session key) and cannot
replay (replay window). The M1 on-path residual from #34 (copy-and-reinject a genuine
*Init*) does not apply: a data packet's ciphertext is bound to its counter, and replaying
it fails the window; injecting from a spoofed source with a valid, unseen counter requires
the session key.

### Severity fixed

Mid-session NAT rebind now recovers on the first authenticated packet from the new address
(sub-RTT), instead of black-holing the obfuscated ingress path for up to a rekey interval.

---

## Compatibility

- **#37** adds `RegisterSigned` (new tag) and an optional trailing `record` on `PeerInfo`,
  leaving the legacy `Register`/no-record `PeerInfo` encodings untouched — non-mesh is
  byte-identical to today. Mesh deployments bump the rendezvous server and clients together;
  a mesh-mode ⇄ rootless-server mismatch fails closed (the expected message is dropped, no
  registration) rather than silently accepting unsigned registers.
- **M2** is internal; no wire or format change; non-mesh and mesh behave identically.

## Testing

**#37 (unit + netns).**
- Unit (`yip-rendezvous`): forged signature rejected; a cert not signed by the roots
  rejected; a record whose `node_id` ≠ `node_id(cert.member_pubkey)` rejected (squatting);
  stale/equal `seq` rejected; a valid record accepted and stored; capacity/rate paths
  unchanged. Peer-side: an unsigned or forged `PeerInfo` is rejected before probing.
- netns: attacker attempts to overwrite an established member's registration → server
  refuses, victim stays reachable (lookup still returns the victim's real address, ping
  succeeds). Both drivers.

**M2 (unit + netns).**
- Unit (`yipd`): an authenticated data packet from a new src updates `endpoint`; a
  *replayed* data packet from a spoofed src does **not** move it; an unauthenticated Init
  from a spoofed src still does not move it (#34 regression guard); a `relay` peer does not
  roam.
- netns: a direct, established A changes address mid-session (re-NAT) and B recovers on the
  first authenticated packet, under the obfuscation path. Both drivers.

**Regression net:** the full #34 / #41 / #91 / 9a unit + netns suites must stay green —
this milestone touches the admission, demux, and ingress paths they cover.

## Accepted residuals

- **#37:** the rendezvous server must be configured with CA roots in mesh mode (loses
  identity-agnosticism). Accepted — it is per-mesh infrastructure.
- **#37:** the server-observed address is not covered by the signature (a NAT-reflexive
  address is unknown to the registering peer). Address integrity is deferred to the
  handshake-commit invariant, exactly as today. This is by design, not a gap.
- **M2:** endpoint follows the last authenticated peer, matching WireGuard's roaming model;
  reordering under a symmetric NAT is absorbed by the replay window.

## Global constraints

`#![forbid(unsafe_code)]`; no `as` casts except `PacketType::X as u8`; no bare `#[allow]`
(use `#[expect(reason = …)]`); RUN `cargo fmt`; `clippy -- -D warnings` clean; `yipd` is a
BINARY — `cargo test -p yipd --bin yipd`. netns money tests use the RELEASE binaries under
both the poll and `YIP_USE_URING=1` drivers. Leave PRs for the user to review + merge; no
"not merging" line in PR descriptions.
