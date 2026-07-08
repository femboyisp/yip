# yip user guide

Practical, step-by-step guide to building and running yip — from a two-node
tunnel to a full obfuscated mesh. For the exhaustive key/flag reference see
[configuration.md](configuration.md); for testing and benchmarking see
[testing-and-benchmarking.md](testing-and-benchmarking.md).

- [What yip is](#what-yip-is)
- [Build](#build)
- [Quickstart: a two-node tunnel](#quickstart-a-two-node-tunnel)
- [Addresses](#addresses)
- [Multiple peers](#multiple-peers)
- [Rendezvous & NAT traversal](#rendezvous--nat-traversal)
- [Mesh mode (decentralized discovery)](#mesh-mode-decentralized-discovery)
- [Anti-DPI obfuscation](#anti-dpi-obfuscation)
- [Choosing the I/O driver](#choosing-the-io-driver)

---

## What yip is

yip is a low-latency P2P mesh VPN. It gives you an encrypted L3 (IP/TUN) or L2
(Ethernet/TAP) tunnel between peers over a UDP transport with **RaptorQ forward
error correction** — so packet loss is recovered without retransmission, keeping
latency flat under loss where plain tunnels spike. On top of the data plane it
adds a decentralized control plane (self-certifying addresses, gossip
discovery, NAT traversal, relay) and opt-in anti-DPI obfuscation.

What's implemented today: the data plane + FEC, multi-peer routing,
self-certifying addresses, rendezvous/hole-punch/relay, CA-gated mesh
discovery, and `obf_psk` traffic obfuscation. Traffic-analysis defense,
TLS-mimicry, and multi-platform hardening are future sub-projects.

---

## Build

Requires a recent stable Rust toolchain on Linux.

```sh
cargo build --release --workspace     # yipd, yip-ca, yip-rendezvous, all crates
```

The binaries land in `target/release/`: `yipd` (the daemon), `yip-ca` (offline
CA), `yip-rendezvous` (rendezvous/relay server). Use the **release** build for
anything performance-sensitive — debug RaptorQ is ~75× slower.

Creating TUN/TAP devices and configuring namespaces needs root (or
`CAP_NET_ADMIN`); the examples below use `sudo`.

---

## Quickstart: a two-node tunnel

Two hosts, **A** and **B**, each running `yipd`, connected directly.

**1. Generate a keypair on each host:**

```sh
yipd --genkey
# private=<64 hex>   <- keep secret, goes in local_private
# public=<64 hex>    <- share with the other side, goes in their peer public_key
```

**2. Write `A.config`** (A listens on its own address, points at B's):

```
local_private=<A private>
local_public=<A public>
listen=0.0.0.0:51820
device=yip0
device_kind=tun

[peer]
public_key=<B public>
endpoint=<B host>:51820
```

**3. Write `B.config`** — mirror image (B's keys, A's public + endpoint).

**4. Start the daemon on each host:**

```sh
sudo yipd A.config      # on A
sudo yipd B.config      # on B
```

**5. Assign tunnel IPs and test.** yipd creates the `yip0` device; give each end
an address on a shared subnet (either your own private range, or each node's
self-certifying mesh address — see below) and ping across:

```sh
sudo ip addr add 10.7.0.1/24 dev yip0 && sudo ip link set yip0 up   # on A
sudo ip addr add 10.7.0.2/24 dev yip0 && sudo ip link set yip0 up   # on B
ping 10.7.0.2      # from A
```

For an L2 bridge instead, set `device_kind=tap` on both sides and bridge `yip0`
into your LAN.

---

## Addresses

Every node has a **self-certifying IPv6 address** derived from its public key —
no address authority, and anyone can verify a claimed address against the
claimed key. Print yours:

```sh
yipd --addr <your-public-key-hex>
# fdxx:xxxx:...   (an address in fd00::/8)
```

The address is `0xfd || BLAKE2s("yip-addr-v1" || pubkey)[..15]`. You can assign
this `/128` to `yip0` and route `fd00::/8` over the tunnel, so peers address
each other by their key-derived address. In mesh mode (below) this is how a node
resolves a destination it has never been statically told about: the address
*is* the identity.

---

## Multiple peers

List each peer in its own `[peer]` block; yipd routes by the inner destination
to the right peer and runs an independent encrypted session per peer:

```
local_private=<A private>
local_public=<A public>
listen=0.0.0.0:51820
device=yip0
device_kind=tun

[peer]
public_key=<B public>
endpoint=<B>:51820

[peer]
public_key=<C public>
endpoint=<C>:51820
```

A `[peer]` with no `endpoint` is valid — it's a peer you can only reach via a
rendezvous server or relay (next section).

---

## Rendezvous & NAT traversal

Peers behind NAT often have no reachable `endpoint`. Point every node at a
`yip-rendezvous` server and yip brings peers up lazily along a
**Direct → UDP hole-punch → Relay** escalation.

**1. Run the server** on a publicly reachable host:

```sh
yip-rendezvous 0.0.0.0:51821
```

It needs no keys and no TUN — it only helps peers find each other and blindly
relays when a direct path can't be punched.

**2. Add `rendezvous=` to each node's config**, and list peers by key (endpoint
optional):

```
local_private=<A private>
local_public=<A public>
listen=0.0.0.0:51820
device=yip0
rendezvous=<server>:51821

[peer]
public_key=<B public>
# no endpoint: found + punched (or relayed) via the rendezvous server
```

The server logs `relay-forwarded=<N>` every 5 s — `0` means the peers punched a
direct path; nonzero means traffic is falling back through the blind relay.

---

## Mesh mode (decentralized discovery)

In mesh mode you don't list peers at all — a node is admitted iff it presents a
**CA-signed membership cert**, and it discovers other members through a gossiped
directory seeded by a signed **root set**. This is a *private membership mesh*:
membership is gated by an offline CA, but there's no central server in the data
path.

### The offline CA workflow (`yip-ca`)

Do all of this on an **offline** machine; the CA private key never touches an
internet-facing node.

**1. Mint the CA key:**

```sh
yip-ca genkey
# ca_private=<64 hex>   <- keep offline
# ca_public=<64 hex>    <- goes in every node's ca_public=
```

**2. For each member node**, mint its data-plane keypair and a record-signing
keypair, then issue a cert:

```sh
yipd --genkey              # -> member X25519 keypair (local_private / local_public)
yip-ca genkey              # -> reuse as the member's Ed25519 record-signing keypair
                           #    (ca_private -> member_sign_private, ca_public -> member-sign pub)

# issue a 30-day cert for this member (CA private read from stdin):
echo "ca_private=<CA priv>" | yip-ca sign-cert \
    --member       <member public> \
    --member-sign  <member record-signing public> \
    --network      <32-hex network id> \
    --days 30  > node.cert
```

**3. Sign a root set** — one or more well-known seed nodes (their public key +
underlay address) that new nodes bootstrap gossip from. Write a roots-input
file:

```
<seed public key> <seed host>:51820
```

then sign it:

```sh
echo "ca_private=<CA priv>" | yip-ca sign-roots --roots roots.in --version 1 > network.roots
```

**4. Write each node's config** with the five mesh keys and **no `[peer]`
blocks**:

```
local_private=<member private>
local_public=<member public>
listen=0.0.0.0:51820
device=yip0
ca_public=<CA public>
cert=/etc/yip/node.cert
roots=/etc/yip/network.roots
member_sign_private=<member record-signing private>
network_id=<32-hex network id>
```

A node boots, handshakes to a seed root (admitted by its cert), gossips its own
signed record, converges the directory, and then — when traffic is sent to
another member's key-derived address — resolves it from the directory and brings
up a session on demand. Combine with `rendezvous=` so members behind NAT are
reachable too.

Certs expire (`--days`), so re-issue before expiry. `ca_public` is repeatable to
trust multiple/rotated CAs.

---

## Anti-DPI obfuscation

By default yip's wire format is efficient but recognizable. Set a network-wide
`obf_psk` and every datagram is wrapped so the wire looks like **uniform-random
UDP** — no fixed bytes, no fixed packet sizes, no plaintext type discriminator,
and control-plane timing is jittered. An nDPI classifier sees only `Unknown`
traffic (verified in CI; see [testing](testing-and-benchmarking.md#the-ndpi-undetectability-oracle)).

**Enable it** by adding the same 64-hex secret to **every** node:

```
obf_psk=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

and, if you use a rendezvous server, pass it there too:

```sh
yip-rendezvous 0.0.0.0:51821 --obf-psk 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

**Security model — read this:**

- Obfuscation is a **layer over** the Noise crypto, not a replacement. It hides
  the *fingerprint*; confidentiality and integrity still come from Noise-IK +
  AEAD.
- It is **opt-in and network-wide**. Every participating node (and the
  rendezvous server) must share the **exact same** `obf_psk`. A mismatch means
  peers can't deobfuscate each other and **no connection forms**. A node with
  `obf_psk` unset speaks the plain wire format.
- **A compromised `obf_psk` degrades to "detectable but still secure":** an
  adversary who learns it can recognize and block yip traffic, but **still
  cannot decrypt it** — that requires breaking Noise. The PSK gates
  *unblockability*, not confidentiality.
- **Not yet covered by 3a:** the payload is high-entropy (as all encrypted
  traffic is), so nDPI's *entropy* heuristic still fires — defeating that needs
  TLS/QUIC mimicry (a later milestone). And a VPN-associated **listen port**
  (e.g. 51820) is itself a fingerprint independent of payload — prefer a neutral
  or plausible port.

---

## Choosing the I/O driver

The data loop runs on epoll by default. You almost never need to change this.

- **Default (epoll):** fastest simple path, works on every kernel. Just run
  `yipd`.
- **io_uring:** `YIP_USE_URING=1 yipd …` — opt-in; auto-falls-back to epoll on
  kernels that reject multishot recv.
- **io_uring + busy-poll:** `YIP_USE_URING=1 YIP_URING_BUSYPOLL=1 yipd …` — spins
  a core to push RTT below epoll (~0.30 ms vs ~0.37 ms). Worth it **only** on
  bare metal with a dedicated core and a recent kernel; on shared-vCPU cloud the
  gain vanishes.
