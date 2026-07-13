# yip configuration reference

Complete reference for the `yipd` daemon: config file keys, CLI flags, the
helper binaries (`yip-ca`, `yip-rendezvous`), and environment variables. For
guided walkthroughs (first tunnel, mesh setup, obfuscation) see the
[user guide](user-guide.md). A fully-annotated starter config lives at
[`example.config`](../example.config).

> **Config format.** `yipd` parses a line-based `key=value` format (one pair
> per line; `#` comments; blank lines ignored; whitespace trimmed; unknown keys
> silently ignored). A first-class TOML config (`[[peer]]` array-of-tables,
> quoted values) is a planned milestone — until then, use the format below.

---

## `yipd` config keys

### Core (required)

| Key | Value | Notes |
|---|---|---|
| `local_private` | 64 hex chars (32 bytes) | This node's X25519 private key. **Secret.** Generate with `yipd --genkey`. |
| `local_public` | 64 hex chars (32 bytes) | This node's X25519 public key. Determines this node's self-certifying mesh address (`yipd --addr`). |
| `listen` | `IP:port` | Local UDP bind address (`0.0.0.0:51820` for all interfaces). |
| `device` | string | TUN/TAP device name to create, e.g. `yip0`. |
| `device_kind` | `tun` \| `tap` | `tun` (L3/IP, default) or `tap` (L2/Ethernet). Any other value is an error. |

Missing any of `local_private`, `local_public`, `listen`, `device` is a fatal
config error.

### Peers (static peer list)

Each peer is a `[peer]` block:

```
[peer]
public_key=<64 hex>          # required: the peer's X25519 public key
endpoint=<IP:port>           # optional: omit for a rendezvous/relay-only peer
```

- `public_key` is **required** in a block; a block with an `endpoint` but no
  `public_key` is an error.
- `endpoint` is **optional** — a peer with no endpoint is reachable only via a
  rendezvous server / relay (see below), not by a direct probe.
- Repeat `[peer]` for each peer.

**Legacy single-peer form** (still supported, used only if there are *no*
`[peer]` blocks): `peer_public=<64hex>` + `peer_endpoint=<IP:port>`.

The peer list may be **empty only in mesh mode** (all five mesh keys set,
below); otherwise an empty peer list is an error.

### Rendezvous + NAT traversal (optional)

| Key | Value | Notes |
|---|---|---|
| `rendezvous` | `IP:port` | Address of a `yip-rendezvous` server. Enables lazy **Direct → UDP hole-punch → Relay** bring-up for peers behind NAT. |

### Mesh / decentralized discovery (optional)

A node is a valid mesh member iff it holds a CA-signed cert. Setting **all
five** of these keys puts the node in *mesh mode*, where it may carry no
`[peer]` blocks and discover peers via the signed root set + gossip.

| Key | Value | Notes |
|---|---|---|
| `ca_public` | 64 hex chars (32 bytes) | Trusted CA Ed25519 public key. **Repeatable** — one line per CA. |
| `cert` | file path | File containing this node's CA-signed cert (hex, from `yip-ca sign-cert`). |
| `roots` | file path | File containing the CA-signed root set (hex, from `yip-ca sign-roots`). Its signature is **verified against `ca_public` at load time**; a bad signature is a fatal error. |
| `member_sign_private` | 64 hex chars (32 bytes) | This node's **Ed25519** record-signing private key (distinct from `local_private`). **Secret.** |
| `network_id` | **32 hex chars (16 bytes)** | Mesh network id. Note the length is **half** that of the other hex keys. |

*Mesh mode* is exactly: `ca_public` non-empty **and** `cert`, `roots`,
`member_sign_private`, `network_id` all set.

### Anti-DPI obfuscation (optional, opt-in)

| Key | Value | Notes |
|---|---|---|
| `obf_psk` | 64 hex chars (32 bytes) | Network-wide obfuscation shared secret. When set, every datagram is wrapped so the wire is indistinguishable from random UDP. **All nodes and the rendezvous server must share the same value.** Absent ⇒ byte-identical to the non-obfuscated wire format. |

See the [user guide](user-guide.md#anti-dpi-obfuscation) for the security model.

### Transport mode (optional)

By default yip runs its inner protocol directly over UDP. Two optional
**mimicry transports** carry the *unchanged* inner protocol (Noise-IK, FEC,
AEAD) inside a real, standard-looking wire protocol so DPI classifies the
traffic as something innocuous. Both connect to the **configured** peer
endpoint (no discovery/hole-punch on these paths) and are **mutually exclusive
with `obf_psk`** — the mimicry layer *is* the obfuscation, so double-wrapping is
rejected at config load.

| Key | Value | Notes |
|---|---|---|
| `transport` | `raw` (or `udp`), `quic`, `tls` | Selects the wire transport. Absent ⇒ `raw` (the default low-latency UDP path — byte-identical to pre-mimicry yip). |
| `tls_sni` | domain string | SNI + self-signed cert name presented by the `tls` costume. Default `www.apple.com`. Only meaningful when `transport=tls`. |

- **`raw` / `udp` (default):** inner protocol directly over UDP. Lowest latency; the FEC/loss-recovery path. Use this unless a network blocks it.
- **`quic` (3c.1):** inner protocol inside a real QUIC connection (RFC 9221 DATAGRAM frames); classifies as QUIC/HTTP-3. Survives networks that permit UDP/443 but fingerprint raw UDP.
- **`tls` (3c.2):** inner protocol inside a real TLS 1.3 connection over **TCP/443** with a browser-parrot ClientHello; classifies as ordinary browser HTTPS. This is an **opt-in last-resort** path for networks that block UDP entirely (so both `raw` and `quic` fail): TCP means head-of-line blocking and yip's FEC gives no benefit over an already-reliable stream, so it trades yip's latency/loss-recovery identity for reachability. The outer TLS is **zero-auth** (it defeats classification, not an *active probe* that checks whether a real site answers — that is the relay-tier REALITY milestone, 3c.3).

### Hex-length quick reference

- **64 hex (32 bytes):** `local_private`, `local_public`, `public_key`,
  `peer_public`, `ca_public`, `member_sign_private`, `obf_psk`.
- **32 hex (16 bytes):** `network_id`.
- `cert` / `roots` are **file paths**, not inline hex.

---

## `yipd` CLI

```
yipd <config-file>          Run the daemon with the given config.
yipd --genkey               Generate an X25519 keypair. Prints:
                              private=<64 hex>
                              public=<64 hex>
yipd --addr <pubkey-hex>    Print the self-certifying mesh address (IPv6) for
                            a 64-hex public key.
yipd --version | -V         Print the version and exit.
```

There is no `--help`; running with no arguments prints the usage above.

---

## `yip-rendezvous` CLI

The standalone rendezvous + blind-relay server (no TUN, no tunnel keys).

```
yip-rendezvous <listen-addr>                 e.g. yip-rendezvous 0.0.0.0:51821
yip-rendezvous <listen-addr> --obf-psk <hex64>   obfuscated networks (must match
                                                 the nodes' obf_psk)
yip-rendezvous --version | -V
```

It logs `relay-forwarded=<N>` to stderr every 5 s (how many datagrams the blind
relay has forwarded — 0 means everything went direct/hole-punched).

---

## `yip-ca` CLI (offline certificate authority)

A one-shot **offline** tool. Its signing key should never live on an
internet-facing node. Errors exit with code 2.

```
yip-ca genkey
    Mint a CA Ed25519 keypair. Prints:
      ca_private=<64 hex>
      ca_public=<64 hex>

yip-ca sign-cert --member <hex64> --member-sign <hex64> \
                 --network <hex32> --days <N> [--ca-private <hex64>]
    Issue a membership cert (valid <N> days). Prints one hex line (the cert)
    to stdout — save it to the file named by the node's `cert=` key.
      --member       the member's X25519 public key (its `local_public`)
      --member-sign  the member's Ed25519 record-signing public key
      --network      the 16-byte network id (32 hex)
    If --ca-private is omitted, the CA private key hex is read from stdin.

yip-ca sign-roots --roots <file> --version <N> [--ca-private <hex64>]
    Sign a root set. Prints one hex line (the root set) to stdout — save it to
    the file named by each node's `roots=` key.
      --roots    path to a roots-input file (see below)
      --version  the root set version number (u64)
```

`genkey`'s output can be piped straight into `sign-cert`/`sign-roots` when
`--ca-private` is omitted:

```sh
yip-ca genkey | yip-ca sign-cert --member <hex64> --member-sign <hex64> \
                                 --network <hex32> --days 30 > node.cert
```

**Roots-input file** (for `sign-roots`): plain text, one root per line,
two whitespace-separated columns — the root's public key and its underlay
address. `#` comments and blank lines are skipped. IPv6 uses the bracket form:

```
4444...4444 192.0.2.1:51820
5555...5555 [2001:db8::1]:51820
```

---

## Environment variables (I/O driver)

The data loop runs on one of two `yip-io` drivers, selected at runtime:

| Variable | Effect |
|---|---|
| *(unset)* | **`PollDriver` (epoll)** — the default. Fastest simple path, works everywhere. |
| `YIP_USE_URING=1` | Opt-in single-ring **`io_uring` `UringDriver`**. Falls back to `PollDriver` at runtime on kernels that reject multishot recv (e.g. 6.12). |
| `YIP_USE_URING=1 YIP_URING_BUSYPOLL=1` | Adaptive busy-poll: spins the completion queue to cut RTT **below** epoll — only worth it on **bare metal with a dedicated core** and a recent kernel. |

Measured tunnel RTT: poll ≈ 0.37 ms, io_uring blocking ≈ 0.41 ms,
io_uring + busy-poll ≈ 0.30 ms (best). Use the default everywhere; reach for
busy-poll only on a dedicated-core, recent-kernel host.
