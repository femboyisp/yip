# Configuration

Runtime configuration for the `yipd` daemon: the config-file format, the environment
variables that select the I/O driver, and the command-line flags. This is the single
reference for everything `yipd` reads at startup — it is otherwise scattered across
`bin/yipd/src/` and the bench harness in `crates/yip-bench/`.

`yipd` today runs a **static multi-peer data plane**: one config file per node, each
listing one or more peers, with keys and endpoints agreed out of band. The remaining
control plane (discovery, NAT traversal, relay) arrives in later sub-project #2
milestones. There is **no `initiate` flag**: the handshake is lazy and in-loop
(WireGuard-style) — whichever side has traffic for a peer first sends the
`[HandshakeInit]`, and simultaneous initiation is resolved deterministically.

Each node has a **self-certifying mesh address** derived from its public key
(`fd00::/8`); print it with `yipd --addr <pubkey-hex>`. Assign that `/128` to the node's
TUN device and route the mesh prefix over it so inner packets addressed to a peer's mesh
address are tunnelled to that peer.

## Invocation

```sh
yipd <config-file>       # run a tunnel from a config file
yipd --genkey            # generate an X25519 keypair and exit
yipd --addr <pubkey-hex> # print the mesh address (node_addr) for a public key and exit
yipd --version           # print "yipd <version>" and exit
```

## Config file

The config file is a simple `key=value` text format — one pair per line. Blank lines
and lines beginning with `#` are ignored, and whitespace around keys and values is
trimmed. All three 32-byte keys are **hex-encoded (exactly 64 hex digits)**. Unknown
keys are silently ignored for forward-compatibility.

Generate a keypair with `yipd --genkey`; it prints `private=<hex>` and `public=<hex>`.

### Node keys

| Key | Required | Value | Meaning |
|---|---|---|---|
| `local_private` | yes | 64 hex digits | This node's X25519 private key. Feeds the Noise-IK handshake. |
| `local_public` | yes | 64 hex digits | This node's X25519 public key. Determines this node's mesh address (`yipd --addr`); the data path itself reads `local_private`. |
| `listen` | yes | `IP:port` socket address | Local UDP address to bind (e.g. `0.0.0.0:51820`). |
| `device` | yes | string | TUN/TAP device name to create (e.g. `yip0`). |
| `device_kind` | no | `tun` \| `tap` | Tunnel mode. `tun` = L3 IP tunnel, `tap` = L2 Ethernet bridging. **Defaults to `tun`** when the key is absent. An unrecognized value is a startup error. |

### Peers

List each remote peer in a `[peer]` block. Repeat the block once per peer:

| Key | Required | Value | Meaning |
|---|---|---|---|
| `public_key` | yes | 64 hex digits | The peer's X25519 public key. Also determines the peer's mesh address you route to (`yipd --addr`). |
| `endpoint` | yes | `IP:port` socket address | The peer's UDP endpoint, used to send it the first handshake message. The actual source address is (re)learned from the peer's own handshake datagram. |

**Legacy single-peer form:** for a one-peer node you may instead use the flat keys
`peer_public=<hex>` and `peer_endpoint=<IP:port>` (no `[peer]` header); they fold into a
single peer entry. The `[peer]` block form is required for two or more peers.

A missing required key, malformed line (no `=`), bad hex, unparseable socket address,
or invalid `device_kind` all cause `yipd` to exit with a parse error. Unknown keys are
ignored (so a leftover `initiate=` from an older config is harmless).

### Example

Two nodes, A and B, peered with each other. There is no initiator/responder role — the
first side with traffic brings the tunnel up. Keys are illustrative — generate real ones
with `yipd --genkey`, and compute each node's mesh address with `yipd --addr <public>`.

`yipA.conf`:

```ini
# Node A
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
listen=10.0.0.1:51820
device=yip0
device_kind=tun

[peer]
public_key=00000000000000000000000000000000000000000000000000000000000000bb
endpoint=10.0.0.2:51820
```

`yipB.conf`:

```ini
# Node B
local_private=00000000000000000000000000000000000000000000000000000000000000aa
local_public=00000000000000000000000000000000000000000000000000000000000000bb
listen=10.0.0.2:51820
device=yip0
device_kind=tun

[peer]
public_key=0000000000000000000000000000000000000000000000000000000000000002
endpoint=10.0.0.1:51820
```

Then assign each node its own mesh address and route the mesh prefix over the tunnel,
e.g. on A: `ip -6 addr add $(yipd --addr 0000…0002)/128 dev yip0` and
`ip -6 route add fd00::/8 dev yip0`. A third node C is added by giving A and B a second
`[peer]` block for C (and C a config listing both A and B).

## Environment variables

Both variables select the `yip-io` event-loop driver. They are **presence-based** —
`yipd` checks only whether the variable is *set* (any value, including empty, counts as
on); it does not parse `1` vs `0`. To disable, leave the variable unset. Neither is
required; the defaults give the safe, fast path.

| Variable | Default | Effect |
|---|---|---|
| `YIP_USE_URING` | unset (off) | Opt into the `io_uring` `UringDriver` instead of the default epoll `PollDriver`. Falls back to epoll if io_uring is unavailable at runtime. The default epoll driver is the faster path on current measurements (lower tunnel RTT, the north-star metric) and is safe Rust; the io_uring driver is the workspace's only `unsafe` and is opt-in for A/B work until it beats epoll and re-benchmarks favourably. |
| `YIP_URING_BUSYPOLL` | unset (off) | Busy-poll the io_uring completion queue before blocking — a "burn CPU for latency" knob (yip's north star), off by default. Only takes effect together with `YIP_USE_URING`. Spinning is **adaptive**: it spins only while an exchange is active and backs off to a blocking wait on an idle tunnel, so it does not burn CPU when there is no traffic. |

```sh
# default: epoll PollDriver
yipd yipA.conf

# opt into io_uring
YIP_USE_URING=1 yipd yipA.conf

# io_uring with adaptive busy-poll (lowest measured RTT)
YIP_USE_URING=1 YIP_URING_BUSYPOLL=1 yipd yipA.conf
```

Driver A/B RTT numbers live in
[`crates/yip-bench/README.md`](../crates/yip-bench/README.md) ("io_uring driver A/B —
RTT").

> Historical note: an earlier `YIP_FORCE_POLL` variable existed when io_uring was the
> default and epoll was the opt-in fallback. The default has since flipped — epoll is
> now the default and io_uring is opt-in via `YIP_USE_URING` — so `YIP_FORCE_POLL` no
> longer exists.

## CLI flags

`yipd` takes a single positional argument (the config-file path) or one flag. There are
no other flags.

| Argument | Effect |
|---|---|
| `<config-file>` | Load the config file and run the tunnel. |
| `--genkey` | Generate an X25519 keypair, print `private=<hex>` / `public=<hex>` to stdout, and exit. |
| `--addr <pubkey-hex>` | Print the self-certifying mesh address (`node_addr`, in `fd00::/8`) derived from a 64-hex-digit public key, and exit. |
| `--version`, `-V` | Print `yipd <version>` and exit. |

Running `yipd` with no argument prints a usage message and exits with an error.
