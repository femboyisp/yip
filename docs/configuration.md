# Configuration

Runtime configuration for the `yipd` daemon: the config-file format, the environment
variables that select the I/O driver, and the command-line flags. This is the single
reference for everything `yipd` reads at startup — it is otherwise scattered across
`bin/yipd/src/` and the bench harness in `crates/yip-bench/`.

`yipd` today runs a **static two-peer tunnel**: one config file per endpoint, no
control plane yet (discovery, NAT traversal, and relay arrive in sub-project #2). Both
peers must agree on keys and endpoints out of band.

## Invocation

```sh
yipd <config-file>     # run a tunnel from a config file
yipd --genkey          # generate an X25519 keypair and exit
yipd --version         # print "yipd <version>" and exit
```

## Config file

The config file is a simple `key=value` text format — one pair per line. Blank lines
and lines beginning with `#` are ignored, and whitespace around keys and values is
trimmed. All three 32-byte keys are **hex-encoded (exactly 64 hex digits)**. Unknown
keys are silently ignored for forward-compatibility.

Generate a keypair with `yipd --genkey`; it prints `private=<hex>` and `public=<hex>`.

### Keys

| Key | Required | Value | Meaning |
|---|---|---|---|
| `local_private` | yes | 64 hex digits | This endpoint's X25519 private key. Feeds the Noise-IK handshake. |
| `local_public` | yes | 64 hex digits | This endpoint's X25519 public key. Carried for key identity / future re-advertisement; the data path itself reads `local_private`. |
| `peer_public` | yes | 64 hex digits | The remote peer's X25519 public key. |
| `listen` | yes | `IP:port` socket address | Local UDP address to bind (e.g. `0.0.0.0:51820`). |
| `peer_endpoint` | yes | `IP:port` socket address | The remote peer's UDP endpoint. Used by the initiator to send the first handshake message; the responder learns the peer's address from the incoming datagram, so on a pure responder this can be a placeholder that is reachable-shaped but is not dialed. |
| `device` | yes | string | TUN/TAP device name to create (e.g. `yip0`). |
| `device_kind` | no | `tun` \| `tap` | Tunnel mode. `tun` = L3 IP tunnel, `tap` = L2 Ethernet bridging. **Defaults to `tun`** when the key is absent. An unrecognized value is a startup error. |
| `initiate` | yes | boolean | Whether this peer initiates the Noise-IK handshake. Exactly one of the two peers should set `true`. Accepted truthy values: `true`, `1`, `yes`; falsy: `false`, `0`, `no`. Any other value is a startup error. |

A missing required key, malformed line (no `=`), bad hex, unparseable socket address,
or invalid boolean/`device_kind` all cause `yipd` to exit with a parse error.

### Example

Two endpoints, A and B. B initiates; A responds. Keys are illustrative — generate real
ones with `yipd --genkey`.

`yipA.conf` (responder):

```ini
# Endpoint A — responder
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=00000000000000000000000000000000000000000000000000000000000000bb
listen=10.0.0.1:51820
peer_endpoint=10.0.0.2:51820
device=yip0
device_kind=tun
initiate=false
```

`yipB.conf` (initiator):

```ini
# Endpoint B — initiator
local_private=00000000000000000000000000000000000000000000000000000000000000aa
local_public=00000000000000000000000000000000000000000000000000000000000000bb
peer_public=0000000000000000000000000000000000000000000000000000000000000002
listen=10.0.0.2:51820
peer_endpoint=10.0.0.1:51820
device=yip0
device_kind=tun
initiate=true
```

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
| `--version`, `-V` | Print `yipd <version>` and exit. |

Running `yipd` with no argument prints a usage message and exits with an error.
