# Sub-project #3 Milestone 3d: Port plausibility — Design

**Status:** draft (under review)
**Sub-project:** #3 (anti-DPI / censorship resistance), milestone 3d. 3a
(`obf_psk`) #43, 3b #47, 3c.1 (QUIC) #48, 3c.2 (TLS) #62, 3c.3 (REALITY relay)
#66 are merged; 3c.4 (relay-dial) #69 in review. On main after #69.

---

## 1. Goal

Close the **port fingerprint** — requirement R8, issue #45. Even with 3a's
payload obfuscation making yip's bytes unclassifiable, yip on UDP **51820**
(WireGuard's default port) is classified by nDPI as **WireGuard by port**
(`[Confidence: Match by port]`) regardless of content; the same obfuscated
traffic on a neutral port is `Unknown`. The tell is not in the code — `listen`
is a required key with no code default — it is that yip **ships `51820` in
`example.config` and the docs**, so real deployments inherit WireGuard's port.

3d makes yip's ports **plausible by default**: auto-select **443** (the single
least-suspicious port on any network) per transport, warn on known
DPI-fingerprinted VPN ports, and prove — with the nDPI oracle — that a mimicry
transport on 443 classifies *as* its cover protocol with **no** WireGuard
port-match and **no** "unknown thing on a weird port" risk. The "pluggable
transports" half of R8/3d already shipped across 3c (`transport=`); 3d is the
port-plausibility axis.

## 2. What this is NOT (non-goals + boundaries)

- **Not a wire or crypto change.** 3d changes only the local **bind address**
  selection. Noise-IK, FEC, AEAD, the obfuscation layer, and every transport's
  wire format are untouched.
- **Not a silent override.** An explicitly configured port is **always
  honored** — 3d only auto-selects when the port is unspecified, and only
  *warns* (never rejects/overrides) on a configured known-bad port. The operator
  keeps control.
- **Not a random port.** R8 is explicit that a plausible *known* port (443)
  beats a random high port ("an unknown encrypted flow on a random high port is
  itself suspicious"). 3d never picks an ephemeral/random listen port.
- **Not relay auto-defaulting.** `yip-rendezvous`'s ports are deliberate
  operator choices (a client dials a *known* relay endpoint, so the relay is not
  hiding the way a peer is). The relay gets only the same known-bad-port
  *warning*; no auto-443. `--listen-tcp` already documents 443 (3c.3).
- **Not solving the raw-UDP cover gap.** Raw obfuscated UDP has no cover
  protocol; 443/UDP is the least-suspicious port available to it, but true
  cover-protocol plausibility requires a mimicry transport (3c). 3d makes raw's
  *port* plausible, not its *payload*.

## 3. Approach (in one line)

Make `listen` (and its port) optional; when the port is unspecified, **try to
bind 443** for the active transport (443/TCP for `tls`, 443/UDP for `quic`/`raw`)
and fall back to **8443** with a warning if binding 443 is denied; warn at config
load when a port is explicitly set to a known DPI-fingerprinted VPN port; and add
an nDPI oracle arm proving the 443 win.

## 4. Design

### 4.1 Port-selection model

`Config.listen` becomes flexible. Resolution of the local bind **port**:

1. **Explicit port** (`listen = 0.0.0.0:9999`) → honored exactly. If the port is
   a **known DPI-fingerprinted VPN port** (§4.2), log a greppable warning
   recommending 443 — the port is still used (operator control).
2. **IP only** (`listen = 0.0.0.0`) **or `listen` omitted** → auto-select: **try
   443** for the active transport; on a *permission* error, fall back to **8443**
   with a warning (§4.3). `listen` thus stops being strictly required (the IP
   defaults to `0.0.0.0` when the whole key is absent).

**All transports default to 443** — `tls` → 443/**TCP**, `quic`/`raw` → 443/**UDP**.
Raw obfuscated UDP has no cover protocol, but 443 is the single least-suspicious
port on any network: "Unknown-on-443" beats "Unknown-on-a-weird-high-port" and
beats "WireGuard-on-51820." A censor deep-inspecting 443/UDP for QUIC-ness is
already past port-matching, at which point raw's 3a payload obfuscation is what
carries the flow, not the port.

The default sets only the **local listen**. A peer relying on the 443 default
means its peers point `peer_endpoint`/`endpoint` at `:443` — that stays explicit
config; 3d just makes `:443` the natural target.

### 4.2 The known-bad-port lint

A pure, table-driven check fired at config load:

```
fn fingerprinted_vpn_port(port: u16) -> Option<&'static str>
```

returning the protocol a port makes yip look like, `None` otherwise:

| Port(s) | Fingerprints as |
|---|---|
| 51820 | WireGuard |
| 1194 | OpenVPN |
| 500, 4500 | IPsec/IKE |
| 1701 | L2TP |
| 1723 | PPTP |
| 655 | tinc |

On a hit, log a greppable warning, e.g.:
`yipd: listen port 51820 is WireGuard's default; DPI classifies yip as WireGuard by port regardless of payload — prefer 443 (anti-DPI R8)`.
It is a **warning, not an error**. The same lint runs on `yip-rendezvous`'s UDP
`listen` (consistency; cheap).

### 4.3 Binding 443 with fallback

Binding a port `< 1024` needs root or `CAP_NET_BIND_SERVICE`. yipd already needs
`CAP_NET_ADMIN` for the TUN device, so a privileged deployment binds 443 fine.
When auto-selecting (§4.1 case 2):

- Attempt to bind 443 (TCP or UDP per transport).
- On a **permission** error (`EACCES`/`PermissionDenied`), fall back to binding
  **8443** and log a greppable warning naming the fallback and how to get 443:
  `yipd: cannot bind 443 (needs CAP_NET_BIND_SERVICE); using 8443 — grant it with 'setcap cap_net_bind_service+ep <yipd>' or run privileged (anti-DPI R8)`.
- On any **other** bind error (e.g. address-in-use), propagate it (a real
  failure, not a plausibility fallback).

8443 ("alt-HTTPS") is a fixed, widely-used, non-VPN port — plausible for TCP,
neutral for UDP. Never ephemeral (a listener must be predictable so peers can
target it).

### 4.4 Where this lives

- **Config** (`bin/yipd/src/config.rs`): make `listen` optional; parse an IP-only
  form; expose the resolved intent (an explicit `SocketAddr`, or "auto: IP +
  transport-default"). Run the known-bad-port lint on an explicit port. The
  `fingerprinted_vpn_port` table lives here (or a small `port.rs`).
- **Bind-with-fallback** (`bin/yipd/src/tunnel.rs`, at each transport's socket
  bind): the transport dispatch already knows the transport; when the port is
  auto, it applies the 443→8443 logic for the right socket type (TCP for `tls`,
  UDP for `quic`/`raw`). The raw-UDP `UdpSocket::bind`, the QUIC socket, and the
  TLS-transport `TcpListener` each consult the resolved port.
- **Relay** (`bin/yip-rendezvous/src/main.rs`): run the known-bad-port lint on
  its UDP `listen`. No auto-default.

## 5. Testing

- **Unit:** `fingerprinted_vpn_port` (each listed port → the right name; a normal
  port → `None`); the port-resolution logic (explicit port honored; IP-only /
  absent → the transport's 443 default as the *intended* port; the 8443 fallback
  candidate). Config parse: `listen=0.0.0.0` and absent `listen` both resolve to
  auto-443; `listen=0.0.0.0:51820` parses and flags the warning.
- **Integration/netns:** the existing tunnel money tests still pass with
  `listen=0.0.0.0` (the sudo CI can bind 443) — proving the default doesn't break
  tunneling. The 443→8443 fallback path is exercisable by attempting 443 as a
  non-privileged user (a targeted test) or documented as CI-privilege-dependent.
- **nDPI 443-proof (the R8 win):**
  1. **The risk disappears on 443.** Run a mimicry transport (`tls` or `quic`) on
     **443**, capture, `ndpiReader` → assert it classifies as the cover protocol
     **and** that `Known Proto on Non Std Port` (which the 3c.1/3c.2 neutral-port
     oracles *reported* as the 3d follow-up) is **absent**. No WireGuard.
  2. **The tell we remove (contrast).** Obfuscated raw UDP on **51820** →
     `ndpiReader` port-matches it as **WireGuard** (`Match by port`), documenting
     #45 and justifying the lint; on 443 there is no WireGuard port-match.
- **No-regression:** explicit `listen=IP:port` behaves identically (only adding a
  warning if the port is known-bad); the existing neutral-port 3c oracles still
  pass unchanged; full workspace + clippy.

## 6. Security & correctness invariants

1. **Wire/crypto untouched** — only the bind address selection changes.
2. **Explicit config always wins** — auto-default only when the port is
   unspecified; a configured port is never silently overridden (only warned).
3. **Backward-compatible** — existing `listen=IP:port` configs run identically.
4. **No ephemeral/random listen port** — auto-selection is always a fixed
   plausible port (443, or 8443 on fallback), per R8.
5. **Fallback is graceful, not silent** — the 443→8443 fallback always logs a
   greppable warning so the operator knows plausibility was reduced and how to
   restore it.

## 7. Scope & files

- **Modify:** `bin/yipd/src/config.rs` (optional `listen`, IP-only parse, the
  `fingerprinted_vpn_port` lint + warning, resolved-port intent), `bin/yipd/src/
  tunnel.rs` (443→8443 bind-with-fallback per transport socket type),
  `bin/yip-rendezvous/src/main.rs` (known-bad-port warning on its UDP listen),
  `example.config` + `docs/configuration.md` (drop 51820; document the 443
  default, the lint, the `setcap`/`CAP_NET_BIND_SERVICE` requirement, the 8443
  fallback), `bin/yipd/tests/run-*-oracle.sh` / `tunnel_netns.rs` (the 443 win +
  51820 contrast arms), `CHANGELOG.md`.
- **Create (maybe):** `bin/yipd/src/port.rs` if the lint + resolution warrant
  their own small module.
- **Untouched:** all wire formats, Noise/FEC/AEAD, the obfuscation layer, the
  transports' pump logic, the relay's TLS front / discriminator.

**Out of scope (later):** giving raw UDP a real cover protocol (that is what the
3c mimicry transports are for); per-flow port hopping / domain fronting; the
relay auto-selecting its own ports.
