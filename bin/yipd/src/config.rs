//! Static two-peer config for the yip daemon.
//!
//! The config file is a simple `key=value` text format (one pair per line,
//! `#`-prefixed comment lines and blank lines are ignored). All three 32-byte
//! keys are hex-encoded (64 hex digits). No external parser is required.

// The mesh fields (`ca_public`/`cert`/`roots`/`member_sign_private`/
// `network_id`) are parsed here in Task 5 but only *read* once Task 6 wires
// `Membership::new` into `tunnel.rs`; until then they're dead code outside
// this module's own tests.
#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;

use crate::mode::TunnelMode;
use yip_membership::{Cert, RootSet};

/// Wire transport selected via `transport=quic|raw|udp` (absent ⇒ `RawUdp`).
///
/// Named `TransportMode` (not `Transport`) to avoid clashing with
/// `yip_transport::Transport`, the FEC engine. Nothing consumes
/// `TransportMode::Quic` yet — Task 5 wires the run-loop selection; this task
/// only parses and validates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportMode {
    #[default]
    RawUdp,
    Quic,
}

/// Configuration for a single remote peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    /// This peer's known direct UDP endpoint, or `None` if the peer is known
    /// only by public key (reachable only via rendezvous/relay once Task 6
    /// wires that path in).
    pub endpoint: Option<SocketAddr>,
}

/// Static configuration for one yip tunnel endpoint.
#[derive(Debug)]
pub struct Config {
    /// Local X25519 private key (32 bytes).
    pub local_private: [u8; 32],
    /// Local X25519 public key (32 bytes). Used by `PeerManager` to derive
    /// this node's self-certifying mesh address (`node_addr`).
    pub local_public: [u8; 32],
    /// List of remote peers.
    pub peers: Vec<PeerConfig>,
    /// Local UDP address to bind.
    pub listen: SocketAddr,
    /// TUN/TAP device name (e.g. `"yip0"`).
    pub device: String,
    /// Tunnel mode selected from `device_kind=tun|tap` (`tun` by default).
    pub device_kind: TunnelMode,
    /// Configured rendezvous+relay server, if any (`rendezvous=<IP:port>`).
    /// Enables lazy Direct→Punch→Relay peer bring-up in `PeerManager` via
    /// `ConfiguredServerRendezvous`.
    pub rendezvous: Option<SocketAddr>,
    /// Mesh CA public key(s) trusted to sign member certs (repeatable
    /// `ca_public=<hex64>`). Empty when mesh mode is not configured.
    pub ca_public: Vec<[u8; 32]>,
    /// This node's CA-issued membership cert, decoded from the file named
    /// by `cert=<path>` (a hex-encoded `Cert::encode` blob, one line).
    pub cert: Option<Cert>,
    /// The CA-signed bootstrap root set, decoded from the file named by
    /// `roots=<path>` (a hex-encoded `RootSet::encode` blob, one line).
    pub roots: Option<RootSet>,
    /// This node's Ed25519 record-signing private key
    /// (`member_sign_private=<hex64>`), generated alongside the X25519
    /// data-plane key. Used to sign this node's gossip `Record`.
    pub member_sign_private: Option<[u8; 32]>,
    /// The mesh network id (`network_id=<hex32>`), embedded in and checked
    /// against every cert/record.
    pub network_id: Option<[u8; 16]>,
    /// Network-wide anti-DPI obfuscation shared secret (`obf_psk=<hex64>`).
    /// Absent (`None`) means obfuscation is disabled for this node. Feeds
    /// `yip_obf::derive_key` once Tasks 3/4 wire obfuscation into the wire
    /// path; this task only parses it.
    pub obf_psk: Option<[u8; 32]>,
    /// Opt-in idle cover-traffic interval in milliseconds
    /// (`cover_traffic_ms=<u64>`). Absent (`None`, the default) means no
    /// cover traffic is emitted. Only meaningful when `obf_psk` is also
    /// configured — `PeerManager` gates emission on both. A configured value
    /// of `0` is rejected as invalid (there is no such thing as a zero-length
    /// idle interval).
    pub cover_traffic_ms: Option<u64>,
    /// Wire transport (`transport=quic|raw|udp`, absent ⇒ `RawUdp`).
    /// Mutually exclusive with `obf_psk`/`cover_traffic_ms` — QUIC provides
    /// its own wire obfuscation. Nothing consumes `TransportMode::Quic` yet;
    /// this task only parses and validates it.
    pub transport: TransportMode,
}

// ── hex decode helper ─────────────────────────────────────────────────────────

/// Decode a 64-char hex string into 32 bytes. Shared with `main.rs`'s
/// `--addr` subcommand so the two paths cannot drift.
pub(crate) fn hex_to_32(hex: &str) -> io::Result<[u8; 32]> {
    if hex.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected 64 hex chars, got {}", hex.len()),
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decode a 32-char hex string into 16 bytes (`network_id=<hex32>`).
pub(crate) fn hex_to_16(hex: &str) -> io::Result<[u8; 16]> {
    if hex.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected 32 hex chars, got {}", hex.len()),
        ));
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decode an arbitrary-length hex string into bytes — used for the
/// variable-length `cert=<path>`/`roots=<path>` file contents (a
/// `Cert`/`RootSet` encodes to a variable number of bytes, unlike the
/// fixed-size 32/16-byte keys `hex_to_32`/`hex_to_16` handle).
fn hex_decode_vec(hex: &str) -> io::Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "odd-length hex string".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Load and decode a `cert=<path>` file: one line of hex-encoded
/// `Cert::encode` bytes.
fn load_cert_file(path: &str) -> io::Result<Cert> {
    let contents = std::fs::read_to_string(path)?;
    let bytes = hex_decode_vec(contents.trim())?;
    Cert::decode(&bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to decode cert file {path}"),
        )
    })
}

/// Load and decode a `roots=<path>` file: one line of hex-encoded
/// `RootSet::encode` bytes.
fn load_roots_file(path: &str) -> io::Result<RootSet> {
    let contents = std::fs::read_to_string(path)?;
    let bytes = hex_decode_vec(contents.trim())?;
    RootSet::decode(&bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to decode roots file {path}"),
        )
    })
}

fn hex_nibble(b: u8) -> io::Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid hex digit: {}", b as char),
        )),
    }
}

// ── missing key helper ────────────────────────────────────────────────────────

fn missing(key: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("missing required config key: {key}"),
    )
}

// ── peer block flush helper ──────────────────────────────────────────────────

fn flush_peer_block(
    cur_pk: Option<[u8; 32]>,
    cur_ep: Option<SocketAddr>,
    peers: &mut Vec<PeerConfig>,
) -> io::Result<()> {
    match cur_pk {
        // `endpoint` is optional: a peer known only by public key is
        // rendezvous-only (unreachable directly until Task 6 supplies a
        // candidate).
        Some(pk) => peers.push(PeerConfig {
            public_key: pk,
            endpoint: cur_ep,
        }),
        None if cur_ep.is_some() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer block has an endpoint but no public_key".to_string(),
            ));
        }
        None => {}
    }
    Ok(())
}

// ── Config::parse ─────────────────────────────────────────────────────────────

impl Config {
    /// Parse a `key=value` config text into a [`Config`].
    ///
    /// Lines beginning with `#` and blank lines are ignored.
    /// Supports `[peer]` block syntax with `public_key` and `endpoint` fields.
    /// Also supports legacy single `peer_public`+`peer_endpoint` fields.
    /// Returns an `io::Error` for any missing or malformed fields.
    pub fn parse(text: &str) -> io::Result<Config> {
        let mut local_private: Option<[u8; 32]> = None;
        let mut local_public: Option<[u8; 32]> = None;
        let mut peers: Vec<PeerConfig> = Vec::new();
        let mut cur_pk: Option<[u8; 32]> = None;
        let mut cur_ep: Option<SocketAddr> = None;
        let mut legacy_peer_public: Option<[u8; 32]> = None;
        let mut legacy_peer_endpoint: Option<SocketAddr> = None;
        let mut listen: Option<SocketAddr> = None;
        let mut device: Option<String> = None;
        let mut device_kind = TunnelMode::default();
        let mut rendezvous: Option<SocketAddr> = None;
        let mut ca_public: Vec<[u8; 32]> = Vec::new();
        let mut cert: Option<Cert> = None;
        let mut roots: Option<RootSet> = None;
        let mut member_sign_private: Option<[u8; 32]> = None;
        let mut network_id: Option<[u8; 16]> = None;
        let mut obf_psk: Option<[u8; 32]> = None;
        let mut cover_traffic_ms: Option<u64> = None;
        let mut transport = TransportMode::default();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check for [peer] block header
            if line == "[peer]" {
                flush_peer_block(cur_pk, cur_ep, &mut peers)?;
                cur_pk = None;
                cur_ep = None;
                continue;
            }

            let (key, val) = line.split_once('=').ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("malformed config line (no '='): {line}"),
                )
            })?;
            let key = key.trim();
            let val = val.trim();
            match key {
                "local_private" => local_private = Some(hex_to_32(val)?),
                "local_public" => local_public = Some(hex_to_32(val)?),
                "public_key" => cur_pk = Some(hex_to_32(val)?),
                "endpoint" => {
                    cur_ep =
                        Some(val.parse::<SocketAddr>().map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?)
                }
                "peer_public" => legacy_peer_public = Some(hex_to_32(val)?),
                "peer_endpoint" => {
                    legacy_peer_endpoint =
                        Some(val.parse::<SocketAddr>().map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?)
                }
                "listen" => {
                    listen =
                        Some(val.parse::<SocketAddr>().map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?)
                }
                "device" => device = Some(val.to_owned()),
                "device_kind" => device_kind = TunnelMode::parse_device_kind(val)?,
                "rendezvous" => {
                    rendezvous =
                        Some(val.parse::<SocketAddr>().map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?)
                }
                "ca_public" => ca_public.push(hex_to_32(val)?),
                "cert" => cert = Some(load_cert_file(val)?),
                "roots" => roots = Some(load_roots_file(val)?),
                "member_sign_private" => member_sign_private = Some(hex_to_32(val)?),
                "network_id" => network_id = Some(hex_to_16(val)?),
                "obf_psk" => obf_psk = Some(hex_to_32(val)?),
                "cover_traffic_ms" => {
                    let ms = val
                        .parse::<u64>()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    if ms == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "cover_traffic_ms must be non-zero",
                        ));
                    }
                    cover_traffic_ms = Some(ms);
                }
                "transport" => {
                    transport = match val {
                        "quic" => TransportMode::Quic,
                        "raw" | "udp" => TransportMode::RawUdp,
                        other => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("unknown transport: {other}"),
                            ));
                        }
                    }
                }
                // Silently ignore unknown keys for forward-compatibility. The
                // netns config files still contain `initiate=true|false` from
                // before Task 5 removed the field; this is intentional so
                // those fixtures don't need editing (verified by
                // `parse_config_unknown_key_is_silently_ignored`, which this
                // arm's removal now also exercises for `initiate` itself).
                _ => {}
            }
        }

        // Flush any trailing peer block
        flush_peer_block(cur_pk, cur_ep, &mut peers)?;

        // If no [peer] blocks, try legacy single-peer format
        if peers.is_empty() {
            if let (Some(pk), Some(ep)) = (legacy_peer_public, legacy_peer_endpoint) {
                peers.push(PeerConfig {
                    public_key: pk,
                    endpoint: Some(ep),
                });
            }
        }

        // Peers list must not be empty, UNLESS full mesh config is present: a
        // mesh node (2c) legitimately has zero statically-configured peers —
        // it bootstraps via the signed root set and discovers everyone else
        // (including a root acting purely as a seed, with no `[peer]` for it
        // either) via gossip. `tunnel.rs` gates `Membership::new` on this same
        // five-field condition (`ca_public` non-empty + `cert`/`roots`/
        // `member_sign_private`/`network_id` all present), so this check is
        // single-sourced with what actually enables mesh mode.
        let mesh_mode = !ca_public.is_empty()
            && cert.is_some()
            && roots.is_some()
            && member_sign_private.is_some()
            && network_id.is_some();
        if peers.is_empty() && !mesh_mode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no peers configured (use [peer] blocks or legacy peer_public/peer_endpoint, \
                 or full mesh config to bootstrap via the root set)"
                    .to_string(),
            ));
        }

        // A signed root set is only as trustworthy as its signature: verify
        // `roots.ca_sig` against the configured `ca_public` set here, at
        // config-load time, rather than trusting whatever `load_roots_file`
        // decoded. `verify_rootset` returns `false` (and this rejects) both
        // for a bad/foreign signature AND for an empty `ca_public` — a roots
        // file with no CA to check it against is unsafe either way.
        if let Some(r) = &roots {
            if !r.verify_rootset(&ca_public) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "root set signature does not verify against any configured ca_public",
                ));
            }
        }

        // `transport=quic` provides its own wire obfuscation, so the
        // obf/cover-traffic knobs (which assume the raw-UDP path) don't
        // apply — reject the combination rather than silently ignoring one
        // side.
        if transport == TransportMode::Quic && (obf_psk.is_some() || cover_traffic_ms.is_some()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transport=quic is mutually exclusive with obf_psk / cover_traffic_ms \
                 (QUIC provides its own wire obfuscation)",
            ));
        }

        Ok(Config {
            local_private: local_private.ok_or_else(|| missing("local_private"))?,
            local_public: local_public.ok_or_else(|| missing("local_public"))?,
            peers,
            listen: listen.ok_or_else(|| missing("listen"))?,
            device: device.ok_or_else(|| missing("device"))?,
            device_kind,
            rendezvous,
            ca_public,
            cert,
            roots,
            member_sign_private,
            network_id,
            obf_psk,
            cover_traffic_ms,
            transport,
        })
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::TunnelMode;

    #[test]
    fn parse_config_from_kv() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\npeer_endpoint=10.0.0.2:51820\ninitiate=true\n\
                    local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                    local_public=00000000000000000000000000000000000000000000000000000000000000aa\n\
                    peer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";
        let c = Config::parse(text).unwrap();
        assert_eq!(c.device, "yip0");
        assert_eq!(c.local_private[31], 0xff);
        assert_eq!(c.peers[0].public_key[31], 0xbb);
    }

    #[test]
    fn parse_config_comments_and_blank_lines_ignored() {
        let text = "\
# this is a comment
device=yip1

listen=127.0.0.1:51820
peer_endpoint=127.0.0.1:51821
initiate=false
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
";
        let c = Config::parse(text).unwrap();
        assert_eq!(c.device, "yip1");
        assert_eq!(c.peers.len(), 1);
    }

    #[test]
    fn parse_config_missing_key_returns_error() {
        // missing 'listen'
        let text = "\
device=yip0
peer_endpoint=10.0.0.2:51820
initiate=true
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
";
        assert!(Config::parse(text).is_err());
    }

    #[test]
    fn parse_config_bad_hex_returns_error() {
        let text = "\
device=yip0
listen=0.0.0.0:51820
peer_endpoint=10.0.0.2:51820
initiate=true
local_private=zzzz0000000000000000000000000000000000000000000000000000000000ff
local_public=00000000000000000000000000000000000000000000000000000000000000aa
peer_public=00000000000000000000000000000000000000000000000000000000000000bb
";
        assert!(Config::parse(text).is_err());
    }

    #[test]
    fn hex_to_32_wrong_length_returns_error() {
        // Too short — exercises the hex.len() != 64 branch in hex_to_32.
        let text = "\
device=yip0
listen=0.0.0.0:51820
peer_endpoint=10.0.0.2:51820
initiate=true
local_private=deadbeef
local_public=00000000000000000000000000000000000000000000000000000000000000aa
peer_public=00000000000000000000000000000000000000000000000000000000000000bb
";
        let err = Config::parse(text).unwrap_err();
        assert!(err.to_string().contains("64 hex chars"));
    }

    #[test]
    fn parse_config_malformed_line_no_equals() {
        // A line without '=' triggers the split_once error path.
        let text = "\
device=yip0
listen=0.0.0.0:51820
peer_endpoint=10.0.0.2:51820
initiate=true
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
THISISMALFORMED
";
        assert!(Config::parse(text).is_err());
    }

    #[test]
    fn parse_config_bad_peer_endpoint_returns_error() {
        let text = "\
device=yip0
listen=0.0.0.0:51820
peer_endpoint=not_a_valid_addr
initiate=true
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
";
        assert!(Config::parse(text).is_err());
    }

    #[test]
    fn parse_config_bad_listen_returns_error() {
        let text = "\
device=yip0
listen=not_valid
peer_endpoint=10.0.0.2:51820
initiate=true
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
";
        assert!(Config::parse(text).is_err());
    }

    #[test]
    fn parse_config_unknown_key_is_silently_ignored() {
        // Unknown keys must not cause an error (forward-compat).
        let text = "\
device=yip0
listen=0.0.0.0:51820
peer_endpoint=10.0.0.2:51820
initiate=false
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
future_key=whatever
";
        assert!(Config::parse(text).is_ok());
    }

    #[test]
    fn parse_config_device_kind_tun() {
        let text = "\
device=yip0
device_kind=tun
listen=0.0.0.0:51820
peer_endpoint=10.0.0.2:51820
initiate=false
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
";
        let c = Config::parse(text).unwrap();
        assert_eq!(c.device_kind, TunnelMode::L3Tun);
    }

    #[test]
    fn parse_config_device_kind_tap() {
        let text = "\
device=yip0
device_kind=tap
listen=0.0.0.0:51820
peer_endpoint=10.0.0.2:51820
initiate=false
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
";
        let c = Config::parse(text).unwrap();
        assert_eq!(c.device_kind, TunnelMode::L2Tap);
    }

    #[test]
    fn parse_config_device_kind_defaults_to_tun_when_absent() {
        let text = "\
device=yip0
listen=0.0.0.0:51820
peer_endpoint=10.0.0.2:51820
initiate=false
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
";
        let c = Config::parse(text).unwrap();
        assert_eq!(c.device_kind, TunnelMode::L3Tun);
    }

    #[test]
    fn parse_config_device_kind_unknown_value_returns_error() {
        let text = "\
device=yip0
device_kind=foo
listen=0.0.0.0:51820
peer_endpoint=10.0.0.2:51820
initiate=false
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
";
        let err = Config::parse(text).unwrap_err();
        assert_eq!(err.to_string(), "invalid device_kind: foo");
    }

    #[test]
    fn parses_multiple_peers_and_legacy_single() {
        // New [peer] block form:
        let text = "local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                    local_public=000000000000000000000000000000000000000000000000000000000000aa01\n\
                    listen=0.0.0.0:51820\ndevice=yip0\n\
                    [peer]\npublic_key=00000000000000000000000000000000000000000000000000000000000000b1\nendpoint=10.0.0.2:51820\n\
                    [peer]\npublic_key=00000000000000000000000000000000000000000000000000000000000000b2\nendpoint=10.0.0.3:51820\n";
        let cfg = Config::parse(text).expect("parses");
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(
            cfg.peers[0].endpoint,
            Some("10.0.0.2:51820".parse().unwrap())
        );
        assert_eq!(cfg.peers[1].public_key[31], 0xb2);
    }

    #[test]
    fn legacy_single_peer_becomes_one_entry() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\npeer_endpoint=10.0.0.2:51820\n\
                    local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                    local_public=00000000000000000000000000000000000000000000000000000000000000aa\n\
                    peer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";
        let cfg = Config::parse(text).expect("legacy parses");
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].public_key[31], 0xbb);
    }

    #[test]
    fn parses_rendezvous_and_optional_endpoint() {
        let text = "local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                    local_public=000000000000000000000000000000000000000000000000000000000000aa01\n\
                    listen=0.0.0.0:51820\ndevice=yip0\nrendezvous=203.0.113.1:51821\n\
                    [peer]\npublic_key=00000000000000000000000000000000000000000000000000000000000000b1\n";
        let cfg = Config::parse(text).expect("parses");
        assert_eq!(cfg.rendezvous, Some("203.0.113.1:51821".parse().unwrap()));
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(
            cfg.peers[0].endpoint, None,
            "peer with no endpoint is rendezvous-only"
        );
    }

    #[test]
    fn rendezvous_absent_is_none() {
        let text = "local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                    local_public=000000000000000000000000000000000000000000000000000000000000aa01\n\
                    listen=0.0.0.0:51820\ndevice=yip0\n\
                    [peer]\npublic_key=00000000000000000000000000000000000000000000000000000000000000b1\nendpoint=10.0.0.2:51820\n";
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.rendezvous, None);
        assert_eq!(
            cfg.peers[0].endpoint,
            Some("10.0.0.2:51820".parse().unwrap())
        );
    }

    // ── mesh config (2c/Task 5) ────────────────────────────────────────

    fn hex_encode_bytes(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    const BASE_CFG: &str = "\
device=yip0
listen=0.0.0.0:51820
peer_endpoint=10.0.0.2:51820
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
";

    #[test]
    fn mesh_fields_absent_are_default() {
        let cfg = Config::parse(BASE_CFG).unwrap();
        assert!(cfg.ca_public.is_empty());
        assert!(cfg.cert.is_none());
        assert!(cfg.roots.is_none());
        assert!(cfg.member_sign_private.is_none());
        assert!(cfg.network_id.is_none());
    }

    #[test]
    fn mesh_fields_present_are_some() {
        use ed25519_dalek::{Signer, SigningKey};
        use yip_membership::cert::{cert_signing_body, rootset_signing_body};

        let ca = SigningKey::from_bytes(&[9u8; 32]);
        let mut cert = Cert {
            version: 1,
            member_pubkey: [2u8; 32],
            member_sign_pubkey: [3u8; 32],
            network_id: [4u8; 16],
            not_before: 0,
            not_after: 1_000_000,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        cert.ca_sig = ca.sign(&cert_signing_body(&cert)).to_bytes();
        let mut cert_bytes = Vec::new();
        cert.encode(&mut cert_bytes);

        let mut roots = RootSet {
            roots: vec![],
            version: 1,
            ca_sig: [0u8; 64],
        };
        roots.ca_sig = ca.sign(&rootset_signing_body(&roots)).to_bytes();
        let mut roots_bytes = Vec::new();
        roots.encode(&mut roots_bytes);

        let dir = std::env::temp_dir();
        let cert_path = dir.join("yipd_test_mesh_cert_present.hex");
        let roots_path = dir.join("yipd_test_mesh_roots_present.hex");
        std::fs::write(&cert_path, hex_encode_bytes(&cert_bytes)).unwrap();
        std::fs::write(&roots_path, hex_encode_bytes(&roots_bytes)).unwrap();

        // `ca_pub_1` must be the verifying key of the CA that actually signed
        // `cert`/`roots` above, now that `Config::parse` verifies the root
        // set's `ca_sig` against `ca_public` at load time. `ca_pub_2` is an
        // unrelated second entry, kept to exercise the multi-CA list.
        let ca_pub_1 = ca.verifying_key().to_bytes();
        let ca_pub_2 = [0x22u8; 32];
        let member_sign_priv = [0x33u8; 32];
        let network_id = [0x44u8; 16];

        let text = format!(
            "{BASE_CFG}\
             ca_public={}\n\
             ca_public={}\n\
             member_sign_private={}\n\
             network_id={}\n\
             cert={}\n\
             roots={}\n",
            hex_encode_bytes(&ca_pub_1),
            hex_encode_bytes(&ca_pub_2),
            hex_encode_bytes(&member_sign_priv),
            hex_encode_bytes(&network_id),
            cert_path.display(),
            roots_path.display(),
        );
        let cfg = Config::parse(&text).expect("mesh config parses");

        assert_eq!(cfg.ca_public, vec![ca_pub_1, ca_pub_2]);
        assert_eq!(cfg.member_sign_private, Some(member_sign_priv));
        assert_eq!(cfg.network_id, Some(network_id));
        assert_eq!(cfg.cert, Some(cert));
        assert_eq!(cfg.roots, Some(roots));

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&roots_path);
    }

    #[test]
    fn bad_cert_file_missing_path_is_parse_error() {
        let text = format!("{BASE_CFG}cert=/nonexistent/path/yipd-does-not-exist.hex\n");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn bad_cert_file_garbage_content_is_parse_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("yipd_test_mesh_cert_garbage.hex");
        std::fs::write(&path, "not_valid_hex!!").unwrap();
        let text = format!("{BASE_CFG}cert={}\n", path.display());
        assert!(Config::parse(&text).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bad_roots_file_garbage_content_is_parse_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("yipd_test_mesh_roots_garbage.hex");
        std::fs::write(&path, "deadbeef").unwrap(); // valid hex, not a valid RootSet
        let text = format!("{BASE_CFG}roots={}\n", path.display());
        assert!(Config::parse(&text).is_err());
        let _ = std::fs::remove_file(&path);
    }

    // ── zero-peer mesh mode (2c/Task 7) ────────────────────────────────
    //
    // A pure mesh node (2c) has no statically-configured `[peer]` at all —
    // everyone it talks to (including a seed root) is reached via the signed
    // root set + gossip, never a `[peer]` block. `Config::parse` must accept
    // an empty peer list when the full mesh config (all five fields) is
    // present, while still rejecting an empty peer list for a plain 2a/2b
    // config (no way to reach anyone).

    #[test]
    fn zero_peers_with_full_mesh_config_parses() {
        use ed25519_dalek::{Signer, SigningKey};
        use yip_membership::cert::{cert_signing_body, rootset_signing_body};

        let ca = SigningKey::from_bytes(&[9u8; 32]);
        let mut cert = Cert {
            version: 1,
            member_pubkey: [2u8; 32],
            member_sign_pubkey: [3u8; 32],
            network_id: [4u8; 16],
            not_before: 0,
            not_after: 1_000_000,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        cert.ca_sig = ca.sign(&cert_signing_body(&cert)).to_bytes();
        let mut cert_bytes = Vec::new();
        cert.encode(&mut cert_bytes);

        let mut roots = RootSet {
            roots: vec![],
            version: 1,
            ca_sig: [0u8; 64],
        };
        roots.ca_sig = ca.sign(&rootset_signing_body(&roots)).to_bytes();
        let mut roots_bytes = Vec::new();
        roots.encode(&mut roots_bytes);

        let dir = std::env::temp_dir();
        let cert_path = dir.join("yipd_test_zero_peer_mesh_cert.hex");
        let roots_path = dir.join("yipd_test_zero_peer_mesh_roots.hex");
        std::fs::write(&cert_path, hex_encode_bytes(&cert_bytes)).unwrap();
        std::fs::write(&roots_path, hex_encode_bytes(&roots_bytes)).unwrap();

        let text = format!(
            "device=yip0\n\
             listen=0.0.0.0:51820\n\
             local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
             local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
             ca_public={}\n\
             member_sign_private={}\n\
             network_id={}\n\
             cert={}\n\
             roots={}\n",
            // `ca_public` must be the verifying key of the CA that signed
            // `cert`/`roots` above (`ca`), now that `Config::parse` verifies
            // the root set's `ca_sig` at load time.
            hex_encode_bytes(&ca.verifying_key().to_bytes()),
            hex_encode_bytes(&[0x33u8; 32]),
            hex_encode_bytes(&[0x44u8; 16]),
            cert_path.display(),
            roots_path.display(),
        );
        let cfg = Config::parse(&text).expect("zero-peer full-mesh config parses");
        assert!(cfg.peers.is_empty());

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&roots_path);
    }

    // ── root set signature verification (2c Task 7 F1) ─────────────────
    //
    // The signed root set is only as trustworthy as its `ca_sig`: a tampered
    // or wrong-CA roots file must be rejected at config-load time, not
    // silently accepted (the spec's "signed root set is CA-signed" promise).

    #[test]
    fn roots_with_wrong_ca_is_parse_error() {
        use ed25519_dalek::{Signer, SigningKey};
        use yip_membership::cert::{cert_signing_body, rootset_signing_body};

        // `ca` signs the cert (and matches `ca_public`); `wrong_ca` signs the
        // root set instead — a config whose roots file was swapped in from a
        // different (or forged) CA.
        let ca = SigningKey::from_bytes(&[9u8; 32]);
        let wrong_ca = SigningKey::from_bytes(&[7u8; 32]);

        let mut cert = Cert {
            version: 1,
            member_pubkey: [2u8; 32],
            member_sign_pubkey: [3u8; 32],
            network_id: [4u8; 16],
            not_before: 0,
            not_after: 1_000_000,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        cert.ca_sig = ca.sign(&cert_signing_body(&cert)).to_bytes();
        let mut cert_bytes = Vec::new();
        cert.encode(&mut cert_bytes);

        let mut roots = RootSet {
            roots: vec![],
            version: 1,
            ca_sig: [0u8; 64],
        };
        roots.ca_sig = wrong_ca.sign(&rootset_signing_body(&roots)).to_bytes();
        let mut roots_bytes = Vec::new();
        roots.encode(&mut roots_bytes);

        let dir = std::env::temp_dir();
        let cert_path = dir.join("yipd_test_roots_wrong_ca_cert.hex");
        let roots_path = dir.join("yipd_test_roots_wrong_ca_roots.hex");
        std::fs::write(&cert_path, hex_encode_bytes(&cert_bytes)).unwrap();
        std::fs::write(&roots_path, hex_encode_bytes(&roots_bytes)).unwrap();

        let text = format!(
            "device=yip0\n\
             listen=0.0.0.0:51820\n\
             local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
             local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
             ca_public={}\n\
             member_sign_private={}\n\
             network_id={}\n\
             cert={}\n\
             roots={}\n",
            // Only `ca`'s key is configured; the roots file was signed by
            // `wrong_ca`, so verification must fail.
            hex_encode_bytes(&ca.verifying_key().to_bytes()),
            hex_encode_bytes(&[0x33u8; 32]),
            hex_encode_bytes(&[0x44u8; 16]),
            cert_path.display(),
            roots_path.display(),
        );
        let err = Config::parse(&text).unwrap_err();
        assert!(
            err.to_string().contains("root set signature"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&roots_path);
    }

    // ── obf_psk (3a Task 2) ─────────────────────────────────────────────

    #[test]
    fn parses_obf_psk_when_present() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    obf_psk=00000000000000000000000000000000000000000000000000000000000000ff\n";
        let cfg = Config::parse(text).unwrap();
        assert_eq!(
            cfg.obf_psk,
            Some({
                let mut a = [0u8; 32];
                a[31] = 0xff;
                a
            })
        );
    }

    #[test]
    fn obf_psk_absent_is_none() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";
        assert_eq!(Config::parse(text).unwrap().obf_psk, None);
    }

    // ── cover_traffic_ms (3b Task 4) ────────────────────────────────────

    #[test]
    fn parses_cover_traffic_ms_when_present() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    cover_traffic_ms=250\n";
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.cover_traffic_ms, Some(250));
    }

    #[test]
    fn cover_traffic_ms_absent_is_none() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";
        assert_eq!(Config::parse(text).unwrap().cover_traffic_ms, None);
    }

    #[test]
    fn cover_traffic_ms_zero_is_parse_error() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    cover_traffic_ms=0\n";
        let err = Config::parse(text).unwrap_err();
        assert!(
            err.to_string().contains("non-zero"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cover_traffic_ms_non_integer_is_parse_error() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    cover_traffic_ms=abc\n";
        assert!(Config::parse(text).is_err());
    }

    // ── transport (3c.1 Task 3) ──────────────────────────────────────────

    #[test]
    fn parses_transport_quic_when_present() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    transport=quic\n";
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.transport, TransportMode::Quic);
    }

    #[test]
    fn transport_absent_defaults_to_raw_udp() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.transport, TransportMode::RawUdp);
    }

    #[test]
    fn transport_raw_and_udp_aliases_parse_to_raw_udp() {
        for val in ["raw", "udp"] {
            let text = format!(
                "device=yip0\nlisten=0.0.0.0:51820\n\
                 local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                 local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                 peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                 transport={val}\n"
            );
            let cfg = Config::parse(&text).unwrap();
            assert_eq!(cfg.transport, TransportMode::RawUdp, "transport={val}");
        }
    }

    #[test]
    fn transport_unknown_value_is_parse_error() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    transport=bogus\n";
        let err = Config::parse(text).unwrap_err();
        assert!(
            err.to_string().contains("unknown transport"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn transport_quic_with_obf_psk_is_parse_error() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    transport=quic\n\
                    obf_psk=00000000000000000000000000000000000000000000000000000000000000ff\n";
        let err = Config::parse(text).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn transport_quic_with_cover_traffic_ms_is_parse_error() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    transport=quic\n\
                    cover_traffic_ms=200\n";
        let err = Config::parse(text).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn transport_quic_alone_parses_ok() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\n\
                    local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
                    local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
                    peer_endpoint=10.0.0.2:51820\npeer_public=00000000000000000000000000000000000000000000000000000000000000bb\n\
                    transport=quic\n";
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.transport, TransportMode::Quic);
        assert_eq!(cfg.obf_psk, None);
        assert_eq!(cfg.cover_traffic_ms, None);
    }

    #[test]
    fn zero_peers_without_mesh_config_is_parse_error() {
        let text = "\
device=yip0
listen=0.0.0.0:51820
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
";
        let err = Config::parse(text).unwrap_err();
        assert!(err.to_string().contains("no peers configured"));
    }
}
