//! Static two-peer config for the yip daemon.
//!
//! The config file is a simple `key=value` text format (one pair per line,
//! `#`-prefixed comment lines and blank lines are ignored). All three 32-byte
//! keys are hex-encoded (64 hex digits). No external parser is required.

use std::io;
use std::net::SocketAddr;

use crate::mode::TunnelMode;

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

        // Peers list must not be empty
        if peers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no peers configured (use [peer] blocks or legacy peer_public/peer_endpoint)"
                    .to_string(),
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
}
