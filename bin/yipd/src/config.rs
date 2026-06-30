//! Static two-peer config for the yip daemon.
//!
//! The config file is a simple `key=value` text format (one pair per line,
//! `#`-prefixed comment lines and blank lines are ignored). All three 32-byte
//! keys are hex-encoded (64 hex digits). No external parser is required.

use std::io;
use std::net::SocketAddr;

/// Static configuration for one yip tunnel endpoint.
#[derive(Debug)]
pub struct Config {
    /// Local X25519 private key (32 bytes).
    pub local_private: [u8; 32],
    /// Local X25519 public key (32 bytes). Carried in config for key-management /
    /// re-advertisement in future milestones; not consumed by the M6 data path itself.
    #[expect(
        dead_code,
        reason = "used for key identity; data path reads local_private"
    )]
    pub local_public: [u8; 32],
    /// Remote peer's X25519 public key (32 bytes).
    pub peer_public: [u8; 32],
    /// Remote peer's UDP endpoint (used by the initiator to send the first
    /// handshake message; the responder learns it from the incoming datagram).
    pub peer_endpoint: SocketAddr,
    /// Local UDP address to bind.
    pub listen: SocketAddr,
    /// TUN/TAP device name (e.g. `"yip0"`).
    pub device: String,
    /// Whether this peer initiates the Noise-IK handshake.
    pub initiate: bool,
}

// ── hex decode helper ─────────────────────────────────────────────────────────

fn hex_to_32(hex: &str) -> io::Result<[u8; 32]> {
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

// ── Config::parse ─────────────────────────────────────────────────────────────

impl Config {
    /// Parse a `key=value` config text into a [`Config`].
    ///
    /// Lines beginning with `#` and blank lines are ignored.
    /// Returns an `io::Error` for any missing or malformed fields.
    pub fn parse(text: &str) -> io::Result<Config> {
        let mut local_private: Option<[u8; 32]> = None;
        let mut local_public: Option<[u8; 32]> = None;
        let mut peer_public: Option<[u8; 32]> = None;
        let mut peer_endpoint: Option<SocketAddr> = None;
        let mut listen: Option<SocketAddr> = None;
        let mut device: Option<String> = None;
        let mut initiate: Option<bool> = None;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
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
                "peer_public" => peer_public = Some(hex_to_32(val)?),
                "peer_endpoint" => {
                    peer_endpoint =
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
                "initiate" => match val {
                    "true" | "1" | "yes" => initiate = Some(true),
                    "false" | "0" | "no" => initiate = Some(false),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid boolean for 'initiate': {val}"),
                        ))
                    }
                },
                // Unknown keys are silently ignored for forward-compatibility.
                _ => {}
            }
        }

        Ok(Config {
            local_private: local_private.ok_or_else(|| missing("local_private"))?,
            local_public: local_public.ok_or_else(|| missing("local_public"))?,
            peer_public: peer_public.ok_or_else(|| missing("peer_public"))?,
            peer_endpoint: peer_endpoint.ok_or_else(|| missing("peer_endpoint"))?,
            listen: listen.ok_or_else(|| missing("listen"))?,
            device: device.ok_or_else(|| missing("device"))?,
            initiate: initiate.ok_or_else(|| missing("initiate"))?,
        })
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config_from_kv() {
        let text = "device=yip0\nlisten=0.0.0.0:51820\npeer_endpoint=10.0.0.2:51820\ninitiate=true\n\
                    local_private=00000000000000000000000000000000000000000000000000000000000000ff\n\
                    local_public=00000000000000000000000000000000000000000000000000000000000000aa\n\
                    peer_public=00000000000000000000000000000000000000000000000000000000000000bb\n";
        let c = Config::parse(text).unwrap();
        assert_eq!(c.device, "yip0");
        assert!(c.initiate);
        assert_eq!(c.local_private[31], 0xff);
        assert_eq!(c.peer_public[31], 0xbb);
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
        assert!(!c.initiate);
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
    fn parse_config_bad_initiate_returns_error() {
        let text = "\
device=yip0
listen=0.0.0.0:51820
peer_endpoint=10.0.0.2:51820
initiate=maybe
local_private=0000000000000000000000000000000000000000000000000000000000000001
local_public=0000000000000000000000000000000000000000000000000000000000000002
peer_public=0000000000000000000000000000000000000000000000000000000000000003
";
        let err = Config::parse(text).unwrap_err();
        assert!(err.to_string().contains("invalid boolean"));
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
    fn parse_config_initiate_numeric_aliases() {
        let yes_text = "\
device=yip0\nlisten=0.0.0.0:51820\npeer_endpoint=10.0.0.2:51820\ninitiate=1\n\
local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
peer_public=0000000000000000000000000000000000000000000000000000000000000003\n";
        assert!(Config::parse(yes_text).unwrap().initiate);

        let no_text = "\
device=yip0\nlisten=0.0.0.0:51820\npeer_endpoint=10.0.0.2:51820\ninitiate=0\n\
local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
peer_public=0000000000000000000000000000000000000000000000000000000000000003\n";
        assert!(!Config::parse(no_text).unwrap().initiate);

        let yes_text2 = "\
device=yip0\nlisten=0.0.0.0:51820\npeer_endpoint=10.0.0.2:51820\ninitiate=yes\n\
local_private=0000000000000000000000000000000000000000000000000000000000000001\n\
local_public=0000000000000000000000000000000000000000000000000000000000000002\n\
peer_public=0000000000000000000000000000000000000000000000000000000000000003\n";
        assert!(Config::parse(yes_text2).unwrap().initiate);
    }
}
