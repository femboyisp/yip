#![forbid(unsafe_code)]

//! The yip daemon. M6 wires device <-> transport <-> crypto <-> wire <-> io
//! and loads a static 2-peer config from a key=value file.

mod addr;
mod config;
mod dataplane;
mod handshake;
mod mac_table;
mod mode;
mod peer_manager;
mod tunnel;
mod wire_glue;

use config::Config;

fn banner() -> String {
    format!("yipd {}", env!("CARGO_PKG_VERSION"))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inverse of [`hex_encode`]: decode a 64-char hex string into a 32-byte
/// pubkey. Returns `Err` (message on stderr already emitted by the caller)
/// on wrong length or a non-hex digit.
fn hex_decode_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    fn nibble(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(format!("invalid hex digit: {}", b as char)),
        }
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = (nibble(chunk[0])? << 4) | nibble(chunk[1])?;
    }
    Ok(out)
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args();
    let _prog = args.next();

    match args.next().as_deref() {
        Some("--version") | Some("-V") => {
            println!("{}", banner());
            Ok(())
        }
        Some("--genkey") => {
            let kp = yip_crypto::generate_keypair();
            println!("private={}", hex_encode(&kp.private));
            println!("public={}", hex_encode(&kp.public));
            Ok(())
        }
        Some("--addr") => {
            let hex = args.next().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--addr requires a 64-char hex pubkey argument",
                )
            })?;
            let pubkey = hex_decode_32(&hex)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            println!("{}", addr::node_addr(&pubkey));
            Ok(())
        }
        Some(path) => {
            let text = std::fs::read_to_string(path)?;
            let config = Config::parse(&text)?;
            tunnel::run(config)
        }
        None => {
            eprintln!("usage: yipd <config-file>");
            eprintln!("       yipd --version");
            eprintln!("       yipd --genkey");
            eprintln!("       yipd --addr <pubkey-hex>");
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no config file specified",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_contains_name() {
        assert!(banner().starts_with("yipd "));
    }

    #[test]
    fn hex_decode_32_round_trips_through_hex_encode() {
        let kp = yip_crypto::generate_keypair();
        let hex = hex_encode(&kp.public);
        assert_eq!(hex_decode_32(&hex).unwrap(), kp.public);
    }

    #[test]
    fn hex_decode_32_matches_node_addr_derivation() {
        let kp = yip_crypto::generate_keypair();
        let hex = hex_encode(&kp.public);
        let decoded = hex_decode_32(&hex).unwrap();
        assert_eq!(addr::node_addr(&decoded), addr::node_addr(&kp.public));
    }

    #[test]
    fn hex_decode_32_rejects_wrong_length() {
        assert!(hex_decode_32("deadbeef").is_err());
    }

    #[test]
    fn hex_decode_32_rejects_bad_digit() {
        let bad = "zz".repeat(32);
        assert!(hex_decode_32(&bad).is_err());
    }
}
