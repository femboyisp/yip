#![forbid(unsafe_code)]

//! The yip daemon. M6 wires device <-> transport <-> crypto <-> wire <-> io
//! and loads a static 2-peer config from a key=value file.

mod config;
mod dataplane;
mod handshake;
mod mode;
mod tunnel;
mod wire_glue;

use config::Config;

fn banner() -> String {
    format!("yipd {}", env!("CARGO_PKG_VERSION"))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
        Some(path) => {
            let text = std::fs::read_to_string(path)?;
            let config = Config::parse(&text)?;
            tunnel::run(config)
        }
        None => {
            eprintln!("usage: yipd <config-file>");
            eprintln!("       yipd --version");
            eprintln!("       yipd --genkey");
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
}
