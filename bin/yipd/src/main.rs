#![forbid(unsafe_code)]

//! The yip daemon. M6 wires device <-> transport <-> crypto <-> wire <-> io
//! and loads a static 2-peer config from a key=value file.

mod addr;
mod config;
mod control;
mod dataplane;
mod epoch;
pub(crate) mod flow;
mod handshake;
mod mac_table;
mod membership;
mod mode;
mod path;
mod peer_manager;
mod port;
mod quic;
mod relay_client;
mod rendezvous;
pub mod sharding;
mod tls;
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
    // Single-sourced with the config parser so the two decoders can't drift.
    crate::config::hex_to_32(hex).map_err(|e| e.to_string())
}

fn print_daemon_usage() {
    println!("Usage: yipd <config-file> [OPTIONS]");
    println!("       yipd <COMMAND> [OPTIONS]");
    println!();
    println!("Commands:");
    println!("  status       Display daemon status and summary");
    println!("  peers        List connected peers and statistics");
    println!("  top          Real-time ANSI telemetry dashboard");
    println!();
    println!("Options:");
    println!("  -c, --control <SOCKET>  UNIX domain control socket path");
    println!("      --mtu <BYTES>       TUN device MTU (576-65535, default: 1400)");
    println!("      --genkey            Generate a fresh X25519 keypair");
    println!("      --addr <HEX-KEY>    Derive self-certifying mesh IPv6 address");
    println!("  -V, --version           Print version");
    println!("  -h, --help              Print help");
}

fn print_cli_usage(subcmd: &str) {
    match subcmd {
        "status" => {
            println!("Usage: yipctl status [OPTIONS]");
            println!();
            println!("Display status and summary telemetry of the local yipd daemon.");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>  Path to yipd UNIX control socket");
            println!("      --json              Output raw JSON");
            println!("  -h, --help              Print help");
        }
        "peers" => {
            println!("Usage: yipctl peers [OPTIONS]");
            println!();
            println!("List peers and transport telemetry from the local yipd daemon.");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>  Path to yipd UNIX control socket");
            println!("      --json              Output raw JSON");
            println!("  -h, --help              Print help");
        }
        "top" => {
            println!("Usage: yipctl top [OPTIONS]");
            println!();
            println!("Real-time terminal dashboard of daemon throughput, loss & FEC recovery.");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>   Path to yipd UNIX control socket");
            println!("  -i, --interval <MILLIS>  Refresh interval in milliseconds [default: 500]");
            println!("  -h, --help               Print help");
        }
        "ping" => {
            println!("Usage: yipctl ping <PEER> [OPTIONS]");
            println!();
            println!("Send latency probes to a mesh peer through the active transport.");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>  Path to yipd UNIX control socket");
            println!("  -h, --help              Print help");
        }
        "peer" => {
            println!("Usage: yipctl peer <add|rm> [ARGS] [OPTIONS]");
            println!();
            println!("Dynamically manage mesh peers at runtime.");
            println!();
            println!("Commands:");
            println!("  add <PUBLIC_KEY> [ENDPOINT] [TRANSPORT]  Add peer dynamically");
            println!("  rm  <PUBLIC_KEY>                         Remove peer");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>  Path to yipd UNIX control socket");
            println!("  -h, --help              Print help");
        }
        _ => {
            println!("Usage: yipctl <COMMAND> [OPTIONS]");
            println!();
            println!("Commands:");
            println!("  status  Display daemon status and summary");
            println!("  peers   List connected peers and statistics");
            println!("  top     Real-time ANSI telemetry dashboard");
            println!("  ping    Probe round-trip latency to a peer");
            println!("  peer    Dynamically add or remove peers");
            println!();
            println!("Options:");
            println!("  -V, --version  Print version");
            println!("  -h, --help     Print help");
        }
    }
}

fn run_client_subcommand(
    subcmd: &str,
    mut args: impl Iterator<Item = String>,
) -> std::io::Result<()> {
    let mut control_path = None;
    let mut json = false;
    let mut interval_ms = 500u64;
    let mut positional: Vec<String> = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--control" | "-c" => {
                let p = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--control requires a socket path",
                    )
                })?;
                control_path = Some(std::path::PathBuf::from(p));
            }
            "--json" => {
                json = true;
            }
            "--interval" | "-i" => {
                let s = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--interval requires milliseconds (e.g. 500)",
                    )
                })?;
                interval_ms = s.parse::<u64>().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                })?;
            }
            "--help" | "-h" => {
                print_cli_usage(subcmd);
                return Ok(());
            }
            other if !other.starts_with('-') => {
                positional.push(other.to_string());
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unrecognized option: {other}"),
                ));
            }
        }
    }

    let socket = control::resolve_control_socket(control_path.as_deref());

    match subcmd {
        "status" => control::run_cli_status(&socket, json).map_err(std::io::Error::other),
        "peers" => control::run_cli_peers(&socket, json).map_err(std::io::Error::other),
        "top" => control::run_cli_top(&socket, interval_ms).map_err(std::io::Error::other),
        "ping" => {
            let target = positional.first().map(|s| s.as_str()).unwrap_or("");
            control::run_cli_ping(&socket, target, 3).map_err(std::io::Error::other)
        }
        "peer" => {
            if positional.is_empty() {
                print_cli_usage("peer");
                return Ok(());
            }
            match positional[0].as_str() {
                "add" => {
                    if positional.len() < 2 {
                        eprintln!("Usage: yipctl peer add <PUBLIC_KEY> [ENDPOINT] [TRANSPORT]");
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "missing public key",
                        ));
                    }
                    let pk = &positional[1];
                    let ep = positional.get(2).map(|s| s.as_str());
                    let tr = positional.get(3).map(|s| s.as_str());
                    control::run_cli_peer_add(&socket, pk, ep, tr).map_err(std::io::Error::other)
                }
                "rm" => {
                    if positional.len() < 2 {
                        eprintln!("Usage: yipctl peer rm <PUBLIC_KEY>");
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "missing public key",
                        ));
                    }
                    control::client_query(
                        &socket,
                        control::ControlCmd::RemovePeer {
                            public_key: positional[1].clone(),
                        },
                    )
                    .map(|resp| {
                        if let control::ControlResponse::Ack { message, .. } = resp {
                            println!("\x1b[1;32m✓\x1b[0m {message}");
                        }
                    })
                    .map_err(std::io::Error::other)
                }
                "set-transport" => {
                    if positional.len() < 3 {
                        eprintln!("Usage: yipctl peer set-transport <PUBLIC_KEY> <TRANSPORT>");
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "missing parameters",
                        ));
                    }
                    control::client_query(
                        &socket,
                        control::ControlCmd::SetTransport {
                            public_key: positional[1].clone(),
                            transport: positional[2..].join(" "),
                        },
                    )
                    .map(|resp| {
                        if let control::ControlResponse::Ack { message, .. } = resp {
                            println!("\x1b[1;32m✓\x1b[0m {message}");
                        }
                    })
                    .map_err(std::io::Error::other)
                }
                other => {
                    eprintln!("Unknown peer action: {other}");
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "unknown peer action",
                    ))
                }
            }
        }
        "cert" => {
            if positional.is_empty() {
                println!("Usage: yipd cert <status|renew>");
                return Ok(());
            }
            match positional[0].as_str() {
                "status" => {
                    let resp = control::client_query(&socket, control::ControlCmd::CertStatus)
                        .map_err(std::io::Error::other)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                    } else if let control::ControlResponse::CertStatus {
                        not_before,
                        not_after,
                        ttl_remaining_secs,
                        renewal_threshold_secs,
                        is_threshold_ca,
                        ..
                    } = resp
                    {
                        println!("Certificate Status:");
                        println!("  Not Before:        {not_before}");
                        println!("  Not After:         {not_after}");
                        println!("  TTL Remaining:     {ttl_remaining_secs}s");
                        println!("  Renewal Threshold: {renewal_threshold_secs}s (70% TTL)");
                        println!(
                            "  Threshold CA:      {}",
                            if is_threshold_ca {
                                "configured"
                            } else {
                                "none (offline root CA)"
                            }
                        );
                    } else if let control::ControlResponse::Err { error, .. } = resp {
                        eprintln!("\x1b[1;31m✗\x1b[0m Error: {error}");
                    }
                    Ok(())
                }
                "renew" => {
                    let resp = control::client_query(&socket, control::ControlCmd::CertRenew)
                        .map_err(std::io::Error::other)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                    } else if let control::ControlResponse::CertRenew {
                        message,
                        new_not_after,
                        ..
                    } = resp
                    {
                        println!("\x1b[1;32m✓\x1b[0m {message}");
                        if let Some(na) = new_not_after {
                            println!("  New Not After: {na}");
                        }
                    } else if let control::ControlResponse::Err { error, .. } = resp {
                        eprintln!("\x1b[1;31m✗\x1b[0m Error: {error}");
                    }
                    Ok(())
                }
                other => {
                    eprintln!("Unknown cert action: {other}");
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "unknown cert action",
                    ))
                }
            }
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown subcommand: {subcmd}"),
        )),
    }
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args();
    let prog_name = args.next();

    let is_yipctl = prog_name
        .as_deref()
        .and_then(|p| std::path::Path::new(p).file_name())
        .map(|f| f == "yipctl")
        .unwrap_or(false);

    if is_yipctl {
        match args.next().as_deref() {
            Some("--version") | Some("-V") => {
                println!("{}", banner());
                return Ok(());
            }
            Some("--help") | Some("-h") | None => {
                print_cli_usage("");
                return Ok(());
            }
            Some("status") => return run_client_subcommand("status", args),
            Some("peers") => return run_client_subcommand("peers", args),
            Some("top") => return run_client_subcommand("top", args),
            Some("ping") => return run_client_subcommand("ping", args),
            Some("peer") => return run_client_subcommand("peer", args),
            Some("cert") => return run_client_subcommand("cert", args),
            Some("genkey") | Some("--genkey") => {
                let kp = yip_crypto::generate_keypair();
                println!("private={}", hex_encode(&kp.private));
                println!("public={}", hex_encode(&kp.public));
                return Ok(());
            }
            Some("addr") | Some("--addr") => {
                let hex = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "addr requires a 64-char hex pubkey argument",
                    )
                })?;
                let pubkey = hex_decode_32(&hex)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                println!("{}", addr::node_addr(&pubkey));
                return Ok(());
            }
            Some(unknown) => {
                eprintln!("yipctl: unknown command '{unknown}'");
                eprintln!("See 'yipctl --help' for available commands.");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unknown command: {unknown}"),
                ));
            }
        }
    }

    match args.next().as_deref() {
        Some("status") => run_client_subcommand("status", args),
        Some("peers") => run_client_subcommand("peers", args),
        Some("top") => run_client_subcommand("top", args),
        Some("ping") => run_client_subcommand("ping", args),
        Some("peer") => run_client_subcommand("peer", args),
        Some("cert") => run_client_subcommand("cert", args),
        Some("--version") | Some("-V") => {
            println!("{}", banner());
            Ok(())
        }
        Some("--help") | Some("-h") => {
            print_daemon_usage();
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
        Some(arg) if arg.starts_with('-') => {
            print_daemon_usage();
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unrecognized option: {arg}"),
            ))
        }
        Some(path) => {
            let mut control_override = None;
            let mut mtu_override = None;
            while let Some(arg) = args.next() {
                if arg == "--control" || arg == "-c" {
                    let cpath = args.next().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "--control requires a socket path argument",
                        )
                    })?;
                    control_override = Some(std::path::PathBuf::from(cpath));
                } else if arg == "--mtu" {
                    let mstr = args.next().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "--mtu requires a byte count argument",
                        )
                    })?;
                    let m: u32 = mstr.parse().map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid mtu '{mstr}': must be an integer"),
                        )
                    })?;
                    if !(576..=65535).contains(&m) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid mtu '{m}': must be between 576 and 65535"),
                        ));
                    }
                    mtu_override = Some(m);
                }
            }

            let text = std::fs::read_to_string(path)?;
            let mut config = Config::parse(&text)?;
            if let Some(sock_path) = control_override {
                config.control_socket = Some(sock_path);
            }
            if let Some(mtu) = mtu_override {
                config.mtu = Some(mtu);
            }
            tunnel::run(config)
        }
        None => {
            print_daemon_usage();
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
