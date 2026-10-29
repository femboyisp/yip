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
            println!("  -n, --count <COUNT>     Number of probes to transmit [default: 4]");
            println!(
                "  -W, --timeout <MILLIS>  Probe response timeout in milliseconds [default: 2000]"
            );
            println!("      --json              Output raw JSON");
            println!("  -h, --help              Print help");
        }
        "trace" | "traceroute" => {
            println!("Usage: yipctl trace <PEER> [OPTIONS]");
            println!();
            println!("Trace the multi-hop path and segment latencies across the mesh.");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>  Path to yipd UNIX control socket");
            println!("      --json              Output raw JSON");
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
        "fec" => {
            println!("Usage: yipctl fec <status|set> [OPTIONS]");
            println!();
            println!("Inspect or dynamically tune Reed-Solomon Forward Error Correction (FEC).");
            println!();
            println!("Commands:");
            println!("  status                               Query FEC recovery telemetry");
            println!("  set [--preset P] [--redundancy PCT]  Update redundancy ratio & shards");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>    Path to yipd UNIX control socket");
            println!("  -p, --preset <PRESET>     Preset (off, low, adaptive, hostile, custom)");
            println!("  -r, --redundancy <PCT>    Redundancy percentage (0..100)");
            println!("      --k <SHARDS>          Data shards count (K >= 1)");
            println!("      --m <SHARDS>          Parity shards count (M)");
            println!("      --json                Output raw JSON");
            println!("  -h, --help                Print help");
        }
        "daita" => {
            println!("Usage: yipctl daita <status|set> [OPTIONS]");
            println!();
            println!("Inspect or dynamically tune DAITA traffic analysis defenses.");
            println!();
            println!("Commands:");
            println!(
                "  status                               Query padding & decoy burst telemetry"
            );
            println!("  set [--preset P] [--buckets B1,B2]   Update quantization & cover bursts");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>          Path to yipd UNIX control socket");
            println!(
                "  -p, --preset <PRESET>           Preset (off, low, balanced, max, paranoid)"
            );
            println!("      --buckets <B1,B2,...>       Quantization buckets in bytes (e.g. 256,512,1024,1420)");
            println!("      --cover-interval <MILLIS>   Decoy burst interval in ms (0 to disable)");
            println!("      --burst <COUNT>             Decoy burst packet ceiling");
            println!("      --jitter <MILLIS>           Maximum egress micro-jitter delay in ms");
            println!("      --json                      Output raw JSON");
            println!("  -h, --help                      Print help");
        }
        "routes" => {
            println!("Usage: yipctl routes [OPTIONS]");
            println!();
            println!("Display the live mesh overlay routing table and next-hop metrics.");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>  Path to yipd UNIX control socket");
            println!("      --json              Output raw JSON");
            println!("  -h, --help              Print help");
        }
        "topology" => {
            println!("Usage: yipctl topology [OPTIONS]");
            println!();
            println!("Display the interactive mesh topology graph with nodes and link categories.");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>  Path to yipd UNIX control socket");
            println!("      --json              Output raw JSON");
            println!("  -h, --help              Print help");
        }
        "split" | "split-tunnel" => {
            println!("Usage: yipctl split <status|set> [OPTIONS]");
            println!();
            println!("Inspect or dynamically tune split-tunnel routing and traffic bypass rules.");
            println!();
            println!("Commands:");
            println!(
                "  status                               Query split-tunnel policy & telemetry"
            );
            println!("  set [--enable|--disable] [--mode M]  Update bypass rules & subnets");
            println!();
            println!("Options:");
            println!("  -c, --control <SOCKET>          Path to yipd UNIX control socket");
            println!("      --enable                    Enable split-tunnel policy enforcement");
            println!("      --disable                   Disable split-tunnel policy enforcement");
            println!("  -m, --mode <MODE>               Policy mode (exclude, include)");
            println!("      --cidrs <C1,C2,...>         Comma-separated subnets (e.g. 10.0.0.0/8)");
            println!("      --domains <D1,D2,...>       Comma-separated domain suffixes");
            println!("      --apps <A1,A2,...>          Comma-separated application names");
            println!("      --json                      Output raw JSON");
            println!("  -h, --help                      Print help");
        }
        _ => {
            println!("Usage: yipctl <COMMAND> [OPTIONS]");
            println!();
            println!("Commands:");
            println!("  status    Display daemon status and summary");
            println!("  peers     List connected peers and statistics");
            println!("  routes    Display live mesh overlay routing table");
            println!("  topology  Display mesh topology graph projection");
            println!("  split     Inspect or configure split-tunnel bypass rules");
            println!("  top       Real-time ANSI telemetry dashboard");
            println!("  ping      Probe round-trip latency to a peer");
            println!("  trace     Trace multi-hop path and segment latencies across mesh");
            println!("  peer      Dynamically add or remove peers");
            println!("  fec       Query or configure dynamic Reed-Solomon FEC");
            println!("  daita     Query or configure dynamic DAITA traffic defense");
            println!("  cert      Display certificate status or trigger manual renewal");
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
    let mut preset = None;
    let mut redundancy = None;
    let mut k_shards = None;
    let mut m_shards = None;
    let mut buckets: Option<Vec<usize>> = None;
    let mut cover_interval: Option<u64> = None;
    let mut cover_burst: Option<u64> = None;
    let mut jitter: Option<u64> = None;
    let mut mode: Option<String> = None;
    let mut split_enabled: Option<bool> = None;
    let mut cidrs: Option<Vec<String>> = None;
    let mut domains: Option<Vec<String>> = None;
    let mut apps: Option<Vec<String>> = None;
    let mut ping_count = 4u32;
    let mut ping_timeout = 2000u64;
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
            "--preset" | "-p" => {
                let p = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--preset requires a preset name (off, low, adaptive, hostile)",
                    )
                })?;
                preset = Some(p);
            }
            "--redundancy" | "-r" => {
                let r = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--redundancy requires a percentage (0..100)",
                    )
                })?;
                let pct = r.parse::<u8>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid redundancy percentage: {e}"),
                    )
                })?;
                redundancy = Some(pct);
            }
            "--k" => {
                let k = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--k requires data shards count",
                    )
                })?;
                let k_val = k.parse::<usize>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid data shards: {e}"),
                    )
                })?;
                k_shards = Some(k_val);
            }
            "--m" => {
                let m = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--m requires parity shards count",
                    )
                })?;
                let m_val = m.parse::<usize>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid parity shards: {e}"),
                    )
                })?;
                m_shards = Some(m_val);
            }
            "--buckets" => {
                let s = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--buckets requires comma-separated byte sizes (e.g. 256,512,1024)",
                    )
                })?;
                let mut parsed_buckets = Vec::new();
                for part in s.split(',') {
                    let trimmed = part.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let b = trimmed.parse::<usize>().map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid bucket size '{trimmed}': {e}"),
                        )
                    })?;
                    parsed_buckets.push(b);
                }
                buckets = Some(parsed_buckets);
            }
            "--cover-interval" => {
                let s = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--cover-interval requires milliseconds (e.g. 500)",
                    )
                })?;
                let civ = s.parse::<u64>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid cover interval: {e}"),
                    )
                })?;
                cover_interval = Some(civ);
            }
            "--burst" | "--cover-burst" => {
                let s = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--burst requires packet count (e.g. 2)",
                    )
                })?;
                let b = s.parse::<u64>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid burst count: {e}"),
                    )
                })?;
                cover_burst = Some(b);
            }
            "--jitter" => {
                let s = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--jitter requires milliseconds (e.g. 2)",
                    )
                })?;
                let j = s.parse::<u64>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid jitter: {e}"),
                    )
                })?;
                jitter = Some(j);
            }
            "--mode" | "-m" => {
                let m = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--mode requires mode name (exclude, include)",
                    )
                })?;
                mode = Some(m);
            }
            "--enable" => {
                split_enabled = Some(true);
            }
            "--disable" => {
                split_enabled = Some(false);
            }
            "--cidrs" => {
                let s = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--cidrs requires comma-separated subnets (e.g. 10.0.0.0/8,192.168.0.0/16)",
                    )
                })?;
                let list = s
                    .split(',')
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty())
                    .collect();
                cidrs = Some(list);
            }
            "--domains" => {
                let s = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--domains requires comma-separated domain suffixes",
                    )
                })?;
                let list = s
                    .split(',')
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty())
                    .collect();
                domains = Some(list);
            }
            "--apps" => {
                let s = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--apps requires comma-separated application names",
                    )
                })?;
                let list = s
                    .split(',')
                    .map(|a| a.trim().to_string())
                    .filter(|a| !a.is_empty())
                    .collect();
                apps = Some(list);
            }
            "--count" | "-n" => {
                let s = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--count requires packet count (e.g. 4)",
                    )
                })?;
                let c = s.parse::<u32>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid count: {e}"),
                    )
                })?;
                ping_count = c;
            }
            "--timeout" | "-W" => {
                let s = args.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--timeout requires milliseconds (e.g. 2000)",
                    )
                })?;
                let t = s.parse::<u64>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid timeout: {e}"),
                    )
                })?;
                ping_timeout = t;
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
            control::run_cli_ping(&socket, target, ping_count, ping_timeout, json)
                .map_err(std::io::Error::other)
        }
        "trace" | "traceroute" => {
            let target = positional.first().map(|s| s.as_str()).unwrap_or("");
            control::run_cli_trace(&socket, target, json).map_err(std::io::Error::other)
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
        "fec" => {
            let action = positional.first().map(|s| s.as_str()).unwrap_or("status");
            match action {
                "status" => {
                    control::run_cli_fec_status(&socket, json).map_err(std::io::Error::other)
                }
                "set" => control::run_cli_fec_set(&socket, preset, redundancy, k_shards, m_shards)
                    .map_err(std::io::Error::other),
                other => {
                    eprintln!("Unknown fec action: {other}");
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unknown fec action: {other}"),
                    ))
                }
            }
        }
        "daita" => {
            let action = positional.first().map(|s| s.as_str()).unwrap_or("status");
            match action {
                "status" => {
                    control::run_cli_daita_status(&socket, json).map_err(std::io::Error::other)
                }
                "set" => control::run_cli_daita_set(
                    &socket,
                    preset,
                    buckets,
                    cover_interval,
                    cover_burst,
                    jitter,
                )
                .map_err(std::io::Error::other),
                other => {
                    eprintln!("Unknown daita action: {other}");
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unknown daita action: {other}"),
                    ))
                }
            }
        }
        "routes" => control::run_cli_routes(&socket, json).map_err(std::io::Error::other),
        "topology" => control::run_cli_topology(&socket, json).map_err(std::io::Error::other),
        "split" | "split-tunnel" => {
            let action = positional.first().map(|s| s.as_str()).unwrap_or("status");
            match action {
                "status" => {
                    control::run_cli_split_status(&socket, json).map_err(std::io::Error::other)
                }
                "set" => {
                    control::run_cli_split_set(&socket, split_enabled, mode, cidrs, domains, apps)
                        .map_err(std::io::Error::other)
                }
                other => {
                    eprintln!("Unknown split action: {other}");
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("unknown split action: {other}"),
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
            Some("trace") | Some("traceroute") => return run_client_subcommand("trace", args),
            Some("peer") => return run_client_subcommand("peer", args),
            Some("fec") => return run_client_subcommand("fec", args),
            Some("daita") => return run_client_subcommand("daita", args),
            Some("cert") => return run_client_subcommand("cert", args),
            Some("routes") => return run_client_subcommand("routes", args),
            Some("topology") => return run_client_subcommand("topology", args),
            Some("split") | Some("split-tunnel") => return run_client_subcommand("split", args),
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
        Some("trace") | Some("traceroute") => run_client_subcommand("trace", args),
        Some("peer") => run_client_subcommand("peer", args),
        Some("fec") => run_client_subcommand("fec", args),
        Some("daita") => run_client_subcommand("daita", args),
        Some("cert") => run_client_subcommand("cert", args),
        Some("routes") => run_client_subcommand("routes", args),
        Some("topology") => run_client_subcommand("topology", args),
        Some("split") | Some("split-tunnel") => run_client_subcommand("split", args),
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
