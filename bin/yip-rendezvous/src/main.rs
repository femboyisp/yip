//! The yip rendezvous + blind relay server. Binds one UDP socket, drives the
//! pure `RendezvousServer` state machine, and sweeps expired registrations on a
//! read-timeout cadence. No TUN, no tunnel keys, no unsafe.
#![forbid(unsafe_code)]

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use yip_rendezvous::{decode, encode, RendezvousServer};

const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Decode a 64-char hex string into 32 bytes (`--obf-psk <hex64>`). Kept
/// local to this binary rather than shared with `yipd::config::hex_to_32`
/// since the two live in separate crates; Task 4 wires the decoded PSK into
/// `yip_obf::derive_key` for wrap/unwrap of relayed datagrams.
fn hex_to_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", b as char)),
    }
}

fn usage_exit() -> ! {
    eprintln!("usage: yip-rendezvous <listen-addr> [--obf-psk <hex64>]   e.g. 0.0.0.0:51821");
    std::process::exit(2);
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args();
    let _prog = args.next();

    let mut listen: Option<String> = None;
    // Network-wide anti-DPI obfuscation shared secret. Only parsed here —
    // Task 4 feeds it to `yip_obf::derive_key` and wraps/unwraps relayed
    // datagrams with it; no obfuscation behavior yet.
    let mut obf_psk: Option<[u8; 32]> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("yip-rendezvous {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--obf-psk" => {
                let Some(hex) = args.next() else {
                    eprintln!("--obf-psk requires a 64-char hex argument");
                    std::process::exit(2);
                };
                match hex_to_32(&hex) {
                    Ok(psk) => obf_psk = Some(psk),
                    Err(e) => {
                        eprintln!("invalid --obf-psk: {e}");
                        std::process::exit(2);
                    }
                }
            }
            _ if listen.is_none() => listen = Some(arg),
            other => {
                eprintln!("unexpected argument: {other}");
                usage_exit();
            }
        }
    }

    let listen = listen.unwrap_or_else(|| usage_exit());
    // Stored for Task 4's wrap/unwrap wiring; no behavior yet this task.
    let _ = &obf_psk;

    let sock = UdpSocket::bind(&listen)?;
    sock.set_read_timeout(Some(SWEEP_INTERVAL))?;
    eprintln!("yip-rendezvous listening on {listen}");

    // Millisecond clock from a monotonic base (Instant), so `now_ms` never goes
    // backwards and needs no wall clock.
    let base = Instant::now();
    let now_ms =
        |base: Instant| -> u64 { u64::try_from(base.elapsed().as_millis()).unwrap_or(u64::MAX) };

    let mut server = RendezvousServer::new(now_ms(base));
    let mut last_sweep = Instant::now();
    let mut rx = [0u8; 2048];
    let mut out = Vec::new();

    loop {
        match sock.recv_from(&mut rx) {
            Ok((n, src)) => {
                if let Some(msg) = decode(&rx[..n]) {
                    for (dst, reply) in server.handle(src, msg, now_ms(base)) {
                        out.clear();
                        encode(&reply, &mut out);
                        let _ = sock.send_to(&out, dst); // best-effort; drop on error
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }
        if last_sweep.elapsed() >= SWEEP_INTERVAL {
            server.sweep(now_ms(base));
            last_sweep = Instant::now();
            // Lets the netns money tests (and operators) grep stderr for the
            // final relay-forward count to assert *which path* carried
            // traffic, without needing any extra IPC/metrics surface.
            eprintln!("relay-forwarded={}", server.forwarded_count());
        }
    }
}
