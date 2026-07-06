//! The yip rendezvous + blind relay server. Binds one UDP socket, drives the
//! pure `RendezvousServer` state machine, and sweeps expired registrations on a
//! read-timeout cadence. No TUN, no tunnel keys, no unsafe.
#![forbid(unsafe_code)]

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use yip_rendezvous::{decode, encode, RendezvousServer};

const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

fn main() -> std::io::Result<()> {
    let mut args = std::env::args();
    let _prog = args.next();
    let listen = match args.next().as_deref() {
        Some("--version") | Some("-V") => {
            println!("yip-rendezvous {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some(addr) => addr.to_string(),
        None => {
            eprintln!("usage: yip-rendezvous <listen-addr>   e.g. 0.0.0.0:51821");
            std::process::exit(2);
        }
    };

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
