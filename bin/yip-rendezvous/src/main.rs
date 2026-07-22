//! The yip rendezvous + blind relay server. Binds one UDP socket, drives the
//! pure `RendezvousServer` state machine, and sweeps expired registrations on a
//! read-timeout cadence. No TUN, no tunnel keys, no unsafe.
#![forbid(unsafe_code)]

mod conn;
mod conn_tunnel;
mod reality;
mod reality_cert;
mod reality_io;
mod reality_replay;
mod tls_front;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use tls_front::RealityCfg;
use yip_rendezvous::{decode, encode, Message, RendezvousServer};

const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Recover the inbound rendezvous `Message` from a received datagram.
/// Obf on (`obf_key = Some`): deobfuscate the envelope, require the dedicated
/// `yip_obf::RDV_TYPE`, then decode — a wrong key / wrong ptype / garbage
/// datagram ⇒ `None` (fail-closed, no panic). Obf off: decode the plain bytes,
/// byte-identical to the pre-Task-4 path.
fn decode_inbound(obf_key: Option<&[u8; 16]>, dg: &[u8]) -> Option<Message> {
    match obf_key {
        Some(key) => yip_obf::deobfuscate(key, dg).and_then(|(pt, body)| {
            if pt == yip_obf::RDV_TYPE {
                decode(&body)
            } else {
                None
            }
        }),
        None => decode(dg),
    }
}

/// Serialize a reply for the wire. Obf on: wrap the encoded `Message` in an
/// `obf_key`-keyed envelope under `yip_obf::RDV_TYPE` with random padding. Obf
/// off: the plain encoding, byte-identical to before Task 4.
fn wrap_reply(obf_key: Option<&[u8; 16]>, reply: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    encode(reply, &mut out);
    match obf_key {
        Some(key) => yip_obf::obfuscate(key, yip_obf::RDV_TYPE, &out, random_pad(OBF_PAD_MAX)),
        None => out,
    }
}

/// Largest length-prefixed TLS-front frame (a Register during classification,
/// or any framed message once upgraded onto the relay tunnel) that will ever
/// be accepted. Shared by `conn`'s classifier and `conn_tunnel::drain_frames`
/// so the two paths' caps can never desync (M8).
pub(crate) const TLS_FRAME_CAP: usize = 2048;

/// Frame a rendezvous Message for the TLS byte-stream: `[u16 BE len][obf env]`.
pub(crate) fn frame_obf(obf_key: &[u8; 16], msg: &Message) -> Vec<u8> {
    let mut plain = Vec::new();
    encode(msg, &mut plain);
    let env = yip_obf::obfuscate(obf_key, yip_obf::RDV_TYPE, &plain, random_pad(OBF_PAD_MAX));
    let mut out = Vec::with_capacity(2 + env.len());
    let len = u16::try_from(env.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&env);
    out
}

/// Maximum random padding (bytes) added to an obfuscated rendezvous-message
/// envelope. Rendezvous messages are small control/relay datagrams, so a
/// modest cap (mirrors `yipd`'s `OBF_DATA_PAD_MAX`) is enough to break any
/// fixed-size fingerprint without materially inflating the wire size.
const OBF_PAD_MAX: usize = 64;

/// A uniformly-random padding length in `0..=max`, drawn from the OS RNG.
/// `max == 0` ⇒ `0` (no `getrandom` call). No numeric `as` casts.
fn random_pad(max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("OS RNG");
    let v = u64::from_le_bytes(b);
    let span = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    usize::try_from(v % span).unwrap_or(0)
}

/// Decode a 64-char hex string into 32 bytes (`--obf-psk <hex64>`). Kept
/// local to this binary rather than shared with `yipd::config::hex_to_32`
/// since the two live in separate crates; feeds `yip_obf::derive_key` for
/// wrap/unwrap of the rendezvous-message layer (Task 4).
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

/// Decode a 16-char hex string into 8 bytes (`--reality-short-id <hex16>`).
/// Mirrors `hex_to_32` at a shorter width (REALITY short IDs are 8 bytes).
fn hex_to_8(hex: &str) -> Result<[u8; 8], String> {
    if hex.len() != 16 {
        return Err(format!("expected 16 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 8];
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

/// If `port` is a canonical VPN/tunnel default port that DPI port-matches,
/// return the protocol it makes the relay look like; `None` for a plausible
/// port. Mirrors `yipd::config::fingerprinted_vpn_port` — kept local to this
/// binary rather than shared with `yipd` since the two live in separate
/// crates (same rationale as `hex_to_32` above). Used to warn (not reject) at
/// startup — anti-DPI R8 (#45).
fn fingerprinted_vpn_port(port: u16) -> Option<&'static str> {
    match port {
        51820 => Some("WireGuard"),
        1194 => Some("OpenVPN"),
        500 | 4500 => Some("IPsec/IKE"),
        1701 => Some("L2TP"),
        1723 => Some("PPTP"),
        655 => Some("tinc"),
        _ => None,
    }
}

/// The anti-DPI startup warning for a fingerprinted VPN listen `port`, or `None`
/// for a plausible port. Kept a pure function (rather than inlining the
/// `format!` in `main`) so the message construction is unit-testable; `main`
/// only prints what this returns.
fn vpn_port_warning(port: u16) -> Option<String> {
    fingerprinted_vpn_port(port).map(|proto| {
        format!(
            "yip-rendezvous: listen port {port} is {proto}'s default; DPI classifies the relay's \
             UDP traffic as {proto} by port — prefer a neutral/plausible port (anti-DPI R8)"
        )
    })
}

fn usage_exit() -> ! {
    eprintln!(
        "usage: yip-rendezvous <listen-addr> [--obf-psk <hex64>] \
         [--listen-tcp <addr> [--tls-cert <path> --tls-key <path>] [--decoy <addr>] \
         [--reality-dest <host:port> --reality-private-key <hex64> \
         [--reality-short-id <hex16>]... [--reality-server-name <name>]... \
         [--reality-cert-refresh-secs <secs>] [--reality-cert-max-stale-secs <secs>] \
         [--reality-replay-max-bucket <n>] [--reality-max-inflight <n>]]]\n\
         (--reality-dest supersedes --decoy when both are set; --tls-cert/--tls-key are \
         optional when --reality-dest is set — REALITY forges its own per-SNI cert)\n\
         e.g. 0.0.0.0:51821"
    );
    std::process::exit(2);
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args();
    let _prog = args.next();

    let mut listen: Option<String> = None;
    // Network-wide anti-DPI obfuscation shared secret. Fed to
    // `yip_obf::derive_key`; when set, every inbound datagram is deobfuscated
    // (expecting `yip_obf::RDV_TYPE`) before `Message::decode`, and every
    // reply is obfuscated before `send_to`.
    let mut obf_psk: Option<[u8; 32]> = None;
    // TCP/TLS Trojan front (3c.3), all opt-in via `--listen-tcp`.
    let mut listen_tcp: Option<String> = None;
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut decoy: Option<String> = None;
    // REALITY anti-probe front (REALITY.1 Task 4), all opt-in via
    // --reality-dest.
    let mut reality_dest: Option<String> = None;
    let mut reality_priv_key: Option<[u8; 32]> = None;
    let mut reality_short_ids: Vec<[u8; 8]> = Vec::new();
    let mut reality_server_names: Vec<String> = Vec::new();
    // REALITY.3 cert-cache / replay-guard tuning (Task 8), all optional with
    // spec-default values.
    let mut reality_cert_refresh_secs: u64 = 3600;
    let mut reality_cert_max_stale_secs: u64 = 21600;
    let mut reality_replay_max_bucket: usize = 16384;
    let mut reality_max_inflight: usize = 1024;

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
            "--listen-tcp" => {
                let Some(v) = args.next() else {
                    eprintln!("--listen-tcp requires an address argument");
                    std::process::exit(2);
                };
                listen_tcp = Some(v);
            }
            "--tls-cert" => {
                let Some(v) = args.next() else {
                    eprintln!("--tls-cert requires a path argument");
                    std::process::exit(2);
                };
                tls_cert = Some(v);
            }
            "--tls-key" => {
                let Some(v) = args.next() else {
                    eprintln!("--tls-key requires a path argument");
                    std::process::exit(2);
                };
                tls_key = Some(v);
            }
            "--decoy" => {
                let Some(v) = args.next() else {
                    eprintln!("--decoy requires an address argument");
                    std::process::exit(2);
                };
                decoy = Some(v);
            }
            "--reality-dest" => {
                let Some(v) = args.next() else {
                    eprintln!("--reality-dest requires a host:port argument");
                    std::process::exit(2);
                };
                reality_dest = Some(v);
            }
            "--reality-private-key" => {
                let Some(hex) = args.next() else {
                    eprintln!("--reality-private-key requires a 64-char hex argument");
                    std::process::exit(2);
                };
                match hex_to_32(&hex) {
                    Ok(key) => reality_priv_key = Some(key),
                    Err(e) => {
                        eprintln!("invalid --reality-private-key: {e}");
                        std::process::exit(2);
                    }
                }
            }
            "--reality-short-id" => {
                let Some(hex) = args.next() else {
                    eprintln!("--reality-short-id requires a 16-char hex argument");
                    std::process::exit(2);
                };
                match hex_to_8(&hex) {
                    Ok(id) => reality_short_ids.push(id),
                    Err(e) => {
                        eprintln!("invalid --reality-short-id: {e}");
                        std::process::exit(2);
                    }
                }
            }
            "--reality-server-name" => {
                let Some(v) = args.next() else {
                    eprintln!("--reality-server-name requires a name argument");
                    std::process::exit(2);
                };
                reality_server_names.push(v);
            }
            "--reality-cert-refresh-secs" => {
                let Some(v) = args.next() else {
                    eprintln!("--reality-cert-refresh-secs requires a seconds argument");
                    std::process::exit(2);
                };
                reality_cert_refresh_secs = v.parse().unwrap_or_else(|e| {
                    eprintln!("invalid --reality-cert-refresh-secs: {e}");
                    std::process::exit(2);
                });
            }
            "--reality-cert-max-stale-secs" => {
                let Some(v) = args.next() else {
                    eprintln!("--reality-cert-max-stale-secs requires a seconds argument");
                    std::process::exit(2);
                };
                reality_cert_max_stale_secs = v.parse().unwrap_or_else(|e| {
                    eprintln!("invalid --reality-cert-max-stale-secs: {e}");
                    std::process::exit(2);
                });
            }
            "--reality-replay-max-bucket" => {
                let Some(v) = args.next() else {
                    eprintln!("--reality-replay-max-bucket requires a count argument");
                    std::process::exit(2);
                };
                reality_replay_max_bucket = v.parse().unwrap_or_else(|e| {
                    eprintln!("invalid --reality-replay-max-bucket: {e}");
                    std::process::exit(2);
                });
            }
            "--reality-max-inflight" => {
                let Some(v) = args.next() else {
                    eprintln!("--reality-max-inflight requires a count argument");
                    std::process::exit(2);
                };
                reality_max_inflight = v.parse().unwrap_or_else(|e| {
                    eprintln!("invalid --reality-max-inflight: {e}");
                    std::process::exit(2);
                });
            }
            _ if listen.is_none() => listen = Some(arg),
            other => {
                eprintln!("unexpected argument: {other}");
                usage_exit();
            }
        }
    }

    let listen = listen.unwrap_or_else(|| usage_exit());
    if let Ok(sa) = listen.parse::<std::net::SocketAddr>() {
        if let Some(w) = vpn_port_warning(sa.port()) {
            eprintln!("{w}");
        }
    }
    // The derived rendezvous-layer obfuscation key, or `None` when `--obf-psk`
    // was not given (plain rendezvous path, byte-identical to before Task 4).
    let obf_key: Option<[u8; 16]> = obf_psk.map(|psk| yip_obf::derive_key(&psk));
    let decoy_addr: Option<SocketAddr> = match decoy {
        Some(ref d) => match d.parse() {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("invalid --decoy address: {e}");
                std::process::exit(2);
            }
        },
        None => None,
    };
    // Pure flag-combo validation, before any network I/O (Task 8 review
    // reorder — a misconfigured REALITY setup must fail fast, not after the
    // ~10s `prewarm` dial below). REALITY runs on the TCP front (the authed
    // branch terminates TLS there), so `--reality-dest` without
    // `--listen-tcp` would be silently ignored — reject it up front.
    if reality_dest.is_some() && listen_tcp.is_none() {
        eprintln!("--reality-dest requires --listen-tcp (REALITY runs on the TCP front)");
        std::process::exit(2);
    }

    // REALITY config: presence of --reality-dest enables it. --reality-dest
    // supersedes --decoy at runtime (tls_front branches on cfg.reality first),
    // so accepting both flags together is harmless.
    let reality_cfg: Option<RealityCfg> = match reality_dest {
        Some(ref d) => {
            let dest: SocketAddr = d.parse().unwrap_or_else(|e| {
                eprintln!("invalid --reality-dest address: {e}");
                std::process::exit(2);
            });
            let Some(priv_key) = reality_priv_key else {
                eprintln!("--reality-dest requires --reality-private-key");
                std::process::exit(2);
            };
            let refresh = Duration::from_secs(reality_cert_refresh_secs);
            let max_stale = Duration::from_secs(reality_cert_max_stale_secs);
            let fetch_timeout = Duration::from_secs(10);
            let certs = reality_cert::RealityCertCache::prewarm(
                &reality_server_names,
                dest,
                refresh,
                max_stale,
                fetch_timeout,
            )
            .await
            .unwrap_or_else(|e| {
                eprintln!("fatal: {e}");
                std::process::exit(1);
            });
            // Start the background refresh now, before `certs` moves into
            // `RealityCfg` — `spawn_refresh` takes `&Arc<Self>`.
            certs.spawn_refresh(dest, refresh, max_stale, fetch_timeout);
            let start_min = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() / 60)
                .unwrap_or(0);
            let replay = Arc::new(reality_replay::ReplayGuard::new(
                start_min,
                reality_replay_max_bucket,
            ));
            Some(RealityCfg {
                dest,
                priv_key,
                short_ids: reality_short_ids,
                server_names: reality_server_names,
                certs,
                replay,
            })
        }
        None => None,
    };

    // No short-ids ⇒ no client can ever authenticate, so the relay forwards EVERY
    // connection to dest (a pure, correct front, but likely a misconfiguration if
    // the operator meant to serve a tunnel). Warn rather than fail — this is a
    // valid "decoy-only" mode (review M-3).
    if reality_cfg.as_ref().is_some_and(|c| c.short_ids.is_empty()) {
        eprintln!(
            "warning: --reality-dest set with no --reality-short-id; no client can \
             authenticate — every connection will be forwarded to the dest"
        );
    }

    // Millisecond clock from a monotonic base (Instant), so `now_ms` never goes
    // backwards and needs no wall clock.
    let base = Instant::now();
    let server = Arc::new(Mutex::new(RendezvousServer::new(0)));

    let sock = tokio::net::UdpSocket::bind(&listen).await?;
    eprintln!("yip-rendezvous listening on {listen} (udp)");

    // TLS Trojan front (3c.3): opt-in via --listen-tcp. Requires --obf-psk
    // (as the discriminator) always. --tls-cert/--tls-key are required for
    // the non-REALITY Trojan front, but optional under REALITY.3: the authed
    // branch (`run_reality_conn`) never uses this generic `acceptor` at all —
    // it builds its own per-SNI forged acceptor from `RealityCfg::certs` — so
    // this acceptor only backstops the (never-taken under REALITY) plain
    // `tokio_boring::accept(&acceptor, ..)` fallback in `run_tls_front`, and a
    // throwaway self-signed cert is fine for that.
    if let Some(tcp_addr) = listen_tcp {
        let Some(obf_key) = obf_key else {
            eprintln!("--listen-tcp requires --obf-psk (it is the tunnel discriminator)");
            std::process::exit(2);
        };
        let acceptor = match (tls_cert.as_deref(), tls_key.as_deref()) {
            (Some(cert), Some(key)) => tls_front::build_acceptor(cert, key).unwrap_or_else(|e| {
                eprintln!("tls cert/key error: {e}");
                std::process::exit(2);
            }),
            _ if reality_cfg.is_some() => {
                tls_front::build_throwaway_acceptor().unwrap_or_else(|e| {
                    eprintln!("failed to build throwaway TLS acceptor: {e}");
                    std::process::exit(1);
                })
            }
            _ => {
                eprintln!("--listen-tcp requires --tls-cert and --tls-key");
                std::process::exit(2);
            }
        };
        let acceptor = Arc::new(acceptor);
        let tcp = tokio::net::TcpListener::bind(&tcp_addr).await?;
        eprintln!("yip-rendezvous TLS front listening on {tcp_addr} (tcp)");
        // One-time (off the hot path): clone the shared forward-count handle
        // so the TLS front bumps the counter lock-free per frame (#68).
        let forwarded = server.lock().await.forwarded_handle();
        let cfg = Arc::new(tls_front::TlsFrontCfg {
            server: Arc::clone(&server),
            obf_key,
            decoy: decoy_addr,
            base,
            routes: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // REALITY.1 Task 4: wired from --reality-*; None keeps the 3c.3
            // Trojan front's behavior byte-identical.
            reality: reality_cfg,
            max_conns: reality_max_inflight,
            forwarded,
        });
        tokio::spawn(tls_front::run_tls_front(tcp, acceptor, cfg));
    }

    run_udp(sock, Arc::clone(&server), obf_key, base).await
}

/// The UDP rendezvous task: recover a Message, drive the shared state machine,
/// send replies. Sweeps on a 5 s interval. Behavior-identical to the previous
/// blocking loop.
async fn run_udp(
    sock: tokio::net::UdpSocket,
    server: Arc<Mutex<RendezvousServer>>,
    obf_key: Option<[u8; 16]>,
    base: Instant,
) -> std::io::Result<()> {
    let now_ms =
        |base: Instant| -> u64 { u64::try_from(base.elapsed().as_millis()).unwrap_or(u64::MAX) };
    let mut rx = [0u8; 2048];
    let mut sweep =
        tokio::time::interval_at(tokio::time::Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
    loop {
        tokio::select! {
            r = sock.recv_from(&mut rx) => {
                let (n, src) = r?;
                // Obf on: unwrap the rendezvous envelope first (wrong key /
                // wrong ptype ⇒ drop, fail-closed, no panic). Obf off: decode
                // the plain bytes exactly as before Task 4.
                if let Some(msg) = decode_inbound(obf_key.as_ref(), &rx[..n]) {
                    let replies = {
                        let mut s = server.lock().await;
                        s.handle(src, msg, now_ms(base))
                    };
                    for (dst, reply) in replies {
                        let wire = wrap_reply(obf_key.as_ref(), &reply);
                        let _ = sock.send_to(&wire, dst).await; // best-effort; drop on error
                    }
                }
            }
            _ = sweep.tick() => {
                let mut s = server.lock().await;
                s.sweep(now_ms(base));
                // Lets the netns money tests (and operators) grep stderr for the
                // final relay-forward count to assert *which path* carried
                // traffic, without needing any extra IPC/metrics surface.
                eprintln!("relay-forwarded={}", s.forwarded_count());
            }
        }
    }
}

#[cfg(test)]
mod port_lint_tests {
    use super::{fingerprinted_vpn_port, vpn_port_warning};

    /// Known VPN default ports are flagged with their protocol name; a
    /// plausible/neutral port (including the rendezvous crate's own example
    /// port, 51821) is not — mirrors `yipd::config::fingerprinted_vpn_ports_are_flagged`.
    #[test]
    fn fingerprinted_vpn_ports_are_flagged() {
        assert_eq!(fingerprinted_vpn_port(51820), Some("WireGuard"));
        assert_eq!(fingerprinted_vpn_port(1194), Some("OpenVPN"));
        assert_eq!(fingerprinted_vpn_port(500), Some("IPsec/IKE"));
        assert_eq!(fingerprinted_vpn_port(4500), Some("IPsec/IKE"));
        assert_eq!(fingerprinted_vpn_port(1701), Some("L2TP"));
        assert_eq!(fingerprinted_vpn_port(1723), Some("PPTP"));
        assert_eq!(fingerprinted_vpn_port(655), Some("tinc"));
        assert_eq!(fingerprinted_vpn_port(51821), None);
        assert_eq!(fingerprinted_vpn_port(443), None);
    }

    /// A fingerprinted port yields a warning naming both the port and the
    /// protocol it looks like; a plausible port yields no warning.
    #[test]
    fn vpn_port_warning_names_port_and_protocol() {
        let w = vpn_port_warning(51820).expect("51820 must warn");
        assert!(w.contains("51820"), "warning names the port: {w}");
        assert!(w.contains("WireGuard"), "warning names the protocol: {w}");
        assert_eq!(vpn_port_warning(443), None);
    }
}

#[cfg(test)]
mod cli_tests {
    use super::hex_to_8;

    /// A valid 16-char hex string decodes to the expected 8 bytes.
    #[test]
    fn hex_to_8_valid() {
        assert_eq!(
            hex_to_8("0123456789abcdef"),
            Ok([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
        );
    }

    /// Wrong-length input (too short / too long) is rejected.
    #[test]
    fn hex_to_8_wrong_length() {
        assert!(hex_to_8("0123456789abcde").is_err()); // 15 chars
        assert!(hex_to_8("0123456789abcdef00").is_err()); // 18 chars
    }

    /// Non-hex characters are rejected.
    #[test]
    fn hex_to_8_non_hex() {
        assert!(hex_to_8("012345678zabcdef").is_err());
    }
}

#[cfg(test)]
mod obf_tests {
    use super::{decode_inbound, wrap_reply};
    use yip_rendezvous::{encode, node_id, Message};

    /// `wrap_reply` + `decode_inbound` round-trip a Message, obf ON: the wire
    /// bytes are obfuscated (not the plain encoding) yet recover exactly.
    #[test]
    fn wrap_and_decode_round_trip_obf_on() {
        let key = yip_obf::derive_key(&[3u8; 32]);
        let msg = Message::Lookup {
            node: node_id(&[8u8; 32]),
        };
        let mut plain = Vec::new();
        encode(&msg, &mut plain);

        let wire = wrap_reply(Some(&key), &msg);
        assert_ne!(
            wire, plain,
            "obf-on wire bytes must not be the plain encoding"
        );
        assert_eq!(
            decode_inbound(Some(&key), &wire),
            Some(msg),
            "obf-on round-trip recovers the Message"
        );
    }

    /// Obf OFF: `wrap_reply` is the plain encoding and `decode_inbound` decodes
    /// plain bytes — byte-identical to the pre-Task-4 path.
    #[test]
    fn wrap_and_decode_plain_obf_off() {
        let msg = Message::Register {
            node: node_id(&[4u8; 32]),
            counter: 1,
        };
        let mut plain = Vec::new();
        encode(&msg, &mut plain);

        assert_eq!(
            wrap_reply(None, &msg),
            plain,
            "obf-off wire == plain encoding"
        );
        assert_eq!(decode_inbound(None, &plain), Some(msg));
    }

    /// Fail-closed: obf ON, a wrong key or a plain (unwrapped) datagram must
    /// NOT decode (dropped, no panic).
    #[test]
    fn decode_inbound_fails_closed_on_wrong_key_and_plaintext() {
        let key = yip_obf::derive_key(&[5u8; 32]);
        let wrong = yip_obf::derive_key(&[6u8; 32]);
        let msg = Message::Lookup {
            node: node_id(&[9u8; 32]),
        };
        let wire = wrap_reply(Some(&key), &msg);
        assert_ne!(
            decode_inbound(Some(&wrong), &wire),
            Some(msg.clone()),
            "a wrong key must not recover the Message"
        );
        let mut plain = Vec::new();
        encode(&msg, &mut plain);
        // A plaintext datagram fed to the obf-on path is not a valid RDV
        // envelope for this key ⇒ it must not recover the original Message
        // (it unmasks to garbage under the key, then fails the RDV_TYPE/decode).
        assert_ne!(decode_inbound(Some(&key), &plain), Some(msg));
    }

    /// `obfuscate` a `Lookup`, `deobfuscate` + `Message::decode` recovers it
    /// exactly, under the dedicated `yip_obf::RDV_TYPE`.
    #[test]
    fn lookup_round_trips_through_obf_envelope() {
        let key = yip_obf::derive_key(&[7u8; 32]);
        let node = node_id(&[1u8; 32]);
        let msg = Message::Lookup { node };
        let mut plain = Vec::new();
        encode(&msg, &mut plain);

        let wrapped = yip_obf::obfuscate(&key, yip_obf::RDV_TYPE, &plain, 12);
        let (ptype, body) = yip_obf::deobfuscate(&key, &wrapped).expect("round-trips");
        assert_eq!(ptype, yip_obf::RDV_TYPE);
        assert_eq!(
            yip_rendezvous::decode(&body),
            Some(msg),
            "decoded Lookup must match the original"
        );
    }

    /// A `RelaySend` payload rides inside the envelope verbatim: it is not
    /// touched by the obf layer, only carried and recovered byte-for-byte.
    #[test]
    fn relay_send_payload_preserved_verbatim() {
        let key = yip_obf::derive_key(&[9u8; 32]);
        let src = node_id(&[2u8; 32]);
        let dst = node_id(&[3u8; 32]);
        let payload = vec![1, 2, 3, 4, 5, 250, 251, 252];
        let msg = Message::RelaySend {
            src,
            dst,
            payload: payload.clone(),
        };
        let mut plain = Vec::new();
        encode(&msg, &mut plain);

        let wrapped = yip_obf::obfuscate(&key, yip_obf::RDV_TYPE, &plain, 0);
        let (ptype, body) = yip_obf::deobfuscate(&key, &wrapped).expect("round-trips");
        assert_eq!(ptype, yip_obf::RDV_TYPE);
        match yip_rendezvous::decode(&body) {
            Some(Message::RelaySend {
                src: s,
                dst: d,
                payload: p,
            }) => {
                assert_eq!(s, src);
                assert_eq!(d, dst);
                assert_eq!(p, payload, "relay payload must survive verbatim");
            }
            other => panic!("expected RelaySend, got {other:?}"),
        }
    }

    /// The wrong key must not recover the original message: `deobfuscate`
    /// either fails outright or yields bytes that do not decode back to the
    /// same `Lookup` — never a false recovery.
    #[test]
    fn wrong_key_does_not_recover_message() {
        let k1 = yip_obf::derive_key(&[1u8; 32]);
        let k2 = yip_obf::derive_key(&[2u8; 32]);
        let node = node_id(&[4u8; 32]);
        let msg = Message::Lookup { node };
        let mut plain = Vec::new();
        encode(&msg, &mut plain);

        let wrapped = yip_obf::obfuscate(&k1, yip_obf::RDV_TYPE, &plain, 8);
        match yip_obf::deobfuscate(&k2, &wrapped) {
            None => {}
            Some((ptype, body)) => {
                let recovered = (ptype == yip_obf::RDV_TYPE)
                    .then(|| yip_rendezvous::decode(&body))
                    .flatten();
                assert_ne!(
                    recovered,
                    Some(msg),
                    "wrong key must not recover the original Lookup"
                );
            }
        }
    }

    /// The anti-DPI property at the message layer: obfuscating the same
    /// `Lookup` many times must not leave any byte offset constant — no
    /// fixed-size/fixed-byte fingerprint for a censor to key on.
    #[test]
    fn no_byte_position_is_constant_across_wrapped_lookups() {
        let key = yip_obf::derive_key(&[5u8; 32]);
        let node = node_id(&[6u8; 32]);
        let mut plain = Vec::new();
        encode(&Message::Lookup { node }, &mut plain);

        let n = 512usize;
        let dgs: Vec<Vec<u8>> = (0..n)
            .map(|_| yip_obf::obfuscate(&key, yip_obf::RDV_TYPE, &plain, 4))
            .collect();
        let len = dgs[0].len();
        for pos in 0..len {
            let first = dgs[0][pos];
            let all_same = dgs.iter().all(|d| d.len() == len && d[pos] == first);
            assert!(
                !all_same,
                "byte position {pos} is constant across wrapped Lookups — a DPI signature"
            );
        }
    }
}
