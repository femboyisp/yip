//! The yip rendezvous + blind relay server. Binds one UDP socket, drives the
//! pure `RendezvousServer` state machine, and sweeps expired registrations on a
//! read-timeout cadence. No TUN, no tunnel keys, no unsafe.
#![forbid(unsafe_code)]

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use yip_rendezvous::{decode, encode, RendezvousServer};

const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

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
    // Network-wide anti-DPI obfuscation shared secret. Fed to
    // `yip_obf::derive_key`; when set, every inbound datagram is deobfuscated
    // (expecting `yip_obf::RDV_TYPE`) before `Message::decode`, and every
    // reply is obfuscated before `send_to`.
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
    // The derived rendezvous-layer obfuscation key, or `None` when `--obf-psk`
    // was not given (plain rendezvous path, byte-identical to before Task 4).
    let obf_key: Option<[u8; 16]> = obf_psk.map(|psk| yip_obf::derive_key(&psk));

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
                // Obf on: unwrap the rendezvous envelope first (wrong key /
                // wrong ptype ⇒ drop, fail-closed, no panic). Obf off: decode
                // the plain bytes exactly as before Task 4.
                let decoded = match obf_key {
                    Some(key) => yip_obf::deobfuscate(&key, &rx[..n]).and_then(|(pt, body)| {
                        if pt == yip_obf::RDV_TYPE {
                            decode(&body)
                        } else {
                            None
                        }
                    }),
                    None => decode(&rx[..n]),
                };
                if let Some(msg) = decoded {
                    for (dst, reply) in server.handle(src, msg, now_ms(base)) {
                        out.clear();
                        encode(&reply, &mut out);
                        let wire = match obf_key {
                            Some(key) => {
                                let pad = random_pad(OBF_PAD_MAX);
                                yip_obf::obfuscate(&key, yip_obf::RDV_TYPE, &out, pad)
                            }
                            None => out.clone(),
                        };
                        let _ = sock.send_to(&wire, dst); // best-effort; drop on error
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

#[cfg(test)]
mod obf_tests {
    use yip_rendezvous::{encode, node_id, Message};

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
