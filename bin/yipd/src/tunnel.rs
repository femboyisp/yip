//! The yipd tunnel: binds a UDP socket, runs the Noise-IK handshake, creates
//! the TUN device, then drives the two data loops (egress and ingress) that
//! move packets between the device and the network.
//!
//! # conn_tag
//!
//! Each wire frame carries an 8-byte `conn_tag` that the receiver uses to
//! select the right session / decoder. For M6 we derive it from the first 8
//! bytes of the Noise channel binding (which both peers compute identically
//! after the handshake, so both will use the same tag). This is a placeholder:
//! M7+ will rotate the tag every epoch for unlinkability.

use std::io;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use yip_device::{DeviceKind, TunTap};
use yip_transport::Transport;
use yip_wire::{Codec, WireCodec};

use crate::config::Config;
use crate::handshake::{self, PacketType};
use crate::wire_glue;

// Maximum UDP datagram we ever allocate for recv.
const MAX_DATAGRAM: usize = 65_535;

// ── conn_tag derivation ───────────────────────────────────────────────────────

/// Derive the per-session `conn_tag` from the first 8 bytes of the Noise
/// channel binding. Both peers compute the same binding after a successful
/// handshake, so they end up with the same tag without any extra signaling.
///
/// M7 will rotate this every ~120 s epoch for unlinkability.
fn conn_tag_from_cb(channel_binding: &[u8; 32]) -> u64 {
    u64::from_be_bytes(channel_binding[..8].try_into().expect("8 bytes"))
}

// ── public entry point ────────────────────────────────────────────────────────

/// Run the tunnel: bind, handshake, create TUN, loop forever (or until an I/O
/// error terminates one of the two threads).
///
/// Blocks until both threads exit. In practice this function only returns on a
/// fatal I/O error.
pub fn run(config: Config) -> io::Result<()> {
    // ── bind the UDP socket ───────────────────────────────────────────────────
    let sock = UdpSocket::bind(config.listen)?;

    // ── handshake ─────────────────────────────────────────────────────────────
    let (established, peer_addr) = if config.initiate {
        let est = handshake::run_initiator(
            &sock,
            config.peer_endpoint,
            &config.local_private,
            &config.peer_public,
        )?;
        (est, config.peer_endpoint)
    } else {
        let (est, addr) = handshake::run_responder(&sock, &config.local_private)?;
        (est, addr)
    };

    // Connect the socket so plain send/recv work on both threads without
    // carrying the peer address on every call.
    sock.connect(peer_addr)?;

    let cb = {
        // We need the channel binding to derive conn_tag; it was consumed during
        // the handshake. Re-derive it from auth_key||hp_key (both are 16-byte
        // sub-slices of the same BLAKE2s digest of the channel binding, so we
        // cannot recover the full CB here without re-exposing it from Established).
        //
        // Instead we expose a stable tag from the auth_key: the first 8 bytes
        // uniquely identify the session and are already derived from the CB.
        // Both peers hold the same auth_key, so both derive the same conn_tag.
        let mut combined = [0u8; 32];
        combined[..16].copy_from_slice(&established.auth_key);
        combined[16..].copy_from_slice(&established.hp_key);
        combined
    };
    let conn_tag = conn_tag_from_cb(&cb);

    // ── build shared state ────────────────────────────────────────────────────
    let codec = Codec::new(established.auth_key, established.hp_key);
    let session = Arc::new(Mutex::new(established.session));
    let transport = Arc::new(Mutex::new(Transport::new(vec![])));

    // ── create + split the TUN device ────────────────────────────────────────
    let tun = TunTap::create(&config.device, DeviceKind::Tun).map_err(io::Error::other)?;
    let (mut tun_reader, mut tun_writer) = tun.split().map_err(io::Error::other)?;

    // ── clone sockets for the two threads ────────────────────────────────────
    let udp_tx = sock.try_clone()?;
    let udp_rx = sock;

    // ── shared codec (immutable, so Arc<> rather than Mutex<>) ───────────────
    let codec = Arc::new(codec);
    let codec_tx = Arc::clone(&codec);
    let codec_rx = codec;

    // ── egress thread: TUN → UDP ──────────────────────────────────────────────
    let session_tx = Arc::clone(&session);
    let transport_tx = Arc::clone(&transport);

    let egress = std::thread::Builder::new()
        .name("yipd-egress".into())
        .spawn(move || -> io::Result<()> {
            let start = Instant::now();
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                // Read one inner frame from the TUN device.
                let n = tun_reader.read_frame(&mut buf)?;
                let inner = &buf[..n];

                let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

                // Seal the inner frame with AEAD.
                let sealed = session_tx
                    .lock()
                    .expect("session lock poisoned")
                    .seal(inner)
                    .map_err(io::Error::other)?;

                // FEC-encode the sealed ciphertext.
                let (class, symbols) = transport_tx
                    .lock()
                    .expect("transport lock poisoned")
                    .encode(&sealed.ciphertext, inner, false, now_ms);

                // Emit one UDP datagram per FEC symbol.
                for sym in &symbols {
                    let frame = wire_glue::symbol_to_frame(conn_tag, sym, sealed.counter, class);
                    let dg = codec_tx.frame(&frame);
                    let mut out = Vec::with_capacity(1 + dg.len());
                    out.push(PacketType::Data as u8);
                    out.extend_from_slice(&dg);
                    // A transient send error (e.g. ENOBUFS) is logged but does
                    // not terminate the egress loop; the packet is simply dropped.
                    if let Err(e) = udp_tx.send(&out) {
                        eprintln!("yipd egress: send error: {e}");
                    }
                }
            }
        })?;

    // ── ingress thread: UDP → TUN ─────────────────────────────────────────────
    let session_rx = Arc::clone(&session);
    let transport_rx = Arc::clone(&transport);

    let ingress = std::thread::Builder::new()
        .name("yipd-ingress".into())
        .spawn(move || -> io::Result<()> {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let n = udp_rx.recv(&mut buf)?;
                let dg = &buf[..n];

                // Validate and strip the 1-byte packet type prefix.
                if dg.is_empty() || dg[0] != PacketType::Data as u8 {
                    continue;
                }
                let wire = &dg[1..];

                // Deframe (auth + header-deprotect). On failure, drop the
                // packet without killing the loop.
                let frame = match codec_rx.deframe(wire) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("yipd ingress: deframe error: {e}");
                        continue;
                    }
                };

                // Parse the FEC symbol + counter out of the frame.
                let (sym, counter, class) = match wire_glue::frame_to_symbol(&frame) {
                    Some(t) => t,
                    None => {
                        eprintln!("yipd ingress: frame_to_symbol returned None (short payload)");
                        continue;
                    }
                };

                // Feed the symbol to the FEC reassembler; continue until an
                // object decodes.
                let ciphertext = match transport_rx
                    .lock()
                    .expect("transport lock poisoned")
                    .decode(&sym, class)
                {
                    Some(ct) => ct,
                    None => continue,
                };

                // Open the AEAD ciphertext. Replay / AEAD failures are logged
                // and the packet is dropped.
                let inner = match session_rx
                    .lock()
                    .expect("session lock poisoned")
                    .open(counter, &ciphertext)
                {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("yipd ingress: open error: {e}");
                        continue;
                    }
                };

                // Inject the plaintext inner frame into the TUN device.
                // An I/O error here is fatal (device gone).
                tun_writer.write_frame(&inner)?;
            }
        })?;

    // Block until both threads finish.  In practice this only happens when a
    // fatal I/O error (device gone, socket closed) terminates one of them.
    let egress_result = egress
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("egress thread panicked")));
    let ingress_result = ingress
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("ingress thread panicked")));

    // Report the first error, if any.
    egress_result.and(ingress_result)
}
