//! Noise-IK handshake over UDP for the yip daemon.
//!
//! Each datagram is prefixed with a 1-byte [`PacketType`] discriminant.
//! **Pre-obfuscation note:** these fixed prefixes are detectable by DPI;
//! sub-project #3 replaces them with randomised header protection so the
//! wire carries no fixed magic bytes.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use yip_crypto::{CryptoError, Handshake, Session};

use crate::wire_glue::derive_wire_keys;

// ── packet type prefix ────────────────────────────────────────────────────────

/// 1-byte datagram prefix that identifies the role of each UDP packet.
///
/// **Pre-obfuscation:** these are fixed magic values; sub-project #3 will
/// replace them with randomised header protection so no fixed prefix appears
/// on the wire.
#[repr(u8)]
pub enum PacketType {
    /// First Noise message (initiator → responder).
    HandshakeInit = 0,
    /// Second Noise message (responder → initiator).
    HandshakeResp = 1,
    /// Data-plane packet (used by later tunnel tasks).
    Data = 2,
}

// ── established session ───────────────────────────────────────────────────────

/// An established session after a successful Noise-IK handshake.
pub struct Established {
    /// The AEAD session for sealing/opening data packets.
    pub session: Session,
    /// 16-byte authentication key derived from the channel binding (for the wire codec).
    pub auth_key: [u8; 16],
    /// 16-byte header-protection key derived from the channel binding (for the wire codec).
    pub hp_key: [u8; 16],
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn crypto_err(e: CryptoError) -> io::Error {
    io::Error::other(e)
}

// Maximum datagram size we ever allocate for recv.
const MAX_DATAGRAM: usize = 2048;

// How long the initiator waits for the responder's reply before retrying.
const RETRY_TIMEOUT: Duration = Duration::from_secs(1);

// How many times the initiator resends the init before giving up.
const MAX_RETRIES: u32 = 5;

// ── public API ────────────────────────────────────────────────────────────────

/// Run the Noise-IK initiator role over `sock`.
///
/// Sends `[HandshakeInit] ++ msg1` to `peer`, waits for `[HandshakeResp] ++ msg2`,
/// then derives an [`Established`] session. Retries up to [`MAX_RETRIES`] times
/// (each with a [`RETRY_TIMEOUT`] read timeout) so the companion test is not
/// flaky even when the responder thread has not started yet.
pub fn run_initiator(
    sock: &UdpSocket,
    peer: SocketAddr,
    local_priv: &[u8; 32],
    peer_pub: &[u8; 32],
) -> io::Result<Established> {
    let mut handshake = Handshake::initiator(local_priv, peer_pub).map_err(crypto_err)?;

    // Build the outgoing init message once; we may send it multiple times.
    let msg1 = handshake.write_message().map_err(crypto_err)?;
    let mut init_pkt = Vec::with_capacity(1 + msg1.len());
    init_pkt.push(PacketType::HandshakeInit as u8);
    init_pkt.extend_from_slice(&msg1);

    sock.set_read_timeout(Some(RETRY_TIMEOUT))?;

    let mut buf = [0u8; MAX_DATAGRAM];
    let mut last_err: io::Error = io::Error::other("no attempts made");

    for _ in 0..MAX_RETRIES {
        sock.send_to(&init_pkt, peer)?;

        let (n, _from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                last_err = e;
                continue;
            }
            Err(e) => return Err(e),
        };

        let pkt = &buf[..n];
        if pkt.is_empty() {
            last_err = io::Error::other("empty datagram");
            continue;
        }
        if pkt[0] != PacketType::HandshakeResp as u8 {
            last_err = io::Error::other("unexpected packet type");
            continue;
        }

        handshake.read_message(&pkt[1..]).map_err(crypto_err)?;

        // Capture channel binding BEFORE consuming the handshake.
        let cb = handshake.channel_binding();
        let session = handshake.into_session().map_err(crypto_err)?;
        let (auth_key, hp_key) = derive_wire_keys(&cb);

        // Restore blocking mode so the socket is left in a sensible state.
        sock.set_read_timeout(None)?;

        return Ok(Established {
            session,
            auth_key,
            hp_key,
        });
    }

    Err(last_err)
}

/// Run the Noise-IK responder role over `sock`.
///
/// Blocks until a `[HandshakeInit]` datagram arrives, sends the
/// `[HandshakeResp]` reply, then returns an [`Established`] session together
/// with the initiator's [`SocketAddr`].
pub fn run_responder(
    sock: &UdpSocket,
    local_priv: &[u8; 32],
) -> io::Result<(Established, SocketAddr)> {
    let mut handshake = Handshake::responder(local_priv).map_err(crypto_err)?;

    let mut buf = [0u8; MAX_DATAGRAM];
    let (n, peer_addr) = sock.recv_from(&mut buf)?;

    let pkt = &buf[..n];
    if pkt.is_empty() || pkt[0] != PacketType::HandshakeInit as u8 {
        return Err(io::Error::other("expected HandshakeInit packet"));
    }
    handshake.read_message(&pkt[1..]).map_err(crypto_err)?;

    let msg2 = handshake.write_message().map_err(crypto_err)?;
    let mut resp_pkt = Vec::with_capacity(1 + msg2.len());
    resp_pkt.push(PacketType::HandshakeResp as u8);
    resp_pkt.extend_from_slice(&msg2);
    sock.send_to(&resp_pkt, peer_addr)?;

    // Capture channel binding BEFORE consuming the handshake.
    let cb = handshake.channel_binding();
    let session = handshake.into_session().map_err(crypto_err)?;
    let (auth_key, hp_key) = derive_wire_keys(&cb);

    Ok((
        Established {
            session,
            auth_key,
            hp_key,
        },
        peer_addr,
    ))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use yip_crypto::generate_keypair;

    #[test]
    fn handshake_over_udp_establishes_matching_keys() {
        let rkp = generate_keypair();
        let ikp = generate_keypair();
        let resp_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let resp_addr = resp_sock.local_addr().unwrap();
        let init_sock = UdpSocket::bind("127.0.0.1:0").unwrap();

        let r_priv = rkp.private;
        let resp = std::thread::spawn(move || run_responder(&resp_sock, &r_priv).unwrap());
        let est_i = run_initiator(&init_sock, resp_addr, &ikp.private, &rkp.public).unwrap();
        let (est_r, _peer) = resp.join().unwrap();

        // both derived the same wire keys
        assert_eq!(est_i.auth_key, est_r.auth_key);
        assert_eq!(est_i.hp_key, est_r.hp_key);

        // and the established sessions actually talk
        let mut si = est_i.session;
        let mut sr = est_r.session;
        let sealed = si.seal(b"after handshake").unwrap();
        assert_eq!(
            sr.open(sealed.counter, &sealed.ciphertext).unwrap(),
            b"after handshake"
        );
    }

    #[test]
    fn crypto_err_converts_to_io_error() {
        // Exercise the crypto_err helper: a CryptoError converts to io::Error.
        use yip_crypto::CryptoError;
        let io_e = super::crypto_err(CryptoError::Handshake);
        assert_eq!(io_e.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn responder_rejects_wrong_packet_type() {
        // Send a datagram with type=Data (2) instead of HandshakeInit (0).
        // The responder must return an error immediately.
        let kp = generate_keypair();
        let resp_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let resp_addr = resp_sock.local_addr().unwrap();

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Wrong type byte: Data=2, not HandshakeInit=0.
        sender
            .send_to(&[PacketType::Data as u8, 0, 0], resp_addr)
            .unwrap();

        match run_responder(&resp_sock, &kp.private) {
            Err(e) => {
                assert!(
                    e.to_string().contains("HandshakeInit"),
                    "unexpected error: {e}"
                )
            }
            Ok(_) => panic!("expected error but responder succeeded"),
        }
    }

    #[test]
    fn initiator_exhausts_retries_when_responder_sends_wrong_type() {
        // Bind a "fake responder" that always replies with the wrong packet type.
        // The initiator should exhaust its retries and return an error.
        use std::time::Duration;
        let kp_i = generate_keypair();
        let kp_r = generate_keypair();

        let fake_resp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let resp_addr = fake_resp.local_addr().unwrap();
        fake_resp
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();

        let init_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let i_priv = kp_i.private;
        let r_pub = kp_r.public;

        // Spawn a thread that drains incoming datagrams and always replies with
        // a Data packet so the initiator never sees a valid HandshakeResp.
        let faker = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            for _ in 0..MAX_RETRIES {
                if let Ok((_, from)) = fake_resp.recv_from(&mut buf) {
                    let _ = fake_resp.send_to(&[PacketType::Data as u8], from);
                }
            }
        });

        match run_initiator(&init_sock, resp_addr, &i_priv, &r_pub) {
            Err(_) => {}
            Ok(_) => panic!("expected error but initiator succeeded"),
        }
        let _ = faker.join();
    }
}
