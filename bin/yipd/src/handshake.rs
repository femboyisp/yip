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
    /// Loss-feedback control packet (receiver → sender).
    Control = 3,
    /// Membership anti-entropy gossip (2c). Carries a self-verifying
    /// [`yip_membership::GossipMsg`] as a plain datagram: every `Record` is
    /// CA→cert→record-sig chained and re-verified on ingest, so a forged or
    /// injected record is rejected by `Membership::ingest_record`. In-session
    /// ENCRYPTION of gossip (metadata privacy) is an explicit 2c non-goal,
    /// deferred to the anonymity milestone.
    Gossip = 4,
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
///
/// Superseded in production by [`HandshakeState`]'s step-functions (Task 5):
/// `tunnel.rs` no longer does a pre-loop blocking handshake, so this blocking,
/// socket-owning variant is unreachable outside its own tests. Kept (per the
/// Task 5 addendum) rather than deleted, since it is still the simplest way to
/// exercise a full initiator/responder round-trip in a unit test.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "superseded by HandshakeState's step-functions; kept for its own unit tests"
    )
)]
pub fn run_initiator(
    sock: &UdpSocket,
    peer: SocketAddr,
    local_priv: &[u8; 32],
    peer_pub: &[u8; 32],
) -> io::Result<Established> {
    let mut handshake = Handshake::initiator(local_priv, peer_pub).map_err(crypto_err)?;

    // Build the outgoing init message once; we may send it multiple times.
    let msg1 = handshake.write_message(&[]).map_err(crypto_err)?;
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

        let _ = handshake.read_message(&pkt[1..]).map_err(crypto_err)?;

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
///
/// Superseded in production by [`HandshakeState`]'s step-functions; see
/// [`run_initiator`]'s doc comment.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "superseded by HandshakeState's step-functions; kept for its own unit tests"
    )
)]
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
    let _ = handshake.read_message(&pkt[1..]).map_err(crypto_err)?;

    let msg2 = handshake.write_message(&[]).map_err(crypto_err)?;
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

/// The initiator's Noise ephemeral public key: the raw, unencrypted first 32
/// bytes of msg1 (Noise-IK's leading `e` token) — i.e. `init_pkt[1..33]`
/// after the 1-byte [`PacketType::HandshakeInit`] prefix. `None` if
/// `init_pkt` is too short to contain it.
///
/// A fresh ephemeral is drawn once per handshake ATTEMPT, in
/// [`HandshakeState::start_initiator`]'s `write_message` call — a
/// retransmit of the same attempt resends the identical `init_pkt` bytes
/// (and therefore the identical `e`), while a genuinely new attempt (a new
/// cold-start handshake, or a new rekey round) draws a new one. This makes
/// it a stable, cheap per-round identifier: `PeerManager::handle_rekey_init`
/// uses it to recognize a retransmitted rekey `Init` (same ephemeral as the
/// round already answered) and reply idempotently instead of minting a
/// second session.
/// LOCKSTEP INVARIANT: `1..33` = skip the 1-byte `PacketType::HandshakeInit`
/// prefix, then the 32-byte Noise-IK `e` token that leads msg1 in the clear.
/// This offset MUST move in lockstep with `start_initiator`'s framing — if a
/// future anti-DPI change reshapes the `HandshakeInit` header, this must be
/// updated too, or it would return wrong-but-well-typed bytes and silently
/// reintroduce the rekey-convergence bug it exists to prevent.
pub fn init_ephemeral(init_pkt: &[u8]) -> Option<[u8; 32]> {
    init_pkt.get(1..33)?.try_into().ok()
}

/// TAI64N label length: 8-byte seconds + 4-byte nanoseconds.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into the handshake paths by a later anti-replay.34 task"
    )
)]
pub const TAI64N_LEN: usize = 12;

/// The current wall clock as a TAI64N label: big-endian `2^62 + unix_secs`
/// (8 bytes) followed by big-endian nanoseconds (4 bytes). Big-endian so that
/// a lexicographic byte comparison of two labels is chronological. Wall-clock
/// based, so it survives a peer restart (a fresh Init is always newer in real
/// time) with no persisted state. A clock that jumps backwards yields a label
/// that a peer with a higher last-accepted label will reject — the WireGuard
/// behavior, accepted.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into the handshake paths by a later anti-replay.34 task"
    )
)]
pub fn now_tai64n() -> [u8; TAI64N_LEN] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs().wrapping_add(1u64 << 62);
    let nanos = now.subsec_nanos();
    let mut out = [0u8; TAI64N_LEN];
    out[..8].copy_from_slice(&secs.to_be_bytes());
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    out
}

/// Build the msg1 Noise payload: the anti-replay TAI64N label followed by the
/// (optional) membership cert. Empty `cert` (2a/2b) yields a 12-byte payload.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into the handshake paths by a later anti-replay.34 task"
    )
)]
pub fn frame_init_payload(cert: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAI64N_LEN + cert.len());
    out.extend_from_slice(&now_tai64n());
    out.extend_from_slice(cert);
    out
}

/// Split a received msg1 payload into `(ts_label, cert_remainder)`.
/// `None` (fail-closed) if it is shorter than the 12-byte label.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into the handshake paths by a later anti-replay.34 task"
    )
)]
pub fn parse_init_payload(payload: &[u8]) -> Option<([u8; TAI64N_LEN], &[u8])> {
    let ts: [u8; TAI64N_LEN] = payload.get(..TAI64N_LEN)?.try_into().ok()?;
    Some((ts, &payload[TAI64N_LEN..]))
}

// ── step-functions (in-band handshakes) ────────────────────────────────────────

/// A handshake in progress, driven step-by-step instead of blocking on a
/// socket. This lets a caller (e.g. `PeerManager`'s event loop) multiplex
/// several concurrent handshakes without dedicating a thread to each.
///
/// Only the initiator side needs to carry state between steps (it must
/// remember the in-progress [`Handshake`] while awaiting the responder's
/// reply); the responder completes in a single step.
pub struct HandshakeState {
    handshake: Handshake,
}

/// Return type of [`HandshakeState::start_responder`]: `(established session,
/// framed [HandshakeResp] ++ msg2 bytes, initiator's recovered static public
/// key, initiator's msg1 app payload — the 2c cert seam)`.
type StartResponderResult = io::Result<(Established, Vec<u8>, [u8; 32], Vec<u8>)>;

impl HandshakeState {
    /// Start the initiator role: build `[HandshakeInit] ++ msg1`.
    ///
    /// Returns the in-progress state (to be resumed via [`Self::read_response`])
    /// together with the framed bytes to send to the peer.
    pub fn start_initiator(
        local_priv: &[u8; 32],
        peer_pub: &[u8; 32],
        payload: &[u8],
    ) -> io::Result<(Self, Vec<u8>)> {
        let mut handshake = Handshake::initiator(local_priv, peer_pub).map_err(crypto_err)?;

        let msg1 = handshake.write_message(payload).map_err(crypto_err)?;
        let mut init_pkt = Vec::with_capacity(1 + msg1.len());
        init_pkt.push(PacketType::HandshakeInit as u8);
        init_pkt.extend_from_slice(&msg1);

        Ok((Self { handshake }, init_pkt))
    }

    /// Run the responder role to completion in a single step: read
    /// `[HandshakeInit] ++ msg1` from `init_pkt`, and return the
    /// `[HandshakeResp] ++ msg2` reply bytes, the completed [`Established`]
    /// session (Noise-IK completes for the responder as soon as it has read
    /// msg1 and written msg2), the initiator's recovered static public key,
    /// and the app payload the initiator carried in msg1 (the 2c cert seam;
    /// `Task 6` will populate/consume it — this task only plumbs it).
    ///
    /// `resp_payload` is written into msg2's Noise payload (the responder's
    /// own cert in 2c; empty for now).
    ///
    /// The static key is required by `PeerManager`'s admission check: a
    /// `HandshakeInit` must only be admitted (and a peer transitioned to
    /// `Established`) if the recovered static key matches a *configured*
    /// peer — otherwise any UDP sender could get a `DataPlane` allocated for
    /// it. The key is captured from `handshake.remote_static()` before
    /// `into_session()` consumes the handshake (the transport-mode
    /// conversion drops the handshake state that holds it).
    pub fn start_responder(
        local_priv: &[u8; 32],
        init_pkt: &[u8],
        resp_payload: &[u8],
    ) -> StartResponderResult {
        let mut handshake = Handshake::responder(local_priv).map_err(crypto_err)?;

        if init_pkt.is_empty() || init_pkt[0] != PacketType::HandshakeInit as u8 {
            return Err(io::Error::other("expected HandshakeInit packet"));
        }
        let initiator_payload = handshake.read_message(&init_pkt[1..]).map_err(crypto_err)?;

        let msg2 = handshake.write_message(resp_payload).map_err(crypto_err)?;
        let mut resp_pkt = Vec::with_capacity(1 + msg2.len());
        resp_pkt.push(PacketType::HandshakeResp as u8);
        resp_pkt.extend_from_slice(&msg2);

        // Capture the initiator's static key and the channel binding BEFORE
        // consuming the handshake into a session.
        let remote_static = handshake
            .remote_static()
            .ok_or_else(|| io::Error::other("responder handshake has no remote static key"))?;
        let cb = handshake.channel_binding();
        let session = handshake.into_session().map_err(crypto_err)?;
        let (auth_key, hp_key) = derive_wire_keys(&cb);

        Ok((
            Established {
                session,
                auth_key,
                hp_key,
            },
            resp_pkt,
            remote_static,
            initiator_payload,
        ))
    }

    /// Resume the initiator role: read `[HandshakeResp] ++ msg2` and
    /// finalize into an [`Established`] session, together with the app
    /// payload the responder carried in msg2 (the 2c cert seam).
    pub fn read_response(mut self, resp_pkt: &[u8]) -> io::Result<(Established, Vec<u8>)> {
        if resp_pkt.is_empty() || resp_pkt[0] != PacketType::HandshakeResp as u8 {
            return Err(io::Error::other("expected HandshakeResp packet"));
        }
        let responder_payload = self
            .handshake
            .read_message(&resp_pkt[1..])
            .map_err(crypto_err)?;

        // Capture channel binding BEFORE consuming the handshake.
        let cb = self.handshake.channel_binding();
        let session = self.handshake.into_session().map_err(crypto_err)?;
        let (auth_key, hp_key) = derive_wire_keys(&cb);

        Ok((
            Established {
                session,
                auth_key,
                hp_key,
            },
            responder_payload,
        ))
    }
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
    fn step_handshake_initiator_responder_agree() {
        let a = generate_keypair();
        let b = generate_keypair();

        let (ha, init_pkt) = HandshakeState::start_initiator(&a.private, &b.public, &[]).unwrap();
        let (b_est, resp_pkt, initiator_static, _initiator_payload) =
            HandshakeState::start_responder(&b.private, &init_pkt, &[]).unwrap();
        let (a_est, _responder_payload) = ha.read_response(&resp_pkt).unwrap();

        // Both derive the same channel binding (conn_tag inputs).
        assert_eq!(a_est.auth_key, b_est.auth_key);
        assert_eq!(a_est.hp_key, b_est.hp_key);
        // The responder recovers the initiator's static public key — this is
        // what `PeerManager` admission-checks against configured peers.
        assert_eq!(initiator_static, a.public);
    }

    #[test]
    fn init_ephemeral_matches_across_identical_retransmits_and_differs_for_new_attempts() {
        let a = generate_keypair();
        let b = generate_keypair();

        let (_ha, init_pkt) = HandshakeState::start_initiator(&a.private, &b.public, &[]).unwrap();
        let eph1a = init_ephemeral(&init_pkt).expect("init_pkt carries a 32-byte ephemeral");
        // A retransmit resends the SAME bytes verbatim: same ephemeral.
        let eph1b = init_ephemeral(&init_pkt).expect("init_pkt carries a 32-byte ephemeral");
        assert_eq!(eph1a, eph1b);

        // A NEW handshake attempt draws a fresh ephemeral.
        let (_hb, init_pkt2) = HandshakeState::start_initiator(&a.private, &b.public, &[]).unwrap();
        let eph2 = init_ephemeral(&init_pkt2).expect("init_pkt carries a 32-byte ephemeral");
        assert_ne!(
            eph1a, eph2,
            "a new handshake attempt must draw a new ephemeral"
        );

        // Too-short input: no panic, just `None`.
        assert_eq!(init_ephemeral(&[0u8; 10]), None);
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

    #[test]
    fn tai64n_is_big_endian_monotonic_and_roundtrips() {
        // frame/parse roundtrip: ts prefix split from the cert remainder.
        let cert = b"a-cert-blob";
        let framed = frame_init_payload(cert);
        assert_eq!(framed.len(), TAI64N_LEN + cert.len());
        let (ts, rest) = parse_init_payload(&framed).expect("parses");
        assert_eq!(rest, cert);
        assert_eq!(&framed[..TAI64N_LEN], &ts);

        // empty cert (2a/2b): payload is exactly the 12-byte ts.
        let framed_empty = frame_init_payload(&[]);
        assert_eq!(framed_empty.len(), TAI64N_LEN);
        let (_ts, rest) = parse_init_payload(&framed_empty).expect("parses");
        assert!(rest.is_empty());

        // big-endian so lexicographic byte-compare is chronological: a later
        // wall-clock ts compares strictly greater than an earlier one.
        let earlier = now_tai64n();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let later = now_tai64n();
        assert!(
            later > earlier,
            "TAI64N must increase with wall-clock and byte-compare"
        );
    }

    #[test]
    fn parse_init_payload_rejects_short_payload() {
        assert!(parse_init_payload(&[0u8; TAI64N_LEN - 1]).is_none());
        assert!(parse_init_payload(&[]).is_none());
    }
}
