//! REALITY.2 Task 7: the `connect()` orchestration and `RealityStream`
//! application-data stream.
//!
//! Composes [`crate::hello`], [`crate::auth`], and [`crate::handshake`] into
//! a full RFC 8446 §2 one-round-trip TLS 1.3 client handshake carrying a
//! REALITY auth seal in the `ClientHello`'s `legacy_session_id`, then hands
//! back an `AsyncRead + AsyncWrite` stream over the negotiated application
//! traffic keys. REALITY is zero-cert-auth by design (the whole point is
//! that the wire is indistinguishable from a real TLS 1.3 connection to the
//! camouflage SNI): by default (`verify: false`) this module does not
//! verify the server's certificate chain or the server's
//! `CertificateVerify`/`Finished` contents, but it does consume every
//! handshake message so the transcript stays correct.
//!
//! REALITY.4b (`verify: true`) adds an OPTIONAL relay-binding check on top
//! of that: it pins the server Certificate leaf's P-256 key to the
//! shared-secret-derived key ([`auth::derive_cert_key`]) and verifies the
//! `CertificateVerify` signature over it, hard-pinning
//! `ecdsa_secp256r1_sha256` — proof the peer holds the REALITY relay's
//! private key, not merely that it can answer a `ClientHello` (which any
//! camouflage-only decoy site also does). This still never validates a CA
//! chain — the leaf is always self-signed — and still never checks
//! `Finished`. See `verify_reality_binding`.
//!
//! The ephemeral X25519 key is generated once, as raw bytes, and reused for
//! both the TLS `key_share`/ECDHE *and* the REALITY auth seal's ECDH — see
//! [`connect`]'s first few lines. `ring::agreement` cannot be used for this
//! because its private key is not extractable, so the same key could not
//! also seal the REALITY auth payload.

use crate::auth;
use crate::error::Error;
use crate::handshake::{
    self, derive_application_keys, derive_handshake_keys, finished_verify_data, parse_server_hello,
    parse_server_hello_shape, record_open, record_open_typed, record_seal, transcript_hash,
    HandshakeKeys, GROUP_X25519, GROUP_X25519MLKEM768,
};
use crate::hello::{self, ClientHelloParams, RandomSource};
use crate::template::{CapturedFlight, EncryptedFlightShape, ServerFlightTemplate};
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{Kem, MlKem768};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub mod cert;
pub mod flight;
pub mod record;
pub mod sig;
#[cfg(test)]
mod tests;

pub use flight::{emit_server_flight, scan_flight_shape, FlightShapeScan, ServerFlight};
pub(crate) use record::*;
pub use sig::sign_certificate_verify;
pub(crate) use sig::*;

/// Byte length of an ML-KEM-768 ciphertext (FIPS 203 §7.2) — the length of
/// the leading portion of a group-`4588` server `key_share`.
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

/// [`RandomSource`] backed by the OS CSPRNG (`getrandom`), for driving
/// [`hello::craft`] in production. [`RandomSource::fill`] cannot itself
/// return a `Result`, so failures are latched and surfaced by
/// [`OsRng::into_result`] after `craft` returns — `craft` only ever
/// transforms already-filled bytes, so a latched failure part-way through
/// still produces *some* `Vec<u8>` (built from bytes that silently stayed
/// zero once RNG failed), but [`connect`] discards it and bails out via
/// `into_result` before ever putting it on the wire.
#[derive(Default)]
struct OsRng {
    error: Option<getrandom::Error>,
}

impl OsRng {
    fn into_result(self) -> Result<(), Error> {
        match self.error {
            Some(e) => Err(Error::Rng(e)),
            None => Ok(()),
        }
    }
}

impl RandomSource for OsRng {
    fn fill(&mut self, buf: &mut [u8]) {
        if self.error.is_some() {
            return;
        }
        if let Err(e) = getrandom::fill(buf) {
            self.error = Some(e);
        }
    }
}

/// The same OS-CSPRNG-backed, latched-error `getrandom` bridge as [`OsRng`],
/// but implementing `rand_core`'s `TryRng`/`TryCryptoRng` instead of
/// [`RandomSource`] — the trait bound `ml_kem::MlKem768::generate_keypair_from_rng`
/// needs (`rand_core::CryptoRng`, blanket-implemented for any
/// `TryRng<Error = Infallible> + TryCryptoRng<Error = Infallible>`).
/// `try_fill_bytes` returns `Result<(), Infallible>` (it cannot itself
/// fail), so a `getrandom` failure is latched the same way `OsRng` latches
/// one, and [`MlKemRng::into_result`] surfaces it to the caller after
/// `generate_keypair_from_rng` returns (which, on a latched failure, still
/// returns *some* keypair built from bytes that silently stayed zero —
/// [`connect`] discards it and bails out via `into_result` before ever using
/// it).
/// `pub(crate)` (not just private to this module) so [`crate::server`]'s test
/// module can generate a real client ML-KEM keypair the same way `connect`
/// does, without duplicating this bridge.
#[derive(Default)]
pub(crate) struct MlKemRng {
    error: Option<getrandom::Error>,
}

impl MlKemRng {
    fn into_result(self) -> Result<(), Error> {
        match self.error {
            Some(e) => Err(Error::Rng(e)),
            None => Ok(()),
        }
    }

    fn fill(&mut self, dest: &mut [u8]) {
        if self.error.is_some() {
            return;
        }
        if let Err(e) = getrandom::fill(dest) {
            self.error = Some(e);
        }
    }
}

impl rand_core::TryRng for MlKemRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.fill(&mut buf);
        Ok(u32::from_ne_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.fill(&mut buf);
        Ok(u64::from_ne_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(dest);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for MlKemRng {}

/// Reads one raw TLS record (5-byte header + body) off `stream`. Returns the
/// outer record type and the (still possibly-encrypted) body.
async fn read_raw_record<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u8, Vec<u8>), Error> {
    let mut header = [0u8; RECORD_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok((header[0], payload))
}
/// `AlertLevel::fatal` (RFC 8446 §6.1, value `2`) — every alert this client
/// ever sends is fatal.
const ALERT_LEVEL_FATAL: u8 = 2;

/// `AlertDescription::bad_certificate` (RFC 8446 §6.2, value `42`) — pinned
/// as the alert a REALITY.4b `CertificateVerify` verification failure sends.
/// This is the RFC-canonical description for "a certificate was corrupt,
/// contained signatures that did not verify correctly, etc." — exactly this
/// client's situation on a pin/signature mismatch — and is documented as
/// what mainstream browsers (Chrome/BoringSSL) send for a TLS 1.3
/// cert-verify failure. This value was NOT captured against a live browser
/// in this environment (no network access + no real cert-mismatch harness
/// available here); REALITY.5's wire-fidelity pass is the place that
/// re-verifies it against a real packet capture and swaps it out if reality
/// disagrees.
const ALERT_DESCRIPTION_BAD_CERTIFICATE: u8 = 42;

/// Best-effort: seals `[fatal, description]` as an encrypted TLS 1.3 alert
/// record under the CLIENT handshake traffic keys (sequence 0 — no prior
/// client-side handshake-key-sealed record has been sent at the point
/// REALITY.4b verification can fail, since it runs before the client
/// `Finished` is sealed/sent) and writes it to `stream`. A seal or write
/// failure on this already-failing path is silently ignored — the caller is
/// about to return the real `Error::RealityVerify` regardless, and a peer
/// that never gets the alert just sees the connection drop, same as any
/// other network failure.
async fn send_alert<S: AsyncWrite + Unpin>(
    stream: &mut S,
    hk: &HandshakeKeys,
    suite: u16,
    description: u8,
) {
    let alert_msg = [ALERT_LEVEL_FATAL, description];
    let Ok(sealed) = record_seal(
        &hk.client_key,
        &hk.client_iv,
        0,
        suite,
        CONTENT_TYPE_ALERT,
        &alert_msg,
    ) else {
        return;
    };
    let Ok(header) = record_header(
        CONTENT_TYPE_APPLICATION_DATA,
        LEGACY_RECORD_VERSION,
        sealed.len(),
    ) else {
        return;
    };
    let _ = stream.write_all(&header).await;
    let _ = stream.write_all(&sealed).await;
}

/// Performs a full RFC 8446 §2 one-round-trip TLS 1.3 client handshake to
/// `stream`, carrying a REALITY auth seal (keyed by `server_reality_pub` and
/// `short_id`) in the crafted Chrome-150 `ClientHello`'s `legacy_session_id`.
/// On success, returns a [`RealityStream`] over the negotiated application
/// traffic keys.
///
/// When `verify` is `false` (byte-identical to this function's pre-
/// REALITY.4b behavior — the JA3/JA4 wire fingerprint is unaffected either
/// way, since verification never changes anything this client SENDS, only
/// what it does with what it receives): does not verify the server's
/// certificate chain, `CertificateVerify`, or `Finished` contents —
/// REALITY's camouflage design means the server on the other end of a
/// *successful* connection presents the real target site's certificate,
/// which this client has no way (and no need) to validate; a misconfigured
/// or non-REALITY-aware peer simply fails to open the auth seal
/// server-side and this handshake either times out or is rejected
/// upstream, not here.
///
/// When `verify` is `true` (REALITY.4b): after the server's
/// EncryptedExtensions/Certificate/CertificateVerify/Finished flight is
/// fully received, ADDITIONALLY pins the Certificate leaf's P-256 key to
/// `auth::derive_cert_key(auth::shared_secret(server_reality_pub,
/// &eph_priv)).public_sec1` and verifies `CertificateVerify` over it (see
/// `verify_reality_binding`) — proof the peer holds
/// `server_reality_pub`'s private key, not merely that it can answer a
/// `ClientHello`. On failure, best-effort sends a `bad_certificate` TLS
/// alert (see `send_alert`) and returns `Err(Error::RealityVerify(_))`
/// BEFORE the client `Finished` is sent — this client never completes a
/// handshake with, nor sends any encrypted client bytes to, a peer that
/// fails this check.
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    sni: &str,
    server_reality_pub: &[u8; 32],
    short_id: [u8; 8],
    verify: bool,
) -> Result<RealityStream<S>, Error> {
    // THE ONE EPHEMERAL KEY: raw bytes from getrandom, reused via
    // x25519-dalek for both the TLS key_share/ECDHE and the REALITY auth
    // seal's ECDH. Never ring::agreement — its private key isn't
    // extractable, so it could not be reused for the seal.
    let mut eph_priv = [0u8; 32];
    getrandom::fill(&mut eph_priv)?;
    let secret = x25519_dalek::StaticSecret::from(eph_priv);
    let eph_pub: [u8; 32] = x25519_dalek::PublicKey::from(&secret).to_bytes();

    // A genuine ML-KEM-768 keypair (REALITY.2 Task 9), generated fresh per
    // connection like the X25519 ephemeral key above. Real Chrome sends
    // `X25519MLKEM768` (group 4588) as its PRIMARY key_share, and real
    // ML-KEM-strict servers (Cloudflare, Google) validate the encapsulation
    // key's canonical encoding — only a genuine key survives that check (see
    // `hello::key_share_body`'s doc comment). `mlkem_dk` is kept to complete
    // the hybrid exchange if the server selects group 4588 below; `mlkem_ek`
    // is sent as-is in the ClientHello.
    let mut mlkem_rng = MlKemRng::default();
    let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair_from_rng(&mut mlkem_rng);
    mlkem_rng.into_result()?;

    let mut client_random = [0u8; 32];
    getrandom::fill(&mut client_random)?;

    let ts_min = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Clock)?
        .as_secs()
        / 60;

    let legacy_session_id = auth::seal(
        server_reality_pub,
        &eph_priv,
        &client_random,
        short_id,
        ts_min,
    );

    let params = ClientHelloParams {
        sni: sni.to_string(),
        key_share_x25519_pub: eph_pub,
        key_share_mlkem_ek: mlkem_ek.to_bytes().to_vec(),
        legacy_session_id,
        client_random,
    };
    let mut rng = OsRng::default();
    let hello_msg = hello::craft(&params, &mut rng);
    rng.into_result()?;

    let ch_header = record_header(
        CONTENT_TYPE_HANDSHAKE,
        LEGACY_RECORD_VERSION_INITIAL,
        hello_msg.len(),
    )?;
    stream.write_all(&ch_header).await?;
    stream.write_all(&hello_msg).await?;

    // ServerHello is sent plaintext (record type 0x16) — RFC 8446 §5.1.
    let (record_type, sh_msg) = read_raw_record(&mut stream).await?;
    if record_type != CONTENT_TYPE_HANDSHAKE {
        return Err(Error::Protocol(
            "expected a plaintext ServerHello handshake record",
        ));
    }
    let server_hello_info = parse_server_hello(&sh_msg)?;

    let mut ch_sh_transcript = Vec::with_capacity(hello_msg.len() + sh_msg.len());
    ch_sh_transcript.extend_from_slice(&hello_msg);
    ch_sh_transcript.extend_from_slice(&sh_msg);
    let transcript_ch_sh = transcript_hash(&ch_sh_transcript, server_hello_info.suite);

    // The (possibly hybrid) ECDHE shared secret fed to the TLS 1.3 key
    // schedule (RFC 8446 §7.1's "(EC)DHE" input, generalized to `&[u8]` —
    // see `derive_handshake_keys`'s doc comment). Group 29 (plain X25519):
    // 32 bytes, the X25519 ECDH output alone. Group 4588
    // (X25519MLKEM768): 64 bytes, `mlkem_shared_secret(32) ‖
    // x25519_shared_secret(32)` — ML-KEM first, matching the client
    // `key_share` entry's own `mlkem_ek ‖ x25519_pub` byte order (see
    // `hello::key_share_body`), per
    // draft-kwiatkowski-tls-ecdhe-mlkem's hybrid combiner. The server's
    // group-4588 key_share is `mlkem768_ciphertext(1088) ‖
    // x25519_public(32)` — `parse_server_hello` already validated that
    // exact length for this group.
    let ecdhe: Vec<u8> = match server_hello_info.group {
        GROUP_X25519MLKEM768 => {
            let (ct_bytes, server_x25519_pub) = server_hello_info
                .server_key_share
                .split_at(MLKEM768_CIPHERTEXT_LEN);
            let ciphertext = ct_bytes
                .try_into()
                .map_err(|_| handshake::Error::MlKemDecapsulation)?;
            let mlkem_ss = mlkem_dk.decapsulate(&ciphertext);
            let server_x25519_pub: [u8; 32] = server_x25519_pub
                .try_into()
                .map_err(|_| handshake::Error::BadKeyShareLength)?;
            let x25519_ss = secret
                .diffie_hellman(&x25519_dalek::PublicKey::from(server_x25519_pub))
                .to_bytes();

            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&mlkem_ss);
            combined.extend_from_slice(&x25519_ss);
            combined
        }
        GROUP_X25519 => {
            let server_x25519_pub: [u8; 32] = server_hello_info
                .server_key_share
                .as_slice()
                .try_into()
                .map_err(|_| handshake::Error::BadKeyShareLength)?;
            secret
                .diffie_hellman(&x25519_dalek::PublicKey::from(server_x25519_pub))
                .to_bytes()
                .to_vec()
        }
        _ => {
            return Err(Error::Protocol(
                "parse_server_hello returned an unexpected key_share group",
            ))
        }
    };
    let hk: HandshakeKeys =
        derive_handshake_keys(&ecdhe, &transcript_ch_sh, server_hello_info.suite);

    // Read the server's EncryptedExtensions/Certificate/CertificateVerify/
    // Finished flight: one or more 0x17 records under the server handshake
    // traffic key, possibly preceded by a middlebox-compatibility CCS.
    let mut hs_flight = Vec::new();
    let mut server_seq = 0u64;
    let finished_end = loop {
        let (record_type, mut payload) = read_raw_record(&mut stream).await?;
        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(Error::Protocol(
                "expected an encrypted handshake record in the server flight",
            ));
        }
        let opened = record_open(
            &hk.server_key,
            &hk.server_iv,
            server_seq,
            server_hello_info.suite,
            record_type,
            &mut payload,
        )?;
        server_seq = server_seq
            .checked_add(1)
            .ok_or(Error::Protocol("server handshake sequence overflow"))?;
        hs_flight.extend_from_slice(&opened);
        if hs_flight.len() > MAX_SERVER_FLIGHT_LEN {
            return Err(Error::Protocol(
                "server handshake flight exceeds sane bound",
            ));
        }

        if let Some(end) = find_finished_end(&hs_flight)? {
            break end;
        }
    };
    hs_flight.truncate(finished_end);

    if verify {
        let shared = auth::shared_secret(server_reality_pub, &eph_priv);
        let expected_pubkey_sec1 = auth::derive_cert_key(&shared).public_sec1;
        if let Err(e) = verify_reality_binding(
            &hs_flight,
            &ch_sh_transcript,
            server_hello_info.suite,
            &expected_pubkey_sec1,
        ) {
            send_alert(
                &mut stream,
                &hk,
                server_hello_info.suite,
                ALERT_DESCRIPTION_BAD_CERTIFICATE,
            )
            .await;
            return Err(e);
        }
    }

    let mut full_transcript = ch_sh_transcript;
    full_transcript.extend_from_slice(&hs_flight);
    let transcript_thru_sfin = transcript_hash(&full_transcript, server_hello_info.suite);

    // Client Finished: verify_data = HMAC-Hash(finished_key, transcript),
    // finished_key = HKDF-Expand-Label(client_hs_traffic, "finished", "",
    // Hash.length) — Hash is the suite's key-schedule hash throughout (RFC
    // 8446 §4.4.4/§7.1), so verify_data is 32 bytes for SHA-256-hash suites
    // but 48 bytes for TLS_AES_256_GCM_SHA384 (0x1302); the u24 length
    // prefix below must match that, not be hardcoded.
    let verify_data = finished_verify_data(
        &hk.client_hs_traffic,
        &transcript_thru_sfin,
        server_hello_info.suite,
    );

    let mut client_finished_msg = Vec::with_capacity(4 + verify_data.len());
    client_finished_msg.push(HS_TYPE_FINISHED);
    let vd_len = u32::try_from(verify_data.len())
        .map_err(|_| Error::Protocol("Finished verify_data length exceeds a u24"))?;
    client_finished_msg.extend_from_slice(&vd_len.to_be_bytes()[1..]); // u24
    client_finished_msg.extend_from_slice(&verify_data);

    // Middlebox-compatibility CCS, then the sealed client Finished, matching
    // real Chrome/BoringSSL's wire shape.
    stream.write_all(&CHANGE_CIPHER_SPEC_RECORD).await?;

    let sealed_finished = record_seal(
        &hk.client_key,
        &hk.client_iv,
        0,
        server_hello_info.suite,
        CONTENT_TYPE_HANDSHAKE,
        &client_finished_msg,
    )?;
    let fin_header = record_header(
        CONTENT_TYPE_APPLICATION_DATA,
        LEGACY_RECORD_VERSION,
        sealed_finished.len(),
    )?;
    stream.write_all(&fin_header).await?;
    stream.write_all(&sealed_finished).await?;

    let ak = derive_application_keys(
        &hk.handshake_secret,
        &transcript_thru_sfin,
        server_hello_info.suite,
    );

    Ok(RealityStream::client(stream, ak))
}

/// REALITY.5a Task 3: probes a REAL `dest` — no REALITY seal, since `dest`
/// ignores `legacy_session_id` — and captures its server flight's structural
/// fingerprint: the `ServerHello` shape (ordered extensions, negotiated
/// suite/group), the encrypted flight's per-record ciphertext-payload
/// lengths and per-message plaintext lengths, and the leaf/intermediate
/// certificate DERs. Later REALITY.5 sub-milestones (5b/5c/5d) reproduce this
/// structure on the relay's authed path.
///
/// Crafts the SAME Chrome-150 `ClientHello` [`connect`] would (same
/// [`hello::craft`] call, same fresh X25519 ephemeral + ML-KEM setup —
/// reused byte-for-byte below), except `legacy_session_id` is filled with
/// random bytes instead of a REALITY auth seal: probing the real `dest`
/// needs no `server_reality_pub`/`short_id`, and `dest` never inspects
/// `legacy_session_id`'s contents, so the wire fingerprint an observer sees
/// here matches exactly what [`connect`] sends. Completes the handshake
/// through the server's `Finished`, but sends neither a client `Finished`
/// nor reads any application data afterward — this is a probe, not a
/// connection, so it stops the instant it has what it came for.
///
/// A focused SIBLING of [`connect`]: shares [`hello::craft`], the ephemeral
/// key setup, [`parse_server_hello`]/[`parse_server_hello_shape`],
/// [`derive_handshake_keys`], [`record_open`], `find_finished_end`, and
/// [`scan_flight_shape`], but DUPLICATES `connect`'s ~15-line encrypted-
/// flight read loop (with one addition: recording each record's pre-decrypt
/// ciphertext-payload length into `record_lengths`) rather than refactoring
/// `connect`'s crux security path to share it — see this module's REALITY.5a
/// Task 3 brief: a probe is not the hot path, so a small, clearly-commented
/// duplication here is safer than touching `connect`. `connect`'s body is
/// byte-for-byte unchanged by this function's existence.
pub async fn capture_dest_flight<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    sni: &str,
) -> Result<CapturedFlight, Error> {
    // THE ONE EPHEMERAL KEY, same setup as connect's (see connect's doc
    // comment) — reused for the TLS key_share/ECDHE only, since there is no
    // REALITY seal to also key here.
    let mut eph_priv = [0u8; 32];
    getrandom::fill(&mut eph_priv)?;
    let secret = x25519_dalek::StaticSecret::from(eph_priv);
    let eph_pub: [u8; 32] = x25519_dalek::PublicKey::from(&secret).to_bytes();

    // A genuine ML-KEM-768 keypair, exactly as connect's — a real
    // ML-KEM-strict dest (Cloudflare, Google) validates the encapsulation
    // key's canonical encoding, so only a genuine key survives probing it.
    let mut mlkem_rng = MlKemRng::default();
    let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair_from_rng(&mut mlkem_rng);
    mlkem_rng.into_result()?;

    let mut client_random = [0u8; 32];
    getrandom::fill(&mut client_random)?;

    // No REALITY seal: dest ignores legacy_session_id entirely, so a random
    // 32-byte value stands in for it — still wire-shaped exactly like a real
    // seal (hello::craft only cares that it fits, not what's inside).
    let mut legacy_session_id = [0u8; 32];
    getrandom::fill(&mut legacy_session_id)?;

    let params = ClientHelloParams {
        sni: sni.to_string(),
        key_share_x25519_pub: eph_pub,
        key_share_mlkem_ek: mlkem_ek.to_bytes().to_vec(),
        legacy_session_id,
        client_random,
    };
    let mut rng = OsRng::default();
    let hello_msg = hello::craft(&params, &mut rng);
    rng.into_result()?;

    let ch_header = record_header(
        CONTENT_TYPE_HANDSHAKE,
        LEGACY_RECORD_VERSION_INITIAL,
        hello_msg.len(),
    )?;
    stream.write_all(&ch_header).await?;
    stream.write_all(&hello_msg).await?;

    // ServerHello is sent plaintext (record type 0x16) — RFC 8446 §5.1.
    let (record_type, sh_msg) = read_raw_record(&mut stream).await?;
    if record_type != CONTENT_TYPE_HANDSHAKE {
        return Err(Error::Protocol(
            "expected a plaintext ServerHello handshake record",
        ));
    }
    // The crypto-relevant fields (suite/group/key_share bytes) via
    // parse_server_hello, and the full structural shape (ordered
    // extensions) via parse_server_hello_shape — both walk the identical
    // bounded header, so neither can disagree with the other about what
    // suite/group was negotiated.
    let server_hello_info = parse_server_hello(&sh_msg)?;
    let server_hello_shape = parse_server_hello_shape(&sh_msg)?;

    let mut ch_sh_transcript = Vec::with_capacity(hello_msg.len() + sh_msg.len());
    ch_sh_transcript.extend_from_slice(&hello_msg);
    ch_sh_transcript.extend_from_slice(&sh_msg);
    let transcript_ch_sh = transcript_hash(&ch_sh_transcript, server_hello_info.suite);

    // The (possibly hybrid) ECDHE shared secret — identical branch to
    // connect's (see connect's doc comment for the group-4588 wire shape).
    let ecdhe: Vec<u8> = match server_hello_info.group {
        GROUP_X25519MLKEM768 => {
            let (ct_bytes, server_x25519_pub) = server_hello_info
                .server_key_share
                .split_at(MLKEM768_CIPHERTEXT_LEN);
            let ciphertext = ct_bytes
                .try_into()
                .map_err(|_| handshake::Error::MlKemDecapsulation)?;
            let mlkem_ss = mlkem_dk.decapsulate(&ciphertext);
            let server_x25519_pub: [u8; 32] = server_x25519_pub
                .try_into()
                .map_err(|_| handshake::Error::BadKeyShareLength)?;
            let x25519_ss = secret
                .diffie_hellman(&x25519_dalek::PublicKey::from(server_x25519_pub))
                .to_bytes();

            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&mlkem_ss);
            combined.extend_from_slice(&x25519_ss);
            combined
        }
        GROUP_X25519 => {
            let server_x25519_pub: [u8; 32] = server_hello_info
                .server_key_share
                .as_slice()
                .try_into()
                .map_err(|_| handshake::Error::BadKeyShareLength)?;
            secret
                .diffie_hellman(&x25519_dalek::PublicKey::from(server_x25519_pub))
                .to_bytes()
                .to_vec()
        }
        _ => {
            return Err(Error::Protocol(
                "parse_server_hello returned an unexpected key_share group",
            ))
        }
    };
    let hk: HandshakeKeys =
        derive_handshake_keys(&ecdhe, &transcript_ch_sh, server_hello_info.suite);

    // Read the server's EncryptedExtensions/Certificate/CertificateVerify/
    // Finished flight, recording each record's ciphertext-payload length
    // (the record header's length field, i.e. `payload.len()` BEFORE
    // `record_open` mutates it in place to strip the tag/padding) into
    // `record_lengths` as we go. DELIBERATE DUPLICATE of connect's own
    // flight-read loop (see this function's doc comment) — the only
    // difference is this extra bookkeeping line; the MAX_SERVER_FLIGHT_LEN
    // cap below applies identically, since the flight buffer is attacker-
    // length-controlled here exactly as it is in connect.
    let mut hs_flight = Vec::new();
    let mut record_lengths = Vec::new();
    let mut server_seq = 0u64;
    let finished_end = loop {
        let (record_type, mut payload) = read_raw_record(&mut stream).await?;
        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(Error::Protocol(
                "expected an encrypted handshake record in the server flight",
            ));
        }
        record_lengths.push(payload.len());
        let opened = record_open(
            &hk.server_key,
            &hk.server_iv,
            server_seq,
            server_hello_info.suite,
            record_type,
            &mut payload,
        )?;
        server_seq = server_seq
            .checked_add(1)
            .ok_or(Error::Protocol("server handshake sequence overflow"))?;
        hs_flight.extend_from_slice(&opened);
        if hs_flight.len() > MAX_SERVER_FLIGHT_LEN {
            return Err(Error::Protocol(
                "server handshake flight exceeds sane bound",
            ));
        }

        if let Some(end) = find_finished_end(&hs_flight)? {
            break end;
        }
    };
    hs_flight.truncate(finished_end);

    // Do NOT send a client Finished or read application data — the probe
    // has everything it needs the instant the server's Finished is seen.
    let scan = scan_flight_shape(&hs_flight)?;

    Ok(CapturedFlight {
        leaf_der: scan.leaf_der,
        template: ServerFlightTemplate {
            server_hello: server_hello_shape,
            encrypted_flight: EncryptedFlightShape {
                record_lengths,
                encrypted_extensions_len: scan.ee_len,
                certificate_len: scan.cert_len,
                certificate_verify_len: scan.cert_verify_len,
                finished_len: scan.finished_len,
            },
            cert_chain: scan.cert_chain,
        },
    })
}

/// REALITY.5c server entry point — the mirror of [`connect`]. Emits the
/// encrypted server flight (via [`emit_server_flight`]) framed to `dest`'s
/// captured record lengths, writes it, drains the client's middlebox CCS +
/// `Finished` (contents UNCHECKED — the outer TLS is zero client-auth by
/// design, exactly as `connect` never checks the server's `Finished`), and
/// returns the server-role [`RealityStream`] on the derived application keys.
/// The ServerHello (REALITY.5b `emit_server_hello`) and `transcript_ch_sh`
/// (raw ClientHello ‖ ServerHello) must already have been produced/sent by
/// the caller (5d).
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    keys: &HandshakeKeys,
    flight_shape: &crate::template::EncryptedFlightShape,
    cert_chain: &crate::template::CertChainShape,
    forged_leaf_der: &[u8],
    cert_signing_key: &p256::ecdsa::SigningKey,
    transcript_ch_sh: &[u8],
) -> Result<RealityStream<S>, Error> {
    let flight = emit_server_flight(
        keys,
        flight_shape,
        cert_chain,
        forged_leaf_der,
        cert_signing_key,
        transcript_ch_sh,
    )?;
    stream.write_all(&flight.wire).await?;

    // Drain the client's CCS + sealed Finished. The client sends a CCS record
    // (skipped) then exactly one application-data record carrying the sealed
    // Finished, opened under the CLIENT handshake key; its contents are not
    // validated (zero client-auth).
    let mut client_hs_seq = 0u64;
    loop {
        let (record_type, mut payload) = read_raw_record(&mut stream).await?;
        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(Error::Protocol(
                "expected the client's sealed Finished record",
            ));
        }
        // Open (and discard) the client Finished — proves it is well-framed
        // under the negotiated key; contents intentionally unchecked.
        record_open(
            &keys.client_key,
            &keys.client_iv,
            client_hs_seq,
            keys.suite,
            record_type,
            &mut payload,
        )?;
        #[expect(
            unused_assignments,
            reason = "written for symmetry with connect()'s analogous server_seq counter \
                      (and to fail closed on overflow before the break); this loop always \
                      exits after the client's single Finished record, so the new value is \
                      never read back"
        )]
        {
            client_hs_seq = client_hs_seq
                .checked_add(1)
                .ok_or(Error::Protocol("client handshake sequence overflow"))?;
        }
        break;
    }

    Ok(RealityStream::server(stream, flight.app_keys))
}

/// An established REALITY/TLS 1.3 connection's application-data stream.
/// Implements `AsyncRead`/`AsyncWrite` over the negotiated application
/// traffic keys, framing plaintext into/out of TLS 1.3 records
/// (RFC 8446 §5.2) with independent per-direction sequence counters. Key
/// update (RFC 8446 §4.6.3) is not implemented — out of scope for the MVP;
/// a long-lived stream that exhausts its 64-bit sequence counter fails
/// closed rather than reusing a nonce.
pub struct RealityStream<S> {
    inner: S,
    /// The negotiated TLS 1.3 cipher suite (`0x1301`/`0x1302`/`0x1303`) —
    /// needed on every seal/open, since `TLS_AES_256_GCM_SHA384` and
    /// `TLS_CHACHA20_POLY1305_SHA256` share a 32-byte key length and so
    /// cannot be told apart from `egress_key`/`ingress_key` alone.
    suite: u16,
    egress_key: Vec<u8>,
    egress_iv: [u8; 12],
    egress_seq: u64,
    ingress_key: Vec<u8>,
    ingress_iv: [u8; 12],
    ingress_seq: u64,
    /// Raw bytes read from `inner` that have not yet been assembled into a
    /// complete TLS record.
    raw_buf: Vec<u8>,
    /// Decrypted application-data plaintext not yet returned to the
    /// `AsyncRead` caller.
    read_buf: Vec<u8>,
    read_pos: usize,
    /// A fully-sealed outgoing record not yet fully written to `inner`.
    write_buf: Vec<u8>,
    write_off: usize,
}

fn protocol_io_error(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn protocol_io_error_owned(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn handshake_io_error(e: handshake::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl<S: AsyncRead + AsyncWrite + Unpin> RealityStream<S> {
    /// Build the CLIENT-role stream (used by [`connect`]): egress sealed with
    /// the client application key, ingress opened with the server's.
    fn client(inner: S, ak: handshake::ApplicationKeys) -> Self {
        RealityStream {
            inner,
            suite: ak.suite,
            egress_key: ak.client_key,
            egress_iv: ak.client_iv,
            egress_seq: 0,
            ingress_key: ak.server_key,
            ingress_iv: ak.server_iv,
            ingress_seq: 0,
            raw_buf: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_off: 0,
        }
    }

    /// Build the SERVER-role stream (used by [`serve`]): egress sealed with the
    /// server application key, ingress opened with the client's — the mirror of
    /// [`client`].
    fn server(inner: S, ak: handshake::ApplicationKeys) -> Self {
        RealityStream {
            inner,
            suite: ak.suite,
            egress_key: ak.server_key,
            egress_iv: ak.server_iv,
            egress_seq: 0,
            ingress_key: ak.client_key,
            ingress_iv: ak.client_iv,
            ingress_seq: 0,
            raw_buf: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_off: 0,
        }
    }

    /// Attempts to decrypt and buffer one more application-data record into
    /// `self.read_buf`, transparently skipping `ChangeCipherSpec` records and
    /// post-handshake handshake-typed records (e.g. `NewSessionTicket`)
    /// interleaved with application data. Returns `Ready(Ok(()))` once at
    /// least one byte of application data has been buffered (or the peer
    /// cleanly closed, in which case `read_buf` is left unchanged and a
    /// subsequent `poll_read` call reports EOF via `Ok(())` with `buf`
    /// untouched).
    fn poll_fill_read_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            while self.raw_buf.len() >= RECORD_HEADER_LEN {
                let len = usize::from(u16::from_be_bytes([self.raw_buf[3], self.raw_buf[4]]));
                let total = RECORD_HEADER_LEN + len;
                if self.raw_buf.len() < total {
                    break;
                }
                let record_type = self.raw_buf[0];
                let mut payload = self.raw_buf[RECORD_HEADER_LEN..total].to_vec();
                self.raw_buf.drain(..total);

                if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
                    continue;
                }
                if record_type != CONTENT_TYPE_APPLICATION_DATA {
                    return Poll::Ready(Err(protocol_io_error(
                        "unexpected outer record type in application-data stream",
                    )));
                }

                let (inner_type, content) = record_open_typed(
                    &self.ingress_key,
                    &self.ingress_iv,
                    self.ingress_seq,
                    self.suite,
                    record_type,
                    &mut payload,
                )
                .map_err(handshake_io_error)?;
                self.ingress_seq = self.ingress_seq.checked_add(1).ok_or_else(|| {
                    protocol_io_error("ingress application sequence counter overflow")
                })?;

                if inner_type == CONTENT_TYPE_APPLICATION_DATA {
                    self.read_buf.extend_from_slice(&content);
                    return Poll::Ready(Ok(()));
                }
                if inner_type == CONTENT_TYPE_ALERT {
                    // RFC 8446 §5.2/§6.1: post-handshake alerts arrive
                    // encrypted, inside TLSInnerPlaintext, exactly like
                    // handshake/application-data content — never as a
                    // distinct outer record type. `content` is
                    // `level(1) || description(1)`.
                    let description = content.get(1).copied();
                    return Poll::Ready(match description {
                        Some(ALERT_DESCRIPTION_CLOSE_NOTIFY) => Ok(()), // clean EOF
                        Some(d) => Err(protocol_io_error_owned(format!(
                            "peer sent a fatal TLS alert (description {d}) instead of application data"
                        ))),
                        None => Err(protocol_io_error("peer sent a truncated TLS alert record")),
                    });
                }
                // Inner type is handshake (e.g. a post-handshake
                // NewSessionTicket) — consumed and ignored, look for the
                // next already-buffered record.
            }

            let mut tmp = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        if self.raw_buf.is_empty() {
                            // Clean EOF at a record boundary.
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "peer closed mid-record",
                        )));
                    }
                    self.raw_buf.extend_from_slice(read_buf.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_pos < this.read_buf.len() {
                let available = this.read_buf.len() - this.read_pos;
                let n = available.min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            let before = this.read_buf.len();
            match this.poll_fill_read_buf(cx) {
                Poll::Ready(Ok(())) => {
                    if this.read_buf.len() == before {
                        // Clean EOF: no new data was buffered.
                        return Poll::Ready(Ok(()));
                    }
                    // New application data buffered; loop to copy it out.
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Drain any previously sealed-but-unsent record before accepting
        // more application-level bytes, to preserve wire ordering.
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_off += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_len = buf.len().min(MAX_APP_RECORD_LEN);
        let chunk = &buf[..chunk_len];
        let sealed = record_seal(
            &this.egress_key,
            &this.egress_iv,
            this.egress_seq,
            this.suite,
            CONTENT_TYPE_APPLICATION_DATA,
            chunk,
        )
        .map_err(handshake_io_error)?;
        this.egress_seq = this
            .egress_seq
            .checked_add(1)
            .ok_or_else(|| protocol_io_error("egress application sequence counter overflow"))?;
        let header = record_header(
            CONTENT_TYPE_APPLICATION_DATA,
            LEGACY_RECORD_VERSION,
            sealed.len(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + sealed.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&sealed);
        this.write_buf = record;
        this.write_off = 0;

        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_off += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break, // remainder stays buffered for the next poll
            }
        }

        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_off += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_off += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
