//! De-risk spike for fast AEAD (Task 1): prove `ring`'s ChaCha20-Poly1305, driven with
//! snow's extracted transport keys and the Noise nonce convention, is byte-identical to
//! snow's own `write_message`, and measure the speedup.
//!
//! Key extraction: `snow::HandshakeState::dangerously_get_raw_split()` (gated behind the
//! `risky-raw-split` feature, enabled for this spike only in Cargo.toml). It returns
//! `([u8; 32], [u8; 32])`. Per snow 0.10's source
//! (`stateless_transportstate.rs::write_message`/`read_message`), the mapping is:
//!
//!   - element 0 = initiator's send key = responder's receive key
//!   - element 1 = responder's send key = initiator's receive key
//!
//! `dangerously_get_raw_split` is literally the same HKDF-derived bytes `split()` uses
//! internally to build the real transport `CipherState`s (see `SymmetricState::split`,
//! which calls `split_raw` and truncates) - so the extracted keys are guaranteed to be the
//! same keys snow's own transport state seals with.
//!
//! Run: cargo run --release -p yip-bench --example aead_spike
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::hint::black_box;
use std::time::Instant;

/// Same parameter string yip_crypto::Handshake uses (Noise IK, X25519, ChaCha20-Poly1305,
/// BLAKE2s). Hardcoded here because yip_crypto keeps its `NOISE_PARAMS` constant private and
/// keeps snow's `HandshakeState` behind its own `Handshake` wrapper (no raw-split escape
/// hatch) - this spike drives snow directly instead of extending yip_crypto's public API for
/// a throwaway measurement.
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Noise ChaChaPoly nonce: 4 zero bytes ++ 8-byte little-endian counter (confirmed against
/// snow's `CipherChaChaPoly::encrypt`, which does `nonce.to_le_bytes()` into bytes[4..]).
fn noise_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

fn main() {
    // --- 1. Complete a real initiator<->responder handshake, driven directly through snow
    //        (mirrors what yip_crypto::Handshake does internally) so we can reach
    //        `dangerously_get_raw_split()`, which yip_crypto does not expose. ---
    let resp_kp = snow::Builder::new(NOISE_PARAMS.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let init_kp = snow::Builder::new(NOISE_PARAMS.parse().unwrap())
        .generate_keypair()
        .unwrap();

    let mut ini = snow::Builder::new(NOISE_PARAMS.parse().unwrap())
        .local_private_key(&init_kp.private)
        .unwrap()
        .remote_public_key(&resp_kp.public)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut res = snow::Builder::new(NOISE_PARAMS.parse().unwrap())
        .local_private_key(&resp_kp.private)
        .unwrap()
        .build_responder()
        .unwrap();

    let mut buf = [0u8; 4096];
    let n = ini.write_message(&[], &mut buf).unwrap();
    let msg1 = buf[..n].to_vec();
    let n = res.read_message(&msg1, &mut buf).unwrap();
    let _ = &buf[..n];
    let n = res.write_message(&[], &mut buf).unwrap();
    let msg2 = buf[..n].to_vec();
    let n = ini.read_message(&msg2, &mut buf).unwrap();
    let _ = &buf[..n];
    assert!(ini.is_handshake_finished() && res.is_handshake_finished());

    // Extract keys from BOTH sides before consuming into transport mode, and assert they
    // agree - a sanity check that the split is deterministic from the (already-authenticated)
    // transcript, independent of which peer calls it.
    let (ini_k0, ini_k1) = ini.dangerously_get_raw_split();
    let (res_k0, res_k1) = res.dangerously_get_raw_split();
    assert_eq!(
        ini_k0, res_k0,
        "both peers derive the same k0 (initiator send key)"
    );
    assert_eq!(
        ini_k1, res_k1,
        "both peers derive the same k1 (responder send key)"
    );

    // k_send is the initiator's send key = responder's recv key (element 0 of the split).
    let k_send = ini_k0;

    let transport = ini.into_stateless_transport_mode().unwrap();

    // --- 2. Byte-identity: ring seal with the extracted key + Noise nonce vs snow's own
    //        write_message, for several counters and a representative inner-packet payload. ---
    let plaintext = {
        // Representative inner IPv4/UDP datagram, DSCP EF - matches yip_bench::sample_inner.
        let mut p = vec![0u8; 1184];
        p[0] = 0x45;
        p[1] = 46 << 2;
        p[9] = 17;
        p
    };

    let ring_key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &k_send).unwrap());

    let mut mismatch: Option<u64> = None;
    for ctr in 0..8u64 {
        let mut snow_out = vec![0u8; plaintext.len() + 16];
        let sn = transport
            .write_message(ctr, &plaintext, &mut snow_out)
            .unwrap();
        snow_out.truncate(sn);

        let mut ring_out = plaintext.clone();
        ring_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(noise_nonce(ctr)),
                Aad::empty(),
                &mut ring_out,
            )
            .unwrap();

        if ring_out != snow_out {
            mismatch = Some(ctr);
            break;
        }
    }
    match mismatch {
        None => println!(
            "byte-identity: OK (counters 0..8, {}-byte plaintext)",
            plaintext.len()
        ),
        Some(ctr) => println!("byte-identity: MISMATCH at counter {ctr}"),
    }

    // --- 3. Timing (release, black_box'd). ---
    let iters = 50_000u32;

    // snow baseline: write_message into a fresh-length buffer each call.
    let t = Instant::now();
    let mut snow_buf = vec![0u8; plaintext.len() + 16];
    for i in 0..iters {
        let n = transport
            .write_message(u64::from(i), black_box(&plaintext), &mut snow_buf)
            .unwrap();
        black_box(&snow_buf[..n]);
    }
    let snow_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    // ring seal, fresh Vec allocated per call (mirrors naive "just call it" usage).
    let t = Instant::now();
    for i in 0..iters {
        let mut out = black_box(&plaintext).clone();
        ring_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(noise_nonce(u64::from(i))),
                Aad::empty(),
                &mut out,
            )
            .unwrap();
        black_box(&out);
    }
    let ring_alloc_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    // ring seal, buffer reused across calls (no per-call heap allocation): keep one Vec at
    // ciphertext capacity, refill the plaintext prefix and truncate the tag off before each
    // call so `seal_in_place_append_tag`'s internal `Extend` push reuses existing capacity.
    let t = Instant::now();
    let mut reused = plaintext.clone();
    reused.reserve_exact(16);
    for i in 0..iters {
        reused.truncate(plaintext.len());
        reused.copy_from_slice(black_box(&plaintext));
        ring_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(noise_nonce(u64::from(i))),
                Aad::empty(),
                &mut reused,
            )
            .unwrap();
        black_box(&reused);
    }
    let ring_reused_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);

    println!("snow write_message      : {snow_us:.3} us/op");
    println!("ring seal (fresh Vec)   : {ring_alloc_us:.3} us/op");
    println!("ring seal (reused buf)  : {ring_reused_us:.3} us/op");
    println!(
        "no-alloc delta          : {:.3} us/op ({:.1}% of fresh-Vec cost)",
        ring_alloc_us - ring_reused_us,
        100.0 * (ring_alloc_us - ring_reused_us) / ring_alloc_us
    );
    println!(
        "ring vs snow speedup    : {:.2}x (fresh Vec), {:.2}x (reused buf)",
        snow_us / ring_alloc_us,
        snow_us / ring_reused_us
    );
}
