//! `yip-obf`: the anti-DPI obfuscation envelope. Wraps a datagram body with a
//! keyed, per-packet-randomized mask so an observer without the key sees only
//! uniform-random bytes — no fixed value, no fixed type byte, no fixed size.
//! A keystream XOR (SipHash-CTR), NOT an AEAD: it hides the fingerprint only;
//! content secrecy/integrity remain the inner layer's job (Noise / AEAD /
//! yip-wire tag), which fail-closed on a wrong key.
#![forbid(unsafe_code)]

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

pub const NONCE_LEN: usize = 8;
/// nonce(8) + type(1) + body_len(2) minimum.
pub const MIN_ENVELOPE: usize = NONCE_LEN + 3;

/// The obfuscation `ptype` for a rendezvous-protocol message (`yip_rendezvous::Message`
/// bytes), distinct from `yipd`'s tunnel `PacketType` values (0..=4). Shared by the
/// `yipd` rendezvous client and the `yip-rendezvous` server so both sides mask/unmask
/// the rendezvous-message layer under the same type tag.
pub const RDV_TYPE: u8 = 5;

/// Decoy/junk datagram type (3b). A datagram wrapped under this ptype carries
/// no real data; the receiver drops it silently. Distinct from the tunnel
/// `PacketType` values (0..=4) and `RDV_TYPE` (5).
pub const JUNK_TYPE: u8 = 6;

/// A fast, non-cryptographic xorshift64* PRNG for junk bodies/lengths/counts.
/// Seeded once from the OS RNG; thereafter pure userspace (no syscall per
/// draw). NOT for any security decision — junk bytes are keystream-masked by
/// `obfuscate`, so their content is irrelevant to indistinguishability.
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn from_getrandom() -> Self {
        let mut seed = [0u8; 8];
        getrandom::getrandom(&mut seed).expect("OS RNG");
        // xorshift64* must never have a zero state.
        let s = u64::from_le_bytes(seed) | 1;
        Self { state: s }
    }

    pub fn next_u64(&mut self) -> u64 {
        // xorshift64* (Marsaglia / Vigna).
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish value in `lo..=hi_inclusive`; returns `lo` if the range is
    /// empty/degenerate. Modulo bias is irrelevant for junk sizing.
    pub fn gen_range(&mut self, lo: u64, hi_inclusive: u64) -> u64 {
        if lo >= hi_inclusive {
            return lo;
        }
        let span = hi_inclusive - lo + 1;
        lo + (self.next_u64() % span)
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let bytes = self.next_u64().to_le_bytes();
            let n = core::cmp::min(8, buf.len() - i);
            buf[i..i + n].copy_from_slice(&bytes[..n]);
            i += n;
        }
    }
}

const DOMAIN: &[u8] = b"yip-obf-v1";

/// Derive the 16-byte SipHash key from the network `obf_psk` (or any keying
/// material — the caller also uses this to derive a per-session key from hp_key).
pub fn derive_key(psk: &[u8]) -> [u8; 16] {
    let mut h = Blake2sVar::new(16).expect("16 is a valid blake2s output len");
    h.update(DOMAIN);
    h.update(psk);
    let mut out = [0u8; 16];
    h.finalize_variable(&mut out).expect("len ok");
    out
}

/// SipHash-CTR keystream of `n` bytes: SipHash24(key, nonce ‖ counter_be) per
/// 8-byte block. Same construction as `yip-wire`'s header mask.
fn keystream(key: &[u8; 16], nonce: &[u8; NONCE_LEN], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut counter: u64 = 0;
    while out.len() < n {
        let mut h = SipHasher24::new_with_key(key);
        h.write(nonce);
        h.write(&counter.to_be_bytes());
        out.extend_from_slice(&h.finish().to_be_bytes());
        counter = counter.wrapping_add(1);
    }
    out.truncate(n);
    out
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n).expect("OS RNG");
    n
}

/// Wrap `(ptype, body)` with `pad_len` random trailing padding bytes.
pub fn obfuscate(key: &[u8; 16], ptype: u8, body: &[u8], pad_len: usize) -> Vec<u8> {
    let nonce = random_nonce();
    let body_len = u16::try_from(body.len()).expect("body fits u16");
    // plaintext region: type(1) ‖ body_len(2) ‖ body ‖ padding
    let mut region = Vec::with_capacity(3 + body.len() + pad_len);
    region.push(ptype);
    region.extend_from_slice(&body_len.to_be_bytes());
    region.extend_from_slice(body);
    region.resize(region.len() + pad_len, 0); // padding masks to random anyway
    let ks = keystream(key, &nonce, region.len());
    for (b, k) in region.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
    let mut out = Vec::with_capacity(NONCE_LEN + region.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&region);
    out
}

/// Recover `(ptype, body)`, or `None` if too short / length-inconsistent.
pub fn deobfuscate(key: &[u8; 16], dg: &[u8]) -> Option<(u8, Vec<u8>)> {
    if dg.len() < MIN_ENVELOPE {
        return None;
    }
    let nonce: [u8; NONCE_LEN] = dg[..NONCE_LEN].try_into().ok()?;
    let masked = &dg[NONCE_LEN..];
    let ks = keystream(key, &nonce, masked.len());
    let mut region = masked.to_vec();
    for (b, k) in region.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
    let ptype = *region.first()?;
    let body_len = usize::from(u16::from_be_bytes(region.get(1..3)?.try_into().ok()?));
    let body = region.get(3..3 + body_len)?.to_vec();
    Some((ptype, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_type_and_body() {
        let key = derive_key(b"network-secret");
        let dg = obfuscate(&key, 2, b"hello world payload", 17);
        let (ptype, body) = deobfuscate(&key, &dg).expect("round-trips");
        assert_eq!(ptype, 2);
        assert_eq!(body, b"hello world payload");
    }

    #[test]
    fn wrong_key_does_not_recover_body() {
        let k1 = derive_key(b"secret-a");
        let k2 = derive_key(b"secret-b");
        let dg = obfuscate(&k1, 2, b"the real body", 8);
        // Wrong key yields either None (inconsistent length) or a garbage body,
        // but MUST NOT recover the real (ptype=2, "the real body").
        match deobfuscate(&k2, &dg) {
            None => {}
            Some((pt, body)) => assert!(pt != 2 || body != b"the real body"),
        }
    }

    #[test]
    fn no_byte_position_is_constant_across_packets() {
        // The core anti-DPI property: obfuscate many datagrams of the SAME
        // (type, body) and assert no byte offset holds a constant value across
        // them (random nonce + keystream => every position varies). This is the
        // whole-datagram generalization of yip-wire's no-constant-header test.
        let key = derive_key(b"k");
        let n = 512usize;
        let dgs: Vec<Vec<u8>> = (0..n)
            .map(|_| obfuscate(&key, 2, b"same body every time", 4))
            .collect();
        let len = dgs[0].len();
        for pos in 0..len {
            let first = dgs[0][pos];
            let all_same = dgs.iter().all(|d| d.len() == len && d[pos] == first);
            assert!(
                !all_same,
                "byte position {pos} is constant across packets — a DPI signature"
            );
        }
    }

    #[test]
    fn deobfuscate_rejects_truncation_and_garbage() {
        let key = derive_key(b"k");
        assert_eq!(deobfuscate(&key, &[]), None);
        assert_eq!(deobfuscate(&key, &[0u8; 3]), None); // < MIN_ENVELOPE
        let mut dg = obfuscate(&key, 1, b"abc", 5);
        dg.truncate(dg.len() - 1); // corrupt length consistency
                                   // Must not panic; returns None or a shorter/garbage body, never OOB.
        let _ = deobfuscate(&key, &dg);
    }

    #[test]
    fn pad_len_changes_size_but_not_recovered_body() {
        let key = derive_key(b"k");
        let a = obfuscate(&key, 0, b"x", 0);
        let b = obfuscate(&key, 0, b"x", 200);
        assert!(b.len() > a.len());
        assert_eq!(deobfuscate(&key, &a).unwrap().1, b"x");
        assert_eq!(deobfuscate(&key, &b).unwrap().1, b"x");
    }

    #[test]
    fn junk_type_is_distinct_from_other_ptypes() {
        // 0..=4 are yipd PacketType, 5 is RDV_TYPE.
        assert_eq!(JUNK_TYPE, 6);
        assert_ne!(JUNK_TYPE, RDV_TYPE);
    }

    #[test]
    fn xorshift_gen_range_stays_in_bounds_and_varies() {
        let mut r = XorShift64::from_getrandom();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let v = r.gen_range(3, 12);
            assert!((3..=12).contains(&v), "in range");
            seen.insert(v);
        }
        assert!(seen.len() > 3, "gen_range must actually vary, got {seen:?}");
        // degenerate range returns lo
        assert_eq!(r.gen_range(7, 7), 7);
        assert_eq!(r.gen_range(9, 4), 9);
    }

    #[test]
    fn xorshift_fill_produces_varied_bytes() {
        let mut r = XorShift64::from_getrandom();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        r.fill(&mut a);
        r.fill(&mut b);
        assert_ne!(a, b, "consecutive fills differ");
        assert!(a.iter().any(|&x| x != 0), "not all-zero");
    }

    #[test]
    fn junk_datagram_deobfuscates_to_junk_type() {
        let key = derive_key(b"net");
        let mut r = XorShift64::from_getrandom();
        let mut body = [0u8; 128];
        r.fill(&mut body);
        let dg = obfuscate(&key, JUNK_TYPE, &body, 7);
        let (pt, _b) = deobfuscate(&key, &dg).expect("round-trips");
        assert_eq!(pt, JUNK_TYPE);
    }
}
