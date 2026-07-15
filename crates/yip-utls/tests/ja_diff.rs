//! JA3/JA4 fixture diff test (REALITY.2 Task 4): locks the crafted
//! ClientHello's JA4 fingerprint to a real Chrome 150 capture (stable across
//! the per-connection extension-order permutation) and proves the crafter's
//! JA3 actually varies connection-to-connection like real Chrome does — see
//! `docs/superpowers/specs/reality-2-chrome150-fingerprint.txt`.

use yip_utls::{hello, ja};

struct Seed(u64);

impl hello::RandomSource for Seed {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *x = (self.0 >> 33) as u8;
        }
    }
}

#[test]
fn crafted_hello_matches_chrome150_ja4_and_permutes_ja3() {
    let params = hello::ClientHelloParams {
        sni: "www.apple.com".into(),
        key_share_x25519_pub: [0x11; 32],
        key_share_mlkem_ek: vec![0x44; 1184],
        legacy_session_id: [0x22; 32],
        client_random: [0x33; 32],
    };

    // JA4 is STABLE across Chrome's per-connection extension permutation — lock it.
    let m1 = hello::craft(&params, &mut Seed(1));
    let m2 = hello::craft(&params, &mut Seed(2));
    assert_eq!(
        ja::ja4(&m1).unwrap(),
        "t13d1516h2_8daaf6152771_806a8c22fdea"
    );
    assert_eq!(
        ja::ja4(&m2).unwrap(),
        "t13d1516h2_8daaf6152771_806a8c22fdea"
    );

    // JA3 is order-sensitive; real Chrome's varies every connection, so ours MUST too
    // (a fixed JA3 is MORE fingerprintable than real Chrome — defeats the purpose).
    assert_ne!(
        ja::ja3_hash(&m1).unwrap(),
        ja::ja3_hash(&m2).unwrap(),
        "extension order must permute per connection like real Chrome"
    );

    // Same seed is reproducible (deterministic shuffle) — for byte-exact debugging.
    let m1b = hello::craft(&params, &mut Seed(1));
    assert_eq!(m1, m1b);
}
