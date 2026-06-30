//! Shared fixtures for the yip hot-path micro-benchmarks.
use yip_crypto::{generate_keypair, Handshake, Session};

/// Build an established initiator/responder session pair for sealing/opening benches.
pub fn established_pair() -> (Session, Session) {
    let rk = generate_keypair();
    let ik = generate_keypair();
    let mut ini = Handshake::initiator(&ik.private, &rk.public).expect("init");
    let mut res = Handshake::responder(&rk.private).expect("resp");
    let m1 = ini.write_message().expect("m1");
    res.read_message(&m1).expect("read m1");
    let m2 = res.write_message().expect("m2");
    ini.read_message(&m2).expect("read m2");
    (
        ini.into_session().expect("a"),
        res.into_session().expect("b"),
    )
}

/// A representative small inner packet (an IPv4 UDP datagram, DSCP EF).
pub fn sample_inner(len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len.max(20)];
    p[0] = 0x45;
    p[1] = 46 << 2;
    p[9] = 17;
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixtures_build() {
        let (mut a, mut b) = established_pair();
        let s = a.seal(b"x").unwrap();
        assert_eq!(b.open(s.counter, &s.ciphertext).unwrap(), b"x");
        assert_eq!(sample_inner(64).len(), 64);
    }
}
