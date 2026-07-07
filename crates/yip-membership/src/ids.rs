//! Key-derived identifiers, matching 2a's `node_addr` and 2b's `node_id`.
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;
use std::net::Ipv6Addr;

pub type NodeId = [u8; 16];

pub fn node_id(pubkey: &[u8; 32]) -> NodeId {
    let mut h = Blake2sVar::new(16).expect("16 valid");
    h.update(b"yip-rdv-v1");
    h.update(pubkey);
    let mut out = [0u8; 16];
    h.finalize_variable(&mut out).expect("len ok");
    out
}

pub fn node_addr(pubkey: &[u8; 32]) -> Ipv6Addr {
    let mut h = Blake2sVar::new(15).expect("15 valid");
    h.update(b"yip-addr-v1");
    h.update(pubkey);
    let mut d = [0u8; 15];
    h.finalize_variable(&mut d).expect("len ok");
    let mut o = [0u8; 16];
    o[0] = 0xfd;
    o[1..].copy_from_slice(&d);
    Ipv6Addr::from(o)
}
