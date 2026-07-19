#![forbid(unsafe_code)]

//! Standalone wire-witness tool for the 9a rekey netns money test
//! (`bin/yipd/tests/run-netns-rekey.sh`): counts genuinely distinct,
//! completed Noise-IK rekey handshake rounds captured on the wire, as the
//! rigorous proof that "the on-wire `conn_tag` actually rotates per
//! epoch" — without needing (and, as explained below, without being ABLE)
//! to recover the actual `conn_tag` value of a live session from a passive
//! capture.
//!
//! # Two dead ends, kept here as the record of why this is the design
//!
//! 1. **Diffing the raw masked header bytes is vacuous.** `crates/yip-wire`'s
//!    `Codec::frame` XORs the entire 15-byte logical header — including the
//!    8 `conn_tag` bytes — under a keystream reseeded by that *specific
//!    frame's own* auth tag (see also `bin/yipd/src/peer_manager.rs`'s "UDP
//!    demux: why routing is by source address, not raw conn_tag bytes" doc
//!    comment, which independently notes the same fact). The visible bytes
//!    at `dg[1..9]` therefore differ on *every* Data datagram, even two
//!    datagrams of the exact same epoch — a "capture dg[1..9], assert more
//!    than one distinct value" check would read >1 in a single-epoch,
//!    zero-rekey run too. `run-netns-rekey.sh` still reports this count
//!    (`RAW_DISTINCT_HEADER_PREFIXES`), labeled non-gating/informational.
//!
//! 2. **Passively re-deriving the real session keys is cryptographically
//!    impossible, by design — an earlier version of this tool tried, and
//!    failed 100% of the time, which is how this doc comment came to be
//!    written.** The idea was: replay each captured `[HandshakeInit]`
//!    through a fresh responder-role `yip_crypto::Handshake` (this test
//!    generates both peers' static keys, so it has both `local_private`s),
//!    then re-derive `(auth_key, hp_key, conn_tag)` from the resulting
//!    `channel_binding` the same way `wire_glue::derive_wire_keys` /
//!    `dataplane::conn_tag_from_keys` do. This is unsound: Noise_IK's
//!    responder generates a FRESH RANDOM EPHEMERAL KEY of its own while
//!    producing message 2 (pattern `<- e, ee, se`), and that ephemeral
//!    feeds the `ee`/`se` Diffie-Hellman terms mixed into the transcript
//!    hash. A locally-replayed responder draws its OWN random ephemeral,
//!    not the real peer's — so it derives a syntactically valid but
//!    cryptographically DIFFERENT session every time. Recovering the real
//!    session from a passive capture would require the real ephemeral
//!    PRIVATE key, which is never transmitted and never stored anywhere
//!    this test can reach — that is Noise's forward-secrecy property doing
//!    exactly its job. Trying to work around it (e.g. by MITM-ing the
//!    daemons, or by having yipd leak its ephemeral) is out of scope for a
//!    test-only task and is not attempted here.
//!
//! # What this tool checks instead — sound, and still on-wire
//!
//! Noise_IK's very first token of *both* messages is `e`: the sender's
//! ephemeral public key, written to the message IN CLEARTEXT (Noise mixes
//! it into the running hash but never encrypts it — there is no cipher key
//! yet when writing the first token of message 1, and message 2's leading
//! `e` is likewise unencrypted per the Noise spec). So the first 32 bytes
//! after the 1-byte `PacketType` prefix of every `[HandshakeInit]` /
//! `[HandshakeResp]` datagram (`bin/yipd/src/handshake.rs`'s wire format)
//! are a raw, unencrypted, freshly-random 32-byte key — visible to any
//! passive observer, no key material needed at all. Counting *distinct*
//! cleartext ephemeral keys across the run's `[HandshakeInit]`/
//! `[HandshakeResp]` datagrams is therefore direct, unambiguous, on-wire
//! evidence of N independently-completed Noise-IK handshake rounds (a
//! replay/retransmit of the SAME round reuses the SAME ephemeral, since
//! `handshake.rs`'s retry logic resends the same message rather than
//! restarting the handshake — see `PeerManager`'s
//! `REKEY_ATTEMPT_TIME`/retransmit comments — so retransmits collapse to
//! one distinct value, not falsely inflating the count).
//!
//! From there, the rest is a mathematical, not empirical, argument:
//! `conn_tag = conn_tag_from_keys(auth_key, hp_key)`, and
//! `(auth_key, hp_key) = derive_wire_keys(channel_binding)`, and
//! `channel_binding` is (by Noise's definition of the transcript hash) a
//! function that mixes in both ephemeral public keys and the `ee` shared
//! secret computed from them. Two handshake rounds with distinct ephemeral
//! keys yield, with the DH problem's usual cryptographic-strength
//! probability (not just "usually" — collision would break X25519), a
//! distinct `ee` term, hence a distinct `channel_binding`, hence a distinct
//! `conn_tag`. So N distinct cleartext ephemerals is a rigorous proof of N
//! distinct on-wire `conn_tag`s, even though — per the dead end above —
//! this tool (or any passive observer) can never learn what those N values
//! actually are.
//!
//! Usage:
//!   rekey_epoch_witness <pcap>
//!
//! Output (stdout), consumed by `run-netns-rekey.sh`:
//!   HANDSHAKE_INIT_PKTS=<n>          total captured [HandshakeInit] datagrams
//!   HANDSHAKE_RESP_PKTS=<n>          total captured [HandshakeResp] datagrams
//!   DISTINCT_INIT_EPHEMERALS=<n>     distinct cleartext initiator ephemerals
//!   DISTINCT_RESP_EPHEMERALS=<n>     distinct cleartext responder ephemerals
//!   COMPLETED_ROUNDS=<n>             min(the two distinct counts above) --
//!                                    a round needs both a distinct Init AND
//!                                    a distinct Resp ephemeral to have
//!                                    produced a fresh conn_tag on both ends
//!   RAW_DISTINCT_HEADER_PREFIXES=<n> informational only, see dead end #1
//!
//! Run: `cargo run --release -p yipd --example rekey_epoch_witness -- <pcap>`

use std::env;
use std::fs;

// ── minimal classic-pcap + Ethernet/IPv4/UDP parsing (no new dependency) ───────

struct UdpPkt {
    payload: Vec<u8>,
}

fn read_u32(b: &[u8], le: bool) -> u32 {
    let a: [u8; 4] = b.try_into().expect("4 bytes");
    if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    }
}

/// Parse a classic (non-pcapng) pcap file, as written by `tcpdump -w`.
/// Supports both byte orders and both micro/nanosecond-timestamp magic
/// variants (only the byte order matters here -- timestamps are unused).
fn parse_pcap(data: &[u8]) -> Vec<UdpPkt> {
    assert!(data.len() >= 24, "pcap file too short for a global header");
    let le = match &data[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        magic => panic!("unrecognized pcap magic: {magic:02x?}"),
    };
    let mut out = Vec::new();
    let mut off = 24usize;
    while off + 16 <= data.len() {
        let incl_len = read_u32(&data[off + 8..off + 12], le) as usize;
        off += 16;
        if off + incl_len > data.len() {
            break;
        }
        let pkt = &data[off..off + incl_len];
        off += incl_len;
        if let Some(u) = parse_eth_ipv4_udp(pkt) {
            out.push(u);
        }
    }
    out
}

/// Strip a 14-byte Ethernet header, an IPv4 header (variable IHL), and an
/// 8-byte UDP header, returning the destination port and UDP payload bytes.
/// Returns `None` for anything that is not an Ethernet/IPv4/UDP frame.
fn parse_eth_ipv4_udp(pkt: &[u8]) -> Option<UdpPkt> {
    if pkt.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    if ethertype != 0x0800 {
        return None; // not IPv4
    }
    let ip = &pkt[14..];
    if ip.len() < 20 {
        return None;
    }
    let ihl = (ip[0] & 0x0F) as usize * 4;
    if ihl < 20 || ip.len() < ihl + 8 {
        return None;
    }
    let proto = ip[9];
    if proto != 17 {
        return None; // not UDP
    }
    let udp = &ip[ihl..];
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp.len() < 8 {
        return None;
    }
    let payload_end = udp_len.min(udp.len());
    if payload_end < 8 {
        return None;
    }
    Some(UdpPkt {
        payload: udp[8..payload_end].to_vec(),
    })
}

const TYPE_HANDSHAKE_INIT: u8 = 0;
const TYPE_HANDSHAKE_RESP: u8 = 1;
const TYPE_DATA: u8 = 2;
/// 1-byte PacketType prefix + 32-byte cleartext Noise ephemeral pubkey.
const MIN_HANDSHAKE_LEN: usize = 33;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: rekey_epoch_witness <pcap>");
        std::process::exit(2);
    }
    let pcap_path = &args[1];

    let data = fs::read(pcap_path).unwrap_or_else(|e| panic!("read {pcap_path}: {e}"));
    let pkts = parse_pcap(&data);

    let mut init_ephemerals: Vec<[u8; 32]> = Vec::new();
    let mut resp_ephemerals: Vec<[u8; 32]> = Vec::new();
    let mut init_pkt_count = 0u32;
    let mut resp_pkt_count = 0u32;

    for p in &pkts {
        if p.payload.len() < MIN_HANDSHAKE_LEN {
            continue;
        }
        let ephemeral: [u8; 32] = p.payload[1..33].try_into().expect("32 bytes");
        match p.payload[0] {
            TYPE_HANDSHAKE_INIT => {
                init_pkt_count += 1;
                if !init_ephemerals.contains(&ephemeral) {
                    init_ephemerals.push(ephemeral);
                }
            }
            TYPE_HANDSHAKE_RESP => {
                resp_pkt_count += 1;
                if !resp_ephemerals.contains(&ephemeral) {
                    resp_ephemerals.push(ephemeral);
                }
            }
            _ => {}
        }
    }

    let completed_rounds = init_ephemerals.len().min(resp_ephemerals.len());

    println!("HANDSHAKE_INIT_PKTS={init_pkt_count}");
    println!("HANDSHAKE_RESP_PKTS={resp_pkt_count}");
    println!("DISTINCT_INIT_EPHEMERALS={}", init_ephemerals.len());
    println!("DISTINCT_RESP_EPHEMERALS={}", resp_ephemerals.len());
    println!("COMPLETED_ROUNDS={completed_rounds}");

    // Informational only, NOT itself a rotation proof (see dead end #1
    // above): the raw masked dg[1..9] bytes on Data frames, deduplicated.
    // Expect this to be large (close to the Data-datagram count) even in a
    // hypothetical single-epoch run, since the header mask is reseeded by
    // each frame's own auth tag -- it is not a stable per-epoch identifier.
    let mut raw_prefixes: Vec<[u8; 8]> = Vec::new();
    for p in &pkts {
        if p.payload.len() < 9 || p.payload[0] != TYPE_DATA {
            continue;
        }
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&p.payload[1..9]);
        if !raw_prefixes.contains(&prefix) {
            raw_prefixes.push(prefix);
        }
    }
    println!(
        "RAW_DISTINCT_HEADER_PREFIXES={} (informational only -- NOT proof of rotation; see module doc)",
        raw_prefixes.len()
    );
}
