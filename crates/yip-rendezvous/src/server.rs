//! Pure rendezvous/relay server state machine: soft-state registration with
//! TTL, per-source rate limiting, and blind relay forwarding. No I/O — the
//! `bin/yip-rendezvous` loop owns the socket and the clock.
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::proto::{Message, NodeId};

/// Registration lifetime; clients refresh well within this.
pub const REG_TTL_MS: u64 = 60_000;
/// Hard cap on concurrent registrations (memory bound).
pub const MAX_REGISTRATIONS: usize = 65_536;
/// Hard cap on distinct source addresses tracked for rate limiting (memory
/// bound). Set to 2x `MAX_REGISTRATIONS` as generous headroom for legitimate
/// distinct sources (registered peers plus in-flight lookups/relays from
/// addresses that never register) while still bounding memory against a
/// flood of packets from many distinct (or spoofed) source addresses.
pub const MAX_RATE_ENTRIES: usize = 131_072;
/// Rate-limit window and per-source message cap within it.
pub const RATE_WINDOW_MS: u64 = 1_000;
pub const MAX_MSGS_PER_WINDOW: usize = 64;

struct Reg {
    addr: SocketAddr,
    expiry_ms: u64,
    last_counter: u64,
}

struct Rate {
    window_start_ms: u64,
    count: usize,
}

/// Soft-state rendezvous + blind relay. Keyed by `NodeId`.
pub struct RendezvousServer {
    regs: HashMap<NodeId, Reg>,
    rates: HashMap<SocketAddr, Rate>,
    forwarded: u64,
}

impl RendezvousServer {
    pub fn new(_now_ms: u64) -> Self {
        Self {
            regs: HashMap::new(),
            rates: HashMap::new(),
            forwarded: 0,
        }
    }

    pub fn forwarded_count(&self) -> u64 {
        self.forwarded
    }

    /// True iff `node` has a live (unexpired) registration. Used by the TLS
    /// front to distinguish an upgraded tunnel client from a decoy request.
    pub fn is_registered(&self, node: &NodeId, now_ms: u64) -> bool {
        self.regs.get(node).is_some_and(|r| r.expiry_ms > now_ms)
    }

    /// True iff `src` is within its per-window budget (and records the hit).
    fn rate_ok(&mut self, src: SocketAddr, now_ms: u64) -> bool {
        // At capacity, refuse to start tracking a brand-new source rather than
        // growing the map unbounded (e.g. a flood of packets from many
        // distinct/spoofed addresses): treat it as over-limit and drop it.
        // Actively-tracked sources are never evicted mid-window by this
        // guard, and `sweep` continuously frees entries whose window has
        // aged out, so capacity is self-healing under normal load.
        if self.rates.len() >= MAX_RATE_ENTRIES && !self.rates.contains_key(&src) {
            return false;
        }
        let r = self.rates.entry(src).or_insert(Rate {
            window_start_ms: now_ms,
            count: 0,
        });
        if now_ms.saturating_sub(r.window_start_ms) >= RATE_WINDOW_MS {
            r.window_start_ms = now_ms;
            r.count = 0;
        }
        if r.count >= MAX_MSGS_PER_WINDOW {
            return false;
        }
        r.count += 1;
        true
    }

    /// Evict expired registrations. Call on a timer from the socket loop.
    pub fn sweep(&mut self, now_ms: u64) {
        self.regs.retain(|_, reg| reg.expiry_ms > now_ms);
        // Rate windows are cheap; drop stale ones opportunistically.
        self.rates
            .retain(|_, r| now_ms.saturating_sub(r.window_start_ms) < RATE_WINDOW_MS);
    }

    /// Process one received message; return datagrams to send as `(dst, msg)`.
    pub fn handle(
        &mut self,
        src: SocketAddr,
        msg: Message,
        now_ms: u64,
    ) -> Vec<(SocketAddr, Message)> {
        if !self.rate_ok(src, now_ms) {
            return Vec::new();
        }
        match msg {
            Message::Register { node, counter } => {
                // Reject a stale/replayed registration: the counter must be
                // strictly greater than the last accepted one for this node.
                // (An unknown node is first-seen and always accepted.)
                if let Some(existing) = self.regs.get(&node) {
                    if existing.expiry_ms > now_ms && counter <= existing.last_counter {
                        return Vec::new();
                    }
                }
                if self.regs.len() >= MAX_REGISTRATIONS && !self.regs.contains_key(&node) {
                    return Vec::new(); // at capacity; refuse new ids (existing refresh ok)
                }
                self.regs.insert(
                    node,
                    Reg {
                        addr: src,
                        expiry_ms: now_ms.saturating_add(REG_TTL_MS),
                        last_counter: counter,
                    },
                );
                Vec::new()
            }
            Message::Lookup { node } => match self.regs.get(&node) {
                Some(reg) if reg.expiry_ms > now_ms => {
                    let peer_addr = reg.addr;
                    let mut out = vec![(
                        src,
                        Message::PeerInfo {
                            node,
                            reflexive: peer_addr,
                        },
                    )];
                    // Tell the looked-up peer to punch back toward the requester.
                    out.push((
                        peer_addr,
                        Message::PunchHint {
                            node,
                            reflexive: src,
                        },
                    ));
                    out
                }
                _ => vec![(src, Message::NotFound { node })],
            },
            Message::RelaySend {
                src: sender,
                dst,
                payload,
            } => match self.regs.get(&dst) {
                Some(reg) if reg.expiry_ms > now_ms => {
                    self.forwarded += 1;
                    vec![(
                        reg.addr,
                        Message::RelayDeliver {
                            src: sender,
                            payload,
                        },
                    )]
                }
                _ => Vec::new(), // dst unknown: drop
            },
            // Server never receives these (they are server->client); ignore.
            Message::PeerInfo { .. }
            | Message::NotFound { .. }
            | Message::PunchHint { .. }
            | Message::RelayDeliver { .. } => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{node_id, Message};
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Synthesize a distinct `SocketAddr` from an index, without relying on
    /// string formatting (kept fast for large-`i` loops) or `as` casts.
    fn synth_addr(i: u32) -> SocketAddr {
        let a = u8::try_from((i >> 24) & 0xff).expect("byte in range");
        let b = u8::try_from((i >> 16) & 0xff).expect("byte in range");
        let c = u8::try_from((i >> 8) & 0xff).expect("byte in range");
        let d = u8::try_from(i & 0xff).expect("byte in range");
        SocketAddr::from((std::net::Ipv4Addr::new(a, b, c, d), 40_000))
    }

    #[test]
    fn register_then_lookup_returns_observed_reflexive() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        let _b = node_id(&[2u8; 32]); // documents which peer looks A up; id itself unused
                                      // A registers from its observed reflexive addr.
        let out = s.handle(
            addr("198.51.100.7:41000"),
            Message::Register {
                node: a,
                counter: 1,
            },
            0,
        );
        assert!(out.is_empty(), "register produces no reply");
        // B looks up A: gets A's reflexive via PeerInfo, and A gets a PunchHint
        // carrying B's reflexive.
        let out = s.handle(addr("203.0.113.9:52000"), Message::Lookup { node: a }, 10);
        // one reply to B (PeerInfo), one to A (PunchHint)
        assert!(out.iter().any(|(d, m)| *d == addr("203.0.113.9:52000")
            && matches!(m, Message::PeerInfo { node, reflexive } if *node == a && *reflexive == addr("198.51.100.7:41000"))));
        assert!(out.iter().any(|(d, m)| *d == addr("198.51.100.7:41000")
            && matches!(m, Message::PunchHint { reflexive, .. } if *reflexive == addr("203.0.113.9:52000"))));
    }

    #[test]
    fn lookup_unregistered_returns_notfound() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        let out = s.handle(addr("203.0.113.9:52000"), Message::Lookup { node: a }, 0);
        assert_eq!(
            out,
            vec![(addr("203.0.113.9:52000"), Message::NotFound { node: a })]
        );
    }

    #[test]
    fn ttl_expiry_evicts_registration() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        s.handle(
            addr("198.51.100.7:41000"),
            Message::Register {
                node: a,
                counter: 1,
            },
            0,
        );
        s.sweep(REG_TTL_MS + 1);
        let out = s.handle(
            addr("203.0.113.9:52000"),
            Message::Lookup { node: a },
            REG_TTL_MS + 2,
        );
        assert!(matches!(out.as_slice(), [(_, Message::NotFound { .. })]));
    }

    #[test]
    fn relay_forwards_to_registered_dst_and_counts() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        let b = node_id(&[2u8; 32]);
        s.handle(
            addr("198.51.100.7:41000"),
            Message::Register {
                node: a,
                counter: 1,
            },
            0,
        ); // A registered
           // B relays a payload to A -> A gets RelayDeliver{src=B, payload}.
        let out = s.handle(
            addr("203.0.113.9:52000"),
            Message::RelaySend {
                src: b,
                dst: a,
                payload: vec![9, 9],
            },
            5,
        );
        assert_eq!(
            out,
            vec![(
                addr("198.51.100.7:41000"),
                Message::RelayDeliver {
                    src: b,
                    payload: vec![9, 9]
                }
            )]
        );
        assert_eq!(s.forwarded_count(), 1);
    }

    #[test]
    fn relay_to_unregistered_dst_drops_no_forward() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        let b = node_id(&[2u8; 32]);
        let out = s.handle(
            addr("203.0.113.9:52000"),
            Message::RelaySend {
                src: b,
                dst: a,
                payload: vec![1],
            },
            0,
        );
        assert!(out.is_empty());
        assert_eq!(s.forwarded_count(), 0);
    }

    #[test]
    fn rate_limit_caps_messages_per_source_window() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        let src = addr("203.0.113.9:52000");
        // Exceed the per-window cap; excess Lookups must produce no replies.
        let mut replies = 0;
        for _ in 0..(MAX_MSGS_PER_WINDOW + 10) {
            replies += s.handle(src, Message::Lookup { node: a }, 0).len();
        }
        // Only up to the cap are serviced (each serviced Lookup -> 1 NotFound).
        assert!(
            replies <= MAX_MSGS_PER_WINDOW,
            "rate limit must drop excess"
        );
    }

    #[test]
    fn rates_map_grows_with_distinct_sources_but_stays_within_cap() {
        let mut s = RendezvousServer::new(0);
        let a = node_id(&[1u8; 32]);
        // Comfortably below MAX_RATE_ENTRIES: exercises normal growth and
        // confirms the map only ever holds one entry per distinct source.
        for i in 0..2_000u32 {
            s.handle(synth_addr(i), Message::Lookup { node: a }, 0);
        }
        assert_eq!(s.rates.len(), 2_000);
        assert!(s.rates.len() <= MAX_RATE_ENTRIES);
    }

    #[test]
    fn register_rejects_stale_or_equal_counter() {
        let mut s = RendezvousServer::new(0);
        let n = node_id(&[1u8; 32]);
        let a = addr("10.0.0.1:41000");
        // First registration at counter 5 is accepted.
        s.handle(
            a,
            Message::Register {
                node: n,
                counter: 5,
            },
            0,
        );
        assert!(s.is_registered(&n, 0), "counter 5 accepted");
        // Replay at counter 5 is rejected: a Lookup still resolves to the
        // ORIGINAL addr, proving the stale Register did not overwrite it.
        let a2 = addr("10.0.0.2:41000");
        s.handle(
            a2,
            Message::Register {
                node: n,
                counter: 5,
            },
            1,
        );
        let out = s.handle(a, Message::Lookup { node: n }, 2);
        match &out[0].1 {
            Message::PeerInfo { reflexive, .. } => assert_eq!(*reflexive, a),
            other => panic!("expected PeerInfo, got {other:?}"),
        }
        // A greater counter is accepted and updates the addr.
        s.handle(
            a2,
            Message::Register {
                node: n,
                counter: 6,
            },
            3,
        );
        let out = s.handle(a, Message::Lookup { node: n }, 4);
        match &out[0].1 {
            Message::PeerInfo { reflexive, .. } => assert_eq!(*reflexive, a2),
            other => panic!("expected PeerInfo, got {other:?}"),
        }
    }

    #[test]
    fn rate_capacity_guard_blocks_new_source_but_services_existing() {
        let mut s = RendezvousServer::new(0);
        // Pre-fill the rates map to capacity with dummy tracked sources via
        // direct field access (same module) -- a 131_072-iteration `handle`
        // loop would be needlessly slow; this exercises the same guard.
        for i in 0..MAX_RATE_ENTRIES {
            let idx = u32::try_from(i).expect("index fits u32");
            s.rates.insert(
                synth_addr(idx),
                Rate {
                    window_start_ms: 0,
                    count: 0,
                },
            );
        }
        assert_eq!(s.rates.len(), MAX_RATE_ENTRIES);

        let a = node_id(&[1u8; 32]);

        // A brand-new source arriving while at capacity must be treated as
        // rate-limited (dropped) rather than growing the map further. Without
        // the capacity guard this Lookup would be serviced (regs is empty,
        // so it would return a NotFound reply) and the map would grow past
        // the cap.
        let new_src = addr("198.51.100.50:9000");
        let out = s.handle(new_src, Message::Lookup { node: a }, 0);
        assert!(out.is_empty(), "new source over capacity must be dropped");
        assert_eq!(
            s.rates.len(),
            MAX_RATE_ENTRIES,
            "map must not grow past the cap"
        );

        // An already-tracked source must still be serviced normally even
        // while the map is at capacity.
        let existing_src = synth_addr(0);
        let out = s.handle(existing_src, Message::Lookup { node: a }, 0);
        assert!(
            !out.is_empty(),
            "already-tracked source must still be serviced"
        );
    }
}
