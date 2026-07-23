//! The mesh membership directory: gossiped, CA-verified `Record`s for every
//! known member, plus the anti-entropy protocol that converges directories
//! across nodes. This is the KNOWLEDGE layer (all members we've heard about
//! via gossip) — separate from `PeerManager`'s peer table (active sessions).
//! Not yet wired into `PeerManager`/`tunnel.rs`; Task 6 drives `on_gossip`/
//! `tick_digest` over real Noise sessions and calls `resolve`/`verify_cert`/
//! `own_cert_bytes` from the handshake path.
//!
//! ## Clocks (do not conflate these)
//! - **Cert validity** (`verify_cert`, `ingest_record`, the expiry sweep) is
//!   WALL-CLOCK seconds (`SystemTime::now().duration_since(UNIX_EPOCH)`).
//! - **Gossip debounce** (`tick_digest`) is MONOTONIC milliseconds (e.g. from
//!   `Instant`). It has nothing to do with cert validity and must never be
//!   compared against `not_before`/`not_after`.
#![allow(
    dead_code,
    reason = "directory/gossip logic not wired into PeerManager until Task 6"
)]

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};

use yip_membership::record;
use yip_membership::{node_addr, node_id, Cert, GossipMsg, NodeId, Record, RootSet};

/// Cert validity is widened by this many WALL-CLOCK seconds on both ends to
/// tolerate clock skew between nodes (matches the `yip-ca`/`yip-membership`
/// convention of an explicit, small, documented skew rather than an
/// unbounded one). Production default; see [`clock_skew_secs`] for the
/// test-only env override.
const CLOCK_SKEW_SECS: u64 = 300;

/// The cert-validity clock-skew widening (seconds), read once from
/// `YIP_CERT_SKEW_SECS` (default [`CLOCK_SKEW_SECS`] = 300). Overridable only
/// so netns tests can make a cert expire in seconds instead of waiting out the
/// 5-minute production grace; production leaves the var unset. Cached, so the
/// value is stable for the process's lifetime (a mid-run change cannot shrink
/// an already-honored validity window).
fn clock_skew_secs() -> u64 {
    static SKEW: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SKEW.get_or_init(|| {
        std::env::var("YIP_CERT_SKEW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(CLOCK_SKEW_SECS)
    })
}

/// Minimum spacing, in MONOTONIC milliseconds, between digests emitted by
/// `tick_digest` — pure gossip-chattiness control, unrelated to cert clocks.
const GOSSIP_INTERVAL_MS: u64 = 5_000;

/// Max `Record`s carried in a single `GossipMsg::Records` reply to a
/// `PullRequest`. Bounds the reply size regardless of how many `node_id`s a
/// single request names — a crafted `PullRequest` listing every `node_id` we
/// hold must not turn into one unboundedly large `Records` datagram (an
/// amplification concern even when the requester is a legitimate,
/// source-validated peer: `PeerManager::on_gossip` restricts *who* may ask,
/// not how much a single ask can cost). When we hold more records than fit
/// in one reply, `on_gossip` splits them across multiple bounded `Records`
/// messages instead of emitting one oversized one.
const MAX_GOSSIP_RECORDS_PER_REPLY: usize = 32;

/// The `seq` a node's own record starts at. Zero is fine: `ingest_record`'s
/// seq-supersession means any received record for our own `node_id` with a
/// higher seq would be a stale/duplicate broadcast of ourselves, which is
/// harmless to skip; only *we* are the source of truth for our own record.
const INITIAL_SEQ: u64 = 0;

/// A resolved member: its data-plane public key and last-known reachable
/// endpoints (from the directory, i.e. gossip — not necessarily live).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub pubkey: [u8; 32],
    pub endpoints: Vec<SocketAddr>,
}

/// The gossiped member directory + anti-entropy state for one node.
///
/// Two indices are kept over the same `Record`s: `directory` (keyed by
/// `node_id`, the authoritative store) and `by_addr` (keyed by the derived
/// `node_addr`, purely a `resolve()` accelerator) — both are derived from
/// each record's `cert.member_pubkey` and kept in sync on every insert/evict.
#[derive(Debug)]
pub struct Membership {
    directory: HashMap<NodeId, Record>,
    by_addr: HashMap<Ipv6Addr, NodeId>,
    ca_pubkeys: Vec<[u8; 32]>,
    network_id: [u8; 16],
    roots: RootSet,
    own_node_id: NodeId,
    /// This node's own cert, kept independent of `directory` so
    /// `own_cert_bytes` never depends on the own record surviving
    /// `sweep_expired` (or any other directory churn). It may become
    /// expired over wall-clock time; that's the operator's renewal
    /// concern, not a reason to panic — an expired own cert is still
    /// returned as-is and left for the peer to reject.
    own_cert: Cert,
    /// WALL-CLOCK-seconds timestamp is not stored here; only the MONOTONIC
    /// millisecond mark of the last digest we emitted, for `tick_digest`'s
    /// debounce.
    last_digest_ms: Option<u64>,
    /// The digest spacing to apply the NEXT time `last_digest_ms` is checked
    /// against `now_ms`. `GOSSIP_INTERVAL_MS` exactly when obfuscation is off
    /// (byte-identical timing); re-rolled via
    /// `crate::peer_manager::jitter_ms(GOSSIP_INTERVAL_MS)` after every digest
    /// fire when `tick_digest`'s `obf_on` is true (3a) — stored and compared,
    /// never re-derived per-tick.
    digest_ms: u64,
}

/// Build and sign a `Record` for `cert`/`endpoints`/`seq` with the member's
/// record-signing private key. Shared by `Membership::new` (the node's own
/// record) and (via `super::*`) the test module, which uses it to mint
/// other members' records.
fn build_signed_record(
    cert: Cert,
    endpoints: Vec<SocketAddr>,
    seq: u64,
    sign_priv: &[u8; 32],
) -> Record {
    let nid = node_id(&cert.member_pubkey);
    let mut r = Record {
        node_id: nid,
        cert,
        endpoints,
        seq,
        sig: [0u8; 64],
    };
    let body = record::record_signing_body(&r);
    r.sig = record::sign(&body, sign_priv);
    r
}

impl Membership {
    /// Construct a fresh directory containing only this node's own record
    /// (built from `own_cert`/`own_endpoints`, signed with `own_sign_priv`,
    /// starting at `INITIAL_SEQ`).
    pub fn new(
        ca_pubkeys: Vec<[u8; 32]>,
        network_id: [u8; 16],
        own_cert: Cert,
        own_sign_priv: [u8; 32],
        roots: RootSet,
        own_endpoints: Vec<SocketAddr>,
    ) -> Self {
        let own_node_id = node_id(&own_cert.member_pubkey);
        let own_cert_stored = own_cert.clone();
        let own_record = build_signed_record(own_cert, own_endpoints, INITIAL_SEQ, &own_sign_priv);

        let mut m = Membership {
            directory: HashMap::new(),
            by_addr: HashMap::new(),
            ca_pubkeys,
            network_id,
            roots,
            own_node_id,
            own_cert: own_cert_stored,
            last_digest_ms: None,
            digest_ms: GOSSIP_INTERVAL_MS,
        };
        m.insert_record(own_record);
        m
    }

    /// Directory lookup by mesh address, via the `node_addr -> node_id`
    /// secondary index. No clock involved.
    pub fn resolve(&self, addr: &Ipv6Addr) -> Option<MemberInfo> {
        let nid = self.by_addr.get(addr)?;
        let rec = self.directory.get(nid)?;
        Some(MemberInfo {
            pubkey: rec.cert.member_pubkey,
            endpoints: rec.endpoints.clone(),
        })
    }

    /// Wraps `yip_membership::verify_cert` with this node's configured
    /// `ca_pubkeys`/`network_id`/`CLOCK_SKEW_SECS`. `now` is WALL-CLOCK
    /// seconds.
    pub fn verify_cert(&self, cert: &Cert, static_key: &[u8; 32], now: u64) -> bool {
        yip_membership::verify_cert(
            cert,
            &self.ca_pubkeys,
            &self.network_id,
            static_key,
            now,
            clock_skew_secs(),
        )
        .is_ok()
    }

    /// This node's own cert, encoded — for the handshake payload (Task 6).
    ///
    /// Reads from the dedicated `own_cert` field, never from `directory` —
    /// the own record can (deliberately) still be evicted-and-reinserted or
    /// otherwise churned in the directory without this ever panicking. If
    /// the own cert has itself expired (wall-clock), this still returns its
    /// encoded bytes as-is: presenting an expired cert is the operator's
    /// renewal problem and is correctly rejected by peers, not a reason for
    /// the daemon to crash.
    pub fn own_cert_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.own_cert.encode(&mut out);
        out
    }

    /// Verify `rec` (CA→cert→record-sig chain, `now` = WALL-CLOCK seconds)
    /// and, iff valid, insert it when its `node_id` is unknown or its `seq`
    /// strictly supersedes what we hold. An invalid record is dropped
    /// without being inserted (no directory poisoning). Every call also
    /// sweeps any *existing* directory entry whose cert has since expired
    /// at `now`, independent of whether `rec` itself verifies — this is how
    /// expired records get evicted over time.
    ///
    /// Returns whether the directory changed (insert or eviction).
    pub fn ingest_record(&mut self, rec: Record, now: u64) -> bool {
        let mut changed = self.sweep_expired(now);

        if rec
            .verify(&self.ca_pubkeys, &self.network_id, now, clock_skew_secs())
            .is_ok()
        {
            changed |= self.insert_if_newer(rec);
        }

        changed
    }

    /// Anti-entropy step. `now` is WALL-CLOCK seconds (forwarded to
    /// `ingest_record` when processing `Records`; unused otherwise).
    ///
    /// - `Digest`: reply with a `PullRequest` for every `node_id` we lack or
    ///   hold at a lower-or-equal `seq` than advertised.
    /// - `PullRequest`: reply with the `Records` we actually hold for the
    ///   requested ids (silently skipping ones we don't have), split across
    ///   multiple messages of at most `MAX_GOSSIP_RECORDS_PER_REPLY` records
    ///   each so one request cannot produce one unboundedly large reply.
    /// - `Records`: `ingest_record` each (invalid ones are dropped, not
    ///   poisoned); no reply.
    pub fn on_gossip(&mut self, msg: GossipMsg, now: u64) -> Vec<GossipMsg> {
        match msg {
            GossipMsg::Digest(entries) => {
                let want: Vec<NodeId> = entries
                    .into_iter()
                    .filter_map(|(nid, seq)| {
                        let have_enough = self
                            .directory
                            .get(&nid)
                            .is_some_and(|existing| existing.seq >= seq);
                        (!have_enough).then_some(nid)
                    })
                    .collect();
                if want.is_empty() {
                    Vec::new()
                } else {
                    vec![GossipMsg::PullRequest(want)]
                }
            }
            GossipMsg::PullRequest(ids) => {
                let recs: Vec<Record> = ids
                    .iter()
                    .filter_map(|nid| self.directory.get(nid).cloned())
                    .collect();
                recs.chunks(MAX_GOSSIP_RECORDS_PER_REPLY)
                    .map(|chunk| GossipMsg::Records(chunk.to_vec()))
                    .collect()
            }
            GossipMsg::Records(recs) => {
                for r in recs {
                    let _ = self.ingest_record(r, now);
                }
                Vec::new()
            }
        }
    }

    /// A debounced `Digest` of the whole local directory, to send to gossip
    /// partners. `now_ms` is MONOTONIC milliseconds — used purely to space
    /// digests at least `GOSSIP_INTERVAL_MS` (jittered ±25% per fire when
    /// `obf_on`, see `digest_ms`) apart; it is never compared against a
    /// cert's validity window. `obf_on` is the caller's
    /// `PeerManager::obf_key.is_some()`; when false `digest_ms` stays exactly
    /// `GOSSIP_INTERVAL_MS` forever (byte-identical obf-off timing).
    pub fn tick_digest(&mut self, now_ms: u64, obf_on: bool) -> Option<GossipMsg> {
        if let Some(last) = self.last_digest_ms {
            if now_ms.saturating_sub(last) < self.digest_ms {
                return None;
            }
        }
        self.last_digest_ms = Some(now_ms);
        self.digest_ms = if obf_on {
            crate::peer_manager::jitter_ms(GOSSIP_INTERVAL_MS)
        } else {
            GOSSIP_INTERVAL_MS
        };
        let entries: Vec<(NodeId, u64)> = self
            .directory
            .iter()
            .map(|(nid, r)| (*nid, r.seq))
            .collect();
        Some(GossipMsg::Digest(entries))
    }

    /// The signed bootstrap root set (pubkey + reachable address), for
    /// bootstrap + always-admit.
    pub fn roots(&self) -> &[([u8; 32], SocketAddr)] {
        &self.roots.roots
    }

    /// Whether `pubkey` is still an admissible member at wall-clock `now`:
    /// `true` if it is an always-admit root, OR the directory holds a valid
    /// (unexpired, verifying) cert for it. `false` only when a non-root member's
    /// record was evicted (expired) or its cert no longer verifies — i.e.
    /// revoked-by-non-renewal. Folding the root check in here keeps roots exempt
    /// from the #41 liveness sweep (they have no directory-cert dependency).
    pub fn member_cert_valid(&self, pubkey: &[u8; 32], now: u64) -> bool {
        if self.roots.roots.iter().any(|(pk, _)| pk == pubkey) {
            return true;
        }
        match self.directory.get(&node_id(pubkey)) {
            Some(rec) => self.verify_cert(&rec.cert, pubkey, now),
            None => false,
        }
    }

    // ── internal helpers ───────────────────────────────────────────────

    /// Unconditionally (re-)insert `rec` into both indices.
    fn insert_record(&mut self, rec: Record) {
        let addr = node_addr(&rec.cert.member_pubkey);
        self.by_addr.insert(addr, rec.node_id);
        self.directory.insert(rec.node_id, rec);
    }

    /// Insert `rec` iff its `node_id` is new or its `seq` strictly exceeds
    /// the one we hold. Returns whether the directory changed.
    fn insert_if_newer(&mut self, rec: Record) -> bool {
        if let Some(existing) = self.directory.get(&rec.node_id) {
            if rec.seq <= existing.seq {
                return false;
            }
        }
        self.insert_record(rec);
        true
    }

    /// Remove the directory entry for `nid` (both indices), if present.
    fn evict(&mut self, nid: &NodeId) -> bool {
        if let Some(rec) = self.directory.remove(nid) {
            let addr = node_addr(&rec.cert.member_pubkey);
            self.by_addr.remove(&addr);
            true
        } else {
            false
        }
    }

    /// Remove every directory entry whose cert is no longer valid at `now`
    /// (WALL-CLOCK seconds, widened by `CLOCK_SKEW_SECS`), EXCEPT this
    /// node's own record (`own_node_id`), which is never evicted here: our
    /// own cert expiring over wall-clock time is inevitable and must not
    /// churn our own directory entry (`own_cert_bytes` is independent of
    /// this anyway, but keeping the own record present is the consistent
    /// behavior for gossip). Returns whether anything was evicted.
    fn sweep_expired(&mut self, now: u64) -> bool {
        let expired: Vec<NodeId> = self
            .directory
            .iter()
            .filter(|(nid, _)| **nid != self.own_node_id)
            .filter(|(_, rec)| {
                yip_membership::verify_cert(
                    &rec.cert,
                    &self.ca_pubkeys,
                    &self.network_id,
                    &rec.cert.member_pubkey,
                    now,
                    clock_skew_secs(),
                )
                .is_err()
            })
            .map(|(nid, _)| *nid)
            .collect();

        let mut changed = false;
        for nid in expired {
            changed |= self.evict(&nid);
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use yip_membership::cert::cert_signing_body;

    fn ca_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn make_cert(
        ca: &SigningKey,
        member_pubkey: [u8; 32],
        member_sign_pub: [u8; 32],
        net: [u8; 16],
        nb: u64,
        na: u64,
    ) -> Cert {
        let mut c = Cert {
            version: 1,
            member_pubkey,
            member_sign_pubkey: member_sign_pub,
            network_id: net,
            not_before: nb,
            not_after: na,
            tags: vec![],
            ca_sig: [0u8; 64],
        };
        c.ca_sig = ca.sign(&cert_signing_body(&c)).to_bytes();
        c
    }

    fn empty_roots() -> RootSet {
        RootSet {
            roots: vec![],
            version: 0,
            ca_sig: [0u8; 64],
        }
    }

    /// Build a fresh `Membership` whose own member key is `own_seed`,
    /// trusting `ca`, for `net`. Returns the membership plus the CA
    /// (so the test can mint other members' certs) and own node_id.
    fn fresh_membership(ca: &SigningKey, net: [u8; 16], own_seed: u8) -> (Membership, NodeId) {
        let ca_pub = ca.verifying_key().to_bytes();
        let own_member_pk = [own_seed; 32];
        let own_sign_key = SigningKey::from_bytes(&[own_seed.wrapping_add(1); 32]);
        let own_sign_pub = own_sign_key.verifying_key().to_bytes();
        let own_cert = make_cert(ca, own_member_pk, own_sign_pub, net, 0, 1_000_000);
        let own_ep = vec!["10.0.0.1:51820".parse().unwrap()];
        let own_nid = node_id(&own_member_pk);
        let m = Membership::new(
            vec![ca_pub],
            net,
            own_cert,
            own_sign_key.to_bytes(),
            empty_roots(),
            own_ep,
        );
        (m, own_nid)
    }

    // (a) ingest a valid record → resolve(node_addr(pubkey)) returns its endpoints.
    #[test]
    fn ingest_valid_record_then_resolve() {
        let ca = ca_key(1);
        let net = [7u8; 16];
        let (mut m, _own_nid) = fresh_membership(&ca, net, 10);

        let member_pk = [20u8; 32];
        let member_sign_key = SigningKey::from_bytes(&[21u8; 32]);
        let member_sign_pub = member_sign_key.verifying_key().to_bytes();
        let cert = make_cert(&ca, member_pk, member_sign_pub, net, 0, 1_000_000);
        let endpoints = vec!["192.0.2.5:9999".parse().unwrap()];
        let rec = build_signed_record(cert, endpoints.clone(), 1, &member_sign_key.to_bytes());

        assert!(m.ingest_record(rec, 500));
        let info = m.resolve(&node_addr(&member_pk)).expect("present");
        assert_eq!(info.pubkey, member_pk);
        assert_eq!(info.endpoints, endpoints);
    }

    // (b) a higher-seq record supersedes a lower one; a lower-seq is ignored.
    #[test]
    fn higher_seq_supersedes_lower_ignored() {
        let ca = ca_key(1);
        let net = [7u8; 16];
        let (mut m, _own_nid) = fresh_membership(&ca, net, 10);

        let member_pk = [30u8; 32];
        let member_sign_key = SigningKey::from_bytes(&[31u8; 32]);
        let member_sign_pub = member_sign_key.verifying_key().to_bytes();
        let cert = make_cert(&ca, member_pk, member_sign_pub, net, 0, 1_000_000);
        let addr = node_addr(&member_pk);

        let ep1 = vec!["192.0.2.1:1111".parse().unwrap()];
        let rec1 = build_signed_record(cert.clone(), ep1.clone(), 5, &member_sign_key.to_bytes());
        assert!(m.ingest_record(rec1, 500));
        assert_eq!(m.resolve(&addr).unwrap().endpoints, ep1);

        // lower seq is ignored
        let ep_lower = vec!["192.0.2.2:2222".parse().unwrap()];
        let rec_lower = build_signed_record(cert.clone(), ep_lower, 3, &member_sign_key.to_bytes());
        assert!(!m.ingest_record(rec_lower, 500));
        assert_eq!(m.resolve(&addr).unwrap().endpoints, ep1);

        // higher seq supersedes
        let ep_higher = vec!["192.0.2.3:3333".parse().unwrap()];
        let rec_higher =
            build_signed_record(cert, ep_higher.clone(), 10, &member_sign_key.to_bytes());
        assert!(m.ingest_record(rec_higher, 500));
        assert_eq!(m.resolve(&addr).unwrap().endpoints, ep_higher);
    }

    // (c) an expired-cert record is rejected/evicted.
    #[test]
    fn expired_cert_record_is_rejected_and_evicted() {
        let ca = ca_key(1);
        let net = [7u8; 16];
        let (mut m, _own_nid) = fresh_membership(&ca, net, 10);

        let member_pk = [40u8; 32];
        let member_sign_key = SigningKey::from_bytes(&[41u8; 32]);
        let member_sign_pub = member_sign_key.verifying_key().to_bytes();
        // Narrow validity window: [100, 200).
        let cert = make_cert(&ca, member_pk, member_sign_pub, net, 100, 200);
        let addr = node_addr(&member_pk);
        let endpoints = vec!["192.0.2.9:4444".parse().unwrap()];
        let rec = build_signed_record(cert, endpoints, 1, &member_sign_key.to_bytes());

        // Valid at now=150 (within window).
        assert!(m.ingest_record(rec.clone(), 150));
        assert!(m.resolve(&addr).is_some());

        // Well past not_after(200) + CLOCK_SKEW_SECS(300) = 500: expired,
        // both rejected on re-ingest and swept from the directory.
        assert!(m.ingest_record(rec, 900));
        assert!(m.resolve(&addr).is_none());
    }

    // (d) a record with a bad member-sig or wrong CA is rejected.
    #[test]
    fn bad_member_sig_and_wrong_ca_are_rejected() {
        let ca = ca_key(1);
        let net = [7u8; 16];
        let (mut m, _own_nid) = fresh_membership(&ca, net, 10);

        // Wrong CA: cert signed by a CA we don't trust.
        let other_ca = ca_key(99);
        let member_pk = [50u8; 32];
        let member_sign_key = SigningKey::from_bytes(&[51u8; 32]);
        let member_sign_pub = member_sign_key.verifying_key().to_bytes();
        let bad_ca_cert = make_cert(&other_ca, member_pk, member_sign_pub, net, 0, 1_000_000);
        let endpoints = vec!["192.0.2.10:5555".parse().unwrap()];
        let rec_wrong_ca = build_signed_record(
            bad_ca_cert,
            endpoints.clone(),
            1,
            &member_sign_key.to_bytes(),
        );
        assert!(!m.ingest_record(rec_wrong_ca, 500));
        assert!(m.resolve(&node_addr(&member_pk)).is_none());

        // Bad member-sig: cert is legitimately CA-signed, but the record is
        // signed with a key other than `cert.member_sign_pubkey`.
        let member_pk2 = [60u8; 32];
        let member_sign_key2 = SigningKey::from_bytes(&[61u8; 32]);
        let member_sign_pub2 = member_sign_key2.verifying_key().to_bytes();
        let cert2 = make_cert(&ca, member_pk2, member_sign_pub2, net, 0, 1_000_000);
        let wrong_key = SigningKey::from_bytes(&[77u8; 32]);
        let rec_bad_sig = build_signed_record(cert2, endpoints, 1, &wrong_key.to_bytes());
        assert!(!m.ingest_record(rec_bad_sig, 500));
        assert!(m.resolve(&node_addr(&member_pk2)).is_none());
    }

    // (e) on_gossip(Digest) returns a PullRequest for a node_id we lack or
    // have a lower seq for.
    #[test]
    fn digest_requests_missing_and_stale_nodes() {
        let ca = ca_key(1);
        let net = [7u8; 16];
        let (mut m, own_nid) = fresh_membership(&ca, net, 10);

        let member_pk = [70u8; 32];
        let member_sign_key = SigningKey::from_bytes(&[71u8; 32]);
        let member_sign_pub = member_sign_key.verifying_key().to_bytes();
        let cert = make_cert(&ca, member_pk, member_sign_pub, net, 0, 1_000_000);
        let known_nid = node_id(&member_pk);
        let endpoints = vec!["192.0.2.20:6666".parse().unwrap()];
        let rec = build_signed_record(cert, endpoints, 5, &member_sign_key.to_bytes());
        assert!(m.ingest_record(rec, 500));

        let unknown_nid = [0xabu8; 16];
        let digest = GossipMsg::Digest(vec![
            (unknown_nid, 1),       // we lack this entirely
            (known_nid, 9),         // we only have seq 5, digest claims 9 (stale)
            (own_nid, INITIAL_SEQ), // we're already at least this fresh
        ]);
        let resp = m.on_gossip(digest, 500);
        assert_eq!(resp.len(), 1);
        match &resp[0] {
            GossipMsg::PullRequest(ids) => {
                assert!(ids.contains(&unknown_nid));
                assert!(ids.contains(&known_nid));
                assert!(!ids.contains(&own_nid));
            }
            other => panic!("expected PullRequest, got {other:?}"),
        }
    }

    // (f) verify_cert accepts own cert, rejects wrong-CA.
    #[test]
    fn verify_cert_accepts_own_rejects_wrong_ca() {
        let ca = ca_key(1);
        let net = [7u8; 16];
        let own_member_pk = [10u8; 32];
        let own_sign_key = SigningKey::from_bytes(&[11u8; 32]);
        let own_sign_pub = own_sign_key.verifying_key().to_bytes();
        let own_cert = make_cert(&ca, own_member_pk, own_sign_pub, net, 0, 1_000_000);

        let (m, _own_nid) = {
            let ca_pub = ca.verifying_key().to_bytes();
            let m = Membership::new(
                vec![ca_pub],
                net,
                own_cert.clone(),
                own_sign_key.to_bytes(),
                empty_roots(),
                vec!["10.0.0.1:51820".parse().unwrap()],
            );
            (m, ())
        };

        assert!(m.verify_cert(&own_cert, &own_member_pk, 500));

        let other_ca = ca_key(88);
        let other_cert = make_cert(&other_ca, own_member_pk, own_sign_pub, net, 0, 1_000_000);
        assert!(!m.verify_cert(&other_cert, &own_member_pk, 500));
    }

    // (g) anti-entropy convergence: two Memberships exchanging
    // tick_digest -> on_gossip rounds converge to the same directory.
    #[test]
    fn anti_entropy_converges() {
        let ca = ca_key(1);
        let net = [7u8; 16];
        let (mut a, a_nid) = fresh_membership(&ca, net, 100);
        let (mut b, b_nid) = fresh_membership(&ca, net, 110);
        assert_ne!(a_nid, b_nid);

        let mut now_ms = 1_000u64;
        let secs = 500u64;

        // Round 1: both emit a digest of what they know (just themselves).
        let da = a
            .tick_digest(now_ms, false)
            .expect("first digest always fires");
        now_ms += GOSSIP_INTERVAL_MS;
        let db = b
            .tick_digest(now_ms, false)
            .expect("first digest always fires");

        // Each peer reacts to the other's digest with a PullRequest for
        // what it's missing.
        let pull_from_b_to_a = b.on_gossip(da, secs);
        let pull_from_a_to_b = a.on_gossip(db, secs);
        assert_eq!(pull_from_b_to_a.len(), 1);
        assert_eq!(pull_from_a_to_b.len(), 1);

        // Each peer answers the other's PullRequest with Records.
        let records_from_a = a.on_gossip(pull_from_b_to_a[0].clone(), secs);
        let records_from_b = b.on_gossip(pull_from_a_to_b[0].clone(), secs);
        assert_eq!(records_from_a.len(), 1);
        assert_eq!(records_from_b.len(), 1);

        // Each peer ingests the other's Records.
        let empty_1 = b.on_gossip(records_from_a[0].clone(), secs);
        let empty_2 = a.on_gossip(records_from_b[0].clone(), secs);
        assert!(empty_1.is_empty());
        assert!(empty_2.is_empty());

        // Converged: both directories now hold exactly {a_nid, b_nid} with
        // identical records.
        assert_eq!(a.directory.len(), 2);
        assert_eq!(b.directory.len(), 2);
        assert_eq!(a.directory, b.directory);
        assert!(a.directory.contains_key(&a_nid));
        assert!(a.directory.contains_key(&b_nid));
    }

    // (h) regression: once wall-clock time passes the OWN cert's
    // `not_after + CLOCK_SKEW_SECS`, `own_cert_bytes()` must still return
    // the (expired) own cert rather than panicking, and the own record
    // must survive `sweep_expired` (driven here via `ingest_record`)
    // rather than being evicted like any other expired record.
    //
    // Pre-fix, `own_cert_bytes` read from `directory.get(&own_node_id)`
    // with `.expect("own record is always present...")`, and
    // `sweep_expired` evicted ANY expired entry with no own-record
    // special-case — so this test panics on the pre-fix code and passes
    // after the fix.
    #[test]
    fn own_cert_bytes_survives_own_cert_expiry() {
        let ca = ca_key(1);
        let net = [7u8; 16];
        let own_member_pk = [90u8; 32];
        let own_sign_key = SigningKey::from_bytes(&[91u8; 32]);
        let own_sign_pub = own_sign_key.verifying_key().to_bytes();
        // Narrow validity window: own cert expires (wall-clock) at 200.
        let own_cert = make_cert(&ca, own_member_pk, own_sign_pub, net, 0, 200);
        let own_nid = node_id(&own_member_pk);
        let ca_pub = ca.verifying_key().to_bytes();
        let mut m = Membership::new(
            vec![ca_pub],
            net,
            own_cert.clone(),
            own_sign_key.to_bytes(),
            empty_roots(),
            vec!["10.0.0.2:51820".parse().unwrap()],
        );

        // Sanity: own record present right after construction.
        assert!(m.directory.contains_key(&own_nid));
        assert!(m.resolve(&node_addr(&own_member_pk)).is_some());

        // Drive an ingest_record call (as `on_gossip`/the handshake path
        // would) with `now` well past not_after(200) + CLOCK_SKEW_SECS(300)
        // = 500 — this is exactly the condition that trips `sweep_expired`.
        let other_member_pk = [95u8; 32];
        let other_sign_key = SigningKey::from_bytes(&[96u8; 32]);
        let other_sign_pub = other_sign_key.verifying_key().to_bytes();
        let other_cert = make_cert(&ca, other_member_pk, other_sign_pub, net, 0, 1_000_000);
        let other_rec = build_signed_record(
            other_cert,
            vec!["192.0.2.50:7777".parse().unwrap()],
            1,
            &other_sign_key.to_bytes(),
        );
        let now_past_own_expiry = 900u64;
        let _ = m.ingest_record(other_rec, now_past_own_expiry);

        // Own record must survive the sweep (not evicted like an ordinary
        // expired entry would be).
        assert!(
            m.directory.contains_key(&own_nid),
            "own record must survive sweep_expired even after its own cert expires"
        );
        assert!(m.resolve(&node_addr(&own_member_pk)).is_some());

        // own_cert_bytes() must not panic and must still return the
        // correct (now-expired) own cert, unconditionally of directory
        // state.
        let mut expected = Vec::new();
        own_cert.encode(&mut expected);
        assert_eq!(m.own_cert_bytes(), expected);
    }

    // ── #41(b): `member_cert_valid` ─────────────────────────────────────────

    /// Build a `Membership` with: a live directory record (`live_pubkey`), a
    /// root (`root_pubkey`, in the `RootSet`, no directory dependency), and
    /// an expired-cert member (`expired_pubkey`) — inserted while its cert
    /// was still valid (window `[100, 200)`, at `ingest` time `now=150`) so
    /// `ingest_record` accepts it, but never re-swept, so it is still present
    /// in the directory (holding its now-expired cert) at the returned `now`.
    /// Returns `(membership, live_pubkey, root_pubkey, expired_pubkey, now)`.
    fn membership_with_live_root_and_expired() -> (Membership, [u8; 32], [u8; 32], [u8; 32], u64) {
        let ca = ca_key(1);
        let net = [7u8; 16];

        let root_pubkey = [200u8; 32];
        let roots = RootSet {
            roots: vec![(root_pubkey, "10.0.0.99:51820".parse().unwrap())],
            version: 0,
            ca_sig: [0u8; 64],
        };

        let own_member_pk = [10u8; 32];
        let own_sign_key = SigningKey::from_bytes(&[11u8; 32]);
        let own_sign_pub = own_sign_key.verifying_key().to_bytes();
        let own_cert = make_cert(&ca, own_member_pk, own_sign_pub, net, 0, 1_000_000);
        let ca_pub = ca.verifying_key().to_bytes();
        let mut m = Membership::new(
            vec![ca_pub],
            net,
            own_cert,
            own_sign_key.to_bytes(),
            roots,
            vec!["10.0.0.1:51820".parse().unwrap()],
        );

        // A live member: valid essentially forever.
        let live_pubkey = [20u8; 32];
        let live_sign_key = SigningKey::from_bytes(&[21u8; 32]);
        let live_sign_pub = live_sign_key.verifying_key().to_bytes();
        let live_cert = make_cert(&ca, live_pubkey, live_sign_pub, net, 0, 1_000_000);
        let live_rec = build_signed_record(
            live_cert,
            vec!["192.0.2.1:1111".parse().unwrap()],
            1,
            &live_sign_key.to_bytes(),
        );
        assert!(m.ingest_record(live_rec, 500));

        // An expired member: window [100, 200) — insert while valid (now=150).
        let expired_pubkey = [30u8; 32];
        let expired_sign_key = SigningKey::from_bytes(&[31u8; 32]);
        let expired_sign_pub = expired_sign_key.verifying_key().to_bytes();
        let expired_cert = make_cert(&ca, expired_pubkey, expired_sign_pub, net, 100, 200);
        let expired_rec = build_signed_record(
            expired_cert,
            vec!["192.0.2.2:2222".parse().unwrap()],
            1,
            &expired_sign_key.to_bytes(),
        );
        assert!(m.ingest_record(expired_rec, 150));

        // now: well past expired_cert's not_after(200) + CLOCK_SKEW_SECS(300)
        // = 500, but well within live_cert's window (not_after 1_000_000).
        let now = 900u64;
        (m, live_pubkey, root_pubkey, expired_pubkey, now)
    }

    #[test]
    fn member_cert_valid_tracks_directory_and_roots() {
        let (m, live_pubkey, root_pubkey, expired_pubkey, now) =
            membership_with_live_root_and_expired();
        assert!(
            m.member_cert_valid(&live_pubkey, now),
            "a live directory record is valid"
        );
        assert!(
            m.member_cert_valid(&root_pubkey, now),
            "a root is always admissible (exempt)"
        );
        assert!(
            !m.member_cert_valid(&expired_pubkey, now),
            "an expired/absent member is invalid"
        );
        let never_seen = [0xAAu8; 32];
        assert!(
            !m.member_cert_valid(&never_seen, now),
            "an unknown non-root member is invalid"
        );
    }

    // (i) Fix-pass (Task 6): a `PullRequest` naming more `node_id`s than fit
    // in one `MAX_GOSSIP_RECORDS_PER_REPLY` batch must not produce one
    // unboundedly large `Records` reply — an amplification/CPU concern even
    // once the caller (`PeerManager::on_gossip`) restricts *who* may ask.
    // `on_gossip` must instead split the reply across multiple `Records`
    // messages, each respecting the cap, while still eventually delivering
    // every record the requester lacked.
    #[test]
    fn pull_request_reply_is_capped_and_split() {
        let ca = ca_key(1);
        let net = [7u8; 16];
        let (mut m, _own_nid) = fresh_membership(&ca, net, 10);

        let member_sign_key = SigningKey::from_bytes(&[199u8; 32]);
        let member_sign_pub = member_sign_key.verifying_key().to_bytes();

        let total = MAX_GOSSIP_RECORDS_PER_REPLY * 2 + 5;
        let mut ids = Vec::with_capacity(total);
        for i in 0..total {
            let mut member_pk = [0u8; 32];
            member_pk[0..2].copy_from_slice(&(100 + i as u16).to_be_bytes());
            let cert = make_cert(&ca, member_pk, member_sign_pub, net, 0, 1_000_000);
            let endpoints = vec![format!("192.0.2.1:{}", 10_000 + i).parse().unwrap()];
            let rec = build_signed_record(cert, endpoints, 1, &member_sign_key.to_bytes());
            ids.push(rec.node_id);
            assert!(m.ingest_record(rec, 500));
        }

        let resp = m.on_gossip(GossipMsg::PullRequest(ids.clone()), 500);
        assert!(
            resp.len() > 1,
            "a request larger than one batch must split across multiple Records messages"
        );

        let mut got_ids = std::collections::HashSet::new();
        for msg in &resp {
            match msg {
                GossipMsg::Records(recs) => {
                    assert!(
                        recs.len() <= MAX_GOSSIP_RECORDS_PER_REPLY,
                        "each Records message must respect the per-reply cap"
                    );
                    for r in recs {
                        got_ids.insert(r.node_id);
                    }
                }
                other => panic!("expected Records, got {other:?}"),
            }
        }
        assert_eq!(
            got_ids.len(),
            total,
            "every requested record must still be delivered, just split across replies"
        );
        for nid in &ids {
            assert!(got_ids.contains(nid), "missing requested record {nid:?}");
        }
    }
}
