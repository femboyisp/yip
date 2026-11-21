//! Dynamic Underlay Path MTU Probing & TCP SYN MSS Clamping.
//!
//! Provides RFC 1624 incremental checksum updates and dynamic TCP MSS clamping
//! for both IPv4 and IPv6 streams traversing TUN interfaces, preventing PMTU
//! blackholing and underlay packet fragmentation.
#![forbid(unsafe_code)]

/// RFC 1624 Equation 3 incremental 16-bit one's complement checksum update:
/// `HC' = ~(~HC + ~m + m')`.
///
/// Computes the updated checksum in O(1) time without rescanning the entire packet.
#[inline]
pub fn update_csum_16(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    // RFC 1624 Equation 3: HC' = ~(~HC + ~m + m')
    // Max sum is 3 * 0xFFFF = 0x2FFFD. Folding (sum & 0xFFFF) + (sum >> 16) is at most
    // 0xFFFD + 2 = 0xFFFF, strictly fitting in 16 bits with no second carry.
    let sum = u32::from(!old_csum) + u32::from(!old_val) + u32::from(new_val);
    let folded = (sum & 0xffff) + (sum >> 16);
    let mut new_csum = !(folded as u16);
    if new_csum == 0 {
        new_csum = 0xffff;
    }
    new_csum
}

/// Overhead added to plaintext TUN packets by AEAD session sealing
/// (12B nonce/epoch/counter wire framing + 16B Poly1305 authentication tag).
pub const CRYPTO_SEAL_OVERHEAD: u16 = 28;

/// Minimum allowable IPv6 MTU per RFC 8200 Section 5.
pub const RFC8200_MIN_IPV6_MTU: u16 = 1280;

/// Minimum allowable IPv6 TCP MSS (1280B MTU - 40B IPv6 header - 20B TCP header).
pub const RFC8200_MIN_IPV6_MSS: u16 = 1220;

/// Standard minimum IPv4 TCP MSS (RFC 879: 576B MTU - 40B IPv4/TCP headers).
pub const RFC879_MIN_IPV4_MSS: u16 = 536;

/// Calculate the maximum TCP Maximum Segment Size (MSS) allowed for a given TUN MTU.
///
/// Accounts for IPv4 (20 bytes) or IPv6 (40 bytes) headers plus the TCP header (20 bytes).
#[inline]
pub fn max_mss_for_mtu(mtu: u16, is_ipv6: bool) -> u16 {
    if is_ipv6 {
        mtu.saturating_sub(60).max(RFC8200_MIN_IPV6_MSS)
    } else {
        mtu.saturating_sub(40).max(RFC879_MIN_IPV4_MSS)
    }
}

/// Fast check whether a packet slice is a TCP SYN packet (IPv4 or IPv6).
#[inline]
pub fn is_tcp_syn(pkt: &[u8]) -> bool {
    if pkt.len() >= 40 && (pkt[0] >> 4) == 4 && pkt[9] == 6 {
        let ihl = usize::from(pkt[0] & 0x0F) * 4;
        if ihl >= 20 && pkt.len() >= ihl + 20 {
            return (pkt[ihl + 13] & 0x02) != 0;
        }
    } else if pkt.len() >= 60 && (pkt[0] >> 4) == 6 && pkt[6] == 6 {
        return (pkt[40 + 13] & 0x02) != 0;
    }
    false
}

/// Clamps the TCP MSS option in `pkt` if `pkt` is an IPv4 or IPv6 TCP SYN packet
/// and its advertised MSS exceeds `max_mss`. Updates the TCP checksum incrementally
/// via [`update_csum_16`].
///
/// Returns `true` if the packet was modified, `false` otherwise.
pub fn clamp_tcp_mss(pkt: &mut [u8], max_mss: u16) -> bool {
    if !is_tcp_syn(pkt) {
        return false;
    }

    let version = pkt[0] >> 4;
    let (tcp_start, tcp_end) = if version == 4 {
        let ihl = usize::from(pkt[0] & 0x0F) * 4;
        let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
        if pkt.len() < total_len {
            return false;
        }
        (ihl, total_len)
    } else {
        let payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
        let total_len = 40 + payload_len;
        if pkt.len() < total_len {
            return false;
        }
        (40, total_len)
    };

    let tcp_len = tcp_end.saturating_sub(tcp_start);
    let data_offset = usize::from(pkt[tcp_start + 12] >> 4) * 4;
    if data_offset < 20 || data_offset > tcp_len {
        return false;
    }

    let opt_start = tcp_start + 20;
    let opt_end = tcp_start + data_offset;
    let mut opt_idx = opt_start;
    let mut clamped = false;
    let max_iterations = opt_end.saturating_sub(opt_idx).min(40);

    for _ in 0..max_iterations {
        if opt_idx >= opt_end {
            break;
        }
        let kind = pkt[opt_idx];
        if kind == 0 {
            // End of options list
            break;
        } else if kind == 1 {
            // NOP padding
            opt_idx += 1;
        } else {
            let remaining = opt_end - opt_idx;
            if remaining < 2 {
                break;
            }
            let len = usize::from(pkt[opt_idx + 1]);
            if len < 2 || len > remaining {
                break;
            }
            if kind == 2 && len == 4 {
                // Option 2: Maximum Segment Size (MSS)
                let current_mss = u16::from_be_bytes([pkt[opt_idx + 2], pkt[opt_idx + 3]]);
                if current_mss > max_mss {
                    let old_csum = u16::from_be_bytes([pkt[tcp_start + 16], pkt[tcp_start + 17]]);
                    let new_csum = update_csum_16(old_csum, current_mss, max_mss);
                    pkt[tcp_start + 16..tcp_start + 18].copy_from_slice(&new_csum.to_be_bytes());
                    pkt[opt_idx + 2..opt_idx + 4].copy_from_slice(&max_mss.to_be_bytes());
                    clamped = true;
                }
            }
            opt_idx += len;
        }
    }

    clamped
}

/// Clamps the TCP MSS option in `pkt` to the appropriate maximum segment size
/// for the specified TUN `mtu`. Automatically derives `max_mss` from packet IP version.
pub fn clamp_tcp_mss_for_mtu(pkt: &mut [u8], mtu: u16) -> bool {
    if pkt.is_empty() {
        return false;
    }
    let is_ipv6 = (pkt[0] >> 4) == 6;
    let max_mss = max_mss_for_mtu(mtu, is_ipv6);
    clamp_tcp_mss(pkt, max_mss)
}

/// Zero-allocation helper on the transmit hotpath: inspects `pkt` and clamps
/// MSS if `pkt` is a TCP SYN packet, writing into `scratch` and returning a
/// borrow. If `pkt` is not a TCP SYN, returns `pkt` immediately with zero copies.
pub fn maybe_clamp_tcp_syn<'a>(pkt: &'a [u8], scratch: &'a mut Vec<u8>, mtu: u16) -> &'a [u8] {
    if is_tcp_syn(pkt) {
        scratch.clear();
        scratch.extend_from_slice(pkt);
        if clamp_tcp_mss_for_mtu(scratch, mtu) {
            return scratch.as_slice();
        }
    }
    pkt
}

/// Discovered underlay link MTU tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnderlayTier {
    /// Defensive floor for restricted cellular relays and conservative profiles (1184B).
    Floor1184,
    /// Standard IPv6 minimum link MTU (1280B).
    Conservative1280,
    /// Standard physical Ethernet WAN underlay (1500B).
    Standard1500,
}

/// Dynamic Path MTU Discovery and MSS Clamping Manager.
#[derive(Debug, Clone)]
pub struct PmtuManager {
    tier: UnderlayTier,
    tun_mtu: u16,
    confirmed_symbol_size: u16,
}

impl Default for PmtuManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PmtuManager {
    /// Create a new PMTU manager defaulted to standard Ethernet 1500B underlays (TUN MTU 1420).
    pub fn new() -> Self {
        Self {
            tier: UnderlayTier::Standard1500,
            tun_mtu: 1420,
            confirmed_symbol_size: 1420 + CRYPTO_SEAL_OVERHEAD,
        }
    }

    /// Construct a PMTU manager configured for a specific underlay tier.
    pub fn with_tier(tier: UnderlayTier) -> Self {
        let tun_mtu = Self::optimal_tun_mtu(tier);
        Self {
            tier,
            tun_mtu,
            confirmed_symbol_size: tun_mtu + CRYPTO_SEAL_OVERHEAD,
        }
    }

    /// Calculate the optimal TUN MTU corresponding to an underlay tier.
    ///
    /// Deducts 68-80 bytes of underlay framing (IP + UDP + SipHash + Poly1305 AEAD tag).
    pub fn optimal_tun_mtu(tier: UnderlayTier) -> u16 {
        match tier {
            UnderlayTier::Standard1500 => 1420,
            UnderlayTier::Conservative1280 => 1212,
            UnderlayTier::Floor1184 => 1184,
        }
    }

    /// The active TUN MTU.
    pub fn tun_mtu(&self) -> u16 {
        self.tun_mtu
    }

    /// The active underlay tier.
    pub fn tier(&self) -> UnderlayTier {
        self.tier
    }

    /// The confirmed FEC symbol size.
    pub fn confirmed_symbol_size(&self) -> u16 {
        self.confirmed_symbol_size
    }

    /// Update the confirmed FEC symbol size from the PLPMTU controller.
    pub fn update_confirmed_symbol_size(&mut self, symbol_size: u16) {
        self.confirmed_symbol_size = symbol_size;
    }

    /// Dynamically override the TUN MTU.
    pub fn set_tun_mtu(&mut self, mtu: u16) {
        self.tun_mtu = mtu;
    }

    /// Calculate the maximum allowable MSS for a packet (IPv4 or IPv6)
    /// keeping ciphertext within a single FEC symbol (K = 1).
    pub fn max_mss_for_packet(&self, is_ipv6: bool) -> u16 {
        let tier_mtu = self
            .confirmed_symbol_size
            .saturating_sub(CRYPTO_SEAL_OVERHEAD);
        let effective_mtu = self.tun_mtu.min(tier_mtu);
        max_mss_for_mtu(effective_mtu, is_ipv6)
    }

    /// Update state on confirmed wire MTU probe receipt.
    pub fn on_probe_confirmed(&mut self, wire_mtu: u16) {
        if wire_mtu >= 1500 {
            self.tier = UnderlayTier::Standard1500;
            self.tun_mtu = 1420;
            self.confirmed_symbol_size = 1420 + CRYPTO_SEAL_OVERHEAD;
        } else if wire_mtu >= 1280 {
            self.tier = UnderlayTier::Conservative1280;
            self.tun_mtu = 1212;
            self.confirmed_symbol_size = 1212 + CRYPTO_SEAL_OVERHEAD;
        } else {
            self.tier = UnderlayTier::Floor1184;
            self.tun_mtu = 1184;
            self.confirmed_symbol_size = 1184 + CRYPTO_SEAL_OVERHEAD;
        }
    }

    /// Fall back to defensive floor on blackhole loss detection.
    pub fn on_blackhole_detected(&mut self) -> u16 {
        self.tier = UnderlayTier::Floor1184;
        self.tun_mtu = 1184;
        self.confirmed_symbol_size = 1184 + CRYPTO_SEAL_OVERHEAD;
        self.tun_mtu
    }

    /// Clamp MSS for a packet traversing the interface according to the current TUN MTU
    /// and confirmed symbol tier.
    pub fn clamp_syn<'a>(&self, pkt: &'a [u8], scratch: &'a mut Vec<u8>) -> &'a [u8] {
        if is_tcp_syn(pkt) {
            scratch.clear();
            scratch.extend_from_slice(pkt);
            let is_ipv6 = (scratch[0] >> 4) == 6;
            let max_mss = self.max_mss_for_packet(is_ipv6);
            if clamp_tcp_mss(scratch, max_mss) {
                return scratch.as_slice();
            }
        }
        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full checksum calculation helper for tests to verify RFC 1624 incremental update equivalence.
    fn compute_tcp_checksum_ipv4(pkt: &[u8]) -> u16 {
        let ihl = usize::from(pkt[0] & 0x0F) * 4;
        let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
        let tcp = &pkt[ihl..total_len];

        let mut sum = 0u32;
        // IPv4 pseudo-header: src IP (4B), dst IP (4B), zero + proto (2B), TCP length (2B)
        sum += u32::from(u16::from_be_bytes([pkt[12], pkt[13]]));
        sum += u32::from(u16::from_be_bytes([pkt[14], pkt[15]]));
        sum += u32::from(u16::from_be_bytes([pkt[16], pkt[17]]));
        sum += u32::from(u16::from_be_bytes([pkt[18], pkt[19]]));
        sum += u32::from(6u16); // protocol TCP
        sum += u32::from(tcp.len() as u16);

        // TCP header + data (with checksum field treated as 0)
        let mut i = 0;
        while i < tcp.len() {
            let word = if i == 16 {
                0u16 // zero out checksum field
            } else if i + 1 < tcp.len() {
                u16::from_be_bytes([tcp[i], tcp[i + 1]])
            } else {
                u16::from_be_bytes([tcp[i], 0])
            };
            sum += u32::from(word);
            i += 2;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let res = !(sum as u16);
        if res == 0 {
            0xffff
        } else {
            res
        }
    }

    fn craft_ipv4_tcp_syn(mss: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 44]; // 20B IPv4 + 24B TCP (4B MSS option)
        pkt[0] = 0x45; // IPv4, IHL=5 (20B)
        pkt[2..4].copy_from_slice(&(44u16).to_be_bytes()); // total_len
        pkt[8] = 64; // TTL
        pkt[9] = 6; // IPPROTO_TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // src IP
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst IP

        // TCP header at offset 20
        pkt[20..22].copy_from_slice(&(12345u16).to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&(80u16).to_be_bytes()); // dst port
        pkt[32] = 0x60; // Data offset = 6 (24B)
        pkt[33] = 0x02; // Flags = SYN

        // Option: MSS (Kind=2, Len=4, Value=mss)
        pkt[40] = 2;
        pkt[41] = 4;
        pkt[42..44].copy_from_slice(&mss.to_be_bytes());

        // Compute genuine TCP checksum
        let csum = compute_tcp_checksum_ipv4(&pkt);
        pkt[36..38].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    #[test]
    fn test_incremental_checksum_matches_full_checksum_calculation() {
        let mut pkt = craft_ipv4_tcp_syn(1460);
        let orig_csum = u16::from_be_bytes([pkt[36], pkt[37]]);
        assert_eq!(orig_csum, compute_tcp_checksum_ipv4(&pkt));

        // Clamp from 1460 to 1380
        let clamped = clamp_tcp_mss(&mut pkt, 1380);
        assert!(clamped);
        let new_csum = u16::from_be_bytes([pkt[36], pkt[37]]);
        let new_mss = u16::from_be_bytes([pkt[42], pkt[43]]);
        assert_eq!(new_mss, 1380);

        // Assert incremental RFC 1624 checksum is EXACTLY equal to recomputing from scratch
        let expected_csum = compute_tcp_checksum_ipv4(&pkt);
        assert_eq!(new_csum, expected_csum);
    }

    #[test]
    fn test_clamp_mss_noop_when_current_mss_already_smaller() {
        let mut pkt = craft_ipv4_tcp_syn(1300);
        let orig_csum = u16::from_be_bytes([pkt[36], pkt[37]]);
        let clamped = clamp_tcp_mss(&mut pkt, 1380);
        assert!(!clamped);
        assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 1300);
        assert_eq!(u16::from_be_bytes([pkt[36], pkt[37]]), orig_csum);
    }

    #[test]
    fn test_non_syn_packets_ignored() {
        let mut pkt = craft_ipv4_tcp_syn(1460);
        pkt[33] = 0x10; // ACK flag only (not SYN)
        let orig_csum = u16::from_be_bytes([pkt[36], pkt[37]]);
        assert!(!is_tcp_syn(&pkt));
        let clamped = clamp_tcp_mss(&mut pkt, 1380);
        assert!(!clamped);
        assert_eq!(u16::from_be_bytes([pkt[36], pkt[37]]), orig_csum);
    }

    #[test]
    fn test_clamp_tcp_mss_ipv6_syn() {
        let mut pkt = vec![0u8; 64]; // 40B IPv6 + 24B TCP
        pkt[0] = 0x60; // IPv6
        pkt[4..6].copy_from_slice(&(24u16).to_be_bytes()); // Payload length
        pkt[6] = 6; // Next header = TCP

        // TCP header at offset 40
        pkt[40..42].copy_from_slice(&(54321u16).to_be_bytes());
        pkt[42..44].copy_from_slice(&(443u16).to_be_bytes());
        pkt[52] = 0x60; // Data offset = 6 (24B)
        pkt[53] = 0x02; // SYN
        pkt[56..58].copy_from_slice(&(0x1234u16).to_be_bytes()); // Dummy csum

        // MSS option
        pkt[60] = 2;
        pkt[61] = 4;
        pkt[62..64].copy_from_slice(&(1440u16).to_be_bytes());

        assert!(is_tcp_syn(&pkt));
        let clamped = clamp_tcp_mss_for_mtu(&mut pkt, 1420); // max_mss = 1420 - 60 = 1360
        assert!(clamped);
        assert_eq!(u16::from_be_bytes([pkt[62], pkt[63]]), 1360);

        // IPv6 SYN with trailing buffer padding (pkt.len() > total_len)
        let mut padded_v6 = pkt.clone();
        padded_v6.resize(80, 0); // pkt.len() = 80 > total_len = 64
        padded_v6[62..64].copy_from_slice(&(1440u16).to_be_bytes());
        assert!(clamp_tcp_mss_for_mtu(&mut padded_v6, 1420));
        assert_eq!(u16::from_be_bytes([padded_v6[62], padded_v6[63]]), 1360);

        // IPv6 non-SYN packet must return false
        pkt[53] = 0x10; // ACK only
        assert!(!is_tcp_syn(&pkt));
    }

    #[test]
    fn test_is_tcp_syn_ipv4_options_and_truncation() {
        // IPv4 with IHL = 6 (24B IPv4 header) but total length only 42B (< 24 + 20 = 44B)
        // Set SYN bit at offset 24 + 13 = 37 to ensure mutant (+ replaced with -) is caught.
        let mut short_pkt = vec![0u8; 42];
        short_pkt[0] = 0x46; // IHL = 6 (24B)
        short_pkt[9] = 6; // TCP
        short_pkt[37] = 0x02; // SYN bit
        assert!(!is_tcp_syn(&short_pkt));

        // IPv4 with invalid IHL = 4 (16B < 20B) with SYN bit at 16 + 13 = 29
        let mut bad_ihl = vec![0u8; 40];
        bad_ihl[0] = 0x44; // IHL = 4 (16B)
        bad_ihl[9] = 6; // TCP
        bad_ihl[29] = 0x02; // SYN bit
        assert!(!is_tcp_syn(&bad_ihl));

        // IPv4 with IHL = 6 and full TCP header with SYN
        let mut full_pkt = vec![0u8; 48];
        full_pkt[0] = 0x46;
        full_pkt[9] = 6;
        full_pkt[24 + 13] = 0x02; // SYN flag at TCP offset 24 + 13
        assert!(is_tcp_syn(&full_pkt));

        // Non-SYN IPv4 packet with options
        full_pkt[24 + 13] = 0x10;
        assert!(!is_tcp_syn(&full_pkt));
    }

    #[test]
    fn test_maybe_clamp_tcp_syn_scratch_zero_copy() {
        let syn_pkt = craft_ipv4_tcp_syn(1460);
        let mut scratch = Vec::new();

        let out = maybe_clamp_tcp_syn(&syn_pkt, &mut scratch, 1420);
        assert_eq!(u16::from_be_bytes([out[42], out[43]]), 1380);

        let mut non_syn = craft_ipv4_tcp_syn(1460);
        non_syn[33] = 0x18; // PSH, ACK
        scratch.clear();
        let out_ptr = maybe_clamp_tcp_syn(&non_syn, &mut scratch, 1420).as_ptr();
        assert_eq!(out_ptr, non_syn.as_ptr());
        assert!(scratch.is_empty(), "non-syn packets must not touch scratch");
    }

    #[test]
    fn test_pmtu_manager_transitions() {
        let mut mgr = PmtuManager::new();
        assert_eq!(mgr.tier(), UnderlayTier::Standard1500);
        assert_eq!(mgr.tun_mtu(), 1420);
        assert_eq!(mgr.confirmed_symbol_size(), 1448); // 1420 + 28

        let c_mgr = PmtuManager::with_tier(UnderlayTier::Conservative1280);
        assert_eq!(c_mgr.tier(), UnderlayTier::Conservative1280);
        assert_eq!(c_mgr.tun_mtu(), 1212);
        assert_eq!(c_mgr.confirmed_symbol_size(), 1240); // 1212 + 28

        let f_mgr = PmtuManager::with_tier(UnderlayTier::Floor1184);
        assert_eq!(f_mgr.tier(), UnderlayTier::Floor1184);
        assert_eq!(f_mgr.tun_mtu(), 1184);
        assert_eq!(f_mgr.confirmed_symbol_size(), 1212); // 1184 + 28

        assert_eq!(
            PmtuManager::optimal_tun_mtu(UnderlayTier::Standard1500),
            1420
        );
        assert_eq!(
            PmtuManager::optimal_tun_mtu(UnderlayTier::Conservative1280),
            1212
        );
        assert_eq!(PmtuManager::optimal_tun_mtu(UnderlayTier::Floor1184), 1184);

        mgr.set_tun_mtu(1350);
        assert_eq!(mgr.tun_mtu(), 1350);

        let syn_pkt = craft_ipv4_tcp_syn(1460);
        let mut scratch = Vec::new();
        let clamped = mgr.clamp_syn(&syn_pkt, &mut scratch);
        assert_eq!(u16::from_be_bytes([clamped[42], clamped[43]]), 1310); // 1350 - 40

        mgr.on_probe_confirmed(1280);
        assert_eq!(mgr.tier(), UnderlayTier::Conservative1280);
        assert_eq!(mgr.tun_mtu(), 1212);
        assert_eq!(mgr.confirmed_symbol_size(), 1240); // 1212 + 28

        mgr.on_probe_confirmed(1150);
        assert_eq!(mgr.tier(), UnderlayTier::Floor1184);
        assert_eq!(mgr.tun_mtu(), 1184);
        assert_eq!(mgr.confirmed_symbol_size(), 1212); // 1184 + 28

        let floor = mgr.on_blackhole_detected();
        assert_eq!(floor, 1184);
        assert_eq!(mgr.tier(), UnderlayTier::Floor1184);
        assert_eq!(mgr.tun_mtu(), 1184);
        assert_eq!(mgr.confirmed_symbol_size(), 1212); // 1184 + 28

        mgr.on_probe_confirmed(1500);
        assert_eq!(mgr.tier(), UnderlayTier::Standard1500);
        assert_eq!(mgr.tun_mtu(), 1420);
        assert_eq!(mgr.confirmed_symbol_size(), 1448); // 1420 + 28
    }

    #[test]
    fn test_dynamic_symbol_tier_mss_clamping_ipv4_and_ipv6() {
        let mut mgr = PmtuManager::new();
        assert_eq!(mgr.tun_mtu(), 1420);

        // Tier 2 (1400B symbol size): effective TUN MTU = 1400 - 28 = 1372
        mgr.update_confirmed_symbol_size(1400);
        assert_eq!(mgr.max_mss_for_packet(false), 1332); // 1372 - 40 (IPv4) -> K = 1
        assert_eq!(mgr.max_mss_for_packet(true), 1312); // 1372 - 60 (IPv6) -> K = 1

        // Tier 0 (1120B symbol size): effective TUN MTU = 1120 - 28 = 1092
        mgr.update_confirmed_symbol_size(1120);
        assert_eq!(mgr.max_mss_for_packet(false), 1052); // 1092 - 40 (IPv4) -> K = 1
        assert_eq!(mgr.max_mss_for_packet(true), 1220); // RFC 8200 floor: max(1220, 1092 - 60) = 1220
    }

    #[test]
    fn test_clamp_tcp_mss_ipv6_rfc8200_floor() {
        let mut mgr = PmtuManager::new();
        mgr.on_blackhole_detected();
        mgr.update_confirmed_symbol_size(1120);
        assert_eq!(mgr.tun_mtu(), 1184);

        // Craft IPv6 TCP SYN with advertised MSS 1440
        let mut syn = vec![0u8; 64];
        syn[0] = 0x60;
        syn[4..6].copy_from_slice(&(24u16).to_be_bytes());
        syn[6] = 6; // TCP
        syn[52] = 0x60; // Data offset 24B
        syn[53] = 0x02; // SYN
        syn[60] = 2; // MSS
        syn[61] = 4;
        syn[62..64].copy_from_slice(&(1440u16).to_be_bytes());

        let mut scratch = Vec::new();
        let clamped = mgr.clamp_syn(&syn, &mut scratch);
        let clamped_mss = u16::from_be_bytes([clamped[62], clamped[63]]);
        assert_eq!(
            clamped_mss, 1220,
            "IPv6 MSS must not be clamped below 1220 (RFC 8200 floor)"
        );
    }

    #[test]
    fn test_tcp_options_parsing_and_variations() {
        // TCP SYN with 2 NOPs + MSS option (total 24B TCP header)
        let mut pkt = craft_ipv4_tcp_syn(1460);
        // Put two NOPs before MSS:
        pkt[40] = 1; // NOP
        pkt[41] = 1; // NOP
                     // Move MSS to 42..46 (requires extending TCP header to 28B)
        pkt.resize(48, 0);
        pkt[2..4].copy_from_slice(&(48u16).to_be_bytes());
        pkt[32] = 0x70; // data offset = 7 (28B)
        pkt[42] = 2; // MSS
        pkt[43] = 4; // Len
        pkt[44..46].copy_from_slice(&(1460u16).to_be_bytes());
        pkt[46] = 0; // End of options
        pkt[47] = 0;
        let csum = compute_tcp_checksum_ipv4(&pkt);
        pkt[36..38].copy_from_slice(&csum.to_be_bytes());

        let clamped = clamp_tcp_mss(&mut pkt, 1380);
        assert!(clamped);
        assert_eq!(u16::from_be_bytes([pkt[44], pkt[45]]), 1380);

        // Boundary: current_mss == max_mss
        assert!(!clamp_tcp_mss(&mut pkt, 1380));

        // Option with kind 2 but invalid length (len = 3 instead of 4)
        pkt[43] = 3;
        assert!(!clamp_tcp_mss(&mut pkt, 1300));

        // Option with len < 2 (corrupted option)
        pkt[43] = 1;
        assert!(!clamp_tcp_mss(&mut pkt, 1300));

        // Corrupted option with len < 2 followed by a subsequent MSS option:
        // Unmutated code must break immediately and NOT process subsequent options.
        // A mutant replacing `||` with `&&` would continue and clamp the subsequent MSS.
        let mut pkt_corrupt_len = craft_ipv4_tcp_syn(1460);
        pkt_corrupt_len.resize(52, 0);
        pkt_corrupt_len[2..4].copy_from_slice(&(52u16).to_be_bytes());
        pkt_corrupt_len[32] = 0x80; // 32B TCP -> opt_end is 52
        pkt_corrupt_len[40] = 3; // Window Scale
        pkt_corrupt_len[41] = 1; // Corrupted len = 1 (< 2)
        pkt_corrupt_len[42] = 2; // Followed by MSS
        pkt_corrupt_len[43] = 4;
        pkt_corrupt_len[44..46].copy_from_slice(&(1460u16).to_be_bytes());
        assert!(!clamp_tcp_mss(&mut pkt_corrupt_len, 1380));

        // Option with len overflowing opt_end
        pkt[43] = 20;
        assert!(!clamp_tcp_mss(&mut pkt, 1300));

        // Truncated option header at boundary: opt_idx + 1 >= opt_end
        // Place Kind=2 at opt_end - 1 with NO space for length byte.
        // Also put a fake MSS option right after opt_end to catch mutants that fail to break!
        let mut truncated_opt = craft_ipv4_tcp_syn(1460);
        truncated_opt.resize(48, 0);
        truncated_opt[2..4].copy_from_slice(&(48u16).to_be_bytes());
        truncated_opt[32] = 0x60; // 24B TCP -> opt_end is 44
        truncated_opt[40] = 1; // NOP
        truncated_opt[41] = 1; // NOP
        truncated_opt[42] = 1; // NOP
        truncated_opt[43] = 2; // Kind = 2 (MSS) at opt_end - 1 (offset 43)
        truncated_opt[44] = 4; // Fake length byte at opt_end
        truncated_opt[45..47].copy_from_slice(&(1460u16).to_be_bytes()); // Fake MSS past opt_end
        assert!(!clamp_tcp_mss(&mut truncated_opt, 1380));

        // Length < 2 boundary: test len = 2 does not break when followed by MSS
        let mut pkt_len2 = craft_ipv4_tcp_syn(1460);
        pkt_len2.resize(52, 0);
        pkt_len2[2..4].copy_from_slice(&(52u16).to_be_bytes());
        pkt_len2[32] = 0x80; // 32B TCP -> opt_end is 52
        pkt_len2[40] = 4; // Option kind 4 (SACK permitted)
        pkt_len2[41] = 2; // len = 2 (valid length for kind 4)
        pkt_len2[42] = 2; // Kind = 2 (MSS)
        pkt_len2[43] = 4; // Len = 4
        pkt_len2[44..46].copy_from_slice(&(1460u16).to_be_bytes());
        pkt_len2[46] = 0; // End of options
        assert!(clamp_tcp_mss(&mut pkt_len2, 1380));
        assert_eq!(u16::from_be_bytes([pkt_len2[44], pkt_len2[45]]), 1380);

        // Multi-option: Kind 3 (Window Scale, len 3) + NOP + MSS
        let mut pkt2 = craft_ipv4_tcp_syn(1460);
        pkt2.resize(48, 0);
        pkt2[2..4].copy_from_slice(&(48u16).to_be_bytes());
        pkt2[32] = 0x70; // 28B TCP
        pkt2[40] = 3; // Window Scale
        pkt2[41] = 3; // Len = 3
        pkt2[42] = 7; // Shift
        pkt2[43] = 1; // NOP
        pkt2[44] = 2; // MSS
        pkt2[45] = 4; // Len = 4
        pkt2[46..48].copy_from_slice(&(1460u16).to_be_bytes());
        let csum2 = compute_tcp_checksum_ipv4(&pkt2);
        pkt2[36..38].copy_from_slice(&csum2.to_be_bytes());

        assert!(clamp_tcp_mss(&mut pkt2, 1380));
        assert_eq!(u16::from_be_bytes([pkt2[46], pkt2[47]]), 1380);
    }

    #[test]
    fn test_malformed_and_boundary_packets() {
        let mut scratch = Vec::new();
        assert!(!clamp_tcp_mss(&mut [], 1380));
        assert!(!clamp_tcp_mss(&mut [0x45; 19], 1380));
        assert!(!clamp_tcp_mss(&mut [0x60; 39], 1380));
        assert_eq!(maybe_clamp_tcp_syn(&[], &mut scratch, 1420), &[]);

        // IPv4 IHL < 20
        let mut bad_ihl = craft_ipv4_tcp_syn(1460);
        bad_ihl[0] = 0x44; // IHL = 16B < 20B
        assert!(!clamp_tcp_mss(&mut bad_ihl, 1380));

        // IPv4 pkt.len() < IHL
        let mut short_ihl = craft_ipv4_tcp_syn(1460);
        short_ihl[0] = 0x47; // IHL = 28B, but truncate to 24B
        short_ihl.truncate(24);
        assert!(!clamp_tcp_mss(&mut short_ihl, 1380));

        // IPv4 pkt.len() < total_len (boundary: pkt.len() == total_len - 1)
        let mut short_total = craft_ipv4_tcp_syn(1460);
        short_total[2..4].copy_from_slice(&(45u16).to_be_bytes()); // total_len = 45 > 44
        assert!(!clamp_tcp_mss(&mut short_total, 1380));

        // IPv4 total_len < ihl + 20 (boundary: total_len = 39 < 40)
        let mut short_ip_tcp = craft_ipv4_tcp_syn(1460);
        short_ip_tcp[2..4].copy_from_slice(&(39u16).to_be_bytes());
        assert!(!clamp_tcp_mss(&mut short_ip_tcp, 1380));

        // IPv4 total_len == ihl + 20 (boundary: exactly 40B, valid but no options)
        let mut no_opt_tcp = craft_ipv4_tcp_syn(1460);
        no_opt_tcp.truncate(40);
        no_opt_tcp[2..4].copy_from_slice(&(40u16).to_be_bytes());
        no_opt_tcp[32] = 0x50; // 20B TCP
        assert!(!clamp_tcp_mss(&mut no_opt_tcp, 1380));

        // IPv6 payload_len < 20 (boundary: payload_len = 19 < 20)
        let mut bad_v6 = vec![0u8; 64];
        bad_v6[0] = 0x60;
        bad_v6[6] = 6;
        bad_v6[4..6].copy_from_slice(&(19u16).to_be_bytes());
        bad_v6[40 + 13] = 0x02; // SYN
        assert!(!clamp_tcp_mss(&mut bad_v6, 1380));

        // IPv6 payload_len == 20 (boundary: valid 20B TCP header, no options)
        let mut no_opt_v6 = vec![0u8; 60];
        no_opt_v6[0] = 0x60;
        no_opt_v6[6] = 6;
        no_opt_v6[4..6].copy_from_slice(&(20u16).to_be_bytes());
        no_opt_v6[40 + 12] = 0x50; // 20B TCP
        no_opt_v6[40 + 13] = 0x02; // SYN
        assert!(!clamp_tcp_mss(&mut no_opt_v6, 1380));

        // IPv6 pkt.len() < 40 + payload_len (boundary: pkt.len() == total_len - 1)
        let mut short_v6 = vec![0u8; 63];
        short_v6[0] = 0x60;
        short_v6[6] = 6;
        short_v6[4..6].copy_from_slice(&(24u16).to_be_bytes()); // total_len = 64 > 63
        short_v6[40 + 13] = 0x02; // SYN
        assert!(!clamp_tcp_mss(&mut short_v6, 1380));

        // TCP data_offset < 20
        let mut bad_offset = craft_ipv4_tcp_syn(1460);
        bad_offset[32] = 0x40; // 16B < 20B
        assert!(!clamp_tcp_mss(&mut bad_offset, 1380));

        // TCP data_offset > tcp_len
        let mut over_offset = craft_ipv4_tcp_syn(1460);
        over_offset[32] = 0x80; // 32B > 24B tcp_len
        assert!(!clamp_tcp_mss(&mut over_offset, 1380));
        assert!(!clamp_tcp_mss(&mut over_offset, 1380));
    }
}
