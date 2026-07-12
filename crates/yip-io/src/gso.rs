//! Shared fate-safe UDP GSO grouping rule, used by both the poll and io_uring
//! backends so the FEC(+addressing)-safety invariant lives in exactly one place:
//! a coalesced `UDP_SEGMENT` skb must never carry two datagrams of one FEC
//! object (same `fate`) and must never mix destinations.
use crate::poll::EgressDatagram;

/// Largest UDP payload the kernel accepts in one datagram.
pub(crate) const MAX_UDP_PAYLOAD: usize = 65_507;
/// Cap on segments coalesced into one `UDP_SEGMENT` send.
pub(crate) const MAX_GSO_SEGMENTS_PER_SEND: usize = 32;

/// If every datagram in `run` (len ≥ 2) shares one destination, one non-zero
/// byte length, and a pairwise-distinct `fate`, return that common length as the
/// GSO segment size; otherwise `None`. The single FEC(+addressing)-safety choke
/// point.
pub(crate) fn can_coalesce(run: &[EgressDatagram]) -> Option<u16> {
    if run.len() < 2 {
        return None;
    }
    let first = run.first()?;
    let first_len = first.bytes.len();
    if first_len == 0 {
        return None;
    }
    let segment_size = u16::try_from(first_len).ok()?;
    let first_dst = first.dst;
    for (i, d) in run.iter().enumerate() {
        if d.bytes.len() != first_len || d.dst != first_dst {
            return None;
        }
        if run[..i].iter().any(|prior| prior.fate == d.fate) {
            return None;
        }
    }
    Some(segment_size)
}

/// Max datagrams to coalesce for a given segment size — bounded by the 64 KB UDP
/// payload ceiling, `MAX_GSO_SEGMENTS_PER_SEND`, and the caller's `hard_cap`.
pub(crate) fn max_gso_run_len(segment_size: u16, hard_cap: usize) -> usize {
    let seg = usize::from(segment_size);
    if seg == 0 {
        return 1;
    }
    (MAX_UDP_PAYLOAD / seg).clamp(1, MAX_GSO_SEGMENTS_PER_SEND.min(hard_cap))
}

/// One fate-safe run: indices into the partitioned slice, plus the common
/// segment size (the shared byte length, or 0 for a non-coalescable singleton).
/// A run with `members.len() >= 2` is GSO-coalescable; length 1 sends plain.
pub(crate) struct GsoRun {
    pub segment_size: u16,
    pub members: Vec<usize>,
}

/// Greedily partition `dgs` into fate-safe runs (arrival order, multi-pass).
/// Each pass starts a run at the first remaining datagram and admits every later
/// remaining datagram that shares its `dst` and byte length, has a `fate` not yet
/// in the run, and fits under `max_gso_run_len(seg, hard_cap)`; the rest defer to
/// the next pass. A zero-length or > `u16` datagram forms its own `segment_size 0`
/// singleton. Reuses `out` (cleared first). Exactly one run is emitted per pass,
/// so the loop always makes progress and terminates.
pub(crate) fn partition_fate_safe(dgs: &[EgressDatagram], hard_cap: usize, out: &mut Vec<GsoRun>) {
    out.clear();
    let mut remaining: Vec<usize> = (0..dgs.len()).collect();
    while !remaining.is_empty() {
        let head_idx = remaining[0];
        let head = &dgs[head_idx];
        match u16::try_from(head.bytes.len()).ok().filter(|&l| l > 0) {
            None => {
                // Cannot be a GSO segment (empty or > u16): emit as a singleton.
                out.push(GsoRun {
                    segment_size: 0,
                    members: vec![head_idx],
                });
                remaining.remove(0);
            }
            Some(seg) => {
                let cap = max_gso_run_len(seg, hard_cap);
                let mut members = vec![head_idx];
                let mut deferred: Vec<usize> = Vec::new();
                for &i in &remaining[1..] {
                    let d = &dgs[i];
                    let admit = d.dst == head.dst
                        && d.bytes.len() == head.bytes.len()
                        && members.iter().all(|&k| dgs[k].fate != d.fate)
                        && members.len() < cap;
                    if admit {
                        members.push(i);
                    } else {
                        deferred.push(i);
                    }
                }
                out.push(GsoRun {
                    segment_size: seg,
                    members,
                });
                remaining = deferred;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poll::EgressDatagram;

    fn dg(fate: u16, dst: &str, len: usize) -> EgressDatagram {
        EgressDatagram {
            fate,
            dst: dst.parse().unwrap(),
            bytes: vec![0u8; len],
        }
    }
    const A: &str = "10.0.0.1:9";
    const B: &str = "10.0.0.2:9";

    #[test]
    fn coalesce_ok_same_dst_len_distinct_fate() {
        let run = [dg(1, A, 1200), dg(2, A, 1200), dg(3, A, 1200)];
        assert_eq!(can_coalesce(&run), Some(1200));
    }
    #[test]
    fn coalesce_none_single() {
        assert_eq!(can_coalesce(&[dg(1, A, 1200)]), None);
    }
    #[test]
    fn coalesce_none_mixed_dst() {
        assert_eq!(can_coalesce(&[dg(1, A, 1200), dg(2, B, 1200)]), None);
    }
    #[test]
    fn coalesce_none_mixed_len() {
        assert_eq!(can_coalesce(&[dg(1, A, 1200), dg(2, A, 1100)]), None);
    }
    #[test]
    fn coalesce_none_repeat_fate() {
        assert_eq!(can_coalesce(&[dg(1, A, 1200), dg(1, A, 1200)]), None);
    }
    #[test]
    fn coalesce_none_zero_len() {
        assert_eq!(can_coalesce(&[dg(1, A, 0), dg(2, A, 0)]), None);
    }
    #[test]
    fn max_run_len_caps_by_udp_ceiling_and_segment_cap() {
        // 1200-byte segments: 65507/1200 = 54, clamped to MAX_GSO_SEGMENTS_PER_SEND (32) ∧ hard_cap.
        assert_eq!(max_gso_run_len(1200, 64), 32);
        assert_eq!(max_gso_run_len(1200, 8), 8);
        assert_eq!(max_gso_run_len(0, 64), 1);
    }

    fn runs(dgs: &[EgressDatagram], cap: usize) -> Vec<(u16, Vec<usize>)> {
        let mut out = Vec::new();
        partition_fate_safe(dgs, cap, &mut out);
        out.into_iter()
            .map(|r| (r.segment_size, r.members))
            .collect()
    }

    #[test]
    fn partition_one_run_all_distinct_fate() {
        let d = [dg(1, A, 1200), dg(2, A, 1200), dg(3, A, 1200)];
        assert_eq!(runs(&d, 64), vec![(1200, vec![0, 1, 2])]);
    }
    #[test]
    fn partition_splits_repeat_fate_to_next_pass() {
        let d = [dg(1, A, 1200), dg(2, A, 1200), dg(1, A, 1200)];
        assert_eq!(runs(&d, 64), vec![(1200, vec![0, 1]), (1200, vec![2])]);
    }
    #[test]
    fn partition_splits_mixed_dst() {
        let d = [dg(1, A, 1200), dg(2, B, 1200)];
        assert_eq!(runs(&d, 64), vec![(1200, vec![0]), (1200, vec![1])]);
    }
    #[test]
    fn partition_splits_mixed_len() {
        let d = [dg(1, A, 1200), dg(2, A, 1100)];
        assert_eq!(runs(&d, 64), vec![(1200, vec![0]), (1100, vec![1])]);
    }
    #[test]
    fn partition_respects_hard_cap() {
        let d = [dg(1, A, 1200), dg(2, A, 1200), dg(3, A, 1200)];
        // cap 2 → first run takes 2, third defers to its own run.
        assert_eq!(runs(&d, 2), vec![(1200, vec![0, 1]), (1200, vec![2])]);
    }
    #[test]
    fn partition_singleton() {
        assert_eq!(runs(&[dg(7, A, 1200)], 64), vec![(1200, vec![0])]);
    }
    #[test]
    fn partition_zero_len_is_singleton_seg0() {
        assert_eq!(runs(&[dg(1, A, 0)], 64), vec![(0, vec![0])]);
    }
}
