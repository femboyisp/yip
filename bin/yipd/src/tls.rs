//! TLS-mimicry transport (3c.2): a rustls TLS-over-TCP costume carrying yip's
//! UNCHANGED inner protocol (Noise-IK / FEC / AEAD via `PeerManager`), framed as
//! length-prefixed datagrams over the TLS byte-stream. Mirrors `quic.rs` (3c.1).

use std::io;

pub(crate) const TLS_FRAME_MAX: usize = yip_io::MAX_WIRE_DATAGRAM;

/// Append `[u16 BE length][dg]` to `out`. Errors if `dg` exceeds `TLS_FRAME_MAX`.
#[cfg_attr(not(test), expect(dead_code, reason = "used by run_tls in Task 3"))]
pub(crate) fn frame_datagram(dg: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    let len = u16::try_from(dg.len())
        .ok()
        .filter(|_| dg.len() <= TLS_FRAME_MAX)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram too large for TLS frame",
            )
        })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(dg);
    Ok(())
}

/// Reassembles length-prefixed datagrams from a TLS plaintext byte-stream.
#[derive(Default)]
#[cfg_attr(not(test), expect(dead_code, reason = "used by run_tls in Task 3"))]
pub(crate) struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// Append freshly-decrypted TLS plaintext.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by run_tls in Task 3"))]
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Pop one complete datagram; `Ok(None)` if incomplete. Fail-closed on a zero
    /// or `> TLS_FRAME_MAX` length prefix (a hostile/corrupt peer).
    #[cfg_attr(not(test), expect(dead_code, reason = "used by run_tls in Task 3"))]
    pub(crate) fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.buf.len() < 2 {
            return Ok(None);
        }
        let len = usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]]));
        if len == 0 || len > TLS_FRAME_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad TLS frame length",
            ));
        }
        if self.buf.len() < 2 + len {
            return Ok(None);
        }
        let dg = self.buf[2..2 + len].to_vec();
        self.buf.drain(..2 + len);
        Ok(Some(dg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_single() {
        let dg = b"hello yip";
        let mut wire = Vec::new();
        frame_datagram(dg, &mut wire).unwrap();
        let mut r = FrameReader::default();
        r.push(&wire);
        assert_eq!(r.next().unwrap().unwrap(), dg);
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn frame_reassembles_across_partial_reads() {
        let dg = vec![0xABu8; 1200];
        let mut wire = Vec::new();
        frame_datagram(&dg, &mut wire).unwrap();
        let mut r = FrameReader::default();
        // deliver the wire in three arbitrary chunks
        r.push(&wire[..1]);
        assert!(r.next().unwrap().is_none());
        r.push(&wire[1..700]);
        assert!(r.next().unwrap().is_none());
        r.push(&wire[700..]);
        assert_eq!(r.next().unwrap().unwrap(), dg);
    }

    #[test]
    fn frame_two_back_to_back() {
        let (a, b) = (b"aaa".as_slice(), b"bbbb".as_slice());
        let mut wire = Vec::new();
        frame_datagram(a, &mut wire).unwrap();
        frame_datagram(b, &mut wire).unwrap();
        let mut r = FrameReader::default();
        r.push(&wire);
        assert_eq!(r.next().unwrap().unwrap(), a);
        assert_eq!(r.next().unwrap().unwrap(), b);
        assert!(r.next().unwrap().is_none());
    }

    #[test]
    fn frame_oversize_body_errs_on_write() {
        let big = vec![0u8; TLS_FRAME_MAX + 1];
        assert!(frame_datagram(&big, &mut Vec::new()).is_err());
    }

    #[test]
    fn reader_rejects_zero_and_oversize_len() {
        let mut r = FrameReader::default();
        r.push(&[0u8, 0]); // len 0
        assert!(r.next().is_err());
        let mut r2 = FrameReader::default();
        let bad = u16::try_from(TLS_FRAME_MAX).unwrap().wrapping_add(1);
        // only valid if TLS_FRAME_MAX < u16::MAX; if TLS_FRAME_MAX >= 65535 this
        // arm is unreachable — assert the max instead. Guard accordingly.
        if usize::from(bad) > TLS_FRAME_MAX && bad != 0 {
            r2.push(&bad.to_be_bytes());
            assert!(r2.next().is_err());
        }
    }
}
