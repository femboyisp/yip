//! Wire framing for the yip data plane: keyed header-protection and
//! coverage-based authentication. Behavior lands in milestone M2; this
//! milestone establishes the public surface later crates depend on.
#![forbid(unsafe_code)]

/// A single on-wire frame carrying one FEC symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Epoch-rotating keyed token selecting the session/decoder.
    pub conn_tag: u64,
    /// Which pipelined FEC object this symbol belongs to.
    pub object_id: u16,
    /// The ciphertext symbol payload.
    pub payload: Vec<u8>,
}

/// Errors from decoding a wire datagram.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// Coverage-auth tag did not verify.
    #[error("authentication failed")]
    AuthFailed,
    /// Datagram was too short or structurally invalid.
    #[error("malformed datagram")]
    Malformed,
}

/// Encodes [`Frame`]s to datagrams and back. Implemented in M2.
pub trait WireCodec {
    /// Serialize and header-protect a frame into a wire datagram.
    fn frame(&self, frame: &Frame) -> Vec<u8>;
    /// Authenticate, deprotect, and parse a datagram into a [`Frame`].
    fn deframe(&self, datagram: &[u8]) -> Result<Frame, WireError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_carries_object_id() {
        let frame = Frame {
            conn_tag: 7,
            object_id: 42,
            payload: vec![1, 2, 3],
        };
        assert_eq!(frame.object_id, 42);
    }
}
