//! Glue mapping the FEC transport's `Symbol`s onto authenticated wire `Frame`s,
//! and deriving the wire codec keys from the session channel binding.

use yip_transport::{FlowClass, Symbol};
use yip_wire::Frame;

/// Derive the wire codec's (auth_key, hp_key) from the session channel binding.
/// Both peers compute the same binding, so both derive the same keys.
pub fn derive_wire_keys(channel_binding: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
    use blake2::{Blake2s256, Digest};
    let mut auth = [0u8; 16];
    let mut hp = [0u8; 16];
    let a = Blake2s256::new_with_prefix(b"yip wire auth")
        .chain_update(channel_binding)
        .finalize();
    let h = Blake2s256::new_with_prefix(b"yip wire hp")
        .chain_update(channel_binding)
        .finalize();
    auth.copy_from_slice(&a[..16]);
    hp.copy_from_slice(&h[..16]);
    (auth, hp)
}

/// Encode a flow class into the low bits of the frame flags byte.
pub fn class_to_flags(c: FlowClass) -> u8 {
    match c {
        FlowClass::Realtime => 0,
        FlowClass::Bulk => 1,
        FlowClass::Default => 2,
    }
}

/// Decode the flow class from the frame flags byte.
pub fn flags_to_class(f: u8) -> FlowClass {
    match f & 0x03 {
        0 => FlowClass::Realtime,
        1 => FlowClass::Bulk,
        _ => FlowClass::Default,
    }
}

/// Build a wire frame for one FEC symbol: the AEAD counter and object size ride
/// in the (authenticated) payload prefix; the class rides in flags.
pub fn symbol_to_frame(conn_tag: u64, sym: &Symbol, counter: u64, class: FlowClass) -> Frame {
    let mut payload = Vec::with_capacity(12 + sym.data.len());
    payload.extend_from_slice(&counter.to_be_bytes());
    payload.extend_from_slice(&sym.object_size.to_be_bytes());
    payload.extend_from_slice(&sym.data);
    Frame {
        conn_tag,
        object_id: sym.object_id,
        payload_id: sym.payload_id,
        flags: class_to_flags(class),
        payload,
    }
}

/// Parse a received frame back into a `(Symbol, counter, class)`, or None if the
/// payload is shorter than the 12-byte counter+object_size prefix.
pub fn frame_to_symbol(frame: &Frame) -> Option<(Symbol, u64, FlowClass)> {
    if frame.payload.len() < 12 {
        return None;
    }
    let counter = u64::from_be_bytes(frame.payload[0..8].try_into().ok()?);
    let object_size = u32::from_be_bytes(frame.payload[8..12].try_into().ok()?);
    let sym = Symbol {
        object_id: frame.object_id,
        object_size,
        payload_id: frame.payload_id,
        data: frame.payload[12..].to_vec(),
    };
    Some((sym, counter, flags_to_class(frame.flags)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_keys_are_deterministic_and_distinct() {
        let cb = [7u8; 32];
        let (a, h) = derive_wire_keys(&cb);
        let (a2, h2) = derive_wire_keys(&cb);
        assert_eq!((a, h), (a2, h2), "deterministic");
        assert_ne!(a, h, "auth and hp keys differ");
    }

    #[test]
    fn symbol_frame_roundtrips_with_counter_and_class() {
        let sym = Symbol {
            object_id: 5,
            object_size: 1234,
            payload_id: [1, 2, 3, 4],
            data: vec![9, 8, 7],
        };
        let frame = symbol_to_frame(42, &sym, 99, FlowClass::Bulk);
        assert_eq!(frame.object_id, 5);
        assert_eq!(frame.payload_id, [1, 2, 3, 4]);
        let (got, counter, class) = frame_to_symbol(&frame).unwrap();
        assert_eq!(got, sym);
        assert_eq!(counter, 99);
        assert_eq!(class, FlowClass::Bulk);
    }

    #[test]
    fn frame_to_symbol_rejects_short_payload() {
        let frame = Frame {
            conn_tag: 1,
            object_id: 0,
            payload_id: [0; 4],
            flags: 0,
            payload: vec![0; 4],
        };
        assert!(frame_to_symbol(&frame).is_none());
    }
}
