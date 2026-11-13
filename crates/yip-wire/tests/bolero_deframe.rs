#![forbid(unsafe_code)]

use bolero::check;
use yip_wire::{Codec, Frame, WireCodec};

#[test]
fn bolero_deframe_never_panics_and_roundtrips() {
    check!().with_type::<Vec<u8>>().for_each(|data| {
        let codec = Codec::new([0x11; 16], [0x22; 16]);

        let borrowed_res = codec.deframe_borrowed(data);
        let owned_res = codec.deframe(data);

        match (borrowed_res, owned_res) {
            (Ok(borrowed), Ok(owned)) => {
                assert_eq!(borrowed.to_owned(), owned);

                let reframed = codec.frame(&owned);
                let again_borrowed = codec
                    .deframe_borrowed(&reframed)
                    .expect("re-framed frame must deframe_borrowed cleanly");
                assert_eq!(borrowed, again_borrowed);

                let again_owned = codec
                    .deframe(&reframed)
                    .expect("re-framed frame must deframe cleanly");
                assert_eq!(owned, again_owned);
            }
            (Err(e1), Err(e2)) => {
                assert_eq!(e1, e2);
            }
            _ => {
                panic!("deframe and deframe_borrowed disagreed on validity");
            }
        }
    });
}

#[test]
fn bolero_frame_roundtrip() {
    check!()
        .with_type::<(u64, u16, [u8; 4], u8, Vec<u8>)>()
        .for_each(|(conn_tag, object_id, payload_id, flags, payload)| {
            let codec = Codec::new([0x33; 16], [0x44; 16]);
            let frame = Frame {
                conn_tag: *conn_tag,
                object_id: *object_id,
                payload_id: *payload_id,
                flags: *flags,
                payload: payload.clone(),
            };

            let wire = codec.frame(&frame);

            let borrowed = codec
                .deframe_borrowed(&wire)
                .expect("valid frame must deframe_borrowed");
            assert_eq!(borrowed.to_owned(), frame);

            let deframed = codec.deframe(&wire).expect("valid frame must deframe");
            assert_eq!(deframed, frame);
        });
}
