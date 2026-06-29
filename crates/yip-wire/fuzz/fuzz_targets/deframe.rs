#![no_main]
use libfuzzer_sys::fuzz_target;
use yip_wire::{Codec, WireCodec};

// deframe must never panic on arbitrary bytes. For inputs it accepts, the
// parsed frame must re-frame and deframe back to an equal frame.
fuzz_target!(|data: &[u8]| {
    let codec = Codec::new([0x11; 16], [0x22; 16]);
    if let Ok(frame) = codec.deframe(data) {
        let reframed = codec.frame(&frame);
        let again = codec.deframe(&reframed).expect("re-framed frame must deframe");
        assert_eq!(frame, again);
    }
});
