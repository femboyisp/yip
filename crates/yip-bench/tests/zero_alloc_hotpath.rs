//! Deterministic zero-allocation hotpath verification gate under DHAT.
#![forbid(unsafe_code)]

use dhat::Alloc as DhatAlloc;
use yip_wire::{Codec, Frame, WireCodec};

#[global_allocator]
static ALLOC: DhatAlloc = DhatAlloc;

#[test]
fn test_zero_alloc_hotpath_framing() {
    let _profiler = dhat::Profiler::builder().testing().build();

    let codec = Codec::new([1u8; 16], [2u8; 16]);
    let frame = Frame {
        conn_tag: 1,
        object_id: 0,
        payload_id: [0; 4],
        flags: 0,
        payload: vec![9u8; 1200],
    };
    let datagram = codec.frame(&frame);

    // Enter zero-allocation evaluated region
    let stats_before = dhat::HeapStats::get();

    let deframed = codec
        .deframe_borrowed(&datagram)
        .expect("valid frame deframes");
    assert_eq!(deframed.conn_tag, 1);
    assert_eq!(deframed.payload, &frame.payload[..]);

    let stats_after = dhat::HeapStats::get();
    // Verify no blocks or bytes were allocated inside the deframing hotpath
    assert_eq!(
        stats_after.total_blocks - stats_before.total_blocks,
        0,
        "Heap allocations detected on deframing hotpath (blocks)"
    );
    assert_eq!(
        stats_after.total_bytes - stats_before.total_bytes,
        0,
        "Heap allocations detected on deframing hotpath (bytes)"
    );

    // Verify looped execution also remains strictly zero-allocation
    let loop_before = dhat::HeapStats::get();
    for _ in 0..100 {
        let borrowed = codec
            .deframe_borrowed(&datagram)
            .expect("valid frame deframes in loop");
        assert_eq!(borrowed.conn_tag, 1);
        assert_eq!(borrowed.payload.len(), 1200);
    }
    let loop_after = dhat::HeapStats::get();
    assert_eq!(
        loop_after.total_blocks - loop_before.total_blocks,
        0,
        "Heap allocations detected on looped deframing hotpath (blocks)"
    );
    assert_eq!(
        loop_after.total_bytes - loop_before.total_bytes,
        0,
        "Heap allocations detected on looped deframing hotpath (bytes)"
    );
}
