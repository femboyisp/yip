//! Volatile zeroize verification for sensitive cryptographic state and key types.
//!
//! Verifies that `SymmetricState`, `Zeroizing<[u8; 32]>`, and `PqDecapsKey` overwrite their
//! underlying memory with zeroes upon `Drop`. Canary buffers (`0xA5`) are pre-allocated,
//! the types are initialized in place and subsequently dropped, followed by a full compiler
//! fence (`SeqCst`) and volatile memory reads to detect lingering secrets.

use std::mem::size_of;
use std::sync::atomic::{compiler_fence, Ordering};
use yip_crypto::{generate_pq_keypair, PqDecapsKey, SymmetricState};
use zeroize::Zeroizing;

const CANARY_BYTE: u8 = 0xA5;

#[test]
fn test_zeroize_symmetric_state_on_drop() {
    let size = size_of::<SymmetricState>();
    let mut canary_buf: Box<[u8]> = vec![CANARY_BYTE; size].into_boxed_slice();
    let raw_ptr = canary_buf.as_mut_ptr();

    // SAFETY:
    // 1. Memory Validity: `raw_ptr` points to a live heap allocation sized for `SymmetricState`.
    // 2. Initialization: `std::ptr::write` initializes `state_ptr` with a valid `SymmetricState` instance.
    // 3. Drop: `std::ptr::drop_in_place` runs the destructor in place without freeing the outer `canary_buf`.
    unsafe {
        let state_ptr = raw_ptr as *mut SymmetricState;
        std::ptr::write(state_ptr, SymmetricState::new(b"canary_protocol_test"));
        std::ptr::drop_in_place(state_ptr);
    }

    compiler_fence(Ordering::SeqCst);

    for i in 0..size {
        // SAFETY:
        // 1. Pointer Validity: `raw_ptr` was obtained from `canary_buf`, an active heap allocation
        //    of length `size` that remains allocated and valid for the entire scope of this loop.
        // 2. Bounds: Offset `i` satisfies `0 <= i < size`, which is strictly within the allocated
        //    bounds of `canary_buf`.
        // 3. Absence of Use-After-Free: `std::ptr::drop_in_place` invoked the destructor for
        //    `SymmetricState` without deallocating `canary_buf`. The backing byte slice is alive
        //    and immutable at the time of this read.
        // 4. Alignment: `u8` has an alignment of 1 byte, satisfying all alignment requirements.
        let val = unsafe { core::ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            val, 0x00,
            "SymmetricState memory at offset {i} was not zeroized on drop"
        );
    }
}

#[test]
fn test_zeroize_zeroizing_array_on_drop() {
    let size = size_of::<Zeroizing<[u8; 32]>>();
    let mut canary_buf: Box<[u8]> = vec![CANARY_BYTE; size].into_boxed_slice();
    let raw_ptr = canary_buf.as_mut_ptr();

    // SAFETY:
    // 1. Memory Validity: `raw_ptr` points to a live heap allocation sized for `Zeroizing<[u8; 32]>`.
    // 2. Initialization: `std::ptr::write` initializes `z_ptr` with valid array data.
    // 3. Drop: `std::ptr::drop_in_place` runs the destructor in place without freeing the outer `canary_buf`.
    unsafe {
        let z_ptr = raw_ptr as *mut Zeroizing<[u8; 32]>;
        std::ptr::write(z_ptr, Zeroizing::new([0x5A; 32]));
        std::ptr::drop_in_place(z_ptr);
    }

    compiler_fence(Ordering::SeqCst);

    for i in 0..size {
        // SAFETY:
        // 1. Pointer Validity: `raw_ptr` is derived from an active `Box<[u8]>` allocation of length
        //    `size` bytes. The heap buffer remains allocated and mapped in memory.
        // 2. Bounds: The read offset `i` satisfies `0 <= i < size`, staying strictly within bounds.
        // 3. Absence of Use-After-Free: Only the `Zeroizing<[u8; 32]>` value in the buffer was dropped;
        //    the enclosing `canary_buf` heap allocation was not deallocated.
        // 4. Alignment: Single-byte reads at `raw_ptr.add(i)` are naturally aligned for `u8`.
        let val = unsafe { core::ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            val, 0x00,
            "Zeroizing<[u8; 32]> memory at offset {i} was not zeroized on drop"
        );
    }
}

#[test]
fn test_zeroize_pq_decaps_key_on_drop() {
    let size = size_of::<PqDecapsKey>();
    let mut canary_buf: Box<[u8]> = vec![CANARY_BYTE; size].into_boxed_slice();
    let raw_ptr = canary_buf.as_mut_ptr();

    let (_, dk) = generate_pq_keypair();

    // SAFETY:
    // 1. Memory Validity: `raw_ptr` points to a live heap allocation sized for `PqDecapsKey`.
    // 2. Initialization: `std::ptr::write` initializes `dk_ptr` with a valid `PqDecapsKey` instance.
    // 3. Drop: `std::ptr::drop_in_place` runs the destructor in place without freeing the outer `canary_buf`.
    unsafe {
        let dk_ptr = raw_ptr as *mut PqDecapsKey;
        std::ptr::write(dk_ptr, dk);
        std::ptr::drop_in_place(dk_ptr);
    }

    compiler_fence(Ordering::SeqCst);

    for i in 0..size {
        // SAFETY:
        // 1. Pointer Validity: `raw_ptr` originates from `canary_buf`, which is a valid, live
        //    heap allocation of size `size_of::<PqDecapsKey>()`.
        // 2. Bounds: `i` is in `0..size`, strictly within the byte allocation.
        // 3. Absence of Use-After-Free: `std::ptr::drop_in_place` only invoked `PqDecapsKey::drop`,
        //    which scrubbed internal state while leaving `canary_buf` allocated. The backing memory
        //    is fully valid for volatile reads.
        // 4. Alignment: Read operations target `u8` elements at byte offsets, requiring 1-byte alignment.
        let val = unsafe { core::ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            val, 0x00,
            "PqDecapsKey memory at offset {i} was not zeroized on drop"
        );
    }
}
