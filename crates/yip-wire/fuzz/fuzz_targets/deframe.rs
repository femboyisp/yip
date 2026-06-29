#![no_main]
use libfuzzer_sys::fuzz_target;

// M2 replaces this with a real WireCodec instance and asserts deframe never
// panics on arbitrary input. For now it proves the fuzz harness builds.
fuzz_target!(|data: &[u8]| {
    let _ = data;
});
