//! Syscall and thread scheduling inspection for detecting blocking IO and context switches.

#[cfg(target_os = "linux")]
#[inline]
pub fn get_thread_rusage() -> libc::rusage {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage is invoked with RUSAGE_THREAD and a valid mutable pointer to uninitialized rusage storage.
    let ret = unsafe { libc::getrusage(libc::RUSAGE_THREAD, usage.as_mut_ptr()) };
    assert_eq!(ret, 0, "libc::getrusage failed");
    // SAFETY: getrusage returned 0, confirming the kernel populated the rusage struct.
    unsafe { usage.assume_init() }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FallbackRusage {
    pub ru_nvcsw: i64,
    pub ru_nivcsw: i64,
}

#[cfg(not(target_os = "linux"))]
#[inline]
pub fn get_thread_rusage() -> FallbackRusage {
    FallbackRusage::default()
}

/// Asserts that the enclosed block performs no blocking syscalls or locks that trigger
/// a voluntary context switch on Linux data-plane threads.
#[macro_export]
macro_rules! assert_no_blocking_io {
    ($block:expr) => {{
        #[cfg(target_os = "linux")]
        let usage_before = $crate::syscall::get_thread_rusage();
        let result = $block;
        #[cfg(target_os = "linux")]
        {
            let usage_after = $crate::syscall::get_thread_rusage();
            assert_eq!(
                usage_after.ru_nvcsw - usage_before.ru_nvcsw,
                0,
                "Voluntary context switch detected: thread blocked on syscall or lock"
            );
        }
        result
    }};
}
