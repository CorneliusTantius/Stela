//! Running emitted code on the host in tests.
use crate::{GuestState, block::loop_budget::LoopBudget};

/// Enter `code` at its first byte with the block ABI's entry: RDI = `state`,
/// RSI and RDX `first` and `second`; RAX and RDX after its exit.
///
/// # Safety
/// `code` must be executable code of the block ABI that `state` and the
/// arguments satisfy.
pub(crate) unsafe fn enter(
    code: *const u8,
    state: *mut GuestState,
    first: u64,
    second: u64,
) -> u128 {
    // SAFETY: the caller's contract.
    unsafe { super::block_entry::enter(code, state, first, second) }
}

/// [`enter`] with what the code returns in RAX, or RAX and RDX, taken as
/// `R`: a value of at most 16 bytes, its low bytes first.
///
/// # Safety
/// As for [`enter`]; `R` must be valid for any bits.
pub(crate) unsafe fn call<R>(
    code: *const u8,
    state: *mut GuestState,
    first: u64,
    second: u64,
) -> R {
    const { assert!(core::mem::size_of::<R>() <= 16) };
    // SAFETY: the caller's contract.
    let returned = unsafe { enter(code, state, first, second) };
    // SAFETY: at most the 16 bytes of `returned`, low first; any bits are
    // valid for `R`.
    unsafe { core::mem::transmute_copy(&returned) }
}

/// Run `code`, followed by a RET, on the host with RDI = `state`: RAX after
/// it, the next PC of a block's exit.
pub(crate) fn run(code: &[u8], state: &mut GuestState) -> u64 {
    // SAFETY: the live RX mapping contains the emitted code.
    run_mapped(code, |page| unsafe { call(page.cast(), state, 0, 0) })
}

/// Run a resident block with its explicit invocation-local budget.
pub(crate) fn run_with_budget(code: &[u8], state: &mut GuestState, budget: &mut LoopBudget) -> u64 {
    // SAFETY: the RX mapping contains the emitted budgeted code.
    run_mapped(code, |page| unsafe {
        call(page.cast(), state, budget as *mut LoopBudget as u64, 0)
    })
}

fn run_mapped(code: &[u8], run: impl FnOnce(*mut core::ffi::c_void) -> u64) -> u64 {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            bytes: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x20;
    const PROT_READ_WRITE: i32 = 3;
    const PROT_READ_EXECUTE: i32 = 5;
    const MAP_PRIVATE: i32 = 2;
    const RET: u8 = 0xc3;
    let bytes = (code.len() + 1).next_multiple_of(4096);
    // SAFETY: private anonymous memory, RX after the copy and unmapped after
    // the call, using the selected emitted test entry.
    unsafe {
        let page = mmap(
            core::ptr::null_mut(),
            bytes,
            PROT_READ_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(page as usize, usize::MAX);
        core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
        page.cast::<u8>().add(code.len()).write(RET);
        assert_eq!(mprotect(page, bytes, PROT_READ_EXECUTE), 0);
        let returned = run(page);
        assert_eq!(munmap(page, bytes), 0);
        returned
    }
}
