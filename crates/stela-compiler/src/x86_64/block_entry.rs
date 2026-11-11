//! The block ABI's entry for hosts that call native code from Rust: it sets
//! [`crate::GuestState::exit_rsp`] to the caller's return address, which
//! every exit reloads RSP from before its `ret` ([`super::chain::EXIT_RETURN`]),
//! and jumps to the code.
use crate::GuestState;

#[cfg(target_os = "macos")]
core::arch::global_asm!(
    ".globl _stela_block_enter",
    "_stela_block_enter:",
    "mov [rdi + {exit_rsp}], rsp",
    "jmp rcx",
    exit_rsp = const super::chain::EXIT_RSP_OFFSET,
);
#[cfg(not(target_os = "macos"))]
core::arch::global_asm!(
    ".globl stela_block_enter",
    "stela_block_enter:",
    "mov [rdi + {exit_rsp}], rsp",
    "jmp rcx",
    exit_rsp = const super::chain::EXIT_RSP_OFFSET,
);

unsafe extern "sysv64" {
    fn stela_block_enter(state: *mut GuestState, first: u64, second: u64, code: u64) -> u128;
}

/// Enter `code` with RDI = `state` and RSI, RDX = `first`, `second`, the
/// exits' stack pointer set: RAX in the low and RDX in the high half of
/// what it returns.
///
/// # Safety
/// `code` must be executable code of the block ABI the state and the two
/// arguments satisfy, with every requirement of that ABI upheld by the caller.
pub unsafe fn enter(code: *const u8, state: *mut GuestState, first: u64, second: u64) -> u128 {
    // SAFETY: the caller's contract; the entry only stores RSP in the state
    // and jumps.
    unsafe { stela_block_enter(state, first, second, code as u64) }
}
