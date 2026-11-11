//! Keyless XPACI/XPACD completion with the current regime's address masks.
//!
//! Arm `Strip` selects the lower/upper TnSZ and effective TBI by bit 55.
//! The runtime derives both keep masks through its authoritative PAC layout
//! and closes this cell whenever derived state changes. A closed cell takes
//! the original instruction exit, without changing architectural state.
use super::Thunk;
use crate::x86_64::asm::{Alu, Asm, BitTest, Code, Cond, Gpr, Mem, Patch, Size};
use crate::{GuestAddress, Place, aarch64::Register, block::ExitKind};

/// Fixed-address state read by a strip thunk. Each keep mask excludes the
/// extension field that is restored from bit 55; tagged bytes remain set.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cell {
    pub enabled: u64,
    pub keep: [u64; 2],
    /// Complement of the upper-range keep mask, used on an independent
    /// dependency chain from the pointer's AND.
    pub upper_extension: u64,
}

const LOWER: i32 = core::mem::offset_of!(Cell, keep) as i32;
const UPPER: i32 = LOWER + 8;
const UPPER_EXTENSION: i32 = core::mem::offset_of!(Cell, upper_extension) as i32;
const REGION_BIT: u8 = 55;

/// XPAC of X`register` (below 31) from `cell`, in place; the jump taken
/// while the cell is closed, before any change. Clobbers RAX, RCX, RDX, R8
/// and host flags.
pub(super) fn strip(asm: &mut Asm, register: u8, cell: Place) -> Patch {
    use Gpr::{R8, Rax, Rcx, Rdx};
    use Size::Qword;
    let pointer = asm.guest(Register::X(register)).expect("X0..X30");
    asm.place(Rdx, cell);
    asm.alu_imm8(Alu::Cmp, Qword, Mem::base(Rdx, 0), 0);
    let closed = asm.jcc(Cond::E);
    asm.mov_load(Qword, Rax, pointer);
    asm.mov_load(Qword, Rcx, Mem::base(Rdx, LOWER));
    asm.bit_imm(BitTest::Bt, Qword, Rax, REGION_BIT);
    asm.cmov(Cond::B, Qword, Rcx, Mem::base(Rdx, UPPER));
    // Bit 55 replicated.
    asm.alu(Alu::Sbb, Qword, R8, R8);
    asm.alu_load(Alu::And, Qword, R8, Mem::base(Rdx, UPPER_EXTENSION));
    asm.alu(Alu::And, Qword, Rax, Rcx);
    asm.alu(Alu::Or, Qword, Rax, R8);
    asm.mov_store(Qword, pointer, Rax);
    closed
}

/// Complete XPAC on `register`, with no key access, from `cell` while open.
/// Only RAX, RCX, RDX, R8 and host flags are clobbered, as at a block exit;
/// guest NZCV, SP and every other register remain in their canonical frame.
pub fn thunk(pc: GuestAddress, register: u8, cell: Place) -> Option<Thunk> {
    if register > 31 {
        return None;
    }
    let mut code = Code::pinned();
    let mut asm = code.asm();
    // XZR has no effect and depends on no regime state.
    let closed = (register != 31).then(|| strip(&mut asm, register, cell));
    let next = asm.len();
    let fallthrough = GuestAddress(pc.0.wrapping_add(4));
    super::super::block::direct_exit_with(&mut asm, fallthrough, ExitKind::Fallthrough);
    if let Some(closed) = closed {
        asm.bind(closed);
    }
    super::super::block::direct_exit_with(&mut asm, pc, ExitKind::PointerAuthentication);
    Some(Thunk::new(code.into_bytes(), Some(next), None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Anchor;

    const CELL: Place = Place::new(Anchor::Pointer, 0);

    #[test]
    fn invalid_register_refuses_and_xzr_needs_no_cell_access() {
        assert!(thunk(GuestAddress(0x4000), 32, CELL).is_none());
        let zero = thunk(GuestAddress(u64::MAX - 3), 31, CELL).unwrap();
        assert_eq!(zero.next, Some(0));
        assert_eq!(
            &zero.code[..super::super::super::chain::DIRECT_EXIT_BYTES],
            // Padded for its offset, where a link patches it.
            &super::super::super::chain::direct_exit_at(0, GuestAddress(0), ExitKind::Fallthrough)
        );
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn native_pointer_strip_changes_only_its_destination() {
        use crate::GuestState;
        use core::ffi::c_void;
        unsafe extern "C" {
            fn mmap(
                p: *mut c_void,
                n: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                off: i64,
            ) -> *mut c_void;
            fn mprotect(p: *mut c_void, n: usize, prot: i32) -> i32;
            fn munmap(p: *mut c_void, n: usize) -> i32;
        }
        #[cfg(target_os = "macos")]
        const ANONYMOUS: i32 = 0x1000;
        #[cfg(target_os = "linux")]
        const ANONYMOUS: i32 = 0x20;
        #[repr(C)]
        #[derive(Debug, PartialEq, Eq)]
        struct Exit(u64, u64);
        let pc = GuestAddress(0x4000);
        let mut cell = Cell::default();
        for register in [0, 8, 17, 30, 31] {
            let code = thunk(pc, register, CELL).unwrap();
            // SAFETY: private anonymous page, writable only during copying,
            // then executable; code touches only this live cell and frame.
            unsafe {
                let page = mmap(core::ptr::null_mut(), 4096, 3, 2 | ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                let entered = crate::x86_64::pinned::entered(&code.code);
                core::ptr::copy_nonoverlapping(entered.as_ptr(), page.cast(), entered.len());
                assert_eq!(mprotect(page, 4096, 5), 0);
                let run = |state: *mut crate::GuestState| -> Exit {
                    crate::x86_64::native::call::<Exit>(page as *const u8, state, 0, 0)
                };
                let mut before = GuestState::default();
                for (i, value) in before.x.iter_mut().enumerate() {
                    *value = 0xfeed_0000_0000_0000 | i as u64;
                }
                before.anchors[Anchor::Pointer] = &cell as *const Cell as u64;
                before.sp = 0x1234_0000;
                before.nzcv = 0xa000_0000;
                before.exclusive_bytes = 0x9876_5432;
                before.fpcr = 0x0300_0000;
                before.fpsr = 0x0800_009f;
                before
                    .v
                    .fill([0x1234_5678_9abc_def0, 0xffff_5555_0000_aaaa]);
                for lower_bits in [25, 39, 47, 48] {
                    for upper_bits in [25, 39, 47, 48] {
                        for tagged in [false, true] {
                            let top = if tagged { 0xff00_0000_0000_0000 } else { 0 };
                            cell = Cell {
                                enabled: 1,
                                keep: [
                                    top | ((1 << lower_bits) - 1),
                                    top | ((1 << upper_bits) - 1),
                                ],
                                upper_extension: !(top | ((1 << upper_bits) - 1)),
                            };
                            core::hint::black_box(&cell);
                            for pointer in [0, u64::MAX, 1 << 55, 1 << 63, 0xab91_ffee_1234_5678] {
                                let mut input = before.clone();
                                if register != 31 {
                                    input.x[usize::from(register)] = pointer;
                                }
                                let mut expected = input.clone();
                                if register != 31 {
                                    let upper = pointer & (1 << 55) != 0;
                                    let keep = cell.keep[usize::from(upper)];
                                    expected.x[usize::from(register)] =
                                        (pointer & keep) | if upper { !keep } else { 0 };
                                }
                                assert_eq!(
                                    run(&mut input),
                                    Exit(pc.0 + 4, ExitKind::Fallthrough as u64)
                                );
                                assert_eq!(input, expected);
                                cell.enabled = 0;
                                core::hint::black_box(&cell);
                                let mut closed = before.clone();
                                let kind = if register == 31 {
                                    ExitKind::Fallthrough
                                } else {
                                    ExitKind::PointerAuthentication
                                };
                                let at = if register == 31 { pc.0 + 4 } else { pc.0 };
                                assert_eq!(run(&mut closed), Exit(at, kind as u64));
                                assert_eq!(closed, before);
                                cell.enabled = 1;
                            }
                        }
                    }
                }
                assert_eq!(munmap(page, 4096), 0);
            }
        }
    }
}
