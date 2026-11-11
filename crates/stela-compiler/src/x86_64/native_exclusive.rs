//! LDXR and STXR of one register in system-mode blocks of PEs that run on
//! host cores of their own (`Options::with_native_system`), which pass by
//! value (the engine's `parallel`): the load records its address, width and
//! value in the guest frame, and a store to that address and width compares
//! the value and stores in one LOCK CMPXCHG. A write of the same value by
//! another PE between them goes unseen, as with LSE CAS.
//!
//! A store to any other address or width, like every fault, a pair and CLREX,
//! exits to the engine at the instruction, with the frame's monitor intact
//! for it to adopt. Code clobbers RAX, RCX and RDX.
use super::atomic::{self, read_rax};
use super::block::direct_exit;
use crate::GuestState;
use crate::aarch64::{
    Register,
    exclusive::{Data, Kind, Operand},
};
use crate::block::{ExitKind, SystemInstruction, system::SystemOperation};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, Size, resolve};
use core::mem::offset_of;

/// The frame's monitor fields, of which no bytes means none is set.
fn address_field() -> Mem {
    super::frame(offset_of!(GuestState, exclusive_address) as u32)
}
fn value_field() -> Mem {
    super::frame(offset_of!(GuestState, exclusive_value) as u32)
}
fn bytes_field() -> Mem {
    super::frame(offset_of!(GuestState, exclusive_bytes) as u32)
}

/// One register's exclusive load or store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scalar {
    bytes: u8,
    base: Register,
    data: Register,
    kind: Kind,
}

/// The transfer of `instruction`, if it is one code can complete.
pub fn operand(instruction: &SystemInstruction) -> Option<Scalar> {
    match instruction.operation {
        SystemOperation::Exclusive(Ok(Operand::Transfer {
            element_bytes,
            base,
            data: Data::Scalar(data),
            kind,
        })) => Some(Scalar {
            bytes: element_bytes,
            base,
            data,
            kind,
        }),
        _ => None,
    }
}

/// `transfer`, the operand of `instruction`, ending with the direct exit
/// past it that a thunk chains on.
pub(crate) fn emit(
    code: &mut Code,
    transfer: Scalar,
    instruction: &SystemInstruction,
    checks: super::MemoryChecks,
) {
    let Scalar {
        bytes,
        base,
        data,
        kind,
    } = transfer;
    atomic::address(code, base, bytes, checks);
    match kind {
        Kind::Load { .. } => {
            read_rax(code, bytes);
            let mut asm = code.asm();
            asm.mov_store(Size::Qword, value_field(), Gpr::Rax);
            asm.mov_store(Size::Qword, address_field(), Gpr::Rdx);
            asm.mov_rm_imm32(Size::Dword, bytes_field(), i32::from(bytes));
            super::store(code, data);
        }
        Kind::Store { status, .. } => {
            let mut asm = code.asm();
            asm.alu_load(Alu::Cmp, Size::Qword, Gpr::Rdx, address_field());
            let elsewhere = asm.jcc8(Cond::Ne);
            asm.alu_imm8(Alu::Cmp, Size::Dword, bytes_field(), bytes as i8);
            let reserved = asm.jcc8(Cond::E);
            asm.bind(elsewhere);
            direct_exit(code, instruction.instruction_pc, ExitKind::System);
            let compare = code.len();
            resolve(code, reserved, compare);
            atomic::input_rcx(code, bytes, data);
            code.asm().mov_load(Size::Qword, Gpr::Rax, value_field());
            atomic::locked_compare_exchange(code, bytes, Gpr::Rcx);
            let mut asm = code.asm();
            asm.setcc(Cond::Ne, Gpr::Rax);
            asm.movzx(Size::Dword, Gpr::Rax, Size::Byte, Gpr::Rax);
            asm.mov_rm_imm32(Size::Dword, bytes_field(), 0);
            super::store(code, status);
        }
    }
    direct_exit(code, instruction.next_pc, ExitKind::Fallthrough);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, block::decode_system_mode_instruction};

    const LDXR_X0_X1: u32 = 0xc85f_7c20;
    const LDAXR_W2_X3: u32 = 0x885f_fc62;
    const LDXRB_W0_X1: u32 = 0x085f_7c20;
    const STXR_W4_X0_X1: u32 = 0xc804_7c20;
    const STLXR_W4_W0_X1: u32 = 0x8804_fc20;

    fn decode(word: u32) -> SystemInstruction {
        decode_system_mode_instruction(GuestAddress(0x4000), word)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn single_register_transfers_name_an_operand() {
        for word in [
            LDXR_X0_X1,
            LDAXR_W2_X3,
            LDXRB_W0_X1,
            STXR_W4_X0_X1,
            STLXR_W4_W0_X1,
        ] {
            assert!(operand(&decode(word)).is_some(), "{word:#x}");
        }
        for word in [
            0xc87f_0820_u32, // ldxp x0, x2, [x1]
            0xd503_305f,     // clrex
        ] {
            assert_eq!(operand(&decode(word)), None, "{word:#x}");
        }
    }

    /// The emitted code runs on the host: a load sets the monitor and a
    /// store through it passes once, fails once RAM changed, and leaves the
    /// monitor for the engine when it reaches another address or width.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn a_store_passes_by_value_through_the_frame_monitor() {
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
        const PAGE: usize = 4096;
        // The kind and target of the direct exit each ends with.
        fn run(word: u32, state: &mut GuestState) -> (u64, u64) {
            let instruction = decode(word);
            let mut code = Code::new();
            let transfer = operand(&instruction).unwrap();
            emit(
                &mut code,
                transfer,
                &instruction,
                super::super::MemoryChecks::DEFAULT,
            );
            // SAFETY: private anonymous memory, RX after the copy, unmapped
            // after the call; the code reads and writes only `state` and the
            // cell its X1 names.
            unsafe {
                let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                assert_eq!(mprotect(page, PAGE, 5), 0);
                let entry = |state: *mut crate::GuestState| -> u128 {
                    crate::x86_64::native::call::<u128>(page as *const u8, state, 0, 0)
                };
                let exit = entry(state);
                assert_eq!(munmap(page, PAGE), 0);
                (exit as u64, (exit >> 64) as u64)
            }
        }
        let next = (0x4004, ExitKind::Fallthrough as u64);
        let mut cell = [0x1122_3344_5566_7788_u64; 2];
        let mut state = GuestState::default();
        state.x[1] = cell.as_mut_ptr() as u64;
        // The monitor unset, a store is the engine's.
        state.x[0] = 1;
        assert_eq!(
            run(STXR_W4_X0_X1, &mut state),
            (0x4000, ExitKind::System as u64)
        );
        assert_eq!(cell[0], 0x1122_3344_5566_7788);
        assert_eq!(run(LDXR_X0_X1, &mut state), next);
        assert_eq!(state.x[0], 0x1122_3344_5566_7788);
        assert_eq!(state.exclusive_bytes, 8);
        state.x[0] = 2;
        state.x[4] = 9;
        assert_eq!(run(STXR_W4_X0_X1, &mut state), next);
        assert_eq!((cell[0], state.x[4], state.exclusive_bytes), (2, 0, 0));
        // Another PE's write fails it, and the monitor goes.
        run(LDXR_X0_X1, &mut state);
        cell[0] = 3;
        state.x[0] = 4;
        assert_eq!(run(STXR_W4_X0_X1, &mut state), next);
        assert_eq!((cell[0], state.x[4], state.exclusive_bytes), (3, 1, 0));
        // Another width keeps the monitor for the engine.
        run(LDXRB_W0_X1, &mut state);
        assert_eq!(state.x[0], 3);
        assert_eq!(
            run(STXR_W4_X0_X1, &mut state),
            (0x4000, ExitKind::System as u64)
        );
        assert_eq!(state.exclusive_bytes, 1);
        // A word store zero-extends its status and compares at its width.
        state.exclusive_bytes = 0;
        cell[0] = 0xdead_beef_0000_0005;
        run(0x885f_7c20, &mut state); // ldxr w0, [x1]
        assert_eq!(state.x[0], 5);
        state.x[0] = 6;
        state.x[4] = u64::MAX;
        assert_eq!(run(STLXR_W4_W0_X1, &mut state), next);
        assert_eq!((cell[0], state.x[4]), (0xdead_beef_0000_0006, 0));
    }
}
