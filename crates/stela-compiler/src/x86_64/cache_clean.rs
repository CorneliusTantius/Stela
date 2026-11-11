//! DC CVAC, DC CVAU and DC CIVAC in system-mode blocks the engine compiles
//! where they neither trap nor are UNDEFINED
//! (`Options::with_native_system`). The host is cache-coherent, so
//! all the engine does for them is translate Xt as a read, taking the Data
//! Abort of a failed translation (`engine::system` `check_maintenance`).
//! Native code makes the same check by reading the byte at Xt through the
//! same direct guest-VA access as LDRB, after the guest range check, then
//! falls through. A read that fails for any reason (a guest fault, Device
//! memory, a watched page, an address outside the guest's ranges) ends the
//! block at the DC with nothing
//! written, and the engine then completes the instruction itself, with the
//! syndrome of a cache maintenance fault. Code clobbers RAX and ECX.
use crate::aarch64::{
    Register,
    system::registers::{Direction, Encoding},
};
use crate::block::{SystemInstruction, system::SystemOperation};
use crate::x86_64::asm::{Code, Gpr, Mem, Size};

/// SYS #3, C7, Cm, #1 of each operation.
const DC_CVAC: Encoding = Encoding::new(1, 3, 7, 10, 1);
const DC_CVAU: Encoding = Encoding::new(1, 3, 7, 11, 1);
const DC_CIVAC: Encoding = Encoding::new(1, 3, 7, 14, 1);

/// A set of the DC clean operations a context completes natively.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Operations(u8);

impl Operations {
    pub const NONE: Self = Self(0);
    pub const CVAC: Self = Self(1);
    pub const CVAU: Self = Self(2);
    pub const CIVAC: Self = Self(4);
    pub const ALL: Self = Self(7);

    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// The operation and Xt of a DC CVAC, DC CVAU or DC CIVAC, or `None` for
/// any other System instruction.
pub fn operand(instruction: &SystemInstruction) -> Option<(Operations, u8)> {
    // SYSL with a DC operation's encoding is not that operation.
    let SystemOperation::Maintenance(access) = instruction.operation else {
        return None;
    };
    if access.direction() != Direction::Write {
        return None;
    }
    let operation = match access.encoding() {
        DC_CVAC => Operations::CVAC,
        DC_CVAU => Operations::CVAU,
        DC_CIVAC => Operations::CIVAC,
        _ => return None,
    };
    Some((operation, access.rt()))
}

/// Read the byte at Xt, so the access faults where its translation would.
pub(crate) fn emit(code: &mut Code, rt: u8, checks: super::MemoryChecks) {
    super::load(
        code,
        if rt == 31 {
            Register::Zero
        } else {
            Register::X(rt)
        },
    );
    super::range_check(code, checks, super::Access::read(1));
    code.asm()
        .guest_access(|asm| asm.movzx(Size::Dword, Gpr::Rcx, Size::Byte, Mem::base(Gpr::Rax, 0)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, block::decode_system_mode_instruction};

    #[test]
    fn only_the_clean_operations_name_an_operand() {
        let decode = |word| decode_system_mode_instruction(GuestAddress(0x4000), word).unwrap();
        assert_eq!(
            operand(&decode(0xd50b_7a20).unwrap()),
            Some((Operations::CVAC, 0))
        );
        assert_eq!(
            operand(&decode(0xd50b_7b25).unwrap()),
            Some((Operations::CVAU, 5))
        );
        assert_eq!(
            operand(&decode(0xd50b_7e3f).unwrap()),
            Some((Operations::CIVAC, 31))
        );
        for word in [
            0xd508_7620_u32, // dc ivac, x0: invalidation needs a write check
            0xd50b_7423,     // dc zva, x3
            0xd50b_7c20,     // dc cvap, x0
            0xd50b_7520,     // ic ivau, x0
            0xd508_7e40,     // dc cisw, x0
            0xd52b_7e20,     // sysl x0, #3, c7, c14, #1
        ] {
            assert_eq!(operand(&decode(word).unwrap()), None, "{word:#x}");
        }
        let all = Operations::CVAC
            .with(Operations::CVAU)
            .with(Operations::CIVAC);
        assert_eq!(all, Operations::ALL);
        assert!(all.contains(Operations::CVAU) && !Operations::CVAC.contains(all));
        assert!(Operations::NONE.is_empty());
    }

    /// The emitted code runs on the host and reads exactly the byte at Xt.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn reads_the_byte_at_xt() {
        use crate::GuestState;
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
        let memory = [0x5au8, 0xc3];
        let mut state = GuestState::default();
        state.x[7] = memory.as_ptr() as u64 + 1;
        let mut code = Code::new();
        emit(&mut code, 7, super::super::MemoryChecks::DEFAULT);
        let mut asm = code.asm();
        asm.mov(Size::Dword, Gpr::Rax, Gpr::Rcx);
        asm.ret();
        // SAFETY: private anonymous memory, RX after the copy, unmapped
        // after the call; the code reads one byte of `memory`.
        let read = unsafe {
            let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
            assert_eq!(mprotect(page, PAGE, 5), 0);
            let entry = |state: *mut crate::GuestState| -> u32 {
                crate::x86_64::native::call::<u32>(page as *const u8, state, 0, 0)
            };
            let read = entry(&mut state);
            assert_eq!(munmap(page, PAGE), 0);
            read
        };
        assert_eq!(read, 0xc3);
        assert_eq!(state.x[7], memory.as_ptr() as u64 + 1);
    }
}
