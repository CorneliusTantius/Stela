//! PAC instructions completed inside the system-mode block that runs them.
//!
//! Given where the engine's PAC service keeps its tag words, strip cells and
//! routine ([`Cells`], at [`Anchor::Pointer`]), a block runs on past a
//! signing, an authentication, PACGA or XPAC that writes a register
//! ([`inlines`]): it completes the instruction as the engine's thunk would
//! (`x86_64::pointer`), from the memo, through the service on a miss, or
//! from the strip cell. What the thunk would leave through the original
//! exit, a key or cell that is not open or an authentication the service
//! does not complete, leaves the block at the instruction with a PAC exit
//! that retires the instructions before it, as a numerical FP exit does.
//! Those paths lie out of line ([`place`]), before the terminal, as a
//! block's direct exits end its code. The service call clobbers what a SysV
//! call may but RSI and RDI, which it saves; between instructions a block
//! keeps nothing else live but the pinned registers, which the call
//! preserves. The branch forms (BRA*, BLRA* and RETA*) still end their
//! block, whose thunk completes them.
use super::{Finish, Form, Lookup, Routine, call_service, lookup, rare};
use crate::x86_64::asm::{Code, Gpr, Patch, Size, resolve};
use crate::{
    Anchor, GuestAddress, Place,
    aarch64::Register,
    block::{ExitKind, PointerAuthenticationOperation as Operation},
};
use alloc::{vec, vec::Vec};

/// Where the engine's PAC service keeps what blocks read, as offsets from
/// [`Anchor::Pointer`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Cells {
    /// The tag words ([`super::TAG_WORDS`] of them).
    pub tags: u32,
    /// The strip cells ([`super::strip::Cell`]), instruction then data.
    pub strips: u32,
    /// The word holding the address of the [`super::ServiceRoutine`].
    pub routine: u32,
}

/// Whether a block completes `operation` inside itself.
pub fn inlines(operation: Operation) -> bool {
    match operation {
        Operation::Strip { .. } => true,
        operation => Form::of(operation).is_some_and(|form| form.completion == Finish::Register),
    }
}

/// What [`emit`] leaves to [`place`] out of line.
pub(crate) struct Slow {
    pc: GuestAddress,
    /// The service call of a memo miss, which returns to the completion,
    /// and the lookup's rare path.
    service: Option<(Form, Vec<Patch>, usize, Patch)>,
    /// The jumps to the exit at the instruction.
    exits: Vec<Patch>,
}

/// The inline completion of `operation` at `pc`, which [`inlines`] admits.
pub(crate) fn emit(code: &mut Code, operation: Operation, pc: GuestAddress, cells: Cells) -> Slow {
    let mut asm = code.asm();
    if let Operation::Strip { data, destination } = operation {
        let mut exits = Vec::new();
        if destination == 31 {
            // XZR has no effect and depends on no regime state.
            asm.nop();
        } else {
            let cell = Place::new(
                Anchor::Pointer,
                cells.strips as usize + usize::from(data) * size_of::<super::strip::Cell>(),
            );
            exits.push(super::strip::strip(&mut asm, destination, cell));
        }
        return Slow {
            pc,
            service: None,
            exits,
        };
    }
    let form = Form::of(operation)
        .filter(|form| form.completion == Finish::Register)
        .expect("a form that completes into its register");
    let Lookup {
        rare: unusual,
        misses,
    } = lookup(
        &mut asm,
        form,
        Place::new(Anchor::Pointer, cells.tags as usize),
    );
    let complete = asm.len();
    let result = asm.guest(Register::X(form.result)).expect("X0..X30");
    asm.mov_store(Size::Qword, result, Gpr::Rax);
    Slow {
        pc,
        service: Some((form, misses, complete, unusual)),
        exits: vec![],
    }
}

/// `slow`'s paths: the service call, back to the completion, and the exit.
pub(crate) fn place(code: &mut Code, slow: Slow, cells: Cells) {
    let mut asm = code.asm();
    let mut exits = slow.exits;
    let mut back = vec![];
    if let Some((form, misses, complete, unusual)) = slow.service {
        for miss in misses {
            asm.bind(miss);
        }
        exits.push(call_service(&mut asm, form, Routine::Cell(cells.routine)));
        back.push((asm.jmp(), complete));
        let (closed, identity) = rare(&mut asm, unusual);
        exits.push(closed);
        back.push((identity, complete));
    }
    for exit in exits {
        asm.bind(exit);
    }
    super::super::block::direct_exit_with(&mut asm, slow.pc, ExitKind::PointerAuthentication);
    for (patch, complete) in back {
        resolve(code, patch, complete);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockProfile, CompilationPlan, Features};
    use crate::x86_64::pointer::{
        Completion, DISABLED, MEMO_ENTRIES, MemoEntry, REQUEST_AUTHENTICATE, SIGNED,
        ServiceRoutine, TAG_WORDS, key_index, slot, strip, tag,
    };
    use crate::{Options, TargetCpu, block::PointerAuthenticationKey as Key};

    // PACIBSP; ADD X0,X0,#1; AUTDA X1,X2; ADD X3,X3,#1; XPACD X4;
    // PACDZB X5; ADD X6,X6,#1
    const WORDS: [u32; 7] = [
        0xd503_237f,
        0x9100_0400,
        0xdac1_1841,
        0x9100_0463,
        0xdac1_47e4,
        0xdac1_2fe5,
        0x9100_04c6,
    ];
    const PC: u64 = 0x4000;

    /// The service's cells as a block reads them.
    #[repr(C)]
    struct Service {
        tags: [u64; TAG_WORDS],
        strips: [strip::Cell; 2],
        routine: u64,
    }

    const CELLS: Cells = Cells {
        tags: core::mem::offset_of!(Service, tags) as u32,
        strips: core::mem::offset_of!(Service, strips) as u32,
        routine: core::mem::offset_of!(Service, routine) as u32,
    };

    fn compile(words: &[u32], cells: Option<Cells>) -> crate::block::CompiledBlock {
        let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let options = Options::new(
            BlockProfile::new(Features::SYSTEM_MODE),
            TargetCpu::Baseline,
        )
        .with_native_system(crate::x86_64::NativeSystem {
            pointer: cells,
            ..crate::x86_64::NativeSystem::NONE
        });
        CompilationPlan::new(&source, GuestAddress(PC), &options)
            .unwrap()
            .compile()
            .unwrap()
    }

    #[test]
    fn blocks_given_the_cells_run_on_past_register_forms_only() {
        // ... BLRAA X8,X16 ends the block either way.
        let mut words = WORDS.to_vec();
        words.push(0xd73f_0910);
        assert_eq!(compile(&words, None).source_bytes, 4);
        let inline = compile(&words, Some(CELLS));
        assert_eq!(inline.source_bytes, 4 * words.len());
        assert_eq!(inline.native.source_map.len(), words.len());
        assert!(inlines(Operation::SignIbSp));
        assert!(inlines(Operation::Strip {
            data: false,
            destination: 31
        }));
        assert!(!inlines(Operation::ReturnIbSp));
        assert!(!inlines(Operation::Branch {
            key: Key::Ia,
            target: 8,
            modifier: crate::block::PointerAuthenticationModifier::Register(16),
            link: true,
        }));
    }

    /// The block completes a memo hit, a service completion and a strip,
    /// then leaves at the PAC instruction whose key is not open with the
    /// instructions before it done and none after it.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn blocks_complete_pac_instructions_and_exit_at_a_closed_key() {
        use crate::GuestState;
        use core::ffi::c_void;
        use core::sync::atomic::{AtomicU64, Ordering::SeqCst};
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
        const BYTES: usize = 1 << 16;
        #[repr(C)]
        #[derive(Debug, PartialEq, Eq)]
        struct Exit {
            pc: u64,
            kind: u64,
        }
        static CALLS: AtomicU64 = AtomicU64::new(0);
        static ARGUMENTS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
        extern "sysv64" fn service(
            state: u64,
            request: u32,
            pointer: u64,
            modifier: u64,
        ) -> Completion {
            CALLS.fetch_add(1, SeqCst);
            for (argument, value) in
                ARGUMENTS
                    .iter()
                    .zip([state, u64::from(request), pointer, modifier])
            {
                argument.store(value, SeqCst);
            }
            Completion {
                completed: 1,
                value: 0x2222,
            }
        }
        let code = compile(&WORDS, Some(CELLS)).native.x86_64_code;
        let bytes = crate::x86_64::pinned::entered(&code);
        let routine: ServiceRoutine = service;
        let mut service = Service {
            tags: [0; TAG_WORDS],
            strips: [strip::Cell::default(); 2],
            routine: routine as usize as u64,
        };
        let (ib, da) = (key_index(Key::Ib), key_index(Key::Da));
        service.tags[usize::from(ib)] = tag(1, ib, 0);
        service.tags[usize::from(da)] = tag(1, da, 0);
        assert_ne!(service.tags[usize::from(key_index(Key::Db))], DISABLED);
        service.strips[1] = strip::Cell {
            enabled: 1,
            keep: [0x0000_007f_ffff_ffff, 0xff00_007f_ffff_ffff],
            upper_extension: 0x00ff_ff80_0000_0000,
        };
        let mut memo = alloc::vec![MemoEntry::default(); MEMO_ENTRIES];
        let (pointer, stack) = (0xffff_fe00_1234_5678u64, 0xffff_fe00_0000_8000u64);
        memo[slot(pointer, stack)] = MemoEntry {
            pointer,
            modifier: stack,
            tag: tag(1, ib, SIGNED),
            value: 0x1111,
        };
        let mut state = GuestState::default();
        state.anchors[Anchor::Memo] = memo.as_ptr() as u64;
        state.anchors[Anchor::Pointer] = &raw const service as u64;
        state.sp = stack;
        state.x[30] = pointer;
        for register in [0, 1, 2, 3, 5, 6] {
            state.x[register] = 0x100 * register as u64;
        }
        state.x[4] = 0x0023_1234_5678_9abc;
        // SAFETY: private anonymous memory, RX after the copy, unmapped
        // after the call; the block touches only `state`, the memo, the
        // service's cells and the stack, and calls `service`.
        let exit = unsafe {
            let page = mmap(core::ptr::null_mut(), BYTES, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            assert!(bytes.len() <= BYTES);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), page.cast(), bytes.len());
            assert_eq!(mprotect(page, BYTES, 5), 0);
            let entry = |state: *mut crate::GuestState| -> Exit {
                crate::x86_64::native::call::<Exit>(page as *const u8, state, 0, 0)
            };
            let exit = entry(&mut state);
            assert_eq!(munmap(page, BYTES), 0);
            exit
        };
        assert_eq!(
            exit,
            Exit {
                pc: PC + 20,
                kind: ExitKind::PointerAuthentication as u64
            }
        );
        assert_eq!(
            (state.x[30], state.x[0], state.x[1], state.x[3]),
            (0x1111, 1, 0x2222, 0x301)
        );
        assert_eq!(state.x[4], 0x0000_0034_5678_9abc);
        assert_eq!((state.x[5], state.x[6]), (0x500, 0x600));
        assert_eq!(CALLS.load(SeqCst), 1);
        assert_eq!(
            ARGUMENTS.each_ref().map(|argument| argument.load(SeqCst)),
            [
                &raw const service as u64,
                u64::from(u32::from(da) | REQUEST_AUTHENTICATE),
                0x100,
                0x200
            ]
        );
        assert_eq!(state.sp, stack);
    }
}
