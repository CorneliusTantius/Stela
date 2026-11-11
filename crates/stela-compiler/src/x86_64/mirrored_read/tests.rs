use super::*;
use crate::block::{BlockProfile, CompilationPlan, Features};
use crate::x86_64::register_read::Cell;
use crate::{Options, TargetCpu};
use alloc::vec::Vec;

// ADD X0,X0,#1; MRS X2,TPIDR_EL1; MRS X8,TPIDR_EL1; ADD X3,X8,#1;
// MRS XZR,TPIDR_EL1; ADD X4,X4,#1
const WORDS: [u32; 6] = [
    0x9100_0400,
    0xd538_d082,
    0xd538_d088,
    0x9100_0503,
    0xd538_d09f,
    0x9100_0484,
];
const PC: u64 = 0x8000;
/// MRS X0,TPIDR_EL1, the register's word with Rt 0.
const TPIDR_EL1: u32 = 0xd538_d080;
/// MRS X0,TPIDR_EL0, which no cell answers.
const TPIDR_EL0: u32 = 0xd53b_d040;

/// The thread pointer's cell is the second.
fn reads() -> Reads {
    Reads {
        reads: [
            Some(Read {
                word: TPIDR_EL1,
                cell: size_of::<Cell>() as u32,
            }),
            None,
            None,
            None,
        ],
    }
}

fn compile(words: &[u32], mirrored: Reads) -> crate::block::CompiledBlock {
    let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let options = Options::new(
        BlockProfile::new(Features::SYSTEM_MODE),
        TargetCpu::Baseline,
    )
    .with_native_system(crate::x86_64::NativeSystem {
        mirrored,
        ..crate::x86_64::NativeSystem::NONE
    });
    CompilationPlan::new(&source, GuestAddress(PC), &options)
        .unwrap()
        .compile()
        .unwrap()
}

#[test]
fn cells_match_the_register_whatever_rt_and_never_a_write() {
    let reads = reads();
    for rt in [0, 2, 8, 30, 31] {
        assert_eq!(reads.cell(TPIDR_EL1 | rt), Some(16));
    }
    assert_eq!(reads.cell(TPIDR_EL0), None);
    // MSR TPIDR_EL1,X2 is not admitted by the parser (L clear); the table
    // matches by register, so the parser checks the direction.
    assert_eq!(Reads::NONE.cell(TPIDR_EL1), None);
    assert_eq!(destination(TPIDR_EL1 | 31), Register::Zero);
    assert_eq!(destination(TPIDR_EL1 | 8), Register::X(8));
}

#[test]
fn blocks_given_the_cells_run_on_past_the_reads() {
    let alone = compile(&WORDS, Reads::NONE);
    assert_eq!(alone.source_bytes, 8, "the first MRS ends the block");
    let inline = compile(&WORDS, reads());
    assert_eq!(inline.source_bytes, 4 * WORDS.len());
    assert_eq!(inline.native.source_map.len(), WORDS.len());
    // Another register's MRS, and MSR of this one, still end the block.
    let other = compile(&[0x9100_0400, TPIDR_EL0 | 2, 0x9100_0400], reads());
    assert_eq!(other.source_bytes, 8);
    let write = compile(&[0x9100_0400, 0xd518_d082, 0x9100_0400], reads());
    assert_eq!(write.source_bytes, 8);
}

/// Each read takes the cell's value while it is readable and leaves at
/// the MRS, with the instructions before it done and none after, while it
/// is not, an MRS of XZR included.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn reads_complete_from_an_open_cell_and_exit_at_a_closed_one() {
    let code = compile(&WORDS, reads()).native.x86_64_code;
    let mut cells = [Cell::default(); 2];
    let start = |cells: &[Cell; 2]| {
        let mut state = crate::GuestState::default();
        state.anchors[Anchor::Cells] = cells.as_ptr() as u64;
        for register in 0..9 {
            state.x[register] = 0x100 * register as u64;
        }
        state
    };
    cells[1] = Cell {
        readable: 1,
        value: 0xffff_fe10_2030_4050,
    };
    cells[0] = Cell {
        readable: 0,
        value: 0x5555,
    };
    let mut state = start(&cells);
    let exit = run(&code, &mut state);
    assert_eq!(
        exit,
        (PC + 4 * WORDS.len() as u64, ExitKind::Fallthrough as u64)
    );
    assert_eq!(
        (state.x[0], state.x[2], state.x[8], state.x[3], state.x[4]),
        (
            1,
            0xffff_fe10_2030_4050,
            0xffff_fe10_2030_4050,
            0xffff_fe10_2030_4051,
            0x401
        )
    );
    cells[1].readable = 0;
    let mut state = start(&cells);
    let exit = run(&code, &mut state);
    assert_eq!(exit, (PC + 4, ExitKind::System as u64));
    assert_eq!((state.x[0], state.x[2], state.x[3]), (1, 0x200, 0x300));
    // MRS XZR reads nothing, but a closed cell (UNDEFINED, trapped) still
    // leaves for the engine.
    let code = compile(&[0x9100_0400, 0xd538_d09f, 0x9100_0400], reads())
        .native
        .x86_64_code;
    let mut state = start(&cells);
    assert_eq!(run(&code, &mut state), (PC + 4, ExitKind::System as u64));
    assert_eq!(state.x[0], 1);
    cells[1].readable = 1;
    let mut state = start(&cells);
    assert_eq!(
        run(&code, &mut state),
        (PC + 12, ExitKind::Fallthrough as u64)
    );
    assert_eq!(state.x[0], 2);
}

/// A conditional branch ending a block with a mirrored read still takes its
/// condition from the host flags its compare left, though the read's exit
/// path lies between them, and branches as the guest flags say.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn a_terminal_branch_reads_the_flags_its_compare_left() {
    // MRS X8,TPIDR_EL1; CMP X8,#5; B.<cond> +0x40
    const NZCV: usize = core::mem::offset_of!(crate::GuestState, nzcv);
    for (condition, cases) in [
        (8u32, [(4u64, false), (5, false), (6, true)]), // HI
        (9, [(4, true), (5, true), (6, false)]),        // LS
        (0, [(4, false), (5, true), (6, false)]),       // EQ
        (11, [(4, true), (5, false), (6, false)]),      // LT
    ] {
        let words = [0xd538_d088, 0xf100_151f, 0x5400_0200 | condition];
        let code = compile(&words, reads()).native.x86_64_code;
        // No reload of the captured flags from the frame: TEST m8,imm8 at
        // [rdi+nzcv+1] (F6 87 disp32) or MOV EAX,[rdi+nzcv] would show it.
        // MOVZX EAX,WORD [rdi+nzcv] (0F B7 87 disp32) the compound ones.
        let reload = [0xf6, 0x87, (NZCV + 1) as u8, (NZCV >> 8) as u8];
        let restore = [0x0f, 0xb7, 0x87, NZCV as u8, (NZCV >> 8) as u8];
        assert!(
            !code.windows(4).any(|w| w == reload),
            "condition {condition}"
        );
        assert!(
            !code.windows(5).any(|w| w == restore),
            "condition {condition}"
        );
        for (value, taken) in cases {
            let cells = [Cell::default(), Cell { readable: 1, value }];
            let mut state = crate::GuestState::default();
            state.anchors[Anchor::Cells] = cells.as_ptr() as u64;
            let (pc, _) = run(&code, &mut state);
            let expected = if taken { PC + 8 + 0x40 } else { PC + 12 };
            assert_eq!(pc, expected, "condition {condition} value {value}");
            assert_eq!(state.x[8], value);
        }
    }
}

/// Run `code` through `pinned::entered`: the exit's PC and kind.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
fn run(code: &[u8], state: &mut crate::GuestState) -> (u64, u64) {
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
    const BYTES: usize = 1 << 16;
    let bytes = crate::x86_64::pinned::entered(code);
    // SAFETY: private anonymous memory, RX after the copy, unmapped after
    // the call; the block touches only `state` and the cells it points at.
    unsafe {
        let page = mmap(core::ptr::null_mut(), BYTES, 3, 2 | MAP_ANONYMOUS, -1, 0);
        assert_ne!(page as usize, usize::MAX);
        assert!(bytes.len() <= BYTES);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), page.cast(), bytes.len());
        assert_eq!(mprotect(page, BYTES, 5), 0);
        let entry = |state: *mut crate::GuestState| -> u128 {
            crate::x86_64::native::call::<u128>(page as *const u8, state, 0, 0)
        };
        let exit = entry(state);
        assert_eq!(munmap(page, BYTES), 0);
        (exit as u64, (exit >> 64) as u64)
    }
}
