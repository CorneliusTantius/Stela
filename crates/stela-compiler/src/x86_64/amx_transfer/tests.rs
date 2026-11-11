use super::*;
use crate::amx::model::{self, AmxMemory, MemoryFault};
use crate::amx::{AmxRegisters, Generation};
use crate::block::{BlockProfile, CompilationPlan, Features};
use crate::{Options, TargetCpu};
use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;

const PC: u64 = 0x8000;
/// ADD X0,X0,#1.
const ADD: u32 = 0x9100_0400;
const AMX: u32 = 0x0020_1000;
const OPERAND: u32 = 5;
const PAGE: usize = 4096;

fn word(operation: AmxOperation, register: u32) -> u32 {
    AMX | operation.encoding().0 << 5 | register
}

fn compile(words: &[u32], amx: bool, target: TargetCpu) -> crate::block::CompiledBlock {
    let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let options = Options::new(BlockProfile::new(Features::SYSTEM_MODE), target)
        .with_native_system(crate::x86_64::NativeSystem {
            amx,
            ..crate::x86_64::NativeSystem::NONE
        });
    CompilationPlan::new(&source, GuestAddress(PC), &options)
        .unwrap()
        .compile()
        .unwrap()
}

const MOVES: [AmxOperation; 8] = [
    AmxOperation::LoadX,
    AmxOperation::LoadY,
    AmxOperation::LoadZ,
    AmxOperation::StoreX,
    AmxOperation::StoreY,
    AmxOperation::StoreZ,
    AmxOperation::LoadZInterleaved,
    AmxOperation::StoreZInterleaved,
];

#[test]
fn blocks_with_amx_run_on_past_moves_and_register_operations() {
    for operation in MOVES {
        let words = [ADD, word(operation, OPERAND), ADD];
        let alone = compile(&words, false, TargetCpu::Baseline);
        assert_eq!(alone.source_bytes, 8, "{operation:?} ends the block");
        let inline = compile(&words, true, TargetCpu::Baseline);
        assert_eq!(inline.source_bytes, 12, "{operation:?}");
        assert_eq!(inline.native.source_map.len(), 3);
    }
    for operation in [
        AmxOperation::ExtractX,
        AmxOperation::Fma32,
        AmxOperation::VectorFloat,
        AmxOperation::GenerateLookup,
    ] {
        let words = [ADD, word(operation, OPERAND), ADD];
        assert_eq!(
            compile(&words, true, TargetCpu::Baseline).source_bytes,
            12,
            "{operation:?} calls the routine"
        );
    }
    // set and clr too.
    for set_clear in [AMX | 17 << 5, AMX | 17 << 5 | 1] {
        let words = [ADD, set_clear, ADD];
        assert_eq!(compile(&words, true, TargetCpu::Baseline).source_bytes, 8);
    }
}

/// Guest memory of the test: host addresses inside `memory`.
struct Buffer<'a> {
    memory: &'a mut [u8],
}

impl Buffer<'_> {
    fn range(&self, address: u64, bytes: usize) -> Option<core::ops::Range<usize>> {
        let start = address.checked_sub(self.memory.as_ptr() as u64)? as usize;
        (start + bytes <= self.memory.len()).then_some(start..start + bytes)
    }
}

impl AmxMemory for Buffer<'_> {
    fn read(&mut self, address: u64, destination: &mut [u8]) -> Result<(), MemoryFault> {
        let range = self.range(address, destination.len()).ok_or(MemoryFault {
            address,
            write: false,
        })?;
        destination.copy_from_slice(&self.memory[range]);
        Ok(())
    }
    fn write(&mut self, address: u64, source: &[u8]) -> Result<(), MemoryFault> {
        let range = self.range(address, source.len()).ok_or(MemoryFault {
            address,
            write: true,
        })?;
        self.memory[range].copy_from_slice(source);
        Ok(())
    }
}

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn filled(random: &mut Random) -> Box<AmxRegisters> {
    let mut registers = Box::new(AmxRegisters::zeroed());
    for row in registers
        .x
        .iter_mut()
        .chain(registers.y.iter_mut())
        .chain(registers.z.iter_mut())
    {
        for byte in row.iter_mut() {
            *byte = random.next() as u8;
        }
    }
    registers
}

/// Whether the code leaves `operand` of `operation` to the service.
fn exits(operation: AmxOperation, operand: u64) -> bool {
    let address = model::effective_address(operand);
    if matches!(
        operation,
        AmxOperation::LoadZInterleaved | AmxOperation::StoreZInterleaved
    ) {
        return address & 0xfff > 0xfc0;
    }
    let (_, rows, load) = file(operation);
    let pair = operand & 1 << 62 != 0;
    (load && rows == 8 && pair && operand & (3 << 60) != 0)
        || (pair && !address.is_multiple_of(128))
        || (!pair && address & 0xfff > 0xfc0)
}

/// The host tiers to check: each one this host runs, the others reported.
fn tiers() -> Vec<(Width, TargetCpu)> {
    let host = TargetCpu::detect();
    [
        (Width::Xmm, TargetCpu::Baseline),
        (Width::Ymm, TargetCpu::Avx2),
        (Width::Zmm, TargetCpu::Avx512f),
    ]
    .into_iter()
    .filter(|(width, target)| {
        assert_eq!(Width::of(*target), *width);
        let runs = host.supports(*target);
        if !runs {
            std::eprintln!("amx_transfer: {width:?} tier not run: the host lacks {target:?}");
        }
        runs
    })
    .collect()
}

/// Every move, form and row on every tier this host runs: the block either
/// completes the word as the model does under every generation, or leaves
/// at it for the service with nothing changed, exactly for the forms it
/// does not lower.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn moves_match_the_model_bit_for_bit_on_every_tier() {
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut backing = alloc::vec![0u8; 5 * PAGE];
    let start = (backing.as_ptr() as usize).next_multiple_of(PAGE) - backing.as_ptr() as usize;
    let mut copy = alloc::vec![0u8; 5 * PAGE];
    let copy_start = (copy.as_ptr() as usize).next_multiple_of(PAGE) - copy.as_ptr() as usize;
    let mut covered = [0usize; 2];
    for (width, target) in tiers() {
        for operation in MOVES {
            let code = compile(&[ADD, word(operation, OPERAND), ADD], true, target)
                .native
                .x86_64_code;
            for case in 0..600 {
                let memory = &mut backing[start..start + 4 * PAGE];
                for byte in memory.iter_mut() {
                    *byte = random.next() as u8;
                }
                // Inside pages 1 and 2: aligned pairs, rows, misaligned rows
                // and rows across the page between them.
                let offset = PAGE as u64
                    + match case % 4 {
                        0 => (random.next() % 31) * 128,
                        1 => (random.next() % 63) * 64,
                        2 => random.next() % (PAGE as u64 - 64),
                        _ => PAGE as u64 - 1 - random.next() % 63,
                    };
                let address = memory.as_ptr() as u64 + offset;
                let operand = (random.next() & 0xff00_0000_0000_0000) | address;
                let registers = filled(&mut random);
                let before = memory.to_vec();
                let mut native = registers.clone();
                let mut state = crate::GuestState::default();
                state.x[OPERAND as usize] = operand;
                let mut cell = Cell {
                    registers: &mut *native as *mut AmxRegisters as u64,
                    ..Cell::default()
                };
                state.anchors[Anchor::Amx] = &mut cell as *mut Cell as u64;
                let exit = run(&code, &mut state);
                let context = format!("{width:?} {operation:?} operand {operand:#x}");
                if exits(operation, operand) {
                    assert_eq!(exit, (PC + 4, ExitKind::Amx as u64), "{context}");
                    assert_eq!(state.x[0], 1, "{context}");
                    assert!(native == registers, "{context}: the file is unchanged");
                    assert!(*memory == before[..], "{context}: memory is unchanged");
                    assert_eq!(cell.moves, 0, "{context}: the service's move");
                    covered[1] += 1;
                    continue;
                }
                assert_eq!(exit, (PC + 12, ExitKind::Fallthrough as u64), "{context}");
                assert_eq!((state.x[0], state.x[OPERAND as usize]), (2, operand));
                assert_eq!(cell.moves, 1, "{context}: counted");
                let produced = memory.to_vec();
                for generation in [
                    Generation::M1,
                    Generation::M2,
                    Generation::M3,
                    Generation::M4,
                ] {
                    let mut expected = registers.clone();
                    // The model addresses the same bytes of a copy at the
                    // same page offsets.
                    let reference = &mut copy[copy_start..copy_start + 4 * PAGE];
                    reference.copy_from_slice(&before);
                    let copied = reference.as_ptr() as u64 + offset;
                    model::execute_for(
                        generation,
                        &mut expected,
                        operation,
                        operand & 0xff00_0000_0000_0000 | copied,
                        &mut Buffer {
                            memory: &mut *reference,
                        },
                    )
                    .unwrap_or_else(|error| panic!("{context} {generation:?}: {error:?}"));
                    assert!(native == expected, "{context} {generation:?}: registers");
                    assert!(
                        produced[..] == *reference,
                        "{context} {generation:?}: memory"
                    );
                }
                covered[0] += 1;
            }
        }
    }
    assert!(covered[0] > 2000 && covered[1] > 500, "{covered:?}");
}

/// A zero anchor (AMX disabled or trapped, no live state) leaves at the
/// word for every move, the operand XZR's included.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn a_zero_anchor_leaves_every_move_to_the_service() {
    for (_, target) in tiers() {
        for operation in MOVES {
            for register in [OPERAND, 31] {
                let code = compile(&[ADD, word(operation, register), ADD], true, target)
                    .native
                    .x86_64_code;
                let mut cell = Cell::default();
                let mut state = crate::GuestState::default();
                state.anchors[Anchor::Amx] = &mut cell as *mut Cell as u64;
                state.x[OPERAND as usize] = 0x40;
                let exit = run(&code, &mut state);
                assert_eq!(exit, (PC + 4, ExitKind::Amx as u64), "{operation:?}");
                assert_eq!((state.x[0], cell.moves), (1, 0));
            }
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
    // the call; the block touches only `state`, the register file its
    // anchor names and the test's memory.
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

/// The cost of a block of eight moves (ldx, ldy pairs, ldz, stz) per tier:
/// `cargo test -p stela-compiler --lib amx_transfer_costs -- --ignored
/// --nocapture`.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
#[ignore = "manual: opt-in"]
fn amx_transfer_costs() {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(a: *mut c_void, b: usize, p: i32, f: i32, fd: i32, o: i64) -> *mut c_void;
        fn mprotect(a: *mut c_void, b: usize, p: i32) -> i32;
        fn munmap(a: *mut c_void, b: usize) -> i32;
    }
    const BYTES: usize = 1 << 16;
    const RUNS: u32 = 1_000_000;
    let pair = 1u64 << 62;
    let words = [
        word(AmxOperation::LoadX, 1),
        word(AmxOperation::LoadY, 2),
        word(AmxOperation::LoadZ, 3),
        word(AmxOperation::LoadZ, 4),
        word(AmxOperation::StoreZ, 3),
        word(AmxOperation::StoreZ, 4),
        word(AmxOperation::LoadX, 5),
        word(AmxOperation::LoadY, 6),
    ];
    let mut memory = alloc::vec![0u8; 2 * PAGE];
    let base = (memory.as_mut_ptr() as u64).next_multiple_of(128);
    let mut registers = Box::new(AmxRegisters::zeroed());
    for (width, target) in tiers() {
        let code = compile(&words, true, target).native.x86_64_code;
        let bytes = crate::x86_64::pinned::entered(&code);
        let mut state = crate::GuestState::default();
        let mut cell = Cell {
            registers: &mut *registers as *mut AmxRegisters as u64,
            ..Cell::default()
        };
        state.anchors[Anchor::Amx] = &mut cell as *mut Cell as u64;
        state.x[1] = pair | base;
        state.x[2] = pair | 2 << 56 | (base + 128);
        state.x[3] = 5 << 56 | (base + 256);
        state.x[4] = pair | 40 << 56 | (base + 384);
        state.x[5] = 7 << 56 | (base + 512);
        state.x[6] = pair | 3 << 56 | (base + 640);
        // SAFETY: as `run`, mapped once for every call.
        unsafe {
            let page = mmap(core::ptr::null_mut(), BYTES, 3, 0x22, -1, 0);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), page.cast(), bytes.len());
            assert_eq!(mprotect(page, BYTES, 5), 0);
            let entry = |state: *mut crate::GuestState| -> u128 {
                crate::x86_64::native::call::<u128>(page as *const u8, state, 0, 0)
            };
            assert_eq!(entry(&mut state) as u64, PC + 32);
            let started = std::time::Instant::now();
            for _ in 0..RUNS {
                entry(&mut state);
            }
            let each = started.elapsed().as_nanos() as f64 / f64::from(RUNS);
            std::println!("{width:?}: {each:.1} ns per block of 8 moves (with entry and exit)");
            assert_eq!(munmap(page, BYTES), 0);
        }
    }
    let _ = &mut memory;
}
