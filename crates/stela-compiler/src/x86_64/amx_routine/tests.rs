use super::*;
use crate::amx::Generation;
use crate::amx::native::Native;
use crate::block::ExitKind;
use crate::block::{BlockProfile, CompilationPlan, Features};
use crate::{GuestAddress, Options, TargetCpu};
use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;

const PC: u64 = 0x8000;
/// ADD X0,X0,#1.
const ADD: u32 = 0x9100_0400;
const AMX: u32 = 0x0020_1000;
const OPERAND: u32 = 7;

fn word(operation: AmxOperation) -> u32 {
    AMX | operation.encoding().0 << 5 | OPERAND
}

fn compile(words: &[u32]) -> Vec<u8> {
    let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let options = Options::new(
        BlockProfile::new(Features::SYSTEM_MODE),
        TargetCpu::Baseline,
    )
    .with_native_system(crate::x86_64::NativeSystem {
        amx: true,
        ..crate::x86_64::NativeSystem::NONE
    });
    CompilationPlan::new(&source, GuestAddress(PC), &options)
        .unwrap()
        .compile()
        .unwrap()
        .native
        .x86_64_code
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
        for chunk in row.as_chunks_mut::<4>().0 {
            // Finite floats of every class, NaNs and integers alike.
            *chunk = (random.next() as u32).to_le_bytes();
        }
    }
    registers
}

const OPERATIONS: [AmxOperation; 14] = [
    AmxOperation::ExtractX,
    AmxOperation::ExtractY,
    AmxOperation::Fma64,
    AmxOperation::Fms64,
    AmxOperation::Fma32,
    AmxOperation::Fms32,
    AmxOperation::Fma16,
    AmxOperation::Fms16,
    AmxOperation::Mac16,
    AmxOperation::VectorFloat,
    AmxOperation::MatrixFloat,
    AmxOperation::VectorInteger,
    AmxOperation::MatrixInteger,
    AmxOperation::GenerateLookup,
];

/// Every register operation a block calls the routine for leaves the
/// registers the model gives, on the model and on this host's paths, for
/// every generation, and the block runs on past it.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn register_operations_complete_in_block_as_the_model_does() {
    let mut random = Random(0x2545_f491_4f6c_dd1d);
    for operation in OPERATIONS {
        assert!(calls(operation), "{operation:?}");
        let code = compile(&[ADD, word(operation), ADD]);
        for native in [Native::MODEL, Native::select(TargetCpu::detect())] {
            for generation in [
                Generation::M1,
                Generation::M2,
                Generation::M3,
                Generation::M4,
            ] {
                for _ in 0..40 {
                    let operand = random.next();
                    let before = filled(&mut random);
                    let mut file = before.clone();
                    let mut cell = Cell {
                        registers: &mut *file as *mut AmxRegisters as u64,
                        routine: routine as *const () as usize as u64,
                        generation: Some(generation),
                        native,
                        ..Cell::default()
                    };
                    let mut state = crate::GuestState::default();
                    state.x[OPERAND as usize] = operand;
                    state.x[8] = 0x8888;
                    state.anchors[crate::Anchor::Amx] = &mut cell as *mut Cell as u64;
                    let exit = run(&code, &mut state);
                    let context = format!("{operation:?} {generation:?} {operand:#x}");
                    assert_eq!(exit, (PC + 12, ExitKind::Fallthrough as u64), "{context}");
                    assert_eq!((state.x[0], state.x[8], cell.calls), (2, 0x8888, 1));
                    let number = operation.encoding().0 as usize;
                    let counts = cell.kernels[number];
                    assert_eq!(counts[0] + counts[1], 1, "{context}");
                    if native == Native::MODEL && operation == AmxOperation::VectorFloat {
                        assert_eq!(counts, [0, 1], "{context}: the model's");
                    }
                    // The first call of each operation is sampled.
                    assert_eq!(cell.sampled[number][0][1] + cell.sampled[number][1][1], 1);
                    let mut expected = before.clone();
                    model::execute_for(
                        generation,
                        &mut expected,
                        operation,
                        operand,
                        &mut NoMemory,
                    )
                    .unwrap();
                    assert!(file == expected, "{context}");
                }
            }
        }
    }
}

/// Without a live file or a generation the block leaves at the word with
/// nothing changed, for the service.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn without_a_file_or_generation_the_service_completes_the_word() {
    let code = compile(&[ADD, word(AmxOperation::Fma32), ADD]);
    let mut random = Random(7);
    let before = filled(&mut random);
    let mut file = before.clone();
    for (registers, generation) in [
        (0, Some(Generation::M2)),
        (&mut *file as *mut AmxRegisters as u64, None),
    ] {
        let mut cell = Cell {
            registers,
            routine: routine as *const () as usize as u64,
            generation,
            ..Cell::default()
        };
        let mut state = crate::GuestState::default();
        state.x[OPERAND as usize] = random.next();
        state.anchors[crate::Anchor::Amx] = &mut cell as *mut Cell as u64;
        assert_eq!(run(&code, &mut state), (PC + 4, ExitKind::Amx as u64));
        assert_eq!((state.x[0], cell.calls), (1, 0));
    }
    assert!(file == before);
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
    // the call; the block touches only `state`, the cell its anchor names
    // and that cell's register file.
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

/// The cost of a block of eight vecfp f16 broadcasts through the routine
/// on the host's paths: `cargo test --release -p stela-compiler --lib
/// routine_costs -- --ignored --nocapture`.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
#[ignore = "manual: opt-in"]
fn routine_costs() {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(a: *mut c_void, b: usize, p: i32, f: i32, fd: i32, o: i64) -> *mut c_void;
        fn mprotect(a: *mut c_void, b: usize, p: i32) -> i32;
        fn munmap(a: *mut c_void, b: usize) -> i32;
    }
    const BYTES: usize = 1 << 16;
    const RUNS: u32 = 200_000;
    let words = [word(AmxOperation::VectorFloat); 8];
    let code = compile(&words);
    let bytes = crate::x86_64::pinned::entered(&code);
    let mut random = Random(3);
    let mut file = filled(&mut random);
    for native in [Native::select(TargetCpu::detect()), Native::MODEL] {
        let mut cell = Cell {
            registers: &mut *file as *mut AmxRegisters as u64,
            routine: routine as *const () as usize as u64,
            generation: Some(Generation::M2),
            native,
            ..Cell::default()
        };
        let mut state = crate::GuestState::default();
        state.x[OPERAND as usize] = 2 << 42 | 1 << 38 | 3 << 32 | 8 << 20;
        state.anchors[crate::Anchor::Amx] = &mut cell as *mut Cell as u64;
        // SAFETY: as `run`, mapped once for every call.
        unsafe {
            let page = mmap(core::ptr::null_mut(), BYTES, 3, 0x22, -1, 0);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), page.cast(), bytes.len());
            assert_eq!(mprotect(page, BYTES, 5), 0);
            let entry = |state: *mut crate::GuestState| -> u128 {
                crate::x86_64::native::call::<u128>(page as *const u8, state, 0, 0)
            };
            let runs = if native == Native::MODEL {
                RUNS / 100
            } else {
                RUNS
            };
            let started = std::time::Instant::now();
            for _ in 0..runs {
                entry(&mut state);
            }
            let each = started.elapsed().as_nanos() as f64 / f64::from(runs) / 8.0;
            std::println!("{native:?}: {each:.1} ns per vecfp through the routine");
            assert_eq!(munmap(page, BYTES), 0);
        }
    }
}
