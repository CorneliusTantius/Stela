use super::*;
use crate::{
    Lifter, Options,
    aarch64::Decoder,
    block::{BlockProfile, CompilationPlan, CompiledBlock, Features},
};

const PC: GuestAddress = GuestAddress(0x1f534c);
// UDIV X20,X21,X1; MSUB X20,X20,X1,X21 from the OpenSSL RSA workload.
const OPENSSL: [u32; 2] = [0x9ac1_0ab4, 0x9b01_d694];

fn lift(words: [u32; 2]) -> [Instruction; 2] {
    core::array::from_fn(|index| {
        Decoder
            .lift(GuestAddress(PC.0 + 4 * index as u64), words[index])
            .unwrap()
    })
}

fn compile(words: &[u32], pc: GuestAddress, target: TargetCpu) -> CompiledBlock {
    compile_profile(words, pc, target, BlockProfile::ORDINARY)
}

fn compile_profile(
    words: &[u32],
    pc: GuestAddress,
    target: TargetCpu,
    profile: BlockProfile,
) -> CompiledBlock {
    let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    CompilationPlan::new(&source, pc, &Options::new(profile, target))
        .unwrap()
        .compile()
        .unwrap()
}

#[test]
fn divide_remainder_emits_two_rows_and_one_remainder_store() {
    for target in [
        TargetCpu::Baseline,
        TargetCpu::Ssse3,
        TargetCpu::Sse41,
        TargetCpu::X86_64_V3,
    ] {
        for (wide, signed, old_bytes, new_bytes, old_count, new_count) in [
            (true, false, 80, 52, 16, 11),
            (false, false, 77, 51, 17, 12),
            (true, true, 98, 72, 20, 16),
            (false, true, 92, 68, 21, 17),
        ] {
            let words = [
                OPENSSL[0] & !(1 << 31) | (u32::from(wide) << 31) | (u32::from(signed) << 10),
                OPENSSL[1] & !(1 << 31) | (u32::from(wide) << 31),
            ];
            let instructions = lift(words);
            let [
                Operation::IntegerMath(division),
                Operation::IntegerMath(product),
            ] = instructions.clone().map(|row| row.operation)
            else {
                panic!("decoded division and MSUB");
            };
            let mut old = Code::new();
            emit(&mut old, &division, target);
            emit(&mut old, &product, target);
            assert_eq!((old.len(), old.instructions()), (old_bytes, old_count));
            let mut grouped = Code::new();
            let mut map = Vec::new();
            assert!(emit_divide_remainder(&mut grouped, &mut map, &instructions));
            assert_eq!(
                (grouped.len(), grouped.instructions()),
                (new_bytes, new_count)
            );
            assert_eq!(&grouped[map[1].1..], &[0x48, 0x89, 0x97, 0xa0, 0, 0, 0]);
            let block = compile(&words, PC, target);
            assert_eq!(block.native.source_map, map);
            assert!(block.native.x86_64_code.starts_with(&grouped));
            let dit = compile(&words, PC, target.with_data_independent_timing());
            assert!(dit.native.x86_64_code.starts_with(&old));
        }
    }
}

#[test]
fn divide_remainder_refuses_aliased_inputs_and_unmatched_rows() {
    let [a, b] = OPENSSL;
    for words in [
        [a & !31 | 21, b & !(31 << 5) | (21 << 5)], // Quotient overwrites the dividend.
        [a & !31 | 1, b & !(31 << 5) | (1 << 5)],   // Quotient overwrites the divisor.
        [a, b ^ (1 << 31)],                         // Different result width.
        [a, b ^ (1 << 15)],                         // MADD.
        [a, b ^ (1 << 10)],                         // A different accumulator.
        [a, b | 31],                                // Discarded remainder.
    ] {
        let mut code = Code::new();
        let mut map = Vec::new();
        assert!(!emit_divide_remainder(&mut code, &mut map, &lift(words)));
        assert!(code.is_empty() && map.is_empty());
    }
    let mut separated = lift(OPENSSL);
    separated[1].pc.0 += 4;
    assert!(!emit_divide_remainder(
        &mut Code::new(),
        &mut Vec::new(),
        &separated
    ));
}

#[test]
fn pinned_divide_remainder_keeps_recovery_at_the_following_access() {
    use crate::block::RecoverySiteKind;

    let system = BlockProfile::new(Features::SYSTEM_MODE);
    let target = TargetCpu::Baseline;
    let instructions = lift(OPENSSL);
    let mut group = Code::pinned();
    let mut map = Vec::new();
    assert!(emit_divide_remainder(&mut group, &mut map, &instructions));
    assert_eq!((group.len(), group.instructions()), (48, 11));
    assert!(group.sites().is_empty());
    let pair = compile_profile(&OPENSSL, PC, target, system);
    assert_eq!(pair.native.source_map, map);
    assert!(pair.native.x86_64_code.starts_with(&group));
    assert!(pair.fault_recovery.is_empty());

    let [a, b] = OPENSSL;
    let load_pc = GuestAddress(PC.0 + 8);
    let with_access = compile_profile(&[a, b, 0xf940_0004], PC, target, system);
    assert_eq!(
        with_access.native.source_map,
        [map[0], map[1], (load_pc, group.len())]
    );
    assert!(with_access.native.x86_64_code.starts_with(&group));
    assert!(
        with_access
            .fault_recovery
            .iter()
            .any(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
    );
    for row in with_access.fault_recovery {
        assert!(row.start >= group.len());
        assert_eq!(row.retirement.instruction_pc(), load_pc);
        assert_eq!(row.retirement.retired_before(), 2);
        assert!(row.bindings.is_empty());
    }

    let dit = target.with_data_independent_timing();
    let mut separate = Code::pinned();
    for row in instructions {
        let Operation::IntegerMath(operand) = row.operation else {
            unreachable!("decoded DIV and MSUB");
        };
        emit(&mut separate, &operand, dit);
    }
    assert_eq!((separate.len(), separate.instructions()), (72, 16));
    assert!(
        compile_profile(&OPENSSL, PC, dit, system)
            .native
            .x86_64_code
            .starts_with(&separate)
    );
}

#[test]
fn pinned_divide_remainder_shortens_the_installed_desktop_pair() {
    // UDIV W8,W12,W9; MSUB W8,W8,W9,W12 from the installed desktop trace.
    let words = [0x1ac9_0988, 0x1b09_b108];
    let pc = GuestAddress(0x18cfb1460);
    let system = BlockProfile::new(Features::SYSTEM_MODE);
    let target = TargetCpu::Baseline;
    let mut group = Code::pinned();
    let mut map = Vec::new();
    let instructions = lift(words);
    assert!(emit_divide_remainder(&mut group, &mut map, &instructions));
    assert_eq!((group.len(), group.instructions()), (37, 12));
    assert_eq!(&group[map[1].1..], &[0x48, 0x89, 0xd6]); // mov rsi,rdx
    let actual = compile_profile(&words, pc, target, system);
    assert_eq!(
        actual.native.source_map,
        [(pc, 0), (GuestAddress(pc.0 + 4), map[1].1)]
    );
    assert!(actual.native.x86_64_code.starts_with(&group));

    let mut separate = Code::pinned();
    for row in instructions {
        let Operation::IntegerMath(operand) = row.operation else {
            unreachable!("decoded DIV and MSUB");
        };
        emit(&mut separate, &operand, target);
    }
    assert_eq!((separate.len(), separate.instructions()), (53, 17));
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn divide_remainder_matches_arm_at_each_row_and_independent_entry() {
    check_state_at_each_row(
        BlockProfile::ORDINARY,
        &[
            [0, 1, 2, 2],
            [0, 1, 2, 0],
            [0, 1, 2, 1],
            [0, 1, 2, 3],
            [0, 0, 2, 30],
            [31, 1, 2, 3],
            [0, 31, 2, 3],
        ],
    );
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn pinned_divide_remainder_settles_both_rows_and_independent_entry() {
    check_state_at_each_row(
        BlockProfile::new(Features::SYSTEM_MODE),
        &[
            [0, 1, 8, 8],
            [8, 19, 0, 19],
            [19, 8, 17, 16],
            [1, 16, 19, 0],
            [21, 1, 20, 20],
            [31, 1, 8, 1],
            [0, 31, 8, 0],
            [0, 0, 8, 8],
        ],
    );
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn pinned_divide_remainder_commits_before_a_polled_exit() {
    use crate::{
        Anchor, GuestState,
        x86_64::{chain, native::run, pinned},
    };

    let division = OPENSSL[0] & !31 | 8;
    let remainder = OPENSSL[1] & !(31 | (31 << 5)) | 8 | (8 << 5);
    let block = compile_profile(
        &[division, remainder, 0x17ff_fffe], // Backward branch to DIV.
        PC,
        TargetCpu::Baseline,
        BlockProfile::new(Features::SYSTEM_MODE),
    );
    let [exit] = block.direct_exits.as_slice() else {
        panic!("one direct exit");
    };
    assert_eq!(exit.target, PC);
    let at = exit.offset - chain::POLLED_LINK_BYTES;
    // The link at offset 0 as the code's own would be at its offset: the
    // pad and point alike once the code lands at an aligned address.
    let (body, link) = chain::link(at as u64, chain::POLLED_LINK_BYTES, 3, 1, 0).unwrap();
    let mut code = block.native.x86_64_code;
    let point = chain::slot_patch(at as u64) as usize;
    code[body as usize..body as usize + link.len()].copy_from_slice(&link);
    code[point..point + chain::PATCH_BYTES].copy_from_slice(&chain::NOP5);

    let mut control = chain::ChainControl {
        count: chain::ChainControl::counting(1, 0),
        interrupt_epoch: 2,
        observed_interrupt_epoch: 1,
        ..Default::default()
    };
    let mut state = GuestState {
        nzcv: 0xb000_0000,
        ..Default::default()
    };
    state.anchors[Anchor::Control] = &raw mut control as u64;
    state.x[21] = 29;
    state.x[1] = 6;
    let mut expected = state.clone();
    expected.x[8] = 5;
    assert_eq!(run(&pinned::entered(&code), &mut state), PC.0);
    assert_eq!(state, expected);
    assert_eq!(
        (control.remaining(), control.retired(), control.block),
        (1, 0, 0)
    );
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn check_state_at_each_row(profile: BlockProfile, aliases: &[[u32; 4]]) {
    use crate::{
        GuestState,
        x86_64::{native::run, pinned},
    };

    let enter = |code: &[u8]| {
        if profile.has(Features::FULL_SYSTEM) {
            pinned::entered(code)
        } else {
            code.to_vec()
        }
    };
    let inputs = [
        0,
        1,
        3,
        0x8000_0000,
        0x8000_0000_0000_0000,
        0xffff_ffff_ffff_fffd,
        u64::MAX,
    ];
    for wide in [false, true] {
        for signed in [false, true] {
            for swapped in [false, true] {
                for &[dividend, divisor, quotient, remainder] in aliases {
                    let form = u32::from(wide) << 31;
                    let divide = 0x1ac0_0800
                        | form
                        | (u32::from(signed) << 10)
                        | (divisor << 16)
                        | (dividend << 5)
                        | quotient;
                    let (left, right) = if swapped {
                        (divisor, quotient)
                    } else {
                        (quotient, divisor)
                    };
                    let msub = 0x1b00_8000
                        | form
                        | (right << 16)
                        | (dividend << 10)
                        | (left << 5)
                        | remainder;
                    let compiled =
                        compile_profile(&[divide, msub], PC, TargetCpu::Baseline, profile);
                    let msub_pc = GuestAddress(PC.0 + 4);
                    let msub_at = compiled.native.source_map[1].1;
                    assert_eq!(compiled.native.source_map, [(PC, 0), (msub_pc, msub_at)]);
                    let alone = compile_profile(&[msub], msub_pc, TargetCpu::Baseline, profile);
                    assert_eq!(alone.native.source_map, [(msub_pc, 0)]);
                    let first_body = enter(&compiled.native.x86_64_code[..msub_at]);
                    let pair_body = enter(&compiled.native.x86_64_code);
                    let second_body = enter(&alone.native.x86_64_code);
                    let mask = if wide { u64::MAX } else { u32::MAX.into() };
                    let signed_value = |v: u64| {
                        if wide {
                            i128::from(v as i64)
                        } else {
                            i128::from(v as i32)
                        }
                    };
                    for a in inputs {
                        for b in inputs {
                            let mut state = GuestState {
                                x: [0xabab_cdcd_efef_0101; 31],
                                sp: 0x1234_5678_9000,
                                nzcv: 0xb000_0000,
                                ..Default::default()
                            };
                            if dividend != 31 {
                                state.x[dividend as usize] = a;
                            }
                            if divisor != 31 {
                                state.x[divisor as usize] = b;
                            }
                            let read =
                                |r| state.x.get(r as usize).copied().unwrap_or_default() & mask;
                            let (a, b) = (read(dividend), read(divisor));
                            let q = if b == 0 {
                                0
                            } else if signed {
                                (signed_value(a) / signed_value(b)) as u64 & mask
                            } else {
                                a / b
                            };
                            let r = a.wrapping_sub(q.wrapping_mul(b)) & mask;
                            let mut first = state.clone();
                            first.x[quotient as usize] = q;
                            let mut expected = first.clone();
                            expected.x[remainder as usize] = r;
                            let mut intermediate = state.clone();
                            run(&first_body, &mut intermediate);
                            assert_eq!(intermediate, first, "{divide:08x}, {msub:08x}");
                            assert_eq!(run(&pair_body, &mut state), PC.0 + 8);
                            assert_eq!(state, expected, "{divide:08x}, {msub:08x}");
                            assert_eq!(run(&second_body, &mut intermediate), PC.0 + 8);
                            assert_eq!(intermediate, expected, "independent {msub:08x}");
                        }
                    }
                }
            }
        }
    }
}
