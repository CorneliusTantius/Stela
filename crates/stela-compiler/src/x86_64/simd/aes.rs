//! AES: constant-time SSE2 circuits, or AES-NI when available. All sources are
//! read before the destination is written.
use crate::x86_64::asm::{Code, Gpr};
pub(in crate::x86_64) mod packed_rounds;
mod sbox;

use super::{Host, commit, packed, read_vector, rearrange::constant, shuffle};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        Instruction, Operation,
        simd::{
            Operand as Simd,
            aes::{Kind, Operand},
        },
    },
    x86_64::isa::ShiftOpcode as Shift,
};
use alloc::vec::Vec;

const RCX: u8 = 1;
const RESULT: u8 = 0;
const OLD_DESTINATION: u8 = 1;
const MASK: u8 = 3;
const LEFT: u8 = 4;
const RIGHT: u8 = 5;
const TERM: u8 = 6;
const HIGH: u8 = 7;
const BYTE_BITS: u8 = 8;
const COLUMN_BITS: u8 = 32;
const COLUMN_REPLICATION: u64 = 0x0000_0001_0000_0001;
const FORWARD_COLUMN_ORDER: [u8; 4] = [0xe4, 0x39, 0x4e, 0x93];
const INVERSE_COLUMN_ORDER: [u8; 4] = [0xe4, 0x93, 0x4e, 0x39];
const BYTE_REPLICATION: u64 = 0x0101_0101_0101_0101;
const FIELD_REDUCTION: u8 = 0x1b;
const SHIFT_ROWS: [u8; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
const INVERSE_SHIFT_ROWS: [u8; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];
/// Broadcast a byte without a memory pool or an additional SIMD clobber.
fn byte_constant(code: &mut Code, destination: u8, value: u8) {
    code.asm()
        .mov_imm64(Gpr::Rcx, u64::from(value) * BYTE_REPLICATION);
    packed(code, Host::MoveGprQword, destination, RCX);
    packed(code, Host::UnpackLowQword, destination, destination);
}

/// Per-byte multiplication by x modulo x^8+x^4+x^3+x+1. MASK holds 1b;
/// HIGH is scratch. PADDB avoids carries between adjacent byte lanes.
fn xtime(code: &mut Code, value: u8) {
    packed(code, Host::Xor, HIGH, HIGH);
    packed(code, Host::GreaterByte, HIGH, value);
    packed(code, Host::AddByte, value, value);
    packed(code, Host::And, HIGH, MASK);
    packed(code, Host::Xor, value, HIGH);
}

fn shift_rows(code: &mut Code, inverse: bool, target: TargetCpu) {
    let selection = if inverse {
        INVERSE_SHIFT_ROWS
    } else {
        SHIFT_ROWS
    };
    if target.supports(TargetCpu::Ssse3) {
        constant(code, MASK, selection);
        Host::ByteShuffle.register(code, RESULT, MASK, target);
        return;
    }
    // Each row rotates whole four-byte columns, then a fixed mask selects
    // that row from every column. PSHUFD is baseline SSE2, not SSSE3.
    let order = if inverse {
        INVERSE_COLUMN_ORDER
    } else {
        FORWARD_COLUMN_ORDER
    };
    for (row, control) in order.into_iter().enumerate() {
        let mask = u64::from(u8::MAX) << (row * usize::from(BYTE_BITS));
        code.asm().mov_imm64(Gpr::Rcx, mask * COLUMN_REPLICATION);
        packed(code, Host::MoveGprQword, MASK, RCX);
        packed(code, Host::UnpackLowQword, MASK, MASK);
        if row == 0 {
            packed(code, Host::MoveAligned, RIGHT, RESULT);
            packed(code, Host::And, RIGHT, MASK);
        } else {
            shuffle(code, LEFT, RESULT, control);
            packed(code, Host::And, LEFT, MASK);
            packed(code, Host::Or, RIGHT, LEFT);
        }
    }
    packed(code, Host::MoveAligned, RESULT, RIGHT);
}

/// Rotate each four-byte AES column right, keeping the input. MASK and HIGH
/// stay free for xtime; RESULT may be the destination.
fn rotate_column(code: &mut Code, destination: u8, source: u8, bits: u8) {
    packed(code, Host::MoveAligned, TERM, source);
    packed(code, Host::MoveAligned, destination, source);
    Shift::LeftDword.emit(code, TERM, COLUMN_BITS - bits);
    Shift::RightDword.emit(code, destination, bits);
    packed(code, Host::Or, destination, TERM);
}

fn mix_columns(code: &mut Code, inverse: bool) {
    byte_constant(code, MASK, FIELD_REDUCTION);
    if inverse {
        rotate_column(code, RIGHT, RESULT, BYTE_BITS * 2);
        packed(code, Host::Xor, RIGHT, RESULT);
        xtime(code, RIGHT);
        xtime(code, RIGHT);
        packed(code, Host::Xor, RESULT, RIGHT);
    }
    packed(code, Host::MoveAligned, LEFT, RESULT);
    rotate_column(code, RIGHT, LEFT, BYTE_BITS);
    packed(code, Host::Xor, RESULT, RIGHT);
    // RESULT = a XOR rot8(a), LEFT keeps a.
    xtime(code, RESULT);
    packed(code, Host::Xor, RESULT, RIGHT);
    rotate_column(code, RIGHT, LEFT, BYTE_BITS * 2);
    packed(code, Host::Xor, RESULT, RIGHT);
    rotate_column(code, RIGHT, LEFT, BYTE_BITS * 3);
    packed(code, Host::Xor, RESULT, RIGHT);
    // Above equals xtime(a XOR rot8(a)) XOR rot8(a) XOR rot16(a) XOR
    // rot24(a): a XOR columnXor simplifies away the duplicate a.
}

fn aes(code: &mut Code, kind: Kind, target: TargetCpu) {
    if kind == Kind::InverseMixColumns {
        Host::AesInverseMixColumns.register(code, RESULT, RESULT, target);
        return;
    }
    packed(code, Host::Xor, MASK, MASK);
    match kind {
        Kind::Encrypt => Host::AesEncryptLast.register(code, RESULT, MASK, target),
        Kind::Decrypt => Host::AesDecryptLast.register(code, RESULT, MASK, target),
        Kind::MixColumns => {
            Host::AesDecryptLast.register(code, RESULT, MASK, target);
            Host::AesEncryptRound.register(code, RESULT, MASK, target);
        }
        Kind::InverseMixColumns => unreachable!("handled before zero preparation"),
    }
}

fn round_input(code: &mut Code, operand: &Operand) {
    read_vector(code, operand.source, RESULT);
    read_vector(code, operand.destination, OLD_DESTINATION);
    packed(code, Host::Xor, RESULT, OLD_DESTINATION);
}

fn round_pair(instructions: &[Instruction]) -> Option<(&Operand, Host)> {
    let [first, second, ..] = instructions else {
        return None;
    };
    let (Operation::Simd(Simd::Aes(round)), Operation::Simd(Simd::Aes(mix))) =
        (&first.operation, &second.operation)
    else {
        return None;
    };
    if first.pc.0.checked_add(4) != Some(second.pc.0)
        || round.destination != mix.source
        || mix.source != mix.destination
    {
        return None;
    }
    let opcode = match (round.kind, mix.kind) {
        (Kind::Encrypt, Kind::MixColumns) => Host::AesEncryptRound,
        (Kind::Decrypt, Kind::InverseMixColumns) => Host::AesDecryptRound,
        _ => return None,
    };
    Some((round, opcode))
}

fn source_row(code: &mut Code, source_map: &mut Vec<(GuestAddress, usize)>, pc: GuestAddress) {
    code.set_instruction(source_map.len());
    source_map.push((pc, code.len()));
}

/// An in-place MixColumns consumes and overwrites the immediately preceding
/// AES row. Both operations are pure once the block has admitted AdvSIMD.
/// Keep both source rows, but commit only the final value within the block.
pub(in crate::x86_64) fn emit_round_pair(
    code: &mut Code,
    source_map: &mut Vec<(GuestAddress, usize)>,
    instructions: &[Instruction],
    target: TargetCpu,
) -> Option<u8> {
    let (round, opcode) = round_pair(instructions)?;
    source_row(code, source_map, instructions[0].pc);
    round_input(code, round);
    source_row(code, source_map, instructions[1].pc);
    // Arm XORs the key before the transforms. AES-NI's final key is zero.
    packed(code, Host::Xor, MASK, MASK);
    opcode.register(code, RESULT, MASK, target);
    commit(code, round.destination, RESULT);
    Some(round.destination)
}

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
    if matches!(operand.kind, Kind::Encrypt | Kind::Decrypt) {
        round_input(code, operand);
    } else {
        read_vector(code, operand.source, RESULT);
    }
    if target.supports(TargetCpu::Aes) {
        aes(code, operand.kind, target);
    } else {
        match operand.kind {
            Kind::Encrypt => {
                shift_rows(code, false, target);
                sbox::emit(code, false);
            }
            Kind::Decrypt => {
                shift_rows(code, true, target);
                sbox::emit(code, true);
            }
            Kind::MixColumns => mix_columns(code, false),
            Kind::InverseMixColumns => mix_columns(code, true),
        }
    }
    commit(code, operand.destination, RESULT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn occurrences(code: &[u8], opcode: Host) -> usize {
        code.windows(opcode.encoding().len())
            .filter(|window| *window == opcode.encoding())
            .count()
    }

    #[test]
    fn independent_aes_target_uses_only_the_reviewed_legacy_recipes() {
        for (kind, expected, bytes) in [
            (Kind::Encrypt, vec![Host::AesEncryptLast], 37),
            (Kind::Decrypt, vec![Host::AesDecryptLast], 37),
            (
                Kind::MixColumns,
                vec![Host::AesDecryptLast, Host::AesEncryptRound],
                30,
            ),
            (
                Kind::InverseMixColumns,
                vec![Host::AesInverseMixColumns],
                21,
            ),
        ] {
            let operand = Operand {
                kind,
                destination: 31,
                source: 31,
            };
            let mut code = Code::new();
            emit(&mut code, &operand, TargetCpu::Aes);
            assert_eq!(code.len(), bytes); // Complete body, excludes harness RET.
            for opcode in [
                Host::AesEncryptLast,
                Host::AesDecryptLast,
                Host::AesEncryptRound,
                Host::AesDecryptRound,
                Host::AesInverseMixColumns,
            ] {
                assert_eq!(
                    occurrences(&code, opcode),
                    usize::from(expected.contains(&opcode))
                );
            }
            assert_eq!(occurrences(&code, Host::ByteShuffle), 0);
        }
    }

    #[test]
    fn baseline_excludes_aes_and_ssse3_even_for_aliases() {
        for kind in [
            Kind::Encrypt,
            Kind::Decrypt,
            Kind::MixColumns,
            Kind::InverseMixColumns,
        ] {
            let mut code = Code::new();
            emit(
                &mut code,
                &Operand {
                    kind,
                    destination: 31,
                    source: 31,
                },
                TargetCpu::Baseline,
            );
            for opcode in [
                Host::AesEncryptLast,
                Host::AesDecryptLast,
                Host::AesEncryptRound,
                Host::AesDecryptRound,
                Host::AesInverseMixColumns,
                Host::ByteShuffle,
            ] {
                assert_eq!(occurrences(&code, opcode), 0);
            }
        }
    }

    /// The software rounds run on the host under both block entry alignments,
    /// so the S-box frame's aligned stack planes never fault, and they match
    /// SubBytes(ShiftRows(Vd ^ Vn)) and its inverse.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn software_rounds_execute_at_either_stack_alignment() {
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
        // `call body; ret`: the body is entered with RSP 16-byte aligned, as
        // chained blocks are, rather than SysV's RSP % 16 == 8.
        const WRAPPER: [u8; 6] = [0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3];
        fn multiply(mut left: u8, mut right: u8) -> u8 {
            let mut product = 0;
            while right != 0 {
                if right & 1 != 0 {
                    product ^= left;
                }
                left = (left << 1) ^ if left & 0x80 != 0 { FIELD_REDUCTION } else { 0 };
                right >>= 1;
            }
            product
        }
        let mut forward = [0u8; 256];
        let mut inverse = [0u8; 256];
        for value in 0..=255u8 {
            let reciprocal = (1..=255u8)
                .find(|&candidate| multiply(value, candidate) == 1)
                .unwrap_or(0);
            let substituted = reciprocal
                ^ reciprocal.rotate_left(1)
                ^ reciprocal.rotate_left(2)
                ^ reciprocal.rotate_left(3)
                ^ reciprocal.rotate_left(4)
                ^ 0x63;
            forward[usize::from(value)] = substituted;
            inverse[usize::from(substituted)] = value;
        }
        assert_eq!((forward[0], forward[0x53]), (0x63, 0xed));
        let bytes = |vector: [u64; 2]| -> [u8; 16] {
            let mut out = [0; 16];
            out[..8].copy_from_slice(&vector[0].to_le_bytes());
            out[8..].copy_from_slice(&vector[1].to_le_bytes());
            out
        };
        let destination = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let source = [0x0f1e_2d3c_4b5a_6978, 0x8796_a5b4_c3d2_e1f0];
        let state_bytes: Vec<u8> = bytes(destination)
            .iter()
            .zip(bytes(source))
            .map(|(left, right)| left ^ right)
            .collect();
        for (kind, rows, table) in [
            (Kind::Encrypt, SHIFT_ROWS, &forward),
            (Kind::Decrypt, INVERSE_SHIFT_ROWS, &inverse),
        ] {
            let expected: Vec<u8> = rows
                .iter()
                .map(|&row| table[usize::from(state_bytes[usize::from(row)])])
                .collect();
            let mut code = Code::new();
            let body = code.asm().call();
            code.asm().ret();
            code.asm().bind(body);
            assert_eq!(code.as_slice(), WRAPPER);
            emit(
                &mut code,
                &Operand {
                    kind,
                    destination: 2,
                    source: 7,
                },
                TargetCpu::Baseline,
            );
            code.asm().ret();
            assert!(code.len() <= PAGE);
            for offset in [0, WRAPPER.len()] {
                let mut state = GuestState::default();
                state.v[2] = destination;
                state.v[7] = source;
                // SAFETY: private anonymous memory, RX after the copy and
                // unmapped after the call; the code writes only `state` and
                // its own stack frame.
                unsafe {
                    let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                    assert_ne!(page as usize, usize::MAX);
                    core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                    assert_eq!(mprotect(page, PAGE, 5), 0);
                    let entry = |state: *mut crate::GuestState| -> () {
                        crate::x86_64::native::call::<()>(
                            page.cast::<u8>().add(offset) as *const u8,
                            state,
                            0,
                            0,
                        )
                    };
                    entry(&mut state);
                    assert_eq!(munmap(page, PAGE), 0);
                }
                assert_eq!(bytes(state.v[2]).to_vec(), expected, "{kind:?} at {offset}");
                assert_eq!(state.v[7], source, "{kind:?} at {offset}");
            }
        }
    }
}
