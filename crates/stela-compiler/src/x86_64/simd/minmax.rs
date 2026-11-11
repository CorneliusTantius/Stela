//! FP min/max: normal, zero or infinite S/D selection and normal H integer ordering.
use super::super::isa::ShiftOpcode;
use super::numerical::helper_section;
use super::numerical::{
    Condition, INPUT_MINIMUM_EXPONENT, branch, clear_high_qword, clear_scalar, exponent_range,
    jump, prepare_vector_input_range, read_numerical_vector, resolve, test_control,
    vector_exponent_range, vector_normal_zero_or_infinite_range,
};
use super::{Host, commit, packed, packed_imm, read_vector};
use crate::x86_64::asm::{Code, Gpr, Rm, ShiftOp, Size, vector_extensions};
use crate::x86_64::asm::{FloatLanes, FloatOp};
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{
            FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format, minmax::MinMaxOperation,
        },
        simd::{
            arithmetic::Shape,
            minmax::{BinaryMode, Operand},
        },
    },
};
use alloc::vec::Vec;

const RESULT_VECTOR: u8 = 0;
const RIGHT_VECTOR: u8 = 1;
const SIGN_VECTOR: u8 = 2;
const PAIR_VECTOR: u8 = 6;
const ORIGINAL_LEFT_VECTOR: u8 = 7;
// XMM3's input validity is dead after the guards. The right operand is consumed
// by selection; XMM6 may itself be that operand after pairwise staging.
const SELECTION_SCRATCH: u8 = 3;
const HALF_SIGN_SHIFT: u8 = u16::BITS as u8 - 1;
const SIGN_MASK_TO_MAGNITUDE_SHIFT: u8 = 1;
const BITS_PER_BYTE: u32 = u8::BITS;
const EVEN_DWORDS: u8 = 0x88;
const ODD_DWORDS: u8 = 0xdd;
const SWAP_ADJACENT_WORDS: u8 = 0xb1;
const EVEN_WORDS: u8 = 0x88;
const TWO_HALF_BYTES: u8 = 2 * (u16::BITS / BITS_PER_BYTE) as u8;
const FOUR_HALF_BYTES: u8 = 4 * (u16::BITS / BITS_PER_BYTE) as u8;

fn is_minimum(operation: MinMaxOperation) -> bool {
    matches!(
        operation,
        MinMaxOperation::Minimum | MinMaxOperation::MinimumNumber
    )
}

fn raw_selection(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    shape: Shape,
    destination: u8,
    right: u8,
) {
    if format == Format::Half {
        packed(
            code,
            if is_minimum(operation) {
                Host::MinSignedWord
            } else {
                Host::MaxSignedWord
            },
            destination,
            right,
        );
        return;
    }
    let lanes = match (format, shape) {
        (Format::Single, Shape::Scalar) => FloatLanes::ScalarSingle,
        (Format::Double, Shape::Scalar) => FloatLanes::ScalarDouble,
        (Format::Double, _) => FloatLanes::PackedDouble,
        (Format::Single, _) => FloatLanes::PackedSingle,
        (Format::Half, _) => unreachable!("half selection is integer-only"),
    };
    let op = if is_minimum(operation) {
        FloatOp::Min
    } else {
        FloatOp::Max
    };
    code.asm().float(op, lanes, destination, Rm::Xmm(right));
}

/// Legacy SSE selects operand2 on a zero tie. Symmetric selection followed by
/// sign AND (maximum) or OR (minimum) gives Arm's standard zero sign, as
/// AVX10.2's VMINMAX does alone. Plain AH=1 keeps operand2 instead. No inactive
/// scalar lane undergoes FP work.
fn selection(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    shape: Shape,
    destination: u8,
    right: u8,
    target: TargetCpu,
) {
    if format == Format::Half {
        raw_selection(code, operation, format, shape, destination, right);
        return;
    }
    debug_assert!(destination != right);
    debug_assert!(destination != SELECTION_SCRATCH && right != SELECTION_SCRATCH);
    let alternative = if matches!(
        operation,
        MinMaxOperation::Minimum | MinMaxOperation::Maximum
    ) {
        test_control(code, FPCR_AH);
        Some(branch(code, Condition::NotZero))
    } else {
        None
    };
    let combine = if is_minimum(operation) {
        Host::Or
    } else {
        Host::And
    };
    if vector_extensions::extrema_supported(target) {
        vector_extensions::extrema(
            code,
            format,
            shape == Shape::Scalar,
            !is_minimum(operation),
            destination,
            right,
        );
    } else if shape == Shape::Scalar {
        packed(code, Host::MoveAligned, SELECTION_SCRATCH, destination);
        raw_selection(code, operation, format, shape, SELECTION_SCRATCH, right);
        raw_selection(code, operation, format, shape, right, destination);
        packed(code, combine, SELECTION_SCRATCH, right);
        packed(
            code,
            if format == Format::Double {
                Host::MoveScalarDouble
            } else {
                Host::MoveScalarSingle
            },
            destination,
            SELECTION_SCRATCH,
        );
    } else {
        packed(code, Host::MoveAligned, SELECTION_SCRATCH, right);
        raw_selection(code, operation, format, shape, right, destination);
        raw_selection(
            code,
            operation,
            format,
            shape,
            destination,
            SELECTION_SCRATCH,
        );
        packed(code, combine, destination, right);
    }
    if let Some(alternative) = alternative {
        let done = jump(code);
        let alternative_start = code.len();
        resolve(code, alternative, alternative_start);
        raw_selection(code, operation, format, shape, destination, right);
        let end = code.len();
        resolve(code, done, end);
    }
}

/// Normal half-precision values map to a signed-word order key, and the same
/// transform restores the bit pattern after integer min/max.
fn half_order(code: &mut Code, vector: u8) {
    packed(code, Host::MoveAligned, SIGN_VECTOR, vector);
    ShiftOpcode::ArithmeticWord.emit(code, SIGN_VECTOR, HALF_SIGN_SHIFT);
    ShiftOpcode::RightWord.emit(code, SIGN_VECTOR, SIGN_MASK_TO_MAGNITUDE_SHIFT);
    packed(code, Host::Xor, vector, SIGN_VECTOR);
}

fn exception_guard(code: &mut Code, helper: &mut Vec<usize>) {
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
}

/// S/D lanes pass when normal, zero or infinite: MINPS/MAXPS order infinities
/// as Arm does, without status. Half lanes must be normal (order key).
fn input_guard(code: &mut Code, format: Format, shape: Shape, source: u8, helper: &mut Vec<usize>) {
    if shape == Shape::Scalar {
        let zero = if format != Format::Half {
            // A zero fraction is a zero, an infinity or a normal value.
            let double = format == Format::Double;
            let mut asm = code.asm();
            if double {
                asm.movq_from_xmm(Gpr::Rax, source);
            } else {
                asm.movd_from_xmm(Gpr::Rax, source);
            }
            asm.shift_imm(
                ShiftOp::Shl,
                Size::of(double),
                Gpr::Rax,
                (format.bits() - format.fraction_bits()) as u8,
            );
            Some(branch(code, Condition::Zero))
        } else {
            None
        };
        exponent_range(code, format, source, INPUT_MINIMUM_EXPONENT);
        helper.push(branch(code, Condition::AboveOrEqual));
        if let Some(zero) = zero {
            let end = code.len();
            resolve(code, zero, end);
        }
    } else {
        if format == Format::Half {
            vector_exponent_range(code, format, shape, source);
        } else {
            vector_normal_zero_or_infinite_range(code, format, shape, source, PAIR_VECTOR);
        }
        helper.push(branch(code, Condition::NotZero));
    }
}

fn shuffle(code: &mut Code, opcode: Host, destination: u8, source: u8, control: u8) {
    packed_imm(code, opcode, destination, source, control);
}

fn shuffle_single(code: &mut Code, destination: u8, right: u8, control: u8) {
    code.asm().shufps(destination, Rm::Xmm(right), control);
}

fn unpack_double(code: &mut Code, destination: u8, right: u8, high: bool) {
    if high {
        code.asm().unpckhpd(destination, Rm::Xmm(right));
    } else {
        code.asm().unpcklpd(destination, Rm::Xmm(right));
    }
}

/// Pairwise results fill both words of each pair. Only integer operations run,
/// so inactive or duplicated lanes have no effect.
fn half_pairs(code: &mut Code, operation: MinMaxOperation, source: u8) {
    shuffle(
        code,
        Host::ShuffleLowWord,
        PAIR_VECTOR,
        source,
        SWAP_ADJACENT_WORDS,
    );
    shuffle(
        code,
        Host::ShuffleHighWord,
        PAIR_VECTOR,
        PAIR_VECTOR,
        SWAP_ADJACENT_WORDS,
    );
    raw_selection(
        code,
        operation,
        Format::Half,
        Shape::Vector128,
        source,
        PAIR_VECTOR,
    );
}

fn compact_half_pairs(code: &mut Code, shape: Shape, source: u8) {
    shuffle(code, Host::ShuffleLowWord, source, source, EVEN_WORDS);
    if shape == Shape::Vector128 {
        shuffle(code, Host::ShuffleHighWord, source, source, EVEN_WORDS);
        shuffle(code, Host::ShuffleDword, source, source, EVEN_DWORDS);
    }
}

fn vector_pairs(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    shape: Shape,
    target: TargetCpu,
) {
    match format {
        Format::Half => {
            for source in [RESULT_VECTOR, RIGHT_VECTOR] {
                half_pairs(code, operation, source);
                compact_half_pairs(code, shape, source);
            }
            packed(
                code,
                if shape == Shape::Vector64 {
                    Host::UnpackLowDword
                } else {
                    Host::UnpackLowQword
                },
                RESULT_VECTOR,
                RIGHT_VECTOR,
            );
        }
        Format::Single if shape == Shape::Vector64 => {
            // Q0 loads zero both upper qwords. Gather [n0,m0,n1,m1], then
            // compare against [n1,m1,0,0]; only the low two results survive.
            let mut asm = code.asm();
            asm.unpcklps(RESULT_VECTOR, Rm::Xmm(RIGHT_VECTOR));
            asm.movhlps(RIGHT_VECTOR, Rm::Xmm(RESULT_VECTOR));
            selection(
                code,
                operation,
                format,
                shape,
                RESULT_VECTOR,
                RIGHT_VECTOR,
                target,
            );
        }
        Format::Single => {
            packed(code, Host::MoveAligned, PAIR_VECTOR, RESULT_VECTOR);
            shuffle_single(code, RESULT_VECTOR, RIGHT_VECTOR, EVEN_DWORDS);
            shuffle_single(code, PAIR_VECTOR, RIGHT_VECTOR, ODD_DWORDS);
            selection(
                code,
                operation,
                format,
                shape,
                RESULT_VECTOR,
                PAIR_VECTOR,
                target,
            );
        }
        Format::Double => {
            packed(code, Host::MoveAligned, PAIR_VECTOR, RESULT_VECTOR);
            unpack_double(code, RESULT_VECTOR, RIGHT_VECTOR, false);
            unpack_double(code, PAIR_VECTOR, RIGHT_VECTOR, true);
            selection(
                code,
                operation,
                format,
                shape,
                RESULT_VECTOR,
                PAIR_VECTOR,
                target,
            );
        }
    }
}

fn finish_binary(code: &mut Code, format: Format, shape: Shape, destination: u8) {
    if shape == Shape::Scalar {
        test_control(code, FPCR_NEP);
        let merge = branch(code, Condition::NotZero);
        if format == Format::Half {
            packed(code, Host::Xor, ORIGINAL_LEFT_VECTOR, ORIGINAL_LEFT_VECTOR);
        } else {
            clear_scalar(code, format, RESULT_VECTOR);
        }
        let merge_target = code.len();
        resolve(code, merge, merge_target);
        if format == Format::Half {
            let mut asm = code.asm();
            asm.movd_from_xmm(Gpr::Rax, RESULT_VECTOR);
            asm.pinsrw(ORIGINAL_LEFT_VECTOR, Gpr::Rax, 0);
            packed(code, Host::MoveAligned, RESULT_VECTOR, ORIGINAL_LEFT_VECTOR);
        }
    } else if shape == Shape::Vector64 {
        clear_high_qword(code, 0);
    }
    commit(code, destination, RESULT_VECTOR);
}

fn binary(code: &mut Code, operand: &Operand, pc: GuestAddress, target: TargetCpu) {
    let Operand::Binary {
        operation,
        format,
        shape,
        mode,
        destination,
        left,
        right,
    } = *operand
    else {
        unreachable!("binary min/max operand")
    };
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_numerical_vector(code, shape, left, RESULT_VECTOR);
    read_numerical_vector(code, shape, right, RIGHT_VECTOR);
    if shape != Shape::Scalar {
        prepare_vector_input_range(code, format);
    }
    input_guard(code, format, shape, RESULT_VECTOR, &mut helper);
    input_guard(code, format, shape, RIGHT_VECTOR, &mut helper);
    helper_section(code, &helper, pc);
    if format == Format::Half {
        if shape == Shape::Scalar {
            packed(code, Host::MoveAligned, ORIGINAL_LEFT_VECTOR, RESULT_VECTOR);
        }
        half_order(code, RESULT_VECTOR);
        half_order(code, RIGHT_VECTOR);
    }
    if mode == BinaryMode::Pairwise {
        vector_pairs(code, operation, format, shape, target);
    } else {
        selection(
            code,
            operation,
            format,
            shape,
            RESULT_VECTOR,
            RIGHT_VECTOR,
            target,
        );
    }
    if format == Format::Half {
        half_order(code, RESULT_VECTOR);
    }
    finish_binary(code, format, shape, destination);
}

fn pairwise_scalar(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    destination: u8,
    source: u8,
    pc: GuestAddress,
    target: TargetCpu,
) {
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_vector(code, source, RESULT_VECTOR);
    packed(code, Host::MoveAligned, RIGHT_VECTOR, RESULT_VECTOR);
    ShiftOpcode::RightBytes.emit(code, RIGHT_VECTOR, (format.bits() / BITS_PER_BYTE) as u8);
    input_guard(code, format, Shape::Scalar, RESULT_VECTOR, &mut helper);
    input_guard(code, format, Shape::Scalar, RIGHT_VECTOR, &mut helper);
    helper_section(code, &helper, pc);
    if format == Format::Half {
        half_order(code, RESULT_VECTOR);
        half_order(code, RIGHT_VECTOR);
    }
    selection(
        code,
        operation,
        format,
        Shape::Scalar,
        RESULT_VECTOR,
        RIGHT_VECTOR,
        target,
    );
    if format == Format::Half {
        half_order(code, RESULT_VECTOR);
    }
    clear_scalar(code, format, RESULT_VECTOR);
    commit(code, destination, RESULT_VECTOR);
}

fn reduction(code: &mut Code, operand: &Operand, pc: GuestAddress, target: TargetCpu) {
    let Operand::Reduction {
        operation,
        format,
        shape,
        destination,
        source,
    } = *operand
    else {
        unreachable!("reduction min/max operand")
    };
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_numerical_vector(code, shape, source, RESULT_VECTOR);
    prepare_vector_input_range(code, format);
    input_guard(code, format, shape, RESULT_VECTOR, &mut helper);
    helper_section(code, &helper, pc);
    if format == Format::Half {
        half_order(code, RESULT_VECTOR);
        half_pairs(code, operation, RESULT_VECTOR);
        // Balanced low/high subtrees match FPReduce: (0,1) with (2,3),
        // and for8H (4,5) with (6,7), followed by the two half results.
        let shifts: &[u8] = if shape == Shape::Vector64 {
            &[TWO_HALF_BYTES]
        } else {
            &[TWO_HALF_BYTES, FOUR_HALF_BYTES]
        };
        for &amount in shifts {
            packed(code, Host::MoveAligned, PAIR_VECTOR, RESULT_VECTOR);
            ShiftOpcode::RightBytes.emit(code, PAIR_VECTOR, amount);
            selection(
                code,
                operation,
                format,
                shape,
                RESULT_VECTOR,
                PAIR_VECTOR,
                target,
            );
        }
        half_order(code, RESULT_VECTOR);
    } else {
        debug_assert_eq!(format, Format::Single);
        packed(code, Host::MoveAligned, RIGHT_VECTOR, RESULT_VECTOR);
        shuffle(
            code,
            Host::ShuffleDword,
            RESULT_VECTOR,
            RESULT_VECTOR,
            EVEN_DWORDS,
        );
        shuffle(
            code,
            Host::ShuffleDword,
            RIGHT_VECTOR,
            RIGHT_VECTOR,
            ODD_DWORDS,
        );
        selection(
            code,
            operation,
            format,
            shape,
            RESULT_VECTOR,
            RIGHT_VECTOR,
            target,
        );
        packed(code, Host::MoveAligned, RIGHT_VECTOR, RESULT_VECTOR);
        ShiftOpcode::RightBytes.emit(code, RIGHT_VECTOR, (format.bits() / BITS_PER_BYTE) as u8);
        selection(
            code,
            operation,
            format,
            Shape::Scalar,
            RESULT_VECTOR,
            RIGHT_VECTOR,
            target,
        );
    }
    clear_scalar(code, format, RESULT_VECTOR);
    commit(code, destination, RESULT_VECTOR);
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    match *operand {
        Operand::Binary { .. } => binary(code, operand, pc, target),
        Operand::PairwiseScalar {
            operation,
            format,
            destination,
            source,
        } => {
            pairwise_scalar(code, operation, format, destination, source, pc, target);
        }
        Operand::Reduction { .. } => reduction(code, operand, pc, target),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        GuestAddress, GuestState, Options, TargetCpu,
        aarch64::floating::{FPCR_AH, Format, minmax::MinMaxOperation, minmax::evaluate},
        block::{BlockProfile, CompilationPlan},
        x86_64::native::run,
    };
    use alloc::vec::Vec;

    const PC: GuestAddress = GuestAddress(0x1000_0000);
    const RETURN: u64 = 0x4000;
    const OPERATIONS: [MinMaxOperation; 4] = [
        MinMaxOperation::Maximum,
        MinMaxOperation::Minimum,
        MinMaxOperation::MaximumNumber,
        MinMaxOperation::MinimumNumber,
    ];
    const SINGLES: [u32; 7] = [
        0x7f80_0000,
        0xff80_0000,
        0x3fc0_0000,
        0xc000_0000,
        0,
        0x8000_0000,
        0x7f7f_ffff,
    ];
    const DOUBLES: [u64; 7] = [
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x3ff8_0000_0000_0000,
        0xc000_0000_0000_0000,
        0,
        0x8000_0000_0000_0000,
        0x7fef_ffff_ffff_ffff,
    ];

    #[derive(Clone, Copy)]
    enum Form {
        Binary,
        Scalar,
        Pairwise,
        PairwiseScalar,
        Reduction,
    }

    /// The `form` word for `operation` with Vd = 0, Vn = 1, Vm = 2.
    fn word(form: Form, operation: MinMaxOperation, double: bool) -> u32 {
        let minimum = matches!(
            operation,
            MinMaxOperation::Minimum | MinMaxOperation::MinimumNumber
        );
        let number = matches!(
            operation,
            MinMaxOperation::MaximumNumber | MinMaxOperation::MinimumNumber
        );
        let registers = 2 << 16 | 1 << 5;
        match form {
            Form::Binary | Form::Pairwise => {
                let base: u32 = if matches!(form, Form::Binary) {
                    0x4e20_f400
                } else {
                    0x6e20_f400
                };
                let base = if number { base & !0x3000 } else { base };
                base | u32::from(minimum) << 23 | u32::from(double) << 22 | registers
            }
            Form::Scalar => {
                let opcode = match (minimum, number) {
                    (false, false) => 0x4800,
                    (true, false) => 0x5800,
                    (false, true) => 0x6800,
                    (true, true) => 0x7800,
                };
                0x1e20_0000 | opcode | u32::from(double) << 22 | registers
            }
            Form::PairwiseScalar | Form::Reduction => {
                let base: u32 = if matches!(form, Form::Reduction) {
                    0x6e30_f800
                } else {
                    0x7e30_f800
                };
                let base = if number { base & !0x3000 } else { base };
                base | u32::from(minimum) << 23 | u32::from(double) << 22 | 1 << 5
            }
        }
    }

    fn targets() -> Vec<TargetCpu> {
        let host = TargetCpu::detect();
        let mut targets: Vec<TargetCpu> = [
            TargetCpu::Baseline,
            TargetCpu::X86_64_V2,
            TargetCpu::X86_64_V3,
        ]
        .into_iter()
        .filter(|target| host.supports(*target))
        .collect();
        targets.push(host);
        targets
    }

    fn compile(word: u32, target: TargetCpu) -> Vec<u8> {
        let source = [word, 0xd65f_03c0].map(u32::to_le_bytes).concat();
        CompilationPlan::new(&source, PC, &Options::new(BlockProfile::ORDINARY, target))
            .unwrap()
            .compile()
            .unwrap()
            .native
            .x86_64_code
    }

    fn lanes(vector: [u64; 2], double: bool) -> Vec<u64> {
        if double {
            vector.to_vec()
        } else {
            vector
                .iter()
                .flat_map(|limb| [limb & 0xffff_ffff, limb >> 32])
                .collect()
        }
    }

    fn pack(values: &[u64], double: bool) -> [u64; 2] {
        let mut vector = [0u64; 2];
        let per_limb = if double { 1 } else { 2 };
        for (lane, value) in values.iter().enumerate() {
            vector[lane / per_limb] |= value << (64 / per_limb * (lane % per_limb));
        }
        vector
    }

    fn expected(
        form: Form,
        operation: MinMaxOperation,
        double: bool,
        fpcr: u32,
        n: [u64; 2],
        m: [u64; 2],
    ) -> [u64; 2] {
        let format = if double {
            Format::Double
        } else {
            Format::Single
        };
        let lane = |left: u64, right: u64| {
            let outcome = evaluate(format, operation, fpcr, left, right).unwrap();
            assert_eq!(outcome.exceptions, 0);
            outcome.bits
        };
        let (n, m) = (lanes(n, double), lanes(m, double));
        let values: Vec<u64> = match form {
            Form::Binary => n.iter().zip(&m).map(|(&a, &b)| lane(a, b)).collect(),
            Form::Scalar => [lane(n[0], m[0])].to_vec(),
            Form::Pairwise => n
                .chunks(2)
                .chain(m.chunks(2))
                .map(|pair| lane(pair[0], pair[1]))
                .collect(),
            Form::PairwiseScalar => [lane(n[0], n[1])].to_vec(),
            Form::Reduction => [lane(lane(n[0], n[1]), lane(n[2], n[3]))].to_vec(),
        };
        pack(&values, double)
    }

    #[test]
    fn infinite_lanes_complete_inline_and_match_the_reference() {
        let forms: [(Form, bool); 9] = [
            (Form::Binary, false),
            (Form::Binary, true),
            (Form::Scalar, false),
            (Form::Scalar, true),
            (Form::Pairwise, false),
            (Form::Pairwise, true),
            (Form::PairwiseScalar, false),
            (Form::PairwiseScalar, true),
            (Form::Reduction, false),
        ];
        for target in targets() {
            for (form, double) in forms {
                for operation in OPERATIONS {
                    let word = word(form, operation, double);
                    let code = compile(word, target);
                    for fpcr in [0, FPCR_AH] {
                        for case in 0..343usize {
                            let pick = |lane: usize| {
                                let index = (case / 7usize.pow(lane as u32 % 3) + lane) % 7;
                                if double {
                                    DOUBLES[index]
                                } else {
                                    u64::from(SINGLES[index])
                                }
                            };
                            let count = if double { 2 } else { 4 };
                            let n: Vec<u64> = (0..count).map(pick).collect();
                            let m: Vec<u64> = (count..2 * count).map(pick).collect();
                            let (n, m) = (pack(&n, double), pack(&m, double));
                            let mut initial = GuestState {
                                fpcr,
                                ..GuestState::default()
                            };
                            initial.x[30] = RETURN;
                            initial.v[1] = n;
                            initial.v[2] = m;
                            initial.v[0] = [u64::MAX; 2];
                            let mut actual = initial.clone();
                            let exit = run(&code, &mut actual);
                            let context =
                                alloc::format!("{word:08x} {n:x?} {m:x?} {fpcr:#x} {target:?}");
                            assert_eq!(exit, RETURN, "{context}");
                            let mut want = initial.clone();
                            want.v[0] = expected(form, operation, double, fpcr, n, m);
                            assert_eq!(actual, want, "{context}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn nan_and_subnormal_lanes_still_exit() {
        for target in targets() {
            for operation in OPERATIONS {
                let code = compile(word(Form::Binary, operation, false), target);
                for special in [0x7fc0_0000u64, 0x0000_0001] {
                    let mut state = GuestState::default();
                    state.x[30] = RETURN;
                    state.v[1] = [0x7f80_0000 | special << 32, 0x3f80_0000];
                    state.v[2] = [0xff80_0000_ff80_0000, 0x3f80_0000];
                    let initial = state.clone();
                    assert_eq!(run(&code, &mut state), PC.0);
                    assert_eq!(state, initial);
                }
            }
        }
    }
}
