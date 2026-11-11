//! Leaf compilation with an execution context and a scalable specialization.
use crate::x86_64::asm::Code;

mod admission;
pub mod block;
pub mod debug_movement;
mod decoded;
mod prefix;
mod profile;

use admission::{decode, decode_recording_features};
pub(crate) use decoded::{Decoded, ordinary_permitted};
pub use profile::ScalableProfile;

use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu,
    aarch64::{
        Instruction, Operation,
        scalable::{
            execution::{InstructionExecutionRequirements, ScalableExecutionRequirements},
            features::FeatureRequirement,
        },
    },
    context::memory::MemoryRequirements,
    x86_64,
};
use alloc::{collections::BTreeMap, vec, vec::Vec};

pub const PROFILE_ID: &str = "apple-sme2-streaming-v1";
pub const DECLARED_PROFILE_ID: &str = "sme-streaming-v2";
const INSTRUCTION_BYTES: usize = size_of::<u32>();
/// `push r15; mov r15, rsi`, the exits' stack pointer
/// (`x86_64::chain::EXIT_RSP_STORE`), `call body; pop r15; ret`: the context
/// ABI's entry, which keeps the context pointer in R15 across the body.
pub const CONTEXT_WRAPPER_BYTES: usize = 13 + x86_64::chain::EXIT_RSP_STORE.len();

pub(crate) fn context_wrapper() -> Code {
    use x86_64::asm::{Gpr, Size};
    let mut code = Code::new();
    let mut asm = code.asm();
    asm.push(Gpr::R15);
    asm.mov(Size::Qword, Gpr::R15, Gpr::Rsi);
    asm.fixed(&x86_64::chain::EXIT_RSP_STORE);
    let body = asm.call();
    asm.pop(Gpr::R15);
    asm.ret();
    asm.bind(body);
    debug_assert_eq!(code.len(), CONTEXT_WRAPPER_BYTES);
    code
}

fn emit_decoded(
    code: &mut Code,
    pc: GuestAddress,
    instruction: Decoded,
    profile: ScalableProfile,
    target: TargetCpu,
    fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
) -> Result<(), CompileError> {
    match instruction {
        Decoded::SharedMemory(_) | Decoded::Exclusive(_) => {
            return Err(CompileError::new(
                crate::CompileErrorKind::ExclusiveServiceNotRequested,
            ));
        }
        Decoded::MemoryScalar(_) => {
            return Err(CompileError::new(
                crate::CompileErrorKind::ScalarMemoryServiceNotRequested,
            ));
        }
        Decoded::MemoryPair(_) | Decoded::MemoryFixed(_) | Decoded::PrefetchHint => {
            return Err(CompileError::new(
                crate::CompileErrorKind::FixedMemoryServiceNotRequested,
            ));
        }
        Decoded::Address(operand) => {
            x86_64::sve::address::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::Ordinary(instruction) => {
            x86_64::emit_instruction(
                code,
                &instruction,
                fixups,
                target,
                x86_64::MemoryChecks::DEFAULT,
            );
        }
        Decoded::IntegerDot(operand) => {
            if !x86_64::sve::dot::emit_integer(code, &operand, profile.vector_length(), target) {
                return Err(
                    CompileError::new(crate::CompileErrorKind::StreamingDotOperands).at(pc),
                );
            }
        }
        Decoded::IntegerPredicateMove(operand) => {
            x86_64::sve::integer_predicate_move::emit(
                code,
                operand,
                profile.vector_length(),
                target,
            );
        }
        Decoded::IntegerBits(operand) => {
            x86_64::sve::integer_bits::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::IntegerLogic(operand) => {
            x86_64::sve::integer_logic::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::IntegerComparison(operand) => {
            x86_64::sve::integer_comparison::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::IntegerArithmetic(operand) => {
            x86_64::sve::integer_arithmetic::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::IntegerSaturation(operand) => {
            x86_64::sve::integer_saturation::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::RearrangeWiden(operand) => {
            x86_64::sve::rearrange_widen::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::Shifts(operand) => {
            x86_64::sve::shifts::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::ShiftsNarrow(operand) => {
            x86_64::sve::shifts_narrow::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::Sign(operand) => {
            x86_64::sve::sign::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::IntegerProducts(operand) => {
            x86_64::sve::integer_products::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::SmeIntegerDots(operand) => {
            x86_64::sme::integer_dots::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::RearrangeExtract(operand) => {
            x86_64::sve::rearrange_extract::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::FloatingCopy(operand) => {
            x86_64::sve::floating_copy::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::PredicateGeneration(operand) => {
            x86_64::sve::predicate_generation::emit(
                code,
                &operand,
                profile.vector_length(),
                target,
            );
        }
        Decoded::PredicateLogic(operand) => {
            x86_64::sve::predicate_logic::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::Reductions(operand) => {
            x86_64::sve::reductions::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::Rearrange(operand) => {
            x86_64::sve::rearrange::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::SmeIntegerVector(operand) => {
            x86_64::sme::integer_vector::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::SmeMovement(operand) => {
            x86_64::sme::movement::emit(code, &operand, profile.vector_length(), target)
                .map_err(|reason| CompileError::from(reason).at(pc))?;
        }
        Decoded::SmeLutV2(operand) => {
            x86_64::sme::tables::emit_lut_v2(code, &operand, profile.vector_length(), target);
        }
        Decoded::SmeTables(operand) => {
            x86_64::sme::tables::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::SveTables(operand) => {
            x86_64::sve::tables::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::SmeIntegerMatrix(operand) => {
            x86_64::sme::integer_matrix::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::SmeMemory(operand) => {
            x86_64::sme::memory::emit(code, &operand, profile.vector_length(), target, pc.0)
                .map_err(|reason| CompileError::from(reason).at(pc))?;
        }
        Decoded::MemoryLoad(operand) => {
            x86_64::sve::memory_load::emit(code, operand, profile.vector_length(), target, pc.0);
        }
        Decoded::MemoryMulti(operand) => {
            x86_64::sve::memory_multi::emit(code, &operand, profile.vector_length(), target, pc.0);
        }
        Decoded::MemoryStore(operand) => {
            x86_64::sve::memory_store::emit(code, &operand, profile.vector_length(), target, pc.0);
        }
        Decoded::MemoryStructure(operand) => {
            x86_64::sve::memory_structure::emit(
                code,
                &operand,
                profile.vector_length(),
                target,
                pc.0,
            );
        }
        Decoded::Length(operand) => {
            x86_64::sme::length::emit(code, &operand, profile.vector_length());
        }
    }
    Ok(())
}

struct DecodedLeafInstruction {
    pc: GuestAddress,
    instruction: Decoded,
    feature_clauses: Vec<FeatureRequirement>,
}

fn decode_leaf(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<Vec<DecodedLeafInstruction>, CompileError> {
    if source.is_empty()
        || !source.len().is_multiple_of(INSTRUCTION_BYTES)
        || !base.0.is_multiple_of(INSTRUCTION_BYTES as u64)
    {
        return Err(CompileError::new(
            crate::CompileErrorKind::InvalidSourceLayout,
        ));
    }
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < source.len() {
        if let Some(pair) = prefix::decode_pair(source, offset, base, profile, target)? {
            instructions.push(DecodedLeafInstruction {
                pc: pair.prefix_pc,
                instruction: Decoded::IntegerLogic(pair.prefix),
                feature_clauses: vec![pair.prefix_features],
            });
            instructions.push(DecodedLeafInstruction {
                pc: pair.follower_pc,
                instruction: pair.follower,
                feature_clauses: pair.follower_features,
            });
            offset += prefix::PAIR_BYTES;
            continue;
        }
        let pc = GuestAddress(
            base.0
                .checked_add(offset as u64)
                .ok_or_else(|| CompileError::new(crate::CompileErrorKind::GuestAddressOverflow))?,
        );
        let word = u32::from_le_bytes(
            source[offset..offset + INSTRUCTION_BYTES]
                .try_into()
                .expect("checked leaf instruction alignment"),
        );
        let mut feature_clauses = Vec::new();
        let instruction =
            decode_recording_features(pc, word, profile, target, &mut feature_clauses)?;
        instructions.push(DecodedLeafInstruction {
            pc,
            instruction,
            feature_clauses,
        });
        offset += INSTRUCTION_BYTES;
    }
    if !matches!(
        instructions.last(),
        Some(DecodedLeafInstruction {
            instruction: Decoded::Ordinary(Instruction {
                operation: Operation::Return,
                ..
            }),
            ..
        })
    ) {
        return Err(CompileError::new(
            crate::CompileErrorKind::MissingLeafReturn,
        ));
    }
    for DecodedLeafInstruction {
        pc,
        instruction: decoded,
        ..
    } in &instructions
    {
        let Decoded::Ordinary(instruction) = decoded else {
            continue;
        };
        let target = match &instruction.operation {
            Operation::Branch { target }
            | Operation::BranchCondition { target, .. }
            | Operation::BranchZero { target, .. }
            | Operation::BranchBit { target, .. } => Some(*target),
            _ => None,
        };
        if let Some(target) = target
            && instructions
                .binary_search_by_key(&target.0, |instruction| instruction.pc.0)
                .is_err()
        {
            return Err(
                CompileError::new(crate::CompileErrorKind::UnresolvedDirectTarget { target })
                    .at(*pc),
            );
        }
    }
    Ok(instructions)
}

/// A validated context leaf: one decode of the whole body, from which its
/// service and execution requirements and its code all derive. No
/// caller-supplied execution metadata or service requirements are accepted.
pub struct Leaf {
    instructions: Vec<DecodedLeafInstruction>,
    memory_requirements: MemoryRequirements,
    profile: ScalableProfile,
    target: TargetCpu,
    source_bytes: usize,
}

impl Leaf {
    /// Decode a two-argument context leaf ending in RET X30. The runtime
    /// validates `profile` against its state before calling it.
    pub(crate) fn decode(
        source: &[u8],
        base: GuestAddress,
        profile: ScalableProfile,
        target: TargetCpu,
    ) -> Result<Self, CompileError> {
        let instructions = decode_leaf(source, base, profile, target)?;
        let memory_requirements = instructions.iter().try_fold(
            MemoryRequirements::default(),
            |requirements, decoded| {
                requirements
                    .merge(decoded.instruction.memory_requirements())
                    .ok_or_else(|| {
                        CompileError::new(crate::CompileErrorKind::ConflictingMemoryRequirements)
                            .at(decoded.pc)
                    })
            },
        )?;
        Ok(Self {
            instructions,
            memory_requirements,
            profile,
            target,
            source_bytes: source.len(),
        })
    }

    pub(crate) const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    /// The whole body's service requirements; empty for a leaf with no
    /// memory access.
    pub(crate) const fn memory_requirements(&self) -> MemoryRequirements {
        self.memory_requirements
    }

    /// Each instruction's scalable execution requirements, in source order.
    pub(crate) fn execution_requirements(&self) -> ScalableExecutionRequirements {
        ScalableExecutionRequirements::new(
            self.instructions
                .iter()
                .map(|decoded| {
                    InstructionExecutionRequirements::new(
                        decoded.pc,
                        decoded.feature_clauses.clone(),
                        decoded.instruction.execution_access_requirements(),
                        decoded.instruction.guest_memory_quantity(),
                    )
                })
                .collect(),
        )
    }

    pub(crate) fn emit(self) -> Result<NativeBlock, CompileError> {
        let mut code = context_wrapper();
        let mut source_map = Vec::with_capacity(self.instructions.len());
        let mut fixups = Vec::new();
        for DecodedLeafInstruction {
            pc, instruction, ..
        } in self.instructions
        {
            source_map.push((pc, code.len()));
            emit_decoded(
                &mut code,
                pc,
                instruction,
                self.profile,
                self.target,
                &mut fixups,
            )?;
        }
        let offsets: BTreeMap<_, _> = source_map
            .iter()
            .map(|(pc, offset)| (pc.0, *offset))
            .collect();
        for (pc, target, displacement) in fixups {
            let destination = offsets.get(&target.0).ok_or_else(|| {
                CompileError::new(crate::CompileErrorKind::UnresolvedDirectTarget { target }).at(pc)
            })?;
            let relative =
                i32::try_from(*destination as i128 - (displacement + size_of::<i32>()) as i128)
                    .map_err(|_| {
                        CompileError::new(crate::CompileErrorKind::NativeBranchOverflow)
                    })?;
            code.patch(displacement, relative.to_le_bytes());
        }
        Ok(NativeBlock {
            x86_64_code: code.into_bytes(),
            source_map,
        })
    }
}

#[cfg(test)]
mod tests;
