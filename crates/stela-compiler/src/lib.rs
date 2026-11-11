//! Ahead-of-time translation of ARM64 code to native x86-64.
//! Unsupported instructions are compile errors; there is no interpreter fallback.
#![no_std]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

use alloc::vec::Vec;
pub mod aarch64;
pub mod amx;
pub mod block;
pub mod context;
mod error;
pub use error::{
    CompileError, CompileErrorKind, EncodingFamily, InstructionContext, RegionError,
    SmeMemoryError, SmeMovementError,
};
pub mod scalable_context;
mod state;
mod target;
#[cfg(test)]
mod testing;
pub mod wkdm;
pub mod x86_64;

pub use state::{Anchor, Anchors, ExitStack, GuestState, Limit, Place};
pub use target::{TargetCpu, TargetParseError};

use serde::{Deserialize, Serialize};

/// SHA-256 of the compiler sources; binds cached native code.
pub const SOURCE_SHA256: &str = env!("STELA_COMPILER_SOURCE_SHA256");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestAddress(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedReason {
    HostCapabilityRequired {
        address: GuestAddress,
        required: TargetCpu,
    },
    NumericalRuntimeRequired {
        address: GuestAddress,
    },
    Instruction {
        address: GuestAddress,
        encoding: u32,
    },
    PrivilegedOperation {
        address: GuestAddress,
    },
    PointerAuthentication {
        address: GuestAddress,
    },
    UnresolvedIndirectTarget {
        address: GuestAddress,
    },
    UnresolvedDirectTarget {
        address: GuestAddress,
        target: GuestAddress,
    },
    RuntimeGeneratedCode,
}

/// A lifted instruction must describe architectural effects, not just syntax.
pub trait Lifter {
    type Instruction;
    fn lift(&self, pc: GuestAddress, encoding: u32)
    -> Result<Self::Instruction, UnsupportedReason>;
}

/// Each native range keeps its guest address for faults and debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeBlock {
    pub x86_64_code: Vec<u8>,
    pub source_map: Vec<(GuestAddress, usize)>,
}

/// What [`compile`] translates for: the guest services and memory checks of a
/// [`block::BlockProfile`], the host's [`TargetCpu`], and the guest's scalable
/// and numerical specialization for the context ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    profile: block::BlockProfile,
    target: TargetCpu,
    scalable: Option<scalable_context::ScalableProfile>,
    numerical: aarch64::floating::features::NumericalFeatures,
    checks: x86_64::MemoryChecks,
    native: x86_64::NativeSystem,
}

impl Options {
    pub const fn new(profile: block::BlockProfile, target: TargetCpu) -> Self {
        Self {
            profile,
            target,
            scalable: None,
            numerical: aarch64::floating::features::NumericalFeatures::new(false, false, false),
            checks: x86_64::MemoryChecks::DEFAULT,
            native: x86_64::NativeSystem::NONE,
        }
    }
    /// The guest's scalable specialization, which [`block::Features::CONTEXT`]
    /// requires.
    pub const fn with_scalable(self, scalable: scalable_context::ScalableProfile) -> Self {
        Self {
            scalable: Some(scalable),
            ..self
        }
    }
    /// The numerical features a context block's numerical completions assume;
    /// they must match the guest identity the runtime completes with.
    pub const fn with_numerical_features(
        self,
        numerical: aarch64::floating::features::NumericalFeatures,
    ) -> Self {
        Self { numerical, ..self }
    }
    /// Emit the memory checks of the regime's SCTLR_ELx: the system-mode engine
    /// compiles separate blocks for SA (or SA0 at EL0) clear, where an access
    /// through a misaligned SP proceeds; for A set, where any access not
    /// aligned to its elements faults; and for nAA set, where an ordered access
    /// may cross its 16-byte granule. Only the direct system-mode profile admits
    /// checks other than [`x86_64::MemoryChecks::DEFAULT`], and a host without
    /// the capability an unchecked SP then needs refuses.
    pub const fn with_memory_checks(self, checks: x86_64::MemoryChecks) -> Self {
        Self { checks, ..self }
    }
    /// Complete a terminal DC ZVA or DC clean operation natively
    /// ([`x86_64::NativeSystem`]): the system-mode engine compiles separate
    /// blocks for the contexts where those operations neither trap nor are
    /// UNDEFINED. Only the direct system-mode profile admits them.
    pub const fn with_native_system(self, native: x86_64::NativeSystem) -> Self {
        Self { native, ..self }
    }

    pub const fn profile(&self) -> block::BlockProfile {
        self.profile
    }
    pub const fn target(&self) -> TargetCpu {
        self.target
    }
    pub const fn scalable(&self) -> Option<scalable_context::ScalableProfile> {
        self.scalable
    }
    pub const fn numerical_features(&self) -> aarch64::floating::features::NumericalFeatures {
        self.numerical
    }
    pub const fn memory_checks(&self) -> x86_64::MemoryChecks {
        self.checks
    }
    pub const fn native_system(&self) -> x86_64::NativeSystem {
        self.native
    }

    /// Refuse options no emitter implements.
    pub fn validate(&self) -> Result<(), CompileError> {
        use block::Features;
        self.profile.validate()?;
        let context = self.profile.has(Features::CONTEXT);
        if context != self.scalable.is_some() {
            return Err(CompileError::new(
                crate::CompileErrorKind::ProfileRequiresScalable {
                    profile: self.profile,
                    required: context,
                },
            ));
        }
        let system_mode = self.profile == block::BlockProfile::new(Features::SYSTEM_MODE);
        if self.checks != x86_64::MemoryChecks::DEFAULT && !system_mode {
            return Err(CompileError::new(
                crate::CompileErrorKind::MemoryChecksUnsupported {
                    profile: self.profile,
                },
            ));
        }
        if let Some(bytes) = self.native.zero_block {
            use x86_64::zero_block::{MAX_BYTES, MIN_BYTES};
            if !system_mode {
                return Err(CompileError::new(
                    crate::CompileErrorKind::NativeZeroBlockUnsupported {
                        profile: self.profile,
                    },
                ));
            }
            if !bytes.is_power_of_two() || !(MIN_BYTES..=MAX_BYTES).contains(&bytes) {
                return Err(CompileError::new(
                    crate::CompileErrorKind::InvalidZeroBlockSize { bytes },
                ));
            }
        }
        if (self.native.exclusive || !self.native.cache_clean.is_empty()) && !system_mode {
            return Err(CompileError::new(
                crate::CompileErrorKind::NativeCacheCleanUnsupported {
                    profile: self.profile,
                },
            ));
        }
        Ok(())
    }
}

/// Translate the guest code at `source`, whose first instruction is at
/// `base`, for `options`: one validated decode, then the emitters its
/// profile's features select. A block ends at its first transfer, trap or
/// runtime exit, or at the input boundary, and bytes after it are unconsumed;
/// a [`block::Features::LEAF`] function translates the whole input, which ends
/// in RET X30. Unknown semantics are compile errors.
pub fn compile(
    source: &[u8],
    base: GuestAddress,
    options: &Options,
) -> Result<block::CompiledBlock, CompileError> {
    block::CompilationPlan::new(source, base, options)?.compile()
}

pub trait Backend<I> {
    fn emit(&self, instructions: &[I]) -> Result<NativeBlock, UnsupportedReason>;
}

/// Platform adaptation is separate from instruction translation.
pub mod platform {
    #[derive(Debug)]
    pub enum Requirement {
        MachTraps,
        BsdSyscalls,
        ThreadState,
        ExceptionDelivery,
        VirtualMemory,
        DynamicLinking,
        KernelBoot,
        Interrupts,
        Graphics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::asm::Code;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn options_without_an_emitter_are_refused() {
        use aarch64::scalable::{ScalableMode, VectorLength};
        use block::{BlockProfile, Features};
        let scalable = scalable_context::ScalableProfile::new(
            VectorLength::from_bytes(16).unwrap(),
            ScalableMode::new(true, false),
        );
        let options = |features| Options::new(BlockProfile::new(features), TargetCpu::Baseline);
        let unaligned = x86_64::MemoryChecks {
            stack_alignment: false,
            ..x86_64::MemoryChecks::DEFAULT
        };
        let zero = |bytes| x86_64::NativeSystem {
            zero_block: Some(bytes),
            ..x86_64::NativeSystem::NONE
        };
        for valid in [
            options(Features::NONE),
            options(Features::LEAF),
            options(Features::CONTEXT).with_scalable(scalable),
            options(Features::SYSTEM_MODE).with_memory_checks(unaligned),
            options(Features::SYSTEM_MODE).with_native_system(zero(64)),
        ] {
            assert_eq!(valid.validate(), Ok(()), "{valid:?}");
        }
        for invalid in [
            options(Features::CONTEXT),
            options(Features::NONE).with_scalable(scalable),
            options(Features::NONE).with_memory_checks(unaligned),
            options(Features::NONE).with_native_system(zero(64)),
            options(Features::SYSTEM_MODE).with_native_system(zero(48)),
            options(Features::CLOCK),
        ] {
            assert!(invalid.validate().is_err(), "{invalid:?}");
            assert!(compile(&0xd65f_03c0_u32.to_le_bytes(), GuestAddress(0), &invalid).is_err());
        }
    }

    #[test]
    fn polynomial64_lowering_requires_independent_pclmul_and_selects_original_halves() {
        use x86_64::isa::SimdOpcode;
        let opcode = SimdOpcode::CarrylessMultiplyQword;
        assert_eq!(opcode.requires(), TargetCpu::Pclmulqdq);
        assert!(!TargetCpu::Sse42.supports(opcode.requires()));
        assert!(
            std::panic::catch_unwind(|| {
                opcode.register(&mut Code::new(), 0, 1, TargetCpu::Sse42);
            })
            .is_err()
        );
        for (word, immediate) in [(0x0ee2e020u32, 0x00), (0x4ee2e020, 0x11)] {
            let source: Vec<_> = [word, 0xd65f03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let baseline = crate::testing::leaf(&source, GuestAddress(0x1000)).unwrap();
            let sse42 =
                crate::testing::leaf_for(&source, GuestAddress(0x1000), TargetCpu::Sse42).unwrap();
            assert_eq!(baseline.x86_64_code, sse42.x86_64_code);
            let pclmul =
                crate::testing::leaf_for(&source, GuestAddress(0x1000), TargetCpu::Pclmulqdq)
                    .unwrap();
            let combined = crate::testing::leaf_for(
                &source,
                GuestAddress(0x1000),
                TargetCpu::Sse42.with_pclmulqdq(),
            )
            .unwrap();
            assert_eq!(pclmul.x86_64_code, combined.x86_64_code);
            assert!(
                pclmul
                    .x86_64_code
                    .windows(6)
                    .any(|bytes| bytes == [0x66, 0x0f, 0x3a, 0x44, 0xc1, immediate])
            );
            assert!(pclmul.x86_64_code.len() < baseline.x86_64_code.len());
            assert_eq!(pclmul.source_map.len(), baseline.source_map.len());
        }
        // Byte polynomial forms keep the lane-isolated SSE2 recipe.
        for word in [0x2e229c20u32, 0x0e22e020, 0x4e22e020] {
            let source: Vec<_> = [word, 0xd65f03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            assert_eq!(
                crate::testing::leaf(&source, GuestAddress(0x1000))
                    .unwrap()
                    .x86_64_code,
                crate::testing::leaf_for(&source, GuestAddress(0x1000), TargetCpu::Pclmulqdq)
                    .unwrap()
                    .x86_64_code,
            );
        }
    }
    #[test]
    fn ordered_load_host_requirements_gate_leaf_and_block_before_output() {
        for word in [0xc8dffc20_u32, 0xf8bfc020] {
            let source: Vec<u8> = [word, 0xd65f03c0]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            assert!(matches!(
                crate::testing::leaf(&source, GuestAddress(0))
                    .unwrap_err()
                    .kind,
                CompileErrorKind::Unsupported(UnsupportedReason::HostCapabilityRequired { .. })
            ));
            assert!(
                crate::testing::leaf_for(&source, GuestAddress(0), TargetCpu::AtomicLoad16).is_ok()
            );
            let blocked = crate::testing::block(&source, GuestAddress(0)).unwrap_err();
            assert!(matches!(
                blocked.kind,
                CompileErrorKind::Unsupported(UnsupportedReason::HostCapabilityRequired { .. })
            ));
            assert!(
                crate::testing::block_for(
                    &source,
                    GuestAddress(0),
                    block::BlockProfile::default(),
                    TargetCpu::AtomicLoad16
                )
                .is_ok()
            );
        }
        for word in [0xc8dfffe0_u32, 0xf8bfc3e0, 0x08dffc20, 0xc89ffc20] {
            let source: Vec<u8> = [word, 0xd65f03c0]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            assert!(crate::testing::leaf(&source, GuestAddress(0)).is_ok());
        }
    }

    #[test]
    fn pair_compare_exchange_requires_only_cx16_for_doubleword_pairs() {
        const CASP_WORD: u32 = 0x08207c82; // casp w0,w1,w2,w3,[x4]
        const CASP_DOUBLEWORD: u32 = 0x48207c82;
        const RET: u32 = 0xd65f03c0;
        for order in [0, 1 << 22, 1 << 15, (1 << 22) | (1 << 15)] {
            for (word, requires_cx16) in [(CASP_WORD, false), (CASP_DOUBLEWORD, true)] {
                let source: Vec<u8> = [word | order, RET]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect();
                for target in [
                    TargetCpu::Baseline,
                    TargetCpu::AtomicLoad16,
                    TargetCpu::Cx16,
                ] {
                    let permitted = !requires_cx16 || target.supports(TargetCpu::Cx16);
                    let leaf = crate::testing::leaf_for(&source, GuestAddress(0), target);
                    let block = crate::testing::block_for(
                        &source,
                        GuestAddress(0),
                        block::BlockProfile::default(),
                        target,
                    );
                    assert_eq!(leaf.is_ok(), permitted);
                    assert_eq!(block.is_ok(), permitted);
                    if !permitted {
                        assert!(matches!(
                            leaf.unwrap_err().kind,
                            CompileErrorKind::Unsupported(
                                UnsupportedReason::HostCapabilityRequired { .. }
                            )
                        ));
                        assert!(matches!(
                            block.unwrap_err().kind,
                            CompileErrorKind::Unsupported(
                                UnsupportedReason::HostCapabilityRequired { .. }
                            )
                        ));
                    } else {
                        const LOCK_CMPXCHG8B_R8: &[u8] = &[0xf0, 0x41, 0x0f, 0xc7, 0x08];
                        let uses_cx8 = leaf
                            .unwrap()
                            .x86_64_code
                            .windows(LOCK_CMPXCHG8B_R8.len())
                            .any(|body| body == LOCK_CMPXCHG8B_R8);
                        assert_eq!(uses_cx8, !requires_cx16 && target.supports(TargetCpu::Cx8));
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_unknown_instructions_bad_boundaries_and_address_overflow() {
        for words in [
            vec![],
            vec![0xd503201fu32],
            vec![0x14000002, 0xd65f03c0], // branch falls outside the region
            vec![0xf8800800, 0xd65f03c0], // reserved unprivileged prefetch neighbor
            vec![0xd65f0000],
        ] {
            let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            assert!(crate::testing::leaf(&bytes, GuestAddress(0)).is_err());
        }
        assert!(crate::testing::leaf(&[0, 0, 0], GuestAddress(0)).is_err());
        assert!(crate::testing::leaf(&0xd65f03c0u32.to_le_bytes(), GuestAddress(1)).is_err());
        let code: Vec<_> = [0xd503201fu32, 0xd65f03c0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert!(crate::testing::leaf(&code, GuestAddress(u64::MAX - 3)).is_err());
    }
}
