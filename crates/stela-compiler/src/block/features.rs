//! Guest services a compiled function provides, and the ABI identity derived
//! from them.
use super::CheckedMemoryProfile;
use crate::CompileError;
use alloc::string::String;
use serde::{Serialize, Serializer, ser::SerializeSeq};

/// Shared by every compiled function; the features follow it in the identity.
const ABI_PREFIX: &str = "x86_64-sysv-guest-state-v14";

/// A set of guest services. Each member admits the instructions that need the
/// service, as runtime exits or native completions, and names itself in the
/// ABI identity.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Features(u16);

impl Features {
    pub const NONE: Self = Self(0);
    /// Software pointer authentication through helper exits. Keys and the PAuth
    /// version are chosen at run time, so cached code contains neither.
    pub const POINTER_AUTHENTICATION: Self = Self(1 << 0);
    /// CNTVCT_EL0 reads and ISB through the clock exit.
    pub const CLOCK: Self = Self(1 << 1);
    /// Thread-register reads and writes through the thread exit.
    pub const THREAD_REGISTERS: Self = Self(1 << 2);
    /// Apple AMX instructions through the AMX exit, against per-thread or per-PE
    /// state.
    pub const AMX: Self = Self(1 << 3);
    /// Restricted context-independent prefixes and checked System exits. This
    /// identifies a service boundary, not CPU feature availability.
    pub const SYSTEM: Self = Self(1 << 4);
    /// System-register accesses through the System exit.
    pub const SYSTEM_REGISTERS: Self = Self(1 << 5);
    /// The system-mode engine: guest VAs are native addresses through shadow
    /// paging, `GuestState` is exact at every instruction boundary, and every
    /// System-class instruction exits with kind 11. Other PEs run concurrently,
    /// so atomics are locked and barriers fence.
    pub const FULL_SYSTEM: Self = Self(1 << 6);
    /// Non-faulting self-loops stay resident, counted by a
    /// [`super::loop_budget::LoopBudget`].
    pub const RESIDENT_LOOPS: Self = Self(1 << 7);
    /// The two-argument entry with an [`crate::context::ExecutionContext`] in
    /// RSI, kept in R15, and a scalable specialization.
    pub const CONTEXT: Self = Self(1 << 8);
    /// The function returns at the guest's RET X30 instead of exiting to the
    /// dispatcher.
    pub const LEAF: Self = Self(1 << 9);

    /// The system-mode engine's services.
    pub const SYSTEM_MODE: Self = Self::FULL_SYSTEM
        .union(Self::SYSTEM)
        .union(Self::SYSTEM_REGISTERS)
        .union(Self::POINTER_AUTHENTICATION)
        .union(Self::AMX);
    /// The process helpers a checked-memory block can call.
    pub const PROCESS_HELPERS: Self = Self::POINTER_AUTHENTICATION
        .union(Self::CLOCK)
        .union(Self::THREAD_REGISTERS);

    const NAMES: [(Self, &'static str); 10] = [
        (Self::CONTEXT, "context"),
        (Self::POINTER_AUTHENTICATION, "pointer-authentication"),
        (Self::CLOCK, "clock"),
        (Self::THREAD_REGISTERS, "thread-registers"),
        (Self::AMX, "amx"),
        (Self::SYSTEM, "system"),
        (Self::SYSTEM_REGISTERS, "system-registers"),
        (Self::FULL_SYSTEM, "full-system"),
        (Self::RESIDENT_LOOPS, "resident-loops"),
        (Self::LEAF, "leaf"),
    ];

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .into_iter()
            .filter(move |(feature, _)| self.contains(*feature))
            .map(|(_, name)| name)
    }
}

impl core::ops::BitOr for Features {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

impl core::fmt::Debug for Features {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Features(")?;
        for (index, name) in self.names().enumerate() {
            if index > 0 {
                f.write_str("|")?;
            }
            f.write_str(name)?;
        }
        f.write_str(")")
    }
}

impl Serialize for Features {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut names = serializer.serialize_seq(None)?;
        for name in self.names() {
            names.serialize_element(name)?;
        }
        names.end()
    }
}

/// The services a compiled function provides and how its memory accesses are
/// checked. Without checked memory, accesses go directly to guest RAM.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BlockProfile {
    features: Features,
    checked: Option<CheckedMemoryProfile>,
}

impl BlockProfile {
    /// A direct-RAM block that exits to the dispatcher at every transfer.
    pub const ORDINARY: Self = Self::new(Features::NONE);

    pub const fn new(features: Features) -> Self {
        Self {
            features,
            checked: None,
        }
    }
    /// The same services with every memory access through the checked memory
    /// service.
    pub const fn with_checked_memory(self, checked: CheckedMemoryProfile) -> Self {
        Self {
            checked: Some(checked),
            ..self
        }
    }
    pub const fn features(self) -> Features {
        self.features
    }
    /// Whether the profile provides every service in `features`.
    pub const fn has(self, features: Features) -> bool {
        self.features.contains(features)
    }
    pub const fn checked_memory(self) -> Option<CheckedMemoryProfile> {
        self.checked
    }

    /// The identity cached code is keyed by: one name per feature, then the
    /// checked memory profile.
    pub fn abi(self) -> String {
        let mut abi = String::from(ABI_PREFIX);
        abi.push_str(if self.has(Features::LEAF) {
            "-leaf"
        } else {
            "-block-exit"
        });
        for name in self.features.difference(Features::LEAF).names() {
            abi.push('+');
            abi.push_str(name);
        }
        if let Some(checked) = self.checked {
            abi.push('+');
            abi.push_str(checked.id());
        }
        abi
    }

    /// Refuse the combinations no emitter implements.
    pub fn validate(self) -> Result<(), CompileError> {
        use Features as F;
        let features = self.features;
        let direct = self.checked.is_none();
        let valid = if features.contains(F::LEAF) || features.contains(F::CONTEXT) {
            direct && features.difference(F::LEAF | F::CONTEXT).is_empty()
        } else if features.contains(F::FULL_SYSTEM) {
            // The shared full-system lane checks SP alignment only.
            features == F::SYSTEM_MODE
                && !matches!(self.checked, Some(CheckedMemoryProfile::AddressChecks(_)))
        } else if features.contains(F::SYSTEM) {
            direct
                && features
                    .difference(F::SYSTEM | F::SYSTEM_REGISTERS)
                    .is_empty()
        } else if features.contains(F::RESIDENT_LOOPS) {
            direct && features == F::RESIDENT_LOOPS
        } else if !direct {
            features.is_empty() || features == F::PROCESS_HELPERS
        } else {
            // The clock exit shares the PAuth helper interface, and AMX state is
            // per guest thread.
            features.difference(F::PROCESS_HELPERS | F::AMX).is_empty()
                && (!features.contains(F::CLOCK) || features.contains(F::POINTER_AUTHENTICATION))
                && features.contains(F::THREAD_REGISTERS) == features.contains(F::AMX)
        };
        if valid {
            Ok(())
        } else {
            Err(CompileError::new(
                crate::CompileErrorKind::ProfileNotImplemented { profile: self },
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use CheckedMemoryProfile::{SpAlignmentDisabled, SpAlignmentEnabled};
    use Features as F;

    #[test]
    fn the_abi_names_each_feature_and_the_checked_profile() {
        assert_eq!(
            BlockProfile::ORDINARY.abi(),
            "x86_64-sysv-guest-state-v14-block-exit"
        );
        assert_eq!(
            BlockProfile::new(F::LEAF | F::CONTEXT).abi(),
            "x86_64-sysv-guest-state-v14-leaf+context"
        );
        assert_eq!(
            BlockProfile::new(F::PROCESS_HELPERS)
                .with_checked_memory(SpAlignmentEnabled)
                .abi(),
            "x86_64-sysv-guest-state-v14-block-exit+pointer-authentication+clock\
             +thread-registers+checked-gpr-memory-sa0-on-normal-wb-v4"
        );
    }

    #[test]
    fn profiles_have_distinct_abis() {
        let mut profiles = alloc::vec![
            BlockProfile::ORDINARY,
            BlockProfile::new(F::LEAF),
            BlockProfile::new(F::LEAF | F::CONTEXT),
            BlockProfile::new(F::CONTEXT),
            BlockProfile::new(F::RESIDENT_LOOPS),
            BlockProfile::new(F::SYSTEM),
            BlockProfile::new(F::SYSTEM | F::SYSTEM_REGISTERS),
            BlockProfile::new(F::SYSTEM_MODE),
            BlockProfile::new(F::POINTER_AUTHENTICATION),
            BlockProfile::new(F::POINTER_AUTHENTICATION | F::CLOCK),
            BlockProfile::new(F::THREAD_REGISTERS | F::AMX),
            BlockProfile::new(F::POINTER_AUTHENTICATION | F::THREAD_REGISTERS | F::AMX),
            BlockProfile::new(F::PROCESS_HELPERS | F::AMX),
        ];
        for checked in [SpAlignmentEnabled, SpAlignmentDisabled] {
            profiles.push(BlockProfile::ORDINARY.with_checked_memory(checked));
            profiles.push(BlockProfile::new(F::PROCESS_HELPERS).with_checked_memory(checked));
            profiles.push(BlockProfile::new(F::SYSTEM_MODE).with_checked_memory(checked));
        }
        let mut abis = alloc::collections::BTreeSet::new();
        for profile in &profiles {
            assert_eq!(profile.validate(), Ok(()), "{profile:?}");
            assert!(abis.insert(profile.abi()), "{profile:?}");
        }
    }

    #[test]
    fn combinations_without_an_emitter_are_refused() {
        for profile in [
            BlockProfile::new(F::CLOCK),
            BlockProfile::new(F::THREAD_REGISTERS),
            BlockProfile::new(F::AMX),
            BlockProfile::new(F::SYSTEM_REGISTERS),
            BlockProfile::new(F::FULL_SYSTEM),
            BlockProfile::new(F::LEAF | F::POINTER_AUTHENTICATION),
            BlockProfile::new(F::RESIDENT_LOOPS | F::POINTER_AUTHENTICATION),
            BlockProfile::new(F::SYSTEM | F::POINTER_AUTHENTICATION),
            BlockProfile::new(F::POINTER_AUTHENTICATION).with_checked_memory(SpAlignmentEnabled),
            BlockProfile::new(F::LEAF).with_checked_memory(SpAlignmentEnabled),
            BlockProfile::new(F::SYSTEM).with_checked_memory(SpAlignmentEnabled),
        ] {
            assert!(profile.validate().is_err(), "{profile:?}");
        }
    }
}
