// SPDX-License-Identifier: GPL-2.0-only
//! Pure native-time policy and calibration arithmetic. Rules follow pinned Linux
//! 7.2.12 cc9de5d4b5ab6459f5774946aa3195ad51236fa8 arch/x86/kernel/{tsc,tsc_sync,hpet}.c
//! and arch/x86/include/asm/tsc.h. These values grant no CPU, clock, register,
//! mapping, lifecycle, synchronization or interrupt permission. Native admission
//! must observe the real owner/controls, reliability and progress.
mod calibration;
mod minimum;
pub use minimum::LowerScale;
mod features;
mod measurement;
mod rate;
mod reference;
pub use rate::NominalRate;
pub use reference::{Calibrated, Measured, Reference, WINDOW_NS, Window, measure, settle};
mod sequence;
pub mod sync;
pub use calibration::{RateWindow, RationalRate, ReferenceScale, Sample, wrapped_delta};
pub use features::{
    CounterPolicy, Deadline, HpetPowerConstraint, RateRequirement, Reliability, Serialization,
    counter_policy, deadline_policy, hpet_power_constraint,
};
pub use measurement::{Calibration, WindowEvidence, calibrate_hpet};
pub use sequence::CounterSequence;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MalformedCapture,
    MissingCpuid(u32),
    DuplicateCpuid(u32),
    MissingMsr(u32),
    DuplicateMsr(u32),
    TscUnavailable,
    InvariantUnavailable,
    HypervisorContractRequired,
    InvalidPackageCount,
    Pc10StopsHpet,
    InvalidRate,
    InvalidMask,
    NoProgress,
    Backwards,
    Disturbed,
    Overflow,
    InconsistentRate,
    AdjustmentChanged,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedCapture => f.write_str("the CPU capture is malformed"),
            Self::MissingCpuid(leaf) => write!(f, "CPUID leaf {leaf:#x} was not captured"),
            Self::DuplicateCpuid(leaf) => write!(f, "CPUID leaf {leaf:#x} was captured twice"),
            Self::MissingMsr(msr) => write!(f, "MSR {msr:#x} was not captured"),
            Self::DuplicateMsr(msr) => write!(f, "MSR {msr:#x} was captured twice"),
            Self::TscUnavailable => f.write_str("the CPU has no time-stamp counter"),
            Self::InvariantUnavailable => {
                f.write_str("the time-stamp counter does not run at a constant rate")
            }
            Self::HypervisorContractRequired => {
                f.write_str("the hypervisor does not promise a stable time-stamp counter")
            }
            Self::InvalidPackageCount => f.write_str("the CPU package count is not valid"),
            Self::Pc10StopsHpet => f.write_str("the HPET stops in the PC10 power state"),
            Self::InvalidRate => f.write_str("the reference timer's rate is not valid"),
            Self::InvalidMask => f.write_str("the reference timer's counter width is not valid"),
            Self::NoProgress => f.write_str("the reference timer did not advance"),
            Self::Backwards => f.write_str("the reference timer went backwards"),
            Self::Disturbed => f.write_str("every measurement window was interrupted"),
            Self::Overflow => f.write_str("the measurement overflowed"),
            Self::InconsistentRate => f.write_str("the counter's rate changed between readings"),
            Self::AdjustmentChanged => f.write_str("the counter's adjustment changed meanwhile"),
        }
    }
}
#[cfg(test)]
mod tests;
