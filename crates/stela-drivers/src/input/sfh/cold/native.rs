// SPDX-License-Identifier: GPL-2.0-or-later
//! Retaining custody for the actual original SFH configuration/root and BAR.
use super::{Error, StopAttempt};
use crate::{
    Clock,
    bus::{
        mmio::owned::Mapping,
        pci::{Bar, requester::preparation::PreparingRequester},
    },
};
use alloc::boxed::Box;
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeError {
    Controller(Error),
    Power(crate::block::BlockError),
}

/// A plain account for the boot log.
impl core::fmt::Display for NativeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Controller(error) => error.fmt(f),
            Self::Power(error) => write!(f, "its power change failed: {error}"),
        }
    }
}

struct Resources {
    requester: PreparingRequester,
    mapping: Mapping,
    bar: Bar,
    clock: Clock,
}
/// Vendor containment may be prepared, but there is no native historical
/// notification/root-mode owner producer for this AMD profile. No method here
/// consumes a quiescence receipt or grants private-root DMA.
pub struct Original {
    resources: Option<Box<Resources>>,
    attempt: StopAttempt,
    attempted: bool,
    failure: Option<Error>,
}
impl Drop for Original {
    fn drop(&mut self) {
        core::mem::forget(self.resources.take());
    }
}
impl Original {
    /// # Safety
    /// These are the same actual exclusive original requester/root/config and
    /// reserved UC BAR2 epoch. Competing source/config/reset writers are kept
    /// excluded. No private domain/allocation/IRQ/work is admitted by this call.
    pub unsafe fn new(
        requester: PreparingRequester,
        mapping: Mapping,
        bar: Bar,
        clock: Clock,
    ) -> Self {
        Self {
            resources: Some(Box::new(Resources {
                requester,
                mapping,
                bar,
                clock,
            })),
            attempt: StopAttempt::new(),
            attempted: false,
            failure: None,
        }
    }
    /// The complete graph remains owned on error, success, unwind and Drop.
    /// Success is vendor sensor containment only, never a migration receipt.
    pub fn prepare(&mut self) -> Result<(), Error> {
        if self.attempted {
            return Err(self.failure.unwrap_or(Error::Terminal));
        }
        self.attempted = true;
        self.failure = Some(Error::Interrupted);
        let result = (|| {
            let r = self.resources.as_mut().unwrap();
            // SAFETY: construction retains this actual original epoch; borrowed
            // storage cannot escape or release either the root or BAR mapping.
            let mut registers = unsafe {
                super::super::pci::NativeRegisters::borrow_original(
                    r.requester.function_mut(),
                    &r.mapping,
                    r.bar,
                )
            }?;
            self.attempt.stop(&mut registers, &r.clock)?;
            Ok(())
        })();
        self.failure = result.as_ref().err().copied();
        result
    }
}
