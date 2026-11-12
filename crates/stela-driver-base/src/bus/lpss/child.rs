// SPDX-License-Identifier: GPL-2.0-only
//! DesignWare PIO composition and owning failures at every LPSS stage.
use super::*;
use crate::bus::i2c::{self, Bus, DesignWare, Operation, Timer};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachError {
    Platform(Error),
    I2c(i2c::Error),
}
/// A plain account for the boot log.
impl core::fmt::Display for AttachError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Platform(error) => error.fmt(f),
            Self::I2c(error) => write!(f, "its I2C controller failed: {error}"),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachStage {
    Validation,
    Claim,
    Platform,
    Child,
}

pub struct AttachFailure<T: Timer + 'static> {
    pub error: AttachError,
    stage: NativeStage<T>,
}
enum NativeStage<T: Timer + 'static> {
    Inputs {
        _inputs: ManuallyDrop<(StoppedRequester, Mapping, T)>,
    },
    Claim {
        _resources: ManuallyDrop<NativeResources>,
        _timer: ManuallyDrop<T>,
    },
    Platform {
        _owner: ControllerFailure<NativeRegisters>,
        _timer: ManuallyDrop<T>,
    },
    Child(I2cFailure<NativeRegisters, T>),
}
impl<T: Timer + 'static> AttachFailure<T> {
    pub fn stage(&self) -> AttachStage {
        match &self.stage {
            NativeStage::Inputs { .. } => AttachStage::Validation,
            NativeStage::Claim { .. } => AttachStage::Claim,
            NativeStage::Platform { .. } => AttachStage::Platform,
            NativeStage::Child(_) => AttachStage::Child,
        }
    }
    pub fn progress(&self) -> Option<i2c::Progress> {
        match &self.stage {
            NativeStage::Child(failure) => failure.progress(),
            _ => None,
        }
    }
}
impl<T: Timer + 'static> core::fmt::Debug for AttachFailure<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

pub struct I2cFailure<R: ChildAccess, T: Timer + 'static> {
    pub error: AttachError,
    stage: ChildStage<R, T>,
}
enum ChildStage<R: ChildAccess, T: Timer + 'static> {
    Engine(i2c::Failure<Child<R>, T>),
    Platform {
        _owner: ControllerFailure<R>,
        _timer: ManuallyDrop<T>,
    },
}
impl<R: ChildAccess, T: Timer + 'static> I2cFailure<R, T> {
    fn engine(failure: i2c::Failure<Child<R>, T>) -> Self {
        Self {
            error: AttachError::I2c(failure.error),
            stage: ChildStage::Engine(failure),
        }
    }
    pub fn progress(&self) -> Option<i2c::Progress> {
        match &self.stage {
            ChildStage::Engine(failure) => Some(failure.progress()),
            ChildStage::Platform { .. } => None,
        }
    }
}
impl<R: ChildAccess, T: Timer + 'static> core::fmt::Debug for I2cFailure<R, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("I2cFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// A disabled/reset owner produced only by acknowledged retirement.
pub struct Retired<R: Registers> {
    pub(super) registers: R,
}
impl Retired<NativeRegisters> {
    pub fn into_resources(self) -> NativeResources {
        self.registers.into_resources()
    }
}
struct Child<R: ChildAccess>(Controller<R>);
impl<R: ChildAccess> i2c::Registers for Child<R> {
    fn read32(&mut self, offset: usize) -> Result<u32, i2c::IoError> {
        self.0
            .registers
            .as_mut()
            .unwrap()
            .child_read32(offset)
            .map_err(i2c::IoError::Lpss)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), i2c::IoError> {
        self.0
            .registers
            .as_mut()
            .unwrap()
            .child_write32(offset, value)
            .map_err(i2c::IoError::Lpss)
    }
}
/// The PIO engine retains its graph unless shutdown acknowledges child disable
/// and platform reset. A read-only failure stage grants no owner extraction.
pub struct I2c<R: ChildAccess, T: Timer + 'static> {
    engine: DesignWare<Child<R>, T>,
}
impl<R: ChildAccess> Controller<R> {
    /// # Safety
    /// Counts are firmware/board-derived for this source profile's input clock,
    /// rise/fall/hold wiring and power epoch. Source clock metadata does not
    /// grant board timing. This is the sole child; no iDMA or IRQ is enabled.
    #[expect(
        clippy::result_large_err,
        reason = "the same controller and timer accompany failure without a new allocation"
    )]
    pub unsafe fn into_i2c<T: Timer + 'static>(
        self,
        timer: T,
        config: i2c::Config,
    ) -> Result<I2c<R, T>, I2cFailure<R, T>> {
        match DesignWare::new(Child(self), timer, config) {
            Ok(engine) => Ok(I2c { engine }),
            Err(failure) => Err(I2cFailure::engine(failure)),
        }
    }
}
impl<T: Timer + 'static> I2c<NativeRegisters, T> {
    /// # Safety
    /// NativeRegisters' stopped function, exclusive complete UC BAR0,
    /// power/clock/firmware epoch and this board's timing contracts all hold.
    #[expect(
        clippy::result_large_err,
        reason = "failure retains the original native graph and timer inline"
    )]
    pub unsafe fn attach_native(
        requester: StoppedRequester,
        mapping: Mapping,
        timer: T,
        config: i2c::Config,
    ) -> Result<Self, AttachFailure<T>> {
        let inputs = ManuallyDrop::new((requester, mapping, timer));
        if config.timeout_us == 0
            || config.recovery_timeout_us == 0
            || inputs.2.check_duration(config.timeout_us).is_err()
            || inputs.2.check_duration(config.recovery_timeout_us).is_err()
        {
            return Err(AttachFailure {
                error: AttachError::I2c(i2c::ErrorKind::InvalidConfiguration.into()),
                stage: NativeStage::Inputs { _inputs: inputs },
            });
        }
        let (requester, mapping, timer) = ManuallyDrop::into_inner(inputs);
        let timer = ManuallyDrop::new(timer);
        // SAFETY: caller supplies the same stopped requester and UC BAR0 grant;
        // claim parks both before callbacks while the original timer stays kept.
        let registers = match unsafe { NativeRegisters::claim(requester, mapping) } {
            Ok(registers) => registers,
            Err((error, resources)) => {
                return Err(AttachFailure {
                    error: AttachError::Platform(error),
                    stage: NativeStage::Claim {
                        _resources: ManuallyDrop::new(resources),
                        _timer: timer,
                    },
                });
            }
        };
        let owner = match Controller::initialize(registers) {
            Ok(owner) => owner,
            Err(failure) => {
                return Err(AttachFailure {
                    error: AttachError::Platform(failure.error),
                    stage: NativeStage::Platform {
                        _owner: failure,
                        _timer: timer,
                    },
                });
            }
        };
        // SAFETY: same board timing grant; DesignWare parks the complete child
        // and timer before its first callback. No callback occurs in the move.
        match unsafe { owner.into_i2c(ManuallyDrop::into_inner(timer), config) } {
            Ok(child) => Ok(child),
            Err(failure) => Err(AttachFailure {
                error: failure.error,
                stage: NativeStage::Child(failure),
            }),
        }
    }
}
impl<R: ChildAccess, T: Timer + 'static> Bus for I2c<R, T> {
    fn transaction(
        &mut self,
        address: i2c::Address,
        operations: &mut [Operation<'_>],
    ) -> Result<(), i2c::Error> {
        self.engine.transaction(address, operations)
    }
}
impl<R: ChildAccess, T: Timer + 'static> I2c<R, T> {
    #[expect(
        clippy::result_large_err,
        reason = "failed child disable or platform reset retains both original providers inline"
    )]
    pub fn shutdown(self) -> Result<(Retired<R>, T), I2cFailure<R, T>> {
        let (child, timer) = match self.engine.shutdown() {
            Ok(providers) => providers,
            Err(failure) => return Err(I2cFailure::engine(failure)),
        };
        let timer = ManuallyDrop::new(timer);
        // SAFETY: this same child acknowledged disable and kept every provider;
        // no child/IRQ/work alias exists, and this owner never enabled DMA.
        match unsafe { child.0.retire() } {
            Ok(retired) => Ok((retired, ManuallyDrop::into_inner(timer))),
            Err(failure) => Err(I2cFailure {
                error: AttachError::Platform(failure.error),
                stage: ChildStage::Platform {
                    _owner: failure,
                    _timer: timer,
                },
            }),
        }
    }
}
