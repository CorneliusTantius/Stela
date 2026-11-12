// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2003-2004 Intel
// Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
// Copyright (C) 2016 Christoph Hellwig.
// Copyright (c) 2026 Stela contributors
//! Single-message PCI MSI configuration with kept real config ownership.
//! Register layouts and narrow message programming follow Linux PCI MSI at
//! a804c5742bff224d4cb4d25dd383554d598be32b. Ownership, validation, readback and
//! quarantine are Stela integration. This is not an IRQ controller or DMA stop.
use super::regs;
use super::{Address, ConfigSpace, EcamConfig, Function, capability, capability::CapabilityError};
use crate::bus::irq::MsiMessage;
use alloc::sync::Arc;
use core::{
    any::Any,
    sync::atomic::{AtomicU64, Ordering},
};

mod retirement;
pub use retirement::DisabledMsiConfig;

const MSI: u8 = 5;
const MSIX: u8 = 0x11;
const ENABLE: u16 = 1;
const MMC: u16 = 7 << 1;
const MME: u16 = 7 << 4;
const WIDE: u16 = 1 << 7;
const MASK_CAPABLE: u16 = 1 << 8;
const MSIX_ENABLE: u16 = 1 << 15;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);

/// A transport whose `write16` has the native word-store effect.
///
/// # Safety
/// Configuration reads/writes have real serialized effects. In particular,
/// `write16` never replays adjacent Status W1C bits through a dword RMW. It
/// has an explicit fallible exact-width implementation. Access remains valid under the
/// enclosing owner and occurs only in process/deferred context.
pub unsafe trait MsiConfigSpace: ConfigSpace {}
// SAFETY: EcamConfig overrides write16 with Mmio::write16, a native volatile
// word store; its real mapped/config lifetime is the constructor's grant.
unsafe impl MsiConfigSpace for EcamConfig {}

pub type RetainedOwner = Arc<dyn Any + Send + Sync>;
pub type Released<C> = (Function<C>, RetainedOwner);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MsiError {
    Config(super::ConfigError),
    MissingCapability,
    MalformedCapability,
    Unsupported,
    ActiveMsi,
    ActiveMsix,
    IdentityChanged,
    CapabilityChanged,
    InvalidMessage,
    FailedRead { offset: u16 },
    Readback { offset: u16 },
    NotProgrammed,
    TerminalRetirement,
    StopAlreadyAttempted,
    Interrupted,
    Released,
}

/// A plain account for the boot log.
impl core::fmt::Display for MsiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Config(error) => return error.fmt(f),
            Self::MissingCapability => "it has no MSI capability",
            Self::MalformedCapability => "its MSI capability is malformed",
            Self::Unsupported => "its MSI layout is unsupported",
            Self::ActiveMsi => "MSI is already enabled on it",
            Self::ActiveMsix => "MSI-X is already enabled on it",
            Self::IdentityChanged => "its identity changed while its MSI was set up",
            Self::CapabilityChanged => "its MSI capability changed while it was set up",
            Self::InvalidMessage => "the MSI message is invalid",
            Self::FailedRead { offset } => {
                return write!(f, "its MSI register {offset:#x} reads all ones");
            }
            Self::Readback { offset } => {
                return write!(
                    f,
                    "its MSI register {offset:#x} did not keep what was written"
                );
            }
            Self::NotProgrammed => "its MSI message is not programmed",
            Self::TerminalRetirement => "its MSI could not be retired and stays held",
            Self::StopAlreadyAttempted => "its MSI stop was already attempted",
            Self::Interrupted => "its MSI change was interrupted",
            Self::Released => "its MSI owner was already released",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Layout {
    offset: u16,
    header: u16,
    features: u16,
}
impl Layout {
    fn wide(self) -> bool {
        self.features & WIDE != 0
    }
    fn data(self) -> u16 {
        self.offset + if self.wide() { 12 } else { 8 }
    }
    fn mask(self) -> Option<u16> {
        (self.features & MASK_CAPABLE != 0)
            .then_some(self.offset + if self.wide() { 16 } else { 12 })
    }
}
impl From<CapabilityError> for MsiError {
    fn from(error: CapabilityError) -> Self {
        match error {
            CapabilityError::Config { error, .. } => Self::Config(error),
            CapabilityError::FailedRead { offset } => Self::FailedRead { offset },
            _ => Self::MalformedCapability,
        }
    }
}
impl From<super::ConfigError> for MsiError {
    fn from(error: super::ConfigError) -> Self {
        Self::Config(error)
    }
}
fn read16<C: ConfigSpace>(c: &C, offset: u16) -> Result<u16, MsiError> {
    let value = c.read16(offset)?;
    if value == u16::MAX {
        Err(MsiError::FailedRead { offset })
    } else {
        Ok(value)
    }
}
fn verify16<C: MsiConfigSpace>(c: &C, offset: u16, expected: u16) -> Result<(), MsiError> {
    let actual = c.read16(offset)?;
    if actual == expected {
        Ok(())
    } else if actual == u16::MAX {
        Err(MsiError::FailedRead { offset })
    } else {
        Err(MsiError::Readback { offset })
    }
}
fn verify32<C: MsiConfigSpace>(c: &C, offset: u16, expected: u32) -> Result<(), MsiError> {
    let actual = c.read32(offset)?;
    if actual == expected {
        Ok(())
    } else if actual == u32::MAX {
        Err(MsiError::FailedRead { offset })
    } else {
        Err(MsiError::Readback { offset })
    }
}
fn write16<C: MsiConfigSpace>(c: &mut C, offset: u16, value: u16) -> Result<(), MsiError> {
    c.write16(offset, value)?;
    verify16(c, offset, value).map_err(|error| match error {
        MsiError::Config(error) => MsiError::Config(super::ConfigError::write_may_have_applied(
            offset,
            2,
            error.reason,
        )),
        error => error,
    })
}
fn write32<C: MsiConfigSpace>(c: &mut C, offset: u16, value: u32) -> Result<(), MsiError> {
    c.write32(offset, value)?;
    verify32(c, offset, value).map_err(|error| match error {
        MsiError::Config(error) => MsiError::Config(super::ConfigError::write_may_have_applied(
            offset,
            4,
            error.reason,
        )),
        error => error,
    })
}

fn discover<C: MsiConfigSpace>(f: &mut Function<C>) -> Result<(Layout, u16), MsiError> {
    let expected = u32::from(f.vendor) | u32::from(f.device) << 16;
    let c = f.config();
    let id = c.read32(0)?;
    if id == u32::MAX {
        return Err(MsiError::FailedRead { offset: 0 });
    }
    if id != expected {
        return Err(MsiError::IdentityChanged);
    }
    let header_type = c.read8(0x0e)? & 0x7f;
    if !matches!(header_type, 0 | 1) {
        return Err(MsiError::Unsupported);
    }
    // The walk reads Status; without a capability list nothing is found.
    let mut found = None;
    let mut msix = false;
    for entry in c.capabilities() {
        let entry = entry?;
        let offset = entry.offset;
        match entry.id {
            MSI => {
                if found.is_some() {
                    return Err(MsiError::MalformedCapability);
                }
                let control = read16(c, offset + 2)?;
                // Extended message data and reserved queue encodings need their
                // own contract; never truncate them to a successful 16-bit MSI.
                if control & !(ENABLE | MMC | MME | WIDE | MASK_CAPABLE) != 0
                    || (control & MMC) >> 1 > 5
                    || (control & MME) >> 4 > (control & MMC) >> 1
                {
                    return Err(MsiError::Unsupported);
                }
                let layout = Layout {
                    offset,
                    header: entry.header,
                    features: control & !(ENABLE | MME),
                };
                found = Some((layout, control));
            }
            MSIX => {
                if core::mem::replace(&mut msix, true) {
                    return Err(MsiError::MalformedCapability);
                }
                if read16(c, offset + 2)? & MSIX_ENABLE != 0 {
                    return Err(MsiError::ActiveMsix);
                }
            }
            0 => return Err(MsiError::MalformedCapability),
            _ if entry.layout == capability::Layout::Unsupported => {
                return Err(MsiError::Unsupported);
            }
            _ => {}
        }
    }
    found.ok_or(MsiError::MissingCapability)
}

/// Owns the original Function and kept PCI/config/root/reset epoch.
/// There is no normal config escape or second enumeration. Terminal retirement
/// separately permits one unsafe scoped device-stop operation. No MSI method changes BM,
/// acknowledges a device cause, drains callbacks, or infers DMA coherency.
/// Operations and final release require process/deferred context, never an ISR.
pub struct MsiConfig<C: MsiConfigSpace = EcamConfig> {
    owner: Option<Released<C>>,
    layout: Layout,
    message: Option<MsiMessage>,
    phase: Phase,
}
#[derive(Clone, Copy)]
enum Phase {
    Live,
    Acting,
    Retiring,
    Failed(MsiError),
}
impl<C: MsiConfigSpace> MsiConfig<C> {
    /// # Safety
    /// `function` is the unique function (unmodified identity/address),
    /// and `retained` is its config/root/PCI/reset-epoch owner, not a
    /// dummy token. This keeps the real mapped configuration transport even
    /// if abandoned. Native config accesses and every source/worker/reset are
    /// serialized; no firmware/alias/other CPU can reconfigure or revoke it.
    /// Old source actions, CPU/EOI/callbacks and captured service/work have
    /// joined under the actual stable notification domain; any old device
    /// cause remains owned. A delayed ordinary fixed/edge packet may notify a
    /// current valid status-checking handler. Unknown format/root handover needs
    /// its independent real completion proof. Initially disabled MSI proves
    /// none of this. No vector, domain or requester-coherency grant is created.
    /// Errors return both owners without modifying configuration.
    pub unsafe fn new(
        function: Function<C>,
        retained: RetainedOwner,
    ) -> Result<Self, (MsiError, Released<C>)> {
        let mut original = super::kept::Kept::new((function, retained));
        let discovered = discover(&mut original.get_mut().0);
        match discovered {
            Ok((layout, control)) if control & ENABLE == 0 => Ok(Self {
                owner: Some(original.take()),
                layout,
                message: None,
                phase: Phase::Live,
            }),
            Ok(_) => Err((MsiError::ActiveMsi, original.take())),
            Err(error) => Err((error, original.take())),
        }
    }
    pub fn address(&self) -> Result<Address, MsiError> {
        Ok(self.owner.as_ref().ok_or(MsiError::Released)?.0.address)
    }
    fn normal(&self) -> Result<(), MsiError> {
        match self.phase {
            Phase::Live if self.owner.is_some() => Ok(()),
            Phase::Live => Err(MsiError::Released),
            Phase::Acting => Err(MsiError::Interrupted),
            Phase::Retiring => Err(MsiError::TerminalRetirement),
            Phase::Failed(error) => Err(error),
        }
    }
    fn operation<T>(
        &mut self,
        run: impl FnOnce(&mut Self) -> Result<T, MsiError>,
    ) -> Result<T, MsiError> {
        self.normal()?;
        self.phase = Phase::Acting;
        let result = run(self);
        self.phase = match result.as_ref() {
            Ok(_) => Phase::Live,
            Err(error) => Phase::Failed(*error),
        };
        if result.is_err() {
            self.message = None;
        }
        result
    }
    /// Irreversibly disable MSI and fallback INTx before a device stop that
    /// needs the original configuration owner. This establishes no DMA, posted
    /// write, IRQ or worker completion. The registry keeps its route/callbacks
    /// while the terminal owner performs the real source stop.
    ///
    /// Authorization is revoked before even the first configuration access.
    /// Failure keeps the owner here with no program/unmask/retry path.
    /// Ordinary admission-time mask remains reversible and does not use this.
    pub fn begin_device_retirement(&mut self) -> Result<DisabledMsiConfig<C>, MsiError> {
        self.normal()?;
        self.phase = Phase::Retiring;
        self.message = None;
        if let Err(error) = self.mask_inner() {
            self.phase = Phase::Failed(error);
            return Err(error);
        }
        Ok(DisabledMsiConfig::new(
            self.owner.take().ok_or(MsiError::Released)?,
        ))
    }
    fn checked(&mut self) -> Result<u16, MsiError> {
        let f = &mut self.owner.as_mut().ok_or(MsiError::Released)?.0;
        let (layout, control) = discover(f)?;
        if layout != self.layout {
            return Err(MsiError::CapabilityChanged);
        }
        Ok(control)
    }
    fn config(&mut self) -> Result<&mut C, MsiError> {
        Ok(self.owner.as_mut().ok_or(MsiError::Released)?.0.config())
    }
    fn mask_inner(&mut self) -> Result<(), MsiError> {
        let control = self.checked()?;
        let layout = self.layout;
        let c = self.config()?;
        // Establish INTxDisable before clearing MSI Enable: clearing Enable
        // first can expose fallback legacy INTx while route state is changing.
        let command = read16(c, regs::COMMAND)?;
        write16(c, regs::COMMAND, command | regs::COMMAND_INTX_DISABLE)?;
        if let Some(offset) = layout.mask() {
            let mask = c.read32(offset)?;
            // All-ones is a valid mask bitmap. Presence/control reads check
            // this transport; never interpret valid all-masked as failed data.
            write32(c, offset, mask | 1)?;
        }
        write16(c, layout.offset + 2, control & !ENABLE)
    }
    /// Mask and acknowledge MSI plus fallback INTx. This does not stop a device
    /// or drain already posted writes, callbacks, timers or deferred work.
    pub fn mask(&mut self) -> Result<(), MsiError> {
        self.operation(|owner| owner.mask_inner())
    }
    /// Disable the route and forget its authorization for subsequent unmask.
    /// Unrelated command/control/mask bits and message fields are preserved.
    pub fn disable(&mut self) -> Result<(), MsiError> {
        self.message = None;
        self.mask()
    }
    /// Program exactly one supplied message, while MSI and INTx are disabled.
    ///
    /// # Safety
    /// This typed message belongs to the registry's checked route;
    /// every callback/resource remains held. Reprogramming requires actual old
    /// source/pending-cause closure plus CPU/EOI/captured service/work joins
    /// under the same retained notification domain. This is not an all-issued
    /// MSI or payload completion receipt; masking alone is insufficient.
    pub unsafe fn program(&mut self, message: MsiMessage) -> Result<(), MsiError> {
        self.normal()?;
        if !message.valid_pci_format()
            || message.data > u32::from(u16::MAX)
            || (!self.layout.wide() && message.address > u64::from(u32::MAX))
        {
            return Err(MsiError::InvalidMessage);
        }
        self.operation(|owner| {
            owner.message = None;
            owner.mask_inner()?;
            let layout = owner.layout;
            let control = owner.checked()? & !(ENABLE | MME);
            let c = owner.config()?;
            write16(c, layout.offset + 2, control)?;
            write32(c, layout.offset + 4, message.address as u32)?;
            if layout.wide() {
                write32(c, layout.offset + 8, (message.address >> 32) as u32)?;
            }
            write16(c, layout.data(), message.data as u16)?;
            verify16(c, layout.offset + 2, control)?;
            owner.message = Some(message);
            Ok(())
        })
    }
    /// # Safety
    /// The registry keeps/publishes the callback and checked route;
    /// the requester and all IRQ/DMA/work/reset owners remain held. BM and
    /// vendor source enable are separately controlled by that owner.
    pub unsafe fn unmask(&mut self) -> Result<(), MsiError> {
        self.normal()?;
        let message = self.message.ok_or(MsiError::NotProgrammed)?;
        self.operation(|owner| {
            owner.mask_inner()?;
            let layout = owner.layout;
            let control = owner.checked()?;
            let c = owner.config()?;
            verify32(c, layout.offset + 4, message.address as u32)?;
            if layout.wide() {
                verify32(c, layout.offset + 8, (message.address >> 32) as u32)?;
            }
            verify16(c, layout.data(), message.data as u16)?;
            if control & MME != 0 {
                return Err(MsiError::CapabilityChanged);
            }
            if let Some(offset) = layout.mask() {
                let mask = c.read32(offset)?;
                write32(c, offset, mask & !1)?;
            }
            write16(c, layout.offset + 2, control | ENABLE)
        })
    }
    /// Return the owners only after independent source/IRQ/work drain.
    ///
    /// # Safety
    /// Device engines are stopped and old IRQ actions have joined their
    /// CPU/EOI/callbacks and captured service/thread/work; former reset users
    /// cannot restart. Stable CPU/root/format ownership remains retained for
    /// delayed ordinary notifications; this is not all-issued MSI completion.
    /// Every payload/DMA lease/fence/IOTLB obligation stays independently owned
    /// until completed; returning config owners proves none of them.
    pub unsafe fn release(&mut self) -> Result<Released<C>, MsiError> {
        self.disable()?;
        self.owner.take().ok_or(MsiError::Released)
    }
}
impl<C: MsiConfigSpace> Drop for MsiConfig<C> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            // No hardware access or guessed completion in Drop. Keep the
            // real configuration and root owner on every uncertain path.
            core::mem::forget(owner);
            let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(1))
            });
        }
    }
}
/// Cumulative abandoned config/root owners, kept for safety.
pub fn quarantined_configurations() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests;
