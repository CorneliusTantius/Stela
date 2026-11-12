// SPDX-License-Identifier: GPL-2.0-only
// Protocols derived from Linux intel-ish-hid, Copyright (c) 2003-2016 Intel.
//! Explicit resident-firmware Intel ISH IPC/HBM/HID attachment.
//!
//! The finite profile is 8086:9d35, ordinary nonfixed HID clients and mailbox
//! payload transport. Startup requires the requester's DMA domain, isolated or
//! the passthrough domain, and real MSI delivery. No host DMA address or firmware is supplied.
//! Firmware clock synchronization lacks an UTC service and is explicitly
//! unsupported. Final armed-MSI retirement remains unsupported until the common
//! root owner implements posted-MSI completion; all original owners are held.
pub mod cold;
mod descriptor;
mod input;
mod native;
pub use input::{ClientRefusal, ClientRefusalCause, InputRefusal, IshInput};
mod protocol;
mod registers;
#[cfg(test)]
mod tests;

use crate::bus::{dma::mapping::DmaError, irq::IrqError, mmio::owned, pci::msi::MsiError};
pub use descriptor::{ReportKind, ReportLayout};
pub use native::{Configuration, InputPoll, Inputs, Native, NativeClock, Time};
pub use protocol::{ClientProperties, Device, FirmwareIdentity, InputReport, TimestampSupport};
pub use registers::{MappedRegisters, Registers};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ConfigAccess(crate::bus::pci::ConfigError),
    Capability(crate::bus::pci::CapabilityError),
    Requirement(&'static str),
    Mapping(owned::Error),
    Config(u16),
    Msi(MsiError),
    Irq(IrqError),
    Dma(DmaError),
    Access(u32),
    Removed,
    Readback(u32),
    Timeout(&'static str),
    Protocol(&'static str),
    Status(u8),
    FirmwareReset,
    Terminal,
    InputPollInterrupted,
    StopInterrupted,
    /// Payload drainage is independent of the missing posted-MSI completion.
    PostedMsiRetirementUnavailable,
}
pub type Result<T> = core::result::Result<T, Error>;

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ConfigAccess(error) => return error.fmt(f),
            Self::Capability(error) => return error.fmt(f),
            Self::Requirement(what) => return write!(f, "it needs {what}"),
            Self::Mapping(error) => return error.fmt(f),
            Self::Config(offset) => {
                return write!(
                    f,
                    "its PCI register {offset:#x} reads wrong or did not keep a write"
                );
            }
            Self::Msi(error) => return error.fmt(f),
            Self::Irq(error) => return error.fmt(f),
            Self::Dma(error) => return error.fmt(f),
            Self::Access(offset) => {
                return write!(f, "an access to its register {offset:#x} failed");
            }
            Self::Removed => "its registers read all ones, as if it was removed",
            Self::Readback(offset) => {
                return write!(f, "its register {offset:#x} did not keep what was written");
            }
            Self::Timeout(what) => return write!(f, "it timed out waiting for {what}"),
            Self::Protocol(what) => return write!(f, "its firmware broke the protocol: {what}"),
            Self::Status(status) => {
                return write!(f, "its firmware answered with status {status:#x}");
            }
            Self::FirmwareReset => "its firmware reset itself",
            Self::Terminal => "an earlier failure stopped it",
            Self::InputPollInterrupted => "an input poll was interrupted",
            Self::StopInterrupted => "its stop was interrupted",
            Self::PostedMsiRetirementUnavailable => {
                "its MSI cannot be retired yet, so it stays held"
            }
        })
    }
}

/// Input reports one poll reads at most, as USB HID bounds its pass.
const POLL_REPORTS: usize = 16;
