// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware resource decoding and reservations backed by native owners.
//!
//! A `_CRS` address is descriptive, not ownership. `MemoryBroker` subdivides
//! already reserved native resources; it never turns an AML integer into MMIO
//! permission. Namespace handles remain CPU-affine in `DeviceResources` while
//! mapping pins keep the underlying native reservation independently.

mod decode;
pub mod gpio;
mod memory;
pub(crate) mod supplier;

pub use decode::{parse, parse_gpio_connection};
pub use memory::{DeviceResources, MemoryBroker, MemoryReservation, reservation_parent};
pub use supplier::Dependency;

use super::{Handle, Value};
use alloc::{string::String, vec::Vec};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Acpi(super::Error),
    InvalidObject(&'static str),
    Unavailable(u64),
    Truncated,
    Malformed,
    Checksum,
    MissingEnd,
    DependentFunctions,
    Limit,
    Unsupported {
        tag: u8,
        revision: u8,
    },
    Unassigned,
    OutsideReservation,
    Conflict,
    ResourceChanged,
    Retirement {
        primary: Option<super::Error>,
        cleanup: super::Error,
    },
}
impl From<super::Error> for Error {
    fn from(error: super::Error) -> Self {
        Self::Acpi(error)
    }
}

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Acpi(error) => return error.fmt(f),
            Self::InvalidObject(name) => {
                return write!(f, "the firmware object {name} has an unexpected form");
            }
            Self::Unavailable(status) => {
                return write!(
                    f,
                    "the device is not present and working (_STA {status:#x})"
                );
            }
            Self::Truncated => "its resource list is truncated",
            Self::Malformed => "its resource list is malformed",
            Self::Checksum => "its resource list checksum is wrong",
            Self::MissingEnd => "its resource list has no end tag",
            Self::DependentFunctions => "its resource list uses dependent functions",
            Self::Limit => "its resources exceed a limit",
            Self::Unsupported { tag, revision } => {
                return write!(
                    f,
                    "its resource descriptor {tag:#x} revision {revision} is unsupported"
                );
            }
            Self::Unassigned => "its resource is not assigned",
            Self::OutsideReservation => "its resource lies outside every firmware reservation",
            Self::Conflict => "its resource overlaps another owner's",
            Self::ResourceChanged => "its resources changed",
            Self::Retirement {
                primary: Some(primary),
                cleanup,
            } => return write!(f, "{primary}, and its cleanup failed: {cleanup}"),
            Self::Retirement {
                primary: None,
                cleanup,
            } => return write!(f, "its cleanup failed: {cleanup}"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Source {
    pub index: u8,
    pub path: String,
}
impl Source {
    /// Resolve relative to the resource's namespace device, preserving
    /// ACPI parent-prefix and absolute-path semantics through ACPICA itself.
    pub fn resolve<'a>(&self, device: Handle<'a>) -> Result<Handle<'a>, Error> {
        Ok(device.child(&self.path)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Space {
    Memory,
    Io,
    Bus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    pub space: Space,
    pub consumer: bool,
    pub subtractive: bool,
    pub minimum_fixed: bool,
    pub maximum_fixed: bool,
    pub specific_flags: u8,
    pub granularity: u64,
    pub minimum: u64,
    pub maximum: u64,
    pub translation: u64,
    pub length: u64,
    pub source: Option<Source>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trigger {
    Level,
    Edge,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Polarity {
    High,
    Low,
    Both,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interrupt {
    pub consumer: bool,
    pub trigger: Trigger,
    pub polarity: Polarity,
    pub shared: bool,
    pub wake: bool,
    pub pins: Vec<u32>,
    pub source: Option<Source>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoRestriction {
    None,
    Input,
    Output,
    Preserve,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GpioKind {
    Interrupt {
        trigger: Trigger,
        polarity: Polarity,
    },
    Io(IoRestriction),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Gpio {
    pub consumer: bool,
    pub kind: GpioKind,
    pub shared: bool,
    pub wake: bool,
    /// ACPI pin configuration (default/up/down/no-pull or vendor-defined).
    pub pull: u8,
    /// Hundredths of a milliampere, as encoded by ACPI.
    pub drive_strength: u16,
    /// Hundredths of a millisecond, as encoded by ACPI.
    pub debounce: u16,
    pub pins: Vec<u16>,
    pub source: Source,
    pub vendor: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SerialKind {
    I2c {
        address: u16,
        ten_bit: bool,
    },
    Spi {
        selection: u16,
        three_wire: bool,
        active_high: bool,
        bits: u8,
        clock_phase: u8,
        clock_polarity: u8,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Serial {
    pub consumer: bool,
    pub controller_initiated: bool,
    pub shared: bool,
    pub speed: u32,
    pub kind: SerialKind,
    pub source: Source,
    pub vendor: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resource {
    Address(Address),
    Interrupt(Interrupt),
    Gpio(Gpio),
    Serial(Serial),
    /// Verbatim for reporting; never silently treated as implemented.
    Unsupported {
        tag: u8,
        bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    /// Resource-template ordinal, including unsupported descriptors.
    pub ordinal: usize,
    pub offset: usize,
    /// Original descriptor, including reserved/padding/vendor bytes.
    pub bytes: Vec<u8>,
    pub resource: Resource,
}

pub fn evaluate(device: Handle<'_>, method: &'static str) -> Result<Vec<Descriptor>, Error> {
    let Some(Value::Buffer(bytes)) = device.evaluate(Some(method), &[])? else {
        return Err(Error::InvalidObject(method));
    };
    parse(&bytes)
}

/// Actual `_DEP` references, with missing `_DEP` following ACPI's empty default.
pub fn dependencies(device: Handle<'_>) -> Result<Vec<Handle<'_>>, Error> {
    match device.evaluate(Some("_DEP"), &[]) {
        Err(super::Error(5)) => Ok(Vec::new()),
        Ok(Some(Value::Package(values))) => values
            .into_iter()
            .map(|value| match value {
                Value::Reference(reference) => Ok(reference.handle),
                _ => Err(Error::InvalidObject("_DEP")),
            })
            .collect(),
        Ok(_) => Err(Error::InvalidObject("_DEP")),
        Err(error) => Err(error.into()),
    }
}
