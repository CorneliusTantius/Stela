// SPDX-License-Identifier: GPL-2.0-or-later
//! Native EC resources from firmware, following Linux `drivers/acpi/ec.c`.
//!
//! Descriptors identify resources; they confer no port, mapping, firmware-lock
//! or interrupt ownership. Boot ECDT and namespace discovery remain distinct:
//! ECDT alone does not establish `_GLK` policy or a live namespace handle.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Length,
    Checksum,
    Signature,
    Register,
    Path,
    Resource,
    UnsupportedResource(u8),
    Ports,
}

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "its firmware description is truncated",
            Self::Length => "its firmware description has a wrong length",
            Self::Checksum => "its firmware description checksum is wrong",
            Self::Signature => "its ECDT signature is wrong",
            Self::Register => "its command or data register is not a valid one-byte register",
            Self::Path => "its ECDT namespace path is invalid",
            Self::Resource => "its _CRS port descriptor is not a one-byte port",
            Self::UnsupportedResource(tag) => {
                return write!(f, "its _CRS has an unsupported descriptor {tag:#x}");
            }
            Self::Ports => "it does not have two distinct I/O ports",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Register {
    Io(u16),
    Memory(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ports {
    pub data: u16,
    pub command: u16,
}

/// Complete checked ECDT; path bytes borrow the original immutable table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ecdt<'a> {
    pub control: Register,
    pub data: Register,
    pub uid: u32,
    /// Ignore this field on an ACPI Reduced Hardware platform.
    pub gpe: u8,
    pub path: &'a str,
}

impl<'a> Ecdt<'a> {
    pub fn parse(table: &'a [u8]) -> Result<Self, Error> {
        if table.len() < 66 {
            return Err(Error::Truncated);
        }
        if &table[..4] != b"ECDT" {
            return Err(Error::Signature);
        }
        let length = u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize;
        if length != table.len() {
            return Err(Error::Length);
        }
        if table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
            return Err(Error::Checksum);
        }
        let control = register(&table[36..48])?;
        let data = register(&table[48..60])?;
        if control == data {
            return Err(Error::Register);
        }
        let path = &table[65..];
        let end = path.iter().position(|byte| *byte == 0).ok_or(Error::Path)?;
        // Keep the firmware path, including Linux's accepted relative
        // path variant. Do not repair a guessed leading backslash or EC name.
        let path = core::str::from_utf8(&path[..end]).map_err(|_| Error::Path)?;
        if path.is_empty() || !path.is_ascii() || path.bytes().any(|b| b.is_ascii_control()) {
            return Err(Error::Path);
        }
        Ok(Self {
            control,
            data,
            uid: u32::from_le_bytes(table[60..64].try_into().unwrap()),
            gpe: table[64],
            path,
        })
    }

    pub fn ports(self) -> Result<Ports, Error> {
        match (self.data, self.control) {
            (Register::Io(data), Register::Io(command)) => Ok(Ports { data, command }),
            _ => Err(Error::Ports),
        }
    }
}

fn register(bytes: &[u8]) -> Result<Register, Error> {
    // EC protocol accesses are exactly one byte, at bit offset zero. GAS access
    // size zero is unspecified, one is byte; wider accesses are not permitted.
    if bytes[1] != 8 || bytes[2] != 0 || !matches!(bytes[3], 0 | 1) {
        return Err(Error::Register);
    }
    let address = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
    if address == 0 {
        return Err(Error::Register);
    }
    match bytes[0] {
        0 if address != u64::MAX => Ok(Register::Memory(address)),
        1 => u16::try_from(address)
            .map(Register::Io)
            .map_err(|_| Error::Register),
        _ => Err(Error::Register),
    }
}

impl Ports {
    /// Decode the native `_CRS` resource-template buffer. As in Linux,
    /// the first IO descriptor is data, the second command/status. This subset
    /// requires two fixed one-byte IO descriptors and refuses unsupported
    /// address/IRQ resources rather than silently skipping their requirements.
    pub fn from_crs(bytes: &[u8]) -> Result<Self, Error> {
        let mut cursor = 0;
        let mut ports = [0; 2];
        let mut count = 0;
        loop {
            let tag = *bytes.get(cursor).ok_or(Error::Truncated)?;
            cursor += 1;
            let (kind, size) = if tag & 0x80 != 0 {
                let length = bytes.get(cursor..cursor + 2).ok_or(Error::Truncated)?;
                cursor += 2;
                (tag, usize::from(u16::from_le_bytes([length[0], length[1]])))
            } else {
                (tag >> 3, usize::from(tag & 7))
            };
            let end = cursor.checked_add(size).ok_or(Error::Length)?;
            let body = bytes.get(cursor..end).ok_or(Error::Truncated)?;
            cursor = end;
            match kind {
                0x0f => {
                    if size != 1 || cursor != bytes.len() {
                        return Err(Error::Length);
                    }
                    // Zero checksum explicitly means no resource checksum.
                    if body[0] != 0 && bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
                        return Err(Error::Checksum);
                    }
                    if count != 2 || ports[0] == ports[1] {
                        return Err(Error::Ports);
                    }
                    return Ok(Self {
                        data: ports[0],
                        command: ports[1],
                    });
                }
                0x08 => {
                    if size != 7 || count == 2 {
                        return Err(Error::Resource);
                    }
                    let minimum = u16::from_le_bytes([body[1], body[2]]);
                    let maximum = u16::from_le_bytes([body[3], body[4]]);
                    if body[0] & !1 != 0 || minimum == 0 || minimum != maximum || body[6] != 1 {
                        return Err(Error::Resource);
                    }
                    ports[count] = minimum;
                    count += 1;
                }
                // Vendor-defined information does not reserve additional
                // hardware; keep no interpretation or inferred capability.
                0x0e | 0x84 => {}
                _ => return Err(Error::UnsupportedResource(tag)),
            }
        }
    }
}

#[cfg(feature = "native-acpi")]
pub mod native {
    use super::*;
    use crate::platform::acpi::{self, Handle, Value};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum DiscoveryError {
        Firmware(&'static str, acpi::Error),
        Malformed(&'static str),
        Resources(Error),
        UnsupportedGpe,
    }

    /// A plain account for the boot log.
    impl core::fmt::Display for DiscoveryError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Firmware(method, error) => {
                    write!(f, "the ACPI method {method} failed: {error}")
                }
                Self::Malformed(method) => {
                    write!(f, "the ACPI method {method} returned an unexpected value")
                }
                Self::Resources(error) => error.fmt(f),
                Self::UnsupportedGpe => f.write_str("its _GPE event is not a plain number"),
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Device<'a> {
        pub handle: Handle<'a>,
        pub ports: Ports,
        pub global_lock: bool,
        /// None permits polling transactions only; no interrupt is inferred.
        pub gpe: Option<u32>,
    }

    impl<'a> Device<'a> {
        /// Read the validated ECDT's ports before namespace initialization.
        /// `_GLK` remains the device's firmware-lock policy. Reduced-hardware
        /// firmware ignores the ECDT GPE field, as ACPI requires.
        pub fn discover_ecdt(
            handle: Handle<'a>,
            table: Ecdt<'_>,
            hardware_reduced: bool,
        ) -> Result<Self, DiscoveryError> {
            Ok(Self {
                handle,
                ports: table.ports().map_err(DiscoveryError::Resources)?,
                global_lock: optional_integer(handle, "_GLK")?.unwrap_or(0) != 0,
                gpe: (!hardware_reduced).then_some(u32::from(table.gpe)),
            })
        }

        /// Use a PNP0C09 handle from Session::devices. Evaluate only
        /// after required native operation regions and firmware services exist.
        /// `_GPE` package/GPIO routing is explicitly outside this IO subset.
        pub fn discover(handle: Handle<'a>) -> Result<Self, DiscoveryError> {
            let value = handle
                .evaluate(Some("_CRS"), &[])
                .map_err(|error| DiscoveryError::Firmware("_CRS", error))?;
            let Some(Value::Buffer(resources)) = value else {
                return Err(DiscoveryError::Malformed("_CRS"));
            };
            let ports = Ports::from_crs(&resources).map_err(DiscoveryError::Resources)?;
            let global_lock = optional_integer(handle, "_GLK")?.unwrap_or(0) != 0;
            let gpe = optional_integer(handle, "_GPE")?
                .map(|value| u32::try_from(value).map_err(|_| DiscoveryError::UnsupportedGpe))
                .transpose()?;
            Ok(Self {
                handle,
                ports,
                global_lock,
                gpe,
            })
        }
    }

    fn optional_integer(
        handle: Handle<'_>,
        name: &'static str,
    ) -> Result<Option<u64>, DiscoveryError> {
        let method = match handle.child(name) {
            Ok(method) => method,
            Err(acpi::Error(5)) => return Ok(None),
            Err(error) => return Err(DiscoveryError::Firmware(name, error)),
        };
        // An existing method can fail with AE_NOT_FOUND while executing AML.
        // That failure never authorizes dropping its firmware-lock/GPE policy.
        match method.evaluate(None, &[]) {
            Ok(Some(Value::Integer(value))) => Ok(Some(value)),
            Err(error) => Err(DiscoveryError::Firmware(name, error)),
            Ok(_) if name == "_GPE" => Err(DiscoveryError::UnsupportedGpe),
            Ok(_) => Err(DiscoveryError::Malformed(name)),
        }
    }
}

#[cfg(test)]
mod tests;
