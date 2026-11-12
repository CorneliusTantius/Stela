// SPDX-License-Identifier: GPL-2.0-or-later
// ACPI battery protocol, following Linux drivers/acpi/battery.c.
// Copyright (C) 2007 Alexey Starikovskiy
// Copyright (C) 2004-2007 Vladimir Lebedev
// Copyright (C) 2001, 2002 Andy Grover and Paul Diefenbaugh
//! Native ACPI control-method batteries (PNP0C0A).
//!
//! Values preserve firmware units and unknown sentinels. This transport does
//! not choose charging policy, invent a percentage, or serve guest ACPI.
use super::acpi::{self, Argument, Handle, Value};
use alloc::vec::Vec;

const PRESENT: u32 = 1 << 4;
const UNKNOWN: u32 = u32::MAX;
const NOT_FOUND: acpi::Error = acpi::Error(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Status,
    ExtendedInformation,
    Information,
    State,
    Trip,
}
impl Method {
    fn name(self) -> &'static str {
        match self {
            Self::Status => "_STA",
            Self::ExtendedInformation => "_BIX",
            Self::Information => "_BIF",
            Self::State => "_BST",
            Self::Trip => "_BTP",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Firmware(Method, acpi::Error),
    Malformed(Method),
    UnsupportedRevision(u32),
    NotPresent,
    PresenceChanged,
    TripUnsupported,
}

/// The method's ACPI name, such as `_BST`.
impl core::fmt::Display for Method {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Firmware(method, error) => write!(f, "the ACPI method {method} failed: {error}"),
            Self::Malformed(method) => {
                write!(f, "the ACPI method {method} returned an unexpected value")
            }
            Self::UnsupportedRevision(revision) => {
                write!(f, "its _BIX revision {revision} is unsupported")
            }
            Self::NotPresent => f.write_str("no battery is present"),
            Self::PresenceChanged => f.write_str("the battery was inserted or removed"),
            Self::TripUnsupported => f.write_str("it has no capacity alarm (_BTP)"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    /// Capacity in mWh, rate in mW.
    Energy,
    /// Capacity in mAh, rate in mA.
    Charge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extended {
    pub revision: u32,
    pub cycle_count: Option<u32>,
    /// Firmware's 1/1000 percent measurement accuracy.
    pub accuracy: Option<u32>,
    pub maximum_sampling_ms: Option<u32>,
    pub minimum_sampling_ms: Option<u32>,
    pub maximum_averaging_ms: Option<u32>,
    pub minimum_averaging_ms: Option<u32>,
    pub swapping_capability: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Information {
    pub unit: Unit,
    pub design_capacity: Option<u32>,
    pub full_charge_capacity: Option<u32>,
    /// Zero means primary, one rechargeable; unknown stays unknown.
    pub rechargeable: Option<bool>,
    pub design_voltage_mv: Option<u32>,
    pub warning_capacity: Option<u32>,
    pub low_capacity: Option<u32>,
    pub low_granularity: Option<u32>,
    pub high_granularity: Option<u32>,
    /// Raw firmware identity, bounded like Linux's 32-byte string storage.
    pub model: Vec<u8>,
    pub serial: Vec<u8>,
    pub chemistry: Vec<u8>,
    pub oem: Vec<u8>,
    pub extended: Option<Extended>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub flags: u32,
    pub rate: Option<u32>,
    pub remaining_capacity: Option<u32>,
    pub voltage_mv: Option<u32>,
}
impl State {
    pub fn discharging(self) -> Option<bool> {
        known(self.flags).map(|flags| flags & 1 != 0)
    }
    pub fn charging(self) -> Option<bool> {
        known(self.flags).map(|flags| flags & 2 != 0)
    }
    pub fn critical(self) -> Option<bool> {
        known(self.flags).map(|flags| flags & 4 != 0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub status: u32,
    pub information: Information,
    pub state: State,
}

/// Owns no invented firmware state: every refresh evaluates native AML anew.
pub struct Battery<'a> {
    handle: Handle<'a>,
    extended: bool,
    trip: bool,
    snapshot: Option<Snapshot>,
    /// None after a failed/uncertain _BTP, removal or new information.
    alarm: Option<u32>,
    /// Actual `_BIX` execution error when Linux's `_BIF` fallback was attempted.
    /// Even if the fallback itself fails; absence is not execution.
    information_fallback: Option<acpi::Error>,
    /// Most recent `_STA` error that Linux's defined status default consumed.
    status_fallback: Option<acpi::Error>,
}
impl<'a> Battery<'a> {
    /// Use a handle from the native session's PNP0C0A device discovery.
    pub fn attach(handle: Handle<'a>) -> Result<Self, Error> {
        let extended = has(handle, Method::ExtendedInformation)?;
        if !extended {
            handle
                .child(Method::Information.name())
                .map_err(|e| Error::Firmware(Method::Information, e))?;
        }
        handle
            .child(Method::State.name())
            .map_err(|e| Error::Firmware(Method::State, e))?;
        Ok(Self {
            handle,
            extended,
            trip: has(handle, Method::Trip)?,
            snapshot: None,
            alarm: None,
            information_fallback: None,
            status_fallback: None,
        })
    }

    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    pub fn information_fallback(&self) -> Option<acpi::Error> {
        self.information_fallback
    }

    pub fn status_fallback(&self) -> Option<acpi::Error> {
        self.status_fallback
    }

    /// No stale snapshot survives a failed evaluation or observed removal.
    /// Notifications 0x80/0x81 and resume can all call the same fresh path.
    pub fn refresh(&mut self) -> Result<Option<&Snapshot>, Error> {
        self.snapshot = None;
        self.alarm = None;
        self.information_fallback = None;
        let status = self.status()?;
        if status & PRESENT == 0 {
            return Ok(None);
        }
        let information = if self.extended {
            match self.evaluate(Method::ExtendedInformation) {
                Ok(value) => parse_information(value, true)?,
                // Linux falls back when _BIX evaluation fails, not when its
                // successfully returned package is malformed.
                Err(Error::Firmware(_, error)) => {
                    self.information_fallback = Some(error);
                    parse_information(self.evaluate(Method::Information)?, false)?
                }
                Err(error) => return Err(error),
            }
        } else {
            parse_information(self.evaluate(Method::Information)?, false)?
        };
        let mut state = parse_state(self.evaluate(Method::State)?)?;
        if information.unit == Unit::Charge {
            // Linux's generic signed-16-bit DSDT rate correction, excluding
            // the unknown sentinel. Preserve all other rates verbatim.
            if let Some(rate) = state.rate {
                let signed = rate as i16;
                if signed < 0 {
                    state.rate = Some(u32::from(signed.unsigned_abs()));
                }
            }
        }
        let after = self.status()?;
        if after != status {
            return Err(Error::PresenceChanged);
        }
        self.snapshot = Some(Snapshot {
            status,
            information,
            state,
        });
        Ok(self.snapshot.as_ref())
    }

    /// Capacity uses the most recently observed battery's native units; zero
    /// disables the alarm. A failing AML call may already have affected hardware.
    pub fn set_trip(&mut self, capacity: u32) -> Result<(), Error> {
        self.alarm = None;
        if !self.trip {
            return Err(Error::TripUnsupported);
        }
        let Some(status) = self.snapshot.as_ref().map(|snapshot| snapshot.status) else {
            return Err(Error::NotPresent);
        };
        let result = (|| {
            if self.status()? != status {
                return Err(Error::PresenceChanged);
            }
            self.handle
                .evaluate(
                    Some(Method::Trip.name()),
                    &[Argument::Integer(capacity.into())],
                )
                .map_err(|e| Error::Firmware(Method::Trip, e))?;
            if self.status()? != status {
                return Err(Error::PresenceChanged);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.snapshot = None;
            return Err(error);
        }
        self.alarm = Some(capacity);
        Ok(())
    }

    pub fn acknowledged_trip(&self) -> Option<u32> {
        self.alarm
    }

    fn evaluate(&self, method: Method) -> Result<Value<'a>, Error> {
        self.handle
            .evaluate(Some(method.name()), &[])
            .map_err(|e| Error::Firmware(method, e))?
            .ok_or(Error::Malformed(method))
    }

    fn status(&mut self) -> Result<u32, Error> {
        self.status_fallback = None;
        match self.evaluate(Method::Status) {
            Ok(value) => integer(value, Method::Status),
            // Match Linux bus.c::acpi_bus_get_status_handle, including an
            // existing AML method that fails AE_NOT_FOUND during execution.
            // The defined default does not invent the battery-present bit.
            Err(Error::Firmware(_, NOT_FOUND)) => {
                self.status_fallback = Some(NOT_FOUND);
                Ok(0x0f)
            }
            Err(error) => Err(error),
        }
    }
}

fn has(handle: Handle<'_>, method: Method) -> Result<bool, Error> {
    match handle.child(method.name()) {
        Ok(_) => Ok(true),
        Err(NOT_FOUND) => Ok(false),
        Err(e) => Err(Error::Firmware(method, e)),
    }
}
fn integer(value: Value<'_>, method: Method) -> Result<u32, Error> {
    match value {
        Value::Integer(value) => u32::try_from(value).map_err(|_| Error::Malformed(method)),
        _ => Err(Error::Malformed(method)),
    }
}
fn known(value: u32) -> Option<u32> {
    (value != UNKNOWN).then_some(value)
}
fn package(value: Value<'_>, method: Method, minimum: usize) -> Result<Vec<Value<'_>>, Error> {
    match value {
        Value::Package(items) if items.len() >= minimum => Ok(items),
        _ => Err(Error::Malformed(method)),
    }
}
fn text(value: Value<'_>, method: Method) -> Result<Vec<u8>, Error> {
    let mut bytes = match value {
        Value::String(bytes) | Value::Buffer(bytes) => bytes,
        Value::Integer(value) => value.to_le_bytes().to_vec(),
        _ => return Err(Error::Malformed(method)),
    };
    bytes.truncate(
        bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(bytes.len())
            .min(31),
    );
    Ok(bytes)
}
fn parse_state(value: Value<'_>) -> Result<State, Error> {
    let method = Method::State;
    let mut items = package(value, method, 4)?.into_iter();
    Ok(State {
        flags: integer(items.next().unwrap(), method)?,
        rate: known(integer(items.next().unwrap(), method)?),
        remaining_capacity: known(integer(items.next().unwrap(), method)?),
        voltage_mv: known(integer(items.next().unwrap(), method)?),
    })
}
fn parse_information(value: Value<'_>, extended: bool) -> Result<Information, Error> {
    let method = if extended {
        Method::ExtendedInformation
    } else {
        Method::Information
    };
    let mut items = package(value, method, if extended { 20 } else { 13 })?.into_iter();
    let mut number = || integer(items.next().ok_or(Error::Malformed(method))?, method);
    let revision = if extended { Some(number()?) } else { None };
    if let Some(revision) = revision
        && revision > 1
    {
        return Err(Error::UnsupportedRevision(revision));
    }
    let unit = match number()? {
        0 => Unit::Energy,
        1 => Unit::Charge,
        _ => return Err(Error::Malformed(method)),
    };
    let design_capacity = known(number()?);
    let full_charge_capacity = known(number()?);
    let rechargeable = match number()? {
        0 => Some(false),
        1 => Some(true),
        UNKNOWN => None,
        _ => return Err(Error::Malformed(method)),
    };
    let design_voltage_mv = known(number()?);
    let warning_capacity = known(number()?);
    let low_capacity = known(number()?);
    let mut extended = if let Some(revision) = revision {
        Some(Extended {
            revision,
            cycle_count: known(number()?),
            accuracy: known(number()?),
            maximum_sampling_ms: known(number()?),
            minimum_sampling_ms: known(number()?),
            maximum_averaging_ms: known(number()?),
            minimum_averaging_ms: known(number()?),
            swapping_capability: None,
        })
    } else {
        None
    };
    let low_granularity = known(number()?);
    let high_granularity = known(number()?);
    let model = text(items.next().unwrap(), method)?;
    let serial = text(items.next().unwrap(), method)?;
    let chemistry = text(items.next().unwrap(), method)?;
    let oem = text(items.next().unwrap(), method)?;
    if let Some(extended) = extended.as_mut()
        && extended.revision == 1
    {
        extended.swapping_capability = known(integer(
            items.next().ok_or(Error::Malformed(method))?,
            method,
        )?);
    }
    Ok(Information {
        unit,
        design_capacity,
        full_charge_capacity,
        rechargeable,
        design_voltage_mv,
        warning_capacity,
        low_capacity,
        low_granularity,
        high_granularity,
        model,
        serial,
        chemistry,
        oem,
        extended,
    })
}

#[cfg(test)]
mod tests;
