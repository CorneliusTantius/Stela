// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2017 Intel Deutschland GmbH
// Copyright (C) 2019-2026 Intel Corporation
//! Owned BIOS reads for one real Intel function. Parsing copied observations
//! remains separate from this unsafe platform-service implementation contract.
use super::{GeneralConfiguration, Scalar, ScalarKind};
use crate::wifi::intel::{platform::Variable, radio::lari};
use alloc::{string::String, vec::Vec};
#[cfg(feature = "native-acpi")]
pub mod native;
pub(crate) mod power;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Glai,
    WideBandwidth,
    ExternalClock,
    Country,
    /// Exact WRDS/EWRD/WGDS/PPAG/WTAS method at this function's real ACPI
    /// handle. Other Variable variants are never requested through this case.
    PowerTable(Variable),
    /// Intel DSM GUID f21202bf-8f78-4dc6-a5b3-1f738e285ade, revision 0,
    /// no fourth-argument payload, at the function's ACPI handle.
    Dsm(u8),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object {
    Integer(u64),
    Buffer(Vec<u8>),
    Package(Vec<Object>),
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError {
    /// The platform service has not been implemented or cannot be called now.
    /// The session records it as such and, as Linux does for any failed
    /// read, goes on as if the value were absent.
    Unavailable,
    /// A collection bound prevented a complete observation.
    BoundExceeded,
    /// Checked lookup/invocation failed, keeping its platform code.
    Failed(u64),
    NotFound,
}
impl IoError {
    fn incomplete(self) -> bool {
        matches!(self, Self::Unavailable | Self::BoundExceeded)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmiIdentity {
    /// SMBIOS system/board vendor strings, or observed absent strings.
    pub system_vendor: Option<String>,
    pub board_vendor: Option<String>,
}
/// ACPI and EFI reads, owned independently of copied resource bytes.
/// # Safety
/// Implementors perform real reads at the device/firmware namespace bound by
/// `ColdRadio::begin_lari`, keeping every resource needed for those services.
/// ACPI requests must use that function's real handle (including an
/// observed missing handle), exact method/GUID/revision and original values.
/// EFI reads use the requested descriptor's exact GUID/name and preserve full
/// returned bytes. NotFound/Failed require an attempted checked read;
/// missing AML/EFI support, invalid lifetime/root mapping or incomplete capture
/// must return Unavailable/BoundExceeded, never pretend the object is absent.
/// Returned objects are bounded to 4096 bytes/256 nodes/depth 4; exceeding that
/// native collection envelope returns BoundExceeded. The provider must remain
/// valid until independently stopped; uncertain owner Drop keeps it. SMBIOS
/// vendor strings come from this same native platform, preserve
/// absence and are individually bounded to 4096 bytes.
pub unsafe trait BiosIo: Clone + 'static {
    fn evaluate(&mut self, request: Request) -> Result<Object, IoError>;
    fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError>;
    /// Real SMBIOS on the same platform; no PCI/ACPI-derived guess.
    /// The default preserves explicitly unavailable native service support.
    fn dmi_identity(&mut self) -> Result<DmiIdentity, IoError> {
        Err(IoError::Unavailable)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    Acpi(Request, Result<Object, IoError>),
    Uefi(Variable, Result<Vec<u8>, IoError>),
    Dmi(Result<DmiIdentity, IoError>),
}
impl Read {
    /// Whether this read left its value unknown rather than absent: a service
    /// that could not answer or an answer past its bound. Like every other
    /// failed read, Linux takes it as an absent value.
    pub fn incomplete(&self) -> bool {
        match self {
            Self::Acpi(_, Err(error)) | Self::Uefi(_, Err(error)) | Self::Dmi(Err(error)) => {
                error.incomplete()
            }
            Self::Uefi(_, Ok(raw)) => raw.len() > MAX_VARIABLE,
            Self::Dmi(Ok(identity)) => oversized(identity),
            _ => false,
        }
    }
}
/// The largest EFI variable this session takes.
const MAX_VARIABLE: usize = 4096;
fn oversized(identity: &DmiIdentity) -> bool {
    [&identity.system_vendor, &identity.board_vendor]
        .into_iter()
        .any(|vendor| vendor.as_ref().is_some_and(|v| v.len() > MAX_VARIABLE))
}
#[derive(Clone, Copy)]
struct Cache {
    values: [u32; 15],
    valid: u32,
    source: lari::Source,
    revision: u8,
}
pub(crate) struct Session<B: BiosIo> {
    pub(crate) io: B,
    reads: Vec<Read>,
    locked: Option<bool>,
    cache: Option<Cache>,
    external_clock: Option<lari::Observation>,
    country: Option<lari::Observation>,
}
impl<B: BiosIo> Session<B> {
    pub(crate) fn new(io: B) -> Self {
        Self {
            io,
            reads: Vec::new(),
            locked: None,
            cache: None,
            external_clock: None,
            country: None,
        }
    }
    /// The SMBIOS vendors, as `dmi_match` sees them: one it cannot read
    /// matches no vendor.
    pub(crate) fn dmi_identity(&mut self) -> DmiIdentity {
        let result = self.io.dmi_identity();
        self.reads.push(Read::Dmi(result.clone()));
        match result {
            Ok(identity) if !oversized(&identity) => identity,
            _ => DmiIdentity {
                system_vendor: None,
                board_vendor: None,
            },
        }
    }
    pub(crate) fn reads(&self) -> &[Read] {
        &self.reads
    }
    /// Source ECKV selection in this session's original namespace.
    /// Missing services are incomplete observations, not an absent clock.
    pub(crate) fn external_clock(&mut self) -> lari::Observation {
        if let Some(observation) = self.external_clock {
            return observation;
        }
        let observation = self.scalar(
            ScalarKind::ExternalClock,
            Variable::Eckv,
            Request::ExternalClock,
        );
        self.external_clock = Some(observation);
        observation
    }
    /// Source WRDD permits CN only. This records a BIOS observation, never
    /// location/OS permission or an override of a firmware response.
    /// `iwl_uefi_get_puncturing`: which countries the platform enables channel
    /// puncturing for. Nothing it cannot say enables any.
    pub(crate) fn puncturing(&mut self) -> u32 {
        const REVISION: u8 = 0;
        const MASK: u32 = 3;
        match self.uefi(Variable::Puncturing) {
            Some(raw) if raw.first() == Some(&REVISION) => raw
                .get(1..5)
                .and_then(|value| value.try_into().ok())
                .map_or(0, |value| u32::from_le_bytes(value) & MASK),
            _ => 0,
        }
    }
    pub(crate) fn country(&mut self) -> lari::Observation {
        if let Some(observation) = self.country {
            return observation;
        }
        let observation = self.scalar(ScalarKind::Country, Variable::Wrdd, Request::Country);
        self.country = Some(observation);
        observation
    }
    fn scalar(
        &mut self,
        kind: ScalarKind,
        variable: Variable,
        request: Request,
    ) -> lari::Observation {
        let mut value = None;
        if self.locked()
            && let Some(raw) = self.uefi(variable)
            && let Ok(scalar) = Scalar::parse(kind, &raw)
        {
            value = Some(lari::Value {
                value: scalar.value(),
                source: lari::Source::Uefi,
                revision: 0,
            });
        }
        if value.is_none()
            && let Some((0, raw)) = self.acpi(request).as_ref().and_then(wifi_value)
            && (kind != ScalarKind::Country || raw as u32 == 0x434e)
        {
            value = Some(lari::Value {
                value: raw as u32,
                source: lari::Source::Acpi,
                revision: 0,
            });
        }
        value.map_or(lari::Observation::Unavailable, lari::Observation::Observed)
    }
    /// `iwl_acpi_get_object`: an object that fails to evaluate, for any
    /// reason, is absent.
    fn acpi(&mut self, request: Request) -> Option<Object> {
        let result = self.io.evaluate(request);
        self.reads.push(Read::Acpi(request, result.clone()));
        result.ok()
    }
    /// `iwl_uefi_get_variable`: a variable that cannot be read, or is larger
    /// than any table, is absent.
    fn uefi(&mut self, variable: Variable) -> Option<Vec<u8>> {
        let result = self.io.variable(variable);
        self.reads.push(Read::Uefi(variable, result.clone()));
        result.ok().filter(|raw| raw.len() <= MAX_VARIABLE)
    }
    fn locked(&mut self) -> bool {
        if let Some(locked) = self.locked {
            return locked;
        }
        let locked = self
            .acpi(Request::Glai)
            .as_ref()
            .and_then(wifi_value)
            .is_some_and(|(revision, status)| revision == 0 && (1..=2).contains(&status));
        self.locked = Some(locked);
        locked
    }
    fn load_uefi(&mut self) {
        if self.cache.is_some() {
            return;
        }
        if let Some(raw) = self.uefi(Variable::GeneralConfiguration)
            && let Ok(table) = GeneralConfiguration::parse(&raw)
        {
            self.cache = Some(Cache {
                values: core::array::from_fn(|i| table.raw_function(i).unwrap()),
                valid: table.source_function_bitmap(),
                source: lari::Source::Uefi,
                revision: 4,
            });
        }
    }
    fn load_acpi(&mut self) {
        if self.cache.is_some() {
            return;
        }
        let mut cache = Cache {
            values: [0; 15],
            valid: 1,
            source: lari::Source::Acpi,
            revision: 0,
        };
        if let Some(query) = self
            .acpi(Request::Dsm(0))
            .as_ref()
            .and_then(|o| integer(o, 4))
        {
            cache.values[0] = query as u32;
            for index in 1..15u8 {
                if query & (1 << index) == 0 || index == 5 {
                    continue;
                }
                let size = if index <= 2 { 1 } else { 4 };
                if let Some(value) = self
                    .acpi(Request::Dsm(index))
                    .as_ref()
                    .and_then(|o| integer(o, size))
                {
                    // Source truncates integer objects to u32, even for the
                    // expected one-byte functions; only buffer copies use size.
                    cache.values[usize::from(index)] = value as u32;
                    cache.valid |= 1 << index;
                }
            }
        }
        self.cache = Some(cache);
    }
    pub(crate) fn observe(&mut self, input: lari::Input) -> lari::Observation {
        let locked = self.locked();
        let result = match input {
            lari::Input::Dsm(index) => {
                if locked {
                    self.load_uefi();
                }
                // Linux shares this cache between both paths: a valid UEFI
                // cache with a missing function cannot trigger fresh AML reads.
                self.load_acpi();
                let cache = self.cache.as_ref().unwrap();
                (index < 15 && index != 5 && cache.valid & (1 << index) != 0).then(|| lari::Value {
                    value: cache.values[usize::from(index)],
                    source: cache.source,
                    revision: cache.revision,
                })
            }
            lari::Input::WideBandwidth => {
                let mut value = None;
                if locked
                    && let Some(raw) = self.uefi(Variable::Wbem)
                    && let Ok(scalar) = Scalar::parse(ScalarKind::WideBandwidth, &raw)
                {
                    value = Some(lari::Value {
                        value: scalar.value(),
                        source: lari::Source::Uefi,
                        revision: 0,
                    });
                }
                if value.is_none()
                    && let Some((0, raw)) = self
                        .acpi(Request::WideBandwidth)
                        .as_ref()
                        .and_then(wifi_value)
                {
                    value = Some(lari::Value {
                        value: (raw as u32) & 3,
                        source: lari::Source::Acpi,
                        revision: 0,
                    });
                }
                value
            }
        };
        result.map_or(lari::Observation::Unavailable, lari::Observation::Observed)
    }
}
fn integer(object: &Object, size: usize) -> Option<u64> {
    match object {
        Object::Integer(value) => Some(*value),
        Object::Buffer(raw) => {
            let mut bytes = [0; 8];
            let length = size.min(raw.len());
            bytes[..length].copy_from_slice(&raw[..length]);
            Some(u64::from_le_bytes(bytes))
        }
        _ => None,
    }
}
fn wifi_value(object: &Object) -> Option<(i32, u64)> {
    let Object::Package(outer) = object else {
        return None;
    };
    if outer.len() < 2 {
        return None;
    }
    let Object::Integer(revision) = outer[0] else {
        return None;
    };
    for object in &outer[1..] {
        if let Object::Package(inner) = object
            && inner.len() == 2
            && inner[0] == Object::Integer(7)
        {
            return match inner[1] {
                Object::Integer(value) => Some((revision as i32, value)),
                _ => None,
            };
        }
    }
    None
}

#[cfg(test)]
mod tests;
