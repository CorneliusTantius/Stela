// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2021-2026 Intel Corporation
//! Pure owned-observation/resource and packed-package contracts for Intel Wi-Fi
//! UEFI data from fw/uefi.{c,h} and PNVM source policy from fw/pnvm.c.
//! GetVariable calls and permanent EBS/root-switch storage belong to boot.
//! Raw length/hash/provenance integrity does not authenticate a vendor signature
//! or grant redistribution rights, calibration validity or regulatory permission.
use super::identity::Profile;
use crate::firmware as resources;
use alloc::{boxed::Box, format, string::String, vec::Vec};
use stela_crypto::{Sha256, digest::Digest};

pub const WIFI_BT_GUID: &str = "e65d8884-d4af-4b20-8d03-772ecc3da531";
pub const WIFI_GUID: &str = "92daaf2f-c02b-455b-b2ec-f5a3594f4aea";
pub const MAX_VARIABLE_BYTES: usize = 4 * 1024 * 1024 + 14;
/// EFI_NOT_FOUND, the status of a variable the firmware does not have.
pub const NOT_FOUND: u64 = (1 << 63) | 14;
const DATA_LICENSE: &str = "LicenseRef-Local-UEFI-Observation";

/// The initial AX200/AX210 raw capture set. This describes observations only;
/// BIOS permission/GLAI, table revisions and firmware capabilities are separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Variable {
    OemPnvm,
    ReducedPower,
    Step,
    Wrds,
    Ewrd,
    Wgds,
    Ppag,
    Wrdd,
    GeneralConfiguration,
    Wbem,
    Eckv,
    Wtas,
    Splc,
    PhyFilters,
    Sgom,
    Uats,
    Uneb,
    Puncturing,
}
#[derive(Clone, Copy, Debug)]
pub struct VariableDescriptor {
    pub variable: Variable,
    pub name: &'static str,
    pub resource_name: &'static str,
    pub guid: &'static str,
    pub minimum_bytes: usize,
    /// Bounded native collection limit, not a schema-validity declaration.
    pub maximum_bytes: usize,
}
macro_rules! descriptor {
    ($variable:ident, $name:literal, $guid:ident, $minimum:expr, $maximum:expr) => {
        VariableDescriptor {
            variable: Variable::$variable,
            name: $name,
            resource_name: concat!("intel/uefi/", $name, ".bin"),
            guid: $guid,
            minimum_bytes: $minimum,
            maximum_bytes: $maximum,
        }
    };
}
/// Sole descriptor table for raw identity, lookup minima and collection bounds.
/// The 4096-byte native limits preserve a separate BoundExceeded
/// observation; they are not Linux limits or permission to treat data as absent.
pub const VARIABLE_DESCRIPTORS: [VariableDescriptor; 18] = [
    descriptor!(
        OemPnvm,
        "UefiCnvWlanOemSignedPnvm",
        WIFI_GUID,
        14,
        MAX_VARIABLE_BYTES
    ),
    descriptor!(
        ReducedPower,
        "UefiCnvWlanReducedPower",
        WIFI_GUID,
        14,
        MAX_VARIABLE_BYTES
    ),
    descriptor!(
        Step,
        "UefiCnvCommonSTEP",
        WIFI_BT_GUID,
        6,
        MAX_VARIABLE_BYTES
    ),
    descriptor!(Wrds, "UefiCnvWlanWRDS", WIFI_GUID, 49, 53),
    descriptor!(Ewrd, "UefiCnvWlanEWRD", WIFI_GUID, 141, 153),
    descriptor!(Wgds, "UefiCnvWlanWGDS", WIFI_GUID, 74, 98),
    descriptor!(Ppag, "UefiCnvWlanPPAG", WIFI_GUID, 27, 4096),
    descriptor!(Wrdd, "UefiCnvWlanWRDD", WIFI_GUID, 5, 4096),
    descriptor!(
        GeneralConfiguration,
        "UefiCnvWlanGeneralCfg",
        WIFI_GUID,
        129,
        4096
    ),
    descriptor!(Wbem, "UefiCnvWlanWBEM", WIFI_GUID, 5, 4096),
    descriptor!(Eckv, "UefiCnvCommonECKV", WIFI_BT_GUID, 5, 4096),
    descriptor!(Wtas, "UefiCnvWlanWTAS", WIFI_GUID, 38, 4096),
    descriptor!(Splc, "UefiCnvWlanSPLC", WIFI_GUID, 5, 4096),
    descriptor!(PhyFilters, "WPFC", WIFI_GUID, 17, 4096),
    descriptor!(Sgom, "UefiCnvWlanSarGeoOffsetMapping", WIFI_GUID, 339, 4096),
    descriptor!(Uats, "CnvUefiWlanUATS", WIFI_GUID, 339, 4096),
    descriptor!(Uneb, "CnvUefiWlanUNEB", WIFI_GUID, 339, 4096),
    descriptor!(Puncturing, "UefiCnvWlanPuncturing", WIFI_GUID, 5, 4096),
];
pub const RADIO_VARIABLE_COUNT: usize = VARIABLE_DESCRIPTORS.len() - Variable::Wrds as usize;
impl Variable {
    pub fn descriptor(self) -> &'static VariableDescriptor {
        &VARIABLE_DESCRIPTORS[self as usize]
    }
    pub fn name(self) -> &'static str {
        self.descriptor().name
    }
    pub fn resource_name(self) -> &'static str {
        self.descriptor().resource_name
    }
    pub fn guid(self) -> &'static str {
        self.descriptor().guid
    }
    pub fn maximum_bytes(self) -> usize {
        self.descriptor().maximum_bytes
    }
    pub fn bounded_bytes(
        self,
        stage: Stage,
        status: u64,
        reported_bytes: u64,
    ) -> Result<usize, Observation> {
        bounded_bytes(stage, status, reported_bytes, self.maximum_bytes())
    }
    fn origin(self) -> &'static str {
        if self.guid() == WIFI_BT_GUID {
            "UEFI GetVariable e65d8884-d4af-4b20-8d03-772ecc3da531"
        } else {
            "UEFI GetVariable 92daaf2f-c02b-455b-b2ec-f5a3594f4aea"
        }
    }
    pub fn requirement(self) -> resources::Requirement<'static> {
        resources::Requirement {
            name: self.resource_name(),
            target: resources::Target {
                driver: "wifi-intel",
                hardware: if self.guid() == WIFI_BT_GUID {
                    "uefi:e65d8884-d4af-4b20-8d03-772ecc3da531"
                } else {
                    "uefi:92daaf2f-c02b-455b-b2ec-f5a3594f4aea"
                },
                revision: self.name(),
                board: None,
            },
            minimum_bytes: self.descriptor().minimum_bytes,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Probe,
    Read,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Observation {
    #[default]
    NotCaptured,
    Absent {
        stage: Stage,
        status: u64,
        reported_bytes: Option<u64>,
    },
    Failed {
        stage: Stage,
        status: u64,
        reported_bytes: Option<u64>,
    },
    BoundExceeded {
        stage: Stage,
        status: u64,
        reported_bytes: u64,
    },
    Present {
        attributes: u32,
        bytes: u64,
        sha256: [u8; 32],
        probe_reported_bytes: Option<u64>,
    },
}
impl Observation {
    pub fn from_error(stage: Stage, status: u64, reported_bytes: Option<u64>) -> Self {
        if status == NOT_FOUND {
            Self::Absent {
                stage,
                status,
                reported_bytes,
            }
        } else {
            Self::Failed {
                stage,
                status,
                reported_bytes,
            }
        }
    }
    /// Bound a size observed from the real UEFI query *before* allocating.
    /// Zero is returned intact for a successful empty variable; it is
    /// never synthesized to represent an error or absence. No retries occur here.
    pub fn bounded_bytes(stage: Stage, status: u64, reported_bytes: u64) -> Result<usize, Self> {
        bounded_bytes(stage, status, reported_bytes, MAX_VARIABLE_BYTES)
    }
}
fn bounded_bytes(
    stage: Stage,
    status: u64,
    reported_bytes: u64,
    limit: usize,
) -> Result<usize, Observation> {
    if reported_bytes > limit as u64 {
        return Err(Observation::BoundExceeded {
            stage,
            status,
            reported_bytes,
        });
    }
    Ok(reported_bytes as usize)
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observations {
    pub oem_pnvm: Observation,
    pub reduced_power: Observation,
    pub step: Observation,
    /// Raw evidence only; never evaluated GLAI/device ACPI permission.
    pub radio: [Observation; RADIO_VARIABLE_COUNT],
}
impl Observations {
    pub fn set(&mut self, variable: Variable, observation: Observation) {
        match variable {
            Variable::OemPnvm => self.oem_pnvm = observation,
            Variable::ReducedPower => self.reduced_power = observation,
            Variable::Step => self.step = observation,
            variable => self.radio[variable as usize - Variable::Wrds as usize] = observation,
        }
    }
    pub fn get(self, variable: Variable) -> Observation {
        match variable {
            Variable::OemPnvm => self.oem_pnvm,
            Variable::ReducedPower => self.reduced_power,
            Variable::Step => self.step,
            variable => self.radio[variable as usize - Variable::Wrds as usize],
        }
    }
}

fn revision(sha: [u8; 32], attributes: u32) -> String {
    let digest: String = sha.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{digest};attributes:{attributes:08x}")
}
/// Capture metadata over owned temporary bytes or permanent mapped
/// slices. An owned Vec must pass through boot's permanent page handoff before
/// root switch/EBS; this type does not itself reserve or protect its storage.
pub struct CapturedVariable<B = Vec<u8>> {
    variable: Variable,
    observation: Observation,
    revision: String,
    bytes: Option<B>,
}
impl<B: AsRef<[u8]>> CapturedVariable<B> {
    pub fn from_variable(
        variable: Variable,
        bytes: B,
        attributes: u32,
        probe_reported_bytes: Option<u64>,
    ) -> Result<Self, Observation> {
        variable.bounded_bytes(Stage::Read, 0, bytes.as_ref().len() as u64)?;
        let sha256 = Sha256::digest(bytes.as_ref()).into();
        let observation = Observation::Present {
            attributes,
            bytes: bytes.as_ref().len() as u64,
            sha256,
            probe_reported_bytes,
        };
        Ok(Self {
            variable,
            observation,
            revision: revision(sha256, attributes),
            bytes: Some(bytes),
        })
    }
    pub fn observation(&self) -> Observation {
        self.observation
    }
    /// Construct exactly one canonical resource, moving the original buffer
    /// without cloning it. Descriptor borrows need survive Catalog construction
    /// only; boot still owns conversion to permanent reserved-page resources.
    pub fn take_resource(&mut self) -> Option<resources::Resource<'_, B>> {
        let bytes = self.bytes.take()?;
        let Observation::Present { sha256, .. } = self.observation else {
            unreachable!("constructed from actual success")
        };
        Some(resources::Resource {
            name: self.variable.resource_name(),
            target: self.variable.requirement().target,
            provenance: resources::Provenance {
                source: self.variable.origin(),
                revision: &self.revision,
                member: self.variable.name(),
                license: DATA_LICENSE,
            },
            expected_length: bytes.as_ref().len(),
            expected_sha256: sha256,
            bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageError {
    Size,
    WrongVariable,
    Unobserved,
    Absent,
    FailedObservation,
    ObservationMismatch,
}
/// The donor's packed 14-byte wrapper. Header fields remain original metadata:
/// Linux consumes the returned variable length, not an invented total
/// size/revision/SKU-count whitelist. Bare TLV parsers validate its payload.
#[derive(Clone, Copy, Debug)]
pub struct Package<'a> {
    raw: &'a [u8],
    revision: u8,
    total_size: u32,
    skus: u8,
    reserved: [u32; 2],
}
impl<'a> Package<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PackageError> {
        if !(14..=MAX_VARIABLE_BYTES).contains(&bytes.len()) {
            return Err(PackageError::Size);
        }
        let word = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        Ok(Self {
            raw: bytes,
            revision: bytes[0],
            total_size: word(1),
            skus: bytes[5],
            reserved: [word(6), word(10)],
        })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn payload(self) -> &'a [u8] {
        &self.raw[14..]
    }
    pub fn revision(self) -> u8 {
        self.revision
    }
    pub fn declared_total_size(self) -> u32 {
        self.total_size
    }
    pub fn declared_skus(self) -> u8 {
        self.skus
    }
    pub fn reserved(self) -> [u32; 2] {
        self.reserved
    }
}
#[derive(Debug)]
pub enum LoadError {
    Package(PackageError),
    Step(StepError),
    Resource(Box<resources::Error>),
}
/// Borrowed canonical image plus original package metadata. No UEFI read,
/// alternate Provider or image-byte copy happens in this post-EBS consumer.
#[derive(Debug)]
pub struct LoadedPackage<'a> {
    pub image: resources::Image<'a>,
    pub package: Package<'a>,
}
fn load_image<'a>(
    variable: Variable,
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<resources::Image<'a>, LoadError> {
    let (attributes, bytes, sha256) = match observation {
        Observation::Present {
            attributes,
            bytes,
            sha256,
            ..
        } => (attributes, bytes, sha256),
        Observation::NotCaptured => return Err(LoadError::Package(PackageError::Unobserved)),
        Observation::Absent {
            status: NOT_FOUND, ..
        } => return Err(LoadError::Package(PackageError::Absent)),
        _ => return Err(LoadError::Package(PackageError::FailedObservation)),
    };
    let requirement = variable.requirement();
    let image = provider
        .load(requirement)
        .map_err(|e| LoadError::Resource(Box::new(e)))?;
    let p = image.provenance();
    if image.name() != requirement.name
        || image.target() != requirement.target
        || image.bytes().len() as u64 != bytes
        || image.sha256() != sha256
        || p.source != variable.origin()
        || p.revision != revision(sha256, attributes)
        || p.member != variable.name()
        || p.license != DATA_LICENSE
    {
        return Err(LoadError::Package(PackageError::ObservationMismatch));
    }
    Ok(image)
}
/// Keep exact raw radio evidence without interpreting it or granting GLAI,
/// ACPI, vendor-authentication or fallback permission. PNVM and STEP have their
/// separate typed entry points and are refused by this radio-only interface.
pub fn load_radio_image<'a>(
    variable: Variable,
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<resources::Image<'a>, LoadError> {
    if matches!(
        variable,
        Variable::OemPnvm | Variable::ReducedPower | Variable::Step
    ) {
        return Err(LoadError::Package(PackageError::WrongVariable));
    }
    load_image(variable, observation, provider)
}
pub fn load<'a>(
    variable: Variable,
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<LoadedPackage<'a>, LoadError> {
    if !matches!(variable, Variable::OemPnvm | Variable::ReducedPower) {
        return Err(LoadError::Package(PackageError::WrongVariable));
    }
    let image = load_image(variable, observation, provider)?;
    let package = Package::parse(image.bytes()).map_err(LoadError::Package)?;
    Ok(LoadedPackage { image, package })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepError {
    Size,
    Revision(u8),
}
/// Raw6-byte STEP prefix from fw/uefi.h. Extra bytes and the source-ignored
/// step_mode remain metadata. No default mailbox is synthesized for failures.
#[derive(Clone, Copy, Debug)]
pub struct Step<'a> {
    raw: &'a [u8],
}
impl<'a> Step<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, StepError> {
        if !(6..=MAX_VARIABLE_BYTES).contains(&raw.len()) {
            return Err(StepError::Size);
        }
        if raw[0] != 1 {
            return Err(StepError::Revision(raw[0]));
        }
        Ok(Self { raw })
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn step_mode(self) -> u8 {
        self.raw[1]
    }
    pub fn mailboxes(self) -> [u32; 2] {
        [
            u32::from_le_bytes([self.raw[0], self.raw[2], self.raw[3], self.raw[4]]),
            u32::from(self.raw[5]),
        ]
    }
}
#[derive(Debug)]
pub struct StepConfiguration<'a> {
    observation: Observation,
    value: StepValue<'a>,
}
#[derive(Debug)]
enum StepValue<'a> {
    Absent,
    /// Captured but unreadable, or of a revision Linux does not parse.
    Ignored(LoadError),
    Present {
        image: resources::Image<'a>,
        step: Step<'a>,
    },
}
impl<'a> StepConfiguration<'a> {
    pub fn observation(&self) -> Observation {
        self.observation
    }
    pub fn image(&self) -> Option<&resources::Image<'a>> {
        match &self.value {
            StepValue::Absent | StepValue::Ignored(_) => None,
            StepValue::Present { image, .. } => Some(image),
        }
    }
    pub fn step(&self) -> Option<Step<'a>> {
        match self.value {
            StepValue::Absent | StepValue::Ignored(_) => None,
            StepValue::Present { step, .. } => Some(step),
        }
    }
    /// Why a captured STEP variable was left out, when it was.
    pub fn ignored(&self) -> Option<&LoadError> {
        match &self.value {
            StepValue::Ignored(error) => Some(error),
            _ => None,
        }
    }
    pub fn mailboxes(&self) -> [u32; 2] {
        match self.value {
            StepValue::Absent | StepValue::Ignored(_) => [0; 2],
            StepValue::Present { step, .. } => step.mailboxes(),
        }
    }
}

/// `iwl_uefi_get_step_table`: a STEP variable that cannot be read, or whose
/// revision is not 1, leaves both mailboxes zero as an absent one does, and
/// the firmware boots without the equalizer data. The reason is kept.
pub fn load_step_or_ignore<'a>(
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> StepConfiguration<'a> {
    load_step(observation, provider).unwrap_or_else(|error| StepConfiguration {
        observation,
        value: StepValue::Ignored(error),
    })
}

pub fn load_step<'a>(
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<StepConfiguration<'a>, LoadError> {
    if let Observation::Absent {
        status: NOT_FOUND, ..
    } = observation
    {
        return Ok(StepConfiguration {
            observation,
            value: StepValue::Absent,
        });
    }
    let image = load_image(Variable::Step, observation, provider)?;
    let step = Step::parse(image.bytes()).map_err(LoadError::Step)?;
    Ok(StepConfiguration {
        observation,
        value: StepValue::Present { image, step },
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PnvmSource {
    None,
    External,
    Bios { external_fallback: bool },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostAlivePlan {
    pub pnvm: PnvmSource,
    pub observe_reduced_power: bool,
    pub pnvm_completion_required: bool,
}
/// Pure source policy from an actual, valid current-epoch ALIVE SKU. It does
/// not convert an absent/failed BIOS observation into an empty/default image.
/// Fallback follows failure to acquire BIOS data, not failure to match a SKU
/// inside a successfully acquired BIOS image.
pub fn post_alive_plan(profile: &Profile, sku: [u32; 3]) -> PostAlivePlan {
    if sku == [0; 3] {
        return PostAlivePlan {
            pnvm: PnvmSource::None,
            observe_reduced_power: false,
            pnvm_completion_required: false,
        };
    }
    let external = profile.pnvm_request().is_some();
    let pnvm = if sku[2] != 0 {
        PnvmSource::Bios {
            external_fallback: external,
        }
    } else if external {
        PnvmSource::External
    } else {
        PnvmSource::None
    };
    PostAlivePlan {
        pnvm,
        observe_reduced_power: true,
        pnvm_completion_required: true,
    }
}

#[cfg(test)]
mod tests;
