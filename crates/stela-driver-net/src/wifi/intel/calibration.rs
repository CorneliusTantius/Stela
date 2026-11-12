// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2020-2026 Intel Corporation
//! ALIVE-selected canonical PNVM/reduced-power resource acquisition, matching
//! fw/pnvm.c and fw/uefi.c. Raw integrity never authenticates vendor data.
use super::{
    firmware::Family,
    identity::Profile,
    platform::{self, Observation, Observations, PnvmSource, Variable},
    pnvm,
};
use crate::firmware as resources;
use alloc::{boxed::Box, vec::Vec};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Observation {
        variable: Variable,
        observation: Observation,
    },
    Package(platform::PackageError),
    Step(platform::StepError),
    Resource(Box<resources::Error>),
    Binding,
    Selection(pnvm::Error),
}
impl From<platform::LoadError> for Error {
    fn from(error: platform::LoadError) -> Self {
        match error {
            platform::LoadError::Package(e) => Self::Package(e),
            platform::LoadError::Step(e) => Self::Step(e),
            platform::LoadError::Resource(e) => Self::Resource(e),
        }
    }
}
impl From<pnvm::Error> for Error {
    fn from(value: pnvm::Error) -> Self {
        Self::Selection(value)
    }
}

/// Acquisition outcome, kept even when source policy allows an
/// unavailable BIOS variable or explicitly selects its external fallback.
#[derive(Clone, Copy, Debug)]
pub enum Source<'a> {
    NotRequired,
    Unavailable {
        observation: Observation,
    },
    Bios {
        observation: Observation,
        image: resources::Image<'a>,
    },
    External {
        image: resources::Image<'a>,
        bios_fallback: Option<Observation>,
    },
    /// The table was required but could not be acquired or matched to the
    /// SKU. As `iwl_pnvm_load_pnvm_to_trans` and
    /// `iwl_pnvm_load_reduce_power_to_trans` do, nothing is handed to the
    /// firmware for it, the doorbell still rings and the firmware runs on
    /// its built-in defaults; the reason is in [`Receipts::skipped`].
    Skipped,
}
#[derive(Debug)]
pub struct Receipts<'a> {
    pub pnvm: Source<'a>,
    pub pnvm_version: Option<u32>,
    pub reduced_power: Source<'a>,
    pub transfer: Transfer,
    /// Why each [`Source::Skipped`] table was left out, PNVM first.
    pub skipped: Vec<Error>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transfer {
    NotRequired,
    ScratchV2,
    NotUsedBeforeAx210,
}
pub(super) struct Prepared<'a> {
    pub receipts: Receipts<'a>,
    pub pnvm: Vec<pnvm::Chunk<'a>>,
    pub reduced_power: Vec<pnvm::Chunk<'a>>,
}

fn unavailable(variable: Variable, observation: Observation) -> Result<bool, Error> {
    match observation {
        Observation::Absent { status, .. } if status == (1 << 63) | 14 => Ok(true),
        Observation::Failed { status, .. } if status & (1 << 63) != 0 => Ok(true),
        // Linux cannot obtain a package payload from a successful variable
        // shorter than its packed header. Preserve that observation.
        Observation::Present { bytes, .. } if bytes < 14 => Ok(true),
        Observation::Present { .. } => Ok(false),
        _ => Err(Error::Observation {
            variable,
            observation,
        }),
    }
}
fn external<'a>(
    profile: &Profile,
    provider: &'a dyn resources::Provider,
) -> Result<resources::Image<'a>, Error> {
    let request = profile.pnvm_request().ok_or(Error::Binding)?;
    let image = profile
        .load(request.name, provider)
        .map_err(|e| Error::Resource(Box::new(e)))?;
    // A Provider implementation is allowed to be independently supplied;
    // never trust a redirected diagnostic/other-board image as this request.
    if !profile.binds(request.name, &image) {
        return Err(Error::Binding);
    }
    Ok(image)
}
fn bios<'a>(
    variable: Variable,
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<platform::LoadedPackage<'a>, Error> {
    let loaded = platform::load(variable, observation, provider)?;
    let requirement = variable.requirement();
    if loaded.image.name() != requirement.name || loaded.image.target() != requirement.target {
        return Err(Error::Binding);
    }
    Ok(loaded)
}

/// Only the owning ROM epoch calls this with its private decoded SKU;
/// this helper grants no upload, signature, firmware status or radio permission.
pub(super) fn prepare<'a>(
    profile: &Profile,
    sku: [u32; 3],
    observations: Observations,
    provider: &'a dyn resources::Provider,
) -> Result<Prepared<'a>, Error> {
    let plan = platform::post_alive_plan(profile, sku);
    if !plan.pnvm_completion_required {
        return Ok(Prepared {
            receipts: Receipts {
                pnvm: Source::NotRequired,
                pnvm_version: None,
                reduced_power: Source::NotRequired,
                transfer: Transfer::NotRequired,
                skipped: Vec::new(),
            },
            pnvm: Vec::new(),
            reduced_power: Vec::new(),
        });
    }
    let mut skipped = Vec::new();
    // A provider that answers with another file's binding is a broken
    // catalog, not a missing table, and stays a failure.
    let (source, pnvm, pnvm_version) =
        match pnvm_tables(profile, sku, plan.pnvm, observations, provider) {
            Ok(tables) => tables,
            Err(Error::Binding) => return Err(Error::Binding),
            Err(error) => {
                skipped.push(error);
                (Source::Skipped, Vec::new(), None)
            }
        };
    let (reduced_source, reduced_power) =
        match reduced_power_tables(sku, observations.reduced_power, provider) {
            Ok(tables) => tables,
            Err(Error::Binding) => return Err(Error::Binding),
            Err(error) => {
                skipped.push(error);
                (Source::Skipped, Vec::new())
            }
        };
    Ok(Prepared {
        receipts: Receipts {
            pnvm: source,
            pnvm_version,
            reduced_power: reduced_source,
            transfer: if profile.family() >= Family::Ax210 {
                Transfer::ScratchV2
            } else {
                Transfer::NotUsedBeforeAx210
            },
            skipped,
        },
        pnvm,
        reduced_power,
    })
}

type PnvmTables<'a> = (Source<'a>, Vec<pnvm::Chunk<'a>>, Option<u32>);

/// `iwl_get_pnvm_image` and `iwl_pnvm_parse`: the BIOS image for a non-Intel
/// SKU, the file beside the firmware when the BIOS has none it can read, and
/// the sections of this SKU in whichever was found.
fn pnvm_tables<'a>(
    profile: &Profile,
    sku: [u32; 3],
    source: PnvmSource,
    observations: Observations,
    provider: &'a dyn resources::Provider,
) -> Result<PnvmTables<'a>, Error> {
    let (source, data) = match source {
        PnvmSource::None => return Ok((Source::NotRequired, Vec::new(), None)),
        PnvmSource::External => {
            let image = external(profile, provider)?;
            (
                Source::External {
                    image,
                    bios_fallback: None,
                },
                image.bytes(),
            )
        }
        PnvmSource::Bios { external_fallback } => {
            let observation = observations.oem_pnvm;
            let read = match unavailable(Variable::OemPnvm, observation) {
                Ok(true) => None,
                Ok(false) => Some(bios(Variable::OemPnvm, observation, provider)),
                Err(error) => Some(Err(error)),
            };
            match read {
                Some(Ok(loaded)) => (
                    Source::Bios {
                        observation,
                        image: loaded.image,
                    },
                    loaded.package.payload(),
                ),
                Some(Err(Error::Binding)) => return Err(Error::Binding),
                // Whatever kept the BIOS image out, the file stands in.
                _ if external_fallback => {
                    let image = external(profile, provider)?;
                    (
                        Source::External {
                            image,
                            bios_fallback: Some(observation),
                        },
                        image.bytes(),
                    )
                }
                Some(Err(error)) => return Err(error),
                None => return Ok((Source::Unavailable { observation }, Vec::new(), None)),
            }
        }
    };
    // A BIOS image that holds no section for this SKU does not switch to the
    // file either: Linux gives up on PNVM for this boot.
    let selection = pnvm::Pnvm::parse(data)?.select(profile, sku)?;
    Ok((source, selection.chunks().to_vec(), selection.version()))
}

/// `iwl_uefi_get_reduced_power` and `iwl_uefi_reduce_power_parse`.
fn reduced_power_tables<'a>(
    sku: [u32; 3],
    observation: Observation,
    provider: &'a dyn resources::Provider,
) -> Result<(Source<'a>, Vec<pnvm::Chunk<'a>>), Error> {
    if unavailable(Variable::ReducedPower, observation)? {
        return Ok((Source::Unavailable { observation }, Vec::new()));
    }
    let loaded = bios(Variable::ReducedPower, observation, provider)?;
    let selection = pnvm::Pnvm::parse(loaded.package.payload())?.select_reduced_power(sku)?;
    Ok((
        Source::Bios {
            observation,
            image: loaded.image,
        },
        selection.chunks().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::identity::Observed;
    use super::*;
    use resources::{Catalog, Provenance, Provider, Resource, Target};
    use sha2::{Digest, Sha256};
    #[test]
    fn only_native_errors_absence_or_short_packages_allow_acquisition_fallback() {
        use platform::Stage;
        for observation in [
            Observation::NotCaptured,
            Observation::Absent {
                stage: Stage::Read,
                status: 0,
                reported_bytes: None,
            },
            Observation::Failed {
                stage: Stage::Read,
                status: 7,
                reported_bytes: None,
            },
            Observation::BoundExceeded {
                stage: Stage::Read,
                status: 0,
                reported_bytes: platform::MAX_VARIABLE_BYTES as u64 + 1,
            },
        ] {
            assert!(matches!(
                unavailable(Variable::OemPnvm, observation),
                Err(Error::Observation { .. })
            ));
        }
        for observation in [
            Observation::from_error(Stage::Probe, (1 << 63) | 14, None),
            Observation::from_error(Stage::Read, (1 << 63) | 7, None),
        ] {
            assert_eq!(unavailable(Variable::OemPnvm, observation), Ok(true));
        }
        for bytes in 0..=14 {
            let observation = Observation::Present {
                attributes: 7,
                bytes,
                sha256: [0; 32],
                probe_reported_bytes: None,
            };
            assert_eq!(unavailable(Variable::OemPnvm, observation), Ok(bytes < 14));
        }
    }
    #[test]
    fn redirected_external_filename_target_or_board_never_reaches_payload_selection() {
        struct Redirect<'a>(resources::Image<'a>);
        impl Provider for Redirect<'_> {
            fn load<'p>(
                &'p self,
                _: resources::Requirement<'_>,
            ) -> Result<resources::Image<'p>, resources::Error> {
                Ok(self.0)
            }
        }
        let profile = Profile::select(Observed {
            link_speed: 3,
            silicon: Default::default(),
            vendor: 0x8086,
            device: 0x2725,
            subsystem_vendor: 0x8086,
            subsystem_device: 0x84,
            pci_revision: 0x1a,
            hardware_revision: 0x420,
            radio_id: 0x10d000,
        })
        .unwrap();
        for mode in 0..3 {
            let request = profile.pnvm_request().unwrap();
            let expected = request.requirement();
            let mut target = expected.target;
            let mut name = expected.name;
            if mode == 0 {
                name = "diagnostic.pnvm";
            }
            if mode == 1 {
                target = Target {
                    driver: "different-driver",
                    ..target
                };
            }
            if mode == 2 {
                target.board = Some("different-board");
            }
            let bytes = vec![0x5a; 16];
            let catalog = Catalog::from_handoff(vec![Resource {
                name,
                target,
                provenance: Provenance {
                    source: "test",
                    revision: "immutable",
                    member: name,
                    license: "LicenseRef-Local-Test-Fixture",
                },
                expected_length: bytes.len(),
                expected_sha256: Sha256::digest(&bytes).into(),
                bytes,
            }])
            .unwrap();
            let image = catalog
                .load(resources::Requirement {
                    name,
                    target,
                    minimum_bytes: 1,
                })
                .unwrap();
            let provider = Redirect(image);
            assert!(matches!(
                prepare(
                    &profile,
                    [0x610d0, 0, 0],
                    Observations::default(),
                    &provider
                ),
                Err(Error::Binding)
            ));
        }
    }
}
