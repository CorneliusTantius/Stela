//! Host-device resources from the selected boot volume and native UEFI before EBS. Unlike
//! a Vec/Arc in the loader heap, this fixed wire representation survives engine
//! relocation. Only immutable bytes in reserved LOADER_DATA pages cross it.
use crate::Result;
use crate::handoff_records::Region;
use alloc::{format, sync::Arc, vec::Vec};
use core::fmt;
use stela_contracts::refuse;
use stela_crypto::digest::Digest;
use stela_drivers::firmware::{Catalog, Provider, Requirement, Target};
use stela_drivers::net::wifi::intel::platform::{
    CapturedVariable, Observation, Observations, VARIABLE_DESCRIPTORS,
};
use stela_loader::host_firmware::{self as manifest, MAX_IMAGES, MAX_MANIFEST_BYTES, Manifest};

pub mod smbios;
pub mod wifi;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Resources {
    pub present: bool,
    pub manifest: Region,
    pub images: [Region; MAX_IMAGES],
    pub count: usize,
    pub wifi: [wifi::Capture; VARIABLE_DESCRIPTORS.len()],
    pub smbios: smbios::Capture,
}
impl Resources {
    pub const fn absent() -> Self {
        Self {
            present: false,
            smbios: smbios::Capture::empty(),
            manifest: Region {
                physical: 0,
                bytes: 0,
            },
            images: [Region {
                physical: 0,
                bytes: 0,
            }; MAX_IMAGES],
            count: 0,
            wifi: [wifi::Capture {
                observation: Observation::NotCaptured,
                region: Region {
                    physical: 0,
                    bytes: 0,
                },
            }; VARIABLE_DESCRIPTORS.len()],
        }
    }

    /// The one log line for a PC whose firmware holds none of the Intel
    /// Wi-Fi variables, in place of a record for each.
    pub fn wifi_summary(&self, phase: &str) -> Option<alloc::string::String> {
        self.wifi
            .iter()
            .all(|capture| matches!(capture.observation, Observation::Absent { .. }))
            .then(|| {
                format!(
                    "HOST WIFI UEFI {phase} none of the {} variables present\n",
                    self.wifi.len()
                )
            })
    }

    pub fn wifi_observations(&self) -> Observations {
        let mut observations = Observations::default();
        for (descriptor, capture) in VARIABLE_DESCRIPTORS.iter().zip(&self.wifi) {
            observations.set(descriptor.variable, capture.observation);
        }
        observations
    }

    /// # Safety
    /// Every region came from this module's reserved LOADER_DATA pages and is
    /// immutable for the boot. `map` must return a permanent mapped alias of the
    /// full range: identity while loading, shared-window physmap in the engine.
    /// No page is reclaimable by the guest/free-page allocator. `log` receives
    /// the phase records and refusals.
    pub unsafe fn catalog(
        &self,
        map: impl Fn(u64) -> u64,
        phase: Option<&'static str>,
        log: fn(fmt::Arguments<'_>),
    ) -> Result<Option<Arc<Catalog>>> {
        if self.count > MAX_IMAGES
            || (!self.present && self.count != 0)
            || (self.present
                && (self.manifest.bytes as usize > MAX_MANIFEST_BYTES || self.manifest.bytes == 0))
        {
            return Err(refuse!("invalid host firmware wire handoff"));
        }
        let view = |region: Region| -> Result<&'static [u8]> {
            let end = region
                .physical
                .checked_add(region.bytes)
                .ok_or(refuse!("host firmware region overflow"))?;
            if region.physical == 0
                || region.bytes == 0
                || map(end - 1) != map(region.physical) + region.bytes - 1
            {
                return Err(refuse!("invalid host firmware mapped range"));
            }
            // SAFETY: caller's reserved immutable pages and permanent alias.
            Ok(unsafe {
                core::slice::from_raw_parts(
                    map(region.physical) as *const u8,
                    region.bytes as usize,
                )
            })
        };
        let manifest_bytes = if self.present {
            Some(view(self.manifest)?)
        } else {
            None
        };
        let parsed = manifest_bytes
            .map(Manifest::parse)
            .transpose()
            .map_err(|error| report(error, log))?;
        if parsed
            .as_ref()
            .is_some_and(|parsed| parsed.images.len() != self.count)
        {
            return Err(refuse!("host firmware wire count mismatch"));
        }
        let mut bytes = Vec::with_capacity(self.count);
        for (image, region) in parsed
            .iter()
            .flat_map(|p| &p.images)
            .zip(&self.images[..self.count])
        {
            if region.bytes != image.length as u64 {
                return Err(refuse!("host firmware wire length mismatch"));
            }
            bytes.push(view(*region)?);
        }
        let mut captures = Vec::new();
        for (variable, capture) in VARIABLE_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.variable)
            .zip(&self.wifi)
        {
            if parsed.as_ref().is_some_and(|parsed| {
                parsed.images.iter().any(|image| {
                    image.name == variable.resource_name()
                        || (image.target.driver == variable.requirement().target.driver
                            && image.target.hardware == variable.requirement().target.hardware
                            && image.target.revision == variable.requirement().target.revision
                            && image.target.board == variable.requirement().target.board)
                })
            }) {
                return Err(refuse!(
                    "installed firmware collides with a live UEFI observation"
                ));
            }
            if let Observation::Present {
                attributes,
                bytes,
                probe_reported_bytes,
                ..
            } = capture.observation
            {
                if bytes > variable.maximum_bytes() as u64 {
                    return Err(refuse!(
                        "Wi-Fi observation wire exceeds its resource budget"
                    ));
                }
                if capture.region.bytes != bytes {
                    return Err(refuse!("Wi-Fi observation wire length mismatch"));
                }
                let raw = if bytes == 0 {
                    &[]
                } else {
                    view(capture.region)?
                };
                let captured = CapturedVariable::from_variable(
                    variable,
                    raw,
                    attributes,
                    probe_reported_bytes,
                )
                .map_err(|_| refuse!("Wi-Fi observation exceeds its permanent resource budget"))?;
                if captured.observation() != capture.observation {
                    return Err(refuse!("Wi-Fi observation wire digest mismatch"));
                }
                captures.push(captured);
            } else if capture.region.bytes != 0 || capture.region.physical != 0 {
                return Err(refuse!("failed Wi-Fi observation has a resource region"));
            }
        }
        if parsed.as_ref().is_some_and(|parsed| {
            parsed.images.iter().any(|image| {
                image.name == stela_drivers::firmware::smbios::NAME
                    || (image.target.driver == stela_drivers::firmware::smbios::TARGET.driver
                        && image.target.hardware
                            == stela_drivers::firmware::smbios::TARGET.hardware
                        && image.target.revision
                            == stela_drivers::firmware::smbios::TARGET.revision
                        && image.target.board.is_none())
            })
        }) {
            return Err(refuse!(
                "installed firmware collides with a live SMBIOS observation"
            ));
        }
        let mut smbios_capture = match self.smbios.state {
            smbios::State::Present => {
                if self.smbios.region.bytes
                    > (stela_drivers::firmware::smbios::MAX_ENTRY_BYTES
                        + stela_drivers::firmware::smbios::MAX_TABLE_BYTES)
                        as u64
                {
                    return Err(refuse!(
                        "SMBIOS observation wire exceeds its resource budget"
                    ));
                }
                let raw = view(self.smbios.region)?;
                if <[u8; 32]>::from(stela_crypto::Sha256::digest(raw)) != self.smbios.sha256 {
                    return Err(refuse!("SMBIOS observation wire digest mismatch"));
                }
                Some(
                    stela_drivers::firmware::smbios::Captured::new(raw)
                        .map_err(|_| refuse!("invalid permanent SMBIOS observation"))?,
                )
            }
            _ => {
                if self.smbios.region.bytes != 0 || self.smbios.region.physical != 0 {
                    return Err(refuse!("unobserved SMBIOS has a resource region"));
                }
                None
            }
        };
        let mut additional: Vec<_> = captures
            .iter_mut()
            .filter_map(CapturedVariable::take_resource)
            .collect();
        additional.extend(
            smbios_capture
                .as_mut()
                .and_then(stela_drivers::firmware::smbios::Captured::take_resource),
        );
        let smbios_identity = additional
            .iter()
            .find(|resource| resource.name == stela_drivers::firmware::smbios::NAME)
            .map(|resource| {
                let raw = resource.bytes;
                let format = self
                    .smbios
                    .format
                    .ok_or(refuse!("SMBIOS wire has no source GUID"))?;
                let length = stela_drivers::firmware::smbios::entry_length(raw, format)
                    .map_err(|_| refuse!("SMBIOS wire source mismatch"))?;
                let entry = stela_drivers::firmware::smbios::entry(&raw[..length], format)
                    .map_err(|_| refuse!("SMBIOS wire source mismatch"))?;
                if <[u8; 32]>::from(stela_crypto::Sha256::digest(&raw[..length]))
                    != self.smbios.entry_sha256
                    || <[u8; 32]>::from(stela_crypto::Sha256::digest(&raw[length..]))
                        != self.smbios.table_sha256
                {
                    return Err(refuse!("SMBIOS observation component digest mismatch"));
                }
                stela_drivers::firmware::smbios::identity(entry, &raw[length..])
                    .map_err(|_| refuse!("invalid SMBIOS identity"))
            })
            .transpose()?;
        if self.count + additional.len() > MAX_IMAGES
            || bytes.iter().map(|b| b.len()).sum::<usize>()
                + additional.iter().map(|r| r.bytes.len()).sum::<usize>()
                > manifest::MAX_TOTAL_BYTES
        {
            return Err(refuse!(
                "combined firmware observations exceed the catalog budget"
            ));
        }
        let records: Vec<_> = phase
            .into_iter()
            .flat_map(|phase| {
                VARIABLE_DESCRIPTORS
                    .iter()
                    .map(|descriptor| descriptor.variable)
                    .zip(&self.wifi)
                    .map(|(variable, capture)| {
                        wifi::record(
                            phase,
                            variable,
                            capture.observation,
                            additional
                                .iter()
                                .find(|resource| resource.name == variable.resource_name()),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let smbios_record = phase.map(|phase| smbios::record(phase, &self.smbios, smbios_identity));
        if let Some(phase) = phase {
            log(format_args!(
                "{}",
                smbios::summary(phase, &self.smbios, smbios_identity)
            ));
        }
        if !self.present && additional.is_empty() {
            if let Some(record) = smbios_record {
                log(format_args!("HOST SMBIOS RECORD {record}\n"));
            }
            match phase.and_then(|phase| self.wifi_summary(phase)) {
                Some(summary) => log(format_args!("{summary}")),
                None => {
                    for record in records {
                        log(format_args!("HOST WIFI UEFI RECORD {record}\n"));
                    }
                }
            }
            return Ok(None);
        }
        let catalog = Arc::new(if let Some(parsed) = &parsed {
            parsed
                .catalog_with(&bytes, additional)
                .map_err(|error| report(error, log))?
        } else {
            Catalog::from_persistent_handoff(additional)
                .map_err(|_| refuse!("invalid permanent Wi-Fi resources"))?
        });
        if let Some(record) = smbios_record {
            // Canonical lookup also checks returned image identity/provenance.
            if self.smbios.state == smbios::State::Present {
                let _ = stela_drivers::firmware::smbios::load(catalog.as_ref())
                    .map_err(|_| refuse!("SMBIOS canonical resource binding mismatch"))?;
            }
            log(format_args!("HOST SMBIOS RECORD {record}\n"));
        }
        match phase.and_then(|phase| self.wifi_summary(phase)) {
            Some(summary) => log(format_args!("{summary}")),
            None => {
                for record in records {
                    log(format_args!("HOST WIFI UEFI RECORD {record}\n"));
                }
            }
        }
        if let Some(phase) = phase
            && let (Some(manifest_bytes), Some(parsed)) = (manifest_bytes, &parsed)
        {
            record(phase, manifest_bytes, parsed, &catalog, log)?;
        }
        Ok(Some(catalog))
    }
}

/// JSON escaping makes literal quotes/backslashes in bounded identity labels
/// unambiguous. Records come from the validated catalog in this phase,
/// including an exact provider lookup for each manifest-selected requirement.
fn record(
    phase: &str,
    manifest_bytes: &[u8],
    manifest: &Manifest<'_>,
    catalog: &Catalog,
    log: fn(fmt::Arguments<'_>),
) -> Result<()> {
    let images = manifest.images.len();
    let bytes: usize = manifest.images.iter().map(|image| image.length).sum();
    let record = serde_json::json!({
        "kind": "manifest", "phase": phase, "images": images, "bytes": bytes,
        "sha256": stela_formats::sha256(manifest_bytes),
    });
    log(format_args!("HOST FIRMWARE RECORD {record}\n"));
    for (index, expected) in manifest.images.iter().enumerate() {
        let image = catalog
            .load(Requirement {
                name: expected.name,
                target: Target {
                    driver: expected.target.driver,
                    hardware: expected.target.hardware,
                    revision: expected.target.revision,
                    board: expected.target.board,
                },
                minimum_bytes: expected.length,
            })
            .map_err(|_| refuse!("cannot record verified host firmware requirement"))?;
        let target = image.target();
        let source = image.provenance();
        let digest: alloc::string::String = image
            .sha256()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let record = serde_json::json!({
            "kind": "resource", "phase": phase, "index": index,
            "name": image.name(), "bytes": image.bytes().len(), "sha256": digest,
            "target": {"driver": target.driver, "hardware": target.hardware,
                "revision": target.revision, "board": target.board},
            "provenance": {"source": source.source, "revision": source.revision,
                "member": source.member, "license": source.license},
        });
        log(format_args!("HOST FIRMWARE RECORD {record}\n"));
    }
    Ok(())
}

pub fn report(error: manifest::Error, log: fn(fmt::Arguments<'_>)) -> &'static str {
    log(format_args!("HOST FIRMWARE refused: {error}\n"));
    "invalid host firmware resources"
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::net::wifi::intel::platform::Variable;

    #[test]
    fn absent_wifi_variables_take_one_line() {
        let mut resources = Resources::absent();
        assert_eq!(resources.wifi_summary("pre-ebs"), None);
        for capture in &mut resources.wifi {
            capture.observation = Observation::Absent {
                stage: stela_drivers::net::wifi::intel::platform::Stage::Probe,
                status: 14,
                reported_bytes: None,
            };
        }
        assert_eq!(
            resources.wifi_summary("pre-ebs").as_deref(),
            Some(
                format!(
                    "HOST WIFI UEFI pre-ebs none of the {} variables present\n",
                    VARIABLE_DESCRIPTORS.len()
                )
                .as_str()
            )
        );
    }

    #[test]
    fn installed_resources_cannot_substitute_a_live_observation_name_or_target() {
        static RAW: [u8; 14] = [1; 14];
        for (requirement, collide_name) in [
            Variable::Step.requirement(),
            Variable::Eckv.requirement(),
            Variable::PhyFilters.requirement(),
            stela_drivers::firmware::smbios::REQUIREMENT,
        ]
        .into_iter()
        .flat_map(|requirement| [true, false].map(|collide| (requirement, collide)))
        {
            let target = requirement.target;
            let digest = stela_formats::sha256(&RAW);
            let manifest = serde_json::json!({"schema":1,"images":[{
                "name":if collide_name {requirement.name} else {"synthetic/raw.bin"},
                "path":"raw.bin","length":RAW.len(),"sha256":digest,
                "target":if collide_name {serde_json::json!({"driver":"fixture","hardware":"synthetic","revision":"v1","board":null})} else {serde_json::json!({"driver":target.driver,"hardware":target.hardware,"revision":target.revision,"board":target.board})},
                "provenance":{"source":"synthetic","revision":"v1","member":"raw.bin","license":"CC0-1.0"}
            }]});
            let bytes =
                alloc::boxed::Box::leak(serde_json::to_vec(&manifest).unwrap().into_boxed_slice());
            let mut resources = Resources::absent();
            resources.present = true;
            resources.count = 1;
            resources.manifest = Region {
                physical: bytes.as_ptr() as u64,
                bytes: bytes.len() as u64,
            };
            resources.images[0] = Region {
                physical: RAW.as_ptr() as u64,
                bytes: RAW.len() as u64,
            };
            assert_eq!(
                // SAFETY: these immutable static fixture aliases cover every byte.
                unsafe { resources.catalog(|address| address, None, |_| {}) }
                    .err()
                    .unwrap(),
                refuse!(
                    if requirement.name == stela_drivers::firmware::smbios::NAME {
                        "installed firmware collides with a live SMBIOS observation"
                    } else {
                        "installed firmware collides with a live UEFI observation"
                    }
                )
            );
        }
    }

    #[test]
    fn physical_host_identity_uses_one_immutable_catalog_image_across_wire_copy() {
        use stela_drivers::firmware::smbios as host;
        let mut table = alloc::vec![1, 8, 1, 0, 1, 0, 2, 0];
        table.extend_from_slice(b"SYNTH-HOST\0SYNTH-VERSION\0\0");
        table.extend_from_slice(&[127, 4, 255, 255, 0, 0]);
        let mut bytes = alloc::vec![0;24];
        bytes[..5].copy_from_slice(b"_SM3_");
        bytes[6] = 24;
        bytes[7] = 3;
        bytes[8] = 8;
        bytes[10] = 1;
        bytes[12..16].copy_from_slice(&(table.len() as u32).to_le_bytes());
        bytes[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        bytes[5] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)));
        bytes.extend_from_slice(&table);
        let raw = alloc::boxed::Box::leak(bytes.into_boxed_slice());
        let mut resources = Resources::absent();
        resources.smbios = smbios::Capture {
            state: smbios::State::Present,
            region: Region {
                physical: 0x1000,
                bytes: raw.len() as u64,
            },
            format: Some(host::Format::Smbios3),
            source_address: 0x3000,
            sha256: stela_crypto::Sha256::digest(&*raw).into(),
            entry_sha256: stela_crypto::Sha256::digest(&raw[..24]).into(),
            table_sha256: stela_crypto::Sha256::digest(&raw[24..]).into(),
        };
        let copied = resources;
        // SAFETY: the static complete fixture models the permanent new alias.
        let catalog = unsafe {
            copied.catalog(
                |address| address - 0x1000 + raw.as_ptr() as u64,
                None,
                |_| {},
            )
        }
        .unwrap()
        .unwrap();
        let snapshot = host::load(catalog.as_ref()).unwrap();
        assert_eq!(snapshot.image.bytes().as_ptr(), raw.as_ptr());
        assert_eq!(
            snapshot.identity.system_vendor,
            host::Observation::Value(&b"SYNTH-HOST\0"[..])
        );
        assert_eq!(snapshot.identity.product_name, host::Observation::Absent);
        assert_eq!(
            snapshot.identity.product_version,
            host::Observation::Value(&b"SYNTH-VERSION\0"[..])
        );
        assert_eq!(catalog.inventory(), (1, raw.len()));
        resources.smbios.region.bytes = (host::MAX_ENTRY_BYTES + host::MAX_TABLE_BYTES + 1) as u64;
        assert_eq!(
            // SAFETY: invalid wire must refuse before invoking any mapper.
            unsafe {
                resources.catalog(|_| panic!("over-bound SMBIOS must not map"), None, |_| {})
            }
            .err(),
            Some(refuse!(
                "SMBIOS observation wire exceeds its resource budget"
            ))
        );
        resources = copied;
        resources.smbios.sha256[0] ^= 1;
        assert_eq!(
            // SAFETY: same complete static fixture with wrong digest.
            unsafe {
                resources.catalog(
                    |address| address - 0x1000 + raw.as_ptr() as u64,
                    None,
                    |_| {},
                )
            }
            .err(),
            Some(refuse!("SMBIOS observation wire digest mismatch"))
        );
    }

    #[test]
    fn radio_wire_bounds_refuse_before_mapping_and_valid_pages_keep_identity() {
        static RAW: [u8; 14] = [0xa5; 14];
        for descriptor in &VARIABLE_DESCRIPTORS[3..] {
            let mut resources = Resources::absent();
            let over = descriptor.maximum_bytes as u64 + 1;
            resources.wifi[descriptor.variable as usize] = wifi::Capture {
                observation: Observation::Present {
                    attributes: 7,
                    bytes: over,
                    sha256: [0; 32],
                    probe_reported_bytes: Some(over),
                },
                region: Region {
                    physical: 0x1000,
                    bytes: over,
                },
            };
            assert_eq!(
                // SAFETY: invalid bounds must be rejected before creating a view.
                unsafe {
                    resources.catalog(|_| panic!("over-limit wire must not map"), None, |_| {})
                }
                .err(),
                Some(refuse!(
                    "Wi-Fi observation wire exceeds its resource budget"
                ))
            );
        }
        let variable = Variable::Eckv;
        let captured = CapturedVariable::from_variable(variable, &RAW[..], 7, Some(14)).unwrap();
        let mut resources = Resources::absent();
        resources.wifi[variable as usize] = wifi::Capture {
            observation: captured.observation(),
            region: Region {
                physical: 0x1000,
                bytes: 14,
            },
        };
        // SAFETY: complete static fixture models the reserved permanent alias.
        let catalog = unsafe {
            resources.catalog(
                |address| address - 0x1000 + RAW.as_ptr() as u64,
                None,
                |_| {},
            )
        }
        .unwrap()
        .unwrap();
        let image = stela_drivers::net::wifi::intel::platform::load_radio_image(
            variable,
            resources.wifi_observations().get(variable),
            catalog.as_ref(),
        )
        .unwrap();
        assert_eq!(image.bytes().as_ptr(), RAW.as_ptr());
        assert_eq!(image.bytes(), RAW);
        assert_eq!(image.target(), variable.requirement().target);
        assert_eq!(catalog.inventory(), (1, 14));
    }

    #[test]
    fn raw_observations_reconstruct_through_permanent_mapping_without_byte_copies() {
        static RAW: [u8; 14] = [1; 14];
        let capture =
            CapturedVariable::from_variable(Variable::OemPnvm, &RAW[..], 0x87, Some(18)).unwrap();
        let mut resources = Resources::absent();
        resources.wifi[0] = wifi::Capture {
            observation: capture.observation(),
            region: Region {
                physical: 0x1000,
                bytes: 14,
            },
        };
        let copied = resources;
        // SAFETY: the mapper returns the complete immutable static fixture,
        // modeling the reserved region's new permanent alias after relocation.
        let catalog = unsafe {
            copied.catalog(
                |address| address - 0x1000 + RAW.as_ptr() as u64,
                None,
                |_| {},
            )
        }
        .unwrap()
        .unwrap();
        let image = catalog.load(Variable::OemPnvm.requirement()).unwrap();
        assert_eq!(image.bytes().as_ptr(), RAW.as_ptr());
        assert_eq!(image.bytes(), RAW);
        assert_eq!(
            image.provenance().license,
            "LicenseRef-Local-UEFI-Observation"
        );
        assert_eq!(copied.wifi_observations(), resources.wifi_observations());
        assert_eq!(
            copied.wifi_observations().reduced_power,
            Observation::NotCaptured
        );
        assert_eq!(catalog.inventory(), (1, 14));
        resources.wifi[0].region.bytes = 13;
        assert!(
            // SAFETY: the same static mapping; invalid wire length must be rejected.
            unsafe {
                resources.catalog(
                    |address| address - 0x1000 + RAW.as_ptr() as u64,
                    None,
                    |_| {},
                )
            }
            .is_err()
        );
        resources.wifi[0].region.bytes = 14;
        resources.wifi[0].observation = Observation::Failed {
            stage: stela_drivers::net::wifi::intel::platform::Stage::Read,
            status: 0,
            reported_bytes: Some(15),
        };
        assert!(
            // SAFETY: invalid failed-with-region metadata is rejected before mapping.
            unsafe { resources.catalog(|_| panic!("failed resources must not map"), None, |_| {}) }
                .is_err()
        );
        resources.wifi[0].observation = Observation::Present {
            attributes: 0,
            bytes: u64::MAX,
            sha256: [0; 32],
            probe_reported_bytes: Some(u64::MAX),
        };
        resources.wifi[0].region.bytes = u64::MAX;
        assert!(
            // SAFETY: the wire budget is checked before any slice/map operation.
            unsafe { resources.catalog(|_| panic!("oversized wire must not map"), None, |_| {}) }
                .is_err()
        );
    }
}
