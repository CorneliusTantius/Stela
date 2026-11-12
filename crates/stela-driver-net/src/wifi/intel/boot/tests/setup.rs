// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

pub(super) fn profile() -> Profile {
    Profile::select(Observed {
        link_speed: 3,
        silicon: Default::default(),
        vendor: 0x8086,
        device: 0x2723,
        subsystem_vendor: 0x8086,
        subsystem_device: 0x84,
        pci_revision: 0x1a,
        hardware_revision: 0x340,
        radio_id: 0x10a000,
    })
    .unwrap()
}

pub(super) fn awake(state: Arc<Mutex<ModelState>>, drops: Arc<AtomicUsize>) -> Power<Model> {
    awake_profile(state, drops, profile())
}

pub(super) fn awake_profile(
    state: Arc<Mutex<ModelState>>,
    drops: Arc<AtomicUsize>,
    profile: Profile,
) -> Power<Model> {
    let mut power = Power::new(
        Model {
            state: state.clone(),
            _owner: Owner(drops),
        },
        profile,
    );
    power.wake(ManagementSession::NotConnected).unwrap();
    state.lock().unwrap().ops.clear();
    power
}

pub(super) fn catalog_for(profile: &Profile, name: &str, bytes: &[u8]) -> resources::Catalog {
    let request = profile.firmware_request();
    catalog_for_target(request.requirement().target, name, bytes)
}

pub(super) fn catalog_for_target(
    target: resources::Target<'_>,
    name: &str,
    bytes: &[u8],
) -> resources::Catalog {
    use sha2::{Digest, Sha256};
    resources::Catalog::from_handoff(vec![resources::Resource {
        name,
        target,
        provenance: resources::Provenance {
            source: "test",
            revision: "immutable",
            member: name,
            license: "LicenseRef-Local-Test-Fixture",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(bytes).into(),
        bytes: bytes.to_vec(),
    }])
    .unwrap()
}

fn tlv(bytes: &mut Vec<u8>, kind: u32, data: &[u8]) {
    bytes.extend(kind.to_le_bytes());
    bytes.extend((data.len() as u32).to_le_bytes());
    bytes.extend(data);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}

/// A PNVM file for `profile` whose tables are for `sku`.
fn pnvm_file(profile: &Profile, sku: [u32; 3]) -> Vec<u8> {
    let mut pnvm = Vec::new();
    let sku_bytes: Vec<_> = sku.into_iter().flat_map(u32::to_le_bytes).collect();
    tlv(&mut pnvm, 64, &sku_bytes);
    let observed = profile.observed();
    let mut hw = Vec::new();
    hw.extend((((observed.hardware_revision & 0xfff0) >> 4) as u16).to_le_bytes());
    hw.extend((((observed.radio_id & 0xfff000) >> 12) as u16).to_le_bytes());
    tlv(&mut pnvm, 58, &hw);
    tlv(&mut pnvm, 62, &0x12345678u32.to_le_bytes());
    for n in 0..2 {
        let mut chunk = (0x1234u32 + n).to_le_bytes().to_vec();
        chunk.extend(vec![0x40 + n as u8; 16 + n as usize]);
        tlv(&mut pnvm, 19, &chunk);
    }
    pnvm
}

/// One catalog of `profile`'s firmware `image` and the PNVM file beside it,
/// its tables for `sku`.
pub(super) fn catalog_with_pnvm(
    profile: &Profile,
    image: &[u8],
    sku: [u32; 3],
) -> resources::Catalog {
    use sha2::{Digest, Sha256};
    let resource = |name, target, bytes: Vec<u8>| resources::Resource {
        name,
        target,
        provenance: resources::Provenance {
            source: "test",
            revision: "immutable",
            member: name,
            license: "LicenseRef-Local-Test-Fixture",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(&bytes).into(),
        bytes,
    };
    let firmware = profile.firmware_request();
    let pnvm = profile.pnvm_request().expect("a PNVM file");
    resources::Catalog::from_handoff(vec![
        resource(firmware.name, firmware.requirement().target, image.to_vec()),
        resource(
            pnvm.name,
            pnvm.requirement().target,
            pnvm_file(profile, sku),
        ),
    ])
    .unwrap()
}

pub(super) fn phase_catalog(
    profile: &Profile,
    sku: [u32; 3],
    bios: bool,
    reduced: bool,
) -> (Observations, resources::Catalog) {
    use crate::wifi::intel::platform::{CapturedVariable, Observation, Stage, Variable};
    use sha2::{Digest, Sha256};
    let pnvm = pnvm_file(profile, sku);
    let sku_bytes: Vec<_> = sku.into_iter().flat_map(u32::to_le_bytes).collect();
    let mut power = Vec::new();
    tlv(&mut power, 64, &sku_bytes);
    for n in 0..2 {
        let mut chunk = (0xf0000000u32 + n).to_le_bytes().to_vec();
        chunk.extend((12u32 + n).to_le_bytes());
        chunk.extend(vec![0x60 + n as u8; 12 + n as usize]);
        tlv(&mut power, 7, &chunk);
    }
    let mut ppackage = vec![0; 14];
    ppackage.extend(&pnvm);
    let mut rpackage = vec![0; 14];
    rpackage.extend(power);
    let mut pc = CapturedVariable::from_variable(Variable::OemPnvm, ppackage, 7, None).unwrap();
    let mut rc =
        CapturedVariable::from_variable(Variable::ReducedPower, rpackage, 7, None).unwrap();
    let absent = Observation::from_error(Stage::Probe, (1 << 63) | 14, None);
    let observations = Observations {
        oem_pnvm: if bios { pc.observation() } else { absent },
        reduced_power: if reduced { rc.observation() } else { absent },
        step: Observation::NotCaptured,
        ..Observations::default()
    };
    let mut resources = Vec::new();
    if bios {
        resources.push(pc.take_resource().unwrap());
    }
    if reduced {
        resources.push(rc.take_resource().unwrap());
    }
    let request = profile.pnvm_request();
    if let Some(ref request) = request {
        resources.push(resources::Resource {
            name: request.name,
            target: request.requirement().target,
            provenance: resources::Provenance {
                source: "test",
                revision: "immutable",
                member: request.name,
                license: "LicenseRef-Local-Test-Fixture",
            },
            expected_length: pnvm.len(),
            expected_sha256: Sha256::digest(&pnvm).into(),
            bytes: pnvm,
        });
    }
    (
        observations,
        resources::Catalog::from_handoff(resources).unwrap(),
    )
}

pub(super) fn start<'a>(
    catalog: &'a resources::Catalog,
    source: &Source,
    domain: &Arc<Domain>,
    state: &Arc<Mutex<ModelState>>,
    drops: &Arc<AtomicUsize>,
) -> Ax200Boot<'a, Model> {
    // SAFETY: fixture owns fresh host RAM and a synchronous isolated
    // coherent domain/device; no IRQ, competing worker or real DMA exists.
    unsafe {
        Ax200Boot::start(
            awake(state.clone(), drops.clone()),
            crate::wifi::intel::identity::stage(&profile(), catalog).unwrap(),
            source,
            Some(domain.clone()),
            32,
        )
        .unwrap()
    }
}

pub(super) fn ax210_profile() -> Profile {
    let mut observed = profile().observed();
    observed.device = 0x2725;
    observed.hardware_revision = 0x420;
    observed.radio_id = 0x10d000;
    Profile::select(observed).unwrap()
}

/// A BE200, of the Bz family, with its FM radio.
pub(super) fn be200_profile() -> Profile {
    let mut observed = profile().observed();
    observed.device = 0x272b;
    observed.hardware_revision = 0x472;
    observed.radio_id = 0x112200;
    Profile::select(observed).unwrap()
}

pub(super) fn ax210_state() -> Arc<Mutex<ModelState>> {
    let state = Arc::new(Mutex::new(ModelState::default()));
    state
        .lock()
        .unwrap()
        .registers
        .extend([(0x28, 0x420), (0x9c, 0x10d000), (0, 0x45678900)]);
    state
}

pub(super) fn step_fixture() -> (
    crate::wifi::intel::platform::Observation,
    resources::Catalog,
) {
    use crate::wifi::intel::platform::{CapturedVariable, Variable};
    let mut captured = CapturedVariable::from_variable(
        Variable::Step,
        vec![1, 0xab, 0x12, 0x34, 0x56, 0x78],
        7,
        Some(6),
    )
    .unwrap();
    (
        captured.observation(),
        resources::Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap(),
    )
}

pub(super) fn start_ax210<'a>(
    catalog: &'a resources::Catalog,
    step: StepConfiguration<'a>,
    source: &Source,
    domain: &Arc<Domain>,
    state: &Arc<Mutex<ModelState>>,
    drops: &Arc<AtomicUsize>,
) -> RomBoot<'a, Model> {
    start_profile(ax210_profile(), catalog, step, source, domain, state, drops)
}

/// [`start_ax210`] for any profile of the AX210 family or later.
pub(super) fn start_profile<'a>(
    profile: Profile,
    catalog: &'a resources::Catalog,
    step: StepConfiguration<'a>,
    source: &Source,
    domain: &Arc<Domain>,
    state: &Arc<Mutex<ModelState>>,
    drops: &Arc<AtomicUsize>,
) -> RomBoot<'a, Model> {
    // SAFETY: All helper callers supply this sole model owner's Source/Domain;
    // fresh RAM and serialized register effects have no real DMA, IRQ or active SAP user.
    unsafe {
        RomBoot::start_ax210(
            awake_profile(state.clone(), drops.clone(), profile.clone()),
            crate::wifi::intel::identity::stage(&profile, catalog).unwrap(),
            step,
            source,
            Some(domain.clone()),
            32,
            ProductResetPolicy::NoIwlmei,
        )
        .unwrap()
    }
}
