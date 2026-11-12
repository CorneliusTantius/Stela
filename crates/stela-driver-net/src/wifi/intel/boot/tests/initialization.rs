// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

pub(super) fn command_ready<'a>(
    mut boot: RomBoot<'a, Model>,
    empty: &'a resources::Catalog,
    source: &Source,
    domain: &Domain,
    state: &Arc<Mutex<ModelState>>,
) -> RomBoot<'a, Model> {
    event(state, 1);
    boot.poll().unwrap();
    let mut packet = rx_packet(1, 0xcafe, 0);
    set_sku(&mut packet, [0; 3]);
    complete(&boot, domain, 0, 1, &packet);
    boot.poll().unwrap().unwrap();
    assert!(matches!(
        // SAFETY: Callers supply the Source/Domain belonging to this same model boot;
        // the empty catalog selects the no-PNVM path, with no alternate device worker.
        unsafe { boot.begin_pnvm(empty, Observations::default(), source) }.unwrap(),
        PnvmProgress::Skipped
    ));
    boot
}

pub(super) fn command_packet(
    id: crate::wifi::intel::command::Id,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    bytes[..4].copy_from_slice(&(4u32 + payload.len() as u32).to_le_bytes());
    bytes[4] = id.opcode;
    bytes[5] = id.group;
    bytes[6..8].copy_from_slice(&sequence.to_le_bytes());
    bytes[8..8 + payload.len()].copy_from_slice(payload);
    let next = (8 + payload.len()).next_multiple_of(64);
    bytes[next..next + 4].copy_from_slice(&0x55550000u32.to_le_bytes());
    bytes
}

pub(super) fn command_id() -> crate::wifi::intel::command::Id {
    crate::wifi::intel::command::Id {
        group: 2,
        opcode: 3,
        version: 1,
    }
}

pub(super) fn alive_ax210<'a>(
    catalog: &'a resources::Catalog,
    step: StepConfiguration<'a>,
    source: &Source,
    domain: &Arc<Domain>,
    state: &Arc<Mutex<ModelState>>,
    drops: &Arc<AtomicUsize>,
) -> RomBoot<'a, Model> {
    let mut boot = start_ax210(catalog, step, source, domain, state, drops);
    event(state, 1);
    boot.poll().unwrap();
    complete(&boot, domain, 0, 1, &rx_packet(1, 0xcafe, 0));
    boot.poll().unwrap().unwrap();
    boot
}

pub(super) fn drive_nvm<'a>(
    boot: RomBoot<'a, Model>,
    source: &Source,
    domain: &Domain,
    state: &Arc<Mutex<ModelState>>,
) -> UnifiedNvm<'a, Model> {
    use crate::wifi::intel::nvm::Request;
    state
        .lock()
        .unwrap()
        .registers
        .extend([(0x388, 0x02123456), (0x38c, 0x789a)]);
    let init = boot.initialize_on_device_nvm();
    let before = state.lock().unwrap().ops.len();
    let mut init = match init.begin_radio() {
        Err(owner) => *owner,
        Ok(_) => panic!("uninitialized owner admitted"),
    };
    assert_eq!(state.lock().unwrap().ops.len(), before);
    // SAFETY: All helper callers keep the original boot Source/Domain pair; its RAM
    // is exclusive and the refused begin_radio returned that exact initializer.
    unsafe { init.advance(source) }.unwrap();
    complete(
        &init.boot,
        domain,
        1,
        2,
        &command_packet(Request::ExtendedConfiguration.id(), 0, &[]),
    );
    // SAFETY: The extended-configuration ACK was synchronously completed in the same
    // Domain; the caller's original Source supplies exclusive model pages.
    unsafe { init.advance(source) }.unwrap();
    complete(
        &init.boot,
        domain,
        2,
        3,
        &command_packet(Request::AccessComplete.id(), 1, &[]),
    );
    // SAFETY: The access-complete ACK belongs to that same model epoch and receive
    // mapping; no caller reset or competing submission occurs during this helper.
    unsafe { init.advance(source) }.unwrap();
    complete(
        &init.boot,
        domain,
        3,
        4,
        &command_packet(
            crate::wifi::intel::command::Id {
                group: 0,
                opcode: 4,
                version: 0,
            },
            0x8000,
            &[0x76],
        ),
    );
    // SAFETY: The init notification was completed synchronously through the original
    // Domain; Source and all model mappings remain held by this initializer.
    unsafe { init.advance(source) }.unwrap();
    complete(
        &init.boot,
        domain,
        4,
        5,
        &command_packet(Request::GetInformation.id(), 2, &nvm_response()),
    );
    assert_eq!(
        // SAFETY: The NVM response resides in that same owned model buffer; the original
        // Source/Domain stay live through parsing and reclamation before returning init.
        unsafe { init.advance(source) }.unwrap(),
        InitializationProgress::Observed
    );
    init
}

pub(super) fn drive_cold_prefix<'a>(
    init: UnifiedNvm<'a, Model>,
    source: &Source,
    domain: &Domain,
) -> (ColdRadio<'a, Model>, u16, u16) {
    let expected = crate::wifi::intel::radio::InitialPlan::prepare(
        &init.boot.firmware,
        init.boot.profile.platform(),
        &init.receipt().unwrap().information,
    )
    .unwrap();
    let mut radio = init.begin_radio().unwrap_or_else(|_| panic!("actual NVM"));
    // SAFETY: Callers keep the exact Source/Domain for init, and begin_radio moves
    // that original owner; the NVM-derived plan uses exclusive model allocations.
    unsafe { radio.advance(source) }.unwrap();
    for (i, command) in expected.commands().iter().enumerate() {
        let mut id = command.id();
        if id.group == 0 {
            id.group = 1;
        }
        complete(
            &radio.initialized.boot,
            domain,
            5 + i as u16,
            6 + i as u16,
            &command_packet(id, 3 + i as u16, &[]),
        );
        // SAFETY: Each prefix ACK was synchronously completed through that same Domain;
        // radio keeps the original Source and DMA backing through the next command.
        unsafe { radio.advance(source) }.unwrap();
    }
    assert_eq!(radio.phase(), ColdRadioPhase::PlatformConfigurationRequired);
    let count = expected.commands().len() as u16;
    (radio, 3 + count, 5 + count)
}

/// `iwl_trans_pcie_start_fw` runs the unified image with the radio switched
/// off: the ROM boot reaches ALIVE and the NVM initialization starts, its
/// commands sent as they are in RF-kill.
#[test]
fn a_switched_off_radio_still_boots_its_firmware_and_starts_initialization() {
    if crate::test_process::isolate_model() {
        return;
    }
    let bytes = unified_bytes(false);
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x0800_0000;
    let drops = Arc::new(AtomicUsize::new(0));
    let boot = start(&catalog, &source, &domain, &state, &drops);
    let boot = command_ready(boot, &empty, &source, &domain, &state);
    let mut init = boot.initialize_on_device_nvm();
    assert_eq!(
        // SAFETY: the initializer owns that same model epoch and domain, and
        // Source stays exclusive.
        unsafe { init.advance(&source) }.unwrap(),
        InitializationProgress::Pending(InitializationPhase::ExtendedConfiguration)
    );
    assert_eq!(state.lock().unwrap().registers[&0x24] & 0x0800_0000, 0);
}
