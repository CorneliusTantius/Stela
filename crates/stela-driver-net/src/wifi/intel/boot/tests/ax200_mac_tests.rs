// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Unbound MAC object and owned command DMA; no PHY/scan substitution.
use super::{ax200_country_tests::Os, ax200_scan_tests::finish_mcc, ax200_tests::*, *};
use core::sync::atomic::AtomicBool;
mod mld_tests;
pub(super) struct Native {
    pub(super) domain: Arc<Domain>,
    pub(super) state: Arc<Mutex<ModelState>>,
    pub(super) drops: Arc<AtomicUsize>,
    pub(super) bios_drops: Arc<AtomicUsize>,
    pub(super) os_drops: Arc<AtomicUsize>,
    pub(super) revoked: Arc<AtomicBool>,
    /// The firmware leaves its PHYs' receive chains to the host.
    pub(super) host_chains: bool,
    /// A complete synthetic firmware image for command/API negotiation fixtures.
    pub(super) firmware: Option<Vec<u8>>,
    /// What firmware reports of each of its transmit FIFOs.
    pub(super) transmit_fifo: core::sync::atomic::AtomicU32,
    /// The function is an AX210, which boots with its PNVM file.
    pub(super) ax210: bool,
}
impl Default for Native {
    fn default() -> Self {
        Self {
            domain: Arc::new(Domain::default()),
            state: Arc::new(Mutex::new(ModelState::default())),
            drops: Arc::new(AtomicUsize::new(0)),
            bios_drops: Arc::new(AtomicUsize::new(0)),
            os_drops: Arc::new(AtomicUsize::new(0)),
            revoked: Arc::new(AtomicBool::new(false)),
            host_chains: false,
            firmware: None,
            transmit_fifo: core::sync::atomic::AtomicU32::new(0),
            ax210: false,
        }
    }
}
pub(super) fn firmware_bytes(case: u8) -> Vec<u8> {
    let mut bytes = setup_bytes();
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            let versions = [
                0x28,
                1,
                if case == 8 { 4 } else { 5 },
                0,
                0xa9,
                1,
                1,
                0,
                0xd2,
                1,
                4,
                0,
            ];
            bytes.splice(at + 8 + len..at + 8 + len, versions);
            bytes[at + 4..at + 8].copy_from_slice(&((len + versions.len()) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    bytes.extend(29u32.to_le_bytes());
    bytes.extend(8u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend((1u32 << 15).to_le_bytes());
    bytes
}
fn country_ready<'a>(
    catalog: &'a resources::Catalog,
    empty: &'a resources::Catalog,
    source: &Source,
    native: &Native,
    options: Ax200SetupOptions,
) -> (Ax200Country<'a, Model, ClockBios, Os>, u16, u16) {
    let os = Os {
        drops: native.os_drops.clone(),
        revoked: native.revoked.clone(),
        unavailable: false,
    };
    country_ready_with_os(catalog, empty, source, native, options, os, false)
}
pub(super) fn country_ready_with_os<'a, O: CountryIo>(
    catalog: &'a resources::Catalog,
    empty: &'a resources::Catalog,
    source: &Source,
    native: &Native,
    options: Ax200SetupOptions,
    os: O,
    second_channel: bool,
) -> (Ax200Country<'a, Model, ClockBios, O>, u16, u16) {
    let domain = &native.domain;
    let state = &native.state;
    let boot = start(catalog, source, domain, state, &native.drops);
    let boot = command_ready(boot, empty, source, domain, state);
    let init = drive_nvm(boot, source, domain, state);
    let (lari, sequence, entry) = finish_lari(init, source, domain, &native.bios_drops, None);
    let (setup, sequence, entry) =
        finish_setup_with_options(lari, sequence, entry, source, domain, options);
    let (mcc, mut sequence, mut entry) = finish_mcc(setup, sequence, entry, source, domain);
    let mut scan = mcc
        .begin_scan_configuration()
        .unwrap_or_else(|_| panic!("scan"));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { scan.advance(source) }.unwrap();
    complete(
        &scan.mcc.setup.lari.radio.initialized.boot,
        domain,
        entry,
        entry + 1,
        &command_packet(
            super::super::super::command::Id {
                group: 1,
                opcode: 0xc,
                version: 0,
            },
            sequence,
            &[],
        ),
    );
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { scan.advance(source) }.unwrap();
    sequence += 1;
    entry += 1;
    scan.mcc.setup.lari.bios.io.board_case = Some(1);
    let mut board = scan
        .begin_board_policy()
        .unwrap_or_else(|_| panic!("board"));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { board.advance(source) }.unwrap();
    // SAFETY: the simulated device and its providers belong to this fixture alone; no other worker
    // touches them.
    let mut country = unsafe { board.begin_country(os) }.unwrap_or_else(|_| panic!("country"));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { country.advance(source) }.unwrap();
    let mut payload = mcc_payload(*b"US", 9, 51);
    if second_channel {
        payload[24..28].copy_from_slice(&0x0f09u32.to_le_bytes());
    }
    complete(
        &country.board.scan.mcc.setup.lari.radio.initialized.boot,
        domain,
        entry,
        entry + 1,
        &command_packet(
            super::super::super::mcc::Request::id().wire(),
            sequence,
            &payload,
        ),
    );
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { country.advance(source) }.unwrap();
    sequence += 1;
    entry += 1;
    (country, sequence, entry)
}
#[test]
fn unbound_mac_commands_reclaim_on_ack() {
    if crate::test_process::isolate_model() {
        return;
    }
    exercise(false);
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn ax200_mld_image_refuses_legacy_mac_before_effects() {
    if crate::test_process::isolate_model() {
        return;
    }
    exercise(true);
}
fn exercise(actual: bool) {
    for case in 0..if actual { 8 } else { 9 } {
        let bytes = if actual {
            use sha2::{Digest, Sha256};
            let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
            let bytes =
                std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name()))
                    .unwrap();
            assert_eq!(
                std::format!("{:x}", Sha256::digest(&bytes)),
                "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
            );
            bytes
        } else {
            firmware_bytes(case)
        };
        if actual {
            assert_mld_mac_refusal(&bytes);
            return;
        }
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let mut options = Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        });
        if case == 5 || case == 6 {
            options.clock.ticks_per_microsecond = 1;
            options.command_timeout_us = 1;
        }
        let (country, mut sequence, mut entry) =
            country_ready(&catalog, &empty, &source, &native, options);
        let mut mac = country
            .begin_mac_context()
            .unwrap_or_else(|_| panic!("MAC"));
        if case == 2 {
            *native
                .state
                .lock()
                .unwrap()
                .registers
                .get_mut(&0x24)
                .unwrap() &= !0x08000000;
        }
        if case == 3 {
            let mut r = native.domain.records.lock().unwrap();
            r.sync_fail = Some(r.syncs + 2);
        }
        if case == 7 {
            native.revoked.store(true, Ordering::Relaxed);
        }
        assert!(mac.mac_id_and_color().is_none());
        let bell = native.state.lock().unwrap().registers[&0x460];
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        let result = unsafe { mac.advance(&source) };
        match case {
            2 => assert_eq!(result, Err(Ax200MacError::Boot(Error::RfKilled))),
            3 => assert!(matches!(result, Err(Ax200MacError::Boot(Error::Dma(_))))),
            7 => {
                assert_eq!(
                    result,
                    Err(Ax200MacError::Country(Ax200CountryError::Revoked))
                );
                assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
            }
            8 => {
                assert_eq!(
                    result,
                    Err(Ax200MacError::Version {
                        kind: MacCommandKind::Add,
                        version: 4
                    })
                );
                assert!(mac.commands().is_empty());
                assert_eq!(native.state.lock().unwrap().registers[&0x460], bell);
            }
            _ => {
                assert_eq!(result.unwrap(), Ax200MacPhase::Waiting(MacCommandKind::Add));
                let add = mac.commands()[0].bytes();
                assert_eq!(add.len(), 148);
                assert_eq!(&add[16..22], &mac.initialized_nvm().address.bytes);
                assert_eq!(&add[24..30], &[0xff; 6]);
                assert_eq!(&add[32..40], &[15, 0, 0, 0, 21, 0, 0, 0]);
                assert_eq!(&add[52..56], &[0x44, 0, 0, 0]);
                assert!(add[100..].iter().all(|v| *v == 0));
                for command in mac.commands().to_vec() {
                    let descriptor = device_read(
                        &native.domain,
                        mac.country
                            .board
                            .scan
                            .mcc
                            .setup
                            .lari
                            .radio
                            .initialized
                            .boot
                            .command
                            .region()
                            .address,
                        usize::from(sequence & 31) * 256,
                        256,
                    );
                    let encoded = super::super::super::command::Command::encode(
                        command.id(),
                        0,
                        sequence,
                        command.bytes(),
                    )
                    .unwrap();
                    let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
                    let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
                    let mut emitted =
                        device_read(&native.domain, first, 0, encoded.first_tb().len());
                    emitted.extend(device_read(
                        &native.domain,
                        rest,
                        0,
                        encoded.remainder().len(),
                    ));
                    assert_eq!(emitted, encoded.bytes());
                    let ticket = mac.ticket().unwrap().clone();
                    if case == 4 {
                        let mut s = native.state.lock().unwrap();
                        s.fail = Some(s.ops.len() + 1);
                        drop(s);
                        assert!(mac.stop().is_err());
                        break;
                    }
                    if case == 5 {
                        options.clock.delay(20);
                        assert_eq!(
                            // SAFETY: the fixture's `source` hands out fresh exclusive pages for
                            // its sole simulated requester domain.
                            unsafe { mac.advance(&source) },
                            Err(Ax200MacError::Deadline(command.kind()))
                        );
                        assert_eq!(mac.ticket(), Some(&ticket));
                        break;
                    }
                    let mut id = command.id().wire();
                    if case == 1 {
                        id.opcode ^= 1;
                    }
                    complete(
                        &mac.country.board.scan.mcc.setup.lari.radio.initialized.boot,
                        &native.domain,
                        entry,
                        entry + 1,
                        &command_packet(id, sequence, &[0x9b]),
                    );
                    let mut r = native.domain.records.lock().unwrap();
                    r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                    drop(r);
                    if case == 6 {
                        options.clock.delay(20);
                        assert_eq!(
                            // SAFETY: the fixture's `source` hands out fresh exclusive pages for
                            // its sole simulated requester domain.
                            unsafe { mac.advance(&source) },
                            Err(Ax200MacError::Deadline(command.kind()))
                        );
                        assert_eq!(mac.ticket(), Some(&ticket));
                        break;
                    }
                    assert!(matches!(
                        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its
                        // sole simulated requester domain.
                        unsafe { mac.advance(&source) },
                        Err(Ax200MacError::Boot(Error::CommandReclaim(_)))
                    ));
                    assert_eq!(mac.ticket(), Some(&ticket));
                    assert!(mac.first_error().is_none());
                    native.domain.records.lock().unwrap().cpu_sync_fail = None;
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    let result = unsafe { mac.advance(&source) };
                    if case == 1 {
                        assert!(matches!(
                            result,
                            Err(Ax200MacError::Boot(Error::InitializationResponse { .. }))
                        ));
                        assert_eq!(mac.responses()[0].raw, [0x9b]);
                        assert!(mac.mac_id_and_color().is_none());
                        break;
                    }
                    result.unwrap();
                    sequence += 1;
                    entry += 1;
                }
                if case == 0 {
                    assert_eq!(mac.phase(), Ax200MacPhase::ScanRequired);
                    assert_eq!(mac.mac_id_and_color(), Some(0));
                    assert_eq!(mac.responses().len(), 3);
                    assert_eq!(&mac.commands()[1].bytes()[4..8], &[0, 0, 25, 0]);
                    assert_eq!(mac.commands()[2].bytes(), &[0; 60]);
                    native.revoked.store(true, Ordering::Relaxed);
                    mac.begin_remove().unwrap();
                    assert_eq!(mac.begin_remove(), Err(Ax200MacError::State));
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { mac.advance(&source) }.unwrap();
                    let remove = mac.commands().last().unwrap();
                    assert_eq!(&remove.bytes()[4..8], &3u32.to_le_bytes());
                    complete(
                        &mac.country.board.scan.mcc.setup.lari.radio.initialized.boot,
                        &native.domain,
                        entry,
                        entry + 1,
                        &command_packet(remove.id().wire(), sequence, &[]),
                    );
                    assert_eq!(
                        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its
                        // sole simulated requester domain.
                        unsafe { mac.advance(&source) }.unwrap(),
                        Ax200MacPhase::Removed
                    );
                    assert!(mac.mac_id_and_color().is_none());
                }
            }
        }
        if let Some(error) = mac.first_error().cloned() {
            let operations = native.state.lock().unwrap().ops.len();
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            assert_eq!(unsafe { mac.advance(&source) }, Err(error));
            assert_eq!(native.state.lock().unwrap().ops.len(), operations);
        }
        if case == 3 || case == 4 {
            let live = native.domain.records.lock().unwrap().live.len();
            assert!(live > 0);
            drop(mac);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.drops.load(Ordering::Relaxed), 0);
            assert_eq!(native.bios_drops.load(Ordering::Relaxed), 0);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            mac.stop().unwrap();
            drop(mac);
            assert!(native.domain.records.lock().unwrap().live.is_empty());
            assert_eq!(native.drops.load(Ordering::Relaxed), 1);
            assert_eq!(native.bios_drops.load(Ordering::Relaxed), 1);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 1);
        }
    }
}
pub(super) fn assert_mld_mac_refusal(bytes: &[u8]) {
    let firmware = crate::wifi::intel::firmware::Firmware::parse(bytes).unwrap();
    assert!(firmware.supports_capability(110));
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let (country, _, _) = country_ready(
        &catalog,
        &empty,
        &source,
        &native,
        Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        }),
    );
    let mut mac = country
        .begin_mac_context()
        .unwrap_or_else(|_| panic!("MAC"));
    let calls = source.calls.load(Ordering::Relaxed);
    let operations = native.state.lock().unwrap().ops.len();
    let syncs = native.domain.records.lock().unwrap().syncs;
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { mac.advance(&source) },
        Err(Ax200MacError::MldContinuationRequired)
    );
    assert!(mac.commands().is_empty());
    assert!(mac.ticket().is_none());
    assert_eq!(source.calls.load(Ordering::Relaxed), calls);
    assert_eq!(native.state.lock().unwrap().ops.len(), operations);
    assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
    assert_eq!(
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { mac.advance(&source) },
        Err(Ax200MacError::MldContinuationRequired)
    );
    assert_eq!(source.calls.load(Ordering::Relaxed), calls);
    assert_eq!(native.state.lock().unwrap().ops.len(), operations);
    assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
    assert_eq!(mac.replenish_completed_receive(), Err(Error::State));
    assert_eq!(native.state.lock().unwrap().ops.len(), operations);
    assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
    mac.stop().unwrap();
    drop(mac);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
}
#[test]
fn mld_selects_distinct_mac_owner_before_any_legacy_publication() {
    if crate::test_process::isolate_model() {
        return;
    }
    let mut bytes = firmware_bytes(0);
    bytes.extend(30u32.to_le_bytes());
    bytes.extend(8u32.to_le_bytes());
    bytes.extend(3u32.to_le_bytes());
    bytes.extend((1u32 << 14).to_le_bytes());
    assert_mld_mac_refusal(&bytes);
}
