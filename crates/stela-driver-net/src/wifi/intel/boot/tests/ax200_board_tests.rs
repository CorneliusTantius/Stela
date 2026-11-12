// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Real board commands on the unchanged modeled AX200 requester/DMA epoch.
use super::{ax200_scan_tests::finish_mcc, ax200_tests::*, *};
use crate::wifi::intel::{platform::Variable, radio::bios::service};
pub(super) fn power_variable(case: u8, variable: Variable) -> Result<Vec<u8>, service::IoError> {
    if case == 1 {
        return Err(service::IoError::NotFound);
    }
    if case == 2 && variable == Variable::Wrds {
        return Err(service::IoError::Unavailable);
    }
    Ok(match variable {
        Variable::Ppag => {
            let mut raw = vec![2, 3, 0, 0, 0];
            raw.extend(1..=22);
            raw
        }
        Variable::Wrds => {
            let mut raw = vec![2, 1, 0, 0, 0];
            raw.extend(1..=44);
            raw
        }
        Variable::Wgds => {
            let mut raw = vec![3, 3];
            raw.extend([14; 72]);
            raw
        }
        Variable::Sgom => {
            let mut raw = vec![1];
            raw.extend([0x31; 338]);
            raw
        }
        // Case 11's block list is full.
        Variable::Wtas if case == 11 => {
            let mut raw = vec![1];
            raw.extend(0x10007u32.to_le_bytes());
            raw.push(16);
            for country in 0..16u16 {
                raw.extend((0x4100 + country).to_le_bytes());
            }
            raw
        }
        Variable::Wtas => {
            let mut raw = vec![1];
            raw.extend(0x10007u32.to_le_bytes());
            raw.push(1);
            raw.extend(u16::from_be_bytes(*b"JP").to_le_bytes());
            raw.resize(38, 0);
            raw
        }
        Variable::Ewrd => return Err(service::IoError::NotFound),
        _ => panic!("unexpected board variable"),
    })
}
fn board_bytes() -> Vec<u8> {
    let mut bytes = setup_bytes();
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            let versions = [
                7, 4, 1, 0, 0x9f, 1, 5, 0, 5, 4, 4, 1, 4, 12, 2, 0, 3, 12, 4, 0,
            ];
            bytes.splice(at + 8 + len..at + 8 + len, versions);
            bytes[at + 4..at + 8].copy_from_slice(&((len + versions.len()) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    for (kind, index, word) in [
        (30u32, 1u32, (1u32 << 20) | (1 << 21)),
        (29, 1, (1 << 13) | (1 << 23)),
    ] {
        bytes.extend(kind.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(index.to_le_bytes());
        bytes.extend(word.to_le_bytes());
    }
    bytes
}
#[test]
fn board_power_commands_use_bios_and_original_reclaimed_dma() {
    if crate::test_process::isolate_model() {
        return;
    }
    exercise(false);
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn ax200_board_schema_and_native_owner() {
    if crate::test_process::isolate_model() {
        return;
    }
    exercise(true);
}
fn exercise(actual: bool) {
    for case in 0..12u8 {
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
            board_bytes()
        };
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let bios_drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let boot = command_ready(boot, &empty, &source, &domain, &state);
        let init = drive_nvm(boot, &source, &domain, &state);
        let (lari, sequence, entry) = finish_lari(init, &source, &domain, &bios_drops, None);
        let mut options = Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        });
        if case == 9 || case == 10 {
            options.clock.ticks_per_microsecond = 1;
            options.command_timeout_us = 1;
        }
        let (setup, sequence, entry) =
            finish_setup_with_options(lari, sequence, entry, &source, &domain, options);
        let (mcc, mut sequence, mut entry) = finish_mcc(setup, sequence, entry, &source, &domain);
        let mut scan = mcc
            .begin_scan_configuration()
            .unwrap_or_else(|_| panic!("scan"));
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { scan.advance(&source) }.unwrap();
        complete(
            &scan.mcc.setup.lari.radio.initialized.boot,
            &domain,
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
        unsafe { scan.advance(&source) }.unwrap();
        sequence += 1;
        entry += 1;
        scan.mcc.setup.lari.bios.io.board_case = Some(case);
        let mut board = scan
            .begin_board_policy()
            .unwrap_or_else(|_| panic!("board"));
        let bell_before = state.lock().unwrap().registers[&0x460];
        if case == 6 {
            *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
        }
        if case == 7 {
            let mut r = domain.records.lock().unwrap();
            r.sync_fail = Some(r.syncs + 2);
        }
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        let result = unsafe { board.advance(&source) };
        if case == 1 {
            assert_eq!(result.unwrap(), Ax200BoardPolicyPhase::CountryRequired);
            assert!(board.commands().is_empty());
            assert!(board.responses().is_empty());
            assert_eq!(state.lock().unwrap().registers[&0x460], bell_before);
        } else if case == 6 {
            assert_eq!(result, Err(Ax200BoardPolicyError::Boot(Error::RfKilled)));
        } else if case == 7 {
            assert!(matches!(
                result,
                Err(Ax200BoardPolicyError::Boot(Error::Dma(_)))
            ));
        } else {
            result.unwrap();
            // Case 2's WRDS cannot be read, so it is absent: no SAR and, as
            // `iwl_mvm_sar_init` does, no geo table without it. Case 3's
            // SMBIOS cannot be read, so it matches no vendor, as case 4's
            // unlisted vendor does.
            if matches!(case, 2 | 3) {
                assert!(board.platform_reads().iter().any(|read| read.incomplete()));
            }
            let expected = if case == 2 {
                vec![
                    BoardCommandKind::Ppag,
                    BoardCommandKind::Sgom,
                    BoardCommandKind::Tas,
                ]
            } else if case == 11 {
                // `iwl_mvm_tas_init`: an unlisted vendor's full block list
                // has no room for US and Canada, so TAS stays off.
                vec![
                    BoardCommandKind::Sar,
                    BoardCommandKind::Geo,
                    BoardCommandKind::Sgom,
                ]
            } else if case == 4 || case == 3 {
                vec![
                    BoardCommandKind::Sar,
                    BoardCommandKind::Geo,
                    BoardCommandKind::Sgom,
                    BoardCommandKind::Tas,
                ]
            } else {
                vec![
                    BoardCommandKind::Ppag,
                    BoardCommandKind::Sar,
                    BoardCommandKind::Geo,
                    BoardCommandKind::Sgom,
                    BoardCommandKind::Tas,
                ]
            };
            assert_eq!(
                board
                    .commands()
                    .iter()
                    .map(BoardCommand::kind)
                    .collect::<Vec<_>>(),
                expected
            );
            let commands = board.commands().to_vec();
            for command in commands {
                let descriptor = device_read(
                    &domain,
                    board
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
                let address = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
                let encoded = super::super::super::command::Command::encode(
                    command.id(),
                    0,
                    sequence,
                    command.bytes(),
                )
                .unwrap();
                let mut emitted = device_read(&domain, address, 0, encoded.first_tb().len());
                if !encoded.remainder().is_empty() {
                    let remainder = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
                    emitted.extend(device_read(
                        &domain,
                        remainder,
                        0,
                        encoded.remainder().len(),
                    ));
                }
                assert_eq!(emitted, encoded.bytes());
                let original = board.ticket().unwrap().clone();
                if case == 9 {
                    options.clock.delay(20);
                    assert_eq!(
                        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its
                        // sole simulated requester domain.
                        unsafe { board.advance(&source) },
                        Err(Ax200BoardPolicyError::Deadline(command.kind()))
                    );
                    assert_eq!(board.ticket(), Some(&original));
                    break;
                }
                if case == 8 {
                    let mut s = state.lock().unwrap();
                    s.fail = Some(s.ops.len() + 1);
                    drop(s);
                    assert!(board.stop().is_err());
                    break;
                }
                let mut id = command.id();
                if id.group == 0 {
                    id.group = 1;
                }
                if case == 5 {
                    id.opcode ^= 1;
                }
                complete(
                    &board.scan.mcc.setup.lari.radio.initialized.boot,
                    &domain,
                    entry,
                    entry + 1,
                    &command_packet(id, sequence, &[0x91]),
                );
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                drop(r);
                if case == 10 {
                    options.clock.delay(20);
                    assert_eq!(
                        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its
                        // sole simulated requester domain.
                        unsafe { board.advance(&source) },
                        Err(Ax200BoardPolicyError::Deadline(command.kind()))
                    );
                    assert_eq!(board.ticket(), Some(&original));
                    break;
                }
                assert!(matches!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { board.advance(&source) },
                    Err(Ax200BoardPolicyError::Boot(Error::CommandReclaim(_)))
                ));
                assert_eq!(board.ticket(), Some(&original));
                assert!(board.first_error().is_none());
                domain.records.lock().unwrap().cpu_sync_fail = None;
                // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                // simulated requester domain.
                let result = unsafe { board.advance(&source) };
                if case == 5 {
                    assert!(matches!(
                        result,
                        Err(Ax200BoardPolicyError::Boot(
                            Error::InitializationResponse { .. }
                        ))
                    ));
                    assert_eq!(board.responses()[0].raw, [0x91]);
                    break;
                }
                result.unwrap();
                sequence += 1;
                entry += 1;
            }
            if case == 11 {
                assert_eq!(board.phase(), Ax200BoardPolicyPhase::CountryRequired);
            }
            if matches!(case, 0 | 3 | 4) {
                assert_eq!(board.phase(), Ax200BoardPolicyPhase::CountryRequired);
                assert_eq!(board.responses().len(), expected.len());
                let sar = board
                    .commands()
                    .iter()
                    .find(|c| c.kind() == BoardCommandKind::Sar)
                    .unwrap();
                assert_eq!(sar.bytes().len(), 44);
                assert_eq!(&sar.bytes()[..4], &2u32.to_le_bytes());
                assert_eq!(&sar.bytes()[16..26], &[1, 0, 2, 0, 3, 0, 4, 0, 5, 0]);
                assert_eq!(&sar.bytes()[26..36], &[12, 0, 13, 0, 14, 0, 15, 0, 16, 0]);
                let tas = board.commands().last().unwrap();
                assert_eq!(
                    u32::from_le_bytes(tas.bytes()[..4].try_into().unwrap()),
                    if case == 0 { 1 } else { 3 }
                );
            }
        }
        if board.first_error().is_some() {
            let original = board.first_error().unwrap().clone();
            let ops = state.lock().unwrap().ops.len();
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            assert_eq!(unsafe { board.advance(&source) }, Err(original));
            assert_eq!(state.lock().unwrap().ops.len(), ops);
        }
        if case == 7 || case == 8 {
            let live = domain.records.lock().unwrap().live.len();
            assert!(live > 0);
            drop(board);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
        } else {
            board.stop().unwrap();
            drop(board);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
        }
    }
}
