// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn lari_bios_source_commands_and_dma_retirement_both_families() {
    if crate::test_process::isolate_model() {
        return;
    }
    exercise_lari_bios(false);
}

#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn lari_images_drive_lari6_without_extension_and_lari8_with_extension() {
    if crate::test_process::isolate_model() {
        return;
    }
    exercise_lari_bios(true);
}

#[test]
fn lari_schema_missing_services_rfkill_and_uncertain_command_keep_original_owner() {
    if crate::test_process::isolate_model() {
        return;
    }
    for case in 0..7 {
        let bytes = lari_bytes(false, if case == 0 { 99 } else { 6 });
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
        let (cold, sequence, entry) = drive_cold_prefix(init, &source, &domain);
        // SAFETY: RadioBios supplies this same modeled function's namespace responses;
        // the owned value and drop counter are moved with cold through kept teardown.
        let mut lari = unsafe {
            cold.begin_lari(RadioBios {
                drops: bios_drops.clone(),
                unavailable: case == 1,
                absent: case == 6,
            })
        }
        .unwrap_or_else(|_| panic!("prefix"));
        let ops = state.lock().unwrap().ops.len();
        let allocations = source.calls.load(Ordering::Relaxed);
        if case == 2 {
            *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
        }
        if case == 4 {
            let mut r = domain.records.lock().unwrap();
            r.sync_fail = Some(r.syncs + 2);
        }
        // SAFETY: The LARI owner keeps that original model domain and exclusive Source;
        // all missing-service/RF-kill/visibility failures are serialized model operations.
        let result = unsafe { lari.advance(&source) };
        match case {
            0 => {
                assert_eq!(
                    result,
                    Err(LariError::Plan(
                        crate::wifi::intel::radio::lari::Error::Version(99)
                    ))
                );
                assert!(lari.platform_reads().is_empty());
            }
            2 => assert_eq!(result, Err(LariError::Boot(Error::RfKilled))),
            3 => {
                result.unwrap();
                complete(
                    &lari.radio.initialized.boot,
                    &domain,
                    entry,
                    entry + 1,
                    &command_packet(
                        crate::wifi::intel::command::Id {
                            group: 12,
                            opcode: 1,
                            version: 0,
                        },
                        sequence,
                        &[0xde, 0xad, 0, 0xff],
                    ),
                );
                assert_eq!(
                    // SAFETY: The wrong response completed synchronously in kept receive RAM;
                    // the same LARI/source/domain owners remain live through response refusal.
                    unsafe { lari.advance(&source) },
                    Err(LariError::Boot(Error::InitializationResponse {
                        group: 12,
                        command: 1
                    }))
                );
                assert_eq!(lari.responses().len(), 1);
                let response = &lari.responses()[0];
                assert_eq!(response.raw, [0xde, 0xad, 0, 0xff]);
                assert_eq!((response.command, response.group), (1, 12));
                assert_eq!((response.request.opcode, response.request.group), (8, 12));
                assert_eq!(response.ticket.sequence(), sequence);
                let doorbell = state.lock().unwrap().registers[&0x460];
                assert_eq!(
                    // SAFETY: Refusal kept the original BIOS and DMA owners; this failed-state
                    // reentry has no competing reset/submission worker or new source mapping.
                    unsafe { lari.advance(&source) },
                    Err(LariError::Boot(Error::State))
                );
                assert_eq!(state.lock().unwrap().registers[&0x460], doorbell);
                assert_eq!(lari.responses().len(), 1);
            }
            4 => {
                assert!(matches!(result, Err(LariError::Boot(Error::Dma(_)))));
            }
            5 => {
                result.unwrap();
            }
            // `iwl_acpi_get_object`: an ACPI namespace that cannot answer
            // reads as one without the objects, so LARI sends nothing.
            1 | 6 => {
                assert_eq!(
                    lari.platform_reads().iter().any(|read| read.incomplete()),
                    case == 1
                );
                assert_eq!(result, Ok(LariPhase::RxQueueConfigurationRequired));
                assert_eq!(lari.plan().unwrap().commands().count(), 0);
                assert!(lari.responses().is_empty());
                assert_eq!(state.lock().unwrap().ops.len(), ops);
                assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
            }
            _ => unreachable!(),
        }
        if case == 0 {
            assert_eq!(state.lock().unwrap().ops.len(), ops);
            assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        }
        if case == 4 || case == 5 {
            if case == 5 {
                let mut s = state.lock().unwrap();
                s.fail = Some(s.ops.len() + 1);
                drop(s);
                assert!(lari.stop().is_err());
            }
            let live = domain.records.lock().unwrap().live.len();
            assert!(live > 0);
            drop(lari);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
        } else {
            assert_eq!(
                lari.phase(),
                if case == 1 || case == 6 {
                    LariPhase::RxQueueConfigurationRequired
                } else {
                    LariPhase::Failed
                }
            );
            let rejected = (case == 3).then(|| lari.responses()[0].clone());
            lari.stop().unwrap();
            if let Some(original) = rejected {
                assert_eq!(lari.responses(), [original]);
            }
            drop(lari);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
}
