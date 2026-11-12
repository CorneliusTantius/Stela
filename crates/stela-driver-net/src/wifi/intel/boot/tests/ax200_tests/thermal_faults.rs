// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
use super::*;

#[test]
fn thermal_power_errors_remain_sticky_and_uncertain_dma_keeps_both_owners() {
    if crate::test_process::isolate_model() {
        return;
    }
    for case in 0..7 {
        let bytes = setup_bytes();
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
        let (lari, sequence, entry) = finish_lari(
            init,
            &source,
            &domain,
            &bios_drops,
            (case == 0).then_some(IoError::Unavailable),
        );
        let before = state.lock().unwrap().ops.len();
        let mut options = Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        });
        if case == 3 || case == 6 {
            options.clock.ticks_per_microsecond = 1;
            options.command_timeout_us = 1;
        }
        let mut setup =
            // SAFETY: the fixture clock is monotonic and advances for the whole device epoch.
            unsafe { lari.begin_ax200_setup(options) }.unwrap_or_else(|_| panic!("AX200"));
        if case == 1 {
            *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
        }
        if case == 4 {
            let mut r = domain.records.lock().unwrap();
            r.sync_fail = Some(r.syncs + 2);
        }
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        let result = unsafe { setup.advance(&source) };
        match case {
            0 => {
                // `iwl_bios_get_eckv`: a clock source the platform cannot give
                // is absent, and the power command goes out without it.
                result.unwrap();
                assert!(state.lock().unwrap().ops.len() > before);
                assert!(setup.first_error().is_none());
                assert!(setup.platform_reads().iter().any(|read| read.incomplete()));
                setup.stop().unwrap();
                drop(setup);
                assert!(domain.records.lock().unwrap().live.is_empty());
                assert_eq!(drops.load(Ordering::Relaxed), 1);
                assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
                continue;
            }
            1 => assert_eq!(result, Err(Ax200SetupError::Boot(Error::RfKilled))),
            2 => {
                result.unwrap();
                complete(
                    &setup.lari.radio.initialized.boot,
                    &domain,
                    entry,
                    entry + 1,
                    &command_packet(
                        crate::wifi::intel::command::Id {
                            group: 4,
                            opcode: 3,
                            version: 0,
                        },
                        sequence,
                        &[0xde, 0xad],
                    ),
                );
                assert_eq!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { setup.advance(&source) },
                    Err(Ax200SetupError::Boot(Error::InitializationResponse {
                        command: 3,
                        group: 4
                    }))
                );
                assert_eq!(setup.responses()[0].raw, [0xde, 0xad]);
                assert!(!setup.thermal_command_acknowledged());
            }
            3 => {
                result.unwrap();
                options.clock.delay(20);
                assert_eq!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { setup.advance(&source) },
                    Err(Ax200SetupError::Deadline(Kind::TemperatureThresholds))
                );
            }
            4 => assert!(matches!(result, Err(Ax200SetupError::Boot(Error::Dma(_))))),
            5 => {
                result.unwrap();
                let mut s = state.lock().unwrap();
                s.fail = Some(s.ops.len() + 1);
                drop(s);
                assert!(setup.stop().is_err());
            }
            6 => {
                result.unwrap();
                complete(
                    &setup.lari.radio.initialized.boot,
                    &domain,
                    entry,
                    entry + 1,
                    &command_packet(
                        crate::wifi::intel::command::Id {
                            group: 4,
                            opcode: 4,
                            version: 0,
                        },
                        sequence,
                        &[],
                    ),
                );
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                drop(r);
                options.clock.delay(20);
                assert_eq!(
                    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole
                    // simulated requester domain.
                    unsafe { setup.advance(&source) },
                    Err(Ax200SetupError::Deadline(Kind::TemperatureThresholds))
                );
                assert!(!setup.thermal_command_acknowledged());
                assert!(setup.responses().is_empty());
            }
            _ => unreachable!(),
        }
        let original = setup.first_error().unwrap().clone();
        let ops = state.lock().unwrap().ops.len();
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { setup.advance(&source) }, Err(original.clone()));
        assert_eq!(setup.first_error(), Some(&original));
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        if case >= 3 {
            let live = domain.records.lock().unwrap().live.len();
            assert!(live > 0);
            drop(setup);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
        } else {
            setup.stop().unwrap();
            drop(setup);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
        }
    }
}
