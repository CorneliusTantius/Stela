// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
use super::*;

#[test]
fn mcc_failures_keep_evidence_and_owner() {
    if crate::test_process::isolate_model() {
        return;
    }
    for case in 0..5 {
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
        let (lari, sequence, entry) = finish_lari(init, &source, &domain, &bios_drops, None);
        let (mut setup, sequence, entry) = finish_setup(lari, sequence, entry, &source, &domain);
        if case == 2 {
            setup.lari.bios.io.country_error = Some(IoError::Unavailable);
        }
        let mut mcc = setup.begin_mcc().unwrap_or_else(|_| panic!("setup"));
        if case == 4 {
            let mut r = domain.records.lock().unwrap();
            r.sync_fail = Some(r.syncs + 2);
        }
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        let result = unsafe { mcc.advance(&source) };
        if case == 4 {
            assert!(matches!(result, Err(Ax200MccError::Boot(Error::Dma(_)))));
        } else {
            result.unwrap();
            let raw = if case == 0 {
                vec![0xaa; 4]
            } else {
                mcc_payload(*b"US", 0x10, if case == 1 { 52 } else { 51 })
            };
            complete(
                &mcc.setup.lari.radio.initialized.boot,
                &domain,
                entry,
                entry + 1,
                &command_packet(
                    crate::wifi::intel::command::Id {
                        group: 1,
                        opcode: if case == 3 { 0xc9 } else { 0xc8 },
                        version: 0,
                    },
                    sequence,
                    &raw,
                ),
            );
            // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
            // requester domain.
            let result = unsafe { mcc.advance(&source) };
            if case == 2 {
                // `iwl_bios_get_mcc`: a WRDD the platform cannot give is
                // absent, and the firmware's current country stands.
                result.unwrap();
                assert!(mcc.first_error().is_none());
                assert_eq!(
                    mcc.bios_country(),
                    Some(crate::wifi::intel::radio::lari::Observation::Unavailable)
                );
                assert!(mcc.platform_reads().iter().any(|read| read.incomplete()));
                mcc.stop().unwrap();
                drop(mcc);
                assert!(domain.records.lock().unwrap().live.is_empty());
                assert_eq!(drops.load(Ordering::Relaxed), 1);
                assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
                continue;
            }
            match case {
                0 => assert!(matches!(result, Err(Ax200MccError::Schema(_)))),
                1 => assert!(matches!(result, Err(Ax200MccError::ChannelInventory(_)))),
                3 => assert!(matches!(
                    result,
                    Err(Ax200MccError::Boot(Error::InitializationResponse { .. }))
                )),
                _ => unreachable!(),
            }
            assert_eq!(mcc.responses().len(), 1);
            assert_eq!(mcc.responses()[0].raw, raw);
            assert!(mcc.profiles().is_empty());
        }
        let original = mcc.first_error().unwrap().clone();
        let ops = state.lock().unwrap().ops.len();
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        assert_eq!(unsafe { mcc.advance(&source) }, Err(original));
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        if case == 4 {
            let live = domain.records.lock().unwrap().live.len();
            assert!(live > 0);
            drop(mcc);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
        } else {
            mcc.stop().unwrap();
            drop(mcc);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
        }
    }
}
