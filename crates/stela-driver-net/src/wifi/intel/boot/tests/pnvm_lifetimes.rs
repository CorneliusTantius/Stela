// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn pnvm_each_new_mapping_visibility_and_partial_stop_failure_preserves_epoch() {
    if crate::test_process::isolate_model() {
        return;
    }
    let mut bytes = ax210_bytes();
    bytes.extend(30u32.to_le_bytes());
    bytes.extend(8u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let (observation, step_catalog) = step_fixture();
    let (observations, provider) =
        phase_catalog(&ax210_profile(), [0x610d0, 0x1234, 0x55667788], true, true);
    for stage in 0..3 {
        for fail in 0..if stage == 2 { 10 } else { 6 } {
            let mut source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let mut boot = alive_ax210(
                &catalog,
                crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            );
            let live = domain.records.lock().unwrap().live.len();
            if stage == 0 {
                source.fail_at = Some(source.calls.load(Ordering::Relaxed) + fail);
            }
            {
                let mut records = domain.records.lock().unwrap();
                if stage == 1 {
                    records.map_fail = Some(records.maps + fail);
                }
                if stage == 2 {
                    records.sync_fail = Some(records.syncs + fail);
                }
            }
            state.lock().unwrap().ops.clear();
            // SAFETY: This same AX210 epoch owns the provider data and exclusive Source/Domain;
            // serialized allocation/visibility failures keep any potentially exposed backing.
            let result = unsafe { boot.begin_pnvm(&provider, observations, &source) };
            assert!(
                matches!(result, Err(Error::PnvmDma(_)) | Err(Error::Dma(_))),
                "stage{stage} fail{fail}"
            );
            if stage == 2 && fail >= 8 {
                assert_eq!(boot.state, State::Poisoned);
                assert_eq!(domain.records.lock().unwrap().live.len(), live + 6);
            } else {
                assert_eq!(boot.state, State::Alive);
                assert_eq!(domain.records.lock().unwrap().live.len(), live);
            }
            assert!(
                !state
                    .lock()
                    .unwrap()
                    .ops
                    .iter()
                    .any(|op| matches!(op, Op::Write(0x44c, 0x100000)))
            );
            boot.stop().unwrap();
            drop(boot);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    for fail in 0..48 {
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = alive_ax210(
            &catalog,
            crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
            &source,
            &domain,
            &state,
            &drops,
        );
        // SAFETY: This sole AX210 model owner keeps provider data and its Source/Domain;
        // PNVM mappings stay owned through the later injected invalidation-failure retries.
        unsafe {
            boot.begin_pnvm(&provider, observations, &source).unwrap();
        }
        {
            let mut records = domain.records.lock().unwrap();
            records.unmap_fail = Some(records.unmaps + fail);
        }
        assert!(boot.stop().is_err(), "unmap{fail}");
        assert_eq!(boot.state, State::Quiescent);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        boot.stop().unwrap();
        drop(boot);
        assert!(domain.records.lock().unwrap().live.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn pnvm_wrong_short_and_failed_doorbell_never_release_or_synthesize_status() {
    if crate::test_process::isolate_model() {
        return;
    }
    let bytes = ax210_bytes();
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let (observation, step_catalog) = step_fixture();
    let (observations, provider) =
        phase_catalog(&ax210_profile(), [0x610d0, 0x1234, 0x55667788], true, true);
    for mode in 0..3 {
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = alive_ax210(
            &catalog,
            crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
            &source,
            &domain,
            &state,
            &drops,
        );
        if mode == 2 {
            let mut model = state.lock().unwrap();
            model.fail = Some(model.ops.len());
        }
        // SAFETY: The original model profile/provider and Source/Domain remain owned;
        // the injected doorbell failure is serialized and cannot release uncertain DMA.
        let result = unsafe { boot.begin_pnvm(&provider, observations, &source) };
        let live = domain.records.lock().unwrap().live.len();
        if mode == 2 {
            assert!(result.is_err());
            assert_eq!(boot.state, State::Poisoned);
        } else {
            result.unwrap();
            let mut packet = pnvm_packet(0);
            if mode == 0 {
                packet[5] = 4;
            } else {
                packet[..4].copy_from_slice(&6u32.to_le_bytes());
            }
            complete(&boot, &domain, 1, 2, &packet);
            if mode == 0 {
                assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Waiting);
            } else {
                assert_eq!(boot.poll_pnvm(), Err(Error::PnvmNotification));
            }
        }
        assert!(boot.pnvm_notification().is_none());
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        boot.stop().unwrap();
        drop(boot);
        assert!(domain.records.lock().unwrap().live.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn ax210_wide_invalid_and_duplicate_completions_never_release_iml() {
    if crate::test_process::isolate_model() {
        return;
    }
    let bytes = ax210_bytes();
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let (observation, step_catalog) = step_fixture();
    for mode in 1..5 {
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start_ax210(
            &catalog,
            crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
            &source,
            &domain,
            &state,
            &drops,
        );
        event(&state, 1);
        boot.poll().unwrap();
        let live = domain.records.lock().unwrap().live.len();
        match mode {
            1 | 2 => {
                device_write(
                    &domain,
                    boot.used.region().address,
                    4,
                    &if mode == 1 { 0xffffu16 } else { 31u16 }.to_le_bytes(),
                    false,
                );
                device_write(
                    &domain,
                    boot.status.region().address,
                    0,
                    &1u16.to_le_bytes(),
                    false,
                );
            }
            3 => {
                complete(&boot, &domain, 0, 1, &rx_packet(2, 0xcafe, 0));
                assert!(boot.poll().unwrap().is_none());
                device_write(
                    &domain,
                    boot.used.region().address,
                    36,
                    &1u16.to_le_bytes(),
                    false,
                );
                device_write(
                    &domain,
                    boot.status.region().address,
                    0,
                    &2u16.to_le_bytes(),
                    false,
                );
            }
            _ => {
                complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
                domain.records.lock().unwrap().cpu_sync_fail = Some(0);
            }
        }
        assert!(boot.poll().is_err(), "mode{mode}");
        assert_eq!(boot.state, State::Poisoned);
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        boot.stop().unwrap();
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
