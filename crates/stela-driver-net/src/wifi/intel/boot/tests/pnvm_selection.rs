// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn alive_bios_source_scratch_doorbell_and_raw_notification_preserve_tables() {
    if crate::test_process::isolate_model() {
        return;
    }
    for fragmented in [false, true] {
        let mut bytes = ax210_bytes();
        if fragmented {
            bytes.extend(30u32.to_le_bytes());
            bytes.extend(8u32.to_le_bytes());
            bytes.extend(1u32.to_le_bytes());
            bytes.extend(1u32.to_le_bytes());
        }
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let (observations, provider) =
            phase_catalog(&ax210_profile(), [0x610d0, 0x1234, 0x55667788], true, true);
        let mut boot = alive_ax210(
            &catalog,
            crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
            &source,
            &domain,
            &state,
            &drops,
        );
        let live = domain.records.lock().unwrap().live.len();
        assert_eq!(
            // SAFETY: The provider/observations belong to this model profile/SKU, and Source
            // supplies exclusive RAM in the original boot Domain through PNVM completion.
            unsafe { boot.begin_pnvm(&provider, observations, &source) }.unwrap(),
            PnvmProgress::Waiting
        );
        let added = if fragmented { 6 } else { 2 };
        assert_eq!(domain.records.lock().unwrap().live.len(), live + added);
        assert!(matches!(
            boot.platform_receipts().unwrap().pnvm,
            calibration::Source::Bios { .. }
        ));
        assert_eq!(
            boot.platform_receipts().unwrap().pnvm_version,
            Some(0x12345678)
        );
        assert_eq!(
            boot.platform_receipts().unwrap().transfer,
            calibration::Transfer::ScratchV2
        );
        let memory = boot.ax210.as_ref().unwrap();
        let pnvm = device_read(&domain, memory.scratch.region().address, 16, 16);
        let power = device_read(&domain, memory.scratch.region().address, 60, 16);
        assert_eq!(u32::from_le_bytes(pnvm[8..12].try_into().unwrap()), 33);
        assert_eq!(u32::from_le_bytes(power[8..12].try_into().unwrap()), 25);
        assert!(
            state
                .lock()
                .unwrap()
                .ops
                .windows(2)
                .any(|ops| ops == [Op::Write(0x444, 0x03d05c04), Op::Write(0x44c, 1 << 20)])
        );
        assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Waiting);
        complete(&boot, &domain, 1, 2, &pnvm_packet(0xdeadbeef));
        assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Observed);
        let notification = boot.pnvm_notification().unwrap();
        assert_eq!(notification.status, 0xdeadbeef);
        assert_eq!(
            notification.raw,
            [0xef, 0xbe, 0xad, 0xde, 0x78, 0x56, 0x34, 0x12]
        );
        assert_eq!(domain.records.lock().unwrap().live.len(), live + added);
        assert!(matches!(
            // SAFETY: The completed PNVM state still keeps its original Source/Domain and
            // platform buffers; this duplicate begin cannot gain a second publication owner.
            unsafe { boot.begin_pnvm(&provider, observations, &source) },
            Err(Error::State)
        ));
        boot.stop().unwrap();
        drop(boot);
        assert!(domain.records.lock().unwrap().live.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

/// Whether the PNVM doorbell (`UREG_DOORBELL_TO_ISR6_PNVM`) rang.
fn pnvm_doorbell(state: &Mutex<ModelState>) -> bool {
    state
        .lock()
        .unwrap()
        .ops
        .windows(2)
        .any(|ops| ops == [Op::Write(0x444, 0x03d05c04), Op::Write(0x44c, 1 << 20)])
}

#[test]
fn zero_sku_requests_nothing_and_tables_linux_does_without_leave_the_doorbell() {
    if crate::test_process::isolate_model() {
        return;
    }
    use core::cell::RefCell;
    struct Spy<'a> {
        catalog: &'a resources::Catalog,
        requests: RefCell<Vec<alloc::string::String>>,
    }
    impl resources::Provider for Spy<'_> {
        fn load<'p>(
            &'p self,
            r: resources::Requirement<'_>,
        ) -> Result<resources::Image<'p>, resources::Error> {
            self.requests.borrow_mut().push(r.name.into());
            resources::Provider::load(self.catalog, r)
        }
    }
    for mode in 0..4 {
        let bytes = ax210_bytes();
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut sku = if mode == 0 {
            [0; 3]
        } else {
            [0x610d0, 0x1234, 0x55667788]
        };
        if mode == 2 {
            sku[0] ^= 1;
        }
        let (mut observations, provider) = phase_catalog(&ax210_profile(), sku, mode != 3, false);
        if mode == 0 || mode == 1 {
            observations = Observations::default();
        }
        let spy = Spy {
            catalog: &provider,
            requests: RefCell::new(Vec::new()),
        };
        // Without a capture the STEP data is left out, as Linux leaves out
        // a variable it cannot read.
        let step = if mode == 1 {
            crate::wifi::intel::platform::load_step_or_ignore(
                crate::wifi::intel::platform::Observation::NotCaptured,
                &step_catalog,
            )
        } else {
            crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap()
        };
        let mut boot = start_ax210(&catalog, step, &source, &domain, &state, &drops);
        event(&state, 1);
        boot.poll().unwrap();
        let mut packet = rx_packet(1, 0xcafe, 0);
        if mode == 0 {
            set_sku(&mut packet, [0; 3]);
        }
        complete(&boot, &domain, 0, 1, &packet);
        boot.poll().unwrap().unwrap();
        let calls = source.calls.load(Ordering::Relaxed);
        state.lock().unwrap().ops.clear();
        // SAFETY: The spy forwards this same profile catalog, including deliberate missing
        // inputs; boot keeps its original Domain and Source for any allowed publication.
        let result = unsafe { boot.begin_pnvm(&spy, observations, &source) };
        match mode {
            0 => {
                assert_eq!(result.unwrap(), PnvmProgress::Skipped);
                assert!(spy.requests.borrow().is_empty());
                assert!(state.lock().unwrap().ops.is_empty());
            }
            // `iwl_get_pnvm_image`: a BIOS image that cannot be read falls
            // back to the file; a reduced-power table that cannot be read is
            // left out and the doorbell still rings.
            1 => {
                assert_eq!(result.unwrap(), PnvmProgress::Waiting);
                assert_eq!(
                    spy.requests.borrow().as_slice(),
                    ["iwlwifi-ty-a0-gf-a0.pnvm"]
                );
                let receipts = boot.platform_receipts().unwrap();
                assert!(matches!(
                    receipts.pnvm,
                    calibration::Source::External {
                        bios_fallback: Some(_),
                        ..
                    }
                ));
                assert!(matches!(
                    receipts.reduced_power,
                    calibration::Source::Skipped
                ));
                assert!(matches!(
                    receipts.skipped.as_slice(),
                    [calibration::Error::Observation { .. }]
                ));
                assert!(pnvm_doorbell(&state));
                assert_eq!(
                    crate::wifi::intel::link::degraded(&boot),
                    [
                        "the platform's Wi-Fi STEP data: the firmware boots without it",
                        "the platform's reduced-power Wi-Fi tables: the firmware runs without them"
                    ]
                );
            }
            // `iwl_pnvm_parse`: a BIOS image without this SKU gives no PNVM
            // and no switch to the file, and the firmware still gets its
            // doorbell to run on its defaults.
            2 => {
                assert_eq!(result.unwrap(), PnvmProgress::Waiting);
                assert_eq!(
                    spy.requests.borrow().as_slice(),
                    [crate::wifi::intel::platform::Variable::OemPnvm.resource_name()]
                );
                let receipts = boot.platform_receipts().unwrap();
                assert!(matches!(receipts.pnvm, calibration::Source::Skipped));
                assert!(matches!(
                    receipts.skipped.as_slice(),
                    [calibration::Error::Selection(_)]
                ));
                assert!(pnvm_doorbell(&state));
                assert_eq!(
                    crate::wifi::intel::link::degraded(&boot),
                    ["the Wi-Fi PNVM tables for this adapter: the firmware runs on its defaults"]
                );
                complete(&boot, &domain, 1, 2, &pnvm_packet(0));
                assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Observed);
            }
            _ => {
                assert_eq!(result.unwrap(), PnvmProgress::Waiting);
                assert_eq!(
                    spy.requests.borrow().as_slice(),
                    ["iwlwifi-ty-a0-gf-a0.pnvm"]
                );
                assert!(matches!(
                    boot.platform_receipts().unwrap().pnvm,
                    calibration::Source::External {
                        bios_fallback: Some(_),
                        ..
                    }
                ));
                assert!(matches!(
                    boot.platform_receipts().unwrap().reduced_power,
                    calibration::Source::Unavailable { .. }
                ));
            }
        }
        if mode != 1 && mode != 3 {
            assert_eq!(source.calls.load(Ordering::Relaxed), calls);
        }
        boot.stop().unwrap();
        drop(boot);
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
}

#[test]
fn ax200_keeps_bios_receipts_and_explicit_pre_v2_no_payload_transfer() {
    if crate::test_process::isolate_model() {
        return;
    }
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let (observations, provider) =
        phase_catalog(&profile(), [0x610d0, 0x1234, 0x55667788], true, true);
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start(&catalog, &source, &domain, &state, &drops);
    event(&state, 1);
    boot.poll().unwrap();
    complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
    boot.poll().unwrap().unwrap();
    let maps = domain.records.lock().unwrap().maps;
    let live = domain.records.lock().unwrap().live.len();
    assert_eq!(
        // SAFETY: The AX200 provider/observations match the model profile/SKU;
        // Source/Domain stay exclusive while the pre-v2 path publishes only its doorbell.
        unsafe { boot.begin_pnvm(&provider, observations, &source) }.unwrap(),
        PnvmProgress::Waiting
    );
    assert_eq!(
        boot.platform_receipts().unwrap().transfer,
        calibration::Transfer::NotUsedBeforeAx210
    );
    assert!(matches!(
        boot.platform_receipts().unwrap().pnvm,
        calibration::Source::Bios { .. }
    ));
    assert_eq!(domain.records.lock().unwrap().maps, maps);
    assert!(
        state
            .lock()
            .unwrap()
            .ops
            .windows(2)
            .any(|ops| ops == [Op::Write(0x444, 0x03005c04), Op::Write(0x44c, 1 << 20)])
    );
    complete(&boot, &domain, 1, 2, &pnvm_packet(0x123));
    assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Observed);
    assert_eq!(boot.pnvm_notification().unwrap().status, 0x123);
    assert_eq!(domain.records.lock().unwrap().live.len(), live);
    boot.stop().unwrap();
    drop(boot);
    assert!(domain.records.lock().unwrap().live.is_empty());
}
