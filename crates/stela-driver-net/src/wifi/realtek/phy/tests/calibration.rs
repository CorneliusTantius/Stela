// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8822C calibration phase fixtures and source comparisons.
use super::*;

#[test]
fn dac_sampling_and_convergence() {
    for (invalid, unstable, adc_residual, dac_residual, expected) in [
        (Some(0), false, 0, 0, Error::DacSamples { accepted: 0 }),
        (Some(99), false, 0, 0, Error::DacSamples { accepted: 99 }),
        (None, true, 0, 0, Error::DacUnstableSamples),
        (
            None,
            false,
            5,
            0,
            Error::DacAdcConvergence { path: Path::A },
        ),
        (None, false, 0, 5, Error::DacConvergence { path: Path::A }),
    ] {
        let (mut bus, initial, report) = dac_setup(0);
        {
            let mut m = bus.model.lock().unwrap();
            let d = m.dac.as_mut().unwrap();
            d.invalid_after = invalid;
            d.unstable = unstable;
            d.adc_residual = adc_residual;
            d.dac_residual = dac_residual;
        }
        assert!(
            // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
            // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
            matches!(block_on(unsafe { initial.calibrate_dac(&mut bus,&report) }),Err(e)if e==expected)
        );
        assert!(bus.model.lock().unwrap().quarantined >= 1);
    }
    for (reg, raw, expected) in [
        (0x2808, 0, Error::DacReadyTimeout { register: 0x2808 }),
        (
            0x2808,
            u32::MAX,
            Error::DacAmbiguousReady { register: 0x2808 },
        ),
        (0x2824, 1 << 19, Error::DacReadyTimeout { register: 0x2824 }),
    ] {
        let (mut bus, initial, report) = dac_setup(0);
        bus.model
            .lock()
            .unwrap()
            .dac
            .as_mut()
            .unwrap()
            .ready_override = Some((reg, raw));
        assert!(
            // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
            // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
            matches!(block_on(unsafe { initial.calibrate_dac(&mut bus,&report) }),Err(e)if e==expected)
        );
        assert!(bus.model.lock().unwrap().quarantined >= 1);
    }
}

#[test]
fn dac_final_poll_bounds() {
    let (mut bus, initial, report) = dac_setup(0);
    {
        let mut m = bus.model.lock().unwrap();
        let d = m.dac.as_mut().unwrap();
        d.invalid_prefix = 9900;
        d.ready_delay = Some((0x2808, 999));
    }
    // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
    // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
    let calibrated = block_on(unsafe { initial.calibrate_dac(&mut bus, &report) }).unwrap();
    assert_eq!(calibrated.residual(), [[0; 2]; 2]);
    let m = bus.model.lock().unwrap();
    assert!(m.dac.as_ref().unwrap().samples >= 10000);
    assert_eq!(m.dac.as_ref().unwrap().ready_reads, 1000);
    assert_eq!(m.quarantined, 0);
}

#[test]
fn dac_rf_backup_and_nibbles() {
    let (mut bus, initial, report) = dac_setup(0);
    {
        let mut m = bus.model.lock().unwrap();
        m.set(0x3e3c, 4, 0x12345);
        m.set(0x4e3c, 4, 0x6789a);
        m.dac.as_mut().unwrap().distinct_cache = true;
    }
    // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
    // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
    let calibrated = block_on(unsafe { initial.calibrate_dac(&mut bus, &report) }).unwrap();
    assert_eq!(calibrated.dck()[1], [[1, 2], [3, 4]]);
    let m = bus.model.lock().unwrap();
    assert_eq!(m.get(0x3e3c, 4) & 0xfffff, 0x12345);
    assert_eq!(m.get(0x4e3c, 4) & 0xfffff, 0x6789a);
    assert_eq!(calibrated.residual(), [[0; 2]; 2]);
    assert_eq!(m.quarantined, 0);
}

#[test]
fn dac_profile_preflight() {
    let (mut bus, initial, _) = dac_setup(0);
    let (_, _, other) = setup(2, 0, 0, 0, false, false);
    assert!(matches!(
        // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
        // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
        block_on(unsafe { initial.calibrate_dac(&mut bus, &other) }),
        Err(Error::WrongProfile)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    let (mut bus, initial, _) = dac_setup(0);
    let (_, _, one) = setup(1, 0, 0, 0, true, false);
    assert!(matches!(
        // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
        // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
        block_on(unsafe { initial.calibrate_dac(&mut bus, &one) }),
        Err(Error::UnsupportedRfLayout)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    for (r, w) in [(2, 1), (0x1f, 1), (0xec, 4)] {
        let (mut bus, initial, report) = dac_setup(0);
        bus.model.lock().unwrap().set(r, w, 0);
        assert!(matches!(
            // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
            // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
            block_on(unsafe { initial.calibrate_dac(&mut bus, &report) }),
            Err(Error::DomainOff)
        ));
        let m = bus.model.lock().unwrap();
        assert!(!m.events.iter().any(|e| e[0] == 1));
        assert_eq!(m.quarantined, 1);
    }
}

#[test]
fn dac_failure_quarantines() {
    let (mut bus, initial, report) = dac_setup(0);
    // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
    // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
    block_on(unsafe { initial.calibrate_dac(&mut bus, &report) }).unwrap();
    let total = bus.model.lock().unwrap().calls;
    let mut points: Vec<_> = (1..=48).collect();
    points.extend((1..=32).map(|i| i * total / 32));
    points.extend(total - 15..=total);
    points.sort_unstable();
    points.dedup();
    for at in points {
        let (mut bus, initial, report) = dac_setup(0);
        bus.model.lock().unwrap().fail = Some(at);
        assert!(
            // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
            // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
            block_on(unsafe { initial.calibrate_dac(&mut bus, &report) }).is_err(),
            "{at}"
        );
        assert!(bus.model.lock().unwrap().quarantined >= 1, "{at}");
    }
    for (r, w, v, at) in [
        (0xf0, 4, 0, total - 4),
        (0x80, 2, 0xffff, total - 3),
        (2, 1, 0, total - 2),
        (0x1f, 1, 0, total - 1),
        (0xec, 4, 0, total),
    ] {
        let (mut bus, initial, report) = dac_setup(0);
        bus.model.lock().unwrap().mutate = Some((at, r, w, v));
        // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
        // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
        assert!(block_on(unsafe { initial.calibrate_dac(&mut bus, &report) }).is_err());
        assert!(bus.model.lock().unwrap().quarantined >= 1);
    }
    let (mut bus, initial, report) = dac_setup(0);
    bus.panic_delay = true;
    assert!(
        // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
        // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| block_on(unsafe {
            initial.calibrate_dac(&mut bus, &report)
        })))
        .is_err()
    );
    assert!(bus.model.lock().unwrap().quarantined >= 1);
}

#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_DAC_ORACLE"]
fn rtl8822c_dac_matches_linux() {
    let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_DAC_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    for case in 0..64 {
        let header: [u32; 3] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        offset += 12;
        let [seed, input, events] = header;
        assert_eq!(input as i32, seed as i32 - 32);
        let (mut bus, initial, report) = dac_setup(seed);
        // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
        // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
        let calibrated = block_on(unsafe { initial.calibrate_dac(&mut bus, &report) }).unwrap();
        let m = bus.model.lock().unwrap();
        let native = source_events(&m.events);
        assert_eq!(native.len(), events as usize * 16, "{case}");
        assert_eq!(
            &native,
            &trace[offset..offset + native.len()],
            "case {case}"
        );
        offset += native.len();
        let mut words = Vec::new();
        words.extend(calibrated.adck());
        words.extend(
            calibrated
                .msbk()
                .iter()
                .flatten()
                .flatten()
                .copied()
                .map(u32::from),
        );
        words.extend(
            calibrated
                .dck()
                .into_iter()
                .flatten()
                .flatten()
                .map(u32::from),
        );
        let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        assert_eq!(bytes.len(), 70 * 4);
        assert_eq!(&bytes, &trace[offset..offset + bytes.len()], "{case}");
        offset += bytes.len();
        assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "{case}");
        offset += 0x5000;
        assert_eq!(m.quarantined, 0);
    }
    // Independently consumed by pure compensation test in child module.
    offset += 201 * 12;
    let negative: [u32; 6] = core::array::from_fn(|i| {
        u32::from_le_bytes(
            trace[offset + i * 4..offset + i * 4 + 4]
                .try_into()
                .unwrap(),
        )
    });
    assert_eq!(negative, [0x6789a, 0x6789a, 1, 3, 2, 4]);
    offset += 24;
    // Full signed-vector source results are independently consumed in child tests.
    offset += 2048 * 828;
    assert_eq!(offset, trace.len());
}
