// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8822C factory phase fixtures and source comparisons.
use super::*;

#[test]
fn optional_factory_trim() {
    let (mut bus, calibration, report, physical) = trim_setup(0);
    // SAFETY: The calibration, report and decoded OTP objects remain live through the
    // call. Bus serializes their register model, including intentional provenance/profile failures.
    let factory =
        block_on(unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }).unwrap();
    assert!(!factory.x2_busy_observed());
    assert_eq!(factory.thermal_written(), [None; 2]);
    assert_eq!(factory.power_gain(), None);
    assert_eq!(factory.power_present_mask(), 0);
    assert_eq!(factory.pa_written(), [[None; 2]; 2]);
    let m = bus.model.lock().unwrap();
    let writes: Vec<_> = m.events.iter().filter(|e| e[0] == 1).collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0][1], 0xa70);
    drop(m);
    let (mut bus, calibration, report, physical) = trim_setup(320);
    // SAFETY: The calibration, report and decoded OTP objects remain live through the
    // call. Bus serializes their register model, including intentional provenance/profile failures.
    let factory =
        block_on(unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }).unwrap();
    assert_eq!(factory.raw().pa[0][1], 255);
    assert_eq!(factory.raw().pa[1][1], 255);
    assert_eq!(factory.pa_written()[0][1], Some(15));
    assert_eq!(factory.pa_written()[1][1], Some(15));
    let m = bus.model.lock().unwrap();
    assert_eq!(m.get(0x3d80, 4) & 0xf0000, 0xf0000);
    assert_eq!(m.get(0x4d80, 4) & 0xf0000, 0xf0000);
    drop(m);
    let (mut bus, calibration, report, physical) = trim_setup(1);
    // SAFETY: The calibration, report and decoded OTP objects remain live through the
    // call. Bus serializes their register model, including intentional provenance/profile failures.
    let factory =
        block_on(unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }).unwrap();
    assert!(factory.x2_busy_observed());
    assert!(factory.thermal_written()[0].is_some());
    assert_eq!(factory.thermal_written()[1], None);
    let gain = factory.power_gain().unwrap();
    assert_eq!(gain[0][0], 0);
    assert_eq!(factory.power_present_mask() & 1, 0);
    assert_ne!(factory.power_present_mask(), 0);
    assert_ne!(factory.power_present_mask(), u16::MAX);
}

#[test]
fn factory_failure_quarantines() {
    let (mut bus, calibration, report, physical) = trim_setup(511);
    // SAFETY: The calibration, report and decoded OTP objects remain live through the
    // call. Bus serializes their register model, including intentional provenance/profile failures.
    block_on(unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }).unwrap();
    let total = bus.model.lock().unwrap().calls;
    let mut points: Vec<_> = (1..=48).collect();
    points.extend((1..=32).map(|i| i * total / 32));
    points.extend(total - 15..=total);
    points.sort_unstable();
    points.dedup();
    for at in points {
        let (mut bus, calibration, report, physical) = trim_setup(511);
        bus.model.lock().unwrap().fail = Some(at);
        assert!(
            // SAFETY: The calibration, report and decoded OTP objects remain live through the
            // call. Bus serializes their register model, including intentional provenance/profile failures.
            block_on(unsafe { calibration.initialize_factory(&mut bus, &report, &physical) })
                .is_err(),
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
        let (mut bus, calibration, report, physical) = trim_setup(511);
        bus.model.lock().unwrap().mutate = Some((at, r, w, v));
        assert!(
            // SAFETY: The calibration, report and decoded OTP objects remain live through the
            // call. Bus serializes their register model, including intentional provenance/profile failures.
            block_on(unsafe { calibration.initialize_factory(&mut bus, &report, &physical) })
                .is_err()
        );
        assert!(bus.model.lock().unwrap().quarantined >= 1);
    }
    let (mut bus, calibration, report, physical) = trim_setup(511);
    bus.panic_delay = true;
    assert!(
        // SAFETY: The calibration, report and decoded OTP objects remain live through the
        // call. Bus serializes their register model, including intentional provenance/profile failures.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| block_on(unsafe {
            calibration.initialize_factory(&mut bus, &report, &physical)
        })))
        .is_err()
    );
    assert_eq!(bus.model.lock().unwrap().quarantined, 1);
}

#[test]
fn factory_calibration_preflight() {
    for change_rfe in [true, false] {
        let (mut bus, calibration, report, _) = trim_setup(0);
        {
            let mut m = bus.model.lock().unwrap();
            if change_rfe {
                m.physical[6] = 5;
            } else {
                // Append a logical power-table word at offset10.
                m.physical[16..21].copy_from_slice(&[0x2e, 1, 2, 0xff, 0xff]);
            }
        }
        // SAFETY: Bus keeps the register buffer and 512-byte OTP array behind its mutex.
        // The modeled OTP command/response runs synchronously, with no other reader or reset worker.
        let other = block_on(unsafe { crate::wifi::realtek::efuse::read(&mut bus) }).unwrap();
        bus.model.lock().unwrap().calls = 0;
        bus.model.lock().unwrap().events.clear();
        assert!(matches!(
            // SAFETY: The calibration, report and decoded OTP objects remain live through the
            // call. Bus serializes their register model, including intentional provenance/profile failures.
            block_on(unsafe { calibration.initialize_factory(&mut bus, &report, &other) }),
            Err(Error::WrongProfile)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
    }
}

#[test]
fn factory_profile_preflight() {
    let (mut bus, calibration, _, physical) = trim_setup(0);
    let (_, _, other) = setup(2, 0, 0, 0, false, false);
    assert!(matches!(
        // SAFETY: The calibration, report and decoded OTP objects remain live through the
        // call. Bus serializes their register model, including intentional provenance/profile failures.
        block_on(unsafe { calibration.initialize_factory(&mut bus, &other, &physical) }),
        Err(Error::WrongProfile)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    let (mut bus, calibration, _, physical) = trim_setup(0);
    let (_, _, one) = setup(1, 0, 0, 0, true, false);
    assert!(matches!(
        // SAFETY: The calibration, report and decoded OTP objects remain live through the
        // call. Bus serializes their register model, including intentional provenance/profile failures.
        block_on(unsafe { calibration.initialize_factory(&mut bus, &one, &physical) }),
        Err(Error::UnsupportedRfLayout)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    for (r, w) in [(2, 1), (0x1f, 1), (0xec, 4)] {
        let (mut bus, calibration, report, physical) = trim_setup(0);
        bus.model.lock().unwrap().set(r, w, 0);
        assert!(matches!(
            // SAFETY: The calibration, report and decoded OTP objects remain live through the
            // call. Bus serializes their register model, including intentional provenance/profile failures.
            block_on(unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }),
            Err(Error::DomainOff)
        ));
        let m = bus.model.lock().unwrap();
        assert!(!m.events.iter().any(|e| e[0] == 1));
        assert_eq!(m.quarantined, 1);
    }
}

#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_TRIM_ORACLE"]
fn rtl8822c_factory_matches_linux() {
    let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_TRIM_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    for case in 0..512 {
        let head: [u32; 3] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        offset += 12;
        let [seed, busy, events] = head;
        assert_eq!(seed, case);
        let (mut bus, calibration, report, physical) = trim_setup(seed);
        assert_eq!(&physical.bytes()[388..], &trace[offset + 388..offset + 512]);
        offset += 512;
        let factory =
            // SAFETY: The calibration, report and decoded OTP objects remain live through the
            // call. Bus serializes their register model, including intentional provenance/profile failures.
            block_on(unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }).unwrap();
        assert_eq!(u32::from(factory.x2_busy_observed()), busy);
        let m = bus.model.lock().unwrap();
        let native = source_events(&m.events);
        assert_eq!(native.len(), events as usize * 16, "case {case}");
        assert_eq!(
            &native,
            &trace[offset..offset + native.len()],
            "case {case}"
        );
        offset += native.len();
        assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "case {case}");
        offset += 0x5000;
        assert_eq!(m.quarantined, 0);
    }
    assert_eq!(offset, trace.len());
}
