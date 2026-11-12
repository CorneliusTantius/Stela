// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8822C tables phase fixtures and source comparisons.
use super::*;

#[test]
fn table_stream_preflight() {
    for cut in 0u32..=6 {
        for rfe in 0u8..=6 {
            let condition = u32::from(rfe)
                | (1 << 8)
                | (15 << 12)
                | (4 << 16)
                | ((if cut == 0 { 15 } else { cut }) << 24);
            for &(table, kind) in &TABLES {
                walk(condition, table, |a, v| check(kind, a, v)).unwrap();
            }
        }
    }
    for (cut, rfe, one, invalid, expected) in [
        (7, 0, false, false, Error::UnsupportedCut(7)),
        (0, 255, false, false, Error::UnsupportedRfe(255)),
        (0, 0, true, false, Error::UnsupportedRfLayout),
        (0, 0, false, true, Error::InvalidMac),
    ] {
        let (mut bus, board, report) = setup(cut, rfe, 0x3f, 0, one, invalid);
        assert!(
            // SAFETY: Bus exclusively serializes its Arc-held register and OTP model.
            // Board/report values stay live, including mismatch cases; no DMA or other client runs.
            matches!(block_on(unsafe { initialize(&mut bus, &board, &report) }),Err(e)if e==expected)
        );
        let m = bus.model.lock().unwrap();
        assert_eq!(m.calls, 0);
        assert!(m.events.is_empty());
        assert_eq!(m.quarantined, 0);
    }
    let (mut bus, board, _) = setup(0, 0, 0, 0, false, false);
    let (_, _, other) = setup(1, 0, 0, 0, false, false);
    assert!(matches!(
        // SAFETY: Bus exclusively serializes its Arc-held register and OTP model.
        // Board/report values stay live, including mismatch cases; no DMA or other client runs.
        block_on(unsafe { initialize(&mut bus, &board, &other) }),
        Err(Error::WrongProfile)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
}

#[test]
fn table_branch_and_grammar() {
    let condition = 5 | (1 << 8) | (15 << 12) | (4 << 16) | (3 << 24);
    let table = [
        [0x800, 1],
        [0x8300f105, 0x12345678],
        [0x40000000, 0],
        [0x804, 2],
        [0x9300f106, 0],
        [0x40000000, 0],
        [0x808, 3],
        [0xa0000000, 0],
        [0x80c, 4],
        [0xb0000000, 0],
        [0x810, 5],
    ];
    let mut actual = Vec::new();
    assert_eq!(
        walk(condition, &table, |a, v| {
            actual.push((a, v));
            Ok(())
        })
        .unwrap(),
        3
    );
    assert_eq!(actual, [(0x800, 1), (0x804, 2), (0x810, 5)]);
    let mut actual = Vec::new();
    walk(condition ^ 3, &table, |a, v| {
        actual.push((a, v));
        Ok(())
    })
    .unwrap();
    assert_eq!(actual, [(0x800, 1), (0x808, 3), (0x810, 5)]);
    for bad in [
        &[[0x40000000, 0]][..],
        &[[0xb0000000, 0]][..],
        &[[0x80000000, 0], [0x804, 1]][..],
        &[[0x80000000, 0], [0x40000000, 0]][..],
        &[[0xc0000000, 0]][..],
        &[
            [0x80000000, 0],
            [0x40000000, 0],
            [0xa0000000, 0],
            [0xa0000000, 0],
            [0xb0000000, 0],
        ][..],
    ] {
        assert!(matches!(
            walk(condition, bad, |_, _| Ok(())),
            Err(Error::TableGrammar { .. })
        ));
    }
    assert_eq!(
        check(Kind::Rf(Path::B), 256, 0),
        Err(Error::TableAddress { address: 256 })
    );
    assert_eq!(
        check(Kind::Rf(Path::A), 1, 0x100000),
        Err(Error::TableValue { address: 1 })
    );
    assert!(check(Kind::Bb, 0x5000, 0).is_err());
    assert!(check(Kind::Agc, 0x801, 0).is_err());
}

#[test]
fn table_failure_quarantines() {
    let (mut bus, board, report) = setup(1, 0, 0x7f, 0, false, false);
    // SAFETY: Bus exclusively serializes its Arc-held register and OTP model.
    // Board/report values stay live, including mismatch cases; no DMA or other client runs.
    block_on(unsafe { initialize(&mut bus, &board, &report) }).unwrap();
    let total = bus.model.lock().unwrap().calls;
    let mut positions: Vec<usize> = (1..=48).collect();
    positions.extend((1..=32).map(|i| (i * total / 32).max(1)));
    positions.extend(total - 15..=total);
    positions.sort_unstable();
    positions.dedup();
    for at in positions {
        let (mut bus, board, report) = setup(1, 0, 0x7f, 0, false, false);
        bus.model.lock().unwrap().fail = Some(at);
        assert!(
            // SAFETY: Bus exclusively serializes its Arc-held register and OTP model.
            // Board/report values stay live, including mismatch cases; no DMA or other client runs.
            block_on(unsafe { initialize(&mut bus, &board, &report) }).is_err(),
            "operation {at}"
        );
        assert!(bus.model.lock().unwrap().quarantined >= 1, "operation {at}");
    }
    for (r, w, v, at) in [(0xf0, 4, 0, total - 1), (0x80, 2, 0xffff, total)] {
        let (mut bus, board, report) = setup(1, 0, 0x7f, 0, false, false);
        bus.model.lock().unwrap().mutate = Some((at, r, w, v));
        // SAFETY: Bus exclusively serializes its Arc-held register and OTP model.
        // Board/report values stay live, including mismatch cases; no DMA or other client runs.
        assert!(block_on(unsafe { initialize(&mut bus, &board, &report) }).is_err());
        let m = bus.model.lock().unwrap();
        assert!(m.events.iter().any(|e| e[0] == 1 && e[1] >= 0x3c00));
        assert!(m.quarantined >= 1);
    }
    let (mut bus, board, report) = setup(1, 0, 0x7f, 0, false, false);
    bus.panic_delay = true;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: Bus exclusively serializes its Arc-held register and OTP model.
        // Board/report values stay live, including mismatch cases; no DMA or other client runs.
        block_on(unsafe { initialize(&mut bus, &board, &report) })
    }));
    assert!(caught.is_err());
    assert!(bus.model.lock().unwrap().quarantined >= 1);
}

#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_PHY_TABLES_ORACLE"]
fn rtl8822c_tables_match_linux() {
    let trace =
        std::fs::read(std::env::var("STELA_REALTEK_WIFI_PHY_TABLES_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    for case in 0..196 {
        let mut header = [0; 6];
        for (i, v) in header.iter_mut().enumerate() {
            *v = u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
        }
        offset += 24;
        let [cut, rfe, crystal, seed, condition, events] = header;
        let (mut bus, board, report) = setup(
            cut as u8,
            rfe as u8,
            crystal as u8,
            seed as usize,
            false,
            false,
        );
        // SAFETY: Bus exclusively serializes its Arc-held register and OTP model.
        // Board/report values stay live, including mismatch cases; no DMA or other client runs.
        let loaded = block_on(unsafe { initialize(&mut bus, &board, &report) }).unwrap();
        assert_eq!(loaded.condition(), condition);
        assert_eq!(loaded.profile(), bus.profile());
        let counts = loaded.configured_pairs();
        assert_eq!(counts[0], 0);
        assert_eq!(counts[3], data::CAL.len());
        assert!(counts[4] > 0 && counts[5] > 0);
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
    // Unchanged source one-PHY case selects B and ignores the
    // helper's rejection. Native preflight test above refuses before I/O.
    let mut rejected = [0; 5];
    for (i, value) in rejected.iter_mut().enumerate() {
        *value = u32::from_le_bytes(
            trace[offset + i * 4..offset + i * 4 + 4]
                .try_into()
                .unwrap(),
        );
    }
    assert_eq!(&rejected[..4], &[1, 1, 1, 1]);
    let condition = (1 << 24) | (4 << 16) | (15 << 12) | (1 << 8);
    let mut expected_rejections = 0;
    walk(condition, data::RF_B, |address, _| {
        if ![0xffe, 0xfe].contains(&address) {
            expected_rejections += 1;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(rejected[4], expected_rejections);
    offset += 20;
    assert_eq!(offset, trace.len());
}
