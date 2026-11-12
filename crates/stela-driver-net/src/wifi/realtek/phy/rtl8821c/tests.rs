// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! The RTL8821C's PHY setup and channel switch on a register file.
use super::*;
use crate::wifi::{
    realtek::{chip::rtl8821c::tests::Regs, efuse::Logical, features::Report},
    stepped::block_on,
};

/// An RTL8821CE board on RFE `rfe`, its swing settings at index 3 and 6.
pub(crate) fn board(rfe: u8) -> Board {
    let profile = super::super::super::chip::rtl8821c::tests::profile(1);
    let mut bytes = [0xff; 768];
    bytes[0xca] = rfe;
    bytes[0xb9] = 0x25;
    bytes[0xc6] = 3;
    bytes[0xc7] = 6;
    bytes[0xd0..0xd6].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    // Path A's indices: CCK 40, 2.4 GHz BW40 42, 5 GHz BW40 38, no
    // differences.
    bytes[0x10..0xb8].fill(0);
    bytes[0x10..0x16].fill(40);
    bytes[0x16..0x1b].fill(42);
    bytes[0x22..0x30].fill(38);
    Logical::of(profile, bytes).board()
}

/// `phy_set_param` on `r` for a board on RFE `rfe`.
fn load(r: &mut Regs, rfe: u8, report: &Report) -> Result<Phy, Error> {
    let board = board(rfe);
    // SAFETY: the register file belongs to the calling test alone.
    block_on(unsafe { phy_set_param(r, &board, report) })
}

/// The PHY of a fresh RTL8821C on RFE `rfe`.
pub(crate) fn set_up(rfe: u8) -> (Regs, Phy, Report) {
    let mut r = Regs::new(1);
    let report = Report::of_one_path(r.profile);
    let phy = load(&mut r, rfe, &report).unwrap();
    (r, phy, report)
}

#[test]
fn phy_set_param_loads_the_tables_for_the_board() {
    for rfe in [0, 2, 4, 6] {
        let (r, phy, _) = set_up(rfe);
        let condition = phy.condition();
        // Package 0 matches as 15, PCIe, platform 4, cut B.
        assert_eq!(
            condition,
            u32::from(rfe) | 1 << 8 | 15 << 12 | 4 << 16 | 1 << 24
        );
        assert_eq!(r.get(REG_SYS_FUNC_EN, 1) & 0x43, 0x43);
        assert_eq!(r.get(REG_RF_CTRL, 1), 7);
        assert_eq!(r.get(REG_WLRF1 + 3, 1), 7);
        assert_eq!(r.get(REG_RXPSEL, 4) & BIT_RX_PSEL_RST, BIT_RX_PSEL_RST);
        // Path A's table goes through SIPI alone, one write per entry.
        let mut expected = alloc::vec::Vec::new();
        walk(condition, data::RF_A, |a, v| {
            if a != 0xffe && a != 0xfe {
                expected.push((a as u8, v));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(r.sipi(), expected);
        assert_eq!(r.get(REG_AFE_XTAL_CTRL, 4) >> 25 & 0x3f, 0x25);
        assert_eq!(r.get(REG_AFE_PLL_CTRL, 4) >> 1 & 0x3f, 0x25);
        assert_eq!(r.get(REG_CCK0_FAREPORT, 4) & (1 << 18 | 1 << 22), 0);
        assert_eq!(r.get(REG_BF_GROUPING, 4), 0xafff_afff);
        assert_eq!(phy.initial_igi(), (r.get(REG_IGI, 4) & 0x7f) as u8);
        assert_eq!(phy.cck_pd_default(), (r.get(REG_CSRATIO, 1) & 0x1f) as u8);
        assert_eq!(phy.crystal_cap(), 0x25);
        assert_eq!(phy.rfe(), rfe);
    }
}

#[test]
fn the_btg_agc_table_is_the_rfe_2_and_4_boards_alone() {
    let count = |rfe| {
        let mut r = Regs::new(1);
        let report = Report::of_one_path(r.profile);
        load(&mut r, rfe, &report).unwrap();
        r.writes.len()
    };
    assert!(count(2) > count(0));
    assert_eq!(count(2), count(4));
    assert_eq!(count(0), count(6));
}

#[test]
fn unknown_boards_and_two_path_reports_are_refused_before_any_write() {
    for rfe in [1, 3, 5, 7, 0x0a] {
        let mut r = Regs::new(1);
        let report = Report::of_one_path(r.profile);
        assert_eq!(
            load(&mut r, rfe, &report).err(),
            Some(Error::UnsupportedRfe(rfe))
        );
        assert!(r.writes.is_empty());
    }
    let mut r = Regs::new(1);
    let report = Report::of_two_paths(r.profile);
    assert_eq!(
        load(&mut r, 0, &report).err(),
        Some(Error::UnsupportedRfLayout)
    );
    assert!(r.writes.is_empty());
}

#[test]
fn set_channel_tunes_path_a_for_each_band_and_width() {
    let (mut r, mut phy, report) = set_up(0);
    let ch_param = phy.ch_param;
    // 2.4 GHz channel 6 at 20 MHz, outside China.
    let g = Geometry::new(6, Width::Mhz20, None, None).unwrap();
    // SAFETY: the register file belongs to this test alone.
    unsafe { phy.set_channel(&mut r, &report, g, false) }.unwrap();
    let rf18 = r.rf(RF_CHANNEL);
    assert_eq!(rf18 & 0xff, 6);
    assert_eq!(rf18 & RF18_BAND_MASK, 0);
    assert_eq!(rf18 & RF18_BW_MASK, RF18_BW_20M);
    assert_eq!(rf18 & RF18_RFSI_MASK, 0);
    assert_eq!(r.get(REG_RXPSEL, 4) & 1 << 28, 1 << 28);
    assert_eq!(r.get(REG_CLKTRK, 4) >> 17 & 0xfff, 0x96a);
    assert_eq!(r.get(REG_TXSF2, 4), ch_param[0]);
    assert_eq!(r.get(REG_TXFILTER, 4), ch_param[2]);
    // RFE 0 is not BTG: WLG switch, its CCA and LNA.
    let rfe = r.get(REG_RFECTL, 4);
    assert_eq!(
        rfe & (B_WL_SWITCH | B_WLG_SWITCH),
        B_WL_SWITCH | B_WLG_SWITCH
    );
    assert_eq!(rfe & (B_BTG_SWITCH | B_WLA_SWITCH | B_CTRL_SWITCH), 0);
    assert_eq!(r.get(REG_ENRXCCA, 4) >> 16 & 0xff, WLG_CCA);
    assert_eq!(r.get(REG_ENTXCCK, 4) & 0xffff, WLG_LNA);
    assert_eq!(r.get(REG_ADCCLK, 4) & 0x0030_03ff, 0);
    assert_eq!(r.get(REG_ADCCLK, 4) & 0x1001_0000, 0x1001_0000);
    // Swing setting 3 of 2.4 GHz is 0x16a.
    assert_eq!(r.get(REG_TXSCALE_A, 4) >> 21, 0x16a);
    assert_eq!(phy.default_ofdm_index(), 18);
    assert_eq!(r.get(REG_ACBBRXFIR, 4) >> 28 & 3, 2);
    assert_eq!(r.get(REG_TXDFIR, 4) >> 31, 1);
    assert_eq!(r.get(REG_CHFIR, 4) >> 31, 0);
    // 2.4 GHz channel 14: its own CCK filter.
    let g = Geometry::new(14, Width::Mhz20, None, None).unwrap();
    // SAFETY: as above.
    unsafe { phy.set_channel(&mut r, &report, g, false) }.unwrap();
    assert_eq!(r.get(REG_TXSF2, 4), 0xb81c);
    assert_eq!(r.get(REG_TXFILTER, 4), 0x3667);
    // 5 GHz channel 100 at 80 MHz, primary 100 of center 106.
    let g = Geometry::new(100, Width::Mhz80, Some(102), Some(106)).unwrap();
    // SAFETY: as above.
    unsafe { phy.set_channel(&mut r, &report, g, false) }.unwrap();
    let rf18 = r.rf(RF_CHANNEL);
    assert_eq!(rf18 & 0xff, 106);
    assert_eq!(rf18 & RF18_BAND_MASK, RF18_BAND_5G);
    assert_eq!(rf18 & RF18_BW_MASK, RF18_BW_80M);
    assert_eq!(rf18 & RF18_RFSI_MASK, RF18_RFSI_GE);
    assert_eq!(r.get(REG_RXPSEL, 4) & 1 << 28, 0);
    assert_eq!(r.get(REG_TXSCALE_A, 4) >> 8 & 0xf, 2);
    assert_eq!(r.get(REG_CLKTRK, 4) >> 17 & 0xfff, 0x452);
    let rfe = r.get(REG_RFECTL, 4);
    assert_eq!(
        rfe & (B_WL_SWITCH | B_WLA_SWITCH),
        B_WL_SWITCH | B_WLA_SWITCH
    );
    // The lowest 20 MHz of the 80 is RTW_SC_20_LOWEST (4).
    assert_eq!(r.get(REG_ADCCLK, 4) & 0x0300_30ff, 0x0000_0012);
    assert_eq!(r.get(REG_ADCCLK, 4) & 0x4004_0000, 0x4004_0000);
    // Swing setting 6 of 5 GHz is 0x101.
    assert_eq!(r.get(REG_TXSCALE_A, 4) >> 21, 0x101);
    assert_eq!(r.get(REG_ACBBRXFIR, 4) >> 28 & 3, 1);
    assert_eq!(r.get(REG_CHFIR, 4) >> 31, 1);
    // RTW_SC_40_LOWER on REG_DATA_SC.
    assert_eq!(r.get(0x483, 1), 4 | 10 << 4);
}

#[test]
fn china_takes_the_srrc_cck_filter_and_btg_boards_the_btg_switch() {
    let (mut r, mut phy, report) = set_up(2);
    let g = Geometry::new(13, Width::Mhz20, None, None).unwrap();
    // SAFETY: the register file belongs to this test alone.
    unsafe { phy.set_channel(&mut r, &report, g, true) }.unwrap();
    assert_eq!(r.get(REG_CCA_FLTR, 4) >> 16, 0xf8fe);
    assert_eq!(r.get(REG_TXSF2, 4), 0x64b8_0c1c);
    assert_eq!(r.get(REG_TXSF6, 4) & 0xffff, 0x8810);
    assert_eq!(r.get(REG_TXFILTER, 4), 0x0123_5667);
    let lut: alloc::vec::Vec<_> = r.sipi().into_iter().rev().take(10).collect();
    assert_eq!(lut[0], (RF_XTALX2, r.rf(RF_XTALX2)));
    let rfe = r.get(REG_RFECTL, 4);
    assert_eq!(rfe & B_BTG_SWITCH, B_BTG_SWITCH);
    assert_eq!(r.get(REG_ENRXCCA, 4) >> 16 & 0xff, BTG_CCA);
    assert_eq!(r.get(REG_ENTXCCK, 4) & 0xffff, BTG_LNA);
    // The LUT writes of channel 13 under SRRC.
    let srrc: alloc::vec::Vec<_> = r
        .sipi()
        .into_iter()
        .filter(|&(a, _)| a == RF_LUTWD0)
        .map(|(_, v)| v)
        .collect();
    assert_eq!(srrc[srrc.len() - 4..], [0x27, 0x27, 0x29, 0x26]);
}

#[test]
fn tx_power_reads_bcd_by_rate_and_writes_absolute_indices() {
    use crate::wifi::realtek::phy::{FactoryBand, FactorySheet, channel_power::Limits};
    let (mut r, phy, report) = set_up(0);
    let power = phy.factory_power();
    // rtw8821c_bb_pg_type0's first row, 0x32343638 in BCD: 1M at 38 over
    // 11M's 32.
    assert_eq!(
        power
            .reference(FactoryBand::Ghz2, 0, 0)
            .unwrap()
            .quarter_dbm(),
        32
    );
    assert_eq!(
        power.rate_delta(FactoryBand::Ghz2, 0, 0).unwrap().steps(),
        6
    );
    // FCC's CCK limit on channel 1 is 30, 2 under the reference.
    assert_eq!(
        power
            .sheet_delta(FactorySheet::Fcc, FactoryBand::Ghz2, 0, 0, 1)
            .unwrap()
            .steps(),
        -2
    );
    let g = Geometry::new(1, Width::Mhz20, None, None).unwrap();
    let limits = Limits {
        factory_sheet: FactorySheet::Fcc,
        max_eirp_mbm: 3000,
        antenna_and_combining_mbm: [600; 2],
        sar_quarter_dbm: None,
        remnant_cck: 0,
        remnant_ofdm: [0; 2],
    };
    let plan = power.plan_channel_power(g, limits).unwrap();
    // 40 plus the lowest of 6, -2 and 24 - 8 steps of EIRP room.
    assert_eq!(plan.gain(0, 0), Some(38));
    assert_eq!(plan.gain(1, 0), None);
    r.writes.clear();
    // SAFETY: the register file belongs to this test alone.
    unsafe { phy.program_channel_power(&mut r, &report, &plan) }.unwrap();
    let written: alloc::vec::Vec<_> = r
        .writes
        .iter()
        .filter(|w| (0x1d00..0x1e00).contains(&w.1))
        .map(|w| w.1)
        .collect();
    assert_eq!(
        written,
        [
            0x1d00, 0x1d04, 0x1d08, 0x1d0c, 0x1d10, 0x1d2c, 0x1d30, 0x1d34
        ]
    );
    assert_eq!(r.get(0x1d00, 1), 38);
    for register in written {
        for byte in r.get(register, 4).to_le_bytes() {
            assert!(byte <= 0x3f);
        }
    }
    // VHT 1SS MCS8 and MCS9 alone in the last word.
    assert_eq!(r.get(0x1d34, 4) >> 16, 0);
}

/// One IQK look on a register file.
fn poll(iqk: &mut Iqk, r: &mut Regs, report: &Report) -> Result<IqkProgress, Error> {
    // SAFETY: the register file belongs to the calling test alone.
    unsafe { iqk.poll(r, report, false) }
}

#[test]
fn firmware_iqk_is_one_look_a_poll_until_done_or_out_of_looks() {
    let (mut r, _, report) = set_up(0);
    r.set(0x2800 + u32::from(RF_DTXLOK) * 4, 4, 0x1234);
    r.set(REG_IQKFAILMSK, 4, 1 << 16 | 0x01);
    let mut iqk = Iqk::default();
    for _ in 0..3 {
        assert_eq!(poll(&mut iqk, &mut r, &report), Ok(IqkProgress::Pending));
    }
    r.set(0x2800 + u32::from(RF_DTXLOK) * 4, 4, IQK_DONE);
    assert_eq!(
        poll(&mut iqk, &mut r, &report),
        Ok(IqkProgress::Done {
            finished: true,
            reload: true,
            failed: 1
        })
    );
    assert_eq!(r.rf(RF_DTXLOK), 0);
    // Firmware that never reports done: 300 looks, then on alike.
    let (mut r, _, report) = set_up(0);
    r.set(REG_IQKFAILMSK, 4, 0);
    let mut iqk = Iqk::default();
    for _ in 1..IQK_POLLS {
        assert_eq!(poll(&mut iqk, &mut r, &report), Ok(IqkProgress::Pending));
    }
    assert_eq!(
        poll(&mut iqk, &mut r, &report),
        Ok(IqkProgress::Done {
            finished: false,
            reload: false,
            failed: 0
        })
    );
    assert_eq!(r.sipi().last(), Some(&(RF_DTXLOK, 0)));
}

#[test]
fn a_hurried_iqk_ends_at_its_next_look() {
    let (mut r, _, report) = set_up(0);
    r.set(REG_IQKFAILMSK, 4, 0);
    let mut iqk = Iqk::default();
    assert_eq!(poll(&mut iqk, &mut r, &report), Ok(IqkProgress::Pending));
    // SAFETY: the register file belongs to this test alone.
    let done = unsafe { iqk.poll(&mut r, &report, true) };
    assert!(matches!(
        done,
        Ok(IqkProgress::Done {
            finished: false,
            ..
        })
    ));
    assert_eq!(r.sipi().last(), Some(&(RF_DTXLOK, 0)));
}

#[test]
fn false_alarms_count_cck_only_while_it_receives_and_reset_each_counter() {
    use crate::wifi::realtek::dynamic::Alarms;
    use runtime::false_alarms;
    let (mut r, _, _) = set_up(0);
    r.set(0xa5c, 2, 30);
    r.set(0xf48, 2, 200);
    r.set(0xf04, 4, 5 << 16 | 7);
    r.set(REG_RXPSEL, 4, 0);
    let alarms = false_alarms(&mut r).unwrap();
    assert_eq!(
        alarms,
        Alarms {
            total: 200,
            cck: 30,
            cck_frames: 12
        }
    );
    r.set(REG_RXPSEL, 4, 1 << 28);
    assert_eq!(false_alarms(&mut r).unwrap().total, 230);
    // Each reset pulses and ends where rtw88 leaves it.
    assert_eq!(r.get(0x9a4, 4) & 1 << 17, 0);
    assert_ne!(r.get(0xa2c, 4) & 1 << 15, 0);
    assert_eq!(r.get(0xb58, 4) & 1, 0);
}

#[test]
fn power_tracking_asks_then_reads_and_moves_path_as_power_with_the_meter() {
    use runtime::{Tracked, Tracking};
    let (mut r, phy, report) = set_up(0);
    let default = phy.default_ofdm_index();
    let mut tracking = Tracking::new(0x20, true);
    let track = |r: &mut Regs, tracking: &mut Tracking| {
        // SAFETY: the register file belongs to this test alone.
        unsafe { tracking.track(r, &report, &phy, 1, 4, 0x30) }.unwrap()
    };
    // The first run asks the meter.
    assert_eq!(track(&mut r, &mut tracking), Tracked::Nothing);
    assert_eq!(r.rf(0x42) >> 16 & 3, 3);
    // The second reads it: ten over the efuse's, 2.4 GHz OFDM's table
    // raises the power by three, all within the TXAGC's room.
    r.set(0x2800 + 0x42 * 4, 4, (r.rf(0x42) & !0xfc00) | 0x2a << 10);
    assert_eq!(track(&mut r, &mut tracking), Tracked::Iqk);
    assert_eq!(r.get(0xc94, 4) >> 1 & 0x3f, 3);
    assert_eq!(
        r.get(REG_TXSCALE_A, 4) >> 21,
        TX_SCALE[usize::from(default)]
    );
    // An unchanged reading moves nothing and asks no second IQK.
    r.set(0xc94, 4, 0);
    assert_eq!(track(&mut r, &mut tracking), Tracked::Nothing);
    assert_eq!(track(&mut r, &mut tracking), Tracked::Nothing);
    assert_eq!(r.get(0xc94, 4), 0);
    // A channel switch starts it again; an untracked board asks nothing.
    tracking.reset();
    let mut untracked = Tracking::new(0x20, false);
    assert_eq!(track(&mut r, &mut untracked), Tracked::Nothing);
}
