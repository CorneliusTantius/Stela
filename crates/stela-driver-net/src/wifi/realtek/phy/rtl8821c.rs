// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! The RTL8821C's PHY as `rtw8821c.c` sets it: `rtw8821c_phy_set_param` with
//! the chip's tables on path A, and `rtw8821c_set_channel`.
use super::{
    Attempt, Error, Kind, Report,
    channel::{self, primary_index},
    channel_power::{Geometry, Width},
    walk,
};
use crate::wifi::realtek::{
    efuse::Board,
    identity::{Chip, Profile},
    io::{Io, sleep},
    rf::{self, Path},
};
mod data;

const REG_SYS_CTRL: u32 = 0x000;
const BIT_FEN_EN: u32 = 1 << 26;
const REG_SYS_FUNC_EN: u32 = 0x002;
const BIT_FEN_PCIEA: u8 = 1 << 6;
const BIT_FEN_BB_GLB_RST: u8 = 1 << 1;
const BIT_FEN_BB_RSTB: u8 = 1 << 0;
const REG_RF_CTRL: u32 = 0x01f;
const REG_WLRF1: u32 = 0x0ec;
const RF_ENABLE: u8 = 0b111;
const REG_AFE_XTAL_CTRL: u32 = 0x024;
const REG_AFE_PLL_CTRL: u32 = 0x028;
const REG_CCK_CHECK: u32 = 0x454;
const REG_RXPSEL: u32 = 0x808;
const BIT_RX_PSEL_RST: u32 = (1 << 28) | (1 << 29);
const REG_RXCCAMSK: u32 = 0x814;
const REG_CLKTRK: u32 = 0x860;
const REG_ADCCLK: u32 = 0x8ac;
const REG_ADC160: u32 = 0x8c4;
const REG_CHFIR: u32 = 0x8f0;
const REG_ACBB0: u32 = 0x948;
const REG_ACBBRXFIR: u32 = 0x94c;
const REG_RXSB: u32 = 0xa00;
const REG_CCA_FLTR: u32 = 0xa20;
const REG_TXSF2: u32 = 0xa24;
const REG_TXSF6: u32 = 0xa28;
const REG_CCK0_FAREPORT: u32 = 0xa2c;
const REG_ENTXCCK: u32 = 0xa80;
const REG_ENRXCCA: u32 = 0xa84;
const REG_CSRATIO: u32 = 0xaaa;
const REG_TXFILTER: u32 = 0xaac;
const REG_TXSCALE_A: u32 = 0xc1c;
const REG_TXDFIR: u32 = 0xc20;
pub(in crate::wifi::realtek) const REG_IGI: u32 = 0xc50;
const REG_RFECTL: u32 = 0xcb8;
const B_BTG_SWITCH: u32 = 1 << 16;
const B_CTRL_SWITCH: u32 = 1 << 18;
const B_WL_SWITCH: u32 = (1 << 20) | (1 << 22);
const B_WLG_SWITCH: u32 = 1 << 21;
const B_WLA_SWITCH: u32 = 1 << 23;
const BTG_LNA: u32 = 0xfc84;
const WLG_LNA: u32 = 0x7532;
const BTG_CCA: u32 = 0x0e;
const WLG_CCA: u32 = 0x12;
const REG_DMEM_CTRL: u32 = 0x1080;
const BIT_WL_RST: u32 = 1 << 16;
const REG_BF_GROUPING: u32 = 0x1c94;

const RF_CHANNEL: u8 = 0x18;
const RF_LUTWA: u8 = 0x33;
const RF_LUTWD0: u8 = 0x3f;
const RF_GAIN_LUT: u8 = 0x64;
const RF_XTALX2: u8 = 0xb8;
const RF_LUTDBG: u8 = 0xdf;
const RF_LUTWE2: u8 = 0xee;
const RF18_BAND_5G: u32 = (1 << 16) | (1 << 8);
const RF18_BAND_MASK: u32 = (1 << 16) | (1 << 9) | (1 << 8);
const RF18_CHANNEL_MASK: u32 = 0xff;
const RF18_RFSI_MASK: u32 = (1 << 18) | (1 << 17);
const RF18_RFSI_GE: u32 = 1 << 17;
const RF18_RFSI_GT: u32 = 1 << 18;
const RF18_BW_MASK: u32 = (1 << 11) | (1 << 10);
const RF18_BW_20M: u32 = (1 << 11) | (1 << 10);
const RF18_BW_40M: u32 = 1 << 11;
const RF18_BW_80M: u32 = 1 << 10;

/// `rtw8821c_txscale_tbl`.
pub(in crate::wifi::realtek) const TX_SCALE: [u32; 37] = [
    0x081, 0x088, 0x090, 0x099, 0x0a2, 0x0ac, 0x0b6, 0x0c0, 0x0cc, 0x0d8, 0x0e5, 0x0f2, 0x101,
    0x110, 0x120, 0x131, 0x143, 0x156, 0x16a, 0x180, 0x197, 0x1af, 0x1c8, 0x1e3, 0x200, 0x21e,
    0x23e, 0x261, 0x285, 0x2ab, 0x2d3, 0x2fe, 0x32b, 0x35c, 0x38e, 0x3c4, 0x3fe,
];

/// The RTL8821C's PHY as `rtw8821c_phy_set_param` leaves it.
#[derive(Debug)]
pub struct Phy {
    profile: Profile,
    condition: u32,
    rfe: u8,
    rfe_btg: bool,
    tx_bb_swing: [u8; 2],
    crystal_cap: u8,
    /// `hal->ch_param`: the CCK TX filter the tables left.
    ch_param: [u32; 3],
    /// `dm_info->igi_history[0]`.
    igi: u8,
    /// `dm_info->cck_pd_default`.
    cck_pd_default: u8,
    /// `dm_info->default_ofdm_index`.
    default_ofdm_index: u8,
}

impl Phy {
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn condition(&self) -> u32 {
        self.condition
    }
    pub fn rfe(&self) -> u8 {
        self.rfe
    }
    pub fn crystal_cap(&self) -> u8 {
        self.crystal_cap
    }
    pub fn initial_igi(&self) -> u8 {
        self.igi
    }
    pub fn cck_pd_default(&self) -> u8 {
        self.cck_pd_default
    }
    pub fn default_ofdm_index(&self) -> u8 {
        self.default_ofdm_index
    }
}

/// `rtw_phy_setup_phy_cond` for an RTL8821C on `board`.
fn condition(profile: Profile, board: &Board, rfe: u8) -> u32 {
    let cut = match profile.cut() {
        0 => 15,
        cut => u32::from(cut),
    };
    let package = match board.raw().package {
        0 => 15,
        package => u32::from(package),
    };
    u32::from(rfe) | (1 << 8) | (package << 12) | (4 << 16) | (cut << 24)
}

/// The tables `rtw_phy_load_tables` loads for `board`, in its order:
/// MAC, BB, AGC, the RFE's 2.4 GHz BTG AGC on RFE 2 and 4, then path A.
fn tables(rfe: u8) -> impl Iterator<Item = (&'static [[u32; 2]], Kind)> {
    let btg = matches!(rfe, 2 | 4).then_some((data::AGC_BTG_TYPE2, Kind::Agc));
    [
        (data::MAC, Kind::Mac),
        (data::BB, Kind::Bb),
        (data::AGC, Kind::Agc),
    ]
    .into_iter()
    .chain(btg)
    .chain([(data::RF_A, Kind::Rf(Path::A))])
}

/// `rtw8821c_get_swing_index`: where `REG_TXSCALE_A`'s swing sits in
/// [`TX_SCALE`], or past its end.
pub(in crate::wifi::realtek) fn swing_index<I: Io>(io: &mut I) -> Result<u8, Error> {
    let swing = io.read32(REG_TXSCALE_A)? >> 21;
    Ok(TX_SCALE
        .iter()
        .position(|&value| value == swing)
        .unwrap_or(TX_SCALE.len()) as u8)
}

/// `rtw8821c_pwrtrack_init`'s default OFDM index.
fn default_ofdm_index<I: Io>(io: &mut I) -> Result<u8, Error> {
    let index = swing_index(io)?;
    Ok(if usize::from(index) >= TX_SCALE.len() {
        24
    } else {
        index
    })
}

/// `rtw8821c_phy_set_param`, with `rtw_phy_init`'s reads.
///
/// # Safety
/// As [`super::initialize`]: the Io, OTP board and report of one RTL8821C and
/// one uninterrupted boot, after the MAC init, with nothing transmitting.
pub async unsafe fn phy_set_param<I: Io>(
    io: &mut I,
    board: &Board,
    report: &Report,
) -> Result<Phy, Error> {
    let profile = io.profile();
    if profile.chip() != Chip::Rtl8821C || board.profile() != profile || report.profile() != profile
    {
        return Err(Error::WrongProfile);
    }
    if profile.cut() > 6 {
        return Err(Error::UnsupportedCut(profile.cut()));
    }
    let rfe = board
        .source_rfe()
        .map_err(|_| Error::UnsupportedRfe(board.raw().rfe_raw))?;
    board.valid_mac().map_err(|_| Error::InvalidMac)?;
    let cap = report.capabilities();
    if cap.rf_phys != 1 || cap.rf_paths != 1 {
        return Err(Error::UnsupportedRfLayout);
    }
    let condition = condition(profile, board, rfe);
    // Every selected stream is checked before the first write.
    for (table, kind) in tables(rfe) {
        walk(condition, table, |a, v| super::check(kind, a, v))?;
    }
    let mut a = Attempt {
        io,
        profile,
        done: false,
    };
    a.verify()?;
    // Power on the BB and RF domains, and pulse the BB reset.
    let mut value = a.io.read8(REG_SYS_FUNC_EN)? | BIT_FEN_PCIEA;
    a.io.write8(REG_SYS_FUNC_EN, value)?;
    value |= BIT_FEN_BB_RSTB | BIT_FEN_BB_GLB_RST;
    a.io.write8(REG_SYS_FUNC_EN, value)?;
    value &= !(BIT_FEN_BB_RSTB | BIT_FEN_BB_GLB_RST);
    a.io.write8(REG_SYS_FUNC_EN, value)?;
    value |= BIT_FEN_BB_RSTB | BIT_FEN_BB_GLB_RST;
    a.io.write8(REG_SYS_FUNC_EN, value)?;
    a.io.write8(REG_RF_CTRL, RF_ENABLE)?;
    sleep(a.io, 10).await;
    a.io.write8(REG_WLRF1 + 3, RF_ENABLE)?;
    sleep(a.io, 10).await;
    // Before the header files.
    a.modify32(REG_RXPSEL, BIT_RX_PSEL_RST, 0)?;
    for (table, kind) in tables(rfe) {
        a.table(table, kind, condition, report).await?;
    }
    let crystal = board.raw().crystal_cap_raw & 0x3f;
    a.modify32(REG_AFE_XTAL_CTRL, 0x7e00_0000, crystal.into())?;
    a.modify32(REG_AFE_PLL_CTRL, 0x7e, crystal.into())?;
    a.modify32(REG_CCK0_FAREPORT, (1 << 18) | (1 << 22), 0)?;
    // After the header files.
    a.modify32(REG_RXPSEL, BIT_RX_PSEL_RST, 3)?;
    let ch_param = [
        a.io.read32(REG_TXSF2)?,
        a.io.read32(REG_TXSF6)?,
        a.io.read32(REG_TXFILTER)?,
    ];
    // rtw_phy_init: the gain the tables left (`rtw8821c_dig`).
    let igi = (a.io.read32(REG_IGI)? & 0x7f) as u8;
    let cck_pd_default = a.io.read8(REG_CSRATIO)? & 0x1f;
    let default_ofdm_index = default_ofdm_index(a.io)?;
    // rtw8821c_phy_bf_init: rtw_bf_phy_init, then the grouping bitmap.
    a.beamforming_init()?;
    a.io.write32(REG_BF_GROUPING, 0xafff_afff)?;
    a.verify()?;
    a.done = true;
    Ok(Phy {
        profile,
        condition,
        rfe,
        rfe_btg: board.raw().rfe_btg,
        tx_bb_swing: board.raw().tx_bb_swing,
        crystal_cap: crystal,
        ch_param,
        igi,
        cck_pd_default,
        default_ofdm_index,
    })
}

/// `rtw8821ce_rf_set`.
#[derive(Clone, Copy)]
enum RfSet {
    Btg,
    Wlg,
    Wla,
}

fn center(g: Geometry) -> u8 {
    g.centers()[g.width() as usize].unwrap_or(g.primary())
}

impl Phy {
    /// `rtw8821c_set_channel` for `geometry`; `srrc` when the country is
    /// China's (`rtw_regd_srrc`).
    ///
    /// # Safety
    /// The Io and report of the boot this PHY came from, with nothing else
    /// reaching the BB or RF.
    pub unsafe fn set_channel<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        geometry: Geometry,
        srrc: bool,
    ) -> Result<(), Error> {
        if io.profile() != self.profile || report.profile() != self.profile {
            return Err(Error::WrongProfile);
        }
        let index = primary_index(geometry);
        let mut a = Attempt {
            io,
            profile: self.profile,
            done: false,
        };
        a.domain()?;
        self.bb(&mut a, report, geometry, index, srrc)?;
        // rtw8821c_set_channel_bb_swing, then rtw8821c_pwrtrack_init.
        let swing = self.bb_swing(center(geometry));
        a.modify32(REG_TXSCALE_A, 0xffe0_0000, swing)?;
        self.default_ofdm_index = default_ofdm_index(a.io)?;
        channel::mac(&mut a, geometry, index)?;
        self.rf(&mut a, report, geometry)?;
        self.rxdfir(&mut a, geometry.width())?;
        a.domain()?;
        a.done = true;
        Ok(())
    }

    /// `rtw8821c_get_bb_swing`.
    fn bb_swing(&self, channel: u8) -> u32 {
        const SETTING: [u32; 4] = [0x200, 0x16a, 0x101, 0x0b6];
        let swing = self.tx_bb_swing[usize::from(channel > 14)];
        SETTING[usize::from(if swing > 9 { 0 } else { swing / 3 })]
    }

    /// `rtw8821c_switch_rf_set`.
    fn switch_rf_set<I: Io>(&self, a: &mut Attempt<'_, I>, set: RfSet) -> Result<(), Error> {
        a.modify32(REG_DMEM_CTRL, BIT_WL_RST, 1)?;
        a.modify32(REG_SYS_CTRL, BIT_FEN_EN, 1)?;
        let mut value = a.io.read32(REG_RFECTL)?;
        match set {
            RfSet::Btg => {
                value |= B_BTG_SWITCH;
                value &= !(B_CTRL_SWITCH | B_WL_SWITCH | B_WLG_SWITCH | B_WLA_SWITCH);
                a.modify32(REG_ENRXCCA, 0x00ff_0000, BTG_CCA)?;
                a.modify32(REG_ENTXCCK, 0xffff, BTG_LNA)?;
            }
            RfSet::Wlg => {
                value |= B_WL_SWITCH | B_WLG_SWITCH;
                value &= !(B_BTG_SWITCH | B_CTRL_SWITCH | B_WLA_SWITCH);
                a.modify32(REG_ENRXCCA, 0x00ff_0000, WLG_CCA)?;
                a.modify32(REG_ENTXCCK, 0xffff, WLG_LNA)?;
            }
            RfSet::Wla => {
                value |= B_WL_SWITCH | B_WLA_SWITCH;
                value &= !(B_BTG_SWITCH | B_CTRL_SWITCH | B_WLG_SWITCH);
            }
        }
        a.io.write32(REG_RFECTL, value)?;
        Ok(())
    }

    /// `rtw8821c_set_channel_rf`.
    fn rf<I: Io>(&self, a: &mut Attempt<'_, I>, report: &Report, g: Geometry) -> Result<(), Error> {
        let channel = center(g);
        if channel <= 14 {
            let set = if self.rfe_btg { RfSet::Btg } else { RfSet::Wlg };
            self.switch_rf_set(a, set)?;
        } else {
            self.switch_rf_set(a, RfSet::Wla)?;
        }
        // SAFETY: the caller's boot, with the BB/RF domains on.
        let mut rf = unsafe { rf::Registers::new(&mut *a.io, report) }?;
        let mut rf18 = rf.read(Path::A, RF_CHANNEL, 0xfffff)?;
        rf18 &= !(RF18_BAND_MASK | RF18_CHANNEL_MASK | RF18_RFSI_MASK | RF18_BW_MASK);
        if channel > 14 {
            rf18 |= RF18_BAND_5G;
        }
        rf18 |= u32::from(channel) & RF18_CHANNEL_MASK;
        if (100..=140).contains(&channel) {
            rf18 |= RF18_RFSI_GE;
        } else if channel > 140 {
            rf18 |= RF18_RFSI_GT;
        }
        rf18 |= match g.width() {
            Width::Mhz20 => RF18_BW_20M,
            Width::Mhz40 => RF18_BW_40M,
            Width::Mhz80 => RF18_BW_80M,
        };
        if channel <= 14 {
            rf.write(Path::A, RF_LUTDBG, 1 << 6, 1)?;
            rf.write(Path::A, RF_GAIN_LUT, 0xf, 0xf)?;
        } else {
            rf.write(Path::A, RF_LUTDBG, 1 << 6, 0)?;
        }
        rf.write(Path::A, RF_CHANNEL, 0xfffff, rf18)?;
        rf.write(Path::A, RF_XTALX2, 1 << 19, 0)?;
        rf.write(Path::A, RF_XTALX2, 1 << 19, 1)?;
        Ok(())
    }

    /// `rtw8821c_set_channel_rxdfir`.
    fn rxdfir<I: Io>(&self, a: &mut Attempt<'_, I>, width: Width) -> Result<(), Error> {
        let (rxfir, txdfir, chfir) = match width {
            Width::Mhz40 => (2, 0, 0),
            Width::Mhz80 => (1, 0, 1),
            Width::Mhz20 => (2, 1, 0),
        };
        a.modify32(REG_ACBB0, 3 << 28, 2)?;
        a.modify32(REG_ACBBRXFIR, 3 << 28, rxfir)?;
        a.modify32(REG_TXDFIR, 1 << 31, txdfir)?;
        a.modify32(REG_CHFIR, 1 << 31, chfir)
    }

    /// The CCK TX filter rtw88 sets on 2.4 GHz outside China.
    fn cck_filter<I: Io>(&self, a: &mut Attempt<'_, I>, channel: u8) -> Result<(), Error> {
        let [sf2, sf6, filter] = if channel == 14 {
            [0x0000_b81c, 0x0000, 0x0000_3667]
        } else {
            self.ch_param
        };
        a.modify32(REG_TXSF2, u32::MAX, sf2)?;
        a.modify32(REG_TXSF6, 0xffff, sf6 & 0xffff)?;
        a.modify32(REG_TXFILTER, u32::MAX, filter)
    }

    /// `rtw8821c_cck_tx_filter_srrc`.
    fn cck_filter_srrc<I: Io>(
        &self,
        a: &mut Attempt<'_, I>,
        report: &Report,
        channel: u8,
        width: Width,
    ) -> Result<(), Error> {
        let (cca, [sf2, sf6, filter], lut) = if channel == 14 {
            (0xe82c, [0x0000_b81c, 0x0000, 0x0000_3667], [0; 4])
        } else if channel == 13 || (channel == 11 && width == Width::Mhz40) {
            (
                0xf8fe,
                [0x64b8_0c1c, 0x8810, 0x0123_5667],
                [0x27, 0x27, 0x29, 0x26],
            )
        } else {
            (0xe82c, self.ch_param, [0; 4])
        };
        a.modify32(REG_CCA_FLTR, 0xffff_0000, cca)?;
        a.modify32(REG_TXSF2, u32::MAX, sf2)?;
        a.modify32(REG_TXSF6, 0xffff, sf6 & 0xffff)?;
        a.modify32(REG_TXFILTER, u32::MAX, filter)?;
        // SAFETY: the caller's boot, with the BB/RF domains on.
        let mut rf = unsafe { rf::Registers::new(&mut *a.io, report) }?;
        rf.write(Path::A, RF_LUTWE2, 0xfffff, 2)?;
        for (address, value) in [0x1e, 0x1c, 0x0e, 0x0c].into_iter().zip(lut) {
            rf.write(Path::A, RF_LUTWA, 0xfffff, address)?;
            rf.write(Path::A, RF_LUTWD0, 0xfffff, value)?;
        }
        rf.write(Path::A, RF_LUTWE2, 0xfffff, 0)?;
        Ok(())
    }

    /// `rtw8821c_set_channel_bb`.
    fn bb<I: Io>(
        &self,
        a: &mut Attempt<'_, I>,
        report: &Report,
        g: Geometry,
        index: u8,
        srrc: bool,
    ) -> Result<(), Error> {
        let channel = center(g);
        if channel <= 14 {
            a.modify32(REG_RXPSEL, 1 << 28, 1)?;
            a.modify32(REG_CCK_CHECK, 1 << 7, 0)?;
            a.modify32(REG_ENTXCCK, 1 << 18, 0)?;
            a.modify32(REG_RXCCAMSK, 0xfc00, 15)?;
            a.modify32(REG_TXSCALE_A, 0xf00, 0)?;
            a.modify32(REG_CLKTRK, 0x1ffe_0000, 0x96a)?;
            if srrc {
                self.cck_filter_srrc(a, report, channel, g.width())?;
            } else {
                self.cck_filter(a, channel)?;
            }
        } else {
            a.modify32(REG_ENTXCCK, 1 << 18, 1)?;
            a.modify32(REG_CCK_CHECK, 1 << 7, 1)?;
            a.modify32(REG_RXPSEL, 1 << 28, 0)?;
            a.modify32(REG_RXCCAMSK, 0xfc00, 15)?;
            let scale = match channel {
                36..=64 => Some(1),
                100..=144 => Some(2),
                149.. => Some(3),
                _ => None,
            };
            if let Some(scale) = scale {
                a.modify32(REG_TXSCALE_A, 0xf00, scale)?;
            }
            let tracking = match channel {
                36..=48 => Some(0x494),
                52..=64 => Some(0x453),
                100..=116 => Some(0x452),
                118..=177 => Some(0x412),
                _ => None,
            };
            if let Some(tracking) = tracking {
                a.modify32(REG_CLKTRK, 0x1ffe_0000, tracking)?;
            }
        }
        let index = u32::from(index & 0xf);
        if g.width() == Width::Mhz40 {
            // The primary 20 MHz is the upper one (RTW_SC_20_UPPER).
            a.modify32(REG_RXSB, 1 << 4, u32::from(index == 1))?;
        }
        let old = a.io.read32(REG_ADCCLK)?;
        let value = match g.width() {
            Width::Mhz20 => (old & 0xffcf_fc00) | 0x1001_0000,
            Width::Mhz40 => (old & 0xff3f_f300) | 0x2002_0000 | (index << 2) | 1,
            Width::Mhz80 => (old & 0xfcff_cf00) | 0x4004_0000 | (index << 2) | 2,
        };
        a.modify32(REG_ADCCLK, u32::MAX, value)?;
        a.modify32(REG_ADC160, 1 << 30, 1)
    }
}

#[cfg(test)]
mod tests;
