// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C transmit calibration around firmware's IQK: `rtw8822c_do_gapk`, which
//! evens out the gain table between steps, and `rtw8822c_do_dpk`, which learns the
//! amplifier's curve and predistorts against it.
use super::{
    coex::{self, Coex},
    features::Report,
    io::{self, Io},
    rf::{self, Path},
};
use alloc::vec::Vec;

const MASK_BYTE0: u32 = 0xff;
const MASK_BYTE1: u32 = 0xff00;
const MASK_BYTE3: u32 = 0xff00_0000;
const MASK_HIGH: u32 = 0xffff_0000;
const MASK_LOW: u32 = 0xffff;
const MASK_WORD: u32 = u32::MAX;
const RF_WHOLE: u32 = 0xfffff;

const REG_RSV_CTRL: u32 = 0x1c;
const REG_WLRF1: u32 = 0xec;
const REG_GNT_CONTROL: u32 = 0x70;
const REG_PMC_DBG_CTRL1: u32 = 0xa8;
const REG_ARFR4: u32 = 0x49c;
const REG_TX_PTCL_CTRL: u32 = 0x520;
const REG_TXPAUSE: u32 = 0x522;
const REG_ANTMAP0: u32 = 0x820;
const REG_ORITXCODE: [u32; 2] = [0x1800, 0x4100];
const REG_3WIRE: [u32; 2] = [0x180c, 0x410c];
const REG_ANAPAR: [u32; 2] = [0x1830, 0x4130];
const REG_RFTXEN_GCK: [u32; 2] = [0x1864, 0x4164];
const REG_DIS_SHARE_RX: [u32; 2] = [0x186c, 0x416c];
const REG_CCKSB: u32 = 0x1a00;
const REG_NCTL0: u32 = 0x1b00;
const REG_DPD_CTL0_S0: u32 = 0x1b04;
const REG_DPD_CTL1_S0: u32 = 0x1b08;
const REG_IQKSTAT: u32 = 0x1b10;
const REG_DPK_SCALE: u32 = 0x1b18;
const REG_IQK_CTL1: u32 = 0x1b20;
const REG_TX_TONE_IDX: u32 = 0x1b2c;
const REG_DPD_LUT0: u32 = 0x1b44;
const REG_DPK_LOSS_SELECT: u32 = 0x1b48;
const REG_DPK_PAS: u32 = 0x1b4c;
const REG_DPK_PWSF: u32 = 0x1b58;
const REG_DPD_CTL0_S1: u32 = 0x1b5c;
const REG_DPD_CTL1_S1: u32 = 0x1b60;
const REG_DPD_AGC: u32 = 0x1b67;
const REG_TABLE_SEL: u32 = 0x1b98;
const REG_TX_GAIN_SET: u32 = 0x1b9c;
const REG_DPD_CTL0: u32 = 0x1bb4;
const REG_SINGLE_TONE_SW: u32 = 0x1bb8;
const REG_R_CONFIG: u32 = 0x1bcc;
const REG_RXSRAM_CTL: u32 = 0x1bd4;
const REG_DPD_CTL11: u32 = 0x1be4;
const REG_DPD_CTL12: u32 = 0x1be8;
const REG_DPD_CTL15: u32 = 0x1bf4;
const REG_DPD_CTL16: u32 = 0x1bf8;
const REG_STAT_RPT: u32 = 0x1bfc;
const REG_IQK_CTRL: u32 = 0x1c38;
const REG_CH_DELAY_EXTR2: u32 = 0x1cd0;
const REG_CCA_OFF: u32 = 0x1d58;
const REG_ENFN: u32 = 0x1e24;
const REG_TXANTSEG: u32 = 0x1e28;
const REG_TXLGMAP: u32 = 0x1e2c;
const REG_TX_FIFO: u32 = 0x1e70;
const REG_RPT_CIP: u32 = 0x2d9c;
const REG_DPK_COEFFICIENTS: [u32; 2] = [0x1b0c, 0x1b64];
/// What separates one path's predistortion block from the other's.
const PATH_STRIDE: u32 = 0x58;

const BITS_PMC_BT_IQK_STS: u32 = 3 << 21;
const BITS_RFC_DIRECT: u32 = 3 << 30;
const BIT_3WIRE_EN: u32 = 3;
const BIT_ANTSEG: u32 = 15;
const BIT_ANT_PATH: u32 = 3;
const BIT_BAND: u32 = 7 << 16;
const BIT_BBMODE: u32 = 3 << 1;
const BIT_BB_GAIN: u32 = 0x1f << 14;
const BIT_BW_RXBB: u32 = 3 << 10;
const BIT_BW_TXBB: u32 = 7 << 12;
const BIT_BYPASS_DPD: u32 = 1 << 25;
const BIT_CCA_ON_BY_PW: u32 = 0x1ff << 3;
const BIT_CFIR_EN: u32 = 7 << 24;
const BIT_DATA_L: u32 = 0xfff;
const BIT_DBG_CCK_CCA: u32 = 1 << 1;
const BIT_DE_PWR_TRIM: u32 = 1 << 19;
const BIT_DE_TRXBW: u32 = 1 << 2;
const BIT_DE_TX_GAIN: u32 = 1 << 16;
const BIT_DIS_SHARERX_TXGAT: u32 = 1 << 27;
const BIT_DPD_CLK: u32 = 15 << 4;
const BIT_DPD_EN: u32 = 1 << 31;
const BIT_EN_IOQ_IQK_DPK: u32 = 1 << 30;
const BIT_GAIN_EXT: u32 = 1 << 12;
const BIT_GAIN_RST: u32 = 1 << 15;
const BIT_GAIN_TXBB: u32 = 0x1f;
const BIT_GAPK_RPT_IDX: u32 = 15 << 8;
const BIT_GLOSS_DB: u32 = 7 << 12;
const BIT_GS_PWSF: u32 = 0xfff_ffff;
const BIT_INNER_LB: u32 = 1 << 21;
const BIT_IQK_DPK_CLOCK_SRC: u32 = 1 << 28;
const BIT_IQK_DPK_EN: u32 = 1 << 17;
const BIT_IQK_DPK_RESET_SRC: u32 = 1 << 29;
const BIT_IQ_SWITCH: u32 = 0x3f;
const BIT_IRQ_TEST_MODE: u32 = 1 << 20;
const BIT_I_GAIN: u32 = 15 << 16;
const BIT_LB_ATT: u32 = 7 << 2;
const BIT_LB_SW: u32 = 3 << 12;
const BIT_PATH_EN: u32 = 1 << 31;
const BIT_PW_EXT_TIA: u32 = 1 << 1;
const BIT_Q_GAIN: u32 = 0xfff;
const BIT_Q_GAIN_SEL: u32 = 7 << 12;
const BIT_RFTXEN_GCK_FORCE_ON: u32 = 1 << 31;
const BIT_RF_GAIN: u32 = 7 << 2;
const BIT_RF_MODE: u32 = 15 << 16;
const BIT_RPT_CIP_STATUS: u32 = 0xff;
const BIT_RPT_DGAIN: u32 = 0xfff << 16;
const BIT_RPT_EN: u32 = 1 << 21;
const BIT_RPT_SEL: u32 = 0x1f << 16;
const BIT_RXAGC: u32 = 0x1f << 5;
const BIT_RXA_MIX_GAIN: u32 = 3 << 3;
const BIT_RXG_GAIN: u32 = 1 << 18;
const BIT_SEL_PATH: u32 = 3 << 1;
const BIT_STOP_TX: u32 = 15;
const BIT_SUBPAGE: u32 = 15;
const BIT_TIA_BYPASS: u32 = 1 << 5;
const BIT_TST_IQK2SET_SRC: u32 = 1 << 31;
const BIT_TXAGC: u32 = 0x1f;
const BIT_TXA_LB_ATT: u32 = 3 << 14;
const BIT_TXA_TANK: u32 = 1 << 4;
const BIT_TXBB: u32 = 1 << 10;
const BIT_TX_CCK_IND: u32 = 1 << 16;
const BIT_TX_CFIR: u32 = 3 << 30;
const BIT_TX_MODE: u32 = 0xfff << 8;
const BIT_TX_SCALE_0DB: u32 = 1 << 7;
const BIT_WL_RFK: u32 = 1;

const RF_MODE_TRXAGC: u8 = 0x00;
const RF_CFGCH: u8 = 0x18;
const RF_RXAGC_OFFSET: u8 = 0x19;
const RF_BW_TRXBB: u8 = 0x1a;
const RF_LUTWA: u8 = 0x33;
const RF_LUTWD0: u8 = 0x3f;
const RF_T_METER: u8 = 0x42;
const RF_TX_GAIN_OFFSET: u8 = 0x55;
const RF_TX_GAIN: u8 = 0x56;
const RF_IDAC: u8 = 0x58;
const RF_TX_RESULT: u8 = 0x5f;
const RF_TXA_LB_SW: u8 = 0x63;
const RF_RXG_GAIN: u8 = 0x87;
const RF_RXA_MIX_GAIN: u8 = 0x8a;
const RF_EXT_TIA_BW: u8 = 0x8f;
const RF_RX_DC: u8 = 0x92;
const RF_DIS_BYPASS_TXBB: u8 = 0x9e;
const RF_DEBUG: u8 = 0xde;
const RF_LUTDBG: u8 = 0xdf;
const RF_LUTWE2: u8 = 0xee;

/// `RF_BAND_2G_CCK` through `RF_BAND_5G_H`, and `RF_GAIN_NUM` in each.
const BANDS: usize = 5;
const GAINS: usize = 11;
/// `RF_HW_OFFSET_NUM`.
const OFFSETS: usize = 10;
/// `BIT_2G_SWING` and `BIT_5G_SWING`.
const SWING_2GHZ: u32 = 0x2d;
const SWING_5GHZ: u32 = 0x36;
/// `check_rf_status`'s RF mode of a frame going out.
const RF_MODE_TX: u32 = 2;
/// `rtw8822c_txgapk_afe_dpk` and `rtw8822c_dpk_afe_is_dpk`'s analog steps.
const AFE_CALIBRATING: [u32; 18] = [
    0x700f0001, 0x700f0001, 0x701f0001, 0x702f0001, 0x703f0001, 0x704f0001, 0x705f0001, 0x706f0001,
    0x707f0001, 0x708f0001, 0x709f0001, 0x70af0001, 0x70bf0001, 0x70cf0001, 0x70df0001, 0x70ef0001,
    0x70ff0001, 0x70ff0001,
];
/// `rtw8822c_txgapk_afe_dpk_restore`, of which the predistortion table sets each
/// path's first seven before either's rest.
const AFE_RUNNING: [u32; 16] = [
    0x700b8041, 0x70144041, 0x70244041, 0x70344041, 0x70444041, 0x705b8041, 0x70644041, 0x707b8041,
    0x708b8041, 0x709b8041, 0x70ab8041, 0x70bb8041, 0x70cb8041, 0x70db8041, 0x70eb8041, 0x70fb8041,
];
const AFE_RUNNING_FIRST: usize = 7;
const IQK_AFE_CALIBRATING: u32 = u32::MAX;
const IQK_AFE_RUNNING: u32 = 0xffa1005e;
const REG_AFE_DPK: [u32; 2] = [0x18a4, 0x41a4];
const AFE_DPK: u32 = 1 << 7;
/// `rtw8822c_dpk_mac_bb`.
const DPK_MAC_BB: [(u32, u32, u32); 14] = [
    (0x1e24, 1 << 17, 1),
    (0x1d58, 0x1ff << 3, 0x1ff),
    (0x1864, 1 << 31, 1),
    (0x4164, 1 << 31, 1),
    (0x180c, 1 << 27, 1),
    (0x410c, 1 << 27, 1),
    (0x186c, 1 << 7, 1),
    (0x416c, 1 << 7, 1),
    (0x180c, 3, 0),
    (0x410c, 3, 0),
    (0x1a14, 3 << 8, 3),
    (0x80c, 15, 8),
    (0x824, 15 << 16, 3),
    (0x824, 15 << 24, 3),
];
/// `rtw8822c_do_dpk`'s saved state.
const DPK_REGISTERS: [u32; 18] = [
    0x520, 0x820, 0x824, 0x1c3c, 0x1d58, 0x1864, 0x4164, 0x180c, 0x410c, 0x186c, 0x416c, 0x1a14,
    0x1e70, 0x80c, 0x1d70, 0x1e7c, 0x18a4, 0x41a4,
];
const DPK_RF_REGISTERS: [u8; 7] = [0x00, 0x1a, 0x55, 0x63, 0x87, 0x8f, 0xde];
/// `rtw8822c_dpk_get_coef_tbl`.
const COEFFICIENT_READS: [u32; 20] = [
    0x000400f0, 0x040400f0, 0x080400f0, 0x010400f0, 0x050400f0, 0x090400f0, 0x020400f0, 0x060400f0,
    0x0a0400f0, 0x030400f0, 0x070400f0, 0x0b0400f0, 0x0c0400f0, 0x100400f0, 0x0d0400f0, 0x110400f0,
    0x0e0400f0, 0x120400f0, 0x0f0400f0, 0x130400f0,
];
/// `DPK_CHANNEL_WIDTH_80` of `RF_CFGCH`'s width.
const WIDTH_80: u32 = 1;
/// `rtw8822c_txgapk_read_offset`'s wait for its report: 100 looks 1 ms apart.
#[cfg(test)]
const GAPK_POLLS: usize = 100;
#[cfg(test)]
const GAPK_POLL_US: u64 = 1000;
/// The path's `REG_RSV_CTRL` or `REG_WLRF1`, whose RFC direct bits the gain
/// measurement takes.
const GAPK_DIRECT: [u32; 2] = [REG_RSV_CTRL, REG_WLRF1];
/// `check_hw_ready`.
const READY_POLLS: usize = 1000;
const READY_POLL_US: u64 = 10;
/// `msleep(10)`.
const ONE_SHOT_US: u64 = 10_000;
/// The DPK_THERMAL weight, `DECLARE_EWMA(thermal, 10, 4)`.
const THERMAL_PRECISION: u32 = 10;
const THERMAL_WEIGHT: u32 = 2;
const THERMAL_MASK: u32 = 0x7e;

/// Why a calibration stopped short of the hardware.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Rf(rf::Error),
    Coex(coex::Error),
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<rf::Error> for Error {
    fn from(error: rf::Error) -> Self {
        Self::Rf(error)
    }
}
impl From<coex::Error> for Error {
    fn from(error: coex::Error) -> Self {
        Self::Coex(error)
    }
}

/// `rtw8822c_dpk_one_shot`'s actions.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Shot {
    Power,
    GainLoss,
    Predistort,
    Enable,
    Gain,
}

/// `rtw8822c_dpk_pas_agc`'s states of a search by loss alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Agc {
    Read,
    Measure,
    TooLoud,
    TooQuiet,
    Done,
}

/// The radio's registers, through both of their doors.
struct Bench<'a, I: Io> {
    io: &'a mut I,
    report: &'a Report,
}

impl<I: Io> Bench<'_, I> {
    /// `rtw_write32_mask`.
    fn set(&mut self, register: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.io.read32(register)?;
        let value = (old & !mask) | ((value << mask.trailing_zeros()) & mask);
        Ok(self.io.write32(register, value)?)
    }

    /// `rtw_read32_mask`.
    fn get(&mut self, register: u32, mask: u32) -> Result<u32, Error> {
        Ok((self.io.read32(register)? & mask) >> mask.trailing_zeros())
    }

    fn write(&mut self, register: u32, value: u32) -> Result<(), Error> {
        Ok(self.io.write32(register, value)?)
    }

    fn rf(&mut self) -> Result<rf::Registers<'_, I>, Error> {
        // SAFETY: as `Calibration::run`'s callers promise.
        Ok(unsafe { rf::Registers::new(self.io, self.report) }?)
    }

    fn rf_set(&mut self, path: Path, address: u8, mask: u32, value: u32) -> Result<(), Error> {
        Ok(self.rf()?.write(path, address, mask, value)?)
    }

    fn rf_get(&mut self, path: Path, address: u8, mask: u32) -> Result<u32, Error> {
        Ok(self.rf()?.read(path, address, mask)?)
    }

    /// `check_hw_ready`.
    fn ready(&mut self, register: u32, mask: u32, target: u32) -> Result<bool, Error> {
        for _ in 0..READY_POLLS {
            if self.get(register, mask)? == target {
                return Ok(true);
            }
            self.io.delay_us(READY_POLL_US);
        }
        Ok(false)
    }

    /// Select `path`'s page of the calibration block.
    fn page(&mut self, path: usize) -> Result<(), Error> {
        self.set(REG_NCTL0, BIT_SUBPAGE, 0x8 | ((path as u32) << 1))
    }

    fn common_page(&mut self) -> Result<(), Error> {
        self.set(REG_NCTL0, BIT_SUBPAGE, 0xc)
    }

    /// `check_rf_status`.
    fn transmitting(&mut self) -> Result<bool, Error> {
        let a = self.rf_get(Path::A, RF_MODE_TRXAGC, BIT_RF_MODE)?;
        let b = self.rf_get(Path::B, RF_MODE_TRXAGC, BIT_RF_MODE)?;
        Ok(a == RF_MODE_TX || b == RF_MODE_TX)
    }

    /// `rtw8822c_dpk_tx_pause` and `rtw8822c_txgapk_tx_pause`.
    fn pause_transmit(&mut self) -> Result<bool, Error> {
        self.io.write8(REG_TXPAUSE, MASK_BYTE0 as u8)?;
        self.set(REG_TX_FIFO, BIT_STOP_TX, 2)?;
        for _ in 0..2500 {
            if !self.transmitting()? {
                return Ok(true);
            }
            self.io.delay_us(2);
        }
        Ok(false)
    }

    fn thermal(&mut self, path: Path) -> Result<u8, Error> {
        for bit in [1, 0, 1] {
            self.rf_set(path, RF_T_METER, 1 << 19, bit)?;
        }
        self.io.delay_us(15);
        Ok(self.rf_get(path, RF_T_METER, THERMAL_MASK)? as u8)
    }
}

fn paths() -> [(usize, Path); 2] {
    [(0, Path::A), (1, Path::B)]
}

/// `_rtw8822c_txgapk_gain_valid`: the top of the table, which calibration keeps.
fn gain_holds(gain: u32) -> bool {
    (gain >> 8) & 15 >= 0xc && (gain >> 4) & 15 >= 0xe
}

/// `rtw8822c_txgapk_cal_gain`.
fn adjusted_gain(gain: u32, offset: i8) -> u32 {
    if gain_holds(gain) {
        return gain;
    }
    let doubled = (gain << 1).wrapping_add_signed(offset.into());
    (doubled >> 1) | if doubled & 1 != 0 { BIT_GAIN_EXT } else { 0 }
}

/// `txgapk->offset` of a report's four bits.
fn gain_offset(report: u32, at: u32) -> i8 {
    let bits = ((report >> (at * 4)) & 15) as u8;
    (if bits & 8 != 0 { bits | 0xf0 } else { bits }) as i8
}

/// `rtw8822c_txgapk_write_tx_gain`'s row and first table entry for `channel`.
fn gain_band(channel: u32) -> Option<(usize, u32)> {
    match channel {
        1..=14 => Some((1, 0x20)),
        36..=64 => Some((2, 0x200)),
        100..=144 => Some((3, 0x280)),
        149..=177 => Some((4, 0x300)),
        _ => None,
    }
}

/// `rtw8822c_psd_log2base`.
fn log2_hundredths(value: u32) -> u32 {
    const FRACTIONS: [u32; 21] = [
        0, 432, 332, 274, 232, 200, 174, 151, 132, 115, 100, 86, 74, 62, 51, 42, 32, 23, 15, 7, 0,
    ];
    if value == 0 {
        return 0;
    }
    let bits = 32 - value.leading_zeros();
    let share = (u64::from(value) * 100) >> bits;
    let at = (share / 5) as usize;
    bits * 100 - FRACTIONS[at.min(FRACTIONS.len() - 1)]
}

/// `rtw8822c_dpk_coef_transfer` of one report.
fn coefficient(report: u32) -> u32 {
    let (i, q) = ((report >> 16) & 0x1fff, report & 0x1fff);
    (i << 16) | u32::from(((0x2000 - q) as u16 & 0x1fff).wrapping_sub(1))
}

/// `rtw8822c_dpk_coef_iq_check`: a coefficient that hit its rail.
fn railed(coefficient: u32) -> bool {
    let (i, q) = ((coefficient >> 16) & 0x1fff, coefficient & 0x1fff);
    [i, q].iter().any(|value| matches!(value, 0x1000 | 0x0fff))
}

/// `rtw_gapk_info`.
#[derive(Debug)]
struct Gapk {
    /// `read_txgain`.
    read: bool,
    /// `rf3f_bp` by band, gain and path.
    table: [[[u32; 2]; GAINS]; BANDS],
    offsets: [[i8; 2]; GAINS],
    channel: u32,
}

/// What a GAPK keeps between its steps: the transmit registers its pause
/// changed, and those the measurement of the path under way holds.
#[derive(Debug)]
pub struct GapkRun {
    held: [(u32, u32); 2],
    measuring: [Result<u32, io::Error>; 5],
}

/// One path of a DPK between its steps: where its gain search started, the
/// temperature before it, and the search itself.
#[derive(Clone, Copy, Debug)]
struct DpkPath {
    start_gain: u32,
    start_agc: u32,
    before: u8,
    tries: u32,
    gain: u32,
    state: Agc,
}

impl Default for DpkPath {
    fn default() -> Self {
        Self {
            start_gain: 0,
            start_agc: 0,
            before: 0,
            tries: 0,
            gain: 0,
            state: Agc::Read,
        }
    }
}

/// What a DPK keeps between its steps: the registers it puts back at the
/// end, and each path's search.
#[derive(Debug)]
pub struct DpkRun {
    held: [u32; DPK_REGISTERS.len()],
    held_rf: [[u32; 2]; DPK_RF_REGISTERS.len()],
    paths: [DpkPath; 2],
}

/// `sizeof(struct rtw_lps_pg_dpk_hdr)`.
const POWER_GATE_PAGE: usize = 169;

/// `rtw_dpk_info`.
#[derive(Debug)]
struct Dpk {
    ok: [bool; 2],
    channel: u32,
    two_ghz: bool,
    wide: bool,
    txagc: [u8; 2],
    gs: [u32; 2],
    offsets: [u8; 2],
    thermal: [u8; 2],
    thermal_delta: [u8; 2],
    internal: [u64; 2],
    coefficients: [[u32; 20]; 2],
}

/// What calibration keeps from one channel to the next.
#[derive(Debug)]
pub struct Calibration {
    gapk: Gapk,
    dpk: Dpk,
    /// `efuse->power_track_type` of the thermal-only kinds, not TSSI.
    thermal_power: bool,
    /// `dm->is_bt_iqk_timeout`.
    bluetooth_stuck: bool,
    /// What went short this run.
    shortfalls: Vec<&'static str>,
}

impl Calibration {
    /// `rtw_lps_pg_dpk_get`: `struct rtw_lps_pg_dpk_hdr`, the predistortion a
    /// power gate has firmware restore.
    pub fn power_gate_page(&self) -> [u8; POWER_GATE_PAGE] {
        let dpk = &self.dpk;
        let mut page = [0; POWER_GATE_PAGE];
        page[0] = u8::from(dpk.ok[0]) | (u8::from(dpk.ok[1]) << 1);
        page[2..4].copy_from_slice(&dpk.txagc);
        for (slot, gs) in page[4..8].as_chunks_mut().0.iter_mut().zip(dpk.gs) {
            *slot = (gs as u16).to_le_bytes();
        }
        let coefficients = dpk.coefficients.iter().flatten();
        for (slot, word) in page[8..168].as_chunks_mut().0.iter_mut().zip(coefficients) {
            *slot = word.to_le_bytes();
        }
        page[168] = dpk.channel as u8;
        page
    }

    pub fn new(power_track: u8) -> Self {
        Self {
            gapk: Gapk {
                read: false,
                table: [[[0; 2]; GAINS]; BANDS],
                offsets: [[0; 2]; GAINS],
                channel: 0,
            },
            dpk: Dpk {
                ok: [false; 2],
                channel: 0,
                two_ghz: true,
                wide: false,
                txagc: [0; 2],
                gs: [0x5b; 2],
                offsets: [0; 2],
                thermal: [0; 2],
                thermal_delta: [0; 2],
                internal: [0; 2],
                coefficients: [[0; 20]; 2],
            },
            thermal_power: !(4..=7).contains(&power_track),
            bluetooth_stuck: false,
            shortfalls: Vec::new(),
        }
    }

    /// What this run could not finish, each named once a run.
    pub fn take_shortfalls(&mut self) -> Vec<&'static str> {
        core::mem::take(&mut self.shortfalls)
    }

    fn fall_short(&mut self, what: &'static str) {
        if !self.shortfalls.contains(&what) {
            self.shortfalls.push(what);
        }
    }

    /// One look at what the half of `rtw8822c_rfk_handshake` before firmware
    /// hears of a start waits for: Bluetooth's own calibration over, or one
    /// that outlasted an earlier wait, which rtw88 no longer waits for.
    pub fn bluetooth_idle<I: Io>(&self, io: &mut I) -> Result<bool, Error> {
        Ok(self.bluetooth_stuck || io.read32(REG_PMC_DBG_CTRL1)? & BITS_PMC_BT_IQK_STS == 0)
    }

    /// Bluetooth's calibration outlasted its 600 ms: `dm->is_bt_iqk_timeout`.
    pub fn bluetooth_outlasted(&mut self) {
        self.bluetooth_stuck = true;
        self.fall_short("Bluetooth's calibration, which outlasted the wait");
    }

    /// One look at what the half of `rtw8822c_rfk_handshake` after firmware
    /// hears waits for: its answer.
    pub fn firmware_answered<I: Io>(io: &mut I) -> Result<bool, Error> {
        Ok(io.read32(REG_ARFR4)? & BIT_WL_RFK == 1)
    }

    /// Firmware did not answer within 100 ms; rtw88 goes on.
    pub fn firmware_unanswered(&mut self) {
        self.fall_short("firmware's calibration handshake");
    }

    /// `rtw8822c_txgapk` in one call, its measurements waited for in place.
    ///
    /// # Safety
    /// As [`rf::Registers::new`]: `io` and `report` are one radio's, whose
    /// frames wait while this worker owns it.
    #[cfg(test)]
    pub unsafe fn even_gains<I: Io>(&mut self, io: &mut I, report: &Report) -> Result<(), Error> {
        // SAFETY: forwarded from the caller.
        let Some(mut run) = (unsafe { self.gapk_begin(io, report) })? else {
            return Ok(());
        };
        for at in 0..2 {
            // SAFETY: as above.
            unsafe { self.gapk_start(io, report, &mut run, at) }?;
            let mut done = false;
            for _ in 0..GAPK_POLLS {
                done = Self::gapk_measured(io)?;
                if done {
                    break;
                }
                io.delay_us(GAPK_POLL_US);
            }
            // SAFETY: as above.
            unsafe { self.gapk_finish(io, report, &mut run, at, done) }?;
        }
        // SAFETY: as above.
        unsafe { self.gapk_end(io, report, run, true) }
    }

    /// The start of `rtw8822c_txgapk`, up to its first path: `None` where
    /// thermal power tracking does not apply and nothing more follows.
    ///
    /// # Safety
    /// As [`rf::Registers::new`]: `io` and `report` are one radio's, whose
    /// frames wait while this worker owns it, from here to [`Self::gapk_end`].
    pub unsafe fn gapk_begin<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
    ) -> Result<Option<GapkRun>, Error> {
        let mut bench = Bench { io, report };
        self.save_gains(&mut bench)?;
        if !self.thermal_power {
            return Ok(None);
        }
        let held = [
            (REG_TX_PTCL_CTRL, bench.io.read32(REG_TX_PTCL_CTRL)?),
            (REG_TX_FIFO, bench.io.read32(REG_TX_FIFO)?),
        ];
        if !bench.pause_transmit()? {
            self.fall_short("a transmit pause for calibration");
        }
        Ok(Some(GapkRun {
            held,
            measuring: [Ok(0); 5],
        }))
    }

    /// Path `at`'s setup and the start of its gain measurement, which
    /// [`Self::gapk_measured`] looks for, up to 100 ms.
    ///
    /// # Safety
    /// As [`Self::gapk_begin`].
    pub unsafe fn gapk_start<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        run: &mut GapkRun,
        at: usize,
    ) -> Result<(), Error> {
        let path = paths()[at].1;
        let mut bench = Bench { io, report };
        self.gapk.channel = bench.rf_get(path, RF_CFGCH, RF_WHOLE)? & MASK_BYTE0;
        Self::gain_setup(&mut bench, at)?;
        Self::gain_analog(&mut bench, at, IQK_AFE_CALIBRATING, &AFE_CALIBRATING)?;
        run.measuring = self.measure_start(&mut bench, at, path)?;
        Ok(())
    }

    /// Whether the gain measurement finished.
    pub fn gapk_measured<I: Io>(io: &mut I) -> Result<bool, Error> {
        let value = io.read32(REG_RPT_CIP)?;
        Ok((value & BIT_RPT_CIP_STATUS) >> BIT_RPT_CIP_STATUS.trailing_zeros() == 0x55)
    }

    /// The rest of path `at`, its measurement `done` or given up on.
    ///
    /// # Safety
    /// As [`Self::gapk_begin`].
    pub unsafe fn gapk_finish<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        run: &mut GapkRun,
        at: usize,
        done: bool,
    ) -> Result<(), Error> {
        let path = paths()[at].1;
        let mut bench = Bench { io, report };
        self.measure_finish(&mut bench, at, run.measuring, done)?;
        bench.rf_set(path, RF_MODE_TRXAGC, BIT_RF_MODE, 3)?;
        bench.rf_set(path, RF_DEBUG, BIT_DE_TRXBW, 0)?;
        bench.rf_set(path, RF_EXT_TIA_BW, BIT_PW_EXT_TIA, 0)?;
        Self::gain_analog(&mut bench, at, IQK_AFE_RUNNING, &AFE_RUNNING)?;
        Self::gain_teardown(&mut bench, at, path)
    }

    /// The end of `rtw8822c_txgapk`: the gains written where both paths
    /// were `measured`, and the transmit pause lifted.
    ///
    /// # Safety
    /// As [`Self::gapk_begin`].
    pub unsafe fn gapk_end<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        run: GapkRun,
        measured: bool,
    ) -> Result<(), Error> {
        let mut bench = Bench { io, report };
        if measured {
            self.write_gains(&mut bench)?;
        }
        for (register, value) in run.held {
            bench.write(register, value)?;
        }
        Ok(())
    }

    /// `rtw8822c_txgapk_save_all_tx_gain_table`.
    fn save_gains<I: Io>(&mut self, bench: &mut Bench<'_, I>) -> Result<(), Error> {
        const CHANNELS: [u32; BANDS] = [1, 1, 36, 100, 149];
        const BAND_BITS: [u32; BANDS] = [0, 0, 1, 3, 5];
        const CCK: [u32; BANDS] = [1, 0, 0, 0, 0];
        if !self.gapk.read {
            for band in 0..BANDS {
                for (at, path) in paths() {
                    let tuned = bench.rf_get(path, RF_CFGCH, RF_WHOLE)?;
                    bench.set(REG_3WIRE[at], BIT_3WIRE_EN, 0)?;
                    bench.rf_set(path, RF_CFGCH, MASK_BYTE0, CHANNELS[band])?;
                    bench.rf_set(path, RF_CFGCH, BIT_BAND, BAND_BITS[band])?;
                    bench.rf_set(path, RF_BW_TRXBB, BIT_DBG_CCK_CCA, CCK[band])?;
                    bench.rf_set(path, RF_BW_TRXBB, BIT_TX_CCK_IND, CCK[band])?;
                    for gain in 0..GAINS {
                        bench.rf_set(path, RF_MODE_TRXAGC, MASK_BYTE0, 1 + 3 * gain as u32)?;
                        self.gapk.table[band][gain][at] =
                            bench.rf_get(path, RF_TX_RESULT, RF_WHOLE)? & BIT_DATA_L;
                    }
                    bench.rf_set(path, RF_CFGCH, RF_WHOLE, tuned)?;
                    bench.set(REG_3WIRE[at], BIT_3WIRE_EN, 3)?;
                }
            }
        }
        for band in 0..BANDS {
            for (at, _) in paths() {
                self.gain_table(bench, band, at)?;
            }
        }
        self.gapk.read = true;
        Ok(())
    }

    /// `_rtw8822c_txgapk_write_gain_bb_table`.
    fn gain_table<I: Io>(
        &self,
        bench: &mut Bench<'_, I>,
        band: usize,
        at: usize,
    ) -> Result<(), Error> {
        bench.set(REG_NCTL0, BIT_SEL_PATH, at as u32)?;
        if let Some(select) = [None, Some(0), Some(2), Some(3), Some(4)][band] {
            bench.set(REG_TABLE_SEL, BIT_Q_GAIN_SEL, select)?;
        }
        bench.set(REG_TX_GAIN_SET, MASK_BYTE0, 0x88)?;
        let (mut held, mut value) = (false, 0);
        for gain in 0..GAINS {
            let entry = self.gapk.table[band][gain][at];
            if !(held && gain_holds(entry)) {
                value = entry;
            }
            held |= gain_holds(entry);
            bench.set(REG_TABLE_SEL, BIT_Q_GAIN, value)?;
            bench.set(REG_TABLE_SEL, BIT_I_GAIN, gain as u32)?;
            bench.set(REG_TABLE_SEL, BIT_GAIN_RST, 1)?;
            bench.set(REG_TABLE_SEL, BIT_GAIN_RST, 0)?;
        }
        Ok(())
    }

    /// `rtw8822c_txgapk_bb_dpk`.
    fn gain_setup<I: Io>(bench: &mut Bench<'_, I>, at: usize) -> Result<(), Error> {
        bench.set(REG_ENFN, BIT_IQK_DPK_EN, 1)?;
        bench.set(REG_CH_DELAY_EXTR2, BIT_IQK_DPK_CLOCK_SRC, 1)?;
        bench.set(REG_CH_DELAY_EXTR2, BIT_IQK_DPK_RESET_SRC, 1)?;
        bench.set(REG_CH_DELAY_EXTR2, BIT_EN_IOQ_IQK_DPK, 1)?;
        bench.set(REG_CH_DELAY_EXTR2, BIT_TST_IQK2SET_SRC, 0)?;
        bench.set(REG_CCA_OFF, BIT_CCA_ON_BY_PW, 0x1ff)?;
        bench.set(REG_RFTXEN_GCK[at], BIT_RFTXEN_GCK_FORCE_ON, 1)?;
        bench.set(REG_3WIRE[at], BIT_DIS_SHARERX_TXGAT, 1)?;
        bench.set(REG_DIS_SHARE_RX[at], BIT_TX_SCALE_0DB, 1)?;
        bench.set(REG_3WIRE[at], BIT_3WIRE_EN, 0)?;
        bench.set(REG_CCKSB, BIT_BBMODE, 2)
    }

    /// `rtw8822c_txgapk_afe_dpk` or its restore.
    fn gain_analog<I: Io>(
        bench: &mut Bench<'_, I>,
        at: usize,
        control: u32,
        steps: &[u32],
    ) -> Result<(), Error> {
        bench.write(REG_IQK_CTRL, control)?;
        for &step in steps {
            bench.write(REG_ANAPAR[at], step)?;
        }
        Ok(())
    }

    /// `rtw8822c_txgapk_calculate_offset` up to its wait: the registers it
    /// holds.
    fn measure_start<I: Io>(
        &mut self,
        bench: &mut Bench<'_, I>,
        at: usize,
        path: Path,
    ) -> Result<[Result<u32, io::Error>; 5], Error> {
        let registers = [
            REG_ANTMAP0,
            REG_TXLGMAP,
            REG_TXANTSEG,
            REG_ORITXCODE[0],
            REG_ORITXCODE[1],
        ];
        let held = registers.map(|register| bench.io.read32(register));
        let channel = self.gapk.channel;
        bench.set(REG_SINGLE_TONE_SW, BIT_IRQ_TEST_MODE, 0)?;
        bench.set(REG_NCTL0, BIT_SEL_PATH, at as u32)?;
        bench.set(REG_R_CONFIG, BIT_IQ_SWITCH, 0x3f)?;
        bench.set(REG_IQK_CTL1, BIT_TX_CFIR, 0)?;
        bench.rf_set(path, RF_DEBUG, BIT_DE_TX_GAIN, 1)?;
        if (1..=14).contains(&channel) {
            bench.rf_set(path, RF_MODE_TRXAGC, RF_WHOLE, 0x5000f)?;
            bench.rf_set(path, RF_TX_GAIN_OFFSET, BIT_RF_GAIN, 0)?;
            bench.rf_set(path, RF_RXG_GAIN, BIT_RXG_GAIN, 1)?;
            bench.rf_set(path, RF_MODE_TRXAGC, BIT_RXAGC, 0x0f)?;
            bench.rf_set(path, RF_DEBUG, BIT_DE_TRXBW, 1)?;
            bench.rf_set(path, RF_BW_TRXBB, BIT_BW_TXBB, 1)?;
            bench.rf_set(path, RF_BW_TRXBB, BIT_BW_RXBB, 0)?;
            bench.rf_set(path, RF_EXT_TIA_BW, BIT_PW_EXT_TIA, 1)?;
            bench.set(REG_IQKSTAT, MASK_BYTE0, 0)?;
            bench.set(REG_TABLE_SEL, BIT_Q_GAIN_SEL, 0)?;
        } else {
            bench.rf_set(path, RF_MODE_TRXAGC, RF_WHOLE, 0x50011)?;
            bench.rf_set(path, RF_TXA_LB_SW, BIT_TXA_LB_ATT, 3)?;
            bench.rf_set(path, RF_TXA_LB_SW, BIT_LB_ATT, 3)?;
            bench.rf_set(path, RF_TXA_LB_SW, BIT_LB_SW, 1)?;
            bench.rf_set(path, RF_RXA_MIX_GAIN, BIT_RXA_MIX_GAIN, 2)?;
            bench.rf_set(path, RF_MODE_TRXAGC, BIT_RXAGC, 0x12)?;
            bench.rf_set(path, RF_DEBUG, BIT_DE_TRXBW, 1)?;
            bench.rf_set(path, RF_BW_TRXBB, BIT_BW_RXBB, 0)?;
            bench.rf_set(path, RF_EXT_TIA_BW, BIT_PW_EXT_TIA, 1)?;
            bench.rf_set(path, RF_MODE_TRXAGC, BIT_RF_MODE, 5)?;
            bench.set(REG_IQKSTAT, MASK_BYTE0, 0)?;
            if let Some(select) = match channel {
                36..=64 => Some(2),
                100..=144 => Some(3),
                149..=177 => Some(4),
                _ => None,
            } {
                bench.set(REG_TABLE_SEL, BIT_Q_GAIN_SEL, select)?;
            }
        }
        self.start_offsets(bench, at, path)?;
        Ok(held)
    }

    /// The rest of `rtw8822c_txgapk_calculate_offset`, and `held` restored.
    fn measure_finish<I: Io>(
        &mut self,
        bench: &mut Bench<'_, I>,
        at: usize,
        held: [Result<u32, io::Error>; 5],
        done: bool,
    ) -> Result<(), Error> {
        let registers = [
            REG_ANTMAP0,
            REG_TXLGMAP,
            REG_TXANTSEG,
            REG_ORITXCODE[0],
            REG_ORITXCODE[1],
        ];
        self.finish_offsets(bench, at, done)?;
        for (register, value) in registers.into_iter().zip(held) {
            bench.write(register, value?)?;
        }
        Ok(())
    }

    /// `rtw8822c_txgapk_read_offset` up to its wait for the report.
    fn start_offsets<I: Io>(
        &mut self,
        bench: &mut Bench<'_, I>,
        at: usize,
        path: Path,
    ) -> Result<(), Error> {
        const FIRST: [u32; 2] = [0xd18, 0xd2a];
        const SECOND: [u32; 2] = [0xd19, 0xd2b];
        bench.set(REG_ANTMAP0, BIT_ANT_PATH, at as u32 + 1)?;
        bench.write(REG_TXLGMAP, 0xe4e40000)?;
        bench.set(REG_TXANTSEG, BIT_ANTSEG, 3)?;
        bench.set(REG_ORITXCODE[at], RF_WHOLE, 0x33312)?;
        bench.set(REG_ORITXCODE[at], BIT_PATH_EN, 1)?;
        bench.set(GAPK_DIRECT[at], BITS_RFC_DIRECT, 0)?;
        bench.rf_set(path, RF_LUTDBG, BIT_TXA_TANK, 1)?;
        bench.rf_set(path, RF_IDAC, BIT_TX_MODE, 0x820)?;
        bench.set(REG_NCTL0, BIT_SEL_PATH, at as u32)?;
        bench.set(REG_IQKSTAT, MASK_BYTE0, 0)?;
        bench.set(REG_TX_TONE_IDX, MASK_BYTE0, 0x18)?;
        bench.io.delay_us(1000);
        let swing = if (1..=14).contains(&self.gapk.channel) {
            SWING_2GHZ
        } else {
            SWING_5GHZ
        };
        bench.set(REG_R_CONFIG, MASK_BYTE0, swing)?;
        bench.io.delay_us(1000);
        bench.write(REG_NCTL0, FIRST[at])?;
        bench.write(REG_NCTL0, SECOND[at])
    }

    /// The rest of `rtw8822c_txgapk_read_offset`, its report `done` or not.
    fn finish_offsets<I: Io>(
        &mut self,
        bench: &mut Bench<'_, I>,
        at: usize,
        done: bool,
    ) -> Result<(), Error> {
        if !done {
            self.fall_short("the gain measurement");
        }
        bench.set(GAPK_DIRECT[at], BITS_RFC_DIRECT, 2)?;
        bench.set(REG_NCTL0, BIT_SEL_PATH, at as u32)?;
        bench.set(REG_RXSRAM_CTL, BIT_RPT_EN, 1)?;
        bench.set(REG_RXSRAM_CTL, BIT_RPT_SEL, 0x12)?;
        bench.set(REG_TX_GAIN_SET, BIT_GAPK_RPT_IDX, 3)?;
        let first = bench.io.read32(REG_STAT_RPT)?;
        bench.set(REG_TX_GAIN_SET, BIT_GAPK_RPT_IDX, 4)?;
        let second = bench.io.read32(REG_STAT_RPT)?;
        for offset in 0..OFFSETS {
            let (report, at_report) = if offset < 8 {
                (first, offset as u32)
            } else {
                (second, offset as u32 - 8)
            };
            self.gapk.offsets[offset][at] = gain_offset(report, at_report);
        }
        Ok(())
    }

    /// `rtw8822c_txgapk_bb_dpk_restore`.
    fn gain_teardown<I: Io>(bench: &mut Bench<'_, I>, at: usize, path: Path) -> Result<(), Error> {
        bench.rf_set(path, RF_DEBUG, BIT_DE_TX_GAIN, 0)?;
        bench.rf_set(path, RF_DIS_BYPASS_TXBB, BIT_TIA_BYPASS, 0)?;
        bench.rf_set(path, RF_DIS_BYPASS_TXBB, BIT_TXBB, 0)?;
        for select in [0, 1] {
            bench.set(REG_NCTL0, BIT_SEL_PATH, select)?;
            bench.set(REG_IQK_CTL1, BIT_TX_CFIR, 0)?;
            bench.set(REG_SINGLE_TONE_SW, BIT_IRQ_TEST_MODE, 0)?;
            bench.set(REG_R_CONFIG, MASK_BYTE0, 0)?;
        }
        bench.set(REG_NCTL0, BIT_SEL_PATH, 0)?;
        bench.set(REG_CCA_OFF, BIT_CCA_ON_BY_PW, 0)?;
        bench.set(REG_RFTXEN_GCK[at], BIT_RFTXEN_GCK_FORCE_ON, 0)?;
        bench.set(REG_3WIRE[at], BIT_DIS_SHARERX_TXGAT, 0)?;
        bench.set(REG_DIS_SHARE_RX[at], BIT_TX_SCALE_0DB, 0)?;
        bench.set(REG_3WIRE[at], BIT_3WIRE_EN, 3)?;
        bench.set(REG_CCKSB, BIT_BBMODE, 0)?;
        bench.set(REG_IQK_CTL1, BIT_CFIR_EN, 5)
    }

    /// `rtw8822c_txgapk_write_tx_gain`.
    fn write_gains<I: Io>(&self, bench: &mut Bench<'_, I>) -> Result<(), Error> {
        let Some((band, first)) = gain_band(self.gapk.channel) else {
            return Ok(());
        };
        for (at, path) in paths() {
            let table = &self.gapk.table[band];
            let mut sums = [0i8; GAINS];
            for (gain, sum) in sums.iter_mut().enumerate() {
                for (entry, offset) in table[gain..].iter().zip(&self.gapk.offsets[gain..]) {
                    if !gain_holds(entry[at]) {
                        *sum = sum.wrapping_add(offset[at]);
                    }
                }
            }
            bench.rf_set(path, RF_LUTWE2, RF_WHOLE, 0x10000)?;
            for gain in 0..GAINS {
                bench.rf_set(path, RF_LUTWA, RF_WHOLE, first + gain as u32)?;
                let value = adjusted_gain(table[gain][at], sums[gain]);
                let mask = BIT_GAIN_EXT | BIT_DATA_L;
                bench.rf_set(path, RF_LUTWD0, mask, value & mask)?;
            }
            bench.rf_set(path, RF_LUTWE2, RF_WHOLE, 0)?;
        }
        Ok(())
    }

    /// `rtw8822c_do_dpk` in one call.
    ///
    /// # Safety
    /// As [`Self::even_gains`].
    #[cfg(test)]
    pub unsafe fn predistort<I: Io>(&mut self, io: &mut I, report: &Report) -> Result<(), Error> {
        // SAFETY: forwarded from the caller.
        let Some(mut run) = (unsafe { self.dpk_begin(io, report) })? else {
            return Ok(());
        };
        // SAFETY: as above, for each step of the same run.
        unsafe {
            for at in 0..2 {
                self.dpk_gain(io, report, &mut run, at)?;
                while !self.dpk_search(io, report, &mut run, at)? {}
                self.dpk_measure(io, report, &mut run, at)?;
            }
            for at in 0..2 {
                self.dpk_turn_on(io, report, at)?;
            }
            self.dpk_end(io, report, run)
        }
    }

    /// The start of `rtw8822c_do_dpk`: `None` where the channel's curves were
    /// learned before and are back in place, so nothing more follows.
    ///
    /// # Safety
    /// As [`rf::Registers::new`]: `io` and `report` are one radio's, whose
    /// frames wait while this worker owns it, from here to [`Self::dpk_end`].
    pub unsafe fn dpk_begin<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
    ) -> Result<Option<DpkRun>, Error> {
        let mut bench = Bench { io, report };
        let bench = &mut bench;
        let channel = bench.rf_get(Path::A, RF_CFGCH, RF_WHOLE)?;
        if channel & MASK_BYTE0 == self.dpk.channel {
            self.reload(bench)?;
            return Ok(None);
        }
        self.dpk.internal = [0; 2];
        self.dpk.two_ghz = channel & (1 << 16) == 0;
        self.dpk.channel = channel & MASK_BYTE0;
        self.dpk.wide = (channel >> 12) & 3 == WIDTH_80;
        let mut held = [0; DPK_REGISTERS.len()];
        for (value, register) in held.iter_mut().zip(DPK_REGISTERS) {
            *value = bench.io.read32(register)?;
        }
        let mut held_rf = [[0; 2]; DPK_RF_REGISTERS.len()];
        for (value, address) in held_rf.iter_mut().zip(DPK_RF_REGISTERS) {
            for (at, path) in paths() {
                value[at] = bench.rf_get(path, address, RF_WHOLE)?;
            }
        }
        if !bench.pause_transmit()? {
            self.fall_short("a transmit pause for calibration");
        }
        for (register, mask, value) in DPK_MAC_BB {
            bench.set(register, mask, value)?;
        }
        Self::analog_on(bench)?;
        self.prepare(bench)?;
        self.reset_results(bench)?;
        Ok(Some(DpkRun {
            held,
            held_rf,
            paths: [DpkPath::default(); 2],
        }))
    }

    /// `rtw8822c_dpk_gainloss` of path `at` up to its search.
    ///
    /// # Safety
    /// As [`Self::dpk_begin`].
    pub unsafe fn dpk_gain<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        run: &mut DpkRun,
        at: usize,
    ) -> Result<(), Error> {
        let path = paths()[at].1;
        let mut bench = Bench { io, report };
        let bench = &mut bench;
        let start_gain = self.rf_setting(bench, path)?;
        let start_agc = bench.rf_get(path, RF_MODE_TRXAGC, BIT_TXAGC)?;
        Self::settle_dc(bench, path)?;
        self.shot(bench, at, Shot::Gain)?;
        Self::digital_gain(bench)?;
        if Self::dc_off(bench)? {
            Self::settle_dc(bench, path)?;
            self.shot(bench, at, Shot::Gain)?;
            Self::dc_off(bench)?;
        }
        run.paths[at] = DpkPath {
            start_gain,
            start_agc,
            before: bench.thermal(path)?,
            ..DpkPath::default()
        };
        Ok(())
    }

    /// `rtw8822c_dpk_pas_agc` with `loss_only`, the search rtw88 runs, up to
    /// one measurement a call: whether it is over.
    ///
    /// # Safety
    /// As [`Self::dpk_begin`].
    pub unsafe fn dpk_search<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        run: &mut DpkRun,
        at: usize,
    ) -> Result<bool, Error> {
        let path = paths()[at].1;
        let mut bench = Bench { io, report };
        let search = &mut run.paths[at];
        loop {
            let state = search.state;
            if state == Agc::Done {
                return Ok(true);
            }
            search.state = self.search_step(&mut bench, at, path, search)?;
            if state == Agc::Measure {
                return Ok(search.state == Agc::Done);
            }
        }
    }

    /// The rest of `rtw8822c_dpk_gainloss` and `rtw8822c_dpk_calibrate` of
    /// path `at`, its search over.
    ///
    /// # Safety
    /// As [`Self::dpk_begin`].
    pub unsafe fn dpk_measure<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        run: &mut DpkRun,
        at: usize,
    ) -> Result<(), Error> {
        let path = paths()[at].1;
        let mut bench = Bench { io, report };
        let bench = &mut bench;
        let search = run.paths[at];
        bench.page(at)?;
        bench.set(REG_DPK_LOSS_SELECT, 1 << 14, 1)?;
        bench.write(REG_RXSRAM_CTL, 0x00060000)?;
        let found = bench.get(REG_STAT_RPT, 0xf0)?;
        bench.set(REG_DPK_LOSS_SELECT, 1 << 14, 0)?;
        let gain = search.gain.saturating_sub(found);
        bench.rf_set(path, RF_TX_GAIN, BIT_GAIN_TXBB, gain)?;
        let after = bench.thermal(path)?;
        self.dpk.thermal_delta[at] = search.before.abs_diff(after);
        let agc = search
            .start_agc
            .wrapping_sub(search.start_gain.wrapping_sub(gain));
        let finished = self.shot(bench, at, Shot::Predistort)?;
        bench.page(at)?;
        let failed = !finished || bench.get(REG_DPD_CTL1_S0, 1 << 26)? != 0;
        bench.rf_set(path, RF_MODE_TRXAGC, RF_WHOLE, 0x33e14)?;
        self.read_coefficients(bench, at)?;
        let good = !failed && !self.dpk.coefficients[at].iter().copied().any(railed);
        bench.page(at)?;
        let value = if good { agc.wrapping_sub(6) as u8 } else { 0 };
        self.set_path_result(bench, at, value, good)?;
        if !good {
            self.fall_short("predistortion on one of its paths");
        }
        Ok(())
    }

    /// Path `at` left out of a run cut short: the flat curve of a path that
    /// failed, as `rtw8822c_dpk_calibrate` leaves one.
    ///
    /// # Safety
    /// As [`Self::dpk_begin`].
    pub unsafe fn dpk_skip<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        at: usize,
    ) -> Result<(), Error> {
        let mut bench = Bench { io, report };
        bench.page(at)?;
        self.set_path_result(&mut bench, at, 0, false)
    }

    /// A path's AGC and curve, and whether it is good.
    fn set_path_result<I: Io>(
        &mut self,
        bench: &mut Bench<'_, I>,
        at: usize,
        agc: u8,
        good: bool,
    ) -> Result<(), Error> {
        bench.io.write8(REG_DPD_AGC, agc)?;
        self.dpk.txagc[at] = bench.io.read8(REG_DPD_AGC)?;
        self.write_coefficients(bench, at, good)?;
        self.dpk.ok[at] = good;
        Ok(())
    }

    /// `rtw8822c_dpk_on` of path `at`.
    ///
    /// # Safety
    /// As [`Self::dpk_begin`].
    pub unsafe fn dpk_turn_on<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        at: usize,
    ) -> Result<(), Error> {
        let mut bench = Bench { io, report };
        self.turn_on(&mut bench, at)
    }

    /// The end of `rtw8822c_do_dpk`: the scale, the curves on and what the
    /// run changed put back.
    ///
    /// # Safety
    /// As [`Self::dpk_begin`].
    pub unsafe fn dpk_end<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        run: DpkRun,
    ) -> Result<(), Error> {
        let mut bench = Bench { io, report };
        let bench = &mut bench;
        self.scale(bench)?;
        Self::analog_off(bench)?;
        self.enable(bench)?;
        for (value, address) in run.held_rf.iter().zip(DPK_RF_REGISTERS) {
            for (at, path) in paths() {
                bench.rf_set(path, address, RF_WHOLE, value[at])?;
            }
        }
        for (_, path) in paths() {
            Self::settle_dc(bench, path)?;
        }
        for (value, register) in run.held.iter().zip(DPK_REGISTERS) {
            bench.write(register, *value)?;
        }
        bench.common_page()?;
        bench.set(REG_RXSRAM_CTL, BIT_DPD_CLK, 4)
    }

    /// `rtw8822c_dpk_afe_is_dpk`.
    fn analog_on<I: Io>(bench: &mut Bench<'_, I>) -> Result<(), Error> {
        bench.write(REG_IQK_CTRL, IQK_AFE_CALIBRATING)?;
        for register in REG_ANAPAR {
            for step in AFE_CALIBRATING {
                bench.write(register, step)?;
            }
        }
        for register in REG_AFE_DPK {
            bench.set(register, AFE_DPK, 1)?;
        }
        Ok(())
    }

    /// `rtw8822c_dpk_afe_no_dpk`.
    fn analog_off<I: Io>(bench: &mut Bench<'_, I>) -> Result<(), Error> {
        for register in REG_AFE_DPK {
            bench.set(register, AFE_DPK, 0)?;
        }
        bench.write(REG_IQK_CTRL, IQK_AFE_RUNNING)?;
        let (first, rest) = AFE_RUNNING.split_at(AFE_RUNNING_FIRST);
        for steps in [first, rest] {
            for register in REG_ANAPAR {
                for &step in steps {
                    bench.write(register, step)?;
                }
            }
        }
        Ok(())
    }

    /// `rtw8822c_dpk_pre_setting`.
    fn prepare<I: Io>(&self, bench: &mut Bench<'_, I>) -> Result<(), Error> {
        for (at, path) in paths() {
            bench.rf_set(path, RF_RXAGC_OFFSET, RF_WHOLE, 0)?;
            bench.write(REG_NCTL0, 0x8 | ((at as u32) << 1))?;
            self.band_setting(bench)?;
            bench.set(REG_DPD_LUT0, BIT_GLOSS_DB, 4)?;
            bench.set(REG_IQK_CTL1, BIT_TX_CFIR, 3)?;
        }
        bench.common_page()?;
        bench.write(REG_DPD_CTL11, 0x3b23170b)?;
        bench.write(REG_DPD_CTL12, 0x775f5347)
    }

    fn band_setting<I: Io>(&self, bench: &mut Bench<'_, I>) -> Result<(), Error> {
        let value = if self.dpk.two_ghz {
            0x1f100000
        } else {
            0x1f0d0000
        };
        bench.write(REG_DPD_CTL1_S1, value)
    }

    /// `rtw8822c_dpk_result_reset`.
    fn reset_results<I: Io>(&mut self, bench: &mut Bench<'_, I>) -> Result<(), Error> {
        for (at, path) in paths() {
            self.dpk.ok[at] = false;
            bench.page(at)?;
            bench.set(REG_DPK_PWSF, 0x7f, 0)?;
            self.dpk.txagc[at] = 0;
            self.dpk.gs[at] = 0x5b;
            self.dpk.offsets[at] = 0;
            self.dpk.thermal[at] = bench.thermal(path)?;
        }
        Ok(())
    }

    /// `rtw8822c_dpk_set_gnt_wl`'s grant around `work`.
    fn with_grant<I: Io>(
        bench: &mut Bench<'_, I>,
        work: impl FnOnce(&mut Bench<'_, I>) -> Result<bool, Error>,
    ) -> Result<bool, Error> {
        const GRANTS: u32 = 0x38;
        let control = bench.io.read32(REG_GNT_CONTROL)?;
        let grants = Coex::arbiter_read(bench.io, GRANTS)?;
        bench.set(REG_GNT_CONTROL, 1 << 26, 1)?;
        Coex::arbiter_write(bench.io, GRANTS, MASK_BYTE1, 0x77)?;
        let finished = work(bench)?;
        Coex::arbiter_write(bench.io, GRANTS, MASK_WORD, grants)?;
        bench.write(REG_GNT_CONTROL, control)?;
        Ok(finished)
    }

    /// `rtw8822c_dpk_one_shot`: whether the block finished.
    fn shot<I: Io>(&self, bench: &mut Bench<'_, I>, at: usize, shot: Shot) -> Result<bool, Error> {
        let wide = u16::from(self.dpk.wide) * 2;
        let path = at as u16;
        let command = (match shot {
            Shot::Power => 0,
            Shot::GainLoss => 0x14 + path,
            Shot::Predistort => 0x16 + path + wide,
            Shot::Enable => 0x1a + path,
            Shot::Gain => 0x1c + path + wide,
        } << 8)
            | 0x48;
        let finished = Self::with_grant(bench, |bench| {
            if shot == Shot::Power {
                bench.set(REG_DPD_CTL0, 1 << 12, 1)?;
                bench.set(REG_DPD_CTL0, 1 << 12, 0)?;
                bench.set(REG_RXSRAM_CTL, BIT_RPT_SEL, 0)?;
                bench.io.delay_us(ONE_SHOT_US);
                return bench.ready(REG_STAT_RPT, 1 << 31, 1);
            }
            bench.page(at)?;
            bench.set(REG_R_CONFIG, BIT_IQ_SWITCH, 9)?;
            bench.write(REG_NCTL0, command.into())?;
            bench.write(REG_NCTL0, u32::from(command) + 1)?;
            bench.io.delay_us(ONE_SHOT_US);
            let finished = bench.ready(REG_RPT_CIP, BIT_RPT_CIP_STATUS, 0x55)?;
            bench.page(at)?;
            bench.set(REG_R_CONFIG, BIT_IQ_SWITCH, 0)?;
            Ok(finished)
        })?;
        bench.io.write8(REG_IQKSTAT, 0)?;
        Ok(finished)
    }

    /// `rtw8822c_dpk_rxbb_dc_cal`.
    fn settle_dc<I: Io>(bench: &mut Bench<'_, I>, path: Path) -> Result<(), Error> {
        bench.rf_set(path, RF_RX_DC, RF_WHOLE, 0x84800)?;
        bench.io.delay_us(5);
        bench.rf_set(path, RF_RX_DC, RF_WHOLE, 0x84801)?;
        bench.io.delay_us(600);
        bench.rf_set(path, RF_RX_DC, RF_WHOLE, 0x84800)
    }

    /// `rtw8822c_dpk_dc_corr_check`: whether the DC or correlation is off.
    fn dc_off<I: Io>(bench: &mut Bench<'_, I>) -> Result<bool, Error> {
        let magnitude = |value: u32| {
            if value & (1 << 11) != 0 {
                0x1000 - value
            } else {
                value
            }
        };
        bench.write(REG_RXSRAM_CTL, 0x000900f0)?;
        let i = magnitude(bench.get(REG_STAT_RPT, 0xfff << 16)?);
        let q = magnitude(bench.get(REG_STAT_RPT, 0xfff)?);
        bench.write(REG_RXSRAM_CTL, 0x000000f0)?;
        let correlation = bench.get(REG_STAT_RPT, 0xff)?;
        Ok(i > 200 || q > 200 || !(40..=65).contains(&correlation))
    }

    /// `rtw8822c_dpk_rf_setting`: the transmit gain it found.
    fn rf_setting<I: Io>(&self, bench: &mut Bench<'_, I>, path: Path) -> Result<u32, Error> {
        bench.rf_set(path, RF_MODE_TRXAGC, RF_WHOLE, 0x50017)?;
        let gain = bench.rf_get(path, RF_TX_GAIN, RF_WHOLE)?;
        bench.rf_set(path, RF_DEBUG, BIT_DE_TX_GAIN, 1)?;
        bench.rf_set(path, RF_DEBUG, BIT_DE_PWR_TRIM, 1)?;
        bench.rf_set(path, RF_TX_GAIN_OFFSET, BIT_BB_GAIN, 0)?;
        bench.rf_set(path, RF_TX_GAIN, RF_WHOLE, gain)?;
        if self.dpk.two_ghz {
            bench.rf_set(path, RF_TX_GAIN_OFFSET, BIT_RF_GAIN, 1)?;
            bench.rf_set(path, RF_RXG_GAIN, BIT_RXG_GAIN, 0)?;
        } else {
            bench.rf_set(path, RF_TXA_LB_SW, BIT_TXA_LB_ATT, 0)?;
            bench.rf_set(path, RF_TXA_LB_SW, BIT_LB_ATT, 6)?;
            bench.rf_set(path, RF_TXA_LB_SW, BIT_LB_SW, 1)?;
            bench.rf_set(path, RF_RXA_MIX_GAIN, BIT_RXA_MIX_GAIN, 0)?;
        }
        bench.rf_set(path, RF_MODE_TRXAGC, BIT_RXAGC, 0xf)?;
        bench.rf_set(path, RF_DEBUG, BIT_DE_TRXBW, 1)?;
        bench.rf_set(path, RF_BW_TRXBB, BIT_BW_RXBB, 0)?;
        let bandwidth = if self.dpk.wide { 2 } else { 1 };
        bench.rf_set(path, RF_BW_TRXBB, BIT_BW_TXBB, bandwidth)?;
        bench.rf_set(path, RF_EXT_TIA_BW, BIT_PW_EXT_TIA, 1)?;
        bench.io.delay_us(100);
        Ok(gain & 0x1f)
    }

    /// `rtw8822c_dpk_dgain_read`.
    fn digital_gain<I: Io>(bench: &mut Bench<'_, I>) -> Result<u32, Error> {
        bench.common_page()?;
        bench.set(REG_RXSRAM_CTL, 0xff << 16, 0)?;
        bench.get(REG_STAT_RPT, 0xfff << 16)
    }

    /// `rtw8822c_dpk_pas_read`: the power of what came back.
    fn returned_power<I: Io>(bench: &mut Bench<'_, I>, at: usize) -> Result<u32, Error> {
        let magnitude = |value: u32| {
            if value & (1 << 15) != 0 {
                0x10000 - value
            } else {
                value
            }
        };
        bench.write(REG_NCTL0, 0x8 | ((at as u32) << 1))?;
        bench.set(REG_DPK_LOSS_SELECT, 1 << 14, 0)?;
        bench.write(REG_RXSRAM_CTL, 0x00060001)?;
        bench.write(REG_DPK_PAS, 0)?;
        bench.write(REG_DPK_PAS, 0x00080000)?;
        let q = magnitude(bench.get(REG_STAT_RPT, MASK_HIGH)?);
        let i = magnitude(bench.get(REG_STAT_RPT, MASK_LOW)?);
        bench.write(REG_DPK_PAS, 0)?;
        Ok(i.wrapping_mul(i).wrapping_add(q.wrapping_mul(q)))
    }

    /// One state of `rtw8822c_dpk_pas_agc`'s search.
    fn search_step<I: Io>(
        &self,
        bench: &mut Bench<'_, I>,
        at: usize,
        path: Path,
        search: &mut DpkPath,
    ) -> Result<Agc, Error> {
        Ok(match search.state {
            Agc::Read => {
                search.gain = bench.rf_get(path, RF_TX_GAIN, BIT_GAIN_TXBB)?;
                search.tries += 1;
                if search.tries >= 6 {
                    Agc::Done
                } else {
                    Agc::Measure
                }
            }
            Agc::Measure => {
                self.shot(bench, at, Shot::GainLoss)?;
                let power = Self::returned_power(bench, at)?;
                if power < 0x4000000 {
                    Agc::TooQuiet
                } else {
                    let loss = (3 * log2_hundredths(power >> 13)).wrapping_sub(3870);
                    match loss {
                        loss if loss > 1000 => Agc::TooLoud,
                        loss if loss < 250 => Agc::TooQuiet,
                        _ => Agc::Done,
                    }
                }
            }
            Agc::TooLoud if search.gain == 0 => Agc::Done,
            Agc::TooQuiet if search.gain == BIT_GAIN_TXBB => Agc::Done,
            Agc::TooLoud => {
                search.gain = search.gain.saturating_sub(2);
                bench.rf_set(path, RF_TX_GAIN, BIT_GAIN_TXBB, search.gain)?;
                Agc::Read
            }
            Agc::TooQuiet => {
                search.gain = (search.gain + 3).min(BIT_GAIN_TXBB);
                bench.rf_set(path, RF_TX_GAIN, BIT_GAIN_TXBB, search.gain)?;
                Agc::Read
            }
            Agc::Done => Agc::Done,
        })
    }

    /// `rtw8822c_dpk_get_coef`.
    fn read_coefficients<I: Io>(
        &mut self,
        bench: &mut Bench<'_, I>,
        at: usize,
    ) -> Result<(), Error> {
        bench.write(REG_NCTL0, 0xc)?;
        bench.set(REG_DPD_CTL0, 1 << 24, at as u32)?;
        let control = [REG_DPD_CTL0_S0, REG_DPD_CTL0_S1][at];
        bench.write(control, 0x30000080)?;
        for (value, read) in self.dpk.coefficients[at].iter_mut().zip(COEFFICIENT_READS) {
            bench.write(REG_RXSRAM_CTL, read)?;
            let high = bench.get(REG_STAT_RPT, MASK_HIGH)?;
            let low = bench.get(REG_STAT_RPT, MASK_LOW)?;
            *value = coefficient((high << 16) | low);
        }
        Ok(())
    }

    /// `rtw8822c_dpk_coef_write`, or the flat curve of a path that failed.
    fn write_coefficients<I: Io>(
        &self,
        bench: &mut Bench<'_, I>,
        at: usize,
        good: bool,
    ) -> Result<(), Error> {
        bench.write(REG_NCTL0, 0xc)?;
        bench.write(REG_RXSRAM_CTL, 0x000000f0)?;
        for (address, &value) in self.dpk.coefficients[at].iter().enumerate() {
            let value = match (good, address) {
                (true, _) => value,
                (false, 3) => 0x04001fff,
                (false, _) => 0x00001fff,
            };
            bench.write(REG_DPK_COEFFICIENTS[at] + address as u32 * 4, value)?;
        }
        Ok(())
    }

    /// `rtw8822c_dpk_on`.
    fn turn_on<I: Io>(&mut self, bench: &mut Bench<'_, I>, at: usize) -> Result<(), Error> {
        self.shot(bench, at, Shot::Enable)?;
        bench.page(at)?;
        bench.set(REG_IQK_CTL1, BIT_TX_CFIR, 0)?;
        if self.dpk.ok[at] {
            self.compensate(bench, at)?;
        }
        Ok(())
    }

    /// `rtw8822c_dpk_cal_gs`.
    fn compensate<I: Io>(&mut self, bench: &mut Bench<'_, I>, at: usize) -> Result<(), Error> {
        let control = [REG_DPD_CTL0_S0, REG_DPD_CTL0_S1][at];
        bench.page(at)?;
        bench.set(REG_IQK_CTL1, BIT_BYPASS_DPD, 0)?;
        bench.set(REG_IQK_CTL1, BIT_TX_CFIR, 0)?;
        bench.set(REG_R_CONFIG, BIT_IQ_SWITCH, 9)?;
        bench.set(REG_R_CONFIG, BIT_INNER_LB, 1)?;
        bench.common_page()?;
        bench.set(REG_RXSRAM_CTL, BIT_DPD_CLK, 0xf)?;
        bench.set(control, BIT_GS_PWSF, 0x1066680)?;
        bench.set([REG_DPD_CTL1_S0, REG_DPD_CTL1_S1][at], BIT_DPD_EN, 1)?;
        let (steps, last) = if self.dpk.wide {
            ([0x80001310, 0x00001310, 0x810000db, 0x010000db], 0x05020000)
        } else {
            ([0x8200190c, 0x0200190c, 0x8301ee14, 0x0301ee14], 0x05020008)
        };
        for step in steps {
            bench.write(REG_DPD_CTL16, step)?;
        }
        bench.write(REG_DPD_CTL16, 0x0000b428)?;
        bench.write(REG_DPD_CTL15, last | (1 << (28 + at)))?;
        bench.set(REG_DPD_CTL0, MASK_BYTE3, 0x8 | at as u32)?;
        self.shot(bench, at, Shot::Power)?;
        bench.set(REG_DPD_CTL15, MASK_BYTE3, 0)?;
        bench.page(at)?;
        bench.set(REG_R_CONFIG, BIT_IQ_SWITCH, 0)?;
        bench.set(REG_R_CONFIG, BIT_INNER_LB, 0)?;
        bench.common_page()?;
        bench.set(control, BIT_GS_PWSF, 0x5b)?;
        bench.set(REG_RXSRAM_CTL, BIT_RPT_SEL, 0)?;
        let scale = (bench.get(REG_STAT_RPT, BIT_RPT_DGAIN)? * 910) >> 10;
        let scale = (scale + 5) / 10;
        bench.set(control, BIT_GS_PWSF, scale)?;
        self.dpk.gs[at] = scale;
        Ok(())
    }

    /// `rtw8822c_dpk_cal_coef1`.
    fn scale<I: Io>(&mut self, bench: &mut Bench<'_, I>) -> Result<(), Error> {
        bench.common_page()?;
        bench.write(REG_RXSRAM_CTL, 0x000000f0)?;
        bench.write(REG_NCTL0, 0x00001148)?;
        bench.write(REG_NCTL0, 0x00001149)?;
        if !bench.ready(REG_RPT_CIP, BIT_RPT_CIP_STATUS, 0x55)? {
            self.fall_short("predistortion's last scaling");
        }
        bench.io.write8(REG_IQKSTAT, 0)?;
        bench.common_page()?;
        for at in 0..2 {
            let stride = at as u32 * PATH_STRIDE;
            let scaling = 0x16c00u32.checked_div(self.dpk.gs[at]).unwrap_or(0);
            bench.set(REG_DPK_SCALE + stride, MASK_HIGH, scaling)?;
            for step in [9, 1, 0] {
                bench.set(REG_DPD_CTL0_S0 + stride, 15 << 28, step)?;
            }
            bench.set(REG_DPD_CTL1_S0 + stride, 1 << 14, 0)?;
        }
        Ok(())
    }

    /// `rtw8822c_dpk_enable_disable`.
    fn enable<I: Io>(&self, bench: &mut Bench<'_, I>) -> Result<(), Error> {
        bench.common_page()?;
        for at in 0..2 {
            let enable = [REG_DPD_CTL1_S0, REG_DPD_CTL1_S1][at];
            bench.set(enable, BIT_DPD_EN, 1)?;
            if self.dpk.ok[at] {
                bench.set(enable, 3 << 14, 0)?;
                let control = [REG_DPD_CTL0_S0, REG_DPD_CTL0_S1][at];
                bench.io.write8(control, self.dpk.gs[at] as u8)?;
            }
        }
        Ok(())
    }

    /// `rtw8822c_dpk_reload_data`, for a channel already learned.
    fn reload<I: Io>(&mut self, bench: &mut Bench<'_, I>) -> Result<(), Error> {
        for at in 0..2 {
            bench.page(at)?;
            self.band_setting(bench)?;
            bench.io.write8(REG_DPD_AGC, self.dpk.txagc[at])?;
            self.write_coefficients(bench, at, self.dpk.ok[at])?;
            self.shot(bench, at, Shot::Enable)?;
            bench.common_page()?;
            let control = [REG_DPD_CTL0_S0, REG_DPD_CTL0_S1][at];
            bench.set(control, BIT_GS_PWSF, self.dpk.gs[at])?;
        }
        self.scale(bench)
    }

    /// `rtw8822c_dpk_track`: the curve's output follows the temperature.
    ///
    /// # Safety
    /// As [`Self::even_gains`].
    pub unsafe fn track<I: Io>(&mut self, io: &mut I, report: &Report) -> Result<(), Error> {
        if self.dpk.thermal == [0; 2] {
            return Ok(());
        }
        let mut bench = Bench { io, report };
        for (at, path) in paths() {
            let reading = bench.thermal(path)?;
            let internal = &mut self.dpk.internal[at];
            let value = u64::from(reading) << THERMAL_PRECISION;
            *internal = if *internal == 0 {
                value
            } else {
                ((*internal << THERMAL_WEIGHT) - *internal + value) >> THERMAL_WEIGHT
            };
            let average = (*internal >> THERMAL_PRECISION) as u8;
            let offset = self.dpk.thermal[at]
                .wrapping_sub(average)
                .wrapping_sub(self.dpk.thermal_delta[at])
                & 0x7f;
            if offset != self.dpk.offsets[at] {
                bench.page(at)?;
                bench.set(REG_DPK_PWSF, 0x7f, offset.into())?;
                self.dpk.offsets[at] = offset;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::realtek::{
        identity::{Profile, tests::profile},
        registers::{FW_READY, REG_MCUFW_CTRL, REG_RF_CTRL, REG_SYS_CFG1, REG_SYS_FUNC_EN},
    };
    use alloc::collections::BTreeMap;

    #[test]
    fn a_power_gate_keeps_each_paths_predistortion() {
        let mut calibration = Calibration::new(0);
        calibration.dpk.ok = [false, true];
        calibration.dpk.channel = 36;
        calibration.dpk.txagc = [0x11, 0x22];
        calibration.dpk.gs = [0x5b, 0x1_0067];
        calibration.dpk.coefficients[0][0] = 0x0403_0201;
        calibration.dpk.coefficients[1][19] = 0x0807_0605;
        let page = calibration.power_gate_page();
        assert_eq!(page[..2], [2, 0], "a bitmap of the paths");
        assert_eq!(page[2..4], [0x11, 0x22]);
        assert_eq!(page[4..8], [0x5b, 0, 0x67, 0]);
        assert_eq!(page[8..12], [1, 2, 3, 4]);
        assert_eq!(page[164..168], [5, 6, 7, 8]);
        assert_eq!(page[168], 36);
    }

    /// The arbiter's control, always ready here.
    const REG_ARBITER: u32 = 0x1700;
    const ARBITER_READY: u32 = 1 << 29;

    /// Registers as words, with the reports calibration polls standing ready.
    struct Bus(BTreeMap<u32, u32>, u32);

    impl Bus {
        fn new(report: u32) -> Self {
            let mut bus = Self(BTreeMap::new(), report);
            bus.0.insert(REG_WLRF1, 0x0700_0000);
            bus.0.insert(0x3c00 + u32::from(RF_CFGCH) * 4, 6);
            bus.0.insert(0x4c00 + u32::from(RF_CFGCH) * 4, 6);
            bus.0.insert(REG_TX_PTCL_CTRL, 0x100);
            bus
        }
        fn get(&self, register: u32) -> u32 {
            match register {
                REG_SYS_CFG1 => profile().observed().sys_cfg1,
                REG_MCUFW_CTRL => FW_READY.into(),
                REG_SYS_FUNC_EN => 3,
                REG_RF_CTRL => 7,
                REG_RPT_CIP => 0x55,
                REG_ARFR4 => 1,
                REG_ARBITER => ARBITER_READY,
                REG_STAT_RPT => self.1,
                _ => self.0.get(&register).copied().unwrap_or(0),
            }
        }
    }

    // SAFETY: nothing here reaches hardware; this is a map of words.
    unsafe impl Io for Bus {
        fn profile(&self) -> Profile {
            profile()
        }
        fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
            Ok(self.get(register) as u8)
        }
        fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
            Ok(self.get(register) as u16)
        }
        fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
            Ok(self.get(register))
        }
        fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
            self.0.insert(register, value.into());
            Ok(())
        }
        fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
            self.0.insert(register, value.into());
            Ok(())
        }
        fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
            self.0.insert(register, value);
            Ok(())
        }
        fn delay_us(&mut self, _: u64) {}
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
            Ok(())
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            Ok(())
        }
        fn quarantine(&mut self) {}
    }

    #[test]
    fn a_whole_calibration_learns_a_curve_and_puts_the_radio_back() {
        let mut bus = Bus::new(0x8123_0456);
        let report = Report::of_two_paths(profile());
        let mut calibration = Calibration::new(0);
        // SAFETY: a map of words.
        unsafe { calibration.even_gains(&mut bus, &report) }.unwrap();
        assert!(calibration.gapk.read);
        assert_eq!(bus.get(REG_TX_PTCL_CTRL), 0x100);
        assert_eq!(bus.get(REG_IQK_CTRL), IQK_AFE_RUNNING);
        for (held, register) in DPK_REGISTERS.into_iter().enumerate() {
            bus.0.insert(register, 0x100 + held as u32);
        }
        // SAFETY: as above.
        unsafe { calibration.predistort(&mut bus, &report) }.unwrap();
        assert_eq!(calibration.dpk.ok, [true; 2]);
        assert_eq!(calibration.dpk.channel, 6);
        assert!(calibration.dpk.two_ghz);
        assert_eq!(calibration.take_shortfalls(), [] as [&str; 0]);
        for (held, register) in DPK_REGISTERS.into_iter().enumerate() {
            assert_eq!(bus.get(register), 0x100 + held as u32);
        }
        assert_eq!(bus.get(REG_DPK_COEFFICIENTS[0]), coefficient(0x8123_0456));
        // The channel's curve comes back without learning it again.
        calibration.dpk.txagc = [0x11, 0x22];
        // SAFETY: as above.
        unsafe { calibration.predistort(&mut bus, &report) }.unwrap();
        assert_eq!(calibration.dpk.txagc, [0x11, 0x22]);
        assert_eq!(bus.get(REG_DPD_AGC), 0x22);
    }

    #[test]
    fn a_curve_on_its_rails_leaves_a_flat_one_and_says_so() {
        let mut bus = Bus::new(0x9000_0456);
        let report = Report::of_two_paths(profile());
        let mut calibration = Calibration::new(0);
        // SAFETY: a map of words.
        unsafe { calibration.predistort(&mut bus, &report) }.unwrap();
        assert_eq!(calibration.dpk.ok, [false; 2]);
        assert_eq!(bus.get(REG_DPK_COEFFICIENTS[0]), 0x1fff);
        assert_eq!(bus.get(REG_DPK_COEFFICIENTS[0] + 12), 0x04001fff);
        assert_eq!(bus.get(REG_DPD_AGC), 0);
        assert_eq!(
            calibration.take_shortfalls(),
            ["predistortion on one of its paths"]
        );
    }

    #[test]
    fn tssi_boards_keep_their_table() {
        let mut bus = Bus::new(0);
        let report = Report::of_two_paths(profile());
        let mut calibration = Calibration::new(5);
        // SAFETY: a map of words.
        unsafe { calibration.even_gains(&mut bus, &report) }.unwrap();
        assert!(calibration.gapk.read);
        assert_eq!(bus.get(REG_TXPAUSE), 0);
    }

    #[test]
    fn the_curves_output_follows_the_temperature_it_was_learned_at() {
        let mut bus = Bus::new(0);
        bus.0.insert(0x3c00 + u32::from(RF_T_METER) * 4, 0x18 << 1);
        bus.0.insert(0x4c00 + u32::from(RF_T_METER) * 4, 0x1e << 1);
        let report = Report::of_two_paths(profile());
        let mut calibration = Calibration::new(0);
        calibration.dpk.thermal = [0x20, 0x20];
        calibration.dpk.thermal_delta = [2, 0];
        // SAFETY: a map of words.
        unsafe { calibration.track(&mut bus, &report) }.unwrap();
        assert_eq!(calibration.dpk.offsets, [6, 2]);
        assert_eq!(bus.get(REG_DPK_PWSF) & 0x7f, 2);
    }

    #[test]
    fn the_top_of_the_gain_table_stands_and_the_rest_moves_by_half_steps() {
        assert!(gain_holds(0xce0));
        assert!(!gain_holds(0xcd0));
        assert!(!gain_holds(0xbf0));
        assert_eq!(adjusted_gain(0xce0, 5), 0xce0);
        assert_eq!(adjusted_gain(0x400, 4), 0x402);
        assert_eq!(adjusted_gain(0x400, 3), 0x401 | BIT_GAIN_EXT);
        assert_eq!(adjusted_gain(0x400, -2), 0x3ff);
    }

    #[test]
    fn a_reports_nibbles_are_signed() {
        assert_eq!(gain_offset(0x0000_00f7, 0), 7);
        assert_eq!(gain_offset(0x0000_00f7, 1), -1);
        assert_eq!(gain_offset(0x8000_0000, 7), -8);
    }

    #[test]
    fn channels_pick_their_gain_rows() {
        assert_eq!(gain_band(6), Some((1, 0x20)));
        assert_eq!(gain_band(64), Some((2, 0x200)));
        assert_eq!(gain_band(100), Some((3, 0x280)));
        assert_eq!(gain_band(165), Some((4, 0x300)));
        assert_eq!(gain_band(0), None);
    }

    #[test]
    fn the_logarithm_matches_the_drivers_table() {
        assert_eq!(log2_hundredths(0), 0);
        // 1024 has eleven bits, and half of the next power.
        assert_eq!(log2_hundredths(1024), 1100 - 100);
        assert_eq!(log2_hundredths(1536), 1100 - 42);
    }

    #[test]
    fn coefficients_negate_their_q_and_rails_fail_the_curve() {
        assert_eq!(coefficient(0x0123_0001), 0x0123_1ffe);
        assert_eq!(coefficient(0x0000_0000), 0x0000_ffff);
        assert!(railed(0x1000_0000));
        assert!(railed(0x0000_0fff));
        assert!(!railed(0x0123_0456));
    }

    #[test]
    fn the_analog_tables_hold_what_the_drivers_do() {
        assert_eq!(AFE_CALIBRATING[0], AFE_CALIBRATING[1]);
        assert_eq!(AFE_CALIBRATING[16], AFE_CALIBRATING[17]);
        assert_eq!(AFE_RUNNING[AFE_RUNNING_FIRST - 1], 0x70644041);
        assert_eq!(AFE_RUNNING[AFE_RUNNING_FIRST], 0x707b8041);
    }
}
