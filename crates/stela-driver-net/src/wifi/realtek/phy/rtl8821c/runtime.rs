// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! What the RTL8821C's `rtw_chip_ops` do for `rtw_phy_dynamic_mechanism`:
//! `rtw8821c_false_alarm_statistics` and `rtw8821c_pwr_track`.
use super::{Error, Phy, REG_TXSCALE_A, Report, TX_SCALE};
use crate::wifi::realtek::{
    dynamic::{AVERAGE_PRECISION, Alarms, average_in, set_mask},
    identity::Chip,
    io::{self, Io},
    rf::{self, Path},
};

const REG_RXPSEL: u32 = 0x808;
const CCK_ENABLED: u32 = 1 << 28;
const REG_FAS: u32 = 0x9a4;
const REG_FA_CCK: u32 = 0xa5c;
const REG_RXDESC: u32 = 0xa2c;
const REG_CNTRST: u32 = 0xb58;
const REG_CRC_CCK: u32 = 0xf04;
const REG_FA_OFDM: u32 = 0xf48;
/// `REG_TXAGCIDX`'s index offset, bits 6:1.
const REG_TXAGCIDX: u32 = 0xc94;
const TXAGC_INDEX: u32 = 0x7e;

const RF_T_METER: u8 = 0x42;
/// `rtw8821c_pwr_track`'s trigger, and where the reading lands.
const THERMAL_TRIGGER: u32 = 0x3_0000;
const THERMAL: u32 = 0xfc00;
/// `DECLARE_EWMA(thermal, 10, 4)`.
const THERMAL_WEIGHT: u32 = 2;
/// `RTW_PWR_TRK_TBL_SZ`.
const TABLE: usize = 30;
/// `rtw8821c_hw_spec.iqk_threshold`.
const IQK_THRESHOLD: u8 = 8;

/// `rtw8821c_false_alarm_statistics`: the counts, then each counter reset.
pub fn false_alarms<I: Io>(io: &mut I) -> Result<Alarms, io::Error> {
    let cck_enabled = io.read32(REG_RXPSEL)? & CCK_ENABLED != 0;
    let cck = u32::from(io.read16(REG_FA_CCK)?);
    let ofdm = u32::from(io.read16(REG_FA_OFDM)?);
    let crc = io.read32(REG_CRC_CCK)?;
    let total = ofdm + if cck_enabled { cck } else { 0 };
    set_mask(io, REG_FAS, 1 << 17, 1)?;
    set_mask(io, REG_FAS, 1 << 17, 0)?;
    set_mask(io, REG_RXDESC, 1 << 15, 0)?;
    set_mask(io, REG_RXDESC, 1 << 15, 1)?;
    set_mask(io, REG_CNTRST, 1, 1)?;
    set_mask(io, REG_CNTRST, 1, 0)?;
    Ok(Alarms {
        total: total.min(u32::from(u16::MAX)) as u16,
        cck,
        cck_frames: (crc & 0xffff) + (crc >> 16),
    })
}

type Swing = [u8; TABLE];

/// `rtw8821c_pwrtrk_2ga_p` and `_n`.
const RAISE_2G: Swing = [
    0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5, 5, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 9, 9, 9, 9,
];
const LOWER_2G: Swing = [
    0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 7, 7, 8, 8, 9,
];
/// `rtw8821c_pwrtrk_2g_cck_a_p` and `_n`.
const RAISE_CCK: Swing = [
    0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 7, 7, 7, 8, 8, 9, 9, 9, 9, 9, 9,
];
const LOWER_CCK: Swing = [
    0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 9,
];
/// `rtw8821c_pwrtrk_5ga_p` and `_n`, by `RTW_PWR_TRK_5G_1` to `_3`.
const RAISE_5G: [Swing; 3] = [
    [
        0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 11, 11, 12, 12, 12, 12, 12,
        12, 12,
    ],
    [
        0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 5, 6, 7, 7, 8, 8, 9, 10, 10, 11, 11, 12, 12, 12, 12, 12,
        12, 12, 12,
    ],
    [
        0, 1, 1, 1, 2, 3, 3, 3, 4, 4, 4, 5, 6, 6, 7, 7, 8, 8, 9, 10, 10, 11, 11, 12, 12, 12, 12,
        12, 12, 12,
    ],
];
const LOWER_5G: [Swing; 3] = [
    [
        0, 1, 1, 2, 3, 3, 3, 4, 4, 5, 5, 6, 6, 6, 7, 8, 8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 12,
        12, 12,
    ],
    [
        0, 1, 1, 1, 2, 3, 3, 4, 4, 5, 5, 5, 6, 6, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 12, 12,
        12, 12, 12,
    ],
    [
        0, 1, 2, 2, 3, 4, 4, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 12, 12,
        12, 12,
    ],
];

/// `rtw_phy_config_swing_table` for path A on `channel` at `tx_rate`.
fn swing(channel: u8, tx_rate: u8) -> (&'static Swing, &'static Swing) {
    match channel {
        36..=64 => (&RAISE_5G[0], &LOWER_5G[0]),
        100..=144 => (&RAISE_5G[1], &LOWER_5G[1]),
        149..=177 => (&RAISE_5G[2], &LOWER_5G[2]),
        // DESC_RATE11M and below are CCK.
        _ if tx_rate <= 3 => (&RAISE_CCK, &LOWER_CCK),
        _ => (&RAISE_2G, &LOWER_2G),
    }
}

/// `rtw8821c_txagc_swing_offset`: the TXAGC offset and the swing index that
/// make up `delta` from `default`, the swing the channel left.
fn swing_offset(delta: i8, default: u8, offset: u8, lower: i8) -> (i8, u8) {
    let offset = offset.min(0xf) as i8;
    let lower = lower.max(-15);
    let (agc, index) = if delta >= 0 {
        if delta <= offset {
            (delta, default)
        } else {
            let index = default.saturating_add((delta - offset) as u8);
            (offset, index.min(default.saturating_add(10)))
        }
    } else if delta >= lower {
        (delta, default)
    } else {
        let short = (lower - delta) as u8;
        let index = default.saturating_sub(short);
        (lower, index)
    };
    (agc, index.min(TX_SCALE.len() as u8 - 1))
}

/// `rtw8821c_pwrtrack_init`'s and `rtw8821c_pwr_track`'s state.
#[derive(Debug)]
pub struct Tracking {
    /// `efuse->thermal_meter[0]`, and whether `power_track_type` is zero.
    factory: u8,
    tracked: bool,
    /// `pwr_trk_triggered` and `pwr_trk_init_trigger`.
    triggered: bool,
    first: bool,
    /// `avg_thermal[0]` and `thermal_avg[0]`.
    internal: u64,
    average: u8,
    /// `delta_power_index_last[0]`.
    last: i8,
    /// `thermal_meter_k`.
    calibrated_at: u8,
}

/// What a tracking step leaves for the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tracked {
    Nothing,
    /// `rtw_phy_pwrtrack_need_iqk`: the meter moved past `iqk_threshold`
    /// since the last IQK.
    Iqk,
}

impl Tracking {
    /// `rtw8821c_pwrtrack_init` for `thermal`, the efuse's meter, tracked
    /// when `tracked` (`power_track_type` zero).
    pub fn new(thermal: u8, tracked: bool) -> Self {
        Self {
            factory: thermal,
            tracked,
            triggered: false,
            first: true,
            internal: 0,
            average: 0,
            last: 0,
            calibrated_at: thermal,
        }
    }

    /// `rtw8821c_pwrtrack_init` again, as each channel switch runs it.
    pub fn reset(&mut self) {
        *self = Self::new(self.factory, self.tracked);
    }

    /// `rtw8821c_pwr_track`: one run asks the meter, the next reads it and
    /// sets path A's power for `tx_index`, the TX power index the channel's
    /// plan gives `tx_rate` (`rtw_phy_get_tx_power_index`).
    ///
    /// # Safety
    /// As [`rf::Registers::new`], with `io`, `report` and `phy` the same
    /// radio's and nothing else reaching its BB or RF.
    pub unsafe fn track<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        phy: &Phy,
        channel: u8,
        tx_rate: u8,
        tx_index: u8,
    ) -> Result<Tracked, Error> {
        if io.profile().chip() != Chip::Rtl8821C || phy.profile() != io.profile() {
            return Err(Error::WrongProfile);
        }
        if !self.tracked {
            return Ok(Tracked::Nothing);
        }
        // SAFETY: the caller's.
        let mut rf = unsafe { rf::Registers::new(&mut *io, report) }?;
        if !self.triggered {
            rf.write(Path::A, RF_T_METER, THERMAL_TRIGGER, 3)?;
            self.triggered = true;
            return Ok(Tracked::Nothing);
        }
        self.triggered = false;
        if self.factory == 0xff {
            return Ok(Tracked::Nothing);
        }
        let reading = rf.read(Path::A, RF_T_METER, THERMAL)? as u8;
        drop(rf);
        average_in(&mut self.internal, u64::from(reading), THERMAL_WEIGHT);
        self.average = (self.internal >> AVERAGE_PRECISION) as u8;
        let changed = core::mem::take(&mut self.first) || self.average != reading;
        if changed {
            let delta = usize::from(self.average.abs_diff(self.factory)).min(TABLE - 1);
            let (raise, lower) = swing(channel, tx_rate);
            let index = if self.average > self.factory {
                raise[delta] as i8
            } else {
                -(lower[delta] as i8)
            };
            if index != self.last {
                self.last = index;
                // rtw8821c_pwrtrack_set.
                let max = phy.profile().rtw88().map_or(0x3f, |s| s.max_power_index);
                let tx_index = tx_index.min(max);
                let (agc, swing) = swing_offset(
                    index,
                    phy.default_ofdm_index(),
                    max - tx_index,
                    -(tx_index as i8),
                );
                set_mask(io, REG_TXAGCIDX, TXAGC_INDEX, u32::from(agc as u8) & 0x3f)?;
                set_mask(io, REG_TXSCALE_A, 0xffe0_0000, TX_SCALE[usize::from(swing)])?;
            }
        }
        if self.average.abs_diff(self.calibrated_at) >= IQK_THRESHOLD {
            self.calibrated_at = self.average;
            return Ok(Tracked::Iqk);
        }
        Ok(Tracked::Nothing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_offset_fits_within_the_txagc_first_and_the_swing_takes_the_rest() {
        // Within the TXAGC's room, the swing stays the channel's.
        assert_eq!(swing_offset(3, 24, 10, -20), (3, 24));
        assert_eq!(swing_offset(-4, 24, 10, -20), (-4, 24));
        // Past it the swing climbs, up to ten over the default.
        assert_eq!(swing_offset(8, 24, 5, -20), (5, 27));
        assert_eq!(swing_offset(12, 24, 0, -20), (0, 34));
        assert_eq!(swing_offset(12, 30, 0, -20), (0, 36), "the table's end");
        // Below the lower room the swing falls, to zero at most.
        assert_eq!(swing_offset(-12, 24, 10, -5), (-5, 17));
        assert_eq!(swing_offset(-12, 3, 10, -5), (-5, 0));
        // rtw88 holds the TXAGC to 15 either way.
        assert_eq!(swing_offset(20, 10, 40, -40), (15, 15));
    }

    #[test]
    fn each_band_tracks_by_its_own_table() {
        assert_eq!(swing(1, 3).0, &RAISE_CCK);
        assert_eq!(swing(1, 4).0, &RAISE_2G);
        assert_eq!(swing(40, 4).1, &LOWER_5G[0]);
        assert_eq!(swing(120, 0).1, &LOWER_5G[1]);
        assert_eq!(swing(157, 0).0, &RAISE_5G[2]);
    }
}
