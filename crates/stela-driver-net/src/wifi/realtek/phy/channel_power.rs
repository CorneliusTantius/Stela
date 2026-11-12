// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2021 Realtek Corporation
//! Calibrated channel/rate gains (`rtw_phy_get_tx_power_index`) and the
//! chip's TXAGC programming. Calculations are observations, not
//! OS/location, antenna or SAR permission.
use super::{Attempt, FactoryBand, FactoryPower, FactorySheet, Io, PhyInitialized, Report};
use crate::wifi::realtek::chip::Txagc;

const SECTIONS: [(u8, u8); 6] = [(0, 4), (4, 8), (12, 8), (20, 8), (44, 10), (54, 10)];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Geometry,
    Rate,
    Factory(super::BoardPowerError),
    Arithmetic,
    GainUnderflow { path: u8, rate: u8 },
    BaseWrap { path: u8, rate: u8 },
    DifferenceEncoding { rate: u8 },
    WrongBoard,
}
impl From<super::BoardPowerError> for Error {
    fn from(e: super::BoardPowerError) -> Self {
        Self::Factory(e)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Width {
    Mhz20,
    Mhz40,
    Mhz80,
}
/// Valid center/primary geometry only. DFS, location, tuning and TX
/// permission must be established independently by the real radio/OS owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    primary: u8,
    centers: [u8; 3],
    width: Width,
    band: FactoryBand,
}
impl Geometry {
    pub fn new(
        primary: u8,
        width: Width,
        center40: Option<u8>,
        center80: Option<u8>,
    ) -> Result<Self, Error> {
        let band = if (1..=14).contains(&primary) {
            FactoryBand::Ghz2
        } else {
            if ![
                36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136,
                140, 144, 149, 153, 157, 161, 165, 169, 173, 177,
            ]
            .contains(&primary)
            {
                return Err(Error::Geometry);
            }
            FactoryBand::Ghz5
        };
        let c40 = match width {
            Width::Mhz20 => {
                if center40.is_some() || center80.is_some() {
                    return Err(Error::Geometry);
                }
                0
            }
            _ => {
                let c = center40.ok_or(Error::Geometry)?;
                if primary.abs_diff(c) != 2
                    || (band == FactoryBand::Ghz2 && (!(3..=11).contains(&c) || primary == 14))
                    || (band == FactoryBand::Ghz5
                        && ![
                            38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175,
                        ]
                        .contains(&c))
                {
                    return Err(Error::Geometry);
                }
                c
            }
        };
        let c80 = if width == Width::Mhz80 {
            let c = center80.ok_or(Error::Geometry)?;
            if band != FactoryBand::Ghz5
                || c40.abs_diff(c) != 4
                || ![42, 58, 106, 122, 138, 155, 171].contains(&c)
            {
                return Err(Error::Geometry);
            }
            c
        } else {
            if center80.is_some() {
                return Err(Error::Geometry);
            }
            0
        };
        Ok(Self {
            primary,
            centers: [primary, c40, c80],
            width,
            band,
        })
    }
    pub fn primary(self) -> u8 {
        self.primary
    }
    pub fn width(self) -> Width {
        self.width
    }
    pub fn centers(self) -> [Option<u8>; 3] {
        self.centers.map(|c| if c == 0 { None } else { Some(c) })
    }
    pub fn band(self) -> FactoryBand {
        self.band
    }
    fn center(self) -> u8 {
        self.centers[self.width as usize]
    }
}
/// Inputs supplied by the platform policy/board service while holding
/// its native then OS permission guards. Public values are useful for diagnostic
/// calculations but cannot grant permission or check a shared applied policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub factory_sheet: FactorySheet,
    /// OS EIRP maximum, in hundredths of dBm.
    pub max_eirp_mbm: i32,
    /// Checked upper bound on antenna gain plus simultaneous-chain combining
    /// per path, in hundredths of dB. No zero/typical antenna default is chosen.
    pub antenna_and_combining_mbm: [i32; 2],
    /// Current source-compatible conducted SAR ceilings in quarter dBm. None
    /// means service determined no additional SAR limit, not unavailable
    /// service. Missing/unknown permission must never reach native application.
    pub sar_quarter_dbm: Option<[i32; 2]>,
    /// Current tracking remnants, in gain steps; zero is valid only for
    /// the real initial tracking state or observed zero compensation.
    pub remnant_cck: i8,
    pub remnant_ofdm: [i8; 2],
}
/// Prepared bounded source register values. No permission, current-channel,
/// applied-power revision, firmware fallback or on-air result is represented.
#[derive(Debug)]
pub struct Plan {
    profile: super::Profile,
    paths: u8,
    rfe: u8,
    nvm: [u8; 168],
    geometry: Geometry,
    limits: Limits,
    gains: [[u8; 84]; 2],
    words: [u32; 12],
}
impl Plan {
    /// Whether the plan was made from `power`'s board.
    pub(super) fn of(&self, power: &FactoryPower) -> bool {
        self.profile == power.profile()
            && self.rfe == power.rfe()
            && &self.nvm == power.raw_gain_calibration()
    }
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    /// Only two-path hardware sections are present; 5 GHz CCK and
    /// unsupported 3/4-stream slots remain absent rather than valid zero gains.
    pub fn gain(&self, path: u8, rate: u8) -> Option<u8> {
        if path >= self.paths
            || rate_section(rate)? >= 6
            || (self.geometry.band == FactoryBand::Ghz5 && rate < 4)
        {
            return None;
        }
        Some(self.gains[path as usize][rate as usize])
    }
}
impl FactoryPower {
    /// Calculate the two-path rate table before any hardware mutation.
    /// Source NVM signed nibbles, section references, factory limits, OS EIRP
    /// and SAR ceilings all participate. This function does not authenticate
    /// its inputs, select a country, tune a channel or grant TX permission.
    pub fn plan_channel_power(&self, geometry: Geometry, limits: Limits) -> Result<Plan, Error> {
        let spec = self.spec();
        let factor = i32::from(spec.txgi_factor);
        let max_gain = i32::from(spec.max_power_index);
        let mut out = Plan {
            profile: self.profile(),
            paths: spec.rf_paths,
            rfe: self.rfe(),
            nvm: *self.raw_gain_calibration(),
            geometry,
            limits,
            gains: [[0; 84]; 2],
            words: [0; 12],
        };
        for path in 0..usize::from(spec.rf_paths) {
            // An index step is a half dB over the chip's factor.
            let eirp = limits
                .max_eirp_mbm
                .checked_sub(limits.antenna_and_combining_mbm[path])
                .ok_or(Error::Arithmetic)?
                .div_euclid(50 / factor);
            let absolute = limits
                .sar_quarter_dbm
                .map_or(eirp, |s| eirp.min(s[path].div_euclid(2 / factor)));
            for (section, &(first, count)) in SECTIONS.iter().enumerate() {
                if geometry.band == FactoryBand::Ghz5 && section == 0 {
                    continue;
                }
                for rate in first..first + count {
                    let base = calibration_base(
                        &self.raw_gain_calibration()[path * 42..path * 42 + 42],
                        geometry,
                        rate,
                        factor,
                    )?;
                    // Source uses u8 at each addition; reject a final base wrap
                    // instead of letting a negative calibration become high.
                    if !(0..=255).contains(&base) {
                        return Err(Error::BaseWrap {
                            path: path as u8,
                            rate,
                        });
                    }
                    let by_rate =
                        i32::from(self.wide_rate_delta(geometry.band, path as u8, rate)?);
                    let max_width = if section <= 1 {
                        0
                    } else if section <= 3 {
                        (geometry.width as u8).min(1)
                    } else {
                        geometry.width as u8
                    };
                    let mut factory = i32::MAX;
                    for width in 0..=max_width {
                        factory = factory.min(i32::from(self.wide_sheet_delta(
                            limits.factory_sheet,
                            geometry.band,
                            width,
                            section as u8,
                            geometry.centers[width as usize],
                        )?));
                    }
                    let reference = i32::from(
                        self.reference(geometry.band, path as u8, section as u8)?
                            .quarter_dbm(),
                    );
                    // High source SAR clamp is conservative. Never narrow or
                    // clamp upward a low ceiling before subtracting reference.
                    let ceiling = absolute
                        .min(max_gain)
                        .checked_sub(reference)
                        .ok_or(Error::Arithmetic)?;
                    let offset = by_rate
                        .min(factory)
                        .min(ceiling)
                        .checked_sub(if spec.dpd_rates && dpd_rate(rate) {
                            6 * factor
                        } else {
                            0
                        })
                        .ok_or(Error::Arithmetic)?;
                    let remnant = if section == 0 {
                        limits.remnant_cck
                    } else {
                        limits.remnant_ofdm[path]
                    };
                    let gain = base
                        .checked_add(offset)
                        .and_then(|v| v.checked_add(i32::from(remnant)))
                        .ok_or(Error::Arithmetic)?;
                    if gain < 0 {
                        return Err(Error::GainUnderflow {
                            path: path as u8,
                            rate,
                        });
                    }
                    out.gains[path][rate as usize] = gain.min(max_gain) as u8;
                }
            }
        }
        if spec.txagc != Txagc::Differential {
            return Ok(out);
        }
        for (i, rate) in (0..28).chain(44..64).step_by(4).enumerate() {
            let mut bytes = [0; 4];
            for (n, b) in bytes.iter_mut().enumerate() {
                let rate = rate + n;
                let reference = if rate < 4 { 3 } else { 19 };
                let a = i16::from(out.gains[0][rate]) - i16::from(out.gains[0][reference]);
                let b_diff = i16::from(out.gains[1][rate]) - i16::from(out.gains[1][reference]);
                let diff = a.min(b_diff);
                if !(-64..=63).contains(&diff) {
                    return Err(Error::DifferenceEncoding { rate: rate as u8 });
                }
                *b = (diff as i8 as u8) & 0x7f;
            }
            out.words[i] = u32::from_le_bytes(bytes);
        }
        Ok(out)
    }
}
/// Source register stores completed under the caller's held permission
/// and same owner; this is not operational radio or shared TX admission proof.
#[derive(Debug)]
pub struct Programmed {
    phy: PhyInitialized,
    plan: Plan,
}
impl Programmed {
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn phy(&self) -> &PhyInitialized {
        &self.phy
    }
    /// Consume this source power result for a later channel/permission
    /// update. Old shared admissions and queued TX must be retired separately.
    pub fn into_phy(self) -> PhyInitialized {
        self.phy
    }
}
impl PhyInitialized {
    /// Apply source TX power references and all twelve packed two-path TXAGC
    /// words. A complete plan is checked before any register access.
    ///
    /// # Safety
    /// Same kept native requester/reset/firmware/board epoch as
    /// self, Io, Report and Plan, not matching fingerprints alone. Hold
    /// native control permission followed by OS/location/SAR permission
    /// for this exact geometry and Limits through the complete batch; no
    /// reverse-order waits. Limits must include checked antenna/chain gain,
    /// current SAR and real tracking remnants, and the OS-selected factory
    /// sheet. Missing policy/board knowledge must deny this call. Quiesce TX
    /// and all competing reset/IRQ/PHY/power workers and invalidate the old
    /// applied policy first; stop/enforce/drain queued air work before
    /// changing power. All earlier PHY/MAC/HCI prerequisites remain valid.
    ///
    /// This does not tune/observe the radio channel, run required IQK/DPK or
    /// EDCCA jurisdiction programming, constrain firmware retry/fallback, prove
    /// MMIO register readback, mint an applied policy revision or admit TX.
    /// The real owner must check those effects before existing shared
    /// regulatory::Owner can permit a matching operation. Errors/unwind keep
    /// the real quarantined owner and all DMA/pins; masking is not stop proof.
    pub unsafe fn program_channel_power<I: Io>(
        self,
        io: &mut I,
        report: &Report,
        plan: Plan,
    ) -> Result<Programmed, super::Error> {
        let p = self.factory_power();
        if p.profile() != io.profile()
            || p.profile() != report.profile()
            || plan.profile != p.profile()
            || plan.rfe != p.rfe()
            || &plan.nvm != p.raw_gain_calibration()
        {
            return Err(super::Error::ChannelPower(Error::WrongBoard));
        }
        let cap = report.capabilities();
        if cap.rf_phys != 2 || cap.rf_paths != 2 || cap.antenna_tx != 3 || cap.antenna_rx != 3 {
            return Err(super::Error::UnsupportedRfLayout);
        }
        let mut a = Attempt {
            io,
            profile: plan.profile,
            done: false,
        };
        a.domain()?;
        program_registers(&mut a, &plan)?;
        a.domain()?;
        a.done = true;
        Ok(Programmed { phy: self, plan })
    }
}
pub(super) fn program_registers<I: Io>(
    a: &mut Attempt<'_, I>,
    plan: &Plan,
) -> Result<(), super::Error> {
    for (reference, regs, mask) in [
        (3, [0x18a0, 0x41a0], 0x7f0000),
        (19, [0x18e8, 0x41e8], 0x1fc00),
    ] {
        for (path, reg) in regs.into_iter().enumerate() {
            a.modify32(0x1c90, 1 << 15, 0)?;
            a.modify32(reg, mask, u32::from(plan.gains[path][reference]))?;
        }
    }
    for (rate, word) in (0..28).chain(44..64).step_by(4).zip(plan.words) {
        a.modify32(0x1c90, 1 << 15, 0)?;
        a.modify32(0x3a00 + rate, u32::MAX, word)?;
    }
    Ok(())
}
/// `rtw8821c_set_tx_power_index`: path by path, the CCK, OFDM, HT 1SS and
/// VHT 1SS indices, four rates a word at the path's base plus the first
/// rate's index, VHT 1SS MCS9's word holding MCS8 and MCS9 alone.
pub(super) fn program_absolute<I: Io>(
    a: &mut Attempt<'_, I>,
    plan: &Plan,
    base: [u32; 2],
) -> Result<(), super::Error> {
    for (path, base) in base.into_iter().enumerate().take(usize::from(plan.paths)) {
        for (first, count) in [(0u8, 4u8), (4, 8), (12, 8), (44, 10)] {
            let mut word = 0;
            for rate in first..first + count {
                let shift = rate & 3;
                word |= u32::from(plan.gains[path][usize::from(rate)]) << (shift * 8);
                if shift == 3 || rate == 53 {
                    a.io.write32(base + u32::from(rate & 0xfc), word)?;
                    word = 0;
                }
            }
        }
    }
    Ok(())
}
pub(super) fn rate_section(rate: u8) -> Option<u8> {
    Some(match rate {
        0..=3 => 0,
        4..=11 => 1,
        12..=19 => 2,
        20..=27 => 3,
        28..=35 => 6,
        36..=43 => 7,
        44..=53 => 4,
        54..=63 => 5,
        64..=73 => 8,
        74..=83 => 9,
        _ => return None,
    })
}
fn dpd_rate(rate: u8) -> bool {
    matches!(rate, 4 | 5 | 12 | 13 | 20 | 21 | 44 | 45 | 54 | 55)
}
fn nibble(v: u8, high: bool) -> i32 {
    let v = if high { v >> 4 } else { v & 15 };
    if v & 8 != 0 {
        i32::from(v) - 16
    } else {
        i32::from(v)
    }
}
fn group(ch: u8, cck: bool) -> Result<usize, Error> {
    Ok(match ch {
        1 | 2 | 36 | 38 | 40 | 42 => 0,
        3..=5 | 44 | 46 | 48 | 50 => 1,
        6..=8 | 52 | 54 | 56 | 58 => 2,
        9..=11 | 60 | 62 | 64 => 3,
        12 | 13 | 100 | 102 | 104 | 106 => 4,
        14 => {
            if cck {
                5
            } else {
                4
            }
        }
        108 | 110 | 112 | 114 => 5,
        116 | 118 | 120 | 122 => 6,
        124 | 126 | 128 | 130 => 7,
        132 | 134 | 136 | 138 => 8,
        140 | 142 | 144 => 9,
        149 | 151 | 153 | 155 => 10,
        157 | 159 | 161 => 11,
        165 | 167 | 169 | 171 => 12,
        173 | 175 | 177 => 13,
        _ => return Err(Error::Geometry),
    })
}
/// The efuse index of `rate` on `g`, its differences in steps of `factor`.
fn calibration_base(nvm: &[u8], g: Geometry, rate: u8, factor: i32) -> Result<i32, Error> {
    let section = rate_section(rate).ok_or(Error::Rate)?;
    let group = group(g.center(), rate < 4)?;
    let streams = match section {
        3 | 5 => 2,
        6 | 8 => 3,
        7 | 9 => 4,
        _ => 1,
    };
    let mcs = section >= 2;
    let mut gain;
    if g.band == FactoryBand::Ghz2 {
        gain = i32::from(nvm[if rate < 4 { group } else { 6 + group }]);
        if section == 1 {
            gain += nibble(nvm[11], false) * factor;
        }
        if mcs {
            if g.width == Width::Mhz20 {
                gain += nibble(nvm[11], true) * factor;
            }
            for s in 2..=streams {
                gain += nibble(nvm[12 + (s - 2) * 2], g.width == Width::Mhz40) * factor;
            }
        }
    } else {
        let n = &nvm[18..];
        gain = i32::from(n[group]);
        if !mcs {
            gain += nibble(n[14], false) * factor;
        } else {
            match g.width {
                Width::Mhz20 => {
                    gain += nibble(n[14], true) * factor;
                    for s in 2..=streams {
                        gain += nibble(n[13 + s], false) * factor;
                    }
                }
                Width::Mhz40 => {
                    for s in 2..=streams {
                        gain += nibble(n[13 + s], true) * factor;
                    }
                }
                Width::Mhz80 => {
                    gain = (i32::from(n[group])
                        + i32::from(*n.get(group + 1).ok_or(Error::Geometry)?))
                        / 2;
                    for s in 1..=streams {
                        gain += nibble(n[19 + s], true) * factor;
                    }
                }
            }
        }
    }
    Ok(gain)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    fn limits() -> Limits {
        Limits {
            factory_sheet: FactorySheet::Fcc,
            max_eirp_mbm: 2500,
            antenna_and_combining_mbm: [100, 125],
            sar_quarter_dbm: Some([90, 89]),
            remnant_cck: 0,
            remnant_ofdm: [0; 2],
        }
    }
    fn nvm(seed: u8) -> [u8; 168] {
        core::array::from_fn(|i| {
            let p = i / 42;
            let j = i % 42;
            if (11..18).contains(&j) || (32..42).contains(&j) {
                0x11
            } else {
                ((usize::from(seed) * 7 + p * 3 + j * 5) % 6 + 62) as u8
            }
        })
    }
    #[test]
    fn channel_geometry_rejects_invalid_centers_bands_and_partial_widths() {
        assert!(Geometry::new(14, Width::Mhz20, None, None).is_ok());
        assert!(Geometry::new(36, Width::Mhz80, Some(38), Some(42)).is_ok());
        assert!(Geometry::new(177, Width::Mhz80, Some(175), Some(171)).is_ok());
        for (p, w, a, b) in [
            (0, Width::Mhz20, None, None),
            (37, Width::Mhz20, None, None),
            (14, Width::Mhz40, Some(12), None),
            (1, Width::Mhz80, Some(3), Some(7)),
            (36, Width::Mhz40, None, None),
            (36, Width::Mhz20, Some(38), None),
            (36, Width::Mhz40, Some(42), None),
            (36, Width::Mhz80, Some(38), Some(58)),
            (177, Width::Mhz80, Some(175), Some(179)),
        ] {
            assert!(Geometry::new(p, w, a, b).is_err());
        }
        for rate in 0..84 {
            assert!(rate_section(rate).is_some());
        }
        assert!(rate_section(84).is_none());
    }
    #[test]
    fn os_eirp_antenna_sar_and_low_ceiling_arithmetic_never_wraps_up() {
        let p = super::super::board_power::channel_fixture(0, nvm(0));
        let g = Geometry::new(1, Width::Mhz20, None, None).unwrap();
        let a = p.plan_channel_power(g, limits()).unwrap();
        assert_eq!(a.geometry(), g);
        assert_eq!(a.limits(), limits());
        assert!(a.gain(0, 0).is_some());
        assert_eq!(a.gain(2, 0), None);
        assert_eq!(a.gain(0, 28), None);
        let mut low = limits();
        low.max_eirp_mbm = 1000;
        low.sar_quarter_dbm = None;
        let b = p.plan_channel_power(g, low).unwrap();
        assert!(b.gain(0, 0).unwrap() < a.gain(0, 0).unwrap());
        low.sar_quarter_dbm = Some([-128, -128]);
        assert!(matches!(
            p.plan_channel_power(g, low),
            Err(Error::GainUnderflow { .. })
        ));
        low.sar_quarter_dbm = Some([i32::MIN, i32::MIN]);
        assert_eq!(p.plan_channel_power(g, low).unwrap_err(), Error::Arithmetic);
        low = limits();
        low.max_eirp_mbm = i32::MIN;
        low.antenna_and_combining_mbm = [1; 2];
        assert_eq!(p.plan_channel_power(g, low).unwrap_err(), Error::Arithmetic);
        // Factory normalization is also reconstructed before narrowing. The
        // raw source diagnostic remains byte-compatible; live low deltas stay
        // negative even where the source's normalized byte becomes positive.
        assert_eq!(p.wide_rate_delta(FactoryBand::Ghz2, 0, 0).unwrap(), 12);
        assert_eq!(
            p.wide_sheet_delta(FactorySheet::Fcc, FactoryBand::Ghz2, 0, 0, 1)
                .unwrap(),
            0
        );
        let blank = super::super::board_power::channel_fixture(0, [255; 168]);
        // Blank calibration is held, never invented zero data.
        assert_eq!(blank.raw_gain_calibration(), &[255; 168]);
        assert!(blank.plan_channel_power(g, limits()).is_ok());
        // Negative nibble with zero base causes the source u8 base to
        // wrap. Reject before all later offsets/register preparation.
        let mut broken = [255; 168];
        broken[..11].fill(0);
        let blank = super::super::board_power::channel_fixture(0, broken);
        assert!(matches!(
            blank.plan_channel_power(g, limits()),
            Err(Error::BaseWrap { .. }) | Err(Error::GainUnderflow { .. })
        ));
    }
    #[test]
    fn native_plan_rejects_unrepresentable_seven_bit_shared_rate_difference() {
        let mut raw = nvm(0);
        for path in 0..2 {
            raw[path * 42 + 18] = 32;
            raw[path * 42 + 19] = 254;
        }
        let p = super::super::board_power::channel_fixture(0, raw);
        let g = Geometry::new(36, Width::Mhz80, Some(38), Some(42)).unwrap();
        let mut l = limits();
        l.max_eirp_mbm = 5000;
        l.sar_quarter_dbm = None;
        assert!(matches!(
            p.plan_channel_power(g, l),
            Err(Error::DifferenceEncoding { .. })
        ));
        l.sar_quarter_dbm = Some([i32::MIN + 95; 2]);
        assert!(p.plan_channel_power(g, l).is_err());
    }
    #[test]
    #[ignore = "oracle: STELA_REALTEK_WIFI_CHANNEL_POWER_ORACLE"]
    fn packed_nvm_all_rate_width_samples_and_real_signed_wrap_negatives_match_source() {
        let bytes =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_CHANNEL_POWER_ORACLE").unwrap())
                .unwrap();
        let mut offset = 0;
        for _ in 0..512 {
            let e =
                u32::from_le_bytes(bytes[offset + 28..offset + 32].try_into().unwrap()) as usize;
            let b =
                u32::from_le_bytes(bytes[offset + 32..offset + 36].try_into().unwrap()) as usize;
            offset += 36 + 168 + 336 + e * 16 + b;
        }
        for c in 0..65536usize {
            let n: [u8; 42] = core::array::from_fn(|i| (c * 17 + i * 29 + (c >> 8)) as u8);
            let rate = (c % 84) as u8;
            let bw = c % 3;
            let two = c & 1 != 0;
            let ch = if two {
                if bw != 0 { 6 } else { 14 }
            } else if bw == 2 {
                42
            } else {
                36
            };
            let width = if two && bw == 2 {
                Width::Mhz20
            } else {
                match bw {
                    0 => Width::Mhz20,
                    1 => Width::Mhz40,
                    _ => Width::Mhz80,
                }
            };
            // Private raw source-helper input, not operational
            // geometry: the oracle also probes invalid CCK/5GHz combinations.
            let g = Geometry {
                primary: ch,
                centers: [ch; 3],
                width,
                band: if two {
                    FactoryBand::Ghz2
                } else {
                    FactoryBand::Ghz5
                },
            };
            assert_eq!(
                calibration_base(&n, g, rate, 2).unwrap() as u8,
                bytes[offset],
                "packed {c}"
            );
            offset += 1;
        }
        let mut positive_low_wrap = 0;
        let mut max_gain_wrap = 0;
        for cap in -256..=127i32 {
            let delta = bytes[offset] as i8;
            let gain = bytes[offset + 1];
            offset += 2;
            let mathematical = cap.clamp(-128, 127) - 72;
            assert_eq!(delta, mathematical as i8);
            if cap < -64 && delta > 0 {
                positive_low_wrap += 1;
            }
            if cap < 0 && gain == 127 {
                max_gain_wrap += 1;
            }
        }
        assert!(positive_low_wrap > 100);
        assert!(max_gain_wrap > 0);
        assert_eq!(offset, bytes.len());
    }
}
