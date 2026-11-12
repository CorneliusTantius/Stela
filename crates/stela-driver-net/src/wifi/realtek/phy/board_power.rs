// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Same-board factory power references, by-rate deltas and all factory sheets.
//! No source sheet, fallback/default lookup seed or raw OTP selects OS country,
//! radio channel or regulatory/EIRP/TX permission.
mod data;
mod data_8821c;
use super::{Board, Profile};
use crate::wifi::realtek::{chip::Rtw88, identity::Chip};
use alloc::vec::Vec;
const CHANNELS_5G: [u8; 49] = [
    36, 38, 40, 42, 44, 46, 48, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 116,
    118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159,
    161, 165, 167, 169, 171, 173, 175, 177,
];
const GROUPS: [(usize, usize); 10] = [
    (0, 4),
    (4, 8),
    (12, 8),
    (20, 8),
    (44, 10),
    (54, 10),
    (28, 8),
    (36, 8),
    (64, 10),
    (74, 10),
];
const ALTERNATIVE: [Option<usize>; 13] = [
    None,
    None,
    None,
    Some(0),
    Some(2),
    Some(2),
    Some(0),
    Some(2),
    Some(0),
    Some(2),
    Some(2),
    Some(2),
    None,
];
const COUNT: [usize; 2] = [14, 49];
const WORLD: usize = 12;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Allocation,
    UnsupportedRfe(u8),
    InvalidTable,
    InvalidIndex,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactoryBand {
    Ghz2,
    Ghz5,
}
impl FactoryBand {
    fn index(self) -> usize {
        match self {
            Self::Ghz2 => 0,
            Self::Ghz5 => 1,
        }
    }
}
/// Numeric sheet codes are source factory-table categories, not current OS
/// country selections or regulatory credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FactorySheet {
    Fcc = 0,
    Mkk = 1,
    Etsi = 2,
    Ic = 3,
    Kcc = 4,
    Acma = 5,
    Chile = 6,
    Ukraine = 7,
    Mexico = 8,
    Cn = 9,
    Qatar = 10,
    Uk = 11,
    WorldMinimum = 12,
}
impl TryFrom<u8> for FactorySheet {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self, Error> {
        Ok(match v {
            0 => Self::Fcc,
            1 => Self::Mkk,
            2 => Self::Etsi,
            3 => Self::Ic,
            4 => Self::Kcc,
            5 => Self::Acma,
            6 => Self::Chile,
            7 => Self::Ukraine,
            8 => Self::Mexico,
            9 => Self::Cn,
            10 => Self::Qatar,
            11 => Self::Uk,
            12 => Self::WorldMinimum,
            _ => return Err(Error::InvalidIndex),
        })
    }
}
/// Source PG absolute reference in quarter dBm for RTL8822C (txgi exponent 2).
/// This reference is distinct from the calibrated raw NVM hardware gain code,
/// measured radiated EIRP and a trusted OS maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuarterDbmReference(i16);
impl QuarterDbmReference {
    pub fn quarter_dbm(self) -> i16 {
        self.0
    }
}
/// Signed gain-step offset relative to a source PG reference, never standalone
/// absolute radiated power or permission to transmit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GainDelta(i16);
impl GainDelta {
    pub fn steps(self) -> i16 {
        self.0
    }
}
/// Privately prepared source board setup, carried through the initial
/// PHY states. Tables have all source factory sheets, not a chosen country.
/// No hardware programming or current per-channel TX validation occurs here.
pub struct FactoryPower {
    profile: Profile,
    rfe: u8,
    nvm: [u8; 168],
    by_rate: [[[i8; 84]; 4]; 2],
    bases: [[[i8; 10]; 4]; 2],
    limits: [Vec<i8>; 2],
    source_center_seed: [u8; 3],
}
impl core::fmt::Debug for FactoryPower {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FactoryPower")
            .field("profile", &self.profile)
            .field("rfe", &self.rfe)
            .field("limit_sheet_type", &self.limit_sheet_type())
            .finish_non_exhaustive()
    }
}
impl FactoryPower {
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn rfe(&self) -> u8 {
        self.rfe
    }
    pub fn limit_sheet_type(&self) -> u8 {
        if self.rfe == 5 { 5 } else { 0 }
    }
    /// Immutable logical board bytes, four 42-byte path records.
    pub fn raw_gain_calibration(&self) -> &[u8; 168] {
        &self.nvm
    }
    /// Source software lookup initialization only; not an observed/set radio
    /// channel. Wider-width centers remain explicitly absent until configured.
    pub fn source_lookup_seed(&self) -> [Option<u8>; 3] {
        self.source_center_seed
            .map(|v| if v == 0 { None } else { Some(v) })
    }
    pub fn reference(
        &self,
        band: FactoryBand,
        path: u8,
        section: u8,
    ) -> Result<QuarterDbmReference, Error> {
        if path >= 4 || section >= 10 {
            return Err(Error::InvalidIndex);
        }
        Ok(QuarterDbmReference(i16::from(
            self.bases[band.index()][path as usize][section as usize],
        )))
    }
    pub fn rate_delta(&self, band: FactoryBand, path: u8, rate: u8) -> Result<GainDelta, Error> {
        if path >= 4 || rate >= 84 {
            return Err(Error::InvalidIndex);
        }
        Ok(GainDelta(i16::from(
            self.by_rate[band.index()][path as usize][rate as usize],
        )))
    }
    /// Factory-sheet delta relative to the source path-A section reference,
    /// as the source board setup normalizes it. This does not select a sheet
    /// for operation or enforce OS/location EIRP constraints.
    pub fn sheet_delta(
        &self,
        sheet: FactorySheet,
        band: FactoryBand,
        width: u8,
        section: u8,
        channel: u8,
    ) -> Result<GainDelta, Error> {
        let band = band.index();
        let ch = channel_index(band, channel).ok_or(Error::InvalidIndex)?;
        if width >= 3 || section >= 10 {
            return Err(Error::InvalidIndex);
        }
        Ok(GainDelta(i16::from(
            self.limits[band][index(band, sheet as usize, width as usize, section as usize, ch)],
        )))
    }
    // Recover the original signed source datum before its byte-width
    // normalization. This is bijective over the original i8 domain. Live
    // validation then subtracts in wide arithmetic, never using a wrapped
    // positive delta as a low absolute ceiling.
    pub(super) fn wide_rate_delta(
        &self,
        band: FactoryBand,
        path: u8,
        rate: u8,
    ) -> Result<i16, Error> {
        let section = super::channel_power::rate_section(rate).ok_or(Error::InvalidIndex)?;
        let base = self.reference(band, path, section)?.quarter_dbm();
        let raw = (self.rate_delta(band, path, rate)?.steps() + base) as u8 as i8;
        Ok(i16::from(raw) - base)
    }
    pub(super) fn wide_sheet_delta(
        &self,
        sheet: FactorySheet,
        band: FactoryBand,
        width: u8,
        section: u8,
        channel: u8,
    ) -> Result<i16, Error> {
        let base = self.reference(band, 0, section)?.quarter_dbm();
        let raw = (self
            .sheet_delta(sheet, band, width, section, channel)?
            .steps()
            + base) as u8 as i8;
        Ok(i16::from(raw) - base)
    }
    pub(super) fn prepare(board: &Board) -> Result<Self, Error> {
        let rfe = board.raw().rfe_raw;
        let profile = board.profile();
        let spec = profile.rtw88().ok_or(Error::UnsupportedRfe(rfe))?;
        if !spec.rfe_options.contains(&rfe) {
            return Err(Error::UnsupportedRfe(rfe));
        }
        // The chip's `rfe_defs`: its PG table and the RFE's limit table.
        let (pg, limits) = match profile.chip() {
            Chip::Rtl8821C => (data_8821c::PG, data_8821c::LIMIT0),
            _ if rfe == 5 => (data::PG, data::LIMIT5),
            _ => (data::PG, data::LIMIT0),
        };
        Self::from_tables(board, rfe, pg, limits)
    }
    /// The chip facts the tables are read with.
    pub(super) fn spec(&self) -> &'static Rtw88 {
        self.profile.rtw88().expect("prepared for an rtw88 chip")
    }
    /// `max_power_index`.
    pub fn max_index(&self) -> u8 {
        self.spec().max_power_index
    }
    fn from_tables(
        board: &Board,
        rfe: u8,
        pg: &[[u32; 6]],
        limits: &[[i16; 6]],
    ) -> Result<Self, Error> {
        // Entire immutable table stream is structurally checked before heap
        // allocation or any caller's later table-driven hardware programming.
        for &[band, path, _tx, address, mask, _value] in pg {
            if band > 1 || path >= 4 || mask != u32::MAX || pg_first_rate(address).is_none() {
                return Err(Error::InvalidTable);
            }
        }
        for &[sheet, band, width, section, channel, value] in limits {
            if !(0..13).contains(&sheet)
                || !(0..2).contains(&band)
                || !(0..3).contains(&width)
                || !(0..10).contains(&section)
                || !(0..=255).contains(&channel)
                || !(-128..=127).contains(&value)
                || channel_index(band as usize, channel as u8).is_none()
            {
                return Err(Error::InvalidTable);
            }
        }
        let spec = board.profile().rtw88().ok_or(Error::InvalidTable)?;
        let max = spec.max_power_index as i8;
        let mut out = Self {
            profile: board.profile(),
            rfe,
            nvm: board.raw().power_tables,
            by_rate: [[[0; 84]; 4]; 2],
            bases: [[[0; 10]; 4]; 2],
            limits: [Vec::new(), Vec::new()],
            source_center_seed: [0; 3],
        };
        for (band, limit) in out.limits.iter_mut().enumerate() {
            let len = 13 * 3 * 10 * COUNT[band];
            limit
                .try_reserve_exact(len)
                .map_err(|_| Error::Allocation)?;
            limit.resize(len, max);
        }
        for &[band, path, _tx, address, _mask, value] in pg {
            let first = pg_first_rate(address).ok_or(Error::InvalidTable)?;
            for i in 0..4 {
                let byte = (value >> (i * 8)) as u8;
                // tbl_to_dec_pwr_by_rate.
                let byte = if spec.power_by_rate_bcd {
                    (byte >> 4) * 10 + (byte & 15)
                } else {
                    byte
                };
                out.by_rate[band as usize][path as usize][first + i] = byte as i8;
            }
        }
        let mut present = 0u16;
        for &[sheet, band, width, section, channel, value] in limits {
            let (sheet, band, width, section) = (
                sheet as usize,
                band as usize,
                width as usize,
                section as usize,
            );
            present |= 1 << sheet;
            let ch = channel_index(band, channel as u8).ok_or(Error::InvalidTable)?;
            let value = (value as i8).clamp(-max, max);
            out.limits[band][index(band, sheet, width, section, ch)] = value;
            let world = index(band, WORLD, width, section, ch);
            out.limits[band][world] = out.limits[band][world].min(value);
        }
        for (sheet, &alternate) in ALTERNATIVE.iter().enumerate() {
            if sheet == WORLD || present & (1 << sheet) != 0 {
                continue;
            }
            let from = alternate
                .filter(|&a| present & (1 << a) != 0)
                .unwrap_or(WORLD);
            for (band, limit) in out.limits.iter_mut().enumerate() {
                let size = 3 * 10 * COUNT[band];
                limit.copy_within(from * size..(from + 1) * size, sheet * size);
            }
        }
        for sheet in 0..13 {
            for width in 0..2 {
                for ch in 0..49 {
                    for (ht, vht) in [(2, 4), (3, 5), (6, 8), (7, 9)] {
                        let h = index(1, sheet, width, ht, ch);
                        let v = index(1, sheet, width, vht, ch);
                        let (hv, vv) = (out.limits[1][h], out.limits[1][v]);
                        if hv != vv {
                            if hv == max {
                                out.limits[1][h] = vv;
                            } else if vv == max {
                                out.limits[1][v] = hv;
                            }
                        }
                    }
                }
            }
        }
        for band in 0..2 {
            for path in 0..4 {
                for (section, &(first, size)) in GROUPS.iter().enumerate() {
                    let base_idx = first + if size == 10 { size - 3 } else { size - 1 };
                    let base = out.by_rate[band][path][base_idx];
                    out.bases[band][path][section] = base;
                    for value in &mut out.by_rate[band][path][first..first + size] {
                        *value = value.wrapping_sub(base);
                    }
                }
            }
        }
        // Source normalizes every factory sheet by path-A's reference; this
        // includes unassigned max-index cells and never selects a live region.
        for (band, limit) in out.limits.iter_mut().enumerate() {
            for sheet in 0..13 {
                for width in 0..3 {
                    for section in 0..10 {
                        let base = out.bases[band][0][section];
                        let first = index(band, sheet, width, section, 0);
                        for value in &mut limit[first..first + COUNT[band]] {
                            *value = value.wrapping_sub(base);
                        }
                    }
                }
            }
        }
        out.source_center_seed[0] = 1;
        Ok(out)
    }
}
fn pg_first_rate(address: u32) -> Option<usize> {
    Some(match address {
        0xc20 | 0xe20 => 0,
        0xc24 | 0xe24 => 4,
        0xc28 | 0xe28 => 8,
        0xc2c | 0xe2c => 12,
        0xc30 | 0xe30 => 16,
        0xc34 | 0xe34 => 20,
        0xc38 | 0xe38 => 24,
        0xc3c | 0xe3c => 44,
        0xc40 | 0xe40 => 48,
        0xc44 | 0xe44 => 52,
        0xc48 | 0xe48 => 56,
        0xc4c | 0xe4c => 60,
        _ => return None,
    })
}
fn channel_index(band: usize, channel: u8) -> Option<usize> {
    match band {
        0 if (1..=14).contains(&channel) => Some((channel - 1) as usize),
        1 => CHANNELS_5G.iter().position(|&c| c == channel),
        _ => None,
    }
}
fn index(band: usize, sheet: usize, width: usize, section: usize, channel: usize) -> usize {
    ((sheet * 3 + width) * 10 + section) * COUNT[band] + channel
}

#[cfg(test)]
pub(super) fn channel_fixture(rfe: u8, nvm: [u8; 168]) -> FactoryPower {
    let mut p = FactoryPower::prepare(&super::tests::power_board_fixture(rfe)).unwrap();
    p.nvm = nvm;
    p
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    fn board(rfe: u8) -> Board {
        super::super::tests::power_board_fixture(rfe)
    }
    fn dump(p: &FactoryPower) -> Vec<u8> {
        let mut out = Vec::new();
        for band in &p.by_rate {
            for path in band {
                out.extend(path.iter().map(|&v| v as u8));
            }
        }
        for band in &p.bases {
            for path in band {
                out.extend(path.iter().map(|&v| v as u8));
            }
        }
        for limits in &p.limits {
            out.extend(limits.iter().map(|&v| v as u8));
        }
        out.extend(p.source_center_seed);
        assert_eq!(out.len(), 25325);
        out
    }
    #[test]
    fn factory_power_preserves_source_units_raw_calibration_and_checked_lookup_domains() {
        let b = board(0);
        let p = FactoryPower::prepare(&b).unwrap();
        assert_eq!(p.profile(), b.profile());
        assert_eq!(p.rfe(), 0);
        assert_eq!(p.limit_sheet_type(), 0);
        assert_eq!(p.raw_gain_calibration(), &b.raw().power_tables);
        assert_eq!(p.source_lookup_seed(), [Some(1), None, None]);
        assert_eq!(
            p.reference(FactoryBand::Ghz2, 0, 0).unwrap().quarter_dbm(),
            72
        );
        assert_eq!(p.rate_delta(FactoryBand::Ghz2, 0, 0).unwrap().steps(), 12);
        assert_eq!(
            p.sheet_delta(FactorySheet::Fcc, FactoryBand::Ghz2, 0, 0, 1)
                .unwrap()
                .steps(),
            0
        );
        assert_eq!(
            p.sheet_delta(FactorySheet::WorldMinimum, FactoryBand::Ghz2, 0, 0, 1)
                .unwrap()
                .steps(),
            -12
        );
        assert!(p.reference(FactoryBand::Ghz2, 4, 0).is_err());
        assert!(p.reference(FactoryBand::Ghz2, 0, 10).is_err());
        assert!(p.rate_delta(FactoryBand::Ghz2, 0, 84).is_err());
        for (band, ch) in [
            (FactoryBand::Ghz2, 0),
            (FactoryBand::Ghz2, 15),
            (FactoryBand::Ghz5, 0),
            (FactoryBand::Ghz5, 37),
            (FactoryBand::Ghz5, 255),
        ] {
            assert!(p.sheet_delta(FactorySheet::Fcc, band, 0, 0, ch).is_err());
        }
        assert!(
            p.sheet_delta(FactorySheet::Fcc, FactoryBand::Ghz2, 3, 0, 1)
                .is_err()
        );
        assert!(
            p.sheet_delta(FactorySheet::Fcc, FactoryBand::Ghz2, 0, 10, 1)
                .is_err()
        );
        assert!(FactorySheet::try_from(13).is_err());
        assert_eq!(
            FactoryPower::prepare(&board(5)).unwrap().limit_sheet_type(),
            5
        );
        assert!(matches!(
            FactoryPower::prepare(&board(7)),
            Err(Error::UnsupportedRfe(7))
        ));
    }
    #[test]
    fn live_factory_deltas_reconstruct_signed_low_ceilings_before_normalization_wrap() {
        for raw in [-128i16, -127, -100, -1, 0, 127] {
            let p =
                FactoryPower::from_tables(&board(0), 0, data::PG, &[[0, 0, 0, 0, 1, raw]]).unwrap();
            let wide = raw.max(-127) - 72;
            assert_eq!(
                p.wide_sheet_delta(FactorySheet::Fcc, FactoryBand::Ghz2, 0, 0, 1)
                    .unwrap(),
                wide
            );
            assert_eq!(
                p.sheet_delta(FactorySheet::Fcc, FactoryBand::Ghz2, 0, 0, 1)
                    .unwrap()
                    .steps(),
                i16::from(wide as i8)
            );
        }
    }
    #[test]
    fn malformed_factory_rows_are_rejected_before_data_publication() {
        let b = board(0);
        for row in [
            [2, 0, 0, 0xc20, u32::MAX, 0],
            [0, 4, 0, 0xc20, u32::MAX, 0],
            [0, 0, 0, 0xc20, 0, 0],
            [0, 0, 0, 0xc21, u32::MAX, 0],
        ] {
            assert!(matches!(
                FactoryPower::from_tables(&b, 0, &[row], &[]),
                Err(Error::InvalidTable)
            ));
        }
        for row in [
            [13, 0, 0, 0, 1, 0],
            [0, 2, 0, 0, 1, 0],
            [0, 0, 3, 0, 1, 0],
            [0, 0, 0, 10, 1, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 37, 0],
            [0, 0, 0, 0, 1, 128],
            [0, 0, 0, 0, 1, -129],
        ] {
            assert!(matches!(
                FactoryPower::from_tables(&b, 0, &[], &[row]),
                Err(Error::InvalidTable)
            ));
        }
    }
    #[test]
    #[ignore = "oracle: STELA_REALTEK_WIFI_BOARD_POWER_ORACLE"]
    fn whole_factory_and_sparse_source_tables_match_every_prepared_byte() {
        let path = std::path::PathBuf::from(
            std::env::var("STELA_REALTEK_WIFI_BOARD_POWER_ORACLE").unwrap(),
        );
        let trace = std::fs::read(&path).unwrap();
        assert_eq!(
            std::fs::read(path.parent().unwrap().join("data.rs")).unwrap(),
            include_bytes!("board_power/data.rs")
        );
        let mut offset = 0;
        for rfe in 0..7 {
            let head: [u32; 4] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 16;
            assert_eq!(head, [rfe, 46, if rfe == 5 { 1365 } else { 2340 }, 0]);
            let p = FactoryPower::prepare(&board(rfe as u8)).unwrap();
            let actual = dump(&p);
            assert_eq!(&actual, &trace[offset..offset + actual.len()], "RFE {rfe}");
            offset += actual.len();
        }
        for c in 0..64 {
            let head: [u32; 4] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 16;
            assert_eq!(head, [c, 2, 3, 0]);
            let pg = [
                [0, 0, 0, 0xc20, u32::MAX, 0x484c5054],
                [0, 0, 0, 0xc24, u32::MAX, 0x54585858],
            ];
            let limits = [
                [0, 0, 0, 0, 1, c as i16 - 32],
                [2, 1, 1, 2, 36, 64 - c as i16],
                [0, 0, 0, 0, 1, c as i16 - 16],
            ];
            let p = FactoryPower::from_tables(&board(0), 0, &pg, &limits).unwrap();
            let actual = dump(&p);
            assert_eq!(
                &actual,
                &trace[offset..offset + actual.len()],
                "sparse case {c}"
            );
            offset += actual.len();
        }
        assert_eq!(offset, trace.len());
    }
}
