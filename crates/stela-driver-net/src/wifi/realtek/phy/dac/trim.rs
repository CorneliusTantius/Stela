// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Source RF X2 and factory OTP trim effects.
mod tail;
use super::super::super::efuse::Physical;
use super::{Attempt, DacCalibrated, Error, Io, Path, Report, sleep};
pub use tail::{PhyInitialized, ThermalTracking};

const POWER_2G: [usize; 3] = [0x1d4, 0x1ee, 0x1d2];
const POWER_5G: [[usize; 5]; 2] = [
    [0x1ec, 0x1e8, 0x1e4, 0x1e0, 0x1dc],
    [0x1eb, 0x1e7, 0x1e3, 0x1df, 0x1db],
];
/// Source factory bytes; 0xff is successfully read blank OTP here,
/// never substituted for a transport timeout. These are not TX policy values.
#[derive(Debug)]
pub struct FactoryBytes {
    pub thermal: [u8; 2],
    pub power_2g: [u8; 3],
    pub power_5g: [[u8; 5]; 2],
    /// Per path, [2 GHz, 5 GHz].
    pub pa: [[u8; 2]; 2],
}
/// Completed source factory initialization effects, including source-defined
/// optional/blank behavior. No analog lock, calibrated channel, power policy or
/// TX permission is implied by stores/delays or a nonbusy X2 observation.
#[derive(Debug)]
pub struct FactoryInitialized {
    calibration: DacCalibrated,
    raw: FactoryBytes,
    thermal_reference: u8,
    x2_busy_observed: bool,
    thermal_written: [Option<u8>; 2],
    power_gain: Option<[[u8; 8]; 2]>,
    power_present_mask: u16,
    pa_written: [[Option<u8>; 2]; 2],
}
impl FactoryInitialized {
    pub fn calibration(&self) -> &DacCalibrated {
        &self.calibration
    }
    pub fn raw(&self) -> &FactoryBytes {
        &self.raw
    }
    /// Source recovery writes/delay ran iff this initial bit was set.
    /// Source has no subsequent analog-lock acknowledgment in this routine.
    pub fn x2_busy_observed(&self) -> bool {
        self.x2_busy_observed
    }
    pub fn thermal_written(&self) -> [Option<u8>; 2] {
        self.thermal_written
    }
    pub fn power_gain(&self) -> Option<[[u8; 8]; 2]> {
        self.power_gain
    }
    /// Path-major eight groups (three 2 GHz, five 5 GHz). Missing cells use
    /// the source's explicit zero-group initialization when any trim exists.
    pub fn power_present_mask(&self) -> u16 {
        self.power_present_mask
    }
    pub fn pa_written(&self) -> [[Option<u8>; 2]; 2] {
        self.pa_written
    }
}
impl DacCalibrated {
    /// Apply the next source RF X2/thermal/power/PA factory initialization.
    /// All optional/default effects are held exactly, with raw presence
    /// facts exposed separately from programmed fields.
    ///
    /// # Safety
    /// Same kept requester and uninterrupted reset/firmware epoch
    /// for this state, Report, Physical and Io, not just equal fingerprints.
    /// Physical is the immutable OTP image used by the completed prior
    /// table/TRX/dynamic/DAC phases on this device. All source board/
    /// power prerequisites remain valid, BAR/clocks/queues/pins kept and
    /// operational TX/competing reset/IRQ/PHY/RF/OTP work quiesced. Run once in
    /// exclusive initial process/deferred context. Immutable OTP reuse avoids
    /// repeated transport reads; it never admits caller-supplied raw bytes.
    /// This phase does not establish trusted OS/channel/power/adaptivity policy,
    /// analog lock, IQK/DPK, runtime tracking, radio or DMA-stop permission.
    pub async unsafe fn initialize_factory<I: Io>(
        self,
        io: &mut I,
        report: &Report,
        physical: &Physical,
    ) -> Result<FactoryInitialized, Error> {
        let profile = self.initial.profile;
        if io.profile() != profile || report.profile() != profile || physical.profile() != profile {
            return Err(Error::WrongProfile);
        }
        let cap = report.capabilities();
        if cap.rf_phys != 2 || cap.rf_paths != 2 || cap.antenna_tx != 3 || cap.antenna_rx != 3 {
            return Err(Error::UnsupportedRfLayout);
        }
        // Validate the immutable board stream before factory-driven IO;
        // same-owner provenance remains the unsafe contract, not this check.
        let board = physical.logical().map_err(Error::Efuse)?.board();
        board.source_rfe().map_err(Error::Efuse)?;
        board.valid_mac().map_err(Error::Efuse)?;
        if board.raw().crystal_cap_raw != self.initial.crystal_cap
            || board.raw().rfe_raw != self.initial.power.rfe()
            || &board.raw().power_tables != self.initial.power.raw_gain_calibration()
        {
            return Err(Error::WrongProfile);
        }
        let bytes = physical.bytes();
        let raw = FactoryBytes {
            thermal: [bytes[0x1ef], bytes[0x1b0]],
            power_2g: POWER_2G.map(|p| bytes[p]),
            power_5g: POWER_5G.map(|p| p.map(|p| bytes[p])),
            pa: [[bytes[0x1d6], bytes[0x1d8]], [bytes[0x1d5], bytes[0x1d7]]],
        };
        let mut gain = [[0; 8]; 2];
        let mut present = 0u16;
        for (i, &value) in raw.power_2g.iter().enumerate() {
            if value != 255 {
                gain[0][i] = value & 15;
                gain[1][i] = value >> 4;
                present |= (1 << i) | (1 << (8 + i));
            }
        }
        for (p, row) in gain.iter_mut().enumerate() {
            for (i, &value) in raw.power_5g[p].iter().enumerate() {
                if value != 255 {
                    row[i + 3] = value & 31;
                    present |= 1 << (p * 8 + i + 3);
                }
            }
        }
        let mut thermal = [None; 2];
        for (out, &value) in thermal.iter_mut().zip(&raw.thermal) {
            if value == 255 {
                break;
            }
            *out = Some(((value >> 1) & 7) | ((value & 1) << 3));
        }
        let mut pa = [[None; 2]; 2];
        let mut both_2g = true;
        for (out, raw) in pa.iter_mut().zip(&raw.pa) {
            if raw[0] == 255 {
                both_2g = false;
                break;
            }
            out[0] = Some(raw[0] & 15);
        }
        // Source 5 GHz helper has no blank check: a 0xff byte gives
        // nibble 0xf. Preserve that defined initialization effect, never
        // reinterpret it as transport success, calibrated EIRP or TX policy.
        if both_2g {
            for (out, raw) in pa.iter_mut().zip(&raw.pa) {
                out[1] = Some(raw[1] & 15);
            }
        }
        let mut a = Attempt {
            io,
            profile,
            done: false,
        };
        a.domain()?;
        sleep(a.io, 1000).await;
        let x2_busy_observed = a.dac_rf_read_mask(report, Path::A, 0xb8, 1 << 15)? != 0;
        if x2_busy_observed {
            for (reg, value) in [(0xb8, 0xc4440), (0xba, 0x6840d), (0xb8, 0x80440)] {
                a.dac_rf_write(report, Path::A, reg, 0xfffff, value)?;
            }
            sleep(a.io, 1000).await;
        }
        for (p, value) in [Path::A, Path::B].into_iter().zip(thermal) {
            if let Some(value) = value {
                a.dac_rf_write(report, p, 0x43, 0xf0000, u32::from(value))?;
            }
        }
        if present != 0 {
            // Source sequence maps both 2 GHz middle indexes and all
            // extra 5 GHz aliases, including explicit zero missing groups.
            for (p, gain) in [Path::A, Path::B].into_iter().zip(gain) {
                a.dac_rf_write(report, p, 0xee, 1 << 19, 1)?;
                for (seq, idx) in [0usize, 1, 2, 2, 3, 4, 5, 6, 7, 3, 4, 5, 6, 7, 7]
                    .into_iter()
                    .enumerate()
                {
                    a.dac_rf_write(report, p, 0x33, 0xfffff, seq as u32)?;
                    a.dac_rf_write(report, p, 0x3f, 0xfffff, u32::from(gain[idx]))?;
                }
                a.dac_rf_write(report, p, 0xee, 1 << 19, 0)?;
            }
        }
        a.modify32(0xa70, 0x3ff, 0x3ff)?;
        // Source all 2 GHz paths precede all 5 GHz paths; an absent 2 GHz
        // value returns early, keeping any earlier path's store.
        for (band, mask) in [(0, 0xf000), (1, 0xf0000)] {
            for (p, value) in [Path::A, Path::B].into_iter().zip(pa) {
                if let Some(value) = value[band] {
                    a.dac_rf_write(report, p, 0x60, mask, u32::from(value))?;
                }
            }
        }
        a.domain()?;
        a.done = true;
        Ok(FactoryInitialized {
            calibration: self,
            thermal_reference: board.raw().thermal_average,
            raw,
            x2_busy_observed,
            thermal_written: thermal,
            power_gain: if present == 0 { None } else { Some(gain) },
            power_present_mask: present,
            pa_written: pa,
        })
    }
}
impl<I: Io> Attempt<'_, I> {
    fn dac_rf_read_mask(
        &mut self,
        report: &Report,
        p: Path,
        reg: u8,
        mask: u32,
    ) -> Result<u32, Error> {
        // SAFETY: same control owner and exclusive live
        // initial-phase BB/RF domain required by the consuming transition.
        Ok(unsafe { super::rf::Registers::new(self.io, report) }?.read(p, reg, mask)?)
    }
}
