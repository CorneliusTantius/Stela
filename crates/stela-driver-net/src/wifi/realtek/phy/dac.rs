// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Initial RTL8822C ADC/DAC calibration, from pinned rtw88/rtw8822c.c.
//! No cached restore, IQK/DPK, runtime tracking or TX admission. Factory RF
//! trim has its own later consumed phase.
mod trim;
use super::{Attempt, Error, InitialPhy, Io, Path, Report, rf, sleep};
pub use trim::{FactoryBytes, FactoryInitialized, PhyInitialized, ThermalTracking};

const BACKUP: [u32; 16] = [
    0x180c, 0x1810, 0x410c, 0x4110, 0x1c3c, 0x1c24, 0x1d70, 0x9b4, 0x1a00, 0x1a14, 0x1d58, 0x1c38,
    0x1e24, 0x1e28, 0x1860, 0x4160,
];
/// Completed bounded initial ADCK/DACK, keeping calibrated vectors.
/// This is not an operational/calibrated-channel or transmit-policy credential.
#[derive(Debug)]
pub struct DacCalibrated {
    initial: InitialPhy,
    adck: [u32; 2],
    msbk: [[[u16; 15]; 2]; 2],
    dck: [[[u8; 2]; 2]; 2],
    residual: [[u32; 2]; 2],
}
impl DacCalibrated {
    pub fn initial(&self) -> &InitialPhy {
        &self.initial
    }
    pub fn adck(&self) -> [u32; 2] {
        self.adck
    }
    pub fn msbk(&self) -> &[[[u16; 15]; 2]; 2] {
        &self.msbk
    }
    pub fn dck(&self) -> [[[u8; 2]; 2]; 2] {
        self.dck
    }
    /// Final signed ten-bit offset observations before absolute testing.
    pub fn residual(&self) -> [[u32; 2]; 2] {
        self.residual
    }
}
impl InitialPhy {
    /// Perform initial source ADC/DAC calibration with samples,
    /// handshakes and convergence. No old cached vectors can enter this path.
    ///
    /// # Safety
    /// Same kept native requester and uninterrupted reset/firmware
    /// epoch as this initial state/Report; prior table/TRX/dynamic phases
    /// still valid. Full BAR/native clocks, queues/pins/claims kept; all
    /// operational TX and competing IRQ/reset/PHY/RF workers quiesced. The
    /// source-required board/power/calibration prerequisites must be checked
    /// on this device; no raw OTP country or guessed policy suffices.
    /// Run once in exclusive initial process/deferred context. Uncertainty
    /// quarantines the real owner; no rollback or DMA-stop proof is implied.
    pub async unsafe fn calibrate_dac<I: Io>(
        self,
        io: &mut I,
        report: &Report,
    ) -> Result<DacCalibrated, Error> {
        if io.profile() != self.profile || report.profile() != self.profile {
            return Err(Error::WrongProfile);
        }
        let cap = report.capabilities();
        if cap.rf_phys != 2 || cap.rf_paths != 2 || cap.antenna_tx != 3 || cap.antenna_rx != 3 {
            return Err(Error::UnsupportedRfLayout);
        }
        let mut a = Attempt {
            io,
            profile: self.profile,
            done: false,
        };
        a.domain()?;
        let mut saved = [0; 16];
        for (out, reg) in saved.iter_mut().zip(BACKUP) {
            *out = a.io.read32(reg)?;
        }
        // Source path*i+i aliases both paths when RF register count is one.
        // Preserve the two independent RF values instead.
        let mut saved_rf = [0; 2];
        for (p, out) in [Path::A, Path::B].into_iter().zip(saved_rf.iter_mut()) {
            *out = a.dac_rf_read(report, p, 0x8f)?;
        }
        a.dac_bb()?;
        let mut adck = [0; 2];
        let mut residual = [[0; 2]; 2];
        for (n, p) in [Path::A, Path::B].into_iter().enumerate() {
            let (adc, value) = a.dac_adc(report, p)?;
            adck[n] = value;
            let mut converged = false;
            for _ in 0..10 {
                a.dac_step1(p, value).await?;
                let compensation = a.dac_step2(report, p)?;
                let offset = a.dac_step3(report, p, adc, compensation).await?;
                residual[n] = offset;
                if offset.into_iter().all(|v| magnitude(v) < 5) {
                    converged = true;
                    break;
                }
            }
            if !converged {
                return Err(Error::DacConvergence { path: p });
            }
            let b = write_base(p);
            a.io.write32(b + 0x68, 0)?;
            a.io.write32(b + 0x10, 0x02d508c4)?;
            a.modify32(b + 0xbc, 1, 0)?;
            a.modify32(b + 0x30, 1 << 30, 1)?;
        }
        a.io.write32(0x1b00, 8)?;
        a.modify32(0x4130, 1 << 30, 1)?;
        a.io.write8(0x1bcc, 0)?;
        a.io.write32(0x1b00, 10)?;
        a.io.write8(0x1bcc, 0)?;
        for (reg, value) in BACKUP.into_iter().zip(saved) {
            a.io.write32(reg, value)?;
        }
        for (p, value) in [Path::A, Path::B].into_iter().zip(saved_rf) {
            a.dac_rf_write(report, p, 0x8f, 0xfffff, value)?;
        }
        let (msbk, dck) = a.dac_backup_vectors()?;
        a.domain()?;
        a.done = true;
        Ok(DacCalibrated {
            initial: self,
            adck,
            msbk,
            dck,
            residual,
        })
    }
}
fn write_base(p: Path) -> u32 {
    match p {
        Path::A => 0x1800,
        Path::B => 0x4100,
    }
}
fn read_base(p: Path) -> u32 {
    match p {
        Path::A => 0x2800,
        Path::B => 0x4500,
    }
}
fn magnitude(v: u32) -> u32 {
    if v >= 0x200 { 0x400 - v } else { v }
}
fn valid_sample(v: u32) -> bool {
    magnitude(v) <= 100
}
fn signed_order(v: u32) -> u32 {
    (v + 0x200) & 0x3ff
}
fn spread(v: &[u32; 100]) -> u32 {
    let min = *v.iter().min_by_key(|v| signed_order(**v)).unwrap();
    let max = *v.iter().max_by_key(|v| signed_order(**v)).unwrap();
    max.wrapping_sub(min) & 0x3ff
}
fn offset(v: &[u32; 100]) -> u32 {
    let (mut p, mut m) = (0, 0);
    for &v in &v[10..90] {
        if v > 0x200 {
            m += 0x400 - v;
        } else {
            p += v;
        }
    }
    if p > m {
        (p - m) / 80
    } else {
        let t = (m - p) / 80;
        if t == 0 { 0 } else { 0x400 - t }
    }
}
fn compensation(v: u32) -> u32 {
    let v = if v == 0 { 0 } else { 0x400 - v };
    if v < 0x300 {
        v * 2 * 6 / 5 + 0x80
    } else {
        0x7fu32.wrapping_sub((0x400 - v) * 2 * 6 / 5)
    }
}
type Vectors = [[[u16; 15]; 2]; 2];
type Dck = [[[u8; 2]; 2]; 2];
impl<I: Io> Attempt<'_, I> {
    fn dac_rf_read(&mut self, report: &Report, p: Path, reg: u8) -> Result<u32, Error> {
        // SAFETY: caller's consumed initial-phase contract keeps this exact
        // control owner/epoch and exclusive live BB/RF domain throughout.
        Ok(unsafe { rf::Registers::new(self.io, report) }?.read(p, reg, 0xfffff)?)
    }
    fn dac_rf_write(
        &mut self,
        report: &Report,
        p: Path,
        reg: u8,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        // SAFETY: same owner/exclusive initial-phase contract.
        Ok(unsafe { rf::Registers::new(self.io, report) }?.write(p, reg, mask, value)?)
    }
    async fn dac_delay(&mut self, us: u64) {
        sleep(self.io, us).await;
    }
    async fn dac_ready(&mut self, reg: u32, mask: u32, target: u32) -> Result<(), Error> {
        self.domain()?;
        for _ in 0..1000 {
            let raw = self.io.read32(reg)?;
            if raw == u32::MAX {
                return Err(Error::DacAmbiguousReady { register: reg });
            }
            if (raw & mask) >> mask.trailing_zeros() == target {
                self.domain()?;
                return Ok(());
            }
            self.dac_delay(10).await;
        }
        Err(Error::DacReadyTimeout { register: reg })
    }
    fn dac_sample(&mut self) -> Result<[[u32; 100]; 2], Error> {
        let mut v = [[0; 100]; 2];
        let mut accepted = 0;
        for _ in 0..10000 {
            let raw = self.io.read32(0x2dbc)? & 0x3fffff;
            let pair = [(raw >> 12) & 0x3ff, raw & 0x3ff];
            if pair.into_iter().all(valid_sample) {
                v[0][accepted] = pair[0];
                v[1][accepted] = pair[1];
                accepted += 1;
                if accepted == 100 {
                    return Ok(v);
                }
            }
        }
        // Source's void sampler leaves missing entries uninitialized. They
        // can never become invented zero samples or apparent convergence.
        Err(Error::DacSamples { accepted })
    }
    fn dac_measure(&mut self, report: &Report) -> Result<[u32; 2], Error> {
        // These source diagnostic RF reads remain hardware operations.
        self.dac_rf_read(report, Path::A, 0)?;
        self.dac_rf_read(report, Path::B, 0)?;
        let mut v = self.dac_sample()?;
        for _ in 0..101 {
            let delta = [spread(&v[0]), spread(&v[1])];
            for v in &mut v {
                v.sort_unstable_by_key(|v| signed_order(*v));
            }
            if delta.into_iter().all(|v| v <= 5) {
                return Ok([offset(&v[0]), offset(&v[1])]);
            }
            for i in [0, 99] {
                let raw = self.io.read32(0x2dbc)? & 0x3fffff;
                v[0][i] = (raw >> 12) & 0x3ff;
                v[1][i] = raw & 0x3ff;
            }
        }
        Err(Error::DacUnstableSamples)
    }
    fn dac_bb(&mut self) -> Result<(), Error> {
        self.modify32(0x1d58, 0xff8, 0x1ff)?;
        self.modify32(0x1a00, 3, 2)?;
        self.modify32(0x1a14, 0x300, 3)?;
        self.io.write32(0x1d70, 0x7e7e7e7e)?;
        self.modify32(0x180c, 3, 0)?;
        self.modify32(0x410c, 3, 0)?;
        self.io.write32(0x1b00, 8)?;
        self.io.write8(0x1bcc, 0x3f)?;
        self.io.write32(0x1b00, 10)?;
        self.io.write8(0x1bcc, 0x3f)?;
        self.modify32(0x1e24, 1 << 31, 0)?;
        self.modify32(0x1e28, 15, 3)
    }
    fn dac_adc(&mut self, report: &Report, p: Path) -> Result<([u32; 2], u32), Error> {
        let b = write_base(p);
        let select = match p {
            Path::A => 0xa0000,
            Path::B => 0x80000,
        };
        self.modify32(b + 0x30, 1 << 30, 0)?;
        if p == Path::B {
            self.io.write32(b + 0x30, 0x30db8041)?;
        }
        self.io.write32(b + 0x60, 0xf0040ff0)?;
        self.io.write32(b + 0x0c, 0xdff00220)?;
        self.io.write32(b + 0x10, 0x02dd08c4)?;
        self.io.write32(b + 0x0c, 0x10000260)?;
        self.dac_rf_write(report, Path::A, 0, 0xfffff, 0x10000)?;
        self.dac_rf_write(report, Path::B, 0, 0xfffff, 0x10000)?;
        let mut adc = [0; 2];
        let mut adck = 0;
        let mut converged = false;
        for _ in 0..10 {
            self.io.write32(0x1c3c, select + 0x8003)?;
            self.io.write32(0x1c24, 0x10002)?;
            let mut iq = self.dac_measure(report)?;
            for i in 0..2 {
                if iq[i] != 0 {
                    iq[i] = 0x400 - iq[i];
                    adc[i] = iq[i];
                }
            }
            adck = (iq[0] & 0x3ff) | ((iq[1] & 0x3ff) << 10);
            self.io.write32(b + 0x68, adck)?;
            self.io.write32(0x1c3c, select + 0x8103)?;
            if self
                .dac_measure(report)?
                .into_iter()
                .all(|v| magnitude(v) < 5)
            {
                converged = true;
                break;
            }
        }
        if !converged {
            return Err(Error::DacAdcConvergence { path: p });
        }
        self.io.write32(0x1c3c, 3)?;
        self.io.write32(b + 0x0c, 0x10000260)?;
        self.io.write32(b + 0x10, 0x02d508c4)?;
        self.dac_rf_write(report, p, 0x8f, 1 << 13, 1)?;
        Ok((adc, adck))
    }
    async fn dac_step1(&mut self, p: Path, adck: u32) -> Result<(), Error> {
        let b = write_base(p);
        let r = read_base(p);
        self.io.write32(b + 0x68, adck)?;
        self.io.write32(b + 0x0c, 0xdff00220)?;
        if p == Path::A {
            self.io.write32(b + 0x60, 0xf0040ff0)?;
            self.io.write32(0x1c38, u32::MAX)?;
        }
        for (reg, value) in [
            (b + 0x10, 0x02d508c5),
            (0x9b4, 0xdb66db00),
            (b + 0xb0, 0x0a11fb88),
            (b + 0xbc, 0x0008ff81),
            (b + 0xc0, 0x0003d208),
            (b + 0xcc, 0x0a11fb88),
            (b + 0xd8, 0x0008ff81),
            (b + 0xdc, 0x0003d208),
            (b + 0xb8, 0x60000000),
        ] {
            self.io.write32(reg, value)?;
        }
        self.dac_delay(2000).await;
        self.io.write32(b + 0xbc, 0x000aff8d)?;
        self.dac_delay(2000).await;
        self.io.write32(b + 0xb0, 0x0a11fb89)?;
        self.io.write32(b + 0xcc, 0x0a11fb89)?;
        self.dac_delay(1000).await;
        self.io.write32(b + 0xb8, 0x62000000)?;
        self.io.write32(b + 0xd4, 0x62000000)?;
        self.dac_delay(20000).await;
        self.dac_ready(r + 8, 0x7fff80, 0xffff).await?;
        self.dac_ready(r + 0x34, 0x7fff80, 0xffff).await?;
        self.io.write32(b + 0xb8, 0x02000000)?;
        self.dac_delay(1000).await;
        self.io.write32(b + 0xbc, 0x0008ff87)?;
        self.io.write32(0x9b4, 0xdb6db600)?;
        self.io.write32(b + 0x10, 0x02d508c5)?;
        self.io.write32(b + 0xbc, 0x0008ff87)?;
        self.io.write32(b + 0x60, 0xf0000000)?;
        Ok(())
    }
    fn dac_step2(&mut self, report: &Report, p: Path) -> Result<[u32; 2], Error> {
        let b = write_base(p);
        for (r, m, v) in [
            (b + 0xbc, 0xf0000000, 0),
            (b + 0xc0, 15, 8),
            (b + 0xd8, 0xf0000000, 0),
            (b + 0xdc, 15, 8),
        ] {
            self.modify32(r, m, v)?;
        }
        self.io.write32(0x1b00, 8)?;
        self.io.write8(0x1bcc, 0x3f)?;
        self.io.write32(b + 0x0c, 0xdff00220)?;
        self.io.write32(b + 0x10, 0x02d508c5)?;
        self.io.write32(0x1c3c, 0x88103)?;
        Ok(self.dac_measure(report)?.map(compensation))
    }
    async fn dac_step3(
        &mut self,
        report: &Report,
        p: Path,
        adc: [u32; 2],
        iq: [u32; 2],
    ) -> Result<[u32; 2], Error> {
        let b = write_base(p);
        let r = read_base(p);
        for (reg, v) in [
            (b + 0x0c, 0xdff00220),
            (b + 0x10, 0x02d508c5),
            (0x9b4, 0xdb66db00),
            (b + 0xb0, 0x0a11fb88),
            (b + 0xbc, 0xc008ff81),
            (b + 0xc0, 0x0003d208),
        ] {
            self.io.write32(reg, v)?;
        }
        self.modify32(b + 0xbc, 0xf0000000, iq[0] & 15)?;
        self.modify32(b + 0xc0, 15, (iq[0] & 0xf0) >> 4)?;
        self.io.write32(b + 0xcc, 0x0a11fb88)?;
        self.io.write32(b + 0xd8, 0xe008ff81)?;
        self.io.write32(b + 0xdc, 0x0003d208)?;
        self.modify32(b + 0xd8, 0xf0000000, iq[1] & 15)?;
        self.modify32(b + 0xdc, 15, (iq[1] & 0xf0) >> 4)?;
        self.io.write32(b + 0xb8, 0x60000000)?;
        self.dac_delay(2000).await;
        self.modify32(b + 0xbc, 14, 6)?;
        self.dac_delay(2000).await;
        self.io.write32(b + 0xb0, 0x0a11fb89)?;
        self.io.write32(b + 0xcc, 0x0a11fb89)?;
        self.dac_delay(1000).await;
        self.io.write32(b + 0xb8, 0x62000000)?;
        self.io.write32(b + 0xd4, 0x62000000)?;
        self.dac_delay(20000).await;
        self.dac_ready(r + 0x24, 0x07f80000, iq[0]).await?;
        self.dac_ready(r + 0x50, 0x07f80000, iq[1]).await?;
        self.io.write32(b + 0xb8, 0x02000000)?;
        self.dac_delay(1000).await;
        self.modify32(b + 0xbc, 14, 3)?;
        self.io.write32(0x9b4, 0xdb6db600)?;
        let temp = ((adc[0] + 0x10) & 0x3ff) | (((adc[1] + 0x10) & 0x3ff) << 10);
        self.io.write32(b + 0x68, temp)?;
        self.io.write32(b + 0x10, 0x02d508c5)?;
        self.io.write32(b + 0x60, 0xf0000000)?;
        Ok(self
            .dac_measure(report)?
            .map(|v| v.wrapping_sub(0x10) & 0x3ff))
    }
    fn dac_backup_vectors(&mut self) -> Result<(Vectors, Dck), Error> {
        let temp = [
            self.io.read32(0x1860)?,
            self.io.read32(0x4160)?,
            self.io.read32(0x9b4)?,
        ];
        self.io.write32(0x9b4, 0xdb66db00)?;
        let mut msbk = [[[0; 15]; 2]; 2];
        for (path, p) in [Path::A, Path::B].into_iter().enumerate() {
            let b = write_base(p);
            let r = read_base(p);
            self.modify32(b + 0x30, 1 << 30, 0)?;
            self.modify32(b + 0x60, 0xfc000000, 0x3c)?;
            for (vec, (w, rd)) in [(b + 0xb0, r + 0x10), (b + 0xcc, r + 0x3c)]
                .into_iter()
                .enumerate()
            {
                for (i, value) in msbk[path][vec].iter_mut().enumerate() {
                    self.modify32(w, 0xf0000000, i as u32)?;
                    *value = ((self.io.read32(rd)? & 0x7fc0000) >> 18) as u16;
                }
            }
        }
        let mut dck = [[[0; 2]; 2]; 2];
        for (path, p) in [Path::A, Path::B].into_iter().enumerate() {
            let b = write_base(p);
            for (vec, (lo, hi)) in [(b + 0xbc, b + 0xc0), (b + 0xd8, b + 0xdc)]
                .into_iter()
                .enumerate()
            {
                dck[path][vec][0] = (self.io.read32(lo)? >> 28) as u8;
                dck[path][vec][1] = (self.io.read32(hi)? & 15) as u8;
            }
        }
        // Source B-I high and B-Q low assignments are transposed. Preserve
        // the distinct fields in the layout its restore path expects.
        self.modify32(0x1830, 1 << 30, 1)?;
        self.modify32(0x4130, 1 << 30, 1)?;
        for (r, v) in [0x1860, 0x4160, 0x9b4].into_iter().zip(temp) {
            self.io.write32(r, v)?;
        }
        Ok((msbk, dck))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    #[ignore = "oracle: STELA_REALTEK_WIFI_DAC_ORACLE"]
    fn compensation_matches_all_accepted_source_constant_samples() {
        let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_DAC_ORACLE").unwrap()).unwrap();
        let offset = trace.len() - 2048 * 828 - 24 - 201 * 12;
        for i in 0..201 {
            let words: [u32; 3] = core::array::from_fn(|j| {
                u32::from_le_bytes(
                    trace[offset + i * 12 + j * 4..offset + i * 12 + j * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            assert_eq!(words[0] as i32, i as i32 - 100);
            assert_eq!(compensation(words[0] & 1023), words[1]);
            assert_eq!(words[1], words[2]);
        }
    }
    #[test]
    #[ignore = "oracle: STELA_REALTEK_WIFI_DAC_ORACLE"]
    fn signed_sample_algorithms_match_whole_source_vectors() {
        let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_DAC_ORACLE").unwrap()).unwrap();
        let mut at = trace.len() - 2048 * 828;
        for c in 0..2048 {
            let head: [u32; 7] = core::array::from_fn(|j| {
                u32::from_le_bytes(trace[at + j * 4..at + j * 4 + 4].try_into().unwrap())
            });
            at += 28;
            assert_eq!(head[0], c);
            for (v, params, extrema, result) in [
                (0, (73, 29), (head[1], head[2]), head[5]),
                (1, (139, 47), (head[3], head[4]), head[6]),
            ] {
                let mut input: [u32; 100] =
                    core::array::from_fn(|i| (c * params.0 + i as u32 * params.1) & 1023);
                assert_eq!(spread(&input), extrema.1.wrapping_sub(extrema.0) & 1023);
                input.sort_unstable_by_key(|v| signed_order(*v));
                let expected: [u32; 100] = core::array::from_fn(|j| {
                    u32::from_le_bytes(trace[at + j * 4..at + j * 4 + 4].try_into().unwrap())
                });
                at += 400;
                assert_eq!(input, expected, "case {c} vector {v}");
                assert_eq!(offset(&input), result);
            }
        }
        assert_eq!(at, trace.len());
    }
}
