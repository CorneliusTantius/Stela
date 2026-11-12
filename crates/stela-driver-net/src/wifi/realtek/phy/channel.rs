// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Source BB/MAC/RF channel sequence. No calibrated radio/TX admission.
use super::channel_power::{self, Geometry, Plan, Programmed, Width};
use super::{Attempt, Error, Io, Path, PhyInitialized, Report, rf};
use crate::wifi::realtek::registers::*;

/// Source channel stores and IGI latch completed. This keeps the same
/// physical PHY state; it is not readback/calibration/OS-policy permission.
#[derive(Debug)]
pub struct ChannelSet {
    phy: PhyInitialized,
    geometry: Geometry,
    primary_index: u8,
    initial_igi: u8,
    programmed_rf18: u32,
}
impl ChannelSet {
    pub fn phy(&self) -> &PhyInitialized {
        &self.phy
    }
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub fn primary_index(&self) -> u8 {
        self.primary_index
    }
    pub fn initial_igi(&self) -> u8 {
        self.initial_igi
    }
    /// Source computed RF18 value written to both paths, not readback.
    pub fn programmed_rf18(&self) -> u32 {
        self.programmed_rf18
    }
    /// Apply the next source power phase for this exact requested geometry.
    ///
    /// # Safety
    /// All same-owner/reset/firmware/board, held native→OS permission,
    /// current power inputs, quiesced work, queued-air drain and validation
    /// requirements of PhyInitialized::program_channel_power apply. Required
    /// coexistence band notification must already complete, preserving
    /// the source channel → coexistence → power order. ChannelSet
    /// stores are not proof that the radio tuned/calibrated or can transmit.
    pub unsafe fn program_channel_power<I: Io>(
        self,
        io: &mut I,
        report: &Report,
        plan: Plan,
    ) -> Result<Programmed, Error> {
        if self.geometry != plan.geometry() {
            return Err(Error::ChannelPower(channel_power::Error::Geometry));
        }
        // SAFETY: caller keeps the same native and policy guards;
        // immutable plan geometry is additionally bound to this source phase.
        unsafe { self.phy.program_channel_power(io, report, plan) }
    }
}
impl PhyInitialized {
    /// Set source baseband, MAC and both RF paths then latch current IGI.
    ///
    /// # Safety
    /// Same kept requester, control owner, reset/firmware/board epoch
    /// as this PHY state, Report and Io, not equal fingerprints alone. Keep
    /// claims/queues/pins/full BAR and checked native clock; genuine
    /// prior MAC/HCI/PHY initialization remains valid. Invalidate old applied
    /// policy and stop/enforce/drain queued air traffic first. Hold
    /// native control permission followed by OS/location permission for
    /// this exact channel/width through the complete sequence; no reverse waits.
    /// Operational TX (including autonomous ACK/beacon/retry), RX and competing
    /// reset/IRQ/PHY/RF/coexistence/power work remain quiesced. A
    /// parsed channel, scan result or caller numeric geometry is not permission.
    /// Caller performs required coexistence notification, per-channel power,
    /// RFK/IQK/DPK, EDCCA and tuning/readback validation before any
    /// shared RX/TX admission. This does not claim DMA stop or air completion.
    pub unsafe fn set_channel<I: Io>(
        self,
        io: &mut I,
        report: &Report,
        geometry: Geometry,
    ) -> Result<ChannelSet, Error> {
        let profile = self.factory_power().profile();
        if io.profile() != profile || report.profile() != profile {
            return Err(Error::WrongProfile);
        }
        let cap = report.capabilities();
        if cap.rf_phys != 2 || cap.rf_paths != 2 || cap.antenna_tx != 3 || cap.antenna_rx != 3 {
            return Err(Error::UnsupportedRfLayout);
        }
        let index = primary_index(geometry);
        let mut a = Attempt {
            io,
            profile,
            done: false,
        };
        a.domain()?;
        let (initial_igi, programmed_rf18) = set(&mut a, report, geometry, index)?;
        a.domain()?;
        a.done = true;
        Ok(ChannelSet {
            phy: self,
            geometry,
            primary_index: index,
            initial_igi,
            programmed_rf18,
        })
    }
}
fn center(g: Geometry) -> u8 {
    g.centers()[g.width() as usize].expect("validated geometry")
}
pub(super) fn primary_index(g: Geometry) -> u8 {
    match g.width() {
        Width::Mhz20 => 0,
        Width::Mhz40 => {
            if g.primary() > center(g) {
                1
            } else {
                2
            }
        }
        Width::Mhz80 => match i16::from(g.primary()) - i16::from(center(g)) {
            2 => 1,
            -2 => 2,
            6 => 3,
            -6 => 4,
            _ => unreachable!("validated geometry"),
        },
    }
}
pub(super) fn set<I: Io>(
    a: &mut Attempt<'_, I>,
    report: &Report,
    g: Geometry,
    index: u8,
) -> Result<(u8, u32), Error> {
    bb(a, g, index)?;
    mac(a, g, index)?;
    let rf18 = rf_channel(a, report, g)?;
    let igi = (a.io.read32(REG_RXIGI)? & 127) as u8;
    for (mask, value) in [
        (0x7f, igi.wrapping_sub(2)),
        (0x7f00, igi.wrapping_sub(2)),
        (0x7f, igi),
        (0x7f00, igi),
    ] {
        a.modify32(REG_RXIGI, mask, u32::from(value))?;
    }
    Ok((igi, rf18))
}
fn bb<I: Io>(a: &mut Attempt<'_, I>, g: Geometry, index: u8) -> Result<(), Error> {
    let ch = center(g);
    if ch <= 14 {
        a.modify32(REG_BGCTRL, 0x300, 0)?;
        a.modify32(REG_TXF4, 1 << 20, 1)?;
        a.modify32(REG_CCK_CHECK, 1 << 7, 0)?;
        a.modify32(REG_CCKTXONLY, 1 << 18, 0)?;
        a.modify32(REG_CCAMSK, 0x3f000000, 0xf)?;
        let (cck, ofdm) = if g.width() == Width::Mhz20 {
            (5, 6)
        } else {
            (4, 0)
        };
        for (reg, mask, value) in [
            (REG_RXAGCCTL0, 0xf000, cck),
            (REG_RXAGCCTL, 0xf000, cck),
            (REG_RXAGCCTL0, 0x1f0, ofdm),
            (REG_RXAGCCTL, 0x1f0, ofdm),
        ] {
            a.modify32(reg, mask, value)?;
        }
        a.modify32(
            0xc30,
            0xfff,
            match ch {
                13 | 14 => 0x969,
                11 | 12 => 0x96a,
                _ => 0x9aa,
            },
        )?;
        let values = if ch == 14 {
            [
                0x3da0, 0x4962c931, 0x6aa3, 0xaa7b, 0xf3d7, 0, 0xff012455, 0xffff,
            ]
        } else {
            [
                0x5284, 0x3e18fec8, 0xa88, 0xacc4, 0xc8b2, 0x00faf0de, 0x00122344, 0x0fffffff,
            ]
        };
        for ((reg, mask), value) in [
            (REG_TXF0, 0xffff0000),
            (REG_TXF1, u32::MAX),
            (REG_TXF2, 0xffff),
            (REG_TXF3, 0xffff0000),
            (REG_TXF4, 0xffff),
            (REG_TXF5, u32::MAX),
            (REG_TXF6, u32::MAX),
            (REG_TXF7, u32::MAX),
        ]
        .into_iter()
        .zip(values)
        {
            a.modify32(reg, mask, value)?;
        }
        a.modify32(REG_TXDFIR0, 0x70, if ch == 13 { 3 } else { 1 })?;
    } else {
        a.modify32(REG_CCKTXONLY, 1 << 18, 1)?;
        a.modify32(REG_CCK_CHECK, 1 << 7, 1)?;
        a.modify32(REG_BGCTRL, 0x300, 3)?;
        a.modify32(REG_TXF4, 1 << 20, 0)?;
        a.modify32(REG_CCAMSK, 0x3f000000, 0x22)?;
        a.modify32(REG_TXDFIR0, 0x70, 3)?;
        let agc = if ch <= 64 {
            1
        } else if ch <= 144 {
            2
        } else {
            3
        };
        for reg in [0x18ac, 0x41ac] {
            a.modify32(reg, 0x1f0, agc)?;
        }
        let sco = match ch {
            36..=51 => 0x494,
            52..=55 => 0x493,
            56..=111 => 0x453,
            112..=119 => 0x452,
            120..=172 => 0x412,
            173..=177 => 0x411,
            _ => unreachable!("validated geometry"),
        };
        a.modify32(REG_SCOTRK, 0xfff, sco)?;
    }
    match g.width() {
        Width::Mhz20 => {
            for (reg, mask, value) in [
                (REG_DFIRBW, 0x3ff0, 0x19b),
                (REG_TXBWCTL, 0xf, 0),
                (REG_TXBWCTL, 0xffc0, 0),
                (REG_TXCLK, 0x700, 7),
                (REG_TXCLK, 0x700000, 6),
                (REG_CCK_SOURCE, 1 << 30, 0),
                (REG_SBD, 0xf000, 1),
                (REG_PT_CHSMO, 1 << 21, 0),
            ] {
                a.modify32(reg, mask, value)?;
            }
        }
        Width::Mhz40 => {
            a.modify32(REG_CCKSB, 1 << 4, u32::from(index == 1))?;
            for (reg, mask, value) in [
                (REG_TXBWCTL, 0xf, 5),
                (REG_TXBWCTL, 0xc0, 0),
                (REG_TXBWCTL, 0xff00, u32::from(index | (index << 4))),
                (REG_CCK_SOURCE, 1 << 30, 1),
                (REG_SBD, 0xf000, 1),
                (REG_PT_CHSMO, 1 << 21, 1),
            ] {
                a.modify32(reg, mask, value)?;
            }
        }
        Width::Mhz80 => {
            for (reg, mask, value) in [
                (REG_TXBWCTL, 0xf, 10),
                (REG_TXBWCTL, 0xc0, 0),
                (REG_TXBWCTL, 0xff00, u32::from(index | (index << 4))),
                (REG_SBD, 0xf000, 6),
                (REG_PT_CHSMO, 1 << 21, 1),
            ] {
                a.modify32(reg, mask, value)?;
            }
        }
    }
    Ok(())
}
/// `rtw_set_channel_mac`.
pub(super) fn mac<I: Io>(a: &mut Attempt<'_, I>, g: Geometry, index: u8) -> Result<(), Error> {
    let sub40 = if g.width() == Width::Mhz80 {
        if index == 1 || index == 3 { 9 } else { 10 }
    } else {
        0
    };
    a.io.write8(REG_DATA_SC, index | (sub40 << 4))?;
    let old = a.io.read32(REG_WMAC_TRXPTCL_CTL)?;
    let mode = match g.width() {
        Width::Mhz20 => 0,
        Width::Mhz40 => 1 << 7,
        Width::Mhz80 => 1 << 8,
    };
    a.io.write32(REG_WMAC_TRXPTCL_CTL, (old & !0x180) | mode)?;
    a.modify32(REG_AFE_CTRL1, 0x300000, 0)?;
    a.io.write8(REG_USTIME_TSF, 80)?;
    a.io.write8(REG_USTIME_EDCA, 80)?;
    let old = a.io.read8(REG_CCK_CHECK)?;
    a.io.write8(
        REG_CCK_CHECK,
        (old & !0x80) | if center(g) > 14 { 0x80 } else { 0 },
    )?;
    Ok(())
}
fn rstb<I: Io>(a: &mut Attempt<'_, I>, on: bool) -> Result<(), Error> {
    a.modify32(REG_RSTB, 1 << 8, u32::from(on))?;
    if on {
        for reg in [0x1830, 0x4130] {
            a.modify32(reg, 1 << 29, 1)?;
        }
    }
    Ok(())
}
fn rf_channel<I: Io>(a: &mut Attempt<'_, I>, report: &Report, g: Geometry) -> Result<u32, Error> {
    // SAFETY: public consumed transition holds the same serialized
    // requester and uninterrupted PHY/firmware epoch with full native domains.
    let old = unsafe { rf::Registers::new(a.io, report) }?.read(Path::A, 0x18, 0xfffff)?;
    let ch = center(g);
    let band = if ch <= 14 { 0 } else { (1 << 16) | (1 << 8) };
    let rfsi = if ch >= 149 {
        1 << 18
    } else if ch >= 100 {
        1 << 17
    } else {
        0
    };
    let (width, rxbb) = match g.width() {
        Width::Mhz20 => (0x3000, 0x18),
        Width::Mhz40 => (0x2000, 0x10),
        Width::Mhz80 => (0x1000, 8),
    };
    let value = (old & !((1 << 16) | (1 << 9) | (1 << 8) | 0xff | (1 << 18) | (1 << 17) | 0x3000))
        | band
        | rfsi
        | u32::from(ch)
        | width;
    rstb(a, false)?;
    {
        // SAFETY: same guarded control owner; no competing worker
        // can reset/revoke the RF domain through this serialized native borrow.
        let mut rf = unsafe { rf::Registers::new(a.io, report) }?;
        for path in [Path::A, Path::B] {
            rf.write(path, 0xee, 4, 1)?;
            rf.write(path, 0x33, 0x1f, 0x12)?;
            rf.write(path, 0x3f, 0xfffff, rxbb)?;
            rf.write(path, 0xee, 4, 0)?;
        }
        for path in [Path::A, Path::B] {
            rf.write(path, 0x18, 0xfffff, value)?;
        }
    }
    rstb(a, true)?;
    Ok(value)
}
