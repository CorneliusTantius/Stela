// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C physical RF register access from pinned rtw88/phy.c. These are
//! source direct reads and mixed direct/SIPI writes, not PHY calibration or
//! table admission. No RF/air/radio readiness is inferred from a register store.
use super::{
    features::Report,
    identity::{Chip, Profile},
    io::{self, Io},
    registers::*,
};

const RF_MASK: u32 = 0xfffff;
const BASE: [u32; 2] = [0x3c00, 0x4c00];
const SIPI: [u32; 2] = [0x1808, 0x4108];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Path {
    A,
    B,
}
impl Path {
    fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(io::Error),
    WrongProfile,
    InvalidState,
    UnsupportedPath,
    InvalidMask,
    InvalidValue,
    IdentityChanged,
    FirmwareNotReady,
    DomainOff,
    Removed,
    AmbiguousObservation { register: u32, raw: u32 },
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Hardware(error)
    }
}

/// Serialized borrow of the real native control owner. No new BAR/config,
/// physical mapping, DMA allocation, IRQ route or owner-erasing wrapper.
pub struct Registers<'a, I: Io> {
    io: &'a mut I,
    profile: Profile,
    rf_phys: u8,
    failed: bool,
}
impl<'a, I: Io> Registers<'a, I> {
    /// # Safety
    /// `io` and `report` belong to the same PCI requester and
    /// uninterrupted boot/reset epoch, not matching Profile fingerprints.
    /// Source BB/RF domain enable has completed; the full mapped BAR
    /// covers both RF windows through 0x5000. Source table/calibration ordering
    /// is caller-owned; use only for operations admitted at the current phase.
    /// No IRQ/reset/RF/PHY/calibration worker competes with this process/deferred
    /// borrow. Native queues, DMA pins and claims remain held. The
    /// native Io's calibrated delays wait at least the requested duration.
    pub unsafe fn new(io: &'a mut I, report: &Report) -> Result<Self, Error> {
        let profile = io.profile();
        let rf_phys = report.capabilities().rf_phys;
        if profile.chip() != Chip::Rtl8822C
            || report.profile() != profile
            || !(1..=2).contains(&rf_phys)
        {
            return Err(Error::WrongProfile);
        }
        let mut registers = Self {
            io,
            profile,
            rf_phys,
            failed: true,
        };
        registers.verify()?;
        registers.failed = false;
        Ok(registers)
    }
    fn verify(&mut self) -> Result<(), Error> {
        let identity = self.io.read32(REG_SYS_CFG1)?;
        if identity == u32::MAX {
            return Err(Error::Removed);
        }
        if identity != self.profile.observed().sys_cfg1 {
            return Err(Error::IdentityChanged);
        }
        if self.io.read16(REG_MCUFW_CTRL)? & FW_READY_MASK != FW_READY {
            return Err(Error::FirmwareNotReady);
        }
        // Source domain-enable bits from rtw8822c_phy_set_param. Their
        // readback is only a prerequisite, never proof of calibrated RF state.
        let bb = self.io.read8(REG_SYS_FUNC_EN)?;
        let rf = self.io.read8(REG_RF_CTRL)?;
        let wlrf = self.io.read32(REG_WLRF1)?;
        if bb & 3 != 3 || rf & 7 != 7 || wlrf & 0x07000000 != 0x07000000 {
            return Err(Error::DomainOff);
        }
        Ok(())
    }
    fn validate(&self, path: Path, mask: u32) -> Result<usize, Error> {
        if self.failed {
            return Err(Error::InvalidState);
        }
        if path.index() >= self.rf_phys as usize {
            return Err(Error::UnsupportedPath);
        }
        // Avoid source __ffs(0), truncation/aliasing of wider masks. Addresses
        // are typed u8, so source modulo-256 aliases cannot enter this API.
        if mask == 0 || mask & !RF_MASK != 0 {
            return Err(Error::InvalidMask);
        }
        Ok(path.index())
    }
    fn finish<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_ok() {
            self.failed = false;
        } else {
            self.io.quarantine();
        }
        result
    }
    fn direct_read(&mut self, path: usize, address: u8) -> Result<u32, Error> {
        let register = BASE[path] + u32::from(address) * 4;
        let value = self.io.read32(register)?;
        // A whole all-ones RF window observation is ambiguous (removed or
        // unavailable RF) and is refused. Legitimate 20-bit all-ones data with
        // other raw register bits remains admitted; no valid read is invented.
        if value == u32::MAX {
            return Err(Error::AmbiguousObservation {
                register,
                raw: value,
            });
        }
        Ok(value)
    }
    /// Source PHY table sentinel/extra delay, under the same exclusive
    /// RF borrow. Delay completion is not a hardware/RF-completion observation.
    pub(super) fn table_delay_us(&mut self, microseconds: u64) -> Result<(), Error> {
        if self.failed {
            return Err(Error::InvalidState);
        }
        self.failed = true;
        let result = (|| {
            self.verify()?;
            self.io.delay_us(microseconds);
            self.verify()
        })();
        self.finish(result)
    }
    /// [`Self::table_delay_us`] as a wait that ends the step of stepped work.
    pub(super) async fn table_wait_us(&mut self, microseconds: u64) -> Result<(), Error> {
        if self.failed {
            return Err(Error::InvalidState);
        }
        self.failed = true;
        let result = async {
            self.verify()?;
            super::io::sleep(self.io, microseconds).await;
            self.verify()
        }
        .await;
        self.finish(result)
    }
    pub fn read(&mut self, path: Path, address: u8, mask: u32) -> Result<u32, Error> {
        let path = self.validate(path, mask)?;
        self.failed = true;
        let result = (|| {
            self.verify()?;
            let value = self.direct_read(path, address)?;
            self.verify()?;
            Ok((value & mask) >> mask.trailing_zeros())
        })();
        self.finish(result)
    }
    /// Source mixed write: address zero uses the SPI/serial path with a 13us
    /// delay; every other address uses direct masked MMIO and a 1us delay.
    /// Success records stores/delay only, never a completed PHY/air operation.
    pub fn write(&mut self, path: Path, address: u8, mask: u32, data: u32) -> Result<(), Error> {
        let path = self.validate(path, mask)?;
        let shift = mask.trailing_zeros();
        if data & !(mask >> shift) != 0 {
            return Err(Error::InvalidValue);
        }
        self.failed = true;
        let result = (|| {
            self.verify()?;
            if address == 0 {
                let value = if mask == RF_MASK {
                    data
                } else {
                    (self.direct_read(path, address)? & !mask) | (data << shift)
                };
                self.io.write32(SIPI[path], value & RF_MASK)?;
                self.io.delay_us(13);
            } else {
                let register = BASE[path] + u32::from(address) * 4;
                let old = self.direct_read(path, address)?;
                self.io
                    .write32(register, (old & !mask) | ((data << shift) & mask))?;
                self.io.delay_us(1);
            }
            self.verify()?;
            Ok(())
        })();
        self.finish(result)
    }
}
impl<I: Io> Drop for Registers<'_, I> {
    fn drop(&mut self) {
        if self.failed {
            self.io.quarantine();
        }
    }
}

#[cfg(test)]
mod tests;
