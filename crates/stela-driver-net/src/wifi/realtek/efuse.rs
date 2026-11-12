// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C read-only physical efuse transport, logical map and raw board data.
//! Raw OTP/regulatory/calibration fields do not attest calibrated radio policy.
use super::{
    chip::{EfuseSize, RTL8822C},
    identity::Profile,
    io::{self, Io, sleep},
    registers::*,
};
use crate::wifi::stepped::yield_now;
/// The physical efuse every rtw88 chip here has.
const PHYSICAL: usize = 512;
/// The largest logical map, whose tail a smaller chip leaves unprogrammed.
const LOGICAL: usize = 768;
#[cfg(test)]
const USABLE: usize = PHYSICAL - 124;
const POLLS: usize = 1_000_000;
/// Looks at one byte's read that wait in place, about a millisecond, before
/// each further look ends the step; and the bytes read a step.
const INLINE_POLLS: usize = 1000;
const BYTES_A_STEP: usize = 16;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(io::Error),
    WrongChip,
    IdentityChanged,
    Removed,
    FirmwareNotReady,
    Timeout { address: u16 },
    CompletionAddress { requested: u16, observed: u16 },
    Header { offset: usize },
    Payload { offset: usize },
    Logical { offset: usize },
    UnsupportedRfe(u8),
    InvalidMac,
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Hardware(e)
    }
}
struct Attempt<'a, I: Io> {
    io: &'a mut I,
    done: bool,
}
impl<I: Io> Drop for Attempt<'_, I> {
    fn drop(&mut self) {
        if !self.done {
            self.io.quarantine();
        }
    }
}
/// Immutable exact-requester OTP read. No public safe constructor admits
/// supplied bytes as a physical board identity or calibrated profile. Profile
/// is a hardware fingerprint, not a unique BDF/reset epoch; PHY admission must
/// keep this result with the same control/claim owner.
pub struct Physical {
    profile: Profile,
    bytes: [u8; PHYSICAL],
}
impl Physical {
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn bytes(&self) -> &[u8; PHYSICAL] {
        &self.bytes
    }
    pub fn logical(&self) -> Result<Logical, Error> {
        Ok(Logical {
            profile: self.profile,
            bytes: logical_map_sized(&self.bytes, efuse_size(self.profile)?)?,
        })
    }
}
pub struct Logical {
    profile: Profile,
    bytes: [u8; LOGICAL],
}
impl Logical {
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn bytes(&self) -> &[u8; LOGICAL] {
        &self.bytes
    }
    pub fn board(&self) -> Board {
        let b = &self.bytes;
        Board {
            profile: self.profile,
            raw: BoardData {
                usb_mode_switch_raw: b[6] & 0x80 != 0,
                rtl_id: u16::from_le_bytes([b[0], b[1]]),
                mac: b[0x120..0x126].try_into().unwrap(),
                rfe_raw: b[0xca],
                rf_board_raw: b[0xc1],
                crystal_cap_raw: b[0xb9] & 0x7f,
                channel_plan_raw: b[0xb8],
                country_raw: [b[0xcb], b[0xcc]],
                bt_raw: b[0xc3],
                regulatory_raw: b[0xc1] & 7,
                thermal_raw: [b[0xd0], b[0xd1]],
                thermal_average: ((u16::from(b[0xd0]) + u16::from(b[0xd1])) >> 1) as u8,
                power_track_raw: b[0xc8] >> 4,
                power_tables: b[0x10..0xb8].try_into().unwrap(),
            },
        }
    }
}
/// Source-decoded raw board identity and all four 42-byte power tables. No
/// country byte, power entry, CAM flag or RFE selector authorizes transmission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Board {
    profile: Profile,
    raw: BoardData,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoardData {
    pub usb_mode_switch_raw: bool,
    pub rtl_id: u16,
    pub mac: [u8; 6],
    pub rfe_raw: u8,
    pub rf_board_raw: u8,
    pub crystal_cap_raw: u8,
    pub channel_plan_raw: u8,
    pub country_raw: [u8; 2],
    pub bt_raw: u8,
    pub regulatory_raw: u8,
    pub thermal_raw: [u8; 2],
    pub thermal_average: u8,
    pub power_track_raw: u8,
    pub power_tables: [u8; 168],
}
impl Board {
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn raw(&self) -> &BoardData {
        &self.raw
    }
    /// Source's seven declared RFE tables, without inventing a fallback for
    /// unknown/unprogrammed boards. Source PHY tables remain separate.
    pub fn source_rfe(&self) -> Result<u8, Error> {
        if self.raw.rfe_raw <= 6 {
            Ok(self.raw.rfe_raw)
        } else {
            Err(Error::UnsupportedRfe(self.raw.rfe_raw))
        }
    }
    pub fn valid_mac(&self) -> Result<[u8; 6], Error> {
        if self.raw.mac[0] & 1 != 0 || self.raw.mac == [0; 6] {
            Err(Error::InvalidMac)
        } else {
            Ok(self.raw.mac)
        }
    }
}
/// Read source RTL8822C physical OTP only; never program any efuse byte. The
/// source chip has no efuse_grant hook. Bank/LDO accesses keep all unrelated
/// bits, and each read trigger has the source bounded 1us polling loop.
///
/// # Safety
/// Selected/requester MAC power and source MCU-ready firmware;
/// exclusive efuse/LDO/bank owner with no competing reset/OTP/calibration worker.
/// Run only in initial process/deferred context, never a hard IRQ. All native
/// HCI queues and claims remain held. Delays are calibrated.
/// Unknown hardware, timeout/removal or uncertain I/O quarantines the real
/// owner. This does not perform the separate firmware hardware-feature report,
/// source PHY power-policy defaults, calibration, channel or station setup.
pub async unsafe fn read<I: Io>(io: &mut I) -> Result<Physical, Error> {
    let profile = io.profile();
    let spec = profile.rtw88().ok_or(Error::WrongChip)?;
    efuse_size(profile)?;
    let mut a = Attempt { io, done: false };
    verify(a.io, profile)?;
    let ready = a.io.read16(REG_MCUFW_CTRL)?;
    if ready == u16::MAX {
        return Err(Error::Removed);
    }
    if ready & FW_READY_MASK != FW_READY {
        return Err(Error::FirmwareNotReady);
    }
    let bank = a.io.read32(REG_LDO_EFUSE_CTRL)?;
    a.io.write32(REG_LDO_EFUSE_CTRL, bank & !0x300)?;
    // The chip's cfg_ldo25(false).
    let (register, bit) = spec.ldo25;
    let ldo = a.io.read8(register)?;
    a.io.write8(register, ldo & !bit)?;
    let mut control = a.io.read32(REG_EFUSE_CTRL)?;
    let mut bytes = [0; PHYSICAL];
    for (address, byte) in bytes.iter_mut().enumerate() {
        if address % BYTES_A_STEP == 0 {
            yield_now().await;
        }
        control = (control & !0x3ffff) | ((address as u32) << 8);
        a.io.write32(REG_EFUSE_CTRL, control & !BIT_EF_FLAG)?;
        let mut ready = false;
        for poll in 0..POLLS {
            if poll < INLINE_POLLS {
                a.io.delay_us(1);
            } else {
                sleep(a.io, 1).await;
            }
            control = a.io.read32(REG_EFUSE_CTRL)?;
            // Source decrements/tests the bound before accepting completion,
            // so even ready on the final millionth observation times out.
            if poll + 1 == POLLS {
                break;
            }
            if control & BIT_EF_FLAG != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(Error::Timeout {
                address: address as u16,
            });
        }
        // The completed EF_ADDR echo must still identify this requested byte.
        // An all-ones control word cannot describe any address in 0..512, even
        // when the independent SYS_CFG identity register remains readable.
        let observed = ((control >> 8) & 0x3ff) as u16;
        if observed != address as u16 {
            return Err(Error::CompletionAddress {
                requested: address as u16,
                observed,
            });
        }
        // Raw EFUSE/LDO data may legitimately contain all ones. Fresh
        // immutable SYS_CFG identity, rather than a data byte, detects removal
        // before any physical observation can enter the immutable map.
        verify(a.io, profile)?;
        *byte = control as u8;
    }
    a.done = true;
    Ok(Physical { profile, bytes })
}
fn verify<I: Io>(io: &mut I, profile: Profile) -> Result<(), Error> {
    let actual = io.read32(REG_SYS_CFG1)?;
    if actual == u32::MAX {
        return Err(Error::Removed);
    }
    if actual != profile.observed().sys_cfg1 {
        return Err(Error::IdentityChanged);
    }
    Ok(())
}
/// Source one/two-byte efuse headers and last-write-wins words. The physical
/// protected tail is held by Physical, never consumed as logical content.
/// Unlike the donor's permissive final-byte check, every header/word must fit
/// completely before that protected tail. Malformed maps are explicit errors.
pub fn logical_map(physical: &[u8; PHYSICAL]) -> Result<[u8; LOGICAL], Error> {
    let size = RTL8822C.rtw88.as_ref().map(|spec| spec.efuse);
    logical_map_sized(physical, size.ok_or(Error::WrongChip)?)
}
/// The chip's efuse sizes, which must fit the buffers here.
fn efuse_size(profile: Profile) -> Result<EfuseSize, Error> {
    let size = profile.rtw88().ok_or(Error::WrongChip)?.efuse;
    if size.physical != PHYSICAL || size.logical > LOGICAL || size.protected >= PHYSICAL {
        return Err(Error::WrongChip);
    }
    Ok(size)
}
/// [`logical_map`] for a chip of `size`: bytes past its logical map stay
/// unprogrammed.
fn logical_map_sized(physical: &[u8; PHYSICAL], size: EfuseSize) -> Result<[u8; LOGICAL], Error> {
    let usable = PHYSICAL - size.protected;
    let mut logical = [255; LOGICAL];
    let mut cursor = 0;
    while cursor < usable {
        let first = physical[cursor];
        if first == 255 {
            break;
        }
        let (block, enabled) = if first & 0x1f == 0xf {
            if cursor + 2 > usable {
                return Err(Error::Header { offset: cursor });
            }
            let second = physical[cursor + 1];
            if second == 255 {
                break;
            }
            cursor += 2;
            (((second & 0xf0) >> 1) | ((first >> 5) & 7), second & 15)
        } else {
            cursor += 1;
            (first >> 4, first & 15)
        };
        for word in 0..4 {
            if enabled & (1 << word) != 0 {
                continue;
            }
            if cursor + 2 > usable {
                return Err(Error::Payload { offset: cursor });
            }
            let offset = usize::from(block) * 8 + word * 2;
            if offset + 2 > size.logical {
                return Err(Error::Logical { offset });
            }
            logical[offset..offset + 2].copy_from_slice(&physical[cursor..cursor + 2]);
            cursor += 2;
        }
    }
    Ok(logical)
}

#[cfg(test)]
mod tests;
