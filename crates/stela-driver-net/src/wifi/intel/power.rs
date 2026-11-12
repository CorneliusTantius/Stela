// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Intel Wi-Fi ownership, persistence, reset and MAC-clock wake.
//! Adapted from pcie/gen1_2/trans.c, iwl-io.c and the pinned MAC configurations.
//! This leaves interrupts masked. It never starts ROM self-load, authenticates
//! firmware, calibrates a radio or claims station/carrier readiness.
use super::{firmware::Family, identity::Profile};
use crate::{
    Handoff,
    bus::{mmio::Mmio, pci::Bar},
};

const HW_IF: u32 = 0;
const INT: u32 = 8;
const INT_MASK: u32 = 12;
const FH_INT: u32 = 16;
const RESET: u32 = 0x20;
const GP: u32 = 0x24;
const HW_REV: u32 = 0x28;
const GIO: u32 = 0x3c;
const MAILBOX: u32 = 0x88;
const RF_ID: u32 = 0x9c;
const CHICKEN: u32 = 0x100;
const HPET: u32 = 0x240;
const LINK_PWR: u32 = 0x250;
const PRPH_WADDR: u32 = 0x444;
const MEM_RADDR: u32 = 0x40c;
const MEM_RDATA: u32 = 0x41c;
const PRPH_RADDR: u32 = 0x448;
const PRPH_WDATA: u32 = 0x44c;
const PRPH_RDATA: u32 = 0x450;
const OWN: u32 = 0x00400000;
const WAKE_ME: u32 = 0x08000000;
const MAC_CLOCK: u32 = 1;
const MAC_ACCESS: u32 = 8;
const GOING_TO_SLEEP: u32 = 0x10;
const HPM_HIPM_GEN_CFG: u32 = 0xa03458;
const POWER_GATE: u32 = 1;
const SLEEP: u32 = 1 << 1;
const FORCE_ACTIVE: u32 = 1 << 10;
const MAC_INIT: u32 = 1 << 6;
const MAC_STATUS: u32 = 1 << 20;
const BZ_MAC_ACCESS: u32 = 1 << 21;
const SW_RESET: u32 = 1 << 31;
/// CSR_RESET_REG_FLAG_SW_RESET, before the Bz family.
const SW_RESET_LEGACY: u32 = 1 << 7;
/// CSR_RESET_REG_FLAG_STOP_MASTER and CSR_RESET_REG_FLAG_MASTER_DISABLED.
const STOP_MASTER: u32 = 1 << 9;
const MASTER_DISABLED: u32 = 1 << 8;
/// CSR_GP_CNTRL_REG_FLAG_BUS_MASTER_DISABLE_REQ and _STATUS, from Bz on.
const BUS_MASTER_DISABLE_REQUEST: u32 = 1 << 29;
const BUS_MASTER_DISABLED: u32 = 1 << 28;
/// CSR_GP_CNTRL_REG_FLAG_INIT_DONE.
const INIT_DONE: u32 = 1 << 2;
const WFPM_CTRL: u32 = 0xa03030;
const WFPM_AUX_MAC_OWNER: u32 = 0x80000000;
const WFPM_OTP_CFG1: u32 = 0xa03098;
const WFPM_RSRCS_REQUEST: u32 = 0xa033f8;
const WFPM_RSRCS_ACK: u32 = 0xa033fc;
const CNVR_TOP: u32 = 1 << 6;
const SD_REG_VER: u32 = 0xa29600;
const SD_REG_VER_GEN2: u32 = 0xa2b800;
const CNVI_AUX_MISC_CHIP: u32 = 0xa200b0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError {
    Unavailable,
    Bounds,
    Mapping,
    Minimum(crate::bus::pci::power::Error),
}

/// A plain account for the boot log.
impl core::fmt::Display for AccessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "its registers are unavailable",
            Self::Bounds => "a register lies outside its register window",
            Self::Mapping => "its register window is not mapped as required",
            Self::Minimum(error) => return error.fmt(f),
        })
    }
}

/// Exclusive process-context CSR access and a real advancing delay source.
/// Native construction requires a checked MMIO/PCI ownership contract.
pub trait Csr {
    fn read32(&mut self, register: u32) -> Result<u32, AccessError>;
    fn write32(&mut self, register: u32, value: u32) -> Result<(), AccessError>;
    fn delay_us(&mut self, microseconds: u32) -> Result<(), AccessError>;
}

/// Direct access to an already mapped BAR. This does not manufacture an
/// exclusive PCI claim or attach a DMA domain/interrupt route.
pub struct NativeCsr {
    registers: Mmio,
    minimum: alloc::rc::Rc<dyn crate::bus::pci::power::Timer>,
}
impl NativeCsr {
    /// # Safety
    /// The caller owns this exact standalone Intel PCI function exclusively,
    /// including its BAR and reset/power state. All old DMA/submissions/IRQ work
    /// are stopped and drained, PCI MSI/MSI-X/legacy interrupt delivery is
    /// disabled, no firmware/AML/other driver accesses the BAR,
    /// and the real mapped uncached BAR stays reserved for this object's life.
    /// The supplied minimum provider retains the real platform grant for this
    /// context; a numeric clock cannot grant hardware minimum delays.
    pub unsafe fn new(
        handoff: &Handoff,
        bar: Option<Bar>,
        minimum: alloc::rc::Rc<dyn crate::bus::pci::power::Timer>,
    ) -> Result<Self, AccessError> {
        minimum.check().map_err(AccessError::Minimum)?;
        let registers =
            crate::registers(handoff, bar, 0, 4096).map_err(|_| AccessError::Mapping)?;
        Ok(Self { registers, minimum })
    }

    /// The CSRs at the start of an already mapped BAR0 window.
    ///
    /// # Safety
    /// As for [`Self::new`], with `window` the start of this function's
    /// uncached BAR0 mapping, which covers at least 4 KiB and stays mapped
    /// for this object's life.
    pub unsafe fn from_window(
        window: core::ptr::NonNull<u8>,
        minimum: alloc::rc::Rc<dyn crate::bus::pci::power::Timer>,
    ) -> Result<Self, AccessError> {
        minimum.check().map_err(AccessError::Minimum)?;
        if !(window.as_ptr() as usize).is_multiple_of(4096) {
            return Err(AccessError::Mapping);
        }
        Ok(Self {
            // SAFETY: covered by this function's own safety contract.
            registers: unsafe { Mmio::new(window.as_ptr() as u64, 4096) },
            minimum,
        })
    }
}
impl Csr for NativeCsr {
    fn read32(&mut self, register: u32) -> Result<u32, AccessError> {
        if !register.is_multiple_of(4) || register > 4092 {
            return Err(AccessError::Bounds);
        }
        Ok(self.registers.read32(register as usize))
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), AccessError> {
        if !register.is_multiple_of(4) || register > 4092 {
            return Err(AccessError::Bounds);
        }
        self.registers.write32(register as usize, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u32) -> Result<(), AccessError> {
        self.minimum
            .wait_us(u64::from(microseconds))
            .map_err(AccessError::Minimum)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Access(AccessError),
    FailedRead { register: u32, value: u32 },
    IdentityChanged,
    Timeout { register: u32, mask: u32 },
    Rejected { register: u32, mask: u32 },
    ManagementUnknown,
    ManagementConnected,
    PersistenceProtected,
    State,
}
impl From<AccessError> for Error {
    fn from(value: AccessError) -> Self {
        Self::Access(value)
    }
}

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Access(error) => return error.fmt(f),
            Self::FailedRead { register, value } => {
                return write!(
                    f,
                    "its register {register:#x} reads {value:#x}, a hardware failure value"
                );
            }
            Self::IdentityChanged => "its hardware or radio revision changed",
            Self::Timeout { register, mask } => {
                return write!(
                    f,
                    "its register {register:#x} did not set bits {mask:#x} in time"
                );
            }
            Self::Rejected { register, mask } => {
                return write!(f, "its register {register:#x} did not keep bits {mask:#x}");
            }
            Self::ManagementUnknown => "it is unknown whether the management engine is using it",
            Self::ManagementConnected => "the management engine is using it",
            Self::PersistenceProtected => "its persistence bit is write protected",
            Self::State => "it is not in the state this step needs",
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementSession {
    NotConnected,
    Connected,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Awake {
    pub family: Family,
    pub rf_killed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Cold,
    Awake(Awake),
    Poisoned,
}

/// What `get_crf_id` reads of the silicon behind the function, which
/// CSR_HW_REV and CSR_HW_RF_ID do not say.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Silicon {
    pub crf: u32,
    pub cnv: u32,
    pub wfpm: u32,
}

/// CSR_GP_CNTRL's NIC access bits, which moved on the Bz family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NicAccess {
    pub(super) request: u32,
    pub(super) mask: u32,
    pub(super) ready: u32,
}

impl NicAccess {
    pub(super) const fn of(family: Family) -> Self {
        if matches!(family, Family::Bz | Family::Sc) {
            Self {
                request: BZ_MAC_ACCESS,
                mask: MAC_STATUS,
                ready: MAC_STATUS,
            }
        } else {
            Self {
                request: MAC_ACCESS,
                mask: MAC_CLOCK | GOING_TO_SLEEP,
                ready: MAC_CLOCK,
            }
        }
    }
}

/// `iwl_trans_is_hw_error_value`: what a register or SRAM word reads as while
/// the device is in no state to answer.
pub(super) fn is_hardware_error(value: u32) -> bool {
    matches!(value & !0xf, 0xa5a5a5a0 | 0x5a5a5a50)
}

/// `iwl_trans_pcie_read_mem`: `N` words of device memory from `address`.
pub(super) fn read_memory<C: Csr, const N: usize>(
    io: C,
    family: Family,
    address: u32,
) -> Result<[u32; N], Error> {
    let mut nic = Nic {
        io,
        family,
        bisr: false,
    };
    nic.grab()?;
    nic.write(MEM_RADDR, address)?;
    let mut words = [0; N];
    for word in &mut words {
        *word = nic.io.read32(MEM_RDATA)?;
    }
    nic.release()?;
    Ok(words)
}

/// The registers every step of waking a function touches.
struct Nic<C: Csr> {
    io: C,
    family: Family,
    bisr: bool,
}

impl<C: Csr> Nic<C> {
    fn read(&mut self, register: u32) -> Result<u32, Error> {
        let value = self.io.read32(register)?;
        if value == u32::MAX || is_hardware_error(value) {
            return Err(Error::FailedRead { register, value });
        }
        Ok(value)
    }
    fn write(&mut self, register: u32, value: u32) -> Result<(), Error> {
        self.io.write32(register, value)?;
        Ok(())
    }
    fn set(&mut self, register: u32, mask: u32) -> Result<(), Error> {
        let value = self.read(register)?;
        self.write(register, value | mask)
    }
    fn set_checked(&mut self, register: u32, mask: u32) -> Result<(), Error> {
        self.set(register, mask)?;
        if self.read(register)? & mask != mask {
            return Err(Error::Rejected { register, mask });
        }
        Ok(())
    }
    fn poll(&mut self, register: u32, mask: u32, microseconds: u32) -> Result<(), Error> {
        // Same 10us interval/strict deadline as iwl_poll_bits_mask. A failed
        // register read is never a successful set-bit observation.
        for _ in 0..microseconds.div_ceil(10) {
            if self.read(register)? & mask == mask {
                return Ok(());
            }
            self.io.delay_us(10)?;
        }
        Err(Error::Timeout { register, mask })
    }
    fn ready(&mut self) -> Result<(), Error> {
        self.set(HW_IF, OWN)?;
        self.poll(HW_IF, OWN, 50)?;
        self.set(MAILBOX, 1 << 5)
    }
    fn ownership(&mut self, management: ManagementSession) -> Result<(), Error> {
        match self.ready() {
            Ok(()) => return Ok(()),
            Err(Error::Timeout { .. }) => {}
            Err(e) => return Err(e),
        }
        self.set_checked(LINK_PWR, 1 << 31)?;
        self.io.delay_us(1000)?;
        for _ in 0..10 {
            self.set(HW_IF, WAKE_ME)?;
            for _ in 0..750 {
                match self.ready() {
                    Ok(()) => return Ok(()),
                    Err(Error::Timeout { .. }) => {}
                    Err(e) => return Err(e),
                }
                match management {
                    ManagementSession::Connected => return Err(Error::ManagementConnected),
                    ManagementSession::Unknown => return Err(Error::ManagementUnknown),
                    ManagementSession::NotConnected => {}
                }
                self.io.delay_us(200)?;
            }
            self.io.delay_us(25000)?;
        }
        Err(Error::Timeout {
            register: HW_IF,
            mask: OWN,
        })
    }
    fn read_prph(&mut self, address: u32) -> Result<u32, Error> {
        let mask = if self.family >= Family::Ax210 {
            0x00ffffff
        } else {
            0x000fffff
        };
        self.write(PRPH_RADDR, (address & mask) | (3 << 24))?;
        self.read(PRPH_RDATA)
    }
    fn write_prph(&mut self, address: u32, value: u32) -> Result<(), Error> {
        let mask = if self.family >= Family::Ax210 {
            0x00ffffff
        } else {
            0x000fffff
        };
        self.write(PRPH_WADDR, (address & mask) | (3 << 24))?;
        self.write(PRPH_WDATA, value)
    }
    /// `__iwl_trans_pcie_grab_nic_access`.
    fn grab(&mut self) -> Result<(), Error> {
        let access = NicAccess::of(self.family);
        self.set(GP, access.request)?;
        self.io.delay_us(2)?;
        for _ in 0..1500 {
            if self.read(GP)? & access.mask == access.ready {
                return Ok(());
            }
            self.io.delay_us(10)?;
        }
        Err(Error::Timeout {
            register: GP,
            mask: access.mask,
        })
    }
    fn release(&mut self) -> Result<(), Error> {
        let gp = self.read(GP)?;
        self.write(GP, gp & !NicAccess::of(self.family).request)
    }
    /// `iwl_set_bits_prph` and `iwl_clear_bits_prph` under NIC access.
    fn update_prph(&mut self, address: u32, clear: u32, set: u32) -> Result<(), Error> {
        self.grab()?;
        let value = self.read_prph(address)?;
        self.write_prph(address, (value & !clear) | set)?;
        self.release()
    }
    /// `iwl_trans_pcie_sw_reset`.
    fn reset(&mut self, management: ManagementSession) -> Result<(), Error> {
        if self.family >= Family::Bz {
            self.set(GP, SW_RESET)?;
            self.io.delay_us(10000)?;
        } else {
            self.set(RESET, 0x80)?;
            self.io.delay_us(5000)?;
        }
        self.ownership(management)
    }
    /// `iwl_pcie_gen1_2_activate_nic`.
    fn activate(&mut self) -> Result<(), Error> {
        if self.bisr {
            self.io.delay_us(2000)?;
        }
        let wake = if self.family >= Family::Bz {
            self.set_checked(GP, BZ_MAC_ACCESS | MAC_INIT)?;
            self.poll(GP, MAC_STATUS, 25000)
        } else {
            self.set_checked(GP, 4)?;
            self.poll(GP, MAC_CLOCK, 25000)
        };
        if self.bisr {
            self.io.delay_us(200)?;
        }
        wake
    }
    /// `iwl_read_umac_prph_no_grab`: the UMAC's registers sit higher on the
    /// AX210 family and later.
    fn umac(&self, address: u32) -> u32 {
        if self.family >= Family::Ax210 {
            address + 0x300000
        } else {
            address
        }
    }
    /// `get_crf_id`, under the NIC access its caller holds.
    fn silicon(&mut self) -> Result<Silicon, Error> {
        if self.family == Family::Sc {
            let request = self.umac(WFPM_RSRCS_REQUEST);
            if self.read_prph(request)? & CNVR_TOP == 0 {
                return Ok(Silicon::default());
            }
            let acknowledge = self.umac(WFPM_RSRCS_ACK);
            for _ in 0..5000 {
                if self.read_prph(acknowledge)? & CNVR_TOP != 0 {
                    break;
                }
                self.io.delay_us(10)?;
            }
        }
        let control = self.umac(WFPM_CTRL);
        let value = self.read_prph(control)?;
        self.write_prph(control, value | WFPM_AUX_MAC_OWNER)?;
        let version = if self.family >= Family::Ax210 {
            SD_REG_VER_GEN2
        } else {
            SD_REG_VER
        };
        let crf = self.read_prph(version)?;
        let cnv = self.read_prph(CNVI_AUX_MISC_CHIP)?;
        let otp = self.umac(WFPM_OTP_CFG1);
        let wfpm = self.read_prph(otp)?;
        Ok(Silicon { crf, cnv, wfpm })
    }
}

impl<C: Csr> Csr for &mut C {
    fn read32(&mut self, register: u32) -> Result<u32, AccessError> {
        (**self).read32(register)
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), AccessError> {
        (**self).write32(register, value)
    }
    fn delay_us(&mut self, microseconds: u32) -> Result<(), AccessError> {
        (**self).delay_us(microseconds)
    }
}

/// Stop a function whatever its last owner left running, as
/// `_iwl_trans_pcie_gen2_stop_device` does: mask and acknowledge its
/// interrupts (`iwl_disable_interrupts`), ask its DMA master to stop
/// (`iwl_pcie_apm_stop_master`), reset the whole device
/// (`iwl_trans_pcie_sw_reset`) and clear INIT_DONE, or MAC_INIT from the Bz
/// family on, with the NIC access request. As in Linux, a master that does
/// not report stopped within 100 us is no failure: the reset follows and
/// stops it. Bus mastering stays off at the PCI level throughout.
pub fn stop<C: Csr>(io: &mut C, family: Family) -> Result<(), Error> {
    let mut nic = Nic {
        io,
        family,
        bisr: false,
    };
    nic.write(INT_MASK, 0)?;
    nic.write(INT, u32::MAX)?;
    nic.write(FH_INT, u32::MAX)?;
    let master = if family >= Family::Bz {
        nic.set(GP, BUS_MASTER_DISABLE_REQUEST)?;
        let stopped = nic.poll(GP, BUS_MASTER_DISABLED, 100);
        nic.io.delay_us(10000)?;
        stopped
    } else {
        nic.set(RESET, STOP_MASTER)?;
        nic.poll(RESET, MASTER_DISABLED, 100)
    };
    match master {
        Ok(()) | Err(Error::Timeout { .. }) => {}
        Err(error) => return Err(error),
    }
    if family >= Family::Bz {
        nic.set(GP, SW_RESET)?;
        nic.io.delay_us(10000)?;
    } else {
        nic.set(RESET, SW_RESET_LEGACY)?;
        nic.io.delay_us(5000)?;
    }
    let initialized = if family >= Family::Bz {
        MAC_INIT
    } else {
        INIT_DONE
    };
    let gp = nic.read(GP)?;
    nic.write(GP, gp & !(initialized | NicAccess::of(family).request))
}

/// `iwl_pci_probe`'s early NIC access: wake the function just far enough to
/// read what its CSRs do not say. A wake from reset follows for the boot.
pub fn read_silicon<C: Csr>(
    io: &mut C,
    family: Family,
    bisr: bool,
    management: ManagementSession,
) -> Result<Silicon, Error> {
    let mut nic = Nic { io, family, bisr };
    nic.ownership(management)?;
    nic.activate()?;
    nic.grab()?;
    let silicon = nic.silicon()?;
    nic.release()?;
    Ok(silicon)
}

pub struct Power<C: Csr> {
    nic: Nic<C>,
    profile: Profile,
    state: State,
    vector: bool,
}
impl<C: Csr> Power<C> {
    pub fn new(io: C, profile: Profile) -> Self {
        Self {
            nic: Nic {
                io,
                family: profile.family(),
                bisr: profile.bisr_workaround(),
            },
            profile,
            state: State::Cold,
            vector: false,
        }
    }
    /// `iwl_pcie_gen2_force_power_gating`, for an integrated 22000 device
    /// between its reset and its power-up.
    fn force_power_gating(&mut self, management: ManagementSession) -> Result<(), Error> {
        self.nic.activate()?;
        self.nic.update_prph(HPM_HIPM_GEN_CFG, 0, FORCE_ACTIVE)?;
        self.nic.io.delay_us(20)?;
        self.nic
            .update_prph(HPM_HIPM_GEN_CFG, 0, POWER_GATE | SLEEP)?;
        self.nic.io.delay_us(20)?;
        self.nic.update_prph(HPM_HIPM_GEN_CFG, FORCE_ACTIVE, 0)?;
        self.nic.reset(management)
    }
    fn clear_persistence(&mut self) -> Result<(), Error> {
        if self.profile.family() != Family::Ax200 {
            return Ok(());
        }
        // AX200's pinned MAC cfg has umac_prph_offset=0. AX210 uses
        // +0x300000, but has no persistence-clear step in this donor routine.
        let hpm = self.nic.read_prph(0xa03440)?;
        if hpm & (1 << 12) != 0 {
            if self.nic.read_prph(0xa04d00)? & (1 << 12) != 0 {
                return Err(Error::PersistenceProtected);
            }
            self.nic.write_prph(0xa03440, hpm & !(1 << 12))?;
            if self.nic.read_prph(0xa03440)? & (1 << 12) != 0 {
                return Err(Error::PersistenceProtected);
            }
        }
        Ok(())
    }
    fn run(&mut self, management: ManagementSession) -> Result<Awake, Error> {
        let observed = self.profile.observed();
        if self.nic.read(HW_REV)? != observed.hardware_revision
            || self.nic.read(RF_ID)? != observed.radio_id
        {
            return Err(Error::IdentityChanged);
        }
        // Registration/routing remains inactive. This is not a DMA quiescence
        // proof; the exclusive NativeCsr constructor requires old DMA stopped.
        self.nic.write(INT_MASK, 0)?;
        if self.nic.read(INT_MASK)? != 0 {
            return Err(Error::Rejected {
                register: INT_MASK,
                mask: u32::MAX,
            });
        }
        self.nic.write(INT, u32::MAX)?;
        self.nic.write(FH_INT, u32::MAX)?;
        self.nic.ownership(management)?;
        self.clear_persistence()?;
        self.nic.reset(management)?;
        if self.profile.platform().integrated && self.profile.family() == Family::Ax200 {
            self.force_power_gating(management)?;
        }
        self.nic.set_checked(CHICKEN, 0x00800000)?;
        self.nic.set_checked(HPET, 0xffff0000)?;
        self.nic.set_checked(HW_IF, 0x00080000)?;
        self.nic.set_checked(GIO, 2)?;
        self.nic.activate()?;
        Ok(Awake {
            family: self.profile.family(),
            rf_killed: self.nic.read(GP)? & 0x08000000 == 0,
        })
    }
    /// Consume only a successful MAC-clock epoch, transferring its exclusive
    /// CSR owner to the firmware/ring transport. This is not radio readiness.
    /// The function's first MSI-X vector reaches the host.
    pub fn with_vector(mut self) -> Self {
        self.vector = true;
        self
    }
    pub fn vector(&self) -> bool {
        self.vector
    }
    pub fn into_awake(self) -> Result<(C, Profile, Awake), Error> {
        if let State::Awake(status) = self.state {
            Ok((self.nic.io, self.profile, status))
        } else {
            Err(Error::State)
        }
    }
    /// Wake the MAC clock with interrupts masked. Retrying an uncertain reset
    /// requires a new checked ownership/reset epoch, never this used object.
    pub fn wake(&mut self, management: ManagementSession) -> Result<Awake, Error> {
        if self.state != State::Cold {
            return Err(Error::State);
        }
        self.state = State::Poisoned;
        let awake = self.run(management)?;
        self.state = State::Awake(awake);
        Ok(awake)
    }
}

#[cfg(test)]
mod tests;
