// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! The chip's half of PCIe link power: `rtw_pci_phy_cfg`, `rtw_pci_interface_cfg`
//! and `rtw_pci_link_ps`. Two modules make up CLKREQ and ASPM here. One follows
//! config space; the other does the work, starts off, and may lose the device
//! if turned on where the host does not support it, so it follows what the
//! host enabled, and L1 only runs under leisure power save.
use super::{
    dynamic::set_mask,
    io::{Error, Io},
};

/// `REG_DBI_WDATA_V1`, `REG_DBI_RDATA_V1` and `REG_DBI_FLAG_V1`.
const REG_DBI_WRITE: u32 = 0x3e8;
const REG_DBI_READ: u32 = 0x3ec;
const REG_DBI_FLAG: u32 = 0x3f0;
/// `BIT_DBI_RFLAG` and `BIT_DBI_WFLAG` as bytes at the flag register's third.
const DBI_READING: u8 = 1 << 1;
const DBI_WRITING: u8 = 1 << 0;
/// `BITS_DBI_ADDR_MASK`, and `BITS_DBI_WREN`'s place.
const DBI_ADDRESS: u16 = 0xffc;
const DBI_BYTE_ENABLE: u32 = 12;
/// `RTW_PCI_WR_RETRY_CNT`, 10 us apart.
const DBI_TRIES: u32 = 20;
const DBI_WAIT_US: u64 = 10;
/// `RTK_PCIE_LINK_CFG` with `BIT_CLKREQ_SW_EN` and `BIT_L1_SW_EN`.
const LINK_CONFIG: u16 = 0x719;
const CLOCK_REQUEST: u8 = 1 << 4;
const L1: u8 = 1 << 3;
/// `RTK_PCIE_CLKDLY_CTRL`.
const CLOCK_DELAY: u16 = 0x725;
/// `PCI_EXP_LNKCTL_ASPM_L1` and `PCI_EXP_LNKCTL_CLKREQ_EN`.
const HOST_L1: u16 = 1 << 1;
const HOST_CLOCK_REQUEST: u16 = 1 << 8;
/// `REG_HCI_MIX_CFG`'s `BIT_PCIE_EMAC_PDN_AUX_TO_FAST_CLK`, from cut D.
const REG_HCI_MIX_CFG: u32 = 0x3fc;
const AUX_TO_FAST_CLOCK: u32 = 1 << 26;
const CUT_D: u8 = 3;
/// `REG_ANAPARSW_MAC_0`'s `BIT_CF_L_V2`, which `rfe_option` 5 sets to 1.
const REG_ANAPARSW_MAC_0: u32 = 0x1010;
const SWITCHER_CURRENT: u32 = 3 << 28;
const CURRENT_RFE: u8 = 5;

fn await_dbi<I: Io>(io: &mut I) -> Result<bool, Error> {
    for _ in 0..DBI_TRIES {
        if io.read8(REG_DBI_FLAG + 2)? == 0 {
            return Ok(true);
        }
        io.delay_us(DBI_WAIT_US);
    }
    Ok(false)
}

/// `rtw_dbi_read8`: `None` when the bridge never finishes.
fn dbi_read8<I: Io>(io: &mut I, address: u16) -> Result<Option<u8>, Error> {
    io.write16(REG_DBI_FLAG, address & DBI_ADDRESS)?;
    io.write8(REG_DBI_FLAG + 2, DBI_READING)?;
    if !await_dbi(io)? {
        return Ok(None);
    }
    io.read8(REG_DBI_READ + u32::from(address & 3)).map(Some)
}

/// `rtw_dbi_write8`: false when the bridge never finishes.
fn dbi_write8<I: Io>(io: &mut I, address: u16, data: u8) -> Result<bool, Error> {
    let byte = address & 3;
    io.write8(REG_DBI_WRITE + u32::from(byte), data)?;
    io.write16(
        REG_DBI_FLAG,
        (address & DBI_ADDRESS) | (1 << (DBI_BYTE_ENABLE + u32::from(byte))),
    )?;
    io.write8(REG_DBI_FLAG + 2, DBI_WRITING)?;
    await_dbi(io)
}

/// Set or clear `bits` of the link configuration.
fn set_link_bits<I: Io>(io: &mut I, bits: u8, on: bool) -> Result<bool, Error> {
    let Some(value) = dbi_read8(io, LINK_CONFIG)? else {
        return Ok(false);
    };
    let value = if on { value | bits } else { value & !bits };
    dbi_write8(io, LINK_CONFIG, value)
}

/// L1 as the host's link allows it. Gone once the bridge to config space has
/// failed.
#[derive(Debug)]
pub struct Link {
    l1: bool,
    answered: bool,
}

impl Link {
    /// `rtw_pci_interface_cfg` and what `rtw_pci_phy_cfg` does for this chip,
    /// whose PCIe PHY tables are empty, on a link under `host_control`.
    pub fn configure<I: Io>(
        io: &mut I,
        cut: u8,
        rfe: u8,
        host_control: u16,
        aspm: bool,
    ) -> Result<Self, Error> {
        if cut >= CUT_D {
            set_mask(io, REG_HCI_MIX_CFG, AUX_TO_FAST_CLOCK, 1)?;
        }
        let mut answered = dbi_write8(io, CLOCK_DELAY, 0)?;
        // `rtw_pci_disable_aspm` leaves both modules as they are.
        if aspm && host_control & HOST_CLOCK_REQUEST != 0 {
            answered &= set_link_bits(io, CLOCK_REQUEST, true)?;
        }
        if rfe == CURRENT_RFE {
            set_mask(io, REG_ANAPARSW_MAC_0, SWITCHER_CURRENT, 1)?;
        }
        Ok(Self {
            l1: aspm && answered && host_control & HOST_L1 != 0,
            answered,
        })
    }

    /// False when the bridge to config space failed. rtw88 logs that and goes
    /// on; here L1 stays off, and the link works as it did.
    pub fn answered(&self) -> bool {
        self.answered
    }

    /// `rtw_pci_link_ps`. The worker only comes here on a change of leisure
    /// power save, so no count of users is needed.
    pub fn set_l1<I: Io>(&mut self, io: &mut I, on: bool) -> Result<(), Error> {
        if self.l1 && !set_link_bits(io, L1, on)? {
            self.l1 = false;
            self.answered = false;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::realtek::{
        identity::{Profile, tests::profile},
        io,
    };
    use alloc::collections::BTreeMap;

    /// Registers as bytes, and config space behind the bridge.
    #[derive(Default)]
    struct Bus {
        bytes: BTreeMap<u32, u8>,
        config: BTreeMap<u16, u8>,
        silent: bool,
    }

    impl Bus {
        fn get(&self, register: u32) -> u8 {
            self.bytes.get(&register).copied().unwrap_or(0)
        }
        fn word(&self, register: u32) -> u32 {
            u32::from_le_bytes([0, 1, 2, 3].map(|at| self.get(register + at)))
        }
        fn link(&self) -> u8 {
            self.config.get(&LINK_CONFIG).copied().unwrap_or(0)
        }
        /// The third byte of the flag register, which starts the bridge.
        fn start(&mut self, flag: u8) {
            let word = u16::from_le_bytes([self.get(REG_DBI_FLAG), self.get(REG_DBI_FLAG + 1)]);
            let base = word & DBI_ADDRESS;
            if flag == DBI_READING {
                // A read names the word, and the byte comes off its lanes.
                for byte in 0..4u16 {
                    let held = self.config.get(&(base + byte)).copied().unwrap_or(0);
                    self.bytes.insert(REG_DBI_READ + u32::from(byte), held);
                }
                return;
            }
            let byte = (word >> DBI_BYTE_ENABLE).trailing_zeros() as u16;
            let data = self.get(REG_DBI_WRITE + u32::from(byte));
            self.config.insert(base + byte, data);
        }
    }

    // SAFETY: nothing here reaches hardware; this is a map of bytes.
    unsafe impl Io for Bus {
        fn profile(&self) -> Profile {
            profile()
        }
        fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
            Ok(if register == REG_DBI_FLAG + 2 {
                u8::from(self.silent)
            } else {
                self.get(register)
            })
        }
        fn read16(&mut self, _: u32) -> Result<u16, io::Error> {
            Ok(0)
        }
        fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
            Ok(self.word(register))
        }
        fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
            if register == REG_DBI_FLAG + 2 {
                self.start(value);
            } else {
                self.bytes.insert(register, value);
            }
            Ok(())
        }
        fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
            for (at, byte) in value.to_le_bytes().into_iter().enumerate() {
                self.bytes.insert(register + at as u32, byte);
            }
            Ok(())
        }
        fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
            for (at, byte) in value.to_le_bytes().into_iter().enumerate() {
                self.bytes.insert(register + at as u32, byte);
            }
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
    fn the_chip_follows_only_what_the_host_enabled() {
        let mut bus = Bus::default();
        bus.config.insert(CLOCK_DELAY, 0x55);
        Link::configure(&mut bus, 0, 0, 0, true).unwrap();
        assert_eq!(bus.link(), 0, "the host enabled neither");
        assert_eq!(bus.config[&CLOCK_DELAY], 0, "REFCLK calibrates itself");
        Link::configure(&mut bus, 0, 0, HOST_CLOCK_REQUEST, true).unwrap();
        assert_eq!(bus.link(), CLOCK_REQUEST);
    }

    #[test]
    fn l1_runs_only_under_power_save_on_a_link_that_allows_it() {
        let mut bus = Bus::default();
        bus.config.insert(LINK_CONFIG, 0x81);
        let mut link = Link::configure(&mut bus, 0, 0, HOST_L1, true).unwrap();
        assert_eq!(bus.link(), 0x81, "off until power save begins");
        link.set_l1(&mut bus, true).unwrap();
        assert_eq!(bus.link(), 0x81 | L1);
        link.set_l1(&mut bus, false).unwrap();
        assert_eq!(bus.link(), 0x81);

        let mut bus = Bus::default();
        let mut link = Link::configure(&mut bus, 0, 0, 0, true).unwrap();
        link.set_l1(&mut bus, true).unwrap();
        assert_eq!(bus.link(), 0, "the host never enabled L1");
    }

    #[test]
    fn a_system_with_aspm_disabled_keeps_both_modules_off() {
        let mut bus = Bus::default();
        bus.config.insert(CLOCK_DELAY, 0x55);
        let mut link =
            Link::configure(&mut bus, 0, 0, HOST_CLOCK_REQUEST | HOST_L1, false).unwrap();
        assert_eq!(bus.link(), 0, "no CLKREQ though the host enabled it");
        assert_eq!(bus.config[&CLOCK_DELAY], 0, "the clock delay is not ASPM");
        link.set_l1(&mut bus, true).unwrap();
        assert_eq!(bus.link(), 0, "no L1 under power save");
        assert!(link.answered());
    }

    #[test]
    fn a_later_cut_and_one_board_take_their_own_settings() {
        let mut bus = Bus::default();
        Link::configure(&mut bus, 2, 4, 0, true).unwrap();
        assert_eq!(bus.word(REG_HCI_MIX_CFG), 0);
        assert_eq!(bus.word(REG_ANAPARSW_MAC_0), 0);
        Link::configure(&mut bus, CUT_D, CURRENT_RFE, 0, true).unwrap();
        assert_eq!(bus.word(REG_HCI_MIX_CFG), AUX_TO_FAST_CLOCK);
        assert_eq!(bus.word(REG_ANAPARSW_MAC_0), 1 << 28);
    }

    #[test]
    fn a_silent_bridge_leaves_l1_off_and_says_so() {
        let mut bus = Bus::default();
        let mut link = Link::configure(&mut bus, 0, 0, HOST_L1, true).unwrap();
        assert!(link.answered());
        bus.silent = true;
        link.set_l1(&mut bus, true).unwrap();
        assert!(!link.answered());
        bus.silent = false;
        link.set_l1(&mut bus, true).unwrap();
        assert_eq!(bus.link(), 0, "no further attempt");
    }
}
