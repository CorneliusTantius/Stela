// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! The RTL8821C's operations on a register file.
use super::*;
use crate::wifi::realtek::{
    identity::{Observed, Profile},
    io,
};
use alloc::{vec, vec::Vec};

/// An RTL8821CE at `cut`.
pub(crate) fn profile(cut: u8) -> Profile {
    Profile::select(Observed {
        vendor: 0x10ec,
        device: 0xc821,
        subsystem_vendor: 0x17aa,
        subsystem_device: 0x1234,
        pci_revision: 1,
        sys_cfg1: u32::from(cut) << 12,
    })
    .unwrap()
}

/// Bytes behind the BAR, each write recorded as (width, register, value).
pub(crate) struct Regs {
    pub profile: Profile,
    pub bytes: Vec<u8>,
    pub writes: Vec<(u8, u32, u32)>,
}

impl Regs {
    /// Every byte seeded so a set or clear of the wrong bits shows.
    pub fn new(cut: u8) -> Self {
        Self {
            profile: profile(cut),
            bytes: (0..0x4000).map(|i| (i * 37 + 11) as u8).collect(),
            writes: vec![],
        }
    }
    pub fn get(&self, register: u32, width: usize) -> u32 {
        let mut b = [0; 4];
        let at = register as usize;
        b[..width].copy_from_slice(&self.bytes[at..at + width]);
        u32::from_le_bytes(b)
    }
    pub fn set(&mut self, register: u32, width: usize, value: u32) {
        let at = register as usize;
        self.bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }
    fn store(&mut self, register: u32, width: usize, value: u32) -> Result<(), io::Error> {
        self.writes.push((width as u8, register, value));
        self.set(register, width, value);
        Ok(())
    }
}

// SAFETY: a byte array; nothing reaches hardware.
unsafe impl Io for Regs {
    fn profile(&self) -> Profile {
        self.profile
    }
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Ok(self.get(register, 1) as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Ok(self.get(register, 2) as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        Ok(self.get(register, 4))
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
        self.store(register, 1, value.into())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
        self.store(register, 2, value.into())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.store(register, 4, value)
    }
    fn delay_us(&mut self, _: u64) {}
    fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
        Err(io::Error::Register)
    }
    unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
        Err(io::Error::Register)
    }
    fn quarantine(&mut self) {}
}

#[test]
fn mac_init_writes_rtw8821c_mac_init() {
    let mut r = Regs::new(1);
    let before = |r: &Regs, register| r.get(register, 1);
    let hang = before(&r, REG_TX_HANG_CTRL);
    let timer = before(&r, REG_TIMER0_SRC_SEL);
    let ptcl = before(&r, REG_TX_PTCL_CTRL + 1);
    mac_init(&mut r).unwrap();
    assert_eq!(r.get(REG_AMPDU_MAX_TIME_V1, 1), 0x70);
    assert_eq!(r.get(REG_TX_HANG_CTRL, 1), hang | 4);
    assert_eq!(r.get(REG_PRECNT_CTRL, 2), 0x1e4 | 0x800);
    assert_eq!(r.get(REG_PROT_MODE_CTRL, 4), 0x2020_08ff);
    assert_eq!(r.get(REG_BAR_MODE_CTRL + 2, 2), 0x0801);
    assert_eq!(r.get(REG_FAST_EDCA_VOVI_SETTING, 1), 6);
    assert_eq!(r.get(REG_FAST_EDCA_BEBK_SETTING + 2, 1), 6);
    assert_eq!(r.get(REG_INIRTS_RATE_SEL, 1) & 0x20, 0x20);
    assert_eq!(r.get(REG_TIMER0_SRC_SEL, 1), timer & !0x70);
    assert_eq!(r.get(REG_TXPAUSE, 2), 0);
    assert_eq!(r.get(REG_SLOT, 1), 9);
    assert_eq!(r.get(REG_PIFS, 1), 0x19);
    assert_eq!(r.get(REG_SIFS, 4), 0x1010_0e0a);
    assert_eq!(r.get(REG_EDCA_VO_PARAM + 2, 2), 0x186);
    assert_eq!(r.get(REG_EDCA_VI_PARAM + 2, 2), 0x3bc);
    assert_eq!(r.get(REG_RD_NAV_NXT, 4), 0x001b_0005);
    assert_eq!(r.get(REG_RXTSF_OFFSET_CCK, 2), 0x3030);
    assert_eq!(r.get(REG_BCN_CTRL, 1) & 8, 8);
    assert_eq!(r.get(REG_TBTT_PROHIBIT, 4), 0x6404);
    assert_eq!(r.get(REG_DRVERLYINT, 1), 4);
    assert_eq!(r.get(REG_BCNDMATIM, 1), 2);
    assert_eq!(r.get(REG_TX_PTCL_CTRL + 1, 1), ptcl & !0x10);
    assert_eq!(r.get(REG_RXFLTMAP0, 2), 0xffff);
    assert_eq!(r.get(REG_RXFLTMAP1, 2), 0x0fff);
    assert_eq!(r.get(REG_RXFLTMAP2, 2), 0xffff);
    assert_eq!(r.get(REG_RCR, 4), 0xe400_220e);
    assert_eq!(r.get(REG_RX_PKT_LIMIT, 1), 0x18);
    assert_eq!(r.get(REG_TCR + 1, 2), 0x3030);
    assert_eq!(r.get(REG_ACKTO_CCK, 1), 0x40);
    assert_eq!(r.get(REG_WMAC_TRXPTCL_CTL_H, 1) & 2, 2);
    assert_eq!(r.get(REG_SND_PTCL_CTRL, 1) & 0x40, 0x40);
    assert_eq!(r.get(REG_WMAC_OPTION_FUNCTION + 8, 4), 0xb081_0041);
    assert_eq!(r.get(REG_WMAC_OPTION_FUNCTION + 4, 1), 0x98);
}
