// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C source TX/RX SRAM geometry, priority queues and firmware H2C FIFO.
//! These are internal device SRAM addresses, never CPU/physical/DMA addresses.
//! Queue configuration is not a firmware command ACK, HCI start or radio ready.
use super::{
    chip::Rtw88,
    identity::Profile,
    io::{Error as HardwareError, Io},
    registers::*,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(HardwareError),
    UnsupportedChip,
    IdentityChanged,
    FirmwareNotReady,
    LltTimeout,
    H2cMismatch { write: u32, read: u32 },
}
impl From<HardwareError> for Error {
    fn from(e: HardwareError) -> Self {
        Self::Hardware(e)
    }
}

/// `RSVD_PG_H2C_EXTRAINFO_NUM`, `RSVD_PG_H2C_STATICINFO_NUM`,
/// `RSVD_PG_H2CQ_NUM` and `RSVD_PG_FW_TXBUF_NUM`; a 3081 CPU chip reserves
/// no instruction pages.
const H2C_EXTRA_PAGES: u16 = 24;
const H2C_STATIC_PAGES: u16 = 8;
const H2C_QUEUE_PAGES: u16 = 8;
const FIRMWARE_TX_PAGES: u16 = 4;
/// `C2H_PKT_BUF`, the receive FIFO's tail kept for firmware reports.
const C2H_PACKET_BUFFER: u32 = 256;

/// A chip's geometry from rtw_set_trx_fifo_info and its chip tables.
/// Every address is in 128-byte pages of internal device TX SRAM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    profile: Profile,
    pages: u16,
    reserved: u16,
    boundary: u16,
    csi: u16,
    firmware_tx: u16,
    cpu_instructions: u16,
    h2c_queue: u16,
    h2c_static: u16,
    h2c_extra: u16,
}
impl Geometry {
    pub fn for_profile(profile: Profile) -> Result<Self, Error> {
        let spec = profile.rtw88().ok_or(Error::UnsupportedChip)?;
        let pages = (spec.txff_bytes >> 7) as u16;
        let reserved = spec.driver_pages
            + H2C_EXTRA_PAGES
            + H2C_STATIC_PAGES
            + H2C_QUEUE_PAGES
            + FIRMWARE_TX_PAGES
            + spec.csi_pages;
        let csi = pages - spec.csi_pages;
        let firmware_tx = csi - FIRMWARE_TX_PAGES;
        let cpu_instructions = firmware_tx;
        let h2c_queue = cpu_instructions - H2C_QUEUE_PAGES;
        let h2c_static = h2c_queue - H2C_STATIC_PAGES;
        let h2c_extra = h2c_static - H2C_EXTRA_PAGES;
        let boundary = h2c_extra - spec.driver_pages;
        Ok(Self {
            profile,
            pages,
            reserved,
            boundary,
            csi,
            firmware_tx,
            cpu_instructions,
            h2c_queue,
            h2c_static,
            h2c_extra,
        })
    }
    pub fn profile(self) -> Profile {
        self.profile
    }
    pub fn pages(self) -> u16 {
        self.pages
    }
    pub fn reserved(self) -> u16 {
        self.reserved
    }
    pub fn boundary(self) -> u16 {
        self.boundary
    }
    pub fn csi_page(self) -> u16 {
        self.csi
    }
    pub fn firmware_tx_page(self) -> u16 {
        self.firmware_tx
    }
    pub fn cpu_instruction_page(self) -> u16 {
        self.cpu_instructions
    }
    pub fn h2c_queue_page(self) -> u16 {
        self.h2c_queue
    }
    pub fn h2c_static_page(self) -> u16 {
        self.h2c_static
    }
    pub fn h2c_extra_page(self) -> u16 {
        self.h2c_extra
    }
}

struct Attempt<'a, I: Io> {
    io: &'a mut I,
    complete: bool,
}
impl<I: Io> Drop for Attempt<'_, I> {
    fn drop(&mut self) {
        if !self.complete {
            self.io.quarantine();
        }
    }
}

/// Execute the source post-download TRX queue/FIFO/H2C initialization only.
///
/// # Safety
/// Requester firmware download completed and its MCU ready was
/// observed; all competing DMA/IRQ/reset/radio workers are stopped/drained.
/// Source HCI descriptor/index setup already configured every engine enabled
/// by CR=0xff with real validated native rings and kept requester-domain
/// DMA pins. An old/empty/unowned RX/TX base cannot satisfy this contract.
/// The PCI domain/queue ownership remains held. Successful LLT and
/// empty H2C pointer observations do not authorize DMA unmap or a ready radio.
pub unsafe fn configure<I: Io>(io: &mut I) -> Result<Geometry, Error> {
    let geometry = Geometry::for_profile(io.profile())?;
    let mut attempt = Attempt {
        io,
        complete: false,
    };
    let result = (|| {
        let identity = attempt.io.read32(REG_SYS_CFG1)?;
        if identity != geometry.profile.observed().sys_cfg1 || identity == u32::MAX {
            return Err(Error::IdentityChanged);
        }
        let control = attempt.io.read32(REG_MCUFW_CTRL)?;
        if control == u32::MAX || control & u32::from(FW_READY_MASK) != u32::from(FW_READY) {
            return Err(Error::FirmwareNotReady);
        }
        let spec = geometry.profile.rtw88().ok_or(Error::UnsupportedChip)?;
        map_queues(attempt.io, spec)?;
        priority_queues(attempt.io, geometry, spec)?;
        h2c(attempt.io, geometry)?;
        Ok(geometry)
    })();
    attempt.complete = result.is_ok();
    result
}
fn modify8<I: Io>(io: &mut I, register: u32, clear: u8, set: u8) -> Result<(), Error> {
    let value = io.read8(register)?;
    io.write8(register, (value & !clear) | set)?;
    Ok(())
}
fn map_queues<I: Io>(io: &mut I, spec: &Rtw88) -> Result<(), Error> {
    // The chip's PCIe rqpn row.
    io.write16(REG_TXDMA_PQ_MAP, spec.queue_map_register())?;
    io.write8(REG_CR, 0)?;
    io.write8(REG_CR, 0xff)?;
    io.write32(REG_H2CQ_CSR, BIT_H2CQ_FULL)?;
    Ok(())
}
fn priority_queues<I: Io>(io: &mut I, g: Geometry, spec: &Rtw88) -> Result<(), Error> {
    let t = spec.page_table;
    for (register, pages) in [
        (REG_FIFOPAGE_INFO_1, t.high),
        (REG_FIFOPAGE_INFO_2, t.low),
        (REG_FIFOPAGE_INFO_3, t.normal),
        (REG_FIFOPAGE_INFO_4, t.extra),
    ] {
        io.write16(register, pages)?;
    }
    // The public queue: TX pages less the reserved ones, the four priority
    // queues and the gap.
    let public = g.pages - g.reserved - t.high - t.normal - t.low - t.extra - t.gap;
    io.write16(REG_FIFOPAGE_INFO_5, public)?;
    let rqpn = io.read32(REG_RQPN_CTRL_2)?;
    io.write32(REG_RQPN_CTRL_2, rqpn | BIT_LD_RQPN)?;
    io.write16(REG_FIFOPAGE_CTRL_2, g.boundary)?;
    modify8(io, REG_FWHW_TXQ_CTRL + 2, 0, 16)?;
    io.write16(REG_BCNQ_BDNY_V1, g.boundary)?;
    io.write16(REG_FIFOPAGE_CTRL_2 + 2, g.boundary)?;
    io.write16(REG_BCNQ1_BDNY_V1, g.boundary)?;
    io.write32(REG_RXFF_BNDY, spec.rxff_bytes - C2H_PACKET_BUFFER - 1)?;
    modify8(io, REG_AUTO_LLT_V1, 0, 1)?;
    for _ in 0..1000 {
        let status = io.read32(REG_AUTO_LLT_V1)?;
        if status == u32::MAX {
            return Err(HardwareError::Register.into());
        }
        if status & 1 == 0 {
            io.write8(REG_CR + 3, 0)?;
            return Ok(());
        }
        io.delay_us(10);
    }
    Err(Error::LltTimeout)
}
fn h2c<I: Io>(io: &mut I, g: Geometry) -> Result<(), Error> {
    let address = u32::from(g.h2c_queue) << 7;
    let size = 8 << 7;
    for register in [REG_H2C_HEAD, REG_H2C_READ_ADDR] {
        let value = io.read32(register)?;
        io.write32(register, (value & 0xfffc_0000) | address)?;
    }
    let value = io.read32(REG_H2C_TAIL)?;
    io.write32(REG_H2C_TAIL, (value & 0xfffc_0000) | (address + size))?;
    modify8(io, REG_H2C_INFO, 3, 1)?;
    modify8(io, REG_H2C_INFO, 4, 4)?;
    modify8(io, REG_TXDMA_OFFSET_CHK + 1, 128, 128)?;
    let write = io.read32(REG_H2C_PKT_WRITEADDR)?;
    let read = io.read32(REG_H2C_PKT_READADDR)?;
    if write == u32::MAX || read == u32::MAX {
        return Err(HardwareError::Register.into());
    }
    let write = write & 0x3ffff;
    let read = read & 0x3ffff;
    let free = if write >= read {
        size.checked_sub(write - read)
    } else {
        Some(read - write)
    };
    if free != Some(size) {
        return Err(Error::H2cMismatch { write, read });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{identity::Observed, io};
    use super::*;
    use alloc::vec::Vec;
    struct Model {
        profile: Profile,
        registers: Vec<u8>,
        trace: Vec<u8>,
        operations: usize,
        fail_at: Option<usize>,
        stuck_llt: bool,
        removed_register: Option<u32>,
        quarantines: usize,
    }
    impl Model {
        fn new(seed: u8) -> Self {
            let profile = Profile::select(Observed {
                vendor: 0x10ec,
                device: 0xc822,
                subsystem_vendor: 0x17aa,
                subsystem_device: 0x1234,
                pci_revision: 1,
                sys_cfg1: 0x1000,
            })
            .unwrap();
            let mut m = Self {
                profile,
                registers: (0..0x170c)
                    .map(|i| (i * 37 + usize::from(seed)) as u8)
                    .collect(),
                trace: Vec::new(),
                operations: 0,
                fail_at: None,
                stuck_llt: false,
                removed_register: None,
                quarantines: 0,
            };
            m.set(REG_SYS_CFG1, 4, 0x1000);
            m.set(REG_MCUFW_CTRL, 4, 0xc078 | (u32::from(seed & 3) << 12));
            m.set(REG_H2C_PKT_READADDR, 4, 0x3e100);
            m.set(REG_H2C_PKT_WRITEADDR, 4, 0x3e100);
            m
        }
        fn get(&self, r: u32, n: usize) -> u32 {
            let mut b = [0; 4];
            b[..n].copy_from_slice(&self.registers[r as usize..r as usize + n]);
            u32::from_le_bytes(b)
        }
        fn set(&mut self, r: u32, n: usize, v: u32) {
            self.registers[r as usize..r as usize + n].copy_from_slice(&v.to_le_bytes()[..n]);
        }
        fn operation(&mut self) -> Result<(), io::Error> {
            let index = self.operations;
            self.operations += 1;
            if self.fail_at == Some(index) || self.quarantines != 0 {
                Err(io::Error::Register)
            } else {
                Ok(())
            }
        }
        fn record(&mut self, tag: u32, r: u32, v: u32) {
            for w in [tag, r, v] {
                self.trace.extend_from_slice(&w.to_le_bytes());
            }
        }
        fn read(&mut self, r: u32, n: usize) -> Result<u32, io::Error> {
            self.operation()?;
            let value = if self.removed_register == Some(r) {
                if n == 4 {
                    u32::MAX
                } else {
                    (1u32 << (8 * n)) - 1
                }
            } else {
                self.get(r, n)
            };
            self.record(n as u32, r, value);
            Ok(value)
        }
        fn write(&mut self, r: u32, n: usize, v: u32) -> Result<(), io::Error> {
            self.operation()?;
            self.record(4 + n as u32, r, v);
            self.set(
                r,
                n,
                if r == 0x208 && n == 1 && !self.stuck_llt {
                    v & !1
                } else {
                    v
                },
            );
            Ok(())
        }
    }
    // SAFETY: stopped synchronous native register-state model, not physical
    // HCI initialization or a claim that all real radio DMA rings exist.
    unsafe impl Io for Model {
        fn profile(&self) -> Profile {
            self.profile
        }
        fn read8(&mut self, r: u32) -> Result<u8, io::Error> {
            self.read(r, 1).map(|v| v as u8)
        }
        fn read16(&mut self, r: u32) -> Result<u16, io::Error> {
            self.read(r, 2).map(|v| v as u16)
        }
        fn read32(&mut self, r: u32) -> Result<u32, io::Error> {
            self.read(r, 4)
        }
        fn write8(&mut self, r: u32, v: u8) -> Result<(), io::Error> {
            self.write(r, 1, v.into())
        }
        fn write16(&mut self, r: u32, v: u16) -> Result<(), io::Error> {
            self.write(r, 2, v.into())
        }
        fn write32(&mut self, r: u32, v: u32) -> Result<(), io::Error> {
            self.write(r, 4, v)
        }
        fn delay_us(&mut self, us: u64) {
            self.record(9, 0, us as u32);
        }
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
            panic!("FIFO cannot submit DMA")
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            panic!("FIFO cannot ACK DMA")
        }
        fn quarantine(&mut self) {
            self.quarantines += 1;
        }
    }
    #[test]
    fn source_sram_reservations_and_empty_h2c_preserve_unrelated_bits() {
        let mut m = Model::new(0xa5);
        let head_upper = m.get(REG_H2C_HEAD, 4) & 0xfffc_0000;
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        let g = unsafe { configure(&mut m) }.unwrap();
        assert_eq!(g.pages(), 2048);
        assert_eq!(g.reserved(), 110);
        assert_eq!(g.boundary(), 0x792);
        assert_eq!(g.csi_page(), 0x7ce);
        assert_eq!(g.firmware_tx_page(), 0x7ca);
        assert_eq!(g.cpu_instruction_page(), 0x7ca);
        assert_eq!(g.h2c_queue_page(), 0x7c2);
        assert_eq!(g.h2c_static_page(), 0x7ba);
        assert_eq!(g.h2c_extra_page(), 0x7a2);
        assert_eq!(m.get(REG_TXDMA_PQ_MAP, 2), 0xc5a0);
        assert_eq!(m.get(REG_FIFOPAGE_INFO_5, 2), 1681);
        assert_eq!(m.get(REG_RXFF_BNDY, 4), 0x5eff);
        assert_eq!(m.get(REG_H2C_HEAD, 4), head_upper | 0x3e100);
        assert_eq!(m.get(REG_H2C_TAIL, 4) & 0x3ffff, 0x3e500);
        assert_eq!(m.get(REG_FIFOPAGE_CTRL_2, 2), 0x792);
        assert_eq!(m.quarantines, 0);
    }
    #[test]
    fn every_uncertain_register_operation_quarantines_without_later_success() {
        let mut baseline = Model::new(11);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe { configure(&mut baseline) }.unwrap();
        for at in 0..baseline.operations {
            let mut m = Model::new(11);
            m.fail_at = Some(at);
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            assert!(unsafe { configure(&mut m) }.is_err(), "op={at}");
            assert_eq!(m.operations, at + 1);
            assert_eq!(m.quarantines, 1);
        }
    }
    #[test]
    fn identity_mcu_llt_h2c_and_removal_failures_are_explicit() {
        for mode in 0..6 {
            let mut m = Model::new(11);
            match mode {
                0 => m.set(REG_SYS_CFG1, 4, 0),
                1 => m.set(REG_MCUFW_CTRL, 4, 0),
                2 => m.stuck_llt = true,
                3 => m.set(REG_H2C_PKT_WRITEADDR, 4, 0x3e101),
                4 => m.set(REG_H2C_PKT_READADDR, 4, u32::MAX),
                _ => m.removed_register = Some(0x208),
            }
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            let error = unsafe { configure(&mut m) }.unwrap_err();
            assert_eq!(
                error,
                match mode {
                    0 => Error::IdentityChanged,
                    1 => Error::FirmwareNotReady,
                    2 => Error::LltTimeout,
                    3 => Error::H2cMismatch {
                        write: 0x3e101,
                        read: 0x3e100
                    },
                    _ => Error::Hardware(io::Error::Register),
                }
            );
            assert_eq!(m.quarantines, 1);
            assert!(m.operations < 1100);
        }
        let mut m = Model::new(11);
        let mut observation = m.profile.observed();
        observation.device = 0xb852;
        m.profile = Profile::select(observation).unwrap();
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        assert_eq!(unsafe { configure(&mut m) }, Err(Error::UnsupportedChip));
        assert_eq!(m.operations, 0);
        assert_eq!(m.quarantines, 0);
        let mut m = Model::new(11);
        m.set(REG_H2C_PKT_WRITEADDR, 4, 0x3ffff);
        m.set(REG_H2C_PKT_READADDR, 4, 0);
        assert_eq!(
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            unsafe { configure(&mut m) },
            Err(Error::H2cMismatch {
                write: 0x3ffff,
                read: 0
            })
        );
        assert_eq!(m.quarantines, 1);
    }
    #[test]
    #[ignore = "oracle: STELA_REALTEK_WIFI_FIFO_ORACLE"]
    fn all_access_widths_bits_and_geometry_match_unchanged_c_helpers() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_FIFO_ORACLE").unwrap()).unwrap();
        let mut offset = 0;
        for seed in 0..16 {
            let mut m = Model::new(seed);
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            let g = unsafe { configure(&mut m) }.unwrap();
            for value in [
                16,
                g.pages,
                g.reserved,
                g.boundary,
                g.boundary,
                g.boundary,
                g.csi,
                g.firmware_tx,
                g.cpu_instructions,
                g.h2c_queue,
                g.h2c_static,
                g.h2c_extra,
            ] {
                m.trace.extend_from_slice(&u32::from(value).to_le_bytes());
            }
            let length = u32::from_le_bytes(trace[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            assert_eq!(m.trace, trace[offset..offset + length], "seed={seed}");
            offset += length;
        }
        assert_eq!(offset, trace.len());
    }
}
