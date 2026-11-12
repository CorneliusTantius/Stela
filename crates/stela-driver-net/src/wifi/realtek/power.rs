// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C source MAC power sequence, before firmware upload. This controls
//! power/reset registers and never grants RF/channel/Link readiness.
use super::{
    chip::Rtw88,
    io::{Error as HardwareError, Io, sleep},
    registers::*,
};
pub(super) mod tables;

const POLLS: usize = 20_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(HardwareError),
    UnsupportedChip,
    UnsupportedCut(u8),
    IdentityChanged,
    PollTimeout { register: u32, mask: u8, target: u8 },
    UnsupportedCommand(u8),
    UnsupportedBase(u8),
    MissingEnd,
    InvalidPowerState,
}
impl From<HardwareError> for Error {
    fn from(e: HardwareError) -> Self {
        Self::Hardware(e)
    }
}

/// One row of a chip's power sequence (`rtw_pwr_seq_cmd`).
#[derive(Clone, Copy, Debug)]
pub struct Step {
    offset: u16,
    cut: u8,
    interface: u8,
    base: u8,
    command: u8,
    mask: u8,
    value: u8,
}
impl Step {
    // Same field order as the unchanged source command structure/table rows.
    const fn new(
        offset: u16,
        cut: u8,
        interface: u8,
        base: u8,
        command: u8,
        mask: u8,
        value: u8,
    ) -> Self {
        Self {
            offset,
            cut,
            interface,
            base,
            command,
            mask,
            value,
        }
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

/// Execute source pre-system configuration, on/off power tables and CPU/DDMA
/// system configuration. Unknown cuts are refused before I/O: the
/// donor's eight-bit cut mask cannot represent cut >= 7 and would skip rows.
///
/// # Safety
/// The selected RTL8822C requester has exclusive ownership, isolated DMA and
/// all previous DMA/IRQ/submission workers stopped and drained. No powered
/// radio operation or other caller races this sequence; the beacon
/// queue is fresh/idle. Power transitions do not prove IOMMU invalidation or
/// authorize releasing any queue/domain/pin. On error the I/O owner is
/// quarantined, and no retry is allowed without independent reset/ownership.
pub async unsafe fn on<I: Io>(io: &mut I) -> Result<(), Error> {
    let profile = io.profile();
    let Some(spec) = profile.rtw88() else {
        return Err(Error::UnsupportedChip);
    };
    if profile.cut() >= 7 {
        return Err(Error::UnsupportedCut(profile.cut()));
    }
    let mut attempt = Attempt {
        io,
        complete: false,
    };
    let result = async {
        let observed = attempt.io.read32(REG_SYS_CFG1)?;
        if observed != profile.observed().sys_cfg1 || observed == u32::MAX {
            return Err(Error::IdentityChanged);
        }
        pre_system(attempt.io)?;
        if !switch(attempt.io, spec, true).await? {
            switch(attempt.io, spec, false).await?;
            pre_system(attempt.io)?;
            if !switch(attempt.io, spec, true).await? {
                return Err(Error::InvalidPowerState);
            }
        }
        system(attempt.io, spec)
    }
    .await;
    attempt.complete = result.is_ok();
    result
}

fn modify8<I: Io>(io: &mut I, r: u32, clear: u8, set: u8) -> Result<(), Error> {
    let value = io.read8(r)?;
    io.write8(r, (value & !clear) | set)?;
    Ok(())
}
fn modify32<I: Io>(io: &mut I, r: u32, clear: u32, set: u32) -> Result<(), Error> {
    let value = io.read32(r)?;
    io.write32(r, (value & !clear) | set)?;
    Ok(())
}
fn pre_system<I: Io>(io: &mut I) -> Result<(), Error> {
    io.write8(REG_RSV_CTRL, 0)?;
    modify32(io, REG_HCI_OPT_CTRL, 0, 1 << 8)?;
    modify32(io, REG_PAD_CTRL1, 0, 1 << 29 | 1 << 28)?;
    modify32(io, REG_LED_CFG, 1 << 26 | 1 << 25, 0)?;
    modify32(io, REG_GPIO_MUXCFG, 0, 1 << 2)?;
    modify8(io, REG_SYS_FUNC_EN, 3, 0)?;
    modify8(io, REG_RF_CTRL, 7, 0)?;
    modify32(io, REG_WLRF1, 7 << 24, 0)
}
fn system<I: Io>(io: &mut I, spec: &Rtw88) -> Result<(), Error> {
    modify32(io, REG_CPU_DMEM_CON, 0, 1 << 16 | 1 << 8)?;
    modify8(io, REG_SYS_FUNC_EN + 1, 0, spec.sys_func_en)?;
    let value = (io.read8(REG_CR_EXT + 3)? & 0xf0) | 0x0c;
    io.write8(REG_CR_EXT + 3, value)?;
    let control = io.read32(REG_MCUFW_CTRL)?;
    if control & (1 << 20) != 0 {
        io.write32(REG_MCUFW_CTRL, control & !(1 << 20))?;
        modify32(io, REG_GPIO_MUXCFG, 1 << 19, 0)?;
    }
    Ok(())
}
async fn switch<I: Io>(io: &mut I, spec: &Rtw88, on: bool) -> Result<bool, Error> {
    let rpwm = io.read8(RPWM_PCIE)?;
    if io.read16(REG_MCUFW_CTRL)? == FW_READY {
        io.write8(RPWM_PCIE, (rpwm ^ BIT_RPWM_TOGGLE) & BIT_RPWM_TOGGLE)?;
    }
    let current = io.read8(REG_CR)? != 0xea;
    if on == current {
        return Ok(false);
    }
    let cut_mask = 1u8 << (io.profile().cut() + 1);
    let sequence = if on { spec.power_on } else { spec.power_off };
    for table in sequence {
        run(io, table, cut_mask).await?;
    }
    Ok(true)
}
async fn poll<I: Io>(io: &mut I, register: u32, mask: u8, target: u8) -> Result<bool, Error> {
    for _ in 0..POLLS {
        if io.read8(register)? & mask == target & mask {
            return Ok(true);
        }
        sleep(io, 50).await;
    }
    Ok(false)
}
async fn run<I: Io>(io: &mut I, table: &[Step], cut_mask: u8) -> Result<(), Error> {
    for step in table {
        if step.command == 4 {
            return Ok(());
        }
        if step.interface & 4 == 0 || step.cut & cut_mask == 0 {
            continue;
        }
        // Selected PCIe rows use absolute MAC addresses. Do not dispatch a
        // guessed access to SDIO local space or an unknown register block.
        if step.base > 2 {
            return Err(Error::UnsupportedBase(step.base));
        }
        let register = u32::from(step.offset);
        match step.command {
            1 => modify8(io, register, step.mask, step.value & step.mask)?,
            2 => {
                if poll(io, register, step.mask, step.value).await? {
                    continue;
                }
                let power = io.read8(4)?;
                io.write8(4, power | 8)?;
                io.write8(4, power & !8)?;
                if !poll(io, register, step.mask, step.value).await? {
                    return Err(Error::PollTimeout {
                        register,
                        mask: step.mask,
                        target: step.value & step.mask,
                    });
                }
            }
            3 if step.value == 0 => sleep(io, register.into()).await,
            3 if step.value == 1 => sleep(io, u64::from(register) * 1000).await,
            _ => return Err(Error::UnsupportedCommand(step.command)),
        }
    }
    Err(Error::MissingEnd)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{
        identity::{Observed, Profile},
        io,
    };
    use super::*;
    use crate::wifi::stepped::block_on;
    use alloc::vec::Vec;
    struct Model {
        profile: Profile,
        bytes: Vec<u8>,
        trace: Vec<u8>,
        operations: usize,
        fail_at: Option<usize>,
        stuck: bool,
        recover: bool,
        toggled: bool,
        quarantines: usize,
    }
    impl Model {
        fn new(cut: u8, already_on: bool, boot_flash: bool) -> Self {
            let profile = Profile::select(Observed {
                vendor: 0x10ec,
                device: 0xc822,
                subsystem_vendor: 0x17aa,
                subsystem_device: 0x1234,
                pci_revision: 1,
                sys_cfg1: u32::from(cut) << 12,
            })
            .unwrap();
            let mut m = Self {
                profile,
                bytes: (0..0x170c).map(|i| (i * 37 + 11) as u8).collect(),
                trace: Vec::new(),
                operations: 0,
                fail_at: None,
                stuck: false,
                recover: false,
                toggled: false,
                quarantines: 0,
            };
            m.set(REG_SYS_CFG1, 4, profile.observed().sys_cfg1);
            m.set(4, 1, 0);
            m.set(5, 1, 0);
            m.set(6, 1, 2);
            m.set(REG_CR, 1, if already_on { 0 } else { 0xea });
            m.set(
                0x80,
                4,
                if already_on { 0xc078 } else { 0 } | if boot_flash { 1 << 20 } else { 0 },
            );
            m
        }
        fn get(&self, r: u32, n: usize) -> u32 {
            let mut b = [0; 4];
            b[..n].copy_from_slice(&self.bytes[r as usize..r as usize + n]);
            u32::from_le_bytes(b)
        }
        fn set(&mut self, r: u32, n: usize, v: u32) {
            self.bytes[r as usize..r as usize + n].copy_from_slice(&v.to_le_bytes()[..n]);
        }
        fn operation(&mut self) -> Result<(), io::Error> {
            let at = self.operations;
            self.operations += 1;
            if self.quarantines != 0 || self.fail_at == Some(at) {
                Err(io::Error::Register)
            } else {
                Ok(())
            }
        }
        fn record(&mut self, tag: u32, r: u32, value: u32) {
            for w in [tag, r, value] {
                self.trace.extend_from_slice(&w.to_le_bytes());
            }
        }
        fn read(&mut self, r: u32, n: usize) -> Result<u32, io::Error> {
            self.operation()?;
            let mut v = self.get(r, n);
            if r == 6 && n == 1 && (self.stuck || (self.recover && !self.toggled)) {
                v &= !2;
            }
            self.record(n as u32, r, v);
            Ok(v)
        }
        fn write(&mut self, r: u32, n: usize, v: u32) -> Result<(), io::Error> {
            self.operation()?;
            self.record(4 + n as u32, r, v);
            let mut stored = v;
            if r == 5 && n == 1 {
                if v & 1 != 0 {
                    self.set(REG_CR, 1, 0);
                    stored &= !1;
                }
                if v & 2 != 0 {
                    self.set(REG_CR, 1, 0xea);
                    stored &= !2;
                }
            }
            if r == 4 && n == 1 && v & 8 != 0 {
                self.toggled = true;
            }
            self.set(r, n, stored);
            Ok(())
        }
    }
    // SAFETY: serial virtual power-state model, bytes/events recorded;
    // no real requester/power/firmware/privileged DMA is claimed by this test.
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
            panic!("MAC power cannot submit firmware")
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            panic!("MAC power cannot manufacture DMA completion")
        }
        fn quarantine(&mut self) {
            self.quarantines += 1;
        }
    }
    #[test]
    fn each_supported_cut_cold_or_firmware_left_on_runs_power_events() {
        for cut in 0..7 {
            for powered in [false, true] {
                for flash in [false, true] {
                    let mut m = Model::new(cut, powered, flash);
                    // SAFETY: synchronous stopped virtual requester, no active queue.
                    block_on(unsafe { on(&mut m) }).unwrap();
                    assert_eq!(m.get(REG_CR, 1), 0);
                    assert_eq!(m.get(REG_CPU_DMEM_CON, 4) & 0x10100, 0x10100);
                    assert_eq!(m.get(REG_SYS_FUNC_EN + 1, 1) & 0xd8, 0xd8);
                    assert_eq!(m.get(REG_CR_EXT + 3, 1) & 15, 12);
                    assert_eq!(m.get(REG_MCUFW_CTRL, 4) & (1 << 20), 0);
                    assert_eq!(m.quarantines, 0);
                }
            }
        }
    }
    #[test]
    fn unsupported_cut_and_chip_have_no_successful_skipped_sequence() {
        for cut in 7..16 {
            let mut m = Model::new(cut, false, false);
            assert_eq!(
                // SAFETY: the model device, its pages and its domain belong to this test alone; no
                // other driver, worker or DMA touches them.
                block_on(unsafe { on(&mut m) }),
                Err(Error::UnsupportedCut(cut))
            );
            assert_eq!(m.operations, 0);
            assert_eq!(m.quarantines, 0);
        }
        let mut m = Model::new(1, false, false);
        let mut o = m.profile.observed();
        o.device = 0xb852;
        m.profile = Profile::select(o).unwrap();
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        assert_eq!(block_on(unsafe { on(&mut m) }), Err(Error::UnsupportedChip));
        assert_eq!(m.operations, 0);
    }
    #[test]
    fn every_uncertain_operation_quarantines_and_identity_change_precedes_mutation() {
        for powered in [false, true] {
            let mut baseline = Model::new(1, powered, true);
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            block_on(unsafe { on(&mut baseline) }).unwrap();
            for at in 0..baseline.operations {
                let mut m = Model::new(1, powered, true);
                m.fail_at = Some(at);
                assert!(
                    // SAFETY: the model device, its pages and its domain belong to this test alone; no
                    // other driver, worker or DMA touches them.
                    block_on(unsafe { on(&mut m) }).is_err(),
                    "on={powered} op={at}"
                );
                assert_eq!(m.quarantines, 1);
            }
        }
        let mut m = Model::new(1, false, false);
        m.set(REG_SYS_CFG1, 4, u32::MAX);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        assert_eq!(block_on(unsafe { on(&mut m) }), Err(Error::IdentityChanged));
        assert_eq!(m.operations, 1);
        assert_eq!(m.quarantines, 1);
    }
    #[test]
    fn bounded_power_poll_retries_real_pfm_toggle_and_terminal_failure() {
        let mut m = Model::new(1, false, false);
        m.recover = true;
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        block_on(unsafe { on(&mut m) }).unwrap();
        assert!(m.toggled);
        assert_eq!(m.quarantines, 0);
        let mut m = Model::new(1, false, false);
        m.stuck = true;
        assert_eq!(
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            block_on(unsafe { on(&mut m) }),
            Err(Error::PollTimeout {
                register: 6,
                mask: 2,
                target: 2
            })
        );
        assert!(m.toggled);
        assert!(m.operations <= 2 * POLLS + 50);
        assert_eq!(m.quarantines, 1);
    }
    #[test]
    #[ignore = "oracle: STELA_REALTEK_WIFI_POWER_ORACLE"]
    fn complete_power_trace_matches_unchanged_c_for_every_source_cut_and_entry_state() {
        let path = std::env::var("STELA_REALTEK_WIFI_POWER_ORACLE").unwrap();
        let trace = std::fs::read(&path).unwrap();
        let raw_tables =
            std::fs::read(std::path::Path::new(&path).with_file_name("tables.bin")).unwrap();
        let mut actual_tables = Vec::new();
        for table in [
            tables::ON_8822C[0],
            tables::ON_8822C[1],
            tables::OFF_8822C[0],
            tables::OFF_8822C[1],
        ] {
            for step in table {
                for value in [
                    u32::from(step.offset),
                    step.cut.into(),
                    step.interface.into(),
                    step.base.into(),
                    step.command.into(),
                    step.mask.into(),
                    step.value.into(),
                ] {
                    actual_tables.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        assert_eq!(actual_tables, raw_tables);
        let mut offset = 0;
        for cut in 0..7 {
            for powered in [false, true] {
                for flash in [false, true] {
                    let mut m = Model::new(cut, powered, flash);
                    // SAFETY: the model device, its pages and its domain belong to this test alone;
                    // no other driver, worker or DMA touches them.
                    block_on(unsafe { on(&mut m) }).unwrap();
                    let length =
                        u32::from_le_bytes(trace[offset..offset + 4].try_into().unwrap()) as usize;
                    offset += 4;
                    assert_eq!(
                        m.trace,
                        trace[offset..offset + length],
                        "cut={cut} powered={powered} flash={flash}"
                    );
                    offset += length;
                }
            }
        }
        assert_eq!(offset, trace.len());
    }
}
