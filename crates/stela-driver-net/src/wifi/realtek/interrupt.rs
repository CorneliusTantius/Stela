// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Source RTL8822C interrupt masks and W1C cause observations.
//! This device block does not allocate vectors or manufacture an MSI route,
//! deferred work, packet completion, firmware ACK or DMA-stop acknowledgement.
use super::{
    identity::Profile,
    io::{self, Bar, Io},
    registers::*,
};
const MASK0: u32 = 0x44fd;
const MASK1: u32 = 1 << 9;
const MASK3: u32 = 1 << 16;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(io::Error),
    WrongChip,
    IdentityChanged,
    Removed,
    Readback,
    InvalidState,
    Quarantined,
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Hardware(e)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Disabled,
    Enabled,
    RxMasked,
    Quarantined,
}
/// Raw HISR values and only this source's masked W1C causes. Unowned
/// latched bits remain untouched. None of these flags proves a DMA/radio/FW ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Causes {
    pub raw: [u32; 3],
    pub owned: [u32; 3],
}
impl Causes {
    pub fn rx(self) -> bool {
        self.owned[0] & 1 != 0
    }
    pub fn firmware_mailbox(self) -> bool {
        self.owned[0] & (1 << 10) != 0
    }
    pub fn h2c_dma(self) -> bool {
        self.owned[2] & (1 << 16) != 0
    }
    /// Queue interrupt cause only; inspect that queue's live hardware
    /// consumer before releasing DMA and its report before air status.
    pub fn tx(self, queue: super::transmit::Queue) -> bool {
        use super::transmit::Queue;
        let bit = match queue {
            Queue::Background => 5,
            Queue::BestEffort => 4,
            Queue::Video => 3,
            Queue::Voice => 2,
            Queue::Management => 6,
            Queue::High => 7,
            Queue::H2c => return self.h2c_dma(),
        };
        self.owned[0] & (1 << bit) != 0
    }
    pub fn beacon_dma(self) -> bool {
        self.owned[0] & (1 << 14) != 0
    }
}
/// The registers an interrupt owner reaches.
///
/// # Safety
/// Exclusive selected RTL8822C requester: fresh volatile reads and ordered
/// stores. Quarantine keeps the requester's claim and mapping for good.
pub unsafe trait Registers {
    fn profile(&self) -> Profile;
    fn read32(&mut self, register: u32) -> Result<u32, io::Error>;
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error>;
    fn quarantine(&mut self);
}
// SAFETY: `Io` makes the same promises of its own requester.
unsafe impl<I: Io> Registers for I {
    fn profile(&self) -> Profile {
        Io::profile(self)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        Io::read32(self, register)
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        Io::write32(self, register, value)
    }
    fn quarantine(&mut self) {
        Io::quarantine(self);
    }
}
// SAFETY: `Bar::new` binds the exclusive requester BAR.
unsafe impl Registers for Bar {
    fn profile(&self) -> Profile {
        Bar::profile(self)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        Ok(Bar::read32(self, register))
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        Bar::write32(self, register, value);
        Ok(())
    }
    fn quarantine(&mut self) {
        self.retain();
    }
}
/// CPU-affine exclusive control I/O; canonical native IRQ routing and worker
/// ownership remain outside this device register block. No concurrent calls,
/// reset or direct HIMR/HISR access may bypass this owner. Uncertain Drop keeps
/// the control/queue/BAR owner through Io::quarantine.
pub struct Controller<I: Registers> {
    io: Option<I>,
    state: State,
}
impl<I: Registers> Controller<I> {
    pub fn new(io: I) -> Result<Self, Error> {
        let mut c = Self {
            io: Some(io),
            state: State::Quarantined,
        };
        let profile = c.io()?.profile();
        if profile.rtw88().is_none() {
            return Err(Error::WrongChip);
        }
        let value = c.read(REG_SYS_CFG1)?;
        if value != profile.observed().sys_cfg1 {
            return Err(Error::IdentityChanged);
        }
        c.mask()?;
        Ok(c)
    }
    pub fn state(&self) -> State {
        self.state
    }
    fn io(&mut self) -> Result<&mut I, Error> {
        self.io.as_mut().ok_or(Error::Quarantined)
    }
    fn read(&mut self, r: u32) -> Result<u32, Error> {
        let value = self.io()?.read32(r)?;
        if value == u32::MAX {
            Err(Error::Removed)
        } else {
            Ok(value)
        }
    }
    fn mask(&mut self) -> Result<(), Error> {
        // Set terminal state before any uncertain write/readback. A caller
        // catching unwind cannot mistake partially disabled masks for success.
        self.state = State::Quarantined;
        for r in [REG_HIMR0, REG_HIMR1, REG_HIMR3] {
            self.io()?.write32(r, 0)?;
            if self.read(r)? != 0 {
                return Err(Error::Readback);
            }
        }
        self.state = State::Disabled;
        Ok(())
    }
    pub fn disable(&mut self) -> Result<(), Error> {
        if self.state == State::Quarantined {
            return Err(Error::Quarantined);
        }
        self.mask()
    }
    /// Mask the device before W1C, as required by the source MSI edge
    /// sequence. The platform EOI follows the device handler; this
    /// bounded register phase allocates no work or memory. Deferred work must
    /// remain held by the canonical caller before it enables the route.
    pub fn capture(&mut self) -> Result<Causes, Error> {
        if self.state == State::Quarantined {
            return Err(Error::Quarantined);
        }
        self.mask()?;
        self.state = State::Quarantined;
        let raw = [
            self.read(REG_HISR0)?,
            self.read(REG_HISR1)?,
            self.read(REG_HISR3)?,
        ];
        let owned = [raw[0] & MASK0, raw[1] & MASK1, raw[2] & MASK3];
        for (r, value) in [REG_HISR0, REG_HISR1, REG_HISR3].into_iter().zip(owned) {
            self.io()?.write32(r, value)?;
        }
        self.state = State::Disabled;
        Ok(Causes { raw, owned })
    }
    /// Enable the source masks, optionally leaving RX masked while the
    /// RX worker drains its ring. No cached IRQ/packet count
    /// is used to decide whether receive work has finished.
    /// # Safety
    /// Requester has a live canonical native IRQ registration and a
    /// handler/deferred worker. Full source HCI/MAC/PHY/start
    /// prerequisites are satisfied. Caller serializes this transition with
    /// IRQ/callback/deferred/RX/reset retirement, including local IRQ
    /// exclusion where required; `rx_pending` describes the real RX worker.
    pub unsafe fn enable(&mut self, rx_pending: bool) -> Result<(), Error> {
        if self.state != State::Disabled {
            return Err(if self.state == State::Quarantined {
                Error::Quarantined
            } else {
                Error::InvalidState
            });
        }
        self.state = State::Quarantined;
        let masks = [MASK0 & !u32::from(rx_pending), MASK1, MASK3];
        for (r, value) in [REG_HIMR0, REG_HIMR1, REG_HIMR3].into_iter().zip(masks) {
            self.io()?.write32(r, value)?;
            if self.read(r)? != value {
                return Err(Error::Readback);
            }
        }
        self.state = if rx_pending {
            State::RxMasked
        } else {
            State::Enabled
        };
        Ok(())
    }
    /// Recover the raw control owner for stopped teardown.
    /// # Safety
    /// Independently acknowledged requester DMA/MSI stop and drained
    /// canonical registration/callback/deferred workers; HIMR disable, W1C,
    /// equal indices or this method do not establish any of those guarantees.
    pub unsafe fn into_stopped(mut self) -> Result<I, Error> {
        self.disable()?;
        self.io.take().ok_or(Error::Quarantined)
    }
}
impl<I: Registers> Drop for Controller<I> {
    fn drop(&mut self) {
        if let Some(io) = &mut self.io {
            io.quarantine();
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::identity::{Observed, Profile};
    use super::*;
    use alloc::{sync::Arc, vec, vec::Vec};
    use std::sync::Mutex;
    struct Model {
        bytes: Vec<u8>,
        events: Vec<[u32; 4]>,
        calls: usize,
        fail: Option<usize>,
        corrupt: Option<u32>,
        wrong: Option<u32>,
        quarantined: bool,
        owner_drops: usize,
    }
    impl Model {
        fn new(case: u32) -> Self {
            let mut m = Self {
                bytes: vec![0; 0x1100],
                events: Vec::new(),
                calls: 0,
                fail: None,
                corrupt: None,
                wrong: None,
                quarantined: false,
                owner_drops: 0,
            };
            let raw = if case < 32 {
                [
                    1u32 << case,
                    (1u32 << case).rotate_left(7),
                    (1u32 << case).rotate_left(19),
                ]
            } else {
                [
                    case.wrapping_mul(0x13ac9571),
                    case.wrapping_mul(0x77235491),
                    case.wrapping_mul(0x129d2157),
                ]
            };
            for (reg, v) in [0xb4, 0xbc, 0x10bc].into_iter().zip(raw) {
                m.bytes[reg..reg + 4].copy_from_slice(&v.to_le_bytes());
            }
            m
        }
        fn access(&mut self, r: u32, value: Option<u32>) -> Result<u32, io::Error> {
            self.calls += 1;
            if self.fail == Some(self.calls) {
                return Err(io::Error::Register);
            }
            let p = r as usize;
            let old = u32::from_le_bytes(self.bytes[p..p + 4].try_into().unwrap());
            if let Some(v) = value {
                let next = if matches!(r, 0xb4 | 0xbc | 0x10bc) {
                    old & !v
                } else {
                    v
                };
                self.bytes[p..p + 4].copy_from_slice(&next.to_le_bytes());
            }
            let result = if value.is_none() && self.corrupt == Some(r) {
                u32::MAX
            } else if value.is_none() && self.wrong == Some(r) {
                u32::from_le_bytes(self.bytes[p..p + 4].try_into().unwrap()) ^ 1
            } else {
                u32::from_le_bytes(self.bytes[p..p + 4].try_into().unwrap())
            };
            if value.is_some() || matches!(r, 0xb4 | 0xbc | 0x10bc) {
                self.events
                    .push([u32::from(value.is_some()), r, 4, value.unwrap_or(result)]);
            }
            Ok(result)
        }
    }
    struct Registers(Arc<Mutex<Model>>);
    // SAFETY: serialized W1C/mask register model with explicit kept-owner
    // quarantine; no physical IRQ route, DMA stop or deferred work is claimed.
    unsafe impl Io for Registers {
        fn profile(&self) -> Profile {
            Profile::select(Observed {
                vendor: 0x10ec,
                device: 0xc822,
                subsystem_vendor: 0x17aa,
                subsystem_device: 0x1234,
                pci_revision: 1,
                sys_cfg1: 0,
            })
            .unwrap()
        }
        fn read8(&mut self, _: u32) -> Result<u8, io::Error> {
            panic!("32-bit interrupt registers only");
        }
        fn read16(&mut self, _: u32) -> Result<u16, io::Error> {
            panic!("32-bit interrupt registers only");
        }
        fn read32(&mut self, r: u32) -> Result<u32, io::Error> {
            self.0.lock().unwrap().access(r, None)
        }
        fn write8(&mut self, _: u32, _: u8) -> Result<(), io::Error> {
            panic!("32-bit interrupt registers only");
        }
        fn write16(&mut self, _: u32, _: u16) -> Result<(), io::Error> {
            panic!("32-bit interrupt registers only");
        }
        fn write32(&mut self, r: u32, v: u32) -> Result<(), io::Error> {
            self.0.lock().unwrap().access(r, Some(v)).map(|_| ())
        }
        fn delay_us(&mut self, _: u64) {
            panic!("no IRQ delay");
        }
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
            panic!("no IRQ submission");
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            panic!("no IRQ completion");
        }
        fn quarantine(&mut self) {
            self.0.lock().unwrap().quarantined = true;
        }
    }
    impl Drop for Registers {
        fn drop(&mut self) {
            let mut m = self.0.lock().unwrap();
            if !m.quarantined {
                m.owner_drops += 1;
            }
        }
    }
    fn cycle(model: &Arc<Mutex<Model>>) -> Result<(), Error> {
        let mut c = Controller::new(Registers(model.clone()))?;
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe {
            c.enable(false)?;
        }
        let first = c.capture()?;
        assert_eq!(
            first.owned,
            [
                first.raw[0] & MASK0,
                first.raw[1] & MASK1,
                first.raw[2] & MASK3
            ]
        );
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe {
            c.enable(true)?;
        }
        let second = c.capture()?;
        assert_eq!(second.owned, [0; 3]);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe {
            c.enable(false)?;
            let _stopped = c.into_stopped()?;
        }
        Ok(())
    }
    #[test]
    fn causes_preserve_unowned_status_and_queue_identity_without_completion_claims() {
        use super::super::transmit::Queue;
        for q in [
            Queue::Background,
            Queue::BestEffort,
            Queue::Video,
            Queue::Voice,
            Queue::Management,
            Queue::High,
            Queue::H2c,
        ] {
            for case in 0..32 {
                let model = Arc::new(Mutex::new(Model::new(case)));
                let mut c = Controller::new(Registers(model.clone())).unwrap();
                // SAFETY: the model device, its pages and its domain belong to this test alone; no
                // other driver, worker or DMA touches them.
                unsafe { c.enable(false) }.unwrap();
                let causes = c.capture().unwrap();
                let bit = match q {
                    Queue::Background => 5,
                    Queue::BestEffort => 4,
                    Queue::Video => 3,
                    Queue::Voice => 2,
                    Queue::Management => 6,
                    Queue::High => 7,
                    Queue::H2c => 16,
                };
                assert_eq!(
                    causes.tx(q),
                    if q == Queue::H2c {
                        causes.raw[2] & (1 << bit) != 0
                    } else {
                        case == bit
                    }
                );
                assert_eq!(causes.rx(), case == 0);
                assert_eq!(causes.firmware_mailbox(), case == 10);
                assert_eq!(causes.beacon_dma(), case == 14);
                assert_eq!(c.state(), State::Disabled);
                assert_eq!(c.capture().unwrap().owned, [0; 3]);
                // SAFETY: the model device, its pages and its domain belong to this test alone; no
                // other driver, worker or DMA touches them.
                unsafe { c.enable(true) }.unwrap();
                assert_eq!(c.state(), State::RxMasked);
                {
                    let m = model.lock().unwrap();
                    assert_eq!(
                        u32::from_le_bytes(m.bytes[0xb0..0xb4].try_into().unwrap()) & 1,
                        0
                    );
                }
                // SAFETY: the model device is stopped and drained, so nothing still uses what this
                // releases.
                unsafe { c.into_stopped() }.unwrap();
                assert_eq!(model.lock().unwrap().owner_drops, 1);
            }
        }
    }
    #[test]
    fn every_uncertain_io_and_all_ones_read_keeps_owner() {
        let normal = Arc::new(Mutex::new(Model::new(0)));
        cycle(&normal).unwrap();
        let calls = normal.lock().unwrap().calls;
        for call in 1..=calls {
            let m = Arc::new(Mutex::new(Model::new(0)));
            m.lock().unwrap().fail = Some(call);
            assert!(cycle(&m).is_err(), "operation {call}");
            assert!(m.lock().unwrap().quarantined);
            assert_eq!(m.lock().unwrap().owner_drops, 0);
        }
        for r in [0xf0, 0xb0, 0xb8, 0x10b8, 0xb4, 0xbc, 0x10bc] {
            let m = Arc::new(Mutex::new(Model::new(0)));
            m.lock().unwrap().corrupt = Some(r);
            assert_eq!(cycle(&m), Err(Error::Removed));
            assert!(m.lock().unwrap().quarantined);
            assert_eq!(m.lock().unwrap().owner_drops, 0);
        }
        let m = Arc::new(Mutex::new(Model::new(0)));
        let mut c = Controller::new(Registers(m.clone())).unwrap();
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        unsafe { c.enable(false) }.unwrap();
        // SAFETY: the model device, its pages and its domain belong to this test alone; no other
        // driver, worker or DMA touches them.
        assert_eq!(unsafe { c.enable(false) }, Err(Error::InvalidState));
        drop(c);
        assert!(m.lock().unwrap().quarantined);
        assert_eq!(m.lock().unwrap().owner_drops, 0);
    }
    #[test]
    fn failed_mask_acknowledgement_cannot_enable_or_reenter_capture() {
        for reg in [0xb0, 0xb8, 0x10b8] {
            let m = Arc::new(Mutex::new(Model::new(0)));
            m.lock().unwrap().wrong = Some(reg);
            assert!(matches!(
                Controller::new(Registers(m.clone())),
                Err(Error::Readback)
            ));
            assert!(m.lock().unwrap().quarantined);
            assert_eq!(m.lock().unwrap().owner_drops, 0);
            let m = Arc::new(Mutex::new(Model::new(0)));
            let mut c = Controller::new(Registers(m.clone())).unwrap();
            m.lock().unwrap().wrong = Some(reg);
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            assert_eq!(unsafe { c.enable(false) }, Err(Error::Readback));
            assert_eq!(c.state(), State::Quarantined);
            assert_eq!(c.capture(), Err(Error::Quarantined));
            assert_eq!(c.disable(), Err(Error::Quarantined));
            drop(c);
            assert!(m.lock().unwrap().quarantined);
            assert_eq!(m.lock().unwrap().owner_drops, 0);
        }
    }
    #[test]
    #[ignore = "oracle: STELA_REALTEK_WIFI_INTERRUPT_ORACLE"]
    fn masks_w1c_widths_order_and_rx_exclusion_match_unchanged_c() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_INTERRUPT_ORACLE").unwrap()).unwrap();
        let mut actual = Vec::new();
        for case in 0..48 {
            let m = Arc::new(Mutex::new(Model::new(case)));
            cycle(&m).unwrap();
            for event in &m.lock().unwrap().events {
                for v in event {
                    actual.extend_from_slice(&v.to_le_bytes());
                }
            }
        }
        assert_eq!(actual, trace);
    }
}
