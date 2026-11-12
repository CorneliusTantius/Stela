// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! The whole bring-up on one modeled chip, a step at a time on the model
//! clock, as a chip reset runs it.
use super::*;
use crate::{
    Clock,
    wifi::{
        connection::keeper::RECOVERY_STEP_US,
        realtek::{
            bootstrap::{self, Booted, Rings},
            download::tests::catalog_for,
            firmware::tests::legacy_fixture,
            phy::PhyInitialized,
        },
        stepped::Stepped,
    },
};
use core::{cell::RefCell, task::Poll};

const MODEL: Clock = Clock {
    ticks_per_microsecond: 1,
};
/// The model's own poll interval between two steps.
const POLL_US: u64 = 1_000;
const STEP_LIMIT: usize = 1_000_000;

/// No rings on a register model: binding and telling firmware are the
/// HCI and transmit tests' own.
struct Unbound;

impl Rings<Bus> for Unbound {
    async unsafe fn bind(&mut self, _: &mut Bus) -> Result<(), bootstrap::Error> {
        Ok(())
    }

    unsafe fn inform(
        &mut self,
        _: crate::wifi::realtek::fifo::Geometry,
        _: &PhyInitialized,
        _: &Report,
    ) -> Result<(), bootstrap::Error> {
        Ok(())
    }
}

/// A powered-off cut B chip on board option 0, with the OTP of the PHY
/// fixtures.
fn chip() -> (Arc<Mutex<Model>>, Profile) {
    let (bus, _, _) = setup(1, 0, 0x3f, 0, false, false);
    let model = bus.model.clone();
    let profile = {
        let mut m = model.lock().unwrap();
        m.bytes.resize(0x10000, 0);
        m.initial(0);
        m.chip = true;
        m.fifo_ready = true;
        m.record = false;
        m.events.clear();
        m.dac = Some(DacModel {
            adc_input: -32,
            ..Default::default()
        });
        m.set(4, 1, 0);
        m.set(5, 1, 0);
        m.set(6, 1, 2);
        m.set(0x100, 1, 0xea);
        m.set(0x80, 4, 0);
        m.set(0x1208, 4, 0);
        m.set(0x1700, 4, 1 << 29);
        m.set(0x1cc, 1, 0);
        // The H2C queue's pointers start together.
        m.set(0x10d0, 4, 0);
        m.set(0x10d4, 4, 0);
        m.profile
    };
    (model, profile)
}

fn bus(model: &Arc<Mutex<Model>>) -> Bus {
    Bus {
        model: model.clone(),
        panic_delay: false,
        panic_register: None,
        clock: Some(MODEL),
    }
}

/// Step `work` until it ends, a poll apart on the model clock; the longest
/// step and the step count.
fn run<T>(work: &mut Stepped<'_, T>) -> (T, u64, usize) {
    let mut longest = 0;
    for steps in 1..=STEP_LIMIT {
        let start = MODEL.now_us();
        let poll = work.step();
        longest = longest.max(MODEL.now_us() - start);
        if let Poll::Ready(output) = poll {
            return (output, longest, steps);
        }
        crate::test_clock::advance(MODEL, POLL_US);
    }
    panic!("the bring-up did not end in {STEP_LIMIT} steps");
}

#[test]
fn a_chip_reset_runs_the_whole_bring_up_within_the_recovery_step() {
    core::mem::forget(crate::test_clock::virtualize());
    let (model, profile) = chip();
    let firmware = catalog_for(profile, legacy_fixture());
    let staged = profile.stage(&firmware).unwrap();
    let mut rings = Unbound;
    let started = MODEL.now_us();
    // SAFETY: the model chip belongs to this test alone, with no rings.
    let mut work = Stepped::new(unsafe {
        bootstrap::boot(bus(&model), &mut rings, profile, &staged, &firmware, 0)
    });
    let (booted, longest, steps) = run(&mut work);
    let elapsed = MODEL.now_us() - started;
    drop(work);
    let Booted { mac, control, .. } = booted.unwrap();
    assert_eq!(mac, crate::Mac([2, 3, 4, 5, 6, 7]));
    assert!(!control.quarantined());
    assert!(longest <= RECOVERY_STEP_US, "a step took {longest} us");
    // The tables' 50 ms delay alone is many polls long.
    assert!(
        steps > 100 && elapsed > 50_000,
        "{steps} steps over {elapsed} us"
    );
    let m = model.lock().unwrap();
    assert!(m.beacons > 1);
    assert_eq!(m.quarantined, 0);
}

#[test]
fn a_dropped_attempt_is_reset_by_the_next() {
    core::mem::forget(crate::test_clock::virtualize());
    let (model, profile) = chip();
    let firmware = catalog_for(profile, legacy_fixture());
    let staged = profile.stage(&firmware).unwrap();
    let mut rings = Unbound;
    // An attempt dropped part way through the firmware download, as a
    // radio dropped mid-reset drops it: the owner it held is quarantined
    // at the await it stopped at, and the chip is left mid-boot.
    // SAFETY: as above.
    let mut work = Stepped::new(unsafe {
        bootstrap::boot(bus(&model), &mut rings, profile, &staged, &firmware, 0)
    });
    while model.lock().unwrap().beacons < 2 {
        assert!(work.step().is_pending());
        crate::test_clock::advance(MODEL, POLL_US);
    }
    drop(work);
    let quarantined = model.lock().unwrap().quarantined;
    assert!(quarantined >= 1);
    // The next attempt starts from the power sequence on the same chip.
    // SAFETY: as above, with the dropped attempt's owner gone.
    let mut work = Stepped::new(unsafe {
        bootstrap::boot(bus(&model), &mut rings, profile, &staged, &firmware, 0)
    });
    let (booted, longest, _) = run(&mut work);
    drop(work);
    assert!(booted.is_ok());
    assert!(longest <= RECOVERY_STEP_US, "a step took {longest} us");
    assert_eq!(model.lock().unwrap().quarantined, quarantined);
}

/// A chip answering the native BAR: a register access that fails reads as
/// a removed device's all-ones and drops the store.
struct Registers(RefCell<Bus>);

impl crate::wifi::realtek::io::model::Chip for Registers {
    fn read(&self, register: u32, width: usize) -> u32 {
        let mut bus = self.0.borrow_mut();
        match width {
            1 => bus.read8(register).map(u32::from),
            2 => bus.read16(register).map(u32::from),
            _ => bus.read32(register),
        }
        .unwrap_or(u32::MAX)
    }

    fn write(&self, register: u32, width: usize, value: u32) {
        let mut bus = self.0.borrow_mut();
        let _ = match width {
            1 => bus.write8(register, value as u8),
            2 => bus.write16(register, value as u16),
            _ => bus.write32(register, value),
        };
    }
}

#[test]
fn a_lost_radio_comes_back_through_a_stepped_chip_reset() {
    use crate::wifi::{
        connection::keeper::Recovery,
        realtek::{
            beacon::tests::{Domain, Model as Memory, Source},
            bootstrap::Claim,
            hardware::Hardware,
            io::model,
            station::Device,
        },
    };
    use alloc::{boxed::Box, rc::Rc};
    use core::ptr::NonNull;
    /// A clock at host speed: a counter read is a tenth of a microsecond,
    /// so the native path's short delays cost what they would.
    const HOST: Clock = Clock {
        ticks_per_microsecond: 1_000,
    };
    core::mem::forget(crate::test_clock::virtualize());
    let (chip, profile) = chip();
    let bar: &'static mut [u32] = Box::leak(vec![0; 0x4000].into_boxed_slice());
    let window = NonNull::new(bar.as_mut_ptr().cast::<u8>()).unwrap();
    model::attach(
        window,
        Rc::new(Registers(RefCell::new(Bus {
            model: chip.clone(),
            panic_delay: false,
            panic_register: None,
            clock: Some(HOST),
        }))),
    );
    let memory = Arc::new(Mutex::new(Memory::default()));
    let claim = Claim {
        window,
        bytes: 0x10000,
        owner: Arc::new(()),
        clock: HOST,
        pages: &Source,
        domain: Arc::new(Domain(memory.clone())),
        firmware: Box::leak(Box::new(catalog_for(profile, legacy_fixture()))),
        observed: profile.observed(),
        link_control: 0,
    };
    // SAFETY: the modeled BAR, its pages and its domain belong to this
    // test alone; no other driver, worker or DMA touches them.
    let up = unsafe { bootstrap::bring_up(claim) }.unwrap();
    let address = up.mac;
    // SAFETY: straight from the bring-up, with no MSI.
    let mut hardware = unsafe { Hardware::new(up, *b"US", 0, false) }.unwrap();
    assert!(!hardware.lost() && hardware.recoverable());
    let rings = memory.lock().unwrap().mappings.len();
    let beacons = chip.lock().unwrap().beacons;
    // Firmware crashes: its ready bits go, the next command finds them
    // gone and the mailbox's owner is quarantined.
    let crashed = chip.lock().unwrap().get(0x80, 2) & !0xc078;
    chip.lock().unwrap().set(0x80, 2, crashed);
    assert!(hardware.command((0x4b, 0)).is_err());
    assert!(hardware.lost());
    let mut longest = 0;
    let mut steps = 0;
    loop {
        let start = HOST.now_us();
        let step = hardware.recover().unwrap();
        longest = longest.max(HOST.now_us() - start);
        steps += 1;
        assert!(steps < STEP_LIMIT);
        if step == Recovery::Done {
            break;
        }
        crate::test_clock::advance(HOST, POLL_US);
    }
    model::detach(window);
    assert!(longest <= RECOVERY_STEP_US, "a step took {longest} us");
    assert!(steps > 100);
    // The chip runs again at its address, with firmware downloaded anew
    // and the crashed boot's rings still mapped beside the new ones.
    assert!(!hardware.lost());
    hardware.command((0x4b, 0)).unwrap();
    let m = chip.lock().unwrap();
    assert!(m.beacons > beacons);
    assert_eq!(memory.lock().unwrap().mappings.len(), 2 * rings);
    assert_eq!(
        m.get(0x610, 4),
        u32::from_le_bytes([address.0[0], address.0[1], address.0[2], address.0[3]])
    );
}
