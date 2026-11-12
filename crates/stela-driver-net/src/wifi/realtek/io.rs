// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C register access over the PCI BAR, adapted from pinned
//! rtw88/{hci,pci}.h. `Io` carries the reserved-page beacon submission the
//! firmware download needs; `Bar` is the plain BAR shared by the beacon, RX
//! and TX register blocks.
use super::identity::Profile;
use crate::{
    Clock, Deadline,
    bus::mmio::Mmio,
    wifi::stepped::{until, yield_now},
};
use alloc::sync::Arc;
use core::ptr::NonNull;

/// A wait of `microseconds` in stepped work: the step ends, and the work goes
/// on once the wait has passed on `io`'s clock. Registers without a clock
/// delay in place and end the step after.
pub async fn sleep<I: Io + ?Sized>(io: &mut I, microseconds: u64) {
    match io.deadline(microseconds) {
        Some(deadline) => until(deadline).await,
        None => {
            io.delay_us(microseconds);
            yield_now().await;
        }
    }
}

/// Bytes of the BAR every RTL8822C register block reaches.
pub const BAR_BYTES: usize = 0x170c;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidState,
    WrongChip,
    WrongFirmwareTarget,
    InvalidBoundary,
    InvalidClock,
    Register,
    Queue,
    Timeout { register: u32, mask: u32 },
    Checksum { destination: u32 },
    DownloadChecksums,
    InvalidFirmwareKey,
    FirmwareNotReady { debug: u32 },
    HardwareFeatureId { observed: u8 },
    HardwareFeatureFirmwareNotReady { observed: u16 },
}

/// One native beacon TXBD queue, never a firmware or OS compatibility shim.
///
/// # Safety
/// The queue must belong to the exact RTL8822C PCI requester whose exclusive
/// UC BAR is passed to `NativeIo`. It must build the donor's 48-byte reserved
/// page TX descriptor and beacon TXBD using canonical pinned memory
/// and requester-specific DMA mappings, then ring PCI beacon work. The caller
/// owns no DMA allocation: the implementation copies `data` before returning
/// and keeps descriptor/payload mappings through DMA completion or
/// acknowledged requester stop. Success means submission, not completion.
/// Errors may follow publication; Drop and quarantine must keep every
/// potentially live DMA resource and its claim until acknowledged quiescence.
pub unsafe trait BeaconQueue {
    fn submit(&mut self, data: &[u8]) -> Result<(), Error>;
    /// # Safety
    /// The FIFO_PAGE BCN_VALID was cleared before this submission,
    /// then observed newly set after it, with exclusive requester ownership.
    /// The device copied this reserved page and no longer reads its host
    /// payload/descriptor. This does not authorize unmapping the queue base.
    unsafe fn consumed(&mut self) -> Result<(), Error>;
    fn quarantine(&mut self);
}

/// Exact register access plus native reserved-page TX submission.
///
/// # Safety
/// All reads must be volatile observations of the selected, exclusively
/// owned RTL8822C requester; stores must complete in program order. No other
/// reset/IRQ/firmware worker may touch it during download. Never substitute
/// cached readiness or manufactured completion. `submit_beacon` follows the
/// `BeaconQueue` ownership contract; quarantine keeps all uncertain DMA,
/// requester and BAR ownership. Delays must wait at least the requested time.
pub unsafe trait Io {
    /// Requester observation kept when acquiring this interface.
    fn profile(&self) -> Profile;
    fn read8(&mut self, register: u32) -> Result<u8, Error>;
    fn read16(&mut self, register: u32) -> Result<u16, Error>;
    fn read32(&mut self, register: u32) -> Result<u32, Error>;
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error>;
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error>;
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error>;
    fn delay_us(&mut self, microseconds: u64);
    /// Monotonic native microseconds for firmware wall-time deadlines.
    /// Implementations must use the same checked CPU-affine clock as delays;
    /// unavailable timing explicitly refuses new elapsed-time command polling.
    fn now_us(&mut self) -> Result<u64, Error> {
        Err(Error::InvalidClock)
    }
    /// When a wait of `microseconds` from now ends, on the clock the delays
    /// keep; `None` where [`Self::delay_us`] stands in for one.
    fn deadline(&mut self, _microseconds: u64) -> Option<Deadline> {
        None
    }
    fn submit_beacon(&mut self, data: &[u8]) -> Result<(), Error>;
    /// # Safety
    /// Same new BCN_VALID completion proof as BeaconQueue::consumed.
    unsafe fn beacon_consumed(&mut self) -> Result<(), Error>;
    fn quarantine(&mut self);
}

// SAFETY: forwards to the interface it borrows, with that interface's promises.
unsafe impl<I: Io> Io for &mut I {
    fn profile(&self) -> Profile {
        (**self).profile()
    }
    fn read8(&mut self, register: u32) -> Result<u8, Error> {
        (**self).read8(register)
    }
    fn read16(&mut self, register: u32) -> Result<u16, Error> {
        (**self).read16(register)
    }
    fn read32(&mut self, register: u32) -> Result<u32, Error> {
        (**self).read32(register)
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error> {
        (**self).write8(register, value)
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error> {
        (**self).write16(register, value)
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error> {
        (**self).write32(register, value)
    }
    fn delay_us(&mut self, microseconds: u64) {
        (**self).delay_us(microseconds);
    }
    fn now_us(&mut self) -> Result<u64, Error> {
        (**self).now_us()
    }
    fn deadline(&mut self, microseconds: u64) -> Option<Deadline> {
        (**self).deadline(microseconds)
    }
    fn submit_beacon(&mut self, data: &[u8]) -> Result<(), Error> {
        (**self).submit_beacon(data)
    }
    unsafe fn beacon_consumed(&mut self) -> Result<(), Error> {
        // SAFETY: the caller's completion proof, for the same interface.
        unsafe { (**self).beacon_consumed() }
    }
    fn quarantine(&mut self) {
        (**self).quarantine();
    }
}

/// Real volatile MMIO and the native beacon queue. The BAR owner is held
/// with the queue on any uncertain download; dropping this adapter cannot
/// unmap memory still accessible to a quarantined device.
pub struct NativeIo<Q: BeaconQueue> {
    registers: Window,
    clock: Clock,
    profile: Profile,
    bytes: usize,
    owned: Option<(Q, Arc<dyn core::any::Any>)>,
}
impl<Q: BeaconQueue> NativeIo<Q> {
    /// Access the native queue for later HCI setup and acknowledged
    /// stop/unmap. Queue methods still enforce their own ownership contracts;
    /// a quarantined download never returns its queue this way.
    pub fn beacon_queue(&mut self) -> Result<&mut Q, Error> {
        Ok(&mut self.owned.as_mut().ok_or(Error::InvalidState)?.0)
    }
    /// # Safety
    /// `window` is the RTL8822C exclusive uncached BAR, at least BAR_BYTES
    /// bytes. `owner` keeps the real PCI claim and mapped BAR reservation
    /// through its final Drop. `queue` is configured on that requester.
    /// Device MAC power and validated FIFO page layout must already be set;
    /// all competing DMA/IRQ/reset workers are stopped for this object's life.
    /// The clock is calibrated against the native host timer for this CPU.
    /// `profile` contains observations read from this requester, not a
    /// marketing/device-ID substitute or another adapter's firmware target.
    pub unsafe fn new(
        window: NonNull<u8>,
        bytes: usize,
        queue: Q,
        owner: Arc<dyn core::any::Any>,
        clock: Clock,
        profile: Profile,
    ) -> Result<Self, Error> {
        // SAFETY: caller supplies mapped exclusive UC requester ownership;
        // this entry additionally requires completed prior MAC power setup.
        unsafe { Self::mapped(window, bytes, queue, owner, clock, profile) }
    }
    /// Construct the real native interface for the source MAC power sequence
    /// ([`super::power::on`]) before firmware download. No MAC power, FIFO,
    /// HCI or radio readiness is implied.
    ///
    /// # Safety
    /// Same real UC BAR/requester/profile/clock ownership as `new`, except MAC
    /// power may be off or left on by prior firmware. All old DMA/IRQ workers
    /// are acknowledged stopped and drained; the native beacon queue is
    /// fresh/idle, its isolated domain owns all mappings and no competing
    /// power/reset path exists. Caller runs the power sequence first and
    /// keeps validated FIFO geometry for the later source MAC configuration
    /// and download restore boundary. After that sequence, HCI/beacon-base
    /// reconfiguration/readback is required before Download or queue
    /// submission. The software queue's configured flag is not evidence that
    /// its base survived a power cycle.
    pub unsafe fn unpowered(
        window: NonNull<u8>,
        bytes: usize,
        queue: Q,
        owner: Arc<dyn core::any::Any>,
        clock: Clock,
        profile: Profile,
    ) -> Result<Self, Error> {
        // SAFETY: caller supplies the exclusive mapped requester.
        unsafe { Self::mapped(window, bytes, queue, owner, clock, profile) }
    }
    /// # Safety
    /// Exclusive UC BAR, owned requester, calibrated clock and exact
    /// observed profile. This mapping helper makes no MAC power-state claim.
    unsafe fn mapped(
        window: NonNull<u8>,
        bytes: usize,
        queue: Q,
        owner: Arc<dyn core::any::Any>,
        clock: Clock,
        profile: Profile,
    ) -> Result<Self, Error> {
        if bytes < BAR_BYTES || window.as_ptr().addr() & 3 != 0 {
            return Err(Error::Register);
        }
        if clock.ticks_per_microsecond == 0 {
            return Err(Error::InvalidClock);
        }
        if profile.rtw88().is_none() {
            return Err(Error::WrongChip);
        }
        Ok(Self {
            // SAFETY: the constructor's UC BAR/ownership contract.
            registers: unsafe { Window::new(window, bytes) },
            clock,
            profile,
            bytes,
            owned: Some((queue, owner)),
        })
    }
    fn check(&self, register: u32, width: usize) -> Result<(), Error> {
        if self.owned.is_none()
            || !(register as usize).is_multiple_of(width)
            || (register as usize)
                .checked_add(width)
                .is_none_or(|end| end > self.bytes)
        {
            return Err(Error::Register);
        }
        Ok(())
    }
}
// SAFETY: constructor binds the exclusive BAR and native beacon queue.
// Each register operation is a volatile store/load, with no readiness cache.
unsafe impl<Q: BeaconQueue> Io for NativeIo<Q> {
    fn profile(&self) -> Profile {
        self.profile
    }
    fn read8(&mut self, register: u32) -> Result<u8, Error> {
        self.check(register, 1)?;
        Ok(self.registers.read8(register as usize))
    }
    fn read16(&mut self, register: u32) -> Result<u16, Error> {
        self.check(register, 2)?;
        Ok(self.registers.read16(register as usize))
    }
    fn read32(&mut self, register: u32) -> Result<u32, Error> {
        self.check(register, 4)?;
        Ok(self.registers.read32(register as usize))
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error> {
        self.check(register, 1)?;
        self.registers.write8(register as usize, value);
        Ok(())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error> {
        self.check(register, 2)?;
        self.registers.write16(register as usize, value);
        Ok(())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error> {
        self.check(register, 4)?;
        self.registers.write32(register as usize, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.clock.delay(microseconds);
    }
    fn now_us(&mut self) -> Result<u64, Error> {
        self.owned.as_ref().ok_or(Error::InvalidState)?;
        Ok(self.clock.now_us())
    }
    fn deadline(&mut self, microseconds: u64) -> Option<Deadline> {
        Some(self.clock.deadline(microseconds))
    }
    fn submit_beacon(&mut self, data: &[u8]) -> Result<(), Error> {
        self.owned
            .as_mut()
            .ok_or(Error::InvalidState)?
            .0
            .submit(data)
    }
    unsafe fn beacon_consumed(&mut self) -> Result<(), Error> {
        // SAFETY: caller supplies the new BCN_VALID completion proof;
        // constructor binds this queue to the exact exclusive requester/BAR.
        unsafe { self.owned.as_mut().ok_or(Error::InvalidState)?.0.consumed() }
    }
    fn quarantine(&mut self) {
        if let Some((queue, owner)) = self.owned.take() {
            let mut retained = core::mem::ManuallyDrop::new((queue, owner));
            retained.0.quarantine();
            // No ACKed requester stop exists. Keep queue plus its real BAR
            // claim indefinitely; clearing MCU enable is not DMA quiescence.
        }
    }
}

/// The registers a [`NativeIo`] or [`Bar`] reaches: the BAR, or in tests a
/// modeled chip attached at the BAR's address ([`model::attach`]).
#[derive(Clone)]
struct Window {
    mmio: Mmio,
    #[cfg(test)]
    model: Option<alloc::rc::Rc<dyn model::Chip>>,
}
impl Window {
    /// # Safety
    /// [`Mmio::new`]'s contract for `window` and `bytes`.
    unsafe fn new(window: NonNull<u8>, bytes: usize) -> Self {
        Self {
            // SAFETY: forwarded from the caller.
            mmio: unsafe { Mmio::new(window.as_ptr() as u64, bytes) },
            #[cfg(test)]
            model: model::find(window),
        }
    }
    fn read8(&self, offset: usize) -> u8 {
        #[cfg(test)]
        if let Some(chip) = &self.model {
            return chip.read(offset as u32, 1) as u8;
        }
        self.mmio.read8(offset)
    }
    fn read16(&self, offset: usize) -> u16 {
        #[cfg(test)]
        if let Some(chip) = &self.model {
            return chip.read(offset as u32, 2) as u16;
        }
        self.mmio.read16(offset)
    }
    fn read32(&self, offset: usize) -> u32 {
        #[cfg(test)]
        if let Some(chip) = &self.model {
            return chip.read(offset as u32, 4);
        }
        self.mmio.read32(offset)
    }
    fn write8(&self, offset: usize, value: u8) {
        #[cfg(test)]
        if let Some(chip) = &self.model {
            return chip.write(offset as u32, 1, value.into());
        }
        self.mmio.write8(offset, value);
    }
    fn write16(&self, offset: usize, value: u16) {
        #[cfg(test)]
        if let Some(chip) = &self.model {
            return chip.write(offset as u32, 2, value.into());
        }
        self.mmio.write16(offset, value);
    }
    fn write32(&self, offset: usize, value: u32) {
        #[cfg(test)]
        if let Some(chip) = &self.model {
            return chip.write(offset as u32, 4, value);
        }
        self.mmio.write32(offset, value);
    }
}

/// Modeled chips that answer a test's BAR in place of memory, so the native
/// register path, rings and [`super::hardware::Hardware`] run on them.
#[cfg(test)]
pub(super) mod model {
    extern crate std;
    use alloc::{rc::Rc, vec::Vec};
    use core::{cell::RefCell, ptr::NonNull};

    /// A chip's registers, by offset and access width in bytes.
    pub(in crate::wifi::realtek) trait Chip {
        fn read(&self, register: u32, width: usize) -> u32;
        fn write(&self, register: u32, width: usize, value: u32);
    }

    type Attached = Vec<(usize, Rc<dyn Chip>)>;

    std::thread_local! {
        static CHIPS: RefCell<Attached> = const { RefCell::new(Vec::new()) };
    }

    /// Answer each BAR this thread maps at `window` from `chip`.
    pub(in crate::wifi::realtek) fn attach(window: NonNull<u8>, chip: Rc<dyn Chip>) {
        CHIPS.with(|chips| chips.borrow_mut().push((window.as_ptr().addr(), chip)));
    }

    /// Stop answering `window` from a chip; BARs mapped before keep theirs.
    pub(in crate::wifi::realtek) fn detach(window: NonNull<u8>) {
        CHIPS.with(|chips| {
            chips
                .borrow_mut()
                .retain(|(at, _)| *at != window.as_ptr().addr())
        });
    }

    pub(super) fn find(window: NonNull<u8>) -> Option<Rc<dyn Chip>> {
        CHIPS.with(|chips| {
            chips
                .borrow()
                .iter()
                .find(|(at, _)| *at == window.as_ptr().addr())
                .map(|(_, chip)| chip.clone())
        })
    }
}

/// The exclusive BAR of one RTL8822C requester, shared by its beacon, RX and
/// TX register blocks. The owner keeps the PCI claim and mapping alive.
pub struct Bar {
    mmio: Window,
    profile: Profile,
    _owner: Arc<dyn core::any::Any>,
}
impl Bar {
    /// # Safety
    /// `window` is the exclusive uncached BAR of the RTL8822C requester named
    /// by `profile`, mapped for at least `bytes`, and `owner` keeps that
    /// claim and mapping. DMA domains used with these registers bind the same
    /// requester, and no other worker resets it while the BAR is in use.
    pub unsafe fn new(
        window: NonNull<u8>,
        bytes: usize,
        profile: Profile,
        owner: Arc<dyn core::any::Any>,
    ) -> Result<Self, Error> {
        if bytes < BAR_BYTES || window.as_ptr().addr() & 3 != 0 {
            return Err(Error::Register);
        }
        if profile.rtw88().is_none() {
            return Err(Error::WrongChip);
        }
        Ok(Self {
            // SAFETY: the constructor's exclusive mapped-BAR contract.
            mmio: unsafe { Window::new(window, bytes) },
            profile,
            _owner: owner,
        })
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    /// Keep the claim and mapping for good: the device may still reach them.
    pub(super) fn retain(&self) {
        core::mem::forget(self._owner.clone());
    }
    pub(super) fn read8(&self, register: u32) -> u8 {
        self.mmio.read8(register as usize)
    }
    pub(super) fn read16(&self, register: u32) -> u16 {
        self.mmio.read16(register as usize)
    }
    pub(super) fn read32(&self, register: u32) -> u32 {
        self.mmio.read32(register as usize)
    }
    pub(super) fn write8(&self, register: u32, value: u8) {
        self.mmio.write8(register as usize, value);
    }
    pub(super) fn write16(&self, register: u32, value: u16) {
        self.mmio.write16(register as usize, value);
    }
    pub(super) fn write32(&self, register: u32, value: u32) {
        self.mmio.write32(register as usize, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::realtek::identity::tests::profile;
    use alloc::vec::Vec;

    #[test]
    fn a_chip_attached_at_the_window_answers_the_bars_mapped_there() {
        use alloc::rc::Rc;
        use core::cell::RefCell;
        type Stores = RefCell<Vec<(u32, usize, u32)>>;
        struct Echo(Stores);
        impl model::Chip for Echo {
            fn read(&self, register: u32, width: usize) -> u32 {
                register ^ width as u32
            }
            fn write(&self, register: u32, width: usize, value: u32) {
                self.0.borrow_mut().push((register, width, value));
            }
        }
        let memory: Arc<Vec<u32>> = Arc::new(alloc::vec![0; BAR_BYTES / 4]);
        let window = NonNull::new(memory.as_ptr().cast_mut().cast::<u8>()).unwrap();
        let chip = Rc::new(Echo(RefCell::new(Vec::new())));
        model::attach(window, chip.clone());
        // SAFETY: the window is this test's own memory, which the chip
        // answers in its place; nothing else maps it.
        let bar = unsafe { Bar::new(window, BAR_BYTES, profile(), memory.clone()) }.unwrap();
        model::detach(window);
        assert_eq!(bar.read32(0x80), 0x84);
        assert_eq!(bar.read8(0x10), 0x11);
        bar.write16(0x100, 7);
        assert_eq!(*chip.0.borrow(), [(0x100, 2, 7)]);
        assert!(memory.iter().all(|word| *word == 0));
        // SAFETY: as above, read only.
        let plain = unsafe { Bar::new(window, BAR_BYTES, profile(), memory.clone()) }.unwrap();
        assert_eq!(plain.read32(0x80), 0);
    }

    #[test]
    fn native_register_adapter_bounds_alignment_and_quarantine_prevent_invalid_access() {
        use core::sync::atomic::AtomicU32;
        struct NoDma;
        // SAFETY: this fixture owns no DMA, and refuses every
        // submission. It only tests local volatile register window validation.
        unsafe impl BeaconQueue for NoDma {
            fn submit(&mut self, _: &[u8]) -> Result<(), Error> {
                Err(Error::Queue)
            }
            fn quarantine(&mut self) {}
            unsafe fn consumed(&mut self) -> Result<(), Error> {
                Err(Error::Queue)
            }
        }
        let memory: Arc<Vec<AtomicU32>> =
            Arc::new((0..BAR_BYTES / 4).map(|_| AtomicU32::new(0)).collect());
        let owner = Arc::downgrade(&memory);
        let address = memory[0].as_ptr() as u64;
        // A local interior-mutable virtual register window, not an invented
        // PCI claim passed through NativeIo's public unsafe constructor.
        // There are no concurrent accesses, including atomic operations.
        let mut io = NativeIo {
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            registers: unsafe { Window::new(NonNull::new(address as *mut u8).unwrap(), BAR_BYTES) },
            clock: Clock {
                ticks_per_microsecond: 1,
            },
            profile: profile(),
            bytes: BAR_BYTES,
            owned: Some((NoDma, memory)),
        };
        let first = io.now_us().unwrap();
        assert!(io.now_us().unwrap() >= first);
        io.write32(0x1708, 0x1234_abcd).unwrap();
        assert_eq!(io.read32(0x1708), Ok(0x1234_abcd));
        assert_eq!(io.read32(0x170c), Err(Error::Register));
        assert_eq!(io.read32(u32::MAX), Err(Error::Register));
        assert_eq!(io.read16(0x170b), Err(Error::Register));
        assert_eq!(io.write32(1, 0), Err(Error::Register));
        io.quarantine();
        assert_eq!(io.now_us(), Err(Error::InvalidState));
        assert!(matches!(io.beacon_queue(), Err(Error::InvalidState)));
        assert_eq!(io.read32(0), Err(Error::Register));
        assert_eq!(io.submit_beacon(&[0]), Err(Error::InvalidState));
        drop(io);
        assert!(
            owner.upgrade().is_some(),
            "uncertain BAR owner must be retained"
        );
    }
}
