// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C native TX ring bases and firmware-packet DMA transport.
//! Hardware consumer progress releases DMA only, never a command or air ACK.
use super::{
    beacon::{self, Allocation},
    fifo::Geometry,
    identity::Profile,
    io::Bar,
    registers::*,
};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain},
    memory::PageSource,
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{Ordering, fence};

const H2C_COUNT: usize = 128;
const DESCRIPTOR: usize = 16;
const PACKET: usize = 48 + 32;
/// One frame's page: its packet descriptor, then the MPDU.
const FRAME: usize = 8192;
/// The longest MPDU a buffer holds behind its descriptor, which an HT peer's
/// long A-MSDU fits and a VHT peer's longest is held to.
pub const MAX_FRAME: usize = FRAME - 48;
/// The pages a quiet queue keeps mapped for the next burst.
const SPARE: usize = 64;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Resource(beacon::Error),
    Register,
    Removed,
    UnsupportedChip,
    UnsupportedLayout,
    IdentityChanged,
    FirmwareNotReady,
    InitialIndices,
    Index,
    CompletionBeyondPending,
    Full,
    Quarantined,
}
impl From<beacon::Error> for Error {
    fn from(e: beacon::Error) -> Self {
        Self::Resource(e)
    }
}

/// Source queues with ordinary host producer/device consumer indices. Beacon
/// is a separate reserved-page queue with its own BCN_VALID ownership proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Queue {
    Background,
    BestEffort,
    Video,
    Voice,
    Management,
    High,
    H2c,
}
const QUEUES: [Queue; 7] = [
    Queue::Background,
    Queue::BestEffort,
    Queue::Video,
    Queue::Voice,
    Queue::Management,
    Queue::High,
    Queue::H2c,
];
/// The frames one queue has given the device.
struct Frames {
    slots: Vec<Option<Allocation>>,
    read: u16,
    write: u16,
}
impl Queue {
    fn index(self) -> usize {
        QUEUES.iter().position(|&queue| queue == self).unwrap_or(0)
    }
    pub fn count(self) -> u16 {
        if self == Self::BestEffort { 256 } else { 128 }
    }
    fn registers(self) -> (u32, u32, u32) {
        match self {
            Self::Background => (
                RTK_PCI_TXBD_DESA_BKQ,
                RTK_PCI_TXBD_NUM_BKQ,
                RTK_PCI_TXBD_IDX_BKQ,
            ),
            Self::BestEffort => (
                RTK_PCI_TXBD_DESA_BEQ,
                RTK_PCI_TXBD_NUM_BEQ,
                RTK_PCI_TXBD_IDX_BEQ,
            ),
            Self::Video => (
                RTK_PCI_TXBD_DESA_VIQ,
                RTK_PCI_TXBD_NUM_VIQ,
                RTK_PCI_TXBD_IDX_VIQ,
            ),
            Self::Voice => (
                RTK_PCI_TXBD_DESA_VOQ,
                RTK_PCI_TXBD_NUM_VOQ,
                RTK_PCI_TXBD_IDX_VOQ,
            ),
            Self::Management => (
                RTK_PCI_TXBD_DESA_MGMTQ,
                RTK_PCI_TXBD_NUM_MGMTQ,
                RTK_PCI_TXBD_IDX_MGMTQ,
            ),
            Self::High => (
                RTK_PCI_TXBD_DESA_HI0Q,
                RTK_PCI_TXBD_NUM_HI0Q,
                RTK_PCI_TXBD_IDX_HI0Q,
            ),
            Self::H2c => (
                RTK_PCI_TXBD_DESA_H2CQ,
                RTK_PCI_TXBD_NUM_H2CQ,
                RTK_PCI_TXBD_IDX_H2CQ,
            ),
        }
    }
}
/// # Safety
/// Exclusive selected RTL8822C register owner and kept UC BAR2.
/// Fresh volatile indices and ordered register stores, no synthesized
/// completion. Hardware remains awake; no competing reset/PS/submission worker.
pub unsafe trait Registers {
    fn profile(&self) -> Profile;
    fn verify_identity(&mut self) -> Result<(), Error>;
    fn firmware_ready(&mut self) -> Result<(), Error>;
    fn indices(&mut self, queue: Queue) -> Result<(u16, u16), Error>;
    fn configure(&mut self, queue: Queue, address: u32) -> Result<(), Error>;
    fn publish_h2c(&mut self, producer: u16) -> Result<(), Error>;
    /// `rtw_pci_tx_kick_off_queue`.
    fn publish(&mut self, queue: Queue, producer: u16) -> Result<(), Error>;
}
// SAFETY: `Bar::new` binds the exclusive BAR of the profile's requester.
unsafe impl Registers for Bar {
    fn profile(&self) -> Profile {
        Bar::profile(self)
    }
    fn verify_identity(&mut self) -> Result<(), Error> {
        let value = self.read32(REG_SYS_CFG1);
        if value == u32::MAX {
            return Err(Error::Removed);
        }
        if value != self.profile().observed().sys_cfg1 {
            return Err(Error::IdentityChanged);
        }
        Ok(())
    }
    fn firmware_ready(&mut self) -> Result<(), Error> {
        let value = self.read16(REG_MCUFW_CTRL);
        if value == u16::MAX {
            return Err(Error::Removed);
        }
        if value & FW_READY_MASK != FW_READY {
            return Err(Error::FirmwareNotReady);
        }
        Ok(())
    }
    fn indices(&mut self, q: Queue) -> Result<(u16, u16), Error> {
        let value = self.read32(q.registers().2);
        if value == u32::MAX {
            return Err(Error::Removed);
        }
        Ok(((value & 0xfff) as u16, ((value >> 16) & 0xfff) as u16))
    }
    fn configure(&mut self, q: Queue, address: u32) -> Result<(), Error> {
        let (base, count, _) = q.registers();
        self.write16(count, q.count());
        self.write32(base, address);
        if self.read16(count) & 0xfff != q.count() || self.read32(base) != address {
            return Err(Error::Register);
        }
        Ok(())
    }
    fn publish_h2c(&mut self, producer: u16) -> Result<(), Error> {
        self.write16(RTK_PCI_TXBD_IDX_H2CQ, producer);
        Ok(())
    }
    fn publish(&mut self, queue: Queue, producer: u16) -> Result<(), Error> {
        self.write16(queue.registers().2, producer);
        Ok(())
    }
}

/// All seven indexed TX queues have real native descriptor backing, so engine
/// prefetch never addresses a placeholder ring. Typed general-info/PHYDM and
/// initial IQK firmware packets use this queue; radio DATA/keys/air reports
/// remain separate. DMA release never stands in for command completion.
pub struct Rings<R: Registers> {
    io: Option<R>,
    domain: Arc<dyn DmaDomain>,
    rings: Vec<Allocation>,
    pending: Vec<Option<Allocation>>,
    frames: Vec<Frames>,
    spare: Vec<Allocation>,
    read: u16,
    write: u16,
    sequence: u16,
    configured: bool,
    used: bool,
    poisoned: bool,
}
impl<R: Registers> Rings<R> {
    /// # Safety
    /// Exact RTL8822C requester independently stopped/drained, every
    /// indexed TX producer/consumer reset to 0, firmware H2C sequence reset 0.
    /// Real coherent WB RAM, NoSnoop/ATS disabled, exclusive UC BAR/requester
    /// and domain. Full RX/beacon rings and HCI reset/start remain separate.
    /// No reset, deep-PS, key/radio retirement or competing worker during use.
    pub unsafe fn install(
        mut io: R,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        if io.profile().rtw88().is_none() {
            return Err(Error::UnsupportedChip);
        }
        io.verify_identity()?;
        for q in QUEUES {
            if io.indices(q)? != (0, 0) {
                return Err(Error::InitialIndices);
            }
        }
        let mut rings = Vec::new();
        let mut pending = Vec::new();
        rings.try_reserve_exact(7).map_err(|_| {
            Error::Resource(beacon::Error::Memory(
                crate::bus::dma::memory::MemoryError::OutOfMemory,
            ))
        })?;
        pending.try_reserve_exact(H2C_COUNT).map_err(|_| {
            Error::Resource(beacon::Error::Memory(
                crate::bus::dma::memory::MemoryError::OutOfMemory,
            ))
        })?;
        for q in QUEUES {
            let a = Allocation::new(
                source,
                domain.clone(),
                usize::from(q.count()) * DESCRIPTOR,
                Direction::Bidirectional,
            )?;
            // Native mappings cover full pages. Clear/synchronize even the
            // unused page tail so hardware prefetch never sees heap content.
            a.write(0, &[0; 4096])?;
            a.dma
                .sync_for_device(0..a.dma.bytes())
                .map_err(beacon::Error::from)?;
            rings.push(a);
        }
        pending.resize_with(H2C_COUNT, || None);
        let mut frames = Vec::new();
        for q in &QUEUES[..6] {
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(usize::from(q.count()))
                .map_err(|_| {
                    Error::Resource(beacon::Error::Memory(
                        crate::bus::dma::memory::MemoryError::OutOfMemory,
                    ))
                })?;
            slots.resize_with(usize::from(q.count()), || None);
            frames.push(Frames {
                slots,
                read: 0,
                write: 0,
            });
        }
        let mut s = Self {
            io: Some(io),
            domain,
            rings,
            pending,
            frames,
            spare: Vec::new(),
            read: 0,
            write: 0,
            sequence: 0,
            configured: false,
            used: false,
            poisoned: true,
        };
        for (index, q) in QUEUES.into_iter().enumerate() {
            let address = s.rings[index].address()?;
            s.rings[index].published = true;
            s.configured = true;
            fence(Ordering::Release);
            s.io.as_mut()
                .ok_or(Error::Quarantined)?
                .configure(q, address)?;
        }
        s.poisoned = false;
        Ok(s)
    }
    pub fn quarantined(&self) -> bool {
        self.poisoned
    }
    pub fn pending(&self) -> usize {
        distance(self.read, self.write)
    }
    /// A frame still with the device, `rtw_pci_deep_ps_enter`'s bar to it. The
    /// firmware's own queue does not count.
    pub fn frames_pending(&self) -> bool {
        QUEUES
            .iter()
            .filter(|&&queue| queue != Queue::H2c)
            .map(|queue| &self.frames[queue.index()])
            .any(|frames| frames.read != frames.write)
    }
    /// Queue source general-info packet; success is publication only. Geometry
    /// must belong to the exact profile. No firmware ACK is invented.
    pub fn general_info(
        &mut self,
        source: &dyn PageSource,
        geometry: Geometry,
    ) -> Result<(), Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        if geometry.profile() != self.io.as_ref().ok_or(Error::Quarantined)?.profile() {
            return Err(Error::IdentityChanged);
        }
        if self.pending() == H2C_COUNT - 1 {
            return Err(Error::Full);
        }
        let payload = general_info(geometry, self.sequence);
        self.command(source, payload)
    }
    /// Publish source PHYDM parameters for the real initialized AB/AB PHY.
    /// Success is publication only, not firmware application or calibration.
    ///
    /// # Safety
    /// phy, report and these rings are the same native
    /// requester/board/reset/firmware epoch, not matching Profile fingerprints
    /// alone. Source PHY/MAC/HCI start completed; all queues/pins remain live,
    /// native control is exclusive and operational TX stays gated pending
    /// channel/RFK/power/OS validation. Real firmware command/data
    /// retirement remains independent of descriptor consumer-index release.
    pub unsafe fn phydm_info(
        &mut self,
        source: &dyn PageSource,
        phy: &super::phy::Initialized,
        report: &super::features::Report,
    ) -> Result<(), Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        let profile = self.io.as_ref().ok_or(Error::Quarantined)?.profile();
        if phy.profile() != profile || report.profile() != profile {
            return Err(Error::IdentityChanged);
        }
        let cap = report.capabilities();
        let rf_type = match (cap.rf_paths, cap.rf_phys, cap.antenna_tx, cap.antenna_rx) {
            (2, 2, 3, 3) => FW_RF_2T2R,
            (1, 1, 1, 1) => FW_RF_1T1R,
            _ => return Err(Error::UnsupportedLayout),
        };
        if self.pending() == H2C_COUNT - 1 {
            return Err(Error::Full);
        }
        let payload = phydm_info(
            phy.rfe(),
            rf_type,
            profile.cut(),
            cap.antenna_tx,
            cap.antenna_rx,
            self.sequence,
        );
        self.command(source, payload)
    }
    /// # Safety
    /// Same kept native requester/reset/firmware epoch as the
    /// calibration control owner. Complete source GAPK/PHYDM and real native
    /// HCI start, held native/OS/coexistence permission, required power
    /// and emission gates, current channel and exclusive calibration work are
    /// caller-owned. IQK may emit calibration signals. This only publishes the
    /// source clear=1/segment=0 command; a fresh IQK completion and
    /// independent DMA/firmware retirement are still required.
    pub(super) unsafe fn initial_iqk_command(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<(), Error> {
        // SAFETY: forwarded from the caller.
        unsafe { self.iqk_command(source, true, false) }
    }
    /// `rtw_fw_do_iqk` with `clear` and `segment_iqk`.
    ///
    /// # Safety
    /// As [`Self::initial_iqk_command`], for the command's own parameters.
    pub unsafe fn iqk_command(
        &mut self,
        source: &dyn PageSource,
        clear: bool,
        segment: bool,
    ) -> Result<(), Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        if self.pending() == H2C_COUNT - 1 {
            return Err(Error::Full);
        }
        self.command(source, iqk(self.sequence, clear, segment))
    }
    /// `rtw_pci_tx_write_data`: give `queue` one frame, which `packet` describes.
    /// [`Error::Full`] only asks to try again once the queue drains.
    pub fn frame(
        &mut self,
        queue: Queue,
        source: &dyn PageSource,
        packet: &[u8; 48],
        frame: &[u8],
    ) -> Result<(), Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        if queue == Queue::H2c || 48 + frame.len() > FRAME {
            return Err(Error::UnsupportedLayout);
        }
        self.used = true;
        self.poisoned = true;
        let result = self.submit_frame(queue, source, packet, frame);
        if matches!(result, Ok(()) | Err(Error::Full)) {
            self.poisoned = false;
        }
        result
    }
    fn submit_frame(
        &mut self,
        queue: Queue,
        source: &dyn PageSource,
        packet: &[u8; 48],
        frame: &[u8],
    ) -> Result<(), Error> {
        self.reclaim_queue(queue)?;
        let which = queue.index();
        let count = queue.count();
        let cursor = &self.frames[which];
        let index = usize::from(cursor.write);
        if (cursor.write + 1) % count == cursor.read {
            return Err(Error::Full);
        }
        let a = match self.spare.pop() {
            Some(a) => a,
            None => Allocation::new(source, self.domain.clone(), FRAME, Direction::ToDevice)?,
        };
        let total = 48 + frame.len();
        let address = a.address()?;
        a.write(0, packet)?;
        a.write(48, frame)?;
        a.dma
            .sync_for_device(0..total)
            .map_err(beacon::Error::from)?;
        let offset = index * DESCRIPTOR;
        let cursor = &mut self.frames[which];
        cursor.slots[index] = Some(a);
        if let Some(a) = &mut cursor.slots[index] {
            a.published = true;
        }
        let descriptor = frame_descriptor(address, frame.len());
        self.rings[which].write(offset, &descriptor)?;
        self.rings[which]
            .dma
            .sync_for_device(offset..offset + DESCRIPTOR)
            .map_err(beacon::Error::from)?;
        let cursor = &mut self.frames[which];
        cursor.write = (cursor.write + 1) % count;
        let producer = cursor.write;
        fence(Ordering::Release);
        self.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .publish(queue, producer)
    }
    /// Take back the frames the device has read, from every queue. That they
    /// were read says nothing of whether they went on air.
    pub fn reclaim_frames(&mut self) -> Result<usize, Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        self.poisoned = true;
        let mut reclaimed = 0;
        for queue in QUEUES {
            if queue != Queue::H2c {
                reclaimed += self.reclaim_queue(queue)?;
            }
        }
        self.poisoned = false;
        Ok(reclaimed)
    }
    fn reclaim_queue(&mut self, queue: Queue) -> Result<usize, Error> {
        let (host, device) = self.io.as_mut().ok_or(Error::Quarantined)?.indices(queue)?;
        let count = queue.count();
        let cursor = &mut self.frames[queue.index()];
        if host != cursor.write || device >= count {
            return Err(Error::Index);
        }
        let done = (device + count - cursor.read) % count;
        if done > (cursor.write + count - cursor.read) % count {
            return Err(Error::CompletionBeyondPending);
        }
        for _ in 0..done {
            let mut a = cursor.slots[usize::from(cursor.read)]
                .take()
                .ok_or(Error::CompletionBeyondPending)?;
            cursor.read = (cursor.read + 1) % count;
            if self.spare.len() < SPARE {
                self.spare.push(a);
            } else {
                // SAFETY: the consumer index passed it, ending device reads.
                unsafe { a.release()? };
            }
        }
        Ok(usize::from(done))
    }
    pub(super) fn quarantine_firmware(&mut self) {
        self.poisoned = true;
    }
    fn command(&mut self, source: &dyn PageSource, payload: [u8; 32]) -> Result<(), Error> {
        self.used = true;
        // A reserved sequence is never rolled back after uncertain DMA/MMIO.
        self.sequence = self.sequence.wrapping_add(1);
        self.poisoned = true;
        let result = self.submit(source, &payload);
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    fn submit(&mut self, source: &dyn PageSource, payload: &[u8; 32]) -> Result<(), Error> {
        self.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .verify_identity()?;
        self.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .firmware_ready()?;
        let (host, device) = self
            .io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .indices(Queue::H2c)?;
        if host != self.write || device as usize >= H2C_COUNT {
            return Err(Error::Index);
        }
        if distance(self.read, device) > self.pending() {
            return Err(Error::CompletionBeyondPending);
        }
        let a = Allocation::new(source, self.domain.clone(), PACKET, Direction::ToDevice)?;
        let (packet, descriptor) = h2c_descriptors(a.address()?)?;
        a.write(0, &packet)?;
        a.write(48, payload)?;
        a.dma
            .sync_for_device(0..PACKET)
            .map_err(beacon::Error::from)?;
        let index = usize::from(self.write);
        let offset = index * DESCRIPTOR;
        if self.pending[index].is_some() {
            return Err(Error::CompletionBeyondPending);
        }
        // Once an IOVA enters an already configured coherent descriptor, the
        // real payload owner must survive even before consumer publication.
        self.pending[index] = Some(a);
        self.pending[index].as_mut().unwrap().published = true;
        self.rings[6].write(offset, &descriptor)?;
        self.rings[6]
            .dma
            .sync_for_device(offset..offset + DESCRIPTOR)
            .map_err(beacon::Error::from)?;
        self.write = ((index + 1) % H2C_COUNT) as u16;
        fence(Ordering::Release);
        self.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .publish_h2c(self.write)
    }
    /// Fresh hardware consumer-index progress releases command DMA only.
    /// Neither emptiness nor release means command accepted/completed by MCU.
    pub fn reclaim_h2c(&mut self) -> Result<usize, Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        self.poisoned = true;
        let result = self.reclaim();
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    fn reclaim(&mut self) -> Result<usize, Error> {
        self.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .verify_identity()?;
        let (host, device) = self
            .io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .indices(Queue::H2c)?;
        if host != self.write || device as usize >= H2C_COUNT {
            return Err(Error::Index);
        }
        let count = distance(self.read, device);
        if count > self.pending() {
            return Err(Error::CompletionBeyondPending);
        }
        for _ in 0..count {
            let index = usize::from(self.read);
            let offset = index * DESCRIPTOR;
            // SAFETY: bounded hardware consumer advance consumed this
            // live descriptor/payload; independent full stop not needed
            // for this completed ToDevice buffer, but no air/FW ACK follows.
            unsafe { self.rings[6].dma.sync_for_cpu(offset..offset + DESCRIPTOR) }
                .map_err(beacon::Error::from)?;
            let a = self.pending[index]
                .as_mut()
                .ok_or(Error::CompletionBeyondPending)?;
            // SAFETY: the consumer advance above ended device reads of this payload.
            unsafe {
                a.release()?;
            }
            self.pending[index] = None;
            self.read = ((index + 1) % H2C_COUNT) as u16;
        }
        Ok(count)
    }
    /// # Safety
    /// Independently stopped/drained requester. Initial HCI only; any
    /// admitted command permanently refuses this path even after DMA reclaim,
    /// so command/key/station generations are never reset through it.
    pub(super) unsafe fn begin_hci_rebind(&mut self) -> Result<[u32; 7], Error> {
        if self.poisoned || self.used || !self.configured {
            return Err(Error::Quarantined);
        }
        self.poisoned = true;
        let mut addresses = [0; 7];
        for (i, a) in self.rings.iter().enumerate() {
            // SAFETY: covered by this function's own safety contract.
            unsafe { a.dma.sync_for_cpu(0..a.dma.bytes()) }.map_err(beacon::Error::from)?;
            for offset in (0..a.dma.bytes()).step_by(4096) {
                a.write(offset, &[0; 4096][..(a.dma.bytes() - offset).min(4096)])?;
            }
            a.dma
                .sync_for_device(0..a.dma.bytes())
                .map_err(beacon::Error::from)?;
            addresses[i] = a.address()?;
        }
        Ok(addresses)
    }
    pub(super) fn finish_hci_rebind(&mut self) {
        self.read = 0;
        self.write = 0;
        self.poisoned = false;
    }
    pub(super) fn initial_indices(&mut self) -> Result<(), Error> {
        for q in QUEUES {
            if self.io.as_mut().ok_or(Error::Quarantined)?.indices(q)? != (0, 0) {
                return Err(Error::InitialIndices);
            }
        }
        Ok(())
    }
    pub(super) fn profile(&self) -> Result<Profile, Error> {
        Ok(self.io.as_ref().ok_or(Error::Quarantined)?.profile())
    }
    /// # Safety
    /// Independent acknowledged requester stop/drain and all workers
    /// stopped through unmap. Index equality/reset writes are insufficient.
    pub unsafe fn release_after_stop(&mut self) -> Result<(), Error> {
        self.poisoned = true;
        for a in &mut self.rings {
            // SAFETY: covered by this function's own safety contract.
            unsafe {
                a.release()?;
            }
        }
        for a in self
            .pending
            .iter_mut()
            .chain(self.frames.iter_mut().flat_map(|queue| &mut queue.slots))
            .flatten()
            .chain(&mut self.spare)
        {
            // SAFETY: covered by this function's own safety contract.
            unsafe {
                a.release()?;
            }
        }
        self.pending.clear();
        self.frames.clear();
        self.spare.clear();
        self.configured = false;
        Ok(())
    }
}
impl<R: Registers> Drop for Rings<R> {
    fn drop(&mut self) {
        if self.configured
            && let Some(io) = self.io.take()
        {
            core::mem::forget(io);
        }
    }
}
fn distance(read: u16, write: u16) -> usize {
    (usize::from(write) + H2C_COUNT - usize::from(read)) % H2C_COUNT
}
fn general_info(geometry: Geometry, sequence: u16) -> [u8; 32] {
    let mut p = [0; 32];
    p[..4].copy_from_slice(&0x000dff01u32.to_le_bytes());
    p[4..8].copy_from_slice(&(12u32 | (u32::from(sequence) << 16)).to_le_bytes());
    p[10] = (geometry.firmware_tx_page() - geometry.boundary()) as u8;
    p
}
/// `FW_RF_2T2R` and `FW_RF_1T1R`.
const FW_RF_2T2R: u8 = 2;
const FW_RF_1T1R: u8 = 4;
fn phydm_info(
    rfe: u8,
    rf_type: u8,
    cut: u8,
    antenna_tx: u8,
    antenna_rx: u8,
    sequence: u16,
) -> [u8; 32] {
    let mut p = [0; 32];
    p[..4].copy_from_slice(&0x0011ff01u32.to_le_bytes());
    p[4..8].copy_from_slice(&(16u32 | (u32::from(sequence) << 16)).to_le_bytes());
    p[8] = rfe;
    p[9] = rf_type;
    p[10] = cut;
    p[11] = (antenna_tx & 15) | ((antenna_rx & 15) << 4);
    p
}
/// `H2C_PKT_IQK`: `IQK_SET_CLEAR` and `IQK_SET_SEGMENT_IQK`.
fn iqk(sequence: u16, clear: bool, segment: bool) -> [u8; 32] {
    let mut p = [0; 32];
    p[..4].copy_from_slice(&0x000eff01u32.to_le_bytes());
    p[4..8].copy_from_slice(&(9u32 | (u32::from(sequence) << 16)).to_le_bytes());
    p[8] = u8::from(clear) | (u8::from(segment) << 1);
    p
}
/// `rtw_pci_tx_write_data`'s two buffer descriptors: the packet descriptor at
/// `address`, then the MPDU behind it.
fn frame_descriptor(address: u32, length: usize) -> [u8; DESCRIPTOR] {
    let mut bd = [0; DESCRIPTOR];
    bd[..2].copy_from_slice(&48u16.to_le_bytes());
    bd[2..4].copy_from_slice(&(((47 + length) / 128 + 1) as u16).to_le_bytes());
    bd[4..8].copy_from_slice(&address.to_le_bytes());
    bd[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    bd[12..16].copy_from_slice(&(address + 48).to_le_bytes());
    bd
}
fn h2c_descriptors(address: u32) -> Result<([u8; 48], [u8; 16]), Error> {
    address
        .checked_add((PACKET - 1) as u32)
        .ok_or(Error::Resource(beacon::Error::Address))?;
    let payload = address + 48;
    let mut p = [0; 48];
    p[..4].copy_from_slice(&32u32.to_le_bytes());
    p[4..8].copy_from_slice(&(19u32 << 8).to_le_bytes());
    let mut bd = [0; 16];
    bd[..2].copy_from_slice(&48u16.to_le_bytes());
    bd[2..4].copy_from_slice(&1u16.to_le_bytes());
    bd[4..8].copy_from_slice(&address.to_le_bytes());
    bd[8..10].copy_from_slice(&32u16.to_le_bytes());
    bd[12..16].copy_from_slice(&payload.to_le_bytes());
    Ok((p, bd))
}

#[cfg(test)]
mod tests;
