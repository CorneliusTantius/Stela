// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C native PCIe RX buffer ring and borrowed raw descriptor facts.
//! Hardware producer/tag/visibility establishes DMA ownership only. Raw
//! decryption flags are not integrity, key, replay, MLME or radio-ready proof.
use super::{
    beacon::{self, Allocation},
    io::Bar,
    registers::*,
};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain},
    memory::PageSource,
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{Ordering, fence};

const COUNT: usize = 512;
const BUFFER: usize = 11454 + 24;
const DESCRIPTOR: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Resource(beacon::Error),
    Register,
    Removed,
    Index(u16),
    InitialIndices,
    Quarantined,
}
impl From<beacon::Error> for Error {
    fn from(e: beacon::Error) -> Self {
        Self::Resource(e)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    Truncated,
    Rate(u8),
    DriverInfo(u8),
    MissingPhy,
    Length,
    Bounds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Facts {
    pub crc_error: bool,
    pub icv_error: bool,
    pub encryption_raw: u8,
    /// Raw !SWDEC && ENC_TYPE != 0; never verified integrity or an installed key.
    pub hardware_decrypted: bool,
    pub phy_present: bool,
    pub firmware: bool,
    pub cam_id: u8,
    pub ppdu_count: u8,
    pub rate_raw: u8,
    pub bandwidth_raw: u8,
    pub tsf_low: u32,
}
#[derive(Debug)]
pub struct Packet<'a> {
    pub descriptor: &'a [u8; 24],
    pub shift: &'a [u8],
    pub driver_info: &'a [u8],
    /// Source packet bytes, including any FCS selected by MAC/RCR.
    /// This is not a validated/decrypted shared Wi-Fi MPDU.
    pub payload: &'a [u8],
    pub facts: Facts,
}
pub fn parse(buffer: &[u8]) -> Result<Packet<'_>, ParseError> {
    let descriptor: &[u8; 24] = buffer
        .get(..24)
        .ok_or(ParseError::Truncated)?
        .try_into()
        .unwrap();
    let word = |i: usize| u32::from_le_bytes(descriptor[i * 4..i * 4 + 4].try_into().unwrap());
    let w0 = word(0);
    let length = (w0 & 0x3fff) as usize;
    let driver_units = ((w0 >> 16) & 15) as u8;
    let shift = ((w0 >> 24) & 3) as usize;
    let enc = ((w0 >> 20) & 7) as u8;
    let phy = w0 & (1 << 26) != 0;
    let firmware = word(2) & (1 << 28) != 0;
    let rate = (word(3) & 0x7f) as u8;
    if rate >= 0x54 {
        return Err(ParseError::Rate(rate));
    }
    if driver_units != 0 && driver_units != 4 {
        return Err(ParseError::DriverInfo(driver_units));
    }
    if phy && driver_units == 0 {
        return Err(ParseError::MissingPhy);
    }
    if length > 11454 || (!firmware && length <= 4) {
        return Err(ParseError::Length);
    }
    let phy_start = 24 + shift;
    let payload_start = phy_start + usize::from(driver_units) * 8;
    let end = payload_start + length;
    if end > BUFFER || end > buffer.len() {
        return Err(ParseError::Bounds);
    }
    Ok(Packet {
        descriptor,
        shift: &buffer[24..phy_start],
        driver_info: &buffer[phy_start..payload_start],
        payload: &buffer[payload_start..end],
        facts: Facts {
            crc_error: w0 & (1 << 14) != 0,
            icv_error: w0 & (1 << 15) != 0,
            encryption_raw: enc,
            hardware_decrypted: w0 & (1 << 27) == 0 && enc != 0,
            phy_present: phy,
            firmware,
            cam_id: (word(1) & 0x7f) as u8,
            ppdu_count: ((word(2) >> 29) & 3) as u8,
            rate_raw: rate,
            bandwidth_raw: ((word(4) >> 4) & 3) as u8,
            tsf_low: word(5),
        },
    })
}

fn buffer_descriptor(address: u32) -> [u8; DESCRIPTOR] {
    let mut bytes = [0; DESCRIPTOR];
    bytes[..2].copy_from_slice(&(BUFFER as u16).to_le_bytes());
    bytes[4..].copy_from_slice(&address.to_le_bytes());
    bytes
}
fn available(consumer: u16, producer: u16) -> usize {
    (usize::from(producer) + COUNT - usize::from(consumer)) % COUNT
}

/// # Safety
/// Exclusive RTL8822C requester RX register block, kept claim/UC
/// BAR mapping for this object's full lifetime. Indices are fresh volatile
/// reads, writes ordered MMIO; no cached/manufactured completion.
/// Configuration requires acknowledged stopped/drained DMA and zero indices.
pub unsafe trait Registers {
    fn configure(&mut self, iova: u32, count: u16) -> Result<(), Error>;
    fn indices(&mut self) -> Result<(u16, u16), Error>;
    fn publish(&mut self, consumer: u16) -> Result<(), Error>;
}
// SAFETY: `Bar::new` binds the exclusive requester BAR.
unsafe impl Registers for Bar {
    fn configure(&mut self, iova: u32, count: u16) -> Result<(), Error> {
        self.write16(RTK_PCI_RXBD_NUM_MPDUQ, count);
        self.write32(RTK_PCI_RXBD_DESA_MPDUQ, iova);
        if self.read16(RTK_PCI_RXBD_NUM_MPDUQ) & 0xfff != count
            || self.read32(RTK_PCI_RXBD_DESA_MPDUQ) != iova
        {
            return Err(Error::Register);
        }
        Ok(())
    }
    fn indices(&mut self) -> Result<(u16, u16), Error> {
        let value = self.read32(RTK_PCI_RXBD_IDX_MPDUQ);
        if value == u32::MAX {
            return Err(Error::Removed);
        }
        Ok(((value & 0xfff) as u16, ((value >> 16) & 0xfff) as u16))
    }
    fn publish(&mut self, consumer: u16) -> Result<(), Error> {
        self.write16(RTK_PCI_RXBD_IDX_MPDUQ, consumer);
        Ok(())
    }
}

/// One source-sized native RX ring. Buffers/descriptor mappings and
/// register owner survive uncertain Drop. Call poll only in deferred context,
/// never from an IRQ handler or concurrently with reset/key/channel retirement.
pub struct Ring<R: Registers> {
    io: Option<R>,
    descriptor: Allocation,
    buffers: Vec<Allocation>,
    read: u16,
    tag: u16,
    configured: bool,
    used: bool,
    poisoned: bool,
    /// Descriptors `rtw_rx_query_rx_desc` refuses or `rtw_pci_rx_napi` finds
    /// oversized, which rtw88 skips and rearms.
    dropped: u32,
    /// Buffers whose tag was not the one expected: rtw88's "pci bus timeout,
    /// check dma status" warning, after which it takes the frame anyway.
    tag_slips: u32,
}
impl<R: Registers> Ring<R> {
    /// # Safety
    /// Real selected RTL8822C is independently stopped/drained with
    /// zero producer/consumer indices and RX tag reset to zero. `io` owns that
    /// requester/UC BAR and `domain` isolates it. All allocations are real
    /// coherent WB DMA RAM with NoSnoop/ATS disabled (WB alone is insufficient).
    /// Full source HCI configuration before enabling engines remains required;
    /// this only installs the native RX ring. No competing worker may touch it.
    pub unsafe fn install(
        mut io: R,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        if io.indices()? != (0, 0) {
            return Err(Error::InitialIndices);
        }
        let descriptor = Allocation::new(
            source,
            domain.clone(),
            COUNT * DESCRIPTOR,
            Direction::Bidirectional,
        )?;
        let mut buffers = Vec::new();
        buffers.try_reserve_exact(COUNT).map_err(|_| {
            Error::Resource(beacon::Error::Memory(
                crate::bus::dma::memory::MemoryError::OutOfMemory,
            ))
        })?;
        for _ in 0..COUNT {
            buffers.push(Allocation::new(
                source,
                domain.clone(),
                BUFFER,
                Direction::FromDevice,
            )?);
        }
        let mut ring = Self {
            io: Some(io),
            descriptor,
            buffers,
            read: 0,
            tag: 0,
            configured: false,
            used: false,
            poisoned: true,
            dropped: 0,
            tag_slips: 0,
        };
        for i in 0..COUNT {
            ring.reset_descriptor(i)?;
        }
        ring.descriptor
            .dma
            .sync_for_device(0..COUNT * DESCRIPTOR)
            .map_err(beacon::Error::from)?;
        fence(Ordering::Release);
        // A configuration store may expose every descriptor and payload,
        // even when its readback/return fails. Set retention beforehand.
        ring.descriptor.published = true;
        for buffer in &mut ring.buffers {
            buffer.published = true;
        }
        ring.configured = true;
        let address = ring.descriptor.address()?;
        ring.io
            .as_mut()
            .ok_or(Error::Quarantined)?
            .configure(address, COUNT as u16)?;
        ring.poisoned = false;
        Ok(ring)
    }
    pub fn quarantined(&self) -> bool {
        self.poisoned
    }
    pub fn consumer(&self) -> u16 {
        self.read
    }
    pub fn expected_tag(&self) -> u16 {
        self.tag
    }
    /// Descriptors skipped as rtw88 skips them, since installation.
    pub fn dropped(&self) -> u32 {
        self.dropped
    }
    /// Tags out of step, which rtw88 only warns of, since installation.
    pub fn tag_slips(&self) -> u32 {
        self.tag_slips
    }
    fn reset_descriptor(&mut self, index: usize) -> Result<(), Error> {
        self.buffers[index]
            .dma
            .sync_for_device(0..BUFFER)
            .map_err(beacon::Error::from)?;
        let bytes = buffer_descriptor(self.buffers[index].address()?);
        self.descriptor.write(index * DESCRIPTOR, &bytes)?;
        Ok(())
    }
    /// Deliver borrowed raw facts only while CPU owns the completed buffer.
    /// Callback cannot keep its borrow through rearm. A producer-index DMA
    /// event is not a radio integrity/key/replay/MLME acknowledgement.
    pub fn poll(
        &mut self,
        budget: usize,
        mut receive: impl FnMut(Packet<'_>),
    ) -> Result<usize, Error> {
        if self.poisoned || !self.configured {
            return Err(Error::Quarantined);
        }
        self.used = true;
        self.poisoned = true;
        let result = self.poll_inner(budget.min(COUNT - 1), &mut receive);
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    fn poll_inner(
        &mut self,
        budget: usize,
        receive: &mut impl FnMut(Packet<'_>),
    ) -> Result<usize, Error> {
        let (consumer, producer) = self.io.as_mut().ok_or(Error::Quarantined)?.indices()?;
        if consumer != self.read {
            return Err(Error::Index(consumer));
        }
        if producer as usize >= COUNT {
            return Err(Error::Index(producer));
        }
        let count = available(self.read, producer);
        let count = count.min(budget);
        for _ in 0..count {
            let index = usize::from(self.read);
            let offset = index * DESCRIPTOR;
            // SAFETY: fresh producer advance transfers this descriptor
            // and corresponding buffer to CPU; no reuse until publish below.
            unsafe {
                self.descriptor
                    .dma
                    .sync_for_cpu(offset..offset + DESCRIPTOR)
            }
            .map_err(beacon::Error::from)?;
            let pointer = self
                .descriptor
                .cpu
                .address(offset + 2, 2)
                .map_err(beacon::Error::from)?;
            // SAFETY: `address` bounds this aligned u16 inside the synced descriptor.
            let observed = u16::from_le(unsafe { pointer.as_ptr().cast::<u16>().read_volatile() });
            // rtw_pci_dma_check: a tag out of step is warned of, and the
            // frame is still taken, with the expected tag counting on.
            if observed != self.tag {
                self.tag_slips = self.tag_slips.saturating_add(1);
            }
            // SAFETY: the same producer advance hands this descriptor's buffer to the CPU.
            unsafe { self.buffers[index].dma.sync_for_cpu(0..BUFFER) }
                .map_err(beacon::Error::from)?;
            let pointer = self.buffers[index]
                .cpu
                .address(0, BUFFER)
                .map_err(beacon::Error::from)?;
            // SAFETY: bounded native allocation, now CPU-owned
            // after hardware completion/visibility; callback borrow ends before
            // descriptor/payload rearm or any new hardware ownership transfer.
            let bytes = unsafe { core::slice::from_raw_parts(pointer.as_ptr(), BUFFER) };
            // rtw_pci_rx_napi skips what rtw_rx_query_rx_desc refuses and
            // what would overrun its buffer, and rearms the slot.
            match parse(bytes) {
                Ok(packet) => receive(packet),
                Err(_) => self.dropped = self.dropped.saturating_add(1),
            }
            self.reset_descriptor(index)?;
            self.descriptor
                .dma
                .sync_for_device(offset..offset + DESCRIPTOR)
                .map_err(beacon::Error::from)?;
            self.read = ((index + 1) % COUNT) as u16;
            self.tag = (self.tag + 1) % 8192;
        }
        if count != 0 {
            fence(Ordering::Release);
            self.io
                .as_mut()
                .ok_or(Error::Quarantined)?
                .publish(self.read)?;
        }
        Ok(count)
    }
    /// # Safety
    /// Independently stopped/drained requester, all workers serialized.
    /// Initial HCI only: any prior poll permanently refuses this path, so it
    /// cannot silently reset a live station's RX/tag/security generation.
    pub(super) unsafe fn begin_hci_rebind(&mut self) -> Result<u32, Error> {
        if self.poisoned || self.used || !self.configured {
            return Err(Error::Quarantined);
        }
        self.poisoned = true;
        // SAFETY: covered by this function's own safety contract.
        unsafe { self.descriptor.dma.sync_for_cpu(0..COUNT * DESCRIPTOR) }
            .map_err(beacon::Error::from)?;
        for i in 0..COUNT {
            self.reset_descriptor(i)?;
        }
        self.descriptor
            .dma
            .sync_for_device(0..COUNT * DESCRIPTOR)
            .map_err(beacon::Error::from)?;
        Ok(self.descriptor.address()?)
    }
    pub(super) fn finish_hci_rebind(&mut self) {
        self.read = 0;
        self.tag = 0;
        self.poisoned = false;
    }
    pub(super) fn initial_indices(&mut self) -> Result<(), Error> {
        if self.io.as_mut().ok_or(Error::Quarantined)?.indices()? != (0, 0) {
            return Err(Error::InitialIndices);
        }
        Ok(())
    }
    /// # Safety
    /// Independent requester stop/drain and stopped submission/IRQ
    /// workers through every unmap; read indices, RX tags or register reset
    /// stores alone do not prove this. Failed invalidations keep ownership.
    pub unsafe fn release_after_stop(&mut self) -> Result<(), Error> {
        self.poisoned = true;
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            self.descriptor.release()?;
        }
        for buffer in &mut self.buffers {
            // SAFETY: covered by this function's own safety contract.
            unsafe {
                buffer.release()?;
            }
        }
        self.configured = false;
        self.poisoned = false;
        Ok(())
    }
}
impl<R: Registers> Drop for Ring<R> {
    fn drop(&mut self) {
        if self.configured
            && let Some(io) = self.io.take()
        {
            core::mem::forget(io);
        }
    }
}

#[cfg(test)]
mod tests;
