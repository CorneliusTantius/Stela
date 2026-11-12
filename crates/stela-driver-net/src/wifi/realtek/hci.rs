// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Initial RTL8822C native HCI reset/rebinding, before RX/command admission.
//! Reset stores and zero indices are not an acknowledged DMA-stop mechanism.
use super::{
    beacon::{self, Beacon},
    io::{self, Io, NativeIo},
    receive,
    registers::*,
    transmit,
};
use core::sync::atomic::{Ordering, fence};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(io::Error),
    Beacon(beacon::Error),
    Receive(receive::Error),
    Transmit(transmit::Error),
    IdentityChanged,
    Removed,
    Readback,
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Hardware(e)
    }
}
impl From<beacon::Error> for Error {
    fn from(e: beacon::Error) -> Self {
        Self::Beacon(e)
    }
}
impl From<receive::Error> for Error {
    fn from(e: receive::Error) -> Self {
        Self::Receive(e)
    }
}
impl From<transmit::Error> for Error {
    fn from(e: transmit::Error) -> Self {
        Self::Transmit(e)
    }
}
struct Attempt<'a, I: Io> {
    io: &'a mut I,
    done: bool,
}
impl<I: Io> Drop for Attempt<'_, I> {
    fn drop(&mut self) {
        if !self.done {
            self.io.quarantine();
        }
    }
}

/// Source reset/base/index/tag sequence using all kept native
/// rings after MAC power and again after firmware download, before any raw
/// RX poll or firmware command has been admitted.
///
/// # Safety
/// All queues/domain/claims/BARs belong to `io`'s exact selected requester.
/// Independent requester stop/drain, with every IRQ/reset/submission
/// worker stopped throughout the operation. Source CTRL/index/reset stores
/// below do not establish that prerequisite. RAM is coherent WB with
/// NoSnoop/ATS disabled. This is initial attachment, not recovery of a live
/// station, outstanding command or security generation. Firmware download has
/// consumed its final beacon payload using fresh BCN_VALID if used.
pub unsafe fn setup<B: beacon::Registers, R: receive::Registers, T: transmit::Registers>(
    io: &mut NativeIo<Beacon<B>>,
    rx: &mut receive::Ring<R>,
    tx: &mut transmit::Rings<T>,
) -> Result<(), Error> {
    let profile = io.profile();
    if profile.rtw88().is_none() || tx.profile()? != profile {
        return Err(Error::IdentityChanged);
    }
    let mut a = Attempt { io, done: false };
    let actual = a.io.read32(REG_SYS_CFG1)?;
    if actual == u32::MAX {
        return Err(Error::Removed);
    }
    if actual != profile.observed().sys_cfg1 {
        return Err(Error::IdentityChanged);
    }
    // SAFETY: Independent stop owns descriptor CPU visibility. Each component
    // becomes poisoned before its own mutation; uncertainty keeps its I/O
    // owner and pins even if another component's preparation later fails.
    let beacon = unsafe { a.io.beacon_queue()?.begin_hci_rebind()? };
    // SAFETY: covered by this function's own safety contract.
    let receive = unsafe { rx.begin_hci_rebind()? };
    // SAFETY: covered by this function's own safety contract.
    let transmit = unsafe { tx.begin_hci_rebind()? };
    fence(Ordering::Release);
    rebind(a.io, beacon, receive, transmit)?;
    rx.initial_indices()?;
    tx.initial_indices()?;
    a.io.beacon_queue()?.finish_hci_rebind();
    rx.finish_hci_rebind();
    tx.finish_hci_rebind();
    a.done = true;
    Ok(())
}
/// `rtw_pci_reset_buf_desc`'s index reset: every TX and RX read and write
/// pointer, then the H2C queue's host and hardware indices.
pub(super) fn reset_indices<I: Io>(io: &mut I) -> Result<(), Error> {
    io.write32(RTK_PCI_TXBD_RWPTR_CLR, u32::MAX)?;
    let v = read32(io, REG_H2CQ_CSR)?;
    io.write32(REG_H2CQ_CSR, v | (1 << 16) | (1 << 8))?;
    Ok(())
}
fn read32<I: Io>(io: &mut I, reg: u32) -> Result<u32, Error> {
    let v = io.read32(reg)?;
    if v == u32::MAX {
        Err(Error::Removed)
    } else {
        Ok(v)
    }
}
fn base<I: Io>(io: &mut I, count: u32, n: u16, reg: u32, address: u32) -> Result<(), Error> {
    io.write16(count, n)?;
    io.write32(reg, address)?;
    if io.read16(count)? & 0xfff != n || io.read32(reg)? != address {
        return Err(Error::Readback);
    }
    Ok(())
}
/// Binding addresses are private observations of kept native allocations,
/// never public invented IOVAs. This function's caller owns all live pins.
fn rebind<I: Io>(io: &mut I, beacon: u32, receive: u32, tx: [u32; 7]) -> Result<(), Error> {
    let value = io.read8(RTK_PCI_CTRL + 3)?;
    if value == u8::MAX {
        return Err(Error::Removed);
    }
    io.write8(RTK_PCI_CTRL + 3, value | 0xf7)?;
    io.write32(RTK_PCI_TXBD_DESA_BCNQ, beacon)?;
    if io.read32(RTK_PCI_TXBD_DESA_BCNQ)? != beacon {
        return Err(Error::Readback);
    }
    // Pinned source order: H2C,BK,BE,VO,VI,management,high,RX.
    base(
        io,
        RTK_PCI_TXBD_NUM_H2CQ,
        128,
        RTK_PCI_TXBD_DESA_H2CQ,
        tx[6],
    )?;
    base(io, RTK_PCI_TXBD_NUM_BKQ, 128, RTK_PCI_TXBD_DESA_BKQ, tx[0])?;
    base(io, RTK_PCI_TXBD_NUM_BEQ, 256, RTK_PCI_TXBD_DESA_BEQ, tx[1])?;
    base(io, RTK_PCI_TXBD_NUM_VOQ, 128, RTK_PCI_TXBD_DESA_VOQ, tx[3])?;
    base(io, RTK_PCI_TXBD_NUM_VIQ, 128, RTK_PCI_TXBD_DESA_VIQ, tx[2])?;
    base(
        io,
        RTK_PCI_TXBD_NUM_MGMTQ,
        128,
        RTK_PCI_TXBD_DESA_MGMTQ,
        tx[4],
    )?;
    base(
        io,
        RTK_PCI_TXBD_NUM_HI0Q,
        128,
        RTK_PCI_TXBD_DESA_HI0Q,
        tx[5],
    )?;
    base(
        io,
        RTK_PCI_RXBD_NUM_MPDUQ,
        512,
        RTK_PCI_RXBD_DESA_MPDUQ,
        receive,
    )?;
    reset_indices(io)?;
    let v = read32(io, RTK_PCI_CTRL)?;
    io.write32(RTK_PCI_CTRL, v | (1 << 20) | (1 << 15))?;
    Ok(())
}

#[cfg(test)]
mod tests;
