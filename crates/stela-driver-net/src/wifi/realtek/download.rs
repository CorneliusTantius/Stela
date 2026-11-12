// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C firmware reset, reserved-page transfer, IDDMA and ready
//! polling, adapted from pinned rtw88/{mac,fw,util}.c. The lower native beacon
//! TXBD queue is an explicit dependency. Downloaded firmware is not a radio:
//! HCI setup, OTP, calibration, channel, MLME and keys are separate operations.
use super::{
    firmware::{ParseError, Rtw88},
    identity::Staged,
    io::{Error, Io, sleep},
    registers::*,
};
use crate::wifi::stepped::yield_now;

const TX_BUFFER_PAYLOAD: u32 = 0x1878_0000 + 48;
const IMEM_BOUNDARY: u32 = 0x0020_0000;
/// `BIT_BCN_VALID_V1` in the high half of `REG_FIFOPAGE_CTRL_2`.
const BCN_VALID: u16 = 1 << 15;
const MAX_POLLS: usize = 1000;
const CHUNK: usize = 4096;

async fn poll<I: Io>(io: &mut I, register: u32, mask: u32, target: u32) -> Result<(), Error> {
    for _ in 0..MAX_POLLS {
        let value = io.read32(register)?;
        // Removed/unmapped devices must not satisfy all-set ready masks.
        if value == u32::MAX {
            return Err(Error::Register);
        }
        if value & mask == target {
            return Ok(());
        }
        sleep(io, 10).await;
    }
    Err(Error::Timeout { register, mask })
}

/// `rtw_fw_write_data_rsvd_page` of `data` at page `head`, with the beacon
/// queue's head left at `boundary`.
pub async fn write_reserved<I: Io>(
    io: &mut I,
    head: u16,
    boundary: u16,
    data: &[u8],
) -> Result<(), Error> {
    let beacon = io.read8(REG_BCN_CTRL)?;
    io.write16(REG_FIFOPAGE_CTRL_2, head | BCN_VALID)?;
    let cr = io.read8(REG_CR + 1)?;
    io.write8(REG_CR + 1, cr | 1)?;
    io.write8(REG_BCN_CTRL, (beacon & !8) | 16)?;
    let txq = io.read8(REG_FWHW_TXQ_CTRL + 2)?;
    io.write8(REG_FWHW_TXQ_CTRL + 2, txq & !64)?;
    let result = async {
        io.submit_beacon(data)?;
        poll(
            io,
            REG_FIFOPAGE_CTRL_2,
            u32::from(BCN_VALID),
            u32::from(BCN_VALID),
        )
        .await?;
        // SAFETY: cleared BCN_VALID before this exact payload,
        // then observed its new hardware event under exclusive I/O.
        unsafe { io.beacon_consumed() }
    }
    .await;
    // Restore even for queue/valid-bit failure. An error in restoration is
    // itself uncertain; outer start quarantines all remaining resources.
    io.write16(REG_FIFOPAGE_CTRL_2, boundary | BCN_VALID)?;
    io.write8(REG_BCN_CTRL, beacon)?;
    io.write8(REG_FWHW_TXQ_CTRL + 2, txq)?;
    io.write8(REG_CR + 1, cr)?;
    result
}

#[derive(Debug)]
pub enum StartError {
    Hardware(Error),
    Format(ParseError),
}
impl From<Error> for StartError {
    fn from(error: Error) -> Self {
        Self::Hardware(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Idle,
    Quarantined,
    /// REG_MCUFW_CTRL ready observed; HCI index reset and radio setup remain.
    FirmwareReady,
}

/// Single download attempt. Any error after hardware mutation is terminal;
/// neither register restoration nor a firmware ready bit proves DMA stopped.
pub struct Download<I: Io> {
    io: I,
    boundary: u16,
    state: State,
    feature_requested: bool,
}
impl<I: Io> Download<I> {
    /// `boundary` is the validated RTL8822C FIFO reserved-page boundary,
    /// established by prior MAC initialization, not an invented default.
    pub fn new(io: I, boundary: u16) -> Result<Self, Error> {
        if boundary > 0x7ff {
            return Err(Error::InvalidBoundary);
        }
        Ok(Self {
            io,
            boundary,
            state: State::Idle,
            feature_requested: false,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    /// Continue native HCI/radio initialization only after the exact
    /// REG_MCUFW_CTRL ready status was observed. This grants no Ethernet/carrier state.
    pub fn after_firmware_ready(&mut self) -> Result<&mut I, Error> {
        if self.state != State::FirmwareReady || self.feature_requested {
            return Err(Error::InvalidState);
        }
        Ok(&mut self.io)
    }
    pub async fn start(&mut self, staged: &Staged<'_>) -> Result<(), StartError> {
        self.start_inner(staged, false).await
    }
    /// Request the source RTL8822C hardware-feature report before booting this
    /// exact firmware. Prior complete HCI/beacon/FIFO setup is still required.
    /// The mailbox is read back as 0xfd before download, so an old report does
    /// not satisfy this request. Raw I/O remains inaccessible until the report
    /// has been consumed; no other reset/IRQ/mailbox worker may run meanwhile.
    pub async fn start_with_hardware_features(
        &mut self,
        staged: &Staged<'_>,
    ) -> Result<(), StartError> {
        self.start_inner(staged, true).await
    }
    /// Consume the one report produced after this object's request and
    /// successful firmware boot. This is capability data, not PHY readiness.
    /// The source report helper is independent of OTP reads; Stela consumes it
    /// immediately after boot to keep the fresh mailbox exclusively owned.
    pub async fn hardware_features(&mut self) -> Result<super::features::Report, Error> {
        if self.state != State::FirmwareReady || !self.feature_requested {
            return Err(Error::InvalidState);
        }
        // Mark before any fallible I/O/unwind. No repeat, even after partial ACK.
        self.state = State::Quarantined;
        self.feature_requested = false;
        match super::features::read(&mut self.io).await {
            Ok(report) => {
                self.state = State::FirmwareReady;
                Ok(report)
            }
            Err(error) => {
                self.io.quarantine();
                Err(error)
            }
        }
    }
    async fn start_inner(
        &mut self,
        staged: &Staged<'_>,
        request_features: bool,
    ) -> Result<(), StartError> {
        if self.state != State::Idle {
            return Err(Error::InvalidState.into());
        }
        let profile = self.io.profile();
        if staged.profile.rtw88().is_none() || staged.profile != profile {
            return Err(Error::WrongChip.into());
        }
        // Staged fields are diagnostic and mutable, whereas Image keeps
        // the immutable Provider binding. Revalidate both before touching I/O.
        if !profile.binds(&staged.image) {
            return Err(Error::WrongFirmwareTarget.into());
        }
        // Reparse the exact provider bytes; public diagnostic layouts cannot
        // be substituted to upload a different set of addresses or payloads.
        let image = Rtw88::parse(staged.image.bytes()).map_err(StartError::Format)?;
        // Set before the first possible mutation, including panicking adapters.
        self.state = State::Quarantined;
        let result = async {
            if request_features {
                super::features::request(&mut self.io)?;
                self.feature_requested = true;
            }
            self.download(&image).await
        }
        .await;
        match result {
            Ok(()) => {
                self.state = State::FirmwareReady;
                Ok(())
            }
            Err(error) => {
                // Donor failure cleanup is best effort, never a reset proof.
                let _ = self.modify8(REG_MCUFW_CTRL, BIT_MCUFWDL_EN, 0);
                let _ = self.modify8(REG_SYS_FUNC_EN + 1, 0, BIT_FEN_CPUEN);
                self.io.quarantine();
                Err(error.into())
            }
        }
    }
    fn modify8(&mut self, register: u32, clear: u8, set: u8) -> Result<(), Error> {
        let value = self.io.read8(register)?;
        self.io.write8(register, (value & !clear) | set)
    }
    async fn poll(&mut self, register: u32, mask: u32, target: u32) -> Result<(), Error> {
        poll(&mut self.io, register, mask, target).await
    }
    fn cpu(&mut self, enabled: bool) -> Result<(), Error> {
        if enabled {
            self.modify8(REG_RSV_CTRL + 1, 0, BIT_WLMCU_IOIF)?;
            self.modify8(REG_SYS_FUNC_EN + 1, 0, BIT_FEN_CPUEN)
        } else {
            self.modify8(REG_SYS_FUNC_EN + 1, BIT_FEN_CPUEN, 0)?;
            self.modify8(REG_RSV_CTRL + 1, BIT_WLMCU_IOIF, 0)
        }
    }
    async fn download(&mut self, image: &Rtw88<'_>) -> Result<(), Error> {
        self.poll(REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1, 1 << 29, 1 << 29)
            .await?;
        self.io
            .write32(REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1, 0x800f_0038)?;
        let lte_backup = self
            .io
            .read32(REG_WL2LTECOEX_INDIRECT_ACCESS_READ_DATA_V1)?;
        self.cpu(false)?;
        let pq = self.io.read8(REG_TXDMA_PQ_MAP + 1)?;
        self.io.write8(REG_TXDMA_PQ_MAP + 1, 3 << 6)?;
        let cr = self.io.read8(REG_CR)?;
        self.io.write8(REG_CR, 5)?;
        self.io.write32(REG_H2CQ_CSR, BIT_H2CQ_FULL)?;
        let pages = self.io.read16(REG_FIFOPAGE_INFO_1)?;
        let rqpn = self.io.read32(REG_RQPN_CTRL_2)? | BIT_LD_RQPN;
        self.io.write16(REG_FIFOPAGE_INFO_1, 0x200)?;
        self.io.write32(REG_RQPN_CTRL_2, rqpn)?;
        let beacon = self.io.read8(REG_BCN_CTRL)?;
        self.io.write8(REG_BCN_CTRL, (beacon & !8) | 16)?;
        self.modify8(REG_CPU_DMEM_CON + 2, 1, 0)?;
        self.modify8(REG_SYS_CLK_CTRL + 1, 64, 0)?;
        self.modify8(REG_CPU_DMEM_CON + 2, 0, 1)?;
        self.modify8(REG_SYS_CLK_CTRL + 1, 0, 64)?;
        let control = (self.io.read16(REG_MCUFW_CTRL)? & 0x3800) | 1;
        self.io.write16(REG_MCUFW_CTRL, control)?;
        for section in &image.sections {
            self.region(section.download_address, section.data).await?;
        }
        // Exact donor six-register restore order and access widths. H2CQ_CSR
        // restores FULL, not an earlier register observation.
        self.io.write8(REG_TXDMA_PQ_MAP + 1, pq)?;
        self.io.write8(REG_CR, cr)?;
        self.io.write32(REG_H2CQ_CSR, BIT_H2CQ_FULL)?;
        self.io.write16(REG_FIFOPAGE_INFO_1, pages)?;
        self.io.write32(REG_RQPN_CTRL_2, rqpn)?;
        self.io.write8(REG_BCN_CTRL, beacon)?;
        self.io.write32(REG_TXDMA_STATUS, 4)?;
        let control = self.io.read16(REG_MCUFW_CTRL)?;
        if control & 0x50 != 0x50 {
            return Err(Error::DownloadChecksums);
        }
        self.io.write16(REG_MCUFW_CTRL, (control | 0x4000) & !1)?;
        self.cpu(true)?;
        self.poll(REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1, 1 << 29, 1 << 29)
            .await?;
        self.io
            .write32(REG_WL2LTECOEX_INDIRECT_ACCESS_WRITE_DATA_V1, lte_backup)?;
        self.io
            .write32(REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1, 0xc00f_0038)?;
        match self
            .poll(REG_MCUFW_CTRL, FW_READY_MASK.into(), FW_READY.into())
            .await
        {
            Ok(()) => Ok(()),
            Err(Error::Timeout { .. }) => {
                let debug = self.io.read32(REG_FW_DBG7)?;
                if debug & 0xffff_ff00 == 0xfaaa_aa00 {
                    Err(Error::InvalidFirmwareKey)
                } else {
                    Err(Error::FirmwareNotReady { debug })
                }
            }
            Err(error) => Err(error),
        }
    }
    async fn reserved_page(&mut self, data: &[u8]) -> Result<(), Error> {
        write_reserved(&mut self.io, 0, self.boundary, data).await
    }
    async fn region(&mut self, destination: u32, data: &[u8]) -> Result<(), Error> {
        let control = self.io.read32(REG_DDMA_CH0CTRL)?;
        self.io
            .write32(REG_DDMA_CH0CTRL, control | BIT_DDMACH0_RESET_CHKSUM_STS)?;
        for (index, chunk) in data.chunks(CHUNK).enumerate() {
            // One chunk a step.
            yield_now().await;
            self.reserved_page(chunk).await?;
            self.poll(REG_DDMA_CH0CTRL, BIT_DDMACH0_OWN, 0).await?;
            self.io.write32(REG_DDMA_CH0SA, TX_BUFFER_PAYLOAD)?;
            self.io
                .write32(REG_DDMA_CH0DA, destination + (index * CHUNK) as u32)?;
            let mut control = BIT_DDMACH0_OWN | BIT_DDMACH0_CHKSUM_EN | chunk.len() as u32;
            if index != 0 {
                control |= BIT_DDMACH0_CHKSUM_CONT;
            }
            self.io.write32(REG_DDMA_CH0CTRL, control)?;
            self.poll(REG_DDMA_CH0CTRL, BIT_DDMACH0_OWN, 0).await?;
        }
        let firmware = self.io.read8(REG_MCUFW_CTRL)?;
        let control = self.io.read32(REG_DDMA_CH0CTRL)?;
        // Donor classifies EMEM with IMEM, by address rather than header kind.
        let (download_ok, checksum_ok) = if destination < IMEM_BOUNDARY {
            (8, 16)
        } else {
            (32, 64)
        };
        if control & BIT_DDMACH0_CHKSUM_STS != 0 {
            self.io
                .write8(REG_MCUFW_CTRL, (firmware | download_ok) & !checksum_ok)?;
            return Err(Error::Checksum { destination });
        }
        self.io
            .write8(REG_MCUFW_CTRL, firmware | download_ok | checksum_ok)
    }
}
impl<I: Io> Drop for Download<I> {
    fn drop(&mut self) {
        if self.state == State::Quarantined {
            self.io.quarantine();
        }
    }
}

#[cfg(test)]
pub(super) mod tests;
