// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Native register-mailbox state and initial firmware calibration control.
//! Publication, mailbox availability, DMA release and raw RFK status are
//! separate observations. None creates OS/air or independent stop permission.
use super::{
    features::Report,
    identity::Profile,
    io::{self, Io},
    registers::*,
    transmit,
};
use crate::bus::dma::memory::PageSource;

// Native access widths are kept at each use (REG_ARFR4 and CIP are byte
// observations in the source handshake).
const BT_IQK_BUSY: u32 = 0x600000;
const INFORM_RFK_STATUS: u32 = 0x6d;
/// `rtw8822c_do_iqk`'s 300 ms wait for `IQK_DONE_8822C`, 20 ms a look.
const IQK_WAIT_US: u64 = 300_000;
#[cfg(test)]
const IQK_STEP_US: u64 = 20_000;
const IQK_DONE: u8 = 0xaa;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(io::Error),
    Packet(transmit::Error),
    WrongProfile,
    UnsupportedLayout,
    InvalidState,
    InitialMailboxBusy(u8),
    MailboxTimeout { mailbox: u8 },
    Timeout { register: u32 },
    StaleRfk,
    Clock,
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Hardware(e)
    }
}
impl From<transmit::Error> for Error {
    fn from(e: transmit::Error) -> Self {
        Self::Packet(e)
    }
}
/// Register publication only. This is not command completion or DMA retirement.
#[derive(Debug)]
pub struct Published {
    mailbox: u8,
}
impl Published {
    pub fn mailbox(&self) -> u8 {
        self.mailbox
    }
}
/// Source RFK status observed after the finish command; the source reuses a
/// sticky one-bit field. This record proves no fresh finish ACK,
/// coexistence handoff, calibration completion or TX permission.
#[derive(Debug)]
pub struct RfkFinishObservation {
    publication: Published,
    status: u8,
}
impl RfkFinishObservation {
    pub fn publication(&self) -> &Published {
        &self.publication
    }
    pub fn raw_status(&self) -> u8 {
        self.status
    }
}
/// What `rtw8822c_do_iqk` saw of one IQK after its command's publication:
/// the status before, and whether firmware reported done within 300 ms.
/// Firmware DMA/key/radio/policy retirement is separate.
#[derive(Debug)]
pub struct InitialIqkObservation {
    baseline: u8,
    status: u8,
    completed: bool,
}
impl InitialIqkObservation {
    pub fn baseline(&self) -> u8 {
        self.baseline
    }
    pub fn status(&self) -> u8 {
        self.status
    }
    /// False where rtw88 warns "failed to poll iqk status bit" and goes on.
    pub fn completed(&self) -> bool {
        self.completed
    }
}
/// An IQK firmware runs: the status before its command, the last one seen,
/// and when its 300 ms end.
#[derive(Debug)]
pub struct IqkWait {
    baseline: u8,
    status: u8,
    /// Set by the first look, which starts the 300 ms.
    end: Option<u64>,
}
/// Same kept native Io, moved here after bootstrap; no second BAR/config,
/// mapping or requester owner is acquired. Mailbox cursor persists until
/// stop, never reset because a command times out or a status is seen.
pub struct Control<I: Io> {
    io: Option<I>,
    profile: Profile,
    next_box: u8,
    poisoned: bool,
    published: bool,
    rfk_active: bool,
    /// An IQK runs, which nothing else may interrupt.
    iqk_active: bool,
    clock_last: u64,
}
impl<I: Io> Drop for Control<I> {
    fn drop(&mut self) {
        if (self.poisoned || self.published)
            && let Some(io) = self.io.as_mut()
        {
            io.quarantine();
        }
    }
}
struct PacketAttempt<'a, R: transmit::Registers> {
    rings: &'a mut transmit::Rings<R>,
    done: bool,
}
impl<R: transmit::Registers> Drop for PacketAttempt<'_, R> {
    fn drop(&mut self) {
        if !self.done {
            self.rings.quarantine_firmware();
        }
    }
}
impl<I: Io> Control<I> {
    /// # Safety
    /// Consume the serialized native control Io for this
    /// requester, Report and uninterrupted freshly downloaded firmware epoch.
    /// Its register-mailbox cursor is the initial zero, no old commands
    /// or competing native/IRQ/firmware/reset worker exist, and mailbox status
    /// is idle. Real MAC/PHY/HCI initialization/queues/pins/claims,
    /// native clock calibration and CPU affinity remain valid. Caller keeps
    /// operational TX gated pending complete radio/policy validation.
    /// Fingerprints, copied receipts or numeric counters are not ownership.
    pub unsafe fn new(io: I, report: &Report) -> Result<Self, Error> {
        let profile = io.profile();
        let mut c = Self {
            io: Some(io),
            profile,
            next_box: 0,
            poisoned: true,
            published: false,
            rfk_active: false,
            iqk_active: false,
            clock_last: 0,
        };
        if profile.rtw88().is_none() || report.profile() != profile {
            return Err(Error::WrongProfile);
        }
        let cap = report.capabilities();
        if cap.rf_phys != 2 || cap.rf_paths != 2 {
            return Err(Error::UnsupportedLayout);
        }
        c.verify()?;
        let now = c.io()?.now_us()?;
        c.clock_last = now;
        let state = c.io()?.read8(REG_HMETFR)?;
        if state & 15 != 0 {
            return Err(Error::InitialMailboxBusy(state));
        }
        c.verify()?;
        c.poisoned = false;
        Ok(c)
    }
    pub fn quarantined(&self) -> bool {
        self.poisoned
    }
    pub fn next_mailbox(&self) -> u8 {
        self.next_box
    }
    /// The register interface beside the mailbox, for the PHY and MAC stores
    /// this owner serializes with its commands.
    pub fn io(&mut self) -> Result<&mut I, Error> {
        self.io.as_mut().ok_or(Error::InvalidState)
    }
    fn verify(&mut self) -> Result<(), Error> {
        let expected = self.profile.observed().sys_cfg1;
        if self.io()?.read32(REG_SYS_CFG1)? != expected {
            return Err(Error::WrongProfile);
        }
        if self.io()?.read16(REG_MCUFW_CTRL)? & FW_READY_MASK != FW_READY {
            return Err(io::Error::FirmwareNotReady { debug: 0 }.into());
        }
        Ok(())
    }
    fn ready(&self) -> Result<(), Error> {
        if self.poisoned || self.io.is_none() || self.iqk_active {
            Err(Error::InvalidState)
        } else {
            Ok(())
        }
    }
    fn finish<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        self.poisoned = result.is_err();
        if result.is_err()
            && let Some(io) = self.io.as_mut()
        {
            io.quarantine();
        }
        result
    }
    fn now(&mut self) -> Result<u64, Error> {
        let now = self.io()?.now_us()?;
        if now < self.clock_last {
            return Err(Error::Clock);
        }
        self.clock_last = now;
        Ok(now)
    }
    fn poll(
        &mut self,
        register: u32,
        timeout: u64,
        delay: u64,
        mut sample: impl FnMut(&mut I) -> Result<bool, io::Error>,
    ) -> Result<(), Error> {
        let start = self.now()?;
        let end = start.checked_add(timeout).ok_or(Error::Clock)?;
        // Exact wall-time predicate and final post-expiry sample from source.
        // The independent count guard detects an unchecked stalled clock.
        for _ in 0..(timeout / delay + 3) * 2 {
            let now = self.now()?;
            let expired = now > end;
            if sample(self.io()?)? {
                return Ok(());
            }
            if expired {
                return Err(Error::Timeout { register });
            }
            self.io()?.delay_us(delay);
            let after = self.now()?;
            if after <= now {
                return Err(Error::Clock);
            }
        }
        Err(Error::Clock)
    }
    /// `rtw_fw_send_h2c_command`: the next free mailbox takes the command.
    fn publish(&mut self, message: u32, extension: u32) -> Result<Published, Error> {
        self.verify()?;
        let mailbox = self.next_box;
        // Source atomic budget: 3,000,000 ns minus 100,000+one ns per failed
        // iteration, with one final condition sample after budget expiry.
        let mut available = false;
        for index in 0..31 {
            let state = self.io()?.read8(REG_HMETFR)?;
            if state & (1 << mailbox) == 0 {
                available = true;
                break;
            }
            if index < 30 {
                self.io()?.delay_us(100);
            }
        }
        if !available {
            return Err(Error::MailboxTimeout { mailbox });
        }
        self.published = true;
        self.io()?
            .write32(REG_HMEBOX0_EX + u32::from(mailbox) * 4, extension)?;
        self.io()?
            .write32(REG_HMEBOX0 + u32::from(mailbox) * 4, message)?;
        self.next_box = (mailbox + 1) % 4;
        self.verify()?;
        Ok(Published { mailbox })
    }
    fn publish_rfk(&mut self, start: bool) -> Result<Published, Error> {
        self.publish(INFORM_RFK_STATUS | (u32::from(start) << 8), 0)
    }
    /// Publish one of [`super::commands`]' mailbox commands. As in
    /// `rtw_fw_send_h2c_command`, a mailbox still busy after 3 ms drops the
    /// command with [`Error::MailboxTimeout`]: nothing was written, the next
    /// command tries the same mailbox, and the device stays usable. Any other
    /// failure quarantines.
    pub fn command(&mut self, (message, extension): (u32, u32)) -> Result<(), Error> {
        self.ready()?;
        self.poisoned = true;
        let result = self.publish(message, extension);
        if let Err(Error::MailboxTimeout { mailbox }) = result {
            self.poisoned = false;
            return Err(Error::MailboxTimeout { mailbox });
        }
        self.finish(result).map(|_| ())
    }
    /// Begin source GAPK's RFK handshake from a non-set baseline.
    /// BT IQK must be observed idle; no source timeout-skip fallback is minted.
    ///
    /// # Safety
    /// Same kept device/firmware/channel/board epoch, held
    /// native→OS/coexistence permission, required current power/RF calibration
    /// emission permission/gates and exclusive RFK worker. Operational TX and
    /// competing BT/WiFi/reset/IRQ/RF/PHY work remain stopped. A raw
    /// BT-idle status does not replace kept BT/coexistence ownership.
    /// This establishes only a new observed source start-status bit, not GAPK,
    /// finish completion, DMA stop or permission for normal TX.
    pub unsafe fn begin_rfk(&mut self) -> Result<Published, Error> {
        self.ready()?;
        if self.rfk_active {
            return Err(Error::InvalidState);
        }
        self.poisoned = true;
        let result = (|| {
            self.verify()?;
            if self.io()?.read8(REG_ARFR4)? & 1 != 0 {
                return Err(Error::StaleRfk);
            }
            self.poll(REG_PMC_DBG_CTRL1, 600000, 20, |io| {
                Ok(io.read32(REG_PMC_DBG_CTRL1)? & BT_IQK_BUSY == 0)
            })?;
            let publication = self.publish_rfk(true)?;
            self.rfk_active = true;
            self.poll(
                REG_ARFR4,
                100000,
                20,
                |io| Ok(io.read8(REG_ARFR4)? & 1 == 1),
            )?;
            self.verify()?;
            Ok(publication)
        })();
        self.finish(result)
    }
    /// Observe the source finish-status condition after finish mailbox
    /// publication. Sticky status is explicitly not promoted to a fresh ACK.
    ///
    /// # Safety
    /// Same kept source RFK session/permission as begin_rfk. GAPK work
    /// has completed/stopped and all source restore obligations hold.
    /// Real firmware/coexistence handoff and radio validation remain caller-
    /// owned; this observation cannot authorize a later ordinary transmission.
    pub unsafe fn finish_rfk(&mut self) -> Result<RfkFinishObservation, Error> {
        self.ready()?;
        if !self.rfk_active {
            return Err(Error::InvalidState);
        }
        self.poisoned = true;
        let result = (|| {
            let publication = self.publish_rfk(false)?;
            self.poll(
                REG_ARFR4,
                100000,
                20,
                |io| Ok(io.read8(REG_ARFR4)? & 1 == 1),
            )?;
            let status = self.io()?.read8(REG_ARFR4)?;
            self.verify()?;
            self.rfk_active = false;
            Ok(RfkFinishObservation {
                publication,
                status,
            })
        })();
        self.finish(result)
    }
    /// `rtw8822c_do_iqk` in one call: publish the clear=1/segment=0 IQK and
    /// wait up to 300 ms for firmware's done status. As in rtw88, a status
    /// still done from an earlier IQK satisfies the wait, and a wait that runs
    /// out is a shortfall the caller reports, not a failure of the device.
    ///
    /// # Safety
    /// As [`Self::start_iqk`].
    #[cfg(test)]
    pub unsafe fn iqk<R: transmit::Registers>(
        &mut self,
        rings: &mut transmit::Rings<R>,
        source: &dyn PageSource,
    ) -> Result<InitialIqkObservation, Error> {
        // SAFETY: forwarded from the caller.
        let mut wait = unsafe { self.start_iqk(rings, source) }?;
        self.iqk_active = false;
        self.poisoned = true;
        let mut packet = PacketAttempt { rings, done: false };
        let result = (|| {
            let mut status = wait.status;
            let poll = self.poll(REG_RPT_CIP, IQK_WAIT_US, IQK_STEP_US, |io| {
                status = io.read8(REG_RPT_CIP)?;
                Ok(status == IQK_DONE)
            });
            wait.status = status;
            let completed = match poll {
                Ok(()) => true,
                Err(Error::Timeout { .. }) => false,
                Err(error) => return Err(error),
            };
            self.end_iqk(&wait, completed)
        })();
        packet.done = result.is_ok();
        self.finish(result)
    }
    /// Publish `rtw8822c_do_iqk`'s clear=1/segment=0 IQK. Firmware then runs
    /// it on its own; [`Self::poll_iqk`] looks for its end, one sample a call,
    /// so that the wait never holds the caller. Nothing else may use this
    /// control until the wait ends.
    ///
    /// # Safety
    /// Rings and this control are the same requester/firmware epoch,
    /// not matching fingerprints. Real source PHYDM and GAPK completed, actual
    /// firmware/coexistence handoff is checked, current channel/
    /// power and native→OS/calibration emission permission held; ordinary
    /// RX/TX and competing reset/RFK/IRQ workers remain quiesced until the
    /// wait ends. IQK can emit calibration signals. Source ready status is not
    /// DPK, applied policy or normal-TX permission. Real command DMA and
    /// firmware retirement remain independently owned through completion or
    /// acknowledged stop.
    pub unsafe fn start_iqk<R: transmit::Registers>(
        &mut self,
        rings: &mut transmit::Rings<R>,
        source: &dyn PageSource,
    ) -> Result<IqkWait, Error> {
        self.ready()?;
        if self.rfk_active {
            return Err(Error::InvalidState);
        }
        if rings.profile()? != self.profile {
            return Err(Error::WrongProfile);
        }
        self.poisoned = true;
        let mut packet = PacketAttempt { rings, done: false };
        let result = (|| {
            self.verify()?;
            let baseline = self.io()?.read8(REG_RPT_CIP)?;
            // SAFETY: caller holds real same native rings/control/permission;
            // status was sampled before this exact command publication.
            unsafe { packet.rings.initial_iqk_command(source) }?;
            self.published = true;
            Ok(IqkWait {
                baseline,
                status: baseline,
                end: None,
            })
        })();
        packet.done = result.is_ok();
        let wait = self.finish(result)?;
        self.iqk_active = true;
        Ok(wait)
    }
    /// One look at the IQK [`Self::start_iqk`] began: `None` while firmware
    /// still runs it within its 300 ms, else what `rtw8822c_do_iqk` saw. With
    /// `hurry`, this look is the last.
    /// A failure quarantines both this control and `rings`, which still
    /// hold the IQK's command.
    pub fn poll_iqk<R: transmit::Registers>(
        &mut self,
        rings: &mut transmit::Rings<R>,
        wait: &mut IqkWait,
        hurry: bool,
    ) -> Result<Option<InitialIqkObservation>, Error> {
        if self.poisoned || self.io.is_none() || !self.iqk_active {
            return Err(Error::InvalidState);
        }
        self.poisoned = true;
        let mut packet = PacketAttempt { rings, done: false };
        let result = (|| {
            let now = self.now()?;
            let end = match wait.end {
                Some(end) => end,
                None => *wait
                    .end
                    .insert(now.checked_add(IQK_WAIT_US).ok_or(Error::Clock)?),
            };
            wait.status = self.io()?.read8(REG_RPT_CIP)?;
            let completed = wait.status == IQK_DONE;
            if !completed && !hurry && now <= end {
                return Ok(None);
            }
            self.end_iqk(wait, completed).map(Some)
        })();
        packet.done = result.is_ok();
        let result = self.finish(result);
        if !matches!(result, Ok(None)) {
            self.iqk_active = false;
        }
        result
    }
    /// The end of `rtw8822c_do_iqk`'s wait, done or not.
    fn end_iqk(&mut self, wait: &IqkWait, completed: bool) -> Result<InitialIqkObservation, Error> {
        // Source clears REG_IQKSTAT after the poll even for a pure timeout.
        self.io()?.write8(REG_IQKSTAT, 0)?;
        self.verify()?;
        Ok(InitialIqkObservation {
            baseline: wait.baseline,
            status: wait.status,
            completed,
        })
    }
    /// Return the same native Io only after independent shutdown.
    ///
    /// # Safety
    /// Vendor DMA/firmware/RFK/autonomous RX/TX, PCI requester activity, posted
    /// interrupts and native callbacks/work have stopped and drained;
    /// rings/pins remain held until quiescence and all users retired.
    /// Mailbox free, raw finish bit, IQK AA, masking and queue emptiness are not
    /// stop proof. No future firmware command can change this device epoch.
    pub unsafe fn release_after_stop(&mut self) -> Result<I, Error> {
        self.published = false;
        self.rfk_active = false;
        self.iqk_active = false;
        self.poisoned = false;
        self.io.take().ok_or(Error::InvalidState)
    }
}

#[cfg(test)]
pub(super) mod tests;
