// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2005-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! AX200 MCC query and BIOS selection, keeping the original requester.
//! Returned profiles remain observations until fully applied radio/OS policy.
use super::*;
use crate::wifi::intel::mcc::{self, channel::Observation as ChannelObservation};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ax200MccPhase {
    NotStarted,
    WaitingCurrent,
    WaitingBios,
    PolicyRequired,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200MccError {
    Boot(Error),
    Schema(mcc::Error),
    ChannelInventory(mcc::channel::InventoryMismatch),
    LarUnsupported,
    CommandVersion(u8),
    Deadline,
    State,
}
pub struct Ax200Mcc<'a, Q: BootIo, B: BiosIo> {
    pub(in crate::wifi::intel::boot) setup: Ax200Setup<'a, Q, B>,
    pub(super) phase: Ax200MccPhase,
    request: Option<mcc::Request>,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    responses: Vec<CommandResponse>,
    profiles: Vec<mcc::Response>,
    channels: Vec<ChannelObservation>,
    bios_country: Option<Observation>,
    pub(super) first_error: Option<Ax200MccError>,
}
impl<'a, Q: BootIo, B: BiosIo> Ax200Setup<'a, Q, B> {
    /// Consume only the completed original setup epoch. A copied MCC table or
    /// BIOS value cannot construct, re-enter or advance this owner.
    pub fn begin_mcc(self) -> Result<Ax200Mcc<'a, Q, B>, Box<Self>> {
        if self.phase != Ax200SetupPhase::RegulatoryRequired
            || self.first_error.is_some()
            || self.lari.radio.initialized.boot.state != State::PnvmObserved
        {
            return Err(Box::new(self));
        }
        Ok(Ax200Mcc {
            setup: self,
            phase: Ax200MccPhase::NotStarted,
            request: None,
            ticket: None,
            deadline: None,
            responses: Vec::new(),
            profiles: Vec::new(),
            channels: Vec::new(),
            bios_country: None,
            first_error: None,
        })
    }
}
impl<Q: BootIo, B: BiosIo> Ax200Mcc<'_, Q, B> {
    pub fn phase(&self) -> Ax200MccPhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200MccError> {
        self.first_error.as_ref()
    }
    pub fn responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    pub fn profiles(&self) -> &[mcc::Response] {
        &self.profiles
    }
    pub fn channels(&self) -> &[ChannelObservation] {
        &self.channels
    }
    pub fn bios_country(&self) -> Option<Observation> {
        self.bios_country
    }
    pub fn platform_reads(&self) -> &[service::Read] {
        self.setup.platform_reads()
    }
    pub fn initialized_nvm(&self) -> &InitializedNvm {
        self.setup.initialized_nvm()
    }
    pub fn take_firmware_notification(&mut self) -> Option<FirmwareNotification> {
        self.setup.take_firmware_notification()
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Error> {
        self.setup.replenish_completed_receive()
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.setup.stop() {
            Ok(()) => {
                self.phase = Ax200MccPhase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.first_error
                    .get_or_insert_with(|| Ax200MccError::Boot(error.clone()));
                self.phase = Ax200MccPhase::Failed;
                Err(error)
            }
        }
    }
    /// Advance cold MCC initialization from firmware RX responses.
    /// This grants no receive/scan/TX or OS/location permission.
    /// # Safety
    /// `source` supplies fresh exclusive coherent pages for the kept
    /// native requester/domain under RomBoot's publication contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200MccPhase, Ax200MccError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        // SAFETY: the caller's native page-source contract.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(error, Ax200MccError::Boot(Error::CommandReclaim(_)))
        {
            self.first_error = Some(error.clone());
            self.phase = Ax200MccPhase::Failed;
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200MccPhase, Ax200MccError> {
        let boot = &mut self.setup.lari.radio.initialized.boot;
        if boot.state != State::PnvmObserved {
            return Err(Ax200MccError::State);
        }
        if self.phase == Ax200MccPhase::PolicyRequired {
            // MCC itself is source-authorized in RF-kill; it cannot grant RF.
            boot.poll_one_notification_buffer()
                .map_err(Ax200MccError::Boot)?;
            return Ok(self.phase);
        }
        if self.phase == Ax200MccPhase::NotStarted {
            if !boot.firmware.supports_capability(1)
                || self.setup.initialized_nvm().information.lar_enabled == 0
            {
                return Err(Ax200MccError::LarUnsupported);
            }
            let fw = &self.setup.lari.radio.initialized.boot.firmware;
            let version = fw
                .command_version(1, 0xc8)
                .ok_or(Ax200MccError::Schema(mcc::Error::MissingApi))?
                .command_version;
            if version != 1 {
                return Err(Ax200MccError::CommandVersion(version));
            }
            mcc::Response::layout(fw).map_err(Ax200MccError::Schema)?;
            self.request = Some(mcc::Request::current(fw));
        }
        if let Some(ticket) = self.ticket.as_ref() {
            let progress = self.setup.lari.radio.initialized.boot.poll_command(ticket);
            if matches!(progress, Err(Error::CommandReclaim(_)))
                && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
            {
                return Err(Ax200MccError::Deadline);
            }
            match progress.map_err(Ax200MccError::Boot)? {
                CommandProgress::Pending => {
                    if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                        return Err(Ax200MccError::Deadline);
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    let (command, group) = (response.command, response.group);
                    self.responses.push(response);
                    self.ticket = None;
                    self.deadline = None;
                    if command != 0xc8 || group != 1 {
                        return Err(Ax200MccError::Boot(Error::InitializationResponse {
                            command,
                            group,
                        }));
                    }
                    let profile = mcc::Response::decode(
                        &self.setup.lari.radio.initialized.boot.firmware,
                        &self.responses.last().unwrap().raw,
                    )
                    .map_err(Ax200MccError::Schema)?;
                    let inventory = self
                        .setup
                        .lari
                        .radio
                        .initialized
                        .boot
                        .profile
                        .channel_inventory();
                    let channels = profile
                        .channel_observations(inventory)
                        .map_err(Ax200MccError::ChannelInventory)?;
                    self.profiles.push(profile);
                    self.channels = channels;
                    if self.phase == Ax200MccPhase::WaitingCurrent {
                        let fw = &self.setup.lari.radio.initialized.boot.firmware;
                        if fw.supports_api(9) || fw.supports_capability(29) {
                            let country = self.setup.lari.bios.country();
                            self.bios_country = Some(country);
                            if let Observation::Observed(value) = country {
                                self.request = Some(mcc::Request {
                                    country: (value.value as u16).to_be_bytes(),
                                    source: 2,
                                });
                            } else {
                                self.request = None;
                            }
                        } else {
                            self.request = None;
                        }
                    } else {
                        self.request = None;
                    }
                }
            }
        }
        let Some(request) = self.request else {
            self.phase = Ax200MccPhase::PolicyRequired;
            return Ok(self.phase);
        };
        let bytes = request.bytes().map_err(Ax200MccError::Schema)?;
        // SAFETY: source MCC_UPDATE explicitly uses CMD_SEND_IN_RFKILL. The
        // command contains no indirect resources and the original epoch stays owned.
        self.ticket = Some(
            unsafe {
                self.setup
                    .lari
                    .radio
                    .initialized
                    .boot
                    .submit_command_with_policy(mcc::Request::id(), &bytes, source, true)
            }
            .map_err(Ax200MccError::Boot)?,
        );
        self.deadline = Some(
            self.setup
                .options
                .clock
                .deadline(self.setup.options.command_timeout_us),
        );
        self.phase = if self.phase == Ax200MccPhase::NotStarted {
            Ax200MccPhase::WaitingCurrent
        } else {
            Ax200MccPhase::WaitingBios
        };
        Ok(self.phase)
    }
}
