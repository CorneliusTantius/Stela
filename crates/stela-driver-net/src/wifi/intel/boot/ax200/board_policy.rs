// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2017 Intel Deutschland GmbH
// Copyright (C) 2018-2026 Intel Corporation
//! Real cold AX200 board-power commands, keeping the original native owner.
//! Completion still requires explicit OS country/database admission and scan.
use super::*;
use crate::wifi::intel::{
    command::Id,
    radio::{bios::service::power, lari::Source as ObservationSource},
};
mod commands;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoardCommandKind {
    Ppag,
    Sar,
    Geo,
    Sgom,
    Tas,
    ApTypes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoardCommand {
    kind: BoardCommandKind,
    id: Id,
    bytes: Vec<u8>,
}
impl BoardCommand {
    pub fn kind(&self) -> BoardCommandKind {
        self.kind
    }
    pub fn id(&self) -> Id {
        self.id
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ax200BoardPolicyPhase {
    NotStarted,
    Waiting(BoardCommandKind),
    CountryRequired,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200BoardPolicyError {
    Boot(Error),
    MissingApi { group: u8, command: u8 },
    Version { kind: BoardCommandKind, version: u8 },
    PpagGain { chain: u8, band: u8, gain: i8 },
    Deadline(BoardCommandKind),
    State,
}
pub struct Ax200BoardPolicy<'a, Q: BootIo, B: BiosIo> {
    pub(in crate::wifi::intel::boot) scan: Ax200ScanConfiguration<'a, Q, B>,
    phase: Ax200BoardPolicyPhase,
    tables: Option<power::Tables>,
    commands: Vec<BoardCommand>,
    next: usize,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    responses: Vec<CommandResponse>,
    first_error: Option<Ax200BoardPolicyError>,
}
impl<'a, Q: BootIo, B: BiosIo> Ax200ScanConfiguration<'a, Q, B> {
    pub fn begin_board_policy(self) -> Result<Ax200BoardPolicy<'a, Q, B>, Box<Self>> {
        if self.phase() != Ax200ScanConfigurationPhase::BoardPolicyRequired
            || self.first_error().is_some()
            || self.mcc.setup.lari.radio.initialized.boot.state != State::PnvmObserved
        {
            return Err(Box::new(self));
        }
        Ok(Ax200BoardPolicy {
            scan: self,
            phase: Ax200BoardPolicyPhase::NotStarted,
            tables: None,
            commands: Vec::new(),
            next: 0,
            ticket: None,
            deadline: None,
            responses: Vec::new(),
            first_error: None,
        })
    }
}
impl<Q: BootIo, B: BiosIo> Ax200BoardPolicy<'_, Q, B> {
    pub fn phase(&self) -> Ax200BoardPolicyPhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200BoardPolicyError> {
        self.first_error.as_ref()
    }
    pub fn commands(&self) -> &[BoardCommand] {
        &self.commands
    }
    pub fn responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    pub fn ticket(&self) -> Option<&CommandTicket> {
        self.ticket.as_ref()
    }
    pub fn platform_reads(&self) -> &[service::Read] {
        self.scan.platform_reads()
    }
    pub fn initialized_nvm(&self) -> &InitializedNvm {
        self.scan.initialized_nvm()
    }
    pub fn profiles(&self) -> &[crate::wifi::intel::mcc::Response] {
        self.scan.profiles()
    }
    pub fn take_firmware_notification(&mut self) -> Option<FirmwareNotification> {
        self.scan.take_firmware_notification()
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Error> {
        self.scan.replenish_completed_receive()
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.scan.stop() {
            Ok(()) => {
                self.phase = Ax200BoardPolicyPhase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.first_error
                    .get_or_insert_with(|| Ax200BoardPolicyError::Boot(error.clone()));
                self.phase = Ax200BoardPolicyPhase::Failed;
                Err(error)
            }
        }
    }
    fn prepare(&mut self) -> Result<(), Ax200BoardPolicyError> {
        // These are real same-session reads, never copied caller observations.
        let tables = self.scan.mcc.setup.lari.bios.power_tables();
        self.tables = Some(tables);
        let fw = &self.scan.mcc.setup.lari.radio.initialized.boot.firmware;
        let tables = self.tables.as_ref().unwrap();
        let identity = if commands::needs_identity(fw, tables) {
            Some(self.scan.mcc.setup.lari.bios.dmi_identity())
        } else {
            None
        };
        let boot = &self.scan.mcc.setup.lari.radio.initialized.boot;
        let six_ghz =
            boot.family() >= Family::Ax210 && boot.radio() != crate::wifi::intel::identity::Rf::Hr;
        self.commands = commands::prepare(fw, tables, identity.as_ref(), six_ghz)?;
        Ok(())
    }
    /// Apply cold source policy through ACK/reclaim in this exact epoch.
    /// # Safety
    /// `source` supplies fresh exclusive coherent pages for the native
    /// requester/domain under RomBoot's complete publication contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200BoardPolicyPhase, Ax200BoardPolicyError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        // SAFETY: caller's exact page-source and kept native epoch contract.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(error, Ax200BoardPolicyError::Boot(Error::CommandReclaim(_)))
        {
            self.first_error = Some(error.clone());
            self.phase = Ax200BoardPolicyPhase::Failed;
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200BoardPolicyPhase, Ax200BoardPolicyError> {
        if self.scan.mcc.setup.lari.radio.initialized.boot.state != State::PnvmObserved {
            return Err(Ax200BoardPolicyError::State);
        }
        if self.phase == Ax200BoardPolicyPhase::CountryRequired {
            self.scan
                .mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .poll_one_notification_buffer()
                .map_err(Ax200BoardPolicyError::Boot)?;
            return Ok(self.phase);
        }
        if self.phase == Ax200BoardPolicyPhase::NotStarted {
            self.prepare()?;
        }
        if let Some(ticket) = self.ticket.as_ref() {
            let command = &self.commands[self.next - 1];
            let progress = self
                .scan
                .mcc
                .setup
                .lari
                .radio
                .initialized
                .boot
                .poll_command(ticket);
            if matches!(progress, Err(Error::CommandReclaim(_)))
                && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
            {
                return Err(Ax200BoardPolicyError::Deadline(command.kind));
            }
            match progress.map_err(Ax200BoardPolicyError::Boot)? {
                CommandProgress::Pending => {
                    if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                        return Err(Ax200BoardPolicyError::Deadline(command.kind));
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    let expected_group = if command.id.group == 0 {
                        1
                    } else {
                        command.id.group
                    };
                    let valid =
                        response.command == command.id.opcode && response.group == expected_group;
                    let (command, group) = (response.command, response.group);
                    self.responses.push(response);
                    self.ticket = None;
                    self.deadline = None;
                    if !valid {
                        return Err(Ax200BoardPolicyError::Boot(Error::InitializationResponse {
                            command,
                            group,
                        }));
                    }
                }
            }
        }
        let Some(command) = self.commands.get(self.next) else {
            self.phase = Ax200BoardPolicyPhase::CountryRequired;
            return Ok(self.phase);
        };
        // SAFETY: prepared internally from this owner's BIOS session;
        // no indirect resources, RF-kill enforced, original native epoch kept.
        self.ticket = Some(
            unsafe {
                self.scan
                    .mcc
                    .setup
                    .lari
                    .radio
                    .initialized
                    .boot
                    .submit_command(command.id, &command.bytes, source)
            }
            .map_err(Ax200BoardPolicyError::Boot)?,
        );
        let options = self.scan.mcc.setup.options;
        self.deadline = Some(options.clock.deadline(options.command_timeout_us));
        self.next += 1;
        self.phase = Ax200BoardPolicyPhase::Waiting(command.kind);
        Ok(self.phase)
    }
}
