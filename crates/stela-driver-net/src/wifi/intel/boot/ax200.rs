// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Owned AX200 continuation from LARI through thermal/device-power
//! commands. Regulatory setup, scanning and a station remain subsequent work.
use super::*;
use crate::Clock;
use crate::wifi::intel::radio::{
    bios::service::{self, BiosIo},
    control::{self, Control, Kind, Ltr, PowerMode},
    lari::Observation,
};
use alloc::boxed::Box;
mod board_policy;
pub use board_policy::{
    Ax200BoardPolicy, Ax200BoardPolicyError, Ax200BoardPolicyPhase, BoardCommand, BoardCommandKind,
};
mod country;
pub use country::{
    Ax200Country, Ax200CountryError, Ax200CountryPhase, CountryIo, CountryIoError, SelectedCountry,
};
mod mac_context;
pub use mac_context::{Ax200Mac, Ax200MacError, Ax200MacPhase, MacCommand, MacCommandKind};
mod mcc;
mod scan;
mod scan_configuration;
pub use mcc::{Ax200Mcc, Ax200MccError, Ax200MccPhase};
pub use scan::{
    Ax200Binding, Ax200BindingError, Ax200BindingPhase, Ax200Coexistence, Ax200CoexistenceError,
    Ax200CoexistencePhase, Ax200LegacyPeer, Ax200LegacyPeerError, Ax200LegacyPeerPhase,
    Ax200ManagementQueue, Ax200ManagementQueueError, Ax200ManagementQueuePhase, Ax200Phy,
    Ax200PhyError, Ax200PhyPhase, Ax200Scan, Ax200ScanError, Ax200ScanPhase, Ax200ScanTraffic,
    Ax200TransmitPower, Ax200TransmitPowerError, Ax200TransmitPowerPhase, BindingCommand,
    BindingCommandKind, LegacyPeer, PeerCommand, PeerCommandKind, PhyCommand, PhyCommandKind,
    Probe, ScanCompletion, ScanRawReceive, ScanRejectedMpdu, ScanResult, ScanResultProgress,
    ScanRetirement, TransmitPowerLimit,
};
pub use scan_configuration::{
    Ax200ScanConfiguration, Ax200ScanConfigurationError, Ax200ScanConfigurationPhase,
};

/// Host wait policy, not firmware completion or permission to release DMA.
#[derive(Clone, Copy, Debug)]
pub struct Ax200SetupOptions {
    pub clock: Clock,
    pub command_timeout_us: u64,
    pub power_mode: PowerMode,
}
impl Ax200SetupOptions {
    pub fn new(clock: Clock) -> Self {
        Self {
            clock,
            command_timeout_us: 2_000_000,
            power_mode: PowerMode::ContinuouslyAwake,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ax200SetupPhase {
    NotStarted,
    Waiting(Kind),
    RegulatoryRequired,
    Failed,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ax200SetupError {
    Boot(Error),
    Control(control::Error),
    QueueLayout,
    AuxiliaryStationRequired,
    PowerBudgetRequired,
    Deadline(Kind),
    State,
}
/// Source branches derived from the context and firmware.
/// These borrowed diagnostics cannot construct or advance another owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupDecisions {
    pub receive_queues: u8,
    pub firmware_auxiliary_station: bool,
    pub dqa_command: bool,
    pub firmware_ltr: bool,
}
pub struct Ax200Setup<'a, Q: BootIo, B: BiosIo> {
    // Keeping the original LARI object also keeps its service owner quarantined
    // whenever RomBoot has not independently completed its real stop fence.
    pub(super) lari: LariRadio<'a, Q, B>,
    phase: Ax200SetupPhase,
    options: Ax200SetupOptions,
    decisions: Option<SetupDecisions>,
    clock_observation: Option<Observation>,
    commands: Vec<Control>,
    next: usize,
    ticket: Option<CommandTicket>,
    deadline: Option<crate::Deadline>,
    responses: Vec<CommandResponse>,
    thermal_acknowledged: bool,
    first_error: Option<Ax200SetupError>,
}
impl<'a, Q: BootIo, B: BiosIo> LariRadio<'a, Q, B> {
    /// Return the original owner unchanged if its family/phase/clock cannot
    /// enter this AX200-only continuation. No new namespace or MMIO read occurs.
    /// # Safety
    /// The supplied clock is calibrated, monotonic and advancing throughout
    /// this native device epoch. It grants no PCI or BIOS permission.
    pub unsafe fn begin_ax200_setup(
        self,
        options: Ax200SetupOptions,
    ) -> Result<Ax200Setup<'a, Q, B>, Box<Self>> {
        if self.phase() != LariPhase::RxQueueConfigurationRequired
            || self.radio.initialized.boot.state != State::PnvmObserved
            || options.clock.ticks_per_microsecond == 0
            || !(1..=60_000_000).contains(&options.command_timeout_us)
        {
            return Err(Box::new(self));
        }
        Ok(Ax200Setup {
            lari: self,
            phase: Ax200SetupPhase::NotStarted,
            options,
            decisions: None,
            clock_observation: None,
            commands: Vec::new(),
            next: 0,
            ticket: None,
            deadline: None,
            responses: Vec::new(),
            thermal_acknowledged: false,
            first_error: None,
        })
    }
}
impl<Q: BootIo, B: BiosIo> Ax200Setup<'_, Q, B> {
    pub fn phase(&self) -> Ax200SetupPhase {
        self.phase
    }
    pub fn first_error(&self) -> Option<&Ax200SetupError> {
        self.first_error.as_ref()
    }
    pub fn decisions(&self) -> Option<&SetupDecisions> {
        self.decisions.as_ref()
    }
    pub fn platform_reads(&self) -> &[service::Read] {
        self.lari.platform_reads()
    }
    pub fn responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    /// Historical completion of this epoch's thermal report, not live carrier,
    /// station readiness or permission to ignore subsequent device faults.
    pub fn thermal_command_acknowledged(&self) -> bool {
        self.thermal_acknowledged
    }
    pub fn initialized_nvm(&self) -> &InitializedNvm {
        self.lari.initialized_nvm()
    }
    pub fn take_firmware_notification(&mut self) -> Option<FirmwareNotification> {
        self.lari.take_firmware_notification()
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Error> {
        self.lari.replenish_completed_receive()
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        match self.lari.stop() {
            Ok(()) => {
                self.phase = Ax200SetupPhase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.first_error
                    .get_or_insert_with(|| Ax200SetupError::Boot(error.clone()));
                self.phase = Ax200SetupPhase::Failed;
                Err(error)
            }
        }
    }
    fn prepare(&mut self) -> Result<(), Ax200SetupError> {
        let boot = &self.lari.radio.initialized.boot;
        // RomBoot's start has precisely one free/used/status queue in
        // context, with no auxiliary queue constructor or registration path.
        // RXQ/RSS helpers therefore take their num_rxqs==1 branches.
        let entries = usize::from(boot.entries);
        let family = boot.profile.family();
        let (free, used, status) = match family {
            Family::Ax200 => (8, 4, 12),
            _ => (16, crate::wifi::intel::receive::used_stride(family), 2),
        };
        if boot.free.region().bytes != entries * free
            || boot.used.region().bytes != entries * used
            || boot.status.region().bytes != status
        {
            return Err(Ax200SetupError::QueueLayout);
        }
        let fw = &boot.firmware;
        let auxiliary = fw.supports_capability(110)
            || fw
                .command_version(1, 0x18)
                .is_some_and(|v| v.command_version >= 12);
        if !auxiliary {
            return Err(Ax200SetupError::AuxiliaryStationRequired);
        }
        let dqa = Control::dqa(fw).map_err(Ax200SetupError::Control)?;
        let thermal = Control::temperature_thresholds(fw, &[]).map_err(Ax200SetupError::Control)?;
        // This continuation has no owned host cooling/budget service yet.
        // Its absence cannot masquerade as an unsupported firmware capability.
        if fw.supports_capability(76) {
            return Err(Ax200SetupError::PowerBudgetRequired);
        }
        Control::ltr(fw, Ltr::NotObserved).map_err(Ax200SetupError::Control)?;
        self.decisions = Some(SetupDecisions {
            receive_queues: 1,
            firmware_auxiliary_station: auxiliary,
            dqa_command: dqa.is_some(),
            firmware_ltr: fw.supports_capability(50),
        });
        // Resolve the ECKV source before any new firmware publication; one
        // the platform cannot give is absent, as `iwl_bios_get_eckv` leaves it.
        let clock = self.lari.bios.external_clock();
        let power = Control::device_power(
            &self.lari.radio.initialized.boot.firmware,
            self.options.power_mode,
            clock,
            false,
        )
        .map_err(Ax200SetupError::Control)?;
        self.clock_observation = Some(clock);
        self.commands.extend(dqa);
        self.commands.push(thermal);
        self.commands.push(power);
        Ok(())
    }
    /// Advance only on the original command ticket's completed native RX and
    /// descriptor/TB0 CPU handoff. Timeout keeps all uncertain resources.
    /// # Safety
    /// `source` supplies fresh exclusive coherent pages for the kept
    /// native requester/domain under RomBoot's publication contract.
    pub unsafe fn advance(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200SetupPhase, Ax200SetupError> {
        if let Some(error) = self.first_error.as_ref() {
            return Err(error.clone());
        }
        // SAFETY: the same page-source contract is forwarded unchanged.
        let result = unsafe { self.advance_inner(source) };
        if let Err(error) = &result
            && !matches!(error, Ax200SetupError::Boot(Error::CommandReclaim(_)))
        {
            self.first_error = Some(error.clone());
            self.phase = Ax200SetupPhase::Failed;
        }
        result
    }
    unsafe fn advance_inner(
        &mut self,
        source: &dyn PageSource,
    ) -> Result<Ax200SetupPhase, Ax200SetupError> {
        if self.lari.radio.initialized.boot.state != State::PnvmObserved {
            return Err(Ax200SetupError::State);
        }
        if self.phase == Ax200SetupPhase::RegulatoryRequired {
            // This historical setup result must not conceal a later live
            // requester fault or RF-kill. Bound work to one RX buffer.
            self.lari
                .radio
                .initialized
                .boot
                .poll_one_notification_buffer()
                .map_err(Ax200SetupError::Boot)?;
            return Ok(self.phase);
        }
        if self.phase == Ax200SetupPhase::NotStarted {
            self.prepare()?;
        }
        if let Some(ticket) = self.ticket.as_ref() {
            let command = &self.commands[self.next - 1];
            let progress = self.lari.radio.initialized.boot.poll_command(ticket);
            if matches!(progress, Err(Error::CommandReclaim(_)))
                && self.deadline.as_ref().is_some_and(crate::Deadline::passed)
            {
                // CPU handoff can fail after RX completion. A deadline
                // ends retries but keeps the exact ticket/response and DMA;
                // it is never a reclamation or stopped-requester proof.
                return Err(Ax200SetupError::Deadline(command.kind()));
            }
            match progress.map_err(Ax200SetupError::Boot)? {
                CommandProgress::Pending => {
                    if self.deadline.as_ref().is_some_and(crate::Deadline::passed) {
                        return Err(Ax200SetupError::Deadline(command.kind()));
                    }
                    return Ok(self.phase);
                }
                CommandProgress::Completed(response) => {
                    let id = command.id();
                    let expected_group = if id.group == 0 { 1 } else { id.group };
                    let valid = response.command == id.opcode && response.group == expected_group;
                    let (command_id, group) = (response.command, response.group);
                    self.responses.push(response);
                    self.ticket = None;
                    self.deadline = None;
                    if !valid {
                        return Err(Ax200SetupError::Boot(Error::InitializationResponse {
                            command: command_id,
                            group,
                        }));
                    }
                    if command.kind() == Kind::TemperatureThresholds {
                        self.thermal_acknowledged = true;
                    }
                }
            }
        }
        let Some(command) = self.commands.get(self.next) else {
            self.phase = Ax200SetupPhase::RegulatoryRequired;
            return Ok(self.phase);
        };
        // SAFETY: original DMA/page-source contract of this advance call.
        self.ticket = Some(
            unsafe {
                self.lari.radio.initialized.boot.submit_command(
                    command.id(),
                    command.bytes(),
                    source,
                )
            }
            .map_err(Ax200SetupError::Boot)?,
        );
        self.deadline = Some(self.options.clock.deadline(self.options.command_timeout_us));
        self.next += 1;
        self.phase = Ax200SetupPhase::Waiting(command.kind());
        Ok(self.phase)
    }
}
