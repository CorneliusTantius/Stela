// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Cold LARI publication after the source prefix. Completion
//! stops before RX queue/RSS configuration and grants no radio readiness.
use super::*;
use crate::wifi::intel::radio::{
    bios::service::{self, BiosIo, Session},
    lari,
};
use alloc::boxed::Box;
use core::mem::ManuallyDrop;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LariPhase {
    NotStarted,
    Waiting { command: u8 },
    RxQueueConfigurationRequired,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LariError {
    Boot(Error),
    Plan(lari::Error),
}
/// Keeps both the initialized radio epoch and the BIOS service owner.
/// Neither public pure observations nor a caller-built plan can enter this path.
pub struct LariRadio<'a, Q: BootIo, B: BiosIo> {
    pub(super) radio: ColdRadio<'a, Q>,
    pub(super) bios: ManuallyDrop<Session<B>>,
    phase: LariPhase,
    inputs: lari::Inputs,
    plan: Option<lari::Plan>,
    next: usize,
    ticket: Option<CommandTicket>,
    responses: Vec<CommandResponse>,
}
impl<'a, Q: BootIo> ColdRadio<'a, Q> {
    /// Bind a BIOS-service owner only after the real prefix completed.
    /// A phase refusal returns both original owners without reading or publishing.
    /// # Safety
    /// `bios` reads the ACPI handle and EFI namespace belonging to this
    /// physical function/platform, not another device or captured file.
    /// Its owned service mappings/lifetimes must remain valid through stop and
    /// deliberate retention on uncertainty. This does not supply a PCI grant.
    pub unsafe fn begin_lari<B: BiosIo>(
        self,
        bios: B,
    ) -> Result<LariRadio<'a, Q, B>, Box<(Self, B)>> {
        if self.phase() != ColdRadioPhase::PlatformConfigurationRequired
            || self.initialized.boot.state != State::PnvmObserved
        {
            return Err(Box::new((self, bios)));
        }
        Ok(LariRadio {
            radio: self,
            bios: ManuallyDrop::new(Session::new(bios)),
            phase: LariPhase::NotStarted,
            inputs: lari::Inputs {
                dsm: [lari::Observation::NotObserved; 15],
                wide_bandwidth: lari::Observation::NotObserved,
            },
            plan: None,
            next: 0,
            ticket: None,
            responses: Vec::new(),
        })
    }
}
impl<Q: BootIo, B: BiosIo> LariRadio<'_, Q, B> {
    pub fn phase(&self) -> LariPhase {
        self.phase
    }
    /// Original reads, including source failures, not a reusable policy grant.
    pub fn platform_reads(&self) -> &[service::Read] {
        self.bios.reads()
    }
    pub fn responses(&self) -> &[CommandResponse] {
        &self.responses
    }
    pub fn plan(&self) -> Option<&lari::Plan> {
        self.plan.as_ref()
    }
    pub fn initialized_nvm(&self) -> &InitializedNvm {
        self.radio.initialized_nvm()
    }
    pub fn take_firmware_notification(&mut self) -> Option<FirmwareNotification> {
        self.radio.take_firmware_notification()
    }
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Error> {
        self.radio.replenish_completed_receive()
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        self.radio.stop()
    }
    /// Preflight all schemas and required BIOS reads before publishing
    /// the source-ordered extension/change. Only canonical DMA completions can
    /// advance; a copied plan or response cannot do so. RF-kill remains active.
    /// # Safety
    /// `source` supplies fresh exclusive pages for this coherent domain,
    /// under the boot owner's native DMA publication contract.
    pub unsafe fn advance(&mut self, source: &dyn PageSource) -> Result<LariPhase, LariError> {
        // SAFETY: forwarded from this method's native page-source contract.
        let result = unsafe { self.advance_inner(source) };
        if result.is_err() && !matches!(result, Err(LariError::Boot(Error::CommandReclaim(_)))) {
            self.phase = LariPhase::Failed;
        }
        result
    }
    unsafe fn advance_inner(&mut self, source: &dyn PageSource) -> Result<LariPhase, LariError> {
        if self.phase == LariPhase::Failed
            || self.radio.initialized.boot.state != State::PnvmObserved
        {
            return Err(LariError::Boot(Error::State));
        }
        if self.phase == LariPhase::RxQueueConfigurationRequired {
            return Ok(self.phase);
        }
        if self.plan.is_none() {
            loop {
                match lari::Plan::prepare(
                    &self.radio.initialized.boot.firmware,
                    self.radio.initialized.boot.profile.observed().radio_id,
                    self.inputs,
                ) {
                    Ok(plan) => {
                        self.plan = Some(plan);
                        break;
                    }
                    Err(lari::Error::NotObserved(input)) => {
                        let value = self.bios.observe(input);
                        match input {
                            lari::Input::Dsm(index) => self.inputs.dsm[usize::from(index)] = value,
                            lari::Input::WideBandwidth => self.inputs.wide_bandwidth = value,
                        }
                    }
                    Err(error) => return Err(LariError::Plan(error)),
                }
            }
        }
        let boot = &mut self.radio.initialized.boot;
        if let Some(ticket) = self.ticket.as_ref() {
            match boot.poll_command(ticket).map_err(LariError::Boot)? {
                CommandProgress::Pending => return Ok(self.phase),
                CommandProgress::Completed(response) => {
                    let (id, _) = self
                        .plan
                        .as_ref()
                        .unwrap()
                        .commands()
                        .nth(self.next - 1)
                        .unwrap();
                    let command = response.command;
                    let group = response.group;
                    // HCMD reclaim has already retired its internal response.
                    // Preserve the original completion, including rejected bytes.
                    self.responses.push(response);
                    self.ticket = None;
                    if command != id.opcode || group != id.group {
                        return Err(LariError::Boot(Error::InitializationResponse {
                            command,
                            group,
                        }));
                    }
                }
            }
        }
        let Some((id, bytes)) = self.plan.as_ref().unwrap().commands().nth(self.next) else {
            self.phase = LariPhase::RxQueueConfigurationRequired;
            return Ok(self.phase);
        };
        // SAFETY: forwarded from this method's native page-source contract.
        self.ticket =
            Some(unsafe { boot.submit_command(id, bytes, source) }.map_err(LariError::Boot)?);
        self.next += 1;
        self.phase = LariPhase::Waiting { command: id.opcode };
        Ok(self.phase)
    }
}
impl<Q: BootIo, B: BiosIo> Drop for LariRadio<'_, Q, B> {
    fn drop(&mut self) {
        if self.radio.initialized.boot.state == State::Stopped {
            // SAFETY: the independent stop fence completed. Otherwise
            // keep the BIOS owner along with RomBoot's uncertain DMA/PCI owner.
            unsafe { ManuallyDrop::drop(&mut self.bios) };
        }
    }
}
