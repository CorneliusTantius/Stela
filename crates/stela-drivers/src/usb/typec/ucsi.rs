// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! Serialized UCSI PPM command, reset and connector observation engine.
//!
//! Adapted from Linux ucsi.c/ucsi.h at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See NOTICE for source
//! hashes. Polling uses the transport, including ACPI _DSM refreshes;
//! an interrupt notification is not treated as command completion by itself.
//! Platform ACPI discovery, SCI/EC service, mux/retimer programming and policy
//! remain separate. No guest Apple transport is implemented here.

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

pub mod acpi;
pub mod altmode;
pub mod ccg;
mod wire;
use wire::*;
pub use wire::{Capability, Cci, ConnectorNumber, ConnectorStatus, Version};

const COMMAND_TIMEOUT_US: u64 = 10_000_000;
const RESET_POLL_US: u64 = 20_000;
const COMMAND_POLL_US: u64 = 1_000;

/// Process/deferred-context monotonic timer. A positive delay must advance
/// time by at least the requested duration; no scheduler sleeps are assumed.
pub trait Timer {
    fn now_us(&self) -> u64;
    fn delay_us(&self, microseconds: u64);
    /// Providers keep a stable timebase and support the complete requested
    /// interval. Native raw counters additionally validate their half-period.
    fn supports_duration(&self, _microseconds: u64) -> bool {
        true
    }
    fn start(&self) -> u64 {
        self.now_us()
    }
    fn elapsed_us(&self, start: u64) -> u64 {
        self.now_us().wrapping_sub(start)
    }
}
impl Timer for crate::Clock {
    fn now_us(&self) -> u64 {
        crate::Clock::now_us(self)
    }
    fn delay_us(&self, microseconds: u64) {
        self.delay(microseconds);
    }
    fn supports_duration(&self, microseconds: u64) -> bool {
        self.check_duration(microseconds).is_ok()
    }
    fn start(&self) -> u64 {
        self.try_start().expect("validated native Type-C clock")
    }
    fn elapsed_us(&self, start: u64) -> u64 {
        self.try_elapsed_us(start)
            .expect("validated native Type-C clock")
    }
}
fn validate_timer(timer: &impl Timer) -> Result<(), Error> {
    if !timer.supports_duration(COMMAND_TIMEOUT_US) {
        return Err(Error::TimerBudget {
            microseconds: COMMAND_TIMEOUT_US,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Unavailable,
    Mapping,
    Bounds { offset: usize, bytes: usize },
    Dsm { function: u64, status: u64 },
    DsmNoResult { function: u64 },
    I2c(crate::bus::i2c::Error),
    UnsupportedTransportVersion(u16),
    Io(u64),
}

/// One exclusively owned PPM transport. Calls must preserve real firmware
/// side effects and return failure when synchronization cannot be established.
/// `poll_cci` refreshes transport state even with notifications disabled.
pub trait Transport {
    fn read_version(&mut self) -> Result<u16, TransportError>;
    fn poll_cci(&mut self) -> Result<u32, TransportError>;
    fn read_message_in(&mut self, bytes: &mut [u8]) -> Result<(), TransportError>;
    fn write_message_out(&mut self, bytes: &[u8]) -> Result<(), TransportError>;
    fn write_control(&mut self, control: u64) -> Result<(), TransportError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Version,
    Poll,
    Submit,
    MessageOut,
    MessageIn,
    Command,
    Acknowledge,
    Cancel,
    Reset,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    TimerBudget {
        microseconds: u64,
    },
    Transport {
        phase: Phase,
        error: TransportError,
    },
    Timeout {
        phase: Phase,
        cci: u32,
    },
    InvalidCci(u32),
    UnexpectedCompletion {
        phase: Phase,
        cci: u32,
    },
    UnsupportedVersion(u16),
    InvalidConnector {
        number: u8,
        count: u8,
    },
    InvalidArgument,
    InvalidResponseLength {
        command: u8,
        bytes: usize,
    },
    NotSupported {
        command: u64,
        cci: u32,
    },
    Ppm {
        command: u64,
        cci: u32,
        status: u16,
    },
    /// PPM error flag without a successfully retrieved error-status payload.
    PpmRejected {
        command: u64,
        cci: u32,
    },
    ErrorStatus {
        command: u64,
        cci: u32,
        failure: Box<Error>,
    },
    /// Cancellation was acknowledged. The original request did not complete;
    /// a caller must decide whether issuing a new request is appropriate.
    Cancelled {
        command: u64,
        cci: u32,
    },
    NeedsReset,
    NotInitialized,
    GenerationExhausted,
}

/// A plain account for the boot log.
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("its mailbox is unavailable"),
            Self::Mapping => f.write_str("its mailbox is not mapped"),
            Self::Bounds { offset, bytes } => {
                write!(f, "{bytes} bytes at {offset:#x} lie outside its mailbox")
            }
            Self::Dsm { function, status } => write!(
                f,
                "its firmware method _DSM function {function} answered {status:#x}"
            ),
            Self::DsmNoResult { function } => write!(
                f,
                "its firmware method _DSM function {function} returned nothing"
            ),
            Self::I2c(error) => write!(f, "its I2C transfer failed: {error}"),
            Self::UnsupportedTransportVersion(version) => {
                write!(f, "its mailbox version {version:#x} is unsupported")
            }
            Self::Io(status) => write!(f, "its mailbox access failed ({status:#x})"),
        }
    }
}

/// The step a UCSI failure happened in, as words.
impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Version => "reading its version",
            Self::Poll => "polling its status",
            Self::Submit => "submitting a command",
            Self::MessageOut => "writing a command's data",
            Self::MessageIn => "reading a command's reply",
            Self::Command => "running a command",
            Self::Acknowledge => "acknowledging a command",
            Self::Cancel => "cancelling a command",
            Self::Reset => "resetting it",
        })
    }
}

/// A plain account for the boot log.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimerBudget { microseconds } => write!(
                f,
                "the delay clock cannot time a {microseconds} microsecond UCSI wait"
            ),
            Self::Transport { phase, error } => {
                write!(f, "UCSI failed while {phase}: {error}")
            }
            Self::Timeout { phase, cci } => {
                write!(f, "UCSI timed out while {phase} (status {cci:#x})")
            }
            Self::InvalidCci(cci) => write!(f, "the UCSI status {cci:#x} is invalid"),
            Self::UnexpectedCompletion { phase, cci } => write!(
                f,
                "UCSI completed unexpectedly while {phase} (status {cci:#x})"
            ),
            Self::UnsupportedVersion(version) => {
                write!(f, "UCSI version {version:#x} is unsupported")
            }
            Self::InvalidConnector { number, count } => write!(
                f,
                "UCSI connector {number} is out of range for {count} connectors"
            ),
            Self::InvalidArgument => f.write_str("a UCSI command argument is invalid"),
            Self::InvalidResponseLength { command, bytes } => write!(
                f,
                "the UCSI reply to command {command:#x} has a wrong length of {bytes} bytes"
            ),
            Self::NotSupported { command, cci } => write!(
                f,
                "the UCSI command {command:#x} is not supported (status {cci:#x})"
            ),
            Self::Ppm {
                command, status, ..
            } => write!(
                f,
                "the UCSI command {command:#x} failed with error status {status:#x}"
            ),
            Self::PpmRejected { command, cci } => write!(
                f,
                "the UCSI command {command:#x} failed with no error status (status {cci:#x})"
            ),
            Self::ErrorStatus {
                command, failure, ..
            } => write!(
                f,
                "the UCSI command {command:#x} failed, and reading why failed too: {failure}"
            ),
            Self::Cancelled { command, cci } => write!(
                f,
                "the UCSI command {command:#x} was cancelled (status {cci:#x})"
            ),
            Self::NeedsReset => f.write_str("UCSI needs a reset after an earlier failure"),
            Self::NotInitialized => f.write_str("UCSI is not started"),
            Self::GenerationExhausted => f.write_str("UCSI ran out of request numbers"),
        }
    }
}
impl core::error::Error for Error {}

/// A reviewed wire command. Its constructors keep all requested effects;
/// neither completion nor an accepted role request proves a role transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command {
    control: u64,
    connector: Option<ConnectorNumber>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    Connector,
    Partner,
    CablePlug,
    CablePlugOther,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataRole {
    Host,
    Device,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerRole {
    Source,
    Sink,
}

impl Command {
    fn global(control: u64) -> Self {
        Self {
            control,
            connector: None,
        }
    }
    fn connector(control: u64, connector: ConnectorNumber) -> Self {
        Self {
            control: control | connector.control(),
            connector: Some(connector),
        }
    }
    pub fn control(self) -> u64 {
        self.control
    }
    pub fn capability() -> Self {
        Self::global(CAPABILITY)
    }
    pub fn connector_capability(connector: ConnectorNumber) -> Self {
        Self::connector(CONNECTOR_CAPABILITY, connector)
    }
    pub fn connector_status(connector: ConnectorNumber) -> Self {
        Self::connector(STATUS, connector)
    }
    pub fn cable_property(connector: ConnectorNumber) -> Self {
        Self::connector(CABLE_PROPERTY, connector)
    }
    pub fn current_cam(connector: ConnectorNumber) -> Self {
        Self::connector(CURRENT_CAM, connector)
    }
    pub fn new_cam(connector: ConnectorNumber, mode: u8, enter: bool) -> Self {
        Self::new_cam_configuration(connector, mode, enter, 0)
    }
    pub fn new_cam_configuration(
        connector: ConnectorNumber,
        mode: u8,
        enter: bool,
        configuration: u32,
    ) -> Self {
        Self::connector(
            NEW_CAM
                | (u64::from(enter) << 23)
                | (u64::from(mode) << 24)
                | (u64::from(configuration) << 32),
            connector,
        )
    }
    pub fn alternate_mode(connector: ConnectorNumber, recipient: Recipient, offset: u8) -> Self {
        let recipient = match recipient {
            Recipient::Connector => 0,
            Recipient::Partner => 1,
            Recipient::CablePlug => 2,
            Recipient::CablePlugOther => 3,
        };
        Self {
            control: ALTERNATE_MODES
                | (recipient << 16)
                | (u64::from(connector.get()) << 24)
                | (u64::from(offset) << 32),
            connector: Some(connector),
        }
    }
    pub fn pdos(
        connector: ConnectorNumber,
        partner: bool,
        source: bool,
        offset: u8,
        count: u8,
    ) -> Result<Self, Error> {
        if !(1..=4).contains(&count) {
            return Err(Error::InvalidArgument);
        }
        Ok(Self::connector(
            PDOS | (u64::from(partner) << 23)
                | (u64::from(offset) << 24)
                | (u64::from(count - 1) << 32)
                | (u64::from(source) << 34),
            connector,
        ))
    }
    pub fn request_data_role(
        connector: ConnectorNumber,
        role: DataRole,
        accept_swaps: bool,
    ) -> Self {
        Self::connector(
            SET_DATA_ROLE
                | (match role {
                    DataRole::Host => 1,
                    DataRole::Device => 2,
                } << 23)
                | (u64::from(accept_swaps) << 25),
            connector,
        )
    }
    pub fn request_power_role(
        connector: ConnectorNumber,
        role: PowerRole,
        accept_swaps: bool,
    ) -> Self {
        Self::connector(
            SET_POWER_ROLE
                | (match role {
                    PowerRole::Source => 1,
                    PowerRole::Sink => 2,
                } << 23)
                | (u64::from(accept_swaps) << 25),
            connector,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub command: u64,
    pub cci: Cci,
    pub bytes: usize,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorSnapshot {
    pub number: ConnectorNumber,
    pub generation: u64,
    pub capability: [u8; 4],
    pub capability_bytes: u8,
    pub status: ConnectorStatus,
}

/// All operations, including notification delivery, are serialized through
/// `&mut self` in process/deferred context. There is one in-flight command and
/// at most one firmware-latched connector change. No asynchronous work or
/// unacknowledged hardware is released by Drop.
pub struct Controller<T: Transport, C: Timer> {
    transport: T,
    timer: C,
    version: Version,
    generation: u64,
    ready: bool,
    initialized: bool,
    fault: Option<Error>,
    pending: Option<ConnectorNumber>,
    capability: Option<Capability>,
    connectors: Vec<ConnectorSnapshot>,
    last_cci: Cci,
    last_completion: Option<Completion>,
}

impl<T: Transport, C: Timer> Controller<T, C> {
    pub fn new(mut transport: T, timer: C) -> Result<Self, Error> {
        validate_timer(&timer)?;
        let raw = transport.read_version().map_err(|error| Error::Transport {
            phase: Phase::Version,
            error,
        })?;
        Ok(Self {
            transport,
            timer,
            version: Version::new(raw)?,
            generation: 0,
            ready: false,
            initialized: false,
            fault: None,
            pending: None,
            capability: None,
            connectors: Vec::new(),
            last_cci: Cci(0),
            last_completion: None,
        })
    }
    pub fn version(&self) -> Version {
        self.version
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn initialized(&self) -> bool {
        self.initialized
    }
    pub fn fault(&self) -> Option<&Error> {
        self.fault.as_ref()
    }
    pub fn capability(&self) -> Option<Capability> {
        self.capability
    }
    pub fn connectors(&self) -> &[ConnectorSnapshot] {
        &self.connectors
    }
    pub fn pending_change(&self) -> Option<ConnectorNumber> {
        self.pending
    }
    pub fn last_cci(&self) -> Cci {
        self.last_cci
    }
    pub fn last_completion(&self) -> Option<Completion> {
        self.last_completion
    }

    fn poison(&mut self, error: Error) -> Error {
        self.ready = false;
        self.initialized = false;
        self.fault = Some(error.clone());
        error
    }
    fn check_ready(&self) -> Result<(), Error> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if !self.ready {
            return Err(Error::NeedsReset);
        }
        validate_timer(&self.timer)
    }
    fn io<U>(&mut self, phase: Phase, result: Result<U, TransportError>) -> Result<U, Error> {
        result.map_err(|error| self.poison(Error::Transport { phase, error }))
    }
    fn cci(&mut self) -> Result<Cci, Error> {
        let read = self.transport.poll_cci();
        let cci = Cci(self.io(Phase::Poll, read)?);
        self.last_cci = cci;
        cci.validate().map_err(|e| self.poison(e))?;
        Ok(cci)
    }
    fn observe(&mut self, cci: Cci) -> Result<(), Error> {
        if cci.busy() {
            return Ok(());
        }
        if let Some(number) = cci.connector() {
            let count = self.capability.map_or(127, |cap| cap.connectors);
            if number.get() > count {
                return Err(self.poison(Error::InvalidConnector {
                    number: number.get(),
                    count,
                }));
            }
            if self.pending.is_some_and(|old| old != number) {
                return Err(self.poison(Error::UnexpectedCompletion {
                    phase: Phase::Poll,
                    cci: cci.0,
                }));
            }
            self.pending = Some(number);
        }
        Ok(())
    }
    /// Deliver a real cached CCI read from a platform notification. Busy CCI
    /// fields are ignored, and no command/ACK is completed on this path.
    pub fn observe_notification(&mut self, raw: u32) -> Result<(), Error> {
        self.check_ready()?;
        let cci = Cci(raw);
        cci.validate().map_err(|e| self.poison(e))?;
        self.observe(cci)
    }
    fn submit(&mut self, control: u64) -> Result<(), Error> {
        let write = self.transport.write_control(control);
        self.io(Phase::Submit, write)
    }
    fn expired(&self, start: u64) -> bool {
        self.timer.elapsed_us(start) >= COMMAND_TIMEOUT_US
    }

    fn await_command(&mut self, phase: Phase) -> Result<Cci, Error> {
        let start = self.timer.start();
        loop {
            let cci = self.cci()?;
            if !cci.busy() {
                if phase != Phase::Acknowledge || cci.0 & ACK_COMPLETE != 0 {
                    self.observe(cci)?;
                }
                let complete = match phase {
                    Phase::Acknowledge => ACK_COMPLETE,
                    Phase::Cancel => CANCEL_COMPLETE | COMMAND_COMPLETE,
                    _ => COMMAND_COMPLETE,
                };
                if cci.0 & complete == complete {
                    let forbidden = match phase {
                        Phase::Acknowledge => {
                            COMMAND_COMPLETE
                                | ERROR
                                | NOT_SUPPORTED
                                | RESET_COMPLETE
                                | CANCEL_COMPLETE
                        }
                        Phase::Cancel => ACK_COMPLETE | ERROR | NOT_SUPPORTED | RESET_COMPLETE,
                        _ => ACK_COMPLETE | RESET_COMPLETE | CANCEL_COMPLETE,
                    };
                    if cci.0 & forbidden != 0 || (phase == Phase::Acknowledge && cci.length() != 0)
                    {
                        return Err(self.poison(Error::UnexpectedCompletion { phase, cci: cci.0 }));
                    }
                    return Ok(cci);
                }
            }
            if self.expired(start) {
                return Err(Error::Timeout { phase, cci: cci.0 });
            }
            self.timer.delay_us(COMMAND_POLL_US);
        }
    }
    fn acknowledge(&mut self, connector: Option<ConnectorNumber>) -> Result<(), Error> {
        // Clear the old software latch before observing ACK_COMPLETE. A new
        // firmware event, including the same connector again, is then kept.
        if let Some(number) = connector {
            if self.pending != Some(number) {
                return Err(self.poison(Error::UnexpectedCompletion {
                    phase: Phase::Acknowledge,
                    cci: self.last_cci.0,
                }));
            }
            self.pending = None;
        }
        let result = self
            .submit(
                ACK | ACK_COMMAND
                    | if connector.is_some() {
                        ACK_CONNECTOR
                    } else {
                        0
                    },
            )
            .and_then(|()| self.await_command(Phase::Acknowledge));
        if let Err(error) = result {
            if self.pending.is_none() {
                self.pending = connector;
            }
            return Err(self.poison(error));
        }
        Ok(())
    }

    /// An explicit reset invalidates all old snapshots, even if reset fails.
    /// Reset is the only operation permitted to recover an unresolved command.
    pub fn reset(&mut self) -> Result<(), Error> {
        validate_timer(&self.timer)?;
        self.generation = match self.generation.checked_add(1) {
            Some(value) => value,
            None => return Err(self.poison(Error::GenerationExhausted)),
        };
        self.ready = false;
        self.initialized = false;
        self.capability = None;
        self.connectors.clear();
        self.pending = None;
        self.last_completion = None;
        let initial = self.cci()?;
        if initial.0 & RESET_COMPLETE != 0 {
            // Source workaround: a new ordinary command clears an old reset
            // completion. A timeout here does not prove the following reset.
            self.submit(NOTIFY)?;
            let start = self.timer.start();
            while self.cci()?.0 & COMMAND_COMPLETE == 0 {
                if self.expired(start) {
                    break;
                }
                self.timer.delay_us(RESET_POLL_US);
            }
        }
        self.submit(RESET)?;
        // Linux ucsi_reset_ppm: done once the reset bit is set, resetting
        // again whenever the PPM still reports other work.
        let start = self.timer.start();
        let mut cci = initial;
        loop {
            if self.expired(start) {
                return Err(self.poison(Error::Timeout {
                    phase: Phase::Reset,
                    cci: cci.0,
                }));
            }
            self.timer.delay_us(RESET_POLL_US);
            cci = self.cci()?;
            if cci.0 & !RESET_COMPLETE != 0 {
                self.submit(RESET)?;
            }
            if cci.0 & RESET_COMPLETE != 0 {
                self.fault = None;
                self.ready = true;
                return Ok(());
            }
        }
    }

    fn run(
        &mut self,
        command: Command,
        input: &mut [u8],
        output: &[u8],
        connector_ack: bool,
    ) -> Result<Completion, Error> {
        self.check_ready()?;
        if input.len() > self.version.message_in_bytes()
            || output.len() > self.version.message_out_bytes()
        {
            return Err(Error::InvalidArgument);
        }
        if let (Some(number), Some(cap)) = (command.connector, self.capability)
            && number.get() > cap.connectors
        {
            return Err(Error::InvalidConnector {
                number: number.get(),
                count: cap.connectors,
            });
        }
        if !output.is_empty() {
            let result = self.transport.write_message_out(output);
            self.io(Phase::MessageOut, result)?;
        }
        self.submit(command.control)?;
        let cci = match self.await_command(Phase::Command) {
            Ok(cci) => cci,
            Err(Error::Timeout { cci, .. }) if cci & BUSY != 0 => {
                self.submit(CANCEL)?;
                if let Err(error) = self.await_command(Phase::Cancel) {
                    return Err(self.poison(error));
                }
                self.acknowledge(None)?;
                return Err(Error::Cancelled {
                    command: command.control,
                    cci,
                });
            }
            Err(error) => return Err(self.poison(error)),
        };
        let bytes = cci.length();
        let mut staged = [0u8; 255];
        let minimum = match command.control & 0xff {
            CAPABILITY => 16,
            CONNECTOR_CAPABILITY => 2,
            CURRENT_CAM => 1,
            CABLE_PROPERTY => 5,
            STATUS => 9,
            ERROR_STATUS => 2,
            _ => 0,
        };
        let protocol_length =
            bytes > input.len() || bytes > self.version.message_in_bytes() || bytes < minimum;
        if !protocol_length && cci.0 & (ERROR | NOT_SUPPORTED) == 0 && bytes != 0 {
            let result = self.transport.read_message_in(&mut staged[..bytes]);
            self.io(Phase::MessageIn, result)?;
        }
        // Error responses acknowledge only command completion; a connector
        // change remains latched until its own successful status observation.
        let ack = (connector_ack && cci.0 & (ERROR | NOT_SUPPORTED) == 0 && !protocol_length)
            .then_some(command.connector)
            .flatten();
        self.acknowledge(ack)?;
        let completion = Completion {
            command: command.control,
            cci,
            bytes,
            generation: self.generation,
        };
        self.last_completion = Some(completion);
        if cci.0 & NOT_SUPPORTED != 0 {
            return Err(Error::NotSupported {
                command: command.control,
                cci: cci.0,
            });
        }
        if cci.0 & ERROR != 0 {
            return Err(Error::PpmRejected {
                command: command.control,
                cci: cci.0,
            });
        }
        if protocol_length {
            return Err(Error::InvalidResponseLength {
                command: command.control as u8,
                bytes,
            });
        }
        input[..bytes].copy_from_slice(&staged[..bytes]);
        Ok(completion)
    }

    fn execute_inner(
        &mut self,
        command: Command,
        input: &mut [u8],
        output: &[u8],
        connector_ack: bool,
    ) -> Result<Completion, Error> {
        match self.run(command, input, output, connector_ack) {
            Err(Error::PpmRejected { cci, .. }) => {
                let target = if self.version.raw() > 0x0120 {
                    command.connector.map_or(0, ConnectorNumber::control)
                } else {
                    0
                };
                let mut bytes = [0u8; 2];
                let detail = self.run(
                    Command::global(ERROR_STATUS | target),
                    &mut bytes,
                    &[],
                    false,
                );
                match detail {
                    Ok(receipt) if receipt.bytes == 2 => Err(Error::Ppm {
                        command: command.control,
                        cci,
                        status: u16::from_le_bytes(bytes),
                    }),
                    Ok(receipt) => Err(Error::ErrorStatus {
                        command: command.control,
                        cci,
                        failure: Box::new(Error::InvalidResponseLength {
                            command: ERROR_STATUS as u8,
                            bytes: receipt.bytes,
                        }),
                    }),
                    Err(error) => Err(Error::ErrorStatus {
                        command: command.control,
                        cci,
                        failure: Box::new(error),
                    }),
                }
            }
            result => result,
        }
    }
    pub fn execute(
        &mut self,
        command: Command,
        input: &mut [u8],
        output: &[u8],
    ) -> Result<Completion, Error> {
        self.execute_inner(command, input, output, false)
    }

    pub fn initialize(&mut self) -> Result<(), Error> {
        let result = self.initialize_inner();
        result.map_err(|error| self.poison(error))
    }
    fn initialize_inner(&mut self) -> Result<(), Error> {
        self.reset()?;
        self.execute(Command::global(NOTIFY | NOTIFY_BASIC), &mut [], &[])?;
        let mut capability = [0; 16];
        let receipt = self.execute(Command::capability(), &mut capability, &[])?;
        let capability = Capability::parse(&capability[..receipt.bytes])?;
        self.capability = Some(capability);
        if let Some(number) = self.pending
            && number.get() > capability.connectors
        {
            return Err(Error::InvalidConnector {
                number: number.get(),
                count: capability.connectors,
            });
        }
        for number in 1..=capability.connectors {
            let number = ConnectorNumber::new(number)?;
            let mut cap = [0; 4];
            let receipt = self.execute(Command::connector_capability(number), &mut cap, &[])?;
            if !(2..=4).contains(&receipt.bytes) {
                return Err(Error::InvalidResponseLength {
                    command: CONNECTOR_CAPABILITY as u8,
                    bytes: receipt.bytes,
                });
            }
            let status = self.read_status(number, false)?;
            self.connectors.push(ConnectorSnapshot {
                number,
                generation: self.generation,
                capability: cap,
                capability_bytes: receipt.bytes as u8,
                status,
            });
        }
        self.execute(
            Command::global(NOTIFY | capability.notifications(self.version)),
            &mut [],
            &[],
        )?;
        self.initialized = true;
        Ok(())
    }
    fn read_status(
        &mut self,
        number: ConnectorNumber,
        acknowledge: bool,
    ) -> Result<ConnectorStatus, Error> {
        let mut bytes = [0; 19];
        let len = bytes.len().min(self.version.message_in_bytes());
        let receipt = self.execute_inner(
            Command::connector_status(number),
            &mut bytes[..len],
            &[],
            acknowledge,
        )?;
        ConnectorStatus::parse(self.version, &bytes[..receipt.bytes])
    }
    pub fn connector_status(&mut self, number: ConnectorNumber) -> Result<ConnectorStatus, Error> {
        self.read_status(number, false)
    }
    pub fn poll_change(&mut self) -> Result<Option<ConnectorNumber>, Error> {
        self.check_ready()?;
        let cci = self.cci()?;
        self.observe(cci)?;
        if !cci.busy() && cci.0 & COMMAND_COMPLETE != 0 {
            return Err(self.poison(Error::UnexpectedCompletion {
                phase: Phase::Poll,
                cci: cci.0,
            }));
        }
        Ok(self.pending)
    }
    /// Return only after the status and connector-change ACK complete.
    /// A role command's completion alone never updates this snapshot.
    pub fn service_change(&mut self) -> Result<Option<ConnectorSnapshot>, Error> {
        if !self.initialized {
            return Err(Error::NotInitialized);
        }
        self.check_ready()?;
        let Some(number) = self.pending else {
            return Ok(None);
        };
        let status = self.read_status(number, true)?;
        let snapshot = &mut self.connectors[usize::from(number.get() - 1)];
        snapshot.status = status;
        Ok(Some(*snapshot))
    }
}

#[cfg(test)]
mod tests;
