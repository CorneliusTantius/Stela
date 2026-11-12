// SPDX-License-Identifier: GPL-2.0-or-later
//! Native AMD SFH v2 (PCI 1022:15e4, ACS dialect 2). This is distinct
//! from AMD MP2 I²C 15e6, legacy SFH and SFH1.1 164a. Linux donor provenance,
//! notices and report limitations are recorded in NOTICE.
//! Copyright 2020-2021 Advanced Micro Devices, Inc.
//! Authors: Shyam Sundar S K, Sandeep Singh, Basavaraj Natikar,
//! Nehal Bakulchandra Shah.
//!
//! Sensors continuously DMA into kept coherent allocations. Reports read
//! each aligned word through the domain's checked coherence service;
//! no ownership-transfer invalidation, stop/read/restart, vector atomicity or
//! new-sample counter is invented. The owner serializes this polling/control
//! API and supplies scheduling (the donor polls every 200 ms).
use crate::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DmaError, DmaMapping},
        memory::{CacheAttribute, MemoryError, PageSource},
    },
    i2c::Timer,
};
use alloc::{sync::Arc, vec::Vec};
pub mod cold;
mod descriptor;
pub mod pci;
mod report;
pub use report::InputReport;

pub const PERIOD_MS: u8 = 200;
pub const POLL_INTERVAL_US: u64 = 200_000;
pub const REGION_BYTES: usize = 0x20000;
const C2P_COMMAND: usize = 0x10500;
const C2P_ADDRESS_LOW: usize = 0x10504;
const C2P_ADDRESS_HIGH: usize = 0x10508;
const C2P_PRESENCE: usize = 0x10510;
const C2P_LIGHT: usize = 0x10514;
const P2C_RESPONSE: usize = 0x10680;
const P2C_DISCOVERY: usize = 0x10684;
const P2C_ACS: usize = 0x1068c;
const P2C_INTERRUPT: usize = 0x10690;
const P2C_INTERRUPT_ACK: usize = 0x10694;
const RESPONSE_TIMEOUT_US: u64 = 10_000_000;
const RESPONSE_INTERVAL_US: u64 = 500;
const SENSOR_ENABLED: u8 = 4;
const SENSOR_DISABLED: u8 = 5;
const DMA_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Sensor {
    Accelerometer = 0,
    Gyroscope = 1,
    Magnetometer = 2,
    OperatingMode = 15,
    HumanPresence = 16,
    AmbientLight = 19,
    AmbientColor = 22,
}
const SENSORS: [Sensor; 7] = [
    Sensor::Accelerometer,
    Sensor::Gyroscope,
    Sensor::Magnetometer,
    Sensor::OperatingMode,
    Sensor::AmbientLight,
    Sensor::HumanPresence,
    Sensor::AmbientColor,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Claimed,
    Running,
    Suspended,
    Stopped,
    Faulted,
    Shutdown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SensorState {
    Disabled,
    Enabled,
    Uncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Config(crate::bus::pci::ConfigError),
    Capability(crate::bus::pci::CapabilityError),
    Claim(crate::bus::pci::requester::ClaimError),
    Clock(crate::ClockError),
    UnsupportedController,
    UnsupportedDialect(u8),
    PciAuthority,
    InvalidBar,
    RegisterUnavailable(usize),
    RegisterRejected(usize),
    DiscoveryFailed(u32),
    NoSensors,
    NoHidSchema(Sensor),
    SensorAbsent(Sensor),
    SensorDisabled(Sensor),
    NotReady,
    NeedsReset,
    AlreadyInitialized,
    Allocation,
    Memory(MemoryError),
    Dma(DmaError),
    Timeout {
        sensor: Sensor,
        expected: u8,
        observed: u32,
    },
    StaleResponse {
        sensor: Sensor,
        expected: u8,
    },
    ReportBuffer {
        needed: usize,
    },
    ReportId {
        expected: u8,
        actual: u8,
    },
    UnsupportedSetReport,
    InvalidPresence(u8),
}

/// The sensor's name, as a log reads it.
impl core::fmt::Display for Sensor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Accelerometer => "accelerometer",
            Self::Gyroscope => "gyroscope",
            Self::Magnetometer => "magnetometer",
            Self::OperatingMode => "operating mode sensor",
            Self::HumanPresence => "human presence sensor",
            Self::AmbientLight => "ambient light sensor",
            Self::AmbientColor => "ambient color sensor",
        })
    }
}

/// The sensor command a response answers, in words.
fn command_name(expected: u8) -> &'static str {
    match expected {
        SENSOR_ENABLED => "enable",
        SENSOR_DISABLED => "disable",
        _ => "sensor",
    }
}

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Config(error) => return error.fmt(f),
            Self::Capability(error) => return error.fmt(f),
            Self::Claim(error) => return error.fmt(f),
            Self::Clock(error) => return error.fmt(f),
            Self::UnsupportedController => "this sensor hub is not supported",
            Self::UnsupportedDialect(dialect) => {
                return write!(f, "its firmware interface {dialect} is unsupported");
            }
            Self::PciAuthority => "its PCI function changed under the driver",
            Self::InvalidBar => "its register BAR is not mapped as required",
            Self::RegisterUnavailable(offset) => {
                return write!(f, "its register {offset:#x} reads all ones");
            }
            Self::RegisterRejected(offset) => {
                return write!(f, "its register {offset:#x} did not keep what was written");
            }
            Self::DiscoveryFailed(value) => {
                return write!(f, "its sensor discovery failed ({value:#x})");
            }
            Self::NoSensors => "it reports no sensors",
            Self::NoHidSchema(sensor) => {
                return write!(f, "its {sensor} has no input report layout");
            }
            Self::SensorAbsent(sensor) => return write!(f, "its {sensor} is absent"),
            Self::SensorDisabled(sensor) => return write!(f, "its {sensor} is disabled"),
            Self::NotReady => "it is not running",
            Self::NeedsReset => "it needs a reset after an earlier failure",
            Self::AlreadyInitialized => "it is already started",
            Self::Allocation => "memory for its sensors ran out",
            Self::Memory(error) => return error.fmt(f),
            Self::Dma(error) => return error.fmt(f),
            Self::Timeout {
                sensor,
                expected,
                observed,
            } => {
                return write!(
                    f,
                    "its {sensor} did not answer the {} command in time (response {observed:#x})",
                    command_name(*expected)
                );
            }
            Self::StaleResponse { sensor, expected } => {
                return write!(
                    f,
                    "its {sensor} showed an old {} answer before the command was sent",
                    command_name(*expected)
                );
            }
            Self::ReportBuffer { needed } => {
                return write!(f, "the report buffer is smaller than {needed} bytes");
            }
            Self::ReportId { expected, actual } => {
                return write!(f, "the report ID is {actual:#x}, not {expected:#x}");
            }
            Self::UnsupportedSetReport => "it does not accept output reports",
            Self::InvalidPresence(value) => {
                return write!(f, "its presence value {value:#x} is invalid");
            }
        })
    }
}
/// Native adapters keep exact ECAM and UC BAR2 owners. Register operations
/// must use aligned 32-bit MMIO and report failures without discarding
/// writes. `check_authority` verifies the device/configuration epoch.
pub trait Registers {
    fn check_authority(&mut self) -> Result<(), Error>;
    fn read32(&mut self, offset: usize) -> Result<u32, Error>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error>;
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error>;
    /// # Safety
    /// Every published sensor acknowledged disable and bus mastering is off.
    unsafe fn mark_quiescent(&mut self);
}
struct Slot {
    sensor: Sensor,
    state: SensorState,
    dma: DmaMapping,
    published: bool,
    pending: Option<bool>,
    ever_published: bool,
    retire_ready: bool,
}
impl Drop for Slot {
    fn drop(&mut self) {
        if (!self.ever_published || self.retire_ready) && self.dma.address().is_ok() {
            // SAFETY: the IOVA was never given to the device, or this sensor's
            // successful disable established its quiescence before clearing it.
            let _ = unsafe { self.dma.unmap() };
        }
        // Published/uncertain mappings quarantine their domain and pins.
    }
}
/// Complete reports containing only source-backed descriptor fields.
pub trait ReportSink {
    fn input(&mut self, sensor: Sensor, report: &InputReport);
}
pub struct Controller<R, T> {
    registers: R,
    timer: T,
    domain: Arc<dyn DmaDomain>,
    state: State,
    first_error: Option<Error>,
    acs: Option<u32>,
    slots: Vec<Slot>,
}
impl<R: Registers, T: Timer> Controller<R, T> {
    /// Claim without device writes. The native PCI adapter supplies
    /// stopped ownership; this grant binds the DMA provider to that requester.
    ///
    /// # Safety
    /// `domain` is the function's DMA domain, isolated or the
    /// passthrough domain ([`DomainKind`](crate::bus::dma::mapping::DomainKind)),
    /// meeting the [`DmaDomain`] contract for its kind, with its WB payload
    /// coherency checked. Firmware/AML/SMM,
    /// reset/removal and other workers cannot change this exclusive SFH epoch.
    /// Registers, domain and backing allocations remain valid in process/
    /// deferred context, including failures. No numeric identity-DMA fallback.
    pub unsafe fn claim(
        mut registers: R,
        timer: T,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        timer
            .check_duration(RESPONSE_TIMEOUT_US)
            .map_err(Error::Clock)?;
        registers.check_authority()?;
        let acs = registers.read32(P2C_ACS)?;
        if acs == u32::MAX {
            return Err(Error::RegisterUnavailable(P2C_ACS));
        }
        if acs & 15 != 2 {
            return Err(Error::UnsupportedDialect((acs & 15) as u8));
        }
        Ok(Self {
            registers,
            timer,
            domain,
            state: State::Claimed,
            first_error: None,
            acs: Some(acs),
            slots: Vec::new(),
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn first_error(&self) -> Option<Error> {
        self.first_error
    }
    /// Full firmware advertisement, including unrecognized bits. Unknown bits
    /// remain visible and do not acquire an invented sensor/report schema.
    pub fn advertised_sensor_mask(&self) -> u32 {
        self.acs.map_or(0, |acs| acs >> 4)
    }
    pub fn available(&self, sensor: Sensor) -> bool {
        self.acs
            .is_some_and(|acs| (acs >> 4) & (1 << sensor as u8) != 0)
    }
    pub fn sensor_state(&self, sensor: Sensor) -> Option<SensorState> {
        self.slots
            .iter()
            .find(|slot| slot.sensor == sensor)
            .map(|slot| slot.state)
    }
    fn authority(&mut self) -> Result<(), Error> {
        self.registers.check_authority()?;
        let acs = self.registers.read32(P2C_ACS)?;
        if Some(acs) != self.acs {
            return Err(Error::PciAuthority);
        }
        Ok(())
    }
    fn fault<U>(&mut self, result: Result<U, Error>) -> Result<U, Error> {
        if result.is_err() {
            if self.first_error.is_none() {
                self.first_error = result.as_ref().err().copied();
            }
            self.state = State::Faulted;
        }
        result
    }
    fn clear_interrupt(&mut self) -> Result<(), Error> {
        if self.registers.read32(P2C_INTERRUPT)? != 0 {
            self.registers.write32(P2C_INTERRUPT, 0)?;
            self.registers.write32(P2C_INTERRUPT_ACK, 15)?;
        }
        Ok(())
    }
    fn response_matches(word: u32, sensor: Sensor, expected: u8) -> bool {
        word & 3 == 0
            && (word >> 4) & 15 == u32::from(expected)
            && (word >> 16) & 63 == u32::from(sensor as u8)
    }
    fn wait_response(&mut self, sensor: Sensor, enable: bool, start: u64) -> Result<(), Error> {
        let expected = if enable {
            SENSOR_ENABLED
        } else {
            SENSOR_DISABLED
        };
        loop {
            if self.timer.elapsed_us(start) >= RESPONSE_TIMEOUT_US {
                return Err(Error::Timeout {
                    sensor,
                    expected,
                    observed: 0,
                });
            }
            let observed = self.registers.read32(P2C_RESPONSE)?;
            if self.timer.elapsed_us(start) >= RESPONSE_TIMEOUT_US {
                return Err(Error::Timeout {
                    sensor,
                    expected,
                    observed,
                });
            }
            if observed == u32::MAX {
                return Err(Error::RegisterUnavailable(P2C_RESPONSE));
            }
            if Self::response_matches(observed, sensor, expected) {
                return Ok(());
            }
            let wait = self.timer.start();
            while self.timer.elapsed_us(wait) < RESPONSE_INTERVAL_US {
                self.timer.relax();
                if self.timer.elapsed_us(start) >= RESPONSE_TIMEOUT_US {
                    return Err(Error::Timeout {
                        sensor,
                        expected,
                        observed,
                    });
                }
            }
        }
    }
    fn check_command_deadline(
        &self,
        sensor: Sensor,
        expected: u8,
        start: u64,
    ) -> Result<(), Error> {
        if self.timer.elapsed_us(start) >= RESPONSE_TIMEOUT_US {
            return Err(Error::Timeout {
                sensor,
                expected,
                observed: 0,
            });
        }
        Ok(())
    }
    fn complete(&mut self, index: usize, enable: bool) {
        self.slots[index].state = if enable {
            SensorState::Enabled
        } else {
            SensorState::Disabled
        };
        self.slots[index].pending = None;
        if !enable {
            self.slots[index].published = false;
        }
    }
    fn command(&mut self, index: usize, enable: bool) -> Result<(), Error> {
        let start = self.timer.start();
        self.authority()?;
        let sensor = self.slots[index].sensor;
        // A previous uncertain command must complete before any opposite one.
        // A late response resolves the operation without replay.
        if let Some(pending) = self.slots[index].pending {
            self.wait_response(sensor, pending, start)?;
            self.complete(index, pending);
            if pending == enable {
                return Ok(());
            }
        }
        let expected = if enable {
            SENSOR_ENABLED
        } else {
            SENSOR_DISABLED
        };
        if Self::response_matches(self.registers.read32(P2C_RESPONSE)?, sensor, expected) {
            return Err(Error::StaleResponse { sensor, expected });
        }
        let address = if enable {
            self.slots[index].dma.address().map_err(Error::Dma)?
        } else {
            0
        };
        if enable {
            self.slots[index]
                .dma
                .sync_for_device(0..DMA_BYTES)
                .map_err(Error::Dma)?;
        }
        self.slots[index].state = SensorState::Uncertain;
        self.slots[index].published = true;
        self.slots[index].ever_published = true;
        self.slots[index].retire_ready = false;
        // Source writeq order: low dword, high dword, command publication last.
        self.check_command_deadline(sensor, expected, start)?;
        self.registers.write32(C2P_ADDRESS_LOW, address as u32)?;
        self.check_command_deadline(sensor, expected, start)?;
        self.registers
            .write32(C2P_ADDRESS_HIGH, (address >> 32) as u32)?;
        self.check_command_deadline(sensor, expected, start)?;
        self.slots[index].pending = Some(enable);
        self.registers
            .write32(C2P_COMMAND, command_word(sensor, enable))?;
        self.check_command_deadline(sensor, expected, start)?;
        self.wait_response(sensor, enable, start)?;
        self.complete(index, enable);
        Ok(())
    }
    pub fn initialize(&mut self, source: &dyn PageSource) -> Result<(), Error> {
        if self.state != State::Claimed {
            return Err(Error::AlreadyInitialized);
        }
        let result = self.initialize_inner(source);
        self.fault(result)
    }
    fn initialize_inner(&mut self, source: &dyn PageSource) -> Result<(), Error> {
        self.authority()?;
        let geometry = source.page_geometry().map_err(Error::Memory)?;
        self.slots
            .try_reserve_exact(SENSORS.len())
            .map_err(|_| Error::Allocation)?;
        for sensor in SENSORS {
            if !self.available(sensor) {
                continue;
            }
            let pages = source
                .allocate(DMA_BYTES, geometry.base_bytes(), CacheAttribute::WriteBack)
                .map_err(Error::Memory)?;
            if !geometry.supports(pages.page_shift())
                || pages.logical_bytes() != DMA_BYTES
                || pages.cache_attribute() != CacheAttribute::WriteBack
            {
                return Err(Error::Memory(MemoryError::InvalidPageList));
            }
            let dma = DmaMapping::map(self.domain.clone(), pages, Direction::FromDevice, u64::MAX)
                .map_err(Error::Dma)?;
            // Check real continuous-coherence support before publishing an IOVA.
            self.slots.push(Slot {
                sensor,
                state: SensorState::Disabled,
                dma,
                published: false,
                pending: None,
                ever_published: false,
                retire_ready: false,
            });
            self.slots
                .last()
                .expect("inserted slot")
                .dma
                .read_coherent_u32(0)
                .map_err(Error::Dma)?;
        }
        if self.slots.is_empty() {
            return Err(Error::NoSensors);
        }
        self.registers.set_bus_master(true)?;
        for index in 0..self.slots.len() {
            self.command(index, true)?;
        }
        let discovery = self.registers.read32(P2C_DISCOVERY)?;
        if discovery == u32::MAX || (discovery >> 3) & 7 == 0 {
            return Err(Error::DiscoveryFailed(discovery));
        }
        self.clear_interrupt()?;
        self.state = State::Running;
        Ok(())
    }
    fn running(&self) -> Result<(), Error> {
        match self.state {
            State::Running => Ok(()),
            State::Faulted => Err(Error::NeedsReset),
            _ => Err(Error::NotReady),
        }
    }
    fn slot_index(&self, sensor: Sensor) -> Result<usize, Error> {
        self.slots
            .iter()
            .position(|slot| slot.sensor == sensor)
            .ok_or(Error::SensorAbsent(sensor))
    }
    pub fn get_input_report(
        &mut self,
        sensor: Sensor,
        report_id: u8,
    ) -> Result<InputReport, Error> {
        self.running()?;
        let expected = sensor.report_id().ok_or(Error::NoHidSchema(sensor))?;
        if report_id != expected {
            return Err(Error::ReportId {
                expected,
                actual: report_id,
            });
        }
        self.slot_index(sensor)?;
        let result = self.read_input(sensor).map(|mut report| {
            report.mark_poll_response();
            report
        });
        self.fault(result)
    }
    fn read_input(&mut self, sensor: Sensor) -> Result<InputReport, Error> {
        self.authority()?;
        let index = self.slot_index(sensor)?;
        if self.slots[index].state != SensorState::Enabled {
            return Err(Error::SensorDisabled(sensor));
        }
        let mut words = [0; 4];
        let range = match sensor {
            Sensor::Accelerometer | Sensor::Gyroscope => 0..3,
            Sensor::Magnetometer => 0..4,
            Sensor::AmbientColor => 1..4,
            _ => 0..0,
        };
        for word in range {
            words[word] = self.slots[index]
                .dma
                .read_coherent_u32(word * 4)
                .map_err(Error::Dma)?;
        }
        let light = if matches!(sensor, Sensor::AmbientLight | Sensor::AmbientColor) {
            self.registers.read32(C2P_LIGHT)?
        } else {
            0
        };
        let hpd = if sensor == Sensor::HumanPresence {
            self.registers.read32(C2P_PRESENCE)?
        } else {
            0
        };
        report::input(sensor, words, light, hpd)
    }
    pub fn get_feature_report(
        &mut self,
        sensor: Sensor,
        report_id: u8,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.running()?;
        self.slot_index(sensor)?;
        let expected = sensor.report_id().ok_or(Error::NoHidSchema(sensor))?;
        if report_id != expected {
            return Err(Error::ReportId {
                expected,
                actual: report_id,
            });
        }
        let result = self.authority();
        self.fault(result)?;
        let len = sensor.feature_report(output)?;
        output[4] = report::STATE_READY;
        output[5..9].copy_from_slice(&u32::from(PERIOD_MS).to_le_bytes());
        Ok(len)
    }
    pub fn set_report(
        &mut self,
        _sensor: Sensor,
        _report_id: u8,
        _bytes: &[u8],
    ) -> Result<(), Error> {
        Err(Error::UnsupportedSetReport)
    }
    /// Deliver the current observations once per enabled HID sensor. The caller
    /// schedules this at 200ms; repeated values are legitimate observations.
    pub fn poll(&mut self, sink: &mut dyn ReportSink) -> Result<usize, Error> {
        self.running()?;
        let mut count = 0;
        for sensor in SENSORS {
            if sensor.report_id().is_some()
                && self.sensor_state(sensor) == Some(SensorState::Enabled)
            {
                let result = self.read_input(sensor);
                let report = self.fault(result)?;
                sink.input(sensor, &report);
                count += 1;
            }
        }
        let result = self.clear_interrupt();
        self.fault(result)?;
        Ok(count)
    }
    /// Source suspend keeps HPD operation and its DMA lease; no report worker
    /// runs while suspended. Full stop below acknowledges HPD disable too.
    pub fn suspend(&mut self) -> Result<(), Error> {
        self.running()?;
        let result = (|| {
            for index in 0..self.slots.len() {
                if self.slots[index].sensor != Sensor::HumanPresence
                    && self.slots[index].state == SensorState::Enabled
                {
                    self.command(index, false)?;
                }
            }
            self.clear_interrupt()?;
            self.state = State::Suspended;
            Ok(())
        })();
        self.fault(result)
    }
    pub fn resume(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Suspended | State::Stopped) {
            return Err(if self.state == State::Faulted {
                Error::NeedsReset
            } else {
                Error::NotReady
            });
        }
        let result = (|| {
            self.authority()?;
            self.registers.set_bus_master(true)?;
            for index in 0..self.slots.len() {
                if self.slots[index].state == SensorState::Disabled {
                    self.command(index, true)?;
                }
            }
            self.clear_interrupt()?;
            self.state = State::Running;
            Ok(())
        })();
        self.fault(result)
    }
    /// Acknowledged per-sensor disable, including uncertain partial startup.
    /// A timeout never frees DMA or silently credits stop-all as completion.
    pub fn stop(&mut self) -> Result<(), Error> {
        if self.state == State::Shutdown {
            return Err(Error::NotReady);
        }
        let result = (|| {
            self.authority()?;
            for index in 0..self.slots.len() {
                if self.slots[index].published {
                    self.command(index, false)?;
                }
            }
            self.clear_interrupt()?;
            self.registers.set_bus_master(false)?;
            // SAFETY: every published sensor acknowledged disable, submissions
            // are serialized and stopped, and PCI mastering is off.
            // This same requester domain performs the platform drain;
            // neither sensor ACK nor PCI BM clear alone retires posted writes.
            if self
                .slots
                .iter()
                .any(|slot| slot.ever_published && !slot.retire_ready)
            {
                // SAFETY: per-sensor DMA sources and serialized submissions are
                // stopped above; this domain drains their posted writes.
                unsafe { self.domain.drain_posted_writes() }.map_err(Error::Dma)?;
            }
            for slot in &mut self.slots {
                slot.retire_ready = true;
            }
            // SAFETY: every published sensor acknowledged disable above,
            // PCI mastering is off and its domain's payload drain has
            // completed (or no IOVA was ever published).
            unsafe { self.registers.mark_quiescent() };
            self.state = State::Stopped;
            Ok(())
        })();
        self.fault(result)
    }
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.stop()?;
        for index in 0..self.slots.len() {
            if self.slots[index].dma.address() == Err(DmaError::Unmapped) {
                continue;
            }
            // SAFETY: each published sensor acknowledged disable, submissions
            // are serialized/stopped and PCI mastering is disabled/read back.
            let result = unsafe { self.slots[index].dma.unmap() }.map_err(Error::Dma);
            self.fault(result)?;
        }
        self.slots.clear();
        self.state = State::Shutdown;
        Ok(())
    }
    pub fn into_shutdown_resources(self) -> Result<(R, T), Self> {
        if self.state != State::Shutdown {
            return Err(self);
        }
        Ok((self.registers, self.timer))
    }
}
fn command_word(sensor: Sensor, enable: bool) -> u32 {
    let id = if enable { 1 } else { 2 };
    let period = if enable { u32::from(PERIOD_MS) } else { 0 };
    id | (1 << 4)
        | (16 << 8)
        | (u32::from(enable && sensor == Sensor::AmbientLight) << 15)
        | (u32::from(sensor as u8) << 16)
        | (period << 24)
}
#[cfg(test)]
mod tests;
