// SPDX-License-Identifier: GPL-2.0-or-later
//! SFHv2 inherited-engine containment under the original requester/root.
//! This observes vendor sensor ACKs only; it grants no root migration,
//! notification mode, IRQ/work completion, DMA allocation or resource release.
use super::{
    C2P_ADDRESS_HIGH, C2P_ADDRESS_LOW, C2P_COMMAND, P2C_ACS, P2C_INTERRUPT, P2C_INTERRUPT_ACK,
    P2C_RESPONSE, RESPONSE_INTERVAL_US, RESPONSE_TIMEOUT_US, Registers, SENSOR_DISABLED, SENSORS,
    Sensor, command_word,
};
use crate::bus::i2c::Timer;
pub mod native;

const KNOWN_MASK: u32 =
    (1 << 0) | (1 << 1) | (1 << 2) | (1 << 15) | (1 << 16) | (1 << 19) | (1 << 22);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Controller(super::Error),
    UnsupportedSensorMask(u32),
    OriginalNotificationOwnerUnavailable,
    Interrupted,
    Terminal,
}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Controller(e)
    }
}

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Controller(error) => error.fmt(f),
            Self::UnsupportedSensorMask(mask) => {
                write!(f, "it runs unknown sensors {mask:#x}")
            }
            Self::OriginalNotificationOwnerUnavailable => {
                f.write_str("nothing can take its notifications over from their original owner")
            }
            Self::Interrupted => f.write_str("its sensor stop was interrupted"),
            Self::Terminal => f.write_str("an earlier sensor stop failed, so it stays held"),
        }
    }
}

/// One observed sensor-stop set, not a configuration-only stopped claim.
pub struct Stopped {
    acs: u32,
}
impl Stopped {
    pub fn advertised_mask(&self) -> u32 {
        self.acs >> 4
    }
}
/// A one-shot attempt must remain with the real original graph. Failure or
/// caught callback unwind cannot replay a command or manufacture success.
pub struct StopAttempt {
    attempted: bool,
    error: Option<Error>,
}
impl Default for StopAttempt {
    fn default() -> Self {
        Self::new()
    }
}
impl StopAttempt {
    pub const fn new() -> Self {
        Self {
            attempted: false,
            error: None,
        }
    }
    pub fn stop(&mut self, r: &mut impl Registers, t: &impl Timer) -> Result<Stopped, Error> {
        if self.attempted {
            return Err(self.error.unwrap_or(Error::Terminal));
        }
        self.attempted = true;
        self.error = Some(Error::Interrupted);
        let result = stop(r, t);
        self.error = result.as_ref().err().copied();
        result
    }
}
fn response_matches(word: u32, sensor: Sensor) -> bool {
    word & 3 == 0
        && (word >> 4) & 15 == u32::from(SENSOR_DISABLED)
        && (word >> 16) & 63 == u32::from(sensor as u8)
}
fn authority(r: &mut impl Registers, acs: u32) -> Result<(), Error> {
    r.check_authority()?;
    if r.read32(P2C_ACS)? != acs {
        return Err(super::Error::PciAuthority.into());
    }
    Ok(())
}
fn deadline(t: &impl Timer, start: u64, sensor: Sensor, observed: u32) -> Result<(), Error> {
    if t.elapsed_us(start) >= RESPONSE_TIMEOUT_US {
        return Err(super::Error::Timeout {
            sensor,
            expected: SENSOR_DISABLED,
            observed,
        }
        .into());
    }
    Ok(())
}
fn wait(r: &mut impl Registers, t: &impl Timer, start: u64, sensor: Sensor) -> Result<(), Error> {
    loop {
        deadline(t, start, sensor, 0)?;
        let observed = r.read32(P2C_RESPONSE)?;
        deadline(t, start, sensor, observed)?;
        if observed == u32::MAX {
            return Err(super::Error::RegisterUnavailable(P2C_RESPONSE).into());
        }
        if response_matches(observed, sensor) {
            return Ok(());
        }
        let wait = t.start();
        while t.elapsed_us(wait) < RESPONSE_INTERVAL_US {
            t.relax();
            deadline(t, start, sensor, observed)?;
        }
    }
}
fn stop(r: &mut impl Registers, t: &impl Timer) -> Result<Stopped, Error> {
    t.check_duration(RESPONSE_TIMEOUT_US)
        .map_err(super::Error::Clock)?;
    r.check_authority()?;
    let acs = r.read32(P2C_ACS)?;
    if acs == u32::MAX {
        return Err(super::Error::RegisterUnavailable(P2C_ACS).into());
    }
    if acs & 15 != 2 {
        return Err(super::Error::UnsupportedDialect((acs & 15) as u8).into());
    }
    let mask = acs >> 4;
    if mask == 0 {
        return Err(super::Error::NoSensors.into());
    }
    if mask & !KNOWN_MASK != 0 {
        return Err(Error::UnsupportedSensorMask(mask & !KNOWN_MASK));
    }
    let baseline = r.read32(P2C_RESPONSE)?;
    if baseline == u32::MAX {
        return Err(super::Error::RegisterUnavailable(P2C_RESPONSE).into());
    }
    // There is no command sequence number in this dialect. When possible,
    // first stop a DIFFERENT advertised sensor from a stale disabled response;
    // every subsequent sensor then requires a fresh sensor-ID transition.
    // A single matching stale response is explicitly unprovable, not an ACK.
    let mut ordered = SENSORS;
    if let Some(first) = ordered.iter().position(|sensor| {
        mask & (1 << (*sensor as u8)) != 0 && !response_matches(baseline, *sensor)
    }) {
        ordered.swap(0, first);
    }
    for sensor in ordered {
        if mask & (1 << (sensor as u8)) == 0 {
            continue;
        }
        let start = t.start();
        authority(r, acs)?;
        let prior = r.read32(P2C_RESPONSE)?;
        deadline(t, start, sensor, prior)?;
        if prior == u32::MAX {
            return Err(super::Error::RegisterUnavailable(P2C_RESPONSE).into());
        }
        if response_matches(prior, sensor) {
            return Err(super::Error::StaleResponse {
                sensor,
                expected: SENSOR_DISABLED,
            }
            .into());
        }
        // Linux amd_stop_sensor_v2: address low then high (writeq source
        // order), then zero-period/intr-disabled DISABLE_SENSOR publication.
        // No inherited buffer is accessed or new IOVA published here.
        r.write32(C2P_ADDRESS_LOW, 0)?;
        deadline(t, start, sensor, prior)?;
        r.write32(C2P_ADDRESS_HIGH, 0)?;
        deadline(t, start, sensor, prior)?;
        r.write32(C2P_COMMAND, command_word(sensor, false))?;
        deadline(t, start, sensor, prior)?;
        wait(r, t, start, sensor)?;
        authority(r, acs)?;
    }
    let interrupt = r.read32(P2C_INTERRUPT)?;
    if interrupt == u32::MAX {
        return Err(super::Error::RegisterUnavailable(P2C_INTERRUPT).into());
    }
    if interrupt != 0 {
        r.write32(P2C_INTERRUPT, 0)?;
        r.write32(P2C_INTERRUPT_ACK, 15)?;
    }
    let interrupt = r.read32(P2C_INTERRUPT)?;
    if interrupt == u32::MAX {
        return Err(super::Error::RegisterUnavailable(P2C_INTERRUPT).into());
    }
    if interrupt != 0 {
        return Err(super::Error::RegisterRejected(P2C_INTERRUPT).into());
    }
    r.set_bus_master(false)?;
    // Do not call mark_quiescent or mint StoppedRequester here. Original-root
    // payload drainage and actual admitted notification/IRQ/work prerequisites
    // remain separate obligations while every inherited allocation stays kept.
    Ok(Stopped { acs })
}

#[cfg(test)]
mod tests;
