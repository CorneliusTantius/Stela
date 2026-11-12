// SPDX-License-Identifier: GPL-2.0-only
//! Native host audio primitives. The HDA backend provides command transport,
//! codec graphs and cyclic PCM DMA; AMD ACP profiles supply direct PDM capture.
#![no_std]
#[cfg_attr(test, macro_use)]
extern crate alloc;

use stela_driver_base::bus;
use stela_driver_core::firmware;

pub mod acp63;
pub mod acp6x;
pub mod acp70;
pub mod acp_i2s;
mod acp_pdm;
pub mod hda;
pub mod intel_dsp;
pub mod renoir;
mod timing;
pub use timing::{Timer, Timing};

/// A failed ownership transition returns its exact cause and original owner.
pub struct Refusal<T, E> {
    pub error: E,
    pub owner: T,
}
impl<T, E: core::fmt::Debug> core::fmt::Debug for Refusal<T, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Refusal")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Playback,
    Capture,
}

/// Interleaved little-endian integer PCM. 8-bit samples are unsigned; 20/24-bit
/// samples occupy 32-bit containers, as in Linux's HDA PCM interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcmFormat {
    pub rate: u32,
    pub bits: u8,
    pub channels: u8,
}

impl PcmFormat {
    pub fn frame_bytes(self) -> Result<usize, Error> {
        self.encode()?;
        Ok(usize::from(self.channels) * usize::from(self.bits.div_ceil(8).next_power_of_two()))
    }

    /// One nonempty HDA link packet contains MULT PCM frames. Fractional rates
    /// change packet cadence, not packet size (32k sends two blocks every third
    /// link frame; 176.4k sends four blocks in each nonempty cadence frame).
    pub fn packet_bytes(self) -> Result<usize, Error> {
        let multiplier = usize::from(((self.encode()? >> 11) & 7) + 1);
        Ok(self.frame_bytes()? * multiplier)
    }

    /// SDxFMT / converter format encoding. Only standard discrete PCM rates
    /// are accepted; arbitrary clock ratios and non-PCM formats are explicit.
    pub fn encode(self) -> Result<u16, Error> {
        let rate = match self.rate {
            8_000 => 5 << 8,
            11_025 => (1 << 14) | (3 << 8),
            16_000 => 2 << 8,
            22_050 => (1 << 14) | (1 << 8),
            32_000 => (1 << 11) | (2 << 8),
            44_100 => 1 << 14,
            48_000 => 0,
            88_200 => (1 << 14) | (1 << 11),
            96_000 => 1 << 11,
            176_400 => (1 << 14) | (3 << 11),
            192_000 => 3 << 11,
            _ => return Err(Error::InvalidFormat),
        };
        let bits = match self.bits {
            8 => 0,
            16 => 1,
            20 => 2,
            24 => 3,
            32 => 4,
            _ => return Err(Error::InvalidFormat),
        };
        if !(1..=16).contains(&self.channels) {
            return Err(Error::InvalidFormat);
        }
        Ok(rate | (bits << 4) | u16::from(self.channels - 1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    LinkResetEnter,
    LinkResetExit,
    CommandStop,
    CommandStart,
    CorbResetEnter,
    CorbResetExit,
    RirbReset,
    Verb,
    StreamStop,
    StreamResetEnter,
    StreamResetExit,
    StreamStart,
    CodecPower,
    DisplayAudio,
    CodecDepop,
    CodecHeadsetDetection,
    LinkPowerDown,
    LinkPowerUp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MinimumDelay(bus::pci::power::Error),
    Interrupted,
    Config(crate::bus::pci::ConfigError),
    PciCapability(crate::bus::pci::CapabilityError),
    InvalidConfiguration,
    ControllerIdentitiesExhausted,
    PciResetControl {
        offset: u16,
    },
    RegisterUnavailable {
        offset: usize,
    },
    UnsupportedVersion {
        major: u8,
        minor: u8,
    },
    UnsupportedRingSize,
    InvalidExtendedCapability {
        offset: usize,
    },
    UnsupportedExtendedCapability {
        id: u16,
        version: u8,
    },
    ProcessingOwned {
        offset: usize,
    },
    UnsupportedLink {
        offset: usize,
    },
    LinkPowerUncertain {
        offset: usize,
    },
    LinkClockRejected {
        offset: usize,
    },
    UnsupportedTopology,
    InvalidVerb,
    CodecAbsent,
    InvalidCodecGraph,
    InvalidHdmiPort,
    InvalidEld,
    InvalidChannelMap,
    SinkUnavailable,
    SinkChanged,
    PlaybackUnderrun,
    InvalidConnectionList,
    InvalidFormat,
    InvalidBuffer,
    LinkBandwidth {
        required_words: u16,
        available_words: u16,
    },
    NoDmaMemory,
    DmaAddress,
    NoStream,
    StreamsAllocated,
    NeedsDiscovery,
    InvalidStream,
    StreamRunning,
    StreamStopped,
    Timeout(Phase),
    CorbMemory,
    InvalidRingPointer,
    StreamDma {
        status: u8,
    },
    InvalidPosition(u32),
    ConverterRejected,
    CoefficientRejected {
        node: u8,
        index: u16,
    },
    InvalidPinControl,
    InvalidJackNotification,
    JackNotificationTagsExhausted,
    RouteRejected,
    RouteInUse,
    /// A command timeout makes later replies ambiguous. A full controller
    /// reset/platform reinitialization is required before further commands.
    NeedsReset,
    Shutdown,
}

/// What the controller was waiting for, as words.
impl core::fmt::Display for Phase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::LinkResetEnter => "the link to enter reset",
            Self::LinkResetExit => "the link to leave reset",
            Self::CommandStop => "the command rings to stop",
            Self::CommandStart => "the command rings to start",
            Self::CorbResetEnter => "the command ring to enter reset",
            Self::CorbResetExit => "the command ring to leave reset",
            Self::RirbReset => "the response ring to reset",
            Self::Verb => "a codec reply",
            Self::StreamStop => "a stream to stop",
            Self::StreamResetEnter => "a stream to enter reset",
            Self::StreamResetExit => "a stream to leave reset",
            Self::StreamStart => "a stream to start",
            Self::CodecPower => "a codec power change",
            Self::DisplayAudio => "the display audio sink",
            Self::CodecDepop => "the codec's depop sequence",
            Self::CodecHeadsetDetection => "headset detection",
            Self::LinkPowerDown => "the link to power down",
            Self::LinkPowerUp => "the link to power up",
        })
    }
}

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::MinimumDelay(error) => return error.fmt(f),
            Self::Interrupted => "an earlier operation was interrupted",
            Self::Config(error) => return error.fmt(f),
            Self::PciCapability(error) => return error.fmt(f),
            Self::InvalidConfiguration => "its configuration is invalid",
            Self::ControllerIdentitiesExhausted => "no controller number is left",
            Self::PciResetControl { offset } => {
                return write!(
                    f,
                    "its PCI reset control {offset:#x} did not take the change"
                );
            }
            Self::RegisterUnavailable { offset } => {
                return write!(f, "its register {offset:#x} reads all ones");
            }
            Self::UnsupportedVersion { major, minor } => {
                return write!(f, "its HD Audio version {major}.{minor} is unsupported");
            }
            Self::UnsupportedRingSize => "its command ring sizes are unsupported",
            Self::InvalidExtendedCapability { offset } => {
                return write!(f, "its extended capability at {offset:#x} is malformed");
            }
            Self::UnsupportedExtendedCapability { id, version } => {
                return write!(
                    f,
                    "its extended capability {id:#x} version {version} is unsupported"
                );
            }
            Self::ProcessingOwned { offset } => {
                return write!(
                    f,
                    "its processing control at {offset:#x} is still owned by another engine"
                );
            }
            Self::UnsupportedLink { offset } => {
                return write!(f, "its link at {offset:#x} is unsupported");
            }
            Self::LinkPowerUncertain { offset } => {
                return write!(f, "its link power at {offset:#x} is uncertain");
            }
            Self::LinkClockRejected { offset } => {
                return write!(f, "its link at {offset:#x} did not take the clock choice");
            }
            Self::UnsupportedTopology => "its codec layout is unsupported",
            Self::InvalidVerb => "a codec command is invalid",
            Self::CodecAbsent => "no codec answered",
            Self::InvalidCodecGraph => "its codec layout is malformed",
            Self::InvalidHdmiPort => "the HDMI port is invalid",
            Self::InvalidEld => "the display's audio description (ELD) is malformed",
            Self::InvalidChannelMap => "the channel map is invalid",
            Self::SinkUnavailable => "no display audio sink is connected",
            Self::SinkChanged => "the display audio sink changed",
            Self::PlaybackUnderrun => "playback ran out of data",
            Self::InvalidConnectionList => "a codec connection list is malformed",
            Self::InvalidFormat => "the audio format is invalid",
            Self::InvalidBuffer => "the audio buffer is invalid",
            Self::LinkBandwidth {
                required_words,
                available_words,
            } => {
                return write!(
                    f,
                    "the link has room for {available_words} words per frame, not {required_words}"
                );
            }
            Self::NoDmaMemory => "DMA memory ran out",
            Self::DmaAddress => "the DMA memory lies above what it can address",
            Self::NoStream => "no stream is free",
            Self::StreamsAllocated => "its streams are still in use",
            Self::NeedsDiscovery => "its codecs are not discovered yet",
            Self::InvalidStream => "the stream is invalid",
            Self::StreamRunning => "the stream is still running",
            Self::StreamStopped => "the stream is stopped",
            Self::Timeout(phase) => return write!(f, "it timed out waiting for {phase}"),
            Self::CorbMemory => "its command ring reported a memory error",
            Self::InvalidRingPointer => "a ring pointer is out of range",
            Self::StreamDma { status } => {
                return write!(f, "a stream's DMA failed (status {status:#x})");
            }
            Self::InvalidPosition(position) => {
                return write!(f, "the stream position {position:#x} is out of range");
            }
            Self::ConverterRejected => "a codec converter did not take its format",
            Self::CoefficientRejected { node, index } => {
                return write!(
                    f,
                    "codec node {node:#x} did not take coefficient {index:#x}"
                );
            }
            Self::InvalidPinControl => "a pin control value is invalid",
            Self::InvalidJackNotification => "the jack notification is invalid",
            Self::JackNotificationTagsExhausted => "no jack notification tag is left",
            Self::RouteRejected => "the codec did not take the route",
            Self::RouteInUse => "the route is in use",
            Self::NeedsReset => "it needs a reset after a command timed out",
            Self::Shutdown => "it is shut down",
        })
    }
}

impl From<crate::bus::pci::ConfigError> for Error {
    fn from(error: crate::bus::pci::ConfigError) -> Self {
        Self::Config(error)
    }
}
impl From<crate::bus::pci::CapabilityError> for Error {
    fn from(error: crate::bus::pci::CapabilityError) -> Self {
        Self::PciCapability(error)
    }
}

#[cfg(test)]
mod display_tests {
    use super::{
        Error, Phase,
        hda::pci::{AttachError, CapabilityRefusal},
    };

    #[test]
    fn audio_failures_read_as_words() {
        let texts = [
            format!("{}", Error::Timeout(Phase::CorbResetExit)),
            format!("{}", Error::RegisterUnavailable { offset: 0x68 }),
            format!(
                "{}",
                Error::LinkBandwidth {
                    required_words: 12,
                    available_words: 8,
                }
            ),
            format!(
                "{}",
                AttachError::InvalidCapabilities(CapabilityRefusal::ControlOverlap {
                    control: 0x44,
                    offset: 0x40,
                    id: 0x09,
                })
            ),
            format!("{}", AttachError::MmioPreflight(Error::CodecAbsent)),
            format!(
                "{}",
                AttachError::InvalidCapabilities(CapabilityRefusal::PcieOwnerMissing {
                    found: None
                })
            ),
        ];
        for text in texts {
            assert!(
                !text.contains('{') && !text.contains("::") && !text.contains("Error"),
                "{text}"
            );
        }
        assert_eq!(
            format!("{}", Error::Timeout(Phase::Verb)),
            "it timed out waiting for a codec reply"
        );
    }
}
