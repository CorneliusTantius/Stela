//! The one path a driver takes a PCI function from its last owner by: the
//! mount prepares the function with bus mastering sealed off, the driver
//! stops what that owner left running through the function's own registers,
//! the original DMA root is drained and the function gets its own DMA
//! domain. Each driver supplies only its vendor stop, as [`ColdStop`].
use super::{NativeServices, ServiceError, map};
use crate::block::BlockError;
use crate::bus::{
    mmio::owned::{self, Mapping},
    pci::{
        Address, Bar, ConfigSpace, Function,
        owned::OwnedConfig,
        regs,
        requester::{
            StoppedRequester,
            preparation::{self, Attachment},
        },
    },
};
use alloc::{boxed::Box, rc::Rc, sync::Arc};
use core::{any::Any, fmt, ptr::NonNull};

/// Why a function could not be taken over, apart from its driver's own stop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandOverError {
    /// The mount refused or lacks a service the hand-over needs.
    Service(ServiceError),
    /// The function's configuration or power state did not answer.
    Device(BlockError),
    /// The register BAR could not be mapped.
    Mapping(owned::Error),
    /// The function stopped answering: its command register reads all ones.
    Vanished,
    /// The driver's stop kept a reference to the register mapping.
    WindowKept,
    /// The stopped function could not be bound to its own DMA domain.
    Bind(preparation::Error),
}

impl fmt::Display for HandOverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service(error) => error.fmt(f),
            Self::Device(error) => error.fmt(f),
            Self::Mapping(error) => write!(f, "its registers could not be mapped ({error})"),
            Self::Vanished => f.write_str("it stopped answering on PCI"),
            Self::WindowKept => {
                f.write_str("its driver kept its registers after stopping it, so it stays held")
            }
            Self::Bind(error) => write!(f, "its DMA could not be isolated: {error}"),
        }
    }
}

impl From<ServiceError> for HandOverError {
    fn from(error: ServiceError) -> Self {
        Self::Service(error)
    }
}

impl From<BlockError> for HandOverError {
    fn from(error: BlockError) -> Self {
        Self::Device(error)
    }
}

impl From<crate::bus::pci::ConfigError> for HandOverError {
    fn from(error: crate::bus::pci::ConfigError) -> Self {
        Self::Device(BlockError::Config(error))
    }
}

/// A function's own register BAR while its driver stops it.
pub(in crate::probe) struct Window {
    pub base: NonNull<u8>,
    pub bytes: usize,
    /// Keeps the mapping; the stop must drop every clone before it returns.
    pub owner: Arc<dyn Any>,
}

/// A driver's stop of what the function's last owner left running.
pub(in crate::probe) trait ColdStop {
    type Error: From<HandOverError>;
    /// The memory BAR the stop and the driver reach the function through,
    /// or none for a function without one or whose driver maps its own.
    const BAR: Option<usize>;
    /// Refuse a function the driver does not run, before any device effect.
    fn admit(&mut self, _function: &mut Function<OwnedConfig>) -> Result<(), Self::Error> {
        Ok(())
    }
    /// Stop every engine the function's last owner may have left running,
    /// so none runs or restarts once bus mastering is allowed again.
    ///
    /// # Safety
    /// `window` is [`Self::BAR`]'s uncached mapping, the function's own and
    /// alive while its owner lives, with memory decoding on; bus mastering
    /// stays sealed off and nothing else reaches the function.
    unsafe fn stop(
        &mut self,
        function: &mut Function<OwnedConfig>,
        window: Option<Window>,
    ) -> Result<(), Self::Error>;
}

/// A function taken over: stopped, bound to its own DMA domain, and with
/// its register BAR still mapped.
pub(in crate::probe) struct HandedOver {
    pub requester: StoppedRequester,
    /// The function's own DMA domain, which outlives every mapping in it.
    pub attachment: Attachment,
    pub bars: [Option<Bar>; 6],
    /// [`ColdStop::BAR`]'s mapping and its window.
    pub registers: Option<(Mapping, NonNull<u8>, usize)>,
}

/// A failed hand-over's reason, with the owners the function may still
/// reach, which must outlive it.
pub(in crate::probe) type Refused<E> = (E, Option<Box<dyn Any>>);

/// Take the function at `address` over with `stop`.
///
/// The function is brought to D0, its BARs sized and `stop`'s BAR mapped;
/// INTx goes off and memory decoding on for that BAR, while bus mastering
/// stays sealed off. After `stop`, the original root is drained and the
/// function bound to its own domain. Every owner the function may still
/// reach is kept on failure.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`.
pub(in crate::probe) unsafe fn hand_over<S: ColdStop>(
    services: &dyn NativeServices,
    address: Address,
    stop: &mut S,
) -> Result<HandedOver, Refused<S::Error>> {
    let failed = |error: HandOverError, owner: Box<dyn Any>| (S::Error::from(error), Some(owner));
    let minimum: Rc<dyn crate::bus::pci::power::Timer> = services
        .minimum_delay()
        .map_err(|error| (HandOverError::from(error).into(), None))?;
    let mut requester = services
        .prepare_requester(address)
        .map_err(|error| (HandOverError::from(error).into(), None))?;
    if let Err(error) = stop.admit(requester.function_mut()) {
        return Err((error, Some(Box::new(requester))));
    }
    if let Err(error) = requester.function_mut().power_up(minimum.as_ref()) {
        return Err(failed(error.into(), Box::new(requester)));
    }
    let bars = match requester.function_mut().bars() {
        Ok(bars) => bars,
        Err(error) => return Err(failed(error.into(), Box::new(requester))),
    };
    let mut registers = None;
    if let Some(index) = S::BAR {
        let mapping = match map(services, address, &bars, index) {
            Ok(mapping) => mapping,
            Err(error) => return Err(failed(error.into(), Box::new(requester))),
        };
        let window = mapping
            .bytes()
            .and_then(|bytes| Ok((mapping.address(0, bytes)?, bytes)));
        match window {
            Ok((base, bytes)) => registers = Some((mapping, base, bytes)),
            Err(error) => {
                return Err(failed(
                    HandOverError::Mapping(error),
                    Box::new((requester, mapping)),
                ));
            }
        }
    }
    // INTx off, and memory decoding on for the stop's BAR; the preparation's
    // seal keeps bus mastering off.
    let decode = if registers.is_some() {
        regs::COMMAND_MEMORY
    } else {
        0
    };
    let decoded = (|| -> Result<(), HandOverError> {
        let config = requester.function_mut().config();
        let command = config.read16(regs::COMMAND)?;
        if command == u16::MAX {
            return Err(HandOverError::Vanished);
        }
        config.write16(regs::COMMAND, command | decode | regs::COMMAND_INTX_DISABLE)?;
        Ok(())
    })();
    if let Err(error) = decoded {
        return Err(failed(error, Box::new((requester, registers))));
    }
    let (window, registers) = match registers {
        Some((mapping, base, bytes)) => {
            let mapping = Arc::new(mapping);
            let window = Window {
                base,
                bytes,
                owner: mapping.clone(),
            };
            (Some(window), Some((mapping, base, bytes)))
        }
        None => (None, None),
    };
    // SAFETY: `window` is the stop's BAR, mapped uncached and kept by its
    // owner, with memory decoding on; the preparation seals bus mastering
    // off and excludes every other user.
    let stopped = unsafe { stop.stop(requester.function_mut(), window) };
    let registers = match registers.map(|(mapping, base, bytes)| {
        Arc::try_unwrap(mapping).map(|mapping| (mapping, base, bytes))
    }) {
        None => None,
        Some(Ok(registers)) => Some(registers),
        Some(Err(kept)) => {
            let error = match stopped {
                Err(error) => error,
                Ok(()) => HandOverError::WindowKept.into(),
            };
            return Err((error, Some(Box::new((requester, kept)))));
        }
    };
    if let Err(error) = stopped {
        return Err((error, Some(Box::new((requester, registers)))));
    }
    // SAFETY: the driver's stop acknowledged every engine of the function
    // stopped without restart, with bus mastering sealed off; no Stela IRQ
    // or work user exists, and the register BAR stays mapped beside the
    // receipt.
    let receipt = unsafe { requester.acknowledge_quiescence() };
    match receipt.finalize() {
        Ok(bound) => Ok(HandedOver {
            requester: bound.requester,
            attachment: bound.attachment,
            bars,
            registers,
        }),
        Err(failure) => {
            let error = HandOverError::Bind(failure.error);
            Err(failed(error, Box::new((failure, registers))))
        }
    }
}

#[cfg(test)]
pub(super) mod tests;
