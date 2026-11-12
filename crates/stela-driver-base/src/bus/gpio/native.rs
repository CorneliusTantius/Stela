// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Stela contributors
//! Native GPIO suppliers joined to firmware/resource reservations.
//!
//! This adapter is ordinary process/deferred GPIO I/O. It exposes no parent
//! IRQ, wake, named pin mux or system-sleep capability. The ACPICA binding owns
//! serialization and keeps the namespace/region-handler lifecycle.
use super::{amd, intel};
use crate::bus::mmio::owned::{Authority, CacheAttribute, Mapping, Protection};
use crate::platform::acpi::{self, Value, resources};
use alloc::{alloc::alloc, boxed::Box, string::String, vec::Vec};
use core::{alloc::Layout, fmt::Write};
use resources::gpio::{Direction, LinePolicy, NativeController, sealed};
use resources::{DeviceResources, MemoryBroker, MemoryReservation, Resource, Space};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Firmware(resources::Error),
    Acpi(acpi::Error),
    Mapping(crate::bus::mmio::owned::Error),
    Intel(intel::Error),
    Amd(amd::Error),
    Unsupported,
    MissingResource,
    Allocation,
    Busy,
    Retired,
}
impl From<resources::Error> for Error {
    fn from(error: resources::Error) -> Self {
        Self::Firmware(error)
    }
}

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Firmware(error) => return error.fmt(f),
            Self::Acpi(error) => return error.fmt(f),
            Self::Mapping(error) => return error.fmt(f),
            Self::Intel(error) => return error.fmt(f),
            Self::Amd(error) => return error.fmt(f),
            Self::Unsupported => "this GPIO controller is not supported",
            Self::MissingResource => "its firmware description lacks a register window",
            Self::Allocation => "memory for it ran out",
            Self::Busy => "its pads are still in use",
            Self::Retired => "it is retired",
        })
    }
}

enum Engine {
    Intel(intel::Controller<intel::NativeRegisters>),
    Amd(Box<amd::Controller<amd::NativeRegisters>>),
}

/// Native controller backend, constructed only by matching live ACPICA identity,
/// current resources and reservations from the post-EBS root broker.
/// Its reservations remain alive through successful restoration and unmapping.
pub struct Device {
    engine: Engine,
    reservations: Vec<MemoryReservation>,
    path: String,
    retired: bool,
    first_error: Option<Error>,
}
impl Device {
    /// Attach one firmware controller. `expected_hid` selects the driver
    /// table only after ACPICA verifies it against this original handle;
    /// a supplied string cannot substitute for physical/native resource ownership.
    pub fn attach(
        device: &DeviceResources<'_>,
        expected_hid: &str,
        broker: &MemoryBroker,
        authority: &Authority,
    ) -> Result<Self, Error> {
        Self::attach_with(
            device,
            expected_hid,
            &|device, ordinal| broker.reserve(device, ordinal),
            authority,
        )
    }
    /// [`Self::attach`] with `reserve` admitting each memory resource, as a
    /// mount's `NativeServices::acpi_memory` reserves it from its broker.
    pub fn attach_with(
        device: &DeviceResources<'_>,
        expected_hid: &str,
        reserve: &dyn Fn(
            &DeviceResources<'_>,
            usize,
        ) -> Result<MemoryReservation, resources::Error>,
        authority: &Authority,
    ) -> Result<Self, Error> {
        device.revalidate()?;
        if !device.matches_hid(expected_hid)? {
            return Err(Error::Unsupported);
        }
        let mut path = String::new();
        path.try_reserve_exact(device.path().len())
            .map_err(|_| Error::Allocation)?;
        path.push_str(device.path());
        let mut memory = Vec::new();
        memory
            .try_reserve_exact(device.descriptors().len())
            .map_err(|_| Error::Allocation)?;
        memory.extend(device.descriptors().iter().filter(|descriptor| matches!(&descriptor.resource, Resource::Address(address) if address.space == Space::Memory)).map(|descriptor| descriptor.ordinal));
        if let Some(profile) = amd::Profile::from_hid(expected_hid) {
            let mut reservations = Vec::new();
            reservations
                .try_reserve_exact(1)
                .map_err(|_| Error::Allocation)?;
            let ordinal = *memory.first().ok_or(Error::MissingResource)?;
            let reservation = reserve(device, ordinal)?;
            let mapping = map(authority, &reservation)?;
            // The original ordinary AMD GPIO path has no gpio_request_enable
            // pinmux hook. Optional named IOMUX functions are not advertised by
            // this backend and no resource index or GPIO function is guessed.
            let registers =
                amd::NativeRegisters::from_owned_mappings(mapping, None).map_err(Error::Amd)?;
            let controller =
                amd::Controller::new(registers, profile, [0; 3]).map_err(Error::Amd)?;
            reservations.push(reservation);
            device.revalidate()?;
            if !device.matches_hid(expected_hid)? {
                return Err(Error::Unsupported);
            }
            return Ok(Self {
                engine: Engine::Amd(box_amd(controller)?),
                reservations,
                path,
                retired: false,
                first_error: None,
            });
        }
        let profile = if let Some(profile) = intel::Profile::from_acpi(expected_hid, None) {
            profile
        } else {
            let uid = match device
                .handle()
                .evaluate(Some("_UID"), &[])
                .map_err(Error::Acpi)?
            {
                Some(Value::String(uid)) => uid,
                Some(Value::Integer(uid)) => {
                    let mut text = String::new();
                    text.try_reserve_exact(20).map_err(|_| Error::Allocation)?;
                    write!(&mut text, "{uid}").map_err(|_| Error::Allocation)?;
                    text.into_bytes()
                }
                _ => return Err(Error::Unsupported),
            };
            let uid = core::str::from_utf8(&uid).map_err(|_| Error::Unsupported)?;
            intel::Profile::from_acpi(expected_hid, Some(uid)).ok_or(Error::Unsupported)?
        };
        let mut reservations = Vec::new();
        let mut windows = Vec::new();
        reservations
            .try_reserve_exact(profile.resource_bars().len())
            .map_err(|_| Error::Allocation)?;
        windows
            .try_reserve_exact(profile.resource_bars().len())
            .map_err(|_| Error::Allocation)?;
        for bar in profile.resource_bars() {
            let ordinal = *memory.get(usize::from(bar)).ok_or(Error::MissingResource)?;
            let reservation = reserve(device, ordinal)?;
            windows.push((bar, map(authority, &reservation)?));
            reservations.push(reservation);
        }
        let registers =
            intel::NativeRegisters::from_owned_mappings(windows).map_err(Error::Intel)?;
        let controller = intel::Controller::new(registers, profile, &[]).map_err(Error::Intel)?;
        device.revalidate()?;
        if !device.matches_hid(expected_hid)? {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            engine: Engine::Intel(controller),
            reservations,
            path,
            retired: false,
            first_error: None,
        })
    }
    pub fn first_error(&self) -> Option<&Error> {
        self.first_error.as_ref()
    }
    /// Mask `pin`'s interrupt at the controller and acknowledge any status
    /// it latched, so the line raises no CPU interrupt while a driver samples
    /// its level.
    pub fn mask_interrupt(&mut self, pin: u16) -> Result<(), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        match &mut self.engine {
            Engine::Intel(controller) => {
                let pad = controller
                    .profile()
                    .gpio_to_pad(pin)
                    .ok_or(Error::Intel(intel::Error::InvalidPad))?;
                controller.interrupt_mask(pad, true).map_err(Error::Intel)
            }
            Engine::Amd(controller) => {
                let pad = u8::try_from(pin)
                    .map_err(|_| Error::Amd(amd::Error::InvalidPad))
                    .and_then(|number| amd::Pad::new(number).map_err(Error::Amd))?;
                controller.interrupt_mask(pad).map_err(Error::Amd)
            }
        }
    }
    fn report(&mut self, error: Error) -> acpi::Error {
        let status = match &error {
            Error::Allocation | Error::Intel(intel::Error::Allocation) => acpi::Error(4),
            Error::Intel(
                intel::Error::InvalidPad
                | intel::Error::UnownedPad
                | intel::Error::InvalidPull
                | intel::Error::InvalidDebounce,
            )
            | Error::Amd(
                amd::Error::InvalidPad
                | amd::Error::UnownedPad
                | amd::Error::InvalidMux
                | amd::Error::InvalidDebounce,
            ) => acpi::BAD_PARAMETER,
            Error::Unsupported
            | Error::Busy
            | Error::Retired
            | Error::Intel(intel::Error::Unsupported) => acpi::SUPPORT,
            _ => acpi::Error(1),
        };
        self.first_error.get_or_insert(error);
        status
    }
}

fn box_amd(
    value: amd::Controller<amd::NativeRegisters>,
) -> Result<Box<amd::Controller<amd::NativeRegisters>>, Error> {
    let layout = Layout::new::<amd::Controller<amd::NativeRegisters>>();
    // SAFETY: nonzero controller layout; the native allocator returns
    // exclusive storage with the requested size/alignment or a null failure.
    let pointer = unsafe { alloc(layout) }.cast::<amd::Controller<amd::NativeRegisters>>();
    if pointer.is_null() {
        return Err(Error::Allocation);
    }
    // SAFETY: fresh exact-layout allocation; initialize once before Box takes
    // ownership and eventually deallocates using that same native layout.
    unsafe {
        pointer.write(value);
        Ok(Box::from_raw(pointer))
    }
}

fn map(authority: &Authority, reservation: &MemoryReservation) -> Result<Mapping, Error> {
    let logical = reservation.physical_span();
    let physical = reservation.resource().physical_span();
    let offset = logical
        .start()
        .checked_sub(physical.start())
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(Error::MissingResource)?;
    let bytes = usize::try_from(logical.bytes()).map_err(|_| Error::MissingResource)?;
    authority
        .map(
            reservation.resource().clone(),
            offset,
            bytes,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .map_err(Error::Mapping)
}

impl sealed::Sealed for Device {}
impl NativeController for Device {
    fn device_path(&self) -> &str {
        &self.path
    }
    fn matches_device(&self, device: &DeviceResources<'_>) -> Result<(), resources::Error> {
        if self.retired {
            return Err(resources::Error::Unassigned);
        }
        for reservation in &self.reservations {
            reservation.matches(device)?;
        }
        Ok(())
    }
    fn request(&mut self, pin: u16, policy: LinePolicy) -> Result<(), acpi::Error> {
        if self.retired {
            return Err(self.report(Error::Retired));
        }
        let result = match &mut self.engine {
            Engine::Intel(controller) => (|| {
                let pad = controller
                    .profile()
                    .gpio_to_pad(pin)
                    .ok_or(Error::Intel(intel::Error::InvalidPad))?;
                controller.capture(pad).map_err(Error::Intel)?;
                controller
                    .claim_debounce(pad, policy.debounce_us)
                    .map_err(Error::Intel)?;
                controller.request_gpio(pad).map_err(Error::Intel)?;
                match policy.direction {
                    Direction::Input => controller.direction_input(pad),
                    Direction::Output(value) => controller.direction_output(pad, value),
                    Direction::Preserve => Ok(()),
                }
                .map_err(Error::Intel)
            })(),
            Engine::Amd(controller) => (|| {
                let pad = amd::Pad::new(
                    u8::try_from(pin).map_err(|_| Error::Amd(amd::Error::InvalidPad))?,
                )
                .map_err(Error::Amd)?;
                controller.capture(pad).map_err(Error::Amd)?;
                controller
                    .claim_debounce(pad, policy.debounce_us)
                    .map_err(Error::Amd)?;
                match policy.direction {
                    Direction::Input => controller.direction_input(pad),
                    Direction::Output(value) => controller.direction_output(pad, value),
                    Direction::Preserve => Ok(()),
                }
                .map_err(Error::Amd)
            })(),
        };
        result.map_err(|error| self.report(error))
    }
    fn read(&mut self, pin: u16) -> Result<bool, acpi::Error> {
        if self.retired {
            return Err(self.report(Error::Retired));
        }
        let result = match &mut self.engine {
            Engine::Intel(controller) => controller
                .profile()
                .gpio_to_pad(pin)
                .ok_or(Error::Intel(intel::Error::InvalidPad))
                .and_then(|pad| controller.value(pad).map_err(Error::Intel)),
            Engine::Amd(controller) => u8::try_from(pin)
                .map_err(|_| Error::Amd(amd::Error::InvalidPad))
                .and_then(|number| amd::Pad::new(number).map_err(Error::Amd))
                .and_then(|pad| controller.input(pad).map_err(Error::Amd)),
        };
        result.map_err(|error| self.report(error))
    }
    fn write(&mut self, pin: u16, value: bool) -> Result<(), acpi::Error> {
        if self.retired {
            return Err(self.report(Error::Retired));
        }
        let result = match &mut self.engine {
            Engine::Intel(controller) => controller
                .profile()
                .gpio_to_pad(pin)
                .ok_or(Error::Intel(intel::Error::InvalidPad))
                .and_then(|pad| controller.write_latch(pad, value).map_err(Error::Intel)),
            Engine::Amd(controller) => u8::try_from(pin)
                .map_err(|_| Error::Amd(amd::Error::InvalidPad))
                .and_then(|number| amd::Pad::new(number).map_err(Error::Amd))
                .and_then(|pad| controller.write_latch(pad, value).map_err(Error::Amd)),
        };
        result.map_err(|error| self.report(error))
    }
    fn release(&mut self, pin: u16) -> Result<(), acpi::Error> {
        if self.retired {
            return Ok(());
        }
        let result = match &mut self.engine {
            Engine::Intel(controller) => match controller.profile().gpio_to_pad(pin) {
                Some(pad) if controller.is_claimed(pad) => {
                    controller.release_pad(pad).map_err(Error::Intel)
                }
                _ => Ok(()), // No capture means request issued no pad writes.
            },
            Engine::Amd(controller) => match u8::try_from(pin)
                .ok()
                .and_then(|number| amd::Pad::new(number).ok())
            {
                Some(pad) if controller.is_claimed(pad) => {
                    controller.release_pad(pad).map_err(Error::Amd)
                }
                _ => Ok(()),
            },
        };
        result.map_err(|error| self.report(error))
    }
    fn shutdown(&mut self) -> Result<(), acpi::Error> {
        if self.retired {
            return Ok(());
        }
        let result = match &mut self.engine {
            Engine::Intel(controller) if !controller.has_claims() => {
                controller.retire().map_err(Error::Intel)
            }
            Engine::Amd(controller) if !controller.has_claims() => {
                controller.retire().map_err(Error::Amd)
            }
            _ => Err(Error::Busy),
        };
        match result {
            Ok(()) => {
                self.retired = true;
                // Original controller restoration and all mapping retirements
                // acknowledged. Only metadata/OSL storage remains in the core;
                // the broker can now admit a fresh physical owner.
                self.reservations.clear();
                Ok(())
            }
            Err(error) => Err(self.report(error)),
        }
    }
}
