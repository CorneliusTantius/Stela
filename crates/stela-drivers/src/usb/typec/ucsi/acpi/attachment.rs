// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! PNP0CA0 attachment to the native ACPICA/SCI provider.
//!
//! Discovery is safe only under a hardware Session. Mapping allocation
//! and dependency installation remain the native platform's permissions. Bind
//! consumes their leases; start performs real PPM reset/discovery. A failed start
//! keeps those leases for explicit recovery. No synthetic notifications or
//! connector observations are generated here.

use super::super::{
    Command, Completion, ConnectorSnapshot, Controller, Error as UcsiError, Timer, TransportError,
};
use super::{
    DSM_UUID, Dsm, Mailbox,
    resources::{MemoryResource, ResourceError, mailbox_resource},
};
use crate::platform::acpi::{self, Handle, Notification, Session, Value};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

/// A real owned coherent write-back CPU mapping of the device's firmware RAM.
/// This is not permission to allocate/free the mailbox RAM, which remains owned
/// by firmware even after the driver's CPU mapping is retired.
///
/// # Safety
/// Implementors must own a mapping lease of the returned physical range,
/// keep its aligned CPU range stable, writable and coherent for their lifetime,
/// and exclude aliases accessible through Rust references. Firmware may publish
/// updates concurrently according to UCSI. Drop must retire only this CPU mapping
/// after users stop; never free or repurpose the underlying firmware RAM.
pub unsafe trait Mapping {
    fn resource(&self) -> MemoryResource;
    fn base(&self) -> NonNull<u8>;
}

/// Native dependency owner kept while UCSI may execute firmware methods.
///
/// # Safety
/// The returned handle must identify the `_DEP` service whose installed
/// native EC/GPIO/serial/other handlers this lease owns. Those handlers, IRQs,
/// region mappings and work execution must remain operational until drop. A
/// handle, `_STA` result or boolean assertion alone is not an implementation.
pub unsafe trait Dependency<'a> {
    fn handle(&self) -> Handle<'a>;
}

// SAFETY: Box keeps the real dependency owner and forwards its exact handle.
unsafe impl<'a, D: Dependency<'a> + ?Sized> Dependency<'a> for Box<D> {
    fn handle(&self) -> Handle<'a> {
        (**self).handle()
    }
}

// SAFETY: the receipt pins the installed EC's operation-region handler and
// its supplier admission, which stay operational while any receipt is kept.
unsafe impl<'a> Dependency<'a> for crate::platform::ec::capability::Installed<'a> {
    fn handle(&self) -> Handle<'a> {
        crate::platform::ec::capability::Installed::handle(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Acpi(acpi::Error),
    Ucsi(UcsiError),
    Resources(ResourceError),
    HardwareInactive,
    DeviceUnavailable(u64),
    InvalidObject(&'static str),
    DependencyUnavailable,
    MappingMismatch,
    ResourcesChanged,
    Inactive,
    NotificationRemovalUncertain(acpi::Error),
}
impl From<acpi::Error> for Error {
    fn from(value: acpi::Error) -> Self {
        Self::Acpi(value)
    }
}

/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Acpi(error) => return error.fmt(f),
            Self::Ucsi(error) => return error.fmt(f),
            Self::Resources(error) => return error.fmt(f),
            Self::HardwareInactive => "the ACPI hardware session is not active",
            Self::DeviceUnavailable(status) => {
                return write!(
                    f,
                    "the device is not present and working (_STA {status:#x})"
                );
            }
            Self::InvalidObject(name) => {
                return write!(f, "the firmware object {name} has an unexpected form");
            }
            Self::DependencyUnavailable => "a device it depends on is not ready",
            Self::MappingMismatch => "its mailbox mapping does not match its firmware resource",
            Self::ResourcesChanged => "its firmware resources changed",
            Self::Inactive => "it is not running",
            Self::NotificationRemovalUncertain(error) => {
                return write!(
                    f,
                    "its notification handler may still be installed: {error}"
                );
            }
        })
    }
}
impl From<UcsiError> for Error {
    fn from(value: UcsiError) -> Self {
        Self::Ucsi(value)
    }
}

pub struct Device<'a> {
    handle: Handle<'a>,
    resource: MemoryResource,
    dependencies: Vec<Handle<'a>>,
}
impl<'a> Device<'a> {
    pub fn handle(&self) -> Handle<'a> {
        self.handle
    }
    pub fn resource(&self) -> MemoryResource {
        self.resource
    }
    pub fn dependencies(&self) -> &[Handle<'a>] {
        &self.dependencies
    }
}

fn optional<'a>(handle: Handle<'a>, name: &str) -> Result<Option<Value<'a>>, Error> {
    match handle.evaluate(Some(name), &[]) {
        Err(acpi::Error(5)) => Ok(None), // AE_NOT_FOUND, specification default.
        result => result.map_err(Error::Acpi),
    }
}
fn inspect(handle: Handle<'_>) -> Result<Device<'_>, Error> {
    if !handle.hardware_active() {
        return Err(Error::HardwareInactive);
    }
    let status = match optional(handle, "_STA")? {
        None => 0x0f,
        Some(Value::Integer(status)) => status,
        _ => return Err(Error::InvalidObject("_STA")),
    };
    if status & 0x0b != 0x0b {
        return Err(Error::DeviceUnavailable(status));
    }
    let dependencies = match optional(handle, "_DEP")? {
        None => Vec::new(),
        Some(Value::Package(values)) => values
            .into_iter()
            .map(|value| match value {
                Value::Reference(reference) => Ok(reference.handle),
                _ => Err(Error::InvalidObject("_DEP")),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(Error::InvalidObject("_DEP")),
    };
    let Some(Value::Buffer(template)) = handle.evaluate(Some("_CRS"), &[])? else {
        return Err(Error::InvalidObject("_CRS"));
    };
    let resource = mailbox_resource(&template).map_err(Error::Resources)?;
    Ok(Device {
        handle,
        resource,
        dependencies,
    })
}

/// Enumerate present PNP0CA0 namespace devices. Namespace paths or caller
/// IDs cannot be used to bypass hardware mode, `_STA`, `_DEP` or `_CRS` checks.
/// A malformed/unsupported device is returned individually for platform reporting.
pub fn discover(session: &Session) -> Result<Vec<Result<Device<'_>, Error>>, Error> {
    if !session.hardware_enabled() {
        return Err(Error::HardwareInactive);
    }
    Ok(session
        .devices("PNP0CA0")?
        .into_iter()
        .map(inspect)
        .collect())
}

pub struct Aml<'a> {
    handle: Handle<'a>,
    #[cfg(test)]
    peer: Option<Box<dyn Dsm>>,
}
impl Dsm for Aml<'_> {
    fn evaluate(
        &mut self,
        uuid: [u8; 16],
        revision: u64,
        function: u64,
    ) -> Result<(), TransportError> {
        #[cfg(test)]
        if let Some(peer) = self.peer.as_mut() {
            return peer.evaluate(uuid, revision, function);
        }
        if uuid != DSM_UUID || revision != 1 {
            return Err(TransportError::Unavailable);
        }
        match self.handle.dsm(&uuid, revision, function) {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(TransportError::DsmNoResult { function }),
            Err(error) => Err(TransportError::Dsm {
                function,
                status: u64::from(error.0),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Bound,
    Running,
    Suspended,
    Faulted,
    /// Notify removal did not complete; original resource owners are held
    /// permanently rather than treating a consumed registration as an ACK.
    Quarantined,
    Retired,
}

/// Completed, acknowledged observations remain available if a later event in
/// the same service batch fails. The failure must be reported/recovered before
/// treating the batch as fully serviced.
#[must_use]
pub struct ServiceReport {
    pub changes: Vec<ConnectorSnapshot>,
    pub error: Option<Error>,
}

pub struct Attachment<'a, M: Mapping, D: Dependency<'a>, C: Timer> {
    device: Device<'a>,
    notification: Option<Notification<'a>>,
    removal_error: Option<acpi::Error>,
    pending: Arc<AtomicBool>,
    controller: Controller<Mailbox<Aml<'a>>, C>,
    mapping: Option<M>,
    dependencies: Option<Vec<D>>,
    state: State,
}
impl<'a, M: Mapping, D: Dependency<'a>, C: Timer> Attachment<'a, M, D, C> {
    /// Bind exact firmware resources and install deferred ACPICA Notify.
    /// This only refreshes VERSION; start explicitly publishes PPM commands.
    pub fn bind(
        device: Device<'a>,
        mapping: M,
        dependencies: Vec<D>,
        timer: C,
    ) -> Result<Self, Error> {
        let aml = Aml {
            handle: device.handle,
            #[cfg(test)]
            peer: None,
        };
        Self::bind_with_aml(device, mapping, dependencies, timer, aml)
    }
    fn bind_with_aml(
        device: Device<'a>,
        mapping: M,
        dependencies: Vec<D>,
        timer: C,
        aml: Aml<'a>,
    ) -> Result<Self, Error> {
        super::super::validate_timer(&timer)?;
        if mapping.resource() != device.resource {
            return Err(Error::MappingMismatch);
        }
        Self::check_dependencies(&device, &dependencies)?;
        let current = inspect(device.handle)?;
        if current.resource != device.resource || current.dependencies != device.dependencies {
            return Err(Error::ResourcesChanged);
        }
        // SAFETY: Mapping's unsafe contract owns this exact firmware resource;
        // equality above binds it to the real namespace _CRS and keeps it.
        let mailbox = unsafe { Mailbox::new(mapping.base(), device.resource.bytes, aml) }.map_err(
            |error| {
                Error::Ucsi(UcsiError::Transport {
                    phase: super::super::Phase::Version,
                    error,
                })
            },
        )?;
        let controller = Controller::new(mailbox, timer)?;
        let pending = Arc::new(AtomicBool::new(false));
        let target = pending.clone();
        let notification = device.handle.notify(move |_| {
            // The event is only a work hint. Never run AML or publish a
            // made-up CCI in a Notify callback; process service reads firmware.
            target.store(true, Ordering::Release);
        })?;
        Ok(Self {
            device,
            notification: Some(notification),
            removal_error: None,
            pending,
            controller,
            mapping: Some(mapping),
            dependencies: Some(dependencies),
            state: State::Bound,
        })
    }
    fn check_dependencies(device: &Device<'a>, leases: &[D]) -> Result<(), Error> {
        if device
            .dependencies
            .iter()
            .any(|handle| !leases.iter().any(|lease| lease.handle() == *handle))
        {
            return Err(Error::DependencyUnavailable);
        }
        Ok(())
    }
    fn revalidate(&self) -> Result<(), Error> {
        let current = inspect(self.device.handle)?;
        if current.resource != self.device.resource
            || current.dependencies != self.device.dependencies
        {
            return Err(Error::ResourcesChanged);
        }
        Self::check_dependencies(
            &current,
            self.dependencies.as_deref().ok_or(Error::Inactive)?,
        )
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn needs_service(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }
    pub fn controller(&self) -> &Controller<Mailbox<Aml<'a>>, C> {
        &self.controller
    }
    /// Access for existing role/PD/alternate-mode coordinators; available only
    /// while live. They must consume observed status, never infer role changes
    /// from a command's successful completion.
    pub fn controller_mut(&mut self) -> Result<&mut Controller<Mailbox<Aml<'a>>, C>, Error> {
        if self.state != State::Running {
            return Err(Error::Inactive);
        }
        self.revalidate()?;
        Ok(&mut self.controller)
    }
    /// Initialize or explicitly recover a faulted binding. The kept mapping
    /// and dependency owners remain available if any real firmware step fails.
    pub fn start(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Bound | State::Suspended | State::Faulted) {
            return Err(Error::Inactive);
        }
        self.revalidate()?;
        self.state = State::Faulted;
        self.controller.resume()?;
        self.state = State::Running;
        Ok(())
    }
    pub fn execute(
        &mut self,
        command: Command,
        input: &mut [u8],
        output: &[u8],
    ) -> Result<Completion, Error> {
        let result = self.controller_mut()?.execute(command, input, output);
        if self.controller.fault().is_some() {
            self.state = State::Faulted;
        }
        result.map_err(Error::Ucsi)
    }
    /// Process/deferred-context service. The finite budget bounds a constantly
    /// changing connector; unserviced hardware-latched work remains pending.
    /// Polling also recovers a missed notification without manufacturing events.
    pub fn service(&mut self, budget: usize) -> Result<ServiceReport, Error> {
        self.controller_mut()?;
        let mut report = ServiceReport {
            changes: Vec::new(),
            error: None,
        };
        if budget == 0 {
            return Ok(report);
        }
        self.pending.swap(false, Ordering::AcqRel);
        for _ in 0..budget {
            let event = self.controller.poll_change().and_then(|number| {
                if number.is_some() {
                    self.controller.service_change()
                } else {
                    Ok(None)
                }
            });
            match event {
                Ok(Some(snapshot)) => report.changes.push(snapshot),
                Ok(None) => break,
                Err(error) => {
                    report.error = Some(Error::Ucsi(error));
                    break;
                }
            }
        }
        if self.controller.fault().is_some() {
            self.state = State::Faulted;
        }
        if report.error.is_some() || self.controller.pending_change().is_some() {
            self.pending.store(true, Ordering::Release);
        }
        Ok(report)
    }
    /// Stop caller work before platform EC/AML suspend; disable PPM Notify with
    /// the real command/ACK. Notify callbacks themselves only set an atomic hint.
    pub fn suspend(&mut self) -> Result<(), Error> {
        self.controller_mut()?;
        self.state = State::Faulted;
        self.controller.suspend()?;
        self.state = State::Suspended;
        Ok(())
    }
    /// Reset a faulted PPM if needed, disable firmware notifications,
    /// remove/drain the ACPICA callback, then release CPU/dependency leases.
    /// On any error resources stay held, so platform services must remain up.
    pub fn detach(&mut self) -> Result<(), Error> {
        if let Some(error) = self.removal_error {
            return Err(Error::NotificationRemovalUncertain(error));
        }
        if self.state == State::Retired {
            return Ok(());
        }
        self.revalidate()?;
        if self.state == State::Faulted || self.controller.fault().is_some() {
            self.state = State::Faulted;
            self.controller.reset()?;
        }
        if !matches!(self.state, State::Bound | State::Suspended) {
            self.state = State::Faulted;
            self.controller.suspend()?;
            self.state = State::Suspended;
        }
        self.remove_notification()?;
        self.state = State::Retired;
        drop(self.mapping.take());
        drop(self.dependencies.take());
        Ok(())
    }
    fn remove_notification(&mut self) -> Result<(), Error> {
        if let Some(error) = self.removal_error {
            return Err(Error::NotificationRemovalUncertain(error));
        }
        if let Some(notification) = self.notification.take()
            && let Err(error) = notification.remove()
        {
            // Notification consumes its local owner on error and Session keeps
            // callback storage. Absence of that owner is never proof of drain.
            self.removal_error = Some(error);
            self.state = State::Quarantined;
            return Err(Error::NotificationRemovalUncertain(error));
        }
        Ok(())
    }
}
impl<'a, M: Mapping, D: Dependency<'a>, C: Timer> Drop for Attachment<'a, M, D, C> {
    fn drop(&mut self) {
        // Removal drains callbacks; their closure owns only the atomic, never
        // mailbox memory. No blocking firmware command is issued from Drop.
        let _ = self.remove_notification();
        if !matches!(self.state, State::Bound | State::Suspended | State::Retired) {
            // Uncertain firmware state cannot authorize resource retirement.
            // Explicit detach while AML services are live is the normal path.
            if let Some(mapping) = self.mapping.take() {
                core::mem::forget(mapping);
            }
            if let Some(dependencies) = self.dependencies.take() {
                core::mem::forget(dependencies);
            }
        }
    }
}

#[cfg(test)]
mod tests;
