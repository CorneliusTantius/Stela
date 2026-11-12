// SPDX-License-Identifier: GPL-2.0-or-later
//! Installed native EC operation regions and a transaction endpoint.
//!
//! ACPICA supplies the real OSL port, timer, semaphore and FACS services. This
//! owner installs EmbeddedControl callbacks; a namespace identifier never
//! grants hardware access. GPE/SCI installation and automatic board grants are
//! separate from this polling attachment.
use super::{discovery::native::Device, *};
use crate::platform::acpi::resources::{self, Dependency, supplier::SupplierState};
use crate::platform::acpi::{self, Handle, Status};
use alloc::{boxed::Box, sync::Arc};
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering},
};

unsafe extern "C" {
    fn acpi_os_create_semaphore(max: u32, initial: u32, out: *mut *mut c_void) -> Status;
    fn acpi_os_delete_semaphore(semaphore: *mut c_void) -> Status;
    fn acpi_os_wait_semaphore(semaphore: *mut c_void, units: u32, milliseconds: u16) -> Status;
    fn acpi_os_signal_semaphore(semaphore: *mut c_void, units: u32) -> Status;
    fn acpi_os_read_port(port: u64, out: *mut u32, width: u32) -> Status;
    fn acpi_os_write_port(port: u64, value: u32, width: u32) -> Status;
    fn acpi_os_get_timer() -> u64;
    fn acpi_os_stall(microseconds: u32);
    fn acpi_acquire_global_lock(milliseconds: u16, token: *mut u32) -> Status;
    fn acpi_release_global_lock(token: u32) -> Status;
    fn stela_acpi_guard_enter(out: *mut *mut c_void, epoch: *mut u64) -> Status;
    fn stela_acpi_guard_leave(guard: *mut c_void);
    fn stela_acpi_namespace_valid() -> u8;
    fn stela_acpi_arbitration_ready() -> u8;
    fn stela_acpi_bind_node(candidate: *mut c_void, epoch: u64) -> Status;
    fn acpi_execute_reg_methods(device: *mut c_void, depth: u32, space: u8) -> Status;
}

/// Linux installs the first EC at the root for firmware regions outside its
/// device subtree. Additional controllers install only in their own subtree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    FirstController,
    Device,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    Firmware(acpi::Error),
    Controller(Error),
    Removed,
    PendingEvent,
    Retirement {
        registration: acpi::Error,
        retirement: acpi::Error,
    },
    Unlock {
        error: acpi::Error,
        controller: Option<Error>,
        io: Option<acpi::Error>,
        arbitration: Option<acpi::Error>,
        /// This call's completion, independent from the first failed
        /// release kept in shared diagnostics. No permission to replay.
        completion: Option<Completion>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Read,
    Write,
    Query,
}
/// A completed controller operation, kept independently from a
/// later owner-semaphore release failure. This never grants permission to replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    pub operation: Operation,
    pub address: u8,
    pub width: u8,
    pub value: u64,
}

/// A plain account for the boot log.
impl core::fmt::Display for Completion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let operation = match self.operation {
            Operation::Read => "read",
            Operation::Write => "write",
            Operation::Query => "query",
        };
        write!(
            f,
            "a {}-bit {operation} at {:#x} completed with {:#x}",
            self.width, self.address, self.value
        )
    }
}

/// A plain account for the boot log.
impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Firmware(error) => error.fmt(f),
            Self::Controller(error) => error.fmt(f),
            Self::Removed => f.write_str("it was removed"),
            Self::PendingEvent => f.write_str("an earlier event is still pending"),
            Self::Retirement {
                registration,
                retirement,
            } => write!(
                f,
                "its registration failed: {registration}, and its cleanup failed: {retirement}"
            ),
            Self::Unlock {
                error,
                controller,
                io,
                arbitration,
                completion,
            } => {
                write!(f, "its lock was not released: {error}")?;
                if let Some(controller) = controller {
                    write!(f, "; the controller: {controller}")?;
                }
                if let Some(io) = io {
                    write!(f, "; its port access: {io}")?;
                }
                if let Some(arbitration) = arbitration {
                    write!(f, "; its arbitration: {arbitration}")?;
                }
                if let Some(completion) = completion {
                    write!(f, "; {completion}")?;
                }
                Ok(())
            }
        }
    }
}

/// Observations remain available after AML returned its mapped ACPICA status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Diagnostics {
    pub controller: Option<Error>,
    pub io: Option<acpi::Error>,
    pub arbitration: Option<acpi::Error>,
    pub synchronization: Option<acpi::Error>,
}

/// A consumed event keeps its originating namespace device. Dispatch cannot
/// accidentally route an event from a second EC to this controller's AML.
#[must_use = "dispatch or explicitly retain the consumed EC event"]
pub struct Event<'a> {
    query: Query,
    device: Handle<'a>,
}
impl Event<'_> {
    pub fn value(&self) -> u8 {
        self.query.value()
    }
    pub fn dispatch(self) -> Result<(), QueryFailure> {
        self.query.evaluate(self.device)
    }
}

struct NamespaceLease(*mut c_void);
impl NamespaceLease {
    fn enter() -> Result<Self, acpi::Error> {
        let mut raw = ptr::null_mut();
        let mut epoch = 0;
        // SAFETY: the binding borrows the active ACPICA session.
        check(unsafe { stela_acpi_guard_enter(&mut raw, &mut epoch) })?;
        Ok(Self(raw))
    }
    fn for_node(node: *mut c_void) -> Result<Self, acpi::Error> {
        let mut raw = ptr::null_mut();
        let mut epoch = 0;
        // SAFETY: the context outlives the core; enter validates current
        // namespace admission before any saved node identity can be dereferenced.
        check(unsafe { stela_acpi_guard_enter(&mut raw, &mut epoch) })?;
        let lease = Self(raw);
        // SAFETY: bind compares pointer identity against the tree under this
        // read lease and rejects temporary/deleted namespace nodes.
        check(unsafe { stela_acpi_bind_node(node, epoch) })?;
        Ok(lease)
    }
}
impl Drop for NamespaceLease {
    fn drop(&mut self) {
        // SAFETY: exactly this read lease remains owned by this value.
        unsafe { stela_acpi_guard_leave(self.0) };
    }
}

struct Ports {
    resources: discovery::Ports,
    last_error: Option<acpi::Error>,
    current_error: Option<acpi::Error>,
}
impl Ports {
    fn read(&mut self, port: u16) -> Result<u8, IoError> {
        let mut value = 0;
        // SAFETY: install's native resource contract and the OSL owner.
        let status = unsafe { acpi_os_read_port(u64::from(port), &mut value, 8) };
        if status != 0 || value > u32::from(u8::MAX) {
            self.last_error = Some(if status != 0 {
                acpi::Error(status)
            } else {
                acpi::BAD_PARAMETER
            });
            self.current_error = self.last_error;
            return Err(IoError);
        }
        Ok(value as u8)
    }
    fn write(&mut self, port: u16, value: u8) -> Result<(), IoError> {
        // SAFETY: the same native register ownership as read.
        let status = unsafe { acpi_os_write_port(u64::from(port), u32::from(value), 8) };
        if status != 0 {
            self.last_error = Some(acpi::Error(status));
            self.current_error = self.last_error;
            return Err(IoError);
        }
        Ok(())
    }
}
impl Registers for Ports {
    fn status(&mut self) -> Result<u8, IoError> {
        self.read(self.resources.command)
    }
    fn read_data(&mut self) -> Result<u8, IoError> {
        self.read(self.resources.data)
    }
    fn command(&mut self, value: u8) -> Result<(), IoError> {
        self.write(self.resources.command, value)
    }
    fn write_data(&mut self, value: u8) -> Result<(), IoError> {
        self.write(self.resources.data, value)
    }
}

struct OsTimer;
impl Timer for OsTimer {
    fn check_duration(&self, microseconds: u64) -> Result<(), crate::ClockError> {
        let ticks = microseconds
            .checked_mul(10)
            .ok_or(crate::ClockError::DurationOverflow)?;
        if ticks > u64::MAX / 2 {
            Err(crate::ClockError::DurationTooLong)
        } else {
            Ok(())
        }
    }
    fn start(&self) -> u64 {
        // SAFETY: the binding keeps the original OSL timer alive.
        unsafe { acpi_os_get_timer() }
    }
    fn elapsed_us(&self, start: u64) -> u64 {
        // SAFETY: start is this same live provider's raw counter origin.
        unsafe { acpi_os_get_timer().wrapping_sub(start) / 10 }
    }
    fn now_us(&self) -> u64 {
        // SAFETY: the original OSL provider outlives all kept callbacks.
        unsafe { acpi_os_get_timer() / 10 }
    }
    fn relax(&self) {
        // SAFETY: process-context polling uses the microsecond service.
        unsafe { acpi_os_stall(1) };
    }
}

struct Arbitration {
    required: bool,
    held: Option<(u32, NamespaceLease)>,
    count: Arc<AtomicUsize>,
    last_error: Option<acpi::Error>,
    current_error: Option<acpi::Error>,
}
impl Arbitration {
    fn failure(&mut self, error: acpi::Error) -> LockError {
        self.last_error = Some(error);
        self.current_error = Some(error);
        LockError
    }
}
impl FirmwareLock for Arbitration {
    fn acquire(&mut self, timeout_us: u64) -> Result<(), LockError> {
        if !self.required {
            return Ok(());
        }
        // Successful software mutex acquisition before hardware initialization
        // does not arbitrate with firmware's FACS owner. Preserve the core's
        // initialized reduced/absent-lock policy only after setup.
        // SAFETY: the binding's namespace/provider retention keeps bridge live.
        if unsafe { stela_acpi_arbitration_ready() } == 0 {
            return Err(self.failure(acpi::SUPPORT));
        }
        if self.held.is_some() {
            return Err(LockError);
        }
        let milliseconds = timeout_us.div_ceil(1_000);
        if milliseconds == 0 || milliseconds >= u64::from(u16::MAX) {
            return Err(LockError);
        }
        let lease = NamespaceLease::enter().map_err(|error| self.failure(error))?;
        let mut token = 0;
        // SAFETY: bounded ACPICA/FACS acquisition, never a local substitute.
        let status = unsafe { acpi_acquire_global_lock(milliseconds as u16, &mut token) };
        if status != 0 {
            return Err(self.failure(acpi::Error(status)));
        }
        self.held = Some((token, lease));
        self.count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| LockError)?;
        // Match the session's EC lock: a blocking native acquisition can return
        // after namespace admission changed. Retire ownership first.
        // SAFETY: this namespace lease and real lock keep the native core.
        if unsafe { stela_acpi_namespace_valid() } == 0 {
            self.failure(acpi::SUPPORT);
            self.release()?;
            return Err(LockError);
        }
        Ok(())
    }
    fn release(&mut self) -> Result<(), LockError> {
        if !self.required {
            return Ok(());
        }
        let Some((token, _)) = self.held.as_ref() else {
            return Err(LockError);
        };
        // SAFETY: token and kept namespace lease belong to this controller.
        let status = unsafe { acpi_release_global_lock(*token) };
        if status != 0 {
            return Err(self.failure(acpi::Error(status)));
        }
        self.held = None;
        self.count.fetch_sub(1, Ordering::AcqRel);
        Ok(())
    }
}
impl Drop for Arbitration {
    fn drop(&mut self) {
        if let Some((_, lease)) = self.held.take() {
            // Real failed-release ownership prevents Session shutdown. Never
            // free its native namespace lease just because a Rust owner drops.
            core::mem::forget(lease);
        }
    }
}

struct State {
    ec: Ec<Ports, OsTimer, Arbitration>,
    last_error: Option<Error>,
    completion: Option<Completion>,
}
impl State {
    fn begin_io(&mut self) {
        self.ec.registers.current_error = None;
        self.ec.gate.current_error = None;
    }
}
struct Context {
    device: *mut c_void,
    connection: AtomicU32,
    connection_error: AtomicU32,
    supplier: Arc<SupplierState>,
    locks: Arc<AtomicUsize>,
    enabled: AtomicBool,
    synchronization: AtomicU32,
    pending_query: AtomicU32,
    failed_completion: AtomicPtr<Completion>,
    failed_error: AtomicPtr<Diagnostics>,
    semaphore: *mut c_void,
    wait_ms: u16,
    state: UnsafeCell<State>,
}
impl Context {
    fn connect(&self) -> Result<(), acpi::Error> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(()); // Removed registrations remain held for retirement.
        }
        match self
            .connection
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(2) => return Ok(()),
            Err(3) => return Err(acpi::Error(self.connection_error.load(Ordering::Acquire))),
            Err(_) => return Err(acpi::SUPPORT),
        }
        let result = (|| {
            let _lease = NamespaceLease::for_node(self.device)?;
            // SAFETY: the namespace read lease validates this
            // device. The live EC handler is installed before subtree _REG AML.
            check(unsafe { acpi_execute_reg_methods(self.device, u32::MAX, 3) })?;
            // SAFETY: reentrant AML can have invalidated facade admission.
            if unsafe { stela_acpi_namespace_valid() } == 0 {
                return Err(acpi::SUPPORT);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.connection_error.store(error.0, Ordering::Release);
        }
        self.connection
            .store(if result.is_ok() { 2 } else { 3 }, Ordering::Release);
        result
    }
    fn admit_supplier(&self) -> Result<(), Failure> {
        self.with_state(|state| {
            if state.ec.needs_reset() || state.ec.gate.held.is_some() {
                Err(Failure::Firmware(acpi::SUPPORT))
            } else if !self.enabled.load(Ordering::Acquire) || self.supplier.connected().is_err() {
                Err(Failure::Removed)
            } else {
                Ok(())
            }
        })
    }
    fn with_state<V>(
        &self,
        operation: impl FnOnce(&mut State) -> Result<V, Failure>,
    ) -> Result<V, Failure> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(Failure::Removed);
        }
        let _namespace = NamespaceLease::enter().map_err(Failure::Firmware)?;
        // SAFETY: the semaphore is held until all core callbacks stop.
        let status = unsafe { acpi_os_wait_semaphore(self.semaphore, 1, self.wait_ms) };
        if status != 0 {
            self.synchronization.store(status, Ordering::Release);
            return Err(Failure::Firmware(acpi::Error(status)));
        }
        let mut completion = None;
        let mut io = None;
        let mut arbitration = None;
        // SAFETY: live namespace lease keeps the core through this post-wait check.
        let result = if unsafe { stela_acpi_namespace_valid() } == 0 {
            Err(Failure::Firmware(acpi::SUPPORT))
        } else if self.enabled.load(Ordering::Acquire) {
            // SAFETY: every access, including callback diagnostics, holds this semaphore.
            let state = unsafe { &mut *self.state.get() };
            state.completion = None;
            let result = operation(state);
            completion = state.completion;
            if completion.is_some() || matches!(&result, Err(Failure::Controller(_))) {
                io = state.ec.registers.current_error;
                arbitration = state.ec.gate.current_error;
            }
            result
        } else {
            Err(Failure::Removed)
        };
        // SAFETY: this call acquired exactly one unit above.
        let status = unsafe { acpi_os_signal_semaphore(self.semaphore, 1) };
        if status != 0 {
            self.enabled.store(false, Ordering::Release);
            self.supplier.close_admission();
            let controller = match &result {
                Err(Failure::Controller(error)) => Some(*error),
                _ => None,
            };
            if let Some(error) = controller {
                let raw = Box::into_raw(Box::new(Diagnostics {
                    controller: Some(error),
                    io,
                    arbitration,
                    synchronization: Some(acpi::Error(status)),
                }));
                if self
                    .failed_error
                    .compare_exchange(ptr::null_mut(), raw, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    // SAFETY: failed CAS never published this fresh Box pointer.
                    unsafe { drop(Box::from_raw(raw)) };
                }
            }
            if let Some(completion) = completion {
                let raw = Box::into_raw(Box::new(completion));
                if self
                    .failed_completion
                    .compare_exchange(ptr::null_mut(), raw, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    // SAFETY: failed CAS leaves this distinct immutable Box owned here.
                    unsafe { drop(Box::from_raw(raw)) };
                }
            }
            self.synchronization.store(status, Ordering::Release);
            return Err(Failure::Unlock {
                error: acpi::Error(status),
                controller,
                io,
                arbitration,
                completion,
            });
        }
        result
    }
    fn read(&self, address: u64, width: u32) -> Result<u64, Failure> {
        self.with_state(|state| {
            state.begin_io();
            let value = state.ec.read_region(address, width).map_err(|error| {
                state.last_error = Some(error);
                Failure::Controller(error)
            })?;
            state.completion = Some(Completion {
                operation: Operation::Read,
                address: address as u8,
                width: width as u8,
                value,
            });
            Ok(value)
        })
    }
    fn write(&self, address: u64, width: u32, value: u64) -> Result<(), Failure> {
        self.with_state(|state| {
            state.begin_io();
            state
                .ec
                .write_region(address, width, value)
                .map_err(|error| {
                    state.last_error = Some(error);
                    Failure::Controller(error)
                })?;
            let value = if width == 64 {
                value
            } else {
                value & ((1u64 << width) - 1)
            };
            state.completion = Some(Completion {
                operation: Operation::Write,
                address: address as u8,
                width: width as u8,
                value,
            });
            Ok(())
        })
    }
    fn poll_query(&self) -> Result<(), Failure> {
        self.with_state(|state| {
            if self.pending_query.load(Ordering::Acquire) != 0 {
                return Err(Failure::PendingEvent);
            }
            state.begin_io();
            let query = state.ec.poll_query().map_err(|error| {
                state.last_error = Some(error);
                Failure::Controller(error)
            })?;
            let value = query.map_or(0, |query| query.value());
            // Save consumed identity before releasing the semaphore. It
            // remains recoverable even if release fails and state access stops.
            self.pending_query
                .store(u32::from(value), Ordering::Release);
            state.completion = Some(Completion {
                operation: Operation::Query,
                address: 0,
                width: 0,
                value: u64::from(value),
            });
            Ok(())
        })
    }
}

/// Installed handler and direct endpoint for the same discovered EC.
/// Callback storage remains owned by ACPICA through core termination, even after
/// explicit removal; finalization retires its semaphore before provider destroy.
pub struct Binding<'a> {
    device: Device<'a>,
    scope: Handle<'a>,
    context: *mut Context,
    installed: bool,
}
impl<'a> Binding<'a> {
    /// Install EmbeddedControl I/O before dependent `_REG`/AML methods.
    /// The first-controller scope includes firmware regions outside its subtree.
    /// Multi-byte regions always request source burst mode; Config::burst is
    /// set by this binding rather than admitting a different region protocol.
    ///
    /// # Safety
    /// The original Session provider must keep the discovered port
    /// reservations, decode/power and native/firmware exclusion for this EC until
    /// session shutdown. Its OSL port services must access those exact resources.
    /// No other EC byte owner may bypass this semaphore/FACS arbitration. The
    /// caller must select the first EC; IDs and `_CRS` alone grant none
    /// of these native ownership facts. Call from process context, not a callback.
    pub unsafe fn install(
        device: Device<'a>,
        config: Config,
        scope: Scope,
    ) -> Result<Self, Failure> {
        let config = Config {
            burst: true,
            ..config
        };
        let wait_ms = config.timeout_us.div_ceil(1_000);
        if wait_ms == 0 || wait_ms >= u64::from(u16::MAX) {
            return Err(Failure::Firmware(acpi::BAD_PARAMETER));
        }
        let ec = Ec::new(
            Ports {
                resources: device.ports,
                last_error: None,
                current_error: None,
            },
            OsTimer,
            Arbitration {
                required: device.global_lock,
                held: None,
                count: device.handle.ec_lock_count(),
                last_error: None,
                current_error: None,
            },
            config,
        )
        .map_err(Failure::Controller)?;
        let target = device
            .handle
            .ec_activation_target()
            .map_err(Failure::Firmware)?;
        let mut semaphore = ptr::null_mut();
        // SAFETY: OSL provider owns this live session and returned handle.
        check(unsafe { acpi_os_create_semaphore(1, 1, &mut semaphore) })
            .map_err(Failure::Firmware)?;
        let context = Box::into_raw(Box::new(Context {
            device: target,
            connection: AtomicU32::new(0),
            connection_error: AtomicU32::new(0),
            supplier: SupplierState::new(),
            locks: device.handle.ec_lock_count(),
            enabled: AtomicBool::new(true),
            synchronization: AtomicU32::new(0),
            pending_query: AtomicU32::new(0),
            failed_completion: AtomicPtr::new(ptr::null_mut()),
            failed_error: AtomicPtr::new(ptr::null_mut()),
            semaphore,
            wait_ms: wait_ms as u16,
            state: UnsafeCell::new(State {
                ec,
                last_error: None,
                completion: None,
            }),
        }));
        // SAFETY: success transfers storage to the real core-termination finalizer.
        if let Err(error) = unsafe {
            device.handle.retain_ec_context(
                before_termination,
                retire,
                Some(activate),
                context.cast(),
            )
        } {
            // No callback has seen this unregistered context. A failed semaphore
            // deletion keeps storage rather than pretending its owner retired.
            // SAFETY: registration failed; this provider still owns the handle.
            let retirement = unsafe { acpi_os_delete_semaphore(semaphore) };
            if retirement == 0 {
                // SAFETY: no callback or finalizer received this unregistered Box.
                unsafe { drop(Box::from_raw(context)) };
            } else {
                // No core finalizer owns this context yet. Pin the original
                // provider permanently rather than destroying its live handle.
                device
                    .handle
                    .ec_resource_quarantine()
                    .store(true, Ordering::Release);
                return Err(Failure::Retirement {
                    registration: error,
                    retirement: acpi::Error(retirement),
                });
            }
            return Err(Failure::Firmware(error));
        }
        let scope = device.handle.ec_scope(scope == Scope::FirstController);
        let mut binding = Self {
            device,
            scope,
            context,
            installed: false,
        };
        // SAFETY: C now keeps this exact context through all callback lifetimes.
        match unsafe { scope.install_ec_region(region, setup, context.cast()) } {
            Ok(()) => {
                binding.installed = true;
                // _GLK firmware must not run _REG while ACPICA still only
                // supplies its InterpreterOnly software mutex. The kept
                // activation stage connects after real FACS/SCI/GLK setup and
                // before _INI. Non-GLK firmware can connect immediately.
                // SAFETY: this binding keeps the live bridge/provider.
                if (!device.global_lock || unsafe { stela_acpi_arbitration_ready() } != 0)
                    && let Err(error) = binding.context().connect()
                {
                    let _ = binding.close();
                    return Err(Failure::Firmware(error));
                }
                Ok(binding)
            }
            Err(error) => {
                // Installation may have succeeded before namespace validation
                // failed. Retention is unconditional; disable further native IO.
                binding.context().enabled.store(false, Ordering::Release);
                Err(Failure::Firmware(error))
            }
        }
    }
    pub fn device(&self) -> Device<'a> {
        self.device
    }
    /// Keep this installed EC as a firmware dependency. A descriptor,
    /// unconnected handler or pre-activation software token cannot issue it.
    /// Consumers keep explicit removal and core termination blocked until their
    /// native effects retire. This grants no GPIO pins, rails or bus ownership.
    /// A failed Session shutdown permanently quarantines the core/provider and
    /// closes endpoint I/O; pins then preserve storage, not operability.
    pub fn supplier(&self) -> Result<Dependency<'a>, resources::Error> {
        self.device.handle.ec_activation_target()?;
        let context = self.context();
        if !self.installed || context.connection.load(Ordering::Acquire) != 2 {
            return Err(resources::Error::Unassigned);
        }
        context
            .admit_supplier()
            .map_err(|error| resources::Error::Acpi(acpi::Error(mapped(error))))?;
        // ACPICA keeps Linux's aggregate _REG error policy. Supplier admission
        // separately requires the byte-owner check/publication above,
        // within the same semaphore. Its release failure closes admission.
        let dependency = Dependency::acquire(self.device.handle, &context.supplier)?;
        if !context.enabled.load(Ordering::Acquire) {
            return Err(resources::Error::Unassigned);
        }
        Ok(dependency)
    }
    fn context(&self) -> &Context {
        // SAFETY: C registration owns this Box until core termination;
        // this Binding's handle borrow prevents termination while it is used.
        unsafe { &*self.context }
    }
    pub fn read_region(&self, address: u64, width: u32) -> Result<u64, Failure> {
        // SAFETY: the core owns storage while this binding borrows its session.
        self.context().read(address, width)
    }
    pub fn write_region(&self, address: u64, width: u32, value: u64) -> Result<(), Failure> {
        self.context().write(address, width, value)
    }
    /// Consume one SCI-checked QR_EC response. The semaphore and FACS
    /// lock are released before returning; evaluate AML only after this call.
    pub fn poll_query(&self) -> Result<Option<Event<'a>>, Failure> {
        self.context().poll_query()?;
        Ok(self.take_pending_event())
    }
    /// Recover a consumed event after failed owner unlock without
    /// touching the EC or replaying QR_EC. Its original device remains attached.
    pub fn take_pending_event(&self) -> Option<Event<'a>> {
        let value = self.context().pending_query.swap(0, Ordering::AcqRel);
        (value != 0).then_some(Event {
            query: Query(value as u8),
            device: self.device.handle,
        })
    }
    pub fn diagnostics(&self) -> Result<Diagnostics, Failure> {
        self.context().with_state(|state| {
            let synchronization = self.context().synchronization.load(Ordering::Acquire);
            Ok(Diagnostics {
                controller: state.last_error,
                io: state.ec.registers.last_error,
                arbitration: state.ec.gate.last_error,
                synchronization: (synchronization != 0).then_some(acpi::Error(synchronization)),
            })
        })
    }
    /// Available even when a failed semaphore signal prevents safe state access.
    pub fn synchronization_error(&self) -> Option<acpi::Error> {
        let status = self.context().synchronization.load(Ordering::Acquire);
        (status != 0).then_some(acpi::Error(status))
    }
    pub fn failed_completion(&self) -> Option<Completion> {
        let raw = self.context().failed_completion.load(Ordering::Acquire);
        if raw.is_null() {
            None
        } else {
            // SAFETY: published immutable snapshot remains allocated until core termination.
            Some(unsafe { *raw })
        }
    }
    /// Primary controller failure survives a second semaphore-release failure,
    /// including late-byte/progress evidence unavailable under that lock.
    pub fn failed_controller_error(&self) -> Option<Error> {
        self.failed_controller_diagnostics()?.controller
    }
    /// First failed controller operation and native IO/arbitration causes
    /// captured before its failed unlock. No broken semaphore is reacquired.
    pub fn failed_controller_diagnostics(&self) -> Option<Diagnostics> {
        let raw = self.context().failed_error.load(Ordering::Acquire);
        if raw.is_null() {
            None
        } else {
            // SAFETY: first-CAS snapshot is immutable and kept with this context.
            Some(unsafe { *raw })
        }
    }
    pub fn remove(mut self) -> Result<(), acpi::Error> {
        self.close()
    }
    #[cfg(test)]
    pub(crate) fn remove_from_core_for_test(&self) -> Result<(), acpi::Error> {
        // Exercise a subsequent removal failure, not a fake status.
        // SAFETY: this scope/handler belongs to this still binding.
        unsafe { self.scope.remove_region(3, region) }
    }
    #[cfg(test)]
    pub(crate) fn semaphore_for_test(&self) -> *mut c_void {
        self.context().semaphore
    }
    #[cfg(test)]
    pub(crate) fn context_for_test(&self) -> *mut c_void {
        self.context.cast()
    }
    fn close(&mut self) -> Result<(), acpi::Error> {
        self.context().supplier.close_admission();
        if self.context().supplier.consumers() != 0 {
            return Err(acpi::SUPPORT);
        }
        if !self.installed {
            return Ok(());
        }
        // Keep the live engine through _REG(DISCONNECT), which can itself
        // issue EC transactions. Failed removal keeps callback storage too.
        // SAFETY: installed scope/handler and core-kept context stay
        // live through disconnect AML and event draining.
        let result = unsafe { self.scope.remove_region(3, region) };
        self.context().enabled.store(false, Ordering::Release);
        self.installed = false;
        result
    }
}
impl Drop for Binding<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn check(status: Status) -> Result<(), acpi::Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(acpi::Error(status))
    }
}
fn mapped(error: Failure) -> Status {
    match error {
        Failure::Firmware(error) => error.0,
        Failure::Removed => acpi::SUPPORT.0,
        Failure::PendingEvent => acpi::SUPPORT.0,
        Failure::Retirement { retirement, .. } => retirement.0,
        Failure::Unlock { error, .. } => error.0,
        Failure::Controller(error) => match error.kind {
            ErrorKind::InvalidRegion | ErrorKind::InvalidConfiguration => acpi::BAD_PARAMETER.0,
            ErrorKind::FirmwareLock => 5, // AE_NOT_FOUND, Linux's -ENODEV mapping.
            ErrorKind::Timeout(_) => 0x11, // AE_TIME
            _ => 1,                       // AE_ERROR; full controller/OSL diagnostics remain held.
        },
    }
}
unsafe extern "C" fn setup(
    _: *mut c_void,
    action: u32,
    context: *mut c_void,
    out: *mut *mut c_void,
) -> Status {
    if context.is_null() || out.is_null() || action > 1 {
        return acpi::BAD_PARAMETER.0;
    }
    // SAFETY: ACPICA supplies this region-context slot; storage is core-kept.
    unsafe {
        out.write(if action == 0 {
            context
        } else {
            ptr::null_mut()
        })
    };
    0
}
unsafe extern "C" fn region(
    function: u32,
    address: u64,
    width: u32,
    value: *mut u64,
    handler: *mut c_void,
    context: *mut c_void,
) -> Status {
    if handler.is_null() || context != handler || value.is_null() || function > 1 {
        return acpi::BAD_PARAMETER.0;
    }
    // SAFETY: setup publishes only this Context pointer.
    let context = unsafe { &*context.cast::<Context>() };
    let result = if function == 0 {
        context.read(address, width).map(|data| {
            // SAFETY: ACPICA supplies this nonnull aligned u64 result slot.
            unsafe { value.write(data) };
        })
    } else {
        // SAFETY: ACPICA initialized this nonnull aligned u64 write operand.
        let data = unsafe { value.read() };
        context.write(address, width, data)
    };
    result.map_or_else(mapped, |()| 0)
}
unsafe extern "C" fn before_termination(context: *mut c_void) -> Status {
    // SAFETY: the core registered this Box; provider quiescence has
    // synchronized/drained all callbacks, while core/provider remain alive.
    let context = unsafe { &*context.cast::<Context>() };
    context.supplier.close_admission();
    context.enabled.store(false, Ordering::Release);
    if context.locks.load(Ordering::Acquire) == 0 && context.supplier.consumers() == 0 {
        0
    } else {
        acpi::SUPPORT.0
    }
}
unsafe extern "C" fn activate(context: *mut c_void) -> Status {
    // SAFETY: registry keeps this Box and invokes activation only after
    // enable_subsystem succeeds, before device initialization or provider stop.
    unsafe { &*context.cast::<Context>() }
        .connect()
        .map_or_else(|error| error.0, |()| 0)
}
#[cfg(test)]
pub(crate) unsafe extern "C" fn hold_global_lock_for_test(context: *mut c_void) {
    // SAFETY: the serial fixture admits this worker before quiescence;
    // no other EC actor accesses State while its provider drains the work item.
    let context = unsafe { &*context.cast::<Context>() };
    // SAFETY: the authored serial worker is the sole State actor at this point.
    let state = unsafe { &mut *context.state.get() };
    state.ec.gate.acquire(1_000_000).unwrap();
}
#[cfg(test)]
pub(crate) unsafe fn read_after_quiescence_for_test(context: *mut c_void) -> Result<u64, Failure> {
    // SAFETY: the serial fixture keeps this real core-registered context.
    unsafe { &*context.cast::<Context>() }.read(0, 8)
}
unsafe extern "C" fn retire(context: *mut c_void) -> Status {
    // SAFETY: bridge invokes once after quiescence + core termination, before
    // provider destroy. No region/evaluation can still access this storage.
    let context = unsafe { &*context.cast::<Context>() };
    // SAFETY: quiescence/termination ended every user, and provider is still live.
    let status = unsafe { acpi_os_delete_semaphore(context.semaphore) };
    if status == 0 {
        let failed_completion = context.failed_completion.load(Ordering::Acquire);
        if !failed_completion.is_null() {
            // SAFETY: successful first CAS transferred this Box to Context;
            // callbacks have stopped and this unique finalizer retires it once.
            unsafe { drop(Box::from_raw(failed_completion)) };
        }
        let failed_error = context.failed_error.load(Ordering::Acquire);
        if !failed_error.is_null() {
            // SAFETY: same unique immutable-snapshot ownership after quiescence.
            unsafe { drop(Box::from_raw(failed_error)) };
        }
        // SAFETY: core owns this original Box; no callbacks/handles remain active.
        unsafe { drop(Box::from_raw((context as *const Context).cast_mut())) };
    }
    // The bridge propagates failed retirement and keeps context/provider.
    status
}
