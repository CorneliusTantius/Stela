//! One original-root HDA owner through cold stop, new DMA and retirement.
use super::{Bar0, Codec};
use crate::{
    audio::{self, hda},
    bus::{
        dma::{AllocationError, DomainAllocator, mapping::DmaError, memory::PageSource},
        mmio::owned::Error as MappingError,
        pci::{
            Bar, Function,
            owned::{ConfigRetention, OwnedConfig},
            requester::preparation::{self, Attachment, PreparingRequester},
        },
    },
};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::RefCell;

/// Distinct engine, root, lease and original-user failures remain diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Pci(hda::pci::AttachError),
    Controller(audio::Error),
    Preparation(preparation::Error),
    Dma(DmaError),
    Allocation(AllocationError),
    Mapping(MappingError),
    Irq(crate::bus::irq::IrqError),
    OriginalUsersUnavailable,
    ForeignOriginalUsers,
    SharedRegisters,
    Terminal,
    Clock(crate::ClockError),
}
/// A plain account for the boot log.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Pci(error) => return error.fmt(f),
            Self::Controller(error) => return error.fmt(f),
            Self::Preparation(error) => return error.fmt(f),
            Self::Dma(error) => return error.fmt(f),
            Self::Allocation(error) => return error.fmt(f),
            Self::Mapping(error) => return error.fmt(f),
            Self::Irq(error) => return error.fmt(f),
            Self::OriginalUsersUnavailable => {
                "nothing can prove its firmware interrupt users are finished"
            }
            Self::ForeignOriginalUsers => {
                "its firmware interrupt users were recorded for another configuration"
            }
            Self::SharedRegisters => "its registers are still shared",
            Self::Terminal => "an earlier failure stopped it",
            Self::Clock(error) => return error.fmt(f),
        })
    }
}

impl From<hda::pci::AttachError> for Error {
    fn from(e: hda::pci::AttachError) -> Self {
        Self::Pci(e)
    }
}
impl From<audio::Error> for Error {
    fn from(e: audio::Error) -> Self {
        Self::Controller(e)
    }
}

/// No native producer exists yet. A real producer must retire original
/// firmware IRQ delivery (INTx/MSI), CPU/EOI/service/work and competing users
/// through the exact original root/configuration/routing epoch. EBS, source
/// masks, PCI Transactions Pending and polled-driver absence cannot construct
/// this capability. Only the test module creates diagnostic model inputs.
pub(super) struct OriginalUsers {
    retained: ConfigRetention,
}

#[cfg(test)]
impl OriginalUsers {
    /// # Safety
    /// Diagnostic-only acknowledgement of independently retired symbolic
    /// firmware/root/IRQ/EOI/work users in the same isolated fixture epoch.
    unsafe fn diagnostic(retained: ConfigRetention) -> Self {
        Self { retained }
    }
}

/// # Safety
/// The original provider owns exact UC BAR0/native widths and keeps actual
/// mapping/reservation/backing while shared accessors exist. Failed retirement
/// and Drop cannot release uncertain resources; retirement admits the original
/// CPU/process context and requires independent full hardware/root/user stop.
pub(super) unsafe trait NativeRegisters: hda::Registers {
    /// # Safety
    /// All DMA/root/IRQ/work/CPU users are retired and its unique requester
    /// Attachment detached. The original graph remains kept on every error.
    unsafe fn retire(&mut self) -> Result<(), MappingError>;
}

pub(super) struct Inputs<R, T> {
    pub requester: PreparingRequester,
    pub registers: R,
    pub clock: T,
    pub pages: &'static dyn PageSource,
    pub bar: Bar,
    pub original_users: Option<OriginalUsers>,
}
struct Shared<R>(Rc<RefCell<R>>);
impl<R> Clone for Shared<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<R: hda::Registers> hda::Registers for Shared<R> {
    fn region_bytes(&self) -> usize {
        self.0.borrow().region_bytes()
    }
    fn validate_config(&self, c: &hda::Config) -> Result<(), audio::Error> {
        self.0.borrow().validate_config(c)
    }
    fn codec_pci_subsystem(&mut self) -> Result<Option<u32>, audio::Error> {
        self.0.borrow_mut().codec_pci_subsystem()
    }
    fn reset_clock_gate(&mut self, e: bool) -> Result<(), audio::Error> {
        self.0.borrow_mut().reset_clock_gate(e)
    }
    fn read8(&mut self, o: usize) -> u8 {
        self.0.borrow_mut().read8(o)
    }
    fn read16(&mut self, o: usize) -> u16 {
        self.0.borrow_mut().read16(o)
    }
    fn read32(&mut self, o: usize) -> u32 {
        self.0.borrow_mut().read32(o)
    }
    fn write8(&mut self, o: usize, v: u8) {
        self.0.borrow_mut().write8(o, v);
    }
    fn write16(&mut self, o: usize, v: u16) {
        self.0.borrow_mut().write16(o, v);
    }
    fn write32(&mut self, o: usize, v: u32) {
        self.0.borrow_mut().write32(o, v);
    }
}
type Pci<R> = hda::pci::PciRegisters<Shared<R>, Box<Function<OwnedConfig>>>;
type Core<R, T> = hda::Controller<Shared<Pci<R>>, T>;
type BindingFailure<R> = hda::pci::BindingFailure<Shared<R>, Box<Function<OwnedConfig>>>;

/// Keep the actual legacy allocator error even though the protocol core's
/// historical error type only reports NoDmaMemory.
struct RecordingAllocator<'a> {
    inner: &'a mut DomainAllocator<'static>,
    failure: Option<AllocationError>,
}
impl crate::bus::dma::DmaAllocator for RecordingAllocator<'_> {
    fn allocate(
        &mut self,
        bytes: usize,
        align: usize,
    ) -> Result<crate::bus::dma::DmaBuffer, crate::block::BlockError> {
        let result = self.inner.allocate(bytes, align);
        if let Err(crate::block::BlockError::Dma(error)) = &result {
            self.failure.get_or_insert(*error);
        }
        result
    }
}

struct Resources<R, T> {
    requester: Option<PreparingRequester>,
    registers: Rc<RefCell<R>>,
    clock: T,
    pages: &'static dyn PageSource,
    bar: Bar,
    original_users: Option<OriginalUsers>,
    attachment: Option<Attachment>,
    pci: Option<Rc<RefCell<Pci<R>>>>,
    controller: Option<Core<R, T>>,
    dma: Option<DomainAllocator<'static>>,
    config: Option<hda::Config>,
    _root_failure: Option<preparation::Failure>,
    _binding_failure: Option<BindingFailure<R>>,
    _construction_failure: Option<hda::ConstructionFailure<Shared<Pci<R>>, T>>,
    retiring_function: Option<Box<Function<OwnedConfig>>>,
    _pin_failure: Option<preparation::PinReleaseFailure>,
}
struct Owner<R, T>(Option<Box<Resources<R, T>>>);
impl<R, T> Drop for Owner<R, T> {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
impl<R, T> Owner<R, T> {
    fn resources(&mut self) -> &mut Resources<R, T> {
        self.0.as_deref_mut().expect("original HDA owner")
    }
}
pub(super) struct Failure<R, T> {
    pub error: Error,
    _owner: Owner<R, T>,
}
impl<R, T> Failure<R, T> {
    pub(super) fn construction_error(&self) -> Option<&crate::block::BlockError> {
        self._owner
            .0
            .as_ref()?
            ._construction_failure
            .as_ref()?
            .owner
            .allocation_error
            .as_ref()
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Active,
    Starting,
    Closing,
    Failed,
    Retired,
}
pub(super) struct Native<R, T> {
    owner: Owner<R, T>,
    phase: Phase,
    error: Option<Error>,
    discovery_attempted: bool,
}
pub(super) struct Discovery {
    pub codecs: Vec<Codec>,
    pub codec_failures: Vec<hda::CodecFailure>,
    pub discovery_error: Option<audio::Error>,
}
impl<R: NativeRegisters, T: audio::Timer + Clone> Native<R, T> {
    pub fn new(inputs: Inputs<R, T>) -> Result<Self, Failure<R, T>> {
        let Inputs {
            requester,
            registers,
            clock,
            pages,
            bar,
            original_users,
        } = inputs;
        let mut owner = Owner(Some(Box::new(Resources {
            requester: Some(requester),
            registers: Rc::new(RefCell::new(registers)),
            clock,
            pages,
            bar,
            original_users,
            attachment: None,
            pci: None,
            controller: None,
            dma: None,
            config: None,
            _root_failure: None,
            _binding_failure: None,
            _construction_failure: None,
            retiring_function: None,
            _pin_failure: None,
        })));
        let result = Self::prepare(owner.resources());
        match result {
            Ok(()) => Ok(Self {
                owner,
                phase: Phase::Active,
                error: None,
                discovery_attempted: false,
            }),
            Err(error) => Err(Failure {
                error,
                _owner: owner,
            }),
        }
    }
    fn prepare(r: &mut Resources<R, T>) -> Result<(), Error> {
        crate::bus::pci::power::Timer::check(&r.clock)
            .map_err(|error| Error::Controller(audio::Error::MinimumDelay(error)))?;
        let requester = r.requester.as_mut().unwrap();
        if let Some(users) = &r.original_users
            && !requester
                .function_mut()
                .config()
                .matches_retention(&users.retained)
                .map_err(Error::Mapping)?
        {
            return Err(Error::ForeignOriginalUsers);
        }
        // SAFETY: actual original requester/root, exact kept BAR provider and
        // exclusive conventional/D0/decode/firmware exclusion are constructor
        // prerequisites. No private bind/new DMA occurs in this cold stage.
        let mut registers = unsafe {
            hda::pci::prepare_cold_with_registers(
                requester.function_mut(),
                r.bar,
                &r.clock,
                hda::pci::Ownership::ExclusiveLegacy,
                Shared(r.registers.clone()),
            )
        }?;
        let config = registers.config();
        let stopped = hda::cold::stop_inherited(&mut registers, &r.clock, &config)?;
        let (prepared, _, _) = registers.into_parts();
        // Source stop/masks above do not establish original IRQ ingress, EOI,
        // firmware or deferred-service completion. Native has no producer;
        // retain the complete original graph and refuse instead of binding.
        if r.original_users.is_none() {
            return Err(Error::OriginalUsersUnavailable);
        }
        let requester = r.requester.take().unwrap();
        // SAFETY: same-owner full inherited hardware stop just acknowledged;
        // independent OriginalUsers supplies prior IRQ/CPU/EOI/firmware/work
        // retirement. Root/config/BAR/inherited backing remain kept, with
        // bypass and competing reset/config/routing users excluded.
        let bound = match unsafe { requester.acknowledge_quiescence() }.finalize() {
            Ok(bound) => bound,
            Err(failure) => {
                let error = Error::Preparation(failure.error);
                r._root_failure = Some(failure);
                return Err(error);
            }
        };
        r.attachment = Some(bound.attachment);
        // SAFETY: paired original bound config and unchanged exact BAR provider.
        let pci = match unsafe {
            prepared.bind_owned_registers(
                Box::new(bound.requester.into_function()),
                Shared(r.registers.clone()),
            )
        } {
            Ok(pci) => pci,
            Err(failure) => {
                let error = Error::Pci(failure.error);
                r._binding_failure = Some(failure);
                return Err(error);
            }
        };
        r.pci = Some(Rc::new(RefCell::new(pci)));
        // SAFETY: inherited hardware and original users/root retired, exact
        // unique private Attachment now exists, and new DMA is not published.
        unsafe { r.pci.as_ref().unwrap().borrow_mut().set_bus_master(true) }?;
        let domain = r.attachment.as_ref().unwrap().domain();
        // SAFETY: actual paired coherent attached requester, original owners
        // and native source-selected snoop/IOVA limit remain kept in this graph.
        r.dma = Some(unsafe {
            DomainAllocator::new(
                r.pages,
                domain,
                u64::MAX >> (64 - u32::from(config.dma_address_bits)),
            )
        });
        r.config = Some(config);
        // Actual register/DMA owners remain in r across constructor failure or
        // callback unwind; dropping its private Shared accessor releases none.
        let mut allocator = RecordingAllocator {
            inner: r.dma.as_mut().unwrap(),
            failure: None,
        };
        // SAFETY: this stopped observation belongs to this exact original
        // owner, original root drain completed before private bind/allocation.
        let controller = unsafe {
            hda::Controller::new_after_stop(
                Shared(r.pci.as_ref().unwrap().clone()),
                r.clock.clone(),
                &mut allocator,
                config,
                stopped,
            )
        };
        let controller = match controller {
            Ok(controller) => controller,
            Err(failure) => {
                let error = allocator
                    .failure
                    .map_or(Error::Controller(failure.error), Error::Allocation);
                r._construction_failure = Some(failure);
                return Err(error);
            }
        };
        r.controller = Some(controller);
        Ok(())
    }
    fn admit(&self) -> Result<(), Error> {
        if self.phase != Phase::Active {
            return Err(self.error.unwrap_or(Error::Terminal));
        }
        Ok(())
    }
    pub fn discover_and_setup(&mut self) -> Result<Discovery, Error> {
        self.admit()?;
        if self.discovery_attempted {
            self.phase = Phase::Failed;
            self.error = Some(Error::Terminal);
            return Err(Error::Terminal);
        }
        self.discovery_attempted = true;
        // A caught protocol callback unwind cannot reopen close/discovery.
        self.phase = Phase::Starting;
        let result = (|| -> Result<Discovery, Error> {
            let controller = self.owner.resources().controller.as_mut().unwrap();
            let discovered = controller.discover_codecs();
            let (graphs, codec_failures, discovery_error) = match discovered {
                Ok(d) => (d.codecs, d.failures, None),
                Err(f) => return Err(Error::Controller(f.error)),
            };
            if let Some(error) = controller.first_effect_error() {
                return Err(Error::Controller(error));
            }
            let mut codecs = Vec::new();
            for graph in graphs {
                let setup = controller.initialize_codec(&graph);
                if let Some(fence) = controller.first_effect_error() {
                    // Preserve the operation's original primary cause. The
                    // actual core still holds reset_error/reset_cleanup_error.
                    return Err(Error::Controller(
                        setup.as_ref().err().copied().unwrap_or(fence),
                    ));
                }
                codecs.push(Codec { graph, setup });
            }
            Ok(Discovery {
                codecs,
                codec_failures,
                discovery_error,
            })
        })();
        match result {
            Ok(discovery) => {
                self.phase = Phase::Active;
                Ok(discovery)
            }
            Err(error) => {
                self.phase = Phase::Failed;
                let first = *self.error.get_or_insert(error);
                Err(first)
            }
        }
    }
    pub fn close(&mut self) -> Result<(), Error> {
        self.admit()?;
        // Admission closes BEFORE any protocol/MMIO callback. Unwind leaves
        // Closing terminal; error preserves its first causal details and owner.
        self.phase = Phase::Closing;
        let result = Self::close_inner(self.owner.resources());
        match result {
            Ok(()) => {
                self.phase = Phase::Retired;
                drop(self.owner.0.take());
                Ok(())
            }
            Err(error) => {
                self.phase = Phase::Failed;
                self.error = Some(error);
                Err(error)
            }
        }
    }
    fn close_inner(r: &mut Resources<R, T>) -> Result<(), Error> {
        r.controller.as_mut().unwrap().shutdown()?;
        // Independently read back complete engine/source containment, not a
        // stale software stopped bit. INTCTL/WAKEEN and PCI MSI/MSIX remained
        // disabled in this private polled lifecycle; no Stela IRQ/work users
        // can exist because neither core nor DMA provider escapes this owner.
        hda::cold::stop_inherited(
            &mut *r.pci.as_ref().unwrap().borrow_mut(),
            &r.clock,
            &r.config.unwrap(),
        )?;
        // SAFETY: acknowledged current hardware/source stop, no restart, and
        // actual original owners/Attachment retained.
        unsafe { r.pci.as_ref().unwrap().borrow_mut().set_bus_master(false) }?;
        // SAFETY: same unique current domain, actual payload stop acknowledged
        // above, original backing/config/BAR and old-user capability stay held.
        unsafe {
            r.attachment
                .as_ref()
                .unwrap()
                .domain()
                .drain_posted_writes()
        }
        .map_err(Error::Dma)?;
        r.attachment
            .as_ref()
            .unwrap()
            .validate_irq_actions()
            .map_err(Error::Irq)?;
        let controller = r.controller.take().unwrap();
        // SAFETY: full payload completion plus source/IRQ/CPU/service/work
        // exclusion through this exact owner; no buffer/reference escapes.
        match unsafe { controller.into_shutdown_resources() } {
            Ok((access, _clock)) => drop(access),
            Err(controller) => {
                r.controller = Some(*controller);
                return Err(Error::Controller(audio::Error::NeedsReset));
            }
        }
        // SAFETY: every coherent buffer reference was consumed only after all
        // required hardware/root/users completed; same allocator/owner/context.
        unsafe { r.dma.as_mut().unwrap().retire() }.map_err(Error::Allocation)?;
        // SAFETY: exact stopped/drained current epoch and original users kept;
        // Attachment independently refuses any surviving mapping before effects.
        let detached = unsafe { r.attachment.as_mut().unwrap().detach() }.map_err(Error::Dma)?;
        if let Err(failed) = r.attachment.as_mut().unwrap().release_irq_pins(detached) {
            let error = Error::Irq(failed.error);
            r._pin_failure = Some(failed);
            return Err(error);
        }
        drop(r.original_users.take());
        let pci = r.pci.take().unwrap();
        let pci = match Rc::try_unwrap(pci) {
            Ok(pci) => pci.into_inner(),
            Err(pci) => {
                r.pci = Some(pci);
                return Err(Error::SharedRegisters);
            }
        };
        let (_, function, bar_access) = pci.into_parts();
        drop(bar_access);
        r.retiring_function = Some(function);
        // SAFETY: all current users/leases and unique Attachment retired. Both
        // mappings remain in this retaining outer graph on errors and unwind.
        unsafe { r.registers.borrow_mut().retire() }.map_err(Error::Mapping)?;
        // SAFETY: same completed final retirement, actual config pin released
        // only after Attachment.detach; external pins correctly refuse here.
        unsafe { r.retiring_function.as_mut().unwrap().config().retire() }
            .map_err(Error::Mapping)?;
        Ok(())
    }
}
// SAFETY: Bar0 owns the exact native Mapping with checked UC/native widths.
// Retirement delegates actual acknowledged unmap; failure/Drop quarantine it.
unsafe impl NativeRegisters for Bar0 {
    unsafe fn retire(&mut self) -> Result<(), MappingError> {
        // SAFETY: forwarded completed native owner/drain/unique detach contract.
        unsafe { self.mapping.retire() }
    }
}

#[cfg(test)]
mod tests;
