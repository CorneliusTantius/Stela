//! The hand-over against services that behave as the boot image's do: the
//! function comes only from `prepare_requester`, and every other grant the
//! boot refuses is refused.
extern crate std;
use super::*;
use crate::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DmaError, DomainMapping},
        memory::{CacheAttribute, MemoryError, PageSource, PinnedPages},
        pages::DmaPages,
    },
    irq::IrqController,
    pci::{
        ConfigSpace,
        owned::test_support::fixture,
        requester::{
            FunctionRole, RequesterBinding,
            preparation::{AttachmentBackend, PreparingRequester, Root},
        },
    },
};
use alloc::{string::String, vec::Vec};
use core::{cell::RefCell, ops::Range};
use std::sync::Mutex;

pub(crate) const ADDRESS: Address = Address {
    segment: 0,
    bus: 4,
    device: 0,
    function: 0,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    Prepare,
    Admit,
    Stop { command: u16 },
    Drain,
    Bind,
    MapBar,
    RootDrop,
}

pub(crate) type Log = Arc<Mutex<Vec<Event>>>;

struct ModelRoot(Log);
impl Drop for ModelRoot {
    fn drop(&mut self) {
        self.0.lock().unwrap().push(Event::RootDrop);
    }
}
// SAFETY: a symbolic root over a hosted configuration fixture; nothing here
// reaches hardware.
unsafe impl Root for ModelRoot {
    fn drain(&self) -> Result<(), DmaError> {
        self.0.lock().unwrap().push(Event::Drain);
        Ok(())
    }
    unsafe fn bind(
        &self,
        binding: RequesterBinding,
    ) -> Result<Box<dyn AttachmentBackend>, DmaError> {
        self.0.lock().unwrap().push(Event::Bind);
        Ok(Box::new(Bound(Some(binding))))
    }
}

struct Bound(Option<RequesterBinding>);
impl Drop for Bound {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
// SAFETY: the symbolic domain maps nothing.
unsafe impl AttachmentBackend for Bound {
    fn domain(&self) -> Arc<dyn DmaDomain> {
        Arc::new(NoDma)
    }
    unsafe fn detach(&mut self) -> Result<(), preparation::DetachError> {
        Ok(())
    }
}

struct NoDma;
// SAFETY: every mapping is refused.
unsafe impl DmaDomain for NoDma {
    unsafe fn map(&self, _: &DmaPages, _: Direction, _: u64) -> Result<DomainMapping, DmaError> {
        Err(DmaError::MappingFailed)
    }
    unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
    unsafe fn sync_for_device(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        Ok(())
    }
}

struct NoPages;
impl PageSource for NoPages {
    fn allocate(&self, _: usize, _: usize, _: CacheAttribute) -> Result<PinnedPages, MemoryError> {
        Err(MemoryError::Unavailable)
    }
}

/// Services as the boot image supplies them: a requester only through
/// preparation over the function's own configuration, and no BAR mapping
/// for a function whose BARs the model does not decode.
pub(crate) struct BootServices {
    pub log: Log,
    /// Vendor, device and class of the modeled function.
    pub identity: (u16, u16, [u8; 3]),
    pub prepared: RefCell<bool>,
}

impl BootServices {
    pub(crate) fn new(vendor: u16, device: u16, class: [u8; 3]) -> Self {
        Self {
            log: Arc::default(),
            identity: (vendor, device, class),
            prepared: RefCell::new(false),
        }
    }
    pub(crate) fn events(&self) -> Vec<Event> {
        self.log.lock().unwrap().clone()
    }
}

// SAFETY: the one requester is a hosted configuration fixture with a symbolic
// root; every other grant is refused, as the boot refuses it.
unsafe impl NativeServices for BootServices {
    fn minimum_delay(&self) -> Result<Rc<dyn crate::bus::pci::power::Timer>, ServiceError> {
        Ok(crate::minimum_model::owned(crate::Clock {
            ticks_per_microsecond: 1000,
        }))
    }
    fn prepare_requester(&self, address: Address) -> Result<PreparingRequester, ServiceError> {
        assert_eq!(address, ADDRESS);
        assert!(!self.prepared.replace(true), "one preparation per function");
        self.log.lock().unwrap().push(Event::Prepare);
        let (vendor, device, class) = self.identity;
        let (mut config, _) = fixture(address);
        config
            .write32(0, u32::from(device) << 16 | u32::from(vendor))
            .unwrap();
        config
            .write32(8, u32::from_be_bytes([class[0], class[1], class[2], 1]))
            .unwrap();
        config.write16(regs::COMMAND, 0).unwrap();
        let function = Function::new(address, config).unwrap();
        // SAFETY: the hosted fixture and symbolic root belong to this test.
        unsafe {
            PreparingRequester::new(
                function,
                FunctionRole::Physical,
                Box::new(ModelRoot(self.log.clone())),
            )
        }
        .map_err(|rejected| ServiceError::Claim(rejected.error))
    }
    fn bridge(&self, _: Address) -> Result<Function<OwnedConfig>, ServiceError> {
        Err(ServiceError::Refused(
            "native bridge forwarding handoff unavailable",
        ))
    }
    fn map_bar(&self, _: Address, _: Bar) -> Result<Mapping, ServiceError> {
        self.log.lock().unwrap().push(Event::MapBar);
        Err(ServiceError::Refused("the model decodes no BAR"))
    }
    fn bar_resource(&self, _: Address, _: Bar) -> Result<owned::Resource, ServiceError> {
        Err(ServiceError::Refused("the model decodes no BAR"))
    }
    fn authority(&self) -> Result<owned::Authority, ServiceError> {
        Err(ServiceError::Unavailable)
    }
    fn interrupts(&self) -> Result<&'static dyn IrqController, ServiceError> {
        Err(ServiceError::Unavailable)
    }
    fn pages(&self) -> &'static dyn PageSource {
        &NoPages
    }
    #[cfg(feature = "native-acpi")]
    fn acpi_memory(
        &self,
        _: &crate::platform::acpi::resources::DeviceResources<'_>,
        _: usize,
    ) -> Result<owned::Resource, ServiceError> {
        Err(ServiceError::Unavailable)
    }
    #[cfg(feature = "native-acpi")]
    fn acpi(&self) -> Option<&'static crate::platform::acpi::Session> {
        None
    }
    #[cfg(feature = "native-acpi")]
    fn firmware_memory(&self, _: u64, _: usize) -> Result<NonNull<u8>, ServiceError> {
        Err(ServiceError::Unavailable)
    }
}

/// A stop that records what it saw.
struct Recording {
    log: Log,
    refuse: bool,
    fail: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum TestError {
    HandOver(String),
    Refused,
    Stop,
}

impl From<HandOverError> for TestError {
    fn from(error: HandOverError) -> Self {
        Self::HandOver(alloc::format!("{error}"))
    }
}

impl ColdStop for Recording {
    type Error = TestError;
    const BAR: Option<usize> = None;
    fn admit(&mut self, _: &mut Function<OwnedConfig>) -> Result<(), TestError> {
        self.log.lock().unwrap().push(Event::Admit);
        if self.refuse {
            Err(TestError::Refused)
        } else {
            Ok(())
        }
    }
    unsafe fn stop(
        &mut self,
        function: &mut Function<OwnedConfig>,
        window: Option<Window>,
    ) -> Result<(), TestError> {
        assert!(window.is_none());
        let command = function.config().read16(regs::COMMAND).unwrap();
        // Bus mastering stays sealed off through the stop.
        assert!(
            function
                .config()
                .write16(regs::COMMAND, command | regs::COMMAND_MASTER)
                .is_err()
        );
        self.log.lock().unwrap().push(Event::Stop { command });
        if self.fail {
            Err(TestError::Stop)
        } else {
            Ok(())
        }
    }
}

#[test]
fn a_function_is_prepared_admitted_stopped_and_only_then_drained_and_bound() {
    let services = BootServices::new(0x8086, 0x1234, [0x0c, 0x05, 0]);
    let mut stop = Recording {
        log: services.log.clone(),
        refuse: false,
        fail: false,
    };
    // SAFETY: the services are this test's model.
    let Ok(handed) = (unsafe { hand_over(&services, ADDRESS, &mut stop) }) else {
        panic!("the hand-over completes");
    };
    assert_eq!(
        services.events(),
        [
            Event::Prepare,
            Event::Admit,
            Event::Stop {
                command: regs::COMMAND_INTX_DISABLE
            },
            Event::Drain,
            Event::Bind,
        ]
    );
    assert!(handed.registers.is_none());
    let mut function = handed.requester.into_function();
    // The bound function may master again.
    function.enable_polled().unwrap();
    drop((function, handed.attachment));
}

#[test]
fn a_refused_or_failed_stop_never_drains_or_binds_and_keeps_the_original_root() {
    for (refuse, fail, error) in [
        (true, false, TestError::Refused),
        (false, true, TestError::Stop),
    ] {
        let services = BootServices::new(0x8086, 0x1234, [0x0c, 0x05, 0]);
        let mut stop = Recording {
            log: services.log.clone(),
            refuse,
            fail,
        };
        // SAFETY: the services are this test's model.
        let Err((actual, owner)) = (unsafe { hand_over(&services, ADDRESS, &mut stop) }) else {
            panic!("the hand-over fails");
        };
        assert_eq!(actual, error);
        drop(owner);
        let events = services.events();
        assert!(!events.contains(&Event::Drain), "{events:?}");
        assert!(!events.contains(&Event::Bind));
        assert!(
            !events.contains(&Event::RootDrop),
            "the original root stays held"
        );
    }
}
