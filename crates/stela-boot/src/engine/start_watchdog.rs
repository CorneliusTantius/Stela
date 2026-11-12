//! The device-start watchdog on the processor that starts the PC's devices
//! (`stela_boot_core::start_watchdog`): enabled once before the scan,
//! armed as each PCI function's driver starts, disarmed once its start
//! ends and back as the firmware left it when device start ends. Its NMI
//! ([`fired`]) names the device, its driver and where it stopped, on the
//! serial port and the screen, through lock-free paths only, and halts:
//! the device's start marker is already on the USB, so the next boot skips
//! it.
use super::interrupts::Frame;
use crate::{cpu::msr, output};
use core::{
    arch::x86_64::{__cpuid, __cpuid_count},
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use stela_boot_core::{
    apic::{self, Apic},
    start_watchdog::{
        Cpuid, Hardware, LVT_PERFORMANCE, Line, Rate, Started, Stopped, Watchdog, report,
    },
};

/// What a healthy start may take after its budget: its cleanup, whose
/// waits each still run in full (`stela_drivers::budget::Bounded`).
const MARGIN_US: u64 = 30_000_000;

/// Written by the starting processor only, while [`ENABLED`] does not name
/// it ([`WATCHDOG`]) or [`ARMED`] is clear ([`STARTED`]); read by its NMI.
struct Slot<T>(UnsafeCell<T>);
// SAFETY: as above: one writer, which its own NMI interrupts, never another
// processor.
unsafe impl<T> Sync for Slot<T> {}

static WATCHDOG: Slot<Option<Watchdog>> = Slot(UnsafeCell::new(None));
static STARTED: Slot<Option<Started>> = Slot(UnsafeCell::new(None));
/// The GS base of the processor the watchdog is enabled on; 0 for none.
static ENABLED: AtomicU64 = AtomicU64::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
/// The watchdog stopped the boot: a later stop elsewhere keeps its report.
static FIRED: AtomicBool = AtomicBool::new(false);

fn gs() -> u64 {
    // SAFETY: read-only architectural CPL0 GS context.
    unsafe { msr::GS_BASE.read() }
}

/// This processor's MSRs, through the probing RDMSR and WRMSR that answer a
/// #GP (`host::pmu`), and its local APIC.
struct Processor {
    apic: Apic,
    tsc_hz: u64,
}

impl Processor {
    fn here(tsc_hz: u64) -> Self {
        // SAFETY: IA32_APIC_BASE, read-only.
        let base = unsafe { msr::APIC_BASE.read() };
        Self {
            apic: Apic::new(base, crate::layout::physical(base & apic::BASE_ADDRESS)),
            tsc_hz,
        }
    }
}

impl Hardware for Processor {
    fn read_msr(&mut self, index: u32) -> Option<u64> {
        super::host::pmu::read(index)
    }
    fn write_msr(&mut self, index: u32, value: u64) -> bool {
        super::host::pmu::write(index, value)
    }
    fn read_lvt(&mut self) -> u32 {
        self.apic.read(LVT_PERFORMANCE)
    }
    fn write_lvt(&mut self, value: u32) {
        self.apic.write(LVT_PERFORMANCE, value);
    }
    fn tsc(&mut self) -> u64 {
        stela_drivers::Clock::ticks()
    }
    fn spin(&mut self) {
        let ticks = (self.tsc_hz / 10_000).max(10_000);
        let started = stela_drivers::Clock::ticks();
        while stela_drivers::Clock::ticks().wrapping_sub(started) < ticks {
            core::hint::spin_loop();
        }
    }
}

fn cpuid() -> Cpuid {
    let leaf0 = __cpuid(0);
    let max_extended = __cpuid(0x8000_0000).eax;
    let perfmon = if leaf0.eax >= 0xa {
        let leaf = __cpuid_count(0xa, 0);
        [leaf.eax, leaf.ebx]
    } else {
        [0, 0]
    };
    let perfmon_v2 = if max_extended >= 0x8000_0022 {
        let leaf = __cpuid(0x8000_0022);
        [leaf.eax, leaf.ebx]
    } else {
        [0, 0]
    };
    Cpuid {
        vendor: [leaf0.ebx, leaf0.edx, leaf0.ecx],
        max_basic: leaf0.eax,
        leaf1_ecx: __cpuid(1).ecx,
        perfmon,
        max_extended,
        extended1_ecx: if max_extended >= 0x8000_0001 {
            __cpuid(0x8000_0001).ecx
        } else {
            0
        },
        perfmon_v2,
    }
}

/// Take a counter on this processor before the scan, or say once why no
/// start is bounded.
pub(super) fn enable(tsc_hz: u64) {
    let mut processor = Processor::here(tsc_hz);
    let budget = stela_drivers::probe::DEVICE_START_US;
    match Watchdog::enable(&cpuid(), budget, MARGIN_US, tsc_hz, &mut processor) {
        Ok(watchdog) => {
            // SAFETY: ENABLED does not name this processor yet: its NMI
            // reads no slot.
            unsafe { *WATCHDOG.0.get() = Some(watchdog) };
            ENABLED.store(gs(), Ordering::Release);
            let plan = watchdog.plan;
            let (counts, hz, latest) = match plan.rate {
                Rate::Fixed(hz) => ("reference cycles at a measured", hz, ""),
                Rate::Core(hz) => (
                    "core cycles against a ceiling of",
                    hz,
                    " on a core at the TSC's rate, later on a slower one",
                ),
            };
            output::arguments(format_args!(
                "HOST DEVICE WATCHDOG on: counter MSR {:#x} counts {counts} {} kHz; a start is \
                 stopped at the earliest {} s, at the latest {} s{latest}, of unhalted time \
                 after it begins\n",
                watchdog.counter.counter,
                hz / 1_000,
                plan.least_us() / 1_000_000,
                plan.latest_us().div_ceil(1_000_000)
            ));
        }
        Err(why) => output::arguments(format_args!(
            "HOST DEVICE WATCHDOG off: {why}; a device start that never ends is not bounded\n"
        )),
    }
}

/// The watchdog of this processor, when it has one.
fn here() -> Option<Watchdog> {
    if ENABLED.load(Ordering::Acquire) != gs() {
        return None;
    }
    // SAFETY: ENABLED names this processor, so only it writes the slot,
    // and it does not now.
    unsafe { *WATCHDOG.0.get() }
}

/// Arm for the start of `function`, whose driver runs next.
pub(super) fn arm(function: &stela_drivers::bus::pci::Identity) {
    let Some(watchdog) = here() else {
        return;
    };
    let started = Started {
        segment: function.address.segment,
        bus: function.address.bus,
        device: function.address.device,
        function: function.address.function,
        vendor: function.vendor,
        id: function.device,
        driver: stela_drivers::probe::driver_name(function),
    };
    ARMED.store(false, Ordering::Release);
    // SAFETY: ARMED is clear: this processor's NMI reads no `STARTED`.
    unsafe { *STARTED.0.get() = Some(started) };
    let mut processor = Processor::here(0);
    ARMED.store(true, Ordering::Release);
    if !watchdog.arm(&mut processor) {
        ARMED.store(false, Ordering::Release);
    }
}

/// The start armed for has ended.
pub(super) fn disarm() {
    let Some(watchdog) = here() else {
        return;
    };
    watchdog.disarm(&mut Processor::here(0));
    ARMED.store(false, Ordering::Release);
}

/// Device start has ended: the counter and the APIC entry as the firmware
/// left them.
pub(super) fn finish() {
    let Some(watchdog) = here() else {
        return;
    };
    ARMED.store(false, Ordering::Release);
    watchdog.finish(&mut Processor::here(0));
    ENABLED.store(0, Ordering::Release);
}

/// Whether the watchdog stopped the boot, whose report a later stop keeps.
pub(crate) fn stopped() -> bool {
    FIRED.load(Ordering::Acquire)
}

/// An NMI: when it is this processor's armed watchdog whose counter
/// overflowed, report the start it ended and halt; otherwise return, for
/// the NMI's usual stop.
pub(crate) fn fired(frame: &Frame) {
    if !ARMED.load(Ordering::Acquire) {
        return;
    }
    let Some(watchdog) = here() else {
        return;
    };
    let mut processor = Processor::here(0);
    if !watchdog.overflowed(&mut processor) {
        return;
    }
    watchdog.disarm(&mut processor);
    // SAFETY: ARMED was set after the slot was written, and its writer is
    // the processor this NMI interrupted.
    let Some(started) = (unsafe { *STARTED.0.get() }) else {
        return;
    };
    FIRED.store(true, Ordering::Release);
    unsafe extern "C" {
        static __ImageBase: u8;
    }
    let step = stela_drivers::budget::passed_step().map(|step| (step.file(), step.line()));
    let mut bytes = [0u8; 768];
    let mut line = Line::new(&mut bytes);
    report(
        &mut line,
        &started,
        &watchdog.plan,
        &Stopped {
            step,
            image_offset: frame.rip.wrapping_sub(&raw const __ImageBase as u64),
        },
    );
    let text = line.as_str();
    {
        use core::fmt::Write;
        let _ = writeln!(crate::serial::Serial, "\nSTELA FATAL {text}");
    }
    // Lock-free: the console is skipped while another use holds it.
    crate::console::reclaim();
    crate::console::write(&[("\n", crate::console::Color::Text)]);
    crate::console::rewrite_wrapped(&[(text, crate::console::Color::Fatal)], 2);
    output::halt_stopped()
}
