//! The device-start watchdog: one core performance counter on the starting
//! processor raises an NMI through the local APIC's performance-counter LVT
//! entry when a single PCI function's start outlasts its budget plus a
//! margin. A start whose driver is stuck where no budget check runs, such
//! as a loop without a wait, then ends the boot with the device named on the
//! screen instead of a silent hang.
//!
//! Two rates, the first the processor offers:
//!
//! - A fixed rate: Intel's architectural "UnHalted Reference Cycles" event
//!   (CPUID leaf 0Ah EBX[2] clear; event 3Ch, umask 01h), which counts
//!   reference cycles at a fixed frequency whatever the core's clock does.
//!   Which reference (the TSC, the core crystal or the bus clock) varies by
//!   processor, so its rate is measured against the TSC at [`Watchdog::enable`],
//!   the highest of several windows: a window the processor spent away (a
//!   hypervisor running another vCPU) only measures lower. The period is the
//!   budget plus margin at that rate, plus 1%: the start is stopped between
//!   60 s and 61 s of unhalted time.
//! - The core's own cycles, where no fixed-rate event exists: Intel's
//!   "UnHalted Core Cycles" (event 3Ch) and, on every AMD processor, PMCx076
//!   "cycles not in halt" (core performance counters, with the
//!   PerfCtrExtCore set when CPUID 8000_0001h ECX[23] offers it, and
//!   PerfMonV2's global control when CPUID 8000_0022h EAX[0] does). AMD's
//!   core counters have no fixed-rate event: MPERF counts at a fixed rate but
//!   raises no interrupt. The period is the budget plus margin at
//!   [`CEILING_HZ`], a clock no core runs at, so a core counts it no sooner
//!   than the budget plus margin; a slower core takes longer, which the log
//!   states as the latest time at the TSC's rate ([`Plan::latest_us`]).
//!
//! Never early: each start loads the counter afresh, so starts never add up;
//! a halted or descheduled processor counts less, never more; a healthy
//! start's waits end at its budget and its cleanup fits the margin; the
//! counter is disabled after each start and restored to what the firmware
//! left once device start ends.
//!
//! Counter writes: on Intel through IA32_A_PMCx when IA32_PERF_CAPABILITIES
//! bit 13 says those take full-width writes, else through IA32_PMCx, whose
//! period this module keeps under 2^31. Either way a written value must read
//! back unchanged, detected at run time, or the counter is refused.
//!
//! Without a usable counter the boot says once why and keeps no bound: no
//! performance monitoring (CPUID leaf 0Ah version 0, or a hypervisor that
//! offers none), counters the firmware is using (every candidate enabled), a
//! period the counter's writes cannot hold, or a counter that does not
//! count.
//!
//! Everything the NMI handler needs is plain data here, and its report is
//! formatted into a caller's buffer: the handler takes no lock and
//! allocates nothing.
use core::fmt::Write;

/// The architectural event select bits both vendors share.
const USR: u64 = 1 << 16;
const OS: u64 = 1 << 17;
const INT: u64 = 1 << 20;
const ENABLE: u64 = 1 << 22;

/// The local APIC's performance-counter LVT entry: NMI delivery, masked.
pub const LVT_PERFORMANCE: u32 = 0x340;
pub const LVT_NMI: u32 = 4 << 8;
pub const LVT_MASKED: u32 = 1 << 16;

const IA32_PERF_CAPABILITIES: u32 = 0x345;
const FULL_WIDTH_WRITES: u64 = 1 << 13;
const IA32_PMC0: u32 = 0xc1;
const IA32_PERFEVTSEL0: u32 = 0x186;
const IA32_A_PMC0: u32 = 0x4c1;
const IA32_PERF_GLOBAL_CTRL: u32 = 0x38f;
const AMD_PERF_CTL0: u32 = 0xc001_0000;
const AMD_PERF_CTR0: u32 = 0xc001_0004;
const AMD_PERF_CTL_EXT0: u32 = 0xc001_0200;
const AMD_PERF_CTR_EXT0: u32 = 0xc001_0201;
const AMD_GLOBAL_CTL: u32 = 0xc000_0301;

/// Intel's architectural events: unhalted core and reference cycles.
const CORE_CYCLES_INTEL: u64 = 0x3c;
const REFERENCE_CYCLES_INTEL: u64 = 0x013c;
const CORE_CYCLES_AMD: u64 = 0x76;

const AMD_VENDOR: [u32; 3] = [0x6874_7541, 0x6974_6e65, 0x444d_4163];
const HYGON_VENDOR: [u32; 3] = [0x6f67_7948, 0x656e_6975, 0x6e65_476e];
const INTEL_VENDOR: [u32; 3] = [0x756e_6547, 0x4965_6e69, 0x6c65_746e];

/// The lowest clock this watchdog takes no core to exceed: well above the
/// fastest x86 core's boost. Twice the TSC's rate when that is higher.
pub const CEILING_HZ: u64 = 8_000_000_000;

/// The windows a fixed rate is measured over; the highest counts.
const RATE_WINDOWS: usize = 5;

/// The CPUID values that decide the counter, read once on the starting
/// processor: leaf 0's vendor and maximum, leaf 1 ECX, leaf 0Ah and the
/// extended leaves 8000_0000h, 8000_0001h ECX and 8000_0022h.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cpuid {
    pub vendor: [u32; 3],
    pub max_basic: u32,
    pub leaf1_ecx: u32,
    /// Leaf 0Ah EAX and EBX.
    pub perfmon: [u32; 2],
    pub max_extended: u32,
    pub extended1_ecx: u32,
    /// Leaf 8000_0022h EAX and EBX.
    pub perfmon_v2: [u32; 2],
}

/// The MSRs and APIC entry the watchdog drives, the TSC and a short spin:
/// the boot's are the processor's own, the tests' a model.
pub trait Hardware {
    /// RDMSR, or `None` where it takes #GP.
    fn read_msr(&mut self, index: u32) -> Option<u64>;
    /// WRMSR; false where it takes #GP.
    fn write_msr(&mut self, index: u32, value: u64) -> bool;
    fn read_lvt(&mut self) -> u32;
    fn write_lvt(&mut self, value: u32);
    fn tsc(&mut self) -> u64;
    /// Run for about a hundred microseconds, unhalted.
    fn spin(&mut self);
}

/// Why the watchdog keeps no bound, said once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// No architectural performance monitoring, or none the vendor names.
    Absent,
    /// The cycle events are not offered.
    NoCycleEvent,
    /// The period does not fit what the counter's writes hold.
    NarrowWrites,
    /// Every candidate counter is already enabled, by the firmware.
    Owned,
    /// A counter write took #GP or did not read back.
    Refused,
    /// The counter did not count while the processor ran.
    NotCounting,
}

impl core::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Absent => "the processor offers no performance counters",
            Self::NoCycleEvent => "the processor's counters offer no cycle event",
            Self::NarrowWrites => "the performance counter's writes cannot hold a 60 s period",
            Self::Owned => "every performance counter is in use by the firmware",
            Self::Refused => "a performance counter refused its setting",
            Self::NotCounting => "the performance counter did not count",
        })
    }
}

/// What the counter counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rate {
    /// Reference cycles at a fixed rate, as measured, in hertz.
    Fixed(u64),
    /// The core's cycles, counted against a ceiling clock in hertz.
    Core(u64),
}

/// The counter one processor uses: its MSRs, width and select value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counter {
    pub select: u32,
    pub counter: u32,
    pub width: u32,
    /// The largest period its writes hold.
    pub most: u64,
    /// The global control MSR and this counter's bit in it.
    pub global: Option<(u32, u64)>,
    /// The event select value, without its enable and interrupt bits.
    pub event: u64,
    /// Whether the event counts at a fixed rate.
    pub fixed: bool,
}

/// Where the counter starts each device start, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub budget_us: u64,
    pub margin_us: u64,
    pub rate: Rate,
    /// The TSC's rate, for the latest time on a slow core.
    pub tsc_hz: u64,
    /// Counts from a start's arming to overflow.
    pub period: u64,
}

impl Plan {
    /// Count the budget plus margin at `rate`, with 1% more for a measured
    /// one.
    fn new(budget_us: u64, margin_us: u64, rate: Rate, tsc_hz: u64) -> Self {
        let us = u128::from(budget_us.saturating_add(margin_us));
        let period = match rate {
            Rate::Fixed(hz) => (us * u128::from(hz) * 101).div_ceil(100 * 1_000_000),
            Rate::Core(hz) => (us * u128::from(hz)).div_ceil(1_000_000),
        };
        Self {
            budget_us,
            margin_us,
            rate,
            tsc_hz,
            period: u64::try_from(period).unwrap_or(u64::MAX),
        }
    }

    fn hz(&self) -> u64 {
        match self.rate {
            Rate::Fixed(hz) | Rate::Core(hz) => hz.max(1),
        }
    }

    /// The least time, in microseconds, from arming to overflow: at a
    /// fixed rate, or on a core whose clock never exceeds the ceiling.
    pub fn least_us(&self) -> u64 {
        let least = u128::from(self.period) * 1_000_000 / u128::from(self.hz());
        u64::try_from(least).unwrap_or(u64::MAX)
    }

    /// The latest time, in microseconds, from arming to overflow on an
    /// unhalted processor: at a fixed rate the least, as measured; counting
    /// core cycles, on a core that runs at the TSC's rate.
    pub fn latest_us(&self) -> u64 {
        let hz = match self.rate {
            Rate::Fixed(hz) => hz,
            Rate::Core(_) => self.tsc_hz,
        };
        let latest = u128::from(self.period) * 1_000_000 / u128::from(hz.max(1));
        u64::try_from(latest).unwrap_or(u64::MAX)
    }
}

/// The counter for this processor, or why there is none.
fn counter(cpuid: &Cpuid, hardware: &mut dyn Hardware) -> Result<Counter, Unavailable> {
    let base = USR | OS;
    if cpuid.vendor == INTEL_VENDOR {
        if cpuid.max_basic < 0xa {
            return Err(Unavailable::Absent);
        }
        let [eax, ebx] = cpuid.perfmon;
        let version = eax & 0xff;
        let counters = (eax >> 8) & 0xff;
        let width = (eax >> 16) & 0xff;
        let known = (eax >> 24) & 0xff;
        if version == 0 || counters == 0 || width < 32 {
            return Err(Unavailable::Absent);
        }
        // EBX bit set, or past the known events: unavailable.
        let offered = |bit: u32| bit < known && ebx & (1 << bit) == 0;
        let (event, fixed) = if offered(2) {
            (REFERENCE_CYCLES_INTEL, true)
        } else if offered(0) {
            (CORE_CYCLES_INTEL, false)
        } else {
            return Err(Unavailable::NoCycleEvent);
        };
        // PDCM: IA32_PERF_CAPABILITIES exists.
        let capabilities = (cpuid.leaf1_ecx & (1 << 15) != 0)
            .then(|| hardware.read_msr(IA32_PERF_CAPABILITIES))
            .flatten()
            .unwrap_or(0);
        let (counter, most) = if capabilities & FULL_WIDTH_WRITES != 0 {
            (IA32_A_PMC0, 1 << (width - 1))
        } else {
            // IA32_PMCx sign-extends bit 31 of a write.
            (IA32_PMC0, 1 << 31)
        };
        let free = free_counter(hardware, counters.min(8), |index| IA32_PERFEVTSEL0 + index)?;
        Ok(Counter {
            select: IA32_PERFEVTSEL0 + free,
            counter: counter + free,
            width,
            most,
            global: (version >= 2).then_some((IA32_PERF_GLOBAL_CTRL, 1 << free)),
            event: event | base,
            fixed,
        })
    } else if cpuid.vendor == AMD_VENDOR || cpuid.vendor == HYGON_VENDOR {
        let extended = cpuid.max_extended >= 0x8000_0001 && cpuid.extended1_ecx & (1 << 23) != 0;
        let v2 = cpuid.max_extended >= 0x8000_0022 && cpuid.perfmon_v2[0] & 1 != 0;
        let (counters, select, counter, stride) = if extended {
            let counters = if v2 { cpuid.perfmon_v2[1] & 0xf } else { 6 };
            (counters, AMD_PERF_CTL_EXT0, AMD_PERF_CTR_EXT0, 2)
        } else {
            (4, AMD_PERF_CTL0, AMD_PERF_CTR0, 1)
        };
        if counters == 0 {
            return Err(Unavailable::Absent);
        }
        let free = free_counter(hardware, counters, |index| select + index * stride)?;
        Ok(Counter {
            select: select + free * stride,
            counter: counter + free * stride,
            width: 48,
            most: 1 << 47,
            global: v2.then_some((AMD_GLOBAL_CTL, 1 << free)),
            event: CORE_CYCLES_AMD | base,
            fixed: false,
        })
    } else {
        Err(Unavailable::Absent)
    }
}

/// The highest-numbered counter of `counters` whose select is not enabled:
/// one the firmware is not using, the last one Linux's scheduler would take.
fn free_counter(
    hardware: &mut dyn Hardware,
    counters: u32,
    select: impl Fn(u32) -> u32,
) -> Result<u32, Unavailable> {
    let mut refused = true;
    for index in (0..counters).rev() {
        match hardware.read_msr(select(index)) {
            Some(value) if value & ENABLE == 0 => return Ok(index),
            Some(_) => refused = false,
            None => {}
        }
    }
    Err(if refused {
        Unavailable::Refused
    } else {
        Unavailable::Owned
    })
}

/// What the firmware left, restored once device start ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Saved {
    select: u64,
    counter: u64,
    global: Option<u64>,
    lvt: u32,
}

/// The watchdog on one processor, between [`Watchdog::enable`] and
/// [`Watchdog::finish`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watchdog {
    pub counter: Counter,
    pub plan: Plan,
    saved: Saved,
}

impl Watchdog {
    /// Take a counter on this processor, check it counts and measure its
    /// rate when fixed; nothing is armed. On refusal nothing the firmware
    /// set is changed.
    pub fn enable(
        cpuid: &Cpuid,
        budget_us: u64,
        margin_us: u64,
        tsc_hz: u64,
        hardware: &mut dyn Hardware,
    ) -> Result<Self, Unavailable> {
        let counter = counter(cpuid, hardware)?;
        let saved = Saved {
            select: hardware
                .read_msr(counter.select)
                .ok_or(Unavailable::Refused)?,
            counter: hardware
                .read_msr(counter.counter)
                .ok_or(Unavailable::Refused)?,
            global: match counter.global {
                Some((msr, _)) => Some(hardware.read_msr(msr).ok_or(Unavailable::Refused)?),
                None => None,
            },
            lvt: hardware.read_lvt(),
        };
        let mut watchdog = Self {
            counter,
            plan: Plan::new(budget_us, margin_us, Rate::Core(0), tsc_hz),
            saved,
        };
        // Count without interrupting for a moment, from a value whose high
        // bits a narrow write would lose: the counter must count, and its
        // rate is measured.
        let start = (counter.most >> 1) | 1;
        let rate = watchdog.measure(hardware, start, tsc_hz);
        watchdog.restore(hardware);
        let rate = rate?;
        let rate = if counter.fixed {
            Rate::Fixed(rate)
        } else {
            Rate::Core(CEILING_HZ.max(tsc_hz.saturating_mul(2)))
        };
        watchdog.plan = Plan::new(budget_us, margin_us, rate, tsc_hz);
        if watchdog.plan.period == 0 || watchdog.plan.period >= counter.most {
            return Err(Unavailable::NarrowWrites);
        }
        Ok(watchdog)
    }

    /// Count from `start` with the interrupt off and return the highest
    /// rate of [`RATE_WINDOWS`] windows, in hertz.
    fn measure(
        &self,
        hardware: &mut dyn Hardware,
        start: u64,
        tsc_hz: u64,
    ) -> Result<u64, Unavailable> {
        let counter = &self.counter;
        let written = hardware.write_msr(counter.counter, start)
            && hardware.read_msr(counter.counter) == Some(start)
            && hardware.write_msr(counter.select, counter.event)
            && self.global(hardware, true)
            && hardware.write_msr(counter.select, counter.event | ENABLE);
        if !written {
            return Err(Unavailable::Refused);
        }
        let mut highest = 0u64;
        for _ in 0..RATE_WINDOWS {
            let (Some(before), ticks) = (hardware.read_msr(counter.counter), hardware.tsc()) else {
                return Err(Unavailable::Refused);
            };
            hardware.spin();
            let (Some(after), elapsed) = (
                hardware.read_msr(counter.counter),
                hardware.tsc().wrapping_sub(ticks),
            ) else {
                return Err(Unavailable::Refused);
            };
            if after <= before || after < start || elapsed == 0 {
                continue;
            }
            let hz = u128::from(after - before) * u128::from(tsc_hz) / u128::from(elapsed);
            highest = highest.max(u64::try_from(hz).unwrap_or(u64::MAX));
        }
        if highest == 0 {
            return Err(Unavailable::NotCounting);
        }
        Ok(highest)
    }

    /// The counter's value at arming: [`Plan::period`] counts before it
    /// overflows its width.
    pub fn initial(&self) -> u64 {
        let mask = if self.counter.width >= 64 {
            u64::MAX
        } else {
            (1 << self.counter.width) - 1
        };
        (mask - self.plan.period + 1) & mask
    }

    fn global(&self, hardware: &mut dyn Hardware, on: bool) -> bool {
        match (self.counter.global, self.saved.global) {
            (Some((msr, bit)), Some(saved)) => {
                hardware.write_msr(msr, if on { saved | bit } else { saved & !bit })
            }
            _ => true,
        }
    }

    /// Arm for one function's start: the counter reloaded, its overflow
    /// an NMI. False when a write was refused; nothing is then armed.
    pub fn arm(&self, hardware: &mut dyn Hardware) -> bool {
        let counter = &self.counter;
        let armed = hardware.write_msr(counter.select, counter.event)
            && hardware.write_msr(counter.counter, self.initial())
            && self.global(hardware, true);
        if armed {
            hardware.write_lvt(LVT_NMI);
            if hardware.write_msr(counter.select, counter.event | INT | ENABLE) {
                return true;
            }
        }
        self.disarm(hardware);
        false
    }

    /// Stop counting once a start ended.
    pub fn disarm(&self, hardware: &mut dyn Hardware) {
        hardware.write_msr(self.counter.select, self.counter.event);
        hardware.write_lvt(LVT_NMI | LVT_MASKED);
    }

    /// Whether this watchdog's counter overflowed since its arming: what
    /// the NMI handler asks before it names the device.
    pub fn overflowed(&self, hardware: &mut dyn Hardware) -> bool {
        hardware
            .read_msr(self.counter.counter)
            .is_some_and(|value| value < self.initial())
    }

    /// Device start has ended: everything as the firmware left it.
    pub fn finish(&self, hardware: &mut dyn Hardware) {
        self.restore(hardware);
    }

    fn restore(&self, hardware: &mut dyn Hardware) {
        let counter = &self.counter;
        hardware.write_msr(counter.select, self.saved.select & !ENABLE);
        hardware.write_msr(counter.counter, self.saved.counter);
        if let (Some((msr, _)), Some(saved)) = (counter.global, self.saved.global) {
            hardware.write_msr(msr, saved);
        }
        hardware.write_lvt(self.saved.lvt);
        hardware.write_msr(counter.select, self.saved.select);
    }
}

/// A fixed buffer the NMI handler formats into, cut at its end.
pub struct Line<'a> {
    bytes: &'a mut [u8],
    used: usize,
}

impl<'a> Line<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, used: 0 }
    }

    pub fn as_str(&self) -> &str {
        // Only whole `str`s and their prefixes at char boundaries are kept.
        core::str::from_utf8(&self.bytes[..self.used]).unwrap_or("")
    }
}

impl Write for Line<'_> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let room = self.bytes.len() - self.used;
        let mut take = text.len().min(room);
        while !text.is_char_boundary(take) {
            take -= 1;
        }
        self.bytes[self.used..self.used + take].copy_from_slice(&text.as_bytes()[..take]);
        self.used += take;
        Ok(())
    }
}

/// The function whose start the watchdog bounds, as its report names it:
/// address and IDs only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Started {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor: u16,
    pub id: u16,
    pub driver: &'static str,
}

/// Where the start was when the watchdog fired: the first wait that saw
/// its budget pass, when one did, and the interrupted instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stopped<'a> {
    pub step: Option<(&'a str, u32)>,
    pub image_offset: u64,
}

/// The screen's and the log's report of a start the watchdog ended.
pub fn report(line: &mut Line<'_>, started: &Started, plan: &Plan, stopped: &Stopped<'_>) {
    let _ = write!(
        line,
        "PCI {:04x}:{:02x}:{:02x}.{:x} {:04x}:{:04x} ({}) did not finish starting in {} s",
        started.segment,
        started.bus,
        started.device,
        started.function,
        started.vendor,
        started.id,
        started.driver,
        (plan.budget_us + plan.margin_us) / 1_000_000,
    );
    match stopped.step {
        Some((file, number)) => {
            let _ = write!(line, ": its budget ran out at {file}:{number}");
        }
        None => {
            let _ = write!(line, ": it never reached a bounded wait");
        }
    }
    let _ = write!(
        line,
        ", last at image+{:#x}. The next boot skips it. Stela stopped. Its log is on this \
         USB: on another computer, `stela setup boot-log --output log.txt` saves it; include \
         that file in a report. Turn the PC off to try again.",
        stopped.image_offset
    );
}

#[cfg(test)]
mod tests;
