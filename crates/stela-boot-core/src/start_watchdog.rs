//! The device-start watchdog: one core performance counter, counting the
//! starting processor's unhalted cycles, raises an NMI through the local
//! APIC's performance-counter LVT entry when a single PCI function's start
//! outlasts its budget plus a margin. A start whose driver is stuck where no
//! budget check runs, such as a loop without a wait, then ends the boot with
//! the device named on the screen instead of a silent hang.
//!
//! The counter is the architectural "unhalted core cycles" event on Intel
//! (CPUID leaf 0Ah, event 3Ch) and PMCx076 "cycles not in halt" on AMD (core
//! performance counters, with the PerfCtrExtCore set when CPUID 8000_0001h
//! ECX[23] offers it, and PerfMonV2's global control when CPUID 8000_0022h
//! EAX[0] does). Intel needs full-width counter writes
//! (IA32_PERF_CAPABILITIES[13], written through IA32_A_PMCx): a 32-bit
//! sign-extended write reaches at most 2^31 cycles, under a second.
//!
//! Never early: each start loads the counter afresh with [`Plan::period`]
//! cycles before overflow, the budget plus margin at [`Plan::ceiling_hz`],
//! a clock no core runs at. A core counts at most its own clock per second
//! of wall time, so the counter cannot overflow before the budget plus the
//! margin has passed, whatever the core's clock does; a slower or halted
//! core only makes it later (at 2 GHz against an 8 GHz ceiling, four times
//! later). A healthy start's waits end at its budget, after which only its
//! cleanup runs, which the margin covers; the counter is disabled after
//! each start and restored to what the firmware left once device start
//! ends.
//!
//! Without a usable counter the boot says once why and keeps no bound: no
//! performance monitoring (CPUID leaf 0Ah version 0, or a hypervisor that
//! offers none), counters the firmware is using (every candidate enabled),
//! Intel without full-width writes, or a counter that does not count.
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
const IA32_PERFEVTSEL0: u32 = 0x186;
const IA32_A_PMC0: u32 = 0x4c1;
const IA32_PERF_GLOBAL_CTRL: u32 = 0x38f;
const AMD_PERF_CTL0: u32 = 0xc001_0000;
const AMD_PERF_CTR0: u32 = 0xc001_0004;
const AMD_PERF_CTL_EXT0: u32 = 0xc001_0200;
const AMD_PERF_CTR_EXT0: u32 = 0xc001_0201;
const AMD_GLOBAL_CTL: u32 = 0xc000_0301;

const AMD_VENDOR: [u32; 3] = [0x6874_7541, 0x6974_6e65, 0x444d_4163];
const HYGON_VENDOR: [u32; 3] = [0x6f67_7948, 0x656e_6975, 0x6e65_476e];
const INTEL_VENDOR: [u32; 3] = [0x756e_6547, 0x4965_6e69, 0x6c65_746e];

/// The lowest clock this watchdog takes no core to exceed: well above the
/// fastest x86 core's boost. Twice the TSC's rate when that is higher.
pub const CEILING_HZ: u64 = 8_000_000_000;

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

/// The MSRs and APIC entry the watchdog drives, and a short spin: the
/// boot's are the processor's own, the tests' a model.
pub trait Hardware {
    /// RDMSR, or `None` where it takes #GP.
    fn read_msr(&mut self, index: u32) -> Option<u64>;
    /// WRMSR; false where it takes #GP.
    fn write_msr(&mut self, index: u32, value: u64) -> bool;
    fn read_lvt(&mut self) -> u32;
    fn write_lvt(&mut self, value: u32);
    /// Run for a few microseconds, unhalted.
    fn spin(&mut self);
}

/// Why the watchdog keeps no bound, said once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// No architectural performance monitoring, or none the vendor names.
    Absent,
    /// The cycle event is not offered.
    NoCycleEvent,
    /// Intel counters take only 32-bit sign-extended writes.
    NarrowWrites,
    /// Every candidate counter is already enabled, by the firmware.
    Owned,
    /// A counter write took #GP or did not stick.
    Refused,
    /// The counter did not count while the processor ran.
    NotCounting,
}

impl core::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Absent => "the processor offers no performance counters",
            Self::NoCycleEvent => "the processor's counters offer no cycle event",
            Self::NarrowWrites => {
                "the processor's counters take only 32-bit writes, under a second of cycles"
            }
            Self::Owned => "every performance counter is in use by the firmware",
            Self::Refused => "a performance counter refused its setting",
            Self::NotCounting => "the performance counter did not count",
        })
    }
}

/// The counter one processor uses: its MSRs, width and select value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counter {
    pub select: u32,
    pub counter: u32,
    pub width: u32,
    /// The global control MSR and this counter's bit in it.
    pub global: Option<(u32, u64)>,
    /// The event select value, without its enable and interrupt bits.
    pub event: u64,
}

/// Where the counter starts each device start, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub budget_us: u64,
    pub margin_us: u64,
    pub ceiling_hz: u64,
    /// Cycles from a start's arming to overflow.
    pub period: u64,
}

impl Plan {
    /// The plan for a start budget and margin on a processor whose TSC
    /// runs at `tsc_hz`.
    pub fn new(budget_us: u64, margin_us: u64, tsc_hz: u64) -> Self {
        let ceiling_hz = CEILING_HZ.max(tsc_hz.saturating_mul(2));
        let seconds_us = budget_us.saturating_add(margin_us);
        let period = (u128::from(seconds_us) * u128::from(ceiling_hz)).div_ceil(1_000_000);
        Self {
            budget_us,
            margin_us,
            ceiling_hz,
            period: u64::try_from(period).unwrap_or(u64::MAX),
        }
    }

    /// The least time, in microseconds, from arming to overflow on a core
    /// whose clock never exceeds the ceiling.
    pub fn least_us(&self) -> u64 {
        u64::try_from(u128::from(self.period) * 1_000_000 / u128::from(self.ceiling_hz.max(1)))
            .unwrap_or(u64::MAX)
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
        if version == 0 || counters == 0 || width < 40 {
            return Err(Unavailable::Absent);
        }
        if known == 0 || ebx & 1 != 0 {
            return Err(Unavailable::NoCycleEvent);
        }
        // PDCM: IA32_PERF_CAPABILITIES exists.
        let capabilities = (cpuid.leaf1_ecx & (1 << 15) != 0)
            .then(|| hardware.read_msr(IA32_PERF_CAPABILITIES))
            .flatten()
            .unwrap_or(0);
        if capabilities & FULL_WIDTH_WRITES == 0 {
            return Err(Unavailable::NarrowWrites);
        }
        let free = free_counter(hardware, counters.min(8), |index| IA32_PERFEVTSEL0 + index)?;
        Ok(Counter {
            select: IA32_PERFEVTSEL0 + free,
            counter: IA32_A_PMC0 + free,
            width,
            global: (version >= 2).then_some((IA32_PERF_GLOBAL_CTRL, 1 << free)),
            event: 0x3c | base,
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
            global: v2.then_some((AMD_GLOBAL_CTL, 1 << free)),
            event: 0x76 | base,
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
    /// Take a counter on this processor and check it counts; nothing is
    /// armed. On refusal nothing the firmware set is changed.
    pub fn enable(
        cpuid: &Cpuid,
        plan: Plan,
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
        let watchdog = Self {
            counter,
            plan,
            saved,
        };
        if plan.period == 0 || plan.period >= 1 << (counter.width - 1) {
            return Err(Unavailable::NarrowWrites);
        }
        // Count without interrupting for a moment: a counter that holds
        // its value while the processor runs is no watchdog.
        let start = watchdog.initial();
        let checked = hardware.write_msr(counter.counter, start)
            && hardware.write_msr(counter.select, counter.event)
            && watchdog.global(hardware, true)
            && hardware.write_msr(counter.select, counter.event | ENABLE);
        hardware.spin();
        let counted = hardware.read_msr(counter.counter);
        watchdog.restore(hardware);
        if !checked {
            return Err(Unavailable::Refused);
        }
        match counted {
            Some(value) if value > start && value < start + watchdog.plan.period => Ok(watchdog),
            Some(_) => Err(Unavailable::NotCounting),
            None => Err(Unavailable::Refused),
        }
    }

    /// The counter's value at arming: [`Plan::period`] cycles before it
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
