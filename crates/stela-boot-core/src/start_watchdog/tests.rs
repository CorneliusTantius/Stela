use super::*;
use std::collections::{BTreeMap, BTreeSet};

const SECOND: u64 = 1_000_000;
const BUDGET: u64 = 30 * SECOND;
const MARGIN: u64 = 30 * SECOND;

/// A counter MSR, its select and its global control bit.
type Pair = (u32, u32, Option<(u32, u64)>);

/// A processor's counters as the architecture describes them: a counter
/// counts its core's cycles while its select and global bit enable it, and
/// its overflow past its width raises an NMI when its select asks for an
/// interrupt and the LVT entry delivers one unmasked.
#[derive(Clone)]
struct Model {
    msrs: BTreeMap<u32, u64>,
    counters: Vec<Pair>,
    width: u32,
    lvt: u32,
    /// MSRs that take #GP.
    refused: BTreeSet<u32>,
    /// Writes accepted and dropped, as a hypervisor without a PMU may.
    dropping: bool,
    /// The core's clock.
    hz: u64,
    nmi: bool,
    now_us: u64,
}

impl Model {
    fn intel(counters: u32) -> Self {
        let mut model = Self::empty(48);
        for index in 0..counters {
            model.counters.push((
                IA32_A_PMC0 + index,
                IA32_PERFEVTSEL0 + index,
                Some((IA32_PERF_GLOBAL_CTRL, 1 << index)),
            ));
            model.msrs.insert(IA32_A_PMC0 + index, 0);
            model.msrs.insert(IA32_PERFEVTSEL0 + index, 0);
        }
        model
            .msrs
            .insert(IA32_PERF_GLOBAL_CTRL, ((1 << counters) - 1) | (0b111 << 32));
        model.msrs.insert(IA32_PERF_CAPABILITIES, FULL_WIDTH_WRITES);
        model
    }

    fn amd(counters: u32) -> Self {
        let mut model = Self::empty(48);
        for index in 0..counters {
            let select = AMD_PERF_CTL_EXT0 + 2 * index;
            model
                .counters
                .push((select + 1, select, Some((AMD_GLOBAL_CTL, 1 << index))));
            model.msrs.insert(select, 0);
            model.msrs.insert(select + 1, 0);
        }
        model.msrs.insert(AMD_GLOBAL_CTL, (1 << counters) - 1);
        model
    }

    fn empty(width: u32) -> Self {
        Self {
            msrs: BTreeMap::new(),
            counters: Vec::new(),
            width,
            // As firmware leaves it: masked.
            lvt: LVT_MASKED,
            refused: BTreeSet::new(),
            dropping: false,
            hz: 3_000_000_000,
            nmi: false,
            now_us: 0,
        }
    }

    /// Let `us` microseconds of wall time pass with the core running.
    fn run(&mut self, us: u64) {
        self.now_us += us;
        let cycles = u64::try_from(u128::from(us) * u128::from(self.hz) / 1_000_000).unwrap();
        let mask = (1u64 << self.width) - 1;
        for (counter, select, global) in self.counters.clone() {
            let select = self.msrs[&select];
            let enabled =
                select & ENABLE != 0 && global.is_none_or(|(msr, bit)| self.msrs[&msr] & bit != 0);
            if !enabled {
                continue;
            }
            let value = self.msrs[&counter];
            let next = value.wrapping_add(cycles);
            if next > mask && select & INT != 0 && self.lvt == LVT_NMI {
                self.nmi = true;
            }
            self.msrs.insert(counter, next & mask);
        }
    }
}

impl Hardware for Model {
    fn read_msr(&mut self, index: u32) -> Option<u64> {
        if self.refused.contains(&index) {
            return None;
        }
        self.msrs.get(&index).copied()
    }
    fn write_msr(&mut self, index: u32, value: u64) -> bool {
        if self.refused.contains(&index) || !self.msrs.contains_key(&index) {
            return false;
        }
        if !self.dropping {
            self.msrs.insert(index, value);
        }
        true
    }
    fn read_lvt(&mut self) -> u32 {
        self.lvt
    }
    fn write_lvt(&mut self, value: u32) {
        self.lvt = value;
    }
    fn spin(&mut self) {
        self.run(5);
    }
}

fn intel_cpuid(version: u32, counters: u32) -> Cpuid {
    Cpuid {
        vendor: INTEL_VENDOR,
        max_basic: 0x20,
        leaf1_ecx: 1 << 15,
        perfmon: [version | counters << 8 | 48 << 16 | 7 << 24, 0],
        ..Cpuid::default()
    }
}

fn amd_cpuid(counters: u32) -> Cpuid {
    Cpuid {
        vendor: AMD_VENDOR,
        max_basic: 0x10,
        max_extended: 0x8000_0022,
        extended1_ecx: 1 << 23,
        perfmon_v2: [1, counters],
        ..Cpuid::default()
    }
}

fn plan() -> Plan {
    Plan::new(BUDGET, MARGIN, 3_000_000_000)
}

#[test]
fn the_period_reaches_budget_and_margin_at_the_ceiling_clock() {
    let plan = plan();
    assert_eq!(plan.ceiling_hz, CEILING_HZ);
    assert_eq!(plan.least_us(), BUDGET + MARGIN);
    assert_eq!(plan.period, 60 * CEILING_HZ);
    // A TSC above half the ceiling raises it.
    assert_eq!(
        Plan::new(BUDGET, MARGIN, 5_000_000_000).ceiling_hz,
        10_000_000_000
    );
    // Well inside 48-bit counters' half range.
    assert!(plan.period < 1 << 47);
}

/// No healthy start fires, at any clock up to the ceiling: each start's
/// count begins afresh, so many long starts never add up.
#[test]
fn a_healthy_start_never_fires_at_any_clock_up_to_the_ceiling() {
    for (cpuid, model) in [
        (intel_cpuid(4, 8), Model::intel(8)),
        (amd_cpuid(6), Model::amd(6)),
    ] {
        for hz in [400_000_000, 2_000_000_000, 5_800_000_000, CEILING_HZ] {
            let mut model = Model {
                hz,
                ..model.clone()
            };
            let watchdog = Watchdog::enable(&cpuid, plan(), &mut model).unwrap();
            // A start at once, one that used its whole budget, one whose
            // cleanup after the budget took most of the margin, and the
            // longest a healthy start can take.
            for length in [0, 1_000, BUDGET, BUDGET + 25 * SECOND, BUDGET + MARGIN - 1] {
                for _ in 0..20 {
                    assert!(watchdog.arm(&mut model));
                    model.run(length);
                    assert!(!watchdog.overflowed(&mut model), "{hz} {length}");
                    watchdog.disarm(&mut model);
                    // Between starts the counter is off.
                    model.run(10 * SECOND);
                }
            }
            assert!(!model.nmi, "{hz}");
            watchdog.finish(&mut model);
            model.run(1_000 * SECOND);
            assert!(!model.nmi, "{hz}");
        }
    }
}

/// A start that never ends fires once budget and margin have passed at the
/// ceiling clock, and only later on a slower core.
#[test]
fn a_stuck_start_fires_after_budget_and_margin_and_never_before() {
    for (cpuid, model) in [
        (intel_cpuid(5, 4), Model::intel(4)),
        (amd_cpuid(6), Model::amd(6)),
    ] {
        for hz in [CEILING_HZ, 2_000_000_000] {
            let mut model = Model {
                hz,
                ..model.clone()
            };
            let watchdog = Watchdog::enable(&cpuid, plan(), &mut model).unwrap();
            let armed_at = model.now_us;
            assert!(watchdog.arm(&mut model));
            while !model.nmi && model.now_us - armed_at < 1_000 * SECOND {
                model.run(SECOND / 10);
            }
            let fired = model.now_us - armed_at;
            assert!(model.nmi);
            assert!(fired >= BUDGET + MARGIN, "{hz} {fired}");
            let expected = (BUDGET + MARGIN) * (CEILING_HZ / hz);
            assert!(fired <= expected + SECOND / 10, "{hz} {fired}");
            assert!(watchdog.overflowed(&mut model));
        }
    }
}

#[test]
fn a_firmware_counter_is_left_alone_and_everything_is_restored() {
    let cpuid = amd_cpuid(6);
    let mut model = Model::amd(6);
    // The firmware counts with the two highest counters.
    let busy = [AMD_PERF_CTL_EXT0 + 10, AMD_PERF_CTL_EXT0 + 8];
    for select in busy {
        model.msrs.insert(select, 0x76 | OS | ENABLE);
        model.msrs.insert(select + 1, 1234);
    }
    model.lvt = LVT_MASKED | 0xfe;
    let before = (model.msrs.clone(), model.lvt);
    let watchdog = Watchdog::enable(&cpuid, plan(), &mut model).unwrap();
    assert_eq!(watchdog.counter.select, AMD_PERF_CTL_EXT0 + 6);
    assert_eq!(watchdog.counter.counter, AMD_PERF_CTR_EXT0 + 6);
    // Its check changed nothing the firmware left, but for the counts of
    // its own counters, which ran.
    let (msrs, lvt) = before.clone();
    assert_eq!(model.lvt, lvt);
    for (index, value) in &msrs {
        if model
            .counters
            .iter()
            .any(|(counter, _, _)| counter == index)
        {
            continue;
        }
        assert_eq!(model.msrs[index], *value, "{index:#x}");
    }
    assert!(watchdog.arm(&mut model));
    model.run(SECOND);
    watchdog.disarm(&mut model);
    watchdog.finish(&mut model);
    assert_eq!(model.lvt, lvt);
    assert_eq!(model.msrs[&watchdog.counter.select], 0);
    assert_eq!(model.msrs[&watchdog.counter.counter], 0);
    assert_eq!(model.msrs[&AMD_GLOBAL_CTL], msrs[&AMD_GLOBAL_CTL]);
    // Every counter enabled: owned.
    let mut owned = Model::amd(6);
    for index in 0..6 {
        owned.msrs.insert(AMD_PERF_CTL_EXT0 + 2 * index, ENABLE);
    }
    assert_eq!(
        Watchdog::enable(&cpuid, plan(), &mut owned),
        Err(Unavailable::Owned)
    );
}

#[test]
fn without_a_usable_counter_the_watchdog_says_why() {
    let mut intel = Model::intel(4);
    // No performance monitoring: leaf 0Ah version 0, or no leaf 0Ah.
    assert_eq!(
        Watchdog::enable(&intel_cpuid(0, 4), plan(), &mut intel),
        Err(Unavailable::Absent)
    );
    let old = Cpuid {
        max_basic: 9,
        ..intel_cpuid(4, 4)
    };
    assert_eq!(
        Watchdog::enable(&old, plan(), &mut intel),
        Err(Unavailable::Absent)
    );
    // Another vendor's processor.
    let other = Cpuid {
        vendor: [1, 2, 3],
        ..intel_cpuid(4, 4)
    };
    assert_eq!(
        Watchdog::enable(&other, plan(), &mut intel),
        Err(Unavailable::Absent)
    );
    // The cycle event unavailable.
    let mut no_cycles = intel_cpuid(4, 4);
    no_cycles.perfmon[1] = 1;
    assert_eq!(
        Watchdog::enable(&no_cycles, plan(), &mut intel),
        Err(Unavailable::NoCycleEvent)
    );
    // No full-width writes, or no IA32_PERF_CAPABILITIES at all.
    intel.msrs.insert(IA32_PERF_CAPABILITIES, 0);
    assert_eq!(
        Watchdog::enable(&intel_cpuid(4, 4), plan(), &mut intel),
        Err(Unavailable::NarrowWrites)
    );
    let no_pdcm = Cpuid {
        leaf1_ecx: 0,
        ..intel_cpuid(4, 4)
    };
    assert_eq!(
        Watchdog::enable(&no_pdcm, plan(), &mut Model::intel(4)),
        Err(Unavailable::NarrowWrites)
    );
    // A hypervisor that drops counter writes: the counter never counts.
    let mut dropping = Model::amd(6);
    dropping.dropping = true;
    assert_eq!(
        Watchdog::enable(&amd_cpuid(6), plan(), &mut dropping),
        Err(Unavailable::NotCounting)
    );
    // Counter MSRs that take #GP.
    let mut refusing = Model::amd(6);
    for index in 0..6 {
        refusing.refused.insert(AMD_PERF_CTL_EXT0 + 2 * index);
    }
    assert_eq!(
        Watchdog::enable(&amd_cpuid(6), plan(), &mut refusing),
        Err(Unavailable::Refused)
    );
    // Without a counter nothing is armed or changed.
    assert!(!dropping.nmi && dropping.lvt == LVT_MASKED);
}

#[test]
fn the_report_names_the_device_its_driver_and_where_it_stopped() {
    let started = Started {
        segment: 0,
        bus: 7,
        device: 0,
        function: 0,
        vendor: 0x10ec,
        id: 0x8125,
        driver: "realtek",
    };
    let mut bytes = [0u8; 512];
    let mut line = Line::new(&mut bytes);
    report(
        &mut line,
        &started,
        &plan(),
        &Stopped {
            step: Some(("crates/stela-driver-net/src/realtek.rs", 812)),
            image_offset: 0x1234,
        },
    );
    let text = line.as_str();
    assert!(
        text.starts_with(
            "PCI 0000:07:00.0 10ec:8125 (realtek) did not finish starting in 60 s: its budget \
             ran out at crates/stela-driver-net/src/realtek.rs:812, last at image+0x1234. The \
             next boot skips it."
        ),
        "{text}"
    );
    assert!(text.contains("log.txt"));
    let mut bytes = [0u8; 512];
    let mut line = Line::new(&mut bytes);
    report(
        &mut line,
        &started,
        &plan(),
        &Stopped {
            step: None,
            image_offset: 0x10,
        },
    );
    assert!(line.as_str().contains("it never reached a bounded wait"));
    // A short buffer keeps a whole prefix.
    let mut bytes = [0u8; 12];
    let mut line = Line::new(&mut bytes);
    let _ = write!(line, "PCI é{}", "x".repeat(20));
    assert_eq!(line.as_str(), "PCI éxxxxxx");
}
