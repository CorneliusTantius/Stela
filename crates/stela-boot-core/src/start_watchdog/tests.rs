use super::*;
use std::collections::{BTreeMap, BTreeSet};

const SECOND: u64 = 1_000_000;
const BUDGET: u64 = 30 * SECOND;
const MARGIN: u64 = 30 * SECOND;
const TSC_HZ: u64 = 3_000_000_000;

/// A counter MSR, its select and its global control bit.
type Pair = (u32, u32, Option<(u32, u64)>);

/// A processor's counters as the architecture describes them: a counter
/// counts while its select and global bit enable it, its core's cycles or
/// reference cycles at a fixed rate, and its overflow past its width raises
/// an NMI when its select asks for an interrupt and the LVT entry delivers
/// one unmasked. Intel's IA32_PMCx alias IA32_A_PMCx and sign-extend bit 31
/// of a write.
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
    /// Whether enabled counters count at all.
    counting: bool,
    /// The core's clock, and the reference clock of reference cycles.
    hz: u64,
    reference_hz: u64,
    /// Spins the processor spends away, as a hypervisor runs another vCPU:
    /// the TSC runs on, the counters do not.
    away: usize,
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
            counting: true,
            hz: 3_000_000_000,
            reference_hz: 24_000_000,
            away: 0,
            nmi: false,
            now_us: 0,
        }
    }

    fn at(mut self, hz: u64) -> Self {
        self.hz = hz;
        self
    }

    /// Let `us` microseconds of wall time pass with the processor running.
    fn run(&mut self, us: u64) {
        self.now_us += us;
        if !self.counting {
            return;
        }
        let mask = (1u64 << self.width) - 1;
        for (counter, select, global) in self.counters.clone() {
            let select = self.msrs[&select];
            let enabled =
                select & ENABLE != 0 && global.is_none_or(|(msr, bit)| self.msrs[&msr] & bit != 0);
            if !enabled {
                continue;
            }
            let hz = if select & 0xffff == REFERENCE_CYCLES_INTEL {
                self.reference_hz
            } else {
                self.hz
            };
            let counts = u64::try_from(u128::from(us) * u128::from(hz) / 1_000_000).unwrap();
            let next = self.msrs[&counter].wrapping_add(counts);
            if next > mask && select & INT != 0 && self.lvt == LVT_NMI {
                self.nmi = true;
            }
            self.msrs.insert(counter, next & mask);
        }
    }

    /// IA32_PMCx is IA32_A_PMCx.
    fn alias(index: u32) -> u32 {
        if (IA32_PMC0..IA32_PMC0 + 8).contains(&index) {
            index - IA32_PMC0 + IA32_A_PMC0
        } else {
            index
        }
    }
}

impl Hardware for Model {
    fn read_msr(&mut self, index: u32) -> Option<u64> {
        if self.refused.contains(&index) {
            return None;
        }
        self.msrs.get(&Self::alias(index)).copied()
    }
    fn write_msr(&mut self, index: u32, mut value: u64) -> bool {
        let target = Self::alias(index);
        if self.refused.contains(&index) || !self.msrs.contains_key(&target) {
            return false;
        }
        if target != index {
            value = value as u32 as i32 as i64 as u64;
        }
        if self
            .counters
            .iter()
            .any(|(counter, _, _)| *counter == target)
        {
            value &= (1 << self.width) - 1;
        }
        if !self.dropping {
            self.msrs.insert(target, value);
        }
        true
    }
    fn read_lvt(&mut self) -> u32 {
        self.lvt
    }
    fn write_lvt(&mut self, value: u32) {
        self.lvt = value;
    }
    fn tsc(&mut self) -> u64 {
        self.now_us * (TSC_HZ / SECOND)
    }
    fn spin(&mut self) {
        if self.away > 0 {
            self.away -= 1;
            self.now_us += 100;
        } else {
            self.run(100);
        }
    }
}

/// Intel with both cycle events, or only core cycles when `reference` is
/// false.
fn intel_cpuid(version: u32, counters: u32, reference: bool) -> Cpuid {
    Cpuid {
        vendor: INTEL_VENDOR,
        max_basic: 0x20,
        leaf1_ecx: 1 << 15,
        perfmon: [
            version | (counters << 8) | (48 << 16) | (7 << 24),
            if reference { 0 } else { 1 << 2 },
        ],
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

fn enable(cpuid: &Cpuid, model: &mut Model) -> Result<Watchdog, Unavailable> {
    Watchdog::enable(cpuid, BUDGET, MARGIN, TSC_HZ, model)
}

/// Arm, let `length` pass, disarm: whether it fired.
fn start(watchdog: &Watchdog, model: &mut Model, length: u64) -> bool {
    assert!(watchdog.arm(model));
    model.run(length);
    let fired = model.nmi || watchdog.overflowed(model);
    watchdog.disarm(model);
    fired
}

/// Arm and run until it fires: the time it took.
fn stuck(watchdog: &Watchdog, model: &mut Model) -> u64 {
    let armed_at = model.now_us;
    assert!(watchdog.arm(model));
    while !model.nmi && model.now_us - armed_at < 2_000 * SECOND {
        model.run(SECOND / 10);
    }
    assert!(model.nmi && watchdog.overflowed(model));
    model.now_us - armed_at
}

/// The fixed-rate path: Intel's reference cycles, measured, whichever
/// clock they tick at, stop a stuck start between 60 and 61 s whatever the
/// core's clock does, and never a healthy one.
#[test]
fn reference_cycles_stop_a_stuck_start_at_budget_and_margin_at_any_core_clock() {
    // The core crystal, the bus clock and the TSC's rate.
    for reference_hz in [24_000_000, 100_000_000, TSC_HZ] {
        for hz in [400_000_000, 2_000_000_000, 5_800_000_000, 9_000_000_000] {
            let mut model = Model {
                reference_hz,
                ..Model::intel(8).at(hz)
            };
            let watchdog = enable(&intel_cpuid(5, 8, true), &mut model).unwrap();
            let Rate::Fixed(measured) = watchdog.plan.rate else {
                panic!("not fixed");
            };
            assert!(
                measured.abs_diff(reference_hz) <= reference_hz / 100,
                "{measured}"
            );
            assert!(watchdog.plan.least_us() >= BUDGET + MARGIN);
            assert!(watchdog.plan.latest_us() <= BUDGET + MARGIN + SECOND);
            for length in [0, BUDGET, BUDGET + MARGIN - 1] {
                for _ in 0..20 {
                    assert!(!start(&watchdog, &mut model, length), "{hz} {length}");
                    model.run(10 * SECOND);
                }
            }
            let fired = stuck(&watchdog, &mut model);
            assert!(fired >= BUDGET + MARGIN, "{reference_hz} {hz} {fired}");
            assert!(
                fired <= BUDGET + MARGIN + SECOND,
                "{reference_hz} {hz} {fired}"
            );
        }
    }
}

/// A processor away for some of the measuring windows measures them low;
/// the highest window counts, so the period is never short.
#[test]
fn a_window_spent_away_never_shortens_the_period() {
    let mut model = Model {
        away: RATE_WINDOWS - 1,
        reference_hz: 100_000_000,
        ..Model::intel(4)
    };
    let watchdog = enable(&intel_cpuid(5, 4, true), &mut model).unwrap();
    assert!(watchdog.plan.least_us() >= BUDGET + MARGIN);
    let fired = stuck(&watchdog, &mut model);
    assert!((BUDGET + MARGIN..=BUDGET + MARGIN + SECOND).contains(&fired));
}

/// Without a fixed-rate event (AMD, or Intel without reference cycles) the
/// core's cycles count against the ceiling: never before budget and margin
/// at any clock up to it, and at the latest the log's time on a core at the
/// TSC's rate.
#[test]
fn core_cycles_stop_a_stuck_start_no_sooner_than_budget_and_margin() {
    for (cpuid, model) in [
        (amd_cpuid(6), Model::amd(6)),
        (intel_cpuid(4, 8, false), Model::intel(8)),
    ] {
        for hz in [
            400_000_000,
            2_000_000_000,
            TSC_HZ,
            5_800_000_000,
            CEILING_HZ,
        ] {
            let mut model = model.clone().at(hz);
            let watchdog = enable(&cpuid, &mut model).unwrap();
            assert_eq!(watchdog.plan.rate, Rate::Core(CEILING_HZ));
            assert_eq!(watchdog.plan.least_us(), BUDGET + MARGIN);
            assert_eq!(
                watchdog.plan.latest_us(),
                (BUDGET + MARGIN) * (CEILING_HZ / TSC_HZ) + (BUDGET + MARGIN) * 2 / 3
            );
            for length in [0, 1_000, BUDGET, BUDGET + 25 * SECOND, BUDGET + MARGIN - 1] {
                for _ in 0..20 {
                    assert!(!start(&watchdog, &mut model, length), "{hz} {length}");
                    model.run(10 * SECOND);
                }
            }
            let fired = stuck(&watchdog, &mut model);
            assert!(fired >= BUDGET + MARGIN, "{hz} {fired}");
            let expected = u64::try_from(
                u128::from(BUDGET + MARGIN) * u128::from(CEILING_HZ) / u128::from(hz),
            )
            .unwrap();
            assert!(fired <= expected + SECOND / 10, "{hz} {fired}");
            if hz >= TSC_HZ {
                assert!(fired <= watchdog.plan.latest_us() + SECOND / 10);
            }
            watchdog.finish(&mut model);
        }
    }
    // A TSC above half the ceiling raises it.
    let watchdog = Watchdog::enable(
        &amd_cpuid(6),
        BUDGET,
        MARGIN,
        5_000_000_000,
        &mut Model::amd(6),
    )
    .unwrap();
    assert_eq!(watchdog.plan.rate, Rate::Core(10_000_000_000));
}

/// Without full-width writes Intel's IA32_PMCx hold under 2^31 counts:
/// enough for reference cycles at a crystal's rate, not at the TSC's or
/// for core cycles; a write that does not read back is refused.
#[test]
fn narrow_writes_hold_only_a_period_under_two_to_the_31() {
    let narrow = |reference_hz| {
        let mut model = Model {
            reference_hz,
            ..Model::intel(4)
        };
        model.msrs.insert(IA32_PERF_CAPABILITIES, 0);
        model
    };
    let mut crystal = narrow(24_000_000);
    let watchdog = enable(&intel_cpuid(5, 4, true), &mut crystal).unwrap();
    assert_eq!(watchdog.counter.counter, IA32_PMC0 + 3);
    let fired = stuck(&watchdog, &mut crystal);
    assert!((BUDGET + MARGIN..=BUDGET + MARGIN + SECOND).contains(&fired));
    assert_eq!(
        enable(&intel_cpuid(5, 4, true), &mut narrow(TSC_HZ)),
        Err(Unavailable::NarrowWrites)
    );
    assert_eq!(
        enable(&intel_cpuid(5, 4, false), &mut narrow(TSC_HZ)),
        Err(Unavailable::NarrowWrites)
    );
    let no_pdcm = Cpuid {
        leaf1_ecx: 0,
        ..intel_cpuid(5, 4, false)
    };
    assert_eq!(
        enable(&no_pdcm, &mut Model::intel(4)),
        Err(Unavailable::NarrowWrites)
    );
    // Full-width writes claimed, but the counter keeps 32 bits of them.
    let mut claimed = Model::intel(4);
    claimed.width = 32;
    assert_eq!(
        enable(&intel_cpuid(5, 4, true), &mut claimed),
        Err(Unavailable::Refused)
    );
}

#[test]
fn a_firmware_counter_is_left_alone_and_everything_is_restored() {
    let cpuid = amd_cpuid(6);
    let mut model = Model::amd(6);
    // The firmware counts with the two highest counters.
    for select in [AMD_PERF_CTL_EXT0 + 10, AMD_PERF_CTL_EXT0 + 8] {
        model.msrs.insert(select, 0x76 | OS | ENABLE);
        model.msrs.insert(select + 1, 1234);
    }
    model.lvt = LVT_MASKED | 0xfe;
    let before = (model.msrs.clone(), model.lvt);
    let watchdog = enable(&cpuid, &mut model).unwrap();
    assert_eq!(watchdog.counter.select, AMD_PERF_CTL_EXT0 + 6);
    assert_eq!(watchdog.counter.counter, AMD_PERF_CTR_EXT0 + 6);
    // Its check left everything as it was, but for the firmware's
    // counters, which counted on.
    let (msrs, lvt) = before;
    assert_eq!(model.lvt, lvt);
    for (index, value) in &msrs {
        if [AMD_PERF_CTR_EXT0 + 10, AMD_PERF_CTR_EXT0 + 8].contains(index) {
            continue;
        }
        assert_eq!(model.msrs[index], *value, "{index:#x}");
    }
    assert!(!start(&watchdog, &mut model, SECOND));
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
    assert_eq!(enable(&cpuid, &mut owned), Err(Unavailable::Owned));
}

#[test]
fn without_a_usable_counter_the_watchdog_says_why() {
    let mut intel = Model::intel(4);
    // No performance monitoring: leaf 0Ah version 0, or no leaf 0Ah.
    assert_eq!(
        enable(&intel_cpuid(0, 4, true), &mut intel),
        Err(Unavailable::Absent)
    );
    let old = Cpuid {
        max_basic: 9,
        ..intel_cpuid(4, 4, true)
    };
    assert_eq!(enable(&old, &mut intel), Err(Unavailable::Absent));
    // Another vendor's processor.
    let other = Cpuid {
        vendor: [1, 2, 3],
        ..intel_cpuid(4, 4, true)
    };
    assert_eq!(enable(&other, &mut intel), Err(Unavailable::Absent));
    // Neither cycle event.
    let mut no_cycles = intel_cpuid(4, 4, false);
    no_cycles.perfmon[1] |= 1;
    assert_eq!(
        enable(&no_cycles, &mut intel),
        Err(Unavailable::NoCycleEvent)
    );
    // A hypervisor that drops counter writes: they do not read back.
    let mut dropping = Model::amd(6);
    dropping.dropping = true;
    assert_eq!(
        enable(&amd_cpuid(6), &mut dropping),
        Err(Unavailable::Refused)
    );
    // A counter that keeps its value.
    let mut still = Model::amd(6);
    still.counting = false;
    assert_eq!(
        enable(&amd_cpuid(6), &mut still),
        Err(Unavailable::NotCounting)
    );
    // Counter MSRs that take #GP.
    let mut refusing = Model::amd(6);
    for index in 0..6 {
        refusing.refused.insert(AMD_PERF_CTL_EXT0 + 2 * index);
    }
    assert_eq!(
        enable(&amd_cpuid(6), &mut refusing),
        Err(Unavailable::Refused)
    );
    // Without a counter nothing is armed or changed.
    for model in [&dropping, &still] {
        assert!(!model.nmi && model.lvt == LVT_MASKED);
    }
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
    let plan = enable(&amd_cpuid(6), &mut Model::amd(6)).unwrap().plan;
    let mut bytes = [0u8; 512];
    let mut line = Line::new(&mut bytes);
    report(
        &mut line,
        &started,
        &plan,
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
        &plan,
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
