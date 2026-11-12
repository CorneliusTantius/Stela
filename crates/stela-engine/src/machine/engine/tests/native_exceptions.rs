//! Native SVC and ERET between EL0 and EL2 of the host
//! (`x86_64::transition::supervisor_call_thunk`, `exception_return_thunk`)
//! against the engine path: every architectural effect the engine's
//! `Cpu::take` and `Cpu::exception_return` make, and the normal exit for
//! each case the record does not cover.

use super::super::transitions::tests::run_native;
use super::*;
use crate::machine::cpu::{RESERVATION_GRANULE, Reservation};
use stela_compiler::x86_64::transition::{EXCEPTION_RETURN, SUPERVISOR_CALL};

/// HCR_EL2.E2H and TGE: the host.
const HCR_HOST: u64 = 1 << 34 | 1 << 27;
const VECTORS: u64 = BASE + 0x8000;
/// The lower-EL synchronous vector.
const SVC_VECTOR: u64 = VECTORS + 0x400;
const ERET_PC: u64 = BASE + 0x40;
const USER: u64 = BASE + 0x100;
const SVC_WORD: u32 = 0xd400_0001 | 0x80 << 5; // svc #0x80
const ERET: u32 = 0xd69f_03e0;
/// SPSR of the return to EL0t: Z and C, DIT and SSBS, every mask clear.
const USER_SPSR: u64 = 0x6 << 28 | 1 << 24 | 1 << 12;

/// A PE at EL2 of the host, its vectors at [`VECTORS`].
fn host() -> Machine<FakeHost, NoDevices> {
    let mut machine = machine(&[]);
    machine.cpu.pstate = Pstate::reset(2);
    machine
        .cpu
        .registers
        .set(SystemRegister::HCR_EL2, 0, HCR_HOST);
    machine
        .cpu
        .registers
        .set(SystemRegister::VBAR_EL2, 0, VECTORS);
    machine.sync_regime();
    machine
}

/// The operands both twins start a case from, at the ERET.
fn prepare(machine: &mut Machine<FakeHost, NoDevices>) {
    machine.cpu.pc = ERET_PC;
    machine.cpu.state.nzcv = 0;
    machine.cpu.state.sp = 0xffff_fe00_1234_5670;
    let registers = &mut machine.cpu.registers;
    registers.set(SystemRegister::SPSR_EL2, 0, USER_SPSR);
    registers.set(SystemRegister::ELR_EL2, 0, USER);
    registers.set(SystemRegister::SP_EL0, 0, 0x0000_7000_0000_1000);
}

/// Engine-path ERETs and SVCs until both have records.
fn warm(machine: &mut Machine<FakeHost, NoDevices>) {
    for _ in 0..2 {
        prepare(machine);
        machine.system_instruction(ERET).unwrap();
        machine.finish_transition(1);
        assert_eq!(machine.cpu.pc, USER);
        machine.system_instruction(SVC_WORD).unwrap();
        machine.finish_transition(1);
        assert_eq!(machine.cpu.pc, SVC_VECTOR);
    }
    let table = &machine.mirrors.transitions;
    assert_eq!(
        table.records[0][SUPERVISOR_CALL].generation,
        table.generation
    );
    assert_eq!(
        table.records[2][EXCEPTION_RETURN].generation,
        table.generation
    );
}

/// Everything an SVC or ERET changes, for comparison.
fn observed(machine: &Machine<FakeHost, NoDevices>) -> alloc::string::String {
    let cpu = &machine.cpu;
    let state = GuestState {
        daif: 0,
        pan: 0,
        anchors: Default::default(),
        lower_limit: Default::default(),
        ..cpu.state.clone()
    };
    let read = |register| cpu.registers.get(register, 0);
    alloc::format!(
        "{:?} {:?} pc={:#x} spsr={:#x} elr={:#x} esr={:#x} sp={:#x},{:#x} state={} \
         event={} monitor={:?} exceptions={} pointer={:x?}",
        cpu.pstate,
        state,
        cpu.pc,
        read(SystemRegister::SPSR_EL2),
        read(SystemRegister::ELR_EL2),
        read(SystemRegister::ESR_EL2),
        cpu.sp(0),
        cpu.sp(2),
        machine.mirror_state(),
        cpu.event_is_set(),
        cpu.monitor.is_some(),
        machine.statistics.exceptions,
        machine.pointer.tags,
    )
}

fn thunks() -> (x86_64_pointer::Thunk, x86_64_pointer::Thunk) {
    let syndrome =
        crate::machine::exception::syndrome(crate::machine::exception::Class::SupervisorCall, 0x80)
            as u32;
    (
        transition::exception_return_thunk(GuestAddress(ERET_PC), &TRANSITIONS, 0),
        transition::supervisor_call_thunk(GuestAddress(USER), syndrome, &TRANSITIONS, 0),
    )
}

/// ERET to EL0 and SVC back complete natively from the records as the
/// engine completes them: PSTATE (EL, SP selection, masks, NZCV, PAN, DIT,
/// UAO, SSBS), SPSR, ELR and ESR, both stacks, the cells' state, the event
/// register, the local monitor, the exception count and the PAC service
/// native PAC instructions run on.
#[test]
fn native_svc_and_eret_match_the_engine_path() {
    let (mut engine, mut native) = (host(), host());
    warm(&mut engine);
    warm(&mut native);
    let (eret, svc) = thunks();
    for machine in [&mut engine, &mut native] {
        prepare(machine);
        machine.cpu.state.nzcv = 0x9000_0000;
        machine.cpu.state.exclusive_bytes = 8;
        machine.cpu.consume_event();
    }
    native.mirrors.lines_until = u64::MAX;
    assert_eq!(observed(&engine), observed(&native));
    engine.system_instruction(ERET).unwrap();
    let exit = run_native(&mut native, &eret.code);
    assert_eq!(exit, (USER, ExitKind::Return as u64));
    assert_eq!(observed(&engine), observed(&native));
    assert_eq!((native.cpu.pstate.el, native.cpu.pstate.sp), (0, false));
    assert!(native.cpu.event_is_set());
    assert_eq!(native.cpu.state.exclusive_bytes, 0);
    // SVC from EL0 with other flags and masks.
    for machine in [&mut engine, &mut native] {
        machine.cpu.pc = USER;
        machine.cpu.state.nzcv = 0x4000_0000;
        machine.cpu.state.sp = 0x0000_7000_0000_0ff0;
        machine.cpu.pstate.daif = 0b0100;
    }
    engine.system_instruction(SVC_WORD).unwrap();
    let exit = run_native(&mut native, &svc.code);
    assert_eq!(exit, (SVC_VECTOR, ExitKind::Return as u64));
    assert_eq!(observed(&engine), observed(&native));
    assert_eq!((native.cpu.pstate.el, native.cpu.pstate.sp), (2, true));
    assert_eq!(native.statistics.native_transitions[..2], [1, 1]);
}

/// A tagged ELR loses its tag where TCR_EL2's TBI0 applies, as
/// `Cpu::branch_address` removes it.
#[test]
fn native_eret_removes_the_tag_the_engine_removes() {
    let (mut engine, mut native) = (host(), host());
    for machine in [&mut engine, &mut native] {
        let tcr = machine.cpu.registers.get(SystemRegister::TCR_EL2, 0);
        machine
            .cpu
            .registers
            .set(SystemRegister::TCR_EL2, 0, tcr | 1 << 37);
        machine.sync_regime();
        warm(machine);
        prepare(machine);
        let tagged = USER | 0x5a << 56;
        machine
            .cpu
            .registers
            .set(SystemRegister::ELR_EL2, 0, tagged);
    }
    native.mirrors.lines_until = u64::MAX;
    engine.system_instruction(ERET).unwrap();
    let (eret, _) = thunks();
    let exit = run_native(&mut native, &eret.code);
    assert_eq!(exit, (USER, ExitKind::Return as u64));
    assert_eq!(observed(&engine), observed(&native));
}

/// What a record does not cover takes the normal exit with nothing
/// changed: another mode, single-step, PACM or an illegal return in SPSR,
/// an interrupt waiting that the return unmasks, an engine monitor, a
/// deadline due or not known, a notification, and for SVC another PAN.
#[test]
fn uncovered_svc_and_eret_take_the_normal_exit() {
    let (eret, svc) = thunks();
    type Case = fn(&mut Machine<FakeHost, NoDevices>);
    let cases: [(&str, Case); 9] = [
        ("EL2h", |m| {
            m.cpu
                .registers
                .set(SystemRegister::SPSR_EL2, 0, USER_SPSR | 0b1001)
        }),
        ("single-step", |m| {
            m.cpu
                .registers
                .set(SystemRegister::SPSR_EL2, 0, USER_SPSR | 1 << 21)
        }),
        // Stored raw: SPSR keeps PACM only with FEAT_PAuth_LR.
        ("PACM", |m| {
            m.cpu
                .registers
                .set_raw(SystemRegister::SPSR_EL2, 0, USER_SPSR | 1 << 35)
        }),
        ("EL1 under TGE", |m| {
            m.cpu
                .registers
                .set(SystemRegister::SPSR_EL2, 0, USER_SPSR | 0b0101)
        }),
        ("IRQ unmasked", |m| m.cpu.state.pending = 0b10),
        ("monitor", |m| {
            m.cpu.monitor = Some(Reservation {
                granule: 0x1000,
                bytes: [0; RESERVATION_GRANULE as usize],
            })
        }),
        ("deadline", |m| m.mirrors.lines_until = 0),
        ("notification", |m| {
            m.chain.weak_storage().upgrade().unwrap().notify()
        }),
        ("SVC's PAN", |_| {}),
    ];
    for (name, case) in cases {
        let mut machine = host();
        warm(&mut machine);
        prepare(&mut machine);
        machine.mirrors.lines_until = u64::MAX;
        let code = if name == "SVC's PAN" {
            machine.system_instruction(ERET).unwrap();
            machine.cpu.pc = USER;
            machine.cpu.pstate.pan = !machine.cpu.pstate.pan;
            &svc.code
        } else {
            &eret.code
        };
        case(&mut machine);
        let before = observed(&machine);
        let pc = machine.cpu.pc;
        let exit = run_native(&mut machine, code);
        assert_eq!(exit, (pc, ExitKind::System as u64), "{name}");
        assert_eq!(observed(&machine), before, "{name}");
    }
}

/// SCTLR_EL2's four PAC key enables.
const KEY_ENABLES: u64 = 1 << 31 | 1 << 30 | 1 << 27 | 1 << 13;

/// With APCTL's kernel-keys bit, EL2 signs with every key while EL0 of a
/// process without JOP keys (SCTLR's enables clear) does not: the engine
/// path reopens the PAC service at each level. A native SVC or ERET
/// switches the service's tag words only from a service with one open, so
/// with the service never opened neither makes a record (the twin round
/// trip below covers an open one). With SCTLR enabling the keys too, both
/// levels sign alike and the records switch nothing.
#[test]
fn svc_and_eret_make_records_only_where_pac_acts_alike() {
    for (enables, recorded) in [(0, [false, false]), (KEY_ENABLES, [true, true])] {
        let mut machine = host();
        let sctlr = machine.cpu.registers.get(SystemRegister::SCTLR_EL2, 0);
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL2, 0, sctlr & !KEY_ENABLES | enables);
        machine.cpu.apple.apctl[1] = 1 << 4;
        machine.sync_regime();
        for _ in 0..2 {
            prepare(&mut machine);
            machine.system_instruction(ERET).unwrap();
            machine.finish_transition(1);
            machine.system_instruction(SVC_WORD).unwrap();
            machine.finish_transition(1);
        }
        let table = &machine.mirrors.transitions;
        for (index, (state, kind)) in [(0, SUPERVISOR_CALL), (2, EXCEPTION_RETURN)]
            .into_iter()
            .enumerate()
        {
            let record = &table.records[state][kind];
            let made = record.generation == table.generation;
            assert_eq!(made, recorded[index], "enables {enables:#x} kind {kind}");
            if made {
                let swaps = record.pointer_swap != 0;
                assert_eq!(swaps, enables == 0, "enables {enables:#x} kind {kind}");
            }
        }
    }
}

/// MSR TTBR0_EL1, X1: TTBR0_EL2 in the host.
const MSR_TTBR0: u32 = 0xd518_2001;

/// A process switch (TTBR0) or an SPRR_PERM write changes the lookup
/// contexts of the level returned to, which records do not forget: the
/// ERET to EL0 then completes but ends its run rather than look its target
/// up in the previous process's context, and the next native entry at EL0
/// gives the record the new contexts.
#[test]
fn svc_and_eret_records_take_new_contexts_after_ttbr0_and_permission_writes() {
    for case in ["TTBR0", "SPRR_PERM"] {
        let mut machine = host();
        warm(&mut machine);
        let current = |machine: &Machine<FakeHost, NoDevices>| {
            let table = &machine.mirrors.transitions;
            let record = &table.records[2][EXCEPTION_RETURN];
            assert_eq!(record.generation, table.generation, "{case}");
            record.contexts_generation == table.contexts_generation
        };
        assert!(current(&machine), "{case}");
        if case == "TTBR0" {
            machine.cpu.state.x[1] = 0x0001_0000_8000_0000;
            machine.system_instruction(MSR_TTBR0).unwrap();
            assert_eq!(
                machine.cpu.registers.get(SystemRegister::TTBR0_EL2, 0),
                0x0001_0000_8000_0000
            );
        } else {
            machine.permissions_changed();
        }
        assert!(!current(&machine), "{case}");
        machine.cpu.pstate = Pstate {
            el: 0,
            sp: false,
            ..machine.cpu.pstate
        };
        machine.refresh_transition_contexts(1);
        assert!(current(&machine), "{case}");
    }
}

/// A process switch at EL2 (TTBR0) moves the lookup contexts; at the next
/// native entry, still at EL2, the ERET record to EL0 takes the contexts
/// of the process switched to, where that process ran before: the ERET
/// then continues in its run where the host switches views natively (the
/// thunk's test past the record's `chain`: its contexts generation is the
/// table's, and its contexts and salts are those a fetch at EL0 runs in). Switched to a process with no EL0
/// context yet, the record stays stale and ends its run, and the first
/// native entry at EL0 gives it the contexts the fetch there made.
#[test]
fn eret_records_take_the_contexts_of_the_process_switched_to_at_el2() {
    const SWITCHED: u64 = 0x0001_0000_8000_0000;
    const FIRST: u64 = 0x0002_0000_9000_0000;
    const NEW: u64 = 0x0003_0000_a000_0000;
    let switch = |machine: &mut Machine<FakeHost, NoDevices>, ttbr0: u64| {
        machine.cpu.state.x[1] = ttbr0;
        let pc = machine.cpu.pc;
        machine.system_instruction(MSR_TTBR0).unwrap();
        machine.cpu.pc = pc;
    };
    let mut machine = host();
    let variant = machine.current_variant(false, false);
    let host_contexts = machine.contexts(2, variant);
    // The process switched to later runs once at EL0 first.
    switch(&mut machine, SWITCHED);
    let switched = machine.contexts(0, variant);
    switch(&mut machine, FIRST);
    let first = machine.contexts(0, variant);
    assert_ne!(first, switched);
    for _ in 0..2 {
        prepare(&mut machine);
        machine.system_instruction(ERET).unwrap();
        machine.chain.set_contexts(first);
        machine.finish_transition(1);
        machine.system_instruction(SVC_WORD).unwrap();
        machine.chain.set_contexts(host_contexts);
        machine.finish_transition(1);
    }
    let record = |machine: &Machine<FakeHost, NoDevices>| {
        let table = &machine.mirrors.transitions;
        let record = table.records[2][EXCEPTION_RETURN];
        assert_eq!(record.generation, table.generation);
        (record.contexts_generation == table.contexts_generation).then_some(record)
    };
    assert_eq!(record(&machine).unwrap().contexts, first);
    switch(&mut machine, SWITCHED);
    assert!(record(&machine).is_none());
    assert_eq!(machine.mirror_state(), 2);
    machine.refresh_transition_contexts(1);
    let refreshed = record(&machine).expect("refreshed at EL2");
    assert_eq!(refreshed.contexts, switched);
    let salts = machine.chain.salts_of(switched);
    assert_eq!(
        refreshed.salts,
        u64::from(salts[0]) | u64::from(salts[1]) << 32
    );
    // A process never run at EL0: genuinely stale until EL0's entry.
    switch(&mut machine, NEW);
    machine.refresh_transition_contexts(1);
    assert!(record(&machine).is_none());
    machine.cpu.pstate = Pstate {
        el: 0,
        sp: false,
        ..machine.cpu.pstate
    };
    let new = machine.contexts(0, variant);
    machine.chain.set_contexts(new);
    machine.refresh_transition_contexts(1);
    assert_eq!(record(&machine).expect("refreshed at EL0").contexts, new);
}

/// The twin round trip where EL2 keeps every key on (APCTL) and EL0 of a
/// process without JOP keys has only IB: after an ERET to EL0 and an SVC
/// back, the PAC service native PAC code runs on is the engine's at each
/// level (IA, DA and DB off at EL0): the records switch it natively, and a
/// service in another state takes the normal exit.
#[test]
fn svc_and_eret_leave_the_pac_service_of_the_level_entered() {
    let configure = |machine: &mut Machine<FakeHost, NoDevices>| {
        let sctlr = machine.cpu.registers.get(SystemRegister::SCTLR_EL2, 0);
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL2, 0, sctlr & !KEY_ENABLES | 1 << 30);
        machine.cpu.apple.apctl[1] = 1 << 4;
        use SystemRegister as R;
        for (index, register) in [
            R::APIAKeyLo_EL1,
            R::APIAKeyHi_EL1,
            R::APIBKeyLo_EL1,
            R::APIBKeyHi_EL1,
            R::APDAKeyLo_EL1,
            R::APDAKeyHi_EL1,
            R::APDBKeyLo_EL1,
            R::APDBKeyHi_EL1,
        ]
        .into_iter()
        .enumerate()
        {
            let half = crate::machine::pointer_keys::Register::architectural(register).unwrap();
            let value = 0x0123_4567_89ab_cdef_u64.rotate_left(8 * index as u32);
            machine.cpu.apple.pointer_keys.write(half, value);
        }
        machine.sync_regime();
        // The service a first PAC exit opens.
        let inputs = PointerInputs {
            keys: machine.pointer_keys(),
            version: machine.pointer_version().unwrap(),
            tcr: machine.cpu.regime_tcr(),
        };
        machine.pointer.open(inputs);
        machine.revalidate_pointers();
        assert!(machine.pointer.any_open());
        for _ in 0..2 {
            prepare(machine);
            machine.system_instruction(ERET).unwrap();
            machine.finish_transition(1);
            machine.system_instruction(SVC_WORD).unwrap();
            machine.finish_transition(1);
        }
    };
    let (mut engine, mut native) = (host(), host());
    configure(&mut engine);
    configure(&mut native);
    let (eret, svc) = thunks();
    let table = &native.mirrors.transitions;
    for (state, kind) in [(0, SUPERVISOR_CALL), (2, EXCEPTION_RETURN)] {
        let record = &table.records[state][kind];
        assert_eq!(record.generation, table.generation, "kind {kind}");
        assert_ne!(record.pointer_swap, 0, "kind {kind}");
    }
    let complete = |machine: &mut Machine<FakeHost, NoDevices>, code: &[u8], _word: u32| {
        let pc = machine.cpu.pc;
        assert_ne!(run_native(machine, code), (pc, ExitKind::System as u64));
    };
    for machine in [&mut engine, &mut native] {
        prepare(machine);
    }
    native.mirrors.lines_until = u64::MAX;
    assert_eq!(observed(&engine), observed(&native));
    engine.system_instruction(ERET).unwrap();
    complete(&mut native, &eret.code, ERET);
    assert_eq!(observed(&engine), observed(&native));
    engine.system_instruction(SVC_WORD).unwrap();
    complete(&mut native, &svc.code, SVC_WORD);
    assert_eq!(observed(&engine), observed(&native));
    assert_eq!(native.statistics.native_transitions[..2], [1, 1]);
    // A service in another state (closed here) takes the normal exit.
    prepare(&mut native);
    native.pointer.close();
    let before = observed(&native);
    let exit = run_native(&mut native, &eret.code);
    assert_eq!(exit, (ERET_PC, ExitKind::System as u64));
    assert_eq!(observed(&native), before);
}

/// The overflow bit of the M2 monitor's counters.
const PMC_OVERFLOW: u64 = 1 << 63;

/// A host PE at EL2 whose PMC0 counts cycles at EL2 only and PMC1
/// instructions at EL0 only, PMC1 at `pmc1` with its PMI armed where
/// `armed` (and PMC0's where `cycles_armed`), after 10 instructions at
/// count 1000.
fn levels_machine(pmc1: u64, armed: bool, cycles_armed: bool) -> Machine<FakeHost, NoDevices> {
    use crate::machine::pmu::{self, Context, Filter, Pmu};
    const AT_EL2: Context = Context {
        el: 2,
        filter: Filter::Host,
        waiting: false,
    };
    let mut machine = host();
    machine.host.now = 1_000;
    let mut monitor = Pmu::new(36_000_000, 24_000_000);
    let arms = u64::from(armed) << 13 | u64::from(cycles_armed) << 12;
    let write = |monitor: &mut Pmu, encoding, value| {
        monitor.write(encoding, value, 1_000, 10, AT_EL2).unwrap();
    };
    write(&mut monitor, pmu::PMCR1, 1 << 9 | 1 << 16);
    write(&mut monitor, pmu::PMCR0, 0b11 | 4 << 8 | arms);
    write(&mut monitor, pmu::PMC[1], pmc1);
    machine.cpu.pmu = Some(monitor);
    machine.cpu.retired = 10;
    machine.derived_changed();
    // Records of the ERET to EL0 and the SVC back, the states a run
    // reaches; they retire nothing and take no time.
    warm(&mut machine);
    machine
}

/// PMC0, PMC1 and the PMI of `machine` at its count and instructions.
fn level_counts(machine: &mut Machine<FakeHost, NoDevices>) -> (u64, u64, bool) {
    use crate::machine::pmu;
    let now = machine.now();
    let retired = machine.cpu.retired;
    let context = machine.cpu.pmu_context(false);
    let monitor = machine.cpu.pmu.as_mut().unwrap();
    (
        monitor.read(pmu::PMC[0], now, retired, context).unwrap(),
        monitor.read(pmu::PMC[1], now, retired, context).unwrap(),
        monitor.asserted(now, retired),
    )
}

/// A run that continues through ERET, SVC and ERET again, logging each
/// ([`transition::CHAIN_LOGGED`]), counts as the engine path does when it
/// synchronizes at each transition: PMC0 the cycles of the EL2 segments
/// alone, PMC1 the instructions of the EL0 segments alone (each
/// transition's own instruction in the level it leaves), and the PMI that
/// PMC1's overflow raises in the last EL0 segment is asserted at the run's
/// end, as the twin's is.
#[test]
fn logged_transitions_count_each_segment_in_its_own_level() {
    use stela_compiler::x86_64::transition::Segment;
    // Instructions retired and the count at each transition, and its word.
    let transitions = [
        (110, 2_000, ERET),
        (130, 2_600, SVC_WORD),
        (160, 3_000, ERET),
    ];
    let (end_retired, end_now) = (170, 3_500);
    let mut twin = levels_machine(PMC_OVERFLOW - 25, true, false);
    let mut native = levels_machine(PMC_OVERFLOW - 25, true, false);
    let mut log = [Segment::default(); transition::LOG];
    for (index, &(retired, now, word)) in transitions.iter().enumerate() {
        if word == ERET {
            prepare(&mut twin);
        } else {
            twin.cpu.pc = USER;
        }
        twin.cpu.retired = retired;
        twin.host.now = now;
        let count = twin.now();
        twin.system_instruction(word).unwrap();
        log[index] = Segment {
            retired: retired - 10,
            count,
            to: twin.mirror_state() as u64,
        };
    }
    assert_eq!(twin.mirror_state(), 0);
    twin.cpu.retired = end_retired;
    twin.host.now = end_now;
    // The native run: the thunks' log, then the run's end at EL0.
    native.mirrors.transitions.log = log;
    native.mirrors.transitions.logged = transitions.len() as u64;
    native.adopt_segments();
    assert_eq!(native.mirrors.transitions.logged, 0);
    native.cpu.retired = end_retired;
    native.host.now = end_now;
    native.cpu.pstate = twin.cpu.pstate;
    native.sync_monitor();
    let expected = level_counts(&mut twin);
    assert_eq!(level_counts(&mut native), expected);
    // PMC1: 20 instructions in the first EL0 segment and 10 in the last,
    // 30 past its start 25 short of the overflow bit.
    assert_eq!(expected.1, PMC_OVERFLOW + 5);
    assert!(expected.2, "the PMI asserted in the last segment");
    assert_ne!(expected.0, 0, "EL2's cycles");
}

/// Counters that tell the levels apart let a run continue through
/// transitions only by logging them, where native code reads the count and
/// no armed PMI could assert within the run in some level; counters that
/// count alike let it continue freely. Native reads stay open, with the
/// rate each counter takes in each state.
#[test]
fn transitions_continue_logged_only_where_no_pmi_falls_within_the_run() {
    use stela_compiler::x86_64::transition::{CHAIN_FREE, CHAIN_LOGGED};
    let native = |mut machine: Machine<FakeHost, NoDevices>| {
        machine.clock.native((0, 1 << 32));
        machine
    };
    let mut machine = native(levels_machine(1_000, true, false));
    assert_eq!(machine.transition_chain(), CHAIN_LOGGED);
    // Native reads stay open, with each state's rate for the logged
    // transitions to take: PMC0 counts at EL2 (state 2), PMC1 at EL0.
    machine.enter_cycles();
    let (cycles, instructions) = (machine.mirrors.cycles, machine.mirrors.instructions);
    assert_ne!(cycles.open, 0);
    assert_ne!(instructions.open, 0);
    assert_eq!(
        (cycles.clock, cycles.clocks[2], cycles.clocks[0]),
        (36_000_000, 36_000_000, 0)
    );
    assert_eq!((instructions.step, instructions.steps[2]), (0, 0));
    assert_eq!(instructions.steps[0], u64::MAX);
    // PMC1's PMI within the run's instructions, though EL2 counts none.
    let mut machine = native(levels_machine(PMC_OVERFLOW - 25, true, false));
    assert_eq!(machine.transition_chain(), 0);
    // Unarmed, it may cross the bit within the run.
    let mut machine = native(levels_machine(PMC_OVERFLOW - 25, false, false));
    assert_eq!(machine.transition_chain(), CHAIN_LOGGED);
    // PMC0's PMI within a second of count.
    let mut machine = levels_machine(1_000, false, true);
    let context = machine.cpu.pmu_context(false);
    let monitor = machine.cpu.pmu.as_mut().unwrap();
    let pmc0 = crate::machine::pmu::PMC[0];
    monitor
        .write(pmc0, PMC_OVERFLOW - 1_000, 1_000, 10, context)
        .unwrap();
    let mut machine = native(machine);
    assert_eq!(machine.transition_chain(), 0);
    // Without native count reads.
    let mut machine = levels_machine(1_000, false, false);
    assert_eq!(machine.transition_chain(), 0);
    // Counting alike, or without a monitor.
    let mut machine = host();
    assert_eq!(machine.transition_chain(), CHAIN_FREE);
}

/// Only the states a run can reach, its own and those its records lead to,
/// tell levels apart: PMC0 and PMC1 counting at EL0 and EL2 of the host let
/// runs between them continue freely whatever PMCR1_EL12 (a VM's EL1&0
/// filter, never written here) and PMCR1_GL1 say. Once a record leads to a
/// guarded level, PMCR1_GL1 decides: counting there as at EL2 (SPTM writes
/// 0x30300) keeps them free, counting nothing there logs the transitions.
#[test]
fn only_the_states_a_run_reaches_tell_levels_apart() {
    use crate::machine::pmu::{self, Context, Filter, Pmu};
    use stela_compiler::x86_64::transition::{CHAIN_FREE, CHAIN_LOGGED};
    const AT_EL2: Context = Context {
        el: 2,
        filter: Filter::Host,
        waiting: false,
    };
    let cases = [
        (0x30300, false, CHAIN_FREE),
        (0, false, CHAIN_FREE),
        (0x30300, true, CHAIN_FREE),
        (0, true, CHAIN_LOGGED),
    ];
    for (guarded, to_guarded, chain) in cases {
        let mut machine = host();
        warm(&mut machine);
        let mut monitor = Pmu::new(36_000_000, 24_000_000);
        monitor.write(pmu::PMCR1, 0x30300, 0, 0, AT_EL2).unwrap();
        monitor.write(pmu::PMCR0, 0b11, 0, 0, AT_EL2).unwrap();
        monitor.set_guarded_filter(guarded, 0, 0, AT_EL2);
        assert!(!monitor.alike(), "PMCR1_EL12 counts nothing");
        machine.cpu.pmu = Some(monitor);
        machine.clock.native((0, 1 << 32));
        if to_guarded {
            // A GENTER from EL2 to GL2 recorded.
            let table = &mut machine.mirrors.transitions;
            table.records[2][transition::GUARDED_ENTER] = transition::Record {
                generation: table.generation,
                to: 6,
                ..transition::Record::default()
            };
        }
        let case = (guarded, to_guarded);
        assert_eq!(machine.transition_chain(), chain, "{case:x?}");
    }
}

/// MRS X10, PMC0 and MRS X10, PMC1.
const MRS_PMC: [u32; 2] = [0xd53a_f00a, 0xd53a_f10a];

/// PMC0 and PMC1 as the engine reads them at `retired` and count `now`.
fn engine_counters(machine: &mut Machine<FakeHost, NoDevices>, retired: u64, now: u64) -> [u64; 2] {
    machine.cpu.retired = retired;
    machine.host.now = now;
    MRS_PMC.map(|word| {
        let pc = machine.cpu.pc;
        machine.system_instruction(word).unwrap();
        assert_eq!(machine.cpu.pc, pc + 4, "completed plainly");
        machine.cpu.pc = pc;
        machine.cpu.state.x[10]
    })
}

/// Write the instructions a native run retired into the machine's chain
/// control, as the blocks it left would have.
fn run_retired(machine: &mut Machine<FakeHost, NoDevices>, retired: u64) {
    let control = machine.chain.address() as *mut chain::ChainControl;
    // SAFETY: the machine's own control, which no native code runs over
    // meanwhile.
    unsafe {
        core::ptr::addr_of_mut!((*control).count).write(chain::ChainControl::counting(0, retired))
    };
}

/// PMC0 and PMC1 as their thunks read them within a native run, after it
/// retired `retired` instructions, at count `now` of `clock`; `None` for
/// one that exited.
fn native_counters(
    machine: &mut Machine<FakeHost, NoDevices>,
    clock: &stela_compiler::x86_64::register_read::CountState,
    retired: u64,
    now: u64,
) -> [Option<u64>; 2] {
    use super::super::transitions::tests::call_native;
    clock
        .offset
        .store(now, core::sync::atomic::Ordering::Relaxed);
    run_retired(machine, retired);
    let cycles = register_read::cycle_counter_thunk(
        GuestAddress(BASE),
        10,
        cell_place(COUNTER_MIRRORS[0]),
        cell_place(CYCLES_PLAIN),
        CYCLES,
        Place::new(Anchor::Count, 0),
    );
    let instructions = register_read::instruction_counter_thunk(
        GuestAddress(BASE),
        10,
        cell_place(COUNTER_MIRRORS[1]),
        cell_place(INSTRUCTIONS_PLAIN),
        INSTRUCTION_COUNTER,
        0,
    )
    .unwrap();
    [cycles.code, instructions.code].map(|code| {
        // Each read computes the count rather than take the value an
        // earlier read opened its cell on.
        machine.mirrors[COUNTER_MIRRORS[0]].readable = 0;
        machine.mirrors[COUNTER_MIRRORS[1]].readable = 0;
        machine.cpu.state.x[10] = 0xdead;
        let exit = call_native(machine, &code);
        (exit == (BASE + 4, ExitKind::Fallthrough as u64)).then_some(machine.cpu.state.x[10])
    })
}

/// A run that continues through ERET, SVC and ERET, logging each
/// ([`transition::CHAIN_LOGGED`]), reads PMC0 and PMC1 natively in every
/// segment as a twin that takes every transition and read in the engine
/// reads them at the same instructions and count: for counters that count
/// at EL0 only, at EL2 only, and at both. The engine's synchronization at
/// each logged transition after the run then agrees with what the reads
/// returned.
#[test]
fn native_counter_reads_in_each_logged_segment_equal_the_engine_path() {
    use super::super::transitions::tests::{call_native, enter_native};
    use crate::machine::pmu::{self, Context, Filter, Pmu};
    use core::sync::atomic::Ordering::Relaxed;
    use stela_compiler::x86_64::register_read::{Count, CountState};
    const AT_EL2: Context = Context {
        el: 2,
        filter: Filter::Host,
        waiting: false,
    };
    const BEGUN: u64 = 1_000;
    // The transitions' thunks, each of a one-instruction block.
    let syndrome =
        crate::machine::exception::syndrome(crate::machine::exception::Class::SupervisorCall, 0x80)
            as u32;
    let thunks = [
        transition::exception_return_thunk(GuestAddress(ERET_PC), &TRANSITIONS, 1),
        transition::supervisor_call_thunk(GuestAddress(USER), syndrome, &TRANSITIONS, 1),
    ];
    // (instructions retired since entry, count) of each segment's reads,
    // then of the transition that ends it, ERET and SVC in turn. EL0 reads
    // of the monitor trap (`pmu::Pmu::write`: no EL0 access), so the EL0
    // segments only count.
    type Reads = &'static [(u64, u64)];
    let segments: [(Reads, Option<(u64, u64)>); 4] = [
        (&[(10, 1_300), (40, 2_000)], Some((50, 2_500))),
        (&[], Some((80, 3_600))),
        (&[(85, 3_700), (90, 4_000)], Some((100, 4_400))),
        (&[], None),
    ];
    // PMCR1: both counters at EL0, at EL2, or at both.
    for filter in [0b11 << 8, 0b11 << 16, 0b11 << 8 | 0b11 << 16] {
        let clock = alloc::boxed::Box::new(CountState::default());
        clock.ceiling.store(u64::MAX, Relaxed);
        let make = || {
            let mut machine = host();
            let mut monitor = Pmu::new(36_000_007, 24_000_000);
            monitor.write(pmu::PMCR1, filter, 0, 0, AT_EL2).unwrap();
            monitor.write(pmu::PMCR0, 0b11, 0, 0, AT_EL2).unwrap();
            monitor.write(pmu::PMC[0], 1_000, 0, 0, AT_EL2).unwrap();
            monitor.write(pmu::PMC[1], 2_000, 0, 0, AT_EL2).unwrap();
            machine.cpu.pmu = Some(monitor);
            machine.derived_changed();
            machine
        };
        // Records name the frame where it stays.
        let ready = |machine: &mut Machine<FakeHost, NoDevices>| {
            machine.host.now = 100;
            warm(machine);
            // An engine read opens EL2's plain cells.
            engine_counters(machine, 0, 100);
            prepare(machine);
            machine.cpu.retired = BEGUN;
            machine.host.now = 1_000;
        };
        let (mut twin, mut native) = (make(), make());
        ready(&mut twin);
        ready(&mut native);
        let reader = native.clock.reader() as *mut Count;
        // SAFETY: the machine's own reader, which no native code runs over
        // meanwhile; `clock` outlives every run of the case.
        unsafe {
            (*reader).per_tsc = 0;
            (*reader).last = 0;
            (*reader).state = &*clock as *const CountState as u64;
        }
        // The run: entered at EL2 with the records continuing (the host's
        // view stays), each transition logged.
        native.mirrors.lines_until = u64::MAX;
        native.mirrors.transitions.chain = transition::CHAIN_LOGGED;
        let generation = native.mirrors.transitions.contexts_generation;
        for (state, kind) in [(2, EXCEPTION_RETURN), (0, SUPERVISOR_CALL)] {
            let record = &mut native.mirrors.transitions.records[state][kind];
            record.chain = 1;
            record.contexts_generation = generation;
        }
        enter_native(&mut native);
        for (index, (reads, transition)) in segments.iter().enumerate() {
            for &(retired, now) in *reads {
                let expected = engine_counters(&mut twin, BEGUN + retired, now);
                let read = native_counters(&mut native, &clock, retired, now);
                let at = (filter, index, retired);
                assert_eq!(read, expected.map(Some), "{at:x?}");
            }
            let Some((retired, now)) = *transition else {
                continue;
            };
            // The twin retires the transition's instruction, then takes it.
            twin.cpu.retired = BEGUN + retired;
            twin.host.now = now;
            let word = [ERET, SVC_WORD][index % 2];
            if word == ERET && index > 0 {
                // The kernel returns to the thread with the SPSR and ELR it
                // made, on both alike.
                prepare(&mut twin);
                prepare(&mut native);
            }
            twin.system_instruction(word).unwrap();
            clock.offset.store(now, Relaxed);
            run_retired(&mut native, retired - 1);
            let exit = call_native(&mut native, &thunks[index % 2].code);
            assert_eq!(
                exit.1,
                ExitKind::Return as u64,
                "{filter:#x} transition {index}"
            );
        }
        assert_eq!(native.mirrors.transitions.logged, 3, "{filter:#x}");
        // The run ends at EL0 as `Machine::execute` leaves it.
        let counts = native.mirrors.transitions.take_counts();
        native.adopt_native_state();
        native.adopt_segments();
        native.cpu.pstate.daif = native.cpu.state.daif as u8;
        native.cpu.pstate.sp = native.mirrors.selected != 0;
        native.mirrors.leave(&mut native.cpu.pstate);
        native.cpu.retired = BEGUN + 160;
        native.host.now = 6_500;
        native.adopt_transitions(counts, 0);
        assert_eq!(native.mirror_state(), twin.mirror_state(), "{filter:#x}");
        twin.cpu.retired = BEGUN + 160;
        twin.host.now = 6_500;
        twin.sync_monitor();
        let expected = level_counts(&mut twin);
        assert_eq!(level_counts(&mut native), expected, "{filter:#x}");
        assert_ne!(expected.0, 1_000, "{filter:#x} PMC0 counted");
        assert_ne!(expected.1, 2_000, "{filter:#x} PMC1 counted");
    }
}
