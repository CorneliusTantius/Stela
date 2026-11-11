//! Register writes that change nothing a GENTER or GEXIT record depends on
//! keep the records: SPRR's field registers, which SPTM writes at every
//! address-space switch, and storage registers a store takes in full, such
//! as XNU's thread keys at each thread switch. A write of a register that
//! derived state reads still drops them.

use super::*;
use stela_compiler::x86_64::transition::GUARDED_ENTER;
use stela_contracts::Chip;

const GENTER: u32 = 0x0020_1423;
const GEXIT: u32 = 0x0020_1400;
const MSR_SPRR_FIELDS_0: u32 = 0xd51e_f300; // msr s3_6_c15_c3_0, x0
const MSR_THREAD_KEY_0: u32 = 0xd51c_fdc6; // msr s3_4_c15_c13_6, x6
const MSR_KERNELKEYLO: u32 = 0xd51c_f100; // msr s3_4_c15_c1_0, x0

/// A machine at EL2 with SPRR and EL2's GXF enabled that made its GENTER
/// and GEXIT records.
fn recorded() -> Machine<FakeHost, NoDevices> {
    let mut machine = machine_on(Chip::AppleM2, &[]);
    machine.cpu.pstate = Pstate::reset(2);
    machine.cpu.apple.sprr_config |= mmu::SPRR_CONFIG_EN;
    machine.cpu.apple.gxf_config[1] |= crate::machine::cpu::GXF_CONFIG_EN;
    machine.cpu.apple.guarded[1].enter = BASE + 0x9000;
    machine.derived_changed();
    machine.cpu.pc = BASE + 0x100;
    for _ in 0..2 {
        machine.system_instruction(GENTER).unwrap();
        machine.finish_transition(1);
        machine.system_instruction(GEXIT).unwrap();
        machine.finish_transition(1);
    }
    let table = &machine.mirrors.transitions;
    assert_eq!(table.records[2][GUARDED_ENTER].generation, table.generation);
    machine
}

#[test]
fn stored_register_writes_keep_the_transition_records() {
    let mut machine = recorded();
    let generation = machine.mirrors.transitions.generation;
    for value in [0x40800, 0] {
        machine.cpu.state.x[0] = value;
        machine.system_instruction(MSR_SPRR_FIELDS_0).unwrap();
        assert_eq!(machine.cpu.apple.sprr_fields[0], value);
        assert_eq!(machine.mirrors.transitions.generation, generation);
    }
    machine.cpu.state.x[6] = 0x1234_5678;
    machine.system_instruction(MSR_THREAD_KEY_0).unwrap();
    assert_eq!(machine.mirrors.transitions.generation, generation);
}

#[test]
fn a_key_register_write_drops_the_transition_records() {
    let mut machine = recorded();
    let generation = machine.mirrors.transitions.generation;
    machine.cpu.state.x[0] = 0x55;
    machine.system_instruction(MSR_KERNELKEYLO).unwrap();
    assert_ne!(machine.mirrors.transitions.generation, generation);
}
