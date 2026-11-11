use super::*;
use crate::{
    GuestState,
    context::{
        ExecutionContext,
        memory::{MemoryContextView, MemoryRequest, MemoryStatus},
    },
};
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;

const GUEST_BASE: u64 = 0x1000;
const GUEST_PC: u64 = 0x4000;
const RAM_BYTES: usize = 128;

fn operand(
    load: bool,
    bytes: u8,
    pair: bool,
    base: Register,
    displacement: i32,
    mode: AddressMode,
) -> Operand {
    if pair {
        Operand::MemoryPair {
            load,
            bytes,
            vectors: [3, 31],
            base,
            displacement,
            mode,
        }
    } else {
        Operand::Memory {
            load,
            bytes,
            vector: 31,
            base,
            displacement,
            mode,
        }
    }
}

#[test]
fn literal_adapter_preserves_absolute_source_address_and_rejects_invalid_shapes() {
    for form in [0x1c00_0000u32, 0x5c00_0000, 0x9c00_0000] {
        for destination in 0..VECTOR_REGISTER_COUNT {
            for immediate in [-262144i32, -1, 0, 1, 262143] {
                for pc in [0, 0x1004, u64::MAX - 3] {
                    let word = form | ((immediate as u32 & 0x7ffff) << 5) | u32::from(destination);
                    let decoded = literal::decode(crate::GuestAddress(pc), word)
                        .unwrap()
                        .unwrap();
                    let checked = CheckedOperand::from_operation(
                        &Operation::Literal(decoded),
                        CheckedMemoryProfile::SpAlignmentEnabled,
                    )
                    .unwrap();
                    assert!(checked.transfer.base.is_none());
                    assert!(!checked.transfer.writeback());
                    assert!(
                        matches!(checked.transfer.address, Address::Literal { address }
                        if address == (i128::from(pc) + i128::from(immediate) * 4) as u64)
                    );
                    assert_eq!(checked.requirements().required_flags, flags::ASIMD);
                    assert_eq!(
                        checked.requirements().required_sp_alignment,
                        SpAlignmentRequirement::Any
                    );
                }
            }
        }
    }
    for (destination, bytes) in [(32, 4), (0, 1), (0, 2), (0, 32)] {
        assert!(
            CheckedOperand::from_operation(
                &Operation::Literal(literal::Operand {
                    address: GUEST_BASE,
                    transfer: literal::Transfer::Simd { destination, bytes },
                }),
                CheckedMemoryProfile::SpAlignmentDisabled,
            )
            .is_none()
        );
    }
    for word in [0x1800_0000, 0x5800_0000, 0x9800_0000] {
        let decoded = literal::decode(crate::GuestAddress(GUEST_PC), word)
            .unwrap()
            .unwrap();
        assert!(
            CheckedOperand::from_operation(
                &Operation::Literal(decoded),
                CheckedMemoryProfile::SpAlignmentDisabled
            )
            .is_none()
        );
    }
}

#[test]
fn descriptors_keep_pair_tag_and_non_temporal_intent() {
    for pair in [false, true] {
        for base in [Register::X(2), Register::Sp] {
            for mode in [
                AddressMode::Offset,
                AddressMode::PreIndex,
                AddressMode::PostIndex,
            ] {
                let operation = operand(false, 8, pair, base, 0, mode);
                let requirements = requirements(&operation);
                let tag = mode != AddressMode::Offset || base != Register::Sp;
                assert_eq!(
                    requirements.required_flags,
                    flags::ASIMD
                        | flags::WRITE
                        | if pair { flags::PAIR } else { 0 }
                        | if tag { flags::TAG_CHECKED } else { 0 }
                );
                assert_eq!(requirements.required_host_caps, 0);
                assert_eq!(
                    requirements.required_sp_alignment,
                    if base == Register::Sp {
                        SpAlignmentRequirement::Enabled
                    } else {
                        SpAlignmentRequirement::Any
                    }
                );
            }
        }
    }
    let operation = non_temporal::Operand {
        load: true,
        bytes: 16,
        data: non_temporal::Data::Vector([0, 31]),
        base: Register::Sp,
        displacement: 16,
    };
    let transfer = Transfer::from_non_temporal(&operation);
    assert_eq!(transfer.quantity_bytes(), STAGING_BYTES);
    assert!(!transfer.writeback());
    assert_eq!(
        requirements_non_temporal(&operation).required_flags,
        flags::ASIMD | flags::PAIR | flags::NON_TEMPORAL
    );
}

#[test]
fn read_snapshot_capabilities_follow_source_quantity_and_alignment() {
    for bytes in [1, 2, 4, 8, 16] {
        for pair in [false, true] {
            if pair && bytes < DWORD_BYTES {
                continue;
            }
            let dynamic = operand(true, bytes, pair, Register::X(2), 0, AddressMode::Offset);
            let total = bytes * if pair { PAIR_ELEMENTS } else { 1 };
            assert_eq!(
                requirements(&dynamic).required_host_caps,
                if matches!(total, 2 | 4 | 8) {
                    host_caps::ATOMIC_LOAD16
                } else {
                    0
                }
            );
            let aligned = operand(true, bytes, pair, Register::Sp, 0, AddressMode::Offset);
            assert_eq!(requirements(&aligned).required_host_caps, 0);
        }
    }
}

struct Harness {
    ram: [u8; RAM_BYTES],
    fail_part: Option<usize>,
    requests: Vec<(u64, u32, u32, u64)>,
    incoming_mxcsr: Vec<u32>,
}

/// A test transport, not the production MemorySystem. It poisons
/// callback scratch registers and MXCSR after touching the reached prefix.
unsafe extern "sysv64" fn callback(
    view: *mut MemoryContextView,
    request: *const MemoryRequest,
) -> u32 {
    let incoming_mxcsr = mxcsr();
    // SAFETY: native test entry borrows these disjoint objects until return.
    let (view, request) = unsafe { (&mut *view, &*request) };
    // SAFETY: view() installs this Harness borrow and NativeCode::run keeps it live until return.
    let harness = unsafe { &mut *view.opaque.cast::<Harness>() };
    harness.incoming_mxcsr.push(incoming_mxcsr);
    harness
        .requests
        .push((request.address, request.bytes, request.flags, request.pc));
    let bytes = request.bytes as usize;
    let start = usize::try_from(request.address - GUEST_BASE).unwrap();
    let part_bytes = if bytes >= 16 && request.address.is_multiple_of(8) {
        8
    } else if (request.address as usize & 15) + bytes <= 16 {
        bytes
    } else if request.flags & flags::PAIR != 0 && request.address.is_multiple_of((bytes / 2) as u64)
    {
        bytes / 2
    } else {
        1
    };
    let mut status = MemoryStatus::Success;
    for (part, offset) in (0..bytes).step_by(part_bytes).enumerate() {
        if harness.fail_part == Some(part) {
            status = MemoryStatus::Permission;
            view.record(
                status,
                request.address + offset as u64,
                request.pc,
                offset as u64,
            );
            break;
        }
        // SAFETY: generated staging has32 bytes and all test RAM spans fit.
        let data = unsafe { core::slice::from_raw_parts_mut(request.data.add(offset), part_bytes) };
        let ram = &mut harness.ram[start + offset..start + offset + part_bytes];
        if request.flags & flags::WRITE != 0 {
            ram.copy_from_slice(data);
        } else {
            data.copy_from_slice(ram);
        }
        view.completed_bytes += part_bytes as u64;
    }
    let poison_mxcsr: u32 = 0x3f81;
    // SAFETY: all XMM registers are caller-saved; the changed
    // valid MXCSR is restored by the exact common callback wrapper under test.
    unsafe {
        core::arch::asm!(
            "pxor xmm0, xmm0", "pxor xmm1, xmm1", "pxor xmm2, xmm2", "pxor xmm3, xmm3",
            "pxor xmm4, xmm4", "pxor xmm5, xmm5", "pxor xmm6, xmm6", "pxor xmm7, xmm7",
            "ldmxcsr [{control}]", control = in(reg) &poison_mxcsr,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            options(nostack)
        );
    }
    status as u32
}

unsafe extern "C" {
    fn mmap(
        address: *mut c_void,
        bytes: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, bytes: usize) -> i32;
}

struct NativeCode(*mut c_void, usize);

impl NativeCode {
    fn new(body: &[u8]) -> Self {
        const PROT_READ_WRITE_EXECUTE: i32 = 7;
        const MAP_PRIVATE: i32 = 2;
        #[cfg(target_os = "macos")]
        const MAP_ANONYMOUS: i32 = 0x1000;
        #[cfg(not(target_os = "macos"))]
        const MAP_ANONYMOUS: i32 = 0x20;
        // Outer entry owns R15; CALL keeps inner RSP8mod16 for callback ABI.
        let mut code = vec![
            0x41, 0x57, 0x49, 0x89, 0xf7, 0xe8, 3, 0, 0, 0, 0x41, 0x5f, 0xc3,
        ];
        code.extend(body);
        code.push(0xc3);
        if let Ok(directory) = std::env::var("STELA_ASIMD_COMPONENT_OUTPUT") {
            use core::sync::atomic::{AtomicUsize, Ordering};
            static NEXT_BODY: AtomicUsize = AtomicUsize::new(0);
            let number = NEXT_BODY.fetch_add(1, Ordering::Relaxed);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                std::path::Path::new(&directory).join(format!("body-{number}.bin")),
                &code,
            )
            .unwrap();
        }
        // SAFETY: private test mapping is held until all native calls end.
        let address = unsafe {
            mmap(
                core::ptr::null_mut(),
                code.len(),
                PROT_READ_WRITE_EXECUTE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(address as usize, usize::MAX);
        // SAFETY: mmap covers code.len() bytes and is disjoint from the source Vec.
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), address.cast::<u8>(), code.len());
        }
        Self(address, code.len())
    }

    fn run(&self, state: &mut GuestState, view: &mut MemoryContextView) -> u32 {
        let mut context = ExecutionContext {
            memory: (view as *mut MemoryContextView).cast(),
            ..ExecutionContext::default()
        };
        let entry = |state: *mut crate::GuestState, second: *mut ExecutionContext| -> u32 {
            // SAFETY: exact generated entry implements this borrowed SystemV ABI.
            unsafe {
                crate::x86_64::native::call::<u32>(self.0 as *const u8, state, second as u64, 0)
            }
        };
        let before = mxcsr();
        // SAFETY: the entry ABI matches; state, context, view and callback Harness remain live.
        let status = entry(state, &mut context);
        assert_eq!(
            mxcsr(),
            before,
            "callback must preserve complete host MXCSR"
        );
        status
    }
}

fn mxcsr() -> u32 {
    let mut value = 0;
    // SAFETY: STMXCSR writes exactly one independently live32-bit scalar.
    unsafe {
        core::arch::asm!("stmxcsr [{address}]", address = in(reg) &mut value, options(nostack));
    }
    value
}

impl Drop for NativeCode {
    fn drop(&mut self) {
        // SAFETY: this object owns the mapping and all synchronous entry calls have finished.
        unsafe {
            munmap(self.0, self.1);
        }
    }
}

fn view(harness: &mut Harness) -> MemoryContextView {
    use crate::context::memory::{MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION};
    MemoryContextView {
        version: MEMORY_CONTEXT_VERSION,
        bytes: MEMORY_CONTEXT_BYTES,
        callback,
        opaque: (harness as *mut Harness).cast(),
        fault_kind: 0,
        fault_access: 0,
        fault_address: 0,
        fault_pc: 0,
        completed_bytes: 0,
        reserved_tail: 0,
    }
}

fn state() -> GuestState {
    let mut state = GuestState {
        sp: GUEST_BASE + 32,
        nzcv: 0xa000_0000,
        exclusive_bytes: 0x1357_9bdf,
        exclusive_address: 0,
        exclusive_value: 0,
        daif: 0,
        pending: 0,
        fpcr: 0x0040_0000,
        fpsr: 0x0800_009f,
        ..GuestState::default()
    };
    for (index, register) in state.x.iter_mut().enumerate() {
        *register = (index as u64).wrapping_mul(0x0101_0101_0101_0101);
    }
    state.x[2] = GUEST_BASE + 32;
    for (index, vector) in state.v.iter_mut().enumerate() {
        *vector = [
            0x1729_3846_5564_7382 ^ index as u64,
            0x91a0_bfce_ddec_fb0a ^ index as u64,
        ];
    }
    state
}

fn low_bytes(vector: [u64; 2]) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&vector[0].to_le_bytes());
    bytes[8..].copy_from_slice(&vector[1].to_le_bytes());
    bytes
}

#[test]
fn callback_defaults_mxcsr_and_restores_hostile_caller_on_both_outcomes() {
    fn set_mxcsr(value: u32) {
        // SAFETY: tests use only allocated SSE control/status bits, mask
        // every exception, and restore the original environment.
        unsafe {
            core::arch::asm!("ldmxcsr [{}]", in(reg) &value, options(nostack));
        }
    }
    struct Original(u32);
    impl Drop for Original {
        fn drop(&mut self) {
            set_mxcsr(self.0);
        }
    }
    let operation = operand(true, 8, false, Register::X(2), 0, AddressMode::Offset);
    let mut body = Code::new();
    emit_context(&mut body, &operation, GUEST_PC);
    let code = NativeCode::new(&body);
    for caller in [0x1fa1, 0x3fa5, 0x5f85, 0x7fa1] {
        for fail_part in [None, Some(0)] {
            let mut actual = state();
            let mut harness = Harness {
                ram: [0x35; RAM_BYTES],
                fail_part,
                requests: vec![],
                incoming_mxcsr: vec![],
            };
            let mut view = view(&mut harness);
            let original = Original(mxcsr());
            set_mxcsr(caller);
            // This executes the emitted common callback wrapper.
            // The transport records entry MXCSR and poisons it
            // before either success or an explicit service refusal.
            let result = code.run(&mut actual, &mut view);
            let returned = mxcsr();
            drop(original);
            assert_eq!(harness.incoming_mxcsr, [0x1f80]);
            assert_eq!(returned, caller);
            assert_eq!(
                result,
                if fail_part.is_some() {
                    MemoryStatus::Permission as u32
                } else {
                    MemoryStatus::Success as u32
                }
            );
            assert_eq!(
                view.completed_bytes,
                if fail_part.is_some() { 0 } else { 8 }
            );
            assert_eq!(harness.requests.len(), 1);
        }
    }
}

#[test]
fn native_staging_defers_all_destinations_and_writeback_on_later_faults() {
    for load in [false, true] {
        for pair in [false, true] {
            for bytes in [1, 2, 4, 8, 16] {
                if pair && bytes < DWORD_BYTES {
                    continue;
                }
                for mode in [
                    AddressMode::Offset,
                    AddressMode::PreIndex,
                    AddressMode::PostIndex,
                ] {
                    for residue in [0, 1, 4, 7, 8, 12, 15] {
                        let operation = operand(load, bytes, pair, Register::X(2), residue, mode);
                        let mut body = Code::new();
                        emit_context(&mut body, &operation, GUEST_PC);
                        let code = NativeCode::new(&body);
                        for fail_part in [None, Some(1)] {
                            let mut actual = state();
                            let original = actual.clone();
                            let mut expected = original.clone();
                            let mut harness = Harness {
                                ram: core::array::from_fn(|i| i as u8 ^ 0xa5),
                                fail_part,
                                requests: vec![],
                                incoming_mxcsr: vec![],
                            };
                            let old_ram = harness.ram;
                            let mut view = view(&mut harness);
                            let result = code.run(&mut actual, &mut view);
                            let transfer = Transfer::from_operand(&operation).unwrap();
                            let address = GUEST_BASE
                                + 32
                                + if mode == AddressMode::PostIndex {
                                    0
                                } else {
                                    residue as u64
                                };
                            assert_eq!(
                                harness.requests,
                                vec![(
                                    address,
                                    u32::from(transfer.quantity_bytes()),
                                    transfer.descriptor(false),
                                    GUEST_PC
                                )]
                            );
                            let total = usize::from(transfer.quantity_bytes());
                            // Independently derive source Mem geometry from the
                            // input scenario, never from native status/prefix.
                            let parts = if total >= 16 {
                                if address.is_multiple_of(8) {
                                    total / 8
                                } else {
                                    total
                                }
                            } else if (address as usize & 15) + total <= 16 {
                                1
                            } else if pair && address.is_multiple_of(u64::from(bytes)) {
                                usize::from(PAIR_ELEMENTS)
                            } else {
                                total
                            };
                            let fault = fail_part.is_some_and(|part| part < parts);
                            let completed = if fault { total / parts } else { total };
                            let expected_status = if fault {
                                MemoryStatus::Permission
                            } else {
                                MemoryStatus::Success
                            };
                            assert_eq!(result, expected_status as u32);
                            assert_eq!(view.fault_kind, expected_status as u32);
                            assert_eq!(view.completed_bytes, completed as u64);
                            let success = !fault;
                            if success && mode != AddressMode::Offset {
                                expected.x[2] += residue as u64;
                            }
                            let start = (address - GUEST_BASE) as usize;
                            for element in 0..transfer.elements {
                                let vector = transfer.vectors[element as usize] as usize;
                                let offset = element as usize * bytes as usize;
                                if load && success {
                                    let mut value = [0u8; 16];
                                    value[..bytes as usize].copy_from_slice(
                                        &old_ram[start + offset..start + offset + bytes as usize],
                                    );
                                    expected.v[vector] = [
                                        u64::from_le_bytes(value[..8].try_into().unwrap()),
                                        u64::from_le_bytes(value[8..].try_into().unwrap()),
                                    ];
                                }
                            }
                            assert_eq!(
                                actual, expected,
                                "load={load} bytes={bytes} pair={pair} mode={mode:?} residue={residue} fail={fail_part:?}"
                            );
                            let mut expected_ram = old_ram;
                            if !load {
                                let staged: Vec<_> = (0..transfer.elements)
                                    .flat_map(|element| {
                                        low_bytes(
                                            original.v[transfer.vectors[element as usize] as usize],
                                        )[..bytes as usize]
                                            .to_vec()
                                    })
                                    .collect();
                                expected_ram[start..start + completed]
                                    .copy_from_slice(&staged[..completed]);
                            }
                            assert_eq!(harness.ram, expected_ram);
                            if !success {
                                assert_eq!(
                                    (view.fault_kind, view.fault_address, view.fault_pc),
                                    (
                                        MemoryStatus::Permission as u32,
                                        address + completed as u64,
                                        GUEST_PC
                                    )
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn literal_loads_zero_upper_bits_and_commit_only_after_the_complete_read() {
    for bytes in [DWORD_BYTES, QWORD_BYTES, VECTOR_BYTES] {
        for destination in 0..VECTOR_REGISTER_COUNT {
            for residue in [0, 4, 8, 12] {
                let address = GUEST_BASE + 32 + residue;
                let operation = Operation::Literal(literal::Operand {
                    address,
                    transfer: literal::Transfer::Simd { destination, bytes },
                });
                let checked = CheckedOperand::from_operation(
                    &operation,
                    CheckedMemoryProfile::SpAlignmentEnabled,
                )
                .unwrap();
                let mut body = Code::new();
                checked.emit_context(&mut body, GUEST_PC);
                let code = NativeCode::new(&body);
                for fail_part in [None, Some(0), Some(1)] {
                    let mut actual = state();
                    actual.sp |= 1; // Literal loads have no SP alignment check.
                    let mut expected = actual.clone();
                    let mut harness = Harness {
                        ram: core::array::from_fn(|i| i as u8 ^ 0xa5),
                        fail_part,
                        requests: vec![],
                        incoming_mxcsr: vec![],
                    };
                    let old_ram = harness.ram;
                    let mut view = view(&mut harness);
                    let result = code.run(&mut actual, &mut view);
                    let total = usize::from(bytes);
                    let parts = if bytes == VECTOR_BYTES {
                        if address.is_multiple_of(8) { 2 } else { total }
                    } else if (address as usize & 15) + total <= 16 {
                        1
                    } else {
                        total
                    };
                    let fault = fail_part.is_some_and(|part| part < parts);
                    let completed = if fault {
                        fail_part.unwrap() * total / parts
                    } else {
                        total
                    };
                    let status = if fault {
                        MemoryStatus::Permission
                    } else {
                        MemoryStatus::Success
                    };
                    assert_eq!(result, status as u32);
                    assert_eq!(view.completed_bytes, completed as u64);
                    assert_eq!(
                        harness.requests,
                        vec![(address, u32::from(bytes), flags::ASIMD, GUEST_PC)]
                    );
                    if !fault {
                        let start = (address - GUEST_BASE) as usize;
                        let mut loaded = [0; 16];
                        loaded[..total].copy_from_slice(&old_ram[start..start + total]);
                        expected.v[usize::from(destination)] = [
                            u64::from_le_bytes(loaded[..8].try_into().unwrap()),
                            u64::from_le_bytes(loaded[8..].try_into().unwrap()),
                        ];
                    } else {
                        assert_eq!(
                            (view.fault_kind, view.fault_address, view.fault_pc),
                            (status as u32, address + completed as u64, GUEST_PC)
                        );
                    }
                    assert_eq!(actual, expected);
                    assert_eq!(harness.ram, old_ram);
                }
            }
        }
    }
}

#[test]
fn original_sp_fault_precedes_offset_and_callback() {
    let operation = operand(false, 16, true, Register::Sp, -1, AddressMode::PreIndex);
    let mut body = Code::new();
    emit_context(&mut body, &operation, GUEST_PC);
    let code = NativeCode::new(&body);
    let mut actual = state();
    actual.sp += 1;
    let original = actual.clone();
    let mut harness = Harness {
        ram: [0xa5; RAM_BYTES],
        fail_part: None,
        requests: vec![],
        incoming_mxcsr: vec![],
    };
    let mut view = view(&mut harness);
    assert_eq!(
        code.run(&mut actual, &mut view),
        MemoryStatus::StackAlignment as u32
    );
    assert_eq!(actual, original);
    assert!(harness.requests.is_empty());
    assert_eq!(
        (view.fault_address, view.fault_pc, view.completed_bytes),
        (original.sp, GUEST_PC, 0)
    );
}

#[test]
fn register_extensions_and_zero_index_keep_original_inputs() {
    use crate::aarch64::simd::memory;
    for load in [false, true] {
        for bytes in [1u8, 2, 4, 8, 16] {
            for (extend, value, mathematical) in [
                (IndexExtend::Uxtw, 0xaaaa_bbbb_0000_0003, 3i64),
                (IndexExtend::Sxtw, 0xaaaa_bbbb_ffff_fffd, -3),
                (IndexExtend::Lsl, 3, 3),
                (IndexExtend::Sxtx, u64::MAX - 2, -3),
            ] {
                for shift in [0, bytes.trailing_zeros() as u8] {
                    let mut actual = state();
                    actual.x[5] = value;
                    actual.x[2] = (GUEST_BASE + 32)
                        .wrapping_sub(mathematical.wrapping_shl(u32::from(shift)) as u64);
                    let original = actual.clone();
                    let operation = Operand::MemoryRegisterOffset(memory::Operand {
                        load,
                        bytes,
                        vector: 31,
                        base: Register::X(2),
                        index: Register::X(5),
                        extend,
                        shift,
                    });
                    let mut body = Code::new();
                    emit_context(&mut body, &operation, GUEST_PC);
                    let code = NativeCode::new(&body);
                    let mut harness = Harness {
                        ram: core::array::from_fn(|index| index as u8 ^ 0x59),
                        fail_part: None,
                        requests: vec![],
                        incoming_mxcsr: vec![],
                    };
                    let old_ram = harness.ram;
                    let mut view = view(&mut harness);
                    assert_eq!(
                        code.run(&mut actual, &mut view),
                        MemoryStatus::Success as u32
                    );
                    let mut expected = original.clone();
                    let mut expected_ram = old_ram;
                    if load {
                        let mut value = [0u8; 16];
                        value[..usize::from(bytes)]
                            .copy_from_slice(&old_ram[32..32 + usize::from(bytes)]);
                        expected.v[31] = [
                            u64::from_le_bytes(value[..8].try_into().unwrap()),
                            u64::from_le_bytes(value[8..].try_into().unwrap()),
                        ];
                    } else {
                        expected_ram[32..32 + usize::from(bytes)]
                            .copy_from_slice(&low_bytes(original.v[31])[..usize::from(bytes)]);
                    }
                    assert_eq!(actual, expected);
                    assert_eq!(harness.ram, expected_ram);
                    assert_eq!(
                        harness.requests,
                        vec![(
                            GUEST_BASE + 32,
                            u32::from(bytes),
                            flags::ASIMD | flags::TAG_CHECKED | if load { 0 } else { flags::WRITE },
                            GUEST_PC
                        )]
                    );
                }
            }
        }
    }
    // A ZR index discards its slot, and an index aliasing the base uses the
    // base's original value, not the effective address.
    for (index, base_value) in [
        (Register::Zero, GUEST_BASE + 32),
        (Register::X(2), GUEST_BASE / 2 + 16),
    ] {
        let operation = Operand::MemoryRegisterOffset(memory::Operand {
            load: false,
            bytes: 8,
            vector: 31,
            base: Register::X(2),
            index,
            extend: IndexExtend::Lsl,
            shift: 0,
        });
        let mut body = Code::new();
        emit_context(&mut body, &operation, GUEST_PC);
        let code = NativeCode::new(&body);
        let mut actual = state();
        actual.x[2] = base_value;
        let original = actual.clone();
        let mut harness = Harness {
            ram: [0; RAM_BYTES],
            fail_part: None,
            requests: vec![],
            incoming_mxcsr: vec![],
        };
        let mut view = view(&mut harness);
        assert_eq!(
            code.run(&mut actual, &mut view),
            MemoryStatus::Success as u32
        );
        assert_eq!(actual, original);
        assert_eq!(harness.requests[0].0, GUEST_BASE + 32);
    }
}

#[test]
fn non_temporal_pairs_stage_duplicate_store_sources() {
    for load in [false, true] {
        for bytes in [4, 8, 16] {
            let vectors = if load { [3, 31] } else { [31, 31] };
            let operation = non_temporal::Operand {
                load,
                bytes,
                data: non_temporal::Data::Vector(vectors),
                base: Register::Sp,
                displacement: 8,
            };
            let mut body = Code::new();
            emit_non_temporal_context(&mut body, &operation, GUEST_PC);
            let code = NativeCode::new(&body);
            let mut actual = state();
            let original = actual.clone();
            let mut harness = Harness {
                ram: core::array::from_fn(|index| index as u8 ^ 0x59),
                fail_part: None,
                requests: vec![],
                incoming_mxcsr: vec![],
            };
            let old_ram = harness.ram;
            let mut view = view(&mut harness);
            assert_eq!(
                code.run(&mut actual, &mut view),
                MemoryStatus::Success as u32
            );
            let mut expected = original.clone();
            let mut expected_ram = old_ram;
            for (element, vector) in vectors.into_iter().enumerate() {
                let start = 40 + element * usize::from(bytes);
                if load {
                    let mut value = [0u8; 16];
                    value[..usize::from(bytes)]
                        .copy_from_slice(&old_ram[start..start + usize::from(bytes)]);
                    expected.v[usize::from(vector)] = [
                        u64::from_le_bytes(value[..8].try_into().unwrap()),
                        u64::from_le_bytes(value[8..].try_into().unwrap()),
                    ];
                } else {
                    expected_ram[start..start + usize::from(bytes)].copy_from_slice(
                        &low_bytes(original.v[usize::from(vector)])[..usize::from(bytes)],
                    );
                }
            }
            assert_eq!(actual, expected);
            assert_eq!(harness.ram, expected_ram);
            assert_eq!(
                harness.requests,
                vec![(
                    GUEST_BASE + 40,
                    u32::from(bytes * PAIR_ELEMENTS),
                    flags::ASIMD
                        | flags::PAIR
                        | flags::NON_TEMPORAL
                        | if load { 0 } else { flags::WRITE },
                    GUEST_PC
                )]
            );
        }
    }
}

#[test]
fn checked_adapter_keeps_disabled_sp_unaligned_read_capability() {
    use crate::aarch64::{Operation, Register};
    let operation = Operation::Simd(Operand::Memory {
        load: true,
        bytes: 8,
        vector: 0,
        base: Register::Sp,
        displacement: 0,
        mode: AddressMode::Offset,
    });
    let enabled =
        CheckedOperand::from_operation(&operation, CheckedMemoryProfile::SpAlignmentEnabled)
            .unwrap();
    let disabled =
        CheckedOperand::from_operation(&operation, CheckedMemoryProfile::SpAlignmentDisabled)
            .unwrap();
    assert_eq!(
        enabled.requirements().required_sp_alignment,
        SpAlignmentRequirement::Enabled
    );
    assert_eq!(
        disabled.requirements().required_sp_alignment,
        SpAlignmentRequirement::Disabled
    );
    assert_eq!(enabled.requirements().required_host_caps, 0);
    assert_eq!(
        disabled.requirements().required_host_caps,
        host_caps::ATOMIC_LOAD16
    );
    let mut enabled_code = Code::new();
    let mut disabled_code = Code::new();
    enabled.emit_context(&mut enabled_code, GUEST_PC);
    disabled.emit_context(&mut disabled_code, GUEST_PC);
    assert!(enabled_code.len() > disabled_code.len());
}
