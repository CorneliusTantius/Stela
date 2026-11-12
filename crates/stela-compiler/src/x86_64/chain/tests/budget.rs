//! Native interruption-gate safety and CPU measurements.
use super::super::*;
use crate::GuestState;
use alloc::{boxed::Box, format, vec::Vec};
use core::ffi::c_void;
use std::{
    fs,
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
/// The default block table's slot mask and ITLB's set mask.
const TABLE_MASK: u32 = LOOKUP_ENTRIES as u32 - 1;
const ITLB_MASK: u32 = ITLB_ENTRIES as u32 / 2 - 1;

fn lookup_slot(pc: u64, key: u64) -> usize {
    super::super::lookup_slot(pc, key, TABLE_MASK)
}

fn itlb_slot(pc: u64, context: u64) -> usize {
    super::super::itlb_slot(pc, context, ITLB_MASK)
}

fn itlb_salt(context: u64) -> u32 {
    super::super::itlb_salt(context, ITLB_MASK)
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
    fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
    fn munmap(address: *mut c_void, bytes: usize) -> i32;
}
struct Mapping {
    page: *mut c_void,
}
impl Mapping {
    fn new() -> Self {
        // SAFETY: one private anonymous page; this object owns it through Drop.
        let page = unsafe { mmap(core::ptr::null_mut(), 4096, 3, 0x22, -1, 0) };
        assert_ne!(page as usize, usize::MAX);
        Self { page }
    }
    fn address(&self) -> u64 {
        self.page as usize as u64
    }
    fn install(&self, code: &[u8]) {
        assert!(code.len() <= 4096);
        // SAFETY: the owned RW page covers code and has no concurrent executor;
        // it becomes RX before run and remains mapped through native return.
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), self.page.cast(), code.len());
            assert_eq!(mprotect(self.page, 4096, 5), 0);
        }
    }
    fn run(&self, control: u64) -> u128 {
        let mut frame = frame(control);
        // SAFETY: installed thunk has the SysV128 return ABI and touches only
        // its frame and control/table. It clobbers caller-volatile registers.
        unsafe {
            let enter: unsafe extern "sysv64" fn(*mut GuestState) -> u128 =
                core::mem::transmute(self.page);
            enter(&mut *frame)
        }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: unique mapping ownership; every executor has returned or joined.
        assert_eq!(unsafe { munmap(self.page, 4096) }, 0);
    }
}
const TARGET: GuestAddress = GuestAddress(0x1234);
const INTERRUPT_TEST_BUDGET: u64 = 4096;
const RENDEZVOUS_AFTER: u64 = 1000;
/// A frame that finds `control`.
fn frame(control: u64) -> Box<GuestState> {
    let mut frame = Box::new(GuestState::default());
    frame.anchors[Anchor::Control] = control;
    frame
}
/// The direct exit to [`TARGET`] at host address `at`, its patch point
/// linked to a thunk right after it into `entry`, and the thunk, which
/// returns through the exit's RAX and EDX.
fn exit_into_thunk(at: u64, entry: u64, policy: Interruption) -> Vec<u8> {
    let mut code = direct_exit_at(at, TARGET, ExitKind::Direct).to_vec();
    let thunk_at = at + code.len() as u64;
    let point = direct_patch(at);
    let offset = (point - at) as usize;
    code[offset..offset + PATCH_BYTES].copy_from_slice(&jump(point, thunk_at).unwrap());
    let thunk = thunk_with_policy(
        ThunkPlan {
            at: thunk_at,
            retired: 7,
            block: 3,
            entry,
            fallback: Fallback::Return(ExitKind::Direct.into()),
        },
        policy,
    )
    .unwrap();
    code.extend(thunk);
    code
}

/// [`exit_into_thunk`] at the mapping's start, into itself.
fn direct(mapping: &Mapping, policy: Interruption) -> Vec<u8> {
    exit_into_thunk(mapping.address(), mapping.address(), policy)
}

/// The link slot of an exit to [`TARGET`] at the mapping's start, linked
/// into itself, and the exit.
fn slot(mapping: &Mapping) -> Vec<u8> {
    let at = mapping.address();
    let mut code = empty_link_at(at, POLLED_LINK_BYTES);
    code.extend(direct_exit_at(
        at + POLLED_LINK_BYTES as u64,
        TARGET,
        ExitKind::Direct,
    ));
    let (body, bytes) = link(at, POLLED_LINK_BYTES, 7, 3, at).unwrap();
    let start = (body - at) as usize;
    code[start..start + bytes.len()].copy_from_slice(&bytes);
    let point = (slot_patch(at) - at) as usize;
    code[point..point + PATCH_BYTES].copy_from_slice(&NOP5);
    code
}
fn exited(value: u128) -> (u64, u64) {
    (value as u64, ExitWord::split((value >> 64) as u64).0)
}

#[test]
fn epoch_mismatch_exits_before_spending_or_changing_accounting() {
    let mut control = Box::new(ChainControl {
        count: ChainControl::counting(17, 19),
        linked: 23,
        block: 29,
        interrupt_epoch: 1,
        observed_interrupt_epoch: 0,
        ..ChainControl::default()
    });
    let address = (&mut *control as *mut ChainControl) as u64;
    let native = Mapping::new();
    native.install(&direct(&native, Interruption::Epoch));
    assert_eq!(
        exited(native.run(address)),
        (TARGET.0, ExitKind::Direct as u64)
    );
    assert_eq!(
        (
            control.remaining(),
            control.retired(),
            control.linked,
            control.block
        ),
        (17, 19, 23, 29)
    );
    control.interrupt_epoch = u64::MAX;
    control.observed_interrupt_epoch = u64::MAX - 1;
    assert_eq!(
        exited(native.run(address)),
        (TARGET.0, ExitKind::Direct as u64)
    );
    assert_eq!(
        (
            control.remaining(),
            control.retired(),
            control.linked,
            control.block
        ),
        (17, 19, 23, 29)
    );
}

#[test]
fn dynamic_lookup_pending_and_saturated_epochs_never_touch_the_invalid_table() {
    for (kind, btype) in [(ExitKind::Return, 0), (ExitKind::Indirect, 3)] {
        let mut control = Box::new(ChainControl {
            count: ChainControl::counting(17, 19),
            hits: 23,
            linked: 29,
            block: 31,
            table: 1 << 63,
            ..ChainControl::default()
        });
        let native = Mapping::new();
        let mut prefix = Code::new();
        prefix.asm().mov_imm64(Rax, TARGET.0);
        let mut code = prefix.into_bytes();
        code.extend(lookup_thunk(7, None, kind, btype).unwrap());
        let address = (&mut *control as *mut ChainControl) as u64;
        native.install(&code);
        for (epoch, observed) in [(1, 0), (u64::MAX, u64::MAX - 1)] {
            control.interrupt_epoch = epoch;
            control.observed_interrupt_epoch = observed;
            let prior = (
                control.remaining(),
                control.retired(),
                control.hits,
                control.linked,
                control.block,
            );
            assert_eq!(exited(native.run(address)), (TARGET.0, kind as u64));
            assert_eq!(
                (
                    control.remaining(),
                    control.retired(),
                    control.hits,
                    control.linked,
                    control.block
                ),
                prior
            );
        }
    }
}

/// Every Rust access is atomic; native aligned loads/stores implement x86's
/// corresponding atomic-width memory accesses. The native runner alone writes
/// the local prefix; the notifying CPU writes only the separate epoch word.
#[repr(C, align(64))]
struct Shared {
    count: AtomicU64,
    block: AtomicU64,
    contexts: [AtomicU64; 2],
    table: AtomicU64,
    hits: AtomicU64,
    linked: AtomicU64,
    stamps: AtomicU64,
    epoch: AtomicU64,
    observed: AtomicU64,
    salts: [AtomicU32; 2],
    itlb: AtomicU64,
}
const _: () = assert!(core::mem::offset_of!(Shared, epoch) == INTERRUPT_EPOCH as usize);
const _: () = assert!(core::mem::offset_of!(Shared, observed) == OBSERVED_INTERRUPT_EPOCH as usize);
const _: () = assert!(core::mem::offset_of!(Shared, linked) == LINKED as usize);
const _: () = assert!(core::mem::offset_of!(Shared, itlb) == ITLB as usize);
impl Shared {
    /// The transfers and instructions its count holds now.
    fn counted(&self) -> (u64, u64) {
        let control = ChainControl {
            count: self.count.load(Ordering::Acquire),
            ..ChainControl::default()
        };
        (control.remaining(), control.retired())
    }

    fn new() -> Self {
        Self {
            count: AtomicU64::new(ChainControl::counting(INTERRUPT_TEST_BUDGET, 0)),
            block: AtomicU64::new(0),
            contexts: [AtomicU64::new(0), AtomicU64::new(0)],
            table: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            linked: AtomicU64::new(0),
            stamps: AtomicU64::new(0),
            epoch: AtomicU64::new(0),
            observed: AtomicU64::new(0),
            salts: [AtomicU32::new(0), AtomicU32::new(0)],
            itlb: AtomicU64::new(0),
        }
    }
}

/// A test successor rendezvous orders the runner's prior plain accounting
/// stores before publication. A notifier-side count load alone cannot do that:
/// x86 permits a later epoch load to pass earlier stores to another address.
#[repr(C, align(64))]
struct Rendezvous {
    ready: AtomicU64,
    release: AtomicU64,
}

#[derive(Debug)]
struct InterruptionOutcome {
    published: u64,
    linked: u64,
    retired: u64,
    budget: u64,
    block: u64,
    epoch: u64,
    observed: u64,
    result: (u64, u64),
}
impl InterruptionOutcome {
    fn interrupted_at_rendezvous(&self) -> bool {
        self.published == RENDEZVOUS_AFTER
            && self.linked == self.published
            && self.linked < INTERRUPT_TEST_BUDGET
            && self.budget == INTERRUPT_TEST_BUDGET - self.linked
            && self.retired == self.linked * 7
            && self.block == 3
            && self.epoch == 1
            && self.observed == 0
            && self.result == (TARGET.0, ExitKind::Direct as u64)
    }
}

/// Only the successor prefix is test synchronization; the thunk is emitted by
/// the production constructor with its normal guard and accounting unchanged.
fn rendezvous_backedge(native: &Mapping, control: u64, gate: u64, policy: Interruption) -> Vec<u8> {
    let mut prefix = Code::new();
    prefix.asm().mov_imm64(Rcx, control);
    // Each transfer counts its 7 instructions with it.
    prefix.asm().mov_imm64(
        Rdx,
        ChainControl::counting(
            INTERRUPT_TEST_BUDGET - RENDEZVOUS_AFTER,
            7 * RENDEZVOUS_AFTER,
        ),
    );
    prefix
        .asm()
        .alu_load(Alu::Cmp, Qword, Rdx, Mem::base(Rcx, COUNT));
    let ordinary = prefix.asm().jcc8(Cond::Ne);
    prefix.asm().mov_imm64(Rax, gate);
    {
        let mut asm = prefix.asm();
        // This worker-side locked publication orders all earlier native
        // accounting stores; it is absent from the production thunk.
        // Intel SDM Vol. 3: loads/stores are not reordered with locked instructions.
        asm.lock();
        asm.alu_imm8(
            Alu::Add,
            Qword,
            Mem::base(Rax, core::mem::offset_of!(Rendezvous, ready) as i32),
            1,
        );
    }
    let waiting = prefix.len();
    prefix.asm().pause();
    prefix.asm().alu_imm8(
        Alu::Cmp,
        Qword,
        Mem::base(Rax, core::mem::offset_of!(Rendezvous, release) as i32),
        0,
    );
    let wait = prefix.asm().jcc8(Cond::E);
    crate::x86_64::asm::resolve(&mut prefix, wait, waiting);
    prefix.asm().bind(ordinary);
    let exit = exit_into_thunk(
        native.address() + prefix.len() as u64,
        native.address(),
        policy,
    );
    let mut bytes = prefix.into_bytes();
    bytes.extend(exit);
    bytes
}

/// The transfers a thunk made from the test budget to `budget`, which wraps
/// when a thunk finds none left.
fn transfers(budget: u64) -> u64 {
    if budget > INTERRUPT_TEST_BUDGET {
        INTERRUPT_TEST_BUDGET
    } else {
        INTERRUPT_TEST_BUDGET - budget
    }
}

fn interrupt_at_rendezvous(policy: Interruption) -> InterruptionOutcome {
    let control = Arc::new(Shared::new());
    let gate = Arc::new(Rendezvous {
        ready: AtomicU64::new(0),
        release: AtomicU64::new(0),
    });
    let native = Mapping::new();
    native.install(&rendezvous_backedge(
        &native,
        Arc::as_ptr(&control) as u64,
        Arc::as_ptr(&gate) as u64,
        policy,
    ));
    let entry = native.address() as usize;
    let retained = Arc::clone(&control);
    let retained_gate = Arc::clone(&gate);
    let worker = std::thread::spawn(move || {
        let mut frame = frame(Arc::as_ptr(&retained) as u64);
        // SAFETY: main keeps the RX mapping until join; both allocations
        // remain owned, and the generated program writes only their declared
        // native counters/test rendezvous using caller-volatile registers.
        let result = unsafe {
            let run: unsafe extern "sysv64" fn(*mut GuestState) -> u128 =
                core::mem::transmute(entry);
            run(&mut *frame)
        };
        (result, retained, retained_gate)
    });
    let began = Instant::now();
    while gate.ready.load(Ordering::Acquire) == 0 {
        if began.elapsed() >= Duration::from_secs(5) {
            control.epoch.fetch_add(1, Ordering::Release);
            gate.release.store(1, Ordering::Release);
            let _ = worker.join();
            panic!("native backedge did not reach the ordered rendezvous");
        }
        std::thread::yield_now();
    }
    // Ready synchronizes the native accounting prefix. Publish before opening
    // the rendezvous; the next production guard must observe the epoch.
    let published = INTERRUPT_TEST_BUDGET - control.counted().0;
    control.epoch.fetch_add(1, Ordering::Release);
    gate.release.store(1, Ordering::Release);
    let (result, retained, _retained_gate) = worker.join().unwrap();
    let (budget, retired) = retained.counted();
    InterruptionOutcome {
        published,
        linked: transfers(budget),
        retired,
        budget,
        block: retained.block.load(Ordering::Acquire),
        epoch: retained.epoch.load(Ordering::Acquire),
        observed: retained.observed.load(Ordering::Acquire),
        result: exited(result),
    }
}

#[test]
fn foreign_epoch_interrupts_the_native_backedge_after_an_ordered_rendezvous() {
    for _ in 0..32 {
        let outcome = interrupt_at_rendezvous(Interruption::Epoch);
        assert!(outcome.interrupted_at_rendezvous(), "{outcome:?}");
    }
}

#[test]
fn rendezvous_oracle_rejects_an_ignored_epoch() {
    let outcome = interrupt_at_rendezvous(Interruption::Legacy);
    assert!(!outcome.interrupted_at_rendezvous(), "{outcome:?}");
    assert_eq!(
        (outcome.published, outcome.epoch, outcome.observed),
        (RENDEZVOUS_AFTER, 1, 0)
    );
    assert_eq!(outcome.linked, INTERRUPT_TEST_BUDGET);
    assert_eq!(outcome.budget, EXHAUSTED);
    assert_eq!(outcome.retired, INTERRUPT_TEST_BUDGET * 7);
    assert_eq!(outcome.result, (TARGET.0, ExitKind::Direct as u64));
}

#[test]
fn an_already_checked_native_boundary_allows_one_transfer_then_stops() {
    let mut control = Box::new(ChainControl {
        count: ChainControl::counting(17, 0),
        interrupt_epoch: 1,
        ..ChainControl::default()
    });
    let native = Mapping::new();
    let address = (&mut *control as *mut ChainControl) as u64;
    let mut prefix = Code::new();
    prefix.asm().mov_imm64(Rcx, address);
    prefix.asm().mov_imm64(Rdx, 0);
    let enter_tail = prefix.asm().jmp();
    let exit = native.address() + prefix.len() as u64;
    let at = exit + DIRECT_EXIT_BYTES as u64;
    let body = thunk(at, 7, 3, at, Fallback::Jump(exit)).unwrap();
    // Golden legacy encodings identify the exact post-guard native window.
    // The first entry has already admitted a transfer with the old epoch;
    // its backedge re-enters the full, unchanged production thunk.
    const AFTER_GUARD: usize = 17;
    assert_eq!(
        &body[7..15],
        &[0x48, 0x8b, 0x51, 0x40, 0x48, 0x3b, 0x51, 0x48]
    );
    assert_eq!(body[15], 0x75);
    assert_eq!(AFTER_GUARD + usize::from(body[16]), body.len() - JUMP_BYTES);
    assert_eq!(&body[AFTER_GUARD..AFTER_GUARD + 3], &[0x48, 0x81, 0x01]);
    assert_eq!(
        body[AFTER_GUARD + 3..AFTER_GUARD + 7],
        ((TRANSFER + 7) as u32).to_le_bytes()
    );
    let distance = relative(
        native.address() + enter_tail.end() as u64,
        at + AFTER_GUARD as u64,
    )
    .unwrap();
    prefix.patch(enter_tail.offset(), distance.to_le_bytes());
    let mut code = prefix.into_bytes();
    code.extend(direct_exit_at(exit, TARGET, ExitKind::Direct));
    code.extend(body);
    native.install(&code);
    assert_eq!(
        exited(native.run(address)),
        (TARGET.0, ExitKind::Direct as u64)
    );
    assert_eq!(
        (
            control.remaining(),
            control.linked,
            control.retired(),
            control.block
        ),
        (16, 0, 7, 3)
    );
    assert_eq!(
        (control.interrupt_epoch, control.observed_interrupt_epoch),
        (1, 0)
    );
}

#[repr(align(64))]
struct Aligned(ChainControl);
#[test]
#[ignore = "manual: opt-in"]
fn native_interruption_gate_costs() {
    const ITERATIONS: u64 = 500_000;
    let output = std::env::var_os("STELA_TEST_CHAIN_BENCH_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("stela-chain-bench-{}", std::process::id()))
        });
    fs::create_dir_all(&output).unwrap();
    let mut report = fs::File::create(output.join("results.txt")).unwrap();
    writeln!(
        report,
        "COMPILER_SHA256={} ITERATIONS={ITERATIONS} SAMPLES=7",
        crate::SOURCE_SHA256
    )
    .unwrap();
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Mode {
        /// An exit whose patch point jumps to a thunk into the block.
        Direct,
        /// A link slot's body, which its patch point falls into; polled.
        Slot,
        /// An exit whose patch point jumps to its tail and the table probe.
        Lookup,
        /// An exit whose patch point jumps to its tail and a cell probe.
        Cell,
    }
    const KEY: u64 = block_key(0x8_0000_0000, 1);
    for mode in [Mode::Direct, Mode::Slot, Mode::Lookup, Mode::Cell] {
        let mut table = LookupTable::new();
        let mut itlb = LookupTable::itlb();
        let mut control = Box::new(Aligned(ChainControl {
            table: table.address(),
            itlb: itlb.address(),
            contexts: [5, 7],
            salts: [itlb_salt(5), itlb_salt(7)],
            masks: [TABLE_MASK, ITLB_MASK],
            ..ChainControl::default()
        }));
        let context = control.0.contexts[half(TARGET.0)];
        itlb.insert(
            itlb_slot(TARGET.0, context),
            LookupEntry::page(TARGET.0 & !0xfff, context, KEY),
        );
        let pointer = (&mut control.0 as *mut ChainControl) as u64;
        for policy in [
            Interruption::Legacy,
            Interruption::LockedBudget,
            Interruption::Flag,
            Interruption::Epoch,
        ] {
            // A slot's body has the production gate alone.
            if mode == Mode::Slot && policy != Interruption::Epoch {
                continue;
            }
            let native = Mapping::new();
            let at = native.address();
            let entry = LookupEntry {
                pc: TARGET.0,
                key: KEY,
                entry: at,
                block: 3,
                targets: 15,
            };
            // The exit, its tail after it and the probes after that.
            let through_tail = |cell: Option<u64>| {
                let mut code = direct_exit_at(at, TARGET, ExitKind::Direct).to_vec();
                let tail = at + code.len() as u64;
                let point = direct_patch(at);
                let offset = (point - at) as usize;
                code[offset..offset + PATCH_BYTES].copy_from_slice(&jump(point, tail).unwrap());
                let probes = (tail + CELL_TAIL_BYTES as u64).next_multiple_of(16);
                match cell {
                    Some(cell) => code.extend(
                        cell_tail(
                            tail,
                            cell,
                            ExitKind::Direct,
                            7,
                            probes + CELL_PROBE_ENTRY as u64,
                        )
                        .unwrap(),
                    ),
                    None => code.extend(
                        lookup_tail(tail, ExitKind::Direct, 7, probes + PROBE_ENTRY as u64, 0)
                            .unwrap(),
                    ),
                }
                code.resize((probes - at) as usize, 0xcc);
                code.extend(dispatcher_with_policy(0, policy).unwrap());
                code
            };
            let code = match mode {
                Mode::Direct => direct(&native, policy),
                Mode::Slot => slot(&native),
                Mode::Lookup => {
                    table.set(lookup_slot(TARGET.0, KEY), entry);
                    through_tail(None)
                }
                Mode::Cell => {
                    let cell = table.link_cell(1, TARGET.0, Some(entry));
                    through_tail(Some(cell))
                }
            };
            native.install(&code);
            let name = format!("{mode:?}-{policy:?}").to_lowercase();
            fs::write(output.join(format!("{name}.bin")), &code).unwrap();
            let mut samples = Vec::new();
            for sample in 0..8 {
                control.0.set_budget(ITERATIONS);
                control.0.set_retired(0);
                control.0.hits = 0;
                let start = Instant::now();
                let result = native.run(pointer);
                let elapsed = start.elapsed();
                assert_eq!(exited(result), (TARGET.0, ExitKind::Direct as u64));
                assert_eq!(control.0.retired(), ITERATIONS * 7);
                assert_eq!(control.0.remaining(), EXHAUSTED);
                let hits = if mode == Mode::Lookup { ITERATIONS } else { 0 };
                assert_eq!(control.0.hits, hits);
                if sample != 0 {
                    samples.push(elapsed.as_nanos() as f64 / ITERATIONS as f64);
                }
            }
            samples.sort_by(f64::total_cmp);
            let line = format!(
                "CASE={name} BYTES={} NS_PER_TRANSFER={:.4} MIN={:.4} MAX={:.4}",
                code.len(),
                samples[3],
                samples[0],
                samples[6]
            );
            std::eprintln!("{line}");
            writeln!(report, "{line}").unwrap();
        }
    }
    ring_costs(&mut report);
    std::eprintln!("CHAIN_BENCH_OUTPUT={}", output.display());
}

/// Blocks in a ring of lookup transfers, each to the next one in a scrambled
/// order: a return or an exit out of the page at every block.
const RING: usize = 64;

/// Transfers around a [`RING`] of blocks, each of whose exits goes to the
/// next block through the table probe: through a tail of its own, as the
/// engine links them, or through one tail they all share, which leaves one
/// indirect jump for every target as the former shared dispatcher did.
fn ring_costs(report: &mut fs::File) {
    const ITERATIONS: u64 = 1 << 20;
    // Direct exits, whose patch points jump to their tails.
    const EXIT_BYTES: usize = DIRECT_EXIT_BYTES;
    const PAGE: usize = 4096;
    let bytes = RING * (EXIT_BYTES + TAIL_BYTES) + TAIL_BYTES + PAGE;
    let bytes = bytes.next_multiple_of(PAGE);
    // SAFETY: private anonymous pages, RX after the copy, unmapped below.
    let base = unsafe { mmap(core::ptr::null_mut(), bytes, 3, 0x22, -1, 0) };
    assert_ne!(base as usize, usize::MAX);
    let base = base as u64;
    // A full-period step through the ring's positions.
    let order: Vec<usize> = (0..RING).map(|i| (i * 37 + 11) % RING).collect();
    let pc = |block: usize| 0xffff_fe00_0010_0000 + 0x1000 * block as u64;
    let probes = base + (RING * (EXIT_BYTES + TAIL_BYTES) + TAIL_BYTES) as u64;
    let mut table = LookupTable::new();
    let mut itlb = LookupTable::itlb();
    // Each block's page has a frame of its own.
    let key = |block: usize| block_key(0x8_0000_0000 + 0x1000 * block as u64, 1);
    for block in 0..RING {
        itlb.insert(
            itlb_slot(pc(block), 5),
            LookupEntry::page(pc(block), 5, key(block)),
        );
    }
    for (name, shared) in [("ring-site", false), ("ring-shared", true)] {
        let shared_tail = base + (RING * (EXIT_BYTES + TAIL_BYTES)) as u64;
        let mut code = Vec::new();
        for block in 0..RING {
            let at = base + code.len() as u64;
            let next = order[(order.iter().position(|&b| b == block).unwrap() + 1) % RING];
            let tail = if shared {
                shared_tail
            } else {
                at + EXIT_BYTES as u64
            };
            let mut bytes = direct_exit_at(at, GuestAddress(pc(next)), ExitKind::Return).to_vec();
            let point = direct_patch(at);
            let offset = (point - at) as usize;
            bytes[offset..offset + PATCH_BYTES].copy_from_slice(&jump(point, tail).unwrap());
            code.extend(bytes);
            let own = at + EXIT_BYTES as u64;
            code.extend(
                lookup_tail(own, ExitKind::Return, 3, probes + PROBE_ENTRY as u64, 0).unwrap(),
            );
            table.set(
                lookup_slot(pc(block), key(block)),
                LookupEntry {
                    pc: pc(block),
                    key: key(block),
                    entry: at,
                    block: block as u32,
                    targets: 15,
                },
            );
        }
        code.extend(
            lookup_tail(
                shared_tail,
                ExitKind::Return,
                3,
                probes + PROBE_ENTRY as u64,
                0,
            )
            .unwrap(),
        );
        code.extend(lookup_dispatcher(0).unwrap());
        let mut control = Box::new(Aligned(ChainControl {
            table: table.address(),
            itlb: itlb.address(),
            contexts: [5, 5],
            salts: [itlb_salt(5); 2],
            masks: [TABLE_MASK, ITLB_MASK],
            ..ChainControl::default()
        }));
        // SAFETY: the mapping covers `code`; nothing runs it meanwhile.
        unsafe {
            assert_eq!(mprotect(base as *mut c_void, bytes, 3), 0);
            core::ptr::copy_nonoverlapping(code.as_ptr(), base as *mut u8, code.len());
            assert_eq!(mprotect(base as *mut c_void, bytes, 5), 0);
        }
        let mut samples = Vec::new();
        for sample in 0..8 {
            control.0.set_budget(ITERATIONS);
            control.0.set_retired(0);
            control.0.hits = 0;
            let mut state = frame((&mut control.0 as *mut ChainControl) as u64);
            let start = Instant::now();
            // SAFETY: the installed ring has the block ABI and touches only
            // its control and table; it clobbers caller-volatile registers.
            let result = unsafe {
                let enter: unsafe extern "sysv64" fn(*mut GuestState) -> u128 =
                    core::mem::transmute(base);
                enter(&mut *state)
            };
            let elapsed = start.elapsed();
            assert_eq!(
                ExitWord::split((result >> 64) as u64).0,
                ExitKind::Return as u64
            );
            assert_eq!(control.0.hits, ITERATIONS);
            assert_eq!(control.0.retired(), ITERATIONS * 3);
            if sample != 0 {
                samples.push(elapsed.as_nanos() as f64 / ITERATIONS as f64);
            }
        }
        samples.sort_by(f64::total_cmp);
        let line = format!(
            "CASE={name} BLOCKS={RING} NS_PER_TRANSFER={:.4} MIN={:.4} MAX={:.4}",
            samples[3], samples[0], samples[6]
        );
        std::eprintln!("{line}");
        writeln!(report, "{line}").unwrap();
    }
    // SAFETY: unique mapping; every run returned.
    assert_eq!(unsafe { munmap(base as *mut c_void, bytes) }, 0);
}
