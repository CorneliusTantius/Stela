//! PAC branch thunks whose exit takes a predicted tail, against the same
//! thunks whose exit takes a lookup tail: for RETAB, BRAA through X16 and
//! through another register, BLRAB and BLRAAZ, over random signed, forged
//! and stale-key pointers and modifiers, key switches, closed and disabled
//! keys, ITLB, block table and cell changes, entries that refuse the
//! branch's BTYPE, contexts, budgets and interruptions, the predicted tail
//! (its direct exit unlinked, through a cell tail or through a stamped
//! tail) completes the same instruction, takes the same transfer into the
//! same block or the same exit, and leaves the guest state, the memo and
//! the control the same, but for the table probe's count of its own
//! transfers. An unlinked direct exit returns what the thunk's own exit
//! returns.
use super::super::*;
use crate::block::{
    PointerAuthenticationKey as Key, PointerAuthenticationModifier as Modifier,
    PointerAuthenticationOperation as Operation,
};
use crate::x86_64::pointer::{
    self, AUTHENTICATED, Completion, DISABLED, MEMO_ENTRIES, MemoEntry, ServiceRoutine, TAG_WORDS,
};
use crate::{GuestState, aarch64::Register};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::ffi::c_void;
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

const PAGE: usize = 4096;
const THUNK: usize = 256;
const TAIL: usize = 1024;
const CELL_TAIL: usize = 1280;
const PROBES: usize = PAGE;
const REGION: usize = 3 * PAGE;
const BLOCKS: usize = 8;
const CONTEXTS: [u64; 3] = [
    5 << LOOKUP_SALT_BITS,
    9 << LOOKUP_SALT_BITS,
    13 << LOOKUP_SALT_BITS,
];
const KEYS: [u64; 2] = [block_key(0x8_0040_0000, 1), block_key(0x8_0040_0000, 2)];
const PC: u64 = 0x1_8000_2ffc;
const RAN: u32 = 7;
/// The BTYPEs entries accept: always BTYPE 0, some only that.
const TARGETS: [u32; 5] = [0b1111, 0b0001, 0b0101, 0b0011, 0b1001];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

struct Pages(*mut u8, usize);
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: our mapping, nothing runs it any more.
        assert_eq!(unsafe { munmap(self.0.cast(), self.1) }, 0);
    }
}
fn pages(bytes: usize) -> Pages {
    // SAFETY: private anonymous memory, unmapped on drop.
    let base = unsafe { mmap(core::ptr::null_mut(), bytes, 7, 0x22, -1, 0) };
    assert_ne!(base as usize, usize::MAX);
    Pages(base.cast(), bytes)
}
fn put(pages: &Pages, offset: usize, bytes: &[u8]) {
    assert!(offset + bytes.len() <= pages.1);
    // SAFETY: inside the mapping; nothing runs it while it is written.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), pages.0.add(offset), bytes.len()) };
}
impl Pages {
    fn at(&self, offset: usize) -> u64 {
        self.0 as u64 + offset as u64
    }
}

/// Blocks that return their marker in RAX and 99 in EDX.
fn blocks() -> Pages {
    let blocks = pages(PAGE);
    for block in 0..BLOCKS {
        let mut code = vec![0x48, 0xb8];
        code.extend((0x7700 + block as u64).to_le_bytes());
        code.extend([0xba, 99, 0, 0, 0, 0xc3]);
        put(&blocks, 64 * block, &code);
    }
    blocks
}

/// Target PCs: two pages in each half.
const PCS: [u64; 4] = [
    0x1_8000_0000,
    0x1_8000_1040,
    0xffff_fe00_1234_0010,
    0xffff_fe00_1235_0ff0,
];

/// The PAC model of the service: a pointer's PAC field, bits 54:48, is a
/// keyed hash of the stripped pointer and the modifier, never zero.
fn strip(pointer: u64) -> u64 {
    const LOW: u64 = (1 << 48) - 1;
    if pointer >> 55 & 1 != 0 {
        pointer | !LOW
    } else {
        pointer & LOW
    }
}
fn sign(pointer: u64, modifier: u64, secret: u64) -> u64 {
    let stripped = strip(pointer);
    let mac = (stripped ^ modifier.rotate_left(17) ^ secret).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    stripped ^ ((mac >> 57 | 1) & 0x7f) << 48
}

/// What the thunks read through [`Anchor::Pointer`] and the service's own.
#[repr(C)]
#[derive(Clone)]
struct Service {
    tags: [u64; TAG_WORDS],
    /// Each generation's key.
    secrets: [u64; 4],
    memo: u64,
    calls: u64,
}

/// The engine's PAC service, modelled: it computes under the key of the
/// requested key's tag word's generation and remembers the result as the
/// engine does, completing signings and successful authentications.
extern "sysv64" fn service(state: u64, request: u32, pointer: u64, modifier: u64) -> Completion {
    // SAFETY: the thunks pass the frame's pointer anchor, a live Service
    // that nothing else touches while they run.
    let service = unsafe { &mut *(state as *mut Service) };
    service.calls += 1;
    let key = (request & 7) as u8;
    let word = service.tags[usize::from(key)];
    if word <= DISABLED {
        return Completion::default();
    }
    let generation = word >> 8;
    let secret = service.secrets[generation as usize];
    let (kind, value) = if request & pointer::REQUEST_AUTHENTICATE != 0 {
        let stripped = strip(pointer);
        if sign(stripped, modifier, secret) == pointer {
            (AUTHENTICATED, stripped)
        } else {
            // A failure, which no thunk takes.
            (6, 0)
        }
    } else {
        (pointer::SIGNED, sign(pointer, modifier, secret))
    };
    // SAFETY: the memo has MEMO_ENTRIES entries and outlives the run.
    let memo =
        unsafe { &mut *(service.memo as *mut MemoEntry).add(pointer::slot(pointer, modifier)) };
    *memo = MemoEntry {
        pointer,
        modifier,
        tag: pointer::tag(generation, key, kind),
        value,
    };
    Completion {
        completed: u64::from(kind != 6),
        value,
    }
}

/// One way the thunk's exit goes on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Way {
    /// Its patch point returns.
    Bare,
    /// A lookup tail.
    Lookup,
    /// A predicted tail whose direct exit returns.
    Unlinked,
    /// A predicted tail whose direct exit takes a cell or stamped tail.
    Linked,
}

/// A thunk, its tail and the probes of `btype`, entered as a block is.
struct Run {
    region: Pages,
    memo: Vec<MemoEntry>,
    service: Box<Service>,
}

impl Run {
    fn new(thunk: &pointer::Thunk, btype: u8, way: Way, predicted: u64, word: ExitWord) -> Self {
        let region = pages(REGION);
        let mut body = vec![0xe9];
        let entered_len = crate::x86_64::pinned::entered(&[0; 5]).len();
        body.extend(((THUNK as i64 - entered_len as i64) as i32).to_le_bytes());
        let entered = crate::x86_64::pinned::entered(&body);
        assert!(entered.len() <= THUNK);
        put(&region, 0, &entered);
        put(&region, THUNK, &thunk.code);
        put(&region, PROBES, &lookup_dispatcher(btype).unwrap());
        let point = dynamic_patch(region.at(THUNK + thunk.dynamic.unwrap()));
        let probe = region.at(PROBES + PROBE_ENTRY);
        let tail = region.at(TAIL);
        match way {
            Way::Bare => {}
            Way::Lookup => put(&region, TAIL, &lookup_tail(tail, word, RAN, probe).unwrap()),
            Way::Unlinked | Way::Linked => put(
                &region,
                TAIL,
                &predicted_tail(tail, GuestAddress(predicted), word, RAN, probe).unwrap(),
            ),
        }
        if way != Way::Bare {
            let offset = (point - region.0 as u64) as usize;
            put(&region, offset, &jump(point, tail).unwrap());
        }
        let memo = vec![MemoEntry::default(); MEMO_ENTRIES];
        let service = Box::new(Service {
            tags: [0; TAG_WORDS],
            secrets: [0, 0x1111, 0x2222, 0x3333],
            memo: 0,
            calls: 0,
        });
        let mut run = Self {
            region,
            memo,
            service,
        };
        run.service.memo = run.memo.as_mut_ptr() as u64;
        run
    }

    /// The predicted tail's exit, which a link of `way` Linked patches.
    fn exit_point(&self) -> u64 {
        direct_patch(self.region.at(TAIL + PREDICTED_EXIT))
    }

    /// Link the predicted tail's exit through `cell` of the table, by a
    /// stamped tail while it held `linked` when linked, else a cell tail.
    fn link(&self, table: &LookupTable, linked: Option<LookupEntry>, word: ExitWord, btype: u8) {
        let site = self.exit_point();
        let number = table.site_cell_number(site).unwrap();
        let cell = LookupTable::cell_slot(&table.cells, number) as *const Slot as u64;
        let at = self.region.at(CELL_TAIL);
        let code = match linked {
            Some(linked) => stamped_branch_tail(
                at,
                cell,
                number,
                predicted_of(table, site),
                word,
                RAN,
                linked.block,
                linked.entry,
                self.region.at(PROBES + STAMPING_PROBE_ENTRY),
                btype,
            )
            .unwrap()
            .to_vec(),
            None => cell_tail(
                at,
                cell,
                word,
                RAN,
                self.region.at(PROBES + CELL_PROBE_ENTRY),
            )
            .unwrap()
            .to_vec(),
        };
        put(&self.region, CELL_TAIL, &code);
        let offset = (site - self.region.0 as u64) as usize;
        put(&self.region, offset, &jump(site, at).unwrap());
    }

    fn run(&mut self, state: &mut GuestState, control: &mut ChainControl) -> (u64, u64) {
        state.anchors[Anchor::Control] = control as *mut ChainControl as u64;
        state.anchors[Anchor::Memo] = self.memo.as_ptr() as u64;
        state.anchors[Anchor::Pointer] = &raw mut *self.service as u64;
        // SAFETY: the region holds the entry, the thunk, its tails and the
        // probes with the block ABI; they touch the frame, the control, the
        // memo, the service, the tables and the blocks, which outlive the
        // call, and call `service`.
        let result =
            unsafe { crate::x86_64::native::enter(self.region.0 as *const u8, state, 0, 0) };
        (result as u64, (result >> 64) as u64)
    }
}

fn predicted_of(table: &LookupTable, site: u64) -> u64 {
    table.site_cell(site).unwrap().pc
}

/// A case: the instruction, its exit's kind and the BTYPE it sets, and
/// where its pointer and modifier are.
struct Case {
    operation: Operation,
    kind: ExitKind,
    btype: u8,
    key: u8,
    pointer: Register,
    modifier: Option<Register>,
}

fn cases() -> [Case; 5] {
    [
        Case {
            operation: Operation::ReturnIbSp,
            kind: ExitKind::Return,
            btype: 0,
            key: 1,
            pointer: Register::X(30),
            modifier: Some(Register::Sp),
        },
        Case {
            operation: Operation::Branch {
                key: Key::Ia,
                target: 16,
                modifier: Modifier::Register(17),
                link: false,
            },
            kind: ExitKind::Indirect,
            btype: 0b01,
            key: 0,
            pointer: Register::X(16),
            modifier: Some(Register::X(17)),
        },
        Case {
            operation: Operation::Branch {
                key: Key::Ia,
                target: 8,
                modifier: Modifier::Register(9),
                link: false,
            },
            kind: ExitKind::Indirect,
            btype: 0b11,
            key: 0,
            pointer: Register::X(8),
            modifier: Some(Register::X(9)),
        },
        Case {
            operation: Operation::Branch {
                key: Key::Ib,
                target: 8,
                modifier: Modifier::Register(16),
                link: true,
            },
            kind: ExitKind::Call,
            btype: 0b10,
            key: 1,
            pointer: Register::X(8),
            modifier: Some(Register::X(16)),
        },
        Case {
            operation: Operation::Branch {
                key: Key::Ia,
                target: 8,
                modifier: Modifier::Zero,
                link: true,
            },
            kind: ExitKind::Call,
            btype: 0b10,
            key: 0,
            pointer: Register::X(8),
            modifier: None,
        },
    ]
}

fn write(state: &mut GuestState, register: Register, value: u64) {
    match register {
        Register::X(n) => state.x[usize::from(n)] = value,
        Register::Sp => state.sp = value,
        _ => unreachable!(),
    }
}

/// The BTYPEs block `block`'s first instruction accepts.
fn targets_of(block: usize) -> u32 {
    TARGETS[block % TARGETS.len()]
}

fn entry_of(blocks: &Pages, block: usize, pc: u64, key: u64, targets: u32) -> LookupEntry {
    LookupEntry {
        pc,
        key,
        entry: blocks.at(64 * block),
        block: block as u32,
        targets,
    }
}

#[test]
fn predicted_tails_complete_pac_branches_as_lookup_tails() {
    let blocks = blocks();
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut totals = [0u32; 7];
    for (number, case) in cases().into_iter().enumerate() {
        let form = pointer::Form::of(case.operation).unwrap();
        let tags = Place::new(Anchor::Pointer, core::mem::offset_of!(Service, tags));
        let routine: ServiceRoutine = service;
        let thunk = pointer::thunk(form, GuestAddress(PC), tags, routine as usize as u64);
        let word = ExitWord::from(case.kind);
        // The predicted target: the first of a page in either half.
        let predicted = PCS[2 * (number % 2)];
        let ways = [Way::Lookup, Way::Linked, Way::Unlinked, Way::Bare];
        let mut runs = ways.map(|way| Run::new(&thunk, case.btype, way, predicted, word));
        let mut table = LookupTable::with_entries(MIN_LOOKUP_ENTRIES);
        let mut itlb = LookupTable::itlb();
        let cells = table.stamped_cells();
        let stamps = table.new_stamps();
        for (block, &pc) in PCS.iter().enumerate() {
            for context in CONTEXTS {
                itlb.insert(
                    itlb.page_slot(pc, context),
                    LookupEntry::page(pc & !0xfff, context, KEYS[0]),
                );
            }
            for (other, key) in KEYS.into_iter().enumerate() {
                let block = block + 4 * other;
                table.insert(
                    table.slot(pc, key),
                    entry_of(&blocks, block, pc, key, targets_of(block)),
                );
            }
        }
        let site = runs[1].exit_point();
        let relink = |table: &mut LookupTable, key: u64| {
            let held = table.find(table.slot(predicted, key), predicted, key);
            let current = (held.pc == predicted && held.key == key).then_some(held);
            table.link_cell(site, predicted, current);
            // As the engine links: a stamped tail only for a block that
            // accepts the BTYPE.
            current.filter(|entry| entry.targets & 1 << case.btype != 0)
        };
        let mut linked = relink(&mut table, KEYS[0]);
        runs[1].link(&table, linked, word, case.btype);
        let mut contexts = [CONTEXTS[0], CONTEXTS[1]];
        let mut keys = BTreeMap::new();
        for &pc in &PCS {
            for context in CONTEXTS {
                keys.insert((pc & !0xfff, context), KEYS[0]);
            }
        }
        let mut tag_words = [0u64; TAG_WORDS];
        tag_words[usize::from(case.key)] = pointer::tag(1, case.key, 0);
        let modifiers = [0xffff_fe00_0000_8000u64, 0x0000_0001_6fdf_f2c0];
        let mut state = GuestState::default();
        for trial in 0..40_000u32 {
            match rng.below(28) {
                0..=3 => {
                    let pc = PCS[rng.below(4) as usize];
                    let context = CONTEXTS[rng.below(3) as usize];
                    let page = pc & !0xfff;
                    let held = keys.entry((page, context)).or_insert(KEYS[0]);
                    if rng.below(3) == 0 {
                        itlb.forget_range_where(page..=page, |entry| entry.key == context);
                        *held = KEYS[usize::from(rng.below(2) == 0)];
                    }
                    itlb.insert(
                        itlb.page_slot(pc, context),
                        LookupEntry::page(page, context, *held),
                    );
                }
                4 => {
                    let page = PCS[rng.below(4) as usize] & !0xfff;
                    itlb.forget_range_where(page..=page, |_| rng.below(2) == 0);
                }
                5 | 6 => {
                    // A block, which may refuse the branch's BTYPE, in
                    // place of the PC's block of that key, as the engine
                    // replaces one.
                    let pc = PCS[rng.below(4) as usize];
                    let key = KEYS[usize::from(rng.below(3) == 0)];
                    let block = rng.below(BLOCKS as u64) as usize;
                    let entry = entry_of(&blocks, block, pc, key, targets_of(block));
                    let slot = table.slot(pc, key);
                    let held = [slot, neighbour(slot)].into_iter().find(|&at| {
                        let resident = table.entry(at);
                        resident.pc == pc && resident.key == key
                    });
                    match held {
                        Some(at) => table.set(at, entry),
                        None => table.insert(slot, entry),
                    }
                }
                7 => {
                    let frame = key_frame(KEYS[rng.below(2) as usize]);
                    table.forget_frames(frame..=frame, |_| rng.below(3) == 0);
                }
                8 => {
                    linked = relink(&mut table, KEYS[rng.below(2) as usize]);
                    runs[1].link(&table, linked, word, case.btype);
                }
                9 => contexts[rng.below(2) as usize] = CONTEXTS[rng.below(3) as usize],
                10 => contexts = [CONTEXTS[0], CONTEXTS[1]],
                11 | 12 => {
                    // A key switch: another generation, closed or disabled.
                    let index = usize::from(case.key);
                    tag_words[index] = match rng.below(16) {
                        0 => 0,
                        1 => DISABLED,
                        generation => pointer::tag(1 + generation % 3, case.key, 0),
                    };
                    totals[0] += 1;
                }
                13 if rng.below(40) == 0 => itlb.clear(),
                _ => {}
            }
            // The operands: a pointer signed under the current key, under
            // another generation's, forged, or unsigned.
            let target = if rng.below(3) == 0 {
                predicted
            } else {
                PCS[rng.below(4) as usize]
            };
            let modifier = case
                .modifier
                .map_or(0, |_| modifiers[rng.below(2) as usize]);
            let generation = match tag_words[usize::from(case.key)] {
                word if word > DISABLED && rng.below(16) != 0 => word >> 8,
                _ => 1 + rng.below(3),
            };
            let secret = runs[0].service.secrets[generation as usize];
            let operand = match rng.below(16) {
                0 => sign(target, modifier, secret) ^ 1 << 50,
                1 => target,
                _ => sign(target, modifier, secret),
            };
            write(&mut state, case.pointer, operand);
            if let Some(register) = case.modifier {
                write(&mut state, register, modifier);
            }
            state.x[30] = if case.pointer == Register::X(30) {
                operand
            } else {
                0x5555
            };
            let base = ChainControl {
                budget: [0, 1, 2, 5, 9][rng.below(5) as usize],
                retired: 100,
                block: 7,
                contexts,
                table: table.address(),
                hits: 3,
                interrupt_epoch: u64::from(rng.below(12) == 0),
                itlb: itlb.address(),
                masks: [table.mask(), itlb.mask()],
                salts: contexts.map(|context| itlb.salt(context)),
                stamps,
                cells,
                ..ChainControl::default()
            };
            // SAFETY: the table made the stamps, which live with it.
            let hits_of = || unsafe { stamp_counts(stamps) }[StampCount::Hits as usize];
            let stamped_hits = hits_of();
            let mut controls = [base; 4];
            let mut states = [(); 4].map(|_| state.clone());
            let mut results = [(0, 0); 4];
            // In a random order: stamps one run leaves serve the next.
            let first = rng.below(4) as usize;
            for index in (0..4).map(|step| (first + step) % 4) {
                let run = &mut runs[index];
                run.service.tags = tag_words;
                results[index] = run.run(&mut states[index], &mut controls[index]);
            }
            let [lookup, linked_way, unlinked, bare] = results;
            let stamped = hits_of() != stamped_hits;
            // The one difference the stamped tail may make, as in the
            // stamped tails' test: the cell probe misses a page this ITLB
            // put out for another (a capacity eviction, not a drop) and the
            // stamped tail enters the cell's block while the page tables
            // still map the page to the cell's key.
            let page = predicted & !0xfff;
            let context = contexts[half(predicted)];
            let resident = itlb.find(itlb.page_slot(predicted, context), page, context);
            let cell = table.site_cell(site).unwrap();
            let evicted = stamped
                && !(resident.pc == page && resident.key == context)
                && keys.get(&(page, context)) == Some(&cell.key)
                && lookup.0 == predicted
                && linked.is_some_and(|linked| linked.entry == cell.entry);
            // And the one difference a cell makes: the table put the
            // target's entry out of its set for another (a capacity
            // eviction, not a forget), and the cell, which keeps it,
            // enters its block where the table probe exits for a refill.
            let resident_key = (resident.pc == page && resident.key == context)
                .then_some(resident.entry)
                .or_else(|| keys.get(&(page, context)).copied().filter(|_| stamped));
            let held = resident_key
                .map(|key| table.find(table.slot(predicted, key), predicted, key))
                .unwrap_or_default();
            let exit = (
                predicted,
                u64::from(word.encoded() | RAN << ExitWord::RAN_SHIFT),
            );
            let entered = ChainControl {
                budget: base.budget.wrapping_sub(1),
                retired: base.retired + u64::from(RAN),
                block: u64::from(cell.block) | u64::from(case.btype) << BLOCK_BTYPE_SHIFT,
                ..base
            };
            let put_out = resident_key == Some(cell.key)
                && cell.pc == predicted
                && !(held.pc == predicted && held.key == cell.key)
                && lookup == exit
                && controls[0] == base
                && if base.budget == 0 {
                    linked_way == exit && controls[1].budget == u64::MAX
                } else {
                    linked_way == (0x7700 + u64::from(cell.block), 99)
                        && ChainControl {
                            hits: entered.hits,
                            ..controls[1]
                        } == entered
                };
            if evicted || put_out {
                totals[6] += 1;
            } else {
                assert_eq!(
                    linked_way, lookup,
                    "case {number} trial {trial}: target {target:#x} operand {operand:#x}"
                );
                let mut linked_control = controls[1];
                // A table probe counts its own transfers; the cell and the
                // stamped tail do not.
                assert!(controls[0].hits - linked_control.hits <= 1);
                if controls[0].hits != linked_control.hits {
                    totals[1] += 1;
                }
                linked_control.hits = controls[0].hits;
                assert_eq!(linked_control, controls[0], "case {number} trial {trial}");
                assert_eq!(states[1].x, states[0].x, "case {number} trial {trial}");
                assert_eq!(states[1].sp, states[0].sp);
            }
            // An unlinked direct exit returns what the thunk's exit does.
            let expected = if bare == (predicted, u64::from(word.encoded())) {
                totals[2] += 1;
                bare
            } else {
                lookup
            };
            assert_eq!(unlinked, expected, "case {number} trial {trial}");
            assert_eq!(
                controls[2],
                if expected == bare {
                    controls[3]
                } else {
                    controls[0]
                }
            );
            assert_eq!(states[2].x, states[0].x);
            assert_eq!(states[3].x, states[0].x);
            if stamped {
                totals[3] += 1;
            }
            if lookup == (PC, ExitKind::PointerAuthentication as u64) {
                totals[4] += 1;
            }
            if lookup.1 == 99 {
                totals[5] += 1;
            }
            let calls = runs[0].service.calls;
            assert!(runs.iter().all(|run| run.service.calls == calls));
            if trial % 4096 == 0 {
                assert!(runs.iter().all(|run| run.memo == runs[0].memo));
            }
        }
        assert!(runs.iter().all(|run| run.memo == runs[0].memo));
        assert!(runs[0].service.calls > 1000, "{}", runs[0].service.calls);
    }
    // Key switches, cell transfers, direct exits taken, stamped hits, PAC
    // exits and transfers into blocks all happened often.
    let [
        switches,
        cell_transfers,
        predicted_exits,
        stamped,
        failures,
        entered,
        _,
    ] = totals;
    assert!(
        switches > 7_000
            && cell_transfers > 1_300
            && predicted_exits > 30_000
            && stamped > 500
            && failures > 20_000
            && entered > 5_000,
        "{totals:?}"
    );
}

/// A cell probe of a BR or BLR form's BTYPE takes only an entry that
/// accepts it, and names the BTYPE with the block, as the table probe does.
#[test]
fn branch_cell_probes_take_entries_that_accept_their_btype() {
    let blocks = blocks();
    let pc = PCS[1];
    for btype in 1..4u8 {
        for targets in TARGETS {
            let region = pages(2 * PAGE);
            put(&region, PROBES, &lookup_dispatcher(btype).unwrap());
            let mut table = LookupTable::with_entries(MIN_LOOKUP_ENTRIES);
            let mut itlb = LookupTable::itlb();
            itlb.insert(
                itlb.page_slot(pc, CONTEXTS[0]),
                LookupEntry::page(pc & !0xfff, CONTEXTS[0], KEYS[0]),
            );
            let entry = entry_of(&blocks, 3, pc, KEYS[0], targets);
            table.insert(table.slot(pc, KEYS[0]), entry);
            let cell = table.link_cell(0x1000, pc, Some(entry));
            // mov rax, pc; then the cell tail.
            let mut code = vec![0x48, 0xb8];
            code.extend(pc.to_le_bytes());
            let at = region.at(code.len());
            let word = ExitWord::from(ExitKind::Indirect);
            code.extend(
                cell_tail(at, cell, word, 2, region.at(PROBES + CELL_PROBE_ENTRY)).unwrap(),
            );
            put(&region, 0, &code);
            let mut control = ChainControl {
                budget: 5,
                contexts: [CONTEXTS[0], CONTEXTS[1]],
                table: table.address(),
                itlb: itlb.address(),
                masks: [table.mask(), itlb.mask()],
                salts: [itlb.salt(CONTEXTS[0]), itlb.salt(CONTEXTS[1])],
                ..ChainControl::default()
            };
            let mut frame = Box::new(GuestState::default());
            frame.anchors[Anchor::Control] = &raw mut control as u64;
            // SAFETY: the region holds the stub, its tail and the probes;
            // they touch the frame, the control, the tables and the blocks.
            let result =
                unsafe { crate::x86_64::native::enter(region.0 as *const u8, &mut *frame, 0, 0) };
            let result = (result as u64, (result >> 64) as u64);
            if targets & 1 << btype != 0 {
                assert_eq!(result, (0x7703, 99), "btype {btype} targets {targets:#b}");
                assert_eq!(control.block, 3 | u64::from(btype) << BLOCK_BTYPE_SHIFT);
                assert_eq!((control.budget, control.retired), (4, 2));
            } else {
                let exit = u64::from(word.encoded() | 2 << ExitWord::RAN_SHIFT);
                assert_eq!(result, (pc, exit), "btype {btype} targets {targets:#b}");
                assert_eq!((control.block, control.budget), (0, 5));
            }
        }
    }
}

/// A predicted tail's bytes: the compare, its direct exit to the target,
/// aligned for its patch point where it lands, and the lookup tail.
#[test]
fn predicted_tails_hold_a_direct_exit_and_a_lookup_tail() {
    for at in (0x1000..0x1010).map(|at| 0x7f00_0000_0000 + at) {
        let target = GuestAddress(0xffff_fe00_1234_0010);
        let word = ExitWord::from(ExitKind::Return);
        let probe = 0x7f00_0010_0000;
        let tail = predicted_tail(at, target, word, 3, probe).unwrap();
        let exit = &tail[PREDICTED_EXIT..PREDICTED_EXIT + DIRECT_EXIT_BYTES];
        assert!(is_direct_exit(exit, target, word));
        assert!(exit_ready(&tail, PREDICTED_EXIT, at, 0));
        assert!(patchable(direct_patch(at + PREDICTED_EXIT as u64)));
        let lookup = at + (PREDICTED_EXIT + DIRECT_EXIT_BYTES) as u64;
        assert_eq!(
            tail[PREDICTED_EXIT + DIRECT_EXIT_BYTES..],
            lookup_tail(lookup, word, 3, probe).unwrap()
        );
        // movabs r8, target; cmp rax, r8; jne over the direct exit.
        assert_eq!(tail[..2], [0x49, 0xb8]);
        assert_eq!(tail[2..10], target.0.to_le_bytes());
        assert_eq!(
            tail[10..15],
            [0x4c, 0x39, 0xc0, 0x75, DIRECT_EXIT_BYTES as u8]
        );
    }
    assert!(predicted_tail(0, GuestAddress(0), ExitKind::Return, 1 << 12, 0).is_none());
}
