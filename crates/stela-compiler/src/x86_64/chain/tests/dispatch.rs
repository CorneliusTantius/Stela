//! Dispatching dispatchers against lookup dispatchers: over random ITLB and
//! block table changes (pages put in, rekeyed, dropped and put out by
//! others; entries put in, replaced, forgotten by frame or block and put
//! out by others), context switches, interruptions and acknowledgements,
//! budgets and every BTYPE sharing one dispatch cache, both take the same
//! transfer into the same block or the same exit and leave the control the
//! same. The one difference allowed is a capacity eviction: the table or
//! the ITLB put out an entry nothing forgot, and the dispatch cache, as a
//! cell, still enters its block while the page tables map the target to
//! it. Both forms of the slot computation (SHR, and RORX where the host has
//! BMI2) run, and a table probe's entry fills the target's slot.
use super::super::*;
use crate::GuestState;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
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
const BLOCKS: usize = 8;
const CONTEXTS: [u64; 3] = [
    5 << LOOKUP_SALT_BITS,
    9 << LOOKUP_SALT_BITS,
    13 << LOOKUP_SALT_BITS,
];
const KEYS: [u64; 2] = [block_key(0x8_0040_0000, 1), block_key(0x8_0040_0000, 2)];
/// The BTYPEs entries accept: always BTYPE 0, some only that.
const TARGETS: [u32; 5] = [0b1111, 0b0001, 0b0101, 0b0011, 0b1001];
/// Target PCs: two pages in each half, and one that shares the first's
/// dispatch slot ([`colliding`]).
const PCS: [u64; 4] = [
    0x1_8000_0000,
    0x1_8000_1040,
    0xffff_fe00_1234_0010,
    0xffff_fe00_1235_0ff0,
];

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

/// Another PC of the first page whose dispatch slot is the first PC's.
fn colliding() -> u64 {
    (1..)
        .map(|step| PCS[0] + 4 * step)
        .find(|&pc| dispatch_slot(pc) == dispatch_slot(PCS[0]))
        .unwrap()
}

fn entry_of(blocks: &Pages, block: usize, pc: u64, key: u64) -> LookupEntry {
    LookupEntry {
        pc,
        key,
        entry: blocks.at(64 * block),
        block: block as u32,
        targets: TARGETS[block % TARGETS.len()],
    }
}

/// The lookup dispatchers, then the dispatching ones, a page each by BTYPE,
/// and a stub at the start that enters one with a target and a word.
struct Run {
    region: Pages,
}

impl Run {
    fn new(target: crate::TargetCpu) -> Self {
        let region = pages(9 * PAGE);
        for btype in 0..4u8 {
            let at = PAGE * (1 + usize::from(btype));
            put(&region, at, &lookup_dispatcher(btype).unwrap());
            let at = PAGE * (5 + usize::from(btype));
            put(&region, at, &dispatching_dispatcher(btype, target).unwrap());
        }
        Self { region }
    }

    fn run(
        &self,
        dispatching: bool,
        btype: u8,
        pc: u64,
        word: u32,
        state: &mut GuestState,
        control: &mut ChainControl,
    ) -> (u64, u64) {
        let probes = PAGE * (1 + 4 * usize::from(dispatching) + usize::from(btype));
        let mut code = Code::new();
        let mut asm = code.asm();
        asm.mov_imm64(Rax, pc);
        asm.mov_imm32(Rdx, word);
        let jump = asm.jmp();
        let distance = relative(
            self.region.at(jump.end()),
            self.region.at(probes + PROBE_ENTRY),
        )
        .unwrap();
        code.patch(jump.offset(), distance.to_le_bytes());
        put(&self.region, 0, &code.into_bytes());
        state.anchors[Anchor::Control] = control as *mut ChainControl as u64;
        // SAFETY: the region holds the stub and the probes; they touch the
        // frame, the control, the tables, the cache and the blocks, which
        // outlive the call.
        let result = unsafe {
            let run: unsafe extern "sysv64" fn(*mut GuestState) -> u128 =
                core::mem::transmute(self.region.0);
            run(state)
        };
        (result as u64, (result >> 64) as u64)
    }
}

fn targets() -> Vec<crate::TargetCpu> {
    let plain = crate::TargetCpu::X86_64_V2;
    let mut targets = vec![plain];
    if crate::TargetCpu::detect().supports(crate::TargetCpu::Bmi2) {
        targets.push(plain.with_bmi2());
    }
    targets
}

#[test]
fn dispatch_caches_complete_transfers_as_table_probes() {
    let blocks = blocks();
    let pcs = [PCS[0], PCS[1], PCS[2], PCS[3], colliding()];
    for target in targets() {
        let run = Run::new(target);
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let mut table = LookupTable::with_entries(MIN_LOOKUP_ENTRIES);
        let mut itlb = LookupTable::itlb();
        let cache = Arc::new(DispatchCache::new());
        table.add_dispatch(&cache);
        itlb.add_dispatch(&cache);
        // What the tables could give with room for everything: entries and
        // pages put out by others stay, as do older entries of a PC and key
        // that a set still holds beside a newer one; forgotten ones go.
        let mut live: BTreeSet<(u64, u64, u32)> = BTreeSet::new();
        let mut mapped: BTreeMap<(u64, u64), u64> = BTreeMap::new();
        for (block, &pc) in pcs.iter().enumerate() {
            for context in CONTEXTS {
                let page = pc & !0xfff;
                itlb.insert(
                    itlb.page_slot(pc, context),
                    LookupEntry::page(page, context, KEYS[0]),
                );
                mapped.insert((page, context), KEYS[0]);
            }
            for (other, key) in KEYS.into_iter().enumerate() {
                let entry = entry_of(&blocks, (block + 3 * other) % BLOCKS, pc, key);
                table.insert(table.slot(pc, key), entry);
                live.insert((pc, key, entry.block));
            }
        }
        let mut contexts = [CONTEXTS[0], CONTEXTS[1]];
        let mut epoch = 0u64;
        let mut observed = 0u64;
        let state = GuestState::default();
        let mut totals = [0u32; 4];
        for trial in 0..150_000u32 {
            match rng.below(120) {
                0..=5 => {
                    // A page put in or rekeyed (a drop), or another page of
                    // its set in its place (an eviction).
                    let pc = pcs[rng.below(5) as usize];
                    let context = CONTEXTS[rng.below(3) as usize];
                    let page = pc & !0xfff;
                    if rng.below(4) == 0 {
                        let slot = itlb.page_slot(pc, context);
                        let junk = LookupEntry::page(page ^ 0x40_0000_0000, context, KEYS[1]);
                        itlb.set(slot, junk);
                    } else {
                        // A page whose translation changes leaves by a
                        // TLBI first, as an evicted one may come back.
                        let key = KEYS[usize::from(rng.below(3) == 0)];
                        if mapped
                            .get(&(page, context))
                            .is_some_and(|&held| held != key)
                        {
                            itlb.forget_range_where(page..=page, |entry| entry.key == context);
                        }
                        itlb.insert(
                            itlb.page_slot(pc, context),
                            LookupEntry::page(page, context, key),
                        );
                        mapped.insert((page, context), key);
                    }
                }
                30 if rng.below(2) == 0 => {
                    let page = pcs[rng.below(5) as usize] & !0xfff;
                    let context = CONTEXTS[rng.below(3) as usize];
                    itlb.forget_range_where(page..=page, |entry| entry.key == context);
                    mapped.remove(&(page, context));
                }
                31 if rng.below(20) == 0 => {
                    itlb.clear();
                    mapped.clear();
                }
                6..=8 => {
                    // Another block of the PC and key in its place.
                    let pc = pcs[rng.below(5) as usize];
                    let key = KEYS[usize::from(rng.below(3) == 0)];
                    let entry = entry_of(&blocks, rng.below(BLOCKS as u64) as usize, pc, key);
                    table.insert(table.slot(pc, key), entry);
                    live.insert((pc, key, entry.block));
                }
                32 | 33 => {
                    // Another PC's entry put in the slot: an eviction.
                    let pc = pcs[rng.below(5) as usize];
                    let key = KEYS[rng.below(2) as usize];
                    let junk = entry_of(&blocks, 0, pc ^ 0x7_0000_0000, key);
                    table.set(table.slot(pc, key), junk);
                }
                9 if rng.below(8) == 0 => {
                    let frame = key_frame(KEYS[rng.below(2) as usize]);
                    let mut forgotten = Vec::new();
                    table.forget_frames(frame..=frame, |entry| {
                        let forget = entry.pc & 0x10 == 0 || entry.block % 2 == 0;
                        if forget {
                            forgotten.push((entry.pc, entry.key, entry.block));
                        }
                        forget
                    });
                    live.retain(|held| !forgotten.contains(held));
                }
                10 if rng.below(2) == 0 => {
                    let pc = pcs[rng.below(5) as usize];
                    let key = KEYS[rng.below(2) as usize];
                    let held: Vec<_> = live
                        .range((pc, key, 0)..=(pc, key, u32::MAX))
                        .copied()
                        .collect();
                    if !held.is_empty() {
                        let named = held[rng.below(held.len() as u64) as usize];
                        table.forget_block(pc, key, named.2);
                        live.remove(&named);
                    }
                }
                11 => {
                    // A context switch: the owner makes the cache stale.
                    contexts = match rng.below(3) {
                        0 => [
                            CONTEXTS[rng.below(3) as usize],
                            CONTEXTS[rng.below(3) as usize],
                        ],
                        _ => [CONTEXTS[0], CONTEXTS[1]],
                    };
                    cache.invalidate();
                }
                12 => epoch += 1,
                13..=20 if observed != epoch => {
                    // An acknowledgement, which makes the cache stale.
                    observed = epoch;
                    cache.invalidate();
                }
                _ => {}
            }
            let btype = rng.below(4) as u8;
            let pc = pcs[rng.below(5) as usize];
            let kind =
                [ExitKind::Return, ExitKind::Indirect, ExitKind::Call][rng.below(3) as usize];
            let ran = 1 + rng.below(9) as u32;
            let word = ExitWord::from(kind).encoded() | ran << ExitWord::RAN_SHIFT;
            let base = ChainControl {
                budget: [0, 1, 2, 5, 9, 1000][rng.below(6) as usize],
                retired: 100,
                block: 7,
                contexts,
                table: table.address(),
                hits: 3,
                interrupt_epoch: epoch,
                observed_interrupt_epoch: observed,
                itlb: itlb.address(),
                masks: [table.mask(), itlb.mask()],
                salts: contexts.map(|context| itlb.salt(context)),
                dispatch: cache.address(),
                ..ChainControl::default()
            };
            let held = cache.slot(btype, pc);
            let cached = held[0] == pc && held[1] == cache.generation() + epoch;
            let (mut probed, mut dispatched) = (base, base);
            let mut states = [state.clone(), state.clone()];
            let lookup = run.run(false, btype, pc, word, &mut states[0], &mut probed);
            let found = run.run(true, btype, pc, word, &mut states[1], &mut dispatched);
            dispatched.dispatch_seen = 0;
            if cached {
                totals[0] += 1;
            }
            let entered = lookup.1 == 99;

            if entered {
                totals[1] += 1;
                if !cached {
                    // The table probe filled the target's slot.
                    let filled = cache.slot(btype, pc);
                    assert_eq!(filled[0], pc, "target {target:?} trial {trial}");
                    assert_eq!(filled[2], probed.block);
                    assert_eq!(filled[3], blocks.at(64 * (lookup.0 - 0x7700) as usize));
                    totals[2] += 1;
                }
            }
            if (found, dispatched) != (lookup, probed) {
                // A capacity eviction or a newer entry of the PC and key:
                // the table probe missed or found another block, and the
                // slot's block is one the tables would give with room for
                // all.
                let page = pc & !0xfff;
                let context = contexts[half(pc)];
                let block = held[2] as u32 as u64;
                let valid = cached
                    && epoch == observed
                    && mapped.get(&(page, context)).is_some_and(|&key| {
                        let entry = entry_of(&blocks, block as usize, pc, key);
                        live.contains(&(pc, key, entry.block))
                            && entry.targets & 1 << btype != 0
                            && held[3] == entry.entry
                    });
                let exit = (pc, u64::from(word));
                let expected = if base.budget == 0 {
                    (
                        exit,
                        ChainControl {
                            budget: u64::MAX,
                            ..base
                        },
                    )
                } else {
                    (
                        (0x7700 + block, 99),
                        ChainControl {
                            budget: base.budget - 1,
                            retired: base.retired + u64::from(ran),
                            hits: base.hits + 1,
                            block: held[2],
                            ..base
                        },
                    )
                };
                assert!(
                    valid
                        && (entered || (lookup == exit && probed == base))
                        && (found, dispatched) == expected,
                    "target {target:?} trial {trial} btype {btype} pc {pc:#x}: \
                     lookup {lookup:x?} found {found:x?}\n{probed:x?}\n{dispatched:x?}"
                );
                totals[3] += 1;
            }
            // A miss refills what the tables put out, as the engine does.
            if !entered && rng.below(2) == 0 {
                let page = pc & !0xfff;
                let context = contexts[half(pc)];
                if let Some(&key) = mapped.get(&(page, context)) {
                    let slot = itlb.page_slot(pc, context);
                    if itlb.find(slot, page, context).key != context {
                        itlb.insert(slot, LookupEntry::page(page, context, key));
                    }
                    let newest = live.range((pc, key, 0)..=(pc, key, u32::MAX)).next_back();
                    if let Some(&(_, _, block)) = newest {
                        let slot = table.slot(pc, key);
                        if table.find(slot, pc, key).key != key {
                            table.insert(slot, entry_of(&blocks, block as usize, pc, key));
                        }
                    }
                }
            }
        }
        // Slots served transfers, table probes entered blocks and filled
        // slots, and evictions happened.
        assert!(
            totals[0] > 8_000 && totals[1] > 25_000 && totals[2] > 15_000 && totals[3] > 100,
            "{target:?} {totals:?}"
        );
    }
}

/// The slot both forms compute is [`dispatch_slot`]'s, in the part of each
/// BTYPE, and a dispatching dispatcher's table probe at the same offsets as
/// the lookup dispatcher's cell probes reach.
#[test]
fn dispatch_slots_and_probe_layout() {
    for pc in [0u64, 0xfff, 0x1_8000_1040, 0xffff_fe00_1235_0ff0, u64::MAX] {
        let pc32 = pc as u32;
        assert_eq!(
            dispatch_slot(pc),
            (((pc32 >> 12) ^ pc32) >> 2) as usize % DISPATCH_SLOTS
        );
        assert_eq!(
            dispatch_slot(pc),
            ((pc32.rotate_right(12) ^ pc32) >> 2) as usize % DISPATCH_SLOTS
        );
    }
    let cache = DispatchCache::new();
    assert_eq!(cache.generation(), 1);
    cache.invalidate();
    assert_eq!(cache.generation(), 2);
    for btype in 0..4 {
        for target in targets() {
            let dispatching = dispatching_dispatcher(btype, target).unwrap();
            let lookup = lookup_dispatcher(btype).unwrap();
            assert_eq!(
                dispatching[..CELL_PROBE_BYTES].len(),
                lookup[..CELL_PROBE_BYTES].len()
            );
            assert!(dispatching.len() > STAMPING_PROBE_ENTRY);
        }
    }
    assert!(dispatching_dispatcher(4, crate::TargetCpu::X86_64_V2).is_none());
}

/// An entry new to the block table leaves dispatch caches as they are: a
/// block they hold stays good until it is forgotten. Another block of the
/// same PC and key in its place, or none, makes them stale.
#[test]
fn new_table_entries_keep_dispatch_caches() {
    let mut table = LookupTable::with_entries(MIN_LOOKUP_ENTRIES);
    let cache = Arc::new(DispatchCache::new());
    table.add_dispatch(&cache);
    let entry = |pc: u64, block: u32| LookupEntry {
        pc,
        key: KEYS[0],
        entry: 0x1000 + u64::from(block) * 0x40,
        block,
        targets: 0xf,
    };
    let generation = cache.generation();
    for (block, pc) in PCS.into_iter().enumerate() {
        table.insert(table.slot(pc, KEYS[0]), entry(pc, block as u32));
    }
    assert_eq!(cache.generation(), generation, "new entries");
    let pc = PCS[0];
    table.insert(table.slot(pc, KEYS[0]), entry(pc, 9));
    assert!(cache.generation() > generation, "a newer block of the PC");
    let generation = cache.generation();
    table.set(table.slot(pc, KEYS[0]), LookupEntry::default());
    assert!(cache.generation() > generation, "an entry removed");
}
