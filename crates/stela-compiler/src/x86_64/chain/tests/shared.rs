//! A board's one block table and its cells while other cores write them:
//! a probe on one thread and the engine's reads on another take an entry
//! whole or not at all, never one entry's target with another's block.
use super::super::*;
use crate::GuestState;
use alloc::{boxed::Box, vec::Vec};
use core::ffi::c_void;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
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

const PAGES: usize = 2;
const PAGE: usize = 4096;
const TARGET: u64 = 0xffff_fe00_0123_4568;
const OTHER: u64 = TARGET ^ (1 << (2 + LOOKUP_BITS) | 1 << 2);
/// The blocks entries name: each returns its marker, and an entry names
/// the block number that goes with it.
const BLOCKS: [(usize, u32); 2] = [(2048, 1), (2304, 2)];
/// How long the writer writes.
const WRITING: Duration = Duration::from_millis(300);

/// Pages that hold the probes and blocks while other threads run them.
struct Code(*mut u8);

// SAFETY: written before the runners start, read-only while they run.
unsafe impl Send for Code {}
// SAFETY: as for Send.
unsafe impl Sync for Code {}

impl Drop for Code {
    fn drop(&mut self) {
        // SAFETY: unique mapping; every runner was joined.
        assert_eq!(unsafe { munmap(self.0.cast(), PAGES * PAGE) }, 0);
    }
}

fn marker(block: u32) -> u64 {
    0x5100 | u64::from(block)
}

/// Rewrite one slot and one cell, between entries of two PCs and two blocks,
/// while a native probe and an engine-side reader read them, until
/// [`WRITING`] has passed. Every hit names the block whose code it entered.
#[test]
fn readers_take_whole_entries_while_one_writer_rewrites_them() {
    const KEY: u64 = block_key(0x8_0123_4000, 1);
    let table_mask = LOOKUP_ENTRIES as u32 - 1;
    let itlb_mask = ITLB_ENTRIES as u32 / 2 - 1;
    let mut table = LookupTable::new();
    let mut itlb = LookupTable::itlb();
    let context = 7;
    for pc in [TARGET, OTHER] {
        itlb.insert(
            itlb.page_slot(pc, context),
            LookupEntry::page(pc & !0xfff, context, KEY),
        );
    }
    // SAFETY: private anonymous memory, unmapped on drop after the joins.
    let base = unsafe { mmap(core::ptr::null_mut(), PAGES * PAGE, 7, 0x22, -1, 0) };
    assert_ne!(base as usize, usize::MAX);
    let code = Arc::new(Code(base.cast()));
    let at = |offset: usize| code.0 as u64 + offset as u64;
    let entries: Vec<LookupEntry> = BLOCKS
        .iter()
        .flat_map(|&(offset, block)| {
            [TARGET, OTHER].map(|pc| LookupEntry {
                pc,
                key: KEY,
                entry: at(offset),
                block,
                targets: 1,
            })
        })
        .collect();
    let cell = table.link_cell(1, TARGET, Some(entries[0]));
    // The cell probe's tail at 0, the table probe's at 64, probes at 256.
    let probes = at(256);
    let mut bytes = Vec::new();
    let mut put = |offset: usize, piece: &[u8]| {
        if bytes.len() < offset + piece.len() {
            bytes.resize(offset + piece.len(), 0xcc);
        }
        bytes[offset..offset + piece.len()].copy_from_slice(piece);
    };
    let cell_tail = cell_tail(at(3), cell, ExitKind::Call, 3, probes).unwrap();
    put(0, &[0x48, 0x89, 0xf0]); // mov rax,rsi
    put(3, &cell_tail);
    put(64, &[0x48, 0x89, 0xf0]);
    let table_tail =
        lookup_tail(at(67), ExitKind::Return, 3, probes + PROBE_ENTRY as u64, 0).unwrap();
    put(67, &table_tail);
    put(256, &lookup_dispatcher(0).unwrap());
    for &(offset, block) in &BLOCKS {
        let value = marker(block) as u32;
        let mut returns = vec![0xb8];
        returns.extend(value.to_le_bytes());
        returns.extend([0xba, 99, 0, 0, 0, 0xc3]);
        put(offset, &returns);
    }
    // SAFETY: inside the mapping; nothing runs it yet.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), code.0, bytes.len()) };
    let (table_address, itlb_address) = (table.address(), itlb.address());
    let stamps = [table.new_stamps(), table.new_stamps()];
    let reader = table.reader();
    let stop = Arc::new(AtomicBool::new(false));
    let runners: Vec<_> = [0usize, 64]
        .into_iter()
        .zip(stamps)
        .map(|(entry, stamps)| {
            let (code, stop) = (code.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut control = Box::new(ChainControl {
                    table: table_address,
                    itlb: itlb_address,
                    contexts: [context; 2],
                    salts: [itlb_salt(context, itlb_mask); 2],
                    masks: [table_mask, itlb_mask],
                    stamps,
                    ..ChainControl::default()
                });
                let mut frame = Box::new(GuestState::default());
                frame.anchors[Anchor::Control] = &mut *control as *mut ChainControl as u64;
                let (mut hits, mut exits) = (0u64, 0u64);
                let mut round = 0u64;
                while !stop.load(Ordering::Acquire) {
                    control.set_budget(1);
                    control.block = 0;
                    // SAFETY: the table's stamps, which outlive the runners;
                    // each runner's own, and nothing of its runs meanwhile.
                    unsafe { next_jump_serial(stamps) };
                    let target = if round.is_multiple_of(2) {
                        TARGET
                    } else {
                        OTHER
                    };
                    round += 1;
                    // SAFETY: the mapping lives until the joins; its code has
                    // the block ABI and touches the frame's control and the
                    // tables, which outlive the runners.
                    let result = unsafe {
                        let run: unsafe extern "sysv64" fn(*mut GuestState, u64) -> u128 =
                            core::mem::transmute(code.0.add(entry));
                        run(&mut *frame, target)
                    };
                    let value = result as u64;
                    if value == target {
                        exits += 1;
                        continue;
                    }
                    let block = (control.block & u64::from(u32::MAX)) as u32;
                    assert_eq!(value, marker(block), "a torn entry");
                    hits += 1;
                }
                (hits, exits)
            })
        })
        .collect();
    let base_address = base as u64;
    let engine = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut found = 0u64;
            while !stop.load(Ordering::Acquire) {
                for pc in [TARGET, OTHER] {
                    let entry = reader.find(reader.slot(pc, KEY), pc, KEY);
                    if entry.pc == pc && entry.key == KEY {
                        let expected = BLOCKS.iter().find(|&&(_, block)| block == entry.block);
                        let &(offset, _) = expected.expect("a block of the test");
                        assert_eq!(entry.entry, code_at(base_address, offset), "a torn read");
                        found += 1;
                    }
                }
            }
            found
        })
    };
    let began = Instant::now();
    let mut writes = 0usize;
    while began.elapsed() < WRITING {
        let entry = entries[writes % entries.len()];
        table.insert(table.slot(entry.pc, entry.key), entry);
        if writes.is_multiple_of(7) {
            table.forget_frames(key_frame(KEY)..=key_frame(KEY), |_| true);
        }
        writes += 1;
    }
    stop.store(true, Ordering::Release);
    for runner in runners {
        let (hits, exits) = runner.join().unwrap();
        assert!(hits > 0 && exits > 0, "{hits} {exits}");
    }
    assert!(engine.join().unwrap() > 0);
    assert!(writes > 1000);
}

fn code_at(base: u64, offset: usize) -> u64 {
    base + offset as u64
}
