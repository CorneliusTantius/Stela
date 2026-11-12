//! Live patches while another core runs the patched code: each patch point
//! changes with one aligned 8-byte store, and a core running the exit in a
//! loop meanwhile only ever takes the old way or the new one.
use super::super::*;
use crate::GuestState;
use alloc::boxed::Box;
use core::ffi::c_void;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
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

const PAGE: usize = 4096;
const TARGET: GuestAddress = GuestAddress(0x1234);
/// Where the block the links enter lies in the page, and the thunks.
const BLOCK_AT: usize = 1024;
const THUNKS_AT: usize = 2048;
/// What the entered block returns: a marker in RAX and EDX.
const ENTERED: (u64, u64) = (0x5151, 99);
/// Patches each test makes in turn, a link, a relink and an unlink a round.
const ROUNDS: usize = 2000;

/// One page that is writable while it runs, as the arena is through its
/// physmap alias.
struct Page(*mut u8);

// SAFETY: the page is shared by the patching thread and the running one
// only through aligned atomic stores and loads of code.
unsafe impl Send for Page {}
// SAFETY: as for Send.
unsafe impl Sync for Page {}

impl Page {
    fn new() -> Self {
        // SAFETY: a private anonymous RWX page, unmapped on drop.
        let page = unsafe { mmap(core::ptr::null_mut(), PAGE, 7, 0x22, -1, 0) };
        assert_ne!(page as usize, usize::MAX);
        Self(page.cast())
    }
    fn address(&self) -> u64 {
        self.0 as u64
    }
    /// Bytes nothing runs yet.
    fn write(&self, at: u64, bytes: &[u8]) {
        let offset = (at - self.address()) as usize;
        assert!(offset + bytes.len() <= PAGE);
        // SAFETY: inside the page; no core runs these bytes yet.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.0.add(offset), bytes.len()) };
    }
    /// Replace the instruction at patch point `point` as a host does: one
    /// aligned 8-byte store of the word holding it.
    fn patch(&self, point: u64, instruction: [u8; PATCH_BYTES]) {
        assert!(patchable(point));
        let word = (point & !7) - self.address();
        // SAFETY: an aligned word inside the page.
        let word = unsafe { AtomicU64::from_ptr(self.0.add(word as usize).cast()) };
        let old = word.load(Ordering::Relaxed);
        word.store(patch_word(old, point, instruction), Ordering::Release);
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        // SAFETY: unique mapping; the running thread was joined.
        assert_eq!(unsafe { munmap(self.0.cast(), PAGE) }, 0);
    }
}

/// What the running thread saw: exits, and entries by the block each link
/// named.
#[derive(Debug, Default)]
struct Seen {
    exits: u64,
    entered: [u64; 4],
}

/// Run the exit at `entry` in a loop on another thread, while `patch`
/// makes its patches, each once the runner has taken the way the one
/// before made. Every run returns from the exit or from the entered block.
fn run_while_patching(
    page: &Arc<Page>,
    entry: u64,
    mut patch: impl FnMut(usize) -> Option<u64>,
) -> Seen {
    let stop = Arc::new(AtomicBool::new(false));
    // The block the runner last entered, 0 for an exit; it bumps `runs`.
    let last = Arc::new(AtomicU64::new(u64::MAX));
    let runs = Arc::new(AtomicU64::new(0));
    let runner = {
        let (page, stop, last, runs) = (page.clone(), stop.clone(), last.clone(), runs.clone());
        std::thread::spawn(move || {
            let _page = page;
            let mut control = Box::new(ChainControl {
                count: ChainControl::counting(MAX_BUDGET, 0),
                ..ChainControl::default()
            });
            let mut frame = Box::new(GuestState::default());
            frame.anchors[Anchor::Control] = &mut *control as *mut ChainControl as u64;
            let mut seen = Seen::default();
            while !stop.load(Ordering::Acquire) {
                control.block = 0;
                // SAFETY: the page stays mapped until join; its code has the
                // block ABI and touches only the frame's control.
                let result = unsafe {
                    let run: unsafe extern "sysv64" fn(*mut GuestState) -> u128 =
                        core::mem::transmute(entry as usize as *const ());
                    run(&mut *frame)
                };
                let (value, word) = (result as u64, (result >> 64) as u64);
                if (value, ExitWord::split(word).0) == (TARGET.0, ExitKind::Direct as u64) {
                    assert_eq!(control.block, 0, "an exit names no block");
                    seen.exits += 1;
                    last.store(0, Ordering::Release);
                } else {
                    assert_eq!((value, word), ENTERED, "a torn transfer");
                    assert!((1..=3).contains(&control.block), "{}", control.block);
                    seen.entered[control.block as usize] += 1;
                    last.store(control.block, Ordering::Release);
                }
                runs.fetch_add(1, Ordering::Release);
            }
            seen
        })
    };
    let wait = |wanted: u64| {
        let began = Instant::now();
        // A few runs after the patch, then one that took its way.
        let from = runs.load(Ordering::Acquire);
        while runs.load(Ordering::Acquire) < from + 64 || last.load(Ordering::Acquire) != wanted {
            assert!(
                began.elapsed() < Duration::from_secs(10),
                "the runner never took the patched way {wanted}"
            );
            core::hint::spin_loop();
        }
    };
    wait(0);
    let mut step = 0;
    while let Some(wanted) = patch(step) {
        wait(wanted);
        step += 1;
    }
    stop.store(true, Ordering::Release);
    runner.join().unwrap()
}

/// The marker block, and thunks into it naming blocks 2 and 3.
fn install_targets(page: &Page, fallback: Fallback) -> [u64; 2] {
    let block = page.address() + BLOCK_AT as u64;
    page.write(block, &[0xb8, 0x51, 0x51, 0, 0, 0xba, 99, 0, 0, 0, 0xc3]);
    [2, 3].map(|named| {
        let at = page.address() + (THUNKS_AT + 64 * named as usize) as u64;
        page.write(at, &thunk(at, 1, named, block, fallback).unwrap());
        at
    })
}

/// A link slot's patch point, while the slot runs: link (the body, which
/// names block 1), relink (a thunk), unlink, round after round.
#[test]
fn a_slot_links_relinks_and_unlinks_while_it_runs() {
    let page = Arc::new(Page::new());
    // An address the slot's point needs a pad at.
    let at = page.address() + 5;
    let site = at + POLLED_LINK_BYTES as u64;
    let mut code = empty_link_at(at, POLLED_LINK_BYTES);
    code.extend(direct_exit_at(site, TARGET, ExitKind::Direct));
    page.write(at, &code);
    let point = slot_patch(at);
    assert_ne!(point, at);
    let thunks = install_targets(&page, Fallback::Jump(site));
    let block = page.address() + BLOCK_AT as u64;
    let (body, bytes) = link(at, POLLED_LINK_BYTES, 1, 1, block).unwrap();
    let (unlink_at, unlink) = unlinked(site, POLLED_LINK_BYTES).unwrap();
    assert_eq!(unlink_at, point);
    let seen = run_while_patching(&page, at, |step| {
        if step == 3 * ROUNDS {
            return None;
        }
        Some(match step % 3 {
            0 => {
                // The body is written once, while the point jumps over it;
                // later rounds fall into the same bytes again.
                if step == 0 {
                    page.write(body, &bytes);
                }
                page.patch(point, NOP5);
                1
            }
            1 => {
                let thunk = thunks[step / 3 % 2];
                page.patch(point, jump(point, thunk).unwrap());
                2 + (step / 3 % 2) as u64
            }
            _ => {
                page.patch(point, unlink);
                0
            }
        })
    });
    assert!(
        seen.exits > 0 && seen.entered[1..].iter().all(|&count| count > 0),
        "{seen:?}"
    );
}

/// An exit's own patch point while the exit runs: link (a thunk naming
/// block 2), relink (one naming block 3), unlink, round after round.
#[test]
fn an_exit_links_relinks_and_unlinks_while_it_runs() {
    let page = Arc::new(Page::new());
    for start in [0, 3, 6] {
        let site = page.address() + start;
        page.write(site, &direct_exit_at(site, TARGET, ExitKind::Direct));
        let thunks = install_targets(&page, Fallback::Return(ExitKind::Direct.into()));
        let (point, unlink) = unlinked(site, 0).unwrap();
        let seen = run_while_patching(&page, site, |step| {
            if step == 3 * ROUNDS {
                return None;
            }
            Some(match step % 3 {
                0 => {
                    page.patch(point, jump(point, thunks[0]).unwrap());
                    2
                }
                1 => {
                    page.patch(point, jump(point, thunks[1]).unwrap());
                    3
                }
                _ => {
                    page.patch(point, unlink);
                    0
                }
            })
        });
        assert!(
            seen.exits > 0 && seen.entered[2] > 0 && seen.entered[3] > 0,
            "{seen:?}"
        );
    }
}
