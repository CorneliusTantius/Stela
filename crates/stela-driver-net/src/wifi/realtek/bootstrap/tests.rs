// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! What a chip reset's failed attempts leave behind.
extern crate std;
use super::super::{
    beacon::tests::{Domain, Model, Source},
    download::tests::catalog_for,
    firmware::tests::legacy_fixture,
    identity::tests::profile,
};
use super::*;
use crate::wifi::connection::keeper::RECOVERY_ATTEMPTS;
use alloc::boxed::Box;
use core::cell::UnsafeCell;
use std::sync::Mutex;

const WINDOW_BYTES: usize = 0x1800;

/// A BAR of plain memory, whose identity register reads zero: each attempt
/// maps its beacon ring and then fails its power sequence.
struct Window(UnsafeCell<[u32; WINDOW_BYTES / 4]>);

#[test]
fn each_failed_attempt_leaves_one_set_of_rings_mapped() {
    #[expect(
        clippy::arc_with_non_send_sync,
        reason = "native owners hold Arc<dyn Any> without Send; this CPU-affine fixture keeps its UnsafeCell registers !Sync"
    )]
    let window = Arc::new(Window(UnsafeCell::new([0; WINDOW_BYTES / 4])));
    let memory = Arc::new(Mutex::new(Model::default()));
    let firmware = Box::leak(Box::new(catalog_for(profile(), legacy_fixture())));
    let claim = Claim {
        window: NonNull::new(window.0.get().cast()).unwrap(),
        bytes: WINDOW_BYTES,
        owner: window.clone(),
        clock: Clock {
            ticks_per_microsecond: 1,
        },
        pages: &Source,
        domain: Arc::new(Domain(memory.clone())),
        firmware,
        observed: profile().observed(),
        link_control: 0,
    };
    let mut rings = 0;
    for attempt in 1..=RECOVERY_ATTEMPTS as usize {
        // SAFETY: the window, its pages and its domain belong to this test
        // alone; no other driver, worker or DMA touches them.
        let Err(error) = block_on(unsafe { start(claim.clone()) }) else {
            panic!("a chip with no identity came up");
        };
        assert_eq!(error.step, "power on");
        // Nothing proves the chip stopped reaching a configured ring before
        // the next power sequence, so each attempt's rings stay mapped: as
        // many as it installed, which the keeper's ten attempts bound.
        let mapped = memory.lock().unwrap().mappings.len();
        if attempt == 1 {
            rings = mapped;
        }
        assert!(rings > 0);
        assert_eq!(mapped, rings * attempt);
    }
}
