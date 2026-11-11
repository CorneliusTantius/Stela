//! EL0's one-sided range check against the two-sided check it replaces:
//! it passes exactly the two-sided check's lower range, so it passes a
//! subset of the same addresses, masks the rest the same way, and with the
//! tagged variant's strip passes the tagged lower-half pointers TBI0 lets
//! through.
use super::{RangeCheck, TopByte, asm::Code};
use crate::GuestState;
use alloc::vec::Vec;

const PLACEMENTS: [RangeCheck; 3] = [
    RangeCheck::FIVE_LEVEL,
    RangeCheck::four_level(2),
    RangeCheck::four_level(9),
];

/// Addresses around every edge either check has, and tagged pointers.
fn addresses(check: RangeCheck) -> Vec<u64> {
    let limit = check.lower_limit();
    let mut addresses = Vec::new();
    for edge in [
        0,
        limit,
        1 << 47,
        1 << 48,
        1 << 56,
        GuestState::UNREACHABLE,
        1 << 63,
        // The four-level upper range's start for 2 and 9 slices, and its
        // guard; LA57's upper range.
        0xffff_8000_0000_0000 + (2 << 41),
        0xffff_8000_0000_0000 + (9 << 41),
        0xffff_8000_0000_0000 + (1 << 41),
        0xff00_0000_0000_0000,
        u64::MAX,
    ] {
        for delta in [-17i64, -16, -8, -1, 0, 1, 8, 16] {
            addresses.push(edge.wrapping_add(delta as u64));
        }
    }
    for tag in [0x01u64, 0x5a, 0x80, 0xff] {
        addresses.push(tag << 56 | 0x0000_0001_0425_6e90);
        addresses.push(tag << 56 | 0x0080_0000_0000_1000);
    }
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..512 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        addresses.push(seed);
        addresses.push(seed % limit);
    }
    addresses
}

#[test]
fn the_one_sided_check_passes_exactly_the_two_sided_lower_range() {
    for check in PLACEMENTS {
        let limit = check.lower_limit();
        let one_sided = check.one_sided(true);
        assert!(!check.one_sided(true).one_sided(false).one_sided);
        for address in addresses(check) {
            assert_eq!(
                one_sided.passes(address),
                check.passes(address) && address < limit,
                "{check:?} {address:#x}"
            );
            // Every lower-range address is native to both.
            if address < limit {
                assert!(check.passes(address), "{check:?} {address:#x}");
            }
        }
    }
    assert_eq!(RangeCheck::FIVE_LEVEL.lower_limit(), 1 << 48);
    assert_eq!(RangeCheck::four_level(2).lower_limit(), 1 << 47);
}

#[test]
fn the_one_sided_check_is_a_frame_compare_and_the_mask() {
    let limit = core::mem::offset_of!(GuestState, lower_limit) as u32;
    let unreachable = core::mem::offset_of!(GuestState, unreachable) as u32;
    // cmp rax,[rdi+limit]
    let mut compare = alloc::vec![0x48, 0x3b, 0x87];
    compare.extend(limit.to_le_bytes());
    // cmovae rax,[rdi+unreachable]
    let mut mask = alloc::vec![0x48, 0x0f, 0x43, 0x87];
    mask.extend(unreachable.to_le_bytes());
    for check in PLACEMENTS {
        let one_sided = check.one_sided(true);
        let mut pinned = Code::new();
        pinned.set_pinned(true);
        one_sided.emit(&mut pinned);
        assert_eq!(
            pinned.into_bytes(),
            [compare.clone(), mask.clone()].concat()
        );
        let mut plain = Code::new();
        one_sided.emit(&mut plain);
        // jb +2; ud2 between them.
        let ud2 = [0x72, 2, 0x0f, 0x0b];
        assert_eq!(
            plain.into_bytes(),
            [compare.clone(), ud2.to_vec(), mask.clone()].concat()
        );
    }
}

/// The pinned forms, run on the host: the address in X2 comes back in X3,
/// or [`GuestState::UNREACHABLE`] where the check fails; with the tagged
/// variant's strip first, as an EL0 block of a learnt page runs it.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn the_emitted_checks_run_as_modelled() {
    use super::asm::{Gpr, Size};
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
        fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x20;
    const PAGE: usize = 4096;
    let x = |index: usize| super::frame((core::mem::offset_of!(GuestState, x) + 8 * index) as u32);
    for check in PLACEMENTS {
        for (one_sided, top_byte) in [
            (false, TopByte::Kept),
            (true, TopByte::Kept),
            (true, TopByte::Lower),
            (false, TopByte::Lower),
        ] {
            let range = check.one_sided(one_sided);
            let mut code = Code::new();
            code.set_pinned(true);
            code.asm().mov_load(Size::Qword, Gpr::Rax, x(2));
            top_byte.emit(&mut code);
            range.emit(&mut code);
            code.asm().mov_store(Size::Qword, x(3), Gpr::Rax);
            code.asm().ret();
            // SAFETY: private anonymous memory, RX after the copy, unmapped
            // after the calls; the code writes only X3 of the frame.
            unsafe {
                let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                assert_eq!(mprotect(page, PAGE, 5), 0);
                let entry = |state: *mut crate::GuestState| -> () {
                    crate::x86_64::native::call::<()>(page as *const u8, state, 0, 0)
                };
                for address in addresses(check) {
                    let mut state = GuestState {
                        lower_limit: crate::Limit(check.lower_limit()),
                        ..GuestState::default()
                    };
                    state.x[2] = address;
                    entry(&mut state);
                    let stripped = top_byte.strip(address);
                    let expected = if range.passes(stripped) {
                        stripped
                    } else {
                        GuestState::UNREACHABLE
                    };
                    assert_eq!(
                        state.x[3], expected,
                        "{check:?} one-sided {one_sided} {top_byte:?} {address:#x}"
                    );
                }
                assert_eq!(munmap(page, PAGE), 0);
            }
        }
    }
}
