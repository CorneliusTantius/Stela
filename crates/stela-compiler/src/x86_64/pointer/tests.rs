use super::*;

/// The tag words of these tests.
const TAGS: Place = Place::new(Anchor::Mirrors, 0);

#[test]
fn forms_name_their_key_kind_operands_and_completion() {
    let form = Form::of(Operation::SignIbSp).unwrap();
    assert_eq!(
        (form.key, form.kind, form.pointer, form.modifier),
        (key_index(Key::Ib), SIGNED, 30, Modifier::StackPointer)
    );
    assert_eq!(requested(form.request()), (Key::Ib, false, false));
    let branch = Form::of(Operation::Branch {
        key: Key::Ia,
        target: 8,
        modifier: Modifier::Register(16),
        link: true,
    })
    .unwrap();
    assert_eq!(branch.completion, Finish::Branch { link: true });
    assert_eq!(branch.kind, AUTHENTICATED);
    assert_eq!(requested(branch.request()), (Key::Ia, true, true));
    let plain = Form::of(Operation::Authenticate {
        key: Key::Db,
        destination: 3,
        modifier: Modifier::Zero,
    })
    .unwrap();
    assert_eq!(requested(plain.request()), (Key::Db, true, false));
    let ret = Form::of(Operation::ReturnIbSp).unwrap();
    assert_eq!(requested(ret.request()), (Key::Ib, true, true));
    let code = |destination, source, modifier| {
        Form::of(Operation::GenericCode(
            crate::block::pauth_memory::GenericCode {
                destination,
                source,
                modifier,
            },
        ))
    };
    let generic = code(1, 2, 31).unwrap();
    assert_eq!(
        (
            generic.key,
            generic.pointer,
            generic.result,
            generic.modifier
        ),
        (GENERIC_KEY, 2, 1, Modifier::StackPointer)
    );
    assert!(requests_generic_code(generic.request()));
    assert!(!requests_generic_code(form.request()));
    assert!(code(1, 31, 3).is_none() && code(31, 2, 3).is_none());
    // Register 31 operands and the other PAC forms stay with the engine.
    assert!(
        Form::of(Operation::Sign {
            key: Key::Da,
            destination: 31,
            modifier: Modifier::Zero,
        })
        .is_none()
    );
    assert!(
        Form::of(Operation::Strip {
            data: true,
            destination: 0
        })
        .is_none()
    );
}

#[test]
fn tags_keep_generation_key_and_kind_apart() {
    assert_eq!(tag(1, 3, AUTHENTICATED), 0x132);
    // A zero tag word matches no entry of any generation.
    assert!(tag(1, 0, SIGNED) > AUTHENTICATED);
    assert!(slot(u64::MAX, u64::MAX) < MEMO_ENTRIES);
}

/// Thunks run on the host: hits complete each form without the service,
/// misses ask it on an aligned stack and complete what it completes, and
/// a cleared tag word or a refusal exits with no write.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn thunks_complete_hits_and_computed_misses_natively() {
    use crate::GuestState;
    use alloc::vec;
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicU64, Ordering::SeqCst};
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
    #[repr(C)]
    #[derive(Debug, PartialEq, Eq)]
    struct Exit {
        pc: u64,
        kind: u64,
    }
    // The service's calls, their last arguments, the stack alignment
    // they saw and the answer they give.
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static STATE: AtomicU64 = AtomicU64::new(0);
    static REQUEST: AtomicU64 = AtomicU64::new(0);
    static OPERANDS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
    static MISALIGNED: AtomicU64 = AtomicU64::new(0);
    static ANSWER: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
    extern "sysv64" fn service(
        state: u64,
        request: u32,
        pointer: u64,
        modifier: u64,
    ) -> Completion {
        // A u128 (16-byte aligned on x86-64) is at an aligned address
        // only in an aligned frame.
        const _: () = assert!(core::mem::align_of::<u128>() == 16);
        let local = core::hint::black_box(0u128);
        let address = core::hint::black_box(&raw const local) as u64;
        MISALIGNED.fetch_add(address & 15, SeqCst);
        CALLS.fetch_add(1, SeqCst);
        STATE.store(state, SeqCst);
        REQUEST.store(u64::from(request), SeqCst);
        OPERANDS[0].store(pointer, SeqCst);
        OPERANDS[1].store(modifier, SeqCst);
        Completion {
            completed: ANSWER[0].load(SeqCst),
            value: ANSWER[1].load(SeqCst),
        }
    }
    fn run(code: &[u8], state: &mut GuestState, misaligned: bool) -> Exit {
        // A misaligned run enters 8 bytes lower: Rust calls arrive with
        // RSP 8 mod 16, blocks run at 0 mod 16.
        let mut bytes = vec![];
        if misaligned {
            bytes.extend([0x48, 0x83, 0xec, 0x08]); // sub rsp,8
            bytes.push(0xe8); // call the thunk, after the next 5 bytes
            bytes.extend(5i32.to_le_bytes());
            bytes.extend([0x48, 0x83, 0xc4, 0x08, 0xc3]); // add rsp,8; ret
        }
        bytes.extend(crate::x86_64::pinned::entered(code));
        // SAFETY: private anonymous memory, RX after the copy, unmapped
        // after the call; the thunk touches only `state`, the memo, the
        // tags and the stack, and calls `service`.
        unsafe {
            let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), page.cast(), bytes.len());
            assert_eq!(mprotect(page, PAGE, 5), 0);
            let entry = |state: *mut crate::GuestState| -> Exit {
                crate::x86_64::native::call::<Exit>(page as *const u8, state, 0, 0)
            };
            let exit = entry(state);
            assert_eq!(munmap(page, PAGE), 0);
            exit
        }
    }
    let pc = GuestAddress(0x4000);
    let (pointer, modifier, value) = (0xffff_fe00_1234_5678, 0xffff_fe00_0000_8000, 0xabcd);
    // Native code reads both through their addresses, so Rust writes
    // them through the same pointers.
    let mut memo = vec![MemoEntry::default(); MEMO_ENTRIES];
    let mut tags = [0u64; 4];
    let (memo, tags) = (memo.as_mut_ptr(), tags.as_mut_ptr());
    // SAFETY: key_index produces 0..4 and tags outlives these synchronous thunk calls.
    let set_tag = |key: u8, value: u64| unsafe { tags.add(usize::from(key)).write(value) };
    // SAFETY: slot masks into MEMO_ENTRIES; each returned borrow ends before native execution.
    let entry = |index: usize| unsafe { &mut *memo.add(index) };
    let routine: ServiceRoutine = service;
    let make = |operation| {
        thunk(
            Form::of(operation).unwrap(),
            pc,
            TAGS,
            routine as usize as u64,
        )
    };
    let mut state = GuestState::default();
    state.anchors[Anchor::Memo] = memo as u64;
    state.anchors[Anchor::Mirrors] = tags as u64;
    state.anchors[Anchor::Pointer] = 0x5e41;
    // PACIBSP: X30 signed with SP.
    let ib = key_index(Key::Ib);
    *entry(slot(pointer, modifier)) = MemoEntry {
        pointer,
        modifier,
        tag: tag(1, ib, SIGNED),
        value,
    };
    let sign = make(Operation::SignIbSp);
    state.x[30] = pointer;
    state.sp = modifier;
    let miss = Exit {
        pc: pc.0,
        kind: ExitKind::PointerAuthentication as u64,
    };
    assert_eq!(run(&sign.code, &mut state, false), miss, "a zero tag word");
    assert_eq!((state.x[30], CALLS.load(SeqCst)), (pointer, 0));
    set_tag(ib, tag(1, ib, 0));
    let next = Exit {
        pc: pc.0 + 4,
        kind: ExitKind::Fallthrough as u64,
    };
    assert_eq!(run(&sign.code, &mut state, false), next);
    assert_eq!((state.x[30], CALLS.load(SeqCst)), (value, 0));
    // Another modifier misses the memo: the service refuses, then
    // completes, on either stack alignment.
    state.x[30] = pointer;
    state.sp = modifier + 16;
    assert_eq!(run(&sign.code, &mut state, true), miss);
    assert_eq!(state.x[30], pointer);
    assert_eq!(
        (
            STATE.load(SeqCst),
            REQUEST.load(SeqCst),
            OPERANDS[0].load(SeqCst),
            OPERANDS[1].load(SeqCst)
        ),
        (0x5e41, u64::from(ib), pointer, modifier + 16)
    );
    ANSWER[0].store(1, SeqCst);
    ANSWER[1].store(0x1357, SeqCst);
    for misaligned in [false, true] {
        state.x[30] = pointer;
        assert_eq!(run(&sign.code, &mut state, misaligned), next);
        assert_eq!(state.x[30], 0x1357);
    }
    assert_eq!((CALLS.load(SeqCst), MISALIGNED.load(SeqCst)), (3, 0));
    // An authentication of the memo's signing operands misses too.
    state.x[30] = pointer;
    state.sp = modifier;
    let authenticate = make(Operation::AuthenticateIbSp);
    assert_eq!(run(&authenticate.code, &mut state, false), next);
    assert_eq!(
        REQUEST.load(SeqCst),
        u64::from(u32::from(ib) | REQUEST_AUTHENTICATE)
    );
    // BLRAA X8, X16 and RETAA take their branch with the result.
    let ia = key_index(Key::Ia);
    set_tag(ia, tag(1, ia, 0));
    entry(slot(pointer, modifier)).tag = tag(1, ia, AUTHENTICATED);
    let call = make(Operation::Branch {
        key: Key::Ia,
        target: 8,
        modifier: Modifier::Register(16),
        link: true,
    });
    state.x[8] = pointer;
    state.x[16] = modifier;
    let taken = |pc, kind: ExitKind| Exit {
        pc,
        kind: kind as u64,
    };
    let calls = CALLS.load(SeqCst);
    assert_eq!(
        run(&call.code, &mut state, false),
        taken(value, ExitKind::Call)
    );
    assert_eq!((state.x[8], state.x[30]), (pointer, pc.0 + 4));
    state.x[30] = pointer;
    let ret = make(Operation::ReturnIaSp);
    assert_eq!(
        run(&ret.code, &mut state, false),
        taken(value, ExitKind::Return)
    );
    assert_eq!((state.x[30], CALLS.load(SeqCst)), (pointer, calls));
    // A computed branch result, from a missed combined request.
    state.x[16] = modifier ^ 1;
    assert_eq!(
        run(&call.code, &mut state, false),
        taken(0x1357, ExitKind::Call)
    );
    assert_eq!(
        REQUEST.load(SeqCst),
        u64::from(u32::from(ia) | REQUEST_AUTHENTICATE | REQUEST_COMBINED)
    );
    // A disabled key returns every pointer unchanged, without the memo
    // or the service: PACIBSP leaves X30, BLRAA branches to X8 itself.
    let calls = CALLS.load(SeqCst);
    set_tag(ib, DISABLED);
    state.x[30] = pointer;
    state.sp = modifier + 32;
    assert_eq!(run(&sign.code, &mut state, false), next);
    assert_eq!(state.x[30], pointer);
    set_tag(ia, DISABLED);
    state.x[30] = 0;
    assert_eq!(
        run(&call.code, &mut state, false),
        taken(pointer, ExitKind::Call)
    );
    assert_eq!((state.x[8], state.x[30]), (pointer, pc.0 + 4));
    assert_eq!(CALLS.load(SeqCst), calls);
}

/// `mov [rdi+disp32],rax`.
const REGISTER_WRITE_BYTES: usize = 7;
/// The second opcode bytes of `jz`, `jnz` and `jbe` with a 32-bit
/// displacement.
const JZ: u8 = 0x84;
const JNZ: u8 = 0x85;
const JBE: u8 = 0x86;

#[test]
fn register_completions_chain_onward_and_misses_exit_unchanged() {
    use super::super::chain::{DIRECT_EXIT_BYTES, DYNAMIC_EXIT_BYTES};
    let pc = GuestAddress(0x4000);
    let form = Form::of(Operation::SignIbSp).unwrap();
    let thunk = thunk(form, pc, TAGS, 0x4000);
    let end = thunk.code.len();
    assert_eq!(
        thunk.code[end - DIRECT_EXIT_BYTES..],
        super::super::chain::direct_exit(pc, ExitKind::PointerAuthentication)
    );
    let next = thunk.next.unwrap();
    assert_eq!(
        thunk.code[next..next + DIRECT_EXIT_BYTES],
        super::super::chain::direct_exit(GuestAddress(0x4004), ExitKind::Fallthrough)
    );
    // The closed key and the refused service land on the exit; the
    // three memo misses on the service call, just after the completion.
    // One JBE takes a closed or disabled key to the rare path before the
    // exit: TEST R8,R8, the closed key's JZ, and the disabled key's JMP to
    // the completion's register write.
    let complete = next - REGISTER_WRITE_BYTES;
    let rare = end - DIRECT_EXIT_BYTES - 5 - 6 - 3;
    let (mut exits, mut calls, mut rares) = (0, 0, 0);
    for at in 0..end - 6 {
        if thunk.code[at] == 0x0f && [JZ, JNZ, JBE].contains(&thunk.code[at + 1]) {
            let relative =
                i32::from_le_bytes(thunk.code[at + 2..at + 6].try_into().unwrap()) as usize;
            match at + 6 + relative {
                target if target == end - DIRECT_EXIT_BYTES => exits += 1,
                target if target == next + DIRECT_EXIT_BYTES => calls += 1,
                target if target == rare && thunk.code[at + 1] == JBE => rares += 1,
                target => panic!("a jump to {target}"),
            }
        }
    }
    assert_eq!((exits, calls, rares), (2, 3, 1));
    assert_eq!(thunk.code[rare..rare + 3], [0x4d, 0x85, 0xc0]);
    let identity = end - DIRECT_EXIT_BYTES - 5;
    assert_eq!(thunk.code[identity], 0xe9);
    let relative = i32::from_le_bytes(thunk.code[identity + 1..identity + 5].try_into().unwrap());
    assert_eq!(
        (identity as i64 + 5 + i64::from(relative)) as usize,
        complete
    );
    assert_eq!(thunk.dynamic, None);
    // A return completes at its exit to the target in RAX, which the
    // service path reaches too.
    let ret = Form::of(Operation::ReturnIaSp).unwrap();
    let ret = super::thunk(ret, pc, TAGS, 0x4000);
    assert_eq!(ret.next, None);
    let returns = ret.dynamic.unwrap();
    // Padded for its patch point, wherever it lands.
    assert!(super::super::chain::is_dynamic_exit(
        &ret.code[returns..returns + DYNAMIC_EXIT_BYTES],
        ExitKind::Return
    ));
    // The disabled key's `jmp complete` precedes the final exit.
    let back = ret.code.len() - DIRECT_EXIT_BYTES - 5;
    assert_eq!(ret.code[back], 0xe9);
    let relative = i32::from_le_bytes(ret.code[back + 1..back + 5].try_into().unwrap());
    assert_eq!((back as i64 + 5 + i64::from(relative)) as usize, returns);
}
