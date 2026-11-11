//! Paired frames run natively: a call's frame and its return's compare,
//! with the frame taken, left or refused, and every exit back at the entry
//! however many frames the run left.
use super::super::*;
use crate::GuestState;
use crate::x86_64::asm::{Code, Patch};
use alloc::{boxed::Box, vec::Vec};
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
/// The guest return address of the calls.
const RETURN: u64 = 0xffff_fe00_0012_3404;
/// Another one, which no frame holds.
const OTHER: u64 = 0xffff_fe00_0045_6704;
/// The RET block's instructions.
const RAN: u32 = 5;
/// What a continuation returns in RAX and EDX.
const CONTINUED: (u64, u64) = (0xc0de, 77);
/// The word of a return's exit, as its dynamic exit returns it.
const RETURNED: u64 = 99;
/// The calling block's word, which a matched return names again.
const CALLER: u64 = 0x3_0000_0042;

struct Pages(*mut u8, usize);
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: our mapping, nothing runs it any more.
        assert_eq!(unsafe { munmap(self.0.cast(), self.1) }, 0);
    }
}
fn pages(code: &[u8]) -> Pages {
    let bytes = code.len().next_multiple_of(PAGE);
    // SAFETY: private anonymous memory, unmapped on drop, written before it runs.
    unsafe {
        let base = mmap(core::ptr::null_mut(), bytes, 7, 0x22, -1, 0);
        assert_ne!(base as usize, usize::MAX);
        core::ptr::copy_nonoverlapping(code.as_ptr(), base.cast(), code.len());
        Pages(base.cast(), bytes)
    }
}

/// The exit of a return that took no frame: RAX as it is, [`RETURNED`].
fn return_exit(asm: &mut crate::x86_64::asm::Asm) {
    asm.mov_imm32(Rdx, RETURNED as u32);
    exit_return(asm);
}

/// A continuation: [`CONTINUED`] out.
fn continued(asm: &mut crate::x86_64::asm::Asm) {
    asm.mov_imm32(Rax, CONTINUED.0 as u32);
    asm.mov_imm32(Rdx, CONTINUED.1 as u32);
    exit_return(asm);
}

/// How the called code returns.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Callee {
    /// A RET to the target in RSI.
    Return,
    /// The retire epoch moved first: a block retired meanwhile.
    Retired,
    /// An interruption pending first.
    Interrupted,
    /// An exit before any return.
    Exit,
}

/// Code that calls [`RETURN`] with a paired frame, the call's exit linked
/// straight into a callee that returns to the target in RSI as `callee`
/// says, and whose continuation returns [`CONTINUED`].
fn call_and_return(callee: Callee) -> Vec<u8> {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let continuation = paired_call(&mut asm, GuestAddress(RETURN));
    // The call's exit, linked: into the callee.
    let to_callee = asm.jmp();
    asm.bind(continuation);
    continued(&mut asm);
    asm.bind(to_callee);
    match callee {
        Callee::Return => {}
        Callee::Retired => {
            asm.place(Rcx, CONTROL);
            asm.mov_load(Qword, R8, Mem::base(Rcx, RETIRE_EPOCH));
            asm.alu_imm8(Alu::Add, Qword, Mem::base(R8, 0), 1);
        }
        Callee::Interrupted => {
            asm.place(Rcx, CONTROL);
            asm.alu_imm8(Alu::Add, Qword, Mem::base(Rcx, INTERRUPT_EPOCH), 1);
        }
        Callee::Exit => {
            asm.mov_imm32(Rdx, 55);
            exit_return(&mut asm);
        }
    }
    asm.mov(Qword, Rax, Gpr::Rsi);
    paired_return(&mut asm, RAN).unwrap();
    return_exit(&mut asm);
    code.into_bytes()
}

struct Run {
    control: Box<ChainControl>,
    epoch: Box<u64>,
}

impl Run {
    fn new(bound: u32) -> Self {
        let mut epoch = Box::new(7);
        let control = Box::new(ChainControl {
            budget: 100,
            block: CALLER,
            frame_bound: bound,
            retire_epoch: &raw mut *epoch as u64,
            ..ChainControl::default()
        });
        Self { control, epoch }
    }

    /// Enter `code` at `at` with RSI = `target`: RAX and RDX of its exit.
    fn enter(&mut self, code: &Pages, at: usize, target: u64) -> (u64, u64) {
        let mut state = Box::new(GuestState::default());
        state.anchors[Anchor::Control] = &raw mut *self.control as u64;
        let entry = (code.0 as usize + at) as *const u8;
        // SAFETY: the code has the block ABI and touches only the state,
        // the control and the epoch, which outlive the call.
        let result = unsafe { crate::x86_64::native::enter(entry, &mut *state, target, 0) };
        (result as u64, (result >> 64) as u64)
    }

    fn pairs(&self) -> [u64; PAIR_COUNTS] {
        self.control.pairs
    }
}

#[test]
fn a_return_to_its_call_takes_the_continuation() {
    let code = pages(&call_and_return(Callee::Return));
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    run.control.block = 9;
    let caller = run.control.block;
    assert_eq!(run.enter(&code, 0, RETURN), CONTINUED);
    assert_eq!(run.pairs(), [1, 1, 0, 0]);
    assert_eq!(run.control.frames, 0);
    // The return counted its block and named the caller again.
    assert_eq!(
        (run.control.retired, run.control.block),
        (u64::from(RAN), caller)
    );
    assert_eq!(run.control.budget, 100);
}

#[test]
fn a_return_elsewhere_takes_the_lookup_and_leaves_the_frame() {
    let code = pages(&call_and_return(Callee::Return));
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    // A modified X30: the exit, at the target, its frame still pushed;
    // the exit's return reaches the entry all the same.
    assert_eq!(run.enter(&code, 0, OTHER), (OTHER, RETURNED));
    assert_eq!(run.pairs(), [1, 0, 1, 0]);
    assert_eq!((run.control.frames, run.control.retired), (1, 0));
}

#[test]
fn a_block_retired_since_the_call_fails_every_frame() {
    let code = pages(&call_and_return(Callee::Retired));
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    assert_eq!(run.enter(&code, 0, RETURN), (RETURN, RETURNED));
    assert_eq!(*run.epoch, 8);
    assert_eq!(run.pairs(), [1, 0, 1, 0]);
}

#[test]
fn an_interruption_between_call_and_return_takes_the_exit() {
    let code = pages(&call_and_return(Callee::Interrupted));
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    assert_eq!(run.enter(&code, 0, RETURN), (RETURN, RETURNED));
    assert_eq!(run.pairs(), [1, 0, 1, 0]);
    // Acknowledged: the next run's frame matches.
    run.control.observed_interrupt_epoch = run.control.interrupt_epoch;
    run.control.frames = 0;
    let code = pages(&call_and_return(Callee::Return));
    assert_eq!(run.enter(&code, 0, RETURN), CONTINUED);
}

#[test]
fn no_budget_left_takes_the_exit() {
    let code = pages(&call_and_return(Callee::Return));
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    run.control.budget = 0;
    assert_eq!(run.enter(&code, 0, RETURN), (RETURN, RETURNED));
    assert_eq!(run.pairs(), [1, 0, 1, 0]);
}

#[test]
fn an_exit_between_call_and_return_discards_the_frame() {
    let code = call_and_return(Callee::Exit);
    let callee = code.len() - return_tail_bytes();
    let code = pages(&code);
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    // The exit leaves with the frame pushed: back at the entry.
    assert_eq!(run.enter(&code, 0, RETURN).1, 55);
    assert_eq!(run.control.frames, 1);
    // The next run starts with none (`frames` 0) and its return, which
    // finds the entry's own stack where a frame would be, takes the exit.
    run.control.frames = 0;
    assert_eq!(run.enter(&code, callee, RETURN), (RETURN, RETURNED));
    assert_eq!(run.pairs(), [1, 0, 0, 0]);
}

/// Bytes of [`call_and_return`]'s return: RAX from RSI, the paired return
/// and the exit.
fn return_tail_bytes() -> usize {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    asm.mov(Qword, Rax, Gpr::Rsi);
    paired_return(&mut asm, RAN).unwrap();
    return_exit(&mut asm);
    code.len()
}

#[test]
fn a_stack_that_looks_like_a_frame_is_none_without_a_count() {
    // The target and an epoch where a frame's would be, from a push the
    // control does not count.
    let mut code = Code::pinned();
    let mut asm = code.asm();
    asm.mov_imm64(R8, 7);
    asm.push(R8);
    asm.push(R8);
    asm.push(Gpr::Rsi);
    let call = asm.call();
    asm.fixed(&[0x0f, 0x0b]);
    asm.bind(call);
    asm.mov(Qword, Rax, Gpr::Rsi);
    paired_return(&mut asm, RAN).unwrap();
    return_exit(&mut asm);
    let code = pages(&code.into_bytes());
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    assert_eq!(run.enter(&code, 0, RETURN), (RETURN, RETURNED));
    assert_eq!(run.pairs(), [0; PAIR_COUNTS]);
}

/// Code that recurses `depth` (RSI) times through one call site whose
/// return address is [`RETURN`], each level's continuation a return to
/// it, the deepest level a return too: what frames there are match, then
/// the return with none left exits.
fn recursion() -> Vec<u8> {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let start = asm.len();
    asm.alu_imm8(Alu::Sub, Qword, Gpr::Rsi, 1);
    let base = asm.jcc(Cond::E);
    let continuation = paired_call(&mut asm, GuestAddress(RETURN));
    let again = asm.jmp();
    asm.bind_back(again, start);
    asm.bind(continuation);
    asm.bind(base);
    asm.mov_imm64(Rax, RETURN);
    paired_return(&mut asm, RAN).unwrap();
    return_exit(&mut asm);
    code.into_bytes()
}

#[test]
fn recursion_past_the_bound_refuses_the_deeper_frames() {
    let code = pages(&recursion());
    for (bound, depth) in [(4, 10), (16, 16), (64, 200), (0, 3)] {
        let mut run = Run::new(bound);
        assert_eq!(run.enter(&code, 0, depth), (RETURN, RETURNED), "{bound}");
        let pushed = u64::from(bound).min(depth - 1);
        // Every frame matched in turn; the deeper calls took the plain exit.
        assert_eq!(
            run.pairs(),
            [pushed, pushed, 0, depth - 1 - pushed],
            "{bound} {depth}"
        );
        assert_eq!(run.control.frames, 0);
        assert_eq!(run.control.retired, pushed * u64::from(RAN));
    }
}

/// Two calls, to [`RETURN`] and then [`OTHER`], whose callee returns to
/// the first, past the second, then to whatever RSI says: an unwinding
/// that skips a frame.
fn unwinding() -> Vec<u8> {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let outer = paired_call(&mut asm, GuestAddress(RETURN));
    let to_inner = asm.jmp();
    asm.bind(outer);
    continued(&mut asm);
    asm.bind(to_inner);
    let inner = paired_call(&mut asm, GuestAddress(OTHER));
    let to_callee = asm.jmp();
    // The inner continuation: [`OTHER`]'s, which returns its own marker.
    asm.bind(inner);
    asm.mov_imm32(Rax, 0x0e);
    asm.mov_imm32(Rdx, 78);
    exit_return(&mut asm);
    asm.bind(to_callee);
    // The callee unwinds to RETURN, which the top frame does not hold:
    // the exit, as for the lookup.
    asm.mov_imm64(Rax, RETURN);
    paired_return(&mut asm, RAN).unwrap();
    // The lookup lands in some code that returns to RSI later.
    asm.mov(Qword, Rax, Gpr::Rsi);
    paired_return(&mut asm, RAN).unwrap();
    return_exit(&mut asm);
    code.into_bytes()
}

#[test]
fn an_unwinding_return_misses_and_a_later_one_takes_the_frame_it_names() {
    let code = pages(&unwinding());
    // The top frame holds OTHER: a return to it is that frame's
    // continuation however the code got there.
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    assert_eq!(run.enter(&code, 0, OTHER), (0x0e, 78));
    assert_eq!(run.pairs(), [2, 1, 1, 0]);
    assert_eq!(run.control.frames, 1);
    // A return to the deeper frame's address under the top one exits.
    let mut run = Run::new(DEFAULT_FRAME_BOUND);
    assert_eq!(run.enter(&code, 0, RETURN), (RETURN, RETURNED));
    assert_eq!(run.pairs(), [2, 0, 2, 0]);
    assert_eq!(run.control.frames, 2);
}

#[test]
fn a_matched_return_takes_no_indirect_jump() {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    paired_return(&mut asm, RAN).unwrap();
    let bytes = code.into_bytes();
    // The hit path is everything up to `ret 24`: conditional branches, ALU
    // and moves; no FF /2 or FF /4 (indirect call or jump) in it.
    let ret = bytes
        .windows(3)
        .position(|window| window == [0xc2, (FRAME_BYTES - 8) as u8, 0])
        .unwrap();
    assert!(!bytes[..ret].contains(&0xff), "{:02x?}", &bytes[..ret]);
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let continuation: Patch = paired_call(&mut asm, GuestAddress(RETURN));
    asm.bind(continuation);
    let bytes = code.into_bytes();
    // The call is a direct one (E8 rel32).
    assert_eq!(bytes.iter().filter(|&&byte| byte == 0xe8).count(), 1);
}

/// A loop of `iterations` (RSI) calls to [`RETURN`] whose callee returns
/// at once: with `paired` the call pushes a frame and the return takes
/// it; without, as today, the call is a plain transfer and the return
/// goes through its lookup tail and the table probe at [`PROBES`], whose
/// table holds the continuation block at [`CONTINUATION_AT`]. The loop's
/// own branches are the same in both.
fn call_loop(paired: bool) -> Vec<u8> {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let start = asm.len();
    asm.alu_imm8(Alu::Sub, Qword, Gpr::Rsi, 1);
    let done = asm.jcc(Cond::E);
    let continuation = paired.then(|| paired_call(&mut asm, GuestAddress(RETURN)));
    let to_callee = asm.jmp();
    let to_continuation = continuation.map(|continuation| {
        asm.bind(continuation);
        asm.jmp()
    });
    asm.bind(to_callee);
    asm.mov_imm64(Rax, RETURN);
    if paired {
        paired_return(&mut asm, RAN).unwrap();
    }
    asm.mov_imm32(
        Rdx,
        ExitWord::from(ExitKind::Return).encoded() | RAN << ExitWord::RAN_SHIFT,
    );
    let probe = asm.jmp();
    asm.bind(done);
    asm.mov_imm32(Rax, 1);
    asm.mov_imm32(Rdx, 2);
    exit_return(&mut asm);
    let used = asm.len();
    assert!(used <= PROBES);
    for _ in used..PROBES {
        asm.int3();
    }
    asm.fixed(&lookup_dispatcher(0).unwrap());
    let probes = asm.len();
    assert!(probes <= CONTINUATION_AT);
    for _ in probes..CONTINUATION_AT {
        asm.int3();
    }
    // The continuation block: back to the loop.
    let back = asm.jmp();
    asm.bind_back(back, start);
    crate::x86_64::asm::resolve(&mut code, probe, PROBES + PROBE_ENTRY);
    if let Some(jump) = to_continuation {
        crate::x86_64::asm::resolve(&mut code, jump, CONTINUATION_AT);
    }
    code.into_bytes()
}

/// Where [`call_loop`]'s probes begin.
const PROBES: usize = 1024;
/// Where its continuation block, which the table names, begins.
const CONTINUATION_AT: usize = 3 * 1024;

/// Host cost of a guest call and return pair, paired and through the
/// table probe, and of a recursion past each frame bound. Prints
/// nanoseconds per pair (run with `--nocapture`); asserts only the counts.
#[test]
fn paired_and_probed_return_costs() {
    use super::{ITLB_MASK, TABLE_MASK, itlb_salt, itlb_slot, lookup_slot};
    const ITERATIONS: u64 = 1 << 21;
    const WARM: u64 = 1 << 10;
    let mut table = LookupTable::new();
    let mut itlb = LookupTable::itlb();
    let key = block_key(0x4000_0000, 1);
    let context = 7;
    let mut results = Vec::new();
    for paired in [false, true] {
        let code = pages(&call_loop(paired));
        itlb.insert(
            itlb_slot(RETURN, context),
            LookupEntry::page(RETURN & !0xfff, context, key),
        );
        table.insert(
            lookup_slot(RETURN, key),
            LookupEntry {
                pc: RETURN,
                key,
                entry: code.0 as u64 + CONTINUATION_AT as u64,
                block: 3,
                targets: 1,
            },
        );
        let mut run = Run::new(DEFAULT_FRAME_BOUND);
        run.control.budget = u64::MAX / 2;
        run.control.table = table.address();
        run.control.itlb = itlb.address();
        run.control.contexts = [5, context];
        run.control.salts = [itlb_salt(5), itlb_salt(context)];
        run.control.masks = [TABLE_MASK, ITLB_MASK];
        assert_eq!(run.enter(&code, 0, WARM), (1, 2));
        let start = std::time::Instant::now();
        assert_eq!(run.enter(&code, 0, ITERATIONS), (1, 2));
        let elapsed = start.elapsed();
        let pairs = ITERATIONS - 1 + WARM - 1;
        if paired {
            assert_eq!(run.pairs(), [pairs, pairs, 0, 0]);
            assert_eq!(run.control.hits, 0);
        } else {
            assert_eq!(run.control.hits, pairs);
        }
        results.push(elapsed.as_secs_f64() * 1e9 / (ITERATIONS - 1) as f64);
    }
    std::println!(
        "call/return pair: probed {:.2} ns, paired {:.2} ns",
        results[0],
        results[1]
    );
    // Recursion: 127 calls deep through one site, then the returns; the
    // ones without a frame through the table probe.
    const DEPTH: u64 = 128;
    const ROUNDS: u64 = 1 << 13;
    let code = pages(&recursion_loop(DEPTH));
    table.insert(
        lookup_slot(RETURN, key),
        LookupEntry {
            pc: RETURN,
            key,
            entry: code.0 as u64 + CONTINUATION_AT as u64,
            block: 3,
            targets: 1,
        },
    );
    for bound in [0, 16, 64, 256] {
        let mut run = Run::new(bound);
        run.control.budget = u64::MAX / 2;
        run.control.table = table.address();
        run.control.itlb = itlb.address();
        run.control.contexts = [5, context];
        run.control.salts = [itlb_salt(5), itlb_salt(context)];
        run.control.masks = [TABLE_MASK, ITLB_MASK];
        let start = std::time::Instant::now();
        for _ in 0..ROUNDS {
            run.control.frames = 0;
            assert_eq!(run.enter(&code, 0, DEPTH), (1, 2));
        }
        let elapsed = start.elapsed();
        let pushed = u64::from(bound).min(DEPTH - 1);
        assert_eq!(run.pairs()[PairCount::Matched as usize], pushed * ROUNDS);
        assert_eq!(run.control.hits, (DEPTH - 1 - pushed) * ROUNDS);
        std::println!(
            "recursion depth {DEPTH}, bound {bound}: {:.2} ns per call and return, {pushed} of {} paired",
            elapsed.as_secs_f64() * 1e9 / (ROUNDS * (DEPTH - 1)) as f64,
            DEPTH - 1
        );
    }
}

/// `depth` (RSI) levels of recursion through one call site whose return
/// address is [`RETURN`]: down by paired calls (plain past the bound), then
/// back up by returns, which take their frame or the table probe into the
/// continuation block at [`CONTINUATION_AT`], which counts the level and
/// returns again until the top.
fn recursion_loop(depth: u64) -> Vec<u8> {
    let mut code = Code::pinned();
    let mut asm = code.asm();
    let start = asm.len();
    asm.alu_imm8(Alu::Sub, Qword, Gpr::Rsi, 1);
    let base = asm.jcc(Cond::E);
    let continuation = paired_call(&mut asm, GuestAddress(RETURN));
    let again = asm.jmp();
    asm.bind_back(again, start);
    asm.bind(continuation);
    let to_continuation = asm.jmp();
    asm.bind(base);
    let returning = asm.len();
    asm.mov_imm64(Rax, RETURN);
    paired_return(&mut asm, RAN).unwrap();
    asm.mov_imm32(
        Rdx,
        ExitWord::from(ExitKind::Return).encoded() | RAN << ExitWord::RAN_SHIFT,
    );
    let probe = asm.jmp();
    let done = asm.len();
    asm.mov_imm32(Rax, 1);
    asm.mov_imm32(Rdx, 2);
    exit_return(&mut asm);
    let used = asm.len();
    for _ in used..PROBES {
        asm.int3();
    }
    asm.fixed(&lookup_dispatcher(0).unwrap());
    let probes = asm.len();
    for _ in probes..CONTINUATION_AT {
        asm.int3();
    }
    asm.alu_imm8(Alu::Add, Qword, Gpr::Rsi, 1);
    asm.alu_imm32(Alu::Cmp, Qword, Gpr::Rsi, i32::try_from(depth - 1).unwrap());
    let finished = asm.jcc(Cond::E);
    asm.bind_back(finished, done);
    let up = asm.jmp();
    asm.bind_back(up, returning);
    crate::x86_64::asm::resolve(&mut code, probe, PROBES + PROBE_ENTRY);
    crate::x86_64::asm::resolve(&mut code, to_continuation, CONTINUATION_AT);
    code.into_bytes()
}

#[test]
fn a_paired_tail_is_the_frame_check_then_the_lookup_tail() {
    let (at, probe) = (0x10_0000, 0x10_4000);
    let tail = paired_tail(at, ExitKind::Return, RAN, probe).unwrap();
    let mut check = Code::new();
    paired_return(&mut check.asm(), RAN).unwrap();
    let check = check.into_bytes();
    let lookup = lookup_tail(at + check.len() as u64, ExitKind::Return, RAN, probe).unwrap();
    assert_eq!(tail[..check.len()], check[..]);
    assert_eq!(tail[check.len()..][..TAIL_BYTES], lookup);
    assert!(
        tail[check.len() + TAIL_BYTES..]
            .iter()
            .all(|&byte| byte == 0xcc)
    );
}
