//! Guest register state, shared by hosted and freestanding execution.

/// What native code reaches of the PE running it, a pointer each in
/// [`GuestState::anchors`]: code holds a [`Place`], never one PE's address.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// `x86_64::chain::ChainControl`.
    Control,
    /// The engine's mirrors of System registers.
    Mirrors,
    /// Those mirrors' cells of the PE's state.
    Cells,
    /// The engine's pointer authentication service.
    Pointer,
    /// That service's memo.
    Memo,
    /// The clock reader (`x86_64::register_read::Count`).
    Count,
    /// The storage of SP_EL0.
    StackZero,
    /// The PE's AMX cell (`x86_64::amx_transfer::Cell`): its live
    /// registers, or zero when native code must leave AMX words to the
    /// engine, and the moves native code completed.
    Amx,
}

/// The entries of [`Anchors`].
const ANCHORS: usize = 8;

/// A PE's pointer for each [`Anchor`]. They are no part of the guest's state:
/// any two compare equal.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Anchors([u64; ANCHORS]);

impl PartialEq for Anchors {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Anchors {}

impl core::ops::Index<Anchor> for Anchors {
    type Output = u64;
    fn index(&self, anchor: Anchor) -> &u64 {
        &self.0[anchor as usize]
    }
}

impl core::ops::IndexMut<Anchor> for Anchors {
    fn index_mut(&mut self, anchor: Anchor) -> &mut u64 {
        &mut self.0[anchor as usize]
    }
}

/// `offset` bytes past an anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place {
    pub anchor: Anchor,
    pub offset: usize,
}

impl Place {
    pub const fn new(anchor: Anchor, offset: usize) -> Self {
        Self { anchor, offset }
    }
}

/// The register state every compiled function takes in RDI
/// ([`crate::block::BlockProfile::abi`] names the ABI). Registers enter and
/// leave native code in this layout. Only NZCV bits 31:28 of PSTATE are held
/// here, or the flag word ([`crate::x86_64::flag_word`]) while pinned code
/// runs. V registers are little-endian pairs of 64-bit halves.
/// Arithmetic preserves unrelated FPCR/FPSR bits, and register accesses apply
/// the declared field masks; saturating integer SIMD sets QC and floating-point
/// arithmetic accumulates exception flags.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestState {
    pub x: [u64; 31],
    pub sp: u64,
    pub nzcv: u32,
    /// The width of the exclusive load native code recorded, or 0 for none
    /// (`x86_64::native_exclusive`).
    pub exclusive_bytes: u32,
    pub v: [[u64; 2]; 32],
    pub fpcr: u32,
    pub fpsr: u32,
    /// The address and the zero-extended value of that load.
    pub exclusive_address: u64,
    pub exclusive_value: u64,
    /// PSTATE.{D,A,I,F} in bits 3:0 while native code runs, which may change
    /// them (`x86_64::register_read::mask_thunk`).
    pub daif: u32,
    /// The masks of interrupts waiting when native code was entered: clearing
    /// one is the engine's.
    pub pending: u32,
    /// [`Self::UNREACHABLE`], which a guest check that fails in system-mode
    /// code moves into the access's address (`x86_64::RangeCheck`).
    pub unreachable: u64,
    /// PSTATE.PAN while native code runs, which completes MSR PAN when the
    /// host keeps it in RFLAGS.AC (`x86_64::register_read::pan_thunk`).
    pub pan: u64,
    /// Set by the engine as it enters native code.
    pub anchors: Anchors,
    /// The end of the guest's native lower range on the host's placement
    /// (`x86_64::RangeCheck::lower_limit`), which an EL0 block's one-sided
    /// check compares access addresses with. Set by the engine as it
    /// enters native code; zero fails every such check.
    pub lower_limit: Limit,
    /// The instructions a native self-loop (`x86_64::block`'s loop mode)
    /// has retired in the iterations before the one it runs, which its exits
    /// move to the chain's count and a fault's settlement adds: 0 outside one.
    pub loop_retired: u64,
    /// The host stack pointer at native code's entry, pointing at the
    /// entry's return address: every exit to the engine reloads RSP from it
    /// before its `ret` ([`crate::x86_64::chain::EXIT_RETURN`]), so frames
    /// native code pushed between blocks are discarded. Set by each entry.
    pub exit_rsp: ExitStack,
}

/// [`GuestState::exit_rsp`]: a host stack address of the native run in
/// progress, no part of the guest's state, so any two compare equal and
/// none prints.
#[repr(transparent)]
#[derive(Clone, Copy, Default)]
pub struct ExitStack(pub u64);

impl PartialEq for ExitStack {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for ExitStack {}

impl core::fmt::Debug for ExitStack {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ExitStack")
    }
}

/// [`GuestState::lower_limit`]: the host's, no part of the guest's state, so
/// any two compare equal.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Limit(pub u64);

impl PartialEq for Limit {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Limit {}

impl GuestState {
    /// Non-canonical at either paging depth, with room for what a check's
    /// access adds to it: the access takes a #GP at its own recovery site.
    pub const UNREACHABLE: u64 = 1 << 62;
}

impl Default for GuestState {
    fn default() -> Self {
        Self {
            x: [0; 31],
            sp: 0,
            nzcv: 0,
            exclusive_bytes: 0,
            v: [[0; 2]; 32],
            fpcr: 0,
            fpsr: 0,
            exclusive_address: 0,
            exclusive_value: 0,
            daif: 0,
            pending: 0,
            unreachable: Self::UNREACHABLE,
            pan: 0,
            anchors: Anchors::default(),
            lower_limit: Limit(0),
            loop_retired: 0,
            exit_rsp: ExitStack(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GuestState;
    use crate::block::{BlockProfile, Features};
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn layout_matches_native_abi() {
        for profile in [BlockProfile::ORDINARY, BlockProfile::new(Features::LEAF)] {
            assert!(profile.abi().starts_with("x86_64-sysv-guest-state-v14-"));
        }
        assert_eq!(size_of::<GuestState>(), 912);
        assert_eq!(align_of::<GuestState>(), 8);
        assert_eq!(offset_of!(GuestState, x), 0);
        assert_eq!(offset_of!(GuestState, sp), 248);
        assert_eq!(offset_of!(GuestState, nzcv), 256);
        assert_eq!(offset_of!(GuestState, exclusive_bytes), 260);
        assert_eq!(offset_of!(GuestState, v), 264);
        assert_eq!(size_of::<[[u64; 2]; 32]>(), 512);
        assert_eq!(offset_of!(GuestState, fpcr), 776);
        assert_eq!(offset_of!(GuestState, fpsr), 780);
        assert_eq!(offset_of!(GuestState, unreachable), 808);
        assert_eq!(offset_of!(GuestState, pan), 816);
        assert_eq!(offset_of!(GuestState, lower_limit), 888);
        assert_eq!(offset_of!(GuestState, loop_retired), 896);
        assert_eq!(offset_of!(GuestState, exit_rsp), 904);
    }

    #[test]
    fn default_initializes_every_architectural_field() {
        let state = GuestState::default();
        assert_eq!(state.x, [0; 31]);
        assert_eq!(state.sp, 0);
        assert_eq!(state.nzcv, 0);
        assert_eq!(state.exclusive_bytes, 0);
        assert_eq!(state.v, [[0; 2]; 32]);
        assert_eq!(state.fpcr, 0);
        assert_eq!(state.fpsr, 0);
    }
}
