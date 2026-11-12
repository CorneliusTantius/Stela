//! Stable chaining storage with one local writer and atomic interruption epochs.
use alloc::sync::Arc;
use core::{
    cell::{Cell, UnsafeCell},
    marker::PhantomData,
    sync::atomic::{AtomicU64, Ordering},
};
use stela_compiler::x86_64::chain::{self, ChainControl, itlb_salt};

/// The salts of `contexts` in an ITLB of the set mask in `masks`.
fn salts(contexts: [u64; 2], masks: [u32; 2]) -> [u32; 2] {
    contexts.map(|context| itlb_salt(context, masks[1]))
}

/// By its hub inbox even when no Machine owns the PE. The hub exposes
/// only the interruption epoch; all other fields belong to its admitted Machine.
#[repr(C, align(64))]
pub(super) struct Storage {
    control: UnsafeCell<ChainControl>,
}
// SAFETY: shared storage exposes only an aligned atomic epoch. Other fields
// are accessed only through the unique Owner admitted by the inbox.
unsafe impl Send for Storage {}
// SAFETY: the same single-writer/atomic-epoch contract applies to shared access.
unsafe impl Sync for Storage {}
impl Storage {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            control: UnsafeCell::new(ChainControl::default()),
        })
    }
    fn count(&self) -> &AtomicU64 {
        // SAFETY: the live allocation has ChainControl's aligned u64 count.
        // Rust never reads/writes this field non-atomically after publication;
        // native chaining uses its aligned architectural accesses at this ABI.
        unsafe { AtomicU64::from_ptr(core::ptr::addr_of_mut!((*self.control.get()).count)) }
    }
    pub(super) fn interrupt_epoch(&self) -> &AtomicU64 {
        // SAFETY: the control has a naturally aligned epoch field.
        // Every Rust access is atomic; native thunks perform aligned loads.
        unsafe {
            AtomicU64::from_ptr(core::ptr::addr_of_mut!(
                (*self.control.get()).interrupt_epoch
            ))
        }
    }
    pub(super) fn notify(&self) {
        // Publish every source write before making the corresponding epoch
        // visible. Exhaustion stays permanently interrupted rather than wraps.
        let _ = self
            .interrupt_epoch()
            .try_update(Ordering::Release, Ordering::Relaxed, |epoch| {
                Some(epoch.saturating_add(1))
            });
    }
}

/// The sole local-control writer. It can move between threads with its Machine,
/// but cannot be shared; a hub keeps Storage without granting this role.
pub(super) struct Owner {
    storage: Arc<Storage>,
    /// The budget the last native call began with ([`Self::begin`]).
    entered: u64,
    _single_writer: PhantomData<Cell<()>>,
    _attachment: Option<Arc<super::parallel::Attached>>,
}
impl Default for Owner {
    fn default() -> Self {
        Self {
            storage: Storage::new(),
            entered: 0,
            _single_writer: PhantomData,
            _attachment: None,
        }
    }
}
impl Owner {
    /// # Safety
    /// The caller holds the unique live attachment claim for this storage,
    /// until this Owner can no longer access it. No old native code or other
    /// writer may run through its previous owner's installed chain thunks.
    pub(super) unsafe fn from_claimed(
        storage: Arc<Storage>,
        attachment: Arc<super::parallel::Attached>,
    ) -> Self {
        Self {
            storage,
            entered: 0,
            _single_writer: PhantomData,
            _attachment: Some(attachment),
        }
    }
    /// The count native code adds its transfers to ([`ChainControl::count`]).
    pub(super) fn count(&self) -> &AtomicU64 {
        self.storage.count()
    }
    /// The decoded control's count, for its budget and instructions.
    fn counted(&self) -> ChainControl {
        ChainControl {
            count: self.count().load(Ordering::Relaxed),
            ..ChainControl::default()
        }
    }
    /// The transfers the last native call's count still allows: more than
    /// it began with once a transfer found none left.
    pub(super) fn remaining(&self) -> u64 {
        self.counted().remaining()
    }
    pub(super) fn address(&self) -> u64 {
        self.storage.control.get() as u64
    }

    /// Reset every local field, keeping the inbox's monotonic notification epoch.
    pub(super) fn initialize(
        &mut self,
        table: u64,
        itlb: u64,
        contexts: [u64; 2],
        masks: [u32; 2],
    ) {
        let control = self.storage.control.get();
        // SAFETY: this Owner is the sole local writer, with no native call
        // in progress. Disjoint raw writes never borrow the shared epoch.
        unsafe {
            core::ptr::addr_of_mut!((*control).block).write(0);
            core::ptr::addr_of_mut!((*control).contexts).write(contexts);
            core::ptr::addr_of_mut!((*control).salts).write(salts(contexts, masks));
            core::ptr::addr_of_mut!((*control).masks).write(masks);
            core::ptr::addr_of_mut!((*control).table).write(table);
            core::ptr::addr_of_mut!((*control).itlb).write(itlb);
            core::ptr::addr_of_mut!((*control).hits).write(0);
            core::ptr::addr_of_mut!((*control).linked).write(0);
            core::ptr::addr_of_mut!((*control).observed_interrupt_epoch).write(0);
        }
        self.count()
            .store(ChainControl::counting(0, 0), Ordering::Relaxed);
    }
    /// Acknowledge only the Acquire snapshot taken before a successful drain.
    /// MAX is never acknowledged, so exhausted notification state stays sticky.
    pub(super) fn acknowledge_interrupt(&mut self, epoch: u64) {
        // SAFETY: only the unique owner writes the observed field outside its
        // synchronous native invocation; notifiers touch the separate epoch.
        unsafe {
            core::ptr::addr_of_mut!((*self.storage.control.get()).observed_interrupt_epoch)
                .write(epoch.min(u64::MAX - 1));
        }
    }
    /// The epoch the owner last acknowledged: every notification up to it
    /// has been drained ([`Self::acknowledge_interrupt`]).
    pub(super) fn acknowledged_interrupt(&self) -> u64 {
        // SAFETY: only this owner writes the observed field, outside native
        // execution; notifiers touch the separate epoch.
        unsafe {
            core::ptr::addr_of!((*self.storage.control.get()).observed_interrupt_epoch).read()
        }
    }
    /// Whether a notification came since the owner last acknowledged one,
    /// as a native GEXIT compares them.
    pub(super) fn interrupt_moved(&self) -> bool {
        self.storage.interrupt_epoch().load(Ordering::Acquire) != self.acknowledged_interrupt()
    }
    pub(super) fn set_table(&mut self, table: u64, itlb: u64, masks: [u32; 2]) {
        // SAFETY: the sole owner writes these non-budget fields outside native execution.
        unsafe {
            let control = self.storage.control.get();
            core::ptr::addr_of_mut!((*control).table).write(table);
            core::ptr::addr_of_mut!((*control).itlb).write(itlb);
            core::ptr::addr_of_mut!((*control).masks).write(masks);
            let contexts = core::ptr::addr_of!((*control).contexts).read();
            core::ptr::addr_of_mut!((*control).salts).write(salts(contexts, masks));
        }
    }
    /// This PE's stamps and the board's stamped cells, which stamped tails
    /// and the cell probe use ([`stela_compiler::x86_64::chain::stamped_tail`]).
    pub(super) fn set_stamps(&mut self, stamps: u64, cells: u64) {
        // SAFETY: the sole owner writes these non-budget fields outside native execution.
        unsafe {
            let control = self.storage.control.get();
            core::ptr::addr_of_mut!((*control).stamps).write(stamps);
            core::ptr::addr_of_mut!((*control).cells).write(cells);
        }
    }
    /// The stamps and stamped cells [`Self::set_stamps`] gave, or zeros.
    pub(super) fn stamps(&self) -> (u64, u64) {
        let control = self.storage.control.get();
        // SAFETY: the sole owner reads these non-budget fields outside native execution.
        unsafe {
            (
                core::ptr::addr_of!((*control).stamps).read(),
                core::ptr::addr_of!((*control).cells).read(),
            )
        }
    }
    /// What this PE's stamped tails and stamping cell probe counted
    /// ([`chain::StampCount`]).
    pub(super) fn stamp_counts(&self) -> [u64; chain::STAMP_COUNTS] {
        // SAFETY: the sole owner reads this non-budget field outside native execution.
        let stamps = unsafe { core::ptr::addr_of!((*self.storage.control.get()).stamps).read() };
        // SAFETY: `set_stamps` stored 0 or the board's table's stamps for
        // this PE, which live as long as the board.
        unsafe { chain::stamp_counts(stamps) }
    }
    fn masks(&self) -> [u32; 2] {
        // SAFETY: only this Owner writes the masks, outside native execution.
        unsafe { core::ptr::addr_of!((*self.storage.control.get()).masks).read() }
    }
    pub(super) fn contexts(&self) -> [u64; 2] {
        // SAFETY: only this Owner or its synchronous native call can write contexts.
        unsafe { core::ptr::addr_of!((*self.storage.control.get()).contexts).read() }
    }
    /// The ITLB salts of [`Self::contexts`].
    pub(super) fn salts(&self) -> [u32; 2] {
        // SAFETY: only this Owner or its synchronous native call can write salts.
        unsafe { core::ptr::addr_of!((*self.storage.control.get()).salts).read() }
    }
    /// The ITLB salts `contexts` would take as [`Self::contexts`].
    pub(super) fn salts_of(&self, contexts: [u64; 2]) -> [u32; 2] {
        salts(contexts, self.masks())
    }
    pub(super) fn set_contexts(&mut self, contexts: [u64; 2]) {
        // SAFETY: the sole owner writes this non-budget field outside native execution.
        unsafe {
            let control = self.storage.control.get();
            core::ptr::addr_of_mut!((*control).contexts).write(contexts);
        }
        let masks = self.masks();
        // SAFETY: as above.
        unsafe {
            core::ptr::addr_of_mut!((*self.storage.control.get()).salts)
                .write(salts(contexts, masks));
        }
    }
    pub(super) fn begin(&mut self, block: usize, budget: u64) {
        let budget = budget.min(chain::MAX_BUDGET);
        let control = self.storage.control.get();
        // SAFETY: the sole owner prepares these disjoint fields before its
        // synchronous native call; remote writers touch only the epoch.
        unsafe {
            core::ptr::addr_of_mut!((*control).block).write(block as u64);
            core::ptr::addr_of_mut!((*control).hits).write(0);
            core::ptr::addr_of_mut!((*control).linked).write(0);
        }
        // SAFETY: `set_stamps` stored 0 or the board's table's stamps for
        // this PE, and its native code does not run.
        unsafe { chain::next_jump_serial(self.stamps().0) };
        self.count()
            .store(ChainControl::counting(budget, 0), Ordering::Relaxed);
        self.entered = budget;
    }
    /// The block that ended the last native call, the instructions of the
    /// blocks it chained out of, the transfers lookup probes made and the
    /// others. Native code counts no other transfers: each spends one of the
    /// budget, and one that finds none left leaves more remaining than any
    /// budget.
    pub(super) fn completed(&self) -> (u64, u64, u64, u64) {
        let control = self.storage.control.get();
        let counted = self.counted();
        let remaining = counted.remaining();
        let chained = if remaining > self.entered {
            self.entered
        } else {
            self.entered - remaining
        };
        // SAFETY: the synchronous native call has returned; no other owner
        // touches these fields, including while a peer posts an interruption.
        let (block, hits) = unsafe {
            (
                core::ptr::addr_of!((*control).block).read(),
                core::ptr::addr_of!((*control).hits).read(),
            )
        };
        let retired = counted.retired();
        (block, retired, hits, chained.saturating_sub(hits))
    }
    #[cfg(test)]
    pub(super) fn weak_storage(&self) -> alloc::sync::Weak<Storage> {
        Arc::downgrade(&self.storage)
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> ChainControl {
        let (block, _, hits, linked) = self.completed();
        let control = self.storage.control.get();
        ChainControl {
            count: self.count().load(Ordering::Relaxed),
            block,
            hits,
            linked,
            contexts: self.contexts(),
            salts: salts(self.contexts(), self.masks()),
            masks: self.masks(),
            // SAFETY: the sole owner observes a non-budget field outside entry.
            table: unsafe { core::ptr::addr_of!((*control).table).read() },
            // SAFETY: as for `table`.
            itlb: unsafe { core::ptr::addr_of!((*control).itlb).read() },
            interrupt_epoch: self.storage.interrupt_epoch().load(Ordering::Acquire),
            // SAFETY: only the unique owner writes the observed epoch.
            observed_interrupt_epoch: unsafe {
                core::ptr::addr_of!((*control).observed_interrupt_epoch).read()
            },
            // SAFETY: as for `table`.
            stamps: unsafe { core::ptr::addr_of!((*control).stamps).read() },
            // SAFETY: as for `table`.
            cells: unsafe { core::ptr::addr_of!((*control).cells).read() },
            // SAFETY: as for `table`; native code adds to it only within a call.
            heat: unsafe { core::ptr::addr_of!((*control).heat).read() },
            loop_entries: self.loops().0,
            loop_iterated: self.loops().1,
        }
    }

    /// [`ChainControl::loop_entries`] and [`ChainControl::loop_iterated`]
    /// since the storage was made.
    pub(super) fn loops(&self) -> (u64, u64) {
        let control = self.storage.control.get();
        // SAFETY: the sole owner reads them outside a native call, the only
        // time native code writes them.
        unsafe {
            (
                core::ptr::addr_of!((*control).loop_entries).read(),
                core::ptr::addr_of!((*control).loop_iterated).read(),
            )
        }
    }
}
