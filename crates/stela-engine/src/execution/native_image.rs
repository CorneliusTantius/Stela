//! Synchronous native ABI calls into borrowed executable storage.
use core::{convert::Infallible, ptr::NonNull};
use stela_compiler::{GuestState, block::BlockExit, context::ExecutionContext};

/// Implemented only by the POSIX RX mapping and the boot-frame owner.
///
/// # Safety
/// While borrowed, the owner keeps the initialized executable bytes, their
/// mapping and cache controls, and the sole right to reclaim them; nothing may
/// write, remap, reclaim or alias them during a call. `entry` is non-null and
/// points at the first byte of the image. `revalidate` checks the live storage
/// controls. The caller binds the compiler, profile, ABI and artifact before
/// calling.
pub(super) unsafe trait ExecutableStorage {
    type Error;
    fn entry(&self) -> NonNull<u8>;
    fn revalidate(&self) -> Result<(), Self::Error>;
}

/// The native result is kept even when the storage check fails. Consumers must
/// keep both this and the context and finalizer outcomes; a storage failure
/// never permits retry or completion.
#[must_use]
pub(crate) struct ReachedCall<R, E> {
    pub(super) returned: R,
    pub(super) storage_after: Result<(), E>,
}
impl<R, E> ReachedCall<R, E> {
    /// The native result and the storage check.
    pub(crate) fn into_observations(self) -> (R, Result<(), E>) {
        (self.returned, self.storage_after)
    }
}

impl<R> ReachedCall<R, Infallible> {
    #[cfg(feature = "std")]
    pub(super) fn into_infallible(self) -> R {
        let (returned, storage_after) = self.into_observations();
        match storage_after {
            Ok(()) => returned,
            Err(never) => match never {},
        }
    }
}

/// Lifetime borrows concrete storage; there is no raw-pointer constructor.
pub(super) struct NativeImage<'rx, S: ExecutableStorage + ?Sized> {
    storage: &'rx S,
}
impl<'rx, S: ExecutableStorage + ?Sized> NativeImage<'rx, S> {
    pub(super) fn borrow(storage: &'rx S) -> Self {
        Self { storage }
    }
    pub(super) fn revalidate(&self) -> Result<(), S::Error> {
        self.storage.revalidate()
    }

    /// # Safety
    /// The caller guarantees the System V GuestState leaf ABI, termination,
    /// host support and every direct-RAM access and aliasing requirement. A PE
    /// may call only from its session, which holds its state, backend, source
    /// and domain through finalization and PC settlement.
    #[cfg(feature = "std")]
    pub(super) unsafe fn call(
        &self,
        state: &mut GuestState,
    ) -> Result<ReachedCall<(), S::Error>, S::Error> {
        self.revalidate()?;
        let function: unsafe extern "sysv64" fn(*mut GuestState) =
            // SAFETY: `entry` starts this storage's revalidated code, compiled for this signature.
            unsafe { core::mem::transmute(self.storage.entry().as_ptr()) };
        // SAFETY: the caller upholds this ABI's contract, documented above.
        unsafe { function(state) };
        Ok(ReachedCall {
            returned: (),
            storage_after: self.revalidate(),
        })
    }

    /// # Safety
    /// The context-block struct-return ABI and the source, body, map and
    /// requirements must be bound. Every state, context and policy view stays
    /// pinned through the call and finalization. The PE session contract above
    /// applies.
    pub(super) unsafe fn call_context_block(
        &self,
        state: &mut GuestState,
        context: &mut ExecutionContext,
    ) -> Result<ReachedCall<BlockExit, S::Error>, S::Error> {
        self.revalidate()?;
        let function: unsafe extern "sysv64" fn(
            *mut GuestState,
            *mut ExecutionContext,
            // SAFETY: `entry` starts this storage's revalidated code, compiled for this signature.
        ) -> BlockExit = unsafe { core::mem::transmute(self.storage.entry().as_ptr()) };
        // SAFETY: the caller upholds this ABI's contract, documented above.
        let returned = unsafe { function(state, context) };
        Ok(ReachedCall {
            returned,
            storage_after: self.revalidate(),
        })
    }

    /// # Safety
    /// The caller binds the resident-budget ABI, register bank and per-call
    /// budget. Resident loops are non-faulting integer code; fallbacks have the
    /// ordinary call's memory, fault and target requirements. No asynchronous
    /// producer domain is allowed. The storage and any session stay borrowed
    /// through both results.
    #[cfg(feature = "std")]
    pub(super) unsafe fn call_budgeted_block(
        &self,
        state: &mut GuestState,
        budget: &mut stela_compiler::block::loop_budget::LoopBudget,
    ) -> Result<ReachedCall<BlockExit, S::Error>, S::Error> {
        self.revalidate()?;
        // SAFETY: `entry` starts this storage's revalidated code, compiled
        // for this signature, and the caller upholds its contract, above.
        let returned = exit(unsafe {
            stela_compiler::x86_64::block_entry::enter(
                self.storage.entry().as_ptr(),
                state,
                budget as *mut _ as u64,
                0,
            )
        });
        Ok(ReachedCall {
            returned,
            storage_after: self.revalidate(),
        })
    }

    /// Call an AMX kernel at `offset` in a `stela_compiler::x86_64::amx`
    /// library image.
    ///
    /// # Safety
    /// `offset` starts a kernel of that image, `z` is a writable 4 KiB Z grid,
    /// and `x` and `y` are 64 readable bytes each. The host admits the
    /// library's tier.
    #[cfg(feature = "std")]
    pub(super) unsafe fn call_amx_kernel(
        &self,
        offset: usize,
        z: *mut u8,
        x: *const u8,
        y: *const u8,
        row: u64,
    ) -> Result<ReachedCall<(), S::Error>, S::Error> {
        self.revalidate()?;
        let function: unsafe extern "sysv64" fn(*mut u8, *const u8, *const u8, u64) =
            // SAFETY: the caller guarantees `offset` starts a kernel of this image, compiled for
            // this signature.
            unsafe { core::mem::transmute(self.storage.entry().as_ptr().add(offset)) };
        // SAFETY: the caller upholds this ABI's contract, documented above.
        unsafe { function(z, x, y, row) };
        Ok(ReachedCall {
            returned: (),
            storage_after: self.revalidate(),
        })
    }

    /// # Safety
    /// The direct-RAM block ABI and every memory, fault and target requirement
    /// apply, as does the PE session contract above.
    pub(super) unsafe fn call_block(
        &self,
        state: &mut GuestState,
    ) -> Result<ReachedCall<BlockExit, S::Error>, S::Error> {
        self.revalidate()?;
        // SAFETY: `entry` starts this storage's revalidated code, compiled
        // for this signature, and the caller upholds its contract, above.
        let returned = exit(unsafe {
            stela_compiler::x86_64::block_entry::enter(self.storage.entry().as_ptr(), state, 0, 0)
        });
        Ok(ReachedCall {
            returned,
            storage_after: self.revalidate(),
        })
    }
}

/// The block exit RAX and RDX hold, as the block entry returns them.
fn exit(returned: u128) -> BlockExit {
    BlockExit {
        next_pc: returned as u64,
        kind: (returned >> 64) as u64,
    }
}
