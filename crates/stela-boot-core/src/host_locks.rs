//! The host drivers' locks, one per lock domain, and their order.
//!
//! Each host controller keeps its state for one owner at a time, so a core
//! enters a driver holding that controller's lock. A domain is either the
//! shared domain, which covers the registry of controllers, hotplug and
//! every driver whose state is not proven to be its controller's alone
//! (USB hosts with the input devices on them, the GPU's environment,
//! firmware, IOMMU and aperture changes), or one controller whose steady
//! I/O touches nothing but its own registers and memory (a storage
//! controller's queues, a network device's rings).
//!
//! Lock order, which rules out deadlock between holders:
//! 1. [`Domain::Shared`] first, then at most one [`Domain::Controller`].
//! 2. A controller holder never takes the shared lock or another
//!    controller's lock, and no holder takes its own lock again.
//!
//! A waiter spins with a callback (the caller answers shootdowns there), and
//! interrupt-context callers only try: neither ever blocks a holder.
use core::sync::atomic::{AtomicU64, Ordering};

/// A lock domain of the host drivers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    /// The registry of controllers, hotplug, and every driver not proven
    /// to own its state alone.
    Shared,
    /// One controller, by its index in the table (below the table's size).
    Controller(u8),
}

impl Domain {
    fn slot(self) -> usize {
        match self {
            Self::Shared => 0,
            Self::Controller(index) => 1 + usize::from(index),
        }
    }
}

/// Why a lock may not be taken now: taking it could deadlock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderError {
    /// The caller holds this lock already.
    Again,
    /// A controller holder asked for the shared lock.
    SharedAfterController,
    /// A controller holder asked for another controller.
    TwoControllers,
    /// No such controller in the table.
    Unknown,
}

/// What one core holds: the shared lock, and at most one controller.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Held {
    pub shared: bool,
    pub controller: Option<u8>,
}

impl Held {
    /// Whether `want` may be taken now, following the lock order.
    pub fn check(self, want: Domain) -> Result<(), OrderError> {
        match (want, self.controller) {
            (Domain::Shared, _) if self.shared => Err(OrderError::Again),
            (Domain::Shared, Some(_)) => Err(OrderError::SharedAfterController),
            (Domain::Shared, None) => Ok(()),
            (Domain::Controller(want), Some(held)) if want == held => Err(OrderError::Again),
            (Domain::Controller(_), Some(_)) => Err(OrderError::TwoControllers),
            (Domain::Controller(_), None) => Ok(()),
        }
    }

    /// What is held after taking `domain` (checked first).
    pub fn with(self, domain: Domain) -> Self {
        match domain {
            Domain::Shared => Self {
                shared: true,
                ..self
            },
            Domain::Controller(index) => Self {
                controller: Some(index),
                ..self
            },
        }
    }
}

/// One lock per domain: the shared one and `CONTROLLERS` controllers. Each
/// records its owner (a nonzero per-processor value, the GS base in the
/// boot program), so a fault handler can ask whether its own processor is
/// inside a driver.
pub struct HostLocks<const SLOTS: usize> {
    owners: [AtomicU64; SLOTS],
}

impl<const SLOTS: usize> Default for HostLocks<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize> HostLocks<SLOTS> {
    /// All free. `SLOTS` counts the shared lock and every controller.
    pub const fn new() -> Self {
        Self {
            owners: [const { AtomicU64::new(0) }; SLOTS],
        }
    }

    fn owner(&self, domain: Domain) -> Option<&AtomicU64> {
        self.owners.get(domain.slot())
    }

    /// What `owner` holds now.
    pub fn held_by(&self, owner: u64) -> Held {
        let mut held = Held::default();
        for (slot, lock) in self.owners.iter().enumerate() {
            if owner != 0 && lock.load(Ordering::Acquire) == owner {
                held = match slot {
                    0 => held.with(Domain::Shared),
                    // Slots past 255 are never handed out (u8 index).
                    _ => held.with(Domain::Controller((slot - 1) as u8)),
                };
            }
        }
        held
    }

    /// Whether any core holds `domain`.
    pub fn taken(&self, domain: Domain) -> bool {
        self.owner(domain)
            .is_some_and(|lock| lock.load(Ordering::Relaxed) != 0)
    }

    /// Take `domain` for `owner` if it is free and the order allows it.
    pub fn try_lock(&self, domain: Domain, owner: u64) -> Result<bool, OrderError> {
        assert_ne!(owner, 0, "a lock owner is nonzero");
        let lock = self.owner(domain).ok_or(OrderError::Unknown)?;
        self.held_by(owner).check(domain)?;
        Ok(lock
            .compare_exchange(0, owner, Ordering::Acquire, Ordering::Relaxed)
            .is_ok())
    }

    /// Take `domain` for `owner`, calling `waiting` between tries; the
    /// count of tries that failed.
    pub fn lock(
        &self,
        domain: Domain,
        owner: u64,
        mut waiting: impl FnMut(),
    ) -> Result<u64, OrderError> {
        let mut tries = 0;
        while !self.try_lock(domain, owner)? {
            tries += 1;
            waiting();
            core::hint::spin_loop();
        }
        Ok(tries)
    }

    /// Release `domain`, which `owner` holds.
    pub fn unlock(&self, domain: Domain, owner: u64) {
        let released = self.owner(domain).is_some_and(|lock| {
            lock.compare_exchange(owner, 0, Ordering::Release, Ordering::Relaxed)
                .is_ok()
        });
        assert!(
            released,
            "{domain:?} released by a core that does not hold it"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn the_order_is_shared_then_one_controller() {
        let none = Held::default();
        assert_eq!(none.check(Domain::Shared), Ok(()));
        assert_eq!(none.check(Domain::Controller(2)), Ok(()));
        let shared = none.with(Domain::Shared);
        assert_eq!(shared.check(Domain::Shared), Err(OrderError::Again));
        assert_eq!(shared.check(Domain::Controller(1)), Ok(()));
        let disk = none.with(Domain::Controller(1));
        assert_eq!(
            disk.check(Domain::Shared),
            Err(OrderError::SharedAfterController)
        );
        assert_eq!(disk.check(Domain::Controller(1)), Err(OrderError::Again));
        assert_eq!(
            disk.check(Domain::Controller(0)),
            Err(OrderError::TwoControllers)
        );
        let both = shared.with(Domain::Controller(1));
        assert_eq!(
            both.check(Domain::Controller(0)),
            Err(OrderError::TwoControllers)
        );
    }

    #[test]
    fn controllers_lock_apart_from_the_shared_lock() {
        let locks = HostLocks::<3>::new();
        assert_eq!(locks.try_lock(Domain::Shared, 7), Ok(true));
        // Another core's disk does not wait for the shared holder.
        assert_eq!(locks.try_lock(Domain::Controller(0), 8), Ok(true));
        assert_eq!(locks.try_lock(Domain::Controller(0), 9), Ok(false));
        assert_eq!(locks.try_lock(Domain::Controller(1), 9), Ok(true));
        assert_eq!(
            locks.held_by(7),
            Held {
                shared: true,
                controller: None
            }
        );
        assert_eq!(locks.held_by(8).controller, Some(0));
        assert_eq!(
            locks.try_lock(Domain::Shared, 8),
            Err(OrderError::SharedAfterController)
        );
        assert_eq!(
            locks.try_lock(Domain::Controller(2), 8),
            Err(OrderError::Unknown)
        );
        locks.unlock(Domain::Controller(0), 8);
        assert!(!locks.taken(Domain::Controller(0)));
        assert!(locks.taken(Domain::Shared));
        assert_eq!(locks.held_by(8), Held::default());
    }

    #[test]
    #[should_panic(expected = "does not hold it")]
    fn only_the_holder_releases() {
        let locks = HostLocks::<2>::new();
        assert_eq!(locks.try_lock(Domain::Controller(0), 1), Ok(true));
        locks.unlock(Domain::Controller(0), 2);
    }

    #[test]
    fn holders_of_one_domain_exclude_each_other() {
        let locks = Arc::new(HostLocks::<2>::new());
        let inside = Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (1..=4u64)
            .map(|owner| {
                let (locks, inside) = (locks.clone(), inside.clone());
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        locks.lock(Domain::Controller(0), owner, || {}).unwrap();
                        assert_eq!(inside.fetch_add(1, Ordering::SeqCst), 0);
                        inside.fetch_sub(1, Ordering::SeqCst);
                        locks.unlock(Domain::Controller(0), owner);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert!(!locks.taken(Domain::Controller(0)));
    }
}
