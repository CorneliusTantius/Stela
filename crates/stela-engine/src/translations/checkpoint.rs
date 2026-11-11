//! When a running boot saves its translation store: a checkpoint decision
//! from the amount of code translated since the last save and how quiet the
//! machine is, so that a power cut, a hard reset or a panic keeps what the
//! boot translated up to its last quiet moment.
//!
//! The decision is pure: the caller feeds it counter ticks, the new pages
//! the store gained and how many PEs wait, and runs the save it asks for in
//! bounded steps from a waiting PE. Nothing here knows what the guest runs;
//! the first saves fall where the guest first goes quiet after translating
//! much (typically a login screen), and again when it next settles after
//! more (typically a desktop).

/// The thresholds of a [`Checkpoints`] decision, in counter ticks and bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// New pages, or new page bytes, since the last save that make a save
    /// worth its writes.
    pub min_pages: u64,
    pub min_bytes: u64,
    /// The machine is quiet while at least this share (per mille) of its PEs
    /// wait, and has to stay so for `quiet_ticks` before a save starts.
    pub quiet_permille: u32,
    pub quiet_ticks: u64,
    /// The least time between two saves, counted from the end of the last.
    pub spacing_ticks: u64,
    /// After this long without new pages, any unsaved page is saved once a
    /// PE waits, however busy the others are: the busy phase has ended.
    pub settle_ticks: u64,
    /// The least time between two looks: a look in between returns at once,
    /// so that idle PEs asking often cost nothing.
    pub look_ticks: u64,
}

impl Policy {
    /// The default thresholds for a counter of `hz` ticks per second: 2048
    /// pages or 8 MiB of new records; half the PEs waiting for 3 s; 60 s
    /// between saves; any unsaved page saved 4 minutes after the last new
    /// one; a look at most every 100 ms.
    pub const fn for_hz(hz: u64) -> Self {
        Self {
            min_pages: 2048,
            min_bytes: 8 << 20,
            quiet_permille: 500,
            quiet_ticks: 3 * hz,
            spacing_ticks: 60 * hz,
            settle_ticks: 240 * hz,
            look_ticks: hz / 10,
        }
    }
}

/// What a look decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Nothing to do now.
    Wait,
    /// Start a save of everything unsaved: enough new code and the machine
    /// quiet long enough.
    Quiet,
    /// Start a save: the busy phase that translated the unsaved pages ended
    /// `settle_ticks` ago.
    Settled,
}

/// The checkpoint state of one boot's store.
#[derive(Debug, Clone)]
pub struct Checkpoints {
    policy: Policy,
    unsaved_pages: u64,
    unsaved_bytes: u64,
    /// Counter of the last new page, of the end of the last save (or of the
    /// start), of the start of the current quiet stretch, and of the next look.
    last_new: u64,
    last_save: u64,
    quiet_since: Option<u64>,
    next_look: u64,
    /// The pages and bytes the running save covers: those noted after it
    /// started stay unsaved when it ends.
    saving: Option<(u64, u64)>,
    /// Saves finished and saves that failed.
    pub saved: u64,
    pub failed: u64,
}

impl Checkpoints {
    /// A boot's state at counter `now`, with nothing unsaved.
    pub const fn new(policy: Policy, now: u64) -> Self {
        Self {
            policy,
            unsaved_pages: 0,
            unsaved_bytes: 0,
            last_new: now,
            last_save: now,
            quiet_since: None,
            next_look: now,
            saving: None,
            saved: 0,
            failed: 0,
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The store gained `pages` pages of `bytes` record bytes at `now`.
    pub fn note_new(&mut self, now: u64, pages: u64, bytes: u64) {
        if pages == 0 && bytes == 0 {
            return;
        }
        self.unsaved_pages = self.unsaved_pages.saturating_add(pages);
        self.unsaved_bytes = self.unsaved_bytes.saturating_add(bytes);
        self.last_new = now;
    }

    /// Pages and bytes not yet saved, including those a running save covers.
    pub fn unsaved(&self) -> (u64, u64) {
        (self.unsaved_pages, self.unsaved_bytes)
    }

    /// Whether a save is running.
    pub fn saving(&self) -> bool {
        self.saving.is_some()
    }

    /// Look at `now`, with `waiting` of `pes` PEs waiting (the caller is one
    /// of them). A decision to start marks the save running until
    /// [`Self::finished`].
    pub fn look(&mut self, now: u64, waiting: u32, pes: u32) -> Decision {
        if now < self.next_look {
            return Decision::Wait;
        }
        self.next_look = now.saturating_add(self.policy.look_ticks);
        let quiet = pes != 0
            && u64::from(waiting) * 1000 >= u64::from(pes) * u64::from(self.policy.quiet_permille);
        if quiet {
            self.quiet_since.get_or_insert(now);
        } else {
            self.quiet_since = None;
        }
        if self.saving.is_some()
            || self.unsaved_pages == 0
            || waiting == 0
            || now.saturating_sub(self.last_save) < self.policy.spacing_ticks
        {
            return Decision::Wait;
        }
        let enough = self.unsaved_pages >= self.policy.min_pages
            || self.unsaved_bytes >= self.policy.min_bytes;
        let decision = if enough
            && self
                .quiet_since
                .is_some_and(|since| now.saturating_sub(since) >= self.policy.quiet_ticks)
        {
            Decision::Quiet
        } else if now.saturating_sub(self.last_new) >= self.policy.settle_ticks {
            Decision::Settled
        } else {
            return Decision::Wait;
        };
        self.saving = Some((self.unsaved_pages, self.unsaved_bytes));
        decision
    }

    /// The running save ended at `now`: `saved` when its pack is durable.
    /// A failed save keeps everything unsaved and waits a spacing before
    /// the next try.
    pub fn finished(&mut self, now: u64, saved: bool) {
        let Some((pages, bytes)) = self.saving.take() else {
            return;
        };
        if saved {
            self.unsaved_pages -= pages.min(self.unsaved_pages);
            self.unsaved_bytes -= bytes.min(self.unsaved_bytes);
            self.saved += 1;
        } else {
            self.failed += 1;
        }
        self.last_save = now;
        self.quiet_since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HZ: u64 = 1000;

    fn policy() -> Policy {
        Policy::for_hz(HZ)
    }

    /// Look every 100 ms from `from` to `to` with `waiting` of 8 PEs
    /// waiting: the first decision to start, and when.
    fn run(state: &mut Checkpoints, from: u64, to: u64, waiting: u32) -> Option<(u64, Decision)> {
        (from..to)
            .step_by(100)
            .find_map(|now| match state.look(now, waiting, 8) {
                Decision::Wait => None,
                decision => Some((now, decision)),
            })
    }

    #[test]
    fn a_busy_machine_translating_does_not_save_until_it_goes_quiet() {
        let mut state = Checkpoints::new(policy(), 0);
        // Boot: all PEs busy translating for 100 s.
        for second in 0..100 {
            state.note_new(second * HZ, 100, 400 << 10);
            assert_eq!(run(&mut state, second * HZ, (second + 1) * HZ, 1), None);
        }
        // Quiet (login screen): a save starts 3 s into the quiet stretch.
        let (at, decision) = run(&mut state, 100 * HZ, 200 * HZ, 6).unwrap();
        assert_eq!(decision, Decision::Quiet);
        assert_eq!(at, 103 * HZ);
        assert!(state.saving());
        // No second start while it runs.
        assert_eq!(run(&mut state, at + 100, 300 * HZ, 8), None);
        state.finished(105 * HZ, true);
        assert_eq!(state.unsaved(), (0, 0));
        assert_eq!(state.saved, 1);
        // Nothing new: no save, however quiet.
        assert_eq!(run(&mut state, 106 * HZ, 1000 * HZ, 8), None);
    }

    #[test]
    fn the_second_save_waits_for_the_spacing_and_the_next_quiet_stretch() {
        let mut state = Checkpoints::new(policy(), 0);
        state.note_new(0, 5000, 20 << 20);
        let (at, _) = run(&mut state, 60 * HZ, 100 * HZ, 8).unwrap();
        state.finished(at + HZ, true);
        // Sign-in: busy translating again right after the save.
        for second in 0..30 {
            let now = at + (2 + second) * HZ;
            state.note_new(now, 200, 1 << 20);
            assert_eq!(run(&mut state, now, now + HZ, 2), None);
        }
        // Desktop settles: quiet, but within the spacing of the first save
        // the next one waits.
        let quiet = at + 32 * HZ;
        let (next, decision) = run(&mut state, quiet, quiet + 100 * HZ, 7).unwrap();
        assert_eq!(decision, Decision::Quiet);
        assert_eq!(next, at + HZ + 60 * HZ);
    }

    #[test]
    fn a_short_quiet_stretch_or_too_little_new_code_does_not_save() {
        let mut state = Checkpoints::new(policy(), 0);
        state.note_new(0, 10, 4096);
        // Quiet, but little new code: only the settle rule saves it.
        let (at, decision) = run(&mut state, 61 * HZ, 400 * HZ, 8).unwrap();
        assert_eq!(decision, Decision::Settled);
        assert_eq!(at, 240 * HZ);
        state.finished(at, true);
        // Enough new code, quiet stretches under 3 s: no save.
        state.note_new(at, 4096, 16 << 20);
        let mut now = at + 61 * HZ;
        for _ in 0..20 {
            assert_eq!(run(&mut state, now, now + 2 * HZ, 8), None);
            assert_eq!(run(&mut state, now + 2 * HZ, now + 3 * HZ, 0), None);
            now += 3 * HZ;
        }
    }

    #[test]
    fn a_busy_phase_that_ends_without_quiet_still_saves_once_a_pe_waits() {
        let mut state = Checkpoints::new(policy(), 0);
        state.note_new(10 * HZ, 3000, 12 << 20);
        // One PE waits now and then, the rest stay busy: settled after 4 min.
        let (at, decision) = run(&mut state, 11 * HZ, 600 * HZ, 1).unwrap();
        assert_eq!(decision, Decision::Settled);
        assert_eq!(at, 250 * HZ);
        // No PE waiting: never, since the save runs on a waiting PE.
        let mut busy = Checkpoints::new(policy(), 0);
        busy.note_new(0, 3000, 12 << 20);
        assert_eq!(run(&mut busy, HZ, 1000 * HZ, 0), None);
    }

    #[test]
    fn pages_noted_during_a_save_stay_unsaved_and_a_failure_keeps_all() {
        let mut state = Checkpoints::new(policy(), 0);
        state.note_new(0, 3000, 12 << 20);
        let (at, _) = run(&mut state, 60 * HZ, 100 * HZ, 8).unwrap();
        state.note_new(at + 10, 7, 700);
        state.finished(at + HZ, true);
        assert_eq!(state.unsaved(), (7, 700));
        state.note_new(at + 2 * HZ, 3000, 1);
        let (again, _) = run(&mut state, at + 2 * HZ, at + 200 * HZ, 8).unwrap();
        assert_eq!(again, at + HZ + 60 * HZ);
        state.finished(again + HZ, false);
        assert_eq!(state.unsaved(), (3007, 701));
        assert_eq!(state.failed, 1);
        // A failure backs off a spacing before the next try.
        let (retry, _) = run(&mut state, again + HZ, again + 300 * HZ, 8).unwrap();
        assert_eq!(retry, again + HZ + 60 * HZ);
    }

    #[test]
    fn looks_closer_than_the_look_interval_return_at_once() {
        let mut state = Checkpoints::new(policy(), 0);
        state.note_new(0, 3000, 12 << 20);
        assert_eq!(state.look(60 * HZ, 8, 8), Decision::Wait);
        // Within 100 ms: not looked at, so the quiet stretch is unchanged.
        for now in 60 * HZ + 1..60 * HZ + 100 {
            assert_eq!(state.look(now, 0, 8), Decision::Wait);
        }
        assert_eq!(state.look(63 * HZ, 8, 8), Decision::Quiet);
    }
}
