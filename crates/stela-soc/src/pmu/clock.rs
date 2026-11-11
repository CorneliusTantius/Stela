//! One declared PMIC upcount owner shared by its SPMI and SMC interfaces.
use super::RTC_HZ;
use crate::Result;
use crate::counter::FREQUENCY_HZ;
use alloc::rc::Rc;
use core::cell::Cell;
use stela_contracts::refuse;
use stela_soc_data::pmu::WallClock;

const LIMIT: u64 = 1 << 47;

/// Unix seconds of the upcount's zero when the host's wall time is known:
/// 2001-01-01T00:00:00Z. The 47-bit upcount then lasts 2^32 seconds, to
/// 2137, and the clock offset is about this base in ticks (3.2e13, inside
/// both the signed 48-bit register and the signed 47-bit legacy field).
pub const UPCOUNT_BASE_UNIX_SECONDS: u64 = 978_307_200;

/// Declared emulated resource origin, not an observed Apple reset value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcEpoch {
    pub counter: u64,
    pub ticks: u64,
}

impl RtcEpoch {
    /// The origin of a PMIC whose upcount has run since
    /// [`UPCOUNT_BASE_UNIX_SECONDS`], as a Mac's RTC keeps counting across
    /// power cycles: each boot's upcount continues the last one's and
    /// follows the host's wall time. Without a wall time, or with one
    /// outside the 47-bit upcount from the base, the upcount starts at zero
    /// at `now`, a PMIC that lost power.
    pub fn continuous(now: u64, wall: Option<WallClock>) -> Self {
        let cold = Self {
            counter: now,
            ticks: 0,
        };
        let Some(wall) = wall else {
            return cold;
        };
        let Some(seconds) = wall.unix_seconds.checked_sub(UPCOUNT_BASE_UNIX_SECONDS) else {
            return cold;
        };
        // Carry the wall time's ticks from its counter to `now`.
        let rate =
            |counter: u64| i128::from(counter) * i128::from(RTC_HZ) / i128::from(FREQUENCY_HZ);
        let ticks = i128::from(seconds) * i128::from(RTC_HZ) + rate(now) - rate(wall.counter);
        match u64::try_from(ticks) {
            Ok(ticks) if ticks < LIMIT => Self {
                counter: now,
                ticks,
            },
            _ => cold,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    counter: u64,
    ticks: u64,
}
#[derive(Debug)]
struct Clock {
    epoch: RtcEpoch,
    sample: Cell<Option<Sample>>,
    /// The last counter refused for preceding the publication, with it.
    regression: Cell<Option<(u64, u64)>>,
}

/// Ownership of one PMIC oscillator/epoch. Clones refer to the same
/// publication; no interface owns another wall clock or a default sample.
#[derive(Debug, Clone)]
pub struct RtcClock(Rc<Clock>);
impl RtcClock {
    pub fn new(epoch: RtcEpoch) -> Result<Self> {
        if epoch.ticks >= LIMIT {
            return Err(refuse!(
                "PMU RTC epoch exceeds the qualified 47-bit upcount"
            ));
        }
        let remaining = counter_ticks(LIMIT - epoch.ticks);
        if epoch.counter.checked_add(remaining).is_none() {
            return Err(refuse!(
                "PMU RTC epoch cannot represent its qualified counter horizon"
            ));
        }
        Ok(Self(Rc::new(Clock {
            epoch,
            sample: Cell::new(None),
            regression: Cell::new(None),
        })))
    }

    /// Check an Access.now without publishing or changing any owner.
    pub fn check(&self, now: u64) -> Result<u64> {
        if let Some(sample) = self.0.sample.get()
            && now < sample.counter
        {
            self.0.regression.set(Some((now, sample.counter)));
            return Err(refuse!("PMU RTC counter publication moved backwards"));
        }
        let elapsed = now
            .checked_sub(self.0.epoch.counter)
            .ok_or(refuse!("PMU RTC counter precedes its declared epoch"))?;
        let elapsed = u128::from(elapsed) * u128::from(RTC_HZ) / u128::from(FREQUENCY_HZ);
        let ticks = u128::from(self.0.epoch.ticks) + elapsed;
        if ticks >= u128::from(LIMIT) {
            return Err(refuse!(
                "PMU RTC upcount/alarm wrap behavior is unqualified"
            ));
        }
        Ok(ticks as u64)
    }

    /// Board service boundary publication, before ASC receive/poll effects.
    /// Refusal preserves the previous sample. This is model time ownership,
    /// never permission to execute on a host worker.
    pub fn publish(&self, now: u64) -> Result<()> {
        let ticks = self.check(now)?;
        self.0.sample.set(Some(Sample {
            counter: now,
            ticks,
        }));
        Ok(())
    }

    /// The last counter [`Self::check`] refused for moving backwards, and
    /// the publication it preceded: a diagnostic of the stop it causes.
    pub fn regression(&self) -> Option<(u64, u64)> {
        self.0.regression.get()
    }

    /// SMC reads the same published upcount. Missing publication must stop the
    /// service; it cannot be replaced with a successful zero-valued read.
    pub fn published_ticks(&self) -> Result<u64> {
        self.0
            .sample
            .get()
            .map(|sample| sample.ticks)
            .ok_or(refuse!("PMU RTC has no actual counter publication"))
    }

    /// First counter at which the oscillator reaches a tick in this epoch.
    /// None denotes a tick already elapsed before the supplied epoch.
    pub(super) fn counter_for(&self, ticks: u64) -> Option<u64> {
        if ticks >= LIMIT {
            return None;
        }
        let elapsed = ticks.checked_sub(self.0.epoch.ticks)?;
        self.0.epoch.counter.checked_add(counter_ticks(elapsed))
    }
}

fn counter_ticks(ticks: u64) -> u64 {
    (u128::from(ticks) * u128::from(FREQUENCY_HZ)).div_ceil(u128::from(RTC_HZ)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_epoch_is_shared_and_has_no_implicit_sample() {
        let clock = RtcClock::new(RtcEpoch {
            counter: 240,
            ticks: 1234,
        })
        .unwrap();
        let smc = clock.clone();
        assert!(smc.published_ticks().is_err());
        clock.publish(240 + FREQUENCY_HZ).unwrap();
        assert_eq!(smc.published_ticks(), Ok(1234 + RTC_HZ));
        assert!(clock.publish(239).is_err());
        assert!(clock.publish(240).is_err());
        assert_eq!(clock.regression(), Some((240, 240 + FREQUENCY_HZ)));
        assert_eq!(smc.published_ticks(), Ok(1234 + RTC_HZ));
        smc.publish(240 + FREQUENCY_HZ).unwrap();
        assert_eq!(clock.published_ticks(), Ok(1234 + RTC_HZ));
    }
    #[test]
    fn continuous_upcount_grows_across_boots_and_cold_without_wall_time() {
        let wall = |unix_seconds, counter| {
            Some(WallClock {
                unix_seconds,
                counter,
            })
        };
        // No wall time, or one before the base: the old cold origin.
        let cold = RtcEpoch {
            counter: 77,
            ticks: 0,
        };
        assert_eq!(RtcEpoch::continuous(77, None), cold);
        assert_eq!(RtcEpoch::continuous(77, wall(0, 77)), cold);
        assert_eq!(
            RtcEpoch::continuous(77, wall(UPCOUNT_BASE_UNIX_SECONDS - 1, 77)),
            cold
        );
        // Past the 47-bit upcount (2137): cold again, never a refusal.
        let end = UPCOUNT_BASE_UNIX_SECONDS + (LIMIT >> 15);
        assert_eq!(RtcEpoch::continuous(77, wall(end, 77)), cold);
        let last = RtcEpoch::continuous(77, wall(end - 1, 77));
        assert_eq!(last.ticks, LIMIT - RTC_HZ);
        assert!(RtcClock::new(last).is_ok());
        // A later boot, even with a smaller counter, has a larger upcount.
        let first = RtcEpoch::continuous(9 * FREQUENCY_HZ, wall(1_792_000_000, 9 * FREQUENCY_HZ));
        let second = RtcEpoch::continuous(3 * FREQUENCY_HZ, wall(1_792_000_100, 3 * FREQUENCY_HZ));
        assert_eq!(
            first.ticks,
            (1_792_000_000 - UPCOUNT_BASE_UNIX_SECONDS) * RTC_HZ
        );
        assert_eq!(second.ticks - first.ticks, 100 * RTC_HZ);
        let a = RtcClock::new(first).unwrap();
        let b = RtcClock::new(second).unwrap();
        // Late in the first boot, still below the start of the second.
        assert!(a.check(90 * FREQUENCY_HZ).unwrap() < b.check(3 * FREQUENCY_HZ).unwrap());
        // The upcount then follows real time.
        assert_eq!(
            b.check(13 * FREQUENCY_HZ).unwrap(),
            second.ticks + 10 * RTC_HZ
        );
        // A wall time sampled at another counter is carried to `now`.
        let carried = RtcEpoch::continuous(FREQUENCY_HZ, wall(1_792_000_000, 5 * FREQUENCY_HZ));
        assert_eq!(carried.ticks, first.ticks - 4 * RTC_HZ);
    }

    #[test]
    fn deadlines_round_up_and_tick_epoch_overflow_refuses_atomically() {
        let clock = RtcClock::new(RtcEpoch {
            counter: 17,
            ticks: LIMIT - 2,
        })
        .unwrap();
        assert_eq!(clock.counter_for(LIMIT - 3), None);
        assert_eq!(clock.counter_for(LIMIT - 2), Some(17));
        let deadline = clock.counter_for(LIMIT - 1).unwrap();
        assert_eq!(clock.check(deadline - 1), Ok(LIMIT - 2));
        assert_eq!(clock.check(deadline), Ok(LIMIT - 1));
        clock.publish(deadline).unwrap();
        assert!(clock.publish(17 + counter_ticks(2)).is_err());
        assert_eq!(clock.published_ticks(), Ok(LIMIT - 1));
        assert_eq!(clock.counter_for(LIMIT), None);
        assert!(
            RtcClock::new(RtcEpoch {
                counter: 0,
                ticks: LIMIT
            })
            .is_err()
        );
        assert!(
            RtcClock::new(RtcEpoch {
                counter: u64::MAX,
                ticks: 0
            })
            .is_err()
        );
    }
}
