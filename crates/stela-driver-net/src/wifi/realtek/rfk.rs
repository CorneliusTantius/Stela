// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! `rtw8822c_phy_calibration` across polls. rtw88 runs it in one go under its
//! mutex, sleeping through each wait; that holds whoever calls it for up to a
//! second, so here each poll takes one step: one look at what a wait waits
//! for, or one stretch of register work whose own waits are a few
//! milliseconds. Each wait keeps rtw88's budget as a deadline on the clock,
//! and one that runs out goes on as rtw88 goes on.
use alloc::string::String;

/// `rtw8822c_rfk_handshake`'s wait for Bluetooth's own calibration.
pub const BLUETOOTH_US: u64 = 600_000;
/// `rtw8822c_rfk_handshake`'s wait for firmware's answer.
pub const FIRMWARE_US: u64 = 100_000;
/// `rtw8822c_txgapk_read_offset`'s wait for its report.
pub const GAPK_US: u64 = 100_000;

/// The radio's side of a calibration, each method one bounded step.
pub trait Bench {
    type Gapk;
    type Iqk;
    type Dpk;
    fn now(&mut self) -> Result<u64, String>;
    /// `rtw8822c_rfk_power_save`.
    fn power_save(&mut self, on: bool) -> Result<(), String>;
    /// Bluetooth's calibration is over, or rtw88 no longer waits for it.
    fn bluetooth_idle(&mut self) -> Result<bool, String>;
    fn bluetooth_outlasted(&mut self);
    /// `rtw_fw_inform_rfk_status`.
    fn inform(&mut self, starting: bool) -> Result<(), String>;
    fn firmware_answered(&mut self) -> Result<bool, String>;
    fn firmware_unanswered(&mut self);
    fn gapk_begin(&mut self) -> Result<Option<Self::Gapk>, String>;
    fn gapk_start(&mut self, run: &mut Self::Gapk, at: usize) -> Result<(), String>;
    fn gapk_measured(&mut self) -> Result<bool, String>;
    fn gapk_finish(&mut self, run: &mut Self::Gapk, at: usize, done: bool) -> Result<(), String>;
    fn gapk_end(&mut self, run: Self::Gapk, measured: bool) -> Result<(), String>;
    fn iqk_start(&mut self) -> Result<Self::Iqk, String>;
    /// `Some(completed)` once the IQK is over; `hurry` makes this look the
    /// last.
    fn iqk_poll(&mut self, wait: &mut Self::Iqk, hurry: bool) -> Result<Option<bool>, String>;
    fn dpk_begin(&mut self) -> Result<Option<Self::Dpk>, String>;
    fn dpk_gain(&mut self, run: &mut Self::Dpk, at: usize) -> Result<(), String>;
    /// One measurement of the gain search at most: whether it is over.
    fn dpk_search(&mut self, run: &mut Self::Dpk, at: usize) -> Result<bool, String>;
    fn dpk_measure(&mut self, run: &mut Self::Dpk, at: usize) -> Result<(), String>;
    fn dpk_skip(&mut self, at: usize) -> Result<(), String>;
    fn dpk_turn_on(&mut self, at: usize) -> Result<(), String>;
    fn dpk_end(&mut self, run: Self::Dpk) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DpkStep {
    Gain(usize),
    Search(usize),
    Measure(usize),
    TurnOn(usize),
    End,
}

enum Phase<B: Bench> {
    Bluetooth {
        end: u64,
    },
    Started {
        end: u64,
    },
    Gapk {
        run: B::Gapk,
        at: usize,
        /// Set while path `at`'s measurement runs.
        end: Option<u64>,
        measured: bool,
    },
    Finished {
        end: u64,
    },
    Iqk(B::Iqk),
    Dpk {
        run: B::Dpk,
        step: DpkStep,
    },
}

/// One calibration under way.
pub struct Run<B: Bench> {
    phase: Option<Phase<B>>,
    hurried: bool,
}

/// Whether the calibration needs another step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    Running,
    /// Over; `hurried` when a step was cut short to end it.
    Done {
        hurried: bool,
    },
}

impl<B: Bench> Run<B> {
    /// `rtw8822c_rfk_power_save` off and the handshake's first look.
    pub fn start(bench: &mut B) -> Result<Self, String> {
        bench.power_save(false)?;
        let end = bench.now()?.saturating_add(BLUETOOTH_US);
        let mut run = Self {
            phase: Some(Phase::Bluetooth { end }),
            hurried: false,
        };
        run.step(bench, false)?;
        Ok(run)
    }

    /// One step. With `hurry`, each wait ends at its next look and what is
    /// left of the predistortion is skipped, so that a few steps end the run.
    pub fn step(&mut self, bench: &mut B, hurry: bool) -> Result<Progress, String> {
        self.hurried |= hurry;
        let Some(phase) = self.phase.take() else {
            return Ok(Progress::Done {
                hurried: self.hurried,
            });
        };
        let now = bench.now()?;
        self.phase = match phase {
            Phase::Bluetooth { end } => {
                if bench.bluetooth_idle()? {
                    Some(self.inform(bench, now)?)
                } else if now > end {
                    bench.bluetooth_outlasted();
                    Some(self.inform(bench, now)?)
                } else if hurry {
                    Some(self.inform(bench, now)?)
                } else {
                    Some(Phase::Bluetooth { end })
                }
            }
            Phase::Started { end } => {
                if !self.answered(bench, now, end, hurry)? {
                    Some(Phase::Started { end })
                } else if self.hurried {
                    Some(self.finish_handshake(bench, now)?)
                } else {
                    match bench.gapk_begin()? {
                        Some(run) => Some(Phase::Gapk {
                            run,
                            at: 0,
                            end: None,
                            measured: true,
                        }),
                        None => Some(self.finish_handshake(bench, now)?),
                    }
                }
            }
            Phase::Gapk { run, end: None, .. } if self.hurried => {
                bench.gapk_end(run, false)?;
                Some(self.finish_handshake(bench, now)?)
            }
            Phase::Gapk {
                mut run,
                at,
                end: None,
                measured,
            } => {
                bench.gapk_start(&mut run, at)?;
                Some(Phase::Gapk {
                    run,
                    at,
                    end: Some(now.saturating_add(GAPK_US)),
                    measured,
                })
            }
            Phase::Gapk {
                mut run,
                at,
                end: Some(end),
                measured,
            } => {
                let done = bench.gapk_measured()?;
                if done || now > end || self.hurried {
                    bench.gapk_finish(&mut run, at, done)?;
                    let measured = measured && done;
                    if at == 0 && !self.hurried {
                        Some(Phase::Gapk {
                            run,
                            at: 1,
                            end: None,
                            measured,
                        })
                    } else {
                        bench.gapk_end(run, measured && at == 1)?;
                        Some(self.finish_handshake(bench, now)?)
                    }
                } else {
                    Some(Phase::Gapk {
                        run,
                        at,
                        end: Some(end),
                        measured,
                    })
                }
            }
            Phase::Finished { end } => {
                if !self.answered(bench, now, end, hurry)? {
                    Some(Phase::Finished { end })
                } else if self.hurried {
                    None
                } else {
                    Some(Phase::Iqk(bench.iqk_start()?))
                }
            }
            Phase::Iqk(mut wait) => match bench.iqk_poll(&mut wait, self.hurried)? {
                None => Some(Phase::Iqk(wait)),
                Some(_) if self.hurried => None,
                Some(_) => bench.dpk_begin()?.map(|run| Phase::Dpk {
                    run,
                    step: DpkStep::Gain(0),
                }),
            },
            Phase::Dpk { mut run, step } => {
                let next = match step {
                    DpkStep::Gain(at) | DpkStep::Search(at) | DpkStep::Measure(at)
                        if self.hurried =>
                    {
                        bench.dpk_skip(at)?;
                        if at == 0 {
                            bench.dpk_skip(1)?;
                        }
                        DpkStep::TurnOn(0)
                    }
                    DpkStep::Gain(at) => {
                        bench.dpk_gain(&mut run, at)?;
                        DpkStep::Search(at)
                    }
                    DpkStep::Search(at) => {
                        if bench.dpk_search(&mut run, at)? {
                            DpkStep::Measure(at)
                        } else {
                            DpkStep::Search(at)
                        }
                    }
                    DpkStep::Measure(at) => {
                        bench.dpk_measure(&mut run, at)?;
                        if at == 0 {
                            DpkStep::Gain(1)
                        } else {
                            DpkStep::TurnOn(0)
                        }
                    }
                    DpkStep::TurnOn(at) => {
                        bench.dpk_turn_on(at)?;
                        if at == 0 {
                            DpkStep::TurnOn(1)
                        } else {
                            DpkStep::End
                        }
                    }
                    DpkStep::End => {
                        bench.dpk_end(run)?;
                        return self.done(bench);
                    }
                };
                Some(Phase::Dpk { run, step: next })
            }
        };
        if self.phase.is_none() {
            return self.done(bench);
        }
        Ok(Progress::Running)
    }

    /// The start notice, and the wait for its answer.
    fn inform(&mut self, bench: &mut B, now: u64) -> Result<Phase<B>, String> {
        bench.inform(true)?;
        Ok(Phase::Started {
            end: now.saturating_add(FIRMWARE_US),
        })
    }

    /// The end notice, and the wait for its answer.
    fn finish_handshake(&mut self, bench: &mut B, now: u64) -> Result<Phase<B>, String> {
        bench.inform(false)?;
        Ok(Phase::Finished {
            end: now.saturating_add(FIRMWARE_US),
        })
    }

    /// Whether the wait for firmware's answer is over.
    fn answered(&mut self, bench: &mut B, now: u64, end: u64, hurry: bool) -> Result<bool, String> {
        if bench.firmware_answered()? {
            return Ok(true);
        }
        if now > end {
            bench.firmware_unanswered();
            return Ok(true);
        }
        Ok(hurry)
    }

    fn done(&mut self, bench: &mut B) -> Result<Progress, String> {
        self.phase = None;
        bench.power_save(true)?;
        Ok(Progress::Done {
            hurried: self.hurried,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec::Vec};

    /// A radio whose waits end at set times, and the steps it was given.
    #[derive(Default)]
    struct Radio {
        now: u64,
        bluetooth_at: u64,
        firmware_at: [u64; 2],
        informed: usize,
        gapk_at: u64,
        iqk_at: u64,
        iqk_end: u64,
        searches: u32,
        dpk_learned: bool,
        calls: Vec<String>,
    }

    impl Radio {
        fn log(&mut self, call: &str) {
            self.calls.push(String::from(call));
        }
    }

    impl Bench for Radio {
        type Gapk = ();
        type Iqk = ();
        type Dpk = u32;
        fn now(&mut self) -> Result<u64, String> {
            Ok(self.now)
        }
        fn power_save(&mut self, on: bool) -> Result<(), String> {
            self.log(if on {
                "power save on"
            } else {
                "power save off"
            });
            Ok(())
        }
        fn bluetooth_idle(&mut self) -> Result<bool, String> {
            Ok(self.now >= self.bluetooth_at)
        }
        fn bluetooth_outlasted(&mut self) {
            self.log("bluetooth outlasted");
        }
        fn inform(&mut self, starting: bool) -> Result<(), String> {
            self.informed += 1;
            self.log(if starting { "start" } else { "end" });
            Ok(())
        }
        fn firmware_answered(&mut self) -> Result<bool, String> {
            Ok(self.now >= self.firmware_at[self.informed - 1])
        }
        fn firmware_unanswered(&mut self) {
            self.log("unanswered");
        }
        fn gapk_begin(&mut self) -> Result<Option<()>, String> {
            self.log("gapk");
            Ok(Some(()))
        }
        fn gapk_start(&mut self, _: &mut (), at: usize) -> Result<(), String> {
            self.calls.push(format!("gapk {at}"));
            Ok(())
        }
        fn gapk_measured(&mut self) -> Result<bool, String> {
            Ok(self.now >= self.gapk_at)
        }
        fn gapk_finish(&mut self, _: &mut (), at: usize, done: bool) -> Result<(), String> {
            self.calls.push(format!("gapk {at} done {done}"));
            Ok(())
        }
        fn gapk_end(&mut self, _: (), measured: bool) -> Result<(), String> {
            self.calls.push(format!("gapk end {measured}"));
            Ok(())
        }
        fn iqk_start(&mut self) -> Result<(), String> {
            // Control's own 300 ms.
            self.iqk_end = self.now + 300_000;
            self.log("iqk");
            Ok(())
        }
        fn iqk_poll(&mut self, _: &mut (), hurry: bool) -> Result<Option<bool>, String> {
            let done = self.now >= self.iqk_at;
            Ok((done || hurry || self.now > self.iqk_end).then_some(done))
        }
        fn dpk_begin(&mut self) -> Result<Option<u32>, String> {
            self.log("dpk");
            Ok((!self.dpk_learned).then_some(0))
        }
        fn dpk_gain(&mut self, run: &mut u32, at: usize) -> Result<(), String> {
            *run = 0;
            self.calls.push(format!("dpk {at}"));
            Ok(())
        }
        fn dpk_search(&mut self, run: &mut u32, _: usize) -> Result<bool, String> {
            *run += 1;
            Ok(*run >= self.searches)
        }
        fn dpk_measure(&mut self, _: &mut u32, at: usize) -> Result<(), String> {
            self.calls.push(format!("dpk {at} measured"));
            Ok(())
        }
        fn dpk_skip(&mut self, at: usize) -> Result<(), String> {
            self.calls.push(format!("dpk {at} skipped"));
            Ok(())
        }
        fn dpk_turn_on(&mut self, at: usize) -> Result<(), String> {
            self.calls.push(format!("dpk {at} on"));
            Ok(())
        }
        fn dpk_end(&mut self, _: u32) -> Result<(), String> {
            self.log("dpk end");
            Ok(())
        }
    }

    /// Step `run` every `period` until it ends: the steps it took.
    fn drive(radio: &mut Radio, run: &mut Run<Radio>, period: u64) -> (usize, bool) {
        for steps in 1..10_000 {
            radio.now += period;
            if let Progress::Done { hurried } = run.step(radio, false).unwrap() {
                return (steps, hurried);
            }
        }
        panic!("the run never ended");
    }

    #[test]
    fn each_wait_is_one_look_a_step_and_the_run_keeps_rtw88s_order() {
        let mut radio = Radio {
            bluetooth_at: 3_000,
            firmware_at: [5_000, 70_000],
            gapk_at: 30_000,
            iqk_at: 260_000,
            searches: 3,
            ..Radio::default()
        };
        let mut run = Run::start(&mut radio).unwrap();
        assert_eq!(
            radio.calls,
            ["power save off"],
            "Bluetooth still calibrates"
        );
        let (steps, hurried) = drive(&mut radio, &mut run, 1_000);
        assert!(!hurried);
        assert!(steps > 250, "the IQK's 260 ms took one look a step");
        assert_eq!(
            radio.calls,
            [
                "power save off",
                "start",
                "gapk",
                "gapk 0",
                "gapk 0 done true",
                "gapk 1",
                "gapk 1 done true",
                "gapk end true",
                "end",
                "iqk",
                "dpk",
                "dpk 0",
                "dpk 0 measured",
                "dpk 1",
                "dpk 1 measured",
                "dpk 0 on",
                "dpk 1 on",
                "dpk end",
                "power save on",
            ]
        );
        assert_eq!(
            run.step(&mut radio, false),
            Ok(Progress::Done { hurried: false })
        );
    }

    #[test]
    fn a_wait_that_runs_out_goes_on_as_rtw88_goes_on() {
        let mut radio = Radio {
            bluetooth_at: u64::MAX,
            firmware_at: [u64::MAX; 2],
            gapk_at: u64::MAX,
            iqk_at: u64::MAX,
            searches: 1,
            dpk_learned: true,
            ..Radio::default()
        };
        let mut run = Run::start(&mut radio).unwrap();
        drive(&mut radio, &mut run, 10_000);
        assert_eq!(
            radio.calls,
            [
                "power save off",
                "bluetooth outlasted",
                "start",
                "unanswered",
                "gapk",
                "gapk 0",
                "gapk 0 done false",
                "gapk 1",
                "gapk 1 done false",
                "gapk end false",
                "end",
                "unanswered",
                "iqk",
                "dpk",
                "power save on",
            ]
        );
        // Bluetooth's wait ran its 600 ms, the others theirs, and no more.
        assert!(radio.now <= 610_000 + 2 * 110_000 + 2 * 110_000 + 310_000 + 50_000);
    }

    #[test]
    fn a_hurried_run_ends_in_a_few_steps_with_predistortion_left_flat() {
        for at_step in 0..40 {
            let mut radio = Radio {
                bluetooth_at: 2_000,
                firmware_at: [4_000, 40_000],
                gapk_at: 20_000,
                iqk_at: 200_000,
                searches: 2,
                ..Radio::default()
            };
            let mut run = Run::start(&mut radio).unwrap();
            let mut ended = false;
            for _ in 0..at_step * 10 {
                radio.now += 1_000;
                if let Progress::Done { .. } = run.step(&mut radio, false).unwrap() {
                    ended = true;
                    break;
                }
            }
            if ended {
                continue;
            }
            let mut steps = 0;
            let hurried = loop {
                steps += 1;
                if let Progress::Done { hurried } = run.step(&mut radio, true).unwrap() {
                    break hurried;
                }
            };
            assert!(hurried);
            assert!(steps <= 6, "{steps} steps after step {}", at_step * 10);
            assert_eq!(radio.calls.last().unwrap(), "power save on");
            let started = radio.calls.iter().filter(|c| *c == "start").count();
            let ended = radio.calls.iter().filter(|c| *c == "end").count();
            assert_eq!(started, ended, "every start notice has its end");
            if radio.calls.iter().any(|c| c == "dpk 0") {
                assert!(radio.calls.iter().any(|c| c == "dpk end"));
            }
        }
    }
}
