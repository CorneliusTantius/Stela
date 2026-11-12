// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Deep power save beneath leisure power save: what `rtw_power_mode_change` and
//! `rtw_pci_deep_ps` ask of firmware. Only the bus's own registers answer down
//! here, so whatever else reaches for the radio leaves first.
use super::io::{Error, Io};

/// `FW_FEATURE_LCLK`, `FW_FEATURE_PG` and `FW_FEATURE_TX_WAKE`.
const LOW_CLOCK_FEATURE: u32 = 1 << 2;
const POWER_GATE_FEATURE: u32 = 1 << 3;
const TRANSMIT_WAKE_FEATURE: u32 = 1 << 4;
/// `hci.rpwm_addr` and `hci.cpwm_addr`.
const REQUEST: u32 = 0x3d9;
const CONFIRM: u32 = 0x3da;
/// `BIT_RPWM_TOGGLE`, `POWER_MODE_ACK`, `POWER_MODE_PG`, `POWER_TX_WAKE` and
/// `POWER_MODE_LCLK`.
const TOGGLE: u8 = 1 << 7;
const ACK: u8 = 1 << 6;
const POWER_GATE: u8 = 1 << 4;
const TRANSMIT_WAKE: u8 = 1 << 1;
const LOW_CLOCK: u8 = 1 << 0;
/// The 15 ms firmware has to answer, in looks 100 us apart.
const CONFIRM_TRIES: u32 = 150;
const CONFIRM_WAIT_US: u64 = 100;

/// `enum rtw_lps_deep_mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    LowClock,
    PowerGate,
}

/// `RTW_FLAG_LEISURE_PS_DEEP`, under firmware's `lps_conf.deep_mode`.
#[derive(Debug)]
pub struct Deep {
    /// Gone once firmware has failed to answer.
    mode: Option<Mode>,
    transmit_wakes: bool,
    active: bool,
}

impl Deep {
    /// `rtw_update_lps_deep_mode` of `fw->feature`, with no mode where `allowed`
    /// is false, as under `rtw_disable_lps_deep_mode`. Power gating also needs
    /// a chip that supports it (`power_gate`, its `lps_deep_mode_supported`).
    pub fn new(features: u32, allowed: bool, power_gate: bool) -> Self {
        let mode = if !allowed {
            None
        } else if power_gate && features & POWER_GATE_FEATURE != 0 {
            Some(Mode::PowerGate)
        } else if features & LOW_CLOCK_FEATURE != 0 {
            Some(Mode::LowClock)
        } else {
            None
        };
        Self {
            mode,
            transmit_wakes: features & TRANSMIT_WAKE_FEATURE != 0,
            active: false,
        }
    }

    pub fn available(&self) -> bool {
        self.mode.is_some()
    }

    pub fn gates_power(&self) -> bool {
        self.mode == Some(Mode::PowerGate)
    }

    pub fn active(&self) -> bool {
        self.active
    }

    /// `FW_FEATURE_TX_WAKE`: kicking a ring wakes the chip by itself.
    pub fn transmit_wakes(&self) -> bool {
        self.transmit_wakes
    }

    /// `rtw_pci_deep_ps_enter`, with the rings already known to allow it. False
    /// the first time firmware fails to answer.
    pub fn enter<I: Io>(&mut self, io: &mut I) -> Result<bool, Error> {
        if self.active || self.mode.is_none() {
            return Ok(true);
        }
        self.active = true;
        self.change(io, true)
    }

    /// `rtw_pci_deep_ps_leave`. False the first time firmware fails to answer.
    pub fn leave<I: Io>(&mut self, io: &mut I) -> Result<bool, Error> {
        if !core::mem::take(&mut self.active) {
            return Ok(true);
        }
        self.change(io, false)
    }

    /// `rtw_power_mode_change`. rtw88 takes a request nobody answers for a
    /// fatal fault and carries on; here deep power save ends with it, leisure
    /// power save stands, and each later step tries the registers as it finds
    /// them.
    fn change<I: Io>(&mut self, io: &mut I, enter: bool) -> Result<bool, Error> {
        let request = io.read8(REQUEST)?;
        let confirm = io.read8(CONFIRM)?;
        let mut next = (!request & TOGGLE) | ACK;
        if enter {
            next |= LOW_CLOCK;
            if self.gates_power() {
                next |= POWER_GATE;
            }
        }
        if self.transmit_wakes {
            next |= TRANSMIT_WAKE;
        }
        io.write8(REQUEST, next)?;
        for _ in 0..CONFIRM_TRIES {
            io.delay_us(CONFIRM_WAIT_US);
            if (io.read8(CONFIRM)? ^ confirm) & TOGGLE != 0 {
                return Ok(true);
            }
        }
        Ok(self.mode.take().is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::realtek::{
        identity::{Profile, tests::profile},
        io,
    };

    /// Firmware's two registers, with the requests it was sent.
    #[derive(Default)]
    struct Bus {
        request: u8,
        confirm: u8,
        requests: alloc::vec::Vec<u8>,
        silent: bool,
    }

    // SAFETY: nothing here reaches hardware; this is two bytes.
    unsafe impl Io for Bus {
        fn profile(&self) -> Profile {
            profile()
        }
        fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
            Ok(if register == REQUEST {
                self.request
            } else {
                self.confirm
            })
        }
        fn read16(&mut self, _: u32) -> Result<u16, io::Error> {
            Ok(0)
        }
        fn read32(&mut self, _: u32) -> Result<u32, io::Error> {
            Ok(0)
        }
        fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
            assert_eq!(register, REQUEST);
            self.request = value;
            self.requests.push(value);
            if !self.silent {
                self.confirm ^= TOGGLE;
            }
            Ok(())
        }
        fn write16(&mut self, _: u32, _: u16) -> Result<(), io::Error> {
            Ok(())
        }
        fn write32(&mut self, _: u32, _: u32) -> Result<(), io::Error> {
            Ok(())
        }
        fn delay_us(&mut self, _: u64) {}
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
            Ok(())
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            Ok(())
        }
        fn quarantine(&mut self) {}
    }

    #[test]
    fn firmware_without_either_feature_offers_nothing() {
        let mut bus = Bus::default();
        let mut deep = Deep::new(TRANSMIT_WAKE_FEATURE, true, true);
        assert!(!deep.available());
        assert!(deep.enter(&mut bus).unwrap());
        assert!(!deep.active());
        assert!(bus.requests.is_empty());
    }

    #[test]
    fn power_gating_wins_over_the_low_clock() {
        assert!(Deep::new(LOW_CLOCK_FEATURE | POWER_GATE_FEATURE, true, true).gates_power());
        // A chip that only lowers its clock takes the low clock.
        let chip = Deep::new(LOW_CLOCK_FEATURE | POWER_GATE_FEATURE, true, false);
        assert!(chip.available() && !chip.gates_power());
        let low = Deep::new(LOW_CLOCK_FEATURE, true, true);
        assert!(low.available() && !low.gates_power());
    }

    #[test]
    fn a_system_with_deep_power_save_disabled_has_no_mode_but_keeps_transmit_wake() {
        let mut deep = Deep::new(
            LOW_CLOCK_FEATURE | POWER_GATE_FEATURE | TRANSMIT_WAKE_FEATURE,
            false,
            true,
        );
        assert!(!deep.available() && deep.transmit_wakes());
        let mut bus = Bus::default();
        assert_eq!(deep.enter(&mut bus), Ok(true));
        assert!(!deep.active() && bus.requests.is_empty());
    }

    #[test]
    fn each_request_toggles_and_asks_for_an_answer() {
        let mut bus = Bus::default();
        let mut deep = Deep::new(LOW_CLOCK_FEATURE, true, true);
        assert!(deep.enter(&mut bus).unwrap());
        assert!(deep.active());
        assert!(deep.leave(&mut bus).unwrap());
        assert!(!deep.active());
        assert_eq!(
            bus.requests,
            [TOGGLE | ACK | LOW_CLOCK, ACK],
            "the toggle flips and no other bit survives"
        );
    }

    #[test]
    fn a_power_gate_says_so_going_in_and_not_coming_out() {
        let mut bus = Bus::default();
        let mut deep = Deep::new(POWER_GATE_FEATURE | TRANSMIT_WAKE_FEATURE, true, true);
        deep.enter(&mut bus).unwrap();
        deep.leave(&mut bus).unwrap();
        assert_eq!(
            bus.requests,
            [
                TOGGLE | ACK | LOW_CLOCK | POWER_GATE | TRANSMIT_WAKE,
                ACK | TRANSMIT_WAKE,
            ]
        );
    }

    #[test]
    fn standing_in_either_state_asks_for_nothing() {
        let mut bus = Bus::default();
        let mut deep = Deep::new(LOW_CLOCK_FEATURE, true, true);
        deep.leave(&mut bus).unwrap();
        deep.enter(&mut bus).unwrap();
        deep.enter(&mut bus).unwrap();
        assert_eq!(bus.requests.len(), 1);
    }

    #[test]
    fn firmware_that_stays_silent_ends_deep_power_save_with_one_report() {
        let mut bus = Bus {
            silent: true,
            ..Bus::default()
        };
        let mut deep = Deep::new(LOW_CLOCK_FEATURE, true, true);
        assert!(!deep.enter(&mut bus).unwrap());
        assert!(deep.active(), "the request stands until it is taken back");
        assert!(deep.leave(&mut bus).unwrap(), "already reported");
        assert!(!deep.active() && !deep.available());
        assert!(deep.enter(&mut bus).unwrap());
        assert!(!deep.active());
        assert_eq!(bus.requests.len(), 2);
    }
}
