// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! The cases of `rtw_coex_run_coex`: which antenna path, RF levels, PTA table
//! and time slots each state of the two radios takes. rtw88 never updates
//! `wl_rx_rate` from its first 5.5 Mb/s, which these cases read accordingly.
use super::{
    Coex,
    bluetooth::Status,
    tables::{RECEIVE_RF, RfLevels},
};

/// `coex_set_ant_phase` of a run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    TwoGhz,
    FiveGhz,
    Freerun,
}

/// What an action of `rtw_coex_run_coex` settles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Plan {
    pub phase: Phase,
    pub rf: RfLevels,
    pub table: u8,
    pub tdma: u8,
    /// `TDMA_4SLOT`.
    pub four_slot: bool,
    /// `rtw_btc_wltoggle_table_a` and `_b`, at this interval.
    pub toggle: Option<u8>,
    /// `rtw_coex_action_freerun`.
    pub freerun: bool,
    /// `COEX_WLINK_2GFREE`.
    pub free: bool,
}

/// The normal `wl_rf_para_rx[0]`.
const NORMAL_RF: RfLevels = RECEIVE_RF[0];

impl Plan {
    fn new(table: u8, tdma: u8) -> Self {
        Self {
            phase: Phase::TwoGhz,
            rf: NORMAL_RF,
            table,
            tdma,
            four_slot: false,
            toggle: None,
            freerun: false,
            free: false,
        }
    }

    fn four_slot(mut self) -> Self {
        self.four_slot = true;
        self
    }

    fn slotted(mut self, four: bool) -> Self {
        self.four_slot = four;
        self
    }

    fn toggled(mut self, toggle: Option<u8>) -> Self {
        self.toggle = toggle;
        self
    }

    /// `COEX_WLINK_2GFREE` at `rf`.
    fn free(mut self, rf: RfLevels) -> Self {
        self.free = true;
        self.rf = rf;
        self
    }
}

impl Coex {
    /// The body of `rtw_coex_run_coex` past its Pure-5G case.
    pub(super) fn plan(&self) -> Plan {
        let bluetooth = &self.bluetooth;
        if self.bluetooth_disabled {
            return if self.connected {
                self.action_wifi_only()
            } else {
                self.action_not_connected()
            };
        }
        if self.sleeping && !self.stays_awake {
            return self.action_native_sleep();
        }
        if bluetooth.game_controller && self.connected {
            return self.action_game_controller();
        }
        if bluetooth.certification {
            return self.action_wifi_only();
        }
        if bluetooth.setting_up {
            return self.action_relink();
        }
        if bluetooth.inquiring {
            return self.action_inquiry();
        }
        let idle = matches!(
            bluetooth.status,
            Status::NotConnectedIdle | Status::ConnectedIdle
        );
        if idle && self.connected {
            return self.action_idle();
        }
        if self.linkscan {
            return self.action_linkscan();
        }
        if self.connected {
            self.action_connected()
        } else {
            self.action_not_connected()
        }
    }

    /// `rtw_coex_action_wl_only` and `rtw_coex_action_bt_whql_test`.
    fn action_wifi_only(&self) -> Plan {
        if self.shared {
            Plan::new(2, 0)
        } else {
            Plan::new(100, 100)
        }
    }

    /// `rtw_coex_action_wl_not_connected`.
    fn action_not_connected(&self) -> Plan {
        if self.shared {
            Plan::new(1, 0)
        } else {
            Plan::new(100, 100)
        }
    }

    /// `rtw_coex_action_wl_native_lps`.
    fn action_native_sleep(&self) -> Plan {
        let plan = if self.shared {
            Plan::new(28, 0)
        } else {
            Plan::new(100, 100)
        };
        if self.bluetooth.game_controller {
            plan.free(self.free_rf())
        } else {
            plan
        }
    }

    /// `wl_rf_para_tx[6]` or `wl_rf_para_rx[5]`, for a controller's sake.
    fn free_rf(&self) -> RfLevels {
        if self.transmitting {
            self.rf_level(true, 6)
        } else {
            self.rf_level(false, 5)
        }
    }

    /// `rtw_coex_action_bt_game_hid`.
    fn action_game_controller(&self) -> Plan {
        let bluetooth = &self.bluetooth;
        if !self.shared {
            return Plan::new(121, if self.rssi_high[1] { 112 } else { 113 });
        }
        let table = if bluetooth.certification {
            2
        } else if self.linkscan || bluetooth.hid {
            33
        } else if bluetooth.setting_up || bluetooth.inquiring {
            0
        } else if bluetooth.a2dp {
            34
        } else {
            33
        };
        Plan::new(table, 0).free(self.free_rf())
    }

    /// `rtw_coex_action_bt_relink`.
    fn action_relink(&self) -> Plan {
        let bluetooth = &self.bluetooth;
        match (self.shared, self.busy) {
            (true, true) => Plan::new(26, 20).slotted(bluetooth.hid && bluetooth.profiles == 1),
            (true, false) => Plan::new(1, 0),
            (false, true) => Plan::new(115, 100),
            (false, false) => Plan::new(100, 100),
        }
    }

    /// `rtw_coex_action_bt_idle`, with no antenna switch to share.
    fn action_idle(&self) -> Plan {
        let bluetooth = &self.bluetooth;
        let idle = bluetooth.status == Status::NotConnectedIdle;
        if self.shared {
            if !self.busy {
                Plan::new(10, 3)
            } else if idle {
                let low_priority = self.counters.low_rx + self.counters.low_tx;
                Plan::new(11, if low_priority > 250 { 17 } else { 7 })
            } else {
                Plan::new(12, 7)
            }
        } else if !self.busy {
            Plan::new(112, 104)
        } else if bluetooth.scan_type & 2 != 0 && idle {
            Plan::new(114, 103)
        } else {
            Plan::new(112, 103)
        }
    }

    /// `rtw_coex_action_bt_inquiry`.
    fn action_inquiry(&self) -> Plan {
        let bluetooth = &self.bluetooth;
        let hurried = self.linkscan || self.connecting_task || self.scanning_task;
        let tdma = |base: u8| {
            base + if bluetooth.profiles > 0 {
                10
            } else if self.connecting_task {
                6
            } else if !bluetooth.paging {
                8
            } else {
                9
            }
        };
        if self.shared {
            if hurried {
                Plan::new(15, tdma(0))
            } else if self.busy {
                match bluetooth.profiles {
                    0 => Plan::new(12, 18),
                    1 if !bluetooth.a2dp => Plan::new(12, 20).four_slot(),
                    _ => Plan::new(12, 26).four_slot(),
                }
            } else if self.connected {
                Plan::new(9, 27)
            } else {
                Plan::new(1, 0)
            }
        } else if hurried {
            Plan::new(114, tdma(100))
        } else if self.busy {
            Plan::new(114, 121)
        } else {
            Plan::new(101, 100)
        }
    }

    /// `rtw_coex_action_bt_hfp`.
    fn action_hfp(&self) -> Plan {
        if self.shared {
            Plan::new(10, 5)
        } else if self.bluetooth.multi_link {
            Plan::new(112, 117)
        } else {
            Plan::new(105, 100)
        }
    }

    /// `rtw_coex_action_bt_hid`.
    fn action_hid(&self) -> Plan {
        let bluetooth = &self.bluetooth;
        let counters = &self.counters;
        let crowded = counters.trustworthy && counters.low_rx + counters.low_tx > 360;
        if self.shared {
            if bluetooth.low_energy {
                if self.scanned {
                    Plan::new(26, 2)
                } else {
                    Plan::new(27, 9)
                }
            } else if bluetooth.a2dp_active {
                Plan::new(9, 18)
            } else if bluetooth.profiles == 1
                && bluetooth.multi_link
                && (crowded || bluetooth.slave || bluetooth.multi_link_remains)
            {
                Plan::new(if self.busy { 13 } else { 12 }, 26)
            } else if bluetooth.hid_418 && self.busy {
                Plan::new(32, 27).four_slot().toggled(Some(1))
            } else if bluetooth.low_energy_hid && self.busy {
                Plan::new(36, 0)
            } else {
                Plan::new(9, 9)
            }
        } else if bluetooth.low_energy {
            if self.scanned {
                Plan::new(121, 102)
            } else {
                Plan::new(122, 109)
            }
        } else if bluetooth.a2dp_active {
            Plan::new(113, 118)
        } else {
            Plan::new(113, 104)
        }
    }

    /// `rtw_coex_action_bt_a2dp`.
    fn action_a2dp(&self) -> Plan {
        if self.shared {
            let table = if self.busy && self.noise == 0 { 12 } else { 9 };
            let tdma = if self.connecting || !self.busy {
                14
            } else {
                13
            };
            Plan::new(table, tdma).four_slot()
        } else {
            let tdma = if self.rssi_high[1] { 112 } else { 113 };
            Plan::new(112, tdma).four_slot()
        }
    }

    /// `rtw_coex_action_bt_a2dpsink`.
    fn action_a2dp_sink(&self) -> Plan {
        if self.shared {
            Plan::new(28, if self.busy { 20 } else { 26 })
        } else {
            Plan::new(119, 120)
        }
    }

    /// `rtw_coex_action_bt_pan`.
    fn action_pan(&self) -> Plan {
        if self.shared {
            let table = if self.busy && self.noise == 0 { 14 } else { 10 };
            Plan::new(table, if self.busy { 17 } else { 20 })
        } else {
            Plan::new(112, if self.busy { 117 } else { 119 })
        }
    }

    /// `rtw_coex_action_bt_a2dp_hid`.
    fn action_a2dp_hid(&self) -> Plan {
        let bluetooth = &self.bluetooth;
        if self.shared {
            let table = if bluetooth.low_energy { 26 } else { 9 };
            let interval = u8::from(!bluetooth.low_energy);
            if self.connecting || !self.busy {
                Plan::new(table, 14).four_slot()
            } else if bluetooth.hid_418 {
                Plan::new(table, 23).four_slot().toggled(Some(interval))
            } else {
                Plan::new(table, 13).four_slot()
            }
        } else {
            let table = if bluetooth.low_energy { 121 } else { 113 };
            let tdma = if self.rssi_high[1] { 112 } else { 113 };
            Plan::new(table, tdma).four_slot()
        }
    }

    /// `rtw_coex_action_bt_a2dp_pan`.
    fn action_a2dp_pan(&self) -> Plan {
        if self.shared {
            let table = if self.busy && self.noise == 0 { 14 } else { 10 };
            Plan::new(table, if self.busy { 15 } else { 20 })
        } else {
            Plan::new(112, if self.busy { 115 } else { 120 })
        }
    }

    /// `rtw_coex_action_bt_pan_hid`.
    fn action_pan_hid(&self) -> Plan {
        if self.shared {
            Plan::new(9, if self.busy { 18 } else { 19 })
        } else {
            Plan::new(113, if self.busy { 117 } else { 119 })
        }
    }

    /// `rtw_coex_action_bt_a2dp_pan_hid`.
    fn action_a2dp_pan_hid(&self) -> Plan {
        if self.shared {
            Plan::new(10, if self.busy { 15 } else { 20 })
        } else {
            Plan::new(113, if self.busy { 115 } else { 120 })
        }
    }

    /// `rtw_coex_freerun_check`: the separate antennas of `ant_distance` 10.
    fn runs_free(&self) -> bool {
        let bluetooth = &self.bluetooth;
        if self.bluetooth_disabled || self.shared || !self.busy {
            return false;
        }
        if bluetooth.hid_pairs >= 2 {
            return true;
        }
        if self.rssi_high[1] && bluetooth.rssi_high[0] {
            return true;
        }
        let bluetooth_high = bluetooth.rssi_high[usize::from(!self.transmitting)];
        self.rssi_high[3] && bluetooth_high && !self.scanned
    }

    /// `rtw_coex_action_freerun`.
    fn action_freerun(&self) -> Plan {
        let level = if self.rssi_high[0] {
            2
        } else if self.rssi_high[1] {
            3
        } else if self.rssi_high[2] {
            4
        } else {
            5
        };
        Plan {
            phase: Phase::Freerun,
            rf: self.rf_level(self.transmitting, level),
            freerun: true,
            ..Plan::new(100, 100)
        }
    }

    /// `rtw_coex_action_wl_linkscan`.
    fn action_linkscan(&self) -> Plan {
        let a2dp = self.bluetooth.a2dp;
        match (self.shared, a2dp) {
            (true, true) => Plan::new(if self.busy { 26 } else { 9 }, 11).four_slot(),
            (true, false) => Plan::new(9, 7),
            (false, true) => Plan::new(112, 111).four_slot(),
            (false, false) => Plan::new(112, 107),
        }
    }

    /// `rtw_coex_action_wl_connected` over `rtw_coex_algorithm`.
    fn action_connected(&self) -> Plan {
        let bluetooth = &self.bluetooth;
        let profile = (bluetooth.hfp, bluetooth.hid, bluetooth.a2dp, bluetooth.pan);
        let free = self.runs_free();
        match profile {
            (true, false, false, false) => self.action_hfp(),
            (_, true, false, false) if free => self.action_freerun(),
            (_, true, false, false) => self.action_hid(),
            (false, false, true, false) if bluetooth.multi_link => {
                if bluetooth.hid_pairs > 0 {
                    self.a2dp_hid(free)
                } else {
                    self.action_a2dp_pan()
                }
            }
            (false, false, true, false) if free => self.action_freerun(),
            (false, false, true, false) if bluetooth.a2dp_sink => self.action_a2dp_sink(),
            (false, false, true, false) => self.action_a2dp(),
            (hfp, hid, true, false) if hfp || hid => self.a2dp_hid(free),
            (false, false, false, true) => self.action_pan(),
            (false, false, true, true) => self.action_a2dp_pan(),
            (hfp, hid, false, true) if hfp || hid => self.action_pan_hid(),
            (hfp, hid, true, true) if hfp || hid => self.action_a2dp_pan_hid(),
            _ => self.action_idle(),
        }
    }

    /// `COEX_ALGO_A2DP_HID` of `rtw_coex_action_wl_connected`.
    fn a2dp_hid(&self, free: bool) -> Plan {
        if free {
            self.action_freerun()
        } else {
            self.action_a2dp_hid()
        }
    }
}
