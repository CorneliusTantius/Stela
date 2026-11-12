// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! What firmware says of the Bluetooth half: `rtw_coex_bt_info_notify` and
//! `rtw_coex_update_bt_link_info`.
use super::tables::{BluetoothFacts, RSSI_TOLERANCE};

/// `COEX_BTINFO_LENGTH`.
const INFO_LENGTH: usize = 7;
/// `COEX_INFO_*`.
const INFO_CONNECTION: u8 = 1 << 0;
const INFO_SCO_ESCO: u8 = 1 << 1;
const INFO_INQ_PAGE: u8 = 1 << 2;
const INFO_ACL_BUSY: u8 = 1 << 3;
const INFO_SCO_BUSY: u8 = 1 << 4;
const INFO_HID: u8 = 1 << 5;
const INFO_A2DP: u8 = 1 << 6;
const INFO_FTP: u8 = 1 << 7;

/// `COEX_BT_GAMEHID_CNT`.
const HID_TRAFFIC: u32 = 800;
/// `COEX_BT_HIDINFO_LIST` and `COEX_BT_HIDINFO_A`.
pub(super) const HID_LIST: u8 = 0;
pub(super) const HID_DEVICE: u8 = 1;
/// `COEX_BT_HIDINFO_NOTCON` and `COEX_BT_BLE_HANDLE_THRS`.
const HANDLE_NOT_CONNECTED: u8 = 0xff;
const HANDLE_LOW_ENERGY: u8 = 0x10;
/// `COEX_BT_HIDINFO_MTK`, and the names of `coex_bt_hidinfo_ps` and
/// `coex_bt_hidinfo_xb`.
const VENDOR_MEDIATEK: u8 = 0x46;
const GAME_NAMES: [[u8; 3]; 2] = [[0x57, 0x69, 0x72], [0x58, 0x62, 0x6f]];

/// A `rtw_coex_hid`.
#[derive(Clone, Copy, Debug, Default)]
struct HidDevice {
    handle: u8,
    vendor: u8,
    name: [u8; 3],
    complete: bool,
}

impl HidDevice {
    fn classic(&self) -> bool {
        self.handle != 0 && self.handle != HANDLE_NOT_CONNECTED && self.handle < HANDLE_LOW_ENERGY
    }

    /// What of `rtw_coex_bt_hid_info_notify` says a game is on the end of it.
    fn game(&self) -> bool {
        self.complete
            && self.classic()
            && self.vendor == VENDOR_MEDIATEK
            && GAME_NAMES.contains(&self.name)
    }
}

/// `hid_handle_list` and `hid_info`.
#[derive(Debug, Default)]
pub(super) struct HidDevices {
    list: [u8; 8],
    devices: [HidDevice; 4],
}

impl HidDevices {
    /// `rtw_coex_bt_hid_info_notify` of what firmware sent. None means
    /// nothing changed; otherwise whether a game controller is connected.
    pub fn report(&mut self, bytes: [u8; 8]) -> Option<bool> {
        match bytes[2] {
            HID_LIST => {
                if bytes == self.list {
                    return None;
                }
                self.list = bytes;
                self.devices = Default::default();
                for (device, &handle) in self.devices.iter_mut().zip(&bytes[4..]) {
                    if handle != HANDLE_NOT_CONNECTED {
                        device.handle = handle;
                    }
                }
            }
            HID_DEVICE => {
                if let Some(device) = self.devices.iter_mut().find(|d| d.handle == bytes[3]) {
                    device.vendor = bytes[4];
                    device.name = [bytes[5], bytes[6], bytes[7]];
                    device.complete = true;
                }
            }
            _ => {}
        }
        Some(self.devices.iter().any(HidDevice::game))
    }

    /// The handles rtw88 still asks about.
    pub fn unknown(&self) -> impl Iterator<Item = u8> + '_ {
        self.devices
            .iter()
            .filter(|device| device.classic() && !device.complete)
            .map(|device| device.handle)
    }
}

/// `coex_bt_status`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum Status {
    #[default]
    NotConnectedIdle,
    ConnectedIdle,
    InquiryOrPage,
    AclBusy,
    ScoBusy,
    AclScoBusy,
    /// `COEX_BTSTATUS_MAX`: a connection that fits no case.
    Other,
}

/// `rtw_coex_next_rssi_state`, which only the sides of its steps tell apart.
pub(super) fn rssi_high(high: bool, rssi: u8, step: u8) -> bool {
    if high {
        rssi >= step
    } else {
        rssi >= step + RSSI_TOLERANCE
    }
}

/// What a report with new contents changed, for the arbiter's timers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Changes {
    /// `bt_inq_page` went to this.
    pub inquiring: Option<bool>,
    /// A link is being set up.
    pub setting_up: bool,
    /// More than one link became one.
    pub multi_link_ended: bool,
    /// Bluetooth came back from a reset that lost what it knew of Wi-Fi.
    pub reset: bool,
    /// Bluetooth ignores Wi-Fi's activity with no link being set up.
    pub ignoring_wifi: bool,
}

/// `coex_stat`'s view of Bluetooth.
#[derive(Debug, Default)]
pub(super) struct Bluetooth {
    /// The chip's way of reading reports.
    pub facts: BluetoothFacts,
    /// `bt_info_lb2`, `lb3`, `hb0` to `hb3`.
    info: [u8; 6],
    /// `coex_dm->bt_status`.
    pub status: Status,
    pub hfp: bool,
    pub hid: bool,
    pub a2dp: bool,
    pub pan: bool,
    /// `bt_profile_num`.
    pub profiles: u8,
    /// `bt_whck_test`.
    pub certification: bool,
    /// `bt_inq_page`.
    pub inquiring: bool,
    /// `bt_page`.
    pub paging: bool,
    /// `bt_ble_exist`: a remote control over Bluetooth Low Energy.
    pub low_energy: bool,
    /// `bt_ble_hid_exist`.
    pub low_energy_hid: bool,
    /// `bt_ble_scan_en`.
    pub low_energy_scan: bool,
    /// `bt_ble_scan_type`.
    pub scan_type: u8,
    /// `bt_setup_link`.
    pub setting_up: bool,
    /// `bt_multi_link`.
    pub multi_link: bool,
    /// `bt_multi_link_remain`.
    pub multi_link_remains: bool,
    /// `bt_a2dp_active`.
    pub a2dp_active: bool,
    /// `bt_a2dp_sink`.
    pub a2dp_sink: bool,
    /// `bt_slave`.
    pub slave: bool,
    /// `bt_hid_slot` and `bt_hid_pair_num`.
    hid_slot: u8,
    pub hid_pairs: u8,
    /// `bt_418_hid_exist`: a controller polled every 4.18 ms.
    pub hid_418: bool,
    /// `bt_game_hid_exist`.
    pub game_controller: bool,
    /// `bt_rssi`.
    rssi: u8,
    /// `coex_dm->bt_rssi_state`, each `COEX_RSSI_HIGH`.
    pub rssi_high: [bool; 4],
    /// `cnt_bt[COEX_CNT_BT_INFOUPDATE]`.
    updates: u32,
}

impl Bluetooth {
    /// Nothing heard yet, on a chip read by `facts`.
    pub fn of(facts: BluetoothFacts) -> Self {
        Self {
            facts,
            ..Self::default()
        }
    }

    /// `rtw_coex_bt_info_notify`'s reading of a report from Bluetooth, none
    /// when it is short or says nothing new. `high_priority` is `hi_pri_tx` and `hi_pri_rx` as last counted.
    pub fn report(&mut self, bytes: &[u8], high_priority: (u32, u32)) -> Option<Changes> {
        if bytes.len() != INFO_LENGTH {
            return None;
        }
        let info: [u8; 6] = bytes[1..].try_into().ok()?;
        if info == self.info {
            return None;
        }
        self.info = info;
        let [low2, _low3, high0, high1, high2, _high3] = info;
        let mut changes = Changes::default();
        self.certification = low2 == 0xff;
        let inquiring = low2 & INFO_INQ_PAGE != 0;
        if inquiring != self.inquiring {
            self.inquiring = inquiring;
            changes.inquiring = Some(inquiring);
        }
        let low_energy = high1 & 1 != 0;
        if self.facts.low_energy_hid {
            self.low_energy_hid = low2 & INFO_HID != 0 && low_energy;
            self.low_energy = low2 & INFO_HID == 0 && low_energy;
        } else {
            // A remote control's traffic, by the last report's HID slot.
            let (high_tx, high_rx) = high_priority;
            self.low_energy_hid =
                low_energy && self.hid_slot == 1 && high_rx + 100 < high_tx && high_rx < 100;
            self.low_energy = low_energy && !self.low_energy_hid;
        }
        self.paging = info[1] & (1 << 7) != 0;
        self.rssi = if self.facts.rssi_ratio {
            // COEX_BTRSSI_RATIO, in rtw88's u8.
            high0.wrapping_mul(2).wrapping_add(10)
        } else {
            // COEX_BTRSSI_DBM.
            match high0 {
                0..=127 => 100,
                156..=255 => 100 - (0u8.wrapping_sub(high0)),
                _ => 0,
            }
        };
        changes.reset = high1 & (1 << 1) != 0;
        changes.setting_up = high1 & (1 << 2) != 0;
        self.setting_up |= changes.setting_up;
        changes.ignoring_wifi = high1 & (1 << 3) != 0 && !changes.setting_up;
        self.low_energy_scan = high1 & (1 << 5) != 0;
        let multi_link = high1 & (1 << 7) != 0;
        if !multi_link && self.multi_link {
            self.multi_link_remains = true;
            changes.multi_link_ended = true;
        }
        self.multi_link = multi_link;
        self.a2dp_active = high2 & (1 << 2) != 0;
        self.slave = high2 & (1 << 3) != 0;
        self.hid_slot = (high2 & 0x30) >> 4;
        self.hid_pairs = (high2 & 0xc0) >> 6;
        if self.hid_pairs > 0 && self.hid_slot >= 2 {
            self.hid_418 = true;
        } else if self.hid_pairs == 0 || self.hid_slot == 1 {
            self.hid_418 = false;
        }
        self.a2dp_sink = info[5] & (1 << 7) != 0;
        Some(changes)
    }

    /// `rtw_coex_update_bt_link_info`. True when it is time to ask what kind
    /// of scan Bluetooth Low Energy runs.
    pub fn update_links(&mut self) -> bool {
        for (high, step) in self.rssi_high.iter_mut().zip(self.facts.rssi_steps) {
            *high = rssi_high(*high, self.rssi, step);
        }
        let ask = self.low_energy_scan && self.updates.is_multiple_of(3);
        let low2 = self.info[0];
        let connected = low2 & INFO_CONNECTION != 0;
        self.pan = connected && low2 & INFO_FTP != 0;
        self.a2dp = connected && low2 & INFO_A2DP != 0;
        self.hid = connected && low2 & INFO_HID != 0;
        self.hfp = connected && low2 & INFO_SCO_ESCO != 0;
        self.profiles = [self.pan, self.a2dp, self.hid, self.hfp]
            .iter()
            .map(|&profile| u8::from(profile))
            .sum();
        self.status = if low2 & INFO_INQ_PAGE != 0 {
            Status::InquiryOrPage
        } else if !connected {
            self.multi_link_remains = false;
            Status::NotConnectedIdle
        } else if low2 == INFO_CONNECTION {
            Status::ConnectedIdle
        } else if low2 & (INFO_SCO_ESCO | INFO_SCO_BUSY) != 0 {
            if low2 & INFO_ACL_BUSY != 0 {
                Status::AclScoBusy
            } else {
                Status::ScoBusy
            }
        } else if low2 & INFO_ACL_BUSY != 0 {
            Status::AclBusy
        } else {
            Status::Other
        };
        self.updates = self.updates.wrapping_add(1);
        ask
    }

    /// `coex_stat`'s fields `rtw_coex_monitor_bt_enable` clears with Bluetooth.
    pub fn disabled(&mut self) {
        self.scan_type = 0;
    }

    /// `rtw_coex_query_bt_hid_list`'s gate: a controller could be there.
    pub fn may_hold_a_controller(&self, high_priority: u32) -> bool {
        self.hid || (self.info[0] & INFO_CONNECTION != 0 && high_priority > HID_TRAFFIC)
    }

    /// `bt_ble_scan_type` as `BT_MP_INFO_OP_SCAN_TYPE` answers.
    pub fn scan_answer(&mut self, kind: u8) {
        self.scan_type = kind;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::realtek::coex::tables::RTL8821C;

    #[test]
    fn an_rtl8821c_reads_rssi_as_a_ratio_and_guesses_a_remote_by_traffic() {
        let mut bluetooth = Bluetooth::of(RTL8821C.bluetooth);
        // hb0 40: 90 % rather than dBm; hb2 0x10 leaves HID slot 1.
        bluetooth.report(&[1, 0x20, 0, 40, 0, 0x10, 0], (0, 0));
        assert_eq!(bluetooth.rssi, 90);
        // Low energy with little received high-priority traffic, slot 1.
        bluetooth.report(&[1, 0, 0, 40, 1, 0x10, 0], (300, 50));
        assert!(bluetooth.low_energy_hid && !bluetooth.low_energy);
        bluetooth.report(&[1, 0, 0, 41, 1, 0x10, 0], (100, 50));
        assert!(!bluetooth.low_energy_hid && bluetooth.low_energy);
    }

    #[test]
    fn a_report_names_the_links_and_what_is_busy() {
        let mut bluetooth = Bluetooth::default();
        // Connected, A2DP and busy, at -60 dBm.
        let report = [1, 0x49, 0, 0xc4, 0, 0, 0];
        assert_eq!(bluetooth.report(&report, (0, 0)), Some(Changes::default()));
        bluetooth.update_links();
        assert!(bluetooth.a2dp && !bluetooth.hid);
        assert_eq!(bluetooth.profiles, 1);
        assert_eq!(bluetooth.status, Status::AclBusy);
        assert_eq!(bluetooth.rssi, 40);
        assert_eq!(bluetooth.rssi_high, [true, true, true, true]);
        assert_eq!(bluetooth.report(&report, (0, 0)), None, "nothing new");
    }

    #[test]
    fn a_controller_is_a_classic_link_of_a_known_vendor_and_name() {
        let mut devices = HidDevices::default();
        assert_eq!(devices.report([0, 6, 0, 2, 3, 0x20, 0xff, 0]), Some(false));
        assert_eq!(devices.unknown().collect::<alloc::vec::Vec<_>>(), [3]);
        assert_eq!(devices.report([0, 6, 0, 2, 3, 0x20, 0xff, 0]), None);
        assert_eq!(
            devices.report([0, 6, 1, 3, 0x46, 1, 2, 3]),
            Some(false),
            "another device of the vendor"
        );
        assert_eq!(
            devices.report([0, 6, 1, 3, 0x46, 0x58, 0x62, 0x6f]),
            Some(true)
        );
        assert_eq!(devices.unknown().count(), 0);
        assert_eq!(
            devices.report([0, 6, 1, 0x20, 0x46, 0x57, 0x69, 0x72]),
            Some(true),
            "a Low Energy handle is not asked about or counted"
        );
        assert_eq!(devices.report([0, 6, 0, 0, 0, 0, 0, 1]), Some(false));
    }

    #[test]
    fn a_short_report_is_no_report() {
        assert_eq!(Bluetooth::default().report(&[1, 0x49], (0, 0)), None);
    }

    #[test]
    fn every_other_kind_of_link_finds_its_status() {
        let status = |low2| {
            let mut bluetooth = Bluetooth::default();
            bluetooth.report(&[1, low2, 0, 0, 0, 0, 1], (0, 0));
            bluetooth.update_links();
            bluetooth.status
        };
        assert_eq!(status(0), Status::NotConnectedIdle);
        assert_eq!(status(1), Status::ConnectedIdle);
        assert_eq!(status(4), Status::InquiryOrPage);
        assert_eq!(status(1 | 2), Status::ScoBusy);
        assert_eq!(status(1 | 2 | 8), Status::AclScoBusy);
        assert_eq!(status(1 | 32), Status::Other);
    }

    #[test]
    fn low_energy_reads_as_a_remote_or_a_hid_by_the_hid_bit() {
        let mut bluetooth = Bluetooth::default();
        bluetooth.report(&[1, 0, 0, 0, 1, 0, 0], (0, 0));
        assert!(bluetooth.low_energy && !bluetooth.low_energy_hid);
        bluetooth.report(&[1, 0x20, 0, 0, 1, 0, 0], (0, 0));
        assert!(!bluetooth.low_energy && bluetooth.low_energy_hid);
    }

    #[test]
    fn a_418_controller_stands_until_a_report_rules_it_out() {
        let mut bluetooth = Bluetooth::default();
        // One pair, slot 2.
        bluetooth.report(&[1, 0, 0, 0, 0, 0x60, 0], (0, 0));
        assert!(bluetooth.hid_418);
        // One pair, slot 0: no ruling.
        bluetooth.report(&[1, 0, 0, 0, 0, 0x40, 0], (0, 0));
        assert!(bluetooth.hid_418);
        bluetooth.report(&[1, 0, 0, 0, 0, 0x50, 0], (0, 0));
        assert!(!bluetooth.hid_418);
    }

    #[test]
    fn the_end_of_multiple_links_leaves_a_remnant() {
        let mut bluetooth = Bluetooth::default();
        bluetooth.report(&[1, 1, 0, 0, 0x80, 0, 0], (0, 0));
        let changes = bluetooth.report(&[1, 3, 0, 0, 0, 0, 0], (0, 0)).unwrap();
        assert!(changes.multi_link_ended && bluetooth.multi_link_remains);
    }

    #[test]
    fn rssi_needs_the_tolerance_to_rise_but_not_to_stay() {
        assert!(!rssi_high(false, 61, 60));
        assert!(rssi_high(false, 62, 60));
        assert!(rssi_high(true, 60, 60));
        assert!(!rssi_high(true, 59, 60));
    }
}
