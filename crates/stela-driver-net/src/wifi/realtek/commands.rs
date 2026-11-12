// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Firmware mailbox commands and reports, from pinned rtw88 `fw.c` and `fw.h`.

/// `H2C_CMD_MEDIA_STATUS_RPT`.
const MEDIA_STATUS: u32 = 0x01;
/// `H2C_CMD_DEFAULT_PORT`.
const DEFAULT_PORT: u32 = 0x2c;
/// `H2C_CMD_RA_INFO`.
const RA_INFO: u32 = 0x40;
/// `H2C_CMD_RSSI_MONITOR`.
const RSSI_MONITOR: u32 = 0x42;
/// `H2C_CMD_WL_PHY_INFO`, `H2C_CMD_SCAN` and `H2C_CMD_ADAPTIVITY`.
const WL_PHY_INFO: u32 = 0x58;
const SCAN: u32 = 0x59;
const ADAPTIVITY: u32 = 0x5a;
/// `H2C_CMD_WIFI_CALIBRATION`.
const CALIBRATION: u32 = 0x6d;
/// `H2C_CMD_RECOVER_BT_DEV`.
const RECOVER_BT_DEVICE: u32 = 0xd1;
/// `C2H_SCAN_RESULT`.
const SCAN_RESULT: u8 = 0x38;

/// `H2C_CMD_RSVD_PAGE` and `H2C_CMD_SET_PWR_MODE`.
const RESERVED_PAGES: u32 = 0;
const POWER_MODE: u32 = 0x20;
/// `H2C_CMD_LPS_PG_INFO`.
const POWER_GATE_PAGES: u32 = 0x2b;

/// `C2H_BT_INFO`, `C2H_BT_MP_INFO` and `C2H_BT_HID_INFO`.
const BT_INFO: u8 = 0x09;
const BT_MP_INFO: u8 = 0x0b;
const BT_HID_INFO: u8 = 0x45;
/// `C2H_CCX_TX_RPT`.
const CCX_TX_REPORT: u8 = 0x03;
/// `C2H_RA_RPT`.
const RA_REPORT: u8 = 0x0c;
/// `C2H_HALMAC`, and its `C2H_CCX_RPT`.
const HALMAC: u8 = 0xff;
const HALMAC_CCX_REPORT: u8 = 0x0f;

/// `rtw_send_rsvd_page_h2c`, with no probe response among the pages.
pub fn reserved_pages(ps_poll: u8, null: u8, qos_null: u8) -> (u32, u32) {
    (
        RESERVED_PAGES | (u32::from(ps_poll) << 16) | (u32::from(null) << 24),
        u32::from(qos_null),
    )
}

/// `rtw_fw_set_pg_info`: where firmware finds what a power gate loses, and
/// whether `keys` were saved among it.
pub fn power_gate_pages(info: u8, predistortion: u8, keys: bool) -> (u32, u32) {
    (
        POWER_GATE_PAGES
            | (u32::from(keys) << 8)
            | (u32::from(info) << 16)
            | (u32::from(predistortion) << 24),
        0,
    )
}

/// `rtw_fw_set_pwr_mode` as `rtw_enter_lps_core` and `rtw_leave_lps_core` set
/// it for the station on `port`.
pub fn power_mode(leisure: bool, port: u8) -> (u32, u32) {
    let (mode, rlbm, smart, state) = if leisure {
        (1, 1, 2, 0)
    } else {
        (0, 0, 0, 0xc)
    };
    (
        POWER_MODE | (mode << 8) | (rlbm << 16) | (smart << 20) | (1 << 24),
        (u32::from(port) << 5) | (state << 8),
    )
}

/// `rtw_fw_media_status_report`.
pub fn media_status(mac_id: u8, connected: bool) -> (u32, u32) {
    (
        MEDIA_STATUS | (u32::from(connected) << 8) | (u32::from(mac_id) << 16),
        0,
    )
}

/// `rtw_fw_default_port`.
pub fn default_port(port: u8, mac_id: u8) -> (u32, u32) {
    (
        DEFAULT_PORT | (u32::from(port) << 8) | (u32::from(mac_id) << 16),
        0,
    )
}

/// What `rtw_update_sta_info` tells firmware's rate adaptation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateInfo {
    pub mac_id: u8,
    pub rate_id: u8,
    /// `init_ra_lv`, one on the first report of an association.
    pub initial_level: u8,
    pub short_gi: bool,
    pub width: u8,
    pub ldpc: bool,
    /// False when `mask` replaces the mask firmware held.
    pub no_update: bool,
    /// `VHT_EN`'s two bits: zero without VHT.
    pub vht: u8,
    pub mask: u32,
}

/// `rtw_fw_send_ra_info`, whose `disable_pt` is always set.
pub fn ra_info(info: RateInfo) -> (u32, u32) {
    let bit = |value: bool, at: u32| u32::from(value) << at;
    (
        RA_INFO
            | (u32::from(info.mac_id) << 8)
            | (u32::from(info.rate_id & 0x1f) << 16)
            | (u32::from(info.initial_level & 3) << 21)
            | bit(info.short_gi, 23)
            | (u32::from(info.width & 3) << 24)
            | bit(info.ldpc, 26)
            | bit(info.no_update, 27)
            | (u32::from(info.vht & 3) << 28)
            | (1 << 30),
        info.mask,
    )
}

/// `rtw_fw_send_rssi_info`, for firmware's choice of rate.
pub fn rssi(mac_id: u8, rssi: u8, stbc: bool) -> (u32, u32) {
    (
        RSSI_MONITOR | (u32::from(mac_id) << 8) | (u32::from(rssi) << 24),
        u32::from(stbc) << 1,
    )
}

/// `rtw_fw_update_wl_phy_info`, for firmware's own decisions.
pub fn phy_info(tx_mbps: u32, rx_mbps: u32, tx_rate: u8, rx_rate: u8, evm_db: u8) -> (u32, u32) {
    (
        WL_PHY_INFO | ((tx_mbps & 0x3ff) << 8) | ((rx_mbps & 0x3ff) << 18),
        u32::from(tx_rate) | (u32::from(rx_rate) << 8) | (u32::from(evm_db) << 16),
    )
}

/// `rtw_fw_inform_rfk_status`, which tells Bluetooth too.
pub fn calibration(start: bool) -> (u32, u32) {
    (CALIBRATION | (u32::from(start) << 8), 0)
}

/// `rtw_fw_set_recover_bt_device`.
pub fn recover_bluetooth() -> (u32, u32) {
    (RECOVER_BT_DEVICE | (1 << 8), 0)
}

/// `rtw_fw_scan_notify`.
pub fn scan(start: bool) -> (u32, u32) {
    (SCAN | (u32::from(start) << 8), 0)
}

/// `rtw_fw_adaptivity`, with its `option` of one.
pub fn adaptivity(mode: u8, gain: u8, threshold: u8, density: u8) -> (u32, u32) {
    (
        ADAPTIVITY
            | (u32::from(mode & 15) << 8)
            | (1 << 12)
            | (u32::from(gain) << 16)
            | (u32::from(threshold) << 24),
        u32::from(density),
    )
}

/// What fits of a report's `payload`, the rest of it zero.
fn first_bytes(payload: &[u8]) -> [u8; 8] {
    let mut bytes = [0; 8];
    let length = payload.len().min(bytes.len());
    bytes[..length].copy_from_slice(&payload[..length]);
    bytes
}

/// One report in a firmware packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    /// `rtw_tx_report_handle`: report number `number`'s frame went or did not.
    Transmitted { number: u8, acknowledged: bool },
    /// `rtw_fw_ra_report_handle`'s `RTW_C2H_RA_RPT_RATE` of the given MAC ID.
    Rate {
        mac_id: u8,
        rate: u8,
        short_gi: bool,
        /// The width it was sent on, which older firmware leaves out.
        width: Option<u8>,
    },
    /// `rtw_fw_scan_result`: how crowded the scan found the air.
    Density(u8),
    /// `rtw_coex_bt_info_notify`, of `length` bytes.
    Bluetooth { bytes: [u8; 10], length: u8 },
    /// `rtw_coex_info_response`.
    BluetoothAnswer([u8; 8]),
    /// `rtw_coex_bt_hid_info_notify`.
    BluetoothHid([u8; 8]),
    /// A report a station does not act on, by ID.
    Other(u8),
}

impl Report {
    /// `rtw_fw_c2h_cmd_handle` of a packet's ID, sequence and payload.
    pub fn parse(packet: &[u8]) -> Option<Self> {
        let (&id, rest) = packet.split_first()?;
        let payload = rest.get(1..)?;
        let transmitted = |number: u8, status: u8| Self::Transmitted {
            number: number & 0xfc,
            acknowledged: status & 0xc0 == 0,
        };
        Some(match id {
            CCX_TX_REPORT => transmitted(*payload.get(6)?, *payload.first()?),
            HALMAC if payload.first() == Some(&HALMAC_CCX_REPORT) => {
                transmitted(*payload.get(8)?, *payload.get(9)?)
            }
            RA_REPORT => Self::Rate {
                rate: payload.first()? & 0x7f,
                short_gi: payload.first()? & 0x80 != 0,
                mac_id: *payload.get(1)?,
                width: payload.get(6).copied(),
            },
            SCAN_RESULT => Self::Density(*payload.first()?),
            BT_INFO => {
                let mut bytes = [0; 10];
                let length = payload.len().min(bytes.len());
                bytes[..length].copy_from_slice(&payload[..length]);
                Self::Bluetooth {
                    bytes,
                    length: length as u8,
                }
            }
            BT_MP_INFO => Self::BluetoothAnswer(first_bytes(payload)),
            BT_HID_INFO => Self::BluetoothHid(first_bytes(payload)),
            _ => Self::Other(id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_keep_their_fields_in_rtw88s_bits() {
        assert_eq!(media_status(1, true), (0x0001_0101, 0));
        assert_eq!(default_port(0, 1), (0x0001_002c, 0));
        assert_eq!(reserved_pages(1, 3, 2), (0x0301_0000, 2));
        assert_eq!(
            Report::parse(&[9, 0, 1, 2, 3, 4, 5, 6, 7]),
            Some(Report::Bluetooth {
                bytes: [1, 2, 3, 4, 5, 6, 7, 0, 0, 0],
                length: 7
            })
        );
        assert_eq!(
            Report::parse(&[0xb, 0, 1, 0, 0, 2]),
            Some(Report::BluetoothAnswer([1, 0, 0, 2, 0, 0, 0, 0]))
        );
        assert_eq!(recover_bluetooth(), (0x1d1, 0));
        assert_eq!(power_mode(true, 0), (0x0121_0120, 0));
        assert_eq!(power_mode(false, 0), (0x0100_0020, 0xc00));
        let (message, mask) = ra_info(RateInfo {
            mac_id: 1,
            rate_id: 9,
            initial_level: 1,
            short_gi: true,
            width: 2,
            ldpc: true,
            no_update: false,
            vht: 2,
            mask: 0xfff_f000,
        });
        assert_eq!(
            message,
            0x40 | (1 << 8)
                | (9 << 16)
                | (1 << 21)
                | (1 << 23)
                | (2 << 24)
                | (1 << 26)
                | (2 << 28)
                | (1 << 30)
        );
        assert_eq!(mask, 0xfff_f000);
    }

    #[test]
    fn both_report_forms_name_the_frame_and_its_fate() {
        let mut old = [0; 10];
        old[0] = 3;
        old[2] = 0x40;
        old[8] = 0x15;
        assert_eq!(
            Report::parse(&old),
            Some(Report::Transmitted {
                number: 0x14,
                acknowledged: false
            })
        );
        let mut halmac = [0; 14];
        halmac[0] = 0xff;
        halmac[2] = 0x0f;
        halmac[10] = 0x18;
        assert_eq!(
            Report::parse(&halmac),
            Some(Report::Transmitted {
                number: 0x18,
                acknowledged: true
            })
        );
        assert_eq!(Report::parse(&[0x46, 0, 1]), Some(Report::Other(0x46)));
        assert_eq!(Report::parse(&[3, 0, 1]), None);
    }
}
