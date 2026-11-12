// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! A Realtek chip's Bluetooth arbiter: `rtw_coex_power_on_setting`,
//! `rtw_coex_init_hw_config`, and the notifiers, timers and
//! `rtw_coex_run_coex` that share the air and antennas with the Bluetooth half
//! as firmware reports it. rtw88's `wl_rx_rate` never moves, so its CCK lock
//! and the 5 ms slot extension it alone asks for never happen here either.
//! Each of rtw88's delayed works is a deadline in [`Timers`], and what it
//! waits for from firmware in a sleep is a [`Request`] answered by a later
//! report. The chip's own `coex_set_*` operations and tables follow its
//! `rtw_chip_info`.
mod actions;
mod bluetooth;
mod tables;

use self::{
    actions::{Phase, Plan},
    bluetooth::{Bluetooth, Changes, HID_DEVICE, HID_LIST, HidDevices, Status, rssi_high},
    tables::*,
};
use super::{
    efuse::Board,
    features::Report,
    identity::Chip,
    io::{self, Io},
    registers::*,
    rf::{self, Path, Registers},
};
use alloc::{collections::VecDeque, vec::Vec};

/// Coexistence registers of `reg.h`.
const REG_GPIO_MUXCFG: u32 = 0x40;
const REG_PAD_CTRL1: u32 = 0x64;
const REG_SYS_SDIO_CTRL: u32 = 0x70;
const REG_WIFI_BT_INFO: u32 = 0xaa;
const REG_LIFETIME_EN: u32 = 0x426;
const REG_RETRY_LIMIT: u32 = 0x42a;
const REG_DARFRC: u32 = 0x430;
const REG_DARFRCH: u32 = 0x434;
const REG_AMPDU_MAX_TIME_V1: u32 = 0x455;
const REG_TX_HANG_CTRL: u32 = 0x45e;
const REG_QUEUE_CTRL: u32 = 0x4c6;
const REG_DUMMY_PAGE4_V1: u32 = 0x4fc;
const REG_BT_COEX_TABLE0: u32 = 0x6c0;
const REG_BT_COEX_TABLE1: u32 = 0x6c4;
const REG_BT_COEX_BRK_TABLE: u32 = 0x6c8;
const REG_BT_COEX_TABLE_H: u32 = 0x6cc;
const REG_BT_COEX_V2: u32 = 0x762;
const REG_BT_COEX_ENH_INTR_CTRL: u32 = 0x76e;
const REG_BT_ACT_STATISTICS: u32 = 0x770;
const REG_BT_ACT_STATISTICS_1: u32 = 0x774;
const REG_BT_STAT_CTRL: u32 = 0x778;
const REG_BT_TDMA_TIME: u32 = 0x790;
const REG_IGN_GNT_BT1: u32 = 0x1860;
const REG_NOMASK_TXBT: u32 = 0x1ca7;
const REG_ANAPAR: u32 = 0x1c30;
const REG_RSTB_SEL: u32 = 0x1c38;
const REG_IGN_GNTBT4: u32 = 0x4160;
/// `BIT_BT_PTA_EN` and `BIT_PO_BT_PTA_PINS`.
const PTA_PINS: u32 = (1 << 5) | (1 << 9);
const PTA_WL_TX_ENABLE: u8 = 1 << 4;
const PTA_EDCCA_ENABLE: u8 = 1 << 5;
const GNT_BT_POLARITY: u16 = 1 << 12;
const BTCCA_CONTROL: u8 = 3;
/// `BIT_LTE_MUX_CTRL_PATH >> 24`.
const MUX_CONTROL_PATH: u8 = 1 << 2;
/// `BIT_FEN_BB_GLB_RST | BIT_FEN_BB_RSTB`.
const BASEBAND_ENABLE: u8 = 3;
const BCN_FUNCTION_ENABLE: u8 = 1 << 3;
const BT_INTERRUPT_ENABLE: u16 = 1 << 15;
/// `BIT_EN_GNT_BT_AWAKE`.
const GNT_BT_AWAKE: u8 = 1 << 3;
/// `BIT_R_GRANTALL_WLMASK | BIT_STATIS_BT_EN`.
const COUNT_BLUETOOTH: u8 = (1 << 3) | (1 << 2);
/// `BIT_WL_RFK`.
const WL_CALIBRATING: u8 = 1 << 0;
/// `BIT_ANAPAR_BTPS >> 16`, `BIT_DAC_OFF_ENABLE`, `BIT_PI_IGNORE_GNT_BT`,
/// `BIT_NOMASK_TXBT_ENABLE`.
const ANAPAR_BTPS: u8 = 1 << 6;
const DAC_OFF_ENABLE: u8 = 1 << 4;
const IGNORE_GNT_BT: u8 = 1 << 3;
const NOMASK_TXBT: u8 = 1 << 3;
/// `RF_MODOPT`'s reset, and the mask of a whole RF register.
const RF_MODOPT: u8 = 1;
const RF_MODOPT_DEFAULT: u32 = 0x40000;
const RF_MASK: u32 = 0xfffff;
/// `RF_RCKD` and `RF_RCK`.
const RF_RCKD: u8 = 0xde;
const RF_RCK: u8 = 0x1d;

/// The RTL8821C's antenna switch and debug pins, of `reg.h` and
/// `rtw8821c.h`.
const REG_LED_CFG: u32 = 0x4c;
const DPDT_SEL_EN: u32 = 1 << 23;
const DPDT_WL_SEL: u32 = 1 << 24;
const REG_RFE_CTRL8: u32 = 0xcb4;
/// `BIT_MASK_R_RFE_SEL_15`'s shift.
const RFE_SEL_15_SHIFT: u32 = 28;
const DPDT_CTRL_PIN: u8 = 0x77;
const PTA_CTRL_PIN: u8 = 0x66;
const REG_CTRL_TYPE: u32 = 0x67;
/// `BIT_CTRL_TYPE1 | BIT_CTRL_TYPE2`.
const CTRL_TYPES: u8 = (1 << 5) | (1 << 4);
/// `BIT_BCN_QUEUE` of `REG_BT_COEX_TABLE_H + 3`.
const BCN_QUEUE_PRIORITY: u8 = 1 << 3;
/// `BIT_BTGP_SPI_EN`, `BIT_BTGP_JTAG_EN`, `BIT_LED1DIS`, `BIT_FSPI_EN`,
/// `BIT_SDIO_INT` and `BIT_DBG_GNT_WL_BT`.
const BTGP_SPI_EN: u32 = 1 << 20;
const BTGP_JTAG_EN: u32 = 1 << 24;
const LED1_DISABLE: u32 = 1 << 15;
const FSPI_EN: u32 = 1 << 19;
const SDIO_INTERRUPT: u32 = 1 << 18;
const DEBUG_GRANTS: u32 = 1 << 27;

/// `COEX_SCBD_*`.
const SCORE_ACTIVE: u16 = 1 << 0;
const SCORE_ON: u16 = 1 << 1;
const SCORE_SCAN: u16 = 1 << 2;
const SCORE_RX_GAIN: u16 = 1 << 4;
const SCORE_BT_CALIBRATING: u16 = 1 << 5;
const SCORE_WL_BUSY: u16 = 1 << 6;
const SCORE_TDMA: u16 = 1 << 9;
const SCORE_FIX_2M: u16 = 1 << 10;
const SCORE_ALL: u16 = 0xffff;

/// `COEX_WLPRI_*`.
const PRIORITY_TX_RESPONSE: u8 = 3;
const PRIORITY_TX_BEACON: u8 = 4;
const PRIORITY_TX_BEACON_QUEUE: u8 = 27;
const PRIORITY_RX_CCK: u8 = 28;

/// The arbiter's indirect registers.
const LTE_COEX_CTRL: u32 = 0x38;
const LTE_WL_TRX_CTRL: u32 = 0xa0;
const LTE_BT_TRX_CTRL: u32 = 0xa4;
const LTE_COEX_ENABLE: u32 = 1 << 7;
const LTECOEX_READY: u32 = 1 << 29;
/// `COEX_GNT_SET_*`.
const GRANT_PTA: u32 = 0;
const GRANT_LOW: u32 = 1;
const GRANT_HIGH: u32 = 3;

/// `H2C_CMD_*`, and `COEX_H2C69_*` under the last.
const COMMAND_TDMA: u32 = 0x60;
const COMMAND_QUERY_BT: u32 = 0x61;
const COMMAND_BT_POWER: u32 = 0x62;
const COMMAND_IGNORE_WLAN: u32 = 0x63;
const COMMAND_CHANNEL_INFO: u32 = 0x66;
const COMMAND_QUERY_BT_MP: u32 = 0x67;
const COMMAND_BT_WIFI_CONTROL: u32 = 0x69;
const COMMAND_QUERY_HID: u32 = 0x73;
const CONTROL_TOGGLE_TABLE_B: u8 = 0x7;
const CONTROL_TDMA_SLOT: u8 = 0xb;
const CONTROL_LEAK_AP: u8 = 0xc;
const CONTROL_TOGGLE_TABLE_A: u8 = 0xd;
/// `PARA1_H2C69_*`.
const LEAK_DISABLE_5MS: u8 = 1;
const SLOT_FOUR: u8 = 0xc1;
const SLOT_TWO: u8 = 1;
const SLOT_TBTT_DIVIDE: u8 = 1 << 7;
/// `TDMA_TIMER_TYPE_4SLOT`.
const TIMER_FOUR_SLOT: u8 = 3;
/// `COEX_WL_SLOT_TOGLLE` and rtw88's default table for it.
const TOGGLE_SLOT: u32 = 0x5a5a_5aaa;
const TOGGLE_TABLE: u32 = 0x5a5a_5a5a;
/// The default `DEF_BRK_TABLE_VAL`.
const BREAK_TABLE: u32 = 0xf0ff_ffff;
/// `COEX_RFK_TIMEOUT` over `COEX_MIN_DELAY`, in its steps.
const CALIBRATION_TRIES: u32 = 60;
const CALIBRATION_STEP_US: u64 = 10_000;
/// The steps of that wait one call takes once the radio runs: rtw88 sleeps
/// through all of them under its mutex, which here would hold the caller.
const RUNTIME_CALIBRATION_TRIES: u32 = 2;
/// `BT_MP_INFO_OP_*`.
const OP_SCAN_TYPE: u8 = 0x2d;
const OP_LNA_CONSTRAINT: u8 = 0x32;
/// `COEX_RESP_ACK_BY_WL_FW`.
const ANSWER_FROM_FIRMWARE: u8 = 1;
/// `COEX_REQUEST_TIMEOUT`.
const REQUEST_TIMEOUT_US: u64 = 10_000;
/// `COEX_BTINFO_SRC_*`.
const SOURCE_FIRMWARE: u8 = 0;
const SOURCE_RESPONSE: u8 = 1;
const SOURCE_ACTION: u8 = 2;
const SOURCE_CALIBRATION: u8 = 3;
const SOURCE_SCOREBOARD: u8 = 4;
/// `bt_iqk_state` once a wait for it ran out.
const CALIBRATION_ABANDONED: u8 = 0xff;

/// A second, for the delays of rtw88's works.
const SECOND_US: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(io::Error),
    Rf(rf::Error),
    /// The arbiter's indirect window stayed busy.
    ArbiterBusy,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Hardware(error)
    }
}

impl From<rf::Error> for Error {
    fn from(error: rf::Error) -> Self {
        Self::Rf(error)
    }
}

/// `COEX_WLINK_*`, as far as a lone station reaches them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    TwoGhz,
    FiveGhz,
    /// `COEX_WLINK_2GFREE`: one antenna each, for a game controller.
    Free,
}

/// What the Wi-Fi side is doing, which `rtw_coex_run_coex` schedules around.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Wifi {
    /// `rtwdev->sta_cnt`.
    pub connected: bool,
    /// `RTW_FLAG_SCANNING`.
    pub scanning: bool,
    /// `RTW_FLAG_BUSY_TRAFFIC`.
    pub busy: bool,
    /// `stats->tx_throughput` over `rx_throughput`.
    pub transmitting: bool,
    /// `dm_info.min_rssi`.
    pub rssi: u8,
    /// `dm_info.cck_ok_cnt + cck_err_cnt`.
    pub cck_frames: u32,
    pub five_ghz: bool,
    /// `hal.current_channel` and `current_band_width`.
    pub channel: u8,
    pub width: u8,
    /// `coex_stat->wl_beacon_interval`.
    pub beacon_interval: u16,
    /// `RTW_FLAG_LEISURE_PS`.
    pub asleep: bool,
}

/// What rtw88 notifies the arbiter of.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    /// `rtw_coex_scan_notify` of `COEX_SCAN_START`.
    ScanStarted,
    /// `rtw_coex_scan_notify` of `COEX_SCAN_FINISH`.
    ScanEnded,
    /// `rtw_coex_switchband_notify`, a channel having changed.
    Tuned { scanning: bool },
    /// `rtw_coex_connect_notify` of `COEX_ASSOCIATE_START`, which rtw88 calls
    /// a 2.4 GHz start whatever the channel.
    Connecting,
    /// `rtw_coex_connect_notify` of `COEX_ASSOCIATE_FINISH`.
    Connected,
    /// `rtw_coex_media_status_notify`. rtw88 only ever calls it to connect;
    /// this also ends what connecting began.
    Media { connected: bool },
    /// `rtw_coex_lps_notify`.
    Sleeping(bool),
    /// `rtw_coex_wl_status_change_notify`.
    Traffic,
    /// `rtw_coex_wl_status_check`.
    Watchdog,
    /// `rtw_coex_bt_info_notify`.
    Bluetooth(&'a [u8]),
    /// `rtw_coex_bt_hid_info_notify`.
    BluetoothHid([u8; 8]),
    /// `rtw_coex_info_response`.
    Answer(&'a [u8]),
    /// Time passed: rtw88's delayed works.
    Tick,
}

/// `coex_runcoex_reason`, as far as a run tells them apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reason {
    /// `COEX_RSN_2GSCANSTART`.
    Scanning,
    /// `COEX_RSN_2GCONSTART`.
    Connecting,
    /// `COEX_RSN_2GSWITCHBAND`.
    TwoGhz,
    /// `COEX_RSN_5GSWITCHBAND`.
    FiveGhz,
    /// `COEX_RSN_BTINFO`.
    Bluetooth,
    /// `COEX_RSN_LPS`.
    Sleep,
    /// `COEX_RSN_2GMEDIA`.
    Media,
    /// Any other.
    Status,
}

/// What a step of the arbiter leaves for its caller, in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Order {
    /// A firmware mailbox command.
    Command((u32, u32)),
    /// `rtw_leave_lps`.
    Wake,
    /// `rtw_set_txrx_1ss`.
    SingleStream(bool),
}

/// What a step of the arbiter leaves undone.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Run {
    pub orders: Vec<Order>,
}

/// What waits in the firmware's answer: `rtw_coex_info_request`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Request {
    ScanType,
    LnaConstraint(u8),
}

/// rtw88's delayed works, each a deadline. As `ieee80211_queue_delayed_work`
/// leaves a pending work be, so setting one leaves a deadline that stands.
#[derive(Debug, Default)]
struct Timers {
    /// `bt_relink_work`.
    relink: Option<u64>,
    /// `bt_reenable_work`.
    reenable: Option<u64>,
    /// `defreeze_work`.
    defreeze: Option<u64>,
    /// `wl_remain_work`.
    wifi_remains: Option<u64>,
    /// `bt_remain_work`.
    inquiry_remains: Option<u64>,
    /// `wl_connecting_work`.
    connecting: Option<u64>,
    /// `bt_multi_link_remain_work`.
    multi_link_remains: Option<u64>,
}

/// Takes a deadline that passed.
fn due(timer: &mut Option<u64>, now: u64) -> bool {
    let passed = timer.is_some_and(|at| at <= now);
    if passed {
        *timer = None;
    }
    passed
}

/// `coex_stat`'s Bluetooth counters, from `rtw_coex_monitor_bt_ctr`.
#[derive(Debug, Default)]
struct Counters {
    high_tx: u32,
    high_rx: u32,
    low_tx: u32,
    low_rx: u32,
    /// `bt_ctr_ok`.
    trustworthy: bool,
}

/// One step's world.
struct Step<'a, I> {
    io: &'a mut I,
    report: &'a Report,
    now: u64,
    wifi: Wifi,
    /// `coex_dm->reason`.
    reason: Reason,
    run: Run,
}

impl<I> Step<'_, I> {
    fn command(&mut self, command: (u32, u32)) {
        self.run.orders.push(Order::Command(command));
    }
}

/// `rtw_fw_bt_wifi_control`.
fn control(operation: u8, data: [u8; 5]) -> (u32, u32) {
    let [one, two, three, four, five] = data.map(u32::from);
    (
        COMMAND_BT_WIFI_CONTROL | (u32::from(operation) << 8) | (one << 16) | (two << 24),
        three | (four << 8) | (five << 16),
    )
}

/// `rtw_fw_coex_tdma_type`.
fn tdma(para: [u8; 5]) -> (u32, u32) {
    let [one, two, three, four, five] = para.map(u32::from);
    (
        COMMAND_TDMA | (one << 8) | (two << 16) | (three << 24),
        four | (five << 8),
    )
}

/// `rtw_fw_query_bt_mp_info` of `operation` with its first parameter.
fn query(operation: u8, parameter: u8) -> (u32, u32) {
    (
        COMMAND_QUERY_BT_MP | (u32::from(operation) << 16) | (u32::from(parameter) << 24),
        0,
    )
}

/// `rtw_fw_coex_query_hid_info`.
fn query_hid(kind: u8, data: u8) -> (u32, u32) {
    (
        COMMAND_QUERY_HID | (u32::from(kind) << 8) | (u32::from(data) << 16),
        0,
    )
}

/// `COEX_SWITCH_CTRL_*` as far as a run reaches them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Control {
    /// `COEX_SWITCH_CTRL_BY_BBSW`.
    Baseband,
    /// `COEX_SWITCH_CTRL_BY_PTA`.
    Pta,
}

/// `COEX_SWITCH_TO_*` as far as a run reaches them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Position {
    Bluetooth,
    /// `COEX_SWITCH_TO_WLA`: Wi-Fi's 5 GHz port.
    WifiA,
    NoCare,
    /// `COEX_SWITCH_TO_WLG_BT`: both on the 2.4 GHz port.
    WifiGBluetooth,
}

/// `coex_dm->cur_switch_status` of a cleared `coex_dm`: control 0, position 0.
const SWITCH_CLEARED: (Control, Position) = (Control::Baseband, Position::Bluetooth);

/// `coex_rfe` of `rtw8821c_coex_cfg_rfe_type`; rtw88 never sets its
/// `ant_switch_diversity`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Switch {
    /// `rfe_module_type`.
    module: u8,
    /// `ant_switch_polarity`.
    inverse: bool,
    /// `ant_switch_exist`.
    exists: bool,
    /// `wlg_at_btg`: Wi-Fi's 2.4 GHz shares Bluetooth's port.
    wifi_g_at_bluetooth: bool,
}

impl Switch {
    fn of(rfe: u8) -> Self {
        let (inverse, exists, wifi_g_at_bluetooth) = match rfe {
            2 | 10 | 7 | 15 => (false, true, true),
            3 | 11 => (true, true, false),
            4 | 12 => (true, true, true),
            5 | 13 | 6 | 14 => (false, false, false),
            _ => (false, true, false),
        };
        Self {
            module: rfe,
            inverse,
            exists,
            wifi_g_at_bluetooth,
        }
    }
}

/// An arbiter's state.
#[derive(Debug)]
pub struct Coex {
    /// `efuse->btcoex`: firmware reports a Bluetooth half beside this one.
    combined: bool,
    /// `efuse->share_ant`.
    shared: bool,
    /// The chip's tables and what of its `rtw_chip_info` the arbiter reads.
    params: &'static Params,
    chip: Chip,
    /// `coex_rfe` of a chip that steers an antenna switch itself.
    switch: Option<Switch>,
    /// `coex_dm->cur_switch_status`.
    switch_status: (Control, Position),
    /// `coex_stat->kt_ver`.
    version: u8,
    /// `coex_stat->score_board`, what this side last told Bluetooth.
    score: u16,
    /// `coex->stop_dm`: nothing to run on a chip alone.
    stopped: bool,
    /// `coex->freeze`.
    freeze: bool,
    /// `coex->freerun`.
    freerun: bool,
    /// `coex->under_5g`.
    five_ghz: bool,
    /// `wl_connected`.
    connected: bool,
    /// `wl_gl_busy`, which outlasts the traffic by `wl_remain_work`.
    busy: bool,
    /// `wl_tput_dir` of `COEX_WL_TPUT_TX`.
    transmitting: bool,
    /// `wl_linkscan_proc`.
    linkscan: bool,
    /// `wl_hi_pri_task1` and `wl_hi_pri_task2`.
    connecting_task: bool,
    scanning_task: bool,
    /// `wl_connecting`.
    connecting: bool,
    /// `wl_under_lps`.
    sleeping: bool,
    /// `wl_force_lps_ctrl`.
    stays_awake: bool,
    /// `cnt_wl[COEX_CNT_WL_SCANAP]` past 5, which a finished scan puts it.
    scanned: bool,
    /// `cnt_wl[COEX_CNT_WL_NOISY0..2]`.
    noise_counts: [u8; 3],
    /// `wl_noisy_level`.
    noise: u8,
    /// `coex_dm->wl_rssi_state`, each `COEX_RSSI_HIGH`.
    rssi_high: [bool; 4],
    /// `bt_disabled` and `bt_disabled_pre`.
    bluetooth_disabled: bool,
    bluetooth_reported_disabled: bool,
    /// `bt_reenable`.
    reenabling: bool,
    /// `bt_inq_remain`.
    inquiry_remains: bool,
    /// `bt_iqk_state`.
    calibration: u8,
    /// Steps of `rtw_coex_check_rfk`'s wait one call takes, and those taken
    /// since a calibration was last seen over.
    calibration_tries: u32,
    calibration_waited: u32,
    /// A path changed while a calibration still ran, not yet told.
    calibration_cut: bool,
    bluetooth: Bluetooth,
    hid: HidDevices,
    counters: Counters,
    timers: Timers,
    /// What the mailbox holds and what waits behind it, with when to stop
    /// waiting for an answer.
    asked: Option<(Request, u64)>,
    requests: VecDeque<Request>,
    /// `coex_stat->wl_coex_mode`.
    mode: Option<Mode>,
    /// `coex_stat->wl_mimo_ps`.
    single_stream: bool,
    /// `coex_stat->gnt_workaround_state`.
    workaround: Option<Mode>,
    /// `coex_dm->cur_ant_pos_type`.
    phase: Option<Phase>,
    /// `coex_dm->cur_bt_pwr_lvl`, `cur_wl_rx_low_gain_en` and `cur_bt_lna_lvl`.
    bluetooth_power: u8,
    low_gain: bool,
    bluetooth_lna: u8,
    /// `coex_dm->cur_ps_tdma`, `cur_ps_tdma_on` and `tdma_timer_base`.
    tdma_case: u8,
    tdma_on: bool,
    timer_base: u8,
    /// `wl_slot_toggle` and `wl_slot_toggle_change`.
    toggling: bool,
    toggle_changed: bool,
    /// `wl_tx_limit_en`, `wl_ampdu_limit_en` and what they replaced.
    transmit_limit: bool,
    aggregate_limit: bool,
    limited: Limited,
}

/// What `rtw_coex_limited_tx` restores.
#[derive(Debug, Default)]
struct Limited {
    darfrc: u32,
    darfrch: u32,
    retry_limit: u16,
    aggregate_time: u8,
}

impl Coex {
    /// `rtw_chip_efuse_info_setup`'s reading of `board`.
    pub fn new(board: &Board) -> Self {
        let raw = board.raw();
        Self::of_chip(
            board.profile().chip(),
            raw.rfe_raw,
            raw.rf_board_raw,
            raw.bt_raw,
        )
    }

    #[cfg(test)]
    fn of(option: u8, bluetooth: u8) -> Self {
        Self::of_chip(Chip::Rtl8822C, 0, option, bluetooth)
    }

    fn of_chip(chip: Chip, rfe: u8, option: u8, bluetooth: u8) -> Self {
        let params = params(chip);
        Self {
            combined: option != 0xff && option & 0xe0 == 0x20,
            shared: bluetooth & 1 != 0,
            params,
            chip,
            switch: (chip == Chip::Rtl8821C).then(|| Switch::of(rfe)),
            switch_status: SWITCH_CLEARED,
            version: 0,
            score: 0,
            stopped: true,
            freeze: false,
            freerun: false,
            five_ghz: false,
            connected: false,
            busy: false,
            transmitting: false,
            linkscan: false,
            connecting_task: false,
            scanning_task: false,
            connecting: false,
            sleeping: false,
            stays_awake: false,
            scanned: false,
            noise_counts: [0; 3],
            noise: 0,
            rssi_high: [false; 4],
            bluetooth_disabled: false,
            bluetooth_reported_disabled: false,
            reenabling: false,
            inquiry_remains: false,
            calibration: 0,
            calibration_tries: CALIBRATION_TRIES,
            calibration_waited: 0,
            calibration_cut: false,
            bluetooth: Bluetooth::of(params.bluetooth),
            hid: HidDevices::default(),
            counters: Counters::default(),
            timers: Timers::default(),
            asked: None,
            requests: VecDeque::new(),
            mode: None,
            single_stream: false,
            workaround: None,
            phase: None,
            bluetooth_power: 0,
            low_gain: false,
            bluetooth_lna: 0,
            tdma_case: 0,
            tdma_on: false,
            timer_base: 0,
            toggling: false,
            toggle_changed: false,
            transmit_limit: false,
            aggregate_limit: false,
            limited: Limited::default(),
        }
    }

    /// From here on, each call waits for a calibration a few steps at most;
    /// the wait's 600 ms add up over calls.
    pub fn bound_waits(&mut self) {
        self.calibration_tries = RUNTIME_CALIBRATION_TRIES;
    }

    /// Whether a path changed while a calibration ran, once each time.
    pub fn take_cut_wait(&mut self) -> bool {
        core::mem::take(&mut self.calibration_cut)
    }

    /// `coex_stat->wl_force_lps_ctrl`, which `rtw_enter_lps` obeys.
    pub fn stays_awake(&self) -> bool {
        self.stays_awake
    }

    /// Whether [`Event::Tick`] at `now` would find anything to do.
    pub fn deadline_passed(&self, now: u64) -> bool {
        let timers = &self.timers;
        let passed = |at: Option<u64>| at.is_some_and(|at| at <= now);
        self.asked
            .as_ref()
            .is_some_and(|(_, deadline)| *deadline <= now)
            || [
                timers.relink,
                timers.reenable,
                timers.defreeze,
                timers.wifi_remains,
                timers.inquiry_remains,
                timers.connecting,
                timers.multi_link_remains,
            ]
            .into_iter()
            .any(passed)
    }

    /// `coex_stat->bt_disabled`, as `rtw_coex_monitor_bt_enable` reads it.
    pub fn bluetooth_off<I: Io>(io: &mut I) -> Result<bool, Error> {
        Ok(io.read16(REG_WIFI_BT_INFO)? & SCORE_ON == 0)
    }

    fn write8_set<I: Io>(io: &mut I, register: u32, bits: u8) -> Result<(), Error> {
        let value = io.read8(register)?;
        Ok(io.write8(register, value | bits)?)
    }

    fn write8_clear<I: Io>(io: &mut I, register: u32, bits: u8) -> Result<(), Error> {
        let value = io.read8(register)?;
        Ok(io.write8(register, value & !bits)?)
    }

    fn write32_set<I: Io>(io: &mut I, register: u32, bits: u32) -> Result<(), Error> {
        let value = io.read32(register)?;
        Ok(io.write32(register, value | bits)?)
    }

    fn write32_clear<I: Io>(io: &mut I, register: u32, bits: u32) -> Result<(), Error> {
        let value = io.read32(register)?;
        Ok(io.write32(register, value & !bits)?)
    }

    fn write8_bit<I: Io>(io: &mut I, register: u32, bit: u8, set: bool) -> Result<(), Error> {
        if set {
            Self::write8_set(io, register, bit)
        } else {
            Self::write8_clear(io, register, bit)
        }
    }

    /// `check_hw_ready` of the arbiter's window: `ltecoex_read_reg`'s budget.
    fn arbiter_ready<I: Io>(io: &mut I) -> Result<(), Error> {
        for _ in 0..1000 {
            if io.read32(REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1)? & LTECOEX_READY != 0 {
                return Ok(());
            }
            io.delay_us(10);
        }
        Err(Error::ArbiterBusy)
    }

    /// `rtw_coex_read_indirect_reg`.
    pub(super) fn arbiter_read<I: Io>(io: &mut I, address: u32) -> Result<u32, Error> {
        Self::arbiter_ready(io)?;
        io.write32(
            REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1,
            0x800f_0000 | address,
        )?;
        Ok(io.read32(REG_WL2LTECOEX_INDIRECT_ACCESS_READ_DATA_V1)?)
    }

    /// `rtw_coex_write_indirect_reg`.
    pub(super) fn arbiter_write<I: Io>(
        io: &mut I,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        let old = Self::arbiter_read(io, address)?;
        let new = (old & !mask) | ((value << mask.trailing_zeros()) & mask);
        Self::arbiter_ready(io)?;
        io.write32(REG_WL2LTECOEX_INDIRECT_ACCESS_WRITE_DATA_V1, new)?;
        Ok(io.write32(
            REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1,
            0xc00f_0000 | address,
        )?)
    }

    /// `rtw_coex_set_gnt_bt` and `rtw_coex_set_gnt_wl`.
    fn grants<I: Io>(io: &mut I, bluetooth: u32, wifi: u32) -> Result<(), Error> {
        Self::arbiter_write(io, LTE_COEX_CTRL, 0xc000, bluetooth)?;
        Self::arbiter_write(io, LTE_COEX_CTRL, 0x0c00, bluetooth)?;
        Self::arbiter_write(io, LTE_COEX_CTRL, 0x3000, wifi)?;
        Self::arbiter_write(io, LTE_COEX_CTRL, 0x0300, wifi)
    }

    /// `rtw_coex_coex_ctrl_owner`; `btg_reg` is 8822B's alone.
    fn owner<I: Io>(io: &mut I, wifi: bool) -> Result<(), Error> {
        Self::write8_bit(io, REG_SYS_SDIO_CTRL + 3, MUX_CONTROL_PATH, wifi)
    }

    /// `coex_set_rfe_type`. `rtw8822c_coex_cfg_rfe_type` keeps LTE
    /// coexistence off; `rtw8821c_coex_cfg_rfe_type` only reads the board,
    /// which [`Switch::of`] did.
    fn rfe<I: Io>(&self, io: &mut I) -> Result<(), Error> {
        if self.chip == Chip::Rtl8821C {
            return Ok(());
        }
        Self::arbiter_write(io, LTE_COEX_CTRL, LTE_COEX_ENABLE, 0)?;
        Self::arbiter_write(io, LTE_WL_TRX_CTRL, 0xffff, 0xffff)?;
        Self::arbiter_write(io, LTE_BT_TRX_CTRL, 0xffff, 0xffff)
    }

    /// `rtw8822c_coex_cfg_gnt_debug` and `rtw8821c_coex_cfg_gnt_debug`.
    fn debug_pins<I: Io>(&self, io: &mut I) -> Result<(), Error> {
        if self.chip == Chip::Rtl8821C {
            Self::write32_clear(io, REG_PAD_CTRL1, BTGP_SPI_EN)?;
            Self::write32_clear(io, REG_PAD_CTRL1, BTGP_JTAG_EN)?;
            Self::write32_clear(io, REG_GPIO_MUXCFG, FSPI_EN)?;
            Self::write32_clear(io, REG_PAD_CTRL1, LED1_DISABLE)?;
            Self::write32_clear(io, REG_SYS_SDIO_CTRL, SDIO_INTERRUPT)?;
            return Self::write32_clear(io, REG_SYS_SDIO_CTRL, DEBUG_GRANTS);
        }
        Self::write8_clear(io, REG_PAD_CTRL1 + 2, 1 << 4)?;
        Self::write8_clear(io, REG_PAD_CTRL1 + 3, 1 << 0)?;
        Self::write8_clear(io, REG_GPIO_MUXCFG + 2, 1 << 3)?;
        Self::write8_clear(io, REG_PAD_CTRL1 + 1, 1 << 7)?;
        Self::write8_clear(io, REG_SYS_SDIO_CTRL + 3, 1 << 3)
    }

    /// `rtw_coex_set_ant_switch`: `rtw8821c_coex_cfg_ant_switch` on a board
    /// with a switch; the RTL8822C has none to steer.
    fn ant_switch<I: Io>(
        &mut self,
        io: &mut I,
        (control, position): (Control, Position),
    ) -> Result<(), Error> {
        let Some(switch) = self.switch.filter(|switch| switch.exists) else {
            return Ok(());
        };
        if self.switch_status == (control, position) {
            return Ok(());
        }
        self.switch_status = (control, position);
        let (control, position) = if switch.wifi_g_at_bluetooth {
            let position = if switch.inverse {
                Position::WifiA
            } else {
                Position::WifiGBluetooth
            };
            (Control::Baseband, position)
        } else {
            (control, position)
        };
        // Wi-Fi's own pins (not BT's), either polarity's select.
        let (straight, crossed) = if switch.inverse { (1, 2) } else { (2, 1) };
        Self::write32_clear(io, REG_LED_CFG, DPDT_SEL_EN)?;
        Self::write32_set(io, REG_LED_CFG, DPDT_WL_SEL)?;
        let (pins, select) = match control {
            Control::Baseband => {
                let select = match position {
                    Position::WifiGBluetooth if !matches!(switch.module, 2 | 4) => 3,
                    Position::WifiGBluetooth => straight,
                    Position::Bluetooth | Position::WifiA | Position::NoCare => crossed,
                };
                (DPDT_CTRL_PIN, select)
            }
            Control::Pta => (PTA_CTRL_PIN, straight),
        };
        io.write8(REG_RFE_CTRL8, pins)?;
        let value = io.read32(REG_RFE_CTRL8)?;
        io.write32(
            REG_RFE_CTRL8,
            (value & !(0xf << RFE_SEL_15_SHIFT)) | (select << RFE_SEL_15_SHIFT),
        )?;
        Self::write8_set(io, REG_CTRL_TYPE, CTRL_TYPES)
    }

    /// `rtw_coex_set_table`.
    fn write_table<I: Io>(io: &mut I, force: bool, table: Table) -> Result<(), Error> {
        if !force
            && io.read32(REG_BT_COEX_TABLE0)? == table.bluetooth
            && io.read32(REG_BT_COEX_TABLE1)? == table.wifi
        {
            return Ok(());
        }
        io.write32(REG_BT_COEX_TABLE0, table.bluetooth)?;
        io.write32(REG_BT_COEX_TABLE1, table.wifi)?;
        Ok(io.write32(REG_BT_COEX_BRK_TABLE, BREAK_TABLE)?)
    }

    /// `rtw_coex_table`'s entry for `case`: a separate-antenna board's run
    /// from 100, so that case 1 is none.
    fn table_entry(&self, case: u8) -> Option<Table> {
        if self.shared {
            self.params.shared_tables.get(usize::from(case)).copied()
        } else {
            self.params
                .separate_tables
                .get(usize::from(case.wrapping_sub(100)))
                .copied()
        }
    }

    /// `rtw_coex_table`.
    fn table<I: Io>(&mut self, step: &mut Step<'_, I>, force: bool, case: u8) -> Result<(), Error> {
        let entry = self.table_entry(case);
        if let Some(table) = entry {
            Self::write_table(step.io, force || step.reason == Reason::Sleep, table)?;
        }
        if self.toggle_changed {
            Self::toggle_table(step, entry);
        }
        Ok(())
    }

    /// `rtw_btc_wltoggle_table_a`.
    fn toggle_table<I>(step: &mut Step<'_, I>, entry: Option<Table>) {
        let table = entry.map_or(TOGGLE_TABLE, |table| table.wifi);
        let [one, two, three, four] = table.to_le_bytes();
        step.command(control(CONTROL_TOGGLE_TABLE_A, [1, one, two, three, four]));
    }

    /// `rtw_btc_wltoggle_table_b`.
    fn toggle_slot<I>(step: &mut Step<'_, I>, interval: u8) {
        let [one, two, three, four] = TOGGLE_SLOT.to_le_bytes();
        step.command(control(
            CONTROL_TOGGLE_TABLE_B,
            [interval, one, two, three, four],
        ));
    }

    /// `rtw_coex_write_scbd`, whose bit 1 stays set while this side runs.
    fn scoreboard<I: Io>(&mut self, io: &mut I, bits: u16, set: bool) -> Result<(), Error> {
        let base = self.score | 2;
        let value = if !self.params.new_scoreboard_10 && bits & SCORE_FIX_2M != 0 {
            // The older bit 10 asks for a fixed 2 Mb/s, the other bits kept.
            if set {
                base & !SCORE_FIX_2M
            } else {
                base | SCORE_FIX_2M
            }
        } else if set {
            base | bits
        } else {
            base & !bits
        };
        if value != self.score {
            self.score = value;
            io.write16(REG_WIFI_BT_INFO, value | BT_INTERRUPT_ENABLE)?;
        }
        Ok(())
    }

    /// `rtw_coex_set_wl_pri_mask`.
    fn priority<I: Io>(io: &mut I, bit: u8, set: bool) -> Result<(), Error> {
        Self::write8_bit(
            io,
            REG_BT_COEX_TABLE_H + u32::from(bit / 8),
            1 << (bit % 8),
            set,
        )
    }

    /// `rtw_coex_power_on_setting`, the path going to Bluetooth.
    pub fn power_on<I: Io>(&mut self, io: &mut I) -> Result<(), Error> {
        self.stopped = true;
        Self::write8_set(io, REG_SYS_FUNC_EN, BASEBAND_ENABLE)?;
        let bluetooth_off = Self::bluetooth_off(io)?;
        self.bluetooth_disabled = bluetooth_off;
        self.rfe(io)?;
        Self::owner(io, bluetooth_off)?;
        self.ant_switch(io, (Control::Baseband, Position::Bluetooth))?;
        if let Some(table) = self.table_entry(1) {
            Self::write_table(io, true, table)?;
        }
        // The "red x" workaround.
        io.write8(0xff1a, 0)?;
        self.debug_pins(io)
    }

    /// `rtw8822c_coex_cfg_init` and `rtw8821c_coex_cfg_init`.
    fn hardware<I: Io>(&self, io: &mut I, report: &Report) -> Result<(), Error> {
        Self::write8_set(io, REG_BCN_CTRL, BCN_FUNCTION_ENABLE)?;
        let time = io.read8(REG_BT_TDMA_TIME)?;
        io.write8(REG_BT_TDMA_TIME, (time & !0x3f) | 5)?;
        io.write8(REG_BT_STAT_CTRL, 1)?;
        let pins = io.read32(REG_GPIO_MUXCFG)?;
        io.write32(REG_GPIO_MUXCFG, pins | PTA_PINS)?;
        Self::write8_set(io, REG_QUEUE_CTRL, PTA_WL_TX_ENABLE)?;
        Self::write8_clear(io, REG_QUEUE_CTRL, PTA_EDCCA_ENABLE)?;
        let polarity = io.read16(REG_BT_COEX_V2)?;
        io.write16(REG_BT_COEX_V2, polarity | GNT_BT_POLARITY)?;
        if self.chip == Chip::Rtl8821C {
            // The beacon queue always high priority.
            return Self::write8_set(io, REG_BT_COEX_TABLE_H + 3, BCN_QUEUE_PRIORITY);
        }
        Self::write8_clear(io, REG_DUMMY_PAGE4_V1, BTCCA_CONTROL)?;
        // SAFETY: `init`'s caller holds this epoch's report and quiet RF.
        let mut rf = unsafe { Registers::new(io, report) }?;
        Ok(rf.write(Path::B, RF_MODOPT, RF_MASK, RF_MODOPT_DEFAULT)?)
    }

    /// `__rtw_coex_init_hw_config`: a chip alone takes the antennas; one with a
    /// Bluetooth half starts with them on Bluetooth's schedule.
    ///
    /// # Safety
    /// As [`Self::power_on`], with firmware running.
    pub unsafe fn init<I: Io>(&mut self, io: &mut I, report: &Report) -> Result<Run, Error> {
        // rtw_coex_init_coex_var's cleared `coex_dm`.
        self.switch_status = SWITCH_CLEARED;
        self.version = io.read8(0xf1)? >> 4;
        let bluetooth_off = Self::bluetooth_off(io)?;
        self.bluetooth_disabled = bluetooth_off;
        let mut step = Step {
            io,
            report,
            now: 0,
            wifi: Wifi::default(),
            reason: Reason::Status,
            run: Run::default(),
        };
        // rtw_coex_wl_slot_extend of its first `false`.
        step.command(control(CONTROL_LEAK_AP, [LEAK_DISABLE_5MS, 0, 0, 0, 0]));
        Self::write8_set(step.io, REG_BCN_CTRL, BCN_FUNCTION_ENABLE)?;
        self.rfe(step.io)?;
        self.hardware(step.io, report)?;
        Self::priority(step.io, PRIORITY_TX_RESPONSE, true)?;
        Self::priority(step.io, PRIORITY_TX_BEACON, true)?;
        Self::priority(step.io, PRIORITY_TX_BEACON_QUEUE, true)?;
        if self.combined && !bluetooth_off {
            Self::grants(step.io, GRANT_HIGH, GRANT_LOW)?;
        } else {
            Self::grants(step.io, GRANT_LOW, GRANT_HIGH)?;
        }
        Self::owner(step.io, true)?;
        self.ant_switch(step.io, (Control::Baseband, Position::Bluetooth))?;
        self.stopped = !self.combined;
        self.freeze = self.combined;
        self.scoreboard(step.io, SCORE_ACTIVE | SCORE_ON, true)?;
        self.table(&mut step, true, 1)?;
        self.tdma(&mut step, true, 0, false)?;
        self.query_bluetooth(&mut step);
        Ok(step.run)
    }

    /// `rtw_coex_query_bt_info`.
    fn query_bluetooth<I>(&self, step: &mut Step<'_, I>) {
        if !self.bluetooth_disabled {
            step.command((COMMAND_QUERY_BT | (1 << 8), 0));
        }
    }

    /// `rtw8822c_coex_cfg_gnt_fix`.
    fn gnt_fix<I: Io>(&mut self, step: &mut Step<'_, I>) -> Result<(), Error> {
        // rtw8821c_coex_cfg_gnt_fix is empty.
        if self.chip == Chip::Rtl8821C || self.workaround == self.mode {
            return Ok(());
        }
        self.workaround = self.mode;
        let mut rf_1 = if (self.version == 0 && self.five_ghz) || self.freerun {
            0x40021
        } else {
            0x40000
        };
        if self.shared {
            rf_1 |= 1 << 13;
        }
        {
            // SAFETY: `notify`'s caller holds this epoch's report and quiet RF.
            let mut rf = unsafe { Registers::new(&mut *step.io, step.report) }?;
            rf.write(Path::B, RF_MODOPT, RF_MASK, rf_1)?;
        }
        let io = &mut *step.io;
        let free = self.mode == Some(Mode::Free);
        if free {
            Self::write8_clear(io, REG_ANAPAR + 2, ANAPAR_BTPS)?;
        } else {
            Self::write8_set(io, REG_ANAPAR + 2, ANAPAR_BTPS)?;
            Self::write8_clear(io, REG_RSTB_SEL + 1, DAC_OFF_ENABLE)?;
            Self::write8_set(io, REG_RSTB_SEL + 3, DAC_OFF_ENABLE)?;
        }
        Self::write8_set(io, REG_IGN_GNTBT4, IGNORE_GNT_BT)?;
        if free {
            Self::write8_set(io, REG_IGN_GNT_BT1, IGNORE_GNT_BT)?;
            Self::write8_set(io, REG_NOMASK_TXBT, NOMASK_TXBT)
        } else if self.mode == Some(Mode::FiveGhz) || self.five_ghz || !self.shared {
            if self.version >= 3 {
                Self::write8_clear(io, REG_IGN_GNT_BT1, IGNORE_GNT_BT)?;
                Self::write8_set(io, REG_NOMASK_TXBT, NOMASK_TXBT)
            } else {
                Self::write8_set(io, REG_IGN_GNT_BT1, IGNORE_GNT_BT)
            }
        } else {
            Self::write8_clear(io, REG_IGN_GNT_BT1, IGNORE_GNT_BT)?;
            if self.version >= 3 {
                Self::write8_clear(io, REG_NOMASK_TXBT, NOMASK_TXBT)?;
            }
            Ok(())
        }
    }

    /// `rtw_coex_check_rfk`: the path's owner must not change under a
    /// calibration of either side.
    fn await_calibrations<I: Io>(&mut self, io: &mut I) -> Result<(), Error> {
        if !self.shared || self.calibration == CALIBRATION_ABANDONED {
            return Ok(());
        }
        for _ in 0..self.calibration_tries {
            let bluetooth = io.read16(REG_WIFI_BT_INFO)? & SCORE_BT_CALIBRATING != 0;
            let wifi = io.read8(REG_ARFR4)? & WL_CALIBRATING != 0;
            if !bluetooth && !wifi {
                self.calibration_waited = 0;
                return Ok(());
            }
            if self.calibration_waited >= CALIBRATION_TRIES {
                break;
            }
            self.calibration_waited += 1;
            io.delay_us(CALIBRATION_STEP_US);
        }
        if self.calibration_waited >= CALIBRATION_TRIES {
            self.calibration = CALIBRATION_ABANDONED;
        } else {
            self.calibration_cut = true;
        }
        Ok(())
    }

    /// `rtw_coex_set_ant_path`, with no antenna switch to steer.
    fn set_path<I: Io>(&mut self, io: &mut I, force: bool, phase: Phase) -> Result<(), Error> {
        if !force && self.phase == Some(phase) {
            return Ok(());
        }
        self.phase = Some(phase);
        self.await_calibrations(io)?;
        let wifi = match phase {
            Phase::TwoGhz => GRANT_PTA,
            Phase::FiveGhz | Phase::Freerun => GRANT_HIGH,
        };
        Self::grants(io, GRANT_PTA, wifi)?;
        Self::owner(io, true)?;
        let switch = match phase {
            Phase::TwoGhz => (Control::Pta, Position::NoCare),
            Phase::FiveGhz => (Control::Baseband, Position::WifiA),
            Phase::Freerun => (Control::Baseband, Position::WifiGBluetooth),
        };
        self.ant_switch(io, switch)
    }

    /// `wl_rf_para_tx[level]` or `wl_rf_para_rx[level]`. A level past the
    /// chip's table, which only a game controller asks for and only a chip
    /// with HID reports finds, takes its last.
    fn rf_level(&self, transmitting: bool, level: usize) -> RfLevels {
        let table = if transmitting {
            self.params.transmit_rf
        } else {
            self.params.receive_rf
        };
        table[level.min(table.len() - 1)]
    }

    /// `rtw_coex_set_rf_para`.
    fn set_rf<I: Io>(&mut self, step: &mut Step<'_, I>, levels: RfLevels) -> Result<(), Error> {
        let offset = if self.freerun && !self.scanned { 3 } else { 0 };
        self.set_bluetooth_power(step, levels.bluetooth_power + offset);
        self.set_low_gain(step, levels.low_gain)?;
        self.set_bluetooth_lna(step, levels.bluetooth_lna)
    }

    /// `rtw_coex_set_bt_tx_power`.
    fn set_bluetooth_power<I>(&mut self, step: &mut Step<'_, I>, level: u8) {
        if level != self.bluetooth_power {
            self.bluetooth_power = level;
            let index = u32::from(0u8.wrapping_sub(level));
            step.command((COMMAND_BT_POWER | (index << 8), 0));
        }
    }

    /// `rtw8822c_coex_cfg_wl_rx_gain`; the RTL8821C's is empty.
    fn set_low_gain<I: Io>(&mut self, step: &mut Step<'_, I>, low: bool) -> Result<(), Error> {
        if low == self.low_gain {
            return Ok(());
        }
        self.low_gain = low;
        if self.chip == Chip::Rtl8821C {
            return Ok(());
        }
        let (rckd, rck) = if low { (0x22, 0x36) } else { (0x20, 0) };
        // SAFETY: `notify`'s caller holds this epoch's report and quiet RF.
        let mut rf = unsafe { Registers::new(&mut *step.io, step.report) }?;
        for path in [Path::A, Path::B] {
            rf.write(path, RF_RCKD, RF_MASK, rckd)?;
            rf.write(path, RF_RCK, RF_MASK, rck)?;
        }
        Ok(())
    }

    /// `rtw_coex_set_bt_rx_gain`.
    fn set_bluetooth_lna<I: Io>(&mut self, step: &mut Step<'_, I>, level: u8) -> Result<(), Error> {
        if level == self.bluetooth_lna {
            return Ok(());
        }
        self.bluetooth_lna = level;
        if level < 7 {
            self.ask(step, Request::LnaConstraint(level));
        }
        self.scoreboard(step.io, SCORE_RX_GAIN, level < 7)
    }

    /// `rtw_coex_info_request`, its wait for the answer left to [`Event::Answer`].
    fn ask<I>(&mut self, step: &mut Step<'_, I>, request: Request) {
        self.requests.push_back(request);
        self.ask_next(step);
    }

    fn ask_next<I>(&mut self, step: &mut Step<'_, I>) {
        if self.asked.is_some() {
            return;
        }
        let Some(request) = self.requests.pop_front() else {
            return;
        };
        step.command(match request {
            Request::ScanType => query(OP_SCAN_TYPE, 0),
            Request::LnaConstraint(level) => query(OP_LNA_CONSTRAINT, level),
        });
        self.asked = Some((request, step.now + REQUEST_TIMEOUT_US));
    }

    /// `rtw_coex_info_response`.
    fn answered<I>(&mut self, step: &mut Step<'_, I>, payload: &[u8]) {
        if payload.first() != Some(&ANSWER_FROM_FIRMWARE) {
            return;
        }
        if let Some((Request::ScanType, _)) = self.asked
            && let Some(&kind) = payload.get(3)
        {
            self.bluetooth.scan_answer(kind);
        }
        self.asked = None;
        self.ask_next(step);
    }

    /// `rtw_coex_tdma_timer_base`.
    fn set_timer_base<I>(&mut self, step: &mut Step<'_, I>, kind: u8) {
        if self.timer_base == kind {
            return;
        }
        self.timer_base = kind;
        let interval = step.wifi.beacon_interval;
        let slots = if kind == TIMER_FOUR_SLOT && interval < 120 {
            SLOT_FOUR
        } else if (1..80).contains(&interval) {
            (100_u16.div_ceil(interval) & 0x3f) as u8
        } else if interval >= 180 {
            let times = interval / 100 - u16::from(interval % 100 <= 80);
            (times & 0x3f) as u8 | SLOT_TBTT_DIVIDE
        } else {
            SLOT_TWO
        };
        step.command(control(CONTROL_TDMA_SLOT, [slots, 0, 0, 0, 0]));
    }

    /// `rtw_coex_set_tdma`, from `rtw_coex_power_save_state` of a schedule
    /// firmware keeps only awake or of none.
    fn set_tdma<I>(&mut self, step: &mut Step<'_, I>, para: [u8; 5]) {
        self.stays_awake =
            (para[0] & (1 << 4) != 0 && para[0] & (1 << 5) == 0) || self.mode == Some(Mode::Free);
        if step.wifi.asleep {
            if self.stays_awake {
                step.command(tdma([0; 5]));
            }
            step.run.orders.push(Order::Wake);
        }
        step.command(tdma(para));
        if para[0] & (1 << 2) != 0 {
            self.toggling = true;
            self.toggle_changed = false;
        } else {
            self.toggle_changed = self.toggling;
            self.toggling = false;
        }
    }

    /// `rtw_coex_tdma`.
    fn tdma<I: Io>(
        &mut self,
        step: &mut Step<'_, I>,
        force: bool,
        case: u8,
        four_slot: bool,
    ) -> Result<(), Error> {
        self.set_timer_base(step, if four_slot { TIMER_FOUR_SLOT } else { 0 });
        let on = case != 0 && case != 100;
        if !force && on == self.tdma_on && case == self.tdma_case {
            return Ok(());
        }
        let bluetooth = &self.bluetooth;
        let keep_clear =
            (bluetooth.a2dp && (self.inquiry_remains || bluetooth.multi_link)) || !step.wifi.busy;
        self.scoreboard(step.io, SCORE_TDMA, !keep_clear)?;
        self.tdma_on = on;
        self.tdma_case = case;
        let para = if self.shared {
            self.params.shared_tdma.get(usize::from(case))
        } else {
            self.params
                .separate_tdma
                .get(usize::from(case.wrapping_sub(100)))
        };
        if let Some(&para) = para {
            self.set_tdma(step, para);
        }
        Ok(())
    }

    /// `rtw_coex_update_wl_ch_info`, with no 5 GHz hop map: a shared antenna
    /// leaves Bluetooth all of 2.4 GHz, and one of its own has it skip the
    /// channel.
    fn channel_info<I>(&self, step: &mut Step<'_, I>, connected: bool) {
        let (mut link, mut channel, mut width) = (0, 0, 0);
        let leaves_all = self.shared && self.mode != Some(Mode::Free);
        if connected && step.wifi.channel != 0 && !(leaves_all && step.wifi.channel <= 14) {
            channel = step.wifi.channel;
            width = step.wifi.width;
            if channel <= 14 {
                link = 1;
                width = if width == 1 { HOP_SPAN_40 } else { HOP_SPAN_20 };
            }
        }
        step.command((
            COMMAND_CHANNEL_INFO
                | (link << 8)
                | (u32::from(channel) << 16)
                | (u32::from(width) << 24),
            0,
        ));
    }

    /// `rtw_coex_wl_noisy_detect`.
    fn detect_noise(&mut self, frames: u32) {
        if self.busy {
            return;
        }
        let band = match frames {
            0..=99 => 0,
            100..=250 => 1,
            _ => 2,
        };
        if self.noise_counts[band] < 5 {
            self.noise_counts[band] += 1;
        }
        if self.noise_counts[band] == 5 {
            self.noise_counts = [0; 3];
            self.noise_counts[band] = 5;
        }
        self.noise = match self.noise_counts {
            [_, _, 5] => 2,
            [_, 5, _] => 1,
            _ => 0,
        };
    }

    /// `rtw_coex_update_wl_link_info`.
    fn update_link<I: Io>(&mut self, step: &mut Step<'_, I>) -> Result<(), Error> {
        let wifi = step.wifi;
        self.connected = wifi.connected;
        if wifi.busy != self.busy {
            if wifi.busy {
                self.busy = true;
            } else {
                self.timers
                    .wifi_remains
                    .get_or_insert(step.now + 12 * SECOND_US);
            }
        }
        self.transmitting = wifi.transmitting;
        self.linkscan = wifi.scanning
            || matches!(
                step.reason,
                Reason::Scanning | Reason::Connecting | Reason::TwoGhz
            );
        self.detect_noise(wifi.cck_frames);
        for (high, step_level) in self.rssi_high.iter_mut().zip(self.params.wifi_rssi_steps) {
            *high = rssi_high(*high, wifi.rssi, step_level);
        }
        let scanning = self.linkscan || self.connecting_task || self.scanning_task || self.busy;
        self.scoreboard(step.io, SCORE_SCAN, scanning)?;
        self.five_ghz = match step.reason {
            Reason::FiveGhz => true,
            Reason::Scanning | Reason::Connecting | Reason::TwoGhz => false,
            Reason::Bluetooth | Reason::Sleep | Reason::Media | Reason::Status => wifi.five_ghz,
        };
        Ok(())
    }

    /// `rtw_coex_monitor_bt_enable`.
    fn monitor_enable<I: Io>(&mut self, step: &mut Step<'_, I>) -> Result<(), Error> {
        let disabled = Self::bluetooth_off(step.io)?;
        if self.bluetooth_disabled == disabled {
            return Ok(());
        }
        self.bluetooth_disabled = disabled;
        self.bluetooth.disabled();
        self.bluetooth_lna = 0;
        self.reenabling = !disabled;
        if !disabled {
            self.timers
                .reenable
                .get_or_insert(step.now + 15 * SECOND_US);
        }
        Ok(())
    }

    /// `rtw_coex_limited_tx`.
    fn limit_transmissions<I: Io>(&mut self, io: &mut I, limit: bool) -> Result<(), Error> {
        if self.transmit_limit == limit && self.aggregate_limit == limit {
            return Ok(());
        }
        if !self.transmit_limit {
            self.limited.darfrc = io.read32(REG_DARFRC)?;
            self.limited.darfrch = io.read32(REG_DARFRCH)?;
            self.limited.retry_limit = io.read16(REG_RETRY_LIMIT)?;
        }
        if !self.aggregate_limit {
            self.limited.aggregate_time = io.read8(REG_AMPDU_MAX_TIME_V1)?;
        }
        self.transmit_limit = limit;
        self.aggregate_limit = limit;
        if limit {
            Self::write8_set(io, REG_TX_HANG_CTRL, GNT_BT_AWAKE)?;
            Self::write8_set(io, REG_LIFETIME_EN, 0xf)?;
            io.write16(REG_RETRY_LIMIT, 0x0808)?;
            io.write32(REG_DARFRC, 0x0100_0000)?;
            io.write32(REG_DARFRCH, 0x0403_0201)?;
            Ok(io.write8(REG_AMPDU_MAX_TIME_V1, 0x20)?)
        } else {
            Self::write8_clear(io, REG_TX_HANG_CTRL, GNT_BT_AWAKE)?;
            Self::write8_clear(io, REG_LIFETIME_EN, 0xf)?;
            io.write16(REG_RETRY_LIMIT, self.limited.retry_limit)?;
            io.write32(REG_DARFRC, self.limited.darfrc)?;
            io.write32(REG_DARFRCH, self.limited.darfrch)?;
            Ok(io.write8(REG_AMPDU_MAX_TIME_V1, self.limited.aggregate_time)?)
        }
    }

    /// What `plan` settles, in the order rtw88's actions take it.
    fn enact<I: Io>(&mut self, step: &mut Step<'_, I>, plan: Plan) -> Result<(), Error> {
        if plan.free {
            self.mode = Some(Mode::Free);
        }
        if plan.freerun {
            self.freerun = true;
            self.channel_info(step, true);
        }
        self.set_path(step.io, false, plan.phase)?;
        if plan.freerun {
            self.scoreboard(step.io, SCORE_FIX_2M, false)?;
        }
        self.set_rf(step, plan.rf)?;
        self.table(step, false, plan.table)?;
        if let Some(interval) = plan.toggle {
            Self::toggle_table(step, self.table_entry(plan.table));
            Self::toggle_slot(step, interval);
        }
        self.tdma(step, false, plan.tdma, plan.four_slot)
    }

    /// `rtw_coex_run_coex`.
    fn run_coex<I: Io>(&mut self, step: &mut Step<'_, I>, reason: Reason) -> Result<(), Error> {
        step.reason = reason;
        self.update_link(step)?;
        self.monitor_enable(step)?;
        if self.freeze && reason == Reason::Bluetooth && !self.bluetooth.setting_up {
            return Ok(());
        }
        self.freerun = false;
        if self.five_ghz {
            // rtw_coex_action_wl_under5g.
            self.mode = Some(if self.bluetooth.game_controller && self.linkscan {
                Mode::Free
            } else {
                Mode::FiveGhz
            });
            self.set_path(step.io, true, Phase::FiveGhz)?;
            self.set_rf(step, self.params.receive_rf[0])?;
            self.scoreboard(step.io, SCORE_FIX_2M, false)?;
            let case = if self.shared { 0 } else { 100 };
            self.table(step, false, case)?;
            self.tdma(step, false, case, false)?;
        } else {
            self.mode = Some(Mode::TwoGhz);
            self.enact(step, self.plan())?;
        }
        let free = self.mode == Some(Mode::Free);
        if self.params.mimo_ps {
            self.set_single_stream(step, free && reason == Reason::Media, free);
        }
        self.gnt_fix(step)?;
        let idle = self.bluetooth.status == Status::NotConnectedIdle;
        self.limit_transmissions(step.io, !self.five_ghz && !idle)
    }

    /// `rtw_coex_mimo_ps`.
    fn set_single_stream<I>(&mut self, step: &mut Step<'_, I>, force: bool, single: bool) {
        if force || single != self.single_stream {
            self.single_stream = single;
            step.run.orders.push(Order::SingleStream(single));
            self.channel_info(step, step.wifi.connected);
        }
    }

    /// `rtw_coex_bt_hid_info_notify`.
    fn hid_report<I: Io>(&mut self, step: &mut Step<'_, I>, bytes: [u8; 8]) -> Result<(), Error> {
        // A chip without MIMO power save ignores the lists and devices.
        if !self.params.mimo_ps {
            return Ok(());
        }
        let Some(game) = self.hid.report(bytes) else {
            return Ok(());
        };
        if game == self.bluetooth.game_controller {
            return Ok(());
        }
        self.bluetooth.game_controller = game;
        self.run_coex(step, Reason::Status)
    }

    /// `rtw_coex_query_bt_hid_list`.
    fn query_hid_devices<I>(&self, step: &mut Step<'_, I>) {
        if !self.params.mimo_ps {
            return;
        }
        let high_priority = self.counters.high_tx + self.counters.high_rx;
        if !self.bluetooth.may_hold_a_controller(high_priority) {
            return;
        }
        step.command(query_hid(HID_LIST, 0));
        for handle in self.hid.unknown() {
            step.command(query_hid(HID_DEVICE, handle));
        }
    }

    /// `rtw_coex_scan_notify` of a start on 2.4 GHz.
    fn scan_started<I: Io>(&mut self, step: &mut Step<'_, I>) -> Result<(), Error> {
        self.freeze = false;
        self.scoreboard(step.io, SCORE_ACTIVE | SCORE_ON, true)?;
        self.scanning_task = true;
        self.set_path(step.io, true, Phase::TwoGhz)?;
        self.run_coex(step, Reason::Scanning)
    }

    /// `rtw_coex_bt_info_notify`.
    fn bluetooth_report<I: Io>(
        &mut self,
        step: &mut Step<'_, I>,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let Some(source) = bytes.first().map(|byte| byte & 0xf) else {
            return Ok(());
        };
        match source {
            SOURCE_CALIBRATION => {
                self.calibration = bytes.get(1).copied().unwrap_or(0);
                self.calibration_waited = 0;
                return Ok(());
            }
            SOURCE_SCOREBOARD => {
                self.monitor_enable(step)?;
                if self.bluetooth_disabled != self.bluetooth_reported_disabled {
                    self.bluetooth_reported_disabled = self.bluetooth_disabled;
                    self.run_coex(step, Reason::Bluetooth)?;
                }
                return Ok(());
            }
            SOURCE_FIRMWARE => {
                self.update_bluetooth_links(step);
                return Ok(());
            }
            SOURCE_RESPONSE | SOURCE_ACTION => {}
            _ => return Ok(()),
        }
        if self.bluetooth_disabled {
            self.bluetooth_disabled = false;
            self.reenabling = true;
            self.timers
                .reenable
                .get_or_insert(step.now + 15 * SECOND_US);
        }
        let high_priority = (self.counters.high_tx, self.counters.high_rx);
        let Some(changes) = self.bluetooth.report(bytes, high_priority) else {
            return Ok(());
        };
        self.follow_report(step, changes);
        self.update_bluetooth_links(step);
        self.run_coex(step, Reason::Bluetooth)
    }

    /// `rtw_coex_update_bt_link_info`.
    fn update_bluetooth_links<I>(&mut self, step: &mut Step<'_, I>) {
        if self.bluetooth.update_links() {
            self.ask(step, Request::ScanType);
        }
    }

    /// The timers and answers a new report asks for.
    fn follow_report<I>(&mut self, step: &mut Step<'_, I>, changes: Changes) {
        let now = step.now;
        if let Some(inquiring) = changes.inquiring {
            self.timers.inquiry_remains = None;
            if inquiring {
                self.inquiry_remains = true;
            } else {
                self.timers.inquiry_remains = Some(now + 4 * SECOND_US);
            }
        }
        if changes.setting_up {
            let wait = if self.reenabling { 6 } else { 1 };
            self.timers.relink.get_or_insert(now + wait * SECOND_US);
        }
        if changes.multi_link_ended {
            self.timers
                .multi_link_remains
                .get_or_insert(now + 3 * SECOND_US);
        }
        if changes.reset {
            self.channel_info(step, step.wifi.connected);
        }
        if changes.ignoring_wifi {
            // rtw_coex_ignore_wlan_act.
            step.command((COMMAND_IGNORE_WLAN, 0));
        }
    }

    /// `rtw_coex_monitor_bt_ctr`.
    fn read_counters<I: Io>(&mut self, io: &mut I) -> Result<(), Error> {
        let high = io.read32(REG_BT_ACT_STATISTICS)?;
        let low = io.read32(REG_BT_ACT_STATISTICS_1)?;
        io.write8(REG_BT_COEX_ENH_INTR_CTRL, COUNT_BLUETOOTH)?;
        let (high_tx, high_rx) = (high & 0xffff, high >> 16);
        let (low_tx, low_rx) = (low & 0xffff, low >> 16);
        self.counters.high_tx = high_tx;
        self.counters.high_rx = high_rx;
        self.counters.low_tx = low_tx;
        self.counters.low_rx = low_rx;
        let saturated = high_rx > 60000 && high_tx == 60000 && low_rx > 60000 && low_tx == 60000;
        self.counters.trustworthy = !self.sleeping && !saturated;
        Ok(())
    }

    /// rtw88's delayed works that came due.
    fn tick<I: Io>(&mut self, step: &mut Step<'_, I>) -> Result<(), Error> {
        let now = step.now;
        if let Some((_, deadline)) = self.asked
            && deadline <= now
        {
            self.asked = None;
            self.ask_next(step);
        }
        if due(&mut self.timers.reenable, now) {
            self.reenabling = false;
        }
        if due(&mut self.timers.multi_link_remains, now) {
            self.bluetooth.multi_link_remains = false;
        }
        let mut changed = false;
        if due(&mut self.timers.relink, now) {
            self.bluetooth.setting_up = false;
            changed = true;
        }
        if due(&mut self.timers.defreeze, now) {
            self.freeze = false;
            self.connecting_task = false;
            changed = true;
        }
        if due(&mut self.timers.wifi_remains, now) {
            self.busy = step.wifi.busy;
            changed = true;
        }
        if due(&mut self.timers.inquiry_remains, now) {
            self.inquiry_remains = self.bluetooth.inquiring;
            changed = true;
        }
        if due(&mut self.timers.connecting, now) {
            self.connecting = false;
            changed = true;
        }
        if changed {
            self.run_coex(step, Reason::Status)?;
        }
        Ok(())
    }

    /// One of rtw88's notifiers, `event`, on the radio as `wifi` says it is.
    /// Nothing runs on a chip alone (`coex->stop_dm`).
    ///
    /// # Safety
    /// As [`Self::init`], with the radio's frames quiet.
    pub unsafe fn notify<I: Io>(
        &mut self,
        io: &mut I,
        report: &Report,
        now: u64,
        wifi: Wifi,
        event: Event<'_>,
    ) -> Result<Run, Error> {
        let mut step = Step {
            io,
            report,
            now,
            wifi,
            reason: Reason::Status,
            run: Run::default(),
        };
        if self.stopped {
            return Ok(step.run);
        }
        match event {
            Event::ScanStarted => self.scan_started(&mut step)?,
            Event::ScanEnded => {
                self.freeze = false;
                self.scoreboard(step.io, SCORE_ACTIVE | SCORE_ON, true)?;
                self.scanned = true;
                self.scanning_task = false;
                self.run_coex(&mut step, Reason::Status)?;
            }
            Event::Tuned { .. } if wifi.five_ghz => self.run_coex(&mut step, Reason::FiveGhz)?,
            Event::Tuned { scanning: true } => self.scan_started(&mut step)?,
            Event::Tuned { scanning: false } => self.run_coex(&mut step, Reason::TwoGhz)?,
            Event::Connecting => {
                self.scoreboard(step.io, SCORE_ACTIVE | SCORE_ON, true)?;
                self.connecting_task = true;
                self.connecting = true;
                self.timers.connecting.get_or_insert(now + 2 * SECOND_US);
                self.set_path(step.io, true, Phase::TwoGhz)?;
                self.run_coex(&mut step, Reason::Connecting)?;
                // Keeps the case through the exchange, whatever Bluetooth says.
                self.freeze = true;
                self.timers.defreeze.get_or_insert(now + 5 * SECOND_US);
            }
            Event::Connected => {
                self.scoreboard(step.io, SCORE_ACTIVE | SCORE_ON, true)?;
                self.connecting_task = false;
                self.freeze = false;
                self.connecting = false;
                self.run_coex(&mut step, Reason::Status)?;
            }
            Event::Media { connected: true } => {
                self.connecting = false;
                self.scoreboard(step.io, SCORE_ACTIVE, true)?;
                self.set_path(step.io, true, Phase::TwoGhz)?;
                Self::priority(step.io, PRIORITY_RX_CCK, true)?;
                self.run_coex(&mut step, Reason::Media)?;
                self.channel_info(&mut step, true);
            }
            Event::Media { connected: false } => {
                Self::priority(step.io, PRIORITY_RX_CCK, false)?;
                self.run_coex(&mut step, Reason::Status)?;
                self.channel_info(&mut step, false);
            }
            Event::Sleeping(true) => {
                self.sleeping = true;
                self.scoreboard(step.io, SCORE_ACTIVE, false)?;
                self.scoreboard(step.io, SCORE_WL_BUSY, false)?;
                self.run_coex(&mut step, Reason::Sleep)?;
            }
            Event::Sleeping(false) => {
                self.sleeping = false;
                self.scoreboard(step.io, SCORE_ACTIVE, true)?;
                if !self.stays_awake {
                    self.query_bluetooth(&mut step);
                }
                self.run_coex(&mut step, Reason::Sleep)?;
            }
            Event::Traffic => self.run_coex(&mut step, Reason::Status)?,
            Event::Watchdog => {
                if !self.sleeping || self.stays_awake {
                    self.read_counters(step.io)?;
                    self.query_hid_devices(&mut step);
                }
            }
            Event::Bluetooth(bytes) => self.bluetooth_report(&mut step, bytes)?,
            Event::BluetoothHid(bytes) => self.hid_report(&mut step, bytes)?,
            Event::Answer(payload) => self.answered(&mut step, payload),
            Event::Tick => self.tick(&mut step)?,
        }
        Ok(step.run)
    }

    /// `rtw_coex_power_off_setting`.
    pub fn power_off<I: Io>(&mut self, io: &mut I) -> Result<(), Error> {
        self.scoreboard(io, SCORE_ALL, false)?;
        io.write16(REG_WIFI_BT_INFO, BT_INTERRUPT_ENABLE)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::realtek::identity::{Profile, tests::profile};
    use alloc::collections::BTreeMap;

    /// Registers as bytes, and the arbiter's indirect window behind them.
    #[derive(Default)]
    struct Bus {
        bytes: BTreeMap<u32, u8>,
        arbiter: BTreeMap<u32, u32>,
        /// What `REG_WIFI_BT_INFO` reads: Bluetooth's scoreboard, not ours.
        board: Option<u16>,
    }

    impl Bus {
        fn get(&self, register: u32) -> u8 {
            self.bytes.get(&register).copied().unwrap_or(0)
        }
        fn word(&self, register: u32) -> u32 {
            u32::from_le_bytes([0, 1, 2, 3].map(|at| self.get(register + at)))
        }
    }

    // SAFETY: nothing here reaches hardware; this is a map of bytes.
    unsafe impl Io for Bus {
        fn profile(&self) -> Profile {
            profile()
        }
        fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
            Ok(self.get(register))
        }
        fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
            if register == REG_WIFI_BT_INFO
                && let Some(board) = self.board
            {
                return Ok(board);
            }
            Ok(self.get(register) as u16 | (self.get(register + 1) as u16) << 8)
        }
        fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
            Ok(match register {
                REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1 => LTECOEX_READY,
                _ => self.word(register),
            })
        }
        fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
            self.bytes.insert(register, value);
            Ok(())
        }
        fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
            for (at, byte) in value.to_le_bytes().into_iter().enumerate() {
                self.bytes.insert(register + at as u32, byte);
            }
            Ok(())
        }
        fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
            if register == REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1 {
                let address = value & 0xffff;
                if value >> 28 == 0x8 {
                    let held = self.arbiter.get(&address).copied().unwrap_or(0);
                    let read = REG_WL2LTECOEX_INDIRECT_ACCESS_READ_DATA_V1;
                    for (at, byte) in held.to_le_bytes().into_iter().enumerate() {
                        self.bytes.insert(read + at as u32, byte);
                    }
                } else {
                    let data = self.word(REG_WL2LTECOEX_INDIRECT_ACCESS_WRITE_DATA_V1);
                    self.arbiter.insert(address, data);
                }
                return Ok(());
            }
            for (at, byte) in value.to_le_bytes().into_iter().enumerate() {
                self.bytes.insert(register + at as u32, byte);
            }
            Ok(())
        }
        fn delay_us(&mut self, _: u64) {}
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
            panic!("no beacon")
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            panic!("no beacon")
        }
        fn quarantine(&mut self) {}
    }

    /// An arbiter past its start, on a chip with Bluetooth alive.
    struct Rig {
        coex: Coex,
        bus: Bus,
        report: Report,
        wifi: Wifi,
        now: u64,
    }

    impl Rig {
        fn new(shared: bool) -> Self {
            let mut bus = Bus {
                board: Some(SCORE_ON),
                ..Bus::default()
            };
            bus.write32(REG_SYS_CFG1, profile().observed().sys_cfg1)
                .unwrap();
            bus.write16(REG_MCUFW_CTRL, FW_READY).unwrap();
            bus.write8(REG_SYS_FUNC_EN, BASEBAND_ENABLE).unwrap();
            bus.write8(REG_RF_CTRL, 7).unwrap();
            bus.write32(REG_WLRF1, 0x0700_0000).unwrap();
            let mut coex = Coex::of(0x20, u8::from(shared));
            coex.stopped = false;
            Self {
                coex,
                bus,
                report: Report::of_two_paths(profile()),
                wifi: Wifi {
                    connected: true,
                    channel: 6,
                    beacon_interval: 100,
                    ..Wifi::default()
                },
                now: 1_000,
            }
        }

        fn event(&mut self, event: Event<'_>) -> Run {
            // SAFETY: this is a map of bytes.
            unsafe {
                self.coex
                    .notify(&mut self.bus, &self.report, self.now, self.wifi, event)
            }
            .unwrap()
        }

        /// A report from Bluetooth of its `lb2`, `hb1` and `hb2`.
        fn bluetooth(&mut self, low2: u8, high1: u8, high2: u8) -> Run {
            self.event(Event::Bluetooth(&[1, low2, 0, 0, high1, high2, 0]))
        }

        fn tick_to(&mut self, now: u64) -> Run {
            self.now = now;
            self.event(Event::Tick)
        }
    }

    fn commands(run: &Run) -> Vec<(u32, u32)> {
        run.orders
            .iter()
            .filter_map(|order| match order {
                Order::Command(command) => Some(*command),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_running_calibration_holds_a_call_a_few_steps_and_all_calls_600_ms() {
        let mut rig = Rig::new(true);
        rig.bus.board = Some(SCORE_ON | SCORE_BT_CALIBRATING);
        rig.coex.bound_waits();
        // Two 10 ms steps a call, as long as the 60 steps last.
        for call in 1..30 {
            rig.coex.await_calibrations(&mut rig.bus).unwrap();
            assert_eq!(rig.coex.calibration_waited, 2 * call);
            assert!(rig.coex.take_cut_wait());
            assert!(!rig.coex.take_cut_wait(), "told once a call");
        }
        rig.coex.await_calibrations(&mut rig.bus).unwrap();
        assert_eq!(
            rig.coex.calibration, CALIBRATION_ABANDONED,
            "as rtw88 gives up"
        );
        assert!(!rig.coex.take_cut_wait());
        // A new report of Bluetooth's calibration starts the wait again.
        rig.coex.calibration = 0;
        rig.coex.calibration_waited = 0;
        rig.bus.board = Some(SCORE_ON);
        rig.coex.await_calibrations(&mut rig.bus).unwrap();
        assert!(!rig.coex.take_cut_wait());
    }

    #[test]
    fn a_tick_counts_as_work_only_past_a_deadline() {
        let mut coex = Coex::of(0x20, 1);
        assert!(!coex.deadline_passed(u64::MAX));
        coex.timers.connecting = Some(100);
        assert!(!coex.deadline_passed(99));
        assert!(coex.deadline_passed(100));
    }

    #[test]
    fn a_boards_bytes_name_its_bluetooth_half_and_antennas() {
        let coex = Coex::of(0x20, 1);
        assert!(coex.combined && coex.shared);
        let coex = Coex::of(0xff, 0xfe);
        assert!(!coex.combined && !coex.shared);
    }

    #[test]
    fn power_on_hands_a_live_bluetooth_the_path_and_keeps_lte_coexistence_off() {
        let mut bus = Bus::default();
        bus.arbiter.insert(LTE_COEX_CTRL, LTE_COEX_ENABLE | 0x55);
        bus.write16(REG_WIFI_BT_INFO, SCORE_ON).unwrap();
        bus.write8(REG_SYS_SDIO_CTRL + 3, MUX_CONTROL_PATH).unwrap();
        let mut coex = Coex::of(0x20, 1);
        coex.power_on(&mut bus).unwrap();
        assert_eq!(bus.get(REG_SYS_FUNC_EN) & 3, 3);
        assert_eq!(bus.arbiter[&LTE_COEX_CTRL], 0x55);
        assert_eq!(bus.arbiter[&LTE_WL_TRX_CTRL], 0xffff);
        assert_eq!(bus.get(REG_SYS_SDIO_CTRL + 3) & MUX_CONTROL_PATH, 0);
        assert_eq!(bus.word(REG_BT_COEX_TABLE0), 0x5555_5555);
        assert_eq!(bus.word(REG_BT_COEX_BRK_TABLE), BREAK_TABLE);
    }

    #[test]
    fn a_separate_antenna_board_has_no_case_under_100() {
        let coex = Coex::of(0x20, 0);
        assert!(coex.table_entry(1).is_none());
        assert_eq!(coex.table_entry(100).unwrap().wifi, 0xffff_ffff);
        let mut bus = Bus::default();
        Coex::grants(&mut bus, GRANT_LOW, GRANT_HIGH).unwrap();
        // GNT_BT low (0x1) over both of its fields, GNT_WL high (0x3) over its.
        assert_eq!(bus.arbiter[&LTE_COEX_CTRL], 0x7700);
    }

    #[test]
    fn an_rtl8821c_reads_its_own_tables_and_older_scoreboard() {
        let coex = Coex::of_chip(Chip::Rtl8821C, 0, 0x20, 1);
        assert_eq!(coex.table_entry(0).unwrap().wifi, 0x5555_5555);
        assert_eq!(coex.table_entry(13).unwrap().wifi, 0x6aaa_6aaa);
        assert!(coex.table_entry(38).is_none());
        assert_eq!(coex.rf_level(true, 1).bluetooth_power, 20);
        assert_eq!(coex.rf_level(true, 6), TRANSMIT_RF_8821C[5], "its last");
        let mut coex = Coex::of_chip(Chip::Rtl8821C, 0, 0x20, 0);
        assert_eq!(coex.table_entry(123).unwrap().wifi, 0x55ff_55ff);
        assert_eq!(coex.bluetooth.facts, RTL8821C.bluetooth);
        let mut bus = Bus::default();
        // Bit 10 set asks for the fixed 2 Mb/s that a clear call ends.
        coex.scoreboard(&mut bus, SCORE_FIX_2M, false).unwrap();
        assert_eq!(
            bus.word(REG_WIFI_BT_INFO) as u16 & SCORE_FIX_2M,
            SCORE_FIX_2M
        );
        coex.scoreboard(&mut bus, SCORE_FIX_2M, true).unwrap();
        assert_eq!(bus.word(REG_WIFI_BT_INFO) as u16 & SCORE_FIX_2M, 0);
    }

    #[test]
    fn an_rtl8821c_steers_its_antenna_switch_by_phase() {
        let select = |bus: &Bus| (bus.get(REG_RFE_CTRL8), bus.word(REG_RFE_CTRL8) >> 28);
        let mut bus = Bus::default();
        bus.write32(REG_LED_CFG, DPDT_SEL_EN).unwrap();
        let mut coex = Coex::of_chip(Chip::Rtl8821C, 0, 0x20, 1);
        // Power-on's (BBSW, BT) is the cleared status: rtw88 writes nothing.
        coex.power_on(&mut bus).unwrap();
        assert_eq!(bus.get(REG_CTRL_TYPE), 0);
        assert!(bus.arbiter.is_empty(), "no LTE coexistence writes");
        coex.set_path(&mut bus, true, Phase::TwoGhz).unwrap();
        assert_eq!(select(&bus), (PTA_CTRL_PIN, 2));
        assert_eq!(bus.word(REG_LED_CFG), DPDT_WL_SEL);
        assert_eq!(bus.get(REG_CTRL_TYPE), CTRL_TYPES);
        coex.set_path(&mut bus, true, Phase::FiveGhz).unwrap();
        assert_eq!(select(&bus), (DPDT_CTRL_PIN, 1));
        coex.set_path(&mut bus, true, Phase::Freerun).unwrap();
        assert_eq!(select(&bus), (DPDT_CTRL_PIN, 3));
        // RFE 4: Wi-Fi's 2.4 GHz on Bluetooth's port, polarity inverse.
        let (mut bus, mut coex) = (Bus::default(), Coex::of_chip(Chip::Rtl8821C, 4, 0x20, 1));
        coex.set_path(&mut bus, true, Phase::TwoGhz).unwrap();
        assert_eq!(select(&bus), (DPDT_CTRL_PIN, 2), "to WLA, crossed");
        // RFE 2, polarity straight: to WLG_BT on a BTG module.
        let (mut bus, mut coex) = (Bus::default(), Coex::of_chip(Chip::Rtl8821C, 2, 0x20, 1));
        coex.set_path(&mut bus, true, Phase::FiveGhz).unwrap();
        assert_eq!(select(&bus), (DPDT_CTRL_PIN, 2));
        // RFE 6 has no switch.
        let (mut bus, mut coex) = (Bus::default(), Coex::of_chip(Chip::Rtl8821C, 6, 0x20, 1));
        coex.set_path(&mut bus, true, Phase::FiveGhz).unwrap();
        assert_eq!(select(&bus), (0, 0));
        assert_eq!(bus.get(REG_CTRL_TYPE), 0);
    }

    #[test]
    fn an_rtl8821c_sets_up_its_pta_without_the_rtl8822c_extras() {
        let mut bus = Bus::default();
        bus.write32(REG_PAD_CTRL1, BTGP_SPI_EN | BTGP_JTAG_EN | LED1_DISABLE | 1)
            .unwrap();
        bus.write32(REG_SYS_SDIO_CTRL, SDIO_INTERRUPT | DEBUG_GRANTS)
            .unwrap();
        bus.write8(REG_DUMMY_PAGE4_V1, BTCCA_CONTROL).unwrap();
        let coex = Coex::of_chip(Chip::Rtl8821C, 0, 0x20, 1);
        coex.debug_pins(&mut bus).unwrap();
        assert_eq!(bus.word(REG_PAD_CTRL1), 1);
        assert_eq!(bus.word(REG_SYS_SDIO_CTRL), 0);
        // No RF write: the report would refuse this map's 8822C profile.
        let report = Report::of_two_paths(profile());
        coex.hardware(&mut bus, &report).unwrap();
        assert_eq!(bus.get(REG_BT_COEX_TABLE_H + 3), BCN_QUEUE_PRIORITY);
        assert_eq!(bus.get(REG_DUMMY_PAGE4_V1), BTCCA_CONTROL, "untouched");
        assert_eq!(bus.word(REG_GPIO_MUXCFG), PTA_PINS);
    }

    #[test]
    fn the_scoreboard_and_priorities_land_on_their_bits() {
        let mut bus = Bus::default();
        let mut coex = Coex::of(0x20, 0);
        coex.scoreboard(&mut bus, SCORE_ACTIVE | SCORE_ON, true)
            .unwrap();
        assert_eq!(bus.word(REG_WIFI_BT_INFO) as u16, 3 | BT_INTERRUPT_ENABLE);
        Coex::priority(&mut bus, PRIORITY_TX_BEACON_QUEUE, true).unwrap();
        assert_eq!(bus.get(REG_BT_COEX_TABLE_H + 3), 1 << 3);
        Coex::priority(&mut bus, PRIORITY_RX_CCK, true).unwrap();
        Coex::priority(&mut bus, PRIORITY_TX_BEACON_QUEUE, false).unwrap();
        assert_eq!(bus.get(REG_BT_COEX_TABLE_H + 3), 1 << 4);
    }

    #[test]
    fn commands_keep_their_fields_in_rtw88s_bits() {
        assert_eq!(
            control(CONTROL_TOGGLE_TABLE_B, [1, 2, 3, 4, 5]),
            (0x0201_0769, 0x0005_0403)
        );
        assert_eq!(tdma([0x51, 8, 3, 0x10, 0x54]), (0x0308_5160, 0x5410));
        assert_eq!(query(OP_LNA_CONSTRAINT, 5), (0x0532_0067, 0));
    }

    #[test]
    fn a_music_link_splits_the_air_into_four_slots() {
        let mut rig = Rig::new(true);
        rig.wifi.busy = true;
        rig.event(Event::Traffic);
        let run = rig.bluetooth(0x49, 0, 0);
        let commands = commands(&run);
        assert!(commands.contains(&control(CONTROL_TDMA_SLOT, [SLOT_FOUR, 0, 0, 0, 0])));
        assert!(commands.contains(&tdma(SHARED_TDMA[13])));
        assert_eq!(rig.bus.word(REG_BT_COEX_TABLE1), SHARED_TABLES[12].wifi);
        assert!(rig.coex.stays_awake(), "case 13 needs Wi-Fi awake");
        assert_eq!(
            rig.bus.get(REG_WIFI_BT_INFO + 1) & 2,
            2,
            "TDMA on the board"
        );
        assert_eq!(rig.bus.get(REG_RETRY_LIMIT), 8, "retries held to 8");
    }

    #[test]
    fn a_repeated_report_runs_nothing() {
        let mut rig = Rig::new(true);
        rig.bluetooth(0x49, 0, 0);
        assert_eq!(rig.bluetooth(0x49, 0, 0), Run::default());
    }

    #[test]
    fn the_same_schedule_is_not_sent_twice() {
        let mut rig = Rig::new(true);
        rig.bluetooth(0x49, 0, 0);
        let run = rig.event(Event::Traffic);
        assert!(
            !commands(&run)
                .iter()
                .any(|command| command.0 & 0xff == 0x60)
        );
    }

    #[test]
    fn a_separate_antenna_board_steps_back_when_the_radios_are_near_each_other() {
        let mut rig = Rig::new(false);
        rig.wifi.busy = true;
        rig.wifi.rssi = 70;
        rig.event(Event::Traffic);
        // A2DP from a loud Bluetooth link, with Wi-Fi receiving well.
        rig.event(Event::Bluetooth(&[1, 0x49, 0, 0xf0, 0, 0, 0]));
        assert!(rig.coex.freerun);
        assert_eq!(rig.coex.bluetooth_power, RECEIVE_RF[2].bluetooth_power + 3);
        assert!(rig.coex.low_gain);
        assert_eq!(rig.coex.phase, Some(Phase::Freerun));
    }

    #[test]
    fn five_ghz_owes_bluetooth_nothing() {
        let mut rig = Rig::new(true);
        rig.bluetooth(0x49, 0, 0);
        rig.wifi.five_ghz = true;
        rig.wifi.channel = 36;
        rig.event(Event::Tuned { scanning: false });
        assert_eq!(rig.bus.word(REG_BT_COEX_TABLE0), SHARED_TABLES[0].bluetooth);
        assert_eq!(rig.coex.tdma_case, 0);
        assert_eq!(rig.bus.get(REG_RETRY_LIMIT), 0, "the limit lifted");
        assert_eq!(rig.bus.arbiter[&LTE_COEX_CTRL] & 0x3300, 0x3300);
    }

    #[test]
    fn a_connection_holds_its_case_against_bluetooth_for_five_seconds() {
        let mut rig = Rig::new(true);
        rig.wifi.connected = false;
        rig.event(Event::Connecting);
        let held = rig.coex.tdma_case;
        rig.bluetooth(0x49, 0, 0);
        assert_eq!(rig.coex.tdma_case, held);
        rig.tick_to(rig.now + 5 * SECOND_US);
        assert!(!rig.coex.freeze && !rig.coex.connecting_task);
        assert_ne!(rig.coex.tdma_case, held);
    }

    #[test]
    fn a_finished_connection_tells_bluetooth_where_wifi_is() {
        let mut rig = Rig::new(false);
        rig.event(Event::Connected);
        let run = rig.event(Event::Media { connected: true });
        let info = (
            COMMAND_CHANNEL_INFO | (1 << 8) | (6 << 16) | (0x24 << 24),
            0,
        );
        assert!(commands(&run).contains(&info));
        assert_eq!(rig.bus.get(REG_BT_COEX_TABLE_H + 3) & (1 << 4), 1 << 4);
        let run = rig.event(Event::Media { connected: false });
        assert!(commands(&run).contains(&(COMMAND_CHANNEL_INFO, 0)));
        assert_eq!(rig.bus.get(REG_BT_COEX_TABLE_H + 3) & (1 << 4), 0);
    }

    #[test]
    fn busy_traffic_outlasts_itself_by_twelve_seconds() {
        let mut rig = Rig::new(true);
        rig.wifi.busy = true;
        rig.event(Event::Traffic);
        rig.wifi.busy = false;
        rig.event(Event::Traffic);
        assert!(rig.coex.busy);
        rig.tick_to(rig.now + 12 * SECOND_US);
        assert!(!rig.coex.busy);
    }

    #[test]
    fn a_page_finished_lingers_for_four_seconds() {
        let mut rig = Rig::new(true);
        rig.bluetooth(4, 0, 0);
        assert!(rig.coex.inquiry_remains);
        rig.bluetooth(0, 0, 0);
        assert!(rig.coex.inquiry_remains);
        rig.tick_to(rig.now + 4 * SECOND_US);
        assert!(!rig.coex.inquiry_remains);
    }

    #[test]
    fn a_link_setting_up_has_a_second_or_six_after_a_return() {
        let mut rig = Rig::new(true);
        rig.bluetooth(0, 1 << 2, 0);
        assert!(rig.coex.bluetooth.setting_up);
        rig.tick_to(rig.now + SECOND_US);
        assert!(!rig.coex.bluetooth.setting_up);
        rig.coex.reenabling = true;
        rig.bluetooth(1, 1 << 2, 0);
        rig.tick_to(rig.now + SECOND_US);
        assert!(rig.coex.bluetooth.setting_up);
        rig.tick_to(rig.now + 5 * SECOND_US);
        assert!(!rig.coex.bluetooth.setting_up);
    }

    #[test]
    fn an_answer_opens_the_way_for_the_next_question() {
        let mut rig = Rig::new(true);
        rig.coex.bluetooth_lna = 7;
        // Low energy scanning, on the third of three reports.
        let run = rig.bluetooth(0, 1 << 5, 0);
        assert!(commands(&run).contains(&query(OP_SCAN_TYPE, 0)));
        let (mut step_bus, report) = (Bus::default(), Report::of_two_paths(profile()));
        let mut step = Step {
            io: &mut step_bus,
            report: &report,
            now: rig.now,
            wifi: rig.wifi,
            reason: Reason::Status,
            run: Run::default(),
        };
        rig.coex.ask(&mut step, Request::LnaConstraint(5));
        assert!(step.run.orders.is_empty(), "one at a time");
        let run = rig.event(Event::Answer(&[1, 0, 0, 2, 0, 0, 0, 0]));
        assert_eq!(rig.coex.bluetooth.scan_type, 2);
        assert_eq!(commands(&run), [query(OP_LNA_CONSTRAINT, 5)]);
    }

    #[test]
    fn a_question_unanswered_gives_way_after_ten_milliseconds() {
        let mut rig = Rig::new(true);
        rig.bluetooth(0, 1 << 5, 0);
        assert!(rig.coex.asked.is_some());
        rig.tick_to(rig.now + REQUEST_TIMEOUT_US);
        assert!(rig.coex.asked.is_none());
    }

    #[test]
    fn an_answer_from_elsewhere_is_not_one() {
        let mut rig = Rig::new(true);
        rig.bluetooth(0, 1 << 5, 0);
        rig.event(Event::Answer(&[0, 0, 0, 2, 0, 0, 0, 0]));
        assert!(rig.coex.asked.is_some());
        assert_eq!(rig.coex.bluetooth.scan_type, 0);
    }

    #[test]
    fn a_sleeping_station_runs_the_native_case_and_a_schedule_wakes_it() {
        let mut rig = Rig::new(true);
        rig.bluetooth(1, 0, 0);
        rig.event(Event::Sleeping(true));
        rig.wifi.asleep = true;
        assert_eq!(rig.bus.word(REG_BT_COEX_TABLE1), SHARED_TABLES[28].wifi);
        assert_eq!(rig.bus.get(REG_WIFI_BT_INFO) & 1, 0, "not active");
        // What firmware keeps only awake leaves the slots empty first.
        rig.coex.sleeping = false;
        let run = rig.bluetooth(0x49, 0, 0);
        let wake = run.orders.iter().position(|order| *order == Order::Wake);
        assert_eq!(run.orders[wake.unwrap() - 1], Order::Command(tdma([0; 5])));
        assert!(rig.coex.stays_awake());
    }

    #[test]
    fn a_silent_scoreboard_ends_bluetooth_and_its_report_returns_it() {
        let mut rig = Rig::new(true);
        rig.bus.board = Some(0);
        rig.event(Event::Bluetooth(&[4]));
        assert!(rig.coex.bluetooth_disabled);
        assert_eq!(rig.coex.plan().table, 2, "the Wi-Fi-only table");
        rig.bus.board = Some(SCORE_ON);
        rig.bluetooth(1, 0, 0);
        assert!(rig.coex.reenabling);
        rig.tick_to(rig.now + 15 * SECOND_US);
        assert!(!rig.coex.reenabling);
    }

    #[test]
    fn a_game_controller_takes_an_antenna_of_its_own() {
        let mut rig = Rig::new(true);
        rig.bluetooth(1 | 0x20, 0, 0);
        rig.bus
            .write32(REG_BT_ACT_STATISTICS, 500 | (500 << 16))
            .unwrap();
        let run = rig.event(Event::Watchdog);
        assert_eq!(commands(&run), [query_hid(HID_LIST, 0)]);
        rig.event(Event::BluetoothHid([0, 6, 0, 1, 3, 0xff, 0xff, 0xff]));
        let run = rig.event(Event::Watchdog);
        assert!(commands(&run).contains(&query_hid(HID_DEVICE, 3)));
        let run = rig.event(Event::BluetoothHid([0, 6, 1, 3, 0x46, 0x58, 0x62, 0x6f]));
        assert!(run.orders.contains(&Order::SingleStream(true)));
        assert_eq!(rig.bus.word(REG_BT_COEX_TABLE1), SHARED_TABLES[33].wifi);
        assert_eq!(rig.coex.mode, Some(Mode::Free));
        assert_eq!(rig.bus.get(REG_NOMASK_TXBT) & NOMASK_TXBT, NOMASK_TXBT);
        // Bluetooth now hops around the channel, shared antenna or not.
        let info = (
            COMMAND_CHANNEL_INFO | (1 << 8) | (6 << 16) | (0x24 << 24),
            0,
        );
        assert!(commands(&run).contains(&info));
        let run = rig.event(Event::BluetoothHid([0, 6, 0, 0, 0, 0, 0, 1]));
        assert!(run.orders.contains(&Order::SingleStream(false)));
        assert_eq!(rig.coex.mode, Some(Mode::TwoGhz));
    }

    #[test]
    fn a_stopped_arbiter_answers_nothing() {
        let mut rig = Rig::new(true);
        rig.coex.stopped = true;
        assert_eq!(rig.bluetooth(0x49, 0, 0), Run::default());
    }

    #[test]
    fn a_noisy_channel_needs_five_quiet_looks_in_a_row() {
        let mut coex = Coex::of(0x20, 1);
        for _ in 0..4 {
            coex.detect_noise(300);
        }
        assert_eq!(coex.noise, 0);
        coex.detect_noise(300);
        assert_eq!(coex.noise, 2);
        for _ in 0..5 {
            coex.detect_noise(10);
        }
        assert_eq!(coex.noise, 0);
    }

    #[test]
    fn plans_follow_the_profiles() {
        let plan = |low2: u8, high2: u8, busy: bool| {
            let mut rig = Rig::new(true);
            rig.coex.busy = busy;
            rig.coex.connected = true;
            rig.coex
                .bluetooth
                .report(&[1, low2, 0, 0, 0, high2, 0], (0, 0));
            rig.coex.bluetooth.update_links();
            let plan = rig.coex.plan();
            (plan.table, plan.tdma, plan.four_slot)
        };
        assert_eq!(plan(1 | 2, 0, false), (10, 5, false), "HFP");
        assert_eq!(plan(1 | 0x20, 0, false), (9, 9, false), "HID");
        assert_eq!(plan(1 | 0x80, 0, true), (14, 17, false), "PAN");
        assert_eq!(plan(1 | 0x40, 0, false), (9, 14, true), "A2DP");
        assert_eq!(plan(1 | 0x60, 0, true), (9, 13, true), "A2DP with HID");
        assert_eq!(plan(1 | 0xc0, 0, true), (14, 15, false), "A2DP with PAN");
        assert_eq!(plan(1 | 0xa0, 0, true), (9, 18, false), "PAN with HID");
        assert_eq!(plan(1 | 0xe0, 0, true), (10, 15, false), "all three");
        assert_eq!(plan(1, 0, false), (10, 3, false), "idle");
    }
}
