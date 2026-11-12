// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! An RTL8822C's registers and rings beneath its [`Rtl8822c`] station: what
//! rtw88's `mac80211.c`, `pci.c`, `sec.c` and `rtw_set_channel` do for
//! mac80211. Each step takes the radio's only worker, so nothing here locks.
//!
//! [`Rtl8822c`]: super::station::Rtl8822c
use super::{
    bootstrap::{self, Claim, Native, Up},
    calibrate::{Calibration, DpkRun, GapkRun},
    coex::{Coex, Event, Order, Wifi},
    commands::{self, Report},
    deep::Deep,
    descriptor::Packet,
    download,
    dynamic::{self, Dynamic, set_mask},
    features,
    firmware_control::{self, Control, IqkWait},
    interrupt::{self, Controller},
    io::{Bar, Io},
    link::Link,
    phy::{
        FactorySheet, PhyInitialized,
        channel_power::{Geometry, Limits, Width as ChannelWidth},
    },
    receive::{self, Ring},
    regd,
    registers::{REG_BCN_CTRL, REG_CR},
    rfk::{self, Progress},
    station::{CamKey, Device, Incoming, MAC_ID, PORT, Received, Watched},
    templates::{self, Templates},
    transmit::{self, Queue, Rings},
};
use crate::{
    Mac,
    bus::dma::memory::PageSource,
    wifi::Band,
    wifi::connection::keeper::Recovery,
    wifi::station::{
        operations::ChannelDefinition,
        phy::{AccessCategory, Width},
    },
    wifi::stepped::{Stepped, block_on},
};
use alloc::{collections::VecDeque, format, string::String, vec::Vec};
use core::{fmt::Debug, task::Poll};

/// `REG_TCR`'s `BIT_PWRMGT_HWDATA_EN` and `BIT_TCR_UPDATE_TIMIE`.
const REG_TCR: u32 = 0x604;
const POWER_BIT_BY_HARDWARE: u32 = 1 << 7;
const UPDATE_TIM_ELEMENT: u32 = 1 << 5;
/// `REG_DTIM_COUNTER_ROOT`.
const REG_DTIM_COUNTER_ROOT: u32 = 0x5a8;
/// `LEAVE_LPS_TRY_CNT` times its 20 ms.
const LEAVE_POWER_SAVE_US: u64 = 100_000;
/// How many hurried steps end any calibration, with room to spare.
const HURRIED_STEPS: usize = 16;

/// `rtw_vif_port[0]`.
const REG_MAC_ADDRESS: u32 = 0x610;
const REG_BSSID: u32 = 0x618;
const REG_AID: u32 = 0x6a8;
const AID_MASK: u32 = 0x7ff;
const NET_TYPE_MASK: u32 = 0x30000;
/// `RTW_NET_NO_LINK` and `RTW_NET_MGD_LINKED`.
const NET_NO_LINK: u32 = 0;
const NET_LINKED: u32 = 2;
/// `BIT_EN_BCN_FUNCTION`.
const BEACON_FUNCTION: u8 = 1 << 3;
/// `REG_RCR`'s `BIT_CBSSID_BCN`.
const REG_RCR: u32 = 0x608;
const OWN_BEACONS: u32 = 1 << 7;
/// `ac_to_edca_param`, by the ACI an AP's parameters name.
const EDCA: [u32; 4] = [0x508, 0x50c, 0x504, 0x500];
/// `RTW_SEC_CMD_REG`, `RTW_SEC_WRITE_REG` and their command.
const REG_CAM_COMMAND: u32 = 0x670;
const REG_CAM_WRITE: u32 = 0x674;
const CAM_WRITE: u32 = (1 << 31) | (1 << 16);
/// `REG_NCTL0`'s `BIT_SEL_PATH`, and `REG_DPD_CTL1_S0`'s `BIT_PS_EN`.
const REG_NCTL0: u32 = 0x1b00;
const SELECT_PATH: u32 = 3 << 1;
const REG_DPD_CTL1: u32 = 0x1b08;
const POWER_SAVE: u32 = 1 << 7;
/// `rtw8822c_dig`: each path's gain within one register.
const REG_GAIN: u32 = 0x1d70;
const GAIN_MASKS: [u32; 2] = [0x7f, 0x7f00];
/// `rtw8822c_false_alarm_statistics`' counters, their resets and clock gate.
const REG_CCK_ENABLE: u32 = 0x1c3c;
const CCK_BLOCK: u32 = 1 << 1;
const REG_CCK_ALARMS: u32 = 0x1a5c;
/// The word of `cck_ok_cnt` and `cck_err_cnt`.
const REG_CCK_FRAMES: u32 = 0x2c04;
const REG_OFDM_ALARMS: [u32; 5] = [0x2d04, 0x2d08, 0x2d0c, 0x2d10, 0x2d20];
const REG_ALARM_RESET: u32 = 0x1a2c;
const CCK_ALARM_RESET: u32 = 3 << 14;
const OFDM_ALARM_RESET: u32 = 3 << 12;
const REG_RX_BREAK: u32 = 0x1d2c;
const RX_CLOCK_GATE: u32 = 1 << 31;
const REG_COUNTER_CONTROL: u32 = 0x1eb4;
const ALL_COUNTERS_RESET: u32 = 1 << 25;
/// `RRSR_INIT_2G` and `RRSR_INIT_5G`, the rates a response may use.
const REG_RRSR: u32 = 0x440;
/// `FW_FEATURE_NOTIFY_SCAN` and `FW_FEATURE_ADAPTIVITY`.
const NOTIFY_SCAN: u32 = 1 << 6;
const ADAPTIVITY: u32 = 1 << 7;
/// `rtw8822c_edcca_th`: both thresholds, each offset by half their range.
const REG_EDCCA: u32 = 0x84c;
const EDCCA_RISING: u32 = 0xff << 16;
const EDCCA_FALLING: u32 = 0xff << 24;
const EDCCA_OFFSET: u32 = 0x80;
const RESPONSE_RATES_2GHZ: u32 = 0x15f;
const RESPONSE_RATES_5GHZ: u32 = 0x150;
/// Frames a look at the receive ring takes, which [`Ring::poll`] holds to the
/// ring's own size.
const RECEIVE_BUDGET: usize = 512;
/// `DBI_TO_MBI(6)`, the antenna gain cfg80211 reads regulatory.db's EIRP under,
/// and the 3 dB of two chains sending one frame. rtw88 keeps to the sheet
/// alone; a board's real antennas are not known here.
const ANTENNA_AND_COMBINING_MBM: i32 = 600 + 301;

/// What the station goes without when config space stops answering the chip.
const LINK_SILENT: &str = "PCIe link power save, for a config space bridge that did not finish";
/// What rtw88 also only skips or warns of on the receive ring.
const RECEIVE_DROPPED: &str = "received descriptors the chip filled in wrongly, which are dropped";
const RECEIVE_TAG_SLIPPED: &str =
    "received buffers whose DMA tag was out of step (PCIe bus timeouts), which are still taken";
/// rtw88's "failed to poll iqk status bit", after which it goes on.
const IQK_UNFINISHED: &str = "an IQK calibration firmware did not report done within 300 ms";
/// rtw88's "failed to send h2c command", after which it goes on.
const MAILBOX_BUSY: &str = "firmware commands dropped while its mailbox stayed busy";
/// rtw88's "firmware failed to leave lps state", after which it clears the
/// power bit itself.
const POWER_SAVE_HELD: &str = "firmware that did not leave power save in time";
/// A calibration another request cut short; the next transmission on the
/// channel calibrates again.
const CALIBRATION_CUT_SHORT: &str = "a calibration another request cut short";
/// The arbiter waits a few steps for a calibration, not rtw88's 600 ms at once.
const COEX_WAIT_CUT: &str = "an antenna path set while a Bluetooth calibration still ran";
/// The synthesizer lock waits 20 ms, not rtw88's 100.
const LOCK_UNSETTLED: &str = "a synthesizer lock that had not settled within 20 ms";

fn failed<E: Debug>(step: &'static str) -> impl FnOnce(E) -> String {
    move |error| format!("{step}: {error:?}")
}

/// What `definition`'s channels are to the PHY.
/// The channel number of a frequency.
fn number(frequency: u32) -> u8 {
    let base = if frequency < 5000 { 2407 } else { 5000 };
    ((frequency - base) / 5) as u8
}

fn geometry(definition: &ChannelDefinition) -> Result<Geometry, String> {
    let primary = definition.control.number as u8;
    let center = number(definition.center1_mhz);
    let (width, forty, eighty) = match definition.width {
        Width::Mhz20 => (ChannelWidth::Mhz20, None, None),
        Width::Mhz40 => (ChannelWidth::Mhz40, Some(center), None),
        Width::Mhz80 => {
            // rtw_get_channel_params: the 40 MHz half the primary lies in.
            let forty = if primary > center {
                center + 4
            } else {
                center - 4
            };
            (ChannelWidth::Mhz80, Some(forty), Some(center))
        }
        _ => return Err(String::from("a channel wider than the RTL8822C's 80 MHz")),
    };
    Geometry::new(primary, width, forty, eighty).map_err(failed("channel"))
}

/// The hardware an attached RTL8822C station runs on.
pub struct Hardware {
    control: Control<Native>,
    interrupts: Controller<Bar>,
    receive: Ring<Bar>,
    transmit: Rings<Bar>,
    /// Taken while a channel changes; gone if one failed part way.
    phy: Option<PhyInitialized>,
    coex: Coex,
    report: features::Report,
    pages: &'static dyn PageSource,
    /// `fifo.rsvd_drv_addr`, which is also `fifo.rsvd_boundary`.
    boundary: u16,
    /// The 2.4 and 5 GHz factory sheets of the country.
    sheets: (FactorySheet, FactorySheet),
    /// `rtwdev->need_rfk`: the channel changed outside a scan.
    calibrate: bool,
    calibration: Calibration,
    band: Band,
    /// `hal.current_channel` and `current_band_width`.
    channel: (u8, u8),
    connected: bool,
    /// `RTW_FLAG_SCANNING`, `RTW_FLAG_BUSY_TRAFFIC` and `RTW_FLAG_LEISURE_PS`.
    scanning: bool,
    busy: bool,
    asleep: bool,
    /// `hal.txrx_1ss`, and each change of it the AP has not heard of.
    single_stream: bool,
    stream_changes: VecDeque<bool>,
    /// `coex_stat->wl_beacon_interval`.
    beacon_interval: u16,
    /// `dm_info.cck_ok_cnt + cck_err_cnt`.
    cck_frames: u32,
    /// The clock as the last look at the arbiter read it.
    now: u64,
    address: Mac,
    bssid: Mac,
    dynamic: Dynamic,
    /// `dm_info->cck_gi_u_bnd` and `cck_gi_l_bnd`.
    cck_bounds: [u8; 2],
    /// `fw->feature`.
    features: u32,
    deep: Deep,
    link: Link,
    /// The association's frames, for downloading again, and where the last
    /// download left the power gate's info and predistortion pages.
    templates: Option<Templates>,
    power_gate_pages: Option<(u8, u8)>,
    /// `sec->cam_map`.
    keys: u32,
    /// The MSI reaches the core that looks for frames.
    vector: bool,
    limitations: Vec<&'static str>,
    /// Limitations already told once, which a repeat does not tell again.
    reported: Vec<&'static str>,
    /// `rtw8822c_phy_calibration` under way, a step each poll.
    rfk: Option<rfk::Run<Hardware>>,
    /// `rtw_leave_lps`'s wait for firmware to clear the power bit, until.
    leaving: Option<u64>,
    /// Bluetooth's reports while a calibration holds the arbiter, as rtw88's
    /// C2H work waits for its mutex.
    held_reports: Vec<Report>,
    /// What a chip reset brings the function up again from, and how.
    claim: Claim,
    alpha2: [u8; 2],
    dfs_region: u8,
    /// The chip reset under way, a step of the bring-up each call.
    recovery: Option<Stepped<'static, Result<Up, bootstrap::Error>>>,
}

impl Hardware {
    /// `rtw_ops_add_interface`'s first station on `up`, under `alpha2`.
    ///
    /// # Safety
    /// `up` comes from [`super::bootstrap::bring_up`] with nothing since, and
    /// `vector` says its function raises an MSI the caller has routed.
    pub unsafe fn new(
        up: Up,
        alpha2: [u8; 2],
        dfs_region: u8,
        vector: bool,
    ) -> Result<Self, String> {
        let Up {
            mut control,
            mut interrupts,
            receive,
            transmit,
            phy,
            report,
            features,
            board,
            coex,
            mac,
            pages,
            geometry,
            link,
            disabled,
            claim,
            ..
        } = up;
        let initial = phy.factory().calibration().initial();
        let cck_bounds = initial.cck_bounds();
        let calibration = Calibration::new(board.raw().power_track_raw);
        let dynamic = Dynamic::new(dynamic::Initial {
            gains: initial.igi_history(),
            crystal_cap: initial.crystal_cap(),
            thermal: board.raw().thermal_raw,
            power_tracked: board.raw().power_track_raw == 0,
            lck_reference: phy.tracking().lck_reference,
            dfs_region,
        });
        let mut limitations = Vec::new();
        if !link.answered() {
            limitations.push(LINK_SILENT);
        }
        let io = control.io().map_err(failed("registers"))?;
        write_address(io, REG_MAC_ADDRESS, mac).map_err(failed("address"))?;
        set_mask(io, REG_CR, NET_TYPE_MASK, NET_NO_LINK).map_err(failed("net type"))?;
        io.write8(REG_BCN_CTRL, BEACON_FUNCTION)
            .map_err(failed("beacon control"))?;
        if vector {
            // SAFETY: the caller's routed MSI, and this worker handles it.
            unsafe { interrupts.enable(false) }.map_err(failed("interrupts"))?;
        }
        Ok(Self {
            control,
            interrupts,
            receive,
            transmit,
            phy: Some(phy),
            coex,
            report,
            pages,
            boundary: geometry.boundary(),
            sheets: regd::sheets(alpha2),
            calibrate: true,
            calibration,
            band: Band::Ghz2,
            channel: (0, 0),
            connected: false,
            scanning: false,
            busy: false,
            asleep: false,
            single_stream: false,
            stream_changes: VecDeque::new(),
            beacon_interval: 0,
            cck_frames: 0,
            now: 0,
            address: mac,
            bssid: Mac([0; 6]),
            dynamic,
            cck_bounds,
            features,
            deep: Deep::new(features, !disabled.lps_deep),
            link,
            templates: None,
            power_gate_pages: None,
            keys: 0,
            vector,
            limitations,
            reported: Vec::new(),
            rfk: None,
            leaving: None,
            held_reports: Vec::new(),
            claim,
            alpha2,
            dfs_region,
            recovery: None,
        })
    }

    /// One step of `rtw_fw_recovery_work`'s chip reset: the bring-up again,
    /// a step per call, from the power sequence on. Done, the chip runs as
    /// new beneath `self`.
    ///
    /// The rings of the boot before, and of each attempt that failed or was
    /// dropped part way, stay mapped: a ring keeps its pages once configured,
    /// since nothing proves the chip stopped reaching them until the next
    /// power sequence. That is one set of rings per attempt, bounded by the
    /// keeper's ten attempts in a row.
    fn reset_step(&mut self) -> Result<Recovery, String> {
        let recovery = match &mut self.recovery {
            Some(recovery) => recovery,
            None => {
                // The power sequence masks the chip's interrupts too; this
                // only keeps the line quiet until then.
                let _ = self.interrupts.disable();
                let claim = self.claim.clone();
                // SAFETY: the claim attach brought up, which this keeps;
                // the old rings stay mapped and the power sequence stops
                // the chip before any is bound again.
                self.recovery
                    .insert(Stepped::new(unsafe { bootstrap::start(claim) }))
            }
        };
        let up = match recovery.step() {
            Poll::Pending => return Ok(Recovery::Pending),
            Poll::Ready(up) => {
                self.recovery = None;
                up.map_err(|error| format!("bring-up: {error}"))?
            }
        };
        // SAFETY: straight from the bring-up, with the MSI attach routed.
        let fresh = unsafe { Self::new(up, self.alpha2, self.dfs_region, self.vector) }?;
        drop(core::mem::replace(self, fresh));
        Ok(Recovery::Done)
    }

    /// `rtw_fw_send_h2c_command`: a command firmware's busy mailbox would not
    /// take is dropped, as rtw88 drops it, and told once.
    fn send(&mut self, command: (u32, u32), step: &'static str) -> Result<(), String> {
        match self.control.command(command) {
            Err(firmware_control::Error::MailboxTimeout { .. }) => {
                self.limit_once(MAILBOX_BUSY);
                Ok(())
            }
            result => result.map_err(failed(step)),
        }
    }

    /// Tell the station of `limitation` the first time it happens.
    fn limit_once(&mut self, limitation: &'static str) {
        if !self.reported.contains(&limitation) {
            self.reported.push(limitation);
            self.limitations.push(limitation);
        }
    }

    /// `rtw_hci_link_ps`.
    fn set_link_power(&mut self, on: bool) -> Result<(), String> {
        let answered = self.link.answered();
        let io = self.control.io().map_err(failed("registers"))?;
        self.link.set_l1(io, on).map_err(failed("pcie link"))?;
        if answered && !self.link.answered() {
            self.limitations.push(LINK_SILENT);
        }
        Ok(())
    }

    /// One of rtw88's notifiers of the arbiter, and what it asks for.
    fn arbitrate(&mut self, event: Event<'_>) -> Result<(), String> {
        self.rouse()?;
        let wifi = Wifi {
            connected: self.connected,
            scanning: self.scanning,
            busy: self.busy,
            transmitting: self.dynamic.transmitting(),
            rssi: self.dynamic.min_rssi(),
            cck_frames: self.cck_frames,
            five_ghz: self.band == Band::Ghz5,
            channel: self.channel.0,
            width: self.channel.1,
            beacon_interval: self.beacon_interval,
            asleep: self.asleep,
        };
        let now = self.now;
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: this worker owns the radio, and its frames wait for it.
        let run = unsafe { self.coex.notify(io, &self.report, now, wifi, event) }
            .map_err(failed("coex"))?;
        if self.coex.take_cut_wait() {
            self.limit_once(COEX_WAIT_CUT);
        }
        for order in run.orders {
            match order {
                Order::Command(command) => self.send(command, "coex command")?,
                Order::Wake => self.set_power_save(false)?,
                Order::SingleStream(single) if single != self.single_stream => {
                    self.single_stream = single;
                    let io = self.control.io().map_err(failed("registers"))?;
                    Dynamic::set_paths(io, single).map_err(failed("paths"))?;
                    self.stream_changes.push_back(single);
                }
                Order::SingleStream(_) => {}
            }
        }
        Ok(())
    }

    /// `rtw_leave_lps_deep`, ahead of anything past the bus's own registers.
    /// Deep power save comes back with the watchdog's next `rtw_enter_lps`.
    fn rouse(&mut self) -> Result<(), String> {
        self.settle()?;
        if !self.deep.active() {
            return Ok(());
        }
        let io = self.control.io().map_err(failed("registers"))?;
        let answered = self.deep.leave(io).map_err(failed("deep power save"))?;
        self.report_silence(answered);
        Ok(())
    }

    /// `__rtw_enter_lps_deep`. A frame still with the device, or firmware that
    /// cannot be told where its pages are, leaves leisure power save standing.
    fn enter_deep(&mut self) -> Result<(), String> {
        if !self.deep.available() || self.deep.active() {
            return Ok(());
        }
        if self.deep.gates_power() {
            let Some((info, predistortion)) = self.power_gate_pages else {
                return Ok(());
            };
            self.send(
                commands::power_gate_pages(info, predistortion, self.keys != 0),
                "power gate",
            )?;
        }
        if !self.deep.transmit_wakes() && self.transmit.frames_pending() {
            return Ok(());
        }
        let io = self.control.io().map_err(failed("registers"))?;
        let answered = self.deep.enter(io).map_err(failed("deep power save"))?;
        self.report_silence(answered);
        Ok(())
    }

    fn report_silence(&mut self, answered: bool) {
        if !answered {
            self.limitations
                .push("firmware that did not answer a deep power save request");
        }
    }

    /// `rtw_fw_download_rsvd_page`, the dummy again last to give the first
    /// page its own descriptor, and `rtw_send_rsvd_page_h2c`.
    fn download_templates(&mut self) -> Result<(), String> {
        let predistortion = self.calibration.power_gate_page();
        let info = templates::power_gate_info(self.keys);
        let Some(pages) = self
            .templates
            .as_ref()
            .map(|templates| templates.pages(&predistortion, &info))
        else {
            return Ok(());
        };
        let boundary = self.boundary;
        let io = self.control.io().map_err(failed("registers"))?;
        for data in [&pages.data[..], &[0]] {
            // Two page waits of 10 ms at most, which the caller may hold.
            block_on(download::write_reserved(io, boundary, boundary, data))
                .map_err(failed("reserved pages"))?;
        }
        self.power_gate_pages = Some((pages.info, pages.predistortion));
        self.send(
            commands::reserved_pages(pages.ps_poll, pages.null, pages.qos_null),
            "reserved pages",
        )
    }

    /// `rtw_ops_set_key`'s last step: a power gate restores keys from the pages.
    fn save_keys(&mut self) -> Result<(), String> {
        if self.deep.gates_power() {
            self.download_templates()?;
        }
        Ok(())
    }

    /// One look of `rtw_leave_lps_core`'s wait for the power bit in frames to
    /// clear. Past its 100 ms, or with `force`, the bit is cleared here, as
    /// rtw88 clears it, and the arbiter hears of the return.
    fn look_leaving(&mut self, force: bool) -> Result<(), String> {
        let Some(end) = self.leaving else {
            return Ok(());
        };
        let io = self.control.io().map_err(failed("registers"))?;
        let now = io.now_us().map_err(failed("clock"))?;
        let control = io.read32(REG_TCR).map_err(failed("power save"))?;
        if control & POWER_BIT_BY_HARDWARE != 0 {
            if !force && now <= end {
                return Ok(());
            }
            set_mask(io, REG_TCR, POWER_BIT_BY_HARDWARE, 0).map_err(failed("power save"))?;
            self.limit_once(POWER_SAVE_HELD);
        }
        self.leaving = None;
        self.arbitrate(Event::Sleeping(false))
    }

    /// Whether frames wait: for a calibration, or for power save to end.
    fn holding(&self) -> bool {
        self.rfk.is_some() || self.leaving.is_some()
    }

    /// One step of the calibration under way, and one look at power save
    /// ending.
    fn advance(&mut self) -> Result<(), String> {
        self.step_calibration(false)?;
        self.look_leaving(false)
    }

    fn step_calibration(&mut self, hurry: bool) -> Result<(), String> {
        let Some(mut run) = self.rfk.take() else {
            return Ok(());
        };
        match run.step(self, hurry)? {
            Progress::Running => self.rfk = Some(run),
            Progress::Done { hurried } => {
                self.limitations.extend(self.calibration.take_shortfalls());
                if hurried {
                    self.calibrate = true;
                    self.limit_once(CALIBRATION_CUT_SHORT);
                }
            }
        }
        Ok(())
    }

    /// End the calibration under way in a few hurried steps, before work that
    /// cannot wait for it.
    fn settle(&mut self) -> Result<(), String> {
        for _ in 0..HURRIED_STEPS {
            if self.rfk.is_none() {
                return Ok(());
            }
            self.step_calibration(true)?;
        }
        Err(String::from("a calibration that hurried steps did not end"))
    }

    /// Bluetooth's reports, unless a calibration holds the arbiter.
    fn hear_bluetooth(&mut self, reports: Vec<Report>) -> Result<(), String> {
        self.held_reports.extend(reports);
        if self.rfk.is_some() {
            return Ok(());
        }
        for report in core::mem::take(&mut self.held_reports) {
            match report {
                Report::Bluetooth { bytes, length } => {
                    self.arbitrate(Event::Bluetooth(&bytes[..usize::from(length)]))?;
                }
                Report::BluetoothAnswer(answer) => self.arbitrate(Event::Answer(&answer))?,
                Report::BluetoothHid(bytes) => self.arbitrate(Event::BluetoothHid(bytes))?,
                _ => {}
            }
        }
        Ok(())
    }

    /// `rtw8822c_false_alarm_statistics`: the total and CCK's own, and a new
    /// count.
    fn false_alarms(&mut self) -> Result<(u16, u32), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        let cck_enabled = io.read32(REG_CCK_ENABLE).map_err(failed("alarms"))? & CCK_BLOCK != 0;
        let cck = io.read16(REG_CCK_ALARMS).map_err(failed("alarms"))?;
        let frames = io.read32(REG_CCK_FRAMES).map_err(failed("alarms"))?;
        self.cck_frames = (frames & 0xffff) + (frames >> 16);
        let mut counts = [0; 5];
        for (count, register) in counts.iter_mut().zip(REG_OFDM_ALARMS) {
            *count = io.read32(register).map_err(failed("alarms"))?;
        }
        let [one, two, three, four, five] = counts;
        let (low, high) = (|word: u32| word & 0xffff, |word: u32| word >> 16);
        let total = high(one)
            + low(two)
            + high(two)
            + low(three)
            + low(four)
            + high(four)
            + low(five)
            + high(five)
            + if cck_enabled { u32::from(cck) } else { 0 };
        let mut reset = |register, mask, value| {
            set_mask(io, register, mask, value).map_err(failed("alarm reset"))
        };
        reset(REG_ALARM_RESET, CCK_ALARM_RESET, 0)?;
        reset(REG_ALARM_RESET, CCK_ALARM_RESET, 2)?;
        reset(REG_ALARM_RESET, OFDM_ALARM_RESET, 0)?;
        reset(REG_ALARM_RESET, OFDM_ALARM_RESET, 2)?;
        reset(REG_RX_BREAK, RX_CLOCK_GATE, 0)?;
        reset(REG_COUNTER_CONTROL, ALL_COUNTERS_RESET, 1)?;
        reset(REG_COUNTER_CONTROL, ALL_COUNTERS_RESET, 0)?;
        reset(REG_RX_BREAK, RX_CLOCK_GATE, 1)?;
        Ok((total as u16, u32::from(cck)))
    }

    /// `rtw_fw_adaptivity`, or `rtw8822c_adaptivity` on firmware without it.
    fn adapt(&mut self) -> Result<(), String> {
        if self.features & ADAPTIVITY != 0 {
            let (mode, gain, threshold, density) = self.dynamic.adaptivity();
            return self.send(
                commands::adaptivity(mode, gain, threshold, density),
                "adaptivity",
            );
        }
        let (rising, falling) = self.dynamic.energy_thresholds();
        let io = self.control.io().map_err(failed("registers"))?;
        for (mask, threshold) in [(EDCCA_RISING, rising), (EDCCA_FALLING, falling)] {
            let value = (u32::from(threshold) + EDCCA_OFFSET) & 0xff;
            set_mask(io, REG_EDCCA, mask, value).map_err(failed("energy threshold"))?;
        }
        Ok(())
    }

    /// `rtw_phy_dig_write`.
    fn write_gain(&mut self, gain: u8) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        for mask in GAIN_MASKS {
            set_mask(io, REG_GAIN, mask, u32::from(gain)).map_err(failed("gain"))?;
        }
        Ok(())
    }

    /// `rtw8822c_rfk_power_save`.
    fn calibration_power_save(&mut self, on: bool) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        for path in 0..2 {
            set_mask(io, REG_NCTL0, SELECT_PATH, path).map_err(failed("path"))?;
            set_mask(io, REG_DPD_CTL1, POWER_SAVE, u32::from(!on)).map_err(failed("power save"))?;
        }
        Ok(())
    }
}

/// `rtw_vif_write_addr`.
fn write_address(io: &mut Native, register: u32, address: Mac) -> Result<(), super::io::Error> {
    for (at, byte) in address.0.into_iter().enumerate() {
        io.write8(register + at as u32, byte)?;
    }
    Ok(())
}

/// `rtw_aifsn_to_aifs` and `__rtw_conf_tx` of one queue.
fn edca_word(category: &AccessCategory, band: Band, short_slot: bool) -> u32 {
    let slot = if short_slot { 9 } else { 20 };
    let sifs = if band == Band::Ghz5 { 16 } else { 10 };
    let aifs = u32::from(category.aifsn) * slot + sifs;
    (u32::from(category.txop_32us) << 16)
        | (u32::from(category.ecw_max) << 12)
        | (u32::from(category.ecw_min) << 8)
        | aifs
}

/// `rtw_sec_write_cam`'s eight words of `key`.
fn cam_words(key: &CamKey<'_>) -> [u32; 8] {
    let [a, b, c, d, e, f] = key.peer.0.map(u32::from);
    let mut words = [0; 8];
    words[0] = u32::from(key.index & 3)
        | (u32::from(key.kind & 7) << 2)
        | (u32::from(key.group) << 6)
        | (1 << 15)
        | (a << 16)
        | (b << 24);
    words[1] = c | (d << 8) | (e << 16) | (f << 24);
    for (word, bytes) in words[2..6].iter_mut().zip(key.material.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    words
}

/// What one `rtw_rx_query_rx_desc` packet gives the station, with the signal it
/// came in on.
fn incoming(
    packet: &receive::Packet<'_>,
    cck_bounds: [u8; 2],
) -> Option<(Incoming, Option<dynamic::Signal>)> {
    let facts = &packet.facts;
    if facts.firmware {
        return Report::parse(packet.payload).map(|report| (Incoming::Report(report), None));
    }
    if facts.crc_error {
        return None;
    }
    // IEEE80211_HW_RX_INCLUDES_FCS.
    let length = packet.payload.len().checked_sub(4)?;
    let signal = if facts.phy_present {
        let format = dynamic::StatusFormat::Rtl8822C { cck_bounds };
        dynamic::phy_status(packet.driver_info, format, facts.rate_raw)
    } else {
        None
    };
    let frame = Received {
        bytes: packet.payload[..length].to_vec(),
        tsf: facts.tsf_low,
        decrypted: facts.hardware_decrypted,
        icv_error: facts.icv_error,
        signal_dbm: signal.map(|signal| signal.power_dbm),
    };
    Some((Incoming::Frame(frame), signal))
}

impl Device for Hardware {
    /// `rtw_set_channel`, and `rtw_phy_set_tx_power_level` under `eirp_mbm`.
    fn tune(
        &mut self,
        definition: &ChannelDefinition,
        scanning: bool,
        eirp_mbm: i32,
    ) -> Result<(), String> {
        self.rouse()?;
        let geometry = geometry(definition)?;
        let phy = self.phy.take().ok_or("the PHY failed a channel change")?;
        let band = definition.control.band;
        let limits = Limits {
            factory_sheet: if band == Band::Ghz2 {
                self.sheets.0
            } else {
                self.sheets.1
            },
            max_eirp_mbm: eirp_mbm,
            antenna_and_combining_mbm: [ANTENNA_AND_COMBINING_MBM; 2],
            sar_quarter_dbm: None,
            remnant_cck: 0,
            remnant_ofdm: [0; 2],
        };
        let plan = phy
            .factory_power()
            .plan_channel_power(geometry, limits)
            .map_err(failed("channel power"))?;
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: the only worker owns the radio and its frames wait for it.
        let set =
            unsafe { phy.set_channel(io, &self.report, geometry) }.map_err(failed("channel"))?;
        self.band = band;
        // SAFETY: as above, with `plan` made for this channel.
        let programmed = unsafe { set.program_channel_power(io, &self.report, plan) }
            .map_err(failed("transmit power"))?;
        self.phy = Some(programmed.into_phy());
        self.calibrate |= !scanning;
        let width = match definition.width {
            Width::Mhz40 => 1,
            Width::Mhz80 => 2,
            _ => 0,
        };
        self.channel = (number(definition.center1_mhz), width);
        self.arbitrate(Event::Tuned { scanning })
    }

    /// `rtw_ops_mgd_prepare_tx`, with `rtw8822c_phy_calibration` once a channel
    /// needs it. The calibration runs a step each poll; frames wait for it.
    fn prepare_transmit(&mut self) -> Result<(), String> {
        self.arbitrate(Event::Connecting)?;
        if core::mem::take(&mut self.calibrate) {
            self.rfk = Some(rfk::Run::start(self)?);
        }
        Ok(())
    }

    fn ready(&self) -> bool {
        !self.holding()
    }

    fn transmit(&mut self, queue: Queue, packet: &Packet, mpdu: &[u8]) -> Result<bool, String> {
        if self.holding() {
            return Ok(false);
        }
        if !self.deep.transmit_wakes() {
            self.rouse()?;
        }
        match self
            .transmit
            .frame(queue, self.pages, &packet.encode(), mpdu)
        {
            Ok(()) => {
                self.dynamic.sent(mpdu);
                Ok(true)
            }
            Err(transmit::Error::Full) => Ok(false),
            Err(error) => Err(format!("transmit: {error:?}")),
        }
    }

    /// `rtw_pci_interrupt_threadfn`: the causes first, so that what arrives
    /// while the rings drain raises the MSI again.
    fn receive(&mut self, sink: &mut dyn FnMut(Incoming)) -> Result<(), String> {
        self.advance()?;
        if self.vector {
            self.interrupts.capture().map_err(failed("interrupt"))?;
        }
        let (cck_bounds, address, bssid) = (self.cck_bounds, self.address, self.bssid);
        let dynamic = &mut self.dynamic;
        let mut bluetooth = Vec::new();
        self.receive
            .poll(RECEIVE_BUDGET, |packet| {
                let Some((item, signal)) = incoming(&packet, cck_bounds) else {
                    return;
                };
                match &item {
                    Incoming::Report(
                        report @ (Report::Bluetooth { .. }
                        | Report::BluetoothAnswer(_)
                        | Report::BluetoothHid(_)),
                    ) => bluetooth.push(*report),
                    Incoming::Report(report) => dynamic.reported(report),
                    Incoming::Frame(frame) => dynamic.frame(&frame.bytes, signal, address, bssid),
                }
                sink(item);
            })
            .map_err(failed("receive"))?;
        for (seen, limitation) in [
            (self.receive.dropped(), RECEIVE_DROPPED),
            (self.receive.tag_slips(), RECEIVE_TAG_SLIPPED),
        ] {
            if seen != 0 {
                self.limit_once(limitation);
            }
        }
        self.transmit
            .reclaim_frames()
            .map_err(failed("transmit reclaim"))?;
        self.transmit
            .reclaim_h2c()
            .map_err(failed("command reclaim"))?;
        self.hear_bluetooth(bluetooth)?;
        if self.vector {
            // SAFETY: this worker is the handler, between its capture and now.
            unsafe { self.interrupts.enable(false) }.map_err(failed("interrupt"))?;
        }
        Ok(())
    }

    fn command(&mut self, command: (u32, u32)) -> Result<(), String> {
        self.rouse()?;
        self.send(command, "command")
    }

    fn set_templates(&mut self, templates: &Templates) -> Result<(), String> {
        self.rouse()?;
        self.templates = Some(templates.clone());
        self.download_templates()
    }

    /// `rtw_enter_lps` and `rtw_leave_lps`. Whether firmware reports the return
    /// or not, it clears the bit it set, so this waits on that.
    fn set_power_save(&mut self, on: bool) -> Result<(), String> {
        self.look_leaving(true)?;
        if on {
            if !self.asleep && !self.coex.stays_awake() {
                self.arbitrate(Event::Sleeping(true))?;
                self.asleep = true;
                self.send(commands::power_mode(true, PORT), "power mode")?;
                self.set_link_power(true)?;
            }
            return if self.asleep {
                self.enter_deep()
            } else {
                Ok(())
            };
        }
        self.rouse()?;
        if !self.asleep {
            return Ok(());
        }
        self.asleep = false;
        self.set_link_power(false)?;
        self.send(commands::power_mode(false, PORT), "power mode")?;
        let io = self.control.io().map_err(failed("registers"))?;
        let now = io.now_us().map_err(failed("clock"))?;
        self.leaving = Some(now.saturating_add(LEAVE_POWER_SAVE_US));
        self.look_leaving(false)
    }

    /// `rtw_ops_bss_info_changed`'s `BSS_CHANGED_BEACON_INT`, and
    /// `rtw_set_dtim_period`.
    fn set_beacon(&mut self, interval_tu: u16, dtim_period: u8) -> Result<(), String> {
        self.rouse()?;
        self.beacon_interval = interval_tu;
        let io = self.control.io().map_err(failed("registers"))?;
        set_mask(io, REG_TCR, UPDATE_TIM_ELEMENT, 1).map_err(failed("dtim"))?;
        io.write8(REG_DTIM_COUNTER_ROOT, dtim_period.saturating_sub(1))
            .map_err(failed("dtim"))
    }

    fn stream_change(&mut self) -> Option<bool> {
        self.stream_changes.pop_front()
    }

    /// The arbiter's time, and rtw88's delayed works that came due.
    fn coexist(&mut self, now: u64) -> Result<(), String> {
        self.now = now;
        if self.holding() {
            return Ok(());
        }
        if self.deep.active() && !self.coex.deadline_passed(now) {
            return Ok(());
        }
        self.arbitrate(Event::Tick)
    }

    /// `rtw_vif_port_config`.
    fn set_port(&mut self, bssid: Mac, aid: u16, linked: bool) -> Result<(), String> {
        self.rouse()?;
        if !linked {
            self.templates = None;
            self.power_gate_pages = None;
        }
        let io = self.control.io().map_err(failed("registers"))?;
        write_address(io, REG_BSSID, bssid).map_err(failed("bssid"))?;
        set_mask(io, REG_AID, AID_MASK, u32::from(aid)).map_err(failed("aid"))?;
        let net_type = if linked { NET_LINKED } else { NET_NO_LINK };
        set_mask(io, REG_CR, NET_TYPE_MASK, net_type).map_err(failed("net type"))?;
        if self.connected != linked {
            self.dynamic.forget();
        }
        let changed = self.connected != linked;
        self.bssid = bssid;
        self.connected = linked;
        if changed && linked {
            self.arbitrate(Event::Connected)?;
        }
        if changed {
            self.arbitrate(Event::Media { connected: linked })?;
        }
        Ok(())
    }

    /// `rtw_ops_configure_filter`'s `FIF_BCN_PRBRESP_PROMISC`.
    fn filter_beacons(&mut self, own_only: bool) -> Result<(), String> {
        self.rouse()?;
        let io = self.control.io().map_err(failed("registers"))?;
        set_mask(io, REG_RCR, OWN_BEACONS, u32::from(own_only)).map_err(failed("receive filter"))
    }

    fn set_edca(&mut self, edca: &[AccessCategory; 4], short_slot: bool) -> Result<(), String> {
        self.rouse()?;
        let band = self.band;
        let io = self.control.io().map_err(failed("registers"))?;
        for category in edca {
            let register = EDCA[usize::from(category.aci & 3)];
            io.write32(register, edca_word(category, band, short_slot))
                .map_err(failed("edca"))?;
        }
        Ok(())
    }

    fn write_key(&mut self, key: &CamKey<'_>) -> Result<(), String> {
        self.rouse()?;
        let words = cam_words(key);
        let address = u32::from(key.entry) << 3;
        let io = self.control.io().map_err(failed("registers"))?;
        for at in (0..8).rev() {
            io.write32(REG_CAM_WRITE, words[at])
                .map_err(failed("cam"))?;
            io.write32(REG_CAM_COMMAND, CAM_WRITE | (address + at as u32))
                .map_err(failed("cam"))?;
        }
        self.keys |= 1 << (key.entry & 31);
        self.save_keys()
    }

    /// `rtw_sec_clear_cam`.
    fn clear_key(&mut self, entry: u8) -> Result<(), String> {
        self.rouse()?;
        let io = self.control.io().map_err(failed("registers"))?;
        io.write32(REG_CAM_WRITE, 0).map_err(failed("cam"))?;
        io.write32(REG_CAM_COMMAND, CAM_WRITE | (u32::from(entry) << 3))
            .map_err(failed("cam"))?;
        self.keys &= !(1 << (entry & 31));
        self.save_keys()
    }

    /// `rtw_phy_dynamic_mechanism`.
    fn watchdog(&mut self, scanning: bool, stbc: bool) -> Result<Watched, String> {
        // rtw88's watchdog work waits for the mutex the calibration holds.
        if self.holding() {
            return Ok(Watched {
                level: self.dynamic.level(),
                busy: true,
            });
        }
        let traffic = self.dynamic.close_period();
        if traffic.busy != core::mem::replace(&mut self.busy, traffic.busy) {
            self.arbitrate(Event::Traffic)?;
        }
        let busy = traffic.sleepless;
        if scanning {
            return Ok(Watched { level: 0, busy });
        }
        self.arbitrate(Event::Watchdog)?;
        let linked = self.connected;
        self.dynamic.sample(linked);
        if linked {
            self.send(commands::rssi(MAC_ID, self.dynamic.rssi(), stbc), "rssi")?;
        }
        let (alarms, cck_alarms) = self.false_alarms()?;
        if let Some(gain) = self.dynamic.gain(alarms, linked) {
            self.write_gain(gain)?;
        }
        let band = self.band;
        let io = self.control.io().map_err(failed("registers"))?;
        if band == Band::Ghz2 {
            self.dynamic
                .detect_cck(io, cck_alarms, linked)
                .map_err(failed("cck detection"))?;
        }
        self.send(self.dynamic.phy_info(), "phy info")?;
        let io = self.control.io().map_err(failed("registers"))?;
        // rtw88 would put the second transmit path back here; a game
        // controller holds it, so one path has none to choose from.
        if linked && !self.single_stream {
            let rates = if band == Band::Ghz5 {
                RESPONSE_RATES_5GHZ
            } else {
                RESPONSE_RATES_2GHZ
            };
            io.write32(REG_RRSR, rates & self.dynamic.response_rates())
                .map_err(failed("response rates"))?;
            self.dynamic
                .choose_path(io)
                .map_err(failed("transmit path"))?;
        }
        let bluetooth_off = Coex::bluetooth_off(io).map_err(failed("coex"))?;
        self.dynamic
            .track_frequency(io, linked, bluetooth_off)
            .map_err(failed("crystal"))?;
        // SAFETY: this worker owns the radio and its frames wait for it.
        unsafe { self.calibration.track(io, &self.report) }.map_err(failed("predistortion"))?;
        // SAFETY: as above.
        unsafe { self.dynamic.track_temperature(io, &self.report, band) }
            .map_err(failed("temperature"))?;
        if self.dynamic.take_unsettled_lock() {
            self.limit_once(LOCK_UNSETTLED);
        }
        self.adapt()?;
        Ok(Watched {
            level: self.dynamic.level(),
            busy,
        })
    }

    /// `rtw_phy_dig_set_max_coverage`, and `rtw_phy_dig_reset` after, each
    /// with `rtw_core_fw_scan_notify`.
    fn scanning(&mut self, scanning: bool) -> Result<(), String> {
        self.rouse()?;
        if scanning {
            self.arbitrate(Event::ScanStarted)?;
        } else {
            self.write_gain(self.dynamic.current_gain())?;
        }
        self.scanning = scanning;
        if self.features & NOTIFY_SCAN != 0 {
            self.send(commands::scan(scanning), "scan notice")?;
        }
        if scanning {
            self.write_gain(dynamic::MAX_COVERAGE)
        } else {
            self.arbitrate(Event::ScanEnded)
        }
    }

    fn signals(&self) -> bool {
        self.vector
    }

    fn limitation(&mut self) -> Option<&'static str> {
        self.limitations.pop()
    }

    /// Any owner of the function quarantined, or a PHY a channel change left
    /// part way: each refuses every later call.
    fn lost(&self) -> bool {
        self.control.quarantined()
            || self.receive.quarantined()
            || self.transmit.quarantined()
            || self.interrupts.state() == interrupt::State::Quarantined
            || self.phy.is_none()
    }

    fn recoverable(&self) -> bool {
        true
    }

    fn recover(&mut self) -> Result<Recovery, String> {
        self.reset_step()
    }
}

/// The calibration's steps on this radio. Frames wait while a calibration
/// runs ([`Hardware::holding`]), and each step comes from the radio's only
/// worker, which is what each register sequence asks of its caller.
impl rfk::Bench for Hardware {
    type Gapk = GapkRun;
    type Iqk = IqkWait;
    type Dpk = DpkRun;

    fn now(&mut self) -> Result<u64, String> {
        let io = self.control.io().map_err(failed("registers"))?;
        io.now_us().map_err(failed("clock"))
    }

    fn power_save(&mut self, on: bool) -> Result<(), String> {
        self.calibration_power_save(on)
    }

    fn bluetooth_idle(&mut self) -> Result<bool, String> {
        let io = self.control.io().map_err(failed("registers"))?;
        self.calibration
            .bluetooth_idle(io)
            .map_err(failed("bluetooth calibration"))
    }

    fn bluetooth_outlasted(&mut self) {
        self.calibration.bluetooth_outlasted();
    }

    fn inform(&mut self, starting: bool) -> Result<(), String> {
        self.send(commands::calibration(starting), "calibration notice")
    }

    fn firmware_answered(&mut self) -> Result<bool, String> {
        let io = self.control.io().map_err(failed("registers"))?;
        Calibration::firmware_answered(io).map_err(failed("calibration handshake"))
    }

    fn firmware_unanswered(&mut self) {
        self.calibration.firmware_unanswered();
    }

    fn gapk_begin(&mut self) -> Result<Option<GapkRun>, String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: this worker owns the radio, and its frames wait for it.
        unsafe { self.calibration.gapk_begin(io, &self.report) }.map_err(failed("gains"))
    }

    fn gapk_start(&mut self, run: &mut GapkRun, at: usize) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: as above, within the run `run` began.
        unsafe { self.calibration.gapk_start(io, &self.report, run, at) }.map_err(failed("gains"))
    }

    fn gapk_measured(&mut self) -> Result<bool, String> {
        let io = self.control.io().map_err(failed("registers"))?;
        Calibration::gapk_measured(io).map_err(failed("gains"))
    }

    fn gapk_finish(&mut self, run: &mut GapkRun, at: usize, done: bool) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: as above.
        unsafe {
            self.calibration
                .gapk_finish(io, &self.report, run, at, done)
        }
        .map_err(failed("gains"))
    }

    fn gapk_end(&mut self, run: GapkRun, measured: bool) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: as above.
        unsafe { self.calibration.gapk_end(io, &self.report, run, measured) }
            .map_err(failed("gains"))
    }

    fn iqk_start(&mut self) -> Result<IqkWait, String> {
        // SAFETY: as above; the IQK's command goes out on this radio's rings.
        unsafe { self.control.start_iqk(&mut self.transmit, self.pages) }.map_err(failed("iqk"))
    }

    fn iqk_poll(&mut self, wait: &mut IqkWait, hurry: bool) -> Result<Option<bool>, String> {
        let Some(observed) = self
            .control
            .poll_iqk(&mut self.transmit, wait, hurry)
            .map_err(failed("iqk"))?
        else {
            return Ok(None);
        };
        if !observed.completed() && !hurry {
            self.limit_once(IQK_UNFINISHED);
        }
        Ok(Some(observed.completed()))
    }

    fn dpk_begin(&mut self) -> Result<Option<DpkRun>, String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: as above.
        unsafe { self.calibration.dpk_begin(io, &self.report) }.map_err(failed("predistortion"))
    }

    fn dpk_gain(&mut self, run: &mut DpkRun, at: usize) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: as above, within the run `run` began.
        unsafe { self.calibration.dpk_gain(io, &self.report, run, at) }
            .map_err(failed("predistortion"))
    }

    fn dpk_search(&mut self, run: &mut DpkRun, at: usize) -> Result<bool, String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: as above.
        unsafe { self.calibration.dpk_search(io, &self.report, run, at) }
            .map_err(failed("predistortion"))
    }

    fn dpk_measure(&mut self, run: &mut DpkRun, at: usize) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: as above.
        unsafe { self.calibration.dpk_measure(io, &self.report, run, at) }
            .map_err(failed("predistortion"))
    }

    fn dpk_skip(&mut self, at: usize) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: as above.
        unsafe { self.calibration.dpk_skip(io, &self.report, at) }.map_err(failed("predistortion"))
    }

    fn dpk_turn_on(&mut self, at: usize) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: as above.
        unsafe { self.calibration.dpk_turn_on(io, &self.report, at) }
            .map_err(failed("predistortion"))
    }

    fn dpk_end(&mut self, run: DpkRun) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: as above.
        unsafe { self.calibration.dpk_end(io, &self.report, run) }.map_err(failed("predistortion"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::Channel;

    fn definition(frequency_mhz: u16, width: Width, center1_mhz: u32) -> ChannelDefinition {
        ChannelDefinition {
            control: Channel {
                band: Band::Ghz5,
                number: (frequency_mhz - 5000) / 5,
                frequency_mhz,
            },
            width,
            center1_mhz,
            center2_mhz: None,
            punctured: 0,
        }
    }

    #[test]
    fn an_80_mhz_channel_names_the_half_its_primary_lies_in() {
        let wide = geometry(&definition(5220, Width::Mhz80, 5210)).unwrap();
        assert_eq!(wide.primary(), 44);
        assert_eq!(wide.centers()[1], Some(46));
        assert_eq!(wide.centers()[2], Some(42));
        let low = geometry(&definition(5180, Width::Mhz80, 5210)).unwrap();
        assert_eq!(low.centers()[1], Some(38));
        assert!(geometry(&definition(5180, Width::Mhz160, 5250)).is_err());
    }

    #[test]
    fn a_queue_word_holds_its_parameters_in_rtw88s_fields() {
        let category = AccessCategory {
            aci: 0,
            admission_control: false,
            aifsn: 3,
            ecw_min: 4,
            ecw_max: 10,
            txop_32us: 94,
        };
        assert_eq!(
            edca_word(&category, Band::Ghz5, true),
            (94 << 16) | 0xa400 | 43
        );
        assert_eq!(edca_word(&category, Band::Ghz2, false) & 0xff, 70);
    }

    #[test]
    fn a_cam_entry_lays_out_its_address_and_key() {
        let material: [u8; 16] = core::array::from_fn(|at| at as u8);
        let key = CamKey {
            entry: 4,
            index: 1,
            kind: 4,
            group: true,
            peer: Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            material: &material,
        };
        let words = cam_words(&key);
        assert_eq!(words[0], 0xbbaa_8051);
        assert_eq!(words[1], 0xffee_ddcc);
        assert_eq!(words[2], 0x0302_0100);
        assert_eq!(words[5], 0x0f0e_0d0c);
        assert_eq!(words[6..], [0, 0]);
    }
}
