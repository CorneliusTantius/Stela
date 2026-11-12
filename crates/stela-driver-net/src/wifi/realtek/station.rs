// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! An RTL8822C as the connection keeper's radio. rtw88 leaves the MAC to
//! mac80211, so what firmware does on other NICs happens here: a scan hops the
//! channels as `ieee80211_scan_work` does, frames carry a host-made IV as
//! `IEEE80211_KEY_FLAG_GENERATE_IV` asks, `Reorder` holds a Block Ack
//! agreement's frames, and robust management frames are sealed in software as
//! `IEEE80211_KEY_FLAG_SW_MGMT_TX` asks. [`Device`] is the hardware beneath it.
use super::{
    bit_rate, ccmp,
    commands::{self, RateInfo, Report},
    descriptor::{
        Aggregate, Packet, QSEL_MANAGEMENT, RATE_1M, RATE_6M, RATE_ID_B, RATE_ID_G, SECURITY_CCMP,
    },
    dynamic, templates,
    transmit::{self, Queue},
};
use crate::wifi::security::{
    aggregate::{OrderedGroup, Shape},
    michael,
};
use crate::wifi::station::fragments::Fragments;
use crate::{
    Clock, Link, LinkError, Mac,
    wifi::{
        Band, Channel, RadioStatus, RawRate, Timestamp,
        connection::keeper::{self, Advertisement, Keeper, Peer, Radio, Stage},
        frame::Mpdu,
        mediatek::reorder::Reorder,
        network::Network,
        regulatory::{
            channel::{DISABLED, NO_IR},
            database::Country,
        },
        scan::{self, Outcome, Retirement, Scanner, result::Bss},
        security::{
            self, Cipher, InstallOutcome, Integrity, KeyIdentity, KeyScope, KeySlot, PacketNumber,
            ReplaySeed, SecurityStatus,
            management::{self as protection, BipKey, ManagementCipher},
            tx::TransmitSeed,
        },
        station::{
            Action, AssociationContext, Completion, Join, NativeBssObservation, Phase as Peering,
            RegulatoryPolicy, Station, Ticket,
            ba::{self, tx},
            data::{self, Ingress, Protection, Qos, SequenceOwner, TxClass, amsdu},
            external,
            multi_link::Affiliation,
            operations::ChannelDefinition,
            phy::{AccessCategory, Capabilities, McsMaps, Role, Width},
            wire::six_ghz::Selection,
        },
    },
};
use alloc::{boxed::Box, collections::VecDeque, format, string::String, sync::Arc, vec::Vec};
use core::fmt;
use stela_driver_base::entropy::Entropy;
use zeroize::Zeroizing;

/// `IEEE80211_CHANNEL_TIME` and `IEEE80211_PASSIVE_CHANNEL_TIME`.
const ACTIVE_DWELL_US: u64 = 30_000;
const PASSIVE_DWELL_US: u64 = 111_000;
/// How long an interrupt-driven station may sleep past its timers, which are
/// reorder releases, retries and the keeper's own.
const TIMER_TICK_US: u64 = 100_000;
/// `RTW_WATCH_DOG_DELAY_TIME`.
const WATCHDOG_US: u64 = 2_000_000;
/// `IEEE80211_SCAN_RESULT_EXPIRE`.
const BSS_EXPIRY_US: u64 = 30_000_000;
/// rtw88's sole station shares its interface's MAC ID, the first it acquires.
pub const MAC_ID: u8 = 0;
/// `rtw_ops_add_interface`'s first port.
pub const PORT: u8 = 0;
/// `RTW_SEC_DEFAULT_KEY_NUM`: group keys sit at their index, pairwise ones after.
const PAIRWISE_CAM: u8 = 4;
/// `RTW_CAM_TKIP` and `RTW_CAM_AES`.
const CAM_TKIP: u8 = 2;
const CAM_AES: u8 = 4;
/// `WLAN_HT_SMPS_CONTROL_DISABLED` and `WLAN_HT_SMPS_CONTROL_STATIC`.
const SMPS_DISABLED: u8 = 0;
const SMPS_STATIC: u8 = 1;
/// `IEEE80211_MIN_AMPDU_BUF`'s window, which `HT_RX_REORDER_BUF_TIMEOUT` serves.
const RECEIVE_WINDOW: u16 = 64;
/// mac80211's `max_tx_aggregation_subframes`, which rtw88 leaves alone.
const TRANSMIT_WINDOW: u16 = 64;
/// A reorder clock of microseconds, `HT_RX_REORDER_BUF_TIMEOUT` of 100 ms.
const REORDER_TICKS_PER_SECOND: u32 = 1_000_000;
/// The frames a TID waits with while its queue is full.
const MAX_HELD: usize = 256;
/// A CCMP header, the IV a frame carries behind its MAC header.
const IV_BYTES: usize = 8;
/// `IEEE80211_TKIP_ICV_LEN`, and where a TKIP key keeps the Michael key for
/// what it receives, `NL80211_TKIP_DATA_OFFSET_RX_MIC_KEY`.
const ICV_BYTES: usize = 4;
const RECEIVE_MICHAEL_KEY: usize = 24;
/// `ieee80211_add_wmm_info_ie`, without U-APSD.
const WMM_ELEMENT: [u8; 9] = [221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0];
/// `WLAN_CATEGORY_BACK`.
const BLOCK_ACK_CATEGORY: u8 = 3;

/// One received frame, as `rtw_rx_query_rx_desc` reads it.
#[derive(Clone, Debug)]
pub struct Received {
    /// The MPDU, its FCS removed. `BIT_APP_MIC` keeps a decrypted frame's IV and
    /// MIC, as mac80211 expects of `RX_FLAG_DECRYPTED` alone.
    pub bytes: Vec<u8>,
    pub tsf: u32,
    pub decrypted: bool,
    pub icv_error: bool,
    pub signal_dbm: Option<i8>,
}

/// What the device gave the host.
#[derive(Clone, Debug)]
pub enum Incoming {
    Frame(Received),
    Report(Report),
}

/// The key `rtw_sec_write_cam` writes to a CAM entry.
pub struct CamKey<'a> {
    pub entry: u8,
    pub index: u8,
    pub kind: u8,
    pub group: bool,
    pub peer: Mac,
    pub material: &'a [u8; 16],
}

/// What a radio's station needs of the hardware beneath it. Each operation is
/// the hardware half of the mac80211 or rtw88 operation it names.
pub trait Device {
    /// `rtw_set_channel`. While `scanning`, no calibration follows.
    fn tune(
        &mut self,
        definition: &ChannelDefinition,
        scanning: bool,
        eirp_mbm: i32,
    ) -> Result<(), String>;
    /// `rtw_chip_prepare_tx`: calibrate for the channel a frame will leave on.
    fn prepare_transmit(&mut self) -> Result<(), String>;
    /// `rtw_pci_tx_write_data` and its kick. False asks to try again.
    fn transmit(&mut self, queue: Queue, packet: &Packet, mpdu: &[u8]) -> Result<bool, String>;
    /// `rtw_pci_rx_napi`: what arrived since the last look.
    fn receive(&mut self, sink: &mut dyn FnMut(Incoming)) -> Result<(), String>;
    fn command(&mut self, command: (u32, u32)) -> Result<(), String>;
    /// `rtw_vif_port_config` of the BSSID, AID and link state.
    fn set_port(&mut self, bssid: Mac, aid: u16, linked: bool) -> Result<(), String>;
    /// `rtw_ops_configure_filter`: keep only the BSS's own beacons, or all.
    fn filter_beacons(&mut self, own_only: bool) -> Result<(), String>;
    /// `__rtw_conf_tx` of every access category.
    fn set_edca(&mut self, edca: &[AccessCategory; 4], short_slot: bool) -> Result<(), String>;
    fn write_key(&mut self, key: &CamKey<'_>) -> Result<(), String>;
    fn clear_key(&mut self, entry: u8) -> Result<(), String>;
    /// `rtw_fw_download_rsvd_page` and `rtw_send_rsvd_page_h2c`.
    fn set_templates(&mut self, _templates: &templates::Templates) -> Result<(), String> {
        Ok(())
    }
    /// `rtw_enter_lps` and `rtw_leave_lps`, which each stand for being there.
    fn set_power_save(&mut self, _on: bool) -> Result<(), String> {
        Ok(())
    }
    /// The beacons' interval and DTIM period.
    fn set_beacon(&mut self, _interval_tu: u16, _dtim_period: u8) -> Result<(), String> {
        Ok(())
    }
    /// `rtw_vif_smps_iter`: the next change to one stream or back to two.
    fn stream_change(&mut self) -> Option<bool> {
        None
    }
    /// A look at the Bluetooth arbiter's timers, at `now`.
    fn coexist(&mut self, _now: u64) -> Result<(), String> {
        Ok(())
    }
    /// `rtw_watch_dog_work`'s traffic accounts, and unless `scanning` its work
    /// on the air, for a peer that takes STBC or not.
    fn watchdog(&mut self, _scanning: bool, _stbc: bool) -> Result<Watched, String> {
        Ok(Watched::default())
    }
    /// `rtw_core_scan_start` and `rtw_core_scan_complete`'s gain.
    fn scanning(&mut self, _scanning: bool) -> Result<(), String> {
        Ok(())
    }
    /// Whether an interrupt wakes the core that looks for frames.
    fn signals(&self) -> bool {
        false
    }
    /// What the hardware does not do yet, each named once or more.
    fn limitation(&mut self) -> Option<&'static str> {
        None
    }
}

#[derive(Debug)]
pub enum Error {
    Hardware(String),
    Station(crate::wifi::station::Error),
    BlockAck(ba::Error),
    Data(data::Error),
    Key(security::Error),
    Scan(scan::Error),
    Refused(&'static str),
    Unsupported(&'static str),
    /// Frames must drain before this can go on.
    Pending,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The keeper's handle on the IGTK the host holds.
pub struct ManagementKey;

/// A BSS and when it was last heard, a `cfg80211_internal_bss`.
struct Heard {
    observation: Arc<NativeBssObservation>,
    at: u64,
}

/// A scan's walk over its channels, `ieee80211_scan_work`.
struct Hop {
    ticket: scan::Ticket,
    channels: Vec<Channel>,
    next: usize,
    leaves_at: u64,
}

/// What a run of the watchdog found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Watched {
    /// The peer's `rssi_level`.
    pub level: u8,
    /// Too many frames for power save.
    pub busy: bool,
}

/// One key the CAM holds.
struct Key {
    slot: KeySlot,
    pairwise: bool,
    index: u8,
    entry: u8,
    material: Zeroizing<Vec<u8>>,
}

/// The channels the country admits, which the real check gates at each frame.
struct Admitted<'a>(&'a [(Channel, u32)]);

impl RegulatoryPolicy for Admitted<'_> {
    fn allow_management_tx(&mut self, channel: Channel) -> bool {
        self.0.iter().any(|(known, _)| *known == channel)
    }
    fn allow_data_tx(&mut self, channel: Channel) -> bool {
        self.allow_management_tx(channel)
    }
}

impl scan::Policy for Admitted<'_> {
    fn allow_receive(&mut self, channel: Channel) -> bool {
        self.0.iter().any(|(known, _)| *known == channel)
    }
    fn allow_probe(&mut self, _: Channel) -> bool {
        true
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        self.0
            .iter()
            .map(|(channel, _)| *channel)
            .find(|channel| channel.band == band && channel.number == number)
    }
}

fn management(local: Mac, ap: Mac, subtype: u16, protected: bool, body: &[u8]) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 24];
    let control = subtype | if protected { 0x4000 } else { 0 };
    bytes[..2].copy_from_slice(&control.to_le_bytes());
    bytes[4..10].copy_from_slice(&ap.0);
    bytes[10..16].copy_from_slice(&local.0);
    bytes[16..22].copy_from_slice(&ap.0);
    bytes.extend_from_slice(body);
    bytes
}

/// `rtw_init_ht_cap` and `rtw_init_vht_cap` of a two-stream 80 MHz RTL8822C, as
/// the elements an association request carries.
fn capability_elements(band: Band) -> Vec<u8> {
    // SGI 20, max A-MSDU 7935, one RX STBC stream, LDPC, TX STBC, 40 MHz,
    // DSSS/CCK in 40 MHz, SGI 40, and SM power save off.
    let ht: u16 =
        (1 << 5) | (1 << 11) | (1 << 8) | 1 | (1 << 7) | (1 << 1) | (1 << 12) | (1 << 6) | (3 << 2);
    let mut elements = alloc::vec![45, 26];
    elements.extend_from_slice(&ht.to_le_bytes());
    // IEEE80211_HT_MAX_AMPDU_64K and IEEE80211_HT_MPDU_DENSITY_2.
    elements.push(3 | (4 << 2));
    elements.extend_from_slice(&[0xff, 0xff, 0, 0, 1, 0, 0, 0, 0, 0]);
    elements.extend_from_slice(&300u16.to_le_bytes());
    // IEEE80211_HT_MCS_TX_DEFINED.
    elements.extend_from_slice(&[1, 0, 0, 0]);
    elements.extend_from_slice(&[0; 7]);
    // mac80211's `ext_capa`: operating mode notifications.
    elements.extend_from_slice(&[127, 8, 0, 0, 0, 0, 0, 0, 0, 0x40]);
    if band == Band::Ghz5 {
        // MPDU 11454, SGI 80, RX LDPC, TX STBC, one RX STBC stream, HTC-VHT,
        // the largest A-MPDU.
        let vht: u32 = 2 | (1 << 5) | (1 << 4) | (1 << 7) | (1 << 8) | (1 << 22) | (7 << 23);
        elements.extend_from_slice(&[191, 12]);
        elements.extend_from_slice(&vht.to_le_bytes());
        for _ in 0..2 {
            // MCS 0-9 on two streams, and 780 Mb/s.
            elements.extend_from_slice(&0xfffau16.to_le_bytes());
            elements.extend_from_slice(&780u16.to_le_bytes());
        }
    }
    elements
}

/// The rates of `rtw_band_2ghz` and `rtw_band_5ghz`.
fn rate_elements(band: Band) -> &'static [u8] {
    match band {
        Band::Ghz2 => &[1, 8, 2, 4, 11, 22, 12, 18, 24, 36, 50, 4, 48, 72, 96, 108],
        _ => &[1, 8, 12, 18, 24, 36, 48, 72, 96, 108],
    }
}

/// `ieee80211_probereq_get`: the elements of a scan's probe on `band`.
fn probe_request(local: Mac, ssid: &[u8], band: Band, extra: &[u8]) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 24];
    bytes[..2].copy_from_slice(&0x40u16.to_le_bytes());
    bytes[4..10].fill(0xff);
    bytes[10..16].copy_from_slice(&local.0);
    bytes[16..22].fill(0xff);
    bytes.extend_from_slice(&[0, ssid.len() as u8]);
    bytes.extend_from_slice(ssid);
    bytes.extend_from_slice(rate_elements(band));
    bytes.extend_from_slice(&capability_elements(band));
    bytes.extend_from_slice(extra);
    bytes
}

/// `rtw_update_sta_info`'s rate ID and what it tells firmware of the peer, on
/// a link `width` wide.
/// `enum rtw_bandwidth`.
fn width_code(width: Width) -> u8 {
    match width {
        Width::Mhz80 => 2,
        Width::Mhz40 => 1,
        _ => 0,
    }
}

/// What `ieee80211_crypto_tkip_decrypt` and `ieee80211_rx_h_michael_mic_verify`
/// make of a TKIP frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Michael {
    Intact,
    /// A frame this key already took, or no TKIP frame at all: dropped, with
    /// no verdict on Michael.
    Dropped,
    Failed,
}

/// Check `frame`, decrypted with `IV` and trailer in place, under `key`.
/// Michael covers an MSDU, so fragments never reach here.
fn check_michael(frame: &mut Mpdu, key: &Key) -> Michael {
    let header = *frame.header();
    let bytes = frame.bytes();
    let body = header.length + IV_BYTES;
    let Some(end) = bytes.len().checked_sub(ICV_BYTES + michael::MIC_BYTES) else {
        return Michael::Dropped;
    };
    let Some(Ok((number, _))) = bytes
        .get(header.length..)
        .map(PacketNumber::from_tkip_header)
    else {
        return Michael::Dropped;
    };
    if end < body {
        return Michael::Dropped;
    }
    let source = bytes[16..22].try_into().unwrap_or([0; 6]);
    let stored = bytes[end..end + michael::MIC_BYTES].to_vec();
    let mut mic_key = [0; michael::MIC_BYTES];
    mic_key.copy_from_slice(&key.material[RECEIVE_MICHAEL_KEY..]);
    let priority = header.tid.unwrap_or(0);
    let computed = michael::michael(
        &mic_key,
        &header.receiver.0,
        &source,
        priority,
        &bytes[body..end],
    );
    frame.security.pn = Some(number);
    if key.slot.replays(frame) {
        Michael::Dropped
    } else if computed == stored[..] {
        Michael::Intact
    } else {
        Michael::Failed
    }
}

fn rate_info(context: &AssociationContext, width: Width, initial: bool, level: u8) -> RateInfo {
    let negotiated = context.negotiated();
    let band = context.channel().band;
    let ht = negotiated.ht.as_ref();
    let vht = negotiated.vht.as_ref();
    let legacy = u64::from(negotiated.legacy.supported);
    let streams = if ht.is_some_and(|ht| ht.peer_rx_mcs[1] != 0) || vht.is_some() {
        2
    } else {
        1
    };
    // CCK in bits 0..4, OFDM in 4..12, then HT's or VHT's rates.
    let mut mask = if band == Band::Ghz2 {
        legacy
    } else {
        legacy << 4
    };
    if let Some(vht) = vht {
        mask |= vht_mask(vht.mcs.rx);
    } else if let Some(ht) = ht {
        mask |= (u64::from(ht.peer_rx_mcs[1]) << 20) | (u64::from(ht.peer_rx_mcs[0]) << 12);
    }
    let cck_only = band == Band::Ghz2 && vht.is_none() && ht.is_none() && legacy <= 0xf;
    let mask = dynamic::rates_at_level(mask, level, cck_only);
    let width = width_code(width);
    // `get_rate_id`.
    let rate_id = match (band, vht.is_some(), ht.is_some(), streams, width) {
        (Band::Ghz2, true, _, 2, _) => 12,
        (Band::Ghz2, true, _, _, _) => 11,
        (_, true, _, 2, _) => 9,
        (_, true, _, _, _) => 10,
        (Band::Ghz2, _, true, 2, 1) => 0,
        (Band::Ghz2, _, true, 1, 1) => 1,
        (Band::Ghz2, _, true, 2, _) => 2,
        (Band::Ghz2, _, true, _, _) => 3,
        (_, _, true, 2, _) => 4,
        (_, _, true, _, _) => 5,
        (Band::Ghz2, ..) if legacy <= 0xf => RATE_ID_B,
        (Band::Ghz2, ..) => 6,
        _ => RATE_ID_G,
    };
    RateInfo {
        mac_id: MAC_ID,
        rate_id,
        initial_level: u8::from(initial),
        short_gi: match width {
            2 => vht.is_some_and(|vht| vht.capability & (1 << 5) != 0),
            1 => ht.is_some_and(|ht| ht.capability & (1 << 6) != 0),
            _ => ht.is_some_and(|ht| ht.capability & (1 << 5) != 0),
        },
        width,
        ldpc: vht.map_or(ht.is_some_and(|ht| ht.capability & 1 != 0), |vht| {
            vht.capability & (1 << 4) != 0
        }),
        no_update: !initial,
        vht: if vht.is_some() { 2 } else { 0 },
        mask: mask as u32,
    }
}

/// `si->stbc_en`.
fn peer_stbc(context: &AssociationContext) -> bool {
    let negotiated = context.negotiated();
    match (&negotiated.vht, &negotiated.ht) {
        (Some(vht), _) => vht.capability & 0x700 != 0,
        (_, Some(ht)) => ht.capability & 0x300 != 0,
        _ => false,
    }
}

/// `get_vht_ra_mask`, of the two streams firmware's 32-bit mask reaches.
fn vht_mask(map: u16) -> u64 {
    let stream = |map: u16| match map & 3 {
        0 => 0x0ff,
        1 => 0x1ff,
        2 => 0x3ff,
        _ => 0,
    };
    (stream(map) << 12) | (stream(map >> 2) << 22)
}

/// `get_highest_vht_tx_rate` and `get_highest_ht_tx_rate`: the rate firmware's
/// rate adaptation starts a frame's descriptor from.
fn highest_rate(context: &AssociationContext) -> u8 {
    let negotiated = context.negotiated();
    if let Some(vht) = &negotiated.vht {
        match (vht.mcs.tx >> 2) & 3 {
            0 => 0x3d,
            1 => 0x3e,
            _ => 0x3f,
        }
    } else if let Some(ht) = &negotiated.ht {
        if ht.peer_rx_mcs[1] != 0 { 0x1b } else { 0x13 }
    } else if negotiated.legacy.supported <= 0xf {
        3
    } else {
        0x0b
    }
}

/// The 20 MHz definition around `channel`, which a scan and a join stand on.
fn twenty(channel: Channel) -> ChannelDefinition {
    ChannelDefinition {
        control: channel,
        width: Width::Mhz20,
        center1_mhz: u32::from(channel.frequency_mhz),
        center2_mhz: None,
        punctured: 0,
    }
}

/// An RTL8822C kept connected to one network.
pub type Wifi<D> = Keeper<Rtl8822c<D>>;

/// An RTL8822C's association state.
pub struct Rtl8822c<D: Device> {
    device: D,
    address: Mac,
    clock: Clock,
    country: Country,
    channels: Vec<(Channel, u32)>,
    station: Station,
    scanner: Scanner,
    hop: Option<Hop>,
    /// A scan finished and waits for the keeper.
    scanned: Option<scan::Ticket>,
    observed: Vec<Heard>,
    outbox: VecDeque<(Option<Ticket>, Vec<u8>)>,
    events: VecDeque<keeper::Event>,
    /// What beacons said of the AP since association.
    following: Option<follow::Following>,
    received: VecDeque<Vec<u8>>,
    /// Data frames waiting for room, each with its queue and descriptor.
    held: VecDeque<(Queue, Packet, Vec<u8>)>,
    /// Data kept from a TID whose transmit agreement is changing, as
    /// `ieee80211_agg_stop_txq` keeps it in the TXQ.
    parked: VecDeque<(u8, Vec<u8>, TxClass)>,
    /// What transmit agreements have yet to do, in turn.
    changes: VecDeque<tx::Action>,
    /// Each TID's agreement in force, `RTW_TXQ_AMPDU`.
    aggregating: [Option<Arc<tx::Session>>; 8],
    /// The TIDs an agreement cannot start on, `RTW_TXQ_BLOCK_BA`.
    unaggregated: [bool; 8],
    /// The TIDs whose agreement carries no A-MSDU, `IEEE80211_TXQ_NO_AMSDU`.
    no_amsdu: [bool; 8],
    /// `agg.max_rc_amsdu_len`, which starts unset.
    rate_amsdu: u16,
    /// The frame last held is plain data, which others may join.
    tail_joins: bool,
    admitted: Option<(Ticket, Arc<AssociationContext>)>,
    context: Option<Arc<AssociationContext>>,
    keys: Vec<Key>,
    next_slot: u16,
    /// The join's management cipher, and the IGTK the host checks frames under.
    management_cipher: Option<ManagementCipher>,
    integrity: Option<BipKey>,
    /// The channel the radio stands on.
    tuned: Option<Channel>,
    /// The frames each TID's Block Ack agreement holds in order.
    agreements: [Option<Reorder<Mpdu>>; 8],
    fragments: Fragments,
    /// The next TX report number, `tx_report.sn`.
    report: u8,
    /// A report's number, which the management frame it names may await.
    reporting: Option<u8>,
    port_open: bool,
    watchdog_at: u64,
    /// `rtwdev->watch_dog_cnt`.
    watchdogs: u32,
    departing: Option<Ticket>,
    left: bool,
    reported: Vec<&'static str>,
    /// Frames and reports refused and dropped, as mac80211 counts `rx_dropped`.
    dropped: u64,
}

impl<D: Device> Rtl8822c<D> {
    /// `device`, running at `address` under `country`, as a keeper's radio.
    pub fn new(device: D, address: Mac, country: Country, clock: Clock) -> Result<Self, Error> {
        let channels = channels(&country);
        let watchdog_at = clock.now_us() + WATCHDOG_US;
        Ok(Self {
            device,
            address,
            clock,
            country,
            channels,
            station: Station::new(address).map_err(Error::Station)?,
            scanner: Scanner::new(address).map_err(Error::Scan)?,
            hop: None,
            scanned: None,
            observed: Vec::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            following: None,
            received: VecDeque::new(),
            held: VecDeque::new(),
            parked: VecDeque::new(),
            changes: VecDeque::new(),
            aggregating: Default::default(),
            unaggregated: [false; 8],
            no_amsdu: [false; 8],
            rate_amsdu: 0,
            tail_joins: false,
            admitted: None,
            context: None,
            keys: Vec::new(),
            next_slot: 0,
            management_cipher: None,
            integrity: None,
            tuned: None,
            agreements: Default::default(),
            fragments: Fragments::default(),
            report: 0,
            reporting: None,
            port_open: false,
            watchdog_at,
            watchdogs: 0,
            departing: None,
            left: false,
            reported: Vec::new(),
            dropped: 0,
        })
    }

    /// Keep `self` connected to `network`; `entropy` gives each handshake's
    /// SNonce.
    pub fn keep(self, network: Network, entropy: Arc<dyn Entropy>) -> Wifi<D> {
        let clock = self.clock;
        Keeper::keep(self, network, entropy, clock)
    }

    fn hardware<T>(result: Result<T, String>) -> Result<T, Error> {
        result.map_err(Error::Hardware)
    }

    /// `chan->max_reg_power` of the channel at `frequency_mhz`.
    fn eirp_mbm(&self, frequency_mhz: u16) -> i32 {
        self.regulated_power_dbm(frequency_mhz) * 100
    }

    fn unsupported(&mut self, operation: &'static str) {
        if !self.reported.contains(&operation) {
            self.reported.push(operation);
            self.events.push_back(keeper::Event::Unsupported(operation));
        }
    }

    fn act(&mut self, action: Action) {
        match action {
            Action::Transmit { ticket, bytes, .. } => {
                self.outbox.push_back((Some(ticket), bytes));
            }
            Action::Configure {
                ticket,
                context: Some(context),
                ..
            } => self.admitted = Some((ticket, context)),
            // Every join here is a modern one, which carries its context.
            Action::Configure { .. } => {
                self.admitted = None;
                if let Ok(Action::Remove { ticket, failure }) = self.station.disconnect() {
                    self.depart(ticket, failure);
                }
            }
            Action::Remove { ticket, failure } => self.depart(ticket, failure),
        }
    }

    fn depart(&mut self, ticket: Ticket, failure: Option<crate::wifi::station::Failure>) {
        if let Some(failure) = failure
            && self.station.external_authentication().is_some()
        {
            self.events
                .push_back(keeper::Event::SaeEnded(format!("{failure:?}")));
        }
        self.departing = Some(ticket);
        self.left = true;
        self.port_open = false;
        self.admitted = None;
        self.outbox.clear();
        self.held.clear();
        self.parked.clear();
        self.end_aggregation();
    }

    /// `ieee80211_sta_tear_down_BA_sessions`, with no frame left to send.
    fn end_aggregation(&mut self) {
        for tid in 0..8 {
            if let Ok(action) = self.station.stop_tx_block_ack(tid, false) {
                self.changes.push_back(action);
            }
        }
        if self.change_agreements().is_err() {
            self.unsupported("a transmit agreement that would not end");
        }
    }

    /// `rtw_sta_remove` and `rtw_ops_bss_info_changed` of the disassociation.
    fn clear(&mut self) -> Result<(), Error> {
        for key in core::mem::take(&mut self.keys) {
            Self::hardware(self.device.clear_key(key.entry))?;
        }
        self.power_save(false)?;
        for agreement in &mut self.agreements {
            *agreement = None;
        }
        self.fragments.clear();
        self.changes.clear();
        self.aggregating = Default::default();
        self.unaggregated = [false; 8];
        Self::hardware(self.device.command(commands::media_status(MAC_ID, false)))?;
        Self::hardware(self.device.set_port(Mac([0; 6]), 0, false))?;
        Self::hardware(self.device.filter_beacons(false))?;
        self.context = None;
        self.following = None;
        self.integrity = None;
        self.management_cipher = None;
        self.departing = None;
        self.left = false;
        self.reporting = None;
        Ok(())
    }

    fn observed(&self, handle: usize) -> Result<Arc<NativeBssObservation>, Error> {
        self.observed
            .get(handle)
            .map(|heard| heard.observation.clone())
            .ok_or(Error::Refused("the BSS is gone"))
    }

    /// `ieee80211_prep_channel` for the exchange ahead of an association.
    fn approach(&mut self, bss: &Bss) -> Result<(), Error> {
        Self::hardware(self.device.filter_beacons(true))?;
        let eirp_mbm = self.eirp_mbm(bss.channel.frequency_mhz);
        Self::hardware(self.device.tune(&twenty(bss.channel), false, eirp_mbm))?;
        self.tuned = Some(bss.channel);
        Self::hardware(self.device.set_port(bss.bssid, 0, false))?;
        Self::hardware(self.device.prepare_transmit())
    }

    fn walk(&mut self, now: u64) -> Result<(), Error> {
        let Some(hop) = &self.hop else {
            return Ok(());
        };
        if now < hop.leaves_at {
            return Ok(());
        }
        let ticket = hop.ticket;
        let Some(channel) = hop.channels.get(hop.next).copied() else {
            self.hop = None;
            Self::hardware(self.device.scanning(false))?;
            self.scanner
                .completed(ticket, Outcome::Completed)
                .map_err(Error::Scan)?;
            self.scanned = Some(ticket);
            return Ok(());
        };
        let request = self.scanner.request().ok_or(Error::Refused("scan"))?;
        let active = request.active() && self.probes(channel);
        let probes: Vec<Vec<u8>> = if active {
            let extra = request.extra_elements();
            let probe = |ssid: &Vec<u8>| probe_request(self.address, ssid, channel.band, extra);
            request.ssids().iter().map(probe).collect()
        } else {
            Vec::new()
        };
        if let Some(hop) = &mut self.hop {
            hop.next += 1;
            hop.leaves_at = now
                + if active {
                    ACTIVE_DWELL_US
                } else {
                    PASSIVE_DWELL_US
                };
        }
        let eirp_mbm = self.eirp_mbm(channel.frequency_mhz);
        Self::hardware(self.device.tune(&twenty(channel), true, eirp_mbm))?;
        self.tuned = Some(channel);
        for probe in probes {
            let packet = self.management_packet(channel.band, &probe, None, None);
            Self::hardware(self.device.transmit(Queue::Management, &packet, &probe))?;
        }
        Ok(())
    }

    /// `rtw_watch_dog_work`.
    fn watchdog(&mut self, now: u64) -> Result<(), Error> {
        if now < self.watchdog_at {
            return Ok(());
        }
        self.watchdog_at = now + WATCHDOG_US;
        let scanning = self.hop.is_some();
        let stbc = self.context.as_deref().is_some_and(peer_stbc);
        if !scanning {
            self.power_save(false)?;
        }
        let Watched { level, busy } = Self::hardware(self.device.watchdog(scanning, stbc))?;
        if scanning {
            return Ok(());
        }
        // `rtw_phy_ra_info_update`.
        if self.watchdogs & 3 == 0
            && let Some(context) = &self.context
        {
            let info = rate_info(context, self.width(context), false, level);
            Self::hardware(self.device.command(commands::ra_info(info)))?;
        }
        self.watchdogs = self.watchdogs.wrapping_add(1);
        // `rtw_recalc_lps`, with `ieee80211_powersave_allowed`.
        let allowed = self.port_open
            && self
                .following
                .as_ref()
                .is_some_and(follow::Following::may_sleep);
        if allowed && !busy {
            self.power_save(true)?;
        }
        Ok(())
    }

    /// `ieee80211_request_smps` of each change the radio made.
    fn announce_streams(&mut self) -> Result<(), Error> {
        while let Some(single) = self.device.stream_change() {
            if let Some(context) = &self.context
                && context.negotiated().ht.is_some()
            {
                let control = if single { SMPS_STATIC } else { SMPS_DISABLED };
                let frame = self
                    .station
                    .spatial_power_save(context, control)
                    .map_err(Error::Station)?;
                self.outbox.push_back((None, frame));
            }
        }
        Ok(())
    }

    /// `rtw_enter_lps` and `rtw_leave_lps`.
    fn power_save(&mut self, on: bool) -> Result<(), Error> {
        Self::hardware(self.device.set_power_save(on))
    }

    /// The width the link to `context` runs at.
    fn width(&self, context: &AssociationContext) -> Width {
        self.following
            .as_ref()
            .map_or(context.negotiated().width, follow::Following::width)
    }

    /// The AP asked for silence, `ieee80211_vif_block_queues_csa`.
    fn silent(&self) -> bool {
        self.following
            .as_ref()
            .is_some_and(follow::Following::silent)
    }

    /// `rtw_tx_mgmt_pkt_info_update` of `bytes`, at the BSS's lowest basic rate.
    fn management_packet(
        &self,
        band: Band,
        bytes: &[u8],
        report: Option<u8>,
        basic: Option<u16>,
    ) -> Packet {
        let (rate_id, lowest) = if band == Band::Ghz2 {
            (RATE_ID_B, RATE_1M)
        } else {
            (RATE_ID_G, RATE_6M)
        };
        let rate = basic
            .filter(|&basic| basic != 0)
            .map_or(lowest, |basic| lowest + basic.trailing_zeros() as u8);
        Packet {
            size: bytes.len() as u16,
            multicast: bytes[4] & 1 != 0,
            mac_id: MAC_ID,
            queue: QSEL_MANAGEMENT,
            rate_id,
            report,
            fixed_rate: true,
            rate,
            device_sequence: true,
            ..Packet::default()
        }
    }

    fn send_management(&mut self) -> Result<(), Error> {
        while let Some((ticket, bytes)) = self.outbox.front().cloned() {
            if self.silent() {
                return Ok(());
            }
            let band = self.tuned.map_or(Band::Ghz2, |channel| channel.band);
            let basic = self.context.as_ref().map(|c| c.negotiated().legacy.basic);
            let report = ticket.is_some().then_some(self.report);
            let bytes = if bytes[1] & 0x40 != 0 {
                self.seal(&bytes)?
            } else {
                bytes
            };
            let packet = self.management_packet(band, &bytes, report, basic);
            if !Self::hardware(self.device.transmit(Queue::Management, &packet, &bytes))? {
                return Ok(());
            }
            self.outbox.pop_front();
            if let Some(ticket) = ticket {
                self.reporting = report;
                self.report = self.report.wrapping_add(4);
                self.station.submitted(ticket).map_err(Error::Station)?;
            }
        }
        Ok(())
    }

    /// `IEEE80211_KEY_FLAG_SW_MGMT_TX`: mac80211 seals a robust management frame
    /// itself, under the pairwise key.
    fn seal(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self
            .keys
            .iter_mut()
            .find(|key| key.pairwise)
            .ok_or(Error::Refused("no pairwise key"))?;
        let identity = key.slot.installed().ok_or(Error::Refused("no key"))?;
        let nonce = key
            .slot
            .reserve_host_tx_nonce(identity)
            .map_err(Error::Key)?;
        let pn = nonce.packet_number();
        let header = nonce.into_header();
        let material: &[u8; 16] = key.material[..]
            .try_into()
            .map_err(|_| Error::Unsupported("a management key longer than CCMP-128's"))?;
        Ok(ccmp::seal(
            material,
            &bytes[..24],
            &header,
            pn,
            &bytes[24..],
        ))
    }

    fn send_data(&mut self) -> Result<(), Error> {
        while !self.silent()
            && let Some((queue, packet, mpdu)) = self.held.front()
        {
            if !Self::hardware(self.device.transmit(*queue, packet, mpdu))? {
                return Ok(());
            }
            let session = packet
                .aggregate
                .and(self.aggregating[usize::from(packet.queue)].clone());
            self.held.pop_front();
            if let Some(session) = session {
                let now = self.clock.now_us();
                // SAFETY: this frame just went to the rings under `session`.
                // A stop under way has revoked it, and that refusal is right.
                let _ = unsafe { self.station.tx_block_ack_published(&session, now) };
            }
        }
        Ok(())
    }

    /// `rtw_txq_check_agg` and `rtw_txq_ba_iter` of data just queued on `tid`.
    fn start_aggregation(&mut self, tid: u8) {
        let index = usize::from(tid);
        if self.aggregating[index].is_some() || self.unaggregated[index] {
            return;
        }
        let now = self.clock.now_us();
        // A PMF association's ADDBA goes under the pairwise key.
        let started = if !self.station.requires_protected_management() {
            self.station.begin_tx_block_ack(tid, 0, now)
        } else if self.keys.iter().any(|key| key.pairwise) {
            self.station.begin_authenticated_tx_block_ack(tid, 0, now)
        } else {
            return;
        };
        match started {
            Ok(action) => self.changes.push_back(action),
            // `ieee80211_start_tx_ba_session`'s -EINVAL ends the attempts; its
            // other refusals leave the next frame to ask again.
            Err(ba::Error::Unsupported | ba::Error::InvalidLimits) => {
                self.unaggregated[index] = true;
            }
            Err(_) => {}
        }
    }

    /// mac80211's aggregation work over `rtw_ops_ampdu_action`, in which
    /// firmware holds no agreement: only a descriptor asks it to aggregate.
    fn change_agreements(&mut self) -> Result<(), Error> {
        while let Some(action) = self.changes.pop_front() {
            let now = self.clock.now_us();
            let next = match action {
                tx::Action::Prepare { ticket, session } => {
                    let tid = session.tid();
                    // mac80211 numbers a frame as it leaves the TXQ, so nothing
                    // it stopped has a number. What this numbered goes first.
                    if self.held.iter().any(|(_, packet, _)| packet.queue == tid) {
                        self.changes
                            .push_front(tx::Action::Prepare { ticket, session });
                        return Ok(());
                    }
                    let sequence = self
                        .context
                        .as_ref()
                        .and_then(|context| self.station.next_qos_sequence(context, tid).ok());
                    // SAFETY: new data of this TID waits in `parked`, none of
                    // it is held, and `sequence` is the station's own counter.
                    unsafe {
                        self.station.complete_tx_block_ack_prepare(
                            ticket,
                            Completion::Accepted,
                            sequence,
                            now,
                        )
                    }
                }
                tx::Action::Transmit {
                    ticket,
                    session,
                    bytes,
                } => {
                    let result = if self.left
                        || self
                            .station
                            .validate_tx_block_ack_transmit(ticket, &session, &bytes)
                            .is_err()
                    {
                        Completion::RejectedAndIdle
                    } else if self.silent() || !self.send_agreement_frame(&bytes)? {
                        self.changes.push_front(tx::Action::Transmit {
                            ticket,
                            session,
                            bytes,
                        });
                        return Ok(());
                    } else {
                        Completion::Accepted
                    };
                    // SAFETY: the frame reached the rings, or never will.
                    unsafe {
                        self.station
                            .complete_tx_block_ack_transmit(ticket, result, now)
                    }
                }
                tx::Action::Program {
                    ticket,
                    session,
                    agreement,
                } => {
                    if agreement.is_none() {
                        let tid = session.tid();
                        self.aggregating[usize::from(tid)] = None;
                        for (_, packet, _) in &mut self.held {
                            if packet.queue == tid {
                                packet.aggregate = None;
                            }
                        }
                    }
                    // SAFETY: firmware holds nothing to change. As under
                    // `IEEE80211_AMPDU_TX_STOP_CONT`, a frame in a ring goes
                    // out as its descriptor says and later ones go singly.
                    unsafe {
                        self.station
                            .complete_tx_block_ack_program(ticket, Completion::Accepted)
                    }
                }
                tx::Action::Operational { session, agreement } => {
                    let tid = usize::from(session.tid());
                    self.no_amsdu[tid] |= !agreement.amsdu_in_ampdu();
                    self.aggregating[tid] = Some(session);
                    continue;
                }
                tx::Action::ResumeLegacy { .. } | tx::Action::None => continue,
            }
            .map_err(Error::BlockAck)?;
            self.changes.push_front(next);
        }
        Ok(())
    }

    /// `bytes` on the management queue, sealed under PMF. False when no room.
    fn send_agreement_frame(&mut self, bytes: &[u8]) -> Result<bool, Error> {
        let context = self.context.clone().ok_or(Error::Refused("no context"))?;
        let frame = if context.pmf().is_some() {
            let mut robust = bytes.to_vec();
            robust[1] |= 0x40;
            self.seal(&robust)?
        } else {
            bytes.to_vec()
        };
        let basic = Some(context.negotiated().legacy.basic);
        let packet = self.management_packet(context.channel().band, &frame, None, basic);
        Self::hardware(self.device.transmit(Queue::Management, &packet, &frame))
    }

    /// `ieee80211_agg_start_txq` of each TID no longer changing.
    fn release_parked(&mut self) -> Result<(), Error> {
        let mut at = 0;
        while at < self.parked.len() && self.held.len() < MAX_HELD {
            let (tid, ..) = self.parked[at];
            if self.station.tx_block_ack_blocks_data(tid) {
                at += 1;
                continue;
            }
            let Some((_, ethernet, class)) = self.parked.remove(at) else {
                break;
            };
            match self.send(&ethernet, class) {
                // mac80211 drops a frame the link can no longer take.
                Err(Error::Data(_)) => self.unsupported("a data frame its link refused once held"),
                result => result?,
            }
        }
        Ok(())
    }

    /// `rtw_ops_tx` of `ethernet`.
    fn send(&mut self, ethernet: &[u8], class: TxClass) -> Result<(), Error> {
        let epoch = self
            .station
            .association_epoch()
            .ok_or(Error::Refused("no association"))?;
        let context = self.context.clone().ok_or(Error::Refused("no context"))?;
        let tid = data::data_tid(&context, None, None, ethernet);
        if let Some(tid) = tid
            && self.station.tx_block_ack_blocks_data(tid)
        {
            if self.parked.len() >= MAX_HELD {
                self.parked.pop_front();
            }
            self.parked.push_back((tid, ethernet.to_vec(), class));
            return Ok(());
        }
        let joining = tid.filter(|&tid| self.tail_has_room(&context, tid, ethernet.len(), class));
        let mut policy = Admitted(&self.channels);
        let mut keys: Vec<&mut KeySlot> = self.keys.iter_mut().map(|key| &mut key.slot).collect();
        if let Some(tid) = joining {
            let plan = self
                .station
                .prepare_qos_subframe_refs(
                    epoch,
                    ethernet,
                    class,
                    Qos {
                        context: &context,
                        tid,
                    },
                    &mut keys,
                    &mut policy,
                )
                .map_err(Error::Data)?;
            if let Some((_, packet, mpdu)) = self.held.back_mut() {
                let iv = if packet.security == 0 { 0 } else { IV_BYTES };
                amsdu::append(mpdu, plan.plaintext_mpdu(), iv);
                packet.size = mpdu.len() as u16;
            }
            return Ok(());
        }
        let plan = match tid {
            Some(tid) => self.station.prepare_qos_msdu_refs(
                epoch,
                ethernet,
                class,
                Qos {
                    context: &context,
                    tid,
                },
                &mut keys,
                &mut policy,
            ),
            None => self.station.prepare_msdu_refs(
                epoch,
                ethernet,
                class,
                SequenceOwner::Host,
                &mut keys,
                &mut policy,
            ),
        }
        .map_err(Error::Data)?;
        let (_, _, mpdu, protection, _, _) = plan.into_parts();
        let security = match protection {
            Protection::None => 0,
            Protection::HostIv { .. } => SECURITY_CCMP,
            Protection::Firmware { .. } => return Err(Error::Refused("a firmware key")),
        };
        let queue = tid.map_or(Queue::BestEffort, tid_queue);
        let info = rate_info(&context, self.width(&context), false, 0);
        let aggregate = tid
            .and_then(|tid| self.aggregating[usize::from(tid)].as_ref())
            .and(context.negotiated().ht.as_ref())
            .map(|ht| {
                Aggregate::from_ht(ht.peer_ampdu_base_exponent | (ht.peer_mpdu_spacing << 2))
            });
        let packet = Packet {
            size: mpdu.len() as u16,
            multicast: mpdu[4] & 1 != 0,
            mac_id: MAC_ID,
            queue: tid.unwrap_or(0),
            rate_id: info.rate_id,
            security,
            rate: highest_rate(&context),
            width: info.width,
            ldpc: info.ldpc,
            stbc: u8::from(peer_stbc(&context)),
            aggregate,
            // `rtw_tx_pkt_info_update`: mac80211 numbers a data frame.
            sequence: u16::from_le_bytes([mpdu[22], mpdu[23]]) >> 4,
            ..Packet::default()
        };
        if self.held.len() >= MAX_HELD {
            self.held.pop_front();
        }
        self.held.push_back((queue, packet, mpdu));
        self.tail_joins = tid.is_some() && class == TxClass::Data;
        if let Some(tid) = tid
            && class == TxClass::Data
            && queue != Queue::Voice
        {
            self.start_aggregation(tid);
        }
        Ok(())
    }

    /// `ieee80211_amsdu_aggregate`: whether `size` more bytes of data on `tid`
    /// may join the frame waiting last, while one waits. `SUPPORTS_AMSDU_IN_AMPDU`
    /// holds, and `rtw_ops_can_aggregate_in_amsdu` keeps 2.4 GHz out of it.
    /// `max_amsdu_subframes` cannot bind here: its least is 8, and no frame
    /// this long holds so many.
    fn tail_has_room(
        &self,
        context: &AssociationContext,
        tid: u8,
        size: usize,
        class: TxClass,
    ) -> bool {
        let peer = usize::from(context.negotiated().max_tx_amsdu);
        let limit = match self.rate_amsdu {
            0 => peer,
            rate => peer.min(rate.into()),
        };
        class == TxClass::Data
            && self.tail_joins
            && context.channel().band != Band::Ghz2
            && !self.no_amsdu[usize::from(tid)]
            && self.held.back().is_some_and(|(_, packet, mpdu)| {
                packet.queue == tid
                    && mpdu.len() + size + amsdu::SUBFRAME_OVERHEAD
                        <= limit.min(transmit::MAX_FRAME)
            })
    }

    /// `rtw_fw_ra_report_iter`'s `max_rc_amsdu_len`, on the width set up for
    /// the peer when firmware does not name one.
    fn rate_reported(&mut self, rate: u8, short_gi: bool, width: Option<u8>) {
        let width = width.unwrap_or_else(|| {
            self.context
                .as_deref()
                .map_or(0, |context| width_code(self.width(context)))
        });
        self.rate_amsdu = bit_rate::max_amsdu(bit_rate::bit_rate(rate, short_gi, width));
    }

    /// Frames and reports refused since attach, which mac80211 drops.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Everything the device received in one look. As mac80211 does, a frame
    /// or report the station refuses is dropped and counted, and the rest of
    /// the look goes on; only the device failing ends it, after the frames
    /// already taken from the ring are handled.
    fn take_incoming(&mut self, now: u64) -> Result<(), Error> {
        let mut incoming = Vec::new();
        Self::hardware(self.device.receive(&mut |item| incoming.push(item)))?;
        while let Some(limitation) = self.device.limitation() {
            self.unsupported(limitation);
        }
        let mut failure = None;
        for item in incoming {
            match self.take(item, now) {
                Ok(()) => {}
                Err(error @ (Error::Hardware(_) | Error::Pending)) => {
                    failure.get_or_insert(error);
                }
                // Counted only: a note would reach the keeper as a failure.
                Err(_) => self.dropped = self.dropped.saturating_add(1),
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn take(&mut self, item: Incoming, now: u64) -> Result<(), Error> {
        match item {
            Incoming::Report(Report::Transmitted {
                number,
                acknowledged,
            }) => {
                if let Some(following) = &mut self.following {
                    following.reported(number, acknowledged, now);
                }
                if self.reporting == Some(number) {
                    self.reporting = None;
                    self.station
                        .management_status(acknowledged, now)
                        .map_err(Error::Station)?;
                }
                Ok(())
            }
            Incoming::Report(Report::Rate {
                mac_id: MAC_ID,
                rate,
                short_gi,
                width,
            }) => {
                self.rate_reported(rate, short_gi, width);
                Ok(())
            }
            Incoming::Report(_) => Ok(()),
            // Nothing is heard before the radio first tunes.
            Incoming::Frame(_) if self.tuned.is_none() => Ok(()),
            Incoming::Frame(frame) => match self.mpdu(frame) {
                Some(mpdu) => self.frame(mpdu, now),
                // `ieee80211_rx_monitor`/`__ieee80211_rx_handle_packet`: a
                // frame too short or of an unknown version is dropped.
                None => Err(Error::Refused("a malformed frame")),
            },
        }
    }

    /// The frame `received` holds, on the channel the radio stands on.
    fn mpdu(&mut self, received: Received) -> Option<Mpdu> {
        let channel = self.tuned?;
        let radio = RadioStatus {
            band: channel.band,
            channel: channel.number,
            frequency_mhz: channel.frequency_mhz,
            signal_dbm: received.signal_dbm,
            chain_signal_dbm: [None; 4],
            rate: RawRate {
                layout: 0,
                words: [0; 4],
            },
            rx_rate: None,
            tsf: Some(Timestamp::Low32(received.tsf)),
        };
        let security = SecurityStatus {
            decrypted: received.decrypted,
            integrity: if received.decrypted {
                Integrity::Verified
            } else {
                Integrity::Unknown
            },
            icv_error: received.icv_error,
            ..SecurityStatus::default()
        };
        Mpdu::new(received.bytes, radio, security).ok()
    }

    fn frame(&mut self, mut frame: Mpdu, now: u64) -> Result<(), Error> {
        let header = *frame.header();
        if let (Some(following), Some(context)) = (&mut self.following, &self.context)
            && header.transmitter == Some(context.bssid())
            && !header.receiver.is_multicast()
        {
            following.heard(now);
        }
        // A beacon or probe response heard during a scan.
        if let Some(hop) = &self.hop
            && matches!(header.control & 0xfc, 0x80 | 0x50)
        {
            let ticket = hop.ticket;
            let mut policy = Admitted(&self.channels);
            if let Ok(bss) = self.scanner.observe(ticket, &frame, &mut policy) {
                self.hear(bss, now);
            }
            return Ok(());
        }
        if header.control & 12 == 0 {
            return self.management_frame(frame, now);
        }
        if header.control & 12 != 8 || !header.data_present() {
            return Ok(());
        }
        if header.protected() {
            let multicast = header.receiver.is_multicast();
            let index = frame.bytes().get(header.length + 3).map(|byte| byte >> 6);
            let held = self
                .keys
                .iter()
                .position(|key| key.pairwise != multicast && Some(key.index) == index);
            let Some(held) = held else {
                return Ok(());
            };
            let Some(key) = self.keys[held].slot.installed() else {
                return Ok(());
            };
            if frame.security.icv_error {
                return Ok(());
            }
            if self.keys[held].material.len() == Cipher::Tkip.key_length()
                && frame.security.decrypted
            {
                if header.fragmented() {
                    self.unsupported("a fragmented TKIP frame");
                    return Ok(());
                }
                match check_michael(&mut frame, &self.keys[held]) {
                    Michael::Intact => {}
                    Michael::Dropped => return Ok(()),
                    Michael::Failed => {
                        let pairwise = !multicast;
                        self.events
                            .push_back(keeper::Event::MichaelFailure { pairwise });
                        return Ok(());
                    }
                }
            }
            frame.security.key = Some(key);
        }
        if header.fragmented() {
            self.reassemble(&frame, now);
            return Ok(());
        }
        self.order(frame, now);
        Ok(())
    }

    /// `ieee80211_sta_manage_reorder_buf` for a frame under an agreement.
    /// `frame`, one fragment; the station has the MSDU with the last of them.
    fn reassemble(&mut self, frame: &Mpdu, now: u64) {
        let key = frame.security.key;
        let slot = self
            .keys
            .iter_mut()
            .map(|key| &mut key.slot)
            .find(|slot| key.is_some() && slot.installed() == key);
        if let Some(whole) = self.fragments.add(frame, slot, now) {
            self.deliver(whole);
        }
    }

    fn order(&mut self, frame: Mpdu, now: u64) {
        let header = frame.header();
        let agreement = header
            .tid
            .filter(|_| !header.receiver.is_multicast())
            .and_then(|tid| self.agreements.get_mut(usize::from(tid)))
            .and_then(Option::as_mut);
        let (Some(agreement), Some(sequence)) = (agreement, header.sequence) else {
            self.deliver(frame);
            return;
        };
        let mut ready = Vec::new();
        if let Err(rejected) =
            agreement.push(sequence, now as u32, frame, |frame| ready.push(frame))
        {
            ready.push(rejected.frame);
        }
        for frame in ready {
            self.deliver(frame);
        }
    }

    /// `frame`, its turn come, to the station. mac80211 drops what its replay
    /// and port checks refuse.
    fn deliver(&mut self, frame: Mpdu) {
        let ingress = if frame.header().amsdu {
            let Some(context) = self.context.clone() else {
                return;
            };
            let key = frame.security.key;
            // SAFETY: an A-MSDU is one record here, in the order the reorder
            // buffer released it, and `clear` drops what is held for an older
            // association.
            let group =
                unsafe { OrderedGroup::new(context, alloc::vec![frame], Shape::WholeMpdu, ()) };
            let slot = self
                .keys
                .iter_mut()
                .map(|key| &mut key.slot)
                .find(|slot| key.is_some() && slot.installed() == key);
            let Ok(received) = self.station.receive_ordered_group(&group, slot) else {
                return;
            };
            let keys: Vec<&KeySlot> = self.keys.iter().map(|key| &key.slot).collect();
            match self.station.receive_group_refs(&received, &keys) {
                Ok(ingress) => ingress,
                Err(_) => return,
            }
        } else {
            let Some(epoch) = self.station.association_epoch() else {
                return;
            };
            let mut keys: Vec<&mut KeySlot> =
                self.keys.iter_mut().map(|key| &mut key.slot).collect();
            match self.station.receive_msdu_refs(epoch, &frame, &mut keys) {
                Ok(ingress) => alloc::vec![ingress],
                Err(_) => return,
            }
        };
        for ingress in ingress {
            match ingress {
                Ingress::Data(ethernet) => self.received.push_back(ethernet),
                Ingress::ControlPort { ethernet, .. } => {
                    self.events.push_back(keeper::Event::Eapol(ethernet));
                }
            }
        }
    }

    fn hear(&mut self, mut bss: Bss, now: u64) {
        let known = self
            .observed
            .iter_mut()
            .find(|heard| heard.observation.bss().bssid == bss.bssid);
        match known {
            Some(heard) => {
                bss.keep_name_of(heard.observation.bss());
                heard.observation = Arc::new(NativeBssObservation { bss });
                heard.at = now;
            }
            None => self.observed.push(Heard {
                observation: Arc::new(NativeBssObservation { bss }),
                at: now,
            }),
        }
    }

    fn management_frame(&mut self, frame: Mpdu, now: u64) -> Result<(), Error> {
        let header = *frame.header();
        // What is heard outside a scan matters only of the associated AP.
        match header.control & 0xfc {
            0x80 => return self.beacon_heard(&frame, now),
            0x50 => return Ok(()),
            _ => {}
        }
        let mut policy = Admitted(&self.channels);
        if header.protected() {
            return self.protected_management(frame, now);
        }
        if self.station.phase() == Peering::ExternalAuthenticating {
            let session = self
                .station
                .external_authentication()
                .ok_or(Error::Refused("exchange"))?
                .clone();
            if let Some(received) = self
                .station
                .receive_external_authentication(&session, frame, now)
                .map_err(Error::Station)?
            {
                self.events
                    .push_back(keeper::Event::Sae(Box::new(received)));
            }
            return Ok(());
        }
        let Some(epoch) = self.station.association_epoch() else {
            return Ok(());
        };
        // `ieee80211_drop_unencrypted_mgmt`: only Public's is not robust.
        if header.control & 0xfc == 0xd0
            && let Some(body) = frame.bytes().get(header.length..)
            && (body.first() == Some(&4)
                || matches!(body.first(), Some(0 | 9))
                    && !self.station.requires_protected_management())
        {
            self.switch_action(body, now);
            return Ok(());
        }
        if header.control & 0xfc == 0xd0
            && frame.bytes().get(header.length) == Some(&BLOCK_ACK_CATEGORY)
        {
            if let Ok(action) = self.station.receive_block_ack(epoch, &frame, now) {
                self.block_ack(action);
            }
            return Ok(());
        }
        // A robust frame to everyone carries its IGTK's MIC: rtw88 leaves
        // BIP to mac80211.
        if header.receiver.is_multicast() && protection::robust(&frame) {
            let Some(integrity) = &mut self.integrity else {
                return Ok(());
            };
            let Ok(authenticated) = integrity.authenticate(&frame) else {
                return Ok(());
            };
            if matches!(header.control & 0xfc, 0xa0 | 0xc0) {
                let body = authenticated.body();
                let action = self
                    .station
                    .receive_protected_departure(epoch, &frame, body)
                    .map_err(Error::Station)?;
                self.events.push_back(keeper::Event::ConnectionLost);
                self.act(action);
            }
            return Ok(());
        }
        // A PMF association takes a departure only under its keys.
        if self.station.requires_protected_management()
            && matches!(header.control & 0xfc, 0xa0 | 0xc0)
            && !self.keys.is_empty()
        {
            return Ok(());
        }
        let action = self
            .station
            .receive(epoch, &frame, now, &mut policy)
            .map_err(Error::Station)?;
        self.act(action);
        Ok(())
    }

    fn protected_management(&mut self, mut frame: Mpdu, now: u64) -> Result<(), Error> {
        let local = self.address;
        let Some(epoch) = self.station.association_epoch() else {
            return Ok(());
        };
        let header = *frame.header();
        let Some(key) = self.keys.iter_mut().find(|key| key.pairwise) else {
            return Ok(());
        };
        // mac80211 decrypts in software what hardware did not.
        if !frame.security.decrypted {
            let number = frame
                .bytes()
                .get(header.length..)
                .and_then(|iv| PacketNumber::from_header(iv).ok());
            let material: Option<&[u8; 16]> = key.material[..].try_into().ok();
            let (Some((number, _)), Some(material)) = (number, material) else {
                return Ok(());
            };
            let Some(opened) = ccmp::open(material, frame.bytes(), number) else {
                return Ok(());
            };
            let security = SecurityStatus {
                decrypted: true,
                integrity: Integrity::Verified,
                ..SecurityStatus::default()
            };
            let Ok(clear) = Mpdu::new(opened, frame.radio.clone(), security) else {
                return Ok(());
            };
            frame = clear;
        }
        frame.security.key = key.slot.installed();
        // Under packet numbers `ieee80211_crypto_ccmp_decrypt` keeps apart
        // from data's.
        let Ok(authenticated) = key.slot.authorize_unicast_management(&frame, local) else {
            return Ok(());
        };
        let body = authenticated.body();
        match header.control & 0xfc {
            0xa0 | 0xc0 => {
                let action = self
                    .station
                    .receive_protected_departure(epoch, &frame, body)
                    .map_err(Error::Station)?;
                self.events.push_back(keeper::Event::ConnectionLost);
                self.act(action);
            }
            0xd0 if body.first() == Some(&BLOCK_ACK_CATEGORY) => {
                let Some(context) = self.context.clone() else {
                    return Ok(());
                };
                if let Ok(action) = self
                    .station
                    .receive_authenticated_block_ack(&context, &frame, body, now)
                {
                    self.block_ack(action);
                }
            }
            0xd0 if matches!(body.first(), Some(0 | 9)) => self.switch_action(body, now),
            0xd0 if body.len() >= 4 && body[..2] == [8, 0] => {
                let response = [8, 1, body[2], body[3]];
                let Some(ap) = header.transmitter else {
                    return Ok(());
                };
                self.outbox
                    .push_back((None, management(self.address, ap, 0xd0, true, &response)));
            }
            _ => {}
        }
        Ok(())
    }

    fn block_ack(&mut self, action: ba::Action) {
        match action {
            ba::Action::Program {
                ticket,
                session,
                enable,
            } => {
                let tid = usize::from(session.tid());
                let completion = if enable {
                    match Reorder::new(
                        session.tid(),
                        session.start_sequence(),
                        session.window().min(RECEIVE_WINDOW),
                        REORDER_TICKS_PER_SECOND,
                    ) {
                        Ok(reorder) => {
                            self.agreements[tid] = Some(reorder);
                            Completion::Accepted
                        }
                        Err(_) => {
                            self.unsupported("a Block Ack window the host cannot hold");
                            Completion::RejectedAndIdle
                        }
                    }
                } else {
                    self.close_agreement(tid);
                    Completion::Accepted
                };
                // SAFETY: the host alone holds an agreement's state, which now
                // matches this ticket.
                let completed = unsafe { self.station.complete_rx_block_ack(ticket, completion) };
                if let Ok(action) = completed {
                    self.block_ack(action);
                }
            }
            ba::Action::Transmit {
                context, mut bytes, ..
            } => {
                // Block Ack action frames are robust.
                if context.pmf().is_some() {
                    bytes[1] |= 0x40;
                }
                self.outbox.push_back((None, bytes));
            }
            ba::Action::Bar {
                session,
                start_sequence,
            } => {
                let tid = usize::from(session.tid());
                let mut ready = Vec::new();
                if let Some(agreement) = &mut self.agreements[tid] {
                    let _ = agreement.bar(start_sequence, |frame| ready.push(frame));
                }
                for frame in ready {
                    self.deliver(frame);
                }
            }
            ba::Action::Tx(action) => self.changes.push_back(action),
            ba::Action::None => {}
        }
    }

    /// `ieee80211_free_tid_rx`: what the agreement still held goes with it.
    fn close_agreement(&mut self, tid: usize) {
        if let Some(mut agreement) = self.agreements[tid].take() {
            agreement.stop();
        }
    }

    /// `sta_rx_agg_reorder_timer_cb`, releasing what waited too long.
    fn release_expired(&mut self, now: u64) {
        let mut ready = Vec::new();
        for agreement in self.agreements.iter_mut().flatten() {
            let _ = agreement.poll(now as u32, |frame| ready.push(frame));
        }
        for frame in ready {
            self.deliver(frame);
        }
    }

    fn operate(&mut self) -> Result<(), Error> {
        let now = self.clock.now_us();
        self.take_incoming(now)?;
        Self::hardware(self.device.coexist(now))?;
        self.announce_streams()?;
        self.watchdog(now)?;
        self.walk(now)?;
        self.release_expired(now);
        let mut policy = Admitted(&self.channels);
        if !self.left
            && let Some(action) = self
                .station
                .poll(now, &mut policy)
                .map_err(Error::Station)?
        {
            self.act(action);
        }
        if !self.left && self.station.phase() == Peering::ExternalAuthenticating {
            let mut policy = Admitted(&self.channels);
            if let Some(bytes) = self
                .station
                .external_retransmission(now, &mut policy)
                .map_err(Error::Station)?
            {
                self.outbox.push_back((None, bytes));
            }
        }
        while !self.left
            && self
                .station
                .next_tx_block_ack_deadline()
                .is_some_and(|deadline| deadline <= now)
        {
            match self.station.poll_tx_block_ack(now) {
                Ok(tx::Action::None) => break,
                Ok(action) => self.changes.push_back(action),
                Err(error) => return Err(Error::BlockAck(error)),
            }
        }
        self.follow(now)?;
        self.send_management()?;
        self.send_data()?;
        self.change_agreements()?;
        self.release_parked()?;
        self.send_data()
    }
}

/// The channels mac80211 registers, as `country` leaves them.
fn channels(country: &Country) -> Vec<(Channel, u32)> {
    let mut out = Vec::new();
    let mut band = |band: Band, numbers: &[u16], frequency: fn(u16) -> u16| {
        let centers: Vec<u16> = numbers.iter().map(|&number| frequency(number)).collect();
        for (&number, regulated) in numbers
            .iter()
            .zip(country.band(&centers).unwrap_or_default())
        {
            if regulated.flags & DISABLED == 0 {
                out.push((
                    Channel {
                        band,
                        number,
                        frequency_mhz: frequency(number),
                    },
                    regulated.flags,
                ));
            }
        }
    };
    band(
        Band::Ghz2,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
        |number| {
            if number == 14 {
                2484
            } else {
                2407 + 5 * number
            }
        },
    );
    band(Band::Ghz5, &CHANNELS_5GHZ, |number| 5000 + 5 * number);
    out
}

/// `rtw_channeltable_5g`.
const CHANNELS_5GHZ: [u16; 25] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
];
const SUPPORTED_2GHZ: [u8; 2] = [1, 14];
const SUPPORTED_5GHZ: [u8; 4] = [36, 28, 149, 9];

/// `rtw_tx_ac_to_hwq` of a TID's access category.
fn tid_queue(tid: u8) -> Queue {
    match tid {
        1 | 2 => Queue::Background,
        4 | 5 => Queue::Video,
        6 | 7 => Queue::Voice,
        _ => Queue::BestEffort,
    }
}

impl<D: Device> Link for Rtl8822c<D> {
    fn mac(&self) -> Mac {
        self.address
    }
    fn carrier(&mut self) -> bool {
        self.port_open
    }
    /// A station signals once its port is open. Until then the handshake
    /// polls, as Intel's does.
    fn signals(&self) -> bool {
        self.port_open && self.device.signals()
    }
    fn due_us(&self) -> Option<u64> {
        self.signals()
            .then(|| self.clock.now_us().saturating_add(TIMER_TICK_US))
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        if !self.port_open {
            return Err(LinkError::NoCarrier);
        }
        self.send(frame, TxClass::Data)
            .map_err(|error| LinkError::Adapter(format!("{error}")))
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        Ok(self.received.pop_front())
    }
}

impl<D: Device> Radio for Rtl8822c<D> {
    type Handle = usize;
    type Profile = ();
    type Management = Arc<ManagementKey>;
    type Error = Error;

    const NAME: &'static str = "rtw88";
    /// rtw88 leaves `max_listen_interval` at mac80211's default.
    const LISTEN_INTERVAL: u16 = 5;

    fn deferred(error: &Error) -> bool {
        matches!(error, Error::Pending)
    }

    fn service(&mut self) -> Result<(), Error> {
        self.operate()
    }

    fn take_event(&mut self) -> Option<keeper::Event> {
        self.events.pop_front()
    }

    fn stage(&self) -> Stage {
        if self.left {
            Stage::NeedsDrain
        } else if self.scanned.is_some() {
            Stage::Scanned
        } else if self.admitted.is_some() {
            Stage::Admitted
        } else if self.hop.is_none() && self.station.phase() == Peering::Idle {
            Stage::Idle
        } else {
            Stage::Busy
        }
    }

    fn station(&self) -> &Station {
        &self.station
    }

    fn channels(&self, band: Band) -> Vec<(Channel, u32)> {
        self.channels
            .iter()
            .filter(|(channel, _)| channel.band == band)
            .copied()
            .collect()
    }

    fn probes(&self, channel: Channel) -> bool {
        self.channels
            .iter()
            .any(|&(known, flags)| known == channel && flags & NO_IR == 0)
    }

    fn supported_channels(&self, band: Band) -> &'static [u8] {
        match band {
            Band::Ghz2 => &SUPPORTED_2GHZ,
            Band::Ghz5 => &SUPPORTED_5GHZ,
            Band::Ghz6 => &[],
        }
    }

    fn regulated_power_dbm(&self, frequency_mhz: u16) -> i32 {
        self.country.channel(frequency_mhz).max_reg_dbm
    }

    fn advertisement(&self, band: Band) -> Result<Advertisement, Error> {
        let mut elements = rate_elements(band).to_vec();
        elements.extend_from_slice(&capability_elements(band));
        elements.extend_from_slice(&WMM_ELEMENT);
        let capabilities = Capabilities::parse(band, Role::Station, &elements)
            .map_err(|_| Error::Refused("advertisement"))?;
        Ok(Advertisement {
            capabilities,
            elements,
            he_source_maps: [McsMaps {
                rx: 0xffff,
                tx: 0xffff,
            }; 3],
            multi_link: Some(false),
        })
    }

    fn profile(&self, _: Peer) -> Result<(), Error> {
        Ok(())
    }

    fn begin_scan(&mut self, request: scan::Request, budget_us: u64) -> Result<(), Error> {
        let now = self.clock.now_us();
        self.power_save(false)?;
        self.observed
            .retain(|heard| now.saturating_sub(heard.at) < BSS_EXPIRY_US);
        let channels = request.channels().to_vec();
        let mut policy = Admitted(&self.channels);
        let ticket = self
            .scanner
            .begin(request, now, budget_us, &mut policy)
            .map_err(Error::Scan)?;
        self.scanner
            .validate_submission(ticket, now, &mut policy)
            .map_err(Error::Scan)?;
        self.scanner.submitted(ticket).map_err(Error::Scan)?;
        Self::hardware(self.device.filter_beacons(false))?;
        Self::hardware(self.device.scanning(true))?;
        self.hop = Some(Hop {
            ticket,
            channels,
            next: 0,
            leaves_at: now,
        });
        Ok(())
    }

    unsafe fn retire_scan(&mut self) -> Result<(), Error> {
        let ticket = self.scanned.take().ok_or(Error::Refused("scan"))?;
        self.scanner
            .retire(ticket, Retirement::Confirmed)
            .map_err(Error::Scan)?;
        Ok(())
    }

    fn six_ghz_scan(
        &self,
        _: &scan::Request,
        _: scan::six_ghz::Options,
    ) -> Result<Option<scan::Request>, Error> {
        Ok(None)
    }

    fn bss(&self) -> Vec<(usize, &Bss)> {
        self.observed
            .iter()
            .enumerate()
            .map(|(handle, heard)| (handle, heard.observation.bss()))
            .collect()
    }

    fn observation(&self, handle: usize) -> Result<Arc<NativeBssObservation>, Error> {
        self.observed(handle)
    }

    fn join(&mut self, handle: usize, join: Join, _: ()) -> Result<(), Error> {
        let observed = self.observed(handle)?;
        let bss = observed.bss().clone();
        self.approach(&bss)?;
        let now = self.clock.now_us();
        self.management_cipher = join.request.pmf().map(|pmf| pmf.management());
        let mut policy = Admitted(&self.channels);
        let action = if join.request.pmf().is_some() {
            self.station
                .begin_modern_pmf(join, observed, now, &mut policy)
        } else {
            self.station
                .begin_modern(join, observed.bss().clone(), now, &mut policy)
        }
        .map_err(Error::Station)?;
        self.act(action);
        Ok(())
    }

    fn begin_external_authentication(
        &mut self,
        handle: usize,
        _: (),
        multi_link: Option<Affiliation>,
        budget_us: u64,
    ) -> Result<Arc<external::Session>, Error> {
        let observed = self.observed(handle)?;
        let bss = observed.bss().clone();
        self.approach(&bss)?;
        let now = self.clock.now_us();
        let mut policy = Admitted(&self.channels);
        self.station
            .begin_external_authentication(
                external::Peer {
                    bssid: bss.bssid,
                    channel: bss.channel,
                    ssid: bss.ssid.clone().unwrap_or_default(),
                    multi_link,
                },
                now,
                budget_us,
                &mut policy,
            )
            .map_err(Error::Station)
    }

    fn begin_six_ghz_external_authentication(
        &mut self,
        _: usize,
        _: Selection,
        _: (),
        _: Option<Affiliation>,
        _: u64,
    ) -> Result<Arc<external::Session>, Error> {
        Err(Error::Unsupported("6 GHz on an RTL8822C"))
    }

    fn transmit_external_authentication(
        &mut self,
        session: &external::Session,
        frame: external::Frame<'_>,
    ) -> Result<(), Error> {
        let now = self.clock.now_us();
        let mut policy = Admitted(&self.channels);
        let bytes = self
            .station
            .external_authentication_transmit(session, frame, now, &mut policy)
            .map_err(Error::Station)?;
        self.outbox.push_back((None, bytes));
        Ok(())
    }

    fn associate_external(
        &mut self,
        session: &external::Session,
        handle: usize,
        join: Join,
    ) -> Result<(), Error> {
        let observed = self.observed(handle)?;
        let now = self.clock.now_us();
        self.management_cipher = join.request.pmf().map(|pmf| pmf.management());
        let mut policy = Admitted(&self.channels);
        let action = self
            .station
            .associate_external_pmf(session, join, observed, now, &mut policy)
            .map_err(Error::Station)?;
        self.act(action);
        Ok(())
    }

    /// `rtw_sta_add`, then `rtw_ops_bss_info_changed` of the association.
    fn configure(&mut self) -> Result<(), Error> {
        let (ticket, context) = self
            .admitted
            .take()
            .ok_or(Error::Refused("configuration"))?;
        let eirp_mbm = self.eirp_mbm(context.channel().frequency_mhz);
        Self::hardware(self.device.tune(&context.definition(), false, eirp_mbm))?;
        self.tuned = Some(context.channel());
        Self::hardware(self.device.prepare_transmit())?;
        let slot = follow::short_slot(context.channel().band, context.beacon().capabilities);
        if let Some(wmm) = &context.negotiated().wmm {
            Self::hardware(self.device.set_edca(&wmm.access_categories, slot))?;
        }
        let following = follow::Following::new(&context, self.clock.now_us());
        let info = rate_info(&context, following.width(), true, 0);
        self.following = Some(following);
        Self::hardware(self.device.command(commands::ra_info(info)))?;
        Self::hardware(self.device.command(commands::media_status(MAC_ID, true)))?;
        Self::hardware(self.device.set_port(
            context.bssid(),
            context.response().aid & 0x7ff,
            true,
        ))?;
        let interval = context.beacon().beacon_interval;
        Self::hardware(self.device.set_beacon(interval, context.dtim_period()))?;
        let wmm = context.negotiated().wmm.is_some();
        let aid = context.response().aid & 0x7ff;
        let band = context.channel().band;
        let pages = templates::build(self.address, context.bssid(), aid, wmm, band);
        Self::hardware(self.device.set_templates(&pages))?;
        Self::hardware(self.device.command(commands::default_port(PORT, MAC_ID)))?;
        self.no_amsdu = [false; 8];
        self.rate_amsdu = 0;
        self.context = Some(context.clone());
        self.station
            .complete_configuration(ticket, Completion::Accepted, self.clock.now_us())
            .map_err(Error::Station)?;
        if context.negotiated().ht.is_some() {
            self.station
                .configure_rx_block_ack(RECEIVE_WINDOW, true)
                .map_err(|_| Error::Refused("Block Ack limits"))?;
            self.station
                .configure_tx_block_ack(TRANSMIT_WINDOW)
                .map_err(|_| Error::Refused("Block Ack limits"))?;
        }
        Ok(())
    }

    fn send_control(&mut self, ethernet: &[u8], key: Option<KeyIdentity>) -> Result<(), Error> {
        let class = key.map_or(TxClass::ControlPortPlaintext, TxClass::ControlPortProtected);
        self.send(ethernet, class)
    }

    /// `rtw_ops_set_key`: the CAM takes CCMP-128 alone of what a station uses.
    fn install_key(
        &mut self,
        pairwise: bool,
        index: u8,
        material: &[u8],
        receive: ReplaySeed,
    ) -> Result<KeyIdentity, Error> {
        // rtw88 takes TKIP as `RTW_CAM_TKIP` and leaves Michael to mac80211.
        let (cipher, kind) = if material.len() == Cipher::Ccmp128.key_length() {
            (Cipher::Ccmp128, CAM_AES)
        } else if !pairwise && material.len() == Cipher::Tkip.key_length() {
            (Cipher::Tkip, CAM_TKIP)
        } else {
            return Err(Error::Unsupported(
                "a key other than CCMP-128 or a TKIP group key on an RTL8822C",
            ));
        };
        let temporal = material
            .first_chunk::<16>()
            .ok_or(Error::Refused("key material"))?;
        let peer = self
            .station
            .pairwise_peer()
            .ok_or(Error::Refused("no peer"))?;
        let scope = if pairwise {
            KeyScope::Pairwise(peer)
        } else {
            KeyScope::Group(peer)
        };
        let transmit = if pairwise {
            TransmitSeed::host(PacketNumber::new(0).ok_or(Error::Refused("packet number"))?)
        } else {
            TransmitSeed::RECEIVE_ONLY
        };
        // SAFETY: the counter gives each key of the adapter its own slot.
        let mut slot = unsafe { KeySlot::new(self.next_slot) }.map_err(Error::Key)?;
        self.next_slot = self.next_slot.wrapping_add(1);
        let ticket = slot
            .begin_install(index, cipher, material, receive, scope, transmit)
            .map_err(Error::Key)?;
        let identity = ticket.identity();
        let entry = if pairwise { PAIRWISE_CAM } else { index };
        Self::hardware(self.device.write_key(&CamKey {
            entry,
            index,
            kind,
            group: !pairwise,
            peer: if pairwise { peer } else { Mac::BROADCAST },
            material: temporal,
        }))?;
        slot.complete_install(ticket, InstallOutcome::Accepted)
            .map_err(Error::Key)?;
        self.keys
            .retain(|key| !(key.pairwise == pairwise && key.index == index));
        self.keys.push(Key {
            slot,
            pairwise,
            index,
            entry,
            material: Zeroizing::new(material.to_vec()),
        });
        Ok(identity)
    }

    fn install_link_key(&mut self, _: u8, _: u8, _: &[u8], _: ReplaySeed) -> Result<(), Error> {
        Err(Error::Unsupported("MLO on an RTL8822C"))
    }

    /// The IGTK stays in the host, where mac80211 runs BIP for rtw88.
    unsafe fn install_management_key(
        &mut self,
        _: u64,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<ManagementKey>, Error> {
        let cipher = self
            .management_cipher
            .ok_or(Error::Refused("no management cipher"))?;
        let gtk = self
            .keys
            .iter()
            .rev()
            .find(|key| !key.pairwise)
            .and_then(|key| key.slot.installed())
            .ok_or(Error::Pending)?;
        self.integrity = Some(
            BipKey::new(gtk, cipher, index, material, receive)
                .map_err(|_| Error::Refused("the IGTK"))?,
        );
        Ok(Arc::new(ManagementKey))
    }

    unsafe fn rotate_management_key(
        &mut self,
        _: &Arc<ManagementKey>,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<ManagementKey>, Error> {
        // SAFETY: forwarded from the keeper.
        unsafe { self.install_management_key(0, index, material, receive) }
    }

    fn authorize_port(&mut self, epoch: u64) -> Result<(), Error> {
        let context = self.context.clone().ok_or(Error::Refused("no context"))?;
        let ptk = self
            .keys
            .iter()
            .find(|key| key.pairwise)
            .ok_or(Error::Refused("no pairwise key"))?;
        let gtk = self
            .keys
            .iter()
            .rev()
            .find(|key| !key.pairwise)
            .ok_or(Error::Refused("no group key"))?;
        let links = [(&ptk.slot, &gtk.slot)];
        if self.station.requires_protected_management() {
            self.station
                .authorize_protected_port(&context, epoch, &links)
        } else {
            self.station.authorize_port(epoch, &links)
        }
        .map_err(Error::Station)?;
        self.port_open = true;
        Ok(())
    }

    fn deauthenticate(&mut self, reason: u16) -> Result<(), Error> {
        if self.left || self.station.phase() == Peering::Idle {
            return Ok(());
        }
        if let Ok((local, ap)) = self.station.addresses() {
            let protected = self.station.protected_port_authorized();
            let bytes = management(local, ap, 0xc0, protected, &reason.to_le_bytes());
            self.outbox.push_back((None, bytes));
            self.send_management()?;
        }
        let action = self.station.disconnect().map_err(Error::Station)?;
        self.act(action);
        Ok(())
    }

    unsafe fn retire_peer(&mut self) -> Result<(), Error> {
        if let Some(ticket) = self.departing {
            self.station
                .complete_removal(ticket, Completion::Accepted)
                .map_err(Error::Station)?;
        }
        self.clear()
    }
}

mod follow;
#[cfg(test)]
mod tests;
