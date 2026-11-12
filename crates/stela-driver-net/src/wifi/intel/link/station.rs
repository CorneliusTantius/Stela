// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! The function as the connection keeper's radio, as mvm serves mac80211: a
//! join raises the PHY, link, AP station and queues, session protection holds
//! the channel for the exchange, the MLD callbacks of each station state
//! follow in order, keys and port opening go to the firmware, each TID's frames
//! get their queue as they first appear, and a departure takes everything down
//! to the scanning MAC again.
//!
//! Firmware commands run one at a time from a queue: a step that raises or
//! needs a firmware answer waits for the one before it, never for time.
use super::*;
use crate::wifi::{
    Channel,
    connection::keeper::{self, Advertisement, Peer, Radio, Stage as Standing},
    frame::{MAX_AMPDU_BUF_EHT, Mpdu},
    intel::{
        association::{
            self as commands, LinkHe, LinkState, MacState, PeerHe, PeerState, StationLink,
        },
        command,
        firmware::Family,
        identity::Rf,
        transmit::{
            LegacyRate, Parameters,
            response::{Response, block_ack_queues},
        },
    },
    regulatory::channel::{
        NO_6GHZ_AFC_CLIENT, NO_6GHZ_VLP_CLIENT, NO_80MHZ, NO_160MHZ, NO_320MHZ, NO_EHT, NO_HE,
        NO_HT40MINUS, NO_HT40PLUS, NO_IR,
    },
    regulatory::{self, Operation, PowerType, ProbeProfiles, Purpose, TxProfile, Width, database},
    security::{
        Cipher, InstallOutcome, InstallTicket, Integrity, KeyIdentity, KeyScope, KeySlot,
        PacketNumber, ReplaySeed, TransmitSeed,
        aggregate::{OrderedGroup, Shape},
        management::ManagementCipher,
    },
    station::{
        self, Action, AssociationContext, Completion, Join, NativeBssObservation, Phase as Peering,
        RegulatoryPolicy, Station, Ticket,
        ba::{self, RxSession},
        data::{self, Ingress, Protection, Qos, SequenceOwner, TxClass, amsdu},
        external,
        fragments::Fragments,
        multi_link::Affiliation,
        operations::ChannelDefinition,
        operations::Operations,
        phy::{self, Capabilities, Role},
        power_envelope::PowerEnvelope,
        wire::six_ghz::Selection,
    },
};
use alloc::{borrow::Cow, collections::VecDeque};
use zeroize::Zeroizing;

mod active_link;
mod beacon;
mod coexistence;
mod country;
mod emlsr;
mod fifos;
mod grade;
mod he;
mod link_changes;
mod link_scan;
mod reception;
mod statistics;

/// How long a signalling station sleeps at most: the coarse timers it keeps
/// between frames, its Block Ack sessions' and its connection's, have no
/// firmware signal of their own.
const TIMER_TICK_US: u64 = 100_000;
use super::super::identity::EhtLimits;
use reception::{MAX_SESSIONS, Parent, Reception};
mod eht;

type Queue<Q, B> = Ax200ManagementQueue<'static, Q, B, Regulatory>;

/// The most frames a TID holds while its queue is added or full, as the
/// mac80211 queue limit bounds what stands in front of a stopped driver.
const MAX_HELD: usize = 64;
/// The TID the management queue answers to, which non-QoS data shares.
const MANAGEMENT_TID: u8 = 15;
/// `he_if_types_ext_capa_sta` and iwlmld's `ext_capa_base`: extended channel
/// switching, Multiple BSSID, operating mode notifications and the largest
/// count of MSDUs in an A-MSDU.
const EXTENDED_CAPABILITIES: [u8; 9] = [4, 0, 0x40, 0, 0, 0, 0, 0xc0, 1];
/// `IWL_MVM_MISSED_BEACONS_THRESHOLD_LONG`.
const MISSED_BEACONS: u32 = 19;
/// `IWL_MVM_MISSED_BEACONS_SINCE_RX_THOLD`.
const MISSED_BEACONS_SINCE_RECEIVE: u32 = 4;
/// `IWL_MLD_MISSED_BEACONS_SINCE_RX_THOLD`, on the radios iwlmld drives.
const MISSED_BEACONS_SINCE_RECEIVE_WIFI_7: u32 = 6;
/// `IWL_MLD_MISSED_BEACONS_THRESHOLD`.
const LINK_SCAN_MISSED_BEACONS: u32 = 8;
/// `MCC_SOURCE_WIFI`.
/// How long a departure's frame may take to reach the air before the queues
/// flush it, as `ieee80211_flush_queues` waits for it.
const DEPARTURE_DRAIN_US: u64 = 200_000;
const SESSION_PROTECTION_NOTIFICATION: (u8, u8) = (0xfb, 3);
const SCAN_START_NOTIFICATION: (u8, u8) = (0xb2, 0);
const MISSED_BEACONS_LEGACY_NOTIFICATION: (u8, u8) = (0xa2, 0);
const MISSED_BEACONS_NOTIFICATION: (u8, u8) = (0xf6, 3);
const TRANSMIT_RESPONSE: (u8, u8) = (0x1c, 0);
const BAR_FRAME_RELEASE: (u8, u8) = (0xc2, 0);
const FRAME_RELEASE: (u8, u8) = (0xc3, 0);
const BLOCK_ACK_NOTIFICATION: (u8, u8) = (0xc5, 0);
const RATE_NOTIFICATION: (u8, u8) = (0xf7, 5);
/// `IWL_TLC_NOTIF_FLAG_AMSDU`.
const RATE_NOTIFICATION_AMSDU: u32 = 2;
/// `iwl_mvm_tlc_update_notif`: below this an A-MSDU is not worth building.
const SMALLEST_AMSDU: u32 = 2000;
/// `IWL_UCODE_TLV_CAPA_CSUM_SUPPORT`, without which mvm offers no A-MSDU.
const CHECKSUM_OFFLOAD: u32 = 21;
/// `IEEE80211_HE_MAC_CAP2_ACK_EN`.
const ACK_ENABLED: u8 = 0x80;
/// `IEEE80211_HE_MAC_CAP5_OM_CTRL_UL_MU_DATA_DIS_RX`.
const UPLINK_DATA_DISABLED: u8 = 0x10;
/// `WLAN_ACTION_BLOCK_ACK`, on an action frame.
const BLOCK_ACK_CATEGORY: u8 = 3;
/// `WLAN_REASON_QSTA_TIMEOUT`.
const SESSION_TIMED_OUT: u16 = 39;
/// `IWL_UCODE_TLV_CAPA_BAID_ML_SUPPORT`, which every firmware of the
/// families here has: their command tables have no `ADD_STA`.
const BLOCK_ACK_ALLOCATION: u32 = 63;
/// `IWL_UCODE_TLV_CAPA_STA_EXP_MFP_SUPPORT`.
const EXPLICIT_MFP: u32 = 114;
/// `IWL_UCODE_TLV_CAPA_PROTECTED_TWT`.
const PROTECTED_TWT: u32 = 56;
/// `MICHAEL_MIC_LEN`.
const MICHAEL_MIC_BYTES: usize = 8;
/// `IWL_UCODE_TLV_CAPA_COEX_HIGH_PRIO`.
const COEX_HIGH_PRIORITY: u32 = 61;
/// `IWL_UCODE_TLV_API_SMART_FIFO_OFFLOAD`.
const SMART_FIFO_OFFLOAD: u32 = 68;
const BEACON_FILTER_V4_API: u32 = 47;

/// What a raised chain does on arrival.
pub(super) enum Plan {
    /// Authenticate and associate.
    Join {
        join: Join,
        observed: Arc<NativeBssObservation>,
    },
    /// An external exchange is running; its frames wait in the outbox.
    Exchange,
}

/// What a firmware step's answer completes.
enum Then {
    Nothing,
    /// The AP's configuration finished.
    Configured(Ticket),
    Key {
        pairwise: bool,
        index: u8,
        ap: Mac,
        ticket: Box<InstallTicket>,
    },
    /// The port's commands finished: firmware rate selection may widen.
    Authorized,
    /// Firmware answered a country update.
    Country,
    /// Firmware reported its FIFOs.
    Fifos,
}

/// A receive Block Ack agreement the firmware is to take up or give up.
struct Agreement {
    ticket: Ticket,
    session: Arc<RxSession>,
    enable: bool,
}

/// One firmware step.
enum Step {
    Command {
        id: command::Id,
        bytes: Vec<u8>,
        then: Then,
    },
    /// `tid`'s queue, from fresh memory.
    Queue {
        tid: u8,
    },
    BlockAck(Agreement),
}

/// A step the firmware has.
struct Waiting {
    ticket: boot::CommandTicket,
    deadline: Deadline,
    step: Step,
}

/// A firmware command's bound, `iwl_trans_send_cmd`'s sync timeout.
const COMMAND_TIMEOUT_US: u64 = 2_000_000;

/// The session protection around the join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Session {
    Off,
    Starting,
    On,
}

/// One installed firmware key.
struct Key {
    slot: KeySlot,
    pairwise: bool,
    index: u8,
    flags: u32,
    acknowledged: bool,
    /// The AP on the link the key belongs to.
    ap: Mac,
    /// Whether firmware holds the key, which a dormant link's does not.
    fitted: bool,
    /// What a group key gives firmware as its link activates: the key and
    /// the packet number its AP's frames continue from.
    material: Option<(Zeroizing<Vec<u8>>, u64)>,
}

/// One IGTK of a link.
struct LinkIntegrity {
    ap: Mac,
    index: u8,
    flags: u32,
    material: Zeroizing<Vec<u8>>,
    receive: u64,
    fitted: bool,
}

/// A data frame waiting for its queue or its queue's room.
struct Held {
    mpdu: Vec<u8>,
    encrypted: bool,
    control_port: bool,
}

/// The transport of an installed IGTK.
pub struct ManagementKey {
    index: u8,
}

/// The association's state beside the kept chain.
/// `IEEE80211_SCAN_RESULT_EXPIRE`.
const BSS_EXPIRY_US: u64 = 30_000_000;
/// `max_rx_aggregation_subframes`, half of what EHT names until Linux takes
/// the full window. A session's mode bounds it further.
const RECEIVE_WINDOW: u16 = MAX_AMPDU_BUF_EHT / 2;

/// A BSS and when it was last heard, a `cfg80211_internal_bss`.
pub(super) struct Heard {
    pub(super) observation: Arc<NativeBssObservation>,
    pub(super) at: u64,
}

pub(super) struct Client {
    station: Station,
    pub(super) plan: Option<Plan>,
    pub(super) observed: Vec<Heard>,
    pub(super) channels: Vec<(Channel, u32)>,
    pub(super) regulatory: Option<database::Country>,
    steps: VecDeque<Step>,
    waiting: Option<Waiting>,
    /// Each link's IGTKs.
    management_keys: Vec<LinkIntegrity>,
    /// The deauthentication a departure sends before anything goes down.
    farewell: Option<Vec<u8>>,
    /// Until when the departure waits for its deauthentication.
    draining: Option<Deadline>,
    /// Management frames waiting for session protection, with the exchange's
    /// ticket each answers to.
    outbox: VecDeque<(Option<Ticket>, Vec<u8>)>,
    events: VecDeque<keeper::Event>,
    received: VecDeque<Vec<u8>>,
    reception: Reception,
    fragments: Fragments,
    /// The longest A-MSDU firmware rate selection allows and its TIDs.
    amsdu: (u32, u32),
    /// What firmware's FIFOs are, once asked.
    fifos: Option<fifos::Fifos>,
    held: [VecDeque<Held>; 16],
    /// TIDs with an added or requested queue.
    requested: u16,
    session: Session,
    /// A management exchange's frame awaits its TX response.
    exchange: bool,
    admitted: Option<(Ticket, Arc<AssociationContext>)>,
    /// The active link's configuration.
    context: Option<Arc<AssociationContext>>,
    /// The other link an MLD association made.
    dormant: Option<Arc<AssociationContext>>,
    /// What the AP MLD is doing to its links.
    changes: link_changes::LinkChanges,
    /// Which of firmware's two sets of link IDs the active link holds.
    seat: u8,
    /// A new look at the links is due.
    reselect: bool,
    link_scan: link_scan::LinkScan,
    statistics: statistics::Statistics,
    emlsr: emlsr::Emlsr,
    tracking: beacon::Tracking,
    /// The radio can run EMLSR.
    pub(super) eml_capable: bool,
    ciphers: Option<(Cipher, Cipher)>,
    management_cipher: Option<ManagementCipher>,
    keys: Vec<Key>,
    next_slot: u16,
    port_open: bool,
    antenna: u8,
    /// The departure the chain's removal answers.
    departing: Option<Ticket>,
    /// The chain goes back down once everything queued for it finished.
    leaving: bool,
    /// The way down finished: the keeper retires the peer.
    left: bool,
    reported: Vec<&'static str>,
    /// Frames from the air dropped as mac80211 drops them, counted as its
    /// `rx_dropped` is, never reported one by one.
    dropped_frames: u64,
    /// Firmware notifications iwlwifi logs and goes past.
    ignored_notifications: u64,
    /// When the rules' last change comes to bear on the links.
    grace_ends: Option<u64>,
    bluetooth: coexistence::Bluetooth,
}

impl Client {
    pub(super) fn new(station: Station) -> Self {
        Self {
            station,
            plan: None,
            observed: Vec::new(),
            channels: Vec::new(),
            regulatory: None,
            steps: VecDeque::new(),
            waiting: None,
            management_keys: Vec::new(),
            farewell: None,
            draining: None,
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            dropped_frames: 0,
            ignored_notifications: 0,
            received: VecDeque::new(),
            reception: Reception::new(),
            fragments: Fragments::default(),
            amsdu: (0, 0),
            fifos: None,
            held: core::array::from_fn(|_| VecDeque::new()),
            requested: 1 << MANAGEMENT_TID,
            session: Session::Off,
            exchange: false,
            admitted: None,
            context: None,
            dormant: None,
            changes: link_changes::LinkChanges::default(),
            seat: 0,
            reselect: false,
            link_scan: link_scan::LinkScan::default(),
            statistics: statistics::Statistics::default(),
            emlsr: emlsr::Emlsr::default(),
            tracking: beacon::Tracking::default(),
            eml_capable: false,
            ciphers: None,
            management_cipher: None,
            keys: Vec::new(),
            next_slot: 0,
            port_open: false,
            antenna: 0,
            departing: None,
            leaving: false,
            left: false,
            reported: Vec::new(),
            grace_ends: None,
            bluetooth: coexistence::Bluetooth::default(),
        }
    }

    /// Report an unsupported operation once and carry on without it.
    pub(super) fn unsupported(&mut self, operation: &'static str) {
        if !self.reported.contains(&operation) {
            self.reported.push(operation);
            self.events.push_back(keeper::Event::Unsupported(operation));
        }
    }

    fn command(&mut self, id: command::Id, bytes: Vec<u8>) {
        self.steps.push_back(Step::Command {
            id,
            bytes,
            then: Then::Nothing,
        });
    }

    fn idle(&self) -> bool {
        self.steps.is_empty() && self.waiting.is_none()
    }

    /// Whether anything the keeper's next step must follow is outstanding.
    fn keys_settled(&self) -> bool {
        self.keys.iter().all(|key| key.acknowledged)
    }

    /// The way down finished.
    pub(super) fn left(&mut self) {
        self.left = true;
        self.leaving = false;
    }

    fn reset(&mut self) {
        self.steps.clear();
        self.outbox.clear();
        self.reception.clear();
        self.fragments.clear();
        self.amsdu = (0, 0);
        self.held.iter_mut().for_each(VecDeque::clear);
        self.requested = 1 << MANAGEMENT_TID;
        self.session = Session::Off;
        self.exchange = false;
        self.admitted = None;
        self.context = None;
        self.dormant = None;
        self.changes = link_changes::LinkChanges::default();
        self.reselect = false;
        self.link_scan = link_scan::LinkScan::default();
        self.statistics = statistics::Statistics::default();
        self.emlsr = emlsr::Emlsr::default();
        self.bluetooth.departed();
        self.tracking = beacon::Tracking::default();
        self.ciphers = None;
        self.management_cipher = None;
        self.keys.clear();
        self.management_keys.clear();
        self.farewell = None;
        self.draining = None;
        self.port_open = false;
        self.departing = None;
        self.leaving = false;
        self.left = false;
    }

    /// A departure began: the chain comes down once its queues drain.
    fn depart(&mut self, ticket: Ticket, failure: Option<station::Failure>) {
        if let Some(failure) = failure
            && self.station.external_authentication().is_some()
        {
            self.events
                .push_back(keeper::Event::SaeEnded(format!("{failure:?}")));
        }
        self.departing = Some(ticket);
        self.leaving = true;
        self.port_open = false;
        self.admitted = None;
        self.outbox.clear();
        self.steps.clear();
        self.held.iter_mut().for_each(VecDeque::clear);
    }

    fn act(&mut self, action: Action) {
        match action {
            Action::Transmit { ticket, bytes, .. } => {
                self.outbox.push_back((Some(ticket), bytes));
            }
            Action::Configure {
                ticket,
                context: Some(context),
                links,
                response,
                ..
            } => {
                if self.eml_capable {
                    self.emlsr = emlsr::Emlsr::offered(&response.elements);
                }
                let mut links = links.into_iter();
                self.dormant = links.next();
                if links.next().is_some() {
                    self.unsupported("a third MLO link: it stays dormant for good");
                }
                let valid = link_changes::link_bit(&context)
                    | self.dormant.as_deref().map_or(0, link_changes::link_bit);
                let changes = if valid == 0 {
                    Some(link_changes::LinkChanges::default())
                } else {
                    link_changes::LinkChanges::answered(&response.elements, valid)
                };
                let Some(changes) = changes else {
                    self.admitted = None;
                    if let Ok(Action::Remove { ticket, failure }) = self.station.disconnect() {
                        self.depart(ticket, failure);
                    }
                    return;
                };
                self.changes = changes;
                self.admitted = Some((ticket, context));
            }
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
}

/// The channels the adapter's rules admit: the real check is the leases at
/// each publication.
struct Admitted<'a>(&'a [(Channel, u32)]);

impl RegulatoryPolicy for Admitted<'_> {
    fn allow_management_tx(&mut self, channel: Channel) -> bool {
        self.0.iter().any(|&(allowed, _)| allowed == channel)
    }
    fn allow_data_tx(&mut self, channel: Channel) -> bool {
        self.allow_management_tx(channel)
    }
}

/// The channels an association's scan listens on: it sends nothing there.
impl scan::Policy for Admitted<'_> {
    fn allow_receive(&mut self, channel: Channel) -> bool {
        self.0.iter().any(|&(allowed, _)| allowed == channel)
    }
    fn allow_probe(&mut self, _: Channel) -> bool {
        false
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        self.0
            .iter()
            .map(|&(channel, _)| channel)
            .find(|channel| channel.band == band && channel.number == number)
    }
}

/// `iwl_mvm_get_tx_rate` for a management frame: the lowest rate the AP takes.
fn lowest_rate(rates: u16) -> LegacyRate {
    const RATES: [LegacyRate; 12] = [
        LegacyRate::Cck1,
        LegacyRate::Cck2,
        LegacyRate::Cck5_5,
        LegacyRate::Cck11,
        LegacyRate::Ofdm6,
        LegacyRate::Ofdm9,
        LegacyRate::Ofdm12,
        LegacyRate::Ofdm18,
        LegacyRate::Ofdm24,
        LegacyRate::Ofdm36,
        LegacyRate::Ofdm48,
        LegacyRate::Ofdm54,
    ];
    RATES[(rates.trailing_zeros() as usize).min(11)]
}

/// `iwl_mvm_next_antenna`: the next of `valid` after `last`.
fn next_antenna(valid: u8, last: u8) -> u8 {
    (1..=4)
        .map(|step| 1u8 << ((last.trailing_zeros() as u8 + step) % 4))
        .find(|antenna| valid & antenna != 0)
        .unwrap_or(valid)
}

/// The station's management header to the AP, with `subtype`'s body.
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

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// Frames from the air this boot dropped, as mac80211's `rx_dropped`.
    pub fn dropped_frames(&self) -> u64 {
        self.client.dropped_frames
    }

    /// Firmware notifications this boot went past, as iwlwifi does.
    pub fn ignored_notifications(&self) -> u64 {
        self.client.ignored_notifications
    }

    /// Raise the chain for `bss`.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn raise(
        &mut self,
        bss: &Bss,
        affiliation: Option<Affiliation>,
        plan: Plan,
    ) -> Result<(), Error> {
        let stage = core::mem::replace(&mut self.stage, Stage::Moving);
        let Stage::Scan(scan) = stage else {
            self.stage = stage;
            return Err(Error::Refused("join"));
        };
        self.selected = Some(Selected {
            bss: bss.clone(),
            rates: legacy_rates(&bss.elements, bss.channel.band),
            affiliation,
        });
        match (*scan).begin_phy_context(bss.channel) {
            Ok(phy) => {
                self.stage = Stage::Phy(Box::new(phy));
                self.client.plan = Some(plan);
                Ok(())
            }
            Err(scan) => {
                self.stage = Stage::Scan(scan);
                Err(Error::Refused("PHY context"))
            }
        }
    }

    /// One service round on the raised chain.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn operate(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        let now = self.clock.now_us();
        if let Some(plan) = self.client.plan.take() {
            self.limit_six_ghz_power(queue);
            self.translate_addresses(queue);
            self.read_fifos(queue);
            self.arrive(plan, now)?;
        }
        self.take_notifications(queue, now)?;
        // A pending command keeps what arrives for after its answer.
        if self.client.waiting.is_none() {
            self.take_frames(queue, now)?;
            self.take_notifications(queue, now)?;
        }
        let client = &mut self.client;
        for tid in client.reception.expired(now) {
            // `tid_rx_timer_expired`, once for an agreement still in force.
            if client.station.active_rx_block_ack(tid).is_some()
                && let Ok(action) = client
                    .station
                    .stop_rx_block_ack(tid, Some(SESSION_TIMED_OUT))
            {
                client.block_ack(action);
            }
        }
        let mut policy = Admitted(&client.channels);
        if !client.leaving
            && let Some(action) = client
                .station
                .poll(now, &mut policy)
                .map_err(Error::Station)?
        {
            client.act(action);
        }
        if !client.leaving
            && !client.exchange
            && client.station.phase() == Peering::ExternalAuthenticating
        {
            let mut policy = Admitted(&client.channels);
            if let Some(bytes) = client
                .station
                .external_retransmission(now, &mut policy)
                .map_err(Error::Station)?
            {
                client.outbox.push_back((None, bytes));
            }
        }
        self.run_steps(queue)?;
        if self.client.reselect && self.client.idle() && !self.client.leaving {
            self.client.reselect = false;
            self.select_link(queue, now)?;
            self.run_steps(queue)?;
        }
        self.run_tracking(queue, now)?;
        self.run_steps(queue)?;
        self.run_coexistence(queue)?;
        self.run_steps(queue)?;
        self.run_emlsr(queue, now)?;
        self.run_link_changes(queue, now)?;
        self.run_steps(queue)?;
        self.run_link_scan(queue, now)?;
        self.run_steps(queue)?;
        self.send_management(queue)?;
        self.send_data(queue)
    }

    /// `iwl_mvm_mld_assign_vif_chanctx`: tell firmware what a 6 GHz AP's power
    /// type and envelopes allow before the first frame to it.
    fn limit_six_ghz_power(&mut self, queue: &mut Queue<Q, B>) {
        let Some(selected) = &self.selected else {
            return;
        };
        if let Some(bytes) = self.six_ghz_power(queue, &selected.bss, 0, None) {
            self.client.command(commands::POWER_CONSTRAINTS, bytes);
        }
    }

    /// What firmware's link `seat` hears of `bss`, an AP on 6 GHz, whose
    /// `envelope` is what its elements limit unless a later word replaced it.
    pub(super) fn six_ghz_power(
        &self,
        queue: &mut Queue<Q, B>,
        bss: &Bss,
        seat: u8,
        envelope: Option<PowerEnvelope>,
    ) -> Option<Vec<u8>> {
        let widest = self.widest(bss.channel.band);
        let flags = self
            .client
            .channels
            .iter()
            .find(|(channel, _)| *channel == bss.channel)
            .map_or(0, |(_, flags)| *flags);
        queue.firmware().command_version(
            commands::POWER_CONSTRAINTS.group,
            commands::POWER_CONSTRAINTS.opcode,
        )?;
        let operations = Operations::parse(&bss.elements).ok()?;
        let six = operations.he.as_ref().and_then(|he| he.six_ghz);
        let ap_type = PowerType::of((six?[1] & 0x78) >> 3, flags)?;
        let envelope = envelope.unwrap_or_else(|| {
            let mut envelope = PowerEnvelope::parse(&bss.elements);
            let ap = operations
                .channel(bss.channel, phy::Mode::Eht, None)
                .ok()
                .filter(|_| self.eht.is_some())
                .map_or_else(|| operations.channel(bss.channel, phy::Mode::He, None), Ok);
            match ap {
                Ok(ap) => envelope.fit(&ap, &ap.narrowed_to(widest)),
                Err(_) => envelope = PowerEnvelope::none(),
            }
            envelope
        });
        Some(commands::power_constraints(seat, ap_type, &envelope))
    }

    /// `iwl_mld_set_wifi_gen`'s MLD case: firmware translates an MLD's
    /// addresses only under EHT, which an AP's own capabilities turn on only
    /// after its association response.
    fn translate_addresses(&mut self, queue: &mut Queue<Q, B>) {
        if self
            .selected
            .as_ref()
            .is_none_or(|selected| selected.affiliation.is_none())
        {
            return;
        }
        let firmware = queue.firmware();
        let mac = MacState {
            address: self.address,
            he: true,
            eht: true,
            aid: None,
            high_priority: firmware.supports_capability(COEX_HIGH_PRIORITY),
            emlsr: None,
            protected_twt: false,
        };
        let bytes = commands::mac_config(version_of(firmware, commands::MAC_CONFIG), mac);
        self.client.command(commands::MAC_CONFIG, bytes);
    }

    /// The chain is up: start what it was raised for, under session protection.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn arrive(&mut self, plan: Plan, now: u64) -> Result<(), Error> {
        let client = &mut self.client;
        if let Plan::Join { join, observed } = plan {
            let mut policy = Admitted(&client.channels);
            client.ciphers = join.request.key_ciphers();
            client.management_cipher = join.request.pmf().map(|pmf| pmf.management());
            let action = if join.request.pmf().is_some() {
                client
                    .station
                    .begin_modern_pmf(join, observed, now, &mut policy)
            } else {
                client
                    .station
                    .begin_modern(join, observed.bss().clone(), now, &mut policy)
            }
            .map_err(Error::Station)?;
            client.act(action);
        }
        Ok(())
    }

    /// `iwl_mvm_mld_mac_sta_state`'s AUTH to ASSOC, then the `vif_cfg_changed`
    /// that follows it.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn association_steps(
        &mut self,
        queue: &mut Queue<Q, B>,
        context: &AssociationContext,
        ticket: Ticket,
    ) -> Result<(), Error> {
        let negotiated = context.negotiated();
        let bss = context.beacon();
        let aid = context.response().aid;
        let he = negotiated.he.is_some();
        let definition = context.definition();
        let eht = negotiated.eht.is_some();
        let commands_of_link = self.link_commands(queue, context, self.client.seat, false)?;
        let phy = if definition.width == phy::Width::Mhz20 && !eht {
            Vec::new()
        } else {
            queue
                .phy_changed(&definition, commands_of_link.wide_ofdma.as_ref())
                .ok_or(Error::Refused("channel width"))?
        };
        let firmware = queue.firmware();
        let high_priority = firmware.supports_capability(COEX_HIGH_PRIORITY);
        let fifo_offloaded = firmware.supports_api(SMART_FIFO_OFFLOAD);
        let mac = MacState {
            address: self.address,
            he,
            eht,
            aid: None,
            high_priority,
            emlsr: None,
            protected_twt: protected_twt(firmware, context),
        };
        let mac_version = version_of(firmware, commands::MAC_CONFIG);
        let power_version = version_of(firmware, commands::MAC_POWER);
        let client = &mut self.client;
        for (id, bytes) in phy {
            client.command(id, bytes);
        }
        client.command(commands::MAC_CONFIG, commands::mac_config(mac_version, mac));
        client.command(commands::LINK_CONFIG, commands_of_link.link);
        client.command(commands::RATE_CONFIG, commands_of_link.rates);
        client.command(commands::STATION_CONFIG, commands_of_link.peer);
        client.command(
            commands::MAC_CONFIG,
            commands::mac_config(
                mac_version,
                MacState {
                    aid: Some(aid),
                    emlsr: client.emlsr.transition(),
                    ..mac
                },
            ),
        );
        if !fifo_offloaded {
            client.command(commands::SMART_FIFO, commands::smart_fifo(negotiated));
        }
        client.steps.push_back(Step::Command {
            id: commands::MAC_POWER,
            bytes: commands::power(
                power_version,
                self.save_power,
                bss.beacon_interval,
                context.dtim_period(),
            ),
            then: Then::Configured(ticket),
        });
        Ok(())
    }

    /// Issue the next step, or take the answer the waiting one has.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn run_steps(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        loop {
            if let Some(waiting) = &self.client.waiting {
                let progress = queue.poll_submitted(&waiting.ticket).map_err(Error::Queue);
                match progress {
                    Ok(boot::CommandProgress::Pending) if !waiting.deadline.passed() => {
                        return Ok(());
                    }
                    Ok(boot::CommandProgress::Pending) => {
                        return Err(Error::Timeout("firmware command"));
                    }
                    Ok(boot::CommandProgress::Completed(response)) => {
                        let waiting = self.client.waiting.take().unwrap();
                        self.finish(queue, waiting.step, response)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            let Some(step) = self.client.steps.pop_front() else {
                return Ok(());
            };
            let pages = self.pages;
            let ticket = match &step {
                // SAFETY: `new`'s contract holds, and the step stays within
                // the channel, power and rates the chain's leases check.
                Step::Command { id, bytes, .. } => unsafe { queue.submit(*id, bytes, pages) },
                // SAFETY: as above.
                Step::Queue { tid } => unsafe {
                    let mode = self.client.context.as_ref().map(|c| c.negotiated().mode);
                    let stations = self.client.stations();
                    queue.add_queue(*tid, mode.unwrap_or(phy::Mode::Legacy), stations, pages)
                },
                Step::BlockAck(agreement) => {
                    let (tid, id) = (
                        agreement.session.tid(),
                        self.client.reception.session(agreement.session.tid()),
                    );
                    let bytes = if agreement.enable {
                        commands::allocate_block_ack(
                            tid,
                            agreement.session.start_sequence(),
                            agreement.session.window(),
                            self.client.stations(),
                        )
                    } else {
                        let version = queue
                            .firmware()
                            .command_version(5, 0x16)
                            .map_or(1, |version| version.command_version);
                        let stations = self.client.stations();
                        commands::remove_block_ack(version, id.unwrap_or(0), tid, stations)
                    };
                    // SAFETY: as above.
                    unsafe { queue.submit(commands::BLOCK_ACK_ALLOCATION, &bytes, pages) }
                }
            }
            .map_err(Error::Queue)?;
            self.client.waiting = Some(Waiting {
                ticket,
                deadline: self.clock.deadline(COMMAND_TIMEOUT_US),
                step,
            });
        }
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn finish(
        &mut self,
        queue: &mut Queue<Q, B>,
        step: Step,
        response: boot::CommandResponse,
    ) -> Result<(), Error> {
        let then = match step {
            Step::Command { then, .. } => then,
            Step::Queue { tid } => {
                queue.queue_added(tid, &response).map_err(Error::Queue)?;
                Then::Nothing
            }
            Step::BlockAck(agreement) => {
                self.block_ack_answered(agreement, &response);
                Then::Nothing
            }
        };
        let client = &mut self.client;
        match then {
            Then::Nothing => {}
            Then::Configured(ticket) => {
                let now = self.clock.now_us();
                client
                    .station
                    .complete_configuration(ticket, Completion::Accepted, now)
                    .map_err(Error::Station)?;
                if !queue.firmware().supports_capability(BLOCK_ACK_ALLOCATION) {
                    client.unsupported("receive Block Ack on firmware without session allocation");
                } else if let Err(ba::Error::Station(_) | ba::Error::Stale) =
                    client.station.configure_rx_block_ack(RECEIVE_WINDOW, true)
                {
                    client.unsupported("receive Block Ack on this association");
                }
            }
            Then::Key {
                pairwise,
                index,
                ap,
                ticket,
            } => {
                let key = client
                    .keys
                    .iter_mut()
                    .find(|key| key.pairwise == pairwise && key.index == index && key.ap == ap)
                    .ok_or(Error::Refused("key"))?;
                key.slot
                    .complete_install(*ticket, InstallOutcome::Accepted)
                    .map_err(Error::Key)?;
                key.acknowledged = true;
            }
            Then::Authorized => {
                client.port_open = true;
                let now = self.clock.now_us();
                client.link_authorized(now);
                client.bluetooth.link_changed();
            }
            Then::Country => self.country_answered(queue, &response)?,
            Then::Fifos => self.fifos_answered(queue, &response),
        }
        Ok(())
    }

    /// Frames from the AP.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn take_frames(&mut self, queue: &mut Queue<Q, B>, now: u64) -> Result<(), Error> {
        loop {
            match queue.poll_receive().map_err(Error::Queue)? {
                MpduProgress::Pending | MpduProgress::Backpressure { .. } => return Ok(()),
                MpduProgress::Rejected(_) => self.client.dropped_frames += 1,
                MpduProgress::Observed(observed) => match observed.normalize() {
                    // mac80211 drops a frame the station cannot use; the
                    // exchange it answers retries or times out.
                    Ok(normalized) => match self.frame(normalized, &observed.metadata(), now) {
                        Err(Error::Station(_)) => self.client.dropped_frames += 1,
                        result => result?,
                    },
                    Err(_) => self.client.dropped_frames += 1,
                },
            }
        }
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn frame(
        &mut self,
        normalized: boot::NormalizedMpdu,
        metadata: &crate::wifi::intel::receive::mpdu::Metadata,
        now: u64,
    ) -> Result<(), Error> {
        let key_index = normalized.key_index();
        let mut frame = normalized.into_frame();
        if self.hear_on_link_scan(&frame) || self.client.beacon_heard(&frame, now) {
            return Ok(());
        }
        let client = &mut self.client;
        // The station's data paths take a frame's MLD view themselves.
        if frame.header().control & 12 == 0
            && let Some(view) =
                client
                    .station
                    .mld_view(&frame)
                    .ok()
                    .and_then(|(view, _)| match view {
                        Cow::Owned(view) => Some(view),
                        Cow::Borrowed(_) => None,
                    })
        {
            frame = view;
        }
        let header = frame.header();
        let mut policy = Admitted(&client.channels);
        if header.control & 12 == 0 {
            if header.protected() {
                return self.protected_management(frame, key_index, now);
            }
            if client.station.phase() == Peering::ExternalAuthenticating {
                let session = client
                    .station
                    .external_authentication()
                    .ok_or(Error::Refused("exchange"))?
                    .clone();
                if let Some(received) = client
                    .station
                    .receive_external_authentication(&session, frame, now)
                    .map_err(Error::Station)?
                {
                    client
                        .events
                        .push_back(keeper::Event::Sae(Box::new(received)));
                }
                return Ok(());
            }
            let Some(epoch) = client.station.association_epoch() else {
                return Ok(());
            };
            // `ieee80211_drop_unencrypted_mgmt`: only Public's is not robust.
            if header.control & 0xfc == 0xd0
                && let Some(body) = frame.bytes().get(header.length..)
                && (body.first() == Some(&4)
                    || matches!(body.first(), Some(0 | 9))
                        && !client.station.requires_protected_management())
            {
                client.switch_action(&frame, body, now);
                return Ok(());
            }
            if header.control & 0xfc == 0xd0
                && frame.bytes().get(header.length) == Some(&BLOCK_ACK_CATEGORY)
            {
                // mac80211 drops an agreement it cannot take; the peer then
                // sends without one.
                if let Ok(action) = client.station.receive_block_ack(epoch, &frame, now) {
                    client.block_ack(action);
                }
                return Ok(());
            }
            // A PMF association takes a departure only under its keys.
            if client.station.requires_protected_management()
                && matches!(header.control & 0xfc, 0xa0 | 0xc0)
                && client.keys_settled()
                && !client.keys.is_empty()
            {
                return Ok(());
            }
            let action = client
                .station
                .receive(epoch, &frame, now, &mut policy)
                .map_err(Error::Station)?;
            client.act(action);
            return Ok(());
        }
        let seat = metadata.status.station_id();
        if header.control & 12 == 8 && metadata.mac.amsdu_index() <= 1 {
            client.count_mpdus(seat.unwrap_or(client.seat), false, 1, now);
        }
        if header.control & 12 != 8 || !client.port_ready() || !header.data_present() {
            return Ok(());
        }
        if header.protected() {
            // The firmware decrypted the frame under the key of this index,
            // which only this client installed.
            let multicast = header.receiver.is_multicast();
            // Each link keeps its group keys, under indices that may match.
            let link = seat
                .and_then(|seat| client.context_at(seat))
                .map(|link| link.bssid());
            let installed = client
                .keys
                .iter()
                .filter(|key| key.pairwise != multicast && Some(key.index) == key_index)
                .filter(|key| key.fitted && (!multicast || link.is_none_or(|ap| key.ap == ap)))
                .find_map(|key| Some((key.slot.installed()?, key.slot.replays(&frame))));
            let Some((key, replayed)) = installed else {
                return Ok(());
            };
            // Firmware's Michael check failed: nothing of it is the AP's.
            if frame.security.tkip_mic_error {
                if !replayed {
                    let pairwise = !multicast;
                    client
                        .events
                        .push_back(keeper::Event::MichaelFailure { pairwise });
                }
                return Ok(());
            }
            frame.security.key = Some(key);
            frame.security.integrity = Integrity::Verified;
        }
        let Some(parent) = client.reception.gather(frame) else {
            return Ok(());
        };
        if client.reception.repeats(&parent) {
            return Ok(());
        }
        if parent.members[0].header().fragmented() {
            client.reassemble(&parent.members[0], now);
            return Ok(());
        }
        let mut ready = Vec::new();
        client.reception.order(parent, metadata, now, &mut ready);
        client.deliver_all(ready);
        Ok(())
    }

    /// The firmware answered `agreement`: its session and reorder buffer exist
    /// or are gone, and the station's agreement goes on from there.
    fn block_ack_answered(&mut self, agreement: Agreement, response: &boot::CommandResponse) {
        let now = self.clock.now_us();
        let client = &mut self.client;
        let Agreement {
            ticket,
            session,
            enable,
        } = agreement;
        let completion = if enable {
            let id = response
                .raw
                .get(..4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .filter(|id| *id < MAX_SESSIONS);
            if id.is_some_and(|id| client.reception.open(id as u8, session, now)) {
                Completion::Accepted
            } else {
                client.unsupported("a Block Ack session the firmware or memory refused");
                Completion::RejectedAndIdle
            }
        } else {
            let mut ready = Vec::new();
            client.reception.close(session.tid(), &mut ready);
            client.deliver_all(ready);
            Completion::Accepted
        };
        // SAFETY: the firmware answered this ticket's command, and the reorder
        // buffer exists, or is drained, to match. A departure may have
        // outrun it; `leave` then removes what this opened.
        if let Ok(action) = unsafe { client.station.complete_rx_block_ack(ticket, completion) } {
            client.block_ack(action);
        }
    }

    /// A protected management frame the firmware decrypted, under packet
    /// numbers `ieee80211_crypto_ccmp_decrypt` keeps apart from data's: its
    /// departure ends the association, and an SA Query is answered, as
    /// `ieee80211_process_sa_query_req` does.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn protected_management(
        &mut self,
        mut frame: Mpdu,
        key_index: Option<u8>,
        now: u64,
    ) -> Result<(), Error> {
        let local = self.address;
        let client = &mut self.client;
        let Some(epoch) = client.station.association_epoch() else {
            return Ok(());
        };
        let Some(key) = client
            .keys
            .iter_mut()
            .find(|key| key.pairwise && key.fitted && Some(key.index) == key_index)
        else {
            return Ok(());
        };
        frame.security.key = key.slot.installed();
        frame.security.integrity = Integrity::Verified;
        let Ok(authenticated) = key.slot.authorize_unicast_management(&frame, local) else {
            return Ok(());
        };
        let header = frame.header();
        let body = authenticated.body();
        match header.control & 0xfc {
            0xa0 | 0xc0 => {
                let action = client
                    .station
                    .receive_protected_departure(epoch, &frame, body)
                    .map_err(Error::Station)?;
                client.events.push_back(keeper::Event::ConnectionLost);
                client.act(action);
            }
            0xd0 if body.first() == Some(&BLOCK_ACK_CATEGORY) => {
                let Some(context) = client.context.clone() else {
                    return Ok(());
                };
                if let Ok(action) = client
                    .station
                    .receive_authenticated_block_ack(&context, &frame, body, now)
                {
                    client.block_ack(action);
                }
            }
            0xd0 if matches!(body.first(), Some(0 | 9)) => {
                client.switch_action(&frame, body, now);
            }
            0xd0 if body.len() >= 4 && body[..2] == [8, 0] => {
                let response = [8, 1, body[2], body[3]];
                let Some(ap) = header.transmitter else {
                    return Ok(());
                };
                client
                    .outbox
                    .push_back((None, management(local, ap, 0xd0, true, &response)));
            }
            _ => {}
        }
        Ok(())
    }

    /// Firmware notifications beside the frames.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn take_notifications(&mut self, queue: &mut Queue<Q, B>, now: u64) -> Result<(), Error> {
        while let Some(update) = queue.take_country_update() {
            self.country_update(&update.raw);
        }
        while let Some(notification) = queue.take_other_notification() {
            let raw = &notification.raw;
            let word = |at: usize| {
                raw.get(at..at + 4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            };
            match (notification.command, notification.group) {
                TRANSMIT_RESPONSE => {
                    let family = queue.family();
                    let Ok(response) = Response::parse_notification(
                        queue.firmware(),
                        family,
                        notification.sequence,
                        raw,
                    ) else {
                        self.client.ignored_notifications += 1;
                        continue;
                    };
                    let (next, queue_id, status) = (
                        response.next_pointer,
                        response.queue,
                        response.reported_outcome(),
                    );
                    if queue.reclaim(queue_id, next).is_err() {
                        self.client.ignored_notifications += 1;
                    }
                    if response.ra_tid & 0xf < 8 {
                        self.client.count_mpdus(response.ra_tid >> 4, true, 1, now);
                    }
                    if queue.queue_tid(queue_id) == Some(MANAGEMENT_TID) && self.client.exchange {
                        self.client.exchange = false;
                        let acked = matches!(
                            status,
                            crate::wifi::intel::transmit::response::Outcome::Success
                                | crate::wifi::intel::transmit::response::Outcome::DirectDone
                        );
                        self.client
                            .station
                            .management_status(acked, now)
                            .map_err(Error::Station)?;
                    }
                }
                FRAME_RELEASE if raw.len() >= 4 => {
                    let through = u16::from_le_bytes([raw[2], raw[3]]) & 0xfff;
                    self.client.release(raw[0], None, through);
                }
                BAR_FRAME_RELEASE => {
                    // `iwl_bar_frame_release`.
                    let (Some(station), Some(information)) = (word(0), word(4)) else {
                        continue;
                    };
                    self.client.release(
                        (information >> 24 & 0x3f) as u8,
                        Some((station & 0xf) as u8),
                        (information & 0xfff) as u16,
                    );
                }
                BLOCK_ACK_NOTIFICATION => {
                    let Ok(queues) = block_ack_queues(raw) else {
                        self.client.ignored_notifications += 1;
                        continue;
                    };
                    for (queue_id, next) in queues {
                        if queue.reclaim(queue_id, next).is_err() {
                            self.client.ignored_notifications += 1;
                        }
                    }
                    if let (Some(&station), Some(&[low, high])) = (
                        raw.get(4),
                        raw.get(14..16).and_then(|txed| txed.first_chunk()),
                    ) {
                        let txed = u16::from_le_bytes([low, high]).into();
                        self.client.count_mpdus(station, true, txed, now);
                    }
                }
                RATE_NOTIFICATION
                    if word(4).is_some_and(|flags| flags & RATE_NOTIFICATION_AMSDU != 0) =>
                {
                    let (size, enabled) = (word(12).unwrap_or(0), word(16).unwrap_or(0));
                    self.client.amsdu = if size < SMALLEST_AMSDU {
                        (0, 0)
                    } else {
                        (size, enabled)
                    };
                }
                SESSION_PROTECTION_NOTIFICATION => {
                    let (status, start) = (word(4).unwrap_or(0), word(8).unwrap_or(0));
                    self.client.session = if status == 1 && start == 1 {
                        Session::On
                    } else {
                        Session::Off
                    };
                }
                MISSED_BEACONS_LEGACY_NOTIFICATION | MISSED_BEACONS_NOTIFICATION
                    if word(8).is_some_and(|missed| missed >= MISSED_BEACONS) =>
                {
                    // Data still heard keeps the link, and leaves the rest
                    // of Linux's reading alone.
                    if word(4).is_some_and(|missed| missed >= self.missed_since_receive())
                        && self.client.station.association_epoch().is_some()
                        && !self.client.leaving
                    {
                        self.client.events.push_back(keeper::Event::ConnectionLost);
                        let action = self.client.station.disconnect().map_err(Error::Station)?;
                        self.client.act(action);
                    }
                }
                MISSED_BEACONS_LEGACY_NOTIFICATION | MISSED_BEACONS_NOTIFICATION
                    if self.client.emlsr.active =>
                {
                    let missed = word(8).unwrap_or(0);
                    let other = word(16).unwrap_or(0);
                    let link = word(0).unwrap_or(u32::from(self.client.seat)) as u8;
                    self.client.emlsr_missed_beacons(link, missed, other);
                }
                MISSED_BEACONS_LEGACY_NOTIFICATION | MISSED_BEACONS_NOTIFICATION
                    if word(4).is_some_and(|missed| missed > LINK_SCAN_MISSED_BEACONS) =>
                {
                    self.client.ask_link_scan(now);
                }
                emlsr::MODE_NOTIFICATION if word(0) == Some(emlsr::RECOMMEND_LEAVE) => {
                    let seat = self.client.seat;
                    self.client.emlsr.ask_exit(emlsr::Exit::Firmware, seat);
                }
                emlsr::TRANSITION_FAILED_NOTIFICATION if self.client.emlsr.active => {
                    let (link, activating) = (word(0).unwrap_or(0), word(4).unwrap_or(0));
                    if activating != 0 {
                        self.client
                            .emlsr
                            .ask_exit(emlsr::Exit::FailedEntry, link as u8);
                    } else if !self.client.leaving {
                        self.client.events.push_back(keeper::Event::ConnectionLost);
                        let action = self.client.station.disconnect().map_err(Error::Station)?;
                        self.client.act(action);
                    }
                }
                beacon::SWITCH_START_NOTIFICATION => {
                    let disable_tx = self.radio != Rf::Fm
                        && !queue.firmware().supports_api(beacon::FIRMWARE_DISABLES_TX);
                    self.client.switch_started(word(0).unwrap_or(0), disable_tx);
                }
                beacon::SWITCH_ERROR_NOTIFICATION if word(4).is_some_and(beacon::switch_failed) => {
                    self.client.tracking.watch.drop_connection();
                }
                coexistence::PROFILE_NOTIFICATION => self.client.bluetooth.profile(raw),
                coexistence::LEGACY_STATISTICS_NOTIFICATION => self.coexistence_statistics(
                    queue,
                    raw,
                    coexistence::StatisticsNotification::Legacy,
                ),
                emlsr::BLUETOOTH_NOTIFICATION => {
                    let active = raw.iter().any(|&byte| byte != 0);
                    self.client.bluetooth_changed(active, now);
                }
                SCAN_START_NOTIFICATION => self.client.link_scan_started(now),
                statistics::OPERATIONAL_NOTIFICATION
                    if matches!(queue.family(), Family::Ax200 | Family::Ax210)
                        && self
                            .client
                            .context
                            .as_ref()
                            .is_none_or(|context| context.affiliation().is_none()) =>
                {
                    self.coexistence_statistics(
                        queue,
                        raw,
                        coexistence::StatisticsNotification::System,
                    );
                }
                statistics::OPERATIONAL_NOTIFICATION => {
                    let version = queue
                        .firmware()
                        .command_version(0x10, 0)
                        .map_or(3, |version| version.notification_version);
                    self.client.statistics_arrived(raw, version, now);
                }
                _ => {}
            }
        }
        // After its start, which came first.
        while let Some(end) = queue.take_scan_completion() {
            let field = |at: usize| end.raw.get(at).copied().unwrap_or(0);
            let ebs_failed = Queue::<Q, B>::energy_based_failed(field(7));
            self.client.link_scan_finished(field(6), ebs_failed)?;
        }
        Ok(())
    }

    fn parameters(&mut self, antennas: u8, encrypted: bool) -> Parameters {
        let client = &mut self.client;
        client.antenna = next_antenna(antennas, client.antenna.max(1));
        Parameters {
            station_authorized: Some(client.port_open),
            force_host_rate: false,
            host_rate: lowest_rate(self.selected.as_ref().map_or(0, |selected| selected.rates)),
            host_antenna: client.antenna,
            firmware_encryption: encrypted,
        }
    }

    /// Management frames, once session protection holds the channel for them.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn send_management(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        if self.client.outbox.is_empty()
            || (self.client.tracking.watch.silent() && !self.client.leaving)
        {
            return Ok(());
        }
        let associated = self.client.station.phase() == Peering::Associated;
        if !associated && self.client.session != Session::On {
            if self.client.session == Session::Off {
                self.client.session = Session::Starting;
                self.client.command(
                    commands::SESSION_PROTECTION,
                    commands::protect_session(false),
                );
            }
            return self.run_steps(queue);
        }
        // The leases refuse a frame while a command is in flight.
        if self.client.waiting.is_some() {
            return Ok(());
        }
        let on_2ghz = queue.channel().band == Band::Ghz2;
        let antennas = queue.antennas();
        let antennas = self.client.bluetooth.management_antennas(on_2ghz, antennas);
        while queue.space(MANAGEMENT_TID) != 0 {
            let Some((ticket, bytes)) = self.client.outbox.pop_front() else {
                break;
            };
            let encrypted = bytes[1] & 0x40 != 0;
            let parameters = Parameters {
                station_authorized: None,
                ..self.parameters(antennas, encrypted)
            };
            let pages = self.pages;
            // SAFETY: `new`'s contract holds; the frame goes to the AP.
            unsafe { queue.publish(MANAGEMENT_TID, &bytes, parameters, pages) }
                .map_err(Error::Queue)?;
            if !associated {
                self.client.exchange = true;
            }
            if let Some(ticket) = ticket {
                self.client
                    .station
                    .submitted(ticket)
                    .map_err(Error::Station)?;
            }
        }
        Ok(())
    }

    /// Data frames onto their TIDs' queues, each adding its queue first.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn send_data(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        if self.client.tracking.watch.silent() {
            return Ok(());
        }
        let antennas = queue.antennas();
        for tid in 0..16u8 {
            if self.client.held[usize::from(tid)].is_empty() {
                continue;
            }
            if self.client.requested & (1 << tid) == 0 {
                self.client.requested |= 1 << tid;
                self.client.steps.push_back(Step::Queue { tid });
            }
            if !queue.has_queue(tid) {
                continue;
            }
            while self.client.waiting.is_none() && queue.space(tid) != 0 {
                let Some(held) = self.client.held[usize::from(tid)].pop_front() else {
                    break;
                };
                let parameters = self.parameters(antennas, held.encrypted);
                let pages = self.pages;
                // SAFETY: `new`'s contract holds; the frame goes to the AP.
                unsafe { queue.publish(tid, &held.mpdu, parameters, pages) }
                    .map_err(Error::Queue)?;
            }
        }
        self.run_steps(queue)
    }

    /// Queue `ethernet` for its TID.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn send(&mut self, ethernet: &[u8], class: TxClass) -> Result<(), Error> {
        let client = &mut self.client;
        let epoch = client
            .station
            .association_epoch()
            .ok_or(Error::Refused("no association"))?;
        let context = client.context.clone().ok_or(Error::Refused("no context"))?;
        let tid = data::data_tid(&context, None, None, ethernet);
        let room = tid
            .filter(|_| matches!(class, TxClass::Data))
            .and_then(|tid| {
                let fifo = client.fifos.unwrap_or_default().amsdu_limit(
                    tid,
                    context.negotiated().mode >= phy::Mode::He,
                    context.channel().band,
                    context.affiliation().is_some(),
                );
                let limit = (client.amsdu.0.min(fifo) as usize)
                    .min(commands::max_amsdu(context.negotiated()).into());
                let tail = client.held[usize::from(tid)].back()?;
                (client.amsdu.1 & 1 << tid != 0
                    && !tail.control_port
                    && tail.mpdu.len() + ethernet.len() + amsdu::SUBFRAME_OVERHEAD <= limit)
                    .then_some(tid)
            });
        let mut policy = Admitted(&client.channels);
        let mut keys: Vec<&mut KeySlot> = client.keys.iter_mut().map(|key| &mut key.slot).collect();
        if let Some(tid) = room {
            // `ieee80211_amsdu_aggregate`: while a frame waits, the next joins it.
            let plan = client
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
            if let Some(tail) = client.held[usize::from(tid)].back_mut() {
                amsdu::append(&mut tail.mpdu, plan.plaintext_mpdu(), 0);
            }
            return Ok(());
        }
        let plan = match tid {
            Some(tid) => client.station.prepare_qos_msdu_refs(
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
            None => client.station.prepare_msdu_refs(
                epoch,
                ethernet,
                class,
                SequenceOwner::Device,
                &mut keys,
                &mut policy,
            ),
        }
        .map_err(Error::Data)?;
        let queue = usize::from(tid.unwrap_or(MANAGEMENT_TID));
        if client.held[queue].len() >= MAX_HELD {
            client.held[queue].pop_front();
        }
        let encrypted = matches!(plan.protection(), Protection::Firmware { .. });
        let mut mpdu = plan.plaintext_mpdu().to_vec();
        // `IEEE80211_KEY_FLAG_PUT_MIC_SPACE`: firmware writes Michael's MIC.
        if encrypted && matches!(client.ciphers, Some((Cipher::Tkip, _))) {
            mpdu.resize(mpdu.len() + MICHAEL_MIC_BYTES, 0);
        }
        client.held[queue].push_back(Held {
            mpdu,
            encrypted,
            control_port: plan.control_port(),
        });
        Ok(())
    }

    /// `iwl_mvm_mld_set_key` for the association's data key, or a group key
    /// of the link of `ap`. A dormant link's stands installed without
    /// reaching firmware, as mac80211 holds it back until the link activates.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn install(
        &mut self,
        ap: Mac,
        pairwise: bool,
        index: u8,
        material: &[u8],
        receive: ReplaySeed,
    ) -> Result<KeyIdentity, Error> {
        let client = &mut self.client;
        let (unicast, group) = client.ciphers.ok_or(Error::Refused("no ciphers"))?;
        let cipher = if pairwise { unicast } else { group };
        let pmf = client.station.requires_protected_management();
        let flags = commands::key_flags(cipher, pairwise, pmf && pairwise)
            .ok_or(Error::Unsupported("the cipher on Intel Wi-Fi"))?;
        let peer = client
            .station
            .pairwise_peer()
            .ok_or(Error::Refused("no peer"))?;
        let seat = client.seat_of(ap);
        let fitted = pairwise || seat.is_some();
        let scope = if pairwise {
            KeyScope::Pairwise(peer)
        } else {
            KeyScope::Group(ap)
        };
        // SAFETY: the counter gives each key of the adapter its own slot.
        let mut slot = unsafe { KeySlot::new(client.next_slot) }.map_err(Error::Key)?;
        client.next_slot = client.next_slot.wrapping_add(1);
        let transmit = if pairwise {
            TransmitSeed::FIRMWARE_FRESH
        } else {
            TransmitSeed::RECEIVE_ONLY
        };
        let ticket = slot
            .begin_install(index, cipher, material, receive, scope, transmit)
            .map_err(Error::Key)?;
        let identity = ticket.identity();
        let counter = receive.counters()[0];
        let stations = match seat {
            Some(seat) if !pairwise => 1 << seat,
            _ => client.stations(),
        };
        let bytes = commands::add_key(index, flags, material, counter, stations)
            .ok_or(Error::Refused("key material"))?;
        if let Some(old) = client
            .keys
            .iter()
            .position(|key| key.pairwise == pairwise && key.index == index && key.ap == ap)
        {
            let old = client.keys.remove(old);
            if old.fitted {
                client.command(
                    commands::SECURITY_KEY,
                    commands::remove_key(old.index, old.flags, stations),
                );
            }
        }
        if !fitted {
            slot.complete_install(ticket, InstallOutcome::Accepted)
                .map_err(Error::Key)?;
        }
        client.keys.push(Key {
            slot,
            pairwise,
            index,
            flags,
            acknowledged: !fitted,
            ap,
            fitted,
            material: (!pairwise).then(|| (Zeroizing::new(material.to_vec()), counter)),
        });
        if !fitted {
            return Ok(identity);
        }
        client.steps.push_back(Step::Command {
            id: commands::SECURITY_KEY,
            bytes,
            then: Then::Key {
                pairwise,
                index,
                ap,
                ticket: Box::new(ticket),
            },
        });
        Ok(identity)
    }

    /// The chain's way down, once its last commands finished.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    pub(super) fn leave(&mut self, queue: &mut Queue<Q, B>) -> Result<bool, Error> {
        if !self.client.leaving || !self.client.idle() || self.client.link_scanning() {
            return Ok(false);
        }
        if let Some(frame) = self.client.farewell.take() {
            let antennas = queue.antennas();
            let parameters = Parameters {
                station_authorized: None,
                ..self.parameters(antennas, frame[1] & 0x40 != 0)
            };
            let pages = self.pages;
            // SAFETY: `new`'s contract holds; the frame goes to the AP.
            unsafe { queue.publish(MANAGEMENT_TID, &frame, parameters, pages) }
                .map_err(Error::Queue)?;
            self.client.draining = Some(self.clock.deadline(DEPARTURE_DRAIN_US));
        }
        if let Some(deadline) = &self.client.draining {
            if queue.in_flight(MANAGEMENT_TID) != 0 && !deadline.passed() {
                return Ok(false);
            }
            self.client.draining = None;
        }
        self.client.stop_statistics();
        // The chain goes down on the IDs it came up with.
        if self.client.emlsr.active {
            self.lower_second(queue, 0)?;
            self.run_steps(queue)?;
            return Ok(false);
        }
        if self.client.seat != 0 {
            self.switch_link(queue)?;
            self.run_steps(queue)?;
            return Ok(false);
        }
        if self.client.session != Session::Off {
            self.client.session = Session::Off;
            self.client.command(
                commands::SESSION_PROTECTION,
                commands::protect_session(true),
            );
        }
        // `ieee80211_sta_tear_down_BA_sessions`: nothing tells a peer that is
        // going, and nothing can use what the buffers held.
        let version = queue
            .firmware()
            .command_version(5, 0x16)
            .map_or(1, |version| version.command_version);
        for (id, tid) in self.client.reception.take_sessions() {
            self.client.command(
                commands::BLOCK_ACK_ALLOCATION,
                commands::remove_block_ack(version, id, tid, self.client.stations()),
            );
        }
        let stations = self.client.stations();
        let keys = core::mem::take(&mut self.client.keys);
        for key in keys.into_iter().filter(|key| key.fitted) {
            self.client.command(
                commands::SECURITY_KEY,
                commands::remove_key(key.index, key.flags, stations),
            );
        }
        let keys = core::mem::take(&mut self.client.management_keys);
        for key in keys.into_iter().filter(|key| key.fitted) {
            self.client.command(
                commands::SECURITY_KEY,
                commands::remove_key(key.index, key.flags, stations),
            );
        }
        if !self.client.idle() {
            self.run_steps(queue)?;
            return Ok(false);
        }
        queue.begin_remove_station().map_err(Error::Queue)?;
        Ok(true)
    }

    /// Serve the raised chain.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    pub(super) fn serve(&mut self) -> Result<(), Error> {
        let stage = core::mem::replace(&mut self.stage, Stage::Moving);
        let Stage::Ready(mut queue) = stage else {
            self.stage = stage;
            return Ok(());
        };
        let mut result = self.operate(&mut queue);
        let down = result.is_ok()
            && match self.leave(&mut queue) {
                Ok(down) => down,
                Err(error) => {
                    result = Err(error);
                    false
                }
            };
        self.stage = if down {
            Stage::Removing(queue)
        } else {
            Stage::Ready(queue)
        };
        result
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn observed(&self, handle: usize) -> Result<Arc<NativeBssObservation>, Error> {
        self.client
            .observed
            .get(handle)
            .map(|heard| heard.observation.clone())
            .ok_or(Error::Refused("BSS"))
    }
}

/// The body of the firmware's `TLC_MNG_CONFIG_CMD` version.
#[expect(
    clippy::result_large_err,
    reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
)]
fn rate_shape(
    firmware: &crate::wifi::intel::firmware::Firmware<'_>,
) -> Result<commands::RateShape, Error> {
    firmware
        .command_version(5, 0x0f)
        .and_then(|version| commands::RateShape::of(version.command_version))
        .ok_or(Error::Refused("TLC_MNG_CONFIG_CMD version"))
}

/// A command's firmware version. Group 0 lists under `LONG_GROUP`.
fn version_of(firmware: &crate::wifi::intel::firmware::Firmware<'_>, id: command::Id) -> u8 {
    firmware
        .command_version(id.group.max(1), id.opcode)
        .map_or(0, |version| version.command_version)
}

fn peer_state(
    context: &AssociationContext,
    explicit_mfp: bool,
    authorized: bool,
    seat: u8,
) -> PeerState {
    let negotiated = context.negotiated();
    PeerState {
        seat,
        address: context.peer(),
        link: context.bssid(),
        aid: context.response().aid,
        mfp: explicit_mfp && (context.pmf().is_some() || !authorized),
        mimo: negotiated.rx_nss > 1,
        ampdu_spacing: negotiated.peer_mpdu_spacing,
        ampdu_exponent: commands::ampdu_exponent(negotiated),
        wmm_service_period: negotiated.wmm.as_ref().map(|wmm| wmm.max_service_period),
        uapsd_queues: negotiated.wmm.as_ref().map_or(0, |wmm| wmm.uapsd_queues),
        he: peer_he(context),
    }
}

/// The AP's HE capabilities, where HE was negotiated.
fn ap_he(context: &AssociationContext) -> Option<&phy::He> {
    let negotiated = context.negotiated();
    negotiated.he.as_ref()?;
    negotiated.peer().he()
}

/// The AP's EHT capabilities, where EHT was negotiated.
fn ap_eht(context: &AssociationContext) -> Option<&phy::Eht> {
    let negotiated = context.negotiated();
    negotiated.eht.as_ref()?;
    negotiated.peer().eht()
}

/// `ieee80211_assoc_config_link`'s HE half, for a link.
fn link_he(context: &AssociationContext) -> Option<LinkHe> {
    let he = ap_he(context)?;
    let operations = context.operations();
    let operation = operations.he.as_ref()?;
    Some(LinkHe {
        packet_extension: operation.packet_extension(),
        uora: operations.uora,
        mu_edca: operations.mu_edca,
        color: operation.color(),
        color_enabled: operation.color_enabled(),
        rts_threshold: operation.rts_threshold(),
        uplink_data_disabled: he.mac[5] & UPLINK_DATA_DISABLED != 0,
    })
}

/// The HE half of `iwl_mvm_mld_cfg_sta`.
fn peer_he(context: &AssociationContext) -> Option<PeerHe> {
    let he = ap_he(context)?;
    Some(PeerHe {
        ack_enabled: he.mac[2] & ACK_ENABLED != 0,
        random_access: context.operations().uora.is_some(),
        packet_extension: commands::packet_extension(he, ap_eht(context)),
        control: commands::control_flags(&he.mac),
    })
}

/// What a station's capability elements read of the device.
#[derive(Clone, Copy, Debug)]
struct Device {
    family: Family,
    radio: Rf,
    /// The transmit and receive antennas.
    chains: (u32, u32),
    /// A radio with EHT's limits.
    eht: Option<EhtLimits>,
}

/// `iwl_init_ht_hw_capab`, `iwl_init_vht_hw_capab` and mac80211's SMPS-off
/// HT capabilities for a device of `tx`, `rx` chains, as an association names
/// them.
fn capability_elements(band: Band, device: Device, widest: phy::Width) -> Vec<u8> {
    let mut elements = probe_elements(band, device, widest);
    if device.family == Family::Ax200 {
        // `iwl_vendor_caps`: Intel's capabilities, with improved HE feedback.
        elements.extend_from_slice(&[221, 6, 0x00, 0x17, 0x35, 8, 1, 0]);
    }
    // `ieee80211_add_wmm_info_ie`, without U-APSD.
    elements.extend_from_slice(&[221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0]);
    elements
}

/// `bss_conf->twt_protected`: `ieee80211_assoc_config_link` reads the response.
fn protected_twt(
    firmware: &crate::wifi::intel::firmware::Firmware<'_>,
    context: &AssociationContext,
) -> bool {
    context.negotiated().he.is_some()
        && firmware.supports_capability(PROTECTED_TWT)
        && commands::twt_protected(&context.response().elements)
}

/// The rates and capabilities a probe names, `ieee80211_build_preq_ies_band`.
fn probe_elements(band: Band, device: Device, widest: phy::Width) -> Vec<u8> {
    let Device {
        family,
        radio,
        chains,
        eht,
    } = device;
    let wide = widest != phy::Width::Mhz80;
    let two_streams = chains.0 & chains.1 == 3;
    let (tx, rx) = (chains.0.count_ones(), chains.1.count_ones());
    let mut elements = Vec::new();
    let mut element = |id: u8, body: &[u8]| {
        elements.extend_from_slice(&[id, body.len() as u8]);
        elements.extend_from_slice(body);
    };
    if band == Band::Ghz2 {
        element(1, &[2, 4, 11, 22, 12, 18, 24, 36]);
        element(50, &[48, 72, 96, 108]);
    } else {
        element(1, &[12, 18, 24, 36, 48, 72, 96, 108]);
    }
    let mut ht = [0; 26];
    let capability: u16 = 0x1000 // DSSSCCK40
        | 1 << 8 // RX STBC, one stream
        | u16::from(tx > 1) << 7 // TX STBC
        | 1 // LDPC
        | 0x800 // 7935-byte A-MSDU
        | 0xc // SMPS off
        | 0x20 // SGI 20
        | 0x2 // 20/40
        | 0x40; // SGI 40
    ht[..2].copy_from_slice(&capability.to_le_bytes());
    ht[2] = 3 | 5 << 2; // 64 KB A-MPDUs at 4 us spacing
    ht[3] = 0xff;
    ht[4] = if rx >= 2 { 0xff } else { 0 };
    ht[13..15].copy_from_slice(&(150 * rx as u16).to_le_bytes());
    ht[15] = 1;
    if tx != rx {
        ht[15] |= 2 | ((tx.saturating_sub(1) as u8) << 2);
    }
    if band != Band::Ghz6 {
        element(45, &ht);
    }
    element(127, &EXTENDED_CAPABILITIES);
    if band == Band::Ghz5 {
        let mut vht = [0; 12];
        let capability: u32 = 2 // 11454-byte MPDUs
            | 0x10 // RX LDPC
            | 0x20 // SGI 80
            | 0x100 // RX STBC 1
            | 0x800 << 1 // SU beamformee
            | 3 << 13 // beamformee STS
            | 0x10_0000 // MU beamformee
            | 7 << 23 // 1 MB A-MPDUs
            | if wide { 0x44 } else { 0 } // 160 MHz, SGI 160
            | if tx > 1 { 0x80 } else { 0x2000_0000 }
            | if rx == 1 { 0x1000_0000 } else { 0 };
        vht[..4].copy_from_slice(&capability.to_le_bytes());
        let map: u16 = if rx >= 2 { 0xfffa } else { 0xfffe };
        vht[4..6].copy_from_slice(&map.to_le_bytes());
        vht[8..10].copy_from_slice(&map.to_le_bytes());
        element(191, &vht);
    }
    elements.extend(he::capability(
        band,
        family,
        radio,
        two_streams,
        wide,
        eht.is_some(),
    ));
    if band == Band::Ghz6 {
        elements.extend(he::six_ghz_capability(tx, rx));
    }
    if let Some(limits) = eht {
        elements.extend(eht::capability(band, limits, two_streams, widest));
    }
    elements
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// The beacons missed since anything was heard that lose the link.
    fn missed_since_receive(&self) -> u32 {
        if self.radio == Rf::Fm {
            MISSED_BEACONS_SINCE_RECEIVE_WIFI_7
        } else {
            MISSED_BEACONS_SINCE_RECEIVE
        }
    }

    fn device(&self) -> Device {
        Device {
            family: self.family,
            radio: self.radio,
            chains: self.chains,
            eht: self.eht,
        }
    }

    /// The widest channel `band` offers this device. 320 MHz is EHT's, and
    /// 6 GHz's alone.
    fn widest(&self, band: Band) -> phy::Width {
        let open = |closed: u32| {
            self.client
                .channels
                .iter()
                .any(|(channel, flags)| channel.band == band && flags & closed == 0)
        };
        let eht = self.eht.is_some_and(EhtLimits::reaches_320);
        if !open(NO_160MHZ) {
            phy::Width::Mhz80
        } else if eht && band == Band::Ghz6 && open(NO_160MHZ | NO_320MHZ) {
            phy::Width::Mhz320
        } else {
            phy::Width::Mhz160
        }
    }

    /// What firmware's probes radiate: its lowest legacy rate of each band,
    /// which `iwl_mvm_scan_rate_n_flags` shows, under the limit of the country
    /// programmed into it, so no higher than that of the strictest channel.
    fn probe_profiles(&self, country: &database::Country) -> ProbeProfiles {
        let profile = |band, rate| TxProfile {
            width: Width::Legacy20,
            rate,
            short_preamble: false,
            max_eirp_mbm: self
                .client
                .channels
                .iter()
                .filter(|(channel, _)| channel.band == band)
                .map(|(channel, _)| country.channel(channel.frequency_mhz).max_reg_dbm * 100)
                .min()
                .unwrap_or(0),
        };
        ProbeProfiles {
            ghz2: profile(Band::Ghz2, regulatory::LegacyRate::Cck1),
            ghz5: profile(Band::Ghz5, regulatory::LegacyRate::Ofdm6),
            ghz6: profile(Band::Ghz6, regulatory::LegacyRate::Ofdm6),
        }
    }

    /// The probes of a scan this adapter runs now.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn probe(&self) -> Result<boot::Probe, Error> {
        let country = self
            .client
            .regulatory
            .as_ref()
            .ok_or(Error::Refused("scan"))?;
        let elements = |band| probe_elements(band, self.device(), self.widest(band));
        Ok(boot::Probe {
            elements: [Band::Ghz2, Band::Ghz5, Band::Ghz6].map(elements),
            profiles: self.probe_profiles(country),
        })
    }
}

/// Polling the link serves the station; frames flow once its port is open.
impl<Q: BootIo, B: BiosIo> Link for Wifi<Q, B> {
    fn mac(&self) -> Mac {
        self.address
    }
    fn carrier(&mut self) -> bool {
        self.client.port_open
    }
    /// A station signals once its port is open. Until then the handshake's
    /// timers run on a caller that keeps polling.
    fn signals(&self) -> bool {
        self.vector && self.client.port_open
    }
    fn due_us(&self) -> Option<u64> {
        self.signals()
            .then(|| self.clock.now_us().saturating_add(TIMER_TICK_US))
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        if !self.client.port_open {
            return Err(LinkError::NoCarrier);
        }
        self.send(frame, TxClass::Data)
            .map_err(|error| match error {
                Error::Pci(error) | Error::Boot(boot::Error::Pci(error)) => LinkError::Pci(error),
                Error::Boot(boot::Error::Access(super::super::power::AccessError::Minimum(
                    error,
                )))
                | Error::Boot(boot::Error::Power(super::super::power::Error::Access(
                    super::super::power::AccessError::Minimum(error),
                ))) => LinkError::Pci(crate::block::BlockError::PciPower(error)),
                error => LinkError::Adapter(format!("{error}")),
            })
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        Ok(self.client.received.pop_front())
    }
}

impl<Q: BootIo, B: BiosIo> Radio for Wifi<Q, B> {
    type Handle = usize;
    type Profile = ();
    type Management = Arc<ManagementKey>;
    type Error = Error;

    const NAME: &'static str = "iwlwifi";
    /// `IWL_MVM_CONN_LISTEN_INTERVAL`.
    const LISTEN_INTERVAL: u16 = 10;

    fn deferred(error: &Error) -> bool {
        matches!(error, Error::Pending)
    }

    fn service(&mut self) -> Result<(), Error> {
        if self.error.is_none() && self.died() {
            let log = self.tables.read(&self.restart.io, self.family);
            self.error = Some(Error::FirmwareDied(log));
        }
        self.poll();
        if self.switched_off() {
            self.client.events.push_back(keeper::Event::FirmwareLost);
            return Err(Error::SwitchedOff);
        }
        let served = if self.error.is_none() {
            self.serve()
        } else {
            Ok(())
        };
        // Firmware that stopped answering is as dead as firmware that says so.
        if let Err(error @ Error::Timeout(_)) = &served {
            self.error = Some(error.clone());
        }
        let Some(error) = self.error.clone() else {
            return served;
        };
        // A terminal firmware/transport failure revokes the controlled port
        // even when stop or reset refuses and the original owner stays held.
        self.client.port_open = false;
        let restarted = self.restart();
        if self.reported && !restarted {
            return Ok(());
        }
        self.reported = !restarted;
        self.client.events.push_back(keeper::Event::FirmwareLost);
        // A restart that failed names its own cause.
        Err(self.error.clone().unwrap_or(error))
    }

    fn take_event(&mut self) -> Option<keeper::Event> {
        self.client.events.pop_front()
    }

    fn stage(&self) -> Standing {
        if self.gone {
            return Standing::Lost;
        }
        match &self.stage {
            Stage::Scan(_) if self.client.left => Standing::NeedsDrain,
            Stage::Scan(scan) => match scan.phase() {
                Ax200ScanPhase::NotStarted => Standing::Idle,
                Ax200ScanPhase::DrainRequired => Standing::Scanned,
                _ => Standing::Busy,
            },
            Stage::Ready(_) if self.client.admitted.is_some() => Standing::Admitted,
            _ => Standing::Busy,
        }
    }

    fn station(&self) -> &Station {
        &self.client.station
    }

    fn channels(&self, band: Band) -> Vec<(Channel, u32)> {
        self.client
            .channels
            .iter()
            .filter(|(channel, _)| channel.band == band)
            .copied()
            .collect()
    }

    /// A channel the firmware and the country let a frame start on.
    fn probes(&self, channel: Channel) -> bool {
        let (Some(country), Some(beacons)) = (&self.client.regulatory, &self.beacons) else {
            return false;
        };
        let profiles = self.probe_profiles(country);
        self.client
            .channels
            .iter()
            .any(|&(known, flags)| known == channel && flags & NO_IR == 0)
            && crate::wifi::intel::policy::allows(
                country,
                beacons,
                Operation::Transmit {
                    channel,
                    purpose: Purpose::Probe,
                    profile: profiles.on(channel),
                },
            )
    }

    fn six_ghz_links(&self) -> bool {
        true
    }

    fn eml_capabilities(&self) -> u16 {
        if self.client.eml_capable {
            emlsr::CAPABILITIES
        } else {
            0
        }
    }

    fn supported_channels(&self, band: Band) -> &'static [u8] {
        match band {
            Band::Ghz2 => &[1, 14],
            Band::Ghz5 => &[36, 28, 149, 9],
            Band::Ghz6 => &[],
        }
    }

    fn regulated_power_dbm(&self, frequency_mhz: u16) -> i32 {
        self.client
            .regulatory
            .as_ref()
            .map_or(0, |country| country.channel(frequency_mhz).max_reg_dbm)
    }

    fn advertisement(&self, band: Band) -> Result<Advertisement, Error> {
        let elements = capability_elements(band, self.device(), self.widest(band));
        let capabilities = Capabilities::parse(band, Role::Station, &elements)
            .map_err(|_| Error::Refused("advertisement"))?;
        Ok(Advertisement {
            capabilities,
            elements,
            he_source_maps: he::maps(self.chains.0 & self.chains.1 == 3),
            multi_link: Some(self.eht.is_some()),
        })
    }

    fn profile(&self, _: Peer) -> Result<(), Error> {
        Ok(())
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn begin_scan(&mut self, request: scan::Request, budget_us: u64) -> Result<(), Error> {
        let probe = request.active().then(|| self.probe()).transpose()?;
        let pages = self.pages;
        let Stage::Scan(owner) = &mut self.stage else {
            return Err(Error::Refused("scan"));
        };
        while !matches!(
            owner.poll_pre_scan_receive().map_err(Error::Scan)?,
            MpduProgress::Pending | MpduProgress::Backpressure { .. }
        ) {}
        // A scan runs in parts, whose results `choose` takes together.
        let now = self.clock.now_us();
        self.client
            .observed
            .retain(|heard| now.saturating_sub(heard.at) < BSS_EXPIRY_US);
        let started = match probe {
            // SAFETY: `new`'s contract covers the scan's pages.
            Some(probe) => unsafe { owner.start_probing(request, &probe, budget_us, pages) },
            // SAFETY: as above.
            None => unsafe { owner.start(request, budget_us, pages) },
        };
        started.map_err(Error::Scan)?;
        Ok(())
    }

    unsafe fn retire_scan(&mut self) -> Result<(), Error> {
        let Stage::Scan(owner) = &mut self.stage else {
            return Err(Error::Refused("scan"));
        };
        while owner
            .poll_retiring_receive()
            .map_err(Error::Scan)?
            .is_some()
        {}
        owner.retire().map_err(Error::Scan)?;
        Ok(())
    }

    fn six_ghz_scan(
        &self,
        request: &scan::Request,
        options: scan::six_ghz::Options,
    ) -> Result<Option<scan::Request>, Error> {
        let known = self.client.observed.iter();
        scan::six_ghz::second_part(request, options, known.map(|heard| heard.observation.bss()))
            .map_err(|error| Error::Scan(boot::Ax200ScanError::Protocol(error)))
    }

    fn bss(&self) -> Vec<(usize, &Bss)> {
        self.client
            .observed
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
        let affiliation = join.request.multi_link().map(|setup| setup.association);
        self.raise(&bss, affiliation, Plan::Join { join, observed })
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
        let now = self.clock.now_us();
        let client = &mut self.client;
        let mut policy = Admitted(&client.channels);
        let session = client
            .station
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
            .map_err(Error::Station)?;
        self.raise(&bss, multi_link, Plan::Exchange)?;
        Ok(session)
    }

    fn begin_six_ghz_external_authentication(
        &mut self,
        handle: usize,
        selection: Selection,
        _: (),
        multi_link: Option<Affiliation>,
        budget_us: u64,
    ) -> Result<Arc<external::Session>, Error> {
        let observed = self.observed(handle)?;
        let bss = observed.bss().clone();
        let local = self.advertisement(bss.channel.band)?.capabilities;
        let now = self.clock.now_us();
        let client = &mut self.client;
        if !client
            .channels
            .iter()
            .any(|(known, _)| *known == bss.channel)
        {
            return Err(Error::Refused("6 GHz channel"));
        }
        let session = client
            .station
            .prepare_six_ghz_authentication(observed, selection, local, multi_link, now, budget_us)
            .map_err(Error::Station)?;
        client
            .station
            .commit_six_ghz_authentication(session.clone(), now)
            .map_err(Error::Station)?;
        self.raise(&bss, multi_link, Plan::Exchange)?;
        Ok(session)
    }

    fn transmit_external_authentication(
        &mut self,
        session: &external::Session,
        frame: external::Frame<'_>,
    ) -> Result<(), Error> {
        let now = self.clock.now_us();
        let client = &mut self.client;
        let mut policy = Admitted(&client.channels);
        let bytes = client
            .station
            .external_authentication_transmit(session, frame, now, &mut policy)
            .map_err(Error::Station)?;
        client.outbox.push_back((None, bytes));
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
        let client = &mut self.client;
        let mut policy = Admitted(&client.channels);
        client.ciphers = join.request.key_ciphers();
        client.management_cipher = join.request.pmf().map(|pmf| pmf.management());
        let action = client
            .station
            .associate_external_pmf(session, join, observed, now, &mut policy)
            .map_err(Error::Station)?;
        client.act(action);
        Ok(())
    }

    fn configure(&mut self) -> Result<(), Error> {
        let (ticket, context) = self
            .client
            .admitted
            .take()
            .ok_or(Error::Refused("configuration"))?;
        self.client.context = Some(context.clone());
        let stage = core::mem::replace(&mut self.stage, Stage::Moving);
        let Stage::Ready(mut queue) = stage else {
            self.stage = stage;
            return Err(Error::Refused("configuration"));
        };
        let result = self.association_steps(&mut queue, &context, ticket);
        self.stage = Stage::Ready(queue);
        result
    }

    fn send_control(&mut self, ethernet: &[u8], key: Option<KeyIdentity>) -> Result<(), Error> {
        let class = key.map_or(TxClass::ControlPortPlaintext, TxClass::ControlPortProtected);
        self.send(ethernet, class)
    }

    fn install_key(
        &mut self,
        pairwise: bool,
        index: u8,
        material: &[u8],
        receive: ReplaySeed,
    ) -> Result<KeyIdentity, Error> {
        let ap = self.client.setup_ap().ok_or(Error::Refused("no peer"))?;
        self.install(ap, pairwise, index, material, receive)
    }

    fn install_link_key(
        &mut self,
        link_id: u8,
        index: u8,
        material: &[u8],
        receive: ReplaySeed,
    ) -> Result<(), Error> {
        let ap = self.client.link_ap(link_id)?;
        self.install(ap, false, index, material, receive)
            .map(|_| ())
    }

    unsafe fn install_link_management_key(
        &mut self,
        link_id: u8,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<bool, Error> {
        let client = &mut self.client;
        let ap = client.link_ap(link_id)?;
        client.keep_management_key(ap, index, material, receive)?;
        Ok(true)
    }

    unsafe fn install_management_key(
        &mut self,
        _: u64,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<ManagementKey>, Error> {
        let client = &mut self.client;
        if !client.keys_settled() {
            return Err(Error::Pending);
        }
        let ap = client.setup_ap().ok_or(Error::Refused("no peer"))?;
        client.keep_management_key(ap, index, material, receive)?;
        Ok(Arc::new(ManagementKey { index }))
    }

    unsafe fn rotate_management_key(
        &mut self,
        session: &Arc<ManagementKey>,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<ManagementKey>, Error> {
        // SAFETY: forwarded from the keeper.
        let installed = unsafe { self.install_management_key(0, index, material, receive) }?;
        let client = &mut self.client;
        let ap = client.setup_ap().ok_or(Error::Refused("no peer"))?;
        client.forget_management_key(ap, session.index);
        Ok(installed)
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn authorize_port(&mut self, epoch: u64) -> Result<(), Error> {
        let client = &mut self.client;
        if !client.keys_settled() || !client.idle() {
            return Err(Error::Pending);
        }
        let context = client.context.clone().ok_or(Error::Refused("no context"))?;
        let ptk = client
            .keys
            .iter()
            .find(|key| key.pairwise)
            .ok_or(Error::Refused("no pairwise key"))?;
        let links = client
            .station
            .on_air()
            .map(|link| {
                let gtk = client
                    .keys
                    .iter()
                    .rev()
                    .find(|key| !key.pairwise && key.ap == link.ap)
                    .ok_or(Error::Refused("no group key"))?;
                Ok((&ptk.slot, &gtk.slot))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        if client.station.requires_protected_management() {
            client
                .station
                .authorize_protected_port(&context, epoch, &links)
        } else {
            client.station.authorize_port(epoch, &links)
        }
        .map_err(Error::Station)?;
        let stage = core::mem::replace(&mut self.stage, Stage::Moving);
        let Stage::Ready(mut queue) = stage else {
            self.stage = stage;
            return Err(Error::Refused("port"));
        };
        let result = self.authorized_steps(&mut queue, &context);
        self.stage = Stage::Ready(queue);
        result
    }

    fn deauthenticate(&mut self, reason: u16) -> Result<(), Error> {
        let client = &mut self.client;
        if client.leaving || client.left {
            return Ok(());
        }
        if client.station.phase() == Peering::Idle {
            client.plan = None;
            // A chain on its way up comes back down; nothing else is raised.
            client.leaving = matches!(
                self.stage,
                Stage::Phy(_)
                    | Stage::Power(_)
                    | Stage::Link(_)
                    | Stage::Peer(_)
                    | Stage::Queue(_)
                    | Stage::Coexistence(_)
                    | Stage::Ready(_)
            );
            return Ok(());
        }
        if let (Ok((local, ap)), true) = (
            client.station.addresses(),
            matches!(self.stage, Stage::Ready(_)),
        ) {
            let protected = client.station.protected_port_authorized();
            client.farewell = Some(management(
                local,
                ap,
                0xc0,
                protected,
                &reason.to_le_bytes(),
            ));
        }
        let action = client.station.disconnect().map_err(Error::Station)?;
        client.act(action);
        Ok(())
    }

    unsafe fn retire_peer(&mut self) -> Result<(), Error> {
        let client = &mut self.client;
        if let Some(ticket) = client.departing {
            client
                .station
                .complete_removal(ticket, Completion::Accepted)
                .map_err(Error::Station)?;
        }
        client.reset();
        Ok(())
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// `iwl_mvm_mld_mac_sta_state`'s ASSOC to AUTHORIZED: the beacon filter,
    /// the MAC's and station's authorized state, and rates at full width.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn authorized_steps(
        &mut self,
        queue: &mut Queue<Q, B>,
        context: &AssociationContext,
    ) -> Result<(), Error> {
        let negotiated = context.negotiated();
        let band = context.beacon().channel.band;
        let antennas = queue.antennas();
        let firmware = queue.firmware();
        let filter = if firmware.supports_api(BEACON_FILTER_V4_API) {
            60
        } else {
            44
        };
        let peer_version = firmware
            .command_version(3, 0x0a)
            .map_or(0, |version| version.command_version);
        let rate_shape = rate_shape(firmware)?;
        let explicit_mfp = firmware.supports_capability(EXPLICIT_MFP);
        let longest = if firmware.supports_capability(CHECKSUM_OFFLOAD) {
            commands::max_amsdu(negotiated)
        } else {
            0
        };
        let mac_version = version_of(firmware, commands::MAC_CONFIG);
        let seat = self.client.seat;
        let rates =
            commands::rate_config(negotiated, band, antennas, rate_shape, true, longest, seat)
                .ok_or(Error::Refused("rates"))?;
        let mac = MacState {
            address: self.address,
            he: negotiated.he.is_some(),
            eht: negotiated.eht.is_some(),
            aid: Some(context.response().aid),
            high_priority: false,
            emlsr: self.client.emlsr.transition(),
            protected_twt: protected_twt(firmware, context),
        };
        let peer =
            commands::station_config(peer_version, peer_state(context, explicit_mfp, true, seat));
        let client = &mut self.client;
        client.command(commands::BEACON_FILTER, commands::beacon_filter(filter));
        client.command(commands::MAC_CONFIG, commands::mac_config(mac_version, mac));
        client.command(commands::STATION_CONFIG, peer);
        client.steps.push_back(Step::Command {
            id: commands::RATE_CONFIG,
            bytes: rates,
            then: Then::Authorized,
        });
        Ok(())
    }
}

impl Client {
    /// The setup link's AP.
    fn setup_ap(&self) -> Option<Mac> {
        self.station.on_air().next().map(|link| link.ap)
    }

    /// The AP on the MLD association's link `link_id`.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn link_ap(&self, link_id: u8) -> Result<Mac, Error> {
        self.station
            .link_contexts()
            .iter()
            .find(|context| {
                context
                    .affiliation()
                    .is_some_and(|link| link.link_id == link_id)
            })
            .map(|context| context.bssid())
            .ok_or(Error::Refused("no such link"))
    }

    fn forget_management_key(&mut self, ap: Mac, index: u8) {
        let stations = self
            .seat_of(ap)
            .map_or_else(|| self.stations(), |seat| 1 << seat);
        let old = self
            .management_keys
            .iter()
            .position(|key| key.ap == ap && key.index == index);
        if let Some(old) = old {
            let old = self.management_keys.remove(old);
            if old.fitted {
                self.command(
                    commands::SECURITY_KEY,
                    commands::remove_key(old.index, old.flags, stations),
                );
            }
        }
    }

    /// An IGTK of the link of `ap`, which firmware takes while that link is
    /// active.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn keep_management_key(
        &mut self,
        ap: Mac,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<(), Error> {
        let flags = commands::management_key_flags(
            self.management_cipher
                .ok_or(Error::Refused("no management cipher"))?,
        );
        let seat = self.seat_of(ap);
        let fitted = seat.is_some();
        self.forget_management_key(ap, index);
        if let Some(seat) = seat {
            let bytes = commands::add_key(index, flags, material, receive.value(), 1 << seat)
                .ok_or(Error::Refused("key material"))?;
            self.command(commands::SECURITY_KEY, bytes);
        }
        self.management_keys.push(LinkIntegrity {
            ap,
            index,
            flags,
            material: Zeroizing::new(material.to_vec()),
            receive: receive.value(),
            fitted,
        });
        Ok(())
    }

    fn port_ready(&self) -> bool {
        self.context.is_some()
    }

    /// A step of the station's Block Ack agreements.
    fn block_ack(&mut self, action: ba::Action) {
        match action {
            ba::Action::Program {
                ticket,
                session,
                enable,
            } => self.steps.push_back(Step::BlockAck(Agreement {
                ticket,
                session,
                enable,
            })),
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
                if let Some(id) = self.reception.session(session.tid()) {
                    self.release(id, Some(session.tid()), start_sequence);
                }
            }
            // The firmware runs transmit agreements itself, as
            // `TX_AMPDU_SETUP_IN_HW` tells mac80211.
            ba::Action::Tx(_) | ba::Action::None => {}
        }
    }

    fn release(&mut self, id: u8, tid: Option<u8>, through: u16) {
        let mut ready = Vec::new();
        self.reception.release(id, tid, through, &mut ready);
        self.deliver_all(ready);
    }

    /// `frame`, one fragment; the station has the MSDU with the last of them.
    fn reassemble(&mut self, frame: &Mpdu, now: u64) {
        let key = frame.security.key;
        let slot = self
            .keys
            .iter_mut()
            .map(|key| &mut key.slot)
            .find(|slot| key.is_some() && slot.installed() == key);
        if let Some(whole) = self.fragments.add(frame, slot, now) {
            self.deliver(Parent {
                members: alloc::vec![whole],
                shape: Shape::WholeMpdu,
            });
        }
    }

    fn deliver_all(&mut self, ready: Vec<Parent>) {
        for parent in ready {
            self.deliver(parent);
        }
    }

    /// `parent`, its turn come, to the station. mac80211 drops what its
    /// replay and port checks refuse.
    fn deliver(&mut self, parent: Parent) {
        let Parent { members, shape } = parent;
        let ingress = if shape == Shape::WholeMpdu && !members[0].header().amsdu {
            let Some(epoch) = self.station.association_epoch() else {
                return;
            };
            let mut keys: Vec<&mut KeySlot> =
                self.keys.iter_mut().map(|key| &mut key.slot).collect();
            match self
                .station
                .receive_msdu_refs(epoch, &members[0], &mut keys)
            {
                Ok(ingress) => alloc::vec![ingress],
                Err(_) => return,
            }
        } else {
            let Some(context) = self.context.clone() else {
                return;
            };
            let key = members[0].security.key;
            // SAFETY: `Reception` gathered every record of this MPDU in the
            // order the receive queue gave them and after any reorder release.
            // `depart` and `reset` drop what they hold for an older association.
            let group = unsafe { OrderedGroup::new(context, members, shape, ()) };
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
}

/// The regulatory flags of the firmware's channel restrictions:
/// `ieee80211_determine_chan_mode` reads them, and a probe needs `NO_IR` clear.
pub fn channel_flags(restrictions: &crate::wifi::intel::mcc::channel::Restrictions) -> u32 {
    let mut flags = 0;
    if restrictions.no_ht40_plus {
        flags |= NO_HT40PLUS;
    }
    if restrictions.no_ht40_minus {
        flags |= NO_HT40MINUS;
    }
    if restrictions.no_80mhz {
        flags |= NO_80MHZ;
    }
    if restrictions.no_160mhz {
        flags |= NO_160MHZ;
    }
    if restrictions.no_320mhz {
        flags |= NO_320MHZ;
    }
    if restrictions.no_he {
        flags |= NO_HE;
    }
    if restrictions.no_eht {
        flags |= NO_EHT;
    }
    if restrictions.no_initiate_radiation {
        flags |= NO_IR;
    }
    if restrictions.no_6ghz_vlp_client {
        flags |= NO_6GHZ_VLP_CLIENT;
    }
    if restrictions.no_6ghz_afc_client {
        flags |= NO_6GHZ_AFC_CLIENT;
    }
    flags
}
