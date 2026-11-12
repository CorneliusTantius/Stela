// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
//! The station against a model of the chip, which plays the AP over the frames
//! it is handed.
use super::*;
use crate::wifi::connection::security::Security;
use crate::wifi::intel::policy::tests::regdb;
use crate::wifi::network::{Network, Secret};
use crate::wifi::supplicant::tests::Authenticator;
use alloc::{rc::Rc, vec};
use core::cell::RefCell;
use core::sync::atomic::{AtomicU8, Ordering};
use stela_driver_base::entropy::EntropyError;

const CLOCK: Clock = Clock {
    ticks_per_microsecond: 1,
};
const LOCAL: [u8; 6] = [2, 0x12, 0x34, 0x56, 0x78, 0x9a];
const AP: [u8; 6] = [2, 3, 4, 5, 6, 7];
const RSN: [u8; 22] = [
    48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0,
];
/// An AP's HT capabilities and operation on channel 1, one stream at 20 MHz.
const HT: [u8; 52] = [
    45, 26, 0x2c, 1, 0x17, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    61, 22, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// A WMM parameter element: best effort at the defaults of each class.
const WMM: [u8; 26] = [
    221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 0x5e, 0,
    0x62, 0x32, 0x2f, 0,
];
const SSID: &[u8] = b"test";

/// Each read one byte over the last, from 0x5a.
#[derive(Default)]
struct FixedEntropy(AtomicU8);

impl Entropy for FixedEntropy {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), EntropyError> {
        bytes.fill(0x5a + self.0.fetch_add(1, Ordering::Relaxed));
        Ok(())
    }
}

/// What the hardware was told, and what it holds for the host.
#[derive(Default)]
struct Air {
    /// The AP's channel, on which each visit hears a beacon.
    channel: u16,
    /// Each channel tuned, with whether a scan tuned it.
    tuned: Vec<(u16, bool)>,
    sent: Vec<(Queue, Packet, Vec<u8>)>,
    /// How many of `sent` the AP has answered.
    answered: usize,
    probed: Vec<u16>,
    incoming: VecDeque<Incoming>,
    commands: Vec<(u32, u32)>,
    prepared: usize,
    ports: Vec<(Mac, u16, bool)>,
    beacon_filters: Vec<bool>,
    edca: Vec<([AccessCategory; 4], bool)>,
    /// Each CAM write: entry, key index, type, group and material.
    keys: Vec<(u8, u8, u8, bool, [u8; 16])>,
    cleared: Vec<u8>,
    /// Queues refuse frames while set.
    full: bool,
    /// Each watchdog run's STBC, and the level it gives.
    watchdogs: Vec<bool>,
    level: u8,
    scans: Vec<bool>,
    /// Management frames lost to the air before the AP hears them.
    losses: usize,
    /// Each power save request, and the pages each association gave firmware.
    sleeps: Vec<bool>,
    templates: Vec<templates::Templates>,
    /// A watchdog run finds too many frames for power save.
    busy: bool,
    /// What Bluetooth changes of the stream count.
    stream_changes: Vec<bool>,
    /// The AP stopped beaconing on its channel.
    quiet: bool,
    /// The AP takes no frame at all.
    gone: bool,
    /// The AP's beacons keep its name to themselves.
    hidden: bool,
    /// The AP's group traffic goes under TKIP.
    tkip: bool,
    /// The SSID of each probe.
    probe_names: Vec<Vec<u8>>,
    /// The device quarantined itself, and each look for frames since.
    lost: bool,
    looks: usize,
}

impl Air {
    fn hear(&mut self, bytes: Vec<u8>, decrypted: bool) {
        self.incoming.push_back(Incoming::Frame(Received {
            bytes,
            tsf: 0,
            decrypted,
            icv_error: false,
            signal_dbm: Some(-40),
        }));
    }

    /// The AP's reply to each frame it has not seen, and each frame's report.
    fn serve(&mut self) {
        while let Some((_, packet, bytes)) = self.sent.get(self.answered).cloned() {
            self.answered += 1;
            let lost = bytes[0] & 0x0c == 0 && packet.report.is_some() && self.losses > 0;
            if let Some(number) = packet.report {
                self.incoming
                    .push_back(Incoming::Report(Report::Transmitted {
                        number,
                        acknowledged: !lost && !self.gone,
                    }));
            }
            if lost {
                self.losses -= 1;
                continue;
            }
            match bytes[0] {
                0x40 => {
                    let name = bytes[26..26 + usize::from(bytes[25])].to_vec();
                    self.probed.extend(self.tuned.last().map(|tuned| tuned.0));
                    let here = self.tuned.last().is_some_and(|t| t.0 == self.channel);
                    if self.hidden && here && name == SSID {
                        let mut response = advertised(self, self.channel as u8);
                        response[0] = 0x50;
                        response[4..10].copy_from_slice(&LOCAL);
                        self.hear(response, false);
                    }
                    self.probe_names.push(name);
                }
                0xb0 => self.hear(management(0xb0, &[0, 0, 2, 0, 0, 0]), false),
                0x00 => {
                    let mut body = vec![0x11, 0, 0, 0, 1, 0xc0];
                    body.extend(rates(self.channel));
                    if self.channel < 14 {
                        body.extend(HT);
                        body.extend(WMM);
                    }
                    self.hear(management(0x10, &body), false);
                }
                _ => {}
            }
        }
    }
}

#[derive(Clone)]
struct Model(Rc<RefCell<Air>>);

impl Device for Model {
    fn tune(
        &mut self,
        definition: &ChannelDefinition,
        scanning: bool,
        eirp_mbm: i32,
    ) -> Result<(), String> {
        let mut air = self.0.borrow_mut();
        let number = definition.control.number;
        assert_eq!(eirp_mbm, 2000);
        air.tuned.push((number, scanning));
        if scanning && number == air.channel {
            let mut heard = advertised(&air, number as u8);
            if air.hidden {
                heard.drain(38..38 + SSID.len());
                heard[37] = 0;
            }
            air.hear(heard, false);
        }
        Ok(())
    }
    fn prepare_transmit(&mut self) -> Result<(), String> {
        self.0.borrow_mut().prepared += 1;
        Ok(())
    }
    fn transmit(&mut self, queue: Queue, packet: &Packet, mpdu: &[u8]) -> Result<bool, String> {
        let mut air = self.0.borrow_mut();
        if air.full {
            return Ok(false);
        }
        air.sent.push((queue, *packet, mpdu.to_vec()));
        Ok(true)
    }
    fn receive(&mut self, sink: &mut dyn FnMut(Incoming)) -> Result<(), String> {
        let mut air = self.0.borrow_mut();
        air.looks += 1;
        if air.lost {
            return Err(String::from("receive ring: Quarantined"));
        }
        if !air.quiet && air.tuned.last() == Some(&(air.channel, false)) {
            let beacon = advertised(&air, air.channel as u8);
            air.hear(beacon, false);
        }
        air.incoming.drain(..).for_each(sink);
        Ok(())
    }
    fn command(&mut self, command: (u32, u32)) -> Result<(), String> {
        self.0.borrow_mut().commands.push(command);
        Ok(())
    }
    fn set_port(&mut self, bssid: Mac, aid: u16, linked: bool) -> Result<(), String> {
        self.0.borrow_mut().ports.push((bssid, aid, linked));
        Ok(())
    }
    fn filter_beacons(&mut self, own_only: bool) -> Result<(), String> {
        self.0.borrow_mut().beacon_filters.push(own_only);
        Ok(())
    }
    fn set_edca(&mut self, edca: &[AccessCategory; 4], short_slot: bool) -> Result<(), String> {
        self.0.borrow_mut().edca.push((*edca, short_slot));
        Ok(())
    }
    fn write_key(&mut self, key: &CamKey<'_>) -> Result<(), String> {
        self.0
            .borrow_mut()
            .keys
            .push((key.entry, key.index, key.kind, key.group, *key.material));
        Ok(())
    }
    fn clear_key(&mut self, entry: u8) -> Result<(), String> {
        self.0.borrow_mut().cleared.push(entry);
        Ok(())
    }
    fn stream_change(&mut self) -> Option<bool> {
        self.0.borrow_mut().stream_changes.pop()
    }
    fn set_templates(&mut self, templates: &templates::Templates) -> Result<(), String> {
        self.0.borrow_mut().templates.push(templates.clone());
        Ok(())
    }
    fn set_power_save(&mut self, on: bool) -> Result<(), String> {
        let mut air = self.0.borrow_mut();
        if air.sleeps.last().copied().unwrap_or(false) != on {
            air.sleeps.push(on);
        }
        Ok(())
    }
    fn watchdog(&mut self, scanning: bool, stbc: bool) -> Result<Watched, String> {
        let mut air = self.0.borrow_mut();
        if !scanning {
            air.watchdogs.push(stbc);
        }
        Ok(Watched {
            level: air.level,
            busy: air.busy,
        })
    }
    fn scanning(&mut self, scanning: bool) -> Result<(), String> {
        self.0.borrow_mut().scans.push(scanning);
        Ok(())
    }
    fn lost(&self) -> bool {
        self.0.borrow().lost
    }
}

/// The AP's rates on `channel`: 1 and 6 Mb/s, or 6 and 9.
fn rates(channel: u16) -> [u8; 4] {
    if channel < 14 {
        [1, 2, 0x82, 0x0c]
    } else {
        [1, 2, 0x8c, 0x12]
    }
}

/// An AP's management frame to the station.
fn management(subtype: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[0] = subtype;
    frame[4..10].copy_from_slice(&LOCAL);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend(body);
    frame
}

/// The AP's beacon on `channel`.
fn beacon(channel: u8) -> Vec<u8> {
    let mut frame = vec![0; 36];
    frame[0] = 0x80;
    frame[4..10].fill(0xff);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[32..34].copy_from_slice(&100u16.to_le_bytes());
    frame[34] = 0x11;
    frame.extend([0, SSID.len() as u8]);
    frame.extend(SSID);
    frame.extend(rates(u16::from(channel)));
    frame.extend([3, 1, channel, 5, 4, 0, 2, 0, 0]);
    frame.extend(RSN);
    frame.extend(HT);
    // HT Operation's primary channel.
    let at = frame.len() - 22;
    frame[at] = channel;
    frame.extend(WMM);
    frame
}

/// `rsn` as an AP under TKIP for its group traffic sends it.
fn tkip_rsn() -> [u8; 22] {
    let mut rsn = RSN;
    rsn[7] = 2;
    rsn
}

/// What the model's AP beacons on `channel`.
fn advertised(air: &Air, channel: u8) -> Vec<u8> {
    let mut frame = beacon(channel);
    if air.tkip {
        let at = frame.windows(RSN.len()).position(|w| w == RSN).unwrap();
        frame[at..at + RSN.len()].copy_from_slice(&tkip_rsn());
    }
    frame
}

/// A data frame from the AP to `receiver`, with `key` its index and packet
/// number.
fn data(
    receiver: [u8; 6],
    sequence: u16,
    kind: [u8; 2],
    body: &[u8],
    key: Option<(u8, u8)>,
) -> Vec<u8> {
    let mut frame = vec![0; 26];
    frame[0] = 0x88;
    frame[1] = if key.is_some() { 0x42 } else { 0x02 };
    frame[4..10].copy_from_slice(&receiver);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    if let Some((index, number)) = key {
        frame.extend([number, 0, 0, 0x20 | index << 6, 0, 0, 0, 0]);
    }
    frame.extend([0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend(kind);
    frame.extend(body);
    if key.is_some() {
        frame.extend([0; 8]);
    }
    frame
}

/// What the station sent past `frame`'s header, IV and LLC when it is EAPOL.
fn eapol(frame: &[u8]) -> Option<&[u8]> {
    if frame[0] & 0x0c != 8 {
        return None;
    }
    let header = if frame[0] & 0x80 != 0 { 26 } else { 24 };
    let header = header + if frame[1] & 0x40 != 0 { 8 } else { 0 };
    (frame.get(header + 6..header + 8)? == [0x88, 0x8e]).then(|| &frame[header + 8..])
}

fn wifi(rules: &[(u32, u32, u8, u16)], channel: u16) -> (Wifi<Model>, Model) {
    core::mem::forget(crate::test_clock::virtualize());
    let database = regdb(&[(*b"US", rules)]);
    let model = Model(Rc::new(RefCell::new(Air {
        channel,
        ..Air::default()
    })));
    let country = database.select(*b"US").unwrap();
    let network = Network {
        ssid: SSID.to_vec(),
        secret: Secret::Psk(Zeroizing::new([0; 32])),
        country: None,
    };
    let radio = Rtl8822c::new(model.clone(), Mac(LOCAL), country, CLOCK).unwrap();
    (
        radio.keep(network, Arc::new(FixedEntropy::default())),
        model,
    )
}

/// Serve the air until `done`, with five milliseconds passing each round.
fn run(
    wifi: &mut Wifi<Model>,
    model: &Model,
    mut done: impl FnMut(&mut Wifi<Model>, &Air) -> bool,
) -> bool {
    for _ in 0..4000 {
        wifi.carrier();
        model.0.borrow_mut().serve();
        if done(wifi, &model.0.borrow()) {
            return true;
        }
        crate::test_clock::advance(CLOCK, 5_000);
    }
    false
}

const OPEN: [(u32, u32, u8, u16); 1] = [(2_402_000, 2_472_000, 0, 2000)];

/// Join the model's AP on channel 1 through its handshake to an open port.
fn connected() -> (Wifi<Model>, Model) {
    connected_on(&OPEN, 1)
}

/// Join the model's AP on `channel` through its handshake to an open port.
fn connected_on(rules: &[(u32, u32, u8, u16)], channel: u16) -> (Wifi<Model>, Model) {
    connected_under(rules, channel, RSN)
}

/// [`connected_on`], with the AP offering `rsn`.
fn connected_under(
    rules: &[(u32, u32, u8, u16)],
    channel: u16,
    rsn: [u8; 22],
) -> (Wifi<Model>, Model) {
    let (mut wifi, model) = wifi(rules, channel);
    model.0.borrow_mut().tkip = rsn != RSN;
    assert!(run(&mut wifi, &model, |wifi, _| {
        wifi.radio().station().phase() == Peering::Associated
    }));
    let security = Security::select(&rsn, true).unwrap();
    let mut ap = Authenticator::between(
        security.suites(),
        Zeroizing::new([0; 32]),
        Mac(AP),
        Mac(LOCAL),
        security.element(),
    );
    let answers = |air: &Air| {
        air.sent
            .iter()
            .filter_map(|(_, _, bytes)| eapol(bytes).map(<[u8]>::to_vec))
            .collect::<Vec<_>>()
    };
    let frame = data(LOCAL, 0, [0x88, 0x8e], &ap.message_1(), None);
    model.0.borrow_mut().hear(frame, false);
    assert!(run(&mut wifi, &model, |_, air| !answers(air).is_empty()));
    ap.message_2(&answers(&model.0.borrow())[0]);
    let frame = data(LOCAL, 1, [0x88, 0x8e], &ap.message_3(&rsn), None);
    model.0.borrow_mut().hear(frame, false);
    assert!(run(&mut wifi, &model, |_, air| answers(air).len() > 1));
    assert!(wifi.carrier());
    ap.signed_reply(&answers(&model.0.borrow())[1], 0x308);
    (wifi, model)
}

/// An IPv4 frame to the AP under `tos`.
fn ip(tos: u8) -> Vec<u8> {
    let mut ethernet = vec![0; 14];
    ethernet[..6].copy_from_slice(&AP);
    ethernet[6..12].copy_from_slice(&LOCAL);
    ethernet[12..14].copy_from_slice(&[8, 0]);
    ethernet.extend([0x45, tos]);
    ethernet.extend([0; 44]);
    ethernet
}

/// The Block Ack actions of `kind` the station sent.
fn actions(air: &Air, kind: u8) -> Vec<&[u8]> {
    let action =
        |sent: &&(Queue, Packet, Vec<u8>)| sent.2[0] == 0xd0 && sent.2[24..26] == [3, kind];
    let frames = air.sent.iter().filter(action);
    frames.map(|sent| &sent.2[26..]).collect()
}

/// The dialog and starting sequence of each ADDBA request sent.
fn requests(air: &Air) -> Vec<(u8, u16)> {
    let request = |body: &[u8]| (body[0], u16::from_le_bytes([body[5], body[6]]) >> 4);
    actions(air, 0).into_iter().map(request).collect()
}

/// The AP's ADDBA response to `dialog` for TID 0, with `status`.
fn response(dialog: u8, status: u16) -> Vec<u8> {
    let mut body = vec![3, 1, dialog];
    body.extend(status.to_le_bytes());
    body.extend((3u16 | 64 << 6).to_le_bytes());
    body.extend([0, 0]);
    management(0xd0, &body)
}

/// The packets of best-effort data sent.
fn best_effort(air: &Air) -> Vec<Packet> {
    let data = |sent: &&(Queue, Packet, Vec<u8>)| sent.0 == Queue::BestEffort;
    air.sent.iter().filter(data).map(|sent| sent.1).collect()
}

/// `connected`, with a frame sent singly and an ADDBA request out for TID 0.
fn asking() -> (Wifi<Model>, Model, u8) {
    let (mut wifi, model) = connected();
    wifi.transmit(&ip(0)).unwrap();
    assert!(run(&mut wifi, &model, |_, air| !requests(air).is_empty()));
    let dialog = requests(&model.0.borrow())[0].0;
    (wifi, model, dialog)
}

/// What the station holds for the network, as each frame's first payload byte.
fn delivered(wifi: &mut Wifi<Model>) -> Vec<u8> {
    let mut values = Vec::new();
    while let Some(ethernet) = wifi.receive().unwrap() {
        values.push(ethernet[14]);
    }
    values
}

#[test]
fn a_scan_probes_where_it_may_and_only_listens_where_it_may_not() {
    let rules = [
        (2_402_000, 2_472_000, 0, 2000),
        // NL80211_RRF_NO_IR, as regdb writes it.
        (5_170_000, 5_250_000, 8, 2000),
    ];
    let (mut wifi, model) = wifi(&rules, 36);
    assert!(run(&mut wifi, &model, |wifi, _| {
        wifi.radio().station().phase() == Peering::Associated
    }));
    let air = model.0.borrow();
    assert!(air.probed.contains(&1) && air.probed.contains(&11));
    assert!(!air.probed.contains(&36) && !air.probed.contains(&48));
    assert!(air.tuned.contains(&(36, true)) && air.tuned.contains(&(48, true)));
    assert_eq!(air.tuned.last(), Some(&(36, false)));
    assert_eq!(air.beacon_filters.first(), Some(&false));
}

#[test]
fn a_network_no_scan_found_is_asked_for_by_name() {
    let (mut wifi, model) = wifi(&OPEN, 1);
    model.0.borrow_mut().hidden = true;
    assert!(run(&mut wifi, &model, |wifi, _| {
        wifi.radio().station().phase() == Peering::Associated
    }));
    let air = model.0.borrow();
    let first_named = air
        .probe_names
        .iter()
        .position(|name| name == SSID)
        .unwrap();
    assert!(first_named > 0, "the first scan keeps the name to itself");
    assert!(air.probe_names[..first_named].iter().all(Vec::is_empty));
}

#[test]
fn a_network_in_plain_sight_is_never_named() {
    let (_, model) = connected();
    let air = model.0.borrow();
    assert!(air.probe_names.iter().all(Vec::is_empty));
}

/// A connection whose group key is the test authenticator's TKIP key.
fn tkip_group() -> (Wifi<Model>, Model) {
    connected_under(&OPEN, 1, tkip_rsn())
}

/// A broadcast TKIP frame from the AP with `mic` behind `body`.
fn tkip_frame(body: &[u8], mic: [u8; 8]) -> Vec<u8> {
    let mut frame = data([0xff; 6], 9, [8, 0], body, Some((1, 1)));
    frame.truncate(frame.len() - 8);
    frame.extend(mic);
    frame.extend([0; 4]);
    frame
}

/// What Michael gives the LLC and `body` of [`tkip_frame`].
fn tkip_mic(body: &[u8]) -> [u8; 8] {
    let mut msdu = vec![0xaa, 0xaa, 3, 0, 0, 0, 8, 0];
    msdu.extend(body);
    // The key's second half, which the AP signs with.
    let key = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67];
    michael::michael(&key, &[0xff; 6], &AP, 0, &msdu)
}

#[test]
fn a_tkip_group_key_reaches_the_cam_by_its_temporal_half() {
    let (_, model) = tkip_group();
    let air = model.0.borrow();
    let tkip = air.keys.iter().find(|key| key.2 == CAM_TKIP).unwrap();
    assert_eq!((tkip.1, tkip.3), (1, true));
    assert_eq!(tkip.4[..], (0x50..0x60).collect::<Vec<u8>>());
}

#[test]
fn a_tkip_frame_passes_on_its_michael() {
    let (mut wifi, model) = tkip_group();
    let body = [0x45, 0, 0, 20];
    model
        .0
        .borrow_mut()
        .hear(tkip_frame(&body, tkip_mic(&body)), true);
    wifi.carrier();
    let ethernet = wifi.receive().unwrap().unwrap();
    assert_eq!(ethernet[..6], [0xff; 6]);
    assert_eq!(ethernet[14..], body);
}

#[test]
fn a_failed_michael_is_dropped_and_told_to_the_ap() {
    let (mut wifi, model) = tkip_group();
    let before = model.0.borrow().sent.len();
    let body = [0x45, 0, 0, 20];
    model.0.borrow_mut().hear(tkip_frame(&body, [0; 8]), true);
    assert!(run(&mut wifi, &model, |_, air| air.sent.len() > before));
    assert!(wifi.receive().unwrap().is_none());
    let air = model.0.borrow();
    assert!(
        air.sent[before..]
            .iter()
            .any(|(_, _, bytes)| eapol(bytes).is_some())
    );
}

#[test]
fn a_scan_gives_the_gain_up_and_back() {
    let (mut wifi, model) = wifi(&OPEN, 1);
    assert!(run(&mut wifi, &model, |_, air| air.scans.len() == 2));
    assert_eq!(model.0.borrow().scans, [true, false]);
}

#[test]
fn the_watchdog_runs_every_two_seconds_and_refreshes_rates_on_each_fourth() {
    let (mut wifi, model) = connected();
    model.0.borrow_mut().watchdogs.clear();
    model.0.borrow_mut().level = 5;
    let context = wifi.radio().context.clone().unwrap();
    let refresh = commands::ra_info(rate_info(&context, context.negotiated().width, false, 5));
    assert_eq!(refresh.0 & (1 << 27), 1 << 27);
    assert_eq!(refresh.1 & 0xff, 0);
    for _ in 0..8 {
        crate::test_clock::advance(CLOCK, WATCHDOG_US);
        wifi.carrier();
    }
    let air = model.0.borrow();
    assert_eq!(air.watchdogs, [peer_stbc(&context); 8]);
    assert_eq!(
        air.commands.iter().filter(|&&sent| sent == refresh).count(),
        2
    );
}

#[test]
fn a_join_programs_the_port_and_the_handshake_fills_the_cam() {
    let (_, model) = connected();
    let air = model.0.borrow();
    assert_eq!(air.ports, [(Mac(AP), 0, false), (Mac(AP), 1, true)]);
    assert_eq!(air.prepared, 2);
    assert!(air.commands.contains(&commands::media_status(0, true)));
    assert!(air.commands.contains(&commands::default_port(0, 0)));
    // The AP's best effort: AIFSN 3, ECW 4 to 10, on a 2.4 GHz long slot.
    let (edca, short_slot) = air.edca[0];
    assert_eq!(
        (edca[0].aifsn, edca[0].ecw_min, edca[0].ecw_max),
        (3, 4, 10)
    );
    assert!(!short_slot);
    // The GTK sits at its index, the PTK past the default keys.
    let cam: Vec<_> = air.keys.iter().map(|key| key.0).collect();
    assert_eq!(cam.len(), 2);
    assert!(cam.contains(&PAIRWISE_CAM) && cam.contains(&1));
    assert!(air.keys.iter().all(|key| key.2 == CAM_AES));
    assert!(
        air.keys
            .iter()
            .any(|key| key.3 && key.0 == 1 && key.4[0] == 0x50)
    );
}

#[test]
fn a_lost_authentication_goes_again() {
    let (mut wifi, model) = self::wifi(&OPEN, 1);
    model.0.borrow_mut().losses = 1;
    assert!(run(&mut wifi, &model, |wifi, _| {
        wifi.radio().station().phase() == Peering::Associated
    }));
    let air = model.0.borrow();
    let tries = air.sent.iter().filter(|sent| sent.2[0] == 0xb0).count();
    assert_eq!(tries, 2);
}

/// Two frames of data that waited for the rings on 5 GHz, as sent.
fn waited_on_five_ghz(before_sending: impl FnOnce(&mut Air)) -> Vec<Vec<u8>> {
    let rules = [(5_170_000, 5_250_000, 0, 2000)];
    let (mut wifi, model) = connected_on(&rules, 36);
    let before = model.0.borrow().sent.len();
    before_sending(&mut model.0.borrow_mut());
    wifi.carrier();
    model.0.borrow_mut().full = true;
    let ethernet = ip(0xc0);
    wifi.transmit(&ethernet).unwrap();
    wifi.transmit(&ethernet).unwrap();
    wifi.carrier();
    model.0.borrow_mut().full = false;
    run(&mut wifi, &model, |_, air| air.sent.len() > before);
    for _ in 0..4 {
        wifi.carrier();
    }
    let air = model.0.borrow();
    let sent = air.sent[before..].iter();
    sent.map(|(_, _, mpdu)| mpdu.clone()).collect()
}

#[test]
fn data_waiting_together_on_five_ghz_leaves_as_one_amsdu() {
    let sent = waited_on_five_ghz(|_| ());
    let [mpdu] = &sent[..] else {
        panic!("{} frames", sent.len());
    };
    assert_eq!(mpdu[24] & 0x80, 0x80);
    assert_eq!(mpdu[26 + 3] & 0x20, 0x20, "under the head's IV");
    assert_eq!(
        mpdu[26 + 8 + 12..26 + 8 + 14],
        [0, 54],
        "LLC and the IP frame"
    );
}

#[test]
fn a_slow_rate_keeps_frames_apart() {
    let sent = waited_on_five_ghz(|air| {
        air.incoming.push_back(Incoming::Report(Report::Rate {
            mac_id: MAC_ID,
            rate: 4,
            short_gi: false,
            width: None,
        }));
    });
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|mpdu| mpdu[24] & 0x80 == 0));
}

#[test]
fn data_leaves_with_its_packet_number_and_waits_out_a_full_queue() {
    let (mut wifi, model) = connected();
    let before = model.0.borrow().sent.len();
    model.0.borrow_mut().full = true;
    let ethernet = ip(0xc0);
    wifi.transmit(&ethernet).unwrap();
    wifi.transmit(&ethernet).unwrap();
    wifi.carrier();
    assert_eq!(model.0.borrow().sent.len(), before);
    model.0.borrow_mut().full = false;
    assert!(run(&mut wifi, &model, |_, air| air.sent.len() == before + 2));
    let air = model.0.borrow();
    let (first, second) = (&air.sent[before], &air.sent[before + 1]);
    for (queue, packet, mpdu) in [first, second] {
        assert_eq!(*queue, Queue::Voice);
        assert_eq!(packet.security, SECURITY_CCMP);
        assert_eq!(usize::from(packet.size), mpdu.len());
        assert_ne!(mpdu[1] & 0x40, 0);
        assert_eq!(mpdu[26 + 3] & 0x20, 0x20);
    }
    assert_eq!(first.2[26] + 1, second.2[26]);
    assert_eq!(first.1.sequence + 1, second.1.sequence);
}

#[test]
fn received_data_passes_its_replay_and_integrity_checks() {
    let (mut wifi, model) = connected();
    let body = [0x45; 46];
    let frame = |sequence, key| data(LOCAL, sequence, [8, 0], &body, Some(key));
    model.0.borrow_mut().hear(frame(10, (0, 1)), true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), [0x45]);
    // Replayed, and then failing the hardware's integrity check.
    model.0.borrow_mut().hear(frame(10, (0, 1)), true);
    model
        .0
        .borrow_mut()
        .incoming
        .push_back(Incoming::Frame(Received {
            bytes: frame(11, (0, 2)),
            tsf: 0,
            decrypted: true,
            icv_error: true,
            signal_dbm: None,
        }));
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), []);
    // A group frame under the key the handshake gave.
    let group = data([0xff; 6], 12, [8, 0], &body, Some((1, 200)));
    model.0.borrow_mut().hear(group, true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), [0x45]);
}

#[test]
fn a_refused_frame_between_good_ones_is_dropped_and_counted_and_the_rest_arrive() {
    let (mut wifi, model) = connected();
    let body = [0x45; 46];
    let frame = |sequence, key| data(LOCAL, sequence, [8, 0], &body, Some(key));
    let before = wifi.radio().dropped();
    {
        let mut air = model.0.borrow_mut();
        air.hear(frame(20, (0, 1)), true);
        // Too short for any 802.11 header, and a version mac80211 drops.
        air.hear(vec![0x88, 0x02, 0], false);
        let mut version = frame(21, (0, 2));
        version[0] |= 1;
        air.hear(version, true);
        // An authentication frame the associated station has no use for.
        air.hear(management(0xb0, &[0, 0, 9, 0, 1, 0]), false);
        air.hear(frame(22, (0, 3)), true);
    }
    // One look takes all of them: the link reports no error, and both good
    // frames reach the network.
    let mut values = Vec::new();
    for _ in 0..2 {
        while let Some(ethernet) = wifi.receive().expect("a refused frame is no link error") {
            values.push(ethernet[14]);
        }
    }
    assert_eq!(values, [0x45, 0x45]);
    assert!(wifi.radio().dropped() > before);
    assert!(wifi.carrier());
}

#[test]
fn a_quarantined_device_is_reported_once_and_the_keeper_stops() {
    let (mut wifi, model) = connected();
    model.0.borrow_mut().lost = true;
    let error = wifi.receive().expect_err("the link is gone");
    assert!(matches!(&error, LinkError::Adapter(reason) if reason.contains("Quarantined")));
    let looks = model.0.borrow().looks;
    assert!(!wifi.carrier());
    assert_eq!(wifi.receive(), Err(error.clone()));
    assert_eq!(wifi.transmit(&[0; 60]), Err(error));
    assert_eq!(
        model.0.borrow().looks,
        looks,
        "nothing reaches the device again"
    );
    let notices = core::iter::from_fn(|| wifi.take_diagnostic()).collect::<Vec<_>>();
    assert_eq!(
        notices
            .iter()
            .filter(|notice| notice.contains("Quarantined"))
            .count(),
        1
    );
}

/// Fragment `number` of frame `sequence` under the pairwise key at packet
/// number `pn`, with `more` to follow.
fn fragment(sequence: u16, number: u8, more: bool, pn: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = data(LOCAL, sequence, [8, 0], &[], Some((0, pn)));
    frame.truncate(34);
    frame.extend_from_slice(payload);
    frame.extend([0; 8]);
    frame[1] |= u8::from(more) << 2;
    frame[22] |= number;
    frame
}

#[test]
fn fragments_under_consecutive_numbers_make_one_frame() {
    let (mut wifi, model) = connected();
    let first = [&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0][..], &[0x45; 4]].concat();
    model
        .0
        .borrow_mut()
        .hear(fragment(30, 0, true, 1, &first), true);
    model
        .0
        .borrow_mut()
        .hear(fragment(30, 1, false, 2, &[0x46; 4]), true);
    wifi.carrier();
    let ethernet = wifi.receive().unwrap().unwrap();
    assert_eq!(
        ethernet[14..],
        [0x45, 0x45, 0x45, 0x45, 0x46, 0x46, 0x46, 0x46]
    );
    assert_eq!(wifi.receive().unwrap(), None);
}

#[test]
fn fragments_that_skip_a_number_are_dropped() {
    let (mut wifi, model) = connected();
    let first = [&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0][..], &[0x45; 4]].concat();
    model
        .0
        .borrow_mut()
        .hear(fragment(31, 0, true, 5, &first), true);
    model
        .0
        .borrow_mut()
        .hear(fragment(31, 1, false, 7, &[0x46; 4]), true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), []);
}

/// An SA Query request at packet number `number`, opened as hardware leaves
/// it, its MIC in place.
fn sa_query(number: u8) -> Vec<u8> {
    let mut frame = management(0xd0, &[number, 0, 0, 0x20, 0, 0, 0, 0, 8, 0, 1, 2]);
    frame[1] = 0x40;
    frame.extend([0; 8]);
    frame
}

/// How many SA Query answers the station sent.
fn query_answers(air: &Air) -> usize {
    air.sent.iter().filter(|sent| sent.2[0] == 0xd0).count()
}

#[test]
fn a_protected_management_frame_is_taken_once_under_its_packet_number() {
    let (mut wifi, model) = connected();
    model.0.borrow_mut().hear(sa_query(5), true);
    assert!(run(&mut wifi, &model, |_, air| query_answers(air) == 1));
    model.0.borrow_mut().hear(sa_query(5), true);
    assert!(!run(&mut wifi, &model, |_, air| query_answers(air) > 1));
    model.0.borrow_mut().hear(sa_query(6), true);
    assert!(run(&mut wifi, &model, |_, air| query_answers(air) == 2));
}

#[test]
fn a_protected_management_frame_hardware_left_sealed_opens_under_the_key() {
    let (mut wifi, model) = connected();
    let key = model.0.borrow().keys.iter().find(|key| !key.3).unwrap().4;
    let sealed = |key: &[u8; 16], number: u8| {
        let frame = sa_query(number);
        let iv: &[u8; 8] = frame[24..32].try_into().unwrap();
        let pn = PacketNumber::new(number.into()).unwrap();
        ccmp::seal(key, &frame[..24], iv, pn, &frame[32..36])
    };
    model.0.borrow_mut().hear(sealed(&[0; 16], 5), false);
    assert!(!run(&mut wifi, &model, |_, air| query_answers(air) > 0));
    model.0.borrow_mut().hear(sealed(&key, 5), false);
    assert!(run(&mut wifi, &model, |_, air| query_answers(air) == 1));
}

#[test]
fn an_a_msdu_gives_up_each_of_its_frames() {
    let (mut wifi, model) = connected();
    let mut frame = data(LOCAL, 20, [8, 0], &[], Some((0, 1)));
    frame.truncate(34);
    frame[24] = 0x80;
    for value in [0x31, 0x32] {
        let padding = (4 - frame[34..].len() % 4) % 4;
        frame.extend(vec![0; padding]);
        frame.extend(LOCAL);
        frame.extend(AP);
        frame.extend(54u16.to_be_bytes());
        frame.extend([0xaa, 0xaa, 3, 0, 0, 0, 8, 0]);
        frame.extend([value; 46]);
    }
    frame.extend([0; 8]);
    model.0.borrow_mut().hear(frame, true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), [0x31, 0x32]);
}

#[test]
fn a_block_ack_agreement_orders_what_it_holds() {
    let (mut wifi, model) = connected();
    // ADDBA request: dialog 7, TID 0, immediate, 64 frames, starting at 100.
    let parameters = 2u16 | 64 << 6;
    let mut body = vec![3, 0, 7];
    body.extend(parameters.to_le_bytes());
    body.extend([0, 0]);
    body.extend((100u16 << 4).to_le_bytes());
    let before = model.0.borrow().sent.len();
    model.0.borrow_mut().hear(management(0xd0, &body), false);
    assert!(run(&mut wifi, &model, |_, air| air.sent.len() > before));
    {
        let air = model.0.borrow();
        let answer = &air.sent[before].2;
        assert_eq!(answer[0], 0xd0);
        assert_eq!(answer[24..27], [3, 1, 7]);
        assert_eq!(answer[27..29], [0, 0]);
    }
    let frame = |sequence: u16, number: u8, value| {
        data(LOCAL, sequence, [8, 0], &[value; 46], Some((0, number)))
    };
    model.0.borrow_mut().hear(frame(101, 2, 0x21), true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), []);
    model.0.borrow_mut().hear(frame(100, 1, 0x20), true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), [0x20, 0x21]);
    // A gap the sender never fills gives way after the reorder timeout.
    model.0.borrow_mut().hear(frame(103, 3, 0x23), true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), []);
    let mut released = Vec::new();
    for _ in 0..30 {
        crate::test_clock::advance(CLOCK, 5_000);
        wifi.carrier();
        released.extend(delivered(&mut wifi));
    }
    assert_eq!(released, [0x23]);
}

/// How many nullfuncs the station sent.
fn nullfuncs(air: &Air) -> usize {
    air.sent.iter().filter(|sent| sent.2[0] == 0x48).count()
}

#[test]
fn a_change_of_streams_is_told_to_the_ap() {
    let (mut wifi, model) = connected();
    model.0.borrow_mut().stream_changes.push(true);
    let action = |air: &Air| {
        air.sent
            .iter()
            .any(|(_, _, frame)| frame[0] == 0xd0 && frame[24..] == [7, 1, 1])
    };
    assert!(run(&mut wifi, &model, |_, air| action(air)));
}

#[test]
fn an_association_leaves_firmware_its_frames() {
    let (_, model) = connected();
    let air = model.0.borrow();
    assert_eq!(air.templates.len(), 1);
    let pages = air.templates[0].pages(&[0; 169], &[0; 16]);
    // The PS-Poll's AID from the association response, in its first bytes.
    assert_eq!(pages.data[80 + 48..80 + 52], [0xa4, 0, 1, 0xc0]);
}

#[test]
fn a_quiet_link_sleeps_between_watchdogs_and_wakes_for_each() {
    let (mut wifi, model) = connected();
    let watch = |wifi: &mut Wifi<Model>| {
        crate::test_clock::advance(CLOCK, WATCHDOG_US);
        wifi.carrier();
        wifi.carrier();
    };
    watch(&mut wifi);
    watch(&mut wifi);
    assert_eq!(model.0.borrow().sleeps, [true, false, true]);
    model.0.borrow_mut().busy = true;
    watch(&mut wifi);
    assert_eq!(model.0.borrow().sleeps, [true, false, true, false]);
}

#[test]
fn a_doubted_link_stays_awake_and_a_departure_wakes_it() {
    let (mut wifi, model) = connected();
    crate::test_clock::advance(CLOCK, WATCHDOG_US);
    wifi.carrier();
    wifi.carrier();
    assert_eq!(model.0.borrow().sleeps.last(), Some(&true));
    model.0.borrow_mut().quiet = true;
    assert!(run(&mut wifi, &model, |_, air| nullfuncs(air) == 1));
    assert_eq!(model.0.borrow().sleeps.last(), Some(&false));
    let (mut wifi, model) = connected();
    crate::test_clock::advance(CLOCK, WATCHDOG_US);
    wifi.carrier();
    wifi.carrier();
    model.0.borrow_mut().hear(management(0xc0, &[1, 0]), false);
    assert!(run(&mut wifi, &model, |_, air| air.cleared.len() == 2));
    assert_eq!(model.0.borrow().sleeps.last(), Some(&false));
}

#[test]
fn an_ap_gone_silent_is_probed_and_given_up_on() {
    let (mut wifi, model) = connected();
    model.0.borrow_mut().quiet = true;
    model.0.borrow_mut().gone = true;
    assert!(run(&mut wifi, &model, |wifi, _| {
        wifi.radio().station().phase() != Peering::Associated
    }));
    let air = model.0.borrow();
    assert_eq!(nullfuncs(&air), 2);
    let probe = air.sent.iter().find(|sent| sent.2[0] == 0x48).unwrap();
    assert_eq!(probe.0, Queue::Voice);
    assert_eq!(probe.2[1], 1);
    assert_eq!(probe.2[4..10], AP);
    assert!(probe.1.report.is_some());
}

#[test]
fn an_ap_that_only_stopped_beaconing_answers_the_probe() {
    let (mut wifi, model) = connected();
    model.0.borrow_mut().quiet = true;
    assert!(run(&mut wifi, &model, |_, air| nullfuncs(air) == 3));
    assert!(wifi.radio().station().phase() == Peering::Associated);
}

#[test]
fn half_a_minute_unheard_asks_the_ap_even_with_its_beacons_coming() {
    let (mut wifi, model) = connected();
    crate::test_clock::advance(CLOCK, 31_000_000);
    wifi.carrier();
    assert_eq!(nullfuncs(&model.0.borrow()), 1);
}

#[test]
fn a_new_wmm_set_and_slot_reach_the_hardware() {
    let (mut wifi, model) = connected();
    let mut changed = beacon(1);
    let at = changed.len() - WMM.len();
    changed[at + 8] = 1;
    changed[at + 11] = 0xa5;
    changed[35] |= 4;
    model.0.borrow_mut().quiet = true;
    model.0.borrow_mut().hear(changed, false);
    wifi.carrier();
    let air = model.0.borrow();
    assert_eq!(air.edca.len(), 2);
    let (edca, short_slot) = air.edca[1];
    assert_eq!(edca[0].ecw_min, 5);
    assert!(short_slot);
}

/// `beacon(1)` announcing channel `to` in `count` beacons, with silence.
fn announcing(to: u8, count: u8) -> Vec<u8> {
    let mut frame = beacon(1);
    frame.extend([37, 3, 1, to, count]);
    frame
}

#[test]
fn a_beacon_moves_the_link_in_silence_until_a_beacon_is_heard_there() {
    let (mut wifi, model) = connected();
    let commands = model.0.borrow().commands.len();
    model.0.borrow_mut().hear(announcing(6, 3), false);
    wifi.carrier();
    wifi.transmit(&ip(0xc0)).unwrap();
    wifi.carrier();
    let voice = |air: &Air| {
        air.sent
            .iter()
            .filter(|sent| sent.0 == Queue::Voice)
            .count()
    };
    let quiet = voice(&model.0.borrow());
    assert_eq!(model.0.borrow().tuned.last(), Some(&(1, false)));
    // Two beacon intervals away, and the AP's withdrawal cannot stop it.
    crate::test_clock::advance(CLOCK, 2 * 100 * 1024);
    wifi.carrier();
    assert_eq!(model.0.borrow().tuned.last(), Some(&(6, false)));
    assert!(
        model.0.borrow().commands[commands..]
            .iter()
            .any(|sent| sent.0 & 0xff == 0x40)
    );
    assert_eq!(voice(&model.0.borrow()), quiet);
    model.0.borrow_mut().channel = 6;
    wifi.carrier();
    wifi.carrier();
    assert_eq!(voice(&model.0.borrow()), quiet + 1);
    assert!(wifi.radio().station().phase() == Peering::Associated);
}

#[test]
fn a_switch_to_a_barred_channel_ends_the_association_unannounced() {
    let (mut wifi, model) = connected();
    let sent = model.0.borrow().sent.len();
    model.0.borrow_mut().hear(announcing(14, 3), false);
    assert!(run(&mut wifi, &model, |wifi, _| {
        wifi.radio().station().phase() != Peering::Associated
    }));
    let air = model.0.borrow();
    assert!(air.sent[sent..].iter().all(|frame| frame.2[0] != 0xc0));
}

#[test]
fn a_moved_link_that_hears_nothing_is_given_up_on() {
    let (mut wifi, model) = connected();
    model.0.borrow_mut().hear(announcing(6, 1), false);
    model.0.borrow_mut().gone = true;
    assert!(run(&mut wifi, &model, |wifi, _| {
        wifi.radio().station().phase() != Peering::Associated
    }));
}

#[test]
fn traffic_opens_an_agreement_and_what_follows_goes_aggregated() {
    let (mut wifi, model) = connected();
    model.0.borrow_mut().full = true;
    wifi.transmit(&ip(0)).unwrap();
    wifi.transmit(&ip(0)).unwrap();
    wifi.carrier();
    model.0.borrow_mut().full = false;
    assert!(run(&mut wifi, &model, |_, air| !requests(air).is_empty()));
    let (dialog, start) = requests(&model.0.borrow())[0];
    {
        // The ADDBA follows what is numbered, and the second frame waits.
        let air = model.0.borrow();
        let frames = best_effort(&air);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].aggregate, None);
        assert_eq!(frames[0].stbc, 1);
        assert_eq!(start, frames[0].sequence + 1);
    }
    model.0.borrow_mut().hear(response(dialog, 0), false);
    assert!(run(&mut wifi, &model, |_, air| best_effort(air).len() == 2));
    let air = model.0.borrow();
    let frame = best_effort(&air)[1];
    assert_eq!(frame.aggregate, Some(Aggregate::from_ht(0x17)));
    assert_eq!(frame.sequence, start);
    assert_eq!(requests(&air).len(), 1);
}

#[test]
fn a_refused_agreement_leaves_frames_single_and_the_next_asks_again() {
    let (mut wifi, model, dialog) = asking();
    wifi.transmit(&ip(0)).unwrap();
    model.0.borrow_mut().hear(response(dialog, 37), false);
    assert!(run(&mut wifi, &model, |_, air| requests(air).len() == 2));
    let air = model.0.borrow();
    assert_eq!(best_effort(&air).len(), 2);
    assert_eq!(best_effort(&air)[1].aggregate, None);
}

#[test]
fn voice_and_handshakes_stay_out_of_agreements() {
    let (mut wifi, model) = connected();
    wifi.transmit(&ip(0xc0)).unwrap();
    assert!(run(&mut wifi, &model, |_, air| {
        air.sent
            .iter()
            .any(|sent| sent.0 == Queue::Voice && sent.2[0] == 0x88)
    }));
    wifi.carrier();
    assert_eq!(requests(&model.0.borrow()), []);
}

#[test]
fn the_ap_ending_an_agreement_sends_frames_singly_again() {
    let (mut wifi, model, dialog) = asking();
    model.0.borrow_mut().hear(response(dialog, 0), false);
    wifi.carrier();
    wifi.transmit(&ip(0)).unwrap();
    assert!(run(&mut wifi, &model, |_, air| best_effort(air).len() == 2));
    assert!(best_effort(&model.0.borrow())[1].aggregate.is_some());
    // DELBA from the recipient of TID 0.
    let delete = management(0xd0, &[3, 2, 0, 0, 37, 0]);
    model.0.borrow_mut().hear(delete, false);
    wifi.carrier();
    wifi.transmit(&ip(0)).unwrap();
    assert!(run(&mut wifi, &model, |_, air| best_effort(air).len() == 3));
    assert_eq!(best_effort(&model.0.borrow())[2].aggregate, None);
}

#[test]
fn an_unanswered_request_ends_in_a_delba_and_frees_its_frames() {
    let (mut wifi, model, _) = asking();
    wifi.transmit(&ip(0)).unwrap();
    assert!(run(&mut wifi, &model, |_, air| best_effort(air).len() == 2));
    let air = model.0.borrow();
    assert_eq!(actions(&air, 2).len(), 1);
    assert_eq!(best_effort(&air)[1].aggregate, None);
}

#[test]
fn a_departure_ends_what_agreements_had_begun() {
    let (mut wifi, model, _) = asking();
    wifi.transmit(&ip(0)).unwrap();
    model.0.borrow_mut().hear(management(0xc0, &[1, 0]), false);
    assert!(run(&mut wifi, &model, |wifi, air| {
        !air.cleared.is_empty() && wifi.radio().station().phase() == Peering::Associated
    }));
    let radio = wifi.radio();
    assert!(!radio.station.tx_block_ack_blocks_data(0));
    assert!(radio.parked.is_empty() && radio.changes.is_empty());
    assert_eq!(actions(&model.0.borrow(), 2).len(), 0);
}

#[test]
fn a_deauthentication_clears_the_port_and_the_cam() {
    let (mut wifi, model) = connected();
    model.0.borrow_mut().hear(management(0xc0, &[1, 0]), false);
    assert!(run(&mut wifi, &model, |_, air| air.cleared.len() == 2));
    assert!(!wifi.carrier());
    let air = model.0.borrow();
    assert_eq!(air.ports.last(), Some(&(Mac([0; 6]), 0, false)));
    assert!(air.cleared.contains(&PAIRWISE_CAM) && air.cleared.contains(&1));
    assert!(air.commands.contains(&commands::media_status(0, false)));
}
