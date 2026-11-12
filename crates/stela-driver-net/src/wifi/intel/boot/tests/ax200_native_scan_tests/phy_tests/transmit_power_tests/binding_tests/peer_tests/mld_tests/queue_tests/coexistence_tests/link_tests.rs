// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
//! The polled bring-up against the device model, which answers every host
//! command, completes ALIVE and NVM init, reports its beacons per scan, and
//! plays the AP: it reads frames from the queues the scheduler added.
use super::*;
use crate::wifi::connection::keeper::{Radio, Stage as Standing};
use crate::wifi::connection::security::Security;
use crate::wifi::intel::{
    identity::EhtLimits,
    link::{Inputs, Phase, Station},
    nvm::Request as NvmRequest,
    policy::{WORLD, tests::regdb},
};
use crate::wifi::network::{Network, Secret};
use crate::wifi::sae::{Derivation, Exchange, Frame, H2E_RSNXE, Template};
use crate::wifi::station::{
    Phase as Peering,
    wire::multi_link::{Basic, Profile},
};
use crate::wifi::supplicant::{self, tests::Authenticator};
use crate::{Link, Mac};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::AtomicU8;
use stela_driver_base::entropy::{Entropy, EntropyError};
use zeroize::Zeroizing;

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

/// Each read one byte over the last, from 0x5a.
#[derive(Default)]
struct FixedEntropy(AtomicU8);

impl Entropy for FixedEntropy {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), EntropyError> {
        bytes.fill(0x5a + self.0.fetch_add(1, Ordering::Relaxed));
        Ok(())
    }
}

/// The model's view of the function: the next RX entry it completes, the
/// last command sequence it answered, the SSID each scan's beacon carries
/// (the last repeating), the MCC channel word of channels 1 and 2 and the
/// countries MCC requests named.
struct Device<'n> {
    native: &'n Native,
    entry: u16,
    answered: Option<u16>,
    beacons: Vec<&'static [u8]>,
    channel: u32,
    countries: Vec<[u8; 2]>,
    /// Every command the firmware answered, as group and opcode.
    commands: Vec<(u8, u8)>,
    /// Each scheduler queue: its TID, identity, descriptors and next index.
    queues: Vec<(u8, u16, u64, u16)>,
    /// Each frame the air carried, by the station's queues.
    air: Vec<Vec<u8>>,
    /// Whether the AP advertises WMM.
    quality: bool,
    /// What else the AP's beacons and association response carry.
    elements: &'static [u8],
    /// Each link and station command.
    configuration: Vec<(u8, Vec<u8>)>,
    /// Each receive Block Ack command.
    block_acks: Vec<Vec<u8>>,
    /// Each scan request.
    scans: Vec<Vec<u8>>,
    /// The second channel's rules, when they differ from the first's, and the
    /// AP then only heard from the first scan.
    second: Option<u32>,
    /// Whether frames are acknowledged in Block Ack notifications alone, as
    /// the firmware reports those it aggregated.
    aggregating: bool,
    /// The address the AP answers.
    receiver: [u8; 6],
    /// The AP's RSN element.
    rsn: &'static [u8],
    /// Each MAC command.
    macs: Vec<Vec<u8>>,
    /// The AP MLD's side of SAE, and the confirm it holds back.
    sae: Option<Exchange>,
    confirm: Option<Frame>,
    /// A beacon of another AP of the AP MLD, and what the association
    /// response then carries instead of `elements`.
    other: Option<(Vec<u8>, Vec<u8>)>,
    /// A scan of an association's links runs until it is told to stop.
    holds_link_scan: bool,
}

impl Device<'_> {
    fn inject(&mut self, rom: &RomBoot<'_, Model>, packet: &[u8]) {
        let slot = self.entry & (rom.entries - 1);
        let raw = device_read(
            &self.native.domain,
            rom.free.region().address,
            usize::from(slot) * 8,
            8,
        );
        let vid = (u64::from_le_bytes(raw.try_into().unwrap()) & 0xfff) as u16;
        assert!(vid > 0 && rom.buffers[usize::from(vid - 1)].device_owned);
        complete_from_free_slot(rom, &self.native.domain, slot, vid, slot, packet);
        self.entry += 1;
    }

    /// Answer the command awaiting a response, once.
    fn respond(&mut self, rom: &RomBoot<'_, Model>) {
        let Some(slot) = rom.hcmd.awaiting() else {
            return;
        };
        let tfd = device_read(
            &self.native.domain,
            rom.command.region().address,
            usize::from(slot) * 256,
            256,
        );
        let first = u64::from_le_bytes(tfd[4..12].try_into().unwrap());
        let header = device_read(&self.native.domain, first, 0, 20);
        let sequence = u16::from_le_bytes(header[2..4].try_into().unwrap());
        if self.answered == Some(sequence) {
            return;
        }
        self.answered = Some(sequence);
        let id = Id {
            group: header[1],
            opcode: header[0],
            version: 0,
        };
        self.commands.push((id.group, id.opcode));
        let rest = u64::from_le_bytes(tfd[14..22].try_into().unwrap());
        let more = usize::from(u16::from_le_bytes([tfd[12], tfd[13]]));
        let mut request = header[8..].to_vec();
        if tfd[0] > 1 {
            request.extend(device_read(&self.native.domain, rest, 0, more));
        }
        let request = &request[..];
        let payload = match (id.group, id.opcode) {
            _ if id == NvmRequest::GetInformation.id().wire() => {
                let mut nvm = nvm_response();
                if self.other.is_some() {
                    // Through channel 36, the first of 5 GHz.
                    nvm[24..28].copy_from_slice(&15u32.to_le_bytes());
                }
                nvm
            }
            (_, 0xc8) => {
                let country = u16::from_le_bytes([request[0], request[1]]).to_be_bytes();
                self.countries.push(country);
                // GET_CURRENT reports US; the world code comes back as 0.
                let country = match &country {
                    b"ZZ" => *b"US",
                    b"00" => [0; 2],
                    _ => country,
                };
                let mut payload = mcc_payload(country, request[2], 51);
                payload[20..24].copy_from_slice(&self.channel.to_le_bytes());
                let second = self.second.unwrap_or(self.channel);
                payload[24..28].copy_from_slice(&second.to_le_bytes());
                if self.other.is_some() {
                    // Channel 36, the first after the 14 of 2.4 GHz.
                    payload[76..80].copy_from_slice(&OPEN.to_le_bytes());
                }
                payload
            }
            (1 | 5, 0x08) => vec![0x9b],
            (_, 0x9f) => vec![0xaa],
            // A queue changing stations stays as it is.
            (5, 0x17) if request[0] == 2 => Vec::new(),
            (5, 0x17) if request[0] == 0 => {
                let queue = 511 - self.queues.len() as u16;
                let descriptors = u64::from_le_bytes(request[28..36].try_into().unwrap());
                self.queues.push((request[8], queue, descriptors, 0));
                let mut answer = reply(queue);
                answer[4..6].fill(0);
                answer.to_vec()
            }
            (5, 0x17) => {
                self.queues.retain(|known| known.0 != request[8]);
                reply(511).to_vec()
            }
            (_, 0x1e) => vec![0; 132],
            (2, 0) | (0 | 1, 0x25) => shared_memory(
                self.native
                    .transmit_fifo
                    .load(core::sync::atomic::Ordering::Relaxed),
            ),
            (5, 0x16) => {
                self.block_acks.push(request.to_vec());
                u32::from(SESSION).to_le_bytes().to_vec()
            }
            _ => Vec::new(),
        };
        self.inject(rom, &command_packet(id, sequence, &payload));
        if id == NvmRequest::AccessComplete.id().wire() {
            let complete = Id {
                group: 0,
                opcode: 4,
                version: 0,
            };
            self.inject(rom, &command_packet(complete, 0x8000, &[0x76]));
        }
        if (id.group, id.opcode) == (3, 8) {
            self.macs.push(request.to_vec());
        }
        if id.group == 3 && matches!(id.opcode, 8..=0x0a) {
            self.configuration.push((id.opcode, request.to_vec()));
        }
        if (id.group, id.opcode) == (1, 0x0d) {
            self.scans.push(request.to_vec());
            let beside = self.other.is_some() && self.scans.len() > 1;
            if beside {
                let started = Id {
                    group: 0,
                    opcode: 0xb2,
                    version: 0,
                };
                self.inject(rom, &command_packet(started, 0x8000, &[0; 8]));
            }
            if self.second.is_none() || self.scans.len() == 1 {
                for ssid in self.beacons.clone() {
                    self.inject(rom, &beacon(ssid, self.rsn, self.quality, self.elements));
                }
                if let Some((frame, _)) = &self.other {
                    let frame = frame.clone();
                    self.inject(rom, &frame);
                }
            }
            if !(beside && self.holds_link_scan) {
                self.finish_scan(rom, 1);
            }
        }
        if (id.group, id.opcode) == (1, 0x0e) {
            self.finish_scan(rom, 2);
        }
        if (id.group, id.opcode) == (3, 5) && request[4] == 1 {
            let notification = Id {
                group: 3,
                opcode: 0xfb,
                version: 0,
            };
            let mut body = [0; 16];
            body[4] = 1;
            body[8] = 1;
            self.inject(rom, &command_packet(notification, 0x8000, &body));
        }
    }

    /// The scan ended with `status`.
    fn finish_scan(&mut self, rom: &RomBoot<'_, Model>, status: u8) {
        let mut body = [0; 16];
        body[6] = status;
        body[7] = 3;
        let done = Id {
            group: 0,
            opcode: 0x0f,
            version: 0,
        };
        self.inject(rom, &command_packet(done, 0x8000, &body));
    }

    /// Answer the station MLD's SAE `frame`: its commit, or its confirm.
    fn exchange(&mut self, rom: &RomBoot<'_, Model>, frame: &[u8]) {
        let field = |at: usize| u16::from_le_bytes([frame[at], frame[at + 1]]);
        let (transaction, status) = (field(26), field(28));
        let own = Basic {
            address: Mac(LOCAL),
            ..Basic::default()
        };
        let data = &frame[30..frame.len() - own.encode().len()];
        let sae = self.sae.as_mut().unwrap();
        let reply = if transaction == 1 {
            self.confirm = sae.receive(1, status, data).unwrap();
            sae.commit()
        } else {
            assert_eq!(sae.receive(2, status, data).unwrap(), None);
            self.confirm.take().unwrap()
        };
        let mut body = [3, 0].to_vec();
        body.extend(reply.transaction.to_le_bytes());
        body.extend(reply.status.to_le_bytes());
        body.extend(reply.data);
        let ap = Basic {
            address: Mac(AP_MLD),
            ..Basic::default()
        };
        body.extend(ap.encode());
        self.inject(rom, &answer(self.receiver, 0xb0, &body));
    }

    /// Carry what the queues hold to the AP, answering each frame, as much
    /// as the receive buffers keep up with.
    fn transmit(&mut self, rom: &RomBoot<'_, Model>) {
        let mut room = 4;
        for at in 0..self.queues.len() {
            loop {
                if room == 0 {
                    return;
                }
                room -= 1;
                let (_, queue, descriptors, index) = self.queues[at];
                let tfd = device_read(
                    &self.native.domain,
                    descriptors,
                    usize::from(index) * 256,
                    64,
                );
                // A finished slot holds one buffer, the invalid one.
                if tfd[0] < 2 {
                    break;
                }
                let next = (index + 1) % 256;
                self.queues[at].3 = next;
                let mut bytes = Vec::new();
                for tb in 0..usize::from(tfd[0]) {
                    let at = 2 + tb * 10;
                    let length = usize::from(u16::from_le_bytes([tfd[at], tfd[at + 1]]));
                    let address = u64::from_le_bytes(tfd[at + 2..at + 10].try_into().unwrap());
                    bytes.extend(device_read(&self.native.domain, address, 0, length));
                }
                if self.aggregating {
                    let mut body = vec![0; 40];
                    body[28] = 1;
                    body[32..34].copy_from_slice(&queue.to_le_bytes());
                    body[34..36].copy_from_slice(&next.to_le_bytes());
                    let acknowledged = Id {
                        group: 0,
                        opcode: 0xc5,
                        version: 0,
                    };
                    self.inject(rom, &command_packet(acknowledged, 0x8000, &body));
                } else {
                    let mut response = vec![0; 56];
                    response[0] = 1;
                    response[36..38].copy_from_slice(&queue.to_le_bytes());
                    response[40] = 1;
                    response[44..48].copy_from_slice(&u32::from(next).to_le_bytes());
                    let done = Id {
                        group: 0,
                        opcode: 0x1c,
                        version: 0,
                    };
                    let sequence = (queue & 31) << 8 | index;
                    self.inject(rom, &command_packet(done, sequence, &response));
                }
                // The command header, then the 20-byte body's rest.
                let mut frame = bytes[24..].to_vec();
                if frame[0] & 0x88 == 0x88 {
                    // The dword pad after the QoS header.
                    frame.drain(26..28);
                }
                match u16::from_le_bytes([frame[0], frame[1]]) & 0xfc {
                    0xb0 if self.sae.is_some() => self.exchange(rom, &frame),
                    0xb0 => self.inject(rom, &answer(self.receiver, 0xb0, &[0, 0, 2, 0, 0, 0])),
                    0x00 => {
                        let mut body = vec![0x11, 0, 0, 0, 1, 0xc0, 1, 2, 0x82, 0x0c];
                        if self.quality {
                            body.extend(HT);
                            body.extend(WMM);
                        }
                        match &self.other {
                            Some((_, response)) => body.extend(response),
                            None => body.extend(self.elements),
                        }
                        self.inject(rom, &answer(self.receiver, 0x10, &body));
                    }
                    _ => {}
                }
                self.air.push(frame);
            }
        }
    }
}

/// A frame from the AP to the station.
fn answer(receiver: [u8; 6], subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[..2].copy_from_slice(&subtype.to_le_bytes());
    frame[4..10].copy_from_slice(&receiver);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend(body);
    mpdu(frame, 3)
}

/// The station address `nvm_response` holds.
const LOCAL: [u8; 6] = [0x02, 0x12, 0x34, 0x56, 0x78, 0x9a];

/// The transmitter of the Multiple BSSID set whose second BSS the model's AP
/// is, for a [`beacon`] whose `elements` start with the set.
const TRANSMITTER: [u8; 6] = [2, 3, 4, 5, 6, 6];

/// A channel 1 ESS beacon from 02:03:04:05:06:07 carrying `ssid` and the 1
/// and 6 Mb/s rates.
fn beacon(ssid: &[u8], rsn: &[u8], quality: bool, elements: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 36];
    frame[..2].copy_from_slice(&0x80u16.to_le_bytes());
    frame[4..10].fill(0xff);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[32..34].copy_from_slice(&100u16.to_le_bytes());
    frame[34] = 0x11;
    frame.extend([0, ssid.len() as u8]);
    frame.extend(ssid);
    frame.extend([1, 2, 0x82, 0x0c, 3, 1, 1, 5, 4, 0, 2, 0, 0]);
    frame.extend(rsn);
    if quality {
        frame.extend(HT);
        frame.extend(WMM);
    }
    frame.extend(elements);
    if elements.first() == Some(&71) {
        frame[10..16].copy_from_slice(&TRANSMITTER);
        frame[16..22].copy_from_slice(&TRANSMITTER);
    }
    mpdu(frame, 3)
}

/// `frame` as the firmware's RX packet, at `status` and the beacon's signal.
fn mpdu(frame: Vec<u8>, status: u32) -> Vec<u8> {
    placed(frame, status, None, 127 << 24)
}

/// A beacon of the AP on the other link of the AP MLD, on channel 36 and
/// quieter than the setup link's.
fn other_beacon(heard: [u8; 2]) -> Vec<u8> {
    announcing_beacon(heard, &[])
}

/// [`other_beacon`] with `extra` elements.
fn announcing_beacon(heard: [u8; 2], extra: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 36];
    frame[..2].copy_from_slice(&0x80u16.to_le_bytes());
    frame[4..10].fill(0xff);
    frame[10..16].copy_from_slice(&OTHER);
    frame[16..22].copy_from_slice(&OTHER);
    frame[32..34].copy_from_slice(&100u16.to_le_bytes());
    frame[34] = 0x11;
    frame.extend([0, 4]);
    frame.extend(b"test");
    frame.extend([1, 2, 0x8c, 0x12, 3, 1, 36, 5, 4, 0, 2, 0, 0]);
    frame.extend(other_elements());
    frame.extend(
        Basic {
            address: Mac(AP_MLD),
            link_id: Some(5),
            mld_capabilities: Some(0),
            ..Basic::default()
        }
        .encode(),
    );
    frame.extend(extra);
    placed_at(frame, 3, None, 127 << 24, [heard[0], heard[1], 36])
}

/// What the AP says of itself on channel 36.
fn other_elements() -> Vec<u8> {
    let mut ht = HT;
    ht[30] = 36;
    let mut elements = RSN_SAE.to_vec();
    elements.extend(ht);
    elements.extend(WMM);
    // mac80211 holds a 5 GHz AP without VHT to HT.
    elements.extend([191, 12, 0, 0, 0, 0, 0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0]);
    elements.extend([192, 5, 0, 0, 0, 0xfa, 0xff]);
    elements.extend(HE_AP);
    elements.extend(EHT_AP);
    elements.extend(H2E_RSNXE);
    elements
}

/// What the association response carries with the other link accepted.
fn other_response() -> Vec<u8> {
    let mut profile = vec![0x11, 0, 0, 0, 1, 2, 0x8c, 0x12];
    profile.extend(&other_elements()[RSN_SAE.len()..]);
    let mut elements = HE_AP.to_vec();
    elements.extend(EHT_AP);
    elements.extend(H2E_RSNXE);
    elements.extend(
        Basic {
            address: Mac(AP_MLD),
            link_id: Some(3),
            mld_capabilities: Some(0),
            eml_capabilities: Some(1 | 6 << 11),
            medium_sync_delay: Some(0x2345),
            profiles: vec![Profile {
                link_id: 5,
                complete: true,
                address: Some(Mac(OTHER)),
                bss_parameters_change_count: Some(0),
                body: profile,
                ..Profile::default()
            }],
            ..Basic::default()
        }
        .encode(),
    );
    elements
}

/// The setup link's AP with `load` of its channel taken: its RNR names the
/// other link.
fn linked_ap(load: u8) -> &'static [u8] {
    let mut elements = vec![11, 5, 0, 0, load, 0, 0];
    elements.extend(mld_ap());
    let mut rnr = vec![0x00, 16, 0, 36, 0];
    rnr.extend(OTHER);
    rnr.extend([0, 0, 0, 0, 0x40, 0, 0, 5, 0]);
    elements.extend([201, rnr.len() as u8]);
    elements.extend(rnr);
    Box::leak(elements.into_boxed_slice())
}

/// [`mpdu`], as an A-MSDU's record at its index and whether it is the last,
/// with `reorder` the descriptor's reorder word.
fn placed(frame: Vec<u8>, status: u32, record: Option<(u8, bool)>, reorder: u32) -> Vec<u8> {
    placed_at(frame, status, record, reorder, [44, 56, 1])
}

/// [`placed`], with `heard` the firmware's two energy readings and channel.
fn placed_at(
    frame: Vec<u8>,
    status: u32,
    record: Option<(u8, bool)>,
    reorder: u32,
    heard: [u8; 3],
) -> Vec<u8> {
    let mut payload = vec![0; 48];
    payload[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    if let Some((index, last)) = record {
        payload[3] = 0x40;
        payload[4] = index | u8::from(last) << 7;
    }
    payload[7] = 1 << 6;
    payload[12..16].copy_from_slice(&status.to_le_bytes());
    payload[16..20].copy_from_slice(&reorder.to_le_bytes());
    payload[28..32].copy_from_slice(&(3u32 << 14).to_le_bytes());
    payload[32..35].copy_from_slice(&heard);
    payload.extend(frame);
    let mpdu = Id {
        group: 0,
        opcode: 0xc1,
        version: 0,
    };
    command_packet(mpdu, 0x8000, &payload)
}

/// Firmware's report of two LMACs whose FIFOs are each `size` bytes.
fn shared_memory(size: u32) -> Vec<u8> {
    let mut payload = vec![0; 260];
    payload[32..36].copy_from_slice(&2u32.to_le_bytes());
    for at in (40..100).chain(112..172).step_by(4) {
        payload[at..at + 4].copy_from_slice(&size.to_le_bytes());
    }
    payload
}

/// Bring the modeled function up for the network "test" until it is ready
/// to authenticate or fails, with `flags` on the US 2.4 GHz rule and
/// `channel` as the firmware's channel word.
fn bring_up<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
) -> (Station<Model, ClockBios>, Phase, Device<'n>) {
    raise(native, country, beacons, flags, channel, false)
}

/// `image` with its PHY SKU allowing the two chains NVM names, and with
/// `host_chains` a first RLC version, which leaves them to the host.
fn two_receive_chains(mut image: Vec<u8>, host_chains: bool) -> Vec<u8> {
    const PHY_SKU: u32 = 20;
    const COMMAND_VERSIONS: u32 = 48;
    let mut at = 88;
    while at < image.len() {
        let word = |at: usize| u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
        let (kind, length) = (word(at), word(at + 4) as usize);
        if kind == PHY_SKU {
            let sku = word(at + 8) | 3 << 20;
            image[at + 8..at + 12].copy_from_slice(&sku.to_le_bytes());
        }
        if kind == COMMAND_VERSIONS && host_chains {
            for entry in image[at + 8..at + 8 + length].as_chunks_mut::<4>().0 {
                if entry[..2] == [8, 5] {
                    entry[2] = 1;
                }
            }
        }
        at += 8 + length.next_multiple_of(4);
    }
    image
}

/// [`bring_up`] with an AP that does or does not advertise WMM.
fn raise<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
    quality: bool,
) -> (Station<Model, ClockBios>, Phase, Device<'n>) {
    raise_beside(native, country, beacons, flags, channel, quality, &[])
}

/// [`raise`], with `elements` on the AP's frames.
fn raise_beside<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
    quality: bool,
    elements: &'static [u8],
) -> (Station<Model, ClockBios>, Phase, Device<'n>) {
    raise_split(
        native, country, beacons, flags, channel, quality, elements, None,
    )
}

/// [`raise_beside`], with [`Device::second`].
#[expect(clippy::too_many_arguments, reason = "each is a fixture's own knob")]
fn raise_split<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
    quality: bool,
    elements: &'static [u8],
    second: Option<u32>,
) -> (Station<Model, ClockBios>, Phase, Device<'n>) {
    let secret = Secret::Psk(Zeroizing::new([0; 32]));
    raise_as(
        native, country, beacons, flags, channel, quality, elements, second, &RSN, None, secret,
        false,
    )
}

/// [`raise_split`], with [`Device::rsn`], a radio standing in for `eht` and
/// whether the AP MLD has [`Device::other`].
#[expect(clippy::too_many_arguments, reason = "each is a fixture's own knob")]
fn raise_as<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
    quality: bool,
    elements: &'static [u8],
    second: Option<u32>,
    rsn: &'static [u8],
    eht: Option<EhtLimits>,
    secret: Secret,
    other: bool,
) -> (Station<Model, ClockBios>, Phase, Device<'n>) {
    let image = native.firmware.clone().unwrap_or_else(|| coex_image(2));
    let catalog: &'static resources::Catalog = Box::leak(Box::new(catalog_for(
        &profile(),
        Family::Ax200.firmware_name(),
        &feature(
            feature(
                feature(two_receive_chains(image, native.host_chains), 30, 63, true),
                30,
                21,
                true,
            ),
            30,
            46,
            true,
        ),
    )));
    let source: &'static Source = Box::leak(Box::new(Source::default()));
    native
        .state
        .lock()
        .unwrap()
        .registers
        .extend([(0x388, 0x02123456), (0x38c, 0x789a)]);
    let mut boot = start(
        catalog,
        source,
        &native.domain,
        &native.state,
        &native.drops,
    );
    event(&native.state, 1);
    boot.poll().unwrap();
    let mut alive = rx_packet(1, 0xcafe, 0);
    set_sku(&mut alive, [0; 3]);
    let mut device = Device {
        native,
        entry: 0,
        answered: None,
        beacons,
        channel,
        countries: Vec::new(),
        commands: Vec::new(),
        queues: Vec::new(),
        air: Vec::new(),
        quality,
        elements,
        configuration: Vec::new(),
        block_acks: Vec::new(),
        scans: Vec::new(),
        second,
        aggregating: false,
        receiver: LOCAL,
        rsn,
        macs: Vec::new(),
        sae: None,
        confirm: None,
        other: other.then(|| (other_beacon([60, 70]), other_response())),
        holds_link_scan: false,
    };
    device.inject(&boot, &alive);
    let inputs = Inputs {
        firmware: catalog,
        observations: Observations::default(),
        pages: source,
        clock: Clock {
            ticks_per_microsecond: 1_000_000,
        },
        bios: clock_bios(&native.bios_drops, Some(1)),
        database: regdb(&[
            (*b"00", &[(2_402_000, 2_472_000, 0, 2000)]),
            (
                *b"US",
                &[
                    (2_402_000, 2_472_000, flags, 3000),
                    (5_170_000, 5_250_000, 0, 3000),
                ],
            ),
        ]),
        network: Network {
            ssid: b"test".to_vec(),
            secret,
            country,
        },
        entropy: Arc::new(FixedEntropy::default()),
    };
    // SAFETY: the model owns its pages and nothing else reaches the function.
    let mut wifi = unsafe { crate::wifi::intel::link::Wifi::new(boot, inputs) };
    wifi.radio_mut().assumed_eht = eht;
    let mut phase = Phase::Booting;
    for _ in 0..600 {
        wifi.carrier();
        phase = wifi.radio().phase();
        if matches!(phase, Phase::AuthenticationRequired | Phase::Failed) {
            break;
        }
        device.respond(wifi.radio().rom().unwrap());
    }
    (wifi, phase, device)
}

/// Serve the modeled air until `done`.
fn run(
    wifi: &mut Station<Model, ClockBios>,
    device: &mut Device<'_>,
    mut done: impl FnMut(&Station<Model, ClockBios>, &Device<'_>, bool) -> bool,
) -> bool {
    for _ in 0..600 {
        let up = wifi.carrier();
        if done(wifi, device, up) {
            return true;
        }
        let Some(rom) = wifi.radio().rom() else {
            panic!("{:?} {:?}", wifi.radio().phase(), wifi.radio().error());
        };
        device.respond(rom);
        device.transmit(rom);
    }
    false
}

/// A data frame from the AP to `receiver`, with `key` the index and packet
/// number the firmware decrypted it under.
fn data(
    receiver: [u8; 6],
    quality: bool,
    kind: [u8; 2],
    body: &[u8],
    key: Option<(u8, u8)>,
) -> Vec<u8> {
    let mut frame = vec![0; if quality { 26 } else { 24 }];
    frame[0] = if quality { 0x88 } else { 0x08 };
    frame[1] = if key.is_some() { 0x42 } else { 0x02 };
    frame[4..10].copy_from_slice(&receiver);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    if let Some((index, number)) = key {
        frame.extend([number, 0, 0, 0x20 | index << 6, 0, 0, 0, 0]);
    }
    frame.extend([0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend(kind);
    frame.extend(body);
    mpdu(
        frame,
        if key.is_some() {
            3 | 2 << 8 | 1 << 6
        } else {
            3
        },
    )
}

/// What `frame` from the station carries past its header and LLC.
fn eapol(frame: &[u8]) -> &[u8] {
    let header = if frame[0] & 0x88 == 0x88 { 26 } else { 24 };
    assert_eq!(frame[header + 6..header + 8], [0x88, 0x8e]);
    &frame[header + 8..]
}

/// Join the model's AP through its handshake to an open port.
fn connect<'n>(native: &'n Native, quality: bool) -> (Station<Model, ClockBios>, Device<'n>) {
    connect_in(native, Some(*b"US"), quality)
}

/// [`connect`] under a configured `country`.
fn connect_in<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    quality: bool,
) -> (Station<Model, ClockBios>, Device<'n>) {
    let (mut wifi, phase, mut device) = raise(native, country, vec![b"test"], 0, OPEN, quality);
    assert_eq!(phase, Phase::AuthenticationRequired);
    let associated = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().station().phase() == Peering::Associated
    });
    assert!(associated, "{:?}", wifi.radio().station().phase());
    let security = Security::select(&RSN, true).unwrap();
    let pmk = Zeroizing::new([0; 32]);
    let mut ap = Authenticator::between(
        security.suites(),
        pmk,
        Mac(AP),
        Mac(LOCAL),
        security.element(),
    );
    let local = data(LOCAL, false, [0x88, 0x8e], &ap.message_1(), None);
    device.inject(wifi.radio().rom().unwrap(), &local);
    let answered = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 2);
    assert!(answered, "{:?}", wifi.radio().error());
    ap.message_2(eapol(&device.air[2]));
    let local = data(LOCAL, false, [0x88, 0x8e], &ap.message_3(&RSN), None);
    device.inject(wifi.radio().rom().unwrap(), &local);
    let up = run(&mut wifi, &mut device, |_, _, up| up);
    assert!(
        up,
        "{:?} {:?}",
        wifi.radio().error(),
        device.commands.last()
    );
    // Message 4: pairwise, MIC and secure.
    let answered = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 3);
    assert!(answered, "{:?}", wifi.radio().error());
    ap.signed_reply(eapol(&device.air[3]), 0x308);
    (wifi, device)
}

/// A valid channel that allows initiated radiation.
const OPEN: u32 = 0x0f09;
/// The session the model's firmware allocates.
const SESSION: u8 = 3;

/// A TID 0 frame of a Block Ack session under the pairwise key, at `sequence`
/// with the window at `next`, carrying `value` under packet number `number`.
fn session_frame(sequence: u16, next: u16, number: u8, value: u8) -> Vec<u8> {
    let (frame, reorder) = protected(sequence, next, number, value, false, false);
    placed(frame, 3 | 2 << 8 | 1 << 6, None, reorder)
}

fn protected(
    sequence: u16,
    next: u16,
    number: u8,
    value: u8,
    record: bool,
    retry: bool,
) -> (Vec<u8>, u32) {
    let mut frame = vec![0; 26];
    frame[0] = 0x88;
    frame[1] = 0x42 | u8::from(retry) << 3;
    frame[4..10].copy_from_slice(&LOCAL);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[21] = value;
    frame[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    frame[24] = u8::from(record) << 7;
    frame.extend([number, 0, 0, 0x20, 0, 0, 0, 0]);
    frame.extend([0xaa, 0xaa, 3, 0, 0, 0, 8, 0]);
    frame.extend([value; 46]);
    let reorder = u32::from(next) | u32::from(sequence) << 12 | u32::from(SESSION) << 24;
    (frame, reorder)
}

/// What the station now holds for the network, as payload values.
fn delivered(wifi: &mut Station<Model, ClockBios>) -> Vec<u8> {
    let mut values = Vec::new();
    while let Some(ethernet) = wifi.receive().unwrap() {
        values.push(ethernet[14]);
    }
    values
}

/// Serve the air until nothing more can come of what it holds.
fn settle(wifi: &mut Station<Model, ClockBios>, device: &mut Device<'_>) {
    run(wifi, device, |_, _, _| false);
}

/// Connect to a WMM AP and agree on TID 0's session from sequence 5.
fn agreed<'n>(native: &'n Native) -> (Station<Model, ClockBios>, Device<'n>) {
    let (mut wifi, mut device) = connect(native, true);
    let parameters: u16 = 3 | 8 << 6;
    let mut body = vec![3, 0, 9];
    body.extend(parameters.to_le_bytes());
    body.extend(0u16.to_le_bytes());
    body.extend((5u16 << 4).to_le_bytes());
    device.inject(wifi.radio().rom().unwrap(), &answer(LOCAL, 0xd0, &body));
    let accepted = run(&mut wifi, &mut device, |_, device, _| {
        device
            .air
            .last()
            .is_some_and(|frame| frame[0] == 0xd0 && frame[24..26] == [3, 1])
    });
    assert!(accepted, "{:?} {:?}", wifi.radio().error(), device.commands);
    (wifi, device)
}

#[test]
fn bring_up_scans_for_the_network_and_readies_its_station() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (wifi, phase, device) = bring_up(&native, Some(*b"US"), vec![b"test"], 0, OPEN);
    let wifi = wifi.radio();
    assert_eq!(wifi.error(), None);
    assert_eq!(device.countries.last(), Some(b"US"));
    assert_eq!(phase, Phase::AuthenticationRequired);
    let selected = wifi.selected().unwrap();
    assert_eq!(selected.bss.bssid, Mac(AP));
    assert_eq!(selected.bss.channel.number, 1);
    assert_eq!(selected.rates, 0b1_0001);
    assert_ne!(wifi.address(), Mac::default());
}

#[test]
fn without_a_country_world_rules_apply_and_only_the_networks_bss_is_joined() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (wifi, phase, device) = bring_up(&native, None, vec![b"other", b"test"], 0, OPEN);
    let wifi = wifi.radio();
    assert_eq!(wifi.error(), None);
    assert_eq!(phase, Phase::AuthenticationRequired);
    // The BIOS country, CN, is not in the database.
    assert_eq!(device.countries.last(), Some(&WORLD));
    assert_eq!(
        wifi.selected().unwrap().bss.ssid.as_deref(),
        Some(b"test".as_slice())
    );
}

#[test]
fn a_station_joins_an_ap_on_a_dfs_no_ir_indoor_only_channel() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    // Valid, without ACTIVE, with RADAR and INDOOR_ONLY.
    let restricted = 0x0f31;
    let (wifi, phase, _) = bring_up(&native, Some(*b"US"), vec![b"test"], 2 | 4 | 8, restricted);
    let wifi = wifi.radio();
    assert_eq!(wifi.error(), None);
    assert_eq!(phase, Phase::AuthenticationRequired);
    assert_eq!(wifi.selected().unwrap().bss.channel.number, 1);
}

#[test]
fn a_station_associates_answers_the_handshake_and_leaves_with_its_ap() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    // Session protection before the exchange, then the MAC, link, rates and
    // station of the association, in mvm's order, and the power update.
    let mut commands = device.commands.iter();
    for command in [(3, 5), (3, 9), (5, 0x0f), (3, 0x0a), (3, 8), (1, 0xa9)] {
        assert!(commands.any(|known| *known == command), "{command:?}");
    }
    assert_eq!(device.air[0][0], 0xb0);
    assert_eq!(device.air[1][0], 0x00);
    // The pairwise key, then the group key; the port opens over both.
    let keys = |device: &Device<'_>| device.commands.iter().filter(|c| **c == (5, 0x18)).count();
    assert_eq!(keys(&device), 2);

    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0xab; 46]].concat();
    wifi.transmit(&ethernet).unwrap();
    let sent = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 4);
    assert!(sent, "{:?}", wifi.radio().error());
    let frame = &device.air[4];
    assert_eq!(frame[..2], [0x08, 0x41]);
    assert_eq!(frame[16..22], [9; 6]);
    // The firmware encrypts, and writes the CCMP header it needs.
    assert_eq!(frame[24 + 8..], ethernet[14..]);

    device.inject(
        wifi.radio().rom().unwrap(),
        &data(LOCAL, false, [8, 0], &[1; 46], Some((0, 1))),
    );
    // Message 3's group counter is 7.
    let group = [1, 0, 0x5e, 0, 0, 1];
    device.inject(
        wifi.radio().rom().unwrap(),
        &data(group, false, [8, 0], &[2; 46], Some((1, 8))),
    );
    run(&mut wifi, &mut device, |_, _, _| false);
    let unicast = wifi.receive().unwrap().expect("the pairwise frame");
    assert_eq!(unicast[..6], LOCAL);
    assert_eq!(unicast[14..], [1; 46]);
    let multicast = wifi.receive().unwrap().expect("the group frame");
    assert_eq!(multicast[..6], group);

    let deauthentication = answer(LOCAL, 0xc0, &[3, 0]);
    device.inject(wifi.radio().rom().unwrap(), &deauthentication);
    assert!(
        run(&mut wifi, &mut device, |wifi, _, _| {
            wifi.radio().stage() == Standing::Idle
        }),
        "{:?} {:?} {:?}",
        wifi.radio().stage(),
        wifi.radio().error(),
        device.commands.last(),
    );
    assert!(device.commands.contains(&(3, 0x0c)));
    assert_eq!(keys(&device), 4);
    assert_eq!(wifi.radio().station().phase(), Peering::Idle);
}

#[test]
fn a_leaving_station_tells_its_ap_before_its_station_goes() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    let commands = device.commands.len();
    wifi.radio_mut().deauthenticate(3).unwrap();
    let left = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().stage() == Standing::Idle
    });
    assert!(left, "{:?}", wifi.radio().error());
    let farewell = device.air.last().unwrap();
    assert_eq!(farewell[0], 0xc0);
    // Protected or not, its reason survives.
    assert_eq!(farewell[24..26], [3, 0]);
    assert!(device.commands[commands..].contains(&(3, 0x0c)));
}

#[test]
fn a_country_the_air_tells_an_associated_station_changes_nothing() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    let update = Id {
        group: 0,
        opcode: 0xc9,
        version: 0,
    };
    device.inject(
        wifi.radio().rom().unwrap(),
        &command_packet(update, 0x8000, &[b'E', b'D', 5, 0]),
    );
    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0xab; 46]].concat();
    wifi.transmit(&ethernet).unwrap();
    let sent = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 4);
    assert!(sent, "{:?}", wifi.radio().error());
}

/// A TKIP frame under packet number `number` that firmware decrypted, with an
/// ICV that holds and a Michael MIC that does not.
fn michael_failure(number: u8) -> Vec<u8> {
    let (mut frame, _) = protected(5, 5, number, 1, false, false);
    frame[26..30].copy_from_slice(&[0, 0x20, number, 0x20]);
    placed(frame, 3 | 3 << 8 | 1 << 5 | 1 << 7, None, 0)
}

#[test]
fn a_second_michael_failure_in_a_minute_leaves_the_ap() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    // A packet number the key already took tells of nothing.
    device.inject(wifi.radio().rom().unwrap(), &michael_failure(0));
    settle(&mut wifi, &mut device);
    assert_eq!(device.air.len(), 4);
    device.inject(wifi.radio().rom().unwrap(), &michael_failure(1));
    let told = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 4);
    assert!(told, "{:?}", wifi.radio().error());
    // Key Information: a request with its error bit, of the pairwise key.
    let info = u16::from_be_bytes(eapol(&device.air[4])[5..7].try_into().unwrap());
    assert_eq!(
        info & (1 << 11 | 1 << 10 | 1 << 3),
        1 << 11 | 1 << 10 | 1 << 3
    );
    assert!(wifi.carrier());
    device.inject(wifi.radio().rom().unwrap(), &michael_failure(2));
    let left = run(&mut wifi, &mut device, |_, device, _| {
        device.air.iter().any(|frame| frame[0] == 0xc0)
    });
    assert!(left, "{:?}", wifi.radio().error());
    let farewell = device.air.last().unwrap();
    assert_eq!(farewell[24..26], [14, 0]);
    let report = device.air[device.air.len() - 2].as_slice();
    assert_eq!(eapol(report)[6] & 8, 8, "the AP hears of the second, too");
}

/// Firmware's word on Bluetooth's activity.
fn bluetooth(grading: u8) -> Vec<u8> {
    let mut body = vec![0; 40];
    body[32] = grading;
    notify(0, 0xce, &body)
}

#[test]
fn firmware_that_keeps_its_chains_leaves_sm_power_save_to_itself() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    device.inject(wifi.radio().rom().unwrap(), &bluetooth(3));
    let told = run(&mut wifi, &mut device, |_, device, _| {
        device.air.iter().any(|frame| frame[24..] == [7, 1, 1])
    });
    assert!(!told, "{:?}", wifi.radio().error());
}

/// Complete v11 notification for the MAC and beacon-filter energy fields
/// measured from the pinned C declaration. The fixture has neither the
/// SYSTEM_STATISTICS command nor NEW_RX_STATS API bit.
fn legacy_beacon_statistics(mac: u32, energy: u8) -> Vec<u8> {
    let mut report = vec![0; 760];
    report[252..256].copy_from_slice(&mac.to_le_bytes());
    report[584] = energy;
    notify(0, 0x9d, &report)
}

#[test]
fn invalid_or_unrelated_firmware_statistics_cannot_reduce_bluetooth_power() {
    if crate::test_process::isolate_model() {
        return;
    }
    for fault in 0..4 {
        let native = Native::default();
        let (mut wifi, mut device) = connect(&native, false);
        let commands = device.commands.len();
        device.inject(wifi.radio().rom().unwrap(), &bluetooth(3));
        assert!(run(&mut wifi, &mut device, |_, device, _| device.commands
            [commands..]
            .iter()
            .any(|command| command.1 == 0x5d)));
        let bad = match fault {
            0 => {
                let mut report = vec![0; 759];
                report[584] = 44;
                notify(0, 0x9d, &report)
            }
            1 => legacy_beacon_statistics(1, 44),
            2 => legacy_beacon_statistics(0, 0),
            _ => notify(0x10, 0, &[0; 492]),
        };
        device.inject(wifi.radio().rom().unwrap(), &bad);
        assert!(!run(&mut wifi, &mut device, |_, device, _| device.commands
            [commands..]
            .iter()
            .any(|command| command.1 == 0x5c)));
        assert!(wifi.carrier());
        device.inject(
            wifi.radio().rom().unwrap(),
            &legacy_beacon_statistics(0, 44),
        );
        assert!(run(&mut wifi, &mut device, |_, device, _| device.commands
            [commands..]
            .iter()
            .any(|command| command.1 == 0x5c)));
    }
}

fn statistics_image(new_statistics: bool, version: u8, system: bool) -> Vec<u8> {
    let mut image = feature(coex_image(2), 29, 35, new_statistics);
    let entries = if system {
        vec![[0x0f, 2, 1, 0xff], [0, 0x10, 0xff, 3]]
    } else {
        vec![[0x9d, 0, 0xff, version]]
    };
    let mut at = 88;
    while at < image.len() {
        let kind = u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
        let length = u32::from_le_bytes(image[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            let mut versions = image[at + 8..at + 8 + length]
                .as_chunks::<4>()
                .0
                .iter()
                .filter(|entry| {
                    !entries
                        .iter()
                        .any(|replacement| entry[..2] == replacement[..2])
                })
                .flatten()
                .copied()
                .collect::<Vec<_>>();
            for entry in entries {
                versions.extend_from_slice(&entry);
            }
            image[at + 4..at + 8].copy_from_slice(&(versions.len() as u32).to_le_bytes());
            image.splice(at + 8..at + 8 + length, versions);
            return image;
        }
        at += 8 + length.next_multiple_of(4);
    }
    panic!("firmware command-version table");
}

#[test]
fn firmware_statistics_negotiate_each_layout_and_drive_bluetooth_hysteresis() {
    if crate::test_process::isolate_model() {
        return;
    }
    for (new_statistics, version, system) in [
        (false, 11, false),
        (true, 13, false),
        (true, 14, false),
        (true, 15, false),
        (false, 255, false),
        (false, 3, true),
    ] {
        let native = Native {
            firmware: Some(statistics_image(new_statistics, version, system)),
            ..Native::default()
        };
        let (mut wifi, mut device) = connect(&native, false);
        assert_eq!(device.commands.contains(&(2, 0x0f)), system);
        let initial = device.commands.len();
        device.inject(wifi.radio().rom().unwrap(), &bluetooth(3));
        assert!(run(&mut wifi, &mut device, |_, device, _| device.commands
            [initial..]
            .iter()
            .any(|command| command.1 == 0x5d)));
        let report = |energy: u32| {
            let (size, id, at) = if system {
                (492, None, 4)
            } else if version == 14 {
                (196, Some(8), 12)
            } else if version == 15 {
                (480, None, 8)
            } else if new_statistics {
                (564, Some(120), 404)
            } else {
                (760, Some(252), 584)
            };
            let mut raw = vec![0; size];
            if !system && matches!(version, 14 | 15) {
                raw[..4].copy_from_slice(&[0, version, size as u8, (size >> 8) as u8]);
            }
            if let Some(id) = id {
                raw[id..id + 4].copy_from_slice(&0u32.to_le_bytes());
            }
            if !system && !matches!(version, 14 | 15) {
                raw[at] = energy as u8;
            } else {
                raw[at..at + 4].copy_from_slice(&energy.to_le_bytes());
            }
            if system {
                notify(0x10, 0, &raw)
            } else {
                notify(0, 0x9d, &raw)
            }
        };
        if system {
            // The negotiated system API supersedes unilateral legacy reports.
            device.inject(
                wifi.radio().rom().unwrap(),
                &legacy_beacon_statistics(0, 44),
            );
            assert!(!run(&mut wifi, &mut device, |_, device, _| device.commands
                [initial..]
                .iter()
                .any(|command| command.1 == 0x5c)));
        }
        device.inject(wifi.radio().rom().unwrap(), &report(44));
        assert!(
            run(&mut wifi, &mut device, |_, device, _| device.commands
                [initial..]
                .iter()
                .any(|command| command.1 == 0x5c)),
            "format {version}, system {system}: {:?}",
            wifi.radio().error()
        );
        let reductions = device
            .commands
            .iter()
            .filter(|command| command.1 == 0x5c)
            .count();
        device.inject(wifi.radio().rom().unwrap(), &report(0));
        assert!(!run(&mut wifi, &mut device, |_, device, _| device
            .commands
            .iter()
            .filter(|command| command.1 == 0x5c)
            .count()
            > reductions));
        device.inject(wifi.radio().rom().unwrap(), &report(70));
        assert!(run(&mut wifi, &mut device, |_, device, _| device
            .commands
            .iter()
            .filter(|command| command.1 == 0x5c)
            .count()
            > reductions));
        assert!(wifi.carrier());
        if system {
            assert_eq!(
                device
                    .commands
                    .iter()
                    .filter(|&&command| command == (2, 0x0f))
                    .count(),
                2,
                "the two initial statistics commands do not repeat"
            );
        }
    }
}

#[test]
fn bluetooth_gets_its_channel_inhibited_and_a_strong_ap_less_power() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    let commands = device.commands.len();
    device.inject(wifi.radio().rom().unwrap(), &bluetooth(3));
    let told = run(&mut wifi, &mut device, |_, device, _| {
        device.commands[commands..].iter().any(|c| c.1 == 0x5d)
    });
    assert!(told, "{:?}", &device.commands[commands..]);
    // A strong AP data frame is not the firmware's beacon-filter statistic.
    let (frame, reorder) = protected(5, 5, 1, 1, false, false);
    let frame = placed(frame, 3 | 2 << 8 | 1 << 6, None, reorder);
    device.inject(wifi.radio().rom().unwrap(), &frame);
    assert!(!run(&mut wifi, &mut device, |_, device, _| device.commands
        [commands..]
        .iter()
        .any(|c| c.1 == 0x5c)));
    let image = coex_image(2);
    let firmware = crate::wifi::intel::firmware::Firmware::parse(&image).unwrap();
    assert!(firmware.command_version(2, 0x0f).is_none());
    assert!(!firmware.supports_api(35));
    // AX200's multi-queue API and old statistics API select the complete v11
    // notification. The original C declaration puts MAC ID at 252 and energy
    // at 584; zero initialization selects this station's MAC 0.
    device.inject(
        wifi.radio().rom().unwrap(),
        &legacy_beacon_statistics(0, 44),
    );
    let reduced = run(&mut wifi, &mut device, |_, device, _| {
        device.commands[commands..].iter().any(|c| c.1 == 0x5c)
    });
    assert!(reduced, "{:?}", &device.commands[commands..]);
}

#[test]
fn busy_bluetooth_tells_the_ap_of_sm_power_save_and_narrows_the_phy() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native {
        host_chains: true,
        ..Native::default()
    };
    let (mut wifi, mut device) = connect(&native, true);
    let phys = device.commands.iter().filter(|c| c.1 == 8).count();
    device.inject(wifi.radio().rom().unwrap(), &bluetooth(3));
    let told = run(&mut wifi, &mut device, |_, device, _| {
        device.air.iter().any(|frame| frame[24..] == [7, 1, 1])
    });
    assert!(told, "{:?}", wifi.radio().error());
    let narrowed = run(&mut wifi, &mut device, |_, device, _| {
        device.commands.iter().filter(|c| c.1 == 8).count() > phys
    });
    assert!(narrowed, "{:?}", wifi.radio().error());
    device.inject(wifi.radio().rom().unwrap(), &bluetooth(0));
    let eased = run(&mut wifi, &mut device, |_, device, _| {
        device.air.iter().any(|frame| frame[24..] == [7, 1, 0])
    });
    assert!(eased, "{:?}", wifi.radio().error());
}

/// Firmware's report that `country` applies, from `source`.
fn country_update(country: [u8; 2], source: u8) -> Vec<u8> {
    let update = Id {
        group: 0,
        opcode: 0xc9,
        version: 0,
    };
    command_packet(update, 0x8000, &[country[1], country[0], source, 0])
}

#[test]
fn a_platform_country_replaces_the_rules_an_associated_station_keeps_to() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect_in(&native, None, false);
    assert_eq!(wifi.radio().rules(), Some(WORLD));
    device.inject(wifi.radio().rom().unwrap(), &country_update(*b"US", 1));
    let taken = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().rules() == Some(*b"US")
    });
    assert!(taken, "{:?}", wifi.radio().error());
    assert_eq!(device.countries.last(), Some(b"US"));
    // The channel stays, so the rules' minute changes nothing.
    wifi.radio_mut().end_country_grace();
    let left = run(&mut wifi, &mut device, |_, _, up| !up);
    assert!(!left, "{:?}", wifi.radio().error());
}

#[test]
fn a_link_the_new_rules_bar_goes_after_the_rules_minute() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect_in(&native, None, false);
    device.channel = 0;
    device.second = Some(0);
    device.inject(wifi.radio().rom().unwrap(), &country_update(*b"US", 1));
    let taken = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().rules() == Some(*b"US")
    });
    assert!(taken, "{:?}", wifi.radio().error());
    assert!(wifi.carrier(), "the minute has not passed");
    wifi.radio_mut().end_country_grace();
    let left = run(&mut wifi, &mut device, |_, _, up| !up);
    assert!(left, "{:?}", wifi.radio().error());
}

#[test]
fn a_configured_country_stands_against_firmwares_report() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    let asked = device.countries.len();
    device.inject(wifi.radio().rom().unwrap(), &country_update(WORLD, 1));
    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0xab; 46]].concat();
    wifi.transmit(&ethernet).unwrap();
    let sent = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 4);
    assert!(sent, "{:?}", wifi.radio().error());
    assert_eq!(device.countries.len(), asked);
    assert_eq!(wifi.radio().rules(), Some(*b"US"));
}

#[test]
fn a_wmm_ap_gets_each_class_on_its_tids_queue() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    // The handshake's voice-class frames took their TID's queue.
    let queues = device.queues.len();
    assert!(queues >= 2, "{:?}", device.queues);
    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0x45], &[0; 45]].concat();
    wifi.transmit(&ethernet).unwrap();
    let sent = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 4);
    assert!(sent, "{:?}", wifi.radio().error());
    // Best effort, a TID of its own.
    assert_eq!(device.air[4][0], 0x88);
    assert_eq!(device.air[4][24], 0);
    assert_eq!(device.queues.len(), queues + 1);
}

#[test]
fn a_block_ack_session_is_agreed_with_the_firmware_first() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (_, device) = agreed(&native);
    let command = &device.block_acks[0];
    assert_eq!(command[..4], [0, 0, 0, 0]);
    assert_eq!(command[4], 1);
    assert_eq!(command[8], 0);
    assert_eq!(command[12..14], 5u16.to_le_bytes());
    assert_eq!(command[14..16], 8u16.to_le_bytes());
    let response = device.air.last().unwrap();
    // The dialog, success, and the window with A-MSDU permission.
    assert_eq!(response[26], 9);
    assert_eq!(response[27..29], [0, 0]);
    let parameters = u16::from_le_bytes([response[29], response[30]]);
    assert_eq!(parameters >> 6, 8);
    assert_eq!(parameters & 1, 1);
}

#[test]
fn a_session_gives_the_station_its_frames_in_order() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = agreed(&native);
    device.inject(wifi.radio().rom().unwrap(), &session_frame(6, 5, 2, 0x66));
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), []);
    device.inject(wifi.radio().rom().unwrap(), &session_frame(5, 7, 1, 0x55));
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), [0x55, 0x66]);
    // The firmware gives up on 7.
    device.inject(wifi.radio().rom().unwrap(), &session_frame(8, 7, 3, 0x88));
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), []);
    let release = Id {
        group: 0,
        opcode: 0xc3,
        version: 0,
    };
    device.inject(
        wifi.radio().rom().unwrap(),
        &command_packet(release, 0x8000, &[SESSION, 0, 9, 0]),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), [0x88]);
}

#[test]
fn a_firmware_split_amsdu_reaches_the_station_whole_under_one_packet_number() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    let status = 3 | 2 << 8 | 1 << 6;
    for (index, value, last) in [(0, 0x11, false), (1, 0x22, false), (2, 0x33, true)] {
        let (frame, _) = protected(5, 6, 1, value, true, false);
        device.inject(
            wifi.radio().rom().unwrap(),
            &placed(frame, status, Some((index, last)), 127 << 24),
        );
    }
    settle(&mut wifi, &mut device);
    let mut sources = Vec::new();
    while let Some(ethernet) = wifi.receive().unwrap() {
        assert_eq!(ethernet[..6], LOCAL);
        sources.push(ethernet[11]);
    }
    assert_eq!(sources, [0x11, 0x22, 0x33]);
    // The same MPDU retried, and one that replays its packet number, go.
    let (frame, _) = protected(5, 6, 1, 0x44, false, true);
    device.inject(
        wifi.radio().rom().unwrap(),
        &placed(frame, status, None, 127 << 24),
    );
    let (frame, _) = protected(6, 7, 1, 0x55, false, false);
    device.inject(
        wifi.radio().rom().unwrap(),
        &placed(frame, status, None, 127 << 24),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), []);
}

#[test]
fn an_amsdu_missing_a_record_is_lost_whole() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    let status = 3 | 2 << 8 | 1 << 6;
    for (index, last) in [(0, false), (2, true)] {
        let (frame, _) = protected(5, 6, 1, 0x11, true, false);
        device.inject(
            wifi.radio().rom().unwrap(),
            &placed(frame, status, Some((index, last)), 127 << 24),
        );
    }
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), []);
}

#[test]
fn a_peer_ending_a_session_releases_what_it_held() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = agreed(&native);
    device.inject(wifi.radio().rom().unwrap(), &session_frame(7, 5, 3, 0x77));
    device.inject(wifi.radio().rom().unwrap(), &session_frame(6, 5, 2, 0x66));
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), []);
    // DELBA from the initiator of TID 0.
    device.inject(
        wifi.radio().rom().unwrap(),
        &answer(LOCAL, 0xd0, &[3, 2, 0, 0x08, 37, 0]),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), [0x66, 0x77]);
    let removal = device.block_acks.last().unwrap();
    assert_eq!(removal[..4], 2u32.to_le_bytes());
    // This firmware's command version names the session.
    assert_eq!(removal[4], SESSION);
    assert!(wifi.radio().station().active_rx_block_ack(0).is_none());
}

#[test]
fn a_departure_takes_its_sessions_down_without_telling_the_peer() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = agreed(&native);
    let sent = device.air.len();
    device.inject(wifi.radio().rom().unwrap(), &answer(LOCAL, 0xc0, &[3, 0]));
    let left = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().stage() == Standing::Idle
    });
    assert!(left, "{:?}", wifi.radio().error());
    assert_eq!(device.block_acks.len(), 2);
    assert_eq!(device.block_acks[1][..4], 2u32.to_le_bytes());
    assert!(!device.air[sent..].iter().any(|frame| frame[0] == 0xd0));
}

#[test]
fn block_ack_notifications_alone_free_the_queues() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    device.aggregating = true;
    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0x45], &[0; 45]].concat();
    // More than the ring holds.
    for _ in 0..6 {
        let goal = device.air.len() + 60;
        for _ in 0..60 {
            wifi.transmit(&ethernet).unwrap();
        }
        let sent = run(&mut wifi, &mut device, |_, device, _| {
            device.air.len() >= goal
        });
        assert!(sent, "{} {:?}", device.air.len(), wifi.radio().error());
    }
}

#[test]
fn frames_that_wait_together_leave_as_an_amsdu_the_firmware_allows() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    let rates = Id {
        group: 5,
        opcode: 0xf7,
        version: 0,
    };
    let mut body = [0; 20];
    body[4] = 2;
    body[12..14].copy_from_slice(&2200u16.to_le_bytes());
    body[16] = 1;
    device.inject(
        wifi.radio().rom().unwrap(),
        &command_packet(rates, 0x8000, &body),
    );
    settle(&mut wifi, &mut device);
    let sent = device.air.len();
    // TID 0 has no queue yet, so all three wait; the third does not fit.
    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0x45], &[0; 999]].concat();
    for _ in 0..3 {
        wifi.transmit(&ethernet).unwrap();
    }
    let gone = run(&mut wifi, &mut device, |_, device, _| {
        device.air.len() >= sent + 2
    });
    assert!(gone, "{:?}", wifi.radio().error());
    settle(&mut wifi, &mut device);
    assert_eq!(device.air.len(), sent + 2);
    let aggregate = &device.air[sent];
    assert_eq!(aggregate[24] & 0x80, 0x80);
    assert_eq!(aggregate[16..22], AP);
    assert_eq!(aggregate[26..32], [9; 6]);
    assert_eq!(aggregate[32..38], LOCAL);
    let length: usize = 1000 + 8;
    assert_eq!(aggregate[38..40], (length as u16).to_be_bytes());
    let second = 26 + (14 + length).next_multiple_of(4);
    assert_eq!(aggregate[second..second + 6], [9; 6]);
    assert_eq!(aggregate.len(), second + 14 + length);
    // The third keeps its one sequence number after theirs.
    let sequence = |frame: &[u8]| u16::from_le_bytes([frame[22], frame[23]]) >> 4;
    assert_eq!(sequence(&device.air[sent + 1]), sequence(aggregate) + 1);
    assert_eq!(device.air[sent + 1][24] & 0x80, 0);
}

#[test]
fn an_amsdu_stops_short_of_firmwares_fifo() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    native
        .transmit_fifo
        .store(1500 + 256, core::sync::atomic::Ordering::Relaxed);
    let (mut wifi, mut device) = connect(&native, true);
    let rates = Id {
        group: 5,
        opcode: 0xf7,
        version: 0,
    };
    let mut body = [0; 20];
    body[4] = 2;
    body[12..14].copy_from_slice(&2200u16.to_le_bytes());
    body[16] = 1;
    device.inject(
        wifi.radio().rom().unwrap(),
        &command_packet(rates, 0x8000, &body),
    );
    settle(&mut wifi, &mut device);
    let sent = device.air.len();
    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0x45], &[0; 999]].concat();
    for _ in 0..2 {
        wifi.transmit(&ethernet).unwrap();
    }
    let gone = run(&mut wifi, &mut device, |_, device, _| {
        device.air.len() >= sent + 2
    });
    assert!(gone, "{:?}", wifi.radio().error());
    assert_eq!(device.air[sent][24] & 0x80, 0);
    assert_eq!(device.air[sent + 1][24] & 0x80, 0);
}

/// A protected frame's fragment `index` of sequence 5, under packet number
/// `number`, carrying `body` straight after its header.
fn fragment(index: u8, more: bool, number: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 26];
    frame[0] = 0x88;
    frame[1] = 0x42 | u8::from(more) << 2;
    frame[4..10].copy_from_slice(&LOCAL);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[22..24].copy_from_slice(&(5u16 << 4 | u16::from(index)).to_le_bytes());
    frame.extend([number, 0, 0, 0x20, 0, 0, 0, 0]);
    frame.extend(body);
    mpdu(frame, 3 | 2 << 8 | 1 << 6)
}

fn first_body() -> Vec<u8> {
    [&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0][..], &[0x11; 40]].concat()
}

/// `ieee80211_rx_handlers`: a frame the receive path cannot take is dropped
/// and counted, and the good frame beside it still arrives; the link never
/// reports a refused frame as a fault.
#[test]
fn a_refused_frame_is_dropped_and_counted_and_the_next_one_arrives() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    let before = wifi.radio().dropped_frames();
    // Too short to hold even an 802.11 header.
    device.inject(
        wifi.radio().rom().unwrap(),
        &mpdu(vec![0x08, 0x02, 0, 0], 3),
    );
    device.inject(
        wifi.radio().rom().unwrap(),
        &data(LOCAL, false, [8, 0], &[0x45; 46], Some((0, 1))),
    );
    settle(&mut wifi, &mut device);
    let ethernet = wifi.receive().unwrap().expect("the good frame");
    assert_eq!(ethernet[12..14], [8, 0]);
    assert_eq!(wifi.radio().dropped_frames(), before + 1);
    assert_eq!(wifi.receive(), Ok(None));
    assert!(wifi.carrier());
}

#[test]
fn fragments_under_consecutive_packet_numbers_become_one_msdu() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(0, true, 1, &first_body()),
    );
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(1, true, 2, &[0x22; 20]),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(wifi.receive().unwrap(), None);
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(2, false, 3, &[0x33; 10]),
    );
    settle(&mut wifi, &mut device);
    let ethernet = wifi.receive().unwrap().expect("the whole MSDU");
    assert_eq!(ethernet[12..14], [8, 0]);
    assert_eq!(ethernet.len(), 14 + 40 + 20 + 10);
    assert_eq!(ethernet[14], 0x11);
    assert_eq!(ethernet[14 + 40], 0x22);
    assert_eq!(ethernet[14 + 60], 0x33);
}

#[test]
fn a_fragment_out_of_its_place_or_its_packet_numbers_is_dropped() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    // With nothing before it.
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(1, false, 1, &[0x22; 20]),
    );
    // A packet number skipped.
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(0, true, 2, &first_body()),
    );
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(1, false, 4, &[0x22; 20]),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(wifi.receive().unwrap(), None);
}

#[test]
fn a_scan_probes_where_a_frame_may_start_and_listens_elsewhere() {
    if crate::test_process::isolate_model() {
        return;
    }
    const FORCE_PASSIVE: u8 = 8;
    let native = Native::default();
    let (_, phase, device) = raise(&native, Some(*b"US"), vec![b"test"], 0, OPEN, true);
    assert_eq!(phase, Phase::AuthenticationRequired);
    let scan = &device.scans[0];
    assert_eq!(scan[9] & FORCE_PASSIVE, 0);
    assert_eq!(scan[48], 1, "the channel probes the wildcard SSID");
    let band = u16::from_le_bytes([scan[602], scan[603]]);
    assert!(usize::from(band) > 26, "rates, DS parameters and HT");

    let native = Native::default();
    let silent = OPEN & !8;
    let (_, phase, device) = raise(&native, Some(*b"US"), vec![b"test"], 0, silent, true);
    assert_eq!(phase, Phase::AuthenticationRequired);
    let scan = &device.scans[0];
    assert_eq!(scan[9] & FORCE_PASSIVE, FORCE_PASSIVE);
    assert_eq!(scan[48], 0);
}

#[test]
fn a_network_one_scan_part_heard_outlives_the_parts_after_it() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (_, phase, device) = raise_split(
        &native,
        Some(*b"US"),
        vec![b"test"],
        0,
        OPEN,
        true,
        &[],
        Some(OPEN & !8),
    );
    assert_eq!(device.scans.len(), 2);
    assert_eq!(phase, Phase::AuthenticationRequired);
}

/// An AP's HE capabilities, one stream with its ACK and HTC bits, then its
/// operation: 3 us packet extension, RTS threshold 5, color 9. Random access
/// and MU EDCA parameters follow it.
#[rustfmt::skip]
const HE_AP: [u8; 2 + 22 + 2 + 7 + 4 + 16] = [
    255, 22, 35,
    0x01, 0, 0x80, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0xfe, 0xff, 0xfe, 0xff,
    255, 7, 36, 0x53, 0, 0, 9, 0xfc, 0xff,
    255, 2, 37, 0x2b,
    255, 14, 38, 0,
    1, 0x95, 3,
    2, 0xa4, 4,
    3, 0xb3, 5,
    4, 0xc2, 6,
];

#[test]
fn an_he_ap_reaches_the_link_and_the_station_commands() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, phase, mut device) =
        raise_beside(&native, Some(*b"US"), vec![b"test"], 0, OPEN, true, &HE_AP);
    assert_eq!(phase, Phase::AuthenticationRequired);
    let associated = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().station().phase() == Peering::Associated
    });
    assert!(associated, "{:?}", wifi.radio().station().phase());
    assert!(run(&mut wifi, &mut device, |_, device, _| {
        device.configuration.len() >= 2
    }));
    let (_, link) = device
        .configuration
        .iter()
        .rfind(|(opcode, _)| *opcode == 9)
        .unwrap();
    assert_eq!(link[100..103], [3, 3, 5], "packet extension and OCW range");
    // The BE record arrives first and the firmware orders BK first.
    assert_eq!(link[104..112], [4, 0, 10, 0, 2, 0, 4, 0]);
    assert_eq!(link[112..120], [5, 0, 9, 0, 1, 0, 3, 0]);
    assert_eq!(link[146], 5, "the RTS threshold");
    assert_eq!(link[148], 2, "MU EDCA, with the color enabled");
    assert_eq!(link[152], 2, "the mask of a firmware that still has one");
    assert_eq!(link[165], 9);
    assert_eq!(link[156..162], [0; 6]);
    let (_, peer) = device
        .configuration
        .iter()
        .rfind(|(opcode, _)| *opcode == 0x0a)
        .unwrap();
    assert_eq!(peer[48], 1, "the AP's HE acknowledgements");
    assert_eq!(peer[52], 1, "random access");
    assert_eq!(peer[72..92], [7; 20], "zero nominal padding");
    assert_eq!(peer[92], 1, "HE-HTC");
}

/// A Multiple BSSID set naming the network the model's AP joins as index 1,
/// with `extra` in its profile, and what makes [`HE_AP`] a set member.
fn multiple_bssid(extra: &[u8]) -> Vec<u8> {
    let mut profile = vec![83, 2, 0x31, 0, 85, 3, 1, 3, 2, 0, 4];
    profile.extend(b"test");
    profile.extend(extra);
    let mut set = vec![71, profile.len() as u8 + 3, 3, 0, profile.len() as u8];
    set.extend(profile);
    set.extend(HE_AP);
    set
}

#[test]
fn a_nontransmitted_bss_joins_on_its_profile_and_names_its_transmitter() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let elements: &'static [u8] = Vec::leak(multiple_bssid(&[]));
    let (mut wifi, phase, mut device) =
        raise_beside(&native, Some(*b"US"), vec![b"top"], 0, OPEN, true, elements);
    assert_eq!(phase, Phase::AuthenticationRequired);
    let associated = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().station().phase() == Peering::Associated
    });
    assert!(associated, "{:?}", wifi.radio().station().phase());
    assert_eq!(device.air[0][4..10], AP, "the profile's own address");
    assert_eq!(device.air[1][28..34], [0, 4, b't', b'e', b's', b't']);
    let extended = [127, 9, 4, 0, 0x40, 0, 0, 0, 0, 0xc0, 1];
    let request = &device.air[1];
    assert!(request.windows(extended.len()).any(|at| at == extended));
    assert!(run(&mut wifi, &mut device, |_, device, _| {
        device.configuration.len() >= 2
    }));
    let (_, link) = device
        .configuration
        .iter()
        .rfind(|(opcode, _)| *opcode == 9)
        .unwrap();
    assert_eq!(link[156..162], TRANSMITTER);
    assert_eq!(link[164], 1);
    assert_eq!(word(link, 140), 300, "the profile's DTIM period");
}

#[test]
fn a_nontransmitted_bss_hears_its_transmitter_announce_a_quiet_switch() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let elements: &'static [u8] = Vec::leak(multiple_bssid(&[]));
    let (mut wifi, _, mut device) =
        raise_beside(&native, Some(*b"US"), vec![b"top"], 0, OPEN, true, elements);
    let associated = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().station().phase() == Peering::Associated
    });
    assert!(associated, "{:?}", wifi.radio().station().phase());
    settle(&mut wifi, &mut device);
    let commands = device.commands.len();
    // The switch element is the set's, which every member inherits.
    let announcement: &[u8] = &[37, 3, 1, 2, 5];
    let mut with = elements.to_vec();
    with.extend(announcement);
    device.inject(
        wifi.radio().rom().unwrap(),
        &beacon(b"top", &RSN, true, &with),
    );
    let timed = run(&mut wifi, &mut device, |_, device, _| {
        device.commands[commands..].contains(&(3, 4))
    });
    assert!(timed, "{:?}", wifi.radio().error());
    assert!(wifi.radio().silent());
}

/// An SA Query request from the other link to `receiver` under the pairwise
/// key at packet number `number`.
fn sa_query(receiver: Mac, number: u8) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[..2].copy_from_slice(&[0xd0, 0x40]);
    frame[4..10].copy_from_slice(&receiver.0);
    frame[10..16].copy_from_slice(&OTHER);
    frame[16..22].copy_from_slice(&OTHER);
    frame.extend([number, 0, 0, 0x20, 0, 0, 0, 0]);
    frame.extend([8, 0, 1, 2]);
    placed_at(frame, 3 | 2 << 8 | 1 << 6, None, 127 << 24, [44, 56, 36])
}

#[test]
fn a_protected_management_frame_is_taken_once_under_its_packet_number() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, local, _) = moved_mld(&native);
    let answers = |device: &Device<'_>| {
        device
            .air
            .iter()
            .filter(|frame| frame.windows(4).any(|at| at == [8, 1, 1, 2]))
            .count()
    };
    device.inject(wifi.radio().rom().unwrap(), &sa_query(local, 5));
    let answered = run(&mut wifi, &mut device, |_, device, _| answers(device) == 1);
    assert!(answered, "{:?}", wifi.radio().error());
    device.inject(wifi.radio().rom().unwrap(), &sa_query(local, 5));
    assert!(!run(&mut wifi, &mut device, |_, device, _| answers(device) > 1));
    device.inject(wifi.radio().rom().unwrap(), &sa_query(local, 6));
    let answered = run(&mut wifi, &mut device, |_, device, _| answers(device) == 2);
    assert!(answered, "{:?}", wifi.radio().error());
}

/// The AP MLD the model's AP is link 3 of.
const AP_MLD: [u8; 6] = [2, 10, 11, 12, 13, 14];
/// The address [`FixedEntropy`] draws for the station's link.
const LINK: [u8; 6] = [0x5a; 6];
/// [`RSN`] under SAE with management frame protection required.
/// The AP on the other link of the AP MLD.
const OTHER: [u8; 6] = [2, 3, 4, 5, 6, 8];
const RSN_SAE: [u8; 22] = [
    48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 8, 0xc0, 0,
];
/// An AP's EHT capabilities and operation, one stream at every MCS.
#[rustfmt::skip]
const EHT_AP: [u8; 2 + 15 + 2 + 6] = [
    255, 15, 108,
    0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x11, 0x11, 0x11,
    255, 6, 106, 0, 0x11, 0, 0, 0,
];

/// [`HE_AP`] and [`EHT_AP`] as link 3 of [`AP_MLD`].
fn mld_ap() -> &'static [u8] {
    let mut elements = HE_AP.to_vec();
    elements.extend(EHT_AP);
    elements.extend(H2E_RSNXE);
    elements.extend(
        Basic {
            address: Mac(AP_MLD),
            link_id: Some(3),
            mld_capabilities: Some(0),
            ..Basic::default()
        }
        .encode(),
    );
    Box::leak(elements.into_boxed_slice())
}

/// The radio and AP MLD of `elements` ready to join over SAE.
fn raise_mld<'n>(
    native: &'n Native,
    elements: &'static [u8],
    other: bool,
) -> (Station<Model, ClockBios>, Device<'n>) {
    let eht = EhtLimits {
        dual_radio: false,
        stops_at_160: false,
        reduced: false,
        urm: false,
        slow_bus: false,
    };
    let (wifi, phase, mut device) = raise_as(
        native,
        Some(*b"US"),
        vec![b"test"],
        0,
        OPEN,
        true,
        elements,
        None,
        &RSN_SAE,
        Some(eht),
        Secret::parse(b"password").unwrap(),
        other,
    );
    assert_eq!(phase, Phase::AuthenticationRequired);
    device.receiver = LINK;
    let template = Template::derive(b"test", b"password", None);
    let mut random = 7;
    device.sae = Some(
        Exchange::new(
            Derivation::HashToElement,
            b"password",
            Some(&template),
            None,
            Mac(AP_MLD),
            Mac(LOCAL),
            &mut || {
                random += 1;
                [random; 32]
            },
        )
        .unwrap(),
    );
    (wifi, device)
}

/// The little-endian word of `bytes` at `at`.
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// An MLD station with its port open, moved to the other link, its address
/// there, and how many link and station commands came before the port.
fn moved_mld(native: &Native) -> (Station<Model, ClockBios>, Device<'_>, Mac, usize) {
    let (mut wifi, mut device) = raise_mld(native, linked_ap(240), true);
    let associated = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().station().phase() == Peering::Associated
    });
    assert!(associated, "{:?}", wifi.radio().error());
    let request = &device.air[2];
    let basic = Basic::find(&request[28..]).unwrap().unwrap();
    let local = basic.profiles[0].address.unwrap();
    let security = Security::select(&RSN_SAE, true).unwrap();
    let link = |link_id, local, ap| supplicant::Link {
        link_id,
        local,
        ap,
        rsn: RSN_SAE.to_vec(),
        rsnxe: Some(H2E_RSNXE.to_vec()),
        accepted: true,
    };
    let (setup, other) = (link(3, Mac(LINK), Mac(AP)), link(5, local, Mac(OTHER)));
    let mut ap = Authenticator::between(
        security.suites(),
        device.sae.as_ref().unwrap().pmk().unwrap(),
        Mac(AP_MLD),
        Mac(LOCAL),
        security.element(),
    )
    .naming_station_mld()
    .naming_links(core::slice::from_ref(&other));
    let eapol_key = |body: &[u8]| data(LINK, false, [0x88, 0x8e], body, None);
    let first = eapol_key(&ap.message_1());
    device.inject(wifi.radio().rom().unwrap(), &first);
    let answered = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 3);
    assert!(answered, "{:?}", wifi.radio().error());
    ap.message_2(eapol(&device.air[3]));
    let keys = [
        supplicant::tests::link_keys(3, 1, 0x50),
        supplicant::tests::link_keys(5, 1, 0x60),
    ]
    .concat();
    let third = eapol_key(&ap.mld_message_3(&[setup, other], &keys));
    device.inject(wifi.radio().rom().unwrap(), &third);
    let authorized = device.configuration.len();
    let moved = run(&mut wifi, &mut device, |_, device, _| {
        device.configuration[authorized..]
            .iter()
            .any(|(opcode, bytes)| *opcode == 9 && word(bytes, 0) == 3)
    });
    assert!(
        moved,
        "{:?} {:?}",
        wifi.radio().error(),
        device.commands.last()
    );
    assert!(wifi.carrier(), "the port stays open across the move");
    assert!(device.commands.contains(&(2, 0x0f)), "firmware reports");
    (wifi, device, local, authorized)
}

/// Firmware's report of its link and PHY 1, `air_us` used and the link heard
/// at `-energy` dBm.
fn report(stamp: u32, energy: u32, air_us: u32) -> Vec<u8> {
    let mut body = vec![0; 4 + 4 * 28 + 3 * 88 + 16 * 4];
    body[..4].copy_from_slice(&stamp.to_le_bytes());
    body[32..36].copy_from_slice(&energy.to_le_bytes());
    body[36..40].copy_from_slice(&air_us.to_le_bytes());
    let statistics = Id {
        group: 0x10,
        opcode: 0,
        version: 0,
    };
    command_packet(statistics, 0x8000, &body)
}

/// Firmware missed nine beacons in a row, and 600 rounds pass.
fn miss_beacons(wifi: &mut Station<Model, ClockBios>, device: &mut Device<'_>) {
    let missed = Id {
        group: 3,
        opcode: 0xf6,
        version: 0,
    };
    let mut body = [0; 20];
    body[4] = 9;
    body[8] = 9;
    device.inject(
        wifi.radio().rom().unwrap(),
        &command_packet(missed, 0x8000, &body),
    );
    assert!(!run(wifi, device, |_, device, _| device.scans.len() > 1));
}

/// A Reconfiguration element removing `links`, `timer` beacons from now.
fn removal(links: &[u8], timer: u16) -> Vec<u8> {
    let mut body = vec![107, 2, 0, 1];
    for link in links {
        body.extend([0, 5, *link | 0x40, 0, 3]);
        body.extend(timer.to_le_bytes());
    }
    [&[255, body.len() as u8][..], &body].concat()
}

/// A mapping of every TID to `links` from `switch_time` on.
fn mapping(links: u8, switch_time: u16) -> Vec<u8> {
    let mut element = vec![255, 13, 109, 2 | 0x08 | 0x20, 0xff];
    element.extend(switch_time.to_le_bytes());
    element.extend([links; 8]);
    element
}

#[test]
fn a_link_the_ap_removes_gives_way_to_the_other_for_good() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    let announced = device.configuration.len();
    device.inject(
        wifi.radio().rom().unwrap(),
        &announcing_beacon([60, 60], &removal(&[5], 0)),
    );
    assert!(
        lowered(&mut wifi, &mut device, announced),
        "{:?}",
        wifi.radio().error()
    );
    settle(&mut wifi, &mut device);
    assert_eq!(wifi.radio().link_count(), 1);
    assert!(wifi.carrier());
    let (_, new) = device.configuration[announced..]
        .iter()
        .find(|(opcode, bytes)| *opcode == 9 && word(bytes, 0) == 1)
        .unwrap();
    assert_eq!(new[166], 3);
}

#[test]
fn the_dormant_link_the_ap_removes_just_goes() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    let announced = device.configuration.len();
    device.inject(
        wifi.radio().rom().unwrap(),
        &announcing_beacon([60, 60], &removal(&[3], 0)),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(wifi.radio().link_count(), 1);
    assert!(links_since(&device, announced).is_empty());
    assert!(wifi.carrier());
}

#[test]
fn removing_every_link_ends_the_association() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    device.inject(
        wifi.radio().rom().unwrap(),
        &announcing_beacon([60, 60], &removal(&[3, 5], 0)),
    );
    run(&mut wifi, &mut device, |_, _, _| false);
    assert!(!wifi.carrier());
}

#[test]
fn an_advertised_mapping_moves_the_station_off_a_link_it_leaves_out_when_it_comes() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    let announced = device.configuration.len();
    device.inject(
        wifi.radio().rom().unwrap(),
        // Within the time a move is given to be ready.
        &announcing_beacon([60, 60], &mapping(1 << 3, 90)),
    );
    assert!(
        lowered(&mut wifi, &mut device, announced),
        "{:?}",
        wifi.radio().error()
    );
    settle(&mut wifi, &mut device);
    assert_eq!(wifi.radio().link_count(), 2, "it may yet come back");
    assert!(wifi.carrier());
    let (_, new) = device.configuration[announced..]
        .iter()
        .find(|(opcode, bytes)| *opcode == 9 && word(bytes, 0) == 1)
        .unwrap();
    assert_eq!(new[166], 3);
}

#[test]
fn an_mld_station_moves_to_its_better_link_and_back_before_it_leaves() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, local, authorized) = moved_mld(&native);
    // The other link comes up beside the first before the first goes.
    let links: Vec<(u32, u32, u32)> = device.configuration[authorized..]
        .iter()
        .filter(|(opcode, _)| *opcode == 9)
        .map(|(_, bytes)| (word(bytes, 0), word(bytes, 4), word(bytes, 24)))
        .collect();
    let position = |wanted: (u32, u32, u32)| {
        links
            .iter()
            .position(|link| *link == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} in {links:?}"))
    };
    let added = position((1, 1, 0));
    let quiet = position((2, 0, 1));
    let active = position((2, 1, 1));
    let removed = position((3, 0, 0));
    assert!(
        added < quiet && quiet < active && active < removed,
        "{links:?}"
    );
    let (_, new) = device.configuration[authorized..]
        .iter()
        .find(|(opcode, bytes)| *opcode == 9 && word(bytes, 0) == 1)
        .unwrap();
    assert_eq!(new[16..22], local.0);
    assert_eq!(new[166], 5);
    let (_, peer) = device.configuration[authorized..]
        .iter()
        .rfind(|(opcode, _)| *opcode == 0x0a)
        .unwrap();
    assert_eq!(word(peer, 0), 1, "the other firmware station");
    assert_eq!(peer[8..14], AP_MLD);
    assert_eq!(peer[16..22], OTHER);
    // It goes back, and everything of the chain's is where the chain left it.
    let back = device.configuration.len();
    wifi.radio_mut().deauthenticate(3).unwrap();
    let left = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().stage() == Standing::Idle
    });
    assert!(left, "{:?}", wifi.radio().error());
    let returned: Vec<&Vec<u8>> = device.configuration[back..]
        .iter()
        .filter(|(opcode, bytes)| *opcode == 9 && word(bytes, 0) == 1)
        .map(|(_, bytes)| bytes)
        .collect();
    let [link, cold] = &returned[..] else {
        panic!("{} links added", returned.len());
    };
    assert_eq!(link[16..22], LINK);
    assert_eq!(link[166], 3);
    assert_eq!(cold[16..22], LOCAL);
    assert!(
        device.configuration[back..]
            .iter()
            .any(|(opcode, bytes)| *opcode == 9 && word(bytes, 0) == 3 && word(bytes, 4) == 1),
        "the other link went"
    );
}

#[test]
fn a_station_that_stops_hearing_its_link_listens_to_both_and_takes_the_better() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    miss_beacons(&mut wifi, &mut device);
    assert_eq!(device.scans.len(), 1, "a link just activated stays 5 s");
    device.other.as_mut().unwrap().0 = other_beacon([90, 90]);
    device.elements = linked_ap(0);
    let back = device.configuration.len();
    wifi.radio_mut().end_link_blockout();
    let moved = run(&mut wifi, &mut device, |_, device, _| {
        device.configuration[back..]
            .iter()
            .any(|(opcode, bytes)| *opcode == 9 && word(bytes, 0) == 3)
    });
    assert!(
        moved,
        "{:?} {:?}",
        wifi.radio().error(),
        device.commands.last()
    );
    // A passive look from the firmware link in use, at both links' channels.
    let scan = &device.scans[1];
    assert_eq!(scan[8] & 2, 2, "whatever it hears");
    assert_eq!(scan[9] & 0x0a, 0x0a, "passive, and saying when it starts");
    assert_eq!(scan[11], 1);
    assert_eq!(scan[45], 2);
    assert_eq!((scan[52], scan[60]), (36, 1));
    // The setup link is back beside the other before the other goes.
    let links: Vec<(u32, u32, u32)> = device.configuration[back..]
        .iter()
        .filter(|(opcode, _)| *opcode == 9)
        .map(|(_, bytes)| (word(bytes, 0), word(bytes, 4), word(bytes, 24)))
        .collect();
    assert_eq!(links[0], (1, 0, 0));
    assert_eq!(links.last(), Some(&(3, 1, 0)), "{links:?}");
    assert!(wifi.carrier());
}

/// Firmware's report of its links and PHYs: `seats` holds, for each, the
/// signal, then how much of its channel others take.
fn seats_report(stamp: u32, seats: [(u32, u32); 2]) -> Vec<u8> {
    let mut body = vec![0; 4 + 4 * 28 + 3 * 88 + 16 * 4];
    body[..4].copy_from_slice(&stamp.to_le_bytes());
    for (seat, (energy, load)) in seats.into_iter().enumerate() {
        let (link, phy) = (4 + seat * 28, 4 + 4 * 28 + seat * 88);
        body[link..link + 4].copy_from_slice(&energy.to_le_bytes());
        body[phy + 8..phy + 12].copy_from_slice(&load.to_le_bytes());
    }
    let statistics = Id {
        group: 0x10,
        opcode: 0,
        version: 0,
    };
    command_packet(statistics, 0x8000, &body)
}

/// An EMLSR association: moved to its better link, it heard both strong and
/// took traffic, and both links are active.
fn emlsr_mld(native: &Native) -> (Station<Model, ClockBios>, Device<'_>, usize) {
    let (mut wifi, mut device, _, _) = moved_mld(native);
    device.other.as_mut().unwrap().0 = other_beacon([40, 40]);
    device.elements = linked_ap(128);
    device.inject(
        wifi.radio().rom().unwrap(),
        &seats_report(1_000_000, [(0, 0), (44, 100)]),
    );
    run(&mut wifi, &mut device, |_, _, _| false);
    let entered = device.configuration.len();
    wifi.radio_mut().end_throughput_block();
    wifi.radio_mut().end_link_blockout();
    let scanned = run(&mut wifi, &mut device, |_, device, _| {
        device.scans.len() > 1
            && device.configuration[entered..]
                .iter()
                .any(|(opcode, bytes)| *opcode == 9 && word(bytes, 0) == 1)
    });
    assert!(
        scanned,
        "{:?} {:?}",
        wifi.radio().error(),
        device.commands.last()
    );
    assert!(
        !lowered(&mut wifi, &mut device, entered),
        "the first link stays: {:?}",
        wifi.radio().error()
    );
    (wifi, device, entered)
}

/// Link operations after `from`: operation, link, active.
fn links_since(device: &Device<'_>, from: usize) -> Vec<(u32, u32, u32)> {
    device.configuration[from..]
        .iter()
        .filter(|(opcode, _)| *opcode == 9)
        .map(|(_, bytes)| (word(bytes, 0), word(bytes, 4), word(bytes, 24)))
        .collect()
}

/// A link is removed after `from`.
fn lowered(wifi: &mut Station<Model, ClockBios>, device: &mut Device<'_>, from: usize) -> bool {
    run(wifi, device, |_, device, _| {
        links_since(device, from)
            .iter()
            .any(|&(operation, _, _)| operation == 3)
    })
}

/// A notification of firmware group `group`.
fn notify(group: u8, opcode: u8, body: &[u8]) -> Vec<u8> {
    let id = Id {
        group,
        opcode,
        version: 0,
    };
    command_packet(id, 0x8000, body)
}

#[test]
fn a_busy_mld_station_with_two_strong_links_keeps_both_active_and_returns_before_it_leaves() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, entered) = emlsr_mld(&native);
    let links = links_since(&device, entered);
    assert_eq!(links[0], (1, 0, 0), "{links:?}");
    assert!(links.contains(&(2, 0, 1)), "{links:?}");
    assert!(
        !links.iter().any(|&(operation, _, _)| operation == 3),
        "{links:?}"
    );
    assert!(wifi.carrier());
    assert!(wifi.radio().emlsr_active());
    // The AP's transition reaches firmware with the association's MAC.
    let mac = device
        .configuration
        .iter()
        .rev()
        .find(|(opcode, bytes)| *opcode == 8 && word(bytes, 40) != 0)
        .unwrap();
    assert_eq!(mac.1[37..40], [6, 0x45, 0x23]);
    let left = device.configuration.len();
    wifi.radio_mut().deauthenticate(3).unwrap();
    let gone = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().stage() == Standing::Idle
    });
    assert!(gone, "{:?}", wifi.radio().error());
    let links = links_since(&device, left);
    assert!(links.contains(&(3, 1, 0)), "{links:?}");
    assert!(!wifi.radio().emlsr_active());
}

#[test]
fn a_fading_link_ends_emlsr_and_the_other_stays() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _) = emlsr_mld(&native);
    let exit = device.configuration.len();
    device.inject(
        wifi.radio().rom().unwrap(),
        &seats_report(2_000_000, [(80, 60), (44, 60)]),
    );
    assert!(
        lowered(&mut wifi, &mut device, exit),
        "{:?}",
        wifi.radio().error()
    );
    let links = links_since(&device, exit);
    assert!(links.contains(&(3, 0, 0)), "{links:?}");
    assert_eq!(leaving_block_tx(&device, exit), 0);
    assert!(wifi.carrier());
    assert!(!wifi.radio().emlsr_active());
}

#[test]
fn firmware_asking_to_leave_ends_emlsr_on_the_primary_link() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _) = emlsr_mld(&native);
    let exit = device.configuration.len();
    device.inject(wifi.radio().rom().unwrap(), &notify(5, 0xf3, &[0; 4]));
    assert!(lowered(&mut wifi, &mut device, exit));
    assert!(links_since(&device, exit).contains(&(3, 0, 0)));
    assert!(!wifi.radio().emlsr_active());
}

#[test]
fn a_link_that_misses_its_beacons_gives_way_to_the_other() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _) = emlsr_mld(&native);
    let exit = device.configuration.len();
    let mut body = [0; 20];
    body[0] = 1;
    body[8] = 15;
    body[16] = 1;
    device.inject(wifi.radio().rom().unwrap(), &notify(3, 0xf6, &body));
    assert!(lowered(&mut wifi, &mut device, exit));
    assert!(links_since(&device, exit).contains(&(3, 1, 0)));
    assert!(wifi.carrier());
    assert!(!wifi.radio().emlsr_active());
}

#[test]
fn a_failed_activation_falls_back_to_the_link_firmware_names() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _) = emlsr_mld(&native);
    let exit = device.configuration.len();
    let mut body = [0; 8];
    body[0] = 1;
    body[4] = 1;
    device.inject(wifi.radio().rom().unwrap(), &notify(3, 0xf7, &body));
    assert!(lowered(&mut wifi, &mut device, exit));
    assert!(links_since(&device, exit).contains(&(3, 0, 0)));
    assert!(wifi.carrier());
}

#[test]
fn a_failed_deactivation_loses_the_connection() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _) = emlsr_mld(&native);
    let mut body = [0; 8];
    body[0] = 1;
    device.inject(wifi.radio().rom().unwrap(), &notify(3, 0xf7, &body));
    let lost = run(&mut wifi, &mut device, |_, _, up| !up);
    assert!(lost, "{:?}", wifi.radio().error());
}

/// `block_tx` of the deactivation after `exit`.
fn leaving_block_tx(device: &Device<'_>, exit: usize) -> u8 {
    device.configuration[exit..]
        .iter()
        .find(|(opcode, bytes)| {
            *opcode == 9 && word(bytes, 0) == 2 && word(bytes, 24) == 1 && word(bytes, 28) == 0
        })
        .unwrap()
        .1[32]
}

#[test]
fn firmware_sends_nothing_on_an_emlsr_link_a_quiet_switch_takes() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _) = emlsr_mld(&native);
    let exit = device.configuration.len();
    device.inject(
        wifi.radio().rom().unwrap(),
        &announcing_beacon([60, 60], &[37, 3, 1, 36, 5]),
    );
    assert!(
        lowered(&mut wifi, &mut device, exit),
        "{:?}",
        wifi.radio().error()
    );
    assert_eq!(leaving_block_tx(&device, exit), 1);
}

#[test]
fn a_quiet_switch_takes_the_link_with_it_and_lasts_until_the_ap_is_heard_again() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    let announced = device.configuration.len();
    let commands = device.commands.len();
    // The model has one 5 GHz channel, which a quiet announcement may name.
    device.inject(
        wifi.radio().rom().unwrap(),
        &announcing_beacon([60, 60], &[37, 3, 1, 36, 5]),
    );
    run(&mut wifi, &mut device, |_, _, _| false);
    assert!(wifi.carrier(), "{:?}", wifi.radio().error());
    assert!(links_since(&device, announced).is_empty());
    assert_eq!(
        device.commands[commands..]
            .iter()
            .filter(|command| **command == (3, 4))
            .count(),
        1,
        "firmware times the switch"
    );
    let disables = |device: &Device<'_>| {
        device.commands[commands..]
            .iter()
            .filter(|command| **command == (3, 0xd))
            .count()
    };
    assert_eq!(
        disables(&device),
        0,
        "firmware keeps sending until the move"
    );
    device.inject(wifi.radio().rom().unwrap(), &notify(3, 0xff, &[1, 0, 0, 0]));
    assert!(
        run(&mut wifi, &mut device, |_, device, _| {
            links_since(device, announced).len() > 2
        }),
        "{:?}",
        wifi.radio().error()
    );
    assert_eq!(disables(&device), 1, "firmware's held frames stop for it");
    // Down, reconfigured on its new PHY, and up.
    let links = links_since(&device, announced);
    assert_eq!(links, [(2, 1, 1), (2, 1, 0xfe), (2, 1, 1)], "{links:?}");
    assert!(wifi.carrier());
    assert!(wifi.radio().silent(), "until the AP is heard");
    device.inject(wifi.radio().rom().unwrap(), &other_beacon([60, 60]));
    let heard = run(&mut wifi, &mut device, |wifi, _, _| !wifi.radio().silent());
    assert!(heard, "{:?}", wifi.radio().error());
    let resumed = run(&mut wifi, &mut device, |_, device, _| disables(device) == 2);
    assert!(resumed, "{:?}", wifi.radio().error());
}

#[test]
fn beacons_missed_while_data_is_heard_keep_the_link() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    let missed = |consecutive: u8, since_receive: u8| {
        let mut body = [0; 20];
        body[4] = since_receive;
        body[8] = consecutive;
        notify(3, 0xf6, &body)
    };
    device.inject(wifi.radio().rom().unwrap(), &missed(30, 3));
    assert!(!run(&mut wifi, &mut device, |_, _, up| !up));
    device.inject(wifi.radio().rom().unwrap(), &missed(30, 4));
    let lost = run(&mut wifi, &mut device, |_, _, up| !up);
    assert!(lost, "{:?}", wifi.radio().error());
}

#[test]
fn an_action_frame_announces_a_switch_as_a_beacon_does() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    let commands = device.commands.len();
    // Unprotected, it says nothing to firmware.
    let public = answer(LOCAL, 0xd0, &[4, 4, 1, 81, 2, 5]);
    device.inject(wifi.radio().rom().unwrap(), &public);
    let quiet = run(&mut wifi, &mut device, |wifi, _, _| wifi.radio().silent());
    assert!(quiet, "{:?}", wifi.radio().error());
    assert!(!device.commands[commands..].contains(&(3, 4)));
    let spectrum = answer(LOCAL, 0xd0, &[0, 4, 37, 3, 1, 2, 5]);
    device.inject(wifi.radio().rom().unwrap(), &spectrum);
    let timed = run(&mut wifi, &mut device, |_, device, _| {
        device.commands[commands..].contains(&(3, 4))
    });
    assert!(timed, "{:?}", wifi.radio().error());
}

#[test]
fn a_new_mu_edca_count_reaches_the_link_once_and_so_does_its_loss() {
    if crate::test_process::isolate_model() {
        return;
    }
    const MU_EDCA: [u8; 16] = [
        255, 14, 38, 1, 2, 0xa4, 8, 2, 0xa4, 8, 2, 0xa4, 8, 2, 0xa4, 8,
    ];
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    device.inject(wifi.radio().rom().unwrap(), &other_beacon([60, 60]));
    settle(&mut wifi, &mut device);
    for (beacon, updates) in [
        (announcing_beacon([60, 60], &MU_EDCA), 1),
        (announcing_beacon([60, 60], &MU_EDCA), 0),
        (other_beacon([60, 60]), 1),
    ] {
        let from = device.configuration.len();
        device.inject(wifi.radio().rom().unwrap(), &beacon);
        settle(&mut wifi, &mut device);
        assert_eq!(links_since(&device, from).len(), updates);
    }
}

#[test]
fn a_switch_firmware_starts_unannounced_is_only_cancelled_by_firmware_that_times_it() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    let commands = device.commands.len();
    device.inject(wifi.radio().rom().unwrap(), &notify(3, 0xff, &[1, 0, 0, 0]));
    run(&mut wifi, &mut device, |_, _, _| false);
    assert!(!device.commands[commands..].contains(&(3, 6)));
    assert!(wifi.carrier());
}

#[test]
fn firmware_saying_a_switch_failed_loses_the_connection() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    device.inject(
        wifi.radio().rom().unwrap(),
        &announcing_beacon([60, 60], &[37, 3, 1, 36, 5]),
    );
    run(&mut wifi, &mut device, |_, _, _| false);
    let mut body = [0; 8];
    body[0] = 1;
    body[4] = 1;
    device.inject(wifi.radio().rom().unwrap(), &notify(3, 0xf9, &body));
    let lost = run(&mut wifi, &mut device, |_, _, up| !up);
    assert!(lost, "{:?}", wifi.radio().error());
}

#[test]
fn a_fading_link_starts_a_scan_that_keeps_out_of_the_way_of_heavy_traffic() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    device.inject(wifi.radio().rom().unwrap(), &report(1_000_000, 44, 0));
    let quiet = run(&mut wifi, &mut device, |_, device, _| {
        device.scans.len() > 1
    });
    assert!(!quiet);
    wifi.radio_mut().end_link_blockout();
    assert!(
        !run(&mut wifi, &mut device, |_, device, _| device.scans.len()
            > 1),
        "a strong link asks for nothing"
    );
    device.inject(wifi.radio().rom().unwrap(), &report(2_000_000, 80, 600_000));
    assert!(!run(&mut wifi, &mut device, |_, device, _| device
        .scans
        .len()
        > 1));
    wifi.radio_mut().end_link_blockout();
    let scanning = run(&mut wifi, &mut device, |_, device, _| {
        device.scans.len() > 1
    });
    assert!(scanning, "{:?}", wifi.radio().error());
    let scan = &device.scans[1];
    assert_eq!(scan[8] & 8, 8, "fragmented");
    assert_eq!(scan[42], 3);
    assert_eq!(word(scan, 20), 44);
    assert_eq!(word(scan, 28), 95);
}

#[test]
fn leaving_stops_a_scan_of_the_links_and_waits_for_firmware_to_let_it_go() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device, _, _) = moved_mld(&native);
    device.holds_link_scan = true;
    miss_beacons(&mut wifi, &mut device);
    wifi.radio_mut().end_link_blockout();
    let scanning = run(&mut wifi, &mut device, |_, device, _| {
        device.scans.len() > 1
    });
    assert!(scanning, "{:?}", wifi.radio().error());
    let links = device.configuration.len();
    wifi.radio_mut().deauthenticate(3).unwrap();
    let left = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().stage() == Standing::Idle
    });
    assert!(left, "{:?}", wifi.radio().error());
    assert!(device.commands.contains(&(1, 0x0e)));
    assert!(
        device.configuration[links..]
            .iter()
            .any(|(opcode, _)| *opcode == 9)
    );
}

#[test]
fn an_ap_mld_takes_the_station_on_a_link_of_its_own_and_gives_it_back() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = raise_mld(&native, mld_ap(), false);
    let associated = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().station().phase() == Peering::Associated
    });
    assert!(
        associated,
        "{:?} {:?}",
        wifi.radio().station().phase(),
        wifi.radio().error()
    );
    // The cold link leaves and the MLD's takes its place.
    let added: Vec<&Vec<u8>> = device
        .configuration
        .iter()
        .filter(|(opcode, bytes)| *opcode == 9 && bytes[0] == 1)
        .map(|(_, bytes)| bytes)
        .collect();
    let [cold, link] = &added[..] else {
        panic!("{} links added", added.len());
    };
    assert_eq!(cold[16..22], LOCAL);
    assert_eq!(link[16..22], LINK);
    assert_eq!(link[166], 3);
    // SAE's two frames and the association leave from the link, for the AP's.
    for frame in &device.air[..3] {
        assert_eq!(frame[4..10], AP);
        assert_eq!(frame[10..16], LINK);
    }
    let request = &device.air[2];
    let basic = Basic::find(&request[28..]).unwrap().unwrap();
    assert_eq!(basic.address, Mac(LOCAL));
    assert!(
        device
            .macs
            .iter()
            .any(|mac| mac[24] == 1 && mac[26] | mac[28] == 1),
        "address translation before the AP's capabilities are known"
    );
    assert!(run(&mut wifi, &mut device, |_, device, _| {
        let last = device
            .configuration
            .iter()
            .rfind(|(opcode, _)| *opcode == 9);
        last.is_some_and(|(_, link)| link[24..28] != 3u32.to_le_bytes())
    }));
    let (_, link) = device
        .configuration
        .iter()
        .rfind(|(opcode, _)| *opcode == 9)
        .unwrap();
    assert_eq!(link[16..22], LINK);
    assert_eq!(link[166], 3);
    let (_, peer) = device
        .configuration
        .iter()
        .rfind(|(opcode, _)| *opcode == 0x0a)
        .unwrap();
    assert_eq!(peer[8..14], AP_MLD);
    assert_eq!(peer[16..22], AP);
    // The handshake's frames name the MLDs, which firmware translates.
    let security = Security::select(&RSN_SAE, true).unwrap();
    let mut ap = Authenticator::between(
        security.suites(),
        device.sae.as_ref().unwrap().pmk().unwrap(),
        Mac(AP_MLD),
        Mac(LOCAL),
        security.element(),
    )
    .naming_station_mld();
    let local = data(LINK, false, [0x88, 0x8e], &ap.message_1(), None);
    device.inject(wifi.radio().rom().unwrap(), &local);
    let answered = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 3);
    assert!(answered, "{:?}", wifi.radio().error());
    assert_eq!(device.air[3][4..10], AP_MLD);
    assert_eq!(device.air[3][10..16], LOCAL);
    ap.message_2(eapol(&device.air[3]));
    let link = supplicant::Link {
        link_id: 3,
        local: Mac(LINK),
        ap: Mac(AP),
        rsn: RSN_SAE.to_vec(),
        rsnxe: Some(H2E_RSNXE.to_vec()),
        accepted: true,
    };
    let message = ap.mld_message_3(&[link], &supplicant::tests::link_keys(3, 1, 0x50));
    let local = data(LINK, false, [0x88, 0x8e], &message, None);
    device.inject(wifi.radio().rom().unwrap(), &local);
    // The link's AP holds the link's group key, which alone opens the port.
    let up = run(&mut wifi, &mut device, |_, _, up| up);
    assert!(
        up,
        "{:?} {:?}",
        wifi.radio().error(),
        device.commands.last()
    );
    let added = device.configuration.len();
    wifi.radio_mut().deauthenticate(3).unwrap();
    let left = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().stage() == Standing::Idle
    });
    assert!(left, "{:?}", wifi.radio().error());
    let farewell = device.air.last().unwrap();
    assert_eq!(farewell[0], 0xc0);
    assert_eq!(farewell[4..10], AP_MLD);
    assert_eq!(farewell[10..16], LOCAL);
    // The cold link comes back with the station's own address.
    let (_, link) = device.configuration[added..]
        .iter()
        .rfind(|(opcode, bytes)| *opcode == 9 && bytes[0] == 1)
        .unwrap();
    assert_eq!(link[16..22], LOCAL);
    assert_eq!(link[166], 0);
}

#[test]
fn an_open_port_sleeps_on_the_vector_which_each_pass_clears_and_rearms() {
    if crate::test_process::isolate_model() {
        return;
    }
    const CAUSES: u32 = 0x2800;
    const AUTOMASK: u32 = 0x2810;
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    assert!(!wifi.signals(), "no vector reached this function");
    assert_eq!(wifi.due_us(), None);
    wifi.radio_mut().vector = true;
    assert!(wifi.signals());
    assert!(wifi.due_us().is_some());
    native.state.lock().unwrap().registers.insert(CAUSES, 1);
    wifi.carrier();
    run(&mut wifi, &mut device, |_, _, _| false);
    let state = native.state.lock().unwrap();
    assert_eq!(state.registers.get(&AUTOMASK), Some(&1));
}

#[test]
fn only_the_last_restarts_reset_the_function_and_one_without_a_reset_still_boots() {
    if crate::test_process::isolate_model() {
        return;
    }
    let resets = |spent: usize, no_reset: bool| {
        let native = Native::default();
        native.state.lock().unwrap().no_reset = no_reset;
        let (mut wifi, _device) = connect(&native, false);
        wifi.radio_mut().spend_restarts(spent);
        native.state.lock().unwrap().registers.insert(8, 1 << 25);
        wifi.carrier();
        assert_eq!(wifi.radio().phase(), Phase::Booting);
        let state = native.state.lock().unwrap();
        let resets = state.ops.iter().filter(|op| matches!(op, Op::Reset));
        (resets.count(), wifi.radio().no_reset())
    };
    let top_fatal = {
        let native = Native::default();
        let (mut wifi, _device) = connect(&native, false);
        wifi.radio_mut().vector = true;
        wifi.radio_mut().family = crate::wifi::intel::firmware::Family::Bz;
        native
            .state
            .lock()
            .unwrap()
            .registers
            .insert(0x2808, 1 << 3);
        wifi.carrier();
        assert_eq!(wifi.radio().phase(), Phase::Booting);
        let state = native.state.lock().unwrap();
        state
            .ops
            .iter()
            .filter(|op| matches!(op, Op::Reset))
            .count()
    };
    assert_eq!(top_fatal, 1, "a TOP fatal error waits for no list");
    assert_eq!(resets(2, false), (0, false));
    assert_eq!(resets(3, false), (1, false));
    assert_eq!(resets(3, true), (1, true));
}

#[test]
fn a_firmware_error_frees_the_function_and_boots_it_for_the_keeper_to_join_again() {
    if crate::test_process::isolate_model() {
        return;
    }
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    let live = native.domain.records.lock().unwrap().live.len();
    native.state.lock().unwrap().registers.insert(8, 1 << 25);
    wifi.carrier();
    assert_eq!(wifi.radio().error(), None);
    assert_eq!(wifi.radio().phase(), Phase::Booting);
    assert_eq!(wifi.radio().station().phase(), Peering::Idle);
    let booted = native.domain.records.lock().unwrap().live.len();
    assert!(booted < live, "{booted} of {live} mappings live");
    assert!(!wifi.carrier(), "the port went with its firmware");
    // ROM answers the second boot as it answered the first.
    device.entry = 0;
    device.answered = None;
    device.queues.clear();
    event(&native.state, 1);
    wifi.carrier();
    let mut alive = rx_packet(1, 0xcafe, 0);
    set_sku(&mut alive, [0; 3]);
    device.inject(wifi.radio().rom().unwrap(), &alive);
    for _ in 0..600 {
        wifi.carrier();
        if wifi.radio().stage() == Standing::Idle {
            assert_eq!(wifi.radio().address(), Mac(LOCAL));
            return;
        }
        device.respond(wifi.radio().rom().unwrap());
    }
    panic!("{:?} {:?}", wifi.radio().phase(), wifi.radio().error());
}

/// `iwl_mvm_set_hw_rfkill_state`: a radio switched off stops the function,
/// which says so once and waits, reading only the switch, then boots again
/// from nothing once the switch is on, without spending a restart.
#[test]
fn a_switched_off_radio_stops_the_function_and_boots_again_once_it_is_on() {
    if crate::test_process::isolate_model() {
        return;
    }
    const GP: u32 = 0x24;
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    let live = native.domain.records.lock().unwrap().live.len();
    *native.state.lock().unwrap().registers.get_mut(&GP).unwrap() &= !0x0800_0000;
    assert!(!wifi.carrier(), "the port went with the radio");
    assert_eq!(wifi.radio().error(), None);
    assert_eq!(wifi.radio().phase(), Phase::Booting);
    assert!(wifi.radio().rom().is_none());
    assert!(native.domain.records.lock().unwrap().live.len() < live);
    let operations = native.state.lock().unwrap().ops.len();
    for _ in 0..5 {
        assert!(!wifi.carrier());
        assert_eq!(wifi.receive(), Ok(None), "a notice, not a fault");
    }
    assert_eq!(wifi.lost(), None);
    let notices: Vec<_> = core::iter::from_fn(|| wifi.take_diagnostic()).collect();
    assert_eq!(
        notices
            .iter()
            .filter(|notice| *notice == "the Wi-Fi radio is switched off")
            .count(),
        1,
        "{notices:?}"
    );
    {
        let state = native.state.lock().unwrap();
        assert!(
            state.ops[operations..]
                .iter()
                .all(|op| matches!(op, Op::Read(GP))),
            "{:?}",
            &state.ops[operations..]
        );
    }
    // The switch on, ROM answers the boot as it answered the first.
    *native.state.lock().unwrap().registers.get_mut(&GP).unwrap() |= 0x0800_0000;
    wifi.carrier();
    assert!(wifi.radio().rom().is_some(), "booting again");
    device.entry = 0;
    device.answered = None;
    device.queues.clear();
    event(&native.state, 1);
    wifi.carrier();
    let mut alive = rx_packet(1, 0xcafe, 0);
    set_sku(&mut alive, [0; 3]);
    device.inject(wifi.radio().rom().unwrap(), &alive);
    for _ in 0..600 {
        wifi.carrier();
        if wifi.radio().stage() == Standing::Idle {
            assert_eq!(wifi.radio().address(), Mac(LOCAL));
            assert!(
                !native
                    .state
                    .lock()
                    .unwrap()
                    .ops
                    .iter()
                    .any(|op| matches!(op, Op::Reset)),
                "no reset and no restart"
            );
            return;
        }
        device.respond(wifi.radio().rom().unwrap());
    }
    panic!("{:?} {:?}", wifi.radio().phase(), wifi.radio().error());
}

#[test]
fn reset_access_refusal_retains_stopped_owner_and_never_boots_or_retries() {
    if crate::test_process::isolate_model() {
        return;
    }
    use crate::bus::pci::{ConfigError, ConfigFailure};
    let native = Native::default();
    let (mut wifi, _device) = connect(&native, false);
    let retained_owners = Arc::strong_count(&native.drops);
    let drops = native.drops.load(Ordering::Relaxed);
    assert!(retained_owners > 1);
    assert!(!native.domain.records.lock().unwrap().live.is_empty());
    let error =
        crate::block::BlockError::Config(ConfigError::before_effect(ConfigFailure::ForeignGrant));
    wifi.radio_mut().spend_restarts(3);
    {
        let mut state = native.state.lock().unwrap();
        state.reset_error = Some(error.clone());
        state.registers.insert(8, 1 << 25);
    }
    wifi.carrier();
    assert_eq!(wifi.radio().phase(), Phase::Failed);
    assert_eq!(
        wifi.radio().error(),
        Some(&crate::wifi::intel::link::Error::Pci(error))
    );
    assert!(!wifi.radio().no_reset());
    assert!(!wifi.signals());
    assert!(wifi.transmit(&[1; 60]).is_err());
    let operations = native.state.lock().unwrap().ops.clone();
    assert_eq!(
        operations
            .iter()
            .filter(|op| matches!(op, Op::Reset))
            .count(),
        1
    );
    // The acknowledged stop releases DMA before the reset attempt. The
    // same function owner remains held even when no live DMA is left.
    assert!(native.domain.records.lock().unwrap().live.is_empty());
    assert_eq!(Arc::strong_count(&native.drops), retained_owners);
    assert_eq!(native.drops.load(Ordering::Relaxed), drops);
    for _ in 0..3 {
        assert!(!wifi.carrier());
    }
    assert_eq!(native.state.lock().unwrap().ops, operations);
    // The keeper says why once and stops: the radio is lost for good.
    assert_eq!(wifi.radio().stage(), Standing::Lost);
    let reason = alloc::string::String::from(wifi.lost().expect("lost for good"));
    assert!(reason.contains("Pci"), "{reason}");
    assert_eq!(
        wifi.receive(),
        Err(crate::LinkError::Adapter(reason.clone()))
    );
    assert_eq!(
        wifi.transmit(&[1; 60]),
        Err(crate::LinkError::Adapter(reason.clone()))
    );
    let notices: Vec<_> = core::iter::from_fn(|| wifi.take_diagnostic()).collect();
    assert_eq!(
        notices.iter().filter(|notice| **notice == reason).count(),
        1
    );
    assert!(native.domain.records.lock().unwrap().live.is_empty());
    assert_eq!(Arc::strong_count(&native.drops), retained_owners);
    assert_eq!(native.drops.load(Ordering::Relaxed), drops);
    drop(wifi);
    assert!(Arc::strong_count(&native.drops) < retained_owners);
    assert!(native.drops.load(Ordering::Relaxed) > drops);
}
