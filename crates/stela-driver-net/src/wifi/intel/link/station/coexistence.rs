// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2013-2014, 2018-2020, 2022-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
//! `iwl_mvm_bt_coex_notif_handle`: what firmware says of Bluetooth shapes a
//! 2.4 GHz link. Busy Bluetooth takes receive chains away by SM power save
//! where firmware leaves the chains to the host, and
//! on AX200's generation the channel it may not use and, with a strong AP, the
//! transmit power follow. Wi-Fi 7 firmware keeps this to itself, and only
//! EMLSR hears of it. The AP's signal comes from its frames rather than
//! firmware's averaged beacons, and chains narrow once the AP's action frame
//! is on its queue rather than on its acknowledgement.
use super::*;

mod statistics;

pub(super) const LEGACY_STATISTICS_NOTIFICATION: (u8, u8) = (0x9d, 0);
const NEW_RX_STATISTICS_API: u32 = 35;

#[derive(Clone, Copy)]
pub(super) enum StatisticsNotification {
    Legacy,
    System,
}
use crate::wifi::{intel::association::SpatialPowerSave, station::operations::ChannelDefinition};

pub(super) const PROFILE_NOTIFICATION: (u8, u8) = (0xce, 0);
const CHANNEL_INHIBITION: command::Id = command::Id {
    group: 0,
    opcode: 0x5d,
    version: 0,
};
const REDUCED_TRANSMIT_POWER: command::Id = command::Id {
    group: 0,
    opcode: 0x5c,
    version: 0,
};
/// `IWL_UCODE_TLV_CAPA_COEX_SCHEMA_2`.
const SCHEMA_2: u32 = 45;
const BT_LOW_TRAFFIC: u32 = 2;
const BT_HIGH_TRAFFIC: u32 = 3;
const BT_VERY_HIGH_TRAFFIC: u32 = 4;
const BT_COEX_LOOSE_LUT: u32 = 1;
/// `BT_REDUCED_TX_POWER_BIT`.
const REDUCED: u32 = 1 << 7;
/// `IWL_MVM_BT_COEX_EN_RED_TXP_THRESH` and `IWL_MVM_BT_COEX_DIS_RED_TXP_THRESH`.
const REDUCE_ABOVE_DBM: i32 = -62;
const RESTORE_BELOW_DBM: i32 = -65;
/// `ANT_B`, the antenna Wi-Fi does not share.
const NON_SHARED: u8 = 2;
/// `iwl_ci_mask` of channels 1 to 14: 20 MHz, then 40 MHz with the center below
/// the control channel and above it.
const INHIBITIONS: [[u64; 3]; 14] = [
    [0x00_0000_1fff, 0, 0x00_007f_ffff],
    [0x00_0000_ffff, 0, 0x00_03ff_ffff],
    [0x00_0003_fffc, 0, 0x00_0fff_fffc],
    [0x00_001f_ffe0, 0, 0x00_7fff_ffe0],
    [0x00_007f_ff80, 0x00_007f_ffff, 0x01_ffff_ff80],
    [0x00_03ff_fc00, 0x00_03ff_ffff, 0x0f_ffff_fc00],
    [0x00_0fff_f000, 0x00_0fff_fffc, 0x3f_ffff_f000],
    [0x00_7fff_8000, 0x00_7fff_ffe0, 0xff_ffff_8000],
    [0x01_fffe_0000, 0x01_ffff_ff80, 0xff_fffe_0000],
    [0x0f_fff0_0000, 0x0f_ffff_fc00, 0],
    [0x3f_ffc0_0000, 0x3f_ffff_f000, 0],
    [0xff_fe00_0000, 0xff_ffff_8000, 0],
    [0xff_f800_0000, 0xff_fffe_0000, 0],
    [0xfe_0000_0000, 0, 0],
];

/// `struct iwl_bt_coex_ci_cmd` of a link on `definition`, primary in PHY `seat`.
fn inhibition(definition: &ChannelDefinition, seat: u8) -> [u8; 24] {
    let control = u32::from(definition.control.frequency_mhz);
    let side = if definition.width == phy::Width::Mhz20 {
        0
    } else if definition.center1_mhz > control {
        2
    } else {
        1
    };
    let row = usize::from(definition.control.number).wrapping_sub(1);
    let mask = INHIBITIONS.get(row).map_or(0, |row| row[side]);
    let mut command = [0; 24];
    command[..8].copy_from_slice(&mask.to_le_bytes());
    command[8] = seat;
    command
}

/// The last word of firmware, and what it led to.
#[derive(Default)]
pub(super) struct Bluetooth {
    grading: u32,
    primary_lut: u32,
    /// `rrc_status`: a PHY firmware takes out of SM power save itself.
    rrc: u8,
    signal: Option<i32>,
    /// What came last needs a look.
    stale: bool,
    inhibition: [u8; 24],
    reduced: bool,
    spatial: SpatialPowerSave,
    /// The AP knows of a change the PHY has not followed yet.
    chains_due: bool,
}

impl Bluetooth {
    /// `iwl_mvm_rx_bt_coex_old_notif`.
    pub(super) fn profile(&mut self, raw: &[u8]) {
        let word = |at: usize| {
            raw.get(at..at + 4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        };
        if let (Some(lut), Some(grading), Some(&rrc)) = (word(24), word(32), raw.get(37)) {
            (self.primary_lut, self.grading, self.rrc) = (lut, grading, rrc);
            self.stale = true;
        }
    }

    /// `iwl_mvm_bt_coex_vif_change`.
    pub(super) fn link_changed(&mut self) {
        self.stale = true;
    }

    /// The association went, with its PHY and firmware station.
    pub(super) fn departed(&mut self) {
        self.reduced = false;
        self.spatial = SpatialPowerSave::Off;
        self.chains_due = false;
        self.signal = None;
        self.stale = true;
    }

    /// The nonzero firmware beacon-filter measurement used by
    /// iwl_mvm_update_link_sig before iwl_mvm_bt_rssi_event.
    pub(super) fn measured(&mut self, signal: i32) {
        self.signal = Some(signal);
        self.stale |= self.grading != 0 && self.reduced_at(signal) != self.reduced;
    }

    fn reduced_at(&self, signal: i32) -> bool {
        if signal > REDUCE_ABOVE_DBM {
            true
        } else if signal < RESTORE_BELOW_DBM {
            false
        } else {
            self.reduced
        }
    }

    /// `iwl_mvm_bt_notif_per_link`'s request of a link on 2.4 GHz or not.
    fn spatial(&self, on_2ghz: bool, seat: u8, schema_2: bool) -> SpatialPowerSave {
        let highest = if schema_2 {
            BT_VERY_HIGH_TRAFFIC
        } else {
            BT_HIGH_TRAFFIC
        };
        if !on_2ghz || self.rrc & 1 << seat != 0 {
            SpatialPowerSave::Off
        } else if self.grading >= highest {
            SpatialPowerSave::Static
        } else if self.grading >= BT_LOW_TRAFFIC {
            SpatialPowerSave::Dynamic
        } else {
            SpatialPowerSave::Off
        }
    }

    /// `iwl_mvm_bt_notif_per_link`'s word on transmit power.
    fn reduces(&self, on_2ghz: bool) -> bool {
        on_2ghz
            && self.primary_lut != BT_COEX_LOOSE_LUT
            && self.grading != 0
            && self.reduced_at(self.signal.unwrap_or(-100))
    }

    /// `iwl_mvm_get_tx_ant`: management frames on 2.4 GHz leave the shared
    /// antenna to busy Bluetooth.
    pub(super) fn management_antennas(&self, on_2ghz: bool, antennas: u8) -> u8 {
        if on_2ghz && self.grading >= BT_HIGH_TRAFFIC && antennas & NON_SHARED != 0 {
            NON_SHARED
        } else {
            antennas
        }
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// iwl_mvm_handle_rx_statistics and iwl_mvm_handle_rx_system_oper_stats.
    /// The native notification still belongs to this queue's firmware epoch;
    /// its MAC index is a selector within that owner, not a new owner grant.
    pub(super) fn coexistence_statistics(
        &mut self,
        queue: &mut Queue<Q, B>,
        raw: &[u8],
        notification: StatisticsNotification,
    ) {
        if !matches!(queue.family(), Family::Ax200 | Family::Ax210)
            || self
                .client
                .context
                .as_ref()
                .is_some_and(|context| context.affiliation().is_some())
            || self.client.leaving
            || self.client.station.phase() != Peering::Associated
        {
            return;
        }
        let firmware = queue.firmware();
        let system = firmware
            .command_version(
                commands::SYSTEM_STATISTICS.group,
                commands::SYSTEM_STATISTICS.opcode,
            )
            .is_some_and(|version| version.command_version != u8::MAX);
        let format = match notification {
            StatisticsNotification::Legacy if system => return,
            StatisticsNotification::Legacy => statistics::Format::Legacy {
                version: firmware
                    .command_version(0, LEGACY_STATISTICS_NOTIFICATION.0)
                    .filter(|version| version.notification_version != u8::MAX)
                    .map_or(0, |version| version.notification_version),
                new_statistics: firmware.supports_api(NEW_RX_STATISTICS_API),
            },
            StatisticsNotification::System => statistics::Format::System {
                version: firmware
                    .command_version(0x10, 0)
                    .filter(|version| version.notification_version != u8::MAX)
                    .map_or(0, |version| version.notification_version),
            },
        };
        match format.signal(raw, self.client.seat) {
            Ok(Some(signal)) => self.client.bluetooth.measured(signal),
            Ok(None) => {}
            Err(statistics::Error::Version(_)) => self
                .client
                .unsupported("a firmware Bluetooth statistics version"),
            Err(_) => self
                .client
                .unsupported("a malformed firmware Bluetooth statistics report"),
        }
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    pub(super) fn run_coexistence(&mut self, queue: &mut Queue<Q, B>) -> Result<(), Error> {
        let family = queue.family();
        let client = &self.client;
        if !client.idle() || client.leaving {
            return Ok(());
        }
        let associated = client.station.phase() == Peering::Associated;
        let system_statistics = queue
            .firmware()
            .command_version(
                commands::SYSTEM_STATISTICS.group,
                commands::SYSTEM_STATISTICS.opcode,
            )
            .is_some_and(|version| version.command_version != u8::MAX);
        if !matches!(family, Family::Ax200 | Family::Ax210) {
            // `iwl_mld_vif_cfg_changed`: iwlmld clears the counters and asks
            // for periodic reports on every association, a single link's too.
            if associated && system_statistics && !client.statistics.watching() {
                self.client.watch_statistics();
            }
            return Ok(());
        }
        if associated
            && system_statistics
            && !client.statistics.watching()
            && client
                .context
                .as_ref()
                .is_some_and(|context| context.affiliation().is_none())
        {
            // mvm configures periodic system reports and clears association
            // counters. The existing serialized command path owns both ACKs.
            self.client.watch_statistics();
            return Ok(());
        }
        let link = client.context.clone().filter(|_| associated);
        if client.bluetooth.chains_due && client.outbox.is_empty() {
            self.client.bluetooth.chains_due = false;
            if let Some(link) = &link {
                self.follow_chains(queue, link)?;
            }
        }
        let client = &mut self.client;
        if !core::mem::take(&mut client.bluetooth.stale) {
            return Ok(());
        }
        let seat = client.seat;
        let definition = link
            .as_ref()
            .map(|link| client.link_definition(link))
            .filter(|definition| definition.control.band == Band::Ghz2);
        let on_2ghz = definition.is_some();
        let schema_2 = queue.firmware().supports_capability(SCHEMA_2);
        let spatial = client.bluetooth.spatial(on_2ghz, seat, schema_2);
        if spatial != client.bluetooth.spatial && queue.limit_receive(spatial) {
            client.bluetooth.spatial = spatial;
            if let Some(link) = link {
                if link.negotiated().mode != phy::Mode::Legacy {
                    let bytes = client
                        .station
                        .spatial_power_save(&link, spatial.control())
                        .map_err(Error::Station)?;
                    client.outbox.push_back((None, bytes));
                }
                client.bluetooth.chains_due = true;
            }
        }
        if family != Family::Ax200 {
            return Ok(());
        }
        let inhibition = definition.map_or([0; 24], |definition| inhibition(&definition, seat));
        if inhibition != client.bluetooth.inhibition {
            client.bluetooth.inhibition = inhibition;
            client.command(CHANNEL_INHIBITION, inhibition.to_vec());
        }
        let reduced = client.bluetooth.reduces(on_2ghz);
        if reduced != client.bluetooth.reduced {
            client.bluetooth.reduced = reduced;
            let value = u32::from(seat) | if reduced { REDUCED } else { 0 };
            client.command(REDUCED_TRANSMIT_POWER, value.to_le_bytes().to_vec());
        }
        Ok(())
    }

    /// `ieee80211_recalc_smps` reaching `iwl_mvm_phy_ctxt_changed`.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn follow_chains(
        &mut self,
        queue: &mut Queue<Q, B>,
        link: &AssociationContext,
    ) -> Result<(), Error> {
        let definition = self.client.link_definition(link);
        let (seat, port_open) = (self.client.seat, self.client.port_open);
        let wide_ofdma = self.link_commands(queue, link, seat, port_open)?.wide_ofdma;
        let commands = queue
            .phy_changed(&definition, wide_ofdma.as_ref())
            .ok_or(Error::Refused("channel width"))?;
        for (id, bytes) in commands {
            self.client.command(id, bytes);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::Channel;

    fn on(number: u16, width: phy::Width, center1_mhz: u32) -> ChannelDefinition {
        ChannelDefinition {
            control: Channel {
                band: Band::Ghz2,
                number,
                frequency_mhz: 2407 + number * 5,
            },
            width,
            center1_mhz,
            center2_mhz: None,
            punctured: 0,
        }
    }

    #[test]
    fn a_channel_and_its_side_choose_what_bluetooth_stays_off() {
        let twenty = inhibition(&on(1, phy::Width::Mhz20, 2412), 0);
        assert_eq!(twenty[..8], 0x1fffu64.to_le_bytes());
        let above = inhibition(&on(5, phy::Width::Mhz40, 2442), 1);
        assert_eq!(above[..8], 0x01_ffff_ff80u64.to_le_bytes());
        assert_eq!(above[8], 1);
        let below = inhibition(&on(5, phy::Width::Mhz40, 2422), 0);
        assert_eq!(below[..8], 0x7f_ffffu64.to_le_bytes());
    }

    #[test]
    fn grading_asks_for_chains_and_rrc_gives_them_back() {
        let mut body = [0; 40];
        body[32] = 2;
        let mut bluetooth = Bluetooth::default();
        bluetooth.profile(&body);
        assert_eq!(bluetooth.spatial(true, 0, true), SpatialPowerSave::Dynamic);
        assert_eq!(bluetooth.spatial(false, 0, true), SpatialPowerSave::Off);
        body[32] = 3;
        bluetooth.profile(&body);
        assert_eq!(bluetooth.spatial(true, 0, true), SpatialPowerSave::Dynamic);
        assert_eq!(bluetooth.spatial(true, 0, false), SpatialPowerSave::Static);
        body[37] = 1;
        bluetooth.profile(&body);
        assert_eq!(bluetooth.spatial(true, 0, false), SpatialPowerSave::Off);
        assert_eq!(bluetooth.spatial(true, 1, false), SpatialPowerSave::Static);
    }

    #[test]
    fn transmit_power_turns_on_a_margin_of_the_aps_signal() {
        let mut body = [0; 40];
        body[32] = 3;
        let mut bluetooth = Bluetooth::default();
        bluetooth.profile(&body);
        bluetooth.stale = false;
        assert!(!bluetooth.reduces(true), "an AP unheard is a weak one");
        bluetooth.measured(-50);
        assert!(bluetooth.stale);
        assert!(bluetooth.reduces(true));
        assert!(!bluetooth.reduces(false));
        bluetooth.reduced = true;
        bluetooth.stale = false;
        bluetooth.measured(-64);
        assert!(!bluetooth.stale, "between the two thresholds nothing moves");
        assert!(bluetooth.reduces(true));
        bluetooth.measured(-70);
        assert!(bluetooth.stale);
        assert!(!bluetooth.reduces(true));
        body[24] = 1;
        bluetooth.profile(&body);
        bluetooth.measured(-50);
        assert!(!bluetooth.reduces(true), "a loose table keeps full power");
    }

    #[test]
    fn busy_bluetooth_keeps_management_frames_off_its_antenna() {
        let mut body = [0; 40];
        body[32] = 3;
        let mut bluetooth = Bluetooth::default();
        assert_eq!(bluetooth.management_antennas(true, 3), 3);
        bluetooth.profile(&body);
        assert_eq!(bluetooth.management_antennas(true, 3), NON_SHARED);
        assert_eq!(bluetooth.management_antennas(false, 3), 3);
        assert_eq!(bluetooth.management_antennas(true, 1), 1);
    }
}
