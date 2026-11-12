// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C firmware hardware-feature report from pinned rtw88/main.c and
//! efuse.h. Only the single-attempt Download creates a Report; pure
//! decoding creates diagnostics, never firmware/PHY/ownership evidence.
use super::{
    identity::{Chip, Profile},
    io::{Error, Io},
    registers::*,
};

const REQUEST: u8 = 0xfd;
const REPORT: u8 = 0x19;
const LENGTH: usize = 13;
/// rtw88 reads the report after the whole efuse dump, some milliseconds after
/// firmware is ready; read at once here, it may still be on its way.
const REPORT_POLLS: usize = 2000;
const REPORT_POLL_US: u64 = 10;

/// Source-decoded capabilities. Zero is the source "ignore" value, not proof
/// of unavailable hardware. HCI/protocol numbers remain raw source encodings;
/// future admission must validate them against the PCI/PHY policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    /// Width bits: bit 0=20 MHz, bit 1=40 MHz, bit 2=80 MHz. Not regulatory permission.
    pub bandwidths: u8,
    pub hci: u8,
    pub protocol: u8,
    pub reported_nss: u8,
    pub reported_antennas: u8,
    pub rf_paths: u8,
    pub rf_phys: u8,
    pub antenna_tx: u8,
    pub antenna_rx: u8,
    pub nss: u8,
}

/// Immutable reply from this Download's request/boot/read/ACK. Profile
/// is a hardware fingerprint, not a unique BDF/reset-epoch credential. Future
/// PHY admission must keep this report with the same control/claim
/// owner; a report alone never authorizes programming another requester.
#[derive(Debug)]
pub struct Report {
    profile: Profile,
    raw: [u8; LENGTH],
    capabilities: Capabilities,
}
#[cfg(test)]
impl Report {
    /// What a two-path radio on `profile` reports.
    pub(crate) fn of_two_paths(profile: Profile) -> Self {
        let raw = [0; LENGTH];
        Self {
            profile,
            raw,
            capabilities: decode(1 << 27, &raw),
        }
    }
}
impl Report {
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn raw(&self) -> &[u8; LENGTH] {
        &self.raw
    }
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
}

/// Pure source decoder. Caller-supplied bytes are diagnostics only, with no
/// mailbox provenance or radio-readiness claim.
pub fn decode(sys_cfg1: u32, raw: &[u8; LENGTH]) -> Capabilities {
    let word = u32::from_le_bytes(raw[4..8].try_into().expect("fixed feature word"));
    let bw = (word >> 16) & 7;
    let reported_nss = ((word >> 19) & 3) as u8;
    let reported_antennas = ((word >> 21) & 7) as u8;
    let mut rf_paths = if sys_cfg1 & (1 << 27) != 0 { 2 } else { 1 };
    // Source RTL8822C has no fix_rf_phy_num. Its only valid reduction is 1.
    if reported_antennas == 1 && reported_antennas < rf_paths {
        rf_paths = 1;
    }
    let antennas = if rf_paths == 2 { 3 } else { 1 };
    Capabilities {
        bandwidths: match bw {
            0 | 7 => 7,
            6 => 3,
            _ => 1,
        },
        hci: (word & 15) as u8,
        protocol: ((word >> 26) & 3) as u8,
        reported_nss,
        reported_antennas,
        rf_paths,
        rf_phys: rf_paths,
        antenna_tx: antennas,
        antenna_rx: antennas,
        nss: if reported_nss == 0 || reported_nss > rf_paths {
            rf_paths
        } else {
            reported_nss
        },
    }
}

fn identity<I: Io>(io: &mut I) -> Result<Profile, Error> {
    let profile = io.profile();
    if profile.chip() != Chip::Rtl8822C {
        return Err(Error::WrongChip);
    }
    if io.read32(REG_SYS_CFG1)? != profile.observed().sys_cfg1 {
        return Err(Error::Register);
    }
    Ok(profile)
}

/// Called only inside Download's single mutation attempt, after immutable
/// image target/reparse validation and before the MCU reset/download.
pub(super) fn request<I: Io>(io: &mut I) -> Result<(), Error> {
    identity(io)?;
    io.write8(REG_C2HEVT, REQUEST)?;
    if io.read8(REG_C2HEVT)? != REQUEST {
        return Err(Error::Register);
    }
    Ok(())
}

/// Called only after that same Download requested then observed ready,
/// with no raw-I/O escape/reset/mailbox worker between request and this read.
pub(super) fn read<I: Io>(io: &mut I) -> Result<Report, Error> {
    let profile = identity(io)?;
    ready(io)?;
    let mut id = io.read8(REG_C2HEVT)?;
    for _ in 0..REPORT_POLLS {
        if id != REQUEST {
            break;
        }
        io.delay_us(REPORT_POLL_US);
        id = io.read8(REG_C2HEVT)?;
    }
    if id != REPORT {
        return Err(Error::HardwareFeatureId { observed: id });
    }
    let mut raw = [0; LENGTH];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = io.read8(REG_C2HEVT + 2 + i as u32)?;
    }
    // Identity/ready must still belong to this boot before admitting the bytes.
    identity(io)?;
    ready(io)?;
    io.write8(REG_C2HEVT, 0)?;
    if io.read8(REG_C2HEVT)? != 0 {
        return Err(Error::Register);
    }
    Ok(Report {
        profile,
        raw,
        capabilities: decode(profile.observed().sys_cfg1, &raw),
    })
}

fn ready<I: Io>(io: &mut I) -> Result<(), Error> {
    let observed = io.read16(REG_MCUFW_CTRL)?;
    if observed & FW_READY_MASK != FW_READY {
        return Err(Error::HardwareFeatureFirmwareNotReady { observed });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec::Vec;

    struct Registers {
        profile: Profile,
        raw: [u8; LENGTH],
        id: u8,
        raw_reads: usize,
        /// Reads of the mailbox that still find the request.
        pending_reads: usize,
        delays: usize,
        change_identity_after_payload: bool,
        lose_ready_after_payload: bool,
        events: Vec<u8>,
    }
    impl Registers {
        fn new(sys_cfg1: u32, raw: [u8; LENGTH]) -> Self {
            Self {
                profile: Profile::select(super::super::identity::Observed {
                    vendor: 0x10ec,
                    device: 0xc822,
                    subsystem_vendor: 0x17aa,
                    subsystem_device: 0x1234,
                    pci_revision: 1,
                    sys_cfg1,
                })
                .unwrap(),
                raw,
                id: REPORT,
                raw_reads: 0,
                pending_reads: 0,
                delays: 0,
                change_identity_after_payload: false,
                lose_ready_after_payload: false,
                events: Vec::new(),
            }
        }
        fn event(&mut self, write: bool, register: u32, value: u8) {
            for word in [u32::from(write), register, 1, u32::from(value)] {
                self.events.extend_from_slice(&word.to_le_bytes());
            }
        }
    }
    // SAFETY: serial deterministic mailbox/register model, no physical device.
    unsafe impl Io for Registers {
        fn profile(&self) -> Profile {
            self.profile
        }
        fn read8(&mut self, register: u32) -> Result<u8, Error> {
            let value = if register == REG_C2HEVT && self.pending_reads != 0 {
                self.pending_reads -= 1;
                REQUEST
            } else if register == REG_C2HEVT {
                self.id
            } else {
                let index = (register - REG_C2HEVT - 2) as usize;
                self.raw_reads += 1;
                self.raw[index]
            };
            self.event(false, register, value);
            Ok(value)
        }
        fn read16(&mut self, register: u32) -> Result<u16, Error> {
            assert_eq!(register, 0x80);
            Ok(
                if self.raw_reads == LENGTH && self.lose_ready_after_payload {
                    0xffff
                } else {
                    0xc078
                },
            )
        }
        fn read32(&mut self, register: u32) -> Result<u32, Error> {
            assert_eq!(register, 0xf0);
            Ok(
                if self.raw_reads == LENGTH && self.change_identity_after_payload {
                    self.profile.observed().sys_cfg1 ^ 0x1000
                } else {
                    self.profile.observed().sys_cfg1
                },
            )
        }
        fn write8(&mut self, register: u32, value: u8) -> Result<(), Error> {
            assert_eq!(register, REG_C2HEVT);
            self.id = value;
            self.event(true, register, value);
            Ok(())
        }
        fn write16(&mut self, _: u32, _: u16) -> Result<(), Error> {
            panic!("no feature 16-bit store")
        }
        fn write32(&mut self, _: u32, _: u32) -> Result<(), Error> {
            panic!("no feature 32-bit store")
        }
        fn delay_us(&mut self, microseconds: u64) {
            assert_eq!(microseconds, REPORT_POLL_US);
            self.delays += 1;
        }
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), Error> {
            panic!("no feature beacon")
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), Error> {
            panic!("no feature beacon completion")
        }
        fn quarantine(&mut self) {
            panic!("outer Download retains/quarantines actual owner")
        }
    }
    #[test]
    fn a_report_still_on_its_way_is_waited_for_within_bounds() {
        let mut registers = Registers::new(1 << 27, [255; LENGTH]);
        registers.pending_reads = 5;
        read(&mut registers).unwrap();
        assert_eq!(registers.delays, 5);
        assert_eq!(registers.id, 0, "the report is acknowledged");
        let mut registers = Registers::new(1 << 27, [255; LENGTH]);
        registers.pending_reads = usize::MAX;
        assert!(matches!(
            read(&mut registers),
            Err(Error::HardwareFeatureId { observed: REQUEST })
        ));
        assert_eq!(registers.delays, REPORT_POLLS);
        assert_eq!(registers.raw_reads, 0);
        // Any other mailbox value is no report, at once.
        let mut registers = Registers::new(1 << 27, [255; LENGTH]);
        registers.id = 0x12;
        assert!(read(&mut registers).is_err());
        assert_eq!(registers.delays, 0);
    }
    #[test]
    fn late_identity_and_ready_loss_cannot_publish_or_ack_a_partial_report() {
        for ready in [false, true] {
            let mut registers = Registers::new(1 << 27, [255; LENGTH]);
            if ready {
                registers.lose_ready_after_payload = true;
            } else {
                registers.change_identity_after_payload = true;
            }
            let result = read(&mut registers);
            if ready {
                assert!(matches!(
                    result,
                    Err(Error::HardwareFeatureFirmwareNotReady { observed: 0xffff })
                ));
            } else {
                assert!(matches!(result, Err(Error::Register)));
            }
            assert_eq!(registers.raw_reads, LENGTH);
            assert_eq!(registers.id, REPORT); // Not acknowledged/admitted.
        }
    }
    #[test]
    #[ignore = "oracle: STELA_REALTEK_WIFI_FEATURES_ORACLE"]
    fn every_capability_combination_and_complete_mailbox_trace_matches_unchanged_c() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_FEATURES_ORACLE").unwrap()).unwrap();
        let mut offset = 0;
        for case in 0..32768 {
            let sys = u32::from_le_bytes(trace[offset..offset + 4].try_into().unwrap());
            let raw = trace[offset + 4..offset + 17].try_into().unwrap();
            offset += 17;
            let mut io = Registers::new(sys, raw);
            let report = read(&mut io).unwrap();
            // Source ID + 13 byte loads + ACK. Additional native guards
            // and ACK readback remain separate from donor's operations.
            assert_eq!(
                &io.events[..15 * 16],
                &trace[offset..offset + 15 * 16],
                "case {case}"
            );
            assert_eq!(io.events.len(), 16 * 16);
            offset += 15 * 16;
            let cap = report.capabilities();
            assert_eq!(
                [
                    cap.bandwidths,
                    cap.hci,
                    cap.protocol,
                    cap.reported_nss,
                    cap.reported_antennas,
                    cap.rf_paths,
                    cap.rf_phys,
                    cap.antenna_tx,
                    cap.antenna_rx,
                    cap.nss,
                ],
                trace[offset..offset + 10],
                "case {case}"
            );
            assert_eq!(report.raw(), &raw);
            assert_eq!(report.profile(), io.profile);
            offset += 10;
        }
        assert_eq!(offset, trace.len());
    }
}
