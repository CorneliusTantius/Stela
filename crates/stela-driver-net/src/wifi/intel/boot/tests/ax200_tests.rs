// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! AX200 owner, completed native command DMA and failure models.
use super::*;
use crate::wifi::intel::radio::{
    bios::service::{self, BiosIo, IoError, Object, Request},
    control::Kind,
};
#[derive(Clone)]
pub(super) struct ClockBios {
    inner: RadioBios,
    clock_error: Option<IoError>,
    country_error: Option<IoError>,
    pub(super) board_case: Option<u8>,
}
// SAFETY: the original exact namespace model plus a real modeled EFI ECKV read.
unsafe impl BiosIo for ClockBios {
    fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
        // The namespace has no power tables, ECKV or WRDD methods: what
        // the EFI variables leave out stays absent.
        if let Request::PowerTable(_) | Request::ExternalClock | Request::Country = request {
            return Err(IoError::NotFound);
        }
        self.inner.evaluate(request)
    }
    fn variable(
        &mut self,
        variable: super::super::super::platform::Variable,
    ) -> Result<Vec<u8>, IoError> {
        use super::super::super::platform::Variable;
        if let Some(case) = self.board_case
            && matches!(
                variable,
                Variable::Ppag
                    | Variable::Wrds
                    | Variable::Ewrd
                    | Variable::Wgds
                    | Variable::Sgom
                    | Variable::Wtas
            )
        {
            return super::ax200_board_tests::power_variable(case, variable);
        }
        if variable == Variable::Wrdd {
            return self
                .country_error
                .map_or_else(|| Ok(vec![0, 0x4e, 0x43, 0, 0]), Err);
        }
        if variable == Variable::Eckv {
            return self
                .clock_error
                .map_or_else(|| Ok(vec![0, 1, 0, 0, 0]), Err);
        }
        self.inner.variable(variable)
    }
    fn dmi_identity(&mut self) -> Result<service::DmiIdentity, IoError> {
        match self.board_case {
            Some(3) | None => Err(IoError::Unavailable),
            case => Ok(service::DmiIdentity {
                system_vendor: Some(
                    if matches!(case, Some(4 | 11)) {
                        "Example"
                    } else {
                        "HP"
                    }
                    .into(),
                ),
                board_vendor: None,
            }),
        }
    }
}
pub(super) fn clock_bios(drops: &Arc<AtomicUsize>, board_case: Option<u8>) -> ClockBios {
    ClockBios {
        inner: RadioBios {
            drops: drops.clone(),
            unavailable: false,
            absent: false,
        },
        clock_error: None,
        country_error: None,
        board_case,
    }
}
pub(super) fn setup_bytes() -> Vec<u8> {
    let mut bytes = lari_bytes(false, 6);
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 48 {
            let versions = [
                0x18, 1, 12, 2, 0x77, 1, 6, 0, 4, 4, 1, 0, 0xc8, 1, 1, 5, 0x0c, 1, 5, 0,
            ];
            bytes.splice(at + 8 + len..at + 8 + len, versions);
            bytes[at + 4..at + 8].copy_from_slice(&((len + versions.len()) as u32).to_le_bytes());
            break;
        }
        at += 8 + len.next_multiple_of(4);
    }
    for (index, mask) in [
        (0u32, (1u32 << 1) | (1 << 2)),
        (1, 1 << 18),
        (2, (1 << 10) | (1 << 11) | (1 << 25)),
    ] {
        bytes.extend(30u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(index.to_le_bytes());
        bytes.extend(mask.to_le_bytes());
    }
    bytes.extend(29u32.to_le_bytes());
    bytes.extend(8u32.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend((1u32 << 9).to_le_bytes());
    bytes.extend(29u32.to_le_bytes());
    bytes.extend(8u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend((1u32 << 24).to_le_bytes());
    let mut at = 88;
    while at < bytes.len() {
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if kind == 23 {
            let word = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) | (3 << 20);
            bytes[at + 8..at + 12].copy_from_slice(&word.to_le_bytes());
        }
        at += 8 + len.next_multiple_of(4);
    }
    bytes
}
pub(super) fn finish_lari<'a>(
    init: UnifiedNvm<'a, Model>,
    source: &Source,
    domain: &Domain,
    bios_drops: &Arc<AtomicUsize>,
    clock_error: Option<IoError>,
) -> (LariRadio<'a, Model, ClockBios>, u16, u16) {
    let (cold, mut sequence, mut entry) = drive_cold_prefix(init, source, domain);
    // SAFETY: the simulated device and its providers belong to this fixture alone; no other worker
    // touches them.
    let mut lari = unsafe {
        cold.begin_lari(ClockBios {
            inner: RadioBios {
                drops: bios_drops.clone(),
                unavailable: false,
                absent: false,
            },
            clock_error,
            country_error: None,
            board_case: None,
        })
    }
    .unwrap_or_else(|_| panic!("real cold prefix"));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { lari.advance(source) }.unwrap();
    let commands: Vec<_> = lari.plan().unwrap().commands().map(|(id, _)| id).collect();
    for id in commands {
        complete(
            &lari.radio.initialized.boot,
            domain,
            entry,
            entry + 1,
            &command_packet(id, sequence, &[]),
        );
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { lari.advance(source) }.unwrap();
        sequence += 1;
        entry += 1;
    }
    assert_eq!(lari.phase(), LariPhase::RxQueueConfigurationRequired);
    (lari, sequence, entry)
}
pub(super) fn finish_setup<'a>(
    lari: LariRadio<'a, Model, ClockBios>,
    sequence: u16,
    entry: u16,
    source: &Source,
    domain: &Domain,
) -> (Ax200Setup<'a, Model, ClockBios>, u16, u16) {
    finish_setup_with_options(
        lari,
        sequence,
        entry,
        source,
        domain,
        Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        }),
    )
}
pub(super) fn finish_setup_with_options<'a>(
    lari: LariRadio<'a, Model, ClockBios>,
    mut sequence: u16,
    mut entry: u16,
    source: &Source,
    domain: &Domain,
    options: Ax200SetupOptions,
) -> (Ax200Setup<'a, Model, ClockBios>, u16, u16) {
    let mut setup =
        // SAFETY: the fixture clock is monotonic and advances for the whole device epoch.
        unsafe { lari.begin_ax200_setup(options) }.unwrap_or_else(|_| panic!("AX200 setup"));
    // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
    // requester domain.
    unsafe { setup.advance(source) }.unwrap();
    for (group, opcode) in [(4, 4), (1, 0x77)] {
        complete(
            &setup.lari.radio.initialized.boot,
            domain,
            entry,
            entry + 1,
            &command_packet(
                super::super::super::command::Id {
                    group,
                    opcode,
                    version: 0,
                },
                sequence,
                &[],
            ),
        );
        // SAFETY: the fixture's `source` hands out fresh exclusive pages for its sole simulated
        // requester domain.
        unsafe { setup.advance(source) }.unwrap();
        sequence += 1;
        entry += 1;
    }
    assert_eq!(setup.phase(), Ax200SetupPhase::RegulatoryRequired);
    (setup, sequence, entry)
}
pub(super) fn mcc_payload(country: [u8; 2], source: u8, count: usize) -> Vec<u8> {
    let mut b = vec![0; 20 + count * 4];
    b[..4].copy_from_slice(&0u32.to_le_bytes());
    b[4..6].copy_from_slice(&u16::from_be_bytes(country).to_le_bytes());
    b[6..8].copy_from_slice(&12u16.to_le_bytes());
    b[12] = source;
    b[16..20].copy_from_slice(&(count as u32).to_le_bytes());
    for i in 0..count {
        b[20 + i * 4..24 + i * 4]
            .copy_from_slice(&(if i == 0 { 0x0f09u32 } else { 0 }).to_le_bytes());
    }
    b
}

mod mcc;
mod mcc_faults;
mod thermal;
mod thermal_faults;
