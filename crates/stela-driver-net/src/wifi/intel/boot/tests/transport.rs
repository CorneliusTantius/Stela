// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Synchronous device-side memory and receive-completion fixtures.
use super::*;

pub(super) fn id(address: u64) -> u64 {
    (address - 0x100000) / 0x10000
}

pub(super) fn device_write(
    domain: &Domain,
    address: u64,
    offset: usize,
    bytes: &[u8],
    complete: bool,
) {
    let mut r = domain.records.lock().unwrap();
    let id = id(address);
    assert!(matches!(
        r.permissions.get(&id),
        Some(Direction::FromDevice | Direction::Bidirectional)
    ));
    let pointer = r
        .live
        .get(&id)
        .unwrap()
        .address(
            (address - (0x100000 + id * 0x10000)) as usize + offset,
            bytes.len(),
        )
        .unwrap();
    // SAFETY: the locked range is live mapped RAM with device-write rights; all
    // fixture callers pass independent packet/scratch bytes. This synchronous
    // model serializes the copy before publishing completion, with no real DMA.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.as_ptr(), bytes.len());
    }
    if complete {
        assert!(r.completed.insert(id));
    }
}

pub(super) fn device_read(domain: &Domain, address: u64, offset: usize, n: usize) -> Vec<u8> {
    let r = domain.records.lock().unwrap();
    let id = id(address);
    assert!(matches!(
        r.permissions.get(&id),
        Some(Direction::ToDevice | Direction::Bidirectional)
    ));
    let pointer = r
        .live
        .get(&id)
        .unwrap()
        .address((address - (0x100000 + id * 0x10000)) as usize + offset, n)
        .unwrap();
    let mut bytes = vec![0; n];
    // SAFETY: address() checked this initialized live mapping; the domain lock
    // keeps its backing and serializes every modeled device access. The fresh
    // output Vec is disjoint, and no real DMA user exists in this fixture.
    unsafe {
        core::ptr::copy_nonoverlapping(pointer.as_ptr(), bytes.as_mut_ptr(), n);
    }
    bytes
}

pub(super) fn rx_packet(command: u8, status: u16, queue: u8) -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    bytes[..4].copy_from_slice(&(148u32 | (u32::from(queue) << 16)).to_le_bytes());
    bytes[4] = command;
    bytes[7] = 0x80;
    bytes[8..10].copy_from_slice(&status.to_le_bytes());
    for (n, word) in [0x610d0u32, 0x1234, 0x55667788].iter().enumerate() {
        bytes[124 + n * 4..128 + n * 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes[192..196].copy_from_slice(&0x55550000u32.to_le_bytes());
    bytes
}

pub(super) fn event(state: &Arc<Mutex<ModelState>>, cause: u32) {
    let mut s = state.lock().unwrap();
    *s.registers.entry(8).or_default() |= cause;
}

pub(super) fn complete(
    boot: &Ax200Boot<'_, Model>,
    domain: &Domain,
    index: u16,
    vid: u16,
    packet: &[u8],
) {
    complete_from_free_slot(boot, domain, index, vid, vid - 1, packet);
}

pub(super) fn complete_from_free_slot(
    boot: &Ax200Boot<'_, Model>,
    domain: &Domain,
    index: u16,
    vid: u16,
    free_slot: u16,
    packet: &[u8],
) {
    let stride = if boot.profile.family() >= Family::Ax210 {
        16
    } else {
        8
    };
    // Model requester consumed this emitted free descriptor before
    // completing its receive payload; this grants only that exact range.
    let mut r = domain.records.lock().unwrap();
    r.completed_ranges.insert((
        id(boot.free.region().address),
        usize::from(free_slot) * stride,
        usize::from(free_slot + 1) * stride,
    ));
    drop(r);
    // The device model's real matching HCMD response ends access to the
    // submitted slot/TB0 before publishing the RX completion. Merely
    // receiving an unsolicited/wrong sequence grants no such ownership.
    if let Ok(packets) = Packets::new(boot.profile.family(), 0, packet) {
        for response in packets.flatten() {
            if response.unsolicited() || (response.group == 0 && response.command == 0x1c) {
                continue;
            }
            let slots = if boot.profile.family() >= Family::Ax210 {
                128
            } else {
                32
            };
            let slot = response.sequence & (slots - 1);
            let tfd = device_read(
                domain,
                boot.command.region().address,
                usize::from(slot) * 256,
                256,
            );
            let first = u64::from_le_bytes(tfd[4..12].try_into().unwrap());
            let header = device_read(domain, first, 0, 8);
            if response.sequence == u16::from_le_bytes(header[2..4].try_into().unwrap()) {
                let mut r = domain.records.lock().unwrap();
                r.completed.insert(id(boot.command.region().address));
                r.completed.insert(id(first));
            }
        }
    }
    let payload = &boot.buffers[usize::from(vid - 1)].allocation;
    device_write(domain, payload.region().address, 0, packet, true);
    let mut descriptor = [0; 32];
    let stride = if boot.profile.family() >= Family::Bz {
        // `iwl_rx_completion_desc_bz`: the buffer ID first, in 4 bytes.
        descriptor[..2].copy_from_slice(&vid.to_le_bytes());
        4
    } else if boot.profile.family() >= Family::Ax210 {
        descriptor[4..6].copy_from_slice(&vid.to_le_bytes());
        32
    } else {
        descriptor[..4].copy_from_slice(&(0xf0000000 | u32::from(vid)).to_le_bytes());
        4
    };
    device_write(
        domain,
        boot.used.region().address,
        usize::from(index) * stride,
        &descriptor[..stride],
        false,
    );
    device_write(
        domain,
        boot.status.region().address,
        0,
        &(index + 1).to_le_bytes(),
        false,
    );
}
