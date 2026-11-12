extern crate std;
use super::super::beacon::tests::{Domain, Model, Source};
use super::*;
use alloc::vec;
use std::sync::Mutex;

#[derive(Default)]
struct Device {
    base: u32,
    consumer: u16,
    producer: u16,
    configured: bool,
    drops: usize,
    fail_configure: bool,
    fail_publish: bool,
    removed: bool,
}
struct Io(Arc<Mutex<Device>>);
// SAFETY: serialized device model observes native ring mappings and owns
// its fresh modeled producer/consumer register state, with no real DMA.
unsafe impl Registers for Io {
    fn configure(&mut self, base: u32, count: u16) -> Result<(), Error> {
        let mut d = self.0.lock().unwrap();
        assert_eq!(count, 512);
        d.base = base;
        d.configured = true;
        if d.fail_configure {
            Err(Error::Register)
        } else {
            Ok(())
        }
    }
    fn indices(&mut self) -> Result<(u16, u16), Error> {
        let d = self.0.lock().unwrap();
        if d.removed {
            Err(Error::Removed)
        } else {
            Ok((d.consumer, d.producer))
        }
    }
    fn publish(&mut self, consumer: u16) -> Result<(), Error> {
        let mut d = self.0.lock().unwrap();
        d.consumer = consumer;
        if d.fail_publish {
            Err(Error::Register)
        } else {
            Ok(())
        }
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        self.0.lock().unwrap().drops += 1;
    }
}
struct Harness {
    memory: Arc<Mutex<Model>>,
    device: Arc<Mutex<Device>>,
    ring: Ring<Io>,
}
impl Harness {
    fn new() -> Self {
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        // SAFETY: synchronous stopped model, real native allocations with
        // distinct serialized IOVAs; no hardware/physical proof claimed.
        let ring = unsafe {
            Ring::install(
                Io(device.clone()),
                &Source,
                Arc::new(Domain(memory.clone())),
            )
        }
        .unwrap();
        Self {
            memory,
            device,
            ring,
        }
    }
    fn descriptor(&self, index: usize) -> [u8; 8] {
        let d = self.device.lock().unwrap();
        let m = self.memory.lock().unwrap();
        let (_, base) = &m.mappings[&u64::from(d.base)];
        // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and
        // nothing accesses it concurrently.
        unsafe { core::slice::from_raw_parts((*base + index * 8) as *const u8, 8) }
            .try_into()
            .unwrap()
    }
    /// Model writes only device-owned buffers addressed by native
    /// RXBDs; completing producer is the final device publication event.
    fn complete(&self, packets: usize, first_tag: u16, packet: &[u8]) {
        let mut d = self.device.lock().unwrap();
        let m = self.memory.lock().unwrap();
        let (_, base) = &m.mappings[&u64::from(d.base)];
        assert_eq!(m.directions[&u64::from(d.base)], Direction::Bidirectional);
        for i in 0..packets {
            let index = (usize::from(d.producer) + i) % COUNT;
            let desc = *base + index * 8;
            // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and
            // nothing accesses it concurrently.
            let bytes = unsafe { core::slice::from_raw_parts(desc as *const u8, 8) };
            assert_eq!(&bytes[..4], &[214, 44, 0, 0]);
            let address = u32::from_le_bytes(bytes[4..].try_into().unwrap());
            let (_, buffer) = &m.mappings[&u64::from(address)];
            assert_eq!(m.directions[&u64::from(address)], Direction::FromDevice);
            assert!(packet.len() <= BUFFER);
            // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and
            // nothing accesses it concurrently.
            unsafe {
                (*buffer as *mut u8).copy_from_nonoverlapping(packet.as_ptr(), packet.len());
                ((desc + 2) as *mut u16).write_volatile(((first_tag + i as u16) % 8192).to_le());
            }
        }
        d.producer = ((usize::from(d.producer) + packets) % COUNT) as u16;
    }
}
fn packet(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length + 24];
    bytes[..4].copy_from_slice(&(length as u32).to_le_bytes());
    for (i, b) in bytes[24..].iter_mut().enumerate() {
        *b = i as u8;
    }
    bytes
}
#[test]
fn source_descriptor_fields_remain_raw_and_all_ranges_are_bounded() {
    let mut bytes = vec![0; 24 + 3 + 32 + 10];
    let w0: u32 = 10 | (1 << 14) | (1 << 15) | (4 << 16) | (7 << 20) | (3 << 24) | (1 << 26);
    bytes[..4].copy_from_slice(&w0.to_le_bytes());
    bytes[4..8].copy_from_slice(&127u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&(3u32 << 29).to_le_bytes());
    bytes[12..16].copy_from_slice(&83u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&48u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&0xfedcba98u32.to_le_bytes());
    let p = parse(&bytes).unwrap();
    assert_eq!(
        (p.shift.len(), p.driver_info.len(), p.payload.len()),
        (3, 32, 10)
    );
    assert!(p.facts.crc_error && p.facts.icv_error && p.facts.hardware_decrypted);
    assert_eq!(
        (
            p.facts.encryption_raw,
            p.facts.cam_id,
            p.facts.ppdu_count,
            p.facts.rate_raw,
            p.facts.bandwidth_raw,
            p.facts.tsf_low
        ),
        (7, 127, 3, 83, 3, 0xfedcba98)
    );
    for n in 0..bytes.len() {
        assert!(parse(&bytes[..n]).is_err());
    }
    for (word, expected) in [
        (10u32 | 1 << 16, ParseError::DriverInfo(1)),
        (10 | 1 << 26, ParseError::MissingPhy),
        (4, ParseError::Length),
        (11455, ParseError::Length),
    ] {
        bytes[..4].copy_from_slice(&word.to_le_bytes());
        assert_eq!(parse(&bytes).unwrap_err(), expected);
    }
    bytes[..4].copy_from_slice(&10u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&84u32.to_le_bytes());
    assert_eq!(parse(&bytes).unwrap_err(), ParseError::Rate(84));
    let mut c2h = packet(0);
    c2h[8..12].copy_from_slice(&(1u32 << 28).to_le_bytes());
    assert!(parse(&c2h).unwrap().facts.firmware);
    assert!(parse(&packet(11454)).is_ok());
    let mut oversized = vec![0; BUFFER + 32];
    oversized[..4].copy_from_slice(&(11454u32 | (4 << 16)).to_le_bytes());
    assert_eq!(parse(&oversized).unwrap_err(), ParseError::Bounds);
}
#[test]
fn native_iovas_visibility_budget_wrap_and_tag_wrap_match_device_ownership() {
    let mut h = Harness::new();
    assert_eq!(h.memory.lock().unwrap().mappings.len(), 513);
    assert_ne!(
        u64::from(h.device.lock().unwrap().base),
        h.ring.descriptor.cpu.address(0, 1).unwrap().as_ptr() as u64
    );
    assert_eq!(
        h.ring.poll(100, |_| panic!("no producer advance")).unwrap(),
        0
    );
    let frame = packet(64);
    let mut received = 0;
    // More than 8192 packets crosses both the 512-slot ring and 13-bit tag.
    for _ in 0..18 {
        h.complete(511, h.ring.expected_tag(), &frame);
        let old_read = h.ring.consumer();
        assert_eq!(
            h.ring
                .poll(7, |p| {
                    assert_eq!(p.payload, &frame[24..]);
                    received += 1;
                })
                .unwrap(),
            7
        );
        assert_eq!(h.ring.consumer(), (old_read + 7) % 512);
        assert_eq!(
            h.ring
                .poll(usize::MAX, |p| {
                    assert_eq!(p.payload, &frame[24..]);
                    received += 1;
                })
                .unwrap(),
            504
        );
        assert_eq!(h.ring.consumer(), h.device.lock().unwrap().consumer);
        assert_eq!(&h.descriptor(usize::from(old_read))[..4], &[214, 44, 0, 0]);
    }
    assert_eq!(received, 9198);
    assert_eq!(h.ring.expected_tag(), 1006);
    assert_eq!(h.memory.lock().unwrap().cpu_syncs, received * 2);
    // SAFETY: model is synchronous, no outstanding writes/workers remain.
    unsafe { h.ring.release_after_stop() }.unwrap();
    assert!(h.memory.lock().unwrap().mappings.is_empty());
    assert_eq!(h.ring.poll(1, |_| {}), Err(Error::Quarantined));
    drop(h.ring);
    assert_eq!(h.device.lock().unwrap().drops, 1);
}
#[test]
fn adverse_completion_errors_never_release_pins_or_claim_a_frame() {
    for mode in 2..8 {
        let mut h = Harness::new();
        h.complete(1, 0, &packet(64));
        match mode {
            2 => h.device.lock().unwrap().consumer = 1,
            3 => h.device.lock().unwrap().producer = 512,
            4 => h.device.lock().unwrap().removed = true,
            5 => h.memory.lock().unwrap().fail_cpu_sync_at = Some(1),
            6 => h.memory.lock().unwrap().fail_cpu_sync_at = Some(2),
            7 => h.memory.lock().unwrap().fail_sync_at = Some(514),
            _ => (),
        }
        let mut frames = 0;
        assert!(h.ring.poll(1, |_| frames += 1).is_err(), "mode {mode}");
        assert_eq!(frames, usize::from(mode == 7));
        assert!(h.ring.quarantined());
        assert_eq!(h.ring.poll(1, |_| panic!()), Err(Error::Quarantined));
        assert_eq!(
            h.device.lock().unwrap().consumer,
            if mode == 2 { 1 } else { 0 }
        );
        drop(h.ring);
        assert_eq!(h.device.lock().unwrap().drops, 0);
        assert_eq!(h.memory.lock().unwrap().mappings.len(), 513);
    }
}
#[test]
fn what_rtw88_drops_or_only_warns_of_leaves_the_ring_running() {
    let mut h = Harness::new();
    let good = packet(64);
    // A slot whose tag is out of step: "pci bus timeout", and the frame is taken.
    h.complete(1, 9, &good);
    // Descriptors rtw_rx_query_rx_desc refuses: an FCS alone, a rate past
    // DESC_RATE_MAX, a driver info size other than the PHY status's, and PHY
    // status with no driver info.
    let mut refused = Vec::new();
    for w0 in [4u32, 64 | (1 << 16), 64 | (1 << 26)] {
        let mut bytes = packet(64);
        bytes[..4].copy_from_slice(&w0.to_le_bytes());
        refused.push(bytes);
    }
    let mut rate = packet(64);
    rate[12] = 0x54;
    refused.push(rate);
    for (at, bytes) in refused.iter().enumerate() {
        h.complete(1, h.ring.expected_tag() + 1 + at as u16, bytes);
    }
    h.complete(1, h.ring.expected_tag() + 5, &good);
    let mut payloads = Vec::new();
    assert_eq!(
        h.ring
            .poll(usize::MAX, |p| payloads.push(p.payload.to_vec()))
            .unwrap(),
        6
    );
    assert_eq!(payloads, [good[24..].to_vec(), good[24..].to_vec()]);
    assert_eq!((h.ring.tag_slips(), h.ring.dropped()), (1, 4));
    assert!(!h.ring.quarantined());
    assert_eq!(h.device.lock().unwrap().consumer, 6);
    // Every slot was rearmed, and the expected tag counted on through them.
    assert_eq!(h.ring.expected_tag(), 6);
    for index in 0..6 {
        assert_eq!(&h.descriptor(index)[..4], &[214, 44, 0, 0]);
    }
    h.complete(1, 6, &good);
    assert_eq!(h.ring.poll(1, |_| {}).unwrap(), 1);
    assert_eq!((h.ring.tag_slips(), h.ring.dropped()), (1, 4));
}
#[test]
fn configuration_publish_unmap_and_callback_uncertainty_keep_owner() {
    let memory = Arc::new(Mutex::new(Model::default()));
    let device = Arc::new(Mutex::new(Device {
        fail_configure: true,
        ..Device::default()
    }));
    assert!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe {
            Ring::install(
                Io(device.clone()),
                &Source,
                Arc::new(Domain(memory.clone())),
            )
        }
        .is_err()
    );
    assert_eq!(device.lock().unwrap().drops, 0);
    assert_eq!(memory.lock().unwrap().mappings.len(), 513);
    for mode in 0..3 {
        let mut h = Harness::new();
        h.complete(1, 0, &packet(64));
        match mode {
            0 => {
                h.device.lock().unwrap().fail_publish = true;
                assert!(h.ring.poll(1, |_| {}).is_err());
            }
            1 => {
                h.memory.lock().unwrap().fail_unmap = true;
                // SAFETY: the model device is stopped and drained, so nothing still uses what
                // this releases.
                assert!(unsafe { h.ring.release_after_stop() }.is_err());
            }
            _ => {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h
                        .ring
                        .poll(1, |_| panic!("model callback"))))
                    .is_err()
                );
            }
        }
        assert!(h.ring.quarantined());
        drop(h.ring);
        assert_eq!(h.device.lock().unwrap().drops, 0);
        assert_eq!(h.memory.lock().unwrap().mappings.len(), 513);
    }
}
#[test]
fn unpublished_errors_release_all_allocations_before_register_publication() {
    for mode in 0..4 {
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        match mode {
            0 => device.lock().unwrap().producer = 1,
            1 => memory.lock().unwrap().address_overflow = true,
            2 => memory.lock().unwrap().fail_sync_at = Some(256),
            3 => memory.lock().unwrap().fail_sync_at = Some(513),
            _ => unreachable!(),
        }
        assert!(
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            unsafe {
                Ring::install(
                    Io(device.clone()),
                    &Source,
                    Arc::new(Domain(memory.clone())),
                )
            }
            .is_err()
        );
        assert_eq!(device.lock().unwrap().drops, 1);
        assert!(!device.lock().unwrap().configured);
        assert!(memory.lock().unwrap().mappings.is_empty());
    }
}
#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_RECEIVE_ORACLE"]
fn raw_parser_rearm_tags_and_all_ring_indices_match_unchanged_c() {
    let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_RECEIVE_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    let word =
        |bytes: &[u8], i: usize| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    for case in 0..131072 {
        let input = &trace[offset..offset + 24];
        let output = &trace[offset + 24..offset + 80];
        let mut buffer = vec![0; BUFFER];
        buffer[..24].copy_from_slice(input);
        let native = parse(&buffer);
        assert_eq!(native.is_ok(), word(output, 0) == 0, "case {case}");
        if let Ok(p) = native {
            let f = p.facts;
            let actual = [
                0,
                p.payload.len() as u32,
                f.crc_error.into(),
                f.icv_error.into(),
                p.driver_info.len() as u32,
                p.shift.len() as u32,
                f.phy_present.into(),
                f.hardware_decrypted.into(),
                f.cam_id.into(),
                f.firmware.into(),
                f.ppdu_count.into(),
                f.rate_raw.into(),
                f.bandwidth_raw.into(),
                f.tsf_low,
            ];
            for (i, actual) in actual.into_iter().enumerate() {
                assert_eq!(actual, word(output, i), "case {case}, field {i}");
            }
            assert_eq!(f.encryption_raw, ((word(input, 0) >> 20) & 7) as u8);
        }
        offset += 80;
    }
    for tag in 0..8192 {
        assert_eq!(buffer_descriptor(0x12340000), trace[offset..offset + 8]);
        assert_eq!(word(&trace[offset + 8..], 0), (tag + 1) % 8192);
        assert_eq!(word(&trace[offset + 8..], 1), 0);
        assert_eq!(word(&trace[offset + 8..], 2), (tag + 1) % 8192);
        assert_eq!(word(&trace[offset + 8..], 3), 1);
        offset += 24;
    }
    for consumer in 0..512 {
        for producer in 0..512 {
            assert_eq!(
                available(consumer, producer) as u32,
                word(&trace[offset..], 0)
            );
            offset += 4;
        }
    }
    assert_eq!(offset, trace.len());
}
