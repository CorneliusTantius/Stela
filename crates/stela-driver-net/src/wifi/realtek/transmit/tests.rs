extern crate std;
use super::super::{
    beacon::tests::{Domain, Model, Source},
    identity::tests::profile,
};
use super::*;
use crate::wifi::realtek::phy::Initialized;
use std::sync::Mutex;
#[derive(Default)]
struct Device {
    bases: [u32; 7],
    indices: [(u16, u16); 7],
    configure_count: usize,
    fail_configure: Option<usize>,
    fail_publish: bool,
    identity_changed: bool,
    not_ready: bool,
    drops: usize,
    packets: Vec<Vec<u8>>,
    iqk_trigger: Option<Arc<core::sync::atomic::AtomicBool>>,
    descriptors: Vec<[u8; 16]>,
}
struct Io {
    device: Arc<Mutex<Device>>,
    memory: Arc<Mutex<Model>>,
    profile: Profile,
}
fn index(q: Queue) -> usize {
    QUEUES.into_iter().position(|v| v == q).unwrap()
}
// SAFETY: serialized model's fresh indices and kept native
// allocation IOVAs; no hardware or privileged DMA proof claimed.
unsafe impl Registers for Io {
    fn profile(&self) -> Profile {
        self.profile
    }
    fn verify_identity(&mut self) -> Result<(), Error> {
        if self.device.lock().unwrap().identity_changed {
            Err(Error::IdentityChanged)
        } else {
            Ok(())
        }
    }
    fn firmware_ready(&mut self) -> Result<(), Error> {
        if self.device.lock().unwrap().not_ready {
            Err(Error::FirmwareNotReady)
        } else {
            Ok(())
        }
    }
    fn indices(&mut self, q: Queue) -> Result<(u16, u16), Error> {
        Ok(self.device.lock().unwrap().indices[index(q)])
    }
    fn configure(&mut self, q: Queue, address: u32) -> Result<(), Error> {
        let mut d = self.device.lock().unwrap();
        d.bases[index(q)] = address;
        d.configure_count += 1;
        if d.fail_configure == Some(d.configure_count) {
            Err(Error::Register)
        } else {
            Ok(())
        }
    }
    fn publish(&mut self, q: Queue, producer: u16) -> Result<(), Error> {
        self.device.lock().unwrap().indices[index(q)].0 = producer;
        Ok(())
    }
    fn publish_h2c(&mut self, producer: u16) -> Result<(), Error> {
        let mut d = self.device.lock().unwrap();
        let m = self.memory.lock().unwrap();
        let (_, base) = &m.mappings[&u64::from(d.bases[6])];
        let slot = usize::from(d.indices[6].0);
        let bytes =
                // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and
                // nothing accesses it concurrently.
                unsafe { core::slice::from_raw_parts((*base + slot * 16) as *const u8, 16) };
        let descriptor: [u8; 16] = bytes.try_into().unwrap();
        let address = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(
            m.directions[&u64::from(d.bases[6])],
            Direction::Bidirectional
        );
        assert_eq!(m.directions[&u64::from(address)], Direction::ToDevice);
        let (_, packet) = &m.mappings[&u64::from(address)];
        d.packets
            // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and
            // nothing accesses it concurrently.
            .push(unsafe { core::slice::from_raw_parts(*packet as *const u8, 80) }.to_vec());
        if d.packets.last().unwrap()[50] == 0x0e
            && let Some(trigger) = &d.iqk_trigger
        {
            trigger.store(true, Ordering::SeqCst);
        }
        d.descriptors.push(descriptor);
        d.indices[6].0 = producer;
        if d.fail_publish {
            Err(Error::Register)
        } else {
            Ok(())
        }
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        self.device.lock().unwrap().drops += 1;
    }
}
fn install(memory: &Arc<Mutex<Model>>, device: &Arc<Mutex<Device>>) -> Result<Rings<Io>, Error> {
    install_profile(memory, device, profile())
}
fn install_profile(
    memory: &Arc<Mutex<Model>>,
    device: &Arc<Mutex<Device>>,
    profile: Profile,
) -> Result<Rings<Io>, Error> {
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    unsafe {
        Rings::install(
            Io {
                device: device.clone(),
                memory: memory.clone(),
                profile,
            },
            &Source,
            Arc::new(Domain(memory.clone())),
        )
    }
}
#[test]
fn frames_take_their_queue_and_come_back_as_the_device_reads_them() {
    let memory = Arc::new(Mutex::new(Model::default()));
    let device = Arc::new(Mutex::new(Device::default()));
    let mut rings = install(&memory, &device).unwrap();
    let queue = Queue::Management;
    for _ in 0..127 {
        rings.frame(queue, &Source, &[0; 48], &[0; 100]).unwrap();
    }
    assert_eq!(
        rings.frame(queue, &Source, &[0; 48], &[0; 100]),
        Err(Error::Full)
    );
    assert!(!rings.quarantined());
    device.lock().unwrap().indices[index(queue)].1 = 3;
    assert_eq!(rings.reclaim_frames(), Ok(3));
    assert_eq!(rings.spare.len(), 3);
    rings.frame(queue, &Source, &[0; 48], &[0; 100]).unwrap();
    assert_eq!(rings.spare.len(), 2);
    assert_eq!(
        rings.frame(Queue::H2c, &Source, &[0; 48], &[]),
        Err(Error::UnsupportedLayout)
    );
    device.lock().unwrap().indices[index(queue)].1 = 1;
    assert_eq!(rings.reclaim_frames(), Err(Error::CompletionBeyondPending));
    assert!(rings.quarantined());
}

#[test]
fn a_frames_two_buffers_are_the_descriptor_and_the_mpdu_behind_it() {
    let descriptor = frame_descriptor(0x1000, 81);
    assert_eq!(descriptor[..4], [48, 0, 2, 0]);
    assert_eq!(descriptor[4..8], 0x1000u32.to_le_bytes());
    assert_eq!(descriptor[8..10], [81, 0]);
    assert_eq!(descriptor[12..], 0x1030u32.to_le_bytes());
}

#[test]
fn phydm_and_iqk_complete_on_fresh_status() {
    use super::super::firmware_control::{Control, tests::bus};
    let (phy, report) = super::super::phy::control_fixture();
    let (io, fw, _, _) = bus(report.profile());
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut control = unsafe { Control::new(io, &report) }.unwrap();
    let memory = Arc::new(Mutex::new(Model::default()));
    let device = Arc::new(Mutex::new(Device::default()));
    device.lock().unwrap().iqk_trigger = Some(fw.lock().unwrap().trigger.clone());
    let mut rings = install_profile(&memory, &device, report.profile()).unwrap();
    rings
        .general_info(&Source, Geometry::for_profile(report.profile()).unwrap())
        .unwrap();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    unsafe {
        rings.phydm_info(
            &Source,
            &Initialized::Rtl8822C(alloc::boxed::Box::new(phy)),
            &report,
        )
    }
    .unwrap();
    fw.lock().unwrap().iqk_after = Some(16);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let observed = unsafe { control.iqk(&mut rings, &Source) }.unwrap();
    assert_eq!(observed.baseline(), 0);
    assert_eq!(observed.status(), 0xaa);
    assert_eq!(rings.pending(), 3);
    assert!(!rings.quarantined());
    let d = device.lock().unwrap();
    assert_eq!(d.packets.len(), 3);
    assert_eq!(
        &d.packets[1][48..80],
        &phydm_info(0, 2, report.profile().cut(), 3, 3, 1)
    );
    assert_eq!(&d.packets[2][48..80], &iqk(2, true, false));
    // rtw8821c_do_iqk's command: no clear, segmented once associated.
    assert_eq!(iqk(3, false, true)[8], 2);
    assert_eq!(iqk(3, false, false)[8], 0);
    drop(d);
    assert_eq!(fw.lock().unwrap().get(REG_IQKSTAT, 1), 0);
    assert_eq!(fw.lock().unwrap().now, 320000);
    // The DMA consumer may release these mappings, independently
    // of firmware execution or the observed IQK status.
    let producer = device.lock().unwrap().indices[6].0;
    device.lock().unwrap().indices[6].1 = producer;
    assert_eq!(rings.reclaim_h2c().unwrap(), 3);
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    unsafe { rings.release_after_stop() }.unwrap();
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    let io = unsafe { control.release_after_stop() }.unwrap();
    drop(io);
}
#[test]
fn a_stale_or_late_iqk_goes_on_and_publication_or_unwind_failures_quarantine_both_owners() {
    use super::super::firmware_control::{Control, Error as FwError, tests::bus};
    for mode in 0..4 {
        let (_, report) = super::super::phy::control_fixture();
        let (io, fw, owner, _) = bus(report.profile());
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let mut control = unsafe { Control::new(io, &report) }.unwrap();
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        device.lock().unwrap().iqk_trigger = Some(fw.lock().unwrap().trigger.clone());
        let mut rings = install_profile(&memory, &device, report.profile()).unwrap();
        fw.lock().unwrap().clear_log();
        match mode {
            0 => fw.lock().unwrap().set(REG_RPT_CIP, 1, 0xaa),
            1 => fw.lock().unwrap().iqk_after = None,
            2 => device.lock().unwrap().fail_publish = true,
            _ => fw.lock().unwrap().panic_at = Some(6),
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            control.iqk(&mut rings, &Source)
        }));
        if mode < 2 {
            // rtw8822c_do_iqk: a done status left from an earlier IQK ends
            // the wait at once, and a wait that runs out is only warned of.
            let observed = result.unwrap().unwrap();
            assert_eq!(observed.completed(), mode == 0);
            assert_eq!(observed.baseline(), if mode == 0 { 0xaa } else { 0 });
            assert_eq!(rings.pending(), 1);
            assert_eq!(fw.lock().unwrap().get(REG_IQKSTAT, 1), 0);
            assert!(!control.quarantined());
            assert!(!rings.quarantined());
            continue;
        } else if mode == 2 {
            assert_eq!(
                result.unwrap().unwrap_err(),
                FwError::Packet(Error::Register)
            );
            assert_eq!(rings.pending(), 1);
        } else {
            assert!(result.is_err());
        }
        assert!(control.quarantined());
        assert!(rings.quarantined());
        drop(control);
        drop(rings);
        assert_eq!(Arc::strong_count(&owner), 2);
    }
}
#[test]
fn a_polled_iqk_takes_one_look_a_call_and_ends_at_done_its_300_ms_or_a_hurry() {
    use super::super::firmware_control::{Control, Error as FwError, tests::bus};
    for mode in 0..3 {
        let (_, report) = super::super::phy::control_fixture();
        let (io, fw, _, _) = bus(report.profile());
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let mut control = unsafe { Control::new(io, &report) }.unwrap();
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        device.lock().unwrap().iqk_trigger = Some(fw.lock().unwrap().trigger.clone());
        let mut rings = install_profile(&memory, &device, report.profile()).unwrap();
        fw.lock().unwrap().iqk_after = (mode == 0).then_some(3);
        // SAFETY: as above.
        let mut wait = unsafe { control.start_iqk(&mut rings, &Source) }.unwrap();
        assert_eq!(
            control.command((0, 0)),
            Err(FwError::InvalidState),
            "nothing interrupts the IQK"
        );
        let mut looks = 0;
        let observed = loop {
            looks += 1;
            let hurry = mode == 2 && looks == 2;
            if let Some(observed) = control.poll_iqk(&mut rings, &mut wait, hurry).unwrap() {
                break observed;
            }
            assert!(looks < 100);
            fw.lock().unwrap().now += 20_000;
        };
        match mode {
            0 => assert!(observed.completed() && looks == 4),
            1 => assert!(
                !observed.completed() && (15..=17).contains(&looks),
                "{looks}"
            ),
            _ => assert!(!observed.completed() && looks == 2),
        }
        assert_eq!(fw.lock().unwrap().get(REG_IQKSTAT, 1), 0);
        assert!(!control.quarantined() && !rings.quarantined());
        assert!(
            control.poll_iqk(&mut rings, &mut wait, false).is_err(),
            "the wait is over"
        );
        assert_eq!(control.command((0, 0)), Ok(()));
    }
}
#[test]
fn every_iqk_control_failure_late_reset_and_regressed_clock_keep_both_owners() {
    use super::super::firmware_control::{Control, tests::bus};
    // One successful run determines the I/O/clock transaction count;
    // each later case fails one operation, including post-publication
    // status/clear/identity checks, while keeping the real DMA model live.
    let mut total = 0;
    for fault in 0..64 {
        if fault > total && fault != 0 {
            break;
        }
        let (_, report) = super::super::phy::control_fixture();
        let (io, fw, owner, _) = bus(report.profile());
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let mut control = unsafe { Control::new(io, &report) }.unwrap();
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        device.lock().unwrap().iqk_trigger = Some(fw.lock().unwrap().trigger.clone());
        let mut rings = install_profile(&memory, &device, report.profile()).unwrap();
        {
            let mut f = fw.lock().unwrap();
            f.clear_log();
            f.iqk_after = Some(1);
            f.fail = (fault != 0).then_some(fault);
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let result = unsafe { control.iqk(&mut rings, &Source) };
        if fault == 0 {
            result.unwrap();
            total = fw.lock().unwrap().calls;
            assert!(total > 10);
            // SAFETY: the model device is stopped and drained, so nothing still uses what this
            // releases.
            unsafe { rings.release_after_stop() }.unwrap();
            // SAFETY: the model device is stopped and drained, so nothing still uses what this
            // releases.
            drop(unsafe { control.release_after_stop() }.unwrap());
        } else {
            assert!(result.is_err(), "operation {fault}");
            assert!(control.quarantined());
            assert!(rings.quarantined());
            drop(control);
            drop(rings);
            assert_eq!(Arc::strong_count(&owner), 2);
        }
    }
    assert!(total < 64);
    for mode in 0..5 {
        let (_, report) = super::super::phy::control_fixture();
        let (io, fw, _, _) = bus(report.profile());
        if mode == 2 {
            fw.lock().unwrap().now = 100;
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let mut control = unsafe { Control::new(io, &report) }.unwrap();
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        device.lock().unwrap().iqk_trigger = Some(fw.lock().unwrap().trigger.clone());
        let mut rings = install_profile(&memory, &device, report.profile()).unwrap();
        {
            let mut f = fw.lock().unwrap();
            f.clear_log();
            match mode {
                0 => f.set(REG_SYS_CFG1, 4, report.profile().observed().sys_cfg1 ^ 1),
                1 => f.set(REG_MCUFW_CTRL, 2, 0),
                2 => f.regress = true,
                3 => f.mutate_at = Some((8, 0xf0, 4, report.profile().observed().sys_cfg1 ^ 1)),
                _ => f.mutate_at = Some((9, 0x80, 2, 0)),
            }
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        assert!(unsafe { control.iqk(&mut rings, &Source) }.is_err());
        assert!(control.quarantined());
        assert!(rings.quarantined());
        if mode < 2 {
            assert!(device.lock().unwrap().packets.is_empty());
        } else {
            assert_eq!(rings.pending(), 1);
        }
    }
}
#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_FIRMWARE_CONTROL_ORACLE"]
fn full_phydm_iqk_packets_and_iqk_ready_deadlines_match_unchanged_source() {
    use super::super::firmware_control::{Control, tests::bus};
    let dir = std::path::PathBuf::from(
        std::env::var("STELA_REALTEK_WIFI_FIRMWARE_CONTROL_ORACLE").unwrap(),
    );
    let bytes = std::fs::read(dir.join("packets.bin")).unwrap();
    assert_eq!(bytes.len(), 65536 * 64);
    for c in 0..65536usize {
        let offset = c * 64;
        assert_eq!(
            phydm_info((c % 7) as u8, 2, ((c / 7) % 7) as u8, 3, 3, c as u16),
            bytes[offset..offset + 32]
        );
        assert_eq!(iqk(c as u16, true, false), bytes[offset + 32..offset + 64]);
    }
    let bytes = std::fs::read(dir.join("iqk.bin")).unwrap();
    let mut offset = 0;
    let mut cases = 0;
    while offset < bytes.len() {
        let h: [u32; 3] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                bytes[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        offset += 12;
        let packet = &bytes[offset..offset + 32];
        offset += 32;
        let source = &bytes[offset..offset + h[1] as usize * 16];
        offset += source.len();
        let (_, report) = super::super::phy::control_fixture();
        let (io, fw, _, _) = bus(report.profile());
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let mut control = unsafe { Control::new(io, &report) }.unwrap();
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        device.lock().unwrap().iqk_trigger = Some(fw.lock().unwrap().trigger.clone());
        let mut rings = install_profile(&memory, &device, report.profile()).unwrap();
        rings.sequence = h[0] as u16;
        {
            let mut f = fw.lock().unwrap();
            f.clear_log();
            f.iqk_after = Some(h[0] as usize);
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let result = unsafe { control.iqk(&mut rings, &Source) };
        assert_eq!(result.unwrap().completed(), h[0] <= 16, "IQK {}", h[0]);
        assert_eq!(&device.lock().unwrap().packets[0][48..80], packet);
        let mut actual: Vec<_> = fw
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .events
            .iter()
            .copied()
            .filter(|e| !(e[0] == 0 && (e[1] == 0xf0 || e[1] == 0x80)))
            .collect();
        assert_eq!(actual.remove(0), [0, 0x2d9c, 1, 0], "fresh baseline");
        let actual: Vec<u8> = actual
            .into_iter()
            .flat_map(|r| r.into_iter().flat_map(u32::to_le_bytes))
            .collect();
        assert_eq!(actual, source, "IQK trace {}", h[0]);
        cases += 1;
    }
    assert_eq!(cases, 19);
}
#[test]
fn native_bases_and_real_dma_consumer_control_firmware_packet_lifetime() {
    let memory = Arc::new(Mutex::new(Model::default()));
    let device = Arc::new(Mutex::new(Device::default()));
    let mut rings = install(&memory, &device).unwrap();
    let geometry = Geometry::for_profile(profile()).unwrap();
    assert_eq!(memory.lock().unwrap().mappings.len(), 7);
    for q in QUEUES {
        let m = memory.lock().unwrap();
        let d = device.lock().unwrap();
        let (pages, pointer) = &m.mappings[&u64::from(d.bases[index(q)])];
        assert_eq!(pages.bytes(), 4096);
        assert!(
            // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and
            // nothing accesses it concurrently.
            unsafe { core::slice::from_raw_parts(*pointer as *const u8, pages.bytes()) }
                .iter()
                .all(|b| *b == 0)
        );
    }
    for round in 0..3 {
        for _ in 0..127 {
            rings.general_info(&Source, geometry).unwrap();
        }
        assert_eq!(rings.general_info(&Source, geometry), Err(Error::Full));
        assert!(!rings.quarantined());
        assert_eq!(rings.pending(), 127);
        assert_eq!(rings.reclaim_h2c().unwrap(), 0);
        assert_eq!(memory.lock().unwrap().mappings.len(), 134);
        let producer = device.lock().unwrap().indices[6].0;
        device.lock().unwrap().indices[6].1 = producer;
        assert_eq!(rings.reclaim_h2c().unwrap(), 127);
        assert_eq!(rings.pending(), 0);
        assert_eq!(memory.lock().unwrap().mappings.len(), 7);
        assert_eq!(rings.read, ((round + 1) * 127 % 128) as u16);
    }
    let d = device.lock().unwrap();
    assert_eq!(d.packets.len(), 381);
    for (seq, packet) in d.packets.iter().enumerate() {
        assert_eq!(&packet[..4], &[32, 0, 0, 0]);
        assert_eq!(&packet[4..8], &[0, 19, 0, 0]);
        assert_eq!(&packet[8..48], &[0; 40]);
        assert_eq!(&packet[48..52], &[1, 255, 13, 0]);
        assert_eq!(
            &packet[52..56],
            &(12u32 | ((seq as u32) << 16)).to_le_bytes()
        );
        assert_eq!(packet[58], 56);
    }
    drop(d);
    rings.sequence = u16::MAX;
    rings.general_info(&Source, geometry).unwrap();
    rings.general_info(&Source, geometry).unwrap();
    assert_eq!(
        &device.lock().unwrap().packets[381][54..56],
        &u16::MAX.to_le_bytes()
    );
    assert_eq!(
        &device.lock().unwrap().packets[382][54..56],
        &0u16.to_le_bytes()
    );
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    unsafe { rings.release_after_stop() }.unwrap();
    drop(rings);
    assert!(memory.lock().unwrap().mappings.is_empty());
    assert_eq!(device.lock().unwrap().drops, 1);
}
#[test]
fn uncertain_initialization_keeps_pins_and_claim() {
    for operation in 1..=7 {
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device {
            fail_configure: Some(operation),
            ..Device::default()
        }));
        assert!(install(&memory, &device).is_err());
        assert_eq!(memory.lock().unwrap().mappings.len(), operation);
        assert_eq!(device.lock().unwrap().drops, 0);
    }
    for phase in 0..4 {
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        let mut rings = install(&memory, &device).unwrap();
        match phase {
            0 => memory.lock().unwrap().fail_sync_at = Some(9),
            1 => device.lock().unwrap().fail_publish = true,
            _ => (),
        }
        let sent = rings.general_info(&Source, Geometry::for_profile(profile()).unwrap());
        if phase < 2 {
            assert!(sent.is_err());
        } else {
            sent.unwrap();
            device.lock().unwrap().indices[6].1 = 1;
            if phase == 2 {
                memory.lock().unwrap().fail_cpu_sync_at = Some(1);
            } else {
                memory.lock().unwrap().fail_unmap = true;
            }
            assert!(rings.reclaim_h2c().is_err());
        }
        assert!(rings.quarantined());
        drop(rings);
        assert_eq!(device.lock().unwrap().drops, 0);
        assert_eq!(memory.lock().unwrap().mappings.len(), 8);
    }
}
#[test]
fn invalid_indices_identity_readiness_and_unpublished_failures_cannot_publish() {
    for mode in 0..7 {
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        let mut rings = install(&memory, &device).unwrap();
        match mode {
            0 => device.lock().unwrap().indices[6].0 = 1,
            1 => device.lock().unwrap().indices[6].1 = 128,
            2 => device.lock().unwrap().indices[6].1 = 1,
            3 => device.lock().unwrap().identity_changed = true,
            4 => device.lock().unwrap().not_ready = true,
            5 => memory.lock().unwrap().fail_sync_at = Some(8),
            6 => memory.lock().unwrap().address_overflow = true,
            _ => (),
        }
        assert!(
            rings
                .general_info(&Source, Geometry::for_profile(profile()).unwrap())
                .is_err()
        );
        assert!(rings.quarantined());
        assert!(device.lock().unwrap().packets.is_empty());
        assert_eq!(memory.lock().unwrap().mappings.len(), 7);
        drop(rings);
        assert_eq!(device.lock().unwrap().drops, 0);
    }
    for mode in 0..3 {
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        match mode {
            0 => device.lock().unwrap().indices[2].1 = 1,
            1 => memory.lock().unwrap().address_overflow = true,
            2 => memory.lock().unwrap().fail_sync_at = Some(7),
            _ => (),
        }
        assert!(install(&memory, &device).is_err());
        assert_eq!(device.lock().unwrap().configure_count, 0);
        assert_eq!(device.lock().unwrap().drops, 1);
        assert!(memory.lock().unwrap().mappings.is_empty());
    }
}
#[test]
fn impossible_completion_and_uncertain_stop_never_free_live_commands() {
    for mode in 0..3 {
        let memory = Arc::new(Mutex::new(Model::default()));
        let device = Arc::new(Mutex::new(Device::default()));
        let mut rings = install(&memory, &device).unwrap();
        rings
            .general_info(&Source, Geometry::for_profile(profile()).unwrap())
            .unwrap();
        if mode == 0 {
            device.lock().unwrap().indices[6].1 = 2;
            assert_eq!(rings.reclaim_h2c(), Err(Error::CompletionBeyondPending));
        }
        if mode == 1 {
            device.lock().unwrap().indices[6].0 = 9;
            assert_eq!(rings.reclaim_h2c(), Err(Error::Index));
        }
        if mode == 2 {
            memory.lock().unwrap().fail_unmap = true;
            // SAFETY: the model device is stopped and drained, so nothing still uses what this
            // releases.
            assert!(unsafe { rings.release_after_stop() }.is_err());
        }
        assert!(rings.quarantined());
        drop(rings);
        assert_eq!(device.lock().unwrap().drops, 0);
        assert_eq!(memory.lock().unwrap().mappings.len(), 8);
    }
    assert!(h2c_descriptors(u32::MAX - 78).is_err());
    assert!(h2c_descriptors(u32::MAX - 79).is_ok());
}
#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_TRANSMIT_ORACLE"]
fn every_sequence_full_packet_and_descriptors_match_unchanged_c() {
    let trace =
        std::fs::read(std::env::var("STELA_REALTEK_WIFI_TRANSMIT_ORACLE").unwrap()).unwrap();
    let geometry = Geometry::for_profile(profile()).unwrap();
    let (packet, descriptor) = h2c_descriptors(0x12340000).unwrap();
    for sequence in 0..=u16::MAX {
        let offset = usize::from(sequence) * 96;
        assert_eq!(
            &trace[offset..offset + 48],
            packet,
            "sequence {sequence}: TXD"
        );
        assert_eq!(
            &trace[offset + 48..offset + 80],
            general_info(geometry, sequence),
            "sequence {sequence}: command"
        );
        assert_eq!(
            &trace[offset + 80..offset + 96],
            descriptor,
            "sequence {sequence}: TXBD"
        );
    }
    assert_eq!(trace.len(), 65536 * 96);
}
