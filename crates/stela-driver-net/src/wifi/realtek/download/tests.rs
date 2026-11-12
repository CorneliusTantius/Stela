extern crate std;
use super::*;
use crate::firmware::{Catalog, Provenance, Resource, Target};
use crate::wifi::realtek::{
    identity::{Profile, tests::observed},
    io::BeaconQueue,
};
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;
use sha2::{Digest, Sha256};
use stela_driver_base::stepped::block_on;

struct Model {
    profile: Profile,
    registers: Vec<u8>,
    trace: Vec<u8>,
    submitted: Vec<Vec<u8>>,
    operations: usize,
    fail_at: Option<usize>,
    stuck_ddma: bool,
    no_beacon: bool,
    bad_checksum: bool,
    no_ready: bool,
    all_ones: Option<u32>,
    quarantined: usize,
    feature_reply: Option<[u8; 13]>,
    ignore_feature_request: bool,
    ignore_feature_ack: bool,
}
impl Model {
    fn new() -> Self {
        let mut m = Self {
            profile: profile(),
            registers: (0..0x170c).map(|i| (i * 37 + 11) as u8).collect(),
            trace: Vec::new(),
            submitted: Vec::new(),
            operations: 0,
            fail_at: None,
            stuck_ddma: false,
            no_beacon: false,
            bad_checksum: false,
            no_ready: false,
            all_ones: None,
            quarantined: 0,
            feature_reply: None,
            ignore_feature_request: false,
            ignore_feature_ack: false,
        };
        m.set(REG_SYS_CFG1, 4, m.profile.observed().sys_cfg1);
        m.set(REG_MCUFW_CTRL, 2, 0x35a5);
        m.set(REG_DDMA_CH0CTRL, 4, 0);
        m.set(REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1, 4, 1 << 29);
        m.set(REG_WL2LTECOEX_INDIRECT_ACCESS_READ_DATA_V1, 4, 0x1234_abcd);
        m
    }
    fn get(&self, r: u32, width: usize) -> u32 {
        let mut b = [0; 4];
        b[..width].copy_from_slice(&self.registers[r as usize..r as usize + width]);
        u32::from_le_bytes(b)
    }
    fn set(&mut self, r: u32, width: usize, value: u32) {
        self.registers[r as usize..r as usize + width]
            .copy_from_slice(&value.to_le_bytes()[..width]);
    }
    fn operation(&mut self) -> Result<(), Error> {
        let at = self.operations;
        self.operations += 1;
        if self.fail_at == Some(at) {
            Err(Error::Register)
        } else {
            Ok(())
        }
    }
    fn record(&mut self, tag: u32, register: u32, value: u32) {
        for word in [tag, register, value] {
            self.trace.extend_from_slice(&word.to_le_bytes());
        }
    }
    fn read(&mut self, r: u32, width: usize) -> Result<u32, Error> {
        self.operation()?;
        let value = if self.all_ones == Some(r) {
            u32::MAX
        } else {
            self.get(r, width)
        };
        self.record(width as u32, r, value);
        Ok(value)
    }
    fn write(&mut self, r: u32, width: usize, value: u32) -> Result<(), Error> {
        self.operation()?;
        self.record(4 + width as u32, r, value);
        if r == 0x1a0
            && ((value == 0xfd && self.ignore_feature_request)
                || (value == 0 && self.ignore_feature_ack))
        {
            return Ok(());
        }
        let mut stored = value;
        if r == REG_DDMA_CH0CTRL && width == 4 {
            if !self.stuck_ddma {
                stored &= !BIT_DDMACH0_OWN;
            }
            if self.bad_checksum && value & BIT_DDMACH0_OWN != 0 {
                stored |= BIT_DDMACH0_CHKSUM_STS;
            }
        }
        if r == REG_FIFOPAGE_CTRL_2 && width == 2 {
            stored &= !u32::from(BCN_VALID);
        }
        if r == REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1 && width == 4 {
            stored = 1 << 29;
        }
        self.set(r, width, stored);
        if r == 3
            && value & 4 != 0
            && !self.no_ready
            && self.get(REG_MCUFW_CTRL, 2) & 0x4050 == 0x4050
        {
            self.set(REG_MCUFW_CTRL, 2, self.get(REG_MCUFW_CTRL, 2) | 0x8000);
            if self.get(REG_C2HEVT, 1) == 0xfd
                && let Some(reply) = self.feature_reply
            {
                self.set(REG_C2HEVT, 1, 0x19);
                self.registers[0x1a2..0x1af].copy_from_slice(&reply);
            }
        }
        Ok(())
    }
}
#[derive(Clone)]
struct ModelIo(Rc<RefCell<Model>>);
fn profile() -> Profile {
    Profile::select(observed(0xc822, 1)).unwrap()
}
// SAFETY: deterministic virtual requester for unit tests, no real DMA.
// Every read/store is recorded; readiness derives from modeled events.
unsafe impl Io for ModelIo {
    fn profile(&self) -> Profile {
        self.0.borrow().profile
    }
    fn read8(&mut self, r: u32) -> Result<u8, Error> {
        self.0.borrow_mut().read(r, 1).map(|v| v as u8)
    }
    fn read16(&mut self, r: u32) -> Result<u16, Error> {
        self.0.borrow_mut().read(r, 2).map(|v| v as u16)
    }
    fn read32(&mut self, r: u32) -> Result<u32, Error> {
        self.0.borrow_mut().read(r, 4)
    }
    fn write8(&mut self, r: u32, v: u8) -> Result<(), Error> {
        self.0.borrow_mut().write(r, 1, v.into())
    }
    fn write16(&mut self, r: u32, v: u16) -> Result<(), Error> {
        self.0.borrow_mut().write(r, 2, v.into())
    }
    fn write32(&mut self, r: u32, v: u32) -> Result<(), Error> {
        self.0.borrow_mut().write(r, 4, v)
    }
    fn delay_us(&mut self, us: u64) {
        self.0.borrow_mut().record(9, 0, us as u32);
    }
    fn submit_beacon(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut m = self.0.borrow_mut();
        m.operation()?;
        m.record(10, 0, data.len() as u32);
        m.trace.extend_from_slice(data);
        m.submitted.push(data.to_vec());
        if !m.no_beacon {
            let value = m.get(REG_FIFOPAGE_CTRL_2, 2) | u32::from(BCN_VALID);
            m.set(REG_FIFOPAGE_CTRL_2, 2, value);
        }
        Ok(())
    }
    fn quarantine(&mut self) {
        self.0.borrow_mut().quarantined += 1;
    }
    unsafe fn beacon_consumed(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
fn catalog(bytes: Vec<u8>) -> Catalog {
    catalog_for(profile(), bytes)
}
/// A catalog holding `bytes` as `p`'s firmware.
pub(in crate::wifi::realtek) fn catalog_for(p: Profile, bytes: Vec<u8>) -> Catalog {
    Catalog::from_handoff(vec![Resource {
        name: p.firmware_name(),
        target: Target {
            driver: "realtek-wifi",
            hardware: &p.hardware_key(),
            revision: &p.revision_key(),
            board: None,
        },
        provenance: Provenance {
            source: "synthetic",
            revision: "1",
            member: p.firmware_name(),
            license: "MIT",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(&bytes).into(),
        bytes,
    }])
    .unwrap()
}
fn setup() -> (Rc<RefCell<Model>>, Download<ModelIo>) {
    let m = Rc::new(RefCell::new(Model::new()));
    let d = Download::new(ModelIo(m.clone()), 0x700).unwrap();
    (m, d)
}
#[test]
fn feature_request_is_fresh_and_report_stays_bound_to_same_download() {
    let c = catalog(super::super::firmware::tests::legacy_fixture());
    let staged = profile().stage(&c).unwrap();
    let (model, mut download) = setup();
    let raw = [
        0x91, 0x2f, 0x11, 0x3a, 0x52, 0x18, 0xef, 0xaa, 0xff, 1, 2, 3, 4,
    ];
    model.borrow_mut().feature_reply = Some(raw);
    model.borrow_mut().set(REG_C2HEVT, 1, 0x19); // Stale prior-boot ID.
    block_on(download.start_with_hardware_features(&staged)).unwrap();
    assert!(matches!(
        download.after_firmware_ready(),
        Err(Error::InvalidState)
    ));
    let report = block_on(download.hardware_features()).unwrap();
    assert_eq!(report.profile(), profile());
    assert_eq!(report.raw(), &raw);
    assert_eq!(
        report.capabilities(),
        super::super::features::decode(profile().observed().sys_cfg1, &raw)
    );
    assert_eq!(model.borrow().get(REG_C2HEVT, 1), 0);
    assert!(download.after_firmware_ready().is_ok());
    assert!(matches!(
        block_on(download.hardware_features()),
        Err(Error::InvalidState)
    ));
    assert_eq!(model.borrow().quarantined, 0);
    let trace = &model.borrow().trace;
    assert_eq!(
        &trace[..36],
        &[4u32, 0xf0, 0x1000, 5, 0x1a0, 0xfd, 1, 0x1a0, 0xfd]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
    );
}
#[test]
fn feature_exchange_faults_never_reuse_stale_or_partial_report() {
    let c = catalog(super::super::firmware::tests::legacy_fixture());
    let staged = profile().stage(&c).unwrap();
    let (good, mut d) = setup();
    good.borrow_mut().feature_reply = Some([0xff; 13]);
    block_on(d.start_with_hardware_features(&staged)).unwrap();
    block_on(d.hardware_features()).unwrap(); // All-ones payload is raw data, not a removal probe.
    let operations = good.borrow().operations;
    for at in 0..operations {
        let (m, mut d) = setup();
        m.borrow_mut().feature_reply = Some([0x55; 13]);
        m.borrow_mut().fail_at = Some(at);
        let failed = block_on(d.start_with_hardware_features(&staged)).is_err()
            || block_on(d.hardware_features()).is_err();
        assert!(failed, "operation {at}");
        assert_eq!(d.state(), State::Quarantined, "operation {at}");
        assert_eq!(m.borrow().quarantined, 1);
        assert!(matches!(d.after_firmware_ready(), Err(Error::InvalidState)));
        assert!(matches!(
            block_on(d.hardware_features()),
            Err(Error::InvalidState)
        ));
        drop(d);
        assert_eq!(m.borrow().quarantined, 2);
    }
    for mode in 0..8 {
        let (m, mut d) = setup();
        m.borrow_mut().set(REG_C2HEVT, 1, 0x19);
        m.borrow_mut().feature_reply = Some([0; 13]);
        match mode {
            0 => m.borrow_mut().ignore_feature_request = true,
            1 => m.borrow_mut().set(REG_SYS_CFG1, 4, u32::MAX),
            2 => m.borrow_mut().feature_reply = None,
            _ => (),
        }
        if mode < 2 {
            assert!(block_on(d.start_with_hardware_features(&staged)).is_err());
            assert!(m.borrow().submitted.is_empty());
        } else {
            block_on(d.start_with_hardware_features(&staged)).unwrap();
            match mode {
                3 => m.borrow_mut().set(REG_SYS_CFG1, 4, 0x2000),
                4 => m.borrow_mut().set(REG_MCUFW_CTRL, 2, 0xffff),
                5 => m.borrow_mut().set(REG_C2HEVT, 1, 0xff),
                6 => m.borrow_mut().ignore_feature_ack = true,
                7 => m.borrow_mut().set(REG_MCUFW_CTRL, 2, 0),
                _ => (),
            }
            assert!(block_on(d.hardware_features()).is_err(), "mode {mode}");
        }
        assert_eq!(d.state(), State::Quarantined);
        assert_eq!(m.borrow().quarantined, 1);
    }
}
#[test]
fn unrequested_features_and_rebound_image_do_not_touch_hardware() {
    let c = catalog(super::super::firmware::tests::legacy_fixture());
    let mut staged = profile().stage(&c).unwrap();
    let (m, mut d) = setup();
    assert!(matches!(
        block_on(d.hardware_features()),
        Err(Error::InvalidState)
    ));
    assert_eq!(m.borrow().operations, 0);
    block_on(d.start(&staged)).unwrap();
    let before = m.borrow().operations;
    assert!(matches!(
        block_on(d.hardware_features()),
        Err(Error::InvalidState)
    ));
    assert_eq!(m.borrow().operations, before);
    let mut actual = profile().observed();
    actual.subsystem_device ^= 1;
    staged.profile = Profile::select(actual).unwrap();
    let model = Rc::new(RefCell::new(Model::new()));
    model.borrow_mut().profile = staged.profile;
    let mut d = Download::new(ModelIo(model.clone()), 0x700).unwrap();
    assert!(matches!(
        block_on(d.start_with_hardware_features(&staged)),
        Err(StartError::Hardware(Error::WrongFirmwareTarget))
    ));
    assert_eq!(d.state(), State::Idle);
    assert_eq!(model.borrow().operations, 0);
}
#[test]
fn real_ready_requires_all_transfers_and_source_ordered_register_restoration() {
    let c = catalog(super::super::firmware::tests::legacy_fixture());
    let staged = profile().stage(&c).unwrap();
    let (model, mut download) = setup();
    assert!(matches!(
        download.after_firmware_ready(),
        Err(Error::InvalidState)
    ));
    let before = model.borrow().registers.clone();
    block_on(download.start(&staged)).unwrap();
    assert_eq!(download.state(), State::FirmwareReady);
    assert!(download.after_firmware_ready().is_ok());
    let m = model.borrow();
    assert_eq!(m.submitted.concat(), staged.image.bytes()[64..]);
    for (r, width) in [
        (0x10d, 1),
        (0x100, 1),
        (0x230, 2),
        (REG_BCN_CTRL, 1),
        (REG_CR + 1, 1),
        (REG_FWHW_TXQ_CTRL + 2, 1),
    ] {
        assert_eq!(
            &m.registers[r as usize..r as usize + width],
            &before[r as usize..r as usize + width]
        );
    }
    assert_eq!(m.get(REG_H2CQ_CSR, 4), 1 << 31);
    assert_eq!(
        m.get(REG_RQPN_CTRL_2, 4),
        u32::from_le_bytes(before[0x22c..0x230].try_into().unwrap()) | 1 << 31
    );
    assert_eq!(
        m.get(REG_MCUFW_CTRL, 2) & u32::from(FW_READY_MASK),
        u32::from(FW_READY)
    );
    assert_eq!(m.quarantined, 0);
    drop(m);
    assert!(matches!(
        block_on(download.start(&staged)),
        Err(StartError::Hardware(Error::InvalidState))
    ));
}
#[test]
fn every_uncertain_operation_is_terminal_and_keeps_submitted_memory_quarantined() {
    let c = catalog(super::super::firmware::tests::legacy_fixture());
    let staged = profile().stage(&c).unwrap();
    let (reference, mut ok) = setup();
    block_on(ok.start(&staged)).unwrap();
    let operations = reference.borrow().operations;
    for at in 0..operations {
        let (m, mut d) = setup();
        m.borrow_mut().fail_at = Some(at);
        assert!(block_on(d.start(&staged)).is_err(), "operation {at}");
        assert_eq!(d.state(), State::Quarantined, "operation {at}");
        assert_eq!(m.borrow().quarantined, 1);
        let submitted = m.borrow().submitted.clone();
        assert!(matches!(
            block_on(d.start(&staged)),
            Err(StartError::Hardware(Error::InvalidState))
        ));
        drop(d);
        assert_eq!(m.borrow().quarantined, 2);
        assert_eq!(m.borrow().submitted, submitted);
    }
}
#[test]
fn descriptor_failures_are_distinct_and_bounded() {
    let c = catalog(super::super::firmware::tests::legacy_fixture());
    let staged = profile().stage(&c).unwrap();
    for mode in 0..7 {
        let (m, mut d) = setup();
        match mode {
            0 => m.borrow_mut().stuck_ddma = true,
            1 => m.borrow_mut().no_beacon = true,
            2 => m.borrow_mut().bad_checksum = true,
            3 | 4 => {
                m.borrow_mut().no_ready = true;
                m.borrow_mut()
                    .set(REG_FW_DBG7, 4, if mode == 4 { 0xfaaa_aa00 } else { 0x1234 });
            }
            5 => m.borrow_mut().all_ones = Some(REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1),
            _ => m.borrow_mut().all_ones = Some(REG_DDMA_CH0CTRL),
        }
        let Err(StartError::Hardware(error)) = block_on(d.start(&staged)) else {
            panic!("mode {mode}");
        };
        assert_eq!(
            error,
            match mode {
                0 => Error::Timeout {
                    register: REG_DDMA_CH0CTRL,
                    mask: BIT_DDMACH0_OWN
                },
                1 => Error::Timeout {
                    register: REG_FIFOPAGE_CTRL_2,
                    mask: BCN_VALID.into()
                },
                2 => Error::Checksum {
                    destination: 0x200000
                },
                3 => Error::FirmwareNotReady { debug: 0x1234 },
                4 => Error::InvalidFirmwareKey,
                _ => Error::Register,
            }
        );
        assert!(m.borrow().operations < 1300);
        assert_eq!(d.state(), State::Quarantined);
        assert_eq!(m.borrow().quarantined, 1);
    }
}
#[test]
fn a_different_exact_provider_target_cannot_be_uploaded_to_this_requester() {
    let c = catalog(super::super::firmware::tests::legacy_fixture());
    let mut staged = profile().stage(&c).unwrap();
    let mut changed = profile().observed();
    changed.subsystem_device ^= 1;
    staged.profile = Profile::select(changed).unwrap();
    let (m, mut d) = setup();
    assert!(matches!(
        block_on(d.start(&staged)),
        Err(StartError::Hardware(Error::WrongChip))
    ));
    assert_eq!(d.state(), State::Idle);
    assert_eq!(m.borrow().operations, 0);
    assert_eq!(m.borrow().quarantined, 0);
    assert!(matches!(
        Download::new(ModelIo(m), 0x800),
        Err(Error::InvalidBoundary)
    ));
}
#[test]
fn forged_diagnostic_profile_cannot_rebind_another_requesters_provider_image() {
    let c = catalog(super::super::firmware::tests::legacy_fixture());
    for field in 0..5 {
        let mut staged = profile().stage(&c).unwrap();
        let mut actual = profile().observed();
        match field {
            0 => actual.device = 0xc82f,
            1 => actual.subsystem_vendor ^= 1,
            2 => actual.subsystem_device ^= 1,
            3 => actual.pci_revision ^= 1,
            _ => actual.sys_cfg1 ^= 1,
        }
        let actual = Profile::select(actual).unwrap();
        staged.profile = actual;
        let (m, mut d) = setup();
        m.borrow_mut().profile = actual;
        assert!(matches!(
            block_on(d.start(&staged)),
            Err(StartError::Hardware(Error::WrongFirmwareTarget))
        ));
        assert_eq!(d.state(), State::Idle);
        assert_eq!(m.borrow().operations, 0);
        assert!(m.borrow().submitted.is_empty());
        assert_eq!(m.borrow().quarantined, 0);
    }
}
#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_IMAGES, STELA_REALTEK_WIFI_TRANSPORT_ORACLE"]
fn firmware_download_register_and_packet_trace_matches_unchanged_c() {
    let root = std::env::var("STELA_REALTEK_WIFI_IMAGES").unwrap();
    let c =
        catalog(std::fs::read(std::path::Path::new(&root).join("rtw88/rtw8822c_fw.bin")).unwrap());
    let staged = profile().stage(&c).unwrap();
    let (m, mut d) = setup();
    block_on(d.start(&staged)).unwrap();
    let trace =
        std::fs::read(std::env::var("STELA_REALTEK_WIFI_TRANSPORT_ORACLE").unwrap()).unwrap();
    assert_eq!(m.borrow().trace, trace);
    assert_eq!(m.borrow().submitted.concat(), staged.image.bytes()[64..]);
    assert_eq!(d.state(), State::FirmwareReady);
    assert_eq!(m.borrow().submitted.len(), 51);
}
#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_IMAGES, STELA_REALTEK_WIFI_TRANSPORT_ORACLE"]
fn download_uses_native_pinned_beacon_dma_with_each_new_completion() {
    use super::super::beacon::tests::Harness;
    struct Combined {
        control: ModelIo,
        queue: Harness,
    }
    // SAFETY: both synchronous hardware models are serialized. A source
    // beacon-valid event is produced only after the real native queue has
    // published model IOVAs and the modeled device copied bytes.
    unsafe impl Io for Combined {
        fn profile(&self) -> Profile {
            self.control.profile()
        }
        fn read8(&mut self, r: u32) -> Result<u8, Error> {
            self.control.read8(r)
        }
        fn read16(&mut self, r: u32) -> Result<u16, Error> {
            self.control.read16(r)
        }
        fn read32(&mut self, r: u32) -> Result<u32, Error> {
            self.control.read32(r)
        }
        fn write8(&mut self, r: u32, v: u8) -> Result<(), Error> {
            self.control.write8(r, v)
        }
        fn write16(&mut self, r: u32, v: u16) -> Result<(), Error> {
            self.control.write16(r, v)
        }
        fn write32(&mut self, r: u32, v: u32) -> Result<(), Error> {
            self.control.write32(r, v)
        }
        fn delay_us(&mut self, us: u64) {
            self.control.delay_us(us);
        }
        fn submit_beacon(&mut self, data: &[u8]) -> Result<(), Error> {
            self.queue.submit(data)?;
            self.control.submit_beacon(data)
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), Error> {
            // SAFETY: the model device is stopped and drained, so nothing still uses what this
            // releases.
            unsafe { self.queue.consumed() }
        }
        fn quarantine(&mut self) {
            self.queue.quarantine();
            self.control.quarantine();
        }
    }
    let root = std::env::var("STELA_REALTEK_WIFI_IMAGES").unwrap();
    let c =
        catalog(std::fs::read(std::path::Path::new(&root).join("rtw88/rtw8822c_fw.bin")).unwrap());
    let staged = profile().stage(&c).unwrap();
    let model = Rc::new(RefCell::new(Model::new()));
    let mut d = Download::new(
        Combined {
            control: ModelIo(model.clone()),
            queue: Harness::new(),
        },
        0x700,
    )
    .unwrap();
    block_on(d.start(&staged)).unwrap();
    let packets = d.io.queue.packets();
    assert_eq!(packets.len(), 51);
    assert_eq!(
        packets
            .iter()
            .flat_map(|p| p[48..].iter().copied())
            .collect::<Vec<_>>(),
        staged.image.bytes()[64..]
    );
    assert!(!d.io.queue.pending());
    assert_eq!(
        d.io.queue.mappings(),
        2,
        "REG_MCUFW_CTRL ready cannot unmap active queue base"
    );
    let oracle =
        std::fs::read(std::env::var("STELA_REALTEK_WIFI_TRANSPORT_ORACLE").unwrap()).unwrap();
    assert_eq!(model.borrow().trace, oracle);
    // SAFETY: synchronous modeled device and submission workers stopped,
    // independently of the REG_MCUFW_CTRL-ready state, before canonical unmaps.
    unsafe {
        d.io.queue.stop();
    }
    assert_eq!(d.io.queue.mappings(), 0);
}
