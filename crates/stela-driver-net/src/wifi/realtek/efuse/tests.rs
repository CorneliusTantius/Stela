extern crate std;
use super::*;
use crate::wifi::realtek::identity::tests::profile;
use alloc::{sync::Arc, vec::Vec};
use std::sync::Mutex;
use stela_driver_base::stepped::block_on;
struct Model {
    physical: [u8; PHYSICAL],
    control: u32,
    bank: u32,
    ldo: u8,
    selected: usize,
    pending: bool,
    polls: usize,
    ready_at: Option<usize>,
    corrupt_completion: Option<(usize, u32)>,
    case: usize,
    calls: usize,
    fail: Option<usize>,
    sys: u32,
    identities: usize,
    change_identity_at: Option<usize>,
    ready: u16,
    record: bool,
    events: Vec<[u32; 4]>,
    delays: usize,
    quarantined: bool,
}
impl Model {
    fn new(case: usize) -> Self {
        Self {
            physical: core::array::from_fn(|i| ((i * 17 + case * 23) & 255) as u8),
            control: 0x5af4abcd ^ (case as u32 * 0x10304),
            bank: u32::MAX - (case as u32 * 0x10304),
            ldo: 255 - case as u8,
            selected: 0,
            pending: false,
            polls: 0,
            ready_at: None,
            corrupt_completion: None,
            case,
            calls: 0,
            fail: None,
            sys: 0,
            identities: 0,
            change_identity_at: None,
            ready: 0xc078,
            record: true,
            events: Vec::new(),
            delays: 0,
            quarantined: false,
        }
    }
    fn event(&mut self, kind: u32, r: u32, n: u32, v: u32) -> Result<(), io::Error> {
        self.calls += 1;
        if self.fail == Some(self.calls) {
            return Err(io::Error::Register);
        }
        if self.record {
            self.events.push([kind, r, n, v]);
        }
        Ok(())
    }
}
struct Registers(Arc<Mutex<Model>>);
/// [`read`] run to completion on `model`.
///
/// # Safety
/// [`read`]'s contract, for the model alone.
unsafe fn read_model(model: Arc<Mutex<Model>>) -> Result<Physical, Error> {
    let mut registers = Registers(model);
    // SAFETY: forwarded from the caller.
    block_on(unsafe { read(&mut registers) })
}
// SAFETY: serialized OTP/register/timer effects model, no physical OTP or
// calibrated timer claim. Source bytes and events stay independent.
unsafe impl Io for Registers {
    fn profile(&self) -> Profile {
        profile()
    }
    fn read8(&mut self, r: u32) -> Result<u8, io::Error> {
        assert_eq!(r, 0x29);
        let mut m = self.0.lock().unwrap();
        let v = m.ldo;
        m.event(0, r, 1, v.into())?;
        Ok(v)
    }
    fn read16(&mut self, r: u32) -> Result<u16, io::Error> {
        assert_eq!(r, 0x80);
        let mut m = self.0.lock().unwrap();
        m.calls += 1;
        if m.fail == Some(m.calls) {
            return Err(io::Error::Register);
        }
        Ok(m.ready)
    }
    fn read32(&mut self, r: u32) -> Result<u32, io::Error> {
        let mut m = self.0.lock().unwrap();
        if r == 0xf0 {
            m.calls += 1;
            if m.fail == Some(m.calls) {
                return Err(io::Error::Register);
            }
            m.identities += 1;
            if m.change_identity_at == Some(m.identities) {
                return Ok(1 << 27);
            }
            return Ok(m.sys);
        }
        let value = match r {
            0x34 => m.bank,
            0x30 => {
                if m.pending {
                    m.polls += 1;
                    let at = m.ready_at.unwrap_or(1 + (m.selected + m.case) % 3);
                    if m.polls >= at {
                        m.control =
                            (m.control & !255) | u32::from(m.physical[m.selected]) | (1 << 31);
                        if let Some((address, value)) = m.corrupt_completion
                            && address == m.selected
                        {
                            m.control = value;
                        }
                        m.pending = false;
                    }
                }
                m.control
            }
            _ => panic!("unexpected efuse register"),
        };
        m.event(0, r, 4, value)?;
        Ok(value)
    }
    fn write8(&mut self, r: u32, v: u8) -> Result<(), io::Error> {
        assert_eq!(r, 0x29);
        let mut m = self.0.lock().unwrap();
        m.event(1, r, 1, v.into())?;
        m.ldo = v;
        Ok(())
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), io::Error> {
        panic!("no OTP16 stores");
    }
    fn write32(&mut self, r: u32, v: u32) -> Result<(), io::Error> {
        let mut m = self.0.lock().unwrap();
        m.event(1, r, 4, v)?;
        match r {
            0x34 => m.bank = v,
            0x30 => {
                assert_eq!(v & (1 << 31), 0);
                m.control = v;
                m.selected = ((v >> 8) & 1023) as usize;
                assert!(m.selected < PHYSICAL);
                m.pending = true;
                m.polls = 0;
            }
            _ => panic!("no OTP programming"),
        };
        Ok(())
    }
    fn delay_us(&mut self, us: u64) {
        assert_eq!(us, 1);
        let mut m = self.0.lock().unwrap();
        m.delays += 1;
        if m.record {
            m.events.push([2, 0, 0, 1]);
        }
    }
    fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
        panic!("no efuse beacon");
    }
    unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
        panic!("no efuse completion");
    }
    fn quarantine(&mut self) {
        self.0.lock().unwrap().quarantined = true;
    }
}
#[test]
fn real_read_trigger_polling_preserves_raw_otp_ldo_bank_and_exact_identity() {
    for case in 0..4 {
        let model = Arc::new(Mutex::new(Model::new(case)));
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let physical = unsafe { read_model(model.clone()) }.unwrap();
        let m = model.lock().unwrap();
        assert_eq!(physical.bytes(), &m.physical);
        assert_eq!(physical.profile(), profile());
        assert_eq!(m.bank, (u32::MAX - case as u32 * 0x10304) & !0x300);
        assert_eq!(m.ldo, (255 - case as u8) & !1);
        assert_eq!(m.identities, 513);
        assert!(!m.quarantined);
        assert_eq!(m.selected, 511);
    }
}
#[test]
fn completed_address_echo_rejects_wrong_or_all_ones_control_with_valid_identity() {
    for address in [0, 1, 255, 511] {
        for value in [u32::MAX, (1 << 31) | (((address ^ 1) as u32) << 8) | 0xff] {
            let model = Arc::new(Mutex::new(Model::new(0)));
            {
                let mut m = model.lock().unwrap();
                m.corrupt_completion = Some((address, value));
            }
            assert!(matches!(
                // SAFETY: the model device, its pages and its domain belong to this test alone;
                // no other driver, worker or DMA touches them.
                unsafe { read_model(model.clone()) },
                Err(Error::CompletionAddress { requested, observed })
                    if requested == address as u16 && observed == ((value >> 8) & 1023) as u16
            ));
            let m = model.lock().unwrap();
            assert_eq!(m.sys, profile().observed().sys_cfg1);
            assert_eq!(m.selected, address);
            assert!(m.quarantined);
        }
    }
    let model = Arc::new(Mutex::new(Model::new(0)));
    model.lock().unwrap().physical = [0xff; PHYSICAL];
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let physical = unsafe { read_model(model.clone()) }.unwrap();
    assert_eq!(physical.bytes(), &[0xff; PHYSICAL]);
    let m = model.lock().unwrap();
    assert!(!m.quarantined);
    assert_eq!(m.selected, 511);
    assert_eq!((m.control >> 8) & 1023, 511);
    assert_eq!(m.control as u8, 0xff);
}
#[test]
fn uncertain_reads_are_quarantined() {
    let normal = Arc::new(Mutex::new(Model::new(0)));
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    unsafe { read_model(normal.clone()) }.unwrap();
    let calls = normal.lock().unwrap().calls;
    for call in 1..=calls {
        let model = Arc::new(Mutex::new(Model::new(0)));
        {
            let mut m = model.lock().unwrap();
            m.fail = Some(call);
            m.record = false;
        }
        assert!(
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            unsafe { read_model(model.clone()) }.is_err(),
            "operation {call}"
        );
        assert!(model.lock().unwrap().quarantined);
    }
    for identity in [1, 2, 19, 513] {
        let model = Arc::new(Mutex::new(Model::new(0)));
        model.lock().unwrap().change_identity_at = Some(identity);
        assert!(matches!(
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            unsafe { read_model(model.clone()) },
            Err(Error::IdentityChanged)
        ));
        assert!(model.lock().unwrap().quarantined);
    }
    for ready in [0, 65535] {
        let model = Arc::new(Mutex::new(Model::new(0)));
        model.lock().unwrap().ready = ready;
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        assert!(unsafe { read_model(model.clone()) }.is_err());
        assert!(model.lock().unwrap().quarantined);
        assert!(model.lock().unwrap().events.is_empty());
    }
    for ready_at in [POLLS, POLLS + 1] {
        let model = Arc::new(Mutex::new(Model::new(0)));
        {
            let mut m = model.lock().unwrap();
            m.ready_at = Some(ready_at);
            m.record = false;
        }
        assert!(matches!(
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            unsafe { read_model(model.clone()) },
            Err(Error::Timeout { address: 0 })
        ));
        assert_eq!(model.lock().unwrap().delays, POLLS);
        assert!(model.lock().unwrap().quarantined);
    }
    let model = Arc::new(Mutex::new(Model::new(0)));
    model.lock().unwrap().sys = u32::MAX;
    assert!(matches!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { read_model(model.clone()) },
        Err(Error::Removed)
    ));
    assert!(model.lock().unwrap().quarantined);
}
#[test]
fn logical_words_extended_blocks_overrides_and_protected_boundaries_are_explicit() {
    let mut p = [255; PHYSICAL];
    p[..9].copy_from_slice(&[0x0e, 1, 2, 0x0e, 3, 4, 0x2f, 0x1e, 5]);
    p[9] = 6;
    let log = logical_map(&p).unwrap();
    assert_eq!(&log[..2], &[3, 4]);
    assert_eq!(&log[9 * 8..9 * 8 + 2], &[5, 6]);
    let mut p = [0x1f; PHYSICAL];
    p[USABLE - 1] = 0x0f;
    assert_eq!(logical_map(&p), Err(Error::Header { offset: USABLE - 1 }));
    let mut p = [0x1f; PHYSICAL];
    p[USABLE - 2] = 0x0e;
    assert_eq!(logical_map(&p), Err(Error::Payload { offset: USABLE - 1 }));
    let mut p = [255; PHYSICAL];
    p[..4].copy_from_slice(&[0x0f, 0xce, 1, 2]);
    assert_eq!(logical_map(&p), Err(Error::Logical { offset: 96 * 8 }));
    let p = [255; PHYSICAL];
    assert_eq!(logical_map(&p).unwrap(), [255; LOGICAL]);
}
#[test]
fn immutable_board_provenance_keeps_raw_values_without_fallback_or_policy() {
    let mut log = Logical {
        profile: profile(),
        bytes: core::array::from_fn(|i| i as u8),
    };
    log.bytes[0x120..0x126].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    let b = log.board();
    assert_eq!(b.valid_mac().unwrap(), [2, 3, 4, 5, 6, 7]);
    assert_eq!(b.profile(), profile());
    assert_eq!(b.raw().power_tables, log.bytes[0x10..0xb8]);
    assert_eq!(b.raw().rfe_raw, 202);
    assert_eq!(b.source_rfe(), Err(Error::UnsupportedRfe(202)));
    let mut diagnostic = b.raw().clone();
    diagnostic.rfe_raw = 0;
    assert_eq!(diagnostic.rfe_raw, 0);
    assert_eq!(b.raw().rfe_raw, 202);
    for rfe in 0..=255 {
        log.bytes[0xca] = rfe;
        assert_eq!(log.board().source_rfe().is_ok(), rfe <= 6);
    }
    for mac in [[0; 6], [255; 6], [1, 0, 0, 0, 0, 0]] {
        log.bytes[0x120..0x126].copy_from_slice(&mac);
        assert_eq!(log.board().valid_mac(), Err(Error::InvalidMac));
    }
}
#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_EFUSE_ORACLE"]
fn physical_transport_logical_maps_and_all_board_fields_match_unchanged_c() {
    let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_EFUSE_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    for case in 0..6400 {
        let input: &[u8; PHYSICAL] = trace[offset..offset + 512].try_into().unwrap();
        let ret = u32::from_le_bytes(trace[offset + 512..offset + 516].try_into().unwrap());
        let native = logical_map(input);
        assert_eq!(native.is_ok(), ret == 0, "case {case}");
        if let Ok(log) = native {
            assert_eq!(
                log,
                trace[offset + 516..offset + 1284],
                "case {case}: logical"
            );
            let board = Logical {
                profile: profile(),
                bytes: log,
            }
            .board();
            let b = board.raw();
            let facts = [
                u32::from(b.usb_mode_switch_raw),
                b.rfe_raw.into(),
                b.rf_board_raw.into(),
                b.crystal_cap_raw.into(),
                b.channel_plan_raw.into(),
                b.country_raw[0].into(),
                b.country_raw[1].into(),
                b.bt_raw.into(),
                b.regulatory_raw.into(),
                b.thermal_raw[0].into(),
                b.thermal_raw[1].into(),
                b.thermal_average.into(),
                b.power_track_raw.into(),
            ];
            let mut actual = Vec::new();
            for word in facts {
                actual.extend_from_slice(&word.to_le_bytes());
            }
            actual.extend_from_slice(&b.mac);
            actual.extend_from_slice(&b.power_tables);
            actual.extend_from_slice(&b.rtl_id.to_le_bytes());
            assert_eq!(
                actual,
                trace[offset + 1284..offset + 1512],
                "case {case}: board"
            );
        }
        offset += 1512;
    }
    for case in 0..4 {
        let model = Arc::new(Mutex::new(Model::new(case)));
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let native = unsafe { read_model(model.clone()) }.unwrap();
        assert_eq!(native.bytes(), &trace[offset..offset + 512]);
        offset += 512;
        let size = u32::from_le_bytes(trace[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let mut actual = Vec::new();
        for event in &model.lock().unwrap().events {
            for word in event {
                actual.extend_from_slice(&word.to_le_bytes());
            }
        }
        assert_eq!(actual.len(), size);
        assert_eq!(actual, trace[offset..offset + size], "physicalcase {case}");
        offset += size;
    }
    for late in 0..2 {
        let model = Arc::new(Mutex::new(Model::new(0)));
        {
            let mut m = model.lock().unwrap();
            m.ready_at = Some(POLLS + late);
            m.record = false;
        }
        assert!(matches!(
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            unsafe { read_model(model.clone()) },
            Err(Error::Timeout { address: 0 })
        ));
        let mut words = [0; 5];
        for (i, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
        }
        let m = model.lock().unwrap();
        assert_ne!(words[0], 0);
        assert_eq!(
            &words[1..],
            &[
                m.polls as u32,
                m.delays as u32,
                m.selected as u32,
                m.control >> 31
            ]
        );
        assert!(m.quarantined);
        offset += 20;
    }
    assert_eq!(offset, trace.len());
}
