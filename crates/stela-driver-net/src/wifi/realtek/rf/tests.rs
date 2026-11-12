extern crate std;
use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use std::sync::Mutex;
use stela_driver_base::stepped::block_on;

struct Model {
    profile: Profile,
    bytes: Vec<u8>,
    events: Vec<u8>,
    calls: usize,
    fail: Option<usize>,
    mutate_at: Option<(usize, u32, usize, u32)>,
    quarantined: usize,
}
impl Model {
    fn new() -> Self {
        let profile = Profile::select(super::super::identity::Observed {
            vendor: 0x10ec,
            device: 0xc822,
            subsystem_vendor: 0x17aa,
            subsystem_device: 0x1234,
            pci_revision: 1,
            sys_cfg1: 1 << 27,
        })
        .unwrap();
        let mut m = Self {
            profile,
            bytes: vec![0; 0x5000],
            events: Vec::new(),
            calls: 0,
            fail: None,
            mutate_at: None,
            quarantined: 0,
        };
        m.set(REG_SYS_CFG1, 4, profile.observed().sys_cfg1);
        m.set(REG_MCUFW_CTRL, 2, 0xc078);
        m.set(REG_SYS_FUNC_EN, 1, 3);
        m.set(REG_RF_CTRL, 1, 7);
        m.set(REG_WLRF1, 4, 0x07000000);
        m.set(REG_C2HEVT, 1, 0x19);
        m
    }
    fn get(&self, r: u32, width: usize) -> u32 {
        let mut bytes = [0; 4];
        bytes[..width].copy_from_slice(&self.bytes[r as usize..r as usize + width]);
        u32::from_le_bytes(bytes)
    }
    fn set(&mut self, r: u32, width: usize, value: u32) {
        self.bytes[r as usize..r as usize + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }
    fn operation(&mut self) -> Result<(), io::Error> {
        self.calls += 1;
        if self.fail == Some(self.calls) {
            return Err(io::Error::Register);
        }
        if let Some((at, r, w, v)) = self.mutate_at
            && at == self.calls
        {
            self.set(r, w, v)
        }
        Ok(())
    }
    fn event(&mut self, k: u32, r: u32, w: u32, v: u32) {
        for word in [k, r, w, v] {
            self.events.extend_from_slice(&word.to_le_bytes());
        }
    }
}
struct ModelIo(Arc<Mutex<Model>>);
// SAFETY: exclusive serialized deterministic MMIO/RF/firmware model;
// no requester, calibration, DMA or physical firmware claim.
unsafe impl Io for ModelIo {
    fn profile(&self) -> Profile {
        self.0.lock().unwrap().profile
    }
    fn read8(&mut self, r: u32) -> Result<u8, io::Error> {
        let mut m = self.0.lock().unwrap();
        m.operation()?;
        Ok(m.get(r, 1) as u8)
    }
    fn read16(&mut self, r: u32) -> Result<u16, io::Error> {
        let mut m = self.0.lock().unwrap();
        m.operation()?;
        Ok(m.get(r, 2) as u16)
    }
    fn read32(&mut self, r: u32) -> Result<u32, io::Error> {
        let mut m = self.0.lock().unwrap();
        m.operation()?;
        let v = m.get(r, 4);
        if (0x3c00..0x5000).contains(&r) {
            m.event(0, r, 4, v)
        }
        Ok(v)
    }
    fn write8(&mut self, r: u32, v: u8) -> Result<(), io::Error> {
        let mut m = self.0.lock().unwrap();
        m.operation()?;
        m.set(r, 1, v.into());
        Ok(())
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), io::Error> {
        panic!("no RF 16-bit store")
    }
    fn write32(&mut self, r: u32, v: u32) -> Result<(), io::Error> {
        let mut m = self.0.lock().unwrap();
        m.operation()?;
        m.event(1, r, 4, v);
        m.set(r, 4, v);
        for p in 0..2 {
            if r == SIPI[p] {
                let target = BASE[p] + (((v >> 20) & 255) * 4);
                let old = m.get(target, 4);
                m.set(target, 4, (old & !RF_MASK) | (v & RF_MASK));
            }
        }
        Ok(())
    }
    fn delay_us(&mut self, us: u64) {
        self.0.lock().unwrap().event(2, 0, 0, us as u32)
    }
    fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
        panic!("no RF beacon")
    }
    unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
        panic!("no RF beacon completion")
    }
    fn quarantine(&mut self) {
        self.0.lock().unwrap().quarantined += 1;
    }
}
fn setup(one_path: bool) -> (Arc<Mutex<Model>>, ModelIo, Report) {
    let model = Arc::new(Mutex::new(Model::new()));
    let mut io = ModelIo(model.clone());
    if one_path {
        model.lock().unwrap().set(0x1a8, 1, 0x20);
    }
    // Internal modeled source report read constructs immutable capability
    // data; Download's separately tested fresh request/boot fence is not
    // bypassable through any public Report constructor.
    let report = block_on(super::super::features::read(&mut io)).unwrap();
    model.lock().unwrap().calls = 0;
    (model, io, report)
}
#[test]
fn masks_paths_and_values_reject_before_io_without_poisoning_valid_state() {
    let (m, mut io, report) = setup(true);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut rf = unsafe { Registers::new(&mut io, &report) }.unwrap();
    let before = m.lock().unwrap().calls;
    assert_eq!(rf.read(Path::B, 0, RF_MASK), Err(Error::UnsupportedPath));
    for mask in [0, 1 << 20, u32::MAX] {
        assert_eq!(rf.read(Path::A, 0, mask), Err(Error::InvalidMask));
        assert_eq!(rf.write(Path::A, 0, mask, 0), Err(Error::InvalidMask));
    }
    for (mask, value) in [(1, 2), (0x55555, 2), (0xfffff, 0x100000), (0x80000, 2)] {
        assert_eq!(rf.write(Path::A, 0, mask, value), Err(Error::InvalidValue));
    }
    assert_eq!(m.lock().unwrap().calls, before);
    rf.write(Path::A, 0, RF_MASK, 0xfffff).unwrap();
    assert_eq!(rf.read(Path::A, 0, RF_MASK).unwrap(), 0xfffff);
    drop(rf);
    assert_eq!(m.lock().unwrap().quarantined, 0);
}
#[test]
fn domain_identity_ready_and_ambiguous_rf_observations_are_terminal() {
    for (register, width, value) in [
        (0xf0, 4, u32::MAX),
        (0xf0, 4, 0),
        (0x80, 2, 0xffff),
        (2, 1, 0),
        (0x1f, 1, 0),
        (0xec, 4, 0),
    ] {
        let (m, mut io, report) = setup(false);
        m.lock().unwrap().set(register, width, value);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        assert!(unsafe { Registers::new(&mut io, &report) }.is_err());
        assert_eq!(m.lock().unwrap().quarantined, 1);
    }
    for op in 0..3 {
        let (m, mut io, report) = setup(false);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let mut rf = unsafe { Registers::new(&mut io, &report) }.unwrap();
        m.lock().unwrap().set(BASE[1], 4, u32::MAX);
        let failed = match op {
            0 => rf.read(Path::B, 0, RF_MASK).map(|_| ()),
            1 => rf.write(Path::B, 0, 1, 1),
            _ => rf.write(Path::B, 1, RF_MASK, 0),
        };
        if op == 2 {
            assert!(failed.is_ok());
            continue;
        } // Different direct target; whole-word guard is per observation.
        assert_eq!(
            failed,
            Err(Error::AmbiguousObservation {
                register: BASE[1],
                raw: u32::MAX
            })
        );
        let before = m.lock().unwrap().calls;
        assert_eq!(rf.read(Path::A, 0, 1), Err(Error::InvalidState));
        assert_eq!(m.lock().unwrap().calls, before);
        drop(rf);
        assert_eq!(m.lock().unwrap().quarantined, 2);
    }
    // Domain-register all-ones alone is not removal; only their required
    // source bits and independent exact identity/MCU observations matter.
    let (m, mut io, report) = setup(false);
    {
        let mut m = m.lock().unwrap();
        m.set(REG_SYS_FUNC_EN, 1, 255);
        m.set(REG_RF_CTRL, 1, 255);
        m.set(REG_WLRF1, 4, u32::MAX);
    }
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    drop(unsafe { Registers::new(&mut io, &report) }.unwrap());
    assert_eq!(m.lock().unwrap().quarantined, 0);
}
#[test]
fn every_io_failure_and_late_identity_loss_quarantines_real_control_borrow() {
    let (m, mut io, report) = setup(false);
    {
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let mut rf = unsafe { Registers::new(&mut io, &report) }.unwrap();
        rf.read(Path::A, 0x18, RF_MASK).unwrap();
        rf.write(Path::A, 0, RF_MASK, 0x12345).unwrap();
        rf.write(Path::B, 0, 0x300, 3).unwrap();
        rf.write(Path::B, 0x18, 0xff, 0x22).unwrap();
    }
    let operations = m.lock().unwrap().calls;
    for at in 1..=operations {
        let (m, mut io, report) = setup(false);
        m.lock().unwrap().fail = Some(at);
        let result = (|| {
            // SAFETY: the model device, its pages and its domain belong to this test alone; no
            // other driver, worker or DMA touches them.
            let mut rf = unsafe { Registers::new(&mut io, &report) }?;
            rf.read(Path::A, 0x18, RF_MASK)?;
            rf.write(Path::A, 0, RF_MASK, 0x12345)?;
            rf.write(Path::B, 0, 0x300, 3)?;
            rf.write(Path::B, 0x18, 0xff, 0x22)
        })();
        assert!(result.is_err(), "operation {at}");
        assert!(m.lock().unwrap().quarantined >= 1, "operation {at}");
    }
    let (m, mut io, report) = setup(false);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let mut rf = unsafe { Registers::new(&mut io, &report) }.unwrap();
    let calls = m.lock().unwrap().calls;
    // Five pre-read guard observations + RF read, then the final
    // identity guard must reject a reset/replacement before returning data.
    m.lock().unwrap().mutate_at = Some((calls + 7, 0xf0, 4, 0));
    assert_eq!(rf.read(Path::A, 0x18, RF_MASK), Err(Error::IdentityChanged));
    drop(rf);
    assert_eq!(m.lock().unwrap().quarantined, 2);
}
#[test]
#[expect(
    clippy::arc_with_non_send_sync,
    reason = "NativeIo holds Arc<dyn Any> without Send; this CPU-affine fixture keeps its registers !Sync"
)]
fn native_mmio_uses_real_rf_offsets_widths_and_keeps_uncertain_owner() {
    use core::{
        cell::UnsafeCell,
        ptr::NonNull,
        sync::atomic::{AtomicBool, Ordering},
    };
    struct Bar(UnsafeCell<alloc::boxed::Box<[u32]>>);
    impl Bar {
        fn pointer(&self) -> NonNull<u8> {
            // SAFETY: fixture owns stable aligned backing storage; every
            // access is a modeled device/CPU volatile access below.
            unsafe { NonNull::new_unchecked((*self.0.get()).as_mut_ptr().cast()) }
        }
        fn set(&self, r: u32, value: u32) {
            // SAFETY: exclusively serialized fixture device update.
            unsafe {
                self.pointer()
                    .as_ptr()
                    .add(r as usize)
                    .cast::<u32>()
                    .write_volatile(value)
            }
        }
        fn get(&self, r: usize) -> u32 {
            // SAFETY: exclusively serialized aligned fixture observation.
            unsafe { self.pointer().as_ptr().add(r).cast::<u32>().read_volatile() }
        }
    }
    struct NoSubmission(Arc<AtomicBool>);
    // SAFETY: register-only test fixture never submits DMA; all beacon
    // calls fail/panic, and quarantine observably keeps owner.
    unsafe impl io::BeaconQueue for NoSubmission {
        fn submit(&mut self, _: &[u8]) -> Result<(), io::Error> {
            panic!("RF cannot submit DMA")
        }
        unsafe fn consumed(&mut self) -> Result<(), io::Error> {
            panic!("RF cannot complete DMA")
        }
        fn quarantine(&mut self) {
            self.0.store(true, Ordering::SeqCst)
        }
    }
    let bar = Arc::new(Bar(UnsafeCell::new(
        vec![0u32; 0x5000 / 4].into_boxed_slice(),
    )));
    let weak = Arc::downgrade(&bar);
    let quarantined = Arc::new(AtomicBool::new(false));
    let profile = Model::new().profile;
    bar.set(REG_SYS_CFG1, profile.observed().sys_cfg1);
    bar.set(REG_MCUFW_CTRL, 0xc078);
    bar.set(0, 3 << 16);
    bar.set(REG_RSV_CTRL, 7 << 24);
    bar.set(REG_WLRF1, 0x07000000);
    bar.set(REG_C2HEVT, 0x19);
    // SAFETY: aligned kept register fixture, no physical requester or
    // operational DMA claim. NativeIo executes volatile operations.
    let mut io = unsafe {
        io::NativeIo::new(
            bar.pointer(),
            0x5000,
            NoSubmission(quarantined.clone()),
            bar.clone(),
            crate::Clock {
                ticks_per_microsecond: 1,
            },
            profile,
        )
    }
    .unwrap();
    let report = block_on(super::super::features::read(&mut io)).unwrap();
    bar.set(BASE[1] + 0x18 * 4, 0xf1234567);
    {
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let mut rf = unsafe { Registers::new(&mut io, &report) }.unwrap();
        rf.write(Path::B, 0x18, 0x3f0, 0x2a).unwrap();
        assert_eq!(
            rf.read(Path::B, 0x18, RF_MASK).unwrap(),
            ((0xf1234567 & !0x3f0) | (0x2a << 4)) & RF_MASK
        );
        rf.write(Path::B, 0, RF_MASK, 0xabcde).unwrap();
    }
    assert_eq!(
        bar.get(BASE[1] as usize + 0x18 * 4),
        (0xf1234567 & !0x3f0) | (0x2a << 4)
    );
    assert_eq!(bar.get(SIPI[1] as usize), 0xabcde);
    assert!(!quarantined.load(Ordering::SeqCst));
    bar.set(BASE[1], u32::MAX);
    {
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let mut rf = unsafe { Registers::new(&mut io, &report) }.unwrap();
        assert!(matches!(
            rf.read(Path::B, 0, RF_MASK),
            Err(Error::AmbiguousObservation { .. })
        ));
    }
    assert!(quarantined.load(Ordering::SeqCst));
    drop(io);
    drop(bar);
    assert!(weak.upgrade().is_some()); // BAR owner quarantined.
}
#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_RF_ORACLE"]
fn all_registers_masks_paths_and_full_io_traces_match_unchanged_c() {
    let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_RF_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    for case in 0..65536 {
        let mut header = [0; 6];
        for (i, word) in header.iter_mut().enumerate() {
            *word = u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
        }
        offset += 24;
        let [p, a, mask, old, full, data] = header;
        let path = if p == 0 { Path::A } else { Path::B };
        let (model, mut io, report) = setup(false);
        {
            let mut m = model.lock().unwrap();
            m.set(BASE[p as usize] + a * 4, 4, old);
            m.events.clear();
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let mut rf = unsafe { Registers::new(&mut io, &report) }.unwrap();
        let before = rf.read(path, a as u8, mask).unwrap();
        rf.write(path, a as u8, RF_MASK, full).unwrap();
        rf.write(path, a as u8, mask, data).unwrap();
        let after = rf.read(path, a as u8, RF_MASK).unwrap();
        drop(rf);
        let m = model.lock().unwrap();
        assert_eq!(
            &m.events,
            &trace[offset..offset + m.events.len()],
            "case {case}"
        );
        offset += m.events.len();
        let expected = [before, after, m.get(BASE[p as usize] + a * 4, 4)];
        for value in expected {
            assert_eq!(
                value,
                u32::from_le_bytes(trace[offset..offset + 4].try_into().unwrap()),
                "case {case}"
            );
            offset += 4;
        }
        assert_eq!(m.quarantined, 0);
    }
    assert_eq!(offset, trace.len());
}
