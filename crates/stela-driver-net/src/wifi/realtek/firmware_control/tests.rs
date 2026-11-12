extern crate std;
use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
pub(in crate::wifi::realtek) struct Owner(pub Arc<AtomicUsize>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
pub(in crate::wifi::realtek) struct Model {
    pub profile: Profile,
    bytes: Vec<u8>,
    pub events: Vec<[u32; 4]>,
    pub calls: usize,
    pub fail: Option<usize>,
    pub panic_at: Option<usize>,
    pub mutate_at: Option<(usize, u32, usize, u32)>,
    pub quarantine: usize,
    pub now: u64,
    pub frozen: bool,
    pub regress: bool,
    pub clock_available: bool,
    pub busy_reads: usize,
    pub busy_target: u8,
    pub busy_other: u8,
    pub busy_seen: usize,
    pub bt_idle_after: usize,
    pub bt_reads: usize,
    pub rfk_after: Option<usize>,
    pub rfk_reads: usize,
    pub rfk_pending: bool,
    pub iqk_after: Option<usize>,
    pub iqk_reads: usize,
    pub trigger: Arc<AtomicBool>,
    pub dropped: usize,
}
pub(in crate::wifi::realtek) struct Bus {
    pub model: Arc<Mutex<Model>>,
    owner: Option<Arc<Owner>>,
}
impl Model {
    pub fn set(&mut self, r: u32, width: usize, value: u32) {
        self.bytes[r as usize..r as usize + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }
    pub fn get(&self, r: u32, width: usize) -> u32 {
        let mut v = [0; 4];
        v[..width].copy_from_slice(&self.bytes[r as usize..r as usize + width]);
        u32::from_le_bytes(v)
    }
    fn operation(&mut self) -> Result<(), io::Error> {
        self.calls += 1;
        if let Some((at, register, width, value)) = self.mutate_at
            && self.calls == at
        {
            self.set(register, width, value);
        }
        if self.panic_at == Some(self.calls) {
            panic!("modeled control unwind");
        }
        if self.fail == Some(self.calls) {
            return Err(io::Error::Register);
        }
        Ok(())
    }
    pub fn clear_log(&mut self) {
        self.calls = 0;
        self.events.clear();
    }
}
pub(in crate::wifi::realtek) fn bus(
    profile: Profile,
) -> (Bus, Arc<Mutex<Model>>, Arc<Owner>, Arc<AtomicUsize>) {
    let dropped = Arc::new(AtomicUsize::new(0));
    let owner = Arc::new(Owner(dropped.clone()));
    let mut m = Model {
        profile,
        bytes: vec![0; 0x5000],
        events: Vec::new(),
        calls: 0,
        fail: None,
        panic_at: None,
        mutate_at: None,
        quarantine: 0,
        now: 0,
        frozen: false,
        regress: false,
        clock_available: true,
        busy_reads: 0,
        busy_target: 0,
        busy_other: 0,
        busy_seen: 0,
        bt_idle_after: 0,
        bt_reads: 0,
        rfk_after: Some(0),
        rfk_reads: 0,
        rfk_pending: false,
        iqk_after: Some(0),
        iqk_reads: 0,
        trigger: Arc::new(AtomicBool::new(false)),
        dropped: 0,
    };
    m.set(REG_SYS_CFG1, 4, profile.observed().sys_cfg1);
    m.set(REG_MCUFW_CTRL, 2, 0xc078);
    let state = Arc::new(Mutex::new(m));
    (
        Bus {
            model: state.clone(),
            owner: Some(owner.clone()),
        },
        state,
        owner,
        dropped,
    )
}
// SAFETY: exclusively serialized byte-register and clock/firmware-response
// model with kept model owner, not physical readiness evidence.
unsafe impl Io for Bus {
    fn profile(&self) -> Profile {
        self.model.lock().unwrap_or_else(|e| e.into_inner()).profile
    }
    fn read8(&mut self, r: u32) -> Result<u8, io::Error> {
        let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
        m.operation()?;
        let v = match r {
            0x1cc => {
                let v = m.busy_other
                    | if m.busy_seen < m.busy_reads {
                        1 << m.busy_target
                    } else {
                        0
                    };
                m.busy_seen += 1;
                v
            }
            0x49c => {
                if m.rfk_pending {
                    if m.rfk_after.is_some_and(|at| m.rfk_reads >= at) {
                        let old = m.get(r, 1) | 1;
                        m.set(r, 1, old);
                    }
                    m.rfk_reads += 1;
                }
                m.get(r, 1) as u8
            }
            0x2d9c => {
                if m.trigger.load(Ordering::SeqCst) {
                    if m.iqk_after.is_some_and(|at| m.iqk_reads >= at) {
                        m.set(r, 1, 0xaa);
                    }
                    m.iqk_reads += 1;
                }
                m.get(r, 1) as u8
            }
            _ => m.get(r, 1) as u8,
        };
        m.events.push([0, r, 1, u32::from(v)]);
        Ok(v)
    }
    fn read16(&mut self, r: u32) -> Result<u16, io::Error> {
        let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
        m.operation()?;
        let v = m.get(r, 2);
        m.events.push([0, r, 2, v]);
        Ok(v as u16)
    }
    fn read32(&mut self, r: u32) -> Result<u32, io::Error> {
        let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
        m.operation()?;
        let v = if r == 0xa8 {
            let v = if m.bt_reads < m.bt_idle_after {
                1 << 21
            } else {
                0
            };
            m.bt_reads += 1;
            v
        } else {
            m.get(r, 4)
        };
        m.events.push([0, r, 4, v]);
        Ok(v)
    }
    fn write8(&mut self, r: u32, v: u8) -> Result<(), io::Error> {
        let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
        m.operation()?;
        m.set(r, 1, u32::from(v));
        m.events.push([1, r, 1, u32::from(v)]);
        Ok(())
    }
    fn write16(&mut self, r: u32, v: u16) -> Result<(), io::Error> {
        let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
        m.operation()?;
        m.set(r, 2, u32::from(v));
        m.events.push([1, r, 2, u32::from(v)]);
        Ok(())
    }
    fn write32(&mut self, r: u32, v: u32) -> Result<(), io::Error> {
        let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
        m.operation()?;
        m.set(r, 4, v);
        m.events.push([1, r, 4, v]);
        if (0x1d0..0x1e0).contains(&r) {
            m.rfk_pending = true;
            m.rfk_reads = 0;
        }
        Ok(())
    }
    fn delay_us(&mut self, us: u64) {
        let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
        if !m.frozen {
            m.now = m.now.checked_add(us).unwrap();
        }
        m.events.push([2, 0, 0, us as u32]);
    }
    fn now_us(&mut self) -> Result<u64, io::Error> {
        let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
        m.operation()?;
        if !m.clock_available {
            return Err(io::Error::InvalidClock);
        }
        Ok(if m.regress {
            m.now.saturating_sub(1)
        } else {
            m.now
        })
    }
    fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
        panic!("not a download")
    }
    unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
        panic!("not a DMA completion")
    }
    fn quarantine(&mut self) {
        self.model
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .quarantine += 1;
        if let Some(owner) = self.owner.take() {
            core::mem::forget(owner);
        }
    }
}
impl Drop for Bus {
    fn drop(&mut self) {
        self.model.lock().unwrap_or_else(|e| e.into_inner()).dropped += 1;
    }
}
fn fixture() -> (
    Control<Bus>,
    Arc<Mutex<Model>>,
    Arc<Owner>,
    Arc<AtomicUsize>,
) {
    let (_, report) = super::super::phy::control_fixture();
    let (io, m, o, d) = bus(report.profile());
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let c = unsafe { Control::new(io, &report) }.unwrap();
    m.lock().unwrap().clear_log();
    (c, m, o, d)
}
fn source_events(events: &[[u32; 4]]) -> Vec<[u32; 4]> {
    events
        .iter()
        .copied()
        .filter(|e| !(e[0] == 0 && (e[1] == 0xf0 || e[1] == 0x80)))
        .collect()
}
#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_FIRMWARE_CONTROL_ORACLE"]
fn every_mailbox_busy_boundary_and_complete_source_rfk_traces_match() {
    let dir = std::path::PathBuf::from(
        std::env::var("STELA_REALTEK_WIFI_FIRMWARE_CONTROL_ORACLE").unwrap(),
    );
    let bytes = std::fs::read(dir.join("mailbox.bin")).unwrap();
    let mut offset = 0;
    let mut cases = 0;
    while offset < bytes.len() {
        let h: [u32; 7] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                bytes[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        offset += 28;
        let (mut c, m, _, _) = fixture();
        c.next_box = h[0] as u8;
        {
            let mut s = m.lock().unwrap();
            s.busy_reads = h[2] as usize;
            s.busy_seen = 0;
            s.busy_target = h[0] as u8;
            s.busy_other = h[3] as u8;
        }
        assert_eq!(
            c.publish_rfk(h[1] != 0).is_ok(),
            h[6] != 0,
            "mailbox {cases}"
        );
        assert_eq!(u32::from(c.next_mailbox()), h[4]);
        let source = &bytes[offset..offset + h[5] as usize * 16];
        offset += source.len();
        let actual = source_events(&m.lock().unwrap().events);
        let actual: Vec<u8> = actual
            .into_iter()
            .flat_map(|r| r.into_iter().flat_map(u32::to_le_bytes))
            .collect();
        assert_eq!(actual, source, "mailbox {cases}");
        cases += 1;
    }
    assert_eq!(cases, 264);
    let bytes = std::fs::read(dir.join("rfk.bin")).unwrap();
    let mut offset = 0;
    let mut cases = 0;
    while offset < bytes.len() {
        let h: [u32; 5] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                bytes[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        offset += 20;
        let (mut c, m, _, _) = fixture();
        {
            let mut s = m.lock().unwrap();
            s.bt_idle_after = h[0] as usize;
            s.rfk_after = Some(h[1] as usize);
        }
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { c.begin_rfk() }.unwrap();
        assert_eq!(u32::from(c.next_mailbox()), h[3]);
        assert_eq!(h[4], 0);
        let mut actual = source_events(&m.lock().unwrap().events);
        assert_eq!(actual.remove(0), [0, 0x49c, 1, 0], "added freshness fence");
        let actual: Vec<u8> = actual
            .into_iter()
            .flat_map(|r| r.into_iter().flat_map(u32::to_le_bytes))
            .collect();
        let source = &bytes[offset..offset + h[2] as usize * 16];
        offset += source.len();
        assert_eq!(actual, source, "RFK start {cases}");
        let h: [u32; 2] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                bytes[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        offset += 8;
        m.lock().unwrap().clear_log();
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        let observed = unsafe { c.finish_rfk() }.unwrap();
        assert_eq!(observed.raw_status() & 1, 1);
        assert_eq!(u32::from(c.next_mailbox()), h[1]);
        let mut actual = source_events(&m.lock().unwrap().events);
        assert_eq!(
            actual.pop(),
            Some([0, 0x49c, 1, 1]),
            "extra labeled raw snapshot"
        );
        let actual: Vec<u8> = actual
            .into_iter()
            .flat_map(|r| r.into_iter().flat_map(u32::to_le_bytes))
            .collect();
        let source = &bytes[offset..offset + h[0] as usize * 16];
        offset += source.len();
        assert_eq!(actual, source, "RFK finish {cases}");
        cases += 1;
    }
    assert_eq!(cases, 32);
}
#[test]
fn mailbox_last_atomic_read_order_rotation_and_real_owner_lifetime() {
    for mailbox in 0..4 {
        let (mut c, m, owner, dropped) = fixture();
        c.next_box = mailbox;
        {
            let mut s = m.lock().unwrap();
            s.busy_target = mailbox;
            s.busy_reads = 30;
            s.busy_seen = 0;
        }
        let result = c.publish_rfk(true).unwrap();
        assert_eq!(result.mailbox(), mailbox);
        assert_eq!(c.next_mailbox(), (mailbox + 1) % 4);
        let s = m.lock().unwrap();
        let events = source_events(&s.events);
        assert_eq!(
            events.iter().filter(|e| e[0] == 0 && e[1] == 0x1cc).count(),
            31
        );
        assert_eq!(events.iter().filter(|e| e[0] == 2).count(), 30);
        assert_eq!(
            &events[events.len() - 2..],
            &[
                [1, 0x1f0 + u32::from(mailbox) * 4, 4, 0],
                [1, 0x1d0 + u32::from(mailbox) * 4, 4, 0x16d]
            ]
        );
        drop(s);
        drop(c);
        assert!(m.lock().unwrap().quarantine >= 1);
        assert_eq!(Arc::strong_count(&owner), 2);
        drop(owner);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
    }
    let (mut c, m, _, _) = fixture();
    {
        let mut s = m.lock().unwrap();
        s.busy_reads = 31;
        s.busy_seen = 0;
    }
    assert_eq!(
        c.publish_rfk(true).unwrap_err(),
        Error::MailboxTimeout { mailbox: 0 }
    );
    assert_eq!(c.next_mailbox(), 0);
    assert!(!m.lock().unwrap().events.iter().any(|e| e[0] == 1));
}
#[test]
fn a_command_a_busy_mailbox_refuses_is_dropped_and_the_next_one_goes_through() {
    let (mut c, m, _, _) = fixture();
    {
        let mut s = m.lock().unwrap();
        s.busy_reads = 31;
        s.busy_seen = 0;
    }
    // rtw_fw_send_h2c_command: "failed to send h2c command", and on.
    assert_eq!(
        c.command((0x1234, 0x5678)),
        Err(Error::MailboxTimeout { mailbox: 0 })
    );
    assert!(!c.quarantined());
    assert_eq!(c.next_mailbox(), 0);
    assert_eq!(m.lock().unwrap().quarantine, 0);
    assert!(!m.lock().unwrap().events.iter().any(|e| e[0] == 1));
    // The mailbox frees, and the next command takes it.
    c.command((0x4321, 0x8765)).unwrap();
    assert_eq!(c.next_mailbox(), 1);
    let s = m.lock().unwrap();
    let events = source_events(&s.events);
    assert_eq!(
        &events[events.len() - 2..],
        &[[1, 0x1f0, 4, 0x8765], [1, 0x1d0, 4, 0x4321]]
    );
}
#[test]
fn fresh_start_and_sticky_finish_are_distinct_from_completion() {
    let (mut c, m, _, _) = fixture();
    {
        let mut s = m.lock().unwrap();
        s.bt_idle_after = 3;
        s.rfk_after = Some(2);
    }
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let start = unsafe { c.begin_rfk() }.unwrap();
    assert_eq!(start.mailbox(), 0);
    assert_eq!(c.next_mailbox(), 1);
    // Real source finish reports bit1 even if the new finish request's
    // responder never runs. Preserve that fact without minting a new ACK.
    m.lock().unwrap().rfk_after = None;
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let finish = unsafe { c.finish_rfk() }.unwrap();
    assert_eq!(finish.raw_status() & 1, 1);
    assert_eq!(finish.publication().mailbox(), 1);
    assert_eq!(c.next_mailbox(), 2);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    assert_eq!(unsafe { c.begin_rfk() }.unwrap_err(), Error::StaleRfk);
    assert!(c.quarantined());
}
#[test]
fn missing_clock_stale_status_deadline_and_uncertain_reads_cannot_start_calibration() {
    let (_, report) = super::super::phy::control_fixture();
    let (io, m, _, _) = bus(report.profile());
    m.lock().unwrap().clock_available = false;
    assert!(matches!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { Control::new(io, &report) },
        Err(Error::Hardware(io::Error::InvalidClock))
    ));
    assert!(m.lock().unwrap().quarantine >= 1);
    let (mut c, m, _, _) = fixture();
    m.lock().unwrap().set(REG_ARFR4, 1, 1);
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    assert_eq!(unsafe { c.begin_rfk() }.unwrap_err(), Error::StaleRfk);
    assert!(!m.lock().unwrap().events.iter().any(|e| e[0] == 1));
    let (mut c, m, _, _) = fixture();
    {
        let mut s = m.lock().unwrap();
        s.bt_idle_after = usize::MAX;
        s.frozen = true;
    }
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    assert_eq!(unsafe { c.begin_rfk() }.unwrap_err(), Error::Clock);
    assert!(!m.lock().unwrap().events.iter().any(|e| e[0] == 1));
    let (mut c, m, _, _) = fixture();
    m.lock().unwrap().bt_idle_after = usize::MAX;
    assert_eq!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { c.begin_rfk() }.unwrap_err(),
        Error::Timeout { register: 0xa8 }
    );
    assert!(!m.lock().unwrap().events.iter().any(|e| e[0] == 1));
    let (mut c, m, _, _) = fixture();
    m.lock().unwrap().rfk_after = None;
    assert_eq!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { c.begin_rfk() }.unwrap_err(),
        Error::Timeout { register: 0x49c }
    );
    assert!(m.lock().unwrap().events.iter().any(|e| e[0] == 1));
    assert!(c.quarantined());
}
#[test]
fn every_start_finish_io_error_unwind_and_shutdown_keeps_control_owner() {
    let (mut c, m, _, _) = fixture();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    unsafe { c.begin_rfk() }.unwrap();
    let start_total = m.lock().unwrap().calls;
    for at in 1..=start_total {
        let (mut c, m, _, _) = fixture();
        m.lock().unwrap().fail = Some(at);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        assert!(unsafe { c.begin_rfk() }.is_err(), "start{at}");
        assert!(c.quarantined());
        assert!(m.lock().unwrap().quarantine >= 1);
    }
    let (mut c, m, _, _) = fixture();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    unsafe { c.begin_rfk() }.unwrap();
    m.lock().unwrap().clear_log();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    unsafe { c.finish_rfk() }.unwrap();
    let end_total = m.lock().unwrap().calls;
    for at in 1..=end_total {
        let (mut c, m, _, _) = fixture();
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        unsafe { c.begin_rfk() }.unwrap();
        m.lock().unwrap().clear_log();
        m.lock().unwrap().fail = Some(at);
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        assert!(unsafe { c.finish_rfk() }.is_err(), "finish{at}");
        assert!(c.quarantined());
    }
    let (mut c, m, _, _) = fixture();
    m.lock().unwrap().panic_at = Some(8);
    assert!(
        // SAFETY: the model device, its pages and its domain belong to this test alone; no
        // other driver, worker or DMA touches them.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe { c.begin_rfk() }))
            .is_err()
    );
    assert!(c.quarantined());
    drop(c);
    assert!(m.lock().unwrap_or_else(|e| e.into_inner()).quarantine >= 1);
    let (mut c, m, owner, dropped) = fixture();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    unsafe { c.begin_rfk() }.unwrap();
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    unsafe { c.finish_rfk() }.unwrap();
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    let io = unsafe { c.release_after_stop() }.unwrap();
    drop(c);
    assert_eq!(m.lock().unwrap().quarantine, 0);
    drop(io);
    assert_eq!(Arc::strong_count(&owner), 1);
    drop(owner);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}
