// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Shared RTL8822C register, OTP and calibration fixtures.
extern crate std;
use super::*;
use crate::wifi::stepped::block_on;
use alloc::{sync::Arc, vec, vec::Vec};
use std::sync::Mutex;
struct Model {
    profile: Profile,
    bytes: Vec<u8>,
    physical: [u8; 512],
    pending: bool,
    calls: usize,
    fail: Option<usize>,
    mutate: Option<(usize, u32, usize, u32)>,
    record: bool,
    events: Vec<[u32; 4]>,
    quarantined: usize,
    dac: Option<DacModel>,
    fifo_ready: bool,
    /// Also answer the power sequence, firmware download and mailbox as a
    /// whole chip does ([`Model::chip_written`]).
    chip: bool,
    beacons: usize,
}
#[derive(Default)]
struct DacModel {
    phase: u8,
    active: u32,
    seed: u32,
    adc_input: i32,
    samples: usize,
    invalid_after: Option<usize>,
    invalid_prefix: usize,
    ready_delay: Option<(u32, usize)>,
    ready_reads: usize,
    unstable: bool,
    adc_residual: u32,
    dac_residual: u32,
    ready_override: Option<(u32, u32)>,
    cache_read: bool,
    distinct_cache: bool,
}
impl Model {
    fn get(&self, r: u32, width: usize) -> u32 {
        let mut b = [0; 4];
        b[..width].copy_from_slice(&self.bytes[r as usize..r as usize + width]);
        u32::from_le_bytes(b)
    }
    fn set(&mut self, r: u32, width: usize, v: u32) {
        self.bytes[r as usize..r as usize + width].copy_from_slice(&v.to_le_bytes()[..width]);
    }
    fn dac_read(&mut self, r: u32) -> u32 {
        let mut v = self.get(r, 4);
        let Some(d) = self.dac.as_ref() else {
            return v;
        };
        if r == 0x2dbc {
            let n = d.samples;
            let sample = if n < d.invalid_prefix || d.invalid_after.is_some_and(|at| n >= at) {
                200
            } else if d.unstable {
                if n.is_multiple_of(2) { 100 } else { 924 }
            } else {
                match d.phase {
                    0 => (d.adc_input as u32) & 1023,
                    1 => d.adc_residual,
                    2 => 53,
                    _ => 16 + d.dac_residual,
                }
            };
            self.dac.as_mut().unwrap().samples += 1;
            return (sample << 12) | sample;
        }
        if let Some((at, raw)) = d.ready_override
            && r == at
        {
            return raw;
        }
        let distinct = d.distinct_cache && d.cache_read;
        let seed = d.seed;
        for p in 0..2 {
            let b = if p == 0 { 0x1800 } else { 0x4100 };
            let rd = if p == 0 { 0x2800 } else { 0x4500 };
            if r == rd + 8 || r == rd + 0x34 {
                v = (v & !0x7fff80) | (0xffff << 7);
            }
            if r == rd + 0x24 || r == rd + 0x50 {
                let off = if r == rd + 0x24 { 0xbc } else { 0xd8 };
                let iq = (self.get(b + off, 4) >> 28) | ((self.get(b + off + 4, 4) & 15) << 4);
                v = (v & !0x07f80000) | (iq << 19);
            }
            if r == rd + 0x10 || r == rd + 0x3c {
                let vec = u32::from(r != rd + 0x10);
                let index = self.get(b + 0xb0 + vec * 0x1c, 4) >> 28;
                let actual = (seed * 17 + p * 71 + vec * 29 + index * 7) & 511;
                v = (v & !0x7fc0000) | (actual << 18);
                self.dac.as_mut().unwrap().cache_read = true;
            }
        }
        if let Some((reg, count)) = self.dac.as_ref().unwrap().ready_delay
            && reg == r
        {
            let d = self.dac.as_mut().unwrap();
            if d.ready_reads < count {
                v &= !0x7fff80;
            }
            d.ready_reads += 1;
        }
        if distinct {
            match r {
                0x41bc => v = 0x10000000,
                0x41c0 => v = 2,
                0x41d8 => v = 0x30000000,
                0x41dc => v = 4,
                _ => {}
            }
        }
        v
    }
    fn dac_written(&mut self, r: u32, v: u32) {
        let Some(d) = self.dac.as_mut() else {
            return;
        };
        if r == 0x1810 {
            d.active = 0;
        }
        if r == 0x4110 {
            d.active = 1;
        }
        let b = if d.active == 0 { 0x1800 } else { 0x4100 };
        let format = self.get(b + 0x10, 4);
        let d = self.dac.as_mut().unwrap();
        if r == 0x1c3c {
            if v & 0xffff == 0x8003 {
                d.phase = 0;
            } else if v & 0xffff == 0x8103 {
                d.phase = if format == 0x02dd08c4 { 1 } else { 2 };
            }
        }
        if r == b + 0x68 && format == 0x02d508c5 {
            d.phase = 3;
        }
    }
    fn initial(&mut self, seed: usize) {
        for (i, b) in self.bytes.iter_mut().enumerate() {
            *b = (i * 13 + seed * 7) as u8;
        }
        self.set(0xf0, 4, self.profile.observed().sys_cfg1);
        self.set(0x80, 4, 0xc078);
        self.pending = false;
    }
    fn op(&mut self) -> Result<(), io::Error> {
        self.calls += 1;
        if self.fail == Some(self.calls) {
            return Err(io::Error::Register);
        }
        if let Some((at, r, w, v)) = self.mutate
            && at == self.calls
        {
            self.set(r, w, v);
        }
        Ok(())
    }
    fn event(&mut self, k: u32, r: u32, w: usize, v: u32) {
        if self.record {
            self.events.push([k, r, w as u32, v]);
        }
    }
    /// What a whole chip does after a store: the power state machine's
    /// self-clearing requests, DDMA and beacon completion, the arbiter's
    /// ready window, and firmware that boots once its CPU starts on a
    /// checked image, answering the feature request.
    fn chip_written(&mut self, r: u32, width: usize, v: u32) {
        use super::super::registers::{
            BIT_DDMACH0_OWN, BIT_PCI_BCNQ_FLAG, REG_C2HEVT, REG_CR, REG_DDMA_CH0CTRL,
            REG_FIFOPAGE_CTRL_2, REG_MCUFW_CTRL, REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1,
            RTK_PCI_TXBD_BCN_WORK, RTK_PCI_TXBD_RWPTR_CLR,
        };
        if !self.chip {
            return;
        }
        match (r, width) {
            (5, 1) => {
                let mut stored = v;
                if v & 1 != 0 {
                    self.set(REG_CR, 1, 0);
                    stored &= !1;
                }
                if v & 2 != 0 {
                    self.set(REG_CR, 1, 0xea);
                    stored &= !2;
                }
                self.set(5, 1, stored);
            }
            (REG_DDMA_CH0CTRL, 4) => self.set(r, 4, v & !BIT_DDMACH0_OWN),
            (REG_FIFOPAGE_CTRL_2, 2) => self.set(r, 2, v & !(1 << 15)),
            (REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1, 4) => self.set(r, 4, 1 << 29),
            // rtw_pci_reset_buf_desc: the pointers clear, as does the H2C
            // queue's index on its self-clearing request.
            (RTK_PCI_TXBD_RWPTR_CLR, 4) => {
                self.bytes[0x3a0..0x3bc].fill(0);
                self.set(r, 4, 0);
            }
            (0x1330, 4) if v & ((1 << 16) | (1 << 8)) != 0 => {
                self.set(0x132c, 4, 0);
                self.set(r, 4, v & !((1 << 16) | (1 << 8)));
            }
            // The native beacon queue's kick: the page lands at once.
            (RTK_PCI_TXBD_BCN_WORK, 1) if v & u32::from(BIT_PCI_BCNQ_FLAG) != 0 => {
                self.beacons += 1;
                let valid = self.get(REG_FIFOPAGE_CTRL_2, 2) | (1 << 15);
                self.set(REG_FIFOPAGE_CTRL_2, 2, valid);
            }
            (3, _) if v & 4 != 0 && self.get(REG_MCUFW_CTRL, 2) & 0x4050 == 0x4050 => {
                let ready = self.get(REG_MCUFW_CTRL, 2) | 0x8000;
                self.set(REG_MCUFW_CTRL, 2, ready);
                if self.get(REG_C2HEVT, 1) == 0xfd {
                    self.set(REG_C2HEVT, 1, 0x19);
                    self.bytes[0x1a2..0x1af].fill(0);
                }
            }
            _ => {}
        }
    }
}
struct Bus {
    model: Arc<Mutex<Model>>,
    panic_delay: bool,
    panic_register: Option<u32>,
    /// The clock delays and deadlines keep; none delays in place.
    clock: Option<crate::Clock>,
}
impl Bus {
    /// A register access on a clocked bus takes a microsecond, about what a
    /// PCIe read does.
    fn access(&self) {
        if let Some(clock) = self.clock {
            crate::test_clock::advance(clock, 1);
        }
    }
}
// SAFETY: the Arc keeps all register/OTP/RF storage live and each access locks
// the same model before applying its width-specific effect. Delays and responses
// are scripted fixture events; beacon DMA methods panic before publication.
unsafe impl Io for Bus {
    fn profile(&self) -> Profile {
        self.model.lock().unwrap().profile
    }
    fn read8(&mut self, r: u32) -> Result<u8, io::Error> {
        self.access();
        let mut m = self.model.lock().unwrap();
        m.op()?;
        let v = m.get(r, 1);
        m.event(0, r, 1, v);
        Ok(v as u8)
    }
    fn read16(&mut self, r: u32) -> Result<u16, io::Error> {
        self.access();
        let mut m = self.model.lock().unwrap();
        m.op()?;
        let v = m.get(r, 2);
        m.event(0, r, 2, v);
        Ok(v as u16)
    }
    fn read32(&mut self, r: u32) -> Result<u32, io::Error> {
        self.access();
        if self.panic_register == Some(r) {
            panic!("modeled register unwind");
        }
        let mut m = self.model.lock().unwrap();
        m.op()?;
        if r == 0x30 && m.pending {
            let control = m.get(r, 4);
            let address = ((control >> 8) & 1023) as usize;
            let value = (control & !255) | (m.physical[address] as u32) | (1 << 31);
            m.set(r, 4, value);
            m.pending = false;
        }
        if r == 0x208 && m.fifo_ready {
            let v = m.get(r, 4) & !1;
            m.set(r, 4, v);
        }
        let v = m.dac_read(r);
        m.event(0, r, 4, v);
        Ok(v)
    }
    fn write8(&mut self, r: u32, v: u8) -> Result<(), io::Error> {
        self.access();
        let mut m = self.model.lock().unwrap();
        m.op()?;
        m.event(1, r, 1, v.into());
        m.set(r, 1, v.into());
        m.chip_written(r, 1, v.into());
        Ok(())
    }
    fn write16(&mut self, r: u32, value: u16) -> Result<(), io::Error> {
        self.access();
        let mut m = self.model.lock().unwrap();
        m.op()?;
        m.event(1, r, 2, value.into());
        m.set(r, 2, value.into());
        m.chip_written(r, 2, value.into());
        Ok(())
    }
    fn write32(&mut self, r: u32, v: u32) -> Result<(), io::Error> {
        self.access();
        let mut m = self.model.lock().unwrap();
        m.op()?;
        m.event(1, r, 4, v);
        m.set(r, 4, v);
        m.dac_written(r, v);
        m.chip_written(r, 4, v);
        if r == 0x30 {
            m.pending = true;
        }
        // Each chip's SIPI ports and the RF registers behind them.
        let ports = if m.profile.chip() == super::super::identity::Chip::Rtl8821C {
            [(0xc90, 0x2800), (0xe90, 0x2c00)]
        } else {
            [(0x1808, 0x3c00), (0x4108, 0x4c00)]
        };
        for (sipi, base) in ports {
            if r == sipi {
                let a = base + (((v >> 20) & 255) * 4);
                let old = m.get(a, 4);
                m.set(a, 4, (old & !0xfffff) | (v & 0xfffff));
            }
        }
        Ok(())
    }
    fn delay_us(&mut self, us: u64) {
        if self.panic_delay {
            panic!("modeled timer unwind")
        }
        self.model.lock().unwrap().event(2, 0, 0, us as u32);
        if let Some(clock) = self.clock {
            crate::test_clock::advance(clock, us);
        }
    }
    fn now_us(&mut self) -> Result<u64, io::Error> {
        self.clock
            .map(|clock| clock.now_us())
            .ok_or(io::Error::InvalidClock)
    }
    fn deadline(&mut self, us: u64) -> Option<crate::Deadline> {
        self.clock.map(|clock| clock.deadline(us))
    }
    fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
        let mut m = self.model.lock().unwrap();
        assert!(m.chip, "no PHY DMA publication");
        m.op()?;
        m.beacons += 1;
        let valid = m.get(0x204, 2) | (1 << 15);
        m.set(0x204, 2, valid);
        Ok(())
    }
    unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
        assert!(self.model.lock().unwrap().chip, "no PHY DMA completion");
        Ok(())
    }
    fn quarantine(&mut self) {
        self.model.lock().unwrap().quarantined += 1;
    }
}
fn setup(
    cut: u8,
    rfe: u8,
    crystal: u8,
    seed: usize,
    one_phy: bool,
    invalid_mac: bool,
) -> (Bus, Board, Report) {
    let profile = Profile::select(super::super::identity::Observed {
        vendor: 0x10ec,
        device: 0xc822,
        subsystem_vendor: 0x17aa,
        subsystem_device: 0x1234,
        pci_revision: 1,
        sys_cfg1: (1 << 27) | (u32::from(cut) << 12),
    })
    .unwrap();
    let mut m = Model {
        profile,
        bytes: vec![0; 0x5000],
        physical: [255; 512],
        pending: false,
        calls: 0,
        fail: None,
        mutate: None,
        record: false,
        events: Vec::new(),
        quarantined: 0,
        dac: None,
        fifo_ready: false,
        chip: false,
        beacons: 0,
    };
    // Decode the board through the same OTP protocol exercised by efuse::read.
    let mac = if invalid_mac {
        [0; 6]
    } else {
        [2, 3, 4, 5, 6, 7]
    };
    let encoded = [
        0xef, 0x2e, 0x7f, crystal, 0x2f, 0x3d, rfe, 0xff, 0x8f, 0x48, mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5], 0xff,
    ];
    m.physical[..encoded.len()].copy_from_slice(&encoded);
    m.initial(seed);
    let model = Arc::new(Mutex::new(m));
    let mut bus = Bus {
        model: model.clone(),
        panic_delay: false,
        panic_register: None,
        clock: None,
    };
    // SAFETY: Bus keeps the register buffer and 512-byte OTP array behind its mutex.
    // The modeled OTP command/response runs synchronously, with no other reader or reset worker.
    let board = block_on(unsafe { super::super::efuse::read(&mut bus) })
        .unwrap()
        .logical()
        .unwrap()
        .board();
    {
        let mut m = model.lock().unwrap();
        m.set(0x1a0, 1, 0x19);
        m.bytes[0x1a2..0x1af].fill(0);
        if one_phy {
            m.set(0x1a8, 1, 0x20);
        }
    }
    let report = block_on(super::super::features::read(&mut bus)).unwrap();
    {
        let mut m = model.lock().unwrap();
        m.initial(seed);
        m.calls = 0;
        m.events.clear();
        m.record = true;
    }
    (bus, board, report)
}
pub(super) fn power_board_fixture(rfe: u8) -> Board {
    let (_, board, _) = setup(1, rfe, 63, 0, false, false);
    board
}
fn source_events(events: &[[u32; 4]]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut index = 0;
    while index < events.len() {
        if events[index][..3] == [0, 0xf0, 4] {
            assert_eq!(events[index + 1][..3], [0, 0x80, 2]);
            index += 2;
            // Native RF guard adds domain reads; prefix/header
            // source operations never contain this contiguous triple.
            if events.get(index).map(|x| &x[..3]) == Some(&[0, 2, 1][..])
                && events.get(index + 1).map(|x| &x[..3]) == Some(&[0, 0x1f, 1][..])
                && events.get(index + 2).map(|x| &x[..3]) == Some(&[0, 0xec, 4][..])
            {
                index += 3;
            }
        } else {
            for v in events[index] {
                result.extend_from_slice(&v.to_le_bytes());
            }
            index += 1;
        }
    }
    result
}
fn paths_setup(pattern: usize, igi: u32) -> (Bus, Loaded, Report) {
    let (mut bus, board, report) = setup(1, 0, 0x3f, 0, false, false);
    // SAFETY: Bus exclusively serializes its Arc-held register and OTP model.
    // Board/report values stay live, including mismatch cases; no DMA or other client runs.
    let loaded = block_on(unsafe { initialize(&mut bus, &board, &report) }).unwrap();
    {
        let mut m = bus.model.lock().unwrap();
        // Broad source-helper input patterns model volatile BB state at
        // this boundary; the table phase was executed above.
        m.initial(pattern);
        let bb = m.get(2, 1) | 3;
        m.set(2, 1, bb);
        let rf = m.get(0x1f, 1) | 7;
        m.set(0x1f, 1, rf);
        let wlrf = m.get(0xec, 4) | 0x07000000;
        m.set(0xec, 4, wlrf);
        let raw = (m.get(0x1d70, 4) & !127) | igi;
        m.set(0x1d70, 4, raw);
        m.calls = 0;
        m.events.clear();
    }
    (bus, loaded, report)
}
fn dynamic_setup(
    pattern: usize,
    igi: u32,
    crystal: u8,
    upper: u32,
    lower: u32,
) -> (Bus, PathsConfigured, Report) {
    let (mut bus, board, report) = setup(1, 0, crystal, 0, false, false);
    // SAFETY: Bus exclusively serializes its Arc-held register and OTP model.
    // Board/report values stay live, including mismatch cases; no DMA or other client runs.
    let loaded = block_on(unsafe { initialize(&mut bus, &board, &report) }).unwrap();
    // SAFETY: The phase value and report remain live while Bus keeps its register/RF
    // model. No other RF client runs; any domain drift is injected by the serialized model.
    let paths = unsafe { loaded.configure_paths(&mut bus, &report) }.unwrap();
    {
        let mut m = bus.model.lock().unwrap();
        // Prior phases execute above; these broad volatile inputs
        // exercise this bounded phase rather than claim physical RF state.
        m.initial(pattern);
        let bb = m.get(2, 1) | 3;
        m.set(2, 1, bb);
        let rf = m.get(0x1f, 1) | 7;
        m.set(0x1f, 1, rf);
        let wlrf = m.get(0xec, 4) | 0x07000000;
        m.set(0xec, 4, wlrf);
        let raw = (m.get(0x1d70, 4) & !127) | igi;
        m.set(0x1d70, 4, raw);
        let raw = (m.get(0x1a98, 4) & !0xc0c0) | ((upper >> 4) << 14) | ((lower >> 4) << 6);
        m.set(0x1a98, 4, raw);
        let raw = (m.get(0x1aa8, 4) & !0xf0000) | ((upper & 15) << 16);
        m.set(0x1aa8, 4, raw);
        let raw = (m.get(0x1a70, 4) & !0xf000000) | ((lower & 15) << 24);
        m.set(0x1a70, 4, raw);
        m.calls = 0;
        m.events.clear();
    }
    (bus, paths, report)
}
fn dynamic_words(state: &InitialPhy) -> Vec<u32> {
    let t = state.tracking();
    let mut words: Vec<u32> = t.fa_history.into_iter().map(u32::from).collect();
    words.push(t.igi_bitmap.into());
    words.extend(state.igi_history().map(u32::from));
    words.extend(t.cck_pd_levels.into_iter().flatten().map(u32::from));
    words.extend([
        t.cck_fa_average.unwrap_or(u32::MAX),
        u32::from(t.iqk_done),
        state.crystal_cap().into(),
        u32::from(t.cfo_adjusting),
        match t.current_tx_path {
            Path::A => 1,
            Path::B => 2,
        },
        t.path_counts[0].into(),
        t.path_sums[0],
        t.path_counts[1].into(),
        t.path_sums[1],
    ]);
    words.extend(state.cck_bounds().map(u32::from));
    words
}
fn dac_setup(seed: u32) -> (Bus, InitialPhy, Report) {
    let (mut bus, paths, report) = dynamic_setup(0, 0, 63, 0, 0);
    // SAFETY: Bus keeps the modeled IGI/CCK/EDCCA registers and phase arguments.
    // Reads, writes and injected failures occur sequentially without another RF client.
    let initial = unsafe { paths.initialize_dynamic(&mut bus, &report) }.unwrap();
    {
        let mut m = bus.model.lock().unwrap();
        m.initial(seed as usize);
        let bb = m.get(2, 1) | 3;
        m.set(2, 1, bb);
        let rf = m.get(0x1f, 1) | 7;
        m.set(0x1f, 1, rf);
        let wlrf = m.get(0xec, 4) | 0x07000000;
        m.set(0xec, 4, wlrf);
        m.set(0x3e3c, 4, 0x12345678);
        m.set(0x4e3c, 4, 0x12345678);
        m.dac = Some(DacModel {
            seed,
            adc_input: seed as i32 - 32,
            ready_delay: Some((0x2808, (seed % 4) as usize)),
            ..Default::default()
        });
        m.calls = 0;
        m.events.clear();
    }
    (bus, initial, report)
}
fn trim_setup(case: u32) -> (Bus, DacCalibrated, Report, super::super::efuse::Physical) {
    let (mut bus, initial, report) = dac_setup(case % 64);
    // SAFETY: The Bus Arc keeps register and scripted ADC/DAC sample storage.
    // Sampling and fault injection are synchronous; no other RF or calibration user can race them.
    let calibration = block_on(unsafe { initial.calibrate_dac(&mut bus, &report) }).unwrap();
    {
        let mut m = bus.model.lock().unwrap();
        m.dac = None;
        // Factory bytes live entirely in the protected OTP tail, outside
        // the logical board stream used by previous phases.
        let addresses = [
            0x1ef, 0x1b0, 0x1d4, 0x1ee, 0x1d2, 0x1ec, 0x1e8, 0x1e4, 0x1e0, 0x1dc, 0x1eb, 0x1e7,
            0x1e3, 0x1df, 0x1db, 0x1d6, 0x1d8, 0x1d5, 0x1d7,
        ];
        for (i, a) in addresses.into_iter().enumerate() {
            m.physical[a] = if case == 0 || (case >> (i % 9)) & 1 == 0 {
                255
            } else {
                (case * 37 + i as u32 * 29) as u8
            };
        }
    }
    // This is the real private-provenance 512-byte native OTP transport,
    // not a publicly constructed Physical or copied diagnostic byte token.
    // SAFETY: Bus keeps the register buffer and 512-byte OTP array behind its mutex.
    // The modeled OTP command/response runs synchronously, with no other reader or reset worker.
    let physical = block_on(unsafe { super::super::efuse::read(&mut bus) }).unwrap();
    {
        let mut m = bus.model.lock().unwrap();
        m.initial(case as usize);
        let bb = m.get(2, 1) | 3;
        m.set(2, 1, bb);
        let rf = m.get(0x1f, 1) | 7;
        m.set(0x1f, 1, rf);
        let wlrf = m.get(0xec, 4) | 0x07000000;
        m.set(0xec, 4, wlrf);
        let b8 = (m.get(0x3ee0, 4) & !(1 << 15)) | ((case & 1) << 15);
        m.set(0x3ee0, 4, b8);
        m.calls = 0;
        m.events.clear();
    }
    (bus, calibration, report, physical)
}
fn tail_setup(pattern: usize, a: u8, b: u8) -> (Bus, FactoryInitialized, Report) {
    let (mut bus, calibration, report, _) = trim_setup(0);
    {
        let mut m = bus.model.lock().unwrap();
        m.physical[16..21].copy_from_slice(&[0x4f, 0x3e, a, b, 255]);
    }
    // SAFETY: Bus keeps the register buffer and 512-byte OTP array behind its mutex.
    // The modeled OTP command/response runs synchronously, with no other reader or reset worker.
    let physical = block_on(unsafe { super::super::efuse::read(&mut bus) }).unwrap();
    assert_eq!(
        physical.logical().unwrap().board().raw().thermal_raw,
        [a, b]
    );
    // SAFETY: The calibration, report and decoded OTP objects remain live through the
    // call. Bus serializes their register model, including intentional provenance/profile failures.
    let factory =
        block_on(unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }).unwrap();
    {
        let mut m = bus.model.lock().unwrap();
        m.initial(pattern);
        let bb = m.get(2, 1) | 3;
        m.set(2, 1, bb);
        let rf = m.get(0x1f, 1) | 7;
        m.set(0x1f, 1, rf);
        let wlrf = m.get(0xec, 4) | 0x07000000;
        m.set(0xec, 4, wlrf);
        m.calls = 0;
        m.events.clear();
    }
    (bus, factory, report)
}
fn source_mac_setup(cut: u8) -> (Bus, Report) {
    let (bus, _, report) = setup(cut, 0, 63, 0, false, false);
    {
        let mut m = bus.model.lock().unwrap();
        m.fifo_ready = true;
        m.set(0x10d0, 4, 0);
        m.set(0x10d4, 4, 0);
    }
    (bus, report)
}

fn channel_setup() -> (Bus, PhyInitialized, Report, channel_power::Geometry) {
    let (bus, phy, report, _) = power_setup();
    let g =
        channel_power::Geometry::new(36, channel_power::Width::Mhz80, Some(38), Some(42)).unwrap();
    (bus, phy, report, g)
}

fn power_limits() -> channel_power::Limits {
    channel_power::Limits {
        factory_sheet: FactorySheet::Fcc,
        max_eirp_mbm: 2500,
        antenna_and_combining_mbm: [100, 125],
        sar_quarter_dbm: Some([90, 89]),
        remnant_cck: 0,
        remnant_ofdm: [0; 2],
    }
}
pub(super) fn control_fixture() -> (PhyInitialized, Report) {
    let (_, phy, report, _) = power_setup();
    (phy, report)
}
fn power_setup() -> (Bus, PhyInitialized, Report, channel_power::Plan) {
    let (mut bus, factory, report) = tail_setup(0, 5, 6);
    // SAFETY: Bus keeps the thermal/beamforming register model and all phase inputs.
    // There is no concurrent RF, packet or reset producer during these serialized effects.
    let phy = unsafe { factory.finish_initial_phy(&mut bus, &report) }.unwrap();
    let g = channel_power::Geometry::new(1, channel_power::Width::Mhz20, None, None).unwrap();
    let plan = phy
        .factory_power()
        .plan_channel_power(g, power_limits())
        .unwrap();
    {
        let mut m = bus.model.lock().unwrap();
        m.calls = 0;
        m.events.clear();
    }
    (bus, phy, report, plan)
}

mod chip;

mod mac;

mod channel_state;

mod power;

mod tail;

mod factory;

mod calibration;

mod dynamic;

mod paths;

mod tables;
