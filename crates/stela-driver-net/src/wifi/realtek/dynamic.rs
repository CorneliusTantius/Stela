// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! What the receive path learns of the air, and what rtw88's
//! `rtw_phy_dynamic_mechanism` makes of it: `query_phy_status`, the peer's RSSI,
//! its level among rates, the gain `rtw_phy_dig` sets against false alarms, CCK
//! packet detection, the transmit path, the crystal, thermal power tracking and
//! energy detection.
use super::{
    commands::{self, Report},
    features::Report as Features,
    io::{self, Io},
    rf::{self, Path},
    station::MAC_ID,
};
use crate::{Mac, wifi::Band};

/// `db_invert_table`: rows past the third hold `FRAC_BITS` less, and 62 dB's
/// entry is the driver's own.
const DB_INVERT: [[u32; 8]; 12] = [
    [10, 13, 16, 20, 25, 32, 40, 50],
    [64, 80, 101, 128, 160, 201, 256, 318],
    [401, 505, 635, 800, 1007, 1268, 1596, 2010],
    [316, 398, 501, 631, 794, 1000, 1259, 1585],
    [1995, 2512, 3162, 3981, 5012, 6310, 7943, 10000],
    [12589, 15849, 19953, 25119, 31623, 39811, 50119, 63098],
    [
        79433, 100000, 125893, 158489, 199526, 251189, 316228, 398107,
    ],
    [
        501187, 630957, 794328, 1000000, 1258925, 1584893, 1995262, 2511886,
    ],
    [
        3162278, 3981072, 5011872, 6309573, 7943282, 1000000, 12589254, 15848932,
    ],
    [
        19952623, 25118864, 31622777, 39810717, 50118723, 63095734, 79432823, 100000000,
    ],
    [
        125892541, 158489319, 199526232, 251188643, 316227766, 398107171, 501187234, 630957345,
    ],
    [
        794328235, 1000000000, 1258925412, 1584893192, 1995262315, 2511886432, 3162277660,
        3981071706,
    ],
];
const FRAC_BITS: u32 = 3;

/// `DIG_PERF_*` and `DIG_CVRG_*`, with `rtw8822c_hw_spec.dig_min`.
const LINKED_ALARMS: [u16; 3] = [750, 500, 250];
const LINKED_LOW: u16 = 250;
const LINKED_HIGH: u16 = 500;
const LINKED_MAX: u8 = 0x5a;
const LINKED_MID: u8 = 0x40;
const LINKED_MIN: u8 = 0x20;
const COVERAGE_ALARMS: [u16; 3] = [5000, 4000, 2000];
const COVERAGE_MAX: u8 = 0x2a;
const COVERAGE_MID: u8 = 0x26;
/// `DIG_CVRG_MIN`, where a scan listens widest.
pub const MAX_COVERAGE: u8 = 0x1c;
/// `RTW_LPS_THRESHOLD`, and what `rtw_watch_dog_work` calls busy.
const LPS_THRESHOLD: u32 = 50;
const BUSY_THRESHOLD: u32 = 100;

/// How a watchdog period's frames count.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Traffic {
    /// `ps_active`.
    pub sleepless: bool,
    /// `RTW_FLAG_BUSY_TRAFFIC`.
    pub busy: bool,
}
const RSSI_GAIN_OFFSET: u8 = 15;
/// `DECLARE_EWMA(rssi, 10, 16)`.
const AVERAGE_PRECISION: u32 = 10;
const AVERAGE_WEIGHT: u32 = 4;
/// `rtw_phy_get_rssi_level`'s table and `RA_FLOOR_UP_GAP`.
const LEVELS: [u8; 7] = [20, 34, 38, 42, 46, 50, 100];
const LEVEL_UP_GAP: u8 = 3;
/// `RA_MASK_CCK_RATES` and `RA_MASK_OFDM_RATES`.
const LEGACY_RATES: u64 = 0xfff;
/// `DESC_RATEVHT4SS_MCS0` down to `DESC_RATE1M`, each family's first rate.
const FIRST_RATES: [u8; 10] = [0x4a, 0x40, 0x36, 0x2c, 0x24, 0x1c, 0x14, 0x0c, 0x04, 0];
const FIRST_HT_RATE: u8 = 0x0c;
/// `DESC_RATE11M`.
const LAST_CCK_RATE: u8 = 3;
/// `RRSR_RATE_ORDER_CCK_LEN`.
const CCK_ORDERS: u8 = 4;

/// `CCK_PD_*`: false alarms, then the gain and RSSI each level asks.
const CCK_ALARMS_RAISE: u32 = 1000;
const CCK_ALARMS_RESTORE: u32 = 500;
const CCK_GAINS: [u8; 3] = [0x38, 0x2a, 0x24];
const CCK_RSSIS: [u8; 3] = [32, 32, 24];
/// `pd_lvl` and `cs_lvl` of `rtw8822c_phy_cck_pd_set`.
const DETECT_LEVELS: [i16; 5] = [0, 2, 4, 6, 8];
const SENSE_LEVELS: [i16; 5] = [0, 2, 2, 2, 4];
/// `rtw8822c_cck_pd_reg` by width and receive paths: threshold, carrier sense.
const CCK_FIELDS: [[[(u32, u32); 2]; 2]; 2] = [
    [
        [(0x1ac8, 0x00ff), (0x1ad0, 0x001f)],
        [(0x1ac8, 0xff00), (0x1ad0, 0x03e0)],
    ],
    [
        [(0x1acc, 0x00ff), (0x1ad0, 0x01f0_0000)],
        [(0x1acc, 0xff00), (0x1ad0, 0x3e00_0000)],
    ],
];
const REG_CCK_PATHS: u32 = 0x1a2c;
const CCK_PATHS: u32 = 0x60000;
const REG_WIDTH: u32 = 0x9b0;
const WIDTH: u32 = 0xc;
/// `RTW_CCK_PD_MAX`, `RTW_CCK_CS_MAX`, and the two senses firmware's table skips.
const DETECT_MAX: u32 = 255;
const SENSE_MAX: u32 = 31;
const SENSE_SKIPPED: [u32; 2] = [27, 29];
/// `REG_RXCCKSEL`, `REG_ANTMAP0`, `REG_TXLGMAP` and `REG_SYS_FUNC_EN`.
const REG_CCK_TX: u32 = 0x1a04;
const CCK_TX: u32 = 0xf000_0000;
const REG_ANTENNA_MAP: u32 = 0x820;
const ANTENNA_MAP: u32 = 0xff;
const REG_LEGACY_MAP: u32 = 0x1e2c;
const LEGACY_MAP: u32 = 0xffff;
const ONE_STREAM_MAP: u32 = 0x0400;
const REG_FUNCTIONS: u32 = 2;
const BB_RESET: u16 = 1;
/// `REG_ANAPAR_XTAL_0`, `BIT_XCAP_0`, and `CFO_TRK_*` in kHz.
const REG_CRYSTAL: u32 = 0x1040;
const CRYSTAL: u32 = 0xfffc00;
const CRYSTAL_MAX: i16 = 0x7f;
const OFFSET_ENABLE_KHZ: i32 = 20;
const OFFSET_STOP_KHZ: i32 = 10;
const OFFSET_ADJUST_KHZ: i32 = 10;
/// `RF_T_METER` and the thermal reading's bits, and `DECLARE_EWMA(thermal, 10, 4)`.
const RF_T_METER: u8 = 0x42;
const THERMAL_TRIGGER: u32 = 1 << 19;
const THERMAL: u32 = 0x7e;
const THERMAL_WEIGHT: u32 = 2;
/// `rtw8822c_pwrtrack_set`, by path.
const REG_POWER_INDEX: [u32; 2] = [0x18a0, 0x41a0];
const POWER_INDEX: u32 = 0x7f;
/// `lck_threshold`.
const LCK_THRESHOLD: u8 = 8;
/// `RF_SYN_CTRL`, `RF_SYN_PFD`, `RF_AAC_CTRL`, `RF_SYN_AAC`, `RF_FAST_LCK`.
const RF_SYN_CTRL: u8 = 0xbb;
const RF_SYN_PFD: u8 = 0xb0;
const RF_AAC_CTRL: u8 = 0xca;
const RF_SYN_AAC: u8 = 0xc9;
const RF_FAST_LCK: u8 = 0xcc;
const RF_WHOLE: u32 = 0xfffff;
/// `read_poll_timeout`'s step, and 20 of rtw88's 100: the lock runs from the
/// watchdog, whose caller this must not hold, and settles in a few steps.
const LCK_POLL_US: u64 = 1000;
const LCK_POLLS: usize = 20;
/// `RTW_TP_SHIFT` and `DECLARE_EWMA(tp, 10, 2)`.
const MBPS_SHIFT: u32 = 18;
const THROUGHPUT_WEIGHT: u32 = 1;
/// `EDCCA_*`, with `l2h_th_ini_ad` and `l2h_th_ini_cs`.
const EDCCA_FLOOR: i16 = 48;
const EDCCA_GAIN_OFFSET: i16 = 8;
const EDCCA_NORMAL_GAP: i16 = 8;
const EDCCA_GAP: i16 = 7;
const EDCCA_BACKOFF: i16 = 12;
const EDCCA_ETSI: u8 = 45;
const EDCCA_JAPAN: u8 = 60;
/// regulatory.db's `NL80211_DFS_ETSI` and `NL80211_DFS_JP`.
const DFS_ETSI: u8 = 2;
const DFS_JAPAN: u8 = 3;
/// `rtw8822c_pwrtrk_*`, for a temperature above or below the factory's. Each
/// 5 GHz sub-band repeats one row.
type Swing = [u8; 30];
const RAISE_2GHZ: [Swing; 2] = [
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 25, 26, 27,
    ],
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28,
    ],
];
const LOWER_2GHZ: [Swing; 2] = [
    [
        0, 1, 2, 2, 3, 4, 4, 5, 6, 6, 7, 8, 8, 9, 9, 10, 11, 11, 12, 13, 13, 14, 15, 15, 16, 17,
        17, 18, 19, 19,
    ],
    [
        0, 1, 2, 3, 4, 4, 5, 6, 7, 8, 9, 9, 10, 11, 12, 13, 14, 15, 15, 16, 17, 18, 19, 20, 20, 21,
        22, 23, 24, 25,
    ],
];
const RAISE_CCK: [Swing; 2] = [
    [
        0, 1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 11, 12, 13, 14, 15, 16, 17, 18, 18, 19, 20, 21,
        22, 23, 24, 24, 25,
    ],
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29,
    ],
];
const LOWER_CCK: [Swing; 2] = [
    [
        0, 1, 2, 3, 3, 4, 5, 6, 6, 7, 8, 9, 9, 10, 11, 12, 12, 13, 14, 15, 15, 16, 17, 18, 18, 19,
        20, 21, 21, 22,
    ],
    [
        0, 1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 11, 12, 13, 14, 15, 16, 17, 17, 18, 19, 20, 21,
        22, 23, 23, 24, 25,
    ],
];
const RAISE_5GHZ: [Swing; 2] = [
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30,
    ],
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 22,
        23, 24, 25, 26, 27,
    ],
];
const LOWER_5GHZ: [Swing; 2] = [
    [
        0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27,
        28, 29, 30, 31, 33,
    ],
    [
        0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 32,
    ],
];

/// Why a tracking step did not reach the hardware.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Rf(rf::Error),
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<rf::Error> for Error {
    fn from(error: rf::Error) -> Self {
        Self::Rf(error)
    }
}

/// `rtw_write32_mask`.
pub fn set_mask<I: Io>(io: &mut I, register: u32, mask: u32, value: u32) -> Result<(), io::Error> {
    let old = io.read32(register)?;
    io.write32(
        register,
        (old & !mask) | ((value << mask.trailing_zeros()) & mask),
    )
}

/// `rtw_read32_mask`.
fn mask_of<I: Io>(io: &mut I, register: u32, mask: u32) -> Result<u32, io::Error> {
    Ok((io.read32(register)? & mask) >> mask.trailing_zeros())
}

/// `ewma_add`, in ten fraction bits.
fn average_in(internal: &mut u64, value: u64, weight: u32) {
    let value = value << AVERAGE_PRECISION;
    *internal = if *internal == 0 {
        value
    } else {
        ((*internal << weight) - *internal + value) >> weight
    };
}

/// What only an OFDM frame's PHY status holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ofdm {
    /// `DESC_RATE*` the frame came at.
    rate: u8,
    /// `dm_info->rssi` of each path.
    paths: [u8; 2],
    /// `pkt_stat->cfo_tail`.
    tails: [i8; 2],
    /// `rx_evm_dbm` of path A.
    evm_db: u8,
}

/// What a frame's PHY status says of its signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signal {
    /// `pkt_stat->rssi`.
    pub rssi: u8,
    /// `pkt_stat->signal_power`.
    pub power_dbm: i8,
    ofdm: Option<Ofdm>,
}

fn power_2_db(power: i8) -> u8 {
    if power <= -100 || power >= 20 {
        0
    } else if power >= 0 {
        100
    } else {
        (100 + i16::from(power)) as u8
    }
}

fn db_2_linear(power_db: u8) -> u64 {
    if power_db < 1 {
        return 1;
    }
    let at = usize::from(power_db.min(96) - 1);
    let (row, column) = (at >> 3, at & 7);
    let linear = u64::from(DB_INVERT[row][column]);
    if row > 2 { linear << FRAC_BITS } else { linear }
}

fn linear_2_db(linear: u64) -> u8 {
    let scaled = |row: usize| {
        if row <= 2 {
            linear << FRAC_BITS
        } else {
            linear
        }
    };
    let found = (0..12).find_map(|row| {
        (0..8)
            .find(|&column| scaled(row) <= u64::from(DB_INVERT[row][column]))
            .map(|column| (row, column))
    });
    let Some((mut row, mut column)) = found else {
        return 96;
    };
    let entry = |row: usize, column: usize| u64::from(DB_INVERT[row][column]);
    // Unsigned as the driver's, whose first rows are compared unscaled here.
    let nearer_below =
        |above: u64, below: u64| above.wrapping_sub(linear) > linear.wrapping_sub(below);
    if column > 0 {
        if nearer_below(entry(row, column), entry(row, column - 1)) {
            column -= 1;
        }
    } else if row > 0 && nearer_below(entry(row, 0), entry(row - 1, 7)) {
        row -= 1;
        column = 7;
    }
    ((row << 3) + column + 1) as u8
}

/// `rtw_phy_rf_power_2_rssi`.
fn rssi(power: &[i8]) -> u8 {
    let sum: u64 = power
        .iter()
        .map(|&path| db_2_linear(power_2_db(path)))
        .sum();
    let sum = (sum + (1 << (FRAC_BITS - 1))) >> FRAC_BITS;
    linear_2_db(sum >> (power.len() - 1))
}

/// `query_phy_status` of a frame's driver information, under the upper and
/// lower CCK gains the PHY's tables left, for a frame at `rate`.
pub fn phy_status(info: &[u8], [upper, lower]: [u8; 2], rate: u8) -> Option<Signal> {
    let word_at = |at: usize| {
        let bytes = info.get(at * 4..)?.first_chunk::<4>()?;
        Some(u32::from_le_bytes(*bytes))
    };
    let word = word_at(0)?;
    let reading = |at: u32| (word >> at) as u8 as i8;
    match word & 15 {
        0 => {
            let gain = ((word >> 16) & 0x3f) as u8;
            let power = if gain < lower {
                reading(8).wrapping_add(((lower - gain) << 1) as i8)
            } else if gain > upper {
                reading(8).wrapping_sub(((gain - upper) << 1) as i8)
            } else {
                reading(8)
            };
            let power = power.wrapping_sub(110);
            Some(Signal {
                rssi: rssi(&[power]),
                power_dbm: power.max(-120),
                ofdm: None,
            })
        }
        1 => {
            let paths = [reading(8).wrapping_sub(110), reading(16).wrapping_sub(110)];
            Some(Signal {
                rssi: rssi(&paths),
                power_dbm: paths[0].max(paths[1]).max(-120),
                ofdm: word_at(4).zip(word_at(5)).map(|(evm, tail)| Ofdm {
                    rate,
                    paths: paths.map(|path| rssi(&[path])),
                    tails: [tail as u8 as i8, (tail >> 8) as u8 as i8],
                    evm_db: evm_db(evm as u8 as i8),
                }),
            })
        }
        _ => None,
    }
}

/// `query_phy_status_page1`'s reading of an error vector.
fn evm_db(evm: i8) -> u8 {
    if evm < 0 && evm != i8::MIN {
        evm.unsigned_abs() >> 1
    } else {
        0
    }
}

/// `rtw_rate_mask_rssi` and `rtw_rate_mask_recover` of a peer's rates.
pub fn rates_at_level(rates: u64, level: u8, cck_only: bool) -> u64 {
    let allowed = match level {
        _ if cck_only => u64::MAX,
        0 => u64::MAX,
        1 => 0xffff_ffff_ffff_fff0,
        2 => 0xffff_ffff_ffff_efe0,
        3 => 0xffff_ffff_ffff_cfc0,
        4 => 0xffff_ffff_ffff_8f80,
        _ => 0xffff_ffff_ffff_0f00,
    };
    let mut kept = rates & allowed;
    if kept & !LEGACY_RATES == 0 {
        kept |= rates & !LEGACY_RATES;
    }
    if kept == 0 {
        kept |= rates & LEGACY_RATES;
    }
    kept
}

/// `rtw_phy_get_rrsr_mask` of the rate firmware last reported.
fn response_rates(rate: u8) -> u32 {
    let first = FIRST_RATES.into_iter().find(|&first| rate >= first);
    let order = rate - first.unwrap_or(0);
    let order = if rate >= FIRST_HT_RATE || order == 0 {
        order + 1
    } else {
        order
    };
    (1 << (order + CCK_ORDERS)) - 1
}

/// What a station starts tracking from.
#[derive(Debug)]
pub struct Initial {
    pub gains: [u8; 4],
    pub crystal_cap: u8,
    /// `efuse->thermal_meter`, by path.
    pub thermal: [u8; 2],
    /// `efuse->power_track_type` is zero.
    pub power_tracked: bool,
    pub lck_reference: u8,
    /// regulatory.db's `dfs_region` of the country.
    pub dfs_region: u8,
}

/// `rtw_cfo_track`.
#[derive(Debug)]
struct Crystal {
    cap: u8,
    factory: u8,
    adjusting: bool,
    tails: [i32; 2],
    counts: [i32; 2],
    packets: u32,
    previous_packets: u32,
}

impl Crystal {
    /// `rtw8822c_set_crystal_cap`.
    fn set<I: Io>(&mut self, io: &mut I, cap: u8) -> Result<(), io::Error> {
        if cap == self.cap {
            return Ok(());
        }
        self.cap = cap;
        let cap = u32::from(cap);
        set_mask(io, REG_CRYSTAL, CRYSTAL, cap | (cap << 7))
    }

    /// `rtw8822c_cfo_calc_avg`.
    fn offset_khz(&mut self) -> i32 {
        let mut sum = 0;
        for path in 0..2 {
            let reports = (self.tails[path] << 1) + (self.tails[path] >> 1);
            if self.counts[path] != 0 {
                sum += reports / self.counts[path];
            }
        }
        self.tails = [0; 2];
        self.counts = [0; 2];
        sum / 2
    }
}

/// `dm_info`'s thermal state.
#[derive(Debug)]
struct Thermal {
    factory: [u8; 2],
    tracked: bool,
    /// `pwr_trk_triggered`: the meters were asked last time.
    triggered: bool,
    internal: [u64; 2],
    averages: [u8; 2],
    lck_reference: u8,
    /// A synthesizer lock went on unsettled, not yet told.
    lock_unsettled: bool,
}

/// `rtw_phy_pwrtrack_get_pwridx`.
fn power_index(average: u8, factory: u8, raise: &Swing, lower: &Swing) -> i8 {
    let delta = usize::from(average.abs_diff(factory)).min(raise.len() - 1);
    if average > factory {
        raise[delta] as i8
    } else {
        -(lower[delta] as i8)
    }
}

/// `rtw_phy_config_swing_table`.
fn swing(band: Band, cck: bool) -> (&'static [Swing; 2], &'static [Swing; 2]) {
    match (band, cck) {
        (Band::Ghz2, true) => (&RAISE_CCK, &LOWER_CCK),
        (Band::Ghz2, false) => (&RAISE_2GHZ, &LOWER_2GHZ),
        _ => (&RAISE_5GHZ, &LOWER_5GHZ),
    }
}

/// `rtw8822c_do_lck`: whether the lock settled within its wait. rtw88 goes
/// on either way, as this does.
fn lock_synthesizer<I: Io>(rf: &mut rf::Registers<'_, I>) -> Result<bool, rf::Error> {
    rf.write(Path::A, RF_SYN_CTRL, RF_WHOLE, 0x80010)?;
    rf.write(Path::A, RF_SYN_PFD, RF_WHOLE, 0x1f0fa)?;
    rf.table_delay_us(1)?;
    rf.write(Path::A, RF_AAC_CTRL, RF_WHOLE, 0x80000)?;
    rf.write(Path::A, RF_SYN_AAC, RF_WHOLE, 0x80001)?;
    let mut settled = false;
    for _ in 0..LCK_POLLS {
        rf.table_delay_us(LCK_POLL_US)?;
        if rf.read(Path::A, RF_AAC_CTRL, 0x1000)? != 1 {
            settled = true;
            break;
        }
    }
    rf.write(Path::A, RF_SYN_PFD, RF_WHOLE, 0x1f0f8)?;
    rf.write(Path::B, RF_SYN_CTRL, RF_WHOLE, 0x80010)?;
    rf.write(Path::A, RF_FAST_LCK, RF_WHOLE, 0x0f000)?;
    rf.write(Path::A, RF_FAST_LCK, RF_WHOLE, 0x4f000)?;
    rf.table_delay_us(1)?;
    rf.write(Path::A, RF_FAST_LCK, RF_WHOLE, 0x0f000)?;
    Ok(settled)
}

/// `rtw_dm_info`'s tracking state, with the peer's `rtw_sta_info`.
#[derive(Debug)]
pub struct Dynamic {
    /// `si->avg_rssi`, in `AVERAGE_PRECISION` fixed point.
    average: u64,
    level: u8,
    min_rssi: u8,
    previous_min: u8,
    gains: [u8; 4],
    alarms: [u16; 4],
    /// `igi_bitmap`: which of the last changes rose.
    rises: u8,
    damping: bool,
    damping_count: u8,
    damping_rssi: u8,
    /// `cck_fa_avg`, none after each reset.
    cck_average: Option<u32>,
    cck_levels: [[u8; 2]; 2],
    /// `dm_path_div`.
    tx_path: Path,
    path_sums: [u32; 2],
    path_counts: [u32; 2],
    crystal: Crystal,
    thermal: Thermal,
    /// `l2h_th_ini`, on rules that ask `RTW_EDCCA_ADAPTIVITY`.
    energy_threshold: Option<u8>,
    /// `scan_density`.
    density: u8,
    /// `dm_info->tx_rate`, the one peer's `ra_report.desc_rate`.
    tx_rate: u8,
    rx_rate: u8,
    evm_db: u8,
    /// Unicast data bytes this period, and their averaged megabits.
    tx_bytes: u64,
    /// `stats.tx_cnt` and `stats.rx_cnt`.
    tx_frames: u32,
    rx_frames: u32,
    rx_bytes: u64,
    tx_throughput: u64,
    rx_throughput: u64,
}

impl Dynamic {
    pub fn new(initial: Initial) -> Self {
        Self {
            average: 0,
            level: 0,
            min_rssi: 0,
            previous_min: 0,
            gains: initial.gains,
            alarms: [0; 4],
            rises: 0,
            damping: false,
            damping_count: 0,
            damping_rssi: 0,
            cck_average: None,
            cck_levels: [[0; 2]; 2],
            tx_path: Path::A,
            path_sums: [0; 2],
            path_counts: [0; 2],
            crystal: Crystal {
                cap: initial.crystal_cap,
                factory: initial.crystal_cap,
                adjusting: true,
                tails: [0; 2],
                counts: [0; 2],
                packets: 0,
                previous_packets: 0,
            },
            thermal: Thermal {
                factory: initial.thermal,
                tracked: initial.power_tracked,
                triggered: false,
                internal: [0; 2],
                averages: [0; 2],
                lck_reference: initial.lck_reference,
                lock_unsettled: false,
            },
            energy_threshold: match initial.dfs_region {
                DFS_ETSI => Some(EDCCA_ETSI),
                DFS_JAPAN => Some(EDCCA_JAPAN),
                _ => None,
            },
            density: 0,
            tx_rate: 0,
            rx_rate: 0,
            evm_db: 0,
            tx_bytes: 0,
            tx_frames: 0,
            rx_frames: 0,
            rx_bytes: 0,
            tx_throughput: 0,
            rx_throughput: 0,
        }
    }

    /// `ewma_rssi_add`.
    fn heard(&mut self, rssi: u8) {
        average_in(&mut self.average, u64::from(rssi), AVERAGE_WEIGHT);
    }

    /// What a firmware report changes.
    pub fn reported(&mut self, report: &Report) {
        match *report {
            Report::Rate {
                mac_id: MAC_ID,
                rate,
                ..
            } => self.tx_rate = rate,
            Report::Density(density) => self.density = density,
            _ => {}
        }
    }

    /// `rtw_rx_stats` of `bytes` arriving, and what `query_phy_status`,
    /// `rtw_phy_parsing_cfo` and `rtw_rx_addr_match_iter` take from `signal`.
    pub fn frame(&mut self, bytes: &[u8], signal: Option<Signal>, address: Mac, bssid: Mac) {
        if is_unicast_data(bytes) {
            self.rx_bytes += bytes.len() as u64;
            self.rx_frames += 1;
        }
        let Some(signal) = signal else {
            return;
        };
        let from_bss = bytes.get(10..16) == Some(&bssid.0[..]);
        let control = bytes.first().is_some_and(|byte| byte & 0x0c == 4);
        if let Some(ofdm) = signal.ofdm {
            self.rx_rate = ofdm.rate;
            self.evm_db = ofdm.evm_db;
            for path in 0..2 {
                self.path_sums[path] += u32::from(ofdm.paths[path]);
                self.path_counts[path] += 1;
            }
            if from_bss && !control {
                for path in 0..2 {
                    self.crystal.tails[path] += i32::from(ofdm.tails[path]);
                    self.crystal.counts[path] += 1;
                }
                self.crystal.packets = self.crystal.packets.wrapping_add(1);
            }
        }
        let to_station = bytes.get(4..10) == Some(&address.0[..]);
        if from_bss && (to_station || bytes.first() == Some(&0x80)) {
            self.heard(signal.rssi);
        }
    }

    /// `rtw_tx_stats`.
    pub fn sent(&mut self, mpdu: &[u8]) {
        if is_unicast_data(mpdu) {
            self.tx_bytes += mpdu.len() as u64;
            self.tx_frames += 1;
        }
    }

    /// `rtw_watch_dog_work`'s accounts of the period that ended.
    pub fn close_period(&mut self) -> Traffic {
        let tx_frames = core::mem::take(&mut self.tx_frames);
        let rx_frames = core::mem::take(&mut self.rx_frames);
        let tx = core::mem::take(&mut self.tx_bytes) >> MBPS_SHIFT;
        let rx = core::mem::take(&mut self.rx_bytes) >> MBPS_SHIFT;
        average_in(&mut self.tx_throughput, tx, THROUGHPUT_WEIGHT);
        average_in(&mut self.rx_throughput, rx, THROUGHPUT_WEIGHT);
        Traffic {
            sleepless: tx_frames > LPS_THRESHOLD || rx_frames > LPS_THRESHOLD,
            busy: tx_frames > BUSY_THRESHOLD || rx_frames > BUSY_THRESHOLD,
        }
    }

    /// `stats->tx_throughput` over `rx_throughput`.
    pub fn transmitting(&self) -> bool {
        self.tx_throughput > self.rx_throughput
    }

    /// `dm_info.min_rssi`.
    pub fn min_rssi(&self) -> u8 {
        self.min_rssi
    }

    /// `rtw_fw_update_wl_phy_info`.
    pub fn phy_info(&self) -> (u32, u32) {
        let mbps = |average: u64| (average >> AVERAGE_PRECISION) as u32;
        commands::phy_info(
            mbps(self.tx_throughput),
            mbps(self.rx_throughput),
            self.tx_rate,
            self.rx_rate,
            self.evm_db,
        )
    }

    /// `rtw_phy_rrsr_update`'s mask for the peer's rate.
    pub fn response_rates(&self) -> u32 {
        response_rates(self.tx_rate)
    }

    /// `rtw_phy_cck_pd_lv`.
    fn cck_level(&self, average: u32, linked: bool) -> Option<u8> {
        let (gain, rssi) = (self.gains[0], self.min_rssi);
        if linked {
            if gain > CCK_GAINS[0] && rssi > CCK_RSSIS[0] {
                return Some(4);
            }
            if gain > CCK_GAINS[1] && rssi > CCK_RSSIS[1] {
                return Some(3);
            }
            if gain > CCK_GAINS[2] || rssi > CCK_RSSIS[2] {
                return Some(2);
            }
        }
        if average > CCK_ALARMS_RAISE {
            Some(1)
        } else if average < CCK_ALARMS_RESTORE {
            Some(0)
        } else {
            None
        }
    }

    /// `rtw_phy_cck_pd` after `alarms` false alarms on CCK.
    pub fn detect_cck<I: Io>(
        &mut self,
        io: &mut I,
        alarms: u32,
        linked: bool,
    ) -> Result<(), io::Error> {
        let average = match self.cck_average {
            Some(average) => (average * 3 + alarms) >> 2,
            None => alarms,
        };
        self.cck_average = Some(average);
        let Some(new) = self.cck_level(average, linked) else {
            return Ok(());
        };
        let paths = mask_of(io, REG_CCK_PATHS, CCK_PATHS)? as usize;
        let width = mask_of(io, REG_WIDTH, WIDTH)? as usize;
        if width > 1 || paths > 1 {
            return Ok(());
        }
        let old = self.cck_levels[width][paths];
        if old == new {
            return Ok(());
        }
        self.cck_average = None;
        let step = |levels: &[i16; 5]| levels[usize::from(new)] - levels[usize::from(old)];
        let [(detect_at, detect), (sense_at, sense)] = CCK_FIELDS[width][paths];
        let threshold = mask_of(io, detect_at, detect)?
            .wrapping_add_signed(step(&DETECT_LEVELS).into())
            .min(DETECT_MAX);
        let carrier = mask_of(io, sense_at, sense)?.wrapping_add_signed(step(&SENSE_LEVELS).into());
        let carrier = if SENSE_SKIPPED.contains(&carrier) {
            carrier + 1
        } else {
            carrier.min(SENSE_MAX)
        };
        set_mask(io, detect_at, detect, threshold)?;
        set_mask(io, sense_at, sense, carrier)?;
        self.cck_levels[width][paths] = new;
        Ok(())
    }

    /// `rtw8822c_config_trx_mode` for path A alone, or both.
    pub fn set_paths<I: Io>(io: &mut I, single: bool) -> Result<(), io::Error> {
        let both = u32::from(!single);
        let second_path = if single { 0x11111 } else { 0x33312 };
        let paths = if single { 1 } else { 3 };
        for (register, mask, value) in [
            (0x1800, 0xfffff, 0x33312),
            (0x4100, 0xfffff, second_path),
            (0x1a2c, 0x00060000, both),
            (0x1a2c, 0x00600000, both),
            (0x1a04, 0x0f000000, both),
            (0x1d30, 0x300, both),
            (0x1d30, 0x600000, both),
            (0xc44, 1 << 17, both),
            (0xc54, 1 << 20, both),
            (0xc38, 1 << 24, both),
            (0x824, 0x0f000000, paths),
            (0x824, 0x000f0000, paths),
            (0x1a04, 0xf0000000, 8),
        ] {
            set_mask(io, register, mask, value)?;
        }
        reset_baseband(io)?;
        let (antennas, legacy_mask, legacy) = if single {
            (0x11, 0xff, 0)
        } else {
            (0x31, 0xffff, 0x0400)
        };
        set_mask(io, 0x820, 0xff, antennas)?;
        set_mask(io, 0x1e2c, legacy_mask, legacy)?;
        reset_baseband(io)?;
        reset_baseband(io)?;
        // rtw8822c_toggle_igi.
        let gain = mask_of(io, 0x1d70, 0x7f)?;
        set_mask(io, 0x1d70, 0x7f, gain - 2)?;
        set_mask(io, 0x1d70, 0x7f00, gain - 2)?;
        set_mask(io, 0x1d70, 0x7f, gain)?;
        set_mask(io, 0x1d70, 0x7f00, gain)
    }

    /// `rtw_phy_tx_path_div_select`: one stream leaves by the stronger path.
    pub fn choose_path<I: Io>(&mut self, io: &mut I) -> Result<(), io::Error> {
        let mean = |path: usize| match self.path_counts[path] {
            0 => 0,
            count => self.path_sums[path] / count,
        };
        let (a, b) = (mean(0), mean(1));
        self.path_sums = [0; 2];
        self.path_counts = [0; 2];
        let path = match a.cmp(&b) {
            core::cmp::Ordering::Equal => self.tx_path,
            core::cmp::Ordering::Greater => Path::A,
            core::cmp::Ordering::Less => Path::B,
        };
        if path == self.tx_path {
            return Ok(());
        }
        self.tx_path = path;
        let (cck, map) = match path {
            Path::A => (8, 0x31),
            Path::B => (4, 0x32),
        };
        // rtw8822c_config_tx_path, with a BB reset after each half and at its end.
        set_mask(io, REG_CCK_TX, CCK_TX, cck)?;
        reset_baseband(io)?;
        set_mask(io, REG_ANTENNA_MAP, ANTENNA_MAP, map)?;
        set_mask(io, REG_LEGACY_MAP, LEGACY_MAP, ONE_STREAM_MAP)?;
        reset_baseband(io)?;
        reset_baseband(io)
    }

    /// `rtw8822c_cfo_track`, whose offset in the crystal Bluetooth shares stays
    /// the factory's while Bluetooth is on.
    pub fn track_frequency<I: Io>(
        &mut self,
        io: &mut I,
        linked: bool,
        bluetooth_off: bool,
    ) -> Result<(), io::Error> {
        let crystal = &mut self.crystal;
        if !linked {
            crystal.adjusting = true;
            let cap = crystal.cap;
            return match cap.cmp(&crystal.factory) {
                core::cmp::Ordering::Equal => Ok(()),
                core::cmp::Ordering::Greater => crystal.set(io, cap - 1),
                core::cmp::Ordering::Less => crystal.set(io, cap + 1),
            };
        }
        if crystal.packets == crystal.previous_packets {
            return Ok(());
        }
        crystal.previous_packets = crystal.packets;
        let cap = i16::from(crystal.cap);
        let offset = crystal.offset_khz();
        if !crystal.adjusting {
            crystal.adjusting = offset.abs() > OFFSET_ENABLE_KHZ;
        } else if offset.abs() <= OFFSET_STOP_KHZ {
            crystal.adjusting = false;
        }
        if !bluetooth_off {
            crystal.adjusting = false;
            crystal.set(io, crystal.factory)?;
        }
        if crystal.adjusting {
            let step = match offset {
                offset if offset > OFFSET_ADJUST_KHZ => 1,
                offset if offset < -OFFSET_ADJUST_KHZ => -1,
                _ => 0,
            };
            crystal.set(io, (cap + step).clamp(0, CRYSTAL_MAX) as u8)?;
        }
        Ok(())
    }

    /// `rtw8822c_pwr_track`: one run asks the meters, the next reads them.
    ///
    /// # Safety
    /// As [`rf::Registers::new`], with `io` and `report` the same radio's.
    pub unsafe fn track_temperature<I: Io>(
        &mut self,
        io: &mut I,
        report: &Features,
        band: Band,
    ) -> Result<(), Error> {
        let thermal = &mut self.thermal;
        if !thermal.tracked {
            return Ok(());
        }
        {
            // SAFETY: the caller's.
            let mut rf = unsafe { rf::Registers::new(io, report) }?;
            if !thermal.triggered {
                for path in [Path::A, Path::B] {
                    for bit in [1, 0, 1] {
                        rf.write(path, RF_T_METER, THERMAL_TRIGGER, bit)?;
                    }
                }
                thermal.triggered = true;
                return Ok(());
            }
            thermal.triggered = false;
            for (at, path) in [Path::A, Path::B].into_iter().enumerate() {
                if thermal.factory[at] != 0xff {
                    let reading = rf.read(path, RF_T_METER, THERMAL)?;
                    average_in(
                        &mut thermal.internal[at],
                        u64::from(reading),
                        THERMAL_WEIGHT,
                    );
                    thermal.averages[at] = (thermal.internal[at] >> AVERAGE_PRECISION) as u8;
                }
            }
            if thermal.averages[0].abs_diff(thermal.lck_reference) >= LCK_THRESHOLD {
                thermal.lck_reference = thermal.averages[0];
                thermal.lock_unsettled |= !lock_synthesizer(&mut rf)?;
            }
        }
        let (raise, lower) = swing(band, self.tx_rate <= LAST_CCK_RATE);
        for at in 0..2 {
            let index = power_index(
                thermal.averages[at],
                thermal.factory[at],
                &raise[at],
                &lower[at],
            );
            let value = index as u8 as u32;
            set_mask(io, REG_POWER_INDEX[at], POWER_INDEX, value)?;
        }
        Ok(())
    }

    /// `rtw_fw_adaptivity`'s mode, gain, threshold and density.
    pub fn adaptivity(&self) -> (u8, u8, u8, u8) {
        (
            u8::from(self.energy_threshold.is_some()),
            self.gains[0],
            self.energy_threshold.unwrap_or(0),
            self.density,
        )
    }

    /// `rtw8822c_adaptivity`: the energy that holds the channel, and frees it.
    pub fn energy_thresholds(&self) -> (u8, u8) {
        let gain = i16::from(self.gains[0]);
        let (rising, gap) = match self.energy_threshold.map(i16::from) {
            None => (
                (gain + EDCCA_GAIN_OFFSET).max(EDCCA_FLOOR),
                EDCCA_NORMAL_GAP,
            ),
            Some(threshold) if gain < threshold - EDCCA_BACKOFF => {
                (gain + EDCCA_BACKOFF, EDCCA_GAP)
            }
            Some(threshold) => (threshold, EDCCA_GAP),
        };
        (rising as u8, (rising - gap) as u8)
    }

    /// `ewma_rssi_read`.
    pub fn rssi(&self) -> u8 {
        (self.average >> AVERAGE_PRECISION) as u8
    }

    /// Whether a synthesizer lock went on before it settled, once each time.
    pub fn take_unsettled_lock(&mut self) -> bool {
        core::mem::take(&mut self.thermal.lock_unsettled)
    }

    /// `si->rssi_level`.
    pub fn level(&self) -> u8 {
        self.level
    }

    pub fn current_gain(&self) -> u8 {
        self.gains[0]
    }

    /// `rtw_phy_stat_rssi` of the peer, or of nobody.
    pub fn sample(&mut self, linked: bool) {
        self.previous_min = self.min_rssi;
        self.min_rssi = if linked {
            let (rssi, old) = (self.rssi(), usize::from(self.level));
            let floor = |at: usize| LEVELS[at] + if at >= old { LEVEL_UP_GAP } else { 0 };
            let level = (0..LEVELS.len()).find(|&at| rssi < floor(at));
            self.level = level.unwrap_or(0) as u8;
            rssi
        } else {
            u8::MAX
        };
    }

    /// A new peer's `ewma_rssi_init`, with its level.
    pub fn forget(&mut self) {
        self.average = 0;
        self.level = 0;
    }

    /// `rtw_phy_dig_check_damping`.
    fn damped(&mut self) -> bool {
        let [g0, g1, g2, g3] = self.gains;
        let [a0, a1, a2, a3] = self.alarms;
        if self.damping {
            let moved = self.min_rssi.abs_diff(self.damping_rssi) > 3;
            let expired = self.damping_count > 20;
            self.damping_count = self.damping_count.saturating_add(1);
            if moved || expired {
                self.damping = false;
                return false;
            }
            return true;
        }
        let swinging = match self.rises & 15 {
            5 => {
                g0 > g1
                    && g2 > g3
                    && g0 - g1 >= 2
                    && g2 - g3 >= 2
                    && a0 > LINKED_HIGH
                    && a1 < LINKED_LOW
                    && a2 > LINKED_HIGH
                    && a3 < LINKED_LOW
            }
            9 => {
                g0 > g1
                    && g3 > g2
                    && g0 - g1 >= 4
                    && g3 - g2 >= 2
                    && a0 > LINKED_HIGH
                    && a1 < LINKED_LOW
                    && a2 < LINKED_LOW
                    && a3 > LINKED_HIGH
            }
            _ => false,
        };
        if swinging {
            self.damping = true;
            self.damping_count = 0;
            self.damping_rssi = self.min_rssi;
        }
        swinging
    }

    /// `rtw_phy_dig`: the gain to write after `alarms` false alarms, if it moved.
    pub fn gain(&mut self, alarms: u16, linked: bool) -> Option<u8> {
        if self.damped() {
            return None;
        }
        let previous = self.gains[0];
        let (thresholds, steps) = match linked {
            true if self.previous_min > self.min_rssi => (LINKED_ALARMS, [6, 4, 2]),
            true => (LINKED_ALARMS, [4, 3, 2]),
            false => (COVERAGE_ALARMS, [4, 3, 2]),
        };
        let step = thresholds
            .into_iter()
            .zip(steps)
            .find_map(|(threshold, step)| (alarms > threshold).then_some(step))
            .unwrap_or(0);
        let (max, mid, min, floor) = if linked {
            let floor = self.min_rssi.max(LINKED_MIN);
            (LINKED_MAX, LINKED_MID, LINKED_MIN, floor)
        } else {
            (COVERAGE_MAX, COVERAGE_MID, MAX_COVERAGE, MAX_COVERAGE)
        };
        let max = max.min(floor.saturating_add(RSSI_GAIN_OFFSET));
        let lower = floor.clamp(min, mid);
        let upper = (lower + RSSI_GAIN_OFFSET).clamp(min, max);
        // Each step stands two above its meaning, so a quiet channel falls.
        let gain = previous
            .wrapping_add(step)
            .wrapping_sub(2)
            .clamp(lower, upper);
        self.rises = (self.rises << 1) | u8::from(gain > previous);
        self.gains = [gain, self.gains[0], self.gains[1], self.gains[2]];
        self.alarms = [alarms, self.alarms[0], self.alarms[1], self.alarms[2]];
        (gain != previous).then_some(gain)
    }
}

/// `rtw8822c_bb_reset`.
fn reset_baseband<I: Io>(io: &mut I) -> Result<(), io::Error> {
    let functions = io.read16(REG_FUNCTIONS)?;
    io.write16(REG_FUNCTIONS, functions | BB_RESET)?;
    io.write16(REG_FUNCTIONS, functions & !BB_RESET)?;
    io.write16(REG_FUNCTIONS, functions | BB_RESET)
}

/// `rtw_rx_stats`' and `rtw_tx_stats`' frames.
fn is_unicast_data(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|byte| byte & 0x0c == 8)
        && bytes.get(4).is_some_and(|byte| byte & 1 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::realtek::identity::{Profile, tests::profile};
    use alloc::collections::BTreeMap;

    /// Registers as words.
    #[derive(Default)]
    struct Bus(BTreeMap<u32, u32>);

    impl Bus {
        fn get(&self, register: u32) -> u32 {
            self.0.get(&register).copied().unwrap_or(0)
        }
    }

    // SAFETY: nothing here reaches hardware; this is a map of words.
    unsafe impl Io for Bus {
        fn profile(&self) -> Profile {
            profile()
        }
        fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
            Ok(self.get(register) as u8)
        }
        fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
            Ok(self.get(register) as u16)
        }
        fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
            Ok(self.get(register))
        }
        fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
            self.0.insert(register, value.into());
            Ok(())
        }
        fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
            self.0.insert(register, value.into());
            Ok(())
        }
        fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
            self.0.insert(register, value);
            Ok(())
        }
        fn delay_us(&mut self, _: u64) {}
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
            Ok(())
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            Ok(())
        }
        fn quarantine(&mut self) {}
    }

    fn at_gain(gain: u8) -> Dynamic {
        Dynamic::new(Initial {
            gains: [gain; 4],
            crystal_cap: 0x40,
            thermal: [0x20, 0x20],
            power_tracked: true,
            lck_reference: 0x20,
            dfs_region: 1,
        })
    }

    #[test]
    fn one_paths_power_comes_back_as_its_own_rssi() {
        assert_eq!(rssi(&[-50]), 50);
        assert_eq!(rssi(&[-90]), 10);
        assert_eq!(rssi(&[-100]), 1);
        assert_eq!(rssi(&[-60, -60]), 40);
    }

    #[test]
    fn a_cck_frame_corrects_its_power_by_the_gain_outside_its_bounds() {
        let mut info = [0; 4];
        // Page 0, power 70, gain 10 under a lower bound of 12.
        info[1] = 70;
        info[2] = 10;
        let signal = phy_status(&info, [30, 12], 0).unwrap();
        assert_eq!(signal.power_dbm, 70 + 4 - 110);
        assert_eq!(signal.rssi, 64);
        // Gain 34 over an upper bound of 30.
        info[2] = 34;
        assert_eq!(
            phy_status(&info, [30, 12], 0).unwrap().power_dbm,
            70 - 8 - 110
        );
    }

    #[test]
    fn an_ofdm_frame_takes_the_stronger_path_and_other_pages_say_nothing() {
        let mut info = [0; 4];
        info[0] = 1;
        info[1] = 60;
        info[2] = 70;
        assert_eq!(phy_status(&info, [0, 0], 0).unwrap().power_dbm, -40);
        info[0] = 2;
        assert_eq!(phy_status(&info, [0, 0], 0), None);
        assert_eq!(phy_status(&[1, 2], [0, 0], 0), None);
    }

    #[test]
    fn the_average_starts_at_the_first_frame_and_follows_by_sixteenths() {
        let mut dynamic = at_gain(0x2a);
        dynamic.heard(50);
        assert_eq!(dynamic.rssi(), 50);
        dynamic.heard(66);
        assert_eq!(dynamic.rssi(), 51);
        dynamic.forget();
        assert_eq!(dynamic.rssi(), 0);
    }

    #[test]
    fn a_level_rises_past_its_gap_and_falls_at_its_floor() {
        let mut dynamic = at_gain(0x2a);
        dynamic.heard(36);
        dynamic.sample(true);
        // Level 0 asks three over each floor: 36 is under 34 + 3 at index 1.
        assert_eq!(dynamic.level(), 1);
        dynamic.heard(0xff);
        for _ in 0..40 {
            dynamic.heard(60);
        }
        dynamic.sample(true);
        assert_eq!(dynamic.level(), 6);
        dynamic.forget();
        assert_eq!(dynamic.level(), 0);
    }

    #[test]
    fn a_level_keeps_some_rates_whatever_it_would_drop() {
        assert_eq!(rates_at_level(0xf_f15f, 0, false), 0xf_f15f);
        assert_eq!(rates_at_level(0xf_f15f, 5, false), 0xf_0100);
        // CCK alone is left whole, and legacy returns when nothing else stood.
        assert_eq!(rates_at_level(0xf, 5, true), 0xf);
        assert_eq!(rates_at_level(0x15, 5, false), 0x15);
    }

    #[test]
    fn responses_keep_to_the_rates_of_the_data_they_answer() {
        assert_eq!(response_rates(0), 0x1f);
        // 11 Mb/s is order three within CCK.
        assert_eq!(response_rates(3), 0x7f);
        // 6 Mb/s opens OFDM's order.
        assert_eq!(response_rates(4), 0x1f);
        assert_eq!(response_rates(0x0c), 0x1f);
        // MCS7 and VHT MCS9 of one stream.
        assert_eq!(response_rates(0x13), 0xfff);
        assert_eq!(response_rates(0x35), 0x3fff);
    }

    #[test]
    fn cck_detection_steps_its_fields_and_starts_its_average_again() {
        let mut bus = Bus::default();
        bus.0.insert(REG_CCK_PATHS, 1 << 17);
        bus.0.insert(0x1ac8, 0x1000);
        bus.0.insert(0x1ad0, 25 << 5);
        let mut dynamic = at_gain(0x30);
        dynamic.heard(30);
        dynamic.sample(true);
        // Gain over level three's and RSSI short of it: level two.
        dynamic.detect_cck(&mut bus, 0, true).unwrap();
        assert_eq!(bus.get(0x1ac8), 0x1400);
        assert_eq!(bus.get(0x1ad0), 28 << 5);
        assert_eq!(dynamic.cck_levels[0][1], 2);
        assert_eq!(dynamic.cck_average, None);
        // Linked no longer, a quiet air restores what level two added.
        dynamic.detect_cck(&mut bus, 0, false).unwrap();
        assert_eq!(bus.get(0x1ac8), 0x1000);
        assert_eq!(bus.get(0x1ad0), 26 << 5);
        // Between the two thresholds nothing moves.
        dynamic.detect_cck(&mut bus, 700, false).unwrap();
        assert_eq!(dynamic.cck_average, Some(700));
        assert_eq!(dynamic.cck_levels[0][1], 0);
    }

    #[test]
    fn one_stream_leaves_by_the_path_that_hears_better() {
        let mut bus = Bus::default();
        let mut dynamic = at_gain(0x30);
        dynamic.path_sums = [40, 90];
        dynamic.path_counts = [2, 3];
        dynamic.choose_path(&mut bus).unwrap();
        assert_eq!(dynamic.tx_path, Path::B);
        assert_eq!(bus.get(REG_CCK_TX), 4 << 28);
        assert_eq!(bus.get(REG_ANTENNA_MAP), 0x32);
        assert_eq!(bus.get(REG_LEGACY_MAP), 0x0400);
        assert_eq!(bus.get(REG_FUNCTIONS), 1);
        // A tie stays.
        bus.0.clear();
        dynamic.choose_path(&mut bus).unwrap();
        assert_eq!(dynamic.tx_path, Path::B);
        assert_eq!(bus.get(REG_ANTENNA_MAP), 0);
    }

    #[test]
    fn the_crystal_follows_the_peers_offset_and_returns_when_alone() {
        let mut bus = Bus::default();
        let mut dynamic = at_gain(0x30);
        let tail = |dynamic: &mut Dynamic, tail: i32| {
            dynamic.crystal.tails = [tail; 2];
            dynamic.crystal.counts = [1; 2];
            dynamic.crystal.packets += 1;
        };
        tail(&mut dynamic, 8);
        dynamic.track_frequency(&mut bus, true, true).unwrap();
        assert_eq!(dynamic.crystal.cap, 0x41);
        assert_eq!(bus.get(REG_CRYSTAL), (0x41 | (0x41 << 7)) << 10);
        // No new frames, nothing to go on.
        dynamic.track_frequency(&mut bus, true, true).unwrap();
        assert_eq!(dynamic.crystal.cap, 0x41);
        // Close enough: tracking stops until the offset passes 20 kHz.
        tail(&mut dynamic, 2);
        dynamic.track_frequency(&mut bus, true, true).unwrap();
        assert!(!dynamic.crystal.adjusting);
        tail(&mut dynamic, 6);
        dynamic.track_frequency(&mut bus, true, true).unwrap();
        assert!(!dynamic.crystal.adjusting);
        // Off the link it walks home a step at a time.
        dynamic.track_frequency(&mut bus, false, true).unwrap();
        assert_eq!(dynamic.crystal.cap, 0x40);
        // Bluetooth on the shared crystal holds the factory's.
        dynamic.crystal.cap = 0x48;
        tail(&mut dynamic, 8);
        dynamic.track_frequency(&mut bus, true, false).unwrap();
        assert_eq!(dynamic.crystal.cap, 0x40);
    }

    #[test]
    fn power_follows_the_temperature_from_the_factorys() {
        let (raise, lower) = swing(Band::Ghz2, false);
        assert_eq!(power_index(0x25, 0x20, &raise[0], &lower[0]), 5);
        assert_eq!(power_index(0x1b, 0x20, &raise[0], &lower[0]), -4);
        assert_eq!(power_index(0x20, 0x20, &raise[0], &lower[0]), 0);
        // The table ends, the temperature need not.
        assert_eq!(power_index(0x60, 0x20, &raise[0], &lower[0]), 27);
        let (raise, lower) = swing(Band::Ghz5, true);
        assert_eq!(raise[1][29], 27);
        assert_eq!(lower[1][29], 32);
        assert_eq!(swing(Band::Ghz2, true).0[1][29], 29);
    }

    #[test]
    fn energy_detection_follows_the_gain_or_the_rules() {
        let mut dynamic = at_gain(0x24);
        assert_eq!(dynamic.energy_thresholds(), (48, 40));
        dynamic.gains[0] = 0x40;
        assert_eq!(dynamic.energy_thresholds(), (72, 64));
        assert_eq!(dynamic.adaptivity(), (0, 0x40, 0, 0));
        // ETSI's 45 stands from gain 33 up, and backs off below.
        dynamic.energy_threshold = Some(EDCCA_ETSI);
        assert_eq!(dynamic.energy_thresholds(), (45, 38));
        dynamic.gains[0] = 0x20;
        assert_eq!(dynamic.energy_thresholds(), (44, 37));
        dynamic.reported(&Report::Density(9));
        assert_eq!(dynamic.adaptivity(), (1, 0x20, 45, 9));
    }

    #[test]
    fn frames_feed_the_link_only_from_its_bss() {
        const LOCAL: Mac = Mac([2; 6]);
        const AP: Mac = Mac([3; 6]);
        let frame = |subtype: u8, to: Mac, from: Mac| {
            let mut bytes = alloc::vec![subtype, 0, 0, 0];
            bytes.extend_from_slice(&to.0);
            bytes.extend_from_slice(&from.0);
            bytes
        };
        let signal = Signal {
            rssi: 50,
            power_dbm: -50,
            ofdm: Some(Ofdm {
                rate: 0x10,
                paths: [50, 40],
                tails: [4, -2],
                evm_db: 6,
            }),
        };
        let mut dynamic = at_gain(0x30);
        dynamic.frame(&frame(0x88, LOCAL, Mac([9; 6])), Some(signal), LOCAL, AP);
        assert_eq!(dynamic.rssi(), 0);
        assert_eq!(dynamic.crystal.packets, 0);
        assert_eq!(dynamic.path_counts, [1; 2]);
        assert_eq!(dynamic.rx_bytes, 16);
        dynamic.frame(&frame(0x88, LOCAL, AP), Some(signal), LOCAL, AP);
        assert_eq!(dynamic.rssi(), 50);
        assert_eq!(dynamic.crystal.tails, [4, -2]);
        assert_eq!(dynamic.rx_rate, 0x10);
        // A beacon counts though it names nobody; a control frame adds no tail.
        let group = Mac([0xff; 6]);
        dynamic.frame(&frame(0x80, group, AP), Some(signal), LOCAL, AP);
        assert_eq!(dynamic.crystal.packets, 2);
        dynamic.frame(&frame(0xd4, LOCAL, AP), Some(signal), LOCAL, AP);
        assert_eq!(dynamic.crystal.packets, 2);
    }

    #[test]
    fn a_periods_bytes_become_averaged_megabits() {
        let mut dynamic = at_gain(0x30);
        dynamic.tx_bytes = 8 << MBPS_SHIFT;
        dynamic.close_period();
        assert_eq!(dynamic.phy_info().0 >> 8 & 0x3ff, 8);
        dynamic.close_period();
        assert_eq!(dynamic.phy_info().0 >> 8 & 0x3ff, 4);
    }

    #[test]
    fn false_alarms_raise_the_gain_within_what_the_peers_signal_allows() {
        let mut dynamic = at_gain(0x30);
        dynamic.heard(0x30);
        dynamic.sample(true);
        assert_eq!(dynamic.gain(800, true), Some(0x32));
        assert_eq!(dynamic.gain(0, true), Some(0x30));
        let mut dynamic = at_gain(0x60);
        dynamic.heard(10);
        dynamic.sample(true);
        assert_eq!(dynamic.gain(0, true), Some(0x2f));
    }

    #[test]
    fn unlinked_gain_stays_in_the_coverage_range() {
        let mut dynamic = at_gain(0x20);
        dynamic.sample(false);
        assert_eq!(dynamic.gain(6000, false), Some(0x22));
        for _ in 0..8 {
            dynamic.gain(0, false);
        }
        assert_eq!(dynamic.current_gain(), MAX_COVERAGE);
    }

    #[test]
    fn one_stream_stands_on_path_a_and_two_come_back() {
        let mut bus = Bus(BTreeMap::new());
        bus.write32(0x1d70, 0x2020).unwrap();
        Dynamic::set_paths(&mut bus, true).unwrap();
        assert_eq!(bus.get(0x4100) & 0xfffff, 0x11111);
        assert_eq!(bus.get(0x820) & 0xff, 0x11);
        assert_eq!(bus.get(0x824), 0x0101_0000);
        assert_eq!(bus.get(0x1d70), 0x2020, "the gain toggled back");
        Dynamic::set_paths(&mut bus, false).unwrap();
        assert_eq!(bus.get(0x4100) & 0xfffff, 0x33312);
        assert_eq!(bus.get(0x820) & 0xff, 0x31);
        assert_eq!(bus.get(0x1e2c) & 0xffff, 0x0400);
        assert_eq!(bus.get(0x824), 0x0303_0000);
    }

    /// A radio whose synthesizer lock stays busy or not, counting its delays.
    struct Synthesizer {
        bus: Bus,
        busy: bool,
        delays: usize,
    }

    // SAFETY: nothing here reaches hardware; this is a map of words.
    unsafe impl Io for Synthesizer {
        fn profile(&self) -> Profile {
            profile()
        }
        fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
            self.bus.read8(register)
        }
        fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
            self.bus.read16(register)
        }
        fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
            let value = self.bus.read32(register)?;
            let lock = 0x3c00 + u32::from(RF_AAC_CTRL) * 4;
            Ok(if register == lock && self.busy {
                value | 0x1000
            } else {
                value
            })
        }
        fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
            self.bus.write8(register, value)
        }
        fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
            self.bus.write16(register, value)
        }
        fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
            self.bus.write32(register, value)
        }
        fn delay_us(&mut self, microseconds: u64) {
            if microseconds == LCK_POLL_US {
                self.delays += 1;
            }
        }
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
            Ok(())
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            Ok(())
        }
        fn quarantine(&mut self) {}
    }

    #[test]
    fn a_synthesizer_lock_waits_20_ms_at_most_and_says_whether_it_settled() {
        use crate::wifi::realtek::registers::{
            FW_READY, REG_MCUFW_CTRL, REG_RF_CTRL, REG_SYS_CFG1, REG_SYS_FUNC_EN, REG_WLRF1,
        };
        for busy in [false, true] {
            let mut bus = Bus::default();
            bus.0.insert(REG_SYS_CFG1, profile().observed().sys_cfg1);
            bus.0.insert(REG_MCUFW_CTRL, FW_READY.into());
            bus.0.insert(REG_SYS_FUNC_EN, 3);
            bus.0.insert(REG_RF_CTRL, 7);
            bus.0.insert(REG_WLRF1, 0x0700_0000);
            let mut radio = Synthesizer {
                bus,
                busy,
                delays: 0,
            };
            let report = Features::of_two_paths(profile());
            // SAFETY: the model radio belongs to this test alone.
            let mut rf = unsafe { rf::Registers::new(&mut radio, &report) }.unwrap();
            assert_eq!(lock_synthesizer(&mut rf).unwrap(), !busy);
            drop(rf);
            assert_eq!(radio.delays, if busy { LCK_POLLS } else { 1 });
            // The lock ends as rtw88 ends it, settled or not.
            let fast = 0x3c00 + u32::from(RF_FAST_LCK) * 4;
            assert_eq!(radio.bus.get(fast) & RF_WHOLE, 0x0f000);
        }
    }

    #[test]
    fn a_gain_swinging_with_its_alarms_is_left_alone_until_the_signal_moves() {
        let mut dynamic = at_gain(0x24);
        dynamic.heard(0x24);
        dynamic.sample(true);
        dynamic.rises = 5;
        dynamic.gains = [0x28, 0x24, 0x28, 0x24];
        dynamic.alarms = [600, 100, 600, 100];
        assert_eq!(dynamic.gain(800, true), None);
        assert_eq!(dynamic.gain(800, true), None);
        for _ in 0..3 {
            dynamic.heard(100);
        }
        dynamic.sample(true);
        assert!(dynamic.gain(800, true).is_some());
    }
}
