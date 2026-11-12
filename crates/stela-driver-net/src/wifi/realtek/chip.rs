// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! What rtw88 keeps per chip in `rtw_chip_info`: one [`Spec`] a chip, which
//! the shared layers read instead of naming a chip. A chip's own operations
//! (rtw88's `rtw_chip_ops`) sit in the modules [`Spec::rtw88`] names.
use super::{identity::Chip, power::Step};

/// `rtw_chip_info`, as far as this driver reads it.
#[derive(Debug)]
pub struct Spec {
    pub chip: Chip,
    /// The PCI device IDs of rtw88's or rtw89's PCI table for the chip.
    pub devices: &'static [u16],
    /// The hardware of the chip's firmware binding ([`super::identity::Profile::chip_target`]).
    pub binding: &'static str,
    /// `fw_name`.
    pub firmware: &'static str,
    /// The smallest image the firmware parser takes.
    pub firmware_minimum: usize,
    /// rtw88's `BIT_RTL_ID`: non-production silicon wants other firmware.
    pub refuses_test_chip: bool,
    /// The facts of an rtw88 chip; `None` for a chip only staged here.
    pub rtw88: Option<Rtw88>,
}

/// The `rtw_chip_info` of an rtw88 chip.
#[derive(Debug)]
pub struct Rtw88 {
    /// `phy_efuse_size`, `ptct_efuse_size` and `log_efuse_size`.
    pub efuse: EfuseSize,
    /// `cfg_ldo25`: the byte and bit that power the 2.5 V efuse LDO.
    pub ldo25: (u32, u8),
    /// `txff_size` and `rxff_size`, in bytes.
    pub txff_bytes: u32,
    pub rxff_bytes: u32,
    /// `rsvd_drv_pg_num` and `csi_buf_pg_num`.
    pub driver_pages: u16,
    pub csi_pages: u16,
    /// `page_table[1]`, the PCIe row.
    pub page_table: PageTable,
    /// `rqpn_table[1]`, the PCIe row: VO, VI, BE, BK, MG, HI.
    pub queue_map: [Mapping; 6],
    /// `sys_func_en`.
    pub sys_func_en: u8,
    /// `pwr_on_seq` and `pwr_off_seq`.
    pub power_on: [&'static [Step]; 2],
    pub power_off: [&'static [Step]; 2],
}

/// Efuse sizes in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EfuseSize {
    pub physical: usize,
    pub protected: usize,
    pub logical: usize,
}

/// `rtw_page_table`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTable {
    pub high: u16,
    pub normal: u16,
    pub low: u16,
    pub extra: u16,
    pub gap: u16,
}

/// `rtw_dma_mapping`, in `REG_TXDMA_PQ_MAP`'s encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Mapping {
    Extra = 0,
    Low = 1,
    Normal = 2,
    High = 3,
}

const QUEUE_MAP: [Mapping; 6] = [
    Mapping::Normal,
    Mapping::Normal,
    Mapping::Low,
    Mapping::Low,
    Mapping::Extra,
    Mapping::High,
];

/// `rtw8822c_hw_spec`.
pub static RTL8822C: Spec = Spec {
    chip: Chip::Rtl8822C,
    devices: &[0xc822, 0xc82f],
    binding: "pci:10ec:c822",
    firmware: "rtw88/rtw8822c_fw.bin",
    firmware_minimum: 64,
    refuses_test_chip: true,
    rtw88: Some(Rtw88 {
        efuse: EfuseSize {
            physical: 512,
            protected: 124,
            logical: 768,
        },
        ldo25: (
            super::registers::REG_ANAPARLDO_POW_MAC,
            super::registers::BIT_LDOE25_PON,
        ),
        txff_bytes: 262_144,
        rxff_bytes: 24_576,
        driver_pages: 16,
        csi_pages: 50,
        page_table: PageTable {
            high: 64,
            normal: 64,
            low: 64,
            extra: 64,
            gap: 1,
        },
        queue_map: QUEUE_MAP,
        sys_func_en: 0xd8,
        power_on: super::power::tables::ON_8822C,
        power_off: super::power::tables::OFF_8822C,
    }),
};

/// rtw89's RTL8852B, whose firmware layout alone is known here.
pub static RTL8852B: Spec = Spec {
    chip: Chip::Rtl8852B,
    devices: &[0xb852, 0xb85b],
    binding: "pci:10ec:b852",
    firmware: "rtw89/rtw8852b_fw-2.bin",
    firmware_minimum: 32,
    refuses_test_chip: false,
    rtw88: None,
};

/// Every chip, in the order PCI IDs are matched.
pub static SPECS: [&Spec; 2] = [&RTL8822C, &RTL8852B];

impl Chip {
    pub fn spec(self) -> &'static Spec {
        match self {
            Chip::Rtl8822C => &RTL8822C,
            Chip::Rtl8852B => &RTL8852B,
        }
    }
}

impl Rtw88 {
    /// `REG_TXDMA_PQ_MAP`'s value for [`Self::queue_map`].
    pub fn queue_map_register(&self) -> u16 {
        let [vo, vi, be, bk, mg, hi] = self.queue_map.map(|m| m as u16);
        hi << 14 | mg << 12 | bk << 10 | be << 8 | vi << 6 | vo << 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_chip_is_its_own_spec_and_ids_do_not_overlap() {
        for spec in SPECS {
            assert_eq!(spec.chip.spec().chip, spec.chip);
            for other in SPECS {
                if !core::ptr::eq(spec, other) {
                    assert!(spec.devices.iter().all(|d| !other.devices.contains(d)));
                }
            }
        }
    }

    #[test]
    fn the_pcie_queue_map_is_rtw88s() {
        // VO and VI normal, BE and BK low, MG extra, HI high.
        let map = RTL8822C.rtw88.as_ref().unwrap().queue_map_register();
        assert_eq!(map, 3 << 14 | 1 << 10 | 1 << 8 | 2 << 6 | 2 << 4);
    }
}
