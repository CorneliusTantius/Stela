// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! What rtw88 keeps per chip in `rtw_chip_info`: one [`Spec`] a chip, which
//! the shared layers read instead of naming a chip. A chip's own operations
//! (rtw88's `rtw_chip_ops`) sit in the modules [`Spec::rtw88`] names.
use super::{identity::Chip, power::Step};
pub mod rtl8821c;

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
    /// `rtw_pci_interface_cfg`: the cut from which `REG_HCI_MIX_CFG` takes
    /// `BIT_PCIE_EMAC_PDN_AUX_TO_FAST_CLK`, on a chip that sets it.
    pub pcie_aux_clock_cut: Option<u8>,
    /// `pcie_gen1_param`'s PHY (MDIO) writes for every cut: address, value.
    pub pcie_gen1_mdio: &'static [(u8, u16)],
    /// The RFE `rtw_pci_phy_cfg` raises the switcher's current for.
    pub switcher_current_rfe: Option<u8>,
    /// The radios `rf_tbl` loads: two on the RTL8822C, path A alone on the
    /// RTL8821C.
    pub rf_paths: u8,
    /// The RFE options `rfe_defs` defines, the boards the chip's tables know.
    pub rfe_options: &'static [u8],
    /// `rf_base_addr` and `rf_sipi_addr` of paths A and B.
    pub rf_base: [u32; 2],
    pub rf_sipi: [u32; 2],
    /// `write_rf`.
    pub rf_write: RfWrite,
    /// `txgi_factor`: TX power index steps a half dB holds.
    pub txgi_factor: u8,
    /// `max_power_index`.
    pub max_power_index: u8,
    /// `is_pwr_by_rate_dec`: by-rate tables hold BCD.
    pub power_by_rate_bcd: bool,
    /// `en_dis_dpd`: the rates sent without predistortion lose 3 dB.
    pub dpd_rates: bool,
    /// How `set_tx_power_index` writes the rates' indices.
    pub txagc: Txagc,
    /// `dig`: each path's initial gain field, register and mask.
    pub dig: &'static [(u32, u32)],
    /// `dig_min`: the lowest gain `rtw_phy_dig` sets while linked.
    pub dig_min: u8,
    /// `lps_deep_mode_supported`'s `LPS_DEEP_MODE_PG`: the chip may gate
    /// its power in deep power save, not only lower its clock.
    pub lps_deep_power_gate: bool,
}

/// A chip's `set_tx_power_index`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Txagc {
    /// `rtw8822c_set_tx_power_index`: each path's CCK and OFDM reference,
    /// and every rate as its difference from them, both paths in one word.
    Differential,
    /// `rtw8821c_set_tx_power_index`: each rate's index, four to a word,
    /// from each path's base.
    Absolute { base: [u32; 2] },
}

/// A chip's `write_rf`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RfWrite {
    /// `rtw_phy_write_rf_reg_mix`: address 0 through SIPI, the rest direct.
    Mix,
    /// `rtw_phy_write_rf_reg_sipi`: every address through SIPI.
    Sipi,
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
        pcie_aux_clock_cut: Some(3),
        pcie_gen1_mdio: &[],
        switcher_current_rfe: Some(5),
        rf_paths: 2,
        rfe_options: &[0, 1, 2, 3, 4, 5, 6],
        rf_base: [0x3c00, 0x4c00],
        rf_sipi: [0x1808, 0x4108],
        rf_write: RfWrite::Mix,
        txgi_factor: 2,
        max_power_index: 0x7f,
        power_by_rate_bcd: false,
        dpd_rates: true,
        txagc: Txagc::Differential,
        dig: &[(0x1d70, 0x7f), (0x1d70, 0x7f00)],
        dig_min: 0x20,
        lps_deep_power_gate: true,
    }),
};

/// `rtw8821c_hw_spec`.
pub static RTL8821C: Spec = Spec {
    chip: Chip::Rtl8821C,
    devices: &[0xb821, 0xc821],
    binding: "pci:10ec:c821",
    firmware: "rtw88/rtw8821c_fw.bin",
    firmware_minimum: 64,
    refuses_test_chip: true,
    rtw88: Some(Rtw88 {
        efuse: EfuseSize {
            physical: 512,
            protected: 96,
            logical: 512,
        },
        // `REG_LDO_EFUSE_CTRL + 3`'s `BIT_LDO25_EN`.
        ldo25: (super::registers::REG_LDO_EFUSE_CTRL + 3, 1 << 7),
        txff_bytes: 65_536,
        rxff_bytes: 16_384,
        driver_pages: 8,
        csi_pages: 0,
        page_table: PageTable {
            high: 16,
            normal: 16,
            low: 16,
            extra: 14,
            gap: 1,
        },
        queue_map: QUEUE_MAP,
        sys_func_en: 0xd8,
        power_on: super::power::tables::ON_8821C,
        power_off: super::power::tables::OFF_8821C,
        pcie_aux_clock_cut: None,
        pcie_gen1_mdio: &[(0x09, 0x6380)],
        switcher_current_rfe: None,
        rf_paths: 1,
        rfe_options: &[0, 2, 4, 6],
        rf_base: [0x2800, 0x2c00],
        rf_sipi: [0xc90, 0xe90],
        rf_write: RfWrite::Sipi,
        txgi_factor: 1,
        max_power_index: 0x3f,
        power_by_rate_bcd: true,
        dpd_rates: false,
        txagc: Txagc::Absolute {
            base: [0x1d00, 0x1d80],
        },
        dig: &[(0xc50, 0x7f)],
        dig_min: 0x1c,
        lps_deep_power_gate: false,
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
pub static SPECS: [&Spec; 3] = [&RTL8822C, &RTL8821C, &RTL8852B];

impl Chip {
    pub fn spec(self) -> &'static Spec {
        match self {
            Chip::Rtl8822C => &RTL8822C,
            Chip::Rtl8821C => &RTL8821C,
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
        for spec in [&RTL8822C, &RTL8821C] {
            let map = spec.rtw88.as_ref().unwrap().queue_map_register();
            assert_eq!(map, 3 << 14 | 1 << 10 | 1 << 8 | 2 << 6 | 2 << 4);
        }
    }
}
