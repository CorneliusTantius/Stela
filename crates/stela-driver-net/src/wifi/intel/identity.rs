// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2015-2017 Intel Deutschland GmbH
// Copyright (C) 2018-2026 Intel Corporation
//! Exact PCIe AX200/AX201/AX210/AX211/BE200/BE201 firmware selection from
//! cfg/{22000,ax210,bz,sc,rf-hr,rf-gf,rf-fm}.c, pcie/drv.c,
//! iwl_drv_get_fwname_pre and get_crf_id at the pinned Linux source revision.
//! These are observed identity records, not permission to program PCI or DMA.
use super::{
    firmware::{self, Family, Firmware},
    mcc::channel::Inventory,
    power::Silicon,
};
use crate::firmware as resources;
use alloc::{boxed::Box, format, string::String};

const INTEL: u16 = 0x8086;
const AX200: u16 = 0x2723;
const AX210: u16 = 0x2725;
const MAC_QU: u32 = 0x33;
const MAC_CC: u32 = 0x34;
const MAC_QUZ: u32 = 0x35;
const MAC_SO: u32 = 0x37;
const MAC_TY: u32 = 0x42;
const MAC_SOF: u32 = 0x43;
const MAC_MA: u32 = 0x44;
const MAC_BZ: u32 = 0x46;
const MAC_GL: u32 = 0x47;
const MAC_SC: u32 = 0x48;
const MAC_BZ_W: u32 = 0x4b;
const BE200: u16 = 0x272b;
/// The subdevices `iwl_hw_card_ids` lists for this device id.
const BZ_SUBDEVICES: [u16; 35] = [
    0x0000, 0x0090, 0x0094, 0x0098, 0x009c, 0x00c0, 0x00c4, 0x00e0, 0x00e4, 0x00e8, 0x00ec, 0x0100,
    0x0110, 0x0114, 0x0118, 0x011c, 0x0310, 0x0314, 0x0510, 0x0a10, 0x1671, 0x1672, 0x1771, 0x1772,
    0x1791, 0x1792, 0x4090, 0x40c4, 0x40e0, 0x4110, 0x4314, 0x1775, 0x1776, 0x1735, 0x1736,
];
const BZ_LISTED: u16 = 0xa840;
/// The Killer BE1730x and BE1735x, which pcie/drv.c holds to 160 MHz
/// (`iwl_rf_fm_160mhz`, `iwl_rf_wh_160mhz`) by subdevice alone.
const KILLER_1730: u16 = 0x1730;
const KILLER_1731: u16 = 0x1731;
const KILLER_1735: u16 = 0x1735;
const KILLER_1736: u16 = 0x1736;
/// The Killer AX1650s and AX1650i, AX201 products whose subdevices carry
/// the bandwidth-limit bit; pcie/drv.c names them after AX203, so they win.
const KILLER_1650S: u16 = 0x1651;
const KILLER_1650I: u16 = 0x1652;
const RF_HR2: u32 = 0x10a;
const RF_GF: u32 = 0x10d;
const RF_FM: u32 = 0x112;
const CDB: u32 = 1 << 28;
/// `REG_CRF_ID_TYPE`s of the admitted radios, for a blank OTP.
const CRF_HR2: u32 = 0x504;
/// `REG_CRF_ID_TYPE_HR_CDB`, an HR2 that is CDB only if the WFPM or the
/// slave bit says so.
const CRF_HR2_CDB: u32 = 0x503;
const CRF_GF: u32 = 0x410;
const CRF_FM: u32 = 0x910;
/// CNVI_AUX_MISC_CHIP_PROD_TYPE_BZ_U.
const BZ_U: u32 = 0x930;
/// `PCI_EXP_LNKSTA_CLS_8_0GB`.
const SPEED_8GT: u8 = 3;
/// `IWL_PNVM_REDUCED_CAP_BIT` of ALIVE's first SKU word.
const REDUCED_CAPABILITY: u32 = 1 << 25;
/// `IWL_SUBDEVICE_BW_LIM`, which makes an integrated HR2 an 80 MHz AX203.
const BANDWIDTH_LIMITED: u16 = 0x0200;
/// The subdevice of AX231, whose radio configuration is not GF's.
const AX231: u16 = 0x0294;
const STEP_A: u32 = 0;
const STEP_B: u32 = 1;
const STEP_C: u32 = 2;

/// The radio beside a MAC. It, not the MAC's family, decides the channel
/// table and part of the PHY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rf {
    Hr,
    Gf,
    Fm,
}

/// What `iwl_nvm_fixup_sband_iftd` reads of a device whose radio has EHT.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EhtLimits {
    /// `bw_limit` of `iwl_rf_fm_160mhz`: BE202 and the Killer BE1730x.
    pub stops_at_160: bool,
    /// `reduced_cap_sku`, which also drops 320 MHz and MCS 12 and 13.
    pub reduced: bool,
    /// `step_urm`: the STEP has no MCS above 9 at 320 MHz.
    pub urm: bool,
    /// `slow_pcie`: a discrete link under 8 GT/s cannot carry two streams of
    /// MCS above 9 at 320 MHz.
    pub slow_bus: bool,
    /// CSR_HW_RFID_IS_CDB: two radios, which `iwl_mld_vif_has_emlsr_cap` keeps
    /// out of EMLSR.
    pub dual_radio: bool,
}

impl EhtLimits {
    pub const fn reaches_320(self) -> bool {
        !self.stops_at_160 && !self.reduced
    }
}

/// What a device's `iwl_mac_cfg` says of the platform around its MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Platform {
    pub integrated: bool,
    /// `xtal_latency`, in microseconds.
    pub xtal_latency: u32,
    pub low_latency_xtal: bool,
    /// `ltr_delay`, which `SOC_FLAGS_LTR_APPLY_DELAY` encodes the same way.
    pub ltr_delay: u32,
    /// `imr_enabled`.
    pub imr: bool,
}

impl Platform {
    pub const AX200: Self = Self::discrete(0);
    pub const AX210: Self = Self::discrete(500);
    pub const BE200: Self = Self {
        low_latency_xtal: true,
        ..Self::discrete(12000)
    };
    const LTR_200US: u32 = 1;
    const LTR_2500US: u32 = 2;
    const LTR_1820US: u32 = 3;

    const fn discrete(xtal_latency: u32) -> Self {
        Self {
            integrated: false,
            xtal_latency,
            low_latency_xtal: false,
            ltr_delay: 0,
            imr: false,
        }
    }
    const fn integrated(xtal_latency: u32, ltr_delay: u32) -> Self {
        Self {
            integrated: true,
            xtal_latency,
            low_latency_xtal: false,
            ltr_delay,
            imr: false,
        }
    }
    const fn long_latency() -> Self {
        Self {
            low_latency_xtal: true,
            ..Self::integrated(12000, Self::LTR_2500US)
        }
    }
    /// `iwl_set_soc_latency`'s flags, for firmware with UMAC scan version 2
    /// or later as every admitted image has.
    pub const fn soc_flags(self) -> u32 {
        !self.integrated as u32 | (self.low_latency_xtal as u32) << 1 | self.ltr_delay << 2
    }
}

/// `bisr_workaround`, set for the standalone AX200 alone.
pub const fn bisr_workaround(device: u16) -> bool {
    device == AX200
}

/// `iwl_hw_card_ids` for the admitted families.
pub const fn device(id: u16) -> Option<(Family, Platform)> {
    Some(match id {
        AX200 => (Family::Ax200, Platform::AX200),
        AX210 => (Family::Ax210, Platform::AX210),
        0x02f0 | 0x06f0 => (
            Family::Ax200,
            Platform::integrated(500, Platform::LTR_200US),
        ),
        0x34f0 | 0x3df0 | 0x4df0 => (
            Family::Ax200,
            Platform::integrated(1820, Platform::LTR_1820US),
        ),
        0x43f0 | 0xa0f0 => (Family::Ax200, Platform::long_latency()),
        0x7af0 | 0x7f70 => (
            Family::Ax210,
            Platform::integrated(500, Platform::LTR_200US),
        ),
        0x51f0 | 0x54f0 => (Family::Ax210, Platform::long_latency()),
        0x7a70 | 0x51f1 => (
            Family::Ax210,
            Platform {
                imr: true,
                ..Platform::long_latency()
            },
        ),
        0x2729 | 0x7e40 => (Family::Ax210, Platform::integrated(0, 0)),
        BE200 => (Family::Bz, Platform::BE200),
        BZ_LISTED | 0x7740 | 0x4d40 => (Family::Bz, Platform::long_latency()),
        0xe440 | 0xe340 | 0xd340 | 0x6e70 | 0xd240 => (Family::Sc, Platform::long_latency()),
        _ => return None,
    })
}

/// `iwl_drv_get_fwname_pre` at the API `cfg/` asks for, with the PNVM Linux
/// finds beside the image.
fn images(
    mac: u32,
    step: u32,
    radio: u32,
    radio_step: u32,
) -> Option<(&'static str, Option<&'static str>)> {
    const TY: &str = "iwlwifi-ty-a0-gf-a0.pnvm";
    const SO: &str = "iwlwifi-so-a0-gf-a0.pnvm";
    const MA: &str = "iwlwifi-ma-b0-gf-a0.pnvm";
    const BZ: &str = "iwlwifi-bz-b0-fm-c0.pnvm";
    const GL: &str = "iwlwifi-gl-c0-fm-c0.pnvm";
    if radio == RF_FM {
        return Some(match (mac, step, radio_step) {
            (MAC_BZ | MAC_BZ_W, STEP_B, STEP_C) => ("iwlwifi-bz-b0-fm-c0-c106.ucode", Some(BZ)),
            (MAC_GL, STEP_C, STEP_C) => ("iwlwifi-gl-c0-fm-c0-c106.ucode", Some(GL)),
            (MAC_SC, STEP_A, STEP_C) => ("iwlwifi-sc-a0-fm-c0-c106.ucode", None),
            _ => return None,
        });
    }
    Some(match (mac, step, radio) {
        (MAC_CC, _, RF_HR2) => ("iwlwifi-cc-a0-77.ucode", None),
        (MAC_QU, STEP_B, RF_HR2) => ("iwlwifi-Qu-b0-hr-b0-77.ucode", None),
        (MAC_QU, STEP_C, RF_HR2) => ("iwlwifi-Qu-c0-hr-b0-77.ucode", None),
        (MAC_QUZ, _, RF_HR2) => ("iwlwifi-QuZ-a0-hr-b0-77.ucode", None),
        (MAC_SO | MAC_SOF, _, RF_HR2) => ("iwlwifi-so-a0-hr-b0-89.ucode", None),
        (MAC_MA, STEP_B, RF_HR2) => ("iwlwifi-ma-b0-hr-b0-89.ucode", None),
        (MAC_TY, _, RF_GF) => ("iwlwifi-ty-a0-gf-a0-89.ucode", Some(TY)),
        (MAC_SO | MAC_SOF, _, RF_GF) => ("iwlwifi-so-a0-gf-a0-89.ucode", Some(SO)),
        (MAC_MA, STEP_B, RF_GF) => ("iwlwifi-ma-b0-gf-a0-89.ucode", Some(MA)),
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observed {
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub pci_revision: u8,
    /// PCI_EXP_LNKSTA's current speed, or zero without PCI Express.
    pub link_speed: u8,
    /// CSR_HW_REV and CSR_HW_RF_ID values, before normalization.
    pub hardware_revision: u32,
    pub radio_id: u32,
    /// What the early NIC access found behind those.
    pub silicon: Silicon,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    UnsupportedPci,
    FailedRead,
    UnsupportedMac(u32),
    UnsupportedRadio(u32),
    /// No firmware is released for this MAC or radio step.
    UnsupportedStep(u32),
}

/// A plain account, with the registers iwlwifi identifies by in hex.
impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedPci => f.write_str("its PCI ID is not one iwlwifi lists"),
            Self::FailedRead => f.write_str("its CSR_HW_REV or CSR_HW_RF_ID reads all ones"),
            Self::UnsupportedMac(revision) => {
                write!(f, "its MAC (CSR_HW_REV {revision:#010x}) is unsupported")
            }
            Self::UnsupportedRadio(radio) => {
                write!(f, "its radio (CSR_HW_RF_ID {radio:#010x}) is unsupported")
            }
            Self::UnsupportedStep(step) => {
                write!(f, "no firmware is released for its step {step:#x}")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    observed: Observed,
    family: Family,
    platform: Platform,
    radio: Rf,
    revision: u32,
    firmware: &'static str,
    pnvm: Option<&'static str>,
    scu_force_active: bool,
    /// [`EhtLimits::stops_at_160`].
    stops_at_160: bool,
}

/// The system vendors `dmi_force_scu_active_approved_list` names.
const SCU_FORCE_ACTIVE_VENDORS: [&str; 2] = ["Dell Inc.", "Alienware"];

/// Whether `iwl_pci_find_dev_info` holds an FM radio to 160 MHz. It takes
/// the last entry of pcie/drv.c that matches, so the Killer subdevices,
/// listed after BE202, decide before the bandwidth-limit bit they also carry.
const fn fm_stops_at_160(device: u16, subdevice: u16) -> bool {
    match subdevice {
        KILLER_1730 | KILLER_1731 | KILLER_1735 | KILLER_1736 => true,
        0x1771 | 0x1772 | 0x1775 | 0x1776 | 0x1791 | 0x1792 => false,
        0x1773 | 0x1774 if device == BE200 => false,
        // BE202 (`iwl_rf_fm_160mhz`).
        _ => subdevice & BANDWIDTH_LIMITED != 0,
    }
}

/// CSR_HW_RF_ID, or `map_crf_id`'s reading of the silicon on a blank OTP.
fn radio_id(observed: Observed) -> Result<u32, IdentityError> {
    if observed.radio_id & 0x00ff_f000 != 0 {
        return Ok(observed.radio_id);
    }
    let Silicon { crf, wfpm, .. } = observed.silicon;
    let radio = match crf & 0xfff {
        CRF_HR2 | CRF_HR2_CDB => RF_HR2,
        CRF_GF => RF_GF,
        CRF_FM => RF_FM,
        _ => return Err(IdentityError::UnsupportedRadio(crf)),
    };
    let step = (crf >> 24) & 0xf;
    let cdb = wfpm & (1 << 4) != 0 || crf & (1 << 19) != 0;
    Ok(radio << 12 | step << 8 | if cdb { CDB } else { 0 })
}

impl Profile {
    pub fn select(observed: Observed) -> Result<Self, IdentityError> {
        if observed.vendor != INTEL {
            return Err(IdentityError::UnsupportedPci);
        }
        let (family, platform) = device(observed.device).ok_or(IdentityError::UnsupportedPci)?;
        if observed.hardware_revision == u32::MAX || observed.radio_id == u32::MAX {
            return Err(IdentityError::FailedRead);
        }
        let radio_id = radio_id(observed)?;
        let mac = (observed.hardware_revision & 0xfff0) >> 4;
        let radio = (radio_id & 0x00ff_f000) >> 12;
        let macs: &[u32] = match observed.device {
            AX200 => &[MAC_CC],
            AX210 => &[MAC_TY],
            BE200 => &[MAC_GL],
            _ if family == Family::Ax200 => &[MAC_QU, MAC_QUZ],
            _ if family == Family::Ax210 => &[MAC_SO, MAC_SOF, MAC_MA],
            _ if family == Family::Bz => &[MAC_BZ, MAC_BZ_W],
            _ => &[MAC_SC],
        };
        if !macs.contains(&mac) {
            return Err(IdentityError::UnsupportedMac(mac));
        }
        let fitted = match radio {
            RF_HR2 => mac != MAC_TY,
            RF_GF => family == Family::Ax210,
            RF_FM => family >= Family::Bz,
            _ => false,
        };
        let limited = observed.subsystem_device & BANDWIDTH_LIMITED != 0;
        let another_product = match radio {
            RF_HR2 => {
                platform.integrated
                    && limited
                    && !matches!(observed.subsystem_device, KILLER_1650S | KILLER_1650I)
            }
            RF_GF => platform.integrated && observed.subsystem_device == AX231,
            _ => false,
        };
        if !fitted || another_product || radio_id & CDB != 0 {
            // A CDB radio chooses a distinct gf4 image or is BE401, and AX203
            // and AX231 have their own configurations. Each needs its own
            // complete profile before admission.
            return Err(IdentityError::UnsupportedRadio(radio_id));
        }
        if observed.device == BZ_LISTED && !BZ_SUBDEVICES.contains(&observed.subsystem_device) {
            return Err(IdentityError::UnsupportedPci);
        }
        let step = match mac {
            // `get_crf_id`: these MACs keep their step in the CNVi.
            MAC_BZ_W => STEP_B,
            MAC_BZ => match (observed.silicon.cnv >> 24) & 0xf {
                STEP_A if observed.silicon.cnv & 0xfff == BZ_U => STEP_B,
                step => step,
            },
            _ => observed.hardware_revision & 0xf,
        };
        let radio_step = (radio_id >> 8) & 0xf;
        let (firmware, pnvm) = images(mac, step, radio, radio_step)
            .ok_or(IdentityError::UnsupportedStep(observed.hardware_revision))?;
        let revision = match mac {
            MAC_BZ | MAC_BZ_W => observed.hardware_revision | step,
            _ => observed.hardware_revision,
        };
        Ok(Self {
            observed,
            family,
            platform,
            radio: match radio {
                RF_HR2 => Rf::Hr,
                RF_GF => Rf::Gf,
                _ => Rf::Fm,
            },
            revision,
            firmware,
            pnvm,
            scu_force_active: false,
            stops_at_160: radio == RF_FM
                && fm_stops_at_160(observed.device, observed.subsystem_device),
        })
    }

    /// The SMBIOS system vendor, whose substring `dmi_check_system` matches
    /// to approve a GL MAC's SCU staying active.
    pub fn with_system_vendor(mut self, vendor: &str) -> Self {
        self.scu_force_active = (self.observed.hardware_revision & 0xfff0) >> 4 == MAC_GL
            && SCU_FORCE_ACTIVE_VENDORS
                .iter()
                .any(|approved| vendor.contains(approved));
        self
    }
    /// Whether the boot context tells firmware to hold the SCU active.
    pub fn scu_force_active(&self) -> bool {
        self.scu_force_active
    }

    pub fn observed(&self) -> Observed {
        self.observed
    }
    pub fn family(&self) -> Family {
        self.family
    }
    pub fn platform(&self) -> Platform {
        self.platform
    }
    pub fn radio(&self) -> Rf {
        self.radio
    }
    /// A radio with EHT's limits. `sku` is ALIVE's, whose word Linux reads
    /// while matching a PNVM section, and `urm` is the STEP's state.
    pub fn eht_limits(&self, sku: [u32; 3], urm: bool) -> Option<EhtLimits> {
        (self.radio == Rf::Fm).then_some(EhtLimits {
            stops_at_160: self.stops_at_160,
            reduced: sku[0] & REDUCED_CAPABILITY != 0,
            urm,
            slow_bus: !self.platform.integrated && self.observed.link_speed < SPEED_8GT,
            dual_radio: radio_id(self.observed).is_ok_and(|id| id & CDB != 0),
        })
    }
    /// CSR_HW_REV with the step `get_crf_id` found, as firmware is told it.
    pub fn revision(&self) -> u32 {
        self.revision
    }
    pub fn bisr_workaround(&self) -> bool {
        bisr_workaround(self.observed.device)
    }
    /// The channel table this radio answers with: `uhb_supported` belongs to
    /// the radio, so an HR radio on an AX210-family MAC has no 6 GHz rows.
    pub fn channel_inventory(&self) -> Inventory {
        match self.radio {
            Rf::Hr => Inventory::Extended,
            Rf::Gf | Rf::Fm => Inventory::UltraHighBand,
        }
    }
    pub fn firmware_request(&self) -> Request {
        self.request(self.firmware)
    }
    pub fn pnvm_request(&self) -> Option<Request> {
        self.pnvm.map(|name| self.request(name))
    }
    fn request(&self, name: &'static str) -> Request {
        let o = self.observed;
        Request {
            name,
            hardware: format!(
                "pci:{:04x}:{:04x}:{:04x}:{:04x}",
                o.vendor, o.device, o.subsystem_vendor, o.subsystem_device
            ),
            revision: format!(
                "pci-{:02x}-hw-{:08x}-rf-{:08x}",
                o.pci_revision, o.hardware_revision, o.radio_id
            ),
        }
    }
    /// The same file under the device's binding, which `stela setup` writes
    /// for an adapter it knows by PCI IDs alone ([`device_images`]).
    fn device_request(&self, name: &'static str) -> Request {
        Request {
            name,
            hardware: format!("pci:{INTEL:04x}:{:04x}", self.observed.device),
            revision: DEVICE_REVISION.into(),
        }
    }
    /// The file `name` under this adapter's observed binding, or else under
    /// its device's binding when the USB has none for the observed adapter.
    /// A failure is the observed request's. A Provider may be supplied
    /// independently, so callers check the image with [`Self::binds`].
    pub fn load<'a>(
        &self,
        name: &'static str,
        provider: &'a dyn resources::Provider,
    ) -> Result<resources::Image<'a>, resources::Error> {
        let mut unbound = None;
        for request in [self.request(name), self.device_request(name)] {
            match provider.load(request.requirement()) {
                Ok(image) => return Ok(image),
                Err(error)
                    if matches!(
                        error.kind,
                        resources::ErrorKind::Missing | resources::ErrorKind::WrongTarget
                    ) =>
                {
                    unbound.get_or_insert(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(unbound.expect("the observed request had no binding"))
    }
    /// Whether `image` is the file `name` under one of the two bindings
    /// [`Self::load`] takes.
    pub fn binds(&self, name: &'static str, image: &resources::Image<'_>) -> bool {
        image.name() == name
            && [self.request(name), self.device_request(name)]
                .iter()
                .any(|request| image.target() == request.requirement().target)
    }
}

/// The revision of a device binding ([`Profile::load`]).
pub const DEVICE_REVISION: &str = "linux-firmware";

/// Every image and PNVM [`Profile::select`] can name for the device `id`,
/// whatever its MAC, radio and steps: what `stela setup` writes under the
/// device binding (`stela_loader::host_firmware::recipes::require_wifi`
/// mirrors this table). `iwlwifi-ma-b0-hr-b0-89.ucode` is left out: setup
/// has no pinned recipe for it, so an MA MAC with an HR radio still needs
/// the observed inventory.
pub const fn device_images(id: u16) -> &'static [&'static str] {
    const QU: &[&str] = &[
        "iwlwifi-Qu-b0-hr-b0-77.ucode",
        "iwlwifi-Qu-c0-hr-b0-77.ucode",
        "iwlwifi-QuZ-a0-hr-b0-77.ucode",
    ];
    const SO: &[&str] = &[
        "iwlwifi-so-a0-hr-b0-89.ucode",
        "iwlwifi-so-a0-gf-a0-89.ucode",
        "iwlwifi-so-a0-gf-a0.pnvm",
        "iwlwifi-ma-b0-gf-a0-89.ucode",
        "iwlwifi-ma-b0-gf-a0.pnvm",
    ];
    match id {
        AX200 => &["iwlwifi-cc-a0-77.ucode"],
        AX210 => &["iwlwifi-ty-a0-gf-a0-89.ucode", "iwlwifi-ty-a0-gf-a0.pnvm"],
        BE200 => &["iwlwifi-gl-c0-fm-c0-c106.ucode", "iwlwifi-gl-c0-fm-c0.pnvm"],
        _ => match device(id) {
            Some((Family::Ax200, _)) => QU,
            Some((Family::Ax210, _)) => SO,
            Some((Family::Bz, _)) => {
                &["iwlwifi-bz-b0-fm-c0-c106.ucode", "iwlwifi-bz-b0-fm-c0.pnvm"]
            }
            Some((Family::Sc, _)) => &["iwlwifi-sc-a0-fm-c0-c106.ucode"],
            None => &[],
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: &'static str,
    pub hardware: String,
    pub revision: String,
}

impl Request {
    pub fn requirement(&self) -> resources::Requirement<'_> {
        resources::Requirement {
            name: self.name,
            target: resources::Target {
                driver: "wifi-intel",
                hardware: &self.hardware,
                revision: &self.revision,
                board: None,
            },
            // An image holds its header and one TLV; a PNVM holds one TLV.
            minimum_bytes: if self.name.ends_with(".ucode") {
                firmware::HEADER_BYTES + firmware::TLV_HEADER_BYTES
            } else {
                firmware::TLV_HEADER_BYTES
            },
        }
    }
}

#[derive(Debug)]
pub enum StageError {
    Resource {
        request: Request,
        error: Box<resources::Error>,
    },
    Firmware {
        request: Request,
        error: firmware::Error,
    },
}

/// Borrowed pre-ROM firmware only. Conditional PNVM/reduced-power resource
/// acquisition must follow current-epoch ALIVE SKU/source policy.
/// The image and its parsed bytes cannot be independently replaced:
/// ```compile_fail
/// use stela_drivers::{firmware::Image,net::wifi::intel::{firmware::Firmware,identity::Staged}};
/// fn forged<'a>(firmware:Firmware<'a>,source:Image<'a>)->Staged<'a> {
///     Staged { firmware,source }
/// }
/// ```
pub struct Staged<'a> {
    firmware: Firmware<'a>,
    source: resources::Image<'a>,
}

impl<'a> Staged<'a> {
    pub fn firmware(&self) -> &Firmware<'a> {
        &self.firmware
    }
    pub fn source(&self) -> resources::Image<'a> {
        self.source
    }
    pub(super) fn into_parts(self) -> (Firmware<'a>, resources::Image<'a>) {
        (self.firmware, self.source)
    }
}

pub fn stage<'a>(
    profile: &Profile,
    provider: &'a dyn resources::Provider,
) -> Result<Staged<'a>, StageError> {
    let request = profile.firmware_request();
    let source = profile
        .load(request.name, provider)
        .map_err(|error| StageError::Resource {
            request: request.clone(),
            error: Box::new(error),
        })?;
    let firmware = Firmware::parse(source.bytes())
        .and_then(|fw| {
            fw.require_family(profile.family)?;
            Ok(fw)
        })
        .map_err(|error| StageError::Firmware { request, error })?;
    Ok(Staged { firmware, source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firmware::{Catalog, Provenance, Provider, Resource};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use sha2::{Digest, Sha256};

    fn observed(device: u16) -> Observed {
        Observed {
            link_speed: 3,
            vendor: INTEL,
            device,
            subsystem_vendor: INTEL,
            subsystem_device: 0x0084,
            pci_revision: 0x1a,
            hardware_revision: if device == AX200 { 0x340 } else { 0x420 },
            radio_id: if device == AX200 {
                RF_HR2 << 12
            } else {
                RF_GF << 12
            },
            silicon: Silicon::default(),
        }
    }
    fn firmware(api: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 88];
        bytes[4..8].copy_from_slice(&0x0a4c_5749u32.to_le_bytes());
        bytes[72..76].copy_from_slice(&api.to_le_bytes());
        bytes.extend(29u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend((1u32 << 20).to_le_bytes());
        bytes
    }

    #[test]
    fn standalone_profiles_preserve_every_raw_binding_field_and_reject_unsupported_variants() {
        for device in [AX200, AX210] {
            let mut o = observed(device);
            o.hardware_revision |= 0xa000_0007;
            o.radio_id |= 0x0000_035a;
            let profile = Profile::select(o).unwrap();
            let request = profile.firmware_request();
            assert_eq!(profile.observed(), o);
            assert!(request.hardware.ends_with(":8086:0084"));
            assert!(request.revision.contains(&format!(
                "hw-{:08x}-rf-{:08x}",
                o.hardware_revision, o.radio_id
            )));
            for field in 0..4 {
                let mut bad = o;
                match field {
                    0 => bad.vendor = 0x1234,
                    1 => bad.hardware_revision = u32::MAX,
                    2 => (bad.radio_id, bad.silicon.crf) = (0, 0x201),
                    _ => bad.radio_id = u32::MAX,
                };
                assert!(Profile::select(bad).is_err());
            }
        }
        let mut o = observed(AX210);
        o.radio_id |= CDB;
        assert!(matches!(
            Profile::select(o),
            Err(IdentityError::UnsupportedRadio(_))
        ));
        for device in [0x24fd, 0x2720] {
            assert_eq!(
                Profile::select(observed(device)).unwrap_err(),
                IdentityError::UnsupportedPci
            );
        }
    }

    fn integrated(device: u16, revision: u32, radio: u32, subsystem: u16) -> Observed {
        Observed {
            device,
            hardware_revision: revision,
            radio_id: radio << 12,
            subsystem_device: subsystem,
            ..observed(AX200)
        }
    }

    #[test]
    fn integrated_devices_name_their_mac_steps_image_and_platform() {
        for (device, revision, radio, ucode, pnvm, flags, latency) in [
            (
                0x06f0,
                0x331,
                RF_HR2,
                "iwlwifi-Qu-b0-hr-b0-77.ucode",
                None,
                4,
                500,
            ),
            (
                0x02f0,
                0x332,
                RF_HR2,
                "iwlwifi-Qu-c0-hr-b0-77.ucode",
                None,
                4,
                500,
            ),
            (
                0x34f0,
                0x354,
                RF_HR2,
                "iwlwifi-QuZ-a0-hr-b0-77.ucode",
                None,
                12,
                1820,
            ),
            (
                0xa0f0,
                0x332,
                RF_HR2,
                "iwlwifi-Qu-c0-hr-b0-77.ucode",
                None,
                10,
                12000,
            ),
            (
                0x7af0,
                0x370,
                RF_HR2,
                "iwlwifi-so-a0-hr-b0-89.ucode",
                None,
                4,
                500,
            ),
            (
                0x51f0,
                0x370,
                RF_GF,
                "iwlwifi-so-a0-gf-a0-89.ucode",
                Some("iwlwifi-so-a0-gf-a0.pnvm"),
                10,
                12000,
            ),
            (
                0x7e40,
                0x441,
                RF_GF,
                "iwlwifi-ma-b0-gf-a0-89.ucode",
                Some("iwlwifi-ma-b0-gf-a0.pnvm"),
                0,
                0,
            ),
        ] {
            let profile = Profile::select(integrated(device, revision, radio, 0x0070)).unwrap();
            assert_eq!(profile.firmware_request().name, ucode);
            assert_eq!(profile.pnvm_request().map(|request| request.name), pnvm);
            assert_eq!(profile.platform().soc_flags(), flags);
            assert_eq!(profile.platform().xtal_latency, latency);
            assert!(!profile.bisr_workaround());
        }
        assert!(
            Profile::select(integrated(0x7a70, 0x370, RF_GF, 0x0090))
                .unwrap()
                .platform()
                .imr
        );
    }

    #[test]
    fn wifi_7_devices_name_their_image_from_the_step_their_cnvi_reports() {
        let radio = RF_FM << 12 | STEP_C << 8;
        let gl = Profile::select(integrated(BE200, 0x472, RF_FM, 0x0020)).unwrap_err();
        assert_eq!(gl, IdentityError::UnsupportedStep(0x472));
        let gl = Observed {
            radio_id: radio,
            ..integrated(BE200, 0x472, RF_FM, 0x0020)
        };
        let profile = Profile::select(gl).unwrap();
        assert_eq!(profile.family(), Family::Bz);
        assert_eq!(
            profile.firmware_request().name,
            "iwlwifi-gl-c0-fm-c0-c106.ucode"
        );
        assert_eq!(profile.platform().soc_flags(), 3);
        assert_eq!(profile.channel_inventory(), Inventory::UltraHighBand);
        let bz = |cnv| Observed {
            radio_id: radio,
            silicon: Silicon {
                crf: 0,
                cnv,
                wfpm: 0,
            },
            ..integrated(0x7740, 0x460, RF_FM, 0x0020)
        };
        let b_step = Profile::select(bz(0x0100_0900)).unwrap();
        assert_eq!(
            b_step.firmware_request().name,
            "iwlwifi-bz-b0-fm-c0-c106.ucode"
        );
        assert_eq!(b_step.revision(), 0x461);
        assert_eq!(Profile::select(bz(0x930)).unwrap().revision(), 0x461);
        assert_eq!(
            Profile::select(bz(0x900)).unwrap_err(),
            IdentityError::UnsupportedStep(0x460)
        );
        // BE202 is `iwl_rf_fm_160mhz`: the same firmware, held to 160 MHz.
        let be202 = Observed {
            radio_id: radio,
            ..integrated(0x7740, 0x460, RF_FM, 0x0220)
        };
        let limits = Profile::select(Observed {
            silicon: Silicon {
                crf: 0,
                cnv: 0x0100_0900,
                wfpm: 0,
            },
            ..be202
        })
        .unwrap()
        .eht_limits([0; 3], false)
        .unwrap();
        assert!(limits.stops_at_160 && !limits.reaches_320());
        let unlisted = Observed {
            subsystem_device: 0x0021,
            ..bz(0x0100_0900)
        };
        assert_eq!(
            Profile::select(Observed {
                device: BZ_LISTED,
                ..unlisted
            })
            .unwrap_err(),
            IdentityError::UnsupportedPci
        );
    }

    #[test]
    fn killer_subdevices_are_their_own_products_despite_the_limit_bit() {
        let radio = RF_FM << 12 | STEP_C << 8;
        let be200 = |subsystem_device| Observed {
            radio_id: radio,
            subsystem_device,
            ..integrated(BE200, 0x472, RF_FM, 0x0020)
        };
        for subdevice in [
            0x1771, 0x1772, 0x1773, 0x1774, 0x1775, 0x1776, 0x1791, 0x1792,
        ] {
            let limits = Profile::select(be200(subdevice))
                .unwrap()
                .eht_limits([0; 3], false)
                .unwrap();
            assert!(limits.reaches_320(), "{subdevice:x}");
        }
        for subdevice in [KILLER_1730, KILLER_1731, KILLER_1735, KILLER_1736, 0x0220] {
            let profile = Profile::select(be200(subdevice)).unwrap();
            assert!(profile.eht_limits([0; 3], false).unwrap().stops_at_160);
        }
        // The discrete Killer subdevices are BE200's alone; elsewhere their
        // limit bit makes the radio a BE202.
        let other = Observed {
            device: 0x7740,
            silicon: Silicon {
                crf: 0,
                cnv: 0x0100_0900,
                wfpm: 0,
            },
            ..be200(0x1773)
        };
        let limits = Profile::select(Observed {
            hardware_revision: 0x460,
            ..other
        })
        .unwrap()
        .eht_limits([0; 3], false)
        .unwrap();
        assert!(limits.stops_at_160);
    }

    #[test]
    fn killer_ax1650s_and_ax1650i_are_ax201s_despite_the_limit_bit() {
        for subdevice in [KILLER_1650S, KILLER_1650I] {
            let profile = Profile::select(integrated(0x06f0, 0x332, RF_HR2, subdevice)).unwrap();
            assert_eq!(
                profile.firmware_request().name,
                "iwlwifi-Qu-c0-hr-b0-77.ucode"
            );
            let so = Profile::select(integrated(0x7af0, 0x370, RF_HR2, subdevice)).unwrap();
            assert_eq!(so.firmware_request().name, "iwlwifi-so-a0-hr-b0-89.ucode");
        }
        // AX203 keeps its own configuration.
        assert!(matches!(
            Profile::select(integrated(0x06f0, 0x332, RF_HR2, 0x0244)),
            Err(IdentityError::UnsupportedRadio(_))
        ));
    }

    #[test]
    fn a_wifi_7_device_reports_what_limits_it() {
        let radio = RF_FM << 12 | STEP_C << 8;
        let slow = Observed {
            radio_id: radio,
            link_speed: 2,
            ..integrated(BE200, 0x472, RF_FM, 0x0020)
        };
        let profile = Profile::select(slow).unwrap();
        let limits = profile.eht_limits([1 << 25, 0, 0], true).unwrap();
        assert!(limits.reduced && limits.urm);
        assert!(limits.slow_bus, "a discrete link at 5 GT/s");
        let fast = Profile::select(Observed {
            link_speed: 3,
            ..slow
        })
        .unwrap();
        assert!(!fast.eht_limits([0; 3], false).unwrap().slow_bus);
        let wifi_6 = Profile::select(observed(AX210)).unwrap();
        assert_eq!(wifi_6.eht_limits([0; 3], false), None);
    }

    #[test]
    fn a_blank_otp_names_its_radio_through_the_silicon() {
        let mut blank = integrated(0x06f0, 0x332, 0, 0x0070);
        blank.silicon.crf = 0x0100_0000 | CRF_HR2;
        let profile = Profile::select(blank).unwrap();
        assert_eq!(profile.radio(), Rf::Hr);
        // `map_crf_id`: REG_CRF_ID_TYPE_HR_CDB is an HR2 whose CDB comes
        // from the WFPM or the slave bit alone.
        let cdb_type = Observed {
            silicon: Silicon {
                crf: 0x0100_0000 | 0x503,
                ..blank.silicon
            },
            ..blank
        };
        assert_eq!(Profile::select(cdb_type).unwrap().radio(), Rf::Hr);
        blank.silicon.wfpm = 1 << 4;
        assert!(matches!(
            Profile::select(blank),
            Err(IdentityError::UnsupportedRadio(_))
        ));
    }

    #[test]
    fn a_radios_inventory_follows_the_radio_and_not_the_family() {
        let hr = Profile::select(integrated(0x7af0, 0x370, RF_HR2, 0x0070)).unwrap();
        let gf = Profile::select(integrated(0x7af0, 0x370, RF_GF, 0x0070)).unwrap();
        assert_eq!(hr.family(), gf.family());
        assert_eq!(hr.channel_inventory(), Inventory::Extended);
        assert_eq!(gf.channel_inventory(), Inventory::UltraHighBand);
    }

    #[test]
    fn products_without_a_profile_are_refused_by_name_of_what_differs() {
        let unsupported = |o: Observed| Profile::select(o).unwrap_err();
        assert!(matches!(
            unsupported(integrated(0x06f0, 0x332, RF_GF, 0x0070)),
            IdentityError::UnsupportedRadio(_)
        ));
        assert!(matches!(
            unsupported(integrated(0x06f0, 0x332, RF_HR2, 0x0274)),
            IdentityError::UnsupportedRadio(_)
        ));
        assert!(matches!(
            unsupported(integrated(0x7af0, 0x370, RF_GF, AX231)),
            IdentityError::UnsupportedRadio(_)
        ));
        assert_eq!(
            unsupported(integrated(0x06f0, 0x340, RF_HR2, 0x0070)),
            IdentityError::UnsupportedMac(MAC_CC)
        );
        assert_eq!(
            unsupported(integrated(0x06f0, 0x330, RF_HR2, 0x0070)),
            IdentityError::UnsupportedStep(0x330)
        );
        assert_eq!(
            unsupported(integrated(0x7e40, 0x440, RF_GF, 0x0070)),
            IdentityError::UnsupportedStep(0x440)
        );
    }

    struct Observing<'a> {
        catalog: &'a Catalog,
        names: RefCell<Vec<String>>,
    }
    impl Provider for Observing<'_> {
        fn load<'a>(
            &'a self,
            requirement: resources::Requirement<'_>,
        ) -> Result<resources::Image<'a>, resources::Error> {
            self.names.borrow_mut().push(requirement.name.into());
            self.catalog.load(requirement)
        }
    }

    #[test]
    fn pre_rom_staging_defers_conditional_pnvm_until_alive() {
        let profile = Profile::select(observed(AX210)).unwrap();
        let catalog = Catalog::from_handoff(vec![]).unwrap();
        let provider = Observing {
            catalog: &catalog,
            names: RefCell::new(Vec::new()),
        };
        assert!(
            matches!(stage(&profile,&provider),Err(StageError::Resource { request,.. }) if request.name=="iwlwifi-ty-a0-gf-a0-89.ucode")
        );
        // The observed binding, then the device's.
        assert_eq!(
            &*provider.names.borrow(),
            &["iwlwifi-ty-a0-gf-a0-89.ucode"; 2]
        );
    }

    fn catalog(name: &'static str, target: resources::Target<'_>, bytes: Vec<u8>) -> Catalog {
        let hash = Sha256::digest(&bytes).into();
        Catalog::from_handoff(vec![Resource {
            name,
            target,
            provenance: Provenance {
                source: "test",
                revision: "immutable",
                member: name,
                license: "BSD",
            },
            expected_length: bytes.len(),
            expected_sha256: hash,
            bytes,
        }])
        .unwrap()
    }

    #[test]
    fn an_adapter_with_no_observed_binding_takes_its_devices_file() {
        let profile = Profile::select(observed(AX210)).unwrap();
        let name = profile.firmware_request().name;
        let device = resources::Target {
            driver: "wifi-intel",
            hardware: "pci:8086:2725",
            revision: DEVICE_REVISION,
            board: None,
        };
        let bound = catalog(name, device, firmware(89));
        let staged = stage(&profile, &bound).unwrap();
        assert_eq!(staged.source.target(), device);
        assert!(profile.binds(name, &staged.source));
        assert!(!profile.binds("iwlwifi-so-a0-gf-a0-89.ucode", &staged.source));
        // Another device's binding is not this adapter's.
        let other = catalog(
            name,
            resources::Target {
                hardware: "pci:8086:7af0",
                ..device
            },
            firmware(89),
        );
        assert!(matches!(
            stage(&profile, &other),
            Err(StageError::Resource { error, .. })
                if error.kind == resources::ErrorKind::WrongTarget
        ));
    }

    /// Every combination of MAC, step, radio and radio step `select` admits
    /// for every listed device names only files of [`device_images`], and
    /// each of those files is named by one.
    #[test]
    fn device_images_hold_every_file_a_device_can_select() {
        let macs = [
            MAC_QU, MAC_CC, MAC_QUZ, MAC_SO, MAC_TY, MAC_SOF, MAC_MA, MAC_BZ, MAC_GL, MAC_SC,
            MAC_BZ_W,
        ];
        let mut devices = 0;
        for id in 0..=u16::MAX {
            if device(id).is_none() {
                assert!(device_images(id).is_empty());
                continue;
            }
            devices += 1;
            let mut named = Vec::new();
            for mac in macs {
                for step in 0..4 {
                    for radio in [RF_HR2, RF_GF, RF_FM] {
                        for radio_step in 0..4 {
                            let o = Observed {
                                device: id,
                                subsystem_device: 0x0090,
                                hardware_revision: mac << 4 | step,
                                radio_id: radio << 12 | radio_step << 8,
                                silicon: Silicon {
                                    crf: 0,
                                    cnv: step << 24,
                                    wfpm: 0,
                                },
                                ..observed(AX200)
                            };
                            let Ok(profile) = Profile::select(o) else {
                                continue;
                            };
                            for name in [Some(profile.firmware), profile.pnvm].into_iter().flatten()
                            {
                                if name == "iwlwifi-ma-b0-hr-b0-89.ucode" {
                                    continue;
                                }
                                assert!(device_images(id).contains(&name), "{id:04x}: {name}");
                                named.push(name);
                            }
                        }
                    }
                }
            }
            for name in device_images(id) {
                assert!(named.contains(name), "{id:04x} never names {name}");
            }
        }
        assert_eq!(devices, 26);
    }

    #[test]
    fn ax210_firmware_only_catalog_can_stage_before_sku_observation() {
        let profile = Profile::select(observed(AX210)).unwrap();
        let request = profile.firmware_request();
        let bytes = firmware(89);
        let hash = Sha256::digest(&bytes).into();
        let catalog = Catalog::from_handoff(vec![Resource {
            name: request.name,
            target: request.requirement().target,
            provenance: Provenance {
                source: "test",
                revision: "immutable",
                member: request.name,
                license: "BSD",
            },
            expected_length: bytes.len(),
            expected_sha256: hash,
            bytes,
        }])
        .unwrap();
        let provider = Observing {
            catalog: &catalog,
            names: RefCell::new(Vec::new()),
        };
        assert_eq!(
            stage(&profile, &provider).unwrap().firmware.api_version(),
            89
        );
        assert_eq!(&*provider.names.borrow(), &["iwlwifi-ty-a0-gf-a0-89.ucode"]);
    }
    #[test]
    fn catalog_identity_and_bytes_are_borrowed_without_variant_fallback() {
        let profile = Profile::select(observed(AX200)).unwrap();
        let request = profile.firmware_request();
        let bytes = firmware(77);
        let pointer = bytes.as_ptr();
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        let catalog = Catalog::from_handoff(vec![Resource {
            name: request.name,
            target: request.requirement().target,
            provenance: Provenance {
                source: "test",
                revision: "immutable",
                member: request.name,
                license: "BSD",
            },
            expected_length: bytes.len(),
            expected_sha256: hash,
            bytes,
        }])
        .unwrap();
        let staged = stage(&profile, &catalog).unwrap();
        assert_eq!(staged.source.bytes().as_ptr(), pointer);
        assert_eq!(staged.firmware.api_version(), 77);
        let mut different = profile.observed();
        different.radio_id ^= 1;
        let different = Profile::select(different).unwrap();
        assert!(
            matches!(stage(&different,&catalog),Err(StageError::Resource {error,..}) if error.kind==resources::ErrorKind::WrongTarget)
        );
    }
}
