// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2005-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! One claimed Intel Wi-Fi function taken from its registers to ROM boot, as
//! `iwl_pci_probe` identifies it from CSR_HW_REV and CSR_HW_RF_ID, wakes it,
//! loads its firmware and `iwl_trans_pcie_gen2_start_fw` starts it, then
//! handed to the polled bring-up.
use super::{
    boot::{self, BootIo, ProductResetPolicy, RomBoot},
    firmware::{self, Family},
    identity::{self, IdentityError, Observed, Profile, StageError},
    link::{Inputs, Station, Wifi},
    platform::{self, Observations},
    power::{self, ManagementSession, Power},
    radio::bios::service::{BiosIo, DmiIdentity},
};
use crate::{
    bus::dma::{mapping::DmaDomain, memory::PageSource},
    firmware::{ErrorKind, Provider},
};
use alloc::{string::String, sync::Arc};
use core::fmt;

/// CSR_HW_REV.
const HW_REV: u32 = 0x28;

/// The function's PCI identity from its configuration space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pci {
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub revision: u8,
    /// PCI_EXP_LNKSTA's current speed.
    pub link_speed: u8,
    /// Whether the function's first MSI-X vector wakes the core that looks
    /// for its frames.
    pub vector: bool,
}

/// Why the function did not reach ROM boot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachError {
    /// The handoff carries no regulatory database, so nothing may scan.
    NoRegulatoryDatabase,
    /// This build reads no ACPI namespace, which iwlwifi's platform
    /// configuration comes from.
    NoNamespace,
    Register(power::AccessError),
    Identity(IdentityError),
    Power(power::Error),
    /// The handoff carries no firmware image `name` for `family`.
    NoPinnedFirmware {
        family: Family,
        name: &'static str,
    },
    Resource {
        name: &'static str,
        kind: ErrorKind,
    },
    Firmware {
        name: &'static str,
        error: firmware::Error,
    },
    Step(String),
    Boot(boot::Error),
    /// Stopping what the function's last owner left running failed.
    Stop(power::Error),
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRegulatoryDatabase => {
                f.write_str("the Wi-Fi regulatory database is missing, so nothing may scan")
            }
            Self::NoNamespace => f.write_str("this build reads no ACPI namespace"),
            Self::Register(error) => write!(f, "its registers did not answer ({error})"),
            Self::Identity(IdentityError::UnsupportedPci) => {
                f.write_str("this Intel Wi-Fi adapter is not supported")
            }
            Self::Identity(error) => {
                write!(f, "this Intel Wi-Fi adapter is not supported: {error}")
            }
            Self::Power(error) => write!(f, "it did not wake up ({error})"),
            Self::NoPinnedFirmware { name, .. } => {
                write!(f, "its firmware {name} is not on the USB")
            }
            Self::Resource { name, kind } => {
                write!(f, "its firmware {name} is unreadable ({kind})")
            }
            Self::Firmware { name, error } => {
                write!(f, "its firmware {name} is invalid ({error})")
            }
            Self::Step(error) => write!(f, "its radio step is unknown ({error})"),
            Self::Boot(boot::Error::RfKilled) => f.write_str(
                "its radio is switched off by the PC's wireless switch or key (RF kill)",
            ),
            Self::Boot(error) => write!(f, "its firmware did not start ({error:?})"),
            Self::Stop(error) => write!(f, "it did not stop for Stela to take over ({error})"),
        }
    }
}

/// The RX buffer count `iwl_trans_get_num_rbds` gives each family's HE
/// radio, within what the ROM boot's context accepts.
fn receive_entries(family: Family) -> u16 {
    match family {
        Family::Ax200 => 2048,
        _ => 1024,
    }
}

/// Identify, wake and ROM-boot the function `io` reaches, then hand it to
/// [`Wifi`].
///
/// # Safety
/// `io` reaches the BAR0 of the claimed, stopped function `pci` describes,
/// with memory decoding and bus mastering on and its interrupts off;
/// `domain` isolates its requester; and [`Wifi::new`]'s contract holds for
/// `inputs`.
pub unsafe fn attach<Q: BootIo, B: BiosIo>(
    mut io: Q,
    pci: Pci,
    domain: Arc<dyn DmaDomain>,
    mut inputs: Inputs<B>,
) -> Result<Station<Q, B>, AttachError> {
    let hardware_revision = io.read32(HW_REV).map_err(AttachError::Register)?;
    let (family, _) =
        identity::device(pci.device).ok_or(AttachError::Identity(IdentityError::UnsupportedPci))?;
    // CSR_HW_RF_ID is read with the MAC awake, as `_iwl_pci_probe` reads it.
    let (silicon, radio_id) = power::read_radio(
        &mut io,
        family,
        identity::bisr_workaround(pci.device),
        ManagementSession::NotConnected,
    )
    .map_err(AttachError::Power)?;
    let mut profile = Profile::select(Observed {
        vendor: pci.vendor,
        device: pci.device,
        subsystem_vendor: pci.subsystem_vendor,
        subsystem_device: pci.subsystem_device,
        pci_revision: pci.revision,
        link_speed: pci.link_speed,
        hardware_revision,
        radio_id,
        silicon,
    })
    .map_err(AttachError::Identity)?;
    // A system without an SMBIOS identity is on no vendor's list.
    if let Ok(DmiIdentity {
        system_vendor: Some(vendor),
        ..
    }) = inputs.bios.dmi_identity()
    {
        profile = profile.with_system_vendor(&vendor);
    }
    // SAFETY: the caller's contract is RomBoot's.
    let boot = unsafe {
        start(
            io,
            profile,
            pci.vector,
            domain,
            receive_entries(family),
            inputs.firmware,
            inputs.observations,
            inputs.pages,
        )
    }?;
    // SAFETY: forwarded from the caller.
    Ok(unsafe { Wifi::new(boot, inputs) })
}

/// Stage `profile`'s firmware, wake the function and ROM-boot it.
///
/// # Safety
/// [`attach`]'s contract, with `io` alone in reaching the stopped function.
#[expect(clippy::too_many_arguments, reason = "each is one input of the boot")]
pub(super) unsafe fn start<Q: BootIo>(
    io: Q,
    profile: Profile,
    vector: bool,
    domain: Arc<dyn DmaDomain>,
    entries: u16,
    firmware: &'static dyn Provider,
    observations: Observations,
    pages: &'static dyn PageSource,
) -> Result<RomBoot<'static, Q>, AttachError> {
    let family = profile.family();
    let staged = identity::stage(&profile, firmware).map_err(|error| match error {
        StageError::Resource { request, error } if error.kind == ErrorKind::Missing => {
            AttachError::NoPinnedFirmware {
                family,
                name: request.name,
            }
        }
        StageError::Resource { request, error } => AttachError::Resource {
            name: request.name,
            kind: error.kind,
        },
        StageError::Firmware { request, error } => AttachError::Firmware {
            name: request.name,
            error,
        },
    })?;
    let mut power = Power::new(io, profile);
    if vector {
        power = power.with_vector();
    }
    power
        .wake(ManagementSession::NotConnected)
        .map_err(AttachError::Power)?;
    match family {
        // SAFETY: the caller's contract is RomBoot's.
        Family::Ax200 => unsafe { RomBoot::start(power, staged, pages, Some(domain), entries) },
        _ => {
            let step = platform::load_step_or_ignore(observations.step, firmware);
            // SAFETY: as above; no CSME session is attached to the function.
            unsafe {
                RomBoot::start_ax210(
                    power,
                    staged,
                    step,
                    pages,
                    Some(domain),
                    entries,
                    ProductResetPolicy::NoIwlmei,
                )
            }
        }
    }
    .map_err(AttachError::Boot)
}

#[cfg(test)]
mod display_tests {
    use super::*;

    /// The account names a switched-off radio in plain words and the
    /// identity registers in hex.
    #[test]
    fn rf_kill_and_identity_failures_read_plainly() {
        assert_eq!(
            alloc::format!("{}", AttachError::Boot(boot::Error::RfKilled)),
            "its radio is switched off by the PC's wireless switch or key (RF kill)"
        );
        assert_eq!(
            alloc::format!(
                "{}",
                AttachError::Identity(IdentityError::UnsupportedRadio(0x0010_d000))
            ),
            "this Intel Wi-Fi adapter is not supported: its radio (CSR_HW_RF_ID 0x0010d000) \
             is unsupported"
        );
    }
}
