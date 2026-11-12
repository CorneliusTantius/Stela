// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! One claimed RTL8822C function taken from its registers to a kept station:
//! `rtw_pci_probe` and `rtw_core_start`, then mac80211's first station on it.
use super::{
    bootstrap::{self, Claim},
    hardware::Hardware,
    identity::Observed,
    station::{self, Rtl8822c, Wifi},
};
use crate::{
    Clock,
    bus::dma::{mapping::DmaDomain, memory::PageSource},
    firmware::Provider,
    wifi::{
        network::Network,
        regulatory::database::{self, Database},
    },
};
use alloc::{string::String, sync::Arc};
use core::{any::Any, fmt, ptr::NonNull};
use stela_driver_base::entropy::Entropy;

/// What a station needs of the machine around it.
pub struct Inputs {
    pub firmware: &'static dyn Provider,
    pub pages: &'static dyn PageSource,
    pub clock: Clock,
    /// regulatory.db, whose country the network names, or the world domain
    /// `00` cfg80211 starts from when it names none.
    pub database: Database,
    pub network: Network,
    /// The source of the station's handshake nonces.
    pub entropy: Arc<dyn Entropy>,
    /// Whether the function's MSI wakes the core that looks for frames.
    pub vector: bool,
    /// The function's PCIe Link Control, as the platform left it.
    pub link_control: u16,
}

/// Why the function did not reach a station. Every owner the device may still
/// reach stays held.
#[derive(Debug)]
pub enum AttachError {
    /// No regulatory database loaded, so the radio may not transmit.
    NoRegulatoryDatabase,
    /// regulatory.db holds no usable rules for the network's country.
    Country([u8; 2], database::Error),
    Bootstrap(bootstrap::Error),
    Hardware(String),
    Station(station::Error),
    /// The function is not an adapter this driver runs.
    Identity(super::identity::IdentityError),
    /// Stopping what the function's last owner left running failed.
    Stop(super::power::Error),
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRegulatoryDatabase => f.write_str("RTL8822C: no regulatory database"),
            Self::Country(alpha2, error) => write!(
                f,
                "RTL8822C: regulatory.db country {}: {error:?}",
                alpha2.escape_ascii()
            ),
            Self::Bootstrap(error) => write!(f, "RTL8822C bring-up: {error}"),
            Self::Hardware(error) => write!(f, "RTL8822C: {error}"),
            Self::Station(error) => write!(f, "RTL8822C station: {error}"),
            Self::Identity(error) => {
                write!(f, "this Realtek Wi-Fi adapter is not supported ({error:?})")
            }
            Self::Stop(error) => write!(f, "it did not stop for Stela to take over ({error:?})"),
        }
    }
}

/// Bring up the function `observed` names and keep it connected to
/// `inputs.network`.
///
/// # Safety
/// [`bootstrap::bring_up`]'s contract holds for `window`, `bytes`, `owner`,
/// `domain` and `inputs.pages`, and `inputs.vector` says `owner`'s function
/// raises a routed MSI.
pub unsafe fn attach(
    window: NonNull<u8>,
    bytes: usize,
    owner: Arc<dyn Any>,
    domain: Arc<dyn DmaDomain>,
    observed: Observed,
    inputs: Inputs,
) -> Result<Wifi<Hardware>, AttachError> {
    let alpha2 = inputs.network.country.unwrap_or(*b"00");
    let country = inputs
        .database
        .select(alpha2)
        .map_err(|error| AttachError::Country(alpha2, error))?;
    let dfs_region = country.dfs_region();
    // SAFETY: forwarded from the caller.
    let up = unsafe {
        bootstrap::bring_up(Claim {
            window,
            bytes,
            owner,
            clock: inputs.clock,
            pages: inputs.pages,
            domain,
            firmware: inputs.firmware,
            observed,
            link_control: inputs.link_control,
        })
    }
    .map_err(AttachError::Bootstrap)?;
    let address = up.mac;
    // SAFETY: straight from bring-up, with the caller's MSI.
    let hardware = unsafe { Hardware::new(up, alpha2, dfs_region, inputs.vector) }
        .map_err(AttachError::Hardware)?;
    let radio =
        Rtl8822c::new(hardware, address, country, inputs.clock).map_err(AttachError::Station)?;
    Ok(radio.keep(inputs.network, inputs.entropy))
}
