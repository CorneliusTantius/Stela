// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! One AX200/AX210 function brought up as iwlwifi's mvm does it, polled one
//! step at a time: ROM boot to ALIVE, PNVM, unified NVM, the cold radio
//! prefix, LARI, setup, MCC, scan configuration, board power policy, the
//! country, the MLD MAC context (`iwl_mvm_up` and `iwl_mvm_mac_add_interface`),
//! then scans and, for the network the connection keeper chooses, the PHY
//! context, transmit power, link, AP station, its management queue and
//! Bluetooth coexistence (`iwl_mvm_mld_assign_vif_chanctx`,
//! `iwl_mvm_mld_add_sta`), and the same chain back down when it leaves.
//!
//! Every step's firmware command waits for its own acknowledgement; a
//! failed step keeps every owner the device may still reach.
use super::{
    association::StationLink,
    attach,
    boot::{
        self, Ax200BindingError, Ax200BindingPhase, Ax200BoardPolicy, Ax200BoardPolicyError,
        Ax200BoardPolicyPhase, Ax200Coexistence, Ax200CoexistenceError, Ax200CoexistencePhase,
        Ax200Country, Ax200CountryError, Ax200CountryPhase, Ax200LegacyPeer, Ax200LegacyPeerError,
        Ax200LegacyPeerPhase, Ax200Mac, Ax200MacError, Ax200MacPhase, Ax200ManagementQueue,
        Ax200ManagementQueueError, Ax200ManagementQueuePhase, Ax200Mcc, Ax200MccError,
        Ax200MccPhase, Ax200Phy, Ax200PhyError, Ax200PhyPhase, Ax200Scan, Ax200ScanConfiguration,
        Ax200ScanConfigurationError, Ax200ScanConfigurationPhase, Ax200ScanError, Ax200ScanPhase,
        Ax200Setup, Ax200SetupError, Ax200SetupOptions, Ax200SetupPhase, Ax200TransmitPower,
        Ax200TransmitPowerError, Ax200TransmitPowerPhase, BootIo, ColdRadio, ColdRadioPhase,
        InitializationProgress, LariError, LariPhase, LariRadio, LegacyPeer, MpduProgress,
        PnvmProgress, RomBoot, ScanResultProgress, UnifiedNvm,
    },
    error_log::Tables,
    firmware::Family,
    identity::Profile,
    interrupts,
    platform::Observations,
    policy::{Beacons, Regulatory},
    radio::{bios::service::BiosIo, control::PowerMode},
};
use crate::{
    Clock, Deadline, Link, LinkError, Mac,
    bus::dma::{mapping::DmaDomain, memory::PageSource},
    firmware::Provider,
    wifi::{
        Band,
        connection::keeper::Keeper,
        network::Network,
        regulatory::database::{self, Database},
        scan::{self, multiple_bssid, result::Bss},
        security,
        station::{self as association, Station as Association},
    },
};
use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::fmt;
use stela_driver_base::entropy::Entropy;

mod station;
pub use station::{ManagementKey, channel_flags};

/// `iwl_trans_determine_restart_mode`'s list of attempts on a function
/// without TOP reset, each of which boots the function again here.
const RESTARTS: usize = 5;
/// iwlwifi's `IWL_TRANS_RESET_OK_TIME`: how long a function goes without an
/// error for its list to start over.
const RESTART_OK_US: u64 = 7_000_000;
/// iwlwifi's `IWL_TRANS_RESET_DELAY`: the wait once the list runs out.
const RESTART_DELAY_US: u64 = 60_000_000;

/// iwlwifi's `IWL_MVM_UCODE_ALIVE_TIMEOUT`.
const ALIVE_TIMEOUT_US: u64 = 2_000_000;
/// iwlwifi's `MVM_UCODE_PNVM_TIMEOUT`.
const PNVM_TIMEOUT_US: u64 = 250_000;

type Country<Q, B> = Ax200Country<'static, Q, B, Regulatory>;

/// Why bring-up stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Pci(crate::block::BlockError),
    Boot(boot::Error),
    Lari(LariError),
    Setup(Ax200SetupError),
    Mcc(Ax200MccError),
    ScanConfiguration(Ax200ScanConfigurationError),
    Board(Ax200BoardPolicyError),
    Country(Ax200CountryError),
    Regulatory(database::Error),
    Mac(Ax200MacError),
    Scan(Ax200ScanError),
    Phy(Ax200PhyError),
    Power(Ax200TransmitPowerError),
    Binding(Ax200BindingError),
    Peer(Ax200LegacyPeerError),
    Queue(Ax200ManagementQueueError),
    Coexistence(Ax200CoexistenceError),
    /// A step's firmware or host deadline passed.
    Timeout(&'static str),
    /// The firmware or NIC reported its own death, in the words of its logs.
    FirmwareDied(String),
    /// Booting the function again failed.
    Restart(String),
    /// A step refused to start from the state the previous one left.
    Refused(&'static str),
    Station(association::Error),
    Data(association::data::Error),
    Key(security::Error),
    /// The firmware has yet to answer what this needs.
    Pending,
    Unsupported(&'static str),
}

impl Error {
    /// Whether another boot may help: not what the host itself refused.
    fn restartable(&self) -> bool {
        !matches!(
            self,
            Self::Pci(_)
                | Self::Boot(boot::Error::Pci(_))
                | Self::Boot(boot::Error::Access(super::power::AccessError::Minimum(_)))
                | Self::Boot(boot::Error::Power(super::power::Error::Access(
                    super::power::AccessError::Minimum(_)
                )))
                | Self::Refused(_)
                | Self::Regulatory(_)
                | Self::Station(_)
                | Self::Data(_)
                | Self::Key(_)
                | Self::Pending
                | Self::Unsupported(_)
                | Self::Restart(_)
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "iwlwifi: {self:?}")
    }
}

/// Where bring-up is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Booting,
    Initializing,
    Scanning,
    Joining,
    /// The AP station and its management queue are up: authentication may
    /// begin.
    AuthenticationRequired,
    Failed,
}

/// The services bring-up borrows for the rest of the boot.
pub struct Inputs<B> {
    pub firmware: &'static dyn Provider,
    pub observations: Observations,
    pub pages: &'static dyn PageSource,
    pub clock: Clock,
    pub bios: B,
    pub database: Database,
    pub network: Network,
    pub entropy: Arc<dyn Entropy>,
}

/// One Intel function kept connected to its network.
pub type Station<Q, B> = Keeper<Wifi<Q, B>>;

enum Stage<Q: BootIo, B: BiosIo> {
    Rom(Box<RomBoot<'static, Q>>),
    Pnvm(Box<RomBoot<'static, Q>>),
    Nvm(Box<UnifiedNvm<'static, Q>>),
    Radio(Box<ColdRadio<'static, Q>>),
    Lari(Box<LariRadio<'static, Q, B>>),
    Setup(Box<Ax200Setup<'static, Q, B>>),
    Mcc(Box<Ax200Mcc<'static, Q, B>>),
    ScanConfiguration(Box<Ax200ScanConfiguration<'static, Q, B>>),
    Board(Box<Ax200BoardPolicy<'static, Q, B>>),
    Country(Box<Country<Q, B>>),
    Mac(Box<Ax200Mac<'static, Q, B, Regulatory>>),
    Scan(Box<Ax200Scan<'static, Q, B, Regulatory>>),
    Phy(Box<Ax200Phy<'static, Q, B, Regulatory>>),
    Power(Box<Ax200TransmitPower<'static, Q, B, Regulatory>>),
    Link(Box<boot::Ax200Binding<'static, Q, B, Regulatory>>),
    Peer(Box<Ax200LegacyPeer<'static, Q, B, Regulatory>>),
    Queue(Box<Ax200ManagementQueue<'static, Q, B, Regulatory>>),
    Coexistence(Box<Ax200Coexistence<'static, Q, B, Regulatory>>),
    Ready(Box<Ax200ManagementQueue<'static, Q, B, Regulatory>>),
    /// The association's way down: the station and its queues,
    Removing(Box<Ax200ManagementQueue<'static, Q, B, Regulatory>>),
    /// the link,
    Unlinking(Box<boot::Ax200Binding<'static, Q, B, Regulatory>>),
    /// and the PHY.
    Unbinding(Box<Ax200Phy<'static, Q, B, Regulatory>>),
    /// Owners a failed step left, kept while the device may reach them.
    Failed {
        owner: Box<dyn Kept>,
    },
    Moving,
}

/// The network a scan chose to join.
#[derive(Clone, Debug)]
pub struct Selected {
    pub bss: Bss,
    pub rates: u16,
    /// The setup link of an MLD association.
    pub affiliation: Option<association::multi_link::Affiliation>,
}

/// Whatever owns the function when bring-up fails.
trait Kept {
    /// Stop the device under this owner, which then holds nothing the device
    /// can reach. Whether it stopped.
    fn stop_function(&mut self) -> bool;
}

impl Kept for () {
    fn stop_function(&mut self) -> bool {
        false
    }
}

impl<T: Kept> Kept for Box<T> {
    fn stop_function(&mut self) -> bool {
        self.as_mut().stop_function()
    }
}

impl<T: Kept, U> Kept for (T, U) {
    fn stop_function(&mut self) -> bool {
        self.0.stop_function()
    }
}

macro_rules! kept {
    ($([$($bounds:tt)*] $owner:ty),+ $(,)?) => {$(
        impl<$($bounds)*> Kept for $owner {
            fn stop_function(&mut self) -> bool {
                self.stop().is_ok()
            }
        }
    )+};
}

kept!(
    [Q: BootIo] RomBoot<'static, Q>,
    [Q: BootIo] UnifiedNvm<'static, Q>,
    [Q: BootIo] ColdRadio<'static, Q>,
    [Q: BootIo, B: BiosIo] LariRadio<'static, Q, B>,
    [Q: BootIo, B: BiosIo] Ax200Setup<'static, Q, B>,
    [Q: BootIo, B: BiosIo] Ax200Mcc<'static, Q, B>,
    [Q: BootIo, B: BiosIo] Ax200ScanConfiguration<'static, Q, B>,
    [Q: BootIo, B: BiosIo] Ax200BoardPolicy<'static, Q, B>,
    [Q: BootIo, B: BiosIo] Country<Q, B>,
    [Q: BootIo, B: BiosIo] Ax200Mac<'static, Q, B, Regulatory>,
    [Q: BootIo, B: BiosIo] Ax200Scan<'static, Q, B, Regulatory>,
    [Q: BootIo, B: BiosIo] Ax200Phy<'static, Q, B, Regulatory>,
    [Q: BootIo, B: BiosIo] Ax200TransmitPower<'static, Q, B, Regulatory>,
    [Q: BootIo, B: BiosIo] boot::Ax200Binding<'static, Q, B, Regulatory>,
    [Q: BootIo, B: BiosIo] Ax200LegacyPeer<'static, Q, B, Regulatory>,
    [Q: BootIo, B: BiosIo] Ax200ManagementQueue<'static, Q, B, Regulatory>,
    [Q: BootIo, B: BiosIo] Ax200Coexistence<'static, Q, B, Regulatory>,
);

impl<Q: BootIo, B: BiosIo> Kept for Stage<Q, B> {
    fn stop_function(&mut self) -> bool {
        self.owner().is_some_and(|owner| owner.stop_function())
    }
}

impl<Q: BootIo, B: BiosIo> Stage<Q, B> {
    fn owner(&mut self) -> Option<&mut dyn Kept> {
        let owner: &mut dyn Kept = match self {
            Stage::Rom(owner) | Stage::Pnvm(owner) => owner.as_mut(),
            Stage::Nvm(owner) => owner.as_mut(),
            Stage::Radio(owner) => owner.as_mut(),
            Stage::Lari(owner) => owner.as_mut(),
            Stage::Setup(owner) => owner.as_mut(),
            Stage::Mcc(owner) => owner.as_mut(),
            Stage::ScanConfiguration(owner) => owner.as_mut(),
            Stage::Board(owner) => owner.as_mut(),
            Stage::Country(owner) => owner.as_mut(),
            Stage::Mac(owner) => owner.as_mut(),
            Stage::Scan(owner) => owner.as_mut(),
            Stage::Phy(owner) | Stage::Unbinding(owner) => owner.as_mut(),
            Stage::Power(owner) => owner.as_mut(),
            Stage::Link(owner) | Stage::Unlinking(owner) => owner.as_mut(),
            Stage::Peer(owner) => owner.as_mut(),
            Stage::Queue(owner) | Stage::Ready(owner) | Stage::Removing(owner) => owner.as_mut(),
            Stage::Coexistence(owner) => owner.as_mut(),
            Stage::Failed { owner } => owner.as_mut(),
            Stage::Moving => return None,
        };
        Some(owner)
    }
}

/// `iwl_trans_determine_restart_mode`'s count of a function's attempts.
#[derive(Default)]
struct Attempts {
    count: usize,
    last_us: u64,
    /// When the wait after the last of the list ends.
    backoff: Option<u64>,
}

impl Attempts {
    /// `iwl_trans_determine_restart_mode`: past three attempts its list resets
    /// the function, and a product reset without the BIOS's `_PRR` does the
    /// same.
    fn resets(&self) -> bool {
        self.count > 3
    }

    /// Whether to boot again at `now`, spending an attempt.
    fn allow(&mut self, now: u64) -> bool {
        match self.backoff {
            Some(at) if now < at => return false,
            Some(_) => self.backoff = None,
            None => {
                if now.saturating_sub(self.last_us) >= RESTART_OK_US {
                    self.count = 0;
                }
                if self.count >= RESTARTS {
                    self.backoff = Some(now.saturating_add(RESTART_DELAY_US));
                    return false;
                }
            }
        }
        self.count += 1;
        self.last_us = now;
        true
    }
}

/// What boots the function again once its firmware dies. `io` also reads the
/// causes every owner above the ROM boot leaves alone.
struct Restart<Q, B> {
    io: Q,
    bios: B,
    database: Database,
    profile: Profile,
    domain: Arc<dyn DmaDomain>,
    entries: u16,
    attempts: Attempts,
    /// The function turned out to have no reset, which is said once.
    no_reset: bool,
    /// `request_top_reset`: the block shared with Bluetooth failed, for which
    /// the list's early reprobes are no use. Stela admits no MAC with a TOP
    /// reset of its own, so it takes the function reset of a product reset
    /// without `_PRR`.
    top_failed: bool,
}

/// One Intel Wi-Fi function's bring-up.
pub struct Wifi<Q: BootIo, B: BiosIo> {
    stage: Stage<Q, B>,
    firmware: &'static dyn Provider,
    observations: Observations,
    pages: &'static dyn PageSource,
    clock: Clock,
    bios: Option<B>,
    database: Option<Database>,
    network: Network,
    deadline: Option<Deadline>,
    beacons: Option<Arc<Beacons>>,
    selected: Option<Selected>,
    client: station::Client,
    /// The transmit and receive antennas.
    chains: (u32, u32),
    pub(crate) family: Family,
    radio: super::identity::Rf,
    /// Whether the function's first MSI-X vector reaches the host.
    pub(super) vector: bool,
    /// What limits a radio with EHT, once firmware is up.
    eht: Option<super::identity::EhtLimits>,
    /// What a test's radio without EHT stands in for.
    #[cfg(test)]
    pub(super) assumed_eht: Option<super::identity::EhtLimits>,
    save_power: bool,
    address: Mac,
    error: Option<Error>,
    /// Whether the link reported the bring-up failure.
    reported: bool,
    /// Where this firmware keeps its error logs.
    tables: Tables,
    restart: Restart<Q, B>,
    /// Platform tables this boot left out, as Linux does, reported once the
    /// station client for this boot exists.
    degraded: Vec<&'static str>,
}

/// What a boot past ALIVE left out of the platform tables Linux also does
/// without: the STEP equalizer data, the PNVM and the reduced-power tables.
pub(super) fn degraded<Q: BootIo>(boot: &RomBoot<'_, Q>) -> Vec<&'static str> {
    let mut left = Vec::new();
    if boot
        .step_configuration()
        .is_some_and(|step| step.ignored().is_some())
    {
        left.push("the platform's Wi-Fi STEP data: the firmware boots without it");
    }
    if let Some(receipts) = boot.platform_receipts() {
        if matches!(receipts.pnvm, super::calibration::Source::Skipped) {
            left.push("the Wi-Fi PNVM tables for this adapter: the firmware runs on its defaults");
        }
        if matches!(receipts.reduced_power, super::calibration::Source::Skipped) {
            left.push("the platform's reduced-power Wi-Fi tables: the firmware runs without them");
        }
    }
    left
}

/// The legacy rate bits `LegacyPeer` takes for the 500 kb/s rate units of a
/// Supported or Extended Supported Rates element, as `ieee80211_get_rates`
/// reads them; unknown rates are ignored.
pub fn legacy_rates(elements: &[u8], band: Band) -> u16 {
    const RATES: [u8; 12] = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    let mut mask = 0u16;
    let mut rest = elements;
    while let [id, length, tail @ ..] = rest {
        let Some((body, next)) = tail.split_at_checked(usize::from(*length)) else {
            break;
        };
        if matches!(id, 1 | 50) {
            for rate in body {
                if let Some(bit) = RATES.iter().position(|known| *known == rate & 0x7f) {
                    mask |= 1 << bit;
                }
            }
        }
        rest = next;
    }
    match band {
        Band::Ghz2 => mask,
        Band::Ghz5 | Band::Ghz6 => mask & 0xff0,
    }
}

/// The station before the NVM names its address.
fn unassigned() -> Association {
    Association::new(Mac([2, 0, 0, 0, 0, 1])).expect("a locally administered unicast address")
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// Take over a ROM boot `RomBoot::start` or `start_ax210` published.
    ///
    /// # Safety
    /// `boot`'s publication contract holds for the rest of the boot: `pages`
    /// gives fresh exclusive pages of its requester's domain, nothing else
    /// submits to or resets the function, and `bios` reads this function's
    /// own ACPI companion and the boot's captured variables.
    pub unsafe fn new(boot: RomBoot<'static, Q>, inputs: Inputs<B>) -> Station<Q, B> {
        let vector = boot.vector();
        let deadline = inputs.clock.deadline(ALIVE_TIMEOUT_US);
        let (io, profile, domain, entries) = boot.restart_inputs();
        let restart = Restart {
            io,
            bios: inputs.bios.clone(),
            database: inputs.database.clone(),
            profile,
            domain,
            entries,
            attempts: Attempts::default(),
            no_reset: false,
            top_failed: false,
        };
        let wifi = Self {
            family: boot.family(),
            radio: boot.radio(),
            vector,
            eht: None,
            #[cfg(test)]
            assumed_eht: None,
            stage: Stage::Rom(Box::new(boot)),
            firmware: inputs.firmware,
            observations: inputs.observations,
            pages: inputs.pages,
            clock: inputs.clock,
            bios: Some(inputs.bios),
            database: Some(inputs.database),
            network: inputs.network.clone(),
            deadline: Some(deadline),
            beacons: None,
            selected: None,
            client: station::Client::new(unassigned()),
            chains: (0, 0),
            save_power: false,
            address: Mac::default(),
            error: None,
            reported: false,
            tables: Tables::default(),
            restart,
            degraded: Vec::new(),
        };
        Keeper::keep(wifi, inputs.network, inputs.entropy, inputs.clock)
    }

    /// Whether the firmware or NIC reported its death since the last pass.
    /// The ROM boot reads this for itself, ALIVE among it. A register that
    /// stopped answering says as much.
    fn died(&mut self) -> bool {
        if matches!(self.stage, Stage::Rom(_) | Stage::Pnvm(_)) {
            return false;
        }
        let Ok(fatal) = interrupts::acknowledge(&mut self.restart.io, self.family, self.vector)
        else {
            return true;
        };
        self.restart.top_failed |= fatal & interrupts::INT_TOP_FATAL != 0;
        fatal != 0
    }

    /// `iwl_trans_restart_wk`, each attempt a reprobe: stop what the failed
    /// firmware left, free it and boot the function again, for the keeper to
    /// join from nothing. Whether the function is booting.
    fn restart(&mut self) -> bool {
        if !self.error.as_ref().is_some_and(Error::restartable)
            || !self.restart.attempts.allow(self.clock.now_us())
            || !self
                .stage
                .owner()
                .is_some_and(|owner| owner.stop_function())
        {
            return false;
        }
        let stopped = core::mem::replace(&mut self.stage, Stage::Moving);
        let reset = self.restart.attempts.resets() || core::mem::take(&mut self.restart.top_failed);
        let no_reset = if reset {
            match self.restart.io.reset_function() {
                Ok(did_reset) => !did_reset,
                Err(error) => {
                    self.error = Some(Error::Pci(error));
                    self.reported = false;
                    self.stage = Stage::Failed {
                        owner: Box::new(stopped),
                    };
                    return false;
                }
            }
        } else {
            false
        };
        drop(stopped);
        let first = no_reset && !core::mem::replace(&mut self.restart.no_reset, true);
        let restart = &self.restart;
        // SAFETY: the owner that held `io`'s twin stopped, and `new`'s
        // contract holds for what it kept.
        let boot = unsafe {
            attach::start(
                restart.io.clone(),
                restart.profile.clone(),
                self.vector,
                restart.domain.clone(),
                restart.entries,
                self.firmware,
                self.observations,
                self.pages,
            )
        };
        let boot = match boot {
            Ok(boot) => boot,
            Err(error) => {
                self.error = Some(match error {
                    attach::AttachError::Boot(boot::Error::Pci(error)) => Error::Pci(error),
                    attach::AttachError::Register(super::power::AccessError::Minimum(error))
                    | attach::AttachError::Power(super::power::Error::Access(
                        super::power::AccessError::Minimum(error),
                    ))
                    | attach::AttachError::Boot(boot::Error::Access(
                        super::power::AccessError::Minimum(error),
                    ))
                    | attach::AttachError::Boot(boot::Error::Power(super::power::Error::Access(
                        super::power::AccessError::Minimum(error),
                    ))) => Error::Pci(crate::block::BlockError::PciPower(error)),
                    error => Error::Restart(format!("{error}")),
                });
                self.reported = false;
                self.stage = Stage::Failed {
                    owner: Box::new(()),
                };
                return false;
            }
        };
        self.stage = Stage::Rom(Box::new(boot));
        self.deadline = Some(self.clock.deadline(ALIVE_TIMEOUT_US));
        self.bios = Some(self.restart.bios.clone());
        self.database = Some(self.restart.database.clone());
        self.beacons = None;
        self.selected = None;
        self.eht = None;
        self.chains = (0, 0);
        self.address = Mac::default();
        self.error = None;
        self.reported = false;
        self.client = station::Client::new(unassigned());
        if first {
            self.client
                .unsupported("a reset of this function: it boots again without one");
        }
        true
    }

    /// As many failed boots as the list's `count`, just now.
    #[cfg(test)]
    pub(crate) fn spend_restarts(&mut self, count: usize) {
        self.restart.attempts.count = count;
        self.restart.attempts.last_us = self.clock.now_us();
    }

    /// Whether a function reset was asked for and not there.
    #[cfg(test)]
    pub(crate) fn no_reset(&self) -> bool {
        self.restart.no_reset
    }

    /// The station address the NVM holds, once read.
    pub fn address(&self) -> Mac {
        self.address
    }

    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }

    /// The network the scan chose, once it has.
    pub fn selected(&self) -> Option<&Selected> {
        self.selected.as_ref()
    }

    pub fn phase(&self) -> Phase {
        match &self.stage {
            _ if self.error.is_some() => Phase::Failed,
            Stage::Rom(_)
            | Stage::Pnvm(_)
            | Stage::Nvm(_)
            | Stage::Radio(_)
            | Stage::Lari(_)
            | Stage::Setup(_)
            | Stage::Mcc(_) => Phase::Booting,
            Stage::ScanConfiguration(_) | Stage::Board(_) | Stage::Country(_) | Stage::Mac(_) => {
                Phase::Initializing
            }
            Stage::Scan(_) => Phase::Scanning,
            Stage::Phy(_)
            | Stage::Power(_)
            | Stage::Link(_)
            | Stage::Peer(_)
            | Stage::Queue(_)
            | Stage::Coexistence(_)
            | Stage::Removing(_)
            | Stage::Unlinking(_)
            | Stage::Unbinding(_) => Phase::Joining,
            Stage::Ready(_) => Phase::AuthenticationRequired,
            Stage::Failed { .. } | Stage::Moving => Phase::Failed,
        }
    }

    /// Advance bring-up by at most one firmware step, never blocking.
    pub fn poll(&mut self) -> Phase {
        if self.error.is_none() {
            let stage = core::mem::replace(&mut self.stage, Stage::Moving);
            // SAFETY: `new`'s contract covers every page and service handed on.
            self.stage = match unsafe { self.step(stage) } {
                Ok(stage) => stage,
                Err((error, kept)) => {
                    self.error = Some(error);
                    Stage::Failed { owner: kept }
                }
            };
        }
        self.phase()
    }

    /// The ROM boot the current owner nests, for device models.
    #[cfg(test)]
    pub(crate) fn rom(&self) -> Option<&RomBoot<'static, Q>> {
        match &self.stage {
            Stage::Rom(owner) | Stage::Pnvm(owner) => owner.rom(),
            Stage::Nvm(owner) => owner.rom(),
            Stage::Radio(owner) => owner.rom(),
            Stage::Lari(owner) => owner.rom(),
            Stage::Setup(owner) => owner.rom(),
            Stage::Mcc(owner) => owner.rom(),
            Stage::ScanConfiguration(owner) => owner.rom(),
            Stage::Board(owner) => owner.rom(),
            Stage::Country(owner) => owner.rom(),
            Stage::Mac(owner) => owner.rom(),
            Stage::Scan(owner) => owner.rom(),
            Stage::Phy(owner) => owner.rom(),
            Stage::Power(owner) => owner.rom(),
            Stage::Link(owner) => owner.rom(),
            Stage::Peer(owner) => owner.rom(),
            Stage::Queue(owner) | Stage::Ready(owner) | Stage::Removing(owner) => owner.rom(),
            Stage::Unlinking(owner) => owner.rom(),
            Stage::Unbinding(owner) => owner.rom(),
            Stage::Coexistence(owner) => owner.rom(),
            Stage::Failed { .. } | Stage::Moving => None,
        }
    }

    fn expired(&self) -> bool {
        self.deadline.as_ref().is_some_and(Deadline::passed)
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    unsafe fn step(&mut self, stage: Stage<Q, B>) -> Result<Stage<Q, B>, (Error, Box<dyn Kept>)> {
        let pages = self.pages;
        macro_rules! advance {
            ($owner:ident, $variant:ident, $error:ident, $done:expr, $next:expr) => {{
                // SAFETY: forwarded from `poll`.
                match unsafe { $owner.advance(pages) } {
                    Ok(phase) if phase == $done => $next,
                    Ok(_) => Ok(Stage::$variant($owner)),
                    Err(error) => Err((Error::$error(error), $owner as Box<dyn Kept>)),
                }
            }};
        }
        match stage {
            Stage::Rom(mut boot) => match boot.poll() {
                Ok(Some(alive)) => {
                    self.tables = Tables::of(&alive);
                    // SAFETY: forwarded from `poll`.
                    let begun = unsafe { boot.begin_pnvm(self.firmware, self.observations, pages) };
                    if begun.is_ok() {
                        self.degraded = degraded(&boot);
                    }
                    match begun {
                        Ok(PnvmProgress::Skipped | PnvmProgress::Observed) => Ok(self.nvm(*boot)),
                        Ok(PnvmProgress::Waiting) => {
                            self.deadline = Some(self.clock.deadline(PNVM_TIMEOUT_US));
                            Ok(Stage::Pnvm(boot))
                        }
                        Err(error) => Err((Error::Boot(error), boot)),
                    }
                }
                Ok(None) if self.expired() => Err((Error::Timeout("ALIVE"), boot)),
                Ok(None) => Ok(Stage::Rom(boot)),
                Err(error) => Err((Error::Boot(error), boot)),
            },
            Stage::Pnvm(mut boot) => match boot.poll_pnvm() {
                Ok(PnvmProgress::Observed | PnvmProgress::Skipped) => Ok(self.nvm(*boot)),
                Ok(PnvmProgress::Waiting) if self.expired() => Err((Error::Timeout("PNVM"), boot)),
                Ok(PnvmProgress::Waiting) => Ok(Stage::Pnvm(boot)),
                Err(error) => Err((Error::Boot(error), boot)),
            },
            Stage::Nvm(mut nvm) => {
                // SAFETY: forwarded from `poll`.
                match unsafe { nvm.advance(pages) } {
                    Ok(InitializationProgress::Observed) => {
                        self.address = Mac(nvm.receipt().map_or([0; 6], |r| r.address.bytes));
                        match Association::new(self.address) {
                            Ok(peer) => self.client = station::Client::new(peer),
                            Err(error) => return Err((Error::Station(error), nvm)),
                        }
                        for left in core::mem::take(&mut self.degraded) {
                            self.client.unsupported(left);
                        }
                        match nvm.begin_radio() {
                            Ok(radio) => Ok(Stage::Radio(Box::new(radio))),
                            Err(nvm) => Err((Error::Refused("cold radio"), nvm)),
                        }
                    }
                    Ok(InitializationProgress::Pending(_)) => Ok(Stage::Nvm(nvm)),
                    Err(error) => Err((Error::Boot(error), nvm)),
                }
            }
            Stage::Radio(mut radio) => {
                // SAFETY: forwarded from `poll`.
                match unsafe { radio.advance(pages) } {
                    Ok(ColdRadioPhase::PlatformConfigurationRequired) => {
                        let bios = self
                            .bios
                            .take()
                            .ok_or((Error::Refused("LARI"), Box::new(()) as Box<dyn Kept>))?;
                        // SAFETY: `bios` reads this function's companion (`new`).
                        match unsafe { radio.begin_lari(bios) } {
                            Ok(lari) => Ok(Stage::Lari(Box::new(lari))),
                            Err(kept) => Err((Error::Refused("LARI"), kept)),
                        }
                    }
                    Ok(_) => Ok(Stage::Radio(radio)),
                    Err(error) => Err((Error::Boot(error), radio)),
                }
            }
            Stage::Lari(mut lari) => {
                advance!(lari, Lari, Lari, LariPhase::RxQueueConfigurationRequired, {
                    let options = Ax200SetupOptions::new(self.clock);
                    self.save_power = options.power_mode == PowerMode::SavePower;
                    // SAFETY: the handoff clock is calibrated and advances.
                    match unsafe { lari.begin_ax200_setup(options) } {
                        Ok(setup) => Ok(Stage::Setup(Box::new(setup))),
                        Err(lari) => Err((Error::Refused("setup"), lari as Box<dyn Kept>)),
                    }
                })
            }
            Stage::Setup(mut setup) => {
                advance!(setup, Setup, Setup, Ax200SetupPhase::RegulatoryRequired, {
                    match setup.begin_mcc() {
                        Ok(mcc) => Ok(Stage::Mcc(Box::new(mcc))),
                        Err(setup) => Err((Error::Refused("MCC"), setup as Box<dyn Kept>)),
                    }
                })
            }
            Stage::Mcc(mut mcc) => advance!(mcc, Mcc, Mcc, Ax200MccPhase::PolicyRequired, {
                match mcc.begin_scan_configuration() {
                    Ok(next) => Ok(Stage::ScanConfiguration(Box::new(next))),
                    Err(mcc) => Err((Error::Refused("scan configuration"), mcc as Box<dyn Kept>)),
                }
            }),
            Stage::ScanConfiguration(mut configuration) => advance!(
                configuration,
                ScanConfiguration,
                ScanConfiguration,
                Ax200ScanConfigurationPhase::BoardPolicyRequired,
                {
                    match configuration.begin_board_policy() {
                        Ok(board) => Ok(Stage::Board(Box::new(board))),
                        Err(kept) => Err((Error::Refused("board policy"), kept as Box<dyn Kept>)),
                    }
                }
            ),
            Stage::Board(mut board) => advance!(
                board,
                Board,
                Board,
                Ax200BoardPolicyPhase::CountryRequired,
                { self.country(board) }
            ),
            Stage::Country(mut country) => advance!(
                country,
                Country,
                Country,
                Ax200CountryPhase::MacContextRequired,
                {
                    match country.begin_mld_mac_context() {
                        Ok(mac) => Ok(Stage::Mac(Box::new(mac))),
                        Err(country) => {
                            Err((Error::Refused("MAC context"), country as Box<dyn Kept>))
                        }
                    }
                }
            ),
            Stage::Mac(mut mac) => {
                if let Err(error) = mac.replenish_completed_receive() {
                    return Err((Error::Boot(error), mac));
                }
                advance!(mac, Mac, Mac, Ax200MacPhase::ScanRequired, {
                    // SAFETY: `Regulatory` is both the country's selection and
                    // the lease, and no other path publishes to this function.
                    match unsafe { mac.begin_scan() } {
                        Ok(mut scan) => {
                            self.client.channels = scan.regulated_channels();
                            self.chains = scan.chains();
                            self.eht = scan.eht_limits();
                            #[cfg(test)]
                            {
                                self.eht = self.eht.or(self.assumed_eht);
                            }
                            self.client.eml_capable =
                                self.eht.is_some_and(|limits| !limits.dual_radio);
                            Ok(Stage::Scan(Box::new(scan)))
                        }
                        Err(mac) => Err((Error::Refused("scan"), mac as Box<dyn Kept>)),
                    }
                })
            }
            // SAFETY: forwarded from poll.
            Stage::Scan(scan) => unsafe { self.scan(scan) },
            Stage::Phy(mut phy) => advance!(phy, Phy, Phy, Ax200PhyPhase::BindingRequired, {
                // The owner floors the request to the country's ceiling.
                match phy.begin_transmit_power(u8::MAX) {
                    Ok(power) => Ok(Stage::Power(Box::new(power))),
                    Err(phy) => Err((Error::Refused("transmit power"), phy as Box<dyn Kept>)),
                }
            }),
            Stage::Power(mut power) => {
                advance!(
                    power,
                    Power,
                    Power,
                    Ax200TransmitPowerPhase::BindingRequired,
                    {
                        if let Err(error) = power.replenish_completed_receive() {
                            return Err((Error::Power(error), power));
                        }
                        let link = self.selected.as_ref().and_then(|selected| {
                            let affiliation = selected.affiliation?;
                            Some(StationLink {
                                address: affiliation.local,
                                id: affiliation.link_id,
                            })
                        });
                        // SAFETY: the same regulatory service and requester remain.
                        match unsafe { power.begin_mld_link(link) } {
                            Ok(link) => Ok(Stage::Link(Box::new(link))),
                            Err(power) => Err((Error::Refused("link"), power as Box<dyn Kept>)),
                        }
                    }
                )
            }
            Stage::Link(mut link) => {
                if let Err(error) = link.replenish_completed_receive() {
                    return Err((Error::Binding(error), link));
                }
                advance!(
                    link,
                    Link,
                    Binding,
                    Ax200BindingPhase::AuthenticationRequired,
                    {
                        let Some(selected) = &self.selected else {
                            return Err((Error::Refused("AP station"), link as Box<dyn Kept>));
                        };
                        let peer = LegacyPeer {
                            address: selected
                                .affiliation
                                .map_or(selected.bss.bssid, |link| link.mld.ap),
                            link: selected.bss.bssid,
                            beacon_interval_tu: selected.bss.beacon_interval,
                            rates: selected.rates,
                        };
                        // SAFETY: the rates are the selected AP's own.
                        match unsafe { link.begin_mld_peer(peer) } {
                            Ok(peer) => Ok(Stage::Peer(Box::new(peer))),
                            Err(link) => Err((Error::Refused("AP station"), link as Box<dyn Kept>)),
                        }
                    }
                )
            }
            Stage::Peer(mut peer) => {
                if let Err(error) = peer.replenish_completed_receive() {
                    return Err((Error::Peer(error), peer));
                }
                advance!(
                    peer,
                    Peer,
                    Peer,
                    Ax200LegacyPeerPhase::ManagementQueueRequired,
                    {
                        // SAFETY: no other queue, station or interrupt worker exists.
                        match unsafe { peer.begin_mld_management_queue() } {
                            Ok(queue) => Ok(Stage::Queue(Box::new(queue))),
                            Err(peer) => {
                                Err((Error::Refused("management queue"), peer as Box<dyn Kept>))
                            }
                        }
                    }
                )
            }
            Stage::Queue(mut queue) => {
                if let Err(error) = queue.replenish_completed_receive() {
                    return Err((Error::Queue(error), queue));
                }
                advance!(
                    queue,
                    Queue,
                    Queue,
                    Ax200ManagementQueuePhase::ManagementFramesRequired,
                    {
                        // SAFETY: as above.
                        match unsafe { queue.begin_mld_coexistence() } {
                            Ok(coexistence) => Ok(Stage::Coexistence(Box::new(coexistence))),
                            Err(queue) => {
                                Err((Error::Refused("coexistence"), queue as Box<dyn Kept>))
                            }
                        }
                    }
                )
            }
            Stage::Coexistence(mut coexistence) => {
                if let Err(error) = coexistence.replenish_completed_receive() {
                    return Err((Error::Coexistence(error), coexistence));
                }
                advance!(
                    coexistence,
                    Coexistence,
                    Coexistence,
                    Ax200CoexistencePhase::ManagementFramesRequired,
                    {
                        match coexistence.into_queue() {
                            Ok(queue) => Ok(Stage::Ready(Box::new(queue))),
                            Err(kept) => {
                                Err((Error::Refused("management frames"), kept as Box<dyn Kept>))
                            }
                        }
                    }
                )
            }
            Stage::Ready(mut queue) => {
                if let Err(error) = queue.replenish_completed_receive() {
                    return Err((Error::Queue(error), queue));
                }
                Ok(Stage::Ready(queue))
            }
            Stage::Removing(mut queue) => {
                if let Err(error) = queue.replenish_completed_receive() {
                    return Err((Error::Queue(error), queue));
                }
                advance!(
                    queue,
                    Removing,
                    Queue,
                    Ax200ManagementQueuePhase::Removed,
                    {
                        match (*queue).into_binding() {
                            Ok(mut link) => match link.begin_remove() {
                                Ok(()) => Ok(Stage::Unlinking(Box::new(link))),
                                Err(error) => {
                                    Err((Error::Binding(error), Box::new(link) as Box<dyn Kept>))
                                }
                            },
                            Err(queue) => Err((Error::Refused("link"), queue as Box<dyn Kept>)),
                        }
                    }
                )
            }
            Stage::Unlinking(mut link) => {
                if let Err(error) = link.replenish_completed_receive() {
                    return Err((Error::Binding(error), link));
                }
                advance!(link, Unlinking, Binding, Ax200BindingPhase::Unbound, {
                    let power = match (*link).into_transmit_power() {
                        Ok(power) => power,
                        Err(link) => return Err((Error::Refused("power"), link)),
                    };
                    match power.into_phy_context() {
                        Ok(mut phy) => match phy.begin_remove() {
                            Ok(()) => Ok(Stage::Unbinding(Box::new(phy))),
                            Err(error) => Err((Error::Phy(error), Box::new(phy) as Box<dyn Kept>)),
                        },
                        Err(power) => Err((Error::Refused("PHY"), power as Box<dyn Kept>)),
                    }
                })
            }
            Stage::Unbinding(mut phy) => {
                advance!(phy, Unbinding, Phy, Ax200PhyPhase::Removed, {
                    match (*phy).into_scan() {
                        Ok(scan) => {
                            self.selected = None;
                            self.client.left();
                            Ok(Stage::Scan(Box::new(scan)))
                        }
                        Err(phy) => Err((Error::Refused("scan"), phy as Box<dyn Kept>)),
                    }
                })
            }
            failed @ Stage::Failed { .. } => Ok(failed),
            Stage::Moving => Err((Error::Refused("bring-up"), Box::new(()))),
        }
    }

    fn nvm(&mut self, boot: RomBoot<'static, Q>) -> Stage<Q, B> {
        self.deadline = None;
        Stage::Nvm(Box::new(boot.initialize_on_device_nvm()))
    }

    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    fn country(
        &mut self,
        board: Box<Ax200BoardPolicy<'static, Q, B>>,
    ) -> Result<Stage<Q, B>, (Error, Box<dyn Kept>)> {
        // `iwl_mvm_init_mcc` leaves the BIOS country, else the current one.
        let firmware = board.profiles().last().map(|profile| profile.country);
        // Every BIOS read of this boot is behind the board policy. Linux
        // takes one that could not answer as an absent table.
        if board
            .platform_reads()
            .iter()
            .any(super::radio::bios::service::Read::incomplete)
        {
            self.client.unsupported(
                "the platform's Wi-Fi ACPI or UEFI settings it could not read: the radio runs without them",
            );
        }
        let Some(database) = self.database.take() else {
            return Err((Error::Refused("country"), board));
        };
        let regulatory = match Regulatory::select(database, self.network.country, firmware) {
            Ok(regulatory) => regulatory,
            Err(error) => return Err((Error::Regulatory(error), board)),
        };
        self.beacons = Some(regulatory.beacons());
        self.client.regulatory = Some(regulatory.country().clone());
        // SAFETY: the selection belongs to this function's own adapter.
        match unsafe { board.begin_country(regulatory) } {
            Ok(country) => Ok(Stage::Country(Box::new(country))),
            Err(kept) => Err((Error::Refused("country"), Box::new(kept) as Box<dyn Kept>)),
        }
    }

    /// One scan step: hear the running scan's beacons. The keeper starts and
    /// retires scans.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    unsafe fn scan(
        &mut self,
        mut scan: Box<Ax200Scan<'static, Q, B, Regulatory>>,
    ) -> Result<Stage<Q, B>, (Error, Box<dyn Kept>)> {
        let pages = self.pages;
        if let Err(error) = scan.replenish_completed_receive() {
            return Err((Error::Boot(error), scan));
        }
        while scan.take_other_notification().is_some() {}
        if matches!(scan.phase(), Ax200ScanPhase::Scanning) {
            loop {
                match scan.poll_result() {
                    Ok(ScanResultProgress::Observed(result)) => {
                        if let Ok(bss) = result.result() {
                            self.observe(bss);
                            for nontransmitted in multiple_bssid::nontransmitted(bss) {
                                self.observe(&nontransmitted);
                            }
                        }
                    }
                    Ok(ScanResultProgress::Rejected(_)) => {}
                    Ok(ScanResultProgress::Pending | ScanResultProgress::Backpressure { .. }) => {
                        break;
                    }
                    Err(error) => return Err((Error::Scan(error), scan)),
                }
            }
        }
        if matches!(
            scan.phase(),
            Ax200ScanPhase::NotStarted | Ax200ScanPhase::DrainRequired
        ) {
            return Ok(Stage::Scan(scan));
        }
        // SAFETY: forwarded from `poll`.
        match unsafe { scan.advance(pages) } {
            Ok(_) => Ok(Stage::Scan(scan)),
            Err(error) => Err((Error::Scan(error), scan)),
        }
    }

    /// Keep `bss`, the latest of each BSS: a scan's beacons replace its
    /// earlier ones, as `cfg80211_bss_update` does.
    fn observe(&mut self, bss: &Bss) {
        // `cfg80211_inform_single_bss_data` hints every ESS beacon's channel.
        if bss.capabilities & 1 != 0
            && let Some(beacons) = &self.beacons
        {
            beacons.heard(bss.channel);
        }
        let known = self
            .client
            .observed
            .iter()
            .position(|known| known.observation.bss().bssid == bss.bssid);
        let mut latest = bss.clone();
        if let Some(known) = known {
            latest.keep_name_of(self.client.observed[known].observation.bss());
        }
        let heard = station::Heard {
            observation: Arc::new(association::NativeBssObservation { bss: latest }),
            at: self.clock.now_us(),
        };
        match known {
            Some(known) => self.client.observed[known] = heard,
            None => self.client.observed.push(heard),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_function_gets_linux_s_attempts_a_wait_and_a_fresh_list_after_quiet() {
        let mut attempts = Attempts::default();
        for second in 1..=RESTARTS as u64 {
            assert!(attempts.allow(second * 1_000_000), "attempt {second}");
        }
        let end = RESTARTS as u64 * 1_000_000;
        assert!(!attempts.allow(end + 1), "the list ran out");
        assert!(!attempts.allow(end + RESTART_DELAY_US), "the wait holds");
        assert!(attempts.allow(end + 1 + RESTART_DELAY_US), "it ended");
        assert!(
            !attempts.allow(end + 2 + RESTART_DELAY_US),
            "the wait again"
        );
        let quiet = end + 2 * RESTART_DELAY_US + RESTART_OK_US + 3;
        assert!(attempts.allow(quiet), "the wait ended");
        assert!(
            attempts.allow(quiet + RESTART_OK_US),
            "the list began again"
        );
        assert_eq!(attempts.count, 1);
    }

    #[test]
    fn the_fourth_and_fifth_attempts_reset_the_function() {
        let mut attempts = Attempts::default();
        let resets: Vec<bool> = (1..=RESTARTS as u64)
            .map(|second| {
                attempts.allow(second * 1_000_000);
                attempts.resets()
            })
            .collect();
        assert_eq!(resets, [false, false, false, true, true]);
    }

    #[test]
    fn legacy_rates_read_both_rate_elements_and_drop_cck_at_5_ghz() {
        let elements = [0, 1, b'x', 1, 4, 0x82, 0x84, 0x8b, 0x96, 50, 2, 12, 108];
        assert_eq!(legacy_rates(&elements, Band::Ghz2), 0b1000_0001_1111);
        assert_eq!(legacy_rates(&elements, Band::Ghz5), 0b1000_0001_0000);
        assert_eq!(legacy_rates(&[1, 9, 2], Band::Ghz2), 0);
    }
}
