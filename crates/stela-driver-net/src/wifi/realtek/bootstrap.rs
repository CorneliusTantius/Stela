// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! One claimed RTL8822C function brought up as `rtw_chip_info_setup` and
//! `rtw_power_on` bring it up, in one power cycle: `rtw_chip_efuse_enable` boots
//! firmware only to read the hardware report and OTP, and powers off again
//! before the real start, where this keeps the firmware it booted.
//!
//! The bring-up is one `async` function: attach runs it to completion with
//! [`block_on`], and a chip reset ([`super::hardware::Hardware`]'s recovery)
//! runs the same function a step per poll. Each wait ends a step at its
//! deadline and each command or table delay is followed by a yield, so no
//! step holds the CPU past one bounded wait.
use super::{
    beacon::{Beacon, FirmwareBand},
    coex::{Coex, Order},
    download::Download,
    efuse::{self, Board, Physical},
    features::Report,
    fifo::Geometry,
    firmware::Layout,
    firmware_control::Control,
    hci,
    identity::{Observed, Profile, Staged},
    interrupt::Controller,
    io::{Bar, Io, NativeIo},
    link::Link,
    phy::{self, PhyInitialized, source_mac},
    power,
    quirks::Disabled,
    receive, transmit,
};
use crate::{
    Clock, Mac,
    bus::dma::{mapping::DmaDomain, memory::PageSource},
    firmware::Provider,
    wifi::stepped::{block_on, yield_now},
};
use alloc::{format, string::String, sync::Arc};
use core::{any::Any, fmt, fmt::Debug, ptr::NonNull};

/// `RTW_SEC_CONFIG`.
const REG_SECURITY: u32 = 0x680;
/// `RTW_SEC_TX_DEC_EN | RTW_SEC_RX_DEC_EN` and default-key search both ways.
const SECURITY_ENGINE: u16 = (1 << 2) | (1 << 3) | (1 << 0) | (1 << 1) | (1 << 6) | (1 << 7);
/// `RTW_SEC_ENGINE_EN` in `REG_CR`.
const SECURITY_ENABLE: u16 = 1 << 9;
/// `REG_RCR`.
pub const REG_RCR: u32 = 0x608;
/// mac80211's receive filter on rtw88's default: every frame with FCS, MIC, ICV
/// and PHY status, with broadcast, multicast and unicast-to-us management.
pub const RECEIVE_FILTER: u32 = (1 << 31)
    | (1 << 30)
    | (1 << 29)
    | (1 << 20)
    | (1 << 14)
    | (1 << 28)
    | (1 << 3)
    | (1 << 2)
    | (1 << 1);

/// The register interface firmware download and the PHY share.
pub type Native = NativeIo<Beacon<Bar>>;

/// The claimed function and the services its bring-up borrows. A chip reset
/// brings the function up again from the same claim.
#[derive(Clone)]
pub struct Claim {
    /// The exclusive uncached BAR.
    pub window: NonNull<u8>,
    pub bytes: usize,
    /// Keeps the PCI claim and the mapping.
    pub owner: Arc<dyn Any>,
    pub clock: Clock,
    pub pages: &'static dyn PageSource,
    pub domain: Arc<dyn DmaDomain>,
    pub firmware: &'static dyn Provider,
    pub observed: Observed,
    /// The function's PCIe Link Control.
    pub link_control: u16,
}

/// What failed, and at which step of the bring-up.
#[derive(Debug)]
pub struct Error {
    pub step: &'static str,
    pub detail: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.step, self.detail)
    }
}

fn at<E: Debug>(step: &'static str) -> impl FnOnce(E) -> Error {
    move |error| Error {
        step,
        detail: format!("{error:?}"),
    }
}

/// An RTL8822C with firmware running, its MAC configured and its PHY loaded.
pub struct Up {
    pub profile: Profile,
    pub control: Control<Native>,
    pub interrupts: Controller<Bar>,
    pub receive: receive::Ring<Bar>,
    pub transmit: transmit::Rings<Bar>,
    pub phy: PhyInitialized,
    pub coex: Coex,
    pub report: Report,
    /// `fw->feature`.
    pub features: u32,
    pub board: Board,
    pub physical: Physical,
    pub geometry: Geometry,
    pub mac: Mac,
    pub clock: Clock,
    pub pages: &'static dyn PageSource,
    pub link: Link,
    /// What `rtw_pci_quirks` turns off on this system.
    pub disabled: Disabled,
    /// What a chip reset brings the function up again from.
    pub claim: Claim,
}

/// The rings beside the registers, which the bring-up hands to the chip
/// at the points `rtw_power_on` and `rtw_core_start` do.
pub(super) trait Rings<I> {
    /// `rtw_pci_setup`, after the power sequence: reset every queue's
    /// indices, which a chip reset finds where the boot before left them,
    /// then install and bind the data rings.
    ///
    /// # Safety
    /// [`hci::setup`]'s contract, for `io`'s requester.
    async unsafe fn bind(&mut self, io: &mut I) -> Result<(), Error>;
    /// Arm the interrupt block, then `rtw_fw_send_general_info` and
    /// `rtw_fw_send_phydm_info` through the transmit ring.
    ///
    /// # Safety
    /// `phy` and `report` come from this boot, with HCI started.
    unsafe fn inform(
        &mut self,
        geometry: Geometry,
        phy: &PhyInitialized,
        report: &Report,
    ) -> Result<(), Error>;
}

/// The rings of a claimed function, installed once the power sequence has
/// stopped whatever the chip ran before.
struct Claimed<'a> {
    pages: &'static dyn PageSource,
    domain: Arc<dyn DmaDomain>,
    bar: &'a dyn Fn() -> Result<Bar, Error>,
    receive: Option<receive::Ring<Bar>>,
    transmit: Option<transmit::Rings<Bar>>,
    interrupts: Option<Controller<Bar>>,
}

impl Rings<Native> for Claimed<'_> {
    async unsafe fn bind(&mut self, io: &mut Native) -> Result<(), Error> {
        hci::reset_indices(io).map_err(at("ring indices"))?;
        // SAFETY: the caller's requester, its indices zero and its DMA
        // stopped by the power sequence. Each ring's pages are mapped in a
        // step of their own.
        let receive =
            unsafe { receive::Ring::install((self.bar)()?, self.pages, self.domain.clone()) }
                .map_err(at("receive ring"))?;
        let receive = self.receive.insert(receive);
        yield_now().await;
        // SAFETY: as above.
        let transmit =
            unsafe { transmit::Rings::install((self.bar)()?, self.pages, self.domain.clone()) }
                .map_err(at("transmit rings"))?;
        let transmit = self.transmit.insert(transmit);
        yield_now().await;
        // SAFETY: forwarded from the caller.
        unsafe { hci::setup(io, receive, transmit) }.map_err(at("hci"))
    }

    unsafe fn inform(
        &mut self,
        geometry: Geometry,
        phy: &PhyInitialized,
        report: &Report,
    ) -> Result<(), Error> {
        self.interrupts = Some(Controller::new((self.bar)()?).map_err(at("interrupts"))?);
        let transmit = self
            .transmit
            .as_mut()
            .ok_or_else(|| at("general info")("unbound"))?;
        transmit
            .general_info(self.pages, geometry)
            .map_err(at("general info"))?;
        // SAFETY: forwarded from the caller.
        unsafe { transmit.phydm_info(self.pages, phy, report) }.map_err(at("phydm info"))
    }
}

/// What [`boot`] leaves running on the registers.
pub(super) struct Booted<I: Io> {
    pub control: Control<I>,
    pub phy: PhyInitialized,
    pub coex: Coex,
    pub report: Report,
    pub board: Board,
    pub physical: Physical,
    pub geometry: Geometry,
    pub mac: Mac,
    pub link: Link,
    pub disabled: Disabled,
}

/// `rtw_chip_info_setup`, then `rtw_power_on` and `rtw_core_start`, run to
/// completion.
///
/// # Safety
/// `claim.window` is the exclusive uncached BAR of the RTL8822C `claim.observed`
/// describes, with its DMA and interrupts quiet and its indices zero;
/// `claim.domain` isolates that requester, and `claim.pages` is coherent
/// write-back RAM. The caller keeps the claim for as long as the device runs.
pub unsafe fn bring_up(claim: Claim) -> Result<Up, Error> {
    // SAFETY: forwarded from the caller.
    block_on(unsafe { start(claim) })
}

/// [`bring_up`] as stepped work. The power sequence resets whatever an
/// earlier boot or a dropped attempt left on the chip.
///
/// # Safety
/// As [`bring_up`]. For a chip reset, the rings of the boot before stay
/// mapped (each ring keeps its pages once configured), so DMA the reset
/// stops lands in memory nothing else uses.
pub async unsafe fn start(claim: Claim) -> Result<Up, Error> {
    let Claim {
        window,
        bytes,
        owner,
        clock,
        pages,
        domain,
        firmware,
        observed,
        link_control,
    } = claim.clone();
    let profile = Profile::select(observed).map_err(at("identity"))?;
    let staged = profile.stage(firmware).map_err(at("firmware"))?;
    let features = match &staged.layout {
        Layout::Rtw88(image) => image.features(),
        Layout::Rtw89(_) => 0,
    };
    let bar = || {
        // SAFETY: the caller's claim; each block reaches registers of its own.
        unsafe { Bar::new(window, bytes, profile, owner.clone()) }.map_err(at("bar"))
    };
    // SAFETY: the caller's requester, domain and pages; the beacon ring
    // keeps no index the chip moves, and firmware download is its first use.
    let queue = unsafe { Beacon::install(bar()?, pages, domain.clone(), FirmwareBand::Ghz2) }
        .map_err(at("beacon ring"))?;
    yield_now().await;
    // SAFETY: as above, with the beacon queue fresh and idle; `boot` runs
    // the power sequence first.
    let io = unsafe { NativeIo::unpowered(window, bytes, queue, owner.clone(), clock, profile) }
        .map_err(at("registers"))?;
    let mut rings = Claimed {
        pages,
        domain,
        bar: &bar,
        receive: None,
        transmit: None,
        interrupts: None,
    };
    // SAFETY: the caller's claim, with these rings its only queues.
    let booted = unsafe { boot(io, &mut rings, profile, &staged, firmware, link_control) }.await?;
    let unbound = || at("rings")("unbound");
    let receive = rings.receive.take().ok_or_else(unbound)?;
    let transmit = rings.transmit.take().ok_or_else(unbound)?;
    let interrupts = rings
        .interrupts
        .take()
        .ok_or_else(|| at("interrupts")("unarmed"))?;
    let Booted {
        control,
        phy,
        coex,
        report,
        board,
        physical,
        geometry,
        mac,
        link,
        disabled,
    } = booted;
    Ok(Up {
        profile,
        control,
        interrupts,
        receive,
        transmit,
        phy,
        coex,
        report,
        features,
        board,
        physical,
        geometry,
        mac,
        clock,
        pages,
        link,
        disabled,
        claim,
    })
}

/// The register half of [`start`] on `io`, from the power sequence to the
/// arbiter's first commands, with `rings` bound and told where rtw88 does.
///
/// # Safety
/// `io` is the exclusive register interface of the RTL8822C `profile` names,
/// with MAC power in any state, and `rings` are its only queues, fresh and
/// idle. `staged` is that profile's firmware from `firmware`.
pub(super) async unsafe fn boot<I: Io, R: Rings<I>>(
    mut io: I,
    rings: &mut R,
    profile: Profile,
    staged: &Staged<'_>,
    firmware: &dyn Provider,
    link_control: u16,
) -> Result<Booted<I>, Error> {
    // SAFETY: the caller's exclusive, quiet requester.
    unsafe { power::on(&mut io) }
        .await
        .map_err(at("power on"))?;
    // SAFETY: as above; no firmware payload is outstanding yet.
    unsafe { rings.bind(&mut io) }.await?;
    let boundary = Geometry::for_profile(profile)
        .map_err(at("fifo geometry"))?
        .boundary();
    let mut download = Download::new(&mut io, boundary).map_err(at("download"))?;
    download
        .start_with_hardware_features(staged)
        .await
        .map_err(at("firmware download"))?;
    let report = download
        .hardware_features()
        .await
        .map_err(at("hardware report"))?;
    drop(download);
    // SAFETY: firmware is running and nothing else touches the requester.
    let physical = unsafe { efuse::read(&mut io) }.await.map_err(at("efuse"))?;
    let board = physical.logical().map_err(at("efuse map"))?.board();
    let mac = Mac(board.valid_mac().map_err(at("mac address"))?);
    // SAFETY: the MAC, tables, paths and calibrations of one uninterrupted
    // boot, in `rtw_mac_init` and `rtw8822c_phy_set_param`'s order, each on
    // the state the one before it left.
    let (mac_state, phy) = unsafe {
        let mac_state = source_mac::initialize(&mut io, &report).map_err(at("mac init"))?;
        yield_now().await;
        let loaded = phy::initialize(&mut io, &board, &report)
            .await
            .map_err(at("phy tables"))?;
        let paths = loaded
            .configure_paths(&mut io, &report)
            .map_err(at("phy paths"))?;
        yield_now().await;
        let initial = paths
            .initialize_dynamic(&mut io, &report)
            .map_err(at("phy dynamics"))?;
        yield_now().await;
        let phy = initial
            .calibrate_dac(&mut io, &report)
            .await
            .map_err(at("dac calibration"))?
            .initialize_factory(&mut io, &report, &physical)
            .await
            .map_err(at("factory trim"))?
            .finish_initial_phy(&mut io, &report)
            .map_err(at("phy tail"))?;
        (mac_state, phy)
    };
    yield_now().await;
    let geometry = mac_state.fifo();
    let disabled = Disabled::load(firmware);
    let link = Link::configure(
        &mut io,
        profile.cut(),
        board.raw().rfe_raw,
        link_control,
        !disabled.aspm,
    )
    .map_err(at("pcie link"))?;
    // SAFETY: the same boot's PHY and report, with HCI started.
    unsafe { rings.inform(geometry, &phy, &report) }?;
    yield_now().await;
    let mut coex = Coex::new(&board);
    coex.power_on(&mut io).map_err(at("coex power on"))?;
    yield_now().await;
    // SAFETY: firmware runs, the PHY is loaded and nothing transmits yet.
    let run = unsafe { coex.init(&mut io, &report) }.map_err(at("coex"))?;
    // Past the bring-up, the arbiter's waits are bounded per call.
    coex.bound_waits();
    yield_now().await;
    // rtw_sec_enable_sec_engine, and rtw_core_start's receive filter.
    let enable = |io: &mut I| -> Result<(), super::io::Error> {
        let control = io.read16(super::registers::REG_CR)?;
        io.write16(super::registers::REG_CR, control | SECURITY_ENABLE)?;
        let security = io.read16(REG_SECURITY)?;
        io.write16(REG_SECURITY, security | SECURITY_ENGINE)?;
        io.write32(REG_RCR, RECEIVE_FILTER)
    };
    enable(&mut io).map_err(at("security engine"))?;
    // SAFETY: firmware booted once on this requester, with its mailbox unused.
    let mut control = unsafe { Control::new(io, &report) }.map_err(at("mailbox"))?;
    for order in run.orders {
        // A chip starting up has no power save to leave.
        if let Order::Command(command) = order {
            control.command(command).map_err(at("coex command"))?;
            yield_now().await;
        }
    }
    Ok(Booted {
        control,
        phy,
        coex,
        report,
        board,
        physical,
        geometry,
        mac,
        link,
        disabled,
    })
}

#[cfg(test)]
mod tests;
