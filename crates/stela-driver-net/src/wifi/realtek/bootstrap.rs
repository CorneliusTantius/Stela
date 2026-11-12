// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! One claimed RTL8822C function brought up as `rtw_chip_info_setup` and
//! `rtw_power_on` bring it up, in one power cycle: `rtw_chip_efuse_enable` boots
//! firmware only to read the hardware report and OTP, and powers off again
//! before the real start, where this keeps the firmware it booted.
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
    identity::{Observed, Profile},
    interrupt::Controller,
    io::{Bar, Io, NativeIo},
    link::Link,
    phy::{self, PhyInitialized, source_mac},
    quirks::Disabled,
    receive, transmit,
};
use crate::{
    Clock, Mac,
    bus::dma::{mapping::DmaDomain, memory::PageSource},
    firmware::Provider,
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

/// The claimed function and the services its bring-up borrows.
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
}

/// `rtw_chip_info_setup`, then `rtw_power_on` and `rtw_core_start`.
///
/// # Safety
/// `claim.window` is the exclusive uncached BAR of the RTL8822C `claim.observed`
/// describes, with its DMA and interrupts quiet and its indices zero;
/// `claim.domain` isolates that requester, and `claim.pages` is coherent
/// write-back RAM. The caller keeps the claim for as long as the device runs.
pub unsafe fn bring_up(claim: Claim) -> Result<Up, Error> {
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
    } = claim;
    let profile = Profile::select(observed).map_err(at("identity"))?;
    let staged = profile.stage(firmware).map_err(at("firmware"))?;
    let features = match &staged.layout {
        Layout::Rtw88(image) => image.features(),
        Layout::Rtw89(_) => 0,
    };
    let bar = || {
        // SAFETY: the caller's claim; each block reaches registers of its own.
        unsafe { Bar::new(window, bytes, profile, owner.clone()) }
    };
    // SAFETY: the caller's quiet requester, domain and pages.
    let (queue, mut receive, mut transmit) = unsafe {
        (
            Beacon::install(
                bar().map_err(at("bar"))?,
                pages,
                domain.clone(),
                FirmwareBand::Ghz2,
            )
            .map_err(at("beacon ring"))?,
            receive::Ring::install(bar().map_err(at("bar"))?, pages, domain.clone())
                .map_err(at("receive ring"))?,
            transmit::Rings::install(bar().map_err(at("bar"))?, pages, domain)
                .map_err(at("transmit rings"))?,
        )
    };
    // SAFETY: as above, with every queue fresh and idle.
    let mut io =
        unsafe { NativeIo::power_on_new(window, bytes, queue, owner.clone(), clock, profile) }
            .map_err(at("power on"))?;
    // SAFETY: as above; no firmware payload is outstanding yet.
    unsafe { hci::setup(&mut io, &mut receive, &mut transmit) }.map_err(at("hci"))?;
    let boundary = Geometry::for_profile(profile)
        .map_err(at("fifo geometry"))?
        .boundary();
    let mut download = Download::new(&mut io, boundary).map_err(at("download"))?;
    download
        .start_with_hardware_features(&staged)
        .map_err(at("firmware download"))?;
    let report = download
        .hardware_features()
        .map_err(at("hardware report"))?;
    drop(download);
    // SAFETY: firmware is running and nothing else touches the requester.
    let physical = unsafe { efuse::read(&mut io) }.map_err(at("efuse"))?;
    let board = physical.logical().map_err(at("efuse map"))?.board();
    let mac = Mac(board.valid_mac().map_err(at("mac address"))?);
    // SAFETY: the MAC, tables, paths and calibrations of one uninterrupted
    // boot, in `rtw_mac_init` and `rtw8822c_phy_set_param`'s order, each on
    // the state the one before it left.
    let (mac_state, phy) = unsafe {
        let mac_state = source_mac::initialize(&mut io, &report).map_err(at("mac init"))?;
        let phy = phy::initialize(&mut io, &board, &report)
            .map_err(at("phy tables"))?
            .configure_paths(&mut io, &report)
            .map_err(at("phy paths"))?
            .initialize_dynamic(&mut io, &report)
            .map_err(at("phy dynamics"))?
            .calibrate_dac(&mut io, &report)
            .map_err(at("dac calibration"))?
            .initialize_factory(&mut io, &report, &physical)
            .map_err(at("factory trim"))?
            .finish_initial_phy(&mut io, &report)
            .map_err(at("phy tail"))?;
        (mac_state, phy)
    };
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
    let interrupts = Controller::new(bar().map_err(at("bar"))?).map_err(at("interrupts"))?;
    transmit
        .general_info(pages, geometry)
        .map_err(at("general info"))?;
    // SAFETY: the same boot's PHY and report, with HCI started.
    unsafe { transmit.phydm_info(pages, &phy, &report) }.map_err(at("phydm info"))?;
    let mut coex = Coex::new(board.raw());
    coex.power_on(&mut io).map_err(at("coex power on"))?;
    // SAFETY: firmware runs, the PHY is loaded and nothing transmits yet.
    let run = unsafe { coex.init(&mut io, &report) }.map_err(at("coex"))?;
    // rtw_sec_enable_sec_engine, and rtw_core_start's receive filter.
    let enable = |io: &mut Native| -> Result<(), super::io::Error> {
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
        }
    }
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
    })
}
