// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Concrete source post-download FIFO/MAC protocol/driver-info/PCI setup:
//! `rtw_mac_init` with the chip's own `mac_init`. Must precede the source PHY
//! table sequence; no radio or TX admission.
mod data;
use super::super::{chip::rtl8821c, fifo, identity::Chip};
use super::{Attempt, Error, Io, Report};
use data::*;
#[derive(Debug)]
pub struct Initialized {
    fifo: fifo::Geometry,
    rx_filter_map1: u16,
}
impl Initialized {
    pub fn fifo(&self) -> fifo::Geometry {
        self.fifo
    }
    pub fn rx_filter_map1(&self) -> u16 {
        self.rx_filter_map1
    }
}
/// Execute the source post-download FIFO, chip protocol initialization,
/// RX PHY-status/driver-info configuration and PCI cut-dependent interface bit.
///
/// # Safety
/// Same kept native requester/reset/firmware epoch and Report/Io,
/// not matching fingerprints alone. Firmware download/ready and full
/// native HCI descriptor/index/domain setup with all live rings/pins completed;
/// all FIFO::configure safety requirements hold. Keep full BAR/claims/DMA
/// pins/native calibrated clock. This runs once before source PHY tables;
/// competing reset/IRQ/PHY/RF/FIFO/firmware workers and operational RX/TX are
/// stopped. Hold a real emission gate independent of TXPAUSE/CR/RCR
/// and autonomous ACK/beacon/retry controls modified here, e.g. the
/// disabled prior PHY/RF domain. Numeric policy or IRQ masking is not a gate.
/// Maintain that gate until real channel/power/RFK/EDCCA, retry/fallback
/// restrictions and OS policy are checked. Source TXPAUSE=0 and
/// beacon/filter/response setup confer no permission or DMA-stop proof.
/// Uncertainty/unwind keeps the quarantined owner. No boot/control
/// owner, policy service or IRQ framework is created by this function.
pub unsafe fn initialize<I: Io>(io: &mut I, report: &Report) -> Result<Initialized, Error> {
    let profile = io.profile();
    if profile.rtw88().is_none() || report.profile() != profile {
        return Err(Error::WrongProfile);
    }
    if profile.cut() > 6 {
        return Err(Error::UnsupportedCut(profile.cut()));
    }
    let cap = report.capabilities();
    let paths = super::rf_paths(profile);
    if cap.rf_phys != paths || cap.rf_paths != paths {
        return Err(Error::UnsupportedRfLayout);
    }
    // SAFETY: caller supplies the native HCI/rings/domain and
    // stopped firmware/IRQ workers, not an empty descriptor-base substitute.
    let fifo = unsafe { fifo::configure(io) }.map_err(Error::Fifo)?;
    let mut a = Attempt {
        io,
        profile,
        done: false,
    };
    a.verify()?;
    let rx_filter_map1 = protocol(&mut a)?;
    a.verify()?;
    a.done = true;
    Ok(Initialized {
        fifo,
        rx_filter_map1,
    })
}
fn update8<I: Io>(a: &mut Attempt<'_, I>, r: u32, set: u32, clear: u32) -> Result<(), Error> {
    let v = a.io.read8(r)?;
    a.io.write8(r, (u32::from(v) & !clear | set) as u8)?;
    Ok(())
}
fn update32<I: Io>(a: &mut Attempt<'_, I>, r: u32, set: u32, clear: u32) -> Result<(), Error> {
    let v = a.io.read32(r)?;
    a.io.write32(r, (v & !clear) | set)?;
    Ok(())
}
/// The chip's MAC body followed by source driver-info and PCI interface
/// phases. The prior FIFO/HCI ordering is established by initialize, not here.
pub(super) fn protocol<I: Io>(a: &mut Attempt<'_, I>) -> Result<u16, Error> {
    let filter = match a.profile.chip() {
        Chip::Rtl8822C => mac_init_8822c(a)?,
        Chip::Rtl8821C => {
            rtl8821c::mac_init(a.io)?;
            rtl8821c::RX_FILTER1
        }
        Chip::Rtl8852B => return Err(Error::WrongProfile),
    };
    // rtw_drv_info_cfg on a 3081 CPU chip.
    a.io.write8(REG_RX_DRVINFO_SZ, 4)?;
    let old = a.io.read8(REG_TRXFF_BNDY + 1)?;
    a.io.write8(REG_TRXFF_BNDY + 1, (old & 0xf0) | 0xf)?;
    update32(a, REG_RCR, BIT_APP_PHYSTS, 0)?;
    update32(a, REG_WMAC_OPTION_FUNCTION + 4, 0, (1 << 8) | (1 << 9))?;
    // rtw_pci_interface_cfg.
    let cut = a.profile.rtw88().and_then(|spec| spec.pcie_aux_clock_cut);
    if cut.is_some_and(|cut| a.profile.cut() >= cut) {
        a.modify32(REG_HCI_MIX_CFG, BIT_PCIE_EMAC_PDN_AUX_TO_FAST_CLK, 1)?;
    }
    Ok(filter)
}

/// `rtw8822c_mac_init`.
fn mac_init_8822c<I: Io>(a: &mut Attempt<'_, I>) -> Result<u16, Error> {
    macro_rules! w8 {
        ($r:expr,$v:expr) => {
            a.io.write8($r, ($v) as u8)?
        };
    }
    macro_rules! w16 {
        ($r:expr,$v:expr) => {
            a.io.write16($r, ($v) as u16)?
        };
    }
    macro_rules! w32 {
        ($r:expr,$v:expr) => {
            a.io.write32($r, $v)?
        };
    }
    // Preserve the source OR expression: it sets bit7 and does not clear bits1/2.
    update8(a, REG_FWHW_TXQ_CTRL, 0x80, 0)?;
    w8!(REG_FWHW_TXQ_CTRL + 1, WLAN_TXQ_RPT_EN);
    w16!(REG_SPEC_SIFS, WLAN_SIFS_DUR_TUNE);
    w32!(REG_SIFS, WLAN_SIFS_CFG);
    w16!(
        REG_RESP_SIFS_CCK,
        WLAN_SIFS_CCK_CTX | (WLAN_SIFS_CCK_IRX << 8)
    );
    w16!(
        REG_RESP_SIFS_OFDM,
        WLAN_SIFS_OFDM_CTX | (WLAN_SIFS_OFDM_IRX << 8)
    );
    for (r, v) in [
        (REG_DARFRC, WLAN_DATA_RATE_FB_CNT_1_4),
        (REG_DARFRCH, WLAN_DATA_RATE_FB_CNT_5_8),
        (REG_RARFRCH, WLAN_RTS_RATE_FB_CNT_5_8),
        (REG_ARFR0, WLAN_DATA_RATE_FB_RATE0),
        (REG_ARFRH0, WLAN_DATA_RATE_FB_RATE0_H),
        (REG_ARFR1_V1, WLAN_RTS_RATE_FB_RATE1),
        (REG_ARFRH1_V1, WLAN_RTS_RATE_FB_RATE1_H),
        (REG_ARFR4, WLAN_RTS_RATE_FB_RATE4),
        (REG_ARFRH4, WLAN_RTS_RATE_FB_RATE4_H),
        (REG_ARFR5, WLAN_RTS_RATE_FB_RATE5),
        (REG_ARFRH5, WLAN_RTS_RATE_FB_RATE5_H),
    ] {
        w32!(r, v);
    }
    w8!(REG_AMPDU_MAX_TIME_V1, WLAN_AMPDU_MAX_TIME);
    update8(a, REG_TX_HANG_CTRL, BIT_EN_EOF_V1, 0)?;
    let pre = WLAN_PRE_TXCNT_TIME_TH | BIT_EN_PRECNT;
    w8!(REG_PRECNT_CTRL, pre & 255);
    w8!(REG_PRECNT_CTRL + 1, pre >> 8);
    w32!(
        REG_PROT_MODE_CTRL,
        WLAN_RTS_LEN_TH
            | (WLAN_RTS_TX_TIME_TH << 8)
            | (WLAN_MAX_AGG_PKT_LIMIT << 16)
            | (WLAN_RTS_MAX_AGG_PKT_LIMIT << 24)
    );
    w16!(
        REG_BAR_MODE_CTRL + 2,
        WLAN_BAR_RETRY_LIMIT | (WLAN_RA_TRY_RATE_AGG_LIMIT << 8)
    );
    for (r, v) in [
        (REG_FAST_EDCA_VOVI_SETTING, FAST_EDCA_VO_TH),
        (REG_FAST_EDCA_VOVI_SETTING + 2, FAST_EDCA_VI_TH),
        (REG_FAST_EDCA_BEBK_SETTING, FAST_EDCA_BE_TH),
        (REG_FAST_EDCA_BEBK_SETTING + 2, FAST_EDCA_BK_TH),
    ] {
        w8!(r, v);
    }
    update8(a, REG_LIFETIME_EN, 0, BIT_BA_PARSER_EN)?;
    update32(a, REG_RRSR, 0, BITS_RRSR_RSC)?;
    for (r, v) in [
        (REG_EDCA_VO_PARAM, WLAN_EDCA_VO_PARAM),
        (REG_EDCA_VI_PARAM, WLAN_EDCA_VI_PARAM),
        (REG_EDCA_BE_PARAM, WLAN_EDCA_BE_PARAM),
        (REG_EDCA_BK_PARAM, WLAN_EDCA_BK_PARAM),
    ] {
        w32!(r, v);
    }
    w8!(REG_PIFS, WLAN_PIFS_TIME);
    update8(a, REG_TX_PTCL_CTRL + 1, 0, BIT_SIFS_BK_EN >> 8)?;
    update8(
        a,
        REG_RD_CTRL + 1,
        (BIT_DIS_TXOP_CFE | BIT_DIS_LSIG_CFE | BIT_DIS_STBC_CFE) >> 8,
        0,
    )?;
    update32(a, REG_AFE_CTRL1, 0, BIT_MAC_CLK_SEL)?;
    w8!(REG_USTIME_TSF, MAC_CLK_SPEED);
    w8!(REG_USTIME_EDCA, MAC_CLK_SPEED);
    update8(a, REG_MISC_CTRL, BIT_EN_FREE_CNT | BIT_DIS_SECOND_CCA, 0)?;
    update8(a, REG_TIMER0_SRC_SEL, 0, BIT_TSFT_SEL_TIMER0)?;
    w16!(REG_TXPAUSE, 0);
    w8!(REG_SLOT, WLAN_SLOT_TIME);
    w32!(REG_RD_NAV_NXT, WLAN_NAV_CFG);
    w16!(REG_RXTSF_OFFSET_CCK, WLAN_RX_TSF_CFG);
    update8(a, REG_BCN_CTRL, BIT_EN_BCN_FUNCTION, 0)?;
    w32!(REG_TBTT_PROHIBIT, WLAN_TBTT_TIME);
    for (r, v) in [
        (REG_DRVERLYINT, WLAN_DRV_EARLY_INT),
        (REG_BCN_CTRL_CLINT0, WLAN_BCN_CTRL_CLT0),
        (REG_BCNDMATIM, WLAN_BCN_DMA_TIME),
        (REG_BCN_MAX_ERR, WLAN_BCN_MAX_ERR),
    ] {
        w8!(r, v);
    }
    w32!(REG_MAR, WLAN_MULTI_ADDR);
    w32!(REG_MAR + 4, WLAN_MULTI_ADDR);
    for (r, v) in [
        (REG_BBPSF_CTRL + 2, WLAN_RESP_TXRATE),
        (REG_ACKTO, WLAN_ACK_TO),
        (REG_ACKTO_CCK, WLAN_ACK_TO_CCK),
    ] {
        w8!(r, v);
    }
    w16!(REG_EIFS, WLAN_EIFS_DUR_TUNE);
    w8!(REG_NAV_CTRL + 2, WLAN_NAV_MAX);
    w8!(REG_WMAC_TRXPTCL_CTL_H + 2, WLAN_BAR_ACK_TYPE);
    w16!(REG_RXFLTMAP0, WLAN_RX_FILTER0);
    w16!(REG_RXFLTMAP1, WLAN_RX_FILTER1);
    w16!(REG_RXFLTMAP2, WLAN_RX_FILTER2);
    w32!(REG_RCR, WLAN_RCR_CFG);
    w8!(REG_RX_PKT_LIMIT, WLAN_RXPKT_MAX_SZ_512);
    w8!(REG_TCR + 2, WLAN_TX_FUNC_CFG2);
    w8!(REG_TCR + 1, WLAN_TX_FUNC_CFG1);
    update32(a, REG_GENERAL_OPTION, BIT_DUMMY_FCS_READY_MASK_EN, 0)?;
    w32!(REG_WMAC_OPTION_FUNCTION + 8, WLAN_MAC_OPT_FUNC2);
    w8!(REG_WMAC_OPTION_FUNCTION_1, WLAN_MAC_OPT_NORM_FUNC1);
    let old = a.io.read16(REG_RXPSF_CTRL + 2)?;
    w16!(
        REG_RXPSF_CTRL + 2,
        (u32::from(old) & 0xf00f) | RX_FIFO_THRESHOLDS
    );
    w16!(
        REG_RXPSF_CTRL,
        RX_PACKET_LENGTH_ONE
            | BIT_RXPSF_CTRLEN
            | BIT_RXPSF_VHTCHKEN
            | BIT_RXPSF_HTCHKEN
            | BIT_RXPSF_OFDMCHKEN
            | BIT_RXPSF_CCKCHKEN
            | BIT_RXPSF_OFDMRST
    );
    w32!(REG_RXPSF_TYPE_CTRL, u32::MAX);
    let old = u32::from(a.io.read16(REG_RXPSF_CTRL)?);
    w16!(
        REG_RXPSF_CTRL,
        (old & !(BIT_RXPSF_MHCHKEN
            | BIT_RXPSF_CCKRST
            | BIT_RXPSF_CONT_ERRCHKEN
            | RX_ERROR_THRESHOLD_MASK))
            | 7
    );
    update8(a, REG_SND_PTCL_CTRL, BIT_DIS_CHK_VHTSIGB_CRC, 0)?;
    w32!(REG_INT_MIG, WLAN_MAC_INT_MIG_CFG);
    Ok(WLAN_RX_FILTER1 as u16)
}
