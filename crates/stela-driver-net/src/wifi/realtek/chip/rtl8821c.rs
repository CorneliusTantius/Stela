// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! The RTL8821C's own operations, as `rtw8821c.c` has them: one stream on
//! path A, its MAC protocol setup and its PHY.
use super::super::io::{Error, Io};

/// `WLAN_RX_FILTER1`: the RTL8821C keeps control frames of subtype 12 to 15
/// out of the receive filter, where the RTL8822C takes them.
pub const RX_FILTER1: u16 = 0x0fff;

const REG_AMPDU_MAX_TIME_V1: u32 = 0x455;
const REG_TX_HANG_CTRL: u32 = 0x45e;
const BIT_EN_EOF_V1: u8 = 1 << 2;
const REG_PRECNT_CTRL: u32 = 0x4e5;
const BIT_EN_PRECNT: u16 = 1 << 11;
const REG_PROT_MODE_CTRL: u32 = 0x4c8;
const REG_BAR_MODE_CTRL: u32 = 0x4cc;
const REG_FAST_EDCA_VOVI_SETTING: u32 = 0x1448;
const REG_FAST_EDCA_BEBK_SETTING: u32 = 0x144c;
const REG_INIRTS_RATE_SEL: u32 = 0x480;
const REG_TIMER0_SRC_SEL: u32 = 0x5b4;
const BIT_TSFT_SEL_TIMER0: u8 = 0x70;
const REG_TXPAUSE: u32 = 0x522;
const REG_SLOT: u32 = 0x51b;
const REG_PIFS: u32 = 0x512;
const REG_SIFS: u32 = 0x514;
const REG_EDCA_VO_PARAM: u32 = 0x500;
const REG_EDCA_VI_PARAM: u32 = 0x504;
const REG_RD_NAV_NXT: u32 = 0x544;
const REG_RXTSF_OFFSET_CCK: u32 = 0x55e;
const REG_BCN_CTRL: u32 = 0x550;
const BIT_EN_BCN_FUNCTION: u8 = 1 << 3;
const REG_TBTT_PROHIBIT: u32 = 0x540;
const REG_DRVERLYINT: u32 = 0x558;
const REG_BCNDMATIM: u32 = 0x559;
const REG_TX_PTCL_CTRL: u32 = 0x520;
const BIT_SIFS_BK_EN: u16 = 1 << 12;
const REG_RXFLTMAP0: u32 = 0x6a0;
const REG_RXFLTMAP1: u32 = 0x6a2;
const REG_RXFLTMAP2: u32 = 0x6a4;
const REG_RCR: u32 = 0x608;
const REG_RX_PKT_LIMIT: u32 = 0x60c;
const REG_TCR: u32 = 0x604;
const REG_ACKTO_CCK: u32 = 0x639;
const REG_WMAC_TRXPTCL_CTL_H: u32 = 0x66c;
const REG_SND_PTCL_CTRL: u32 = 0x718;
const BIT_DIS_CHK_VHTSIGB_CRC: u8 = 1 << 6;
const REG_WMAC_OPTION_FUNCTION: u32 = 0x7d0;

const WLAN_SLOT_TIME: u8 = 0x09;
const WLAN_PIFS_TIME: u8 = 0x19;
const WLAN_SIFS_CFG: u32 = 0x0a | 0x0e << 8 | 0x10 << 16 | 0x10 << 24;
const WLAN_VO_TXOP_LIMIT: u16 = 0x186;
const WLAN_VI_TXOP_LIMIT: u16 = 0x3bc;
const WLAN_NAV_CFG: u32 = 0x05 | 0x1b << 16;
const WLAN_RX_TSF_CFG: u16 = 0x30 | 0x30 << 8;
const WLAN_TBTT_TIME: u32 = 0x04 | 0x064 << 8;
const WLAN_DRV_EARLY_INT: u8 = 0x04;
const WLAN_BCN_DMA_TIME: u8 = 0x02;
const WLAN_RX_FILTER0: u16 = 0xffff;
const WLAN_RX_FILTER2: u16 = 0xffff;
const WLAN_RCR_CFG: u32 = 0xe400_220e;
const WLAN_RXPKT_MAX_SZ_512: u8 = (12288 >> 9) as u8;
const WLAN_AMPDU_MAX_TIME: u8 = 0x70;
const WLAN_RTS_LEN_TH: u32 = 0xff;
const WLAN_RTS_TX_TIME_TH: u32 = 0x08;
const WLAN_MAX_AGG_PKT_LIMIT: u32 = 0x20;
const WLAN_RTS_MAX_AGG_PKT_LIMIT: u32 = 0x20;
const FAST_EDCA_TH: u8 = 0x06;
const WLAN_BAR_RETRY_LIMIT: u16 = 0x01;
const WLAN_RA_TRY_RATE_AGG_LIMIT: u16 = 0x08;
const WLAN_TX_FUNC_CFG1: u8 = 0x30;
const WLAN_TX_FUNC_CFG2: u8 = 0x30;
const WLAN_MAC_OPT_NORM_FUNC1: u8 = 0x98;
const WLAN_MAC_OPT_FUNC2: u32 = 0xb081_0041;
const WLAN_PRE_TXCNT_TIME_TH: u16 = 0x1e4;

fn set8<I: Io>(io: &mut I, register: u32, bits: u8) -> Result<(), Error> {
    let value = io.read8(register)?;
    io.write8(register, value | bits)
}

fn clear8<I: Io>(io: &mut I, register: u32, bits: u8) -> Result<(), Error> {
    let value = io.read8(register)?;
    io.write8(register, value & !bits)
}

/// `rtw8821c_mac_init`.
pub fn mac_init<I: Io>(io: &mut I) -> Result<(), Error> {
    // Protocol configuration.
    io.write8(REG_AMPDU_MAX_TIME_V1, WLAN_AMPDU_MAX_TIME)?;
    set8(io, REG_TX_HANG_CTRL, BIT_EN_EOF_V1)?;
    let pre_txcnt = WLAN_PRE_TXCNT_TIME_TH | BIT_EN_PRECNT;
    io.write8(REG_PRECNT_CTRL, pre_txcnt as u8)?;
    io.write8(REG_PRECNT_CTRL + 1, (pre_txcnt >> 8) as u8)?;
    io.write32(
        REG_PROT_MODE_CTRL,
        WLAN_RTS_LEN_TH
            | WLAN_RTS_TX_TIME_TH << 8
            | WLAN_MAX_AGG_PKT_LIMIT << 16
            | WLAN_RTS_MAX_AGG_PKT_LIMIT << 24,
    )?;
    io.write16(
        REG_BAR_MODE_CTRL + 2,
        WLAN_BAR_RETRY_LIMIT | WLAN_RA_TRY_RATE_AGG_LIMIT << 8,
    )?;
    for register in [
        REG_FAST_EDCA_VOVI_SETTING,
        REG_FAST_EDCA_VOVI_SETTING + 2,
        REG_FAST_EDCA_BEBK_SETTING,
        REG_FAST_EDCA_BEBK_SETTING + 2,
    ] {
        io.write8(register, FAST_EDCA_TH)?;
    }
    set8(io, REG_INIRTS_RATE_SEL, 1 << 5)?;
    // EDCA configuration.
    clear8(io, REG_TIMER0_SRC_SEL, BIT_TSFT_SEL_TIMER0)?;
    io.write16(REG_TXPAUSE, 0)?;
    io.write8(REG_SLOT, WLAN_SLOT_TIME)?;
    io.write8(REG_PIFS, WLAN_PIFS_TIME)?;
    io.write32(REG_SIFS, WLAN_SIFS_CFG)?;
    io.write16(REG_EDCA_VO_PARAM + 2, WLAN_VO_TXOP_LIMIT)?;
    io.write16(REG_EDCA_VI_PARAM + 2, WLAN_VI_TXOP_LIMIT)?;
    io.write32(REG_RD_NAV_NXT, WLAN_NAV_CFG)?;
    io.write16(REG_RXTSF_OFFSET_CCK, WLAN_RX_TSF_CFG)?;
    // Beacon control: TSF and its functions.
    set8(io, REG_BCN_CTRL, BIT_EN_BCN_FUNCTION)?;
    io.write32(REG_TBTT_PROHIBIT, WLAN_TBTT_TIME)?;
    io.write8(REG_DRVERLYINT, WLAN_DRV_EARLY_INT)?;
    io.write8(REG_BCNDMATIM, WLAN_BCN_DMA_TIME)?;
    clear8(io, REG_TX_PTCL_CTRL + 1, (BIT_SIFS_BK_EN >> 8) as u8)?;
    // WMAC configuration.
    io.write16(REG_RXFLTMAP0, WLAN_RX_FILTER0)?;
    io.write16(REG_RXFLTMAP1, RX_FILTER1)?;
    io.write16(REG_RXFLTMAP2, WLAN_RX_FILTER2)?;
    io.write32(REG_RCR, WLAN_RCR_CFG)?;
    io.write8(REG_RX_PKT_LIMIT, WLAN_RXPKT_MAX_SZ_512)?;
    io.write8(REG_TCR + 2, WLAN_TX_FUNC_CFG2)?;
    io.write8(REG_TCR + 1, WLAN_TX_FUNC_CFG1)?;
    io.write8(REG_ACKTO_CCK, 0x40)?;
    set8(io, REG_WMAC_TRXPTCL_CTL_H, 1 << 1)?;
    set8(io, REG_SND_PTCL_CTRL, BIT_DIS_CHK_VHTSIGB_CRC)?;
    io.write32(REG_WMAC_OPTION_FUNCTION + 8, WLAN_MAC_OPT_FUNC2)?;
    io.write8(REG_WMAC_OPTION_FUNCTION + 4, WLAN_MAC_OPT_NORM_FUNC1)
}

#[cfg(test)]
pub(crate) mod tests;
