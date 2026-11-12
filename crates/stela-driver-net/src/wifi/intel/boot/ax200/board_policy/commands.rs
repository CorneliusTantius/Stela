// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2017 Intel Deutschland GmbH
// Copyright (C) 2018-2026 Intel Corporation
//! Source cold PPAG/SAR/geo/SGOM/TAS/AP type commands, private to the AX200
//! owner.
use super::*;
use crate::wifi::intel::{firmware::Firmware, radio::bios::service::power};
const PPAG_CAPABILITY: u32 = 52;
const TAS_CAPABILITY: u32 = 53;
const PPAG_CHINA_CAPABILITY: u32 = 112;
const CANADA_TAS_CAPABILITY: u32 = 124;
const REDUCE_TX_POWER_API: u32 = 45;
const TX_POWER_ACK_CAPABILITY: u32 = 84;
const SAR_TABLE_VERSION_API: u32 = 55;
const PPAG_COMMAND: Id = Id {
    group: 4,
    opcode: 7,
    version: 0,
};
const SAR_COMMAND: Id = Id {
    group: 0,
    opcode: 0x9f,
    version: 0,
};
const GEO_COMMAND: Id = Id {
    group: 4,
    opcode: 5,
    version: 0,
};
const SGOM_COMMAND: Id = Id {
    group: 12,
    opcode: 4,
    version: 0,
};
/// `MCC_ALLOWED_AP_TYPE_CMD`.
const AP_TYPE_COMMAND: Id = Id {
    group: 12,
    opcode: 5,
    version: 0,
};
const TAS_COMMAND: Id = Id {
    group: 12,
    opcode: 3,
    version: 0,
};
const SET_POWER_CHAINS: u32 = 2;
const PPAG_ETSI: u32 = 1;
const PPAG_ETSI_CHINA: u32 = 3;
const PPAG_V5_MASK: u32 = PPAG_ETSI_CHINA | (1 << 2) | (1 << 5);
fn version(fw: &Firmware<'_>, id: Id) -> Result<u8, Ax200BoardPolicyError> {
    let wire = id.wire();
    fw.command_version(wire.group, wire.opcode)
        .map(|v| v.command_version)
        .ok_or(Ax200BoardPolicyError::MissingApi {
            group: wire.group,
            command: wire.opcode,
        })
}
fn unsupported(kind: BoardCommandKind, version: u8) -> Ax200BoardPolicyError {
    Ax200BoardPolicyError::Version { kind, version }
}
fn matches(identity: &service::DmiIdentity, system: &str, board: Option<&str>) -> bool {
    identity
        .system_vendor
        .as_ref()
        .is_some_and(|v| v.contains(system))
        && board.is_none_or(|expected| {
            identity
                .board_vendor
                .as_ref()
                .is_some_and(|v| v.contains(expected))
        })
}
pub(super) fn ppag_approved(identity: &service::DmiIdentity) -> bool {
    [
        "HP",
        "SAMSUNG ELECTRONICS CO., LTD",
        "Microsoft Corporation",
        "ASUSTeK COMPUTER INC.",
        "ASUS",
        "Dell Inc.",
        "Alienware",
        "Razer",
        "HONOR",
        "WIKO",
        "XIAOMI",
    ]
    .iter()
    .any(|s| matches(identity, s, None))
        || [
            "HP",
            "ASUSTek COMPUTER INC.",
            "SAMSUNG ELECTRONICS CO., LTD",
        ]
        .iter()
        .any(|b| matches(identity, "Google", Some(b)))
}
pub(super) fn tas_approved(identity: &service::DmiIdentity) -> bool {
    [
        "HP",
        "SAMSUNG ELECTRONICS CO., LTD",
        "LENOVO",
        "Dell Inc.",
        "Microsoft Corporation",
        "Acer",
        "ASUSTeK COMPUTER INC.",
        "ASUS",
        "Micro-Star International Co., Ltd.",
        "HONOR",
    ]
    .iter()
    .any(|s| matches(identity, s, None))
        || matches(identity, "Google", Some("HP"))
}
/// `iwl_mld_init_ap_type_tables`' body at command `version`: the country
/// maps either UEFI table made valid, the first version knowing only one.
fn ap_types(version: u8, tables: &power::Tables) -> Result<Option<Vec<u8>>, Ax200BoardPolicyError> {
    if tables.ap_types.is_none() && tables.unii9_ap_types.is_none() {
        return Ok(None);
    }
    let mut bytes = tables.ap_types.unwrap_or([0; 338]).to_vec();
    match version {
        1 => bytes.extend([0; 2]),
        2 => bytes.extend(tables.unii9_ap_types.unwrap_or([0; 338])),
        _ => return Err(unsupported(BoardCommandKind::ApTypes, version)),
    }
    Ok(Some(bytes))
}
fn command(kind: BoardCommandKind, id: Id, bytes: Vec<u8>) -> BoardCommand {
    BoardCommand { kind, id, bytes }
}
/// Whether a SMBIOS read is necessary for a potentially emitted command.
pub(super) fn needs_identity(fw: &Firmware<'_>, tables: &power::Tables) -> bool {
    (fw.supports_capability(PPAG_CAPABILITY) && tables.ppag.is_some())
        || (fw.supports_capability(TAS_CAPABILITY) && tables.tas.is_some())
}
pub(super) fn prepare(
    fw: &Firmware<'_>,
    tables: &power::Tables,
    identity: Option<&service::DmiIdentity>,
    six_ghz: bool,
) -> Result<Vec<BoardCommand>, Ax200BoardPolicyError> {
    let mut commands = Vec::new();
    if fw.supports_capability(PPAG_CAPABILITY)
        && let Some(table) = &tables.ppag
    {
        let identity = identity.ok_or(Ax200BoardPolicyError::State)?;
        if ppag_approved(identity) {
            let v = version(fw, PPAG_COMMAND)?;
            let (bands, offset, len, flags) = match v {
                1 => (
                    5,
                    4,
                    16,
                    table.value.flags
                        & if fw.supports_capability(PPAG_CHINA_CAPABILITY) {
                            PPAG_ETSI_CHINA
                        } else {
                            PPAG_ETSI
                        },
                ),
                5 => (11, 4, 28, table.value.flags & PPAG_V5_MASK),
                7 => (11, 8, 32, table.value.flags),
                8 => (12, 8, 32, table.value.flags),
                _ => return Err(unsupported(BoardCommandKind::Ppag, v)),
            };
            if (v > 3 || table.value.flags != 0) && ppag_revision_taken(fw, v, table) {
                let mut bytes = alloc::vec![0; len];
                if v >= 7 {
                    bytes[0] = source(table.source);
                    bytes[1] = table.revision;
                }
                bytes[offset - 4..offset].copy_from_slice(&flags.to_le_bytes());
                for chain in 0..2 {
                    for band in 0..bands {
                        let gain = table.value.gains[chain][band];
                        let maximum = if band == 0 { 24 } else { 40 };
                        if v <= 3 && !(-16..=maximum).contains(&gain) {
                            return Err(Ax200BoardPolicyError::PpagGain {
                                chain: chain as u8,
                                band: band as u8,
                                gain,
                            });
                        }
                        bytes[offset + chain * bands + band] = gain as u8;
                    }
                }
                commands.push(command(BoardCommandKind::Ppag, PPAG_COMMAND, bytes));
            }
        }
    }
    let sar_enabled = tables
        .sar
        .as_ref()
        .is_some_and(|v| v.value.profiles[0].enabled);
    if sar_enabled {
        let sar = &tables.sar.as_ref().unwrap().value;
        let v = version(fw, SAR_COMMAND)?;
        let (bands, offset, len, flags) = match v {
            11 => (12, 10, 116, Some(112)),
            10 => (11, 10, 108, Some(104)),
            9 => (5, 12, 40, None),
            8 => (11, 16, 120, Some(112)),
            3..=5 => {
                let tail = if fw.supports_api(REDUCE_TX_POWER_API) {
                    8
                } else if fw.supports_capability(TX_POWER_ACK_CAPABILITY) {
                    4
                } else {
                    0
                };
                (5, 16, 36 + tail, None)
            }
            _ => return Err(unsupported(BoardCommandKind::Sar, v)),
        };
        let mut bytes = alloc::vec![0; len];
        bytes[..4].copy_from_slice(&SET_POWER_CHAINS.to_le_bytes()); // SET_CHAINS; source cold profile1,1.
        if let Some(offset) = flags {
            bytes[offset..offset + 4].copy_from_slice(&sar.reduced_flags.to_le_bytes());
        }
        // Source fills one table even where v8/v10 reserve two tables. The
        // zeroed remaining table and cold timer/ACK/per-band fields are source defaults.
        for chain in 0..2 {
            for band in 0..bands {
                let at = offset + (chain * bands + band) * 2;
                bytes[at..at + 2]
                    .copy_from_slice(&u16::from(sar.profiles[0].values[chain][band]).to_le_bytes());
            }
        }
        commands.push(command(BoardCommandKind::Sar, SAR_COMMAND, bytes));
    }
    // `iwl_mvm_sar_init` only logs a WGDS without WRDS, and sends no geo
    // table without the SAR one.
    if sar_enabled && let Some(table) = &tables.geo {
        let v = version(fw, GEO_COMMAND)?;
        let (profiles, bands, has_revision) = match v {
            6 => (8, 4, true),
            5 => (8, 3, true),
            4 => (8, 2, true),
            3 => (3, 3, true),
            1 | 2 => (3, 2, fw.supports_api(SAR_TABLE_VERSION_API)),
            _ => return Err(unsupported(BoardCommandKind::Geo, v)),
        };
        let end = 4 + profiles * bands * 4;
        let mut bytes = alloc::vec![0; end + if has_revision { 4 } else { 0 }];
        for profile in 0..profiles {
            for band in 0..bands {
                let value = table.value.profiles[profile][band];
                let at = 4 + (profile * bands + band) * 4;
                bytes[at..at + 2].copy_from_slice(&u16::from(value.maximum).to_le_bytes());
                bytes[at + 2..at + 4].copy_from_slice(&value.chain_offsets);
            }
        }
        if v == 6 {
            bytes[end] = source(table.source);
            bytes[end + 1] = table.revision;
        } else if has_revision {
            bytes[end..end + 4].copy_from_slice(&u32::from(table.revision == 1).to_le_bytes());
        }
        commands.push(command(BoardCommandKind::Geo, GEO_COMMAND, bytes));
    }
    if let Some(map) = tables.sgom {
        let v = version(fw, SGOM_COMMAND)?;
        if v != 2 {
            return Err(unsupported(BoardCommandKind::Sgom, v));
        }
        let mut bytes = map.to_vec();
        bytes.extend([0; 2]);
        commands.push(command(BoardCommandKind::Sgom, SGOM_COMMAND, bytes));
    }
    if fw.supports_capability(TAS_CAPABILITY)
        && let Some(table) = &tables.tas
    {
        let v = version(fw, TAS_COMMAND)?;
        if !(2..=5).contains(&v) {
            return Err(unsupported(BoardCommandKind::Tas, v));
        }
        if table.value.selection & 1 != 0 || v == 5 {
            'tas: {
                let identity = identity.ok_or(Ax200BoardPolicyError::State)?;
                let mut countries = table.value.countries.clone();
                if !tas_approved(identity) {
                    for country in [u16::from_be_bytes(*b"US"), u16::from_be_bytes(*b"CA")] {
                        if !countries.contains(&country) {
                            if countries.len() == 16 {
                                // `iwl_mvm_tas_init`: with no room to block US
                                // and Canada, TAS stays off.
                                break 'tas;
                            }
                            countries.push(country);
                        }
                    }
                }
                let mut bytes = alloc::vec![0; if v == 2 { 68 } else if v == 5 { 44 } else { 72 }];
                if v == 5 {
                    bytes[..2].copy_from_slice(&(countries.len() as u16).to_le_bytes());
                    for (i, value) in countries.iter().enumerate() {
                        bytes[2 + i * 2..4 + i * 2].copy_from_slice(&value.to_le_bytes());
                    }
                    bytes[36] = source(table.source);
                    bytes[37] = table.revision;
                    bytes[40..44].copy_from_slice(&table.value.selection.to_le_bytes());
                } else {
                    bytes[..4].copy_from_slice(&(countries.len() as u32).to_le_bytes());
                    for (i, value) in countries.iter().enumerate() {
                        bytes[4 + i * 4..8 + i * 4]
                            .copy_from_slice(&u32::from(*value).to_le_bytes());
                    }
                    let selection = table.value.selection;
                    let override_iec = table.revision > 0 && selection & 2 != 0;
                    let enable_iec = table.revision > 0 && selection & 4 != 0;
                    if v == 3 {
                        bytes[68..70].copy_from_slice(&u16::from(override_iec).to_le_bytes());
                        bytes[70..72].copy_from_slice(&u16::from(enable_iec).to_le_bytes());
                    } else if v == 4 {
                        bytes[68] = u8::from(override_iec);
                        bytes[69] = u8::from(enable_iec);
                        bytes[70] = u8::from(table.revision > 0 && selection & (1 << 16) != 0);
                        bytes[71] = u8::from(
                            fw.supports_capability(CANADA_TAS_CAPABILITY)
                                && table.revision > 1
                                && selection & (1 << 15) != 0,
                        );
                    }
                }
                commands.push(command(BoardCommandKind::Tas, TAS_COMMAND, bytes));
            }
        }
    }
    if six_ghz
        && fw
            .command_version(AP_TYPE_COMMAND.wire().group, AP_TYPE_COMMAND.wire().opcode)
            .is_some()
        && let Some(bytes) = ap_types(version(fw, AP_TYPE_COMMAND)?, tables)?
    {
        commands.push(command(BoardCommandKind::ApTypes, AP_TYPE_COMMAND, bytes));
    }
    Ok(commands)
}

/// `iwl_fw_lookup_cmd_bios_supported_revision`: firmware may name the newest
/// table a version 7 or 8 command takes. Linux sends nothing for a newer one.
fn ppag_revision_taken(
    fw: &Firmware<'_>,
    version: u8,
    table: &power::Selected<power::Ppag>,
) -> bool {
    let wire = PPAG_COMMAND.wire();
    let uefi = table.source == ObservationSource::Uefi;
    let newest = fw.bios_table_revision(wire.group, wire.opcode, uefi);
    match version {
        7 => table.revision <= newest.unwrap_or(4),
        8 => table.revision <= newest.unwrap_or(5),
        _ => true,
    }
}
fn source(source: ObservationSource) -> u8 {
    match source {
        ObservationSource::Acpi => 1,
        ObservationSource::Uefi => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables(ap_types: Option<u8>, unii9: Option<u8>) -> power::Tables {
        power::Tables {
            ppag: None,
            sar: None,
            geo: None,
            tas: None,
            sgom: None,
            ap_types: ap_types.map(|value| [value; 338]),
            unii9_ap_types: unii9.map(|value| [value; 338]),
        }
    }

    #[test]
    fn neither_uefi_table_sends_nothing() {
        if crate::test_process::isolate_model() {
            return;
        }
        assert_eq!(ap_types(1, &tables(None, None)), Ok(None));
    }

    #[test]
    fn the_first_version_carries_one_map_and_the_second_both() {
        if crate::test_process::isolate_model() {
            return;
        }
        let first = ap_types(1, &tables(Some(1), Some(2))).unwrap().unwrap();
        assert_eq!(first.len(), 340);
        assert_eq!((first[337], first[338]), (1, 0));
        let second = ap_types(2, &tables(None, Some(2))).unwrap().unwrap();
        assert_eq!(second.len(), 676);
        assert_eq!((second[337], second[338]), (0, 2));
        assert!(ap_types(3, &tables(Some(1), None)).is_err());
    }
}
