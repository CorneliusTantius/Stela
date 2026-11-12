// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2017 Intel Deutschland GmbH
// Copyright (C) 2018-2026 Intel Corporation
//! Source BIOS power-table selection from the same ACPI/EFI session.
//! Normalized values never constitute firmware programming or RF admission.
use super::*;
use crate::wifi::intel::radio::bios::power_tables;

pub(crate) const SAR_CHAINS: usize = 4;
pub(crate) const SAR_SUBBANDS: usize = 12;
pub(crate) const SAR_PROFILES: usize = 4;
pub(crate) const GEO_PROFILES: usize = 8;
pub(crate) const GEO_BANDS: usize = 4;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SarProfile {
    pub enabled: bool,
    pub values: [[u8; SAR_SUBBANDS]; SAR_CHAINS],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Selected<T> {
    pub source: lari::Source,
    pub revision: u8,
    pub value: T,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sar {
    pub profiles: [SarProfile; SAR_PROFILES],
    pub reduced_flags: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Geo {
    pub profiles: [[power_tables::GeoBand; GEO_BANDS]; GEO_PROFILES],
    pub count: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ppag {
    pub flags: u32,
    pub gains: [[i8; SAR_SUBBANDS]; 2],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tas {
    pub selection: u32,
    pub countries: Vec<u16>,
}
/// Source-selected tables. None means optional getter exhaustion, never
/// a missing native service. Raw successful/rejected reads stay in Session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tables {
    pub ppag: Option<Selected<Ppag>>,
    pub sar: Option<Selected<Sar>>,
    pub geo: Option<Selected<Geo>>,
    pub tas: Option<Selected<Tas>>,
    pub sgom: Option<[u8; 338]>,
    /// UATS: the 6 GHz AP types each country allows.
    pub ap_types: Option<[u8; 338]>,
    /// UNEB: the same of UNII-9.
    pub unii9_ap_types: Option<[u8; 338]>,
}

fn integer(object: &Object) -> Option<u64> {
    if let Object::Integer(value) = object {
        Some(*value)
    } else {
        None
    }
}
// Source first matching Wi-Fi package for each candidate size. A size
// match with the wrong table revision is not silently skipped by that getter.
fn wifi_package(object: &Object, minimum: usize, maximum: usize) -> Option<(u8, &[Object])> {
    let Object::Package(root) = object else {
        return None;
    };
    if root.len() < 2 {
        return None;
    }
    // Source stores the revision in int; supported revisions here are 0..5.
    let revision = integer(&root[0])? as u32 as i32;
    let revision = u8::try_from(revision).ok()?;
    for object in &root[1..] {
        let Object::Package(package) = object else {
            continue;
        };
        if (minimum..=maximum).contains(&package.len()) && integer(&package[0]) == Some(7) {
            return Some((revision, package));
        }
    }
    None
}
fn byte(object: &Object) -> Option<u8> {
    u8::try_from(integer(object)?).ok()
}
fn sar_dimensions(revision: u8) -> Option<(usize, usize)> {
    match revision {
        0 => Some((2, 5)),
        1 => Some((2, 11)),
        2 => Some((4, 11)),
        3 => Some((4, 12)),
        _ => None,
    }
}
fn acpi_sar(object: &Object) -> Option<(u8, Sar)> {
    for candidate in (0..=3).rev() {
        let (chains, bands) = sar_dimensions(candidate)?;
        let n = 2 + chains * bands;
        let Some((revision, package)) = wifi_package(object, n, n) else {
            continue;
        };
        if revision != candidate {
            return None;
        }
        let flags = integer(&package[1])? as u32;
        let mut profile = SarProfile {
            enabled: flags & 1 != 0,
            ..SarProfile::default()
        };
        for chain in 0..chains {
            for band in 0..bands {
                profile.values[chain][band] = byte(&package[2 + chain * bands + band])?;
            }
        }
        let mut profiles = [SarProfile::default(); SAR_PROFILES];
        profiles[0] = profile;
        return Some((
            revision,
            Sar {
                profiles,
                reduced_flags: flags >> 1,
            },
        ));
    }
    None
}
fn uefi_sar(raw: &[u8]) -> Option<(u8, Sar)> {
    let table = power_tables::Sar::parse(power_tables::SarKind::Wrds, raw).ok()?;
    let mut profiles = [SarProfile::default(); SAR_PROFILES];
    profiles[0].enabled = table.source_enabled();
    for chain in 0..SAR_CHAINS {
        for band in 0..table.subbands() {
            profiles[0].values[chain][band] = table.value(1, chain, band)?;
        }
    }
    // The UEFI source passes mode through bool and does not set reduced flags.
    Some((
        raw[0],
        Sar {
            profiles,
            reduced_flags: 0,
        },
    ))
}
fn acpi_extended_sar(object: &Object) -> Option<(u8, [SarProfile; 3])> {
    for candidate in (0..=3).rev() {
        let (chains, bands) = sar_dimensions(candidate)?;
        let n = 3 + 3 * chains * bands;
        let Some((revision, package)) = wifi_package(object, n, n) else {
            continue;
        };
        if revision != candidate {
            return None;
        }
        let enabled = integer(&package[1])? != 0;
        // Native bound rejects source signed int truncation/negative counts.
        let count = usize::try_from(integer(&package[2])?).ok()?;
        if count > 3 {
            return None;
        }
        let mut profiles = [SarProfile::default(); 3];
        let mut at = 3;
        // Source ACPI lays out all non-CDB pairs first, then all CDB pairs.
        for first_chain in (0..chains).step_by(2) {
            for profile in profiles.iter_mut().take(count) {
                profile.enabled = enabled;
                for chain in first_chain..first_chain + 2 {
                    for band in 0..bands {
                        profile.values[chain][band] = byte(package.get(at)?)?;
                        at += 1;
                    }
                }
            }
        }
        return Some((revision, profiles));
    }
    None
}
fn uefi_extended_sar(raw: &[u8]) -> Option<(u8, [SarProfile; 3])> {
    let table = power_tables::Sar::parse(power_tables::SarKind::Ewrd, raw).ok()?;
    let mut profiles = [SarProfile::default(); 3];
    for (index, profile) in profiles
        .iter_mut()
        .enumerate()
        .take(usize::from(table.declared_profiles()))
    {
        profile.enabled = table.source_enabled();
        for chain in 0..SAR_CHAINS {
            for band in 0..table.subbands() {
                profile.values[chain][band] = table.value(index as u8 + 2, chain, band)?;
            }
        }
    }
    Some((raw[0], profiles))
}
const EMPTY_GEO_BAND: power_tables::GeoBand = power_tables::GeoBand {
    maximum: 0,
    chain_offsets: [0; 2],
};
fn acpi_geo(object: &Object) -> Option<(u8, Geo)> {
    for (revisions, bands, capacity, has_count) in [
        (1u8 << 4, 4, 8, true),
        (1 << 3, 3, 8, true),
        (1 << 2, 3, 3, false),
        (3, 2, 3, false),
    ] {
        let header = if has_count { 2 } else { 1 };
        let maximum = header + bands * capacity * 3;
        let minimum = if has_count {
            header + bands * 3 * 3
        } else {
            maximum
        };
        let Some((revision, package)) = wifi_package(object, minimum, maximum) else {
            continue;
        };
        if revision >= 8 || revisions & (1 << revision) == 0 {
            continue;
        }
        let count = if has_count {
            usize::try_from(integer(&package[1])?).ok()?
        } else {
            capacity
        };
        if !(3..=capacity).contains(&count) || package.len() != maximum {
            return None;
        }
        let mut profiles = [[EMPTY_GEO_BAND; GEO_BANDS]; GEO_PROFILES];
        let mut at = header;
        for profile in profiles.iter_mut().take(count) {
            for band in 0..GEO_BANDS {
                if band >= bands {
                    profile[band] = profile[1];
                    continue;
                }
                profile[band] = power_tables::GeoBand {
                    maximum: byte(&package[at])?,
                    chain_offsets: [byte(&package[at + 1])?, byte(&package[at + 2])?],
                };
                at += 3;
            }
        }
        return Some((
            revision,
            Geo {
                profiles,
                count: count as u8,
            },
        ));
    }
    None
}
fn uefi_geo(raw: &[u8]) -> Option<(u8, Geo)> {
    let table = power_tables::Geo::parse(raw).ok()?;
    let mut profiles = [[EMPTY_GEO_BAND; GEO_BANDS]; GEO_PROFILES];
    for (index, profile) in profiles
        .iter_mut()
        .enumerate()
        .take(usize::from(table.declared_profiles()))
    {
        for (band, value) in profile.iter_mut().enumerate().take(table.bands()) {
            *value = table.band(index, band)?;
        }
    }
    Some((
        raw[0],
        Geo {
            profiles,
            count: table.declared_profiles(),
        },
    ))
}
fn ppag_flags(flags: u32, revision: u8) -> u32 {
    match revision {
        0..=2 => flags & 3,
        3 => flags & 0x7ff,
        _ => flags,
    }
}
fn acpi_ppag(object: &Object) -> Option<(u8, Ppag)> {
    for (minimum_rev, maximum_rev, bands) in [(5, 5, 12), (1, 4, 11), (0, 0, 5)] {
        let n = 2 + 2 * bands;
        let Some((revision, package)) = wifi_package(object, n, n) else {
            continue;
        };
        if !(minimum_rev..=maximum_rev).contains(&revision) {
            return None;
        }
        let flags = ppag_flags(integer(&package[1])? as u32, revision);
        let mut gains = [[0; SAR_SUBBANDS]; 2];
        for (chain, values) in gains.iter_mut().enumerate() {
            for (band, gain) in values.iter_mut().enumerate().take(bands) {
                // Source assignment to s8, including integer truncation.
                *gain = integer(&package[2 + chain * bands + band])? as i8;
            }
        }
        return Some((revision, Ppag { flags, gains }));
    }
    None
}
fn uefi_ppag(raw: &[u8]) -> Option<(u8, Ppag)> {
    let table = power_tables::Ppag::parse(raw).ok()?;
    let mut gains = [[0; SAR_SUBBANDS]; 2];
    for (chain, values) in gains.iter_mut().enumerate() {
        for (band, gain) in values.iter_mut().enumerate().take(table.subbands()) {
            *gain = table.gain(chain, band)?;
        }
    }
    Some((
        raw[0],
        Ppag {
            flags: table.source_flags(),
            gains,
        },
    ))
}
fn acpi_tas(object: &Object) -> Option<(u8, Tas)> {
    let (revision, package) = wifi_package(object, 19, 19)?;
    if revision > 2 {
        return None;
    }
    let selection = integer(&package[1])? as u32;
    let count = usize::try_from(integer(&package[2])?).ok()?;
    if count > 16 {
        return None;
    }
    let mut countries = Vec::new();
    for value in &package[3..3 + count] {
        countries.push(integer(value)? as u16);
    }
    Some((
        revision,
        Tas {
            selection,
            countries,
        },
    ))
}
fn uefi_tas(raw: &[u8]) -> Option<(u8, Tas)> {
    let table = power_tables::Tas::parse(raw).ok()?;
    Some((
        raw[0],
        Tas {
            selection: table.raw_selection(),
            countries: (0..usize::from(table.declared_countries()))
                .map(|i| table.country(i).unwrap())
                .collect(),
        },
    ))
}
impl<B: BiosIo> Session<B> {
    fn selected_table<T>(
        &mut self,
        variable: Variable,
        uefi: fn(&[u8]) -> Option<(u8, T)>,
        acpi: fn(&Object) -> Option<(u8, T)>,
    ) -> Option<Selected<T>> {
        if self.locked()
            && let Some(raw) = self.uefi(variable)
            && let Some((revision, value)) = uefi(&raw)
        {
            return Some(Selected {
                source: lari::Source::Uefi,
                revision,
                value,
            });
        }
        if let Some(object) = self.acpi(Request::PowerTable(variable))
            && let Some((revision, value)) = acpi(&object)
        {
            return Some(Selected {
                source: lari::Source::Acpi,
                revision,
                value,
            });
        }
        None
    }
    pub(crate) fn power_tables(&mut self) -> Tables {
        let ppag = self.selected_table(Variable::Ppag, uefi_ppag, acpi_ppag);
        let mut sar = self.selected_table(Variable::Wrds, uefi_sar, acpi_sar);
        if let Some(sar) = sar.as_mut()
            && let Some(extended) =
                self.selected_table(Variable::Ewrd, uefi_extended_sar, acpi_extended_sar)
        {
            sar.value.profiles[1..].copy_from_slice(&extended.value);
        }
        // Source also observes WGDS without WRDS for diagnostics. AX200 API77
        // is newer than the source's serial>=38 geo-support threshold.
        let geo = self.selected_table(Variable::Wgds, uefi_geo, acpi_geo);
        let sgom = if let Some(geo) = &geo {
            self.uefi(Variable::Sgom)
                .as_deref()
                .and_then(|raw| power_tables::CountryMap::parse(raw).ok())
                .and_then(|table| table.sgom(geo.value.count).ok())
        } else {
            None
        };
        let tas = self.selected_table(Variable::Wtas, uefi_tas, acpi_tas);
        let map = |raw: Option<_>| {
            raw.as_deref()
                .and_then(|raw| power_tables::CountryMap::parse(raw).ok())
                .and_then(|table| table.raw_map().try_into().ok())
        };
        let ap_types = map(self.uefi(Variable::Uats));
        let unii9_ap_types = map(self.uefi(Variable::Uneb));
        Tables {
            ppag,
            sar,
            geo,
            tas,
            sgom,
            ap_types,
            unii9_ap_types,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn package(revision: u8, values: Vec<Object>) -> Object {
        let mut wifi = vec![Object::Integer(7)];
        wifi.extend(values);
        Object::Package(vec![
            Object::Integer(u64::from(revision)),
            Object::Package(wifi),
        ])
    }
    fn integers(values: impl IntoIterator<Item = u64>) -> Vec<Object> {
        values.into_iter().map(Object::Integer).collect()
    }
    #[test]
    fn source_sar_revisions_zero_pad_missing_bands_and_keep_uefi_bool_mode() {
        for revision in 0..=3 {
            let (chains, bands) = sar_dimensions(revision).unwrap();
            let mut values = vec![Object::Integer(7)];
            values.extend(integers((1..=chains * bands).map(|i| i as u64)));
            let (observed, sar) = acpi_sar(&package(revision, values)).unwrap();
            assert_eq!(observed, revision);
            assert_eq!(sar.reduced_flags, 3);
            assert!(sar.profiles[0].enabled);
            for chain in 0..SAR_CHAINS {
                for band in 0..SAR_SUBBANDS {
                    assert_eq!(
                        sar.profiles[0].values[chain][band],
                        if chain < chains && band < bands {
                            (1 + chain * bands + band) as u8
                        } else {
                            0
                        }
                    );
                }
            }
        }
        for revision in [2, 3] {
            let bands = if revision == 2 { 11 } else { 12 };
            let mut raw = vec![revision, 2, 0, 0, 0];
            raw.extend(vec![17; 4 * bands]);
            let (_, sar) = uefi_sar(&raw).unwrap();
            assert!(sar.profiles[0].enabled);
            assert_eq!(sar.reduced_flags, 0);
            assert_eq!(sar.profiles[0].values[3][bands - 1], 17);
            raw.push(0);
            assert!(uefi_sar(&raw).is_none());
        }
    }
    #[test]
    fn source_extended_acpi_orders_non_cdb_before_cdb_and_preserves_unused_profiles() {
        for revision in 0..=3 {
            let (chains, bands) = sar_dimensions(revision).unwrap();
            let mut values = vec![Object::Integer(2), Object::Integer(2)];
            let mut raw = Vec::new();
            for pair in 0..chains / 2 {
                for profile in 0..2 {
                    for chain in 0..2 {
                        for band in 0..bands {
                            raw.push((1 + pair * 80 + profile * 24 + chain * 12 + band) as u64);
                        }
                    }
                }
            }
            // The source package always reserves capacity for all 3 profiles.
            raw.resize(chains * bands * 3, 0);
            values.extend(integers(raw));
            let (_, profiles) = acpi_extended_sar(&package(revision, values)).unwrap();
            assert!(profiles[0].enabled && profiles[1].enabled && !profiles[2].enabled);
            assert_eq!(
                profiles[1].values[1][bands - 1],
                (1 + 24 + 12 + bands - 1) as u8
            );
            if chains == 4 {
                assert_eq!(
                    profiles[1].values[3][bands - 1],
                    (1 + 80 + 24 + 12 + bands - 1) as u8
                );
            }
        }
    }
    #[test]
    fn geo_acpi_replicates_missing_band_but_uefi_keeps_source_zero_initialization() {
        for revision in 0..=4 {
            let bands = if revision < 2 {
                2
            } else if revision == 4 {
                4
            } else {
                3
            };
            let capacity = if revision >= 3 { 8 } else { 3 };
            let mut values = Vec::new();
            if revision >= 3 {
                values.push(Object::Integer(3));
            }
            values.extend(integers((0..capacity * bands * 3).map(|i| (1 + i) as u64)));
            let (_, geo) = acpi_geo(&package(revision, values)).unwrap();
            assert_eq!(geo.count, 3);
            assert_eq!(geo.profiles[0][0].maximum, 1);
            for band in bands..4 {
                assert_eq!(geo.profiles[0][band], geo.profiles[0][1]);
            }
            if capacity == 8 {
                assert_eq!(geo.profiles[7], [EMPTY_GEO_BAND; 4]);
            }
        }
        let mut raw = vec![3, 3];
        raw.extend([8; 72]);
        let (_, geo) = uefi_geo(&raw).unwrap();
        assert_eq!(geo.profiles[0][2].maximum, 8);
        assert_eq!(geo.profiles[0][3], EMPTY_GEO_BAND);
    }
    #[test]
    fn ppag_and_tas_follow_source_revision_selection() {
        for revision in 0..=5 {
            let bands = if revision == 0 {
                5
            } else if revision == 5 {
                12
            } else {
                11
            };
            let mut values = vec![Object::Integer(u64::MAX)];
            values.extend(integers([0x1ff].repeat(2 * bands)));
            let (_, ppag) = acpi_ppag(&package(revision, values)).unwrap();
            assert_eq!(ppag.flags, ppag_flags(u32::MAX, revision));
            assert_eq!(ppag.gains[1][bands - 1], -1);
        }
        for revision in 0..=2 {
            let mut values = vec![
                Object::Integer(0x100000007),
                Object::Integer(1),
                Object::Integer(0x12345553),
            ];
            values.resize(18, Object::Other);
            let (_, tas) = acpi_tas(&package(revision, values)).unwrap();
            assert_eq!(tas.selection, 7);
            assert_eq!(tas.countries, [0x5553]);
        }
        let mut values = vec![Object::Integer(1)];
        values.extend(integers([256].repeat(10)));
        assert!(acpi_sar(&package(0, values)).is_none());
    }
    #[derive(Clone)]
    struct Namespace {
        incomplete: bool,
        uefi_valid: bool,
    }
    // SAFETY: a bounded raw namespace model, never physical platform permission.
    unsafe impl BiosIo for Namespace {
        fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
            match request {
                Request::Glai => Ok(package(0, vec![Object::Integer(1)])),
                Request::PowerTable(Variable::Wrds) => {
                    let mut values = vec![Object::Integer(3)];
                    values.extend(integers(1..=10));
                    Ok(package(0, values))
                }
                _ => Err(IoError::NotFound),
            }
        }
        fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError> {
            if variable == Variable::Wrds {
                if self.incomplete {
                    return Err(IoError::Unavailable);
                }
                if self.uefi_valid {
                    let mut raw = vec![2, 1, 0, 0, 0];
                    raw.extend([9; 44]);
                    return Ok(raw);
                }
                return Ok(vec![9; 49]);
            }
            Err(IoError::NotFound)
        }
    }
    #[test]
    fn selection_reads_same_session_uefi_then_acpi_and_an_unreadable_variable_is_absent() {
        for uefi_valid in [false, true] {
            let mut session = Session::new(Namespace {
                incomplete: false,
                uefi_valid,
            });
            let tables = session.power_tables();
            let sar = tables.sar.unwrap();
            assert_eq!(
                sar.source,
                if uefi_valid {
                    lari::Source::Uefi
                } else {
                    lari::Source::Acpi
                }
            );
            assert_eq!(
                sar.value.profiles[0].values[0][0],
                if uefi_valid { 9 } else { 1 }
            );
            assert_eq!(
                session
                    .reads()
                    .iter()
                    .filter(|r| matches!(r, Read::Acpi(Request::PowerTable(Variable::Wrds), _)))
                    .count(),
                usize::from(!uefi_valid)
            );
        }
        let mut session = Session::new(Namespace {
            incomplete: true,
            uefi_valid: false,
        });
        // `iwl_bios_get_wrds_table`: the UEFI table it cannot read gives way
        // to the ACPI one, as an absent one does.
        let sar = session.power_tables().sar.unwrap();
        assert_eq!(sar.source, lari::Source::Acpi);
        let reads = session.reads();
        let unread = reads
            .iter()
            .find(|r| matches!(r, Read::Uefi(Variable::Wrds, _)))
            .unwrap();
        assert_eq!(
            unread,
            &Read::Uefi(Variable::Wrds, Err(IoError::Unavailable))
        );
        assert!(unread.incomplete());
    }
}
