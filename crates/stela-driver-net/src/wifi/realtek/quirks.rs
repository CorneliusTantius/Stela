// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! `rtw_pci_quirks`: systems whose RTL8822CE loses its link with PCIe ASPM, or
//! hangs in deep power save, matched on SMBIOS as `dmi_check_system` matches.
use crate::firmware::{
    Provider,
    smbios::{self, Observation, SystemIdentity},
};

/// `DMI_SYS_VENDOR`, `DMI_PRODUCT_NAME`, `DMI_PRODUCT_SKU` and `DMI_BOARD_NAME`.
#[derive(Clone, Copy)]
enum Field {
    Vendor,
    Product,
    Sku,
    Board,
}

/// One `dmi_system_id`: every substring present, and what it turns off.
struct Quirk {
    matches: &'static [(Field, &'static [u8])],
    aspm: bool,
    lps_deep: bool,
}

const QUIRKS: &[Quirk] = &[
    Quirk {
        matches: &[
            (Field::Vendor, b"HP"),
            (Field::Product, b"HP Notebook"),
            (Field::Sku, b"P3S95EA#ACB"),
        ],
        aspm: true,
        lps_deep: true,
    },
    Quirk {
        matches: &[
            (Field::Vendor, b"ASUSTeK COMPUTER INC."),
            (Field::Board, b"FA506II"),
        ],
        aspm: true,
        lps_deep: true,
    },
    Quirk {
        matches: &[
            (Field::Vendor, b"ASUSTeK COMPUTER INC."),
            (Field::Board, b"FA506IH"),
        ],
        aspm: true,
        lps_deep: true,
    },
    Quirk {
        matches: &[
            (Field::Vendor, b"Dell Inc."),
            (Field::Product, b"Vostro 15 3530"),
        ],
        aspm: true,
        lps_deep: true,
    },
    Quirk {
        matches: &[(Field::Vendor, b"LENOVO"), (Field::Product, b"81N4")],
        aspm: true,
        lps_deep: false,
    },
];

/// `QUIRK_DIS_CAP_PCI_ASPM` and `QUIRK_DIS_CAP_LPS_DEEP` for this system.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Disabled {
    pub aspm: bool,
    pub lps_deep: bool,
}

impl Disabled {
    /// The system's SMBIOS identity from `firmware`. Linux matches nothing
    /// without a DMI table, and neither does a handoff without one.
    pub fn load(firmware: &dyn Provider) -> Self {
        smbios::load(firmware)
            .map(|snapshot| Self::of(&snapshot.identity))
            .unwrap_or_default()
    }

    /// Every quirk whose fields all hold their substring, as `dmi_matches`
    /// compares the saved strings. A field Linux would not have saved matches
    /// nothing.
    pub fn of(system: &SystemIdentity<'_>) -> Self {
        let saved = |field: Field| match field {
            Field::Vendor => system.system_vendor,
            Field::Product => system.product_name,
            Field::Sku => system.product_sku,
            Field::Board => system.board_name,
        };
        let holds = |&(field, wanted): &(Field, &[u8])| match saved(field) {
            Observation::Value(bytes) => {
                let text = bytes.split(|&byte| byte == 0).next().unwrap_or(bytes);
                text.windows(wanted.len()).any(|window| window == wanted)
            }
            _ => false,
        };
        QUIRKS
            .iter()
            .filter(|quirk| quirk.matches.iter().all(holds))
            .fold(Self::default(), |disabled, quirk| Self {
                aspm: disabled.aspm || quirk.aspm,
                lps_deep: disabled.lps_deep || quirk.lps_deep,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system<'a>(
        vendor: &'a [u8],
        product: &'a [u8],
        sku: &'a [u8],
        board: &'a [u8],
    ) -> SystemIdentity<'a> {
        SystemIdentity {
            system_vendor: Observation::Value(vendor),
            product_name: Observation::Value(product),
            product_sku: Observation::Value(sku),
            board_name: Observation::Value(board),
            ..SystemIdentity::default()
        }
    }

    const BOTH: Disabled = Disabled {
        aspm: true,
        lps_deep: true,
    };

    #[test]
    fn each_listed_system_turns_off_what_linux_turns_off() {
        for (identity, disabled) in [
            (
                system(b"HP\0", b"HP Notebook\0", b"P3S95EA#ACB\0", b"\0"),
                BOTH,
            ),
            (
                system(b"ASUSTeK COMPUTER INC.\0", b"x\0", b"\0", b"FA506II\0"),
                BOTH,
            ),
            (
                system(b"ASUSTeK COMPUTER INC.\0", b"x\0", b"\0", b"FA506IH\0"),
                BOTH,
            ),
            (
                system(b"Dell Inc.\0", b"Vostro 15 3530\0", b"\0", b"\0"),
                BOTH,
            ),
            (
                system(b"LENOVO\0", b"81N4\0", b"\0", b"\0"),
                Disabled {
                    aspm: true,
                    lps_deep: false,
                },
            ),
        ] {
            assert_eq!(Disabled::of(&identity), disabled);
        }
    }

    #[test]
    fn fields_match_as_substrings_before_the_nul_and_all_must_hold() {
        // DMI_MATCH is strstr: a longer saved string still matches.
        assert!(Disabled::of(&system(b"LENOVO\0", b"81N4002BUS\0", b"\0", b"\0")).aspm);
        assert_eq!(
            Disabled::of(&system(b"HP\0", b"HP Notebook\0", b"P3S95EA\0", b"\0")),
            Disabled::default(),
            "the SKU is part of the match"
        );
        assert_eq!(
            Disabled::of(&system(b"Dell Inc.\0Vostro 15 3530", b"\0", b"\0", b"\0")),
            Disabled::default(),
            "nothing past the string's NUL"
        );
        let unread = SystemIdentity {
            system_vendor: Observation::Value(b"LENOVO\0"),
            product_name: Observation::Absent,
            ..SystemIdentity::default()
        };
        assert_eq!(Disabled::of(&unread), Disabled::default());
        assert_eq!(
            Disabled::of(&SystemIdentity::default()),
            Disabled::default()
        );
    }
}
