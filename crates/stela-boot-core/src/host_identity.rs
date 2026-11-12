//! The boot's header block: which `stela.efi` ran on which PC and when, so
//! a log a user sends can be matched to a build and to hardware.
use crate::log_style::{RULE, THIN_RULE};
use alloc::{format, string::String};

/// What the line names.
pub struct Identity<'a> {
    /// `stela.efi`'s version (its crate version).
    pub version: &'a str,
    /// The source revision it was built from, or `unknown`.
    pub build: &'a str,
    /// The firmware clock's date and time at the start, when it has one.
    pub time: Option<&'a str>,
    /// A hypervisor runs the PC (CPUID).
    pub hypervisor: bool,
    /// The CPU's brand string ([`brand`]).
    pub cpu: &'a str,
    /// CPUID leaf 1's EAX: family, model and stepping.
    pub signature: u32,
    /// Every byte the firmware's memory map describes as RAM.
    pub ram_bytes: u64,
    pub firmware_vendor: &'a str,
    pub firmware_revision: u32,
}

/// The CPU brand string CPUID leaves 0x8000_0002..=0x8000_0004 hold, as
/// their EAX, EBX, ECX and EDX in order, without its padding.
pub fn brand(words: [u32; 12]) -> String {
    let mut bytes = [0u8; 48];
    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().into()
}

/// The display family, model and stepping of CPUID leaf 1's EAX.
pub fn signature_parts(signature: u32) -> (u32, u32, u32) {
    let base_family = (signature >> 8) & 0xf;
    let family = if base_family == 0xf {
        base_family + ((signature >> 20) & 0xff)
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xf {
        ((signature >> 12) & 0xf0) | ((signature >> 4) & 0xf)
    } else {
        (signature >> 4) & 0xf
    };
    (family, model, signature & 0xf)
}

/// The vendor string CPUID leaf 0 holds in EBX, EDX and ECX.
pub fn vendor(words: [u32; 3]) -> String {
    let bytes: alloc::vec::Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    String::from_utf8_lossy(&bytes)
        .trim_end_matches('\0')
        .into()
}

/// An SMBIOS string as text: without the NUL terminator the table walk keeps
/// and without padding spaces, or `None` when nothing is left.
pub fn smbios_text(value: &[u8]) -> Option<&[u8]> {
    let end = value
        .iter()
        .rposition(|&byte| byte != 0 && !byte.is_ascii_whitespace())?
        + 1;
    let start = value
        .iter()
        .position(|&byte| byte != 0 && !byte.is_ascii_whitespace())?;
    Some(&value[start..end])
}

/// The string at byte `offset` of the first SMBIOS structure of type `kind`
/// in `table` (DSP0134 §6.1.3), or `None` when there is none or the table
/// ends early. Callers name only model and version fields: type 0's BIOS
/// version (offset 5), type 2's product (offset 5); never serial numbers,
/// UUIDs or asset tags.
pub fn smbios_string(table: &[u8], kind: u8, offset: usize) -> Option<&[u8]> {
    let mut at = 0usize;
    while let Some(head) = table.get(at..at + 4) {
        let length = usize::from(head[1]);
        let strings = table.get(at + length..)?;
        let end = strings.windows(2).position(|pair| pair == [0, 0])?;
        if head[0] == kind {
            let index = usize::from(*table.get(at + offset).filter(|_| offset < length)?);
            return strings[..end]
                .split(|&byte| byte == 0)
                .nth(index.checked_sub(1)?)
                .filter(|value| !value.is_empty());
        }
        if head[0] == 127 {
            return None;
        }
        at += length + end + 2;
    }
    None
}

/// The header block, each line labelled in an 8-character column:
///
/// ```text
/// ================================================================================
/// STELA   0.3.0, build db45c012c4f1, started 2026-11-11 18:44:05 (firmware clock)
/// PC      Intel(R) Core(TM) i7-12700K, family 0x6 model 0x97 stepping 2
///         14.9 GiB RAM, firmware "EDK II" revision 0x10000
/// --------------------------------------------------------------------------------
/// ```
pub fn header(identity: &Identity<'_>) -> String {
    let (family, model, stepping) = signature_parts(identity.signature);
    let started = identity
        .time
        .map(|time| format!(", started {time} (firmware clock)"))
        .unwrap_or_default();
    let hypervisor = if identity.hypervisor {
        ", under a hypervisor"
    } else {
        ""
    };
    format!(
        "{RULE}\nSTELA   {}, build {}{started}\nPC      {}, family {family:#x} model {model:#x} \
         stepping {stepping}\n        {} RAM, firmware \"{}\" revision {:#x}{hypervisor}\n{}\n",
        identity.version,
        identity.build,
        identity.cpu,
        crate::log_style::size(identity.ram_bytes),
        identity.firmware_vendor,
        identity.firmware_revision,
        THIN_RULE,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_line_names_build_cpu_ram_and_firmware() {
        let text = b"Intel(R) Core(TM) i7-12700K\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let mut words = [0u32; 12];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes(text[index * 4..index * 4 + 4].try_into().unwrap());
        }
        let cpu = brand(words);
        assert_eq!(cpu, "Intel(R) Core(TM) i7-12700K");
        assert_eq!(signature_parts(0x0009_0672), (6, 0x97, 2));
        // Zen 5: family 0x1a.
        assert_eq!(signature_parts(0x00b4_0f40).0, 0x1a);
        assert_eq!(
            vendor([0x6874_7541, 0x6974_6e65, 0x444d_4163]),
            "AuthenticAMD"
        );
        // Alder Lake: family 6, model 0x97, stepping 2.
        let header = header(&Identity {
            version: "0.1.0",
            build: "db45c012c4f1",
            time: Some("2026-11-11 18:44:05"),
            hypervisor: false,
            cpu: &cpu,
            signature: 0x0009_0672,
            ram_bytes: 16 << 30,
            firmware_vendor: "EDK II",
            firmware_revision: 0x10000,
        });
        assert_eq!(
            header,
            format!(
                "{RULE}\nSTELA   0.1.0, build db45c012c4f1, started 2026-11-11 18:44:05 \
                 (firmware clock)\nPC      Intel(R) Core(TM) i7-12700K, family 0x6 model 0x97 \
                 stepping 2\n        16.0 GiB RAM, firmware \"EDK II\" revision 0x10000\n{}\n",
                THIN_RULE
            )
        );
        // Every line keeps to 80 columns but the CPU's, and is laid out
        // already: the formatter leaves it.
        for line in header.lines() {
            assert_eq!(crate::log_style::lay_out(line), line);
        }
        // AMD Zen 4: family 0x19 from the extended family.
        let zen = super::header(&Identity {
            signature: 0x00a6_0f12,
            ..Identity {
                version: "0.1.0",
                build: "unknown",
                time: None,
                hypervisor: true,
                cpu: "AMD Ryzen 7 7700X",
                signature: 0,
                ram_bytes: 0,
                firmware_vendor: "AMI",
                firmware_revision: 0,
            }
        });
        assert!(zen.contains("family 0x19 model 0x61 stepping 2"), "{zen}");
        assert!(zen.contains("STELA   0.1.0, build unknown\n"), "{zen}");
        assert!(zen.contains("under a hypervisor"), "{zen}");
    }

    #[test]
    fn smbios_strings_are_read_by_structure_type_and_offset() {
        // Type 0 with vendor and version strings, type 2 with a product but no
        // version, then the end structure.
        let mut table = alloc::vec![0, 0x18, 0, 0, 1, 2, 0, 0];
        table.resize(0x18, 0);
        table.extend(b"AMI\x002.02\x00\x00");
        table.extend([2, 8, 1, 0, 1, 2, 0, 0]);
        table.extend(b"ASUSTeK\x00ROG STRIX\x00\x00");
        table.extend([127, 4, 2, 0, 0, 0]);
        assert_eq!(smbios_string(&table, 0, 5), Some(&b"2.02"[..]));
        assert_eq!(smbios_string(&table, 2, 5), Some(&b"ROG STRIX"[..]));
        assert_eq!(smbios_string(&table, 2, 6), None);
        assert_eq!(smbios_string(&table, 2, 9), None);
        assert_eq!(smbios_string(&table, 3, 4), None);
        assert_eq!(smbios_string(&table[..20], 2, 5), None);
    }

    #[test]
    fn smbios_text_drops_the_terminator_and_padding() {
        // The table walk keeps each string's NUL.
        assert_eq!(smbios_text(b"QEMU\0"), Some(&b"QEMU"[..]));
        assert_eq!(
            smbios_text(b"Standard PC (Q35 + ICH9, 2009)\0"),
            Some(&b"Standard PC (Q35 + ICH9, 2009)"[..])
        );
        assert_eq!(smbios_text(b"  ASUS  \0\0"), Some(&b"ASUS"[..]));
        assert_eq!(smbios_text(b" \0"), None);
        assert_eq!(smbios_text(b""), None);
    }
}
