// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Checked ACPI ResourceTemplate memory descriptors for a UCSI mailbox.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryResource {
    pub physical: u64,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceError {
    Truncated,
    Checksum,
    MissingEnd,
    MissingMemory,
    MultipleMemory,
    UnsupportedMemory,
    InvalidMemory,
}

/// A plain account for the boot log.
impl core::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "its _CRS resource list is truncated",
            Self::Checksum => "its _CRS checksum is wrong",
            Self::MissingEnd => "its _CRS has no end tag",
            Self::MissingMemory => "its _CRS has no mailbox memory",
            Self::MultipleMemory => "its _CRS has more than one memory range",
            Self::UnsupportedMemory => "its _CRS memory descriptor is unsupported",
            Self::InvalidMemory => "its _CRS mailbox memory range is invalid",
        })
    }
}

fn number(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
}

/// Accept fixed writable Memory32Fixed or fixed consumer Word/DWord/QWord
/// address descriptors. Relocatable, translated, producer and read-only ranges
/// cannot authorize direct CPU mailbox access. Unknown non-memory descriptors
/// are skipped, keeping the template's bounds and optional checksum checks.
pub fn mailbox_resource(template: &[u8]) -> Result<MemoryResource, ResourceError> {
    let mut offset = 0;
    let mut memory = None;
    while offset < template.len() {
        let tag = template[offset];
        let (header, length) = if tag & 0x80 != 0 {
            let size = template
                .get(offset + 1..offset + 3)
                .ok_or(ResourceError::Truncated)?;
            (3, usize::from(u16::from_le_bytes([size[0], size[1]])))
        } else {
            (1, usize::from(tag & 7))
        };
        let end = offset
            .checked_add(header + length)
            .ok_or(ResourceError::Truncated)?;
        let data = template
            .get(offset + header..end)
            .ok_or(ResourceError::Truncated)?;
        if tag & 0xf8 == 0x78 {
            if tag != 0x79 || end != template.len() {
                return Err(ResourceError::MissingEnd);
            }
            if data[0] != 0 && template.iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0 {
                return Err(ResourceError::Checksum);
            }
            return memory.ok_or(ResourceError::MissingMemory);
        }
        let range = match tag {
            0x86 => {
                if data.len() != 9 || data[0] != 1 {
                    return Err(ResourceError::UnsupportedMemory);
                }
                Some((number(&data[1..5]), number(&data[5..9])))
            }
            0x87 | 0x88 | 0x8a => {
                let width = match tag {
                    0x88 => 2,
                    0x87 => 4,
                    _ => 8,
                };
                if data.len() < 3 + width * 5 {
                    return Err(ResourceError::Truncated);
                }
                if data[0] != 0 {
                    None // I/O/bus address descriptor, not a mailbox.
                } else {
                    // General flags: consumer, positive decode, min/max fixed.
                    // Memory flags: read/write; cache policy is supplied by the
                    // owned WB mapping, not inferred from descriptor caching.
                    if data[1] & 0x0f != 0x0d || data[2] & 1 == 0 {
                        return Err(ResourceError::UnsupportedMemory);
                    }
                    let min = number(&data[3 + width..3 + width * 2]);
                    let max = number(&data[3 + width * 2..3 + width * 3]);
                    let translation = number(&data[3 + width * 3..3 + width * 4]);
                    let length = number(&data[3 + width * 4..3 + width * 5]);
                    if translation != 0
                        || min.checked_add(length).and_then(|end| end.checked_sub(1)) != Some(max)
                    {
                        return Err(ResourceError::InvalidMemory);
                    }
                    Some((min, length))
                }
            }
            // Memory24, Memory32 and ExtendedAddress64 require additional
            // allocation/revision semantics; never silently ignore them.
            0x81 | 0x85 | 0x8b => return Err(ResourceError::UnsupportedMemory),
            _ => None,
        };
        if let Some((physical, bytes)) = range {
            if memory.is_some() {
                return Err(ResourceError::MultipleMemory);
            }
            if physical == 0
                || physical & 7 != 0
                || bytes < 16
                || physical.checked_add(bytes).is_none()
            {
                return Err(ResourceError::InvalidMemory);
            }
            memory = Some(MemoryResource {
                physical,
                bytes: usize::try_from(bytes).map_err(|_| ResourceError::InvalidMemory)?,
            });
        }
        offset = end;
    }
    Err(ResourceError::MissingEnd)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixed() -> [u8; 14] {
        [0x86, 9, 0, 1, 0, 0x90, 0, 0, 0x10, 2, 0, 0, 0x79, 0]
    }
    #[test]
    fn fixed_template_and_checksum() {
        let mut bytes = fixed();
        assert_eq!(
            mailbox_resource(&bytes),
            Ok(MemoryResource {
                physical: 0x9000,
                bytes: 528
            })
        );
        bytes[13] = 0u8.wrapping_sub(bytes[..13].iter().fold(0u8, |a, b| a.wrapping_add(*b)));
        assert!(mailbox_resource(&bytes).is_ok());
        bytes[13] ^= 1;
        assert_eq!(mailbox_resource(&bytes), Err(ResourceError::Checksum));
    }
    #[test]
    fn truncated_duplicate_readonly_unaligned_and_missing_end_refuse() {
        let good = fixed();
        for size in 0..good.len() {
            assert!(mailbox_resource(&good[..size]).is_err());
        }
        let mut two = good[..12].to_vec();
        two.extend_from_slice(&good);
        assert_eq!(mailbox_resource(&two), Err(ResourceError::MultipleMemory));
        let mut bad = good;
        bad[3] = 0;
        assert_eq!(
            mailbox_resource(&bad),
            Err(ResourceError::UnsupportedMemory)
        );
        bad = good;
        bad[4] = 1;
        assert_eq!(mailbox_resource(&bad), Err(ResourceError::InvalidMemory));
    }
    #[test]
    fn fixed_consumer_qword_and_translation_rejection() {
        let mut bytes = alloc::vec![0x8a, 43, 0, 0, 0x0d, 1];
        for word in [0u64, 0x9000, 0x920f, 0, 528] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x79, 0]);
        assert_eq!(
            mailbox_resource(&bytes),
            Ok(MemoryResource {
                physical: 0x9000,
                bytes: 528
            })
        );
        bytes[30] = 1;
        assert_eq!(mailbox_resource(&bytes), Err(ResourceError::InvalidMemory));
        bytes[30] = 0;
        bytes[4] = 0x0c;
        assert_eq!(
            mailbox_resource(&bytes),
            Err(ResourceError::UnsupportedMemory)
        );
    }
}
