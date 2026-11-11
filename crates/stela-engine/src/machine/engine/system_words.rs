//! System exits by instruction word under step timing: an open-addressed
//! table, one multiply and usually one probe per exit, instead of an
//! ordered map's search and node walk. Words past its capacity go to an
//! ordered map, so none is lost.
use super::DeviceRegister;
use alloc::{boxed::Box, collections::BTreeMap};

/// Slots: far above the distinct exiting words a PE meets (a few hundred).
const SLOTS: usize = 1024;
/// Probes before a word goes to the overflow map.
const PROBES: usize = 16;

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    /// The word plus 1 << 32; zero when the slot is free.
    key: u64,
    timed: DeviceRegister,
}

#[derive(Debug, Clone)]
pub(super) struct SystemWords {
    slots: Box<[Slot; SLOTS]>,
    overflow: BTreeMap<u32, DeviceRegister>,
}

impl Default for SystemWords {
    fn default() -> Self {
        Self {
            slots: Box::new([Slot::default(); SLOTS]),
            overflow: BTreeMap::new(),
        }
    }
}

impl SystemWords {
    /// Count one exit of `word` that took `ticks`.
    #[inline]
    pub(super) fn add(&mut self, word: u32, ticks: u64) {
        let key = u64::from(word) | 1 << 32;
        let start = (word.wrapping_mul(0x9e37_79b1) >> 22) as usize;
        for probe in 0..PROBES {
            let slot = &mut self.slots[(start + probe) % SLOTS];
            if slot.key == 0 {
                slot.key = key;
            }
            if slot.key == key {
                slot.timed.accesses += 1;
                slot.timed.ticks += ticks;
                return;
            }
        }
        let timed = self.overflow.entry(word).or_default();
        timed.accesses += 1;
        timed.ticks += ticks;
    }

    /// Every word's totals, ordered by word.
    pub(super) fn to_map(&self) -> BTreeMap<u32, DeviceRegister> {
        let mut map = self.overflow.clone();
        for slot in self.slots.iter().filter(|slot| slot.key != 0) {
            map.insert(slot.key as u32, slot.timed);
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_words_table_matches_an_ordered_map() {
        let mut table = SystemWords::default();
        let mut map: BTreeMap<u32, DeviceRegister> = BTreeMap::new();
        let mut state = 0x1234_5678_u64;
        for i in 0..20_000u64 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            // Mostly a few hot words, then enough distinct ones to fill the
            // table and spill, including 0 and u32::MAX.
            let word = match i % 4 {
                0 => [0xd51b_d020, 0, u32::MAX][(state % 3) as usize],
                1 => (state % 64) as u32 * 0x20,
                _ => (state % 3000) as u32 * 0x1_0001,
            };
            table.add(word, i);
            let timed = map.entry(word).or_default();
            timed.accesses += 1;
            timed.ticks += i;
        }
        assert!(map.len() > SLOTS);
        assert!(!table.overflow.is_empty());
        assert_eq!(table.to_map(), map);
    }
}
