//! Which lines a boot prints ([`classify`]), and the counter that keeps
//! lines alike to one line and a few counts ([`Repeats`]). The serial
//! console and the boot logs carry one stream: a line the boot does not
//! print reaches neither, and waits in a ring of held-back detail that a
//! stopping boot prints.
//!
//! Two levels: the default one, which carries everything that helps find a
//! problem from one pasted log, with the heartbeat once a minute; and
//! `--profile` in `stela.cfg` (`stela setup configure --log profile`), which
//! adds the engine's per-beat measurement families in their fixed formats.

/// How much a boot logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Steps, inventory, each step's inputs and results, every refusal and
    /// failure, and the heartbeat's summary once a minute.
    Default,
    /// Also the engine's timing, sampling and counter families each beat,
    /// as `--profile` always printed them.
    Profile,
}

/// What a line's family asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// Printed at every level.
    Always,
    /// A heartbeat summary line: printed at the default level only in a
    /// logged beat ([`BEAT_EVERY`]), every beat with `--profile`.
    Beat,
    /// Printed only with `--profile`.
    Profile,
}

impl Need {
    /// Whether a boot at `level` prints the line, in a logged beat or not.
    pub fn printed(self, level: Level, logged_beat: bool) -> bool {
        match self {
            Need::Always => true,
            Need::Beat => logged_beat || level == Level::Profile,
            Need::Profile => level == Level::Profile,
        }
    }
}

/// The default level logs one heartbeat in this many: once a minute at
/// the engine's 10-second beat.
pub const BEAT_EVERY: u64 = 6;

/// The heartbeat's summary families, which the default level keeps once a
/// minute.
const BEAT: &[&str] = &[
    "ANS",
    "ASC",
    "BEAT",
    "CLOCK RATE",
    "EXCEPTION",
    "HEAP",
    "HOST DISK IO",
    "REGISTERS",
    "STALE",
    "SUSPENDED",
    "TRANSLATION",
    "USB",
];

/// Lines of a heartbeat or profile family that every beat prints: a device
/// that failed or came and went.
const ALWAYS: &[&str] = &[
    "USB FAILED",
    "USB UNUSED",
    "USB VENDOR FAILED",
    "USB added",
    "USB removed",
    "USB storage",
];

/// Families printed only with `--profile`: the engine's timing, sampling
/// and counter reports, the firmware's records as JSON, each file read and
/// each progress detail, whose totals the default lines carry.
const PROFILE: &[&str] = &[
    "BEAT COST",
    "CLOCK",
    "CURSOR",
    "DCP PACING",
    "DCP payload",
    "DEVICE LOCK",
    "DEVICE REGISTERS",
    "DEVICE TRANSFERS",
    "DEVICE WAKES",
    "ENGINE MEMORY",
    "EXITS",
    "GPU CALLS",
    "GPU COMPILER",
    "GPU EXIT",
    "GPU HEAP",
    "GPU JOBS",
    "GPU LATENCY",
    "GPU LINUX",
    "GPU LOCK",
    "GPU MEMORY",
    "GPU NVKM",
    "GPU PASSES",
    "GPU PHASES",
    "GPU PIPELINE",
    "GPU POSTED",
    "GPU PRESENTS",
    "GPU PUMP",
    "GPU QUEUED",
    "GPU SERVED",
    "GPU STORE",
    "GPU TAKEN",
    "GPU TIMES",
    "GUEST PERFORMANCE",
    "HEAP LARGE",
    "HEAP OWNERS",
    "HEAP PEAK",
    "HOST DISK CALLBACK",
    "HOST FIRMWARE RECORD",
    "HOST SERVICE",
    "HOST SMBIOS RECORD",
    "HOST WIFI UEFI RECORD",
    "HOT",
    "HOT CODE",
    "INPUT TIMES",
    "NATIVE FIRMWARE INIT delivered",
    "PE BROADCAST",
    "PE SOURCE",
    "PES",
    "PROFILE",
    "READ",
    "SAMPLE",
    "SAMPLES",
    "SHADOW",
    "STEP DETAIL",
    "SUSPENSION",
    "SYSTEM WORDS",
    "TIMERS",
    "XHCI",
];

/// Whether `line` starts with family `name`: the name, then the end of the
/// line or a character that cannot continue a word of it.
pub fn is_family(line: &str, name: &str) -> bool {
    line.strip_prefix(name)
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
}

/// The longest family of `names` that `line` belongs to, by its length.
fn longest(line: &str, names: &[&str]) -> usize {
    names
        .iter()
        .filter(|name| is_family(line, name))
        .map(|name| name.len())
        .max()
        .unwrap_or(0)
}

/// What the line starting with `line` asks for: the longest family name it
/// starts with decides, so `BEAT COST` is a profile line while `BEAT` is a
/// heartbeat one, and `CLOCK RATE` one while `CLOCK` is a profile line. A
/// family no table names is printed at every level. The start of a line is
/// enough: names are matched as prefixes.
pub fn classify(line: &str) -> Need {
    let candidates = [
        (longest(line, ALWAYS), Need::Always),
        (longest(line, BEAT), Need::Beat),
        (longest(line, PROFILE), Need::Profile),
    ];
    candidates
        .into_iter()
        .filter(|(length, _)| *length != 0)
        .max_by_key(|(length, _)| *length)
        .map_or(Need::Always, |(_, need)| need)
}

/// Lines alike seen so far, by hash: the first is printed, and then the
/// count at 10, 100, 1000 and so on. Lines are alike when they differ only
/// in numbers (a process ID, an address), as a refusal an app repeats
/// hundreds of times does.
pub struct Repeats {
    seen: [(u64, u64); Self::SLOTS],
}

/// What to do with a line [`Repeats::see`] was shown.
#[derive(Debug, PartialEq, Eq)]
pub enum Repeat {
    /// First seen: print it.
    First,
    /// Seen this many times: print one line saying so.
    Count(u64),
    /// Seen before: leave it out.
    Again,
}

impl Default for Repeats {
    fn default() -> Self {
        Self::new()
    }
}

impl Repeats {
    /// Distinct lines followed at once; a further one takes the slot of
    /// the least seen.
    pub const SLOTS: usize = 32;

    pub const fn new() -> Self {
        Self {
            seen: [(0, 0); Self::SLOTS],
        }
    }

    pub fn see(&mut self, line: &str) -> Repeat {
        let hash = alike(line.trim_end().as_bytes()) | 1;
        if let Some(slot) = self.seen.iter_mut().find(|(seen, _)| *seen == hash) {
            slot.1 += 1;
            let count = slot.1;
            let mut power = 10;
            while power < count {
                power = power.saturating_mul(10);
            }
            return if power == count {
                Repeat::Count(count)
            } else {
                Repeat::Again
            };
        }
        let slot = self
            .seen
            .iter_mut()
            .min_by_key(|(_, count)| *count)
            .expect("Repeats has slots");
        *slot = (hash, 1);
        Repeat::First
    }
}

/// FNV-1a of `bytes` without their numbers: decimal digits, and the hex
/// digits after `0x`.
fn alike(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut hex = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'x' && index > 0 && bytes[index - 1] == b'0' {
            hex = true;
            continue;
        }
        if byte.is_ascii_digit() || (hex && byte.is_ascii_hexdigit()) {
            continue;
        }
        hex = false;
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_take_their_level_by_the_longest_name() {
        assert_eq!(classify("PES SYSTEM count/ns 1"), Need::Profile);
        assert_eq!(classify("PES switches=4"), Need::Profile);
        assert_eq!(classify("BEAT blocks=1 pc=0x0"), Need::Beat);
        assert_eq!(classify("BEAT COST 3 ms"), Need::Profile);
        assert_eq!(classify("CLOCK RATE guest_per_wall=1.000"), Need::Beat);
        assert_eq!(classify("CLOCK count=0x5"), Need::Profile);
        assert_eq!(classify("HOT samples=4 0x1:2"), Need::Profile);
        assert_eq!(classify("HOST MEMORY free=1M"), Need::Always);
        assert_eq!(classify("HOST DISK IO serial=x"), Need::Beat);
        assert_eq!(classify("HOST FIRMWARE RECORD {}"), Need::Profile);
        assert_eq!(classify("HOST FIRMWARE BUNDLE USE a"), Need::Always);
        assert_eq!(classify("READ \\stela\\boot\\x"), Need::Profile);
        assert_eq!(classify("READY"), Need::Always);
        assert_eq!(classify("USB port=1 attached=true"), Need::Beat);
        assert_eq!(classify("USB FAILED 1-2: stall"), Need::Always);
        assert_eq!(classify("USBX"), Need::Always);
        assert_eq!(classify("HEAP small=3M large=9M"), Need::Beat);
        assert_eq!(classify("HEAP LARGE 4M"), Need::Profile);
        assert_eq!(classify("GPU STORE hits=0 misses=11"), Need::Profile);
        assert_eq!(
            classify("NATIVE FIRMWARE INIT delivered apic=0x1"),
            Need::Profile
        );
        assert_eq!(classify("NATIVE FIRMWARE INIT deliveries=15"), Need::Always);
        for kept in [
            "STELA FATAL x",
            "STELA STOPPED code=0x11",
            "UNSUPPORTED register",
            "WDT MECHANISM armed",
            "GPU REFUSED call",
            "MMU fault at",
            "STEP  Reading",
            "CHOSEN DISK x",
            "GUEST| x",
            "DCP call x",
        ] {
            assert_eq!(classify(kept), Need::Always, "{kept}");
        }
    }

    #[test]
    fn levels_print_what_they_need() {
        assert!(Need::Always.printed(Level::Default, false));
        assert!(!Need::Beat.printed(Level::Default, false));
        assert!(Need::Beat.printed(Level::Default, true));
        assert!(Need::Beat.printed(Level::Profile, false));
        assert!(!Need::Profile.printed(Level::Default, true));
        assert!(Need::Profile.printed(Level::Profile, false));
    }

    #[test]
    fn lines_alike_print_once_then_counts() {
        let mut repeats = Repeats::new();
        let mut printed = alloc::vec::Vec::new();
        for _ in 0..120 {
            match repeats.see("mediaanalysisd[812] asked by Metal+0x1f00: status 5") {
                Repeat::Again => {}
                other => printed.push(other),
            }
        }
        // Another process and address are alike; other words are not.
        assert_eq!(
            repeats.see("mediaanalysisd[90] asked by Metal+0xa0: status 5"),
            Repeat::Again
        );
        assert_eq!(
            repeats.see("WindowServer[90] asked by Metal+0xa0: status 5"),
            Repeat::First
        );
        assert_eq!(
            printed,
            [Repeat::First, Repeat::Count(10), Repeat::Count(100)]
        );
    }
}
