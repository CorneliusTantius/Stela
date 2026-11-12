//! How Stela's log lines look, and the one formatter that lays them out
//! ([`layout`]): the boot's serial console and the USB's
//! `EFI/stela/boot.log` carry the same lines, and `stela boot-log` and the
//! screen's step list follow the same design.
//!
//! # Line layout
//!
//! ```text
//! [   34.094]       FIRMWARE       bundle files=10 size=65.6MiB manifest=2d5f5dfbef26
//! [   91.453] OK    Reading the boot files (484.0 MiB, 17.7 s)
//! ```
//!
//! - Time column: seconds since the PC started, in the USB log only (the
//!   serial console has its own clock).
//! - Mark column, [`MARK_WIDTH`] characters: `STEP` a step begins, `OK`,
//!   `WARN` or `FAIL` its result with its duration, `NOTE` a sentence for the
//!   user, blank for a detail line, which the blank column indents under its
//!   step.
//! - Topic column, [`TOPIC_WIDTH`] characters: the family in capitals; a
//!   longer one overflows by one space.
//! - Text: a plain sentence for what a user reads, else `key=value` pairs in
//!   a fixed order (identity, sizes, times, status). Keys are lowercase;
//!   values unquoted unless they hold spaces; units inside the value
//!   (`size=60.6MiB`, `time=585ms`, `time=17.7s`, [`size`], [`duration`]).
//!   No JSON and no Rust `Debug` text. Hashes keep 12 hex digits
//!   ([`short_hash`]).
//!
//! Lines whose format is a contract stay raw: the profile families, the
//! `STELA`/`STOP`/`GUEST|` lines and the boot's header and outcome blocks.
//!
//! # Private identifiers
//!
//! Disk and device serial numbers, MAC addresses, ECIDs and the UUIDs of the
//! user's volumes keep only their last 4 characters ([`short_id`],
//! [`short_ids`], [`redact`]) in everything a user may paste into a public
//! report. With `--profile`, which test runs use, the boot prints them
//! whole.
//!
//! # Repetition
//!
//! State once per boot, then only changes. Progress is drawn on the screen
//! and never appended to the log: the log gets the step's start and its end
//! with totals. Lines alike but for their numbers print once and then as a
//! count (`log_level::Repeats`); the heartbeat's summary prints once a
//! minute.
use alloc::{format, string::String};

/// The mark column's width, with its gap.
pub const MARK_WIDTH: usize = 6;
/// The topic column's width.
pub const TOPIC_WIDTH: usize = 14;

/// A line's marks: each begins the line followed by spaces up to the topic
/// column, so a line that starts with one is laid out already.
pub const STEP: &str = "STEP  ";
pub const OK: &str = "OK    ";
pub const WARN: &str = "WARN  ";
pub const FAIL: &str = "FAIL  ";
pub const NOTE: &str = "NOTE  ";

/// Lines that keep their own form: test scripts read them as they are.
const RAW: &[&str] = &[
    "STELA",
    "GUEST|",
    "GUEST-FRAGMENT",
    "STOP ",
    "WDT MECHANISM",
    "maintenance overrun",
    "MMU fault",
    "RESET ",
    "OUTCOME ",
];

/// How [`layout`] places the start of a line.
#[derive(Debug, PartialEq, Eq)]
pub enum Layout {
    /// Written as it is.
    Raw,
    /// The line's topic is `start[..topic]`; its first `taken` bytes, the
    /// topic and what follows it up to the text, become the blank mark
    /// column and the topic padded to [`TOPIC_WIDTH`] ([`columns`]).
    Detail { topic: usize, taken: usize },
}

/// Lay out the start of a line, `start` (at least its first words): a line
/// that is laid out already, starts with a space, or keeps its own form
/// ([`RAW`]) stays; any other gets the blank mark column and its topic, the
/// leading words in capitals (at most three), padded to [`TOPIC_WIDTH`]. A
/// word ending in `:` closes the topic (`ACPI: RSDP` has topic `ACPI`).
/// Allocates nothing: the boot lays out lines before its heap exists.
pub fn layout(start: &str) -> Layout {
    if start.is_empty()
        || start.starts_with(|c: char| !c.is_ascii_uppercase())
        || RAW.iter().any(|raw| start.starts_with(raw))
        || laid_out(start)
    {
        return Layout::Raw;
    }
    let (mut topic, mut taken) = (0, 0);
    for _ in 0..3 {
        let rest = &start[taken..];
        let word_end = rest.find(' ').unwrap_or(rest.len());
        let word = &rest[..word_end];
        let (word, closes) = match word.strip_suffix(':') {
            Some(word) => (word, true),
            None => (word, false),
        };
        if !is_topic_word(word) {
            break;
        }
        topic = taken + word.len();
        let spaces = rest[word_end..].len() - rest[word_end..].trim_start_matches(' ').len();
        taken += word_end + spaces;
        if closes || spaces != 1 {
            break;
        }
    }
    if topic == 0 {
        return Layout::Raw;
    }
    Layout::Detail { topic, taken }
}

/// The spaces after a topic of `length` bytes up to the text: the padding
/// to [`TOPIC_WIDTH`] and one more.
pub fn topic_gap(length: usize) -> usize {
    TOPIC_WIDTH.saturating_sub(length) + 1
}

/// Whether `start` begins with a mark or a block label: a first word
/// followed by two spaces or more.
fn laid_out(start: &str) -> bool {
    start
        .find(' ')
        .is_some_and(|end| start[end..].starts_with("  "))
}

/// A word of a topic: two or more capitals, digits or `_`, with a letter.
fn is_topic_word(word: &str) -> bool {
    word.len() >= 2
        && word
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && word.bytes().any(|b| b.is_ascii_uppercase())
}

/// `line` laid out whole ([`layout`]), for text that is not written in
/// parts, such as `stela boot-log`'s output and tests.
pub fn lay_out(line: &str) -> String {
    match layout(line) {
        Layout::Raw => String::from(line),
        Layout::Detail { topic, taken } => format!(
            "{:mark$}{}{:gap$}{}",
            "",
            &line[..topic],
            "",
            &line[taken..],
            mark = MARK_WIDTH,
            gap = topic_gap(topic)
        ),
    }
}

/// `line` as it was before [`layout`]: a detail line's blank mark column
/// and topic padding taken out (`TOPIC text`), for tools that read lines by
/// their family; any other line as it is.
pub fn unlay(line: &str) -> alloc::borrow::Cow<'_, str> {
    use alloc::borrow::Cow;
    let Some(rest) = line.strip_prefix(&SPACES[..MARK_WIDTH]) else {
        return Cow::Borrowed(line);
    };
    if !rest.starts_with(|c: char| c.is_ascii_uppercase()) {
        return Cow::Borrowed(line);
    }
    match rest.find("  ") {
        Some(end) if end <= TOPIC_WIDTH => Cow::Owned(format!(
            "{} {}",
            &rest[..end],
            rest[end..].trim_start_matches(' ')
        )),
        _ => Cow::Borrowed(rest),
    }
}

/// [`unlay`] of every line of `text`.
pub fn unlay_text(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        plain.push_str(&unlay(line));
    }
    plain
}

/// Spaces for the mark column.
const SPACES: &str = "      ";

/// How many trailing characters a private identifier keeps.
pub const ID_KEPT: usize = 4;
/// How many hex digits a hash keeps.
pub const HASH_KEPT: usize = 12;

/// `value` with all but its last [`ID_KEPT`] characters left out, as
/// `..1A2B`; a value that short stays whole, and an empty one stays empty.
pub fn short_id(value: &str) -> String {
    let value = value.trim();
    let count = value.chars().count();
    if count <= ID_KEPT {
        return String::from(value);
    }
    let tail: String = value.chars().skip(count - ID_KEPT).collect();
    format!("..{tail}")
}

/// `value`, a list of identifiers joined by `:` (a disk serial and a
/// partition UUID, or a volume group, volume and disk), each shortened.
pub fn short_ids(value: &str) -> String {
    value
        .split(':')
        .map(short_id)
        .collect::<alloc::vec::Vec<_>>()
        .join(":")
}

/// The first [`HASH_KEPT`] characters of a hex digest.
pub fn short_hash(hex: &str) -> &str {
    hex.get(..HASH_KEPT).unwrap_or(hex)
}

/// `bytes` in MiB below 1 GiB and in GiB from there, one decimal.
pub fn size(bytes: u64) -> String {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    if bytes >= GIB {
        format!("{}.{} GiB", bytes / GIB, bytes % GIB * 10 / GIB)
    } else {
        format!("{}.{} MiB", bytes / MIB, bytes % MIB * 10 / MIB)
    }
}

/// [`size`] as a `key=value` value: no space before the unit.
pub fn size_value(bytes: u64) -> String {
    size(bytes).replace(' ', "")
}

/// [`duration`] as a `key=value` value: no space before the unit.
pub fn duration_value(millis: u64) -> String {
    duration(millis).replace(' ', "")
}

/// `millis` as `ms` below 10 s and as seconds with one decimal from there.
pub fn duration(millis: u64) -> String {
    if millis < 10_000 {
        format!("{millis} ms")
    } else {
        format!("{}.{} s", millis / 1000, millis % 1000 / 100)
    }
}

/// `line` with every private identifier shortened: each UUID
/// (8-4-4-4-12 hex digits) to its last [`ID_KEPT`] characters, and the
/// value of each `serial=` or `mac=` field likewise. Lines a boot wrote
/// before its own lines were shortened, and identifiers no line names on
/// purpose, are covered this way when a log is printed for a report.
pub fn redact(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut at = 0;
    while at < line.len() {
        if let Some(length) = uuid_at(bytes, at)
            && (at == 0 || !bytes[at - 1].is_ascii_alphanumeric())
        {
            // `SERIAL:UUID` names a disk by its serial number too.
            if let Some(before) = out.strip_suffix(':') {
                let start = before
                    .rfind(|c: char| c.is_whitespace() || c == '=' || c == '"' || c == ':')
                    .map_or(0, |at| at + 1);
                let serial = short_id(&before[start..]);
                out.truncate(start);
                out.push_str(&serial);
                out.push(':');
            }
            out.push_str(&short_id(&line[at..at + length]));
            at += length;
            continue;
        }
        if let Some(key) = ["serial=", "mac="]
            .into_iter()
            .find(|key| line[at..].starts_with(key))
            && (at == 0 || !bytes[at - 1].is_ascii_alphanumeric())
        {
            out.push_str(key);
            at += key.len();
            let rest = &line[at..];
            let (value, length) = match rest.strip_prefix('"') {
                Some(quoted) => {
                    let end = quoted.find('"').unwrap_or(quoted.len());
                    (&quoted[..end], (end + 2).min(rest.len()))
                }
                None => {
                    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                    (&rest[..end], end)
                }
            };
            let quoted = rest.starts_with('"');
            if quoted {
                out.push('"');
            }
            out.push_str(&match key {
                "mac=" => short_id(value),
                _ => short_ids(value),
            });
            if quoted {
                out.push('"');
            }
            at += length;
            continue;
        }
        let next = line[at..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&line[at..at + next]);
        at += next;
    }
    out
}

/// The length of the UUID starting at byte `at` of `bytes`, if one does.
fn uuid_at(bytes: &[u8], at: usize) -> Option<usize> {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let mut position = at;
    for (index, group) in GROUPS.iter().enumerate() {
        let digits = bytes.get(position..position + group)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        position += group;
        if index + 1 < GROUPS.len() {
            if bytes.get(position) != Some(&b'-') {
                return None;
            }
            position += 1;
        }
    }
    if bytes.get(position).is_some_and(u8::is_ascii_alphanumeric) {
        return None;
    }
    Some(position - at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_lines_get_the_mark_and_topic_columns() {
        assert_eq!(
            lay_out("HOST PCI 0000:00:01.0 1234:1111 class=030000: GPU"),
            "      HOST PCI       0000:00:01.0 1234:1111 class=030000: GPU"
        );
        assert_eq!(
            lay_out("CHOSEN DISK ..9A1B:..4E5F"),
            "      CHOSEN DISK    ..9A1B:..4E5F"
        );
        assert_eq!(
            lay_out("INSTALL MEDIUM pieces=6 size=23.8GiB"),
            "      INSTALL MEDIUM pieces=6 size=23.8GiB"
        );
        assert_eq!(
            lay_out("NATIVE FIRMWARE INIT deliveries=15"),
            "      NATIVE FIRMWARE INIT deliveries=15"
        );
        assert_eq!(
            lay_out("ACPI: RSDP 0x7F97E014"),
            "      ACPI           RSDP 0x7F97E014"
        );
        assert_eq!(lay_out("DISPLAY "), "      DISPLAY        ");
        // Laying out and taking the layout out again.
        for line in [
            "HOST PCI 0000:00:01.0 GPU",
            "INSTALL MEDIUM pieces=6",
            "NATIVE FIRMWARE INIT deliveries=15",
            "DISPLAY a  b",
            "STEP  Reading",
            "GUEST| x",
        ] {
            assert_eq!(unlay(&lay_out(line)), line);
        }
        assert_eq!(unlay_text("      TCP            a\nb\n"), "TCP a\nb\n");
        // A line laid out already, a block label, a raw family, text.
        for raw in [
            "STEP  Reading the boot files",
            "OK    Reading the boot files (17.7 s)",
            "BOOT    3, Stela 0.3.0",
            "        continued",
            "STELA FATAL no disk",
            "GUEST| panic",
            "STOP reset: watchdog",
            "WDT MECHANISM armed",
            "maintenance overrun pe=1",
            "Boot log",
            "x2APIC on",
        ] {
            assert_eq!(lay_out(raw), raw);
        }
    }

    #[test]
    fn identifiers_keep_their_last_four_characters() {
        assert_eq!(short_id("S5GXNX0T123456A"), "..456A");
        assert_eq!(short_id("AB12"), "AB12");
        assert_eq!(short_id(""), "");
        assert_eq!(
            short_ids("S5GXNX0T123456A:5E1A0000-0000-4000-8000-0000000000C0"),
            "..456A:..00C0"
        );
    }

    #[test]
    fn sizes_times_and_hashes_take_one_form() {
        assert_eq!(size(484 << 20), "484.0 MiB");
        assert_eq!(size(25_595_669_503), "23.8 GiB");
        assert_eq!(duration(585), "585 ms");
        assert_eq!(duration(17_754), "17.7 s");
        assert_eq!(size_value(484 << 20), "484.0MiB");
        assert_eq!(duration_value(585), "585ms");
        assert_eq!(
            short_hash("2d5f5dfbef26f61935f254d51f1db4c9"),
            "2d5f5dfbef26"
        );
        assert_eq!(short_hash("abc"), "abc");
    }

    #[test]
    fn redaction_shortens_uuids_serials_and_macs() {
        assert_eq!(
            redact("CHOSEN DISK 2111082561276:5E1A0000-0000-4000-8000-0000000000C0"),
            "CHOSEN DISK ..1276:..00C0"
        );
        assert_eq!(
            redact("INSTALLER disk SATA PNY CS900 serial=\"PNY123456789\" bytes=1 table=5"),
            "INSTALLER disk SATA PNY CS900 serial=\"..6789\" bytes=1 table=5"
        );
        assert_eq!(
            redact("HOST DISK IO serial=STELAANS read=1"),
            "HOST DISK IO serial=..AANS read=1"
        );
        assert_eq!(redact("NET mac=52:54:00:12:34:56 up"), "NET mac=..4:56 up");
        // Hashes and words that only look alike stay.
        let plain = "TRANSLATIONS stela\\store\\fac05158.pak sha=2d5f5dfbef26f619 caf\u{e9}";
        assert_eq!(redact(plain), plain);
        assert_eq!(redact("deserial=abc"), "deserial=abc");
    }
}
