//! The persistent boot log: `stela.efi`'s output kept on the machine-state
//! partition, so a bare-metal run leaves a log to read after the machine
//! reboots.
//!
//! The region starts at [`OFFSET`] of the partition, after the NOR image and
//! the SEP's state, and is [`LOG_BYTES`] long; a partition of at least
//! [`PARTITION_BYTES`] holds it. Its first [`HEADER_BYTES`] are the header:
//!
//! | Offset | Bytes | Field |
//! | --- | --- | --- |
//! | 0 | 8 | magic `STELALOG` |
//! | 8 | 4 | version, 2 |
//! | 12 | 4 | reserved, zero |
//! | 16 | 8 | `head`: every byte ever appended, monotonic |
//! | 24 | 8 | `boots`: boots that opened the log |
//! | 32 | 8 | `ring_bytes`: the region less the header and the kept blocks |
//! | 40 | 32 | SHA-256 of bytes 0..40 |
//!
//! The kept blocks follow the header: [`KEPT_SLOTS`] slots of
//! [`SLOT_BYTES`], boot `n`'s at `n % KEPT_SLOTS`, each holding that boot's
//! header block and outcome block ([`Kept`]), so a boot the ring has
//! overwritten still shows what ran and how it ended:
//!
//! | Offset | Bytes | Field |
//! | --- | --- | --- |
//! | 0 | 8 | the boot's number; 0 for an empty slot |
//! | 8 | 2 | `h`: header bytes |
//! | 10 | 2 | `o`: outcome bytes |
//! | 12 | 32 | SHA-256 of bytes 0..12 and the `h + o` text bytes |
//! | 44 | `h + o` | the header block's lines, then the outcome block's |
//!
//! The ring follows them. Stream byte `i` lives at `ring[i % ring_bytes]`,
//! so the valid stream is `[head.saturating_sub(ring_bytes), head)`. A blank
//! or invalid header is a fresh log, reported by its [`HeaderError`];
//! [`read`] refuses it. Version 1 had no kept blocks, its ring right after
//! the header: [`read`] still reads it, and a boot starts it over as a
//! version 2 log.
//!
//! [`Writer`] opens the log once per boot, counts the boot and appends a
//! `=== STELA BOOT n ===` line. It keeps the boot's header block, the lines
//! between the first [`RULE`] and the [`THIN_RULE`] after it, and its
//! latest outcome block, a [`THIN_RULE`], an [`OUTCOME`] line and a
//! [`RULE`], in the boot's slot. Appends wait in a bounded [`Pending`]
//! buffer; a flush writes the changed ring blocks, makes them durable, then
//! writes the header and makes it durable, so the header never counts bytes
//! the ring does not hold. Once the ring has wrapped, an interrupted flush can
//! leave the bytes it wrote in place of the oldest ones the old header still
//! counts, at most the bytes of that one flush.
//!
//! A file preallocated on a FAT32 volume can hold a log too: a machine-state
//! file (`--nor-file`) laid out as the partition is, or the USB's own log
//! (`stela_loader::mount_interface::BOOT_LOG_FILE`), [`LOG_BYTES`] of the
//! region alone. Writes reach its blocks directly, never the volume's
//! directory or FAT: [`file_runs`] gives the block-aligned runs of its
//! clusters, wherever they lie, that hold the bytes its layout needs.
use super::fat32;
use alloc::{collections::VecDeque, format, vec, vec::Vec};
use core::{
    convert::Infallible,
    fmt::{self, Write as _},
};
use stela_crypto::Sha256;
use stela_crypto::digest::Digest;
use stela_drivers::block::{BlockDevice, BlockError, Finished, Request};
use stela_soc_data::nor::CAPACITY;

/// Where the region starts in the machine-state partition.
pub const OFFSET: u64 = CAPACITY as u64 + stela_formats::machine_state::SEP_BYTES;
/// The region: the header, the kept blocks and the ring.
pub const LOG_BYTES: u64 = 4 << 20;
/// The smallest machine-state partition that holds the log.
pub const PARTITION_BYTES: u64 = OFFSET + LOG_BYTES;
pub const HEADER_BYTES: u64 = 4096;
/// The boots whose header and outcome blocks the log keeps.
pub const KEPT_SLOTS: u64 = 64;
/// One boot's kept blocks.
pub const SLOT_BYTES: usize = 1024;
pub const KEPT_BYTES: u64 = KEPT_SLOTS * SLOT_BYTES as u64;
/// What comes before the ring: the header and the kept blocks.
pub const LAYOUT_BYTES: u64 = HEADER_BYTES + KEPT_BYTES;
/// The ring of a [`LOG_BYTES`] region.
pub const RING_BYTES: u64 = LOG_BYTES - LAYOUT_BYTES;
/// The bound of a pending buffer between flushes.
pub const PENDING_BYTES: usize = 1 << 20;
pub const MAGIC: &[u8; 8] = b"STELALOG";
pub const VERSION: u32 = 2;
/// The rule that opens a boot's header block and closes its outcome block.
pub const RULE: &str =
    "================================================================================";
/// The rule that closes the header block and opens the outcome block.
pub const THIN_RULE: &str =
    "--------------------------------------------------------------------------------";
/// The line of a boot's outcome block that says how it ended.
pub const OUTCOME: &str = "OUTCOME ";
/// The header fields the checksum covers.
const FIELDS: usize = 40;
const RECORD: usize = FIELDS + 32;

/// Why a region holds no log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// All zeros: no boot has written a log here.
    Blank,
    /// The region does not start with `STELALOG`.
    NotALog,
    Version(u32),
    /// Reserved header bytes are not zero.
    Reserved,
    Checksum,
    /// The header's ring is not the one this region holds.
    RingSize {
        recorded: u64,
        region: u64,
    },
    /// The region is too short for the header and a ring.
    Short {
        bytes: u64,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blank => f.write_str("the log region is blank"),
            Self::NotALog => f.write_str("the log region holds no STELALOG header"),
            Self::Version(version) => {
                write!(f, "the log header is version {version}, not {VERSION}")
            }
            Self::Reserved => f.write_str("the log header's reserved bytes are not zero"),
            Self::Checksum => f.write_str("the log header's checksum does not match"),
            Self::RingSize { recorded, region } => write!(
                f,
                "the log header records a {recorded:#x}-byte ring; the region holds {region:#x}"
            ),
            Self::Short { bytes } => write!(
                f,
                "the log region holds {bytes:#x} bytes, too few for its header, kept blocks and \
                 a ring"
            ),
        }
    }
}

impl core::error::Error for HeaderError {}

/// Why a file cannot stand in for the machine-state partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileError {
    /// A run of its clusters starts or ends off a block boundary.
    Misaligned { offset: u64, block: u64 },
    /// It holds fewer than the `needed` bytes in whole blocks.
    Short { bytes: u64, needed: u64 },
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Misaligned { offset, block } => write!(
                f,
                "the file has bytes from {offset:#x}, not on a {block}-byte block boundary"
            ),
            Self::Short { bytes, needed } => write!(
                f,
                "the file holds {bytes:#x} bytes in whole blocks; it needs {needed:#x}"
            ),
        }
    }
}

/// Why the device does not hold what a flush stored ([`Writer::verify`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unkept {
    Read(BlockError),
    Header(HeaderError),
    /// The stored header counts other bytes than the flush wrote.
    Head {
        stored: u64,
        written: u64,
    },
}

impl fmt::Display for Unkept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(f, "the header cannot be read back: {error}"),
            Self::Header(error) => {
                write!(f, "the header read back is not the one written: {error}")
            }
            Self::Head { stored, written } => write!(
                f,
                "the header read back counts {stored:#x} bytes; {written:#x} were written"
            ),
        }
    }
}

impl core::error::Error for Unkept {}

/// The runs of `file`'s blocks that hold its first `needed` bytes, each a
/// first block and a count, in order: `file` is on a partition of
/// `block`-byte blocks and holds [`PARTITION_BYTES`] for a machine-state
/// file, [`LOG_BYTES`] for a log file.
pub fn file_runs(
    file: &fat32::File,
    block: u64,
    needed: u64,
) -> Result<Vec<(u64, u64)>, FileError> {
    let (mut runs, mut bytes) = (Vec::<(u64, u64)>::new(), 0);
    // Where the last run ended inside a block, which no next run can follow.
    let mut partial = None;
    for extent in &file.extents {
        if bytes >= needed {
            break;
        }
        if let Some(offset) =
            partial.or((!extent.offset.is_multiple_of(block)).then_some(extent.offset))
        {
            return Err(FileError::Misaligned { offset, block });
        }
        let count = (extent.bytes / block).min((needed - bytes).div_ceil(block));
        if !extent.bytes.is_multiple_of(block) {
            partial = Some(extent.offset + extent.bytes);
        }
        let first = extent.offset / block;
        match runs.last_mut() {
            Some((start, blocks)) if *start + *blocks == first => *blocks += count,
            _ => runs.push((first, count)),
        }
        bytes += count * block;
    }
    if bytes < needed {
        return Err(FileError::Short { bytes, needed });
    }
    Ok(runs)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Header {
    version: u32,
    head: u64,
    boots: u64,
    ring_bytes: u64,
}

impl Header {
    /// A fresh log's header.
    fn new(ring_bytes: u64) -> Self {
        Self {
            version: VERSION,
            head: 0,
            boots: 0,
            ring_bytes,
        }
    }

    /// The ring of a `region`-byte region in this header's version.
    fn ring_of(version: u32, region: u64) -> u64 {
        let before = if version == 1 {
            HEADER_BYTES
        } else {
            LAYOUT_BYTES
        };
        region.saturating_sub(before)
    }

    /// `block` with the header at its start and zeros after it.
    fn encode(&self, block: &mut [u8]) {
        block.fill(0);
        block[..8].copy_from_slice(MAGIC);
        block[8..12].copy_from_slice(&self.version.to_le_bytes());
        block[16..24].copy_from_slice(&self.head.to_le_bytes());
        block[24..32].copy_from_slice(&self.boots.to_le_bytes());
        block[32..40].copy_from_slice(&self.ring_bytes.to_le_bytes());
        let digest = Sha256::digest(&block[..FIELDS]);
        block[FIELDS..RECORD].copy_from_slice(&digest);
    }

    /// The header at the start of `bytes`, for a `region`-byte region, in
    /// this version or version 1.
    fn decode(bytes: &[u8], region: u64) -> Result<Self, HeaderError> {
        if bytes.iter().all(|&byte| byte == 0) {
            return Err(HeaderError::Blank);
        }
        if bytes.len() < RECORD || &bytes[..8] != MAGIC {
            return Err(HeaderError::NotALog);
        }
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != VERSION && version != 1 {
            return Err(HeaderError::Version(version));
        }
        if Sha256::digest(&bytes[..FIELDS])[..] != bytes[FIELDS..RECORD] {
            return Err(HeaderError::Checksum);
        }
        if bytes[12..16] != [0; 4] {
            return Err(HeaderError::Reserved);
        }
        let header = Self {
            version,
            head: u64_at(16),
            boots: u64_at(24),
            ring_bytes: u64_at(32),
        };
        let ring_bytes = Self::ring_of(version, region);
        if ring_bytes == 0 {
            return Err(HeaderError::Short { bytes: region });
        }
        if header.ring_bytes != ring_bytes {
            return Err(HeaderError::RingSize {
                recorded: header.ring_bytes,
                region: ring_bytes,
            });
        }
        Ok(header)
    }
}

/// A boot's kept blocks, which outlive the ring ([`KEPT_SLOTS`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Kept {
    pub boot: u64,
    /// The header block's lines, without its rules.
    pub header: Vec<u8>,
    /// The outcome block's lines, without its rules; empty while the boot
    /// has written none.
    pub outcome: Vec<u8>,
}

/// The bytes of a slot before its text.
const SLOT_FIELDS: usize = 12 + 32;
/// The most text bytes of each block a slot keeps; an outcome block is one
/// line, a header block about four.
const OUTCOME_KEPT: usize = 400;
const HEADER_KEPT: usize = SLOT_BYTES - SLOT_FIELDS - OUTCOME_KEPT;

impl Kept {
    fn slot_digest(fields: &[u8], text: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(fields);
        digest.update(text);
        digest.finalize().into()
    }

    /// `slot` holding these blocks.
    fn encode(&self, slot: &mut [u8]) {
        slot.fill(0);
        let (header, outcome) = (self.header.len(), self.outcome.len());
        slot[..8].copy_from_slice(&self.boot.to_le_bytes());
        slot[8..10].copy_from_slice(&(header as u16).to_le_bytes());
        slot[10..12].copy_from_slice(&(outcome as u16).to_le_bytes());
        let text = &mut slot[SLOT_FIELDS..SLOT_FIELDS + header + outcome];
        text[..header].copy_from_slice(&self.header);
        text[header..].copy_from_slice(&self.outcome);
        let digest = Self::slot_digest(
            &slot[..12],
            &slot[SLOT_FIELDS..SLOT_FIELDS + header + outcome],
        );
        slot[12..SLOT_FIELDS].copy_from_slice(&digest);
    }

    /// The blocks `slot` holds; `None` for an empty or damaged slot.
    fn decode(slot: &[u8]) -> Option<Self> {
        let boot = u64::from_le_bytes(slot.get(..8)?.try_into().ok()?);
        let header = usize::from(u16::from_le_bytes(slot.get(8..10)?.try_into().ok()?));
        let outcome = usize::from(u16::from_le_bytes(slot.get(10..12)?.try_into().ok()?));
        let text = slot.get(SLOT_FIELDS..SLOT_FIELDS + header + outcome)?;
        if boot == 0 || Self::slot_digest(&slot[..12], text)[..] != slot[12..SLOT_FIELDS] {
            return None;
        }
        Some(Self {
            boot,
            header: text[..header].to_vec(),
            outcome: text[header..].to_vec(),
        })
    }
}

/// Where a boot's lines are for [`Keeper`].
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Scan {
    /// Before the header block's opening [`RULE`].
    #[default]
    Before,
    /// Inside the header block.
    Header,
    /// After it.
    Body,
    /// Just after a [`THIN_RULE`], which may open an outcome block.
    Rule,
    /// Inside an outcome block.
    Outcome,
}

/// Picks a boot's header block and its latest outcome block from the lines
/// it appends, for its slot.
#[derive(Default)]
struct Keeper {
    /// The line being appended, its first [`LINE_KEPT`] bytes.
    line: Vec<u8>,
    scan: Scan,
    kept: Kept,
    /// An outcome block being read.
    outcome: Vec<u8>,
    /// Counts each change to `kept`.
    generation: u64,
}

/// The most bytes of a line [`Keeper`] looks at and keeps.
const LINE_KEPT: usize = 320;

impl Keeper {
    fn scan(&mut self, bytes: &[u8]) {
        for piece in bytes.split_inclusive(|&byte| byte == b'\n') {
            let room = LINE_KEPT.saturating_sub(self.line.len());
            self.line.extend_from_slice(&piece[..piece.len().min(room)]);
            if piece.ends_with(b"\n") {
                let line = core::mem::take(&mut self.line);
                self.line_done(&line);
                self.line = line;
                self.line.clear();
            }
        }
    }

    fn line_done(&mut self, line: &[u8]) {
        let content = unstamped(line.trim_ascii_end());
        let rule = content == RULE.as_bytes();
        let thin = content == THIN_RULE.as_bytes();
        match self.scan {
            Scan::Before if rule => self.scan = Scan::Header,
            // A boot that printed no header block can still end with an
            // outcome block.
            Scan::Before | Scan::Body if thin => self.scan = Scan::Rule,
            Scan::Header if thin => {
                self.scan = Scan::Body;
                self.generation += 1;
            }
            Scan::Header => keep_line(&mut self.kept.header, line, HEADER_KEPT),
            Scan::Rule if content.starts_with(OUTCOME.as_bytes()) => {
                self.outcome.clear();
                keep_line(&mut self.outcome, line, OUTCOME_KEPT);
                self.scan = Scan::Outcome;
            }
            Scan::Rule if !thin => self.scan = Scan::Body,
            Scan::Outcome if rule => {
                self.kept.outcome = core::mem::take(&mut self.outcome);
                self.generation += 1;
                self.scan = Scan::Body;
            }
            Scan::Outcome => keep_line(&mut self.outcome, line, OUTCOME_KEPT),
            _ => {}
        }
    }
}

/// `line` without the `[   12.345] ` time column the boot adds.
fn unstamped(line: &[u8]) -> &[u8] {
    if line.first() == Some(&b'[')
        && let Some(end) = line.windows(2).position(|pair| pair == b"] ")
        && line[1..end]
            .iter()
            .all(|&byte| byte == b' ' || byte == b'.' || byte.is_ascii_digit())
    {
        return &line[end + 2..];
    }
    line
}

/// Add `line` to `text`, cut to what `limit` leaves and ended by a line
/// feed.
fn keep_line(text: &mut Vec<u8>, line: &[u8], limit: usize) {
    let room = limit.saturating_sub(text.len());
    if room < 2 {
        return;
    }
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    text.extend_from_slice(&line[..line.len().min(room - 1)]);
    text.push(b'\n');
}

/// The device blocks that hold this boot's slot, kept in memory.
struct Slot {
    lba: u64,
    blocks: Vec<u8>,
    /// The slot's place in `blocks`.
    offset: usize,
}

impl Slot {
    /// Boot `boot`'s slot on a device of `block`-byte blocks.
    fn of(boot: u64, block: usize) -> Self {
        let at = HEADER_BYTES as usize + (boot % KEPT_SLOTS) as usize * SLOT_BYTES;
        let span = SLOT_BYTES.max(block);
        Self {
            lba: (at / block) as u64,
            blocks: vec![0; span],
            offset: at % span,
        }
    }

    fn bytes(&mut self) -> &mut [u8] {
        &mut self.blocks[self.offset..self.offset + SLOT_BYTES]
    }
}

/// The line that stands for bytes an overflow dropped.
struct DroppedLine {
    bytes: [u8; 64],
    len: usize,
}

impl DroppedLine {
    fn new(dropped: u64) -> Self {
        let mut line = Self {
            bytes: [0; 64],
            len: 0,
        };
        let _ = writeln!(line, "[boot log dropped {dropped} bytes]");
        line
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Write for DroppedLine {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len + text.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Bytes waiting for a flush, at most the storage's length. An overflow
/// drops the oldest and counts them; [`Pending::drain`] puts a
/// `[boot log dropped N bytes]` line in their place. Several logs can read
/// the same bytes instead, each from its own position
/// ([`Pending::copy_since`]).
pub struct Pending<S> {
    storage: S,
    start: usize,
    len: usize,
    dropped: u64,
    /// Every byte pushed, held or not.
    pushed: u64,
}

impl<S> Pending<S> {
    pub const fn new(storage: S) -> Self {
        Self {
            storage,
            start: 0,
            len: 0,
            dropped: 0,
            pushed: 0,
        }
    }
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Pending<S> {
    pub fn push(&mut self, mut bytes: &[u8]) {
        self.pushed += bytes.len() as u64;
        let capacity = self.storage.as_ref().len();
        if capacity == 0 {
            self.dropped += bytes.len() as u64;
            return;
        }
        if bytes.len() >= capacity {
            self.dropped += (self.len + bytes.len() - capacity) as u64;
            self.start = 0;
            self.len = 0;
            bytes = &bytes[bytes.len() - capacity..];
        } else if self.len + bytes.len() > capacity {
            let excess = self.len + bytes.len() - capacity;
            self.start = (self.start + excess) % capacity;
            self.len -= excess;
            self.dropped += excess as u64;
        }
        let at = (self.start + self.len) % capacity;
        let first = bytes.len().min(capacity - at);
        let storage = self.storage.as_mut();
        storage[at..at + first].copy_from_slice(&bytes[..first]);
        storage[..bytes.len() - first].copy_from_slice(&bytes[first..]);
        self.len += bytes.len();
    }

    /// Nothing waits, and nothing was dropped.
    pub fn is_empty(&self) -> bool {
        self.len == 0 && self.dropped == 0
    }

    /// The bytes [`Pending::drain`] would hand over.
    pub fn bytes(&self) -> usize {
        self.len
            + if self.dropped == 0 {
                0
            } else {
                DroppedLine::new(self.dropped).len
            }
    }

    /// The position after every byte pushed so far.
    pub fn pushed(&self) -> u64 {
        self.pushed
    }

    /// Hand `sink` the bytes pushed since position `from` (an earlier
    /// [`Pending::pushed`]) and keep them, after a dropped-bytes line for
    /// those no longer held; the position reached.
    pub fn copy_since<E>(
        &self,
        from: u64,
        mut sink: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<u64, E> {
        let oldest = self.pushed - self.len as u64;
        if from < oldest {
            sink(DroppedLine::new(oldest - from).as_bytes())?;
        }
        let skip = from.saturating_sub(oldest).min(self.len as u64) as usize;
        let storage = self.storage.as_ref();
        let start = (self.start + skip) % storage.len().max(1);
        let len = self.len - skip;
        let first = len.min(storage.len() - start);
        if first != 0 {
            sink(&storage[start..start + first])?;
        }
        if len > first {
            sink(&storage[..len - first])?;
        }
        Ok(self.pushed)
    }

    /// Hand every pending byte to `sink` in order, after the dropped-bytes
    /// line when an overflow dropped any, and empty the buffer.
    pub fn drain<E>(&mut self, mut sink: impl FnMut(&[u8]) -> Result<(), E>) -> Result<(), E> {
        let (dropped, start, len) = (self.dropped, self.start, self.len);
        (self.dropped, self.start, self.len) = (0, 0, 0);
        if dropped != 0 {
            sink(DroppedLine::new(dropped).as_bytes())?;
        }
        let storage = self.storage.as_ref();
        let first = len.min(storage.len() - start);
        if first != 0 {
            sink(&storage[start..start + first])?;
        }
        if len > first {
            sink(&storage[..len - first])?;
        }
        Ok(())
    }
}

/// The ring on the device and its block at the head, kept in memory.
struct Ring {
    block: usize,
    ring_bytes: u64,
    head: u64,
    /// The ring block holding stream position `head`: its bytes before
    /// `head % block` are the stream's newest, those after are the oldest
    /// once the ring has wrapped.
    tail: Vec<u8>,
    /// `tail` holds bytes the device does not.
    dirty: bool,
    /// The ring has wrapped and `tail`'s block still holds oldest stream
    /// bytes past the head that `tail` lacks: read before it is written.
    unread: bool,
}

impl Ring {
    /// The device block of the ring block holding stream position `at`.
    fn lba(&self, at: u64) -> u64 {
        LAYOUT_BYTES / self.block as u64 + (at % self.ring_bytes) / self.block as u64
    }

    /// Copy `bytes` to the ring at the head; each block they fill joins
    /// `writes`, consecutive blocks one write. `remaining` counts this
    /// store's bytes still to come: a block they will overwrite whole is
    /// not read first.
    fn stage(&mut self, mut bytes: &[u8], remaining: &mut usize, writes: &mut Vec<(u64, Vec<u8>)>) {
        while !bytes.is_empty() {
            let offset = (self.head % self.block as u64) as usize;
            let count = (self.block - offset).min(bytes.len());
            self.tail[offset..offset + count].copy_from_slice(&bytes[..count]);
            self.head += count as u64;
            self.dirty = true;
            bytes = &bytes[count..];
            *remaining -= count;
            if self.head.is_multiple_of(self.block as u64) {
                join(writes, self.lba(self.head - 1), &self.tail, self.block);
                self.dirty = false;
                // The next block holds the oldest stream bytes once the ring
                // has wrapped; keep those this store does not overwrite.
                self.unread = self.head >= self.ring_bytes && *remaining < self.block;
                self.tail.fill(0);
            }
        }
    }
}

/// Add block `lba`'s `bytes` to `writes`, joining the last write when it
/// ends just before.
fn join(writes: &mut Vec<(u64, Vec<u8>)>, lba: u64, bytes: &[u8], block: usize) {
    match writes.last_mut() {
        Some((first, data)) if *first + (data.len() / block) as u64 == lba => {
            data.extend_from_slice(bytes);
        }
        _ => writes.push((lba, bytes.to_vec())),
    }
}

/// A step of a store ([`Writer::begin_store`]), each a request the last
/// one's completion lets go: the ring's bytes, then the header.
enum Step {
    /// Ring blocks from this one; `tail` when the last is the head's.
    Blocks {
        lba: u64,
        data: Vec<u8>,
        tail: bool,
    },
    /// The head's block, for the oldest bytes `tail` lacks.
    ReadTail,
    /// The head's block.
    Tail,
    /// The boot's slot, with its blocks as of this generation.
    Kept {
        generation: u64,
    },
    Header,
}

/// The log of one boot: appends wait in memory until a flush stores them.
pub struct Writer {
    ring: Ring,
    boots: u64,
    /// The head the header on the device records.
    durable: Option<u64>,
    fresh: Option<HeaderError>,
    pending: Pending<Vec<u8>>,
    /// The store in progress: its steps to come and the one running.
    steps: VecDeque<Step>,
    running: Option<Step>,
    keeper: Keeper,
    slot: Slot,
    /// The keeper's generation the device holds.
    kept_stored: u64,
    /// A fresh log's kept blocks still hold what the region held before.
    clear_kept: bool,
}

impl Writer {
    /// Open the log `device` holds whole (a [`LOG_BYTES`] window of the
    /// machine-state partition), count this boot and append its marker
    /// line. A blank or invalid header starts a fresh log ([`Writer::fresh`]).
    pub fn open(device: &mut dyn BlockDevice) -> Result<Self, BlockError> {
        Self::with_pending(device, PENDING_BYTES, true)
    }

    /// Open the log again later in the same boot, as the system engine does
    /// after the loader wrote it: the boot is not counted again and gets no
    /// second marker line.
    pub fn resume(device: &mut dyn BlockDevice) -> Result<Self, BlockError> {
        Self::with_pending(device, PENDING_BYTES, false)
    }

    fn with_pending(
        device: &mut dyn BlockDevice,
        pending: usize,
        new_boot: bool,
    ) -> Result<Self, BlockError> {
        let identity = device.identity();
        let block = identity.block_size as usize;
        if block == 0 || !(HEADER_BYTES as usize).is_multiple_of(block) {
            return Err(BlockError::Unsupported(
                "the boot log needs blocks that divide its 4 KiB header",
            ));
        }
        if identity.read_only {
            return Err(BlockError::ReadOnly);
        }
        let bytes = identity.blocks.saturating_mul(block as u64);
        if bytes <= LAYOUT_BYTES {
            return Err(BlockError::Unsupported("the boot log region holds no ring"));
        }
        let ring_bytes = bytes - LAYOUT_BYTES;
        let mut first = vec![0; block];
        device.read(0, &mut first)?;
        let (header, fresh) = match Header::decode(&first, bytes) {
            Ok(header) if header.version == VERSION => (header, None),
            Ok(Header { version, .. }) => {
                (Header::new(ring_bytes), Some(HeaderError::Version(version)))
            }
            Err(error) => (Header::new(ring_bytes), Some(error)),
        };
        let mut ring = Ring {
            block,
            ring_bytes,
            head: header.head,
            tail: vec![0; block],
            dirty: false,
            unread: false,
        };
        let head = header.head;
        let offset = (head % block as u64) as usize;
        if offset != 0 || head >= ring_bytes {
            device.read(ring.lba(head), &mut ring.tail)?;
        }
        // A boot that stopped mid-line gets its line ended first.
        let last = match (head, offset) {
            (0, _) => b'\n',
            (_, 0) => {
                let mut previous = vec![0; block];
                device.read(ring.lba(head - 1), &mut previous)?;
                previous[block - 1]
            }
            _ => ring.tail[offset - 1],
        };
        let boots = header.boots.saturating_add(u64::from(new_boot));
        let mut slot = Slot::of(boots, block);
        let mut keeper = Keeper::default();
        keeper.kept.boot = boots;
        if fresh.is_none() {
            device.read(slot.lba, &mut slot.blocks)?;
            // The same boot opened its log before: keep what it kept.
            if let Some(kept) = Kept::decode(slot.bytes())
                && kept.boot == boots
                && !new_boot
            {
                keeper.scan = if kept.header.is_empty() {
                    Scan::Before
                } else {
                    Scan::Body
                };
                keeper.kept = kept;
            }
        }
        let mut writer = Self {
            ring,
            boots,
            durable: fresh.is_none().then_some(head),
            clear_kept: fresh.is_some(),
            fresh,
            pending: Pending::new(vec![0; pending]),
            steps: VecDeque::new(),
            running: None,
            keeper,
            slot,
            kept_stored: 0,
        };
        if last != b'\n' {
            writer.append(b"\n");
        }
        if new_boot {
            writer.append(format!("=== STELA BOOT {} ===\n", writer.boots).as_bytes());
        }
        Ok(writer)
    }

    /// Read the header back and check that it records the last flush: a
    /// device that accepts writes and keeps none fails here.
    pub fn verify(&self, device: &mut dyn BlockDevice) -> Result<(), Unkept> {
        let mut block = vec![0; self.ring.block];
        device.read(0, &mut block).map_err(Unkept::Read)?;
        let stored =
            Header::decode(&block, LAYOUT_BYTES + self.ring.ring_bytes).map_err(Unkept::Header)?;
        let written = self.durable.unwrap_or_default();
        if stored.head != written || stored.boots != self.boots {
            return Err(Unkept::Head {
                stored: stored.head,
                written,
            });
        }
        Ok(())
    }

    /// Why the log started fresh this boot, if it did.
    pub fn fresh(&self) -> Option<&HeaderError> {
        self.fresh.as_ref()
    }

    /// This boot's number.
    pub fn boots(&self) -> u64 {
        self.boots
    }

    /// Every byte appended so far, including those still pending.
    pub fn head(&self) -> u64 {
        self.ring.head + self.pending.bytes() as u64
    }

    pub fn ring_bytes(&self) -> u64 {
        self.ring.ring_bytes
    }

    pub fn append(&mut self, bytes: &[u8]) {
        self.pending.push(bytes);
        self.keeper.scan(bytes);
    }

    /// Store the pending bytes, the caller waiting: [`Self::begin_store`]
    /// with each request run to completion.
    pub fn flush(&mut self, device: &mut dyn BlockDevice) -> Result<(), BlockError> {
        if !self.begin_store() {
            return Ok(());
        }
        while let Some(request) = self.next_request() {
            self.completed(request.run(device))?;
        }
        Ok(())
    }

    /// Whether a store has requests left ([`Self::next_request`]).
    pub fn storing(&self) -> bool {
        self.running.is_some() || !self.steps.is_empty()
    }

    /// Begin storing the pending bytes; whether there are any. The store
    /// is the ring's blocks, each durable once written, then the header,
    /// durable too: a header never names bytes the device lacks, and no
    /// cache is flushed whole. Bytes appended meanwhile wait for the next.
    pub fn begin_store(&mut self) -> bool {
        if self.storing() {
            return true;
        }
        let mut remaining = self.pending.bytes();
        let kept = self.keeper.generation != self.kept_stored;
        if remaining == 0 && self.durable == Some(self.ring.head) && !kept && !self.clear_kept {
            return false;
        }
        if self.clear_kept {
            self.clear_kept = false;
            self.steps.push_back(Step::Blocks {
                lba: HEADER_BYTES / self.ring.block as u64,
                data: vec![0; KEPT_BYTES as usize],
                tail: false,
            });
        }
        let mut writes = Vec::new();
        let ring = &mut self.ring;
        let Ok(()) = self.pending.drain(|bytes| {
            ring.stage(bytes, &mut remaining, &mut writes);
            Ok::<_, Infallible>(())
        });
        // The head's partial block joins the ring's writes unless its old
        // bytes must be read first.
        let mut tail = false;
        if ring.dirty && !ring.unread {
            join(&mut writes, ring.lba(ring.head), &ring.tail, ring.block);
            tail = true;
        }
        let count = writes.len();
        for (index, (lba, data)) in writes.into_iter().enumerate() {
            let tail = tail && index + 1 == count;
            self.steps.push_back(Step::Blocks { lba, data, tail });
        }
        if ring.unread {
            self.steps.push_back(Step::ReadTail);
        }
        if ring.dirty && !tail {
            self.steps.push_back(Step::Tail);
        }
        if kept {
            self.keeper.kept.encode(self.slot.bytes());
            self.steps.push_back(Step::Kept {
                generation: self.keeper.generation,
            });
        }
        self.steps.push_back(Step::Header);
        true
    }

    /// The store's next request once the last one completed
    /// ([`Self::completed`]); `None` when it has no more.
    pub fn next_request(&mut self) -> Option<Request> {
        if self.running.is_some() {
            return None;
        }
        let ring = &self.ring;
        let step = self.steps.pop_front()?;
        let (request, step) = match step {
            Step::Blocks { lba, data, tail } => (
                Request::Write {
                    lba,
                    data,
                    durable: true,
                },
                Step::Blocks {
                    lba,
                    data: Vec::new(),
                    tail,
                },
            ),
            Step::ReadTail => (
                Request::Read {
                    lba: ring.lba(ring.head),
                    bytes: ring.block,
                },
                Step::ReadTail,
            ),
            Step::Tail => (
                Request::Write {
                    lba: ring.lba(ring.head),
                    data: ring.tail.clone(),
                    durable: true,
                },
                Step::Tail,
            ),
            Step::Kept { generation } => (
                Request::Write {
                    lba: self.slot.lba,
                    data: self.slot.blocks.clone(),
                    durable: true,
                },
                Step::Kept { generation },
            ),
            Step::Header => {
                let mut block = vec![0; ring.block];
                Header {
                    version: VERSION,
                    head: ring.head,
                    boots: self.boots,
                    ring_bytes: ring.ring_bytes,
                }
                .encode(&mut block);
                let request = Request::Write {
                    lba: 0,
                    data: block,
                    durable: true,
                };
                (request, Step::Header)
            }
        };
        self.running = Some(step);
        Some(request)
    }

    /// The running request finished with `finished`. A failure ends the
    /// store: the next starts over from what the device then holds.
    pub fn completed(&mut self, finished: Finished) -> Result<(), BlockError> {
        let step = self.running.take();
        let data = match finished {
            Ok(data) => data,
            Err(error) => {
                self.steps.clear();
                return Err(error);
            }
        };
        let ring = &mut self.ring;
        match step {
            Some(Step::Blocks { tail: true, .. }) | Some(Step::Tail) => ring.dirty = false,
            Some(Step::ReadTail) => {
                // The bytes before the head are this store's; keep the old
                // ones after it.
                let old = data.ok_or(BlockError::Protocol("a log read returned no data"))?;
                let offset = (ring.head % ring.block as u64) as usize;
                ring.tail[offset..].copy_from_slice(&old[offset..]);
                ring.unread = false;
            }
            Some(Step::Kept { generation }) => self.kept_stored = generation,
            Some(Step::Header) => self.durable = Some(ring.head),
            Some(Step::Blocks { .. }) | None => {}
        }
        Ok(())
    }
}

/// A region's log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    pub boots: u64,
    pub head: u64,
    pub ring_bytes: u64,
    /// The valid stream, oldest byte first.
    pub stream: Vec<u8>,
    /// The boots' kept blocks, oldest boot first.
    pub kept: Vec<Kept>,
}

impl Log {
    /// The stream bytes the ring has overwritten.
    pub fn overwritten(&self) -> u64 {
        self.head.saturating_sub(self.ring_bytes)
    }
}

/// The log a whole region holds, its stream in order. A blank or invalid
/// header is refused by name.
pub fn read(region: &[u8]) -> Result<Log, HeaderError> {
    let bytes = region.len() as u64;
    if bytes <= HEADER_BYTES {
        return Err(HeaderError::Short { bytes });
    }
    let Header {
        version,
        head,
        boots,
        ring_bytes,
    } = Header::decode(&region[..HEADER_BYTES as usize], bytes)?;
    let ring = &region[(bytes - ring_bytes) as usize..];
    let mut kept: Vec<Kept> = match version {
        1 => Vec::new(),
        _ => region[HEADER_BYTES as usize..LAYOUT_BYTES as usize]
            .as_chunks::<SLOT_BYTES>()
            .0
            .iter()
            .filter_map(|slot| Kept::decode(slot))
            .filter(|kept| kept.boot <= boots)
            .collect(),
    };
    kept.sort_by_key(|kept| kept.boot);
    let start = head.saturating_sub(ring_bytes);
    let len = (head - start) as usize;
    let at = (start % ring_bytes) as usize;
    let first = len.min(ring.len() - at);
    let mut stream = Vec::with_capacity(len);
    stream.extend_from_slice(&ring[at..at + first]);
    stream.extend_from_slice(&ring[..len - first]);
    Ok(Log {
        boots,
        head,
        ring_bytes,
        stream,
        kept,
    })
}

#[cfg(test)]
mod tests;
