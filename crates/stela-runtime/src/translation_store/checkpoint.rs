//! A pack written while the guest runs, in bounded steps, so that a power
//! cut at any byte leaves a pack that loads: the one before the write or the
//! one it writes, never a torn one.
//!
//! A pack's index sits at its start and its records after it. A checkpoint
//! writes over the pack in place, as the stop's write does, but only after
//! the new index has a durable second copy:
//!
//! 1. the new records, past every record the current index names;
//! 2. a backup of the new index right after the new pack's last record,
//!    then a flush;
//! 3. the footer in the file's last [`FOOTER_BYTES`]: where the backup is,
//!    its length and SHA-256, under a checksum of its own, then a flush;
//! 4. the new index over the old one, then a flush.
//!
//! Until step 4 starts, the old index at the start is whole and names only
//! records the write did not touch. While step 4 runs, a torn index fails
//! its checksum and the footer leads to the backup, which names the new
//! records flushed in step 2. A reader ([`load`], [`backup_index`]) takes the
//! index at the start when it checks, else the backup. A boot that loaded the
//! backup puts it back at the start first (`repair`), before any record write
//! may reach the bytes the backup occupies.
//!
//! A pack laid out from the start again (`Layout::changed` is `None`) moves
//! records the current index names, so a checkpoint refuses it over a valid
//! pack: only the stop writes that.
use alloc::vec::Vec;
use core::ops::Range;
use sha2::{Digest as _, Sha256};
use stela_engine::translations::{
    Digest,
    pack::{self, HEADER_BYTES, Layout, Pack},
};

use super::{CHECKSUM_BYTES, COUNT_AT, INDEX_ENTRY_BYTES};

/// The file's last bytes, which hold the footer naming the index backup.
pub const FOOTER_BYTES: u64 = 4096;

/// The bound to plan a pack within when the store may use `bound` bytes of
/// its file: room is left for the footer and the index backup (an index
/// takes 48 bytes a record, records several KiB each).
pub const fn plan_bound(bound: u64) -> u64 {
    bound.saturating_sub(2 * FOOTER_BYTES + bound / 16)
}

const FOOTER_MAGIC: [u8; 8] = *b"STLTBKUP";
/// Magic, backup offset and length, the backup's SHA-256, and the SHA-256
/// of those.
const FOOTER_FIELDS: usize = 8 + 8 + 8 + 32 + 32;
/// The most index bytes a backup may hold: a pack's largest index.
const MAX_INDEX_BYTES: u64 =
    (HEADER_BYTES + pack::MAX_RECORDS * INDEX_ENTRY_BYTES + CHECKSUM_BYTES) as u64;

/// A pack file the checkpoint writes: whole device blocks at block-aligned
/// offsets from the pack's start, and a flush that makes them durable.
pub trait PackFile {
    type Error;
    /// The device block size: a power of two of at most [`FOOTER_BYTES`].
    fn block(&self) -> u64;
    /// The file's bytes: the pack may use them all but the footer's.
    fn len(&self) -> u64;
    fn write(&mut self, at: u64, data: &[u8]) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}

/// Why a checkpoint was not planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The pack and its index backup do not fit before the footer.
    Small { needed: u64, room: u64 },
    /// The block size or the file's length do not suit the footer.
    Misaligned,
    /// The layout moves records the file's valid index names.
    Relayout,
    /// A new record shares a device block with the index.
    HeadBlock,
}

/// What one step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// More steps follow.
    More,
    /// The new pack is durable.
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    /// The layout's bytes in this block-aligned range.
    Layout(Range<u64>),
    /// These bytes, block-padded, at this block-aligned offset.
    Bytes(u64, Vec<u8>),
    Flush,
}

/// The pack bytes the index of `layout` (header, entries, checksum) takes.
fn index_bytes(layout: &Layout) -> usize {
    let mut header = [0; HEADER_BYTES];
    layout.read_at(0, &mut header);
    let count =
        u32::from_le_bytes(header[COUNT_AT..COUNT_AT + 4].try_into().expect("a word")) as usize;
    HEADER_BYTES + count * INDEX_ENTRY_BYTES + CHECKSUM_BYTES
}

/// A checkpoint in progress: the writes and flushes left, run a bounded
/// amount at a time by [`Self::step`].
#[derive(Debug)]
pub struct Checkpoint {
    ops: Vec<Op>,
    next: usize,
    /// Bytes of the current op written already.
    done: u64,
    buffer: Vec<u8>,
}

impl Checkpoint {
    /// Plan writing `layout` over a file of `file` bytes in `block`-byte
    /// blocks. `fresh` says the file holds no valid pack, so that a layout
    /// from the start may be written; `repair` is the index backup a boot
    /// loaded because the file's own index failed its checks: it goes back
    /// to the start before anything else.
    pub fn plan(
        layout: &Layout,
        file: u64,
        block: u64,
        fresh: bool,
        repair: Option<&[u8]>,
    ) -> Result<Self, Refused> {
        if !block.is_power_of_two() || block > FOOTER_BYTES || file < FOOTER_BYTES {
            return Err(Refused::Misaligned);
        }
        let footer_at = (file - FOOTER_BYTES) & !(block - 1);
        let index = index_bytes(layout) as u64;
        let backup_at = layout.bytes().next_multiple_of(block);
        let needed = backup_at + index;
        if needed > footer_at {
            return Err(Refused::Small {
                needed,
                room: footer_at,
            });
        }
        let round = |range: Range<u64>| {
            range.start & !(block - 1)..range.end.next_multiple_of(block).min(backup_at)
        };
        let mut ops = Vec::new();
        if let Some(index) = repair {
            ops.push(Op::Bytes(0, index.to_vec()));
            ops.push(Op::Flush);
        }
        let records: Vec<Range<u64>> = match layout.changed() {
            Some([]) => return Ok(Self::of(ops)),
            Some([_head, records @ ..]) => records.to_vec(),
            None if fresh => {
                // Nothing valid to keep: the footer goes first, so that it
                // never leads to a backup whose records this write moves.
                ops.push(Op::Bytes(footer_at, Vec::new()));
                ops.push(Op::Flush);
                vec![index..layout.bytes()]
            }
            None => return Err(Refused::Relayout),
        };
        // A record write must not reach the index's blocks: those are
        // written last.
        let head_end = index.next_multiple_of(block);
        if layout.changed().is_some()
            && records
                .iter()
                .any(|range| !range.is_empty() && range.start < head_end)
        {
            return Err(Refused::HeadBlock);
        }
        for range in records {
            if !range.is_empty() {
                ops.push(Op::Layout(round(range)));
            }
        }
        let mut backup = vec![0; index as usize];
        layout.read_at(0, &mut backup);
        let mut footer = Vec::with_capacity(FOOTER_FIELDS);
        footer.extend(FOOTER_MAGIC);
        footer.extend(backup_at.to_le_bytes());
        footer.extend(index.to_le_bytes());
        footer.extend(Sha256::digest(&backup));
        let sealed = Sha256::digest(&footer);
        footer.extend(sealed);
        ops.push(Op::Bytes(backup_at, backup));
        ops.push(Op::Flush);
        ops.push(Op::Bytes(footer_at, footer));
        ops.push(Op::Flush);
        ops.push(Op::Layout(round(0..index)));
        ops.push(Op::Flush);
        Ok(Self::of(ops))
    }

    fn of(ops: Vec<Op>) -> Self {
        Self {
            ops,
            next: 0,
            done: 0,
            buffer: Vec::new(),
        }
    }

    /// Whether every write and flush is done.
    pub fn done(&self) -> bool {
        self.next == self.ops.len()
    }

    /// Run the next flush, or write up to `max_bytes` (at least one block)
    /// of the next write, of the `layout` this checkpoint was planned for.
    /// An error leaves the file as a power cut there would: loadable.
    pub fn step<F: PackFile>(
        &mut self,
        layout: &Layout,
        file: &mut F,
        max_bytes: u64,
    ) -> Result<Step, F::Error> {
        let block = file.block();
        let Some(op) = self.ops.get(self.next) else {
            return Ok(Step::Done);
        };
        let take = max_bytes.max(block) & !(block - 1);
        let finished = match op {
            Op::Flush => {
                file.flush()?;
                true
            }
            Op::Layout(range) => {
                let at = range.start + self.done;
                let bytes = take.min(range.end - at);
                self.buffer.clear();
                self.buffer.resize(bytes as usize, 0);
                layout.read_at(at, &mut self.buffer);
                file.write(at, &self.buffer)?;
                self.done += bytes;
                range.start + self.done >= range.end
            }
            Op::Bytes(start, data) => {
                let padded = (data.len() as u64).next_multiple_of(block).max(block);
                let bytes = take.min(padded - self.done);
                let from = self.done as usize;
                self.buffer.clear();
                self.buffer.resize(bytes as usize, 0);
                if from < data.len() {
                    let end = data.len().min(from + bytes as usize);
                    self.buffer[..end - from].copy_from_slice(&data[from..end]);
                }
                file.write(start + self.done, &self.buffer)?;
                self.done += bytes;
                self.done >= padded
            }
        };
        if finished {
            self.next += 1;
            self.done = 0;
        }
        Ok(if self.done() { Step::Done } else { Step::More })
    }
}

/// The index backup the footer of a file of `file` bytes names, when the
/// footer and the backup check: the header, entries and checksum of a pack
/// of `translator` whose records lie in the file after its own index room.
/// `read` fills a buffer from a file offset, or says it could not.
pub fn backup_index(
    read: &mut dyn FnMut(u64, &mut [u8]) -> bool,
    file: u64,
    translator: &Digest,
) -> Option<Vec<u8>> {
    if file < FOOTER_BYTES {
        return None;
    }
    let mut footer = [0; FOOTER_FIELDS];
    // The footer starts on a block boundary at or below `file - FOOTER_BYTES`:
    // look at each boundary a block size may give.
    let starts = [512u64, 1024, 2048, 4096].map(|block| (file - FOOTER_BYTES) & !(block - 1));
    let mut last = None;
    for footer_at in starts {
        if last == Some(footer_at) {
            continue;
        }
        last = Some(footer_at);
        if !read(footer_at, &mut footer) {
            continue;
        }
        if footer[..8] != FOOTER_MAGIC
            || Sha256::digest(&footer[..FOOTER_FIELDS - 32]).as_slice()
                != &footer[FOOTER_FIELDS - 32..]
        {
            continue;
        }
        let field = |at: usize| u64::from_le_bytes(footer[at..at + 8].try_into().expect("a field"));
        let (at, bytes) = (field(8), field(16));
        if bytes > MAX_INDEX_BYTES || at.checked_add(bytes).is_none_or(|end| end > footer_at) {
            continue;
        }
        let mut index = vec![0; bytes as usize];
        if !read(at, &mut index) || Sha256::digest(&index).as_slice() != &footer[24..56] {
            continue;
        }
        let length = Pack::length(&index, translator).ok()?;
        if pack::prefix_bytes(&index, translator).ok()? != index.len() || length > at {
            return None;
        }
        return Some(index);
    }
    None
}

/// Where the pack [`load`] returned came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The index at the file's start.
    Head,
    /// The footer's backup: the boot repairs the start with it before it
    /// writes the pack again.
    Backup,
}

/// The whole pack of `translator` in a file of `file` bytes: the one its
/// own index names when that checks, else the one the footer's backup
/// names, with the backup put in front of its records. `None` when neither
/// checks.
pub fn load(
    read: &mut dyn FnMut(u64, &mut [u8]) -> bool,
    file: u64,
    translator: &Digest,
) -> Option<(Vec<u8>, Source)> {
    let head = (|| {
        let mut header = [0; HEADER_BYTES];
        if !read(0, &mut header) {
            return None;
        }
        let mut image = vec![0; pack::prefix_bytes(&header, translator).ok()?];
        if image.len() as u64 > file || !read(0, &mut image) {
            return None;
        }
        let length = Pack::length(&image, translator).ok()?;
        if length > file {
            return None;
        }
        let start = image.len();
        image.resize(length as usize, 0);
        (read(start as u64, &mut image[start..]) && Pack::parse(&image, translator).is_ok())
            .then_some(image)
    })();
    if let Some(image) = head {
        return Some((image, Source::Head));
    }
    let mut image = backup_index(read, file, translator)?;
    let length = Pack::length(&image, translator).ok()?;
    let start = image.len();
    image.resize(length as usize, 0);
    if !read(start as u64, &mut image[start..]) {
        return None;
    }
    Pack::parse(&image, translator).ok()?;
    Some((image, Source::Backup))
}

/// The pack file of a block device's extents (a FAT32 file's cluster chain,
/// cut to its size), as the stop's write uses it.
#[cfg(target_arch = "x86_64")]
pub struct ExtentFile<'d> {
    pub device: &'d mut dyn stela_drivers::block::BlockDevice,
    pub extents: &'d [stela_formats::payload::pieces::Extent],
}

#[cfg(target_arch = "x86_64")]
impl PackFile for ExtentFile<'_> {
    type Error = super::WriteError;

    fn block(&self) -> u64 {
        u64::from(self.device.identity().block_size)
    }

    fn len(&self) -> u64 {
        self.extents.iter().map(|extent| extent.bytes).sum()
    }

    fn write(&mut self, at: u64, data: &[u8]) -> Result<(), Self::Error> {
        let block = self.block();
        let mut start = 0;
        let mut done = 0usize;
        for extent in self.extents {
            let end = start + extent.bytes.next_multiple_of(block);
            let from = at + done as u64;
            if from < end && from >= start {
                if extent.offset % block != 0 {
                    return Err(super::WriteError::Misaligned);
                }
                let take = ((end - from) as usize).min(data.len() - done);
                self.device
                    .write(
                        (extent.offset + (from - start)) / block,
                        &data[done..done + take],
                    )
                    .map_err(super::WriteError::Device)?;
                done += take;
                if done == data.len() {
                    return Ok(());
                }
            }
            start += extent.bytes;
        }
        Err(super::WriteError::Small {
            file: self.len(),
            pack: at + data.len() as u64,
        })
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.device.flush().map_err(super::WriteError::Device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_engine::translations::pack::Piece;

    const BLOCK: u64 = 512;

    /// A file whose writes reach the medium in any order until a flush,
    /// and that stops taking writes after `cut` blocks.
    struct Torn {
        durable: Vec<u8>,
        pending: Vec<(u64, Vec<u8>)>,
        cut: usize,
        written: usize,
    }

    #[derive(Debug)]
    struct Cut;

    impl PackFile for Torn {
        type Error = Cut;
        fn block(&self) -> u64 {
            BLOCK
        }
        fn len(&self) -> u64 {
            self.durable.len() as u64
        }
        fn write(&mut self, at: u64, data: &[u8]) -> Result<(), Cut> {
            assert_eq!(at % BLOCK, 0);
            assert_eq!(data.len() as u64 % BLOCK, 0);
            for (index, chunk) in data.chunks(BLOCK as usize).enumerate() {
                if self.written == self.cut {
                    return Err(Cut);
                }
                self.written += 1;
                self.pending
                    .push((at + index as u64 * BLOCK, chunk.to_vec()));
            }
            Ok(())
        }
        fn flush(&mut self) -> Result<(), Cut> {
            for (at, chunk) in self.pending.drain(..) {
                self.durable[at as usize..][..chunk.len()].copy_from_slice(&chunk);
            }
            Ok(())
        }
    }

    impl Torn {
        /// The files a cut now may leave: the pending blocks landed in
        /// order or in reverse order, any number of them.
        fn outcomes(&self) -> Vec<Vec<u8>> {
            let mut outcomes = Vec::new();
            for order in [false, true] {
                let mut blocks: Vec<&(u64, Vec<u8>)> = self.pending.iter().collect();
                if order {
                    blocks.reverse();
                }
                for count in 0..=blocks.len() {
                    let mut file = self.durable.clone();
                    for (at, chunk) in &blocks[..count] {
                        file[*at as usize..][..chunk.len()].copy_from_slice(chunk);
                    }
                    outcomes.push(file);
                }
            }
            outcomes
        }
    }

    fn records(range: Range<u8>, size: usize) -> Vec<(Digest, Vec<u8>)> {
        range
            .map(|index| (Digest::of(&[index, 7]), vec![index; size]))
            .collect()
    }

    fn read_from(file: &[u8]) -> impl FnMut(u64, &mut [u8]) -> bool + '_ {
        |at, buffer| {
            let Some(end) = (at as usize).checked_add(buffer.len()) else {
                return false;
            };
            match file.get(at as usize..end) {
                Some(bytes) => {
                    buffer.copy_from_slice(bytes);
                    true
                }
                None => false,
            }
        }
    }

    /// The record set of a loaded pack, by key.
    fn contents(image: &[u8], translator: &Digest) -> Vec<(Digest, Vec<u8>)> {
        Pack::parse(image, translator)
            .unwrap()
            .iter()
            .map(|(key, bytes)| (key, bytes.to_vec()))
            .collect()
    }

    fn sorted(mut records: Vec<(Digest, Vec<u8>)>) -> Vec<(Digest, Vec<u8>)> {
        records.sort();
        records
    }

    /// Run `checkpoint` to the end, or until the file cuts.
    fn run(checkpoint: &mut Checkpoint, layout: &Layout, file: &mut Torn, step: u64) -> bool {
        loop {
            match checkpoint.step(layout, file, step) {
                Ok(Step::Done) => return true,
                Ok(Step::More) => {}
                Err(Cut) => return false,
            }
        }
    }

    const FILE: usize = 512 * BLOCK as usize;

    /// A file holding the first pack, written by a fresh checkpoint.
    fn first(translator: &Digest) -> (Vec<u8>, Vec<(Digest, Vec<u8>)>) {
        let old = records(0..20, 300);
        let pieces = old
            .iter()
            .map(|(key, bytes)| (*key, Piece::New(bytes.clone())))
            .collect();
        let layout = Layout::over(translator, None, pieces, (FILE as u64) / 2);
        let mut file = Torn {
            durable: vec![0xee; FILE],
            pending: Vec::new(),
            cut: usize::MAX,
            written: 0,
        };
        let mut checkpoint = Checkpoint::plan(&layout, FILE as u64, BLOCK, true, None).unwrap();
        assert!(run(&mut checkpoint, &layout, &mut file, 2048));
        assert!(file.pending.is_empty());
        (file.durable, old)
    }

    /// The second pack's layout over the first: its records kept, ten new.
    fn second<'a>(translator: &Digest, image: &'a [u8]) -> (Layout<'a>, Vec<(Digest, Vec<u8>)>) {
        let pack = Pack::parse(image, translator).unwrap();
        let mut pieces: Vec<(Digest, Piece<'a>)> = pack
            .iter()
            .map(|(key, bytes)| (key, Piece::Kept(bytes)))
            .collect();
        let new = records(100..110, 700);
        pieces.extend(
            new.iter()
                .map(|(key, bytes)| (*key, Piece::New(bytes.clone()))),
        );
        let all = pack
            .iter()
            .map(|(key, bytes)| (key, bytes.to_vec()))
            .chain(new)
            .collect();
        (
            Layout::over(translator, Some(pack), pieces, (FILE as u64) / 2),
            all,
        )
    }

    #[test]
    fn a_cut_at_any_block_of_a_checkpoint_loads_the_old_or_the_new_pack() {
        let translator = Digest::of(b"translator");
        let (base, old) = first(&translator);
        let (image, source) = load(&mut read_from(&base), FILE as u64, &translator).unwrap();
        assert_eq!(source, Source::Head);
        assert_eq!(contents(&image, &translator), sorted(old.clone()));
        let (layout, new) = second(&translator, &image);
        assert!(layout.changed().is_some_and(|ranges| ranges.len() > 1));
        let (old, new) = (sorted(old), sorted(new));
        let mut cuts = 0;
        let mut saw_backup = false;
        for cut in 0.. {
            let mut file = Torn {
                durable: base.clone(),
                pending: Vec::new(),
                cut,
                written: 0,
            };
            let mut checkpoint =
                Checkpoint::plan(&layout, FILE as u64, BLOCK, false, None).unwrap();
            let finished = run(&mut checkpoint, &layout, &mut file, 3 * BLOCK);
            for outcome in file.outcomes() {
                let (loaded, source) = load(&mut read_from(&outcome), FILE as u64, &translator)
                    .expect("a pack loads after any cut");
                let found = contents(&loaded, &translator);
                assert!(
                    found == old || found == new,
                    "cut {cut}: a torn pack loaded"
                );
                saw_backup |= source == Source::Backup;
            }
            if finished {
                let (loaded, source) =
                    load(&mut read_from(&file.durable), FILE as u64, &translator).unwrap();
                assert_eq!(source, Source::Head);
                assert_eq!(contents(&loaded, &translator), new);
                break;
            }
            cuts += 1;
        }
        assert!(cuts > 5);
        assert!(saw_backup, "some cut tears the index and loads the backup");
    }

    #[test]
    fn a_boot_that_loaded_the_backup_repairs_the_start_before_it_writes() {
        let translator = Digest::of(b"translator");
        let (base, _) = first(&translator);
        let (image, _) = load(&mut read_from(&base), FILE as u64, &translator).unwrap();
        let (layout, second_records) = second(&translator, &image);
        let mut file = Torn {
            durable: base.clone(),
            pending: Vec::new(),
            cut: usize::MAX,
            written: 0,
        };
        let mut checkpoint = Checkpoint::plan(&layout, FILE as u64, BLOCK, false, None).unwrap();
        assert!(run(&mut checkpoint, &layout, &mut file, 4096));
        // The start torn: the backup loads.
        let mut torn = file.durable.clone();
        torn[..BLOCK as usize].fill(0x5a);
        let (loaded, source) = load(&mut read_from(&torn), FILE as u64, &translator).unwrap();
        assert_eq!(source, Source::Backup);
        let second_records = sorted(second_records);
        assert_eq!(contents(&loaded, &translator), second_records);
        let backup = backup_index(&mut read_from(&torn), FILE as u64, &translator).unwrap();
        // A third pack over the loaded one, written with the repair, cut
        // anywhere: the second or the third loads.
        let pack = Pack::parse(&loaded, &translator).unwrap();
        let mut pieces: Vec<(Digest, Piece)> = pack
            .iter()
            .map(|(key, bytes)| (key, Piece::Kept(bytes)))
            .collect();
        let more = records(200..230, 900);
        pieces.extend(
            more.iter()
                .map(|(key, bytes)| (*key, Piece::New(bytes.clone()))),
        );
        let third = sorted(second_records.iter().cloned().chain(more).collect());
        let layout = Layout::over(&translator, Some(pack), pieces, (FILE as u64) / 2);
        for cut in 0.. {
            let mut file = Torn {
                durable: torn.clone(),
                pending: Vec::new(),
                cut,
                written: 0,
            };
            let mut checkpoint =
                Checkpoint::plan(&layout, FILE as u64, BLOCK, false, Some(&backup)).unwrap();
            let finished = run(&mut checkpoint, &layout, &mut file, BLOCK);
            for outcome in file.outcomes() {
                let (loaded, _) = load(&mut read_from(&outcome), FILE as u64, &translator)
                    .expect("a pack loads after any cut");
                let found = contents(&loaded, &translator);
                assert!(found == second_records || found == third, "cut {cut}");
            }
            if finished {
                break;
            }
        }
    }

    #[test]
    fn a_file_cut_short_at_any_block_loads_a_whole_pack_or_none() {
        let translator = Digest::of(b"translator");
        let (base, _) = first(&translator);
        let (image, _) = load(&mut read_from(&base), FILE as u64, &translator).unwrap();
        let (layout, new) = second(&translator, &image);
        let mut file = Torn {
            durable: base.clone(),
            pending: Vec::new(),
            cut: usize::MAX,
            written: 0,
        };
        let mut checkpoint = Checkpoint::plan(&layout, FILE as u64, BLOCK, false, None).unwrap();
        assert!(run(&mut checkpoint, &layout, &mut file, 4096));
        let new = sorted(new);
        let mut whole = 0;
        for blocks in 0..=FILE / BLOCK as usize {
            let short = &file.durable[..blocks * BLOCK as usize];
            // As the file's size, and as a reader that cannot pass its end.
            if let Some((loaded, _)) = load(&mut read_from(short), FILE as u64, &translator) {
                assert_eq!(contents(&loaded, &translator), new);
                whole += 1;
            }
            if let Some((loaded, _)) = load(&mut read_from(short), short.len() as u64, &translator)
            {
                assert_eq!(contents(&loaded, &translator), new);
            }
        }
        assert!(whole > 0);
    }

    #[test]
    fn a_checkpoint_refuses_what_it_cannot_write_safely() {
        let translator = Digest::of(b"translator");
        let (base, _) = first(&translator);
        let (image, _) = load(&mut read_from(&base), FILE as u64, &translator).unwrap();
        let pack = Pack::parse(&image, &translator).unwrap();
        // Laid out from the start over a valid pack: refused.
        let pieces = pack
            .iter()
            .map(|(key, bytes)| (key, Piece::New(bytes.to_vec())))
            .collect();
        let relayout = Layout::new(&translator, pieces);
        assert_eq!(relayout.changed(), None);
        assert_eq!(
            Checkpoint::plan(&relayout, FILE as u64, BLOCK, false, None).err(),
            Some(Refused::Relayout)
        );
        // No room before the footer for the backup.
        let (layout, _) = second(&translator, &image);
        assert!(matches!(
            Checkpoint::plan(&layout, layout.bytes() + FOOTER_BYTES, BLOCK, false, None),
            Err(Refused::Small { .. })
        ));
        assert_eq!(
            Checkpoint::plan(&layout, FILE as u64, 3000, false, None).err(),
            Some(Refused::Misaligned)
        );
        // Nothing changed: nothing to write.
        let kept = pack
            .iter()
            .map(|(key, bytes)| (key, Piece::Kept(bytes)))
            .collect();
        let same = Layout::over(&translator, Some(pack), kept, (FILE as u64) / 2);
        let checkpoint = Checkpoint::plan(&same, FILE as u64, BLOCK, false, None).unwrap();
        assert!(checkpoint.done());
    }
}
