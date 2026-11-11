//! The persistent translation store's format: page records of
//! block translations keyed by the SHA-256 of their guest fetch page, with
//! guest addresses in the native code stored relative to the page, and the
//! proof that a block's code depends on its address only through them.
//!
//! The format is the same in every container: the directory store
//! and the pack `stela.efi` keeps
//! ([`pack`]).
pub mod checkpoint;
pub mod pack;

use alloc::{string::String, vec::Vec};
use stela_compiler::block::Features;
use stela_compiler::{
    GuestAddress, NativeBlock,
    block::{
        CompiledBlock, ExitKind, RecoveryBinding, RecoverySiteKind, RecoverySource,
        RetirementPhase, RetirementPoint, SpillOffset, UnqualifiedFaultRecovery,
    },
    x86_64::chain::DirectExit,
};
use stela_crypto::Sha256;
use stela_crypto::digest::Digest as _;

/// The bytes of the fetch page a record covers: no block leaves it.
pub const PAGE_BYTES: usize = 4096;
pub const SCHEMA: u32 = 3;
const RECORD_MAGIC: [u8; 8] = *b"STLTPAGE";
const HEADER_BYTES: usize = 88;
const TRAILER_BYTES: usize = 32;
/// Context, guest offset, source and input lengths, code length, and four
/// metadata counts. Variable-length payloads follow these fixed fields.
const ENTRY_MIN_BYTES: usize = 32 + 3 * 2 + 5 * 4;
const RELOCATION_BYTES: usize = 4;
const SOURCE_MAP_BYTES: usize = 6;
const EXIT_BYTES: usize = 15;
const RECOVERY_ROW_BYTES: usize = 24;
const RECOVERY_BINDING_BYTES: usize = 4;
/// A relocated field: a little-endian u64 in the native code.
const FIELD_BYTES: usize = 8;
/// The bits of a page's address its translations are bound to (the
/// address class): probes and rebasing never change them.
const CLASS_SHIFT: u32 = 47;
/// The probe displacements: 16 KiB multiples (every slide is one, so page
/// offsets are kept) with bits set in every 16-bit lane below the class
/// bits, in complementary patterns, so that a guest address the compiler
/// narrowed or partly overwrote moves by other than the displacement.
const PROBES: [u64; 2] = [0x2aaa_aaaa_c000, 0x1555_5555_4000];

/// A SHA-256 digest: a translator id, a page key or an entry context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// The translator id: what decides the code a translation input produces.
pub fn translator_id() -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_MAGIC);
    hasher.update(SCHEMA.to_le_bytes());
    let abi = stela_compiler::block::BlockProfile::new(Features::SYSTEM_MODE).abi();
    for part in [
        abi.as_str(),
        stela_compiler::SOURCE_SHA256,
        ENGINE_SOURCE_SHA256,
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    Digest(hasher.finalize().into())
}

/// The runtime crate's sources (`build.rs`).
pub const ENGINE_SOURCE_SHA256: &str = env!("STELA_ENGINE_SOURCE_SHA256");

/// The address class of a page: bits 47..63 of its address.
pub const fn address_class(page: u64) -> u64 {
    page >> CLASS_SHIFT
}

/// One direct exit, its target relative to the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    pub offset: u32,
    pub target: u64,
    pub kind: u8,
    pub skipped: u16,
}

/// One stored block translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub context: Digest,
    /// The page offset of its entry PC.
    pub offset: u16,
    pub source_bytes: u16,
    /// Exact admitted instruction bytes given to the compiler, including any
    /// analyzed suffix beyond the emitted block. Raw fetch-page identity and
    /// the preparation context remain separate record bindings.
    pub input: Vec<u8>,
    /// Native code, each relocation field holding `value - page`.
    pub code: Vec<u8>,
    /// Code offsets of the relocation fields, ascending.
    pub relocations: Vec<u32>,
    /// Page offset of each guest instruction and its native offset.
    pub source_map: Vec<(u16, u32)>,
    pub exits: Vec<Exit>,
    pub recovery: Vec<UnqualifiedFaultRecovery>,
}

/// A rebased immutable template. Persisted fault tags remain unchecked until
/// the exact input/profile/template passes compiler plan validation.
#[derive(Debug, Clone)]
pub struct StoredBlock {
    pub native: NativeBlock,
    pub source_bytes: usize,
    pub direct_exits: Vec<DirectExit>,
    pub fault_recovery: Vec<UnqualifiedFaultRecovery>,
}

/// A stored entry's code and direct exits as installed at one page
/// ([`Entry::relocate`]): buffers a machine reuses for every install, so a
/// stored block costs no allocation.
#[derive(Debug, Default)]
pub struct Relocated {
    pub code: Vec<u8>,
    pub direct_exits: Vec<DirectExit>,
}

impl Entry {
    /// The heap bytes its buffers own.
    fn buffer_bytes(&self) -> usize {
        let mut bytes = self.input.capacity() + self.code.capacity();
        bytes += self.relocations.capacity() * core::mem::size_of::<u32>();
        bytes += self.source_map.capacity() * core::mem::size_of::<(u16, u32)>();
        bytes += self.exits.capacity() * core::mem::size_of::<Exit>();
        bytes += self.recovery.capacity() * core::mem::size_of::<UnqualifiedFaultRecovery>();
        for row in &self.recovery {
            bytes += row.bindings.capacity() * core::mem::size_of::<RecoveryBinding>();
        }
        bytes
    }

    /// What it costs in a record: its slot and its buffers.
    pub(crate) fn retained_bytes(&self) -> usize {
        core::mem::size_of::<Self>() + self.buffer_bytes()
    }

    /// The block as compiled at the page whose address is `page`.
    pub fn rebase(&self, page: u64, admitted: &[u8]) -> Option<StoredBlock> {
        if !self.consistent() || admitted.get(..self.input.len())? != self.input {
            return None;
        }
        if !page.is_multiple_of(PAGE_BYTES as u64) {
            return None;
        }
        page.checked_add(u64::from(self.offset))?
            .checked_add(u64::from(self.source_bytes))?;
        let mut code = self.code.clone();
        for &at in &self.relocations {
            let field = code.get_mut(at as usize..at as usize + FIELD_BYTES)?;
            let value = u64::from_le_bytes(field.try_into().ok()?).wrapping_add(page);
            field.copy_from_slice(&value.to_le_bytes());
        }
        let direct_exits = self
            .exits
            .iter()
            .map(|exit| {
                Some(DirectExit {
                    offset: exit.offset as usize,
                    target: GuestAddress(exit.target.wrapping_add(page)),
                    kind: ExitKind::try_from(u64::from(exit.kind)).ok()?,
                    skipped: exit.skipped,
                })
            })
            .collect::<Option<_>>()?;
        Some(StoredBlock {
            native: NativeBlock {
                x86_64_code: code,
                source_map: self
                    .source_map
                    .iter()
                    .map(|&(guest, native)| {
                        (GuestAddress(page + u64::from(guest)), native as usize)
                    })
                    .collect(),
            },
            source_bytes: usize::from(self.source_bytes),
            direct_exits,
            fault_recovery: self
                .recovery
                .iter()
                .map(|row| {
                    let mut row = row.clone();
                    row.retirement = self.retirement_at(row.retirement, page)?;
                    Some(row)
                })
                .collect::<Option<_>>()?,
        })
    }

    /// What installing the block at the page whose address is `page` needs
    /// of it, written into `into`, whose buffers keep their capacity for the
    /// next: its code, rebased, and its direct exits. Its source map and
    /// recovery rows stay here; the rows' first fault rebases them
    /// ([`Self::rebase`]), and only their check that they rebase is made
    /// now. The entry's other checks ([`Self::consistent`]) are its
    /// record's: [`Record::decode`] made them; the bounds that keep the
    /// writes and the install inside the code are checked here again.
    pub fn relocate(&self, page: u64, admitted: &[u8], into: &mut Relocated) -> bool {
        self.relocate_into(page, admitted, into).is_some()
    }

    fn relocate_into(&self, page: u64, admitted: &[u8], into: &mut Relocated) -> Option<()> {
        if admitted.get(..self.input.len())? != self.input
            || !page.is_multiple_of(PAGE_BYTES as u64)
            || self.source_map.len() * 4 != usize::from(self.source_bytes)
        {
            return None;
        }
        page.checked_add(u64::from(self.offset))?
            .checked_add(u64::from(self.source_bytes))?;
        if !self
            .recovery
            .iter()
            .all(|row| row.start < row.end && row.end <= self.code.len())
            || !self
                .recovery
                .iter()
                .all(|row| self.retirement_at(row.retirement, page).is_some())
        {
            return None;
        }
        into.code.clear();
        into.code.extend_from_slice(&self.code);
        for &at in &self.relocations {
            let field = into.code.get_mut(at as usize..at as usize + FIELD_BYTES)?;
            let value = u64::from_le_bytes(field.try_into().ok()?).wrapping_add(page);
            field.copy_from_slice(&value.to_le_bytes());
        }
        into.direct_exits.clear();
        for exit in &self.exits {
            if exit.offset as usize > self.code.len() {
                return None;
            }
            into.direct_exits.push(DirectExit {
                offset: exit.offset as usize,
                target: GuestAddress(exit.target.wrapping_add(page)),
                kind: ExitKind::try_from(u64::from(exit.kind)).ok()?,
                skipped: exit.skipped,
            });
        }
        Some(())
    }

    /// Reconstruct only a source-backed retirement shape. This never mints a
    /// guest-access site or grants memory-effect permission from a portable tag.
    fn retirement_at(&self, point: RetirementPoint, page: u64) -> Option<RetirementPoint> {
        use stela_compiler::Lifter as _;
        let relative = point
            .instruction_pc()
            .0
            .checked_sub(u64::from(self.offset))?;
        if !relative.is_multiple_of(4)
            || relative > u64::from(self.source_bytes)
            || u64::from(point.retired_before()) != relative / 4
        {
            return None;
        }
        let pc = GuestAddress(page.checked_add(point.instruction_pc().0)?);
        match point.phase() {
            RetirementPhase::Before => RetirementPoint::before(pc, point.retired_before()).ok(),
            RetirementPhase::AfterFallthrough => {
                let at = usize::try_from(relative).ok()?;
                if at.checked_add(4)? > usize::from(self.source_bytes) {
                    return None;
                }
                let word = u32::from_le_bytes(self.input.get(at..at + 4)?.try_into().ok()?);
                let instruction = stela_compiler::aarch64::Decoder.lift(pc, word).ok()?;
                RetirementPoint::from_instruction(
                    &instruction,
                    point.retired_before(),
                    point.phase(),
                )
                .ok()
            }
        }
    }

    /// Check what decoding cannot: offsets inside the code and the page,
    /// ascending source map and relocations, and fields that do not overlap.
    fn consistent(&self) -> bool {
        let code = self.code.len();
        let in_code = |offset: u32, bytes: usize| (offset as usize).saturating_add(bytes) <= code;
        usize::from(self.offset) + usize::from(self.source_bytes) <= PAGE_BYTES
            && self.source_bytes != 0
            && self.offset.is_multiple_of(4)
            && self.source_bytes.is_multiple_of(4)
            && self.input.len() >= usize::from(self.source_bytes)
            && self.input.len().is_multiple_of(4)
            && usize::from(self.offset)
                .checked_add(self.input.len())
                .is_some_and(|end| end <= PAGE_BYTES)
            && self.relocations.windows(2).all(|pair| {
                pair[0]
                    .checked_add(FIELD_BYTES as u32)
                    .is_some_and(|end| end <= pair[1])
            })
            && self
                .relocations
                .iter()
                .all(|&offset| in_code(offset, FIELD_BYTES))
            && crate::artifact::validate_source_map_geometry(
                u64::from(self.offset),
                usize::from(self.source_bytes),
                code,
                0,
                self.source_map
                    .iter()
                    .map(|&(guest, native)| (u64::from(guest), native as usize)),
            )
            .is_ok()
            && self.exits.iter().all(|exit| {
                in_code(exit.offset, 0) && ExitKind::try_from(u64::from(exit.kind)).is_ok()
            })
            && self.recovery.iter().all(|range| {
                range.start < range.end
                    && range.end <= code
                    && self.retirement_at(range.retirement, 0).is_some()
                    && (range.site == RecoverySiteKind::NativeInternal
                        || range.retirement.phase() == RetirementPhase::Before)
                    && range.bindings.iter().all(|binding| {
                        binding.guest <= 31
                            && match binding.source {
                                RecoverySource::HostRegister(host) => host < 32,
                                RecoverySource::NativeSpill(_) => true,
                            }
                    })
            })
    }
}

/// Why a stored record is not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// A bounded decode allocation could not be made.
    Capacity,
    Truncated,
    Magic,
    Schema,
    Translator,
    Key,
    Checksum,
    Entry,
}

/// The translations of one page content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub translator: Digest,
    pub key: Digest,
    // Ordered by entry PC and context, including records loaded from disk.
    entries: Vec<Entry>,
}

impl Record {
    pub fn new(translator: Digest, key: Digest) -> Self {
        Self {
            translator,
            key,
            entries: Vec::new(),
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Heap bytes owned by a shared decoded record, excluding allocator
    /// bookkeeping. The per-PE source page cache accounts for its own pages.
    fn retained_bytes(&self) -> usize {
        let mut bytes = core::mem::size_of::<Self>() + 2 * core::mem::size_of::<usize>();
        bytes += self.entries.capacity() * core::mem::size_of::<Entry>();
        for entry in &self.entries {
            bytes += entry.buffer_bytes();
        }
        bytes
    }

    fn entry_index(&self, offset: u16, context: &Digest) -> Result<usize, usize> {
        // Keep the first entry when decoding a legacy record with duplicate
        // keys, as the previous sequential lookup did.
        let key = (offset, context);
        let index = self
            .entries
            .partition_point(|entry| (entry.offset, &entry.context) < key);
        match self.entries.get(index) {
            Some(entry) if (entry.offset, &entry.context) == key => Ok(index),
            _ => Err(index),
        }
    }

    pub fn find(&self, offset: u16, context: &Digest) -> Option<&Entry> {
        // A sequential scan is cheaper for short records, where the
        // dependent probes of a binary search cost more than they save.
        if self.entries.len() <= 32 {
            return self
                .entries
                .iter()
                .find(|entry| entry.offset == offset && entry.context == *context);
        }
        self.entry_index(offset, context)
            .ok()
            .map(|index| &self.entries[index])
    }

    /// Add `entry`, replacing one for the same entry PC and context.
    pub fn insert(&mut self, entry: Entry) {
        match self.entry_index(entry.offset, &entry.context) {
            Ok(index) => self.entries[index] = entry,
            Err(index) => self.entries.insert(index, entry),
        }
    }

    /// Add the entries of `other` this record lacks.
    pub fn merge(&mut self, mut other: Self) {
        if other.entries.is_empty() {
            return;
        }
        let key = |entry: &Entry| (entry.offset, entry.context);
        // Legacy packs can contain duplicate keys. The first one wins
        // unless this record already holds an entry for that key.
        other.entries.dedup_by_key(|entry| key(entry));
        if self.entries.is_empty() {
            self.entries = other.entries;
            return;
        }
        let mut merged = Vec::with_capacity(self.entries.len() + other.entries.len());
        let mut incoming = other.entries.into_iter().peekable();
        for entry in self.entries.drain(..) {
            let current = key(&entry);
            while incoming.peek().is_some_and(|next| key(next) < current) {
                merged.extend(incoming.next());
            }
            if incoming.peek().is_some_and(|next| key(next) == current) {
                incoming.next();
            }
            merged.push(entry);
        }
        merged.extend(incoming);
        self.entries = merged;
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded_bytes = HEADER_BYTES + TRAILER_BYTES;
        for entry in &self.entries {
            encoded_bytes += ENTRY_MIN_BYTES
                + entry.input.len()
                + entry.code.len()
                + entry.relocations.len() * RELOCATION_BYTES
                + entry.source_map.len() * SOURCE_MAP_BYTES
                + entry.exits.len() * EXIT_BYTES;
            for row in &entry.recovery {
                encoded_bytes += RECOVERY_ROW_BYTES + row.bindings.len() * RECOVERY_BINDING_BYTES;
            }
        }
        let mut out = Vec::with_capacity(encoded_bytes);
        out.extend(RECORD_MAGIC);
        out.extend(SCHEMA.to_le_bytes());
        out.extend((self.entries.len() as u32).to_le_bytes());
        out.extend(self.translator.0);
        out.extend(self.key.0);
        out.extend(0u64.to_le_bytes());
        for entry in &self.entries {
            out.extend(entry.context.0);
            out.extend(entry.offset.to_le_bytes());
            out.extend(entry.source_bytes.to_le_bytes());
            out.extend((entry.input.len() as u16).to_le_bytes());
            out.extend(&entry.input);
            out.extend((entry.code.len() as u32).to_le_bytes());
            out.extend((entry.relocations.len() as u32).to_le_bytes());
            for offset in &entry.relocations {
                out.extend(offset.to_le_bytes());
            }
            out.extend((entry.source_map.len() as u32).to_le_bytes());
            for (guest, native) in &entry.source_map {
                out.extend(guest.to_le_bytes());
                out.extend(native.to_le_bytes());
            }
            out.extend((entry.exits.len() as u32).to_le_bytes());
            for exit in &entry.exits {
                out.extend(exit.offset.to_le_bytes());
                out.extend(exit.target.to_le_bytes());
                out.push(exit.kind);
                out.extend(exit.skipped.to_le_bytes());
            }
            out.extend((entry.recovery.len() as u32).to_le_bytes());
            for range in &entry.recovery {
                out.extend((range.start as u32).to_le_bytes());
                out.extend((range.end as u32).to_le_bytes());
                out.extend(range.retirement.instruction_pc().0.to_le_bytes());
                out.extend(range.retirement.retired_before().to_le_bytes());
                out.push(match range.retirement.phase() {
                    RetirementPhase::Before => 0,
                    RetirementPhase::AfterFallthrough => 1,
                });
                out.push(range.site as u8);
                out.extend((range.bindings.len() as u32).to_le_bytes());
                for binding in &range.bindings {
                    out.push(binding.guest);
                    let (kind, value) = match binding.source {
                        RecoverySource::HostRegister(host) => (0, u16::from(host)),
                        RecoverySource::NativeSpill(offset) => (1, offset.bytes()),
                    };
                    out.push(kind);
                    out.extend(value.to_le_bytes());
                }
            }
            out.extend(&entry.code);
        }
        let total = (out.len() + TRAILER_BYTES) as u64;
        out[80..88].copy_from_slice(&total.to_le_bytes());
        let checksum = Sha256::digest(&out);
        out.extend(checksum);
        debug_assert_eq!(out.len(), encoded_bytes);
        out
    }

    /// Decode a record for `translator` and page `key`, checking it whole.
    pub fn decode(bytes: &[u8], translator: &Digest, key: &Digest) -> Result<Self, FormatError> {
        Self::decode_checked(bytes, translator, key, true)
    }

    /// [`Self::decode`] of bytes that may already have passed it: with
    /// `check` false, the trailer's hash and each entry's
    /// [`Entry::consistent`] are not checked again, as the same immutable
    /// bytes decode to the same entries. The format's bounds are.
    pub fn decode_checked(
        bytes: &[u8],
        translator: &Digest,
        key: &Digest,
        check: bool,
    ) -> Result<Self, FormatError> {
        if bytes.len() < HEADER_BYTES + TRAILER_BYTES {
            return Err(FormatError::Truncated);
        }
        let (body, trailer) = bytes.split_at(bytes.len() - TRAILER_BYTES);
        let mut reader = Reader(body);
        if reader.take(8)? != RECORD_MAGIC {
            return Err(FormatError::Magic);
        }
        if reader.u32()? != SCHEMA {
            return Err(FormatError::Schema);
        }
        let count = reader.u32()? as usize;
        if reader.digest()? != *translator {
            return Err(FormatError::Translator);
        }
        if reader.digest()? != *key {
            return Err(FormatError::Key);
        }
        if reader.u64()? != bytes.len() as u64 {
            return Err(FormatError::Truncated);
        }
        if check && Sha256::digest(body).as_slice() != trailer {
            return Err(FormatError::Checksum);
        }
        if count > reader.0.len() / ENTRY_MIN_BYTES {
            return Err(FormatError::Truncated);
        }
        let mut entries = decode_items(count, || {
            let entry = reader.entry()?;
            if check && !entry.consistent() {
                return Err(FormatError::Entry);
            }
            Ok(entry)
        })?;
        if !reader.0.is_empty() {
            return Err(FormatError::Entry);
        }
        if !entries.is_sorted_by_key(|entry| (entry.offset, entry.context)) {
            entries.sort_by_key(|entry| (entry.offset, entry.context));
        }
        Ok(Self {
            translator: *translator,
            key: *key,
            entries,
        })
    }
}

/// Reserve for the common case without letting a corrupt count make the
/// decoder allocate a large vector before checking its first item.
fn decode_items<T>(
    count: usize,
    mut next: impl FnMut() -> Result<T, FormatError>,
) -> Result<Vec<T>, FormatError> {
    let mut items = Vec::new();
    items
        .try_reserve_exact(count.min(256))
        .map_err(|_| FormatError::Capacity)?;
    for _ in 0..count {
        items.push(next()?);
    }
    Ok(items)
}

/// Bounded little-endian reads; every count is checked against the bytes
/// left before anything is allocated.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, bytes: usize) -> Result<&'a [u8], FormatError> {
        if self.0.len() < bytes {
            return Err(FormatError::Truncated);
        }
        let (taken, rest) = self.0.split_at(bytes);
        self.0 = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FormatError> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8, FormatError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, FormatError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, FormatError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, FormatError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn digest(&mut self) -> Result<Digest, FormatError> {
        Ok(Digest(self.array()?))
    }

    /// A count of items of at least `item` bytes each.
    fn count(&mut self, item: usize) -> Result<usize, FormatError> {
        let count = self.u32()? as usize;
        if count.saturating_mul(item) > self.0.len() {
            return Err(FormatError::Truncated);
        }
        Ok(count)
    }

    fn entry(&mut self) -> Result<Entry, FormatError> {
        let context = self.digest()?;
        let offset = self.u16()?;
        let source_bytes = self.u16()?;
        let input_bytes = usize::from(self.u16()?);
        if input_bytes > PAGE_BYTES {
            return Err(FormatError::Entry);
        }
        let input = self.take(input_bytes)?.to_vec();
        let code_bytes = self.u32()? as usize;
        let relocations = decode_items(self.count(RELOCATION_BYTES)?, || self.u32())?;
        let source_map = decode_items(self.count(SOURCE_MAP_BYTES)?, || {
            Ok((self.u16()?, self.u32()?))
        })?;
        let exits = decode_items(self.count(EXIT_BYTES)?, || {
            Ok(Exit {
                offset: self.u32()?,
                target: self.u64()?,
                kind: self.u8()?,
                skipped: self.u16()?,
            })
        })?;
        let recovery = decode_items(self.count(RECOVERY_ROW_BYTES)?, || {
            let start = self.u32()? as usize;
            let end = self.u32()? as usize;
            let pc = GuestAddress(self.u64()?);
            let count = self.u16()?;
            let phase = match self.u8()? {
                0 => RetirementPhase::Before,
                1 => RetirementPhase::AfterFallthrough,
                _ => return Err(FormatError::Entry),
            };
            let site = RecoverySiteKind::try_from(self.u8()?).map_err(|_| FormatError::Entry)?;
            let bindings = decode_items(self.count(RECOVERY_BINDING_BYTES)?, || {
                let guest = self.u8()?;
                let kind = self.u8()?;
                let value = self.u16()?;
                let source = match kind {
                    0 => RecoverySource::HostRegister(
                        u8::try_from(value).map_err(|_| FormatError::Entry)?,
                    ),
                    1 => RecoverySource::NativeSpill(
                        SpillOffset::new(value).map_err(|_| FormatError::Entry)?,
                    ),
                    _ => return Err(FormatError::Entry),
                };
                Ok(RecoveryBinding { guest, source })
            })?;
            // Build a structurally valid source-backed shape using an
            // entry view below; no raw After constructor is exposed.
            let before = RetirementPoint::before(pc, count).map_err(|_| FormatError::Entry)?;
            let retirement = match phase {
                RetirementPhase::Before => before,
                RetirementPhase::AfterFallthrough => {
                    use stela_compiler::Lifter as _;
                    let at = usize::try_from(
                        pc.0.checked_sub(u64::from(offset))
                            .ok_or(FormatError::Entry)?,
                    )
                    .map_err(|_| FormatError::Entry)?;
                    if at.checked_add(4).ok_or(FormatError::Entry)? > usize::from(source_bytes) {
                        return Err(FormatError::Entry);
                    }
                    let word = u32::from_le_bytes(
                        input
                            .get(at..at + 4)
                            .ok_or(FormatError::Entry)?
                            .try_into()
                            .map_err(|_| FormatError::Entry)?,
                    );
                    let instruction = stela_compiler::aarch64::Decoder
                        .lift(pc, word)
                        .map_err(|_| FormatError::Entry)?;
                    RetirementPoint::from_instruction(&instruction, count, phase)
                        .map_err(|_| FormatError::Entry)?
                }
            };
            Ok(UnqualifiedFaultRecovery {
                start,
                end,
                bindings,
                retirement,
                site,
            })
        })?;
        let code = self.take(code_bytes)?.to_vec();
        Ok(Entry {
            context,
            offset,
            source_bytes,
            input,
            code,
            relocations,
            source_map,
            exits,
            recovery,
        })
    }
}

/// The two probe displacements for a page at `page`: each moves it within
/// its address class, up when that stays in the class and down otherwise.
pub fn probe_displacements(page: u64) -> [u64; 2] {
    PROBES.map(|probe| {
        let up = page.wrapping_add(probe);
        if address_class(up) == address_class(page) && up > page {
            probe
        } else {
            probe.wrapping_neg()
        }
    })
}

/// The stored form of `block`, compiled at `pc` in the page at `page`, given
/// the same source compiled at the two [`probe_displacements`] of the page:
/// `None` unless the three differ only in 8-byte fields, each by exactly
/// its probe's displacement, and in their exit targets and source maps by
/// the same.
pub fn prove(
    block: &CompiledBlock,
    input: &[u8],
    page: u64,
    pc: u64,
    context: Digest,
    probes: [&CompiledBlock; 2],
) -> Option<Entry> {
    let displacements = probe_displacements(page);
    let code = &block.native.x86_64_code;
    let same_shape = |probe: &CompiledBlock, displacement: u64| {
        probe.source_bytes == block.source_bytes
            && probe.native.x86_64_code.len() == code.len()
            && probe.fault_recovery.len() == block.fault_recovery.len()
            && probe
                .fault_recovery
                .iter()
                .zip(&block.fault_recovery)
                .all(|(moved, original)| {
                    moved.start == original.start
                        && moved.end == original.end
                        && moved.bindings == original.bindings
                        && moved.site == original.site
                        && moved.retirement.phase() == original.retirement.phase()
                        && moved.retirement.retired_before() == original.retirement.retired_before()
                        && moved
                            .retirement
                            .instruction_pc()
                            .0
                            .wrapping_sub(original.retirement.instruction_pc().0)
                            == displacement
                })
            && probe.native.source_map.len() == block.native.source_map.len()
            && probe
                .native
                .source_map
                .iter()
                .zip(&block.native.source_map)
                .all(|(moved, original)| {
                    moved.1 == original.1 && moved.0.0.wrapping_sub(original.0.0) == displacement
                })
            && probe.direct_exits.len() == block.direct_exits.len()
            && probe
                .direct_exits
                .iter()
                .zip(&block.direct_exits)
                .all(|(moved, original)| {
                    moved.offset == original.offset
                        && moved.word() == original.word()
                        && moved.target.0.wrapping_sub(original.target.0) == displacement
                })
    };
    if !probes
        .iter()
        .zip(displacements)
        .all(|(probe, displacement)| same_shape(probe, displacement))
    {
        return None;
    }
    let field = |bytes: &[u8], at: usize| {
        u64::from_le_bytes(bytes[at..at + FIELD_BYTES].try_into().expect("8 bytes"))
    };
    let moves = |at: usize| {
        at + FIELD_BYTES <= code.len()
            && probes
                .iter()
                .zip(displacements)
                .all(|(probe, displacement)| {
                    field(&probe.native.x86_64_code, at).wrapping_sub(field(code, at))
                        == displacement
                })
    };
    let mut relocations = Vec::new();
    let mut at = 0;
    while at < code.len() {
        if probes
            .iter()
            .all(|probe| probe.native.x86_64_code[at] == code[at])
        {
            at += 1;
            continue;
        }
        // The field holding the first differing byte starts at most 7
        // bytes before it, and after the previous field.
        let floor = relocations
            .last()
            .map_or(0, |&last: &u32| last as usize + FIELD_BYTES);
        let start =
            (at.saturating_sub(FIELD_BYTES - 1).max(floor)..=at).find(|&start| moves(start))?;
        relocations.push(start as u32);
        at = start + FIELD_BYTES;
    }
    let mut stored = code.clone();
    for &start in &relocations {
        let start = start as usize;
        let value = field(code, start).wrapping_sub(page);
        stored[start..start + FIELD_BYTES].copy_from_slice(&value.to_le_bytes());
    }
    let page_offset = |guest: u64| {
        u16::try_from(guest.wrapping_sub(page))
            .ok()
            .filter(|&offset| usize::from(offset) < PAGE_BYTES)
    };
    let entry = Entry {
        context,
        offset: page_offset(pc)?,
        source_bytes: u16::try_from(block.source_bytes).ok()?,
        input: input.to_vec(),
        code: stored,
        relocations,
        source_map: block
            .native
            .source_map
            .iter()
            .map(|&(guest, native)| Some((page_offset(guest.0)?, u32::try_from(native).ok()?)))
            .collect::<Option<_>>()?,
        exits: block
            .direct_exits
            .iter()
            .map(|exit| {
                Some(Exit {
                    offset: u32::try_from(exit.offset).ok()?,
                    target: exit.target.0.wrapping_sub(page),
                    kind: exit.kind as u8,
                    skipped: exit.skipped,
                })
            })
            .collect::<Option<_>>()?,
        recovery: block
            .fault_recovery
            .iter()
            .map(|row| {
                let mut row = UnqualifiedFaultRecovery::from(row);
                row.retirement = row
                    .retirement
                    .relocated(GuestAddress(
                        row.retirement.instruction_pc().0.checked_sub(page)?,
                    ))
                    .ok()?;
                Some(row)
            })
            .collect::<Option<_>>()?,
    };
    entry.consistent().then_some(entry)
}

#[cfg(test)]
mod tests;
