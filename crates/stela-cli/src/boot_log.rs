//! `stela boot-log`: the boot logs `stela.efi` keeps. Every boot writes the
//! USB's own log, [`crate::efi::BOOT_LOG`] on the USB's EFI partition, from
//! its first line; an install keeps another on its machine-state partition
//! (`stela_runtime::pc::boot_log`), at the partition's start, or in the tail
//! of an Apple region that also holds the machine state
//! (`pc::machine_state`), as a setup with `--target` alone lays it out.
//!
//! Without FILE the command reads this computer's disks through raw device
//! access, never through a mounted folder, which Windows refuses for an EFI
//! partition: the disks that do not run this computer first and, when they
//! hold no log, the system disks too. FILE is a whole-disk image or device,
//! a raw partition, or a copy of the `boot.log` file itself. The hidden
//! `--partition`, `--offset` and `--in-target` name one machine-state place
//! instead. `stela setup boot-log` reads the same places of a setup.
use crate::setup::host::{self, Disk, Host};
use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::Args;
use std::{
    fmt::Write as _,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use stela_drivers::block::{BlockDevice, BlockError, Identity, Transport};
use stela_formats::payload::ReadAt;
use stela_runtime::pc::{
    boot_log::{self, Kept, Log},
    fat32::Fat32,
    gpt::{self, Guid},
    machine_state,
};

#[derive(Args)]
pub(crate) struct BootLog {
    /// A whole-disk image or device, a raw partition, or a copied boot.log
    /// file: every boot log on it is printed. Without it, every disk of this
    /// computer is read directly (with sudo for disks only root may read),
    /// so the USB Stela booted from only needs to be plugged in.
    file: Option<PathBuf>,
    /// Write the logs to this file instead of the terminal, to attach to a
    /// report.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Only the newest boot of each log.
    #[arg(long)]
    last: bool,
    /// Only the boots that failed: a stop, a failed step, or a log that
    /// ends while a step runs.
    #[arg(long)]
    failed: bool,
    /// Only the machine-state partition with this unique GUID in FILE's
    /// GPT.
    #[arg(long, conflicts_with = "offset", requires = "file", hide = true)]
    partition: Option<String>,
    /// Only the machine-state partition at this byte offset in FILE (0 for
    /// a raw partition).
    #[arg(long, value_parser = crate::args::parse_address, requires = "file", hide = true)]
    offset: Option<u64>,
    /// With --partition or --offset: the partition is a Mac's SSD partition
    /// whose last bytes hold the machine state; with --offset, FILE ends
    /// where the partition does.
    #[arg(long, hide = true)]
    in_target: bool,
}

impl BootLog {
    pub(crate) fn run(&self) -> Result<()> {
        let (logs, headings) = match &self.file {
            None => (scan(&host::System)?, true),
            Some(file) if self.partition.is_none() && self.offset.is_none() => {
                let logs = find(file)?;
                let several = logs.len() > 1;
                (logs, several)
            }
            Some(file) => (vec![(String::new(), self.load(file)?)], false),
        };
        let shown = Shown {
            last: self.last,
            failed: self.failed,
        };
        write_logs(&logs, headings, self.output.as_deref(), shown)
    }

    fn load(&self, path: &Path) -> Result<Log> {
        let mut file =
            File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let (offset, end) = match (&self.partition, self.offset) {
            (Some(guid), _) => {
                let guid: Guid = guid.parse().map_err(anyhow::Error::msg)?;
                let (table, block) = table(path)?;
                let partition = table
                    .partitions
                    .iter()
                    .find(|partition| partition.unique_guid == guid)
                    .with_context(|| {
                        format!(
                            "{} has no partition {guid}; it has:\n{}",
                            path.display(),
                            listing(&table, block)
                        )
                    })?;
                let bytes = partition.blocks() * block;
                ensure!(
                    self.in_target || bytes >= boot_log::PARTITION_BYTES,
                    "partition {guid} holds {bytes:#x} bytes; the boot log needs {:#x}, so \
                     stela.efi boots it without one",
                    boot_log::PARTITION_BYTES
                );
                let start = partition.first_lba * block;
                (start, start + bytes)
            }
            (None, Some(offset)) => (offset, file.seek(SeekFrom::End(0))?),
            (None, None) => unreachable!("`run` finds the logs without a place"),
        };
        // The machine state starts at the partition's start, or in its tail.
        let offset = if self.in_target {
            let layout = machine_state::split(end.saturating_sub(offset)).map_err(|error| {
                anyhow!(
                    "{} at {offset:#x} holds no machine state in its last bytes: {error}",
                    path.display()
                )
            })?;
            offset + layout.state_offset()
        } else {
            offset
        };
        read(&mut file, offset).with_context(|| format!("{}", path.display()))
    }
}

/// Print `logs` in order, each after a heading naming its place when
/// `headings`, or write them to `output` and say where they went. Each log
/// is printed by boot, oldest first, as [`render`] lays it out; each log's
/// one-line summary goes to standard error, and a closing line says what
/// to attach to a report.
pub(crate) fn write_logs(
    logs: &[(String, Log)],
    headings: bool,
    output: Option<&Path>,
    shown: Shown,
) -> Result<()> {
    let mut sink: Box<dyn Write> = match output {
        Some(path) => Box::new(
            File::create(path).with_context(|| format!("cannot create {}", path.display()))?,
        ),
        None => Box::new(std::io::stdout().lock()),
    };
    for (place, log) in logs {
        let mut written = Ok(());
        if headings {
            eprint!("{place}: ");
            written = writeln!(sink, "=== {place} ===");
        }
        eprint!("{}", summary(log));
        match written.and_then(|()| sink.write_all(render(log, shown).as_bytes())) {
            // A reader that closed the pipe early (`| head`) has what it
            // asked for.
            Err(error) if output.is_none() && error.kind() == std::io::ErrorKind::BrokenPipe => {
                return Ok(());
            }
            result => result.context("cannot write the boot log")?,
        }
    }
    match sink.flush() {
        Err(error) if output.is_none() && error.kind() == std::io::ErrorKind::BrokenPipe => {}
        result => result.context("cannot write the boot log")?,
    }
    match output {
        Some(path) => eprintln!("{}", saved(logs.len(), path)),
        None => eprintln!("{ATTACH}"),
    }
    Ok(())
}

/// The closing line of a log printed to the terminal.
const ATTACH: &str = "To attach this to a report, run `stela boot-log --output stela-log.txt` \
                      and attach stela-log.txt. Disk serial numbers and volume IDs are shortened.";

/// Where `count` logs were written, as the full path to attach.
fn saved(count: usize, path: &Path) -> String {
    let logs = match count {
        1 => String::from("the boot log"),
        _ => format!("{count} boot logs"),
    };
    format!(
        "Saved {logs} to {}. Attach that file to your report.",
        shown(path).display()
    )
}

/// Which boots `stela boot-log` prints.
#[derive(Clone, Copy, Default)]
pub(crate) struct Shown {
    /// Only the newest boot of each log.
    pub(crate) last: bool,
    /// Only boots that failed: a fatal stop, a failed step, or a log that
    /// ends while a step runs.
    pub(crate) failed: bool,
}

/// One boot of a log's stream: its number (none for the part of a boot the
/// ring overwrote the start of) and its lines.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Boot<'a> {
    pub(crate) number: Option<u64>,
    pub(crate) text: &'a str,
}

/// The stream's boots, oldest first, split at each `=== STELA BOOT n ===`
/// line the log writes as a boot opens it.
pub(crate) fn boots(stream: &str) -> Vec<Boot<'_>> {
    let mut boots = Vec::new();
    let mut number = None;
    let mut start = 0;
    let mut at = 0;
    for line in stream.split_inclusive('\n') {
        let marker = line
            .trim_end()
            .strip_prefix("=== STELA BOOT ")
            .and_then(|rest| rest.strip_suffix(" ==="))
            .and_then(|n| n.parse::<u64>().ok());
        if let Some(next) = marker {
            if at > start || number.is_some() {
                boots.push(Boot {
                    number,
                    text: &stream[start..at],
                });
            }
            number = Some(next);
            start = at + line.len();
        }
        at += line.len();
    }
    if at > start || number.is_some() {
        boots.push(Boot {
            number,
            text: &stream[start..],
        });
    }
    boots
}

/// How a boot ended, as its lines tell, and whether it failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) text: String,
    pub(crate) failed: bool,
    /// The boot wrote its own outcome block.
    pub(crate) recorded: bool,
}

/// The step a line begins, in this release's form (`STEP  title`) or an
/// older one's (`STEP title t=1.2`).
fn step_begins(line: &str) -> Option<&str> {
    if let Some(title) = line.strip_prefix(stela_boot_core::log_style::STEP) {
        return Some(title.trim());
    }
    let rest = line.strip_prefix("STEP ")?;
    if ["o ", "w ", "f ", "DETAIL "]
        .iter()
        .any(|mark| rest.starts_with(mark))
    {
        return None;
    }
    Some(
        rest.rsplit_once(" t=")
            .map_or(rest, |(title, _)| title)
            .trim(),
    )
}

/// Whether a line ends a step, and whether as failed.
fn step_ends(line: &str) -> Option<bool> {
    use stela_boot_core::log_style::{FAIL, OK, WARN};
    if [OK, WARN, "STEP o ", "STEP w "]
        .iter()
        .any(|mark| line.starts_with(mark))
    {
        return Some(false);
    }
    (line.starts_with(FAIL) || line.starts_with("STEP f ")).then_some(true)
}

/// How `text`, one boot's lines, ended: its own `OUTCOME` line when it has
/// one, else what its last lines show.
pub(crate) fn outcome(text: &str) -> Outcome {
    let (mut running, mut last, mut failed_step) = (None, None, false);
    let (mut fatal, mut stop, mut recorded) = (None, None, None);
    for line in text.lines() {
        let line = stela_boot_core::log_style::unlay(strip_stamp(line));
        let line = line.as_ref();
        if let Some(title) = step_begins(line) {
            running = Some(title.to_owned());
        } else if let Some(failed) = step_ends(line) {
            failed_step |= failed;
            last = running.take().or(last);
        } else if let Some(message) = line.strip_prefix("STELA FATAL ") {
            fatal = Some(message.to_owned());
        } else if let Some(message) = line.strip_prefix("STOP ") {
            stop = Some(message.to_owned());
        } else if let Some(text) = line.strip_prefix("OUTCOME ") {
            recorded = Some(text.to_owned());
        }
    }
    if let Some(text) = recorded {
        // A boot that stopped failed; one macOS restarted or turned off
        // ended, with the guest's step still running.
        let ended = text.starts_with("restarted") || text.starts_with("turned off");
        return Outcome {
            failed: fatal.is_some() || failed_step || !ended,
            text,
            recorded: true,
        };
    }
    let failed = fatal.is_some() || failed_step || running.is_some();
    let text = match (&fatal, &running, &stop) {
        (Some(message), Some(step), _) => format!("stopped in \"{step}\": {message}"),
        (Some(message), None, _) => format!("stopped: {message}"),
        (None, Some(step), _) => format!(
            "the log ends during \"{step}\": the boot hung, lost power, or stopped before its \
             log was written again; the screen showed why"
        ),
        (None, None, Some(stop)) => format!("stopped: {stop}"),
        (None, None, None) => match &last {
            Some(step) => format!("the log ends after \"{step}\" with no stop recorded"),
            None => String::from("the log holds no step of this boot"),
        },
    };
    Outcome {
        text,
        failed,
        recorded: false,
    }
}

/// `line` without the `[   12.345] ` time column the USB log adds.
fn strip_stamp(line: &str) -> &str {
    if let Some(rest) = line.strip_prefix('[')
        && let Some((time, text)) = rest.split_once("] ")
        && time
            .trim_start()
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.')
    {
        return text;
    }
    line
}

/// One boot `stela boot-log` prints: its lines the ring still holds, and
/// its kept blocks once the ring has overwritten its start.
struct Listed<'a> {
    number: Option<u64>,
    lines: &'a str,
    kept: Option<&'a Kept>,
    outcome: Outcome,
}

/// How a boot whose lines the ring overwrote ended, from its kept outcome
/// block.
fn kept_outcome(kept: &Kept) -> Outcome {
    let block = String::from_utf8_lossy(&kept.outcome);
    let found = outcome(&block);
    if found.recorded {
        return found;
    }
    Outcome {
        text: String::from(
            "no outcome kept: the boot hung, lost power, or stopped before its log was written \
             again",
        ),
        failed: true,
        recorded: false,
    }
}

/// `log` as `stela boot-log` prints it: each boot `shown` under a title
/// with its number and outcome, newest last, with private identifiers
/// shortened, and an outcome block from the tool for a boot that wrote
/// none. A boot the ring overwrote whole, or the start of, shows the
/// header and outcome blocks the log kept for it.
pub(crate) fn render(log: &Log, shown: Shown) -> String {
    use stela_boot_core::log_style::{RULE, THIN_RULE, redact};
    let stream = String::from_utf8_lossy(&log.stream);
    let mut parts = boots(&stream);
    // The part before the first boot marker is the end of the boot before
    // it, or of the newest boot when the ring holds no marker.
    let first = parts.iter().find_map(|boot| boot.number);
    if let Some(part) = parts.first_mut()
        && part.number.is_none()
    {
        part.number = first.map_or(Some(log.boots), |first| first.checked_sub(1));
    }
    let oldest = parts.first().and_then(|boot| boot.number);
    let kept_of = |number: Option<u64>| {
        number.and_then(|number| log.kept.iter().find(|kept| kept.boot == number))
    };
    let mut boots: Vec<Listed<'_>> = log
        .kept
        .iter()
        .filter(|kept| oldest.is_none_or(|oldest| kept.boot < oldest))
        .map(|kept| Listed {
            number: Some(kept.boot),
            lines: "",
            kept: Some(kept),
            outcome: kept_outcome(kept),
        })
        .collect();
    for (index, part) in parts.iter().enumerate() {
        boots.push(Listed {
            number: part.number,
            lines: part.text,
            kept: (index == 0 && first != part.number)
                .then(|| kept_of(part.number))
                .flatten()
                .filter(|kept| !kept.header.is_empty()),
            outcome: outcome(part.text),
        });
    }
    if shown.failed {
        boots.retain(|boot| boot.outcome.failed);
    }
    if shown.last && boots.len() > 1 {
        boots.drain(..boots.len() - 1);
    }
    let rule = "#".repeat(80);
    let mut text = String::new();
    for boot in &boots {
        let name = match boot.number {
            Some(number) => format!("Boot {number}"),
            None => String::from("Older boot, its start overwritten"),
        };
        let outcome = &boot.outcome;
        let mark = if outcome.failed { "FAILED" } else { "ended" };
        let _ = writeln!(text, "{rule}\n# {name}: {mark}: {}\n{rule}", outcome.text);
        if let Some(kept) = boot.kept {
            let which = if boot.lines.is_empty() {
                "this boot's lines"
            } else {
                "the start of this boot"
            };
            let _ = writeln!(
                text,
                "(the log's ring has overwritten {which}; these are its kept header and outcome)\n\
                 {RULE}"
            );
            for line in String::from_utf8_lossy(&kept.header).lines() {
                let _ = writeln!(text, "{}", redact(line));
            }
            let _ = writeln!(text, "{THIN_RULE}");
            if boot.lines.is_empty() {
                for line in String::from_utf8_lossy(&kept.outcome).lines() {
                    let _ = writeln!(text, "{}", redact(line));
                }
                if outcome.recorded {
                    let _ = writeln!(text, "{RULE}");
                }
            }
        }
        for line in boot.lines.lines() {
            let _ = writeln!(text, "{}", redact(line));
        }
        if !outcome.recorded {
            // A kept boot's header block ended with the rule already.
            if boot.kept.is_none() || !boot.lines.is_empty() {
                let _ = writeln!(text, "{THIN_RULE}");
            }
            let _ = writeln!(
                text,
                "OUTCOME (from stela boot-log) {}\n{RULE}",
                outcome.text
            );
        }
    }
    text
}

/// `path` in full, as a file to attach is found again.
pub(crate) fn shown(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Every boot log in FILE, each with where it is: the file itself when it
/// is a copied `boot.log`; else in each GPT partition, or in FILE itself
/// without a GPT, the USB's log file on a FAT32 volume, then the machine
/// state's at the start or in the tail.
fn find(path: &Path) -> Result<Vec<(String, Log)>> {
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let end = file.seek(SeekFrom::End(0))?;
    let mut magic = [0u8; 8];
    file.seek(SeekFrom::Start(0))?;
    if file.read_exact(&mut magic).is_ok() && &magic == boot_log::MAGIC {
        let mut region = vec![0; usize::try_from(end.min(boot_log::LOG_BYTES))?];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut region)?;
        let log = boot_log::read(&region).with_context(|| format!("{}", path.display()))?;
        return Ok(vec![(String::from("the file"), log)]);
    }
    let (spans, listed) = match table(path) {
        Ok((table, block)) => (
            table
                .partitions
                .iter()
                .map(|partition| {
                    let place = format!("partition {}", partition.unique_guid);
                    (
                        place,
                        partition.first_lba * block,
                        partition.blocks() * block,
                    )
                })
                .collect::<Vec<_>>(),
            format!("; its GPT has:\n{}", listing(&table, block)),
        ),
        Err(_) => (vec![(String::from("the file"), 0, end)], String::new()),
    };
    let mut logs = Logs::default();
    for (place, start, bytes) in spans {
        let mut read = |offset: u64, buffer: &mut [u8]| -> Result<()> {
            ensure!(
                offset + buffer.len() as u64 <= bytes,
                "read past the partition"
            );
            file.seek(SeekFrom::Start(start + offset))?;
            Ok(file.read_exact(buffer)?)
        };
        logs.extend(partition_logs(&mut read, bytes, &place));
    }
    ensure!(
        !logs.is_empty(),
        "{} holds no Stela boot log: no {} on a FAT32 volume, and nothing at the start or in \
         the last 16 MiB of any partition{listed}",
        path.display(),
        crate::efi::BOOT_LOG
    );
    Ok(logs.all())
}

/// The boot logs found on one disk or partition: the USB's own log file,
/// then the machine state's.
#[derive(Default)]
pub(crate) struct Logs {
    pub(crate) usb: Vec<(String, Log)>,
    pub(crate) machine: Vec<(String, Log)>,
}

impl Logs {
    fn is_empty(&self) -> bool {
        self.usb.is_empty() && self.machine.is_empty()
    }

    fn extend(&mut self, other: Self) {
        self.usb.extend(other.usb);
        self.machine.extend(other.machine);
    }

    /// The USB's logs first.
    pub(crate) fn all(self) -> Vec<(String, Log)> {
        let mut logs = self.usb;
        logs.extend(self.machine);
        logs
    }
}

/// Fills a buffer from one partition, or from a file standing for one, at a
/// byte offset.
type Reader<'a> = dyn FnMut(u64, &mut [u8]) -> Result<()> + 'a;

/// A partition as the FAT32 reader reads it.
struct Span<'a, 'b> {
    read: &'a mut Reader<'b>,
    bytes: u64,
}

impl ReadAt for Span<'_, '_> {
    type Error = anyhow::Error;

    fn len(&self) -> u64 {
        self.bytes
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        (self.read)(offset, buffer)
    }
}

/// Every boot log of a `bytes`-long partition named `place`: the USB's
/// own file when it holds a FAT32 volume, as `stela.efi`'s own FAT reader
/// finds it, and the machine state's at its start and in its last bytes.
fn partition_logs(read: &mut Reader<'_>, bytes: u64, place: &str) -> Logs {
    let mut logs = Logs::default();
    if let Ok(log) = file_log(read, bytes) {
        logs.usb
            .push((format!("{place}, {}", crate::efi::BOOT_LOG), log));
    }
    if bytes >= boot_log::PARTITION_BYTES
        && let Ok(log) = state_log(read, 0)
    {
        logs.machine.push((place.to_owned(), log));
    }
    if let Ok(layout) = machine_state::split(bytes)
        && let Ok(log) = state_log(read, layout.state_offset())
    {
        logs.machine
            .push((format!("{place}, machine state in its last bytes"), log));
    }
    logs
}

/// The USB's own log, [`crate::efi::BOOT_LOG`] on the FAT32 volume of a
/// `bytes`-long partition: the file's first [`boot_log::LOG_BYTES`], which
/// `stela.efi` writes through its clusters.
fn file_log(read: &mut Reader<'_>, bytes: u64) -> Result<Log> {
    let mut volume = Fat32::open(Span { read, bytes }).map_err(|error| anyhow!("{error}"))?;
    let file = volume
        .file(crate::efi::BOOT_LOG)
        .map_err(|error| anyhow!("{error}"))?;
    ensure!(
        file.bytes >= boot_log::LOG_BYTES,
        "{} holds {} bytes, fewer than the log's {}",
        crate::efi::BOOT_LOG,
        file.bytes,
        boot_log::LOG_BYTES
    );
    let mut span = volume.into_inner();
    let mut region = vec![0; boot_log::LOG_BYTES as usize];
    let mut done = 0;
    for extent in &file.extents {
        let take = usize::try_from(extent.bytes)?.min(region.len() - done);
        span.read_at(extent.offset, &mut region[done..done + take])?;
        done += take;
        if done == region.len() {
            break;
        }
    }
    ensure!(done == region.len(), "{} ends early", crate::efi::BOOT_LOG);
    boot_log::read(&region).with_context(|| format!("{} has no boot log", crate::efi::BOOT_LOG))
}

/// The boot log of the machine state that starts at byte `state`, when a
/// log header is there: one block is read before the whole region.
fn state_log(read: &mut Reader<'_>, state: u64) -> Result<Log> {
    let start = state + boot_log::OFFSET;
    let mut header = vec![0; boot_log::HEADER_BYTES as usize];
    read(start, &mut header)?;
    ensure!(
        header.starts_with(boot_log::MAGIC),
        "no boot log at {start:#x}"
    );
    let mut region = vec![0; boot_log::LOG_BYTES as usize];
    read(start, &mut region)?;
    boot_log::read(&region).with_context(|| format!("no boot log at {start:#x}"))
}

/// A whole disk as the person running the command knows it: its model,
/// size, device, and the folders or drive letters its volumes have.
pub(crate) fn describe(disk: &Disk) -> String {
    let device = if cfg!(windows) {
        format!(
            "PhysicalDrive{}",
            disk.identifier.trim_start_matches("disk")
        )
    } else {
        format!("/dev/{}", disk.identifier)
    };
    let mut text = match disk.name.trim() {
        "" => String::from("disk"),
        name => name.to_owned(),
    };
    let _ = write!(text, " ({}, {device}", host::size_text(disk.bytes));
    for mount in disk.partitions.iter().filter_map(|p| p.mount.as_ref()) {
        let _ = write!(text, ", {}", mount.display());
    }
    text.push(')');
    text
}

/// The boot logs on whole disk `disk`, read through `host`'s raw access to
/// its partitions, each placed by its partition. A disk none of whose
/// partitions can be read is refused with the first reason.
pub(crate) fn disk_logs(host: &dyn Host, disk: &Disk) -> Result<Logs> {
    let mut logs = Logs::default();
    let (mut refused, mut readable) = (None, false);
    for partition in &disk.partitions {
        let Ok(info) = host.partition(&partition.identifier) else {
            continue;
        };
        let identifier = partition.identifier.as_str();
        let mut read = |offset: u64, buffer: &mut [u8]| -> Result<()> {
            let bytes = host.read(identifier, offset, buffer.len())?;
            ensure!(bytes.len() == buffer.len(), "{identifier} read short");
            buffer.copy_from_slice(&bytes);
            Ok(())
        };
        if let Err(error) = read(0, &mut [0; 512]) {
            refused.get_or_insert(error);
            continue;
        }
        readable = true;
        logs.extend(partition_logs(
            &mut read,
            info.bytes,
            &format!("partition {identifier}"),
        ));
    }
    match refused {
        Some(error) if !readable => Err(error),
        _ => Ok(logs),
    }
}

/// Every boot log on `host`'s disks, each placed by its disk and partition:
/// the disks that do not run this computer first and, when they hold none,
/// the system disks too. No log anywhere is refused with the disks looked
/// at and what to try.
pub(crate) fn scan(host: &dyn Host) -> Result<Vec<(String, Log)>> {
    let disks = host.disks()?;
    let (mut looked, mut unread) = (String::new(), String::new());
    for system in [false, true] {
        let mut logs = Vec::new();
        for disk in disks.iter().filter(|disk| disk.system == system) {
            let name = describe(disk);
            let _ = writeln!(looked, "  {name}");
            match disk_logs(host, disk) {
                Ok(found) => logs.extend(
                    found
                        .all()
                        .into_iter()
                        .map(|(place, log)| (format!("{name}: {place}"), log)),
                ),
                Err(error) => {
                    let _ = writeln!(unread, "  {name}: {error:#}");
                }
            }
        }
        if !logs.is_empty() {
            return Ok(logs);
        }
    }
    let rights = if cfg!(windows) {
        format!("from {}", host::ADMIN)
    } else {
        format!("with {}", host::ADMIN)
    };
    let looked = if looked.is_empty() {
        String::from("This computer lists no disks.\n")
    } else {
        format!("Looked at:\n{looked}")
    };
    let unread = if unread.is_empty() {
        unread
    } else {
        format!("Could not read:\n{unread}")
    };
    bail!(
        "no Stela boot log on this computer's disks.\n{looked}{unread}Plug in the USB Stela \
         booted from and run this again {rights}."
    )
}

/// The boot log of the machine state that starts at byte `state` of `file`.
fn read(file: &mut File, state: u64) -> Result<Log> {
    let start = state + boot_log::OFFSET;
    let mut region = vec![0; boot_log::LOG_BYTES as usize];
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut region).with_context(|| {
        format!(
            "no boot log region at {start:#x}: the machine-state partition needs {:#x} bytes",
            boot_log::PARTITION_BYTES
        )
    })?;
    boot_log::read(&region).with_context(|| format!("no boot log at {start:#x}"))
}

/// What a log holds, one line.
pub(crate) fn summary(log: &Log) -> String {
    let mut text = format!(
        "Stela boot log: {} boots, {} bytes",
        log.boots,
        log.stream.len()
    );
    if log.overwritten() != 0 {
        let _ = write!(
            text,
            "; the {} bytes before them were overwritten",
            log.overwritten()
        );
    }
    text.push('\n');
    text
}

/// A disk image read through 512- or 4096-byte blocks.
struct Image {
    file: File,
    identity: Identity,
}

impl BlockDevice for Image {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        self.file
            .seek(SeekFrom::Start(lba * u64::from(self.identity.block_size)))
            .and_then(|_| self.file.read_exact(buffer))
            .map_err(|_| BlockError::Device { status: 0 })
    }

    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
}

/// The GPT of a whole-disk image or device and its block size. A device's
/// length is where it ends, as its metadata says none.
fn table(path: &Path) -> Result<(gpt::Table, u64)> {
    let bytes = File::open(path)?.seek(SeekFrom::End(0))?;
    let mut last = None;
    for block in [512u32, 4096] {
        let mut image = Image {
            file: File::open(path)?,
            identity: Identity {
                transport: Transport::VirtioBlk,
                location: path.display().to_string(),
                model: String::from("image"),
                serial: String::new(),
                blocks: bytes / u64::from(block),
                block_size: block,
                read_only: true,
                features: Default::default(),
            },
        };
        match gpt::read(&mut image) {
            Ok(table) => return Ok((table, u64::from(block))),
            Err(error) => last = Some(error),
        }
    }
    bail!(
        "{} holds no GPT ({}); pass --offset for a raw partition",
        path.display(),
        last.expect("two block sizes were tried")
    )
}

fn listing(table: &gpt::Table, block: u64) -> String {
    let mut text = String::new();
    for partition in &table.partitions {
        let _ = writeln!(
            text,
            "  {}  {:#x} bytes at {:#x}  {}",
            partition.unique_guid,
            partition.blocks() * block,
            partition.first_lba * block,
            partition.name
        );
    }
    text
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use stela_formats::payload::gpt::{Disk, Partition, Table, encode};
    use stela_runtime::pc::boot_log::Writer;

    /// A partition of a byte vector.
    struct Bytes<'a> {
        bytes: &'a mut [u8],
        identity: Identity,
    }

    impl BlockDevice for Bytes<'_> {
        fn identity(&self) -> &Identity {
            &self.identity
        }

        fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            self.identity.check(lba, buffer.len())?;
            let at = (lba * 512) as usize;
            buffer.copy_from_slice(&self.bytes[at..at + buffer.len()]);
            Ok(())
        }

        fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
            self.identity.check(lba, data.len())?;
            let at = (lba * 512) as usize;
            self.bytes[at..at + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    /// A log region with one boot per entry of `boots`, each printing it.
    pub(crate) fn region(boots: &[&str]) -> Vec<u8> {
        let mut bytes = vec![0u8; boot_log::LOG_BYTES as usize];
        let mut region = Bytes {
            bytes: &mut bytes,
            identity: Identity {
                transport: Transport::VirtioBlk,
                location: "test".into(),
                model: "RAM".into(),
                serial: String::new(),
                blocks: boot_log::LOG_BYTES / 512,
                block_size: 512,
                read_only: false,
                features: Default::default(),
            },
        };
        for line in boots {
            let mut writer = Writer::open(&mut region).unwrap();
            writer.append(line.as_bytes());
            writer.flush(&mut region).unwrap();
        }
        bytes
    }

    const GUID: &str = "5E1A0000-0000-4000-8000-0000000000C0";

    /// A GPT image with a machine-state partition at 1 MiB, whose log has two
    /// boots when it holds one.
    fn image(path: &Path, partition_bytes: u64) {
        let mib = 1024 * 1024;
        let disk_bytes = (partition_bytes + 2 * mib).max(16 * mib);
        let blocks = disk_bytes / 512;
        let mut bytes = vec![0u8; disk_bytes as usize];
        let table = Table {
            disk_guid: Guid([7; 16]),
            partitions: vec![Partition {
                type_guid: "0FC63DAF-8483-4772-8E79-3D69D8477DE4".parse().unwrap(),
                unique_guid: GUID.parse().unwrap(),
                first_lba: 2048,
                last_lba: 2048 + partition_bytes / 512 - 1,
                attributes: 0,
                name: "machine state".into(),
            }],
        };
        let disk = Disk {
            block_bytes: 512,
            blocks,
        };
        for write in encode(disk, &table).unwrap() {
            let at = (write.lba * 512) as usize;
            bytes[at..at + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        if partition_bytes >= boot_log::PARTITION_BYTES {
            let start = (2048 * 512 + boot_log::OFFSET) as usize;
            bytes[start..start + boot_log::LOG_BYTES as usize]
                .copy_from_slice(&region(&["first boot\n", "second boot\n"]));
        }
        std::fs::write(path, bytes).unwrap();
    }

    fn command(file: &Path, partition: Option<&str>, offset: Option<u64>) -> BootLog {
        BootLog {
            file: Some(file.into()),
            output: None,
            last: false,
            failed: false,
            partition: partition.map(Into::into),
            offset,
            in_target: false,
        }
    }

    #[test]
    fn gpt_log_selection_accepts_guid_or_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine-state.img");
        image(&path, boot_log::PARTITION_BYTES);
        let expected = "=== STELA BOOT 1 ===\nfirst boot\n=== STELA BOOT 2 ===\nsecond boot\n";
        let log = command(&path, Some(&GUID.to_lowercase()), None)
            .load(&path)
            .unwrap();
        assert_eq!(log.boots, 2);
        assert_eq!(String::from_utf8(log.stream.clone()).unwrap(), expected);
        assert_eq!(
            summary(&log),
            format!("Stela boot log: 2 boots, {} bytes\n", expected.len())
        );
        let raw = command(&path, None, Some(2048 * 512)).load(&path).unwrap();
        assert_eq!(raw, log);

        // Without a place the command finds the log itself.
        let found = find(&path).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], (format!("partition {GUID}"), log.clone()));
        let error = format!(
            "{:#}",
            command(&path, Some("5E1A0000-0000-4000-8000-0000000000C1"), None)
                .load(&path)
                .unwrap_err()
        );
        assert!(error.contains("has no partition"), "{error}");
        // A region that holds no log is refused by name.
        let error = format!(
            "{:#}",
            command(&path, None, Some(0)).load(&path).unwrap_err()
        );
        assert!(error.contains("the log region is blank"), "{error}");
    }

    #[test]
    fn boot_log_reads_machine_state_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("region.img");
        // A 20 MiB partition keeps its machine state from 4 MiB.
        let partition_bytes = 20 * 1024 * 1024;
        image(&path, partition_bytes);
        let mut bytes = std::fs::read(&path).unwrap();
        let tail = machine_state::split(partition_bytes)
            .unwrap()
            .state_offset();
        assert_eq!(tail, 4 * 1024 * 1024);
        let at = (2048 * 512 + tail + boot_log::OFFSET) as usize;
        bytes[at..at + boot_log::LOG_BYTES as usize].copy_from_slice(&region(&["in the tail\n"]));
        std::fs::write(&path, &bytes).unwrap();
        let mut tail_log = command(&path, Some(GUID), None);
        tail_log.in_target = true;
        let log = tail_log.load(&path).unwrap();
        assert_eq!(
            String::from_utf8(log.stream).unwrap(),
            "=== STELA BOOT 1 ===\nin the tail\n"
        );
        // A raw partition ends with the file.
        let raw = dir.path().join("raw.img");
        std::fs::write(
            &raw,
            &bytes[2048 * 512..2048 * 512 + partition_bytes as usize],
        )
        .unwrap();
        let mut raw_log = command(&raw, None, Some(0));
        raw_log.in_target = true;
        assert_eq!(raw_log.load(&raw).unwrap().boots, 1);
        // A partition too small for a tail is named.
        let small = dir.path().join("small.img");
        image(&small, 2 * 1024 * 1024);
        let mut small_log = command(&small, Some(GUID), None);
        small_log.in_target = true;
        let error = format!("{:#}", small_log.load(&small).unwrap_err());
        assert!(
            error.contains("no machine state in its last bytes"),
            "{error}"
        );
    }

    #[test]
    fn boot_log_reports_undersized_partition() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.img");
        image(&path, 2 * 1024 * 1024);
        let error = format!(
            "{:#}",
            command(&path, Some(GUID), None).load(&path).unwrap_err()
        );
        assert!(error.contains("boots it without one"), "{error}");
        // Without a place, no log anywhere is named with the GPT's partitions.
        let error = format!("{:#}", find(&path).unwrap_err());
        assert!(error.contains("holds no Stela boot log"), "{error}");
        assert!(error.contains(GUID), "{error}");
    }

    #[test]
    fn boot_log_finds_logs_at_a_partition_start_and_in_its_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("both.img");
        let partition_bytes = 20 * 1024 * 1024;
        image(&path, partition_bytes);
        let mut bytes = std::fs::read(&path).unwrap();
        let tail = machine_state::split(partition_bytes)
            .unwrap()
            .state_offset();
        let at = (2048 * 512 + tail + boot_log::OFFSET) as usize;
        bytes[at..at + boot_log::LOG_BYTES as usize].copy_from_slice(&region(&["in the tail\n"]));
        std::fs::write(&path, &bytes).unwrap();
        let found = find(&path).unwrap();
        let places: Vec<_> = found
            .iter()
            .map(|(place, log)| (place.as_str(), log.boots))
            .collect();
        assert_eq!(
            places,
            [
                (format!("partition {GUID}").as_str(), 2),
                (
                    format!("partition {GUID}, machine state in its last bytes").as_str(),
                    1
                ),
            ]
        );
        // A raw partition without a GPT is searched as one.
        let raw = dir.path().join("raw.img");
        std::fs::write(
            &raw,
            &bytes[2048 * 512..2048 * 512 + partition_bytes as usize],
        )
        .unwrap();
        let found = find(&raw).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, "the file");
    }

    /// A 40 MiB FAT32 volume as setup's EFI partition holds it:
    /// `EFI/STELA/BOOT.LOG` holds `log` when given, in a contiguous chain.
    pub(crate) fn fat_volume(log: Option<&[u8]>) -> Vec<u8> {
        use stela_runtime::pc::fat32::format::{
            END_OF_CHAIN, FATS, Geometry, MEDIA_ENTRY, volume_label,
        };
        const DIRECTORY: u8 = 0x10;
        const ARCHIVE: u8 = 0x20;
        let sectors = 40 * 2048;
        let geometry = Geometry::new(sectors, 512).unwrap();
        let mut bytes = vec![0u8; (sectors * 512) as usize];
        let boot = geometry
            .boot_sector(0, &volume_label("EFI").unwrap(), 1)
            .unwrap();
        bytes[..512].copy_from_slice(&boot);
        let set = |bytes: &mut [u8], cluster: u32, value: u32| {
            for copy in 0..FATS {
                let at = (geometry.fat_sector(copy) * 512 + u64::from(cluster) * 4) as usize;
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
        };
        set(&mut bytes, 0, MEDIA_ENTRY);
        for cluster in 1..=4 {
            set(&mut bytes, cluster, END_OF_CHAIN);
        }
        let entry = |bytes: &mut [u8],
                     directory: u32,
                     name: &[u8; 11],
                     attributes: u8,
                     first: u32,
                     size: u32| {
            let at = geometry.cluster_offset(directory) as usize;
            let entry = &mut bytes[at..at + 32];
            entry[..11].copy_from_slice(name);
            entry[11] = attributes;
            entry[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
            entry[26..28].copy_from_slice(&(first as u16).to_le_bytes());
            entry[28..32].copy_from_slice(&size.to_le_bytes());
        };
        entry(&mut bytes, 2, b"EFI        ", DIRECTORY, 3, 0);
        entry(&mut bytes, 3, b"STELA      ", DIRECTORY, 4, 0);
        if let Some(log) = log {
            let clusters = log.len().div_ceil(geometry.cluster_bytes() as usize) as u32;
            for cluster in 5..5 + clusters {
                let next = if cluster + 1 == 5 + clusters {
                    END_OF_CHAIN
                } else {
                    cluster + 1
                };
                set(&mut bytes, cluster, next);
            }
            entry(&mut bytes, 4, b"BOOT    LOG", ARCHIVE, 5, log.len() as u32);
            let at = geometry.cluster_offset(5) as usize;
            bytes[at..at + log.len()].copy_from_slice(log);
        }
        bytes
    }

    /// A whole-disk image of `partitions`, each a type and its bytes, laid
    /// out from 1 MiB.
    fn disk_image(path: &Path, partitions: &[(&str, &[u8])]) {
        let mut first = 2048u64;
        let mut table = Table {
            disk_guid: Guid([9; 16]),
            partitions: Vec::new(),
        };
        let mut writes = Vec::new();
        for (index, (kind, bytes)) in partitions.iter().enumerate() {
            let blocks = bytes.len() as u64 / 512;
            table.partitions.push(Partition {
                type_guid: kind.parse().unwrap(),
                unique_guid: format!("5E1A0000-0000-4000-8000-00000000000{index}")
                    .parse()
                    .unwrap(),
                first_lba: first,
                last_lba: first + blocks - 1,
                attributes: 0,
                name: String::new(),
            });
            writes.push((first * 512, *bytes));
            first += blocks;
        }
        let disk = Disk {
            block_bytes: 512,
            blocks: first + 2048,
        };
        let mut image = vec![0u8; (disk.blocks * 512) as usize];
        for write in encode(disk, &table).unwrap() {
            let at = (write.lba * 512) as usize;
            image[at..at + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        for (at, bytes) in writes {
            image[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        }
        std::fs::write(path, image).unwrap();
    }

    const ESP: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
    const LINUX: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

    #[test]
    fn boot_log_reads_the_usb_s_own_file_before_the_machine_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usb.img");
        let esp = fat_volume(Some(&region(&["CHOICE 3 (Install macOS)\n"])));
        let mut state = vec![0u8; boot_log::PARTITION_BYTES as usize];
        state[boot_log::OFFSET as usize..].copy_from_slice(&region(&["NOR persistent\n"]));
        disk_image(&path, &[(LINUX, &state), (ESP, &esp)]);
        let found = find(&path).unwrap();
        let places: Vec<_> = found
            .iter()
            .map(|(place, log)| (place.as_str(), log.boots))
            .collect();
        assert_eq!(
            places,
            [
                (
                    "partition 5E1A0000-0000-4000-8000-000000000001, EFI/stela/boot.log",
                    1
                ),
                ("partition 5E1A0000-0000-4000-8000-000000000000", 1),
            ]
        );
        assert_eq!(
            found[0].1.stream,
            b"=== STELA BOOT 1 ===\nCHOICE 3 (Install macOS)\n"
        );
        // A raw EFI partition, and a stick whose log file was never made.
        let raw = dir.path().join("esp.img");
        std::fs::write(&raw, &esp).unwrap();
        assert_eq!(find(&raw).unwrap()[0].0, "the file, EFI/stela/boot.log");
        let bare = dir.path().join("bare.img");
        disk_image(&bare, &[(ESP, &fat_volume(None))]);
        let error = format!("{:#}", find(&bare).unwrap_err());
        assert!(
            error.contains("no EFI/stela/boot.log on a FAT32 volume"),
            "{error}"
        );
    }

    #[test]
    fn boot_log_reads_a_copied_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot.log");
        std::fs::write(&path, region(&["first\n", "second\n"])).unwrap();
        let found = find(&path).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "the file");
        assert_eq!(found[0].1.boots, 2);
        // A blank copy holds nothing to print.
        std::fs::write(&path, vec![0u8; boot_log::LOG_BYTES as usize]).unwrap();
        assert!(find(&path).is_err());
    }

    #[test]
    fn boot_log_output_holds_each_boot_with_its_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("log.txt");
        let log = boot_log::read(&region(&["caf\u{e9} \x01\n"])).unwrap();
        let logs = [
            (String::from("USB"), log.clone()),
            (String::from("disk"), log.clone()),
        ];
        write_logs(&logs, true, Some(&output), Shown::default()).unwrap();
        let rendered = render(&log, Shown::default());
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            format!("=== USB ===\n{rendered}=== disk ===\n{rendered}")
        );
        let said = saved(2, &output);
        assert!(said.starts_with("Saved 2 boot logs to "), "{said}");
        assert!(
            said.ends_with("log.txt. Attach that file to your report."),
            "{said}"
        );
        let error = write_logs(
            &logs,
            false,
            Some(&dir.path().join("no/such/dir")),
            Shown::default(),
        );
        assert!(format!("{:#}", error.unwrap_err()).contains("cannot create"));
    }

    /// Three boots as release 0.2.0 wrote them (identifiers made up): one
    /// that went on, and two that ended in the same step, the second with
    /// its stop recorded in this release's form.
    const BOOTS: [&str; 3] = [
        "[   31.349] STEP Opening the boot log on the USB t=31.349\n\
         [   31.365] STEP o Opening the boot log on the USB ms=15\n\
         [   73.399] CHOSEN DISK 2111082561276:5E1A0000-0000-4000-8000-0000000000C0\n\
         [   95.164] STEP Taking control of the other processors t=95.164\n",
        "[   27.527] STEP  Opening the boot log on the USB\n\
         [   27.544] OK    Opening the boot log on the USB (16 ms)\n\
         [   36.656]       INSTALLER      disk SATA \"PNY\" serial=PNY123456789 size=1.0GiB\n\
         [   95.164] STEP  Taking control of the other processors\n",
        "[   27.527] STEP  Reading the boot files\n\
         [   28.000] FAIL  Reading the boot files (a file is short, 473 ms)\n\
         \nSTELA FATAL a bundle file ended early\n\
         --------------------------------------------------------------------------------\n\
         OUTCOME stopped in \"Reading the boot files\" at 28.1 s, code 0x11: a bundle file \
         ended early\n\
         ================================================================================\n",
    ];

    #[test]
    fn boots_the_ring_overwrote_show_their_kept_blocks() {
        use stela_boot_core::log_style::{RULE, THIN_RULE};
        let kept = |boot: u64, outcome: &str| Kept {
            boot,
            header: format!(
                "STELA   0.3.0, build b{boot}\nPC      CPU, disk serial=SERIAL{boot}wxyz\n"
            )
            .into_bytes(),
            outcome: outcome.as_bytes().to_vec(),
        };
        let stream = format!(
            "[  49.000] GUEST| bye\n{THIN_RULE}\n[  50.000] OUTCOME restarted at 50.0 s, code 0x12\n\
             {RULE}\n=== STELA BOOT 4 ===\n[   1.000] STEP  A\n[   2.000] OK    A (1 ms)\n"
        );
        let log = Log {
            boots: 4,
            head: 1 << 30,
            ring_bytes: stream.len() as u64,
            stream: stream.into_bytes(),
            kept: vec![
                kept(
                    1,
                    "[   1.000] OUTCOME stopped in \"A\" at 1.0 s, code 0x11: broke\n",
                ),
                kept(2, ""),
                kept(3, "[  50.000] OUTCOME restarted at 50.0 s, code 0x12\n"),
                kept(4, ""),
            ],
        };
        let rendered = render(&log, Shown::default());
        let titles: Vec<&str> = rendered
            .lines()
            .filter(|line| line.starts_with("# Boot "))
            .collect();
        assert_eq!(
            titles,
            [
                "# Boot 1: FAILED: stopped in \"A\" at 1.0 s, code 0x11: broke",
                "# Boot 2: FAILED: no outcome kept: the boot hung, lost power, or stopped before \
                 its log was written again",
                "# Boot 3: ended: restarted at 50.0 s, code 0x12",
                "# Boot 4: ended: the log ends after \"A\" with no stop recorded",
            ],
            "{rendered}"
        );
        assert!(
            rendered.contains("overwritten this boot's lines"),
            "{rendered}"
        );
        assert!(
            rendered.contains("overwritten the start of this boot"),
            "{rendered}"
        );
        assert!(rendered.contains("STELA   0.3.0, build b3\n"), "{rendered}");
        // Boot 4's start is in the ring, so its kept header is not repeated.
        assert!(!rendered.contains("build b4"), "{rendered}");
        assert!(!rendered.contains("SERIAL"), "{rendered}");
        assert!(rendered.contains("serial=..wxyz"), "{rendered}");
        let failed = render(
            &log,
            Shown {
                last: false,
                failed: true,
            },
        );
        assert_eq!(failed.matches("# Boot ").count(), 2, "{failed}");
    }

    #[test]
    fn boots_are_numbered_with_their_outcomes() {
        let log = boot_log::read(&region(&BOOTS)).unwrap();
        let text = String::from_utf8(log.stream.clone()).unwrap();
        let split = boots(&text);
        assert_eq!(
            split.iter().map(|boot| boot.number).collect::<Vec<_>>(),
            [Some(1), Some(2), Some(3)]
        );
        let outcomes: Vec<_> = split.iter().map(|boot| outcome(boot.text)).collect();
        assert!(outcomes[0].failed && !outcomes[0].recorded);
        assert!(
            outcomes[0]
                .text
                .starts_with("the log ends during \"Taking control of the other processors\""),
            "{}",
            outcomes[0].text
        );
        assert!(outcomes[1].failed);
        assert!(outcomes[2].failed && outcomes[2].recorded);
        assert!(
            outcomes[2]
                .text
                .starts_with("stopped in \"Reading the boot files\" at 28.1 s")
        );

        let rendered = render(&log, Shown::default());
        // Private identifiers are shortened; the boot's own lines stay.
        assert!(!rendered.contains("5E1A0000-0000-4000-8000-0000000000C0"));
        assert!(rendered.contains("CHOSEN DISK ..1276:..00C0"), "{rendered}");
        assert!(rendered.contains("serial=..6789"), "{rendered}");
        assert!(
            rendered.contains("# Boot 1: FAILED: the log ends during"),
            "{rendered}"
        );
        assert!(rendered.contains("OUTCOME (from stela boot-log) the log ends during"));
        // The boot that recorded its outcome gets no second one.
        assert_eq!(rendered.matches("OUTCOME").count(), 3, "{rendered}");

        let last = render(
            &log,
            Shown {
                last: true,
                failed: false,
            },
        );
        assert!(
            last.starts_with(&format!("{}\n# Boot 3: FAILED", "#".repeat(80))),
            "{last}"
        );
        assert_eq!(last.matches("# Boot ").count(), 1);
        // A clean boot is left out of the failures.
        let clean =
            boot_log::read(&region(&["[ 1.000] STEP  A\n[ 2.000] OK    A (1 ms)\n"])).unwrap();
        assert_eq!(
            render(
                &clean,
                Shown {
                    last: false,
                    failed: true
                }
            ),
            ""
        );
        assert!(
            render(&clean, Shown::default()).contains("# Boot 1: ended: the log ends after \"A\"")
        );
    }
}
