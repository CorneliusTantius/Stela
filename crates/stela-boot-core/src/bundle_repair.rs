//! The automatic repair of a missing Metal plugin, `StelaGPU.bundle` in
//! `/Library/GPUBundles` on the Data volume.
//!
//! The StelaGPU kext writes the plugin's files from the copy it carries, but
//! the kernel gives a kext no way to create a directory (`files.h`), so on a
//! freshly installed system, whose Data volume holds only Apple's empty
//! `/Library/GPUBundles`, it reports the plugin missing. Nothing else can
//! create them before the first boot: the Data volume is encrypted, Stela's
//! APFS code only reads, and the restore runs Apple's own programs. A root
//! process of a normal boot is refused too: `/Library/GPUBundles` is
//! restricted, and the GPU policy's SIP grant keeps filesystem protection on.
//!
//! So a normal boot that finds the plugin missing records
//! [`BUNDLE_REPAIR_PENDING`] in NVRAM at its stop and restarts. The loader
//! turns that into one single-user boot with filesystem protection off
//! (`--bundle-repair`) and records [`BUNDLE_REPAIR_ATTEMPTED`] before it
//! boots, so neither a failure nor a power loss in the middle repeats the
//! repair by itself. In that boot the engine types [`steps`] at the guest's
//! root console ([`Driver`]), as the manual remedy does: it mounts the Data
//! volume, creates the plugin's directories root-owned, 0755, with the
//! `KernelExtensionManagement` rootless class and the restricted flag, and
//! restarts. The next boot's kext then creates the files in place. A boot
//! that finds the plugin installed removes the record; one that finds it
//! missing after an attempt stops with the manual remedy ([`decide`]).
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use stela_loader::boot_selection::{
    BUNDLE_REPAIR, BUNDLE_REPAIR_ATTEMPTED, BUNDLE_REPAIR_PENDING, lookup,
};
use stela_soc_data::nor::nvram::{Partition, Variables};

/// The plugin's parent on the Data volume, as the kext looks for it.
pub const PLUGINS: &str = "/System/Volumes/Data/Library/GPUBundles";

/// The plugin's directories, parents first: the bundle layout
/// `cargo xtask guest` builds (`Contents/Info.plist`,
/// `Contents/MacOS/StelaGPU`), whose files the kext writes.
pub const DIRECTORIES: [&str; 3] = [
    "StelaGPU.bundle",
    "StelaGPU.bundle/Contents",
    "StelaGPU.bundle/Contents/MacOS",
];

/// What the kext found of the plugin (the gate's `BUNDLE` report).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    Current,
    Updated,
    Missing,
    Failed,
}

/// Which boot reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boot {
    /// A multi-user boot, whose Metal clients need the plugin.
    Normal,
    /// A single-user boot an operator asked for (`--single-user`).
    SingleUser,
    /// The automatic repair's maintenance boot (`--bundle-repair`).
    Repair,
}

/// [`BUNDLE_REPAIR`] as NVRAM holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    None,
    Pending,
    Attempted,
    /// A value Stela never writes.
    Other,
}

impl Record {
    pub fn read(variables: &Variables) -> Self {
        match lookup(variables, BUNDLE_REPAIR)
            .map(|value| value.strip_suffix(b"\0").unwrap_or(value))
        {
            None => Self::None,
            Some(BUNDLE_REPAIR_PENDING) => Self::Pending,
            Some(BUNDLE_REPAIR_ATTEMPTED) => Self::Attempted,
            Some(_) => Self::Other,
        }
    }
}

/// What NVRAM's record becomes at the stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Ask the next boot to repair.
    Request,
    /// The plugin is installed: forget any repair.
    Forget,
}

impl Change {
    /// Apply to `variables`; whether they changed, when the bank must be
    /// saved.
    pub fn apply(self, variables: &mut Variables) -> Result<bool, String> {
        match self {
            Self::Request => {
                if Record::read(variables) == Record::Pending {
                    return Ok(false);
                }
                variables
                    .set(Partition::System, BUNDLE_REPAIR, BUNDLE_REPAIR_PENDING)
                    .map_err(|error| format!("{error:?}"))?;
                Ok(true)
            }
            Self::Forget => {
                let mut changed = false;
                for partition in [Partition::System, Partition::Common] {
                    changed |= variables.remove(partition, BUNDLE_REPAIR).is_some();
                }
                Ok(changed)
            }
        }
    }
}

/// What the engine does with a report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The plugin is in place: boot on, applying the change at the stop.
    Continue(Option<Change>),
    /// A single-user boot logs the report; its console may install it.
    Log,
    /// Record the request and restart into the repair.
    Repair,
    /// Stop with the manual remedy; `attempted` when the automatic repair
    /// already ran and did not help, or cannot run.
    StopMissing { attempted: bool },
    /// The kext failed to write the plugin; its lines say why.
    StopFailed,
}

/// Decide what `report` means for `boot`, given NVRAM's `record` and
/// whether this boot can write NVRAM at its stop (`persistent`).
pub fn decide(report: Report, boot: Boot, record: Record, persistent: bool) -> Decision {
    match (report, boot) {
        (Report::Current | Report::Updated, _) => {
            Decision::Continue((record != Record::None).then_some(Change::Forget))
        }
        (Report::Missing | Report::Failed, Boot::SingleUser | Boot::Repair) => Decision::Log,
        (Report::Failed, Boot::Normal) => Decision::StopFailed,
        (Report::Missing, Boot::Normal) => match record {
            Record::None | Record::Other if persistent => Decision::Repair,
            // A pending request this boot did not take means NVRAM was not
            // read for it; another request would loop.
            Record::None | Record::Other | Record::Pending => {
                Decision::StopMissing { attempted: false }
            }
            Record::Attempted => Decision::StopMissing { attempted: true },
        },
    }
}

/// One console command and the seconds it may take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub command: String,
    pub seconds: u64,
}

/// The repair's commands, in order, each answered by its exit status.
pub fn steps() -> Vec<Step> {
    let directories = DIRECTORIES
        .iter()
        .map(|directory| format!("{PLUGINS}/{directory}"))
        .collect::<Vec<_>>()
        .join(" ");
    let step = |command: String, seconds| Step { command, seconds };
    Vec::from([
        // The Data volume, as the single-user banner says for a machine
        // with a SEP.
        step("/sbin/mount -P 1".into(), 120),
        step("/usr/libexec/init_data_protection".into(), 180),
        step("/sbin/mount -P 2".into(), 180),
        step(format!("/bin/test -d {PLUGINS}"), 30),
        // Each named last, so `-m` gives each its mode.
        step(format!("/bin/mkdir -p -m 0755 {directories}"), 30),
        step(format!("/usr/sbin/chown root:wheel {directories}"), 30),
        step(
            format!("/usr/bin/xattr -w com.apple.rootless KernelExtensionManagement {directories}"),
            30,
        ),
        step(format!("/usr/bin/chflags restricted {directories}"), 30),
        step("/bin/sync".into(), 120),
    ])
}

/// The command that ends the repair; the guest's restart restarts the PC.
pub const REBOOT: &str = "/sbin/reboot";
/// The line the single-user shell's banner starts with.
pub const BANNER: &str = "*** Single-user boot ***";
/// How long the single-user banner may take to appear, from the start.
pub const BANNER_SECONDS: u64 = 1800;
/// How long to wait after the banner before the first command: launchd
/// starts the shell after it, and input before the shell reads may be
/// flushed.
pub const SETTLE_SECONDS: u64 = 5;
/// How long the guest may take to restart after [`REBOOT`].
pub const RESTART_SECONDS: u64 = 300;

/// Why the repair failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// No single-user banner in time.
    NoShell,
    /// Step `index` printed no exit status in time.
    Timeout { index: usize },
    /// Step `index` exited with `status`.
    Exit { index: usize, status: u32 },
    /// The guest did not restart after the repair.
    NoRestart,
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoShell => write!(f, "no single-user shell within {BANNER_SECONDS} s"),
            Self::Timeout { index } => {
                write!(f, "step {} printed no exit status in time", index + 1)
            }
            Self::Exit { index, status } => {
                write!(f, "step {} exited with status {status}", index + 1)
            }
            Self::NoRestart => write!(f, "macOS did not restart within {RESTART_SECONDS} s"),
        }
    }
}

/// What the driver did, for the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Shell,
    Sent { index: usize, command: String },
    Passed { index: usize },
    Rebooting,
    Failed(Failure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Banner { deadline: u64 },
    Settle { until: u64 },
    Step { index: usize, deadline: u64 },
    Rebooting { deadline: u64 },
    Failed,
}

/// Types [`steps`] at the guest's console, one at a time, each followed by
/// an `echo` of its exit status under a marker, and goes on only when that
/// line says 0. Times are milliseconds on any monotonic clock.
pub struct Driver {
    steps: Vec<Step>,
    state: State,
    input: Vec<u8>,
    sent: usize,
    events: Vec<Event>,
}

const MILLIS: u64 = 1000;

impl Driver {
    pub fn new(steps: Vec<Step>, now: u64) -> Self {
        Self {
            steps,
            state: State::Banner {
                deadline: now + BANNER_SECONDS * MILLIS,
            },
            input: Vec::new(),
            sent: 0,
            events: Vec::new(),
        }
    }

    fn marker(index: usize) -> String {
        format!("STELA-REPAIR-{}-rc=", index + 1)
    }

    fn send(&mut self, index: usize, now: u64) {
        let step = &self.steps[index];
        let line = format!("{}; echo {}$?\n", step.command, Self::marker(index));
        self.input.extend_from_slice(line.as_bytes());
        self.events.push(Event::Sent {
            index,
            command: step.command.clone(),
        });
        self.state = State::Step {
            index,
            deadline: now + step.seconds * MILLIS,
        };
    }

    fn fail(&mut self, failure: Failure) {
        self.events.push(Event::Failed(failure));
        self.state = State::Failed;
    }

    /// A complete line the guest's console printed.
    pub fn line(&mut self, text: &str, now: u64) {
        match self.state {
            State::Banner { .. } if text.contains(BANNER) => {
                self.events.push(Event::Shell);
                self.state = State::Settle {
                    until: now + SETTLE_SECONDS * MILLIS,
                };
            }
            State::Step { index, .. } => {
                let marker = Self::marker(index);
                // The shell's echo of the command holds the marker before
                // `$?`; only the `echo`'s output has digits after it.
                let Some(at) = text.find(&marker) else {
                    return;
                };
                let digits: String = text[at + marker.len()..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                let Ok(status) = digits.parse::<u32>() else {
                    return;
                };
                if status != 0 {
                    return self.fail(Failure::Exit { index, status });
                }
                self.events.push(Event::Passed { index });
                self.advance(index + 1, now);
            }
            _ => {}
        }
    }

    /// Send step `index`, or after the last, the restart.
    fn advance(&mut self, index: usize, now: u64) {
        if index < self.steps.len() {
            return self.send(index, now);
        }
        self.input.extend_from_slice(REBOOT.as_bytes());
        self.input.push(b'\n');
        self.events.push(Event::Rebooting);
        self.state = State::Rebooting {
            deadline: now + RESTART_SECONDS * MILLIS,
        };
    }

    /// Advance the clock: the settle's end and every deadline.
    pub fn tick(&mut self, now: u64) {
        match self.state {
            State::Banner { deadline } if now >= deadline => self.fail(Failure::NoShell),
            State::Settle { until } if now >= until => self.advance(0, now),
            State::Step { index, deadline } if now >= deadline => {
                self.fail(Failure::Timeout { index })
            }
            State::Rebooting { deadline } if now >= deadline => self.fail(Failure::NoRestart),
            _ => {}
        }
    }

    /// The next byte to type, if any. A failed repair types nothing more.
    pub fn next_byte(&mut self) -> Option<u8> {
        if self.state == State::Failed {
            return None;
        }
        let byte = *self.input.get(self.sent)?;
        self.sent += 1;
        if self.sent == self.input.len() {
            self.input.clear();
            self.sent = 0;
        }
        Some(byte)
    }

    /// What happened since the last call.
    pub fn take_events(&mut self) -> Vec<Event> {
        core::mem::take(&mut self.events)
    }

    /// Whether the repair failed.
    pub fn failed(&self) -> bool {
        self.state == State::Failed
    }
}

/// The log line for `event`.
pub fn describe(event: &Event) -> String {
    match event {
        Event::Shell => "BUNDLE REPAIR single-user shell up".to_string(),
        Event::Sent { index, command } => {
            format!("BUNDLE REPAIR step {} sent: {command}", index + 1)
        }
        Event::Passed { index } => format!("BUNDLE REPAIR step {} ok", index + 1),
        Event::Rebooting => "BUNDLE REPAIR directories created; restarting".to_string(),
        Event::Failed(failure) => format!("BUNDLE REPAIR failed: {failure}"),
    }
}

#[cfg(test)]
mod tests;
