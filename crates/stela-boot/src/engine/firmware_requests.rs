//! The firmware the host drivers ask for. When a driver finds a file the
//! USB lacks, the boot log names each such file once and then holds the
//! boot's complete request inventory on one line
//! (`stela_loader::host_firmware::requirements::LOG_LINE`), which
//! `stela setup repair` and `update stela` read to add the pinned files.
//! The device that needed the file stays off, as its driver reports.
use crate::output;
use alloc::{boxed::Box, string::String};
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use stela_drivers::firmware::{Error, Image, Provider, Requirement};
use stela_loader::host_firmware::{recipes, requirements::RecordingProvider};

/// What the screen says once a driver found a file missing that setup has
/// a pinned source for.
pub const MISSING: &str = "Firmware this PC's devices need is missing from the USB, so they \
    stay off: running `stela setup repair --usb USB` on a computer with internet adds it.";

/// Every firmware request of the boot's host drivers, which reach it only
/// through the host drivers' lock (`storage::RestoreRoot`).
pub struct Requests {
    recorder: RecordingProvider<'static>,
    /// How many missing files the log names.
    reported: AtomicUsize,
    /// Whether setup has a pinned source for one of them.
    fixable: AtomicBool,
}

impl Requests {
    /// Record every request to `inner` for the rest of the boot.
    pub fn new(inner: &'static dyn Provider) -> &'static Self {
        Box::leak(Box::new(Self {
            recorder: RecordingProvider::new(inner),
            reported: AtomicUsize::new(0),
            fixable: AtomicBool::new(false),
        }))
    }

    /// Name each file found missing since the last report, then log the
    /// complete inventory. Call while holding the host drivers' lock.
    pub fn report(&self) {
        if let Some(text) = self.take_report() {
            output::arguments(format_args!("{text}"));
        }
    }

    /// The text [`Self::report`] prints, built while holding the host
    /// drivers' lock, which the recorder needs; printed after it is
    /// released, as a long inventory line would hold every other core's
    /// driver call while it is written. `None` with nothing new missing.
    pub fn take_report(&self) -> Option<String> {
        let reported = self.reported.load(Ordering::Relaxed);
        let missing = self.recorder.missing_count();
        if missing <= reported {
            return None;
        }
        let mut text = String::new();
        for request in self.recorder.missing_since(reported) {
            let pinned = recipes::recipe(&request).is_some();
            let _ = writeln!(
                text,
                "HOST FIRMWARE MISSING {}{}",
                request.name,
                if pinned { "" } else { " (no pinned source)" }
            );
            if pinned {
                self.fixable.store(true, Ordering::Relaxed);
            }
        }
        let _ = writeln!(text, "{}", self.recorder.log_line());
        self.reported.store(missing, Ordering::Relaxed);
        Some(text)
    }

    /// Whether a report named a missing file setup can add.
    pub fn missing(&self) -> bool {
        self.fixable.load(Ordering::Relaxed)
    }
}

impl Provider for Requests {
    fn load(&self, requirement: Requirement<'_>) -> Result<Image<'_>, Error> {
        self.recorder.load(requirement)
    }
}
