//! The `stela` command line prepares a USB that boots Stela to install macOS
//! on a PC and reads the boot log. Research and development commands belong to
//! `stela-dev`, which uses this library's boot-bundle and restore-image tools.
use clap::{Parser, Subcommand};
use std::process::ExitCode;

/// A message beside the command's progress, in one of three forms on
/// standard error: `note:` (something to know, the command goes on),
/// `warning:` (something may be wrong, the command goes on) and `error:`
/// (the command stopped; [`main`] prints it, ending with the command that
/// fixes it when there is one). The label is coloured only on a terminal
/// that takes colour.
pub(crate) fn say(label: Label, text: std::fmt::Arguments<'_>) {
    eprintln!("{} {text}", label.styled());
}

/// The three message labels ([`say`]).
#[derive(Clone, Copy)]
pub(crate) enum Label {
    Note,
    Warning,
    Error,
}

impl Label {
    fn styled(self) -> console::StyledObject<&'static str> {
        let (text, color) = match self {
            Label::Note => ("note:", console::Color::Cyan),
            Label::Warning => ("warning:", console::Color::Yellow),
            Label::Error => ("error:", console::Color::Red),
        };
        console::style(text).for_stderr().fg(color).bold()
    }
}

/// `note!(...)`: [`say`] with [`Label::Note`], formatted as `format!`.
macro_rules! note {
    ($($arg:tt)*) => {
        $crate::say($crate::Label::Note, format_args!($($arg)*))
    };
}

/// `warning!(...)`: [`say`] with [`Label::Warning`].
macro_rules! warning {
    ($($arg:tt)*) => {
        $crate::say($crate::Label::Warning, format_args!($($arg)*))
    };
}

pub mod apfs;
pub mod args;
pub mod boot;
mod boot_log;
pub mod efi;
pub use stela_gpu_maintenance as gpu;
mod net;
mod progress;
pub mod restore;
mod setup;

pub use setup::InstallMedium;

/// The help's examples, with this computer's spelling of a whole disk.
fn examples() -> String {
    let disk = setup::host::DISK_EXAMPLE;
    format!(
        "Examples:
  stela setup                       Create a macOS installer USB, step by step
  stela setup --usb {disk:<15} Erase that USB and write the installer, downloading macOS
  stela setup status --usb VOLUME   Check an installer USB by its mounted STELA volume"
    )
}
const ABOUT: &str = "Prepare a USB that boots Stela to install macOS on a PC";

#[derive(Parser)]
#[command(
    name = "stela",
    version,
    about = ABOUT,
    after_help = examples(),
    arg_required_else_help = true
)]
#[cfg_attr(
    windows,
    allow(
        dead_code,
        reason = "Windows runs Installer directly; the shared command grammar remains covered by tests"
    )
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[cfg_attr(
    windows,
    allow(
        dead_code,
        reason = "Windows runs Installer directly; the shared command grammar remains covered by tests"
    )
)]
pub(crate) enum Command {
    /// Create a macOS installer USB interactively, or manage an existing USB.
    Setup(Box<setup::Setup>),
    /// Print every boot log stela.efi kept: without FILE, the USB's own log
    /// and each install's, read straight from this computer's disks; with
    /// FILE, those on a disk image, device, raw partition or boot.log copy.
    BootLog(boot_log::BootLog),
}

// Windows ships the direct installer; other hosts expose these subcommands.
#[cfg_attr(
    windows,
    allow(
        dead_code,
        reason = "Windows runs Installer directly; the shared command grammar remains covered by tests"
    )
)]
impl Command {
    fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Setup(command) => command.run(),
            Self::BootLog(command) => command.run(),
        }
    }
}

/// Parse the command line and run it, reporting errors on stderr.
pub fn main() -> ExitCode {
    #[cfg(windows)]
    let result = installer();
    #[cfg(not(windows))]
    let result = commands();
    let code = match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            say(Label::Error, format_args!("{error:#}"));
            ExitCode::FAILURE
        }
    };
    setup::hold_window(code == ExitCode::SUCCESS);
    code
}

#[cfg(not(windows))]
fn commands() -> anyhow::Result<()> {
    Cli::parse().command.run()
}

/// `stela.exe` is the installer alone: running it opens the setup wizard, and
/// its arguments are `stela setup`'s own flags and commands.
#[cfg(windows)]
#[derive(Parser)]
#[command(name = "stela", version, about = ABOUT)]
struct Installer {
    #[command(flatten)]
    setup: setup::Setup,
}

#[cfg(windows)]
fn installer() -> anyhow::Result<()> {
    Installer::parse_from(installer_arguments(std::env::args_os()))
        .setup
        .run()
}

/// `stela.exe`'s arguments without a leading `setup`, so the `stela setup
/// ...` commands that messages and the docs name work as typed.
#[cfg(any(windows, test))]
fn installer_arguments(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Vec<std::ffi::OsString> {
    let mut arguments: Vec<_> = arguments.into_iter().collect();
    if arguments.get(1).is_some_and(|word| word == "setup") {
        arguments.remove(1);
    }
    arguments
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(words: &[&str]) -> Command {
        Cli::try_parse_from(std::iter::once("stela").chain(words.iter().copied()))
            .unwrap()
            .command
    }

    #[test]
    #[cfg(windows)]
    fn windows_executable_exposes_installer_commands() {
        // No arguments opens the wizard; setup's own flags and commands stay
        // scriptable.
        Installer::command()
            .try_get_matches_from(["stela"])
            .unwrap();
        let scripted = Installer::command()
            .try_get_matches_from(["stela", "--ipsw", "a.ipsw", "--profile"])
            .unwrap();
        assert!(scripted.get_flag("profile") && scripted.contains_id("ipsw"));
        Installer::try_parse_from(["stela", "status", "--usb", "E:\\"]).unwrap();
        Installer::try_parse_from(installer_arguments(
            ["stela", "setup", "status", "--usb", "E:\\"].map(Into::into),
        ))
        .unwrap();
        let help = Installer::command().render_help().to_string();
        assert!(help.contains("status"), "{help}");
        Installer::command().debug_assert();
    }

    #[test]
    fn a_leading_setup_word_is_dropped_for_the_installer() {
        let words =
            |list: &[&str]| -> Vec<std::ffi::OsString> { list.iter().map(Into::into).collect() };
        assert_eq!(
            installer_arguments(words(&["stela", "setup", "status", "--usb", "E:\\"])),
            words(&["stela", "status", "--usb", "E:\\"])
        );
        assert_eq!(installer_arguments(words(&["stela"])), words(&["stela"]));
        assert_eq!(
            installer_arguments(words(&["stela", "--usb", "setup"])),
            words(&["stela", "--usb", "setup"])
        );
    }

    #[test]
    fn help_lists_shipped_commands() {
        let help = Cli::command().render_help().to_string();
        assert!(
            help.contains("setup") && help.contains("boot-log") && !help.contains("\n  gpu"),
            "{help}"
        );
        for command in [
            "compile-block",
            "boot",
            "efi",
            "install-medium",
            "cpu-info",
            "gpu",
        ] {
            assert!(
                Cli::try_parse_from(["stela", command, "--help"]).is_err(),
                "{command}"
            );
        }
        Cli::command().debug_assert();
    }

    #[test]
    fn portable_commands_dispatch() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let missing = directory.path().join("missing.img");
        let error = parse(&["boot-log", missing.to_str().unwrap()])
            .run()
            .unwrap_err();
        assert!(error.to_string().contains("cannot open"), "{error:#}");
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(matches!(
            parse(&["setup", "--usb", missing.to_str().unwrap(), "--dry-run"]),
            Command::Setup(_)
        ));
        Ok(())
    }

    #[test]
    fn setup_without_a_usb_enters_the_wizard_and_preserves_test_options() {
        assert!(matches!(parse(&["setup"]), Command::Setup(_)));
        assert!(matches!(
            parse(&["setup", "--ipsw", "local.ipsw", "--profile"]),
            Command::Setup(_)
        ));
    }

    #[test]
    fn setup_actions_are_subcommands_that_take_only_their_own_options() {
        let usb = ["--usb", "/Volumes/STELA"];
        for words in [
            &["status"][..],
            &["repair", "--ipsw", "a.ipsw", "--erase-target"],
            &["update", "stela", "--efi", "stela.efi"],
            &["update", "os", "--ipsw", "a.ipsw"],
            &["update", "stela", "--fetch"],
            &["uninstall"],
            &["nvram", "next-boot", "recovery", "--install", "macOS"],
            &["nvram", "reset", "--nor", "sdc3"],
            &["state", "backup", "state.bin"],
            &["state", "restore", "state.bin", "--nor", "sdc3"],
            &["boot-log"],
            &["configure", "--no-profile", "--chooser-timeout", "0"],
            &["configure", "--log", "profile"],
            &["host-firmware", "install", "package"],
            &[
                "host-firmware",
                "fetch",
                "requests.json",
                "--cache",
                "cache",
            ],
        ] {
            let line = ["stela", "setup"].into_iter().chain(words.iter().copied());
            Cli::try_parse_from(line.chain(usb))
                .unwrap_or_else(|error| panic!("{words:?}: {error}"));
        }
        // Each action takes neither creation's flags nor another action's.
        for words in [
            &["status", "--target", "sdc2"][..],
            &["uninstall", "--ipsw", "a.ipsw"],
            &["configure", "--profile", "--no-profile"],
            &["configure", "--log", "verbose"],
            &["configure", "--log", "default", "--profile"],
            &["state", "backup", "state.bin", "--chooser-timeout", "0"],
            &["--target", "sdc2", "status"],
            &["status", "repair"],
            &["--fetch"],
            &["update", "os", "--fetch"],
            &["doctor"],
        ] {
            let line = ["stela", "setup"].into_iter().chain(words.iter().copied());
            assert!(Cli::try_parse_from(line.chain(usb)).is_err(), "{words:?}");
        }
    }
}
