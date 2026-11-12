//! `STELA_BUILD`: the source revision `stela.efi` is built from, its first
//! 12 hex digits, which the boot's header block names so a log matches a
//! build. `unknown` when the source is not a Git checkout or Git is absent.
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
}

fn main() {
    let build = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=STELA_BUILD={build}");
    // Built again when HEAD moves: the files that name it.
    for path in ["HEAD", "packed-refs"] {
        if let Some(path) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(head) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(&["rev-parse", "--git-path", &head])
    {
        println!("cargo:rerun-if-changed={path}");
    }
}
