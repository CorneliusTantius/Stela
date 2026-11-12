//! Copy selected guest files out of a decrypted Apple disk image.
//!
//! The image is attached read-only through `hdiutil` under a private mount root
//! and always detached afterwards. Guest paths resolve inside the selected
//! volume without following symbolic links out of it.
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use serde_json::json;
use std::{
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

const HDIUTIL: &str = "/usr/bin/hdiutil";
const MAX_SYMLINKS: usize = 32;

/// Guest files to copy; optional paths may be missing from the image.
pub struct Selection {
    pub required: Vec<String>,
    pub optional: Vec<String>,
    pub volume: Option<String>,
}

/// One attached image; detaches on drop.
struct Attachment {
    device: String,
    mounts: Vec<PathBuf>,
}

impl Attachment {
    fn new(image: &Path, mount_root: &Path) -> Result<Self> {
        let output = Command::new(HDIUTIL)
            .arg("attach")
            .arg(image)
            .args(["-readonly", "-nobrowse", "-noautoopen", "-noautofsck"])
            .args(["-mount", "required", "-plist", "-mountroot"])
            .arg(mount_root)
            .output()
            .with_context(|| format!("cannot run {HDIUTIL}"))?;
        ensure!(
            output.status.success(),
            "hdiutil attach failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let plist = Value::from_reader(std::io::Cursor::new(output.stdout))?;
        let entities = plist
            .as_dictionary()
            .and_then(|root| root.get("system-entities"))
            .and_then(Value::as_array)
            .context("hdiutil reported no system entities")?;
        let field = |entity: &Value, key: &str| {
            entity
                .as_dictionary()
                .and_then(|entity| entity.get(key))
                .and_then(Value::as_string)
                .map(str::to_owned)
        };
        // The whole-disk entity is the shortest device node.
        let device = entities
            .iter()
            .filter_map(|entity| field(entity, "dev-entry"))
            .min_by_key(String::len)
            .context("hdiutil reported no device")?;
        let mounts = entities
            .iter()
            .filter_map(|entity| field(entity, "mount-point"))
            .map(PathBuf::from)
            .collect();
        Ok(Self { device, mounts })
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        // Its "ejected" line is not the caller's output.
        let detached = Command::new(HDIUTIL)
            .args(["detach", &self.device])
            .output()
            .is_ok_and(|output| output.status.success());
        if !detached {
            warning!("could not detach {}", self.device);
        }
    }
}

/// Resolve `guest` (absolute) inside `volume`, following symbolic links only
/// while they stay inside it.
fn resolve(volume: &Path, guest: &str) -> Result<PathBuf> {
    ensure!(
        guest.starts_with('/'),
        "guest path {guest} must be absolute"
    );
    let mut pending: Vec<String> = guest
        .split('/')
        .filter(|part| !part.is_empty())
        .rev()
        .map(str::to_owned)
        .collect();
    let mut resolved = PathBuf::new();
    let mut links = 0;
    while let Some(part) = pending.pop() {
        match part.as_str() {
            "." => continue,
            ".." => {
                resolved.pop();
                continue;
            }
            _ => {}
        }
        let candidate = resolved.join(&part);
        let host = volume.join(&candidate);
        let metadata = fs::symlink_metadata(&host)
            .with_context(|| format!("{guest} is missing from the image"))?;
        if !metadata.file_type().is_symlink() {
            resolved = candidate;
            continue;
        }
        links += 1;
        ensure!(links <= MAX_SYMLINKS, "{guest} has too many symbolic links");
        let target = fs::read_link(&host)?;
        if target.is_absolute() {
            resolved = PathBuf::new();
        }
        for component in target.components().rev() {
            match component {
                Component::Normal(name) => pending.push(name.to_string_lossy().into_owned()),
                Component::ParentDir => pending.push("..".into()),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
    }
    let host = volume.join(&resolved);
    ensure!(
        fs::metadata(&host)?.is_file(),
        "{guest} is not a regular file"
    );
    Ok(host)
}

/// One guest file copied out of an image.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Copied {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// What [`copy_into`] copied from one image.
#[derive(Debug)]
pub struct Extraction {
    /// The mounted volume's name.
    pub volume: Option<String>,
    pub files: Vec<Copied>,
    pub missing_optional: Vec<String>,
}

/// The selection's volume among the image's mounts: the named one, the only
/// one, or the only one that holds every required path.
fn select_volume<'a>(mounts: &'a [PathBuf], selection: &Selection) -> Result<&'a Path> {
    if let Some(name) = &selection.volume {
        return mounts
            .iter()
            .find(|mount| mount.file_name().is_some_and(|file| file == name.as_str()))
            .map(PathBuf::as_path)
            .with_context(|| format!("no mounted volume named {name}"));
    }
    if let [volume] = mounts {
        return Ok(volume);
    }
    let holds = |volume: &Path| {
        selection
            .required
            .iter()
            .all(|path| resolve(volume, path).is_ok())
    };
    let mut holding = mounts.iter().filter(|volume| holds(volume));
    match (holding.next(), holding.next()) {
        (Some(volume), None) if !selection.required.is_empty() => Ok(volume),
        _ => bail!(
            "image mounts {} volumes; select one with --volume",
            mounts.len()
        ),
    }
}

/// Copy the selection from `image` into the directory `root`, keeping guest
/// paths; no file there is replaced.
pub fn copy_into(image: &Path, root: &Path, selection: &Selection) -> Result<Extraction> {
    let mount_root = tempfile::tempdir()?;
    let attachment = Attachment::new(image, mount_root.path())?;
    let volume = select_volume(&attachment.mounts, selection)?.to_path_buf();
    let volume = volume.as_path();
    let paths: Vec<(String, bool)> = selection
        .required
        .iter()
        .map(|path| (path.clone(), true))
        .chain(selection.optional.iter().map(|path| (path.clone(), false)))
        .collect();
    let mut files = vec![];
    let mut missing = vec![];
    for (guest, required) in paths {
        let source = match resolve(volume, &guest) {
            Ok(source) => source,
            Err(_) if !required => {
                missing.push(guest);
                continue;
            }
            Err(error) => return Err(error),
        };
        let destination = root.join(guest.trim_start_matches('/'));
        ensure!(
            !destination.try_exists()?,
            "{} exists",
            destination.display()
        );
        fs::create_dir_all(destination.parent().context("guest path has no parent")?)?;
        fs::copy(&source, &destination)
            .with_context(|| format!("cannot copy {guest} out of the image"))?;
        let (bytes, sha256) = super::payload::file_sha256(&destination)?;
        files.push(Copied {
            path: guest,
            bytes,
            sha256,
        });
    }
    let volume = volume
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    drop(attachment);
    Ok(Extraction {
        volume,
        files,
        missing_optional: missing,
    })
}

/// Copy the selection from `image` into the new directory `output`, keeping
/// guest paths, and return a receipt of every copied file.
pub fn extract(image: &Path, output: &Path, selection: &Selection) -> Result<serde_json::Value> {
    ensure!(!output.exists(), "{} exists", output.display());
    let copy = copy_into(image, output, selection)?;
    let receipt = json!({
        "kind": "guest_file_extraction",
        "image": image.canonicalize()?,
        "volume": copy.volume,
        "files": copy.files,
        "missing_optional": copy.missing_optional,
    });
    fs::create_dir_all(output)?;
    fs::write(output.join("receipt.json"), format!("{receipt:#}\n"))?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn guest_paths_follow_links_only_inside_the_volume() -> Result<()> {
        use std::os::unix::fs::symlink;
        let volume = tempfile::tempdir()?;
        let root = volume.path();
        fs::create_dir_all(root.join("usr/lib"))?;
        fs::write(root.join("usr/lib/libz.dylib"), b"z")?;
        symlink("libz.dylib", root.join("usr/lib/libz.1.dylib"))?;
        symlink("/usr/lib", root.join("lib"))?;
        symlink("../../../../etc/passwd", root.join("usr/lib/escape"))?;
        assert_eq!(
            resolve(root, "/usr/lib/libz.1.dylib")?,
            root.join("usr/lib/libz.dylib")
        );
        assert_eq!(
            resolve(root, "/lib/libz.dylib")?,
            root.join("usr/lib/libz.dylib")
        );
        assert!(resolve(root, "/usr/lib/escape").is_err());
        assert!(resolve(root, "usr/lib/libz.dylib").is_err());
        assert!(resolve(root, "/usr/lib").is_err());
        Ok(())
    }

    #[test]
    fn volume_selection_follows_preboot_target() -> Result<()> {
        let image = tempfile::tempdir()?;
        let data = image.path().join("Data");
        let system = image.path().join("Macintosh HD");
        fs::create_dir_all(data.join("Users"))?;
        fs::create_dir_all(system.join("usr/lib"))?;
        fs::write(system.join("usr/lib/dyld"), b"dyld")?;
        let mounts = [data.clone(), system.clone()];
        let selection = |required: &[&str], volume: Option<&str>| Selection {
            required: required.iter().map(|path| path.to_string()).collect(),
            optional: vec![],
            volume: volume.map(str::to_owned),
        };
        assert_eq!(
            select_volume(&mounts, &selection(&["/usr/lib/dyld"], None))?,
            system
        );
        assert_eq!(select_volume(&mounts, &selection(&[], Some("Data")))?, data);
        assert!(select_volume(&mounts, &selection(&[], None)).is_err());
        assert!(select_volume(&mounts, &selection(&["/missing"], None)).is_err());
        assert_eq!(select_volume(&mounts[..1], &selection(&[], None))?, data);
        Ok(())
    }
}
