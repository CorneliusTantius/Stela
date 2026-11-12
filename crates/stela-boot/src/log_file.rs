//! The USB's own boot log, [`BOOT_LOG_FILE`] beside Stela on its volume,
//! which `stela setup` preallocates: the loader writes it through the
//! firmware's file system from its first line until boot services end
//! ([`open`]), and the system engine writes on to the same clusters, wherever
//! they lie, through Stela's own drivers ([`resume`]), so the stick keeps the
//! whole run.
use crate::Result;
use crate::{
    engine::{bundle::Bytes, translations},
    output::{self, Log},
    status,
};
use alloc::{boxed::Box, format, string::String};
use stela_contracts::refuse;
use stela_drivers::block::{BlockDevice, BlockError, Features, Identity, Shared, Transport};
use stela_loader::mount_interface::{BOOT_LOG_FILE, OLD_BOOT_LOG_FILE};
use stela_runtime::pc::{
    boot_log::{self, LOG_BYTES, Writer},
    fat32::Fat32,
    gpt::Guid,
};
use uefi::{
    CString16, Handle,
    boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol},
    proto::{
        ProtocolPointer,
        loaded_image::LoadedImage,
        media::{
            file::{Directory, File as _, FileAttribute, FileInfo, FileMode, RegularFile},
            fs::SimpleFileSystem,
        },
    },
};

/// The blocks the firmware's file is addressed in.
const BLOCK: u32 = 512;

/// Open the log on the volume Stela was loaded from, when it has one, and
/// return that partition's GUID, which the system engine opens it by.
pub fn open() -> Option<Guid> {
    status::begin("Opening the boot log on the USB");
    let opened = firmware_file().and_then(|(device, partition)| {
        let mut device: Box<dyn BlockDevice> = Box::new(device);
        let writer = Writer::open(&mut *device)
            .map_err(|error| refuse!("firmware boot log: {error}", %error))?;
        report(&writer, "firmware");
        output::add_log(writer, device, Log::Firmware)
            .map_err(|error| refuse!("firmware boot log output: {error}", %error))?;
        Ok(partition)
    });
    finish(opened).flatten()
}

/// Write on to the loader's log in its file on `partition`, the volume
/// [`open`] found it on.
pub fn resume(partition: Box<dyn BlockDevice>) {
    status::begin("Opening the boot log on the USB again");
    finish(engine_file(partition));
}

/// End the step: the log is kept, or why not, which the boot goes on
/// without.
fn finish<T>(opened: Result<T>) -> Option<T> {
    match opened {
        Ok(value) => {
            status::done(BOOT_LOG_FILE);
            Some(value)
        }
        Err(why) => {
            output::arguments(format_args!("LOG off: {why}\n"));
            status::warn(&format!("not kept: {why}"));
            None
        }
    }
}

fn report(writer: &Writer, through: &str) {
    if let Some(reason) = writer.fresh() {
        output::arguments(format_args!("LOG fresh: {reason}\n"));
    }
    output::arguments(format_args!(
        "LOG {BOOT_LOG_FILE} through the {through}, boot {}, head={:#x}\n",
        writer.boots(),
        writer.head()
    ));
}

/// `handle`'s `P`, shared with whoever else holds it.
fn shared<P: ProtocolPointer + ?Sized>(handle: Handle) -> Option<ScopedProtocol<P>> {
    // SAFETY: used only for queries and file access while boot services
    // run; no driver on `handle` is replaced while it is held.
    unsafe {
        boot::open_protocol::<P>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()
}

fn firmware_file() -> Result<(FileDevice, Option<Guid>)> {
    let device_handle = shared::<LoadedImage>(boot::image_handle())
        .ok_or(refuse!("no loaded image"))?
        .device()
        .ok_or(refuse!("Stela was not loaded from a volume"))?;
    let mut volume = shared::<SimpleFileSystem>(device_handle)
        .ok_or(refuse!("Stela's volume has no file system"))?;
    let mut root = volume
        .open_volume()
        .map_err(|_| refuse!("Stela's volume cannot be opened"))?;
    let path =
        CString16::try_from(BOOT_LOG_FILE).map_err(|_| refuse!("the log's path is not UCS-2"))?;
    let mut file = root
        .open(&path, FileMode::ReadWrite, FileAttribute::empty())
        .ok()
        .and_then(|file| file.into_regular_file())
        .ok_or(refuse!("Stela's volume has no \\EFI\\stela\\boot.log"))?;
    let size = file
        .get_boxed_info::<FileInfo>()
        .map_err(|_| refuse!("the log file's size cannot be read"))?
        .file_size();
    if size < LOG_BYTES {
        return Err(refuse!("\\EFI\\stela\\boot.log is shorter than the log"));
    }
    let mut device = FileDevice {
        identity: file_identity(),
        file,
    };
    keep_older_format(&mut device, &mut root);
    Ok((device, translations::partition(device_handle).map(Guid)))
}

/// Keep the log when it is of an earlier format, which [`Writer::open`]
/// starts over: as [`OLD_BOOT_LOG_FILE`], byte for byte, replacing an older
/// one. A refusal is one note, and the log starts over all the same.
fn keep_older_format(device: &mut FileDevice, root: &mut Directory) {
    let older = match boot_log::older_format(device) {
        Ok(Some(older)) => older,
        Ok(None) => return,
        Err(error) => {
            status::info(&format!(
                "The USB's boot log could not be read to keep it before it starts over: {error}."
            ));
            return;
        }
    };
    let (version, region) = older;
    match write_file(root, OLD_BOOT_LOG_FILE, &region) {
        Ok(()) => output::arguments(format_args!(
            "LOG kept the format {version} log as {OLD_BOOT_LOG_FILE} ({}) before starting \
             {BOOT_LOG_FILE} over\n",
            stela_boot_core::log_style::size(region.len() as u64)
        )),
        Err(why) => status::info(&format!(
            "The USB's earlier boot log (format {version}) could not be kept as \
             {OLD_BOOT_LOG_FILE}: {why}. It is started over."
        )),
    }
}

/// Make `path` hold exactly `bytes`, replacing the file that was there.
fn write_file(root: &mut Directory, path: &str, bytes: &[u8]) -> Result<(), &'static str> {
    let path = CString16::try_from(path).map_err(|_| "its path is not UCS-2")?;
    if let Ok(old) = root.open(&path, FileMode::ReadWrite, FileAttribute::empty()) {
        old.delete()
            .map_err(|_| "the firmware refused to remove the older copy")?;
    }
    let mut file = root
        .open(&path, FileMode::CreateReadWrite, FileAttribute::empty())
        .ok()
        .and_then(|file| file.into_regular_file())
        .ok_or("the firmware refused to create the file")?;
    for chunk in bytes.chunks(64 << 10) {
        file.write(chunk)
            .map_err(|_| "the firmware refused a write")?;
    }
    file.flush()
        .map_err(|_| "the firmware refused to store the file")
}

/// The log file as a device of [`BLOCK`]-byte blocks.
fn file_identity() -> Identity {
    Identity {
        transport: Transport::Firmware,
        location: String::from(BOOT_LOG_FILE),
        model: String::new(),
        serial: String::new(),
        blocks: LOG_BYTES / u64::from(BLOCK),
        block_size: BLOCK,
        read_only: false,
        // The firmware's file system may hold writes until a flush.
        features: Features {
            write_cache: true,
            ..Features::default()
        },
    }
}

fn engine_file(partition: Box<dyn BlockDevice>) -> Result<()> {
    let block = u64::from(partition.identity().block_size);
    let mut volume = Fat32::open(Bytes::new(partition))
        .map_err(|error| refuse!("boot log volume: {error}", %error))?;
    let file = volume
        .file(&BOOT_LOG_FILE.replace('\\', "/"))
        .map_err(|error| refuse!("boot log file: {error}", %error))?;
    let runs = boot_log::file_runs(&file, block, LOG_BYTES)
        .map_err(|error| refuse!("boot log file runs: {error}", %error))?;
    let partition = volume.into_inner().into_inner();
    let mut device: Box<dyn BlockDevice> = Box::new(
        Shared::new(partition)
            .runs(runs)
            .map_err(|error| refuse!("boot log device: {error}", %error))?,
    );
    let writer = Writer::resume(&mut *device)
        .map_err(|error| refuse!("boot log resume: {error}", %error))?;
    report(&writer, "USB driver");
    output::add_log(writer, device, Log::Usb)
        .map_err(|error| refuse!("USB boot log output: {error}", %error))
}

/// The log file as blocks, through the firmware's file system.
struct FileDevice {
    identity: Identity,
    file: RegularFile,
}

impl FileDevice {
    fn seek(&mut self, lba: u64, bytes: usize) -> Result<(), BlockError> {
        if !bytes.is_multiple_of(BLOCK as usize) {
            return Err(BlockError::Misaligned {
                bytes,
                block_size: BLOCK,
            });
        }
        let blocks = (bytes / BLOCK as usize) as u64;
        if lba.saturating_add(blocks) > self.identity.blocks {
            return Err(BlockError::OutOfRange {
                lba,
                blocks,
                capacity: self.identity.blocks,
            });
        }
        self.file
            .set_position(lba * u64::from(BLOCK))
            .map_err(|error| failed(error.status()))
    }
}

fn failed(status: uefi::Status) -> BlockError {
    BlockError::Device {
        status: status.0 as u32,
    }
}

impl BlockDevice for FileDevice {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.seek(lba, buffer.len())?;
        let mut done = 0;
        while done < buffer.len() {
            match self.file.read(&mut buffer[done..]) {
                Ok(0) => return Err(failed(uefi::Status::END_OF_FILE)),
                Ok(count) => done += count,
                Err(error) => return Err(failed(error.status())),
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.seek(lba, data.len())?;
        self.file
            .write(data)
            .map_err(|error| failed(error.status()))
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        self.file.flush().map_err(|error| failed(error.status()))
    }
}
