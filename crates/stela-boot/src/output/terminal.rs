//! Terminal panic path. The report reaches the serial port first, built
//! without the heap, output queues or callbacks; only then does the boot
//! log get it, through a bounded store ([`super::at_panic`]).
use super::Text;
use crate::serial::Serial;
use core::{
    arch::asm,
    fmt::Write,
    panic::PanicInfo,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
};

/// Whether the hypervisor exit port is written: 0 before CPUID is read,
/// then 1 without a hypervisor and 2 under one.
static EXIT_PORT: AtomicU8 = AtomicU8::new(0);
static PRINTING: AtomicBool = AtomicBool::new(false);
/// The APIC ID of the processor storing the logs after its panic, else
/// [`NO_PROCESSOR`]: a second panic there is the store failing.
static STORING: AtomicU32 = AtomicU32::new(NO_PROCESSOR);
const NO_PROCESSOR: u32 = u32::MAX;

/// The hypervisor exit port ([`stela_boot_core::exit_port`]) under a
/// hypervisor, `None` on a PC without one. CPUID is read once; no
/// queued/logging output is invoked.
pub(super) fn exit_port() -> Option<u16> {
    let present = match EXIT_PORT.load(Ordering::Relaxed) {
        0 => {
            let present =
                stela_boot_core::exit_port::port(core::arch::x86_64::__cpuid(1).ecx).is_some();
            EXIT_PORT.store(1 + u8::from(present), Ordering::Relaxed);
            present
        }
        state => state == 2,
    };
    present.then_some(stela_boot_core::exit_port::PORT)
}

/// Write `code` to the hypervisor exit port, where there is one.
pub(super) fn exit(code: u32) {
    if let Some(port) = exit_port() {
        // SAFETY: the debug-exit port of the hypervisor CPUID reports; a
        // write the hypervisor does not own is discarded.
        unsafe {
            asm!("out dx, eax", in("dx") port, in("eax") code, options(nostack, preserves_flags));
        }
    }
}

/// Write the `STELA STACK` line to the serial port from `stack` on
/// ([`write_stack`]).
///
/// # Safety
/// `stack`'s page reads from `stack` on.
pub(crate) unsafe fn print_stack_at(stack: *const u64) {
    // SAFETY: the caller's.
    unsafe { write_stack(&mut Serial, stack) };
}

/// The stack words that lie in this image, as offsets from its base: the
/// return addresses among them name the caller, as `stela.pdb` resolves them.
/// A release build has no frame pointers to walk. From `stack` to the end
/// of its page, at most 512 words: the page above may be a stack's guard,
/// and a fault here would halt this processor before the failure stops the
/// machine.
///
/// # Safety
/// `stack`'s page reads from `stack` on.
unsafe fn write_stack(out: &mut impl Write, stack: *const u64) {
    const SHOWN: usize = 32;
    let _ = write!(out, "STELA STACK");
    // SAFETY: the caller's.
    for offset in unsafe { image_offsets(stack) }.take(SHOWN) {
        let _ = write!(out, " {offset:#x}");
    }
    let _ = writeln!(out);
}

/// The words from `stack` to the end of its page, at most 512, that lie in
/// this image, as offsets from its base.
///
/// # Safety
/// `stack`'s page reads from `stack` on.
unsafe fn image_offsets(stack: *const u64) -> impl Iterator<Item = u64> {
    const PAGE: usize = 4096;
    unsafe extern "C" {
        static __ImageBase: u8;
    }
    let base = &raw const __ImageBase as u64;
    // SAFETY: the mapped PE headers of this image: the DOS header's
    // `e_lfanew`, and the optional header's `SizeOfImage`.
    let bytes = unsafe {
        let header = u64::from((base as *const u32).byte_add(0x3c).read_unaligned());
        u64::from(
            ((base + header) as *const u32)
                .byte_add(0x50)
                .read_unaligned(),
        )
    };
    let words = (PAGE - stack.addr() % PAGE) / 8;
    (0..words.min(512))
        // SAFETY: the caller's.
        .map(move |word| unsafe { stack.add(word).read() }.wrapping_sub(base))
        .filter(move |&offset| offset < bytes)
}

/// The first image offsets on a stack ([`print_stack_at`]'s), for a failure
/// message: the screen and the boot log keep the message, not the port's
/// detail.
pub(crate) struct Callers {
    offsets: [u64; Self::SHOWN],
    count: usize,
}

impl Callers {
    const SHOWN: usize = 10;

    /// # Safety
    /// `stack`'s page reads from `stack` on.
    pub(crate) unsafe fn at(stack: *const u64) -> Self {
        let mut callers = Self {
            offsets: [0; Self::SHOWN],
            count: 0,
        };
        // SAFETY: the caller's.
        for offset in unsafe { image_offsets(stack) }.take(Self::SHOWN) {
            callers.offsets[callers.count] = offset;
            callers.count += 1;
        }
        callers
    }
}

impl core::fmt::Display for Callers {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (index, offset) in self.offsets[..self.count].iter().enumerate() {
            write!(f, "{}{offset:#x}", if index == 0 { "" } else { " " })?;
        }
        Ok(())
    }
}

pub(crate) fn panic(info: &PanicInfo<'_>) -> ! {
    // Never invoke arbitrary Display implementations in a failing process.
    // OOM's exact Layout was reported at the first null allocation instead.
    let message = info
        .message()
        .as_str()
        .unwrap_or("<nonliteral panic message omitted>");
    let processor = crate::native_idle::apic_id();
    if PRINTING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
        let mut reason = Text::<512>::default();
        let _ = match info.location() {
            Some(at) => write!(reason, "panic at {}:{}: {message}", at.file(), at.line()),
            None => write!(reason, "panic: {message}"),
        };
        let mut report = Text::<2048>::default();
        let _ = writeln!(
            report,
            "\nSTELA PANIC{}",
            reason.as_str().get("panic".len()..).unwrap_or("")
        );
        let stack: *const u64;
        // SAFETY: reads the stack pointer.
        unsafe { asm!("mov {}, rsp", out(reg) stack, options(nomem, nostack, preserves_flags)) };
        // SAFETY: the stack pointer's own page is mapped.
        unsafe { write_stack(&mut report, stack) };
        let _ = Serial.write_str(report.as_str());
        STORING.store(processor, Ordering::Relaxed);
        let stored = super::at_panic(report.as_str(), reason.as_str());
        STORING.store(NO_PROCESSOR, Ordering::Relaxed);
        let _ = match stored {
            Ok(()) => writeln!(Serial, "LOG stored up to this panic"),
            Err(why) => writeln!(
                Serial,
                "LOG not stored: {why}; this panic is kept only on the serial port"
            ),
        };
        let _ = writeln!(Serial, "STELA STOPPED code=0x11; power off to continue");
        exit(0x11);
    } else if STORING.load(Ordering::Relaxed) == processor {
        // The store after this processor's panic failed: the frames above
        // are abandoned, and the run ends here.
        let _ = writeln!(
            Serial,
            "\nLOG not stored: a second panic while storing it ({message}); the first panic is \
             kept only on the serial port"
        );
        let _ = writeln!(Serial, "STELA STOPPED code=0x11; power off to continue");
        exit(0x11);
    }
    // Other panicking CPUs must not end the run before the first report ends.
    loop {
        // SAFETY: terminal CPL0 path, no continuation or resource release.
        unsafe {
            asm!("cli", "hlt", options(nostack));
        }
    }
}
