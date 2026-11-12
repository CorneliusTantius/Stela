//! `--profile`: where a run's host time goes between translated blocks, by
//! phase of the engine's step loop and by the exit kind the engine handles.
//! The host supplies the clock ([`super::Host::profile_ticks`]); while off,
//! each phase boundary costs one branch.

/// A phase of the step loop ([`super::Machine::run_blocks`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Phase {
    /// Choosing the PE to run, ending slices and waiting.
    Schedule,
    /// Due device work and interrupt delivery before each step.
    Devices,
    /// Finding the next block, compiling and installing it when new.
    Fetch,
    /// Translated code, chained blocks included.
    Native,
    /// Handling the exit translated code returned with, by kind.
    Exit,
}

impl Phase {
    pub const COUNT: usize = Self::Exit as usize + 1;
    pub const ALL: [Self; Self::COUNT] = [
        Self::Schedule,
        Self::Devices,
        Self::Fetch,
        Self::Native,
        Self::Exit,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Schedule => "schedule",
            Self::Devices => "devices",
            Self::Fetch => "fetch",
            Self::Native => "native",
            Self::Exit => "exit",
        }
    }
}

/// The exits [`StepTiming::exits`] counts: each `ExitKind`, then native
/// faults by cause ([`fault_slot`]), then [`DEVICE_SITE_SLOT`], then the
/// native check faults by what the engine found ([`Check`]).
pub const EXIT_SLOTS: usize = CHECK_SLOTS + Check::COUNT;
/// [`StepTiming::exits`]' first native-fault slot.
const FAULT_SLOTS: usize = 13;
/// The slot of native faults that reached a device ([`fault_slot`]).
pub const DEVICE_FAULT_SLOT: usize = FAULT_SLOTS + 1;
/// The slot of native check faults (`FaultCause::NonCanonical` and
/// `InvalidOpcode`) whose outcome no [`Check`] names.
pub const CHECK_FAULT_SLOT: usize = FAULT_SLOTS + 2;
/// The slot of System exits at a device site's stub: device accesses the
/// engine completes (`Machine::complete_device_site`), not System
/// instructions.
pub const DEVICE_SITE_SLOT: usize = FAULT_SLOTS + 5;
/// [`StepTiming::exits`]' first [`Check`] slot.
const CHECK_SLOTS: usize = DEVICE_SITE_SLOT + 1;

/// What the engine found at a native check fault, which takes the fault's
/// slot from [`CHECK_FAULT_SLOT`] ([`Check::slot`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Check {
    /// A tagged address that translates under TBI, run again untagged by a
    /// single-instruction block (`Machine::retry_untagged`).
    Tagged,
    /// An Alignment fault: SP alignment, SCTLR_ELx.A, or an atomic or
    /// ordered access crossing its granule.
    Alignment,
    /// An address outside the native ranges whose translation faults: a
    /// Data Abort.
    Abort,
    /// An untagged address the host does not map natively: the page runs in
    /// the translated variant.
    Translated,
}

impl Check {
    pub const COUNT: usize = Self::Translated as usize + 1;

    /// Its slot in [`StepTiming::exits`].
    pub const fn slot(self) -> usize {
        CHECK_SLOTS + self as usize
    }
}

/// The [`SystemExits`] key of an exit at a device site's stub. No System
/// instruction has this word.
pub const DEVICE_SITE_KEY: u32 = u32::MAX;

/// The [`SystemExits`] key of the System exit at instruction `word`: the
/// word without the registers it names, so one register's MRS from every
/// Xt counts together.
pub fn system_key(word: u32) -> u32 {
    match word >> 24 {
        // MRS, MSR, SYS, SYSL, hints and barriers: Rt.
        0xd5 => word & !0x1f,
        // Exclusives: Rs, Rt2, Rn and Rt.
        0x08 | 0x48 | 0x88 | 0xc8 => word & !0x001f_7fff,
        // LDTR and STTR forms: imm9, Rn and Rt.
        0x38 | 0x78 | 0xb8 | 0xf8 => word & !0x001f_f3ff,
        _ => word,
    }
}

/// Whether [`SystemExits`] key `key` is a floating-point exit's word, which
/// the engine charges by the whole word next to the System keys; no System
/// key decodes as numerical FP.
pub fn numerical_key(key: u32) -> bool {
    key != DEVICE_SITE_KEY
        && matches!(
            stela_compiler::aarch64::FloatingPointOperation::decode(key),
            Some(Ok(_))
        )
}

/// Whether [`SystemExits`] key `key` is a pointer authentication exit's
/// word (an authenticated branch, return or load, or a PAC form a closed
/// key cell sent to the engine), which the report shows apart from the
/// System keys; no System key decodes as one.
pub fn pointer_key(key: u32) -> bool {
    key != DEVICE_SITE_KEY
        && matches!(
            stela_compiler::block::decode_pointer_authentication(
                stela_compiler::GuestAddress(0),
                register_word(key)
            ),
            Ok(Some(_))
        )
}

/// The word of [`system_key`] `key` with its MRS, MSR, SYS, SYSL or hint
/// Rt set to 31, which the key cleared.
fn register_word(key: u32) -> u32 {
    if key >> 24 == 0xd5 { key | 0x1f } else { key }
}

/// A short name of [`system_key`] `key` for reports: the accessor's for
/// MRS, MSR, SYS and SYSL (`MRS_TPIDR_EL1`, `TLBI_VAE1IS`), else the
/// operation's kind and the key (`Exception.ExceptionReturn:0xd69f03e0`).
pub fn system_key_name(key: u32) -> alloc::string::String {
    use stela_compiler::aarch64::system::registers::{self, Direction};
    if key == DEVICE_SITE_KEY {
        return "device-site".into();
    }
    if let Some(Ok(operation)) = stela_compiler::aarch64::FloatingPointOperation::decode(key) {
        let debug = alloc::format!("{operation:?}");
        let kind = debug.split(['(', ' ', '{']).next().unwrap_or("FP");
        return alloc::format!("{kind}:{key:#010x}");
    }
    if let Ok(Some(instruction)) = stela_compiler::block::decode_pointer_authentication(
        stela_compiler::GuestAddress(0),
        register_word(key),
    ) {
        let debug = alloc::format!("{:?}", instruction.operation);
        let kind = debug.split(['(', ' ', '{']).next().unwrap_or("PAC");
        return alloc::format!("PAC.{kind}:{key:#010x}");
    }
    let word = register_word(key);
    let access = registers::decode(word)
        .map(|access| (access, true))
        .or_else(|| registers::decode_sys(word).map(|access| (access, false)));
    if let Some((access, register)) = access {
        let read = access.direction() == Direction::Read;
        let encoding = access.encoding();
        if let Some((accessor, _)) = crate::machine::system::Lookup::new().find(encoding, read) {
            return accessor
                .name
                .replace("MSRregister", "MSR")
                .replace(' ', "_");
        }
        let kind = match (register, read) {
            (true, true) => "MRS",
            (true, false) => "MSR",
            (false, true) => "SYSL",
            (false, false) => "SYS",
        };
        return alloc::format!(
            "{kind}_S{}_{}_C{}_C{}_{}",
            encoding.op0(),
            encoding.op1(),
            encoding.crn(),
            encoding.crm(),
            encoding.op2()
        );
    }
    let operation = stela_compiler::block::decode_system_mode_instruction(
        stela_compiler::GuestAddress(0),
        word,
    )
    .ok()
    .flatten()
    .map(|instruction| alloc::format!("{:?}", instruction.operation));
    let kind = operation
        .as_deref()
        .and_then(|debug| debug.split([' ', '{', ')']).next())
        .unwrap_or("word")
        .trim_end_matches('(')
        .replace('(', ".");
    alloc::format!("{kind}:{key:#010x}")
}

/// What a System exit key does, for the per-class totals of `PES SYSTEM`,
/// which leave no key out: device sites; Apple's compression instructions;
/// barriers; TLB and cache maintenance and address translation (TLBI, IC,
/// DC, AT: SYS with CRn 7 or 8); waits (WFE, WFI); the generic timer's
/// registers (CRn 14); implementation-defined registers (CRn 15: Apple's
/// counters, IPIs and controls); the translation controls (SCTLR, CPACR,
/// TTBRn, TCR, MAIR, CONTEXTIDR: CRn 1, 2, 10, 13); exception entries and
/// returns and guarded-level transitions; and everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemClass {
    Device,
    Compression,
    Barrier,
    Maintenance,
    Wait,
    Timer,
    ImplementationDefined,
    TranslationControl,
    Transition,
    Other,
}

impl SystemClass {
    pub const COUNT: usize = Self::Other as usize + 1;
    pub const NAMES: [&'static str; Self::COUNT] = [
        "device",
        "compression",
        "barrier",
        "maintenance",
        "wait",
        "timer",
        "impdef",
        "translation",
        "transition",
        "other",
    ];

    /// The class of System exit key `key`.
    pub fn of(key: u32) -> Self {
        use stela_compiler::aarch64::system::registers;
        if key == DEVICE_SITE_KEY {
            return Self::Device;
        }
        let word = if key >> 24 == 0xd5 { key | 0x1f } else { key };
        if let Some(access) = registers::decode(word) {
            let encoding = access.encoding();
            return match (encoding.op0(), encoding.crn()) {
                (3, 15) => Self::ImplementationDefined,
                (3, 14) => Self::Timer,
                (3, 1 | 2 | 10 | 13) => Self::TranslationControl,
                _ => Self::Other,
            };
        }
        if let Some(access) = registers::decode_sys(word) {
            return match access.encoding().crn() {
                7 | 8 => Self::Maintenance,
                _ => Self::Other,
            };
        }
        let name = system_key_name(key);
        match name.split(['.', ':']).next().unwrap_or_default() {
            "Compression" => Self::Compression,
            "Synchronization" => Self::Barrier,
            "Wait" => Self::Wait,
            "Exception" | "Guarded" => Self::Transition,
            _ => Self::Other,
        }
    }
}

/// One [`SystemExits`] key's exits, the ticks handling them, and how many
/// of them closed every mirror cell (`Machine::derived_changed`), after
/// which each MRS and MSR site exits again once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemExit {
    pub key: u32,
    pub count: u64,
    pub ticks: u64,
    pub closes: u64,
}

impl SystemExit {
    fn add(&mut self, count: u64, ticks: u64, closes: u64) {
        self.count += count;
        self.ticks += ticks;
        self.closes += closes;
    }
}

/// System exits by [`system_key`] since they were last taken, under step
/// timing: an open-addressed table, with the keys past its size in `other`;
/// the device accesses the engine completed; and the floating-point exits
/// by what their completion found ([`FloatingReason`]), in all and by word
/// with their operands ([`FloatingWords`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemExits {
    pub entries: [SystemExit; SYSTEM_KEYS],
    pub other: SystemExit,
    pub devices: DeviceExits,
    pub floating: [u64; FloatingReason::COUNT],
    pub floating_words: FloatingWords,
    pub barriers: BarrierWaits,
    pub regimes: RegimeSyncs,
    /// WKDMC, then WKDMD ([`Compression`]).
    pub compression: [Compression; 2],
}

/// The host's regime changes ([`super::Host::set_regime`]) and prediction
/// isolations ([`super::Host::isolate_predictions`]) under step timing: how
/// many and their profile ticks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RegimeSyncs {
    pub syncs: u64,
    pub sync_ticks: u64,
    pub isolations: u64,
    pub isolation_ticks: u64,
    /// The syncs that gave the host the regime it had and isolated nothing.
    pub unchanged: u64,
    /// The syncs by what asked for them ([`SyncSource`]).
    pub sources: [u64; SyncSource::COUNT],
}

/// What asked for a regime sync ([`RegimeSyncs::sources`]): a PAN change by
/// MSR in the engine, a PAN change native code made, a translation change
/// (an SPRR_PERM write and others), a TTBR0 write, an exception entry or
/// return or GXF transition the engine made, a change of derived state, and
/// anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncSource {
    Pan,
    NativePan,
    Translation,
    TableBase,
    Transition,
    Derived,
    Other,
}

impl SyncSource {
    pub const COUNT: usize = Self::Other as usize + 1;
    pub const NAMES: [&str; Self::COUNT] = [
        "pan",
        "native_pan",
        "translation",
        "table_base",
        "transition",
        "derived",
        "other",
    ];
}

impl RegimeSyncs {
    /// Add every change `other` counts.
    pub fn merge(&mut self, other: &Self) {
        self.syncs += other.syncs;
        self.sync_ticks += other.sync_ticks;
        self.isolations += other.isolations;
        self.isolation_ticks += other.isolation_ticks;
        self.unchanged += other.unchanged;
        for (count, more) in self.sources.iter_mut().zip(other.sources) {
            *count += more;
        }
    }
}

/// The [`BarrierWaits`] blocker of a PE in native code.
pub const BLOCKER_NATIVE: u64 = 1;
/// The [`BarrierWaits`] blocker of a PE that entered a fetched block and
/// prepares its native run, or takes the fetch's exception or checked
/// instruction.
pub const BLOCKER_ENTERING: u64 = 2;
/// The [`BarrierWaits`] blocker of a PE whose native run returned, before
/// it knows the exit.
pub const BLOCKER_RETURNED: u64 = 3;
/// Bit 63 of a blocker: a PE completing an exit of the slot in bits 32-62
/// at the [`system_key`] in bits 0-31 (0 where the exit has no word).
pub const BLOCKER_EXIT: u64 = 1 << 63;
/// The blockers [`BarrierWaits`] holds apart.
pub const BARRIER_BLOCKERS: usize = 32;

/// The blocker of PE in an exit of `slot` at `word`.
pub fn exit_blocker(slot: usize, word: Option<u32>) -> u64 {
    BLOCKER_EXIT | (slot as u64) << 32 | u64::from(word.map_or(0, system_key))
}

/// The waits for one blocker: how many and their ticks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BarrierBlocker {
    pub key: u64,
    pub count: u64,
    pub ticks: u64,
}

/// DSBs that completed maintenance this PE posted, under step timing: how
/// many, those that found every PE had applied it at the first look
/// (`quick`), and the profile ticks they spent; and by the last PE they
/// waited for, what that PE was doing when last seen (its blocker: native
/// code, [`BLOCKER_NATIVE`], or an exit, [`exit_blocker`]), with the rest in
/// `other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarrierWaits {
    pub waits: u64,
    pub quick: u64,
    pub ticks: u64,
    pub blockers: [BarrierBlocker; BARRIER_BLOCKERS],
    pub other: BarrierBlocker,
}

impl Default for BarrierWaits {
    fn default() -> Self {
        Self {
            waits: 0,
            quick: 0,
            ticks: 0,
            blockers: [BarrierBlocker::default(); BARRIER_BLOCKERS],
            other: BarrierBlocker::default(),
        }
    }
}

impl BarrierWaits {
    /// Count a wait of `ticks`: one that waited for a PE last seen at
    /// `blocker`, or `None` when none was waited for.
    pub fn add(&mut self, blocker: Option<u64>, ticks: u64) {
        self.waits += 1;
        self.ticks += ticks;
        match blocker {
            None => self.quick += 1,
            Some(key) => self.add_blocker(key, 1, ticks),
        }
    }

    fn add_blocker(&mut self, key: u64, count: u64, ticks: u64) {
        let entry = match self
            .blockers
            .iter()
            .position(|entry| entry.count == 0 || entry.key == key)
        {
            Some(index) => &mut self.blockers[index],
            None => &mut self.other,
        };
        if entry.count == 0 {
            entry.key = key;
        }
        entry.count += count;
        entry.ticks += ticks;
    }

    /// Add every wait `other` counts.
    pub fn merge(&mut self, other: &Self) {
        self.waits += other.waits;
        self.quick += other.quick;
        self.ticks += other.ticks;
        for entry in other.blockers.iter().filter(|entry| entry.count != 0) {
            self.add_blocker(entry.key, entry.count, entry.ticks);
        }
        self.other.count += other.other.count;
        self.other.ticks += other.other.ticks;
    }
}

/// WKDMC or WKDMD instructions the engine completed under step timing, and
/// the ticks of their handling split: the whole handler; reading the source
/// through translated guest memory; the codec; and writing the destination
/// (the host's publication of the bytes into guest RAM). The rest of the
/// handler is translation checks and the result; the rest of the exit, in
/// `SYSTEM WORDS`, is leaving and entering the guest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Compression {
    pub count: u64,
    pub whole: u64,
    pub read: u64,
    pub codec: u64,
    pub write: u64,
}

impl Compression {
    /// Count one of `whole` ticks: `parts` are its read, codec and write.
    pub fn add(&mut self, whole: u64, parts: [u64; 3]) {
        self.count += 1;
        self.whole += whole;
        self.read += parts[0];
        self.codec += parts[1];
        self.write += parts[2];
    }

    fn merge(&mut self, other: &Self) {
        self.count += other.count;
        self.whole += other.whole;
        self.read += other.read;
        self.codec += other.codec;
        self.write += other.write;
    }
}

/// What the software completion of a floating-point exit found, which names
/// the guard that sent it there: an enabled trap (FPCR's enables, which every
/// recipe sends to the helper), the first fresh FPSR flag in Arm's order
/// (invalid: NaN or invalid operation; divide by zero; overflow; underflow: a
/// tiny result; input denormal flushed), inexact alone, no flag (exact: a
/// signed zero, an infinity, a quiet NaN, a subnormal input or result that
/// was exact, or a form without an inline recipe), and apart from those, how
/// many ran with FZ, FZ16, FIZ, AH or DN set (`Mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatingReason {
    Trap,
    Invalid,
    Divide,
    Overflow,
    Underflow,
    Denormal,
    Inexact,
    Exact,
    Mode,
}

impl FloatingReason {
    pub const COUNT: usize = Self::Mode as usize + 1;
    pub const NAMES: [&'static str; Self::COUNT] = [
        "trap",
        "invalid",
        "divide",
        "overflow",
        "underflow",
        "denormal",
        "inexact",
        "exact",
        "mode",
    ];

    /// The reason of a completion with fresh cumulative flags `fresh`
    /// (FPSR's bit layout) that trapped (`trapped`) or not under `fpcr`.
    pub fn of(fpcr: u32, fresh: u32, trapped: bool) -> Self {
        use stela_compiler::aarch64::floating::FPCR_EXCEPTION_ENABLE_MASK;
        const FLAGS: [(u32, FloatingReason); 6] = [
            (1 << 0, FloatingReason::Invalid),
            (1 << 1, FloatingReason::Divide),
            (1 << 2, FloatingReason::Overflow),
            (1 << 3, FloatingReason::Underflow),
            (1 << 7, FloatingReason::Denormal),
            (1 << 4, FloatingReason::Inexact),
        ];
        if trapped || fpcr & FPCR_EXCEPTION_ENABLE_MASK != 0 {
            return Self::Trap;
        }
        FLAGS
            .iter()
            .find(|(flag, _)| fresh & flag != 0)
            .map_or(Self::Exact, |&(_, reason)| reason)
    }

    /// Whether `fpcr` selects a flushing or alternative mode.
    pub fn moded(fpcr: u32) -> bool {
        use stela_compiler::aarch64::floating::{FPCR_AH, FPCR_DN, FPCR_FIZ, FPCR_FZ, FPCR_FZ16};
        fpcr & (FPCR_FZ | FPCR_FZ16 | FPCR_FIZ | FPCR_AH | FPCR_DN) != 0
    }
}

/// What the operands of a floating-point exit held, which names the recipe
/// guard that sent it to the engine where its flags do not (a subnormal
/// input raises no flag with FZ clear, a quiet NaN none at all): a NaN, a
/// subnormal, a zero or an infinity in an active source lane; a nonzero
/// result lane below twice the minimum normal (`Tiny`, which recipes leave
/// to the engine in case it was tiny before rounding); none of those
/// (`Ordinary`); and a form whose lanes [`census_lanes`] does not read
/// (`Unread`). An exit counts in every class its operands show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operands {
    Nan,
    Subnormal,
    Zero,
    Infinite,
    Tiny,
    Ordinary,
    Unread,
}

impl Operands {
    pub const COUNT: usize = Self::Unread as usize + 1;
    pub const NAMES: [&'static str; Self::COUNT] = [
        "nan",
        "subnormal",
        "zero",
        "infinite",
        "tiny",
        "ordinary",
        "unread",
    ];

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// A register the census reads: its lanes, from one lane alone when
/// indexed.
#[derive(Debug, Clone, Copy)]
struct CensusRegister {
    register: u8,
    lane: Option<u8>,
    lanes: u32,
}

impl CensusRegister {
    const fn whole(register: u8, lanes: u32) -> Self {
        Self {
            register,
            lane: None,
            lanes,
        }
    }
}

/// The lanes of an operation the census reads: its format, up to three
/// sources and the result.
#[derive(Debug, Clone, Copy)]
struct CensusLanes {
    format: stela_compiler::aarch64::floating::Format,
    sources: [Option<CensusRegister>; 3],
    result: CensusRegister,
}

/// The lanes [`Operands`] classifies for the families with the most exits
/// (fused, binary arithmetic, min/max, estimates, roots and rounding); none
/// for the rest, which count as [`Operands::Unread`].
fn census_lanes(
    operation: &stela_compiler::aarch64::FloatingPointOperation,
) -> Option<CensusLanes> {
    use stela_compiler::aarch64::{
        FloatingPointOperation as Operation,
        simd::{arithmetic::Inputs, estimate::Kind, minmax},
    };
    let whole = CensusRegister::whole;
    let lanes =
        |format, shape: stela_compiler::aarch64::simd::arithmetic::Shape| shape.lane_count(format);
    Some(match operation {
        Operation::Fused(operand) => {
            let count = lanes(operand.format, operand.shape);
            CensusLanes {
                format: operand.format,
                sources: [
                    Some(whole(operand.left, count)),
                    Some(CensusRegister {
                        register: operand.right,
                        lane: operand.right_lane,
                        lanes: count,
                    }),
                    Some(whole(operand.addend, count)),
                ],
                result: whole(operand.destination, count),
            }
        }
        Operation::Binary(operand) => {
            let count = lanes(operand.format, operand.shape);
            let (left, right) = match operand.inputs {
                Inputs::Elementwise { left, right } | Inputs::Pairwise { left, right } => {
                    (whole(left, count), Some(whole(right, count)))
                }
                Inputs::Indexed {
                    left,
                    right,
                    right_lane,
                } => (
                    whole(left, count),
                    Some(CensusRegister {
                        register: right,
                        lane: Some(right_lane),
                        lanes: count,
                    }),
                ),
                Inputs::PairwiseScalar { source } => (whole(source, 2), None),
            };
            CensusLanes {
                format: operand.format,
                sources: [Some(left), right, None],
                result: whole(operand.destination, count),
            }
        }
        Operation::MinMax(operand) => match *operand {
            minmax::Operand::Binary {
                format,
                shape,
                destination,
                left,
                right,
                ..
            } => {
                let count = lanes(format, shape);
                CensusLanes {
                    format,
                    sources: [Some(whole(left, count)), Some(whole(right, count)), None],
                    result: whole(destination, count),
                }
            }
            minmax::Operand::PairwiseScalar {
                format,
                destination,
                source,
                ..
            } => CensusLanes {
                format,
                sources: [Some(whole(source, 2)), None, None],
                result: whole(destination, 1),
            },
            minmax::Operand::Reduction {
                format,
                shape,
                destination,
                source,
                ..
            } => CensusLanes {
                format,
                sources: [Some(whole(source, lanes(format, shape))), None, None],
                result: whole(destination, 1),
            },
        },
        Operation::Estimate(operand)
            if !matches!(
                operand.kind,
                Kind::UnsignedReciprocal | Kind::UnsignedReciprocalSquareRoot
            ) =>
        {
            let count = lanes(operand.format, operand.shape);
            CensusLanes {
                format: operand.format,
                sources: [Some(whole(operand.source, count)), None, None],
                result: whole(operand.destination, count),
            }
        }
        Operation::SquareRoot(operand) => {
            let count = lanes(operand.format, operand.shape);
            CensusLanes {
                format: operand.format,
                sources: [Some(whole(operand.source, count)), None, None],
                result: whole(operand.destination, count),
            }
        }
        Operation::Rounding(operand) => {
            let count = lanes(operand.format, operand.shape);
            CensusLanes {
                format: operand.format,
                sources: [Some(whole(operand.source, count)), None, None],
                result: whole(operand.destination, count),
            }
        }
        _ => return None,
    })
}

/// The lane `lane` of `format` in vector `vector`.
fn census_lane(
    vector: &[u64; 2],
    format: stela_compiler::aarch64::floating::Format,
    lane: u32,
) -> u64 {
    let bits = format.bits();
    let offset = lane * bits;
    let word = vector[(offset / u64::BITS) as usize] >> (offset % u64::BITS);
    word & (u64::MAX >> (u64::BITS - bits))
}

/// The exponent field and the fraction of `format` value `bits`, and the
/// field's all-ones value.
fn census_fields(bits: u64, format: stela_compiler::aarch64::floating::Format) -> (u64, u64, u64) {
    use stela_compiler::aarch64::floating::Format;
    let (exponent_bits, fraction_bits) = match format {
        Format::Half => (5, 10),
        Format::Single => (8, 23),
        Format::Double => (11, 52),
    };
    let maximum = (1 << exponent_bits) - 1;
    (
        (bits >> fraction_bits) & maximum,
        bits & ((1 << fraction_bits) - 1),
        maximum,
    )
}

/// The operand census of one floating-point exit: what its sources held
/// before the completion ([`FloatingCensus::read`]), then what its result
/// held after it ([`FloatingCensus::finish`]).
#[derive(Debug, Clone, Copy)]
pub struct FloatingCensus {
    lanes: Option<CensusLanes>,
    classes: u8,
}

impl FloatingCensus {
    /// Classify the active source lanes of `operation` in `state`.
    pub fn read(
        state: &stela_compiler::GuestState,
        operation: &stela_compiler::aarch64::FloatingPointOperation,
    ) -> Self {
        let lanes = census_lanes(operation);
        let mut classes = 0;
        let sources = lanes.iter().flat_map(|lanes| {
            lanes
                .sources
                .iter()
                .flatten()
                .map(move |source| (lanes.format, source))
        });
        for (format, source) in sources {
            let vector = &state.v[usize::from(source.register & 31)];
            for lane in 0..source.lanes {
                let bits = census_lane(vector, format, source.lane.map_or(lane, u32::from));
                let (exponent, fraction, maximum) = census_fields(bits, format);
                classes |= match (exponent, fraction == 0) {
                    (0, true) => Operands::Zero.bit(),
                    (0, false) => Operands::Subnormal.bit(),
                    (e, true) if e == maximum => Operands::Infinite.bit(),
                    (e, false) if e == maximum => Operands::Nan.bit(),
                    _ => 0,
                };
            }
        }
        Self { lanes, classes }
    }

    /// Add the classes of the result lanes in `state` (none when the
    /// completion trapped and wrote no result), and return every class
    /// seen as [`Operands`] bits.
    pub fn finish(self, state: &stela_compiler::GuestState, completed: bool) -> u8 {
        let Some(lanes) = self.lanes else {
            return Operands::Unread.bit();
        };
        let mut classes = self.classes;
        if completed {
            let result = lanes.result;
            let vector = &state.v[usize::from(result.register & 31)];
            for lane in 0..result.lanes {
                let bits = census_lane(vector, lanes.format, lane);
                let (exponent, fraction, maximum) = census_fields(bits, lanes.format);
                if exponent < 2 && (exponent != 0 || fraction != 0) && exponent != maximum {
                    classes |= Operands::Tiny.bit();
                }
            }
        }
        const DATA: u8 = Operands::Nan.bit() | Operands::Subnormal.bit() | Operands::Tiny.bit();
        if classes & DATA == 0 {
            classes |= Operands::Ordinary.bit();
        }
        classes
    }
}

/// One floating-point exit word's exits since they were last taken, by
/// [`FloatingReason`] (the `Mode` count apart from the others), by the
/// [`Operands`] classes they showed, and how many found FPSR.IXC clear,
/// where no sticky-inexact path runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FloatingWord {
    pub key: u32,
    pub reasons: [u32; FloatingReason::COUNT],
    pub operands: [u32; Operands::COUNT],
    pub inexact_clear: u32,
}

impl FloatingWord {
    /// Its exits: every reason but `Mode`, which they also count in.
    pub fn count(&self) -> u64 {
        self.reasons[..FloatingReason::Mode as usize]
            .iter()
            .map(|&count| u64::from(count))
            .sum()
    }

    /// Add every exit `other` counts.
    pub fn merge(&mut self, other: &Self) {
        for (count, more) in self.reasons.iter_mut().zip(other.reasons) {
            *count = count.saturating_add(more);
        }
        for (count, more) in self.operands.iter_mut().zip(other.operands) {
            *count = count.saturating_add(more);
        }
        self.inexact_clear = self.inexact_clear.saturating_add(other.inexact_clear);
    }
}

/// The words [`FloatingWords`] holds apart: a beat's floating-point exits
/// have reached about 240 words machine-wide.
pub const FLOATING_WORDS: usize = 256;

/// Floating-point exits by word with their causes ([`FloatingWord`]),
/// under step timing: an open-addressed table, with the words past its
/// size in `other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloatingWords {
    pub entries: [FloatingWord; FLOATING_WORDS],
    pub other: FloatingWord,
}

impl Default for FloatingWords {
    fn default() -> Self {
        Self {
            entries: [FloatingWord::default(); FLOATING_WORDS],
            other: FloatingWord::default(),
        }
    }
}

impl FloatingWords {
    /// The entry of `key`, or `other` once the table is full.
    fn entry(&mut self, key: u32) -> &mut FloatingWord {
        let start =
            (key.wrapping_mul(0x9e37_79b9) >> (u32::BITS - FLOATING_WORDS.ilog2())) as usize;
        let found = (0..FLOATING_WORDS)
            .map(|probe| (start + probe) % FLOATING_WORDS)
            .find(|&index| {
                let entry = &self.entries[index];
                entry.key == key || entry.count() == 0
            });
        match found {
            Some(index) => {
                let entry = &mut self.entries[index];
                entry.key = key;
                entry
            }
            None => &mut self.other,
        }
    }

    /// Count one exit of `key` for `reason`, in `Mode` too if `moded`,
    /// with [`Operands`] bits `operands`, that found FPSR.IXC clear if
    /// `inexact_clear`.
    pub fn add(
        &mut self,
        key: u32,
        reason: FloatingReason,
        moded: bool,
        operands: u8,
        inexact_clear: bool,
    ) {
        let entry = self.entry(key);
        entry.reasons[reason as usize] = entry.reasons[reason as usize].saturating_add(1);
        if moded {
            let mode = &mut entry.reasons[FloatingReason::Mode as usize];
            *mode = mode.saturating_add(1);
        }
        for (class, count) in entry.operands.iter_mut().enumerate() {
            if operands & (1 << class) != 0 {
                *count = count.saturating_add(1);
            }
        }
        entry.inexact_clear = entry.inexact_clear.saturating_add(u32::from(inexact_clear));
    }

    /// Add every exit `words` counts.
    pub fn merge(&mut self, words: &Self) {
        for word in words.counted() {
            self.entry(word.key).merge(word);
        }
        self.other.merge(&words.other);
    }

    /// The words with exits.
    pub fn counted(&self) -> impl Iterator<Item = &FloatingWord> {
        self.entries.iter().filter(|word| word.count() != 0)
    }

    pub fn is_empty(&self) -> bool {
        self.other.count() == 0 && self.counted().next().is_none()
    }
}

/// The keys [`SystemExits`] holds apart. The report merges every PE's into
/// one table each beat, and a process spawn alone exits on well over 128
/// keys machine-wide: with 128 the costliest of them landed in `other`
/// (12-18 ms of exit time per spawn, unnamed).
pub const SYSTEM_KEYS: usize = 512;

impl Default for SystemExits {
    fn default() -> Self {
        Self {
            entries: [SystemExit::default(); SYSTEM_KEYS],
            other: SystemExit::default(),
            devices: DeviceExits::default(),
            floating: [0; FloatingReason::COUNT],
            floating_words: FloatingWords::default(),
            barriers: BarrierWaits::default(),
            regimes: RegimeSyncs::default(),
            compression: [Compression::default(); 2],
        }
    }
}

impl SystemExits {
    /// Count `count` exits of `key` that took `ticks` and closed the cells
    /// `closes` times.
    pub fn add(&mut self, key: u32, count: u64, ticks: u64, closes: u64) {
        let start = (key.wrapping_mul(0x9e37_79b9) >> (u32::BITS - SYSTEM_KEYS.ilog2())) as usize;
        for probe in 0..SYSTEM_KEYS {
            let entry = &mut self.entries[(start + probe) % SYSTEM_KEYS];
            if entry.count == 0 {
                entry.key = key;
            }
            if entry.key == key {
                return entry.add(count, ticks, closes);
            }
        }
        self.other.add(count, ticks, closes);
    }

    /// Add every exit `exits` counts.
    pub fn merge(&mut self, exits: &Self) {
        for entry in exits.entries.iter().filter(|entry| entry.count != 0) {
            self.add(entry.key, entry.count, entry.ticks, entry.closes);
        }
        let other = exits.other;
        self.other.add(other.count, other.ticks, other.closes);
        self.devices.merge(&exits.devices);
        for (count, more) in self.floating.iter_mut().zip(exits.floating) {
            *count += more;
        }
        self.floating_words.merge(&exits.floating_words);
        self.barriers.merge(&exits.barriers);
        self.regimes.merge(&exits.regimes);
        for (compression, other) in self.compression.iter_mut().zip(&exits.compression) {
            compression.merge(other);
        }
    }

    /// The keys with exits.
    pub fn counted(&self) -> impl Iterator<Item = &SystemExit> {
        self.entries.iter().filter(|entry| entry.count != 0)
    }

    pub fn is_empty(&self) -> bool {
        self.other.count == 0
            && self.counted().next().is_none()
            && self.devices.is_empty()
            && self.floating.iter().all(|&count| count == 0)
            && self.floating_words.is_empty()
            && self.barriers.waits == 0
            && self.regimes == RegimeSyncs::default()
            && self
                .compression
                .iter()
                .all(|compression| compression.count == 0)
    }
}

/// The 4 KiB page of a device register, as [`DeviceExits`] keys it.
pub fn device_page(physical: u64) -> u32 {
    (physical >> 12) as u32
}

/// One device page's accesses, the ticks handling them, and the host
/// counter ticks of those spent waiting for the board's lock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceExit {
    pub page: u32,
    pub count: u64,
    pub ticks: u64,
    pub waited: u64,
}

impl DeviceExit {
    fn add(&mut self, count: u64, ticks: u64, waited: u64) {
        self.count += count;
        self.ticks += ticks;
        self.waited += waited;
    }
}

/// The device pages [`DeviceExits`] holds apart.
pub const DEVICE_PAGES: usize = 64;

/// One device register's reads or writes the engine completed, with
/// [`DeviceExit`]'s counts: `register` its physical address, with
/// [`DEVICE_REGISTER_WRITE`] set for writes, whose ticks also split as
/// [`DeviceWrites`]' do into the access and the settle after it, and the
/// settle's transfer and deferred copies; `longest` is the longest exit,
/// which tells a few long exits (a preempted host thread) from many.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceRegisterExit {
    pub register: u64,
    pub count: u64,
    pub ticks: u64,
    pub waited: u64,
    pub access: u64,
    pub settle: u64,
    pub transfer: u64,
    pub copies: u64,
    pub released: u64,
    pub longest: u64,
}

impl DeviceRegisterExit {
    fn add(&mut self, other: &Self) {
        self.count += other.count;
        self.ticks += other.ticks;
        self.waited += other.waited;
        self.access += other.access;
        self.settle += other.settle;
        self.transfer += other.transfer;
        self.copies += other.copies;
        self.released += other.released;
        self.longest = self.longest.max(other.longest);
    }
}

/// The parts a device write's exit is timed in: its access, its settle,
/// its gate call, and of the settle the transfer under the devices' lock,
/// the deferred DMA copies after the lock's release and the host work the
/// release did on the writing core, in the board counter's ticks as a lock
/// wait is ([`DeviceWrites::add`]).
pub const WRITE_PARTS: usize = 6;

/// The bit of [`DeviceRegisterExit::register`] that says writes: physical
/// addresses never reach it.
pub const DEVICE_REGISTER_WRITE: u64 = 1 << 63;

/// The registers and directions [`DeviceExits`] holds apart.
pub const DEVICE_REGISTERS: usize = 128;

/// Device writes the engine completed, and the ticks of their exits split:
/// the whole exit; the access, up to the model's write done (the devices'
/// lock and the write); the settle after it (in the same locked call every
/// master's transfer, then the release: the PEs it woke, the publication,
/// the deferred copies and the host work after); and a gate call it made
/// ([`super::Devices::write_settled`]). The rest of the exit is the
/// engine's own: leaving and entering the guest, decode, routing and
/// watching.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceWrites {
    pub count: u64,
    pub exit: u64,
    pub access: u64,
    pub settle: u64,
    pub call: u64,
    pub transfer: u64,
    pub copies: u64,
    pub released: u64,
}

impl DeviceWrites {
    pub fn add(&mut self, exit: u64, parts: [u64; WRITE_PARTS]) {
        self.count += 1;
        self.exit += exit;
        self.access += parts[0];
        self.settle += parts[1];
        self.call += parts[2];
        self.transfer += parts[3];
        self.copies += parts[4];
        self.released += parts[5];
    }

    fn merge(&mut self, other: &Self) {
        self.count += other.count;
        self.exit += other.exit;
        self.access += other.access;
        self.settle += other.settle;
        self.call += other.call;
        self.transfer += other.transfer;
        self.copies += other.copies;
        self.released += other.released;
    }
}

/// Device accesses the engine completed, from native faults and device
/// sites, by [`device_page`], under step timing: an open-addressed table,
/// with the pages past its size in `other`; and the accesses forwarded to
/// the home machine, with the ticks their PEs waited for its answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceExits {
    pub entries: [DeviceExit; DEVICE_PAGES],
    pub other: DeviceExit,
    pub forwarded: u64,
    pub forwarded_ticks: u64,
    pub writes: DeviceWrites,
    /// The same accesses by register and direction, an open-addressed
    /// table too, with the rest in `other_registers`.
    pub registers: [DeviceRegisterExit; DEVICE_REGISTERS],
    pub other_registers: DeviceRegisterExit,
}

impl Default for DeviceExits {
    fn default() -> Self {
        Self {
            entries: [DeviceExit::default(); DEVICE_PAGES],
            other: DeviceExit::default(),
            forwarded: 0,
            forwarded_ticks: 0,
            writes: DeviceWrites::default(),
            registers: [DeviceRegisterExit::default(); DEVICE_REGISTERS],
            other_registers: DeviceRegisterExit::default(),
        }
    }
}

impl DeviceExits {
    /// Count `count` accesses of `page` that took `ticks`, `waited` of them
    /// in host counter ticks waiting for the board's lock.
    pub fn add(&mut self, page: u32, count: u64, ticks: u64, waited: u64) {
        let start = (page.wrapping_mul(0x9e37_79b9) >> (u32::BITS - DEVICE_PAGES.ilog2())) as usize;
        for probe in 0..DEVICE_PAGES {
            let entry = &mut self.entries[(start + probe) % DEVICE_PAGES];
            if entry.count == 0 {
                entry.page = page;
            }
            if entry.page == page {
                return entry.add(count, ticks, waited);
            }
        }
        self.other.add(count, ticks, waited);
    }

    /// Count the accesses `exit` holds of its register as [`Self::add`]
    /// counts its page's.
    pub fn add_register(&mut self, exit: DeviceRegisterExit) {
        let register = exit.register;
        let hash = (register ^ register >> 32).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let start = (hash >> (u64::BITS - DEVICE_REGISTERS.ilog2())) as usize;
        for probe in 0..DEVICE_REGISTERS {
            let entry = &mut self.registers[(start + probe) % DEVICE_REGISTERS];
            if entry.count == 0 {
                entry.register = register;
            }
            if entry.register == register {
                return entry.add(&exit);
            }
        }
        self.other_registers.add(&exit);
    }

    /// The registers with accesses.
    pub fn counted_registers(&self) -> impl Iterator<Item = &DeviceRegisterExit> {
        self.registers.iter().filter(|entry| entry.count != 0)
    }

    pub fn merge(&mut self, exits: &Self) {
        for entry in exits.counted() {
            self.add(entry.page, entry.count, entry.ticks, entry.waited);
        }
        for entry in exits.counted_registers() {
            self.add_register(*entry);
        }
        self.other_registers.add(&exits.other_registers);
        let other = exits.other;
        self.other.add(other.count, other.ticks, other.waited);
        self.forwarded += exits.forwarded;
        self.forwarded_ticks += exits.forwarded_ticks;
        self.writes.merge(&exits.writes);
    }

    /// The pages with accesses.
    pub fn counted(&self) -> impl Iterator<Item = &DeviceExit> {
        self.entries.iter().filter(|entry| entry.count != 0)
    }

    pub fn is_empty(&self) -> bool {
        self.other.count == 0 && self.forwarded == 0 && self.counted().next().is_none()
    }
}

/// A native fault's slot in [`StepTiming::exits`], by cause: the guest's
/// translation, a device, a native check, a watched or tag-checked page,
/// or translation the engine does not implement.
pub fn fault_slot(cause: &super::FaultCause) -> usize {
    use super::FaultCause;
    FAULT_SLOTS
        + match cause {
            FaultCause::Guest(_) => 0,
            FaultCause::Device { .. } => DEVICE_FAULT_SLOT - FAULT_SLOTS,
            FaultCause::NonCanonical | FaultCause::InvalidOpcode => CHECK_FAULT_SLOT - FAULT_SLOTS,
            FaultCause::Watched | FaultCause::TagChecked => 3,
            FaultCause::Translation(_) => 4,
        }
}

/// One completed phase's largest observed profile-clock interval.
///
/// The CPU fields are a materialized snapshot after the phase, not a precise
/// fault PC or an attribution to one guest instruction. Fetch includes finding,
/// compiling and installing code; every phase can include host descheduling.
/// These observations are diagnostics, never architectural latency bounds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Maximum {
    pub ticks: u64,
    /// The same profile-clock sample used to close this interval.
    pub finished_ticks: u64,
    pub pc_after: u64,
    pub el_after: u8,
    pub daif_after: u8,
}

impl Maximum {
    #[inline]
    pub(super) fn observe(
        &mut self,
        ticks: u64,
        finished_ticks: u64,
        pc_after: u64,
        el_after: u8,
        daif_after: u8,
    ) {
        if ticks > self.ticks {
            *self = Self {
                ticks,
                finished_ticks,
                pc_after,
                el_after,
                daif_after,
            };
        }
    }
}

/// The guest states [`Levels::ticks`] splits busy time by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Level {
    /// EL0.
    User,
    /// EL1 or EL2 outside guarded mode.
    Kernel,
    /// Apple GXF guarded mode at any level.
    Guarded,
}

impl Level {
    pub const COUNT: usize = Self::Guarded as usize + 1;

    pub fn of(el: u8, guarded: bool) -> Self {
        match (guarded, el) {
            (true, _) => Self::Guarded,
            (false, 0) => Self::User,
            (false, _) => Self::Kernel,
        }
    }
}

/// Where native code was when a sampled run's transfer budget ran out, under
/// step timing (`Machine::execute`): one run in [`HOT_SAMPLE_EVERY`] gets a
/// budget drawn uniformly from 1..=[`HOT_SAMPLE_SPAN`], so a run of `n`
/// transfers is sampled with a chance in proportion to `n` and at a uniformly
/// chosen one of them: each transfer of native code is equally likely to be
/// the sample, which ranks blocks by the native work in them rather than by
/// where they exit. A sample is the entered block's guest PC and [`Level`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HotBlocks {
    /// Open-addressed `(pc, level, count)` entries, [`HOT_BLOCKS`] of them
    /// once the first sample is added; samples past them are in `other`.
    pub entries: alloc::vec::Vec<HotBlock>,
    /// Samples by [`Level`], and those that found the table full.
    pub samples: [u64; Level::COUNT],
    pub other: u64,
    /// The samples that were a block's RET, BLR or BR form's transfer, at
    /// most [`DYNAMIC_SAMPLES`]; those past them are in `dynamic_other`.
    pub dynamic: alloc::vec::Vec<DynamicSample>,
    pub dynamic_other: u64,
}

/// A sampled transfer of a block's RET, BLR or BR form ([`HotBlocks`]):
/// the form and the block's PC, which stands for its site, and the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicSample {
    pub form: DynamicForm,
    pub site: u64,
    pub target: u64,
}

/// A branch to a register's value: RET, BLR, BR, then their PAC forms
/// (RETA*, BLRA*, BRA*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DynamicForm {
    Ret,
    Blr,
    Br,
    Reta,
    Blra,
    Bra,
}

impl DynamicForm {
    pub const ALL: [Self; 6] = [
        Self::Ret,
        Self::Blr,
        Self::Br,
        Self::Reta,
        Self::Blra,
        Self::Bra,
    ];
}

/// The [`DynamicSample`]s one [`HotBlocks`] holds.
pub const DYNAMIC_SAMPLES: usize = 1 << 16;

/// The sites of sampled RET, BLR and BR transfers since the first sample
/// ([`HotBlocks::dynamic`]), each with the first target seen there and
/// whether another followed: whether a one-target inline cache would serve
/// the hot ones. At most [`DYNAMIC_SITES`] sites; samples of further ones
/// are in `untracked`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamicSites {
    sites: alloc::collections::BTreeMap<(DynamicForm, u64), DynamicSite>,
    pub untracked: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DynamicSite {
    target: u64,
    samples: u64,
    targets_differ: bool,
}

/// The sites [`DynamicSites`] tells apart.
pub const DYNAMIC_SITES: usize = 1 << 15;

/// One form's sites with at least two samples ([`DynamicSites::seen`]):
/// how many, how many had one target in every sample, and the samples of
/// each group.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DynamicSeen {
    pub sites: u64,
    pub monomorphic: u64,
    pub samples: u64,
    pub monomorphic_samples: u64,
}

impl DynamicSites {
    pub fn add(&mut self, samples: &[DynamicSample]) {
        for sample in samples {
            let key = (sample.form, sample.site);
            if let Some(site) = self.sites.get_mut(&key) {
                site.samples += 1;
                site.targets_differ |= site.target != sample.target;
            } else if self.sites.len() < DYNAMIC_SITES {
                self.sites.insert(
                    key,
                    DynamicSite {
                        target: sample.target,
                        samples: 1,
                        targets_differ: false,
                    },
                );
            } else {
                self.untracked += 1;
            }
        }
    }

    /// The sites of `form` sampled at least twice.
    pub fn seen(&self, form: DynamicForm) -> DynamicSeen {
        let mut seen = DynamicSeen::default();
        let sites = self.sites.range((form, 0)..=(form, u64::MAX));
        for site in sites.map(|(_, site)| site).filter(|site| site.samples >= 2) {
            seen.sites += 1;
            seen.samples += site.samples;
            if !site.targets_differ {
                seen.monomorphic += 1;
                seen.monomorphic_samples += site.samples;
            }
        }
        seen
    }
}

/// One block's samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HotBlock {
    /// An EL0 block's PC; a kernel or guarded block's PC less the
    /// sampling PE's vector base (wrapping), which moves with the slide.
    pub pc: u64,
    pub level: u8,
    pub count: u64,
}

/// The blocks [`HotBlocks`] holds apart.
pub const HOT_BLOCKS: usize = 8192;
/// One run in this many is sampled.
pub const HOT_SAMPLE_EVERY: u32 = 16;
/// A sampled run's budget is at most this many transfers.
pub const HOT_SAMPLE_SPAN: u64 = 4096;

impl HotBlocks {
    /// Count `count` samples of the block at `pc` at `level`.
    pub fn add(&mut self, pc: u64, level: Level, count: u64) {
        if self.entries.is_empty() {
            self.entries = alloc::vec![HotBlock::default(); HOT_BLOCKS];
        }
        self.samples[level as usize] += count;
        let key = pc ^ (level as u64) << 62;
        let start =
            (key.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (u64::BITS - HOT_BLOCKS.ilog2())) as usize;
        for probe in 0..HOT_BLOCKS / 8 {
            let entry = &mut self.entries[(start + probe) % HOT_BLOCKS];
            if entry.count == 0 {
                *entry = HotBlock {
                    pc,
                    level: level as u8,
                    count: 0,
                };
            }
            if entry.pc == pc && entry.level == level as u8 {
                entry.count += count;
                return;
            }
        }
        self.other += count;
    }

    /// Add every sample `hot` holds.
    pub fn merge(&mut self, hot: &Self) {
        for entry in hot.counted() {
            let level =
                [Level::User, Level::Kernel, Level::Guarded][usize::from(entry.level).min(2)];
            self.add(entry.pc, level, entry.count);
        }
        self.other += hot.other;
        // `add` counted the table's samples by level; the others only here.
        for (level, samples) in self.samples.iter_mut().enumerate() {
            let counted: u64 = hot
                .counted()
                .filter(|e| usize::from(e.level) == level)
                .map(|e| e.count)
                .sum();
            *samples += hot.samples[level] - counted;
        }
        self.add_dynamic(&hot.dynamic);
        self.dynamic_other += hot.dynamic_other;
    }

    /// Keep `samples` of dynamic transfers, as many as fit.
    pub fn add_dynamic(&mut self, samples: &[DynamicSample]) {
        let room = DYNAMIC_SAMPLES.saturating_sub(self.dynamic.len());
        let kept = samples.len().min(room);
        self.dynamic.extend_from_slice(&samples[..kept]);
        self.dynamic_other += (samples.len() - kept) as u64;
    }

    /// The blocks with samples.
    pub fn counted(&self) -> impl Iterator<Item = &HotBlock> {
        self.entries.iter().filter(|entry| entry.count != 0)
    }

    /// The `shown` blocks of `level` with the most samples, most first.
    pub fn top(&self, level: Level, shown: usize) -> alloc::vec::Vec<HotBlock> {
        let mut blocks: alloc::vec::Vec<HotBlock> = self
            .counted()
            .filter(|e| e.level == level as u8)
            .copied()
            .collect();
        blocks.sort_unstable_by(|a, b| b.count.cmp(&a.count).then(a.pc.cmp(&b.pc)));
        blocks.truncate(shown);
        blocks
    }

    pub fn is_empty(&self) -> bool {
        self.samples.iter().all(|&n| n == 0)
    }
}

/// Where a PE's busy time goes in guest terms, under step timing: every
/// phase but [`Phase::Schedule`] charged by the guest's state at the charge
/// (an exit after its handling: an exception entry counts as the level it
/// entered), and the PE's waits for interrupt and event. What the guest's
/// own CPU accounting cannot see apart: its idle path between WFIs and its
/// interrupt handlers run on busy host time too.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Levels {
    /// Ticks by [`Level`].
    pub ticks: [u64; Level::COUNT],
    /// IRQs and FIQs taken, and the ticks charged from taking one until the
    /// next exception return: handlers, and the switch to another thread
    /// when one returns through it.
    pub interrupts: u64,
    pub interrupt_ticks: u64,
    /// WFIs, and those that completed at once with an interrupt pending.
    pub wfi: u64,
    pub wfi_at_once: u64,
    /// WFEs that reached the engine, and those that completed at once with
    /// the event register set (native code completes some itself).
    pub wfe: u64,
    pub wfe_at_once: u64,
    /// WFEs native code completed after spinning for the event register,
    /// spins that ended without it, WFEs that exited without a spin for an
    /// exclusive monitor, and the system counts spins spent
    /// (`x86_64::register_read::event_wait_thunk`).
    pub wfe_spun: u64,
    pub wfe_spin_missed: u64,
    pub wfe_held: u64,
    pub wfe_spin_counts: u64,
    /// At each WFI, the kernel ticks charged since the PE last ran EL0 code
    /// or reached a WFI: wake-ups that found nothing for user code, idle
    /// paths and kernel threads.
    pub kernel_before_wfi: u64,
    /// Between an interrupt's entry and the next exception return.
    pub in_interrupt: bool,
    /// Kernel ticks charged since the PE last ran EL0 code or reached a WFI.
    pub kernel_run: u64,
}

impl Levels {
    /// Charge `spent` busy ticks at `level`.
    #[inline]
    pub(super) fn charge(&mut self, level: Level, spent: u64) {
        self.ticks[level as usize] += spent;
        if self.in_interrupt {
            self.interrupt_ticks += spent;
        }
        if level == Level::User {
            self.kernel_run = 0;
        } else {
            self.kernel_run += spent;
        }
    }

    pub(super) fn interrupt_taken(&mut self) {
        self.interrupts += 1;
        self.in_interrupt = true;
    }

    /// A WFI, which completed at once if `at_once`.
    pub(super) fn wait_for_interrupt(&mut self, at_once: bool) {
        self.wfi += 1;
        self.wfi_at_once += u64::from(at_once);
        self.kernel_before_wfi += core::mem::take(&mut self.kernel_run);
    }

    /// A WFE, which completed at once if `at_once`.
    pub(super) fn wait_for_event(&mut self, at_once: bool) {
        self.wfe += 1;
        self.wfe_at_once += u64::from(at_once);
    }

    /// What native WFEs counted of their spins.
    pub(super) fn event_spins(&mut self, spin: stela_compiler::x86_64::register_read::EventSpin) {
        self.wfe_spun += spin.completed;
        self.wfe_spin_missed += spin.missed;
        self.wfe_held += spin.held;
        self.wfe_spin_counts += spin.counts;
    }

    /// The counts since `earlier`; the state is this one's.
    pub fn since(&self, earlier: &Self) -> Self {
        let mut ticks = self.ticks;
        for (now, then) in ticks.iter_mut().zip(earlier.ticks) {
            *now = now.wrapping_sub(then);
        }
        Self {
            ticks,
            interrupts: self.interrupts.wrapping_sub(earlier.interrupts),
            interrupt_ticks: self.interrupt_ticks.wrapping_sub(earlier.interrupt_ticks),
            wfi: self.wfi.wrapping_sub(earlier.wfi),
            wfi_at_once: self.wfi_at_once.wrapping_sub(earlier.wfi_at_once),
            wfe: self.wfe.wrapping_sub(earlier.wfe),
            wfe_at_once: self.wfe_at_once.wrapping_sub(earlier.wfe_at_once),
            wfe_spun: self.wfe_spun.wrapping_sub(earlier.wfe_spun),
            wfe_spin_missed: self.wfe_spin_missed.wrapping_sub(earlier.wfe_spin_missed),
            wfe_held: self.wfe_held.wrapping_sub(earlier.wfe_held),
            wfe_spin_counts: self.wfe_spin_counts.wrapping_sub(earlier.wfe_spin_counts),
            kernel_before_wfi: self
                .kernel_before_wfi
                .wrapping_sub(earlier.kernel_before_wfi),
            ..*self
        }
    }
}

/// Whether `word` is ERET, ERETAA or ERETAB.
pub fn exception_return(word: u32) -> bool {
    matches!(word, 0xd69f_03e0 | 0xd69f_0bff | 0xd69f_0fff)
}

/// Host ticks spent so far, by phase and by exit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StepTiming {
    pub phases: [u64; Phase::COUNT],
    /// Lifetime maxima since timing was enabled or reset. A zero interval
    /// has no witness. These are held, not subtracted, by [`Self::since`].
    pub lifetime_maxima: [Maximum; Phase::COUNT],
    /// Exits handled and the ticks handling them, by `ExitKind` value, then
    /// native faults by cause ([`fault_slot`]).
    pub exits: [(u64, u64); EXIT_SLOTS],
    /// What the native check fault being handled found, which its exit is
    /// charged to ([`Check`]).
    pub check: Option<Check>,
    /// Busy time in guest terms ([`Levels`]).
    pub levels: Levels,
}

impl StepTiming {
    /// Cumulative phase/exit totals spent since `earlier`, keeping the
    /// current lifetime maximum snapshots. An interval maximum cannot be
    /// derived by subtracting maxima.
    pub fn since(&self, earlier: &Self) -> Self {
        let mut delta = *self;
        for (now, then) in delta.phases.iter_mut().zip(earlier.phases) {
            *now = now.wrapping_sub(then);
        }
        for (now, then) in delta.exits.iter_mut().zip(earlier.exits) {
            *now = (now.0.wrapping_sub(then.0), now.1.wrapping_sub(then.1));
        }
        delta.levels = self.levels.since(&earlier.levels);
        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAULT_SLOT: usize = FAULT_SLOTS + 1;

    /// Each System exit key falls in the class of what it does.
    #[test]
    fn system_keys_fall_in_the_class_of_what_they_do() {
        let cases = [
            (DEVICE_SITE_KEY, SystemClass::Device),
            (0x0020_0c20, SystemClass::Compression),
            (0xd503_3b80, SystemClass::Barrier),
            (0xd508_83a0, SystemClass::Maintenance),
            (0xd508_7500, SystemClass::Maintenance),
            (0xd503_2040, SystemClass::Wait),
            (0xd51b_e300, SystemClass::Timer),
            (0xd53a_f000, SystemClass::ImplementationDefined),
            (0xd51d_f000, SystemClass::ImplementationDefined),
            (0xd518_2000, SystemClass::TranslationControl),
            (0xd518_1000, SystemClass::TranslationControl),
            (0xd69f_03e0, SystemClass::Transition),
            (0xd400_1001, SystemClass::Transition),
            (0xd503_47e0, SystemClass::Other),
        ];
        for (key, class) in cases {
            let name = system_key_name(key);
            assert_eq!(SystemClass::of(key), class, "{key:#010x} {name}");
        }
    }

    #[test]
    fn hot_blocks_rank_by_samples_per_level_and_merge() {
        let mut hot = HotBlocks::default();
        assert!(hot.is_empty());
        hot.add(0x1000, Level::Kernel, 3);
        hot.add(0x2000, Level::Kernel, 5);
        // The same PC at another level is another block.
        hot.add(0x1000, Level::User, 7);
        let top = hot.top(Level::Kernel, 8);
        assert_eq!(
            top.iter()
                .map(|b| (b.pc, b.count))
                .collect::<alloc::vec::Vec<_>>(),
            [(0x2000, 5), (0x1000, 3)]
        );
        assert_eq!(hot.top(Level::User, 8)[0].count, 7);
        assert_eq!(hot.samples, [7, 8, 0]);
        let mut merged = HotBlocks::default();
        merged.add(0x2000, Level::Kernel, 1);
        merged.merge(&hot);
        assert_eq!(
            merged.top(Level::Kernel, 1)[0],
            HotBlock {
                pc: 0x2000,
                level: Level::Kernel as u8,
                count: 6
            }
        );
        assert_eq!(merged.samples, [7, 9, 0]);
    }

    /// One run in HOT_SAMPLE_EVERY gets a drawn budget; a sampled run whose
    /// budget ran out names the block it ended in, and nothing is sampled
    /// without step timing.
    #[test]
    fn a_sampled_run_whose_budget_ran_out_names_its_last_block() {
        use super::super::{NativeExit, chain::ChainControl};
        use stela_compiler::block::ExitKind;
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        let mut machine = super::super::tests::machine(&[ADD, 0x1400_0002, 0, ADD, 0x17ff_fffc]);
        let base = machine.cpu.pc;
        let direct = |next_pc| NativeExit::Exit {
            next_pc,
            kind: ExitKind::Direct as u64,
        };
        let run = |machine: &mut crate::machine::Machine<
            super::super::tests::FakeHost,
            crate::machine::NoDevices,
        >,
                   runs: u32| {
            for _ in 0..runs {
                let next = if machine.cpu.pc == base {
                    base + 12
                } else {
                    base
                };
                let current = machine.chain.snapshot();
                machine.host.chained = Some((
                    machine.chain.address() as *mut ChainControl,
                    ChainControl {
                        count: ChainControl::exhausted(0),
                        block: 1,
                        ..current
                    },
                ));
                machine.host.exits = alloc::vec![direct(next)];
                machine.step().unwrap();
            }
        };
        // Both blocks compiled, then runs that all spend their budget.
        machine.slice_end = u64::MAX;
        machine.block_limit = u64::MAX;
        machine.host.exits = alloc::vec![direct(base + 12), direct(base)];
        machine.step().unwrap();
        machine.step().unwrap();
        run(&mut machine, 2 * HOT_SAMPLE_EVERY);
        assert!(!machine.has_hot_samples(), "no samples without step timing");
        // Kernel PCs are kept as offsets from the vector base of their EL.
        const VBAR: u64 = 0x800;
        for register in [
            crate::machine::system::Register::VBAR_EL1,
            crate::machine::system::Register::VBAR_EL2,
        ] {
            machine.cpu.registers.set(register, 0, VBAR);
        }
        let expected =
            if Level::of(machine.cpu.pstate.el, machine.cpu.pstate.guarded) == Level::User {
                base + 12
            } else {
                (base + 12).wrapping_sub(VBAR)
            };
        machine.set_step_timing(true);
        run(&mut machine, 2 * HOT_SAMPLE_EVERY);
        let mut hot = HotBlocks::default();
        machine.take_hot_samples(&mut hot);
        let total: u64 = hot.samples.iter().sum();
        assert_eq!(total, 2);
        let pcs: alloc::vec::Vec<u64> = hot.counted().map(|block| block.pc).collect();
        assert_eq!(pcs, [expected]);
        assert!(!machine.has_hot_samples());
        // Draws stay within the span and below the run's own budget.
        for _ in 0..1000 {
            let (budget, sampled) = machine.sampled_budget(HOT_SAMPLE_SPAN + 1);
            assert!((1..=HOT_SAMPLE_SPAN + 1).contains(&budget));
            assert_eq!(sampled, budget <= HOT_SAMPLE_SPAN);
        }
    }

    /// Sites sampled once are not judged; a site whose samples all named
    /// one target is monomorphic; the forms are counted apart; a merge
    /// keeps the samples of both, as many as fit.
    #[test]
    fn dynamic_sites_tell_one_target_sites_apart() {
        let sample = |form, site, target| DynamicSample { form, site, target };
        let mut hot = HotBlocks::default();
        hot.add_dynamic(&[
            sample(DynamicForm::Ret, 0x100, 0x500),
            sample(DynamicForm::Ret, 0x100, 0x500),
            sample(DynamicForm::Ret, 0x100, 0x500),
            sample(DynamicForm::Ret, 0x200, 0x600),
            sample(DynamicForm::Ret, 0x200, 0x604),
            sample(DynamicForm::Ret, 0x300, 0x700),
            sample(DynamicForm::Blr, 0x100, 0x800),
            sample(DynamicForm::Blr, 0x100, 0x800),
        ]);
        let mut merged = HotBlocks::default();
        merged.merge(&hot);
        assert_eq!(merged.dynamic, hot.dynamic);
        let mut sites = DynamicSites::default();
        sites.add(&merged.dynamic);
        let seen = |sites: &DynamicSites, form| {
            let seen = sites.seen(form);
            [
                seen.sites,
                seen.monomorphic,
                seen.samples,
                seen.monomorphic_samples,
            ]
        };
        assert_eq!(seen(&sites, DynamicForm::Ret), [2, 1, 5, 3]);
        assert_eq!(seen(&sites, DynamicForm::Blr), [1, 1, 2, 2]);
        assert_eq!(seen(&sites, DynamicForm::Br), [0; 4]);
        let mut full = HotBlocks {
            dynamic: alloc::vec![sample(DynamicForm::Br, 0, 0); DYNAMIC_SAMPLES - 1],
            ..HotBlocks::default()
        };
        full.add_dynamic(&hot.dynamic[..2]);
        assert_eq!(
            (full.dynamic.len(), full.dynamic_other),
            (DYNAMIC_SAMPLES, 1)
        );
    }

    #[test]
    fn hot_blocks_count_what_the_table_cannot_hold_as_other() {
        let mut hot = HotBlocks::default();
        for pc in 0..(HOT_BLOCKS as u64 + 100) {
            hot.add(pc * 4, Level::Kernel, 1);
        }
        let held: u64 = hot.counted().map(|e| e.count).sum();
        assert_eq!(held + hot.other, HOT_BLOCKS as u64 + 100);
        assert_eq!(hot.samples[Level::Kernel as usize], HOT_BLOCKS as u64 + 100);
        let mut merged = HotBlocks::default();
        merged.merge(&hot);
        assert_eq!(merged.samples, hot.samples);
    }

    #[test]
    fn system_keys_drop_registers_and_name_the_instruction() {
        // MRS X1 and X30, TPIDR_EL1: one key, the accessor's name.
        assert_eq!(system_key(0xd538_d081), system_key(0xd538_d09e));
        assert_eq!(system_key(0xd538_d081), 0xd538_d080);
        assert_eq!(system_key_name(0xd538_d080), "MRS_TPIDR_EL1");
        assert_eq!(system_key_name(0xd518_c000), "MSR_VBAR_EL1");
        // TLBI VAE1IS, X0.
        assert_eq!(system_key_name(system_key(0xd508_8320)), "TLBI_VAE1IS");
        // An Apple register without an accessor: its encoding.
        assert_eq!(system_key_name(0xd53c_f200), "MRS_S3_4_C15_C2_0");
        assert_eq!(
            system_key_name(0xd69f_03e0),
            "Exception.ExceptionReturn:0xd69f03e0"
        );
        assert_eq!(system_key_name(DEVICE_SITE_KEY), "device-site");
        // LDXR W1, [X2] and LDXR W3, [X4]: one key.
        assert_eq!(system_key(0x885f_7c41), system_key(0x885f_7c83));
    }

    #[test]
    fn system_exits_count_by_key_and_keep_the_rest_in_other() {
        let mut exits = SystemExits::default();
        assert!(exits.is_empty());
        for key in 0..SYSTEM_KEYS as u32 + 2 {
            exits.add(key, 1, 10, u64::from(key == 0));
        }
        exits.add(0, 1, 5, 0);
        let first = exits.counted().find(|exit| exit.key == 0).unwrap();
        assert_eq!((first.count, first.ticks, first.closes), (2, 15, 1));
        assert_eq!(exits.counted().count(), SYSTEM_KEYS);
        assert_eq!((exits.other.count, exits.other.ticks), (2, 20));
        let mut merged = SystemExits::default();
        merged.merge(&exits);
        merged.merge(&exits);
        let first = merged.counted().find(|exit| exit.key == 0).unwrap();
        assert_eq!((first.count, first.closes), (4, 2));
        assert_eq!(merged.other.count, 4);
    }

    /// Registers count apart by address and direction, the ones past the
    /// table in `other_registers`, and merge.
    #[test]
    fn device_exits_count_by_register_and_direction() {
        let mut exits = DeviceExits::default();
        const REGISTER: u64 = 0x2_3b0c_8000;
        let exit = |register, ticks, waited, access, settle| DeviceRegisterExit {
            register,
            count: 1,
            ticks,
            waited,
            access,
            settle,
            ..DeviceRegisterExit::default()
        };
        exits.add_register(exit(REGISTER, 10, 2, 0, 0));
        exits.add_register(exit(REGISTER | DEVICE_REGISTER_WRITE, 20, 0, 6, 9));
        exits.add_register(exit(REGISTER, 5, 1, 0, 0));
        for index in 0..DEVICE_REGISTERS as u64 {
            exits.add_register(exit(0x1000 + index * 4, 1, 0, 0, 0));
        }
        let count = |exits: &DeviceExits, register| {
            exits
                .counted_registers()
                .find(|exit| exit.register == register)
                .map(|exit| {
                    (
                        exit.count,
                        exit.ticks,
                        exit.waited,
                        exit.access,
                        exit.settle,
                    )
                })
        };
        assert_eq!(count(&exits, REGISTER), Some((2, 15, 3, 0, 0)));
        assert_eq!(
            count(&exits, REGISTER | DEVICE_REGISTER_WRITE),
            Some((1, 20, 0, 6, 9))
        );
        assert_eq!(exits.other_registers.count, 2);
        let mut merged = DeviceExits::default();
        merged.merge(&exits);
        merged.merge(&exits);
        assert_eq!(count(&merged, REGISTER), Some((4, 30, 6, 0, 0)));
        let total: u64 = merged.counted_registers().map(|exit| exit.count).sum();
        assert_eq!(
            total + merged.other_registers.count,
            2 * (3 + DEVICE_REGISTERS as u64)
        );
    }

    #[test]
    fn regime_syncs_merge() {
        let regimes = RegimeSyncs {
            syncs: 3,
            sync_ticks: 30,
            isolations: 1,
            isolation_ticks: 7,
            unchanged: 2,
            sources: [1, 0, 0, 0, 2, 0, 0],
        };
        let exits = SystemExits {
            regimes,
            ..SystemExits::default()
        };
        assert!(!exits.is_empty());
        let mut merged = SystemExits::default();
        merged.merge(&exits);
        merged.merge(&exits);
        assert_eq!(
            merged.regimes,
            RegimeSyncs {
                syncs: 6,
                sync_ticks: 60,
                isolations: 2,
                isolation_ticks: 14,
                unchanged: 4,
                sources: [2, 0, 0, 0, 4, 0, 0],
            }
        );
    }

    #[test]
    fn barrier_waits_count_quick_ones_apart_and_merge_by_blocker() {
        let system = stela_compiler::block::ExitKind::System as usize;
        let mut waits = BarrierWaits::default();
        waits.add(None, 3);
        waits.add(Some(BLOCKER_NATIVE), 10);
        let dsb = exit_blocker(system, Some(0xd503_3b9f));
        assert_eq!(dsb, exit_blocker(system, Some(0xd503_3b80)));
        waits.add(Some(dsb), 20);
        for key in 0..BARRIER_BLOCKERS as u64 {
            waits.add(Some(BLOCKER_EXIT | key << 32), 1);
        }
        assert_eq!((waits.waits, waits.quick, waits.ticks), (35, 1, 65));
        assert_eq!(waits.other.count, 2);
        let exits = SystemExits {
            barriers: waits,
            ..SystemExits::default()
        };
        assert!(!exits.is_empty());
        let mut merged = SystemExits::default();
        merged.merge(&exits);
        merged.merge(&exits);
        let merged = merged.barriers;
        assert_eq!((merged.waits, merged.quick, merged.ticks), (70, 2, 130));
        let native = merged
            .blockers
            .iter()
            .find(|b| b.key == BLOCKER_NATIVE)
            .unwrap();
        assert_eq!((native.count, native.ticks), (2, 20));
        let dsb = merged.blockers.iter().find(|b| b.key == dsb).unwrap();
        assert_eq!((dsb.count, dsb.ticks), (2, 40));
        assert_eq!(merged.other.count, 4);
    }

    #[test]
    fn device_exits_count_by_page_and_merge_with_forwards() {
        let mut exits = DeviceExits::default();
        assert!(exits.is_empty());
        assert_eq!(device_page(0x2_3b0c_8000), device_page(0x2_3b0c_8ffc));
        assert_ne!(device_page(0x2_3b0c_8000), device_page(0x2_3b0c_6658));
        for page in 0..DEVICE_PAGES as u32 + 3 {
            exits.add(page, 1, 10, 2);
        }
        exits.add(0, 1, 5, 1);
        exits.forwarded = 1;
        exits.forwarded_ticks = 7;
        let first = *exits.counted().find(|exit| exit.page == 0).unwrap();
        assert_eq!((first.count, first.ticks, first.waited), (2, 15, 3));
        assert_eq!(exits.counted().count(), DEVICE_PAGES);
        assert_eq!((exits.other.count, exits.other.waited), (3, 6));
        let system = SystemExits {
            devices: exits,
            ..SystemExits::default()
        };
        assert!(!system.is_empty());
        let mut merged = SystemExits::default();
        merged.merge(&system);
        merged.merge(&system);
        let first = *merged
            .devices
            .counted()
            .find(|exit| exit.page == 0)
            .unwrap();
        assert_eq!((first.count, first.waited), (4, 6));
        assert_eq!(
            (merged.devices.forwarded, merged.devices.forwarded_ticks),
            (2, 14)
        );
    }

    #[test]
    fn a_system_exit_is_charged_to_its_key_with_the_cells_it_closed() {
        use super::super::tests::BASE;
        const MRS_X1_TPIDR_EL1: u32 = 0xd538_d081;
        const MSR_VBAR_EL1_X2: u32 = 0xd518_c002;
        let mut machine = super::super::tests::machine(&[MRS_X1_TPIDR_EL1, MSR_VBAR_EL1_X2]);
        machine.set_step_timing(true);
        machine.cpu.state.x[2] = BASE + 0x800;
        for pc in [BASE, BASE + 4] {
            machine.host.exits.push(super::super::NativeExit::Exit {
                next_pc: pc,
                kind: stela_compiler::block::ExitKind::System as u64,
            });
            machine.step().unwrap();
        }
        assert_eq!(machine.cpu.pc, BASE + 8);
        let system = stela_compiler::block::ExitKind::System as usize;
        assert_eq!(machine.step_timing().unwrap().exits[system].0, 2);
        let exits = machine.take_system_exits();
        let key = |key| *exits.counted().find(|exit| exit.key == key).unwrap();
        // The read changed nothing; the VBAR_EL1 write closed every cell.
        assert_eq!((key(0xd538_d080).count, key(0xd538_d080).closes), (1, 0));
        assert_eq!((key(0xd518_c000).count, key(0xd518_c000).closes), (1, 1));
        assert!(machine.take_system_exits().is_empty());
    }

    /// A floating-point exit is charged to its whole word, which the report
    /// tells from System keys, and stays out of the System words.
    #[test]
    fn a_floating_point_exit_is_charged_to_its_word() {
        use super::super::tests::BASE;
        const FADD_S0_S1_S2: u32 = 0x1e22_2820;
        const FCVTNU_8H: u32 = 0x6e79_aa67;
        let mut machine = super::super::tests::machine(&[FADD_S0_S1_S2]);
        machine.set_step_timing(true);
        // FP/SIMD enabled at EL1 (CPACR_EL1.FPEN).
        machine
            .cpu
            .registers
            .set(crate::machine::system::Register::CPACR_EL1, 0, 0b11 << 20);
        machine.host.exits.push(super::super::NativeExit::Exit {
            next_pc: BASE,
            kind: stela_compiler::block::ExitKind::FloatingPoint as u64,
        });
        machine.step().unwrap();
        assert_eq!(machine.cpu.pc, BASE + 4);
        let slot = stela_compiler::block::ExitKind::FloatingPoint as usize;
        assert_eq!(machine.step_timing().unwrap().exits[slot].0, 1);
        let exits = machine.take_system_exits();
        let exit = *exits
            .counted()
            .find(|exit| exit.key == FADD_S0_S1_S2)
            .unwrap();
        assert_eq!(exit.count, 1);
        assert!(numerical_key(FADD_S0_S1_S2) && numerical_key(FCVTNU_8H));
        assert!(!numerical_key(0xd538_d080) && !numerical_key(DEVICE_SITE_KEY));
        assert!(system_key_name(FCVTNU_8H).ends_with(":0x6e79aa67"));
        assert!(!machine.system_words().contains_key(&FADD_S0_S1_S2));
        // Zeros add exactly: no fresh flag.
        assert_eq!(exits.floating[FloatingReason::Exact as usize], 1);
        assert_eq!(exits.floating.iter().sum::<u64>(), 1);
        // Its word counts the reason, the zero operands and the clear IXC.
        let word = *exits
            .floating_words
            .counted()
            .find(|word| word.key == FADD_S0_S1_S2)
            .unwrap();
        assert_eq!(word.count(), 1);
        assert_eq!(word.reasons[FloatingReason::Exact as usize], 1);
        assert_eq!(word.inexact_clear, 1);
        assert_eq!(word.operands[Operands::Zero as usize], 1);
        assert_eq!(word.operands[Operands::Ordinary as usize], 1);
        assert_eq!(word.operands[Operands::Subnormal as usize], 0);
    }

    /// A pointer authentication exit is charged to its word, which the
    /// report tells from System and floating-point keys, and stays out of
    /// the System words.
    #[test]
    fn a_pointer_authentication_exit_is_charged_to_its_word() {
        use super::super::tests::BASE;
        const RETAA: u32 = 0xd65f_0bff;
        // PACIASP, a hint whose key clears Rt.
        const PACIASP: u32 = 0xd503_233f;
        let mut machine = super::super::tests::machine(&[RETAA]);
        machine.set_step_timing(true);
        machine.cpu.state.x[30] = BASE + 0x40;
        machine.host.exits.push(super::super::NativeExit::Exit {
            next_pc: BASE,
            kind: stela_compiler::block::ExitKind::PointerAuthentication as u64,
        });
        let _ = machine.step();
        let slot = stela_compiler::block::ExitKind::PointerAuthentication as usize;
        assert_eq!(machine.step_timing().unwrap().exits[slot].0, 1);
        let exits = machine.take_system_exits();
        let exit = *exits.counted().find(|exit| exit.key == RETAA).unwrap();
        assert_eq!(exit.count, 1);
        assert!(!machine.system_words().contains_key(&RETAA));
        assert!(pointer_key(RETAA) && pointer_key(system_key(PACIASP)));
        assert!(system_key_name(RETAA).starts_with("PAC."));
        assert!(system_key_name(system_key(PACIASP)).starts_with("PAC."));
        assert!(!pointer_key(0xd538_d080) && !pointer_key(DEVICE_SITE_KEY));
        assert!(!pointer_key(0x1e22_2820) && !numerical_key(RETAA));
    }

    /// The census names what the operands of an exit held: subnormal, NaN
    /// and zero source lanes, an indexed source's one lane, a tiny result,
    /// and forms it does not read.
    #[test]
    fn a_floating_point_census_classifies_operands() {
        use stela_compiler::{GuestState, aarch64::FloatingPointOperation};
        // FMLA V29.4S, V26.4S, V21.S[1].
        const FMLA_INDEXED_4S: u32 = 0x4fb5_135d;
        // SCVTF D0, X0.
        const SCVTF_D0_X0: u32 = 0x9e62_0000;
        const ONE: u64 = 0x3f80_0000;
        const SUBNORMAL: u64 = 0x0000_0001;
        const NAN: u64 = 0x7fc0_0000;
        let decode = |word| match FloatingPointOperation::decode(word) {
            Some(Ok(operation)) => operation,
            other => panic!("{word:#x}: {other:?}"),
        };
        let fmla = decode(FMLA_INDEXED_4S);
        let ones = ONE | ONE << 32;
        let bit = |class: Operands| 1u8 << class as u8;
        let mut state = GuestState::default();
        state.v[26] = [ones, ones];
        state.v[29] = [ones, ones];
        // Only lane 1 of V21 is read: a NaN in lane 0 is not.
        state.v[21] = [NAN | ONE << 32, NAN | NAN << 32];
        let census = FloatingCensus::read(&state, &fmla);
        assert_eq!(census.finish(&state, true), bit(Operands::Ordinary));
        // A subnormal lane of V26 and a tiny result lane.
        state.v[26][1] = ONE | SUBNORMAL << 32;
        let census = FloatingCensus::read(&state, &fmla);
        state.v[29][0] = SUBNORMAL;
        assert_eq!(
            census.finish(&state, true),
            bit(Operands::Subnormal) | bit(Operands::Tiny)
        );
        // A trapped completion's result is not read.
        state.v[29] = [ones, ones];
        let census = FloatingCensus::read(&state, &fmla);
        state.v[29][0] = SUBNORMAL;
        assert_eq!(census.finish(&state, false), bit(Operands::Subnormal));
        // NaN and zero in the addend.
        state.v[26] = [ones, ones];
        state.v[29] = [NAN, ones];
        let census = FloatingCensus::read(&state, &fmla);
        state.v[29] = [ones, ones];
        assert_eq!(
            census.finish(&state, true),
            bit(Operands::Nan) | bit(Operands::Zero)
        );
        let scvtf = decode(SCVTF_D0_X0);
        let census = FloatingCensus::read(&state, &scvtf);
        assert_eq!(census.finish(&state, true), bit(Operands::Unread));
    }

    #[test]
    fn floating_words_count_by_word_and_keep_the_rest_in_other() {
        let mut words = FloatingWords::default();
        assert!(words.is_empty());
        let subnormal = 1 << Operands::Subnormal as u8;
        for key in 0..FLOATING_WORDS as u32 + 2 {
            words.add(key, FloatingReason::Exact, false, subnormal, true);
        }
        words.add(0, FloatingReason::Inexact, true, subnormal, false);
        let first = *words.counted().find(|word| word.key == 0).unwrap();
        assert_eq!(first.count(), 2);
        assert_eq!(first.reasons[FloatingReason::Mode as usize], 1);
        assert_eq!(first.operands[Operands::Subnormal as usize], 2);
        assert_eq!(first.inexact_clear, 1);
        assert_eq!(words.counted().count(), FLOATING_WORDS);
        assert_eq!(words.other.count(), 2);
        let exits = SystemExits {
            floating_words: words,
            ..SystemExits::default()
        };
        assert!(!exits.is_empty());
        let mut merged = SystemExits::default();
        merged.merge(&exits);
        merged.merge(&exits);
        let first = *merged
            .floating_words
            .counted()
            .find(|word| word.key == 0)
            .unwrap();
        assert_eq!((first.count(), first.inexact_clear), (4, 2));
        assert_eq!(merged.floating_words.other.count(), 4);
    }

    /// The reason counter keeps FPSR as the completion leaves it: earlier
    /// flags stay, fresh ones are added, and the first fresh one names it.
    #[test]
    fn a_floating_point_exit_reason_keeps_fpsr() {
        use super::super::tests::BASE;
        const FDIV_S0_S1_S2: u32 = 0x1e22_1820;
        const INEXACT: u32 = 1 << 4;
        let mut machine = super::super::tests::machine(&[FDIV_S0_S1_S2]);
        machine.set_step_timing(true);
        machine
            .cpu
            .registers
            .set(crate::machine::system::Register::CPACR_EL1, 0, 0b11 << 20);
        machine.cpu.state.fpsr = INEXACT;
        // 1 / 0: divide by zero.
        machine.cpu.state.v[1] = [0x3f80_0000, 0];
        machine.host.exits.push(super::super::NativeExit::Exit {
            next_pc: BASE,
            kind: stela_compiler::block::ExitKind::FloatingPoint as u64,
        });
        machine.step().unwrap();
        assert_eq!(machine.cpu.state.fpsr, INEXACT | 1 << 1);
        assert_eq!(machine.cpu.state.v[0][0], 0x7f80_0000);
        let exits = machine.take_system_exits();
        assert_eq!(exits.floating[FloatingReason::Divide as usize], 1);
        assert_eq!(FloatingReason::of(0, 0x11, false), FloatingReason::Invalid);
        assert_eq!(FloatingReason::of(1 << 8, 0, false), FloatingReason::Trap);
        assert_eq!(
            FloatingReason::of(0, 0x18, false),
            FloatingReason::Underflow
        );
        assert_eq!(FloatingReason::of(0, 0x10, false), FloatingReason::Inexact);
    }

    /// Busy phases go to the guest level they were charged at, the kernel
    /// run before a WFI is kept at it, and an interrupt's ticks end with
    /// its exception return, whose own ticks count.
    #[test]
    fn busy_time_is_split_by_level_wait_and_interrupt() {
        use super::super::tests::{machine_on, one_timer_bank};
        const WFI: u32 = 0xd503_207f;
        let mut machine = machine_on(one_timer_bank(), &[]);
        machine.set_step_timing(true);
        machine.cpu.pstate.el = 0;
        machine.host.now = 10;
        machine.timing_charge(Phase::Native, 0);
        machine.cpu.pstate.el = 1;
        machine.host.now = 30;
        machine.timing_charge(Phase::Fetch, 10);
        machine.host.now = 100;
        machine.timing_charge(Phase::Schedule, 30);
        machine.cpu.pstate.guarded = true;
        machine.host.now = 105;
        machine.timing_charge(Phase::Native, 100);
        machine.cpu.pstate.guarded = false;
        let levels = machine.step_timing().unwrap().levels;
        assert_eq!(levels.ticks, [10, 20, 5]);
        assert_eq!(levels.kernel_run, 25);
        // Nothing pending: the WFI waits, and takes the kernel run.
        machine.lines();
        machine.system_instruction(WFI).unwrap();
        assert!(machine.waiting.is_some());
        machine.waiting = None;
        let levels = machine.step_timing().unwrap().levels;
        assert_eq!((levels.wfi, levels.wfi_at_once), (1, 0));
        assert_eq!((levels.kernel_before_wfi, levels.kernel_run), (25, 0));
        // An expired virtual timer's FIQ, taken, then its handler's return.
        machine.cpu.state.x[0] = 1500;
        machine.system_instruction(0xd51b_e300).unwrap(); // msr cntv_tval_el0, x0
        machine.cpu.state.x[0] = 1;
        machine.system_instruction(0xd51b_e320).unwrap(); // msr cntv_ctl_el0, x0
        machine.host.now = 2000;
        machine.lines();
        // Pending though masked: a WFI completes at once.
        machine.cpu.pstate.daif = 0xf;
        machine.system_instruction(WFI).unwrap();
        assert!(machine.waiting.is_none());
        machine.cpu.pstate.daif = 0;
        assert!(machine.deliver_interrupts());
        machine.host.now = 2007;
        machine.timing_charge(Phase::Native, 2000);
        machine.timed_word = Some(0xd69f_03e0);
        machine.host.now = 2010;
        machine.timing_exit(stela_compiler::block::ExitKind::System as usize, 2007);
        machine.host.now = 2050;
        machine.timing_charge(Phase::Native, 2010);
        let levels = machine.step_timing().unwrap().levels;
        assert_eq!((levels.wfi, levels.wfi_at_once), (2, 1));
        assert_eq!((levels.interrupts, levels.interrupt_ticks), (1, 10));
        assert!(!levels.in_interrupt);
        // A delta keeps the state and subtracts the counts.
        let delta = levels.since(&Levels {
            wfi: 1,
            ticks: [10, 0, 0],
            ..Levels::default()
        });
        assert_eq!((delta.wfi, delta.ticks[0]), (1, 0));
        assert_eq!(delta.kernel_run, levels.kernel_run);
        assert!(exception_return(0xd69f_0bff) && !exception_return(0xd65f_03c0));
    }

    #[test]
    fn a_delta_subtracts_each_phase_and_exit() {
        let mut earlier = StepTiming::default();
        earlier.phases[Phase::Exit as usize] = 5;
        earlier.exits[FAULT_SLOT] = (1, 10);
        earlier.lifetime_maxima[Phase::Exit as usize].observe(5, 50, 0x1000, 1, 2);
        let mut now = earlier;
        now.phases[Phase::Exit as usize] = 12;
        now.exits[FAULT_SLOT] = (3, 40);
        now.lifetime_maxima[Phase::Exit as usize].observe(9, 90, 0x2000, 2, 3);
        let delta = now.since(&earlier);
        assert_eq!(delta.phases[Phase::Exit as usize], 7);
        assert_eq!(delta.exits[FAULT_SLOT], (2, 30));
        assert_eq!(delta.phases[Phase::Native as usize], 0);
        assert_eq!(delta.lifetime_maxima, now.lifetime_maxima);
        let later_delta = now.since(&now);
        assert_eq!(later_delta.phases, [0; Phase::COUNT]);
        assert_eq!(later_delta.lifetime_maxima, now.lifetime_maxima);
    }

    #[test]
    fn completed_phase_maxima_keep_their_materialized_witness_and_clock_samples() {
        let mut machine = super::super::tests::machine(&[]);
        machine.set_step_timing(true);
        let reads = machine.host.counter_reads;
        machine.host.now = 100;
        machine.cpu.pc = 0x4000;
        machine.cpu.pstate.el = 1;
        machine.cpu.pstate.daif = 2;
        assert_eq!(machine.timing_charge(Phase::Fetch, 90), 100);
        let first = Maximum {
            ticks: 10,
            finished_ticks: 100,
            pc_after: 0x4000,
            el_after: 1,
            daif_after: 2,
        };
        assert_eq!(
            machine.step_timing().unwrap().lifetime_maxima[Phase::Fetch as usize],
            first
        );
        machine.host.now = 115;
        machine.cpu.pc = 0x5000;
        machine.timing_charge(Phase::Fetch, 110);
        machine.host.now = 125;
        machine.timing_charge(Phase::Fetch, 115);
        // Smaller and tied intervals preserve the original witness.
        assert_eq!(
            machine.step_timing().unwrap().lifetime_maxima[Phase::Fetch as usize],
            first
        );
        machine.host.now = 200;
        machine.cpu.pstate.el = 2;
        machine.cpu.pstate.daif = 15;
        machine.timing_charge(Phase::Fetch, 150);
        let timing = machine.step_timing().unwrap();
        assert_eq!(timing.phases[Phase::Fetch as usize], 75);
        assert_eq!(
            timing.lifetime_maxima[Phase::Fetch as usize],
            Maximum {
                ticks: 50,
                finished_ticks: 200,
                pc_after: 0x5000,
                el_after: 2,
                daif_after: 15
            }
        );
        // Exit/fault accounting uses its existing sample too, including wrap.
        machine.host.now = 4;
        machine.timing_exit(FAULT_SLOT, u64::MAX - 8);
        let timing = machine.step_timing().unwrap();
        assert_eq!(timing.exits[FAULT_SLOT], (1, 13));
        assert_eq!(timing.phases[Phase::Exit as usize], 13);
        assert_eq!(
            timing.lifetime_maxima[Phase::Exit as usize],
            Maximum {
                ticks: 13,
                finished_ticks: 4,
                pc_after: 0x5000,
                el_after: 2,
                daif_after: 15
            }
        );
        assert_eq!(machine.host.counter_reads - reads, 5);
    }

    #[test]
    fn a_device_faults_ticks_go_to_the_register_it_reached() {
        const REGISTER: u64 = 0x2_3520_0018;
        let mut machine = super::super::tests::machine(&[]);
        machine.set_step_timing(true);
        machine.count_device_access(REGISTER);
        machine.host.now = 30;
        machine.timing_exit(DEVICE_FAULT_SLOT, 10);
        // Another exit's ticks are not the register's, even after an
        // access it did not fault for.
        machine.count_device_access(REGISTER);
        machine.host.now = 100;
        machine.timing_exit(FAULT_SLOTS, 40);
        machine.host.now = 120;
        machine.timing_exit(DEVICE_FAULT_SLOT, 110);
        assert_eq!(
            machine.device_registers()[&REGISTER],
            super::super::DeviceRegister {
                accesses: 2,
                ticks: 20
            }
        );
    }

    /// A native check fault is charged to what the engine found at it, once;
    /// another exit keeps its slot and leaves the finding alone.
    #[test]
    fn check_faults_are_charged_by_outcome() {
        assert_eq!(
            fault_slot(&super::super::FaultCause::NonCanonical),
            CHECK_FAULT_SLOT
        );
        let slots = [
            Check::Tagged,
            Check::Alignment,
            Check::Abort,
            Check::Translated,
        ]
        .map(Check::slot);
        assert_eq!(slots, [19, 20, 21, 22]);
        assert_eq!(EXIT_SLOTS, 23);
        let mut machine = super::super::tests::machine(&[]);
        machine.set_step_timing(true);
        machine.timed_check(Check::Tagged);
        machine.timing_exit(CHECK_FAULT_SLOT, 0);
        machine.timing_exit(CHECK_FAULT_SLOT, 0);
        machine.timed_check(Check::Abort);
        machine.timing_exit(FAULT_SLOTS, 0);
        let exits = machine.step_timing().unwrap().exits;
        assert_eq!(exits[Check::Tagged.slot()].0, 1);
        assert_eq!(exits[CHECK_FAULT_SLOT].0, 1);
        assert_eq!(exits[FAULT_SLOTS].0, 1);
        assert_eq!(exits[Check::Abort.slot()].0, 0);
        assert_eq!(machine.step_timing().unwrap().check, None);
    }

    #[test]
    fn resetting_timing_clears_maxima_and_disabled_timing_reads_no_clock() {
        let mut machine = super::super::tests::machine(&[]);
        let reads = machine.host.counter_reads;
        assert_eq!(machine.timing_start(), 0);
        assert_eq!(machine.timing_charge(Phase::Fetch, 0), 0);
        machine.timing_exit(FAULT_SLOT, 0);
        assert_eq!(machine.host.counter_reads, reads);
        machine.set_step_timing(true);
        machine.host.now = 20;
        machine.timing_charge(Phase::Native, 10);
        assert_eq!(
            machine.step_timing().unwrap().lifetime_maxima[Phase::Native as usize].ticks,
            10
        );
        let reads = machine.host.counter_reads;
        machine.set_step_timing(true);
        assert_eq!(machine.step_timing(), Some(&StepTiming::default()));
        machine.set_step_timing(false);
        assert!(machine.step_timing().is_none());
        machine.timing_exit(FAULT_SLOT, 0);
        assert_eq!(machine.host.counter_reads, reads);
    }
}
