use super::*;

const RTC: Rtc = Rtc {
    upcount: 0xf802,
    clock_offset: ClockOffset::Register(0xf900),
    alarm_control: 0xf800,
    alarm_enable: 0x40,
    alarm_offset: 0xf808,
    alarm_event: 0xf80c,
    irq_mask: 0xf80e,
    event_mask: DEFAULT_EVENT_MASK,
    interrupt_mask: 0x1,
};
const STOWE_OFFSET: u16 = 0xf900;
const MAVERICK_OFFSET: u16 = 0x1411;
fn stowe(wall: Option<WallClock>) -> Pmu {
    let windows = alloc::vec![
        Window {
            base: 0x8000,
            bytes: 0x2800
        },
        Window {
            base: 0xf700,
            bytes: LEGACY_SCRATCH_BYTES
        },
        Window {
            base: 0xf801,
            bytes: 1
        },
        Window {
            base: 0xfa00,
            bytes: 5
        },
    ];
    Pmu::new(windows, Some(RTC), wall)
}

pub(super) fn maverick() -> Rtc {
    Rtc {
        upcount: 0x1406,
        clock_offset: ClockOffset::Register(0x1411),
        alarm_control: 0x1401,
        alarm_enable: 0x40,
        alarm_offset: 0x140c,
        alarm_event: 0x14c0,
        irq_mask: 0x14c2,
        event_mask: 1,
        interrupt_mask: 1,
    }
}

#[test]
fn configuration_unifies_storage_aliases_and_rejects_semantic_aliases_or_bad_masks() {
    let rtc = maverick();
    assert!(Configuration::new(Vec::new(), Some(rtc), 1).is_ok());
    for window in [
        Window {
            base: rtc.upcount,
            bytes: 1,
        },
        Window {
            base: 0xffff,
            bytes: 2,
        },
        Window { base: 1, bytes: 0 },
    ] {
        assert!(Configuration::new(alloc::vec![window], Some(rtc), 1).is_err());
    }
    assert!(
        Configuration::new(
            alloc::vec![
                Window {
                    base: 0x8000,
                    bytes: 16
                },
                Window {
                    base: 0x800f,
                    bytes: 1
                }
            ],
            None,
            0
        )
        .is_ok()
    );
    for invalid in [
        Rtc {
            alarm_event: rtc.irq_mask,
            ..rtc
        },
        Rtc {
            clock_offset: ClockOffset::Register(0xfffb),
            ..rtc
        },
        Rtc {
            event_mask: 0,
            ..rtc
        },
        Rtc {
            interrupt_mask: 0,
            ..rtc
        },
        Rtc {
            alarm_enable: 1,
            ..rtc
        },
    ] {
        assert!(Configuration::new(Vec::new(), Some(invalid), 1).is_err());
    }
    assert!(Configuration::new(Vec::new(), Some(rtc), 0).is_err());
    assert!(Configuration::new(Vec::new(), None, 1).is_err());
    let config = Configuration::new(
        alloc::vec![
            Window {
                base: 0x8000,
                bytes: 0x1000
            },
            Window {
                base: 0x867b,
                bytes: 16
            }
        ],
        None,
        0,
    )
    .unwrap();
    assert_eq!(
        config.storage_windows(),
        alloc::vec![Window {
            base: 0x8000,
            bytes: 0x1000
        }]
    );
    let mut pmu = Pmu::configured(config, None).unwrap();
    pmu.write(0x867b, &[1, 2, 3], 0).unwrap();
    let mut bytes = [0; 3];
    pmu.read(0x867b, &mut bytes, 0).unwrap();
    assert_eq!(bytes, [1, 2, 3]);
    assert!(
        Pmu::configured(
            Configuration::new(Vec::new(), Some(rtc), 1).unwrap(),
            Some(WallClock {
                unix_seconds: u64::MAX,
                counter: 0
            })
        )
        .is_err()
    );
}

#[test]
fn both_original_maverick_rtcs_have_independent_registers_without_identity_substitutes() {
    let rtc = maverick();
    let mut primary =
        Pmu::configured(Configuration::new(Vec::new(), Some(rtc), 1).unwrap(), None).unwrap();
    let mut secondary =
        Pmu::configured(Configuration::new(Vec::new(), Some(rtc), 1).unwrap(), None).unwrap();
    primary
        .write(MAVERICK_OFFSET, &[1, 2, 3, 4, 5, 6], 0)
        .unwrap();
    let mut data = [0xff; 6];
    secondary.read(MAVERICK_OFFSET, &mut data, 0).unwrap();
    assert_eq!(data, [0; 6]);
    secondary
        .read(rtc.upcount, &mut data, 3 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(
        u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], 0, 0]) >> 1,
        3 * RTC_HZ
    );
    for pmu in [&mut primary, &mut secondary] {
        assert_eq!(pmu.read(0, &mut [0; 10], 0), Err(SlaveError::Nack));
        assert_eq!(pmu.read(0x3000, &mut [0; 16], 0), Err(SlaveError::Nack));
    }
}

/// The J514sAP Chapel RTC, whose control and event share one byte.
fn chapel() -> Rtc {
    Rtc {
        upcount: 0x2002,
        clock_offset: ClockOffset::Register(0x2100),
        alarm_control: 0x2000,
        alarm_enable: 0x40,
        alarm_offset: 0x2008,
        alarm_event: 0x2000,
        irq_mask: 0x200e,
        event_mask: 0x2,
        interrupt_mask: 0x1,
    }
}

/// `programRTCAlarm` on a shared byte: the event write-back carries the
/// control bits it read.
fn program_shared(pmu: &mut Pmu, seconds: u32, now: u64) -> u8 {
    let rtc = chapel();
    let mut read = [0];
    pmu.read(rtc.alarm_event, &mut read, now).unwrap();
    if read[0] & rtc.event_mask != 0 {
        pmu.write(rtc.alarm_event, &read, now).unwrap();
    }
    if seconds != 0 {
        pmu.write(rtc.alarm_offset, &seconds.to_le_bytes(), now)
            .unwrap();
    }
    let mask = if seconds != 0 { 0 } else { rtc.interrupt_mask };
    pmu.write(rtc.irq_mask, &[mask], now).unwrap();
    let control = 0x1 | if seconds != 0 { rtc.alarm_enable } else { 0 };
    pmu.write(rtc.alarm_control, &[control], now).unwrap();
    read[0]
}

#[test]
fn shared_byte_keeps_control_and_clears_events() {
    let rtc = chapel();
    for overlapping in [1, 0x40] {
        let bad = Rtc {
            event_mask: overlapping,
            ..rtc
        };
        assert!(Configuration::new(Vec::new(), Some(bad), 1).is_err());
    }
    let scratch = alloc::vec![Window {
        base: 0x8000,
        bytes: 0x2800
    }];
    let mut pmu =
        Pmu::configured(Configuration::new(scratch, Some(rtc), 1).unwrap(), None).unwrap();
    let output = pmu.interrupt();
    assert_eq!(program_shared(&mut pmu, 30, 0), 0);
    let mut byte = [0];
    pmu.read(rtc.alarm_control, &mut byte, 0).unwrap();
    assert_eq!(byte, [0x41]);
    // Control writes never carry an event acknowledgement by themselves.
    assert_eq!(pmu.advance(30 * FREQUENCY_HZ), None);
    assert!(output.asserted());
    pmu.write(rtc.alarm_control, &[0x41], 31 * FREQUENCY_HZ)
        .unwrap();
    assert!(output.asserted());
    pmu.read(rtc.alarm_event, &mut byte, 31 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(byte, [0x43]);
    // A control field outside monitor / monitor+enable refuses whole.
    for value in [0x42, 0x02, 0x83] {
        assert!(matches!(
            pmu.write(rtc.alarm_control, &[value], 31 * FREQUENCY_HZ),
            Err(SlaveError::Unsupported(_))
        ));
    }
    assert!(output.asserted());
    // Disabling: the write-back of 0x43 clears the event, then monitor alone.
    assert_eq!(program_shared(&mut pmu, 0, 31 * FREQUENCY_HZ), 0x43);
    assert!(!output.asserted() && !pmu.interrupt_armed());
    pmu.read(rtc.alarm_control, &mut byte, 31 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(byte, [0x01]);
    // A future alarm fires once again through the same byte.
    program_shared(&mut pmu, 40, 31 * FREQUENCY_HZ);
    assert_eq!(pmu.advance(39 * FREQUENCY_HZ), Some(40 * FREQUENCY_HZ));
    assert_eq!(pmu.advance(40 * FREQUENCY_HZ), None);
    assert!(output.asserted());
}

/// `_readCurrentOffsetTicks`'s legacy-scratch decode.
fn legacy_offset(pmu: &mut Pmu, base: u16, now: u64) -> i64 {
    let mut seconds = [0; 4];
    let mut fraction = [0; 2];
    pmu.read(base + 4, &mut seconds, now).unwrap();
    pmu.read(base + 0x15, &mut fraction, now).unwrap();
    let raw = u64::from(u32::from_le_bytes(seconds)) << 15
        | u64::from(fraction[1] & 0x7f) << 8
        | u64::from(fraction[0]);
    ((raw << 17) as i64) >> 17
}

#[test]
fn a_legacy_scratch_clock_offset_keeps_seconds_and_fraction_in_scratch_storage() {
    // The J700AP Baku primary declares no `info-clock_offset`.
    let rtc = Rtc {
        clock_offset: ClockOffset::LegacyScratch(0xf700),
        ..RTC
    };
    let windows = || {
        alloc::vec![
            Window {
                base: 0x8000,
                bytes: 0x1000
            },
            Window {
                base: 0xf700,
                bytes: LEGACY_SCRATCH_BYTES
            },
            Window {
                base: 0xf801,
                bytes: 1
            },
        ]
    };
    // The fields must be existing scratch storage, never RTC registers.
    assert!(Configuration::new(windows()[..1].to_vec(), Some(rtc), 1).is_err());
    let partial = alloc::vec![Window {
        base: 0xf700,
        bytes: 0x16
    }];
    assert!(Configuration::new(partial, Some(rtc), 1).is_err());
    let wrapped = Rtc {
        clock_offset: ClockOffset::LegacyScratch(0xfff0),
        ..rtc
    };
    assert!(Configuration::new(windows(), Some(wrapped), 1).is_err());
    let wall = WallClock {
        unix_seconds: 1_792_000_000,
        counter: 5 * FREQUENCY_HZ,
    };
    let config = || Configuration::new(windows(), Some(rtc), 1).unwrap();
    let mut pmu = Pmu::configured(config(), Some(wall)).unwrap();
    let now = 125 * FREQUENCY_HZ;
    let offset = legacy_offset(&mut pmu, 0xf700, now);
    let mut up = [0u8; 8];
    pmu.read(rtc.upcount, &mut up[..6], now).unwrap();
    let upcount = (u64::from_le_bytes(up) >> 1) as i64;
    assert_eq!((upcount + offset) >> 15, 1_792_000_000 + 120);
    // No six-byte register exists beside the boot keys.
    assert_eq!(pmu.read(0xf900, &mut [0; 6], now), Err(SlaveError::Nack));
    // A negative offset (wall time behind the upcount) round-trips.
    let behind = WallClock {
        unix_seconds: 2,
        counter: 1000 * FREQUENCY_HZ,
    };
    let mut pmu = Pmu::configured(config(), Some(behind)).unwrap();
    assert_eq!(
        legacy_offset(&mut pmu, 0xf700, 0),
        (2 - 1000) * RTC_HZ as i64
    );
    let mut seconds = [0; 4];
    pmu.read(0xf704, &mut seconds, 0).unwrap();
    assert_eq!(i32::from_le_bytes(seconds), 2 - 1000);
    assert!(
        Pmu::configured(
            config(),
            Some(WallClock {
                unix_seconds: 1 << 32,
                counter: 0
            })
        )
        .is_err()
    );
}

#[test]
fn a_pmu_without_rtc_routes_an_permanently_deasserted_output() {
    use {
        crate::spmi::Spmi, stela_contracts::interrupt::AicInput,
        stela_soc_data::spmi::Configuration as Controller, stela_soc_data::spmi::Profile,
    };
    // A Vale-shaped secondary: scratch, legacy scratch, no RTC.
    let windows = alloc::vec![
        Window {
            base: 0xa000,
            bytes: 0x800
        },
        Window {
            base: 0xbb00,
            bytes: LEGACY_SCRATCH_BYTES
        },
    ];
    let mut pmu = Pmu::configured(Configuration::new(windows, None, 0).unwrap(), None).unwrap();
    let output = pmu.interrupt();
    assert_eq!(pmu.interrupt_level(), Some(false));
    assert!(!pmu.interrupt_armed());
    pmu.write(0xbb01, &[0x30], FREQUENCY_HZ).unwrap();
    assert_eq!(pmu.advance(u64::MAX / 2), None);
    assert!(!output.asserted() && !pmu.interrupt_armed());
    assert_eq!(pmu.read(0xf800, &mut [0], 0), Err(SlaveError::Nack));
    let mut spmi = Spmi::with_configuration(
        AicInput::new(0, 0x180),
        Controller::new(Profile::Gen2, 192, [256, 256]).unwrap(),
    );
    spmi.attach_with_interrupt(0xe, 2, Box::new(pmu)).unwrap();
}

#[test]
fn firmware_mailbox_and_doorbell_are_explicit_requirements_without_firmware() {
    let scratch = || {
        Configuration::new(
            alloc::vec![Window {
                base: 0x8000,
                bytes: 0x1000
            }],
            None,
            0,
        )
        .unwrap()
    };
    for (mailbox, doorbell) in [(0x8ff8, 0x2808), (0x2860, 0x8000), (0xfff8, 0x2808)] {
        assert!(
            scratch()
                .with_unqualified_firmware_mailbox(mailbox, doorbell)
                .is_err()
        );
    }
    // The doorbell may not sit inside the mailbox's own bytes.
    assert!(
        scratch()
            .with_unqualified_firmware_mailbox(0x2860, 0x2865)
            .is_err()
    );
    let config = scratch()
        .with_unqualified_firmware_mailbox(0x2860, 0x2808)
        .unwrap();
    assert!(
        config
            .clone()
            .with_unqualified_firmware_mailbox(0x3000, 0x3100)
            .is_err()
    );
    let mut pmu = Pmu::configured(config, None).unwrap();
    // `mailboxTransactionGated` touches +0..+0xa; the doorbell is one byte.
    for (address, bytes) in [
        (0x2860, 5),
        (0x2865, 1),
        (0x2866, 5),
        (0x286a, 1),
        (0x2808, 1),
    ] {
        let mut data = alloc::vec![0xaa; bytes];
        assert!(matches!(
            pmu.read(address, &mut data, 0),
            Err(SlaveError::Unsupported(_))
        ));
        assert!(data.iter().all(|&byte| byte == 0xaa));
        assert!(matches!(
            pmu.write(address, &data, 0),
            Err(SlaveError::Unsupported(_))
        ));
    }
    assert_eq!(pmu.read(0x286b, &mut [0], 0), Err(SlaveError::Nack));
    assert_eq!(pmu.read(0x2809, &mut [0], 0), Err(SlaveError::Nack));
}

#[test]
fn declared_identity_is_an_explicit_requirement_and_never_zero_or_absent_readback() {
    let config = Configuration::new(Vec::new(), Some(maverick()), 1).unwrap();
    assert!(
        config
            .clone()
            .with_unqualified_identity(Window {
                base: 0xffff,
                bytes: 2
            })
            .is_err()
    );
    assert!(
        config
            .clone()
            .with_unqualified_identity(Window {
                base: 0x1401,
                bytes: 1
            })
            .is_err()
    );
    let config = config
        .with_unqualified_identity(Window { base: 0, bytes: 10 })
        .unwrap();
    assert!(
        config
            .clone()
            .with_unqualified_identity(Window { base: 16, bytes: 1 })
            .is_err()
    );
    let mut pmu = Pmu::configured(config, None).unwrap();
    let mut bytes = [0xaa; 16];
    assert!(matches!(
        pmu.read(0, &mut bytes[..10], 0),
        Err(SlaveError::Unsupported(_))
    ));
    assert!(matches!(
        pmu.read(9, &mut bytes, 0),
        Err(SlaveError::Unsupported(_))
    ));
    assert_eq!(bytes, [0xaa; 16]);
    assert!(matches!(
        pmu.write(0, &[0; 10], 0),
        Err(SlaveError::Unsupported(_))
    ));
    assert_eq!(pmu.read(10, &mut bytes[..1], 0), Err(SlaveError::Nack));
}

#[test]
fn rtc_controls_preflight_whole_transfer_and_preserve_due_alarm_on_refusal() {
    let rtc = maverick();
    let mut pmu =
        Pmu::configured(Configuration::new(Vec::new(), Some(rtc), 1).unwrap(), None).unwrap();
    pmu.write(rtc.alarm_offset, &30u32.to_le_bytes(), 0)
        .unwrap();
    pmu.write(rtc.alarm_control, &[0x41], 0).unwrap();
    let output = pmu.interrupt();
    for (address, value) in [
        (rtc.alarm_control, 0),
        (rtc.alarm_control, 0x80),
        (rtc.alarm_control, 0x40),
        (rtc.irq_mask, 2),
        (rtc.alarm_event, 2),
    ] {
        assert!(matches!(
            pmu.write(address, &[value], 31 * FREQUENCY_HZ),
            Err(SlaveError::Unsupported(_))
        ));
        assert!(!output.asserted());
        assert!(pmu.armed);
    }
    assert_eq!(
        pmu.write(rtc.alarm_offset, &[99; 6], 31 * FREQUENCY_HZ),
        Err(SlaveError::Nack)
    );
    assert!(pmu.armed);
    assert_eq!(pmu.advance(30 * FREQUENCY_HZ), None);
    assert!(output.asserted());
    // Masking changes the wire without discarding the latched wake event.
    pmu.write(rtc.irq_mask, &[1], 31 * FREQUENCY_HZ).unwrap();
    assert!(!output.asserted());
    let mut event = [0];
    pmu.read(rtc.alarm_event, &mut event, 31 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(event, [1]);
    pmu.write(rtc.irq_mask, &[0], 31 * FREQUENCY_HZ).unwrap();
    assert!(output.asserted());
    pmu.write(rtc.alarm_event, &[1], 31 * FREQUENCY_HZ).unwrap();
    assert!(!output.asserted());
}

#[test]
fn unqualified_upcount_wrap_refuses_before_read_write_or_autonomous_effects() {
    let mut pmu = stowe(None);
    let now = (1u128 << 47) * u128::from(FREQUENCY_HZ) / u128::from(RTC_HZ);
    let now = u64::try_from(now).unwrap();
    let mut data = [0xaa; 6];
    assert!(matches!(
        pmu.read(RTC.upcount, &mut data, now),
        Err(SlaveError::Unsupported(_))
    ));
    assert_eq!(data, [0xaa; 6]);
    assert!(matches!(
        pmu.write(STOWE_OFFSET, &[0xaa; 6], now),
        Err(SlaveError::Unsupported(_))
    ));
    assert!(matches!(
        pmu.check_time(now),
        Err(SlaveError::Unsupported(_))
    ));
    pmu.read(STOWE_OFFSET, &mut data, 0).unwrap();
    assert_eq!(data, [0; 6]);
}

#[test]
fn wall_time_follows_upcount_plus_offset_at_32768_hz() {
    let wall = WallClock {
        unix_seconds: 1_792_000_000,
        counter: 5 * FREQUENCY_HZ,
    };
    let mut pmu = stowe(Some(wall));
    let now = 125 * FREQUENCY_HZ;
    let mut up = [0u8; 6];
    pmu.read(RTC.upcount, &mut up, now).unwrap();
    let mut raw = [0u8; 8];
    raw[..6].copy_from_slice(&up);
    let upcount = u64::from_le_bytes(raw) >> 1;
    assert_eq!(upcount, 125 * RTC_HZ);
    let mut off = [0u8; 8];
    pmu.read(STOWE_OFFSET, &mut off[..6], now).unwrap();
    // Sign-extend the 48-bit offset, as `_readCurrentOffsetTicks` does.
    let offset = (i64::from_le_bytes(off) << 16) >> 16;
    let seconds = (upcount as i64 + offset) >> 15;
    assert_eq!(seconds, 1_792_000_000 + 120);
    // settimeofday rewrites the offset, which then reads back.
    pmu.write(STOWE_OFFSET, &[1, 2, 3, 4, 5, 6], now).unwrap();
    pmu.read(STOWE_OFFSET, &mut off[..6], now).unwrap();
    assert_eq!(off[..6], [1, 2, 3, 4, 5, 6]);
    assert_eq!(pmu.write(RTC.upcount, &[0], now), Err(SlaveError::Nack));
}

#[test]
fn unnamed_addresses_nack() {
    let mut pmu = stowe(None);
    pmu.write(0xf701, &[0x30], 0).unwrap();
    let mut keys = [0xffu8; 0x20];
    pmu.read(0xf700, &mut keys, 0).unwrap();
    assert_eq!(keys[1], 0x30);
    assert!(keys.iter().enumerate().all(|(i, &b)| i == 1 || b == 0));
    pmu.write(0xf801, &[0x04], 0).unwrap();
    let mut fault = [0xffu8; 5];
    pmu.read(0xfa00, &mut fault, 0).unwrap();
    assert_eq!(fault, [0; 5]);
    // The window ends at 0xfa05; a straddling access changes nothing.
    assert_eq!(pmu.write(0xfa04, &[1, 1], 0), Err(SlaveError::Nack));
    pmu.read(0xfa04, &mut fault[..1], 0).unwrap();
    assert_eq!(fault[0], 0);
    assert_eq!(pmu.read(0x1234, &mut [0], 0), Err(SlaveError::Nack));
    // Without the host's wall time the RTC reads the Unix epoch.
    let mut off = [0xffu8; 6];
    pmu.read(STOWE_OFFSET, &mut off, 0).unwrap();
    assert_eq!(off, [0; 6]);
}

/// `programRTCAlarm`'s writes for an alarm at upcount second `seconds`,
/// or for none.
fn program(pmu: &mut Pmu, seconds: u32, now: u64) {
    let mut event = [0];
    pmu.read(RTC.alarm_event, &mut event, now).unwrap();
    if event[0] & RTC.event_mask != 0 {
        pmu.write(RTC.alarm_event, &[RTC.event_mask], now).unwrap();
    }
    let enabled = seconds != 0;
    pmu.write(RTC.alarm_offset, &seconds.to_le_bytes(), now)
        .unwrap();
    let mask = if enabled { 0 } else { RTC.interrupt_mask };
    pmu.write(RTC.irq_mask, &[mask], now).unwrap();
    let control = 0x1 | if enabled { RTC.alarm_enable } else { 0 };
    pmu.write(RTC.alarm_control, &[control], now).unwrap();
}

#[test]
fn an_enabled_alarm_latches_its_event_at_its_second_and_interrupts_until_cleared() {
    let mut pmu = stowe(None);
    let interrupt = pmu.interrupt();
    // No alarm: nothing to wait for.
    program(&mut pmu, 0, 0);
    assert_eq!(pmu.advance(0), None);
    // An alarm at upcount second 30 fires at 30 s of the counter.
    program(&mut pmu, 30, FREQUENCY_HZ);
    assert_eq!(pmu.advance(FREQUENCY_HZ), Some(30 * FREQUENCY_HZ));
    assert!(!interrupt.asserted());
    assert_eq!(pmu.advance(30 * FREQUENCY_HZ - 1), Some(30 * FREQUENCY_HZ));
    assert_eq!(pmu.advance(30 * FREQUENCY_HZ), None);
    assert!(interrupt.asserted());
    let mut event = [0];
    pmu.read(RTC.alarm_event, &mut event, 30 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(event, [RTC.event_mask]);
    // Disabling it clears the event and masks the interrupt.
    program(&mut pmu, 0, 31 * FREQUENCY_HZ);
    assert!(!interrupt.asserted());
    pmu.read(RTC.alarm_event, &mut event, 31 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(event, [0]);
    // A time already passed never fires.
    program(&mut pmu, 10, 40 * FREQUENCY_HZ);
    assert_eq!(pmu.advance(40 * FREQUENCY_HZ), None);
    pmu.read(RTC.alarm_event, &mut event, 40 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(event, [0]);
    // A masked alarm still latches its event, without interrupting.
    program(&mut pmu, 50, 49 * FREQUENCY_HZ);
    pmu.write(RTC.irq_mask, &[RTC.interrupt_mask], 49 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(pmu.advance(50 * FREQUENCY_HZ), None);
    pmu.read(RTC.alarm_event, &mut event, 50 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(event, [RTC.event_mask]);
    assert!(!interrupt.asserted());
    // Cleared, a fired alarm stays quiet until it is programmed again.
    pmu.write(RTC.alarm_event, &[RTC.event_mask], 51 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(pmu.advance(51 * FREQUENCY_HZ), None);
    pmu.read(RTC.alarm_event, &mut event, 51 * FREQUENCY_HZ)
        .unwrap();
    assert_eq!(event, [0]);
    // A PMU without an RTC has no RTC registers.
    let mut aux = Pmu::new(
        alloc::vec![Window {
            base: 0xa000,
            bytes: 0x800
        }],
        None,
        None,
    );
    assert_eq!(aux.read(0xf802, &mut [0; 6], 0), Err(SlaveError::Nack));
    aux.write(0xa7ff, &[9], 0).unwrap();
    assert_eq!(aux.advance(0), None);
}
#[test]
#[ignore = "oracle: STELA_TEST_PMGR_M1_KERNELCACHE"]
fn original_primary_service_rtc_registers_alarm_and_edge_contract_are_source_pinned() {
    let data = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_KERNELCACHE").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&data),
        "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90"
    );
    for (offset, bytes, digest) in [
        (
            0x2d53facusize,
            208usize,
            "aa7a73fd15abdeaf204380645aaedc18c853dd98711ce169dd673d845ad5f2c7",
        ), // fault-log-count
        (
            0x1c85b2cusize,
            224usize,
            "da1639c284a54128a62d241ebf9b3f5b35aa9b0d924ccf18fffd28cfdb0a591f",
        ), // spmi-long-wrappers
        (
            0x2d54ee4usize,
            632usize,
            "31e6d88dbfb049d96923baaa68e1568e5231b59a30416c638502105b0fc1d599",
        ), // pmu-read-write-and-retry
        (
            0x2d4e5c4usize,
            12usize,
            "ed122dab0fa82ceea645c8407ec5262eaca8bb5c6dc6d2127a6624ac6da06d93",
        ), // controller-mode
        (
            0x2d4e7acusize,
            372usize,
            "fe52ab77e84967db2b65e3507219bc51ea23fd0d0d04e28802c2b425766257eb",
        ), // controller-chunk-lengths
        (
            0x2d55cf4usize,
            492usize,
            "9589a8ab2afc9a41eb886446c9fc1e9f6b6e3cdccf48f521dbd5c16e3593b7dc",
        ), // complete-fault-log-consumer
        (
            0x2d53a24usize,
            184usize,
            "39f5200f3b2267cdae8f5e29ec5d4293b8e4c2957625cee6a2394b388c2e8469",
        ), // configuration-required-legacy
        (
            0x2d549acusize,
            40usize,
            "27e91094d85bd53f6ca5bb1df7fea2f5d6600c66522fcea9a1e9e8902ca09608",
        ), // configuration-return
        (
            0x2d51480usize,
            3632usize,
            "dbc14082608594c40cd85664786a97447e03b3c6453605450af9070c3b83a636",
        ), // start
        (
            0x2d55b4cusize,
            424usize,
            "2cf8402d36132ecec69eb4e2fdb17acf52827f5bb9b8363d2969351859261541",
        ), // boot-key
        (
            0x2d552f8usize,
            1216usize,
            "f6a80ac867c834d37f1e75c71a9f4b0d908ef3bac3193b1f0490019ae4c990fe",
        ), // memory
        (
            0x2d5a504usize,
            12usize,
            "185b69410ba1e6bd9bbd267500bfbd9aaf87eb4672710113c02ff2e99c98a9da",
        ), // handle-start
        (
            0x1c86618usize,
            1632usize,
            "a0c1723a9e9570b8d979edbf58c64a4b085de86afba8e66c1f5c2a9858ebd18b",
        ), // user-client
        (
            0x2d53b00usize,
            96usize,
            "ae72f04d836556710cd8623bf9b2363ef48d1cab10996e739e0062175178d32c",
        ), // primary-configuration
        (
            0x2d51b78usize,
            76usize,
            "fe0fd661e1a7e0cb7a9b73341ecfdb78b602f2e3d2379b57125d872a1ce033b4",
        ), // primary-registration
        (
            0x2d5b4b4usize,
            428usize,
            "eb7dfdd469a93045a2973ead2831e79b91c2710c899f60791612ae12aac8b160",
        ), // rtc-primary-start
        (
            0x2d523fcusize,
            88usize,
            "6cdf10ae91af7d453a6b7d2f5d526e3c92f248ec99ac90f98b0a93d136d8df5c",
        ), // rtc-alarm-interrupt-action
        (
            0x2d5d528usize,
            616usize,
            "4daed85c0f254899e551d039561acca4c1bd0bdd12ba90dc87cfb279482812ea",
        ), // rtc-program
        (
            0x2d5da14usize,
            104usize,
            "a9ee1c7e106e4d2333a784c35233fc407dfefd4826290a38e1a71439e9695c86",
        ), // rtc-upcount
        (
            0x2d5c284usize,
            2028usize,
            "78c4fcde5203af89991b24a4afe42b85f930e87177c434051e4d192b7e632e02",
        ), // rtc-register-configuration
        (
            0x2d5dbccusize,
            420usize,
            "4e6176a07847a9d3425fa88b7cb61875c4fd955e8db99d379c5a84db0c448fec",
        ), // rtc-schedule
        (
            0x2d5de60usize,
            132usize,
            "8e624bf9b2d4bc205e9ef306279804737a3ad6e613d0b71b32a99e8183b5d493",
        ), // rtc-read-wake-event
        (
            0x12a6e18usize,
            8usize,
            "3e0e0067b1027e83b92ef97507faea7580ffed3c5bbcb72e63c5a9876b4499f4",
        ), // spmi-get-vector-type-slot
        (
            0x54821a4usize,
            8usize,
            "2f6110664dbd16b514a0c2c7c8326932a36e85d2f15b91e57ca76efd2c7a625a",
        ), // spmi-edge-handler
        (
            0x12a8ff0usize,
            8usize,
            "628c0e30cbecff297891396eb57936a4b8e6df7e493b51fd2bdd52fb9f721b41",
        ), // rtc-alarm-vtable-slot
        (
            0x2d51864usize,
            80usize,
            "77649b1296a66d2725fe2bc3c1b607b70fa6f9d2c6da9f0dcf661cdeacdd014b",
        ), // identity-descriptor-keep
    ] {
        assert_eq!(
            stela_formats::sha256(&data[offset..offset + bytes]),
            digest,
            "source span {offset:#x}"
        );
    }
    // A missing legacy descriptor branches directly to the false return,
    // before the later ID-descriptor retention and register initialization.
    let required = u32::from_le_bytes(data[0x2d53a9c..0x2d53aa0].try_into().unwrap());
    assert_eq!(required & 0xff00_001f, 0xb400_0000); // CBZ X0
    let displacement = (((required >> 5) & 0x7ffff) as i32) << 13 >> 11;
    assert_eq!(0x2d53a9c_i64 + i64::from(displacement), 0x2d549ac);
    let handle_start = u64::from_le_bytes(data[0x12a8260..0x12a8268].try_into().unwrap());
    assert_eq!(
        0xfffffe0007004000 + (handle_start & 0x3fffffff),
        0xfffffe0009d5e504
    );
    assert_eq!(
        &data[0x2d5a508..0x2d5a510],
        &[0x20, 0, 0x80, 0x52, 0xc0, 3, 0x5f, 0xd6] // MOV W0, #1; RET
    );
    let edge = u64::from_le_bytes(data[0x12a6e18..0x12a6e20].try_into().unwrap());
    assert_eq!(0xfffffe0007004000 + (edge & 0x3fffffff), 0xfffffe000c4861a4);
    assert_eq!(
        &data[0x54821a4..0x54821ac],
        &[0, 0, 128, 82, 192, 3, 95, 214]
    );
    let alarm = u64::from_le_bytes(data[0x12a8ff0..0x12a8ff8].try_into().unwrap());
    assert_eq!(
        0xfffffe0007004000 + (alarm & 0x3fffffff),
        0xfffffe0009d61528
    );
}

#[test]
#[ignore = "oracle: STELA_TEST_SPMI_DT"]
fn original_j314s_two_rtc_resources_have_one_primary_service_and_local_output() {
    use stela_contracts::adt::Node;
    let data = std::fs::read(std::env::var("STELA_TEST_SPMI_DT").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&data),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let root = Node::root(&data).unwrap();
    let mut pmus = 0;
    let mut rtcs = 0;
    let mut primaries = 0;
    for controller in root.child("arm-io").unwrap().children().unwrap() {
        if !controller.compatible("aapl,spmi") {
            continue;
        }
        for node in controller.children().unwrap() {
            if !node.compatible("pmu,spmi") {
                continue;
            }
            pmus += 1;
            assert_eq!(node.cells32("info-id").unwrap(), [0, 10]); // address/length, not ID bytes
            // The original AP driver requires legacy scratch before keeping
            // this descriptor. Monaco remains a provider without that service;
            // neither property grants identity-byte readback semantics.
            if node.compatible("pmu,maverick") {
                assert_eq!(node.first_u32("info-leg_scrpad"), Some(0x6000));
                assert_eq!(
                    node.cells32("info-fw-sram").unwrap(),
                    [0xc830, 0xc831, 0xc833, 0x3000, 16]
                );
                assert!(node.property("has-socd-fw-sram").is_none());
            } else {
                assert!(node.compatible("pmu,monaco"));
                assert!(node.property("info-leg_scrpad").is_none());
                assert!(node.property("info-fw-sram").is_none());
            }
            let mut windows = Vec::new();
            for key in ["info-scrpad", "info-fault_shadow"] {
                if let Some(pair) = node.cells32(key) {
                    windows.push(Window {
                        base: pair[0] as u16,
                        bytes: pair[1] as u16,
                    });
                }
            }
            if let Some(base) = node.first_u32("info-leg_scrpad") {
                windows.push(Window {
                    base: base as u16,
                    bytes: LEGACY_SCRATCH_BYTES,
                });
            }
            if let Some(base) = node.first_u32("info-pm_setting") {
                windows.push(Window {
                    base: base as u16,
                    bytes: 1,
                });
            }
            let rtc = if node.first_u32("info-rtc").is_some() {
                rtcs += 1;
                let expected = maverick();
                for (key, value) in [
                    ("info-rtc", expected.upcount),
                    ("info-rtc_alarm_ctrl", expected.alarm_control),
                    ("info-rtc_alarm_offset", expected.alarm_offset),
                    ("info-rtc_alarm_event", expected.alarm_event),
                    ("info-rtc_irq_mask_offset", expected.irq_mask),
                ] {
                    assert_eq!(node.first_u32(key), Some(u32::from(value)));
                }
                assert_eq!(node.cells32("info-clock_offset").unwrap(), [0x1411, 6]);
                assert_eq!(node.first_u32("info-rtc_alarm_monitor_mask"), Some(1));
                assert_eq!(node.first_u32("info-rtc_alarm_ctrl_en_mask"), Some(64));
                assert_eq!(node.first_u32("info-rtc_alarm_mask"), Some(1));
                Some(expected)
            } else {
                None
            };
            let log = node.cells32("info-fault_log").unwrap();
            let log = Window {
                base: log[0] as u16,
                bytes: log[1] as u16,
            };
            assert_eq!(log.base, 0x1000);
            assert_eq!(log.bytes, if rtc.is_some() { 10 } else { 1 });
            let configuration = Configuration::new(windows, rtc, u8::from(rtc.is_some()))
                .unwrap()
                // This fixture declares empty virtual history, not an Apple
                // reset value or the live reference Mac's fault state.
                .with_fault_history(log, alloc::vec![0; usize::from(log.bytes)])
                .unwrap()
                .with_unqualified_identity(Window { base: 0, bytes: 10 })
                .unwrap();
            let mut model = Pmu::configured(configuration, None).unwrap();
            let mut history = alloc::vec![0xff; usize::from(log.bytes)];
            model.read(log.base, &mut history, 0).unwrap();
            assert!(history.iter().all(|&byte| byte == 0));
            model.write(log.base, &history, 0).unwrap();
            assert!(matches!(
                model.read(0, &mut [0; 10], 0),
                Err(SlaveError::Unsupported(_))
            ));
            if node.first_u32("is-primary") == Some(1) {
                primaries += 1;
                assert!(rtc.is_some());
                assert_eq!(node.cells32("interrupts").unwrap(), [2]);
                assert_eq!(
                    node.first_u32("interrupt-parent"),
                    controller.first_u32("AAPL,phandle")
                );
            } else {
                assert!(node.property("interrupts").is_none());
            }
        }
    }
    assert_eq!((pmus, rtcs, primaries), (5, 2, 1));
}
