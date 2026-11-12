use super::super::identity::Observed;
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Read(u32),
    Write(u32, u32),
    Delay(u32),
}
struct Model {
    registers: BTreeMap<u32, u32>,
    peripheral: BTreeMap<u32, u32>,
    ops: Vec<Op>,
    fail: Option<usize>,
    sentinel: Option<usize>,
    sentinel_value: u32,
    own_attempts: usize,
    grant_after: usize,
    clock_after: Option<usize>,
    clock_reads: usize,
    mask_rejected: bool,
}
impl Model {
    fn new(family: Family) -> Self {
        let (hw, rf) = if family == Family::Ax200 {
            (0x340, 0x10a000)
        } else {
            (0x420, 0x10d000)
        };
        Self {
            registers: BTreeMap::from([
                (HW_REV, hw),
                (RF_ID, rf),
                (HW_IF, 0x1000),
                (INT_MASK, 0x1234),
                (CHICKEN, 0x400),
                (HPET, 0x1234),
                (GIO, 0x100),
                (GP, 0x08000000),
            ]),
            peripheral: BTreeMap::from([(0x3440, 0x01231000), (0x4d00, 0)]),
            ops: Vec::new(),
            fail: None,
            sentinel: None,
            sentinel_value: 0x5a5a5a5a,
            own_attempts: 0,
            grant_after: 1,
            clock_after: Some(0),
            clock_reads: 0,
            mask_rejected: false,
        }
    }
    fn op(&mut self, op: Op) -> Result<(), AccessError> {
        let at = self.ops.len();
        self.ops.push(op);
        if self.fail == Some(at) {
            return Err(AccessError::Unavailable);
        }
        Ok(())
    }
}
impl Csr for Model {
    fn read32(&mut self, register: u32) -> Result<u32, AccessError> {
        self.op(Op::Read(register))?;
        if self.sentinel == Some(self.ops.len() - 1) {
            return Ok(self.sentinel_value);
        }
        if register == PRPH_RDATA {
            let address = self.registers[&PRPH_RADDR] & 0x00ffffff;
            return Ok(*self.peripheral.get(&address).unwrap_or(&0));
        }
        if register == GP && self.registers[&GP] & MAC_INIT != 0 {
            *self.registers.get_mut(&GP).unwrap() |= MAC_STATUS;
        }
        if register == GP && self.registers[&GP] & 4 != 0 {
            self.clock_reads += 1;
            if self
                .clock_after
                .is_some_and(|count| self.clock_reads >= count)
            {
                *self.registers.get_mut(&GP).unwrap() |= 1;
            }
        }
        // Mailbox SET is modeled write-only/W1S, not a readable receipt.
        if register == MAILBOX {
            return Ok(0);
        }
        Ok(*self.registers.get(&register).unwrap_or(&0))
    }
    fn write32(&mut self, register: u32, mut value: u32) -> Result<(), AccessError> {
        self.op(Op::Write(register, value))?;
        if register == HW_IF && value & OWN != 0 {
            self.own_attempts += 1;
            if self.own_attempts < self.grant_after {
                value &= !OWN;
            }
        }
        if register == RESET && value & 0x80 != 0 {
            *self.registers.get_mut(&HW_IF).unwrap() &= !OWN;
            *self.registers.get_mut(&GP).unwrap() &= !5;
        }
        if register == INT || register == FH_INT {
            self.registers.insert(register, 0);
            return Ok(());
        }
        if register == INT_MASK && self.mask_rejected {
            return Ok(());
        }
        if register == PRPH_WDATA {
            let address = self.registers[&PRPH_WADDR] & 0x00ffffff;
            self.peripheral.insert(address, value);
        }
        self.registers.insert(register, value);
        Ok(())
    }
    fn delay_us(&mut self, us: u32) -> Result<(), AccessError> {
        self.op(Op::Delay(us))
    }
}
fn profile(family: Family) -> Profile {
    Profile::select(Observed {
        link_speed: 3,
        silicon: Default::default(),
        vendor: 0x8086,
        device: if family == Family::Ax200 {
            0x2723
        } else {
            0x2725
        },
        subsystem_vendor: 0x8086,
        subsystem_device: 0x84,
        pci_revision: 0x1a,
        hardware_revision: if family == Family::Ax200 {
            0x340
        } else {
            0x420
        },
        radio_id: if family == Family::Ax200 {
            0x10a000
        } else {
            0x10d000
        },
    })
    .unwrap()
}
#[test]
fn real_family_ownership_reset_persistence_bisr_and_stable_neighbor_effects() {
    for family in [Family::Ax200, Family::Ax210] {
        let mut power = Power::new(Model::new(family), profile(family));
        let awake = power.wake(ManagementSession::Unknown).unwrap();
        assert_eq!(
            awake,
            Awake {
                family,
                rf_killed: false
            }
        );
        assert_eq!(power.state, State::Awake(awake));
        assert_eq!(power.nic.io.registers[&INT_MASK], 0);
        assert_eq!(power.nic.io.registers[&CHICKEN], 0x00800400);
        assert_eq!(power.nic.io.registers[&HPET], 0xffff1234);
        assert_eq!(power.nic.io.registers[&GIO], 0x102);
        assert_eq!(power.nic.io.registers[&HW_IF] & 0x1000, 0x1000);
        let delays: Vec<_> = power
            .nic
            .io
            .ops
            .iter()
            .filter_map(|op| {
                if let Op::Delay(us) = op {
                    Some(*us)
                } else {
                    None
                }
            })
            .collect();
        if family == Family::Ax200 {
            assert_eq!(delays, [5000, 2000, 200]);
            assert_eq!(power.nic.io.peripheral[&0x3440], 0x01230000);
        } else {
            assert_eq!(delays, [5000]);
            assert!(
                !power
                    .nic
                    .io
                    .ops
                    .iter()
                    .any(|op| matches!(op, Op::Write(PRPH_RADDR | PRPH_WADDR, _)))
            );
        }
        let before = power.nic.io.ops.len();
        assert_eq!(
            power.wake(ManagementSession::NotConnected),
            Err(Error::State)
        );
        assert_eq!(before, power.nic.io.ops.len());
        let (io, selected, status) = power.into_awake().unwrap();
        assert_eq!(selected.family(), family);
        assert_eq!(status, awake);
        assert_eq!(io.registers[&INT_MASK], 0);
    }
}
#[test]
fn late_ownership_deadlines_management_unknown_and_connected_stay_explicit() {
    let family = Family::Ax200;
    let mut model = Model::new(family);
    model.grant_after = 3;
    let mut power = Power::new(model, profile(family));
    power.wake(ManagementSession::NotConnected).unwrap();
    assert!(power.nic.io.ops.contains(&Op::Delay(1000)));
    assert!(power.nic.io.ops.contains(&Op::Delay(200)));
    for (session, expected) in [
        (ManagementSession::Unknown, Error::ManagementUnknown),
        (ManagementSession::Connected, Error::ManagementConnected),
    ] {
        let mut model = Model::new(family);
        model.grant_after = usize::MAX;
        let mut power = Power::new(model, profile(family));
        assert_eq!(power.wake(session), Err(expected));
        assert_eq!(power.state, State::Poisoned);
        assert!(
            !power
                .nic
                .io
                .ops
                .iter()
                .any(|op| matches!(op, Op::Write(RESET, _)))
        );
    }
    let mut model = Model::new(family);
    model.grant_after = usize::MAX;
    let mut power = Power::new(model, profile(family));
    assert_eq!(
        power.wake(ManagementSession::NotConnected),
        Err(Error::Timeout {
            register: HW_IF,
            mask: OWN
        })
    );
    assert_eq!(
        power
            .nic
            .io
            .ops
            .iter()
            .filter(|op| **op == Op::Delay(25000))
            .count(),
        10
    );
}
#[test]
fn persistence_protection_clock_timeout_rfkill_and_identity_never_invent_ready() {
    let family = Family::Ax200;
    let mut model = Model::new(family);
    model.peripheral.insert(0x4d00, 1 << 12);
    let mut power = Power::new(model, profile(family));
    assert_eq!(
        power.wake(ManagementSession::Unknown),
        Err(Error::PersistenceProtected)
    );
    assert!(
        !power
            .nic
            .io
            .ops
            .iter()
            .any(|op| matches!(op, Op::Write(RESET, _)))
    );
    let mut model = Model::new(family);
    model.clock_after = None;
    let mut power = Power::new(model, profile(family));
    assert_eq!(
        power.wake(ManagementSession::Unknown),
        Err(Error::Timeout {
            register: GP,
            mask: 1
        })
    );
    assert_eq!(power.nic.io.ops.last(), Some(&Op::Delay(200)));
    let mut model = Model::new(family);
    model.registers.insert(GP, 0);
    let mut power = Power::new(model, profile(family));
    assert!(power.wake(ManagementSession::Unknown).unwrap().rf_killed);
    let mut model = Model::new(family);
    model.registers.insert(RF_ID, 0x10d000);
    let mut power = Power::new(model, profile(family));
    assert_eq!(
        power.wake(ManagementSession::Unknown),
        Err(Error::IdentityChanged)
    );
    assert!(
        !power
            .nic
            .io
            .ops
            .iter()
            .any(|op| matches!(op, Op::Write(..)))
    );
    let mut model = Model::new(family);
    model.mask_rejected = true;
    let mut power = Power::new(model, profile(family));
    assert!(matches!(
        power.wake(ManagementSession::Unknown),
        Err(Error::Rejected {
            register: INT_MASK,
            ..
        })
    ));
    assert!(
        !power
            .nic
            .io
            .ops
            .iter()
            .any(|op| matches!(op, Op::Write(RESET, _)))
    );
}
#[test]
fn every_source_operation_failure_and_failed_word_poison_the_epoch() {
    for family in [Family::Ax200, Family::Ax210] {
        let mut baseline = Power::new(Model::new(family), profile(family));
        baseline.wake(ManagementSession::Unknown).unwrap();
        for (index, op) in baseline.nic.io.ops.iter().enumerate() {
            let mut model = Model::new(family);
            model.fail = Some(index);
            let mut power = Power::new(model, profile(family));
            assert!(
                power.wake(ManagementSession::Unknown).is_err(),
                "failure {family:?} {index} {op:?}"
            );
            assert_eq!(power.state, State::Poisoned);
            let before = power.nic.io.ops.len();
            assert_eq!(
                power.wake(ManagementSession::NotConnected),
                Err(Error::State)
            );
            assert_eq!(before, power.nic.io.ops.len());
            if matches!(op, Op::Read(_)) {
                for sentinel_value in [u32::MAX, 0xa5a5a5a5, 0x5a5a5a5a] {
                    let mut model = Model::new(family);
                    model.sentinel = Some(index);
                    model.sentinel_value = sentinel_value;
                    let mut power = Power::new(model, profile(family));
                    assert!(
                        matches!(
                            power.wake(ManagementSession::Unknown),
                            Err(Error::FailedRead { .. })
                        ),
                        "sentinel {family:?} {index} {op:?} {sentinel_value:x}"
                    );
                }
            }
        }
    }
}

#[test]
#[ignore = "oracle: STELA_IWLWIFI_POWER_ORACLE"]
fn unchanged_linux_ownership_reset_and_clock_effects() {
    extern crate std;
    use sha2::{Digest, Sha256};
    let path = std::env::var("STELA_IWLWIFI_POWER_ORACLE").expect("power trace");
    let trace = std::fs::read(path).unwrap();
    let digest: alloc::string::String = Sha256::digest(&trace)
        .iter()
        .map(|b| alloc::format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest,
        "58c3468c51e9a8c5e34ae5f06e78e65cff867e717384230288a11d1866618d60"
    );
    let text = core::str::from_utf8(&trace).unwrap();
    let mut lines = text.lines();
    let mut cases = 0;
    let mut effects = 0;
    while let Some(line) = lines.next() {
        let scenario = line
            .strip_prefix("case ")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let family = if scenario < 6 {
            Family::Ax200
        } else {
            Family::Ax210
        };
        let kind = scenario % 6;
        let mut expected = Vec::new();
        let expected_result;
        loop {
            let line = lines.next().unwrap();
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields[0] {
                "w" => expected.push(Op::Write(
                    u32::from_str_radix(fields[1], 16).unwrap(),
                    u32::from_str_radix(fields[2], 16).unwrap(),
                )),
                "d" => expected.push(Op::Delay(fields[1].parse().unwrap())),
                "result" => {
                    expected_result = fields[1];
                    break;
                }
                other => panic!("unexpected source record {other}"),
            }
        }
        let mut model = Model::new(family);
        model
            .peripheral
            .insert(0x3440, if kind == 0 { 0x01230000 } else { 0x01231000 });
        model
            .peripheral
            .insert(0x4d00, if kind == 2 { 0x1000 } else { 0 });
        model.grant_after = if kind == 3 { 3 } else { 1 };
        model.clock_after = if kind == 4 { None } else { Some(0) };
        if kind == 5 {
            model.registers.insert(GP, 0);
        }
        let mut power = Power::new(model, profile(family));
        let result = power.wake(ManagementSession::NotConnected);
        let status = match result {
            Ok(_) => "ok",
            Err(Error::PersistenceProtected) => "protected",
            Err(Error::Timeout { .. }) => "timeout",
            Err(e) => panic!("unexpected power failure {e:?}"),
        };
        assert_eq!(status, expected_result, "case {scenario}");
        let actual: Vec<_> = power
            .nic
            .io
            .ops
            .iter()
            .copied()
            .filter(|op| !matches!(op, Op::Read(_) | Op::Write(PRPH_RADDR, _)))
            .collect();
        assert_eq!(actual, expected, "source effects case {scenario}");
        cases += 1;
        effects += actual.len();
    }
    assert_eq!(cases, 12);
    assert!(effects > 5000);
}

#[test]
fn an_integrated_22000_device_gates_power_between_its_reset_and_power_up() {
    let mut model = Model::new(Family::Ax200);
    model.registers.insert(HW_REV, 0x332);
    let profile = Profile::select(Observed {
        link_speed: 3,
        device: 0x06f0,
        hardware_revision: 0x332,
        subsystem_device: 0x70,
        ..profile(Family::Ax200).observed()
    })
    .unwrap();
    let mut power = Power::new(model, profile);
    power.wake(ManagementSession::NotConnected).unwrap();
    let ops = &power.nic.io.ops;
    let written: Vec<u32> = ops
        .iter()
        .filter_map(|op| match op {
            Op::Write(PRPH_WDATA, value) => Some(*value),
            _ => None,
        })
        .collect();
    assert_eq!(
        written[written.len() - 3..],
        [
            FORCE_ACTIVE,
            FORCE_ACTIVE | POWER_GATE | SLEEP,
            POWER_GATE | SLEEP
        ]
    );
    let resets = ops
        .iter()
        .filter(|op| matches!(op, Op::Write(RESET, value) if value & 0x80 != 0))
        .count();
    assert_eq!(resets, 2);
    assert!(!ops.contains(&Op::Delay(2000)));
}

fn wifi_7(model: &mut Model) -> Profile {
    model.registers.insert(HW_REV, 0x472);
    model.registers.insert(RF_ID, 0x112200);
    Profile::select(Observed {
        link_speed: 3,
        device: 0x272b,
        hardware_revision: 0x472,
        radio_id: 0x112200,
        subsystem_device: 0x20,
        ..profile(Family::Ax200).observed()
    })
    .unwrap()
}

#[test]
fn a_bz_mac_resets_and_wakes_through_gp_control() {
    let mut model = Model::new(Family::Ax210);
    let profile = wifi_7(&mut model);
    let mut power = Power::new(model, profile);
    let awake = power.wake(ManagementSession::NotConnected).unwrap();
    assert_eq!(awake.family, Family::Bz);
    let ops = &power.nic.io.ops;
    assert!(!ops.iter().any(|op| matches!(op, Op::Write(RESET, _))));
    assert!(ops.contains(&Op::Delay(10000)));
    assert!(ops.iter().any(|op| {
        matches!(op, Op::Write(GP, value) if value & SW_RESET != 0 && value & MAC_INIT == 0)
    }));
    assert!(ops.iter().any(|op| {
        matches!(op, Op::Write(GP, value) if value & (BZ_MAC_ACCESS | MAC_INIT) == BZ_MAC_ACCESS | MAC_INIT)
    }));
}

#[test]
fn the_early_access_reads_what_the_csrs_do_not_say() {
    let mut model = Model::new(Family::Ax210);
    model.peripheral.extend([
        (0xa2b800, 0x0200_0910),
        (0xa200b0, 0x0100_0900),
        (0xd03098, 0x10),
        (0xd03030, 0x0f),
    ]);
    let silicon = read_silicon(
        &mut model,
        Family::Bz,
        false,
        ManagementSession::NotConnected,
    )
    .unwrap();
    assert_eq!(
        silicon,
        Silicon {
            crf: 0x0200_0910,
            cnv: 0x0100_0900,
            wfpm: 0x10
        }
    );
    assert_eq!(model.peripheral[&0xd03030], 0x8000_000f);
    assert_eq!(model.registers[&GP] & BZ_MAC_ACCESS, 0);
}

#[test]
fn a_cold_stop_masks_interrupts_stops_the_master_and_resets_the_device() {
    for acknowledged in [true, false] {
        let mut model = Model::new(Family::Ax210);
        model.registers.insert(GP, 0x0800_000d);
        if acknowledged {
            model.registers.insert(RESET, MASTER_DISABLED);
        }
        stop(&mut model, Family::Ax210).unwrap();
        let ops = &model.ops;
        assert_eq!(
            ops[..3],
            [
                Op::Write(INT_MASK, 0),
                Op::Write(INT, u32::MAX),
                Op::Write(FH_INT, u32::MAX)
            ]
        );
        let stop_master = ops
            .iter()
            .position(|op| matches!(op, Op::Write(RESET, value) if value & STOP_MASTER != 0))
            .unwrap();
        let reset = ops
            .iter()
            .position(|op| matches!(op, Op::Write(RESET, value) if value & SW_RESET_LEGACY != 0))
            .unwrap();
        assert!(stop_master < reset);
        // An unacknowledged master stop is polled for its 100 us, then reset;
        // the reset's own read-modify-write reads the register once more.
        let reads = ops[stop_master..reset]
            .iter()
            .filter(|op| **op == Op::Read(RESET))
            .count();
        assert_eq!(reads, if acknowledged { 2 } else { 11 });
        assert_eq!(ops[reset + 1], Op::Delay(5000));
        assert_eq!(model.registers[&GP] & (INIT_DONE | MAC_ACCESS), 0);
        assert!(
            !ops.iter()
                .any(|op| matches!(op, Op::Write(GP, value) if value & SW_RESET != 0))
        );
    }
}

#[test]
fn a_bz_cold_stop_uses_gp_control_and_a_vanished_device_fails() {
    let mut model = Model::new(Family::Ax210);
    model
        .registers
        .insert(GP, 0x0800_0000 | MAC_INIT | BZ_MAC_ACCESS);
    stop(&mut model, Family::Bz).unwrap();
    let ops = &model.ops;
    assert!(!ops.iter().any(|op| matches!(op, Op::Write(RESET, _))));
    let request = ops
        .iter()
        .position(
            |op| matches!(op, Op::Write(GP, value) if value & BUS_MASTER_DISABLE_REQUEST != 0),
        )
        .unwrap();
    let reset = ops
        .iter()
        .position(|op| matches!(op, Op::Write(GP, value) if value & SW_RESET != 0))
        .unwrap();
    assert!(request < reset);
    assert_eq!(ops[reset + 1], Op::Delay(10000));
    assert_eq!(model.registers[&GP] & (MAC_INIT | BZ_MAC_ACCESS), 0);

    let mut model = Model::new(Family::Ax210);
    model.registers.insert(RESET, u32::MAX);
    assert!(matches!(
        stop(&mut model, Family::Ax210),
        Err(Error::FailedRead {
            register: RESET,
            ..
        })
    ));
    assert!(!model.ops.iter().any(|op| matches!(op, Op::Write(RESET, _))));
}
