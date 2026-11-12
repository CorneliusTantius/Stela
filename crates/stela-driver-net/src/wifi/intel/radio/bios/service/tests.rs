extern crate std;
use super::*;
use alloc::vec;
#[derive(Clone)]
struct Model {
    scenario: u32,
}
fn pattern(scenario: u32, index: u32) -> u32 {
    0x9e3779b9u32.wrapping_mul(index + 1) ^ scenario
}
fn package(revision: u64, value: u64, domain: u64) -> Object {
    Object::Package(vec![
        Object::Integer(revision),
        Object::Package(vec![Object::Integer(domain), Object::Integer(value)]),
    ])
}
fn buffer(value: u64, length: usize) -> Object {
    Object::Buffer(value.to_le_bytes()[..length].to_vec())
}
// SAFETY: modeled raw namespace calls; this grants no real platform
// attachment. The unchanged source oracle separately consumes these inputs.
unsafe impl BiosIo for Model {
    fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
        let s = self.scenario;
        Ok(match request {
            Request::ExternalClock | Request::Country | Request::PowerTable(_) => {
                panic!("scalar is outside the historical LARI model")
            }
            Request::Glai => {
                let mode = s % 8;
                if mode == 0 {
                    return Err(IoError::NotFound);
                }
                package(
                    if mode == 5 {
                        1
                    } else if mode == 7 {
                        0x100000000
                    } else {
                        0
                    },
                    [0, 0, 1, 2, 3, 1, 1, 1][mode as usize],
                    if mode == 6 { 8 } else { 7 },
                )
            }
            Request::WideBandwidth => {
                let mode = (s / 512) % 8;
                if mode == 0 {
                    return Err(IoError::NotFound);
                }
                package(
                    if mode == 1 { 1 } else { 0 },
                    u64::from(pattern(s, 31)),
                    if mode == 2 { 8 } else { 7 },
                )
            }
            Request::Dsm(0) => match (s / 64) % 8 {
                0 => return Err(IoError::NotFound),
                1 => Object::Other,
                2 => Object::Integer(0),
                3 => Object::Integer(0x7fff),
                4 => buffer(0x7fff, 1),
                5 => buffer(0x7fff, 3),
                6 => buffer(0x7fff, 8),
                _ => Object::Integer(0xffffffff00007fff),
            },
            Request::Dsm(index) => {
                let kind = (u32::from(index) + (s / 512) % 8) % 6;
                let value = 0x1234567800000000 | u64::from(pattern(s, u32::from(index)));
                match kind {
                    0 => return Err(IoError::NotFound),
                    1 => Object::Other,
                    2 => Object::Integer(value),
                    3 => buffer(value, 0),
                    4 => buffer(value, 1),
                    _ => buffer(value, 8),
                }
            }
        })
    }
    fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError> {
        let dsm = variable == Variable::GeneralConfiguration;
        assert!(dsm || variable == Variable::Wbem);
        let mode = (self.scenario / if dsm { 8 } else { 512 }) % 8;
        if mode == 0 {
            return Err(IoError::NotFound);
        }
        let mut raw = vec![if dsm {
            if mode == 2 { 3 } else { 4 }
        } else if mode == 2 {
            1
        } else {
            0
        }];
        if dsm {
            let masks = [0, 0, 0, 0, 0x7fff, 0xaaaa, 0x5555, 1 << 4];
            for f in 0..32 {
                raw.extend(
                    if f == 0 {
                        masks[mode as usize]
                    } else {
                        pattern(self.scenario, f)
                    }
                    .to_le_bytes(),
                );
            }
        } else {
            raw.extend(pattern(self.scenario, 30).to_le_bytes());
        }
        if mode == 1 {
            raw.pop();
        }
        Ok(raw)
    }
}
fn call_ids(reads: &[Read]) -> Vec<u64> {
    reads
        .iter()
        .map(|read| match read {
            Read::Acpi(Request::Glai, _) => 1,
            Read::Acpi(Request::WideBandwidth, _) => 2,
            Read::Acpi(Request::ExternalClock | Request::Country, _) => {
                panic!("unexpected historical scalar read")
            }
            Read::Acpi(Request::Dsm(index), _) => 10 + u64::from(*index),
            Read::Uefi(Variable::GeneralConfiguration, _) => 3,
            Read::Uefi(Variable::Wbem, _) => 4,
            _ => panic!("unexpected call"),
        })
        .collect()
}
#[test]
fn locked_uefi_cache_never_fills_missing_functions_from_copied_acpi() {
    let mut session = Session::new(Model {
        scenario: 2 + 3 * 8 + 3 * 64,
    }); // locked, valid UEFI with empty bitmap
    assert_eq!(
        session.observe(lari::Input::Dsm(4)),
        lari::Observation::Unavailable
    );
    assert_eq!(
        session.observe(lari::Input::Dsm(1)),
        lari::Observation::Unavailable
    );
    assert_eq!(session.reads().len(), 2);
    assert!(matches!(session.reads()[0], Read::Acpi(Request::Glai, _)));
    assert!(matches!(
        session.reads()[1],
        Read::Uefi(Variable::GeneralConfiguration, _)
    ));
    // Invalid UEFI falls back to AML once, and reuses its original
    // values/source/revision through later UEFI getter attempts.
    let mut session = Session::new(Model {
        scenario: 2 + 2 * 8 + 3 * 64,
    });
    let value = session.observe(lari::Input::Dsm(2));
    assert!(matches!(
        value,
        lari::Observation::Observed(lari::Value {
            source: lari::Source::Acpi,
            revision: 0,
            ..
        })
    ));
    let reads = session.reads().len();
    assert_eq!(session.observe(lari::Input::Dsm(2)), value);
    assert_eq!(session.reads().len(), reads);
}
#[derive(Clone)]
struct Missing {
    request: Option<Request>,
    variable: Option<Variable>,
    error: IoError,
}
// SAFETY: modeled incomplete/failed service responses, never physical permission.
unsafe impl BiosIo for Missing {
    fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
        if self.request == Some(request) {
            return Err(self.error);
        }
        Model {
            scenario: 2 + 4 * 8 + 3 * 64,
        }
        .evaluate(request)
    }
    fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError> {
        if self.variable == Some(variable) {
            return Err(self.error);
        }
        Model {
            scenario: 2 + 4 * 8 + 3 * 64,
        }
        .variable(variable)
    }
}
/// `iwl_acpi_get_object` and `iwl_uefi_get_variable`: whatever keeps a read
/// from answering, the value is absent and selection carries on as it does
/// without it. The session still records that the read was incomplete.
#[test]
fn an_incomplete_service_or_collection_reads_as_absent() {
    for error in [IoError::Unavailable, IoError::BoundExceeded] {
        for (request, variable, input) in [
            (Some(Request::Glai), None, lari::Input::Dsm(4)),
            (
                None,
                Some(Variable::GeneralConfiguration),
                lari::Input::Dsm(4),
            ),
            (None, Some(Variable::Wbem), lari::Input::WideBandwidth),
            (
                Some(Request::WideBandwidth),
                None,
                lari::Input::WideBandwidth,
            ),
        ] {
            let mut session = Session::new(Missing {
                request,
                variable,
                error,
            });
            let mut absent = Session::new(Missing {
                request,
                variable,
                error: IoError::NotFound,
            });
            assert_eq!(session.observe(input), absent.observe(input));
            assert_eq!(call_ids(session.reads()), call_ids(absent.reads()));
            assert!(session.reads().iter().any(Read::incomplete));
            assert!(!absent.reads().iter().any(Read::incomplete));
        }
    }
    let mut session = Session::new(Missing {
        request: Some(Request::Glai),
        variable: None,
        error: IoError::Failed(0x1234),
    });
    // Source failure defaults GLAI to unlocked and can exhaust the
    // ACPI path. The exact failure remains in the original reads.
    session.observe(lari::Input::Dsm(4));
    assert_eq!(
        session.reads()[0],
        Read::Acpi(Request::Glai, Err(IoError::Failed(0x1234)))
    );
    assert!(session.reads().iter().all(|r| !matches!(r, Read::Uefi(..))));
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_BIOS_SELECTION_ORACLE"]
fn unchanged_linux_bios_selection_cache_and_complete_raw_call_order() {
    use sha2::{Digest, Sha256};
    let bytes =
        std::fs::read(std::env::var("STELA_IWLWIFI_BIOS_SELECTION_ORACLE").unwrap()).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "8e819022cad9cfa05aced446905120f3075b060bb0aabe6a1da8d4c8130269c7"
    );
    let mut current = None;
    let mut session = None;
    let mut rows = 0;
    for line in core::str::from_utf8(&bytes).unwrap().lines() {
        let f: Vec<u64> = line
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(f.len(), 9 + f[7] as usize);
        if current != Some(f[0]) {
            current = Some(f[0]);
            session = Some(Session::new(Model {
                scenario: f[0] as u32,
            }));
        }
        let session = session.as_mut().unwrap();
        let input = if f[1] == 99 {
            lari::Input::WideBandwidth
        } else {
            lari::Input::Dsm(f[1] as u8)
        };
        let result = session.observe(input);
        match result {
            lari::Observation::Observed(value) => {
                assert_eq!(f[2], 1, "{line}");
                assert_eq!(u64::from(value.value), f[3], "{line}");
                assert_eq!(
                    match value.source {
                        lari::Source::Acpi => 1,
                        lari::Source::Uefi => 2,
                    },
                    f[4],
                    "{line}"
                );
                assert_eq!(u64::from(value.revision), f[5], "{line}");
            }
            lari::Observation::Unavailable => assert_eq!(f[2], 0, "{line}"),
            lari::Observation::NotObserved => panic!("unobserved {line}"),
        }
        assert_eq!(session.locked.unwrap(), f[6] > 0, "{line}");
        assert_eq!(session.reads().len() as u64, f[7], "{line}");
        let ids = call_ids(session.reads());
        assert_eq!(ids, f[9..], "{line}");
        assert_eq!(
            ids.iter()
                .fold(0u64, |h, id| h.wrapping_mul(131).wrapping_add(*id)),
            f[8],
            "{line}"
        );
        rows += 1;
    }
    assert_eq!(rows, 65536);
    assert_eq!(current, Some(4095));
}
#[derive(Clone)]
struct ClockModel(u8);
// SAFETY: exact raw modeled ECKV namespaces; no native platform permission.
unsafe impl BiosIo for ClockModel {
    fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
        match request {
            Request::Glai => Ok(package(0, u64::from(self.0 != 4), 7)),
            Request::ExternalClock if self.0 == 5 => Err(IoError::Unavailable),
            Request::ExternalClock if self.0 == 6 => Err(IoError::NotFound),
            Request::ExternalClock => {
                Ok(package(if self.0 == 7 { 1 } else { 0 }, 0x1_0000_0001, 7))
            }
            _ => panic!("unrequested clock source"),
        }
    }
    fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError> {
        assert_eq!(variable, Variable::Eckv);
        match self.0 {
            0 => Ok(vec![0, 2, 0, 0, 0]),
            1 => Ok(vec![99, 2, 0, 0, 0]),
            2 => Err(IoError::Unavailable),
            3 => Err(IoError::BoundExceeded),
            _ => Err(IoError::NotFound),
        }
    }
}
#[test]
fn clock_selection_requires_source_and_takes_an_unread_one_as_absent() {
    for scenario in 0..8 {
        let mut session = Session::new(ClockModel(scenario));
        let result = session.external_clock();
        let expected = match scenario {
            0 => lari::Observation::Observed(lari::Value {
                value: 2,
                source: lari::Source::Uefi,
                revision: 0,
            }),
            5..=7 => lari::Observation::Unavailable,
            _ => lari::Observation::Observed(lari::Value {
                value: 1,
                source: lari::Source::Acpi,
                revision: 0,
            }),
        };
        assert_eq!(result, expected, "{scenario}");
        let count = session.reads().len();
        assert_eq!(session.external_clock(), expected);
        assert_eq!(session.reads().len(), count);
        assert_eq!(count, if scenario == 0 || scenario == 4 { 2 } else { 3 });
        assert_eq!(
            session.reads().iter().any(Read::incomplete),
            matches!(scenario, 2 | 3 | 5),
            "{scenario}"
        );
        if scenario == 4 {
            assert!(matches!(
                session.reads()[1],
                Read::Acpi(Request::ExternalClock, _)
            ));
        }
    }
}
#[derive(Clone)]
struct CountryModel(u8);
// SAFETY: modeled BIOS service reads, never a real location issuer.
unsafe impl BiosIo for CountryModel {
    fn evaluate(&mut self, request: Request) -> Result<Object, IoError> {
        match request {
            Request::Glai => Ok(package(0, 1, 7)),
            Request::Country if self.0 == 4 => Err(IoError::Unavailable),
            Request::Country if self.0 == 5 => Err(IoError::NotFound),
            Request::Country => Ok(package(
                0,
                if self.0 == 3 { 0x5553 } else { 0x1_0000_434e },
                7,
            )),
            _ => panic!("unexpected country read"),
        }
    }
    fn variable(&mut self, variable: Variable) -> Result<Vec<u8>, IoError> {
        assert_eq!(variable, Variable::Wrdd);
        match self.0 {
            0 => Ok(vec![0, 0x4e, 0x43, 0, 0]),
            1 => Ok(vec![0, 0x53, 0x55, 0, 0]),
            2 => Err(IoError::Unavailable),
            _ => Err(IoError::NotFound),
        }
    }
}
#[test]
fn bios_country_accepts_only_cn_and_takes_an_unread_one_as_absent() {
    for scenario in 0..6 {
        let mut session = Session::new(CountryModel(scenario));
        let result = session.country();
        let expected = match scenario {
            0..=2 => lari::Observation::Observed(lari::Value {
                value: 0x434e,
                source: if scenario == 0 {
                    lari::Source::Uefi
                } else {
                    lari::Source::Acpi
                },
                revision: 0,
            }),
            _ => lari::Observation::Unavailable,
        };
        assert_eq!(result, expected, "{scenario}");
        assert_eq!(
            session.reads().iter().any(Read::incomplete),
            matches!(scenario, 2 | 4)
        );
        let reads = session.reads().len();
        assert_eq!(session.country(), expected);
        assert_eq!(session.reads().len(), reads);
    }
}
