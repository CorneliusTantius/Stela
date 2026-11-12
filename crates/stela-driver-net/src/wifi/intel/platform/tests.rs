use super::super::identity::Observed;
use super::*;
use resources::{Catalog, ErrorKind};
#[test]
fn radio_descriptor_identities_minima_and_collection_bounds_are_exact() {
    let expected = [
        ("UefiCnvWlanWRDS", 49, 53, false),
        ("UefiCnvWlanEWRD", 141, 153, false),
        ("UefiCnvWlanWGDS", 74, 98, false),
        ("UefiCnvWlanPPAG", 27, 4096, false),
        ("UefiCnvWlanWRDD", 5, 4096, false),
        ("UefiCnvWlanGeneralCfg", 129, 4096, false),
        ("UefiCnvWlanWBEM", 5, 4096, false),
        ("UefiCnvCommonECKV", 5, 4096, true),
        ("UefiCnvWlanWTAS", 38, 4096, false),
        ("UefiCnvWlanSPLC", 5, 4096, false),
        ("WPFC", 17, 4096, false),
        ("UefiCnvWlanSarGeoOffsetMapping", 339, 4096, false),
        ("CnvUefiWlanUATS", 339, 4096, false),
        ("CnvUefiWlanUNEB", 339, 4096, false),
        ("UefiCnvWlanPuncturing", 5, 4096, false),
    ];
    assert_eq!(expected.len(), RADIO_VARIABLE_COUNT);
    let mut observations = Observations::default();
    for (index, descriptor) in VARIABLE_DESCRIPTORS.iter().enumerate() {
        let variable = descriptor.variable;
        assert_eq!(variable as usize, index);
        assert_eq!(variable.descriptor().variable, variable);
        assert_eq!(observations.get(variable), Observation::NotCaptured);
        assert!(
            VARIABLE_DESCRIPTORS[..index]
                .iter()
                .all(|other| other.name != descriptor.name
                    && other.resource_name != descriptor.resource_name)
        );
        assert_eq!(
            variable.bounded_bytes(Stage::Probe, 5, descriptor.maximum_bytes as u64),
            Ok(descriptor.maximum_bytes)
        );
        assert_eq!(
            variable.bounded_bytes(Stage::Probe, 5, descriptor.maximum_bytes as u64 + 1),
            Err(Observation::BoundExceeded {
                stage: Stage::Probe,
                status: 5,
                reported_bytes: descriptor.maximum_bytes as u64 + 1
            })
        );
        observations.set(
            variable,
            Observation::from_error(Stage::Read, 0x8000_0000_0000_0007, Some(index as u64)),
        );
        assert_eq!(
            observations.get(variable),
            Observation::Failed {
                stage: Stage::Read,
                status: 0x8000_0000_0000_0007,
                reported_bytes: Some(index as u64)
            }
        );
        if index < Variable::Wrds as usize {
            continue;
        }
        let (name, minimum, maximum, common) = expected[index - Variable::Wrds as usize];
        assert_eq!(variable.name(), name);
        assert_eq!(variable.resource_name(), format!("intel/uefi/{name}.bin"));
        assert_eq!(
            variable.guid(),
            if common { WIFI_BT_GUID } else { WIFI_GUID }
        );
        assert_eq!(variable.requirement().minimum_bytes, minimum);
        assert_eq!(variable.maximum_bytes(), maximum);
        assert_eq!(variable.requirement().target.revision, name);
        assert_eq!(variable.requirement().target.board, None);
    }
}

#[test]
fn radio_loader_refuses_package_and_step_variables_before_provider_access() {
    struct UnexpectedProvider;
    impl resources::Provider for UnexpectedProvider {
        fn load<'a>(
            &'a self,
            _: resources::Requirement<'_>,
        ) -> Result<resources::Image<'a>, resources::Error> {
            panic!("wrong variable must be refused before Provider access")
        }
    }
    for variable in [Variable::OemPnvm, Variable::ReducedPower, Variable::Step] {
        assert!(matches!(
            load_radio_image(variable, Observation::NotCaptured, &UnexpectedProvider),
            Err(LoadError::Package(PackageError::WrongVariable))
        ));
    }
}

#[test]
fn raw_radio_bytes_stay_present_without_package_or_permission_inference() {
    for descriptor in &VARIABLE_DESCRIPTORS[Variable::Wrds as usize..] {
        let variable = descriptor.variable;
        let raw = vec![0xa5; descriptor.minimum_bytes + 1];
        let mut captured = CapturedVariable::from_variable(
            variable,
            raw,
            0x87,
            Some(descriptor.minimum_bytes as u64 + 1),
        )
        .unwrap();
        let observation = captured.observation();
        let resource = captured.take_resource().unwrap();
        let pointer = resource.bytes.as_ptr();
        let catalog = Catalog::from_handoff(vec![resource]).unwrap();
        let image = load_radio_image(variable, observation, &catalog).unwrap();
        assert_eq!(image.bytes().as_ptr(), pointer);
        assert_eq!(image.bytes().len(), descriptor.minimum_bytes + 1);
        assert_eq!(image.target(), variable.requirement().target);
        assert_eq!(image.provenance().source, variable.origin());
        assert_eq!(image.provenance().license, DATA_LICENSE);
        assert!(matches!(
            load(variable, observation, &catalog),
            Err(LoadError::Package(PackageError::WrongVariable))
        ));
        assert!(matches!(
            load_radio_image(variable, Observation::NotCaptured, &catalog),
            Err(LoadError::Package(PackageError::Unobserved))
        ));
        for length in [0, descriptor.minimum_bytes - 1] {
            let mut short =
                CapturedVariable::from_variable(variable, vec![0; length], 0, Some(length as u64))
                    .unwrap();
            let observation = short.observation();
            assert!(
                matches!(observation, Observation::Present { bytes, .. } if bytes == length as u64)
            );
            let catalog = Catalog::from_handoff(vec![short.take_resource().unwrap()]).unwrap();
            assert!(
                matches!(load_radio_image(variable, observation, &catalog), Err(LoadError::Resource(error)) if error.kind == ErrorKind::Truncated { expected: descriptor.minimum_bytes, actual: length })
            );
        }
    }
}
#[test]
fn custom_provider_cannot_redirect_an_observed_resource_name_or_target() {
    use resources::{Image, Provider, Requirement};
    struct Redirect<'a> {
        image: Image<'a>,
        expected: Requirement<'static>,
    }
    impl Provider for Redirect<'_> {
        fn load(&self, requirement: Requirement<'_>) -> Result<Image<'_>, resources::Error> {
            assert_eq!(requirement.name, self.expected.name);
            assert_eq!(requirement.target, self.expected.target);
            assert_eq!(requirement.minimum_bytes, self.expected.minimum_bytes);
            Ok(self.image)
        }
    }
    for variable in VARIABLE_DESCRIPTORS
        .iter()
        .map(|descriptor| descriptor.variable)
    {
        for changed in 0..6 {
            let raw = if variable == Variable::Step {
                vec![1, 0xfe, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb]
            } else if matches!(variable, Variable::OemPnvm | Variable::ReducedPower) {
                package()
            } else {
                vec![0; variable.descriptor().minimum_bytes]
            };
            let mut captured = CapturedVariable::from_variable(variable, raw, 7, None).unwrap();
            let observation = captured.observation();
            let mut resource = captured.take_resource().unwrap();
            match changed {
                0 => {} // Exact custom-provider binding is accepted.
                1 => resource.name = "redirected/raw.bin",
                2 => resource.target.driver = "redirected",
                3 => resource.target.hardware = "uefi:other",
                4 => resource.target.revision = "other-observation",
                _ => resource.target.board = Some("other-board"),
            }
            let redirected = Requirement {
                name: resource.name,
                target: resource.target,
                minimum_bytes: variable.requirement().minimum_bytes,
            };
            let catalog = Catalog::from_handoff(vec![resource]).unwrap();
            let provider = Redirect {
                image: catalog.load(redirected).unwrap(),
                expected: variable.requirement(),
            };
            let result = if variable == Variable::Step {
                load_step(observation, &provider).map(|_| ())
            } else if matches!(variable, Variable::OemPnvm | Variable::ReducedPower) {
                load(variable, observation, &provider).map(|_| ())
            } else {
                load_radio_image(variable, observation, &provider).map(|_| ())
            };
            if changed == 0 {
                assert!(result.is_ok());
            } else {
                assert!(
                    matches!(
                        result,
                        Err(LoadError::Package(PackageError::ObservationMismatch))
                    ),
                    "{variable:?} field {changed}"
                );
            }
        }
    }
}
/// `iwl_uefi_get_step_table` ignores a STEP variable it cannot read or whose
/// revision is not 1: the firmware boots with both mailboxes zero.
#[test]
fn an_unusable_step_variable_boots_with_zero_mailboxes_as_linux_does() {
    let empty = Catalog::from_handoff(vec![]).unwrap();
    for observation in [
        Observation::NotCaptured,
        Observation::from_error(Stage::Read, (1 << 63) | 21, None),
        Observation::BoundExceeded {
            stage: Stage::Probe,
            status: 0,
            reported_bytes: MAX_VARIABLE_BYTES as u64 + 1,
        },
    ] {
        let step = load_step_or_ignore(observation, &empty);
        assert_eq!(step.mailboxes(), [0; 2]);
        assert!(step.ignored().is_some(), "{observation:?}");
        assert!(step.step().is_none() && step.image().is_none());
    }
    let mut captured =
        CapturedVariable::from_variable(Variable::Step, vec![2, 0, 1, 2, 3, 4], 7, None).unwrap();
    let observation = captured.observation();
    let catalog = Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap();
    let step = load_step_or_ignore(observation, &catalog);
    assert!(matches!(
        step.ignored(),
        Some(LoadError::Step(StepError::Revision(2)))
    ));
    assert_eq!(step.mailboxes(), [0; 2]);
    let absent = load_step_or_ignore(
        Observation::from_error(Stage::Probe, NOT_FOUND, None),
        &empty,
    );
    assert!(absent.ignored().is_none());
    let mut captured =
        CapturedVariable::from_variable(Variable::Step, vec![1, 0, 1, 2, 3, 4], 7, None).unwrap();
    let observation = captured.observation();
    let catalog = Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap();
    let step = load_step_or_ignore(observation, &catalog);
    assert!(step.ignored().is_none());
    assert_eq!(step.mailboxes(), [0x03020101, 4]);
}

#[test]
fn borrowed_permanent_capture_keeps_the_byte_pointer_and_provenance() {
    static RAW: [u8; 8] = [1, 0xfe, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb];
    let mut capture =
        CapturedVariable::from_variable(Variable::Step, &RAW[..], 0x87, Some(12)).unwrap();
    let observation = capture.observation();
    let catalog = Catalog::from_persistent_handoff(vec![capture.take_resource().unwrap()]).unwrap();
    assert!(capture.take_resource().is_none());
    let loaded = load_step(observation, &catalog).unwrap();
    assert_eq!(loaded.image().unwrap().bytes().as_ptr(), RAW.as_ptr());
    assert_eq!(
        loaded.image().unwrap().provenance().source,
        "UEFI GetVariable e65d8884-d4af-4b20-8d03-772ecc3da531"
    );
    assert_eq!(loaded.image().unwrap().provenance().license, DATA_LICENSE);
    assert_eq!(loaded.mailboxes(), [0x56341201, 0x78]);
    assert_eq!(loaded.observation(), observation);
}
fn profile(ax210: bool) -> Profile {
    Profile::select(Observed {
        link_speed: 3,
        silicon: Default::default(),
        vendor: 0x8086,
        device: if ax210 { 0x2725 } else { 0x2723 },
        subsystem_vendor: 0x8086,
        subsystem_device: 0x84,
        pci_revision: 0x1a,
        hardware_revision: if ax210 { 0x420 } else { 0x340 },
        radio_id: if ax210 { 0x10d000 } else { 0x10a000 },
    })
    .unwrap()
}
fn package() -> Vec<u8> {
    vec![
        7, 0x78, 0x56, 0x34, 0x12, 3, 1, 2, 3, 4, 5, 6, 7, 8, 0xaa, 0xbb,
    ]
}
#[test]
fn captured_resource_moves_bytes_once_and_checks_observation() {
    for variable in [Variable::OemPnvm, Variable::ReducedPower] {
        let bytes = package();
        let original = bytes.as_ptr();
        let mut captured = CapturedVariable::from_variable(variable, bytes, 7, Some(123)).unwrap();
        let observation = captured.observation();
        let resource = captured.take_resource().unwrap();
        assert_eq!(resource.bytes.as_ptr(), original);
        assert_eq!(resource.target, variable.requirement().target);
        assert_eq!(resource.provenance.license, DATA_LICENSE);
        let catalog = Catalog::from_handoff(vec![resource]).unwrap();
        assert!(captured.take_resource().is_none());
        let loaded = load(variable, observation, &catalog).unwrap();
        assert_eq!(loaded.package.raw().as_ptr(), original);
        assert_eq!(loaded.package.payload(), [0xaa, 0xbb]);
        assert_eq!(loaded.package.revision(), 7);
        assert_eq!(loaded.package.declared_total_size(), 0x12345678);
        assert_eq!(loaded.package.declared_skus(), 3);
        assert_eq!(loaded.package.reserved(), [0x04030201, 0x08070605]);
        let Observation::Present {
            attributes,
            bytes,
            sha256,
            probe_reported_bytes,
        } = observation
        else {
            panic!()
        };
        for changed in [
            Observation::Present {
                attributes: attributes ^ 1,
                bytes,
                sha256,
                probe_reported_bytes,
            },
            Observation::Present {
                attributes,
                bytes: bytes + 1,
                sha256,
                probe_reported_bytes,
            },
            Observation::Present {
                attributes,
                bytes,
                sha256: [0; 32],
                probe_reported_bytes,
            },
        ] {
            assert!(matches!(
                load(variable, changed, &catalog),
                Err(LoadError::Package(PackageError::ObservationMismatch))
            ));
        }
        assert!(
            matches!(load(if variable==Variable::OemPnvm {Variable::ReducedPower} else {Variable::OemPnvm}, observation,&catalog),Err(LoadError::Resource(e)) if e.kind==ErrorKind::Missing)
        );
    }
}
#[test]
fn errors_absence_bounds_empty_and_collision_are_distinct() {
    assert!(matches!(
        Observation::from_error(Stage::Probe, NOT_FOUND, None),
        Observation::Absent { .. }
    ));
    assert!(matches!(
        Observation::from_error(Stage::Read, (1 << 63) | 5, Some(99)),
        Observation::Failed {
            reported_bytes: Some(99),
            ..
        }
    ));
    assert!(matches!(
        Observation::bounded_bytes(Stage::Probe, 0, MAX_VARIABLE_BYTES as u64 + 1),
        Err(Observation::BoundExceeded { .. })
    ));
    assert_eq!(Observation::bounded_bytes(Stage::Probe, 0, 0), Ok(0));
    let empty = Catalog::from_handoff(vec![]).unwrap();
    for (observation, expected) in [
        (Observation::NotCaptured, PackageError::Unobserved),
        (
            Observation::from_error(Stage::Read, NOT_FOUND, None),
            PackageError::Absent,
        ),
        (
            Observation::from_error(Stage::Read, 9, None),
            PackageError::FailedObservation,
        ),
    ] {
        assert!(
            matches!(load(Variable::OemPnvm,observation,&empty),Err(LoadError::Package(e)) if e==expected)
        );
    }
    let mut captured = CapturedVariable::from_variable(Variable::OemPnvm, vec![], 7, None).unwrap();
    let observation = captured.observation();
    assert!(matches!(observation, Observation::Present { bytes: 0, .. }));
    let catalog = Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap();
    assert!(
        matches!(load(Variable::OemPnvm,observation,&catalog),Err(LoadError::Resource(e)) if matches!(e.kind,ErrorKind::Truncated{actual:0,..}))
    );
    for n in 0..14 {
        assert_eq!(Package::parse(&vec![0; n]).unwrap_err(), PackageError::Size);
    }
    let mut a = CapturedVariable::from_variable(Variable::OemPnvm, package(), 7, None).unwrap();
    let mut b = CapturedVariable::from_variable(Variable::OemPnvm, package(), 7, None).unwrap();
    assert!(
        matches!(Catalog::from_handoff(vec![a.take_resource().unwrap(),b.take_resource().unwrap()]),Err(e) if e.kind==ErrorKind::Duplicate)
    );
}
#[test]
fn configured_platform_shadow_and_provenance_changes_refuse() {
    for field in 0..4 {
        let mut captured =
            CapturedVariable::from_variable(Variable::OemPnvm, package(), 7, None).unwrap();
        let observation = captured.observation();
        let mut resource = captured.take_resource().unwrap();
        match field {
            0 => resource.provenance.source = "configured",
            1 => resource.provenance.member = "other",
            2 => resource.provenance.license = "MIT",
            _ => resource.provenance.revision = "other",
        }
        let catalog = Catalog::from_handoff(vec![resource]).unwrap();
        assert!(matches!(
            load(Variable::OemPnvm, observation, &catalog),
            Err(LoadError::Package(PackageError::ObservationMismatch))
        ));
    }
    let mut a = CapturedVariable::from_variable(Variable::OemPnvm, package(), 7, None).unwrap();
    let mut different = package();
    different.push(0);
    let mut b = CapturedVariable::from_variable(Variable::OemPnvm, different, 7, None).unwrap();
    assert!(
        matches!(Catalog::from_handoff(vec![a.take_resource().unwrap(),b.take_resource().unwrap()]),Err(e) if e.kind==ErrorKind::Conflict)
    );
}
#[test]
fn sku_source_policy_has_no_default_image() {
    for ax210 in [false, true] {
        let p = profile(ax210);
        assert_eq!(
            post_alive_plan(&p, [0; 3]),
            PostAlivePlan {
                pnvm: PnvmSource::None,
                observe_reduced_power: false,
                pnvm_completion_required: false
            }
        );
        assert_eq!(
            post_alive_plan(&p, [1, 2, 0]),
            PostAlivePlan {
                pnvm: if ax210 {
                    PnvmSource::External
                } else {
                    PnvmSource::None
                },
                observe_reduced_power: true,
                pnvm_completion_required: true
            }
        );
        assert_eq!(
            post_alive_plan(&p, [1, 2, 3]),
            PostAlivePlan {
                pnvm: PnvmSource::Bios {
                    external_fallback: ax210
                },
                observe_reduced_power: true,
                pnvm_completion_required: true
            }
        );
    }
}
#[test]
fn step_uses_distinct_guid_absence_and_full_observed_resource() {
    assert_eq!(Variable::Step.guid(), WIFI_BT_GUID);
    assert_ne!(
        Variable::Step.requirement().target.hardware,
        Variable::OemPnvm.requirement().target.hardware
    );
    assert_eq!(
        Observations::default().get(Variable::Step),
        Observation::NotCaptured
    );
    let catalog = Catalog::from_handoff(vec![]).unwrap();
    let absence = Observation::from_error(Stage::Probe, NOT_FOUND, None);
    let absent = load_step(absence, &catalog).unwrap();
    assert_eq!(absent.observation(), absence);
    assert_eq!(absent.mailboxes(), [0; 2]);
    assert!(absent.image().is_none());
    assert!(absent.step().is_none());
    for observation in [
        Observation::NotCaptured,
        Observation::from_error(Stage::Read, 9, None),
        Observation::Absent {
            stage: Stage::Read,
            status: 0,
            reported_bytes: None,
        },
    ] {
        assert!(load_step(observation, &catalog).is_err());
    }
    let bytes = vec![1, 0xfe, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb];
    let pointer = bytes.as_ptr();
    let mut captured = CapturedVariable::from_variable(Variable::Step, bytes, 7, Some(8)).unwrap();
    let observation = captured.observation();
    let catalog = Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap();
    let loaded = load_step(observation, &catalog).unwrap();
    assert_eq!(loaded.mailboxes(), [0x56341201, 0x78]);
    assert_eq!(loaded.step().unwrap().step_mode(), 0xfe);
    assert_eq!(
        loaded.step().unwrap().raw(),
        [1, 0xfe, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xbb]
    );
    assert_eq!(loaded.image().unwrap().bytes().as_ptr(), pointer);
    assert!(matches!(
        load(Variable::Step, observation, &catalog),
        Err(LoadError::Package(PackageError::WrongVariable))
    ));
    for n in 0..6 {
        assert_eq!(Step::parse(&vec![1; n]).unwrap_err(), StepError::Size);
    }
    for revision in [0, 2, 255] {
        assert_eq!(
            Step::parse(&[revision, 0, 0, 0, 0, 0]).unwrap_err(),
            StepError::Revision(revision)
        );
    }
    let mut captured =
        CapturedVariable::from_variable(Variable::Step, vec![1; 5], 7, None).unwrap();
    let observation = captured.observation();
    let catalog = Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap();
    assert!(
        matches!(load_step(observation,&catalog),Err(LoadError::Resource(e)) if matches!(e.kind,ErrorKind::Truncated{expected:6,actual:5}))
    );
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_STEP_ORACLE"]
fn unchanged_linux_step_mailboxes_and_every_revision() {
    extern crate std;
    use core::fmt::Write;
    let trace =
        std::fs::read(std::env::var("STELA_IWLWIFI_STEP_ORACLE").expect("STEP trace")).unwrap();
    let digest: String = Sha256::digest(&trace)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest,
        "6841f423d0d5720aba4037c12811cd4a1cb58cf5252354777b58ab4160f26152"
    );
    let mut actual = String::new();
    for revision in 0..=255 {
        let bytes = [revision, 0xfe, 0x12, 0x34, 0x56, 0x78];
        match Step::parse(&bytes) {
            Ok(step) => {
                let words = step.mailboxes();
                writeln!(actual, "step {revision} ok {:x} {:x}", words[0], words[1]).unwrap();
            }
            Err(StepError::Revision(actual_revision)) => {
                assert_eq!(actual_revision, revision);
                writeln!(actual, "step {revision} invalid 0 0").unwrap();
            }
            other => panic!("unexpected STEP result {other:?}"),
        }
    }
    assert_eq!(actual.as_bytes(), trace);
}
