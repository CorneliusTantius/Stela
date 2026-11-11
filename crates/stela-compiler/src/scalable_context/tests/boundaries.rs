use super::*;

#[test]
fn ordinary_payload_and_maps_preserve_original_bytes() {
    let source = words(&[NOP, 0xd280_00e0, RET_X30]);
    let old = crate::testing::leaf(&source, GuestAddress(0x1000)).unwrap();
    let new = crate::testing::context_leaf(
        &source,
        GuestAddress(0x1000),
        profile(32, true),
        TargetCpu::Baseline,
    )
    .unwrap();
    assert_eq!(&new.x86_64_code[CONTEXT_WRAPPER_BYTES..], old.x86_64_code);
    assert_eq!(
        new.source_map,
        old.source_map
            .iter()
            .map(|(pc, offset)| (*pc, offset + CONTEXT_WRAPPER_BYTES))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        context_wrapper(),
        [
            0x41, 0x57, 0x49, 0x89, 0xf7, // push r15; mov r15, rsi
            0x4c, 0x8d, 0x5c, 0x24, 0xf8, // lea r11, [rsp - 8]
            0x4c, 0x89, 0x9f, 0x88, 0x03, 0, 0, // mov [rdi + exit_rsp], r11
            0xe8, 3, 0, 0, 0, 0x41, 0x5f, 0xc3 // call body; pop r15; ret
        ]
    );
}

#[test]
fn variable_length_modes_and_prefix_boundary_are_explicit() {
    for bytes in [16, 32, 64, 128, 256] {
        let source = words(&[AND_Z0_Z1_Z2, RDSVL_X0_ONE, RET_X30]);
        assert!(
            crate::testing::context_leaf(
                &source,
                GuestAddress(0),
                profile(bytes, true),
                TargetCpu::Baseline
            )
            .is_ok()
        );
        assert!(
            crate::testing::context_leaf(
                &source,
                GuestAddress(0),
                profile(bytes, false),
                TargetCpu::Baseline
            )
            .unwrap_err()
            .to_string()
            .contains("streaming mode required")
        );
        assert!(
            crate::testing::context_leaf(
                &words(&[RDSVL_X0_ONE, RET_X30]),
                GuestAddress(0),
                profile(bytes, false),
                TargetCpu::Baseline
            )
            .is_ok()
        );
    }
    assert!(
        crate::testing::context_leaf(
            &words(&[MOVPRFX_Z0_Z1, AND_Z0_Z1_Z2, RET_X30]),
            GuestAddress(0),
            profile(32, true),
            TargetCpu::Baseline
        )
        .unwrap_err()
        .to_string()
        .contains("MOVPRFX pair validation")
    );
    for word in [0xf940_0020, 0x4e22_8420, 0x1e22_2820] {
        assert!(
            crate::testing::context_leaf(
                &words(&[word, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline
            )
            .is_err()
        );
    }
}
#[test]
fn branches_resolve_across_scalable_instruction_bodies() {
    const BRANCH_PLUS_EIGHT: u32 = 0x1400_0002;
    let native = crate::testing::context_leaf(
        &words(&[BRANCH_PLUS_EIGHT, AND_Z0_Z1_Z2, RET_X30]),
        GuestAddress(0),
        profile(32, true),
        TargetCpu::Baseline,
    )
    .unwrap();
    let branch = native.source_map[0].1;
    assert_eq!(native.x86_64_code[branch], 0xe9);
    let displacement = i32::from_le_bytes(
        native.x86_64_code[branch + 1..branch + 5]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        (branch + 5) as i64 + i64::from(displacement),
        native.source_map[2].1 as i64
    );
}

#[test]
fn multi_vector_integer_access_and_legacy_abi_boundaries() {
    const ADD_PAIR: u32 = 0xc120_a300;
    const SQCVT_PAIR: u32 = 0xc123_e000;
    const SVE_SQCVTN_PAIR: u32 = 0x4531_4000;
    const SRSHL_PAIR: u32 = 0xc120_a220;
    const RESERVED_QUARTET_SHIFT: u32 = 0xc120_d800;
    let features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
    let declared = |bytes, streaming| {
        let length = VectorLength::from_bytes(bytes).unwrap();
        ScalableProfile::new_with_features(
            length,
            ScalableMode::new(streaming, false),
            features,
            ScalableControls::new(length, false),
        )
        .unwrap()
    };
    for word in [ADD_PAIR, SQCVT_PAIR, SVE_SQCVTN_PAIR, SRSHL_PAIR] {
        let source = words(&[word, RET_X30]);
        assert!(crate::testing::leaf(&source, GuestAddress(0)).is_err());
        let compatible = crate::testing::context_leaf(
            &source,
            GuestAddress(0),
            profile(16, true),
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(
            compatible.source_map[0],
            (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
        );
        for bytes in [16, 32, 64, 128, 256] {
            for streaming in [false, true] {
                let result = crate::testing::context_leaf(
                    &source,
                    GuestAddress(0),
                    declared(bytes, streaming),
                    TargetCpu::Baseline,
                );
                if streaming {
                    let native = result.unwrap();
                    assert_eq!(
                        native.source_map[0],
                        (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                    );
                    assert_eq!(native.source_map[1].0, GuestAddress(4));
                } else {
                    assert!(matches!(
                        result.unwrap_err().kind,
                        crate::CompileErrorKind::StreamingModeRequired
                    ));
                }
            }
        }
    }
    assert!(
        crate::testing::context_leaf(
            &words(&[RESERVED_QUARTET_SHIFT, RET_X30]),
            GuestAddress(0),
            declared(16, true),
            TargetCpu::Baseline,
        )
        .unwrap_err()
        .to_string()
        .contains("reserved multi-vector integer")
    );
    let sme_only = ScalableProfile::new_with_features(
        VectorLength::from_bytes(16).unwrap(),
        ScalableMode::new(true, false),
        ScalableFeatures::of(ScalableFeature::Sme),
        ScalableControls::new(VectorLength::from_bytes(16).unwrap(), false),
    )
    .unwrap();
    for word in [ADD_PAIR, SQCVT_PAIR, SVE_SQCVTN_PAIR, SRSHL_PAIR] {
        assert!(
            crate::testing::context_leaf(
                &words(&[word, RET_X30]),
                GuestAddress(0),
                sme_only,
                TargetCpu::Baseline,
            )
            .is_err()
        );
    }
}

#[test]
fn floating_copies_require_streaming_without_za() {
    const FCPY_HALF_P15_Z31: u32 = 0x055f_ce1f;
    const FDUP_DOUBLE_Z31: u32 = 0x25f9_ce1f;
    const RESERVED_FCPY_SIZE: u32 = 0x051f_ce1f;
    for bytes in [16, 32, 64, 128, 256] {
        for svcr in 0..=3 {
            let profile = ScalableProfile::new(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::from_svcr(svcr).unwrap(),
            );
            let source = words(&[FCPY_HALF_P15_Z31, FDUP_DOUBLE_Z31, RET_X30]);
            let result = crate::testing::context_leaf(
                &source,
                GuestAddress(0),
                profile,
                TargetCpu::Baseline,
            );
            if profile.mode().streaming() {
                let native = result.unwrap();
                assert_eq!(
                    native.source_map[0],
                    (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                );
                assert_eq!(native.source_map[1].0, GuestAddress(4));
                assert!(native.source_map[1].1 > native.source_map[0].1);
            } else {
                assert!(matches!(
                    result.unwrap_err().kind,
                    crate::CompileErrorKind::StreamingModeRequired
                ));
            }
        }
    }
    assert!(crate::testing::leaf(&words(&[FCPY_HALF_P15_Z31, RET_X30]), GuestAddress(0)).is_err());
    assert!(
        crate::testing::context_leaf(
            &words(&[RESERVED_FCPY_SIZE, RET_X30]),
            GuestAddress(0),
            profile(16, true),
            TargetCpu::Baseline
        )
        .unwrap_err()
        .to_string()
        .contains("reserved streaming floating copy")
    );
}
