// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn rx_recycling_publishes_initial_tail_and_sustains_command_ring_wraps() {
    if crate::test_process::isolate_model() {
        return;
    }
    exercise_rx_recycling(None);
}

#[test]
#[ignore = "oracle: STELA_IWLWIFI_RX_RECYCLE_ORACLE"]
fn rx_recycling_unchanged_source_free_producer_and_vid_oracle() {
    if crate::test_process::isolate_model() {
        return;
    }
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_RX_RECYCLE_ORACLE").unwrap()).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "6b4528a5d64209cc87aa2976e58fd0c358f76a15642557e263f10e830af8732d"
    );
    exercise_rx_recycling(Some(core::str::from_utf8(&bytes).unwrap()));
}

#[test]
fn rx_recycling_waits_for_target_slot_completion_when_payloads_complete_out_of_order() {
    if crate::test_process::isolate_model() {
        return;
    }
    let bytes = firmware_bytes();
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = Arc::new(Mutex::new(ModelState::default()));
    let drops = Arc::new(AtomicUsize::new(0));
    let boot = start(&catalog, &source, &domain, &state, &drops);
    let mut boot = command_ready(boot, &empty, &source, &domain, &state);
    boot.replenish_completed_receive().unwrap();
    for (index, vid, expected_return, expected_wait) in
        [(1, 3, 1, false), (2, 4, 0, true), (3, 2, 2, false)]
    {
        // SAFETY: Each direct-payload command uses the same model owner/Source/Domain;
        // completions are serialized, with no indirect resources or competing submitter.
        let ticket = unsafe { boot.submit_command(command_id(), &[], &source) }.unwrap();
        complete_from_free_slot(
            &boot,
            &domain,
            index,
            vid,
            vid - 1,
            &command_packet(command_id(), ticket.sequence(), &[]),
        );
        assert!(matches!(
            boot.poll_command(&ticket).unwrap(),
            CommandProgress::Completed(_)
        ));
        let r = boot.replenish_completed_receive().unwrap();
        assert_eq!(r.returned, expected_return);
        assert_eq!(r.waiting_for_completed_slot, expected_wait);
        assert_eq!(r.published, 0);
    }
    boot.stop().unwrap();
    assert!(domain.records.lock().unwrap().live.is_empty());
}

/// `iwl_pcie_rx_handle`: an RB the device marks as continued in the next one
/// is dropped with that next one, and reception carries on after them.
#[test]
fn a_fragmented_rb_and_its_continuation_are_dropped_and_reception_continues() {
    if crate::test_process::isolate_model() {
        return;
    }
    let bytes = ax210_bytes();
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let (observation, step_catalog) = step_fixture();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = ax210_state();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut boot = start_ax210(
        &catalog,
        crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
        &source,
        &domain,
        &state,
        &drops,
    );
    event(&state, 1);
    boot.poll().unwrap();
    let alive = rx_packet(1, 0xcafe, 0);
    complete(&boot, &domain, 0, 1, &alive);
    // The fragmented-RB flag of the AX210 completion descriptor.
    device_write(&domain, boot.used.region().address, 6, &[1], false);
    complete(&boot, &domain, 1, 2, &alive);
    assert!(boot.poll().unwrap().is_none(), "both halves are dropped");
    assert!(!boot.buffers[0].device_owned && !boot.buffers[1].device_owned);
    complete(&boot, &domain, 2, 3, &alive);
    assert!(boot.poll().unwrap().is_some());
    boot.stop().unwrap();
    drop(boot);
    assert!(domain.records.lock().unwrap().live.is_empty());
}

#[test]
fn rx_recycling_faults_keep_dma_and_requester() {
    if crate::test_process::isolate_model() {
        return;
    }
    for failure in 0..4 {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        if failure == 3 {
            boot.replenish_completed_receive().unwrap();
            // SAFETY: This sole model owner keeps its original Source/Domain and RAM;
            // the empty fixture command has no indirect objects before receive-fault injection.
            let ticket = unsafe { boot.submit_command(command_id(), &[], &source) }.unwrap();
            complete(
                &boot,
                &domain,
                1,
                2,
                &command_packet(command_id(), ticket.sequence(), &[]),
            );
            assert!(matches!(
                boot.poll_command(&ticket).unwrap(),
                CommandProgress::Completed(_)
            ));
            let mut r = domain.records.lock().unwrap();
            r.cpu_sync_fail = Some(r.cpu_syncs);
        } else if failure < 2 {
            let mut r = domain.records.lock().unwrap();
            r.sync_fail = Some(r.syncs + failure);
        } else {
            let mut s = state.lock().unwrap();
            s.fail = Some(s.ops.len());
        }
        let live = domain.records.lock().unwrap().live.len();
        assert!(boot.replenish_completed_receive().is_err());
        assert_eq!(boot.state, State::Poisoned);
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        {
            let mut s = state.lock().unwrap();
            s.fail = None;
            s.stop_ack = false;
        }
        assert!(boot.stop().is_err());
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
    }
}
