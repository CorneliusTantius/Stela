// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Shared Intel boot fixtures and protocol cases.
extern crate std;
use super::super::{
    dma::tests::{Domain, Records, Source},
    identity::Observed,
    power::ManagementSession,
};
use super::*;
use alloc::collections::BTreeMap;
use cold_fixture::exercise_cold_radio;
use core::sync::atomic::AtomicUsize;
use initialization::{
    alive_ax210, command_id, command_packet, command_ready, drive_cold_prefix, drive_nvm,
};
use inputs::{
    ax210_bytes, firmware_bytes, lari_bytes, nvm_response, pnvm_packet, radio_bytes, set_sku,
    unified_bytes,
};
use lari_fixture::exercise_lari_bios;
use model::{Model, ModelState, Op, Owner};
use mpdu_fixture::exercise_mpdu_observations;
use recycle_fixture::exercise_rx_recycling;
use setup::{
    awake, awake_profile, ax210_profile, ax210_state, catalog_for, catalog_for_target,
    catalog_with_pnvm, phase_catalog, profile, start, start_ax210, step_fixture,
};
use std::sync::Mutex;
use transport::{
    complete, complete_from_free_slot, device_read, device_write, event, id, rx_packet,
};
use unified_fixture::exercise_unified_nvm;

#[derive(Clone)]
struct RadioBios {
    drops: Arc<AtomicUsize>,
    unavailable: bool,
    absent: bool,
}
impl Drop for RadioBios {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: this peripheral model executes exact namespace reads for the
// same modeled function; production service attachment remains external.
unsafe impl super::super::radio::bios::service::BiosIo for RadioBios {
    fn evaluate(
        &mut self,
        request: super::super::radio::bios::service::Request,
    ) -> Result<
        super::super::radio::bios::service::Object,
        super::super::radio::bios::service::IoError,
    > {
        use super::super::radio::bios::service::{IoError, Object, Request};
        if self.unavailable {
            return Err(IoError::Unavailable);
        }
        if self.absent {
            return Err(IoError::NotFound);
        }
        assert_eq!(request, Request::Glai);
        Ok(Object::Package(vec![
            Object::Integer(0),
            Object::Package(vec![Object::Integer(7), Object::Integer(1)]),
        ]))
    }
    fn variable(
        &mut self,
        variable: super::super::platform::Variable,
    ) -> Result<Vec<u8>, super::super::radio::bios::service::IoError> {
        use super::super::platform::Variable;
        if self.absent {
            return Err(super::super::radio::bios::service::IoError::NotFound);
        }
        Ok(match variable {
            Variable::GeneralConfiguration => {
                let mut raw = vec![4];
                for i in 0..32u32 {
                    raw.extend(if i == 0 { u32::MAX } else { i }.to_le_bytes());
                }
                raw
            }
            Variable::Wbem => vec![0, 3, 0, 0, 0],
            Variable::Uats | Variable::Uneb => {
                return Err(super::super::radio::bios::service::IoError::NotFound);
            }
            _ => panic!("unrequested source"),
        })
    }
}
// Kept with the original boot peripheral model: these cases exercise the
// same physical-owner/DMA epoch through post-LARI command retirement.
mod ax200_board_tests;
mod ax200_country_tests;
mod ax200_mac_tests;
mod ax200_native_scan_tests;
mod ax200_scan_tests;
mod ax200_tests;

mod cold_fixture;
mod cold_radio;
mod command_completion;
mod command_publication;
mod firmware_inputs;
mod initialization;
mod inputs;
mod lari_fixture;
mod lari_policy;
mod model;
mod mpdu_fixture;
mod nvm_admission;
mod nvm_completion;
mod pnvm_lifetimes;
mod pnvm_selection;
mod product_reset;
mod receive_recycling;
mod recycle_fixture;
mod rom_admission;
mod rom_context;
mod rom_fault_cleanup;
mod rom_publication_faults;
mod rom_retirement;
mod setup;
mod transport;
mod unified_fixture;
