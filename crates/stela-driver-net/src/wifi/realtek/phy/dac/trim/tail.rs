// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Initial source thermal tracking reset and beamforming register defaults.
use super::{Attempt, Error, FactoryInitialized, Io, Report};
/// Initial software tracking reset, not observed temperature or a running
/// tracking/calibration worker. Raw factory reference is not regulatory power.
#[derive(Debug)]
pub struct ThermalTracking {
    pub delta_power_index: [i8; 4],
    pub averages: [Option<u8>; 4],
    /// Empty native fixed-point filter state; no thermal sample has arrived.
    pub filter_state: [u64; 4],
    pub triggered: bool,
    pub thermal_reference: u8,
    pub lck_reference: u8,
}
/// Bounded initial source PHY sequence finished under its prior-phase
/// prerequisites. No operational radio, TX policy, sounding, IQK/DPK, runtime
/// tracking, cached recovery or independent stop/drain permission is implied.
#[derive(Debug)]
pub struct PhyInitialized {
    factory: FactoryInitialized,
    tracking: ThermalTracking,
}
impl PhyInitialized {
    pub fn factory_power(&self) -> &super::super::super::board_power::FactoryPower {
        self.factory.calibration.initial.factory_power()
    }
    pub fn factory(&self) -> &FactoryInitialized {
        &self.factory
    }
    pub fn tracking(&self) -> &ThermalTracking {
        &self.tracking
    }
}
impl FactoryInitialized {
    /// Reset initial thermal tracking and apply source initial MU/NDPA/CSI
    /// defaults. MU transmission/table validity remain disabled as source
    /// requires until sounding; no operational sounding is started.
    ///
    /// # Safety
    /// Same kept native requester, Io and Report and uninterrupted
    /// boot/reset/firmware epoch as every consumed prior phase. Initial source
    /// table/TRX/dynamic/DAC/factory and prior MAC/HCI/board/power prerequisites
    /// remain valid. Native BAR, claims, queues and pins kept, operational
    /// TX and competing reset/IRQ/PHY/RF/OTP workers quiesced. Run once in
    /// exclusive initial process/deferred context. Initial hardware rate/retry
    /// defaults confer no shared OS/regulatory TX permission. This is not
    /// DMA-stop proof, operational calibration or a working Wi-Fi interface.
    pub unsafe fn finish_initial_phy<I: Io>(
        self,
        io: &mut I,
        report: &Report,
    ) -> Result<PhyInitialized, Error> {
        let profile = self.calibration.initial.profile;
        if io.profile() != profile || report.profile() != profile {
            return Err(Error::WrongProfile);
        }
        let cap = report.capabilities();
        if cap.rf_phys != 2 || cap.rf_paths != 2 || cap.antenna_tx != 3 || cap.antenna_rx != 3 {
            return Err(Error::UnsupportedRfLayout);
        }
        let mut a = Attempt {
            io,
            profile,
            done: false,
        };
        a.domain()?;
        a.beamforming_init()?;
        a.domain()?;
        a.done = true;
        let reference = self.thermal_reference;
        Ok(PhyInitialized {
            factory: self,
            tracking: ThermalTracking {
                delta_power_index: [0; 4],
                averages: [None; 4],
                filter_state: [0; 4],
                triggered: false,
                thermal_reference: reference,
                lck_reference: reference,
            },
        })
    }
}
