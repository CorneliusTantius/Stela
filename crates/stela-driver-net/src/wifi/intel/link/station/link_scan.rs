// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2024-2026 Intel Corporation
//! `iwl_mld_int_mlo_scan`: a station listens on both links' channels when a
//! link goes quiet or EMLSR comes within reach, and `_iwl_mld_select_links`
//! then takes what is better. Firmware runs the scan
//! beside the association; frames keep flowing and the scan protocol's
//! [`Scanner`] keeps its one request.
use super::*;
use crate::wifi::scan::{Outcome, Retirement, Scanner, Ticket as ScanTicket};

/// `IWL_MLD_MLO_SCAN_BLOCKOUT_TIME`: a link just activated stays that long.
const BLOCKOUT_US: u64 = 5_000_000;
/// How long the first selection trusts what the join's scan heard:
/// `iwl_mld_set_link_sel_data` ignores the scan before last, and Linux runs
/// its scans 5 s apart.
const JOIN_SCAN_US: u64 = 5_000_000;
/// Two passive dwells and the service periods between them, many times over.
const BUDGET_US: u64 = 5_000_000;
/// `iwl_mld_scan_stop`'s wait for the firmware's word.
const ABORT_US: u64 = 1_000_000;
/// `IWL_SCAN_OFFLOAD_COMPLETED`.
const COMPLETED: u8 = 1;

/// The internal MLO scan of one association.
#[derive(Default)]
pub(super) struct LinkScan {
    running: Option<(Scanner, ScanTicket)>,
    /// When a scan asked for may start.
    due: Option<u64>,
    /// `last_mlo_scan_start_time`: what is older did not come from this scan.
    pub(super) started: Option<u64>,
    /// `last_link_activation_time`.
    pub(super) activated: u64,
    /// When firmware must have let go of a scan told to stop.
    abort: Option<Deadline>,
    /// A scan's EBS went wrong, `last_ebs_failed`.
    ebs_failed: bool,
}

impl Client {
    pub(super) fn link_scanning(&self) -> bool {
        self.link_scan.running.is_some()
    }

    /// The port opened on the active link: the join's scan chooses at first.
    pub(super) fn link_authorized(&mut self, now: u64) {
        self.reselect = true;
        if self.dormant.is_some() {
            self.watch_statistics();
        }
        self.link_scan.started = Some(now.saturating_sub(JOIN_SCAN_US));
        self.link_scan.activated = now;
        self.emlsr.block_for_throughput(now);
    }

    /// `iwl_mld_int_mlo_scan`.
    pub(super) fn ask_link_scan(&mut self, now: u64) {
        if self.dormant.is_none() || self.leaving || self.link_scanning() {
            return;
        }
        let earliest = self.link_scan.activated.saturating_add(BLOCKOUT_US);
        self.link_scan.due.get_or_insert(now.max(earliest));
    }

    /// `iwl_mld_handle_scan_start_notif`.
    pub(super) fn link_scan_started(&mut self, now: u64) {
        if self.link_scanning() {
            self.link_scan.started = Some(now);
        }
    }

    /// `iwl_mld_handle_scan_complete_notif`: only a whole scan of both
    /// channels chooses.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    pub(super) fn link_scan_finished(&mut self, status: u8, ebs_failed: bool) -> Result<(), Error> {
        let Some((mut scanner, ticket)) = self.link_scan.running.take() else {
            return Ok(());
        };
        self.link_scan.abort = None;
        self.link_scan.ebs_failed |= ebs_failed;
        let outcome = if status == COMPLETED {
            Outcome::Completed
        } else {
            Outcome::Aborted
        };
        scanner.completed(ticket, outcome).map_err(protocol)?;
        let retired = scanner
            .retire(ticket, Retirement::Confirmed)
            .map_err(protocol)?;
        self.reselect |= retired == Some(Outcome::Completed);
        Ok(())
    }
}

fn protocol(error: scan::Error) -> Error {
    Error::Scan(boot::Ax200ScanError::Protocol(error))
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// Start the scan that is due, and stop the one that may not go on.
    #[expect(
        clippy::result_large_err,
        reason = "preserve complete typed PCI and timing causes without allocating on recovery or refusal"
    )]
    pub(super) fn run_link_scan(&mut self, queue: &mut Queue<Q, B>, now: u64) -> Result<(), Error> {
        let client = &mut self.client;
        let leaving = client.leaving;
        if client
            .link_scan
            .abort
            .as_ref()
            .is_some_and(Deadline::passed)
        {
            // `iwl_mld_scan_stop`: a scan firmware did not let go of in time
            // is taken as stopped all the same, and its late word ignored.
            client.link_scan.abort = None;
            client.link_scan.running = None;
            return Ok(());
        }
        if let Some((scanner, ticket)) = &mut client.link_scan.running {
            let cancel = if leaving {
                scanner.cancel(*ticket).map_err(protocol)?
            } else {
                scanner.poll(*ticket, now).map_err(protocol)?
            };
            if cancel {
                client.link_scan.abort = Some(self.clock.deadline(ABORT_US));
                let (id, bytes) = Queue::<Q, B>::scan_abort();
                client.command(id, bytes);
            }
            return Ok(());
        }
        if !client.idle() || client.link_scan.due.is_none_or(|due| now < due) {
            return Ok(());
        }
        client.link_scan.due = None;
        let (Some(active), Some(dormant)) = (&client.context, &client.dormant) else {
            return Ok(());
        };
        let channels = vec![active.definition().control, dormant.definition().control];
        let mut policy = Admitted(&client.channels);
        let mut scanner = Scanner::new(self.address).map_err(protocol)?;
        let admitted = scan::Request::new(channels, Vec::new(), Vec::new()).and_then(|request| {
            let ticket = scanner.begin(request, now, BUDGET_US, &mut policy)?;
            scanner.validate_submission(ticket, now, &mut policy)?;
            Ok(ticket)
        });
        let Ok(ticket) = admitted else {
            client.unsupported("a scan of a channel the country no longer allows");
            return Ok(());
        };
        let request = scanner.request().ok_or(Error::Refused("scan"))?;
        let (id, bytes) = queue
            .internal_scan(
                request,
                self.address,
                client.seat,
                match client.statistics.traffic {
                    boot::Ax200ScanTraffic::High => boot::Ax200ScanTraffic::High,
                    _ if client.emlsr.active => boot::Ax200ScanTraffic::Balanced,
                    traffic => traffic,
                },
                client.link_scan.ebs_failed,
            )
            .map_err(Error::Scan)?;
        scanner.submitted(ticket).map_err(protocol)?;
        client.link_scan.started = None;
        client.link_scan.running = Some((scanner, ticket));
        client.command(id, bytes);
        Ok(())
    }

    /// Whether `frame` is what the scan listens for, a beacon or a probe
    /// response. The association itself uses neither.
    pub(super) fn hear_on_link_scan(&mut self, frame: &Mpdu) -> bool {
        let client = &self.client;
        let (Some((scanner, ticket)), true) = (
            &client.link_scan.running,
            matches!(frame.header().control & 0xfc, 0x50 | 0x80),
        ) else {
            return false;
        };
        let mut policy = Admitted(&client.channels);
        if let Ok(bss) = scanner.observe(*ticket, frame, &mut policy) {
            self.observe(&bss);
        }
        true
    }

    /// Let the scan that is due start: tests have no 5 s to wait.
    #[cfg(test)]
    pub(crate) fn end_link_blockout(&mut self) {
        self.client.link_scan.due = self.client.link_scan.due.map(|_| 0);
    }
}
