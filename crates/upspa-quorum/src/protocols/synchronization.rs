use crate::protocols::messages::{
    account_read_request_bytes, account_read_response_bytes, encode_roupspa_account_record,
    identification_request_bytes, identification_response_bytes, MessageEvent, ProtocolStage, ProtocolTrace,
    ReceiverRole, SenderRole, WaitPolicy,
};
use crate::protocols::provider::{
    AccountFamilyKey, AccountReplica, IdentificationReplica, ReplicaStatus, SignedAccountRecord,
    SignedIdentificationRecord,
};
use crate::protocols::roupspa::{InFlightOperation, PhaseError, RoUpSpaSystem};
use ed25519_dalek::{Verifier, VerifyingKey};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynchronizationOutcome {
    pub valid_responses: usize,
    pub installed_counter: u64,
    pub trace: ProtocolTrace,
}

fn root_record_is_valid(uid: &[u8], svk: &VerifyingKey, record: &SignedIdentificationRecord) -> bool {
    match (record.ctrid, record.signature.as_ref()) {
        (0, None) => true,
        (0, Some(_)) | (_, None) => false,
        (_, Some(signature)) => svk.verify(&record.signed_bytes(uid), signature).is_ok(),
    }
}

fn elapsed_ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

impl RoUpSpaSystem {
    pub fn synchronize_identification(
        &mut self,
        recovering_index: usize,
    ) -> Result<SynchronizationOutcome, PhaseError> {
        if !matches!(self.identification_operation_state(), InFlightOperation::Idle) {
            return Err(PhaseError::OperationInFlight);
        }
        let recovering_provider = self
            .providers
            .get(recovering_index)
            .ok_or(PhaseError::InvalidProviderIndex(recovering_index))?;
        if !recovering_provider.reachable {
            return Err(PhaseError::ProviderRejected(
                crate::protocols::provider::ProviderError::Unreachable,
            ));
        }
        let recovering_has_share = recovering_provider.share(&self.uid).is_some();
        if !recovering_has_share {
            if let Some(replica) = self.providers[recovering_index]
                .identifications
                .get_mut(&self.uid)
            {
                replica.status = ReplicaStatus::Stale;
            }
            return Err(PhaseError::MissingProviderShare);
        }

        let mut trace = ProtocolTrace::default();
        let mut contacted = 0_usize;
        let mut grouped: HashMap<[u8; 32], Vec<(VerifyingKey, SignedIdentificationRecord)>> = HashMap::new();
        for (index, provider) in self.providers.iter().enumerate() {
            if index == recovering_index || !provider.reachable {
                continue;
            }
            contacted += 1;
            let started = Instant::now();
            let response = provider.identification_response(&self.uid, None);
            trace.record_provider_processing(elapsed_ns(started));
            let Ok(response) = response else {
                continue;
            };
            if !root_record_is_valid(&self.uid, &response.svk, &response.current) {
                continue;
            }
            grouped
                .entry(response.svk.to_bytes())
                .or_default()
                .push((response.svk, response.current));
        }
        let mut groups: Vec<_> = grouped.into_values().collect();
        groups.sort_by_key(|group| std::cmp::Reverse(group.len()));
        let Some(candidates) = groups.first() else {
            if let Some(replica) = self.providers[recovering_index]
                .identifications
                .get_mut(&self.uid)
            {
                replica.status = ReplicaStatus::Stale;
            }
            return Err(PhaseError::NotEnoughValidResponses {
                valid: 0,
                required: self.qsp,
            });
        };
        if candidates.len() < self.qsp {
            if let Some(replica) = self.providers[recovering_index]
                .identifications
                .get_mut(&self.uid)
            {
                replica.status = ReplicaStatus::Stale;
            }
            return Err(PhaseError::NotEnoughValidResponses {
                valid: candidates.len(),
                required: self.qsp,
            });
        }
        if groups.get(1).is_some_and(|group| group.len() == candidates.len()) {
            if let Some(replica) = self.providers[recovering_index]
                .identifications
                .get_mut(&self.uid)
            {
                replica.status = ReplicaStatus::Stale;
            }
            return Err(PhaseError::InconsistentVerifyingKeys);
        }
        let max_ctrid = candidates
            .iter()
            .map(|(_, record)| record.ctrid)
            .max()
            .expect("qsp candidates are non-empty");
        let mut maxima = Vec::new();
        for (_, record) in candidates.iter().filter(|(_, record)| record.ctrid == max_ctrid) {
            if !maxima
                .iter()
                .any(|known: &SignedIdentificationRecord| known == record)
            {
                maxima.push(record.clone());
            }
        }
        if maxima.len() != 1 {
            if let Some(replica) = self.providers[recovering_index]
                .identifications
                .get_mut(&self.uid)
            {
                replica.status = ReplicaStatus::Stale;
            }
            return Err(PhaseError::ConflictingMaximum {
                family: "identification",
                counter: max_ctrid,
            });
        }
        let record = maxima.pop().expect("one identification maximum");
        let svk = candidates[0].0;
        let started = Instant::now();
        self.providers[recovering_index].identifications.insert(
            self.uid.clone(),
            IdentificationReplica {
                svk,
                current: record,
                status: ReplicaStatus::Active,
                tentative_identification: None,
            },
        );
        trace.record_provider_processing(elapsed_ns(started));

        trace.push(MessageEvent {
            stage_id: 1,
            stage: ProtocolStage::SynchronizationRead,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::Provider,
            recipient_count: contacted,
            request_bytes: identification_request_bytes(&self.uid),
            response_bytes: identification_response_bytes(max_ctrid > 0, false),
            wait_policy: WaitPolicy::Quorum(self.qsp),
            acknowledgements: self.qsp,
        });
        self.last_trace = trace.clone();
        Ok(SynchronizationOutcome {
            valid_responses: candidates.len(),
            installed_counter: max_ctrid,
            trace,
        })
    }

    pub fn synchronize_account(
        &mut self,
        uid: &[u8],
        suid: [u8; 32],
        recovering_index: usize,
    ) -> Result<SynchronizationOutcome, PhaseError> {
        let key = AccountFamilyKey::new(uid, suid);
        if !matches!(self.account_operation_state(&key), InFlightOperation::Idle) {
            return Err(PhaseError::OperationInFlight);
        }
        if recovering_index >= self.providers.len() {
            return Err(PhaseError::InvalidProviderIndex(recovering_index));
        }
        if !self.providers[recovering_index].reachable {
            return Err(PhaseError::ProviderRejected(
                crate::protocols::provider::ProviderError::Unreachable,
            ));
        }
        let expected_svk = self.providers[recovering_index]
            .identifications
            .get(uid)
            .map(|replica| replica.svk)
            .or_else(|| {
                self.providers.iter().find_map(|provider| {
                    provider
                        .identifications
                        .get(uid)
                        .filter(|replica| replica.status == ReplicaStatus::Active)
                        .map(|replica| replica.svk)
                })
            });
        let Some(expected_svk) = expected_svk else {
            self.providers[recovering_index].mark_account_status(&key, ReplicaStatus::Stale);
            return Err(PhaseError::InconsistentVerifyingKeys);
        };

        let mut trace = ProtocolTrace::default();
        let mut contacted = 0_usize;
        let mut candidates = Vec::<SignedAccountRecord>::new();
        for (index, provider) in self.providers.iter().enumerate() {
            if index == recovering_index || !provider.reachable {
                continue;
            }
            contacted += 1;
            let started = Instant::now();
            let record = provider.account_response(&key);
            trace.record_provider_processing(elapsed_ns(started));
            let Ok(record) = record else {
                continue;
            };
            if record.uid != uid || record.suid != suid {
                continue;
            }
            if expected_svk
                .verify(
                    &encode_roupspa_account_record(uid, &suid, &record.cj, record.ctr),
                    &record.signature,
                )
                .is_err()
            {
                continue;
            }
            candidates.push(record);
        }
        if candidates.len() < self.qsp {
            self.providers[recovering_index].mark_account_status(&key, ReplicaStatus::Stale);
            return Err(PhaseError::NotEnoughValidResponses {
                valid: candidates.len(),
                required: self.qsp,
            });
        }
        let max_ctr = candidates
            .iter()
            .map(|record| record.ctr)
            .max()
            .expect("qsp account candidates are non-empty");
        let mut maxima = Vec::<SignedAccountRecord>::new();
        for record in candidates.iter().filter(|record| record.ctr == max_ctr) {
            if !maxima.iter().any(|known| known == record) {
                maxima.push(record.clone());
            }
        }
        if maxima.len() != 1 {
            self.providers[recovering_index].mark_account_status(&key, ReplicaStatus::Stale);
            return Err(PhaseError::ConflictingMaximum {
                family: "account",
                counter: max_ctr,
            });
        }
        let started = Instant::now();
        self.providers[recovering_index].accounts.insert(
            key,
            AccountReplica {
                current: maxima.pop(),
                status: ReplicaStatus::Active,
            },
        );
        trace.record_provider_processing(elapsed_ns(started));
        trace.push(MessageEvent {
            stage_id: 1,
            stage: ProtocolStage::SynchronizationRead,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::Provider,
            recipient_count: contacted,
            request_bytes: account_read_request_bytes(uid),
            response_bytes: account_read_response_bytes(),
            wait_policy: WaitPolicy::Quorum(self.qsp),
            acknowledgements: self.qsp,
        });
        self.last_trace = trace.clone();
        Ok(SynchronizationOutcome {
            valid_responses: candidates.len(),
            installed_counter: max_ctr,
            trace,
        })
    }
}
