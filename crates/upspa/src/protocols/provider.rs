use std::collections::{HashMap, HashSet};
use std::fmt;

#[cfg(test)]
use std::cell::Cell;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::crypto::CtBlob;

use super::messages::{UpSpaPasswordUpdateRequest, CIPHERID_PT_LEN, CIPHERSP_PT_LEN};

pub type Uid = Vec<u8>;
pub type Suid = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpSpaIdentificationRecord {
    pub uid: Uid,
    pub svk: VerifyingKey,
    pub cid: CtBlob<CIPHERID_PT_LEN>,
    pub share: Scalar,
    pub last_password_update_time: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingUpSpaIdentification {
    pub cidnew: CtBlob<CIPHERID_PT_LEN>,
    pub share_new: Scalar,
    pub time: u64,
    pub provider_index: u32,
    pub signature: Signature,
}

impl PendingUpSpaIdentification {
    fn matches(&self, request: &UpSpaPasswordUpdateRequest) -> bool {
        self.cidnew == request.cidnew
            && self.share_new == request.share_new
            && self.time == request.time
            && self.provider_index == request.provider_index
            && self.signature.to_bytes() == request.signature.to_bytes()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpSpaAccountSlot {
    pub committed: Option<CtBlob<CIPHERSP_PT_LEN>>,
    pub pending: Option<CtBlob<CIPHERSP_PT_LEN>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpSpaIdentificationResponse {
    pub provider_index: u32,
    pub svk: VerifyingKey,
    pub cid: CtBlob<CIPHERID_PT_LEN>,
    pub toprf_contribution: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteDisposition {
    Accepted,
    Idempotent,
}

/// One-shot terminal-handler faults used to exercise coordinated recovery.
///
/// These are transport/handler failures, not protocol state.  A fault is
/// consumed before the matching terminal operation mutates provider state, so
/// retrying the exact Store or Discard is safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProviderFinalizationAction {
    StoreAccount,
    DiscardAccount,
    StorePasswordUpdate,
    DiscardPasswordUpdate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderError {
    Unreachable,
    DuplicateSetup,
    UnknownUser,
    InvalidPoint,
    AccountAlreadyExists,
    AccountDoesNotExist,
    PendingConflict,
    NoMatchingPending,
    WrongProviderIndex { expected: u32, actual: u32 },
    InvalidSignature,
    StaleTimestamp { committed: u64, proposed: u64 },
    InjectedFinalizationFailure(ProviderFinalizationAction),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable => write!(f, "provider is unreachable"),
            Self::DuplicateSetup => write!(f, "identification record already exists"),
            Self::UnknownUser => write!(f, "unknown user"),
            Self::InvalidPoint => write!(f, "invalid Ristretto request"),
            Self::AccountAlreadyExists => write!(f, "account already exists"),
            Self::AccountDoesNotExist => write!(f, "account does not exist"),
            Self::PendingConflict => write!(f, "a different tuple is already pending"),
            Self::NoMatchingPending => write!(f, "no matching pending tuple"),
            Self::WrongProviderIndex { expected, actual } => {
                write!(f, "wrong provider index: expected {expected}, got {actual}")
            }
            Self::InvalidSignature => write!(f, "invalid password-update signature"),
            Self::StaleTimestamp { committed, proposed } => write!(
                f,
                "password-update timestamp {proposed} is not newer than {committed}"
            ),
            Self::InjectedFinalizationFailure(action) => {
                write!(f, "injected failure before {action:?}")
            }
        }
    }
}

impl std::error::Error for ProviderError {}

#[derive(Clone, Debug)]
pub struct UpSpaProvider {
    provider_index: u32,
    reachable: bool,
    identifications: HashMap<Uid, UpSpaIdentificationRecord>,
    pending_identifications: HashMap<Uid, PendingUpSpaIdentification>,
    accounts: HashMap<Suid, UpSpaAccountSlot>,
    account_responses_enabled: bool,
    finalization_faults: HashSet<ProviderFinalizationAction>,
    #[cfg(test)]
    identification_request_count: Cell<usize>,
}

impl UpSpaProvider {
    pub fn new(provider_index: u32) -> Self {
        assert!(provider_index != 0, "provider indices are one-based");
        Self {
            provider_index,
            reachable: true,
            identifications: HashMap::new(),
            pending_identifications: HashMap::new(),
            accounts: HashMap::new(),
            account_responses_enabled: true,
            finalization_faults: HashSet::new(),
            #[cfg(test)]
            identification_request_count: Cell::new(0),
        }
    }

    pub fn provider_index(&self) -> u32 {
        self.provider_index
    }

    pub fn is_reachable(&self) -> bool {
        self.reachable
    }

    pub fn set_reachable(&mut self, reachable: bool) {
        self.reachable = reachable;
    }

    /// Enables or suppresses account-read responses without affecting the
    /// identification exchange.  This models a coordinated account-service
    /// failure independently from provider reachability.
    pub fn set_account_responses_enabled(&mut self, enabled: bool) {
        self.account_responses_enabled = enabled;
    }

    #[cfg(test)]
    pub fn identification_request_count(&self) -> usize {
        self.identification_request_count.get()
    }

    /// Fails the next matching terminal handler before it changes state.
    pub fn inject_finalization_failure(&mut self, action: ProviderFinalizationAction) {
        self.finalization_faults.insert(action);
    }

    fn consume_finalization_fault(
        &mut self,
        action: ProviderFinalizationAction,
    ) -> Result<(), ProviderError> {
        if self.finalization_faults.remove(&action) {
            Err(ProviderError::InjectedFinalizationFailure(action))
        } else {
            Ok(())
        }
    }

    fn require_reachable(&self) -> Result<(), ProviderError> {
        if self.reachable {
            Ok(())
        } else {
            Err(ProviderError::Unreachable)
        }
    }

    pub fn can_setup(&self, uid: &[u8]) -> Result<(), ProviderError> {
        self.require_reachable()?;
        if self.identifications.contains_key(uid) {
            Err(ProviderError::DuplicateSetup)
        } else {
            Ok(())
        }
    }

    pub fn setup(
        &mut self,
        uid: Uid,
        svk: VerifyingKey,
        cid: CtBlob<CIPHERID_PT_LEN>,
        share: Scalar,
    ) -> Result<(), ProviderError> {
        self.can_setup(&uid)?;
        self.identifications.insert(
            uid.clone(),
            UpSpaIdentificationRecord {
                uid,
                svk,
                cid,
                share,
                last_password_update_time: 0,
            },
        );
        Ok(())
    }

    pub fn identification_record(&self, uid: &[u8]) -> Option<&UpSpaIdentificationRecord> {
        self.identifications.get(uid)
    }

    pub fn pending_identification(&self, uid: &[u8]) -> Option<&PendingUpSpaIdentification> {
        self.pending_identifications.get(uid)
    }

    pub fn identification_response(
        &self,
        uid: &[u8],
        blinded_point: Option<&[u8; 32]>,
    ) -> Result<UpSpaIdentificationResponse, ProviderError> {
        #[cfg(test)]
        self.identification_request_count
            .set(self.identification_request_count.get().saturating_add(1));
        self.require_reachable()?;
        let record = self.identifications.get(uid).ok_or(ProviderError::UnknownUser)?;
        let contribution = if let Some(encoded) = blinded_point {
            let blinded = CompressedRistretto(*encoded)
                .decompress()
                .ok_or(ProviderError::InvalidPoint)?;
            Some((blinded * record.share).compress().to_bytes())
        } else {
            None
        };
        Ok(UpSpaIdentificationResponse {
            provider_index: self.provider_index,
            svk: record.svk,
            cid: record.cid.clone(),
            toprf_contribution: contribution,
        })
    }

    pub fn account_slot(&self, suid: &Suid) -> Option<&UpSpaAccountSlot> {
        self.accounts.get(suid)
    }

    /// Ordinary reads deliberately expose only the committed value.
    pub fn read_account(&self, suid: &Suid) -> Result<Option<CtBlob<CIPHERSP_PT_LEN>>, ProviderError> {
        self.require_reachable()?;
        if !self.account_responses_enabled {
            return Ok(None);
        }
        Ok(self.accounts.get(suid).and_then(|slot| slot.committed.clone()))
    }

    pub fn prepare_registration(
        &mut self,
        suid: Suid,
        candidate: CtBlob<CIPHERSP_PT_LEN>,
    ) -> Result<WriteDisposition, ProviderError> {
        self.require_reachable()?;
        let slot = self.accounts.entry(suid).or_default();
        if slot.committed.is_some() {
            return Err(ProviderError::AccountAlreadyExists);
        }
        match &slot.pending {
            Some(pending) if pending == &candidate => Ok(WriteDisposition::Idempotent),
            Some(_) => Err(ProviderError::PendingConflict),
            None => {
                slot.pending = Some(candidate);
                Ok(WriteDisposition::Accepted)
            }
        }
    }

    pub fn prepare_secret_update(
        &mut self,
        suid: Suid,
        candidate: CtBlob<CIPHERSP_PT_LEN>,
    ) -> Result<WriteDisposition, ProviderError> {
        self.require_reachable()?;
        let slot = self
            .accounts
            .get_mut(&suid)
            .ok_or(ProviderError::AccountDoesNotExist)?;
        if slot.committed.is_none() {
            return Err(ProviderError::AccountDoesNotExist);
        }
        match &slot.pending {
            Some(pending) if pending == &candidate => Ok(WriteDisposition::Idempotent),
            Some(_) => Err(ProviderError::PendingConflict),
            None => {
                slot.pending = Some(candidate);
                Ok(WriteDisposition::Accepted)
            }
        }
    }

    pub fn store_account(
        &mut self,
        suid: &Suid,
        expected: &CtBlob<CIPHERSP_PT_LEN>,
    ) -> Result<WriteDisposition, ProviderError> {
        self.require_reachable()?;
        self.consume_finalization_fault(ProviderFinalizationAction::StoreAccount)?;
        let slot = self
            .accounts
            .get_mut(suid)
            .ok_or(ProviderError::NoMatchingPending)?;
        match &slot.pending {
            Some(pending) if pending == expected => {
                slot.committed = slot.pending.take();
                Ok(WriteDisposition::Accepted)
            }
            _ if slot.pending.is_none() && slot.committed.as_ref() == Some(expected) => {
                Ok(WriteDisposition::Idempotent)
            }
            _ => Err(ProviderError::NoMatchingPending),
        }
    }

    pub fn discard_account(
        &mut self,
        suid: &Suid,
        expected: &CtBlob<CIPHERSP_PT_LEN>,
    ) -> Result<WriteDisposition, ProviderError> {
        self.require_reachable()?;
        self.consume_finalization_fault(ProviderFinalizationAction::DiscardAccount)?;
        let slot = self
            .accounts
            .get_mut(suid)
            .ok_or(ProviderError::NoMatchingPending)?;
        match &slot.pending {
            Some(pending) if pending == expected => {
                slot.pending = None;
                Ok(WriteDisposition::Accepted)
            }
            _ => Err(ProviderError::NoMatchingPending),
        }
    }

    pub fn prepare_password_update(
        &mut self,
        request: &UpSpaPasswordUpdateRequest,
    ) -> Result<WriteDisposition, ProviderError> {
        self.require_reachable()?;
        if request.provider_index != self.provider_index {
            return Err(ProviderError::WrongProviderIndex {
                expected: self.provider_index,
                actual: request.provider_index,
            });
        }
        let record = self
            .identifications
            .get(&request.uid)
            .ok_or(ProviderError::UnknownUser)?;

        if let Some(pending) = self.pending_identifications.get(&request.uid) {
            return if pending.matches(request) {
                Ok(WriteDisposition::Idempotent)
            } else {
                Err(ProviderError::PendingConflict)
            };
        }
        if request.time <= record.last_password_update_time {
            return Err(ProviderError::StaleTimestamp {
                committed: record.last_password_update_time,
                proposed: request.time,
            });
        }
        record
            .svk
            .verify(&request.signed_bytes(), &request.signature)
            .map_err(|_| ProviderError::InvalidSignature)?;
        self.pending_identifications.insert(
            request.uid.clone(),
            PendingUpSpaIdentification {
                cidnew: request.cidnew.clone(),
                share_new: request.share_new,
                time: request.time,
                provider_index: request.provider_index,
                signature: request.signature,
            },
        );
        Ok(WriteDisposition::Accepted)
    }

    pub fn store_password_update(
        &mut self,
        request: &UpSpaPasswordUpdateRequest,
    ) -> Result<WriteDisposition, ProviderError> {
        self.require_reachable()?;
        self.consume_finalization_fault(ProviderFinalizationAction::StorePasswordUpdate)?;
        let pending = self
            .pending_identifications
            .get(&request.uid)
            .ok_or(ProviderError::NoMatchingPending)?;
        if !pending.matches(request) {
            return Err(ProviderError::NoMatchingPending);
        }
        let record = self
            .identifications
            .get_mut(&request.uid)
            .ok_or(ProviderError::UnknownUser)?;
        record.cid = pending.cidnew.clone();
        record.share = pending.share_new;
        record.last_password_update_time = pending.time;
        self.pending_identifications.remove(&request.uid);
        Ok(WriteDisposition::Accepted)
    }

    pub fn discard_password_update(
        &mut self,
        request: &UpSpaPasswordUpdateRequest,
    ) -> Result<WriteDisposition, ProviderError> {
        self.require_reachable()?;
        self.consume_finalization_fault(ProviderFinalizationAction::DiscardPasswordUpdate)?;
        let pending = self
            .pending_identifications
            .get(&request.uid)
            .ok_or(ProviderError::NoMatchingPending)?;
        if !pending.matches(request) {
            return Err(ProviderError::NoMatchingPending);
        }
        self.pending_identifications.remove(&request.uid);
        Ok(WriteDisposition::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn root_blob(byte: u8) -> CtBlob<CIPHERID_PT_LEN> {
        CtBlob {
            nonce: [byte; 24],
            ct: [byte; CIPHERID_PT_LEN],
            tag: [byte; 16],
        }
    }

    fn account_blob(byte: u8) -> CtBlob<CIPHERSP_PT_LEN> {
        CtBlob {
            nonce: [byte; 24],
            ct: [byte; CIPHERSP_PT_LEN],
            tag: [byte; 16],
        }
    }

    fn setup_provider() -> (UpSpaProvider, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut provider = UpSpaProvider::new(1);
        provider
            .setup(
                b"alice".to_vec(),
                signing_key.verifying_key(),
                root_blob(1),
                Scalar::from(3u64),
            )
            .unwrap();
        (provider, signing_key)
    }

    fn password_request(
        signing_key: &SigningKey,
        uid: &[u8],
        cid: CtBlob<CIPHERID_PT_LEN>,
        share: Scalar,
        time: u64,
        provider_index: u32,
    ) -> UpSpaPasswordUpdateRequest {
        let bytes =
            super::super::messages::encode_upspa_password_update(uid, &cid, &share, time, provider_index);
        UpSpaPasswordUpdateRequest {
            uid: uid.to_vec(),
            cidnew: cid,
            share_new: share,
            time,
            provider_index,
            signature: signing_key.sign(&bytes),
        }
    }

    #[test]
    fn pending_accounts_are_invisible_and_discard_preserves_committed() {
        let (mut provider, _) = setup_provider();
        let suid = [4; 32];
        let old = account_blob(1);
        let new = account_blob(2);
        provider.prepare_registration(suid, old.clone()).unwrap();
        assert_eq!(provider.read_account(&suid).unwrap(), None);
        provider.store_account(&suid, &old).unwrap();
        provider.prepare_secret_update(suid, new.clone()).unwrap();
        assert_eq!(provider.read_account(&suid).unwrap(), Some(old.clone()));
        provider.discard_account(&suid, &new).unwrap();
        assert_eq!(provider.read_account(&suid).unwrap(), Some(old));
    }

    #[test]
    fn password_update_is_tentative_idempotent_and_atomic_on_store() {
        let (mut provider, signing_key) = setup_provider();
        let old = provider.identification_record(b"alice").unwrap().clone();
        let request = password_request(&signing_key, b"alice", root_blob(2), Scalar::from(11u64), 5, 1);
        assert_eq!(
            provider.prepare_password_update(&request).unwrap(),
            WriteDisposition::Accepted
        );
        assert_eq!(
            provider.prepare_password_update(&request).unwrap(),
            WriteDisposition::Idempotent
        );
        let still_old = provider.identification_record(b"alice").unwrap();
        assert_eq!(still_old.cid, old.cid);
        assert_eq!(still_old.share, old.share);
        provider.store_password_update(&request).unwrap();
        let committed = provider.identification_record(b"alice").unwrap();
        assert_eq!(committed.cid, request.cidnew);
        assert_eq!(committed.share, request.share_new);
        assert_eq!(committed.last_password_update_time, 5);
        assert!(matches!(
            provider.prepare_password_update(&request),
            Err(ProviderError::StaleTimestamp { .. })
        ));
    }

    #[test]
    fn password_update_discard_preserves_the_old_root_and_share() {
        let (mut provider, signing_key) = setup_provider();
        let old = provider.identification_record(b"alice").unwrap().clone();
        let request = password_request(&signing_key, b"alice", root_blob(2), Scalar::from(11u64), 5, 1);
        provider.prepare_password_update(&request).unwrap();
        provider.discard_password_update(&request).unwrap();
        let committed = provider.identification_record(b"alice").unwrap();
        assert_eq!(committed.cid, old.cid);
        assert_eq!(committed.share, old.share);
        assert_eq!(committed.last_password_update_time, 0);
        assert!(provider.pending_identification(b"alice").is_none());
    }

    #[test]
    fn password_signature_binds_every_field() {
        let (provider, signing_key) = setup_provider();
        let request = password_request(&signing_key, b"alice", root_blob(2), Scalar::from(11u64), 5, 1);

        let mut variants = Vec::new();
        let mut changed = request.clone();
        changed.uid = b"mallory".to_vec();
        variants.push(changed);
        let mut changed = request.clone();
        changed.cidnew.ct[0] ^= 1;
        variants.push(changed);
        let mut changed = request.clone();
        changed.share_new += Scalar::ONE;
        variants.push(changed);
        let mut changed = request.clone();
        changed.time += 1;
        variants.push(changed);
        let mut changed = request;
        changed.provider_index = 2;
        variants.push(changed);

        for variant in variants {
            let mut candidate = provider.clone();
            assert!(candidate.prepare_password_update(&variant).is_err());
        }
    }
}
