use crate::crypto::CtBlob;
use crate::protocols::messages::{
    encode_roupspa_account_record, encode_roupspa_identification_record, ACCOUNT_PLAINTEXT_LEN,
    IDENTIFICATION_PLAINTEXT_LEN,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicaStatus {
    Active,
    Stale,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedIdentificationRecord {
    pub cid: CtBlob<IDENTIFICATION_PLAINTEXT_LEN>,
    pub ctrid: u64,
    pub signature: Option<Signature>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAccountRecord {
    pub uid: Vec<u8>,
    pub suid: [u8; 32],
    pub cj: CtBlob<ACCOUNT_PLAINTEXT_LEN>,
    pub ctr: u64,
    pub signature: Signature,
}

impl SignedAccountRecord {
    pub fn signed_bytes(&self) -> Vec<u8> {
        encode_roupspa_account_record(&self.uid, &self.suid, &self.cj, self.ctr)
    }
}

impl SignedIdentificationRecord {
    pub fn signed_bytes(&self, uid: &[u8]) -> Vec<u8> {
        encode_roupspa_identification_record(uid, &self.cid, self.ctrid)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AccountFamilyKey {
    pub uid: Vec<u8>,
    pub suid: [u8; 32],
}

impl AccountFamilyKey {
    pub fn new(uid: &[u8], suid: [u8; 32]) -> Self {
        Self {
            uid: uid.to_vec(),
            suid,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentificationReplica {
    pub svk: VerifyingKey,
    pub current: SignedIdentificationRecord,
    pub status: ReplicaStatus,
    pub tentative_identification: Option<SignedIdentificationRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountReplica {
    pub current: Option<SignedAccountRecord>,
    pub status: ReplicaStatus,
}

#[derive(Clone, Debug)]
pub struct IdentificationResponse {
    pub provider_id: u32,
    pub svk: VerifyingKey,
    pub current: SignedIdentificationRecord,
    pub toprf_response: Option<RistrettoPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderError {
    Unreachable,
    DuplicateSetup,
    MissingIdentification,
    MissingShare,
    Stale,
    InvalidSetupRecord,
    InvalidSignature,
    WrongCounter { expected: u64, received: u64 },
    ConflictingRecord,
    MissingTentative,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoUpSpaProvider {
    pub id: u32,
    pub reachable: bool,
    pub shares: HashMap<Vec<u8>, Scalar>,
    pub identifications: HashMap<Vec<u8>, IdentificationReplica>,
    pub accounts: HashMap<AccountFamilyKey, AccountReplica>,
}

impl RoUpSpaProvider {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            reachable: true,
            shares: HashMap::new(),
            identifications: HashMap::new(),
            accounts: HashMap::new(),
        }
    }

    pub fn set_reachable(&mut self, reachable: bool) {
        self.reachable = reachable;
    }

    pub fn install_setup(
        &mut self,
        uid: &[u8],
        svk: VerifyingKey,
        record: SignedIdentificationRecord,
        share: Scalar,
    ) -> Result<(), ProviderError> {
        if !self.reachable {
            return Err(ProviderError::Unreachable);
        }
        if record.ctrid != 0 || record.signature.is_some() {
            return Err(ProviderError::InvalidSetupRecord);
        }
        if self.identifications.contains_key(uid) || self.shares.contains_key(uid) {
            return Err(ProviderError::DuplicateSetup);
        }
        self.shares.insert(uid.to_vec(), share);
        self.identifications.insert(
            uid.to_vec(),
            IdentificationReplica {
                svk,
                current: record,
                status: ReplicaStatus::Active,
                tentative_identification: None,
            },
        );
        Ok(())
    }

    pub fn identification_response(
        &self,
        uid: &[u8],
        blinded: Option<&RistrettoPoint>,
    ) -> Result<IdentificationResponse, ProviderError> {
        if !self.reachable {
            return Err(ProviderError::Unreachable);
        }
        let replica = self
            .identifications
            .get(uid)
            .ok_or(ProviderError::MissingIdentification)?;
        if replica.status != ReplicaStatus::Active {
            return Err(ProviderError::Stale);
        }
        let toprf_response = match blinded {
            Some(point) => {
                let share = self.shares.get(uid).ok_or(ProviderError::MissingShare)?;
                Some(point * share)
            }
            None => None,
        };
        Ok(IdentificationResponse {
            provider_id: self.id,
            svk: replica.svk,
            current: replica.current.clone(),
            toprf_response,
        })
    }

    pub fn account_response(&self, key: &AccountFamilyKey) -> Result<SignedAccountRecord, ProviderError> {
        if !self.reachable {
            return Err(ProviderError::Unreachable);
        }
        let replica = self.accounts.get(key).ok_or(ProviderError::Stale)?;
        if replica.status != ReplicaStatus::Active {
            return Err(ProviderError::Stale);
        }
        replica.current.clone().ok_or(ProviderError::Stale)
    }

    fn verifying_key(&self, uid: &[u8]) -> Result<VerifyingKey, ProviderError> {
        self.identifications
            .get(uid)
            .map(|replica| replica.svk)
            .ok_or(ProviderError::MissingIdentification)
    }

    pub fn accept_registration_account(&mut self, record: SignedAccountRecord) -> Result<(), ProviderError> {
        if !self.reachable {
            return Err(ProviderError::Unreachable);
        }
        if record.ctr != 0 {
            return Err(ProviderError::WrongCounter {
                expected: 0,
                received: record.ctr,
            });
        }
        let svk = self.verifying_key(&record.uid)?;
        svk.verify(&record.signed_bytes(), &record.signature)
            .map_err(|_| ProviderError::InvalidSignature)?;
        let key = AccountFamilyKey::new(&record.uid, record.suid);
        match self.accounts.get_mut(&key) {
            Some(replica) if replica.current.as_ref() == Some(&record) => {
                replica.status = ReplicaStatus::Active;
                Ok(())
            }
            Some(replica) if replica.current.is_some() => Err(ProviderError::ConflictingRecord),
            Some(replica) => {
                replica.current = Some(record);
                replica.status = ReplicaStatus::Active;
                Ok(())
            }
            None => {
                self.accounts.insert(
                    key,
                    AccountReplica {
                        current: Some(record),
                        status: ReplicaStatus::Active,
                    },
                );
                Ok(())
            }
        }
    }

    pub fn accept_secret_update_account(&mut self, record: SignedAccountRecord) -> Result<(), ProviderError> {
        if !self.reachable {
            return Err(ProviderError::Unreachable);
        }
        let svk = self.verifying_key(&record.uid)?;
        svk.verify(&record.signed_bytes(), &record.signature)
            .map_err(|_| ProviderError::InvalidSignature)?;
        let key = AccountFamilyKey::new(&record.uid, record.suid);
        let replica = self.accounts.get_mut(&key).ok_or(ProviderError::Stale)?;

        if replica.current.as_ref() == Some(&record) {
            replica.status = ReplicaStatus::Active;
            return Ok(());
        }
        if replica.status != ReplicaStatus::Active {
            return Err(ProviderError::Stale);
        }
        let current = replica.current.as_ref().ok_or(ProviderError::Stale)?;
        let expected = current.ctr.checked_add(1).ok_or(ProviderError::WrongCounter {
            expected: current.ctr,
            received: record.ctr,
        })?;
        if record.ctr != expected {
            return Err(ProviderError::WrongCounter {
                expected,
                received: record.ctr,
            });
        }
        replica.current = Some(record);
        replica.status = ReplicaStatus::Active;
        Ok(())
    }

    pub fn accept_tentative_identification(
        &mut self,
        uid: &[u8],
        record: SignedIdentificationRecord,
    ) -> Result<(), ProviderError> {
        if !self.reachable {
            return Err(ProviderError::Unreachable);
        }
        let replica = self
            .identifications
            .get_mut(uid)
            .ok_or(ProviderError::MissingIdentification)?;
        if replica.status != ReplicaStatus::Active {
            return Err(ProviderError::Stale);
        }
        let expected = replica
            .current
            .ctrid
            .checked_add(1)
            .ok_or(ProviderError::WrongCounter {
                expected: replica.current.ctrid,
                received: record.ctrid,
            })?;
        if record.ctrid != expected {
            return Err(ProviderError::WrongCounter {
                expected,
                received: record.ctrid,
            });
        }
        let signature = record.signature.as_ref().ok_or(ProviderError::InvalidSignature)?;
        replica
            .svk
            .verify(&record.signed_bytes(uid), signature)
            .map_err(|_| ProviderError::InvalidSignature)?;

        // Password-update retransmission is idempotent only while the exact
        // replacement is still tentative.  In particular, a replay of the
        // already committed root (including the unsigned ctrid=0 setup root)
        // is not a new current+1 write and must not be acknowledged.
        match &replica.tentative_identification {
            Some(existing) if existing == &record => Ok(()),
            Some(_) => Err(ProviderError::ConflictingRecord),
            None => {
                replica.tentative_identification = Some(record);
                Ok(())
            }
        }
    }

    pub fn store_tentative_identification(
        &mut self,
        uid: &[u8],
        expected: &SignedIdentificationRecord,
    ) -> Result<(), ProviderError> {
        let replica = self
            .identifications
            .get_mut(uid)
            .ok_or(ProviderError::MissingIdentification)?;
        if &replica.current == expected {
            replica.status = ReplicaStatus::Active;
            return Ok(());
        }
        match replica.tentative_identification.as_ref() {
            Some(record) if record == expected => {
                replica.current = record.clone();
                replica.tentative_identification = None;
                replica.status = ReplicaStatus::Active;
                Ok(())
            }
            Some(_) => Err(ProviderError::ConflictingRecord),
            None => Err(ProviderError::MissingTentative),
        }
    }

    pub fn discard_tentative_identification(
        &mut self,
        uid: &[u8],
        expected: &SignedIdentificationRecord,
    ) -> Result<(), ProviderError> {
        let replica = self
            .identifications
            .get_mut(uid)
            .ok_or(ProviderError::MissingIdentification)?;
        match replica.tentative_identification.as_ref() {
            Some(record) if record == expected => {
                replica.tentative_identification = None;
                Ok(())
            }
            Some(_) => Err(ProviderError::ConflictingRecord),
            None => Err(ProviderError::MissingTentative),
        }
    }

    pub fn mark_identification_status(
        &mut self,
        uid: &[u8],
        status: ReplicaStatus,
    ) -> Result<(), ProviderError> {
        let replica = self
            .identifications
            .get_mut(uid)
            .ok_or(ProviderError::MissingIdentification)?;
        replica.status = status;
        Ok(())
    }

    pub fn mark_account_status(&mut self, key: &AccountFamilyKey, status: ReplicaStatus) {
        self.accounts
            .entry(key.clone())
            .and_modify(|replica| replica.status = status)
            .or_insert(AccountReplica {
                current: None,
                status,
            });
    }

    pub fn identification_status(&self, uid: &[u8]) -> Option<ReplicaStatus> {
        self.identifications.get(uid).map(|replica| replica.status)
    }

    pub fn account_status(&self, key: &AccountFamilyKey) -> Option<ReplicaStatus> {
        self.accounts.get(key).map(|replica| replica.status)
    }

    pub fn share(&self, uid: &[u8]) -> Option<&Scalar> {
        self.shares.get(uid)
    }
}

/// Backwards-compatible short name retained for callers of the former crate.
pub type Provider = RoUpSpaProvider;
