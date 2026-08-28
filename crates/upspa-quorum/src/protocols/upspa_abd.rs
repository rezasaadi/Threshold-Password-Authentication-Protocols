//! Backwards-compatible module path for the former `upspa_abd` name.
//!
//! The implementation is RoUpSPA; this module contains no alternate storage
//! protocol or duplicate state machine.

pub use super::login_server::{LoginServer, LoginServerError, PendingLsOperation, VInfo};
pub use super::messages::*;
pub use super::provider::*;
pub use super::roupspa::*;
pub use super::synchronization::SynchronizationOutcome;

pub const CIPHERID_PT_LEN: usize = IDENTIFICATION_PLAINTEXT_LEN;
pub const CIPHERSP_PT_LEN: usize = ACCOUNT_PLAINTEXT_LEN;
pub const CIPHERID_BLOB_BYTES: usize = IDENTIFICATION_BLOB_BYTES;
pub const CIPHERSP_BLOB_BYTES: usize = ACCOUNT_BLOB_BYTES;
pub const MSG_STATUS_BYTES: usize = STATUS_BYTES;
pub const MSG_TOPRF_REQ_BYTES: usize = RISTRETTO_MESSAGE_BYTES;
pub const MSG_TOPRF_RESP_BYTES: usize = RISTRETTO_MESSAGE_BYTES;
pub const MSG_CIPHERSP_RESP_BYTES: usize = STATUS_BYTES + ACCOUNT_BLOB_BYTES + 8 + SIGNATURE_BYTES;

pub fn validate_threshold(nsp: usize, tsp: usize) {
    let qsp = quorum_size(nsp, tsp);
    validate_thresholds(nsp, tsp, qsp).expect("valid RoUpSPA threshold tuple");
}

pub fn max_executable_unavailable(nsp: usize, tsp: usize) -> usize {
    max_quorum_unavailable(nsp, tsp)
}

pub fn hash_suid_shared(rsp: &[u8; 32], lsj: &[u8]) -> [u8; 32] {
    crate::crypto::hash_roupspa_suid(rsp, lsj)
}
