//! Backwards-compatible provider module name.

pub use super::provider::*;

pub const RISTRETTO_BYTES: usize = super::messages::RISTRETTO_BYTES;
pub const NET_UPSPA_SETUP_RESP_BYTES: usize = super::messages::STATUS_BYTES;
pub const NET_UPSPA_TOPRF_RESP_BYTES: usize = super::messages::RISTRETTO_BYTES;
pub const NET_UPSPA_GET_CSP_REQ_BYTES: usize = 32;
pub const NET_UPSPA_GET_CSP_RESP_BYTES: usize =
    super::messages::STATUS_BYTES + super::messages::account_blob_bytes();
pub const NET_UPSPA_PUT_CSP_REQ_BYTES: usize = 32 + super::messages::account_blob_bytes();
pub const NET_UPSPA_PUT_CSP_RESP_BYTES: usize = super::messages::STATUS_BYTES;

#[inline]
pub fn uid_hash(uid: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"upspa/legacy-uid-hash/v1");
    h.update(uid);
    *h.finalize().as_bytes()
}
