use crate::crypto;
use crate::protocols::upspa as upspa_proto;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;

pub const RISTRETTO_BYTES: usize = 32;

pub const NET_UPSPA_SETUP_REQ_BYTES: usize = 32 + 32 + 136 + 32 + 4;

pub const NET_UPSPA_SETUP_RESP_BYTES: usize = 1;

pub const NET_UPSPA_TOPRF_REQ_BYTES: usize = 32 + RISTRETTO_BYTES;

pub const NET_UPSPA_TOPRF_RESP_BYTES: usize = RISTRETTO_BYTES;

pub const NET_UPSPA_GET_CSP_REQ_BYTES: usize = 32;

pub const NET_UPSPA_GET_CSP_RESP_BYTES: usize =
    crypto::NONCE_LEN + upspa_proto::CIPHERSP_PT_LEN + crypto::TAG_LEN;

pub const NET_UPSPA_PUT_CSP_REQ_BYTES: usize = 32 + NET_UPSPA_GET_CSP_RESP_BYTES;

pub const NET_UPSPA_PUT_CSP_RESP_BYTES: usize = 1;

pub const NET_UPSPA_PWDUPD_REQ_BYTES: usize =
    32 + (crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN + crypto::TAG_LEN + 32 + 8 + 4) + 64;

pub const NET_UPSPA_PWDUPD_RESP_BYTES: usize = 1;

#[derive(Clone)]
pub struct UpSpaProvider {
    pub sp_id: u32,

    pub share: Scalar,

    pub sig_pk: VerifyingKey,

    pub ciphersp_db: HashMap<[u8; 32], crypto::CtBlob<{ upspa_proto::CIPHERSP_PT_LEN }>>,

    pub last_cipherid: crypto::CtBlob<{ upspa_proto::CIPHERID_PT_LEN }>,

    pub last_pwdupd_ts: u64,
}

impl UpSpaProvider {
    pub fn new(
        sp_id: u32,
        share: Scalar,
        sig_pk_bytes: [u8; 32],
        initial_cipherid: crypto::CtBlob<{ upspa_proto::CIPHERID_PT_LEN }>,
    ) -> Self {
        let sig_pk = VerifyingKey::from_bytes(&sig_pk_bytes).expect("valid verifying key bytes");
        Self {
            sp_id,
            share,
            sig_pk,
            ciphersp_db: HashMap::new(),
            last_cipherid: initial_cipherid,
            last_pwdupd_ts: 0,
        }
    }

    #[inline]
    pub fn toprf_send_eval(&self, blinded_bytes: &[u8; 32]) -> [u8; 32] {
        let blinded = CompressedRistretto(*blinded_bytes)
            .decompress()
            .expect("valid compressed Ristretto");
        let y = blinded * self.share;
        y.compress().to_bytes()
    }

    #[inline]
    pub fn get_ciphersp(&self, suid: &[u8; 32]) -> Option<crypto::CtBlob<{ upspa_proto::CIPHERSP_PT_LEN }>> {
        self.ciphersp_db.get(suid).cloned()
    }

    #[inline]
    pub fn put_ciphersp(&mut self, suid: [u8; 32], blob: crypto::CtBlob<{ upspa_proto::CIPHERSP_PT_LEN }>) {
        self.ciphersp_db.insert(suid, blob);
    }

    #[inline]
    pub fn apply_password_update(&mut self, msg: &[u8], sig: &Signature) -> bool {
        const MIN_MSG: usize =
            crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN + crypto::TAG_LEN + 32 + 8 + 4;
        if msg.len() < MIN_MSG {
            return false;
        }
        let ts_off = crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN + crypto::TAG_LEN + 32;
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&msg[ts_off..ts_off + 8]);
        let ts = u64::from_le_bytes(ts_bytes);
        if ts < self.last_pwdupd_ts {
            return false;
        }

        if self.sig_pk.verify(msg, sig).is_err() {
            return false;
        }

        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce.copy_from_slice(&msg[0..crypto::NONCE_LEN]);
        let mut ct = [0u8; upspa_proto::CIPHERID_PT_LEN];
        ct.copy_from_slice(&msg[crypto::NONCE_LEN..crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN]);
        let mut tag = [0u8; crypto::TAG_LEN];
        tag.copy_from_slice(
            &msg[crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN
                ..crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN + crypto::TAG_LEN],
        );
        self.last_cipherid = crypto::CtBlob { nonce, ct, tag };

        let share_off = crypto::NONCE_LEN + upspa_proto::CIPHERID_PT_LEN + crypto::TAG_LEN;
        let mut share_bytes = [0u8; 32];
        share_bytes.copy_from_slice(&msg[share_off..share_off + 32]);
        self.share = Scalar::from_bytes_mod_order(share_bytes);

        self.last_pwdupd_ts = ts;
        true
    }
}

#[inline]
pub fn compress_point(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

#[inline]
pub fn uid_hash(uid: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"uptspa/uid_hash/v1");
    h.update(uid);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}
