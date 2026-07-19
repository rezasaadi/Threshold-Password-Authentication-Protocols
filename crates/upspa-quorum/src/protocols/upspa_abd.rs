use crate::crypto;
use crate::crypto::CtBlob;

use blake3;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::collections::HashMap;
use std::fmt;
use std::hint::black_box;

pub const CIPHERID_PT_LEN: usize = 32 + 32 + 32 + 8;
pub const CIPHERSP_PT_LEN: usize = 32 + 8;

pub const CIPHERID_BLOB_BYTES: usize = crypto::NONCE_LEN + CIPHERID_PT_LEN + crypto::TAG_LEN;
pub const CIPHERSP_BLOB_BYTES: usize = crypto::NONCE_LEN + CIPHERSP_PT_LEN + crypto::TAG_LEN;

pub const MSG_UID_BYTES: usize = 32;
pub const MSG_STATUS_BYTES: usize = 1;
pub const MSG_TOPRF_REQ_BYTES: usize = 32 + 32;
pub const MSG_TOPRF_RESP_BYTES: usize = 32;
pub const MSG_CIPHERID_REQ_BYTES: usize = 32;
pub const MSG_CIPHERID_RESP_BYTES: usize = CIPHERID_BLOB_BYTES;
pub const MSG_CIPHERSP_REQ_BYTES: usize = 32;
pub const MSG_CIPHERSP_RESP_BYTES: usize = CIPHERSP_BLOB_BYTES;
pub const MSG_CIPHERSP_WRITE_REQ_BYTES: usize = 32 + 64 + CIPHERSP_BLOB_BYTES + 8;
pub const MSG_MASTER_WRITE_REQ_BYTES: usize = 32 + 64 + CIPHERID_BLOB_BYTES + 8;
pub const MSG_LS_REGISTER_REQ_BYTES: usize = 32 + 32;
pub const MSG_LS_UPDATE_REQ_BYTES: usize = 32 + 32 + 32;

#[derive(Clone)]
pub struct MasterRecord {
    pub cipherid: CtBlob<CIPHERID_PT_LEN>,
    pub ctrid: u64,
}

#[derive(Clone)]
pub struct CspRecord {
    pub ciphersp: CtBlob<CIPHERSP_PT_LEN>,
    pub ctr: u64,
    pub active: bool,
    pub sig: Signature,
}

#[derive(Clone)]
pub struct Provider {
    pub id: u32,
    pub online: bool,
    pub share: Scalar,
    pub svk: VerifyingKey,
    pub master: MasterRecord,
    pub csp_db: HashMap<[u8; 32], CspRecord>,
}

impl Provider {
    fn toprf_eval(&self, blinded: &RistrettoPoint) -> RistrettoPoint {
        black_box(blinded * self.share)
    }

    fn accept_csp_register(
        &mut self,
        suid: [u8; 32],
        ciphersp: CtBlob<CIPHERSP_PT_LEN>,
        ctr: u64,
        sig: &Signature,
    ) -> bool {
        if ctr != 0 {
            return false;
        }
        let msg = csp_write_message(&suid, &ciphersp, ctr);
        if self.svk.verify(&msg, sig).is_err() {
            return false;
        }
        match self.csp_db.get(&suid) {
            Some(rec) if rec.active => false,
            _ => {
                self.csp_db.insert(
                    suid,
                    CspRecord {
                        ciphersp,
                        ctr,
                        active: true,
                        sig: sig.clone(),
                    },
                );
                true
            }
        }
    }

    fn accept_csp_update(
        &mut self,
        suid: [u8; 32],
        ciphersp: CtBlob<CIPHERSP_PT_LEN>,
        ctr: u64,
        sig: &Signature,
    ) -> bool {
        let msg = csp_write_message(&suid, &ciphersp, ctr);
        if self.svk.verify(&msg, sig).is_err() {
            return false;
        }
        match self.csp_db.get(&suid) {
            Some(rec) if rec.active && ctr > rec.ctr => {
                self.csp_db.insert(
                    suid,
                    CspRecord {
                        ciphersp,
                        ctr,
                        active: true,
                        sig: sig.clone(),
                    },
                );
                true
            }
            _ => false,
        }
    }

    fn accept_master_update(
        &mut self,
        uid: &[u8],
        newcipherid: CtBlob<CIPHERID_PT_LEN>,
        ctrid: u64,
        sig: &Signature,
    ) -> bool {
        if ctrid <= self.master.ctrid {
            return false;
        }
        let msg = master_update_message(uid, &newcipherid, ctrid);
        if self.svk.verify(&msg, sig).is_err() {
            return false;
        }
        self.master = MasterRecord {
            cipherid: newcipherid,
            ctrid,
        };
        true
    }
}

#[derive(Clone)]
pub struct LoginServer {
    pub vinfo: Option<[u8; 32]>,
}

impl LoginServer {
    pub fn new() -> Self {
        Self { vinfo: None }
    }

    fn register(&mut self, vinfo: [u8; 32]) -> bool {
        if self.vinfo.is_some() {
            false
        } else {
            self.vinfo = Some(vinfo);
            true
        }
    }

    fn update(&mut self, old_vinfo: [u8; 32], new_vinfo: [u8; 32]) -> bool {
        match self.vinfo {
            Some(v) if v == old_vinfo => {
                self.vinfo = Some(new_vinfo);
                true
            }
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct System {
    pub nsp: usize,
    pub tsp: usize,
    pub qsp: usize,
    pub uid: Vec<u8>,
    pub lsj: Vec<u8>,
    pub password: Vec<u8>,
    pub new_password: Vec<u8>,
    pub pwd_point: RistrettoPoint,
    pub new_pwd_point: RistrettoPoint,
    pub user_ssk: SigningKey,
    pub cipherid_aad: Vec<u8>,
    pub ciphersp_aad: Vec<u8>,
    pub providers: Vec<Provider>,
    pub login_server: LoginServer,
}

#[derive(Clone, Debug)]
pub enum PhaseError {
    NotEnoughOnline { online: usize, needed: usize },
    NoCoordinator,
    MissingCipherSp,
    QuorumFailed { acks: usize, qsp: usize },
    LoginServerRejected,
    DecryptFailed,
}

impl fmt::Display for PhaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhaseError::NotEnoughOnline { online, needed } => {
                write!(
                    f,
                    "not enough online providers: online={}, needed={}",
                    online, needed
                )
            }
            PhaseError::NoCoordinator => write!(f, "no online coordinator available"),
            PhaseError::MissingCipherSp => write!(f, "not enough ciphersp candidates"),
            PhaseError::QuorumFailed { acks, qsp } => {
                write!(f, "quorum write failed: acks={}, qsp={}", acks, qsp)
            }
            PhaseError::LoginServerRejected => write!(f, "login server rejected the update"),
            PhaseError::DecryptFailed => write!(f, "authenticated decryption failed"),
        }
    }
}

pub fn majority_quorum(nsp: usize) -> usize {
    nsp / 2 + 1
}

pub fn quorum_size(nsp: usize, tsp: usize) -> usize {
    assert!(nsp > 0, "invalid ABD-style nsp: nsp must be positive");
    assert!(
        tsp > 0 && tsp <= nsp,
        "invalid ABD-style tsp: require 1 <= tsp <= nsp; got tsp={} for nsp={}",
        tsp,
        nsp
    );
    (nsp + tsp + 1) / 2
}

pub fn validate_threshold(nsp: usize, tsp: usize) {
    assert!(nsp > 0, "invalid ABD-style nsp: nsp must be positive");
    assert!(
        tsp > 0 && tsp <= nsp,
        "invalid ABD-style threshold: tsp={} for nsp={}; require 1 <= tsp <= nsp",
        tsp,
        nsp
    );
    let qsp = quorum_size(nsp, tsp);
    assert!(
        tsp <= qsp && qsp <= nsp,
        "invalid ABD-style quorum range: nsp={}, tsp={}, qsp={}; require tsp <= qsp <= nsp",
        nsp,
        tsp,
        qsp
    );
    let intersection = 2 * qsp - nsp;
    assert!(
        intersection > tsp - 1,
        "invalid ABD-style quorum intersection: nsp={}, tsp={}, qsp={} gives 2*qsp-nsp={} but requires > tsp-1 = {}",
        nsp,
        tsp,
        qsp,
        intersection,
        tsp - 1
    );
}

pub fn max_quorum_unavailable(nsp: usize, tsp: usize) -> usize {
    validate_threshold(nsp, tsp);
    nsp.saturating_sub(quorum_size(nsp, tsp))
}

pub fn max_executable_unavailable(nsp: usize, tsp: usize) -> usize {
    validate_threshold(nsp, tsp);

    nsp.saturating_sub(quorum_size(nsp, tsp))
}

pub fn hash_suid_shared(rsp: &[u8; 32], lsj: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"upspa/abd/suid/shared/v1");
    h.update(rsp);
    h.update(lsj);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

pub fn uid_hash(uid: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"upspa/abd/uid/v1");
    h.update(uid);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

fn master_plaintext(ssk: &SigningKey, rsp: &[u8; 32], fk: &[u8; 32], ctrid: u64) -> [u8; CIPHERID_PT_LEN] {
    let mut pt = [0u8; CIPHERID_PT_LEN];
    pt[0..32].copy_from_slice(&ssk.to_bytes());
    pt[32..64].copy_from_slice(rsp);
    pt[64..96].copy_from_slice(fk);
    pt[96..104].copy_from_slice(&ctrid.to_le_bytes());
    pt
}

fn parse_master_plaintext(pt: &[u8; CIPHERID_PT_LEN]) -> (SigningKey, [u8; 32], [u8; 32], u64) {
    let mut ssk_bytes = [0u8; 32];
    ssk_bytes.copy_from_slice(&pt[0..32]);
    let ssk = SigningKey::from_bytes(&ssk_bytes);

    let mut rsp = [0u8; 32];
    rsp.copy_from_slice(&pt[32..64]);

    let mut fk = [0u8; 32];
    fk.copy_from_slice(&pt[64..96]);

    let mut ctrid_bytes = [0u8; 8];
    ctrid_bytes.copy_from_slice(&pt[96..104]);
    let ctrid = u64::from_le_bytes(ctrid_bytes);

    (ssk, rsp, fk, ctrid)
}

fn master_update_message(uid: &[u8], blob: &CtBlob<CIPHERID_PT_LEN>, ctrid: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(uid.len() + CIPHERID_BLOB_BYTES + 8);
    msg.extend_from_slice(uid);
    msg.extend_from_slice(&blob.nonce);
    msg.extend_from_slice(&blob.ct);
    msg.extend_from_slice(&blob.tag);
    msg.extend_from_slice(&ctrid.to_le_bytes());
    msg
}

fn csp_write_message(suid: &[u8; 32], blob: &CtBlob<CIPHERSP_PT_LEN>, ctr: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32 + CIPHERSP_BLOB_BYTES + 8);
    msg.extend_from_slice(suid);
    msg.extend_from_slice(&blob.nonce);
    msg.extend_from_slice(&blob.ct);
    msg.extend_from_slice(&blob.tag);
    msg.extend_from_slice(&ctr.to_le_bytes());
    msg
}

fn verify_csp_record(svk: &VerifyingKey, suid: &[u8; 32], rec: &CspRecord) -> bool {
    if !rec.active {
        return false;
    }
    let msg = csp_write_message(suid, &rec.ciphersp, rec.ctr);
    svk.verify(&msg, &rec.sig).is_ok()
}

pub fn seed_for(tag: &[u8], nsp: usize, tsp: usize, iter: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(&(nsp as u64).to_le_bytes());
    h.update(&(tsp as u64).to_le_bytes());
    h.update(&iter.to_le_bytes());
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(out.as_bytes());
    seed
}

impl System {
    pub fn new(nsp: usize, tsp: usize, seed: [u8; 32]) -> Self {
        validate_threshold(nsp, tsp);
        let qsp = quorum_size(nsp, tsp);
        let mut rng = ChaCha20Rng::from_seed(seed);

        let uid = b"user123".to_vec();
        let lsj = b"LS1".to_vec();
        let password = b"benchmark password".to_vec();
        let new_password = b"new benchmark password".to_vec();
        let pwd_point = crypto::hash_to_point(&password);
        let new_pwd_point = crypto::hash_to_point(&new_password);

        let (master_sk, shares) = crypto::toprf_gen(nsp, tsp, &mut rng);
        let y = &pwd_point * master_sk;
        let state_key = crypto::oprf_finalize(&password, &y);

        let ssk = SigningKey::generate(&mut rng);
        let svk = ssk.verifying_key();
        let mut rsp = [0u8; 32];
        rng.fill_bytes(&mut rsp);
        let mut fk = [0u8; 32];
        rng.fill_bytes(&mut fk);
        let ctrid = 0u64;
        let cipherid_pt = master_plaintext(&ssk, &rsp, &fk, ctrid);

        let cipherid_aad = {
            let mut aad = Vec::new();
            aad.extend_from_slice(&uid);
            aad.extend_from_slice(b"|cipherid|abd");
            aad
        };
        let ciphersp_aad = {
            let mut aad = Vec::new();
            aad.extend_from_slice(&uid);
            aad.extend_from_slice(b"|ciphersp|abd");
            aad
        };

        let cipherid = crypto::xchacha_encrypt_detached(&state_key, &cipherid_aad, &cipherid_pt, &mut rng);
        let master = MasterRecord { cipherid, ctrid };

        let providers = shares
            .into_iter()
            .map(|(id, share)| Provider {
                id,
                online: true,
                share,
                svk: svk.clone(),
                master: master.clone(),
                csp_db: HashMap::new(),
            })
            .collect();

        Self {
            nsp,
            tsp,
            qsp,
            uid,
            lsj,
            password,
            new_password,
            pwd_point,
            new_pwd_point,
            user_ssk: ssk.clone(),
            cipherid_aad,
            ciphersp_aad,
            providers,
            login_server: LoginServer::new(),
        }
    }

    pub fn online_count(&self) -> usize {
        self.providers.iter().filter(|p| p.online).count()
    }

    pub fn set_rotating_unavailable(&mut self, unavailable: usize, offset: usize) {
        for p in &mut self.providers {
            p.online = true;
        }
        if unavailable == 0 || self.nsp == 0 {
            return;
        }
        for j in 0..unavailable.min(self.nsp) {
            let idx = (offset + j) % self.nsp;
            self.providers[idx].online = false;
        }
    }

    pub fn coordinator_index(&self) -> Option<usize> {
        self.providers.iter().position(|p| p.online)
    }

    fn select_online_indices(&self, needed: usize) -> Result<Vec<usize>, PhaseError> {
        let online = self.online_count();
        if online < needed {
            return Err(PhaseError::NotEnoughOnline { online, needed });
        }
        Ok(self
            .providers
            .iter()
            .enumerate()
            .filter_map(|(idx, p)| if p.online { Some(idx) } else { None })
            .take(needed)
            .collect())
    }

    fn select_quorum_indices(&self) -> Result<Vec<usize>, PhaseError> {
        self.select_online_indices(self.qsp)
    }

    fn toprf_eval_with_point(
        &self,
        password: &[u8],
        password_point: &RistrettoPoint,
        rng: &mut impl RngCore,
    ) -> Result<[u8; 32], PhaseError> {
        let indices = self.select_online_indices(self.tsp)?;
        let r = crypto::random_scalar(rng);
        let blinded = password_point * r;
        black_box(blinded.compress());

        let mut ids = Vec::with_capacity(self.tsp);
        let mut partials = Vec::with_capacity(self.tsp);
        for idx in indices {
            let p = &self.providers[idx];
            ids.push(p.id);
            partials.push(p.toprf_eval(&blinded));
        }
        let lambdas = crypto::lagrange_coeffs_at_zero(&ids);
        Ok(crypto::toprf_client_eval_from_partials(
            password, r, &partials, &lambdas,
        ))
    }

    fn decrypt_master(
        &self,
        state_key: &[u8; 32],
        cipherid: &CtBlob<CIPHERID_PT_LEN>,
    ) -> Result<(SigningKey, [u8; 32], [u8; 32], u64, [u8; CIPHERID_PT_LEN]), PhaseError> {
        let pt = crypto::xchacha_decrypt_detached(state_key, &self.cipherid_aad, cipherid)
            .map_err(|_| PhaseError::DecryptFailed)?;
        let (ssk, rsp, fk, ctrid) = parse_master_plaintext(&pt);
        Ok((ssk, rsp, fk, ctrid, pt))
    }

    pub fn qwrite_csp_register(
        &mut self,
        suid: [u8; 32],
        ciphersp: CtBlob<CIPHERSP_PT_LEN>,
        ctr: u64,
        sig: &Signature,
    ) -> Result<usize, PhaseError> {
        let indices = self.select_quorum_indices()?;
        let mut acks = 0usize;
        for idx in indices {
            if self.providers[idx].accept_csp_register(suid, ciphersp.clone(), ctr, sig) {
                acks += 1;
            }
        }
        if acks >= self.qsp {
            Ok(acks)
        } else {
            Err(PhaseError::QuorumFailed { acks, qsp: self.qsp })
        }
    }

    pub fn qwrite_csp_update(
        &mut self,
        suid: [u8; 32],
        ciphersp: CtBlob<CIPHERSP_PT_LEN>,
        ctr: u64,
        sig: &Signature,
    ) -> Result<usize, PhaseError> {
        let indices = self.select_quorum_indices()?;
        let mut acks = 0usize;
        for idx in indices {
            if self.providers[idx].accept_csp_update(suid, ciphersp.clone(), ctr, sig) {
                acks += 1;
            }
        }
        if acks >= self.qsp {
            Ok(acks)
        } else {
            Err(PhaseError::QuorumFailed { acks, qsp: self.qsp })
        }
    }

    pub fn qwrite_master(
        &mut self,
        newcipherid: CtBlob<CIPHERID_PT_LEN>,
        ctrid: u64,
        sig: &Signature,
    ) -> Result<usize, PhaseError> {
        let indices = self.select_quorum_indices()?;
        let uid = self.uid.clone();
        let mut acks = 0usize;
        for idx in indices {
            if self.providers[idx].accept_master_update(&uid, newcipherid.clone(), ctrid, sig) {
                acks += 1;
            }
        }
        if acks >= self.qsp {
            Ok(acks)
        } else {
            Err(PhaseError::QuorumFailed { acks, qsp: self.qsp })
        }
    }

    pub fn phase_registration(&mut self, rng: &mut impl RngCore) -> Result<[u8; 32], PhaseError> {
        let coord = self.coordinator_index().ok_or(PhaseError::NoCoordinator)?;
        black_box(uid_hash(&self.uid));

        let state_key = self.toprf_eval_with_point(&self.password, &self.pwd_point, rng)?;
        let master = self.providers[coord].master.clone();
        let (ssk, rsp, fk, _ctrid, _pt) = self.decrypt_master(&state_key, &master.cipherid)?;
        let suid = hash_suid_shared(&rsp, &self.lsj);

        let mut rlsj = [0u8; 32];
        rng.fill_bytes(&mut rlsj);
        let ctr = 0u64;
        let mut csp_pt = [0u8; CIPHERSP_PT_LEN];
        csp_pt[0..32].copy_from_slice(&rlsj);
        csp_pt[32..40].copy_from_slice(&ctr.to_le_bytes());
        let ciphersp = crypto::xchacha_encrypt_detached(&fk, &self.ciphersp_aad, &csp_pt, rng);
        let vinfo = crypto::hash_vinfo(&rlsj, &self.lsj);
        let sig = ssk.sign(&csp_write_message(&suid, &ciphersp, ctr));
        let acks = self.qwrite_csp_register(suid, ciphersp, ctr, &sig)?;
        if !self.login_server.register(vinfo) {
            return Err(PhaseError::LoginServerRejected);
        }

        let mut h = blake3::Hasher::new();
        h.update(b"upspa/abd/registration/result/v1");
        h.update(&suid);
        h.update(&vinfo);
        h.update(&sig.to_bytes());
        h.update(&(acks as u64).to_le_bytes());
        h.update(&(self.online_count() as u64).to_le_bytes());
        let out = h.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(out.as_bytes());
        Ok(r)
    }

    pub fn phase_secret_update(&mut self, rng: &mut impl RngCore) -> Result<[u8; 32], PhaseError> {
        let coord = self.coordinator_index().ok_or(PhaseError::NoCoordinator)?;
        black_box(uid_hash(&self.uid));

        let state_key = self.toprf_eval_with_point(&self.password, &self.pwd_point, rng)?;
        let master = self.providers[coord].master.clone();
        let (ssk, rsp, fk, _ctrid, _pt) = self.decrypt_master(&state_key, &master.cipherid)?;
        let suid = hash_suid_shared(&rsp, &self.lsj);

        let candidate_indices = self.select_online_indices(self.tsp)?;
        let mut best_ctr = None::<u64>;
        let mut best_rlsj = [0u8; 32];
        for idx in candidate_indices {
            let rec = self.providers[idx]
                .csp_db
                .get(&suid)
                .ok_or(PhaseError::MissingCipherSp)?
                .clone();
            let pt = crypto::xchacha_decrypt_detached(&fk, &self.ciphersp_aad, &rec.ciphersp)
                .map_err(|_| PhaseError::DecryptFailed)?;
            let mut rlsj = [0u8; 32];
            rlsj.copy_from_slice(&pt[0..32]);
            let mut ctr_bytes = [0u8; 8];
            ctr_bytes.copy_from_slice(&pt[32..40]);
            let ctr = u64::from_le_bytes(ctr_bytes);
            if best_ctr.map_or(true, |b| ctr >= b) {
                best_ctr = Some(ctr);
                best_rlsj = rlsj;
            }
        }
        let old_ctr = best_ctr.ok_or(PhaseError::MissingCipherSp)?;
        let old_vinfo = crypto::hash_vinfo(&best_rlsj, &self.lsj);

        let mut new_rlsj = [0u8; 32];
        rng.fill_bytes(&mut new_rlsj);
        let new_ctr = old_ctr + 1;
        let mut csp_pt = [0u8; CIPHERSP_PT_LEN];
        csp_pt[0..32].copy_from_slice(&new_rlsj);
        csp_pt[32..40].copy_from_slice(&new_ctr.to_le_bytes());
        let new_ciphersp = crypto::xchacha_encrypt_detached(&fk, &self.ciphersp_aad, &csp_pt, rng);
        let new_vinfo = crypto::hash_vinfo(&new_rlsj, &self.lsj);
        let sig = ssk.sign(&csp_write_message(&suid, &new_ciphersp, new_ctr));
        let acks = self.qwrite_csp_update(suid, new_ciphersp, new_ctr, &sig)?;
        if !self.login_server.update(old_vinfo, new_vinfo) {
            return Err(PhaseError::LoginServerRejected);
        }

        let mut h = blake3::Hasher::new();
        h.update(b"upspa/abd/secret_update/result/v1");
        h.update(&suid);
        h.update(&old_ctr.to_le_bytes());
        h.update(&new_ctr.to_le_bytes());
        h.update(&new_vinfo);
        h.update(&sig.to_bytes());
        h.update(&(acks as u64).to_le_bytes());
        let out = h.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(out.as_bytes());
        Ok(r)
    }

    pub fn phase_password_update(&mut self, rng: &mut impl RngCore) -> Result<[u8; 32], PhaseError> {
        let coord = self.coordinator_index().ok_or(PhaseError::NoCoordinator)?;
        black_box(uid_hash(&self.uid));

        let old_state_key = self.toprf_eval_with_point(&self.password, &self.pwd_point, rng)?;
        let master = self.providers[coord].master.clone();
        let (ssk, rsp, fk, ctrid, _old_pt) = self.decrypt_master(&old_state_key, &master.cipherid)?;

        let new_state_key = self.toprf_eval_with_point(&self.new_password, &self.new_pwd_point, rng)?;
        let new_ctrid = ctrid + 1;
        let new_pt = master_plaintext(&ssk, &rsp, &fk, new_ctrid);
        let newcipherid = crypto::xchacha_encrypt_detached(&new_state_key, &self.cipherid_aad, &new_pt, rng);
        let msg = master_update_message(&self.uid, &newcipherid, new_ctrid);
        let sig = ssk.sign(&msg);
        let acks = self.qwrite_master(newcipherid, new_ctrid, &sig)?;

        let mut h = blake3::Hasher::new();
        h.update(b"upspa/abd/password_update/result/v1");
        h.update(&new_ctrid.to_le_bytes());
        h.update(&sig.to_bytes());
        h.update(&(acks as u64).to_le_bytes());
        let out = h.finalize();
        let mut r = [0u8; 32];
        r.copy_from_slice(out.as_bytes());
        Ok(r)
    }

    pub fn force_registered_all(&mut self, rng: &mut impl RngCore) -> Result<[u8; 32], PhaseError> {
        for p in &mut self.providers {
            p.online = true;
        }
        let digest = self.phase_registration(rng)?;
        self.force_sync_latest_csp_to_all();
        Ok(digest)
    }

    pub fn force_sync_latest_csp_to_all(&mut self) {
        let mut latest: Option<([u8; 32], CspRecord)> = None;
        for p in &self.providers {
            for (suid, rec) in &p.csp_db {
                if rec.active && latest.as_ref().map_or(true, |(_, old)| rec.ctr >= old.ctr) {
                    latest = Some((*suid, rec.clone()));
                }
            }
        }
        if let Some((suid, rec)) = latest {
            for p in &mut self.providers {
                p.csp_db.insert(suid, rec.clone());
            }
        }
    }

    pub fn force_sync_latest_master_to_all(&mut self) {
        let latest = self
            .providers
            .iter()
            .max_by_key(|p| p.master.ctrid)
            .map(|p| p.master.clone());
        if let Some(master) = latest {
            for p in &mut self.providers {
                p.master = master.clone();
            }
        }
    }

    pub fn any_suid(&self) -> Option<[u8; 32]> {
        for p in &self.providers {
            if let Some((&suid, _)) = p.csp_db.iter().next() {
                return Some(suid);
            }
        }
        None
    }

    pub fn recover_master_for_provider(&mut self, recover_idx: usize) -> Result<usize, PhaseError> {
        let active: Vec<usize> = self
            .providers
            .iter()
            .enumerate()
            .filter_map(|(idx, p)| {
                if p.online && idx != recover_idx {
                    Some(idx)
                } else {
                    None
                }
            })
            .take(self.qsp)
            .collect();
        if active.len() < self.qsp {
            return Err(PhaseError::NotEnoughOnline {
                online: active.len(),
                needed: self.qsp,
            });
        }
        let mut best = self.providers[recover_idx].master.clone();
        for idx in active.iter().copied() {
            let candidate = self.providers[idx].master.clone();
            if candidate.ctrid > best.ctrid {
                best = candidate;
            }
        }
        self.providers[recover_idx].master = best;
        self.providers[recover_idx].online = true;
        Ok(active.len())
    }

    pub fn recover_csp_for_provider(
        &mut self,
        recover_idx: usize,
        suid: [u8; 32],
    ) -> Result<usize, PhaseError> {
        let active: Vec<usize> = self
            .providers
            .iter()
            .enumerate()
            .filter_map(|(idx, p)| {
                if p.online && idx != recover_idx {
                    Some(idx)
                } else {
                    None
                }
            })
            .take(self.qsp)
            .collect();
        if active.len() < self.qsp {
            return Err(PhaseError::NotEnoughOnline {
                online: active.len(),
                needed: self.qsp,
            });
        }
        let svk = self.providers[recover_idx].svk.clone();
        let mut best = self.providers[recover_idx]
            .csp_db
            .get(&suid)
            .filter(|rec| verify_csp_record(&svk, &suid, rec))
            .cloned();
        for idx in active.iter().copied() {
            if let Some(candidate) = self.providers[idx].csp_db.get(&suid).cloned() {
                if verify_csp_record(&svk, &suid, &candidate)
                    && best.as_ref().map_or(true, |old| candidate.ctr > old.ctr)
                {
                    best = Some(candidate);
                }
            }
        }
        if let Some(best) = best {
            self.providers[recover_idx].csp_db.insert(suid, best);
        }
        self.providers[recover_idx].online = true;
        Ok(active.len())
    }

    pub fn sign_csp_write(&self, suid: &[u8; 32], ciphersp: &CtBlob<CIPHERSP_PT_LEN>, ctr: u64) -> Signature {
        self.user_ssk.sign(&csp_write_message(suid, ciphersp, ctr))
    }

    pub fn make_synthetic_csp_payload(
        &self,
        rng: &mut impl RngCore,
        ctr: u64,
    ) -> ([u8; 32], CtBlob<CIPHERSP_PT_LEN>, u64) {
        let suid = self.synthetic_suid(rng);
        let (blob, ctr) = self.synthetic_csp_blob(rng, ctr);
        (suid, blob, ctr)
    }

    pub fn make_valid_master_update_payload(
        &self,
        rng: &mut impl RngCore,
    ) -> Result<(CtBlob<CIPHERID_PT_LEN>, u64, Signature), PhaseError> {
        let coord = self.coordinator_index().ok_or(PhaseError::NoCoordinator)?;
        let old_state_key = self.toprf_eval_with_point(&self.password, &self.pwd_point, rng)?;
        let master = self.providers[coord].master.clone();
        let (ssk, rsp, fk, ctrid, _old_pt) = self.decrypt_master(&old_state_key, &master.cipherid)?;
        let new_state_key = self.toprf_eval_with_point(&self.new_password, &self.new_pwd_point, rng)?;
        let new_ctrid = ctrid + 1;
        let new_pt = master_plaintext(&ssk, &rsp, &fk, new_ctrid);
        let newcipherid = crypto::xchacha_encrypt_detached(&new_state_key, &self.cipherid_aad, &new_pt, rng);
        let msg = master_update_message(&self.uid, &newcipherid, new_ctrid);
        let sig = ssk.sign(&msg);
        Ok((newcipherid, new_ctrid, sig))
    }

    pub fn quorum_overhead_csp_register(&mut self, rng: &mut impl RngCore) -> Result<[u8; 32], PhaseError> {
        let suid = self.synthetic_suid(rng);
        let (blob, ctr) = self.synthetic_csp_blob(rng, 0);
        let sig = self.sign_csp_write(&suid, &blob, ctr);
        let acks = self.qwrite_csp_register(suid, blob, ctr, &sig)?;
        Ok(digest_with_count(b"qover/csp/register", &suid, acks))
    }

    pub fn quorum_overhead_csp_update(&mut self, rng: &mut impl RngCore) -> Result<[u8; 32], PhaseError> {
        self.install_synthetic_csp_all(rng, 0);
        let suid = self.any_suid().expect("synthetic csp installed");
        let (blob, ctr) = self.synthetic_csp_blob(rng, 1);
        let sig = self.sign_csp_write(&suid, &blob, ctr);
        let acks = self.qwrite_csp_update(suid, blob, ctr, &sig)?;
        Ok(digest_with_count(b"qover/csp/update", &suid, acks))
    }

    pub fn quorum_overhead_master_update(&mut self, rng: &mut impl RngCore) -> Result<[u8; 32], PhaseError> {
        let coord = self.coordinator_index().ok_or(PhaseError::NoCoordinator)?;
        let state_key = self.toprf_eval_with_point(&self.password, &self.pwd_point, rng)?;
        let master = self.providers[coord].master.clone();
        let (ssk, rsp, fk, ctrid, _old_pt) = self.decrypt_master(&state_key, &master.cipherid)?;
        let new_ctrid = ctrid + 1;
        let new_pt = master_plaintext(&ssk, &rsp, &fk, new_ctrid);
        let new_state_key = self.toprf_eval_with_point(&self.new_password, &self.new_pwd_point, rng)?;
        let newcipherid = crypto::xchacha_encrypt_detached(&new_state_key, &self.cipherid_aad, &new_pt, rng);
        let msg = master_update_message(&self.uid, &newcipherid, new_ctrid);
        let sig = ssk.sign(&msg);
        let acks = self.qwrite_master(newcipherid, new_ctrid, &sig)?;
        Ok(digest_with_count(b"qover/master/update", &sig.to_bytes(), acks))
    }

    pub fn install_synthetic_csp_all(&mut self, rng: &mut impl RngCore, ctr: u64) {
        let suid = self.synthetic_suid(rng);
        let (blob, ctr) = self.synthetic_csp_blob(rng, ctr);
        let sig = self.sign_csp_write(&suid, &blob, ctr);
        let rec = CspRecord {
            ciphersp: blob,
            ctr,
            active: true,
            sig,
        };
        for p in &mut self.providers {
            p.csp_db.insert(suid, rec.clone());
        }
    }

    fn synthetic_suid(&self, rng: &mut impl RngCore) -> [u8; 32] {
        let mut suid = [0u8; 32];
        rng.fill_bytes(&mut suid);
        suid
    }

    fn synthetic_csp_blob(&self, rng: &mut impl RngCore, ctr: u64) -> (CtBlob<CIPHERSP_PT_LEN>, u64) {
        let mut fk = [0u8; 32];
        rng.fill_bytes(&mut fk);
        let mut rlsj = [0u8; 32];
        rng.fill_bytes(&mut rlsj);
        let mut pt = [0u8; CIPHERSP_PT_LEN];
        pt[0..32].copy_from_slice(&rlsj);
        pt[32..40].copy_from_slice(&ctr.to_le_bytes());
        let blob = crypto::xchacha_encrypt_detached(&fk, &self.ciphersp_aad, &pt, rng);
        (blob, ctr)
    }
}

fn digest_with_count(tag: &[u8], bytes: &[u8], count: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(bytes);
    h.update(&(count as u64).to_le_bytes());
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}
