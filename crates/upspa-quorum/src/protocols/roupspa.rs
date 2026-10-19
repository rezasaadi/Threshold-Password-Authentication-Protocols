use crate::crypto;
use crate::protocols::login_server::{LoginServer, LoginServerError, PendingLsOperation};
use crate::protocols::messages::{
    account_read_request_bytes, account_read_response_bytes, account_write_request_bytes,
    encode_roupspa_account_record, encode_roupspa_identification_record, identification_request_bytes,
    identification_response_bytes, identification_write_request_bytes, login_server_registration_bytes,
    login_server_update_bytes, setup_write_request_bytes, MessageEvent, ProtocolStage, ProtocolTrace,
    ReceiverRole, SenderRole, WaitPolicy, ACCOUNT_PLAINTEXT_LEN, IDENTIFICATION_PLAINTEXT_LEN,
    RISTRETTO_MESSAGE_BYTES, STATUS_BYTES,
};
use crate::protocols::provider::{
    AccountFamilyKey, ProviderError, ReplicaStatus, RoUpSpaProvider, SignedAccountRecord,
    SignedIdentificationRecord,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::time::Instant;

pub const DEFAULT_UID: &[u8] = b"user123";
pub const DEFAULT_LOGIN_SERVER: &[u8] = b"LS1";
pub const DEFAULT_PASSWORD: &[u8] = b"benchmark password";
pub const DEFAULT_NEW_PASSWORD: &[u8] = b"new benchmark password";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PhaseError {
    InvalidThreshold { nsp: usize, tsp: usize, qsp: usize },
    NotSetup,
    DuplicateSetup,
    SetupRequiresAllProviders,
    NotEnoughValidResponses { valid: usize, required: usize },
    InconsistentVerifyingKeys,
    InvalidSignature,
    ConflictingMaximum { family: &'static str, counter: u64 },
    ExternalInternalCounterMismatch { external: u64, internal: u64 },
    DecryptFailed,
    MissingAccount,
    AuthenticationRejected,
    LoginServerRejected(LoginServerError),
    ProviderRejected(ProviderError),
    OperationInFlight,
    NoInFlightOperation,
    WrongInFlightOperation,
    DiscardForbidden,
    TerminalStoreNotReady,
    MissingProviderShare,
    InvalidProviderIndex(usize),
    EmptyProviderTargets,
}

impl fmt::Display for PhaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PhaseError {}

impl From<LoginServerError> for PhaseError {
    fn from(value: LoginServerError) -> Self {
        Self::LoginServerRejected(value)
    }
}

impl From<ProviderError> for PhaseError {
    fn from(value: ProviderError) -> Self {
        Self::ProviderRejected(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PhaseResult {
    Completed {
        acknowledgements: usize,
        record_digest: [u8; 32],
        decision: Option<bool>,
        trace: ProtocolTrace,
    },
    ReadyForTerminalStore {
        acknowledgements: usize,
        required: usize,
        record_digest: [u8; 32],
        trace: ProtocolTrace,
    },
    Aborted {
        error: PhaseError,
        trace: ProtocolTrace,
    },
    Unresolved {
        acknowledgements: usize,
        required: usize,
        record_digest: [u8; 32],
        trace: ProtocolTrace,
    },
}

impl PhaseResult {
    pub fn trace(&self) -> &ProtocolTrace {
        match self {
            Self::Completed { trace, .. }
            | Self::ReadyForTerminalStore { trace, .. }
            | Self::Aborted { trace, .. }
            | Self::Unresolved { trace, .. } => trace,
        }
    }

    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccountWriteKind {
    Registration,
    SecretUpdate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InFlightOperation {
    Idle,
    PreparedAtLoginServer {
        record_digest: [u8; 32],
    },
    PreparedForProviderWrite {
        record_digest: [u8; 32],
    },
    ProviderWriteStarted {
        exact_encoded_tuple: Vec<u8>,
        accepted_providers: BTreeSet<u32>,
        acknowledgement_set: BTreeSet<u32>,
    },
    ReadyForTerminalStore {
        exact_encoded_tuple: Vec<u8>,
        accepted_providers: BTreeSet<u32>,
        acknowledgement_set: BTreeSet<u32>,
    },
}

#[derive(Clone, Debug)]
struct AccountOperationContext {
    kind: AccountWriteKind,
    record: SignedAccountRecord,
    ls_operation: PendingLsOperation,
    state: InFlightOperation,
    trace: ProtocolTrace,
}

#[derive(Clone, Debug)]
struct IdentificationOperationContext {
    record: SignedIdentificationRecord,
    new_password: Vec<u8>,
    state: InFlightOperation,
    trace: ProtocolTrace,
}

#[derive(Clone)]
struct RecoveredIdentification {
    ssk: SigningKey,
    svk: VerifyingKey,
    rsp: [u8; 32],
    k0: [u8; 32],
    ctrid: u64,
}

#[derive(Clone)]
struct RecoveredAccount {
    record: SignedAccountRecord,
    rlsj: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct RoUpSpaSystem {
    pub nsp: usize,
    pub tsp: usize,
    pub qsp: usize,
    pub uid: Vec<u8>,
    pub lsj: Vec<u8>,
    pub password: Vec<u8>,
    pub new_password: Vec<u8>,
    pub providers: Vec<RoUpSpaProvider>,
    pub login_server: LoginServer,
    pub last_trace: ProtocolTrace,
    pub initialized: bool,
    seed: [u8; 32],
    operation_counter: u64,
    account_operations: HashMap<AccountFamilyKey, AccountOperationContext>,
    identification_operations: HashMap<Vec<u8>, IdentificationOperationContext>,
    initial_toprf_key_commitment: Option<[u8; 32]>,
    toprf_share_commitments: HashMap<u32, [u8; 32]>,
}

pub fn validate_thresholds(nsp: usize, tsp: usize, qsp: usize) -> Result<(), PhaseError> {
    let valid_range = nsp >= 1 && tsp >= 1 && tsp <= qsp && qsp <= nsp;
    let intersection = 2_i128 * qsp as i128 - nsp as i128;
    if !valid_range || intersection <= tsp as i128 - 1 {
        return Err(PhaseError::InvalidThreshold { nsp, tsp, qsp });
    }
    Ok(())
}

pub fn minimum_quorum_size(nsp: usize, tsp: usize) -> Result<usize, PhaseError> {
    if nsp == 0 || tsp == 0 || tsp > nsp {
        return Err(PhaseError::InvalidThreshold { nsp, tsp, qsp: 0 });
    }
    (tsp..=nsp)
        .find(|&qsp| 2_i128 * qsp as i128 - nsp as i128 > tsp as i128 - 1)
        .ok_or(PhaseError::InvalidThreshold { nsp, tsp, qsp: nsp })
}

pub fn quorum_size(nsp: usize, tsp: usize) -> usize {
    minimum_quorum_size(nsp, tsp).expect("valid RoUpSPA nsp/tsp")
}

pub fn max_quorum_unavailable(nsp: usize, tsp: usize) -> usize {
    nsp.saturating_sub(quorum_size(nsp, tsp))
}

pub fn seed_for(tag: &[u8], nsp: usize, tsp: usize, iter: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"roupspa/deterministic-seed/v1");
    hasher.update(tag);
    hasher.update(&(nsp as u64).to_le_bytes());
    hasher.update(&(tsp as u64).to_le_bytes());
    hasher.update(&iter.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn exact_account_tuple(record: &SignedAccountRecord) -> Vec<u8> {
    let mut bytes = record.signed_bytes();
    bytes.extend_from_slice(&record.signature.to_bytes());
    bytes
}

fn exact_identification_tuple(uid: &[u8], record: &SignedIdentificationRecord) -> Vec<u8> {
    let mut bytes = record.signed_bytes(uid);
    if let Some(signature) = &record.signature {
        bytes.extend_from_slice(&signature.to_bytes());
    }
    bytes
}

fn next_stage_id(trace: &ProtocolTrace) -> u32 {
    trace.events.iter().map(|event| event.stage_id).max().unwrap_or(0) + 1
}

fn elapsed_ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

fn make_identification_plaintext(
    ssk: &SigningKey,
    rsp: &[u8; 32],
    k0: &[u8; 32],
    ctrid: u64,
) -> [u8; IDENTIFICATION_PLAINTEXT_LEN] {
    let mut plaintext = [0_u8; IDENTIFICATION_PLAINTEXT_LEN];
    plaintext[0..32].copy_from_slice(&ssk.to_bytes());
    plaintext[32..64].copy_from_slice(rsp);
    plaintext[64..96].copy_from_slice(k0);
    plaintext[96..104].copy_from_slice(&ctrid.to_le_bytes());
    plaintext
}

fn parse_identification_plaintext(
    plaintext: &[u8; IDENTIFICATION_PLAINTEXT_LEN],
) -> (SigningKey, [u8; 32], [u8; 32], u64) {
    let mut ssk_bytes = [0_u8; 32];
    ssk_bytes.copy_from_slice(&plaintext[0..32]);
    let mut rsp = [0_u8; 32];
    rsp.copy_from_slice(&plaintext[32..64]);
    let mut k0 = [0_u8; 32];
    k0.copy_from_slice(&plaintext[64..96]);
    let mut ctrid_bytes = [0_u8; 8];
    ctrid_bytes.copy_from_slice(&plaintext[96..104]);
    (
        SigningKey::from_bytes(&ssk_bytes),
        rsp,
        k0,
        u64::from_le_bytes(ctrid_bytes),
    )
}

fn make_account_plaintext(rlsj: &[u8; 32], ctr: u64) -> [u8; ACCOUNT_PLAINTEXT_LEN] {
    let mut plaintext = [0_u8; ACCOUNT_PLAINTEXT_LEN];
    plaintext[0..32].copy_from_slice(rlsj);
    plaintext[32..40].copy_from_slice(&ctr.to_le_bytes());
    plaintext
}

fn parse_account_plaintext(plaintext: &[u8; ACCOUNT_PLAINTEXT_LEN]) -> ([u8; 32], u64) {
    let mut rlsj = [0_u8; 32];
    rlsj.copy_from_slice(&plaintext[0..32]);
    let mut ctr_bytes = [0_u8; 8];
    ctr_bytes.copy_from_slice(&plaintext[32..40]);
    (rlsj, u64::from_le_bytes(ctr_bytes))
}

impl RoUpSpaSystem {
    pub fn new(nsp: usize, tsp: usize, qsp: usize, seed: [u8; 32]) -> Result<Self, PhaseError> {
        Self::with_identity(
            nsp,
            tsp,
            qsp,
            DEFAULT_UID.to_vec(),
            DEFAULT_LOGIN_SERVER.to_vec(),
            DEFAULT_PASSWORD.to_vec(),
            DEFAULT_NEW_PASSWORD.to_vec(),
            seed,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_identity(
        nsp: usize,
        tsp: usize,
        qsp: usize,
        uid: Vec<u8>,
        lsj: Vec<u8>,
        password: Vec<u8>,
        new_password: Vec<u8>,
        seed: [u8; 32],
    ) -> Result<Self, PhaseError> {
        validate_thresholds(nsp, tsp, qsp)?;
        let providers = (1..=nsp).map(|id| RoUpSpaProvider::new(id as u32)).collect();
        Ok(Self {
            nsp,
            tsp,
            qsp,
            uid,
            lsj,
            password,
            new_password,
            providers,
            login_server: LoginServer::new(),
            last_trace: ProtocolTrace::default(),
            initialized: false,
            seed,
            operation_counter: 0,
            account_operations: HashMap::new(),
            identification_operations: HashMap::new(),
            initial_toprf_key_commitment: None,
            toprf_share_commitments: HashMap::new(),
        })
    }

    fn operation_rng(&mut self, tag: &[u8]) -> ChaCha20Rng {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"roupspa/system-operation-rng/v1");
        hasher.update(&self.seed);
        hasher.update(tag);
        hasher.update(&self.operation_counter.to_le_bytes());
        self.operation_counter = self.operation_counter.wrapping_add(1);
        ChaCha20Rng::from_seed(*hasher.finalize().as_bytes())
    }

    fn cipherid_aad(&self) -> Vec<u8> {
        let mut aad = self.uid.clone();
        aad.extend_from_slice(b"|cipherid");
        aad
    }

    fn ciphersp_aad(&self) -> Vec<u8> {
        let mut aad = self.uid.clone();
        aad.extend_from_slice(b"|ciphersp");
        aad
    }

    pub fn set_provider_reachable(&mut self, index: usize, reachable: bool) -> Result<(), PhaseError> {
        let provider = self
            .providers
            .get_mut(index)
            .ok_or(PhaseError::InvalidProviderIndex(index))?;
        provider.reachable = reachable;
        Ok(())
    }

    pub fn set_rotating_unavailable(&mut self, unavailable: usize, offset: usize) {
        for provider in &mut self.providers {
            provider.reachable = true;
        }
        for index in 0..unavailable.min(self.nsp) {
            self.providers[(offset + index) % self.nsp].reachable = false;
        }
    }

    pub fn reachable_count(&self) -> usize {
        self.providers
            .iter()
            .filter(|provider| provider.reachable)
            .count()
    }

    fn validate_provider_targets(&self, provider_indices: &[usize]) -> Result<Vec<usize>, PhaseError> {
        if provider_indices.is_empty() {
            return Err(PhaseError::EmptyProviderTargets);
        }
        let mut unique = BTreeSet::new();
        for &index in provider_indices {
            if index >= self.providers.len() {
                return Err(PhaseError::InvalidProviderIndex(index));
            }
            unique.insert(index);
        }
        Ok(unique.into_iter().collect())
    }

    pub fn setup(&mut self) -> PhaseResult {
        let mut rng = self.operation_rng(b"setup");
        self.setup_with_rng(&mut rng)
    }

    pub fn setup_with_rng(&mut self, rng: &mut (impl RngCore + CryptoRng)) -> PhaseResult {
        let mut trace = ProtocolTrace::default();
        trace.push(MessageEvent {
            stage_id: 1,
            stage: ProtocolStage::SetupWrite,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::Provider,
            recipient_count: self.nsp,
            request_bytes: setup_write_request_bytes(&self.uid),
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::AllResponses,
            acknowledgements: self.nsp,
        });
        if self.initialized
            || self.providers.iter().any(|provider| {
                provider.identifications.contains_key(&self.uid) || provider.shares.contains_key(&self.uid)
            })
        {
            self.last_trace = trace.clone();
            return PhaseResult::Aborted {
                error: PhaseError::DuplicateSetup,
                trace,
            };
        }
        if self.providers.iter().any(|provider| !provider.reachable) {
            self.last_trace = trace.clone();
            return PhaseResult::Aborted {
                error: PhaseError::SetupRequiresAllProviders,
                trace,
            };
        }

        let (toprf_key, shares) = crypto::toprf_gen(self.nsp, self.tsp, rng);
        let state_key = crypto::oprf_finalize(
            &self.password,
            &(crypto::hash_to_point(&self.password) * toprf_key),
        );
        let ssk = SigningKey::generate(rng);
        let svk = ssk.verifying_key();
        let mut rsp = [0_u8; 32];
        rng.fill_bytes(&mut rsp);
        let mut k0 = [0_u8; 32];
        rng.fill_bytes(&mut k0);
        let plaintext = make_identification_plaintext(&ssk, &rsp, &k0, 0);
        let cid = crypto::xchacha_encrypt_detached(&state_key, &self.cipherid_aad(), &plaintext, rng);
        let record = SignedIdentificationRecord {
            cid,
            ctrid: 0,
            signature: None,
        };

        for ((provider_id, share), provider) in shares.into_iter().zip(&mut self.providers) {
            let started = Instant::now();
            let result = provider.install_setup(&self.uid, svk, record.clone(), share);
            trace.record_provider_processing(elapsed_ns(started));
            if let Err(error) = result {
                self.last_trace = trace.clone();
                return PhaseResult::Aborted {
                    error: error.into(),
                    trace,
                };
            }
            self.toprf_share_commitments.insert(provider_id, share.to_bytes());
        }
        self.initialized = true;
        self.initial_toprf_key_commitment = Some(digest_bytes(&toprf_key.to_bytes()));
        let digest = digest_bytes(&encode_roupspa_identification_record(
            &self.uid,
            &record.cid,
            record.ctrid,
        ));
        self.last_trace = trace.clone();
        PhaseResult::Completed {
            acknowledgements: self.nsp,
            record_digest: digest,
            decision: None,
            trace,
        }
    }

    fn ensure_setup(&self) -> Result<(), PhaseError> {
        if self.initialized {
            Ok(())
        } else {
            Err(PhaseError::NotSetup)
        }
    }

    fn root_operation_state(&self) -> InFlightOperation {
        self.identification_operations
            .get(&self.uid)
            .map(|context| context.state.clone())
            .unwrap_or(InFlightOperation::Idle)
    }

    pub fn identification_operation_state(&self) -> InFlightOperation {
        self.root_operation_state()
    }

    pub fn account_operation_state(&self, key: &AccountFamilyKey) -> InFlightOperation {
        self.account_operations
            .get(key)
            .map(|context| context.state.clone())
            .unwrap_or(InFlightOperation::Idle)
    }

    fn validate_identification_record(
        uid: &[u8],
        svk: &VerifyingKey,
        record: &SignedIdentificationRecord,
    ) -> bool {
        match (record.ctrid, record.signature.as_ref()) {
            (0, None) => true,
            (0, Some(_)) | (_, None) => false,
            (_, Some(signature)) => svk.verify(&record.signed_bytes(uid), signature).is_ok(),
        }
    }

    fn common_identification(
        &self,
        password: &[u8],
        stage: ProtocolStage,
        trace: &mut ProtocolTrace,
        rng: &mut impl RngCore,
    ) -> Result<RecoveredIdentification, PhaseError> {
        self.ensure_setup()?;
        if !matches!(self.root_operation_state(), InFlightOperation::Idle) {
            return Err(PhaseError::OperationInFlight);
        }
        let blind = crypto::random_scalar(rng);
        let blinded = crypto::hash_to_point(password) * blind;
        let mut grouped: HashMap<[u8; 32], Vec<_>> = HashMap::new();
        let mut contacted = 0_usize;
        for provider in &self.providers {
            if !provider.reachable {
                continue;
            }
            contacted += 1;
            let started = Instant::now();
            let response = provider.identification_response(&self.uid, Some(&blinded));
            trace.record_provider_processing(elapsed_ns(started));
            let Ok(response) = response else {
                continue;
            };
            let share_is_valid = provider.share(&self.uid).is_some_and(|share| {
                self.toprf_share_commitments.get(&provider.id) == Some(&share.to_bytes())
            });
            if !Self::validate_identification_record(&self.uid, &response.svk, &response.current)
                || response.toprf_response.is_none()
                || !share_is_valid
            {
                continue;
            }
            grouped.entry(response.svk.to_bytes()).or_default().push(response);
        }
        let mut groups: Vec<_> = grouped.into_values().collect();
        groups.sort_by_key(|group| std::cmp::Reverse(group.len()));
        let Some(responses) = groups.first() else {
            return Err(PhaseError::NotEnoughValidResponses {
                valid: 0,
                required: self.tsp,
            });
        };
        if responses.len() < self.tsp {
            return Err(PhaseError::NotEnoughValidResponses {
                valid: responses.len(),
                required: self.tsp,
            });
        }
        if groups
            .get(1)
            .is_some_and(|second| second.len() == responses.len())
        {
            return Err(PhaseError::InconsistentVerifyingKeys);
        }

        let max_ctrid = responses
            .iter()
            .map(|response| response.current.ctrid)
            .max()
            .expect("non-empty valid response group");
        let mut maxima = Vec::<SignedIdentificationRecord>::new();
        for response in responses
            .iter()
            .filter(|response| response.current.ctrid == max_ctrid)
        {
            if !maxima.iter().any(|record| record == &response.current) {
                maxima.push(response.current.clone());
            }
        }
        if maxima.len() != 1 {
            return Err(PhaseError::ConflictingMaximum {
                family: "identification",
                counter: max_ctrid,
            });
        }
        let selected = maxima.pop().expect("one maximum");

        let threshold = &responses[..self.tsp];
        let ids: Vec<u32> = threshold.iter().map(|response| response.provider_id).collect();
        let partials: Vec<RistrettoPoint> = threshold
            .iter()
            .map(|response| response.toprf_response.expect("validated TOPRF response"))
            .collect();
        let lambdas = crypto::lagrange_coeffs_at_zero(&ids);
        let state_key = crypto::toprf_client_eval_from_partials(password, blind, &partials, &lambdas);
        let plaintext = crypto::xchacha_decrypt_detached(&state_key, &self.cipherid_aad(), &selected.cid)
            .map_err(|_| PhaseError::DecryptFailed)?;
        let (ssk, rsp, k0, ctrid_internal) = parse_identification_plaintext(&plaintext);
        if ctrid_internal != selected.ctrid {
            return Err(PhaseError::ExternalInternalCounterMismatch {
                external: selected.ctrid,
                internal: ctrid_internal,
            });
        }
        let svk = VerifyingKey::from_bytes(&responses[0].svk.to_bytes())
            .map_err(|_| PhaseError::InconsistentVerifyingKeys)?;
        if ssk.verifying_key() != svk {
            return Err(PhaseError::InconsistentVerifyingKeys);
        }

        trace.push(MessageEvent {
            stage_id: next_stage_id(trace),
            stage,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::Provider,
            recipient_count: contacted,
            request_bytes: identification_request_bytes(&self.uid),
            response_bytes: identification_response_bytes(selected.signature.is_some(), true),
            wait_policy: WaitPolicy::Threshold(self.tsp),
            acknowledgements: self.tsp,
        });
        Ok(RecoveredIdentification {
            ssk,
            svk,
            rsp,
            k0,
            ctrid: selected.ctrid,
        })
    }

    fn evaluate_same_toprf(
        &self,
        password: &[u8],
        trace: &mut ProtocolTrace,
        rng: &mut impl RngCore,
    ) -> Result<[u8; 32], PhaseError> {
        let blind = crypto::random_scalar(rng);
        let blinded = crypto::hash_to_point(password) * blind;
        let mut ids = Vec::new();
        let mut partials = Vec::new();
        let mut contacted = 0;
        for provider in &self.providers {
            if !provider.reachable {
                continue;
            }
            contacted += 1;
            let started = Instant::now();
            let contribution = (|| {
                let replica = provider.identifications.get(&self.uid)?;
                if replica.status != ReplicaStatus::Active {
                    return None;
                }
                let share = provider.share(&self.uid)?;
                if self.toprf_share_commitments.get(&provider.id) != Some(&share.to_bytes()) {
                    return None;
                }
                Some((provider.id, blinded * share))
            })();
            trace.record_provider_processing(elapsed_ns(started));
            if let Some((provider_id, partial)) = contribution {
                ids.push(provider_id);
                partials.push(partial);
            }
        }
        if ids.len() < self.tsp {
            return Err(PhaseError::NotEnoughValidResponses {
                valid: ids.len(),
                required: self.tsp,
            });
        }
        ids.truncate(self.tsp);
        partials.truncate(self.tsp);
        let lambdas = crypto::lagrange_coeffs_at_zero(&ids);
        let key = crypto::toprf_client_eval_from_partials(password, blind, &partials, &lambdas);
        trace.push(MessageEvent {
            stage_id: next_stage_id(trace),
            stage: ProtocolStage::ToprfNewSameShares,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::Provider,
            recipient_count: contacted,
            request_bytes: RISTRETTO_MESSAGE_BYTES,
            response_bytes: RISTRETTO_MESSAGE_BYTES,
            wait_policy: WaitPolicy::Threshold(self.tsp),
            acknowledgements: self.tsp,
        });
        Ok(key)
    }

    fn shared_suid(&self, rsp: &[u8; 32]) -> [u8; 32] {
        crypto::hash_roupspa_suid(rsp, &self.lsj)
    }

    pub fn hash_shared_suid(&self, rsp: &[u8; 32]) -> [u8; 32] {
        self.shared_suid(rsp)
    }

    fn read_account(
        &self,
        key: &AccountFamilyKey,
        k0: &[u8; 32],
        svk: &VerifyingKey,
        trace: &mut ProtocolTrace,
    ) -> Result<RecoveredAccount, PhaseError> {
        if !matches!(self.account_operation_state(key), InFlightOperation::Idle) {
            return Err(PhaseError::OperationInFlight);
        }
        let mut candidates = Vec::<(SignedAccountRecord, [u8; 32])>::new();
        let mut contacted = 0_usize;
        for provider in &self.providers {
            if !provider.reachable {
                continue;
            }
            contacted += 1;
            let started = Instant::now();
            let record = provider.account_response(key);
            trace.record_provider_processing(elapsed_ns(started));
            let Ok(record) = record else {
                continue;
            };
            if record.uid != key.uid || record.suid != key.suid {
                continue;
            }
            if svk
                .verify(
                    &encode_roupspa_account_record(&record.uid, &record.suid, &record.cj, record.ctr),
                    &record.signature,
                )
                .is_err()
            {
                continue;
            }
            let Ok(plaintext) = crypto::xchacha_decrypt_detached(k0, &self.ciphersp_aad(), &record.cj) else {
                continue;
            };
            let (rlsj, internal_ctr) = parse_account_plaintext(&plaintext);
            if internal_ctr != record.ctr {
                continue;
            }
            candidates.push((record, rlsj));
        }
        if candidates.len() < self.tsp {
            return Err(PhaseError::NotEnoughValidResponses {
                valid: candidates.len(),
                required: self.tsp,
            });
        }
        let max_ctr = candidates
            .iter()
            .map(|(record, _)| record.ctr)
            .max()
            .ok_or(PhaseError::MissingAccount)?;
        let mut maxima = Vec::<(SignedAccountRecord, [u8; 32])>::new();
        for candidate in candidates.into_iter().filter(|(record, _)| record.ctr == max_ctr) {
            if !maxima.iter().any(|(record, _)| record == &candidate.0) {
                maxima.push(candidate);
            }
        }
        if maxima.len() != 1 {
            return Err(PhaseError::ConflictingMaximum {
                family: "account",
                counter: max_ctr,
            });
        }
        trace.push(MessageEvent {
            stage_id: next_stage_id(trace),
            stage: ProtocolStage::AccountRead,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::Provider,
            recipient_count: contacted,
            request_bytes: account_read_request_bytes(&self.uid),
            response_bytes: account_read_response_bytes(),
            wait_policy: WaitPolicy::Threshold(self.tsp),
            acknowledgements: self.tsp,
        });
        let (record, rlsj) = maxima.pop().expect("one maximum account record");
        Ok(RecoveredAccount { record, rlsj })
    }

    pub fn begin_registration(&mut self) -> Result<AccountFamilyKey, PhaseError> {
        let mut rng = self.operation_rng(b"begin-registration");
        self.begin_registration_with_rng(&mut rng)
    }

    pub fn begin_registration_with_rng(
        &mut self,
        rng: &mut impl RngCore,
    ) -> Result<AccountFamilyKey, PhaseError> {
        let mut trace = ProtocolTrace::default();
        let recovered = match self.common_identification(
            &self.password,
            ProtocolStage::Identification,
            &mut trace,
            rng,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.last_trace = trace;
                return Err(error);
            }
        };
        let suid = self.shared_suid(&recovered.rsp);
        let key = AccountFamilyKey::new(&self.uid, suid);
        if !matches!(self.account_operation_state(&key), InFlightOperation::Idle) {
            self.last_trace = trace;
            return Err(PhaseError::OperationInFlight);
        }
        let mut rlsj = [0_u8; 32];
        rng.fill_bytes(&mut rlsj);
        let ctr = 0;
        let plaintext = make_account_plaintext(&rlsj, ctr);
        let cj = crypto::xchacha_encrypt_detached(&recovered.k0, &self.ciphersp_aad(), &plaintext, rng);
        let signature = recovered
            .ssk
            .sign(&encode_roupspa_account_record(&self.uid, &suid, &cj, ctr));
        let record = SignedAccountRecord {
            uid: self.uid.clone(),
            suid,
            cj,
            ctr,
            signature,
        };
        let vinfo = crypto::hash_vinfo(&rlsj, &self.lsj);
        let started = Instant::now();
        let prepare_result = self.login_server.prepare_registration(&self.uid, vinfo);
        trace.record_login_server_processing(elapsed_ns(started));
        let ls_operation = match prepare_result {
            Ok(operation) => operation,
            Err(error) => {
                trace.push(MessageEvent {
                    stage_id: next_stage_id(&trace),
                    stage: ProtocolStage::LsPrepare,
                    sender_role: SenderRole::User,
                    receiver_role: ReceiverRole::LoginServer,
                    recipient_count: 1,
                    request_bytes: login_server_registration_bytes(&self.uid),
                    response_bytes: STATUS_BYTES,
                    wait_policy: WaitPolicy::AllResponses,
                    acknowledgements: 1,
                });
                self.last_trace = trace;
                return Err(error.into());
            }
        };
        trace.push(MessageEvent {
            stage_id: next_stage_id(&trace),
            stage: ProtocolStage::LsPrepare,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::LoginServer,
            recipient_count: 1,
            request_bytes: login_server_registration_bytes(&self.uid),
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::AllResponses,
            acknowledgements: 1,
        });
        let digest = digest_bytes(&exact_account_tuple(&record));
        self.account_operations.insert(
            key.clone(),
            AccountOperationContext {
                kind: AccountWriteKind::Registration,
                record,
                ls_operation,
                state: InFlightOperation::PreparedAtLoginServer {
                    record_digest: digest,
                },
                trace: trace.clone(),
            },
        );
        self.last_trace = trace;
        Ok(key)
    }

    pub fn begin_secret_update(&mut self) -> Result<AccountFamilyKey, PhaseError> {
        let mut rng = self.operation_rng(b"begin-secret-update");
        self.begin_secret_update_with_rng(&mut rng)
    }

    pub fn begin_secret_update_with_rng(
        &mut self,
        rng: &mut impl RngCore,
    ) -> Result<AccountFamilyKey, PhaseError> {
        let mut trace = ProtocolTrace::default();
        let recovered = match self.common_identification(
            &self.password,
            ProtocolStage::Identification,
            &mut trace,
            rng,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.last_trace = trace;
                return Err(error);
            }
        };
        let suid = self.shared_suid(&recovered.rsp);
        let key = AccountFamilyKey::new(&self.uid, suid);
        let old = match self.read_account(&key, &recovered.k0, &recovered.svk, &mut trace) {
            Ok(value) => value,
            Err(error) => {
                self.last_trace = trace;
                return Err(error);
            }
        };
        let old_vinfo = crypto::hash_vinfo(&old.rlsj, &self.lsj);
        let mut new_rlsj = [0_u8; 32];
        rng.fill_bytes(&mut new_rlsj);
        let new_ctr = old
            .record
            .ctr
            .checked_add(1)
            .ok_or(PhaseError::ConflictingMaximum {
                family: "account-counter-overflow",
                counter: old.record.ctr,
            })?;
        let plaintext = make_account_plaintext(&new_rlsj, new_ctr);
        let cj = crypto::xchacha_encrypt_detached(&recovered.k0, &self.ciphersp_aad(), &plaintext, rng);
        let signature = recovered
            .ssk
            .sign(&encode_roupspa_account_record(&self.uid, &suid, &cj, new_ctr));
        let record = SignedAccountRecord {
            uid: self.uid.clone(),
            suid,
            cj,
            ctr: new_ctr,
            signature,
        };
        let new_vinfo = crypto::hash_vinfo(&new_rlsj, &self.lsj);
        let started = Instant::now();
        let prepare_result = self
            .login_server
            .prepare_secret_update(&self.uid, old_vinfo, new_vinfo);
        trace.record_login_server_processing(elapsed_ns(started));
        let ls_operation = match prepare_result {
            Ok(operation) => operation,
            Err(error) => {
                trace.push(MessageEvent {
                    stage_id: next_stage_id(&trace),
                    stage: ProtocolStage::LsPrepare,
                    sender_role: SenderRole::User,
                    receiver_role: ReceiverRole::LoginServer,
                    recipient_count: 1,
                    request_bytes: login_server_update_bytes(&self.uid),
                    response_bytes: STATUS_BYTES,
                    wait_policy: WaitPolicy::AllResponses,
                    acknowledgements: 1,
                });
                self.last_trace = trace;
                return Err(error.into());
            }
        };
        trace.push(MessageEvent {
            stage_id: next_stage_id(&trace),
            stage: ProtocolStage::LsPrepare,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::LoginServer,
            recipient_count: 1,
            request_bytes: login_server_update_bytes(&self.uid),
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::AllResponses,
            acknowledgements: 1,
        });
        let digest = digest_bytes(&exact_account_tuple(&record));
        self.account_operations.insert(
            key.clone(),
            AccountOperationContext {
                kind: AccountWriteKind::SecretUpdate,
                record,
                ls_operation,
                state: InFlightOperation::PreparedAtLoginServer {
                    record_digest: digest,
                },
                trace: trace.clone(),
            },
        );
        self.last_trace = trace;
        Ok(key)
    }

    pub fn attempt_registration_write(
        &mut self,
        key: &AccountFamilyKey,
        provider_indices: &[usize],
    ) -> Result<PhaseResult, PhaseError> {
        if self
            .account_operations
            .get(key)
            .is_none_or(|context| context.kind != AccountWriteKind::Registration)
        {
            return Err(PhaseError::WrongInFlightOperation);
        }
        self.retry_inflight_account_write(key, provider_indices)
    }

    pub fn attempt_secret_update_write(
        &mut self,
        key: &AccountFamilyKey,
        provider_indices: &[usize],
    ) -> Result<PhaseResult, PhaseError> {
        if self
            .account_operations
            .get(key)
            .is_none_or(|context| context.kind != AccountWriteKind::SecretUpdate)
        {
            return Err(PhaseError::WrongInFlightOperation);
        }
        self.retry_inflight_account_write(key, provider_indices)
    }

    pub fn retry_inflight_account_write(
        &mut self,
        key: &AccountFamilyKey,
        provider_indices: &[usize],
    ) -> Result<PhaseResult, PhaseError> {
        let context = self
            .account_operations
            .get(key)
            .cloned()
            .ok_or(PhaseError::NoInFlightOperation)?;
        let provider_indices = self.validate_provider_targets(provider_indices)?;
        let exact_tuple = exact_account_tuple(&context.record);
        let mut accepted = match &context.state {
            InFlightOperation::PreparedAtLoginServer { .. } => BTreeSet::new(),
            InFlightOperation::ProviderWriteStarted {
                accepted_providers, ..
            }
            | InFlightOperation::ReadyForTerminalStore {
                accepted_providers, ..
            } => accepted_providers.clone(),
            _ => return Err(PhaseError::WrongInFlightOperation),
        };
        let accepted_before = accepted.len();
        let mut provider_processing_ns = 0_u64;
        for &index in &provider_indices {
            let provider = &mut self.providers[index];
            let started = Instant::now();
            let result = match context.kind {
                AccountWriteKind::Registration => {
                    provider.accept_registration_account(context.record.clone())
                }
                AccountWriteKind::SecretUpdate => {
                    provider.accept_secret_update_account(context.record.clone())
                }
            };
            provider_processing_ns = provider_processing_ns.saturating_add(elapsed_ns(started));
            if result.is_ok() {
                accepted.insert(provider.id);
            }
        }
        let newly_acknowledged = accepted.len().saturating_sub(accepted_before);
        let acknowledgements = accepted.len();
        let ready = acknowledgements >= self.qsp;
        let state = if ready {
            InFlightOperation::ReadyForTerminalStore {
                exact_encoded_tuple: exact_tuple.clone(),
                accepted_providers: accepted.clone(),
                acknowledgement_set: accepted.clone(),
            }
        } else {
            InFlightOperation::ProviderWriteStarted {
                exact_encoded_tuple: exact_tuple.clone(),
                accepted_providers: accepted.clone(),
                acknowledgement_set: accepted.clone(),
            }
        };
        let stored = self
            .account_operations
            .get_mut(key)
            .expect("context remains present");
        stored.trace.record_provider_processing(provider_processing_ns);
        stored.trace.push(MessageEvent {
            stage_id: next_stage_id(&stored.trace),
            stage: ProtocolStage::ProviderQuorumWrite,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::Provider,
            recipient_count: provider_indices.len(),
            request_bytes: account_write_request_bytes(&self.uid),
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::Quorum(self.qsp),
            acknowledgements: newly_acknowledged,
        });
        stored.state = state;
        let digest = digest_bytes(&exact_tuple);
        let trace = stored.trace.clone();
        self.last_trace = trace.clone();
        Ok(if ready {
            PhaseResult::ReadyForTerminalStore {
                acknowledgements,
                required: self.qsp,
                record_digest: digest,
                trace,
            }
        } else {
            PhaseResult::Unresolved {
                acknowledgements,
                required: self.qsp,
                record_digest: digest,
                trace,
            }
        })
    }

    pub fn retry_inflight_account_write_exact(
        &mut self,
        key: &AccountFamilyKey,
        record: &SignedAccountRecord,
        provider_indices: &[usize],
    ) -> Result<PhaseResult, PhaseError> {
        let frozen = self
            .account_operations
            .get(key)
            .ok_or(PhaseError::NoInFlightOperation)?;
        if exact_account_tuple(&frozen.record) != exact_account_tuple(record) {
            return Err(PhaseError::WrongInFlightOperation);
        }
        self.retry_inflight_account_write(key, provider_indices)
    }

    pub fn abort_account_before_write(&mut self, key: &AccountFamilyKey) -> Result<(), PhaseError> {
        let context = self
            .account_operations
            .get(key)
            .cloned()
            .ok_or(PhaseError::NoInFlightOperation)?;
        match context.state {
            InFlightOperation::PreparedAtLoginServer { .. } => {
                self.login_server.discard(&self.uid, &context.ls_operation)?;
                self.account_operations.remove(key);
                Ok(())
            }
            InFlightOperation::ProviderWriteStarted { .. }
            | InFlightOperation::ReadyForTerminalStore { .. } => Err(PhaseError::DiscardForbidden),
            _ => Err(PhaseError::WrongInFlightOperation),
        }
    }

    pub fn deliver_account_store(&mut self, key: &AccountFamilyKey) -> Result<PhaseResult, PhaseError> {
        let context = self
            .account_operations
            .get(key)
            .cloned()
            .ok_or(PhaseError::NoInFlightOperation)?;
        let acknowledgement_set = match &context.state {
            InFlightOperation::ReadyForTerminalStore {
                acknowledgement_set, ..
            } => acknowledgement_set.clone(),
            InFlightOperation::ProviderWriteStarted { .. } => return Err(PhaseError::TerminalStoreNotReady),
            _ => return Err(PhaseError::WrongInFlightOperation),
        };
        let mut trace = context.trace;
        let started = Instant::now();
        let store_result = self.login_server.store(&self.uid, &context.ls_operation);
        trace.record_login_server_processing(elapsed_ns(started));
        store_result?;
        for provider in &mut self.providers {
            let status = if acknowledgement_set.contains(&provider.id) {
                ReplicaStatus::Active
            } else {
                ReplicaStatus::Stale
            };
            provider.mark_account_status(key, status);
        }
        trace.push(MessageEvent {
            stage_id: next_stage_id(&trace),
            stage: ProtocolStage::LsTerminalDelivery,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::LoginServer,
            recipient_count: 1,
            request_bytes: match context.ls_operation {
                PendingLsOperation::Registration { .. } => login_server_registration_bytes(&self.uid),
                PendingLsOperation::SecretUpdate { .. } => login_server_update_bytes(&self.uid),
            },
            response_bytes: 0,
            wait_policy: WaitPolicy::OneWayDeliveryBound,
            acknowledgements: 0,
        });
        let exact = exact_account_tuple(&context.record);
        self.account_operations.remove(key);
        self.last_trace = trace.clone();
        Ok(PhaseResult::Completed {
            acknowledgements: acknowledgement_set.len(),
            record_digest: digest_bytes(&exact),
            decision: None,
            trace,
        })
    }

    fn reachable_indices(&self) -> Vec<usize> {
        self.providers
            .iter()
            .enumerate()
            .filter_map(|(index, provider)| provider.reachable.then_some(index))
            .collect()
    }

    pub fn registration(&mut self) -> PhaseResult {
        let mut rng = self.operation_rng(b"registration");
        self.registration_with_rng(&mut rng)
    }

    pub fn registration_with_rng(&mut self, rng: &mut impl RngCore) -> PhaseResult {
        let key = match self.begin_registration_with_rng(rng) {
            Ok(key) => key,
            Err(error) => {
                return PhaseResult::Aborted {
                    error,
                    trace: self.last_trace.clone(),
                }
            }
        };
        let indices = self.reachable_indices();
        match self.attempt_registration_write(&key, &indices) {
            Ok(PhaseResult::ReadyForTerminalStore { .. }) => {
                self.deliver_account_store(&key)
                    .unwrap_or_else(|error| PhaseResult::Aborted {
                        error,
                        trace: self.last_trace.clone(),
                    })
            }
            Ok(result) => result,
            Err(error) => PhaseResult::Aborted {
                error,
                trace: self.last_trace.clone(),
            },
        }
    }

    pub fn secret_update(&mut self) -> PhaseResult {
        let mut rng = self.operation_rng(b"secret-update");
        self.secret_update_with_rng(&mut rng)
    }

    pub fn secret_update_with_rng(&mut self, rng: &mut impl RngCore) -> PhaseResult {
        let key = match self.begin_secret_update_with_rng(rng) {
            Ok(key) => key,
            Err(error) => {
                return PhaseResult::Aborted {
                    error,
                    trace: self.last_trace.clone(),
                }
            }
        };
        let indices = self.reachable_indices();
        match self.attempt_secret_update_write(&key, &indices) {
            Ok(PhaseResult::ReadyForTerminalStore { .. }) => {
                self.deliver_account_store(&key)
                    .unwrap_or_else(|error| PhaseResult::Aborted {
                        error,
                        trace: self.last_trace.clone(),
                    })
            }
            Ok(result) => result,
            Err(error) => PhaseResult::Aborted {
                error,
                trace: self.last_trace.clone(),
            },
        }
    }

    pub fn authenticate(&mut self) -> Result<bool, PhaseError> {
        let mut rng = self.operation_rng(b"authenticate");
        self.authenticate_with_rng(&mut rng)
    }

    pub fn authenticate_with_rng(&mut self, rng: &mut impl RngCore) -> Result<bool, PhaseError> {
        let mut trace = ProtocolTrace::default();
        let recovered =
            self.common_identification(&self.password, ProtocolStage::Identification, &mut trace, rng)?;
        let key = AccountFamilyKey::new(&self.uid, self.shared_suid(&recovered.rsp));
        let account = self.read_account(&key, &recovered.k0, &recovered.svk, &mut trace)?;
        let vinfo = crypto::hash_vinfo(&account.rlsj, &self.lsj);
        let started = Instant::now();
        let decision = self.login_server.authenticate(&self.uid, &vinfo);
        trace.record_login_server_processing(elapsed_ns(started));
        trace.push(MessageEvent {
            stage_id: next_stage_id(&trace),
            stage: ProtocolStage::LsAuthentication,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::LoginServer,
            recipient_count: 1,
            request_bytes: login_server_registration_bytes(&self.uid),
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::AllResponses,
            acknowledgements: 1,
        });
        self.last_trace = trace;
        Ok(decision)
    }

    pub fn authentication(&mut self) -> PhaseResult {
        match self.authenticate() {
            Ok(decision) => PhaseResult::Completed {
                acknowledgements: usize::from(decision),
                record_digest: digest_bytes(&self.uid),
                decision: Some(decision),
                trace: self.last_trace.clone(),
            },
            Err(error) => PhaseResult::Aborted {
                error,
                trace: self.last_trace.clone(),
            },
        }
    }

    pub fn begin_password_update(&mut self) -> Result<(), PhaseError> {
        let mut rng = self.operation_rng(b"begin-password-update");
        self.begin_password_update_with_rng(&mut rng)
    }

    pub fn begin_password_update_with_rng(&mut self, rng: &mut impl RngCore) -> Result<(), PhaseError> {
        let mut trace = ProtocolTrace::default();
        let recovered = match self.common_identification(
            &self.password,
            ProtocolStage::IdentificationOld,
            &mut trace,
            rng,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.last_trace = trace;
                return Err(error);
            }
        };
        let new_password = self.new_password.clone();
        let new_state_key = match self.evaluate_same_toprf(&new_password, &mut trace, rng) {
            Ok(value) => value,
            Err(error) => {
                self.last_trace = trace;
                return Err(error);
            }
        };
        let new_ctrid = recovered
            .ctrid
            .checked_add(1)
            .ok_or(PhaseError::ConflictingMaximum {
                family: "identification-counter-overflow",
                counter: recovered.ctrid,
            })?;
        let plaintext =
            make_identification_plaintext(&recovered.ssk, &recovered.rsp, &recovered.k0, new_ctrid);
        let cid = crypto::xchacha_encrypt_detached(&new_state_key, &self.cipherid_aad(), &plaintext, rng);
        let signature = recovered
            .ssk
            .sign(&encode_roupspa_identification_record(&self.uid, &cid, new_ctrid));
        let record = SignedIdentificationRecord {
            cid,
            ctrid: new_ctrid,
            signature: Some(signature),
        };
        let exact = exact_identification_tuple(&self.uid, &record);
        let digest = digest_bytes(&exact);
        self.identification_operations.insert(
            self.uid.clone(),
            IdentificationOperationContext {
                record,
                new_password,
                state: InFlightOperation::PreparedForProviderWrite {
                    record_digest: digest,
                },
                trace: trace.clone(),
            },
        );
        self.last_trace = trace;
        Ok(())
    }

    pub fn attempt_password_update_write(
        &mut self,
        provider_indices: &[usize],
    ) -> Result<PhaseResult, PhaseError> {
        let context = self
            .identification_operations
            .get(&self.uid)
            .cloned()
            .ok_or(PhaseError::NoInFlightOperation)?;
        let provider_indices = self.validate_provider_targets(provider_indices)?;
        let exact = exact_identification_tuple(&self.uid, &context.record);
        let mut accepted = match &context.state {
            InFlightOperation::PreparedForProviderWrite { .. } => BTreeSet::new(),
            InFlightOperation::ProviderWriteStarted {
                accepted_providers, ..
            }
            | InFlightOperation::ReadyForTerminalStore {
                accepted_providers, ..
            } => accepted_providers.clone(),
            _ => return Err(PhaseError::WrongInFlightOperation),
        };
        let accepted_before = accepted.len();
        let mut provider_processing_ns = 0_u64;
        for &index in &provider_indices {
            let provider = &mut self.providers[index];
            let started = Instant::now();
            let result = provider
                .accept_tentative_identification(&self.uid, context.record.clone())
                .is_ok();
            provider_processing_ns = provider_processing_ns.saturating_add(elapsed_ns(started));
            if result {
                accepted.insert(provider.id);
            }
        }
        let newly_acknowledged = accepted.len().saturating_sub(accepted_before);
        let acknowledgements = accepted.len();
        let ready = acknowledgements >= self.qsp;
        let state = if ready {
            InFlightOperation::ReadyForTerminalStore {
                exact_encoded_tuple: exact.clone(),
                accepted_providers: accepted.clone(),
                acknowledgement_set: accepted.clone(),
            }
        } else {
            InFlightOperation::ProviderWriteStarted {
                exact_encoded_tuple: exact.clone(),
                accepted_providers: accepted.clone(),
                acknowledgement_set: accepted.clone(),
            }
        };
        let stored = self
            .identification_operations
            .get_mut(&self.uid)
            .expect("root operation remains present");
        stored.trace.record_provider_processing(provider_processing_ns);
        stored.trace.push(MessageEvent {
            stage_id: next_stage_id(&stored.trace),
            stage: ProtocolStage::QuorumTentativeWrites,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::Provider,
            recipient_count: provider_indices.len(),
            request_bytes: identification_write_request_bytes(&self.uid),
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::Quorum(self.qsp),
            acknowledgements: newly_acknowledged,
        });
        stored.state = state;
        let trace = stored.trace.clone();
        let digest = digest_bytes(&exact);
        self.last_trace = trace.clone();
        Ok(if ready {
            PhaseResult::ReadyForTerminalStore {
                acknowledgements,
                required: self.qsp,
                record_digest: digest,
                trace,
            }
        } else {
            PhaseResult::Unresolved {
                acknowledgements,
                required: self.qsp,
                record_digest: digest,
                trace,
            }
        })
    }

    pub fn retry_inflight_password_write(
        &mut self,
        provider_indices: &[usize],
    ) -> Result<PhaseResult, PhaseError> {
        self.attempt_password_update_write(provider_indices)
    }

    pub fn retry_inflight_password_write_exact(
        &mut self,
        record: &SignedIdentificationRecord,
        provider_indices: &[usize],
    ) -> Result<PhaseResult, PhaseError> {
        let context = self
            .identification_operations
            .get(&self.uid)
            .ok_or(PhaseError::NoInFlightOperation)?;
        if exact_identification_tuple(&self.uid, &context.record)
            != exact_identification_tuple(&self.uid, record)
        {
            return Err(PhaseError::WrongInFlightOperation);
        }
        self.attempt_password_update_write(provider_indices)
    }

    pub fn abort_password_update_before_write(&mut self) -> Result<(), PhaseError> {
        let context = self
            .identification_operations
            .get(&self.uid)
            .ok_or(PhaseError::NoInFlightOperation)?;
        match context.state {
            InFlightOperation::PreparedForProviderWrite { .. } => {
                self.identification_operations.remove(&self.uid);
                Ok(())
            }
            InFlightOperation::ProviderWriteStarted { .. }
            | InFlightOperation::ReadyForTerminalStore { .. } => Err(PhaseError::DiscardForbidden),
            _ => Err(PhaseError::WrongInFlightOperation),
        }
    }

    pub fn deliver_password_update_store(&mut self) -> Result<PhaseResult, PhaseError> {
        let context = self
            .identification_operations
            .get(&self.uid)
            .cloned()
            .ok_or(PhaseError::NoInFlightOperation)?;
        let acknowledgement_set = match &context.state {
            InFlightOperation::ReadyForTerminalStore {
                acknowledgement_set, ..
            } => acknowledgement_set.clone(),
            InFlightOperation::ProviderWriteStarted { .. } => return Err(PhaseError::TerminalStoreNotReady),
            _ => return Err(PhaseError::WrongInFlightOperation),
        };
        let mut trace = context.trace;
        for provider in &mut self.providers {
            if acknowledgement_set.contains(&provider.id) {
                let started = Instant::now();
                provider.store_tentative_identification(&self.uid, &context.record)?;
                provider.mark_identification_status(&self.uid, ReplicaStatus::Active)?;
                trace.record_provider_processing(elapsed_ns(started));
            } else {
                provider.mark_identification_status(&self.uid, ReplicaStatus::Stale)?;
            }
        }
        trace.push(MessageEvent {
            stage_id: next_stage_id(&trace),
            stage: ProtocolStage::OneWayProviderStore,
            sender_role: SenderRole::User,
            receiver_role: ReceiverRole::Provider,
            recipient_count: acknowledgement_set.len(),
            request_bytes: encode_roupspa_identification_record(
                &self.uid,
                &context.record.cid,
                context.record.ctrid,
            )
            .len(),
            response_bytes: 0,
            wait_policy: WaitPolicy::OneWayDeliveryBound,
            acknowledgements: 0,
        });
        let exact = exact_identification_tuple(&self.uid, &context.record);
        self.password = context.new_password;
        self.identification_operations.remove(&self.uid);
        self.last_trace = trace.clone();
        Ok(PhaseResult::Completed {
            acknowledgements: acknowledgement_set.len(),
            record_digest: digest_bytes(&exact),
            decision: None,
            trace,
        })
    }

    pub fn password_update(&mut self) -> PhaseResult {
        let mut rng = self.operation_rng(b"password-update");
        self.password_update_with_rng(&mut rng)
    }

    pub fn password_update_with_rng(&mut self, rng: &mut impl RngCore) -> PhaseResult {
        if let Err(error) = self.begin_password_update_with_rng(rng) {
            return PhaseResult::Aborted {
                error,
                trace: self.last_trace.clone(),
            };
        }
        let indices = self.reachable_indices();
        match self.attempt_password_update_write(&indices) {
            Ok(PhaseResult::ReadyForTerminalStore { .. }) => self
                .deliver_password_update_store()
                .unwrap_or_else(|error| PhaseResult::Aborted {
                    error,
                    trace: self.last_trace.clone(),
                }),
            Ok(result) => result,
            Err(error) => PhaseResult::Aborted {
                error,
                trace: self.last_trace.clone(),
            },
        }
    }

    pub fn any_account_family(&self) -> Option<AccountFamilyKey> {
        self.providers
            .iter()
            .flat_map(|provider| provider.accounts.keys())
            .find(|key| key.uid == self.uid)
            .cloned()
    }

    pub fn provider_share_bytes(&self) -> Vec<Option<[u8; 32]>> {
        self.providers
            .iter()
            .map(|provider| provider.share(&self.uid).map(Scalar::to_bytes))
            .collect()
    }

    pub fn initial_toprf_key_commitment(&self) -> Option<[u8; 32]> {
        self.initial_toprf_key_commitment
    }

    pub fn phase_setup(&mut self) -> PhaseResult {
        self.setup()
    }

    pub fn phase_registration(&mut self) -> PhaseResult {
        self.registration()
    }

    pub fn phase_authentication(&mut self) -> PhaseResult {
        self.authentication()
    }

    pub fn phase_secret_update(&mut self) -> PhaseResult {
        self.secret_update()
    }

    pub fn phase_password_update(&mut self) -> PhaseResult {
        self.password_update()
    }
}

/// Backwards-compatible short name for the former quorum engine.
pub type System = RoUpSpaSystem;
