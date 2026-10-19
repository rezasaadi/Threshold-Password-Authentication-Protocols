use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use crate::crypto::{self, hash_upspa_suid, hash_vinfo, CtBlob};

use super::login_server::{LoginServer, LoginServerError, PendingLsOperation};
use super::messages::{
    account_blob_bytes, encode_uid, identification_blob_bytes, MessageEvent, MessageRole, ProtocolStage,
    ProtocolTrace, UpSpaPasswordUpdateRequest, WaitPolicy, CIPHERID_PT_LEN, CIPHERSP_PT_LEN, RISTRETTO_BYTES,
    SCALAR_BYTES, STATUS_BYTES,
};
use super::provider::{ProviderError, Suid, UpSpaIdentificationResponse, UpSpaProvider};

pub trait Clock {
    fn now(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemClock {
    last: AtomicU64,
}

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        let wall_clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        let mut previous = self.last.load(Ordering::Relaxed);
        loop {
            let next = wall_clock.max(previous.saturating_add(1));
            match self
                .last
                .compare_exchange_weak(previous, next, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(observed) => previous = observed,
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeterministicTestClock {
    value: Arc<AtomicU64>,
}

impl DeterministicTestClock {
    pub fn new(initial: u64) -> Self {
        Self {
            value: Arc::new(AtomicU64::new(initial)),
        }
    }

    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::SeqCst);
    }

    pub fn advance(&self, delta: u64) -> u64 {
        self.value
            .fetch_add(delta, Ordering::SeqCst)
            .saturating_add(delta)
    }
}

impl Default for DeterministicTestClock {
    fn default() -> Self {
        Self::new(1)
    }
}

impl Clock for DeterministicTestClock {
    fn now(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseKind {
    Setup,
    Registration,
    Authentication,
    SecretUpdate,
    PasswordUpdate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseResult {
    Completed,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseOutcome {
    pub phase: PhaseKind,
    pub result: PhaseResult,
    pub trace: ProtocolTrace,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationOutcome {
    pub authenticated: bool,
    pub selected_counter: u64,
    pub trace: ProtocolTrace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentificationRequirement {
    Threshold,
    AllProviders,
}

#[derive(Clone)]
pub struct IdentifiedState {
    pub signing_key: SigningKey,
    pub rsp: [u8; 32],
    pub k0: [u8; 32],
    pub cid: CtBlob<CIPHERID_PT_LEN>,
    pub svk: VerifyingKey,
    pub responding_providers: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PhaseError {
    InvalidParameters {
        nsp: usize,
        tsp: usize,
    },
    OperationInProgress,
    Provider {
        provider_index: u32,
        source: ProviderError,
    },
    LoginServer(LoginServerError),
    InsufficientIdentificationResponses {
        valid: usize,
        required: usize,
    },
    InconsistentIdentificationRecords,
    InvalidToprfContribution,
    RootDecryptionFailed,
    RootVerificationKeyMismatch,
    InsufficientAccountResponses {
        valid: usize,
        required: usize,
    },
    AccountDecryptionFailed,
    AccountCounterOverflow,
    NoFinalizationPending,
    FinalizationIncomplete {
        acknowledgements: usize,
        required: usize,
        login_server_processed: bool,
    },
}

impl fmt::Display for PhaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameters { nsp, tsp } => {
                write!(f, "invalid UpSPA parameters nsp={nsp}, tsp={tsp}")
            }
            Self::OperationInProgress => write!(f, "another state-changing operation is in progress"),
            Self::Provider {
                provider_index,
                source,
            } => write!(f, "provider {provider_index}: {source}"),
            Self::LoginServer(source) => write!(f, "login server: {source}"),
            Self::InsufficientIdentificationResponses { valid, required } => write!(
                f,
                "insufficient valid identification responses: {valid} < {required}"
            ),
            Self::InconsistentIdentificationRecords => {
                write!(f, "identification responses do not identify one valid root")
            }
            Self::InvalidToprfContribution => write!(f, "invalid TOPRF contribution"),
            Self::RootDecryptionFailed => write!(f, "identification ciphertext did not decrypt"),
            Self::RootVerificationKeyMismatch => {
                write!(f, "identification plaintext and public verification key disagree")
            }
            Self::InsufficientAccountResponses { valid, required } => {
                write!(f, "insufficient valid account responses: {valid} < {required}")
            }
            Self::AccountDecryptionFailed => write!(f, "account ciphertext did not decrypt"),
            Self::AccountCounterOverflow => write!(f, "account counter overflow"),
            Self::NoFinalizationPending => write!(f, "no retained finalization exists for this user"),
            Self::FinalizationIncomplete {
                acknowledgements,
                required,
                login_server_processed,
            } => write!(
                f,
                "terminal step incomplete: {acknowledgements}/{required} provider acknowledgements, login-server processed={login_server_processed}"
            ),
        }
    }
}

impl std::error::Error for PhaseError {}

pub struct IdentificationOutcome {
    pub state: IdentifiedState,
    pub trace: ProtocolTrace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalAction {
    Store,
    Discard,
}

#[derive(Clone)]
enum FinalizationPayload {
    Account {
        suids: Vec<Suid>,
        account: CtBlob<CIPHERSP_PT_LEN>,
        login_server_operation: PendingLsOperation,
        secret_update: bool,
    },
    PasswordUpdate {
        requests: Vec<UpSpaPasswordUpdateRequest>,
    },
}

#[derive(Clone)]
struct PendingFinalization {
    phase: PhaseKind,
    action: TerminalAction,
    provider_positions: Vec<usize>,
    acknowledged_positions: HashSet<usize>,
    login_server_required: bool,
    login_server_processed: bool,
    payload: FinalizationPayload,
    trace: ProtocolTrace,
    stage_id: u32,
    original_error: Option<PhaseError>,
}

pub struct UpSpaSystem<C: Clock = SystemClock> {
    nsp: usize,
    tsp: usize,
    pub providers: Vec<UpSpaProvider>,
    pub login_server: LoginServer,
    rng: ChaCha20Rng,
    clock: C,
    active_operations: HashSet<Vec<u8>>,
    pending_finalizations: HashMap<Vec<u8>, PendingFinalization>,
    last_trace: ProtocolTrace,
}

impl UpSpaSystem<SystemClock> {
    pub fn new(nsp: usize, tsp: usize) -> Result<Self, PhaseError> {
        let clock = SystemClock::default();
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&clock.now().to_le_bytes());
        seed[8..16].copy_from_slice(&(nsp as u64).to_le_bytes());
        seed[16..24].copy_from_slice(&(tsp as u64).to_le_bytes());
        Self::with_seed_and_clock(nsp, tsp, seed, clock)
    }
}

impl<C: Clock> UpSpaSystem<C> {
    pub fn with_seed_and_clock(nsp: usize, tsp: usize, seed: [u8; 32], clock: C) -> Result<Self, PhaseError> {
        if nsp == 0 || tsp == 0 || tsp > nsp || nsp > u32::MAX as usize {
            return Err(PhaseError::InvalidParameters { nsp, tsp });
        }
        let providers = (1..=nsp).map(|index| UpSpaProvider::new(index as u32)).collect();
        Ok(Self {
            nsp,
            tsp,
            providers,
            login_server: LoginServer::new(),
            rng: ChaCha20Rng::from_seed(seed),
            clock,
            active_operations: HashSet::new(),
            pending_finalizations: HashMap::new(),
            last_trace: ProtocolTrace::default(),
        })
    }

    pub fn nsp(&self) -> usize {
        self.nsp
    }

    pub fn tsp(&self) -> usize {
        self.tsp
    }

    pub fn clock(&self) -> &C {
        &self.clock
    }

    pub fn last_trace(&self) -> &ProtocolTrace {
        &self.last_trace
    }

    pub fn provider(&self, provider_index: u32) -> Option<&UpSpaProvider> {
        provider_index
            .checked_sub(1)
            .and_then(|index| self.providers.get(index as usize))
    }

    pub fn provider_mut(&mut self, provider_index: u32) -> Option<&mut UpSpaProvider> {
        provider_index
            .checked_sub(1)
            .and_then(|index| self.providers.get_mut(index as usize))
    }

    pub fn set_provider_reachable(&mut self, provider_index: u32, reachable: bool) -> Result<(), PhaseError> {
        let provider = self
            .provider_mut(provider_index)
            .ok_or_else(|| PhaseError::Provider {
                provider_index,
                source: ProviderError::UnknownUser,
            })?;
        provider.set_reachable(reachable);
        Ok(())
    }

    pub fn setup(&mut self, uid: &[u8], password: &[u8]) -> Result<PhaseOutcome, PhaseError> {
        self.acquire_operation(uid)?;
        let result = self.setup_inner(uid, password);
        self.release_if_resolved(uid);
        result
    }

    fn setup_inner(&mut self, uid: &[u8], password: &[u8]) -> Result<PhaseOutcome, PhaseError> {
        let mut trace = ProtocolTrace::default();
        for provider in &self.providers {
            let started = Instant::now();
            let result = provider.can_setup(uid);
            trace.record_processing(MessageRole::Provider, elapsed_ns(started));
            result.map_err(|source| PhaseError::Provider {
                provider_index: provider.provider_index(),
                source,
            })?;
        }

        let mut rsp = [0u8; 32];
        self.rng.fill_bytes(&mut rsp);
        let (master_key, shares) = crypto::toprf_gen(self.nsp, self.tsp, &mut self.rng);
        let signing_key = SigningKey::generate(&mut self.rng);
        let svk = signing_key.verifying_key();
        let mut k0 = [0u8; 32];
        self.rng.fill_bytes(&mut k0);
        let root_plaintext = encode_root_plaintext(&signing_key, &rsp, &k0);
        let fk = evaluate_full_toprf(password, master_key);
        let cid = crypto::xchacha_encrypt_detached(&fk, &cipherid_aad(uid), &root_plaintext, &mut self.rng);

        for (provider, (_, share)) in self.providers.iter_mut().zip(shares) {
            let started = Instant::now();
            let result = provider.setup(uid.to_vec(), svk, cid.clone(), share);
            trace.record_processing(MessageRole::Provider, elapsed_ns(started));
            result.map_err(|source| PhaseError::Provider {
                provider_index: provider.provider_index(),
                source,
            })?;
        }

        trace.push(MessageEvent {
            stage_id: 1,
            stage: ProtocolStage::Setup,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::Provider,
            recipient_count: self.nsp,
            request_bytes: encode_uid(uid).len() + 32 + identification_blob_bytes() + SCALAR_BYTES,
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::AllResponses,
        });
        Ok(self.completed(PhaseKind::Setup, trace))
    }

    pub fn identify(
        &mut self,
        uid: &[u8],
        password: &[u8],
        requirement: IdentificationRequirement,
    ) -> Result<IdentificationOutcome, PhaseError> {
        if self.active_operations.contains(uid) {
            return Err(PhaseError::OperationInProgress);
        }
        let mut trace = ProtocolTrace::default();
        let state = self.identify_into_trace(uid, password, requirement, &mut trace, 1)?;
        self.last_trace = trace.clone();
        Ok(IdentificationOutcome { state, trace })
    }

    fn identify_into_trace(
        &mut self,
        uid: &[u8],
        password: &[u8],
        requirement: IdentificationRequirement,
        trace: &mut ProtocolTrace,
        stage_id: u32,
    ) -> Result<IdentifiedState, PhaseError> {
        let contacted_positions = match requirement {
            IdentificationRequirement::AllProviders => (0..self.nsp).collect::<Vec<_>>(),
            IdentificationRequirement::Threshold => self
                .providers
                .iter()
                .enumerate()
                .filter(|(_, provider)| provider.is_reachable())
                .take(self.tsp)
                .map(|(position, _)| position)
                .collect::<Vec<_>>(),
        };
        let contribution_positions = contacted_positions
            .iter()
            .copied()
            .take(self.tsp)
            .collect::<HashSet<_>>();
        push_identification_events(
            trace,
            stage_id,
            uid,
            contacted_positions.len(),
            self.tsp,
            requirement,
        );

        let r = crypto::random_scalar(&mut self.rng);
        let blinded = (crypto::hash_to_point(password) * r).compress().to_bytes();
        let mut responses: Vec<(usize, UpSpaIdentificationResponse)> = Vec::new();
        for position in contacted_positions {
            let provider = &self.providers[position];
            let started = Instant::now();
            let response = provider.identification_response(
                uid,
                contribution_positions.contains(&position).then_some(&blinded),
            );
            trace.record_processing(MessageRole::Provider, elapsed_ns(started));
            if let Ok(response) = response {
                responses.push((position, response));
            }
        }

        let required = match requirement {
            IdentificationRequirement::Threshold => self.tsp,
            IdentificationRequirement::AllProviders => self.nsp,
        };
        if responses.len() < required {
            return self.fail_with_trace(
                trace,
                PhaseError::InsufficientIdentificationResponses {
                    valid: responses.len(),
                    required,
                },
            );
        }
        if matches!(requirement, IdentificationRequirement::AllProviders) && responses.len() != self.nsp {
            return self.fail_with_trace(
                trace,
                PhaseError::InsufficientIdentificationResponses {
                    valid: responses.len(),
                    required: self.nsp,
                },
            );
        }

        let mut groups: Vec<Vec<(usize, UpSpaIdentificationResponse)>> = Vec::new();
        for response in responses {
            if let Some(group) = groups
                .iter_mut()
                .find(|group| group[0].1.svk == response.1.svk && group[0].1.cid == response.1.cid)
            {
                group.push(response);
            } else {
                groups.push(vec![response]);
            }
        }
        let mut eligible = groups
            .into_iter()
            .filter(|group| group.len() >= required)
            .collect::<Vec<_>>();
        if eligible.len() != 1 {
            return self.fail_with_trace(trace, PhaseError::InconsistentIdentificationRecords);
        }
        let group = eligible.pop().unwrap();
        if matches!(requirement, IdentificationRequirement::AllProviders) && group.len() != self.nsp {
            return self.fail_with_trace(trace, PhaseError::InconsistentIdentificationRecords);
        }

        let mut ids = Vec::with_capacity(self.tsp);
        let mut partials = Vec::with_capacity(self.tsp);
        for (_, response) in group
            .iter()
            .filter(|(_, response)| response.toprf_contribution.is_some())
        {
            let contribution = response
                .toprf_contribution
                .ok_or(PhaseError::InvalidToprfContribution)?;
            let point = CompressedRistretto(contribution)
                .decompress()
                .ok_or(PhaseError::InvalidToprfContribution)?;
            ids.push(response.provider_index);
            partials.push(point);
            if ids.len() == self.tsp {
                break;
            }
        }
        if partials.len() < self.tsp {
            return self.fail_with_trace(trace, PhaseError::InvalidToprfContribution);
        }
        let lambdas = crypto::lagrange_coeffs_at_zero(&ids);
        let fk = crypto::toprf_client_eval_from_partials(password, r, &partials, &lambdas);
        let representative = &group[0].1;
        let plaintext = crypto::xchacha_decrypt_detached(&fk, &cipherid_aad(uid), &representative.cid)
            .map_err(|_| PhaseError::RootDecryptionFailed)?;
        let (signing_key, rsp, k0) = decode_root_plaintext(&plaintext);
        if signing_key.verifying_key() != representative.svk {
            return self.fail_with_trace(trace, PhaseError::RootVerificationKeyMismatch);
        }

        Ok(IdentifiedState {
            signing_key,
            rsp,
            k0,
            cid: representative.cid.clone(),
            svk: representative.svk,
            responding_providers: group
                .iter()
                .map(|(_, response)| response.provider_index)
                .collect(),
        })
    }

    pub fn registration(
        &mut self,
        uid: &[u8],
        password: &[u8],
        lsj: &[u8],
    ) -> Result<PhaseOutcome, PhaseError> {
        self.acquire_operation(uid)?;
        let result = self.registration_inner(uid, password, lsj);
        self.release_if_resolved(uid);
        result
    }

    fn registration_inner(
        &mut self,
        uid: &[u8],
        password: &[u8],
        lsj: &[u8],
    ) -> Result<PhaseOutcome, PhaseError> {
        let mut trace = ProtocolTrace::default();
        let state = self.identify_into_trace(
            uid,
            password,
            IdentificationRequirement::AllProviders,
            &mut trace,
            1,
        )?;
        let mut rlsj = [0u8; 32];
        self.rng.fill_bytes(&mut rlsj);
        let account = encrypt_account(&state.k0, uid, rlsj, 0, &mut self.rng);
        let vinfo = hash_vinfo(&rlsj, lsj);
        let suids = self
            .providers
            .iter()
            .map(|provider| hash_upspa_suid(&state.rsp, lsj, provider.provider_index()))
            .collect::<Vec<_>>();
        push_parallel_prepare_events(&mut trace, 2, uid, self.nsp, false);

        let mut accepted = Vec::new();
        let mut first_error = None;
        for (position, (provider, suid)) in self.providers.iter_mut().zip(&suids).enumerate() {
            let started = Instant::now();
            let response = provider.prepare_registration(*suid, account.clone());
            trace.record_processing(MessageRole::Provider, elapsed_ns(started));
            match response {
                Ok(_) => accepted.push(position),
                Err(source) if first_error.is_none() => {
                    first_error = Some(PhaseError::Provider {
                        provider_index: provider.provider_index(),
                        source,
                    });
                }
                Err(_) => {}
            }
        }
        let ls_operation = PendingLsOperation::Registration { vinfo };
        let started = Instant::now();
        let ls_response = self.login_server.prepare_registration(uid.to_vec(), vinfo);
        trace.record_processing(MessageRole::LoginServer, elapsed_ns(started));
        let ls_accepted = match ls_response {
            Ok(_) => true,
            Err(source) => {
                if first_error.is_none() {
                    first_error = Some(PhaseError::LoginServer(source));
                }
                false
            }
        };

        if let Some(error) = first_error {
            return self.run_finalization(
                uid,
                PendingFinalization {
                    phase: PhaseKind::Registration,
                    action: TerminalAction::Discard,
                    provider_positions: accepted,
                    acknowledged_positions: HashSet::new(),
                    login_server_required: ls_accepted,
                    login_server_processed: false,
                    payload: FinalizationPayload::Account {
                        suids,
                        account,
                        login_server_operation: ls_operation,
                        secret_update: false,
                    },
                    trace,
                    stage_id: 3,
                    original_error: Some(error),
                },
            );
        }

        self.run_finalization(
            uid,
            PendingFinalization {
                phase: PhaseKind::Registration,
                action: TerminalAction::Store,
                provider_positions: (0..self.nsp).collect(),
                acknowledged_positions: HashSet::new(),
                login_server_required: true,
                login_server_processed: false,
                payload: FinalizationPayload::Account {
                    suids,
                    account,
                    login_server_operation: ls_operation,
                    secret_update: false,
                },
                trace,
                stage_id: 3,
                original_error: None,
            },
        )
    }

    pub fn authentication(
        &mut self,
        uid: &[u8],
        password: &[u8],
        lsj: &[u8],
    ) -> Result<AuthenticationOutcome, PhaseError> {
        if self.active_operations.contains(uid) {
            return Err(PhaseError::OperationInProgress);
        }
        let mut trace = ProtocolTrace::default();
        let state =
            self.identify_into_trace(uid, password, IdentificationRequirement::Threshold, &mut trace, 1)?;
        let reachable = self
            .providers
            .iter()
            .filter(|provider| provider.is_reachable())
            .count();
        trace.push(MessageEvent {
            stage_id: 2,
            stage: ProtocolStage::AccountRead,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::Provider,
            recipient_count: reachable,
            request_bytes: 32,
            response_bytes: STATUS_BYTES + account_blob_bytes(),
            wait_policy: WaitPolicy::Threshold(self.tsp),
        });

        let mut candidates = Vec::new();
        for provider in &self.providers {
            let suid = hash_upspa_suid(&state.rsp, lsj, provider.provider_index());
            let started = Instant::now();
            let response = provider.read_account(&suid);
            trace.record_processing(MessageRole::Provider, elapsed_ns(started));
            if let Ok(Some(blob)) = response {
                if let Ok((rlsj, counter)) = decrypt_account(&state.k0, uid, &blob) {
                    candidates.push((counter, rlsj));
                }
            }
        }
        if candidates.len() < self.tsp {
            return self.fail_with_trace(
                &trace,
                PhaseError::InsufficientAccountResponses {
                    valid: candidates.len(),
                    required: self.tsp,
                },
            );
        }
        candidates.sort_by_key(|(counter, _)| *counter);
        let (selected_counter, rlsj) = candidates.last().copied().unwrap();
        let vinfo = hash_vinfo(&rlsj, lsj);
        trace.push(MessageEvent {
            stage_id: 3,
            stage: ProtocolStage::LoginServerAuthentication,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::LoginServer,
            recipient_count: 1,
            request_bytes: encode_uid(uid).len() + 32,
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::AllResponses,
        });
        let started = Instant::now();
        let authenticated = self.login_server.authenticate(uid, &vinfo);
        trace.record_processing(MessageRole::LoginServer, elapsed_ns(started));
        let authenticated = authenticated.map_err(PhaseError::LoginServer)?;
        self.last_trace = trace.clone();
        Ok(AuthenticationOutcome {
            authenticated,
            selected_counter,
            trace,
        })
    }

    pub fn secret_update(
        &mut self,
        uid: &[u8],
        password: &[u8],
        lsj: &[u8],
    ) -> Result<PhaseOutcome, PhaseError> {
        self.acquire_operation(uid)?;
        let result = self.secret_update_inner(uid, password, lsj);
        self.release_if_resolved(uid);
        result
    }

    fn secret_update_inner(
        &mut self,
        uid: &[u8],
        password: &[u8],
        lsj: &[u8],
    ) -> Result<PhaseOutcome, PhaseError> {
        let mut trace = ProtocolTrace::default();
        let state = self.identify_into_trace(
            uid,
            password,
            IdentificationRequirement::AllProviders,
            &mut trace,
            1,
        )?;
        trace.push(MessageEvent {
            stage_id: 2,
            stage: ProtocolStage::AccountRead,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::Provider,
            recipient_count: self.nsp,
            request_bytes: 32,
            response_bytes: STATUS_BYTES + account_blob_bytes(),
            wait_policy: WaitPolicy::AllResponses,
        });
        let suids = self
            .providers
            .iter()
            .map(|provider| hash_upspa_suid(&state.rsp, lsj, provider.provider_index()))
            .collect::<Vec<_>>();
        let mut current = Vec::with_capacity(self.nsp);
        for (provider, suid) in self.providers.iter().zip(&suids) {
            let started = Instant::now();
            let response = provider.read_account(suid);
            trace.record_processing(MessageRole::Provider, elapsed_ns(started));
            let blob = response
                .map_err(|source| PhaseError::Provider {
                    provider_index: provider.provider_index(),
                    source,
                })?
                .ok_or(PhaseError::InsufficientAccountResponses {
                    valid: current.len(),
                    required: self.nsp,
                })?;
            let decoded =
                decrypt_account(&state.k0, uid, &blob).map_err(|_| PhaseError::AccountDecryptionFailed)?;
            current.push(decoded);
        }
        current.sort_by_key(|(_, counter)| *counter);
        let (old_rlsj, old_counter) = current.last().copied().unwrap();
        let old_vinfo = hash_vinfo(&old_rlsj, lsj);
        let new_counter = old_counter
            .checked_add(1)
            .ok_or(PhaseError::AccountCounterOverflow)?;
        let mut new_rlsj = [0u8; 32];
        self.rng.fill_bytes(&mut new_rlsj);
        let account = encrypt_account(&state.k0, uid, new_rlsj, new_counter, &mut self.rng);
        let new_vinfo = hash_vinfo(&new_rlsj, lsj);
        push_parallel_prepare_events(&mut trace, 3, uid, self.nsp, true);

        let mut accepted = Vec::new();
        let mut first_error = None;
        for (position, (provider, suid)) in self.providers.iter_mut().zip(&suids).enumerate() {
            let started = Instant::now();
            let response = provider.prepare_secret_update(*suid, account.clone());
            trace.record_processing(MessageRole::Provider, elapsed_ns(started));
            match response {
                Ok(_) => accepted.push(position),
                Err(source) if first_error.is_none() => {
                    first_error = Some(PhaseError::Provider {
                        provider_index: provider.provider_index(),
                        source,
                    });
                }
                Err(_) => {}
            }
        }
        let ls_operation = PendingLsOperation::SecretUpdate { old_vinfo, new_vinfo };
        let started = Instant::now();
        let ls_response = self
            .login_server
            .prepare_secret_update(uid.to_vec(), old_vinfo, new_vinfo);
        trace.record_processing(MessageRole::LoginServer, elapsed_ns(started));
        let ls_accepted = match ls_response {
            Ok(_) => true,
            Err(source) => {
                if first_error.is_none() {
                    first_error = Some(PhaseError::LoginServer(source));
                }
                false
            }
        };
        if let Some(error) = first_error {
            return self.run_finalization(
                uid,
                PendingFinalization {
                    phase: PhaseKind::SecretUpdate,
                    action: TerminalAction::Discard,
                    provider_positions: accepted,
                    acknowledged_positions: HashSet::new(),
                    login_server_required: ls_accepted,
                    login_server_processed: false,
                    payload: FinalizationPayload::Account {
                        suids,
                        account,
                        login_server_operation: ls_operation,
                        secret_update: true,
                    },
                    trace,
                    stage_id: 4,
                    original_error: Some(error),
                },
            );
        }

        self.run_finalization(
            uid,
            PendingFinalization {
                phase: PhaseKind::SecretUpdate,
                action: TerminalAction::Store,
                provider_positions: (0..self.nsp).collect(),
                acknowledged_positions: HashSet::new(),
                login_server_required: true,
                login_server_processed: false,
                payload: FinalizationPayload::Account {
                    suids,
                    account,
                    login_server_operation: ls_operation,
                    secret_update: true,
                },
                trace,
                stage_id: 4,
                original_error: None,
            },
        )
    }

    pub fn password_update(
        &mut self,
        uid: &[u8],
        old_password: &[u8],
        new_password: &[u8],
    ) -> Result<PhaseOutcome, PhaseError> {
        self.acquire_operation(uid)?;
        let result = self.password_update_inner(uid, old_password, new_password);
        self.release_if_resolved(uid);
        result
    }

    fn password_update_inner(
        &mut self,
        uid: &[u8],
        old_password: &[u8],
        new_password: &[u8],
    ) -> Result<PhaseOutcome, PhaseError> {
        let mut trace = ProtocolTrace::default();
        let state = self.identify_into_trace(
            uid,
            old_password,
            IdentificationRequirement::AllProviders,
            &mut trace,
            1,
        )?;
        let (new_master_key, new_shares) = crypto::toprf_gen(self.nsp, self.tsp, &mut self.rng);
        let new_fk = evaluate_full_toprf(new_password, new_master_key);
        let root_plaintext = encode_root_plaintext(&state.signing_key, &state.rsp, &state.k0);
        let cidnew =
            crypto::xchacha_encrypt_detached(&new_fk, &cipherid_aad(uid), &root_plaintext, &mut self.rng);
        let mut requests = Vec::with_capacity(self.nsp);
        for (provider, (_, share_new)) in self.providers.iter().zip(new_shares) {
            let time = self.clock.now();
            let provider_index = provider.provider_index();
            let signed_bytes =
                super::messages::encode_upspa_password_update(uid, &cidnew, &share_new, time, provider_index);
            requests.push(UpSpaPasswordUpdateRequest {
                uid: uid.to_vec(),
                cidnew: cidnew.clone(),
                share_new,
                time,
                provider_index,
                signature: state.signing_key.sign(&signed_bytes),
            });
        }
        let request_bytes = requests
            .first()
            .map(UpSpaPasswordUpdateRequest::encoded_len)
            .unwrap_or(0);
        trace.push(MessageEvent {
            stage_id: 2,
            stage: ProtocolStage::AllProviderPendingWrites,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::Provider,
            recipient_count: self.nsp,
            request_bytes,
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::AllResponses,
        });

        let mut accepted = Vec::new();
        let mut first_error = None;
        for (position, (provider, request)) in self.providers.iter_mut().zip(&requests).enumerate() {
            let started = Instant::now();
            let response = provider.prepare_password_update(request);
            trace.record_processing(MessageRole::Provider, elapsed_ns(started));
            match response {
                Ok(_) => accepted.push(position),
                Err(source) if first_error.is_none() => {
                    first_error = Some(PhaseError::Provider {
                        provider_index: provider.provider_index(),
                        source,
                    });
                }
                Err(_) => {}
            }
        }
        if let Some(error) = first_error {
            return self.run_finalization(
                uid,
                PendingFinalization {
                    phase: PhaseKind::PasswordUpdate,
                    action: TerminalAction::Discard,
                    provider_positions: accepted,
                    acknowledged_positions: HashSet::new(),
                    login_server_required: false,
                    login_server_processed: false,
                    payload: FinalizationPayload::PasswordUpdate { requests },
                    trace,
                    stage_id: 3,
                    original_error: Some(error),
                },
            );
        }

        self.run_finalization(
            uid,
            PendingFinalization {
                phase: PhaseKind::PasswordUpdate,
                action: TerminalAction::Store,
                provider_positions: (0..self.nsp).collect(),
                acknowledged_positions: HashSet::new(),
                login_server_required: false,
                login_server_processed: false,
                payload: FinalizationPayload::PasswordUpdate { requests },
                trace,
                stage_id: 3,
                original_error: None,
            },
        )
    }

    /// Retries exactly the retained terminal tuple for a partially finalized
    /// phase.  No new state-changing phase for this user can start until this
    /// method obtains every required provider acknowledgement (and processes
    /// the matching login-server terminal action when applicable).
    pub fn retry_finalization(&mut self, uid: &[u8]) -> Result<PhaseOutcome, PhaseError> {
        let pending = self
            .pending_finalizations
            .remove(uid)
            .ok_or(PhaseError::NoFinalizationPending)?;
        let result = self.run_finalization(uid, pending);
        self.release_if_resolved(uid);
        result
    }

    pub fn has_pending_finalization(&self, uid: &[u8]) -> bool {
        self.pending_finalizations.contains_key(uid)
    }

    fn run_finalization(
        &mut self,
        uid: &[u8],
        mut pending: PendingFinalization,
    ) -> Result<PhaseOutcome, PhaseError> {
        let positions = pending
            .provider_positions
            .iter()
            .copied()
            .filter(|position| !pending.acknowledged_positions.contains(position))
            .collect::<Vec<_>>();
        let mut acknowledged_this_attempt = 0;
        for position in &positions {
            let started = Instant::now();
            let response = match &pending.payload {
                FinalizationPayload::Account { suids, account, .. } => match pending.action {
                    TerminalAction::Store => {
                        self.providers[*position].store_account(&suids[*position], account)
                    }
                    TerminalAction::Discard => {
                        self.providers[*position].discard_account(&suids[*position], account)
                    }
                },
                FinalizationPayload::PasswordUpdate { requests } => match pending.action {
                    TerminalAction::Store => {
                        self.providers[*position].store_password_update(&requests[*position])
                    }
                    TerminalAction::Discard => {
                        self.providers[*position].discard_password_update(&requests[*position])
                    }
                },
            };
            pending
                .trace
                .record_processing(MessageRole::Provider, elapsed_ns(started));
            if response.is_ok() {
                pending.acknowledged_positions.insert(*position);
                acknowledged_this_attempt += 1;
            }
        }

        let login_server_attempted = pending.login_server_required && !pending.login_server_processed;
        if login_server_attempted {
            let FinalizationPayload::Account {
                login_server_operation,
                ..
            } = &pending.payload
            else {
                unreachable!("password update never has a login-server terminal step")
            };
            let started = Instant::now();
            let response = match pending.action {
                TerminalAction::Store => self.login_server.store(uid, login_server_operation),
                TerminalAction::Discard => self.login_server.discard(uid, login_server_operation),
            };
            pending
                .trace
                .record_processing(MessageRole::LoginServer, elapsed_ns(started));
            if response.is_ok() {
                pending.login_server_processed = true;
            }
        }

        match &pending.payload {
            FinalizationPayload::Account { secret_update, .. } => push_parallel_terminal_attempt(
                &mut pending.trace,
                pending.stage_id,
                uid,
                positions.len(),
                acknowledged_this_attempt,
                login_server_attempted,
                *secret_update,
            ),
            FinalizationPayload::PasswordUpdate { requests } => push_password_terminal_attempt(
                &mut pending.trace,
                pending.stage_id,
                positions.len(),
                acknowledged_this_attempt,
                requests
                    .first()
                    .map(UpSpaPasswordUpdateRequest::encoded_len)
                    .unwrap_or(0),
            ),
        }

        let provider_acknowledgements = pending.acknowledged_positions.len();
        let required = pending.provider_positions.len();
        let login_server_complete = !pending.login_server_required || pending.login_server_processed;
        if provider_acknowledgements == required && login_server_complete {
            self.last_trace = pending.trace.clone();
            if let Some(error) = pending.original_error {
                Err(error)
            } else {
                Ok(self.completed(pending.phase, pending.trace))
            }
        } else {
            self.last_trace = pending.trace.clone();
            self.pending_finalizations.insert(uid.to_vec(), pending);
            Err(PhaseError::FinalizationIncomplete {
                acknowledgements: provider_acknowledgements,
                required,
                login_server_processed: login_server_complete,
            })
        }
    }

    fn acquire_operation(&mut self, uid: &[u8]) -> Result<(), PhaseError> {
        if self.active_operations.insert(uid.to_vec()) {
            Ok(())
        } else {
            Err(PhaseError::OperationInProgress)
        }
    }

    fn release_operation(&mut self, uid: &[u8]) {
        self.active_operations.remove(uid);
    }

    fn release_if_resolved(&mut self, uid: &[u8]) {
        if !self.pending_finalizations.contains_key(uid) {
            self.release_operation(uid);
        }
    }

    fn completed(&mut self, phase: PhaseKind, trace: ProtocolTrace) -> PhaseOutcome {
        self.last_trace = trace.clone();
        PhaseOutcome {
            phase,
            result: PhaseResult::Completed,
            trace,
        }
    }

    fn fail_with_trace<T>(&mut self, trace: &ProtocolTrace, error: PhaseError) -> Result<T, PhaseError> {
        self.last_trace = trace.clone();
        Err(error)
    }
}

fn evaluate_full_toprf(password: &[u8], master_key: Scalar) -> [u8; 32] {
    let output = crypto::hash_to_point(password) * master_key;
    crypto::oprf_finalize(password, &output)
}

fn cipherid_aad(uid: &[u8]) -> Vec<u8> {
    let mut aad = uid.to_vec();
    aad.extend_from_slice(b"|cipherid");
    aad
}

fn ciphersp_aad(uid: &[u8]) -> Vec<u8> {
    let mut aad = uid.to_vec();
    aad.extend_from_slice(b"|ciphersp");
    aad
}

fn encode_root_plaintext(signing_key: &SigningKey, rsp: &[u8; 32], k0: &[u8; 32]) -> [u8; CIPHERID_PT_LEN] {
    let mut plaintext = [0u8; CIPHERID_PT_LEN];
    plaintext[..32].copy_from_slice(&signing_key.to_bytes());
    plaintext[32..64].copy_from_slice(rsp);
    plaintext[64..96].copy_from_slice(k0);
    plaintext
}

fn decode_root_plaintext(plaintext: &[u8; CIPHERID_PT_LEN]) -> (SigningKey, [u8; 32], [u8; 32]) {
    let mut signing_key = [0u8; 32];
    signing_key.copy_from_slice(&plaintext[..32]);
    let mut rsp = [0u8; 32];
    rsp.copy_from_slice(&plaintext[32..64]);
    let mut k0 = [0u8; 32];
    k0.copy_from_slice(&plaintext[64..96]);
    (SigningKey::from_bytes(&signing_key), rsp, k0)
}

fn encrypt_account(
    k0: &[u8; 32],
    uid: &[u8],
    rlsj: [u8; 32],
    counter: u64,
    rng: &mut impl RngCore,
) -> CtBlob<CIPHERSP_PT_LEN> {
    let mut plaintext = [0u8; CIPHERSP_PT_LEN];
    plaintext[..32].copy_from_slice(&rlsj);
    plaintext[32..40].copy_from_slice(&counter.to_le_bytes());
    crypto::xchacha_encrypt_detached(k0, &ciphersp_aad(uid), &plaintext, rng)
}

fn decrypt_account(k0: &[u8; 32], uid: &[u8], blob: &CtBlob<CIPHERSP_PT_LEN>) -> Result<([u8; 32], u64), ()> {
    let plaintext = crypto::xchacha_decrypt_detached(k0, &ciphersp_aad(uid), blob).map_err(|_| ())?;
    let mut rlsj = [0u8; 32];
    rlsj.copy_from_slice(&plaintext[..32]);
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&plaintext[32..40]);
    Ok((rlsj, u64::from_le_bytes(counter)))
}

fn push_identification_events(
    trace: &mut ProtocolTrace,
    stage_id: u32,
    uid: &[u8],
    recipients: usize,
    threshold: usize,
    requirement: IdentificationRequirement,
) {
    let selected = threshold.min(recipients);
    let wait_policy = match requirement {
        IdentificationRequirement::Threshold => WaitPolicy::Threshold(threshold),
        IdentificationRequirement::AllProviders => WaitPolicy::AllResponses,
    };
    trace.push(MessageEvent {
        stage_id,
        stage: ProtocolStage::Identification,
        sender_role: MessageRole::Client,
        receiver_role: MessageRole::Provider,
        recipient_count: selected,
        request_bytes: encode_uid(uid).len() + RISTRETTO_BYTES,
        response_bytes: STATUS_BYTES + 32 + identification_blob_bytes() + RISTRETTO_BYTES,
        wait_policy,
    });
    if recipients > selected {
        trace.push(MessageEvent {
            stage_id,
            stage: ProtocolStage::Identification,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::Provider,
            recipient_count: recipients - selected,
            request_bytes: encode_uid(uid).len(),
            response_bytes: STATUS_BYTES + 32 + identification_blob_bytes(),
            wait_policy,
        });
    }
}

fn push_parallel_prepare_events(
    trace: &mut ProtocolTrace,
    stage_id: u32,
    uid: &[u8],
    nsp: usize,
    secret_update: bool,
) {
    trace.push(MessageEvent {
        stage_id,
        stage: ProtocolStage::ParallelProviderAndLsPrepare,
        sender_role: MessageRole::Client,
        receiver_role: MessageRole::Provider,
        recipient_count: nsp,
        request_bytes: 32 + account_blob_bytes(),
        response_bytes: STATUS_BYTES,
        wait_policy: WaitPolicy::AllResponses,
    });
    trace.push(MessageEvent {
        stage_id,
        stage: ProtocolStage::ParallelProviderAndLsPrepare,
        sender_role: MessageRole::Client,
        receiver_role: MessageRole::LoginServer,
        recipient_count: 1,
        request_bytes: encode_uid(uid).len() + if secret_update { 64 } else { 32 },
        response_bytes: STATUS_BYTES,
        wait_policy: WaitPolicy::AllResponses,
    });
}

fn push_parallel_terminal_attempt(
    trace: &mut ProtocolTrace,
    stage_id: u32,
    uid: &[u8],
    attempted_providers: usize,
    acknowledged_providers: usize,
    login_server_attempted: bool,
    secret_update: bool,
) {
    if acknowledged_providers != 0 {
        trace.push(MessageEvent {
            stage_id,
            stage: ProtocolStage::ParallelTerminalAndProviderFinalAcks,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::Provider,
            recipient_count: acknowledged_providers,
            request_bytes: STATUS_BYTES + 32 + account_blob_bytes(),
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::AllResponses,
        });
    }
    let unacknowledged = attempted_providers.saturating_sub(acknowledged_providers);
    if unacknowledged != 0 {
        trace.push(MessageEvent {
            stage_id,
            stage: ProtocolStage::ParallelTerminalAndProviderFinalAcks,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::Provider,
            recipient_count: unacknowledged,
            request_bytes: STATUS_BYTES + 32 + account_blob_bytes(),
            response_bytes: 0,
            wait_policy: WaitPolicy::AllResponses,
        });
    }
    if login_server_attempted {
        trace.push(MessageEvent {
            stage_id,
            stage: ProtocolStage::ParallelTerminalAndProviderFinalAcks,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::LoginServer,
            recipient_count: 1,
            request_bytes: STATUS_BYTES + encode_uid(uid).len() + if secret_update { 64 } else { 32 },
            response_bytes: 0,
            wait_policy: WaitPolicy::OneWayDeliveryBound,
        });
    }
}

fn push_password_terminal_attempt(
    trace: &mut ProtocolTrace,
    stage_id: u32,
    attempted_providers: usize,
    acknowledged_providers: usize,
    request_bytes: usize,
) {
    if acknowledged_providers != 0 {
        trace.push(MessageEvent {
            stage_id,
            stage: ProtocolStage::AllProviderTerminalAcks,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::Provider,
            recipient_count: acknowledged_providers,
            request_bytes: request_bytes + STATUS_BYTES,
            response_bytes: STATUS_BYTES,
            wait_policy: WaitPolicy::AllResponses,
        });
    }
    let unacknowledged = attempted_providers.saturating_sub(acknowledged_providers);
    if unacknowledged != 0 {
        trace.push(MessageEvent {
            stage_id,
            stage: ProtocolStage::AllProviderTerminalAcks,
            sender_role: MessageRole::Client,
            receiver_role: MessageRole::Provider,
            recipient_count: unacknowledged,
            request_bytes: request_bytes + STATUS_BYTES,
            response_bytes: 0,
            wait_policy: WaitPolicy::AllResponses,
        });
    }
}

fn elapsed_ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: &[u8] = b"alice";
    const PASSWORD: &[u8] = b"old password";
    const NEW_PASSWORD: &[u8] = b"new password";
    const LSJ: &[u8] = b"login.example";

    fn system(nsp: usize, tsp: usize) -> UpSpaSystem<DeterministicTestClock> {
        UpSpaSystem::with_seed_and_clock(nsp, tsp, [42; 32], DeterministicTestClock::new(10)).unwrap()
    }

    #[test]
    fn setup_requires_all_and_rejects_duplicates() {
        let mut unavailable = system(3, 2);
        unavailable.set_provider_reachable(3, false).unwrap();
        assert!(unavailable.setup(UID, PASSWORD).is_err());
        assert!(unavailable
            .providers
            .iter()
            .all(|provider| provider.identification_record(UID).is_none()));

        let mut ready = system(3, 2);
        ready.setup(UID, PASSWORD).unwrap();
        assert!(ready.setup(UID, PASSWORD).is_err());
    }

    #[test]
    fn provider_specific_suids_change_with_provider_and_domain() {
        let rsp = [9; 32];
        assert_ne!(
            hash_upspa_suid(&rsp, b"ls-a", 1),
            hash_upspa_suid(&rsp, b"ls-a", 2)
        );
        assert_ne!(
            hash_upspa_suid(&rsp, b"ls-a", 1),
            hash_upspa_suid(&rsp, b"ls-b", 1)
        );
    }

    #[test]
    fn identification_contacts_each_selected_provider_exactly_once() {
        let mut all = system(4, 2);
        all.setup(UID, PASSWORD).unwrap();
        let outcome = all
            .identify(UID, PASSWORD, IdentificationRequirement::AllProviders)
            .unwrap();
        assert_eq!(outcome.trace.stage_order(), vec![ProtocolStage::Identification]);
        assert_eq!(
            outcome
                .trace
                .events
                .iter()
                .map(|event| event.recipient_count)
                .sum::<usize>(),
            4
        );
        assert!(all
            .providers
            .iter()
            .all(|provider| provider.identification_request_count() == 1));

        let mut threshold = system(4, 2);
        threshold.setup(UID, PASSWORD).unwrap();
        threshold.set_provider_reachable(1, false).unwrap();
        let outcome = threshold
            .identify(UID, PASSWORD, IdentificationRequirement::Threshold)
            .unwrap();
        assert_eq!(outcome.trace.events.len(), 1);
        assert_eq!(outcome.trace.events[0].recipient_count, 2);
        assert_eq!(threshold.provider(1).unwrap().identification_request_count(), 0);
        assert_eq!(threshold.provider(2).unwrap().identification_request_count(), 1);
        assert_eq!(threshold.provider(3).unwrap().identification_request_count(), 1);
        assert_eq!(threshold.provider(4).unwrap().identification_request_count(), 0);
    }

    #[test]
    fn complete_phases_mutate_real_provider_and_login_server_state() {
        let mut system = system(3, 2);
        system.setup(UID, PASSWORD).unwrap();
        let registration = system.registration(UID, PASSWORD, LSJ).unwrap();
        assert_eq!(
            registration.trace.stage_order(),
            vec![
                ProtocolStage::Identification,
                ProtocolStage::ParallelProviderAndLsPrepare,
                ProtocolStage::ParallelTerminalAndProviderFinalAcks,
            ]
        );
        let recovered = system
            .identify(UID, PASSWORD, IdentificationRequirement::AllProviders)
            .unwrap()
            .state;
        for provider in &system.providers {
            let suid = hash_upspa_suid(&recovered.rsp, LSJ, provider.provider_index());
            let slot = provider.account_slot(&suid).unwrap();
            assert!(slot.committed.is_some());
            assert!(slot.pending.is_none());
        }
        assert!(system.authentication(UID, PASSWORD, LSJ).unwrap().authenticated);
        let old_vinfo = *system.login_server.current_vinfo(UID).unwrap();
        let update = system.secret_update(UID, PASSWORD, LSJ).unwrap();
        assert_eq!(
            update.trace.stage_order(),
            vec![
                ProtocolStage::Identification,
                ProtocolStage::AccountRead,
                ProtocolStage::ParallelProviderAndLsPrepare,
                ProtocolStage::ParallelTerminalAndProviderFinalAcks,
            ]
        );
        assert_ne!(*system.login_server.current_vinfo(UID).unwrap(), old_vinfo);
        for provider in &system.providers {
            let suid = hash_upspa_suid(&recovered.rsp, LSJ, provider.provider_index());
            let slot = provider.account_slot(&suid).unwrap();
            let (_, counter) = decrypt_account(&recovered.k0, UID, slot.committed.as_ref().unwrap()).unwrap();
            assert_eq!(counter, 1);
            assert!(slot.pending.is_none());
        }
        assert!(system.authentication(UID, PASSWORD, LSJ).unwrap().authenticated);
    }

    #[test]
    fn authentication_uses_any_threshold_but_not_fewer() {
        let mut system = system(4, 2);
        system.setup(UID, PASSWORD).unwrap();
        system.registration(UID, PASSWORD, LSJ).unwrap();
        system.set_provider_reachable(1, false).unwrap();
        system.set_provider_reachable(2, false).unwrap();
        assert!(system.authentication(UID, PASSWORD, LSJ).unwrap().authenticated);
        system.set_provider_reachable(3, false).unwrap();
        assert!(matches!(
            system.authentication(UID, PASSWORD, LSJ),
            Err(PhaseError::InsufficientIdentificationResponses { .. })
        ));
    }

    #[test]
    fn authentication_reports_fewer_than_threshold_valid_account_responses_after_identification() {
        let mut system = system(4, 2);
        system.setup(UID, PASSWORD).unwrap();
        system.registration(UID, PASSWORD, LSJ).unwrap();
        for provider_index in 1..=3 {
            system
                .provider_mut(provider_index)
                .unwrap()
                .set_account_responses_enabled(false);
        }

        assert!(matches!(
            system.authentication(UID, PASSWORD, LSJ),
            Err(PhaseError::InsufficientAccountResponses {
                valid: 1,
                required: 2
            })
        ));
        assert_eq!(
            system.last_trace().stage_order(),
            vec![ProtocolStage::Identification, ProtocolStage::AccountRead]
        );
    }

    #[test]
    fn password_update_rotates_every_share_and_preserves_root_secrets() {
        let mut system = system(3, 2);
        system.setup(UID, PASSWORD).unwrap();
        let before = system
            .identify(UID, PASSWORD, IdentificationRequirement::AllProviders)
            .unwrap()
            .state;
        let old_shares = system
            .providers
            .iter()
            .map(|provider| provider.identification_record(UID).unwrap().share)
            .collect::<Vec<_>>();
        let update = system.password_update(UID, PASSWORD, NEW_PASSWORD).unwrap();
        assert_eq!(
            update.trace.stage_order(),
            vec![
                ProtocolStage::Identification,
                ProtocolStage::AllProviderPendingWrites,
                ProtocolStage::AllProviderTerminalAcks,
            ]
        );
        let after = system
            .identify(UID, NEW_PASSWORD, IdentificationRequirement::AllProviders)
            .unwrap()
            .state;
        let new_shares = system
            .providers
            .iter()
            .map(|provider| provider.identification_record(UID).unwrap().share)
            .collect::<Vec<_>>();
        assert_eq!(before.rsp, after.rsp);
        assert_eq!(before.k0, after.k0);
        assert!(old_shares
            .iter()
            .zip(new_shares.iter())
            .all(|(old, new)| old != new));
        assert!(system
            .identify(UID, PASSWORD, IdentificationRequirement::Threshold)
            .is_err());
    }

    #[test]
    fn failed_registration_prepare_discards_every_matching_pending_record() {
        let mut system = system(3, 2);
        system.setup(UID, PASSWORD).unwrap();
        system
            .login_server
            .prepare_registration(UID.to_vec(), [99; 32])
            .unwrap();
        assert!(system.registration(UID, PASSWORD, LSJ).is_err());
        assert_eq!(
            system
                .last_trace()
                .events
                .iter()
                .filter(|event| {
                    event.stage == ProtocolStage::ParallelTerminalAndProviderFinalAcks
                        && event.receiver_role == MessageRole::LoginServer
                })
                .count(),
            0,
            "LS rejected Prepare, so no LS terminal message may be traced"
        );
        assert_eq!(
            system
                .last_trace()
                .events
                .iter()
                .filter(|event| {
                    event.stage == ProtocolStage::ParallelTerminalAndProviderFinalAcks
                        && event.receiver_role == MessageRole::Provider
                        && event.response_bytes != 0
                })
                .map(|event| event.recipient_count)
                .sum::<usize>(),
            3
        );
        let root = system
            .identify(UID, PASSWORD, IdentificationRequirement::AllProviders)
            .unwrap()
            .state;
        for provider in &system.providers {
            let suid = hash_upspa_suid(&root.rsp, LSJ, provider.provider_index());
            let slot = provider.account_slot(&suid);
            assert!(slot.is_none() || slot.unwrap().committed.is_none());
            assert!(slot.is_none() || slot.unwrap().pending.is_none());
        }
    }

    #[test]
    fn failed_rollback_is_retained_until_every_accepted_provider_acknowledges_discard() {
        let mut system = system(3, 2);
        system.setup(UID, PASSWORD).unwrap();
        system
            .login_server
            .prepare_registration(UID.to_vec(), [99; 32])
            .unwrap();
        system
            .provider_mut(2)
            .unwrap()
            .inject_finalization_failure(super::super::provider::ProviderFinalizationAction::DiscardAccount);

        assert!(matches!(
            system.registration(UID, PASSWORD, LSJ),
            Err(PhaseError::FinalizationIncomplete {
                acknowledgements: 2,
                required: 3,
                ..
            })
        ));
        assert!(system.has_pending_finalization(UID));
        assert!(matches!(
            system.authentication(UID, PASSWORD, LSJ),
            Err(PhaseError::OperationInProgress)
        ));
        assert!(matches!(
            system.retry_finalization(UID),
            Err(PhaseError::LoginServer(LoginServerError::PendingConflict))
        ));
        assert!(!system.has_pending_finalization(UID));

        let root = system
            .identify(UID, PASSWORD, IdentificationRequirement::AllProviders)
            .unwrap()
            .state;
        for provider in &system.providers {
            let suid = hash_upspa_suid(&root.rsp, LSJ, provider.provider_index());
            let slot = provider.account_slot(&suid).unwrap();
            assert!(slot.committed.is_none());
            assert!(slot.pending.is_none());
        }
    }

    #[test]
    fn partial_store_retains_family_and_retries_only_missing_acknowledgement() {
        let mut system = system(3, 2);
        system.setup(UID, PASSWORD).unwrap();
        let root = system
            .identify(UID, PASSWORD, IdentificationRequirement::AllProviders)
            .unwrap()
            .state;
        system
            .provider_mut(2)
            .unwrap()
            .inject_finalization_failure(super::super::provider::ProviderFinalizationAction::StoreAccount);

        assert!(matches!(
            system.registration(UID, PASSWORD, LSJ),
            Err(PhaseError::FinalizationIncomplete {
                acknowledgements: 2,
                required: 3,
                login_server_processed: true,
            })
        ));
        assert!(system.has_pending_finalization(UID));
        assert!(system.login_server.current_vinfo(UID).is_some());
        for provider in &system.providers {
            let suid = hash_upspa_suid(&root.rsp, LSJ, provider.provider_index());
            let slot = provider.account_slot(&suid).unwrap();
            if provider.provider_index() == 2 {
                assert!(slot.committed.is_none());
                assert!(slot.pending.is_some());
            } else {
                assert!(slot.committed.is_some());
                assert!(slot.pending.is_none());
            }
        }
        assert!(matches!(
            system.secret_update(UID, PASSWORD, LSJ),
            Err(PhaseError::OperationInProgress)
        ));

        let completed = system.retry_finalization(UID).unwrap();
        assert_eq!(completed.phase, PhaseKind::Registration);
        assert_eq!(completed.result, PhaseResult::Completed);
        assert!(!system.has_pending_finalization(UID));
        for provider in &system.providers {
            let suid = hash_upspa_suid(&root.rsp, LSJ, provider.provider_index());
            let slot = provider.account_slot(&suid).unwrap();
            assert!(slot.committed.is_some());
            assert!(slot.pending.is_none());
        }
        assert!(system.authentication(UID, PASSWORD, LSJ).unwrap().authenticated);
    }

    #[test]
    fn failed_password_update_discards_only_its_matching_tentative_records() {
        let mut system = system(3, 2);
        system.setup(UID, PASSWORD).unwrap();
        let recovered = system
            .identify(UID, PASSWORD, IdentificationRequirement::AllProviders)
            .unwrap()
            .state;
        let old_records = system
            .providers
            .iter()
            .map(|provider| provider.identification_record(UID).unwrap().clone())
            .collect::<Vec<_>>();

        let unrelated_cid = CtBlob {
            nonce: [1; 24],
            ct: [2; CIPHERID_PT_LEN],
            tag: [3; 16],
        };
        let unrelated_share = Scalar::from(77u64);
        let signed_bytes = super::super::messages::encode_upspa_password_update(
            UID,
            &unrelated_cid,
            &unrelated_share,
            10,
            3,
        );
        let unrelated = UpSpaPasswordUpdateRequest {
            uid: UID.to_vec(),
            cidnew: unrelated_cid,
            share_new: unrelated_share,
            time: 10,
            provider_index: 3,
            signature: recovered.signing_key.sign(&signed_bytes),
        };
        system
            .provider_mut(3)
            .unwrap()
            .prepare_password_update(&unrelated)
            .unwrap();

        assert!(system.password_update(UID, PASSWORD, NEW_PASSWORD).is_err());
        for (position, provider) in system.providers.iter().enumerate() {
            let committed = provider.identification_record(UID).unwrap();
            assert_eq!(committed.cid, old_records[position].cid);
            assert_eq!(committed.share, old_records[position].share);
            if provider.provider_index() < 3 {
                assert!(provider.pending_identification(UID).is_none());
            }
        }
        let pending = system.provider(3).unwrap().pending_identification(UID).unwrap();
        assert_eq!(pending.cidnew, unrelated.cidnew);
        assert_eq!(pending.share_new, unrelated.share_new);
        assert_eq!(pending.time, unrelated.time);
        assert_eq!(pending.provider_index, unrelated.provider_index);
        assert_eq!(pending.signature.to_bytes(), unrelated.signature.to_bytes());
    }
}
