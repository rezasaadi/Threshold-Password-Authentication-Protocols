use crate::crypto::CtBlob;

pub const IDENTIFICATION_PLAINTEXT_LEN: usize = 32 + 32 + 32 + 8;
pub const ACCOUNT_PLAINTEXT_LEN: usize = 32 + 8;
pub const SIGNATURE_BYTES: usize = 64;
pub const VERIFYING_KEY_BYTES: usize = 32;
pub const SHARE_BYTES: usize = 32;
pub const COUNTER_BYTES: usize = 8;
pub const STATUS_BYTES: usize = 1;
pub const RISTRETTO_MESSAGE_BYTES: usize = 32;
pub const IDENTIFICATION_BLOB_BYTES: usize = CtBlob::<IDENTIFICATION_PLAINTEXT_LEN>::ENCODED_LEN;
pub const ACCOUNT_BLOB_BYTES: usize = CtBlob::<ACCOUNT_PLAINTEXT_LEN>::ENCODED_LEN;

pub fn encode_uid(uid: &[u8]) -> Vec<u8> {
    let len = u32::try_from(uid.len()).expect("Uid exceeds the canonical u32 length field");
    let mut out = Vec::with_capacity(4 + uid.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(uid);
    out
}

pub fn encode_roupspa_account_record(
    uid: &[u8],
    suid: &[u8; 32],
    cj: &CtBlob<ACCOUNT_PLAINTEXT_LEN>,
    ctr: u64,
) -> Vec<u8> {
    let mut out = encode_uid(uid);
    out.reserve(32 + ACCOUNT_BLOB_BYTES + COUNTER_BYTES);
    out.extend_from_slice(suid);
    out.extend_from_slice(&cj.nonce);
    out.extend_from_slice(&cj.ct);
    out.extend_from_slice(&cj.tag);
    out.extend_from_slice(&ctr.to_le_bytes());
    out
}

pub fn encode_roupspa_identification_record(
    uid: &[u8],
    cidnew: &CtBlob<IDENTIFICATION_PLAINTEXT_LEN>,
    ctrid: u64,
) -> Vec<u8> {
    let mut out = encode_uid(uid);
    out.reserve(IDENTIFICATION_BLOB_BYTES + COUNTER_BYTES);
    out.extend_from_slice(&cidnew.nonce);
    out.extend_from_slice(&cidnew.ct);
    out.extend_from_slice(&cidnew.tag);
    out.extend_from_slice(&ctrid.to_le_bytes());
    out
}

pub fn account_write_request_bytes(uid: &[u8]) -> usize {
    encode_uid(uid).len() + 32 + ACCOUNT_BLOB_BYTES + COUNTER_BYTES + SIGNATURE_BYTES
}

pub fn identification_write_request_bytes(uid: &[u8]) -> usize {
    encode_uid(uid).len() + IDENTIFICATION_BLOB_BYTES + COUNTER_BYTES + SIGNATURE_BYTES
}

pub fn setup_write_request_bytes(uid: &[u8]) -> usize {
    encode_uid(uid).len() + VERIFYING_KEY_BYTES + IDENTIFICATION_BLOB_BYTES + SHARE_BYTES
}

pub fn identification_request_bytes(uid: &[u8]) -> usize {
    encode_uid(uid).len() + RISTRETTO_MESSAGE_BYTES
}

pub fn identification_response_bytes(has_signature: bool, includes_toprf: bool) -> usize {
    STATUS_BYTES
        + VERIFYING_KEY_BYTES
        + IDENTIFICATION_BLOB_BYTES
        + COUNTER_BYTES
        + usize::from(has_signature) * SIGNATURE_BYTES
        + usize::from(includes_toprf) * RISTRETTO_MESSAGE_BYTES
}

pub fn account_read_request_bytes(uid: &[u8]) -> usize {
    encode_uid(uid).len() + 32
}

pub fn account_read_response_bytes() -> usize {
    STATUS_BYTES + ACCOUNT_BLOB_BYTES + COUNTER_BYTES + SIGNATURE_BYTES
}

pub fn login_server_registration_bytes(uid: &[u8]) -> usize {
    encode_uid(uid).len() + 32
}

pub fn login_server_update_bytes(uid: &[u8]) -> usize {
    encode_uid(uid).len() + 32 + 32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtocolStage {
    SetupWrite,
    Identification,
    IdentificationOld,
    ToprfNewSameShares,
    AccountRead,
    LsPrepare,
    ProviderQuorumWrite,
    LsTerminalDelivery,
    LsAuthentication,
    QuorumTentativeWrites,
    OneWayProviderStore,
    SynchronizationRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderRole {
    User,
    Provider,
    LoginServer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverRole {
    User,
    Provider,
    LoginServer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitPolicy {
    AllResponses,
    Threshold(usize),
    Quorum(usize),
    OneWayDeliveryBound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageEvent {
    pub stage_id: u32,
    pub stage: ProtocolStage,
    pub sender_role: SenderRole,
    pub receiver_role: ReceiverRole,
    pub recipient_count: usize,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub wait_policy: WaitPolicy,
    /// Matching acknowledgements newly added by this event.  This is kept
    /// separate from the formal wait policy so retries retain Quorum(qsp)
    /// without counting qsp again for every retry round.
    pub acknowledgements: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtocolTrace {
    pub events: Vec<MessageEvent>,
    provider_processing_ns: u64,
    login_server_processing_ns: u64,
}

impl ProtocolTrace {
    pub fn push(&mut self, event: MessageEvent) {
        self.events.push(event);
    }

    pub fn record_provider_processing(&mut self, elapsed_ns: u64) {
        self.provider_processing_ns = self.provider_processing_ns.saturating_add(elapsed_ns);
    }

    pub fn record_login_server_processing(&mut self, elapsed_ns: u64) {
        self.login_server_processing_ns = self.login_server_processing_ns.saturating_add(elapsed_ns);
    }

    pub fn provider_processing_ns(&self) -> u64 {
        self.provider_processing_ns
    }

    pub fn login_server_processing_ns(&self) -> u64 {
        self.login_server_processing_ns
    }

    pub fn stages(&self) -> Vec<ProtocolStage> {
        let mut ordered = self.events.clone();
        ordered.sort_by_key(|event| event.stage_id);
        let mut stages = Vec::new();
        for event in ordered {
            if stages.last().copied() != Some(event.stage) {
                stages.push(event.stage);
            }
        }
        stages
    }

    pub fn terminal_events_have_no_response(&self) -> bool {
        self.events
            .iter()
            .filter(|event| {
                matches!(
                    event.stage,
                    ProtocolStage::LsTerminalDelivery | ProtocolStage::OneWayProviderStore
                )
            })
            .all(|event| event.response_bytes == 0)
    }

    pub fn request_bytes(&self) -> usize {
        self.events
            .iter()
            .map(|event| event.request_bytes.saturating_mul(event.recipient_count))
            .sum()
    }

    pub fn response_bytes(&self) -> usize {
        self.events
            .iter()
            .map(|event| event.response_bytes.saturating_mul(event.recipient_count))
            .sum()
    }

    pub fn message_count(&self) -> usize {
        self.events
            .iter()
            .map(|event| event.recipient_count * if event.response_bytes == 0 { 1 } else { 2 })
            .sum()
    }

    pub fn acknowledgement_count(&self) -> usize {
        self.events.iter().map(|event| event.acknowledgements).sum()
    }
}
