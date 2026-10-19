use crate::crypto::CtBlob;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Signature;

pub const SIGNATURE_BYTES: usize = 64;
pub const SCALAR_BYTES: usize = 32;
pub const COUNTER_BYTES: usize = 8;
pub const PROVIDER_INDEX_BYTES: usize = 4;
pub const STATUS_BYTES: usize = 1;
pub const RISTRETTO_BYTES: usize = 32;
pub const CIPHERID_PT_LEN: usize = 96;
pub const CIPHERSP_PT_LEN: usize = 40;

/// Encodes a variable-length user identifier without ambiguity.
pub fn encode_uid(uid: &[u8]) -> Vec<u8> {
    let len = u32::try_from(uid.len()).expect("Uid is too long to encode");
    let mut encoded = Vec::with_capacity(PROVIDER_INDEX_BYTES + uid.len());
    encoded.extend_from_slice(&len.to_le_bytes());
    encoded.extend_from_slice(uid);
    encoded
}

/// Exact bytes authenticated by an UpSPA password-update signature.
///
/// Field order: `len(Uid) || Uid || cidnew || ki,new || time || i`.
pub fn encode_upspa_password_update(
    uid: &[u8],
    cidnew: &CtBlob<CIPHERID_PT_LEN>,
    ki_new: &Scalar,
    time: u64,
    provider_index: u32,
) -> Vec<u8> {
    let mut encoded = encode_uid(uid);
    encoded.reserve(
        CtBlob::<CIPHERID_PT_LEN>::encoded_len() + SCALAR_BYTES + COUNTER_BYTES + PROVIDER_INDEX_BYTES,
    );
    encoded.extend_from_slice(&cidnew.encode());
    encoded.extend_from_slice(&ki_new.to_bytes());
    encoded.extend_from_slice(&time.to_le_bytes());
    encoded.extend_from_slice(&provider_index.to_le_bytes());
    encoded
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpSpaPasswordUpdateRequest {
    pub uid: Vec<u8>,
    pub cidnew: CtBlob<CIPHERID_PT_LEN>,
    pub share_new: Scalar,
    pub time: u64,
    pub provider_index: u32,
    pub signature: Signature,
}

impl UpSpaPasswordUpdateRequest {
    pub fn signed_bytes(&self) -> Vec<u8> {
        encode_upspa_password_update(
            &self.uid,
            &self.cidnew,
            &self.share_new,
            self.time,
            self.provider_index,
        )
    }

    pub fn encoded_len(&self) -> usize {
        self.signed_bytes().len() + SIGNATURE_BYTES
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtocolStage {
    Setup,
    Identification,
    ParallelProviderAndLsPrepare,
    ParallelTerminalAndProviderFinalAcks,
    AccountRead,
    LoginServerAuthentication,
    AllProviderPendingWrites,
    AllProviderTerminalAcks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageRole {
    Client,
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
    pub sender_role: MessageRole,
    pub receiver_role: MessageRole,
    pub recipient_count: usize,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub wait_policy: WaitPolicy,
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

    pub fn record_processing(&mut self, role: MessageRole, elapsed_ns: u64) {
        match role {
            MessageRole::Client => {}
            MessageRole::Provider => {
                self.provider_processing_ns = self.provider_processing_ns.saturating_add(elapsed_ns)
            }
            MessageRole::LoginServer => {
                self.login_server_processing_ns = self.login_server_processing_ns.saturating_add(elapsed_ns)
            }
        }
    }

    pub fn provider_processing_ns(&self) -> u64 {
        self.provider_processing_ns
    }

    pub fn login_server_processing_ns(&self) -> u64 {
        self.login_server_processing_ns
    }

    pub fn stage_order(&self) -> Vec<ProtocolStage> {
        let mut ordered = Vec::new();
        let mut stage_ids = Vec::new();
        for event in &self.events {
            if !stage_ids.contains(&event.stage_id) {
                stage_ids.push(event.stage_id);
                ordered.push(event.stage);
            }
        }
        ordered
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
        self.events
            .iter()
            .filter(|event| event.response_bytes != 0)
            .map(|event| event.recipient_count)
            .sum()
    }
}

pub const fn account_blob_bytes() -> usize {
    CtBlob::<CIPHERSP_PT_LEN>::encoded_len()
}

pub const fn identification_blob_bytes() -> usize {
    CtBlob::<CIPHERID_PT_LEN>::encoded_len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_update_encoding_binds_uid_first_and_every_required_field() {
        let cid = CtBlob {
            nonce: [1; 24],
            ct: [2; CIPHERID_PT_LEN],
            tag: [3; 16],
        };
        let share = Scalar::from(9u64);
        let encoded = encode_upspa_password_update(b"alice", &cid, &share, 17, 4);

        assert_eq!(&encoded[..4], &5u32.to_le_bytes());
        assert_eq!(&encoded[4..9], b"alice");
        assert_eq!(
            encoded.len(),
            4 + 5 + identification_blob_bytes() + SCALAR_BYTES + COUNTER_BYTES + PROVIDER_INDEX_BYTES
        );
    }
}
