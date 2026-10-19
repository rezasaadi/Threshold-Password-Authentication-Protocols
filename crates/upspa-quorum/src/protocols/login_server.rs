use std::collections::HashMap;

pub type VInfo = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingLsOperation {
    Registration { vinfo: VInfo },
    SecretUpdate { old_vinfo: VInfo, new_vinfo: VInfo },
}

impl PendingLsOperation {
    pub fn resulting_vinfo(&self) -> VInfo {
        match self {
            Self::Registration { vinfo } => *vinfo,
            Self::SecretUpdate { new_vinfo, .. } => *new_vinfo,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginServerError {
    ExistingAccount,
    MissingAccount,
    VerifierMismatch,
    ConflictingPendingOperation,
    PendingOperationMismatch,
}

#[derive(Clone, Debug, Default)]
pub struct LoginServer {
    pub current: HashMap<Vec<u8>, VInfo>,
    pub pending: HashMap<Vec<u8>, PendingLsOperation>,
    last_stored: HashMap<Vec<u8>, PendingLsOperation>,
    last_discarded: HashMap<Vec<u8>, PendingLsOperation>,
}

impl LoginServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare_registration(
        &mut self,
        uid: &[u8],
        vinfo: VInfo,
    ) -> Result<PendingLsOperation, LoginServerError> {
        let operation = PendingLsOperation::Registration { vinfo };
        if self.pending.get(uid) == Some(&operation) {
            return Ok(operation);
        }
        if self.pending.contains_key(uid) {
            return Err(LoginServerError::ConflictingPendingOperation);
        }
        if self.current.contains_key(uid) {
            return Err(LoginServerError::ExistingAccount);
        }
        self.pending.insert(uid.to_vec(), operation.clone());
        Ok(operation)
    }

    pub fn prepare_secret_update(
        &mut self,
        uid: &[u8],
        old_vinfo: VInfo,
        new_vinfo: VInfo,
    ) -> Result<PendingLsOperation, LoginServerError> {
        let operation = PendingLsOperation::SecretUpdate { old_vinfo, new_vinfo };
        if self.pending.get(uid) == Some(&operation) {
            return Ok(operation);
        }
        if self.pending.contains_key(uid) {
            return Err(LoginServerError::ConflictingPendingOperation);
        }
        match self.current.get(uid) {
            Some(current) if current == &old_vinfo => {
                self.pending.insert(uid.to_vec(), operation.clone());
                Ok(operation)
            }
            Some(_) => Err(LoginServerError::VerifierMismatch),
            None => Err(LoginServerError::MissingAccount),
        }
    }

    /// Processes the terminal Store. The returned `Result<()>` is local handler
    /// state only; RoUpSPA's message trace deliberately contains no response.
    pub fn store(&mut self, uid: &[u8], operation: &PendingLsOperation) -> Result<(), LoginServerError> {
        if self.last_stored.get(uid) == Some(operation) && !self.pending.contains_key(uid) {
            return Ok(());
        }
        match self.pending.get(uid) {
            Some(pending) if pending == operation => {}
            _ => return Err(LoginServerError::PendingOperationMismatch),
        }
        match operation {
            PendingLsOperation::Registration { vinfo } => {
                if self.current.contains_key(uid) {
                    return Err(LoginServerError::ExistingAccount);
                }
                self.current.insert(uid.to_vec(), *vinfo);
            }
            PendingLsOperation::SecretUpdate { old_vinfo, new_vinfo } => match self.current.get(uid) {
                Some(current) if current == old_vinfo => {
                    self.current.insert(uid.to_vec(), *new_vinfo);
                }
                Some(_) => return Err(LoginServerError::VerifierMismatch),
                None => return Err(LoginServerError::MissingAccount),
            },
        }
        self.pending.remove(uid);
        self.last_discarded.remove(uid);
        self.last_stored.insert(uid.to_vec(), operation.clone());
        Ok(())
    }

    /// Processes a pre-write Discard. Like terminal Store this has no formal
    /// application-level response message.
    pub fn discard(&mut self, uid: &[u8], operation: &PendingLsOperation) -> Result<(), LoginServerError> {
        if self.last_discarded.get(uid) == Some(operation) && !self.pending.contains_key(uid) {
            return Ok(());
        }
        match self.pending.get(uid) {
            Some(pending) if pending == operation => {
                self.pending.remove(uid);
                self.last_discarded.insert(uid.to_vec(), operation.clone());
                Ok(())
            }
            _ => Err(LoginServerError::PendingOperationMismatch),
        }
    }

    pub fn authenticate(&self, uid: &[u8], supplied: &VInfo) -> bool {
        self.current.get(uid) == Some(supplied)
    }

    pub fn current_verifier(&self, uid: &[u8]) -> Option<VInfo> {
        self.current.get(uid).copied()
    }
}
