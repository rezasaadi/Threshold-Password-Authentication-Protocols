use std::collections::HashMap;
use std::fmt;

use super::provider::{Uid, WriteDisposition};

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
    Unreachable,
    AlreadyRegistered,
    NotRegistered,
    CurrentVerifierMismatch,
    PendingConflict,
    NoMatchingPending,
}

impl fmt::Display for LoginServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable => write!(f, "login server is unreachable"),
            Self::AlreadyRegistered => write!(f, "user is already registered"),
            Self::NotRegistered => write!(f, "user is not registered"),
            Self::CurrentVerifierMismatch => write!(f, "current verifier does not match"),
            Self::PendingConflict => write!(f, "a different login-server operation is pending"),
            Self::NoMatchingPending => write!(f, "no matching login-server operation is pending"),
        }
    }
}

impl std::error::Error for LoginServerError {}

#[derive(Clone, Debug)]
pub struct LoginServer {
    reachable: bool,
    pub current: HashMap<Uid, VInfo>,
    pub pending: HashMap<Uid, PendingLsOperation>,
    completed: HashMap<Uid, PendingLsOperation>,
}

impl Default for LoginServer {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginServer {
    pub fn new() -> Self {
        Self {
            reachable: true,
            current: HashMap::new(),
            pending: HashMap::new(),
            completed: HashMap::new(),
        }
    }

    pub fn is_reachable(&self) -> bool {
        self.reachable
    }

    pub fn set_reachable(&mut self, reachable: bool) {
        self.reachable = reachable;
    }

    fn require_reachable(&self) -> Result<(), LoginServerError> {
        if self.reachable {
            Ok(())
        } else {
            Err(LoginServerError::Unreachable)
        }
    }

    pub fn prepare_registration(
        &mut self,
        uid: Uid,
        vinfo: VInfo,
    ) -> Result<WriteDisposition, LoginServerError> {
        self.require_reachable()?;
        let requested = PendingLsOperation::Registration { vinfo };
        if let Some(pending) = self.pending.get(&uid) {
            return if pending == &requested {
                Ok(WriteDisposition::Idempotent)
            } else {
                Err(LoginServerError::PendingConflict)
            };
        }
        if self.current.contains_key(&uid) {
            return Err(LoginServerError::AlreadyRegistered);
        }
        self.pending.insert(uid, requested);
        Ok(WriteDisposition::Accepted)
    }

    pub fn prepare_secret_update(
        &mut self,
        uid: Uid,
        old_vinfo: VInfo,
        new_vinfo: VInfo,
    ) -> Result<WriteDisposition, LoginServerError> {
        self.require_reachable()?;
        let requested = PendingLsOperation::SecretUpdate { old_vinfo, new_vinfo };
        if let Some(pending) = self.pending.get(&uid) {
            return if pending == &requested {
                Ok(WriteDisposition::Idempotent)
            } else {
                Err(LoginServerError::PendingConflict)
            };
        }
        let current = self.current.get(&uid).ok_or(LoginServerError::NotRegistered)?;
        if current != &old_vinfo {
            return Err(LoginServerError::CurrentVerifierMismatch);
        }
        self.pending.insert(uid, requested);
        Ok(WriteDisposition::Accepted)
    }

    pub fn store(
        &mut self,
        uid: &[u8],
        expected: &PendingLsOperation,
    ) -> Result<WriteDisposition, LoginServerError> {
        self.require_reachable()?;
        match self.pending.get(uid) {
            Some(pending) if pending == expected => {}
            None if self.completed.get(uid) == Some(expected) => return Ok(WriteDisposition::Idempotent),
            _ => return Err(LoginServerError::NoMatchingPending),
        }
        if let PendingLsOperation::SecretUpdate { old_vinfo, .. } = expected {
            if self.current.get(uid) != Some(old_vinfo) {
                return Err(LoginServerError::CurrentVerifierMismatch);
            }
        }
        self.current.insert(uid.to_vec(), expected.resulting_vinfo());
        self.pending.remove(uid);
        self.completed.insert(uid.to_vec(), expected.clone());
        Ok(WriteDisposition::Accepted)
    }

    pub fn discard(
        &mut self,
        uid: &[u8],
        expected: &PendingLsOperation,
    ) -> Result<WriteDisposition, LoginServerError> {
        self.require_reachable()?;
        match self.pending.get(uid) {
            Some(pending) if pending == expected => {
                self.pending.remove(uid);
                Ok(WriteDisposition::Accepted)
            }
            _ => Err(LoginServerError::NoMatchingPending),
        }
    }

    pub fn authenticate(&self, uid: &[u8], supplied: &VInfo) -> Result<bool, LoginServerError> {
        self.require_reachable()?;
        Ok(self.current.get(uid) == Some(supplied))
    }

    pub fn current_vinfo(&self, uid: &[u8]) -> Option<&VInfo> {
        self.current.get(uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_keeps_old_verifier_active_until_matching_store() {
        let mut server = LoginServer::new();
        let uid = b"alice".to_vec();
        let registration = PendingLsOperation::Registration { vinfo: [1; 32] };
        server.prepare_registration(uid.clone(), [1; 32]).unwrap();
        server.store(&uid, &registration).unwrap();

        let update = PendingLsOperation::SecretUpdate {
            old_vinfo: [1; 32],
            new_vinfo: [2; 32],
        };
        server
            .prepare_secret_update(uid.clone(), [1; 32], [2; 32])
            .unwrap();
        assert!(server.authenticate(&uid, &[1; 32]).unwrap());
        assert!(!server.authenticate(&uid, &[2; 32]).unwrap());
        server.store(&uid, &update).unwrap();
        assert!(server.authenticate(&uid, &[2; 32]).unwrap());
    }

    #[test]
    fn discard_preserves_old_verifier() {
        let mut server = LoginServer::new();
        let uid = b"alice".to_vec();
        let registration = PendingLsOperation::Registration { vinfo: [1; 32] };
        server.prepare_registration(uid.clone(), [1; 32]).unwrap();
        server.store(&uid, &registration).unwrap();
        let update = PendingLsOperation::SecretUpdate {
            old_vinfo: [1; 32],
            new_vinfo: [2; 32],
        };
        server
            .prepare_secret_update(uid.clone(), [1; 32], [2; 32])
            .unwrap();
        server.discard(&uid, &update).unwrap();
        assert_eq!(server.current_vinfo(&uid), Some(&[1; 32]));
    }

    #[test]
    fn exact_prepare_and_store_replays_are_idempotent() {
        let mut server = LoginServer::new();
        let uid = b"alice".to_vec();
        let operation = PendingLsOperation::Registration { vinfo: [1; 32] };
        assert_eq!(
            server.prepare_registration(uid.clone(), [1; 32]).unwrap(),
            WriteDisposition::Accepted
        );
        assert_eq!(
            server.prepare_registration(uid.clone(), [1; 32]).unwrap(),
            WriteDisposition::Idempotent
        );
        assert_eq!(
            server.store(&uid, &operation).unwrap(),
            WriteDisposition::Accepted
        );
        assert_eq!(
            server.store(&uid, &operation).unwrap(),
            WriteDisposition::Idempotent
        );
    }
}
