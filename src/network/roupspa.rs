//! Socket adapter for the existing RoUpSPA provider and login-server machines.
//!
//! A service replays only its own durable accepted transitions. The client never
//! holds a provider object or a provider's long-lived TOPRF share after Setup.
use super::common::{self, Config, Metrics, RunResult};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use upspa_quorum_bench::crypto::{self, CtBlob};
use upspa_quorum_bench::protocols::login_server::{LoginServer, PendingLsOperation};
use upspa_quorum_bench::protocols::messages::{ACCOUNT_PLAINTEXT_LEN, IDENTIFICATION_PLAINTEXT_LEN};
use upspa_quorum_bench::protocols::provider::{
    AccountFamilyKey, IdentificationReplica, ReplicaStatus, RoUpSpaProvider, SignedAccountRecord,
    SignedIdentificationRecord,
};
use upspa_quorum_bench::protocols::roupspa::{
    DEFAULT_LOGIN_SERVER, DEFAULT_NEW_PASSWORD, DEFAULT_PASSWORD, DEFAULT_UID,
};

fn ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}
fn bytes(v: &Value) -> Result<Vec<u8>, String> {
    serde_json::from_value(v.clone()).map_err(|e| format!("byte array: {e}"))
}
fn fixed<const N: usize>(v: &Value) -> Result<[u8; N], String> {
    bytes(v)?.try_into().map_err(|_| format!("expected {N} bytes"))
}
fn ctr(v: &Value, name: &str) -> Result<u64, String> {
    v[name].as_u64().ok_or_else(|| format!("missing {name}"))
}
fn action(v: &Value) -> Result<&str, String> {
    v["action"].as_str().ok_or_else(|| "missing action".into())
}
fn blob<const N: usize>(v: &Value) -> Result<CtBlob<N>, String> {
    let b = bytes(v)?;
    if b.len() != CtBlob::<N>::ENCODED_LEN {
        return Err("invalid ciphertext length".into());
    }
    Ok(CtBlob {
        nonce: b[..24].try_into().unwrap(),
        ct: b[24..24 + N].try_into().unwrap(),
        tag: b[24 + N..].try_into().unwrap(),
    })
}
fn identification(v: &Value) -> Result<SignedIdentificationRecord, String> {
    Ok(SignedIdentificationRecord {
        cid: blob(&v["cid"])?,
        ctrid: ctr(v, "ctrid")?,
        signature: if v["signature"].is_null() {
            None
        } else {
            Some(Signature::from_bytes(&fixed::<64>(&v["signature"])?))
        },
    })
}
fn account(v: &Value) -> Result<SignedAccountRecord, String> {
    Ok(SignedAccountRecord {
        uid: bytes(&v["uid"])?,
        suid: fixed(&v["suid"])?,
        cj: blob(&v["cj"])?,
        ctr: ctr(v, "ctr")?,
        signature: Signature::from_bytes(&fixed::<64>(&v["signature"])?),
    })
}
fn id_json(r: &SignedIdentificationRecord) -> Value {
    json!({"cid":r.cid.encode(),"ctrid":r.ctrid,
        "signature":r.signature.as_ref().map(|s| s.to_bytes().to_vec())})
}
fn account_json(r: &SignedAccountRecord) -> Value {
    json!({"uid":r.uid,"suid":r.suid,"cj":r.cj.encode(),"ctr":r.ctr,
        "signature":r.signature.to_bytes().to_vec()})
}
fn ls_operation(v: &Value) -> Result<PendingLsOperation, String> {
    if v["old_vinfo"].is_null() {
        Ok(PendingLsOperation::Registration {
            vinfo: fixed(&v["new_vinfo"])?,
        })
    } else {
        Ok(PendingLsOperation::SecretUpdate {
            old_vinfo: fixed(&v["old_vinfo"])?,
            new_vinfo: fixed(&v["new_vinfo"])?,
        })
    }
}
fn signed_id_valid(uid: &[u8], key: &VerifyingKey, record: &SignedIdentificationRecord) -> bool {
    match (record.ctrid, &record.signature) {
        (0, None) => true,
        (0, Some(_)) | (_, None) => false,
        (_, Some(sig)) => key.verify(&record.signed_bytes(uid), sig).is_ok(),
    }
}
fn encoded(v: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(v).map_err(|e| e.to_string())
}
fn persist(path: &Path, v: &impl Serialize) -> Result<(), String> {
    common::atomic_write(path, &serde_json::to_vec(v).map_err(|e| e.to_string())?)
}
fn load_events(path: &Path) -> Result<Vec<Value>, String> {
    match fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Clone)]
struct ProviderState {
    provider: RoUpSpaProvider,
    events: Vec<Value>,
    sessions: HashMap<String, Value>,
    counter_sessions: HashMap<String, String>,
}
impl ProviderState {
    fn new(id: u32) -> Self {
        Self {
            provider: RoUpSpaProvider::new(id),
            events: Vec::new(),
            sessions: HashMap::new(),
            counter_sessions: HashMap::new(),
        }
    }
    fn replay(id: u32, events: Vec<Value>) -> Result<Self, String> {
        let mut state = Self::new(id);
        for e in events {
            state.apply(&e)?;
            state.events.push(e);
        }
        Ok(state)
    }
    fn session_key(v: &Value) -> Result<String, String> {
        let session = v["session"].as_str().ok_or("missing session")?;
        if session.len() != 64 || !session.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("session must be 32 random bytes encoded as hex".into());
        }
        let stage = match action(v)? {
            "id_store" | "id_discard" => "id_terminal",
            other => other,
        };
        Ok(format!("{session}:{stage}"))
    }
    fn check_duplicate(&self, v: &Value) -> Result<bool, String> {
        let key = Self::session_key(v)?;
        match self.sessions.get(&key) {
            Some(old) if old == v => Ok(true),
            Some(_) => Err("conflicting reuse of session".into()),
            None => Ok(false),
        }
    }
    fn locally_discarded_identification(&self, uid: &[u8], record: &SignedIdentificationRecord) -> bool {
        self.sessions.values().any(|v| {
            v["action"] == "id_discard"
                && bytes(&v["uid"]).is_ok_and(|u| u == uid)
                && identification(&v["record"]).is_ok_and(|r| &r == record)
        })
    }
    fn apply(&mut self, v: &Value) -> Result<(), String> {
        let a = action(v)?;
        if a == "restart_stale" {
            for r in self.provider.identifications.values_mut() {
                r.status = ReplicaStatus::Stale;
            }
            for r in self.provider.accounts.values_mut() {
                r.status = ReplicaStatus::Stale;
            }
            return Ok(());
        }
        if a == "sync_id_install" {
            let uid = bytes(&v["uid"])?;
            let record = identification(&v["record"])?;
            // A signature authenticates a candidate, not its terminal decision.
            // Never resurrect a tuple whose exact Discard is in our journal.
            // Peers lacking that decision still need completion evidence; this
            // local veto is deliberately not a distributed commit certificate.
            if self.locally_discarded_identification(&uid, &record) {
                return Err("synchronization candidate was locally discarded".into());
            }
            let local = self
                .provider
                .identifications
                .get(&uid)
                .ok_or("missing own initialization")?;
            if !self.provider.shares.contains_key(&uid) {
                return Err("missing own TOPRF share".into());
            }
            if record.ctrid < local.current.ctrid || !signed_id_valid(&uid, &local.svk, &record) {
                return Err("invalid/lower synchronization record".into());
            }
            if record.ctrid > local.current.ctrid {
                // A Byzantine responder can replay a valid signature from an
                // abandoned Password Update as its alleged current record.
                // Without a locally processed Store, peer signatures alone do
                // not establish the terminal decision, even after q responses.
                return Err("PROTOCOL GAP: a higher signed identification record lacks locally processed Store or a verifiable completion certificate".into());
            }
            if record.ctrid == local.current.ctrid && record != local.current {
                return Err("conflicting synchronization maximum".into());
            }
            // Recovery of the completed current record must not erase a
            // persisted unfinished Password Update. A later identical Store
            // still needs that exact tentative tuple after restart.
            let tentative = match &local.tentative_identification {
                Some(pending) if pending.ctrid == record.ctrid && pending != &record => {
                    return Err("synchronization conflicts with persisted tentative tuple".into());
                }
                Some(pending) if pending.ctrid > record.ctrid => Some(pending.clone()),
                _ => None,
            };
            self.provider.identifications.insert(
                uid,
                IdentificationReplica {
                    svk: local.svk,
                    current: record,
                    status: ReplicaStatus::Active,
                    tentative_identification: tentative,
                },
            );
            return Ok(());
        }
        if self.check_duplicate(v)? {
            return Ok(());
        }
        let uid = bytes(&v["uid"])?;
        match a {
            "setup" => {
                let key = VerifyingKey::from_bytes(&fixed(&v["svk"])?).map_err(|e| e.to_string())?;
                let share = Option::<Scalar>::from(Scalar::from_canonical_bytes(fixed(&v["share"])?))
                    .ok_or("noncanonical TOPRF share")?;
                if v["provider_id"].as_u64() != Some(self.provider.id as u64) {
                    return Err("wrong share recipient".into());
                }
                self.provider
                    .install_setup(&uid, key, identification(&v["record"])?, share)
                    .map_err(|e| format!("{e:?}"))?;
            }
            "registration_write" | "secret_write" => {
                let r = account(&v["record"])?;
                if r.uid != uid {
                    return Err("wrong UID record binding".into());
                }
                let family = format!("{:?}:{:?}:{}", r.uid, r.suid, r.ctr);
                let session = v["session"].as_str().unwrap();
                if self
                    .counter_sessions
                    .get(&family)
                    .is_some_and(|old| old != session)
                {
                    return Err("counter already bound to another session".into());
                }
                if a == "registration_write" {
                    self.provider.accept_registration_account(r)
                } else {
                    self.provider.accept_secret_update_account(r)
                }
                .map_err(|e| format!("{e:?}"))?;
                self.counter_sessions.insert(family, session.into());
            }
            "id_write" => {
                let r = identification(&v["record"])?;
                let family = format!("id:{uid:?}:{}", r.ctrid);
                let session = v["session"].as_str().unwrap();
                if self
                    .counter_sessions
                    .get(&family)
                    .is_some_and(|old| old != session)
                {
                    return Err("identification counter already bound to another session".into());
                }
                self.provider
                    .accept_tentative_identification(&uid, r)
                    .map_err(|e| format!("{e:?}"))?;
                self.counter_sessions.insert(family, session.into());
            }
            "id_store" | "id_discard" => {
                let sid = v["session"].as_str().unwrap();
                let write = self
                    .sessions
                    .get(&format!("{sid}:id_write"))
                    .ok_or("no matching phase session")?;
                if write["record"] != v["record"] || write["uid"] != v["uid"] {
                    return Err("terminal tuple differs from prepared tuple".into());
                }
                let r = identification(&v["record"])?;
                if a == "id_store" {
                    self.provider.store_tentative_identification(&uid, &r)
                } else {
                    self.provider.discard_tentative_identification(&uid, &r)
                }
                .map_err(|e| format!("{e:?}"))?;
                if a == "id_discard" {
                    // A discarded replacement never became current, so its
                    // counter is free again: a later Password Update (new
                    // session) may reuse current+1.
                    self.counter_sessions.remove(&format!("id:{uid:?}:{}", r.ctrid));
                }
            }
            _ => return Err(format!("unknown provider transition {a}")),
        }
        self.sessions.insert(Self::session_key(v)?, v.clone());
        Ok(())
    }
    fn transition(&mut self, path: &Path, v: &Value) -> Result<(), String> {
        if !matches!(action(v)?, "restart_stale" | "sync_id_install") && self.check_duplicate(v)? {
            return Ok(());
        }
        let mut next = self.clone();
        next.apply(v)?;
        next.events.push(v.clone());
        persist(path, &next.events)?;
        *self = next;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct LoginState {
    server: LoginServer,
    events: Vec<Value>,
    sessions: HashMap<String, Value>,
}
impl LoginState {
    fn apply(&mut self, v: &Value) -> Result<(), String> {
        let session = v["session"].as_str().ok_or("missing session")?;
        if session.len() != 64 || !session.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid session".into());
        }
        let a = action(v)?;
        let key = format!(
            "{session}:{}",
            if a == "ls_prepare" { "prepare" } else { "terminal" }
        );
        if let Some(old) = self.sessions.get(&key) {
            return if old == v {
                Ok(())
            } else {
                Err("conflicting session reuse".into())
            };
        }
        let uid = bytes(&v["uid"])?;
        let op = ls_operation(v)?;
        match a {
            "ls_prepare" => {
                match op {
                    PendingLsOperation::Registration { vinfo } => {
                        self.server.prepare_registration(&uid, vinfo)
                    }
                    PendingLsOperation::SecretUpdate { old_vinfo, new_vinfo } => {
                        self.server.prepare_secret_update(&uid, old_vinfo, new_vinfo)
                    }
                }
                .map_err(|e| format!("{e:?}"))?;
            }
            "ls_store" | "ls_discard" => {
                let prep = self
                    .sessions
                    .get(&format!("{session}:prepare"))
                    .ok_or("no matching Prepare session")?;
                if prep["uid"] != v["uid"] || ls_operation(prep)? != op {
                    return Err("terminal session binding mismatch".into());
                }
                if a == "ls_store" {
                    self.server.store(&uid, &op)
                } else {
                    self.server.discard(&uid, &op)
                }
                .map_err(|e| format!("{e:?}"))?;
            }
            _ => return Err("unknown login-server transition".into()),
        }
        self.sessions.insert(key, v.clone());
        Ok(())
    }
    fn replay(events: Vec<Value>) -> Result<Self, String> {
        let mut s = Self::default();
        for e in events {
            s.apply(&e)?;
            s.events.push(e);
        }
        Ok(s)
    }
    fn transition(&mut self, path: &Path, v: &Value) -> Result<(), String> {
        let mut next = self.clone();
        next.apply(v)?;
        if next.sessions != self.sessions {
            next.events.push(v.clone());
            persist(path, &next.events)?;
        }
        *self = next;
        Ok(())
    }
}

fn endpoint_log(dir: &Path, v: &Value, result: &Result<(), String>, elapsed: u64) -> Result<(), String> {
    let line = json!({"action":v["action"],"session":v["session"],"handler_ns":elapsed,
        "processed":result.is_ok(),"reason":result.as_ref().err(),
        "unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis()});
    let mut data = encoded(&line)?;
    data.push(b'\n');
    common::append_durable(&dir.join("endpoint.jsonl"), &data)
}

/// Start one independently launched role. `state` belongs to this role alone.
pub fn service(role: &str, id: u32, listen: &str, state: &Path, config: &Config) -> Result<(), String> {
    fs::create_dir_all(state).map_err(|e| e.to_string())?;
    let journal = state.join("roupspa-events.json");
    if role == "provider" {
        let existed = journal.exists();
        let mut owned = ProviderState::replay(id, load_events(&journal)?)?;
        // A provider relaunched only to arm a fault (suppressed stage, crash
        // point, corrupted TOPRF contributions) did not miss any operation: the
        // harness relaunches it while the deployment is quiescent. It keeps its
        // replicas active instead of entering crash recovery; the relaunch after
        // the fault (without these variables) is the real recovery.
        let injection = [
            "BENCH_SUPPRESS_STAGE",
            "BENCH_CRASH_BEFORE_STAGE",
            "BENCH_CRASH_AFTER_STAGE",
            "BENCH_CORRUPT_PARTIAL",
        ]
        .iter()
        .any(|v| std::env::var(v).is_ok());
        if existed && !owned.provider.identifications.is_empty() && !injection {
            owned.transition(&journal, &json!({"action":"restart_stale"}))?;
            // A returning provider initiates its own repair. Cap startup work;
            // failed rounds retain stale state and can be retried explicitly
            // after the rest of the deployment has returned.
            let deadline =
                Instant::now() + Duration::from_millis(config.timeout_ms.saturating_mul(2).clamp(250, 5000));
            let families = owned.provider.identifications.keys().cloned().collect::<Vec<_>>();
            for uid in families {
                if Instant::now() >= deadline {
                    break;
                }
                let mut bounded = config.clone();
                bounded.timeout_ms = bounded.timeout_ms.min(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .max(1) as u64,
                );
                let repair = Instant::now();
                let result = synchronize_identification(&mut owned, &journal, &uid, &bounded);
                endpoint_log(
                    state,
                    &json!({"action":"restart_synchronize","uid":uid}),
                    &result,
                    ns(repair),
                )?;
            }
            let accounts = owned.provider.accounts.keys().cloned().collect::<Vec<_>>();
            for family in accounts {
                let repair = Instant::now();
                let result = if Instant::now() < deadline {
                    let mut bounded = config.clone();
                    bounded.timeout_ms = bounded.timeout_ms.min(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis()
                            .max(1) as u64,
                    );
                    synchronize_account(&owned, &journal, &family, &bounded)
                } else {
                    Err("PROTOCOL GAP: account repair requires completion evidence; startup recovery deadline reached".into())
                };
                endpoint_log(
                    state,
                    &json!({"action":"restart_account_sync_unresolved","uid":family.uid,"suid":family.suid}),
                    &result,
                    ns(repair),
                )?;
            }
        }
        let cfg = config.clone();
        let dir = state.to_path_buf();
        common::serve(listen, state, move |v| {
            let start = Instant::now();
            let a = action(v)?.to_owned();
            match a.as_str() {
                "identify" => {
                    let uid = bytes(&v["uid"])?;
                    let blind = if v["blinded"].is_null() {
                        None
                    } else {
                        Some(
                            CompressedRistretto(fixed(&v["blinded"])?)
                                .decompress()
                                .ok_or("invalid Ristretto point")?,
                        )
                    };
                    let r = owned
                        .provider
                        .identification_response(&uid, blind.as_ref())
                        .map_err(|e| format!("{e:?}"))?;
                    // Fault injection (benchmark only): a corrupted provider that
                    // returns a well-formed but wrong TOPRF contribution.
                    let corrupt = std::env::var("BENCH_CORRUPT_PARTIAL").is_ok();
                    let partial = r.toprf_response.map(|p| {
                        if corrupt {
                            p + crypto::hash_to_point(b"bench/corrupt-partial")
                        } else {
                            p
                        }
                    });
                    Ok((
                        json!({"ok":true,"provider_id":id,"svk":r.svk.to_bytes(),"record":id_json(&r.current),
                        "partial":partial.map(|p|p.compress().to_bytes())}),
                        false,
                    ))
                }
                "account_read" => {
                    let key = AccountFamilyKey::new(&bytes(&v["uid"])?, fixed(&v["suid"])?);
                    let r = owned
                        .provider
                        .account_response(&key)
                        .map_err(|e| format!("{e:?}"))?;
                    Ok((
                        json!({"ok":true,"provider_id":id,"record":account_json(&r)}),
                        false,
                    ))
                }
                "sync_evidence" => {
                    // Public signed evidence may be read while stale. It is not
                    // an authentication response and contains no TOPRF share.
                    let uid = bytes(&v["uid"])?;
                    let r = owned.provider.identifications.get(&uid).ok_or("unknown family")?;
                    Ok((
                        json!({"ok":true,"provider_id":id,"svk":r.svk.to_bytes(),"record":id_json(&r.current)}),
                        false,
                    ))
                }
                "account_sync_evidence" => {
                    // Safe diagnostic evidence, including while stale. The user
                    // signature binds the record but proves neither a write
                    // quorum nor processing of login-server Store.
                    let family = AccountFamilyKey::new(&bytes(&v["uid"])?, fixed(&v["suid"])?);
                    let identification = owned
                        .provider
                        .identifications
                        .get(&family.uid)
                        .ok_or("unknown user")?;
                    let replica = owned
                        .provider
                        .accounts
                        .get(&family)
                        .ok_or("unknown account family")?;
                    let record = replica.current.as_ref().ok_or("missing account record")?;
                    Ok((
                        json!({"ok":true,"provider_id":id,"svk":identification.svk.to_bytes(),
                        "record":account_json(record),"proves_completion":false,
                        "active":replica.status == ReplicaStatus::Active}),
                        false,
                    ))
                }
                "synchronize" => {
                    let uid = bytes(&v["uid"])?;
                    let scope = v["scope"].as_str().unwrap_or("all");
                    if !["all", "identification"].contains(&scope) {
                        return Err("synchronization scope must be all or identification".into());
                    }
                    let repair = Instant::now();
                    if !v["suid"].is_null() {
                        let family = AccountFamilyKey::new(&uid, fixed(&v["suid"])?);
                        let result = synchronize_account(&owned, &journal, &family, &cfg);
                        endpoint_log(&dir, v, &result, ns(start))?;
                        result?;
                    } else {
                        let result = synchronize_identification(&mut owned, &journal, &uid, &cfg);
                        endpoint_log(&dir, v, &result, ns(start))?;
                        result?;
                        if scope == "all" {
                            for (family, replica) in &owned.provider.accounts {
                                if family.uid == uid && replica.status == ReplicaStatus::Stale {
                                    let result = synchronize_account(&owned, &journal, family, &cfg);
                                    endpoint_log(&dir, v, &result, ns(start))?;
                                    result?;
                                }
                            }
                        }
                    }
                    Ok((json!({"ok":true,"scope":scope,"repair_ns":ns(repair)}), false))
                }
                "setup" | "registration_write" | "secret_write" | "id_write" | "id_store" | "id_discard" => {
                    let one_way = matches!(a.as_str(), "id_store" | "id_discard");
                    let result = owned.transition(&journal, v);
                    endpoint_log(&dir, v, &result, ns(start))?;
                    result?;
                    if one_way {
                        Ok((Value::Null, true))
                    } else {
                        Ok((json!({"ok":true,"session":v["session"]}), false))
                    }
                }
                _ => Err(format!("action {a} is not permitted on the provider wire")),
            }
        })
    } else if role == "login" || role == "login-server" {
        let mut owned = LoginState::replay(load_events(&journal)?)?;
        let dir = state.to_path_buf();
        common::serve(listen, state, move |v| {
            let start = Instant::now();
            let a = action(v)?;
            if a == "authenticate" {
                let decision = owned
                    .server
                    .authenticate(&bytes(&v["uid"])?, &fixed(&v["vinfo"])?);
                return Ok((json!({"ok":decision}), false));
            }
            let one_way = matches!(a, "ls_store" | "ls_discard");
            let result = owned.transition(&journal, v);
            endpoint_log(&dir, v, &result, ns(start))?;
            result?;
            if one_way {
                Ok((Value::Null, true))
            } else {
                Ok((json!({"ok":true,"session":v["session"]}), false))
            }
        })
    } else {
        Err(format!("unknown RoUpSPA role {role}"))
    }
}

fn synchronize_identification(
    owned: &mut ProviderState,
    journal: &Path,
    uid: &[u8],
    cfg: &Config,
) -> Result<(), String> {
    let repair = Instant::now();
    let local = owned
        .provider
        .identifications
        .get(uid)
        .ok_or("no locally initialized identification")?;
    let key = local.svk;
    let own_id = owned.provider.id;
    let mut transport = ClientTransport::default();
    let req = json!({"action":"sync_evidence","uid":uid,"provider_id":own_id});
    let targets = (0..cfg.providers.len())
        .filter(|i| (*i + 1) as u32 != own_id)
        .collect::<Vec<_>>();
    let responses = transport.stage(cfg, &targets, &encoded(&req)?, cfg.q_sp, |i, v| {
        if v["provider_id"].as_u64() != Some((i + 1) as u64)
            || fixed::<32>(&v["svk"]).ok() != Some(key.to_bytes())
        {
            return false;
        }
        identification(&v["record"]).is_ok_and(|r| signed_id_valid(uid, &key, &r))
    });
    transport.finish();
    let mut record = encoded(&json!({"provider_id":own_id,"stage":"sync_evidence","uid":uid,
        "metrics":transport.metrics,"repair_ns":ns(repair),"error":responses.as_ref().err()}))?;
    record.push(b'\n');
    common::append_durable(&journal.with_file_name("sync-transports.jsonl"), &record)?;
    let replies = responses?;
    let records = replies
        .into_iter()
        .map(|(_, v)| identification(&v["record"]))
        .collect::<Result<Vec<_>, _>>()?;
    let max = records
        .iter()
        .map(|r| r.ctrid)
        .max()
        .ok_or("no synchronization responses")?;
    let maximum = records.iter().find(|r| r.ctrid == max).unwrap();
    if records.iter().filter(|r| r.ctrid == max).any(|r| r != maximum) {
        return Err("conflicting synchronization maximum".into());
    }
    owned.transition(
        journal,
        &json!({"action":"sync_id_install","uid":uid,"record":id_json(maximum)}),
    )
}

/// Collect authenticated account-record evidence without treating it as proof
/// of completion. Direct writes precede login-server Store, so even q valid
/// signatures cannot justify activation. Keep this path fail-closed until the
/// protocol defines a verifiable terminal witness or distributed exclusion.
fn synchronize_account(
    owned: &ProviderState,
    journal: &Path,
    family: &AccountFamilyKey,
    cfg: &Config,
) -> Result<(), String> {
    let repair = Instant::now();
    let key = owned
        .provider
        .identifications
        .get(&family.uid)
        .ok_or("no locally initialized identification")?
        .svk;
    let own_id = owned.provider.id;
    let mut transport = ClientTransport::default();
    let req = json!({"action":"account_sync_evidence","uid":family.uid,"suid":family.suid,
        "provider_id":own_id});
    let targets = (0..cfg.providers.len())
        .filter(|i| (*i + 1) as u32 != own_id)
        .collect::<Vec<_>>();
    let responses = transport.stage(cfg, &targets, &encoded(&req)?, cfg.q_sp, |i, v| {
        v["provider_id"].as_u64() == Some((i + 1) as u64)
            && fixed::<32>(&v["svk"]).ok() == Some(key.to_bytes())
            && account(&v["record"]).is_ok_and(|r| {
                r.uid == family.uid
                    && r.suid == family.suid
                    && key.verify(&r.signed_bytes(), &r.signature).is_ok()
            })
    });
    transport.finish();
    let result = (|| {
        let records = responses?
            .into_iter()
            .map(|(_, v)| account(&v["record"]))
            .collect::<Result<Vec<_>, _>>()?;
        let maximum = records
            .iter()
            .max_by_key(|r| r.ctr)
            .ok_or("no account synchronization responses")?;
        if records
            .iter()
            .filter(|r| r.ctr == maximum.ctr)
            .any(|r| r != maximum)
        {
            return Err("conflicting account synchronization maximum".into());
        }
        if let Some(local) = owned
            .provider
            .accounts
            .get(family)
            .and_then(|r| r.current.as_ref())
        {
            if maximum.ctr < local.ctr {
                return Err("lower account synchronization maximum".into());
            }
            if maximum.ctr == local.ctr && maximum != local {
                return Err("account synchronization maximum conflicts with local record".into());
            }
        }
        Err(format!("PROTOCOL GAP: q={} signed account responses (maximum counter {}) do not prove login-server Store; account synchronization remains unresolved", cfg.q_sp, maximum.ctr))
    })();
    let mut record = encoded(&json!({"provider_id":own_id,"stage":"account_sync_evidence",
        "uid":family.uid,"suid":family.suid,"metrics":transport.metrics,
        "repair_ns":ns(repair),"proves_completion":false,"error":result.as_ref().err()}))?;
    record.push(b'\n');
    common::append_durable(&journal.with_file_name("sync-transports.jsonl"), &record)?;
    result
}

#[derive(Serialize, Deserialize, Clone)]
struct Session {
    id: String,
    phase: String,
    prepare: Option<Vec<u8>>,
    write: Vec<Vec<u8>>,
    terminal: Vec<u8>,
    prepared: bool,
    write_started: bool,
    acknowledged: BTreeSet<usize>,
    terminal_started: bool,
    /// Durable terminal choice: once Discard is chosen, crash recovery must
    /// redeliver Discard and must never resume writes or switch to Store.
    #[serde(default)]
    discard_decided: bool,
    next_password: Option<Vec<u8>>,
    #[serde(default)]
    endpoints: Vec<String>,
    #[serde(default)]
    login_endpoint: String,
    #[serde(default)]
    thresholds: [usize; 3],
}
#[derive(Serialize, Deserialize, Clone)]
struct ClientState {
    initialized: bool,
    password: Vec<u8>,
    pending: Option<Session>,
    #[serde(default)]
    pinned_svk: Option<[u8; 32]>,
}
impl Default for ClientState {
    fn default() -> Self {
        Self {
            initialized: false,
            password: DEFAULT_PASSWORD.to_vec(),
            pending: None,
            pinned_svk: None,
        }
    }
}

#[derive(Default)]
struct ClientTransport {
    metrics: Metrics,
    workers: Vec<JoinHandle<Metrics>>,
    wait_ns: u64,
    /// Explanation attached to a non-error outcome (e.g. why a Password Update
    /// was discarded); copied into `RunResult::reason`.
    note: Option<String>,
}

/// Number of provider responses a read waits for.
///
/// The paper's read size is r = n - q + t: any r responders intersect every
/// completed write quorum W of size q in at least r+q-n=t providers, including
/// at least one honest provider when at most t-1 are corrupt. This freshness
/// intersection does not guarantee t honest TOPRF replies: that separate
/// worst-case guarantee needs r >= 2t-1.
/// `read_policy = "threshold"` reproduces the legacy t-response reads and is
/// meant only for ablation against earlier measurements.
fn read_size(cfg: &Config) -> usize {
    if cfg.read_policy == "threshold" {
        cfg.t_sp
    } else {
        (cfg.n_sp - cfg.q_sp + cfg.t_sp).min(cfg.n_sp)
    }
}

impl ClientTransport {
    /// Send `raw` to `targets` and return as soon as `required` valid replies
    /// arrived. With `fanout = "all"` every target is contacted at once; with
    /// `fanout = "minimal"` only the first `required` targets are contacted and
    /// the remaining ones only if the first wave cannot complete.
    fn stage<F>(
        &mut self,
        cfg: &Config,
        targets: &[usize],
        raw: &[u8],
        required: usize,
        valid: F,
    ) -> Result<Vec<(usize, Value)>, String>
    where
        F: Fn(usize, &Value) -> bool,
    {
        let start = Instant::now();
        let mut replies = Vec::new();
        let mut seen = BTreeSet::new();
        let mut last = String::new();
        if cfg.fanout == "minimal" && targets.len() > required {
            let (first, rest) = targets.split_at(required);
            self.wave(
                cfg,
                first,
                raw,
                required,
                &valid,
                &mut replies,
                &mut seen,
                &mut last,
            );
            if replies.len() < required {
                self.metrics.fanout_extensions += 1;
                self.wave(
                    cfg,
                    rest,
                    raw,
                    required,
                    &valid,
                    &mut replies,
                    &mut seen,
                    &mut last,
                );
            }
        } else {
            self.wave(
                cfg,
                targets,
                raw,
                required,
                &valid,
                &mut replies,
                &mut seen,
                &mut last,
            );
        }
        self.metrics.quorum_ns += ns(start);
        if replies.len() >= required {
            Ok(replies)
        } else {
            Err(format!(
                "only {} valid replies, required {required}: {last}",
                replies.len()
            ))
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn wave<F>(
        &mut self,
        cfg: &Config,
        targets: &[usize],
        raw: &[u8],
        required: usize,
        valid: &F,
        replies: &mut Vec<(usize, Value)>,
        seen: &mut BTreeSet<usize>,
        last: &mut String,
    ) where
        F: Fn(usize, &Value) -> bool,
    {
        if targets.is_empty() || replies.len() >= required {
            return;
        }
        let (tx, rx) = mpsc::channel();
        for &i in targets {
            let address = cfg.providers[i].clone();
            let bytes = raw.to_vec();
            let tx = tx.clone();
            let timeout = cfg.timeout_ms;
            self.workers.push(thread::spawn(move || {
                let mut m = Metrics::default();
                let r = common::request(&address, &bytes, timeout, &mut m);
                let _ = tx.send((i, r));
                m
            }));
        }
        drop(tx);
        loop {
            let waiting = Instant::now();
            let received = rx.recv_timeout(Duration::from_millis(cfg.timeout_ms.max(1)));
            self.wait_ns += ns(waiting);
            let Ok((i, response)) = received else {
                break;
            };
            match response {
                Ok(v) if valid(i, &v) && seen.insert(i) => replies.push((i, v)),
                Ok(_) => *last = "invalid response".into(),
                Err(e) => *last = e,
            }
            if replies.len() >= required {
                return;
            }
        }
    }
    fn single(&mut self, cfg: &Config, raw: &[u8]) -> Result<Value, String> {
        let waiting = Instant::now();
        let result = common::request(&cfg.login_server, raw, cfg.timeout_ms, &mut self.metrics);
        self.wait_ns += ns(waiting);
        result
    }
    fn finish(&mut self) {
        let waiting = Instant::now();
        for worker in self.workers.drain(..) {
            if let Ok(m) = worker.join() {
                self.metrics.merge(&m);
            }
        }
        self.wait_ns += ns(waiting);
    }
}

struct Recovered {
    ssk: SigningKey,
    rsp: [u8; 32],
    fk: [u8; 32],
    ctrid: u64,
}
fn aad(suffix: &[u8]) -> Vec<u8> {
    let mut a = DEFAULT_UID.to_vec();
    a.extend_from_slice(suffix);
    a
}
fn recover(cfg: &Config, state: &ClientState, net: &mut ClientTransport) -> Result<Recovered, String> {
    let blind = crypto::random_scalar(&mut OsRng);
    let point = (crypto::hash_to_point(&state.password) * blind)
        .compress()
        .to_bytes();
    let req = encoded(&json!({"action":"identify","uid":DEFAULT_UID,"blinded":point}))?;
    let targets = (0..cfg.providers.len()).collect::<Vec<_>>();
    let required = read_size(cfg);
    net.metrics.read_replies_required = net.metrics.read_replies_required.max(required as u64);
    let replies = net.stage(cfg, &targets, &req, required, |i, v| {
        if v["provider_id"].as_u64() != Some((i + 1) as u64) {
            return false;
        }
        let Ok(k) = fixed(&v["svk"]).and_then(|b| VerifyingKey::from_bytes(&b).map_err(|e| e.to_string()))
        else {
            return false;
        };
        if state.pinned_svk.is_some_and(|pin| pin != k.to_bytes()) {
            return false;
        }
        identification(&v["record"]).is_ok_and(|r| signed_id_valid(DEFAULT_UID, &k, &r))
            && fixed(&v["partial"]).is_ok_and(|b| CompressedRistretto(b).decompress().is_some())
    })?;
    let key = VerifyingKey::from_bytes(&fixed(&replies[0].1["svk"])?).map_err(|e| e.to_string())?;
    if replies
        .iter()
        .any(|(_, v)| fixed::<32>(&v["svk"]).ok() != Some(key.to_bytes()))
    {
        return Err("inconsistent verification keys".into());
    }
    // Distinct validly signed candidates, highest counter first. A candidate with
    // a higher counter that does not open under the current password (for
    // example a discarded Password Update replacement replayed by a corrupted
    // provider) is skipped instead of aborting the read.
    let mut candidates: Vec<SignedIdentificationRecord> = Vec::new();
    for (_, v) in &replies {
        let r = identification(&v["record"])?;
        if !candidates.contains(&r) {
            candidates.push(r);
        }
    }
    candidates.sort_by(|a, b| b.ctrid.cmp(&a.ctrid));
    net.metrics.id_candidates += candidates.len() as u64;
    let ids = replies.iter().map(|(i, _)| (*i + 1) as u32).collect::<Vec<_>>();
    let partials = replies
        .iter()
        .map(|(_, v)| fixed(&v["partial"]).map(|b| CompressedRistretto(b).decompress().unwrap()))
        .collect::<Result<Vec<_>, _>>()?;
    // TOPRF contributions are not individually verifiable (2HashTDH without
    // proofs). The first t responders are tried first; if their output opens no
    // candidate, the next t-subset of the r responders is tried. Under the
    // liveness condition at least t responders are honest, so some subset
    // succeeds; AE integrity rejects outputs derived from invalid contributions.
    let combine = Instant::now();
    let mut subset = (0..cfg.t_sp).collect::<Vec<_>>();
    let mut tried = 0u64;
    let opened = loop {
        tried += 1;
        let sub_ids = subset.iter().map(|&k| ids[k]).collect::<Vec<_>>();
        let sub_partials = subset.iter().map(|&k| partials[k]).collect::<Vec<_>>();
        let state_key = crypto::toprf_client_eval_from_partials(
            &state.password,
            blind,
            &sub_partials,
            &crypto::lagrange_coeffs_at_zero(&sub_ids),
        );
        if let Some(found) = candidates
            .iter()
            .find_map(|c| open_identification(&state_key, c, &key))
        {
            break Some(found);
        }
        if !crypto::next_combination(&mut subset, ids.len()) {
            break None;
        }
    };
    net.metrics.toprf_subsets_tried += tried;
    net.metrics.toprf_combine_ns += ns(combine);
    opened.ok_or_else(|| {
        format!(
            "no t-subset of the {} TOPRF contributions opens an identification candidate ({tried} subsets tried)",
            ids.len()
        )
    })
}

/// Decrypt one identification candidate under a TOPRF output and check the
/// internal counter and signing-key binding. `None` if any check fails.
fn open_identification(
    state_key: &[u8; 32],
    record: &SignedIdentificationRecord,
    key: &VerifyingKey,
) -> Option<Recovered> {
    let plain = crypto::xchacha_decrypt_detached(state_key, &aad(b"|cipherid"), &record.cid).ok()?;
    let ssk = SigningKey::from_bytes(&plain[..32].try_into().unwrap());
    let internal = u64::from_le_bytes(plain[96..104].try_into().unwrap());
    if internal != record.ctrid || ssk.verifying_key() != *key {
        return None;
    }
    Some(Recovered {
        ssk,
        rsp: plain[32..64].try_into().unwrap(),
        fk: plain[64..96].try_into().unwrap(),
        ctrid: internal,
    })
}
fn read_account(
    cfg: &Config,
    r: &Recovered,
    net: &mut ClientTransport,
) -> Result<(SignedAccountRecord, [u8; 32]), String> {
    let suid = crypto::hash_roupspa_suid(&r.rsp, DEFAULT_LOGIN_SERVER);
    let req = encoded(&json!({"action":"account_read","uid":DEFAULT_UID,"suid":suid}))?;
    let targets = (0..cfg.providers.len()).collect::<Vec<_>>();
    // Same read size as identification: r responders intersect the completed
    // account write quorum in an honest provider holding the latest record.
    let required = read_size(cfg);
    net.metrics.read_replies_required = net.metrics.read_replies_required.max(required as u64);
    let replies = net.stage(cfg, &targets, &req, required, |i, v| {
        v["provider_id"].as_u64() == Some((i + 1) as u64)
            && account(&v["record"]).is_ok_and(|a| {
                a.uid == DEFAULT_UID
                    && a.suid == suid
                    && r.ssk
                        .verifying_key()
                        .verify(&a.signed_bytes(), &a.signature)
                        .is_ok()
                    && crypto::xchacha_decrypt_detached(&r.fk, &aad(b"|ciphersp"), &a.cj)
                        .is_ok_and(|pt| u64::from_le_bytes(pt[32..].try_into().unwrap()) == a.ctr)
            })
    })?;
    let mut candidates = Vec::new();
    for (_, v) in replies {
        let record = account(&v["record"])?;
        let pt = crypto::xchacha_decrypt_detached(&r.fk, &aad(b"|ciphersp"), &record.cj)
            .map_err(|_| "account decryption failed")?;
        let counter = u64::from_le_bytes(pt[32..].try_into().unwrap());
        if counter != record.ctr {
            return Err("account external/internal counter mismatch".into());
        }
        candidates.push((record, pt[..32].try_into().unwrap()));
    }
    let max = candidates.iter().map(|(r, _)| r.ctr).max().unwrap();
    let selected = candidates.iter().find(|(r, _)| r.ctr == max).unwrap().clone();
    if candidates
        .iter()
        .filter(|(r, _)| r.ctr == max)
        .any(|(r, _)| r != &selected.0)
    {
        return Err("conflicting maximum account records".into());
    }
    Ok(selected)
}
fn random_session() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn initial_session(cfg: &Config, id: String) -> Result<Session, String> {
    let (key, shares) = crypto::toprf_gen(cfg.n_sp, cfg.t_sp, &mut OsRng);
    let state_key = crypto::oprf_finalize(DEFAULT_PASSWORD, &(crypto::hash_to_point(DEFAULT_PASSWORD) * key));
    let ssk = SigningKey::generate(&mut OsRng);
    let mut pt = [0u8; IDENTIFICATION_PLAINTEXT_LEN];
    pt[..32].copy_from_slice(&ssk.to_bytes());
    OsRng.fill_bytes(&mut pt[32..96]);
    let record = SignedIdentificationRecord {
        cid: crypto::xchacha_encrypt_detached(&state_key, &aad(b"|cipherid"), &pt, &mut OsRng),
        ctrid: 0,
        signature: None,
    };
    let write=shares.into_iter().map(|(i,s)|encoded(&json!({"action":"setup","session":id,
        "uid":DEFAULT_UID,"provider_id":i,"svk":ssk.verifying_key().to_bytes(),"share":s.to_bytes(),"record":id_json(&record)})))
        .collect::<Result<Vec<_>,_>>()?;
    Ok(Session {
        id,
        phase: "setup".into(),
        prepare: None,
        write,
        terminal: Vec::new(),
        prepared: true,
        write_started: false,
        acknowledged: BTreeSet::new(),
        terminal_started: false,
        discard_decided: false,
        next_password: None,
        endpoints: cfg.providers.clone(),
        login_endpoint: cfg.login_server.clone(),
        thresholds: [cfg.n_sp, cfg.t_sp, cfg.q_sp],
    })
}
fn new_session(
    cfg: &Config,
    phase: &str,
    state: &ClientState,
    net: &mut ClientTransport,
    id: String,
) -> Result<Session, String> {
    if phase == "setup" {
        return initial_session(cfg, id);
    }
    if !state.initialized {
        return Err("Setup has not completed".into());
    }
    // This benchmark currently has a fixed replacement password. Do not count
    // a repeated call as a fresh Password Update or create another signed
    // candidate under the unchanged password. Prior/discarded password history
    // is a separate protocol issue, not established by this local equality test.
    if phase == "password_update" && state.password == DEFAULT_NEW_PASSWORD {
        return Err(
            "clean abort: replacement password equals the current password; no update performed".into(),
        );
    }
    let r = recover(cfg, state, net)?;
    let (write, prepare, terminal, next_password) = if phase == "password_update" {
        let required = read_size(cfg);
        // Polynomial consistency identifies the honest polynomial only if at
        // least t accepted contributions are honest. Under f <= t-1 this needs
        // r >= 2t-1, a condition not implied by the write-quorum inequality.
        // Do not silently widen the specified read or commit an uncheckable key.
        let safe_required = cfg.t_sp.saturating_mul(2).saturating_sub(1);
        if required < safe_required {
            return Err(format!(
                "clean abort: new-password TOPRF consistency needs at least 2*t_sp-1={safe_required} replies under t_sp-1 corruptions, but read_policy={} requests {required}; Password Update stopped before any provider write",
                cfg.read_policy
            ));
        }
        let blind = crypto::random_scalar(&mut OsRng);
        let blinded = (crypto::hash_to_point(DEFAULT_NEW_PASSWORD) * blind)
            .compress()
            .to_bytes();
        let req = encoded(&json!({"action":"identify","uid":DEFAULT_UID,"blinded":blinded}))?;
        let targets = (0..cfg.providers.len()).collect::<Vec<_>>();
        let replies = net.stage(cfg, &targets, &req, required, |i, v| {
            v["provider_id"].as_u64() == Some((i + 1) as u64)
                && fixed(&v["partial"]).is_ok_and(|b| CompressedRistretto(b).decompress().is_some())
        })?;
        let ids = replies.iter().map(|(i, _)| (*i + 1) as u32).collect::<Vec<_>>();
        let partials = replies
            .iter()
            .map(|(_, v)| fixed(&v["partial"]).map(|b| CompressedRistretto(b).decompress().unwrap()))
            .collect::<Result<Vec<_>, _>>()?;
        // No ciphertext exists yet under the new password, so a wrong output
        // could not be detected later. The r contributions must therefore lie on
        // one polynomial of degree t-1 (in the exponent); with at least t honest
        // responders this implies every contribution is correct. Otherwise the
        // update stops before any provider write, leaving nothing to resolve.
        let check = Instant::now();
        let consistent = crypto::toprf_partials_consistent(&ids, &partials, cfg.t_sp, &mut OsRng);
        net.metrics.toprf_consistency_checks += 1;
        net.metrics.toprf_combine_ns += ns(check);
        if !consistent {
            return Err(format!(
                "clean abort: the {} TOPRF contributions for the new password are inconsistent; Password Update stopped before any provider write",
                ids.len()
            ));
        }
        let key = crypto::toprf_client_eval_from_partials(
            DEFAULT_NEW_PASSWORD,
            blind,
            &partials[..cfg.t_sp],
            &crypto::lagrange_coeffs_at_zero(&ids[..cfg.t_sp]),
        );
        let next = r.ctrid.checked_add(1).ok_or("counter overflow")?;
        let mut pt = [0u8; IDENTIFICATION_PLAINTEXT_LEN];
        pt[..32].copy_from_slice(&r.ssk.to_bytes());
        pt[32..64].copy_from_slice(&r.rsp);
        pt[64..96].copy_from_slice(&r.fk);
        pt[96..].copy_from_slice(&next.to_le_bytes());
        let mut record = SignedIdentificationRecord {
            cid: crypto::xchacha_encrypt_detached(&key, &aad(b"|cipherid"), &pt, &mut OsRng),
            ctrid: next,
            signature: None,
        };
        record.signature = Some(r.ssk.sign(&record.signed_bytes(DEFAULT_UID)));
        let write =
            encoded(&json!({"action":"id_write","session":id,"uid":DEFAULT_UID,"record":id_json(&record)}))?;
        let terminal =
            encoded(&json!({"action":"id_store","session":id,"uid":DEFAULT_UID,"record":id_json(&record)}))?;
        (write, None, terminal, Some(DEFAULT_NEW_PASSWORD.to_vec()))
    } else {
        let (next, old) = if phase == "registration" {
            (0, None)
        } else if phase == "secret_update" {
            let (account, rls) = read_account(cfg, &r, net)?;
            (
                account.ctr.checked_add(1).ok_or("counter overflow")?,
                Some(crypto::hash_vinfo(&rls, DEFAULT_LOGIN_SERVER)),
            )
        } else {
            return Err(format!("unknown phase {phase}"));
        };
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let vinfo = crypto::hash_vinfo(&secret, DEFAULT_LOGIN_SERVER);
        let mut pt = [0u8; ACCOUNT_PLAINTEXT_LEN];
        pt[..32].copy_from_slice(&secret);
        pt[32..].copy_from_slice(&next.to_le_bytes());
        let mut record = SignedAccountRecord {
            uid: DEFAULT_UID.to_vec(),
            suid: crypto::hash_roupspa_suid(&r.rsp, DEFAULT_LOGIN_SERVER),
            cj: crypto::xchacha_encrypt_detached(&r.fk, &aad(b"|ciphersp"), &pt, &mut OsRng),
            ctr: next,
            signature: r.ssk.sign(b"temporary"),
        };
        record.signature = r.ssk.sign(&record.signed_bytes());
        let write = encoded(
            &json!({"action":if phase=="registration"{"registration_write"}else{"secret_write"},
            "session":id,"uid":DEFAULT_UID,"record":account_json(&record)}),
        )?;
        let prepare = encoded(
            &json!({"action":"ls_prepare","session":id,"uid":DEFAULT_UID,"old_vinfo":old,"new_vinfo":vinfo}),
        )?;
        let terminal = encoded(
            &json!({"action":"ls_store","session":id,"uid":DEFAULT_UID,"old_vinfo":old,"new_vinfo":vinfo}),
        )?;
        (write, Some(prepare), terminal, None)
    };
    Ok(Session {
        id,
        phase: phase.into(),
        prepare,
        write: vec![write],
        terminal,
        prepared: false,
        write_started: false,
        acknowledged: BTreeSet::new(),
        terminal_started: false,
        discard_decided: false,
        next_password,
        endpoints: cfg.providers.clone(),
        login_endpoint: cfg.login_server.clone(),
        thresholds: [cfg.n_sp, cfg.t_sp, cfg.q_sp],
    })
}

fn terminal_delivery(
    cfg: &Config,
    s: &Session,
    net: &mut ClientTransport,
    discard: bool,
) -> Result<(), String> {
    let start = Instant::now();
    let mut raw = s.terminal.clone();
    let terminal_providers = s.phase == "password_update";
    if discard {
        let mut v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        v["action"] = json!(if terminal_providers {
            "id_discard"
        } else {
            "ls_discard"
        });
        raw = encoded(&v)?;
    }
    // Password Update: Store goes to the acknowledgement set; Discard goes to
    // every provider that was sent the tentative tuple (all providers).
    let provider_targets: Vec<usize> = if discard {
        (0..cfg.providers.len()).collect()
    } else {
        s.acknowledged.iter().copied().collect()
    };
    // Transmit at time zero and retry through Delta. The final send is followed
    // by a full Delta wait. No endpoint response is requested or consumed.
    let mut last_send;
    let deadline = Instant::now() + Duration::from_millis(cfg.delta_ms);
    let mut successful = false;
    let mut failures = Vec::new();
    let mut delivered = BTreeSet::new();
    let mut round = 0;
    loop {
        if round > 0 {
            net.metrics.retries += if terminal_providers {
                provider_targets.len() as u64
            } else {
                1
            };
        }
        if terminal_providers {
            let sends = provider_targets
                .iter()
                .map(|&i| {
                    let addr = cfg.providers[i].clone();
                    let bytes = raw.clone();
                    let timeout = cfg.timeout_ms;
                    (
                        i,
                        thread::spawn(move || {
                            let mut m = Metrics::default();
                            let r = common::one_way(&addr, &bytes, timeout, &mut m);
                            (r, m)
                        }),
                    )
                })
                .collect::<Vec<_>>();
            for (i, send) in sends {
                let (result, m) = send.join().map_err(|_| "terminal worker panicked")?;
                net.metrics.merge(&m);
                match result {
                    Ok(()) => {
                        successful = true;
                        delivered.insert(i);
                    }
                    Err(e) => failures.push(e),
                }
            }
        } else {
            match common::one_way(&cfg.login_server, &raw, cfg.timeout_ms, &mut net.metrics) {
                Ok(()) => successful = true,
                Err(e) => failures.push(e),
            }
        }
        last_send = Instant::now();
        round += 1;
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(
            Duration::from_millis(cfg.retry_ms.max(1))
                .min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    thread::sleep(
        (last_send + Duration::from_millis(cfg.delta_ms)).saturating_duration_since(Instant::now()),
    );
    net.metrics.terminal_ns += ns(start);
    net.wait_ns += ns(start);
    if terminal_providers && discard {
        // A Password Update Discard only removes a tentative tuple that never
        // became current; the user's state is unaffected. Unreachable providers
        // keep the tuple until a later Discard or synchronization (availability
        // only), so they are reported but do not fail the abort.
        let undelivered = provider_targets.len() - delivered.len();
        net.metrics.discard_undelivered += undelivered as u64;
        if undelivered > 0 {
            net.note = Some(format!(
                "Discard not delivered to {undelivered} of {} providers",
                provider_targets.len()
            ));
        }
        return Ok(());
    }
    if !successful || !failures.is_empty() {
        return Err(format!(
            "terminal delivery outside synchronous assumption: {}",
            failures.join("; ")
        ));
    }
    Ok(())
}

fn client_crash(point: &str, stage: &str) {
    let name = format!("BENCH_CLIENT_CRASH_{point}_STAGE");
    if std::env::var(name).ok().is_some_and(|s| s == stage || s == "*") {
        std::process::exit(if point == "BEFORE" { 74 } else { 75 });
    }
}

fn resolve_discard(
    cfg: &Config,
    state_path: &Path,
    state: &mut ClientState,
    net: &mut ClientTransport,
    mut s: Session,
) -> Result<String, String> {
    // Persist the choice before the first terminal send. Re-running this helper
    // after a crash only repeats the identical Discard, which is idempotent.
    s.discard_decided = true;
    s.terminal_started = true;
    state.pending = Some(s.clone());
    persist(state_path, state)?;
    client_crash("BEFORE", "discard");
    if s.prepare.is_some() || (s.phase == "password_update" && s.write_started) {
        terminal_delivery(cfg, &s, net, true)?;
    }
    client_crash("AFTER", "discard");
    if s.phase == "password_update" && s.write_started {
        net.metrics.discards += 1;
        persist(&state_path.with_file_name("roupspa-last-discard.json"), &s)?;
    }
    state.pending = None;
    persist(state_path, state)?;
    Ok("cleanly_aborted".into())
}

fn advance(
    cfg: &Config,
    state_path: &Path,
    state: &mut ClientState,
    net: &mut ClientTransport,
    mode: &str,
) -> Result<String, String> {
    let mut s = state.pending.clone().ok_or("no unfinished session")?;
    if s.discard_decided {
        return resolve_discard(cfg, state_path, state, net, s);
    }
    if !s.prepared {
        if let Some(prep) = &s.prepare {
            client_crash("BEFORE", "ls_prepare");
            let reply = match net.single(cfg, prep) {
                Ok(reply) => reply,
                Err(e)
                    if [
                        "ExistingAccount",
                        "VerifierMismatch",
                        "ConflictingPendingOperation",
                        "MissingAccount",
                    ]
                    .contains(&e.as_str()) =>
                {
                    state.pending = None;
                    persist(state_path, state)?;
                    return Err(format!("Prepare rejected before provider writes: {e}"));
                }
                Err(e) => return Err(e),
            };
            if reply["ok"] != true || reply["session"] != s.id {
                return Err("Prepare response binding mismatch".into());
            }
        }
        s.prepared = true;
        state.pending = Some(s.clone());
        persist(state_path, state)?;
        client_crash("AFTER", "ls_prepare");
    }
    if mode == "prepare_only" {
        return Ok("unresolved".into());
    }
    if mode == "discard" {
        if s.terminal_started {
            return Err("Discard forbidden after terminal transmission started".into());
        }
        // Registration and Secret Update may be discarded only before the first
        // direct provider write. A Password Update writes tentative tuples only,
        // so it may be discarded at any point before Store.
        if s.write_started && s.phase != "password_update" {
            return Err("Discard forbidden after provider transmission started".into());
        }
        return resolve_discard(cfg, state_path, state, net, s);
    }
    let needed = if s.phase == "setup" { cfg.n_sp } else { cfg.q_sp };
    if s.acknowledged.len() < needed {
        client_crash("BEFORE", "provider_write");
        s.write_started = true;
        state.pending = Some(s.clone());
        persist(state_path, state)?;
        // Minimal fan-out may need a second wave after the first one timed out.
        let waves = if cfg.fanout == "minimal" { 2 } else { 1 };
        let end = Instant::now() + Duration::from_millis(cfg.timeout_ms.saturating_mul(waves));
        let mut round = 0;
        while s.acknowledged.len() < needed {
            let mut targets = (0..cfg.providers.len())
                .filter(|i| !s.acknowledged.contains(i))
                .collect::<Vec<_>>();
            if cfg.fanout == "minimal" && round == 0 && s.phase != "setup" {
                // Contact only as many providers as are still needed; later
                // rounds (after a missing acknowledgement) contact all others.
                targets.truncate(needed - s.acknowledged.len());
            } else if cfg.fanout == "minimal" && round == 1 && s.phase != "setup" {
                net.metrics.fanout_extensions += 1;
            }
            if round > 0 {
                net.metrics.retries += targets.len() as u64;
            }
            if s.phase == "setup" {
                // Distinct shares require distinct requests, concurrently.
                let (tx, rx) = mpsc::channel();
                for &i in &targets {
                    let addr = cfg.providers[i].clone();
                    let raw = s.write[i].clone();
                    let timeout = cfg.timeout_ms;
                    let tx = tx.clone();
                    net.workers.push(thread::spawn(move || {
                        let mut m = Metrics::default();
                        let r = common::request(&addr, &raw, timeout, &mut m);
                        let _ = tx.send((i, r));
                        m
                    }));
                }
                drop(tx);
                loop {
                    let waiting = Instant::now();
                    let received = rx.recv();
                    net.wait_ns += ns(waiting);
                    let Ok((i, r)) = received else {
                        break;
                    };
                    if r.is_ok_and(|v| v["ok"] == true && v["session"] == s.id) {
                        s.acknowledged.insert(i);
                        state.pending = Some(s.clone());
                        persist(state_path, state)?;
                    }
                }
            } else {
                // Accumulate acknowledgements as they arrive, including a
                // partial round; an interrupted client retains them on disk.
                let start = Instant::now();
                let (tx, rx) = mpsc::channel();
                for &i in &targets {
                    let addr = cfg.providers[i].clone();
                    let raw = s.write[0].clone();
                    let tx = tx.clone();
                    let timeout = cfg.timeout_ms;
                    net.workers.push(thread::spawn(move || {
                        let mut m = Metrics::default();
                        let r = common::request(&addr, &raw, timeout, &mut m);
                        let _ = tx.send((i, r));
                        m
                    }));
                }
                drop(tx);
                loop {
                    let waiting = Instant::now();
                    let received = rx.recv_timeout(Duration::from_millis(cfg.timeout_ms.max(1)));
                    net.wait_ns += ns(waiting);
                    let Ok((i, r)) = received else {
                        break;
                    };
                    if r.is_ok_and(|v| v["ok"] == true && v["session"] == s.id) {
                        s.acknowledged.insert(i);
                        state.pending = Some(s.clone());
                        persist(state_path, state)?;
                    }
                    if s.acknowledged.len() >= needed {
                        break;
                    }
                }
                net.metrics.quorum_ns += ns(start);
            }
            round += 1;
            if mode == "write_once" || Instant::now() >= end {
                break;
            }
            if s.acknowledged.len() < needed {
                let waiting = Instant::now();
                thread::sleep(Duration::from_millis(cfg.retry_ms.max(1)));
                net.wait_ns += ns(waiting);
            }
        }
        if s.acknowledged.len() < needed {
            if s.phase == "password_update" && mode == "normal" {
                // Password Update resolves a failed quorum by Discard: the
                // tentative tuple never became current and the user keeps the
                // old password. (Registration/Secret Update stay unresolved.)
                let acknowledged = s.acknowledged.len();
                let outcome = resolve_discard(cfg, state_path, state, net, s)?;
                let mut note =
                    format!("Password Update discarded: {acknowledged} acknowledgements, required {needed}");
                if let Some(extra) = net.note.take() {
                    note = format!("{note}; {extra}");
                }
                net.note = Some(note);
                return Ok(outcome);
            }
            return Err(format!("provider write started; {} durable acknowledgements, required {needed}; identical retry required",s.acknowledged.len()));
        }
        client_crash("AFTER", "provider_write");
    }
    if mode == "write_once" {
        return Ok("unresolved".into());
    }
    if s.phase == "setup" {
        let request: Value = serde_json::from_slice(&s.write[0]).map_err(|e| e.to_string())?;
        state.pinned_svk = Some(fixed(&request["svk"])?);
        state.initialized = true;
        state.pending = None;
        persist(state_path, state)?;
        return Ok("completed".into());
    }
    client_crash("BEFORE", "terminal");
    s.terminal_started = true;
    state.pending = Some(s.clone());
    persist(state_path, state)?;
    terminal_delivery(cfg, &s, net, false)?;
    client_crash("AFTER", "terminal");
    // One-way transport cannot prove processing outside the delay assumption.
    // Retain the exact terminal for independent audit and explicit redelivery.
    persist(&state_path.with_file_name("roupspa-last-session.json"), &s)?;
    if let Some(p) = s.next_password {
        state.password = p;
    }
    state.pending = None;
    persist(state_path, state)?;
    Ok("completed".into())
}

/// Run one actual session. Resuming sends the stored JSON byte vectors unchanged.
pub fn run(config: &Config, phase: &str, state_dir: &Path) -> RunResult {
    let start = Instant::now();
    let id = random_session();
    let mut out = RunResult::new("roupspa", phase, &id);
    let mut net = ClientTransport::default();
    let execute = (|| -> Result<String, String> {
        fs::create_dir_all(state_dir).map_err(|e| e.to_string())?;
        let path = state_dir.join("roupspa-client.json");
        let mut state = match fs::read(&path) {
            Ok(raw) => serde_json::from_slice::<ClientState>(&raw).map_err(|e| e.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ClientState::default(),
            Err(e) => return Err(e.to_string()),
        };
        if phase == "retry_terminal" && state.pending.is_none() {
            let raw = fs::read(state_dir.join("roupspa-last-session.json")).map_err(|e| e.to_string())?;
            state.pending = Some(serde_json::from_slice(&raw).map_err(|e| e.to_string())?);
            persist(&path, &state)?;
        }
        if phase == "authentication" {
            if state.pending.is_some() {
                return Err("an unresolved session blocks later operations".into());
            }
            let recovered = recover(config, &state, &mut net)?;
            let (_, secret) = read_account(config, &recovered, &mut net)?;
            let vinfo = crypto::hash_vinfo(&secret, DEFAULT_LOGIN_SERVER);
            let reply = net.single(
                config,
                &encoded(&json!({"action":"authenticate","uid":DEFAULT_UID,"vinfo":vinfo}))?,
            )?;
            return if reply["ok"] == true {
                Ok("completed".into())
            } else {
                Err("login server rejected verifier".into())
            };
        }
        if phase == "synchronize" || phase == "synchronization" {
            if state.pending.is_some() {
                return Err("an unresolved session blocks synchronization".into());
            }
            let req = encoded(&json!({"action":"synchronize","uid":DEFAULT_UID}))?;
            let repair = Instant::now();
            // Each recovering process performs its own peer round. Initiating
            // all repairs together would occupy every serial endpoint handler.
            for addr in &config.providers {
                let waiting = Instant::now();
                let result =
                    common::request(addr, &req, config.timeout_ms.saturating_mul(4), &mut net.metrics)?;
                net.wait_ns += ns(waiting);
                if result["ok"] != true {
                    return Err("synchronization rejected".into());
                }
            }
            net.metrics.repair_ns += ns(repair);
            return Ok("completed".into());
        }
        let mut base = phase;
        let mode = if let Some(p) = phase.strip_suffix("_prepare_only") {
            base = p;
            "prepare_only"
        } else if let Some(p) = phase.strip_suffix("_write_once") {
            base = p;
            "write_once"
        } else if phase == "discard" {
            "discard"
        } else {
            "normal"
        };
        if let Some(s) = &state.pending {
            out.session = s.id.clone();
            if s.endpoints != config.providers
                || s.login_endpoint != config.login_server
                || s.thresholds != [config.n_sp, config.t_sp, config.q_sp]
            {
                return Err("unfinished session is bound to its original endpoints and thresholds".into());
            }
            if phase != "resume" && phase != "retry_terminal" && phase != "discard" && base != s.phase {
                return Err(format!("unfinished {} session {}; use resume", s.phase, s.id));
            }
        } else {
            if phase == "resume" || phase == "discard" {
                return Err("no unfinished session".into());
            }
            if base == "setup" && state.initialized {
                return Err("already initialized".into());
            }
            let s = new_session(config, base, &state, &mut net, id)?;
            state.pending = Some(s);
            persist(&path, &state)?;
        }
        advance(config, &path, &mut state, &mut net, mode)
    })();
    // Draining outstanding concurrent requests is part of observable process
    // return time and is deliberately included, even if a quorum arrived sooner.
    let drain = Instant::now();
    net.finish();
    net.metrics.drain_ns += ns(drain);
    out.outcome = match execute {
        Ok(o) => {
            out.reason = net.note.take();
            o
        }
        Err(e) => {
            let pending = fs::read(state_dir.join("roupspa-client.json"))
                .ok()
                .and_then(|b| serde_json::from_slice::<ClientState>(&b).ok())
                .and_then(|s| s.pending);
            let outcome = if pending.is_some() || e.contains("PROTOCOL GAP:") {
                "unresolved"
            } else if e.starts_with("clean abort:") {
                // Stopped before any write: nothing to resolve.
                "cleanly_aborted"
            } else {
                "failed"
            };
            out.reason = Some(e);
            outcome.into()
        }
    };
    net.metrics.end_to_end_ns = ns(start);
    net.metrics.client_ns = net.metrics.end_to_end_ns.saturating_sub(net.wait_ns);
    out.metrics = net.metrics;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup_request(id: u32) -> Value {
        let s = SigningKey::generate(&mut OsRng);
        let key = [1u8; 32];
        let record = SignedIdentificationRecord {
            cid: crypto::xchacha_encrypt_detached(
                &key,
                b"test",
                &[0u8; IDENTIFICATION_PLAINTEXT_LEN],
                &mut OsRng,
            ),
            ctrid: 0,
            signature: None,
        };
        json!({"action":"setup","session":"11".repeat(32),"uid":DEFAULT_UID,"provider_id":id,
            "svk":s.verifying_key().to_bytes(),"share":Scalar::ONE.to_bytes(),"record":id_json(&record)})
    }
    #[test]
    fn provider_replay_exact_session_and_restart() {
        let req = setup_request(1);
        let mut p = ProviderState::new(1);
        p.apply(&req).unwrap();
        p.apply(&req).unwrap();
        let mut conflict = req.clone();
        conflict["share"] = json!(Scalar::from(2u64).to_bytes());
        assert!(p.apply(&conflict).is_err());
        let recovered =
            ProviderState::replay(1, vec![req.clone(), json!({"action":"restart_stale"})]).unwrap();
        assert_eq!(recovered.provider.share(DEFAULT_UID), Some(&Scalar::ONE));
        assert_eq!(
            recovered.provider.identification_status(DEFAULT_UID),
            Some(ReplicaStatus::Stale)
        );
        assert!(recovered
            .provider
            .identification_response(DEFAULT_UID, None)
            .is_err());
        let mut wrong = ProviderState::new(2);
        assert!(wrong.apply(&req).is_err());
    }
    #[test]
    fn synchronization_never_resurrects_a_locally_discarded_password_record() {
        let signing = SigningKey::generate(&mut OsRng);
        let mut setup = setup_request(1);
        setup["svk"] = json!(signing.verifying_key().to_bytes());
        let mut replacement = identification(&setup["record"]).unwrap();
        replacement.ctrid = 1;
        replacement.signature = Some(signing.sign(&replacement.signed_bytes(DEFAULT_UID)));
        let write = json!({"action":"id_write","session":"44".repeat(32),
            "uid":DEFAULT_UID,"record":id_json(&replacement)});
        let mut discard = write.clone();
        discard["action"] = json!("id_discard");
        let mut recovered = ProviderState::replay(
            1,
            vec![setup.clone(), write, discard, json!({"action":"restart_stale"})],
        )
        .unwrap();
        let malicious_max = json!({"action":"sync_id_install","uid":DEFAULT_UID,
            "record":id_json(&replacement)});
        assert!(recovered
            .apply(&malicious_max)
            .unwrap_err()
            .contains("locally discarded"));
        assert_eq!(recovered.provider.identifications[DEFAULT_UID].current.ctrid, 0);
        assert_eq!(
            recovered.provider.identification_status(DEFAULT_UID),
            Some(ReplicaStatus::Stale)
        );
        // The unsigned initialization remains the established local root.
        recovered
            .apply(&json!({"action":"sync_id_install","uid":DEFAULT_UID,
            "record":setup["record"]}))
            .unwrap();
        assert_eq!(
            recovered.provider.identification_status(DEFAULT_UID),
            Some(ReplicaStatus::Active)
        );
    }
    #[test]
    fn higher_signed_sync_candidate_requires_local_terminal_evidence() {
        let signing = SigningKey::generate(&mut OsRng);
        let mut setup = setup_request(1);
        setup["svk"] = json!(signing.verifying_key().to_bytes());
        let mut replacement = identification(&setup["record"]).unwrap();
        replacement.ctrid = 1;
        replacement.signature = Some(signing.sign(&replacement.signed_bytes(DEFAULT_UID)));
        let install = json!({"action":"sync_id_install","uid":DEFAULT_UID,
            "record":id_json(&replacement)});
        let write = json!({"action":"id_write","session":"77".repeat(32),
            "uid":DEFAULT_UID,"record":id_json(&replacement)});
        // This provider knows neither a Store nor a Discard. Even a genuine
        // signature must not authorize it to activate the higher candidate.
        let mut absent =
            ProviderState::replay(1, vec![setup.clone(), json!({"action":"restart_stale"})]).unwrap();
        assert!(absent
            .apply(&install)
            .unwrap_err()
            .contains("lacks locally processed Store"));
        assert_eq!(absent.provider.identifications[DEFAULT_UID].current.ctrid, 0);
        // A persisted tentative tuple is likewise not a terminal witness.
        let mut tentative = ProviderState::replay(
            1,
            vec![setup.clone(), write.clone(), json!({"action":"restart_stale"})],
        )
        .unwrap();
        assert!(tentative
            .apply(&install)
            .unwrap_err()
            .contains("lacks locally processed Store"));
        assert!(tentative.provider.identifications[DEFAULT_UID]
            .tentative_identification
            .is_some());
        // Normal local terminal processing supplies the evidence needed for a
        // later restart to reactivate this same current tuple.
        let mut store = write.clone();
        store["action"] = json!("id_store");
        let mut completed =
            ProviderState::replay(1, vec![setup, write, store, json!({"action":"restart_stale"})]).unwrap();
        completed.apply(&install).unwrap();
        assert_eq!(
            completed.provider.identification_status(DEFAULT_UID),
            Some(ReplicaStatus::Active)
        );
    }
    #[test]
    fn login_terminal_is_exact_session_bound_and_replayable() {
        let prepare = json!({"action":"ls_prepare","session":"22".repeat(32),"uid":DEFAULT_UID,"old_vinfo":null,"new_vinfo":vec![3u8;32]});
        let mut store = prepare.clone();
        store["action"] = json!("ls_store");
        let mut p = LoginState::default();
        p.apply(&prepare).unwrap();
        let mut wrong = store.clone();
        wrong["session"] = json!("33".repeat(32));
        assert!(p.apply(&wrong).is_err());
        p.apply(&store).unwrap();
        p.apply(&store).unwrap();
        assert!(p.server.authenticate(DEFAULT_UID, &[3u8; 32]));
        let mut discard = store.clone();
        discard["action"] = json!("ls_discard");
        assert!(p.apply(&discard).is_err());
        let p = LoginState::replay(vec![prepare, store]).unwrap();
        assert!(p.server.authenticate(DEFAULT_UID, &[3u8; 32]));
    }
}
