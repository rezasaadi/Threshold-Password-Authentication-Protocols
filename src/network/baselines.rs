//! Socket adapters for the existing PASTA-U and AugSSO cryptographic algorithms.
//! Setup provisions separate files; a service loads only its own scalar shares.
use super::common::{self, Config, Metrics, RunResult};
use augsso_bench::{benchmark as update, crypto_augsso as ac, crypto_core as acore, protocols::augsso as a};
use bls12_381::{G2Projective, Scalar as BScalar};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar as RScalar};
use pastau_bench::{crypto_core as pcore, crypto_pastau as pc, protocols::pastau as p};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
struct Cached {
    request: Vec<u8>,
    reply: Value,
    one_way: bool,
}

/// Each provider file contains only this provider's long-lived shares and account.
#[derive(Clone, Serialize, Deserialize)]
struct Node {
    scheme: String,
    id: u32,
    first_share: Vec<u8>,
    second_share: Vec<u8>,
    verify_key: Vec<u8>,
    client_id: Vec<u8>,
    record: Vec<u8>,
    sessions: BTreeMap<String, Vec<u8>>,
    cache: BTreeMap<String, Cached>,
}

#[derive(Serialize, Deserialize)]
struct Client {
    scheme: String,
    uid: Vec<u8>,
    password: Vec<u8>,
    verify_key: Vec<u8>,
    account_public: Vec<(u32, Vec<u8>)>,
    gamma_public: Vec<(u32, Vec<u8>)>,
    phi_public: Vec<(u32, Vec<u8>)>,
    pending: Option<String>,
}

fn save<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    common::atomic_write(
        path,
        &serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?,
    )
}
fn load<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?)
        .map_err(|e| e.to_string())
}
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("expected {N} bytes, received {}", bytes.len()))
}
fn scalar(bytes: &[u8]) -> Result<BScalar, String> {
    Option::<BScalar>::from(BScalar::from_bytes(&fixed(bytes)?)).ok_or("noncanonical BLS scalar".into())
}
fn rscalar(bytes: &[u8]) -> Result<RScalar, String> {
    Option::<RScalar>::from(RScalar::from_canonical_bytes(fixed(bytes)?))
        .ok_or("noncanonical Ristretto scalar".into())
}
fn random_session() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}
fn data(value: &Value) -> Result<Vec<u8>, String> {
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(error.into());
    }
    serde_json::from_value(value.get("data").cloned().ok_or("missing data")?).map_err(|e| e.to_string())
}
fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}
fn body(value: &Value) -> Result<Vec<u8>, String> {
    data(value)
}
fn reply(bytes: Vec<u8>) -> Value {
    json!({"data":bytes})
}

/// One trusted benchmark setup, outside timed operations. No service or client
/// later loads other providers' files. Existing state is never overwritten.
pub fn provision(scheme: &str, cfg: &Config, root: &Path) -> Result<(), String> {
    if !matches!(scheme, "pastau" | "augsso") {
        return Err("unknown baseline".into());
    }
    if root.join("client/baseline.json").exists() {
        return Err("baseline state already exists; choose a new state directory".into());
    }
    fs::create_dir_all(root.join("client")).map_err(|e| e.to_string())?;
    fs::create_dir_all(root.join("login")).map_err(|e| e.to_string())?;
    let mut uid = [0; 32];
    OsRng.fill_bytes(&mut uid);
    let mut client = Client {
        scheme: scheme.into(),
        uid: uid.to_vec(),
        password: b"correct horse battery staple".to_vec(),
        verify_key: vec![],
        account_public: vec![],
        gamma_public: vec![],
        phi_public: vec![],
        pending: None,
    };
    let (first, second, vk) = if scheme == "pastau" {
        let setup = p::global_setup(128, cfg.n_sp, cfg.t_sp, &mut OsRng);
        (
            setup
                .ttg_shares
                .iter()
                .map(|(_, x)| x.to_bytes().to_vec())
                .collect::<Vec<_>>(),
            vec![vec![]; cfg.n_sp],
            setup.vk.to_vec(),
        )
    } else {
        let setup = a::setup(cfg.n_sp, cfg.t_sp, &mut OsRng);
        client.gamma_public = setup
            .gamma_pub_shares
            .iter()
            .map(|(id, x)| (*id, ac::g2_to_bytes(x).to_vec()))
            .collect();
        client.phi_public = setup
            .phi_pub_shares
            .iter()
            .map(|(id, x)| (*id, ac::g2_to_bytes(x).to_vec()))
            .collect();
        (
            setup
                .gamma_shares
                .iter()
                .map(|(_, x)| x.to_bytes().to_vec())
                .collect(),
            setup
                .phi_shares
                .iter()
                .map(|(_, x)| x.to_bytes().to_vec())
                .collect(),
            ac::g2_to_bytes(&setup.gamma_pk).to_vec(),
        )
    };
    client.verify_key = vk.clone();
    for i in 0..cfg.n_sp {
        let dir = root.join(format!("provider-{}", i + 1));
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        save(
            &dir.join("baseline.json"),
            &Node {
                scheme: scheme.into(),
                id: (i + 1) as u32,
                first_share: first[i].clone(),
                second_share: second[i].clone(),
                verify_key: vk.clone(),
                client_id: vec![],
                record: vec![],
                sessions: BTreeMap::new(),
                cache: BTreeMap::new(),
            },
        )?;
    }
    save(
        &root.join("login/baseline.json"),
        &Node {
            scheme: scheme.into(),
            id: 0,
            first_share: vec![],
            second_share: vec![],
            verify_key: vk,
            client_id: vec![],
            record: vec![],
            sessions: BTreeMap::new(),
            cache: BTreeMap::new(),
        },
    )?;
    save(&root.join("client/baseline.json"), &client)
}

fn pastau_server(node: &Node) -> Result<p::PastauServer, String> {
    let mut server = p::PastauServer::new(node.id, scalar(&node.first_share)?);
    if !node.record.is_empty() {
        if node.record.len() != 64 {
            return Err("invalid persisted PASTA-U record".into());
        }
        server.store(
            p::ClientId(fixed(&node.client_id)?),
            &p::RegistrationMsg {
                server_id: node.id,
                k_i: rscalar(&node.record[..32])?,
                h_i: fixed(&node.record[32..])?,
            },
        );
    }
    Ok(server)
}
fn augsso_server(node: &Node, cfg: &Config) -> Result<a::AugSsoServer, String> {
    let gamma = scalar(&node.first_share)?;
    let phi = scalar(&node.second_share)?;
    let mut server = a::AugSsoServer::new(
        node.id,
        gamma,
        phi,
        G2Projective::generator() * gamma,
        G2Projective::generator() * phi,
        a::PublicParams {
            n: cfg.n_sp,
            t: cfg.t_sp,
            cnt: u64::MAX / 2,
            caf: u64::MAX / 2,
        },
    );
    if !node.record.is_empty() {
        if node.record.len() != 64 {
            return Err("invalid persisted AugSSO record".into());
        }
        server.store(
            a::ClientId(fixed(&node.client_id)?),
            &a::RegistrationMsg {
                server_id: node.id,
                sk_i: scalar(&node.record[..32])?,
                rpk: fixed(&node.record[32..])?,
            },
        );
    }
    Ok(server)
}

fn blob<const N: usize>(value: &acore::CtBlob<N>) -> Vec<u8> {
    join(&[&value.nonce, &value.ct, &value.tag])
}
fn ablob<const N: usize>(bytes: &[u8]) -> Result<acore::CtBlob<N>, String> {
    if bytes.len() != acore::NONCE_LEN + N + acore::TAG_LEN {
        return Err("invalid ciphertext size".into());
    }
    Ok(acore::CtBlob {
        nonce: fixed(&bytes[..24])?,
        ct: fixed(&bytes[24..24 + N])?,
        tag: fixed(&bytes[24 + N..])?,
    })
}
fn pblob<const N: usize>(bytes: &[u8]) -> Result<pc::CtBlob<N>, String> {
    if bytes.len() != pc::NONCE_LEN + N + pc::TAG_LEN {
        return Err("invalid ciphertext size".into());
    }
    Ok(pc::CtBlob {
        nonce: fixed(&bytes[..24])?,
        ct: fixed(&bytes[24..24 + N])?,
        tag: fixed(&bytes[24 + N..])?,
    })
}

fn handle_pastau(
    node: &mut Node,
    server: &mut Option<p::PastauServer>,
    op: &str,
    bytes: &[u8],
) -> Result<(Value, bool), String> {
    match op {
        "register" => {
            if bytes.len() != 96 {
                return Err("invalid registration size".into());
            }
            let uid = p::ClientId(fixed(&bytes[..32])?);
            let message = p::RegistrationMsg {
                server_id: node.id,
                k_i: rscalar(&bytes[32..64])?,
                h_i: fixed(&bytes[64..])?,
            };
            let server = server.as_mut().ok_or("missing provider")?;
            server.store(uid, &message);
            let rec = server.get_record(uid).ok_or("registration failed")?;
            node.client_id = uid.0.to_vec();
            node.record = join(&[&rec.k_i.to_bytes(), &rec.h_i]);
            Ok((reply(vec![]), true))
        }
        "toprf" | "token" | "token-variable" => {
            if bytes.len() < 64 {
                return Err("invalid request size".into());
            }
            let server = server.as_ref().ok_or("missing provider")?;
            let uid = p::ClientId(fixed(&bytes[..32])?);
            let req = fixed(&bytes[32..64])?;
            if op == "toprf" {
                return Ok((
                    reply(
                        p::respond_toprf_only(server, uid, &req)
                            .ok_or("TOPRF rejected")?
                            .to_vec(),
                    ),
                    false,
                ));
            }
            let resp = if op == "token" {
                p::respond(server, uid, fixed(&bytes[64..])?, &req, &mut OsRng)
            } else {
                p::respond_var_payload(server, uid, &bytes[64..], &req, &mut OsRng)
            }
            .ok_or("token request rejected")?;
            Ok((
                reply(join(&[
                    &resp.server_id.to_be_bytes(),
                    &resp.z_i,
                    &resp.ctxt_i.nonce,
                    &resp.ctxt_i.ct,
                    &resp.ctxt_i.tag,
                ])),
                false,
            ))
        }
        "update" => {
            if bytes.len() < 32 + pc::TTG_TOKEN_LEN {
                return Err("invalid update size".into());
            }
            let uid = p::ClientId(fixed(&bytes[..32])?);
            let token = fixed(&bytes[32..32 + pc::TTG_TOKEN_LEN])?;
            let server = server.as_mut().ok_or("missing provider")?;
            if !p::password_update_handle(
                server,
                &fixed(&node.verify_key)?,
                &bytes[32 + pc::TTG_TOKEN_LEN..],
                &token,
            ) {
                return Err("password update rejected".into());
            }
            let rec = server.get_record(uid).ok_or("missing updated record")?;
            node.record = join(&[&rec.k_i.to_bytes(), &rec.h_i]);
            // PASTA-U's final submission is one-way, no RoUpSPA terminal stage.
            Ok((reply(vec![]), true))
        }
        "verify" => {
            if bytes.len() != 32 + 32 + pc::TTG_TOKEN_LEN {
                return Err("invalid verification size".into());
            }
            let valid = p::verify(
                &fixed(&node.verify_key)?,
                p::ClientId(fixed(&bytes[..32])?),
                fixed(&bytes[32..64])?,
                &fixed(&bytes[64..])?,
            );
            if !valid {
                return Err("invalid PASTA-U token".into());
            }
            Ok((reply(vec![1]), false))
        }
        _ => Err("unknown PASTA-U operation".into()),
    }
}

fn handle_augsso(
    node: &mut Node,
    server: &mut Option<a::AugSsoServer>,
    op: &str,
    key: &str,
    bytes: &[u8],
) -> Result<(Value, bool), String> {
    match op {
        "register" => {
            if bytes.len() != 96 {
                return Err("invalid registration size".into());
            }
            let uid = a::ClientId(fixed(&bytes[..32])?);
            let message = a::RegistrationMsg {
                server_id: node.id,
                sk_i: scalar(&bytes[32..64])?,
                rpk: fixed(&bytes[64..])?,
            };
            let server = server.as_mut().ok_or("missing provider")?;
            server.store(uid, &message);
            let rec = server.get_record(uid).ok_or("registration failed")?;
            node.client_id = uid.0.to_vec();
            node.record = join(&[&rec.sk_i.to_bytes(), &rec.rpk]);
            Ok((reply(vec![]), true))
        }
        "auth1" => {
            if bytes.len() != a::PLD_LEN + a::BPW_LEN {
                return Err("invalid auth1 size".into());
            }
            let (resp, sess) = a::respond1(
                server.as_ref().ok_or("missing provider")?,
                &a::ClientRequest {
                    pld: fixed(&bytes[..64])?,
                    bpw: fixed(&bytes[64..])?,
                },
                &mut OsRng,
            )
            .ok_or("auth1 rejected")?;
            node.sessions
                .insert(key.into(), join(&[&sess.ek, &sess.ch, &sess.pld]));
            Ok((
                reply(join(&[
                    &resp.server_id.to_be_bytes(),
                    &resp.sigma_i,
                    &ac::pke_serialize(&resp.ct_res),
                ])),
                false,
            ))
        }
        "auth2" => {
            let sess_bytes = node
                .sessions
                .get(&key.replace(":auth2", ":auth1"))
                .ok_or("no durable auth1 session")?;
            if sess_bytes.len() != 128 {
                return Err("invalid durable auth session".into());
            }
            let sess = a::ServerSession {
                server_id: node.id,
                ek: fixed(&sess_bytes[..32])?,
                ch: fixed(&sess_bytes[32..64])?,
                pld: fixed(&sess_bytes[64..])?,
            };
            let resp = a::respond2(
                server.as_ref().ok_or("missing provider")?,
                &sess,
                &ablob(bytes)?,
                &mut OsRng,
            )
            .ok_or("auth2 rejected")?;
            Ok((
                reply(join(&[&resp.server_id.to_be_bytes(), &blob(&resp.ct_tkn)])),
                false,
            ))
        }
        "update1" => {
            if bytes.len() != 32 + 2 * a::BPW_LEN {
                return Err("invalid update1 size".into());
            }
            let req = update::PasswordUpdateRequest {
                client_id: a::ClientId(fixed(&bytes[..32])?),
                bpw_old: fixed(&bytes[32..80])?,
                bpw_new: fixed(&bytes[80..])?,
            };
            let (resp, sess) = update::password_update_respond1(
                server.as_ref().ok_or("missing provider")?,
                &req,
                &mut OsRng,
            )
            .ok_or("update1 rejected")?;
            node.sessions.insert(
                key.into(),
                join(&[&sess.client_id.0, &sess.bpw_new, &sess.ek, &sess.ch]),
            );
            Ok((
                reply(join(&[
                    &resp.server_id.to_be_bytes(),
                    &resp.sigma_old_i,
                    &ac::pke_serialize(&resp.ct_res),
                ])),
                false,
            ))
        }
        "update2" => {
            let sess_bytes = node
                .sessions
                .get(&key.replace(":update2", ":update1"))
                .ok_or("no durable update1 session")?;
            if sess_bytes.len() != 144 {
                return Err("invalid durable update session".into());
            }
            let sess = update::PasswordUpdateServerSession {
                server_id: node.id,
                client_id: a::ClientId(fixed(&sess_bytes[..32])?),
                bpw_new: fixed(&sess_bytes[32..80])?,
                ek: fixed(&sess_bytes[80..112])?,
                ch: fixed(&sess_bytes[112..])?,
            };
            let server = server.as_mut().ok_or("missing provider")?;
            let resp =
                update::password_update_respond2(server, &sess, &ablob(bytes)?).ok_or("update2 rejected")?;
            let sk_i = server
                .get_record(sess.client_id)
                .ok_or("missing update account")?
                .sk_i;
            server.store(
                sess.client_id,
                &a::RegistrationMsg {
                    server_id: server.id,
                    sk_i,
                    rpk: resp.new_rpk,
                },
            );
            node.record[32..].copy_from_slice(&resp.new_rpk);
            Ok((
                reply(join(&[
                    &resp.server_id.to_be_bytes(),
                    &resp.sigma_phi_i,
                    &resp.new_rpk,
                ])),
                false,
            ))
        }
        "verify" => {
            if bytes.len() != a::PLD_LEN + ac::G1_LEN {
                return Err("invalid token size".into());
            }
            let token = a::Token {
                pld: fixed(&bytes[..64])?,
                tkn: fixed(&bytes[64..])?,
            };
            let vk = ac::g2_from_bytes(&fixed(&node.verify_key)?).ok_or("invalid token-server key")?;
            if !a::verify_token(&vk, &token) {
                return Err("invalid AugSSO token".into());
            }
            Ok((reply(vec![1]), false))
        }
        _ => Err("unknown AugSSO operation".into()),
    }
}

pub fn service(
    scheme: &str,
    role: &str,
    id: u32,
    listen: &str,
    state: &Path,
    cfg: &Config,
) -> Result<(), String> {
    let path = state.join("baseline.json");
    let mut node: Node = load(&path)?;
    if node.scheme != scheme || node.id != if role == "provider" { id } else { 0 } {
        return Err("state scheme/role/id mismatch".into());
    }
    if !matches!(role, "provider" | "login" | "token") {
        return Err("unknown baseline role".into());
    }
    let mut pastau = if role == "provider" && scheme == "pastau" {
        Some(pastau_server(&node)?)
    } else {
        None
    };
    let mut augsso = if role == "provider" && scheme == "augsso" {
        Some(augsso_server(&node, cfg)?)
    } else {
        None
    };
    common::serve(listen, state, |value| {
        let op = value
            .get("op")
            .and_then(Value::as_str)
            .ok_or("missing operation")?;
        if op == "ping" {
            return Ok((reply(vec![]), false));
        }
        if (role == "provider" && op == "verify") || (role != "provider" && op != "verify") {
            return Err("operation sent to wrong role".into());
        }
        let session = value
            .get("session")
            .and_then(Value::as_str)
            .ok_or("missing session")?;
        let key = format!("{session}:{op}");
        let exact = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        if let Some(cached) = node.cache.get(&key) {
            if cached.request != exact {
                return Err("conflicting reuse of baseline session/stage".into());
            }
            return Ok((cached.reply.clone(), cached.one_way));
        }
        let bytes = body(value)?;
        let mut candidate = node.clone();
        // Clone only local endpoint state so an unsuccessful durable write cannot
        // leave an in-memory transition acknowledged by a later request.
        let mut next_pastau = pastau.clone();
        let mut next_augsso = augsso.clone();
        let (reply, one_way) = if scheme == "pastau" {
            handle_pastau(&mut candidate, &mut next_pastau, op, &bytes)?
        } else {
            handle_augsso(&mut candidate, &mut next_augsso, op, &key, &bytes)?
        };
        candidate.cache.insert(
            key,
            Cached {
                request: exact,
                reply: reply.clone(),
                one_way,
            },
        );
        save(&path, &candidate)?;
        node = candidate;
        pastau = next_pastau;
        augsso = next_augsso;
        Ok((reply, one_way))
    })
}

fn rpc(
    addr: &str,
    request: &[u8],
    cfg: &Config,
    metrics: &mut Metrics,
    one_way: bool,
) -> Result<Value, String> {
    let deadline = Instant::now() + Duration::from_millis(cfg.timeout_ms);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now()).as_millis() as u64;
        if remaining == 0 {
            metrics.timeouts += 1;
            return Err(format!("request deadline at {addr}"));
        }
        let result = if one_way {
            common::one_way(addr, request, remaining, metrics).map(|_| reply(vec![]))
        } else {
            common::request(addr, request, remaining, metrics)
        };
        match result {
            Ok(value) => {
                data(&value)?;
                return Ok(value);
            }
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(e);
                }
                metrics.retries += 1;
                thread::sleep(Duration::from_millis(cfg.retry_ms.min(remaining)));
            }
        }
    }
}

fn stage(
    cfg: &Config,
    ids: &[u32],
    session: &str,
    op: &str,
    payloads: Vec<Vec<u8>>,
    one_way: bool,
    metrics: &mut Metrics,
) -> Result<Vec<Vec<u8>>, String> {
    let start = Instant::now();
    let outputs = thread::scope(|scope| {
        let handles: Vec<_> = ids
            .iter()
            .zip(payloads)
            .map(|(id, bytes)| {
                scope.spawn(move || {
                    let mut local = Metrics::default();
                    let request = serde_json::to_vec(&json!({"op":op,"session":session,"data":bytes}))
                        .map_err(|e| e.to_string());
                    let answer = request
                        .and_then(|req| rpc(&cfg.providers[*id as usize - 1], &req, cfg, &mut local, one_way))
                        .and_then(|value| data(&value));
                    (answer, local)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .map_err(|_| "baseline request thread panicked".to_string())
            })
            .collect::<Vec<_>>()
    });
    metrics.quorum_ns += start.elapsed().as_nanos() as u64;
    let mut replies = Vec::new();
    let mut error = None;
    for output in outputs {
        match output {
            Ok((res, local)) => {
                metrics.merge(&local);
                match res {
                    Ok(bytes) => replies.push(bytes),
                    Err(e) => error = Some(e),
                }
            }
            Err(e) => error = Some(e),
        }
    }
    if let Some(e) = error {
        Err(e)
    } else {
        Ok(replies)
    }
}

fn decode_presponse(bytes: &[u8]) -> Result<p::ServerResponse, String> {
    if bytes.len() != 4 + 32 + 24 + pc::TTG_TOKEN_LEN + 16 {
        return Err("invalid PASTA-U response size".into());
    }
    Ok(p::ServerResponse {
        server_id: u32::from_be_bytes(fixed(&bytes[..4])?),
        z_i: fixed(&bytes[4..36])?,
        ctxt_i: pblob(&bytes[36..])?,
    })
}
fn toprf(
    cfg: &Config,
    session: &str,
    op: &str,
    uid: &[u8],
    password: &[u8],
    metrics: &mut Metrics,
) -> Result<[u8; 32], String> {
    let ids: Vec<u32> = (1..=cfg.t_sp as u32).collect();
    let rho = pcore::random_scalar(&mut OsRng);
    let req = pc::toprf_encode(password, rho).compress().to_bytes();
    // The wrapper session suffix separates the two independent TOPRF rounds.
    let replies = stage(
        cfg,
        &ids,
        &format!("{session}-{op}"),
        "toprf",
        vec![join(&[uid, &req]); ids.len()],
        false,
        metrics,
    )?;
    let partials = replies
        .iter()
        .map(|bytes| {
            CompressedRistretto(fixed(bytes)?)
                .decompress()
                .ok_or("invalid TOPRF point".into())
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(pcore::toprf_client_eval_from_partials(
        password,
        rho,
        &partials,
        &pcore::lagrange_coeffs_at_zero(&ids),
    ))
}
fn token(
    cfg: &Config,
    session: &str,
    uid: &[u8],
    password: &[u8],
    payload: &[u8],
    variable: bool,
    metrics: &mut Metrics,
) -> Result<pc::TtgToken, String> {
    let ids: Vec<u32> = (1..=cfg.t_sp as u32).collect();
    let rho = pcore::random_scalar(&mut OsRng);
    let req = pc::toprf_encode(password, rho).compress().to_bytes();
    let replies = stage(
        cfg,
        &ids,
        session,
        if variable { "token-variable" } else { "token" },
        vec![join(&[uid, &req, payload]); ids.len()],
        false,
        metrics,
    )?;
    let responses = replies
        .iter()
        .map(|bytes| decode_presponse(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    p::finalize(
        &p::ClientState {
            c: p::ClientId(fixed(uid)?),
            password: password.to_vec(),
            rho,
            t_set: ids,
        },
        &responses,
    )
    .ok_or("PASTA-U token generation failed".into())
}
fn public_shares(entries: &[(u32, Vec<u8>)]) -> Result<Vec<(u32, ac::G2)>, String> {
    entries
        .iter()
        .map(|(id, bytes)| {
            Ok((
                *id,
                ac::g2_from_bytes(&fixed(bytes)?).ok_or("invalid public share")?,
            ))
        })
        .collect()
}

fn execute(
    scheme: &str,
    cfg: &Config,
    phase: &str,
    session: &str,
    client: &mut Client,
    metrics: &mut Metrics,
    additional_wait: &mut u64,
) -> Result<(), String> {
    let all: Vec<u32> = (1..=cfg.n_sp as u32).collect();
    let threshold: Vec<u32> = (1..=cfg.t_sp as u32).collect();
    // "setup" is the cross-scheme name for provisioning per-server key material
    // to all n servers; for PASTA-U and AugSSO this is their registration.
    if phase == "registration" || phase == "reg" || phase == "setup" {
        if scheme == "pastau" {
            let reg = p::registration(cfg.n_sp, cfg.t_sp, &client.password, &mut OsRng);
            let payloads = reg
                .msgs
                .iter()
                .map(|msg| join(&[&client.uid, &msg.k_i.to_bytes(), &msg.h_i]))
                .collect();
            stage(cfg, &all, session, "register", payloads, true, metrics)?;
        } else {
            let reg = a::registration_client(cfg.n_sp, cfg.t_sp, &client.password, &mut OsRng);
            let payloads = reg
                .msgs
                .iter()
                .map(|msg| join(&[&client.uid, &msg.sk_i.to_bytes(), &msg.rpk]))
                .collect();
            client.account_public = reg
                .msgs
                .iter()
                .map(|msg| {
                    (
                        msg.server_id,
                        ac::g2_to_bytes(&(G2Projective::generator() * msg.sk_i)).to_vec(),
                    )
                })
                .collect();
            stage(cfg, &all, session, "register", payloads, true, metrics)?;
        }
        return Ok(());
    }
    if phase == "authentication" || phase == "auth" {
        let mut x = [0; 32];
        OsRng.fill_bytes(&mut x);
        let verify_bytes = if scheme == "pastau" {
            let tk = token(cfg, session, &client.uid, &client.password, &x, false, metrics)?;
            join(&[&client.uid, &x, &tk])
        } else {
            let pld = fixed(&join(&[&x, &client.uid]))?;
            let (st, req) = a::request(&client.password, pld, &threshold, &mut OsRng);
            let replies = stage(
                cfg,
                &threshold,
                session,
                "auth1",
                vec![join(&[&req.pld, &req.bpw]); threshold.len()],
                false,
                metrics,
            )?;
            let responses = replies
                .iter()
                .map(|bytes| {
                    if bytes.len() != 4 + 48 + ac::pke_ct_len::<{ a::PKE_PT_LEN }>() {
                        return Err("invalid auth1 response".into());
                    }
                    Ok(a::ServerResponse1 {
                        server_id: u32::from_be_bytes(fixed(&bytes[..4])?),
                        sigma_i: fixed(&bytes[4..52])?,
                        ct_res: ac::pke_deserialize(&bytes[52..]).ok_or("invalid PKE response")?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let phase1 = a::client_phase1(
                &st,
                &req,
                &responses,
                &public_shares(&client.account_public)?,
                None,
                &mut OsRng,
            )
            .ok_or("AugSSO password/challenge verification failed")?;
            let payloads = threshold
                .iter()
                .map(|id| {
                    phase1
                        .ct_ch
                        .iter()
                        .find(|(sid, _)| sid == id)
                        .map(|(_, ct)| blob(ct))
                        .ok_or("missing provider challenge".into())
                })
                .collect::<Result<Vec<_>, String>>()?;
            let replies = stage(cfg, &threshold, session, "auth2", payloads, false, metrics)?;
            let responses = replies
                .iter()
                .map(|bytes| {
                    if bytes.len() != 4 + a::CTTKN_LEN {
                        return Err("invalid auth2 response".into());
                    }
                    Ok(a::ServerResponse2 {
                        server_id: u32::from_be_bytes(fixed(&bytes[..4])?),
                        ct_tkn: ablob(&bytes[4..])?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let tk = a::client_finalize(&st, &phase1, &responses, &public_shares(&client.gamma_public)?)
                .ok_or("AugSSO token generation failed")?;
            join(&[&tk.pld, &tk.tkn])
        };
        let request = serde_json::to_vec(&json!({"op":"verify","session":session,"data":verify_bytes}))
            .map_err(|e| e.to_string())?;
        let wait_start = Instant::now();
        let verified = rpc(&cfg.login_server, &request, cfg, metrics, false);
        *additional_wait += wait_start.elapsed().as_nanos() as u64;
        verified?;
        return Ok(());
    }
    if phase != "password_update" && phase != "update" {
        return Err("baseline supports registration, authentication, password_update".into());
    }
    let new_password = format!("updated password {session}").into_bytes();
    if scheme == "pastau" {
        let old_h = toprf(cfg, session, "old", &client.uid, &client.password, metrics)?;
        let new_h = toprf(cfg, session, "new", &client.uid, &new_password, metrics)?;
        let mut update_body = Vec::new();
        for id in &all {
            let old_hi = pc::hash_hi(&old_h, *id);
            let new_hi = pc::hash_hi(&new_h, *id);
            let plaintext = fixed::<{ p::UPDATE_PT_LEN }>(&join(&[&old_hi, &new_hi]))?;
            let ct = pc::xchacha_encrypt_detached(&old_hi, &[], &plaintext, &mut OsRng);
            update_body.extend_from_slice(&join(&[&ct.nonce, &ct.ct, &ct.tag]));
        }
        let tk = token(
            cfg,
            session,
            &client.uid,
            &client.password,
            &update_body,
            true,
            metrics,
        )?;
        let pld3 = join(&[&update_body, &client.uid]);
        if !pc::ttg_verify(&fixed(&client.verify_key)?, &pld3, &tk) {
            return Err("invalid PASTA-U update token".into());
        }
        stage(
            cfg,
            &all,
            session,
            "update",
            vec![join(&[&client.uid, &tk, &pld3]); all.len()],
            true,
            metrics,
        )?;
    } else {
        let (st, req) = update::password_update_request_for(
            a::ClientId(fixed(&client.uid)?),
            cfg.n_sp,
            &threshold,
            &client.password,
            &new_password,
            &mut OsRng,
        );
        let replies = stage(
            cfg,
            &all,
            session,
            "update1",
            vec![join(&[&req.client_id.0, &req.bpw_old, &req.bpw_new]); all.len()],
            false,
            metrics,
        )?;
        let responses = replies
            .iter()
            .map(|bytes| {
                if bytes.len() != 4 + 48 + ac::pke_ct_len::<{ update::UPDATE_PKE_PT_LEN }>() {
                    return Err("invalid update1 response".into());
                }
                Ok(update::PasswordUpdateResponse1 {
                    server_id: u32::from_be_bytes(fixed(&bytes[..4])?),
                    sigma_old_i: fixed(&bytes[4..52])?,
                    ct_res: ac::pke_deserialize(&bytes[52..]).ok_or("invalid update PKE response")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let phase1 = update::password_update_client_phase1(
            &st,
            &req,
            &responses,
            &public_shares(&client.account_public)?,
            None,
            &mut OsRng,
        )
        .ok_or("AugSSO update challenge verification failed")?;
        let payloads = all
            .iter()
            .map(|id| {
                phase1
                    .ct_ch
                    .iter()
                    .find(|(sid, _)| sid == id)
                    .map(|(_, ct)| blob(ct))
                    .ok_or("missing update challenge".into())
            })
            .collect::<Result<Vec<_>, String>>()?;
        let replies = stage(cfg, &all, session, "update2", payloads, false, metrics)?;
        let responses = replies
            .iter()
            .map(|bytes| {
                if bytes.len() != 4 + 48 + 32 {
                    return Err("invalid update2 response".into());
                }
                Ok(update::PasswordUpdateResponse2 {
                    server_id: u32::from_be_bytes(fixed(&bytes[..4])?),
                    sigma_phi_i: fixed(&bytes[4..52])?,
                    new_rpk: fixed(&bytes[52..])?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        update::password_update_client_finalize(&st, &req, &responses, &public_shares(&client.phi_public)?)
            .ok_or("AugSSO update finalization failed")?;
    }
    client.password = new_password;
    Ok(())
}

pub fn run(scheme: &str, cfg: &Config, phase: &str, state: &Path) -> RunResult {
    let session = random_session();
    let mut result = RunResult::new(scheme, phase, &session);
    let start = Instant::now();
    let path = state.join("baseline.json");
    let mut additional_wait = 0;
    let attempted = (|| {
        let mut client: Client = load(&path)?;
        if client.scheme != scheme {
            return Err("client state belongs to another scheme".into());
        }
        if let Some(pending) = &client.pending {
            return Err(format!(
                "unfinished baseline session {pending}; inspect provider durable logs before recovery"
            ));
        }
        client.pending = Some(session.clone());
        save(&path, &client)?;
        execute(
            scheme,
            cfg,
            phase,
            &session,
            &mut client,
            &mut result.metrics,
            &mut additional_wait,
        )?;
        client.pending = None;
        save(&path, &client)
    })();
    result.metrics.end_to_end_ns = start.elapsed().as_nanos() as u64;
    result.metrics.client_ns = result
        .metrics
        .end_to_end_ns
        .saturating_sub(result.metrics.quorum_ns.saturating_add(additional_wait));
    match attempted {
        Ok(()) => result.outcome = "completed".into(),
        Err(e) => {
            result.outcome = "unresolved".into();
            result.reason = Some(e);
        }
    }
    result
}
