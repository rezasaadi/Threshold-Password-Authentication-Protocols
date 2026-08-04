use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::paper_crypto::*;

#[derive(Clone)]
pub struct Server {
    pub id: u32,
    pub top_share: ToprfShare,
    pub ttg_share: ShoupShare,
    pub h_i: [u8; 32],
}

#[derive(Clone)]
pub struct Fixture {
    pub n: usize,
    pub t: usize,
    pub password: Vec<u8>,
    pub new_password: Vec<u8>,
    pub client_id: Vec<u8>,
    pub payload: Vec<u8>,
    pub top: ToprfSetup,
    pub ttg: ShoupSetup,
    pub servers: Vec<Server>,
}

#[derive(Clone)]
pub struct TokenResponse {
    pub id: u32,
    pub z_i: BigUint,
    pub encrypted_partial: Vec<u8>,
    pub iv: [u8; 16],
}

pub fn setup_fixture_with_ttg<R: RngCore + CryptoRng>(
    n: usize,
    t: usize,
    ttg: ShoupSetup,
    rng: &mut R,
) -> Result<Fixture, CryptoError> {
    let password = b"correct horse battery staple".to_vec();
    let new_password = b"new correct horse battery staple".to_vec();
    let client_id = b"user@example".to_vec();
    let payload = b"ssh-challenge-payload".to_vec();
    let top = toprf_setup(n, t, rng)?;
    let (enc, rho) = toprf_encode(&top.params, &password, rng);
    let ids: Vec<u32> = (1..=t as u32).collect();
    let zs: Vec<BigUint> = ids
        .iter()
        .map(|&i| toprf_eval(&top.params, &top.shares[(i - 1) as usize], &enc))
        .collect();
    let h = toprf_combine(&top.params, &password, &rho, &ids, &zs)?;
    let servers = (0..n)
        .map(|i| Server {
            id: (i + 1) as u32,
            top_share: top.shares[i].clone(),
            ttg_share: ttg.shares[i].clone(),
            h_i: derive_hi(&h, (i + 1) as u32),
        })
        .collect();
    Ok(Fixture {
        n,
        t,
        password,
        new_password,
        client_id,
        payload,
        top,
        ttg,
        servers,
    })
}

fn signed_message(payload: &[u8], client_id: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + client_id.len());
    v.extend_from_slice(payload);
    v.extend_from_slice(client_id);
    v
}

pub fn token_generation<R: RngCore + CryptoRng>(
    fx: &Fixture,
    payload: &[u8],
    password: &[u8],
    rng: &mut R,
) -> Result<BigUint, CryptoError> {
    let ids: Vec<u32> = (1..=fx.t as u32).collect();
    let (enc, rho) = toprf_encode(&fx.top.params, password, rng);
    let msg = signed_message(payload, &fx.client_id);
    let modulus_bytes = ((fx.ttg.public.n.bits() + 7) / 8) as usize;
    let em = emsa_pkcs1_v1_5_sha256(&msg, modulus_bytes)?;
    let mut responses = Vec::with_capacity(fx.t);
    for &id in &ids {
        let srv = &fx.servers[(id - 1) as usize];
        let z_i = toprf_eval(&fx.top.params, &srv.top_share, &enc);
        let partial = shoup_part_eval(&fx.ttg.public, &srv.ttg_share, &em);
        let mut bytes = partial.value.to_bytes_be();
        if bytes.len() < modulus_bytes {
            let mut p = vec![0u8; modulus_bytes - bytes.len()];
            p.extend_from_slice(&bytes);
            bytes = p;
        }
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);
        aes128_ofb_apply(&srv.h_i, &iv, &mut bytes);
        responses.push(TokenResponse {
            id,
            z_i,
            encrypted_partial: bytes,
            iv,
        });
    }
    let zs: Vec<BigUint> = responses.iter().map(|r| r.z_i.clone()).collect();
    let h = toprf_combine(&fx.top.params, password, &rho, &ids, &zs)?;
    let mut partials = Vec::with_capacity(fx.t);
    for r in responses {
        let mut bytes = r.encrypted_partial;
        let hi = derive_hi(&h, r.id);
        aes128_ofb_apply(&hi, &r.iv, &mut bytes);
        partials.push(ShoupPartial {
            id: r.id,
            value: BigUint::from_bytes_be(&bytes),
        });
    }
    shoup_combine(&fx.ttg.public, &em, &partials)
}

pub fn verify_token(fx: &Fixture, payload: &[u8], sig: &BigUint) -> Result<bool, CryptoError> {
    let msg = signed_message(payload, &fx.client_id);
    let em = emsa_pkcs1_v1_5_sha256(&msg, ((fx.ttg.public.n.bits() + 7) / 8) as usize)?;
    Ok(shoup_verify(&fx.ttg.public, &em, sig))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordUpdateResult {
    pub payload_len: usize,
    pub updated: usize,
}

pub fn password_update<R: RngCore + CryptoRng>(
    fx: &mut Fixture,
    rng: &mut R,
) -> Result<PasswordUpdateResult, CryptoError> {
    let ids: Vec<u32> = (1..=fx.t as u32).collect();
    let (e1, r1) = toprf_encode(&fx.top.params, &fx.password, rng);
    let z1: Vec<_> = ids
        .iter()
        .map(|&id| toprf_eval(&fx.top.params, &fx.servers[(id - 1) as usize].top_share, &e1))
        .collect();
    let h_old = toprf_combine(&fx.top.params, &fx.password, &r1, &ids, &z1)?;
    let (e2, r2) = toprf_encode(&fx.top.params, &fx.new_password, rng);
    let z2: Vec<_> = ids
        .iter()
        .map(|&id| toprf_eval(&fx.top.params, &fx.servers[(id - 1) as usize].top_share, &e2))
        .collect();
    let h_new = toprf_combine(&fx.top.params, &fx.new_password, &r2, &ids, &z2)?;

    let mut body = Vec::new();
    for id in 1..=fx.n as u32 {
        let old = derive_hi(&h_old, id);
        let new = derive_hi(&h_new, id);
        let mut pt = Vec::with_capacity(64);
        pt.extend_from_slice(&old);
        pt.extend_from_slice(&new);
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);
        aes128_ofb_apply(&old, &iv, &mut pt);
        body.extend_from_slice(&iv);
        body.extend_from_slice(&pt);
    }
    let sig = token_generation(fx, &body, &fx.password, rng)?;
    if !verify_token(fx, &body, &sig)? {
        return Err(CryptoError::InvalidRepresentative);
    }
    let mut updated = 0;
    let chunk = 80;
    for (idx, srv) in fx.servers.iter_mut().enumerate() {
        let off = idx * chunk;
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&body[off..off + 16]);
        let mut pt = body[off + 16..off + 80].to_vec();
        aes128_ofb_apply(&srv.h_i, &iv, &mut pt);
        if pt[..32] == srv.h_i {
            srv.h_i.copy_from_slice(&pt[32..64]);
            updated += 1;
        }
    }
    fx.password = fx.new_password.clone();
    Ok(PasswordUpdateResult {
        payload_len: body.len(),
        updated,
    })
}
