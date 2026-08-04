use aes::Aes128;
use cipher::{KeyIvInit, StreamCipher};
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use openssl::bn::BigNum;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

type Aes128Ofb = ofb::Ofb<Aes128>;

use crate::math::{eval_poly_mod, factorial, modinv_u, modpow_signed, shoup_lambda};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid threshold parameters")]
    InvalidThreshold,
    #[error("modular inverse does not exist")]
    NoInverse,
    #[error("invalid RSA representative")]
    InvalidRepresentative,
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ShoupPublicKey {
    pub n: BigUint,
    pub e: BigUint,
    pub delta: BigUint,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ShoupShare {
    pub id: u32,
    pub s_i: BigUint,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ShoupSetup {
    pub public: ShoupPublicKey,
    pub shares: Vec<ShoupShare>,
}
#[derive(Clone)]
pub struct ShoupPartial {
    pub id: u32,
    pub value: BigUint,
}

fn openssl_safe_prime(bits: i32) -> Result<BigUint, CryptoError> {
    let mut p = BigNum::new()?;
    p.generate_prime(bits, true, None, None)?;
    Ok(BigUint::from_bytes_be(&p.to_vec()))
}

pub fn shoup_setup<R: RngCore + CryptoRng>(
    n_servers: usize,
    threshold: usize,
    rng: &mut R,
) -> Result<ShoupSetup, CryptoError> {
    if threshold == 0 || threshold > n_servers {
        return Err(CryptoError::InvalidThreshold);
    }
    // Two 1024-bit safe primes give a 2048-bit RSA modulus, as in PAS-TA-U.
    let p = openssl_safe_prime(1024)?;
    let mut q = openssl_safe_prime(1024)?;
    while q == p {
        q = openssl_safe_prime(1024)?;
    }
    let n = &p * &q;
    let p1 = (&p - BigUint::one()) >> 1usize;
    let q1 = (&q - BigUint::one()) >> 1usize;
    let m = &p1 * &q1;
    let e = BigUint::from(65537u32);
    if e.gcd(&m) != BigUint::one() {
        return shoup_setup(n_servers, threshold, rng);
    }
    let d = modinv_u(&e, &m).ok_or(CryptoError::NoInverse)?;

    let mut coeffs = Vec::with_capacity(threshold);
    coeffs.push(d);
    for _ in 1..threshold {
        coeffs.push(rng.gen_biguint_below(&m));
    }
    let shares = (1..=n_servers)
        .map(|i| ShoupShare {
            id: i as u32,
            s_i: eval_poly_mod(&coeffs, &BigUint::from(i as u64), &m),
        })
        .collect();
    Ok(ShoupSetup {
        public: ShoupPublicKey {
            n,
            e,
            delta: factorial(n_servers),
        },
        shares,
    })
}

/// EMSA-PKCS1-v1_5 encoding for SHA-256, matching an RSA-2048 signing input.
pub fn emsa_pkcs1_v1_5_sha256(msg: &[u8], modulus_bytes: usize) -> Result<BigUint, CryptoError> {
    const DER: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0x04, 0x20,
    ];
    let digest = Sha256::digest(msg);
    let t_len = DER.len() + digest.len();
    if modulus_bytes < t_len + 11 {
        return Err(CryptoError::InvalidRepresentative);
    }
    let ps_len = modulus_bytes - t_len - 3;
    let mut em = Vec::with_capacity(modulus_bytes);
    em.extend_from_slice(&[0x00, 0x01]);
    em.extend(std::iter::repeat(0xff).take(ps_len));
    em.push(0x00);
    em.extend_from_slice(&DER);
    em.extend_from_slice(&digest);
    Ok(BigUint::from_bytes_be(&em))
}

pub fn shoup_part_eval(pk: &ShoupPublicKey, share: &ShoupShare, representative: &BigUint) -> ShoupPartial {
    let exponent = BigUint::from(2u8) * &pk.delta * &share.s_i;
    ShoupPartial {
        id: share.id,
        value: representative.modpow(&exponent, &pk.n),
    }
}

pub fn shoup_combine(
    pk: &ShoupPublicKey,
    representative: &BigUint,
    partials: &[ShoupPartial],
) -> Result<BigUint, CryptoError> {
    let ids: Vec<u32> = partials.iter().map(|p| p.id).collect();
    let mut w = BigUint::one();
    for p in partials {
        let lambda = shoup_lambda(&pk.delta, p.id, &ids);
        let exp = BigInt::from(2u8) * lambda;
        let term = modpow_signed(&p.value, &exp, &pk.n).ok_or(CryptoError::NoInverse)?;
        w = (w * term) % &pk.n;
    }
    let four_delta_sq = BigUint::from(4u8) * &pk.delta * &pk.delta;
    let a = modinv_u(&(&four_delta_sq % &pk.e), &pk.e).ok_or(CryptoError::NoInverse)?;
    let lhs = &four_delta_sq * &a;
    let b = (BigInt::one() - BigInt::from_biguint(Sign::Plus, lhs))
        / BigInt::from_biguint(Sign::Plus, pk.e.clone());
    let wa = w.modpow(&a, &pk.n);
    let mb = modpow_signed(representative, &b, &pk.n).ok_or(CryptoError::NoInverse)?;
    Ok((wa * mb) % &pk.n)
}

pub fn shoup_verify(pk: &ShoupPublicKey, representative: &BigUint, sig: &BigUint) -> bool {
    sig.modpow(&pk.e, &pk.n) == *representative
}

// RFC 3526 group 14 prime. We use the prime-order subgroup generated by g=4.
const MODP14_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
);

#[derive(Clone)]
pub struct ToprfParams {
    pub modulus: BigUint,
    pub order: BigUint,
    pub generator: BigUint,
}
#[derive(Clone)]
pub struct ToprfShare {
    pub id: u32,
    pub value: BigUint,
}
#[derive(Clone)]
pub struct ToprfSetup {
    pub params: ToprfParams,
    pub shares: Vec<ToprfShare>,
}

pub fn toprf_params() -> ToprfParams {
    let modulus = BigUint::parse_bytes(MODP14_HEX.as_bytes(), 16).unwrap();
    let order = (&modulus - BigUint::one()) >> 1usize;
    ToprfParams {
        modulus,
        order,
        generator: BigUint::from(4u8),
    }
}

pub fn toprf_setup<R: RngCore + CryptoRng>(
    n: usize,
    t: usize,
    rng: &mut R,
) -> Result<ToprfSetup, CryptoError> {
    if t == 0 || t > n {
        return Err(CryptoError::InvalidThreshold);
    }
    let params = toprf_params();
    let mut coeffs = Vec::with_capacity(t);
    for _ in 0..t {
        coeffs.push(rng.gen_biguint_below(&params.order));
    }
    let shares = (1..=n)
        .map(|i| ToprfShare {
            id: i as u32,
            value: eval_poly_mod(&coeffs, &BigUint::from(i as u64), &params.order),
        })
        .collect();
    Ok(ToprfSetup { params, shares })
}

pub fn hash_password_to_group(params: &ToprfParams, password: &[u8]) -> BigUint {
    let exponent = BigUint::from_bytes_be(&Sha512::digest(password)) % &params.order;
    params.generator.modpow(&exponent, &params.modulus)
}

pub fn toprf_encode<R: RngCore + CryptoRng>(
    params: &ToprfParams,
    password: &[u8],
    rng: &mut R,
) -> (BigUint, BigUint) {
    let mut rho = rng.gen_biguint_below(&params.order);
    while rho.is_zero() {
        rho = rng.gen_biguint_below(&params.order);
    }
    let h2 = hash_password_to_group(params, password);
    (h2.modpow(&rho, &params.modulus), rho)
}

pub fn toprf_eval(params: &ToprfParams, share: &ToprfShare, encoded: &BigUint) -> BigUint {
    encoded.modpow(&share.value, &params.modulus)
}

pub fn lagrange_at_zero_mod(ids: &[u32], modulus: &BigUint) -> Result<Vec<BigUint>, CryptoError> {
    let mut out = Vec::with_capacity(ids.len());
    for &i in ids {
        let xi = BigUint::from(i);
        let mut num = BigUint::one();
        let mut den = BigUint::one();
        for &j in ids {
            if i == j {
                continue;
            }
            let xj = BigUint::from(j);
            num = (num * &xj) % modulus;
            let diff = if xj >= xi {
                &xj - &xi
            } else {
                modulus - (&xi - &xj)
            };
            den = (den * diff) % modulus;
        }
        out.push((num * modinv_u(&den, modulus).ok_or(CryptoError::NoInverse)?) % modulus);
    }
    Ok(out)
}

pub fn toprf_combine(
    params: &ToprfParams,
    password: &[u8],
    rho: &BigUint,
    ids: &[u32],
    partials: &[BigUint],
) -> Result<[u8; 32], CryptoError> {
    let lambdas = lagrange_at_zero_mod(ids, &params.order)?;
    let mut z = BigUint::one();
    for (part, lambda) in partials.iter().zip(lambdas.iter()) {
        z = (z * part.modpow(lambda, &params.modulus)) % &params.modulus;
    }
    let rho_inv = modinv_u(rho, &params.order).ok_or(CryptoError::NoInverse)?;
    let y = z.modpow(&rho_inv, &params.modulus);
    let mut h = Sha256::new();
    h.update(password);
    h.update(y.to_bytes_be());
    Ok(h.finalize().into())
}

pub fn derive_hi(h: &[u8; 32], id: u32) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(h);
    d.update(id.to_string().as_bytes());
    d.finalize().into()
}

pub fn aes128_ofb_apply(key_material: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
    let mut c = Aes128Ofb::new_from_slices(&key_material[..16], iv).expect("fixed key/iv lengths");
    c.apply_keystream(data);
}
