use blake3;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar as RScalar};
use rand_core::RngCore;

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar as BScalar};
use ff::Field;
use group::Group;

pub use crate::crypto_core::{
    hash_to_point, lagrange_coeffs_at_zero, oprf_finalize, random_scalar, toprf_client_eval,
    toprf_client_eval_from_partials, xchacha_decrypt_detached, xchacha_encrypt_detached, CtBlob, NONCE_LEN,
    TAG_LEN,
};

pub fn hash_hi(h: &[u8; 32], i: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pastau/hi/v1");
    hasher.update(h);
    hasher.update(&i.to_le_bytes());
    let out = hasher.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

pub fn xchacha_encrypt_detached_with_nonce<const PT_LEN: usize>(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8; PT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> CtBlob<PT_LEN> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let xnonce = XNonce::from_slice(nonce);
    let mut ct = *plaintext;
    let tag = cipher.encrypt_in_place_detached(xnonce, aad, &mut ct).unwrap();
    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_slice());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce);
    CtBlob {
        nonce: nonce_bytes,
        ct,
        tag: tag_bytes,
    }
}

pub fn toprf_direct(password: &[u8], k0: RScalar) -> [u8; 32] {
    let p = hash_to_point(password);
    let y = p * k0;
    oprf_finalize(password, &y)
}

pub fn toprf_encode(password: &[u8], rho: RScalar) -> RistrettoPoint {
    hash_to_point(password) * rho
}

pub fn toprf_eval_share(share: RScalar, req: &RistrettoPoint) -> RistrettoPoint {
    req * share
}

pub const TTG_TOKEN_LEN: usize = 48;
pub const TTG_VK_LEN: usize = 96;

pub type TtgShare = BScalar;
pub type TtgPartial = G1Projective;
pub type TtgToken = [u8; TTG_TOKEN_LEN];
pub type TtgVk = [u8; TTG_VK_LEN];

pub fn ttg_hash_to_g1(msg: &[u8]) -> G1Projective {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pastau/ttg_h2g1/v1");
    hasher.update(msg);
    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);
    let s = BScalar::from_bytes_wide(&wide);
    G1Projective::generator() * s
}

pub fn ttg_setup(n: usize, t: usize, rng: &mut impl RngCore) -> (Vec<(u32, TtgShare)>, TtgVk) {
    assert!(t >= 1 && t <= n);

    let sk = TtgShare::random(&mut *rng);
    let mut coeffs = Vec::with_capacity(t);
    coeffs.push(sk);
    for _ in 1..t {
        coeffs.push(TtgShare::random(&mut *rng));
    }

    fn eval(coeffs: &[TtgShare], x: TtgShare) -> TtgShare {
        let mut acc = TtgShare::ZERO;
        let mut pow = TtgShare::ONE;
        for c in coeffs {
            acc += *c * pow;
            pow *= x;
        }
        acc
    }

    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        shares.push((i as u32, eval(&coeffs, TtgShare::from(i as u64))));
    }

    let pk = G2Projective::generator() * sk;
    let vk_bytes = G2Affine::from(pk).to_compressed();
    (shares, vk_bytes)
}

pub fn ttg_part_eval(share: &TtgShare, msg: &[u8]) -> TtgPartial {
    let h = ttg_hash_to_g1(msg);
    h * *share
}

pub fn ttg_lagrange_coeffs_at_zero(ids: &[u32]) -> Vec<TtgShare> {
    let xs: Vec<TtgShare> = ids.iter().map(|&i| TtgShare::from(i as u64)).collect();
    let mut lambdas = Vec::with_capacity(xs.len());

    for i in 0..xs.len() {
        let mut num = TtgShare::ONE;
        let mut den = TtgShare::ONE;
        for j in 0..xs.len() {
            if i != j {
                num *= xs[j];
                den *= xs[j] - xs[i];
            }
        }
        let inv = den.invert();

        let inv = Option::<TtgShare>::from(inv).unwrap_or(TtgShare::ZERO);
        lambdas.push(num * inv);
    }
    lambdas
}

pub fn ttg_combine(ids: &[u32], partials: &[TtgPartial]) -> TtgToken {
    assert_eq!(ids.len(), partials.len());
    let lambdas = ttg_lagrange_coeffs_at_zero(ids);
    let mut acc = G1Projective::identity();
    for (p, l) in partials.iter().zip(lambdas.iter()) {
        acc += *p * *l;
    }
    G1Affine::from(acc).to_compressed()
}

pub fn ttg_verify(vk: &TtgVk, msg: &[u8], token: &TtgToken) -> bool {
    let pk = match Option::<G2Affine>::from(G2Affine::from_compressed(vk)) {
        Some(p) => p,
        None => return false,
    };
    let sig = match Option::<G1Affine>::from(G1Affine::from_compressed(token)) {
        Some(s) => s,
        None => return false,
    };

    let h = G1Affine::from(ttg_hash_to_g1(msg));
    let g2 = G2Affine::from(G2Projective::generator());
    pairing(&sig, &g2) == pairing(&h, &pk)
}

pub fn ttg_token_from_partial_bytes(partial_bytes: &[u8; TTG_TOKEN_LEN]) -> Option<TtgPartial> {
    let aff = Option::<G1Affine>::from(G1Affine::from_compressed(partial_bytes))?;
    Some(G1Projective::from(aff))
}

pub fn ttg_partial_to_bytes(partial: &TtgPartial) -> [u8; TTG_TOKEN_LEN] {
    G1Affine::from(*partial).to_compressed()
}
