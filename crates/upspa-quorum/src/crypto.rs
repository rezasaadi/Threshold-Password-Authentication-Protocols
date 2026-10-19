use blake3;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace, Error as AeadError, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use rand_core::RngCore;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CtBlob<const PT_LEN: usize> {
    pub nonce: [u8; NONCE_LEN],
    pub ct: [u8; PT_LEN],
    pub tag: [u8; TAG_LEN],
}

impl<const PT_LEN: usize> CtBlob<PT_LEN> {
    pub const ENCODED_LEN: usize = NONCE_LEN + PT_LEN + TAG_LEN;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct);
        out.extend_from_slice(&self.tag);
        out
    }
}

pub fn hash_to_point(msg: &[u8]) -> RistrettoPoint {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"uptspa/hash_to_point");
    hasher.update(msg);

    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);

    RistrettoPoint::from_uniform_bytes(&wide)
}

pub fn oprf_finalize(password: &[u8], y: &RistrettoPoint) -> [u8; 32] {
    let y_bytes = y.compress().to_bytes();

    let mut h = blake3::Hasher::new();
    h.update(b"uptspa/oprf_finalize");
    h.update(password);
    h.update(&y_bytes);

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

pub fn xchacha_encrypt_detached<const PT_LEN: usize>(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8; PT_LEN],
    rng: &mut impl RngCore,
) -> CtBlob<PT_LEN> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let xnonce = XNonce::from_slice(&nonce);

    let mut ct = *plaintext;
    let tag = cipher.encrypt_in_place_detached(xnonce, aad, &mut ct).unwrap();

    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_slice());

    CtBlob {
        nonce,
        ct,
        tag: tag_bytes,
    }
}

pub fn xchacha_decrypt_detached<const PT_LEN: usize>(
    key: &[u8; 32],
    aad: &[u8],
    blob: &CtBlob<PT_LEN>,
) -> Result<[u8; PT_LEN], AeadError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
    let xnonce = XNonce::from_slice(&blob.nonce);

    let mut pt = blob.ct;
    let tag = GenericArray::from_slice(&blob.tag);

    cipher.decrypt_in_place_detached(xnonce, aad, &mut pt, tag)?;
    Ok(pt)
}

pub fn hash_suid(rsp: &[u8; 32], lsj: &[u8], i: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"uptspa/suid");
    h.update(rsp);
    h.update(lsj);
    h.update(&i.to_le_bytes());

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

/// RoUpSPA's shared routing/synchronization identifier H(Rsp || LSj).
///
/// Unlike the UpSPA identifier, this intentionally has no provider index.
pub fn hash_roupspa_suid(rsp: &[u8; 32], lsj: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"roupspa/suid/v1");
    h.update(rsp);
    h.update(lsj);

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

pub fn hash_vinfo(rlsj: &[u8; 32], lsj: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"uptspa/vinfo");
    h.update(rlsj);
    h.update(lsj);

    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(out.as_bytes());
    r
}

pub fn toprf_gen(nsp: usize, tsp: usize, rng: &mut impl RngCore) -> (Scalar, Vec<(u32, Scalar)>) {
    assert!(tsp >= 1 && tsp <= nsp);

    let a0 = random_scalar(rng);
    let mut coeffs = vec![a0];
    for _ in 1..tsp {
        coeffs.push(random_scalar(rng));
    }

    fn eval(coeffs: &[Scalar], x: Scalar) -> Scalar {
        let mut acc = Scalar::ZERO;
        let mut pow = Scalar::ONE;
        for c in coeffs {
            acc += c * pow;
            pow *= x;
        }
        acc
    }

    let mut shares = Vec::with_capacity(nsp);
    for i in 1..=nsp {
        shares.push((i as u32, eval(&coeffs, Scalar::from(i as u64))));
    }

    (a0, shares)
}

pub fn lagrange_coeffs_at_zero(ids: &[u32]) -> Vec<Scalar> {
    let xs: Vec<Scalar> = ids.iter().map(|&i| Scalar::from(i as u64)).collect();
    let mut lambdas = Vec::with_capacity(xs.len());

    for i in 0..xs.len() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for j in 0..xs.len() {
            if i != j {
                num *= xs[j];
                den *= xs[j] - xs[i];
            }
        }
        lambdas.push(num * den.invert());
    }
    lambdas
}

/// Lagrange coefficients that interpolate, at the point `x`, the degree-(|ids|-1)
/// polynomial through the evaluation points `ids` (provider indices).
/// `lagrange_coeffs_at(ids, Scalar::ZERO)` equals `lagrange_coeffs_at_zero(ids)`.
/// The indices must be distinct; duplicate indices are rejected by the callers.
pub fn lagrange_coeffs_at(ids: &[u32], x: Scalar) -> Vec<Scalar> {
    let xs: Vec<Scalar> = ids.iter().map(|&i| Scalar::from(i as u64)).collect();
    let mut lambdas = Vec::with_capacity(xs.len());
    for i in 0..xs.len() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for j in 0..xs.len() {
            if i != j {
                num *= x - xs[j];
                den *= xs[i] - xs[j];
            }
        }
        lambdas.push(num * den.invert());
    }
    lambdas
}

/// Batch check that TOPRF contributions `partials[k] = k_{ids[k]} * B` are all
/// evaluations (in the exponent) of one polynomial of degree `t - 1`.
///
/// The first `t` contributions define the polynomial; every further contribution
/// must equal its interpolation at its own index.  All conditions are folded into
/// one random linear combination, so an inconsistent set passes with probability
/// at most 1/ell.  If at least `t` of the contributions are honest, a passing set
/// is entirely correct, so any `t` of them yield the correct TOPRF output.  The
/// check needs no proofs from providers. The implementation below evaluates the
/// randomized linear relation with one scalar multiplication per contribution;
/// it does not use an optimized multi-scalar multiplication routine.
pub fn toprf_partials_consistent(
    ids: &[u32],
    partials: &[RistrettoPoint],
    t: usize,
    rng: &mut impl RngCore,
) -> bool {
    let m = ids.len();
    if t == 0 || m != partials.len() || m < t {
        return false;
    }
    let mut distinct = ids.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() != m {
        return false;
    }
    if m == t {
        return true;
    }
    let base = &ids[..t];
    let mut coeffs = vec![Scalar::ZERO; m];
    for k in t..m {
        let rho = random_scalar(rng);
        coeffs[k] += rho;
        let lambdas = lagrange_coeffs_at(base, Scalar::from(ids[k] as u64));
        for (i, l) in lambdas.iter().enumerate() {
            coeffs[i] -= rho * l;
        }
    }
    let mut acc = RistrettoPoint::identity();
    for (p, c) in partials.iter().zip(coeffs.iter()) {
        acc += p * c;
    }
    acc == RistrettoPoint::identity()
}

/// Advance `idx` (a strictly increasing selection of `idx.len()` positions out of
/// `0..m`) to the next selection in lexicographic order.  Returns `false` once
/// all selections have been produced.  Start from `[0, 1, ..., k-1]`.
pub fn next_combination(idx: &mut [usize], m: usize) -> bool {
    let k = idx.len();
    if k == 0 || k > m {
        return false;
    }
    let mut i = k;
    while i > 0 && idx[i - 1] == m - k + (i - 1) {
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    idx[i - 1] += 1;
    for j in i..k {
        idx[j] = idx[j - 1] + 1;
    }
    true
}

pub fn toprf_client_eval(
    password: &[u8],
    r: Scalar,
    partials: &[RistrettoPoint],
    lambdas: &[Scalar],
) -> [u8; 32] {
    let p = hash_to_point(password);
    let blinded = p * r;
    std::hint::black_box(blinded.compress());

    let mut acc = RistrettoPoint::identity();
    for (y, l) in partials.iter().zip(lambdas) {
        acc += y * l;
    }

    let y = acc * r.invert();
    oprf_finalize(password, &y)
}

pub fn toprf_client_eval_from_partials(
    password: &[u8],
    r: Scalar,
    partials: &[RistrettoPoint],
    lambdas: &[Scalar],
) -> [u8; 32] {
    let mut acc = RistrettoPoint::identity();
    for (y, l) in partials.iter().zip(lambdas) {
        acc += y * l;
    }

    let y = acc * r.invert();
    oprf_finalize(password, &y)
}

pub fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    loop {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

#[cfg(test)]
mod toprf_robustness_tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    fn shares_times(base: &RistrettoPoint, shares: &[(u32, Scalar)]) -> Vec<RistrettoPoint> {
        shares.iter().map(|(_, s)| base * s).collect()
    }

    #[test]
    fn interpolation_at_zero_matches_existing_formula() {
        for ids in [vec![1u32, 2, 3], vec![2, 5, 7, 9], vec![4]] {
            assert_eq!(
                lagrange_coeffs_at(&ids, Scalar::ZERO),
                lagrange_coeffs_at_zero(&ids)
            );
        }
    }

    #[test]
    fn consistency_accepts_honest_and_rejects_one_bad_contribution() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        for (n, t) in [(7usize, 3usize), (10, 6), (4, 2), (5, 5), (3, 1)] {
            let (key, shares) = toprf_gen(n, t, &mut rng);
            let base = hash_to_point(b"password");
            let ids: Vec<u32> = shares.iter().map(|(i, _)| *i).collect();
            let mut partials = shares_times(&base, &shares);
            assert!(toprf_partials_consistent(&ids, &partials, t, &mut rng));
            // Any t contributions reconstruct key * base.
            let lam = lagrange_coeffs_at_zero(&ids[n - t..]);
            let mut acc = RistrettoPoint::identity();
            for (p, l) in partials[n - t..].iter().zip(lam.iter()) {
                acc += p * l;
            }
            assert_eq!(acc, base * key);
            if n > t {
                partials[n - 1] += hash_to_point(b"bench/corrupt-partial");
                assert!(!toprf_partials_consistent(&ids, &partials, t, &mut rng));
            }
        }
    }

    #[test]
    fn combinations_are_complete_and_ordered() {
        let mut idx = vec![0usize, 1, 2];
        let mut seen = vec![idx.clone()];
        while next_combination(&mut idx, 5) {
            seen.push(idx.clone());
        }
        assert_eq!(seen.len(), 10);
        assert_eq!(seen.last().unwrap(), &vec![2, 3, 4]);
        let mut sorted = seen.clone();
        sorted.sort();
        assert_eq!(seen, sorted);
    }
}
