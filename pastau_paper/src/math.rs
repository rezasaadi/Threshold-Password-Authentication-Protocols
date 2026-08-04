use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};

pub fn modinv_u(a: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let a = BigInt::from_biguint(Sign::Plus, a.clone());
    let m = BigInt::from_biguint(Sign::Plus, modulus.clone());
    modinv_i(&a, &m).and_then(|x| x.to_biguint())
}

pub fn modinv_i(a: &BigInt, modulus: &BigInt) -> Option<BigInt> {
    let eg = a.extended_gcd(modulus);
    if eg.gcd.abs() != BigInt::one() {
        return None;
    }
    Some(eg.x.mod_floor(modulus))
}

pub fn modpow_signed(base: &BigUint, exp: &BigInt, modulus: &BigUint) -> Option<BigUint> {
    if exp.is_negative() {
        let inv = modinv_u(base, modulus)?;
        Some(inv.modpow(&(-exp).to_biguint()?, modulus))
    } else {
        Some(base.modpow(&exp.to_biguint()?, modulus))
    }
}

pub fn factorial(n: usize) -> BigUint {
    (2..=n).fold(BigUint::one(), |acc, x| acc * BigUint::from(x as u64))
}

pub fn eval_poly_mod(coeffs: &[BigUint], x: &BigUint, modulus: &BigUint) -> BigUint {
    let mut acc = BigUint::zero();
    for c in coeffs.iter().rev() {
        acc = (acc * x + c) % modulus;
    }
    acc
}

/// Shoup's integer interpolation coefficient:
/// lambda_i = Delta * product_{j in S, j != i} j/(j-i), Delta=n!.
pub fn shoup_lambda(delta: &BigUint, id: u32, ids: &[u32]) -> BigInt {
    let mut num = BigInt::from_biguint(Sign::Plus, delta.clone());
    let mut den = BigInt::one();
    let ii = BigInt::from(id);
    for &j in ids {
        if j == id {
            continue;
        }
        num *= BigInt::from(j);
        den *= BigInt::from(j) - &ii;
    }
    assert!(
        (&num % &den).is_zero(),
        "Delta must clear interpolation denominators"
    );
    num / den
}
