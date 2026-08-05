//! CRT helpers. Ported from private-membership/research/InsPIRe,
//! commit 89f04516c4b8b48b8e65e50d25b37256e04096ad, Apache-2.0.
//!
//! The extended-Euclidean inverse here is variable-time in its inputs; every
//! in-tree caller passes public parameters only (moduli, ring_dim, Galois
//! elements). A secret-data call site must switch to Fermat exponentiation.

/// `Some(x)` with `(a * x) % modulus == 1`, or `None` when `a` is not invertible.
pub fn try_mod_inverse(a: u64, modulus: u64) -> Option<u64> {
    let mut t: i128 = 0;
    let mut new_t: i128 = 1;
    let mut r: i128 = modulus as i128;
    let mut new_r: i128 = a as i128;

    while new_r != 0 {
        let quotient = r / new_r;
        let tmp_t = t - quotient * new_t;
        t = new_t;
        new_t = tmp_t;

        let tmp_r = r - quotient * new_r;
        r = new_r;
        new_r = tmp_r;
    }

    if r != 1 {
        return None;
    }

    if t < 0 {
        t += modulus as i128;
    }
    Some(t as u64)
}

/// `x` such that `(a * x) % modulus == 1`.
///
/// # Panics
///
/// If `a` is not invertible. Callers that cannot establish `gcd(a, modulus) == 1`
/// via `InspireParams::validate()` MUST use [`try_mod_inverse`].
#[allow(
    clippy::panic,
    reason = "documented abort with a typed sibling: try_mod_inverse"
)]
#[must_use]
pub fn mod_inverse(a: u64, modulus: u64) -> u64 {
    match try_mod_inverse(a, modulus) {
        Some(x) => x,
        None => panic!(
            "mod_inverse: value {a} is not invertible modulo {modulus} \
             (invariant violated; callers must check gcd or use try_mod_inverse)"
        ),
    }
}

/// `a0 + q0 * ((a1 - a0) * q0^{-1} mod q1)`, the residue pair recombined mod q0*q1.
pub fn crt_compose_2(a0: u64, a1: u64, q0: u64, q1: u64, q0_inv_mod_q1: u64) -> u64 {
    let a0_mod_q1 = a0 % q1;
    let diff = if a1 >= a0_mod_q1 {
        a1 - a0_mod_q1
    } else {
        (a1 + q1) - a0_mod_q1
    };
    let t = ((diff as u128 * q0_inv_mod_q1 as u128) % q1 as u128) as u64;
    a0 + q0 * t
}

/// Split a value into two CRT residues.
#[inline]
pub fn crt_decompose_2(value: u64, q0: u64, q1: u64) -> (u64, u64) {
    (value % q0, value % q1)
}

/// Compute the product of moduli (composite modulus).
pub fn crt_modulus(moduli: &[u64]) -> u64 {
    moduli.iter().copied().fold(1u64, u64::saturating_mul)
}
