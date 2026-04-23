//! CRT (Chinese Remainder Theorem) helpers.
//!
//! Ported and adapted from Google InsPIRe reference code
//! (private-membership/research/InsPIRe, commit 89f04516c4b8b48b8e65e50d25b37256e04096ad)
//! under the Apache-2.0 license.
//!
//! # Constant-time audit
//!
//! `mod_inverse` + `try_mod_inverse` use the extended Euclidean
//! algorithm, which is variable-time with respect to its inputs (the
//! loop runs O(log(max(a, modulus))) iterations with the exact count
//! depending on the input bit patterns). This COULD leak bit
//! structure of the input via timing on platforms where `a` or
//! `modulus` comes from secret data.
//!
//! **Audit finding:** every in-tree caller of `mod_inverse` passes
//! PUBLIC values:
//! - `Poly::init_moduli` (via `super::crt`): arguments are
//!   `InspireParams::crt_moduli[0]` and `[1]` — public parameters
//!   from the CRS.
//! - `params.rs` + `inspiring2.rs` local `mod_inverse_*` helpers:
//!   arguments are `num_to_pack`, Galois elements (public), ring_dim
//!   (public).
//! - `pir/extract.rs`: arguments are `ring_dim` and `p` (public;
//!   validation in `InspireParams::validate` enforces `gcd(d, p) == 1`
//!   so a fallible caller always succeeds under shipping config).
//!
//! No caller feeds secret-derived data (RLWE secret key, plaintext
//! message, gadget digits) into `mod_inverse`. The variable-time
//! implementation is therefore acceptable for the current surface.
//!
//! **If future work introduces a secret-data call site**, swap the
//! implementation for Fermat's method (a^(p-2) mod p via fast
//! modular exponentiation) or add a `debug_assert` documenting the
//! public-input contract.

/// Try to compute a modular inverse using the extended Euclidean
/// algorithm.
///
/// Returns `Some(x)` such that `(a * x) % modulus == 1` when `gcd(a,
/// modulus) == 1`; returns `None` when `a` is not invertible modulo
/// `modulus`. Fallible companion to the invariant-panicking
/// [`mod_inverse`].
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

/// Compute a modular inverse using extended Euclidean algorithm.
///
/// Returns `x` such that `(a * x) % modulus == 1`.
///
/// Panics if `a` is not invertible modulo `modulus`. The panic is an
/// internal invariant: every in-tree caller reaches this function
/// only after `InspireParams::validate()` has ensured
/// `gcd(crt_moduli[0], crt_moduli[1]) == 1` (for Poly internals) or
/// `gcd(ring_dim, p) == 1` (for `extract.rs`'s tree-packed un-scale).
/// Callers that cannot
/// guarantee the invariant MUST use [`try_mod_inverse`] instead.
pub fn mod_inverse(a: u64, modulus: u64) -> u64 {
    match try_mod_inverse(a, modulus) {
        Some(x) => x,
        None => panic!(
            "mod_inverse: value {} is not invertible modulo {} \
             (invariant violated; callers must check gcd or use try_mod_inverse)",
            a, modulus
        ),
    }
}

/// Compose two CRT residues into a value modulo q0 * q1.
///
/// Formula:
///   x = a0 + q0 * ((a1 - a0) * q0^{-1} mod q1)
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
    moduli
        .iter()
        .copied()
        .fold(1u64, |acc, m| acc.saturating_mul(m))
}
