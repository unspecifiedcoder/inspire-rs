//! Galois automorphisms `tau_g(X) = X^g` for g in `(Z/2dZ)^*`.

use crate::math::Poly;

use super::types::RlweCiphertext;

/// `p(X^g) mod (X^d + 1)`; `g` MUST be odd and coprime to 2d.
///
/// X^d = -1, so X^i lands at `g*i mod 2d` and negates once that index passes d.
#[inline]
pub fn apply_automorphism(poly: &Poly, g: usize) -> Poly {
    let d = poly.dimension();
    let q = poly.modulus();
    let two_d = 2 * d;

    let mut result_coeffs = vec![0u64; d];

    for i in 0..d {
        let coeff = poly.coeff(i);
        if coeff == 0 {
            continue;
        }

        let new_idx = (g * i) % two_d;

        let (actual_idx, negate) = if new_idx < d {
            (new_idx, false)
        } else {
            (new_idx - d, true)
        };

        if negate {
            result_coeffs[actual_idx] = mod_sub(result_coeffs[actual_idx], coeff, q);
        } else {
            result_coeffs[actual_idx] = mod_add(result_coeffs[actual_idx], coeff, q);
        }
    }

    Poly::from_coeffs_moduli(result_coeffs, poly.moduli())
}

/// `(tau_g(a), tau_g(b))`. The result decrypts under `tau_g(s)`, so callers MUST
/// key-switch back to `s`.
pub fn automorphism_ciphertext(ct: &RlweCiphertext, g: usize) -> RlweCiphertext {
    RlweCiphertext {
        a: apply_automorphism(&ct.a, g),
        b: apply_automorphism(&ct.b, g),
    }
}

/// Generators of `(Z/2dZ)^* = Z_{d/2} x Z_2` for power-of-two d: `(3, 2d - 1)`.
pub fn galois_generators(d: usize) -> (usize, usize) {
    debug_assert!(d.is_power_of_two(), "d must be a power of 2");
    debug_assert!(d >= 4, "d must be at least 4");

    let g1 = 3;
    // The negation automorphism: X^{-1} = -X^{d-1}.
    let g2 = 2 * d - 1;

    (g1, g2)
}

/// Order of g in `(Z/2dZ)^*`.
pub fn automorphism_order(g: usize, d: usize) -> usize {
    let two_d = 2 * d;
    let mut val = g % two_d;
    let mut order = 1;

    while val != 1 {
        val = (val * g) % two_d;
        order += 1;

        assert!(order <= two_d, "g={g} is not in (Z/{two_d}Z)^*");
    }

    order
}

/// True when g is odd, below 2d, and coprime to 2d.
pub fn is_valid_galois_element(g: usize, d: usize) -> bool {
    g % 2 == 1 && g < 2 * d && gcd(g, 2 * d) == 1
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[inline]
fn mod_add(a: u64, b: u64, q: u64) -> u64 {
    let sum = a as u128 + b as u128;
    (sum % q as u128) as u64
}

#[inline]
fn mod_sub(a: u64, b: u64, q: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        q - b + a
    }
}

/// `tau_g1 . tau_g2 = tau_{g1*g2 mod 2d}`.
pub fn compose_automorphisms(g1: usize, g2: usize, d: usize) -> usize {
    (g1 * g2) % (2 * d)
}

/// `tau_g^{-1} = tau_{g^{-1} mod 2d}`, or `None` when `g` is not coprime to 2d.
#[must_use]
pub fn try_inverse_automorphism(g: usize, d: usize) -> Option<usize> {
    mod_inverse(g, 2 * d)
}

/// [`try_inverse_automorphism`] for callers that already screened `g`.
///
/// # Panics
///
/// When `g` is not coprime to 2d.
#[allow(
    clippy::expect_used,
    reason = "documented abort with a typed sibling: try_inverse_automorphism"
)]
#[must_use]
pub fn inverse_automorphism(g: usize, d: usize) -> usize {
    try_inverse_automorphism(g, d).expect("g must be coprime to 2d")
}

fn mod_inverse(a: usize, m: usize) -> Option<usize> {
    let (g, x, _) = extended_gcd(a as i64, m as i64);
    if g == 1 {
        Some(((x % m as i64 + m as i64) % m as i64) as usize)
    } else {
        None
    }
}

fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = extended_gcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::InspireParams;

    fn test_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    #[test]
    fn test_automorphism_identity() {
        let params = test_params();
        let d = params.ring_dim;

        let coeffs: Vec<u64> = (0..d).map(|i| i as u64).collect();
        let poly = Poly::from_coeffs_moduli(coeffs.clone(), params.moduli());

        let result = apply_automorphism(&poly, 1);

        for (i, expected) in coeffs.iter().enumerate().take(d) {
            assert_eq!(result.coeff(i), *expected, "Identity failed at {i}");
        }
    }

    #[test]
    fn test_automorphism_composition() {
        let params = test_params();
        let d = params.ring_dim;

        let (g1, g2) = galois_generators(d);

        let coeffs: Vec<u64> = (0..d).map(|i| ((i * 17 + 5) as u64) % params.p).collect();
        let poly = Poly::from_coeffs_moduli(coeffs, params.moduli());

        let step1 = apply_automorphism(&poly, g1);
        let composed = apply_automorphism(&step1, g2);

        let g_combined = compose_automorphisms(g1, g2, d);
        let direct = apply_automorphism(&poly, g_combined);

        for i in 0..d {
            assert_eq!(
                composed.coeff(i),
                direct.coeff(i),
                "Composition failed at coefficient {i}"
            );
        }
    }

    #[test]
    fn test_automorphism_inverse() {
        let params = test_params();
        let d = params.ring_dim;
        let (g1, _) = galois_generators(d);

        let coeffs: Vec<u64> = (0..d).map(|i| ((i * 13 + 7) as u64) % params.p).collect();
        let poly = Poly::from_coeffs_moduli(coeffs.clone(), params.moduli());

        let g_inv = inverse_automorphism(g1, d);
        let forward = apply_automorphism(&poly, g1);
        let back = apply_automorphism(&forward, g_inv);

        for (i, expected) in coeffs.iter().enumerate().take(d) {
            assert_eq!(back.coeff(i), *expected, "Inverse failed at {i}");
        }
    }

    #[test]
    fn test_galois_generators() {
        let d = 2048;
        let (g1, g2) = galois_generators(d);

        assert_eq!(g1, 3);
        assert_eq!(g2, 4095);

        let order_g1 = automorphism_order(g1, d);
        assert_eq!(order_g1, d / 2, "g1 should have order d/2");

        let order_g2 = automorphism_order(g2, d);
        assert_eq!(order_g2, 2, "g2 should have order 2");
    }

    #[test]
    fn test_galois_generators_d4096() {
        let d = 4096;
        let (g1, g2) = galois_generators(d);

        assert_eq!(g1, 3);
        assert_eq!(g2, 8191);

        let order_g1 = automorphism_order(g1, d);
        assert_eq!(order_g1, d / 2);

        let order_g2 = automorphism_order(g2, d);
        assert_eq!(order_g2, 2);
    }

    #[test]
    fn test_negation_automorphism() {
        let params = test_params();
        let d = params.ring_dim;
        let (_, g2) = galois_generators(d);

        let mut coeffs = vec![0u64; d];
        coeffs[1] = 1;
        let poly = Poly::from_coeffs_moduli(coeffs, params.moduli());

        let result = apply_automorphism(&poly, g2);

        assert_eq!(result.coeff(d - 1), params.q - 1);
        for i in 0..d {
            if i != d - 1 {
                assert_eq!(result.coeff(i), 0);
            }
        }
    }

    #[test]
    fn test_valid_galois_elements() {
        let d = 2048;

        assert!(is_valid_galois_element(1, d));
        assert!(is_valid_galois_element(3, d));
        assert!(is_valid_galois_element(5, d));
        assert!(is_valid_galois_element(4095, d)); // 2d - 1

        assert!(!is_valid_galois_element(2, d));
        assert!(!is_valid_galois_element(4, d));
    }

    #[test]
    fn test_automorphism_ciphertext() {
        let params = test_params();
        let d = params.ring_dim;
        let (g1, _) = galois_generators(d);

        let a_coeffs: Vec<u64> = (0..d).map(|i| (i as u64 * 3) % params.q).collect();
        let b_coeffs: Vec<u64> = (0..d).map(|i| (i as u64 * 7 + 1) % params.q).collect();

        let a = Poly::from_coeffs_moduli(a_coeffs, params.moduli());
        let b = Poly::from_coeffs_moduli(b_coeffs, params.moduli());
        let ct = RlweCiphertext::from_parts(a.clone(), b.clone());

        let ct_auto = automorphism_ciphertext(&ct, g1);

        let a_auto = apply_automorphism(&a, g1);
        let b_auto = apply_automorphism(&b, g1);

        for i in 0..d {
            assert_eq!(ct_auto.a.coeff(i), a_auto.coeff(i));
            assert_eq!(ct_auto.b.coeff(i), b_auto.coeff(i));
        }
    }

    #[test]
    fn test_automorphism_linearity() {
        let params = test_params();
        let d = params.ring_dim;
        let (g1, _) = galois_generators(d);

        let p1_coeffs: Vec<u64> = (0..d).map(|i| (i as u64 * 11) % params.p).collect();
        let p2_coeffs: Vec<u64> = (0..d).map(|i| (i as u64 * 13 + 3) % params.p).collect();

        let p1 = Poly::from_coeffs_moduli(p1_coeffs, params.moduli());
        let p2 = Poly::from_coeffs_moduli(p2_coeffs, params.moduli());

        let sum = &p1 + &p2;
        let auto_sum = apply_automorphism(&sum, g1);

        let auto_p1 = apply_automorphism(&p1, g1);
        let auto_p2 = apply_automorphism(&p2, g1);
        let sum_auto = &auto_p1 + &auto_p2;

        for i in 0..d {
            assert_eq!(
                auto_sum.coeff(i),
                sum_auto.coeff(i),
                "Linearity failed at {i}"
            );
        }
    }
}
