//! External product operation: RLWE × RGSW → RLWE
//!
//! This is the key operation for homomorphic multiplication in the InsPIRe scheme.

use crate::math::mod_q::DEFAULT_Q;
use crate::math::{NttContext, Poly};
use crate::rlwe::RlweCiphertext;

use super::types::{GadgetVector, RgswCiphertext};

/// Decompose a polynomial coefficient-wise into base-z digits
///
/// For each coefficient c, computes digits [c₀, c₁, ..., c_{ℓ-1}] such that:
/// c ≡ c₀ + c₁·z + c₂·z² + ... + c_{ℓ-1}·z^{ℓ-1} (mod q)
///
/// The digits are in [0, z) range for simplicity.
pub fn gadget_decompose(poly: &Poly, gadget: &GadgetVector) -> Vec<Poly> {
    // Fast path for single-prime DEFAULT_Q + shipping gadget config
    // (base = 2^20, len = 3). Under multi-CRT moduli,
    // `poly.coeff(j)` reconstructs a composite value via `crt_compose_2`
    // and `set_coeff` decomposes digits back to CRT limbs — neither is
    // a direct per-limb operation, so the fast path's direct slice
    // access would be incorrect. Gate on single-prime DEFAULT_Q to stay
    // byte-identical with the generic path under 2-CRT.
    if gadget.base == (1u64 << 20)
        && gadget.len == 3
        && poly.moduli().len() == 1
        && poly.moduli()[0] == DEFAULT_Q
    {
        return gadget_decompose_default_q(poly);
    }

    let d = poly.dimension();
    let base = gadget.base;
    let ell = gadget.len;

    let mut result = Vec::with_capacity(ell);
    for _ in 0..ell {
        result.push(Poly::zero_moduli(d, poly.moduli()));
    }

    for j in 0..d {
        let mut val = poly.coeff(j);

        for result_poly in &mut result {
            let digit = val % base;
            result_poly.set_coeff(j, digit);
            val /= base;
        }
    }

    result
}

/// Fast-path gadget decomposition for DEFAULT_Q's shipping gadget
/// `(base = 2^20, len = 3)`.
///
/// Operates directly on `Poly::coeffs()` without per-coefficient method
/// calls. Compile-time base + unrolled ell=3 loop. Byte-identical output
/// to the generic path at the matching gadget parameters; verified by
/// `gadget_decompose_reconstruct_roundtrip` + `gadget_decompose_small_digits`
/// tests in the module.
#[inline]
fn gadget_decompose_default_q(poly: &Poly) -> Vec<Poly> {
    const BASE_MASK: u64 = (1u64 << 20) - 1;

    // Caller already gates on `moduli.len() == 1 && moduli[0] == DEFAULT_Q`,
    // so the outer `for m in 0..crt_count` loop is always a single
    // iteration. Specialise the single-CRT shape to eliminate the
    // outer loop's LLVM bounds checks + let the compiler hoist pointer
    // setup out of any iteration overhead.
    let moduli = poly.moduli();
    debug_assert_eq!(
        moduli.len(),
        1,
        "gadget_decompose_default_q: caller must gate on single-prime moduli"
    );
    debug_assert_eq!(
        moduli[0],
        DEFAULT_Q,
        "gadget_decompose_default_q: caller must gate on DEFAULT_Q"
    );

    let d = poly.dimension();
    let src = poly.coeffs();

    let mut digit0 = vec![0u64; d];
    let mut digit1 = vec![0u64; d];
    let mut digit2 = vec![0u64; d];

    // Single-CRT specialised loop: one pass over d coefficients.
    for j in 0..d {
        let val = src[j];
        digit0[j] = val & BASE_MASK;
        digit1[j] = (val >> 20) & BASE_MASK;
        digit2[j] = (val >> 40) & BASE_MASK;
    }

    // Skip the `reduce()` pass since digits are masked by
    // BASE_MASK = 2^20 − 1 < DEFAULT_Q. The invariant is enforced by
    // the mask above; `from_crt_coeffs_reduced` preserves it.
    vec![
        Poly::from_crt_coeffs_reduced(digit0, moduli),
        Poly::from_crt_coeffs_reduced(digit1, moduli),
        Poly::from_crt_coeffs_reduced(digit2, moduli),
    ]
}

/// Reconstruct a polynomial from its gadget decomposition
///
/// Given decomposition [p₀, p₁, ..., p_{ℓ-1}], computes:
/// p = p₀ + p₁·z + p₂·z² + ... + p_{ℓ-1}·z^{ℓ-1}
pub fn gadget_reconstruct(decomposed: &[Poly], gadget: &GadgetVector) -> Poly {
    assert!(!decomposed.is_empty(), "Decomposition cannot be empty");
    assert_eq!(
        decomposed.len(),
        gadget.len,
        "Decomposition length must match gadget length"
    );

    let d = decomposed[0].dimension();
    let moduli = decomposed[0].moduli();
    for (idx, poly) in decomposed.iter().enumerate() {
        assert_eq!(
            poly.dimension(),
            d,
            "Decomposed poly[{idx}] has mismatched dimension"
        );
        assert_eq!(
            poly.moduli(),
            moduli,
            "Decomposed poly[{idx}] has mismatched moduli"
        );
    }
    let powers = gadget.powers();

    let mut result = Poly::zero_moduli(d, moduli);

    for (i, poly) in decomposed.iter().enumerate() {
        let scaled = poly.scalar_mul(powers[i]);
        result += scaled;
    }

    result
}

/// Precomputed NTT form of an RGSW ciphertext's rows for reuse
/// across many `external_product` calls (e.g. the 128-column PIR
/// server loop). Each entry is `(a_ntt, b_ntt)` corresponding to
/// `rgsw.rows[i].a / .b` converted to NTT domain once.
///
/// Pre-NTT conversion eliminates redundant forward-NTTs of RGSW
/// components on every external product call. At 128 columns ×
/// 2ℓ=6 rows × 2 polys = 1536 NTTs saved per query.
pub type RgswRowsNtt = Vec<(Poly, Poly)>;

/// Pre-convert all RGSW row polynomials to NTT form for reuse.
///
/// Callers that will run many `external_product` calls against the
/// same RGSW (e.g. one query × many DB columns) should invoke this
/// once before the loop and pass the result into
/// [`external_product_with_ntt_rgsw`].
pub fn rgsw_rows_to_ntt(rgsw: &RgswCiphertext, ctx: &NttContext) -> RgswRowsNtt {
    rgsw.rows
        .iter()
        .map(|row| {
            let mut a_ntt = row.a.clone();
            if !a_ntt.is_ntt() {
                a_ntt.to_ntt(ctx);
            }
            let mut b_ntt = row.b.clone();
            if !b_ntt.is_ntt() {
                b_ntt.to_ntt(ctx);
            }
            (a_ntt, b_ntt)
        })
        .collect()
}

/// Fast external product using pre-NTT'd RGSW rows.
///
/// Byte-identical to `external_product(rlwe, rgsw, ctx)` at
/// matching inputs. Key differences:
/// - Assumes `rgsw_ntt` has been pre-converted via
///   [`rgsw_rows_to_ntt`] (constant across many calls).
/// - Converts the gadget-decomposed `rlwe.a` / `rlwe.b` digits to
///   NTT form ONCE (not twice as in the classical `mul_ntt` pattern).
/// - Accumulates the pointwise products directly in NTT domain,
///   deferring the inverse NTT to a single pair at the end.
///
/// Op-count reduction per call at ℓ=3:
/// - Classical `external_product`: 12 `mul_ntt` ops. Each
///   `Poly::mul_ntt` converts both operands to NTT then converts the
///   product back (2 forward + 1 inverse = 3 NTTs per op). Total per
///   call: 12 × 3 = **36 NTTs** (of which 12 are on the RGSW .a/.b).
/// - This function per call: 6 forward (a_decomp + b_decomp) +
///   2 forward (zero-poly init to NTT domain) + 2 inverse at the end
///   = **10 NTTs**.
/// - Amortization: the RGSW's 12 forward NTTs (from `rgsw_rows_to_ntt`)
///   are paid ONCE before the par_iter loop over the shard's columns.
///   For a 128-column shard the effective per-column forward count drops
///   to 12/128 ≈ 0.09 shared + 10 per-call = ~10.1 vs classical 36.
///   Net: **~3.6x fewer NTTs per column amortized**.
///
/// # Arguments
/// * `rlwe` - The RLWE operand (coefficient-form, as produced by
///   `trivial_encrypt` on DB polynomials).
/// * `rgsw_ntt` - Pre-NTT'd RGSW row polynomials (length `2ℓ`).
/// * `gadget` - Gadget parameters matching the RGSW.
/// * `ctx` - NTT context; must match the moduli used by both operands.
pub fn external_product_with_ntt_rgsw(
    rlwe: &RlweCiphertext,
    rgsw_ntt: &[(Poly, Poly)],
    gadget: &GadgetVector,
    ctx: &NttContext,
) -> RlweCiphertext {
    let d = rlwe.ring_dim();
    let moduli = rlwe.a.moduli();
    let ell = gadget.len;
    assert_eq!(rgsw_ntt.len(), 2 * ell, "RGSW NTT rows must have 2ℓ entries");
    assert_eq!(rlwe.b.moduli(), moduli, "RLWE components must share moduli");
    assert_eq!(
        ctx.moduli(),
        moduli,
        "NTT context moduli must match ciphertext moduli"
    );

    // Decompose a and b into ℓ digit-polys in coefficient form
    // (standard gadget_decompose; fast path kicks in under
    // single-prime DEFAULT_Q).
    let a_decomp = gadget_decompose(&rlwe.a, gadget);
    let b_decomp = gadget_decompose(&rlwe.b, gadget);

    // Forward-NTT each digit poly exactly once (each is used twice —
    // against the .a and .b component of its RGSW row — so caching
    // the NTT form saves half the forward conversions).
    let a_decomp_ntt: Vec<Poly> = a_decomp
        .into_iter()
        .map(|mut p| {
            p.to_ntt(ctx);
            p
        })
        .collect();
    let b_decomp_ntt: Vec<Poly> = b_decomp
        .into_iter()
        .map(|mut p| {
            p.to_ntt(ctx);
            p
        })
        .collect();

    // Accumulate in NTT domain. Start with zero polys in NTT form.
    let mut result_a = Poly::zero_moduli(d, moduli);
    let mut result_b = Poly::zero_moduli(d, moduli);
    result_a.to_ntt(ctx);
    result_b.to_ntt(ctx);

    for i in 0..ell {
        let (row_a_a_ntt, row_a_b_ntt) = &rgsw_ntt[i];
        // result_a += a_decomp_ntt[i] * row_a_a_ntt
        // result_b += a_decomp_ntt[i] * row_a_b_ntt
        result_a.mul_acc_ntt_domain(&a_decomp_ntt[i], row_a_a_ntt, ctx);
        result_b.mul_acc_ntt_domain(&a_decomp_ntt[i], row_a_b_ntt, ctx);

        let (row_b_a_ntt, row_b_b_ntt) = &rgsw_ntt[ell + i];
        // result_a += b_decomp_ntt[i] * row_b_a_ntt
        // result_b += b_decomp_ntt[i] * row_b_b_ntt
        result_a.mul_acc_ntt_domain(&b_decomp_ntt[i], row_b_a_ntt, ctx);
        result_b.mul_acc_ntt_domain(&b_decomp_ntt[i], row_b_b_ntt, ctx);
    }

    // Single inverse NTT per component at the end.
    result_a.from_ntt(ctx);
    result_b.from_ntt(ctx);

    RlweCiphertext::from_parts(result_a, result_b)
}

/// Compute the external product: RLWE(m₀) ⊡ RGSW(m₁) → RLWE(m₀·m₁)
///
/// This is the key operation for homomorphic multiplication by an encrypted bit.
///
/// # Algorithm
///
/// Given RLWE ciphertext (a, b) and RGSW ciphertext C:
/// 1. Decompose a and b using gadget inverse: g⁻¹(a), g⁻¹(b)
/// 2. Compute: (a', b') = Σᵢ \[g⁻¹(a)ᵢ · C\[i\] + g⁻¹(b)ᵢ · C\[ℓ+i\]\]
///
/// The result decrypts to m₀·m₁ with controlled noise growth.
pub fn external_product(
    rlwe: &RlweCiphertext,
    rgsw: &RgswCiphertext,
    ctx: &NttContext,
) -> RlweCiphertext {
    let d = rlwe.ring_dim();
    let moduli = rlwe.a.moduli();
    let gadget = &rgsw.gadget;
    let ell = gadget.len;
    assert_eq!(rlwe.b.moduli(), moduli, "RLWE components must share moduli");
    assert_eq!(
        ctx.moduli(),
        moduli,
        "NTT context moduli must match ciphertext moduli"
    );
    assert_eq!(rgsw.rows.len(), 2 * ell, "RGSW must have 2ℓ rows");
    for (idx, row) in rgsw.rows.iter().enumerate() {
        assert_eq!(
            row.ring_dim(),
            d,
            "RGSW row[{idx}] has mismatched ring dimension"
        );
        assert_eq!(
            row.a.moduli(),
            moduli,
            "RGSW row[{idx}] moduli mismatch in a component"
        );
        assert_eq!(
            row.b.moduli(),
            moduli,
            "RGSW row[{idx}] moduli mismatch in b component"
        );
    }

    // Decompose both components of the RLWE ciphertext
    let a_decomp = gadget_decompose(&rlwe.a, gadget);
    let b_decomp = gadget_decompose(&rlwe.b, gadget);

    // Initialize result as zero
    let mut result_a = Poly::zero_moduli(d, moduli);
    let mut result_b = Poly::zero_moduli(d, moduli);

    // Sum over decomposition digits
    for i in 0..ell {
        // First ℓ rows of RGSW correspond to 'a' component
        // g⁻¹(a)ᵢ · RGSW[i]
        let row_a = &rgsw.rows[i];
        let term_a_a = a_decomp[i].mul_ntt(&row_a.a, ctx);
        let term_a_b = a_decomp[i].mul_ntt(&row_a.b, ctx);
        result_a += term_a_a;
        result_b += term_a_b;

        // Next ℓ rows of RGSW correspond to 'b' component
        // g⁻¹(b)ᵢ · RGSW[ℓ+i]
        let row_b = &rgsw.rows[ell + i];
        let term_b_a = b_decomp[i].mul_ntt(&row_b.a, ctx);
        let term_b_b = b_decomp[i].mul_ntt(&row_b.b, ctx);
        result_a += term_b_a;
        result_b += term_b_b;
    }

    RlweCiphertext::from_parts(result_a, result_b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::GaussianSampler;
    use crate::params::InspireParams;
    use crate::rlwe::RlweSecretKey;

    fn test_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    fn make_ctx(params: &InspireParams) -> NttContext {
        params.ntt_context()
    }

    fn sample_error_poly(dim: usize, moduli: &[u64], sampler: &mut GaussianSampler) -> Poly {
        Poly::sample_gaussian_moduli(dim, moduli, sampler)
    }

    #[test]
    fn test_gadget_decompose_reconstruct_roundtrip() {
        let params = test_params();
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Random polynomial
        let poly = Poly::random_moduli(params.ring_dim, params.moduli());

        // Decompose and reconstruct
        let decomposed = gadget_decompose(&poly, &gadget);
        let reconstructed = gadget_reconstruct(&decomposed, &gadget);

        // Should be equal
        assert_eq!(poly, reconstructed);
    }

    #[test]
    fn test_gadget_decompose_small_digits() {
        let params = test_params();
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        let poly = Poly::random_moduli(params.ring_dim, params.moduli());
        let decomposed = gadget_decompose(&poly, &gadget);

        // Each digit should be in [0, base) range
        for digit_poly in &decomposed {
            for j in 0..params.ring_dim {
                let coeff = digit_poly.coeff(j);
                assert!(
                    coeff < params.gadget_base,
                    "Digit {} exceeds base {}",
                    coeff,
                    params.gadget_base
                );
            }
        }
    }

    #[test]
    fn test_gadget_decompose_zero() {
        let params = test_params();
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        let zero = Poly::zero_moduli(params.ring_dim, params.moduli());
        let decomposed = gadget_decompose(&zero, &gadget);

        for digit_poly in &decomposed {
            assert!(digit_poly.is_zero());
        }
    }

    #[test]
    fn test_external_product_by_zero() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Encrypt a message
        let msg_coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|i| (i as u64) % params.p)
            .collect();
        let msg = Poly::from_coeffs_moduli(msg_coeffs, params.moduli());
        let a = Poly::random_moduli(params.ring_dim, params.moduli());
        let e = sample_error_poly(params.ring_dim, params.moduli(), &mut sampler);
        let rlwe = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

        // RGSW(0)
        let rgsw_zero =
            super::super::RgswCiphertext::encrypt_scalar(&sk, 0, &gadget, &mut sampler, &ctx);

        // External product with RGSW(0) should give encryption of 0
        let result = external_product(&rlwe, &rgsw_zero, &ctx);
        let decrypted = result.decrypt(&sk, delta, params.p, &ctx);

        // All coefficients should be 0 (or very close due to noise)
        for i in 0..params.ring_dim {
            assert_eq!(decrypted.coeff(i), 0, "Expected 0 at coefficient {}", i);
        }
    }

    #[test]
    fn test_external_product_by_one() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Encrypt a message
        let msg_coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|i| (i as u64) % params.p)
            .collect();
        let msg = Poly::from_coeffs_moduli(msg_coeffs.clone(), params.moduli());
        let a = Poly::random_moduli(params.ring_dim, params.moduli());
        let e = sample_error_poly(params.ring_dim, params.moduli(), &mut sampler);
        let rlwe = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

        // RGSW(1)
        let rgsw_one =
            super::super::RgswCiphertext::encrypt_scalar(&sk, 1, &gadget, &mut sampler, &ctx);

        // External product with RGSW(1) should preserve the message
        let result = external_product(&rlwe, &rgsw_one, &ctx);
        let decrypted = result.decrypt(&sk, delta, params.p, &ctx);

        for (i, expected) in msg_coeffs.iter().enumerate().take(params.ring_dim) {
            assert_eq!(
                decrypted.coeff(i),
                *expected,
                "Mismatch at coefficient {}",
                i
            );
        }
    }

    #[test]
    fn test_external_product_scalar_multiplication() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Encrypt message with small values
        let msg_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 10).collect();
        let msg = Poly::from_coeffs_moduli(msg_coeffs.clone(), params.moduli());
        let a = Poly::random_moduli(params.ring_dim, params.moduli());
        let e = sample_error_poly(params.ring_dim, params.moduli(), &mut sampler);
        let rlwe = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

        // RGSW(3)
        let scalar = 3u64;
        let rgsw_scalar =
            super::super::RgswCiphertext::encrypt_scalar(&sk, scalar, &gadget, &mut sampler, &ctx);

        // External product should multiply by 3
        let result = external_product(&rlwe, &rgsw_scalar, &ctx);
        let decrypted = result.decrypt(&sk, delta, params.p, &ctx);

        for (i, msg_coeff) in msg_coeffs.iter().enumerate().take(params.ring_dim) {
            let expected = (*msg_coeff * scalar) % params.p;
            assert_eq!(
                decrypted.coeff(i),
                expected,
                "Mismatch at coefficient {}: expected {}, got {}",
                i,
                expected,
                decrypted.coeff(i)
            );
        }
    }

    #[test]
    fn test_external_product_monomial() {
        let params = test_params();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let delta = params.delta();

        let sk = RlweSecretKey::generate(&params, &mut sampler);
        let gadget = GadgetVector::new(params.gadget_base, params.gadget_len, params.q);

        // Encrypt constant message
        let mut msg_coeffs = vec![0u64; params.ring_dim];
        msg_coeffs[0] = 5;
        let msg = Poly::from_coeffs_moduli(msg_coeffs, params.moduli());
        let a = Poly::random_moduli(params.ring_dim, params.moduli());
        let e = sample_error_poly(params.ring_dim, params.moduli(), &mut sampler);
        let rlwe = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

        // RGSW(X) - monomial
        let mut monomial_coeffs = vec![0u64; params.ring_dim];
        monomial_coeffs[1] = 1;
        let monomial = Poly::from_coeffs_moduli(monomial_coeffs, params.moduli());
        let rgsw_mono =
            super::super::RgswCiphertext::encrypt(&sk, &monomial, &gadget, &mut sampler, &ctx);

        // External product: 5 * X = 5X
        let result = external_product(&rlwe, &rgsw_mono, &ctx);
        let decrypted = result.decrypt(&sk, delta, params.p, &ctx);

        assert_eq!(decrypted.coeff(0), 0, "Constant term should be 0");
        assert_eq!(decrypted.coeff(1), 5, "X coefficient should be 5");
        for i in 2..params.ring_dim {
            assert_eq!(decrypted.coeff(i), 0, "Higher terms should be 0");
        }
    }
}
