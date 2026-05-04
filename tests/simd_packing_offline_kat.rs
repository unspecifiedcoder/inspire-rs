//! Byte-identity KAT for the AVX-512-IFMA52 multiply-accumulate
//! dispatch in `Poly::mul_acc_ntt_domain`.
//!
//! Locks the invariant that the SIMD path produces bit-identical output
//! to the scalar Solinas-Montgomery path for every coefficient,
//! across:
//!
//! - The packing-offline gadget length γ ∈ {16, 64, 256} (mirroring
//!   the production sweep), and
//! - Single-prime DEFAULT_Q + Solinas-Montgomery semantics (the only
//!   configuration the SIMD path is gated on).
//!
//! This KAT runs unconditionally when the host CPU exposes
//! AVX-512-IFMA52; otherwise it skips with an explanatory message.
//! A failure here = invention broken = revert.

use raven_inspire::math::mod_q::DEFAULT_Q;
use raven_inspire::math::ntt::NttContext;
use raven_inspire::math::Poly;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Build a deterministic NTT-domain polynomial for KAT inputs.
///
/// Uses a seeded `StdRng` so the test is reproducible; coefficients
/// are sampled in `[0, q)` then routed through `to_ntt` so the
/// resulting `Poly` matches the precondition of `mul_acc_ntt_domain`
/// (Montgomery form, NTT-domain).
fn random_ntt_poly(seed: u64, n: usize, ctx: &NttContext) -> Poly {
    let mut rng = StdRng::seed_from_u64(seed);
    let q = DEFAULT_Q;
    let coeffs: Vec<u64> = (0..n).map(|_| rng.gen_range(0..q)).collect();
    let mut p = Poly::from_coeffs(coeffs, q);
    p.to_ntt(ctx);
    p
}

/// Drive `mul_acc_ntt_domain` for a fixed scalar/SIMD pair and assert
/// per-coefficient equality across the full ring stripe.
///
/// `γ` is the gadget-decomposition fan-in: the kernel is invoked
/// `γ` times against fresh `(a, b)` pairs to mirror the
/// inspiring2.rs backward recursion shape.
fn run_kat_at(n: usize, gamma: usize, base_seed: u64) {
    let ctx = NttContext::with_default_q(n);

    // Build γ independent (a, b) pairs deterministically.
    let pairs: Vec<(Poly, Poly)> = (0..gamma)
        .map(|k| {
            let a = random_ntt_poly(base_seed + (k as u64) * 2, n, &ctx);
            let b = random_ntt_poly(base_seed + (k as u64) * 2 + 1, n, &ctx);
            (a, b)
        })
        .collect();

    // Reference accumulator (what the scalar path computes).
    let mut acc_ref = Poly::zero_default(n);
    acc_ref.to_ntt(&ctx);

    // SIMD accumulator (what the dispatched path computes).
    let mut acc_simd = acc_ref.clone();

    // Drive the reference scalar path manually: it's an exact mirror
    // of the scalar branch in `Poly::mul_acc_ntt_domain` against the
    // single-prime DEFAULT_Q config (which routes through
    // pointwise_mul -> pointwise_mul_solinas internally), so the
    // reference accumulation here represents the byte-exact "no
    // dispatch" semantics. We work on the raw coefficient slice
    // because NTT-domain `coeff()`/`set_coeff()` are intentionally
    // forbidden.
    let mut tmp_prod = vec![0u64; n];
    for (a, b) in &pairs {
        ctx.pointwise_mul(a.coeffs(), b.coeffs(), &mut tmp_prod);
        let acc_slice = acc_ref.coeffs_mut();
        for i in 0..n {
            let sum = acc_slice[i] + tmp_prod[i];
            acc_slice[i] = if sum >= DEFAULT_Q {
                sum - DEFAULT_Q
            } else {
                sum
            };
        }
    }

    // Drive the SIMD-or-scalar dispatched path through the public API.
    for (a, b) in &pairs {
        acc_simd.mul_acc_ntt_domain(a, b, &ctx);
    }

    // Byte-identity per coefficient against the raw NTT-domain slice.
    let ref_slice = acc_ref.coeffs();
    let simd_slice = acc_simd.coeffs();
    assert_eq!(
        ref_slice.len(),
        simd_slice.len(),
        "γ={gamma} n={n} seed={base_seed}: coefficient slice lengths differ"
    );
    for i in 0..ref_slice.len() {
        assert_eq!(
            ref_slice[i], simd_slice[i],
            "γ={gamma} n={n} seed={base_seed}: coeff[{i}] differs (ref={}, dispatched={})",
            ref_slice[i], simd_slice[i]
        );
    }
}

#[test]
fn dispatched_mul_acc_matches_scalar_at_gamma_16() {
    if !is_x86_feature_detected!("avx512ifma") {
        eprintln!("SKIP: host lacks AVX-512-IFMA52 (dispatch falls through to scalar; no divergence to test)");
        return;
    }
    run_kat_at(2048, 16, 0xC0DEC0DE);
}

#[test]
fn dispatched_mul_acc_matches_scalar_at_gamma_64() {
    if !is_x86_feature_detected!("avx512ifma") {
        eprintln!("SKIP: host lacks AVX-512-IFMA52");
        return;
    }
    run_kat_at(2048, 64, 0xBADCAFE);
}

#[test]
fn dispatched_mul_acc_matches_scalar_at_gamma_256() {
    if !is_x86_feature_detected!("avx512ifma") {
        eprintln!("SKIP: host lacks AVX-512-IFMA52");
        return;
    }
    run_kat_at(2048, 256, 0xFEEDBEEF);
}

#[test]
fn dispatched_mul_acc_matches_scalar_smaller_n() {
    // Smaller ring dim still divisible by 8 — locks the loop edge case.
    if !is_x86_feature_detected!("avx512ifma") {
        eprintln!("SKIP: host lacks AVX-512-IFMA52");
        return;
    }
    run_kat_at(256, 16, 0x1234_5678);
}
