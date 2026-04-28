//! IFMA52 Montgomery differential KAT.
//!
//! Verifies:
//! - `mont_mul_split52` (scalar reference) is byte-identical to
//!   inspire-rs's `to_mont` / `from_mont` round-trip across 10 000
//!   random inputs.
//! - `avx512_ifma::pointwise_mont_mul_x8` produces lane-identical
//!   results to the scalar reference on AVX-512-IFMA-capable hardware;
//!   auto-skips on hosts without the feature.
//!
//! Integration gate: no IFMA52 code lands in the hot path until this
//! KAT is green. A failure here = invention broken = revert, pivot.

use raven_inspire::math::ifma52::{ifma52_product_lohi, mont_mul_split52};
use raven_inspire::math::mod_q::DEFAULT_Q;
use raven_inspire::math::ntt::NttContext;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Reference Montgomery multiply via inspire-rs's NttContext: Mont-mul
/// is the private `montgomery_mul_at`; we access via the round-trip
/// `to_mont(a) * to_mont(b)` reduced. Simpler path: go through the
/// scalar NTT's `pointwise_mul` with a single non-zero position.
fn ref_mont_mul(ctx: &NttContext, a: u64, b: u64) -> u64 {
    let a_mont = ctx.to_mont(a);
    let b_mont = ctx.to_mont(b);
    let ab_mont = ctx.pointwise_mul_single(a_mont, b_mont);
    ctx.from_mont(ab_mont)
}

fn naive_mul_mod(a: u64, b: u64, q: u64) -> u64 {
    (((a as u128) * (b as u128)) % (q as u128)) as u64
}

#[test]
fn ifma52_product_lohi_matches_u128() {
    let q = DEFAULT_Q;
    let mut rng = StdRng::seed_from_u64(0xA11CE);

    for _ in 0..10_000 {
        let a = rng.gen_range(0..q);
        let b = rng.gen_range(0..q);

        let (lo, hi) = ifma52_product_lohi(a, b);
        let combined: u128 = (lo as u128) | ((hi as u128) << 64);
        let expected: u128 = (a as u128) * (b as u128);

        assert_eq!(
            combined, expected,
            "ifma52_product_lohi mismatch: a={a} b={b} lo={lo:016x} hi={hi:016x} \
             combined={combined:032x} expected={expected:032x}"
        );
    }
}

#[test]
fn ifma52_product_edge_cases() {
    let q = DEFAULT_Q;
    let edges: Vec<u64> = vec![
        0,
        1,
        2,
        (1u64 << 51) - 1,
        1u64 << 51,
        (1u64 << 52) - 1,
        1u64 << 52,
        (1u64 << 52) + 1,
        (1u64 << 59),
        (1u64 << 60) - (1u64 << 14) - 1, // q - 2
        q - 1,
    ];

    for &a in &edges {
        if a >= q {
            continue;
        }
        for &b in &edges {
            if b >= q {
                continue;
            }
            let (lo, hi) = ifma52_product_lohi(a, b);
            let combined: u128 = (lo as u128) | ((hi as u128) << 64);
            let expected: u128 = (a as u128) * (b as u128);
            assert_eq!(
                combined, expected,
                "edge case a={a} b={b} combined={combined:032x} expected={expected:032x}"
            );
        }
    }
}

#[test]
fn mont_mul_split52_matches_ref_default_q() {
    let q = DEFAULT_Q;
    let ctx = NttContext::with_default_q(2048);
    let q_inv_neg = ctx.q_inv_neg_for_test(0);

    let mut rng = StdRng::seed_from_u64(0xB0B_u64);
    for _ in 0..10_000 {
        let a = rng.gen_range(0..q);
        let b = rng.gen_range(0..q);

        // Reference: Montgomery round-trip via NttContext.
        let expected = ref_mont_mul(&ctx, a, b);

        // Candidate: mont_mul_split52 operates on plain operands,
        // computing a * b * R^{-1} mod q directly. For it to produce
        // the same "plain" a * b mod q, we feed in Montgomery-form a,
        // Montgomery-form b, and interpret the output as Montgomery-
        // form a*b. Or: feed plain a, plain b, and the output is
        // a*b*R^{-1} mod q; one more mont_mul_split52 call with R^2
        // lifts it back. Simpler check: verify the operator matches
        // NttContext's `montgomery_mul_at` on Montgomery-form inputs.
        let a_mont = ctx.to_mont(a);
        let b_mont = ctx.to_mont(b);
        let candidate_mont_form = mont_mul_split52(a_mont, b_mont, q, q_inv_neg);
        let candidate = ctx.from_mont(candidate_mont_form);

        assert_eq!(
            candidate, expected,
            "mont_mul_split52 disagrees with reference: a={a} b={b} \
             candidate={candidate} expected={expected}"
        );
        // Also verify against u128 naive.
        assert_eq!(candidate, naive_mul_mod(a, b, q));
    }
}

#[test]
fn mont_mul_split52_edge_cases_default_q() {
    let q = DEFAULT_Q;
    let ctx = NttContext::with_default_q(2048);
    let q_inv_neg = ctx.q_inv_neg_for_test(0);

    let edges: Vec<u64> = vec![0, 1, (1u64 << 52) - 1, 1u64 << 52, q / 2, q - 2, q - 1];
    for &a in &edges {
        if a >= q {
            continue;
        }
        for &b in &edges {
            if b >= q {
                continue;
            }
            let a_mont = ctx.to_mont(a);
            let b_mont = ctx.to_mont(b);
            let candidate = ctx.from_mont(mont_mul_split52(a_mont, b_mont, q, q_inv_neg));
            let expected = naive_mul_mod(a, b, q);
            assert_eq!(
                candidate, expected,
                "edge a={a} b={b} got={candidate} expected={expected}"
            );
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn ifma52_x8_matches_scalar_default_q() {
    if !is_x86_feature_detected!("avx512ifma") || !is_x86_feature_detected!("avx512f") {
        eprintln!("SKIP: host lacks AVX-512-IFMA");
        return;
    }

    use raven_inspire::math::ifma52::avx512_ifma::pointwise_mont_mul_x8;

    let q = DEFAULT_Q;
    let ctx = NttContext::with_default_q(2048);
    let q_inv_neg = ctx.q_inv_neg_for_test(0);
    let mut rng = StdRng::seed_from_u64(0xCAFE_CAFE);

    // Run 1024 batches of 8 lanes = 8192 paired inputs.
    let len = 8192usize;
    let a_std: Vec<u64> = (0..len).map(|_| rng.gen_range(0..q)).collect();
    let b_std: Vec<u64> = (0..len).map(|_| rng.gen_range(0..q)).collect();

    // Montgomery-convert inputs.
    let a_mont: Vec<u64> = a_std.iter().map(|&a| ctx.to_mont(a)).collect();
    let b_mont: Vec<u64> = b_std.iter().map(|&b| ctx.to_mont(b)).collect();

    // Scalar reference.
    let expected: Vec<u64> = a_mont
        .iter()
        .zip(b_mont.iter())
        .map(|(&am, &bm)| mont_mul_split52(am, bm, q, q_inv_neg))
        .collect();

    // SIMD candidate.
    let mut candidate = vec![0u64; len];
    unsafe {
        pointwise_mont_mul_x8(&a_mont, &b_mont, &mut candidate, q, q_inv_neg);
    }

    // Lane-by-lane comparison for diagnostic quality.
    for i in 0..len {
        assert_eq!(
            candidate[i], expected[i],
            "SIMD IFMA52 lane mismatch at i={i}: candidate={} expected={} \
             (a_mont={} b_mont={})",
            candidate[i], expected[i], a_mont[i], b_mont[i]
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn ifma52_x8_matches_naive_default_q() {
    if !is_x86_feature_detected!("avx512ifma") || !is_x86_feature_detected!("avx512f") {
        eprintln!("SKIP: host lacks AVX-512-IFMA");
        return;
    }

    use raven_inspire::math::ifma52::avx512_ifma::pointwise_mont_mul_x8;

    let q = DEFAULT_Q;
    let ctx = NttContext::with_default_q(2048);
    let q_inv_neg = ctx.q_inv_neg_for_test(0);

    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
    let len = 8192usize;

    let a_std: Vec<u64> = (0..len).map(|_| rng.gen_range(0..q)).collect();
    let b_std: Vec<u64> = (0..len).map(|_| rng.gen_range(0..q)).collect();

    let a_mont: Vec<u64> = a_std.iter().map(|&a| ctx.to_mont(a)).collect();
    let b_mont: Vec<u64> = b_std.iter().map(|&b| ctx.to_mont(b)).collect();

    let mut simd_out = vec![0u64; len];
    unsafe {
        pointwise_mont_mul_x8(&a_mont, &b_mont, &mut simd_out, q, q_inv_neg);
    }

    // Strip Montgomery form; compare to naive a*b mod q.
    for i in 0..len {
        let got = ctx.from_mont(simd_out[i]);
        let want = naive_mul_mod(a_std[i], b_std[i], q);
        assert_eq!(
            got, want,
            "lane {i}: a={} b={} got={} want={}",
            a_std[i], b_std[i], got, want
        );
    }
}
