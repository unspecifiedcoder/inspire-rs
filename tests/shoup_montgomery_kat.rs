//! The Shoup NTT path must be byte-identical to the Montgomery path at
//! DEFAULT_Q and at each 30-bit 2-CRT prime, cross-checked against u128
//! modular multiplication. Nothing Shoup-based enters the hot path until this
//! is green.

use raven_inspire::math::mod_q::DEFAULT_Q;
use raven_inspire::math::ntt::NttContext;
use raven_inspire::params::DEFAULT_Q_2CRT_30BIT;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn naive_mul_mod(a: u64, b: u64, q: u64) -> u64 {
    (((a as u128) * (b as u128)) % (q as u128)) as u64
}

fn random_std_coeffs(n: usize, moduli: &[u64], seed: u64) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut out = Vec::with_capacity(n * moduli.len());
    for &q in moduli {
        for _ in 0..n {
            out.push(rng.gen_range(0..q));
        }
    }
    out
}

#[test]
fn shoup_scalar_mul_matches_naive_default_q() {
    let n = 2048usize;
    let ctx = NttContext::with_default_q(n);
    let q = DEFAULT_Q;

    let mut rng = StdRng::seed_from_u64(0xA11CE_u64);
    for _ in 0..10_000 {
        let a = rng.gen_range(0..q);
        let b = rng.gen_range(0..q);
        let expected = naive_mul_mod(a, b, q);

        // one non-zero position; shoup_mul_at(0, ..) = 0 leaves the rest inert
        let total = n * ctx.crt_count();
        let mut a_vec = vec![0u64; total];
        let mut b_vec = vec![0u64; total];
        a_vec[0] = a;
        b_vec[0] = b;
        let b_shoup = ctx.shoup_precompute_vec(&b_vec);
        let mut result = vec![0u64; total];
        ctx.pointwise_mul_shoup(&a_vec, &b_vec, &b_shoup, &mut result);

        assert_eq!(
            result[0], expected,
            "shoup_mul at position 0 disagrees with naive: a={a} b={b} q={q} got={} expected={expected}",
            result[0]
        );
    }
}

#[test]
fn shoup_scalar_mul_matches_naive_2crt_30bit_limb0() {
    let q = DEFAULT_Q_2CRT_30BIT[0];
    let n = 2048usize;
    let ctx = NttContext::new(n, q);

    let mut rng = StdRng::seed_from_u64(0xB0B_u64);
    for _ in 0..10_000 {
        let a = rng.gen_range(0..q);
        let b = rng.gen_range(0..q);
        let expected = naive_mul_mod(a, b, q);

        let total = n;
        let mut a_vec = vec![0u64; total];
        let mut b_vec = vec![0u64; total];
        a_vec[0] = a;
        b_vec[0] = b;
        let b_shoup = ctx.shoup_precompute_vec(&b_vec);
        let mut result = vec![0u64; total];
        ctx.pointwise_mul_shoup(&a_vec, &b_vec, &b_shoup, &mut result);

        assert_eq!(result[0], expected, "2-CRT limb-0 shoup mismatch");
    }
}

#[test]
fn shoup_scalar_mul_matches_naive_2crt_30bit_limb1() {
    let q = DEFAULT_Q_2CRT_30BIT[1];
    let n = 2048usize;
    let ctx = NttContext::new(n, q);

    let mut rng = StdRng::seed_from_u64(0xCAFE_u64);
    for _ in 0..10_000 {
        let a = rng.gen_range(0..q);
        let b = rng.gen_range(0..q);
        let expected = naive_mul_mod(a, b, q);

        let total = n;
        let mut a_vec = vec![0u64; total];
        let mut b_vec = vec![0u64; total];
        a_vec[0] = a;
        b_vec[0] = b;
        let b_shoup = ctx.shoup_precompute_vec(&b_vec);
        let mut result = vec![0u64; total];
        ctx.pointwise_mul_shoup(&a_vec, &b_vec, &b_shoup, &mut result);

        assert_eq!(result[0], expected, "2-CRT limb-1 shoup mismatch");
    }
}

#[test]
fn shoup_forward_inverse_roundtrip_default_q_small() {
    for &n in &[16usize, 64, 256, 1024, 2048] {
        let ctx = NttContext::with_default_q(n);
        let original = random_std_coeffs(n, ctx.moduli(), 0xDEAD_u64 + n as u64);
        let mut coeffs = original.clone();
        ctx.forward_shoup(&mut coeffs);
        ctx.inverse_shoup(&mut coeffs);
        assert_eq!(
            coeffs, original,
            "Shoup forward-inverse roundtrip failed at n={n}"
        );
    }
}

#[test]
fn shoup_forward_inverse_roundtrip_2crt_30bit() {
    for &n in &[256usize, 1024, 2048] {
        let ctx = NttContext::with_moduli(n, &DEFAULT_Q_2CRT_30BIT);
        let original = random_std_coeffs(n, ctx.moduli(), 0xBEEF_u64 + n as u64);
        let mut coeffs = original.clone();
        ctx.forward_shoup(&mut coeffs);
        ctx.inverse_shoup(&mut coeffs);
        assert_eq!(
            coeffs, original,
            "Shoup forward-inverse roundtrip 2-CRT failed at n={n}"
        );
    }
}

#[test]
fn shoup_convolution_matches_montgomery_default_q() {
    let n = 256usize;
    let ctx = NttContext::with_default_q(n);
    let q = DEFAULT_Q;
    let mut rng = StdRng::seed_from_u64(0x1234_5678);

    for trial in 0..16 {
        let a: Vec<u64> = (0..n).map(|_| rng.gen_range(0..q)).collect();
        let b: Vec<u64> = (0..n).map(|_| rng.gen_range(0..q)).collect();

        let mut a_mont = a.clone();
        let mut b_mont = b.clone();
        ctx.forward(&mut a_mont);
        ctx.forward(&mut b_mont);
        let mut result_mont = vec![0u64; n];
        ctx.pointwise_mul(&a_mont, &b_mont, &mut result_mont);
        ctx.inverse(&mut result_mont);

        let mut a_shoup = a.clone();
        let mut b_shoup_coeffs = b.clone();
        ctx.forward_shoup(&mut a_shoup);
        ctx.forward_shoup(&mut b_shoup_coeffs);
        let b_shoup_twins = ctx.shoup_precompute_vec(&b_shoup_coeffs);
        let mut result_shoup = vec![0u64; n];
        ctx.pointwise_mul_shoup(&a_shoup, &b_shoup_coeffs, &b_shoup_twins, &mut result_shoup);
        ctx.inverse_shoup(&mut result_shoup);

        assert_eq!(
            result_mont, result_shoup,
            "Shoup convolution disagrees with Montgomery at trial={trial}"
        );
    }
}

#[test]
fn shoup_edge_cases_default_q() {
    let n = 64usize;
    let ctx = NttContext::with_default_q(n);
    let q = DEFAULT_Q;

    let edges = [
        0u64,
        1,
        2,
        q - 1,
        q - 2,
        (1u64 << 32),
        (1u64 << 52) - 1,
        (1u64 << 52),
    ];
    for &a in &edges {
        if a >= q {
            continue;
        }
        for &b in &edges {
            if b >= q {
                continue;
            }
            let expected = naive_mul_mod(a, b, q);
            let total = n * ctx.crt_count();
            let mut a_vec = vec![0u64; total];
            let mut b_vec = vec![0u64; total];
            a_vec[0] = a;
            b_vec[0] = b;
            let b_shoup = ctx.shoup_precompute_vec(&b_vec);
            let mut result = vec![0u64; total];
            ctx.pointwise_mul_shoup(&a_vec, &b_vec, &b_shoup, &mut result);
            assert_eq!(
                result[0], expected,
                "edge case failed: a={a} b={b} q={q} got={} expected={expected}",
                result[0]
            );
        }
    }
}
