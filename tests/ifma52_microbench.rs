//! IFMA52 pointwise mul against scalar Montgomery; runs only under
//! `RAVEN_MICROBENCH=1`.

use raven_inspire::math::ifma52::avx512_ifma::pointwise_mont_mul_x8;
use raven_inspire::math::mod_q::DEFAULT_Q;
use raven_inspire::math::ntt::NttContext;

use std::time::Instant;

const N: usize = 2048;
const ITERS: usize = 50_000;

fn build_input(ctx: &NttContext, seed: u64) -> Vec<u64> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let q = ctx.modulus();
    (0..N)
        .map(|_| {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z ^= z >> 30;
            z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z ^= z >> 27;
            z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            z % q
        })
        .collect()
}

#[test]
fn microbench_ifma52_x8_vs_montgomery_pointwise() {
    if std::env::var("RAVEN_MICROBENCH").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set RAVEN_MICROBENCH=1 to run");
        return;
    }

    if !is_x86_feature_detected!("avx512ifma") {
        eprintln!("SKIP: host lacks AVX-512-IFMA");
        return;
    }

    let ctx = NttContext::with_default_q(N);
    let q = DEFAULT_Q;
    let q_inv_neg = ctx.q_inv_neg_for_test(0);

    let mut a = build_input(&ctx, 11);
    ctx.forward(&mut a);
    let mut b = build_input(&ctx, 17);
    ctx.forward(&mut b);

    let mut out_mont = vec![0u64; N];
    for _ in 0..100 {
        ctx.pointwise_mul(&a, &b, &mut out_mont);
        std::hint::black_box(&out_mont);
    }
    let mut out_ifma = vec![0u64; N];
    for _ in 0..100 {
        unsafe {
            pointwise_mont_mul_x8(&a, &b, &mut out_ifma, q, q_inv_neg);
        }
        std::hint::black_box(&out_ifma);
    }

    let t0 = Instant::now();
    for _ in 0..ITERS {
        ctx.pointwise_mul(&a, &b, &mut out_mont);
        std::hint::black_box(&out_mont);
    }
    let mont_elapsed = t0.elapsed();

    let t0 = Instant::now();
    for _ in 0..ITERS {
        unsafe {
            pointwise_mont_mul_x8(&a, &b, &mut out_ifma, q, q_inv_neg);
        }
        std::hint::black_box(&out_ifma);
    }
    let ifma_elapsed = t0.elapsed();

    let mont_ns_per = mont_elapsed.as_nanos() as f64 / ITERS as f64;
    let ifma_ns_per = ifma_elapsed.as_nanos() as f64 / ITERS as f64;
    let speedup = mont_ns_per / ifma_ns_per;

    eprintln!("=== Pointwise mul at n={N}, {ITERS} iters, DEFAULT_Q ===");
    eprintln!(
        "  Montgomery scalar: {mont_ns_per:.1} ns/call  ({:.3} μs)",
        mont_ns_per / 1000.0
    );
    eprintln!(
        "  IFMA52 8-wide:     {ifma_ns_per:.1} ns/call  ({:.3} μs)",
        ifma_ns_per / 1000.0
    );
    eprintln!("  Speedup:           {speedup:.3}x");

    assert_eq!(out_mont, out_ifma, "results diverged during microbench run");
}
