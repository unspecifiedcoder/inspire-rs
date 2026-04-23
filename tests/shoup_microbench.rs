//! Microbenchmark: Shoup vs Montgomery NTT butterflies.
//!
//! Before committing to the invasive hot-path integration, measure the
//! ISOLATED win on the core NTT operations. If Shoup at butterfly level
//! is clearly faster than Montgomery here, the integration-cost/benefit
//! calculus favors proceeding. If not, Shoup is wasted scope and we
//! should pivot straight to IFMA52.
//!
//! Runs under `cargo test --release`. Gated behind `RAVEN_MICROBENCH=1`
//! env var so it does not fire during the regular regression runs.

use raven_inspire::math::mod_q::DEFAULT_Q;
use raven_inspire::math::ntt::NttContext;

use std::time::Instant;

const N: usize = 2048;
const ITERS: usize = 5_000;

fn build_input(ctx: &NttContext, seed: u64) -> Vec<u64> {
    // Pseudo-random values in [0, q). SplitMix64-derived; deterministic.
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
fn microbench_shoup_vs_montgomery_forward() {
    if std::env::var("RAVEN_MICROBENCH").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set RAVEN_MICROBENCH=1 to run");
        return;
    }

    let ctx = NttContext::with_default_q(N);

    // Warmup both paths.
    for s in 0..16u64 {
        let mut v = build_input(&ctx, s);
        ctx.forward(&mut v);
    }
    for s in 0..16u64 {
        let mut v = build_input(&ctx, s);
        ctx.forward_shoup(&mut v);
    }

    // Montgomery timing.
    let inputs: Vec<Vec<u64>> = (0..ITERS as u64).map(|s| build_input(&ctx, s)).collect();
    let t0 = Instant::now();
    for mut v in inputs.clone() {
        ctx.forward(&mut v);
        std::hint::black_box(&v);
    }
    let mont_elapsed = t0.elapsed();

    // Shoup timing (same inputs).
    let inputs: Vec<Vec<u64>> = (0..ITERS as u64).map(|s| build_input(&ctx, s)).collect();
    let t0 = Instant::now();
    for mut v in inputs {
        ctx.forward_shoup(&mut v);
        std::hint::black_box(&v);
    }
    let shoup_elapsed = t0.elapsed();

    let mont_us_per = mont_elapsed.as_secs_f64() * 1e6 / ITERS as f64;
    let shoup_us_per = shoup_elapsed.as_secs_f64() * 1e6 / ITERS as f64;
    let speedup = mont_us_per / shoup_us_per;

    eprintln!("=== Forward NTT at n={N}, {ITERS} iters ===");
    eprintln!("  Montgomery: {mont_us_per:.3} μs/call");
    eprintln!("  Shoup:      {shoup_us_per:.3} μs/call");
    eprintln!("  Speedup:    {speedup:.3}x");
}

#[test]
fn microbench_shoup_vs_montgomery_inverse() {
    if std::env::var("RAVEN_MICROBENCH").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set RAVEN_MICROBENCH=1 to run");
        return;
    }

    let ctx = NttContext::with_default_q(N);

    // Warmup.
    for s in 0..16u64 {
        let mut v = build_input(&ctx, s);
        ctx.forward(&mut v);
        ctx.inverse(&mut v);
    }
    for s in 0..16u64 {
        let mut v = build_input(&ctx, s);
        ctx.forward_shoup(&mut v);
        ctx.inverse_shoup(&mut v);
    }

    // Montgomery inverse: pre-forward each input, then time inverse.
    let mont_inputs: Vec<Vec<u64>> = (0..ITERS as u64)
        .map(|s| {
            let mut v = build_input(&ctx, s);
            ctx.forward(&mut v);
            v
        })
        .collect();
    let t0 = Instant::now();
    for mut v in mont_inputs {
        ctx.inverse(&mut v);
        std::hint::black_box(&v);
    }
    let mont_elapsed = t0.elapsed();

    // Shoup inverse.
    let shoup_inputs: Vec<Vec<u64>> = (0..ITERS as u64)
        .map(|s| {
            let mut v = build_input(&ctx, s);
            ctx.forward_shoup(&mut v);
            v
        })
        .collect();
    let t0 = Instant::now();
    for mut v in shoup_inputs {
        ctx.inverse_shoup(&mut v);
        std::hint::black_box(&v);
    }
    let shoup_elapsed = t0.elapsed();

    let mont_us_per = mont_elapsed.as_secs_f64() * 1e6 / ITERS as f64;
    let shoup_us_per = shoup_elapsed.as_secs_f64() * 1e6 / ITERS as f64;
    let speedup = mont_us_per / shoup_us_per;

    eprintln!("=== Inverse NTT at n={N}, {ITERS} iters ===");
    eprintln!("  Montgomery: {mont_us_per:.3} μs/call");
    eprintln!("  Shoup:      {shoup_us_per:.3} μs/call");
    eprintln!("  Speedup:    {speedup:.3}x");
}

#[test]
fn microbench_shoup_pointwise_vs_montgomery() {
    if std::env::var("RAVEN_MICROBENCH").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set RAVEN_MICROBENCH=1 to run");
        return;
    }

    let ctx = NttContext::with_default_q(N);

    // Build NTT-domain operands for each path. Shoup path's b_shoup is
    // precomputed ONCE outside the timing loop to model the realistic
    // session-cached case (w_all_ntt).
    let a_std: Vec<u64> = build_input(&ctx, 42);
    let b_std: Vec<u64> = build_input(&ctx, 7);

    let mut a_mont = a_std.clone();
    ctx.forward(&mut a_mont);
    let mut b_mont = b_std.clone();
    ctx.forward(&mut b_mont);

    let mut a_shoup_ntt = a_std.clone();
    ctx.forward_shoup(&mut a_shoup_ntt);
    let mut b_shoup_ntt = b_std.clone();
    ctx.forward_shoup(&mut b_shoup_ntt);
    let b_shoup_twins = ctx.shoup_precompute_vec(&b_shoup_ntt);

    // Warmup.
    let mut out_mont = vec![0u64; N];
    for _ in 0..100 {
        ctx.pointwise_mul(&a_mont, &b_mont, &mut out_mont);
    }
    let mut out_shoup = vec![0u64; N];
    for _ in 0..100 {
        ctx.pointwise_mul_shoup(&a_shoup_ntt, &b_shoup_ntt, &b_shoup_twins, &mut out_shoup);
    }

    let iters = ITERS * 10;

    let t0 = Instant::now();
    for _ in 0..iters {
        ctx.pointwise_mul(&a_mont, &b_mont, &mut out_mont);
        std::hint::black_box(&out_mont);
    }
    let mont_elapsed = t0.elapsed();

    let t0 = Instant::now();
    for _ in 0..iters {
        ctx.pointwise_mul_shoup(&a_shoup_ntt, &b_shoup_ntt, &b_shoup_twins, &mut out_shoup);
        std::hint::black_box(&out_shoup);
    }
    let shoup_elapsed = t0.elapsed();

    let mont_us_per = mont_elapsed.as_secs_f64() * 1e6 / iters as f64;
    let shoup_us_per = shoup_elapsed.as_secs_f64() * 1e6 / iters as f64;
    let speedup = mont_us_per / shoup_us_per;

    eprintln!("=== Pointwise mul at n={N}, {iters} iters ===");
    eprintln!("  Montgomery:            {mont_us_per:.3} μs/call");
    eprintln!("  Shoup (b precomputed): {shoup_us_per:.3} μs/call");
    eprintln!("  Speedup:               {speedup:.3}x");
}
