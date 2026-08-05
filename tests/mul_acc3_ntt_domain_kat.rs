//! `mul_acc3_ntt_domain` must be byte-identical to three chained
//! `mul_acc_ntt_domain` calls, at single-prime q and at 2-CRT.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use raven_inspire::math::mod_q::DEFAULT_Q;
use raven_inspire::math::{NttContext, Poly};

const D: usize = 256;
const ITERS: usize = 32;

fn random_poly_ntt(seed: u64, moduli: &[u64]) -> Poly {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut coeffs = Vec::with_capacity(D * moduli.len());
    for &q in moduli {
        for _ in 0..D {
            let bits = rand::RngCore::next_u64(&mut rng);
            coeffs.push(bits % q);
        }
    }
    let mut p = Poly::from_crt_coeffs(coeffs, moduli);
    let ctx = NttContext::with_moduli(D, moduli);
    p.to_ntt(&ctx);
    p
}

fn assert_byte_identical(a: &Poly, b: &Poly, label: &str) {
    assert_eq!(a.coeffs(), b.coeffs(), "coeffs mismatch ({label})");
    assert_eq!(a.is_ntt(), b.is_ntt(), "is_ntt flag mismatch ({label})");
    assert_eq!(a.moduli(), b.moduli(), "moduli mismatch ({label})");
}

#[test]
fn mul_acc3_matches_serial_chain_default_q() {
    let moduli = [DEFAULT_Q];
    let ctx = NttContext::with_moduli(D, &moduli);

    for seed in 0..ITERS as u64 {
        let a0 = random_poly_ntt(seed * 10, &moduli);
        let b0 = random_poly_ntt(seed * 10 + 1, &moduli);
        let a1 = random_poly_ntt(seed * 10 + 2, &moduli);
        let b1 = random_poly_ntt(seed * 10 + 3, &moduli);
        let a2 = random_poly_ntt(seed * 10 + 4, &moduli);
        let b2 = random_poly_ntt(seed * 10 + 5, &moduli);

        let base = random_poly_ntt(seed * 10 + 6, &moduli);

        let mut serial = base.clone();
        serial.mul_acc_ntt_domain(&a0, &b0, &ctx);
        serial.mul_acc_ntt_domain(&a1, &b1, &ctx);
        serial.mul_acc_ntt_domain(&a2, &b2, &ctx);

        let mut fused = base.clone();
        fused.mul_acc3_ntt_domain(&a0, &b0, &a1, &b1, &a2, &b2, &ctx);

        assert_byte_identical(&fused, &serial, &format!("seed={seed} default_q"));
    }
}

#[test]
fn mul_acc3_matches_serial_chain_2crt_30bit() {
    // both primes are 1 mod 512, so D=256 has a root of unity
    let moduli = [1_073_479_681u64, 1_073_692_673u64];
    let ctx = NttContext::with_moduli(D, &moduli);

    for seed in 0..ITERS as u64 {
        let a0 = random_poly_ntt(seed * 10, &moduli);
        let b0 = random_poly_ntt(seed * 10 + 1, &moduli);
        let a1 = random_poly_ntt(seed * 10 + 2, &moduli);
        let b1 = random_poly_ntt(seed * 10 + 3, &moduli);
        let a2 = random_poly_ntt(seed * 10 + 4, &moduli);
        let b2 = random_poly_ntt(seed * 10 + 5, &moduli);

        let base = random_poly_ntt(seed * 10 + 6, &moduli);

        let mut serial = base.clone();
        serial.mul_acc_ntt_domain(&a0, &b0, &ctx);
        serial.mul_acc_ntt_domain(&a1, &b1, &ctx);
        serial.mul_acc_ntt_domain(&a2, &b2, &ctx);

        let mut fused = base.clone();
        fused.mul_acc3_ntt_domain(&a0, &b0, &a1, &b1, &a2, &b2, &ctx);

        assert_byte_identical(&fused, &serial, &format!("seed={seed} 2crt30"));
    }
}

#[test]
fn mul_acc3_accumulation_is_commutative_across_reorderings() {
    // Montgomery products over R_q commute, so the fused accumulator must not
    // depend on pair order.
    let moduli = [DEFAULT_Q];
    let ctx = NttContext::with_moduli(D, &moduli);

    let a0 = random_poly_ntt(101, &moduli);
    let b0 = random_poly_ntt(102, &moduli);
    let a1 = random_poly_ntt(103, &moduli);
    let b1 = random_poly_ntt(104, &moduli);
    let a2 = random_poly_ntt(105, &moduli);
    let b2 = random_poly_ntt(106, &moduli);
    let base = random_poly_ntt(107, &moduli);

    let mut order_012 = base.clone();
    order_012.mul_acc3_ntt_domain(&a0, &b0, &a1, &b1, &a2, &b2, &ctx);

    let mut order_201 = base.clone();
    order_201.mul_acc3_ntt_domain(&a2, &b2, &a0, &b0, &a1, &b1, &ctx);

    let mut order_120 = base.clone();
    order_120.mul_acc3_ntt_domain(&a1, &b1, &a2, &b2, &a0, &b0, &ctx);

    assert_byte_identical(&order_012, &order_201, "order 0-1-2 vs 2-0-1");
    assert_byte_identical(&order_012, &order_120, "order 0-1-2 vs 1-2-0");
}
