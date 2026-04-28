//! Differential KAT for `external_product_with_ntt_rgsw`.
//!
//! Verifies that the pre-NTT'd RGSW variant of the external product
//! produces byte-identical `RlweCiphertext` output compared to the
//! classical `external_product` function across random inputs.
//! Integration gate: byte-identity required before wiring into the
//! respond hot path.

use raven_inspire::math::{GaussianSampler, Poly};
use raven_inspire::params::InspireParams;
use raven_inspire::rgsw::{
    external_product, external_product_with_ntt_rgsw, rgsw_rows_to_ntt, GadgetVector,
    RgswCiphertext,
};
use raven_inspire::rlwe::{RlweCiphertext, RlweSecretKey};

fn params() -> InspireParams {
    InspireParams::secure_128_d2048()
}

fn sample_db_poly(dim: usize, moduli: &[u64], seed: u64) -> Poly {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let coeffs: Vec<u64> = (0..dim)
        .map(|_| {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z ^= z >> 30;
            z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z ^= z >> 27;
            z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            z
        })
        .collect();
    Poly::from_coeffs_moduli(coeffs, moduli)
}

#[test]
fn external_product_ntt_matches_classical_rgsw_zero() {
    let p = params();
    let ctx = p.ntt_context();
    let mut sampler = GaussianSampler::new(p.sigma);
    let delta = p.delta();

    let sk = RlweSecretKey::generate(&p, &mut sampler);
    let gadget = GadgetVector::new(p.gadget_base, p.gadget_len, p.q);

    // RLWE encrypting a message polynomial
    let msg_coeffs: Vec<u64> = (0..p.ring_dim).map(|i| (i as u64) % p.p).collect();
    let msg = Poly::from_coeffs_moduli(msg_coeffs, p.moduli());
    let a = Poly::random_moduli(p.ring_dim, p.moduli());
    let e = Poly::sample_gaussian_moduli(p.ring_dim, p.moduli(), &mut sampler);
    let rlwe = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

    // RGSW(0)
    let rgsw = RgswCiphertext::encrypt_scalar(&sk, 0, &gadget, &mut sampler, &ctx);

    let classical = external_product(&rlwe, &rgsw, &ctx);
    let rgsw_ntt = rgsw_rows_to_ntt(&rgsw, &ctx);
    let fast = external_product_with_ntt_rgsw(&rlwe, &rgsw_ntt, &gadget, &ctx);

    assert_eq!(
        classical.a, fast.a,
        "RGSW(0): external_product_with_ntt_rgsw.a diverged from classical"
    );
    assert_eq!(
        classical.b, fast.b,
        "RGSW(0): external_product_with_ntt_rgsw.b diverged from classical"
    );
}

#[test]
fn external_product_ntt_matches_classical_random_rlwe() {
    // 64 independent random RLWE + RGSW combinations, byte-identity
    // required between classical and pre-NTT'd paths.
    let p = params();
    let ctx = p.ntt_context();
    let gadget = GadgetVector::new(p.gadget_base, p.gadget_len, p.q);

    for seed_idx in 0..64u64 {
        let mut sampler = GaussianSampler::new(p.sigma);
        let sk = RlweSecretKey::generate(&p, &mut sampler);

        // Random-ish RLWE: coefficient-form arbitrary polynomials.
        let a_poly = sample_db_poly(p.ring_dim, p.moduli(), seed_idx * 17 + 1);
        let b_poly = sample_db_poly(p.ring_dim, p.moduli(), seed_idx * 17 + 2);
        let rlwe = RlweCiphertext::from_parts(a_poly, b_poly);

        // RGSW encrypting a small random value.
        let scalar = (seed_idx % 5) + 1;
        let rgsw = RgswCiphertext::encrypt_scalar(&sk, scalar, &gadget, &mut sampler, &ctx);

        let classical = external_product(&rlwe, &rgsw, &ctx);
        let rgsw_ntt = rgsw_rows_to_ntt(&rgsw, &ctx);
        let fast = external_product_with_ntt_rgsw(&rlwe, &rgsw_ntt, &gadget, &ctx);

        assert_eq!(
            classical.a, fast.a,
            "seed {seed_idx}: .a components diverged"
        );
        assert_eq!(
            classical.b, fast.b,
            "seed {seed_idx}: .b components diverged"
        );
    }
}

#[test]
fn external_product_ntt_preserves_correctness_rgsw_scalar() {
    let p = params();
    let ctx = p.ntt_context();
    let mut sampler = GaussianSampler::new(p.sigma);
    let delta = p.delta();

    let sk = RlweSecretKey::generate(&p, &mut sampler);
    let gadget = GadgetVector::new(p.gadget_base, p.gadget_len, p.q);

    // Encrypt a message with small values
    let msg_coeffs: Vec<u64> = (0..p.ring_dim).map(|i| (i as u64) % 10).collect();
    let msg = Poly::from_coeffs_moduli(msg_coeffs.clone(), p.moduli());
    let a = Poly::random_moduli(p.ring_dim, p.moduli());
    let e = Poly::sample_gaussian_moduli(p.ring_dim, p.moduli(), &mut sampler);
    let rlwe = RlweCiphertext::encrypt(&sk, &msg, delta, a, &e, &ctx);

    // RGSW(3)
    let scalar = 3u64;
    let rgsw = RgswCiphertext::encrypt_scalar(&sk, scalar, &gadget, &mut sampler, &ctx);
    let rgsw_ntt = rgsw_rows_to_ntt(&rgsw, &ctx);

    let result = external_product_with_ntt_rgsw(&rlwe, &rgsw_ntt, &gadget, &ctx);
    let decrypted = result.decrypt(&sk, delta, p.p, &ctx);

    for (i, msg_coeff) in msg_coeffs.iter().enumerate().take(p.ring_dim) {
        let expected = (*msg_coeff * scalar) % p.p;
        assert_eq!(decrypted.coeff(i), expected, "Mismatch at coefficient {i}");
    }
}
