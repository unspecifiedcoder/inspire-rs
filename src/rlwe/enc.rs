//! RLWE encryption and decryption; `delta = floor(q/p)` is the scaling factor.

use crate::lwe::LweCiphertext;
use crate::math::{GaussianSampler, NttContext, Poly};
use crate::params::InspireParams;

use super::types::{RlweCiphertext, RlweSecretKey};

impl RlweSecretKey {
    /// Samples a secret key from the error distribution.
    pub fn generate(params: &InspireParams, sampler: &mut GaussianSampler) -> Self {
        let poly = Poly::sample_gaussian_moduli(params.ring_dim, params.moduli(), sampler);
        Self { poly }
    }
}

impl RlweCiphertext {
    /// `(a, -a*s + e + delta*m)`; `message_poly` coefficients MUST lie in `[0, p)`.
    pub fn encrypt(
        sk: &RlweSecretKey,
        message_poly: &Poly,
        delta: u64,
        a_random: Poly,
        error: &Poly,
        ctx: &NttContext,
    ) -> Self {
        let scaled_msg = message_poly.scalar_mul(delta);
        let neg_a_s = -a_random.mul_ntt(&sk.poly, ctx);
        let b = &(&neg_a_s + error) + &scaled_msg;

        Self { a: a_random, b }
    }

    /// [`Self::encrypt`] against a CRS-derived `a`, which need not be transmitted.
    pub fn encrypt_with_crs(
        sk: &RlweSecretKey,
        message_poly: &Poly,
        delta: u64,
        crs_a: &Poly,
        error: &Poly,
        ctx: &NttContext,
    ) -> Self {
        let scaled_msg = message_poly.scalar_mul(delta);
        let neg_a_s = -crs_a.mul_ntt(&sk.poly, ctx);
        let b = &(&neg_a_s + error) + &scaled_msg;

        Self {
            a: crs_a.clone(),
            b,
        }
    }

    /// `round((a*s + b) / delta) mod p`.
    pub fn decrypt(&self, sk: &RlweSecretKey, delta: u64, p: u64, ctx: &NttContext) -> Poly {
        let d = self.ring_dim();

        let a_s = self.a.mul_ntt(&sk.poly, ctx);
        let noisy_msg = &a_s + &self.b;

        let mut coeffs = vec![0u64; d];
        for (i, coeff) in coeffs.iter_mut().enumerate().take(d) {
            let val = noisy_msg.coeff(i);
            let half_delta = delta / 2;
            let rounded = ((val as u128 + half_delta as u128) / delta as u128) as u64;
            *coeff = rounded % p;
        }

        Poly::from_coeffs(coeffs, p)
    }

    /// Componentwise sum, decrypting to `m1 + m2`.
    pub fn add(&self, other: &RlweCiphertext) -> RlweCiphertext {
        RlweCiphertext {
            a: &self.a + &other.a,
            b: &self.b + &other.b,
        }
    }

    /// Componentwise difference, decrypting to `m1 - m2`.
    pub fn sub(&self, other: &RlweCiphertext) -> RlweCiphertext {
        RlweCiphertext {
            a: &self.a - &other.a,
            b: &self.b - &other.b,
        }
    }

    /// Componentwise scalar product, decrypting to `c*m`.
    pub fn scalar_mul(&self, scalar: u64) -> RlweCiphertext {
        RlweCiphertext {
            a: self.a.scalar_mul(scalar),
            b: self.b.scalar_mul(scalar),
        }
    }

    /// Componentwise plaintext product, decrypting to `p(X)*m(X) mod (X^d + 1)`.
    pub fn poly_mul(&self, plaintext_poly: &Poly, ctx: &NttContext) -> RlweCiphertext {
        RlweCiphertext {
            a: self.a.mul_ntt(plaintext_poly, ctx),
            b: self.b.mul_ntt(plaintext_poly, ctx),
        }
    }

    /// `(0, 0)`, the identity for homomorphic addition.
    pub fn zero(params: &InspireParams) -> RlweCiphertext {
        let a = Poly::zero_moduli(params.ring_dim, params.moduli());
        let b = Poly::zero_moduli(params.ring_dim, params.moduli());
        RlweCiphertext { a, b }
    }

    /// `(0, delta*m)`: decrypts under any key and hides nothing, for folding a
    /// known plaintext into a homomorphic chain.
    pub fn trivial_encrypt(
        message_poly: &Poly,
        delta: u64,
        params: &InspireParams,
    ) -> RlweCiphertext {
        let a = Poly::zero_moduli(params.ring_dim, params.moduli());
        let b = message_poly.scalar_mul(delta);
        RlweCiphertext { a, b }
    }

    /// RLWE-to-LWE sample extraction at coefficient 0: `a'_i = a_{d-i mod d}`, `b' = b_0`.
    pub fn sample_extract_coeff0(&self) -> LweCiphertext {
        let d = self.ring_dim();
        let q = self.modulus();

        let mut a_vec = vec![0u64; d];
        a_vec[0] = self.a.coeff(0);
        for (i, a) in a_vec.iter_mut().enumerate().take(d).skip(1) {
            *a = self.a.coeff(d - i);
        }

        let b0 = self.b.coeff(0);

        LweCiphertext { a: a_vec, b: b0, q }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> InspireParams {
        InspireParams::secure_128_d2048()
    }

    fn make_ctx(params: &InspireParams) -> NttContext {
        params.ntt_context()
    }

    fn random_poly(params: &InspireParams) -> Poly {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x5eed);
        Poly::random_with_rng_moduli(params.ring_dim, params.moduli(), &mut rng)
    }

    fn sample_error_poly(params: &InspireParams, sampler: &mut GaussianSampler) -> Poly {
        Poly::sample_gaussian_moduli(params.ring_dim, params.moduli(), sampler)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::with_seed(params.sigma, 0);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let msg_coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|i| (i as u64) % params.p)
            .collect();
        let message = Poly::from_coeffs_moduli(msg_coeffs.clone(), params.moduli());

        let a_random = random_poly(&params);
        let error = sample_error_poly(&params, &mut sampler);

        let ct = RlweCiphertext::encrypt(&sk, &message, delta, a_random, &error, &ctx);

        let decrypted = ct.decrypt(&sk, delta, params.p, &ctx);

        for (i, expected) in msg_coeffs.iter().enumerate().take(params.ring_dim) {
            assert_eq!(decrypted.coeff(i), *expected, "Mismatch at coefficient {i}");
        }
    }

    #[test]
    fn test_encrypt_decrypt_zero() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::with_seed(params.sigma, 0);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let message = Poly::zero_moduli(params.ring_dim, params.moduli());
        let a_random = random_poly(&params);
        let error = sample_error_poly(&params, &mut sampler);

        let ct = RlweCiphertext::encrypt(&sk, &message, delta, a_random, &error, &ctx);
        let decrypted = ct.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            assert_eq!(decrypted.coeff(i), 0, "Expected zero at coefficient {i}");
        }
    }

    #[test]
    fn test_homomorphic_addition() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::with_seed(params.sigma, 0);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let msg1_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 100).collect();
        let msg2_coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|i| ((i + 50) as u64) % 100)
            .collect();

        let msg1 = Poly::from_coeffs_moduli(msg1_coeffs.clone(), params.moduli());
        let msg2 = Poly::from_coeffs_moduli(msg2_coeffs.clone(), params.moduli());

        let a1 = random_poly(&params);
        let e1 = sample_error_poly(&params, &mut sampler);
        let ct1 = RlweCiphertext::encrypt(&sk, &msg1, delta, a1, &e1, &ctx);

        let a2 = random_poly(&params);
        let e2 = sample_error_poly(&params, &mut sampler);
        let ct2 = RlweCiphertext::encrypt(&sk, &msg2, delta, a2, &e2, &ctx);

        let ct_sum = ct1.add(&ct2);
        let decrypted = ct_sum.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            let expected = (msg1_coeffs[i] + msg2_coeffs[i]) % params.p;
            assert_eq!(decrypted.coeff(i), expected, "Mismatch at coefficient {i}");
        }
    }

    #[test]
    fn test_homomorphic_subtraction() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::with_seed(params.sigma, 0);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let msg1_coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|i| 200 + (i as u64) % 100)
            .collect();
        let msg2_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 100).collect();

        let msg1 = Poly::from_coeffs_moduli(msg1_coeffs.clone(), params.moduli());
        let msg2 = Poly::from_coeffs_moduli(msg2_coeffs.clone(), params.moduli());

        let a1 = random_poly(&params);
        let e1 = sample_error_poly(&params, &mut sampler);
        let ct1 = RlweCiphertext::encrypt(&sk, &msg1, delta, a1, &e1, &ctx);

        let a2 = random_poly(&params);
        let e2 = sample_error_poly(&params, &mut sampler);
        let ct2 = RlweCiphertext::encrypt(&sk, &msg2, delta, a2, &e2, &ctx);

        let ct_diff = ct1.sub(&ct2);
        let decrypted = ct_diff.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            let expected = (msg1_coeffs[i] - msg2_coeffs[i]) % params.p;
            assert_eq!(decrypted.coeff(i), expected, "Mismatch at coefficient {i}");
        }
    }

    #[test]
    fn test_scalar_multiplication() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::with_seed(params.sigma, 0);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let msg_coeffs: Vec<u64> = (0..params.ring_dim).map(|i| (i as u64) % 50).collect();
        let message = Poly::from_coeffs_moduli(msg_coeffs.clone(), params.moduli());

        let a = random_poly(&params);
        let e = sample_error_poly(&params, &mut sampler);
        let ct = RlweCiphertext::encrypt(&sk, &message, delta, a, &e, &ctx);

        let scalar = 3u64;
        let ct_scaled = ct.scalar_mul(scalar);
        let decrypted = ct_scaled.decrypt(&sk, delta, params.p, &ctx);

        for (i, msg_coeff) in msg_coeffs.iter().enumerate().take(params.ring_dim) {
            let expected = (*msg_coeff * scalar) % params.p;
            assert_eq!(decrypted.coeff(i), expected, "Mismatch at coefficient {i}");
        }
    }

    #[test]
    fn test_zero_ciphertext() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::with_seed(params.sigma, 0);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let zero_ct = RlweCiphertext::zero(&params);
        let decrypted = zero_ct.decrypt(&sk, delta, params.p, &ctx);

        for i in 0..params.ring_dim {
            assert_eq!(decrypted.coeff(i), 0);
        }
    }

    #[test]
    fn test_crs_mode_encryption() {
        let params = test_params();
        let delta = params.delta();
        let ctx = make_ctx(&params);
        let mut sampler = GaussianSampler::with_seed(params.sigma, 0);

        let sk = RlweSecretKey::generate(&params, &mut sampler);

        let crs_a = random_poly(&params);

        let msg_coeffs: Vec<u64> = (0..params.ring_dim)
            .map(|i| (i as u64) % params.p)
            .collect();
        let message = Poly::from_coeffs_moduli(msg_coeffs.clone(), params.moduli());
        let error = sample_error_poly(&params, &mut sampler);

        let ct = RlweCiphertext::encrypt_with_crs(&sk, &message, delta, &crs_a, &error, &ctx);
        let decrypted = ct.decrypt(&sk, delta, params.p, &ctx);

        for (i, expected) in msg_coeffs.iter().enumerate().take(params.ring_dim) {
            assert_eq!(decrypted.coeff(i), *expected, "Mismatch at coefficient {i}");
        }
    }
}
