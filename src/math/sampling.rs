//! Superseded stateless sampler shim; forwards to [`crate::math::gaussian::GaussianSampler`].

use crate::math::gaussian;
use rand::Rng;

/// Forwarding shim.
#[deprecated(
    since = "0.1.0",
    note = "use raven_inspire::math::GaussianSampler; this shim only forwards to it"
)]
#[derive(Debug, Clone)]
pub struct GaussianSampler {
    sigma: f64,
}

#[allow(deprecated)]
impl GaussianSampler {
    pub fn new(sigma: f64) -> Self {
        Self { sigma }
    }

    /// One draw from D_sigma, seeded off `rng`.
    pub fn sample<R: Rng>(&self, rng: &mut R) -> i64 {
        self.seeded_from(rng).sample()
    }

    /// `n` draws, seeded off `rng`.
    pub fn sample_vec<R: Rng>(&self, n: usize, rng: &mut R) -> Vec<i64> {
        let mut inner = self.seeded_from(rng);
        (0..n).map(|_| inner.sample()).collect()
    }

    /// The standard deviation.
    pub fn sigma(&self) -> f64 {
        self.sigma
    }

    fn seeded_from<R: Rng>(&self, rng: &mut R) -> gaussian::GaussianSampler {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        gaussian::GaussianSampler::from_seed(self.sigma, seed)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn test_gaussian_distribution() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);
        let sampler = GaussianSampler::new(3.2);

        let samples: Vec<i64> = (0..10000).map(|_| sampler.sample(&mut rng)).collect();

        let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64;
        assert!(mean.abs() < 0.5, "Mean {mean} should be close to 0");

        let variance: f64 = samples
            .iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>()
            / samples.len() as f64;
        let std_dev = variance.sqrt();
        assert!(
            (std_dev - 3.2).abs() < 0.5,
            "Std dev {std_dev} should be close to 3.2"
        );
    }

    #[test]
    fn test_sample_vec() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(123);
        let sampler = GaussianSampler::new(3.2);

        let samples = sampler.sample_vec(100, &mut rng);
        assert_eq!(samples.len(), 100);
    }

    #[test]
    fn shim_output_equals_canonical_sampler() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        let mut expected_seed = [0u8; 32];
        {
            let mut probe = rand_chacha::ChaCha20Rng::seed_from_u64(7);
            probe.fill_bytes(&mut expected_seed);
        }
        let from_shim = GaussianSampler::new(3.2).sample_vec(100_000, &mut rng);
        let from_canonical =
            gaussian::GaussianSampler::from_seed(3.2, expected_seed).sample_vec(100_000);
        assert_eq!(from_shim, from_canonical);

        let bound = (6.0 * 3.2f64).ceil() as i64;
        for s in from_shim {
            assert!(s.abs() <= bound, "sample {s} exceeds tailcut {bound}");
        }
    }
}
