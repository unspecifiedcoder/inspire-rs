//! Superseded stateful sampler shim; forwards to [`crate::math::gaussian::GaussianSampler`].

use crate::math::gaussian::{self, EntropyUnavailable};

/// Forwarding shim.
#[deprecated(
    since = "0.1.0",
    note = "use raven_inspire::math::GaussianSampler; this shim only forwards to it"
)]
pub struct GaussianSampler {
    inner: gaussian::GaussianSampler,
}

#[allow(deprecated)]
impl GaussianSampler {
    /// Sampler over a fresh 32-byte draw from the platform entropy source.
    pub fn try_new(sigma: f64) -> Result<Self, EntropyUnavailable> {
        Ok(Self {
            inner: gaussian::GaussianSampler::from_os_entropy(sigma)?,
        })
    }

    /// [`Self::try_new`], aborting when the platform entropy source fails.
    pub fn new(sigma: f64) -> Self {
        Self {
            inner: gaussian::GaussianSampler::new(sigma),
        }
    }

    /// Seeded sampler, reproducible.
    pub fn with_seed(sigma: f64, seed: u64) -> Self {
        Self {
            inner: gaussian::GaussianSampler::with_seed(sigma, seed),
        }
    }

    /// One draw from D_sigma.
    pub fn sample(&mut self) -> i64 {
        self.inner.sample()
    }

    /// `n` draws, centered into Z_q.
    pub fn sample_vec_centered(&mut self, n: usize, q: u64) -> Vec<u64> {
        self.inner.sample_vec_centered(n, q)
    }

    /// The standard deviation.
    pub fn sigma(&self) -> f64 {
        self.inner.sigma()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn shim_matches_canonical_sampler_stream() {
        let mut shim = GaussianSampler::with_seed(3.2, 99);
        let mut canonical = gaussian::GaussianSampler::with_seed(3.2, 99);
        let from_shim: Vec<i64> = (0..10_000).map(|_| shim.sample()).collect();
        let from_canonical: Vec<i64> = (0..10_000).map(|_| canonical.sample()).collect();
        assert_eq!(from_shim, from_canonical);
    }

    #[test]
    fn new_draws_a_distinct_stream_each_time() {
        let a: Vec<i64> = (0..16)
            .map(|_| GaussianSampler::new(3.2).sample())
            .collect();
        let b: Vec<i64> = (0..16)
            .map(|_| GaussianSampler::new(3.2).sample())
            .collect();
        assert_ne!(a, b);
    }

    #[test]
    fn try_new_draws_a_distinct_stream_each_time() {
        let a: Vec<i64> = (0..16)
            .map(|_| GaussianSampler::try_new(3.2).expect("OS entropy").sample())
            .collect();
        let b: Vec<i64> = (0..16)
            .map(|_| GaussianSampler::try_new(3.2).expect("OS entropy").sample())
            .collect();
        assert_ne!(a, b);
    }
}
