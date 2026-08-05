//! LWE ciphertext and key types.

use serde::{Deserialize, Serialize};

/// LWE secret key: a small-coefficient vector in Z_q^d.
///
/// # Example
///
/// ```
/// use raven_inspire::lwe::LweSecretKey;
/// use raven_inspire::math::GaussianSampler;
/// use raven_inspire::math::mod_q::DEFAULT_Q;
///
/// let mut sampler = GaussianSampler::new(3.2);
/// let sk = LweSecretKey::generate(256, DEFAULT_Q, &mut sampler);
/// assert_eq!(sk.dim, 256);
/// ```
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct LweSecretKey {
    /// Secret key coefficients in Z_q.
    pub coeffs: Vec<u64>,
    /// Dimension of the key.
    pub dim: usize,
    /// Ciphertext modulus.
    pub q: u64,
}

impl std::fmt::Debug for LweSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LweSecretKey")
            .field("dim", &self.dim)
            .field("q", &self.q)
            .finish_non_exhaustive()
    }
}

/// LWE ciphertext `(a, b)` with `b = -<a, s> + e + delta*m`; decrypt via `b + <a, s>`.
///
/// # Example
///
/// ```
/// use raven_inspire::lwe::{LweSecretKey, LweCiphertext};
/// use raven_inspire::math::mod_q::DEFAULT_Q;
///
/// let sk = LweSecretKey::from_coeffs(vec![1, 2, 3, 4], DEFAULT_Q);
/// let ct = LweCiphertext::zero(4, DEFAULT_Q);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LweCiphertext {
    /// Uniform vector in Z_q^d.
    pub a: Vec<u64>,
    /// `-<a, s> + e + delta*m`.
    pub b: u64,
    /// Ciphertext modulus.
    pub q: u64,
}
