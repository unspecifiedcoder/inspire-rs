//! RLWE ciphertext and key types.

use crate::math::Poly;
use serde::{Deserialize, Serialize};

/// RLWE secret key: a small-coefficient polynomial in R_q.
///
/// # Example
///
/// ```
/// use raven_inspire::rlwe::RlweSecretKey;
/// use raven_inspire::math::Poly;
/// use raven_inspire::math::mod_q::DEFAULT_Q;
///
/// let poly = Poly::zero(256, DEFAULT_Q);
/// let sk = RlweSecretKey::from_poly(poly);
/// assert_eq!(sk.ring_dim(), 256);
/// ```
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct RlweSecretKey {
    /// Secret polynomial in R_q.
    pub poly: Poly,
}

impl std::fmt::Debug for RlweSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RlweSecretKey")
            .field("ring_dim", &self.ring_dim())
            .finish_non_exhaustive()
    }
}

/// RLWE ciphertext `(a, b)` with `b = -a*s + e + delta*m`; decrypt via `b + a*s`.
///
/// # Example
///
/// ```
/// use raven_inspire::rlwe::RlweCiphertext;
/// use raven_inspire::math::Poly;
/// use raven_inspire::math::mod_q::DEFAULT_Q;
///
/// let a = Poly::zero(256, DEFAULT_Q);
/// let b = Poly::zero(256, DEFAULT_Q);
/// let ct = RlweCiphertext::from_parts(a, b);
/// assert_eq!(ct.ring_dim(), 256);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RlweCiphertext {
    /// Uniform polynomial in R_q.
    pub a: Poly,
    /// `-a*s + e + delta*m`.
    pub b: Poly,
}

impl RlweSecretKey {
    /// Wraps a secret polynomial.
    pub fn from_poly(poly: Poly) -> Self {
        Self { poly }
    }

    /// Ring dimension d.
    pub fn ring_dim(&self) -> usize {
        self.poly.dimension()
    }

    /// Modulus q.
    pub fn modulus(&self) -> u64 {
        self.poly.modulus()
    }
}

impl RlweCiphertext {
    /// Pairs `a` and `b`, which MUST share dimension and modulus.
    pub fn from_parts(a: Poly, b: Poly) -> Self {
        debug_assert_eq!(
            a.dimension(),
            b.dimension(),
            "Ciphertext polynomials must have same dimension"
        );
        debug_assert_eq!(
            a.modulus(),
            b.modulus(),
            "Ciphertext polynomials must have same modulus"
        );
        Self { a, b }
    }

    /// Ring dimension d.
    pub fn ring_dim(&self) -> usize {
        self.a.dimension()
    }

    /// Modulus q.
    pub fn modulus(&self) -> u64 {
        self.a.modulus()
    }
}

/// [`RlweCiphertext`] carrying `a` as its 32-byte seed, halving the wire size.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeededRlweCiphertext {
    /// Seed `a` is regenerated from.
    pub seed: [u8; 32],
    /// `-a*s + e + delta*m`.
    pub b: Poly,
}

impl SeededRlweCiphertext {
    /// Pairs a seed with its `b` polynomial.
    pub fn new(seed: [u8; 32], b: Poly) -> Self {
        Self { seed, b }
    }

    /// Regenerates `a` from the seed.
    pub fn expand(&self) -> RlweCiphertext {
        let dim = self.b.dimension();
        let a = Poly::from_seed_moduli(&self.seed, dim, self.b.moduli());
        RlweCiphertext::from_parts(a, self.b.clone())
    }

    /// Ring dimension d.
    pub fn ring_dim(&self) -> usize {
        self.b.dimension()
    }

    /// Modulus q.
    pub fn modulus(&self) -> u64 {
        self.b.modulus()
    }
}
