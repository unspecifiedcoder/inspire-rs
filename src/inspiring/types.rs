//! Intermediate representations used while packing LWE into RLWE.

use crate::math::Poly;
use serde::{Deserialize, Serialize};

/// Ciphertext between the InspiRING transform and collapse stages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntermediateCiphertext {
    /// a_hat in R_q^k.
    pub a_polys: Vec<Poly>,
    /// b_tilde in R_q.
    pub b_poly: Poly,
}

impl IntermediateCiphertext {
    /// Pair the components.
    pub fn new(a_polys: Vec<Poly>, b_poly: Poly) -> Self {
        Self { a_polys, b_poly }
    }

    /// Number of a-polynomials.
    pub fn dimension(&self) -> usize {
        self.a_polys.len()
    }

    /// Ring dimension.
    pub fn ring_dim(&self) -> usize {
        self.b_poly.dimension()
    }

    /// Coefficient modulus.
    pub fn modulus(&self) -> u64 {
        self.b_poly.modulus()
    }
}

/// Sum of several `IntermediateCiphertext`s.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedCiphertext {
    /// a_hat_agg in R_q^k.
    pub a_polys: Vec<Poly>,
    /// b_tilde_agg in R_q.
    pub b_poly: Poly,
}

impl AggregatedCiphertext {
    /// Pair the components.
    pub fn new(a_polys: Vec<Poly>, b_poly: Poly) -> Self {
        Self { a_polys, b_poly }
    }

    /// Number of a-polynomials.
    pub fn dimension(&self) -> usize {
        self.a_polys.len()
    }

    /// Ring dimension.
    pub fn ring_dim(&self) -> usize {
        self.b_poly.dimension()
    }

    /// Coefficient modulus.
    pub fn modulus(&self) -> u64 {
        self.b_poly.modulus()
    }

    /// Reinterpret as an `IntermediateCiphertext` for collapse.
    pub fn to_intermediate(&self) -> IntermediateCiphertext {
        IntermediateCiphertext {
            a_polys: self.a_polys.clone(),
            b_poly: self.b_poly.clone(),
        }
    }
}
