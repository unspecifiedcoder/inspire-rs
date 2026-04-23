//! Number-Theoretic Transform (NTT) for fast polynomial multiplication.
//!
//! Implements Cooley-Tukey radix-2 NTT for negacyclic convolution over
//! R_q = Z_q\[X\]/(X^d + 1). The NTT enables O(n log n) polynomial multiplication
//! instead of O(n²) naive multiplication.
//!
//! # Theory
//!
//! For negacyclic convolution (multiplication modulo X^n + 1), we use a
//! primitive 2n-th root of unity ψ where ψ^n = -1. The NTT evaluates a
//! polynomial at powers of ψ, enabling pointwise multiplication in the
//! evaluation domain.
//!
//! # Requirements
//!
//! The modulus q must satisfy q ≡ 1 (mod 2n) for a primitive 2n-th root
//! of unity to exist. The default modulus `DEFAULT_Q` supports n up to 2048.
//!
//! # Example
//!
//! ```
//! use raven_inspire::math::ntt::NttContext;
//!
//! let ctx = NttContext::with_default_q(256);
//!
//! // Forward NTT
//! let mut coeffs = vec![1u64; 256];
//! ctx.forward(&mut coeffs);
//!
//! // Inverse NTT recovers original
//! ctx.inverse(&mut coeffs);
//! assert_eq!(coeffs[0], 1);
//! ```

use super::mod_q::DEFAULT_Q;

/// Precomputed NTT context with twiddle factors.
///
/// Stores precomputed roots of unity and Montgomery constants for efficient
/// NTT operations. Create once and reuse for all polynomial operations with
/// the same dimension and modulus.
///
/// # Fields
///
/// * `n` - Ring dimension (must be a power of two)
/// * `q` - Modulus (must satisfy q ≡ 1 mod 2n)
/// * `psi_powers` - Forward twiddle factors (powers of ψ)
/// * `psi_inv_powers` - Inverse twiddle factors (powers of ψ^(-1))
/// * `n_inv` - n^(-1) mod q for inverse NTT scaling
///
/// # Example
///
/// ```
/// use raven_inspire::math::ntt::NttContext;
///
/// let ctx = NttContext::with_default_q(2048);
/// assert_eq!(ctx.dimension(), 2048);
/// ```
#[derive(Clone)]
pub struct NttContext {
    /// Ring dimension (power of two).
    n: usize,
    /// CRT moduli (length 1 for single-modulus mode).
    moduli: Vec<u64>,
    /// Precomputed values for Montgomery arithmetic (per modulus).
    q_inv_neg: Vec<u64>,
    r_squared: Vec<u64>,
    /// Forward twiddle factors (powers of ψ where ψ^(2n) = 1 and ψ^n = -1).
    psi_powers: Vec<Vec<u64>>,
    /// Inverse twiddle factors (powers of ψ^(-1)).
    psi_inv_powers: Vec<Vec<u64>>,
    /// n^(-1) mod q in Montgomery form for inverse NTT scaling.
    n_inv: Vec<u64>,
    // Shoup parallel path: twiddles precomputed in STANDARD form (not
    // Montgomery) so the Shoup butterfly consumes + produces standard-
    // form coefficients directly, eliminating the boundary Montgomery
    // conversions. Each standard-form twiddle has a matching Shoup
    // precomputation `shoup(b) = floor(b · 2^64 / q)` that the inner
    // multiply uses to skip a u64 mul + Montgomery reduction step per
    // butterfly multiply.
    /// Forward twiddle factors in standard form (Shoup path).
    psi_powers_std: Vec<Vec<u64>>,
    /// Shoup precomputation of `psi_powers_std`.
    psi_powers_shoup: Vec<Vec<u64>>,
    /// Inverse twiddle factors in standard form (Shoup path).
    psi_inv_powers_std: Vec<Vec<u64>>,
    /// Shoup precomputation of `psi_inv_powers_std`.
    psi_inv_powers_shoup: Vec<Vec<u64>>,
    /// n^(-1) mod q in standard form (Shoup path).
    n_inv_std: Vec<u64>,
    /// Shoup precomputation of `n_inv_std`.
    n_inv_shoup: Vec<u64>,
}

impl NttContext {
    /// Creates an NTT context for the given dimension and modulus.
    ///
    /// Precomputes twiddle factors and Montgomery constants for efficient
    /// NTT operations.
    ///
    /// # Arguments
    ///
    /// * `n` - Ring dimension (must be a power of two)
    /// * `q` - Modulus (must satisfy q ≡ 1 mod 2n)
    ///
    /// # Returns
    ///
    /// A new `NttContext` with precomputed values.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `n` is not a power of two
    /// - `q` does not satisfy q ≡ 1 (mod 2n)
    ///
    /// # Example
    ///
    /// ```
    /// use raven_inspire::math::ntt::NttContext;
    /// use raven_inspire::math::mod_q::DEFAULT_Q;
    ///
    /// let ctx = NttContext::new(2048, DEFAULT_Q);
    /// assert_eq!(ctx.dimension(), 2048);
    /// ```
    pub fn new(n: usize, q: u64) -> Self {
        Self::with_moduli(n, &[q])
    }

    /// Creates an NTT context for multiple CRT moduli.
    ///
    /// # Arguments
    ///
    /// * `n` - Ring dimension (power of two)
    /// * `moduli` - CRT moduli (each must satisfy q ≡ 1 (mod 2n))
    pub fn with_moduli(n: usize, moduli: &[u64]) -> Self {
        assert!(n.is_power_of_two(), "n must be a power of two");
        assert!(!moduli.is_empty(), "moduli must be non-empty");

        let mut q_inv_neg = Vec::with_capacity(moduli.len());
        let mut r_squared = Vec::with_capacity(moduli.len());
        let mut psi_powers = Vec::with_capacity(moduli.len());
        let mut psi_inv_powers = Vec::with_capacity(moduli.len());
        let mut n_inv = Vec::with_capacity(moduli.len());
        let mut psi_powers_std = Vec::with_capacity(moduli.len());
        let mut psi_powers_shoup = Vec::with_capacity(moduli.len());
        let mut psi_inv_powers_std = Vec::with_capacity(moduli.len());
        let mut psi_inv_powers_shoup = Vec::with_capacity(moduli.len());
        let mut n_inv_std = Vec::with_capacity(moduli.len());
        let mut n_inv_shoup = Vec::with_capacity(moduli.len());

        for &q in moduli {
            assert!(q % (2 * n as u64) == 1, "q must be ≡ 1 (mod 2n)");

            let q_inv = Self::compute_q_inv_neg(q);
            let r2 = Self::compute_r_squared(q);

            // Find primitive 2n-th root of unity ψ
            let psi = Self::find_primitive_root(2 * n as u64, q);
            let psi_mont = Self::to_montgomery(psi, q, r2, q_inv);

            // Precompute forward twiddle factors in bit-reversed order
            let psi_pow = Self::compute_twiddle_factors(n, psi_mont, q, q_inv, r2);

            // Compute inverse: ψ^(-1) mod q
            let psi_inv = Self::mod_pow(psi, q - 2, q);
            let psi_inv_mont = Self::to_montgomery(psi_inv, q, r2, q_inv);
            let psi_inv_pow = Self::compute_twiddle_factors(n, psi_inv_mont, q, q_inv, r2);

            // Compute n^(-1) mod q
            let n_inv_val = Self::mod_pow(n as u64, q - 2, q);
            let n_inv_mont = Self::to_montgomery(n_inv_val, q, r2, q_inv);

            // Shoup path: standard-form twiddle ladder + Shoup
            // precomputation per entry. Uses the same bit-reversed order
            // so the Shoup butterflies index identically to the
            // Montgomery butterflies.
            let psi_pow_std = Self::compute_twiddle_factors_std(n, psi, q);
            let psi_pow_shoup = Self::compute_shoup_twins(&psi_pow_std, q);
            let psi_inv_pow_std = Self::compute_twiddle_factors_std(n, psi_inv, q);
            let psi_inv_pow_shoup = Self::compute_shoup_twins(&psi_inv_pow_std, q);
            let n_inv_shoup_val = Self::shoup_precompute(n_inv_val, q);

            q_inv_neg.push(q_inv);
            r_squared.push(r2);
            psi_powers.push(psi_pow);
            psi_inv_powers.push(psi_inv_pow);
            n_inv.push(n_inv_mont);
            psi_powers_std.push(psi_pow_std);
            psi_powers_shoup.push(psi_pow_shoup);
            psi_inv_powers_std.push(psi_inv_pow_std);
            psi_inv_powers_shoup.push(psi_inv_pow_shoup);
            n_inv_std.push(n_inv_val);
            n_inv_shoup.push(n_inv_shoup_val);
        }

        Self {
            n,
            moduli: moduli.to_vec(),
            q_inv_neg,
            r_squared,
            psi_powers,
            psi_inv_powers,
            n_inv,
            psi_powers_std,
            psi_powers_shoup,
            psi_inv_powers_std,
            psi_inv_powers_shoup,
            n_inv_std,
            n_inv_shoup,
        }
    }

    /// Creates an NTT context with the default modulus.
    ///
    /// # Arguments
    ///
    /// * `n` - Ring dimension (must be a power of two, at most 2048)
    ///
    /// # Returns
    ///
    /// A new `NttContext` using `DEFAULT_Q` as the modulus.
    pub fn with_default_q(n: usize) -> Self {
        Self::new(n, DEFAULT_Q)
    }

    /// Returns the ring dimension.
    ///
    /// # Returns
    ///
    /// The dimension n of the polynomial ring.
    pub fn dimension(&self) -> usize {
        self.n
    }

    /// Returns the modulus q.
    ///
    /// # Returns
    ///
    /// The modulus used for this NTT context.
    pub fn modulus(&self) -> u64 {
        self.moduli
            .iter()
            .copied()
            .fold(1u64, |acc, m| acc.saturating_mul(m))
    }

    /// Returns the CRT moduli.
    pub fn moduli(&self) -> &[u64] {
        &self.moduli
    }

    /// Number of CRT moduli.
    pub fn crt_count(&self) -> usize {
        self.moduli.len()
    }

    /// Precomputed Montgomery constant `-q^{-1} mod 2^64` for the given
    /// CRT limb. Exposed for test harnesses that need to drive
    /// `ifma52::mont_mul_split52` against this context's modulus set.
    /// Not part of the stable public API.
    #[doc(hidden)]
    pub fn q_inv_neg_for_test(&self, idx: usize) -> u64 {
        self.q_inv_neg[idx]
    }

    /// True when configured for single-prime DEFAULT_Q, enabling
    /// Solinas-form Montgomery reduction. `forward`/`inverse`/
    /// `pointwise_mul` route through the Solinas fast path when true;
    /// byte-identical output (per `tests/solinas_montgomery_kat.rs`).
    #[inline]
    fn is_solinas_default_q(&self) -> bool {
        self.moduli.len() == 1 && self.moduli[0] == super::mod_q::DEFAULT_Q
    }

    /// Performs forward NTT in-place using Cooley-Tukey decimation-in-time.
    ///
    /// Converts polynomial coefficients to NTT representation (evaluations
    /// at powers of ψ). Input coefficients are automatically converted to
    /// Montgomery form.
    ///
    /// # Arguments
    ///
    /// * `coeffs` - Polynomial coefficients (modified in-place)
    ///
    /// # Panics
    ///
    /// Panics if `coeffs.len() != n * crt_count`.
    pub fn forward(&self, coeffs: &mut [u64]) {
        assert_eq!(
            coeffs.len(),
            self.n * self.crt_count(),
            "Input length must match dimension * crt_count"
        );

        // When configured for single-prime DEFAULT_Q, route through the
        // Solinas fast path (byte-identical output). Automatic dispatch;
        // callers are unaware.
        if self.is_solinas_default_q() {
            return self.forward_solinas(coeffs);
        }

        for (idx, _) in self.moduli.iter().enumerate() {
            let start = idx * self.n;
            let end = start + self.n;

            // Convert to Montgomery form
            for c in coeffs[start..end].iter_mut() {
                *c = Self::to_montgomery_at(
                    *c,
                    self.moduli[idx],
                    self.r_squared[idx],
                    self.q_inv_neg[idx],
                );
            }

            self.forward_inplace_at(&mut coeffs[start..end], idx);
        }
    }

    /// Performs forward NTT assuming input is already in Montgomery form.
    ///
    /// Use this when coefficients are already in Montgomery representation
    /// to avoid redundant conversions.
    ///
    /// # Arguments
    ///
    /// * `coeffs` - Polynomial coefficients in Montgomery form (modified in-place)
    pub fn forward_inplace(&self, coeffs: &mut [u64]) {
        assert_eq!(
            coeffs.len(),
            self.n * self.crt_count(),
            "Input length must match dimension * crt_count"
        );
        // Solinas dispatch (see `forward`).
        if self.is_solinas_default_q() {
            self.forward_inplace_solinas_at(coeffs, 0);
            return;
        }
        for (idx, _) in self.moduli.iter().enumerate() {
            let start = idx * self.n;
            let end = start + self.n;
            self.forward_inplace_at(&mut coeffs[start..end], idx);
        }
    }

    fn forward_inplace_at(&self, coeffs: &mut [u64], idx: usize) {
        let n = self.n;
        let q = self.moduli[idx];
        let psi_powers = &self.psi_powers[idx];

        let mut t = n;
        let mut m = 1;

        while m < n {
            t >>= 1;
            for i in 0..m {
                let j1 = 2 * i * t;
                let j2 = j1 + t;
                let w = psi_powers[m + i];

                for j in j1..j2 {
                    let u = coeffs[j];
                    let v = self.montgomery_mul_at(coeffs[j + t], w, idx);

                    coeffs[j] = if u + v >= q { u + v - q } else { u + v };
                    coeffs[j + t] = if u >= v { u - v } else { q - v + u };
                }
            }
            m <<= 1;
        }
    }

    /// Performs inverse NTT in-place using Gentleman-Sande decimation-in-frequency.
    ///
    /// Converts NTT representation back to polynomial coefficients.
    /// Output is automatically converted from Montgomery form.
    ///
    /// # Arguments
    ///
    /// * `coeffs` - NTT representation (modified in-place)
    ///
    /// # Panics
    ///
    /// Panics if `coeffs.len() != n * crt_count`.
    pub fn inverse(&self, coeffs: &mut [u64]) {
        assert_eq!(
            coeffs.len(),
            self.n * self.crt_count(),
            "Input length must match dimension * crt_count"
        );

        // Solinas dispatch: reuses the Solinas-REDC butterflies and
        // the classic Montgomery strip at the output boundary.
        if self.is_solinas_default_q() {
            return self.inverse_solinas(coeffs);
        }

        self.inverse_inplace(coeffs);

        // Convert from Montgomery form
        for (idx, _) in self.moduli.iter().enumerate() {
            let start = idx * self.n;
            let end = start + self.n;
            for c in coeffs[start..end].iter_mut() {
                *c = self.montgomery_mul_at(*c, 1, idx);
            }
        }
    }

    /// Performs inverse NTT, output remains in Montgomery form.
    ///
    /// Use this when you need to continue operations in Montgomery form
    /// after the inverse NTT.
    ///
    /// # Arguments
    ///
    /// * `coeffs` - NTT representation in Montgomery form (modified in-place)
    pub fn inverse_inplace(&self, coeffs: &mut [u64]) {
        assert_eq!(
            coeffs.len(),
            self.n * self.crt_count(),
            "Input length must match dimension * crt_count"
        );
        // Solinas dispatch (see `inverse`).
        if self.is_solinas_default_q() {
            self.inverse_inplace_solinas_at(coeffs, 0);
            return;
        }
        for (idx, _) in self.moduli.iter().enumerate() {
            let start = idx * self.n;
            let end = start + self.n;
            self.inverse_inplace_at(&mut coeffs[start..end], idx);
        }
    }

    fn inverse_inplace_at(&self, coeffs: &mut [u64], idx: usize) {
        let n = self.n;
        let q = self.moduli[idx];
        let psi_inv_powers = &self.psi_inv_powers[idx];

        let mut t = 1;
        let mut m = n;

        while m > 1 {
            m >>= 1;
            let j1 = 0;
            for i in 0..m {
                let j2 = j1 + i * 2 * t;
                let w = psi_inv_powers[m + i];

                for j in j2..(j2 + t) {
                    let u = coeffs[j];
                    let v = coeffs[j + t];

                    coeffs[j] = if u + v >= q { u + v - q } else { u + v };
                    let diff = if u >= v { u - v } else { q - v + u };
                    coeffs[j + t] = self.montgomery_mul_at(diff, w, idx);
                }
            }
            t <<= 1;
        }

        // Scale by n^(-1)
        for c in coeffs.iter_mut() {
            *c = self.montgomery_mul_at(*c, self.n_inv[idx], idx);
        }
    }

    /// Performs pointwise multiplication in NTT domain.
    ///
    /// Both inputs must be in Montgomery form (as produced by `forward`).
    ///
    /// # Arguments
    ///
    /// * `a` - First polynomial in NTT domain
    /// * `b` - Second polynomial in NTT domain
    /// * `result` - Output buffer for the product
    ///
    /// # Panics
    ///
    /// Panics if any array length does not equal n * crt_count.
    pub fn pointwise_mul(&self, a: &[u64], b: &[u64], result: &mut [u64]) {
        assert_eq!(
            a.len(),
            self.n * self.crt_count(),
            "Input length must match dimension * crt_count"
        );
        assert_eq!(
            b.len(),
            self.n * self.crt_count(),
            "Input length must match dimension * crt_count"
        );
        assert_eq!(
            result.len(),
            self.n * self.crt_count(),
            "Input length must match dimension * crt_count"
        );

        // Solinas dispatch.
        if self.is_solinas_default_q() {
            let q_inv_neg = self.q_inv_neg[0];
            for i in 0..self.n {
                result[i] = super::solinas_redc::solinas_mont_mul_default_q(a[i], b[i], q_inv_neg);
            }
            return;
        }

        for idx in 0..self.crt_count() {
            let start = idx * self.n;
            for i in 0..self.n {
                result[start + i] = self.montgomery_mul_at(a[start + i], b[start + i], idx);
            }
        }
    }

    /// Performs a single pointwise multiplication.
    ///
    /// Useful for fused multiply-add operations.
    ///
    /// # Arguments
    ///
    /// * `a` - First value in Montgomery form
    /// * `b` - Second value in Montgomery form
    ///
    /// # Returns
    ///
    /// The product `(a * b) mod q` in Montgomery form.
    #[inline]
    pub fn pointwise_mul_single(&self, a: u64, b: u64) -> u64 {
        self.montgomery_mul_at(a, b, 0)
    }

    /// Performs a single pointwise multiplication for a specific CRT modulus.
    ///
    /// Solinas auto-dispatch applied here too. `mul_acc_ntt_domain` on
    /// `Poly` calls this in a tight inner loop over all coefficients;
    /// the compile-time const Q + `#[inline]` on the Solinas free function
    /// matters for codegen.
    #[inline]
    pub fn pointwise_mul_single_at(&self, a: u64, b: u64, idx: usize) -> u64 {
        if self.is_solinas_default_q() {
            // idx must be 0 under the Solinas gate (single-prime config).
            return super::solinas_redc::solinas_mont_mul_default_q(a, b, self.q_inv_neg[0]);
        }
        self.montgomery_mul_at(a, b, idx)
    }

    // ===== Shoup-form NTT path =====
    //
    // Standard-form in/out NTT variants. Internally use precomputed
    // Shoup twiddle twins to replace every inner-butterfly Montgomery
    // multiply with one Shoup multiply. Clients on the Shoup path do
    // NOT Montgomery-convert coefficient arrays at the NTT boundary;
    // inputs/outputs are raw residues in `[0, q)`.
    //
    // These methods are ADDITIVE: the existing `forward` / `inverse`
    // Montgomery pipeline is unchanged and remains the default.

    /// Forward NTT in Shoup mode (standard-form I/O). See module doc.
    ///
    /// # Panics
    /// Panics if `coeffs.len() != n * crt_count`.
    pub fn forward_shoup(&self, coeffs: &mut [u64]) {
        assert_eq!(
            coeffs.len(),
            self.n * self.crt_count(),
            "Input length must match dimension * crt_count"
        );
        for idx in 0..self.moduli.len() {
            let start = idx * self.n;
            let end = start + self.n;
            self.forward_inplace_shoup_at(&mut coeffs[start..end], idx);
        }
    }

    /// Inverse NTT in Shoup mode (standard-form I/O). Output is already
    /// scaled by `n^{-1}` and reduced to `[0, q)`; no Montgomery
    /// conversion follows.
    ///
    /// # Panics
    /// Panics if `coeffs.len() != n * crt_count`.
    pub fn inverse_shoup(&self, coeffs: &mut [u64]) {
        assert_eq!(
            coeffs.len(),
            self.n * self.crt_count(),
            "Input length must match dimension * crt_count"
        );
        for idx in 0..self.moduli.len() {
            let start = idx * self.n;
            let end = start + self.n;
            self.inverse_inplace_shoup_at(&mut coeffs[start..end], idx);
        }
    }

    /// Per-CRT-limb forward Cooley-Tukey butterfly over standard-form
    /// coefficients using Shoup twiddles.
    fn forward_inplace_shoup_at(&self, coeffs: &mut [u64], idx: usize) {
        let n = self.n;
        let q = self.moduli[idx];
        let psi = &self.psi_powers_std[idx];
        let psi_shoup = &self.psi_powers_shoup[idx];

        let mut t = n;
        let mut m = 1;

        while m < n {
            t >>= 1;
            for i in 0..m {
                let j1 = 2 * i * t;
                let j2 = j1 + t;
                let w = psi[m + i];
                let w_shoup = psi_shoup[m + i];

                for j in j1..j2 {
                    let u = coeffs[j];
                    let v = Self::shoup_mul_at(coeffs[j + t], w, w_shoup, q);

                    coeffs[j] = if u + v >= q { u + v - q } else { u + v };
                    coeffs[j + t] = if u >= v { u - v } else { q - v + u };
                }
            }
            m <<= 1;
        }
    }

    /// Per-CRT-limb inverse Gentleman-Sande butterfly over standard-form
    /// coefficients using Shoup twiddles, followed by `n^{-1}` scaling.
    fn inverse_inplace_shoup_at(&self, coeffs: &mut [u64], idx: usize) {
        let n = self.n;
        let q = self.moduli[idx];
        let psi_inv = &self.psi_inv_powers_std[idx];
        let psi_inv_shoup = &self.psi_inv_powers_shoup[idx];

        let mut t = 1;
        let mut m = n;

        while m > 1 {
            m >>= 1;
            let j1 = 0;
            for i in 0..m {
                let j2 = j1 + i * 2 * t;
                let w = psi_inv[m + i];
                let w_shoup = psi_inv_shoup[m + i];

                for j in j2..(j2 + t) {
                    let u = coeffs[j];
                    let v = coeffs[j + t];

                    coeffs[j] = if u + v >= q { u + v - q } else { u + v };
                    let diff = if u >= v { u - v } else { q - v + u };
                    coeffs[j + t] = Self::shoup_mul_at(diff, w, w_shoup, q);
                }
            }
            t <<= 1;
        }

        // Scale by n^{-1} (standard-form Shoup).
        let n_inv = self.n_inv_std[idx];
        let n_inv_shoup = self.n_inv_shoup[idx];
        for c in coeffs.iter_mut() {
            *c = Self::shoup_mul_at(*c, n_inv, n_inv_shoup, q);
        }
    }

    /// Pointwise multiplication in NTT domain with a Shoup-precomputed
    /// second operand. Both inputs are in standard form; caller supplies
    /// `b_shoup[i] = shoup_precompute(b[i], q_of_limb)`. Output is in
    /// standard form.
    ///
    /// For workloads where `b` is fixed across many `a` (session-cached
    /// packing keys, NTT twiddles not already covered), the Shoup
    /// precomputation is amortized over all `a`-variable pointwise
    /// multiplications.
    ///
    /// # Panics
    /// Panics if any length differs from `n * crt_count`.
    pub fn pointwise_mul_shoup(&self, a: &[u64], b: &[u64], b_shoup: &[u64], result: &mut [u64]) {
        let total = self.n * self.crt_count();
        assert_eq!(a.len(), total, "a length mismatch");
        assert_eq!(b.len(), total, "b length mismatch");
        assert_eq!(b_shoup.len(), total, "b_shoup length mismatch");
        assert_eq!(result.len(), total, "result length mismatch");

        for idx in 0..self.crt_count() {
            let start = idx * self.n;
            let q = self.moduli[idx];
            for i in 0..self.n {
                result[start + i] =
                    Self::shoup_mul_at(a[start + i], b[start + i], b_shoup[start + i], q);
            }
        }
    }

    // ===== Solinas-REDC NTT path =====
    //
    // Replaces the classical Montgomery REDC's `m · q` step with
    // Solinas shift-based expansion using `q = 2^60 − 2^14 + 1`'s
    // generalized-Mersenne structure. Saves one u128 multiply per
    // inner butterfly op (scalar) and ~7 madd52 ops per op (IFMA).
    // Only valid at DEFAULT_Q single-prime; caller must ensure this.

    /// Forward NTT in Solinas-Montgomery mode, DEFAULT_Q single-prime
    /// only. Inputs/outputs in Montgomery form (same representation as
    /// classical `forward` path).
    ///
    /// # Panics
    /// Panics if the context is not configured for single-prime
    /// DEFAULT_Q or if `coeffs.len() != n`.
    pub fn forward_solinas(&self, coeffs: &mut [u64]) {
        assert_eq!(self.moduli.len(), 1, "Solinas path is single-prime DEFAULT_Q only");
        assert_eq!(self.moduli[0], super::mod_q::DEFAULT_Q, "Solinas path requires DEFAULT_Q");
        assert_eq!(coeffs.len(), self.n, "Input length must match dimension");

        let q = self.moduli[0];
        let r_squared = self.r_squared[0];
        let q_inv_neg = self.q_inv_neg[0];

        // Convert to Montgomery form at the boundary (same as `forward`).
        for c in coeffs.iter_mut() {
            *c = Self::to_montgomery(*c, q, r_squared, q_inv_neg);
        }

        self.forward_inplace_solinas_at(coeffs, 0);
    }

    /// Inverse NTT in Solinas-Montgomery mode, DEFAULT_Q single-prime
    /// only. Inputs/outputs in Montgomery form.
    pub fn inverse_solinas(&self, coeffs: &mut [u64]) {
        assert_eq!(self.moduli.len(), 1, "Solinas path is single-prime DEFAULT_Q only");
        assert_eq!(self.moduli[0], super::mod_q::DEFAULT_Q, "Solinas path requires DEFAULT_Q");
        assert_eq!(coeffs.len(), self.n, "Input length must match dimension");

        self.inverse_inplace_solinas_at(coeffs, 0);

        // Strip Montgomery form at the output boundary (matches `inverse`).
        for c in coeffs.iter_mut() {
            *c = self.montgomery_mul_at(*c, 1, 0);
        }
    }

    fn forward_inplace_solinas_at(&self, coeffs: &mut [u64], idx: usize) {
        let n = self.n;
        let q = self.moduli[idx];
        let q_inv_neg = self.q_inv_neg[idx];
        let psi_powers = &self.psi_powers[idx];

        // Scalar path preferred: SIMD butterfly and manual unroll experiments
        // both measured flat-to-regressed at this ring dimension. LLVM at
        // opt-level=3 already pipelines the Solinas REDC + add/sub/cmov chain
        // optimally; no additional parallelism is extractable.
        let mut t = n;
        let mut m = 1;
        while m < n {
            t >>= 1;
            for i in 0..m {
                let j1 = 2 * i * t;
                let j2 = j1 + t;
                let w = psi_powers[m + i];

                for j in j1..j2 {
                    let u = coeffs[j];
                    // Solinas-REDC inner multiply (drop-in for montgomery_mul_at).
                    let v = super::solinas_redc::solinas_mont_mul_default_q(
                        coeffs[j + t],
                        w,
                        q_inv_neg,
                    );
                    coeffs[j] = if u + v >= q { u + v - q } else { u + v };
                    coeffs[j + t] = if u >= v { u - v } else { q - v + u };
                }
            }
            m <<= 1;
        }
    }

    fn inverse_inplace_solinas_at(&self, coeffs: &mut [u64], idx: usize) {
        let n = self.n;
        let q = self.moduli[idx];
        let q_inv_neg = self.q_inv_neg[idx];
        let psi_inv_powers = &self.psi_inv_powers[idx];

        // Scalar path preferred (see forward_inplace_solinas_at comment).
        let mut t = 1;
        let mut m = n;
        while m > 1 {
            m >>= 1;
            let j1 = 0;
            for i in 0..m {
                let j2 = j1 + i * 2 * t;
                let w = psi_inv_powers[m + i];

                for j in j2..(j2 + t) {
                    let u = coeffs[j];
                    let v = coeffs[j + t];
                    coeffs[j] = if u + v >= q { u + v - q } else { u + v };
                    let diff = if u >= v { u - v } else { q - v + u };
                    coeffs[j + t] = super::solinas_redc::solinas_mont_mul_default_q(
                        diff,
                        w,
                        q_inv_neg,
                    );
                }
            }
            t <<= 1;
        }

        // Scale by n^(-1) (in Montgomery form, same as classical `inverse_inplace`).
        for c in coeffs.iter_mut() {
            *c = super::solinas_redc::solinas_mont_mul_default_q(
                *c,
                self.n_inv[idx],
                q_inv_neg,
            );
        }
    }

    /// Pointwise NTT-domain multiplication using Solinas-REDC, DEFAULT_Q
    /// single-prime only. Both inputs + output in Montgomery form.
    pub fn pointwise_mul_solinas(&self, a: &[u64], b: &[u64], result: &mut [u64]) {
        assert_eq!(self.moduli.len(), 1, "Solinas path is single-prime DEFAULT_Q only");
        assert_eq!(self.moduli[0], super::mod_q::DEFAULT_Q, "Solinas path requires DEFAULT_Q");
        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);
        assert_eq!(result.len(), self.n);
        let q_inv_neg = self.q_inv_neg[0];
        for i in 0..self.n {
            result[i] = super::solinas_redc::solinas_mont_mul_default_q(a[i], b[i], q_inv_neg);
        }
    }

    /// Compute the Shoup twin for every coefficient of a standard-form
    /// operand laid out as `n * crt_count` u64s (per-CRT-limb order, same
    /// as `Poly::coeffs()`). Callers cache the result alongside the
    /// operand for reuse.
    pub fn shoup_precompute_vec(&self, b: &[u64]) -> Vec<u64> {
        let total = self.n * self.crt_count();
        assert_eq!(b.len(), total, "b length mismatch");
        let mut out = Vec::with_capacity(total);
        for idx in 0..self.crt_count() {
            let start = idx * self.n;
            let q = self.moduli[idx];
            for i in 0..self.n {
                out.push(Self::shoup_precompute(b[start + i], q));
            }
        }
        out
    }

    /// Converts a value to Montgomery form.
    ///
    /// # Arguments
    ///
    /// * `a` - Value in standard representation
    ///
    /// # Returns
    ///
    /// The value in Montgomery form.
    pub fn to_mont(&self, a: u64) -> u64 {
        Self::to_montgomery(a, self.moduli[0], self.r_squared[0], self.q_inv_neg[0])
    }

    /// Converts a value from Montgomery form.
    ///
    /// # Arguments
    ///
    /// * `a` - Value in Montgomery form
    ///
    /// # Returns
    ///
    /// The value in standard representation.
    pub fn from_mont(&self, a: u64) -> u64 {
        self.montgomery_mul_at(a, 1, 0)
    }

    // `#[inline]` on the generic Montgomery inner kernel, bringing the
    // fallback (non-Solinas) path to parity with the Solinas free function.
    #[inline]
    fn montgomery_mul_at(&self, a: u64, b: u64, idx: usize) -> u64 {
        let q = self.moduli[idx];
        let q_inv_neg = self.q_inv_neg[idx];
        let ab = (a as u128) * (b as u128);
        let m = ((ab as u64).wrapping_mul(q_inv_neg)) as u128;
        let t = ((ab + m * (q as u128)) >> 64) as u64;
        if t >= q {
            t - q
        } else {
            t
        }
    }

    fn to_montgomery(a: u64, q: u64, r_squared: u64, q_inv_neg: u64) -> u64 {
        let ab = (a as u128) * (r_squared as u128);
        let m = ((ab as u64).wrapping_mul(q_inv_neg)) as u128;
        let t = ((ab + m * (q as u128)) >> 64) as u64;
        if t >= q {
            t - q
        } else {
            t
        }
    }

    #[inline]
    fn to_montgomery_at(a: u64, q: u64, r_squared: u64, q_inv_neg: u64) -> u64 {
        Self::to_montgomery(a, q, r_squared, q_inv_neg)
    }

    fn compute_q_inv_neg(q: u64) -> u64 {
        let mut y: u64 = 1;
        for i in 1..64 {
            let yi = y.wrapping_mul(q) & (1u64 << i);
            y |= yi;
        }
        y.wrapping_neg()
    }

    fn compute_r_squared(q: u64) -> u64 {
        let r_mod_q = (1u128 << 64) % (q as u128);
        ((r_mod_q * r_mod_q) % (q as u128)) as u64
    }

    fn mod_pow(mut base: u64, mut exp: u64, m: u64) -> u64 {
        let mut result = 1u64;
        base %= m;
        while exp > 0 {
            if exp & 1 == 1 {
                result = ((result as u128 * base as u128) % m as u128) as u64;
            }
            exp >>= 1;
            base = ((base as u128 * base as u128) % m as u128) as u64;
        }
        result
    }

    /// Find a primitive n-th root of unity modulo q
    fn find_primitive_root(n: u64, q: u64) -> u64 {
        // g is a generator of Z_q^*, find ψ = g^((q-1)/n)
        let exp = (q - 1) / n;

        // Try small generators
        for g in 2..q {
            let candidate = Self::mod_pow(g, exp, q);
            // Check that ψ^n = 1 and ψ^(n/2) ≠ 1
            if Self::mod_pow(candidate, n, q) == 1 && Self::mod_pow(candidate, n / 2, q) != 1 {
                return candidate;
            }
        }
        // Internal invariant: for any `q` satisfying `q ≡ 1 (mod 2n)`
        // a primitive 2n-th root of unity MUST exist in Z_q^*.
        // `InspireParams::validate()` rejects CRT moduli violating this.
        // Reaching this panic means the modulus does not satisfy the
        // NTT-friendliness precondition.
        panic!("No primitive root found; modulus may not satisfy q ≡ 1 (mod 2n)");
    }

    /// Compute standard-form (non-Montgomery) twiddle factor ladder.
    ///
    /// Mirrors `compute_twiddle_factors`' indexing so the Shoup path
    /// uses the same bit-reversed structure as the Montgomery path, but
    /// computes in plain mod-q arithmetic (no R = 2^64 factor). Output is
    /// directly consumable by `shoup_mul_at` once paired with its Shoup
    /// precomputation via [`compute_shoup_twins`].
    fn compute_twiddle_factors_std(n: usize, psi: u64, q: u64) -> Vec<u64> {
        let mut factors = vec![0u64; n];
        factors[1] = 1; // ψ^0

        for m in 1..n {
            if m.is_power_of_two() {
                // New level: compute ψ^(n/(2m))
                let exp = (n / (2 * m)) as u64;
                factors[m] = Self::mod_pow(psi, exp, q);
            } else {
                let prev_idx = m & (m - 1);
                let step_idx = m & (!m + 1);
                let ab = (factors[prev_idx] as u128) * (factors[step_idx] as u128);
                factors[m] = (ab % q as u128) as u64;
            }
        }

        factors
    }

    /// Compute Shoup precomputation twins for a twiddle ladder.
    ///
    /// For each b in `factors`, returns `floor(b · 2^64 / q)`. This enables
    /// the Shoup multiply (`shoup_mul_at`) to skip a Montgomery-style u64
    /// multiplication + add-shift on every inner butterfly multiply.
    fn compute_shoup_twins(factors: &[u64], q: u64) -> Vec<u64> {
        factors.iter().map(|&b| Self::shoup_precompute(b, q)).collect()
    }

    /// Precompute `floor(b · 2^64 / q)` for Shoup multiplication with a
    /// fixed multiplicand b. One-time cost amortized over all (a · b)
    /// evaluations that re-use this twin.
    #[inline]
    fn shoup_precompute(b: u64, q: u64) -> u64 {
        (((b as u128) << 64) / (q as u128)) as u64
    }

    /// Shoup modular multiplication: given `a, b ∈ [0, q)` and the
    /// precomputed `b_shoup = floor(b · 2^64 / q)`, returns `a · b mod q`
    /// in standard form (not Montgomery).
    ///
    /// Contract mirrors fhe.rs `Modulus::mul_shoup`: two u128 mults + one
    /// subtract + one conditional reduction, byte-identical to
    /// `(a * b) mod q` at all inputs.
    #[inline]
    fn shoup_mul_at(a: u64, b: u64, b_shoup: u64, q: u64) -> u64 {
        let q_est = ((a as u128) * (b_shoup as u128)) >> 64;
        let r = ((a as u128)
            .wrapping_mul(b as u128)
            .wrapping_sub(q_est.wrapping_mul(q as u128))) as u64;
        if r >= q {
            r - q
        } else {
            r
        }
    }

    /// Compute twiddle factors in the order needed for NTT
    fn compute_twiddle_factors(
        n: usize,
        psi: u64,
        q: u64,
        q_inv_neg: u64,
        r_squared: u64,
    ) -> Vec<u64> {
        let mut factors = vec![0u64; n];

        // factors[0] is unused, factors[1] = ψ^0 = 1
        factors[1] = Self::to_montgomery(1, q, r_squared, q_inv_neg);

        // Build in bit-reversed order for efficient access
        for m in 1..n {
            if m.is_power_of_two() {
                // New level: compute ψ^(n/(2m))
                let exp = n / (2 * m);

                // ψ^exp in Montgomery form
                let mut pow = Self::to_montgomery(1, q, r_squared, q_inv_neg);
                for _ in 0..exp {
                    let ab = (pow as u128) * (psi as u128);
                    let mm = ((ab as u64).wrapping_mul(q_inv_neg)) as u128;
                    pow = ((ab + mm * (q as u128)) >> 64) as u64;
                    if pow >= q {
                        pow -= q;
                    }
                }
                factors[m] = pow;
            } else {
                // Multiply previous by ψ^(n/m) computed from factors[m - (m & -m as isize as usize)]
                let prev_idx = m & (m - 1); // Clear lowest set bit
                let step_idx = m & (!m + 1); // Lowest set bit

                let ab = (factors[prev_idx] as u128) * (factors[step_idx] as u128);
                let mm = ((ab as u64).wrapping_mul(q_inv_neg)) as u128;
                let t = ((ab + mm * (q as u128)) >> 64) as u64;
                factors[m] = if t >= q { t - q } else { t };
            }
        }

        factors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_inverse_roundtrip_small() {
        let n = 16;
        let ctx = NttContext::with_default_q(n);

        let original: Vec<u64> = (0..n as u64).collect();
        let mut coeffs = original.clone();

        ctx.forward(&mut coeffs);
        ctx.inverse(&mut coeffs);

        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_ntt_inverse_roundtrip_1024() {
        let n = 1024;
        let ctx = NttContext::with_default_q(n);

        let original: Vec<u64> = (0..n as u64).collect();
        let mut coeffs = original.clone();

        ctx.forward(&mut coeffs);
        ctx.inverse(&mut coeffs);

        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_ntt_inverse_roundtrip_2048() {
        let n = 2048;
        let ctx = NttContext::with_default_q(n);

        let original: Vec<u64> = (0..n as u64).map(|i| i * 1000 % DEFAULT_Q).collect();
        let mut coeffs = original.clone();

        ctx.forward(&mut coeffs);
        ctx.inverse(&mut coeffs);

        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_ntt_inverse_roundtrip_4096() {
        let n = 4096;
        let ctx = NttContext::with_default_q(n);

        let original: Vec<u64> = (0..n as u64).map(|i| (i * 12345) % DEFAULT_Q).collect();
        let mut coeffs = original.clone();

        ctx.forward(&mut coeffs);
        ctx.inverse(&mut coeffs);

        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_ntt_zero_polynomial() {
        let n = 256;
        let ctx = NttContext::with_default_q(n);

        let mut coeffs = vec![0u64; n];
        ctx.forward(&mut coeffs);

        assert!(coeffs.iter().all(|&c| c == 0));

        ctx.inverse(&mut coeffs);
        assert!(coeffs.iter().all(|&c| c == 0));
    }

    #[test]
    fn test_ntt_constant_polynomial() {
        let n = 256;
        let ctx = NttContext::with_default_q(n);

        let mut coeffs = vec![0u64; n];
        coeffs[0] = 42;
        let original = coeffs.clone();

        ctx.forward(&mut coeffs);
        ctx.inverse(&mut coeffs);

        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_pointwise_multiplication() {
        let n = 256;
        let ctx = NttContext::with_default_q(n);

        // a(x) = 1, b(x) = 1 => a*b = 1
        let mut a = vec![0u64; n];
        let mut b = vec![0u64; n];
        a[0] = 1;
        b[0] = 1;

        ctx.forward(&mut a);
        ctx.forward(&mut b);

        let mut result = vec![0u64; n];
        ctx.pointwise_mul(&a, &b, &mut result);

        ctx.inverse(&mut result);

        assert_eq!(result[0], 1);
        assert!(result[1..].iter().all(|&c| c == 0));
    }

    #[test]
    fn test_negacyclic_convolution() {
        // For R_q = Z_q[X]/(X^n + 1), x^n = -1
        // So x * x^(n-1) = x^n = -1 (mod X^n + 1)
        let n = 256;
        let q = DEFAULT_Q;
        let ctx = NttContext::with_default_q(n);

        // a(x) = x (coefficient at index 1)
        let mut a = vec![0u64; n];
        a[1] = 1;

        // b(x) = x^(n-1) (coefficient at index n-1)
        let mut b = vec![0u64; n];
        b[n - 1] = 1;

        ctx.forward(&mut a);
        ctx.forward(&mut b);

        let mut result = vec![0u64; n];
        ctx.pointwise_mul(&a, &b, &mut result);

        ctx.inverse(&mut result);

        // Result should be x^n = -1 (mod X^n + 1) = q - 1 in coefficient 0
        assert_eq!(result[0], q - 1);
        assert!(result[1..].iter().all(|&c| c == 0));
    }

    #[test]
    fn test_linearity() {
        let n = 256;
        let ctx = NttContext::with_default_q(n);
        let q = DEFAULT_Q;

        let a: Vec<u64> = (0..n as u64).collect();
        let b: Vec<u64> = (0..n as u64).map(|i| (i * 2) % q).collect();

        let mut a_ntt = a.clone();
        let mut b_ntt = b.clone();
        ctx.forward(&mut a_ntt);
        ctx.forward(&mut b_ntt);

        // NTT(a + b) should equal NTT(a) + NTT(b)
        let mut sum: Vec<u64> = a.iter().zip(b.iter()).map(|(&x, &y)| (x + y) % q).collect();
        ctx.forward(&mut sum);

        for i in 0..n {
            let expected = (a_ntt[i] + b_ntt[i]) % q;
            assert_eq!(sum[i], expected);
        }
    }
}
