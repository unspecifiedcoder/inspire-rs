//! Solinas-form Montgomery reduction for DEFAULT_Q = 2^60 − 2^14 + 1.
//!
//! Classical Montgomery REDC computes `a · b · R^{-1} mod q` via
//! `m = (ab_lo · q_inv_neg) mod 2^64`, then `t = (ab + m · q) >> 64`,
//! then `t -= q` if `t >= q`. The `m · q` sub-step is the dominant
//! cost in both scalar Montgomery and IFMA52 split-52 Montgomery.
//!
//! Because DEFAULT_Q = 2^60 − 2^14 + 1 is a generalized-Mersenne
//! (Solinas) prime, `m · q` expands to:
//!
//! ```text
//! m · q = m · 2^60 − m · 2^14 + m
//! ```
//!
//! which is **three shifts + one subtract + one add**, zero
//! multiplications. This module provides that specialization.
//!
//! # Properties
//!
//! - Byte-identical to classical scalar Montgomery at DEFAULT_Q for
//!   every `(a, b, q_inv_neg)` input triple. Verified over 10 000
//!   random inputs + edge cases in `tests/solinas_montgomery_kat.rs`.
//! - No `u128` multiply in the hot step; only `u128` shifts + adds.
//! - Preserves Montgomery form: inputs in Montgomery form produce
//!   output in Montgomery form. The Solinas substitution affects
//!   only the computation of `m · q`; all invariants of the
//!   Montgomery framework are preserved.

use super::mod_q::DEFAULT_Q;

/// Solinas-form Montgomery reduction specialized to DEFAULT_Q.
///
/// Computes `a · b · R^{-1} mod DEFAULT_Q` where `R = 2^64`, for
/// inputs `a, b ∈ [0, DEFAULT_Q)`.
///
/// # Arguments
/// * `a`, `b`: operands in `[0, DEFAULT_Q)`.
/// * `q_inv_neg`: precomputed `-DEFAULT_Q^{-1} mod 2^64`.
///
/// # Invariants preserved
/// Standard Montgomery REDC invariant: the computed result is
/// congruent to `a · b · R^{-1} (mod DEFAULT_Q)` and lies in
/// `[0, DEFAULT_Q)` after the final conditional subtract.
#[inline]
pub fn solinas_mont_mul_default_q(a: u64, b: u64, q_inv_neg: u64) -> u64 {
    const Q: u64 = DEFAULT_Q;
    let ab = (a as u128).wrapping_mul(b as u128);
    let m = (ab as u64).wrapping_mul(q_inv_neg);
    // Solinas: m · q = m · 2^60 − m · 2^14 + m
    let mq = ((m as u128) << 60)
        .wrapping_sub((m as u128) << 14)
        .wrapping_add(m as u128);
    let t = (ab.wrapping_add(mq) >> 64) as u64;
    if t >= Q {
        t - Q
    } else {
        t
    }
}

/// Pointwise Montgomery multiplication of two coefficient vectors
/// using Solinas-form reduction at DEFAULT_Q.
///
/// Both inputs are in NTT/Montgomery form; output is also in
/// Montgomery form (i.e. `a[i] · b[i] · R^{-1} mod DEFAULT_Q`).
///
/// # Panics
/// Panics if array lengths differ.
#[inline]
pub fn pointwise_solinas_mont_mul(a: &[u64], b: &[u64], result: &mut [u64], q_inv_neg: u64) {
    assert_eq!(a.len(), b.len(), "pointwise lengths mismatch");
    assert_eq!(a.len(), result.len(), "pointwise result length mismatch");
    for i in 0..a.len() {
        result[i] = solinas_mont_mul_default_q(a[i], b[i], q_inv_neg);
    }
}

#[cfg(target_arch = "x86_64")]
pub mod avx512_ifma {
    //! 8-wide SIMD Solinas-Montgomery via AVX-512-IFMA intrinsics.
    //!
    //! Uses the split-52 approach for the full `ab` product (7 madd52
    //! assembling the 120-bit partial-products layout), then replaces
    //! the `m · q` step with the Solinas shift-based expansion:
    //!
    //! ```text
    //! m · q = m · 2^60 − m · 2^14 + m
    //!       → shifts + subtract + add, zero multiplications
    //! ```
    //!
    //! Savings per 8-lane batch vs split-52 IFMA52: −7 madd52
    //! (≈ −3.5 cycles IFMA work, −5-6 scalar-ALU cycles, −2-3 cycles
    //! dependency-chain; ~10-12 cycles/batch total).
    //!
    //! Runtime dispatch: callers MUST check
    //! `is_x86_feature_detected!("avx512ifma")` before invoking.

    use super::DEFAULT_Q;
    use std::arch::x86_64::*;

    const MASK52: u64 = (1u64 << 52) - 1;

    /// 8-wide Solinas-Montgomery multiply using AVX-512-IFMA.
    ///
    /// Computes `a[i] · b[i] · R^{-1} mod DEFAULT_Q` for 8 lanes in
    /// parallel. R = 2^64. Both operands in `[0, DEFAULT_Q)`.
    ///
    /// # Safety
    /// Caller MUST ensure `is_x86_feature_detected!("avx512ifma")`
    /// is true on the executing CPU.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub unsafe fn solinas_mont_mul_x8(a: __m512i, b: __m512i, q_inv_neg_vec: __m512i) -> __m512i {
        let mask52 = _mm512_set1_epi64(MASK52 as i64);
        let q_vec = _mm512_set1_epi64(DEFAULT_Q as i64);
        let zero = _mm512_setzero_si512();

        // --- Step 1: Compute ab (full 120-bit product via split-52) ---
        let a_lo = _mm512_and_si512(a, mask52);
        let a_hi = _mm512_srli_epi64::<52>(a);
        let b_lo = _mm512_and_si512(b, mask52);
        let b_hi = _mm512_srli_epi64::<52>(b);

        let p00_lo = _mm512_madd52lo_epu64(zero, a_lo, b_lo);
        let p00_hi = _mm512_madd52hi_epu64(zero, a_lo, b_lo);
        let p10_lo = _mm512_madd52lo_epu64(zero, a_hi, b_lo);
        let p10_hi = _mm512_madd52hi_epu64(zero, a_hi, b_lo);
        let p01_lo = _mm512_madd52lo_epu64(zero, a_lo, b_hi);
        let p01_hi = _mm512_madd52hi_epu64(zero, a_lo, b_hi);
        let p11_lo = _mm512_madd52lo_epu64(zero, a_hi, b_hi);

        let cross_mid = _mm512_add_epi64(_mm512_add_epi64(p00_hi, p10_lo), p01_lo);
        let cross_mid_lo52 = _mm512_and_si512(cross_mid, mask52);
        let cross_mid_carry = _mm512_srli_epi64::<52>(cross_mid);

        let upper_9 = _mm512_add_epi64(_mm512_add_epi64(p10_hi, p01_hi), cross_mid_carry);
        let mask8 = _mm512_set1_epi64(0xFFi64);
        let p11_low8 = _mm512_and_si512(p11_lo, mask8);
        let p11_high = _mm512_srli_epi64::<8>(p11_lo);

        let cm_shifted = _mm512_slli_epi64::<52>(cross_mid_lo52);
        let ab_lo = _mm512_or_si512(p00_lo, cm_shifted);

        let cm_top = _mm512_srli_epi64::<12>(cross_mid_lo52);
        let upper_plus_low = _mm512_add_epi64(upper_9, p11_low8);
        let upper_shifted = _mm512_slli_epi64::<40>(upper_plus_low);
        let p11_hi_shifted = _mm512_slli_epi64::<48>(p11_high);
        let ab_hi = _mm512_add_epi64(_mm512_add_epi64(cm_top, upper_shifted), p11_hi_shifted);

        // --- Step 2: m = ab_lo · q_inv_neg mod 2^64 ---
        let m = _mm512_mullo_epi64(ab_lo, q_inv_neg_vec);

        // --- Step 3: Solinas expansion m · q = (m << 60) - (m << 14) + m ---
        //
        // As u128 per lane:
        //   m_shifted_60: hi = m >> 4,   lo = m << 60
        //   m_shifted_14: hi = m >> 50,  lo = m << 14
        //   m_base:       hi = 0,        lo = m
        //
        //   diff = m_shifted_60 - m_shifted_14 (u128 sub, borrow-aware)
        //   mq   = diff + m_base (u128 add, carry-aware)

        let mq_60_hi = _mm512_srli_epi64::<4>(m);
        let mq_60_lo = _mm512_slli_epi64::<60>(m);
        let mq_14_hi = _mm512_srli_epi64::<50>(m);
        let mq_14_lo = _mm512_slli_epi64::<14>(m);

        // Subtract m_shifted_14 from m_shifted_60 (u128 semantics):
        let diff_lo = _mm512_sub_epi64(mq_60_lo, mq_14_lo);
        // Borrow if mq_60_lo < mq_14_lo (unsigned compare)
        let borrow_mask = _mm512_cmplt_epu64_mask(mq_60_lo, mq_14_lo);
        let one = _mm512_set1_epi64(1i64);
        let borrow = _mm512_maskz_mov_epi64(borrow_mask, one);
        let diff_hi = _mm512_sub_epi64(_mm512_sub_epi64(mq_60_hi, mq_14_hi), borrow);

        // Add m to the lo half (u128 add with carry-forward):
        let mq_lo = _mm512_add_epi64(diff_lo, m);
        let carry_mask = _mm512_cmplt_epu64_mask(mq_lo, diff_lo);
        let carry = _mm512_maskz_mov_epi64(carry_mask, one);
        let mq_hi = _mm512_add_epi64(diff_hi, carry);

        // --- Step 4: t = (ab + mq) >> 64 ---
        let sum_lo = _mm512_add_epi64(ab_lo, mq_lo);
        let sum_carry_mask = _mm512_cmplt_epu64_mask(sum_lo, ab_lo);
        let sum_carry = _mm512_maskz_mov_epi64(sum_carry_mask, one);
        let t = _mm512_add_epi64(_mm512_add_epi64(ab_hi, mq_hi), sum_carry);

        // --- Step 5: Conditional subtract ---
        let ge_mask = _mm512_cmpge_epu64_mask(t, q_vec);
        _mm512_mask_sub_epi64(t, ge_mask, t, q_vec)
    }

    /// 8-wide forward Cooley-Tukey butterfly over Solinas-Montgomery
    /// at DEFAULT_Q.
    ///
    /// Given `coeffs` laid out with `coeffs[j..j+8]` (the low half of
    /// the butterfly) and `coeffs[j+t..j+t+8]` (the high half), a
    /// broadcast twiddle `w_vec` in Montgomery form, and
    /// `q_inv_neg_vec`, this computes 8 butterflies in parallel:
    ///
    /// ```text
    ///   v = solinas_mul(hi_lane, w)   (Montgomery mul)
    ///   hi'    = (lo + v) mod q
    ///   lo'    = (lo - v) mod q   (coeffs[j]   slot)
    /// ```
    ///
    /// Stored back per the Cooley-Tukey DIT convention: `coeffs[j] =
    /// (lo + v) mod q`, `coeffs[j+t] = (lo - v) mod q`.
    ///
    /// Mirrors the scalar `forward_inplace_solinas_at` inner loop
    /// with 8× parallelism. Correct for any `t >= 8` (stride between
    /// low and high lanes). For `t < 8` the scalar path handles it.
    ///
    /// # Safety
    /// Caller MUST ensure:
    /// - `is_x86_feature_detected!("avx512ifma")` is true.
    /// - `lo_ptr` + `hi_ptr` point to 8 contiguous u64 slots.
    /// - The 8 low + 8 high slots do not overlap (t >= 8).
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub unsafe fn forward_butterfly_solinas_x8(
        lo_ptr: *mut u64,
        hi_ptr: *mut u64,
        w_vec: __m512i,
        q_inv_neg_vec: __m512i,
    ) {
        let q_vec = _mm512_set1_epi64(DEFAULT_Q as i64);
        let lo = _mm512_loadu_si512(lo_ptr.cast());
        let hi = _mm512_loadu_si512(hi_ptr.cast());
        // v = solinas_mul(hi, w)
        let v = solinas_mont_mul_x8(hi, w_vec, q_inv_neg_vec);
        // new_lo = (lo + v) mod q   — stored back at coeffs[j]
        let sum = _mm512_add_epi64(lo, v);
        let sum_ge = _mm512_cmpge_epu64_mask(sum, q_vec);
        let new_lo = _mm512_mask_sub_epi64(sum, sum_ge, sum, q_vec);
        // new_hi = (lo - v) mod q   — stored back at coeffs[j+t]
        // Implement via borrow-aware sub: if lo < v then result = q + lo - v.
        let borrow_mask = _mm512_cmplt_epu64_mask(lo, v);
        let diff = _mm512_sub_epi64(lo, v);
        let new_hi = _mm512_mask_add_epi64(diff, borrow_mask, diff, q_vec);
        _mm512_storeu_si512(lo_ptr.cast(), new_lo);
        _mm512_storeu_si512(hi_ptr.cast(), new_hi);
    }

    /// 8-wide inverse Gentleman-Sande butterfly over Solinas-Montgomery
    /// at DEFAULT_Q.
    ///
    /// Inverse NTT butterfly: compute `(u+v) mod q` and
    /// `solinas_mul((u-v) mod q, w)`, store back at lo/hi lanes.
    ///
    /// # Safety
    /// Same preconditions as [`forward_butterfly_solinas_x8`].
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub unsafe fn inverse_butterfly_solinas_x8(
        lo_ptr: *mut u64,
        hi_ptr: *mut u64,
        w_vec: __m512i,
        q_inv_neg_vec: __m512i,
    ) {
        let q_vec = _mm512_set1_epi64(DEFAULT_Q as i64);
        let u = _mm512_loadu_si512(lo_ptr.cast());
        let v = _mm512_loadu_si512(hi_ptr.cast());
        // new_lo = (u + v) mod q
        let sum = _mm512_add_epi64(u, v);
        let sum_ge = _mm512_cmpge_epu64_mask(sum, q_vec);
        let new_lo = _mm512_mask_sub_epi64(sum, sum_ge, sum, q_vec);
        // diff = (u - v) mod q
        let borrow_mask = _mm512_cmplt_epu64_mask(u, v);
        let raw_diff = _mm512_sub_epi64(u, v);
        let diff_mod = _mm512_mask_add_epi64(raw_diff, borrow_mask, raw_diff, q_vec);
        // new_hi = solinas_mul(diff, w)
        let new_hi = solinas_mont_mul_x8(diff_mod, w_vec, q_inv_neg_vec);
        _mm512_storeu_si512(lo_ptr.cast(), new_lo);
        _mm512_storeu_si512(hi_ptr.cast(), new_hi);
    }

    /// Pointwise 8-wide Solinas-Montgomery multiply for a pair of
    /// coefficient arrays at DEFAULT_Q.
    ///
    /// Both inputs in Montgomery form; output in Montgomery form.
    /// Array lengths must be multiples of 8.
    ///
    /// # Safety
    /// Caller MUST ensure `is_x86_feature_detected!("avx512ifma")`
    /// is true. Memory access is via `loadu/storeu` (unaligned OK).
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub unsafe fn pointwise_solinas_mont_mul_x8(
        a: &[u64],
        b: &[u64],
        result: &mut [u64],
        q_inv_neg: u64,
    ) {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), result.len());
        assert_eq!(a.len() % 8, 0, "array length must be multiple of 8");

        let q_inv_neg_vec = _mm512_set1_epi64(q_inv_neg as i64);

        for i in (0..a.len()).step_by(8) {
            let av = _mm512_loadu_si512(a[i..].as_ptr().cast());
            let bv = _mm512_loadu_si512(b[i..].as_ptr().cast());
            let rv = solinas_mont_mul_x8(av, bv, q_inv_neg_vec);
            _mm512_storeu_si512(result[i..].as_mut_ptr().cast(), rv);
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub mod avx512_ifma {
    #[allow(unused_variables)]
    pub unsafe fn pointwise_solinas_mont_mul_x8(
        a: &[u64],
        b: &[u64],
        result: &mut [u64],
        q_inv_neg: u64,
    ) {
        panic!("AVX-512-IFMA not available on this target architecture");
    }
}
