//! `GeneratorPowers` must report a degenerate ring dimension instead of
//! aborting the process.
//!
//! `GeneratorPowers::try_new` builds `g^i mod 2d` for the canonical generator
//! `g = 5`, which is invertible mod `2d` only when `5` does not divide `2d`.
//! `d = 0` and any `d` divisible by 5 must surface as `PackParamsError`
//! rather than aborting.

use raven_inspire::inspiring::{GeneratorPowers, PackParamsError};

#[test]
fn try_new_rejects_zero_ring_dim() {
    assert!(matches!(
        GeneratorPowers::try_new(0),
        Err(PackParamsError::RingDimNotPowerOfTwo { ring_dim: 0 })
    ));
}

#[test]
fn try_new_rejects_ring_dim_divisible_by_five() {
    assert!(matches!(
        GeneratorPowers::try_new(10),
        Err(PackParamsError::RingDimNotPowerOfTwo { ring_dim: 10 })
    ));
}

/// Odd and non-power-of-two dimensions where 5 IS invertible mod 2d, so the
/// downstream inverse succeeds and only the power-of-two guard rejects them.
/// Without that guard these build silently wrong generator tables.
#[test]
fn try_new_rejects_dimensions_the_inverse_fallback_would_accept() {
    for d in [3usize, 6, 7, 12, 14, 24] {
        assert!(
            matches!(
                GeneratorPowers::try_new(d),
                Err(PackParamsError::RingDimNotPowerOfTwo { ring_dim }) if ring_dim == d
            ),
            "ring_dim {d} must be rejected by the power-of-two guard"
        );
    }
}

#[test]
fn try_new_accepts_power_of_two_ring_dim() {
    let table = GeneratorPowers::try_new(2048).expect("2048 is a legal ring dimension");
    assert_eq!(table.order(), 2048);
    assert_eq!(table.pow(0), 1);
    assert_eq!(table.pow(1), 5);
    // g^i * g^{-i} = 1 mod 2d for every i in the table.
    for i in 0..2048 {
        assert_eq!((table.pow(i) * table.inv_pow(i)) % 4096, 1);
    }
}
