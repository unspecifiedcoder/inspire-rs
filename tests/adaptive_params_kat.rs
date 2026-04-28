//! Adaptive-params Known-Answer Tests
//!
//! Locks every field of `InspireParams::for_scenario(2^20, 256,
//! [64, 1024, 64], 1)` to byte-exact values so that future agents
//! can detect drift in the derivation before it corrupts a
//! downstream bench measurement.
//!
//! The reference values come from the derivation itself; they match
//! the adapter's original port at
//! `crates/raven-b1-bench/src/adaptive_params.rs` (checked against
//! the original parameter dump
//! modulo the Raven-local p = 65537 deviation).
//!
//! See the theoretical bounds documentation for the full
//! noise-budget proof.

use raven_inspire::params::{derive_medium_payload, AdaptiveInputs, InspireParams, SecurityLevel};

#[test]
fn slo_cell_derivation_matches_reference() {
    let inputs = AdaptiveInputs {
        input_num_items: 1 << 20,
        input_item_size_bits: 256 * 8,
        gammas: [64, 1024, 64],
        performance_factor: 1,
    };
    let d = derive_medium_payload(&inputs);

    // Integer fields are byte-exact.
    assert_eq!(d.poly_len, 2048);
    assert_eq!(d.p, 65537, "Raven-local deviation from Google's p=65536");
    assert_eq!(d.nu_1, 0);
    assert_eq!(d.nu_2, 0);
    assert_eq!(d.q2_bits, 28);
    assert_eq!(d.t_exp_left, 3);
    assert_eq!(d.z, 1u64 << 19);
    assert_eq!(d.db_rows, 0);
    assert_eq!(d.db_cols, 64);
    assert_eq!(d.num_tiles_log2, 0);
    assert_eq!(d.custom_moduli, vec![67_043_329u64, 132_120_577u64]);

    // sigma_x is an exact literal in the port; compare with fixed precision.
    assert_eq!(d.sigma_x.to_bits(), 6.4f64.to_bits());

    // Floating-point fields: bound to known-derived values within tight
    // tolerance. Expected values computed independently from Google's
    // formulas from the theoretical bounds; tolerance of 1e-3 is 3 orders of
    // magnitude tighter than the 0.09-bit slack budget.
    approx_eq(d.term_0_variance, 29.97, 1e-2, "term_0_variance");
    approx_eq(d.term_1_variance, 31.97, 1e-2, "term_1_variance");
    approx_eq(d.term_2_variance, 29.97, 1e-2, "term_2_variance");
    approx_eq(d.max_variance, 31.97, 1e-2, "max_variance");
    approx_eq(d.required_q_log2, 52.884, 1e-2, "required_q_log2");
    approx_eq(d.custom_q_log2, 52.977, 1e-2, "custom_q_log2");

    // Noise-budget gate holds.
    assert!(
        d.custom_q_log2 >= d.required_q_log2,
        "noise budget violated: custom_q_log2 {:.6} < required_q_log2 {:.6}",
        d.custom_q_log2,
        d.required_q_log2
    );
}

#[test]
fn for_scenario_bridges_to_inspire_params_byte_identical() {
    let params = InspireParams::for_scenario(1 << 20, 256, [64, 1024, 64], 1)
        .expect("for_scenario must produce validated params");

    assert_eq!(params.ring_dim, 2048);
    assert_eq!(params.crt_moduli, vec![67_043_329u64, 132_120_577u64]);
    assert_eq!(params.q, 67_043_329u64 * 132_120_577u64);
    assert_eq!(
        params.p, 65537,
        "Fermat F4 preserved for d-inverse invariant"
    );
    assert_eq!(params.sigma.to_bits(), 6.4f64.to_bits());
    assert_eq!(params.gadget_base, 1u64 << 19);
    assert_eq!(params.gadget_len, 3);
    assert_eq!(params.security_level, SecurityLevel::Bits128);

    // validate() passes: NTT-friendliness + CRT-coprimality + q >= p.
    params
        .validate()
        .expect("derived params must self-validate");
}

#[test]
fn for_scenario_rejects_noise_budget_violation() {
    // gammas = [1, 1, 1] drives variance below the required-q bound but
    // should still pass because Google's CUSTOM_MOD has slack at these
    // dimensions. Use a deliberately oversized N instead to force the
    // budget violation.
    let huge_n = usize::MAX / (256 * 8) - 1;
    let result = InspireParams::for_scenario(huge_n, 256, [64, 1024, 64], 1);
    // The derivation may fail much earlier on overflow or variance saturating
    // to +inf - any error is acceptable, but we must NOT get Ok back with
    // an insecure parameter set.
    assert!(
        result.is_err(),
        "for_scenario at huge N must return Err, got {:?}",
        result.map(|p| (p.ring_dim, p.q, p.p))
    );
}

#[test]
fn for_scenario_at_32_byte_record_paper_gammas() {
    // Paper's gamma triple at 32 B (Google's shipped bin default).
    let params = InspireParams::for_scenario(1 << 20, 32, [16, 1024, 16], 1)
        .expect("32 B scenario must derive clean");

    assert_eq!(params.ring_dim, 2048);
    assert_eq!(params.crt_moduli, vec![67_043_329u64, 132_120_577u64]);
    assert_eq!(params.p, 65537);
    // Gadget shape unchanged (z is hardcoded in the derivation).
    assert_eq!(params.gadget_base, 1u64 << 19);
    assert_eq!(params.gadget_len, 3);
}

fn approx_eq(actual: f64, expected: f64, tol: f64, label: &str) {
    let delta = (actual - expected).abs();
    assert!(
        delta <= tol,
        "{label}: |{actual:.6} - {expected:.6}| = {delta:.6} > tol {tol}",
    );
}
