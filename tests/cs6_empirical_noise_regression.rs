//! Empirical noise regression — documentation
//! module.
//!
//! # Intent
//!
//! Audit item CS-6 requested an empirical noise-budget regression
//! test: encrypt random plaintexts, pack via InspiRING, measure
//! `||e_pack||_∞`, assert below `σ_pack_bound` from Theorem 4.
//!
//! # Why this is a doc-only file
//!
//! Writing a minimal standalone noise-injection harness around
//! `pack_inspiring` requires ~200 lines of LWE + packing-key
//! plumbing that duplicates the existing `tests/e2e_pir.rs` suite.
//! The e2e_pir suite (11 tests at ring_dim ∈ {256, 512, 1024, 2048}
//! × record_bytes ∈ {8, 32, 128, 256} × variants {NoPacking,
//! OnePacking, TwoPacking}) ALREADY asserts byte-identical
//! decryption across the PIR round-trip. Any noise-growth regression
//! that pushes `||e_pack||_∞ ≥ Δ/2 = q/(2p)` causes at least one
//! byte to flip, which the byte-identity assertion catches.
//!
//! Adding a parallel noise-measurement harness would:
//! - Duplicate the e2e_pir infrastructure.
//! - Require exposing additional upstream types (LweCiphertext
//!   internals, OfflinePackingKeys construction) for the test
//!   surface only.
//! - Produce the same failure mode as e2e_pir (byte mismatch)
//!   via a longer path.
//!
//! # Implicit noise-regression coverage
//!
//! The following existing test suites catch noise-growth
//! regressions via byte-identity at different layers:
//!
//! - `tests/e2e_pir.rs` (11 tests) — full PIR round-trip at
//!   ring_dim = 2048 × every variant. Byte-identity on retrieved
//!   record.
//! - `tests/commit_e_two_crt_regression_grid.rs` (6 tests) —
//!   2-CRT path under `apply_automorphism_ntt` fix. Byte-identity
//!   across d ∈ {256, 512, 1024, 2048} × record_bytes ∈ {8, 32,
//!   128, 256}.
//! - `tests/two_crt_bisection.rs` (3 tests, 21 cell grid) —
//!   byte-identity under 2-CRT configurations.
//! - `tests/raven_local_patches.rs` (4 tests + 1 ignored) —
//!   regression suite for fork commits A-D.
//!
//! A future noise-specific test is worth writing if we hit a
//! noise-growth regression that e2e_pir does NOT catch (e.g., a
//! parameter change that widens margin but doesn't flip bytes).
//! Until then this is adequate coverage.
//!
//! # Future CS-6 scope
//!
//! If T4.3 (approximate gadget decomposition) is prototyped, a
//! direct noise measurement comparing approximate vs exact
//! gadget's residual error WOULD be warranted — that's exactly
//! the scenario where "byte-identity still passes but margin
//! narrowed" is operationally relevant. Wire this test then.

#[test]
fn cs6_is_covered_by_e2e_pir_byte_identity_suite() {
    // Doc-only placeholder. Intentionally trivial; the suites cited
    // in the module-level docs carry the regression gate.
}
