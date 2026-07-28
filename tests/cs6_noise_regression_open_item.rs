//! CS-6 empirical noise-budget regression: OPEN, NOT IMPLEMENTED.
//!
//! This file is the record of a gap. It deliberately contains no test.
//! Nothing here may be read as coverage.
//!
//! # What CS-6 asked for
//!
//! Encrypt random plaintexts, pack via InspiRING (`pack_inspiring`,
//! `src/inspiring/inspiring2.rs:1449`), measure `||e_pack||_inf`, and assert
//! it stays under the Theorem 4 packing-noise bound.
//!
//! # Status
//!
//! Not written. No test in this crate measures packing noise.
//!
//! # The claim this file replaces
//!
//! A previous revision closed CS-6 by asserting that `tests/e2e_pir.rs` runs
//! "11 tests at ring_dim in {256, 512, 1024, 2048} x record_bytes in
//! {8, 32, 128, 256}". Measured against the source, that is false on both
//! axes: all 11 tests build their parameters from one `test_params()` fixture
//! pinned to `ring_dim: 256` (`tests/e2e_pir.rs:14`), 2 of the 11 are
//! `#[ignore]`d (`tests/e2e_pir.rs:337` and `:410`), and the record widths
//! used are {2, 16, 32, 64}. Production runs at d = 2048, so the suite never
//! executes in the production regime. The multi-ring grid the claim described
//! exists, but in `tests/commit_e_two_crt_regression_grid.rs` and
//! `tests/two_crt_bisection.rs`, and it was misattributed.
//!
//! # Why byte-identity is not a substitute
//!
//! A byte-identity assertion fails only after noise exceeds `Delta/2 = q/(2p)`
//! and flips a byte. It is blind to margin narrowing: a change that consumes
//! most of the remaining budget while still decoding correctly passes every
//! existing suite unchanged. That margin is the quantity CS-6 exists to watch,
//! so the round-trip suites cannot stand in for it.
//!
//! # Why the test is not written here
//!
//! The assertion needs a bound to assert against. The only in-crate noise
//! model is `get_variance` (`src/params.rs:532`), which is private and carries
//! an unresolved correctness question of its own: a possibly missing
//! `(q_tilde / q)^2` factor against InsPIRe Theorem 7, documented in place at
//! `src/params.rs:510-530`, with a recorded slack of roughly 0.09 bits at
//! 2^20 x 256 B. Asserting a measured noise value against a bound whose
//! derivation is itself open would reproduce the failure this file corrects.
//! The bound is settled first; the measurement test follows it.
//!
//! # What closing CS-6 requires
//!
//! 1. Resolve the `(q_tilde / q)^2` question and fix the bound.
//! 2. Measure `||e_pack||_inf` at production parameters and at every cell
//!    shape in use, recording the observed margin rather than a pass or fail.
//! 3. Write a test that fails on a real noise regression, demonstrated by
//!    injecting one and watching it fail, not by inspection.
//!
//! Until all three land, CS-6 is open.
