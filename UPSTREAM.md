# Upstream attribution

This crate is a Raven-local fork of `inspire-rs`
(https://github.com/igor53627/inspire-rs), licensed under MIT OR
Apache-2.0. Raven redistributes under Apache-2.0 per Raven's
framework-level license choice; no rights are waived on the original
upstream.

The fork was taken at the `inspire-rs` repository state as of
2026-04-21, with no upstream pulls between that date and the fork
snapshot (2026-04-28).

Raven-local patches applied in this fork (one commit each, fork-
relative history):

| # | File(s) | Fix |
|---|---|---|
| 1 | `src/pir/encode_db.rs` | Promote `debug_assert!(entries_per_shard <= ring_dim)` to a runtime typed error so release builds surface oversized ShardConfig instead of silently panicking inside `inverse_monomial`. |
| 2 | `src/pir/respond.rs` | `respond_with_variant(TwoPacking)` returns `Err(...)` directing callers to the seeded entry point instead of silently routing through OnePacking code. |
| 3 | `src/pir/extract.rs` | `extract_with_variant(TwoPacking)` routes to `extract_inspiring` when the response is InspiRING-shaped (peek format), matching the upstream binary pair at `bin/client.rs:302`. |
| 4 | `src/params.rs` | `secure_128_d{2048,4096}` constructors use the single-prime DEFAULT_Q form (q = 2^60 - 2^14 + 1) instead of the under-provisioned 2-CRT `[268369921, 249561089]`. |
| 5 | `src/inspiring/inspiring2.rs` | `apply_automorphism_ntt` + `apply_automorphism_ntt_into` + `apply_automorphism_ntt_double` apply the NTT permutation to EACH CRT limb independently. Pre-fork allocated a length-n buffer and iterated `0..n`, silently dropping the second CRT limb under 2-CRT storage (`n * crt_count` u64s). The bug caused decryption to return random-looking bytes at every cell d >= 256 under TwoPacking + InspiRING whenever any 2-CRT modulus was used. Upstream test coverage gap (`tests/e2e_pir.rs:408-462` only exercises single-prime `test_params`) meant the bug shipped unobserved. |

Raven-local additions (not upstream):

| File | Purpose |
|---|---|
| `src/pir/session.rs` | `ClientSession` cache that captures `PackParams` + `ClientPackingKeys` once per server session instead of regenerating on every `query` / `query_seeded` call. Plus `ServerSessionStore` + `ServerSessionHandle` for the packing-key pre-exchange handshake: client uploads keys once at session setup, subsequent queries reference the handle, dropping per-query wire bytes by the inlined-keys size (~48 KiB at d=2048 / 3 gadget digits). |
| `src/params.rs` adaptive derivation | `InspireParams::for_scenario` + `for_scenario_with_crt` port Google's `params_for_scenario_medium_payload` natively into the fork, with `p = 65537` Fermat-F4 preserved (Raven-local deviation from Google's `p = 65536`; see the noise-budget analysis for the rationale). Adaptive derivation is unblocked for measurement use after commit E resolves the 2-CRT bug. |

Upstream issue drafts corresponding to fixes 1–5 are tracked
internally. Raven's fork carries the fixes locally until (or if)
the upstream PRs land.
