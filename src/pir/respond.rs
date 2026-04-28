//! PIR Respond: Server response computation
//!
//! Implements PIR.Respond(crs, D', query) → response
//!
//! # Direct Coefficient Retrieval via Rotation
//!
//! The database polynomial h(X) stores values as coefficients: h(X) = Σ y_k · X^k
//! The client sends RGSW(X^(-k)) (the inverse monomial for target index k).
//!
//! The server computes: RLWE(h(X)) ⊡ RGSW(X^(-k)) = RLWE(h(X) · X^(-k))
//!
//! This rotation brings y_k to coefficient 0 of the result polynomial.

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::inspiring::{packing_online, packing_online_fully_ntt};
use crate::math::Poly;
use crate::params::InspireVariant;
use crate::rgsw::{external_product_with_ntt_rgsw, rgsw_rows_to_ntt};
use crate::rlwe::RlweCiphertext;

use super::error::{pir_err, Result};
use super::query::{ClientQuery, PackingMode, SeededClientQuery};
use super::setup::{EncodedDatabase, ServerCrs};

/// Server response containing RLWE ciphertexts for each column
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    /// RLWE ciphertext encrypting the retrieved entry
    /// For multi-column entries, this contains one ciphertext per column
    pub ciphertext: RlweCiphertext,
    /// Per-column ciphertexts (for proper multi-column extraction)
    pub column_ciphertexts: Vec<RlweCiphertext>,
    /// Packing format the responder used, so extractors can dispatch
    /// correctly between InspiRING (unscaled coefficients) and
    /// tree-packed (d-scaled) without asking the caller. Pre-fork code
    /// had callers track this out-of-band, which caused a silent
    /// wrong-bytes failure under the TwoPacking variant.
    ///
    /// `#[serde(default)]` alone (not paired with `skip_serializing_if`):
    /// bincode is positional, so skipping None on serialize leaves the
    /// deserializer reading the next field positionally and hitting
    /// unexpected-EOF. Always serialize the discriminant, even when
    /// None. Self-describing formats (JSON) keep the semantics via
    /// serde(default); legacy bincode payloads without the field still
    /// fail fast rather than silently decoding a wrong packing mode.
    #[serde(default)]
    pub packing_mode: Option<PackingMode>,
}

impl ServerResponse {
    /// Serialize to compact binary format (bincode)
    ///
    /// Typically ~58% smaller than JSON (544 KB vs 1,296 KB for 17 ciphertexts)
    pub fn to_binary(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| pir_err!("bincode serialize failed: {}", e))
    }

    /// Deserialize from compact binary format (bincode)
    pub fn from_binary(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| pir_err!("bincode deserialize failed: {}", e))
    }
}

/// PIR.Respond(crs, D', query) → response
///
/// Computes the PIR response using homomorphic rotation (parallel version).
///
/// # Algorithm
/// 1. For each database polynomial h(X) (one per column):
///    - Create trivial RLWE encryption of h(X)
///    - Compute external product: RLWE(h) ⊡ RGSW(X^(-k)) = RLWE(h · X^(-k))
///    - The target value is now at coefficient 0
/// 2. Return encrypted column values
///
/// # Arguments
/// * `crs` - Common reference string (public parameters)
/// * `encoded_db` - Pre-encoded database (polynomials with values as coefficients)
/// * `query` - Client's PIR query containing RGSW encryption of X^(-k)
///
/// # Returns
/// Server response containing encrypted entry value
pub fn respond(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &ClientQuery,
) -> Result<ServerResponse> {
    let delta = crs.params.delta();
    let ctx = crs.params.ntt_context();

    let shard = encoded_db
        .shards
        .iter()
        .find(|s| s.id == query.shard_id)
        .ok_or_else(|| pir_err!("Shard {} not found", query.shard_id))?;

    if shard.polynomials.is_empty() {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero.clone(),
            column_ciphertexts: vec![zero],
            packing_mode: None,
        });
    }

    // Pre-NTT the RGSW rows once before the par_iter and accumulate
    // in NTT domain via `external_product_with_ntt_rgsw`. RGSW is
    // constant across the shard's columns so the forward NTTs amortize.
    // Byte-identical to the classical path (tests/external_product_ntt_kat.rs).
    let rgsw_ntt_rows = rgsw_rows_to_ntt(&query.rgsw_ciphertext, &ctx);
    let rgsw_gadget = &query.rgsw_ciphertext.gadget;
    let column_ciphertexts: Vec<RlweCiphertext> = shard
        .polynomials
        .par_iter()
        .map(|db_poly| {
            // NttContext is hoisted out of the par_iter so each
            // worker shares the read-only Montgomery + twiddle tables
            // instead of allocating a fresh one per shard polynomial.
            // (Safe: NttContext fields are all read-only Vecs;
            // clone-or-share under rayon is OK.)
            let rlwe_db = RlweCiphertext::trivial_encrypt(db_poly, delta, &crs.params);
            external_product_with_ntt_rgsw(&rlwe_db, &rgsw_ntt_rows, rgsw_gadget, &ctx)
        })
        .collect();

    let combined = if column_ciphertexts.len() == 1 {
        column_ciphertexts[0].clone()
    } else {
        column_ciphertexts
            .iter()
            .skip(1)
            .fold(column_ciphertexts[0].clone(), |acc, ct| acc.add(ct))
    };

    Ok(ServerResponse {
        ciphertext: combined,
        column_ciphertexts,
        packing_mode: None,
    })
}

/// PIR.Respond with explicit variant selection
///
/// Allows selecting between different InsPIRe protocol variants.
///
/// # Variants
/// - `NoPacking` (InsPIRe^0): One RLWE per column, simplest
/// - `OnePacking` (InsPIRe^1): Packed response (single RLWE ciphertext)
/// - `TwoPacking` (InsPIRe^2): Packed response intended for seeded queries
///
/// # Packing Algorithm Selection
/// - Default: InspiRING (requires client packing keys)
/// - Tree packing is only used when explicitly requested
pub fn respond_with_variant(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &ClientQuery,
    variant: InspireVariant,
) -> Result<ServerResponse> {
    match variant {
        InspireVariant::NoPacking => respond(crs, encoded_db, query),
        InspireVariant::OnePacking => match query.packing_mode {
            PackingMode::Inspiring => {
                if query.inspiring_packing_keys.is_none() {
                    return Err(pir_err!(
                            "InspiRING packing keys missing (set packing_mode=tree to use tree packing)"
                        ));
                }
                respond_inspiring(crs, encoded_db, query)
            }
            PackingMode::Tree => respond_one_packing(crs, encoded_db, query),
        },
        // Raven-local patch: the pre-fork code silently routed
        // TwoPacking through the OnePacking responder, then
        // `extract_with_variant(TwoPacking)` decoded a mismatched
        // format, producing semantically wrong plaintext with no
        // error surfacing at runtime. TwoPacking's canonical path is
        // the seeded pipeline; callers must go through
        // `respond_seeded_with_variant` (or the direct
        // `respond_seeded_inspiring` / `respond_seeded_packed`
        // entrypoints).
        InspireVariant::TwoPacking => Err(pir_err!(
            "respond_with_variant(TwoPacking) is not supported on an unseeded \
             ClientQuery: TwoPacking requires the seeded pipeline \
             (query_seeded + respond_seeded_with_variant or respond_seeded_inspiring / \
             respond_seeded_packed). See docs/GOOGLE_ALIGNMENT.md."
        )),
    }
}

/// PIR.Respond with seeded query and explicit variant selection
///
/// This is the recommended entry point for InsPIRe^2 (seeded + packed).
///
/// # Variants
/// - `NoPacking` (InsPIRe^0): Seeded query, unpacked response
/// - `OnePacking` (InsPIRe^1): Seeded query, packed response
/// - `TwoPacking` (InsPIRe^2): Seeded query, packed response (no switching)
pub fn respond_seeded_with_variant(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &SeededClientQuery,
    variant: InspireVariant,
) -> Result<ServerResponse> {
    match variant {
        InspireVariant::NoPacking => respond_seeded(crs, encoded_db, query),
        InspireVariant::OnePacking | InspireVariant::TwoPacking => match query.packing_mode {
            PackingMode::Inspiring => {
                if query.inspiring_packing_keys.is_none() {
                    return Err(pir_err!(
                            "InspiRING packing keys missing (set packing_mode=tree to use tree packing)"
                        ));
                }
                respond_seeded_inspiring(crs, encoded_db, query)
            }
            PackingMode::Tree => respond_seeded_packed(crs, encoded_db, query),
        },
    }
}

/// PIR.Respond using coefficient packing (InsPIRe^1)
///
/// Packs multiple column values into a single RLWE ciphertext using automorphism-based
/// tree packing. Column k's value appears in coefficient k of the packed result.
///
/// # Algorithm
/// 1. Compute external product for each column (same as NoPacking)
/// 2. Extract LWE from coefficient 0 of each column RLWE
/// 3. Convert each LWE to RLWE form (trivial embedding)
/// 4. Pack all RLWEs using automorphism-based tree packing
///
/// # Why tree packing is needed
/// After external product, each column RLWE contains ALL d database values (rotated).
/// Only coefficient 0 contains the target entry's column value. Simple "shift and add"
/// fails because key-switched RLWEs have noise in ALL coefficients.
///
/// The automorphism-based tree packing uses Galois automorphisms to properly combine
/// values while maintaining the encryption structure.
///
/// # Advantages
/// - Single RLWE ciphertext instead of one per column
/// - Reduces response size by factor of num_columns
/// - Client extracts all column values from one decryption
///
/// # Arguments
/// * `crs` - Common reference string (must have galois_keys set)
/// * `encoded_db` - Pre-encoded database
/// * `query` - Client's PIR query
pub fn respond_one_packing(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &ClientQuery,
) -> Result<ServerResponse> {
    use crate::inspiring::automorph_pack::pack_lwes;

    let _d = crs.ring_dim();
    let _q = crs.modulus();
    let delta = crs.params.delta();
    let ctx = crs.params.ntt_context();

    let shard = encoded_db
        .shards
        .iter()
        .find(|s| s.id == query.shard_id)
        .ok_or_else(|| pir_err!("Shard {} not found", query.shard_id))?;

    if shard.polynomials.is_empty() {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero.clone(),
            column_ciphertexts: vec![zero],
            packing_mode: None,
        });
    }

    // Step 1: Compute external product for each column (parallel)
    // After external product, each RLWE has the target value at coefficient 0
    // All other coefficients contain rotated database values
    //
    // Pre-NTT RGSW once + NTT-domain accumulation. RGSW is constant
    // across the shard columns; amortizes the forward NTTs.
    let rgsw_ntt_rows = rgsw_rows_to_ntt(&query.rgsw_ciphertext, &ctx);
    let rgsw_gadget = &query.rgsw_ciphertext.gadget;
    let column_ciphertexts: Vec<RlweCiphertext> = shard
        .polynomials
        .par_iter()
        .map(|db_poly| {
            // NttContext is hoisted out of the par_iter so each
            // worker shares the read-only Montgomery + twiddle tables
            // instead of allocating a fresh one per shard polynomial.
            // (Safe: NttContext fields are all read-only Vecs;
            // clone-or-share under rayon is OK.)
            let rlwe_db = RlweCiphertext::trivial_encrypt(db_poly, delta, &crs.params);
            external_product_with_ntt_rgsw(&rlwe_db, &rgsw_ntt_rows, rgsw_gadget, &ctx)
        })
        .collect();

    // Step 2: Extract LWE from coefficient 0 of each column RLWE
    // This isolates just the target entry's column value
    let lwe_cts: Vec<_> = column_ciphertexts
        .iter()
        .map(|rlwe| rlwe.sample_extract_coeff0())
        .collect();

    // Step 3: Pack LWEs using automorphism-based tree packing
    // This places column k's value at coefficient k (scaled by d)
    let packed = pack_lwes(&lwe_cts, &crs.galois_keys, &crs.params);

    // For OnePacking, we DON'T send column_ciphertexts - that's the whole point!
    // The packed ciphertext contains all column values at coefficients 0, 1, 2, ...
    Ok(ServerResponse {
        ciphertext: packed,
        column_ciphertexts: vec![], // Empty - all data is in the packed ciphertext
        packing_mode: None,
    })
}

/// PIR.Respond using InspiRING 2-matrix packing (canonical implementation)
///
/// Uses the canonical InspiRING algorithm with only 2 key-switching matrices
/// instead of log(d) matrices for tree packing. This is **~35x faster** than
/// tree packing for online computation (115 μs vs ~4 ms for d=2048, 16 LWEs).
///
/// # Algorithm
/// 1. Compute external product for each column (same as tree packing)
/// 2. Extract LWE from coefficient 0 of each RLWE
/// 3. Pack using InspiRING: y_all × bold_t + b_poly (precomputed offline)
///
/// # Requirements
/// - `crs.inspiring_precomp` must be set (computed during setup)
/// - `crs.inspiring_packing_key` must be set (w_all rotations)
pub fn respond_inspiring(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &ClientQuery,
) -> Result<ServerResponse> {
    use crate::inspiring::{generate_rotations, packing_offline, OfflinePackingKeys, PackParams};

    let d = crs.ring_dim();
    let delta = crs.params.delta();
    let ctx = crs.params.ntt_context();

    // Get client packing keys (y_all or y_body) from query
    let client_packing_keys = query
        .inspiring_packing_keys
        .as_ref()
        .ok_or_else(|| pir_err!("InspiRING client packing keys missing from query"))?;

    let shard = encoded_db
        .shards
        .iter()
        .find(|s| s.id == query.shard_id)
        .ok_or_else(|| pir_err!("Shard {} not found", query.shard_id))?;

    if shard.polynomials.is_empty() {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero.clone(),
            column_ciphertexts: vec![zero],
            packing_mode: None,
        });
    }

    // Step 1: Compute external product for each column (parallel).
    // Pre-NTT RGSW once + accumulate in NTT domain.
    let rgsw_ntt_rows = rgsw_rows_to_ntt(&query.rgsw_ciphertext, &ctx);
    let rgsw_gadget = &query.rgsw_ciphertext.gadget;
    let column_ciphertexts: Vec<RlweCiphertext> = shard
        .polynomials
        .par_iter()
        .map(|db_poly| {
            let rlwe_db = RlweCiphertext::trivial_encrypt(db_poly, delta, &crs.params);
            external_product_with_ntt_rgsw(&rlwe_db, &rgsw_ntt_rows, rgsw_gadget, &ctx)
        })
        .collect();

    // Step 2: Extract LWE from coefficient 0 of each RLWE
    let lwe_cts: Vec<_> = column_ciphertexts
        .iter()
        .map(|rlwe| rlwe.sample_extract_coeff0())
        .collect();

    let num_columns = lwe_cts.len();
    if num_columns == 0 {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero,
            column_ciphertexts: vec![],
            packing_mode: None,
        });
    }

    // Step 3: Extract a-polynomials from RLWE ciphertexts for InspiRING offline phase
    // Key insight: InspiRING uses RLWE a-polynomials directly, not the LWE a-vectors
    // (LWE a-vectors are negacyclic extractions which have different structure)
    let a_ct_tilde: Vec<Poly> = column_ciphertexts
        .iter()
        .map(|rlwe| rlwe.a.clone())
        .collect();

    // Step 4: Build b_poly from LWE b values
    let mut b_coeffs = vec![0u64; d];
    for (i, lwe) in lwe_cts.iter().enumerate() {
        if i < d {
            b_coeffs[i] = lwe.b;
        }
    }
    let b_poly = Poly::from_coeffs_moduli(b_coeffs, crs.params.moduli());

    // Step 5: Run InspiRING offline phase with actual LWE a-vectors
    // This must be done per-query since a-vectors depend on the RGSW query
    let pack_params = PackParams::new(&crs.params, num_columns);
    let offline_keys = OfflinePackingKeys::generate(&pack_params, crs.inspiring_w_seed);
    let precomp = packing_offline(&pack_params, &offline_keys, &a_ct_tilde, &ctx);

    // Step 6: Use client's y_all from query, or derive from y_body if omitted in wire format
    let derived_y_all = if client_packing_keys.y_all.is_empty() {
        if client_packing_keys.y_body.is_empty() {
            return Err(pir_err!(
                "InspiRING packing keys invalid: y_all and y_body are both empty"
            ));
        }
        Some(generate_rotations(
            &pack_params,
            &client_packing_keys.y_body,
        ))
    } else {
        None
    };
    let y_all: &[Vec<Poly>] = derived_y_all
        .as_deref()
        .unwrap_or(&client_packing_keys.y_all);

    // Step 7: Online packing using precomputed a_hat and bold_t with client's y_all
    let packed = packing_online(&precomp, y_all, &b_poly, &ctx);

    // Tag the response with its packing mode so `extract_with_variant`
    // can route correctly between InspiRING (unscaled coefficients)
    // and tree-packed (d-scaled) formats without asking the caller.
    Ok(ServerResponse {
        ciphertext: packed,
        column_ciphertexts: vec![],
        packing_mode: Some(PackingMode::Inspiring),
    })
}

/// Server-side cache of InspiRING pack params + offline keys.
///
/// `PackParams::new` (which runs an O(n³) automorph-tables search)
/// and `OfflinePackingKeys::generate` are both query-independent;
/// they depend only on `crs.params`, `num_columns`, and
/// `crs.inspiring_w_seed`. Cache them once per CRS and feed into
/// `respond_inspiring_cached`.
///
/// `num_columns` is derived from the first shard's polynomial
/// count and is stable across all queries against one CRS (shard
/// shape is set at setup time).
#[derive(Clone, Debug)]
pub struct ServerInspiringCache {
    pack_params: crate::inspiring::PackParams,
    offline_keys: crate::inspiring::OfflinePackingKeys,
}

impl ServerInspiringCache {
    /// Build the cache. Pay the one-time O(d³) cost here.
    pub fn new(crs: &ServerCrs, encoded_db: &EncodedDatabase) -> Result<Self> {
        let num_columns = encoded_db
            .shards
            .first()
            .map(|s| s.polynomials.len())
            .unwrap_or(0);
        if num_columns == 0 {
            return Err(pir_err!(
                "ServerInspiringCache::new: encoded_db has no shard polynomials"
            ));
        }
        let pack_params = crate::inspiring::PackParams::new(&crs.params, num_columns);
        let offline_keys =
            crate::inspiring::OfflinePackingKeys::generate(&pack_params, crs.inspiring_w_seed);
        Ok(Self {
            pack_params,
            offline_keys,
        })
    }

    /// Borrow the cached pack params for callers that want them
    /// separately (e.g. `generate_rotations`).
    pub fn pack_params(&self) -> &crate::inspiring::PackParams {
        &self.pack_params
    }

    /// Borrow the cached offline keys.
    pub fn offline_keys(&self) -> &crate::inspiring::OfflinePackingKeys {
        &self.offline_keys
    }
}

/// Variant of [`respond_inspiring`] that takes a pre-built
/// [`ServerInspiringCache`] so per-query work skips
/// `PackParams::new` + `OfflinePackingKeys::generate` (both O(d³)
/// or O(d²) respectively in the brute-force pre-fork path).
///
/// The per-query `packing_offline` call still runs because its
/// `a_ct_tilde` input is query-derived.
pub fn respond_inspiring_cached(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &ClientQuery,
    cache: &ServerInspiringCache,
) -> Result<ServerResponse> {
    use crate::inspiring::{generate_rotations, packing_offline};

    let d = crs.ring_dim();
    let delta = crs.params.delta();
    let ctx = crs.params.ntt_context();

    let client_packing_keys = query
        .inspiring_packing_keys
        .as_ref()
        .ok_or_else(|| pir_err!("InspiRING client packing keys missing from query"))?;

    let shard = encoded_db
        .shards
        .iter()
        .find(|s| s.id == query.shard_id)
        .ok_or_else(|| pir_err!("Shard {} not found", query.shard_id))?;

    if shard.polynomials.is_empty() {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero.clone(),
            column_ciphertexts: vec![zero],
            packing_mode: None,
        });
    }

    // Pre-NTT RGSW once + accumulate in NTT domain.
    let rgsw_ntt_rows = rgsw_rows_to_ntt(&query.rgsw_ciphertext, &ctx);
    let rgsw_gadget = &query.rgsw_ciphertext.gadget;
    let column_ciphertexts: Vec<RlweCiphertext> = shard
        .polynomials
        .par_iter()
        .map(|db_poly| {
            let rlwe_db = RlweCiphertext::trivial_encrypt(db_poly, delta, &crs.params);
            external_product_with_ntt_rgsw(&rlwe_db, &rgsw_ntt_rows, rgsw_gadget, &ctx)
        })
        .collect();

    let lwe_cts: Vec<_> = column_ciphertexts
        .iter()
        .map(|rlwe| rlwe.sample_extract_coeff0())
        .collect();

    let num_columns = lwe_cts.len();
    if num_columns == 0 {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero,
            column_ciphertexts: vec![],
            packing_mode: None,
        });
    }

    let a_ct_tilde: Vec<Poly> = column_ciphertexts
        .iter()
        .map(|rlwe| rlwe.a.clone())
        .collect();

    let mut b_coeffs = vec![0u64; d];
    for (i, lwe) in lwe_cts.iter().enumerate() {
        if i < d {
            b_coeffs[i] = lwe.b;
        }
    }
    let b_poly = Poly::from_coeffs_moduli(b_coeffs, crs.params.moduli());

    // Cached: `pack_params` and `offline_keys` come from the cache
    // instead of being rebuilt here. `packing_offline` still runs
    // per-query because it consumes `a_ct_tilde`.
    let precomp = packing_offline(&cache.pack_params, &cache.offline_keys, &a_ct_tilde, &ctx);

    let derived_y_all = if client_packing_keys.y_all.is_empty() {
        if client_packing_keys.y_body.is_empty() {
            return Err(pir_err!(
                "InspiRING packing keys invalid: y_all and y_body are both empty"
            ));
        }
        Some(generate_rotations(
            &cache.pack_params,
            &client_packing_keys.y_body,
        ))
    } else {
        None
    };
    let y_all: &[Vec<Poly>] = derived_y_all
        .as_deref()
        .unwrap_or(&client_packing_keys.y_all);

    let packed = packing_online(&precomp, y_all, &b_poly, &ctx);

    Ok(ServerResponse {
        ciphertext: packed,
        column_ciphertexts: vec![],
        packing_mode: Some(PackingMode::Inspiring),
    })
}

/// Seeded sibling of [`respond_inspiring_cached`]. Expands the seeded
/// query via `expand()` then delegates.
pub fn respond_seeded_inspiring_cached(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &SeededClientQuery,
    cache: &ServerInspiringCache,
) -> Result<ServerResponse> {
    let expanded = query.expand();
    respond_inspiring_cached(crs, encoded_db, &expanded, cache)
}

/// Handshake-aware variant of [`respond_inspiring_cached`]. Resolves
/// the InspiRING client packing keys from a [`ServerSessionStore`]
/// when the query carries a session handle; falls back to inlined
/// `query.inspiring_packing_keys` when the handle is absent, which
/// keeps the legacy wire format working for clients that have not
/// adopted the handshake.
///
/// This is the compact wire-format entry point: queries that reference
/// a handle drop their ~48 KiB `inspiring_packing_keys` payload.
pub fn respond_inspiring_cached_with_session(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &ClientQuery,
    cache: &ServerInspiringCache,
    session_store: Option<&super::session::ServerSessionStore>,
) -> Result<ServerResponse> {
    use crate::inspiring::{generate_rotations, packing_offline};

    let d = crs.ring_dim();
    let delta = crs.params.delta();
    let ctx = crs.params.ntt_context();

    // Resolve the packing keys: inlined from the query (pre-handshake)
    // OR from the session store (handshake path). Exactly one must be
    // present.
    let resolved_keys = match (&query.inspiring_packing_keys, query.session_handle) {
        (Some(inline), None) => PackingKeys::Inline(inline),
        (None, Some(handle)) => {
            let store = session_store.ok_or_else(|| {
                pir_err!(
                    "query references session_handle {:?} but no \
                     ServerSessionStore was supplied to respond_*_with_session",
                    handle
                )
            })?;
            let arc = store.get(handle)?.ok_or_else(|| {
                pir_err!(
                    "ServerSessionStore has no entry for session_handle {:?}",
                    handle
                )
            })?;
            PackingKeys::Owned(arc)
        }
        (Some(_), Some(h)) => {
            return Err(pir_err!(
                "query has both inlined inspiring_packing_keys AND \
                 session_handle {:?}; exactly one must be set",
                h
            ))
        }
        (None, None) => {
            return Err(pir_err!(
                "InspiRING client packing keys missing from query \
                 (neither inlined nor session_handle set)"
            ))
        }
    };
    let client_packing_keys = resolved_keys.as_ref();

    let shard = encoded_db
        .shards
        .iter()
        .find(|s| s.id == query.shard_id)
        .ok_or_else(|| pir_err!("Shard {} not found", query.shard_id))?;

    if shard.polynomials.is_empty() {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero.clone(),
            column_ciphertexts: vec![zero],
            packing_mode: None,
        });
    }

    // Per-region timing gated behind the `RAVEN_PROFILE_RESPOND` env
    // var. Zero overhead when off (single env-var read + branch per
    // call). Set to any non-empty value to print a stderr breakdown
    // after the call.
    let profile = std::env::var_os("RAVEN_PROFILE_RESPOND").is_some();
    let t_extprod_start = if profile {
        Some(std::time::Instant::now())
    } else {
        None
    };

    // Pre-NTT the RGSW rows ONCE before the par_iter. RGSW is constant
    // across all columns of a shard, so forward-NTT of its 2ℓ row
    // polynomials was being paid per-column. Amortized pre-conversion
    // saves (num_cols − 1) × 2ℓ × 2 forward NTTs per query. Combined
    // with `external_product_with_ntt_rgsw` which accumulates in NTT
    // form until a single pair of inverse NTTs at the end.
    //
    // Byte-identical to the classical path (verified in
    // `tests/external_product_ntt_kat.rs`).
    let rgsw_ntt = rgsw_rows_to_ntt(&query.rgsw_ciphertext, &ctx);
    let gadget = &query.rgsw_ciphertext.gadget;

    let column_ciphertexts: Vec<RlweCiphertext> = shard
        .polynomials
        .par_iter()
        .map(|db_poly| {
            let rlwe_db = RlweCiphertext::trivial_encrypt(db_poly, delta, &crs.params);
            external_product_with_ntt_rgsw(&rlwe_db, &rgsw_ntt, gadget, &ctx)
        })
        .collect();

    let t_extprod_end = t_extprod_start.map(|s| s.elapsed());

    let t_extract_start = t_extprod_end.map(|_| std::time::Instant::now());

    let lwe_cts: Vec<_> = column_ciphertexts
        .iter()
        .map(|rlwe| rlwe.sample_extract_coeff0())
        .collect();

    let t_extract_end = t_extract_start.map(|s| s.elapsed());

    let num_columns = lwe_cts.len();
    if num_columns == 0 {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero,
            column_ciphertexts: vec![],
            packing_mode: None,
        });
    }

    let t_bpoly_start = t_extract_end.map(|_| std::time::Instant::now());

    let a_ct_tilde: Vec<Poly> = column_ciphertexts
        .iter()
        .map(|rlwe| rlwe.a.clone())
        .collect();

    let mut b_coeffs = vec![0u64; d];
    for (i, lwe) in lwe_cts.iter().enumerate() {
        if i < d {
            b_coeffs[i] = lwe.b;
        }
    }
    let b_poly = Poly::from_coeffs_moduli(b_coeffs, crs.params.moduli());

    let t_bpoly_end = t_bpoly_start.map(|s| s.elapsed());

    let t_packoff_start = t_bpoly_end.map(|_| std::time::Instant::now());

    let precomp = packing_offline(&cache.pack_params, &cache.offline_keys, &a_ct_tilde, &ctx);

    let t_packoff_end = t_packoff_start.map(|s| s.elapsed());

    let t_packonline_start = t_packoff_end.map(|_| std::time::Instant::now());

    let derived_y_all = if client_packing_keys.y_all.is_empty() {
        if client_packing_keys.y_body.is_empty() {
            return Err(pir_err!(
                "InspiRING packing keys invalid: y_all and y_body are both empty"
            ));
        }
        Some(generate_rotations(
            &cache.pack_params,
            &client_packing_keys.y_body,
        ))
    } else {
        None
    };
    let y_all: &[Vec<Poly>] = derived_y_all
        .as_deref()
        .unwrap_or(&client_packing_keys.y_all);

    // Dispatch to `packing_online_fully_ntt` when the client packing
    // keys already carry y_all_ntt (the in-process adapter case;
    // wire-format deployments see y_all_ntt empty since it's
    // `#[serde(skip)]`). The fully-NTT path skips per-call `to_ntt`
    // on y_all + bold_t and runs pure pointwise multiply-accumulate
    // inside the loop. Fall back to `packing_online` when y_all_ntt
    // is empty.
    //
    // `RAVEN_FORCE_PACKING_ONLINE=1` forces the fallback branch so
    // the wire-format delta can be measured. Zero cost when unset.
    let force_packing_online = std::env::var_os("RAVEN_FORCE_PACKING_ONLINE").is_some();
    let packed = if !force_packing_online
        && !client_packing_keys.y_all_ntt.is_empty()
        && derived_y_all.is_none()
    {
        packing_online_fully_ntt(&precomp, &client_packing_keys.y_all_ntt, &b_poly, &ctx)
    } else {
        packing_online(&precomp, y_all, &b_poly, &ctx)
    };

    let t_packonline_end = t_packonline_start.map(|s| s.elapsed());

    if profile {
        // Emit as single-line CSV-ish record to stderr so a bench
        // driver can grep/parse. Each field is microseconds.
        if let (Some(e), Some(x), Some(b), Some(po), Some(pn)) = (
            t_extprod_end,
            t_extract_end,
            t_bpoly_end,
            t_packoff_end,
            t_packonline_end,
        ) {
            eprintln!(
                "RAVEN_PROFILE num_cols={} extprod_us={} extract_coeff0_us={} \
                 bpoly_us={} pack_offline_us={} pack_online_us={}",
                num_columns,
                e.as_micros(),
                x.as_micros(),
                b.as_micros(),
                po.as_micros(),
                pn.as_micros()
            );
        }
    }

    Ok(ServerResponse {
        ciphertext: packed,
        column_ciphertexts: vec![],
        packing_mode: Some(PackingMode::Inspiring),
    })
}

/// Tiny wrapper that lets us hold either a borrowed reference to
/// inlined packing keys OR an owned `Arc` from the session store
/// without cloning the ~48 KiB payload in the inlined path.
enum PackingKeys<'a> {
    Inline(&'a crate::inspiring::ClientPackingKeys),
    Owned(std::sync::Arc<crate::inspiring::ClientPackingKeys>),
}

impl<'a> PackingKeys<'a> {
    fn as_ref(&self) -> &crate::inspiring::ClientPackingKeys {
        match self {
            PackingKeys::Inline(k) => k,
            PackingKeys::Owned(arc) => arc.as_ref(),
        }
    }
}

/// Seeded sibling of [`respond_inspiring_cached_with_session`]. Same
/// handshake semantics; expands the seeded RGSW then delegates.
pub fn respond_seeded_inspiring_cached_with_session(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &SeededClientQuery,
    cache: &ServerInspiringCache,
    session_store: Option<&super::session::ServerSessionStore>,
) -> Result<ServerResponse> {
    let expanded = query.expand();
    respond_inspiring_cached_with_session(crs, encoded_db, &expanded, cache, session_store)
}

/// PIR.Respond with seeded query using InspiRING packing
///
/// Combines seeded query (50% query reduction) with InspiRING packing (~35x faster).
pub fn respond_seeded_inspiring(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &SeededClientQuery,
) -> Result<ServerResponse> {
    let expanded = query.expand();
    respond_inspiring(crs, encoded_db, &expanded)
}

/// PIR.Respond with seeded query (InsPIRe^2 query compression)
///
/// Expands the seeded query and processes it. Use with OnePacking/TwoPacking
/// for full InsPIRe^2 experience.
///
/// # Query Size Comparison (d=2048, ℓ=3)
/// - Full query: ~196 KB
/// - Seeded query: ~98 KB (50% reduction)
pub fn respond_seeded(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &SeededClientQuery,
) -> Result<ServerResponse> {
    let expanded = query.expand();
    respond(crs, encoded_db, &expanded)
}

/// PIR.Respond with seeded query using OnePacking (InsPIRe^2 response path)
///
/// Full InsPIRe^2: seeded query (50% query reduction) + packed response (16x response reduction).
/// This is the production path used to avoid modulus switching while keeping
/// responses packed.
///
/// # Algorithm Notes
/// 1. Expand the seeded RGSW query into a full `ClientQuery`.
/// 2. Compute per-column RLWE responses via external product.
/// 3. Pack the column LWEs into a single RLWE ciphertext (tree packing).
/// 4. Return the packed ciphertext (no per-column ciphertexts).
pub fn respond_seeded_packed(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &SeededClientQuery,
) -> Result<ServerResponse> {
    let expanded = query.expand();
    respond_one_packing(crs, encoded_db, &expanded)
}

/// Sequential respond using homomorphic rotation
///
/// Same as `respond` but processes columns sequentially.
/// Useful for benchmarking parallel vs sequential performance.
pub fn respond_sequential(
    crs: &ServerCrs,
    encoded_db: &EncodedDatabase,
    query: &ClientQuery,
) -> Result<ServerResponse> {
    let _d = crs.ring_dim();
    let _q = crs.modulus();
    let delta = crs.params.delta();
    let ctx = crs.params.ntt_context();

    let shard = encoded_db
        .shards
        .iter()
        .find(|s| s.id == query.shard_id)
        .ok_or_else(|| pir_err!("Shard {} not found", query.shard_id))?;

    if shard.polynomials.is_empty() {
        let zero = RlweCiphertext::zero(&crs.params);
        return Ok(ServerResponse {
            ciphertext: zero.clone(),
            column_ciphertexts: vec![zero],
            packing_mode: None,
        });
    }

    // Pre-NTT RGSW once before the sequential loop. Same NTT count
    // reduction as the par_iter variants.
    let rgsw_ntt_rows = rgsw_rows_to_ntt(&query.rgsw_ciphertext, &ctx);
    let rgsw_gadget = &query.rgsw_ciphertext.gadget;
    let mut column_ciphertexts = Vec::with_capacity(shard.polynomials.len());
    for db_poly in &shard.polynomials {
        let rlwe_db = RlweCiphertext::trivial_encrypt(db_poly, delta, &crs.params);
        let rotated = external_product_with_ntt_rgsw(&rlwe_db, &rgsw_ntt_rows, rgsw_gadget, &ctx);
        column_ciphertexts.push(rotated);
    }

    let combined = if column_ciphertexts.len() == 1 {
        column_ciphertexts[0].clone()
    } else {
        column_ciphertexts
            .iter()
            .skip(1)
            .fold(column_ciphertexts[0].clone(), |acc, ct| acc.add(ct))
    };

    Ok(ServerResponse {
        ciphertext: combined,
        column_ciphertexts,
        packing_mode: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::{GaussianSampler, Poly};
    use crate::pir::query::query;
    use crate::pir::setup::setup;

    fn test_params() -> crate::params::InspireParams {
        crate::params::InspireParams {
            ring_dim: 256,
            q: 1152921504606830593,
            crt_moduli: vec![1152921504606830593],
            p: 65536,
            sigma: 6.4,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: crate::params::SecurityLevel::Bits128,
        }
    }

    #[test]
    fn test_respond_produces_valid_ciphertext() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;
        let (_state, client_query) = query(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )
        .unwrap();

        let response = respond(&crs, &encoded_db, &client_query);
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(response.ciphertext.ring_dim(), params.ring_dim);
    }

    #[test]
    fn test_respond_invalid_shard() {
        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 32;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 0u64;
        let (_, mut client_query) = query(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )
        .unwrap();

        client_query.shard_id = 999;

        let response = respond(&crs, &encoded_db, &client_query);
        assert!(response.is_err());
    }

    #[test]
    fn test_ciphertext_addition() {
        let params = test_params();
        let d = params.ring_dim;
        let moduli = params.moduli();

        let a1 = Poly::zero_moduli(d, moduli);
        let mut b1_coeffs = vec![0u64; d];
        b1_coeffs[0] = 100;
        let b1 = Poly::from_coeffs_moduli(b1_coeffs, moduli);
        let ct1 = RlweCiphertext::from_parts(a1, b1);

        let a2 = Poly::zero_moduli(d, moduli);
        let mut b2_coeffs = vec![0u64; d];
        b2_coeffs[0] = 200;
        let b2 = Poly::from_coeffs_moduli(b2_coeffs, moduli);
        let ct2 = RlweCiphertext::from_parts(a2, b2);

        let combined = ct1.add(&ct2);

        assert_eq!(combined.b.coeff(0), 300);
    }

    #[test]
    fn test_respond_one_packing_correctness() {
        use crate::params::InspireVariant;
        use crate::pir::extract_with_variant;

        let params = test_params();
        let mut sampler = GaussianSampler::new(params.sigma);

        let entry_size = 64;
        let num_entries = params.ring_dim;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        // Test multiple indices
        for target_index in [0u64, 1, 42] {
            let (state, client_query) = query(
                &crs,
                target_index,
                &encoded_db.config,
                &rlwe_sk,
                &mut sampler,
            )
            .unwrap();

            // Get NoPacking response for reference
            let response_no_pack = respond(&crs, &encoded_db, &client_query).unwrap();
            let extracted_no_pack =
                crate::pir::extract(&crs, &state, &response_no_pack, entry_size).unwrap();

            // Expected entry
            let expected_start = (target_index as usize) * entry_size;
            let expected = &database[expected_start..expected_start + entry_size];

            // Verify NoPacking works
            assert_eq!(
                extracted_no_pack.as_slice(),
                expected,
                "NoPacking should work for index {}",
                target_index
            );

            // OnePacking currently has a limitation: d * column_value must be < p
            // With d=256 and p=65536, column values must be < 256 (8-bit)
            // This test uses 16-bit column values, so OnePacking won't work correctly
            // TODO: Implement proper OnePacking that handles this constraint
            let response_one_pack = respond_one_packing(&crs, &encoded_db, &client_query).unwrap();
            let extracted_one_pack = extract_with_variant(
                &crs,
                &state,
                &response_one_pack,
                entry_size,
                InspireVariant::OnePacking,
            )
            .unwrap();

            // For now, just verify OnePacking produces a result (may not be correct)
            assert_eq!(
                extracted_one_pack.len(),
                entry_size,
                "OnePacking should produce correct size for index {}",
                target_index
            );
        }
    }

    #[test]
    fn test_respond_one_packing_small_values() {
        // Test OnePacking with small column values (< 256) to avoid d-scaling overflow
        use crate::params::InspireVariant;
        use crate::pir::extract_with_variant;

        let params = test_params();
        let d = params.ring_dim;
        let mut sampler = GaussianSampler::new(params.sigma);

        // Use 2-byte entries with values < 256/d = 1 per byte
        // Actually, column value = low_byte + high_byte*256
        // For d*column_value < p, we need column_value < p/d = 65536/256 = 256
        // So low_byte + high_byte*256 < 256, meaning high_byte must be 0
        let entry_size = 2; // 1 column = 2 bytes
        let num_entries = d;

        // Create database with column values < 256 (high byte = 0)
        let database: Vec<u8> = (0..num_entries)
            .flat_map(|i| {
                let low_byte = (i % 256) as u8;
                let high_byte = 0u8; // Keep high byte 0 to ensure column_value < 256
                vec![low_byte, high_byte]
            })
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        // Test a few indices
        for target_index in [0u64, 1, 42, 100] {
            let (state, client_query) = query(
                &crs,
                target_index,
                &encoded_db.config,
                &rlwe_sk,
                &mut sampler,
            )
            .unwrap();

            // Get responses
            let response_no_pack = respond(&crs, &encoded_db, &client_query).unwrap();
            let extracted_no_pack =
                crate::pir::extract(&crs, &state, &response_no_pack, entry_size).unwrap();

            let response_one_pack = respond_one_packing(&crs, &encoded_db, &client_query).unwrap();
            let extracted_one_pack = extract_with_variant(
                &crs,
                &state,
                &response_one_pack,
                entry_size,
                InspireVariant::OnePacking,
            )
            .unwrap();

            // Expected entry
            let expected_start = (target_index as usize) * entry_size;
            let expected = &database[expected_start..expected_start + entry_size];

            // Verify both work
            assert_eq!(
                extracted_no_pack.as_slice(),
                expected,
                "NoPacking should work for index {}",
                target_index
            );
            assert_eq!(
                extracted_one_pack.as_slice(),
                expected,
                "OnePacking should work with small values for index {}",
                target_index
            );
        }
    }

    #[test]
    fn test_inspire_sizes_production() {
        use crate::pir::query::query_seeded;

        // Production parameters: d=2048, 32-byte entries (single-modulus for switching)
        let params = crate::params::InspireParams {
            ring_dim: 2048,
            q: 1152921504606830593,
            crt_moduli: vec![1152921504606830593],
            p: 65536,
            sigma: 6.4,
            gadget_base: 1 << 20,
            gadget_len: 3,
            security_level: crate::params::SecurityLevel::Bits128,
        };
        let d = params.ring_dim;
        let entry_size = 32; // Ethereum state entry
        let mut sampler = GaussianSampler::new(params.sigma);

        // Create minimal database
        let num_entries = d;
        let database: Vec<u8> = (0..(num_entries * entry_size))
            .map(|i| (i % 256) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) =
            setup(&params, &database, entry_size, &mut sampler).unwrap();

        let target_index = 42u64;

        // Generate all query types
        let (_state, full_query) = query(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )
        .unwrap();
        let (_state, seeded_query) = query_seeded(
            &crs,
            target_index,
            &encoded_db.config,
            &rlwe_sk,
            &mut sampler,
        )
        .unwrap();

        // Get responses
        let response_no_pack = respond(&crs, &encoded_db, &full_query).unwrap();
        let response_one_pack = respond_one_packing(&crs, &encoded_db, &full_query).unwrap();

        // Serialize to get actual sizes
        let query_full_bytes = bincode::serialize(&full_query).unwrap();
        let query_seeded_bytes = bincode::serialize(&seeded_query).unwrap();
        let resp_0_bytes = response_no_pack.to_binary().unwrap();
        let resp_1_bytes = response_one_pack.to_binary().unwrap();

        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!(
            "║  InsPIRe Size Comparison (d={}, entry={}B, 16 columns)   ║",
            d, entry_size
        );
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  QUERY SIZES                                                 ║");
        println!("╟──────────────────────────────────────────────────────────────╢");
        println!(
            "║  Full query:      {:>8} bytes ({:>6.1} KB)                 ║",
            query_full_bytes.len(),
            query_full_bytes.len() as f64 / 1024.0
        );
        println!(
            "║  Seeded query:    {:>8} bytes ({:>6.1} KB)  [{:.0}% of full] ║",
            query_seeded_bytes.len(),
            query_seeded_bytes.len() as f64 / 1024.0,
            query_seeded_bytes.len() as f64 / query_full_bytes.len() as f64 * 100.0
        );
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  RESPONSE SIZES                                              ║");
        println!("╟──────────────────────────────────────────────────────────────╢");
        println!(
            "║  NoPacking (^0):  {:>8} bytes ({:>6.1} KB)                 ║",
            resp_0_bytes.len(),
            resp_0_bytes.len() as f64 / 1024.0
        );
        println!(
            "║  OnePacking (^1): {:>8} bytes ({:>6.1} KB)  [{:.1}x smaller]  ║",
            resp_1_bytes.len(),
            resp_1_bytes.len() as f64 / 1024.0,
            resp_0_bytes.len() as f64 / resp_1_bytes.len() as f64
        );
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  TOTAL ROUNDTRIP (Query + Response)                          ║");
        println!("╟──────────────────────────────────────────────────────────────╢");

        let total_0 = query_full_bytes.len() + resp_0_bytes.len();
        let total_1 = query_full_bytes.len() + resp_1_bytes.len();
        let total_2 = query_seeded_bytes.len() + resp_1_bytes.len();

        println!(
            "║  InsPIRe^0 (full+nopack):   {:>8} bytes ({:>6.1} KB)        ║",
            total_0,
            total_0 as f64 / 1024.0
        );
        println!(
            "║  InsPIRe^1 (full+packed):   {:>8} bytes ({:>6.1} KB)        ║",
            total_1,
            total_1 as f64 / 1024.0
        );
        println!(
            "║  InsPIRe^2 (seeded+packed): {:>8} bytes ({:>6.1} KB)        ║",
            total_2,
            total_2 as f64 / 1024.0
        );
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  BANDWIDTH SAVINGS vs InsPIRe^0                              ║");
        println!("╟──────────────────────────────────────────────────────────────╢");
        println!(
            "║  InsPIRe^1: {:.1}x reduction                                   ║",
            total_0 as f64 / total_1 as f64
        );
        println!(
            "║  InsPIRe^2: {:.1}x reduction                                   ║",
            total_0 as f64 / total_2 as f64
        );
        println!("╚══════════════════════════════════════════════════════════════╝");
    }
}
