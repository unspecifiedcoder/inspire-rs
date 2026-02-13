//! API Contract Verification Tests
//!
//! Ensures that public API types maintain their serialization contracts,
//! trait bounds, and security invariants (e.g., secret key fields are
//! never leaked through serde).

use inspire::params::{InspireParams, InspireVariant, SecurityLevel, ShardConfig};
use inspire::pir::{
    ClientQuery, ClientState, EncodedDatabase, InspireCrs, PackingMode, SeededClientQuery,
    ServerCrs, ServerResponse, ShardData,
};

// ---------------------------------------------------------------------------
// Helper: small test parameters (ring_dim=256 for speed)
// ---------------------------------------------------------------------------
fn test_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1152921504606830593,
        crt_moduli: vec![1152921504606830593],
        p: 65536,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

// ===========================================================================
// 1. Trait bound smoke tests — ensure key types implement required traits
// ===========================================================================

fn assert_serialize<T: serde::Serialize>() {}
fn assert_deserialize<T: serde::de::DeserializeOwned>() {}
fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn trait_bounds_client_query() {
    assert_serialize::<ClientQuery>();
    assert_deserialize::<ClientQuery>();
    assert_clone::<ClientQuery>();
    assert_debug::<ClientQuery>();
}

#[test]
fn trait_bounds_seeded_client_query() {
    assert_serialize::<SeededClientQuery>();
    assert_deserialize::<SeededClientQuery>();
    assert_clone::<SeededClientQuery>();
    assert_debug::<SeededClientQuery>();
}

#[test]
fn trait_bounds_client_state() {
    assert_serialize::<ClientState>();
    assert_deserialize::<ClientState>();
    assert_clone::<ClientState>();
    assert_debug::<ClientState>();
}

#[test]
fn trait_bounds_server_response() {
    assert_serialize::<ServerResponse>();
    assert_deserialize::<ServerResponse>();
    assert_clone::<ServerResponse>();
    assert_debug::<ServerResponse>();
}

#[test]
fn trait_bounds_server_crs() {
    assert_serialize::<ServerCrs>();
    assert_deserialize::<ServerCrs>();
    assert_clone::<ServerCrs>();
    assert_debug::<ServerCrs>();
}

#[test]
fn trait_bounds_inspire_crs_alias() {
    // InspireCrs is a type alias for ServerCrs — verify it compiles identically
    assert_serialize::<InspireCrs>();
    assert_deserialize::<InspireCrs>();
}

#[test]
fn trait_bounds_encoded_database() {
    assert_serialize::<EncodedDatabase>();
    assert_deserialize::<EncodedDatabase>();
    assert_clone::<EncodedDatabase>();
    assert_debug::<EncodedDatabase>();
}

#[test]
fn trait_bounds_shard_data() {
    assert_serialize::<ShardData>();
    assert_deserialize::<ShardData>();
    assert_clone::<ShardData>();
    assert_debug::<ShardData>();
}

#[test]
fn trait_bounds_packing_mode() {
    assert_serialize::<PackingMode>();
    assert_deserialize::<PackingMode>();
    assert_clone::<PackingMode>();
    assert_debug::<PackingMode>();
    // PackingMode also derives PartialEq, Eq, Copy, Default
    fn assert_eq_copy_default<T: PartialEq + Eq + Copy + Default>() {}
    assert_eq_copy_default::<PackingMode>();
}

#[test]
fn trait_bounds_inspire_params() {
    assert_serialize::<InspireParams>();
    assert_deserialize::<InspireParams>();
    assert_clone::<InspireParams>();
    assert_debug::<InspireParams>();
}

#[test]
fn trait_bounds_shard_config() {
    assert_serialize::<ShardConfig>();
    assert_deserialize::<ShardConfig>();
    assert_clone::<ShardConfig>();
    assert_debug::<ShardConfig>();
}

// ===========================================================================
// 2. Serde round-trip tests — verify JSON serialization contracts
// ===========================================================================

#[test]
fn serde_roundtrip_packing_mode_json() {
    for mode in [PackingMode::Inspiring, PackingMode::Tree] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: PackingMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

#[test]
fn serde_packing_mode_rename_all_snake_case() {
    // PackingMode uses #[serde(rename_all = "snake_case")]
    let json = serde_json::to_string(&PackingMode::Inspiring).unwrap();
    assert_eq!(json, "\"inspiring\"");

    let json = serde_json::to_string(&PackingMode::Tree).unwrap();
    assert_eq!(json, "\"tree\"");
}

#[test]
fn serde_packing_mode_default_is_inspiring() {
    assert_eq!(PackingMode::default(), PackingMode::Inspiring);
}

#[test]
fn serde_roundtrip_inspire_params_json() {
    let params = test_params();
    let json = serde_json::to_string(&params).unwrap();
    let back: InspireParams = serde_json::from_str(&json).unwrap();
    assert_eq!(back, params);
}

#[test]
fn serde_roundtrip_shard_config_json() {
    let config = ShardConfig {
        shard_size_bytes: 8192,
        entry_size_bytes: 32,
        total_entries: 256,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: ShardConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ===========================================================================
// 3. Security-sensitive serde(skip) verification
// ===========================================================================

#[test]
fn client_state_secret_keys_not_serialized() {
    // ClientState.secret_key and .rlwe_secret_key are #[serde(skip, default)].
    // After a JSON round-trip the secret key fields must be empty/default.

    use inspire::math::GaussianSampler;
    use inspire::pir::setup;

    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = params.ring_dim;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let (_state, _query) = inspire::pir::query(
        &crs,
        42,
        &encoded_db.config,
        &rlwe_sk,
        &mut sampler,
    )
    .unwrap();

    // Serialize → deserialize via JSON
    let json = serde_json::to_string(&_state).unwrap();
    let recovered: ClientState = serde_json::from_str(&json).unwrap();

    // Secret keys must NOT survive the round-trip
    assert_eq!(recovered.secret_key.dim, 0, "LWE secret key must be zeroed after serde round-trip");
    assert_eq!(recovered.rlwe_secret_key.ring_dim(), 0, "RLWE secret key must be zeroed after serde round-trip");

    // Non-secret metadata MUST survive
    assert_eq!(recovered.index, _state.index);
    assert_eq!(recovered.shard_id, _state.shard_id);
    assert_eq!(recovered.local_index, _state.local_index);
}

#[test]
fn client_state_secret_keys_absent_from_json() {
    // Verify the JSON output literally does not contain the secret key fields.
    use inspire::math::GaussianSampler;
    use inspire::pir::setup;

    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = params.ring_dim;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let (state, _query) = inspire::pir::query(
        &crs,
        42,
        &encoded_db.config,
        &rlwe_sk,
        &mut sampler,
    )
    .unwrap();

    let json = serde_json::to_string(&state).unwrap();

    assert!(
        !json.contains("secret_key"),
        "JSON must not contain 'secret_key' field: {json}"
    );
    assert!(
        !json.contains("rlwe_secret_key"),
        "JSON must not contain 'rlwe_secret_key' field: {json}"
    );
}

#[test]
fn server_crs_skipped_fields_absent_from_json() {
    // ServerCrs.inspiring_pack_params and .inspiring_packing_key are #[serde(skip)].
    // They must not appear in serialized output.

    use inspire::math::GaussianSampler;
    use inspire::pir::setup;

    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = params.ring_dim;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, _encoded_db, _rlwe_sk) =
        setup(&params, &database, entry_size, &mut sampler).unwrap();

    // The CRS should have the skipped fields set before serialization
    assert!(
        crs.inspiring_pack_params.is_some(),
        "pack_params should be set after setup"
    );
    assert!(
        crs.inspiring_packing_key.is_some(),
        "packing_key should be set after setup"
    );

    let json = serde_json::to_string(&crs).unwrap();

    assert!(
        !json.contains("inspiring_pack_params"),
        "JSON must not contain 'inspiring_pack_params'"
    );
    assert!(
        !json.contains("inspiring_packing_key"),
        "JSON must not contain 'inspiring_packing_key'"
    );
}

#[test]
fn server_crs_skipped_fields_none_after_roundtrip() {
    // After a JSON round-trip, the skipped Option fields should be None.
    use inspire::math::GaussianSampler;
    use inspire::pir::setup;

    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = params.ring_dim;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, _encoded_db, _rlwe_sk) =
        setup(&params, &database, entry_size, &mut sampler).unwrap();

    let json = serde_json::to_string(&crs).unwrap();
    let recovered: ServerCrs = serde_json::from_str(&json).unwrap();

    assert!(
        recovered.inspiring_pack_params.is_none(),
        "inspiring_pack_params must be None after serde round-trip"
    );
    assert!(
        recovered.inspiring_packing_key.is_none(),
        "inspiring_packing_key must be None after serde round-trip"
    );

    // Non-skipped fields MUST survive
    assert_eq!(recovered.params.ring_dim, crs.params.ring_dim);
    assert_eq!(recovered.inspiring_w_seed, crs.inspiring_w_seed);
    assert_eq!(recovered.inspiring_v_seed, crs.inspiring_v_seed);
    assert_eq!(recovered.inspiring_num_columns, crs.inspiring_num_columns);
}

// ===========================================================================
// 4. Bincode round-trip for ServerResponse (used on the wire)
// ===========================================================================

#[test]
fn server_response_bincode_roundtrip() {
    use inspire::math::GaussianSampler;
    use inspire::pir::{respond, setup};

    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = params.ring_dim;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let (_state, client_query) = inspire::pir::query(
        &crs,
        42,
        &encoded_db.config,
        &rlwe_sk,
        &mut sampler,
    )
    .unwrap();

    let response = respond(&crs, &encoded_db, &client_query).unwrap();

    // Round-trip via bincode (to_binary / from_binary)
    let bytes = response.to_binary().unwrap();
    let recovered = ServerResponse::from_binary(&bytes).unwrap();

    assert_eq!(
        recovered.ciphertext.ring_dim(),
        response.ciphertext.ring_dim()
    );
    assert_eq!(
        recovered.column_ciphertexts.len(),
        response.column_ciphertexts.len()
    );
}

#[test]
fn server_response_json_roundtrip() {
    use inspire::math::GaussianSampler;
    use inspire::pir::{respond, setup};

    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = params.ring_dim;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let (_state, client_query) = inspire::pir::query(
        &crs,
        42,
        &encoded_db.config,
        &rlwe_sk,
        &mut sampler,
    )
    .unwrap();

    let response = respond(&crs, &encoded_db, &client_query).unwrap();

    let json = serde_json::to_string(&response).unwrap();
    let recovered: ServerResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(
        recovered.ciphertext.ring_dim(),
        response.ciphertext.ring_dim()
    );
    assert_eq!(
        recovered.column_ciphertexts.len(),
        response.column_ciphertexts.len()
    );
}

// ===========================================================================
// 5. ClientQuery serde defaults — packing_mode defaults to Inspiring
// ===========================================================================

#[test]
fn client_query_packing_mode_defaults_to_inspiring() {
    // If packing_mode is missing from JSON, it should default to Inspiring.
    let mut value = serde_json::json!({
        "shard_id": 0,
        "packing_mode": "tree",
        "rgsw_ciphertext": {
            "rows": [],
            "gadget": {"base": 1048576u64, "len": 3u64, "q": 1152921504606830593u64}
        }
    });
    value.as_object_mut().unwrap().remove("packing_mode");

    let query: ClientQuery = serde_json::from_value(value).unwrap();
    assert_eq!(query.packing_mode, PackingMode::Inspiring);
    assert!(query.inspiring_packing_keys.is_none());
}

#[test]
fn seeded_client_query_packing_mode_defaults_to_inspiring() {
    // Same check for SeededClientQuery.
    let mut value = serde_json::json!({
        "shard_id": 0,
        "packing_mode": "tree",
        "rgsw_ciphertext": {
            "rows": [],
            "gadget": {"base": 1048576u64, "len": 3u64, "q": 1152921504606830593u64}
        }
    });
    value.as_object_mut().unwrap().remove("packing_mode");

    let query: SeededClientQuery = serde_json::from_value(value).unwrap();
    assert_eq!(query.packing_mode, PackingMode::Inspiring);
    assert!(query.inspiring_packing_keys.is_none());
}

// ===========================================================================
// 6. Re-export completeness — ensure all public API functions are accessible
// ===========================================================================

#[test]
fn reexport_extract_inspiring_accessible() {
    // extract_inspiring should be accessible from the crate root
    // This is the fix for the missing re-export bug
    let _fn_ptr: fn(
        &ServerCrs,
        &ClientState,
        &ServerResponse,
        usize,
    ) -> inspire::pir::Result<Vec<u8>> = inspire::extract_inspiring;
    // Also accessible via inspire::pir::extract_inspiring
    let _fn_ptr2: fn(
        &ServerCrs,
        &ClientState,
        &ServerResponse,
        usize,
    ) -> inspire::pir::Result<Vec<u8>> = inspire::pir::extract_inspiring;
}

#[test]
fn reexport_all_extract_variants_accessible() {
    // All extract functions should be accessible from the crate root
    type ExtractFn = fn(
        &ServerCrs,
        &ClientState,
        &ServerResponse,
        usize,
    ) -> inspire::pir::Result<Vec<u8>>;
    type ExtractWithVariantFn = fn(
        &ServerCrs,
        &ClientState,
        &ServerResponse,
        usize,
        InspireVariant,
    ) -> inspire::pir::Result<Vec<u8>>;

    let _: ExtractFn = inspire::extract;
    let _: ExtractFn = inspire::extract_inspiring;
    let _: ExtractFn = inspire::extract_two_packing;
    let _: ExtractWithVariantFn = inspire::extract_with_variant;
}

// ===========================================================================
// 7. InspireVariant enum coverage
// ===========================================================================

#[test]
fn inspire_variant_all_values() {
    // Verify all variants exist (will break if a variant is added/removed)
    let variants = [
        InspireVariant::NoPacking,
        InspireVariant::OnePacking,
        InspireVariant::TwoPacking,
    ];
    assert_eq!(variants.len(), 3);
}

// ===========================================================================
// 8. SecurityLevel enum coverage
// ===========================================================================

#[test]
fn security_level_all_values() {
    let levels = [SecurityLevel::Bits128, SecurityLevel::Bits256];
    assert_eq!(levels.len(), 2);
}

// ===========================================================================
// 9. API function signature smoke tests — verify they compile with expected types
// ===========================================================================

#[test]
fn api_setup_query_respond_extract_compiles() {
    // This test verifies that the primary API flow compiles with the
    // expected types. The actual correctness is tested in e2e_pir.rs.
    use inspire::math::GaussianSampler;
    use inspire::pir::{extract, query, respond, setup};

    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = params.ring_dim;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();
    let (state, client_query) =
        query(&crs, 0, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
    let response = respond(&crs, &encoded_db, &client_query).unwrap();
    let result = extract(&crs, &state, &response, entry_size).unwrap();

    assert_eq!(result.len(), entry_size);
}

#[test]
fn api_seeded_query_compiles() {
    use inspire::math::GaussianSampler;
    use inspire::pir::{query_seeded, setup};

    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = params.ring_dim;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();
    let (state, seeded_query) =
        query_seeded(&crs, 0, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();

    // SeededClientQuery.expand() should produce a ClientQuery
    let _expanded: ClientQuery = seeded_query.expand();

    assert_eq!(state.index, 0);
}

// ===========================================================================
// 10. ClientQuery JSON round-trip with full setup
// ===========================================================================

#[test]
fn client_query_json_roundtrip() {
    use inspire::math::GaussianSampler;
    use inspire::pir::setup;

    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = params.ring_dim;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let (_state, client_query) = inspire::pir::query(
        &crs,
        42,
        &encoded_db.config,
        &rlwe_sk,
        &mut sampler,
    )
    .unwrap();

    let json = serde_json::to_string(&client_query).unwrap();
    let recovered: ClientQuery = serde_json::from_str(&json).unwrap();

    assert_eq!(recovered.shard_id, client_query.shard_id);
    assert_eq!(recovered.packing_mode, client_query.packing_mode);
}

#[test]
fn seeded_client_query_json_roundtrip() {
    use inspire::math::GaussianSampler;
    use inspire::pir::setup;

    let params = test_params();
    let mut sampler = GaussianSampler::new(params.sigma);

    let entry_size = 32;
    let num_entries = params.ring_dim;
    let database: Vec<u8> = (0..(num_entries * entry_size))
        .map(|i| (i % 256) as u8)
        .collect();

    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler).unwrap();

    let (_state, seeded_query) = inspire::pir::query_seeded(
        &crs,
        42,
        &encoded_db.config,
        &rlwe_sk,
        &mut sampler,
    )
    .unwrap();

    let json = serde_json::to_string(&seeded_query).unwrap();
    let recovered: SeededClientQuery = serde_json::from_str(&json).unwrap();

    assert_eq!(recovered.shard_id, seeded_query.shard_id);
    assert_eq!(recovered.packing_mode, seeded_query.packing_mode);
}
