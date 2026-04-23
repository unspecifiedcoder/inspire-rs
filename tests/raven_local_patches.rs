//! Raven-local fork patches: regression tests
//!
//! One test per patch applied in the Raven-local fork
//! (see `UPSTREAM.md`). Each test locks the fix against future
//! upstream pulls that might revert the change.

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant, SecurityLevel, ShardConfig};


use raven_inspire::{
    encode_database, setup,
    extract_inspiring, extract_with_variant, query_seeded, respond_seeded_inspiring,
    respond_seeded_inspiring_cached_with_session, respond_with_variant, ClientSession,
    PackingMode, ServerInspiringCache, ServerResponse, ServerSessionStore,
};

/// Small params for fast correctness tests.
fn small_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

/// Commit A: `encode_database` returns a typed error when
/// `entries_per_shard > ring_dim` instead of the upstream
/// `debug_assert!` that release builds silently dropped.
#[test]
fn commit_a_encode_database_returns_error_on_oversized_shard() {
    let params = small_params();
    // Deliberately mis-sized: 1 GiB shards at 32 B/entry -> 2^25 entries per
    // shard, which exceeds ring_dim=256 by ~130000x. The pre-fork code
    // path would have debug_asserted (gone in release) then panicked deep
    // in `inverse_monomial`.
    let shard_config = ShardConfig {
        shard_size_bytes: 1 << 30,
        entry_size_bytes: 32,
        total_entries: 1 << 20,
    };
    // Small non-empty database so the `database.is_empty()` early return
    // doesn't mask the check.
    let db = vec![0u8; 32 * 4];
    let err = encode_database(&db, 32, &params, &shard_config)
        .expect_err("oversized ShardConfig must return a typed error");
    let msg = err.to_string();
    assert!(
        msg.contains("entries_per_shard"),
        "error must explain the invariant; got: {msg}"
    );
    assert!(
        msg.contains("ring_dim"),
        "error must cite ring_dim; got: {msg}"
    );
}

/// Commit B: `respond_with_variant(TwoPacking)` returns a typed error
/// redirecting the caller to the seeded pipeline, instead of silently
/// routing through the OnePacking response path (which produced
/// semantically wrong plaintext via `extract_two_packing`).
#[test]
fn commit_b_respond_with_variant_twopacking_returns_error() {
    let params = small_params();
    let mut sampler = GaussianSampler::new(params.sigma);
    let num_entries = params.ring_dim;
    let entry_size = 2usize;
    let db: Vec<u8> = (0..num_entries)
        .flat_map(|i| vec![(i % 256) as u8, 0u8])
        .collect();
    let (crs, encoded_db, rlwe_sk) = setup(&params, &db, entry_size, &mut sampler).unwrap();

    let target_index = 42u64;
    let (_state, client_query) = raven_inspire::query(
        &crs,
        target_index,
        &encoded_db.config,
        &rlwe_sk,
        &mut sampler,
    )
    .unwrap();

    let err = respond_with_variant(&crs, &encoded_db, &client_query, InspireVariant::TwoPacking)
        .expect_err("TwoPacking on unseeded query must return a typed error");
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("seeded")
            || msg.to_lowercase().contains("twopacking"),
        "error must direct to the seeded path; got: {msg}"
    );
}

/// Commit C: `extract_with_variant(TwoPacking)` routes to
/// `extract_inspiring` when the server produced an InspiRING-shaped
/// response, matching the upstream binary pair at
/// `bin/client.rs:302` (pre-fork) that bypassed the wrapper.
#[test]
fn commit_c_extract_with_variant_handles_inspiring_response() {
    let params = small_params();
    let mut sampler = GaussianSampler::new(params.sigma);
    let num_entries = params.ring_dim;
    let entry_size = 2usize;
    let db: Vec<u8> = (0..num_entries)
        .flat_map(|i| vec![(i % 256) as u8, 0u8])
        .collect();
    let (crs, encoded_db, rlwe_sk) = setup(&params, &db, entry_size, &mut sampler).unwrap();

    let target_index = 17u64;
    let (state, mut seeded_query) =
        query_seeded(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler).unwrap();
    seeded_query.packing_mode = PackingMode::Inspiring;
    let response: ServerResponse = respond_seeded_inspiring(&crs, &encoded_db, &seeded_query).unwrap();

    // The canonical path: `extract_inspiring` direct.
    let via_inspiring = extract_inspiring(&crs, &state, &response, entry_size).unwrap();
    // Commit C makes `extract_with_variant(TwoPacking)` match the canonical
    // path for InspiRING-shaped responses. The two outputs must be equal.
    let via_wrapper =
        extract_with_variant(&crs, &state, &response, entry_size, InspireVariant::TwoPacking)
            .unwrap();

    assert_eq!(via_inspiring, via_wrapper, "commit C must route TwoPacking extraction to extract_inspiring for InspiRING-shaped responses");
    // Also verify the extracted value matches the planted entry.
    let target_byte = (target_index as usize) * entry_size;
    assert_eq!(&via_wrapper[..], &db[target_byte..target_byte + entry_size]);
}

/// Commit D: `secure_128_d{2048,4096}` constructors use the
/// library-internal DEFAULT_Q (2^60 - 2^14 + 1) in single-prime form
/// instead of the under-provisioned 2-CRT `[268369921, 249561089]`
/// product (q approx 2^56). Correctness at 2^20 x 256 B under the
/// fixed preset + the InsPIRe^2 Seeded+Inspiring pipeline.
///
/// Marked `#[ignore]` by default: the setup at ring_dim 2048 +
/// 1M entries + 256 B allocates 256 MiB of database + 5+s setup and
/// takes ~ 10 s per smoke invocation. Run explicitly with
/// `cargo test --manifest-path crates/raven-inspire/Cargo.toml
/// --release -- --ignored commit_d`.
#[test]
#[ignore = "2^20 x 256 B cell; run explicitly under --release"]
fn commit_d_preset_default_q_passes_smoke_at_2_20_x_256b() {
    let params = InspireParams::secure_128_d2048();
    // The commit-D fix is that this preset now carries the DEFAULT_Q
    // struct literal instead of the 2-CRT moduli.
    assert_eq!(
        params.q, 1_152_921_504_606_830_593,
        "secure_128_d2048 must ship DEFAULT_Q after commit D"
    );
    assert_eq!(
        params.crt_moduli,
        vec![1_152_921_504_606_830_593],
        "secure_128_d2048 must use single-prime CRT form after commit D"
    );

    let mut sampler = GaussianSampler::new(params.sigma);
    let entries: u64 = 1 << 20;
    let entry_size: usize = 256;
    let total = (entries as usize) * entry_size;
    let mut db = vec![0u8; total];
    for i in 0..entries as usize {
        for j in 0..entry_size {
            db[i * entry_size + j] = ((i + j) % 251) as u8;
        }
    }
    let (crs, encoded_db, sk) =
        setup(&params, &db, entry_size, &mut sampler).expect("setup must succeed");

    for &idx in &[entries / 4 - 1, entries / 2 - 1, 3 * entries / 4 - 1] {
        let (state, mut seeded_query) =
            query_seeded(&crs, idx, &encoded_db.config, &sk, &mut sampler).unwrap();
        seeded_query.packing_mode = PackingMode::Inspiring;
        let response = respond_seeded_inspiring(&crs, &encoded_db, &seeded_query).unwrap();
        let recovered = extract_inspiring(&crs, &state, &response, entry_size).unwrap();
        let expected: Vec<u8> = (0..entry_size)
            .map(|j| (((idx as usize) + j) % 251) as u8)
            .collect();
        assert_eq!(
            &recovered[..],
            &expected[..],
            "commit D: smoke byte-match must pass at index {idx}"
        );
    }
}

/// Packing-key pre-exchange handshake.
///
/// Validates two things:
/// 1. `ClientSession::register_with` uploads keys once, returns a handle,
///    and subsequent queries emit compact wire payloads
///    (`inspiring_packing_keys = None`, `session_handle = Some(h)`).
/// 2. `respond_seeded_inspiring_cached_with_session` resolves the handle
///    against a `ServerSessionStore` and produces a byte-equal result
///    to the pre-handshake inlined-keys path.
#[test]
fn phase_b_handshake_roundtrip_byte_equal_to_inlined_keys() {
    let params = small_params();
    let mut sampler = GaussianSampler::new(params.sigma);
    let num_entries = params.ring_dim;
    let entry_size = 2usize;
    let db: Vec<u8> = (0..num_entries)
        .flat_map(|i| vec![(i % 256) as u8, 0u8])
        .collect();
    let (crs, encoded_db, rlwe_sk) = setup(&params, &db, entry_size, &mut sampler).unwrap();

    let server_cache = ServerInspiringCache::new(&crs, &encoded_db).unwrap();
    let session_store = ServerSessionStore::new();

    // Inlined-keys baseline (pre-handshake wire format).
    let mut session_inline =
        ClientSession::new(crs.clone(), rlwe_sk.clone(), &mut sampler).unwrap();
    assert!(session_inline.session_handle().is_none());

    let (state_inline, mut q_inline) = session_inline
        .query_seeded(42, &encoded_db.config, &mut sampler)
        .unwrap();
    q_inline.packing_mode = PackingMode::Inspiring;

    assert!(
        q_inline.inspiring_packing_keys.is_some(),
        "pre-handshake session must inline the keys"
    );
    assert!(
        q_inline.session_handle.is_none(),
        "pre-handshake session must NOT reference a handle"
    );

    let response_inline = respond_seeded_inspiring(&crs, &encoded_db, &q_inline).unwrap();
    let decoded_inline =
        extract_inspiring(&crs, &state_inline, &response_inline, entry_size).unwrap();

    // Handshake path: register, emit compact query, respond via session.
    let mut session_hs = ClientSession::new(crs.clone(), rlwe_sk, &mut sampler).unwrap();
    let handle = session_hs
        .register_with(&session_store)
        .unwrap()
        .expect("InspiRING session must register a handle");
    assert_eq!(session_hs.session_handle(), Some(handle));
    assert_eq!(session_store.len(), 1);

    let (state_hs, mut q_hs) = session_hs
        .query_seeded(42, &encoded_db.config, &mut sampler)
        .unwrap();
    q_hs.packing_mode = PackingMode::Inspiring;

    assert!(
        q_hs.inspiring_packing_keys.is_none(),
        "handshake session must drop inlined keys"
    );
    assert_eq!(
        q_hs.session_handle,
        Some(handle),
        "handshake session must carry the handle"
    );

    // Compact query wire bytes must be strictly smaller than inlined.
    let bytes_inline = bincode::serialize(&q_inline).unwrap().len();
    let bytes_hs = bincode::serialize(&q_hs).unwrap().len();
    assert!(
        bytes_hs < bytes_inline,
        "handshake query must be smaller than inlined: hs={bytes_hs} B, inline={bytes_inline} B"
    );

    let response_hs = respond_seeded_inspiring_cached_with_session(
        &crs,
        &encoded_db,
        &q_hs,
        &server_cache,
        Some(&session_store),
    )
    .unwrap();
    let decoded_hs = extract_inspiring(&crs, &state_hs, &response_hs, entry_size).unwrap();

    // Both paths must recover the same planted byte.
    let target_byte = 42 * entry_size;
    let expected = &db[target_byte..target_byte + entry_size];
    assert_eq!(decoded_inline.as_slice(), expected);
    assert_eq!(decoded_hs.as_slice(), expected);
    assert_eq!(
        decoded_inline, decoded_hs,
        "handshake and inlined paths must produce the same plaintext"
    );
}
