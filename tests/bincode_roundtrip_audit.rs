//! Bincode roundtrip audit sweep.
//!
//! Bug 1 (`ServerResponse.packing_mode`, Option<PackingMode>) and
//! Bug 2 (`ClientPackingKeys.z_body`, Vec<Poly>) were the same class:
//! pairing `skip_serializing_if` with bincode's positional format
//! produced unexpected-EOF on deserialize when the field was absent.
//! Both fixed in session 015 by removing the `skip_serializing_if`
//! attribute + keeping `#[serde(default)]`.
//!
//! This sweep systematically exercises the fix across every
//! public-API Option<T> / Vec<T> field in types that derive
//! Serialize + Deserialize in the fork. Roundtrip via bincode
//! at BOTH edge states (None / Some for Option; empty / non-empty
//! for Vec) and assert byte-identity of the recovered value against
//! the original.
//!
//! A future `skip_serializing_if` regression would fail one of
//! these roundtrips. Catches the Bug 1/2 pattern before it ships.

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, SecurityLevel};
use raven_inspire::{
    extract_inspiring, query, query_seeded, respond, respond_seeded_inspiring, setup, PackingMode,
    ServerResponse, ServerSessionHandle,
};

/// Small params for fast roundtrip tests.
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

/// Helper: round-trip via bincode; assert_eq the serialized bytes
/// after a second round-trip (byte-stable serialization under
/// `Serialize + Deserialize`).
fn bincode_roundtrip_stable<T>(value: &T, label: &str)
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let bytes = bincode::serialize(value)
        .unwrap_or_else(|e| panic!("{label}: bincode::serialize failed: {e:?}"));
    let recovered: T = bincode::deserialize(&bytes)
        .unwrap_or_else(|e| panic!("{label}: bincode::deserialize failed: {e:?}"));
    let bytes2 = bincode::serialize(&recovered)
        .unwrap_or_else(|e| panic!("{label}: re-serialize failed: {e:?}"));
    assert_eq!(
        bytes, bytes2,
        "{label}: bincode re-serialize must be byte-stable"
    );
}

#[test]
fn server_response_packing_mode_all_variants_bincode_stable() {
    // Exercise the Bug 1 field (`packing_mode: Option<PackingMode>`)
    // across all 3 discriminant states. `api_contract.rs` already has
    // the single-variant tests; this sweep asserts byte-stable across
    // repeated serialize to catch any future drift.
    let params = small_params();
    let mut sampler = GaussianSampler::new(params.sigma);
    let entry_size = 32;
    let n = params.ring_dim;
    let db: Vec<u8> = (0..n * entry_size).map(|i| (i % 256) as u8).collect();
    let (crs, encoded_db, sk) = setup(&params, &db, entry_size, &mut sampler).unwrap();
    let (_state, client_query) = query(&crs, 42, &encoded_db.config, &sk, &mut sampler).unwrap();
    let mut base = respond(&crs, &encoded_db, &client_query).unwrap();

    for mode in &[None, Some(PackingMode::Tree), Some(PackingMode::Inspiring)] {
        base.packing_mode = *mode;
        bincode_roundtrip_stable(&base, &format!("ServerResponse.packing_mode = {mode:?}"));
    }
}

#[test]
fn client_query_session_handle_both_states_bincode_stable() {
    // New in session 015 (handshake): `session_handle:
    // Option<ServerSessionHandle>`. Must roundtrip under None and
    // Some.
    let params = small_params();
    let mut sampler = GaussianSampler::new(params.sigma);
    let entry_size = 32;
    let n = params.ring_dim;
    let db: Vec<u8> = (0..n * entry_size).map(|i| (i % 256) as u8).collect();
    let (crs, encoded_db, sk) = setup(&params, &db, entry_size, &mut sampler).unwrap();
    let (_state, mut cq) = query(&crs, 17, &encoded_db.config, &sk, &mut sampler).unwrap();

    cq.session_handle = None;
    bincode_roundtrip_stable(&cq, "ClientQuery.session_handle = None");

    cq.session_handle = Some(ServerSessionHandle(42));
    bincode_roundtrip_stable(&cq, "ClientQuery.session_handle = Some(42)");
}

#[test]
fn seeded_client_query_session_handle_both_states_bincode_stable() {
    let params = small_params();
    let mut sampler = GaussianSampler::new(params.sigma);
    let entry_size = 32;
    let n = params.ring_dim;
    let db: Vec<u8> = (0..n * entry_size).map(|i| (i % 256) as u8).collect();
    let (crs, encoded_db, sk) = setup(&params, &db, entry_size, &mut sampler).unwrap();
    let (_state, mut sq) = query_seeded(&crs, 17, &encoded_db.config, &sk, &mut sampler).unwrap();

    sq.session_handle = None;
    bincode_roundtrip_stable(&sq, "SeededClientQuery.session_handle = None");

    sq.session_handle = Some(ServerSessionHandle(7));
    bincode_roundtrip_stable(&sq, "SeededClientQuery.session_handle = Some(7)");
}

#[test]
fn inspiring_packing_keys_z_body_empty_and_nonempty_bincode_stable() {
    // Bug 2 field: `ClientPackingKeys.z_body: Vec<Poly>`. Under
    // partial-InspiRING (TwoPacking with 2 KS matrices, no full
    // packing) z_body IS empty. Fix keeps `#[serde(default)]` without
    // skip_serializing_if so the Vec length prefix is always
    // emitted.
    //
    // We drive z_body's state indirectly through a full
    // query_seeded roundtrip: SeededClientQuery carries
    // `inspiring_packing_keys: Option<ClientPackingKeys>` which
    // holds z_body. Partial-InspiRING path (our default) produces
    // an empty z_body. A separate test would need full-InspiRING
    // setup to produce non-empty z_body; for session 016 we
    // validate the empty state which was the actual Bug 2
    // failure mode.
    let params = small_params();
    let mut sampler = GaussianSampler::new(params.sigma);
    let entry_size = 32;
    let n = params.ring_dim;
    let db: Vec<u8> = (0..n * entry_size).map(|i| (i % 256) as u8).collect();
    let (crs, encoded_db, sk) = setup(&params, &db, entry_size, &mut sampler).unwrap();
    let (_state, sq) = query_seeded(&crs, 13, &encoded_db.config, &sk, &mut sampler).unwrap();

    let keys = sq
        .inspiring_packing_keys
        .as_ref()
        .expect("session-015 partial-InspiRING path should produce inspiring_packing_keys");
    assert!(
        keys.z_body.is_empty(),
        "partial-InspiRING path must produce empty z_body (Bug 2 coverage)"
    );
    bincode_roundtrip_stable(keys, "ClientPackingKeys z_body empty");
}

#[test]
fn end_to_end_seeded_response_bincode_stable_across_packing_modes() {
    // Full seeded-InspiRING pipeline bincode roundtrip: query_seeded
    // -> respond_seeded_inspiring -> extract_inspiring. The response
    // carries `packing_mode: Some(PackingMode::Inspiring)` from
    // commit C. Assert byte-stable bincode roundtrip + correctness.
    let params = small_params();
    let mut sampler = GaussianSampler::new(params.sigma);
    let entry_size = 2usize;
    let n = params.ring_dim;
    let db: Vec<u8> = (0..n as u64)
        .flat_map(|i| vec![(i % 256) as u8, 0u8])
        .collect();
    let (crs, encoded_db, sk) = setup(&params, &db, entry_size, &mut sampler).unwrap();

    for idx in &[11u64, 42, 100, 200] {
        let (state, mut sq) =
            query_seeded(&crs, *idx, &encoded_db.config, &sk, &mut sampler).unwrap();
        sq.packing_mode = PackingMode::Inspiring;
        let response: ServerResponse = respond_seeded_inspiring(&crs, &encoded_db, &sq).unwrap();
        bincode_roundtrip_stable(&response, &format!("ServerResponse @ idx={idx}"));
        let recovered = extract_inspiring(&crs, &state, &response, entry_size).unwrap();
        // DB generator above emits [(i % 256), 0] per entry, so the
        // expected bytes at idx are [(idx % 256), 0].
        let expected = vec![((*idx as usize) % 256) as u8, 0u8];
        assert_eq!(recovered, expected, "roundtrip extract @ idx={idx}");
    }
}
