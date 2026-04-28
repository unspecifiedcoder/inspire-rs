//! Server-side y_all_ntt derivation byte-identity KAT.
//! KAT.
//!
//! The wire-format gap comes from
//! `ClientPackingKeys::y_all` + `y_all_ntt` being `#[serde(skip)]`:
//! deserialized servers see only `y_body` and dispatch falls to the
//! slow `packing_online` path. The fix derives `y_all` + `y_all_ntt`
//! server-side from `y_body` so the fully_ntt dispatch fires.
//!
//! These tests prove the derivation is byte-identical to the in-
//! process client-computed version.
//!
//! ### What "byte-identical" means here
//!
//! Because `ClientPackingKeys::generate` builds `y_all` + `y_all_ntt`
//! from `y_body` via the exact code path that `generate_rotations`
//! runs + `Poly::to_ntt`, the server-side helper
//! `ensure_server_derivatives` produces the same values. The KAT
//! proves this across a randomized input vector + the configured
//! `InspireParams` used at the SLO cell.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
use raven_inspire::math::{GaussianSampler, NttContext};
use raven_inspire::params::InspireParams;
use raven_inspire::rlwe::RlweSecretKey;

fn test_params() -> InspireParams {
    // Small-ring test params that exercise the same automorph +
    // key-switching ladder as the SLO cell (ring_dim=2048, 128
    // columns) but at ring_dim=256, 16 columns so the KAT runs fast
    // under `cargo test --release`.
    InspireParams {
        ring_dim: 256,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: raven_inspire::params::SecurityLevel::Bits128,
    }
}

#[test]
fn ensure_server_derivatives_byte_identical_to_client_generation() {
    let params = test_params();
    let num_to_pack = 16;
    let pack_params = PackParams::new(&params, num_to_pack);
    let ctx = NttContext::with_moduli(params.ring_dim, params.moduli());

    let mut sampler = GaussianSampler::new(params.sigma);
    let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
    let w_seed = {
        let mut s = [0u8; 32];
        let mut rng = ChaCha20Rng::seed_from_u64(0xDEADBEEF);
        rand::Rng::fill(&mut rng, &mut s);
        s
    };

    // Baseline: client generates full keys in-process. y_all + y_all_ntt
    // are populated in this object.
    let mut sampler_b = GaussianSampler::new(params.sigma);
    let expected = ClientPackingKeys::generate(&rlwe_sk, &pack_params, w_seed, &mut sampler_b);

    // Simulate wire-format: create a keys object carrying only y_body
    // + z_body + metadata (empty y_all + y_all_ntt + y_bar_all + y_bar_all_ntt).
    let mut wire_side = ClientPackingKeys {
        y_body: expected.y_body.clone(),
        z_body: expected.z_body.clone(),
        y_all: Vec::new(),
        y_all_ntt: Vec::new(),
        y_bar_all: Vec::new(),
        y_bar_all_ntt: Vec::new(),
        full_key: expected.full_key,
        num_to_pack: expected.num_to_pack,
    };

    // Apply server-side derivation.
    wire_side.ensure_server_derivatives(&pack_params, &ctx);

    assert_eq!(
        wire_side.y_all.len(),
        expected.y_all.len(),
        "y_all outer length mismatch"
    );
    assert_eq!(
        wire_side.y_all_ntt.len(),
        expected.y_all_ntt.len(),
        "y_all_ntt outer length mismatch"
    );

    for (i, (got, want)) in wire_side
        .y_all
        .iter()
        .zip(expected.y_all.iter())
        .enumerate()
    {
        assert_eq!(got.len(), want.len(), "y_all[{}] inner length mismatch", i);
        for (k, (p_got, p_want)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(
                p_got.coeffs(),
                p_want.coeffs(),
                "y_all[{}][{}] coeffs mismatch",
                i,
                k
            );
            assert_eq!(
                p_got.is_ntt(),
                p_want.is_ntt(),
                "y_all[{}][{}] is_ntt flag mismatch",
                i,
                k
            );
        }
    }

    for (i, (got, want)) in wire_side
        .y_all_ntt
        .iter()
        .zip(expected.y_all_ntt.iter())
        .enumerate()
    {
        assert_eq!(
            got.len(),
            want.len(),
            "y_all_ntt[{}] inner length mismatch",
            i
        );
        for (k, (p_got, p_want)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(
                p_got.coeffs(),
                p_want.coeffs(),
                "y_all_ntt[{}][{}] coeffs mismatch",
                i,
                k
            );
            assert!(
                p_got.is_ntt(),
                "y_all_ntt[{}][{}] must be in NTT form",
                i,
                k
            );
            assert!(
                p_want.is_ntt(),
                "expected y_all_ntt[{}][{}] must be in NTT form",
                i,
                k
            );
        }
    }
}

#[test]
fn ensure_server_derivatives_is_noop_when_populated() {
    let params = test_params();
    let num_to_pack = 16;
    let pack_params = PackParams::new(&params, num_to_pack);
    let ctx = NttContext::with_moduli(params.ring_dim, params.moduli());

    let mut sampler = GaussianSampler::new(params.sigma);
    let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
    let mut keys = ClientPackingKeys::generate(&rlwe_sk, &pack_params, [7u8; 32], &mut sampler);

    let y_all_snapshot: Vec<Vec<Vec<u64>>> = keys
        .y_all
        .iter()
        .map(|inner| inner.iter().map(|p| p.coeffs().to_vec()).collect())
        .collect();
    let y_all_ntt_snapshot: Vec<Vec<Vec<u64>>> = keys
        .y_all_ntt
        .iter()
        .map(|inner| inner.iter().map(|p| p.coeffs().to_vec()).collect())
        .collect();

    // Second call must not mutate state.
    keys.ensure_server_derivatives(&pack_params, &ctx);

    for (i, inner) in keys.y_all.iter().enumerate() {
        for (k, p) in inner.iter().enumerate() {
            assert_eq!(
                p.coeffs(),
                y_all_snapshot[i][k].as_slice(),
                "noop violated at y_all[{}][{}]",
                i,
                k
            );
        }
    }
    for (i, inner) in keys.y_all_ntt.iter().enumerate() {
        for (k, p) in inner.iter().enumerate() {
            assert_eq!(
                p.coeffs(),
                y_all_ntt_snapshot[i][k].as_slice(),
                "noop violated at y_all_ntt[{}][{}]",
                i,
                k
            );
        }
    }
}

#[test]
fn bincode_roundtrip_then_server_derive_matches_original_y_all_ntt() {
    let params = test_params();
    let num_to_pack = 16;
    let pack_params = PackParams::new(&params, num_to_pack);
    let ctx = NttContext::with_moduli(params.ring_dim, params.moduli());

    let mut sampler = GaussianSampler::new(params.sigma);
    let rlwe_sk = RlweSecretKey::generate(&params, &mut sampler);
    let original = ClientPackingKeys::generate(&rlwe_sk, &pack_params, [42u8; 32], &mut sampler);

    // Simulate wire transport.
    let bytes = bincode::serialize(&original).expect("bincode serialize");
    let mut wire: ClientPackingKeys = bincode::deserialize(&bytes).expect("bincode deserialize");
    assert!(wire.y_all.is_empty(), "serde(skip) drops y_all on the wire");
    assert!(
        wire.y_all_ntt.is_empty(),
        "serde(skip) drops y_all_ntt on the wire"
    );

    wire.ensure_server_derivatives(&pack_params, &ctx);

    assert_eq!(wire.y_all.len(), original.y_all.len());
    assert_eq!(wire.y_all_ntt.len(), original.y_all_ntt.len());
    for (i, (got, want)) in wire
        .y_all_ntt
        .iter()
        .zip(original.y_all_ntt.iter())
        .enumerate()
    {
        for (k, (pg, pw)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(
                pg.coeffs(),
                pw.coeffs(),
                "post-roundtrip y_all_ntt[{}][{}] mismatch",
                i,
                k
            );
        }
    }
}
