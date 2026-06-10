//! Byte-identity gate for the `parallel` (rayon) feature: `respond` produces byte-identical
//! output whether rayon is on or off.
//!
//! Layered:
//! 1. DIRECT (`respond_byte_identical_par_vs_seq_on_fixed_input`): a checked-in fixed
//!    `(crs, encoded_db, query)` fixture is hashed through the PRODUCTION `respond_inspiring`
//!    under both feature builds; both must equal the same golden. Same input + same golden in
//!    both builds == par-bytes == seq-bytes. The fixture freezes the (thread_rng-sampled)
//!    ciphertext `a`, so cross-run reproducibility of setup/query is not needed.
//! 2. STRUCTURAL (`par_iter_map_collect_is_order_identical_to_sequential`, parallel-only): the
//!    respond/packing kernels are all `par_iter().map(pure_fn).collect()` over PUBLIC data, so
//!    their byte-identity reduces to rayon's order-preserving `collect`. This pins that fact and
//!    catches a future non-order-preserving `par_iter`.
//! Production-cell decode (d=2048) under `--features parallel` is covered by `e2e_pir`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::path::PathBuf;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, SecurityLevel};
use raven_inspire::pir::{
    query, respond_inspiring, setup_with_rng, ClientQuery, EncodedDatabase, ServerCrs,
};

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn d256_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65_536,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/respond_byte_identity_d256.bin")
}

// Byte-identity is a structural, d-independent property of order-preserving maps; a small d=256
// fixture suffices. The golden is captured from the frozen fixture and re-verified under both
// feature builds.
const GOLDEN_FNV1A: u64 = 0x2205_050f_4bc4_b12c;

#[test]
fn respond_byte_identical_par_vs_seq_on_fixed_input() {
    let path = fixture_path();
    let (crs, encoded_db, q): (ServerCrs, EncodedDatabase, ClientQuery) = match std::fs::read(&path)
    {
        Ok(bytes) => bincode::deserialize(&bytes).expect("deserialize fixture"),
        Err(_) => {
            // Bootstrap: generate the fixture once, then fail so the golden can be captured.
            let params = d256_params();
            let entry_size = 32usize;
            let db: Vec<u8> = (0..params.ring_dim * entry_size)
                .map(|i| (i % 251) as u8)
                .collect();
            let mut sampler = GaussianSampler::with_seed(params.sigma, 1);
            let mut rng = ChaCha20Rng::seed_from_u64(2);
            let (crs, encoded_db, sk) =
                setup_with_rng(&params, &db, entry_size, &mut sampler, &mut rng).unwrap();
            let (_state, qy) = query(&crs, 3, &encoded_db.config, &sk, &mut sampler).unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                bincode::serialize(&(&crs, &encoded_db, &qy)).unwrap(),
            )
            .unwrap();
            panic!("fixture generated at {path:?}; re-run this test to print the golden, then pin GOLDEN_FNV1A");
        }
    };

    let response = respond_inspiring(&crs, &encoded_db, &q).expect("respond");
    let hash = fnv1a(&bincode::serialize(&response).unwrap());
    eprintln!("respond byte-identity (fixed input): fnv1a={hash:#018x}");
    assert_eq!(
        hash, GOLDEN_FNV1A,
        "respond bytes differ from the golden - a par/seq divergence (or the fixture changed)"
    );
}

#[cfg(feature = "parallel")]
#[test]
fn par_iter_map_collect_is_order_identical_to_sequential() {
    use rayon::prelude::*;

    fn kernel(x: &u64) -> Vec<u64> {
        (0u64..9)
            .map(|k| {
                x.wrapping_mul(k.wrapping_add(1))
                    .wrapping_add(0x9e37_79b9_7f4a_7c15)
            })
            .collect()
    }
    let items: Vec<u64> = (0..8192u64).collect();
    let seq: Vec<Vec<u64>> = items.iter().map(kernel).collect();
    let par: Vec<Vec<u64>> = items.par_iter().map(kernel).collect();
    assert_eq!(
        seq, par,
        "par_iter().map().collect() must equal the sequential collect"
    );

    let seq_r: Vec<Vec<u64>> = (0..8192u64).map(|i| kernel(&i)).collect();
    let par_r: Vec<Vec<u64>> = (0..8192u64).into_par_iter().map(|i| kernel(&i)).collect();
    assert_eq!(
        seq_r, par_r,
        "into_par_iter range collect must equal sequential"
    );
}
