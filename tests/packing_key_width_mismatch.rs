//! Client packing keys built at one gamma must not register against a server using
//! another. The automorphism generator is `(2n/gamma)+1`, so mismatched keys are
//! rotations under a different automorphism than the `bold_t` they multiply - and
//! `packing_online` guards its loop with `if i < len`, skipping the shortfall instead
//! of rejecting it. The result is HTTP 200 carrying wrong plaintext.

#![allow(
    clippy::expect_used,
    reason = "test-target fixture helpers; an abort here is the failure report"
)]

use raven_inspire::inspiring::inspiring2::{ClientPackingKeys, PackParams};
use raven_inspire::math::{GaussianSampler, NttContext};
use raven_inspire::params::{InspireParams, SecurityLevel};
use raven_inspire::pir::ServerSessionStore;
use raven_inspire::rlwe::RlweSecretKey;

const RING_DIM: usize = 256;

fn params() -> InspireParams {
    InspireParams {
        ring_dim: RING_DIM,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65536,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

fn keys_at(width: usize) -> (ClientPackingKeys, PackParams) {
    let p = params();
    let pack = PackParams::try_new(&p, width).expect("legal width");
    let mut sampler = GaussianSampler::with_seed(p.sigma, 7);
    let sk = RlweSecretKey::generate(&p, &mut sampler);
    let keys = ClientPackingKeys::generate(&sk, &pack, [3u8; 32], &mut sampler);
    (keys, pack)
}

#[test]
fn keys_matching_the_server_width_register() {
    let (keys, pack) = keys_at(8);
    let ctx = NttContext::new(RING_DIM, pack.q);
    let store = ServerSessionStore::new();
    store
        .register_server_side(keys, &pack, &ctx)
        .expect("matching gamma must register");
}

#[test]
fn keys_from_a_different_width_are_refused() {
    let (client_keys, _client_pack) = keys_at(4);
    let (_unused, server_pack) = keys_at(8);
    assert_eq!(client_keys.num_to_pack, 4);
    assert_eq!(server_pack.num_to_pack, 8);

    let ctx = NttContext::new(RING_DIM, server_pack.q);
    let store = ServerSessionStore::new();
    let err = store
        .register_server_side(client_keys, &server_pack, &ctx)
        .expect_err("gamma 4 keys must not register against a gamma 8 server");
    let msg = format!("{err}");
    assert!(
        msg.contains("width mismatch"),
        "the refusal must name the mismatch; got: {msg}"
    );
    assert!(
        msg.contains('4') && msg.contains('8'),
        "the refusal must name both widths; got: {msg}"
    );
}

/// Every legal width pairing must be screened, not just the one above.
#[test]
fn every_mismatched_legal_width_pair_is_refused() {
    for client_width in [2usize, 4, 8, 16, 32] {
        for server_width in [2usize, 4, 8, 16, 32] {
            let (client_keys, _) = keys_at(client_width);
            let (_unused, server_pack) = keys_at(server_width);
            let ctx = NttContext::new(RING_DIM, server_pack.q);
            let store = ServerSessionStore::new();
            let outcome = store.register_server_side(client_keys, &server_pack, &ctx);
            assert_eq!(
                outcome.is_ok(),
                client_width == server_width,
                "client gamma {client_width} against server gamma {server_width}: \
                 registration must succeed only when the widths agree"
            );
        }
    }
}

/// The inlined-key path is a SECOND place the two widths meet. `respond_inspiring` takes
/// the keys straight off the query and never goes through `register_server_side`, so a
/// guard placed only there would leave the wrong-bytes-as-success failure fully reachable.
#[test]
fn respond_refuses_inlined_keys_from_a_different_width() {
    use raven_inspire::pir::{query, setup};

    let p = params();
    let mut sampler = GaussianSampler::with_seed(p.sigma, 11);
    let entry_size = 32usize;
    let database = vec![7u8; RING_DIM * entry_size];
    let (crs, encoded_db, sk) = setup(&p, &database, entry_size, &mut sampler).expect("setup");

    let (_state, mut query) = query(&crs, 0, &encoded_db.config, &sk, &mut sampler).expect("query");
    let keys = query
        .inspiring_packing_keys
        .as_mut()
        .expect("the InspiRING path inlines packing keys");
    let honest_width = keys.num_to_pack;
    // Any other legal width; the automorphism generator differs, so the rotation table
    // the server precomputed no longer matches these keys.
    keys.num_to_pack = if honest_width == 8 { 4 } else { 8 };

    let err = raven_inspire::pir::respond_inspiring(&crs, &encoded_db, &query)
        .expect_err("inlined keys at a foreign width must be refused, not packed");
    let msg = format!("{err}");
    assert!(
        msg.contains("width mismatch"),
        "the refusal must name the mismatch; got: {msg}"
    );
}
