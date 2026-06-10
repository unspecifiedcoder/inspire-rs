//! Byte budget for the shipped d=2048 client session (CRS + packing key).
//!
//! Separates two cost axes:
//!   - transferred / persisted bytes (bincode-serialized): the CRS the
//!     client downloads plus the y_body packing key it uploads/persists;
//!   - resident-only bytes: the rotation tables (`y_all*`) and pack-params
//!     automorph tables, which are `#[serde(skip)]` and live only in RAM.
//!
//! Regression guard: asserts (1) the shipped CRS stays under 2 MiB, so a large public
//! matrix cannot re-enter the client wire format, and (2) a query decodes byte-identically
//! through a serialized-then-deserialized CRS at the production cell - the gate that
//! actually guards a `ServerCrs` wire-format change.
//!
//! Run: `cargo test --release --test zz_session_byte_profile -- --nocapture`.

use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::pir::{extract_inspiring, query, respond_inspiring, ServerCrs};
use raven_inspire::setup;
use serde::Serialize;

fn ssize<T: Serialize>(v: &T) -> u64 {
    bincode::serialized_size(v).expect("serialized_size")
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn poly_rows_bytes<T: Serialize>(rows: &[Vec<T>]) -> (usize, u64) {
    let count = rows.iter().map(|r| r.len()).sum();
    let bytes = rows.iter().flat_map(|r| r.iter()).map(|p| ssize(p)).sum();
    (count, bytes)
}

fn profile(entry_size: usize) {
    let params = InspireParams::secure_128_d2048();
    let d = params.ring_dim;
    let mut sampler = GaussianSampler::new(params.sigma);

    let db = vec![0u8; d * entry_size];
    let (crs, encoded_db, rlwe_sk) = setup(&params, &db, entry_size, &mut sampler).expect("setup");

    let galois = ssize(&crs.galois_keys);
    let crs_total = ssize(&crs);
    let rlwe = ssize(&rlwe_sk);

    let pp = PackParams::new(&crs.params, crs.inspiring_num_columns);
    let pp_resident = ssize(&pp);
    let keys = ClientPackingKeys::generate(&rlwe_sk, &pp, crs.inspiring_w_seed, &mut sampler);
    let y_body = ssize(&keys.y_body);
    let z_body = ssize(&keys.z_body);
    let (n_yall, y_all) = poly_rows_bytes(&keys.y_all);
    let (_n_yall_ntt, y_all_ntt) = poly_rows_bytes(&keys.y_all_ntt);
    let (_n_ybar, y_bar) = poly_rows_bytes(&keys.y_bar_all);
    let (_n_ybar_ntt, y_bar_ntt) = poly_rows_bytes(&keys.y_bar_all_ntt);

    let transferred = crs_total + y_body + z_body + rlwe;
    let resident = transferred + pp_resident + y_all + y_all_ntt + y_bar + y_bar_ntt;

    eprintln!("================================================================");
    eprintln!(
        "d={d}  entry_size={entry_size} B  num_columns(gamma)={}  num_to_pack={}  y_all rotations={n_yall}",
        crs.inspiring_num_columns, pp.num_to_pack
    );
    eprintln!("---- transferred / persisted (bincode-serialized) ----");
    eprintln!("  galois_keys          {:>10.2} MiB", mib(galois));
    eprintln!("  ServerCrs total      {:>10.2} MiB", mib(crs_total));
    eprintln!("  y_body (+z_body)     {:>10.2} MiB", mib(y_body + z_body));
    eprintln!("  rlwe_sk              {:>10.2} MiB", mib(rlwe));
    eprintln!("  >>> TRANSFERRED      {:>10.2} MiB", mib(transferred));
    eprintln!("---- resident-only (serde-skip, RAM) ----");
    eprintln!("  pack_params tables   {:>10.2} MiB", mib(pp_resident));
    eprintln!("  y_all                {:>10.2} MiB", mib(y_all));
    eprintln!("  y_all_ntt            {:>10.2} MiB", mib(y_all_ntt));
    eprintln!(
        "  y_bar_all (+ntt)     {:>10.2} MiB",
        mib(y_bar + y_bar_ntt)
    );
    eprintln!("  >>> RESIDENT TOTAL   {:>10.2} MiB", mib(resident));

    // Size guard: a >2 MiB CRS means a large field (e.g. a public a-matrix) re-entered
    // the client wire format.
    assert!(
        crs_total < 2 * 1024 * 1024,
        "ServerCrs is {:.2} MiB; expected < 2 MiB. A >2 MiB CRS means a large field \
         (e.g. a reintroduced public a-matrix) crept back into the client wire format.",
        mib(crs_total)
    );

    // Wire-format decode gate at the production cell: serialize -> deserialize the CRS,
    // then run query -> respond -> extract through the DESERIALIZED CRS and assert the
    // planted entry decodes byte-identical. A field wrongly dropped on the wire breaks this.
    let crs2: ServerCrs = bincode::deserialize(&bincode::serialize(&crs).expect("serialize crs"))
        .expect("deserialize crs");
    let (state, q) = query(&crs2, 0, &encoded_db.config, &rlwe_sk, &mut sampler).expect("query");
    let response = respond_inspiring(&crs2, &encoded_db, &q).expect("respond");
    let decoded = extract_inspiring(&crs2, &state, &response, entry_size).expect("extract");
    assert_eq!(
        decoded.as_slice(),
        &db[0..entry_size],
        "production-cell decode through a deserialized CRS must match the planted entry"
    );
}

#[test]
fn session_byte_profile() {
    for es in [32usize, 256, 512] {
        profile(es);
    }
}
