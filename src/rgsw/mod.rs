//! RGSW encryption: a `2*ell x 2` matrix of RLWE rows over the gadget powers.
//!
//! Its point is the external product `RLWE(m0) x RGSW(m1) -> RLWE(m0*m1)`, which
//! multiplies by an encrypted value with controlled noise growth.

mod external_product;
mod types;

pub use external_product::{
    external_product, external_product_with_ntt_rgsw, gadget_decompose, gadget_reconstruct,
    rgsw_rows_to_ntt, RgswRowsNtt,
};
pub use types::{GadgetVector, RgswCiphertext, SeededRgswCiphertext};
