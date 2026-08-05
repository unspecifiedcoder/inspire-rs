//! Key-switching: move an RLWE ciphertext from secret key s to key s'.
//!
//! The matrix holds `K[i] = RLWE_{s'}(s * z^i)` for the gadget powers z^i; switching
//! gadget-decomposes `a` and accumulates `(0, b) + sum_i a_i * K[i]`.

mod setup;
mod switch;

pub use setup::{
    generate_automorphism_ks_matrix, generate_ks_matrix, generate_packing_ks_matrix,
    KeySwitchingMatrix,
};
pub use switch::key_switch;
