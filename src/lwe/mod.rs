//! LWE encryption over Z_q^d: `b = -<a, s> + e + delta*m`, `delta = floor(q/p)`.
//!
//! Under a CRS the vector `a` is public, so a query carries only `b`.
//!
//! ```
//! use raven_inspire::lwe::{LweSecretKey, LweCiphertext};
//! use raven_inspire::math::GaussianSampler;
//! use raven_inspire::math::mod_q::DEFAULT_Q;
//!
//! let mut sampler = GaussianSampler::from_os_entropy(3.2)?;
//! let sk = LweSecretKey::generate(256, DEFAULT_Q, &mut sampler);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod enc;
mod types;

pub use types::{LweCiphertext, LweSecretKey};
