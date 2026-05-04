//! Error handling for PIR module
//!
//! Provides a stable `PirError` type that works across all feature configurations.
//! This ensures the public API doesn't change based on enabled features.

use std::fmt;

/// PIR operation error
///
/// A simple, stable error type for PIR operations that works in all environments
/// including WASM. This type is always the same regardless of feature flags.
#[derive(Debug)]
pub struct PirError(pub String);

impl fmt::Display for PirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PirError {}

impl PirError {
    /// Create a new PIR error with the given message
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl From<std::io::Error> for PirError {
    fn from(err: std::io::Error) -> Self {
        Self(err.to_string())
    }
}

impl From<bincode::Error> for PirError {
    fn from(err: bincode::Error) -> Self {
        Self(err.to_string())
    }
}

/// Errors that can arise during `PIR.Extract`.
///
/// Currently only the tree-packed (`extract_packed`) path can fail at extract
/// time: when `gcd(d, p) != 1`, the modular inverse `d^{-1} mod p` does not
/// exist, so the d-scaling un-pack cannot recover the column values. The
/// pre-fork code silently substituted `1` for the missing inverse and
/// returned d-scaled garbage; the typed variant surfaces the misuse instead.
///
/// A converting `From<ExtractError> for PirError` impl is provided so
/// callers that already plumb `Result<_, PirError>` keep working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// The ring dimension `d` is not invertible modulo the plaintext modulus
    /// `p` (i.e. `gcd(d, p) != 1`), so `extract_packed` cannot un-scale the
    /// packed column values. Use a parameter set with `gcd(ring_dim, p) == 1`
    /// (e.g. p=65537 / d=2048) or use `validate_strict_tree_packed` at
    /// param-construction time to reject this configuration earlier.
    DegreeNotInvertible {
        /// Ring dimension that failed the gcd check.
        d: u64,
        /// Plaintext modulus that failed the gcd check.
        p: u64,
    },
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DegreeNotInvertible { d, p } => write!(
                f,
                "extract_packed: d^{{-1}} mod p does not exist (d={}, p={}, gcd != 1); \
                 use parameters with gcd(ring_dim, p) == 1",
                d, p
            ),
        }
    }
}

impl std::error::Error for ExtractError {}

impl From<ExtractError> for PirError {
    fn from(err: ExtractError) -> Self {
        Self(err.to_string())
    }
}

/// Result type for PIR operations
///
/// Always uses `PirError` regardless of feature flags for API stability.
pub type Result<T> = std::result::Result<T, PirError>;

/// Create a PirError with format string support
macro_rules! pir_err {
    ($($arg:tt)*) => {
        $crate::pir::error::PirError(format!($($arg)*))
    };
}

pub(crate) use pir_err;
