//! `PirError` is feature-invariant so the public API does not shift with cargo features.

use std::fmt;

/// PIR operation error.
#[derive(Debug)]
pub struct PirError(pub String);

impl fmt::Display for PirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PirError {}

impl PirError {
    /// Wrap a message.
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

/// Failures raised by `PIR.Extract`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// `gcd(d, p) != 1`, so the tree-packed path cannot un-scale by `d^{-1} mod p`.
    DegreeNotInvertible {
        /// Ring dimension.
        d: u64,
        /// Plaintext modulus.
        p: u64,
    },
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DegreeNotInvertible { d, p } => write!(
                f,
                "extract_packed: d^{{-1}} mod p does not exist (d={d}, p={p}, gcd != 1); \
                 use parameters with gcd(ring_dim, p) == 1"
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

/// Result carrying `PirError`.
pub type Result<T> = std::result::Result<T, PirError>;

macro_rules! pir_err {
    ($($arg:tt)*) => {
        $crate::pir::error::PirError(format!($($arg)*))
    };
}

pub(crate) use pir_err;
