//! Parallelism prelude.
//!
//! With the `parallel` feature on, re-exports rayon's prelude so the respond /
//! packing-offline hot loops parallelize. With it off (the default, and the
//! client/wasm build), provides sequential `par_iter` / `into_par_iter` shims so
//! those loops compile and run without rayon. The loops are pure order-preserving
//! maps over PUBLIC data (the encoded DB polynomials, the query-derived a-polys),
//! so the sequential fallback is byte-identical to the parallel path.

#[cfg(feature = "parallel")]
pub(crate) use rayon::prelude::*;

#[cfg(not(feature = "parallel"))]
pub(crate) use seq::{IntoParIterShim, ParIterShim};

#[cfg(not(feature = "parallel"))]
mod seq {
    /// Sequential `.par_iter()`: aliases `<[T]>::iter`. `Vec<T>` auto-derefs to `[T]`.
    pub(crate) trait ParIterShim<T> {
        fn par_iter(&self) -> core::slice::Iter<'_, T>;
    }

    impl<T> ParIterShim<T> for [T] {
        fn par_iter(&self) -> core::slice::Iter<'_, T> {
            self.iter()
        }
    }

    /// Sequential `.into_par_iter()`: a range is already a sequential iterator.
    pub(crate) trait IntoParIterShim {
        type Iter: Iterator;
        fn into_par_iter(self) -> Self::Iter;
    }

    impl IntoParIterShim for core::ops::Range<usize> {
        type Iter = core::ops::Range<usize>;
        fn into_par_iter(self) -> Self::Iter {
            self
        }
    }
}
