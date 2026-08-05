//! Loops using this prelude are order-preserving maps over public data, so the
//! non-`parallel` sequential shims stay byte-identical to the rayon path.

#[cfg(feature = "parallel")]
pub(crate) use rayon::prelude::*;

#[cfg(not(feature = "parallel"))]
pub(crate) use seq::{IntoParIterShim, ParIterShim};

#[cfg(not(feature = "parallel"))]
mod seq {
    pub(crate) trait ParIterShim<T> {
        fn par_iter(&self) -> core::slice::Iter<'_, T>;
    }

    impl<T> ParIterShim<T> for [T] {
        fn par_iter(&self) -> core::slice::Iter<'_, T> {
            self.iter()
        }
    }

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
