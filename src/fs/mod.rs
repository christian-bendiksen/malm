//! Filesystem primitives: atomic writes, path identity checks, advisory
//! locking, and copy/move helpers.

pub mod atomic;
pub mod inspect;
pub mod lock;
pub mod util;
