//! Prevent the crash-consistency suite from being skipped silently.
//!
//! A bare `cargo test` compiles out every file guarded by
//! `#![cfg(feature = "failpoints")]`: `crash_matrix`, `disable_enable`, and `recover`.
//! Those tests cover durable state transitions, so a passing run without them
//! is misleading.
//!
//! This file always compiles and fails with the required command when the
//! feature is missing:
//!
//!     cargo test --features failpoints

#[test]
fn failpoints_suite_requires_the_failpoints_feature() {
    #[cfg(not(feature = "failpoints"))]
    panic!(
        "the crash-consistency test suite is compiled out.\n\
         33 tests across crash_matrix, disable_enable, and recover are gated \
         behind `#![cfg(feature = \"failpoints\")]` and will not run without \
         the feature.\n\
         Run the full suite with:\n    \
         cargo test --features failpoints"
    );

    #[cfg(feature = "failpoints")]
    {
        // Reaching this branch confirms the `failpoints` feature is enabled.
    }
}
