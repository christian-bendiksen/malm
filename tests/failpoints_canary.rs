//! Prevents the crash-consistency suite from being skipped silently.
//!
//! A bare `cargo test` excludes every file guarded by
//! `#![cfg(feature = "failpoints")]`, including the commit crash and race,
//! adapter recovery, prepare publication, and syscall trace suites. Those tests
//! cover durable state transitions, so passing without them is misleading.
//!
//! This file always compiles. When the feature is absent, it fails with the
//! required command:
//!
//!     cargo test --features failpoints

#[test]
fn failpoints_suite_requires_the_failpoints_feature() {
    #[cfg(not(feature = "failpoints"))]
    panic!(
        "the crash-consistency test suite is compiled out.\n\
         Commit crash, race, adapter-recovery, prepare-publication, and \
         syscall-trace tests are gated behind `#![cfg(feature = \"failpoints\")]` \
         and will not run without the feature.\n\
         Run the full suite with:\n    \
         cargo test --features failpoints"
    );

    #[cfg(feature = "failpoints")]
    {
        // This branch succeeds only when the crash suites are compiled in.
    }
}
