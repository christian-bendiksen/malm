//! Malm library entry points.

// Diagnostics carry spans, labels, and help text; boxing every parse-error
// return would obscure the code for a cold path.
#![allow(clippy::result_large_err)]

// The `failpoints` feature compiles in crash-injection sites that abort the
// process on an environment variable. It must never ship in a release build.
// `debug_assertions` is enabled in dev/test and disabled in release, so this
// fires only for `--release --features failpoints`.
#[cfg(all(feature = "failpoints", not(debug_assertions)))]
compile_error!("the `failpoints` feature must not be enabled in release builds");

pub mod api;
pub(crate) mod config;

/// Hardened parsers exposed to fuzz targets for archive traversal and
/// decompression-limit testing.
#[cfg(feature = "fuzzing")]
pub mod fuzz_api {
    pub use crate::assets::extract::{extract_tar_gz, extract_tar_xz, extract_zip};
}

pub(crate) mod app;
pub(crate) mod assets;
pub(crate) mod cas;
pub(crate) mod cli;
pub(crate) mod domain;
pub(crate) mod execution;
pub mod failpoint;
pub(crate) mod fs;
pub(crate) mod lang;
pub(crate) mod net;
pub(crate) mod output;
pub(crate) mod paths;
pub(crate) mod planning;
pub(crate) mod policy;
pub(crate) mod sanitize;
pub(crate) mod source;
pub(crate) mod state;
pub(crate) mod status;
pub(crate) mod workflow;
