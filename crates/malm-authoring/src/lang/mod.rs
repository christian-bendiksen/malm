//! Typed language model and compilation pipeline. Parsing builds the AST,
//! resolution merges extensions and profiles, and compilation expands typed
//! module scopes into validated outputs without mutating the filesystem.

// Diagnostics carry their reporting context by value and travel only on cold
// error paths, so boxing large errors would add unnecessary indirection.
#![allow(clippy::result_large_err)]

pub mod artifact;
pub mod ast;
pub mod budget;
pub mod compile;
pub mod config_file;
pub mod diag;
pub mod expand;
pub(crate) mod kdl_util;
pub mod parse;
pub mod render;
pub mod resolve;
pub mod scope;
pub mod text;
pub mod typecheck;
pub mod value;
