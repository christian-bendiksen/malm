//! Typed language model and compilation pipeline. Parsing builds the AST,
//! resolution merges extensions and profiles, and compilation expands typed
//! module scopes into validated outputs without mutating the filesystem.

pub mod artifact;
pub mod ast;
pub mod budget;
pub mod compile;
pub mod config_file;
pub mod diag;
pub mod doctor;
pub mod expand;
pub(crate) mod kdl_util;
pub mod parse;
pub mod render;
pub mod resolve;
pub mod scope;
pub mod text;
pub mod typecheck;
pub mod value;
