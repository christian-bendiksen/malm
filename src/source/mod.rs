//! Resolves trusted local paths and untrusted Git URLs into source trees and
//! content-addressed snapshots.

pub mod git;
mod git_archive;
mod git_process;
pub(crate) mod git_url;
pub mod identity;
pub mod local;
pub mod store;

pub use git::{GitReference, SourceSpec};
pub use identity::{ResolvedSource, SourceIdentity, SourceKind, TrustMode};
