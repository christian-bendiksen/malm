//! Config subsystem: KDL parsing, include-aware loading, the config
//! data model, and profile selection. The language itself (modules,
//! profiles, typed values, structural nodes) lives in [`crate::lang`].
mod discovery;
pub(crate) mod kdl;
pub(crate) mod loader;
mod model;
mod profile;

pub(crate) use discovery::validate_remote_config_relative;
pub use loader::{ConfigFileKind, ConfigFileProvenance};
pub(crate) use loader::{
    LoadedConfigSource, load_local_config, load_remote_config, load_snapshot_config,
    reload_staged_config,
};
pub use model::{Config, ConfigSettings, ConflictPolicy, MetaSection, MissingSourcePolicy};
pub use profile::ProfileSelection;
