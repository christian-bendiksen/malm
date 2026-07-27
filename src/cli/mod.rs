//! Contains the CLI adapters and command dispatcher.
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::{EngineConfig, StoreAccess};

pub mod args;
mod contracts;
mod deployment;
pub mod dispatch;
mod ids;
mod interactive;
mod machine;
mod output;
mod store;

pub use args::{
    Args, Cmd, ColorChoice, Dispatch, LockCmd, OutputFormat, OutputOptions, RetentionObjectKind,
    StoreCmd,
};

pub(super) struct SuccessorEnvironment {
    home: Option<PathBuf>,
    state_root: PathBuf,
}

impl SuccessorEnvironment {
    pub(super) fn ambient() -> Result<Self> {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let xdg_state_home = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from);
        let state_root = malm_root::resolve_root(home.as_deref(), xdg_state_home.as_deref())?;
        Ok(Self { home, state_root })
    }

    pub(super) fn engine_config(&self, access: StoreAccess) -> Result<EngineConfig> {
        Ok(EngineConfig::new(&self.state_root, access)?)
    }

    pub(super) fn home(&self) -> Result<&Path> {
        Ok(malm_root::require_home(self.home.as_deref())?)
    }

    pub(super) fn state_root(&self) -> &Path {
        &self.state_root
    }
}
