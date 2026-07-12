//! Policy overrides granted by remote-config `--allow-*` flags.
//!
//! The domain type stays independent of CLI parsing. `cli::dispatch` converts
//! clap's `RemotePolicyOverrideFlags` into `RemotePolicyOverrides`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct RemotePolicyOverrides {
    pub external_symlink_sources: bool,
    pub outside_home: bool,
    pub unverified_assets: bool,
    pub secrets: bool,
}
