//! Clap definitions for global options and commands.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(clap::Args, Debug, Default, Clone)]
pub struct RemotePolicyOverrideFlags {
    /// Allow external symlink sources
    #[arg(long)]
    pub allow_external_symlink_sources: bool,
    /// Allow destinations outside your home dir
    #[arg(long)]
    pub allow_outside_home: bool,
    /// Allow remote assets without SHA256 checksums
    #[arg(long)]
    pub allow_unverified_assets: bool,
    /// Allow writing into credential stores
    #[arg(long)]
    pub allow_secrets: bool,
}

#[derive(Parser)]
#[command(name = "malm", version, about = "Declarative configuration manager")]
pub struct Args {
    /// Override the path to the local config repo
    #[arg(short, long, global = true)]
    pub repo: Option<PathBuf>,
    /// Path to the malm.kdl file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,
    /// The profile to evaluate
    #[arg(short, long, global = true)]
    pub profile: Option<String>,
    /// The state namespace to use
    #[arg(short, long, default_value = "default", global = true)]
    pub state: String,
    /// Format command output as JSON.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Deploy a local or remote configuration
    Apply {
        source: Option<String>,
        #[arg(long, short = 'y')]
        yes: bool,
        /// Deprecated alias for --trust-remote --allow-local-includes
        #[arg(long, hide = true)]
        trust: bool,
        #[arg(long)]
        /// Trust this remote repository
        trust_remote: bool,
        #[arg(long)]
        /// Let a remote config read local files it requests via `~/` or absolute includes
        allow_local_includes: bool,
        #[arg(long)]
        /// Choose a commit
        commit: Option<String>,
        #[arg(long)]
        /// Choose a branch
        branch: Option<String>,
        #[arg(long)]
        /// Choose a tag
        tag: Option<String>,
        #[arg(long)]
        /// Track the repository
        track: bool,
        #[arg(long)]
        /// Deploy to a disabled state and re-enable it
        reenable: bool,
        #[command(flatten)]
        allow: RemotePolicyOverrideFlags,
        /// Permit asset downloads from non-public hosts (private IPs, localhost,
        /// cloud metadata endpoints). Off by default as an SSRF defence.
        #[arg(long)]
        allow_ssrf: bool,
    },
    /// Evaluate a config and show the plan without applying
    Plan {
        source: Option<String>,
        #[arg(long)]
        /// Choose repo branch
        branch: Option<String>,
        #[arg(long)]
        /// Choose repo tag
        tag: Option<String>,
        #[arg(long)]
        /// Choose repo commit
        commit: Option<String>,
        /// Deprecated alias for --allow-local-includes
        #[arg(long, hide = true)]
        trust: bool,
        #[arg(long)]
        /// Read local includes requested by a remote config
        allow_local_includes: bool,
        #[arg(long, short = 'v')]
        /// Show all info
        verbose: bool,
    },
    /// Apply the latest commits from tracked remote
    Update {
        #[arg(long, short = 'y')]
        yes: bool,
        #[arg(long)]
        /// Grant the tracked remote permission to read local files it
        /// requests via `~/` or absolute includes (persisted for future updates)
        allow_local_includes: bool,
        #[command(flatten)]
        allow: RemotePolicyOverrideFlags,
        /// Permit asset downloads from non-public hosts (private IPs, localhost,
        /// cloud metadata endpoints). Off by default as an SSRF defence.
        #[arg(long)]
        allow_ssrf: bool,
    },
    /// Detect drift between system and the applied config
    Status {
        #[arg(long, short = 'q')]
        quiet: bool,
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Validate the configuration: every module API, profile override,
    /// fragment, reference, and generated document
    #[command(alias = "validate")]
    Check {
        source: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        commit: Option<String>,
        /// Compile and validate every declared profile, not only the selected one
        #[arg(long)]
        all_profiles: bool,
        /// Check a single module's API and outputs
        #[arg(long)]
        module: Option<String>,
        #[command(flatten)]
        allow: RemotePolicyOverrideFlags,
    },
    /// Render a profile's generated outputs into a directory with a
    /// deterministic manifest
    Render {
        /// Directory to write rendered outputs into
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
    /// Check the requirements (commands, files, features) every active
    /// module declares
    Doctor {},
    /// List declared profiles and identify inheritance-only abstract profiles
    Profiles {
        /// Show only profiles that may be selected for plan/apply/render
        #[arg(long)]
        selectable: bool,
    },
    /// Print the resolved template variables for a config
    Vars { source: Option<String> },
    /// Inspect and manage transactional state history
    State {
        #[command(subcommand)]
        cmd: StateCmd,
    },
}

#[derive(Subcommand)]
pub enum StateCmd {
    /// List all recorded states and their deployment status
    #[command(alias = "ls")]
    List,
    /// Show the history of applied transactions
    Log,
    /// Checkout a previously recorded transaction.
    Checkout {
        id: String,
        #[arg(long, short = 'y')]
        yes: bool,
        /// Re-hash the source snapshot against its content address first
        #[arg(long)]
        verify: bool,
    },
    /// Tear down a state: remove everything it deployed and delete its records
    Destroy {
        /// State to destroy; defaults to --state when that names a non-default state
        name: Option<String>,
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Prune old and unused transactions
    Prune {
        /// Keep the newest N transactions across all states
        #[arg(long, default_value = "5")]
        keep: usize,
        /// Keep the newest N transactions in each state instead (replaces --keep's global window)
        #[arg(long)]
        keep_per_state: Option<usize>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Prune despite unreadable state metadata; everything the affected
        /// state's history references is retained instead of collected
        #[arg(long)]
        force: bool,
    },
    /// Show how much disk space transactions and cached objects use
    Usage {
        /// Keep the newest N transactions across all states
        #[arg(long, default_value = "5")]
        keep: usize,
        /// Keep the newest N transactions in each state instead (replaces --keep's global window)
        #[arg(long)]
        keep_per_state: Option<usize>,
    },
    /// Protect a transaction from pruning
    Pin { reference: String },
    /// Remove a transaction's pin
    Unpin { reference: String },
    /// Remove a state's deployed files but keep its records for `enable`
    Disable {
        /// State to disable; defaults to --state
        name: Option<String>,
        #[arg(long, short = 'y')]
        yes: bool,
        /// Disable even when some owned targets were modified and cannot be
        /// safely removed; they stay in place and remain tracked
        #[arg(long)]
        keep_modified: bool,
        /// Show what would be removed or kept without changing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Restore the deployment a state had when it was disabled
    Enable {
        /// State to enable; defaults to --state
        name: Option<String>,
        #[arg(long, short = 'y')]
        yes: bool,
        /// Redeploy over targets `disable --keep-modified` left in place
        /// (the modified files are backed up in the new transaction first)
        #[arg(long)]
        replace_kept: bool,
    },
    /// Check state records for consistency problems
    #[command(visible_alias = "doctor")]
    Fsck {
        /// Also re-hash active source snapshots against their content address
        #[arg(long)]
        verify_objects: bool,
    },
    /// Repair an interrupted transaction (undo partial changes or finish it)
    Recover {
        /// Transaction to recover (id or alias prefix)
        reference: Option<String>,
        /// Recover every interrupted transaction
        #[arg(long, conflicts_with = "reference")]
        all: bool,
        /// Show what would be done without changing anything
        #[arg(long)]
        dry_run: bool,
        #[arg(long, short = 'y')]
        yes: bool,
    },
}
