//! Defines the public command graph and maps it to semantic CLI operations.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(ValueEnum, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(ValueEnum, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(clap::Args, Clone, Copy, Debug, Default)]
pub struct OutputOptions {
    /// Select human or structured JSON output
    #[arg(long, value_enum, default_value_t, global = true)]
    pub format: OutputFormat,

    /// Control ANSI styling for human output
    #[arg(long, value_enum, default_value_t, global = true)]
    pub color: ColorChoice,

    /// Include technical identities and detailed records
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
}

#[derive(clap::Args, Debug, Default, Clone)]
pub struct TargetOptions {
    /// Target authority as NAME=ABSOLUTE_PATH; defaults to home=$HOME
    #[arg(long = "target", value_name = "NAME=ABSOLUTE_PATH")]
    pub targets: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum RetentionObjectKind {
    PreparedPlan,
    StateGeneration,
    ArtifactBlob,
    PackObject,
    CanonicalFile,
    CanonicalSymlink,
    CanonicalTree,
}

#[derive(clap::Args, Debug)]
pub struct LockOptions {
    /// Root of the source pack; defaults to the current directory
    #[arg(long, value_name = "PACK_ROOT", default_value = ".")]
    pub source: PathBuf,
    /// Absolute trusted Git executable; defaults to `git` found on PATH
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    pub git_executable: Option<PathBuf>,
    /// Root-relative local locator explicitly granted for discovery
    #[arg(long = "allow-local", value_name = "LOCATOR")]
    pub local_locators: Vec<String>,
    /// Normalized HTTPS Git URL explicitly granted for discovery
    #[arg(long = "allow-git", value_name = "HTTPS_URL")]
    pub git_urls: Vec<String>,
    /// Exact Git source and its caller-owned scratch directory
    #[arg(
        long = "git-scratch",
        num_args = 4,
        action = clap::ArgAction::Append,
        value_names = ["HTTPS_URL", "GIT_OBJECT_ID", "PACK_SUBDIR", "ABSOLUTE_PATH"]
    )]
    pub git_scratch: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum LockCmd {
    /// Discover the complete source graph and create an absent malm.lock
    Create(LockOptions),
    /// Rediscover the complete source graph and update malm.lock
    Update(LockOptions),
}

#[derive(clap::Args, Debug)]
pub struct StaticPlanOptions {
    /// Source pack root; defaults to the current directory
    #[arg(long)]
    pub source: Option<PathBuf>,
    #[arg(long)]
    pub lock: Option<PathBuf>,
    /// Use only verified pack objects already present in the store
    #[arg(long)]
    pub cached: bool,
    /// Select a profile; defaults to the source's declared default
    #[arg(long)]
    pub profile: Option<String>,
    #[arg(long, default_value = "default")]
    pub namespace: String,
    #[arg(long, default_value = "home")]
    pub target_authority: String,
    /// Target authority as NAME=ABSOLUTE_PATH; defaults to home=$HOME
    #[arg(long = "target", value_name = "NAME=ABSOLUTE_PATH")]
    pub targets: Vec<String>,
    /// Root-relative local locator explicitly granted for acquisition
    #[arg(
        long = "allow-local",
        conflicts_with = "cached",
        value_name = "LOCATOR"
    )]
    pub local_locators: Vec<String>,
    /// Normalized HTTPS Git URL explicitly granted for acquisition
    #[arg(
        long = "allow-git",
        conflicts_with = "cached",
        value_name = "HTTPS_URL"
    )]
    pub git_urls: Vec<String>,
    /// Missing locked content digest mapped to caller-owned scratch
    #[arg(
        long = "git-scratch",
        conflicts_with = "cached",
        value_name = "DIGEST=ABSOLUTE_PATH"
    )]
    pub git_scratch: Vec<String>,
    /// Absolute trusted Git executable; defaults to `git` found on PATH
    #[arg(long, conflicts_with = "cached", value_name = "ABSOLUTE_PATH")]
    pub git_executable: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct DeployArgs {
    #[command(flatten)]
    pub output: OutputOptions,
    #[command(flatten)]
    pub plan: StaticPlanOptions,
    /// Apply without prompting when no finding requires approval
    #[arg(long)]
    pub yes: bool,
}

#[derive(clap::Args, Debug)]
pub struct TrackOptions {
    /// Normalized HTTPS URL for the tracked root repository
    #[arg(long)]
    pub source_url: String,
    /// Bounded symbolic Git selector, such as refs/heads/main
    #[arg(long)]
    pub selector: String,
    /// Repository-relative pack root
    #[arg(long, default_value = ".")]
    pub source_subdir: String,
    /// Pack-root-relative configuration entry point
    #[arg(long, default_value = "malm.kdl")]
    pub config_entry: String,
    /// Select a profile; defaults to the source's declared default
    #[arg(long)]
    pub profile: Option<String>,
    #[arg(long, default_value = "default")]
    pub namespace: String,
    #[arg(long, default_value = "home")]
    pub target_authority: String,
    #[arg(long = "target", value_name = "NAME=ABSOLUTE_PATH")]
    pub targets: Vec<String>,
    #[arg(long = "allow-local", value_name = "LOCATOR")]
    pub local_locators: Vec<String>,
    #[arg(long = "allow-git", value_name = "HTTPS_URL")]
    pub git_urls: Vec<String>,
    #[arg(long = "git-scratch", value_name = "DIGEST=ABSOLUTE_PATH")]
    pub git_scratch: Vec<String>,
    /// Absolute trusted Git executable used for resolution and acquisition
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    pub git_executable: PathBuf,
    /// Absolute caller-owned scratch directory for the tracked root
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    pub root_scratch: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct RefreshOptions {
    #[arg(long, default_value = "default")]
    pub namespace: String,
    #[arg(long = "target", value_name = "NAME=ABSOLUTE_PATH")]
    pub targets: Vec<String>,
    #[arg(long = "git-scratch", value_name = "DIGEST=ABSOLUTE_PATH")]
    pub git_scratch: Vec<String>,
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    pub git_executable: PathBuf,
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    pub root_scratch: PathBuf,
}

#[derive(Subcommand, Debug)]
pub enum SourceCmd {
    /// Check every module, profile, and reference without writing state
    Check {
        /// Source root; defaults to the current directory
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Render one profile into an explicit output directory
    Render {
        /// Source root; defaults to the current directory
        #[arg(long)]
        source: Option<PathBuf>,
        /// Profile to render; defaults to the declared default
        #[arg(long)]
        profile: Option<String>,
        /// Directory receiving the rendered tree
        #[arg(long, short = 'o')]
        output: PathBuf,
        /// Apply declared machine-local overlays
        #[arg(long)]
        overlays: bool,
    },
    /// Show resolved source inputs with provenance
    Vars {
        /// Source root; defaults to the current directory
        #[arg(long)]
        source: Option<PathBuf>,
        /// Profile to inspect; defaults to the declared default
        #[arg(long)]
        profile: Option<String>,
        /// Restrict output to one input name
        name: Option<String>,
        /// Apply declared machine-local overlays
        #[arg(long)]
        overlays: bool,
    },
    /// Create or update the exact source dependency graph
    Lock {
        #[command(subcommand)]
        command: LockCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum PlanArtifactCmd {
    /// List the artifacts retained by a plan
    List {
        /// Full pp- ID or typed plan:<hex> short ID
        #[arg(value_name = "PLAN")]
        plan_id: String,
    },
    /// Show metadata for one retained artifact
    Show {
        /// Full pp- ID or typed plan:<hex> short ID
        #[arg(value_name = "PLAN")]
        plan_id: String,
        id: String,
    },
    /// Export one retained artifact to a host path
    Export {
        /// Full pp- ID or typed plan:<hex> short ID
        #[arg(value_name = "PLAN")]
        plan_id: String,
        id: String,
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum RestorePointCmd {
    /// Add a retained generation restore point
    Add {
        /// Full sha256- ID or typed gen:<hex> short ID
        #[arg(value_name = "GENERATION")]
        generation: String,
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Drop a retained generation restore point
    Drop {
        /// Full sha256- ID or typed gen:<hex> short ID
        #[arg(value_name = "GENERATION")]
        generation: String,
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
}

#[derive(Subcommand, Debug)]
pub enum PlanRetentionCmd {
    /// Replace the bounded predecessor-history policy
    SetHistory {
        generations: u32,
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Add an explicit immutable-object retention pin
    Pin {
        #[arg(value_enum)]
        kind: RetentionObjectKind,
        /// Full canonical ID or the short-ID domain selected by KIND
        #[arg(value_name = "OBJECT")]
        object: String,
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Remove an explicit immutable-object retention pin
    Unpin {
        #[arg(value_enum)]
        kind: RetentionObjectKind,
        /// Full canonical ID or the short-ID domain selected by KIND
        #[arg(value_name = "OBJECT")]
        object: String,
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Add or drop retained generation restore points
    RestorePoint {
        #[command(subcommand)]
        command: RestorePointCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum PlanCmd {
    /// Create a deployment plan from a source tree
    Create(StaticPlanOptions),
    /// Create the initial plan for a moving Git source
    Track(TrackOptions),
    /// Create an update plan from retained tracking authority
    Refresh(RefreshOptions),
    /// Create an offline profile-change plan from retained inputs
    SwitchProfile {
        profile: String,
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Create a restoration plan from a retained generation
    Restore {
        /// Full sha256- ID or typed gen:<hex> short ID
        #[arg(value_name = "GENERATION")]
        generation: String,
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Create a plan that disables one namespace
    Disable {
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Create a plan that restores one disabled namespace
    Enable {
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Create a plan that removes one namespace and its history
    Remove {
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Create a retention-authority plan
    Retention {
        #[command(subcommand)]
        command: PlanRetentionCmd,
    },
    /// List durable plans in newest-first order
    List,
    /// Show one durable plan
    Show {
        /// Full pp- ID or typed plan:<hex> short ID
        #[arg(value_name = "PLAN")]
        plan_id: String,
    },
    /// Review and apply one durable plan
    Apply {
        /// Full pp- ID or typed plan:<hex> short ID
        #[arg(value_name = "PLAN")]
        plan_id: String,
        /// Exact approval digest for non-interactive application
        #[arg(long)]
        approval: Option<String>,
        #[command(flatten)]
        target: TargetOptions,
        /// Apply without prompting when no finding requires approval
        #[arg(long)]
        yes: bool,
    },
    /// Delete unreferenced durable plans and newly unreachable objects
    Delete {
        /// Full pp- IDs or typed plan:<hex> short IDs
        #[arg(required = true, num_args = 1..)]
        plan_ids: Vec<String>,
    },
    /// Inspect exact captured inputs for one plan
    Inputs {
        /// Full pp- ID or typed plan:<hex> short ID
        #[arg(value_name = "PLAN")]
        plan_id: String,
    },
    /// Inspect deterministic transform provenance for one plan
    Transforms {
        /// Full pp- ID or typed plan:<hex> short ID
        #[arg(value_name = "PLAN")]
        plan_id: String,
    },
    /// Inspect or export retained plan artifacts
    Artifact {
        #[command(subcommand)]
        command: PlanArtifactCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum GenerationCmd {
    /// Show one retained generation
    Show {
        /// Full sha256- ID or typed gen:<hex> short ID
        #[arg(value_name = "GENERATION")]
        generation: String,
        #[arg(long, default_value = "default")]
        namespace: String,
    },
    /// Show one generation's cumulative desired state
    Desired {
        /// Full sha256- ID or typed gen:<hex> short ID
        #[arg(value_name = "GENERATION")]
        generation: String,
        #[arg(long, default_value = "default")]
        namespace: String,
    },
    /// Show one generation's retention authority
    Retention {
        /// Full sha256- ID or typed gen:<hex> short ID
        #[arg(value_name = "GENERATION")]
        generation: String,
        #[arg(long, default_value = "default")]
        namespace: String,
    },
    /// Show one generation's redacted tracking authority
    Tracking {
        /// Full sha256- ID or typed gen:<hex> short ID
        #[arg(value_name = "GENERATION")]
        generation: String,
        #[arg(long, default_value = "default")]
        namespace: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum NamespaceCmd {
    /// List selected namespace generations
    List,
    /// Show one selected namespace generation
    Show {
        #[arg(long, default_value = "default")]
        namespace: String,
    },
    /// Compare desired state with managed targets
    Status {
        #[arg(long, default_value = "default")]
        namespace: String,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Show verified predecessor history
    History {
        #[arg(long, default_value = "default")]
        namespace: String,
    },
    /// Inspect retained generation records
    Generation {
        #[command(subcommand)]
        command: GenerationCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum StoreAction {
    /// Report whether the state store is absent, uninitialized, or ready
    Status,
    /// Initialize the state store descriptor
    Init,
    /// Verify the store without repair or hidden writes
    Verify {
        /// Also compare desired state with managed targets
        #[arg(long)]
        observe_targets: bool,
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Recover an interrupted target transaction
    Recover {
        #[command(flatten)]
        target: TargetOptions,
    },
    /// Remove unreferenced plans and immutable objects
    Gc {
        /// Report what would be removed without changing the store
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ObjectCmd {
    /// Inspect canonical tree objects
    Tree {
        #[command(subcommand)]
        command: TreeCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum ComponentCmd {
    /// Show the exact deterministic format-component host profile
    HostProfile,
}

#[derive(Subcommand, Debug)]
pub enum TreeCmd {
    /// Recursively show one canonical tree
    Show {
        /// Full sha256- ID or typed tree:<hex> short ID
        #[arg(value_name = "TREE")]
        tree: String,
    },
}

#[derive(Parser, Debug)]
#[command(
    name = "malm",
    version,
    about = "Deterministic, transactional configuration deployment",
    disable_help_subcommand = true
)]
pub struct Args {
    #[command(subcommand)]
    pub command: TopLevelCmd,
}

#[derive(Subcommand, Debug)]
pub enum TopLevelCmd {
    /// Plan, review, and apply configuration from source
    Deploy(DeployArgs),
    /// Check, render, inspect, and lock source inputs
    Source {
        #[command(flatten)]
        output: OutputOptions,
        #[command(subcommand)]
        command: SourceCmd,
    },
    /// Create, inspect, apply, and delete durable plans
    Plan {
        #[command(flatten)]
        output: OutputOptions,
        #[command(subcommand)]
        command: PlanCmd,
    },
    /// Inspect deployed namespaces, history, and target status
    Namespace {
        #[command(flatten)]
        output: OutputOptions,
        #[command(subcommand)]
        command: NamespaceCmd,
    },
    /// Initialize, verify, recover, and clean the state store
    Store {
        #[command(flatten)]
        output: OutputOptions,
        #[command(subcommand)]
        command: StoreAction,
    },
    /// Inspect low-level immutable objects
    Object {
        #[command(flatten)]
        output: OutputOptions,
        #[command(subcommand)]
        command: ObjectCmd,
    },
    /// Inspect the local WebAssembly component host contract
    Component {
        #[command(flatten)]
        output: OutputOptions,
        #[command(subcommand)]
        command: ComponentCmd,
    },
    /// Execute one strict machine/v1 JSONL request from stdin
    Machine,
}

#[derive(Debug)]
pub struct Invocation {
    pub command_name: &'static str,
    pub command: Cmd,
    pub output: OutputOptions,
    pub selected_profile: Option<String>,
}

#[derive(Debug)]
pub enum Dispatch {
    Human(Box<Invocation>),
    Machine,
}

impl Args {
    #[must_use]
    pub fn into_dispatch(self) -> Dispatch {
        match self.command {
            TopLevelCmd::Machine => Dispatch::Machine,
            TopLevelCmd::Deploy(arguments) => {
                let StaticPlanOptions {
                    source,
                    lock,
                    cached,
                    profile,
                    namespace,
                    target_authority,
                    targets,
                    local_locators,
                    git_urls,
                    git_scratch,
                    git_executable,
                } = arguments.plan;
                human(
                    "deploy",
                    arguments.output,
                    profile,
                    Cmd::Apply {
                        source,
                        lock,
                        cached,
                        namespace,
                        target_authority,
                        targets,
                        local_locators,
                        git_urls,
                        git_scratch,
                        git_executable,
                        yes: arguments.yes,
                    },
                )
            }
            TopLevelCmd::Source { output, command } => source_dispatch(output, command),
            TopLevelCmd::Plan { output, command } => plan_dispatch(output, command),
            TopLevelCmd::Namespace { output, command } => namespace_dispatch(output, command),
            TopLevelCmd::Store { output, command } => store_dispatch(output, command),
            TopLevelCmd::Object { output, command } => object_dispatch(output, command),
            TopLevelCmd::Component { output, command } => component_dispatch(output, command),
        }
    }
}

fn source_dispatch(output: OutputOptions, command: SourceCmd) -> Dispatch {
    match command {
        SourceCmd::Check { source } => human("source.check", output, None, Cmd::Check { source }),
        SourceCmd::Render {
            source,
            profile,
            output: destination,
            overlays,
        } => human(
            "source.render",
            output,
            profile,
            Cmd::Render {
                source,
                output: destination,
                overlays,
            },
        ),
        SourceCmd::Vars {
            source,
            profile,
            name,
            overlays,
        } => human(
            "source.vars",
            output,
            profile,
            Cmd::Vars {
                source,
                name,
                overlays,
            },
        ),
        SourceCmd::Lock { command } => {
            let name = match command {
                LockCmd::Create(_) => "source.lock.create",
                LockCmd::Update(_) => "source.lock.update",
            };
            human(name, output, None, Cmd::Lock { cmd: command })
        }
    }
}

fn plan_dispatch(output: OutputOptions, command: PlanCmd) -> Dispatch {
    match command {
        PlanCmd::Refresh(RefreshOptions {
            namespace,
            targets,
            git_scratch,
            git_executable,
            root_scratch,
        }) => human(
            "plan.refresh",
            output,
            None,
            Cmd::Update {
                namespace,
                targets,
                git_scratch,
                git_executable,
                root_scratch,
            },
        ),
        PlanCmd::Disable { namespace, target } => human(
            "plan.disable",
            output,
            None,
            Cmd::Disable { namespace, target },
        ),
        PlanCmd::Enable { namespace, target } => human(
            "plan.enable",
            output,
            None,
            Cmd::Enable { namespace, target },
        ),
        PlanCmd::Remove { namespace, target } => human(
            "plan.remove",
            output,
            None,
            Cmd::RemoveNamespace { namespace, target },
        ),
        PlanCmd::List => human("plan.list", output, None, Cmd::PlanList),
        PlanCmd::Inputs { plan_id } => {
            human("plan.inputs", output, None, Cmd::CapturedInputs { plan_id })
        }
        PlanCmd::Transforms { plan_id } => human(
            "plan.transforms",
            output,
            None,
            Cmd::TransformProvenance { plan_id },
        ),
        PlanCmd::Create(options) => {
            let StaticPlanOptions {
                source,
                lock,
                cached,
                profile,
                namespace,
                target_authority,
                targets,
                local_locators,
                git_urls,
                git_scratch,
                git_executable,
            } = options;
            human(
                "plan.create",
                output,
                profile,
                Cmd::Prepare {
                    source: source.unwrap_or_else(|| PathBuf::from(".")),
                    lock,
                    cached,
                    namespace,
                    target_authority,
                    targets,
                    local_locators,
                    git_urls,
                    git_scratch,
                    git_executable,
                },
            )
        }
        PlanCmd::Track(options) => human(
            "plan.track",
            output,
            options.profile,
            Cmd::Track {
                source_url: options.source_url,
                selector: options.selector,
                source_subdir: options.source_subdir,
                config_entry: options.config_entry,
                namespace: options.namespace,
                target_authority: options.target_authority,
                targets: options.targets,
                local_locators: options.local_locators,
                git_urls: options.git_urls,
                git_scratch: options.git_scratch,
                git_executable: options.git_executable,
                root_scratch: options.root_scratch,
            },
        ),
        PlanCmd::SwitchProfile {
            profile,
            namespace,
            target,
        } => human(
            "plan.switch-profile",
            output,
            Some(profile),
            Cmd::Switch {
                namespace,
                targets: target.targets,
            },
        ),
        PlanCmd::Restore {
            generation,
            namespace,
            target,
        } => human(
            "plan.restore",
            output,
            None,
            Cmd::Checkout {
                generation,
                namespace,
                targets: target.targets,
            },
        ),
        PlanCmd::Retention { command } => retention_dispatch(output, command),
        PlanCmd::Show { plan_id } => human(
            "plan.show",
            output,
            None,
            Cmd::Plan {
                plan_id: Some(plan_id),
            },
        ),
        PlanCmd::Apply {
            plan_id,
            approval,
            target,
            yes,
        } => human(
            "plan.apply",
            output,
            None,
            Cmd::Commit {
                plan_id: Some(plan_id),
                approval,
                targets: target.targets,
                yes,
            },
        ),
        PlanCmd::Delete { plan_ids } => human(
            "plan.delete",
            output,
            None,
            Cmd::Prune {
                plan_ids,
                dry_run: false,
            },
        ),
        PlanCmd::Artifact { command } => artifact_dispatch(output, command),
    }
}

fn retention_dispatch(output: OutputOptions, command: PlanRetentionCmd) -> Dispatch {
    match command {
        PlanRetentionCmd::SetHistory {
            generations,
            namespace,
            target,
        } => human(
            "plan.retention.set-history",
            output,
            None,
            Cmd::SetHistoryRetention {
                generations,
                namespace,
                target,
            },
        ),
        PlanRetentionCmd::Pin {
            kind,
            object,
            namespace,
            target,
        } => human(
            "plan.retention.pin",
            output,
            None,
            Cmd::Pin {
                kind,
                object,
                namespace,
                target,
            },
        ),
        PlanRetentionCmd::Unpin {
            kind,
            object,
            namespace,
            target,
        } => human(
            "plan.retention.unpin",
            output,
            None,
            Cmd::Unpin {
                kind,
                object,
                namespace,
                target,
            },
        ),
        PlanRetentionCmd::RestorePoint {
            command:
                RestorePointCmd::Add {
                    generation,
                    namespace,
                    target,
                },
        } => human(
            "plan.retention.restore-point.add",
            output,
            None,
            Cmd::AddRestorePoint {
                generation,
                namespace,
                target,
            },
        ),
        PlanRetentionCmd::RestorePoint {
            command:
                RestorePointCmd::Drop {
                    generation,
                    namespace,
                    target,
                },
        } => human(
            "plan.retention.restore-point.drop",
            output,
            None,
            Cmd::DropRestorePoint {
                generation,
                namespace,
                target,
            },
        ),
    }
}

fn artifact_dispatch(output: OutputOptions, command: PlanArtifactCmd) -> Dispatch {
    match command {
        PlanArtifactCmd::List { plan_id } => human(
            "plan.artifact.list",
            output,
            None,
            Cmd::ArtifactList { plan_id },
        ),
        PlanArtifactCmd::Show { plan_id, id } => human(
            "plan.artifact.show",
            output,
            None,
            Cmd::ArtifactMetadata { plan_id, id },
        ),
        PlanArtifactCmd::Export {
            plan_id,
            id,
            output: destination,
        } => human(
            "plan.artifact.export",
            output,
            None,
            Cmd::Artifact {
                plan_id,
                id,
                output: destination,
            },
        ),
    }
}

fn namespace_dispatch(output: OutputOptions, command: NamespaceCmd) -> Dispatch {
    match command {
        NamespaceCmd::List => human("namespace.list", output, None, Cmd::Catalog),
        NamespaceCmd::Show { namespace } => {
            human("namespace.show", output, None, Cmd::Namespace { namespace })
        }
        NamespaceCmd::Status { namespace, target } => human(
            "namespace.status",
            output,
            None,
            Cmd::Status { namespace, target },
        ),
        NamespaceCmd::History { namespace } => human(
            "namespace.history",
            output,
            None,
            Cmd::History { namespace },
        ),
        NamespaceCmd::Generation {
            command:
                GenerationCmd::Show {
                    generation,
                    namespace,
                },
        } => human(
            "namespace.generation.show",
            output,
            None,
            Cmd::Generation {
                generation,
                namespace,
            },
        ),
        NamespaceCmd::Generation {
            command:
                GenerationCmd::Desired {
                    generation,
                    namespace,
                },
        } => human(
            "namespace.generation.desired",
            output,
            None,
            Cmd::DesiredSnapshot {
                generation,
                namespace,
            },
        ),
        NamespaceCmd::Generation {
            command:
                GenerationCmd::Retention {
                    generation,
                    namespace,
                },
        } => human(
            "namespace.generation.retention",
            output,
            None,
            Cmd::Retention {
                generation,
                namespace,
            },
        ),
        NamespaceCmd::Generation {
            command:
                GenerationCmd::Tracking {
                    generation,
                    namespace,
                },
        } => human(
            "namespace.generation.tracking",
            output,
            None,
            Cmd::Tracking {
                generation,
                namespace,
            },
        ),
    }
}

fn store_dispatch(output: OutputOptions, command: StoreAction) -> Dispatch {
    match command {
        StoreAction::Verify {
            observe_targets,
            target,
        } => human(
            "store.verify",
            output,
            None,
            Cmd::Fsck {
                observe_targets,
                target,
            },
        ),
        StoreAction::Status => human(
            "store.status",
            output,
            None,
            Cmd::Store {
                cmd: StoreCmd::Status,
            },
        ),
        StoreAction::Init => human(
            "store.init",
            output,
            None,
            Cmd::Store {
                cmd: StoreCmd::Initialize,
            },
        ),
        StoreAction::Recover { target } => human(
            "store.recover",
            output,
            None,
            Cmd::Recover {
                targets: target.targets,
            },
        ),
        StoreAction::Gc { dry_run } => human(
            "store.gc",
            output,
            None,
            Cmd::Prune {
                plan_ids: Vec::new(),
                dry_run,
            },
        ),
    }
}

fn object_dispatch(output: OutputOptions, command: ObjectCmd) -> Dispatch {
    match command {
        ObjectCmd::Tree {
            command: TreeCmd::Show { tree },
        } => human(
            "object.tree.show",
            output,
            None,
            Cmd::CanonicalTree { tree },
        ),
    }
}

fn component_dispatch(output: OutputOptions, command: ComponentCmd) -> Dispatch {
    match command {
        ComponentCmd::HostProfile => human(
            "component.host-profile",
            output,
            None,
            Cmd::ComponentHostProfile,
        ),
    }
}

fn human(
    command_name: &'static str,
    output: OutputOptions,
    selected_profile: Option<String>,
    command: Cmd,
) -> Dispatch {
    Dispatch::Human(Box::new(Invocation {
        command_name,
        command,
        output,
        selected_profile,
    }))
}

/// Internal semantic operations used by the human adapter.
///
/// Their names are intentionally independent of the public command hierarchy.
#[derive(Debug)]
pub enum Cmd {
    ComponentHostProfile,
    Store {
        cmd: StoreCmd,
    },
    Lock {
        cmd: LockCmd,
    },
    Prepare {
        source: PathBuf,
        lock: Option<PathBuf>,
        cached: bool,
        namespace: String,
        target_authority: String,
        targets: Vec<String>,
        local_locators: Vec<String>,
        git_urls: Vec<String>,
        git_scratch: Vec<String>,
        git_executable: Option<PathBuf>,
    },
    Apply {
        source: Option<PathBuf>,
        lock: Option<PathBuf>,
        cached: bool,
        namespace: String,
        target_authority: String,
        targets: Vec<String>,
        local_locators: Vec<String>,
        git_urls: Vec<String>,
        git_scratch: Vec<String>,
        git_executable: Option<PathBuf>,
        yes: bool,
    },
    Check {
        source: Option<PathBuf>,
    },
    Render {
        source: Option<PathBuf>,
        output: PathBuf,
        overlays: bool,
    },
    Vars {
        source: Option<PathBuf>,
        name: Option<String>,
        overlays: bool,
    },
    Track {
        source_url: String,
        selector: String,
        source_subdir: String,
        config_entry: String,
        namespace: String,
        target_authority: String,
        targets: Vec<String>,
        local_locators: Vec<String>,
        git_urls: Vec<String>,
        git_scratch: Vec<String>,
        git_executable: PathBuf,
        root_scratch: PathBuf,
    },
    Update {
        namespace: String,
        targets: Vec<String>,
        git_scratch: Vec<String>,
        git_executable: PathBuf,
        root_scratch: PathBuf,
    },
    Switch {
        namespace: String,
        targets: Vec<String>,
    },
    Plan {
        plan_id: Option<String>,
    },
    PlanList,
    ArtifactList {
        plan_id: String,
    },
    Artifact {
        plan_id: String,
        id: String,
        output: PathBuf,
    },
    Commit {
        plan_id: Option<String>,
        approval: Option<String>,
        targets: Vec<String>,
        yes: bool,
    },
    Checkout {
        generation: String,
        namespace: String,
        targets: Vec<String>,
    },
    Recover {
        targets: Vec<String>,
    },
    Prune {
        plan_ids: Vec<String>,
        dry_run: bool,
    },
    Disable {
        namespace: String,
        target: TargetOptions,
    },
    Enable {
        namespace: String,
        target: TargetOptions,
    },
    RemoveNamespace {
        namespace: String,
        target: TargetOptions,
    },
    SetHistoryRetention {
        generations: u32,
        namespace: String,
        target: TargetOptions,
    },
    Pin {
        kind: RetentionObjectKind,
        object: String,
        namespace: String,
        target: TargetOptions,
    },
    Unpin {
        kind: RetentionObjectKind,
        object: String,
        namespace: String,
        target: TargetOptions,
    },
    AddRestorePoint {
        generation: String,
        namespace: String,
        target: TargetOptions,
    },
    DropRestorePoint {
        generation: String,
        namespace: String,
        target: TargetOptions,
    },
    Catalog,
    Namespace {
        namespace: String,
    },
    History {
        namespace: String,
    },
    Generation {
        generation: String,
        namespace: String,
    },
    DesiredSnapshot {
        generation: String,
        namespace: String,
    },
    CanonicalTree {
        tree: String,
    },
    ArtifactMetadata {
        plan_id: String,
        id: String,
    },
    CapturedInputs {
        plan_id: String,
    },
    TransformProvenance {
        plan_id: String,
    },
    Retention {
        generation: String,
        namespace: String,
    },
    Tracking {
        generation: String,
        namespace: String,
    },
    Status {
        namespace: String,
        target: TargetOptions,
    },
    Fsck {
        observe_targets: bool,
        target: TargetOptions,
    },
}

#[derive(Debug)]
pub enum StoreCmd {
    Status,
    Initialize,
}
