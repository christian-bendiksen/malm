//! Adapts store lifecycle operations to the human CLI.

use anyhow::Result;

use crate::cli::output::{Output, Tone, json_path};
use crate::cli::{StoreCmd, SuccessorEnvironment};
use crate::{Engine, EngineOperation, StoreStatus};

pub fn run(command: &StoreCmd, output: &Output) -> Result<()> {
    let contract = crate::cli::contracts::store_contract(command);
    let access = contract
        .effect()
        .store_access()
        .expect("store commands have a fixed store-access effect");
    let environment = SuccessorEnvironment::ambient()?;
    let config = environment.engine_config(access)?;
    let engine = Engine::new(config, output.engine_ports(crate::EnginePorts::system()));
    let status = match command {
        StoreCmd::Status => {
            contract.assert_engine_operation(EngineOperation::StoreStatus);
            engine.store_status()?
        }
        StoreCmd::Initialize => {
            contract.assert_engine_operation(EngineOperation::InitializeStore);
            engine.initialize_store()?.status()
        }
    };
    output.emit(
        "ok",
        || {
            serde_json::json!({
                "status": status_label(status),
                "path": json_path(environment.state_root()),
            })
        },
        |rendered| {
            let (title, tone) = match status {
                StoreStatus::Absent => ("Store is not initialized", Tone::Neutral),
                StoreStatus::Uninitialized => ("Store needs initialization", Tone::Attention),
                StoreStatus::Ready => ("Store is ready", Tone::Success),
            };
            rendered.push_str(&format!(
                "{}\n  Path    {}\n  Status  {}\n",
                output.heading(title, tone),
                environment.state_root().display(),
                status_label(status)
            ));
            if !matches!(status, StoreStatus::Ready) {
                rendered.push_str("\nNext\n  malm store init\n");
            }
        },
    )
}

const fn status_label(status: StoreStatus) -> &'static str {
    match status {
        StoreStatus::Absent => "absent",
        StoreStatus::Uninitialized => "uninitialized",
        StoreStatus::Ready => "ready",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_status_has_stable_human_text() {
        assert_eq!(status_label(StoreStatus::Absent), "absent");
        assert_eq!(status_label(StoreStatus::Uninitialized), "uninitialized");
        assert_eq!(status_label(StoreStatus::Ready), "ready");
    }
}
