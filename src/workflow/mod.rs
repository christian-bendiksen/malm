//! CLI workflows that connect config loading, planning, policy, and execution.

pub mod apply;
pub mod bookkeeping;
pub mod check;
pub mod checkout;
pub mod destroy;
pub mod disable;
pub mod doctor;
pub mod enable;
mod frozen_plan;
pub mod fsck;
pub mod gc;
mod pipeline;
pub mod plan;
pub mod policy_gate;
pub mod profiles;
pub mod recover;
pub mod render;
pub mod risk_prompt;
pub(crate) mod source_resolution;
pub mod state_list;
pub mod status;
pub mod update;
pub mod vars;

pub(crate) fn state_cli_flag(state: &crate::domain::id::StateName) -> String {
    if state.as_str() == "default" {
        String::new()
    } else {
        format!(" --state {}", crate::lang::text::shell_word(state.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::id::StateName;

    #[test]
    fn state_cli_flag_preserves_non_default_namespaces() {
        assert_eq!(state_cli_flag(&StateName::parse("default").unwrap()), "");
        assert_eq!(
            state_cli_flag(&StateName::parse("system-models").unwrap()),
            " --state system-models"
        );
    }
}
