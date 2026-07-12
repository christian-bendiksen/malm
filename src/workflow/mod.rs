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
