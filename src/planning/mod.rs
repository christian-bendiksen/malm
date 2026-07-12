//! Turns a loaded config into a validated plan of filesystem operations.

pub mod assets;
pub mod destination;
pub mod evaluation;
pub mod graph;
pub(crate) mod output;
pub mod plan;
pub mod planner;
pub(crate) mod stale;
