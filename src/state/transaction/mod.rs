//! The transaction journal: ids, the manifest model with the ApplyPhase
//! recovery state machine, and the on-disk store.

mod id;
mod model;
mod store;

pub use id::{new_transaction_id, transaction_alias};
pub use model::{
    ApplyMetadataIntent, ApplyPhase, DesiredAsset, DesiredLink, MIN_SUPPORTED_MANIFEST_VERSION,
    OperationStatus, PathKind, PreviousState, RecordedOp, TRANSACTION_MANIFEST_VERSION,
    TransactionKind, TransactionManifest, TransactionMeta, TransactionStatus,
};
pub use store::{TransactionStore, transactions_dir};
