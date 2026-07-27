//! `machine/v1` records over stable Engine semantic DTOs.
//!
//! The codec performs no I/O or Engine operations. Callers provide one complete
//! LF-terminated record and map decoded requests to an Engine facade.

mod codec;
mod model;

pub use codec::{
    MachineReadError, MachineWriteError, decode_request_v1, decode_server_frame_v1,
    encode_request_v1, encode_server_frame_v1, request_error_frame_v1,
};
pub use model::{
    DiagnosticSeverityV1, MachineCodeV1, MachineDiagnosticV1, MachineErrorCategoryV1,
    MachineErrorCodeV1, MachineErrorDetailsV1, MachineErrorV1, MachineOperationV1,
    MachineRequestV1, MachineResultV1, MachineStreamError, MachineTextV1, MachineValidationError,
    RequestEnvelopeV1, RequestIdV1, ResponseStreamValidatorV1, SchemaFamilyV1, ServerFrameV1,
};

/// Implemented machine schema version.
pub const MACHINE_SCHEMA_VERSION: u32 = 1;

/// Maximum bytes in one complete LF-terminated machine record.
pub const MAX_MACHINE_FRAME_BYTES: usize = 1024 * 1024;

/// Maximum JSON object or array nesting in one record.
pub const MAX_MACHINE_JSON_DEPTH: usize = 64;

/// Maximum members in one JSON object.
pub const MAX_MACHINE_OBJECT_MEMBERS: usize = 128;

/// Maximum items in one JSON array.
pub const MAX_MACHINE_ARRAY_ITEMS: usize = 4096;

/// Maximum aggregate JSON values in one record.
pub const MAX_MACHINE_VALUES: usize = 65_536;

/// Maximum request ID bytes.
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// Maximum stable code bytes.
pub const MAX_MACHINE_CODE_BYTES: usize = 64;

/// Maximum bytes in one human text field.
pub const MAX_MACHINE_TEXT_BYTES: usize = 64 * 1024;

/// Maximum diagnostics attached to one terminal error.
pub const MAX_MACHINE_DIAGNOSTICS: usize = 256;

/// Largest sequence represented exactly by interoperable JSON implementations.
pub const MAX_MACHINE_SEQUENCE: u64 = 9_007_199_254_740_991;
