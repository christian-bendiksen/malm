use std::fmt;

use crate::{MAX_TARGET_PATH_BYTES, MAX_TARGET_PATH_SEGMENTS};

/// Invalid primitive value supplied to the rich config model.
// `thiserror` supports `#[error(fmt = ...)]` only on enums. This struct varies
// its output by `value_len`, so its `Display` implementation remains manual.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigValueError {
    kind: &'static str,
    value_len: Option<usize>,
    reason: &'static str,
}

impl ConfigValueError {
    const fn new(kind: &'static str, value_len: Option<usize>, reason: &'static str) -> Self {
        Self {
            kind,
            value_len,
            reason,
        }
    }
}

impl ConfigValueError {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }
    #[must_use]
    pub const fn value_len(&self) -> Option<usize> {
        self.value_len
    }
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for ConfigValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(value_len) = self.value_len {
            write!(
                formatter,
                "invalid {} ({value_len} bytes): {}",
                self.kind, self.reason
            )
        } else {
            write!(formatter, "invalid {}: {}", self.kind, self.reason)
        }
    }
}

impl std::error::Error for ConfigValueError {}

/// A finite, normalized IEEE-754 value accepted by rich config/v1.
#[derive(Clone, Copy, Debug)]
pub struct FiniteFloatV1(f64);

impl FiniteFloatV1 {
    pub fn new(value: f64) -> Result<Self, ConfigValueError> {
        if !value.is_finite() {
            return Err(ConfigValueError::new(
                "config float",
                None,
                "must be finite",
            ));
        }
        Ok(Self(if value == 0.0 { 0.0 } else { value }))
    }
}

impl FiniteFloatV1 {
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl PartialEq for FiniteFloatV1 {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for FiniteFloatV1 {}

malm_types::validated_string! {
    /// A canonical UTF-8 path relative to one configured deployment target.
    pub struct TargetPathV1;
    error: ConfigValueError;
    validate: validate_target_path;
    make_error: |value, reason| ConfigValueError::new("target path", Some(value.len()), reason);
}

fn validate_target_path(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.len() > MAX_TARGET_PATH_BYTES {
        return Err("must be at most 4096 bytes");
    }
    if value.starts_with('/') {
        return Err("must be relative to the deployment target");
    }
    if value.contains('\\') {
        return Err("must use slash separators");
    }
    if value.chars().any(char::is_control) {
        return Err("must not contain control characters");
    }
    let segments = value.split('/').collect::<Vec<_>>();
    if segments.len() > MAX_TARGET_PATH_SEGMENTS {
        return Err("must contain at most 64 segments");
    }
    for segment in segments {
        if segment.is_empty() {
            return Err("must not contain empty segments");
        }
        if matches!(segment, "." | "..") {
            return Err("must not contain dot segments");
        }
        if segment.len() > 255 {
            return Err("segments must be at most 255 bytes");
        }
    }
    Ok(())
}
