//! Shared text validators.
//!
//! Validators return a [`ValidationError`] that callers can convert into their
//! own error types.

/// A failed text validation rule.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid {field}: {reason}")]
pub struct ValidationError {
    /// The field being validated.
    pub field: &'static str,
    /// Why the value was rejected.
    pub reason: &'static str,
}

/// Validates a non-empty string under a byte-length ceiling.
pub fn validate_text(
    field: &'static str,
    value: &str,
    limit: usize,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > limit {
        return Err(ValidationError {
            field,
            reason: "exceeds its byte limit",
        });
    }
    Ok(())
}

/// Validates a nonempty, bounded label without control characters.
pub fn validate_label(field: &'static str, value: &str) -> Result<(), ValidationError> {
    validate_text(field, value, 1024)?;
    if value.chars().any(char::is_control) {
        return Err(ValidationError {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

/// Validates a canonical slash-separated relative path.
pub fn validate_relative_path(value: &str) -> Result<(), ValidationError> {
    validate_text("relative path", value, 4096)?;
    if value.starts_with('/')
        || value.contains('\\')
        || value.split('/').any(|segment| {
            segment.is_empty() || matches!(segment, "." | "..") || segment.len() > 255
        })
        || value.split('/').count() > 64
        || value.chars().any(char::is_control)
    {
        return Err(ValidationError {
            field: "relative path",
            reason: "must be a bounded canonical slash-separated relative path",
        });
    }
    Ok(())
}

/// Validates a canonical lowercase dotted-name diagnostic code.
pub fn validate_diagnostic_code(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > 128 {
        return Err(ValidationError {
            field: "transform diagnostic code",
            reason: "must contain between 1 and 128 bytes",
        });
    }
    for segment in value.split('.') {
        let Some((&first, rest)) = segment.as_bytes().split_first() else {
            return Err(ValidationError {
                field: "transform diagnostic code",
                reason: "must not contain empty dot-separated segments",
            });
        };
        if !first.is_ascii_lowercase()
            || !rest.iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'_')
            })
        {
            return Err(ValidationError {
                field: "transform diagnostic code",
                reason: "must use canonical lowercase dotted-name syntax",
            });
        }
    }
    Ok(())
}
