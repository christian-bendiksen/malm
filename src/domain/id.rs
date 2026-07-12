//! Validated newtypes for object, transaction, and state identifiers.
//!
//! They serialize as plain strings. Serde deserialization bypasses the
//! constructors, so persisted values still need validation at read boundaries.

use crate::app::validation::validate_name;
use crate::cas::validate_object_id;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A content-addressed object id: `sha256-` followed by 64 lowercase hex
/// digits. Identifies CAS blobs, source snapshots, asset payloads, and
/// archives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(String);

impl ObjectId {
    pub fn parse(id: &str) -> Result<Self> {
        validate_object_id(id)?;
        Ok(Self(id.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ObjectId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for ObjectId {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// A transaction identifier: a zero-padded secs-nanos-pid-random string.
/// Lexicographic order is chronological (relied on by GC tie-breaking).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransactionId(String);

impl TransactionId {
    pub fn new(id: String) -> Result<Self> {
        validate_name(&id, "transaction id")?;
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for TransactionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A state namespace name matching `[A-Za-z0-9_-]+`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StateName(String);

impl StateName {
    pub fn new(name: String) -> Result<Self> {
        validate_name(&name, "state name")?;
        Ok(Self(name))
    }

    pub fn parse(name: &str) -> Result<Self> {
        validate_name(name, "state name")?;
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StateName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for StateName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for StateName {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_id_validates_on_construction() {
        assert!(ObjectId::parse("sha256-").is_err());
        assert!(ObjectId::parse("not-a-hash").is_err());
        assert!(ObjectId::parse("sha256-abc").is_err());
        assert!(
            ObjectId::parse(
                "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .is_ok()
        );
    }

    #[test]
    fn object_id_round_trips_through_serde() {
        let id = ObjectId::parse(
            "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(
            json,
            "\"sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\""
        );
        let back: ObjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn transaction_id_rejects_bad_chars_and_preserves_order() {
        assert!(TransactionId::new("has spaces".to_owned()).is_err());
        let a = TransactionId::new("0000000001-000000001-1-0000000000000001".to_owned()).unwrap();
        let b = TransactionId::new("0000000002-000000001-1-0000000000000001".to_owned()).unwrap();
        assert!(a < b, "lexicographic order is chronological");
    }

    #[test]
    fn state_name_validates_on_construction() {
        assert!(StateName::new("has spaces".to_owned()).is_err());
        assert!(StateName::parse("../escape").is_err());
        assert!(StateName::parse("").is_err());
        assert!(StateName::parse("default").is_ok());
        assert!(StateName::parse("work-123_test").is_ok());
    }

    #[test]
    fn state_name_round_trips_through_serde() {
        let name = StateName::new("default".to_owned()).unwrap();
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, "\"default\"");
        let back: StateName = serde_json::from_str(&json).unwrap();
        assert_eq!(name, back);
    }
}
