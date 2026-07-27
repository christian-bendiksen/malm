//! Serde helpers for bounded wire-format collections.

use serde::de::{Deserialize, Deserializer, Error, IgnoredAny, SeqAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;

/// Deserializes a sequence with a fixed element limit.
///
/// A declared size above `limit` is rejected before allocation. If no size is
/// declared, the deserializer reads at most one element past the limit.
/// `what` names the collection in both error messages.
pub fn bounded_seq<'de, D, T>(
    deserializer: D,
    limit: usize,
    what: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T> {
        what: &'static str,
        limit: usize,
        marker: PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> Visitor<'de> for BoundedVecVisitor<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {} {}", self.limit, self.what)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > self.limit) {
                return Err(A::Error::custom(format_args!(
                    "{} exceeds its count limit {}",
                    self.what, self.limit
                )));
            }
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or_default().min(self.limit));
            while values.len() < self.limit {
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(format_args!(
                    "{} exceeds its count limit {}",
                    self.what, self.limit
                )));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor {
        what,
        limit,
        marker: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::bounded_seq;
    use serde::de::value::{Error as ValueError, SeqDeserializer};

    fn deserialize(values: &[u32], limit: usize) -> Result<Vec<u32>, ValueError> {
        let deserializer = SeqDeserializer::new(values.iter().copied());
        bounded_seq(deserializer, limit, "test values")
    }

    #[test]
    fn bounded_seq_accepts_sequences_within_the_limit() {
        assert_eq!(deserialize(&[], 2).unwrap(), Vec::<u32>::new());
        assert_eq!(deserialize(&[1, 2], 2).unwrap(), vec![1, 2]);
    }

    #[test]
    fn bounded_seq_rejects_sequences_beyond_the_limit() {
        let error = deserialize(&[1, 2, 3], 2).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("test values exceeds its count limit 2"),
            "unexpected message: {error}"
        );
    }
}
