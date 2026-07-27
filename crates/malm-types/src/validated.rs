//! The shared validated-string newtype macro.

/// Defines an immutable validated-string newtype.
///
/// Each expansion provides `new`, `as_str`, `into_inner`, `Display`,
/// `AsRef<str>`, and `FromStr`. Construction applies exactly one rule:
///
/// - `validate:` takes `fn(&str) -> Result<(), Reason>` and stores the
///   input unchanged, or
/// - `normalize:` takes `fn(&str) -> Result<String, Reason>` and stores
///   the returned canonical spelling.
///
/// `make_error:` receives the rejected owned input and the rejection reason.
/// It must produce the declared error type. Its bindings must be identifiers;
/// prefix an unused binding with an underscore.
///
/// Optional trailing `impl:` flags, in any order:
///
/// - `serde`: serializes as a string and deserializes through `Self::new`.
///   Omit it in crates without serde.
/// - `from_string`: `impl From<Self> for String` via `into_inner`.
/// - `borrow_str`: `impl Borrow<str>`.
///
/// # Examples
///
/// ```
/// malm_types::validated_string! {
///     /// A non-empty token.
///     pub struct Token;
///     error: String;
///     validate: |value: &str| if value.is_empty() { Err("must not be empty") } else { Ok(()) };
///     make_error: |value, reason| format!("invalid {value:?}: {reason}");
/// }
///
/// assert_eq!(Token::new("ok").unwrap().as_str(), "ok");
/// assert_eq!(Token::new("").unwrap_err(), "invalid \"\": must not be empty");
/// ```
#[macro_export]
macro_rules! validated_string {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
        error: $error:ty;
        validate: $validate:expr;
        make_error: |$err_value:ident, $err_reason:ident| $make_error:expr;
        $(impl: $($extra:ident),+ $(,)?;)?
    ) => {
        $crate::validated_string! {
            @emit
            meta: [$(#[$meta])*];
            decl: [$vis struct $name];
            error: [$error];
            rule: [validate $validate];
            make_error: [$err_value, $err_reason, $make_error];
            extras: [$($($extra)+)?];
        }
    };
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
        error: $error:ty;
        normalize: $normalize:expr;
        make_error: |$err_value:ident, $err_reason:ident| $make_error:expr;
        $(impl: $($extra:ident),+ $(,)?;)?
    ) => {
        $crate::validated_string! {
            @emit
            meta: [$(#[$meta])*];
            decl: [$vis struct $name];
            error: [$error];
            rule: [normalize $normalize];
            make_error: [$err_value, $err_reason, $make_error];
            extras: [$($($extra)+)?];
        }
    };
    (
        @emit
        meta: [$(#[$meta:meta])*];
        decl: [$vis:vis struct $name:ident];
        error: [$error:ty];
        rule: [$($rule:tt)+];
        make_error: [$err_value:ident, $err_reason:ident, $make_error:expr];
        extras: [$($extra:ident)*];
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis struct $name(::std::string::String);

        impl $name {
            pub fn new(
                value: impl ::core::convert::Into<::std::string::String>,
            ) -> ::core::result::Result<Self, $error> {
                let candidate: ::std::string::String = value.into();
                $crate::validated_string!(
                    @construct candidate,
                    [$err_value, $err_reason, $make_error],
                    $($rule)+
                )
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn into_inner(self) -> ::std::string::String {
                self.0
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl ::core::convert::AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $error;

            fn from_str(value: &str) -> ::core::result::Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        $($crate::validated_string!(@extra $extra $name);)*
    };
    (
        @construct $candidate:ident,
        [$err_value:ident, $err_reason:ident, $make_error:expr],
        validate $validate:expr
    ) => {
        match ($validate)(&$candidate) {
            ::core::result::Result::Ok(()) => ::core::result::Result::Ok(Self($candidate)),
            ::core::result::Result::Err($err_reason) => {
                let $err_value = $candidate;
                ::core::result::Result::Err($make_error)
            }
        }
    };
    (
        @construct $candidate:ident,
        [$err_value:ident, $err_reason:ident, $make_error:expr],
        normalize $normalize:expr
    ) => {
        match ($normalize)(&$candidate) {
            ::core::result::Result::Ok(normalized) => ::core::result::Result::Ok(Self(normalized)),
            ::core::result::Result::Err($err_reason) => {
                let $err_value = $candidate;
                ::core::result::Result::Err($make_error)
            }
        }
    };
    (@extra serde $name:ident) => {
        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let value =
                    <::std::string::String as ::serde::Deserialize<'de>>::deserialize(deserializer)?;
                Self::new(value).map_err(::serde::de::Error::custom)
            }
        }
    };
    (@extra from_string $name:ident) => {
        impl ::core::convert::From<$name> for ::std::string::String {
            fn from(value: $name) -> Self {
                value.into_inner()
            }
        }
    };
    (@extra borrow_str $name:ident) => {
        impl ::core::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }
    };
}
