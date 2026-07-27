//! Pins every `malm-config` `Display` string and `Error::source()` edge exactly.
//!
//! These assertions allow implementations to change without altering rendered
//! bytes or error chains.

use std::error::Error as _;

use malm_config::{
    ConfigValueError, RichConfigErrorV1, RichConfigReadErrorV1, RichKeyV1, RichNameV1,
    RichSyntaxErrorV1, SourceRangeV1, TargetPathV1, TransformContractErrorV1,
    TransformExecutionErrorV1, TransformFailureKindV1, TransformFailureV1,
};

fn key(value: &str) -> RichKeyV1 {
    RichKeyV1::new(value).expect("test key is valid")
}

fn name(value: &str) -> RichNameV1 {
    RichNameV1::new(value).expect("test name is valid")
}

#[test]
fn rich_syntax_error_display_is_byte_stable() {
    let cases: Vec<(RichSyntaxErrorV1, &str)> = vec![
        (
            RichSyntaxErrorV1::TooLarge {
                limit: 7,
                actual: 9,
            },
            "rich config document is 9 bytes; limit is 7",
        ),
        (
            RichSyntaxErrorV1::InvalidUtf8,
            "rich config document is not UTF-8",
        ),
        (
            RichSyntaxErrorV1::NestingTooDeep { limit: 64 },
            "rich config KDL nesting exceeds limit 64",
        ),
        (
            RichSyntaxErrorV1::CommentNestingTooDeep { limit: 64 },
            "rich config KDL block-comment nesting exceeds limit 64",
        ),
        (
            RichSyntaxErrorV1::MalformedKdl("boom".to_owned()),
            "malformed rich config KDL: boom",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert!(error.source().is_none());
    }
}

#[test]
fn rich_config_error_display_is_byte_stable() {
    let cases: Vec<(RichConfigErrorV1, &str)> = vec![
        (
            RichConfigErrorV1::LimitExceeded {
                resource: "widgets",
                limit: 4,
                actual: 5,
            },
            "widgets count/size 5 exceeds limit 4",
        ),
        (
            RichConfigErrorV1::InvalidName {
                kind: "rich key",
                value_len: 3,
                reason: "is too long",
            },
            "invalid rich key (3 bytes): is too long",
        ),
        (
            RichConfigErrorV1::DuplicateName {
                resource: "variable",
                name: "a.b".to_owned(),
            },
            "duplicate variable name \"a.b\"",
        ),
        (
            RichConfigErrorV1::InvalidValue {
                reason: "must be finite",
            },
            "invalid rich value: must be finite",
        ),
        (
            RichConfigErrorV1::TypeMismatch {
                expected: "list<bool>".to_owned(),
                actual: "record",
            },
            "expected list<bool>, found record",
        ),
        (
            RichConfigErrorV1::MissingRecordField(key("alpha")),
            "required record field RichKeyV1(\"alpha\") is missing",
        ),
        (
            RichConfigErrorV1::UnknownRecordField(key("alpha")),
            "record contains undeclared field RichKeyV1(\"alpha\")",
        ),
        (
            RichConfigErrorV1::InvalidSourceRange { start: 9, end: 4 },
            "invalid source byte range 9..4",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert!(error.source().is_none());
    }
}

#[test]
fn rich_config_read_error_display_and_source_are_byte_stable() {
    let syntax = RichConfigReadErrorV1::Source(RichSyntaxErrorV1::InvalidUtf8);
    assert_eq!(syntax.to_string(), "rich config document is not UTF-8");
    assert_eq!(
        syntax
            .source()
            .expect("syntax read errors expose their source")
            .to_string(),
        "rich config document is not UTF-8"
    );

    let unsupported = RichConfigReadErrorV1::UnsupportedVersion {
        expected: 1,
        actual: 3,
    };
    assert_eq!(
        unsupported.to_string(),
        "unsupported rich config schema 3; expected exactly 1"
    );
    assert!(unsupported.source().is_none());

    let ranged = RichConfigReadErrorV1::InvalidDocument {
        message: "bad node".to_owned(),
        range: Some(SourceRangeV1::new(2, 11).expect("range is valid")),
    };
    assert_eq!(
        ranged.to_string(),
        "invalid rich config at bytes 2..11: bad node"
    );
    assert!(ranged.source().is_none());
    assert_eq!(
        ranged.range(),
        Some(SourceRangeV1::new(2, 11).expect("range is valid"))
    );

    let unranged = RichConfigReadErrorV1::InvalidDocument {
        message: "bad node".to_owned(),
        range: None,
    };
    assert_eq!(unranged.to_string(), "invalid rich config: bad node");
    assert!(unranged.source().is_none());
    assert_eq!(unranged.range(), None);

    let model = RichConfigReadErrorV1::InvalidModel(RichConfigErrorV1::InvalidValue {
        reason: "must be finite",
    });
    assert_eq!(
        model.to_string(),
        "invalid rich config model: invalid rich value: must be finite"
    );
    assert_eq!(
        model
            .source()
            .expect("model read errors expose their source")
            .to_string(),
        "invalid rich value: must be finite"
    );
}

#[test]
fn transform_contract_error_display_and_source_are_byte_stable() {
    let model = TransformContractErrorV1::RichModel(RichConfigErrorV1::InvalidValue {
        reason: "must be finite",
    });
    assert_eq!(model.to_string(), "invalid rich value: must be finite");
    assert_eq!(
        model
            .source()
            .expect("rich-model contract errors expose their source")
            .to_string(),
        "invalid rich value: must be finite"
    );

    let cases: Vec<(TransformContractErrorV1, &str)> = vec![
        (
            TransformContractErrorV1::UnsupportedVersion {
                expected: 1,
                actual: 4,
            },
            "unsupported transform contract version 4; expected exactly 1",
        ),
        (
            TransformContractErrorV1::DuplicateOption(name("pretty")),
            "duplicate transform option pretty",
        ),
        (
            TransformContractErrorV1::DuplicateResource(name("schema")),
            "duplicate declared transform resource schema",
        ),
        (
            TransformContractErrorV1::ResourceDigestMismatch(name("schema")),
            "declared resource schema bytes do not match its digest",
        ),
        (
            TransformContractErrorV1::InvalidIdentity("implementation version must not be empty"),
            "invalid transform identity: implementation version must not be empty",
        ),
        (
            TransformContractErrorV1::InvalidMediaType,
            "invalid transform response media type",
        ),
        (
            TransformContractErrorV1::UnknownDiagnosticSource,
            "transform diagnostic references an unknown source document",
        ),
        (
            TransformContractErrorV1::InvalidDiagnosticSourceRange,
            "transform diagnostic range exceeds its captured source document",
        ),
        (
            TransformContractErrorV1::InvalidDiagnosticOutputRange,
            "transform diagnostic has an invalid output byte range",
        ),
        (
            TransformContractErrorV1::OutputDiagnosticOnFailure,
            "failed transform diagnostic cannot reference unavailable output",
        ),
        (
            TransformContractErrorV1::ErrorDiagnosticOnSuccess,
            "successful transform response contains an error diagnostic",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert!(
            error.source().is_none(),
            "{expected} must not have a source"
        );
    }
}

#[test]
fn transform_execution_error_display_is_byte_stable() {
    let contract = TransformContractErrorV1::InvalidMediaType;
    let failure = TransformFailureV1::new(
        TransformFailureKindV1::Internal,
        "the component trapped",
        Vec::new(),
    )
    .expect("bounded failure");

    let cases: Vec<(TransformExecutionErrorV1, &str)> = vec![
        (
            TransformExecutionErrorV1::InvalidRequest(contract.clone()),
            "invalid transform request: invalid transform response media type",
        ),
        (
            TransformExecutionErrorV1::TransformFailed(failure),
            "transform failed: the component trapped",
        ),
        (
            TransformExecutionErrorV1::InvalidResponse(contract),
            "invalid transform response: invalid transform response media type",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert!(
            error.source().is_none(),
            "{expected} must not have a source"
        );
    }
}

#[test]
fn config_value_error_display_is_byte_stable() {
    let with_len = TargetPathV1::new("/absolute").expect_err("absolute paths are rejected");
    assert_eq!(
        with_len.to_string(),
        "invalid target path (9 bytes): must be relative to the deployment target"
    );
    assert_eq!(with_len.kind(), "target path");
    assert_eq!(with_len.value_len(), Some(9));
    assert_eq!(
        with_len.reason(),
        "must be relative to the deployment target"
    );
    assert!(with_len.source().is_none());

    let without_len: ConfigValueError =
        malm_config::FiniteFloatV1::new(f64::NAN).expect_err("non-finite floats are rejected");
    assert_eq!(
        without_len.to_string(),
        "invalid config float: must be finite"
    );
    assert_eq!(without_len.value_len(), None);
    assert!(without_len.source().is_none());
}

#[test]
fn target_path_rejection_messages_are_byte_stable() {
    let cases: Vec<(&str, &str)> = vec![
        ("", "invalid target path (0 bytes): must not be empty"),
        (
            "/x",
            "invalid target path (2 bytes): must be relative to the deployment target",
        ),
        (
            "a\\b",
            "invalid target path (3 bytes): must use slash separators",
        ),
        (
            "a\u{1}b",
            "invalid target path (3 bytes): must not contain control characters",
        ),
        (
            "a//b",
            "invalid target path (4 bytes): must not contain empty segments",
        ),
        (
            "a/./b",
            "invalid target path (5 bytes): must not contain dot segments",
        ),
        (
            "a/../b",
            "invalid target path (6 bytes): must not contain dot segments",
        ),
    ];
    for (value, expected) in cases {
        assert_eq!(
            TargetPathV1::new(value)
                .expect_err("value is rejected")
                .to_string(),
            expected,
            "value {value:?}"
        );
    }

    let overlong_segment = format!("a/{}", "b".repeat(256));
    assert_eq!(
        TargetPathV1::new(overlong_segment.clone())
            .expect_err("overlong segment is rejected")
            .to_string(),
        format!(
            "invalid target path ({} bytes): segments must be at most 255 bytes",
            overlong_segment.len()
        )
    );

    let overlong = "a".repeat(4097);
    assert_eq!(
        TargetPathV1::new(overlong)
            .expect_err("overlong path is rejected")
            .to_string(),
        "invalid target path (4097 bytes): must be at most 4096 bytes"
    );

    let too_many_segments = vec!["a"; 65].join("/");
    assert_eq!(
        TargetPathV1::new(too_many_segments.clone())
            .expect_err("oversegmented path is rejected")
            .to_string(),
        format!(
            "invalid target path ({} bytes): must contain at most 64 segments",
            too_many_segments.len()
        )
    );
}

#[test]
fn rich_name_rejection_messages_are_byte_stable() {
    let cases: Vec<(&str, &str)> = vec![
        ("", "invalid rich name (0 bytes): must not be empty"),
        (
            "a..b",
            "invalid rich name (4 bytes): must not contain empty dot-separated segments",
        ),
        (
            "A",
            "invalid rich name (1 bytes): each segment must start with a lowercase ASCII letter",
        ),
        (
            "aB",
            "invalid rich name (2 bytes): segments may contain only lowercase ASCII letters, digits, hyphens, and underscores",
        ),
    ];
    for (value, expected) in cases {
        assert_eq!(
            RichNameV1::new(value)
                .expect_err("value is rejected")
                .to_string(),
            expected,
            "value {value:?}"
        );
    }

    let overlong = "a".repeat(129);
    assert_eq!(
        RichNameV1::new(overlong)
            .expect_err("overlong name is rejected")
            .to_string(),
        "invalid rich name (129 bytes): is too long"
    );
}

#[test]
fn rich_key_rejection_messages_are_byte_stable() {
    assert_eq!(
        RichKeyV1::new("")
            .expect_err("empty keys are rejected")
            .to_string(),
        "invalid rich key (0 bytes): must not be empty"
    );
    assert_eq!(
        RichKeyV1::new("a\u{1}")
            .expect_err("control characters are rejected")
            .to_string(),
        "invalid rich key (2 bytes): must not contain control characters"
    );
    let overlong = "k".repeat(1025);
    assert_eq!(
        RichKeyV1::new(overlong)
            .expect_err("overlong keys are rejected")
            .to_string(),
        "invalid rich key (1025 bytes): is too long"
    );
}

#[test]
fn safe_relative_symlink_rejection_messages_are_byte_stable() {
    let cases: Vec<(String, &str)> = vec![
        (
            String::new(),
            "invalid rich value: safe relative symlink target must not be empty",
        ),
        (
            "/abs".to_owned(),
            "invalid rich value: safe symlink target must be relative and use slash separators",
        ),
        (
            "a\\b".to_owned(),
            "invalid rich value: safe symlink target must be relative and use slash separators",
        ),
        (
            "a\u{1}b".to_owned(),
            "invalid rich value: safe symlink target must not contain control characters",
        ),
        (
            "a//b".to_owned(),
            "invalid rich value: safe symlink target contains an empty, dot, or overlong segment",
        ),
        (
            "a/./b".to_owned(),
            "invalid rich value: safe symlink target contains an empty, dot, or overlong segment",
        ),
        (
            "a/../b".to_owned(),
            "invalid rich value: safe symlink target contains an empty, dot, or overlong segment",
        ),
        (
            format!("a/{}", "b".repeat(256)),
            "invalid rich value: safe symlink target contains an empty, dot, or overlong segment",
        ),
    ];
    for (value, expected) in cases {
        assert_eq!(
            malm_config::SafeRelativeSymlinkV1::new(value.clone())
                .expect_err("value is rejected")
                .to_string(),
            expected,
            "value {value:?}"
        );
    }

    assert_eq!(
        malm_config::SafeRelativeSymlinkV1::new("a".repeat(4097))
            .expect_err("overlong target is rejected")
            .to_string(),
        "safe relative symlink target bytes count/size 4097 exceeds limit 4096"
    );
    let too_many_segments = vec!["a"; 65].join("/");
    assert_eq!(
        malm_config::SafeRelativeSymlinkV1::new(too_many_segments)
            .expect_err("oversegmented target is rejected")
            .to_string(),
        "safe relative symlink target segments count/size 65 exceeds limit 64"
    );
}

#[test]
fn rich_name_and_key_value_len_is_reported_in_bytes_not_chars() {
    assert_eq!(
        RichNameV1::new("é")
            .expect_err("non-ascii names are rejected")
            .to_string(),
        "invalid rich name (2 bytes): each segment must start with a lowercase ASCII letter"
    );
}

mod output_declaration_precedence {
    use malm_config::{CapturedDocumentIdV1, DocumentAuthorityV1, decode_rich_config_document_v1};
    use malm_pack::PackPath;
    use malm_types::{ContributionName, Digest};

    fn document(outputs: &str) -> String {
        format!(
            "rich-config schema-version=1 default-profile=\"base\" {{\n\
             includes {{ }}\n\
             modules {{ }}\n\
             variables {{ }}\n\
             fragments {{ }}\n\
             slots {{ }}\n\
             statements {{ }}\n\
             profiles {{\n\
             profile \"base\" abstract=#false {{\n\
             extends {{ }}\n\
             statements {{ }}\n\
             outputs {{\n{outputs}\n}}\n\
             }}\n\
             }}\n\
             }}\n"
        )
    }

    fn reject(outputs: &str) -> String {
        let id = CapturedDocumentIdV1::new(
            DocumentAuthorityV1::new(
                ContributionName::new("root").expect("valid contribution name"),
                Digest::sha256(b"abc"),
            ),
            PackPath::new("malm.kdl").expect("valid pack path"),
        );
        decode_rich_config_document_v1(id, document(outputs).as_bytes())
            .expect_err("declaration is rejected")
            .to_string()
    }

    #[test]
    fn symlink_rejects_its_name_before_its_target() {
        let message = reject("symlink \"Bad-Name\" destination=\"etc/link\" target=\"../escape\"");
        assert!(
            message.contains("each segment must start with a lowercase ASCII letter"),
            "expected the name rejection first, got: {message}"
        );
    }

    #[test]
    fn symlink_rejects_its_destination_before_its_target() {
        let message = reject("symlink \"ok\" destination=\"/absolute\" target=\"../escape\"");
        assert!(
            message.contains("must be relative to the deployment target"),
            "expected the destination rejection first, got: {message}"
        );
    }

    #[test]
    fn decoded_archive_rejects_its_decoder_version_before_its_name() {
        let message = reject(
            "decoded-archive \"Bad-Name\" destination=\"etc/tree\" source=\"a.tar\" \
             source-kind=\"asset\" raw-digest=\"sha256-0000000000000000000000000000000000000000000000000000000000000000\" \
             object-digest=\"sha256-0000000000000000000000000000000000000000000000000000000000000000\" \
             byte-len=1 decoder=\"ustar\" decoder-version=99999 \
             tree-digest=\"sha256-0000000000000000000000000000000000000000000000000000000000000000\"",
        );
        assert!(
            message.contains("decoder-version is outside u16"),
            "expected the decoder-version rejection first, got: {message}"
        );
    }
}
